defmodule Ouroboros.Session.RecoveryIsolationTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log

  alias Ouroboros.Maintenance.Fence
  alias Ouroboros.Session.Recovery

  defmodule ProjectedStore do
    use Agent

    def start_link(_opts), do: Agent.start_link(fn -> [] end, name: __MODULE__)
    def replace(rows), do: Agent.update(__MODULE__, fn _ -> rows end)
    def list_recoverable, do: Agent.get(__MODULE__, & &1)
    def prune_terminal(_retention), do: {:ok, []}
  end

  # A forwarding fault seam, not an alternative admission implementation: every
  # returned capability and every validation comes from the private real Fence.
  defmodule Authority do
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)
    def init(opts), do: {:ok, Map.new(opts)}

    def handle_call(
          {:acquire, _operation, id, _generation},
          _from,
          %{fault: :acquire, fault_id: id} = state
        ) do
      send(state.test, {:authority_fault, :acquire, id})
      {:stop, :injected_acquire_exit, state}
    end

    def handle_call({:release, %{session_id: id}} = message, _from, state)
        when state.fault == :release and state.fault_id == id do
      # Lose the response after the real authority settled the lease. Recovery
      # must survive an uncertain release without assuming its call returned.
      :ok = GenServer.call(state.backing, message)
      send(state.test, {:authority_fault, :release, id})
      {:stop, :injected_release_exit, state}
    end

    def handle_call(message, _from, state),
      do: {:reply, GenServer.call(state.backing, message), state}
  end

  # DynamicSupervisor's start protocol is isolated here so these tests exercise
  # Recovery's real Interactive.Task special case without opening native work.
  # A refused child must still release the capability acquired for its start.
  defmodule ChildStarter do
    use GenServer

    def start_link(test), do: GenServer.start_link(__MODULE__, test, name: __MODULE__)
    def init(test), do: {:ok, test}

    def handle_call({:start_child, child}, _from, test) do
      start = if is_map(child), do: child.start, else: elem(child, 0)
      {Ouroboros.Interactive.Task, :start_link, [argument]} = start

      case argument do
        {id, admission} ->
          validation =
            Ouroboros.Maintenance.Fence.validate_admission(
              admission,
              id,
              Ouroboros.Session.RecoveryIsolationTest.Authority
            )

          send(test, {:child_start_attempt, id, validation})

        id when is_binary(id) ->
          send(test, {:child_start_attempt, id, :without_admission})
      end

      {:reply, {:error, :fixture_child_refused}, test}
    end
  end

  setup context do
    id = "recovery-isolation-#{System.unique_integer([:positive, :monotonic])}"
    root = Path.join(System.tmp_dir!(), id)
    previous_server = Application.fetch_env(:ouroboros, :maintenance_fence_server)
    backing_name = __MODULE__.BackingFence

    File.mkdir_p!(root)

    on_exit(fn ->
      case previous_server do
        {:ok, server} -> Application.put_env(:ouroboros, :maintenance_fence_server, server)
        :error -> Application.delete_env(:ouroboros, :maintenance_fence_server)
      end

      File.rm_rf!(root)
    end)

    start_supervised!({Fence, name: backing_name, data_dir: Path.join(root, "maintenance")})
    start_supervised!(ProjectedStore)
    start_supervised!({ChildStarter, self()})

    authority =
      start_authority!(backing_name, context.fault, id, :initial_authority)

    Application.put_env(:ouroboros, :maintenance_fence_server, Authority)

    recovery =
      start_supervised!(
        {Recovery,
         name: nil,
         interval: 60_000,
         store: ProjectedStore,
         task: Ouroboros.Interactive.Task,
         registry: Ouroboros.Interactive.Registry,
         supervisor: ChildStarter}
      )

    # Finish the initial empty tick before installing the fault's projected row.
    :sys.get_state(recovery)
    %{id: id, recovery: recovery, authority: authority, backing: backing_name}
  end

  @tag fault: :acquire
  test "an authority exit during acquire does not terminate the recovery sweep", context do
    authority_monitor = Process.monitor(context.authority)
    ProjectedStore.replace([row(context.id)])
    run_tick(context.recovery)

    assert_receive {:authority_fault, :acquire, id}, 1_000
    assert id == context.id
    assert_receive {:DOWN, ^authority_monitor, :process, _, :injected_acquire_exit}, 1_000
    refute_receive {:child_start_attempt, ^id, _}, 0
    assert Process.alive?(context.recovery)
    assert Fence.inspect(context.backing).active_admissions == 0

    assert_later_admission(context)
  end

  @tag fault: :release
  test "an authority exit during release does not terminate the recovery sweep", context do
    authority_monitor = Process.monitor(context.authority)
    ProjectedStore.replace([row(context.id)])
    run_tick(context.recovery)

    assert_receive {:child_start_attempt, id, :ok}, 1_000
    assert id == context.id
    assert_receive {:authority_fault, :release, ^id}, 1_000
    assert_receive {:DOWN, ^authority_monitor, :process, _, :injected_release_exit}, 1_000
    assert Process.alive?(context.recovery)
    assert Fence.inspect(context.backing).active_admissions == 0

    assert_later_admission(context)
  end

  defp assert_later_admission(context) do
    start_authority!(context.backing, nil, nil, :replacement_authority)
    later_id = context.id <> "-later"
    ProjectedStore.replace([row(later_id)])
    run_tick(context.recovery)

    assert_receive {:child_start_attempt, ^later_id, :ok}, 1_000
    assert Process.alive?(context.recovery)
    assert Fence.inspect(context.backing).active_admissions == 0
  end

  defp start_authority!(backing, fault, id, child_id) do
    spec =
      Supervisor.child_spec(
        {Authority, backing: backing, fault: fault, fault_id: id, test: self()},
        restart: :temporary
      )

    start_supervised!(spec, id: child_id)
  end

  defp run_tick(recovery) do
    send(recovery, :recover)
    # Same-sender ordering makes this a bounded completion barrier for the tick.
    :sys.get_state(recovery, 2_000)
  end

  defp row(id) do
    %{
      id: id,
      node: node(),
      terminal?: false,
      removed_provider?: false,
      updated_at: "2000-01-01T00:00:00Z"
    }
  end
end
