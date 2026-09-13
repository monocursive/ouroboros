defmodule Ouroboros.InteractiveRecoveryAdmissionTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log

  alias Ouroboros.Interactive.{Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Maintenance.Fence
  alias Ouroboros.Test.NativeConfig

  test "released startup admission recovers through a fresh lease without losing supervisors" do
    id = "admission-recovery-#{System.unique_integer([:positive])}"
    root = Path.join(System.tmp_dir!(), id)
    File.mkdir_p!(root)
    Ouroboros.Test.DurableFence.ensure_started!(root)
    config = NativeConfig.snapshot()
    NativeConfig.configure(%{native: %{test_pid: self()}})

    on_exit(fn ->
      if pid = Task.whereis(id),
        do: DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      for info <- Ouroboros.Session.list(),
          info.logical_id == id,
          do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)

      case Store.get(id) do
        {:ok, state} ->
          Store.put(%{state | status: :closed})
          Store.delete(id)

        _ ->
          :ok
      end

      NativeConfig.configure(config)
      File.rm_rf!(root)
    end)

    assert {:ok, _ref} = InteractiveSession.start(id: id, workspace: root)
    coordinator = Task.whereis(id)
    supervisor = Process.whereis(Ouroboros.Interactive.TaskSupervisor)
    transport = Process.whereis(Ouroboros.SessionTransportSupervisor)
    supervisor_monitor = Process.monitor(supervisor)
    coordinator_monitor = Process.monitor(coordinator)
    # Only the validation result is asserted/emitted, never the retained capability.
    stale? = :sys.get_state(coordinator).maintenance_admission |> Fence.validate_admission(id)
    assert stale? == {:error, :stale_admission}
    {:ok, before} = Store.get(id)

    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^coordinator_monitor, :process, ^coordinator, :killed}, 1_000
    refute_receive {:DOWN, ^supervisor_monitor, :process, ^supervisor, _reason}, 200

    # No facade call: only the supervised recovery sweep can replace the coordinator.
    replacement =
      eventually(fn ->
        case Task.whereis(id) do
          pid when is_pid(pid) and pid != coordinator -> pid
          _ -> nil
        end
      end)

    assert {:ok, _} = GenServer.call(replacement, :ready)
    assert Process.whereis(Ouroboros.Interactive.TaskSupervisor) == supervisor
    assert Process.whereis(Ouroboros.SessionTransportSupervisor) == transport
    {:ok, after_recovery} = Store.get(id)
    assert after_recovery.runtime_id == before.runtime_id
    assert after_recovery.runtime_generation == before.runtime_generation
    refute_receive {:ouroboros_test_model_started, _, _, _}, 50
  end

  test "the supervised sweep acknowledges retained terminal output without reopening execution" do
    alias Ouroboros.Interactive.{Event, State}
    alias Ouroboros.Session
    alias Ouroboros.Test.NativeModelScript

    id = "terminal-sweep-#{System.unique_integer([:positive])}"
    root = Path.join(System.tmp_dir!(), id)
    File.mkdir_p!(root)
    Ouroboros.Test.DurableFence.ensure_started!(root)
    previous = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    {model, model_agent} = NativeModelScript.start([])
    {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
    {:ok, runtime_id} = Session.open(id, %{cwd: root, model: model})
    {:ok, attachment, info} = Session.attach(runtime_id, self(), 0)
    :ok = Session.close(runtime_id)
    {:ok, events, _} = Session.drain(attachment, 0, 500)
    cursor = List.last(events).sequence
    {:ok, base} = State.new(id, workspace: root, runtime_exposure: false)

    session = %{
      base
      | status: :closed,
        runtime_id: runtime_id,
        runtime_generation: info.generation,
        runtime_cursor: cursor,
        cursor: cursor,
        events: Enum.map(events, &Event.from_execution(id, &1))
    }

    :ok = Store.create(session)

    on_exit(fn ->
      if pid = Task.whereis(id),
        do: DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      if Process.alive?(info.pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)

      Store.delete(id)

      if previous,
        do: Application.put_env(:ouroboros, :native_model_module, previous),
        else: Application.delete_env(:ouroboros, :native_model_module)

      File.rm_rf!(root)
    end)

    monitor = Process.monitor(info.pid)
    # A real Fence closes admission while its barrier is outstanding. Hold that
    # boundary across the zero-retention prune, then let the refused barrier reopen it.
    parent = self()

    start_supervised!(
      Supervisor.child_spec(
        {Fence,
         name: :terminal_recovery_fence,
         data_dir: Path.join(root, "fence"),
         barrier: fn _, _ ->
           send(parent, {:barrier_waiting, self()})

           receive do
             :release -> {:error, :diagnostic_barrier_refusal}
           end
         end},
        id: :terminal_recovery_fence
      )
    )

    previous_fence = Application.get_env(:ouroboros, :maintenance_fence_server)
    Application.put_env(:ouroboros, :maintenance_fence_server, :terminal_recovery_fence)

    on_exit(fn ->
      if previous_fence,
        do: Application.put_env(:ouroboros, :maintenance_fence_server, previous_fence),
        else: Application.delete_env(:ouroboros, :maintenance_fence_server)
    end)

    enter =
      Elixir.Task.async(fn -> Fence.enter("terminal-retention", 0, :terminal_recovery_fence) end)

    assert_receive {:barrier_waiting, worker}, 1_000
    Registry.unregister(Ouroboros.Interactive.Registry, id)
    assert {:error, :maintenance_fenced} = Fence.acquire("late", id, :terminal_recovery_fence)
    assert {:ok, pruned} = Store.prune_terminal(0)
    refute id in pruned
    assert {:error, :session_delivery_pending} = Store.delete(id)
    assert {:ok, ^session} = Store.get(id)
    Process.sleep(2_100)
    assert {:ok, pruned} = Store.prune_terminal(0)
    refute id in pruned
    assert Task.whereis(id) == nil
    assert Process.alive?(info.pid)
    send(worker, :release)
    assert {:error, {:barrier_refused, :diagnostic_barrier_refusal}} = Elixir.Task.await(enter)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 5_000
    assert {:ok, ^session} = Store.get(id)
    assert NativeModelScript.call_count(model_agent) == 0
    assert {:ok, ids} = Store.prune_terminal(0)
    assert id in ids
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(_fun, 0), do: flunk("coordinator was not recovered by the supervised sweep")

  defp eventually(fun, attempts) do
    case fun.() do
      nil ->
        Process.sleep(50)
        eventually(fun, attempts - 1)

      pid ->
        pid
    end
  end
end
