defmodule Ouroboros.Provider.Native.MaintenanceFenceIntegrationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Maintenance.{Fence, NativeInventory}
  alias Ouroboros.Session
  alias Ouroboros.Test.NativeModelScript

  # Discovery coverage needs the complete registry, but must not checkpoint native
  # owners left by unrelated tests. The real mailbox/durable behavior is exercised
  # separately below against the exact native participants each fixture owns.
  defmodule RegistryProjection do
    def prepare_fence(pid, generation, _token) do
      logical =
        Enum.find_value(Registry.keys(Ouroboros.SessionRegistry, pid), fn
          {:logical, id} -> id
          _other -> nil
        end)

      if is_binary(logical) do
        digest = :crypto.hash(:sha256, logical) |> Base.encode16(case: :lower)

        {:ok,
         %{
           logical_id: logical,
           runtime_id: "runtime-" <> digest,
           provider_session_id: "provider-" <> digest,
           fence_generation: generation,
           root_digest: digest
         }}
      else
        {:error, :participant_disappeared}
      end
    end

    def release_fence(_pid, _generation, _token), do: :ok
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "native-fence-runtime-#{System.unique_integer([:positive])}")

    data = Path.join(root, "native")
    File.mkdir_p!(data)

    previous =
      for key <- [:native_data_dir, :native_model_module, :native_epoch_server],
          into: %{},
          do: {key, Application.get_env(:ouroboros, key)}

    epoch =
      start_supervised!(
        {Ouroboros.Maintenance.Epoch, name: nil, data_dir: Path.join(root, "epoch")}
      )

    Application.put_env(:ouroboros, :native_data_dir, data)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    Application.put_env(:ouroboros, :native_epoch_server, epoch)

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if is_nil(value),
          do: Application.delete_env(:ouroboros, key),
          else: Application.put_env(:ouroboros, key, value)
      end)

      File.rm_rf!(root)
    end)

    %{root: root}
  end

  test "default discovery includes the complete logical registry and its exact owners" do
    sentinel = "non-logical-discovery-#{System.unique_integer([:positive])}"

    assert {:ok, _} =
             Registry.register(Ouroboros.SessionRegistry, {:runtime, sentinel}, :sentinel)

    owned =
      for suffix <- ["a", "b"] do
        logical = "native-discovery-#{System.unique_integer([:positive])}-#{suffix}"

        pid =
          start_supervised!(%{
            id: {:discovery_owner, logical},
            start:
              {Agent, :start_link,
               [
                 fn ->
                   {:ok, _} =
                     Registry.register(Ouroboros.SessionRegistry, {:logical, logical}, nil)

                   logical
                 end
               ]}
          })

        {logical, pid}
      end

    {registered, snapshot} = stable_registry_snapshot()
    assert Enum.sort(snapshot.release.participants) == registered
    assert Enum.map(snapshot.rows, & &1.logical_id) == Enum.map(registered, &elem(&1, 0))
    assert Enum.all?(owned, &(&1 in snapshot.release.participants))
    refute Enum.any?(snapshot.release.participants, fn {_logical, pid} -> pid == self() end)
  end

  test "participant death before publication reopens Fence and replacement inherits no token", %{
    root: root
  } do
    context = open_session(root)
    participants = [{context.logical, context.pid}]
    parent = self()

    barrier = fn generation, opts ->
      {:ok, native} = NativeInventory.snapshot(generation, opts)
      send(parent, {:observed, self(), native})

      receive do
        :return -> {:ok, barrier_value(generation, native)}
      end
    end

    start_supervised!(
      {Fence,
       name: :native_death_fence,
       data_dir: Path.join(root, "fence-a"),
       barrier: barrier,
       barrier_opts: [participants: participants]}
    )

    enter = Task.async(fn -> Fence.enter("death-before-persist", 0, :native_death_fence) end)

    assert_receive {:observed, worker, first}, 1_000
    assert first.release.participants == participants
    send(worker, :return)
    assert_receive {:observed, ^worker, second}, 1_000
    assert second.release.participants == participants
    assert first.release.token == second.release.token

    ref = Process.monitor(context.pid)
    Process.exit(context.pid, :kill)
    assert_receive {:DOWN, ^ref, :process, _, _}
    send(worker, :return)

    assert {:error, {:native_participant_died, logical}} = Task.await(enter)
    assert logical == context.logical
    assert %{state: :open, generation: 0} = Fence.inspect(:native_death_fence)
    refute File.exists?(Path.join(root, "fence-a/maintenance-fence.json"))

    replacement = open_session(root, context.logical)
    assert replacement.pid != context.pid
    replacement_token = make_ref()

    assert {:ok, _row} =
             Ouroboros.Provider.Native.Session.prepare_fence(
               replacement.runtime,
               2,
               replacement_token
             )

    assert :ok =
             Ouroboros.Provider.Native.Session.release_fence(
               replacement.runtime,
               2,
               replacement_token
             )

    assert :ok = Session.kill(replacement.runtime)
    DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, replacement.pid)
    wait_dead(replacement.pid)
  end

  test "participant death after publication cannot reopen durable Fence", %{root: root} do
    context = open_session(root)
    participants = [{context.logical, context.pid}]
    fence_root = Path.join(root, "fence-b")

    barrier = fn generation, opts ->
      with {:ok, native} <- NativeInventory.snapshot(generation, opts) do
        assert native.release.participants == participants
        {:ok, barrier_value(generation, native)}
      end
    end

    start_supervised!(
      {Fence,
       name: :native_durable_fence,
       data_dir: fence_root,
       barrier: barrier,
       barrier_opts: [participants: participants]}
    )

    assert {:ok, marker} = Fence.enter("durable-death", 0, :native_durable_fence)
    assert marker["generation"] == 1

    ref = Process.monitor(context.pid)
    Process.exit(context.pid, :kill)
    assert_receive {:DOWN, ^ref, :process, _, _}

    assert %{state: :fenced, generation: 1} = Fence.inspect(:native_durable_fence)

    assert {:error, :maintenance_fenced} =
             Fence.acquire("late", context.logical, :native_durable_fence)

    assert File.regular?(Path.join(fence_root, "maintenance-fence.json"))

    stop_supervised!(Fence)

    start_supervised!(
      {Fence,
       name: :native_durable_fence,
       data_dir: fence_root,
       barrier: barrier,
       barrier_opts: [participants: participants]}
    )

    assert %{state: :fenced, generation: 1, transaction_id: "durable-death"} =
             Fence.inspect(:native_durable_fence)

    assert {:error, :maintenance_fenced} =
             Fence.acquire("after-restart", context.logical, :native_durable_fence)
  end

  defp open_session(root, logical \\ nil) do
    logical = logical || "fenced-logical-#{System.unique_integer([:positive])}"

    case Registry.register(Ouroboros.Interactive.Registry, logical, nil) do
      {:ok, _} -> :ok
      {:error, {:already_registered, pid}} when pid == self() -> :ok
    end

    {model, _agent} = NativeModelScript.start([[{:text, "ok"}, {:finish, :stop}]])
    request = %{provider: :native, cwd: root, model: model, approval_mode: :auto_approve}
    {:ok, runtime} = Session.open(logical, request)
    [{pid, _projection}] = Registry.lookup(Ouroboros.SessionRegistry, {:runtime, runtime})

    # Native sessions belong to the application supervisor, not the test supervisor.
    # Reap this exact owner even if an assertion fails before the explicit death;
    # otherwise it survives after its private Epoch and directory have gone away.
    on_exit(fn ->
      if Process.alive?(pid) do
        DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, pid)
        wait_dead(pid)
      end
    end)

    {:ok, _attachment, info} = Session.attach(runtime, self(), 0)
    %{logical: logical, runtime: runtime, pid: info.pid}
  end

  defp wait_dead(pid, attempts \\ 100)
  defp wait_dead(pid, 0), do: refute(Process.alive?(pid))

  defp wait_dead(pid, attempts) do
    if Process.alive?(pid) do
      Process.sleep(10)
      wait_dead(pid, attempts - 1)
    else
      :ok
    end
  end

  defp stable_registry_snapshot(attempts \\ 20)
  defp stable_registry_snapshot(0), do: flunk("logical registry kept changing during discovery")

  defp stable_registry_snapshot(attempts) do
    before = registered_participants()

    result =
      NativeInventory.snapshot(7,
        maintenance_token: make_ref(),
        native_session_module: RegistryProjection
      )

    if registered_participants() == before do
      assert {:ok, snapshot} = result
      {before, snapshot}
    else
      # Retry only observed membership changes, never an inventory mismatch on a
      # stable registry. All projection calls here are read-only and immediate.
      stable_registry_snapshot(attempts - 1)
    end
  end

  defp registered_participants do
    Registry.select(Ouroboros.SessionRegistry, [
      {{:"$1", :"$2", :_}, [], [{{:"$1", :"$2"}}]}
    ])
    |> Enum.flat_map(fn
      {{:logical, logical}, pid} -> [{logical, pid}]
      _non_logical -> []
    end)
    |> Enum.sort()
  end

  defp barrier_value(generation, native) do
    root =
      :crypto.hash(:sha256, :erlang.term_to_binary(native.rows, [:deterministic]))
      |> Base.encode16(case: :lower)

    %{
      snapshot: %{
        generation: generation,
        token: root,
        digest: root,
        root_digest: root,
        total: length(native.rows)
      },
      write_epoch: 0,
      native_release: native.release,
      native_rows: native.rows
    }
  end
end
