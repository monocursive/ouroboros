defmodule Ouroboros.Provider.Native.MaintenanceFenceIntegrationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Maintenance.{Fence, NativeInventory}
  alias Ouroboros.Session
  alias Ouroboros.Test.NativeModelScript

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

  test "participant death before publication reopens Fence and replacement inherits no token", %{
    root: root
  } do
    context = open_session(root)
    parent = self()

    barrier = fn generation, opts ->
      {:ok, native} = NativeInventory.snapshot(generation, opts)
      send(parent, {:observed, self(), native})

      receive do
        :return -> {:ok, barrier_value(generation, native)}
      end
    end

    start_supervised!(
      {Fence, name: :native_death_fence, data_dir: Path.join(root, "fence-a"), barrier: barrier}
    )

    enter = Task.async(fn -> Fence.enter("death-before-persist", 0, :native_death_fence) end)

    assert_receive {:observed, worker, first}
    send(worker, :return)
    assert_receive {:observed, ^worker, second}
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
    fence_root = Path.join(root, "fence-b")

    barrier = fn generation, opts ->
      with {:ok, native} <- NativeInventory.snapshot(generation, opts),
           do: {:ok, barrier_value(generation, native)}
    end

    start_supervised!(
      {Fence, name: :native_durable_fence, data_dir: fence_root, barrier: barrier}
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
      {Fence, name: :native_durable_fence, data_dir: fence_root, barrier: barrier}
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
