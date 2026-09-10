defmodule Ouroboros.InteractiveNotificationTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Interactive.Task
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.{ControlledModel, NativeConfig}

  setup do
    root = Path.join(System.tmp_dir!(), "j2-notification-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    old = NativeConfig.snapshot()
    old_dir = Application.get_env(:ouroboros, :native_data_dir)
    NativeConfig.configure(%{native: %{test_pid: self()}})
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    {:ok, ref} = InteractiveSession.start(workspace: root, runtime_exposure: false)
    coordinator = Task.whereis(ref.id)

    on_exit(fn ->
      InteractiveSession.close(ref)
      NativeConfig.configure(old)

      if old_dir,
        do: Application.put_env(:ouroboros, :native_data_dir, old_dir),
        else: Application.delete_env(:ouroboros, :native_data_dir)

      File.rm_rf!(root)
    end)

    %{ref: ref, coordinator: coordinator}
  end

  test "an idle attached coordinator has no polling cadence or recurring output timer", ctx do
    :erlang.trace(ctx.coordinator, true, [:receive, {:tracer, self()}])
    Process.sleep(150)
    :erlang.trace(ctx.coordinator, false, [:receive])
    refute_receive {:trace, _, :receive, :poll}, 0
    runtime = :sys.get_state(ctx.coordinator)
    refute Map.has_key?(runtime, :cadence)
    refute Map.has_key?(runtime, :poll_timer)
    assert runtime.reconcile_timer == nil
  end

  test "a running turn sleeps until native output notifies it and then streams the persisted event",
       ctx do
    {:ok, turn} = InteractiveSession.send_message(ctx.ref, "wait for output")
    assert_receive {:ouroboros_test_model_started, _, _, producer}, 3_000
    {:ok, _} = InteractiveSession.subscribe(ctx.ref)
    :erlang.trace(ctx.coordinator, true, [:receive, {:tracer, self()}])
    Process.sleep(100)
    refute_receive {:trace, _, :receive, :poll}, 0
    ControlledModel.emit(producer, :provider_event, %{"kind" => "notified_output"})
    assert_receive {:trace, _, :receive, {:session_output, _, _, _}}, 3_000

    assert_receive {:ouroboros_interactive_event, _, %{payload: %{"kind" => "notified_output"}}},
                   3_000

    :erlang.trace(ctx.coordinator, false, [:receive])
    ControlledModel.finish(producer)
    assert {:ok, %{status: :completed}} = InteractiveSession.await(ctx.ref, turn.id, 3_000)
    await_no_timer(ctx.coordinator)
  end

  test "repeated public reads and subscriptions do not arm an idle timer", ctx do
    for _ <- 1..20 do
      assert {:ok, _} = InteractiveSession.info(ctx.ref)
      assert {:ok, _} = InteractiveSession.subscribe(ctx.ref)
    end

    await_no_timer(ctx.coordinator)
  end

  defp await_no_timer(pid, attempts \\ 300)
  defp await_no_timer(_pid, 0), do: flunk("coordinator retained an idle reconciliation timer")

  defp await_no_timer(pid, attempts) do
    if :sys.get_state(pid).reconcile_timer != nil do
      Process.sleep(2)
      await_no_timer(pid, attempts - 1)
    end
  end
end
