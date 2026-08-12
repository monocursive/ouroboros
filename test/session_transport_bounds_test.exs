defmodule Ouroboros.SessionTransportBoundsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Coding.{Store, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Interactive.{Ref, State}
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.{StubRun, StubSession}

  @provider :ouroboros_test
  @timeout_key :session_call_timeout
  @wedged_ms 1_500

  setup do
    previous = Application.get_env(:ouroboros, @timeout_key)
    Application.put_env(:ouroboros, @timeout_key, 100)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ouroboros, @timeout_key)
        value -> Application.put_env(:ouroboros, @timeout_key, value)
      end
    end)

    :ok
  end

  test "a wedged coding coordinator times out the caller instead of blocking forever" do
    id = unique_id("wedged-transport-task")
    run_id = unique_id("stub-run")

    start_supervised!({StubRun, run_id: run_id, provider: @provider, delay_ms: @wedged_ms})

    {:ok, task} =
      TaskState.new(id, "wedged transport", provider: @provider, workspace: File.cwd!())

    assert :ok = Store.create(%{task | status: :running, harness_run_id: run_id})
    on_exit(fn -> retire_task(id) end)

    assert {:error, :timeout} = timed(fn -> CodingSession.info(TaskRef.new(id)) end)
  end

  test "a wedged interactive coordinator times out the caller instead of blocking forever" do
    id = unique_id("wedged-transport-session")
    harness_session_id = unique_id("stub-session")

    start_supervised!(
      {StubSession, session_id: harness_session_id, provider: @provider, delay_ms: @wedged_ms}
    )

    {:ok, session} = State.new(id, provider: @provider, workspace: File.cwd!())

    assert :ok =
             InteractiveStore.create(%{
               session
               | status: :idle,
                 harness_session_id: harness_session_id
             })

    on_exit(fn -> retire_session(id) end)

    assert {:error, :timeout} = timed(fn -> InteractiveSession.info(Ref.new(id)) end)
  end

  # The bound is only meaningful if it returns well before the wedge clears.
  defp timed(fun) do
    started = System.monotonic_time(:millisecond)
    result = fun.()
    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < @wedged_ms
    result
  end

  defp retire_task(id) do
    case Store.get(id) do
      {:ok, task} ->
        _ = Store.put(%{task | status: :cancelled})
        _ = Store.delete(id)

      _other ->
        :ok
    end
  end

  defp retire_session(id) do
    case InteractiveStore.get(id) do
      {:ok, session} ->
        _ = InteractiveStore.put(%{session | status: :cancelled})
        _ = InteractiveStore.delete(id)

      _other ->
        :ok
    end
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
