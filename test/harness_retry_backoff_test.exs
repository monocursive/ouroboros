defmodule Ouroboros.HarnessRetryBackoffTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Coding.{Store, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Interactive.{Ref, State}
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.{StubRun, StubSession}

  @provider :ouroboros_test

  test "a wedged coding run checkpoints one error event and backs off" do
    id = unique_id("wedged-task")
    run_id = unique_id("stub-run")

    run =
      start_supervised!(
        {StubRun, run_id: run_id, provider: @provider, replay: {:error, :provider_wedged}}
      )

    {:ok, task} =
      TaskState.new(id, "wedged run", provider: @provider, workspace: File.cwd!())

    assert :ok = Store.create(%{task | status: :running, harness_run_id: run_id})
    on_exit(fn -> retire_task(id) end)

    task_ref = TaskRef.new(id)
    assert {:ok, %TaskState{}} = CodingSession.info(task_ref)

    assert_eventually(fn -> error_count(task_ref, :harness_replay_failed) == 1 end)
    Process.sleep(300)

    # Unbounded retry used to append one durable event per 25ms attempt, evicting
    # real output from the retained ring within minutes.
    assert error_count(task_ref, :harness_replay_failed) == 1
    assert StubRun.replay_calls(run) <= 8

    assert [%{payload: %{consecutive_errors: consecutive}}] =
             error_events(task_ref, :harness_replay_failed)

    assert consecutive == 1

    # A different failure is new information and is checkpointed.
    assert :ok = StubRun.set_replay(run, {:error, :provider_unauthorized})
    assert_eventually(fn -> error_count(task_ref, :harness_replay_failed) == 2 end)

    assert [_first, %{payload: %{consecutive_errors: repeated}}] =
             error_events(task_ref, :harness_replay_failed)

    assert repeated > 1
  end

  test "a wedged interactive session checkpoints one error and backs off" do
    id = unique_id("wedged-session")
    harness_session_id = unique_id("stub-session")

    session =
      start_supervised!(
        {StubSession,
         session_id: harness_session_id,
         provider: @provider,
         state: :idle,
         replay: {:error, :provider_wedged}}
      )

    {:ok, state} = State.new(id, provider: @provider, workspace: File.cwd!())

    assert :ok =
             InteractiveStore.create(%{
               state
               | status: :idle,
                 harness_session_id: harness_session_id
             })

    on_exit(fn -> retire_session(id) end)

    assert {:ok, %State{}} = InteractiveSession.info(Ref.new(id))

    assert_eventually(fn ->
      match?(
        {:ok, %State{error: {:harness_session_replay_failed, :provider_wedged}}},
        InteractiveStore.get(id)
      )
    end)

    assert {:ok, %State{updated_at: checkpointed_at}} = InteractiveStore.get(id)
    Process.sleep(300)

    # A repeated identical error rewrites nothing: the aggregate is untouched.
    assert {:ok, %State{updated_at: ^checkpointed_at}} = InteractiveStore.get(id)
    assert StubSession.replay_calls(session) <= 8
  end

  defp error_events(task_ref, type) do
    {:ok, events} = CodingSession.replay(task_ref, cursor: 0, limit: 1_000)
    Enum.filter(events, &(&1.type == type))
  end

  defp error_count(task_ref, type), do: task_ref |> error_events(type) |> length()

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

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
