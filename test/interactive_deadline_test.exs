defmodule Ouroboros.InteractiveDeadlineTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.TurnRequest
  alias Ouroboros.Interactive.{Ref, State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.StubSession
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @provider :ouroboros_test
  @deadline_key :interactive_unresolved_turn_deadline_ms

  setup do
    workspace =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-interactive-deadline-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(workspace)

    start_supervised!(
      {Workspace,
       allowed_roots: [workspace],
       name: WorkspaceManager,
       id: {:interactive_deadline_workspace, System.unique_integer([:positive, :monotonic])}}
    )

    previous_deadline = Application.get_env(:ouroboros, @deadline_key)

    on_exit(fn ->
      restore_deadline(previous_deadline)
      File.rm_rf(workspace)
    end)

    {:ok, workspace: workspace}
  end

  test "an unresolved turn at session close settles as ambiguous once the deadline expires", %{
    workspace: workspace
  } do
    Application.put_env(:ouroboros, @deadline_key, 0)
    %{id: id, turn_id: turn_id, ref: ref} = start_livelocked_session(workspace)

    waiter = Elixir.Task.async(fn -> InteractiveSession.await(ref, turn_id, 5_000) end)

    assert {:ok, %{status: :ambiguous, error: {:unresolved_at_session_close, ^turn_id}}} =
             Elixir.Task.await(waiter, 6_000)

    assert {:ok, %State{status: :closed} = session} = InteractiveSession.info(ref)
    assert session.turns[turn_id].status == :ambiguous

    # The session reaches its terminal state, so the workspace lease it was holding
    # is released and the coordinator retires instead of polling forever.
    assert_eventually(fn -> Workspace.list() == [] end)
    assert_eventually(fn -> Task.whereis(id) == nil end)
    assert :ok = Store.delete(id)
  end

  test "the wait is bounded by the deadline, not abandoned before it", %{workspace: workspace} do
    Application.put_env(:ouroboros, @deadline_key, 60_000)
    %{id: id, turn_id: turn_id, ref: ref} = start_livelocked_session(workspace)

    Process.sleep(200)

    assert {:ok, %State{status: :idle} = session} = InteractiveSession.info(ref)
    assert session.turns[turn_id].status == :running
    assert [_lease] = Workspace.list()

    Application.put_env(:ouroboros, @deadline_key, 0)

    assert_eventually(fn ->
      match?({:ok, %State{status: :closed}}, InteractiveSession.info(ref))
    end)

    assert_eventually(fn -> Task.whereis(id) == nil end)
    assert :ok = Store.delete(id)
  end

  defp start_livelocked_session(workspace) do
    id = unique_id("deadline-session")
    turn_id = unique_id("deadline-turn")
    harness_session_id = unique_id("stub-session")
    harness_turn_id = unique_id("stub-turn")

    # A provider session that has already closed but still reports one dispatched
    # turn as pending: `Session.await/3` answers `{:error, :timeout}` forever.
    start_supervised!(
      {StubSession, session_id: harness_session_id, provider: @provider, state: :closed}
    )

    {:ok, session} = State.new(id, provider: @provider, workspace: workspace)
    {:ok, request} = TurnRequest.new("work that may well have happened")

    turn =
      turn_id
      |> State.new_turn(:message, request)
      |> Map.put(:harness_turn_id, harness_turn_id)
      |> Map.put(:status, :running)

    assert :ok =
             Store.create(%{
               session
               | status: :idle,
                 harness_session_id: harness_session_id,
                 turns: %{turn_id => turn}
             })

    ref = Ref.new(id)
    assert {:ok, %State{}} = InteractiveSession.info(ref)

    %{id: id, turn_id: turn_id, ref: ref}
  end

  defp restore_deadline(nil), do: Application.delete_env(:ouroboros, @deadline_key)
  defp restore_deadline(value), do: Application.put_env(:ouroboros, @deadline_key, value)

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
