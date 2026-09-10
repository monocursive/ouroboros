defmodule Ouroboros.HarnessRetryBackoffTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Interactive.{Ref, State}
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.StubSession

  @provider :native

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
                 runtime_id: harness_session_id
             })

    on_exit(fn -> retire_session(id) end)

    assert {:ok, %State{}} = InteractiveSession.info(Ref.new(id))

    assert_eventually(fn ->
      match?(
        {:ok, %State{error: {:runtime_drain_failed, :provider_wedged}}},
        InteractiveStore.get(id)
      )
    end)

    assert {:ok, %State{updated_at: checkpointed_at}} = InteractiveStore.get(id)
    Process.sleep(300)

    # A repeated identical error rewrites nothing: the aggregate is untouched.
    assert {:ok, %State{updated_at: ^checkpointed_at}} = InteractiveStore.get(id)
    assert StubSession.replay_calls(session) <= 8
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
