defmodule Ouroboros.Test.StubRun do
  @moduledoc """
  A deterministic stand-in for one supervised Harness run.

  `Jido.Harness.Run` dispatches through `Jido.Harness.RunRegistry`, so registering
  under a run id is enough to hold that boundary still: a provider that answers
  `info` but wedges on `replay` is otherwise unreachable from a test.
  """

  use GenServer

  alias Jido.Harness.RunInfo

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: via(Keyword.fetch!(opts, :run_id)))
  end

  def via(run_id), do: {:via, Registry, {Jido.Harness.RunRegistry, run_id}}

  @doc "Returns how many replay calls the stub has served since the last change."
  def replay_calls(server), do: GenServer.call(server, :stub_replay_calls)

  @doc "Replaces the replay reply and resets the call counter."
  def set_replay(server, reply), do: GenServer.call(server, {:stub_set_replay, reply})

  @impl true
  def init(opts) do
    {:ok,
     %{
       run_id: Keyword.fetch!(opts, :run_id),
       provider: Keyword.get(opts, :provider, :ouroboros_test),
       state: Keyword.get(opts, :state, :running),
       replay: Keyword.get(opts, :replay, {:ok, []}),
       delay_ms: Keyword.get(opts, :delay_ms, 0),
       replay_calls: 0
     }}
  end

  @impl true
  def handle_call(:info, _from, state) do
    delay(state)
    {:reply, {:ok, info(state)}, state}
  end

  def handle_call({:replay, _cursor, _limit}, _from, state) do
    delay(state)
    {:reply, state.replay, %{state | replay_calls: state.replay_calls + 1}}
  end

  def handle_call(:result, _from, state), do: {:reply, {:pending, info(state)}, state}

  def handle_call(:stub_replay_calls, _from, state), do: {:reply, state.replay_calls, state}

  def handle_call({:stub_set_replay, reply}, _from, state) do
    {:reply, :ok, %{state | replay: reply, replay_calls: 0}}
  end

  def handle_call(_message, _from, state), do: {:reply, :ok, state}

  defp info(state) do
    RunInfo.new!(
      run_id: state.run_id,
      provider: state.provider,
      state: state.state,
      started_at: DateTime.utc_now() |> DateTime.to_iso8601()
    )
  end

  # Blocking here blocks the coordinator that is calling into the harness, which is
  # what a wedged provider transport looks like from Ouroboros.
  defp delay(%{delay_ms: 0}), do: :ok
  defp delay(%{delay_ms: delay_ms}), do: Process.sleep(delay_ms)
end

defmodule Ouroboros.Test.StubSession do
  @moduledoc """
  A deterministic stand-in for one supervised Harness session.

  `Jido.Harness.Session` dispatches through `Jido.Harness.SessionRegistry`, so
  registering under a session id is enough to reproduce boundaries the real harness
  never produces on demand: a closed session whose dispatched turn never resolves,
  or a session that answers `info` but wedges on `replay`.
  """

  use GenServer

  alias Jido.Harness.SessionInfo

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: via(Keyword.fetch!(opts, :session_id)))
  end

  def via(session_id), do: {:via, Registry, {Jido.Harness.SessionRegistry, session_id}}

  @doc "Returns how many replay calls the stub has served since the last change."
  def replay_calls(server), do: GenServer.call(server, :stub_replay_calls)

  @impl true
  def init(opts) do
    {:ok,
     %{
       session_id: Keyword.fetch!(opts, :session_id),
       provider: Keyword.get(opts, :provider, :ouroboros_test),
       state: Keyword.get(opts, :state, :idle),
       replay: Keyword.get(opts, :replay, {:ok, []}),
       delay_ms: Keyword.get(opts, :delay_ms, 0),
       replay_calls: 0
     }}
  end

  @impl true
  def handle_call(:info, _from, state) do
    delay(state)
    {:reply, {:ok, info(state)}, state}
  end

  def handle_call({:replay, _cursor, _limit}, _from, state) do
    delay(state)
    {:reply, state.replay, %{state | replay_calls: state.replay_calls + 1}}
  end

  # Known, dispatched, and never resolving: `Session.await/3` reports this as a
  # timeout for as long as the caller keeps asking.
  def handle_call({:turn_result, _turn_id}, _from, state),
    do: {:reply, {:pending, info(state)}, state}

  def handle_call(:stub_replay_calls, _from, state), do: {:reply, state.replay_calls, state}

  def handle_call(_message, _from, state), do: {:reply, :ok, state}

  defp info(state) do
    SessionInfo.new!(
      session_id: state.session_id,
      provider: state.provider,
      state: state.state,
      started_at: DateTime.utc_now() |> DateTime.to_iso8601()
    )
  end

  # Blocking here blocks the coordinator that is calling into the harness, which is
  # what a wedged provider transport looks like from Ouroboros.
  defp delay(%{delay_ms: 0}), do: :ok
  defp delay(%{delay_ms: delay_ms}), do: Process.sleep(delay_ms)
end
