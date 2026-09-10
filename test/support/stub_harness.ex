defmodule Ouroboros.Test.StubHarness do
  @moduledoc """
  What a stub session needs: an `info` whose `output_cursor` agrees with the `drain`
  fixture.

  The coordinator peeks `info.output_cursor` and calls `drain` only once it has advanced
  past its durable checkpoint, so a stub answering the two from independent fixtures would
  leave its replay reply unreachable. Deriving the cursor from the replay fixture keeps
  them in lockstep by construction: events advertise the highest sequence they carry, and
  an error advertises a cursor no checkpoint reaches — a wedged drain only wedges a reconciliation
  that attempts it.
  """

  def output_cursor({:ok, events}), do: Enum.reduce(events, 0, &max(&1.sequence, &2))
  def output_cursor({:error, _reason}), do: 1_000_000_000
end

defmodule Ouroboros.Test.StubSession do
  @moduledoc """
  A deterministic stand-in for one registered native runtime.

  `Ouroboros.Session` dispatches through `Ouroboros.SessionRegistry`, so
  registering under a session id is enough to reproduce boundaries the real runtime
  never produces on demand: a closed session whose dispatched turn never resolves,
  or a session that answers `info` but wedges on `replay`.
  """

  use GenServer

  alias Ouroboros.Session.RuntimeInfo, as: SessionInfo

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: via(Keyword.fetch!(opts, :session_id)))
  end

  def via(session_id), do: {:via, Registry, {Ouroboros.SessionRegistry, {:runtime, session_id}}}

  @doc "Returns how many replay calls the stub has served since the last change."
  def replay_calls(server), do: GenServer.call(server, :stub_replay_calls)

  @impl true
  def init(opts) do
    {:ok,
     %{
       session_id: Keyword.fetch!(opts, :session_id),
       provider: Keyword.get(opts, :provider, :native),
       state: Keyword.get(opts, :state, :idle),
       replay: Keyword.get(opts, :replay, {:ok, []}),
       send_message: Keyword.get(opts, :send_message, :ok),
       delay_ms: Keyword.get(opts, :delay_ms, 0),
       replay_calls: 0
     }}
  end

  @impl true
  def handle_call(:runtime_info, _from, state) do
    delay(state)
    {:reply, {:ok, info(state)}, state}
  end

  def handle_call({:attach, coordinator, _cursor}, _from, state) do
    attachment = %{runtime_id: state.session_id, generation: "stub-generation", token: make_ref()}

    send(
      coordinator,
      {:session_output, state.session_id, "stub-generation", info(state).output_cursor}
    )

    {:reply, {:ok, attachment, info(state)}, state}
  end

  def handle_call({:drain, _attachment, cursor, limit}, _from, state) do
    delay(state)

    reply =
      case state.replay do
        {:ok, events} ->
          {:ok, events |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit), info(state)}

        error ->
          error
      end

    {:reply, reply, %{state | replay_calls: state.replay_calls + 1}}
  end

  def handle_call({:ack, _attachment, _cursor}, _from, state), do: {:reply, :ok, state}

  # Known, dispatched, and never resolving: `Session.turn_result/2` reports this as a
  # timeout for as long as the caller keeps asking.
  def handle_call({:turn_result, _turn_id}, _from, state),
    do: {:reply, {:error, :timeout}, state}

  # Fault injection for the boundary where the caller sees a GenServer exit before
  # this stand-in performed any turn dispatch. The observer message proves the first
  # call reached this boundary and a same-id replay did not call it a second time.
  def handle_call(
        {:submit, _id, _mode, _request},
        _from,
        %{send_message: {:exit_before_dispatch, observer}} = state
      )
      when is_pid(observer) do
    send(observer, {:stub_session_exited_before_dispatch, state.session_id})
    {:stop, :normal, state}
  end

  def handle_call(
        {:submit, _id, _mode, request},
        _from,
        %{send_message: {:observe, observer, reply}} = state
      )
      when is_pid(observer) do
    send(observer, {:stub_session_send_message, state.session_id, request})
    {:reply, reply, state}
  end

  def handle_call({:submit, _id, _mode, _request}, _from, %{send_message: reply} = state),
    do: {:reply, reply, state}

  def handle_call(:stub_replay_calls, _from, state), do: {:reply, state.replay_calls, state}

  def handle_call(_message, _from, state), do: {:reply, :ok, state}

  defp info(state) do
    SessionInfo.new!(
      session_id: state.session_id,
      runtime_id: state.session_id,
      logical_id: state.session_id,
      generation: "stub-generation",
      pid: self(),
      provider: state.provider,
      state: state.state,
      started_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      output_cursor: Ouroboros.Test.StubHarness.output_cursor(state.replay)
    )
  end

  # Blocking here blocks the coordinator that is calling into the runtime, which is
  # what a wedged provider transport looks like from Ouroboros.
  defp delay(%{delay_ms: 0}), do: :ok
  defp delay(%{delay_ms: delay_ms}), do: Process.sleep(delay_ms)
end
