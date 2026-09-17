defmodule Ouroboros.Fleet.Deployment.Client do
  @moduledoc """
  One process holding one deployment worker's socket (seams S3 and S4).

  The worker is not this runtime's child — it was forked detached and outlives the BEAM by
  design — so this is a *client*, not a supervisor of it. It connects to the worker's Unix
  socket, presents the capability file's contents in its first frame, and from then on owns
  exactly two things: the frames in flight, and what this connection is allowed to answer.

  ## The secret never lands here

  `respond/5` is the only entry point that takes one, and it is called *by the caller's own
  process*: the broker never sees it, because a secret that passes through a named singleton
  passes through that singleton's mailbox and its crash dumps. Inside this process the
  response travels from the call argument into `Frame.encode/1` and onto the socket, and is
  referenced nowhere afterwards. It is never put in `state`, never logged, and never handed
  to `inspect/1`. The audit line this writes names the operation, the challenge, its kind and
  the outcome, which is the allowlist the spec's "Secret handling and authorization" section
  gives.

  ## What this refuses before the worker hears about it

  A challenge is bound at issue to the subject and session that were attached (S4). A
  response from a different identity or a different browser/listener session is refused here
  — `challenge_not_bound` — and the frame is never written. So are a response after the
  challenge's own expiry (`challenge_expired`), a second response to one already answered
  (`challenge_consumed`), and a response of the wrong shape for the challenge's kind
  (`challenge_kind_mismatch`), which is what stops a host-trust acceptance from being
  delivered as an answer to a password prompt.

  ## Frames are bounded by the socket, not by hope

  The socket is opened with `packet: :line` and `packet_size`, so a worker that writes past
  the cap without a newline stops being accumulated inside the driver rather than making
  this runtime buffer it. What the driver then hands over is a *fragment*, which is
  recognisable because it does not end in a newline — measuring what arrived would mean
  having already held it. A fragment ends this connection, and only this connection: the
  broker records a disconnect and stays up.
  """

  # `:temporary`, and that is a correctness property rather than a preference. This process
  # holds a connection to an operating-system process it did not start and cannot restart.
  # Restarting it would reconnect to a socket the worker has removed, fail, and be restarted
  # again until the supervisor above gave up and took the surface tree down with it. A lost
  # connection is a fact about the worker, not a fault in this process: the broker records
  # the disconnect, and `fleet.deployment.resume` is the verb that starts a *new* worker.
  use GenServer, restart: :temporary

  require Logger

  alias Ouroboros.Fleet.Deployment.Frame
  alias Ouroboros.Fleet.Deployment.Journal

  @connect_timeout 5_000
  @attach_timeout 10_000
  @request_timeout 30_000
  # Enough to render the tail of an operation without turning this process into a log store.
  @max_log 50
  @max_steps 200

  @typedoc "Who is asking, as `Audit.Identity.actor/0` and the client session id."
  @type binding :: %{subject: String.t(), session: String.t()}

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "The sanitized snapshot of everything this connection knows about its operation."
  @spec snapshot(pid()) :: {:ok, map()} | {:error, term()}
  def snapshot(pid), do: call(pid, :snapshot, @request_timeout)

  @doc """
  Answers one challenge.

  `expect` is the set of challenge kinds this verb may answer; `response` is the object the
  worker gets verbatim. Called from the caller's process so that a secret inside `response`
  never enters the broker.
  """
  @spec respond(pid(), String.t(), [String.t()], map(), binding()) ::
          {:ok, map()} | {:error, term()}
  def respond(pid, challenge, expect, response, binding)
      when is_binary(challenge) and is_list(expect) and is_map(response) and is_map(binding) do
    call(pid, {:respond, challenge, expect, response, binding}, @request_timeout)
  end

  @doc "Asks the worker to stop at a safe boundary and report its residue."
  @spec cancel(pid()) :: {:ok, map()} | {:error, term()}
  def cancel(pid), do: call(pid, :cancel, @request_timeout)

  @doc "Sends `{:ouroboros_fleet_deployment, operation, event}` to `pid` for every event."
  @spec subscribe(pid(), pid()) :: :ok
  def subscribe(pid, subscriber), do: GenServer.cast(pid, {:subscribe, subscriber})

  @doc "Stops sending events to `pid`."
  @spec unsubscribe(pid(), pid()) :: :ok
  def unsubscribe(pid, subscriber), do: GenServer.cast(pid, {:unsubscribe, subscriber})

  # A client that has just died is a disconnected worker, which every caller here already
  # has an answer for. Turning the exit into that answer keeps a race between "the worker
  # closed" and "somebody asked" from crashing the asker.
  defp call(pid, message, timeout) do
    GenServer.call(pid, message, timeout)
  catch
    :exit, {reason, _mfa} when reason in [:noproc, :normal, :shutdown] ->
      {:error, :worker_unavailable}

    :exit, {{:shutdown, _detail}, _mfa} ->
      {:error, :worker_unavailable}

    :exit, {:timeout, _mfa} ->
      {:error, :worker_timeout}
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    state = %{
      operation: Keyword.fetch!(opts, :operation),
      instance: Keyword.fetch!(opts, :instance),
      socket_path: Keyword.fetch!(opts, :socket_path),
      subject: Keyword.fetch!(opts, :subject),
      session: Keyword.fetch!(opts, :session),
      clock: Keyword.get(opts, :clock, &default_clock/0),
      socket: nil,
      counter: 0,
      pending: %{},
      timers: %{},
      subscribers: %{},
      challenges: %{},
      steps: [],
      log: [],
      state: nil,
      kind: nil,
      last_error: nil,
      done: nil
    }

    cap = Keyword.fetch!(opts, :cap)

    with {:ok, socket} <- connect(state.socket_path),
         {:ok, reply} <- attach(socket, cap, state) do
      :ok = :inet.setopts(socket, active: :once)
      {:ok, adopt_attach(%{state | socket: socket}, reply)}
    else
      {:error, reason} -> {:stop, {:attach_failed, reason}}
    end
  end

  defp default_clock, do: System.system_time(:second)

  defp connect(path) do
    :gen_tcp.connect({:local, path}, 0, socket_options(), @connect_timeout)
  end

  defp socket_options do
    [
      :binary,
      packet: :line,
      packet_size: Frame.max_bytes(),
      active: false,
      nodelay: true
    ]
  end

  # The handshake runs synchronously, before the socket goes active: a worker that will not
  # accept this capability, or belongs to another operation, must never become a process
  # somebody can send a credential to.
  defp attach(socket, cap, state) do
    frame = %{
      "v" => 1,
      "id" => "attach",
      "op" => "attach",
      "cap" => cap,
      "subject" => state.subject,
      "session" => state.session
    }

    with {:ok, line} <- Frame.encode(frame),
         :ok <- :gen_tcp.send(socket, line),
         {:ok, raw} <- :gen_tcp.recv(socket, 0, @attach_timeout),
         {:ok, reply} <- Frame.decode(raw) do
      verify_attach(reply, state)
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_attach(%{"ok" => true, "operation" => operation, "instance" => instance} = reply, %{
         operation: operation,
         instance: instance
       }) do
    {:ok, reply}
  end

  # Seam S2's whole point: a reconnect verifies the worker's instance identity rather than
  # trusting that whatever is listening on this path is the process that printed it.
  defp verify_attach(%{"ok" => true}, _state), do: {:error, :instance_mismatch}

  defp verify_attach(%{"ok" => false, "reason" => reason}, _state),
    do: {:error, {:refused, reason}}

  defp verify_attach(_frame, _state), do: {:error, :attach_not_answered}

  defp adopt_attach(state, reply) do
    %{
      state
      | state: reply["state"] || state.state,
        kind: reply["kind"] || state.kind
    }
  end

  # ---------------------------------------------------------------------------

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, {:ok, snapshot_of(state)}, state}

  def handle_call({:respond, challenge_id, expect, response, binding}, from, state) do
    now = state.clock.()

    case authorize(state, challenge_id, expect, binding, now) do
      {:ok, challenge} ->
        # Consumed at the moment it is sent, not when the answer comes back: two responses
        # racing on one challenge must not both reach the worker, and a worker that never
        # answers must not leave a challenge somebody can try again with a second guess.
        state = put_in(state.challenges[challenge_id], %{challenge | consumed?: true})

        deliver(
          state,
          from,
          %{"op" => "respond", "challenge" => challenge_id, "response" => response},
          challenge
        )

      {:error, reason} ->
        audit(state, challenge_id, kind_of(state, challenge_id), reason)
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:cancel, from, state), do: deliver(state, from, %{"op" => "cancel"}, nil)

  @impl true
  def handle_cast({:subscribe, pid}, state) do
    if Map.has_key?(state.subscribers, pid) do
      {:noreply, state}
    else
      ref = Process.monitor(pid)
      {:noreply, put_in(state.subscribers[pid], ref)}
    end
  end

  def handle_cast({:unsubscribe, pid}, state), do: {:noreply, drop_subscriber(state, pid)}

  @impl true
  # A frame is a line, and `packet_size` is what stops one from being buffered without
  # bound: past the cap the driver stops accumulating and hands over what it has. What it
  # hands over is therefore a *fragment*, and a fragment is recognisable — it does not end
  # in a newline. That is the check, rather than measuring what arrived: by the time this
  # process could measure a whole oversized line, the runtime would already have held it.
  #
  # The connection ends here. Only this connection: the broker records the disconnect and
  # stays up, which is the difference between one worker misbehaving and this runtime going
  # down with it.
  def handle_info({:tcp, socket, line}, %{socket: socket} = state) do
    if String.ends_with?(line, "\n") do
      :ok = :inet.setopts(socket, active: :once)
      decode_frame(state, line)
    else
      Logger.warning(
        "fleet deployment worker #{state.operation} wrote a frame over the " <>
          "#{Frame.max_bytes()} byte cap; dropping the connection"
      )

      {:stop, {:shutdown, {:frame_too_large, byte_size(line)}}, state}
    end
  end

  def handle_info({:tcp_error, socket, reason}, %{socket: socket} = state),
    do: {:stop, {:shutdown, {:socket_error, reason}}, state}

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state),
    do: {:stop, {:shutdown, :worker_disconnected}, state}

  def handle_info({:request_timeout, id}, state) do
    case pop_in(state.pending[id]) do
      {nil, state} ->
        {:noreply, state}

      {from, state} ->
        GenServer.reply(from, {:error, :worker_timeout})
        {:noreply, %{state | timers: Map.delete(state.timers, id)}}
    end
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state),
    do: {:noreply, drop_subscriber(state, pid)}

  def handle_info(_other, state), do: {:noreply, state}

  defp decode_frame(state, line) do
    case Frame.decode(line) do
      {:ok, frame} ->
        {:noreply, receive_frame(state, frame)}

      {:error, {:frame_too_large, bytes}} ->
        {:stop, {:shutdown, {:frame_too_large, bytes}}, state}

      {:error, reason} ->
        Logger.warning(
          "fleet deployment worker #{state.operation} sent an unreadable frame: #{reason}"
        )

        {:noreply, state}
    end
  end

  @impl true
  def terminate(reason, state) do
    # Every caller still waiting is told the truth rather than left to its own timeout, and
    # every subscriber learns the operation lost its worker. A challenge this connection was
    # holding dies with it: an unconsumed secret has nowhere to go, and the next attached
    # client gets a fresh challenge rather than inheriting this one.
    Enum.each(state.pending, fn {_id, from} ->
      GenServer.reply(from, {:error, disconnect(reason)})
    end)

    broadcast(state, %{
      "event" => "disconnected",
      "operation" => state.operation,
      "reason" => to_string(disconnect(reason))
    })

    if state.socket, do: :gen_tcp.close(state.socket)
    :ok
  end

  defp disconnect({:shutdown, {:frame_too_large, _detail}}), do: :worker_frame_too_large
  defp disconnect({:shutdown, {:socket_error, _reason}}), do: :worker_unavailable
  defp disconnect(_reason), do: :worker_unavailable

  # ---------------------------------------------------------------------------
  # Sending

  defp deliver(state, from, body, challenge) do
    id = "c" <> Integer.to_string(state.counter)
    frame = Map.merge(%{"v" => 1, "id" => id}, body)

    case Frame.encode(frame) do
      {:ok, line} ->
        case :gen_tcp.send(state.socket, line) do
          :ok ->
            timer = Process.send_after(self(), {:request_timeout, id}, @request_timeout)

            state = %{
              state
              | counter: state.counter + 1,
                pending: Map.put(state.pending, id, from),
                timers: Map.put(state.timers, id, timer)
            }

            if challenge, do: audit(state, challenge.id, challenge.kind, :sent)
            {:noreply, state}

          {:error, reason} ->
            {:reply, {:error, {:worker_unreachable, reason}}, state}
        end

      {:error, {:frame_too_large, bytes}} ->
        {:reply, {:error, {:frame_too_large, bytes}}, state}
    end
  end

  # ---------------------------------------------------------------------------
  # Receiving

  defp receive_frame(state, frame) do
    if Frame.event?(frame), do: apply_event(state, frame), else: apply_reply(state, frame)
  end

  defp apply_reply(state, %{"id" => id} = frame) do
    case pop_in(state.pending[id]) do
      {nil, state} ->
        state

      {from, state} ->
        state = cancel_timer(state, id)
        GenServer.reply(from, reply_of(frame))
        state
    end
  end

  defp apply_reply(state, _frame), do: state

  defp reply_of(%{"ok" => true} = frame), do: {:ok, Journal.scrub_value(Map.drop(frame, ["v"]))}

  defp reply_of(%{"ok" => false} = frame),
    do: {:error, {:worker_refused, frame["reason"] || "unknown", frame["detail"]}}

  defp reply_of(_frame), do: {:error, :worker_answered_nothing}

  defp cancel_timer(state, id) do
    case Map.pop(state.timers, id) do
      {nil, timers} ->
        %{state | timers: timers}

      {timer, timers} ->
        Process.cancel_timer(timer)
        %{state | timers: timers}
    end
  end

  defp apply_event(state, %{"event" => "state"} = frame) do
    state
    |> Map.put(:state, frame["state"] || state.state)
    |> announce(frame)
  end

  defp apply_event(state, %{"event" => "step"} = frame) do
    step = Journal.scrub_value(Map.drop(frame, ["v", "event"]))

    %{state | steps: Enum.take(state.steps ++ [step], -@max_steps)}
    |> announce(frame)
  end

  defp apply_event(state, %{"event" => "challenge"} = frame), do: record_challenge(state, frame)

  defp apply_event(state, %{"event" => "log"} = frame) do
    line = Journal.scrub_value(Map.drop(frame, ["v", "event"]))

    %{state | log: Enum.take(state.log ++ [line], -@max_log)}
    |> announce(frame)
  end

  defp apply_event(state, %{"event" => "done"} = frame) do
    %{
      state
      | done: Journal.scrub_value(Map.drop(frame, ["v", "event"])),
        state: frame["state"] || state.state,
        last_error: frame["error"] || state.last_error
    }
    |> announce(frame)
  end

  defp apply_event(state, frame), do: announce(state, frame)

  # A challenge names the subject and session it was issued to. This connection attached as
  # exactly one of those, so a challenge naming a different one is not this connection's to
  # hold — it is dropped rather than recorded, and nobody here can answer it.
  defp record_challenge(state, %{"challenge" => id} = frame) when is_binary(id) do
    bound = frame["bound_to"] || %{"subject" => state.subject, "session" => state.session}

    if bound["subject"] == state.subject and bound["session"] == state.session do
      challenge = %{
        id: id,
        kind: frame["kind"],
        expires_at: frame["expires_at"],
        consumed?: false,
        metadata: Journal.scrub_value(Map.drop(frame, ["v", "event", "bound_to"]))
      }

      %{state | challenges: Map.put(state.challenges, id, challenge)}
      |> announce(frame)
    else
      Logger.warning(
        "fleet deployment worker #{state.operation} issued challenge #{id} bound to another " <>
          "session; ignoring it"
      )

      state
    end
  end

  defp record_challenge(state, _frame), do: state

  defp announce(state, frame) do
    broadcast(state, frame)
    state
  end

  defp broadcast(state, frame) do
    event = Journal.scrub_value(Map.drop(frame, ["v"]))

    Enum.each(
      Map.keys(state.subscribers),
      &send(&1, {:ouroboros_fleet_deployment, state.operation, event})
    )
  end

  defp drop_subscriber(state, pid) do
    case Map.pop(state.subscribers, pid) do
      {nil, _subscribers} ->
        state

      {ref, subscribers} ->
        Process.demonitor(ref, [:flush])
        %{state | subscribers: subscribers}
    end
  end

  # ---------------------------------------------------------------------------
  # Authorization

  # Order matters and is the order an operator reads it in: is this yours, is it still open,
  # has it already been answered, and is it the kind this verb answers. An unknown challenge
  # answers `challenge_not_bound` rather than "no such challenge", because the caller that
  # is not bound to it has no business learning whether it exists.
  defp authorize(state, id, expect, binding, now) do
    with {:ok, challenge} <- fetch(state, id, binding),
         :ok <- unexpired(challenge, now),
         :ok <- unconsumed(challenge),
         :ok <- expected_kind(challenge, expect) do
      {:ok, challenge}
    end
  end

  defp fetch(state, id, binding) do
    case Map.fetch(state.challenges, id) do
      {:ok, challenge} ->
        if binding[:subject] == state.subject and binding[:session] == state.session,
          do: {:ok, challenge},
          else: {:error, :challenge_not_bound}

      :error ->
        {:error, :challenge_not_bound}
    end
  end

  # A challenge with no expiry the worker declared is treated as open: this runtime does not
  # invent a deadline the worker never agreed to and then refuse an answer the worker would
  # have taken.
  defp unexpired(%{expires_at: nil}, _now), do: :ok

  defp unexpired(%{expires_at: expires_at}, now) do
    case parse_time(expires_at) do
      {:ok, seconds} -> if seconds > now, do: :ok, else: {:error, :challenge_expired}
      :error -> :ok
    end
  end

  defp unconsumed(%{consumed?: true}), do: {:error, :challenge_consumed}
  defp unconsumed(_challenge), do: :ok

  defp expected_kind(%{kind: kind}, expect) do
    if kind in expect, do: :ok, else: {:error, :challenge_kind_mismatch}
  end

  defp parse_time(value) when is_integer(value), do: {:ok, value}

  defp parse_time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, at, _offset} -> {:ok, DateTime.to_unix(at)}
      _other -> :error
    end
  end

  defp parse_time(_other), do: :error

  defp kind_of(state, id) do
    case Map.fetch(state.challenges, id) do
      {:ok, %{kind: kind}} -> kind
      :error -> nil
    end
  end

  # The allowlist, and nothing else: operation, challenge id, challenge kind, outcome. The
  # response object is not an argument to this function, so no future edit to this line can
  # accidentally start printing it.
  defp audit(state, challenge_id, kind, outcome) do
    Logger.info(
      "fleet deployment challenge operation=#{state.operation} challenge=#{challenge_id} " <>
        "kind=#{kind || "unknown"} outcome=#{outcome}"
    )
  end

  # ---------------------------------------------------------------------------

  defp snapshot_of(state) do
    %{
      "operation" => state.operation,
      "instance" => state.instance,
      "source" => "worker",
      "attached" => true,
      "state" => state.state,
      "kind" => state.kind,
      "steps" => state.steps,
      "log" => state.log,
      "last_error" => Journal.scrub_value(state.last_error),
      "done" => state.done,
      "challenges" =>
        state.challenges
        |> Map.values()
        |> Enum.reject(& &1.consumed?)
        |> Enum.map(&challenge_view/1)
        |> Enum.sort_by(& &1["challenge"])
    }
  end

  defp challenge_view(challenge) do
    challenge.metadata
    |> Map.put("challenge", challenge.id)
    |> Map.put("kind", challenge.kind)
    |> Map.put("expires_at", challenge.expires_at)
  end
end
