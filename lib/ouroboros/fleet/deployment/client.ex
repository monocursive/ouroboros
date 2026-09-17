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
  # A deployment asks for a host key, a password with at most three attempts, a passphrase
  # and a plan. Sixty-four is two orders of magnitude of headroom over that; past it, the
  # worker is not running a deployment.
  @max_challenges 64
  # How long a consumed challenge is kept so that a second answer still gets the precise
  # `challenge_consumed` rather than the vaguer `challenge_not_bound`.
  @consumed_grace 300

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

  # EVERY exit, mapped to one of two stable reasons, and the raw reason is discarded here
  # rather than returned.
  #
  # That last part is the whole point. A `GenServer.call` exit carries the *call arguments*
  # in its reason — for `respond` that is the secret — and a reason this returned would be
  # passed to `Ouroboros.Gateway.Methods.Safe.exit_result/1`, Wire-encoded, and written onto
  # the socket as JSON-RPC error data. Catching only the three shapes that were expected let
  # every unexpected one through with the credential attached (review F1). There is no
  # reason here a caller needs that is worth that risk: the worker is either gone or it did
  # not answer, and those are the two answers.
  defp call(pid, message, timeout) do
    GenServer.call(pid, message, timeout)
  catch
    :exit, {:timeout, _mfa} -> {:error, :worker_timeout}
    :exit, _any -> {:error, :worker_unavailable}
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    # Belt to `call/3`'s braces, and the one that holds when a future edit gets it wrong.
    # A sensitive process keeps its mailbox, dictionary and stack out of crash reports,
    # `Process.info/2` and the crash dump — which is exactly where a `respond` call's
    # arguments would otherwise be printed if anything on that path ever raised again.
    _ = :erlang.process_flag(:sensitive, true)

    state = %{
      operation: Keyword.fetch!(opts, :operation),
      instance: Keyword.fetch!(opts, :instance),
      socket_path: Keyword.fetch!(opts, :socket_path),
      subject: Keyword.fetch!(opts, :subject),
      session: Keyword.fetch!(opts, :session),
      cap: Keyword.fetch!(opts, :cap),
      # The worker refuses an attach from a subject other than the operation's owner unless
      # this says so, and records a `takeover` step when it does. The broker has already
      # made the same decision against the journal; this is the half the worker enforces,
      # and the two agreeing is what makes the audit line and the journal tell one story.
      takeover?: Keyword.get(opts, :takeover?, false),
      clock: Keyword.get(opts, :clock, &default_clock/0),
      socket: nil,
      counter: 0,
      pending: %{},
      timers: %{},
      subscribers: %{},
      challenges: %{},
      challenge_seq: 0,
      steps: [],
      log: [],
      state: "attaching",
      kind: nil,
      owner: nil,
      last_error: nil,
      done: nil
    }

    # The connection and the handshake happen in `handle_continue`, not here. `init/1` runs
    # inside `DynamicSupervisor.start_child/2`, which the broker calls from its own
    # `handle_call`: a worker that accepts the socket and then says nothing used to hold the
    # named broker — and therefore every other operation — for the full attach timeout
    # (review F12). Now `prepare` answers as soon as the process exists, in state
    # `attaching`, and the handshake's own failure kills this process rather than the call.
    {:ok, state, {:continue, :attach}}
  end

  @impl true
  def handle_continue(:attach, state) do
    with {:ok, socket} <- connect(state.socket_path),
         {:ok, reply} <- attach(socket, state.cap, state) do
      :ok = :inet.setopts(socket, active: :once)

      # The capability has been presented; there is no reason to keep it.
      {:noreply, adopt_attach(%{state | socket: socket, cap: nil}, reply)}
    else
      {:error, reason} -> {:stop, {:shutdown, {:attach_failed, reason}}, %{state | cap: nil}}
    end
  end

  defp default_clock, do: System.system_time(:second)

  # The path is inspected before the capability is written to it. A socket the worker
  # removed on exit can be replaced by any local account, and connecting first would hand
  # that account a capability it could replay against the real worker (review L1). `lstat`
  # so a symlink is refused rather than followed, and the directory is checked too: a
  # world-writable deploy directory is a place where the swap can still happen.
  defp connect(path) do
    with :ok <- private_socket(path) do
      :gen_tcp.connect({:local, path}, 0, socket_options(), @connect_timeout)
    end
  end

  defp private_socket(path) do
    with {:ok, %File.Stat{type: :other, uid: uid}} <- File.lstat(path),
         true <- uid == own_uid(),
         {:ok, %File.Stat{type: :directory, uid: dir_uid, mode: mode}} <-
           File.lstat(Path.dirname(path)),
         true <- dir_uid == own_uid() and Bitwise.band(mode, 0o077) == 0 do
      :ok
    else
      {:ok, %File.Stat{}} -> {:error, :socket_not_private}
      false -> {:error, :socket_not_private}
      {:error, reason} -> {:error, {:socket_unreadable, reason}}
    end
  end

  # Cached for the life of the VM: it is a fact about the process, it cannot change, and
  # resolving it means running `id -u` through the trusted-executable path.
  defp own_uid do
    case :persistent_term.get({__MODULE__, :uid}, nil) do
      nil ->
        uid = Ouroboros.DataDir.current_uid!()
        :persistent_term.put({__MODULE__, :uid}, uid)
        uid

      uid ->
        uid
    end
  end

  # `buffer` and `recbuf` alongside `packet_size`, and that is not decoration. `packet_size`
  # tells the driver what a legal line may be; `buffer` is how much it will actually
  # accumulate before giving up, and its default is 9216 bytes. Without these two, every
  # worker frame over about nine kilobytes — an ordinary plan, an SSH banner — was delivered
  # as a fragment and reported to the operator as a frame over the one-megabyte cap (review
  # F9). The cap in the protocol and the cap the socket enforces are now the same number.
  defp socket_options do
    [
      :binary,
      packet: :line,
      packet_size: Frame.max_bytes(),
      buffer: Frame.max_bytes(),
      recbuf: Frame.max_bytes(),
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
      "session" => state.session,
      "takeover" => state.takeover?
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
      | state: reply["state"] || "attached",
        kind: reply["kind"] || state.kind,
        # Seam S5's ownership field, echoed by the worker. The broker compares it against
        # the actor asking, so a snapshot that carries it is what makes `status` and
        # `cancel` answerable without a second source of truth.
        owner: string_or_nil(reply["owner"])
    }
  end

  defp string_or_nil(value) when is_binary(value), do: value
  defp string_or_nil(_other), do: nil

  # ---------------------------------------------------------------------------

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, {:ok, snapshot_of(state)}, state}

  # Everything that writes to the socket needs one. While the handshake is still running
  # there is nothing to write to, and saying so is better than blocking the caller until
  # there is (review F12): the operation exists, it is simply not ready to be answered yet.
  def handle_call(_message, _from, %{socket: nil} = state),
    do: {:reply, {:error, :worker_attaching}, state}

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
  defp disconnect({:shutdown, {:attach_failed, _reason}}), do: :attach_failed
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
  #
  # `bound_to` is matched as a map rather than indexed into. A worker that sent a string
  # there used to raise `FunctionClauseError` out of `Access.get/2` and take the whole
  # connection with it (review F3); now it is a frame this build does not understand, which
  # is a thing to drop and log, not a thing to die of.
  defp record_challenge(state, %{"challenge" => id, "bound_to" => bound})
       when is_binary(id) and not is_map(bound) and not is_nil(bound) do
    Logger.warning(
      "fleet deployment worker #{label(state.operation)} issued a challenge whose bound_to " <>
        "is not an object; dropping it"
    )

    state
  end

  defp record_challenge(state, %{"challenge" => id} = frame) when is_binary(id) do
    bound = frame["bound_to"] || %{"subject" => state.subject, "session" => state.session}

    if bound["subject"] == state.subject and bound["session"] == state.session do
      challenge = %{
        id: id,
        kind: frame["kind"],
        expires_at: frame["expires_at"],
        consumed?: false,
        recorded_at: state.clock.(),
        # A sequence, because `recorded_at` is in seconds and a worker can issue a thousand
        # challenges inside one of them: ordering by the clock made "keep the newest" a tie
        # nobody broke, and the challenge an operator was actually answering could be the
        # one evicted.
        seq: state.challenge_seq,
        metadata: challenge_metadata(frame)
      }

      state
      |> put_challenge(id, challenge)
      |> announce(frame)
    else
      Logger.warning(
        "fleet deployment worker #{label(state.operation)} issued challenge #{label(id)} " <>
          "bound to another session; ignoring it"
      )

      state
    end
  end

  defp record_challenge(state, _frame), do: state

  # `steps` is capped and `log` is capped; this was the one collection a worker could grow
  # without bound, and 2 500 challenges of ordinary size came to ten megabytes of retained
  # state per connection (review F2).
  #
  # Two rules, in order. A consumed challenge is dead weight past its grace window — it is
  # kept only so a second answer still gets `challenge_consumed` rather than the vaguer
  # `challenge_not_bound` — so those go first. If that is not enough, the oldest go, and the
  # drop is logged rather than silent: a worker issuing this many challenges is a worker
  # doing something nobody designed for.
  defp put_challenge(state, id, challenge) do
    challenges = Map.put(state.challenges, id, challenge)
    now = state.clock.()

    challenges =
      if map_size(challenges) > @max_challenges,
        do: evict(challenges, now, state.operation),
        else: challenges

    %{state | challenges: challenges, challenge_seq: state.challenge_seq + 1}
  end

  defp evict(challenges, now, operation) do
    kept =
      :maps.filter(
        fn _id, challenge ->
          not (challenge.consumed? and now - challenge.recorded_at > @consumed_grace)
        end,
        challenges
      )

    kept =
      if map_size(kept) > @max_challenges do
        kept
        |> Enum.sort_by(fn {_id, challenge} -> challenge.seq end, :desc)
        |> Enum.take(@max_challenges)
        |> Map.new()
      else
        kept
      end

    if map_size(kept) < map_size(challenges) do
      Logger.warning(
        "fleet deployment worker #{label(operation)} has issued more than " <>
          "#{@max_challenges} challenges; dropping the oldest"
      )
    end

    kept
  end

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
  #
  # Every field is put through a labeller rather than interpolated. `kind` is chosen by the
  # *worker*, and a worker that answered `kind: {"trap": true}` made this line raise
  # `Protocol.UndefinedError` inside the call that was holding the secret — which put the
  # secret in the crash report and, through the exit reason, onto the wire (review F1).
  # Interpolating a value another process chose is the bug; the labeller is the fix.
  defp audit(state, challenge_id, kind, outcome) do
    Logger.info([
      "fleet deployment challenge operation=",
      label(state.operation),
      " challenge=",
      label(challenge_id),
      " kind=",
      label(kind),
      " outcome=",
      label(outcome)
    ])
  end

  @doc false
  # A binary stays a binary (cut, and only if it is printable), an atom becomes its name,
  # and anything else — a map, a list, a number a worker made up — becomes "unknown". This
  # never raises and never grows the line.
  def label(value) when is_binary(value) do
    if String.printable?(value), do: String.slice(value, 0, 64), else: "unknown"
  end

  def label(value) when is_atom(value) and not is_nil(value), do: Atom.to_string(value)
  def label(_other), do: "unknown"

  # ---------------------------------------------------------------------------

  defp snapshot_of(state) do
    %{
      "operation" => state.operation,
      "instance" => state.instance,
      "source" => "worker",
      "attached" => not is_nil(state.socket),
      "state" => state.state,
      "kind" => state.kind,
      # Seam S5's owner, as the worker reports it. Null on a worker that does not yet send
      # it, which is exactly when the broker falls back to refusing a takeover rather than
      # permitting one.
      "owner" => state.owner,
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

  # Seam S4 describes a challenge's kind-specific fields as fields *of the challenge*: a
  # `password` carries `{target, user, port, attempt, max_attempts}`, a `review` carries its
  # plan and digest. The worker sends them one level down, under `metadata`, so this lifts
  # them — a client reads `challenge["plan_digest"]` because that is where the seam says it
  # is, rather than `challenge["metadata"]["plan_digest"]` because that is where this build
  # happened to leave it.
  #
  # Found by driving the real worker. Both fakes had agreed with each other and with the
  # seam; only the worker disagreed, which is the one opinion that decides.
  defp challenge_metadata(frame) do
    raw = Map.drop(frame, ["v", "event", "bound_to", "challenge", "kind", "expires_at"])

    case Map.pop(raw, "metadata") do
      {nested, rest} when is_map(nested) -> Journal.scrub_value(Map.merge(rest, nested))
      _flat -> Journal.scrub_value(raw)
    end
  end
end
