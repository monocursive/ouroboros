defmodule Ouroboros.Fleet.Deployment.Worker do
  @moduledoc """
  One process per running operation, owning one port program (§8, §9).

  `ouro fleet <kind> … --frames --operation <id>` speaks NDJSON on its own stdin and stdout.
  This process opens it as a port, decodes its frames with
  `Ouroboros.Fleet.Deployment.Frame`, keeps the last state, the steps, the open challenge and
  the last #{50} log lines, and forwards every frame to its subscribers.

  ## The program is not this process's child in the sense that matters

  It calls `setsid` at start and ignores `SIGHUP` and `SIGPIPE`, and once the review is
  accepted it needs nothing more from stdin: on EOF it finishes the operation, keeps writing
  the journal, and stops writing to stdout (§8). So killing *this* process closes the port,
  which closes the program's stdin, which the program reads as "carry on without me" rather
  than as a signal. That is the whole of how a local `setup` survives the runtime it was
  started from, and there is no reattach: what happened afterwards is in the journal.

  Erlang does not signal a port program when the port closes — it closes the pipes and reaps
  the exit — so this property is the platform's and not a favour this module does.

  ## Where the secret is, and is not

  `respond/3` is the only entry point that takes one, and it is called *by the gateway
  connection's own process*: the broker never sees it, because a secret that passes through a
  named singleton passes through that singleton's mailbox and its crash dumps. Inside this
  process the response travels from the call argument into `Frame.encode/1` and onto the
  port, and is referenced nowhere afterwards. It is never put in `state`, never logged and
  never handed to `inspect/1`.

  Two belts hold that where a future edit might not. The process is `:sensitive`, which keeps
  its mailbox, dictionary and stack out of `Process.info/2` and the crash dump; and
  `format_status/1` replaces the last message and the state in the report OTP's `gen_server`
  writes when this process dies, because that report prints `last_message` regardless.
  """

  use GenServer, restart: :temporary

  require Logger

  alias Ouroboros.Fleet.Deployment.Frame
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher

  # Enough to render the tail of an operation without turning this process into a log store.
  @max_log 50
  @max_steps 200
  # A `respond` is one encode and one write to a pipe. A ceiling exists so that a program
  # that has stopped reading its stdin cannot wedge the gateway connection that is answering
  # a prompt.
  @call_timeout 15_000

  @typedoc "What `status/1` answers, and what a subscriber's frames are bounded the same way."
  @type snapshot :: map()

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "Everything this process knows about its operation, sanitized."
  @spec snapshot(pid()) :: {:ok, snapshot()} | {:error, term()}
  def snapshot(pid), do: call(pid, :snapshot)

  @doc """
  Answers the open challenge.

  `response` is `%{"accept" => bool}` for `host_trust` and `review` and
  `%{"secret" => binary}` for `password` and `passphrase`. Called from the caller's process
  so that a secret inside it never enters the broker; see the module note.
  """
  @spec respond(pid(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def respond(pid, challenge, response) when is_binary(challenge) and is_map(response),
    do: call(pid, {:respond, challenge, response})

  @doc "Asks the program to stop at a safe boundary."
  @spec cancel(pid()) :: {:ok, map()} | {:error, term()}
  def cancel(pid), do: call(pid, :cancel)

  @doc """
  Sends `{:ouroboros_fleet_deployment, operation, frame}` to the caller for every frame.

  No session travels with it. A challenge is answered by whoever is an administrator on this
  runtime (§10), so a subscription is a subscription and not a claim on the prompts.
  """
  @spec subscribe(pid(), pid()) :: :ok
  def subscribe(worker, subscriber), do: GenServer.call(worker, {:subscribe, subscriber})

  @doc "Stops the caller's subscription."
  @spec unsubscribe(pid(), pid()) :: :ok
  def unsubscribe(worker, subscriber), do: GenServer.call(worker, {:unsubscribe, subscriber})

  # The exit reason is discarded rather than wrapped, because an exit reason is an argument
  # list: a `{:respond, …, %{"secret" => …}}` call that timed out carries the secret in the
  # `{:timeout, {GenServer, :call, [...]}}` term the caller would otherwise propagate.
  defp call(pid, message) do
    GenServer.call(pid, message, @call_timeout)
  catch
    :exit, {:timeout, _mfa} -> {:error, :worker_timeout}
    :exit, _any -> {:error, :worker_unavailable}
  end

  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    _ = :erlang.process_flag(:sensitive, true)

    state = %{
      operation: Keyword.fetch!(opts, :operation),
      kind: Keyword.fetch!(opts, :kind),
      argv: Keyword.fetch!(opts, :argv),
      data_dir: Keyword.fetch!(opts, :data_dir),
      executable: Keyword.fetch!(opts, :executable),
      port: nil,
      os_pid: nil,
      state: "running",
      steps: [],
      challenge: nil,
      answered: MapSet.new(),
      log: [],
      plan: nil,
      summary: nil,
      last_error: nil,
      done?: false,
      exit_status: nil,
      # A line longer than the port's own cap arrives in pieces, none of which is a frame.
      # The first piece is refused and the rest are swallowed rather than measured: measuring
      # what arrived would mean having already held it.
      oversize?: false,
      # Whether this program has done anything beyond announcing a state. A refusal's whole
      # output is a state and a `done`; work starts with a step, a log line or a challenge.
      progressed?: false,
      subscribers: %{}
    }

    {:ok, state, {:continue, :open}}
  end

  # OTP's `gen_server` terminate report prints `last_message` even for a `:sensitive`
  # process. `format_status/1` is the callback that report consults.
  @impl true
  def format_status(status) when is_map(status) do
    status
    |> Map.put(:message, :redacted)
    |> Map.update(:state, nil, &redact/1)
  end

  defp redact(%{operation: operation, state: run_state}),
    do: %{operation: operation, state: run_state, rest: :redacted}

  defp redact(_other), do: :redacted

  @impl true
  def handle_continue(:open, state) do
    port =
      Port.open({:spawn_executable, state.executable}, [
        :binary,
        :exit_status,
        :hide,
        {:line, Frame.max_bytes()},
        {:args, state.argv},
        {:env, Launcher.child_env(state.data_dir)}
      ])

    os_pid =
      case Port.info(port, :os_pid) do
        {:os_pid, pid} -> pid
        _gone -> nil
      end

    {:noreply, %{state | port: port, os_pid: os_pid}}
  rescue
    exception ->
      Logger.warning(
        "fleet deployment operation #{state.operation} could not start its program: " <>
          Exception.message(exception)
      )

      {:stop, {:shutdown, {:worker_spawn_failed, :port_open_failed}}, state}
  end

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, {:ok, view(state)}, state}

  def handle_call({:respond, challenge, response}, _from, state) do
    case authorize(state, challenge, response) do
      {:ok, frame} ->
        case write(state, frame) do
          :ok ->
            audit(state, challenge)

            {:reply, {:ok, %{"accepted" => true}},
             %{
               state
               | challenge: nil,
                 answered: MapSet.put(state.answered, challenge)
             }}

          {:error, reason} ->
            audit(state, challenge, reason)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        audit(state, challenge, reason)
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:cancel, _from, state) do
    case write(state, %{"op" => "cancel"}) do
      # §9's table answers `{state}`, and the contract text beside it says a cancel reports
      # residue. Both come back here: the state this process holds, and the residue the
      # program has durably recorded, because residue is a thing a program writes down
      # rather than a frame it sends. `%{"cancelling" => true}` was neither, which is why
      # the page's "What this left behind" panel could not be drawn by any path.
      :ok -> {:reply, {:ok, %{"state" => state.state, "residue" => residue(state)}}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:probe, _from, state) do
    {:reply, {:ok, probe_of(state)}, state}
  end

  def handle_call({:subscribe, pid}, _from, state) do
    if Map.has_key?(state.subscribers, pid) do
      {:reply, :ok, state}
    else
      {:reply, :ok, put_in(state.subscribers[pid], Process.monitor(pid))}
    end
  end

  def handle_call({:unsubscribe, pid}, _from, state), do: {:reply, :ok, forget(state, pid)}

  # The last clause, and it is not a convenience.
  #
  # Without it an unmatched call raises `FunctionClauseError`, and an Erlang
  # `function_clause` stacktrace prints its arguments in full — so the terminate report, the
  # exit reason, and everything downstream that interpolates that reason all carry the real
  # argument list, which for this process is `{:respond, id, %{"secret" => …}}`. `:sensitive`
  # keeps the mailbox out of the crash dump and `format_status/1` redacts the report's
  # `Last message` and `State`; neither touches a stacktrace.
  #
  # So this crashes — a caller must not wait out the ceiling for a call nobody will
  # answer — on a term of its own making. `shape/1` names the head of the message and how
  # many elements it had, and nothing else: an atom and an integer, which cannot be a
  # password however the message was built.
  def handle_call(message, _from, state) do
    raise ArgumentError,
          "the deployment worker for #{state.operation} does not serve #{shape(message)}"
  end

  defp shape(message) when is_tuple(message) and tuple_size(message) > 0,
    do: "#{inspect(elem(message, 0))}/#{tuple_size(message)}"

  defp shape(message) when is_atom(message), do: inspect(message)
  defp shape(_other), do: "a call of a shape this process does not name"

  @impl true
  def handle_info({port, {:data, {:eol, line}}}, %{port: port} = state) do
    if state.oversize? do
      # The tail of a line already refused. Nothing in it is a frame.
      {:noreply, %{state | oversize?: false}}
    else
      {:noreply, decoded(state, line)}
    end
  end

  def handle_info({port, {:data, {:noeol, _fragment}}}, %{port: port} = state) do
    if state.oversize? do
      {:noreply, state}
    else
      {:noreply, %{fault(state, :worker_frame_too_large, nil) | oversize?: true}}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    state = %{state | port: nil, exit_status: status}

    state =
      if state.done? do
        state
      else
        # §8's program finishes the operation after stdin EOF and stops writing to stdout, so
        # an exit with no `done` frame is not by itself a failure — it is this runtime losing
        # sight of an operation that may well have completed. The journal is the authority
        # and `resume` is the verb; this says which it was rather than inventing an outcome.
        fault(state, :worker_exited, "the deployment program exited with status #{status}")
      end

    {:stop, {:shutdown, {:exited, status}}, state}
  end

  def handle_info({:EXIT, port, _reason}, %{port: port} = state) do
    {:stop, {:shutdown, :port_closed}, %{state | port: nil}}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state),
    do: {:noreply, forget(state, pid)}

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    # Deliberately not a kill. Closing the port closes the program's stdin, which is the
    # signal §8 gives it to finish on its own; signalling it here would be this runtime
    # taking back the one property the port program exists for.
    _ = if state.port && Port.info(state.port), do: Port.close(state.port)
    broadcast(state, %{"event" => "detached"})
    :ok
  end

  # ---------------------------------------------------------------------------
  # Frames in

  defp decoded(state, line) do
    case Frame.decode(line) do
      {:ok, frame} -> apply_frame(state, frame)
      {:error, {:frame_too_large, _size}} -> fault(state, :worker_frame_too_large, nil)
      {:error, :frame_not_json} -> fault(state, :worker_answered_nothing, "not JSON")
      {:error, :frame_not_object} -> fault(state, :worker_answered_nothing, "not an object")
      {:error, :frame_version} -> fault(state, :worker_answered_nothing, "unknown frame version")
    end
  end

  defp apply_frame(state, frame) do
    case Frame.event(frame) do
      "state" -> state |> put_state(frame["state"]) |> broadcast(frame)
      "step" -> state |> progressed() |> put_step(frame) |> broadcast(frame)
      "log" -> state |> progressed() |> put_log(frame["line"]) |> broadcast(frame)
      "challenge" -> state |> progressed() |> put_challenge(frame) |> broadcast(frame)
      "done" -> state |> put_done(frame) |> broadcast(frame)
      # A frame this build does not name is counted and dropped rather than passed on: a
      # subscriber renders what it is given, and an unnamed event is a program this runtime
      # does not understand rather than a new thing to draw.
      nil -> fault(state, :worker_answered_nothing, "an unnamed event")
    end
  end

  defp progressed(state), do: %{state | progressed?: true}

  @states ~w(running waiting completed failed cancelled)

  defp put_state(state, run_state) when run_state in @states, do: %{state | state: run_state}
  defp put_state(state, _unreadable), do: state

  defp put_step(state, frame) do
    step = %{
      "step" => Journal.scrub_value(frame["step"]),
      "state" => Journal.scrub_value(frame["state"]),
      "detail" => Journal.scrub_value(frame["detail"])
    }

    %{state | steps: Enum.take(state.steps ++ [step], -@max_steps)}
  end

  defp put_log(state, line) when is_binary(line),
    do: %{state | log: Enum.take(state.log ++ [Journal.scrub_line(line, 300)], -@max_log)}

  defp put_log(state, _absent), do: state

  @kinds ~w(host_trust password passphrase review)

  defp put_challenge(state, %{"challenge" => id, "kind" => kind} = frame)
       when is_binary(id) and kind in @kinds do
    challenge = %{
      "challenge" => id,
      "kind" => kind,
      "expires_at" => Journal.scrub_value(frame["expires_at"]),
      "metadata" => Journal.scrub_value(frame["metadata"]) || %{}
    }

    # The reviewed lines are the plan (§6). Kept past the challenge that carried them,
    # because the finish step still names what was approved.
    %{state | challenge: challenge, plan: plan_of(frame) || state.plan}
  end

  defp put_challenge(state, _unreadable),
    do: fault(state, :worker_answered_nothing, "a challenge this build cannot read")

  defp plan_of(%{"metadata" => %{"lines" => plan}}) when is_list(plan),
    do: plan_lines(plan)

  # Accept the list-shaped metadata used by earlier frames producers too.
  defp plan_of(%{"metadata" => %{"plan" => plan}}) when is_list(plan),
    do: plan_lines(plan)

  defp plan_of(_absent), do: nil

  defp plan_lines(plan) do
    case Journal.scrub_value(plan) do
      lines when is_list(lines) -> Enum.filter(lines, &is_binary/1)
      _unreadable -> nil
    end
  end

  defp put_done(state, frame) do
    %{
      state
      | done?: true,
        summary: Journal.scrub_value(frame["summary"]),
        challenge: nil,
        state: if(frame["state"] in @states, do: frame["state"], else: state.state),
        last_error: done_error(state, frame)
    }
  end

  # A `done` that ends the operation badly says why in a stable code beside its sentence.
  # §8 fixes `state` and `summary` on that frame; a `reason` alongside them is what lets a
  # refusal be recognised as one rather than read out of an English summary — `resume/1`
  # turns on exactly that, because a second program against a live operation exits promptly
  # with `operation_in_progress` and this runtime has to answer the refusal rather than
  # report a deployment it did not start.
  defp done_error(state, %{"state" => "failed"} = frame) do
    case Journal.scrub_value(frame["reason"]) do
      reason when is_binary(reason) and reason != "" ->
        %{"reason" => reason, "detail" => Journal.scrub_value(frame["summary"])}

      _unnamed ->
        state.last_error
    end
  end

  defp done_error(state, _frame), do: state.last_error

  # A fault is recorded rather than raised: a program writing something this build cannot read
  # is a fact about the operation, and one an operator has to be told without the connection
  # to it dying first. The first one wins, because the first is the one that explains the rest.
  defp fault(state, reason, detail) do
    Logger.warning(
      "fleet deployment operation #{state.operation}: #{reason}#{if detail, do: " (#{detail})"}"
    )

    if state.last_error do
      state
    else
      %{
        state
        | last_error: %{"reason" => Atom.to_string(reason), "detail" => detail}
      }
    end
  end

  # ---------------------------------------------------------------------------
  # Frames out

  # `expect` is fixed by the challenge's own kind, so a host-trust acceptance cannot be
  # delivered as the answer to a password prompt and a secret cannot be delivered to a review.
  defp authorize(%{challenge: nil} = state, id, _response), do: stale(state, id)

  defp authorize(state, id, response) do
    open = state.challenge

    cond do
      open["challenge"] != id -> stale(state, id)
      expired?(open) -> {:error, :challenge_expired}
      true -> shaped(open["kind"], id, response)
    end
  end

  # An id that was answered is `challenge_consumed` — the honest answer to a double click —
  # and one that was never issued is `unknown_challenge`. Asked in that order, because a
  # consumed challenge is also not the open one and answering it "unknown" would tell an
  # operator their password went nowhere when it had already gone.
  defp stale(state, id) do
    if MapSet.member?(state.answered, id),
      do: {:error, :challenge_consumed},
      else: {:error, :unknown_challenge}
  end

  defp shaped(kind, id, %{"accept" => accept})
       when kind in ~w(host_trust review) and is_boolean(accept),
       do: {:ok, %{"op" => "respond", "challenge" => id, "accept" => accept}}

  defp shaped(kind, id, %{"secret" => secret})
       when kind in ~w(password passphrase) and is_binary(secret),
       do: {:ok, %{"op" => "respond", "challenge" => id, "secret" => secret}}

  defp shaped(_kind, _id, _response), do: {:error, :challenge_kind_mismatch}

  # An `expires_at` this build cannot read is not an expiry. The program fails the operation
  # `challenge_expired` on its own five-minute deadline (§8); this is the same refusal made
  # before a late answer is written, so a secret typed after the deadline is not sent at all.
  defp expired?(%{"expires_at" => at}) when is_binary(at) do
    case DateTime.from_iso8601(at) do
      {:ok, deadline, _offset} -> DateTime.compare(DateTime.utc_now(), deadline) == :gt
      _unreadable -> false
    end
  end

  defp expired?(_absent), do: false

  defp write(%{port: nil}, _frame), do: {:error, :worker_unavailable}

  defp write(state, frame) do
    case Frame.encode(frame) do
      {:ok, line} ->
        Port.command(state.port, line)
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    _closed -> {:error, :worker_unavailable}
  catch
    _kind, _reason -> {:error, :worker_unavailable}
  end

  # The allowlist the spec's secret handling gives: the operation and the challenge, and the
  # challenge's kind and the outcome, which this process knows without being told. Never the
  # response — a refusal's audit line is written from the *challenge*, not from what was
  # offered to it, so an answer of the wrong shape does not get logged by being wrong.
  # The challenge named is the one this operation is *waiting on*, never the string the
  # caller sent. A challenge id is a token a client chose, and a client that chose
  # `"trust-1\ngateway operate fleet.deployment.respond params=redacted …"` writes a second
  # line into the operator's log that reads exactly like a real one. Stripping the newline
  # is not enough — the rest of the sentence is still the client's — and this runtime
  # already knows the only id that matters. An answer to anything else is named by its
  # outcome (`unknown_challenge`, `challenge_consumed`), which is the fact worth recording.
  defp audit(state, _challenge, outcome \\ :sent) do
    Logger.info(
      "fleet deployment respond operation=#{state.operation} " <>
        "challenge=#{id_of(state.challenge)} " <>
        "kind=#{kind_of(state.challenge)} outcome=#{outcome}"
    )
  end

  defp id_of(%{"challenge" => id}) when is_binary(id), do: Journal.scrub_line(id, 128)
  defp id_of(_none), do: "none"

  defp kind_of(%{"kind" => kind}), do: kind
  defp kind_of(_none), do: "none"

  # ---------------------------------------------------------------------------

  defp broadcast(state, frame) do
    Enum.each(Map.keys(state.subscribers), fn pid ->
      send(pid, {:ouroboros_fleet_deployment, state.operation, frame})
    end)

    state
  end

  defp forget(state, pid) do
    case Map.pop(state.subscribers, pid) do
      {nil, _subscribers} ->
        state

      {ref, subscribers} ->
        Process.demonitor(ref, [:flush])
        %{state | subscribers: subscribers}
    end
  end

  @doc """
  The §9 answer shape, from a live operation.

  `source` is `worker`, which is the operator's whole question after an interruption: a
  journal says what was durably recorded, only a live process says what is happening now.
  """
  @spec view(map()) :: snapshot()
  def view(state) do
    %{
      "operation" => state.operation,
      "kind" => state.kind,
      "state" => state.state,
      "steps" => state.steps,
      "challenge" => state.challenge,
      "log" => state.log,
      "plan" => state.plan,
      "summary" => state.summary,
      "last_error" => state.last_error,
      "residue" => residue(state),
      "running" => not is_nil(state.port),
      "source" => "worker"
    }
  end

  # What the operation left behind, from the one place that records it. A program writes
  # residue into its journal rather than sending it as a frame, so a live answer reads the
  # same file a journal answer does — bounded, sanitized, and `[]` where there is nothing to
  # say or nothing readable to say it from.
  defp residue(state) do
    case Journal.read(state.data_dir, state.operation) do
      {:ok, %{"residue" => residue}} when is_list(residue) -> residue
      _none -> []
    end
  end

  @doc """
  What a caller that has just *started* this process needs to know about it, and no more.

  `resume/1` is the caller: §8's program holds a lock on the journal it writes, so a second
  run against an operation the first is still finishing exits promptly with a `done failed`
  whose reason is `operation_in_progress`. That is the only way this runtime can see a
  program it did not start, and it is a refusal to pass on rather than a deployment to
  report. `:progressed` is the other side of the same question — a program that has sent a
  step, a log line or a challenge is one that is doing the work.
  """
  @spec probe(pid()) ::
          {:ok, :pending | :progressed | :done | {:refused, String.t()}}
          | {:error, :worker_timeout | :worker_unavailable}
  def probe(pid), do: call(pid, :probe)

  defp probe_of(%{done?: true, last_error: %{"reason" => reason}})
       when is_binary(reason),
       do: {:refused, reason}

  defp probe_of(%{done?: true}), do: :done
  defp probe_of(%{progressed?: true}), do: :progressed
  defp probe_of(_pending), do: :pending
end
