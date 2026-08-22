defmodule Ouroboros.Interactive.Task do
  @moduledoc false

  use GenServer, restart: :transient

  require Logger

  alias Jido.Harness.{Session, SessionInfo, TurnRequest, TurnResult}
  alias Ouroboros.Interactive.{Event, State, Store}
  alias Ouroboros.Provider
  alias Ouroboros.Runtime.Exposure
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager
  alias Ouroboros.Workspace.Path, as: WorkspacePath

  @poll_interval 25
  @replay_limit 100
  @terminal_retire_ms 100
  @workspace_reacquire_attempts 25
  @workspace_reacquire_delay_ms 4
  @retry_backoff_max_ms 5_000
  @default_unresolved_turn_deadline_ms 10 * 60 * 1_000
  @default_readiness_deadline_ms 10 * 60 * 1_000
  @max_pending_steers 32
  def child_spec(id) do
    %{
      id: {__MODULE__, id},
      start: {__MODULE__, :start_link, [id]},
      restart: :transient
    }
  end

  def start_link(id) when is_binary(id), do: GenServer.start_link(__MODULE__, id, name: via(id))

  def via(id), do: {:via, Registry, {Ouroboros.Interactive.Registry, id}}

  def whereis(id) do
    case Registry.lookup(Ouroboros.Interactive.Registry, id) do
      [{pid, _value}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  catch
    :exit, _reason -> nil
  end

  @impl true
  def init(id) do
    case Store.get(id) do
      {:ok, %State{node: owner} = session} when owner == node() ->
        if State.terminal?(session) do
          {:ok, runtime(session), {:continue, :attach}}
        else
          case admit_workspace(session) do
            # A checkpoint this build cannot turn into a Harness request — a trace from a
            # newer prompt format, a prompt that is no longer a binary — fails as itself,
            # before any provider session, and releases what it holds.
            {:ok, runtime} ->
              case State.unrequestable_reason(runtime.session) do
                nil -> {:ok, runtime, {:continue, :attach}}
                reason -> {:ok, runtime, {:continue, {:unrequestable, reason}}}
              end

            {:error, reason} ->
              {:stop, reason}
          end
        end

      {:ok, %State{node: owner}} ->
        {:stop, {:wrong_owner, owner}}

      :not_found ->
        {:stop, :not_found}

      {:error, reason} ->
        {:stop, {:storage_error, reason}}
    end
  end

  @impl true
  def handle_continue(:attach, %{session: session} = runtime) do
    if State.terminal?(session) do
      {:noreply, runtime |> reply_ready_waiters() |> schedule_retire()}
    else
      {:noreply, attach_or_start(runtime)}
    end
  end

  def handle_continue({:unrequestable, reason}, runtime) do
    Logger.error(
      "interactive session #{runtime.session.id} cannot build a request: " <>
        "#{inspect(reason)}; failing it"
    )

    {:noreply, fail_start(runtime, {:unrequestable_session_state, reason})}
  end

  @impl true
  def handle_call(:ready, from, runtime) do
    cond do
      ready?(runtime.session) ->
        {:reply, {:ok, State.public(runtime.session)}, runtime}

      State.terminal?(runtime.session) ->
        {:reply, {:error, {:session_start_failed, runtime.session.error}}, runtime}

      true ->
        monitor = Process.monitor(elem(from, 0))

        runtime = %{runtime | ready_waiters: [{from, monitor} | runtime.ready_waiters]}
        {:noreply, arm_ready_deadline(runtime)}
    end
  end

  def handle_call(:info, _from, runtime),
    do: {:reply, {:ok, State.public(runtime.session)}, runtime}

  def handle_call({:replay, cursor, limit}, _from, runtime) do
    {:reply, replay_events(runtime.session, cursor, limit), runtime}
  end

  def handle_call({:subscribe, subscriber, cursor}, _from, runtime) when is_pid(subscriber) do
    case subscription_events(runtime.session, cursor) do
      {:ok, backlog} ->
        runtime =
          if State.terminal?(runtime.session),
            do: runtime,
            else: put_subscriber(runtime, subscriber)

        {:reply, {:ok, backlog}, runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:subscribe, _subscriber, _cursor}, _from, runtime),
    do: {:reply, {:error, :invalid_subscriber}, runtime}

  def handle_call({:unsubscribe, subscriber}, _from, runtime) do
    {:reply, :ok, drop_subscriber(runtime, subscriber)}
  end

  def handle_call({:send_turn, mode, id, input, opts}, _from, runtime) do
    case dispatch_turn(runtime, mode, id, input, opts) do
      {:ok, turn, runtime} -> {:reply, {:ok, State.public_turn(turn)}, runtime}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:await_turn, request_ref, turn_id}, from, runtime)
      when is_map_key(runtime.session.turns, turn_id) do
    turn = Map.fetch!(runtime.session.turns, turn_id)

    if State.terminal_turn?(turn) do
      {:reply, {:ok, State.public_turn(turn)}, runtime}
    else
      add_turn_waiter(runtime, turn_id, request_ref, from)
    end
  end

  def handle_call({:await_turn, _request_ref, _turn_id}, _from, runtime),
    do: {:reply, {:error, :not_found}, runtime}

  def handle_call({:steer, input, opts}, _from, runtime) do
    case with_harness_session(runtime, &Session.steer(&1, input, opts)) do
      {:ok, request_id} when is_binary(request_id) ->
        {:reply, {:ok, request_id},
         runtime
         |> remember_steer(request_id, input)
         |> schedule_poll(0)}

      reply ->
        {:reply, reply, schedule_poll(runtime, 0)}
    end
  end

  def handle_call({:respond_approval, request_id, response}, _from, runtime) do
    reply = with_harness_session(runtime, &Session.respond_approval(&1, request_id, response))
    {:reply, reply, schedule_poll(runtime, 0)}
  end

  def handle_call({:configure, changes}, _from, runtime) do
    case configure_session(runtime, changes) do
      {:ok, result, runtime} -> {:reply, {:ok, result}, schedule_poll(runtime, 0)}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  # A rename touches nothing but the durable record: no provider knows this session by a
  # name, and a terminal session is still worth finding in a picker, so unlike `configure`
  # this is allowed after the conversation has ended.
  def handle_call({:rename, title}, _from, runtime) do
    with {:ok, title} <- State.validate_title(title),
         renamed = runtime.session |> State.put_title(title, :human) |> State.touch(),
         {:ok, runtime} <- persist(runtime, renamed, []) do
      {:reply, {:ok, State.public(runtime.session)}, runtime}
    else
      {:error, {:invalid_title, _detail} = reason} -> {:reply, {:error, reason}, runtime}
      {:error, runtime} -> {:reply, {:error, {:rename_checkpoint_failed, :storage_error}}, runtime}
    end
  end

  def handle_call({:interrupt, turn_id}, _from, runtime) do
    reply =
      case harness_turn_id(runtime.session, turn_id) do
        {:ok, harness_turn_id} ->
          with_harness_session(runtime, &Session.interrupt(&1, harness_turn_id))

        {:error, _reason} = error ->
          error
      end

    {:reply, reply, schedule_poll(runtime, 0)}
  end

  def handle_call(:close, _from, %{session: session} = runtime)
      when session.status in [:closed, :cancelled] do
    {:reply, :ok, runtime}
  end

  # A session the caller asked to end is not a session the runtime lost, so the Harness
  # session going away after this is the answer, not a break to resume across. Settled
  # whether or not the call itself succeeded: the intent is the same either way, and
  # reviving a session someone asked to close would be the worse mistake.
  def handle_call(:close, _from, runtime) do
    reply = with_harness_session(runtime, &Session.close/1)
    {:reply, reply, schedule_poll(settle_resume(runtime), 0)}
  end

  def handle_call(:kill, _from, %{session: session} = runtime)
      when session.status in [:closed, :cancelled] do
    {:reply, :ok, runtime}
  end

  def handle_call(:kill, _from, runtime) do
    reply = with_harness_session(runtime, &Session.kill/1)
    {:reply, reply, schedule_poll(settle_resume(runtime), 0)}
  end

  def handle_call(_message, _from, runtime),
    do: {:reply, {:error, :invalid_session_operation}, runtime}

  @impl true
  def handle_cast({:cancel_await, request_ref}, runtime) do
    {:noreply, drop_turn_waiter(runtime, request_ref)}
  end

  @impl true
  def handle_info(:poll, runtime), do: {:noreply, poll(runtime)}

  def handle_info(:ready_deadline, %{ready_waiters: []} = runtime),
    do: {:noreply, %{runtime | ready_timer: nil}}

  def handle_info(:ready_deadline, runtime) do
    Logger.warning(
      "interactive session #{runtime.session.id} did not reach a ready or terminal " <>
        "state within the readiness deadline (#{readiness_deadline_ms()}ms); answering " <>
        "start waiters as unresolved while polling continues " <>
        "(last retry: #{inspect(runtime.retry.signature)})"
    )

    Enum.each(runtime.ready_waiters, fn {from, monitor} ->
      Process.demonitor(monitor, [:flush])
      GenServer.reply(from, {:error, {:session_start_unresolved, runtime.session.id}})
    end)

    {:noreply, %{runtime | ready_waiters: [], ready_timer: nil}}
  end

  # A turn waiter that arrives in the window between the terminal checkpoint and
  # this message used to strand the coordinator: nothing rescheduled retirement
  # once it had been declined.
  def handle_info(:retire, runtime) do
    cond do
      not State.terminal?(runtime.session) -> {:noreply, runtime}
      map_size(runtime.turn_waiters) == 0 -> {:stop, :normal, runtime}
      true -> {:noreply, schedule_retire(runtime)}
    end
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, runtime) do
    {:noreply,
     runtime
     |> drop_subscriber_by_monitor(monitor)
     |> drop_turn_waiter_by_monitor(monitor)
     |> drop_ready_waiter_by_monitor(monitor)}
  end

  def handle_info(_message, runtime), do: {:noreply, runtime}

  @impl true
  def terminate(_reason, runtime) do
    _ = release_workspace(runtime)
    :ok
  end

  defp runtime(session, lease \\ nil, capability \\ nil) do
    %{
      session: session,
      subscribers: %{},
      subscriber_monitors: %{},
      turn_waiters: %{},
      ready_waiters: [],
      ready_timer: nil,
      workspace_lease: lease,
      workspace_capability: capability,
      retry: no_retry(),
      terminal_observed_at: nil,
      pending_steers: [],
      resume_settled: false
    }
  end

  defp no_retry, do: %{signature: nil, count: 0, delay: 0}

  defp attach_or_start(%{session: %State{harness_session_id: id}} = runtime) when is_binary(id) do
    case safe_session_call(fn -> Session.info(id) end) do
      {:ok, %SessionInfo{}} -> runtime |> clear_retry() |> schedule_poll(0)
      {:error, :not_found} -> resume_or_lose(runtime, :harness_session_not_found)
      {:error, reason} -> retry(runtime, :harness_session_info_failed, reason)
    end
  end

  defp attach_or_start(runtime) do
    case find_adoptable_session(runtime.session.id) do
      {:ok, id} -> adopt(runtime, id)
      :not_found -> start_harness_session(runtime)
      {:error, reason} -> fail_start(runtime, reason)
    end
  end

  defp find_adoptable_session(ouroboros_id) do
    sessions = safe_session_call(&Session.list/0)

    matches =
      if is_list(sessions) do
        Enum.filter(sessions, fn info ->
          metadata = info.metadata || %{}

          Map.get(metadata, :ouroboros_session_id) == ouroboros_id or
            Map.get(metadata, "ouroboros_session_id") == ouroboros_id
        end)
      else
        []
      end

    case {sessions, matches} do
      {{:error, reason}, _matches} ->
        {:error, reason}

      {_sessions, []} ->
        :not_found

      {_sessions, [info]} ->
        {:ok, info.session_id}

      {_sessions, infos} ->
        {:error, {:ambiguous_adoptable_sessions, Enum.map(infos, & &1.session_id)}}
    end
  end

  defp start_harness_session(runtime) do
    session = runtime.session

    case State.unrequestable_reason(session) do
      nil ->
        case safe_session_call(fn ->
               Session.start(session.provider, State.request(session))
             end) do
          {:ok, id} -> adopt(runtime, id)
          {:error, reason} -> fail_start(runtime, reason)
        end

      reason ->
        fail_start(runtime, {:unrequestable_session_state, reason})
    end
  end

  defp adopt(runtime, harness_session_id) do
    session =
      runtime.session
      |> Map.put(:harness_session_id, harness_session_id)
      |> State.touch()

    case persist(runtime, session, []) do
      {:ok, runtime} -> schedule_poll(runtime, 0)
      {:error, runtime} -> retry(runtime, :session_adoption_checkpoint_failed, :storage_error)
    end
  end

  defp poll(%{session: session} = runtime)
       when session.status in [:closed, :failed, :cancelled, :lost],
       do: runtime

  defp poll(%{session: %State{harness_session_id: nil}} = runtime), do: attach_or_start(runtime)

  defp poll(runtime) do
    session = runtime.session

    case safe_session_call(fn ->
           Session.replay(session.harness_session_id,
             cursor: harness_cursor(session),
             limit: @replay_limit
           )
         end) do
      {:ok, [_ | _] = events} ->
        runtime |> clear_retry() |> persist_harness_events(rebase_sequences(session, events))

      {:ok, []} ->
        refresh_session(runtime)

      {:error, :not_found} ->
        resume_or_lose(runtime, :harness_session_not_found)

      {:error, reason} ->
        retry(runtime, :harness_session_replay_failed, reason)
    end
  end

  # A resumed session polls a Harness session whose log starts at one again, while the
  # Ouroboros sequence a client holds must keep climbing. `sequence_offset` is the
  # durable distance between the two, so the harness-side cursor is the Ouroboros one
  # minus the offset, and every replayed event is shifted back into the session's own
  # number space before anything downstream — projection, event ids, the checkpoint —
  # sees it. Both are identities until the first resume.
  defp harness_cursor(%State{} = session), do: session.cursor - State.sequence_offset(session)

  defp rebase_sequences(%State{} = session, events) do
    case State.sequence_offset(session) do
      0 -> events
      offset -> Enum.map(events, &%{&1 | sequence: &1.sequence + offset})
    end
  end

  defp persist_harness_events(runtime, harness_events) do
    projected = Enum.map(harness_events, &Event.from_harness(runtime.session.id, &1))

    # Harness deliberately records only that input was accepted. Ouroboros already owns
    # the durable turn request, so correlate the Harness turn id and copy its prompt
    # through Redaction into the projected event. This gives every replaying client the
    # user side of the chat without changing Harness or inventing client-local rows.
    reconciled = reconcile_turn_ids(runtime.session, projected)
    projected = Enum.map(projected, &enrich_chat_input(&1, reconciled))

    {projected, pending_steers} =
      Enum.map_reduce(projected, runtime.pending_steers, &enrich_steer_input/2)

    runtime = %{runtime | pending_steers: pending_steers}

    session =
      Enum.reduce(projected, reconciled, fn event, session ->
        session
        |> Map.put(:cursor, event.sequence)
        |> maybe_provider_session(event.provider_session_id)
        |> append_event(event)
      end)
      |> apply_turn_event_statuses(projected)
      |> mark_gap_ambiguities(projected)
      # What the session spent rides the same checkpoint as the events it was read from,
      # so a restart resumes the account rather than restarting it at zero.
      |> State.fold_usage(projected)
      |> auto_title(projected)
      |> State.touch()

    case persist(runtime, session, projected) do
      {:ok, runtime} -> runtime |> reply_all_terminal_turn_waiters() |> schedule_poll(0)
      {:error, runtime} -> schedule_poll(runtime, @poll_interval)
    end
  end

  defp enrich_chat_input(
         %Event{type: :input_accepted, payload: %{"kind" => "message"}} = event,
         session
       ) do
    with turn when is_map(turn) <- find_turn_by_harness_id(session, event.turn_id),
         prompt when is_binary(prompt) <- get_in(turn, [:request, :prompt]) do
      %{event | payload: Map.put(event.payload, "text", Jido.Harness.Redaction.redact(prompt))}
    else
      _missing -> event
    end
  end

  defp enrich_chat_input(event, _session), do: event

  # Names an unnamed session from the first user input the provider accepted.
  #
  # Hung on `input_accepted` rather than on the turn dispatch because that event is the
  # one whose text is already redacted and durable — `enrich_chat_input/2` put it there —
  # so the title is derived from exactly the bytes the transcript shows, and a turn that
  # was never accepted never names anything.
  #
  # `State.put_title/3` is what makes this safe to run on every batch: an `:auto` title
  # writes only into a session nobody has named, so a second prompt cannot rename a
  # conversation and a rename can never be undone by one.
  defp auto_title(session, projected) do
    with nil <- State.title(session),
         %Event{payload: %{"text" => text}} <- first_accepted_input(projected),
         title when is_binary(title) <- State.auto_title(text) do
      State.put_title(session, title, :auto)
    else
      _named_or_nothing_to_name -> session
    end
  end

  defp first_accepted_input(projected) do
    Enum.find(projected, fn
      %Event{type: :input_accepted, payload: %{"kind" => kind}} -> kind in ["message", "steer"]
      _event -> false
    end)
  end

  # Harness records only *that* a steer was accepted (`input_accepted` with
  # `%{"kind" => "steer"}` and a fresh request id), never the text that produced it.
  # `remember_steer/3` held the prompt for exactly this moment: the first projected
  # acceptance carrying the matching request id is enriched with it — redacted like
  # every other durable payload — and consumed, so each remembered prompt quotes one
  # row exactly once. The ring is in-memory on purpose: a coordinator restart between
  # the steer call and its event loses one enrichment instead of inventing a second
  # durable schema, and an event a provider never echoes is bounded by the cap rather
  # than growing forever.
  defp enrich_steer_input(
         %Event{type: :input_accepted, request_id: request_id, payload: %{"kind" => "steer"}} =
           event,
         pending
       )
       when is_binary(request_id) do
    case List.keyfind(pending, request_id, 0) do
      {^request_id, prompt} ->
        {%{
           event
           | payload: Map.put(event.payload, "text", Jido.Harness.Redaction.redact(prompt))
         }, List.keydelete(pending, request_id, 0)}

      nil ->
        {event, pending}
    end
  end

  defp enrich_steer_input(event, pending), do: {event, pending}

  # The prompt is held raw in process memory only; the durable copy is the redacted
  # text this enrichment writes into the event. Oldest entries fall off the cap first,
  # which bounds the cost of a steer whose acceptance event never arrives.
  defp remember_steer(runtime, request_id, input) do
    case turn_prompt(input) do
      prompt when is_binary(prompt) and prompt != "" ->
        %{
          runtime
          | pending_steers:
              Enum.take([{request_id, prompt} | runtime.pending_steers], @max_pending_steers)
        }

      _unquotable ->
        runtime
    end
  end

  defp turn_prompt(input) when is_binary(input), do: input
  defp turn_prompt(%{prompt: prompt}) when is_binary(prompt), do: prompt
  defp turn_prompt(%{"prompt" => prompt}) when is_binary(prompt), do: prompt
  defp turn_prompt(_input), do: nil

  defp refresh_session(runtime) do
    case safe_session_call(fn -> Session.info(runtime.session.harness_session_id) end) do
      {:ok, %SessionInfo{} = info} ->
        runtime = runtime |> clear_retry() |> collect_turn_results()

        case recover_checkpointed_dispatch(runtime, info) do
          {:ok, runtime} -> checkpoint_info(runtime, info)
          {:retry, runtime, kind, reason} -> retry(runtime, kind, reason)
        end

      {:error, :not_found} ->
        resume_or_lose(runtime, :harness_session_not_found)

      {:error, reason} ->
        retry(runtime, :harness_session_info_failed, reason)
    end
  end

  defp harness_session_present?(runtime) do
    match?(
      {:ok, %SessionInfo{}},
      safe_session_call(fn -> Session.info(runtime.session.harness_session_id) end)
    )
  end

  defp collect_turn_results(runtime) do
    Enum.reduce(runtime.session.turns, runtime, fn {_id, turn}, runtime ->
      cond do
        State.terminal_turn?(turn) and not is_nil(turn.result) ->
          runtime

        not is_binary(turn.harness_turn_id) ->
          runtime

        true ->
          case safe_session_call(fn ->
                 Session.await(runtime.session.harness_session_id, turn.harness_turn_id, 0)
               end) do
            {:ok, %TurnResult{} = result} ->
              # A turn result becomes readable in the same provider transition that
              # appends the turn's terminal event, so a result read here can be newer
              # than the mirrored event log. Finishing now would reply to an awaiter
              # whose subsequent replay is missing the completion it just waited for.
              if mirrored_through_result?(runtime) do
                finish_turn(runtime, turn.id, result)
              else
                runtime
              end

            {:error, :timeout} ->
              runtime

            # `await` answers `:not_found` both for a turn this session never had and
            # for a session that is no longer there. Only the first is a fact about the
            # turn. If the session itself has gone, the diagnosis belongs to
            # `refresh_session`, which resumes or loses it; relabelling every in-flight
            # turn here would pre-empt that decision with a sentence about a Harness
            # session rather than about what happened to the work.
            {:error, :not_found} ->
              if harness_session_present?(runtime),
                do: mark_turn_ambiguous(runtime, turn.id, :harness_turn_not_found),
                else: runtime

            {:error, reason} ->
              mark_turn_ambiguous(runtime, turn.id, {:harness_turn_await_failed, reason})
          end
      end
    end)
  end

  # Read the provider's cursor high-water mark *after* the result: whatever the
  # provider had emitted when the result existed is included in it, so a mirror that
  # has reached it has already checkpointed the turn's terminal event. Anything still
  # missing is drained by the next poll, and a pruned event still advances the cursor,
  # so this defers a turn at most until the mirror catches up. An unreachable session
  # fails open — `refresh_session` owns that diagnosis.
  defp mirrored_through_result?(runtime) do
    case safe_session_call(fn -> Session.info(runtime.session.harness_session_id) end) do
      {:ok, %SessionInfo{output_cursor: output_cursor}} ->
        harness_cursor(runtime.session) >= output_cursor

      _unavailable ->
        true
    end
  end

  # Waiting for a turn to resolve after the provider session has already reached a
  # terminal state is correct only for as long as resolution is still plausible. An
  # unbounded wait is a livelock: the session never reaches its terminal status, the
  # workspace lease is never released, and recovery faithfully resurrects the wait
  # after every restart. The deadline is measured from the first terminal
  # observation, and expiry resolves outstanding turns as explicitly ambiguous —
  # the provider work may well have happened.
  defp checkpoint_info(runtime, info) do
    runtime = settle_terminal_dispatch_intents(runtime, info)

    if terminal_session_state?(info.state) and unresolved_result_turns?(runtime.session) do
      runtime = observe_terminal_session(runtime)

      runtime =
        if unresolved_deadline_expired?(runtime),
          do: resolve_turns_at_session_close(runtime),
          else: runtime

      # A resolution whose checkpoint failed has not happened. Retry rather than
      # close the session over a turn the store never accepted as settled.
      if unresolved_result_turns?(runtime.session) do
        schedule_poll(runtime, @poll_interval)
      else
        persist_session_info(runtime, info)
      end
    else
      persist_session_info(%{runtime | terminal_observed_at: nil}, info)
    end
  end

  defp observe_terminal_session(%{terminal_observed_at: nil} = runtime),
    do: %{runtime | terminal_observed_at: System.monotonic_time(:millisecond)}

  defp observe_terminal_session(runtime), do: runtime

  defp unresolved_deadline_expired?(%{terminal_observed_at: observed_at})
       when is_integer(observed_at) do
    System.monotonic_time(:millisecond) - observed_at >= unresolved_turn_deadline_ms()
  end

  defp unresolved_deadline_expired?(_runtime), do: false

  defp unresolved_turn_deadline_ms do
    case Application.get_env(
           :ouroboros,
           :interactive_unresolved_turn_deadline_ms,
           @default_unresolved_turn_deadline_ms
         ) do
      deadline when is_integer(deadline) and deadline >= 0 -> deadline
      _invalid -> @default_unresolved_turn_deadline_ms
    end
  end

  defp resolve_turns_at_session_close(runtime) do
    runtime.session.turns
    |> Enum.reject(fn {_id, turn} -> State.terminal_turn?(turn) end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
    |> Enum.reduce(runtime, fn turn_id, runtime ->
      mark_turn_ambiguous(runtime, turn_id, {:unresolved_at_session_close, turn_id})
    end)
  end

  defp persist_session_info(runtime, info) do
    session =
      runtime.session
      |> Map.put(:status, normalize_session_status(info.state))
      |> Map.put(
        :provider_session_id,
        info.provider_session_id || runtime.session.provider_session_id
      )
      |> Map.put(:error, durable(info.error))
      |> State.touch()

    case persist(runtime, session, []) do
      {:ok, runtime} ->
        runtime = reply_all_terminal_turn_waiters(runtime)
        runtime = if ready?(runtime.session), do: reply_ready_waiters(runtime), else: runtime

        if State.terminal?(runtime.session) do
          runtime
          |> release_workspace()
          |> reply_ready_waiters()
          |> reply_all_terminal_turn_waiters()
          |> schedule_retire()
        else
          schedule_poll(runtime, @poll_interval)
        end

      {:error, runtime} ->
        schedule_poll(runtime, @poll_interval)
    end
  end

  defp dispatch_turn(runtime, mode, id, input, opts)
       when mode in [:message, :follow_up] and is_binary(id) and is_list(opts) do
    with :ok <- validate_turn_id(id),
         true <- Keyword.keyword?(opts) || {:error, :invalid_turn_options},
         {:ok, request} <- build_turn_request(runtime.session.provider, input, opts),
         {:ok, request} <- authorize_turn_attachments(request, runtime.session.workspace),
         :ok <- ensure_serializable(request),
         :ok <- ensure_secret_free_options(request),
         :ok <- ensure_exposable_turn(runtime.session, request),
         turn = State.new_turn(id, mode, request) do
      case Map.fetch(runtime.session.turns, id) do
        {:ok, existing} ->
          cond do
            existing.fingerprint != turn.fingerprint ->
              {:error, {:turn_id_conflict, id}, runtime}

            # These are not acknowledgements. `:dispatching` is the last durable state
            # both before a recovered send and after Harness accepted a turn whose
            # correlation checkpoint failed; `:ambiguous` means the Harness call exited
            # without a trustworthy answer. Replaying either as `{:ok, existing}` makes
            # a stable-id client clear its input even though nothing proved the turn was
            # accepted. Keep the outcome unknown and let polling/transcript evidence
            # reconcile it without ever dispatching a duplicate here.
            existing.status in [:dispatching, :ambiguous] ->
              {:error, {:turn_dispatch_ambiguous, id}, runtime}

            true ->
              {:ok, existing, runtime}
          end

        :error ->
          case unresolved_dispatches(runtime.session) do
            [] -> persist_and_dispatch_turn(runtime, turn, request)
            ids -> {:error, {:turn_dispatch_unresolved, ids}, runtime}
          end
      end
    else
      false -> {:error, :invalid_turn_options, runtime}
      {:error, reason} -> {:error, reason, runtime}
    end
  end

  defp dispatch_turn(runtime, _mode, _id, _input, _opts),
    do: {:error, :invalid_turn_request, runtime}

  defp persist_and_dispatch_turn(runtime, turn, request) do
    session =
      %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, turn)} |> State.touch()

    case persist(runtime, session, []) do
      {:ok, runtime} ->
        dispatch_persisted_turn(runtime, turn, request)

      {:error, runtime} ->
        {:error, {:turn_intent_checkpoint_failed, :storage_error}, runtime}
    end
  end

  defp dispatch_persisted_turn(runtime, turn, request) do
    with {:ok, harness_request} <- expose_turn_request(runtime.session, request) do
      call =
        case turn.mode do
          :message -> fn id -> Session.send_message(id, harness_request) end
          :follow_up -> fn id -> Session.follow_up(id, harness_request) end
        end

      case with_harness_session(runtime, call) do
        {:ok, harness_turn_id} ->
          updated =
            turn
            |> Map.put(:harness_turn_id, harness_turn_id)
            |> Map.put(:status, if(turn.mode == :follow_up, do: :queued, else: :running))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, updated)}
            |> State.touch()

          case persist(runtime, session, []) do
            {:ok, runtime} ->
              {:ok, updated, schedule_poll(runtime, 0)}

            {:error, runtime} ->
              {:error, {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id},
               schedule_poll(runtime, 0)}
          end

        {:error, reason}
        when is_tuple(reason) and elem(reason, 0) in [:harness_call_exception, :harness_call_exit] ->
          ambiguous =
            turn
            |> Map.put(:status, :ambiguous)
            |> Map.put(:error, durable(reason))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, ambiguous)}
            |> State.touch()

          case persist(runtime, session, []) do
            {:ok, runtime} ->
              {:error, {:turn_dispatch_ambiguous, turn.id}, reply_turn_waiters(runtime, turn.id)}

            {:error, runtime} ->
              {:error, {:turn_dispatch_ambiguous, turn.id, :checkpoint_failed}, runtime}
          end

        {:error, reason} ->
          failed =
            turn
            |> Map.put(:status, :failed)
            |> Map.put(:error, durable(reason))
            |> State.touch_turn()

          session =
            %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, failed)}
            |> State.touch()

          case persist(runtime, session, []) do
            {:ok, runtime} ->
              {:error, {:turn_dispatch_failed, reason}, reply_turn_waiters(runtime, turn.id)}

            {:error, runtime} ->
              # Harness refused this call synchronously, but the failed checkpoint leaves
              # the durable turn at `:dispatching`. Recovery still owns that intent and
              # may send it once the Harness session becomes idle, so the caller cannot
              # safely mint a replacement id. Preserve both the reconciliation id and the
              # original refusal as a diagnostic while classifying the outcome unknown.
              {:error,
               {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id,
                {:harness_refused, reason}}, schedule_poll(runtime, 0)}
          end
      end
    else
      {:error, reason} ->
        failed =
          turn
          |> Map.put(:status, :failed)
          |> Map.put(:error, durable(reason))
          |> State.touch_turn()

        session =
          %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, failed)}
          |> State.touch()

        case persist(runtime, session, []) do
          {:ok, runtime} ->
            {:error, {:turn_dispatch_failed, reason}, reply_turn_waiters(runtime, turn.id)}

          {:error, runtime} ->
            # Exposure failed before Harness was called, but the only durable record is
            # still `:dispatching`. Recovery owns that intent and can send it after the
            # capture is repaired, so a fresh caller id could duplicate the recovered turn.
            {:error,
             {:turn_dispatch_checkpoint_failed, :dispatch_may_have_started, turn.id,
              {:request_exposure_failed, reason}}, schedule_poll(runtime, 0)}
        end
    end
  end

  defp expose_turn_request(session, request) do
    if Map.get(session.options, :runtime_exposure, true) do
      Exposure.wrap_turn_request_capture(request, Map.get(session, :runtime_snapshot))
    else
      {:ok, request}
    end
  end

  defp ensure_exposable_turn(session, %{prompt: prompt}) when is_binary(prompt) do
    if Map.get(session.options, :runtime_exposure, true) and
         Ouroboros.AgentProfile.reserved_delimiter?(prompt) do
      {:error, {:reserved_prompt_delimiter, :prompt}}
    else
      :ok
    end
  end

  defp ensure_exposable_turn(_session, _request), do: :ok

  defp build_turn_request(provider, input, opts) do
    allowed = [:attachments, :reasoning_effort, :output_schema, :metadata, :provider_options]

    case Enum.find(Keyword.keys(opts), &(&1 not in allowed)) do
      nil ->
        attrs =
          case input do
            prompt when is_binary(prompt) ->
              Map.put(Map.new(opts), :prompt, prompt)

            map when is_map(map) ->
              Map.merge(map, Map.new(opts))

            list when is_list(list) ->
              if Keyword.keyword?(list), do: Map.merge(Map.new(list), Map.new(opts)), else: list

            other ->
              other
          end

        with {:ok, request} <- TurnRequest.new(attrs) do
          {:ok, Provider.apply_runtime_provider_policy(request, provider)}
        end

      key ->
        {:error, {:unknown_turn_option, key}}
    end
  end

  defp authorize_turn_attachments(%TurnRequest{attachments: []} = request, _workspace),
    do: {:ok, request}

  defp authorize_turn_attachments(%TurnRequest{} = request, workspace) do
    with {:ok, root} <- WorkspacePath.canonicalize(workspace),
         {:ok, attachments} <- canonical_attachments(request.attachments, root) do
      {:ok, %{request | attachments: attachments}}
    else
      {:error, {:attachment_outside_workspace, _path} = reason} -> {:error, reason}
      {:error, {:invalid_attachment, _path, _reason} = reason} -> {:error, reason}
      {:error, reason} -> {:error, {:invalid_attachment_workspace, reason}}
    end
  end

  defp canonical_attachments(attachments, root) do
    Enum.reduce_while(attachments, {:ok, []}, fn path, {:ok, authorized} ->
      candidate =
        if Path.type(path) == :absolute,
          do: path,
          else: Path.join(root, path)

      lexical = Path.expand(candidate)

      cond do
        not WorkspacePath.within?(lexical, root) ->
          {:halt, {:error, {:attachment_outside_workspace, path}}}

        true ->
          case WorkspacePath.canonicalize_file(candidate) do
            {:ok, canonical} ->
              if WorkspacePath.within?(canonical, root) do
                {:cont, {:ok, [canonical | authorized]}}
              else
                {:halt, {:error, {:attachment_outside_workspace, path}}}
              end

            {:error, reason} ->
              {:halt, {:error, {:invalid_attachment, path, reason}}}
          end
      end
    end)
    |> case do
      {:ok, authorized} -> {:ok, Enum.reverse(authorized)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp finish_turn(runtime, turn_id, result) do
    case Map.fetch(runtime.session.turns, turn_id) do
      :error ->
        runtime

      {:ok, turn} ->
        status =
          if result.status in [:completed, :failed, :interrupted],
            do: result.status,
            else: :ambiguous

        updated =
          turn
          |> Map.put(:status, status)
          |> Map.put(:result, turn_result_summary(result))
          |> Map.put(:error, durable(result.error))
          |> State.touch_turn()

        session =
          runtime.session
          |> put_in([Access.key(:turns), turn_id], updated)
          |> maybe_provider_session(result.provider_session_id)
          |> State.touch()

        case persist(runtime, session, []) do
          {:ok, runtime} -> reply_turn_waiters(runtime, turn_id)
          {:error, runtime} -> runtime
        end
    end
  end

  # An ambiguity already recorded is not relabelled by a later, less specific one: the
  # first observation is the one this coordinator actually made. A turn finalised
  # outcome-unknown at a resume would otherwise be rewritten on the next poll by the new
  # Harness session's entirely correct "I have never heard of that turn" — a sentence
  # about a session that did not run it. It also stops a permanently unresolvable turn
  # from rewriting the whole session aggregate to disk every 25 ms to record the same
  # reason it already holds.
  defp mark_turn_ambiguous(runtime, turn_id, reason) do
    case Map.fetch(runtime.session.turns, turn_id) do
      {:ok, %{status: :ambiguous}} ->
        runtime

      {:ok, turn} ->
        turn =
          turn
          |> Map.put(:status, :ambiguous)
          |> Map.put(:error, durable(reason))
          |> State.touch_turn()

        session =
          %{runtime.session | turns: Map.put(runtime.session.turns, turn_id, turn)}
          |> State.touch()

        case persist(runtime, session, []) do
          {:ok, runtime} -> reply_turn_waiters(runtime, turn_id)
          {:error, runtime} -> runtime
        end

      :error ->
        runtime
    end
  end

  defp recover_checkpointed_dispatch(runtime, %SessionInfo{} = info) do
    case unresolved_dispatches(runtime.session) do
      [] ->
        {:ok, runtime}

      [turn_id]
      when info.state == :idle and is_nil(info.active_turn_id) and info.queued_turns == 0 ->
        turn = Map.fetch!(runtime.session.turns, turn_id)

        with {:ok, request} <- TurnRequest.new(turn.request),
             request =
               Provider.apply_runtime_provider_policy(request, runtime.session.provider),
             {:ok, request} <-
               authorize_turn_attachments(request, runtime.session.workspace) do
          case checkpoint_recovered_turn_request(runtime, turn, request) do
            {:ok, turn, runtime} ->
              case dispatch_persisted_turn(runtime, turn, request) do
                {:ok, _turn, runtime} -> {:ok, runtime}
                {:error, _reason, runtime} -> {:ok, runtime}
              end

            {:error, runtime} ->
              # Never dispatch under a policy the durable same-id fingerprint does not
              # describe. Once storage is writable, the exact same recovery path retries
              # the migration before it can cross into Harness.
              {:retry, runtime, :checkpointed_turn_policy_migration_failed, :storage_error}
          end
        else
          # The workspace *root* did not canonicalize. That is infrastructure — a mount
          # that is not up yet — not a verdict on this turn, and the checkpointed input
          # is still exactly reproducible once the root is back. Retry on the same
          # bounded backoff an unreachable session info call uses.
          {:error, {:invalid_attachment_workspace, reason}} ->
            {:retry, runtime, :attachment_workspace_unavailable, reason}

          # An attachment-level failure is a verdict: the file named in the checkpointed
          # input is gone or outside the workspace, so that input cannot be reproduced.
          {:error, reason} ->
            {:ok,
             mark_turn_ambiguous(runtime, turn_id, {:invalid_checkpointed_turn_request, reason})}
        end

      ids ->
        {:ok,
         Enum.reduce(ids, runtime, fn turn_id, runtime ->
           mark_turn_ambiguous(runtime, turn_id, {:dispatch_could_not_be_correlated, info.state})
         end)}
    end
  end

  defp checkpoint_recovered_turn_request(runtime, turn, request) do
    normalized = State.new_turn(turn.id, turn.mode, request)

    if turn.request == normalized.request and turn.fingerprint == normalized.fingerprint do
      {:ok, turn, runtime}
    else
      updated =
        turn
        |> Map.put(:request, normalized.request)
        |> Map.put(:fingerprint, normalized.fingerprint)
        |> State.touch_turn()

      session =
        %{runtime.session | turns: Map.put(runtime.session.turns, turn.id, updated)}
        |> State.touch()

      case persist(runtime, session, []) do
        {:ok, runtime} -> {:ok, updated, runtime}
        {:error, runtime} -> {:error, runtime}
      end
    end
  end

  defp settle_terminal_dispatch_intents(runtime, %SessionInfo{state: state}) do
    if terminal_session_state?(state) do
      Enum.reduce(unresolved_dispatches(runtime.session), runtime, fn turn_id, runtime ->
        mark_turn_ambiguous(
          runtime,
          turn_id,
          {:session_terminal_before_dispatch_reconciliation, state}
        )
      end)
    else
      runtime
    end
  end

  defp unresolved_result_turns?(session) do
    Enum.any?(session.turns, fn {_id, turn} ->
      is_binary(turn.harness_turn_id) and turn.status in [:queued, :running, :finishing]
    end)
  end

  defp unresolved_dispatches(session) do
    session.turns
    |> Enum.filter(fn {_id, turn} ->
      turn.status == :dispatching and is_nil(turn.harness_turn_id)
    end)
    |> Enum.map(&elem(&1, 0))
    |> Enum.sort()
  end

  defp mark_gap_ambiguities(session, events) do
    if Enum.any?(events, &replay_gap?/1) do
      Enum.reduce(unresolved_dispatches(session), session, fn turn_id, session ->
        turn = Map.fetch!(session.turns, turn_id)

        turn =
          turn
          |> Map.put(:status, :ambiguous)
          |> Map.put(:error, :dispatch_event_pruned_before_reconciliation)
          |> State.touch_turn()

        put_in(session.turns[turn_id], turn)
      end)
    else
      session
    end
  end

  defp replay_gap?(%Event{type: :provider_event, payload: payload}) when is_map(payload) do
    Map.get(payload, "kind") == "replay_gap" or Map.get(payload, :kind) == "replay_gap"
  end

  defp replay_gap?(_event), do: false

  defp reconcile_turn_ids(session, events) do
    known =
      session.turns
      |> Map.values()
      |> Enum.map(& &1.harness_turn_id)
      |> Enum.filter(&is_binary/1)
      |> MapSet.new()

    unknown_ids =
      events
      |> Enum.filter(&(&1.type in [:input_accepted, :turn_queued, :turn_started]))
      |> Enum.map(& &1.turn_id)
      |> Enum.filter(&is_binary/1)
      |> Enum.uniq()
      |> Enum.reject(&MapSet.member?(known, &1))

    dispatching =
      session.turns
      |> Map.values()
      |> Enum.filter(&(&1.status == :dispatching and is_nil(&1.harness_turn_id)))
      |> Enum.sort_by(& &1.created_at)

    {session, remaining_ids} =
      Enum.reduce(dispatching, {session, unknown_ids}, fn
        turn, {session, [harness_turn_id | rest]} ->
          status = status_for_harness_turn(events, harness_turn_id, turn.mode)

          turn =
            turn
            |> Map.put(:harness_turn_id, harness_turn_id)
            |> Map.put(:status, status)
            |> State.touch_turn()

          {put_in(session.turns[turn.id], turn), rest}

        _turn, {session, []} ->
          {session, []}
      end)

    Enum.reduce(remaining_ids, session, fn harness_turn_id, session ->
      id = "recovered:" <> harness_turn_id
      now = DateTime.utc_now() |> DateTime.to_iso8601()

      recovered = %{
        id: id,
        mode: :follow_up,
        fingerprint: State.fingerprint(:follow_up, %{harness_turn_id: harness_turn_id}),
        request: %{},
        harness_turn_id: harness_turn_id,
        status: status_for_harness_turn(events, harness_turn_id, :follow_up),
        result: nil,
        error: :recovered_without_request_checkpoint,
        created_at: now,
        updated_at: now
      }

      put_in(session.turns[id], recovered)
    end)
  end

  defp apply_turn_event_statuses(session, events) do
    Enum.reduce(events, session, fn event, session ->
      case find_turn_by_harness_id(session, event.turn_id) do
        nil ->
          session

        turn ->
          status =
            case event.type do
              type when type in [:input_accepted, :turn_started] -> :running
              :turn_queued -> :queued
              type when type in [:turn_completed, :turn_failed, :turn_interrupted] -> :finishing
              _other -> turn.status
            end

          put_in(session.turns[turn.id], turn |> Map.put(:status, status) |> State.touch_turn())
      end
    end)
  end

  defp status_for_harness_turn(events, harness_turn_id, mode) do
    types = events |> Enum.filter(&(&1.turn_id == harness_turn_id)) |> Enum.map(& &1.type)

    cond do
      Enum.any?(types, &(&1 in [:turn_completed, :turn_failed, :turn_interrupted])) -> :finishing
      :turn_started in types or :input_accepted in types -> :running
      :turn_queued in types or mode == :follow_up -> :queued
      true -> :dispatching
    end
  end

  defp find_turn_by_harness_id(_session, nil), do: nil

  defp find_turn_by_harness_id(session, harness_turn_id) do
    Enum.find_value(session.turns, fn {_id, turn} ->
      if turn.harness_turn_id == harness_turn_id, do: turn
    end)
  end

  defp harness_turn_id(_session, :active), do: {:ok, :active}

  defp harness_turn_id(session, id) when is_binary(id) do
    case Map.fetch(session.turns, id) do
      {:ok, %{harness_turn_id: harness_turn_id}} when is_binary(harness_turn_id) ->
        {:ok, harness_turn_id}

      {:ok, _turn} ->
        {:error, :turn_not_dispatched}

      :error ->
        if Enum.any?(session.turns, fn {_id, turn} -> turn.harness_turn_id == id end),
          do: {:ok, id},
          else: {:error, :not_found}
    end
  end

  defp turn_result_summary(result) do
    %{
      session_id: result.session_id,
      turn_id: result.turn_id,
      provider: result.provider,
      provider_session_id: result.provider_session_id,
      status: result.status,
      text: durable(result.text),
      text_truncated?: result.text_truncated?,
      usage: durable(result.usage),
      metadata: durable(result.metadata)
    }
  end

  defp fail_start(runtime, reason) do
    session =
      runtime.session
      |> Map.put(:status, :failed)
      |> Map.put(:error, durable(reason))
      |> State.touch()

    case persist(runtime, session, []) do
      {:ok, runtime} ->
        runtime |> release_workspace() |> reply_ready_waiters() |> schedule_retire()

      {:error, runtime} ->
        schedule_poll(runtime, @poll_interval)
    end
  end

  # Settled means this coordinator has nothing left to decide about resuming: it already
  # attempted one, already explained why it could not, or was told to end the session.
  defp settle_resume(runtime), do: %{runtime | resume_settled: true}

  # A Harness session Harness no longer knows is not the same thing as a provider
  # session that is gone. `provider_session_id` is durable, and every transport that
  # declares it can be handed it again — `claude --resume`, Codex `thread/resume`, ACP
  # `session/load`. So the answer to "Harness does not know this session" is to open a
  # new one against the same provider session and keep going; `:lost` is what is left
  # when there is nothing to resume with, or when the provider refuses.
  #
  # Bounded to one decision per coordinator incarnation — one attempt, or one refusal
  # explained once. A provider that loses the session again ends the session honestly
  # instead of spinning up a start loop, and a genuinely transient outage still gets a
  # fresh decision the next time recovery restarts the coordinator.
  defp resume_or_lose(%{resume_settled: true} = runtime, reason), do: lose(runtime, reason)

  defp resume_or_lose(runtime, reason) do
    runtime = settle_resume(runtime)

    case State.resume_support(runtime.session) do
      :ok ->
        attempt_resume(runtime)

      {:error, unsupported} ->
        Logger.info(
          "interactive session #{runtime.session.id} cannot be resumed " <>
            "(#{inspect(unsupported)}); losing it"
        )

        lose(runtime, reason)
    end
  end

  defp attempt_resume(runtime) do
    session = runtime.session

    case State.unrequestable_reason(session) do
      nil ->
        case safe_session_call(fn ->
               Session.start(session.provider, State.request(session))
             end) do
          {:ok, harness_session_id} ->
            adopt_resumed(runtime, harness_session_id, session.harness_session_id)

          {:error, reason} ->
            lose(runtime, {:resume_failed, reason})
        end

      unrequestable ->
        lose(runtime, {:resume_failed, {:unrequestable_session_state, unrequestable}})
    end
  end

  # What the resume does and does not restore, recorded where a client can read it: the
  # journal and the turn ledger are Ouroboros's and survive intact; the conversation
  # itself is the provider's and comes back only as far as the provider carries it. The
  # turn that was in flight at the break is finalised outcome-unknown rather than
  # retried — the provider may well have completed it, and nothing here can tell.
  # The workspace lease is untouched: this coordinator has held it since admission and
  # goes on holding it, exactly as it does across a restart.
  defp adopt_resumed(runtime, harness_session_id, previous_harness_session_id) do
    session = runtime.session
    sequence = session.cursor + 1

    event =
      Event.from_runtime(
        session.id,
        sequence,
        :status,
        %{
          "kind" => "resumed",
          "provider_session_id" => session.provider_session_id,
          "previous_harness_session_id" => previous_harness_session_id
        },
        harness_session_id: harness_session_id,
        provider: session.provider,
        provider_session_id: session.provider_session_id
      )

    resumed =
      session
      |> finalize_unresolved_turns({:session_resumed, :outcome_unknown})
      |> Map.put(:harness_session_id, harness_session_id)
      |> Map.put(:sequence_offset, sequence)
      |> Map.put(:cursor, sequence)
      |> Map.put(:resumes, State.resumes(session) + 1)
      |> Map.put(:error, nil)
      |> append_event(event)
      |> State.touch()

    case persist(runtime, resumed, [event]) do
      {:ok, runtime} ->
        runtime |> clear_retry() |> reply_all_terminal_turn_waiters() |> schedule_poll(0)

      # A resume whose checkpoint was refused did not happen. Close the new Harness
      # session rather than leave it running unreferenced; the attempt stays spent, so
      # the next poll finds the old session still missing and loses honestly.
      {:error, runtime} ->
        _ = safe_session_call(fn -> Session.close(harness_session_id) end)
        retry(runtime, :session_resume_checkpoint_failed, :storage_error)
    end
  end

  # Mid-session configuration, in the order that keeps the two records honest.
  #
  # The provider is told first. `Jido.Harness.Session.configure/2` is a synchronous call
  # whose answer is unambiguous — unlike a turn dispatch, nothing here can have half
  # happened — so a refusal leaves both the provider and the checkpoint on the old
  # options, which is the only outcome where "nothing changed" is true.
  #
  # Only then is the change recorded, and the record is what `interactive.info` answers
  # with and what a resume rebuilds the request from. A storage outage between the two is
  # named rather than swallowed: the provider took the change and this node could not
  # write it down, so the caller is told exactly that instead of being handed a success
  # that a restart would silently undo.
  defp configure_session(%{session: session} = runtime, changes) do
    if State.terminal?(session) do
      {:error, {:session_not_configurable, session.status}, runtime}
    else
      with {:ok, changes, applies} <-
             Provider.session_configuration(
               session.provider,
               changes,
               Map.get(session.options, :transport)
             ),
           :ok <- apply_configuration(runtime, changes) do
        record_configuration(runtime, changes, applies)
      else
        {:error, reason} -> {:error, reason, runtime}
      end
    end
  end

  defp apply_configuration(runtime, changes) do
    case with_harness_session(runtime, &Session.configure(&1, changes)) do
      :ok -> :ok
      {:error, reason} -> {:error, {:configure_refused, durable(reason)}}
      other -> {:error, {:configure_refused, durable(other)}}
    end
  end

  # The event is Ouroboros's own: no provider reports that its own settings were changed
  # from outside, and a client watching the stream has to see the change land in the same
  # ordered log as everything else. `applies` travels with it because "next turn" is a
  # fact about the transport that a footer has to be able to state rather than imply.
  #
  # `sequence_offset` climbs with the cursor for exactly the reason it exists: the next
  # poll asks Harness for events after `cursor - offset`, and moving one without the
  # other would either skip a provider event or collide with it.
  defp record_configuration(runtime, changes, applies) do
    session = runtime.session
    sequence = session.cursor + 1

    event =
      Event.from_runtime(
        session.id,
        sequence,
        :status,
        %{
          "kind" => "configured",
          "applies" => Atom.to_string(applies),
          "changed" => Map.new(changes, fn {key, value} -> {Atom.to_string(key), value} end)
        },
        harness_session_id: session.harness_session_id,
        provider: session.provider,
        provider_session_id: session.provider_session_id
      )

    configured =
      session
      |> State.configure(changes)
      |> Map.put(:cursor, sequence)
      |> Map.put(:sequence_offset, State.sequence_offset(session) + 1)
      |> append_event(event)
      |> State.touch()

    case persist(runtime, configured, [event]) do
      {:ok, runtime} ->
        {:ok,
         %{
           options: State.public(runtime.session).options,
           applies: applies,
           changed: changes |> Map.keys() |> Enum.sort()
         }, runtime}

      {:error, runtime} ->
        {:error, {:configure_checkpoint_failed, :provider_accepted}, runtime}
    end
  end

  defp lose(runtime, reason) do
    session =
      runtime.session
      |> finalize_unresolved_turns({:session_lost, reason})
      |> Map.put(:status, :lost)
      |> Map.put(:error, durable(reason))
      |> State.touch()

    case persist(runtime, session, []) do
      {:ok, runtime} ->
        runtime
        |> release_workspace()
        |> reply_ready_waiters()
        |> reply_all_terminal_turn_waiters()
        |> schedule_retire()

      {:error, runtime} ->
        schedule_poll(runtime, @poll_interval)
    end
  end

  # A wedged provider used to be retried every 25ms, rewriting the whole session
  # aggregate to disk on every attempt to record an error identical to the one
  # already checkpointed. Back off, and only checkpoint the error the first time it
  # is seen or when it changes.
  defp retry(runtime, kind, reason) do
    error = {kind, durable(reason)}
    {repeat?, runtime} = note_retry(runtime, error)
    delay = runtime.retry.delay

    if repeat? do
      schedule_poll(runtime, delay)
    else
      session = runtime.session |> Map.put(:error, error) |> State.touch()

      case persist(runtime, session, []) do
        {:ok, runtime} -> schedule_poll(runtime, delay)
        {:error, runtime} -> schedule_poll(runtime, delay)
      end
    end
  end

  defp note_retry(%{retry: retry} = runtime, signature) do
    repeat? = retry.count > 0 and retry.signature == signature

    delay =
      if retry.count == 0, do: @poll_interval, else: min(retry.delay * 2, @retry_backoff_max_ms)

    {repeat?, %{runtime | retry: %{signature: signature, count: retry.count + 1, delay: delay}}}
  end

  defp clear_retry(%{retry: %{count: 0}} = runtime), do: runtime
  defp clear_retry(runtime), do: %{runtime | retry: no_retry()}

  defp finalize_unresolved_turns(session, reason) do
    reason = durable(reason)

    turns =
      Map.new(session.turns, fn {id, turn} ->
        if State.terminal_turn?(turn) do
          {id, turn}
        else
          {id,
           turn
           |> Map.put(:status, :ambiguous)
           |> Map.put(:error, reason)
           |> State.touch_turn()}
        end
      end)

    %{session | turns: turns}
  end

  defp persist(runtime, session, events) do
    case Store.put(session) do
      :ok ->
        Enum.each(runtime.subscribers, fn {pid, _monitor} ->
          Enum.each(events, &send(pid, {:ouroboros_interactive_event, session.id, &1}))
        end)

        {:ok, %{runtime | session: session}}

      # A refused checkpoint is not a storage outage. Polling cannot make a session the
      # store will not accept acceptable, and the old shared retry path left exactly that
      # session running forever: no waiter answered, no workspace released.
      {:error, :invalid_interactive_session} ->
        {:error, abandon(runtime, session)}

      {:error, _reason} ->
        {:error, runtime}
    end
  end

  defp abandon(%{session: session} = runtime, _rejected) do
    if State.terminal?(session), do: runtime, else: do_abandon(runtime, session)
  end

  # The refused state is not the one that gets recorded: it is the state the store just
  # rejected. What is recorded is the last accepted state, marked failed, which the store
  # accepts because a terminal session never builds another request.
  defp do_abandon(runtime, last_accepted) do
    reason =
      {:unstorable_session_state,
       State.unrequestable_reason(runtime.session) || :rejected_by_store}

    Logger.error(
      "interactive session #{last_accepted.id} was refused by the store: " <>
        "#{inspect(reason)}; failing it"
    )

    session =
      last_accepted
      |> finalize_unresolved_turns({:session_failed, reason})
      |> Map.put(:status, :failed)
      |> Map.put(:error, reason)
      |> State.touch()

    # Even a refused terminal record leaves this process ending honestly: the durable
    # checkpoint stays as the store last accepted it, and nothing here spins.
    _ = Store.put(session)

    %{runtime | session: session}
    |> release_workspace()
    |> reply_ready_waiters()
    |> reply_all_terminal_turn_waiters()
    |> schedule_retire()
  end

  defp append_event(session, event) do
    events = session.events ++ [event]
    overflow = max(length(events) - session.event_limit, 0)
    {discarded, events} = Enum.split(events, overflow)

    floor =
      case List.last(discarded) do
        nil -> session.event_floor
        discarded_event -> discarded_event.sequence
      end

    %{session | events: events, event_floor: floor}
  end

  defp maybe_provider_session(session, nil), do: session
  defp maybe_provider_session(session, id), do: %{session | provider_session_id: id}

  defp normalize_session_status(status)
       when status in [
              :starting,
              :idle,
              :running,
              :awaiting_approval,
              :closing,
              :closed,
              :failed,
              :cancelled
            ],
       do: status

  defp normalize_session_status(_status), do: :failed

  defp terminal_session_state?(status), do: status in [:closed, :failed, :cancelled]

  defp ready?(%State{status: status}), do: status in [:idle, :running, :awaiting_approval]

  defp with_harness_session(%{session: %State{harness_session_id: nil}}, _fun),
    do: {:error, :session_not_started}

  defp with_harness_session(runtime, fun) do
    safe_session_call(fn -> fun.(runtime.session.harness_session_id) end)
  end

  # Everything that lands in durable session state goes through here. Redaction removes
  # secrets; it leaves runtime authority alone, and a harness call exit reason carries
  # the pid it was calling. The store refuses such a checkpoint on every attempt, so a
  # session that wrote one used to retry that refusal for the rest of its life.
  defp durable(term), do: term |> Jido.Harness.Redaction.redact() |> State.durable_term()

  defp safe_session_call(fun) do
    try do
      fun.()
    rescue
      error -> {:error, {:harness_call_exception, error.__struct__, Exception.message(error)}}
    catch
      :exit, reason -> {:error, {:harness_call_exit, reason}}
    end
  end

  defp replay_events(session, cursor, limit)
       when is_integer(cursor) and cursor >= 0 and is_integer(limit) and limit > 0 and
              limit <= 10_000 do
    if cursor < session.event_floor do
      {:error, {:cursor_pruned, session.event_floor}}
    else
      {:ok, session.events |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit)}
    end
  end

  defp replay_events(_session, cursor, limit),
    do: {:error, {:invalid_cursor_or_limit, cursor, limit}}

  defp subscription_events(session, cursor) when is_integer(cursor) and cursor >= 0 do
    if cursor < session.event_floor,
      do: {:error, {:cursor_pruned, session.event_floor}},
      else: {:ok, Enum.filter(session.events, &(&1.sequence > cursor))}
  end

  defp subscription_events(_session, cursor), do: {:error, {:invalid_cursor, cursor}}

  defp put_subscriber(runtime, subscriber) when is_pid(subscriber) do
    runtime = drop_subscriber(runtime, subscriber)
    monitor = Process.monitor(subscriber)

    %{
      runtime
      | subscribers: Map.put(runtime.subscribers, subscriber, monitor),
        subscriber_monitors: Map.put(runtime.subscriber_monitors, monitor, subscriber)
    }
  end

  defp drop_subscriber(runtime, subscriber) do
    case Map.pop(runtime.subscribers, subscriber) do
      {nil, _subscribers} ->
        runtime

      {monitor, subscribers} ->
        Process.demonitor(monitor, [:flush])

        %{
          runtime
          | subscribers: subscribers,
            subscriber_monitors: Map.delete(runtime.subscriber_monitors, monitor)
        }
    end
  end

  defp drop_subscriber_by_monitor(runtime, monitor) do
    case Map.pop(runtime.subscriber_monitors, monitor) do
      {nil, _monitors} ->
        runtime

      {subscriber, monitors} ->
        %{
          runtime
          | subscribers: Map.delete(runtime.subscribers, subscriber),
            subscriber_monitors: monitors
        }
    end
  end

  defp add_turn_waiter(runtime, turn_id, request_ref, from) do
    monitor = Process.monitor(elem(from, 0))
    waiter = %{from: from, monitor: monitor, turn_id: turn_id}
    {:noreply, %{runtime | turn_waiters: Map.put(runtime.turn_waiters, request_ref, waiter)}}
  end

  defp drop_turn_waiter(runtime, request_ref) do
    case Map.pop(runtime.turn_waiters, request_ref) do
      {nil, _waiters} ->
        runtime

      {%{monitor: monitor}, waiters} ->
        Process.demonitor(monitor, [:flush])
        %{runtime | turn_waiters: waiters}
    end
  end

  defp drop_turn_waiter_by_monitor(runtime, monitor) do
    case Enum.find(runtime.turn_waiters, fn {_ref, waiter} -> waiter.monitor == monitor end) do
      nil ->
        runtime

      {request_ref, _waiter} ->
        %{runtime | turn_waiters: Map.delete(runtime.turn_waiters, request_ref)}
    end
  end

  defp reply_turn_waiters(runtime, turn_id) do
    case Map.fetch(runtime.session.turns, turn_id) do
      {:ok, turn} when turn.status in [:completed, :failed, :interrupted, :ambiguous] ->
        {matching, remaining} =
          Enum.split_with(runtime.turn_waiters, fn {_ref, waiter} -> waiter.turn_id == turn_id end)

        Enum.each(matching, fn {_ref, waiter} ->
          Process.demonitor(waiter.monitor, [:flush])
          GenServer.reply(waiter.from, {:ok, State.public_turn(turn)})
        end)

        %{runtime | turn_waiters: Map.new(remaining)}

      _other ->
        runtime
    end
  end

  defp reply_all_terminal_turn_waiters(runtime) do
    Enum.reduce(Map.keys(runtime.session.turns), runtime, &reply_turn_waiters(&2, &1))
  end

  defp reply_ready_waiters(%{ready_timer: timer} = runtime) when is_reference(timer) do
    Process.cancel_timer(timer)
    reply_ready_waiters(%{runtime | ready_timer: nil})
  end

  defp reply_ready_waiters(runtime) do
    reply =
      if ready?(runtime.session),
        do: {:ok, State.public(runtime.session)},
        else: {:error, {:session_start_failed, runtime.session.error}}

    Enum.each(runtime.ready_waiters, fn {from, monitor} ->
      Process.demonitor(monitor, [:flush])
      GenServer.reply(from, reply)
    end)

    %{runtime | ready_waiters: []}
  end

  defp arm_ready_deadline(%{ready_timer: nil} = runtime) do
    %{runtime | ready_timer: Process.send_after(self(), :ready_deadline, readiness_deadline_ms())}
  end

  defp arm_ready_deadline(runtime), do: runtime

  defp readiness_deadline_ms do
    case Application.get_env(
           :ouroboros,
           :interactive_readiness_deadline_ms,
           @default_readiness_deadline_ms
         ) do
      deadline when is_integer(deadline) and deadline > 0 -> deadline
      _invalid -> @default_readiness_deadline_ms
    end
  end

  defp drop_ready_waiter_by_monitor(runtime, monitor) do
    waiters =
      Enum.reject(runtime.ready_waiters, fn {_from, waiter_monitor} ->
        waiter_monitor == monitor
      end)

    %{runtime | ready_waiters: waiters}
  end

  defp schedule_poll(runtime, delay) do
    Process.send_after(self(), :poll, delay)
    runtime
  end

  defp schedule_retire(runtime) do
    Process.send_after(self(), :retire, @terminal_retire_ms)
    runtime
  end

  defp validate_turn_id(id) do
    if String.trim(id) == "", do: {:error, :invalid_turn_id}, else: :ok
  end

  defp ensure_serializable(value) do
    if serializable?(value), do: :ok, else: {:error, :non_serializable_turn_request}
  end

  defp ensure_secret_free_options(%TurnRequest{} = request) do
    private_options =
      request
      |> Map.from_struct()
      |> Map.take([:attachments, :output_schema, :metadata, :provider_options])

    if Jido.Harness.Redaction.redact(private_options) == private_options,
      do: :ok,
      else: {:error, :secret_bearing_turn_options}
  end

  defp serializable?(value)
       when is_pid(value) or is_port(value) or is_reference(value) or is_function(value),
       do: false

  defp serializable?(value) when is_struct(value),
    do: value |> Map.from_struct() |> serializable?()

  defp serializable?(value) when is_map(value),
    do: Enum.all?(value, fn {key, nested} -> serializable?(key) and serializable?(nested) end)

  defp serializable?(value) when is_list(value), do: Enum.all?(value, &serializable?/1)

  defp serializable?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(_value), do: true

  defp admit_workspace(session) do
    if is_pid(Process.whereis(WorkspaceManager)) do
      case acquire_workspace(session, @workspace_reacquire_attempts) do
        {:ok, lease, capability} ->
          leased =
            session
            |> Map.put(:workspace, lease.root)
            |> Map.put(:workspace_mode, lease.mode)
            |> Map.put(:workspace_lease_id, lease.id)
            |> State.touch()

          case Store.put(leased) do
            :ok ->
              {:ok, runtime(leased, lease, capability)}

            # The store refuses a session it cannot run. Keep the lease rather than stop:
            # this session is about to fail as itself, and that failure is what releases
            # the workspace and clears the recovery reservation the lease just replaced.
            {:error, :invalid_interactive_session} ->
              {:ok, runtime(leased, lease, capability)}

            {:error, reason} ->
              _ = safe_workspace_release(lease.id, capability)
              {:error, {:storage_error, reason}}
          end

        {:error, reason} ->
          checkpoint_admission_failure(session, reason)
      end
    else
      {:ok, runtime(session)}
    end
  end

  defp acquire_workspace(session, attempts) do
    result =
      try do
        Workspace.acquire_managed(
          session.workspace,
          "interactive:" <> session.id,
          :interactive,
          mode: session.workspace_mode,
          server: WorkspaceManager
        )
      catch
        :exit, reason -> {:error, {:workspace_manager_unavailable, reason}}
      end

    case result do
      {:error, {:workspace_conflict, conflicts}} = error when attempts > 0 ->
        if stale_own_lease?(conflicts, session.id) do
          Process.sleep(@workspace_reacquire_delay_ms)
          acquire_workspace(session, attempts - 1)
        else
          error
        end

      other ->
        other
    end
  end

  defp stale_own_lease?([_ | _] = conflicts, session_id) do
    task_id = "interactive:" <> session_id
    Enum.all?(conflicts, &(Map.get(&1, :task_id) == task_id))
  end

  defp stale_own_lease?(_conflicts, _session_id), do: false

  defp checkpoint_admission_failure(session, reason) do
    redacted = durable(reason)

    failed =
      session
      |> Map.put(:status, :failed)
      |> Map.put(:error, {:workspace_admission_failed, redacted})
      |> State.touch()

    case Store.put(failed) do
      :ok ->
        {:error, {:workspace_admission_failed, redacted}}

      {:error, store_reason} ->
        {:error, {:workspace_admission_failed, redacted, {:checkpoint_failed, store_reason}}}
    end
  end

  defp release_workspace(%{workspace_lease: nil} = runtime), do: runtime

  defp release_workspace(runtime) do
    _ = safe_workspace_release(runtime.workspace_lease.id, runtime.workspace_capability)
    %{runtime | workspace_lease: nil, workspace_capability: nil}
  end

  defp safe_workspace_release(lease_id, capability) do
    try do
      Workspace.release(lease_id, server: WorkspaceManager, capability: capability)
    catch
      :exit, _reason -> :ok
    end
  end
end
