defmodule Ouroboros.Interactive.Task do
  @moduledoc false

  use GenServer, restart: :transient

  require Logger

  alias Jido.Harness.{Session, SessionInfo, TurnRequest, TurnResult}
  alias Ouroboros.Interactive.{Event, State, Store}
  alias Ouroboros.Provider
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Session, as: NativeSession
  alias Ouroboros.Provider.Session, as: ProviderSession
  alias Ouroboros.Team
  alias Ouroboros.Runtime.Exposure
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Exec
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager
  alias Ouroboros.Workspace.Path, as: WorkspacePath
  alias Ouroboros.Workspace.Worktree

  @poll_interval 25
  @replay_limit 100
  @terminal_retire_ms 100
  @workspace_reacquire_attempts 25
  @workspace_reacquire_delay_ms 4
  @retry_backoff_max_ms 5_000
  @default_unresolved_turn_deadline_ms 10 * 60 * 1_000
  @default_readiness_deadline_ms 10 * 60 * 1_000
  @max_pending_steers 32

  # B7. A command line an operator typed, bounded where it is accepted. The permission
  # engine bounds its own reading at 8 KiB; anything past this is not a command somebody
  # meant to run in a terminal.
  @max_shell_command_bytes 8_192

  # How many of an operator's own commands the next turn's runtime envelope carries.
  # Three, and only their excerpts: the model is being told what the person just did, not
  # given a second transcript to read.
  @max_exposed_operator_commands 3

  # G1. An objective an operator typed into a composer, bounded where it is accepted. It
  # becomes a coding task's durable objective, and the coding plane has its own bound;
  # this one is smaller because it is a sentence, not a document.
  @max_delegation_objective_bytes 8_192

  # C2 — external approvals. One session may hold at most this many unanswered questions
  # at once; the next is denied rather than queued, because a provider that can ask nine
  # times without being answered is a provider nobody is reading, and an unbounded table
  # of waiting callers is an unbounded table.
  @max_external_approvals 8

  # I1. How many `request_id => ledger effect id` stamps this coordinator keeps in memory
  # so a later `approval_resolved` can name its entry. Comfortably above the eight
  # approvals that can be outstanding at once, and bounded because it is memory.
  @max_approval_effects 64

  # The coordinator's own wait, when the session states none. Layered deliberately below
  # `Ouroboros.InteractiveSession`'s transport wait and the gateway's method ceiling, so
  # the answer a caller gets is this module's honest denial rather than a killed task.
  @external_approval_default_timeout_ms 10 * 60 * 1_000
  @external_approval_min_timeout_ms 1_000
  @external_approval_ceiling_ms 13 * 60 * 1_000

  # Consulted through `Code.ensure_loaded?/1` on purpose: C1 lands separately, and a
  # runtime without it must still ask a human rather than fail or invent a verdict. The
  # name is read from application environment rather than hard-called so that this module
  # compiles, and behaves, on a node where the engine does not exist yet.
  @default_permissions_engine Ouroboros.Control.Permissions
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
  def handle_continue(:attach, runtime) do
    # An external approval outstanding when this coordinator died was never answered, and
    # the call waiting on it died with the gateway task that held it. Closing those rows
    # as denials before anything else keeps the journal from claiming a question that
    # nobody is going to answer, and keeps the deny-by-default posture across a restart.
    runtime = deny_orphaned_external_approvals(runtime)

    if State.terminal?(runtime.session) do
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

  # C2. An approval this runtime was asked for by something that is not the Harness — the
  # `ouro mcp-serve` bridge answering Claude's `--permission-prompt-tool`, today the only
  # caller. The coordinator mints the request id, so the same `respond_approval` verb, the
  # same modal, and the same durable `approval_requested`/`approval_resolved` pair serve a
  # managed transport that has no approvals channel of its own.
  #
  # Every path here ends in an answer, and none of them allows by omission: a full table,
  # a terminal session, a refused checkpoint, and a deadline all deny, and each says why.
  def handle_call({:request_approval, request_ref, request}, from, runtime)
      when is_reference(request_ref) and is_map(request) do
    cond do
      State.terminal?(runtime.session) ->
        {:reply,
         {:ok,
          external_answer(
            nil,
            :deny,
            :session_terminal,
            "session #{runtime.session.id} is #{runtime.session.status}"
          )}, runtime}

      map_size(runtime.external_approvals) >= @max_external_approvals ->
        {:reply,
         {:ok,
          external_answer(
            nil,
            :deny,
            :capacity,
            "session #{runtime.session.id} already has #{@max_external_approvals} " <>
              "unanswered approval requests outstanding"
          )}, runtime}

      true ->
        open_external_approval(runtime, request_ref, request, from)
    end
  end

  # Routed ahead of the Harness clause, and only for an id this coordinator minted. A
  # request id the Harness owns is not in this map and falls through to the clause below
  # untouched, which is what keeps the existing modal working for Codex and ACP.
  def handle_call({:respond_approval, request_id, response}, _from, runtime)
      when is_map_key(runtime.external_approvals, request_id) do
    decision = if Map.get(response, :decision) == :approve, do: :allow, else: :deny

    reason =
      case Map.get(response, :reason) do
        text when is_binary(text) and text != "" -> text
        _absent -> nil
      end

    scope = Map.get(response, :scope, :once)

    # I1. Recorded before the answer reaches the caller waiting on it, for the same reason
    # the request was recorded before it was asked.
    {effect_id, runtime} =
      record_approval(
        runtime,
        request_id,
        decision,
        scope,
        response,
        external_approval_subject(runtime, request_id),
        "external"
      )

    {:reply, :ok,
     close_external_approval(runtime, request_id, decision, :human, reason, scope, effect_id)}
  end

  def handle_call({:respond_approval, request_id, response}, _from, runtime) do
    # I1. Written before the answer is forwarded to the transport. Every provider reaches
    # this clause — the native session, the Codex and ACP dialects — so one entry per human
    # answer holds however the provider asked the question.
    decision = if Map.get(response, :decision) == :approve, do: :allow, else: :deny

    runtime =
      case harness_approval_subject(runtime, request_id) do
        :unknown ->
          runtime

        subject ->
          {_effect_id, runtime} =
            record_approval(
              runtime,
              request_id,
              decision,
              Map.get(response, :scope, :once),
              response,
              subject,
              "provider"
            )

          runtime
      end

    reply = with_harness_session(runtime, &Session.respond_approval(&1, request_id, response))
    {:reply, reply, schedule_poll(runtime, 0)}
  end

  def handle_call({:configure, changes}, _from, runtime) do
    case configure_session(runtime, changes) do
      {:ok, result, runtime} -> {:reply, {:ok, result}, schedule_poll(runtime, 0)}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  # D9. Compaction is native-only because only there does this runtime hold the
  # conversation to fold. A vendor CLI's own compaction is surfaced as an event when it
  # reports one; imitating it here would be a summary Ouroboros invented for a transcript
  # it never had.
  def handle_call({:rewind, to_turn, what}, _from, runtime) do
    case native_transport(runtime.session, :rewind) do
      {:ok, pid} ->
        result =
          case safe_session_call(fn -> NativeSession.rewind(pid, to_turn, what) end) do
            {:ok, report} when is_map(report) -> {:ok, durable(report)}
            {:error, reason} -> {:error, {:rewind_refused, durable(reason)}}
            other -> {:error, {:rewind_refused, durable(other)}}
          end

        {:reply, result, runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call(:rewind_points, _from, runtime) do
    case native_transport(runtime.session, :rewind_points) do
      {:ok, pid} ->
        result =
          case safe_session_call(fn -> NativeSession.rewind_points(pid) end) do
            {:ok, points} -> {:ok, durable(points)}
            {:error, reason} -> {:error, {:rewind_refused, durable(reason)}}
            other -> {:error, {:rewind_refused, durable(other)}}
          end

        {:reply, result, runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:compact, focus}, _from, runtime) do
    case native_transport(runtime.session, :compact) do
      {:ok, pid} ->
        {:reply, compact_native(pid, focus), runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  # Read-only, and it answers for every transport — with different amounts of truth. The
  # native session knows its own prefix, window, compactions and instruction files; every
  # other transport knows only what its `usage` events reported, and that is what it says
  # rather than a shape padded out with nulls that look like measurements.
  def handle_call(:context, _from, runtime) do
    {:reply, {:ok, session_context(runtime.session)}, runtime}
  end

  # B7. Two calls, not one, and the split is the whole design: a command may run for ten
  # minutes, and a coordinator blocked behind one would answer nothing — not `info`, not
  # `interrupt`, not its own turns — for that long. This call decides, records, and hands
  # back a plan; `Ouroboros.InteractiveSession.exec/2` runs the command in the caller's
  # own process, under the caller's own ceiling.
  def handle_call({:exec_plan, command}, _from, runtime) do
    case plan_operator_shell(runtime, command) do
      {:ok, plan, runtime} -> {:reply, {:ok, plan}, runtime}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:exec_settled, effect_id, outcome}, _from, runtime) do
    {:reply, :ok, settle_operator_shell(runtime, effect_id, outcome)}
  end

  # G1. Split for the same reason the shell verb is: `Team.add_worker/3` and
  # `Team.delegate/4` bound themselves at sixty seconds, and a conversation that answered
  # nothing for a minute because it had asked a team a question would be a worse bargain
  # than the delegation is worth. This call decides and mints; the caller does the team
  # work; `{:delegation_started, …}` brings the result back.
  def handle_call({:delegate_plan, objective, opts}, _from, runtime) do
    {:reply, delegate_plan(runtime, objective, opts), runtime}
  end

  def handle_call({:delegation_started, record}, _from, runtime) do
    case record_delegation(runtime, record) do
      {:ok, runtime} -> {:reply, {:ok, Map.take(record, [:id, :task_id, :task_node])}, runtime}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call(:delegations, _from, runtime) do
    {:reply, {:ok, State.delegations(runtime.session)}, runtime}
  end

  # Same three-step shape as a fork, and for the same reason: this coordinator writes the
  # packet and names the child, and `Ouroboros.InteractiveSession.handoff/3` starts the
  # child outside this process so a parent is never blocked behind provider readiness it
  # does not own.
  def handle_call({:handoff_plan, prompt, id}, _from, runtime) do
    {:reply, handoff_plan(runtime, prompt, id), runtime}
  end

  # Planning a fork is this coordinator's job; *starting* one is not. A session start
  # waits on provider readiness, which is legitimately unbounded, and a parent blocked on
  # that wait would answer nothing — not `info`, not `interrupt`, not its own turns —
  # until a child it does not own had finished starting or hit the readiness deadline. So
  # this answers with the child's start intent and nothing else, and
  # `Ouroboros.InteractiveSession.fork/2` starts the child outside this process.
  def handle_call({:fork_plan, id}, _from, runtime) do
    {:reply, fork_plan(runtime.session, id), runtime}
  end

  # Counted only once the child exists, so the number never claims a session nobody can
  # open. A refused checkpoint leaves the count low rather than losing the child:
  # `forked_from` on the child is the durable half of the relationship.
  def handle_call(:count_fork, _from, runtime) do
    counted = runtime.session |> State.count_fork() |> State.touch()

    case persist(runtime, counted, []) do
      {:ok, runtime} ->
        {:reply, {:ok, State.forks(runtime.session)}, runtime}

      {:error, runtime} ->
        Logger.warning(
          "interactive session #{runtime.session.id} started a fork but could not " <>
            "checkpoint its fork count; the child is unaffected"
        )

        {:reply, {:error, :fork_count_checkpoint_failed}, runtime}
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
      {:error, {:invalid_title, _detail} = reason} ->
        {:reply, {:error, reason}, runtime}

      {:error, runtime} ->
        {:reply, {:error, {:rename_checkpoint_failed, :storage_error}}, runtime}
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

  # G1's other direction: the team learned a delegated task reached a terminal status and
  # is telling the conversation that asked for it. A cast rather than a call on purpose —
  # `Team.Server` must never block on a session coordinator to finish delivering a result
  # — so a note whose parent is not up is lost, and `interactive.delegations` reads the
  # team's own record rather than this one when it wants the truth.
  @impl true
  def handle_cast({:delegation_settled, delegation_id, status, result_digest}, runtime) do
    {:noreply, settle_delegation(runtime, delegation_id, status, result_digest)}
  end

  def handle_cast({:cancel_await, request_ref}, runtime) do
    {:noreply, drop_turn_waiter(runtime, request_ref)}
  end

  # The waiting side gave up first — its own transport ceiling fired, or the gateway task
  # was killed at the method ceiling. The row is closed as a denial rather than dropped,
  # so the journal records that the question was asked and never answered by a human, and
  # the slot returns to the eight.
  def handle_cast({:cancel_approval, request_ref}, runtime) do
    case Enum.find(runtime.external_approvals, fn {_id, pending} ->
           pending.request_ref == request_ref
         end) do
      {request_id, _pending} ->
        {:noreply,
         close_external_approval(
           runtime,
           request_id,
           :deny,
           :caller_gone,
           "the caller stopped waiting for this approval",
           :once
         )}

      nil ->
        {:noreply, runtime}
    end
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

  # The coordinator's own ceiling on an unanswered external approval. It fires below the
  # transport wait and well below the gateway's method ceiling on purpose: a denial that
  # names the deadline is a better answer than a killed task, and the tool must never run
  # because nobody got round to saying no.
  def handle_info({:external_approval_timeout, request_id}, runtime)
      when is_map_key(runtime.external_approvals, request_id) do
    ms = runtime.external_approvals[request_id].timeout_ms

    {:noreply,
     close_external_approval(
       runtime,
       request_id,
       :deny,
       :timeout,
       "no answer within #{ms}ms",
       :once
     )}
  end

  def handle_info({:external_approval_timeout, _request_id}, runtime), do: {:noreply, runtime}

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
      resume_settled: false,
      external_approvals: %{},
      # I1. `request_id => effect_id` for approvals this coordinator has recorded, so the
      # `approval_resolved` a transport emits later can be stamped with the ledger entry
      # its answer was written under. Memory, and bounded: the durable record is the
      # ledger entry itself, and a coordinator restart loses only the stamp.
      approval_effects: %{}
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

  # B2. A plan exit the native session applied changed the session's approval and
  # sandbox modes from inside, on an answer this coordinator only relayed. The durable
  # record — and so `interactive.info` — follows the event, or a client would keep drawing
  # a posture the session no longer runs under. Mode names are matched against the closed
  # vocabularies rather than turned into atoms.
  @plan_exit_approval_modes %{
    "auto_edit" => :auto_edit,
    "prompt" => :prompt,
    "auto_approve" => :auto_approve,
    "default" => :default
  }
  @plan_exit_sandbox_modes %{
    "read_only" => :read_only,
    "workspace_write" => :workspace_write,
    "danger_full_access" => :danger_full_access
  }

  defp apply_plan_exits(session, events) do
    Enum.reduce(events, session, fn
      %Event{
        type: :provider_event,
        payload: %{"kind" => "plan_exit", "applied" => true} = payload
      },
      session ->
        State.configure(session, plan_exit_changes(payload))

      _event, session ->
        session
    end)
  end

  defp plan_exit_changes(payload) do
    %{plan: Map.get(payload, "plan") == true}
    |> put_known(:approval_mode, @plan_exit_approval_modes, Map.get(payload, "approval_mode"))
    |> put_known(:sandbox_mode, @plan_exit_sandbox_modes, Map.get(payload, "sandbox_mode"))
  end

  defp put_known(changes, key, vocabulary, value) do
    case Map.fetch(vocabulary, value) do
      {:ok, atom} -> Map.put(changes, key, atom)
      :error -> changes
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
    projected = Enum.map(projected, &enrich_approval_resolved(&1, runtime.approval_effects))

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
      |> apply_plan_exits(projected)
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
      # B2/C4. Two keys are not Harness configuration fields — the pinned `SessionRequest`
      # refuses a fifth — so they are split off here and go around `Session.configure/2`:
      # `plan` to the native session, where `Provider.plan_mode/2` says the transport can
      # be told mid-life, and `mode` to the session's own transport, where
      # `Provider.session_mode/2` says the agent published a vocabulary to name. Everything
      # else takes the path it always took.
      {plan, rest} = Map.pop(changes, :plan)
      {mode, rest} = Map.pop(rest, :mode)

      with {:ok, rest, applies} <- configuration_changes(session, rest, plan, mode),
           :ok <- apply_plan(runtime, plan),
           :ok <- apply_mode(runtime, mode),
           :ok <- apply_rest(runtime, rest) do
        record_configuration(runtime, plan_changes(rest, plan, mode), applies)
      else
        {:error, reason} -> {:error, reason, runtime}
      end
    end
  end

  # A change that is only `plan` or only `mode` has nothing for the provider to validate;
  # a change that is nothing at all is still refused there, as it always was.
  defp configuration_changes(_session, rest, planning?, mode)
       when rest == %{} and (is_boolean(planning?) or is_binary(mode)),
       do: {:ok, %{}, :now}

  defp configuration_changes(session, rest, _planning?, _mode),
    do:
      Provider.session_configuration(session.provider, rest, Map.get(session.options, :transport))

  defp apply_rest(_runtime, rest) when rest == %{}, do: :ok
  defp apply_rest(runtime, rest), do: apply_configuration(runtime, rest)

  defp plan_changes(rest, plan, mode) do
    rest
    |> then(fn changes -> if is_nil(plan), do: changes, else: Map.put(changes, :plan, plan) end)
    |> then(fn changes -> if is_nil(mode), do: changes, else: Map.put(changes, :mode, mode) end)
  end

  # C4. The agent's own mode id, forwarded as `session/set_mode` and validated by the
  # dialect against what the agent announced. Not written into the session's durable
  # options: a mode belongs to the live agent process, and a resumed session starts a new
  # one in that agent's own default. The `configured` event still records the change, so
  # the transcript says what was asked for even though nothing claims it survives.
  defp apply_mode(_runtime, nil), do: :ok

  defp apply_mode(%{session: session} = runtime, mode) when is_binary(mode) do
    case Provider.session_mode(session.provider, Map.get(session.options, :transport)) do
      {:ok, _support} ->
        with_harness_session(runtime, fn harness_session_id ->
          case ProviderSession.ask(harness_session_id, :set_mode, %{mode: mode}) do
            {:ok, _answer} -> :ok
            {:error, reason} -> {:error, {:configure_refused, durable(reason)}}
          end
        end)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp apply_plan(_runtime, nil), do: :ok

  defp apply_plan(%{session: session}, planning?) when is_boolean(planning?) do
    case Provider.plan_mode(session.provider, Map.get(session.options, :transport)) do
      {:ok, %{settable: :any_time}} ->
        with {:ok, pid} <- native_transport(session, :plan) do
          case safe_session_call(fn -> NativeSession.plan_mode(pid, planning?) end) do
            :ok -> :ok
            {:ok, _state} -> :ok
            {:error, reason} -> {:error, {:configure_refused, durable(reason)}}
            other -> {:error, {:configure_refused, durable(other)}}
          end
        end

      {:ok, %{settable: :at_start, via: via}} ->
        {:error,
         {:unsupported_configuration,
          %{
            provider: session.provider,
            field: :plan,
            reason: :at_start_only,
            message:
              "#{session.provider} can only be told to plan when the session starts " <>
                "(it carries the posture as #{via} on every launch); start a new session " <>
                "with `plan: true` instead."
          }}}

      {:error, reason} ->
        {:error, reason}
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

  # Branching a session is starting a new one, and the only thing that makes it a fork is
  # what its start request carries: the parent's `provider_session_id` plus the option the
  # transport spells "branch this" (`--fork-session` for Claude, `thread/fork` for the
  # Codex app server). Everything else about the child is the parent's own start intent.
  #
  # The parent is untouched. No turn is sent, nothing is interrupted, and the only thing
  # ever written to it is a count of the branches it has started.
  #
  # The workspace is admitted exactly as it is for any other session, which means a fork
  # of a live session holding an exclusive lease is refused by the lease. That is honest
  # and it is a real limit: until worktrees (D7), a branch runs where the parent is not.
  defp fork_plan(%State{} = session, id) do
    with {:ok, id} <- validate_fork_id(id),
         {:ok, parent_session_id} <- forkable_provider_session(session),
         {:ok, fork_options} <-
           Provider.session_fork_options(session.provider, Map.get(session.options, :transport)) do
      {:ok, fork_start_options(session, id, parent_session_id, fork_options)}
    end
  end

  # ---------------------------------------------------------------- context (D9)

  # The transport a session actually reaches its provider over, asked of the provider spec
  # rather than read off the stored option: a session that named none still runs on the
  # provider's default, and refusing it by a `nil` transport would name the wrong thing.
  defp session_transport(%State{} = session) do
    case Provider.session_capabilities(session.provider, Map.get(session.options, :transport)) do
      %{transport: transport} -> transport
      _unresolvable -> Map.get(session.options, :transport)
    end
  end

  # Two refusals, and they say different things. `unsupported_on_transport` is a
  # capability answer — this verb does not exist on this wire, and no amount of waiting
  # changes that. `native_transport_unavailable` is a liveness answer — the verb exists,
  # the session has not opened its transport yet or it has gone away, and retrying is
  # sensible.
  defp native_transport(%State{} = session, verb) do
    case session_transport(session) do
      :native ->
        case NativeSession.whereis(session.provider_session_id || "") do
          pid when is_pid(pid) ->
            {:ok, pid}

          nil ->
            {:error,
             {:native_transport_unavailable,
              %{
                verb: verb,
                reason:
                  if(session.provider_session_id, do: :no_live_transport, else: :not_started),
                message:
                  "this session has no live native transport to ask; send a turn first, " <>
                    "or reopen the session."
              }}}
        end

      transport ->
        {:error,
         {:unsupported_on_transport,
          %{
            transport: transport,
            verb: verb,
            provider: session.provider,
            message:
              "#{inspect(session.provider)} reaches this session over the " <>
                "#{inspect(transport)} transport, which does not hand its conversation to " <>
                "this runtime. Only a `native` session can #{verb}."
          }}}
    end
  end

  defp compact_native(pid, focus) do
    case safe_session_call(fn -> NativeSession.compact(pid, focus) end) do
      {:ok, report} when is_map(report) -> {:ok, durable(report)}
      {:error, reason} -> {:error, {:compaction_refused, durable(reason)}}
      other -> {:error, {:compaction_refused, durable(other)}}
    end
  end

  # Never a guess. A native session answers with the facts it holds; every other transport
  # answers with the two numbers its `usage` events carried and says so in `source`, so a
  # footer can tell "this provider never reported a window" from "the window is zero".
  defp session_context(%State{} = session) do
    usage = Map.get(session, :usage) || %{}

    base = %{
      session_id: session.id,
      provider: session.provider,
      transport: session_transport(session),
      model: Map.get(session.options, :model),
      provider_session_id: session.provider_session_id,
      context_window: Map.get(usage, :context_window),
      context_used: Map.get(usage, :context_used),
      total_tokens: Map.get(usage, :total_tokens),
      handed_off_from: State.handed_off_from(session),
      source: :usage
    }

    case native_transport(session, :context) do
      {:ok, pid} -> Map.merge(base, native_context(pid))
      {:error, _reason} -> base
    end
  end

  defp native_context(pid) do
    case safe_session_call(fn -> NativeSession.info(pid) end) do
      {:ok, info} when is_map(info) ->
        %{
          source: :native,
          prefix_fingerprint: Map.get(info, :prefix_fingerprint),
          # The native session's own figures win over the folded `usage` account: it is
          # the thing that counted them, and the fold is a projection of its events.
          context_window: Map.get(info, :context_window),
          context_used: Map.get(info, :context_used),
          compact_at: Map.get(info, :compact_at),
          keep_recent_tokens: Map.get(info, :keep_recent_tokens),
          messages: Map.get(info, :messages),
          compaction_thrashing: Map.get(info, :compaction_thrashing),
          compactions: durable(List.wrap(Map.get(info, :compactions))),
          # Ids, not archives: the archive bodies are the conversation this runtime just
          # folded away, and a context reply that carried them would undo the fold.
          archive_ids: info |> Map.get(:archives) |> List.wrap() |> Enum.map(&Map.get(&1, :id)),
          instruction_files: List.wrap(Map.get(info, :instruction_files)),
          instruction_files_dropped:
            durable(List.wrap(Map.get(info, :instruction_files_dropped))),
          instruction_bytes: Map.get(info, :instruction_bytes),
          tools: List.wrap(Map.get(info, :tools)),
          handed_off_to: Map.get(info, :handed_off_to)
        }

      _unavailable ->
        %{}
    end
  end

  # ---------------------------------------------------------------- delegation (G1)

  # What the caller needs to reach a team with, and nothing this coordinator has to hold
  # a lock for. The workspace defaults to this session's own, which is the whole point of
  # `/delegate`: the child works where the conversation is.
  defp delegate_plan(runtime, objective, opts) do
    session = runtime.session

    with :ok <- delegatable?(session, objective),
         {:ok, id} <- validate_delegation_id(Keyword.get(opts, :id)),
         {:ok, workspace} <- delegation_workspace(session, Keyword.get(opts, :workspace)),
         {:ok, provider} <- delegation_provider(session, Keyword.get(opts, :provider)) do
      case Map.fetch(State.delegations(session), id) do
        # An id already recorded is the same delegation, answered from the record rather
        # than started again: this verb is caller-keyed for the same reason a start is.
        {:ok, existing} ->
          {:ok,
           Map.put(plan_from(existing, session, objective, workspace, provider), :existing, true)}

        :error ->
          {:ok,
           %{
             id: id,
             team_id: Team.workspace_team_id(workspace),
             worker_id: delegation_worker_id(session),
             workspace: workspace,
             provider: provider,
             coding_node: node(),
             parent: %{plane: :interactive, id: session.id},
             objective_digest: digest_text(objective),
             existing: false
           }}
      end
    end
  end

  # Answered from the record, not rebuilt: the child already exists under this id, and
  # recomputing where it *would* have gone could name a different task than the one this
  # conversation is actually linked to.
  defp plan_from(existing, session, objective, workspace, provider) do
    %{
      id: existing.id,
      team_id: existing.team_id,
      task_id: existing.task_id,
      worker_id: delegation_worker_id(session),
      workspace: workspace,
      provider: provider,
      coding_node: existing.task_node,
      parent: %{plane: :interactive, id: session.id},
      objective_digest: digest_text(objective)
    }
  end

  defp delegatable?(session, objective) do
    cond do
      State.terminal?(session) ->
        {:error, {:session_not_delegable, %{status: session.status}}}

      not is_binary(objective) or String.trim(objective) == "" ->
        {:error, {:invalid_objective, %{reason: :blank}}}

      byte_size(objective) > @max_delegation_objective_bytes ->
        {:error,
         {:invalid_objective, %{reason: :too_long, limit: @max_delegation_objective_bytes}}}

      map_size(State.delegations(session)) >= State.max_delegations() ->
        {:error, {:delegation_limit_reached, %{limit: State.max_delegations()}}}

      true ->
        :ok
    end
  end

  defp validate_delegation_id(nil), do: {:ok, Jido.Signal.ID.generate!()}

  defp validate_delegation_id(id) when is_binary(id) do
    if String.trim(id) != "",
      do: {:ok, id},
      else: {:error, {:invalid_delegation_id, %{reason: :blank}}}
  end

  defp validate_delegation_id(id), do: {:error, {:invalid_delegation_id, %{value: id}}}

  defp delegation_workspace(session, nil), do: {:ok, session.workspace}

  defp delegation_workspace(_session, workspace) when is_binary(workspace) do
    if String.trim(workspace) != "",
      do: {:ok, workspace},
      else: {:error, {:invalid_workspace, %{reason: :blank}}}
  end

  defp delegation_workspace(_session, workspace),
    do: {:error, {:invalid_workspace, %{value: workspace}}}

  defp delegation_provider(session, nil), do: {:ok, session.provider}
  defp delegation_provider(_session, provider) when is_atom(provider), do: {:ok, provider}
  defp delegation_provider(_session, provider), do: {:error, {:invalid_provider, provider}}

  # One worker per conversation, not one per delegation: `Team.Server` refuses a second
  # active delegation to a busy worker, which is exactly the serialisation a single
  # conversation's `/delegate` should have, and it embeds `node()` because a worker id is
  # a mesh agent id.
  defp delegation_worker_id(%State{} = session), do: "#{node()}:session:#{session.id}"

  defp digest_text(text) when is_binary(text),
    do: :sha256 |> :crypto.hash(text) |> Base.encode16(case: :lower) |> binary_slice(0, 32)

  defp digest_text(_text), do: nil

  # The parent's durable half of the relationship plus the transcript entry, in one step
  # for the same reason the shell verb's settlement is: the record and the log answer the
  # same question from two directions.
  defp record_delegation(runtime, record) do
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    delegation =
      %{
        id: record.id,
        team_id: record.team_id,
        task_id: record.task_id,
        task_node: record.task_node,
        objective_digest: record.objective_digest,
        status: :started,
        result_digest: nil,
        created_at: now,
        updated_at: now
      }

    case State.put_delegation(runtime.session, delegation) do
      {:ok, session} ->
        append_delegation_event(%{runtime | session: session}, delegation, :started)

      {:error, reason} ->
        {:error, reason, runtime}
    end
  end

  defp settle_delegation(runtime, delegation_id, status, result_digest) do
    case Map.fetch(State.delegations(runtime.session), delegation_id) do
      {:ok, delegation} when delegation.status != status ->
        settled = %{
          delegation
          | status: status,
            result_digest: result_digest,
            updated_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        case State.put_delegation(runtime.session, settled) do
          {:ok, session} ->
            case append_delegation_event(%{runtime | session: session}, settled, status) do
              {:ok, runtime} ->
                runtime

              {:error, _reason, runtime} ->
                runtime
            end

          {:error, _reason} ->
            runtime
        end

      # A status this conversation already recorded, or a delegation it never started.
      # Both are silence rather than a second event: the team retries delivery, and one
      # transcript row per terminal status is the honest count.
      _nothing_new ->
        runtime
    end
  end

  defp append_delegation_event(runtime, delegation, status) do
    payload =
      %{
        "delegation_id" => delegation.id,
        "team_id" => delegation.team_id,
        "task_id" => delegation.task_id,
        "task_node" => Atom.to_string(delegation.task_node),
        "objective_digest" => delegation.objective_digest,
        "status" => Atom.to_string(status)
      }
      |> put_present("result_digest", delegation.result_digest)

    case emit_runtime_event(runtime, :delegation, payload,
           provider: runtime.session.provider,
           harness_session_id: runtime.session.harness_session_id,
           provider_session_id: runtime.session.provider_session_id
         ) do
      {:ok, runtime} ->
        {:ok, runtime}

      {:error, runtime} ->
        Logger.warning(
          "interactive session #{runtime.session.id} could not append delegation " <>
            "#{delegation.id} (#{status}) to its transcript"
        )

        {:error, {:delegation_checkpoint_failed, delegation.id}, runtime}
    end
  end

  # ---------------------------------------------------------------- operator shell (B7)

  # Deny by default, in the order that makes each answer honest. A terminal session has
  # no workspace to run in. `auto_approve` is the operator having already said "stop
  # asking me", which is exactly what this verb needs and nothing weaker. Otherwise the
  # permission engine decides, and anything that is not a rule saying `allow` — including
  # a store that could not be read — is a refusal that names what would have worked.
  defp plan_operator_shell(runtime, command) do
    session = runtime.session

    cond do
      State.terminal?(session) ->
        {:error, {:session_not_executable, %{status: session.status}}, runtime}

      not is_binary(command) or String.trim(command) == "" ->
        {:error, {:invalid_shell_command, %{reason: :blank}}, runtime}

      byte_size(command) > @max_shell_command_bytes ->
        {:error, {:invalid_shell_command, %{reason: :too_long, limit: @max_shell_command_bytes}},
         runtime}

      true ->
        case shell_authority(runtime, command) do
          {:ok, authority} -> open_operator_shell(runtime, command, authority)
          {:error, reason} -> {:error, reason, runtime}
        end
    end
  end

  defp shell_authority(runtime, command) do
    session = runtime.session

    if Map.get(session.options, :approval_mode) == :auto_approve do
      {:ok, %{reason: :auto_approve, rule: nil}}
    else
      case evaluate_shell_permission(runtime, command) do
        {:allow, rule} -> {:ok, %{reason: :rule, rule: rule}}
        {:deny, rule} -> {:error, shell_refused(runtime, command, :rule_denied, rule)}
        {:ask, reason} -> {:error, shell_refused(runtime, command, reason, nil)}
      end
    end
  end

  # Built in the shape `Ouroboros.Control.Permissions.Request` actually normalises, rather
  # than the coordinator's own approval subject: this is a real command line with a real
  # working directory, and a request the engine had to guess at would be judged against
  # `tool: "unknown"`.
  defp shell_request(%State{} = session, command) do
    %{
      principal: %{session_id: session.id, provider: session.provider, node: node()},
      tool: "bash",
      command: command,
      mode: :execute,
      context: %{workspace: session.workspace}
    }
  end

  defp evaluate_shell_permission(runtime, command) do
    case permissions_engine(:evaluate, 1) do
      nil ->
        {:ask, :no_permission_engine}

      engine ->
        case apply(engine, :evaluate, [shell_request(runtime.session, command)]) do
          {:allow, rule} -> {:allow, rule}
          {:deny, rule} -> {:deny, rule}
          {:ask, reason} -> {:ask, reason}
          _unrecognised -> {:ask, :engine_answer_unrecognised}
        end
    end
  rescue
    exception -> {:ask, {:engine_failed, Exception.message(exception)}}
  catch
    :exit, _reason -> {:ask, :engine_unavailable}
  end

  # A refusal that only says no is a refusal an operator has to guess their way out of.
  # This one names the rule that would allow the command and the two ways to install it,
  # which is the same pattern `permissions.add` takes and the same one the approval modal
  # already offers.
  defp shell_refused(runtime, command, reason, rule) do
    session = runtime.session

    {:shell_refused,
     %{
       reason: shell_reason(reason),
       session_id: session.id,
       workspace: session.workspace,
       approval_mode: Map.get(session.options, :approval_mode),
       denied_by: rule_reference(rule),
       suggested_rule: shell_suggestion(session, command),
       message: shell_refusal_message(reason)
     }}
  end

  defp shell_reason(reason) when is_atom(reason), do: reason
  defp shell_reason({tag, _detail}) when is_atom(tag), do: tag
  defp shell_reason(_reason), do: :not_permitted

  defp rule_reference(%{scope: scope, id: id, pattern: pattern}),
    do: %{scope: scope, id: id, pattern: pattern}

  defp rule_reference(_rule), do: nil

  defp shell_suggestion(session, command) do
    case permissions_engine(:suggest, 1) do
      nil ->
        nil

      engine ->
        case apply(engine, :suggest, [shell_request(session, command)]) do
          rule when is_binary(rule) and rule != "" -> rule
          _nothing_to_suggest -> nil
        end
    end
  rescue
    _exception -> nil
  catch
    :exit, _reason -> nil
  end

  defp shell_refusal_message(:rule_denied),
    do:
      "a permission rule denies this command. A deny beats every allow at every scope, " <>
        "so remove that rule with permissions.remove before adding another."

  defp shell_refusal_message(_reason),
    do:
      "workspace.exec runs a command as your own act, so it needs the session to be at " <>
        "approval_mode auto_approve or a permission rule that allows it. Add the " <>
        "suggested rule with permissions.add, or move the session with " <>
        "interactive.configure."

  # Checkpoint before run, and it is a hard gate rather than best effort: the entire
  # claim this verb makes is that a command run through the runtime is accountable
  # afterwards, and a command whose attempt could not be written down is not.
  defp open_operator_shell(runtime, command, authority) do
    session = runtime.session
    effect_id = operator_shell_id(session.id, command)

    attrs = %{
      id: effect_id,
      effect: :operator_shell,
      principal: "session:" <> session.id,
      attempt: %{
        session_id: session.id,
        command_digest: Exec.digest(command),
        cwd: session.workspace,
        node: node(),
        rule_id: authority.rule && Map.get(authority.rule, :id)
      },
      authority: %{
        decision: :allow,
        reason: Atom.to_string(authority.reason),
        constraints: rule_reference(authority.rule)
      },
      cause: %{signal_type: "workspace.exec", signal_id: effect_id}
    }

    case safe_ledger(fn -> EffectLedger.record_started(attrs) end) do
      {:ok, _entry, _created} ->
        {:ok,
         %{
           effect_id: effect_id,
           command_digest: attrs.attempt.command_digest,
           cwd: session.workspace,
           spill_dir: shell_spill_dir(session.id),
           timeout_ms: Exec.timeout_ms(),
           authority: authority.reason,
           rule: rule_reference(authority.rule)
         }, runtime}

      other ->
        {:error,
         {:shell_unrecordable,
          %{
            reason: :effect_ledger_unavailable,
            detail: durable(other),
            message:
              "the effect ledger could not record this command before it ran, and a " <>
                "command nobody can account for afterwards does not run."
          }}, runtime}
    end
  end

  defp shell_spill_dir(session_id) do
    case Exec.spill_dir(session_id) do
      {:ok, path} -> path
      {:error, _reason} -> nil
    end
  end

  # Embeds `node()` for the same reason every other id in this runtime does: an effect id
  # is read across a fleet, and a VM-local integer alone collides with the same one
  # allocated on another machine.
  defp operator_shell_id(session_id, command) do
    digest =
      :sha256
      |> :crypto.hash(
        :erlang.term_to_binary(
          {node(), session_id, Exec.digest(command), System.system_time(:nanosecond),
           System.unique_integer([:positive, :monotonic])}
        )
      )
      |> Base.encode16(case: :lower)

    "shell-" <> binary_slice(digest, 0, 32)
  end

  # The settlement and the transcript entry are one step because they answer the same
  # question from two directions: the ledger says a command this session was authorised
  # to run has finished, and the session's own log says what it did.
  defp settle_operator_shell(runtime, effect_id, outcome) do
    _ = safe_ledger(fn -> EffectLedger.settle(effect_id, settlement(outcome)) end)

    case emit_runtime_event(runtime, :provider_event, shell_event_payload(effect_id, outcome),
           provider: runtime.session.provider,
           harness_session_id: runtime.session.harness_session_id,
           provider_session_id: runtime.session.provider_session_id
         ) do
      {:ok, runtime} ->
        refresh_operator_exposure(runtime)

      {:error, runtime} ->
        Logger.warning(
          "interactive session #{runtime.session.id} ran an operator command but could " <>
            "not append it to the transcript; the ledger entry #{effect_id} stands"
        )

        runtime
    end
  end

  defp settlement(%{exit_status: status, timed_out: timed_out?} = result) do
    %{
      status: if(status == 0 and not timed_out?, do: :ok, else: :failed),
      result: %{
        exit_status: status,
        duration_ms: Map.get(result, :duration_ms),
        output_bytes: Map.get(result, :output_bytes),
        spilled: not is_nil(Map.get(result, :spilled)),
        timed_out: timed_out?
      }
    }
  end

  defp settlement(%{error: reason}), do: %{status: :failed, error: durable(reason)}

  defp shell_event_payload(effect_id, %{exit_status: _status} = result) do
    %{
      "kind" => "operator_shell",
      "effect_id" => effect_id,
      "command_digest" => Map.get(result, :command_digest),
      "exit_status" => Map.get(result, :exit_status),
      "duration_ms" => Map.get(result, :duration_ms),
      "timed_out" => Map.get(result, :timed_out),
      "output_bytes" => Map.get(result, :output_bytes),
      "output_excerpt" => Map.get(result, :excerpt)
    }
    |> put_present("spilled", Map.get(result, :spilled))
  end

  defp shell_event_payload(effect_id, %{error: reason}) do
    %{
      "kind" => "operator_shell",
      "effect_id" => effect_id,
      "exit_status" => nil,
      "output_excerpt" => "",
      "error" => inspect(reason, limit: 6)
    }
  end

  # The one place a durable runtime capture is deliberately re-taken. Everywhere else the
  # capture is frozen at admission so retries and recovery cannot observe a different
  # runtime; here the runtime genuinely changed, because a person ran a command in the
  # session's workspace, and the next turn is entitled to know. Bounded and redacted by
  # `Exposure` itself, so this cannot widen by being called from somewhere else later.
  defp refresh_operator_exposure(runtime) do
    session = runtime.session

    if Map.get(session.options, :runtime_exposure, true) do
      capture =
        Exposure.capture(
          sandbox_mode: Map.get(session.options, :sandbox_mode),
          operator_shell: recent_operator_commands(session)
        )

      updated = session |> Map.put(:runtime_snapshot, capture) |> State.touch()

      case persist(runtime, updated, []) do
        {:ok, runtime} ->
          runtime

        {:error, runtime} ->
          Logger.warning(
            "interactive session #{session.id} could not refresh its runtime exposure " <>
              "after an operator command; the next turn carries the previous envelope"
          )

          runtime
      end
    else
      runtime
    end
  end

  # Read back off the session's own log rather than kept in a second durable list: the
  # events are already bounded by `event_limit`, already redacted, and already survive a
  # restart. A command whose event has aged out has aged out of the envelope too, which
  # is the same honest silence a pruned transcript gives.
  defp recent_operator_commands(session) do
    session.events
    |> Enum.filter(
      &(&1.type == :provider_event and Map.get(&1.payload, "kind") == "operator_shell")
    )
    |> Enum.take(-@max_exposed_operator_commands)
    |> Enum.map(
      &%{
        command_digest: Map.get(&1.payload, "command_digest"),
        exit_status: Map.get(&1.payload, "exit_status"),
        excerpt: Map.get(&1.payload, "output_excerpt")
      }
    )
  end

  defp safe_ledger(fun) do
    fun.()
  rescue
    error -> {:error, {:effect_ledger_exception, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:effect_ledger_exit, inspect(reason, limit: 4)}}
  end

  # ---------------------------------------------------------------- handoff (D9)

  # The packet is written and the child is named here; the child session is started by the
  # caller. `open_child: false` is load-bearing — a transport process opened here would
  # inherit this session's harness owner, and the worker adopts the `provider_session_id`
  # of any adapter event it receives, so the orphan's readiness event would rename *this*
  # session's provider session to the child's.
  defp handoff_plan(runtime, prompt, id) do
    session = runtime.session

    with {:ok, id} <- validate_fork_id(id),
         {:ok, prompt} <- validate_handoff_prompt(prompt),
         {:ok, pid} <- native_transport(session, :handoff),
         {:ok, result} <-
           safe_session_call(fn -> NativeSession.handoff(pid, prompt, open_child: false) end) do
      {:ok, handoff_start_options(session, id, result.provider_session_id)}
    else
      {:error, reason} -> {:error, handoff_error(reason)}
      other -> {:error, {:handoff_refused, durable(other)}}
    end
  end

  defp handoff_error({tag, _detail} = reason)
       when tag in [:unsupported_on_transport, :native_transport_unavailable, :invalid_fork_id],
       do: reason

  defp handoff_error(:invalid_fork_id), do: :invalid_handoff_id
  defp handoff_error({:invalid_handoff_prompt, _detail} = reason), do: reason
  defp handoff_error(reason), do: {:handoff_refused, durable(reason)}

  defp validate_handoff_prompt(prompt) when is_binary(prompt) do
    cond do
      String.trim(prompt) == "" ->
        {:error, {:invalid_handoff_prompt, %{reason: :blank}}}

      not String.valid?(prompt) ->
        {:error, {:invalid_handoff_prompt, %{reason: :not_utf8}}}

      Ouroboros.AgentProfile.reserved_delimiter?(prompt) ->
        {:error, {:invalid_handoff_prompt, %{reason: :reserved_delimiter}}}

      true ->
        {:ok, prompt}
    end
  end

  defp validate_handoff_prompt(nil), do: {:ok, nil}
  defp validate_handoff_prompt(prompt), do: {:error, {:invalid_handoff_prompt, %{value: prompt}}}

  # The child's start intent is the parent's, minus this session's identity and plus the
  # provider session the packet was written under. Unlike a fork it carries no branch
  # option: the child is a *new* conversation seeded with a packet, and telling the
  # provider to branch would be a second, contradictory claim about the same session.
  defp handoff_start_options(%State{} = session, id, child_provider_session_id) do
    session.options
    |> Map.drop([:provider_options, :provider_session_id, :attachments])
    |> Map.to_list()
    |> Keyword.merge(
      id: id,
      provider: session.provider,
      workspace: session.workspace,
      workspace_mode: session.workspace_mode,
      event_limit: session.event_limit,
      provider_session_id: child_provider_session_id,
      handed_off_from: session.id
    )
  end

  defp validate_fork_id(nil), do: {:ok, Jido.Signal.ID.generate!()}

  defp validate_fork_id(id) when is_binary(id) do
    if String.trim(id) != "", do: {:ok, id}, else: {:error, :invalid_fork_id}
  end

  defp validate_fork_id(_id), do: {:error, :invalid_fork_id}

  # There is nothing to branch until the provider has named its own session. A fork of a
  # session the provider never acknowledged would be a fresh conversation wearing a
  # relationship it does not have.
  defp forkable_provider_session(%State{provider_session_id: id}) when is_binary(id) and id != "",
    do: {:ok, id}

  defp forkable_provider_session(%State{} = session) do
    {:error,
     {:unforkable_session,
      %{
        provider: session.provider,
        reason: :no_provider_session_id,
        message:
          "this session has no provider session id yet, so there is nothing to branch " <>
            "from; send a turn first, or start a new session."
      }}}
  end

  # The child's start intent is the parent's, minus the parts that are this session's
  # identity (its own id, its own place in a fork tree) and plus the two that make it a
  # branch. Options are read from the durable record, so a child of a session whose mode
  # was changed mid-life starts under the mode it is actually running with.
  defp fork_start_options(%State{} = session, id, parent_session_id, fork_options) do
    provider_options =
      session.options
      |> Map.get(:provider_options, %{})
      |> then(&(&1 || %{}))
      |> Map.merge(fork_options)

    opts =
      session.options
      |> Map.drop([:provider_options, :provider_session_id, :attachments])
      |> Map.to_list()
      |> Keyword.merge(
        id: id,
        provider: session.provider,
        workspace: session.workspace,
        workspace_mode: session.workspace_mode,
        event_limit: session.event_limit,
        provider_session_id: parent_session_id,
        provider_options: provider_options,
        forked_from: session.id
      )

    opts
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

  # ---------------------------------------------------------------------------
  # C2 — the external-approval path
  #
  # A managed transport (`claude`, `amp`, `zai`, `codex exec`) runs one process per turn
  # and declares no approvals channel, so nothing inside the Harness can ask before a tool
  # runs. What Claude Code *does* offer is `--permission-prompt-tool`: an MCP tool it calls
  # instead of prompting. `ouro mcp-serve` is that tool's server, and this is where its
  # call lands. The runtime relays; it does not decide, except where C1's rule engine has
  # already decided and where a bound has been reached.
  # ---------------------------------------------------------------------------

  defp open_external_approval(runtime, request_ref, request, from) do
    request_id = "ouro-approval-" <> Jido.Signal.ID.generate!()
    verdict = evaluate_permission(runtime, request)

    case emit_runtime_event(
           runtime,
           :approval_requested,
           external_request_payload(runtime, request_id, request, verdict),
           request_id: request_id,
           provider: runtime.session.provider,
           harness_session_id: runtime.session.harness_session_id,
           provider_session_id: runtime.session.provider_session_id
         ) do
      # Checkpoint before broadcast, and before the tool. A request that could not be
      # recorded is a request no replaying client will ever see, so it is denied here
      # rather than allowed against a journal that does not mention it.
      {:error, runtime} ->
        {:reply,
         {:ok,
          external_answer(
            request_id,
            :deny,
            :checkpoint_failed,
            "the approval request could not be recorded durably"
          )}, runtime}

      {:ok, runtime} ->
        settle_external_verdict(runtime, request_id, request_ref, request, from, verdict)
    end
  end

  defp settle_external_verdict(runtime, request_id, _ref, request, _from, {:allow, rule}) do
    record_permission(runtime, request, request_id, :allow, :engine, rule)

    runtime =
      resolve_external_event(runtime, request_id, :allow, :engine, rule_reason(rule), :once)

    {:reply, {:ok, external_answer(request_id, :allow, :engine, rule_reason(rule))}, runtime}
  end

  defp settle_external_verdict(runtime, request_id, _ref, request, _from, {:deny, rule}) do
    record_permission(runtime, request, request_id, :deny, :engine, rule)

    runtime =
      resolve_external_event(runtime, request_id, :deny, :engine, rule_reason(rule), :once)

    {:reply, {:ok, external_answer(request_id, :deny, :engine, rule_reason(rule))}, runtime}
  end

  defp settle_external_verdict(runtime, request_id, request_ref, request, from, {:ask, _reason}) do
    timeout_ms = external_approval_timeout_ms(runtime.session)
    timer = Process.send_after(self(), {:external_approval_timeout, request_id}, timeout_ms)

    pending = %{
      from: from,
      request_ref: request_ref,
      request: request,
      timer: timer,
      timeout_ms: timeout_ms
    }

    {:noreply,
     %{runtime | external_approvals: Map.put(runtime.external_approvals, request_id, pending)}}
  end

  defp close_external_approval(
         runtime,
         request_id,
         decision,
         source,
         reason,
         scope,
         effect_id \\ nil
       ) do
    {pending, table} = Map.pop(runtime.external_approvals, request_id)
    runtime = %{runtime | external_approvals: table}

    if pending do
      _ = Process.cancel_timer(pending.timer)
      record_permission(runtime, pending.request, request_id, decision, source, nil, scope)

      runtime =
        resolve_external_event(runtime, request_id, decision, source, reason, scope, effect_id)

      GenServer.reply(pending.from, {:ok, external_answer(request_id, decision, source, reason)})
      runtime
    else
      runtime
    end
  end

  defp resolve_external_event(
         runtime,
         request_id,
         decision,
         source,
         reason,
         scope,
         effect_id \\ nil
       ) do
    payload =
      %{
        "decision" => if(decision == :allow, do: "approve", else: "deny"),
        "scope" => Atom.to_string(scope),
        "source" => Atom.to_string(source),
        "origin" => "external",
        "request_id" => request_id
      }
      |> put_present("reason", reason)
      |> put_present("ledger_ref", effect_id && ledger_ref(effect_id))

    case emit_runtime_event(runtime, :approval_resolved, payload,
           request_id: request_id,
           provider: runtime.session.provider,
           harness_session_id: runtime.session.harness_session_id,
           provider_session_id: runtime.session.provider_session_id
         ) do
      {:ok, runtime} ->
        runtime

      # The answer still goes back to the caller: a resolution that could not be recorded
      # is a gap in the journal, not a reason to strand the tool call or to allow it.
      {:error, runtime} ->
        Logger.warning(
          "interactive session #{runtime.session.id} could not checkpoint the " <>
            "resolution of external approval #{request_id}"
        )

        runtime
    end
  end

  # The shape the Codex and ACP dialects already emit, so the modal that reads
  # `tool_call` and `request_id` needs no new case. `input` rather than `command`,
  # because a `--permission-prompt-tool` call carries the tool's arguments object.
  defp external_request_payload(runtime, request_id, request, verdict) do
    tool_call =
      %{"name" => Map.get(request, :tool_name)}
      |> put_present("input", Map.get(request, :input))
      |> put_present("cwd", Map.get(request, :cwd))

    %{
      "tool_call" => tool_call,
      "kind" => "permissions",
      "request_id" => request_id,
      "origin" => "external"
    }
    |> put_present("tool_use_id", Map.get(request, :tool_use_id))
    |> put_present(
      "suggested_rule",
      suggested_rule(permission_subject(runtime, request), verdict)
    )
  end

  # `evaluate/1` is C1's contract: `{:allow, rule} | {:deny, rule} | {:ask, reason}`. With
  # no engine on the node every request is `:ask`, which is the honest default — the
  # runtime has no rules, so it has no basis to skip the human.
  defp evaluate_permission(runtime, request) do
    case permissions_engine(:evaluate, 1) do
      nil ->
        {:ask, :no_permission_engine}

      engine ->
        case apply(engine, :evaluate, [permission_subject(runtime, request)]) do
          {:allow, rule} -> {:allow, rule}
          {:deny, rule} -> {:deny, rule}
          {:ask, reason} -> {:ask, reason}
          _unrecognised -> {:ask, :engine_answer_unrecognised}
        end
    end
  rescue
    exception -> {:ask, {:engine_failed, Exception.message(exception)}}
  catch
    :exit, _reason -> {:ask, :engine_unavailable}
  end

  # `record/2` takes a caller-minted, stable decision id and the answer; the request map
  # `evaluate/1` took rides along so the entry is attributed to this session rather than
  # to "unattributed". Until 2026-08-23 this passed the subject where the id goes, which
  # the engine refuses as `:invalid_permission_record` — so no bridged decision ever
  # reached the ledger, and the test fixture mirrored the wrong shape.
  defp record_permission(runtime, request, request_id, decision, source, rule, scope \\ :once) do
    case permissions_engine(:record, 2) do
      nil ->
        :ok

      engine ->
        _ =
          apply(engine, :record, [
            permission_decision_id(runtime, request_id),
            %{
              decision: if(decision == :allow, do: :approve, else: :deny),
              scope: scope,
              actor: if(source == :engine, do: :rule, else: :human),
              rule_ref: rule,
              reason: nil,
              request: permission_subject(runtime, request)
            }
          ])

        :ok
    end
  rescue
    _exception -> :ok
  catch
    :exit, _reason -> :ok
  end

  # The engine's seams use `"<session id>:<provider request id>"`: stable across a retry
  # after a lost acknowledgement, so the same answer records one entry rather than two.
  defp permission_decision_id(runtime, request_id), do: "#{runtime.session.id}:#{request_id}"

  # The "don't ask again" line a modal can offer. It is the engine's to phrase — this
  # module has no rule language — so the key is present only when C1 is loaded and
  # answered with one, and absent rather than invented when it is not.
  defp suggested_rule(subject, _verdict) do
    case permissions_engine(:suggest, 1) do
      nil ->
        nil

      engine ->
        case apply(engine, :suggest, [subject]) do
          rule when is_binary(rule) and rule != "" -> rule
          _nothing_to_suggest -> nil
        end
    end
  rescue
    _exception -> nil
  catch
    :exit, _reason -> nil
  end

  # The engine's own request shape — the same one `shell_request/2` and the native agent
  # build — so a bridged Claude approval is judged by the rules an operator wrote, not
  # normalised to an unknown tool that no rule can match. Claude's prompt-tool input names
  # the tool in its own vocabulary (`Bash`, `Write`, `Edit`, `MultiEdit`, `Read`,
  # `WebFetch`, `mcp__server__tool`); what each one reads or writes is taken from its
  # input, and anything unrecognised is classified as an execution so it asks.
  defp permission_subject(runtime, request) do
    session = runtime.session
    tool_name = to_string(Map.get(request, :tool_name) || "")
    input = if(is_map(Map.get(request, :input)), do: Map.get(request, :input), else: %{})
    cwd = Map.get(request, :cwd) || session.workspace
    tool = permission_tool(tool_name)

    %{
      principal: %{session_id: session.id, provider: session.provider, node: node()},
      tool: tool,
      command: if(tool == "bash", do: string_field(input, ["command"]), else: nil),
      paths: permission_paths(input, cwd),
      mode: permission_mode(tool),
      domains: permission_domains(input),
      context: %{
        workspace: session.workspace,
        cwd: cwd,
        tool_name: tool_name,
        tool_use_id: Map.get(request, :tool_use_id),
        transport: Map.get(session.options, :transport),
        origin: :external
      }
    }
  end

  defp permission_tool(name) do
    case String.downcase(name) do
      "bash" -> "bash"
      "powershell" -> "bash"
      "write" -> "write"
      "edit" -> "edit"
      "multiedit" -> "edit"
      "notebookedit" -> "edit"
      "read" -> "read"
      "glob" -> "glob"
      "grep" -> "grep"
      "ls" -> "ls"
      "webfetch" -> "web_fetch"
      "websearch" -> "web_search"
      "mcp__" <> _rest = mcp -> mcp
      other when other != "" -> other
      _blank -> "unknown"
    end
  end

  defp permission_mode("bash"), do: :execute
  defp permission_mode(tool) when tool in ["write", "edit"], do: :write
  defp permission_mode(tool) when tool in ["read", "glob", "grep", "ls"], do: :read
  defp permission_mode(tool) when tool in ["web_fetch", "web_search"], do: :network
  defp permission_mode(_tool), do: :execute

  defp permission_paths(input, cwd) do
    ["file_path", "path", "notebook_path"]
    |> Enum.map(&string_field(input, [&1]))
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&Path.expand(&1, cwd))
    |> Enum.uniq()
  end

  defp permission_domains(input) do
    case string_field(input, ["url"]) do
      nil ->
        []

      url ->
        case URI.parse(url) do
          %URI{host: host} when is_binary(host) and host != "" -> [host]
          _other -> []
        end
    end
  end

  defp string_field(input, keys) do
    Enum.find_value(keys, fn key ->
      case Map.get(input, key) || Map.get(input, String.to_atom(key)) do
        value when is_binary(value) and value != "" -> value
        _other -> nil
      end
    end)
  end

  defp permissions_engine(function, arity) do
    engine =
      Application.get_env(:ouroboros, :permissions_engine, @default_permissions_engine)

    if is_atom(engine) and not is_nil(engine) and Code.ensure_loaded?(engine) and
         function_exported?(engine, function, arity),
       do: engine
  end

  # A runtime-native event on the session's own log. `sequence_offset` moves with the
  # cursor because it *is* the distance between the two number spaces: an event no Harness
  # log contains widens that distance by exactly one, and `harness_cursor/1` has to go on
  # pointing at the same Harness row or the next poll would skip one.
  defp emit_runtime_event(runtime, type, payload, fields) do
    session = runtime.session
    sequence = session.cursor + 1
    event = Event.from_runtime(session.id, sequence, type, payload, fields)

    session =
      session
      |> Map.put(:cursor, sequence)
      |> Map.put(:sequence_offset, State.sequence_offset(session) + 1)
      |> append_event(event)
      |> State.touch()

    persist(runtime, session, [event])
  end

  # Best effort by construction: the pending table is memory, so the durable trace of an
  # unanswered question is an `approval_requested` this runtime minted with no matching
  # `approval_resolved` after it. A journal trimmed to `event_limit` can have lost the
  # pair, and then there is nothing to close — which is the same honest silence as a
  # session whose events aged out.
  defp deny_orphaned_external_approvals(runtime) do
    resolved =
      runtime.session.events
      |> Enum.filter(&(&1.type == :approval_resolved and is_binary(&1.request_id)))
      |> MapSet.new(& &1.request_id)

    runtime.session.events
    |> Enum.filter(fn event ->
      event.type == :approval_requested and is_binary(event.request_id) and
        Map.get(event.payload, "origin") == "external" and
        not MapSet.member?(resolved, event.request_id)
    end)
    |> Enum.reduce(runtime, fn event, runtime ->
      resolve_external_event(
        runtime,
        event.request_id,
        :deny,
        :coordinator_restart,
        "the session coordinator restarted before this was answered",
        :once
      )
    end)
  end

  # ---------------------------------------------------------------------------
  # I1 — the human answer, in the effect ledger
  #
  # `Ouroboros.Control.Permissions` already records what the *engine* decided as a
  # `:permission` entry. This records what a *person* decided, which is the one answer no
  # rule can reconstruct afterwards, and it records it on every provider: the external
  # bridge above, the native session's approval channel, and the Codex and ACP dialects
  # all pass through `respond_approval`.
  #
  # Written before the answer is forwarded, and — unlike `workspace.exec` — best effort
  # rather than a hard gate. The difference is deliberate: refusing to forward an answer
  # because the ledger is down would strand a tool call the operator has already decided
  # about, on a provider waiting for exactly one reply. Here the cheaper failure is the
  # missing row, and it is missing visibly.
  # ---------------------------------------------------------------------------

  defp record_approval(runtime, request_id, decision, scope, response, subject, origin) do
    session = runtime.session
    effect_id = approval_effect_id(session.id, request_id)

    attrs = %{
      id: effect_id,
      effect: :approval,
      principal: "session:" <> session.id,
      attempt:
        %{
          session_id: session.id,
          request_id: request_id,
          provider: session.provider,
          subject: subject.subject,
          node: node()
        }
        |> put_present(:tool, subject.tool),
      authority: %{
        decision: decision,
        reason: "human",
        constraints: %{scope: scope, actor: approval_actor(response), origin: origin}
      },
      cause: %{signal_type: "interactive.respond_approval", signal_id: request_id},
      result:
        %{
          decision: decision,
          scope: scope,
          actor: approval_actor(response),
          origin: origin
        }
        |> put_present(:rule_id, approval_rule_id(response))
    }

    write =
      if decision == :deny do
        fn -> EffectLedger.record_denied(Map.put(attrs, :error, :approval_denied)) end
      else
        fn -> EffectLedger.record_settled(attrs) end
      end

    case safe_ledger(write) do
      {:ok, _entry, _disposition} ->
        {effect_id, remember_approval_effect(runtime, request_id, effect_id)}

      other ->
        Logger.warning(
          "interactive session #{session.id} could not record the answer to approval " <>
            "#{request_id} in the effect ledger (#{inspect(durable(other))}); the answer " <>
            "still stands and the session's own approval_resolved event carries it"
        )

        {nil, runtime}
    end
  end

  # Who answered. The runtime observes a `respond_approval` and nothing about the caller
  # behind it, so `:human` is the honest default and anything else has to be *said*: a
  # caller that answers without a person at the keyboard — `ouro run --approve-all` is the
  # one that exists — names itself in the response. See TUI.md §2.4.
  defp approval_actor(response) do
    case Map.get(response, :actor) do
      actor when actor in [:human, :headless, :automation] -> actor
      "headless" -> :headless
      "automation" -> :automation
      _unstated -> :human
    end
  end

  # Present only when the answer wrote a durable rule and said so. The "don't ask again"
  # button is a separate `permissions.add` call this seam never sees, so inventing an id
  # from the `suggested_rule` in the request would claim a rule that may not exist.
  defp approval_rule_id(response) do
    case Map.get(response, :rule_id) do
      id when is_binary(id) and id != "" -> id
      _absent -> nil
    end
  end

  # The subject of an approval this coordinator is holding: the request the bridge handed
  # in, which is the same shape `permission_subject/2` reads.
  defp external_approval_subject(runtime, request_id) do
    case Map.get(runtime.external_approvals, request_id) do
      %{request: request} when is_map(request) ->
        input = if is_map(Map.get(request, :input)), do: Map.get(request, :input), else: %{}
        tool = to_string(Map.get(request, :tool_name) || "")

        %{
          tool: presence(tool),
          subject:
            approval_subject_fields(
              tool,
              string_field(input, ["command"]),
              permission_paths(input, Map.get(request, :cwd) || runtime.session.workspace)
            )
        }

      _absent ->
        %{tool: nil, subject: %{}}
    end
  end

  # The subject of an approval a *provider* asked for: read back off the durable
  # `approval_requested` event, which is where every dialect and the native session put the
  # same three facts. An event aged out of the retained window leaves the subject empty
  # rather than guessed.
  # An answer to a request this session never asked is not a human decision to record — it
  # is a caller naming an id, and a ledger that wrote a row for each of those would be both
  # unbounded and untrue. `:unknown` is that case. A session that *is* waiting on an
  # approval whose request event has aged out of the retained window still records, with an
  # empty subject: the answer happened, and only its subject is beyond recall.
  defp harness_approval_subject(runtime, request_id) do
    case Enum.find(runtime.session.events, fn event ->
           event.type == :approval_requested and event.request_id == request_id
         end) do
      %Event{payload: payload} when is_map(payload) ->
        call = Map.get(payload, "tool_call")
        call = if is_map(call), do: call, else: %{}
        tool = to_string(Map.get(call, "name") || "")

        %{
          tool: presence(tool),
          subject:
            approval_subject_fields(
              tool,
              string_field(call, ["command"]),
              Map.get(payload, "paths")
            )
        }

      _absent ->
        if runtime.session.status == :awaiting_approval,
          do: %{tool: nil, subject: %{}},
          else: :unknown
    end
  end

  defp approval_subject_fields(tool, command, paths) do
    %{}
    |> put_present(:paths, presence(paths))
    |> put_present(:command_sha256, command && Exec.digest(command))
    |> Map.merge(mcp_subject(tool))
  end

  # `mcp__server__tool` carries two identities in one name, on every provider that speaks
  # it. Splitting it here lets a reader ask what a session did through one MCP server
  # without parsing tool names out of the ledger.
  defp mcp_subject("mcp__" <> rest) do
    case String.split(rest, "__", parts: 2) do
      [server, tool] when server != "" and tool != "" -> %{mcp_server: server, mcp_tool: tool}
      _unsplittable -> %{}
    end
  end

  defp mcp_subject(_tool), do: %{}

  defp presence(""), do: nil
  defp presence([]), do: nil
  defp presence(value), do: value

  # Embeds `node()` for the same reason every other effect id here does: it is read across
  # a fleet, where a VM-local number alone collides.
  defp approval_effect_id(session_id, request_id) do
    digest =
      :sha256
      |> :crypto.hash(:erlang.term_to_binary({node(), session_id, request_id}))
      |> Base.encode16(case: :lower)

    "approval-" <> binary_slice(digest, 0, 32)
  end

  # Exactly the two parameters `ledger.get` takes, so a client resolves the row it drew
  # without a second vocabulary to translate.
  defp ledger_ref(effect_id), do: %{"node" => Atom.to_string(node()), "id" => effect_id}

  defp remember_approval_effect(runtime, request_id, effect_id) do
    effects = Map.put(runtime.approval_effects, request_id, effect_id)

    effects =
      if map_size(effects) > @max_approval_effects,
        do:
          Map.drop(
            effects,
            Enum.take(Map.keys(effects), map_size(effects) - @max_approval_effects)
          ),
        else: effects

    %{runtime | approval_effects: effects}
  end

  # Stamps the transport's own `approval_resolved` with the ledger entry the answer was
  # written under, the same way `enrich_chat_input/2` stamps an input the runtime already
  # had the words for. The provider does not know about the ledger and should not have to.
  defp enrich_approval_resolved(
         %Event{type: :approval_resolved, request_id: request_id} = event,
         effects
       )
       when is_binary(request_id) do
    case Map.get(effects, request_id) do
      nil -> event
      effect_id -> %{event | payload: Map.put(event.payload, "ledger_ref", ledger_ref(effect_id))}
    end
  end

  defp enrich_approval_resolved(event, _effects), do: event

  defp external_answer(request_id, decision, source, reason) do
    %{request_id: request_id, decision: decision, source: source, reason: reason}
  end

  defp external_approval_timeout_ms(%State{} = session) do
    case Map.get(session.options, :approval_timeout_ms) do
      ms when is_integer(ms) and ms > 0 ->
        ms |> max(@external_approval_min_timeout_ms) |> min(@external_approval_ceiling_ms)

      _unset_or_infinity ->
        @external_approval_default_timeout_ms
    end
  end

  defp rule_reason(rule) when is_binary(rule), do: rule
  defp rule_reason(nil), do: nil
  defp rule_reason(rule), do: inspect(rule)

  defp put_present(map, _key, nil), do: map
  defp put_present(map, _key, ""), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

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

  # D7. A session that asked for a worktree gets one *before* the lease is acquired, and
  # the lease is then taken on the worktree's own path — so every containment check in
  # the runtime, and every path check inside the provider, applies to the worktree rather
  # than to the repository it came from. Provisioning is idempotent, so the admission
  # that follows a restart finds the worktree already recorded and re-leases it.
  defp admit_workspace(session) do
    case Worktree.provision(session, "interactive-" <> session.id, []) do
      {:ok, provisioned} -> admit_leased_workspace(provisioned)
      {:error, reason} -> checkpoint_admission_failure(session, {:worktree_failed, reason})
    end
  end

  defp admit_leased_workspace(session) do
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

  defp release_workspace(runtime) do
    runtime =
      case runtime.workspace_lease do
        nil ->
          runtime

        lease ->
          _ = safe_workspace_release(lease.id, runtime.workspace_capability)
          %{runtime | workspace_lease: nil, workspace_capability: nil}
      end

    retire_worktree(runtime)
  end

  # A worktree is retired only when the session itself is over. `terminate/2` runs on a
  # supervisor restart too, and removing the directory there would take the isolation out
  # from under a session that is about to come back. `Worktree.remove/2` never deletes
  # uncommitted work, so the worst outcome of being wrong here is a stray directory that
  # `Worktree.reconcile/1` clears at the next boot.
  defp retire_worktree(runtime) do
    if State.terminal?(runtime.session) do
      case Worktree.retire(runtime.session, []) do
        {:ok, session, :removed} ->
          %{runtime | session: session}

        {:ok, session, {:kept, reason}} ->
          Logger.warning(
            "interactive session #{session.id}: worktree kept at " <>
              "#{Map.get(session.worktree, "path")} (#{inspect(reason)})"
          )

          note_retained_worktree(%{runtime | session: session})

        _absent_or_failed ->
          runtime
      end
    else
      runtime
    end
  end

  # The operator is told where their work was left, on the session's own log, in the same
  # number space as everything else it will replay.
  defp note_retained_worktree(runtime) do
    case emit_runtime_event(
           runtime,
           :status,
           %{
             "kind" => "worktree_retained",
             "path" => Map.get(runtime.session.worktree, "path"),
             "reason" => Map.get(runtime.session.worktree, "retained_reason"),
             "message" =>
               "the worktree holds uncommitted changes and was left in place. " <>
                 "Commit or discard them, then remove it with `git worktree remove`."
           },
           []
         ) do
      {:ok, runtime} -> runtime
      {:error, runtime} -> runtime
    end
  end

  defp safe_workspace_release(lease_id, capability) do
    try do
      Workspace.release(lease_id, server: WorkspaceManager, capability: capability)
    catch
      :exit, _reason -> :ok
    end
  end
end
