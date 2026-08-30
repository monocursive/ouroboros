defmodule Ouroboros.Interactive.Task do
  @moduledoc false

  use GenServer, restart: :transient

  require Logger

  alias Jido.Harness.{Session, SessionInfo, TurnRequest, TurnResult}
  alias Ouroboros.Interactive.{Event, State, Store}
  alias Ouroboros.Interactive.Task.{Approvals, Resume, Shell, Turns}
  alias Ouroboros.Provider
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Replay
  alias Ouroboros.Provider.Native.Session, as: NativeSession
  alias Ouroboros.Provider.Session, as: ProviderSession
  alias Ouroboros.Team
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager
  alias Ouroboros.Workspace.Worktree

  @poll_interval 25
  @replay_limit 100
  # C4. How long this coordinator waits on a provider-side fold. Under the gateway's own
  # 120s ceiling for `interactive.compact`, so a transport that never answers is this
  # call's failure rather than a connection's.
  @compaction_wait 110_000
  @terminal_retire_ms 100
  @workspace_reacquire_attempts 25
  @workspace_reacquire_delay_ms 4
  @retry_backoff_max_ms 5_000
  @default_unresolved_turn_deadline_ms 10 * 60 * 1_000
  @default_readiness_deadline_ms 10 * 60 * 1_000
  @max_pending_steers 32

  # G1. An objective an operator typed into a composer, bounded where it is accepted. It
  # becomes a coding task's durable objective, and the coding plane has its own bound;
  # this one is smaller because it is a sentence, not a document.
  @max_delegation_objective_bytes 8_192

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
    runtime = Approvals.deny_orphaned_external_approvals(runtime)

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
    case Turns.dispatch_turn(runtime, mode, id, input, opts) do
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
    case authorize_steer_attachments(input, opts, runtime) do
      {:ok, input, opts} ->
        case with_harness_session(runtime, &Session.steer(&1, input, opts)) do
          {:ok, request_id} when is_binary(request_id) ->
            {:reply, {:ok, request_id},
             runtime
             |> remember_steer(request_id, input)
             |> schedule_poll(0)}

          reply ->
            {:reply, reply, schedule_poll(runtime, 0)}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
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
    Approvals.request(runtime, request_ref, request, from)
  end

  def handle_call({:respond_approval, _request_id, response}, _from, runtime)
      when not is_map(response),
      do: {:reply, {:error, :invalid_approval_response}, runtime}

  def handle_call({:respond_approval, _request_id, response}, _from, runtime)
      when not is_map_key(response, :decision),
      do: {:reply, {:error, :invalid_approval_response}, runtime}

  def handle_call({:respond_approval, _request_id, %{decision: decision}}, _from, runtime)
      when decision not in [:approve, :deny],
      do: {:reply, {:error, :invalid_approval_response}, runtime}

  def handle_call(
        {:respond_approval, _request_id, %{scope: scope}},
        _from,
        runtime
      )
      when scope not in [:once, :session],
      do: {:reply, {:error, :invalid_approval_response}, runtime}

  # Routed ahead of the Harness clause, and only for an id this coordinator minted. A
  # request id the Harness owns is not in this map and falls through to the clause below
  # untouched, which is what keeps the existing modal working for Codex and ACP.
  def handle_call({:respond_approval, request_id, response}, _from, runtime)
      when is_map_key(runtime.external_approvals, request_id) do
    {:reply, :ok, Approvals.respond_external(runtime, request_id, response)}
  end

  def handle_call({:respond_approval, request_id, response}, _from, runtime) do
    {reply, runtime} = Approvals.respond_provider(runtime, request_id, response)
    {:reply, reply, runtime}
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

  # R1. Reads one file and starts nothing, so it is `:read` scope — but it still goes
  # through the native transport, because the transport is what knows where this session's
  # directory is. The refusal vocabulary is `rewind_points`'s, unchanged: a session with no
  # live native transport says so rather than answering with an empty record.
  def handle_call({:journal, opts}, _from, runtime) do
    case native_transport(runtime.session, :journal) do
      {:ok, pid} ->
        result =
          case safe_session_call(fn -> NativeSession.journal(pid, opts) end) do
            {:ok, window} -> {:ok, durable(window)}
            {:error, reason} -> {:error, {:journal_unavailable, durable(reason)}}
            other -> {:error, {:journal_unavailable, durable(other)}}
          end

        {:reply, result, runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  # R2. Verified replay reads the journal *file*, so unlike `:journal` it needs no live
  # native transport: the session may be long dead and its record is still on disk, which is
  # most of the point of having a record. What it does need is the start request's shape —
  # the system prompt and the tool list are *re-derived* from the workspace, because the
  # journal holds their digests and not their bytes, so the workspace and the tool
  # allow/deny lists are inputs to the verdict rather than decoration on it.
  def handle_call(:replay_verify, _from, runtime) do
    {:reply, replay_verify(runtime.session), runtime}
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

  # C4. Two transports can fold a conversation now, and they fold different things.
  # `Provider.compact_capability/1` is the declaration both branches read, so a transport
  # gains compaction by declaring it rather than by being named here.
  def handle_call({:compact, focus}, _from, runtime) do
    {:reply, compact(runtime, focus), runtime}
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
  def handle_call({:exec_plan, command}, {caller, _tag}, runtime) do
    case Shell.plan(runtime, command, caller) do
      {:ok, plan, runtime} -> {:reply, {:ok, plan}, runtime}
      {:error, reason, runtime} -> {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:exec_settled, effect_id, outcome}, _from, runtime) do
    {:reply, :ok, Shell.settle(runtime, effect_id, outcome)}
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
    {:reply, reply, schedule_poll(Resume.settle_resume(runtime), 0)}
  end

  def handle_call(:kill, _from, %{session: session} = runtime)
      when session.status in [:closed, :cancelled] do
    {:reply, :ok, runtime}
  end

  def handle_call(:kill, _from, runtime) do
    reply = with_harness_session(runtime, &Session.kill/1)
    {:reply, reply, schedule_poll(Resume.settle_resume(runtime), 0)}
  end

  def handle_call(_message, _from, runtime),
    do: {:reply, {:error, :invalid_session_operation}, runtime}

  # A steer's attachments reach the same transports as a turn's, but the Harness
  # validates steer attachments for existence only, never containment — so this plane
  # applies the same workspace gate `Turns.dispatch_turn` enforces on messages. Without
  # it, a steer names any file the daemon user can read, and the native transport reads
  # it into the model context.
  defp authorize_steer_attachments(input, opts, runtime) do
    workspace = runtime.session.workspace

    with {:ok, input} <- authorize_steer_input(input, workspace),
         {:ok, opts} <- authorize_steer_options(opts, workspace) do
      {:ok, input, opts}
    end
  end

  # `Jido.Harness.TurnRequest` accepts atom-keyed maps, string-keyed maps, and lists of
  # key/value pairs. Check every representation before handing it to the Harness rather
  # than accidentally making containment depend on which public API spelling a caller
  # chose.
  defp authorize_steer_input(input, workspace) when is_map(input) do
    Enum.reduce_while([:attachments, "attachments"], {:ok, input}, fn key, {:ok, input} ->
      case Map.fetch(input, key) do
        :error ->
          {:cont, {:ok, input}}

        {:ok, paths} ->
          case Turns.authorize_attachment_paths(paths, workspace) do
            {:ok, authorized} -> {:cont, {:ok, Map.put(input, key, authorized)}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
      end
    end)
  end

  defp authorize_steer_input(input, workspace) when is_list(input) do
    if Enum.all?(input, &match?({_, _}, &1)) do
      input |> Map.new() |> authorize_steer_input(workspace)
    else
      # Let the Harness produce its ordinary validation error for a non key/value list.
      {:ok, input}
    end
  end

  defp authorize_steer_input(input, _workspace), do: {:ok, input}

  # Options are merged over the input by the Harness, so an `attachments:` option is the
  # final attachment list and needs the same gate even when the input itself is a string.
  defp authorize_steer_options(opts, workspace) when is_list(opts) do
    case Keyword.fetch(opts, :attachments) do
      :error ->
        {:ok, opts}

      {:ok, paths} ->
        case Turns.authorize_attachment_paths(paths, workspace) do
          {:ok, authorized} -> {:ok, Keyword.put(opts, :attachments, authorized)}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp authorize_steer_options(opts, _workspace), do: {:ok, opts}

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
         Approvals.close_external_approval(
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
     Approvals.close_external_approval(
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
      {:error, :not_found} -> Resume.resume_or_lose(runtime, :harness_session_not_found)
      {:error, reason} -> retry(runtime, :harness_session_info_failed, reason)
    end
  end

  defp attach_or_start(runtime) do
    case Resume.find_adoptable_session(runtime.session.id) do
      {:ok, id} -> Resume.adopt(runtime, id)
      :not_found -> start_harness_session(runtime)
      {:error, reason} -> fail_start(runtime, reason)
    end
  end

  defp start_harness_session(runtime) do
    session = runtime.session

    case State.unrequestable_reason(session) do
      nil ->
        case safe_session_call(fn ->
               Session.start(session.provider, State.request(session))
             end) do
          {:ok, id} -> Resume.adopt(runtime, id)
          {:error, reason} -> fail_start(runtime, reason)
        end

      reason ->
        fail_start(runtime, {:unrequestable_session_state, reason})
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
        Resume.resume_or_lose(runtime, :harness_session_not_found)

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

    projected =
      Enum.map(projected, &Approvals.enrich_approval_resolved(&1, runtime.approval_effects))

    {projected, pending_steers} =
      Enum.map_reduce(projected, runtime.pending_steers, &enrich_steer_input/2)

    runtime = %{runtime | pending_steers: pending_steers}

    session =
      projected
      |> Enum.reduce(reconciled, fn event, session ->
        session
        |> Map.put(:cursor, event.sequence)
        |> maybe_provider_session(event.provider_session_id)
      end)
      |> append_events(projected)
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
        Resume.resume_or_lose(runtime, :harness_session_not_found)

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
                Turns.finish_turn(runtime, turn.id, result)
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
                do: Turns.mark_turn_ambiguous(runtime, turn.id, :harness_turn_not_found),
                else: runtime

            {:error, reason} ->
              Turns.mark_turn_ambiguous(runtime, turn.id, {:harness_turn_await_failed, reason})
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
      Turns.mark_turn_ambiguous(runtime, turn_id, {:unresolved_at_session_close, turn_id})
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

  defp recover_checkpointed_dispatch(runtime, %SessionInfo{} = info) do
    case Turns.unresolved_dispatches(runtime.session) do
      [] ->
        {:ok, runtime}

      [turn_id]
      when info.state == :idle and is_nil(info.active_turn_id) and info.queued_turns == 0 ->
        turn = Map.fetch!(runtime.session.turns, turn_id)

        with {:ok, request} <- TurnRequest.new(turn.request),
             request =
               Provider.apply_runtime_provider_policy(request, runtime.session.provider),
             {:ok, request} <-
               Turns.authorize_turn_attachments(request, runtime.session.workspace) do
          case checkpoint_recovered_turn_request(runtime, turn, request) do
            {:ok, turn, runtime} ->
              case Turns.dispatch_persisted_turn(runtime, turn, request) do
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
             Turns.mark_turn_ambiguous(
               runtime,
               turn_id,
               {:invalid_checkpointed_turn_request, reason}
             )}
        end

      ids ->
        {:ok,
         Enum.reduce(ids, runtime, fn turn_id, runtime ->
           Turns.mark_turn_ambiguous(
             runtime,
             turn_id,
             {:dispatch_could_not_be_correlated, info.state}
           )
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
      Enum.reduce(Turns.unresolved_dispatches(runtime.session), runtime, fn turn_id, runtime ->
        Turns.mark_turn_ambiguous(
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

  defp mark_gap_ambiguities(session, events) do
    if Enum.any?(events, &replay_gap?/1) do
      Enum.reduce(Turns.unresolved_dispatches(session), session, fn turn_id, session ->
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
      # B2/C4. `plan` and `mode` are not Harness configuration fields: each mutates a
      # different live surface. One call may target exactly one surface, because no
      # transaction spans the native session, an agent's own mode, and Harness
      # configuration. Refusing a mixed request before the first mutation is the only
      # outcome in which an error can still mean "nothing changed".
      {plan, rest} = Map.pop(changes, :plan)
      {mode, rest} = Map.pop(rest, :mode)

      with :ok <- one_configuration_surface(plan, mode, rest),
           {:ok, rest, applies} <- configuration_changes(session, rest, plan, mode),
           :ok <- apply_plan(runtime, plan),
           :ok <- apply_mode(runtime, mode),
           :ok <- apply_rest(runtime, rest) do
        record_configuration(runtime, plan_changes(rest, plan, mode), applies)
      else
        {:error, reason} -> {:error, reason, runtime}
      end
    end
  end

  defp one_configuration_surface(plan, mode, rest) do
    surfaces =
      []
      |> then(fn surfaces -> if is_nil(plan), do: surfaces, else: [:plan | surfaces] end)
      |> then(fn surfaces -> if is_nil(mode), do: surfaces, else: [:mode | surfaces] end)
      |> then(fn surfaces -> if rest == %{}, do: surfaces, else: [:session | surfaces] end)

    if length(surfaces) <= 1 do
      :ok
    else
      {:error,
       {:invalid_configuration,
        %{
          reason: :mixed_surfaces,
          surfaces: Enum.sort(surfaces),
          message:
            "plan, agent mode, and session options change different live surfaces; " <>
              "configure one surface per call so a refusal cannot leave a partial change"
        }}}
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

  defp replay_verify(%State{} = session) do
    with :ok <- native_record(session),
         {:ok, provider_session_id} <- recorded_session(session),
         {:ok, session_dir, _durable?} <- Paths.session_dir(provider_session_id) do
      case Replay.verify(session_dir, replay_options(session, provider_session_id)) do
        # The events are the engine's own working evidence and can run to tens of thousands
        # of deltas for one turn. The verdict crosses the wire; the stream does not.
        {:ok, verdict} -> {:ok, verdict |> Map.delete(:events) |> durable()}
        {:error, reason} -> {:error, {:replay_refused, durable(reason)}}
      end
    end
  end

  # The same capability answer `native_transport/2` gives, minus the liveness half: a vendor
  # session has no journal to verify and never will, and saying so is a different fact from
  # "this native session is not running right now".
  defp native_record(%State{} = session) do
    case session_transport(session) do
      :native ->
        :ok

      transport ->
        {:error,
         {:unsupported_on_transport,
          %{
            transport: transport,
            verb: :replay_verify,
            provider: session.provider,
            message:
              "#{inspect(session.provider)} reaches this session over the " <>
                "#{inspect(transport)} transport, which keeps no turn journal on this " <>
                "runtime. Only a `native` session can be replay-verified."
          }}}
    end
  end

  defp recorded_session(%State{provider_session_id: id}) when is_binary(id) and id != "",
    do: {:ok, id}

  defp recorded_session(_session),
    do:
      {:error,
       {:replay_refused,
        %{
          reason: :not_started,
          message:
            "this session never opened a native transport, so nothing recorded a journal " <>
              "for it. Send a turn first."
        }}}

  defp replay_options(%State{} = session, provider_session_id) do
    [
      workspace: session.workspace,
      add_dirs: Map.get(session.options, :add_dirs, []),
      allowed_tools: Map.get(session.options, :allowed_tools),
      disallowed_tools: Map.get(session.options, :disallowed_tools),
      system_prompt: Map.get(session.options, :system_prompt),
      event_limit: Map.get(session.options, :event_limit),
      session_id: session.id,
      provider_session_id: provider_session_id
    ]
  end

  defp compact(%{session: session} = runtime, focus) do
    case Provider.session_compact(session.provider, Map.get(session.options, :transport)) do
      :native ->
        with {:ok, pid} <- native_transport(session, :compact), do: compact_native(pid, focus)

      :provider ->
        compact_provider(runtime, focus)

      false ->
        {:error, uncompactable(session)}
    end
  end

  defp compact_native(pid, focus) do
    case safe_session_call(fn -> NativeSession.compact(pid, focus) end) do
      {:ok, report} when is_map(report) -> {:ok, durable(report)}
      {:error, reason} -> {:error, {:compaction_refused, durable(reason)}}
      other -> {:error, {:compaction_refused, durable(other)}}
    end
  end

  # The provider folds its own thread. A `focus` is refused by the dialect rather than
  # dropped, and that refusal travels out untouched: `unsupported_on_transport` with
  # `reason: focus_not_supported` is a capability answer a client can render, where
  # `compaction_refused` would look like something worth retrying.
  defp compact_provider(runtime, focus) do
    with_harness_session(runtime, fn harness_session_id ->
      case ProviderSession.ask(harness_session_id, :compact, %{focus: focus}, @compaction_wait) do
        {:ok, report} when is_map(report) -> {:ok, durable(report)}
        {:error, {:unsupported_on_transport, _details} = reason} -> {:error, durable(reason)}
        {:error, reason} -> {:error, {:compaction_refused, durable(reason)}}
        other -> {:error, {:compaction_refused, durable(other)}}
      end
    end)
  end

  defp uncompactable(%State{} = session) do
    transport = session_transport(session)

    {:unsupported_on_transport,
     %{
       transport: transport,
       verb: :compact,
       provider: session.provider,
       message:
         "#{inspect(session.provider)} reaches this session over the " <>
           "#{inspect(transport)} transport, which neither hands its conversation to this " <>
           "runtime nor offers a fold of its own. Only a `native` session or a Codex " <>
           "app-server thread can compact."
     }}
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
          with :ok <- delegation_capacity(session) do
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

      true ->
        :ok
    end
  end

  defp delegation_capacity(session) do
    if map_size(State.delegations(session)) < State.max_delegations(),
      do: :ok,
      else: {:error, {:delegation_limit_reached, %{limit: State.max_delegations()}}}
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

  # B7 operator shell lives in `Ouroboros.Interactive.Task.Shell`.

  def safe_ledger(fun) do
    fun.()
  rescue
    error -> {:error, {:effect_ledger_exception, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:effect_ledger_exit, inspect(reason, limit: 4)}}
  end

  # ---------------------------------------------------------------- handoff (D9)

  # The packet and the child's durable session intent are written here; the child
  # coordinator is started by the caller. Reserving the intent before replying makes the
  # caller-owned id a real reconciliation key: a retry reuses the packet's provider
  # session id instead of writing a second packet and conflicting with the first child.
  # `open_child: false` remains load-bearing — a transport process opened here would
  # inherit this session's harness owner and could rename the parent.
  defp handoff_plan(runtime, prompt, id) do
    session = runtime.session

    with {:ok, id} <- validate_fork_id(id),
         {:ok, prompt} <- validate_handoff_prompt(prompt) do
      case existing_handoff_options(session, id) do
        {:ok, opts} ->
          {:ok, opts}

        :not_found ->
          with {:ok, pid} <- native_transport(session, :handoff),
               {:ok, result} <-
                 safe_session_call(fn ->
                   NativeSession.handoff(pid, prompt, open_child: false)
                 end),
               opts = handoff_start_options(session, id, result.provider_session_id),
               {:ok, opts} <- reserve_handoff(session, opts) do
            {:ok, opts}
          else
            {:error, reason} -> {:error, handoff_error(reason)}
            other -> {:error, {:handoff_refused, durable(other)}}
          end

        {:error, reason} ->
          {:error, handoff_error(reason)}
      end
    else
      {:error, reason} -> {:error, handoff_error(reason)}
    end
  end

  defp reserve_handoff(parent, opts) do
    id = Keyword.fetch!(opts, :id)

    with {:ok, child} <- State.new(id, opts) do
      case Store.create(child) do
        :ok -> {:ok, opts}
        {:error, :already_exists} -> existing_handoff_options(parent, id)
        {:error, reason} -> {:error, {:handoff_checkpoint_failed, reason}}
      end
    end
  end

  defp existing_handoff_options(parent, id) do
    case Store.get(id) do
      {:ok, %State{} = child} ->
        if State.handed_off_from(child) == parent.id do
          {:ok, stored_handoff_start_options(child)}
        else
          {:error,
           {:handoff_id_conflict,
            %{id: id, handed_off_from: State.handed_off_from(child), expected: parent.id}}}
        end

      :not_found ->
        :not_found

      {:error, reason} ->
        {:error, {:handoff_checkpoint_unavailable, reason}}
    end
  end

  defp stored_handoff_start_options(%State{} = child) do
    child.options
    |> Map.to_list()
    |> Keyword.merge(
      id: child.id,
      provider: child.provider,
      workspace: child.workspace,
      workspace_mode: child.workspace_mode,
      event_limit: child.event_limit,
      handed_off_from: State.handed_off_from(child)
    )
  end

  defp handoff_error({tag, _detail} = reason)
       when tag in [
              :unsupported_on_transport,
              :native_transport_unavailable,
              :invalid_fork_id,
              :handoff_id_conflict
            ],
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

  # A wedged provider used to be retried every 25ms, rewriting the whole session
  # aggregate to disk on every attempt to record an error identical to the one
  # already checkpointed. Back off, and only checkpoint the error the first time it
  # is seen or when it changes.
  def retry(runtime, kind, reason) do
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

  def clear_retry(%{retry: %{count: 0}} = runtime), do: runtime
  def clear_retry(runtime), do: %{runtime | retry: no_retry()}

  def finalize_unresolved_turns(session, reason) do
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

  def persist(runtime, session, events) do
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

  def append_event(session, event), do: append_events(session, [event])

  defp append_events(session, new_events) do
    events = session.events ++ new_events
    overflow = max(length(session.events) + length(new_events) - session.event_limit, 0)
    {discarded, events} = Enum.split(events, overflow)

    floor =
      case List.last(discarded) do
        nil -> session.event_floor
        discarded_event -> discarded_event.sequence
      end

    %{session | events: events, event_floor: floor}
  end

  # A runtime-native event on the session's own log. `sequence_offset` moves with the
  # cursor because it *is* the distance between the two number spaces: an event no Harness
  # log contains widens that distance by exactly one, and `harness_cursor/1` has to go on
  # pointing at the same Harness row or the next poll would skip one.
  def emit_runtime_event(runtime, type, payload, fields) do
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

  defp put_present(map, _key, nil), do: map
  defp put_present(map, _key, ""), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  def maybe_provider_session(session, nil), do: session
  def maybe_provider_session(session, id), do: %{session | provider_session_id: id}

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

  def with_harness_session(%{session: %State{harness_session_id: nil}}, _fun),
    do: {:error, :session_not_started}

  def with_harness_session(runtime, fun) do
    safe_session_call(fn -> fun.(runtime.session.harness_session_id) end)
  end

  # Everything that lands in durable session state goes through here. Redaction removes
  # secrets; it leaves runtime authority alone, and a harness call exit reason carries
  # the pid it was calling. The store refuses such a checkpoint on every attempt, so a
  # session that wrote one used to retry that refusal for the rest of its life.
  def durable(term), do: term |> Jido.Harness.Redaction.redact() |> State.durable_term()

  def safe_session_call(fun) do
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

  def reply_turn_waiters(runtime, turn_id) do
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

  def reply_all_terminal_turn_waiters(runtime) do
    Enum.reduce(Map.keys(runtime.session.turns), runtime, &reply_turn_waiters(&2, &1))
  end

  def reply_ready_waiters(%{ready_timer: timer} = runtime) when is_reference(timer) do
    Process.cancel_timer(timer)
    reply_ready_waiters(%{runtime | ready_timer: nil})
  end

  def reply_ready_waiters(runtime) do
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

  def schedule_poll(runtime, delay) do
    Process.send_after(self(), :poll, delay)
    runtime
  end

  def schedule_retire(runtime) do
    Process.send_after(self(), :retire, @terminal_retire_ms)
    runtime
  end

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

  def release_workspace(runtime) do
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
