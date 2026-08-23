defmodule Ouroboros.Provider.Native.Session do
  @moduledoc """
  The interactive transport for the native agent: one supervised GenServer per session.

  `Jido.Harness.SessionAdapter` asks for an opaque handle with `open/send/interrupt/close`
  and the three optional callbacks. This transport answers all of them, which is the
  whole point — the loop is in this VM, so `steer/3`, `respond_approval/3`, and
  `configure/2` are things this runtime can actually do rather than declare.

  ## Division of labour with the session worker

  The worker owns session and turn *bookkeeping*: it appends `session_started`,
  `session_ready`, `session_idle`, `input_accepted`, `turn_started`, `queue_changed`,
  `approval_resolved`, and it finishes a turn when it sees a terminal event or when its
  own `interrupt` call returns `:ok`. This process owns everything a provider produces:
  text, thinking, tool calls, tool results, file changes, plans, usage, approval
  requests, and the terminal turn event.

  Approvals therefore have two timers by design. The worker starts one from the
  session's `approval_timeout_ms` and denies through `respond_approval/3` when it fires;
  this process starts the same one in the loop so that a session driven directly — a
  test, or a future embedding — still denies on time. Whichever fires first wins and the
  other's `respond_approval` finds nothing pending, which is a no-op.

  ## Checkpoint before broadcast

  A turn's conversation is written to `Ouroboros.Provider.Native.Checkpoint` *before*
  the terminal turn event reaches the owner. The failure that ordering chooses is
  replaying one turn after a crash, over losing one — the same rule the interactive
  coordinator already follows for its own checkpoints.

  ## Why this process is findable by name

  `info/1`, `compact/2` and `handoff/2` are not `SessionAdapter` callbacks — the harness
  has no notion of a context window or a curated handoff packet, so there is no worker
  method to pass them through, and the transport handle is private worker state. Rather
  than reach into that state, this process registers itself under its own
  `provider_session_id` in `Ouroboros.Provider.Native.Registry`, which the interactive
  coordinator already holds durably. Registration is best effort and never fails an
  open: a duplicate id (two coordinators resuming the same provider session at once) is
  a state this runtime does not create, and the honest answer for the loser is that
  these three verbs cannot reach a transport, not that the session refused to start.
  """

  use GenServer, restart: :temporary

  @behaviour Jido.Harness.SessionAdapter

  require Logger

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.Event
  alias Jido.Harness.SessionAdapter
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Archive
  alias Ouroboros.Provider.Native.Context.Compaction
  alias Ouroboros.Provider.Native.Context.Handoff
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools

  @startup_timeout 30_000
  @checkpoint_timeout 15_000

  @registry Ouroboros.Provider.Native.Registry

  # B2. Plan mode deliberately does **not** shorten the tool list, and the reason is a seam
  # rather than a preference. The only lever this process has over what the model is shown
  # is `disallowed_tools`, and the loop resolves a call against the same list
  # (`Loop.dispatch/2` → `Tools.lookup/3`) — so `write` removed from the list is `write`
  # whose call never reaches `Native.Permissions`, coming back as "`write` is not a tool in
  # this session": true of the list, and misleading about the session. Between a shorter
  # list and a refusal that says "this session is planning, record the plan instead", the
  # refusal is worth more.
  #
  # The prompt closes the gap: `Native.Prompt`'s `## Plan mode` block names `write`,
  # `edit`, `apply_patch` and `bash` as refused, so the model is told rather than left to
  # find out. Doing both needs one change in `Loop.run_turn/2` — honouring the `tool_specs`
  # the session already passes rather than rebuilding them, which is what that struct's own
  # comment already promises — and that module is not this one's to change.

  # The three answers to "your plan is ready". `kind` is ACP's vocabulary, and it is there
  # so that a client which has never heard of plan mode still renders something it can
  # send: `Ouroboros`'s own TUI maps `allow_always`/`allow_once`/`reject_once` onto
  # approve-session / approve-once / deny and labels the row with `name`. A plan-aware
  # client sends `optionId` back in `provider_options["choice"]` and gets exactly what it
  # picked.
  @plan_exit_options [
    %{"optionId" => "auto_edit", "name" => "Yes, auto-accept edits", "kind" => "allow_always"},
    %{"optionId" => "prompt", "name" => "Yes, manual approvals", "kind" => "allow_once"},
    %{"optionId" => "keep_planning", "name" => "No, keep planning", "kind" => "reject_once"}
  ]

  @max_plan_message_bytes 8 * 1024
  @max_follow_up_bytes 32 * 1024
  # The posture that has to outlive the process. Held apart from `conversation.json`
  # because it is not conversation: a resume that restored the messages and dropped the
  # read-only posture would put a planning session back to work without asking anyone.
  @posture_file "posture.json"

  # ---------------------------------------------------------------- adapter

  @impl Jido.Harness.SessionAdapter
  def open(request, context) do
    case DynamicSupervisor.start_child(
           Jido.Harness.SessionTransportSupervisor,
           {__MODULE__, {request, context}}
         ) do
      {:ok, pid} ->
        case SessionAdapter.call(pid, :initialize, @startup_timeout) do
          {:ok, provider_session_id} ->
            SessionAdapter.emit(
              context.owner,
              Event.new!(
                type: :provider_event,
                provider: context.provider,
                provider_session_id: provider_session_id,
                payload: %{"kind" => "native_ready"}
              )
            )

            {:ok, pid}

          {:error, _reason} = error ->
            DynamicSupervisor.terminate_child(Jido.Harness.SessionTransportSupervisor, pid)
            error
        end

      {:error, _reason} = error ->
        error
    end
  catch
    :exit, reason -> {:error, reason}
  end

  @impl Jido.Harness.SessionAdapter
  def send(handle, %TurnRequest{} = request, turn_id),
    do: SessionAdapter.call(handle, {:send, request, turn_id})

  @impl Jido.Harness.SessionAdapter
  def steer(handle, %TurnRequest{} = request, request_id),
    do: SessionAdapter.call(handle, {:steer, request, request_id})

  @impl Jido.Harness.SessionAdapter
  def interrupt(handle, turn_id), do: SessionAdapter.call(handle, {:interrupt, turn_id})

  @impl Jido.Harness.SessionAdapter
  def respond_approval(handle, request_id, %ApprovalResponse{} = response),
    do: SessionAdapter.call(handle, {:respond_approval, request_id, response})

  @impl Jido.Harness.SessionAdapter
  def configure(handle, changes), do: SessionAdapter.call(handle, {:configure, changes})

  @impl Jido.Harness.SessionAdapter
  def close(handle), do: SessionAdapter.call(handle, :close)

  @doc """
  Rewinds this session to the end of `to_turn` — D10's `/rewind`, and its honesty.

  `what` is `:files`, `:conversation`, or `:both`. `to_turn` is a turn id from a
  `provider_event` of kind `checkpoint`, or `0`/`:start` for "before anything this
  session did".

      {:ok, %{restored: [%{path: …, action: "restored" | "deleted"}],
              unrestorable: [%{path: … | nil, turn_id: …, reason: …}],
              turns: [turn ids], messages: n}}

  **`unrestorable` is the point of the return value.** Claude Code's rewind silently
  under-delivered (issue #18516) and §2.5 of the plan names that as a mistake with
  receipts, so this answers with both lists and a caller is expected to show the second
  one *before* the operator commits. Anything a `bash` command changed is in it, by turn,
  because a shell's effects are not checkpointed and never can be by a runtime that does
  not inspect the programs it runs.

  Both halves emit: one `file_change` carrying every restored path, and a `status`-kind
  `provider_event` naming the rewind. A rewind that left no trace in the transcript would
  be a change to the workspace that the transcript denies.

  Refused while a turn is running: rewinding underneath a loop that is mid-edit would
  race its own writes.
  """
  @spec rewind(pid(), String.t() | non_neg_integer() | :start, :files | :conversation | :both) ::
          {:ok, map()} | {:error, term()}
  def rewind(handle, to_turn, what \\ :both) when what in [:files, :conversation, :both],
    do: SessionAdapter.call(handle, {:rewind, to_turn, what}, 60_000)

  @doc """
  The turns this session can be rewound to, oldest first.

  The rewind menu, in the shape a client renders: turn id, when, how many files, which
  paths, and how many shell commands ran in it — the last being what tells an operator
  that a turn is only partly undoable before they choose it.
  """
  @spec rewind_points(pid()) :: {:ok, [map()]} | {:error, term()}
  def rewind_points(handle), do: SessionAdapter.call(handle, :rewind_points)

  @doc """
  Puts this session into, or out of, plan mode — B2's runtime half.

  Plan mode is a read-only posture with a job attached. While it is on:

    * `sandbox_mode` is forced to `:read_only` and what it displaced is remembered, so
      leaving gives the operator back the sandbox they chose;
    * `write`, `edit`, `apply_patch` and `bash` are dropped from the tool list the model
      sees, and every `:write` or `:execute` attempt is refused by
      `Ouroboros.Provider.Native.Permissions` with a message that names planning — a rule
      that would have allowed it does not un-plan the session;
    * the system prompt carries a `## Plan mode` block telling the model to explore,
      record the plan with the `plan` tool, and stop;
    * a turn that completes with a plan raises a **plan-exit approval** on the ordinary
      approval channel offering "Yes, auto-accept edits" / "Yes, manual approvals" /
      "No, keep planning", and the answer configures this session accordingly. A follow-up
      prompt supplied with the answer runs as the rest of that same turn.

  It is durable: the posture is written beside the conversation, so a session resumed by
  id comes back planning rather than back at work.

  This is a verb rather than an `interactive.configure` key because the pinned harness's
  `Jido.Harness.Session.RequestValidator.normalize_configuration/1` refuses any key
  outside `model`/`reasoning_effort`/`approval_mode`/`sandbox_mode`, and a fifth key on
  that path would be advertised and then rejected one call later. It reaches a session the
  way `compact/2`, `handoff/2` and `rewind/3` do — by name through the registry.
  """
  @spec plan_mode(pid(), boolean()) :: :ok | {:error, term()}
  def plan_mode(handle, planning?) when is_boolean(planning?),
    do: configure(handle, %{plan: planning?})

  @doc "Whether this session is planning, and what it would go back to when it stops."
  @spec plan_state(pid()) :: {:ok, map()} | {:error, term()}
  def plan_state(handle), do: SessionAdapter.call(handle, :plan_state)

  @doc false
  def start_link({request, context}), do: GenServer.start_link(__MODULE__, {request, context})

  @doc """
  Finds the transport process serving one `provider_session_id`, or `nil`.

  The registry may not be running at all — the native provider is usable from a bare
  `Session.open/2` in a test with no Ouroboros application behind it — so an absent
  registry answers `nil` rather than raising.
  """
  @spec whereis(String.t()) :: pid() | nil
  def whereis(provider_session_id) when is_binary(provider_session_id) do
    case Registry.lookup(@registry, provider_session_id) do
      [{pid, _value}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  catch
    :exit, _reason -> nil
  end

  def whereis(_provider_session_id), do: nil

  # ---------------------------------------------------------------- lifecycle

  @impl GenServer
  def init({request, context}) do
    options = Map.new(request.provider_options || %{})

    with {:ok, provider_session_id} <- session_id(request.provider_session_id),
         {:ok, scope} <-
           Paths.scope(request.cwd, request.add_dirs, Loop.sandbox_mode(request.sandbox_mode)),
         {:ok, model_spec} <- Loop.resolve_model(request.model),
         {:ok, session_dir, durable?} <- Paths.session_dir(provider_session_id),
         {:ok, checkpoint_path, _durable?} <- Checkpoint.locate(provider_session_id),
         {:ok, messages} <- restore(checkpoint_path, request.provider_session_id) do
      posture = restore_posture(session_dir, request, options)
      scope = if posture.plan?, do: %{scope | sandbox_mode: :read_only}, else: scope

      state = %{
        request: request,
        context: context,
        provider_session_id: provider_session_id,
        scope: scope,
        session_dir: session_dir,
        checkpoint_path: checkpoint_path,
        checkpoint_durable?: durable?,
        checkpoint_limit: Checkpoint.limit(options),
        model_module: Model.module(),
        model_spec: model_spec,
        reasoning_effort: request.reasoning_effort,
        approval_mode: posture.approval_mode || Loop.approval_mode(request.approval_mode),
        max_iterations: Loop.max_iterations(options, nil),
        tool_timeout_ms: Loop.tool_timeout(options),
        messages: messages,
        reads: %{},
        session_grants: MapSet.new(),
        loop: nil,
        approvals: MapSet.new(),
        # ---- context engineering (D3/D9) ----
        prompt_context: nil,
        options: options,
        compact_at: Window.compact_at(options),
        keep_recent_tokens: Window.keep_recent_tokens(options),
        # The last request's size as the provider counted it, and the turn it was
        # counted on. Both are needed by the thrash guard, which asks "how many turns
        # ago", not "how long ago".
        context_used: 0,
        turns: 0,
        compactions: [],
        thrashing?: false,
        archives: [],
        handed_off_to: nil,
        plan: nil,
        # A lazily-loaded rule enters the conversation once per session, not once per
        # turn: the loop reports back what it injected so the next turn does not repeat it.
        rules_loaded: [],
        # ---- plan mode (B2) ----
        plan_mode?: posture.plan?,
        # The `approval_mode` a plan-exit answer chose, or nil. Held apart from
        # `approval_mode` itself so that only a mode *this runtime's own approval* set is
        # restored across a restart: a session that never planned resumes exactly as it
        # always has, from its request.
        plan_exit_mode: posture.approval_mode,
        # What the operator's sandbox was before plan mode forced `:read_only`, so leaving
        # plan mode gives back what they chose rather than this runtime's default.
        sandbox_before_plan: posture.sandbox_before_plan,
        # The plan-exit approval this session is holding a terminal turn event for, or nil.
        plan_exit: nil,
        # What *this turn* produced, which is what the plan-exit question is about. Both
        # are reset per turn: a plan from three turns ago is not this turn's answer.
        turn_plan: nil,
        turn_text: nil,
        # ---- hooks (D5's three lifecycle events) ----
        hooks: Hooks.load(scope.root),
        # `SessionStart`'s `additionalContext`, held until the first turn's prompt and
        # dropped once it has been sent. It never joins the system prompt: the prefix has
        # a fingerprint and a session-scoped instruction in it would cost the cache.
        start_context: [],
        resumed?: not is_nil(request.provider_session_id)
      }

      case build_context(state) do
        {:ok, state} ->
          register(provider_session_id)
          # Written at open as well as on every change: a session that *started* planning
          # — `provider_options: %{plan: true}` — has a posture worth resuming into, and
          # waiting for a `configure` that may never come would lose it.
          {:ok, persist_posture(state)}

        {:error, reason} ->
          {:stop, reason}
      end
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  # Best effort, and deliberately not part of the process name: a registry that is not
  # running, or an id something else already holds, must not stop a session opening.
  defp register(provider_session_id) do
    _ = Registry.register(@registry, provider_session_id, nil)
    :ok
  rescue
    ArgumentError -> :ok
  catch
    :exit, _reason -> :ok
  end

  # `SessionStart` runs here rather than in `init/1` for one reason: `init/1` blocks the
  # supervisor's `start_child`, which nothing bounds, whereas this call is bounded by
  # `@startup_timeout` and each hook is bounded again inside `Hooks.session_start/2`. A
  # session whose operator wrote a slow start hook opens late; it does not hang a
  # supervisor.
  @impl GenServer
  def handle_call(:initialize, _from, state) do
    context =
      Hooks.session_start(
        state.hooks,
        Map.put(hook_base(state), "source", if(state.resumed?, do: "resume", else: "startup"))
      )

    {:reply, {:ok, state.provider_session_id}, %{state | start_context: context}}
  end

  def handle_call({:send, _request, _turn_id}, _from, %{loop: loop} = state)
      when not is_nil(loop),
      do: {:reply, {:error, :busy}, state}

  def handle_call({:send, request, turn_id}, _from, state) do
    case start_turn(state, request, turn_id) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:steer, _request, _request_id}, _from, %{loop: nil} = state),
    do: {:reply, {:error, :no_active_turn}, state}

  def handle_call({:steer, request, _request_id}, _from, state) do
    Kernel.send(state.loop.pid, {:native_steer, TurnRequest.text(request)})
    {:reply, :ok, state}
  end

  # An interrupt while the plan-exit question is open cancels the question, not the turn:
  # the model's turn genuinely completed, and the held event is the one that says so. The
  # session stays in plan mode, which is what "I did not answer" means.
  def handle_call({:interrupt, requested}, _from, %{loop: nil, plan_exit: %{} = pending} = state) do
    if requested in [:active, pending.turn_id] do
      {:reply, :ok, settle_plan_exit(state, :keep_planning, nil)}
    else
      {:reply, {:error, :not_active}, state}
    end
  end

  def handle_call({:interrupt, _turn_id}, _from, %{loop: nil} = state),
    do: {:reply, {:error, :not_active}, state}

  def handle_call({:interrupt, requested}, _from, state) do
    if requested in [:active, state.loop.turn_id] do
      Kernel.send(state.loop.pid, :native_interrupt)
      {:reply, :ok, state}
    else
      {:reply, {:error, :not_active}, state}
    end
  end

  # The plan-exit answer is handled *here* rather than forwarded to the loop, because the
  # loop that produced the plan has already returned: its turn ended, and what is waiting
  # is this process holding that turn's terminal event.
  def handle_call(
        {:respond_approval, request_id, response},
        _from,
        %{plan_exit: %{request_id: request_id}} = state
      ) do
    {:reply, :ok, answer_plan_exit(state, response)}
  end

  def handle_call({:respond_approval, request_id, response}, _from, state) do
    if MapSet.member?(state.approvals, request_id) and state.loop do
      Kernel.send(state.loop.pid, {:native_approval, request_id, response})
      {:reply, :ok, %{state | approvals: MapSet.delete(state.approvals, request_id)}}
    else
      {:reply, {:error, :unknown_request}, state}
    end
  end

  # `configure` is one of the two things allowed to change the cached prefix, so it
  # rebuilds it here rather than letting the next turn discover a stale one. A change
  # that fails validation leaves both the session and its prefix untouched.
  def handle_call({:configure, changes}, _from, state) do
    with {:ok, state} <- apply_configuration(state, changes),
         {:ok, state} <- build_context(state) do
      {:reply, :ok, supersede_plan_exit_mode(state, changes)}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:context_info, _from, state), do: {:reply, {:ok, context_info(state)}, state}

  def handle_call(:plan_state, _from, state) do
    {:reply,
     {:ok,
      %{
        plan: state.plan_mode?,
        sandbox_mode: state.scope.sandbox_mode,
        sandbox_after_plan: state.sandbox_before_plan,
        approval_mode: state.approval_mode,
        awaiting_plan_exit: state.plan_exit != nil
      }}, state}
  end

  def handle_call({:compact, _focus}, _from, %{loop: loop} = state) when not is_nil(loop),
    do: {:reply, {:error, :busy}, state}

  def handle_call({:compact, focus}, _from, state) do
    case run_compaction(state, focus, :manual) do
      {:ok, state, report} -> {:reply, {:ok, report}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:handoff, prompt, open_child?}, _from, state) do
    case start_handoff(state, prompt, open_child?) do
      {:ok, state, result} -> {:reply, {:ok, result}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:close, _from, state) do
    # A held terminal event goes out before the session does. A client whose turn never
    # ended because the plan-exit question was still open would be waiting on a session
    # that no longer exists.
    state = state |> release_held_terminal() |> stop_loop()
    _ = checkpoint(state)
    _ = session_end(state, "closed")

    emit(state, %{
      type: :session_closed,
      payload: %{"reason" => "closed"},
      turn_id: nil,
      request_id: nil
    })

    {:stop, :normal, :ok, state}
  end

  # The loop calls this synchronously, immediately before it emits the terminal turn
  # event. Returning `:ok` from here is the guarantee that the conversation on disk is
  # at least as new as the event about to reach the owner.
  def handle_call({:checkpoint, turn_id, snapshot}, _from, %{loop: %{turn_id: turn_id}} = state) do
    state = %{
      state
      | messages: snapshot.messages,
        reads: snapshot.reads,
        session_grants: snapshot.session_grants,
        rules_loaded: Map.get(snapshot, :rules_loaded, state.rules_loaded)
    }

    _ = checkpoint(state)
    {:reply, :ok, state}
  end

  def handle_call({:checkpoint, _stale_turn_id, _snapshot}, _from, state),
    do: {:reply, :ok, state}

  def handle_call(:rewind_points, _from, state) do
    case Checkpoint.turns(state.session_dir) do
      {:ok, turns} -> {:reply, {:ok, Enum.map(turns, &Checkpoint.summary/1)}, state}
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  def handle_call({:rewind, _to_turn, _what}, _from, %{loop: loop} = state)
      when not is_nil(loop),
      do: {:reply, {:error, :busy}, state}

  def handle_call({:rewind, to_turn, what}, _from, state) do
    case rewind_files(state, to_turn, what) do
      {:ok, outcome} ->
        {state, truncated} = rewind_conversation(state, to_turn, what)
        outcome = Map.put(outcome, :messages, truncated)

        announce(state, to_turn, what, outcome)
        {:reply, {:ok, outcome}, state}

      {:error, _reason} = error ->
        {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_info({:native_event, turn_id, event}, %{loop: %{turn_id: turn_id}} = state) do
    state =
      state
      |> track_approval(event)
      |> track_usage(event)
      |> track_plan(event)
      |> track_text(event)

    cond do
      # B2. A planning turn that finished is not a finished turn: the operator still has to
      # say what happens to the plan. The terminal event is *held* — not emitted and then
      # followed by a question — because `Jido.Harness.Session.Lifecycle` denies any
      # approval request whose turn is no longer the worker's active one, so an exit
      # approval raised after `turn_completed` would be auto-denied as stale. Holding it
      # also states the truth: from a client's point of view the turn is still running,
      # and it is, because the answer decides whether it continues.
      plan_exit?(state, event) ->
        {:noreply, raise_plan_exit(state, event)}

      event.type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        emit(state, event)
        {:noreply, release(state)}

      true ->
        emit(state, event)
        {:noreply, state}
    end
  end

  def handle_info({:native_event, _stale_turn_id, _event}, state), do: {:noreply, state}

  def handle_info(
        {:plan_exit_timeout, request_id},
        %{plan_exit: %{request_id: request_id}} = state
      ) do
    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "status",
        "status" => "plan_exit_unanswered",
        "message" =>
          "nobody answered the plan-exit question within " <>
            "#{inspect(state.request.approval_timeout_ms)} ms, so this session is still planning."
      },
      turn_id: nil,
      request_id: nil
    })

    {:noreply, settle_plan_exit(state, :keep_planning, nil)}
  end

  def handle_info({:plan_exit_timeout, _stale}, state), do: {:noreply, state}

  def handle_info({ref, :ok}, %{loop: %{ref: ref}} = state) do
    Process.demonitor(ref, [:flush])
    {:noreply, release(state)}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{loop: %{ref: ref}} = state) do
    if reason != :normal do
      emit(state, %{
        type: :turn_failed,
        payload: %{"error" => "native loop crashed: #{inspect(reason)}", "reason" => "crash"},
        turn_id: state.loop.turn_id,
        request_id: nil
      })
    end

    # A crash after the loop emitted its terminal event but before it returned would leave
    # a held `turn_completed` behind a `turn_failed`. One turn, one terminal: the failure
    # that just went out is the one that stands, so the held event is dropped rather than
    # emitted after it.
    {:noreply, release(discard_held_terminal(state, reason))}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp discard_held_terminal(%{plan_exit: nil} = state, _reason), do: state
  defp discard_held_terminal(state, :normal), do: state

  defp discard_held_terminal(%{plan_exit: pending} = state, _crash) do
    _ = pending.timer && Process.cancel_timer(pending.timer)
    %{state | plan_exit: nil}
  end

  # A turn that ended leaves no loop and no pending approvals. Both are per-turn state:
  # a request_id from a finished turn must not be answerable afterwards.
  defp release(state), do: %{state | loop: nil, approvals: MapSet.new()}

  # `:normal` is the `close` path, which already fired `SessionEnd` with its own reason.
  # Anything else is the session going away without being asked to, which is exactly the
  # case a `SessionEnd` hook exists to notice.
  @impl GenServer
  def terminate(:normal, state) do
    _ = stop_loop(state)
    :ok
  rescue
    _error -> :ok
  end

  def terminate(reason, state) do
    _ = stop_loop(state)
    _ = session_end(state, terminate_reason(reason))
    :ok
  rescue
    _error -> :ok
  end

  defp terminate_reason(:shutdown), do: "shutdown"
  defp terminate_reason({:shutdown, _detail}), do: "shutdown"
  defp terminate_reason(_crash), do: "crashed"

  # ---------------------------------------------------------------- turns

  defp start_turn(state, request, turn_id) do
    with {:ok, state} <- maybe_compact(state),
         {:ok, state} <- ensure_context(state) do
      owner = self()

      loop = %Loop{
        emit: fn event -> Kernel.send(owner, {:native_event, turn_id, event}) end,
        checkpoint: fn snapshot ->
          GenServer.call(owner, {:checkpoint, turn_id, snapshot}, @checkpoint_timeout)
        end,
        model_module: state.model_module,
        model_spec: state.model_spec,
        system: state.prompt_context.system,
        tool_specs: state.prompt_context.tools,
        context_window: state.prompt_context.context_window,
        rules: Context.rules(state.prompt_context),
        rules_loaded: state.rules_loaded,
        scope: state.scope,
        session_dir: state.session_dir,
        session_id: state.context.session_id,
        provider_session_id: state.provider_session_id,
        turn_id: turn_id,
        reasoning_effort: request.reasoning_effort || state.reasoning_effort,
        # `:plan` is not one of the four modes `Jido.Harness.SessionRequest` accepts, and it
        # never travels as one: it is set on the loop's own struct for the turns a planning
        # session runs, and `Loop.permission_request/2` copies it into `context.approval_mode`
        # where `Native.Permissions` reads it. That is the whole mechanism by which a
        # planning session refuses a write with a reason that says "planning".
        approval_mode: loop_approval_mode(state),
        allowed_tools: state.request.allowed_tools,
        disallowed_tools: state.request.disallowed_tools,
        messages: state.messages,
        reads: state.reads,
        session_grants: state.session_grants,
        max_iterations: state.max_iterations,
        tool_timeout_ms: state.tool_timeout_ms,
        approval_timeout_ms: state.request.approval_timeout_ms
      }

      prompt = TurnRequest.text(request) <> injected(state.start_context)

      task =
        Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
          {:ok, _finished} = Loop.run_turn(loop, prompt)
          :ok
        end)

      {:ok,
       %{
         state
         | loop: %{pid: task.pid, ref: task.ref, turn_id: turn_id},
           turns: state.turns + 1,
           # Sent once. A `SessionStart` hook's context belongs to the session opening, not
           # to every prompt after it.
           start_context: [],
           turn_plan: nil,
           turn_text: nil
       }}
    end
  end

  defp stop_loop(%{loop: nil} = state), do: state

  defp stop_loop(%{loop: loop} = state) do
    Process.demonitor(loop.ref, [:flush])
    _ = Task.Supervisor.terminate_child(Jido.Harness.SessionTaskSupervisor, loop.pid)
    %{state | loop: nil, approvals: MapSet.new()}
  end

  defp track_approval(state, %{type: :approval_requested, request_id: request_id})
       when is_binary(request_id),
       do: %{state | approvals: MapSet.put(state.approvals, request_id)}

  defp track_approval(state, _event), do: state

  defp emit(state, event) do
    SessionAdapter.emit(
      state.context.owner,
      Loop.to_event(event, state.context.provider, state.provider_session_id)
    )
  end

  # ---------------------------------------------------------------- config

  # An operator naming an `approval_mode` from outside outranks the one a plan-exit answer
  # chose, and clears it: two durable records of one fact eventually disagree, and the
  # newer instruction is the one that means something. Only the `configure` call runs this
  # — the plan-exit path calls `apply_configuration/2` directly — so it cannot clear its
  # own answer on the way in.
  defp supersede_plan_exit_mode(state, changes) do
    if Enum.any?(changes, fn {key, _value} -> normalize_key(key) == :approval_mode end),
      do: persist_posture(%{state | plan_exit_mode: nil}),
      else: state
  end

  defp apply_configuration(state, changes) do
    Enum.reduce_while(changes, {:ok, state}, fn {key, value}, {:ok, state} ->
      case configure_one(state, normalize_key(key), value) do
        {:ok, state} -> {:cont, {:ok, state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp configure_one(state, :model, value) when is_binary(value) and value != "",
    do: {:ok, %{state | model_spec: value}}

  defp configure_one(state, :reasoning_effort, value) when value in [:low, :medium, :high, nil],
    do: {:ok, %{state | reasoning_effort: value}}

  defp configure_one(state, :approval_mode, value)
       when value in [:default, :prompt, :auto_edit, :auto_approve],
       do: {:ok, %{state | approval_mode: Loop.approval_mode(value)}}

  # Sandbox mode changes the tools' own refusals, so it takes effect on the next tool
  # call, not the next turn — which is what `dynamic_configuration: :native` promises.
  #
  # While the session is planning the operator's value is *recorded* rather than applied:
  # `:read_only` is the posture plan mode is, and letting a `sandbox_mode` change lift it
  # would be a way past a mode rather than a change of one. It lands the moment plan mode
  # is left, which is what `sandbox_before_plan` is for.
  defp configure_one(%{plan_mode?: true} = state, :sandbox_mode, value)
       when value in [:default, :read_only, :workspace_write] do
    {:ok, %{state | sandbox_before_plan: Loop.sandbox_mode(value)}}
  end

  defp configure_one(state, :sandbox_mode, value)
       when value in [:default, :read_only, :workspace_write] do
    {:ok, %{state | scope: %{state.scope | sandbox_mode: Loop.sandbox_mode(value)}}}
  end

  # B2's key, and the reason it is `plan` rather than a fifth `approval_mode`: the pinned
  # `Jido.Harness.SessionRequest` validates `approval_mode` against a four-member
  # `Zoi.enum`, so a `:plan` member would be refused at every session start and every
  # resume. A mode label a transport rejects is not a mode.
  #
  # Entering forces `sandbox_mode: :read_only` and remembers what it displaced; leaving
  # gives that back. Both directions rebuild the cached prefix, because the plan
  # instruction block is part of it — the caller is `handle_call({:configure, …})`, which
  # already does.
  defp configure_one(%{plan_mode?: true} = state, :plan, true), do: {:ok, state}
  defp configure_one(%{plan_mode?: false} = state, :plan, false), do: {:ok, state}

  defp configure_one(state, :plan, true) do
    {:ok,
     %{
       state
       | plan_mode?: true,
         sandbox_before_plan: state.scope.sandbox_mode,
         scope: %{state.scope | sandbox_mode: :read_only}
     }
     |> persist_posture()}
  end

  defp configure_one(state, :plan, false) do
    restored = state.sandbox_before_plan || Loop.sandbox_mode(state.request.sandbox_mode)

    {:ok,
     %{
       state
       | plan_mode?: false,
         sandbox_before_plan: nil,
         scope: %{state.scope | sandbox_mode: restored}
     }
     |> persist_posture()}
  end

  defp configure_one(_state, key, value),
    do: {:error, {:unsupported_configuration, key, value}}

  defp normalize_key(key) when is_atom(key), do: key

  defp normalize_key(key) when is_binary(key) do
    case key do
      "model" -> :model
      "reasoning_effort" -> :reasoning_effort
      "approval_mode" -> :approval_mode
      "sandbox_mode" -> :sandbox_mode
      "plan" -> :plan
      other -> other
    end
  end

  # What the loop is told this turn runs under. `:plan` only ever exists here and on the
  # loop's own struct; the session's durable `approval_mode` keeps whatever the operator
  # set, so leaving plan mode without naming a mode returns to it.
  defp loop_approval_mode(%{plan_mode?: true}), do: :plan
  defp loop_approval_mode(state), do: state.approval_mode

  # ---------------------------------------------------------------- resume

  # A caller-supplied id is validated as untrusted input before it becomes a directory
  # name; a session that names none gets a fresh node-embedded one.
  defp session_id(nil), do: {:ok, Paths.new_session_id()}

  defp session_id(id) do
    case Paths.validate_session_id(id) do
      :ok -> {:ok, id}
      {:error, _reason} = error -> error
    end
  end

  # Only a session that asked to resume reads a checkpoint. A fresh id has no history by
  # definition, and a corrupt file must fail the open rather than silently start an
  # empty session under an id whose transcript the operator believes still exists.
  defp restore(_path, nil), do: {:ok, []}

  defp restore(path, _requested) do
    case Checkpoint.read(path) do
      {:ok, messages} -> {:ok, messages}
      {:error, :no_checkpoint} -> {:ok, []}
      {:error, reason} -> {:error, {:checkpoint_unusable, reason}}
    end
  end

  # ---------------------------------------------------------------- rewind

  defp rewind_files(_state, _to_turn, :conversation),
    do: {:ok, %{restored: [], unrestorable: [], turns: []}}

  defp rewind_files(state, to_turn, _files_or_both),
    do: Checkpoint.restore_files(state.session_dir, to_turn)

  defp rewind_conversation(state, _to_turn, :files), do: {state, length(state.messages)}

  defp rewind_conversation(state, to_turn, _conversation_or_both) do
    case Checkpoint.message_count_at(state.session_dir, to_turn) do
      {:ok, count} when count <= length(state.messages) ->
        state = %{state | messages: Enum.take(state.messages, count)}
        _ = checkpoint(state)
        {state, count}

      # A count this session cannot honour — a turn id it never recorded, or a
      # conversation already shorter than the mark — leaves the transcript alone. A
      # rewind that truncated to a number it could not justify would lose messages the
      # manifest never claimed to cover.
      _unusable ->
        {state, length(state.messages)}
    end
  end

  defp announce(state, to_turn, what, outcome) do
    if outcome.restored != [] do
      emit(state, %{
        type: :file_change,
        payload: %{
          "changes" =>
            Enum.map(outcome.restored, fn entry ->
              %{
                "path" => entry.path,
                "relative_path" => Path.relative_to(entry.path, state.scope.root),
                "kind" => if(entry.action == "deleted", do: "delete", else: "modify"),
                "diff" => "",
                "reason" => "rewind"
              }
            end),
          "status" => "completed"
        },
        turn_id: nil,
        request_id: nil
      })
    end

    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "status",
        "event" => "rewind",
        "to_turn" => to_string(to_turn),
        "what" => Atom.to_string(what),
        "restored" => length(outcome.restored),
        "unrestorable" => Enum.map(outcome.unrestorable, &describe_unrestorable/1),
        "messages" => outcome.messages
      },
      turn_id: nil,
      request_id: nil
    })
  end

  defp describe_unrestorable(%{path: nil, turn_id: turn_id, reason: reason}),
    do: %{"turn_id" => turn_id, "reason" => reason}

  defp describe_unrestorable(%{path: path} = entry),
    do: %{"path" => path, "reason" => Map.get(entry, :reason) || "could not be restored"}

  defp checkpoint(state) do
    case Checkpoint.write(state.checkpoint_path, state.messages,
           event_limit: state.checkpoint_limit
         ) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("native session checkpoint failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------- context (D3/D9)

  @doc """
  What this session's cached prefix and context meter currently say.

  Names, digests and numbers only — never the instruction text, never the conversation.
  The gateway surfaces this as part of `interactive.info`; the footer wants
  `prefix_fingerprint` and `context_window`/`context_used` from it.
  """
  @spec info(pid()) :: {:ok, map()} | {:error, term()}
  def info(handle), do: SessionAdapter.call(handle, :context_info)

  @doc """
  Compacts this session's conversation now, optionally focused.

  This is `/compact [focus]`. It returns the same report a client would have seen from
  the automatic path, so a caller can show "what was folded" without waiting for the
  threshold.
  """
  @spec compact(pid(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def compact(handle, focus \\ nil), do: SessionAdapter.call(handle, {:compact, focus})

  @doc """
  Starts a fresh native session in this workspace, seeded with a curated packet.

  Amp replaced compaction with Handoff because compaction produces "summary on top of
  summary" (R3 §5). This is that: rather than folding the conversation again, the
  operator gets a *new* session whose first message states the goal, the constraints, the
  progress, the decisions and the next steps, the files this session touched with their
  current hashes, the open plan items, and whatever the operator typed as `prompt`.

  Returns the new session's `provider_session_id`. The parent records `handed_off_to` and
  keeps running: a handoff is not a close, and deciding to end the parent is the
  operator's.

  ## `open_child`

  `true` (the default) opens the child transport here, inheriting this session's
  `context.owner` because a runtime-level handoff has nowhere else to send events.

  `false` writes the packet, names the child, and stops. That is the shape the
  interactive plane needs: there, the child is a *session* with its own coordinator and
  its own harness worker, and it opens its own transport from the checkpoint this call
  already wrote. Opening one here as well would put two processes on one
  `provider_session_id` and — because the worker adopts the `provider_session_id` of any
  adapter event it receives ([session/worker.ex:289](../../../../deps/jido_harness/lib/jido_harness/session/worker.ex))
  — the orphan's `native_ready` would rename the *parent's* provider session to the
  child's.
  """
  @spec handoff(pid(), String.t() | nil, keyword()) :: {:ok, map()} | {:error, term()}
  def handoff(handle, prompt \\ nil, opts \\ []),
    do: SessionAdapter.call(handle, {:handoff, prompt, Keyword.get(opts, :open_child, true)})

  # ---------------------------------------------------------------- prefix

  defp build_context(state) do
    case Context.build(context_options(state)) do
      {:ok, context} -> {:ok, %{state | prompt_context: context}}
      {:error, _reason} = error -> error
    end
  end

  defp context_options(state) do
    [
      system_prompt: state.request.system_prompt,
      cwd: state.scope.root,
      add_dirs: state.scope.roots -- [state.scope.root],
      sandbox_mode: state.scope.sandbox_mode,
      approval_mode: loop_approval_mode(state),
      tools: Tools.specs(state.request.allowed_tools, state.request.disallowed_tools),
      model_module: state.model_module,
      model_spec: state.model_spec,
      reasoning_effort: state.reasoning_effort,
      compactions: length(state.compactions)
    ]
  end

  # The prefix is built once and reused. It is rebuilt only where the operator changed
  # the session — `configure` — or where compaction rewrote the conversation, which are
  # the two documented cache invalidators this runtime can cause. Rebuilding it per turn
  # would produce the same bytes today and would be a standing invitation to put
  # something turn-dependent in it tomorrow.
  defp ensure_context(%{prompt_context: nil} = state), do: build_context(state)
  defp ensure_context(state), do: {:ok, state}

  defp context_info(state) do
    context = state.prompt_context

    base =
      if context,
        do: Context.info(context),
        else: %{prefix_fingerprint: nil, context_window: nil}

    Map.merge(base, %{
      provider_session_id: state.provider_session_id,
      context_used: state.context_used,
      compact_at: state.compact_at,
      keep_recent_tokens: state.keep_recent_tokens,
      messages: length(state.messages),
      compaction_thrashing: state.thrashing?,
      compactions: Enum.reverse(state.compactions),
      archives: Enum.reverse(state.archives),
      handed_off_to: state.handed_off_to,
      plan: state.plan_mode?,
      awaiting_plan_exit: state.plan_exit != nil
    })
  end

  # ---------------------------------------------------------------- the meter

  # The size reported is whatever the provider counted for the last request. A session
  # that has not spent a turn yet reports zero used, which is true, rather than an
  # estimate of what the prefix will cost, which would be a guess presented as a
  # measurement.
  defp track_usage(state, %{type: :usage, payload: payload}) when is_map(payload) do
    case Window.used(payload) do
      used when used > 0 -> %{state | context_used: used}
      _none -> state
    end
  end

  defp track_usage(state, _event), do: state

  # ---------------------------------------------------------------- compaction

  # The thrash latch is deliberately permanent for the *automatic* path. "Stop rather
  # than loop" means stop: a session whose tail alone fills the window will keep meeting
  # the threshold on every turn, and re-arming would be the loop the guard exists to
  # prevent. The operator's own `/compact` is not latched — they were told what happened
  # and what to change, and overruling them would be a different mistake.
  defp maybe_compact(%{thrashing?: true} = state), do: {:ok, state}

  defp maybe_compact(state) do
    window = state.prompt_context && state.prompt_context.context_window

    if Window.over_threshold?(state.context_used, window, state.compact_at) do
      case run_compaction(state, nil, :automatic) do
        {:ok, state, _report} -> {:ok, state}
        # A refused compaction is not a refused turn. The operator has been told, in an
        # event with the reason in it, and the turn goes to the model as it stands —
        # which the provider may still reject for length, honestly, rather than this
        # runtime failing it pre-emptively on a threshold it just admitted it cannot act
        # on.
        {:error, _reason, state} -> {:ok, state}
      end
    else
      {:ok, state}
    end
  end

  # Two compactions inside three turns is not a context that needs folding, it is a
  # threshold or a tail that cannot fit. Say so once, as a `status` provider event, and
  # stop — Claude Code's thrashing detection with the reason made visible.
  defp run_compaction(state, focus, trigger) do
    if thrash_guard(state) do
      emit(state, %{
        type: :provider_event,
        payload: %{
          "kind" => "status",
          "status" => "compaction_thrashing",
          "message" =>
            "two compactions within three turns; stopping rather than looping. " <>
              "Raise `keep_recent_tokens`, lower `compact_at`, or hand off to a new " <>
              "session with the packet this one can build."
        },
        turn_id: nil,
        request_id: nil
      })

      {:error, :compaction_thrashing, %{state | thrashing?: true}}
    else
      gated_compaction(state, focus, trigger)
    end
  end

  # `PreCompact`, on the `PreToolUse` contract: exit 2 refuses, stderr is the reason. It is
  # the second thing in this provider a hook may stop, and it earns that for the same
  # reason a tool call does — compaction rewrites the conversation, and a repository that
  # knows this is the wrong moment has no other way to say so.
  #
  # A refusal is the *existing* refusal path, which is the point: nothing is dropped, the
  # whole conversation stays, prior archives stay, and the reason reaches the operator in
  # the event that names it. The next model request may still be refused for length, which
  # is a truthful failure rather than a silent loss.
  defp gated_compaction(state, focus, trigger) do
    base =
      hook_base(state)
      |> Map.put("trigger", if(trigger == :manual, do: "manual", else: "automatic"))
      |> Map.put("custom_instructions", focus || "")
      |> Map.put("messages", length(state.messages))

    case Hooks.pre_compact(state.hooks, base) do
      {:ok, _context} ->
        do_compaction(state, focus, trigger)

      {:deny, reason} ->
        announce_refusal(
          state,
          "pre_compact_hook_denied",
          reason,
          "the conversation was not compacted because a PreCompact hook refused it. " <>
            "Nothing was dropped."
        )

        {:error, {:pre_compact_denied, reason}, state}
    end
  end

  defp do_compaction(state, focus, trigger) do
    {:ok, outcome} =
      Compaction.compact(state.messages,
        keep_recent_tokens: state.keep_recent_tokens,
        focus: focus,
        summarize: summariser(state)
      )

    case archive(state, outcome.archived) do
      {:ok, entry} -> apply_compaction(state, outcome, entry, trigger)
      {:error, reason} -> refuse_compaction(state, reason)
    end
  end

  # "Compaction always leaves the archive" is an invariant, so it decides the outcome
  # rather than decorating it: messages that could not be written down are not dropped.
  # The session keeps its whole conversation, the operator is told why, and the provider
  # may still refuse the next request for length — which is a truthful failure rather
  # than a silent loss.
  defp refuse_compaction(state, reason) do
    Logger.warning("native compaction refused: archive unwritable (#{inspect(reason)})")

    announce_refusal(
      state,
      "archive_unwritable",
      inspect(reason),
      "the conversation was not compacted because its pre-compaction transcript " <>
        "could not be archived. Nothing was dropped."
    )

    {:error, {:archive_unwritable, reason}, state}
  end

  # One event shape for every refused compaction, whatever refused it. The `status` stays
  # `compaction_refused` — a client keys on that — and `cause` names which of the two it
  # was, because "a hook said no" and "this node could not write the archive" are
  # different problems with different fixes.
  defp announce_refusal(state, cause, reason, message) do
    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "status",
        "status" => "compaction_refused",
        "cause" => cause,
        "reason" => reason,
        "message" => message
      },
      turn_id: nil,
      request_id: nil
    })
  end

  defp apply_compaction(state, outcome, entry, trigger) do
    report = %{
      trigger: Atom.to_string(trigger),
      turn: state.turns,
      archived_messages: length(outcome.archived),
      archive_id: entry && entry.id,
      elided_tool_results: outcome.elided,
      summary_tokens: outcome.summary_tokens,
      before_tokens: outcome.before_tokens,
      after_tokens: outcome.after_tokens,
      summarised: outcome.summarised
    }

    state = %{
      state
      | messages: outcome.messages,
        compactions: [report | state.compactions],
        archives: if(entry, do: [entry | state.archives], else: state.archives),
        prompt_context: Context.compacted(state.prompt_context, context_options(state)),
        context_used: 0
    }

    # Checkpoint before broadcast, the same order every other durable write in this
    # process follows: a client told the conversation was folded must never be able to
    # restart onto a conversation that was not.
    _ = checkpoint(state)

    emit(state, %{
      type: :provider_event,
      payload: compaction_payload(report, outcome),
      turn_id: nil,
      request_id: nil
    })

    {:ok, state, report}
  end

  defp thrash_guard(%{compactions: [%{turn: turn} | _rest]} = state), do: state.turns - turn <= 3
  defp thrash_guard(_state), do: false

  defp compaction_payload(report, outcome) do
    %{
      "kind" => "compaction",
      "trigger" => report.trigger,
      "archived_messages" => report.archived_messages,
      "archive_id" => report.archive_id,
      "elided_tool_results" => report.elided_tool_results,
      "summary_tokens" => report.summary_tokens,
      "before_tokens" => report.before_tokens,
      "after_tokens" => report.after_tokens,
      "summary" => outcome.summary
    }
    |> Map.reject(fn {_key, value} -> is_nil(value) end)
  end

  # Nothing to archive is not a failed archive: eliding tool results alone dropped no
  # message, so there is no transcript to keep.
  defp archive(_state, []), do: {:ok, nil}

  defp archive(state, messages),
    do: Archive.write(state.session_dir, messages, event_limit: state.checkpoint_limit)

  # The summariser is one more call on the same model module the turn uses, with no
  # tools. It is deliberately not the loop: a summary that could call `bash` would be a
  # second agent nobody asked for.
  defp summariser(state) do
    fn %{messages: messages, instruction: instruction} ->
      request = %{
        model: state.model_spec,
        system: instruction,
        messages: messages ++ [%{role: :user, content: instruction}],
        tools: [],
        reasoning_effort: nil,
        max_tokens: nil
      }

      case Model.stream(state.model_module, request, []) do
        {:ok, stream} -> {:ok, collect_text(stream)}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp collect_text(stream) do
    stream
    |> Enum.reduce([], fn
      {:text, delta}, acc when is_binary(delta) -> [acc, delta]
      _other, acc -> acc
    end)
    |> IO.iodata_to_binary()
  rescue
    _error -> ""
  catch
    :exit, _reason -> ""
  end

  # ---------------------------------------------------------------- handoff

  # The packet is made durable *before* the child is started. A handoff whose child
  # failed to start is then still a handoff the operator can open by id, rather than a
  # summary that existed only inside a call that returned an error.
  defp start_handoff(state, prompt, open_child?) do
    packet =
      Handoff.packet(
        summary: handoff_summary(state),
        files: Map.keys(state.reads),
        plan: state.plan,
        prompt: prompt,
        workspace: state.scope.root,
        parent: state.provider_session_id
      )

    child_id = Paths.new_session_id()
    seeded = [%{role: :user, content: packet}]

    with {:ok, checkpoint_path, _durable?} <- Checkpoint.locate(child_id),
         :ok <- Checkpoint.write(checkpoint_path, seeded, event_limit: state.checkpoint_limit),
         {:ok, pid} <- maybe_open_child(state, child_id, open_child?) do
      result = %{
        provider_session_id: child_id,
        pid: pid,
        packet_bytes: byte_size(packet),
        files: length(Map.keys(state.reads)),
        parent: state.provider_session_id
      }

      emit(state, %{
        type: :provider_event,
        payload: %{
          "kind" => "handoff",
          "provider_session_id" => child_id,
          "packet_bytes" => result.packet_bytes,
          "files" => result.files
        },
        turn_id: nil,
        request_id: nil
      })

      {:ok, %{state | handed_off_to: child_id}, result}
    end
  end

  # The child inherits this session's request — same workspace, same tools, same posture —
  # with its own id and no caller-supplied resume. It also inherits `context.owner`,
  # because a runtime-level handoff has nowhere else to send events; the gateway replaces
  # the owner when it wires the verb, and that is the one thing this function does not
  # decide.
  defp open_child(state, child_id) do
    request = %{state.request | provider_session_id: child_id}
    open(request, state.context)
  end

  # `{:ok, nil}` rather than a separate result shape: the caller that asked for no child
  # process is the one that is about to open it properly, and the packet on disk is the
  # thing a handoff actually is.
  defp maybe_open_child(state, child_id, true), do: open_child(state, child_id)
  defp maybe_open_child(_state, _child_id, false), do: {:ok, nil}

  # A handoff summarises the whole conversation, not the part past `keep_recent_tokens`:
  # the new session gets no verbatim tail, so a summary that stopped short of the last
  # twenty thousand tokens would hand over a packet missing the most recent work.
  defp handoff_summary(%{messages: []}), do: nil

  defp handoff_summary(state) do
    instruction = Compaction.summary_instruction(nil)

    case summariser(state).(%{messages: state.messages, focus: nil, instruction: instruction}) do
      {:ok, summary} when is_binary(summary) ->
        case String.trim(summary) do
          "" -> Compaction.structural_summary(state.messages, nil)
          text -> text
        end

      _failed ->
        Compaction.structural_summary(state.messages, nil)
    end
  end

  defp track_plan(state, %{type: :plan_updated, payload: payload}) when is_map(payload),
    do: %{state | plan: payload, turn_plan: payload}

  defp track_plan(state, _event), do: state

  defp track_text(state, %{type: :output_text_final, payload: %{"text" => text}})
       when is_binary(text),
       do: %{state | turn_text: text}

  defp track_text(state, _event), do: state

  # ---------------------------------------------------------------- plan mode (B2)

  # Only a completed turn raises the question, and only when the turn produced something
  # to ask about. A failed or interrupted turn has no plan to accept, and a turn that
  # neither called `plan` nor said anything has nothing to show a person — asking anyway
  # would be a modal with an empty body.
  defp plan_exit?(%{plan_mode?: true, plan_exit: nil} = state, %{type: :turn_completed}),
    do: plan_summary(state) != nil

  defp plan_exit?(_state, _event), do: false

  # The plan, in the two shapes a turn can produce one. `plan_updated` is the tool's, and
  # it is preferred because it is structured. A model that ignored the tool and wrote the
  # plan in prose still planned, and refusing to show that would make the exit approval
  # depend on the model using a tool the prompt calls optional — so the final message is
  # the fallback, labelled as such rather than passed off as a step list.
  defp plan_summary(%{turn_plan: %{} = plan}) do
    case Map.get(plan, "plan") do
      [_first | _rest] = steps -> %{source: "plan_tool", plan: plan, steps: steps, message: nil}
      _empty -> nil
    end
  end

  defp plan_summary(%{turn_text: text}) when is_binary(text) do
    case String.trim(text) do
      "" ->
        nil

      trimmed ->
        %{
          source: "message",
          plan: nil,
          steps: [],
          message: clip(trimmed, @max_plan_message_bytes)
        }
    end
  end

  defp plan_summary(_state), do: nil

  defp raise_plan_exit(state, terminal) do
    summary = plan_summary(state)
    request_id = "plan_exit_" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    emit(state, %{
      type: :approval_requested,
      payload: plan_exit_payload(summary),
      turn_id: terminal.turn_id,
      request_id: request_id
    })

    %{
      state
      | plan_exit: %{
          request_id: request_id,
          turn_id: terminal.turn_id,
          terminal: terminal,
          timer: plan_exit_timer(state, request_id)
        }
    }
  end

  defp plan_exit_payload(summary) do
    %{
      "kind" => "plan_exit",
      "header" => "Plan ready",
      "question" =>
        "This session has been planning. Ready to build it?\n" <>
          "· Yes, auto-accept edits — edits inside the workspace apply without asking; " <>
          "commands still ask.\n" <>
          "· Yes, manual approvals — every write and command is put to you.\n" <>
          "· No, keep planning — nothing changes and the session stays read-only.",
      "plan_source" => summary.source,
      "options" => @plan_exit_options
    }
    |> maybe_put("plan", summary.plan)
    |> maybe_put("message", summary.message)
  end

  defp maybe_put(payload, _key, nil), do: payload
  defp maybe_put(payload, key, value), do: Map.put(payload, key, value)

  defp plan_exit_timer(%{request: %{approval_timeout_ms: :infinity}}, _request_id), do: nil

  defp plan_exit_timer(%{request: %{approval_timeout_ms: timeout}}, request_id)
       when is_integer(timeout) and timeout > 0,
       do: Process.send_after(self(), {:plan_exit_timeout, request_id}, timeout)

  defp plan_exit_timer(_state, _request_id), do: nil

  defp answer_plan_exit(state, response) do
    choice = plan_exit_choice(response)
    settle_plan_exit(state, choice, follow_up(response))
  end

  # How the three choices are read, in the order that keeps a client which has never heard
  # of plan mode useful. An explicit `provider_options["choice"]` wins. Otherwise `reason`
  # is matched *exactly* against the three ids and labels — loosely matching free text a
  # person typed would put a session to work on a sentence that mentioned edits. Otherwise
  # the decision and scope decide, which is what today's TUI actually sends: it renders the
  # three options' `kind`s onto approve-session, approve-once and deny.
  defp plan_exit_choice(response) do
    options = Map.get(response, :provider_options) || %{}
    explicit = Map.get(options, "choice") || Map.get(options, :choice)

    cond do
      choice = known_choice(explicit) -> choice
      choice = known_choice(Map.get(response, :reason)) -> choice
      Map.get(response, :decision) == :deny -> :keep_planning
      Map.get(response, :scope) == :session -> :auto_edit
      true -> :prompt
    end
  end

  defp known_choice(value) when is_binary(value) do
    case value |> String.trim() |> String.downcase() do
      "auto_edit" -> :auto_edit
      "yes, auto-accept edits" -> :auto_edit
      "prompt" -> :prompt
      "yes, manual approvals" -> :prompt
      "keep_planning" -> :keep_planning
      "no, keep planning" -> :keep_planning
      _free_text -> nil
    end
  end

  defp known_choice(value) when value in [:auto_edit, :prompt, :keep_planning], do: value
  defp known_choice(_other), do: nil

  defp follow_up(response) do
    options = Map.get(response, :provider_options) || %{}

    case Map.get(options, "follow_up") || Map.get(options, :follow_up) do
      text when is_binary(text) ->
        case String.trim(text) do
          "" -> nil
          trimmed -> clip(trimmed, @max_follow_up_bytes)
        end

      _absent ->
        nil
    end
  end

  # The one place the three answers become configuration. `keep_planning` deliberately
  # calls nothing: "leaves everything as it was" is a claim about the session, and the way
  # to keep it true is to not touch it.
  defp settle_plan_exit(%{plan_exit: nil} = state, _choice, _follow_up), do: state

  defp settle_plan_exit(state, choice, follow_up) do
    pending = state.plan_exit
    _ = pending.timer && Process.cancel_timer(pending.timer)
    state = %{state | plan_exit: nil}

    {state, applied} = apply_plan_exit(state, choice)

    emit(state, %{
      type: :provider_event,
      payload: %{
        "kind" => "plan_exit",
        "choice" => Atom.to_string(choice),
        "approval_mode" => Atom.to_string(state.approval_mode),
        "sandbox_mode" => Atom.to_string(state.scope.sandbox_mode),
        "plan" => state.plan_mode?,
        "applied" => applied,
        "follow_up" => follow_up != nil
      },
      turn_id: pending.turn_id,
      request_id: pending.request_id
    })

    continue_after_plan_exit(state, pending, follow_up)
  end

  defp apply_plan_exit(state, :keep_planning), do: {state, false}

  defp apply_plan_exit(state, mode) when mode in [:auto_edit, :prompt] do
    changes = %{plan: false, approval_mode: mode}

    with {:ok, state} <- apply_configuration(state, changes),
         {:ok, state} <- build_context(state) do
      # The answer is made durable here, not left to the plane. A person answered an
      # approval this runtime raised; a restart that put the session back to the mode it
      # was started with would lose their answer without saying so.
      {persist_posture(%{state | plan_exit_mode: mode}), true}
    else
      # A refused reconfiguration leaves the session planning and says so in the event
      # above rather than reporting a mode the session is not in. There is nothing here a
      # caller can retry differently, so it is not an error return: the question was
      # answered, and the answer could not be carried out.
      {:error, reason} ->
        Logger.warning("native plan exit could not reconfigure the session: #{inspect(reason)}")
        {state, false}
    end
  end

  # Two ways a held turn ends. Without a follow-up the terminal event finally goes out and
  # the turn is over. With one, the *same* turn continues: the follow-up runs under the
  # turn id the plan ran under, which is what keeps the harness worker's bookkeeping true —
  # its active turn is still active, its approvals still route, and the terminal event it
  # eventually sees is the one that finishes the work it dispatched. A completed turn
  # followed by more work under a turn nobody started would be neither.
  defp continue_after_plan_exit(state, pending, nil), do: emit_held(state, pending)

  defp continue_after_plan_exit(state, pending, follow_up) do
    case start_turn(state, TurnRequest.new!(follow_up), pending.turn_id) do
      {:ok, state} ->
        state

      {:error, reason} ->
        emit(state, %{
          type: :provider_event,
          payload: %{
            "kind" => "status",
            "status" => "plan_follow_up_refused",
            "reason" => inspect(reason),
            "message" =>
              "the plan was accepted and the follow-up prompt could not be started; " <>
                "send it again as an ordinary turn."
          },
          turn_id: pending.turn_id,
          request_id: nil
        })

        emit_held(state, pending)
    end
  end

  defp emit_held(state, pending) do
    emit(state, pending.terminal)
    release(state)
  end

  defp release_held_terminal(%{plan_exit: nil} = state), do: state

  defp release_held_terminal(%{plan_exit: pending} = state) do
    _ = pending.timer && Process.cancel_timer(pending.timer)
    emit_held(%{state | plan_exit: nil}, pending)
  end

  # ---------------------------------------------------------------- posture

  # Read at open, and only for a session that asked to resume — the same rule the
  # conversation checkpoint follows, for the same reason: a fresh id has no posture by
  # definition. An unreadable or nonsense file is treated as no file. It names a boolean
  # and a sandbox mode, so the worst a corrupt one can do is start a session at the
  # posture its request already asked for.
  # A written posture **wins outright on a resume**, and that precedence is the whole
  # point. `provider_options` are *start* intent, and the interactive plane replays them
  # verbatim when it rebuilds a request from its checkpoint — so a session that started
  # planning, was accepted, and went to work would be dragged back into plan mode on every
  # restart if the request could outvote the file. The file is what the session is
  # actually doing; the request is what someone once asked for.
  #
  # A resume that finds no posture file at all falls back to the request, which is what
  # makes a session written by an older build resume the way its caller asked.
  defp restore_posture(session_dir, request, options) do
    stored =
      case read_posture(Path.join(session_dir, @posture_file), request.provider_session_id) do
        {:ok, stored} ->
          stored

        :absent ->
          %{plan?: requested_plan?(options), sandbox_before_plan: nil, approval_mode: nil}
      end

    %{
      plan?: stored.plan?,
      approval_mode: stored.approval_mode,
      sandbox_before_plan:
        if(stored.plan?,
          do: stored.sandbox_before_plan || Loop.sandbox_mode(request.sandbox_mode)
        )
    }
  end

  defp read_posture(_path, nil), do: :absent

  defp read_posture(path, _resumed) do
    with {:ok, body} <- File.read(path),
         {:ok, %{} = decoded} <- decode_posture(body) do
      {:ok,
       %{
         plan?: decoded["plan"] == true,
         sandbox_before_plan: sandbox_atom(decoded["sandbox_before_plan"]),
         approval_mode: approval_atom(decoded["approval_mode"])
       }}
    else
      _absent_or_unusable -> :absent
    end
  end

  # Only the two a plan exit can choose. Anything else in the file — a hand-edit, an older
  # build — is read as "no plan exit set a mode", which falls back to the request.
  defp approval_atom("auto_edit"), do: :auto_edit
  defp approval_atom("prompt"), do: :prompt
  defp approval_atom(_other), do: nil

  defp decode_posture(body) do
    {:ok, JSON.decode!(body)}
  rescue
    _error -> :error
  end

  defp sandbox_atom("read_only"), do: :read_only
  defp sandbox_atom("workspace_write"), do: :workspace_write
  defp sandbox_atom("unrestricted"), do: :unrestricted
  defp sandbox_atom(_other), do: nil

  # `provider_options` is where a start-time posture rides, the same channel
  # `max_iterations`, `tool_timeout_ms` and `checkpoint_limit` already use — the harness's
  # `SessionRequest` accepts it as a free map, which is the only reason plan mode can be
  # asked for at start at all.
  defp requested_plan?(options),
    do: Map.get(options, :plan) == true or Map.get(options, "plan") == true

  # Best effort, and deliberately not fatal: a session whose data directory went read-only
  # keeps planning, it just would not remember it across a restart. Saying so once beats
  # refusing a mode change over a file.
  defp persist_posture(state) do
    payload =
      JSON.encode!(%{
        "plan" => state.plan_mode?,
        "sandbox_before_plan" =>
          state.sandbox_before_plan && Atom.to_string(state.sandbox_before_plan),
        "approval_mode" => state.plan_exit_mode && Atom.to_string(state.plan_exit_mode)
      })

    case File.write(Path.join(state.session_dir, @posture_file), payload) do
      :ok ->
        state

      {:error, reason} ->
        Logger.warning("native session posture not persisted: #{inspect(reason)}")
        state
    end
  end

  # ---------------------------------------------------------------- hooks (D5)

  # The same content-minimised payload the loop's hooks get, minus the turn: none of the
  # three lifecycle events happens inside one.
  defp hook_base(state) do
    %{
      "session_id" => state.context.session_id,
      "provider_session_id" => state.provider_session_id,
      "turn_id" => nil,
      "cwd" => state.scope.root,
      "workspace_trusted" => state.hooks.trusted?
    }
  end

  # Detached, because this runs on the way out. A node whose task supervisor is not up —
  # a session driven straight from a test — runs it inline instead, under the same
  # per-hook ceiling: bounded either way, and observable either way.
  defp session_end(state, reason) do
    config = state.hooks
    base = Map.put(hook_base(state), "reason", reason)

    case Task.Supervisor.start_child(Jido.Harness.SessionTaskSupervisor, fn ->
           Hooks.session_end(config, base)
         end) do
      {:ok, _pid} -> :ok
      _unavailable -> Hooks.session_end(config, base)
    end
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp injected([]), do: ""
  defp injected(lines), do: "\n" <> Enum.join(lines, "\n")

  defp clip(text, limit) when byte_size(text) <= limit, do: text
  defp clip(text, limit), do: binary_part(text, 0, limit) <> "…"
end
