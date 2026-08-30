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
  alias Ouroboros.Provider.Native.Attachments
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Archive
  alias Ouroboros.Provider.Native.Context.Compaction
  alias Ouroboros.Provider.Native.Context.Handoff
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Inference
  alias Ouroboros.Provider.Native.Journal
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool

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

  A conversation half that cannot be honoured is
  `{:error, {:rewind_checkpoint_failed, reason, outcome}}`, not a quiet `{:ok, …}` with
  the transcript left where it was. That happens when the turn's boundary is older than
  what this session still holds of its own conversation — a resume keeps the newest
  `event_limit` messages and a compaction folded the head — and the honest answer is that
  the files came back and the transcript could not, rather than a `:both` that delivered
  one half and reported two.

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
  R1. A window of this session's turn journal, with the chain state that bounds it.

  `{head, head_seq, verified_through, truncated_through, count, records}`. The chain is
  verified on the way past rather than reported as a boolean: `verified_through` below
  `head_seq` is how a reader learns the record is trustworthy only up to a point, and
  `truncated_through` is what the budget dropped. Neither is an error, because both are
  states a record honestly reaches.
  """
  @spec journal(pid(), keyword()) :: {:ok, map()} | {:error, term()}
  def journal(handle, opts \\ []), do: SessionAdapter.call(handle, {:journal, opts})

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
    fork? = truthy_option(options, "fork_session")
    fork_to_turn = option(options, "fork_to_turn")
    requested_id = if(fork?, do: nil, else: request.provider_session_id)
    checkpoint_limit = Checkpoint.limit(options)

    with {:ok, provider_session_id} <- session_id(requested_id),
         {:ok, seeded} <-
           seed_fork(
             request.provider_session_id,
             provider_session_id,
             fork?,
             checkpoint_limit,
             fork_to_turn
           ),
         {:ok, scope} <-
           Paths.scope(request.cwd, request.add_dirs, Loop.sandbox_mode(request.sandbox_mode)),
         {:ok, model_spec} <- Loop.resolve_model(request.model),
         {:ok, session_dir, durable?} <- Paths.session_dir(provider_session_id),
         {:ok, checkpoint_path, _durable?} <- Checkpoint.locate(provider_session_id),
         {:ok, conversation} <- restore(checkpoint_path) do
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
        checkpoint_limit: checkpoint_limit,
        model_module: Model.module(),
        model_spec: model_spec,
        reasoning_effort: request.reasoning_effort,
        approval_mode: posture.approval_mode || Loop.approval_mode(request.approval_mode),
        max_iterations: Loop.max_iterations(options, nil),
        tool_timeout_ms: Loop.tool_timeout(options),
        messages: conversation.messages,
        # Where `messages` sits in the conversation this session has had in total, and the
        # oldest point a rewind can still cut it at. A resumed session holds the tail its
        # checkpoint kept and a compacted one holds a summary where its head used to be;
        # the turn manifest counts from the beginning either way, so these two are what
        # make its numbers mean something here. See `rewind_conversation/3`.
        message_offset: conversation.offset,
        rewind_floor: conversation.rewind_floor,
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
        # ---- subagents (G3) ----
        # Where this session sits in the subagent tree, and whose child it is. All three
        # ride in `provider_options` because that is the only channel a `SessionRequest`
        # carries an unvalidated map on — the same channel `plan` and `max_iterations`
        # already use — and because a child is opened by this runtime rather than by an
        # operator, so nothing that is not this runtime ever sets them.
        subagent_depth: subagent_depth(options),
        subagent_parent: string_option(options, "subagent_parent"),
        subagent_task_id: string_option(options, "subagent_task_id"),
        # `task_id => %{pid:, monitor:, meta:, status:}`. The session holds them, not the
        # loop, because a background child outlives the turn that spawned it and the loop
        # does not. Closing the session stops every one of them.
        subagents: %{},
        # A child can settle before the loop's tracking call reaches this process. These
        # bounded tombstones preserve that ordering fact until the corresponding track.
        settled_subagents: MapSet.new(),
        # ---- hooks (D5's three lifecycle events) ----
        hooks: Hooks.load(scope.root),
        # `SessionStart`'s `additionalContext`, held until the first turn's prompt and
        # dropped once it has been sent. It never joins the system prompt: the prefix has
        # a fingerprint and a session-scoped instruction in it would cost the cache.
        start_context: [],
        resumed?: not fork? and not is_nil(request.provider_session_id),
        # R1. The session's own handle on the turn journal. It is opened here and passed
        # into every `Loop` this session runs; between turns this process is the writer,
        # and each of its own records syncs the handle first because the loop advanced the
        # file while it was not looking.
        journal: Journal.open(session_dir)
      }

      case build_context(state) do
        {:ok, state} ->
          register(provider_session_id)

          state =
            journal(
              state,
              "session_opened",
              %{
                "provider_session_id" => provider_session_id,
                "resumed" => state.resumed?,
                "forked_from_provider_session_id" => if(fork?, do: request.provider_session_id),
                "journal_version" => Journal.version()
              }
              |> Map.merge(seeded_fields(seeded))
            )

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
    case Attachments.message(TurnRequest.text(request), request.attachments, state.session_dir) do
      {:ok, message} ->
        Kernel.send(state.loop.pid, {:native_steer, message})
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
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

  # ---------------------------------------------------------------- subagents (G3)

  # The parent session is the registry, and deliberately not a global one. A task id is
  # only ever meaningful to the session that spawned it, so scoping the table to this
  # process makes "collect a child of another session" structurally impossible rather
  # than a check somebody has to remember.
  def handle_call({:subagent_track, task_id, pid, meta}, _from, state) do
    if map_size(state.subagents) >= AgentTool.max_tracked() do
      {:reply, {:error, :subagent_table_full}, state}
    else
      monitor = Process.monitor(pid)
      settled? = MapSet.member?(state.settled_subagents, task_id)

      entry = %{
        pid: pid,
        monitor: monitor,
        meta: meta,
        status: if(settled?, do: :settled, else: :running)
      }

      {:reply, :ok,
       %{
         state
         | subagents: Map.put(state.subagents, task_id, entry),
           settled_subagents: MapSet.delete(state.settled_subagents, task_id)
       }}
    end
  end

  def handle_call({:subagent_lookup, task_id}, _from, state) do
    case Map.fetch(state.subagents, task_id) do
      {:ok, %{pid: pid}} -> {:reply, {:ok, pid}, state}
      :error -> {:reply, :error, state}
    end
  end

  def handle_call({:subagent_release, task_id}, _from, state),
    do: {:reply, :ok, forget_subagent(state, task_id)}

  # `running` is what the four-at-once cap counts; `tracked` includes settled children
  # whose processes deliberately stay alive until `agent_result` collects them.
  def handle_call(:subagent_counts, _from, state) do
    running =
      Enum.count(state.subagents, fn {_task_id, entry} ->
        entry.status == :running and subagent_alive?(entry.pid)
      end)

    {:reply, %{running: running, tracked: map_size(state.subagents)}, state}
  end

  def handle_call(:close, _from, state) do
    # A held terminal event goes out before the session does. A client whose turn never
    # ended because the plan-exit question was still open would be waiting on a session
    # that no longer exists.
    state = state |> release_held_terminal() |> stop_loop() |> stop_subagents("session closed")

    case checkpoint(state) do
      {:ok, _digest} ->
        _ = session_end(state, "closed")

        emit(state, %{
          type: :session_closed,
          payload: %{"reason" => "closed"},
          turn_id: nil,
          request_id: nil
        })

        {:stop, :normal, :ok, state}

      {:error, reason} ->
        {:reply, {:error, {:checkpoint_failed, reason}}, state}
    end
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

    case checkpoint(state) do
      {:ok, digest} -> {:reply, {:ok, digest}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:checkpoint, _stale_turn_id, _snapshot}, _from, state),
    do: {:reply, :ok, state}

  def handle_call({:journal, opts}, _from, state) do
    {:reply, Journal.window(Journal.path(state.session_dir), opts), state}
  end

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
        case rewind_conversation(state, to_turn, what) do
          {:ok, state, truncated} ->
            outcome = Map.put(outcome, :messages, truncated)
            announce(state, to_turn, what, outcome)
            {:reply, {:ok, outcome}, state}

          {:error, state, reason} ->
            outcome =
              outcome
              |> Map.put(:messages, length(state.messages))
              |> Map.put(:checkpoint_error, reason)

            announce(state, to_turn, what, outcome)
            {:reply, {:error, {:rewind_checkpoint_failed, reason, outcome}}, state}
        end

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

  # G3. A background child reports here rather than to a loop, because the turn that
  # spawned it has ended. Its progress and its terminal digest reach the client as
  # `provider_event`s of this session with no turn id, which is the truth: the work is
  # this session's, and no turn of it is running.
  def handle_info({:subagent, _task_id, {:progress, payload}}, state) do
    emit(state, subagent_event(payload))
    {:noreply, state}
  end

  # A settled background child stays in the table until somebody collects it: the summary
  # lives in its own process, and forgetting the entry here would make `agent_result`
  # answer "no such task" about a child that finished a second ago.
  def handle_info({:subagent, task_id, {:settled, summary}}, state) do
    emit(state, subagent_event(Subagent.settled_payload(summary)))
    {:noreply, mark_subagent_settled(state, task_id)}
  end

  # An approval a background child raised reaches nobody here, and this process must not
  # pretend otherwise. `Subagent` denies it at source with a legible reason and counts it
  # in the digest; this clause exists so that a message which somehow arrives is dropped
  # rather than matched by something else.
  def handle_info({:subagent, _task_id, {:approval, _request_id, _payload}}, state),
    do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    {:noreply, forget_by_monitor(state, monitor)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp forget_subagent(state, task_id) do
    state = %{state | settled_subagents: MapSet.delete(state.settled_subagents, task_id)}

    case Map.fetch(state.subagents, task_id) do
      {:ok, entry} ->
        Process.demonitor(entry.monitor, [:flush])
        %{state | subagents: Map.delete(state.subagents, task_id)}

      :error ->
        state
    end
  end

  defp mark_subagent_settled(state, task_id) do
    case Map.fetch(state.subagents, task_id) do
      {:ok, entry} ->
        put_in(state.subagents[task_id], %{entry | status: :settled})

      :error ->
        tombstones =
          if MapSet.size(state.settled_subagents) < AgentTool.max_tracked(),
            do: MapSet.put(state.settled_subagents, task_id),
            else: state.settled_subagents

        %{state | settled_subagents: tombstones}
    end
  end

  # `Process.alive?/1` answers only about this node and **raises** for a pid of any other,
  # so a child placed on another machine cannot be asked here. It does not need to be: every
  # tracked child is monitored, a monitor fires across the distribution link — including on
  # `:noconnection` — and `forget_by_monitor/2` drops the entry when it does. Membership in
  # the table is therefore already the answer for a remote child, and the local check stays
  # only because for a local child it is free and one step fresher.
  defp subagent_alive?(pid) when node(pid) == node(), do: Process.alive?(pid)
  defp subagent_alive?(_remote), do: true

  defp forget_by_monitor(state, monitor) do
    case Enum.find(state.subagents, fn {_task_id, entry} -> entry.monitor == monitor end) do
      {task_id, _entry} -> %{state | subagents: Map.delete(state.subagents, task_id)}
      nil -> state
    end
  end

  # Children are stopped when the **session** closes, not when a turn ends. That is the
  # whole lifecycle promise a background child makes, and it is kept here: every tracked
  # child, settled or not, is stopped, its own session closed, and its worktree retired by
  # `Subagent`'s own terminate.
  defp stop_subagents(%{subagents: subagents} = state, _reason) when map_size(subagents) == 0,
    do: state

  defp stop_subagents(state, _reason) do
    Enum.each(state.subagents, fn {_task_id, entry} ->
      Process.demonitor(entry.monitor, [:flush])
      _ = Subagent.stop(entry.pid, :stopped)
    end)

    %{state | subagents: %{}}
  end

  defp subagent_event(payload) do
    %{
      type: :provider_event,
      payload: Map.put(payload, "kind", "subagent"),
      turn_id: nil,
      request_id: nil
    }
  end

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
    _ = stop_subagents(state, "session closed")
    _ = Ouroboros.Provider.Native.Desktop.forget_state(state.session_dir)
    :ok
  rescue
    _error -> :ok
  end

  def terminate(reason, state) do
    _ = stop_loop(state)
    _ = stop_subagents(state, "session ended")
    _ = session_end(state, terminate_reason(reason))
    _ = Ouroboros.Provider.Native.Desktop.forget_state(state.session_dir)
    :ok
  rescue
    _error -> :ok
  end

  defp terminate_reason(:shutdown), do: "shutdown"
  defp terminate_reason({:shutdown, _detail}), do: "shutdown"
  defp terminate_reason(_crash), do: "crashed"

  # ---------------------------------------------------------------- turns

  defp start_turn(state, request, turn_id) do
    text = TurnRequest.text(request) <> injected(state.start_context)

    with {:ok, state} <- maybe_compact(state),
         {:ok, state} <- ensure_context(state),
         {:ok, user_message} <-
           Attachments.message(text, request.attachments, state.session_dir) do
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
        prefix_fingerprint: state.prompt_context.fingerprint,
        # R1. The loop is the journal's writer for the length of the turn; it syncs the
        # handle at the top of `run_turn/2` because this process may have advanced the file
        # since the handle was built.
        journal: state.journal,
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
        message_offset: state.message_offset,
        reads: state.reads,
        session_grants: state.session_grants,
        max_iterations: state.max_iterations,
        tool_timeout_ms: state.tool_timeout_ms,
        approval_timeout_ms: state.request.approval_timeout_ms,
        # G3. What the loop needs to be somebody's parent: the process that outlives the
        # turn, and the two values a child's own session is built from. Passing the
        # request and the context rather than a copied list of fields is the mechanism
        # that makes "a child inherits its parent's posture" true by construction.
        session_pid: owner,
        session_request: state.request,
        session_context: state.context,
        subagent_depth: state.subagent_depth,
        subagent_parent: state.subagent_parent,
        subagent_task_id: state.subagent_task_id
      }

      task =
        Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
          {:ok, _finished} = Loop.run_turn(loop, user_message)
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

  # R1's `configure` records are written here rather than inside each `configure_one/3`
  # clause: this is the one place that knows a change was *applied* rather than refused,
  # and eight clauses each remembering to journal themselves is eight places for the ninth
  # to forget. A refused change writes nothing, which is correct — nothing changed.
  defp apply_configuration(state, changes) do
    Enum.reduce_while(changes, {:ok, state}, fn {key, value}, {:ok, state} ->
      key = normalize_key(key)

      case configure_one(state, key, value) do
        {:ok, state} ->
          {:cont, {:ok, journal(state, "configure", %{"key" => key, "value" => value})}}

        {:error, reason} ->
          {:halt, {:error, reason}}
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

  defp seed_fork(_source_id, _child_id, false, _limit, _to_turn), do: {:ok, nil}

  defp seed_fork(source_id, child_id, true, limit, to_turn)
       when is_binary(source_id) and is_binary(child_id) do
    with :ok <- Paths.validate_session_id(source_id),
         {:ok, source_path, _durable?} <- Checkpoint.locate(source_id),
         {:ok, conversation} <- Checkpoint.load(source_path),
         {:ok, messages} <- fork_slice(source_path, conversation, to_turn),
         {:ok, child_path, _durable?} <- Checkpoint.locate(child_id),
         {:ok, _digest} <- Checkpoint.write(child_path, messages, event_limit: limit) do
      {:ok, %{to_turn: to_turn, message_count: length(messages)}}
    else
      {:error, :no_checkpoint} -> {:error, :fork_source_unavailable}
      # A boundary this parent cannot honour is named as itself. Wrapping it as
      # `fork_source_unusable` would report a broken checkpoint for a turn that is merely
      # older than what the parent still holds, which is a different problem with a
      # different answer.
      {:refused, reason} -> {:error, reason}
      {:error, reason} -> {:error, {:fork_source_unusable, reason}}
    end
  end

  defp seed_fork(_source_id, _child_id, true, _limit, _to_turn),
    do: {:error, :fork_source_required}

  # R3. A tail fork is the whole list, exactly as it was before `to_turn` existed.
  defp fork_slice(_source_path, conversation, nil), do: {:ok, conversation.messages}

  # Otherwise the child is the parent's conversation *as it stood at the end of a turn*.
  # The arithmetic is `rewind`'s, and it has to be: the parent's turn manifest counts
  # messages from the start of the session while the list on disk may be a tail a trim
  # left behind or a compaction rewrote (checkpoint.ex moduledoc), so a `to_turn` is only
  # meaningful once it is rebased through `offset`, and only *exists* above
  # `rewind_floor`. Below that floor there is no slice of this list that is the
  # conversation as it stood at that turn, and answering with the tail anyway would hand
  # back a fork that claims a branch point it does not have.
  defp fork_slice(source_path, conversation, to_turn) do
    session_dir = Path.dirname(source_path)

    case Checkpoint.message_count_at(session_dir, to_turn) do
      {:ok, 0} ->
        {:ok, []}

      {:ok, absolute} when absolute < conversation.rewind_floor ->
        {:refused, {:turn_boundary_dropped, to_turn}}

      {:ok, absolute}
      when absolute - conversation.offset > length(conversation.messages) ->
        {:refused, {:turn_boundary_beyond_conversation, to_turn}}

      {:ok, absolute} ->
        {:ok, Enum.take(conversation.messages, absolute - conversation.offset)}

      # `message_count_at/2` refuses a turn id this session never recorded, which is what
      # stops a turn id borrowed from another session cutting this one's transcript.
      :error ->
        {:refused, {:unknown_turn, to_turn}}
    end
  end

  # The truncation, written into the child's own `session_opened` record. A fork that cut
  # its parent's conversation and left a record indistinguishable from a tail fork would
  # make the child's journal claim a history it does not have; `to_turn` + `message_count`
  # is the `rewind` record's own pair, for the same reason.
  defp seeded_fields(nil), do: %{}
  defp seeded_fields(%{to_turn: nil}), do: %{}

  defp seeded_fields(%{to_turn: to_turn, message_count: count}) do
    %{"forked_at_turn" => Journal.jsonable(to_turn), "forked_message_count" => count}
  end

  defp truthy_option(options, key) do
    Map.get(options, key) == true or Map.get(options, String.to_existing_atom(key)) == true
  rescue
    ArgumentError -> Map.get(options, key) == true
  end

  # Provider options reach here as atoms from `Ouroboros.Provider.session_fork_options/3`
  # and as strings from a durable checkpoint that was written as JSON. Both spellings are
  # the same option, which is the assumption `truthy_option/2` already makes.
  defp option(options, key) do
    case Map.get(options, key) do
      nil -> Map.get(options, String.to_existing_atom(key))
      value -> value
    end
  rescue
    ArgumentError -> Map.get(options, key)
  end

  # A corrupt checkpoint fails the open rather than silently starting an empty session
  # under an id whose transcript the operator believes still exists.
  defp restore(path) do
    case Checkpoint.load(path) do
      {:ok, conversation} -> {:ok, conversation}
      {:error, :no_checkpoint} -> {:ok, %{messages: [], offset: 0, rewind_floor: 0}}
      {:error, reason} -> {:error, {:checkpoint_unusable, reason}}
    end
  end

  # ---------------------------------------------------------------- rewind

  defp rewind_files(_state, _to_turn, :conversation),
    do: {:ok, %{restored: [], unrestorable: [], turns: []}}

  defp rewind_files(state, to_turn, _files_or_both),
    do: Checkpoint.restore_files(state.session_dir, to_turn)

  defp rewind_conversation(state, _to_turn, :files),
    do: {:ok, state, length(state.messages)}

  defp rewind_conversation(state, to_turn, _conversation_or_both) do
    case boundary(state, to_turn) do
      {:ok, count} ->
        state = %{state | messages: Enum.take(state.messages, count)}

        case checkpoint(state) do
          {:ok, digest} ->
            state =
              journal(state, "rewind", %{
                "to_turn" => Journal.jsonable(to_turn),
                "message_count" => count,
                "conversation_digest" => digest
              })

            {:ok, state, count}

          {:error, reason} ->
            {:error, state, reason}
        end

      # A boundary this session cannot honour leaves the transcript alone and *says so*.
      # Reporting success here is how a `:both` rewind silently becomes a files-only one;
      # truncating anyway is how it keeps a window from the middle of the conversation and
      # calls it a turn. Both are the same lie in different directions.
      {:error, reason} ->
        {:error, state, reason}
    end
  end

  # The manifest counts messages from the start of the session. `state.messages` may not:
  # a resume holds the tail `event_limit` kept, and a compaction put a summary where the
  # head used to be. Rebasing by `message_offset` is what makes the two comparable, and
  # `rewind_floor` is where the answer stops existing — no slice of the list this session
  # holds is the conversation as it stood at a turn older than that.
  defp boundary(state, to_turn) do
    case Checkpoint.message_count_at(state.session_dir, to_turn) do
      # Before the first turn is the empty conversation, whatever is left of the rest.
      {:ok, 0} ->
        {:ok, 0}

      {:ok, absolute} when absolute < state.rewind_floor ->
        {:error, {:turn_boundary_dropped, to_turn}}

      {:ok, absolute} when absolute - state.message_offset > length(state.messages) ->
        {:error, {:turn_boundary_beyond_conversation, to_turn}}

      {:ok, absolute} ->
        {:ok, absolute - state.message_offset}

      :error ->
        {:error, {:unknown_turn, to_turn}}
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
      payload:
        %{
          "kind" => "status",
          "event" => "rewind",
          "to_turn" => to_string(to_turn),
          "what" => Atom.to_string(what),
          "restored" => length(outcome.restored),
          "unrestorable" => Enum.map(outcome.unrestorable, &describe_unrestorable/1),
          "messages" => outcome.messages
        }
        |> conversation_note(outcome),
      turn_id: nil,
      request_id: nil
    })
  end

  # A client that only reads the event has to be able to see that the conversation half
  # did not happen; the return value is not the only place this is said.
  defp conversation_note(payload, %{checkpoint_error: reason}),
    do: Map.put(payload, "conversation_error", inspect(reason, limit: 6))

  defp conversation_note(payload, _outcome), do: payload

  defp describe_unrestorable(%{path: nil, turn_id: turn_id, reason: reason}),
    do: %{"turn_id" => turn_id, "reason" => reason}

  defp describe_unrestorable(%{path: path} = entry),
    do: %{"path" => path, "reason" => Map.get(entry, :reason) || "could not be restored"}

  # Answers with the digest the write computed, because the loop's `turn_settled` journal
  # record carries it as the journal↔conversation cross-link (R1) and recomputing it here
  # would be a second digest over the same list.
  defp checkpoint(state) do
    case Checkpoint.write(state.checkpoint_path, state.messages,
           event_limit: state.checkpoint_limit,
           offset: state.message_offset,
           rewind_floor: state.rewind_floor
         ) do
      {:ok, digest} ->
        {:ok, digest}

      {:error, reason} ->
        Logger.warning("native session checkpoint failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------- journal (R1)

  # This process is the journal's writer between turns; the loop is its writer during one.
  # Syncing first is what makes that safe without a lock: the handle picks up whatever the
  # loop appended while this process was not looking, and a bounded tail read is all it
  # costs. The degradation is announced here for the same reason the loop announces its
  # own — a session whose record has holes should say so once, not silently.
  defp journal(state, kind, fields) do
    journal = journal_direct(state, kind, fields)

    if journal != nil and journal.degraded? do
      emit(state, %{
        type: :provider_event,
        payload: %{
          "kind" => "journal_degraded",
          "message" =>
            "this session's turn journal could not be written, so it is not fully " <>
              "replayable. Nothing else about the session is affected; the next record " <>
              "the journal does write names what was lost."
        },
        turn_id: nil,
        request_id: nil
      })
    end

    %{state | journal: journal}
  end

  # The same append without the announcement or the state update, for the summariser: it
  # runs inside a closure that has no state to give back, so it writes through the file —
  # which is the authority anyway — and this process's next `journal/3` syncs onto it.
  defp journal_direct(state, kind, fields) do
    state.journal |> Journal.sync() |> Journal.append(kind, fields)
  end

  defp text_digest(text) when is_binary(text),
    do: :sha256 |> :crypto.hash(text) |> Base.encode16(case: :lower)

  defp text_digest(_text), do: nil

  # The same principal shape the loop's tool-call entries use, so one reader's filter finds
  # a session's tool calls and its model calls together.
  defp principal(%{context: %{session_id: id}}) when is_binary(id) and id != "",
    do: "session:" <> id

  defp principal(%{provider_session_id: id}) when is_binary(id) and id != "",
    do: "native:" <> id

  defp principal(_state), do: "native"

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
    context_window = Window.resolve(state.model_spec)

    [
      system_prompt: state.request.system_prompt,
      cwd: state.scope.root,
      add_dirs: state.scope.roots -- [state.scope.root],
      sandbox_mode: state.scope.sandbox_mode,
      approval_mode: loop_approval_mode(state),
      tools:
        Tools.specs(state.request.allowed_tools, state.request.disallowed_tools,
          workspace: state.scope.root,
          context_window: context_window,
          subagent_depth: state.subagent_depth
        ),
      model_module: state.model_module,
      model_spec: state.model_spec,
      context_window: context_window,
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
  # G3. A child's spend folds into this session's `usage` events so `/cost` stays true,
  # but a child's *request size* is a fact about the child's window and never about this
  # one. The meter therefore ignores any payload that names a subagent — the one thing on
  # that event a session must not be able to misreport about itself.
  defp track_usage(state, %{type: :usage, payload: %{"subagent_task_id" => _child}}), do: state

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
    case fold(state, focus) do
      {:ok, outcome} ->
        case archive(state, outcome.archived) do
          {:ok, entry} -> apply_compaction(state, outcome, entry, trigger)
          {:error, reason} -> refuse_compaction(state, reason)
        end

      {:error, reason} ->
        refuse_broken_compaction(state, reason)
    end
  end

  # `Compaction.compact/2` is documented not to fail, and this is the belt on top of that
  # contract rather than a substitute for it. This process is `restart: :temporary`, so a
  # raise anywhere on the compaction path is the whole session gone — and both `/compact`
  # and the automatic threshold reach it. A conversation shape compaction cannot fold
  # becomes the refusal that already exists: nothing dropped, the operator told.
  defp fold(state, focus) do
    Compaction.compact(state.messages,
      keep_recent_tokens: state.keep_recent_tokens,
      focus: focus,
      summarize: summariser(state)
    )
  rescue
    error -> {:error, Exception.message(error)}
  catch
    kind, reason -> {:error, {kind, reason}}
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

  defp refuse_broken_compaction(state, reason) do
    Logger.warning("native compaction refused: it failed (#{inspect(reason)})")

    announce_refusal(
      state,
      "compaction_failed",
      inspect(reason),
      "the conversation was not compacted because compaction itself failed. " <>
        "Nothing was dropped."
    )

    {:error, {:compaction_failed, reason}, state}
  end

  # One event shape for every refused compaction, whatever refused it. The `status` stays
  # `compaction_refused` — a client keys on that — and `cause` names which one it was,
  # because "a hook said no", "this node could not write the archive" and "compaction
  # itself failed" are different problems with different fixes.
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
    # Taken before anything moves: after `rebase/2` and the message swap there is no way
    # left to say what the conversation hashed to going in.
    pre_digest = Checkpoint.digest_of(state.messages, event_limit: state.checkpoint_limit)

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

    state = rebase(state, outcome)

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
    digest =
      case checkpoint(state) do
        {:ok, digest} -> digest
        {:error, _reason} -> nil
      end

    # R1. `elided_count` is how many tool results compaction rewrote in place — a count
    # rather than the per-call list REPLAY.md §3.2 asks for, because `Compaction.compact/2`
    # returns a count and nothing else knows which calls they were. It costs nothing that
    # matters: the elided *bytes* survive in this journal's own `tool_result` records, keyed
    # by `call_id`, which is the copy the in-place rewrite used to destroy. `post_digest` is
    # the folded conversation; `pre_digest` is what it hashed to going in.
    state =
      journal(state, "compaction", %{
        "turn_id" => "compact_" <> Integer.to_string(state.turns + 1),
        "trigger" => report.trigger,
        # The summariser's own `model_call`/`model_result` pair is written at top level
        # under this turn id rather than inlined here, so a replay engine feeds it back
        # through the same path as any other model call. An elide-only fold ran no
        # summariser and says so with `null` rather than a pointer to nothing.
        "summariser_turn_id" =>
          if(report.summarised, do: "compact_" <> Integer.to_string(state.turns + 1)),
        "elided_count" => outcome.elided,
        "archived_messages" => report.archived_messages,
        "archive_id" => report.archive_id,
        "summarised" => report.summarised,
        "pre_digest" => pre_digest,
        "post_digest" => digest
      })

    emit(state, %{
      type: :provider_event,
      payload: compaction_payload(report, outcome),
      turn_id: nil,
      request_id: nil
    })

    {:ok, state, report}
  end

  # Eliding tool results rewrites messages in place, so the conversation still lines up
  # with the manifest's counts.
  defp rebase(state, %{summarised: false}), do: state

  # Summarising does not: the new list is `[summary | recent]`, and the summary is not a
  # message this conversation ever had. A rewind's count therefore lands one slot further
  # along — which keeps the summary, as it must, since without it the tail has no
  # beginning — and no count inside the folded range can be honoured at all.
  defp rebase(state, outcome) do
    kept = length(outcome.messages) - 1
    floor = state.message_offset + length(state.messages) - kept

    %{state | message_offset: floor - 1, rewind_floor: floor}
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
  #
  # R1 §4.2 makes it a *gated* model call all the same: it spends tokens on the operator's
  # key, so it gets an `:inference` entry before the request leaves and a `model_call` /
  # `model_result` journal pair under its own `compact_N` turn id. Nothing here is
  # best-effort telemetry — a summariser nobody can account for is the same hole as an
  # unaccounted turn, and cheaper to close here than to explain later.
  defp summariser(state), do: summariser(state, "compact_" <> Integer.to_string(state.turns + 1))

  defp summariser(state, turn_id) do
    fn %{messages: messages, instruction: instruction} ->
      request = %{
        model: state.model_spec,
        system: instruction,
        messages: messages ++ [%{role: :user, content: instruction}],
        tools: [],
        provider_session_id: state.provider_session_id,
        turn_id: turn_id,
        reasoning_effort: nil,
        max_tokens: nil
      }

      case run_summariser(state, request, turn_id) do
        {:ok, text, _seq} -> {:ok, text}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Returns the `model_result` journal sequence alongside the text, so the `compaction`
  # record can point at the call that produced its summary. A pointer rather than an
  # inlined copy of the pair: the chunk list can be large, and a `model_result` record at
  # top level is one the replay engine feeds back through the same path as any other model
  # call rather than a special case buried inside a compaction record.
  defp run_summariser(state, request, turn_id) do
    prompt_sha256 = Journal.digest(Model.project(state.model_module, request))

    effect_id =
      Inference.new_effect_id({state.provider_session_id, turn_id, state.turns})

    attempt = %{
      session_id: state.context.session_id,
      turn_id: turn_id,
      iteration: 1,
      model: request.model,
      prompt_sha256: prompt_sha256
    }

    case Inference.gate(effect_id, attempt,
           principal: principal(state),
           cause: summariser_cause(turn_id)
         ) do
      :ok ->
        stream_summary(state, request, turn_id, effect_id, prompt_sha256)

      {:error, reason} ->
        {:error, {:inference_unrecordable, reason}}
    end
  end

  defp stream_summary(state, request, turn_id, effect_id, prompt_sha256) do
    _ =
      journal_direct(state, "model_call", %{
        "turn_id" => turn_id,
        "iteration" => 1,
        "request_sha256" => prompt_sha256,
        "system_sha256" => text_digest(request.system),
        "message_count" => length(request.messages),
        "tools_sha256" => Journal.digest([]),
        "ledger_effect_id" => effect_id
      })

    started = System.monotonic_time(:millisecond)

    case Model.stream(state.model_module, request, []) do
      {:ok, stream} ->
        {text, chunks, usage} = collect(stream)
        elapsed = System.monotonic_time(:millisecond) - started

        journal =
          journal_direct(state, "model_result", %{
            "turn_id" => turn_id,
            "iteration" => 1,
            "chunks" => chunks,
            "duration_ms" => elapsed
          })

        seq = journal && journal.seq
        Inference.settle(effect_id, :completed, elapsed, seq, usage)
        {:ok, text, seq}

      {:error, reason} ->
        Inference.settle(
          effect_id,
          Inference.status_of(reason),
          System.monotonic_time(:millisecond) - started,
          nil,
          %{}
        )

        {:error, reason}
    end
  end

  defp summariser_cause(_turn_id), do: "native.compaction.inference"

  # The whole stream, retained: the text the summary is, the chunks the journal records —
  # thinking included, which nothing durable held before R1 — and the provider's last usage
  # map for the ledger's token counts.
  defp collect(stream) do
    {text, chunks, usage} =
      Enum.reduce(stream, {[], [], %{}}, fn chunk, {text, chunks, usage} ->
        chunks = [Journal.jsonable(chunk) | chunks]

        case chunk do
          {:text, delta} when is_binary(delta) -> {[text, delta], chunks, usage}
          {:usage, next} when is_map(next) -> {text, chunks, next}
          _other -> {text, chunks, usage}
        end
      end)

    {IO.iodata_to_binary(text), Enum.reverse(chunks), usage}
  rescue
    _error -> {"", [], %{}}
  catch
    :exit, _reason -> {"", [], %{}}
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
         {:ok, _digest} <-
           Checkpoint.write(checkpoint_path, seeded, event_limit: state.checkpoint_limit),
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

    # Gated exactly like the compaction summariser, under its own turn id so the two are
    # never confused in the record. A handoff that could not be accounted for falls back to
    # the structural summary below, which spends nothing — the same answer it already gives
    # when the model call fails.
    summariser = summariser(state, "handoff_" <> Integer.to_string(state.turns + 1))

    case summariser.(%{messages: state.messages, focus: nil, instruction: instruction}) do
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

  # A depth this runtime did not set is 0 — a session an operator started. A nonsense
  # value is read as the cap rather than as 0, which fails closed: the worst a corrupt or
  # hand-written option can do is deny a session its `agent` tool, never grant one a level
  # of nesting it was not given.
  defp subagent_depth(options) do
    case Map.get(options, :subagent_depth) || Map.get(options, "subagent_depth") do
      depth when is_integer(depth) and depth >= 0 -> min(depth, AgentTool.max_depth())
      nil -> 0
      _nonsense -> AgentTool.max_depth()
    end
  end

  # Both key spellings, and never by minting an atom from a string: `provider_options`
  # arrives from a caller, and a lookup that creates atoms turns a request into a way to
  # grow this node's atom table.
  defp string_option(options, key) do
    Enum.find_value(options, fn {candidate, value} ->
      if to_string(candidate) == key and is_binary(value) and value != "", do: value
    end)
  end

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
