defmodule Ouroboros.Provider.Native.Loop do
  @moduledoc """
  One turn: model → tool calls → tool results → model, until the model stops.

  This is the piece Ouroboros did not have. It runs in its own process so the session
  GenServer stays answerable while a model is streaming and a tool is running, and it
  talks to that session through exactly two channels: an `emit` function for events, and
  its own mailbox for control.

      {:native_steer, text}                 injected as a user message at the next
                                            tool boundary of the running turn
      :native_interrupt                     stop after the current tool
      {:native_approval, id, response}      the answer to an `approval_requested`

  ## Why not `Jido.AI.Agent`

  `Jido.AI.Agent` is a complete agent server: its ReAct runtime owns the request
  lifecycle and, critically, **executes the tools itself**. Every capability this slice
  exists to deliver lives exactly at the boundary that runtime owns — blocking a tool on
  a human approval, injecting a steered message between two tools, stopping after the
  current tool on interrupt, refusing the third identical call. Reaching each of those
  through a strategy's internals would be a deeper coupling to `jido_ai` than driving
  the model directly, and it would put a second supervised process inside a session the
  harness already supervises.

  So the loop is here, and `jido_ai` is used for the one thing it does that we would
  otherwise duplicate: `Jido.AI.ToolAdapter` turns a `Jido.Action` schema into the JSON
  Schema a model sees (`Ouroboros.Provider.Native.Tools`). Models are reached through
  `Ouroboros.Provider.Native.Model`, whose ReqLLM implementation opens all thirty-odd
  ReqLLM providers.

  ## Bounds

  `max_iterations` (default 100) caps model round-trips per turn. The last round is
  reserved: tools are omitted so the model must answer rather than start more work.
  `max_iterations: 1` is therefore a single tool-free response. Dropping tools on that
  last call is a deliberate prefix-cache miss on the full-history request; the
  alternative is discovering the ceiling after a tool call that cannot be answered. If
  the model still emits tool calls, the turn fails by name and those unpaired calls are
  stripped from the checkpointed transcript so a resume remains well-formed. During the
  final ten calls the system prompt exposes the remaining budget, becoming urgent for
  the final three and naming the last round as tool-free. `tool_timeout_ms` caps one tool.
  The doom-loop guard stops a turn on the third identical `(name, input)` call — OpenCode's
  rule, and the cheapest defence against a model that has found a loop it likes. Each
  bound fails the turn by name rather than running out quietly.

  ## The ledger (I1)

  Every tool this loop is admitted to run gets one `:tool_call` entry in
  `Ouroboros.Agent.EffectLedger`, checkpointed **before the tool runs** and settled after
  with its status, duration, and output size. This is the same hard gate `workspace.exec`
  makes for the one command an operator typed: **a ledger that cannot record the call
  refuses it**, and the model is told so in a tool result it can read. A tool call nobody
  can account for afterwards is exactly what the entry exists to prevent, so "best effort
  telemetry" is not an option here.

  The entry names identities and never contents: the tool, the call id, the session and
  turn, the permission decision that admitted it, and a `subject` — the paths a file tool
  would touch, a SHA-256 digest of a `bash` command line, the host `web_fetch` would
  reach, the server and tool behind an `mcp__server__tool` name.

  Every dispatch that reached the gate writes exactly one entry, whichever way the gate
  answered: admitted calls open `:started`, refusals (a rule, a hook, an unanswered
  deadline, an interrupt while the question was on screen) are written terminal as
  `:denied`. That is what lets the `tool_call` event carry its `ledger_ref` before the
  answer is known — the reference names an entry that will exist on every path but one,
  and that one is the ledger being unreachable, which is also the one case where the tool
  is refused and says why.

  A tool the session does not have is not gated, does not run, and gets no entry; its
  `tool_call` event carries no `ledger_ref`, which is the honest way to say that nothing
  was admitted.

  ### The subagent link (G3)

  A child session's tool calls are its own entries, under the child's `provider_session_id`
  and its own turn id — but under the **parent's** `session_id` and principal, because the
  child is opened with the parent's harness context and belongs to the parent's interactive
  session. The provider-session link rides in `authority.constraints` as `subagent_parent`
  and `subagent_task_id`, and the cause is `native.subagent.tool_call` rather than
  `native.tool_call`, so a reader can ask "everything a subagent of this session did"
  without parsing anything. It is in `constraints` rather than in `attempt.subject` for one
  structural reason: `Ouroboros.Agent.EffectLedger`'s subject vocabulary is a closed
  whitelist and this module does not own that file.

  ## Subagents (G3)

  `agent` is the second tool this loop answers itself rather than in the tool task, and
  for the same reason `ask_user` is: it has to block on things only this process can
  reach. A foreground child's approvals are put on **this session's** approval channel
  with a fresh parent request id, and the answer is handed back to the child by the id
  the child minted — two id spaces, one person. See
  `Ouroboros.Provider.Native.Subagent` for the lifecycle and every bound.
  """

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Context.Instructions
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.CodeIntel
  alias Ouroboros.Provider.Native.Cost
  alias Ouroboros.Provider.Native.Desktop

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Permissions
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool
  alias Ouroboros.Provider.Native.Tools.AgentResult
  alias Ouroboros.Provider.Native.Tools.AskUser

  @default_max_iterations 100
  @default_tool_timeout_ms 120_000
  @doom_loop_repeats 3
  @iteration_warning_at 10
  @iteration_urgent_at 3
  @max_injected_context_bytes 8 * 1024
  # How much of a sandboxed attempt's own output the escalation event carries. Enough to
  # read the denial and what led to it; not the whole spill file, which the tool result
  # already names a path for.
  @max_escalation_output_bytes 4 * 1024

  defstruct [
    :emit,
    :model_module,
    :model_spec,
    :system,
    :scope,
    :session_dir,
    :session_id,
    :provider_session_id,
    :turn_id,
    :reasoning_effort,
    :approval_mode,
    :allowed_tools,
    :disallowed_tools,
    # The tool definitions exactly as `Ouroboros.Provider.Native.Context` laid them out,
    # so the prefix the fingerprint describes is the prefix the model is sent. `nil`
    # falls back to deriving them here, which is what the coding plane and the older
    # tests do.
    # The model's context window, for the meter merged into every `usage` event. `nil`
    # means this node could not resolve one, and the meter says so by omitting the key
    # rather than by inventing a denominator.
    :context_window,
    # The `.agents/rules` held back for lazy loading, and the ones already injected. A
    # rule enters the conversation once per session, however many matching files are
    # read after it.
    rules: [],
    rules_loaded: [],
    # Called with `%{messages:, reads:, session_grants:}` immediately *before* the
    # terminal turn event is emitted. The session makes the conversation durable inside
    # this callback, which is what makes "checkpoint before broadcast" true here rather
    # than aspirational: the emit that follows cannot outrun a write that already
    # returned. The coding plane passes a no-op — a finite run has nothing to resume.
    checkpoint: nil,
    # `Ouroboros.Provider.Native.Hooks` configuration, loaded once at the start of the
    # turn. Loading it per tool call would read and parse `ouroboros.toml` on every
    # dispatch, and would let a hook edit its own configuration mid-turn.
    hooks: nil,
    # Injected 3-arity helper (`method, params, timeout`) for Computer Use. Production
    # leaves this nil and `Desktop` uses the pool; tests stub a failing or canned act
    # without starting the live helper.
    desktop_runner: nil,
    # The tool schemas, built once at the start of the turn. Two reasons, and the second
    # is the important one: building thirteen JSON Schemas per model call is measurable,
    # and a tool list that could change between two calls of one turn is a changed cached
    # prefix — the documented cause of slow, expensive turns (R3 §8d). `skill`'s
    # description reads the workspace, so without this a file appearing under
    # `.agents/skills/` mid-turn would silently invalidate the cache.
    tool_specs: nil,
    # G3. What this session needs in order to be somebody's parent. `session_pid` is the
    # transport GenServer, which is the only thing that outlives a turn and can therefore
    # hold a background child; `session_request` and `session_context` are what a child's
    # own `Session.open/2` is built from, so a child inherits its parent's posture by
    # construction rather than by a list of fields somebody remembered to copy.
    # `subagent_depth` is this session's own depth — 0 for one an operator started — and
    # `subagent_parent`/`subagent_task_id` are set only on a child, which is what makes a
    # child's ledger entries say whose they are.
    session_pid: nil,
    session_request: nil,
    session_context: nil,
    subagent_depth: 0,
    subagent_parent: nil,
    subagent_task_id: nil,
    messages: [],
    # How many messages this session had before `messages` begins. A resumed session holds
    # only the tail its checkpoint kept, and the turn manifest counts from the start of the
    # conversation, so a turn record that wrote `length(messages)` would name a boundary
    # `rewind` cannot find. See `Ouroboros.Provider.Native.Checkpoint.load/1`.
    message_offset: 0,
    reads: %{},
    session_grants: MapSet.new(),
    signatures: %{},
    interrupted?: false,
    steer: [],
    # The turn's file checkpoint, accumulated as tools run: `path => %{before:, after:}`
    # with `turn_paths` preserving the order they were first touched. Written to the
    # manifest at the terminal, so a crash mid-turn loses the manifest entry and not the
    # blobs — the direction that costs a rewind menu row rather than a file.
    turn_files: %{},
    turn_paths: [],
    turn_commands: [],
    usage: %{input: 0, output: 0, cost: 0.0},
    max_iterations: @default_max_iterations,
    tool_timeout_ms: @default_tool_timeout_ms,
    approval_timeout_ms: :infinity
  ]

  @type t :: %__MODULE__{}

  @doc """
  Runs one turn to completion in the calling process.

  Returns the loop state — the caller keeps `messages`, `reads`, and `session_grants`
  for the next turn — plus the terminal event that was already emitted.
  """
  @spec run_turn(t(), String.t() | map()) :: {:ok, t()}
  def run_turn(%__MODULE__{} = state, prompt) when is_binary(prompt),
    do: run_turn(state, %{role: :user, content: prompt})

  def run_turn(%__MODULE__{} = state, %{role: :user} = user_message) do
    state = %{
      state
      | hooks: state.hooks || Hooks.load(state.scope.root),
        tool_specs: build_tool_specs(state),
        turn_files: %{},
        turn_paths: [],
        turn_commands: []
    }

    injected = injected(Hooks.notify(state.hooks, :user_prompt_submit, hook_base(state)))
    user_message = append_user_text(user_message, injected)
    state = %{state | messages: state.messages ++ [user_message]}

    emit(state, :turn_started, %{
      "model" => state.model_spec,
      "tools" => Enum.map(tool_specs(state), & &1.name),
      "approval_mode" => Atom.to_string(state.approval_mode),
      "sandbox_mode" => Atom.to_string(state.scope.sandbox_mode),
      "hooks" => length(state.hooks.hooks),
      "workspace_trusted" => state.hooks.trusted?
    })

    _ = report_hook_errors(state)

    iterate(state, 1)
  end

  # A repository whose `ouroboros.toml` does not parse, or one whose hooks were declined
  # for want of trust, says so once per turn. Silence there would be the worst of both:
  # the operator believes their hooks ran and nothing did.
  defp report_hook_errors(%{hooks: %{errors: [], declined: 0}}), do: :ok

  defp report_hook_errors(state) do
    declined =
      if state.hooks.declined > 0,
        do: [
          "#{state.hooks.declined} hook(s)/check(s) in #{Path.join(state.scope.root, "ouroboros.toml")} " <>
            "were not loaded: this workspace is not trusted. An operator can trust it by " <>
            "adding its canonical root to `config :ouroboros, :trusted_workspaces`."
        ],
        else: []

    emit(state, :provider_event, %{
      "kind" => "status",
      "message" => Enum.join(declined ++ state.hooks.errors, "\n")
    })
  end

  defp iterate(state, iteration) when iteration > state.max_iterations do
    fail(
      state,
      "reached max_iterations (#{state.max_iterations}) without finishing the turn",
      "max_iterations"
    )
  end

  defp iterate(state, iteration) do
    state = drain_control(state)

    cond do
      state.interrupted? ->
        interrupted(state)

      true ->
        case call_model(state, iteration) do
          {:ok, state, text, calls, reasoning_details, provider_metadata} ->
            state = drain_control(state)

            if state.interrupted? do
              interrupted(state)
            else
              state =
                append_assistant(state, text, calls, reasoning_details, provider_metadata)

              cond do
                calls == [] ->
                  complete(state, iteration)

                iteration >= state.max_iterations ->
                  fail(
                    drop_unpaired_tool_calls(state),
                    "reached max_iterations (#{state.max_iterations}); the model attempted " <>
                      "another tool call during the reserved tool-free final response",
                    "max_iterations"
                  )

                true ->
                  case run_tools(state, calls) do
                    {:continue, state} -> iterate(apply_steer(state), iteration + 1)
                    {:interrupted, state} -> interrupted(state)
                    {:failed, state, message, reason} -> fail(state, message, reason)
                  end
              end
            end

          {:error, state, reason} ->
            fail(state, "model call failed: #{describe(reason)}", "model_error")
        end
    end
  end

  # ---------------------------------------------------------------- model

  defp call_model(state, iteration) do
    request = %{
      model: state.model_spec,
      system: iteration_system(state.system, iteration, state.max_iterations),
      messages: state.messages,
      tools: iteration_tools(state, iteration),
      provider_session_id: state.provider_session_id,
      turn_id: state.turn_id,
      reasoning_effort: state.reasoning_effort,
      max_tokens: nil
    }

    case Model.stream(state.model_module, request, []) do
      {:ok, stream} -> consume(state, stream)
      {:error, reason} -> {:error, state, reason}
    end
  end

  defp iteration_system(system, iteration, max_iterations) when is_binary(system) do
    remaining = max_iterations - iteration + 1

    if remaining <= @iteration_warning_at do
      urgency =
        cond do
          remaining == 1 ->
            " This is the reserved final response round. No tools are available. Return " <>
              "the best honest final answer now and state anything unverified explicitly."

          remaining <= @iteration_urgent_at ->
            " Do not begin optional work. Complete required validation now and return an " <>
              "honest final answer before the limit; state anything unverified explicitly."

          true ->
            " Prioritize the work required to validate the result and finish the turn."
        end

      system <>
        "\n\n## Turn budget\n" <>
        "#{remaining} model round-trip(s) remain in this turn, including this one." <>
        urgency
    else
      system
    end
  end

  defp iteration_system(system, _iteration, _max_iterations), do: system

  defp iteration_tools(_state, iteration) when iteration < 1, do: []

  defp iteration_tools(state, iteration) do
    if iteration >= state.max_iterations, do: [], else: tool_specs(state)
  end

  defp consume(state, stream) do
    {text, calls, usages, reasoning_details, provider_metadata} =
      Enum.reduce(stream, {[], [], [], [], %{}}, fn chunk,
                                                    {text, calls, usages, details, metadata} ->
        case chunk do
          {:text, delta} when is_binary(delta) and delta != "" ->
            emit(state, :output_text_delta, %{"text" => delta})
            {[text, delta], calls, usages, details, metadata}

          {:thinking, delta} when is_binary(delta) and delta != "" ->
            emit(state, :thinking_delta, %{"text" => delta})
            {text, calls, usages, details, metadata}

          {:tool_call, call} ->
            {text, calls ++ [call], usages, details, metadata}

          {:reasoning_details, next} when is_list(next) ->
            {text, calls, usages, next, metadata}

          {:provider_metadata, next} when is_map(next) ->
            {text, calls, usages, details, Map.merge(metadata, next)}

          {:usage, usage} ->
            {text, calls, usages ++ [usage], details, metadata}

          _ignored ->
            {text, calls, usages, details, metadata}
        end
      end)

    final = IO.iodata_to_binary(text)
    if final != "", do: emit(state, :output_text_final, %{"text" => final})

    state = Enum.reduce(usages, state, &record_usage(&2, &1))
    {:ok, state, final, calls, reasoning_details, provider_metadata}
  rescue
    error -> {:error, state, {:stream_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, state, {:stream_exited, inspect(reason)}}
  end

  # The meter rides on `usage` because that is the event a client already subscribes to
  # and `context_window` is the key the TUI footer decodes. `context_used` is the size of
  # *this* request, not the session's running total: the two diverge the moment anything
  # is compacted, and it is the request size that decides whether the next one fits.
  defp record_usage(state, usage) do
    payload =
      usage
      |> Cost.payload(state.model_spec)
      |> Window.meter(state.context_window)

    emit(state, :usage, payload)

    %{
      state
      | usage: %{
          input: state.usage.input + Map.get(payload, "input_tokens", 0),
          output: state.usage.output + Map.get(payload, "output_tokens", 0),
          cost: state.usage.cost + Map.get(payload, "cost_usd", 0.0)
        }
    }
  end

  defp append_assistant(state, "", [], [], metadata) when metadata == %{}, do: state

  defp append_assistant(state, text, calls, reasoning_details, provider_metadata) do
    message =
      %{
        role: :assistant,
        content: text,
        tool_calls: calls
      }
      |> put_nonempty(:reasoning_details, reasoning_details)
      |> put_nonempty(:provider_metadata, provider_metadata)

    %{state | messages: state.messages ++ [message]}
  end

  # The reserved final round already appended the assistant message, including any tool
  # calls the model emitted despite an empty tool list. Those calls will not run, and a
  # checkpoint that kept them would resume as an assistant `tool_calls` turn with no
  # matching tool results. Strip the unpaired calls; drop the message if nothing else
  # remains to persist.
  defp drop_unpaired_tool_calls(%{messages: messages} = state) do
    case Enum.split(messages, -1) do
      {prefix, [%{role: :assistant, tool_calls: [_ | _]} = message]} ->
        stripped = %{message | tool_calls: []}

        %{
          state
          | messages: if(keep_assistant?(stripped), do: prefix ++ [stripped], else: prefix)
        }

      _other ->
        state
    end
  end

  defp keep_assistant?(%{content: content} = message) do
    content not in [nil, ""] or (message[:reasoning_details] || []) != [] or
      map_size(message[:provider_metadata] || %{}) > 0
  end

  defp keep_assistant?(_message), do: false

  # ---------------------------------------------------------------- tools

  defp run_tools(state, calls) do
    Enum.reduce_while(calls, {:continue, state}, fn call, {:continue, state} ->
      case run_tool(state, call) do
        {:continue, state} ->
          # Interrupt is honoured *after* the tool that was already running, never in
          # the middle of it: a half-applied edit is worse than one extra tool call.
          state = drain_control(state)

          if state.interrupted?,
            do: {:halt, {:interrupted, state}},
            else: {:cont, {:continue, state}}

        other ->
          {:halt, other}
      end
    end)
  end

  defp run_tool(state, call) do
    signature = signature(call)
    seen = Map.get(state.signatures, signature, 0)

    if seen + 1 >= @doom_loop_repeats do
      {:failed, state,
       "doom loop: `#{call.name}` was called #{seen + 1} times with identical arguments. " <>
         "Stopping the turn rather than repeating it.", "doom_loop"}
    else
      state = %{state | signatures: Map.put(state.signatures, signature, seen + 1)}
      dispatch(state, call)
    end
  end

  # The lookup is first so a tool this session does not have never claims a ledger
  # reference it will not have an entry for. Everything past it is gated, and everything
  # gated is recorded.
  defp dispatch(state, call) do
    case Tools.lookup(call.name, state.allowed_tools, state.disallowed_tools) do
      {:error, :unknown_tool} ->
        emit_tool_call(state, call, nil)
        {:continue, tool_result(state, call, unknown_tool(call.name, state))}

      {:ok, module} ->
        if depth_capped?(state, module) do
          # G3. The schema list a session at the cap was shown has no `agent` in it, so a
          # call is an invention. It is refused by name rather than as "unknown tool",
          # because the truthful answer — the cap — is the one the model can act on.
          emit_tool_call(state, call, nil)

          {:continue,
           tool_result(state, call, %{
             output: AgentTool.depth_refusal(state.subagent_depth),
             is_error: true
           })}
        else
          case Tools.validate_call(call.name, call.input, tool_specs(state)) do
            {:ok, input} ->
              call = %{call | input: input}

              # Classified once, here, and handed to the gate: re-deriving it would run
              # `code_intel`'s rename preview a second time for nothing.
              classified =
                call.name
                |> Tools.classify(call.input, state.scope)
                |> Desktop.enrich_classified(state.session_dir)

              effect_id = tool_effect_id(state, call)
              emit_tool_call(state, call, effect_id)

              gated(state, call, module, classified, effect_id)

            {:error, message} ->
              # Invalid calls have no effect to admit or record. They remain paired tool
              # call/results so the model can repair its arguments on the next iteration.
              emit_tool_call(state, call, nil)

              attempts = Map.get(state.signatures, signature(call), 1)
              message = invalid_call_message(message, attempts)
              {:continue, tool_result(state, call, %{output: message, is_error: true})}
          end
        end
    end
  end

  defp depth_capped?(state, module) when module in [AgentTool, AgentResult],
    do: is_integer(state.subagent_depth) and state.subagent_depth >= AgentTool.max_depth()

  defp depth_capped?(_state, _module), do: false

  defp gated(state, call, module, classified, effect_id) do
    case gate(state, call, classified) do
      {:allow, state, call, classified, hook_context, authority} ->
        case confirm_desktop_act(state, call, classified, hook_context, authority) do
          {:allow, state, call, classified, hook_context, authority} ->
            admit_and_run(state, call, module, classified, hook_context, authority, effect_id)

          {:deny, state, message, classified, authority} ->
            refuse_tool_effect(state, call, classified, effect_id, authority)
            {:continue, tool_result(state, call, %{output: message, is_error: true})}

          {:interrupted, state, classified} ->
            refuse_tool_effect(state, call, classified, effect_id, interrupted_authority())
            {:interrupted, state}

          {:error, message} ->
            refuse_tool_effect(
              state,
              call,
              classified,
              effect_id,
              authority(:deny, "runtime", :once, :runtime, {:desktop, :unresolved}, nil)
            )

            {:continue, tool_result(state, call, %{output: message, is_error: true})}
        end

      {:deny, state, message, classified, authority} ->
        refuse_tool_effect(state, call, classified, effect_id, authority)
        {:continue, tool_result(state, call, %{output: message, is_error: true})}

      {:interrupted, state, classified} ->
        refuse_tool_effect(state, call, classified, effect_id, interrupted_authority())
        {:interrupted, state}
    end
  end

  defp admit_and_run(state, call, module, classified, hook_context, authority, effect_id) do
    case open_tool_effect(state, call, classified, effect_id, authority) do
      :ok ->
        cond do
          module == AgentTool ->
            run_subagent(state, call, hook_context, effect_id)

          Tools.interactive?(module) ->
            ask_question(state, call, hook_context, effect_id)

          true ->
            execute(state, call, module, classified, hook_context, effect_id)
        end

      {:error, reason} ->
        {:continue, tool_result(state, call, unrecordable(call, reason))}
    end
  end

  # §6.3: if the last state (or a focus retarget) resolved a different app than the one
  # first evaluated, evaluate again. Never inject first. Sensitive acts still ask once.
  defp confirm_desktop_act(state, call, classified, hook_context, authority) do
    if classified.tool != "desktop_act" do
      {:allow, state, call, classified, hook_context, authority}
    else
      claimed = classified.context[:app]

      case Desktop.resolve_act(call.input, state.session_dir) do
        {:error, message} ->
          {:error, message}

        {:ok, resolved} ->
          classified = put_in(classified.context[:app], resolved)

          allowed =
            if claimed != nil and Desktop.same_app?(claimed, resolved) do
              {:allow, state, call, classified, hook_context, authority}
            else
              reevaluate_desktop(state, call, classified, hook_context)
            end

          case allowed do
            {:allow, state, call, classified, hook_context, authority} ->
              maybe_ask_sensitive(state, call, classified, hook_context, authority)

            other ->
              other
          end
      end
    end
  end

  defp reevaluate_desktop(state, call, classified, hook_context) do
    case Permissions.evaluate(permission_request(state, classified)) do
      {:allow, rule} ->
        {:allow, state, call, classified, hook_context,
         authority(
           :allow,
           "rule",
           :once,
           :rule,
           rule,
           record(state, :approve, :once, :rule, rule)
         )}

      {:deny, rule} ->
        {:deny, state, Permissions.deny_message(call.name, rule), classified,
         authority(:deny, "rule", :once, :rule, rule, record(state, :deny, :once, :rule, rule))}

      {:ask, reason} ->
        ask(state, call, classified, reason, hook_context)
    end
  end

  defp maybe_ask_sensitive(state, call, classified, hook_context, authority) do
    if Desktop.sensitive_act?(call.input, state.session_dir) do
      ask(state, call, classified, :sensitive_desktop_act, hook_context)
    else
      {:allow, state, call, classified, hook_context, authority}
    end
  end

  defp execute(state, call, module, classified, hook_context, effect_id) do
    context =
      %{
        scope: state.scope,
        session_dir: state.session_dir,
        reads: state.reads,
        # G3. `agent_result` collects a child the *session* holds, not one this turn owns,
        # so it is handed two closures over the session rather than a pid to call: the tool
        # never learns which process tracks what, and a run with no session gets `nil` and
        # says so instead of failing obscurely.
        subagents: subagent_handles(state),
        desktop_evaluated_app: classified.context[:app]
      }
      |> maybe_desktop_runner(state)

    # Checkpoint before write, always, and before the language server is asked anything:
    # the baseline is a convenience and the snapshot is the thing a rewind depends on.
    state = snapshot_before(state, classified.write_paths)
    baselines = CodeIntel.baseline(classified.write_paths, root: state.scope.root)

    started = System.monotonic_time(:millisecond)
    result = Tools.execute(module, call.input, context, execute_timeout(state, classified))
    elapsed = System.monotonic_time(:millisecond) - started

    state =
      if classified.tool == "desktop_act", do: flush_interrupt(state), else: state

    if state.interrupted? do
      settle_tool_effect(state, effect_id, %{output: "interrupted", is_error: true}, elapsed)
      {:interrupted, state}
    else
      finish_execute(
        state,
        call,
        module,
        classified,
        hook_context,
        effect_id,
        result,
        elapsed,
        context,
        baselines
      )
    end
  end

  defp finish_execute(
         state,
         call,
         module,
         classified,
         hook_context,
         effect_id,
         result,
         elapsed,
         context,
         baselines
       ) do
    {state, result, elapsed} =
      escalate(state, %{
        call: call,
        module: module,
        classified: classified,
        context: context,
        result: result,
        elapsed: elapsed
      })

    settle_tool_effect(state, effect_id, result, elapsed)

    state = %{state | reads: Map.merge(state.reads, Map.get(result, :reads, %{}))}

    changes = Map.get(result, :changes, [])
    changed = Enum.flat_map(changes, fn change -> List.wrap(change["path"]) end)
    state = snapshot_after(state, changed)
    state = record_command(state, classified)

    result = append_diagnostics(result, changed, baselines, root: state.scope.root)

    result =
      append_context(
        result,
        Hooks.post_tool_use(
          state.hooks,
          classified.tool,
          redact_desktop_input(classified.tool, call.input),
          %{"output" => result.output, "is_error" => result.is_error},
          hook_base(state)
        ) ++ hook_context
      )

    state = tool_result(state, call, result)
    state = emit_changes(state, changes)
    state = emit_plan(state, Map.get(result, :plan))
    state = inject_rules(state, Map.get(result, :reads, %{}))

    {:continue, state}
  end

  defp execute_timeout(state, %{tool: "desktop_act"}),
    do: max(state.tool_timeout_ms, Desktop.config(:act_timeout_ms))

  defp execute_timeout(state, _classified), do: state.tool_timeout_ms

  defp maybe_desktop_runner(context, %{desktop_runner: fun}) when is_function(fun, 3),
    do: Map.put(context, :desktop_runner, fun)

  defp maybe_desktop_runner(context, _state), do: context

  defp flush_interrupt(state) do
    receive do
      :native_interrupt -> %{state | interrupted?: true}
    after
      0 -> state
    end
  end

  # D3's lazy half. A `.agents/rules/*.md` whose front-matter `paths:` matches the file
  # this tool just touched is appended to the *conversation*, once, right after the tool
  # result that earned it — never to the system prompt, because a prefix that changed
  # when a file was read would cost a cache miss on every turn after it.
  defp inject_rules(%{rules: rules} = state, reads)
       when is_list(rules) and rules != [] and map_size(reads) > 0 do
    Enum.reduce(Map.keys(reads), state, fn path, state ->
      pending = Enum.reject(rules, &(&1.path in state.rules_loaded))

      case Instructions.render_for_path(pending, path, state.scope.root) do
        {:ok, nil} ->
          state

        {:ok, text} ->
          loaded =
            pending
            |> Enum.filter(&Instructions.matches?(&1, path, state.scope.root))
            |> Enum.map(& &1.path)

          %{
            state
            | messages: state.messages ++ [%{role: :user, content: text}],
              rules_loaded: state.rules_loaded ++ loaded
          }

        # A rule that would forge a runtime delimiter is dropped rather than injected, and
        # marked loaded so the same file is not retried on every read of every path it
        # matches. The session goes on without it; the refusal is the rule's own fault and
        # not a reason to fail the operator's turn mid-tool.
        {:error, _reason} ->
          %{state | rules_loaded: state.rules_loaded ++ Enum.map(pending, & &1.path)}
      end
    end)
  end

  defp inject_rules(state, _reads), do: state
  # The diagnostics report is appended only to a successful write. A failed edit has no
  # new state to describe, and appending anything after a failure is how a model comes to
  # read diagnostics as the failure itself (OpenCode #9102).
  defp append_diagnostics(%{is_error: true} = result, _changed, _baselines, _opts), do: result
  defp append_diagnostics(result, [], _baselines, _opts), do: result

  defp append_diagnostics(result, changed, baselines, opts) do
    case CodeIntel.feedback(changed, baselines, opts) do
      "" -> result
      feedback -> %{result | output: result.output <> "\n" <> feedback}
    end
  end

  defp append_context(result, []), do: result

  defp append_context(result, lines) do
    %{result | output: result.output <> injected(lines)}
  end

  defp emit_changes(state, []), do: state

  defp emit_changes(state, changes) do
    emit(state, :file_change, %{"changes" => changes, "status" => "completed"})

    _ =
      Hooks.notify(
        state.hooks,
        :file_changed,
        Map.put(hook_base(state), "paths", Enum.flat_map(changes, &List.wrap(&1["path"])))
      )

    state
  end

  # ---------------------------------------------------------------- checkpoint

  defp snapshot_before(state, []), do: state

  defp snapshot_before(state, paths) do
    Enum.reduce(paths, state, fn path, state ->
      if Map.has_key?(state.turn_files, path) do
        state
      else
        {:ok, before} = Checkpoint.snapshot(state.session_dir, path)

        %{
          state
          | turn_files: Map.put(state.turn_files, path, %{before: before, after: nil}),
            turn_paths: state.turn_paths ++ [path]
        }
      end
    end)
  end

  # A path a tool changed but never declared — the second file of a rename the classifier
  # could not preview, say — is snapshotted after the fact. Its `before` is then the file
  # as it stands, which is *not* restorable, so it is recorded as unsnapshotted rather
  # than as a checkpoint that would restore the wrong bytes.
  defp snapshot_after(state, changed) do
    Enum.reduce(changed, state, fn path, state ->
      {:ok, digest} = Checkpoint.snapshot(state.session_dir, path)

      case Map.fetch(state.turn_files, path) do
        {:ok, entry} ->
          %{state | turn_files: Map.put(state.turn_files, path, %{entry | after: digest})}

        :error ->
          %{
            state
            | turn_files:
                Map.put(state.turn_files, path, %{
                  before: {:unsnapshotted, :not_declared_before_the_write},
                  after: digest
                }),
              turn_paths: state.turn_paths ++ [path]
          }
      end
    end)
  end

  defp record_command(state, %{command: command}) when is_binary(command),
    do: %{state | turn_commands: Enum.take(state.turn_commands ++ [command], 50)}

  defp record_command(state, _classified), do: state

  defp emit_plan(state, nil), do: state

  defp emit_plan(state, plan) do
    emit(state, :plan_updated, plan)
    state
  end

  defp tool_result(state, call, result) do
    images = Map.get(result, :images, [])

    emit(state, :tool_result, tool_result_event(call, result, images))

    %{
      state
      | messages:
          state.messages ++
            [
              %{
                role: :tool,
                tool_call_id: call.id,
                name: call.name,
                content: tool_result_content(result.output, images),
                is_error: result.is_error
              }
            ]
    }
  end

  # A tool result carrying staged images (`desktop_state`, §8.2) becomes a multimodal tool
  # message: the text output plus one `:image` part per screenshot, which `Model.ReqLLM`
  # encodes for a vision model and degrades to a marker otherwise. A tool with no images
  # keeps the plain string content, so the cached prefix for every existing tool is
  # byte-for-byte unchanged.
  defp tool_result_content(output, []), do: output

  defp tool_result_content(output, images),
    do: [%{type: :text, text: output} | Enum.map(images, &Map.put(&1, :type, :image))]

  # Clients never receive pixels on the event — they get the sha to fetch through
  # `computer_use.artifact` (§8.5). `bytes` is the staged size; width/height are bounded,
  # advisory capture metadata that lets a client reserve layout before the fetch.
  defp tool_result_event(call, result, []) do
    %{
      "name" => call.name,
      "call_id" => call.id,
      "output" => result.output,
      "is_error" => result.is_error
    }
  end

  defp tool_result_event(call, result, images) do
    artifacts =
      Enum.map(images, fn image ->
        %{
          "kind" => "image",
          "sha256" => image.sha256,
          "media_type" => image.media_type,
          "bytes" => image.size
        }
        |> put_nonempty("width", Map.get(image, :width))
        |> put_nonempty("height", Map.get(image, :height))
      end)

    call
    |> tool_result_event(result, [])
    |> Map.put("artifacts", artifacts)
  end

  defp unknown_tool(name, state) do
    available = state |> tool_specs() |> Enum.map_join(", ", & &1.name)

    %{
      output: "`#{name}` is not a tool in this session. Available: #{available}.",
      is_error: true
    }
  end

  # ---------------------------------------------------------------- approvals

  # Every tool is put to the engine, including `read`. The order is engine, then the
  # `PreToolUse` hooks, then the session's own grants, then the mode, then a human. A
  # rule that says deny is never softened by `auto_approve`: a mode decides what happens
  # when no rule decided, it is not a way past one.
  #
  # Hooks run **after** the engine and only when the engine did not deny, which is what
  # makes "a hook may deny what a rule allowed, never allow what a rule denied" true by
  # construction rather than by convention: on a denial no hook is invoked at all.
  # `updatedInput` is put back through the engine before it is used, so a hook cannot
  # launder a denied command through a rewrite.
  #
  # The gate also carries the *authority* out with its answer — which decision admitted or
  # refused the call, at what scope, by whom, and the id of the `:permission` entry that
  # recorded it. That is what the `:tool_call` ledger entry is written against, and it is
  # threaded rather than re-derived because only the branch that decided knows.
  defp gate(state, call, classified) do
    case Permissions.evaluate(permission_request(state, classified)) do
      {:allow, rule} ->
        authority =
          authority(
            :allow,
            "rule",
            :once,
            :rule,
            rule,
            record(state, :approve, :once, :rule, rule)
          )

        hooked(state, call, classified, :allow, nil, authority)

      {:deny, rule} ->
        {:deny, state, Permissions.deny_message(call.name, rule), classified,
         authority(:deny, "rule", :once, :rule, rule, record(state, :deny, :once, :rule, rule))}

      {:ask, reason} ->
        hooked(state, call, classified, :ask, reason, nil)
    end
  end

  defp hooked(state, call, classified, verdict, reason, authority) do
    if Hooks.any?(state.hooks, :pre_tool_use, classified.tool) do
      case Hooks.pre_tool_use(
             state.hooks,
             classified.tool,
             redact_desktop_input(classified.tool, call.input),
             hook_base(state)
           ) do
        {:deny, hook_reason} ->
          ref = {:hook, :pre_tool_use}

          {:deny, state,
           "Refused: a PreToolUse hook denied this #{classified.tool} call: " <> hook_reason,
           classified,
           authority(:deny, "hook", :once, :rule, ref, record(state, :deny, :once, :rule, ref))}

        # A hook's `ask` outranks the *mode*, not just the rule: `auto_approve` swallowing
        # it would make the decision meaningless in the mode people actually run.
        {:ask, hook_reason, input, context, rewritten?} ->
          revise(
            state,
            call,
            classified,
            input,
            rewritten?,
            :ask_human,
            hook_reason,
            context,
            authority
          )

        # A hook that said `allow` resolves an engine `ask`. It can, because it is either
        # the operator's own user-scope hook or a repository hook the operator trusted —
        # the same two authorities a rule answers to. It can never resolve a `deny`,
        # because on a denial no hook was invoked at all.
        {:allow, input, context, rewritten?} ->
          revise(
            state,
            call,
            classified,
            input,
            rewritten?,
            :allow,
            reason,
            context,
            hook_allowed(authority)
          )

        # Silence is not consent. A hook that only annotated or rewrote leaves the
        # engine's verdict exactly where it was.
        {:none, input, context, rewritten?} ->
          revise(
            state,
            call,
            classified,
            input,
            rewritten?,
            verdict,
            reason,
            context,
            authority
          )
      end
    else
      proceed(state, call, classified, verdict, reason, [], authority)
    end
  end

  # A hook that rewrote the input hands back a different call, so the engine sees the
  # call that will actually run and not the one the model proposed.
  defp revise(
         state,
         call,
         classified,
         input,
         rewritten?,
         verdict,
         reason,
         context,
         authority
       ) do
    if not rewritten? or input == call.input do
      # Unchanged arguments keep the classification already computed: re-deriving it
      # would run `code_intel`'s rename preview a second time for nothing.
      proceed(state, call, classified, verdict, reason, context, authority)
    else
      call = %{call | input: input}

      classified =
        call.name
        |> Tools.classify(input, state.scope)
        |> Desktop.enrich_classified(state.session_dir)

      case Permissions.evaluate(permission_request(state, classified)) do
        {:deny, rule} ->
          {:deny, state,
           "Refused: a PreToolUse hook rewrote this call's arguments and " <>
             Permissions.deny_message(call.name, rule), classified,
           authority(:deny, "rule", :once, :rule, rule, record(state, :deny, :once, :rule, rule))}

        {:allow, _rule} ->
          proceed(state, call, classified, verdict, reason, context, authority)

        {:ask, engine_reason} ->
          proceed(
            state,
            call,
            classified,
            narrow(verdict),
            reason || engine_reason,
            context,
            authority
          )
      end
    end
  end

  # A re-evaluated call that the engine now only allows conditionally cannot keep a
  # verdict of `allow` it earned before the rewrite.
  defp narrow(:ask_human), do: :ask_human
  defp narrow(_allow_or_ask), do: :ask

  defp proceed(state, call, classified, :allow, _reason, context, authority),
    do: {:allow, state, call, classified, context, authority}

  defp proceed(state, call, classified, :ask_human, reason, context, _authority),
    do: ask(state, call, classified, reason || :no_engine, context)

  defp proceed(state, call, classified, :ask, reason, context, _authority),
    do: decide(state, call, classified, reason || :no_engine, context)

  # What `:ask` means before a rule engine exists. A tool with no effect outside this
  # process — `read`, `plan` — runs; anything that writes a file or executes a command
  # asks. Fail-closed is about effects, and prompting for every file read would make the
  # provider unusable without making it safer: the model already has the transcript.
  defp decide(state, call, classified, reason, context) do
    cond do
      MapSet.member?(state.session_grants, grant_key(classified)) ->
        ref = {:session_grant, classified.tool}

        {:allow, state, call, classified, context,
         authority(
           :allow,
           "session_grant",
           :session,
           :human,
           ref,
           record(state, :approve, :session, :human, ref)
         )}

      desktop_tool?(classified.tool) ->
        ask(state, call, classified, reason, context)

      classified.mode == :read ->
        {:allow, state, call, classified, context,
         authority(:allow, "read", :once, :runtime, {:mode, :read}, nil)}

      state.approval_mode == :auto_approve ->
        ref = {:mode, :auto_approve}

        {:allow, state, call, classified, context,
         authority(
           :allow,
           "mode",
           :once,
           :rule,
           ref,
           record(state, :approve, :once, :rule, ref)
         )}

      state.approval_mode == :auto_edit and auto_editable?(state, classified) ->
        ref = {:mode, :auto_edit}

        {:allow, state, call, classified, context,
         authority(
           :allow,
           "mode",
           :once,
           :rule,
           ref,
           record(state, :approve, :once, :rule, ref)
         )}

      true ->
        ask(state, call, classified, reason, context)
    end
  end

  defp desktop_tool?(name) when name in ["desktop_state", "desktop_act"], do: true
  defp desktop_tool?(_name), do: false

  defp redact_desktop_input("desktop_act", input) when is_map(input) do
    input
    |> redact_desktop_text()
    |> redact_desktop_long_key()
  end

  defp redact_desktop_input(_name, input), do: input

  defp redact_desktop_text(input) do
    text = Map.get(input, "text") || Map.get(input, :text)

    if is_binary(text) do
      input
      |> Map.drop(["text", :text])
      |> Map.put("text_bytes", byte_size(text))
    else
      input
    end
  end

  defp redact_desktop_long_key(input) do
    key = Map.get(input, "key") || Map.get(input, :key)

    if is_binary(key) and byte_size(key) > 32 do
      input
      |> Map.drop(["key", :key])
      |> Map.put("key_bytes", byte_size(key))
    else
      input
    end
  end

  defp image_bytes(%{images: images}) when is_list(images) do
    Enum.reduce(images, 0, fn
      %{size: size}, acc when is_integer(size) and size > 0 -> acc + size
      _part, acc -> acc
    end)
  end

  defp image_bytes(_result), do: 0

  # `auto_edit` is edits inside the workspace, and only those. A write whose path
  # resolved into a declared `add_dirs` root is still a write outside the repository the
  # operator opened, and a command is never an edit.
  defp auto_editable?(state, classified) do
    classified.mode == :write and classified.paths != [] and
      Enum.all?(classified.paths, &inside_workspace?(&1, state.scope.root))
  end

  defp inside_workspace?(path, root),
    do: Ouroboros.Workspace.Path.within?(path, root)

  defp ask(state, call, classified, reason, context) do
    request_id = new_request_id()
    persist? = persist_grant?(reason)

    payload =
      %{
        "kind" => approval_kind(classified.tool),
        "tool_call" =>
          %{
            "name" => call.name,
            "command" => classified.command,
            "cwd" => state.scope.root
          }
          |> reject_nils(),
        "paths" => classified.paths,
        "reason" => reason_text(reason)
      }

    # Only where the engine had a pattern to offer. An absent key is a card with no
    # remember row; a key carrying anything `permissions.add` will not take is a row that
    # cannot be saved, which is worse.
    payload =
      with true <- persist?,
           rule when is_binary(rule) <-
             Permissions.suggested_rule(permission_request(state, classified)) do
        Map.put(payload, "suggested_rule", rule)
      else
        _no_rule_to_offer -> payload
      end

    emit(state, :approval_requested, payload, request_id)

    _ =
      Hooks.notify(
        state.hooks,
        :notification,
        Map.put(hook_base(state), "tool_name", classified.tool)
      )

    wait_for_approval(
      state,
      call,
      request_id,
      classified,
      context,
      persist?,
      deadline(state.approval_timeout_ms)
    )
  end

  defp wait_for_approval(state, call, request_id, classified, context, persist?, deadline) do
    remaining = remaining(deadline)

    receive do
      {:native_approval, ^request_id, %ApprovalResponse{decision: :approve} = response} ->
        state = if persist?, do: grant(state, classified, response.scope), else: state

        {:allow, state, call, classified, context,
         authority(
           :allow,
           "human",
           response.scope,
           :human,
           nil,
           record(state, :approve, response.scope, :human, nil),
           request_id
         )}

      {:native_approval, ^request_id, %ApprovalResponse{} = response} ->
        {:deny, state,
         "Refused: the operator denied this #{classified.tool} call" <>
           reason_suffix(response.reason) <> ".", classified,
         authority(
           :deny,
           "human",
           response.scope,
           :human,
           nil,
           record(state, :deny, response.scope, :human, nil),
           request_id
         )}

      {:native_approval, _other_id, _response} ->
        wait_for_approval(state, call, request_id, classified, context, persist?, deadline)

      :native_interrupt ->
        {:interrupted, %{state | interrupted?: true}, classified}

      {:native_steer, text} ->
        state = %{state | steer: state.steer ++ [text]}
        wait_for_approval(state, call, request_id, classified, context, persist?, deadline)
    after
      remaining ->
        ref = {:timeout, state.approval_timeout_ms}

        {:deny, state,
         "Refused: nobody answered the approval request within " <>
           "#{state.approval_timeout_ms} ms, so it was denied.", classified,
         authority(
           :deny,
           "timeout",
           :once,
           :rule,
           ref,
           record(state, :deny, :once, :rule, ref),
           request_id
         )}
    end
  end

  # ---------------------------------------------------------------- questions

  # `ask_user` rides the approval channel: the same `approval_requested` event, the same
  # `respond_approval` verb, the same wait, with `kind: "question"` so a client that has
  # learned about questions can render a picker and one that has not still shows a modal
  # whose approve-with-a-reason is the answer.
  defp ask_question(state, call, hook_context, effect_id) do
    case AskUser.question(call.input) do
      {:error, :empty_question} ->
        settle_tool_effect(state, effect_id, :failed, 0, 0)

        {:continue,
         tool_result(state, call, %{
           output: "ask_user needs a `question`. Nothing was asked.",
           is_error: true
         })}

      {:ok, payload} ->
        request_id = new_request_id()
        emit(state, :approval_requested, payload, request_id)

        _ =
          Hooks.notify(
            state.hooks,
            :notification,
            Map.put(hook_base(state), "tool_name", "ask_user")
          )

        wait_for_answer(
          state,
          call,
          request_id,
          payload,
          hook_context,
          effect_id,
          deadline(state.approval_timeout_ms)
        )
    end
  end

  defp wait_for_answer(state, call, request_id, payload, hook_context, effect_id, deadline) do
    remaining = remaining(deadline)

    receive do
      {:native_approval, ^request_id, %ApprovalResponse{} = response} ->
        result = payload |> AskUser.answer(response) |> Tools.normalize_result_of()
        settle_tool_effect(state, effect_id, result, nil)
        {:continue, tool_result(state, call, append_context(result, hook_context))}

      {:native_approval, _other_id, _response} ->
        wait_for_answer(state, call, request_id, payload, hook_context, effect_id, deadline)

      :native_interrupt ->
        settle_tool_effect(state, effect_id, :refused, nil, 0)
        {:interrupted, %{state | interrupted?: true}}

      {:native_steer, text} ->
        state = %{state | steer: state.steer ++ [text]}
        wait_for_answer(state, call, request_id, payload, hook_context, effect_id, deadline)
    after
      remaining ->
        result =
          payload
          |> AskUser.unanswered(state.approval_timeout_ms)
          |> Tools.normalize_result_of()

        settle_tool_effect(state, effect_id, :timed_out, state.approval_timeout_ms, 0)
        {:continue, tool_result(state, call, append_context(result, hook_context))}
    end
  end

  # ------------------------------------------------------- sandbox escalation

  # C5+. What happens after `Ouroboros.Provider.Native.Sandbox` stopped a command.
  #
  # Before this, a denial was a dead end: `bash` failed, the guidance told the model to
  # ask a human with `ask_user`, and the human's best option was to do the work
  # themselves. The useful answer is to ask once and re-run the same command in a
  # narrowly widened sandbox profile, and that is what this is.
  #
  # The shape, exactly:
  #
  #   * The offer comes from the tool, not from here. `Tools.Bash` reports
  #     `escalation: %{constraint:, evidence:, reason:, …}` when — and only when —
  #     `Sandbox.escalatable?/3` says this denial is liftable: a **filesystem** denial in
  #     a **`workspace_write`** session whose evidence and command line name no protected
  #     root. Network is a node setting, `read_only` is a label that must hold, and the
  #     runtime's own data directory is nobody's to escalate into.
  #   * The engine answers first, on the **same `Bash(…)` subject the command already
  #     has** — same tool, same command, same paths, with `context.sandbox_escalation`
  #     set. That is the simplest honest mapping onto C1's existing vocabulary and it has
  #     a sharp edge worth naming: a rule that allows *running* this command therefore
  #     also allows *escalating* it, because the engine is being asked about the same
  #     subject. If that is too coarse it wants a dimension in
  #     `Ouroboros.Control.Permissions`, not a second vocabulary invented here.
  #   * `approval_mode` does **not** answer it. `auto_approve` means "do not ask me about
  #     tool calls"; it has never meant "leave the OS sandbox", and reading it that way
  #     would turn a convenience into a hole. Only an engine rule or a human grants this.
  #   * A human `approve` at `scope: session` is remembered under a key of its own —
  #     `{:sandbox_escalation, command}` — so approving a *bash call* for the session
  #     never leaks into approving an *escape* for it.
  #   * Approval re-runs the identical command once under Sandbox's internal escalated
  #     profile. It permits `.git` beneath the declared writable roots, but preserves the
  #     protected data/config roots, `.ouroboros`, and network policy. This is deliberately
  #     not `:unrestricted`: the shell is opaque and a text check cannot prove which paths
  #     it will resolve after environment expansion, symlinks, or command substitution.
  #   * Deny, an unanswered deadline, and an interrupt all mean *not re-run*: the
  #     sandboxed failure stands, with a line saying the escalation was declined.
  #
  # Plan mode never reaches here — `Permissions.evaluate/1` refuses `:execute` while
  # planning, before a tool runs — and that is checked rather than assumed.
  defp escalate(state, pending) do
    case Map.get(pending.result, :escalation) do
      offer when is_map(offer) -> consider_escalation(state, Map.put(pending, :offer, offer))
      _none -> {state, pending.result, pending.elapsed}
    end
  end

  defp consider_escalation(%{approval_mode: :plan} = state, pending),
    do: declined(state, pending, :plan_mode, nil)

  defp consider_escalation(state, pending) do
    case Permissions.evaluate(escalation_request(state, pending.classified)) do
      {:allow, rule} ->
        ref = escalation_ref(rule)
        _ = record(state, :approve, :once, :rule, ref)
        rerun(state, pending, "rule", nil)

      {:deny, rule} ->
        ref = escalation_ref(rule)
        _ = record(state, :deny, :once, :rule, ref)
        declined(state, pending, :rule, rule)

      {:ask, _reason} ->
        if MapSet.member?(state.session_grants, escalation_key(pending.classified)) do
          rerun(state, pending, "session_grant", nil)
        else
          ask_escalation(state, pending)
        end
    end
  end

  defp ask_escalation(state, pending) do
    request_id = new_request_id()
    classified = pending.classified

    payload = %{
      # A kind clients already render as an approval modal. The payload is deliberately
      # the same shape `ask/5` emits for an ordinary command approval, so a client that
      # has not learned this kind still shows a legible question with the command, the
      # working directory, and why it is being asked.
      "kind" => "sandbox_escalation",
      "tool_call" =>
        %{
          "name" => pending.call.name,
          "command" => classified.command,
          "cwd" => state.scope.root
        }
        |> reject_nils(),
      "paths" => classified.paths,
      "reason" => pending.offer.reason
    }

    # The engine's pattern, or no key at all — the same rule `ask/5` follows. This is the
    # card where remembering matters most, and it is the one that used to carry a map no
    # client could draw and `permissions.add` would not take.
    payload =
      case Permissions.suggested_rule(permission_request(state, classified)) do
        rule when is_binary(rule) -> Map.put(payload, "suggested_rule", rule)
        nil -> payload
      end

    emit(state, :approval_requested, payload, request_id)

    _ =
      Hooks.notify(
        state.hooks,
        :notification,
        Map.put(hook_base(state), "tool_name", classified.tool)
      )

    wait_for_escalation(state, pending, request_id, deadline(state.approval_timeout_ms))
  end

  defp wait_for_escalation(state, pending, request_id, deadline) do
    remaining = remaining(deadline)

    receive do
      {:native_approval, ^request_id, %ApprovalResponse{decision: :approve} = response} ->
        state = grant_escalation(state, pending.classified, response.scope)
        _ = record(state, :approve, response.scope, :human, escalation_ref(nil))
        rerun(state, pending, "human", request_id)

      {:native_approval, ^request_id, %ApprovalResponse{} = response} ->
        _ = record(state, :deny, response.scope, :human, escalation_ref(nil))
        declined(state, pending, :human, response.reason, request_id)

      {:native_approval, _other_id, _response} ->
        wait_for_escalation(state, pending, request_id, deadline)

      # The turn stops after this tool either way; an escalation nobody is left to answer
      # is a declined one, not a wedged one.
      :native_interrupt ->
        declined(%{state | interrupted?: true}, pending, :interrupted, nil, request_id)

      {:native_steer, text} ->
        wait_for_escalation(
          %{state | steer: state.steer ++ [text]},
          pending,
          request_id,
          deadline
        )
    after
      remaining ->
        declined(state, pending, :timeout, state.approval_timeout_ms, request_id)
    end
  end

  # The same command, once, in the fenced escalation profile. Nothing about the session
  # changes: the next `bash` call uses the ordinary workspace-write profile again.
  defp rerun(state, pending, granted_by, request_id) do
    context = %{pending.context | scope: Sandbox.escalated_scope(state.scope)}

    # Emitted before the re-run rather than after it: everything the event states is
    # already known, and a command that takes its full deadline should not leave a client
    # holding an answered approval with nothing to show for it.
    emit_escalation(state, pending, "approved", granted_by, request_id)

    started = System.monotonic_time(:millisecond)
    result = Tools.execute(pending.module, pending.call.input, context, state.tool_timeout_ms)
    elapsed = System.monotonic_time(:millisecond) - started

    output =
      "The OS sandbox stopped the first attempt at this command (#{pending.offer.evidence}). " <>
        "The escalation to re-run it in the fenced workspace profile was granted, and " <>
        "this is that re-run. Runtime data, config, `.ouroboros`, and network protections " <>
        "remained enforced. Anything the first attempt completed before the denial " <>
        "has now happened twice — check for that before you trust this output.\n\n" <>
        Map.get(result, :output, "")

    {state, result |> Map.put(:output, output) |> Map.put(:escalation, nil), elapsed}
  end

  defp declined(state, pending, source, detail, request_id \\ nil) do
    emit_escalation(state, pending, "declined", to_string(source), request_id)

    result =
      pending.result
      |> Map.put(:output, pending.result.output <> "\n" <> decline_text(source, detail))
      |> Map.put(:escalation, nil)

    {state, result, pending.elapsed}
  end

  defp decline_text(:human, reason),
    do:
      "The operator was asked whether to re-run this command in the fenced escalation " <>
        "profile and " <>
        "declined" <> reason_suffix(reason) <> ". Do not ask for it again for this command."

  defp decline_text(:rule, rule),
    do:
      "A permission rule (#{inspect(rule)}) refuses the fenced escalation re-run, so the " <>
        "command was not re-run."

  defp decline_text(:timeout, timeout),
    do:
      "Nobody answered the request to re-run this command in the fenced escalation " <>
        "profile within " <>
        "#{inspect(timeout)} ms, so it was declined and the command was not re-run."

  defp decline_text(:interrupted, _detail),
    do:
      "The turn was interrupted while the fenced escalation request was outstanding, " <>
        "so it was declined and the command was not re-run."

  defp decline_text(:plan_mode, _detail),
    do:
      "This session is planning, so no escalation out of the sandbox is offered. Record " <>
        "the plan instead."

  # The transcript's own record. The `tool_result` carries whichever attempt's output the
  # model is meant to act on; this carries the other half, so "it ran twice" is a fact a
  # reader can find rather than infer from a header in a tool result.
  defp emit_escalation(state, pending, decision, granted_by, request_id) do
    emit(
      state,
      :provider_event,
      %{
        "kind" => "sandbox_escalation",
        "decision" => decision,
        "granted_by" => granted_by,
        "call_id" => pending.call.id,
        "command" => pending.classified.command,
        "constraint" => to_string(pending.offer.constraint),
        "evidence" => pending.offer.evidence,
        # Not `"sandbox"`: on a `tool_call` that key means "what this ran under", and a
        # reader who carried that meaning here would read an approved escalation as
        # having run sandboxed. This names the thing that *stopped* the first attempt.
        "stopped_by" => pending.offer.label,
        "sandboxed_output" => clip(pending.result.output, @max_escalation_output_bytes)
      },
      request_id
    )
  end

  defp escalation_request(state, classified) do
    request = permission_request(state, classified)
    %{request | context: Map.put(request.context, :sandbox_escalation, true)}
  end

  # A rule reference that says which decision this was, so a `:permission` entry for an
  # escalation cannot be read as one for the command itself.
  defp escalation_ref(rule), do: {:sandbox_escalation, rule}

  # Deliberately not `grant_key/1`. Approving a `bash` call for the session must not also
  # approve escaping the sandbox for it; these are two different questions and they get
  # two different keys in the one set the session already carries across turns.
  defp escalation_key(classified), do: {:sandbox_escalation, classified.command}

  defp grant_escalation(state, classified, :session),
    do: %{state | session_grants: MapSet.put(state.session_grants, escalation_key(classified))}

  defp grant_escalation(state, _classified, _once), do: state

  defp clip(text, limit) when is_binary(text) and byte_size(text) > limit,
    do: binary_part(text, 0, limit) <> "\n… #{byte_size(text) - limit} bytes elided …"

  defp clip(text, _limit) when is_binary(text), do: text

  defp new_request_id,
    do: "napp_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

  defp grant(state, classified, :session) do
    if desktop_tool?(classified.tool) and not is_binary(classified.context[:app]) do
      # A session grant keyed on a missing app would cover every later window_id-only
      # observe. Ask again instead.
      state
    else
      %{state | session_grants: MapSet.put(state.session_grants, grant_key(classified))}
    end
  end

  defp grant(state, _classified, _once), do: state

  defp grant_key(classified) do
    if desktop_tool?(classified.tool) do
      {classified.tool, classified.context[:app]}
    else
      {classified.tool, classified.command, Enum.sort(classified.paths)}
    end
  end

  # Returns the id of the `:permission` entry this decision was written under, or `nil`
  # when there was no engine to write it into. A `:tool_call` entry links to that id
  # rather than restating the decision, so the two records cannot drift.
  defp record(state, decision, scope, actor, rule_ref) do
    decision_id =
      "ndec_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    case Permissions.record(decision_id, %{
           decision: decision,
           scope: scope,
           actor: actor,
           rule_ref: rule_ref,
           reason: nil,
           session_id: state.session_id,
           provider: :native
         }) do
      :ok -> decision_id
      {:error, _no_engine_or_refused} -> nil
    end
  end

  defp permission_request(state, classified) do
    %{
      principal: %{session_id: state.session_id, provider: :native, node: node()},
      tool: classified.tool,
      command: classified.command,
      paths: classified.paths,
      mode: classified.mode,
      domains: Map.get(classified, :domains, []),
      # A tool may contribute context the engine matches on — Computer Use puts the
      # resolved `:app`/`:desktop_action` here so a `ComputerUse(app:…)` rule can allow on
      # the app this node measured. The loop's own keys are merged SECOND so they always
      # win: a classifier can add facts but never spoof the approval mode, sandbox posture,
      # workspace, or turn. `classify/3` returns `%{}` for every non-Computer-Use tool, so
      # this is a no-op for them.
      context:
        Map.merge(Map.get(classified, :context, %{}), %{
          approval_mode: state.approval_mode,
          sandbox_mode: state.scope.sandbox_mode,
          workspace: state.scope.root,
          turn_id: state.turn_id
        })
    }
  end

  defp persist_grant?(:sensitive_desktop_act), do: false
  defp persist_grant?(_reason), do: true

  defp approval_kind("bash"), do: "command"
  defp approval_kind(name) when name in ["write", "edit", "apply_patch"], do: "file_change"
  defp approval_kind(_name), do: "tool"

  defp reason_text(:no_engine),
    do: "no permission rule engine is configured on this node, so every gated tool asks"

  defp reason_text({:engine_error, message}),
    do: "the permission engine could not decide (#{message}), so this is being asked"

  defp reason_text(reason) when is_binary(reason), do: reason

  defp reason_text(:sensitive_desktop_act),
    do: "this desktop_act targets a password field or looks like a secret; it asks every time"

  defp reason_text(reason), do: inspect(reason)

  defp reason_suffix(nil), do: ""
  defp reason_suffix(""), do: ""
  defp reason_suffix(reason), do: ": #{reason}"

  # ---------------------------------------------------------------- subagents (G3)

  # `agent`, from the moment the gate admitted it to the moment its child's summary
  # becomes a tool result. Everything here runs in the loop process, which is the point:
  # a child's approval has to reach this session's approval channel, and this is the only
  # process that owns one.
  defp run_subagent(state, call, hook_context, effect_id) do
    case subagent_parent(state) do
      {:ok, parent} ->
        case AgentTool.plan(call.input, parent) do
          {:ok, spec} -> spawn_subagent(state, call, spec, hook_context, effect_id)
          {:error, message} -> refuse_subagent(state, call, hook_context, effect_id, message)
        end

      {:error, message} ->
        refuse_subagent(state, call, hook_context, effect_id, message)
    end
  end

  # A refusal is an ordinary failed tool result and an ordinary settled ledger entry. The
  # call was admitted — the entry is open — and what failed is the tool, which is exactly
  # what `:failed` means there.
  defp refuse_subagent(state, call, hook_context, effect_id, message) do
    result = Tools.normalize_result_of(%{output: message, is_error: true})
    settle_tool_effect(state, effect_id, result, 0)
    {:continue, tool_result(state, call, append_context(result, hook_context))}
  end

  # What a child inherits, gathered in one place so that "a child may never be more
  # permissive than its parent" is a property of this map rather than of the tool's
  # discipline. Nothing the model wrote reaches it except through
  # `Native.Tools.Agent.plan/2`'s own arguments.
  defp subagent_parent(%{session_context: nil}),
    do:
      {:error,
       "Refused: `agent` needs an interactive native session to own the child, and this " <>
         "is a one-shot run. Do the work in this run instead."}

  defp subagent_parent(state) do
    counts = subagent_counts(state)

    {:ok,
     %{
       depth: state.subagent_depth,
       provider_session_id: state.provider_session_id,
       session_id: state.session_id,
       session_pid: state.session_pid,
       request: state.session_request,
       context: state.session_context,
       scope: state.scope,
       model_spec: state.model_spec,
       approval_mode: state.approval_mode,
       tool_names: state |> tool_specs() |> Enum.map(& &1.name),
       options: Map.new(state.session_request.provider_options || %{}),
       subscriber: self(),
       background_subscriber: state.session_pid,
       running: counts.running,
       tracked: counts.tracked
     }}
  end

  defp spawn_subagent(state, call, spec, hook_context, effect_id) do
    started_at = System.monotonic_time(:millisecond)

    case Subagent.spawn(spec) do
      {:ok, started} ->
        emit(state, :provider_event, subagent_event(AgentTool.spawned_payload(spec, started)))
        _ = track_subagent(state, spec, started)

        if spec.background do
          background_result(state, call, spec, started, hook_context, effect_id, started_at)
        else
          wait_for_subagent(
            state,
            call,
            spec,
            started,
            hook_context,
            effect_id,
            started_at,
            deadline(spec.deadline_ms + 5_000),
            %{}
          )
        end

      # Every way a launch can fail is now mostly a fact about the node the child was
      # placed on — its worktree root, its filesystem, its reachability — so the tool's own
      # module says each of them in a sentence rather than inspecting a tuple into the
      # transcript.
      {:error, reason} ->
        refuse_subagent(state, call, hook_context, effect_id, AgentTool.start_refusal(reason))
    end
  end

  defp background_result(state, call, spec, started, hook_context, effect_id, started_at) do
    result =
      Tools.normalize_result_of(%{
        output:
          "Subagent #{spec.task_id} (#{spec.description}) is running in the background as " <>
            "#{started.provider_session_id}. Collect it with " <>
            "`agent_result` and that task_id — it is stopped when this session closes, and " <>
            "a collection after that says so.",
        is_error: false
      })

    settle_tool_effect(state, effect_id, result, System.monotonic_time(:millisecond) - started_at)
    {:continue, tool_result(state, call, append_context(result, hook_context))}
  end

  # The wait, and the four things that can interrupt it. `pending` maps the parent request
  # ids this process minted to the child's own — the whole of the approval translation.
  defp wait_for_subagent(
         state,
         call,
         spec,
         started,
         hook_context,
         effect_id,
         started_at,
         deadline,
         pending
       ) do
    task_id = spec.task_id
    remaining = remaining(deadline)

    receive do
      {:subagent, ^task_id, {:progress, payload}} ->
        emit(state, :provider_event, subagent_event(payload))

        wait_for_subagent(
          state,
          call,
          spec,
          started,
          hook_context,
          effect_id,
          started_at,
          deadline,
          pending
        )

      {:subagent, ^task_id, {:approval, child_request_id, payload}} ->
        request_id = new_request_id()
        emit(state, :approval_requested, subagent_approval(payload, spec), request_id)

        wait_for_subagent(
          state,
          call,
          spec,
          started,
          hook_context,
          effect_id,
          started_at,
          deadline,
          Map.put(pending, request_id, child_request_id)
        )

      {:subagent, ^task_id, {:settled, summary}} ->
        finish_subagent(state, call, spec, started, summary, hook_context, effect_id, started_at)

      {:subagent, _other, _message} ->
        wait_for_subagent(
          state,
          call,
          spec,
          started,
          hook_context,
          effect_id,
          started_at,
          deadline,
          pending
        )

      {:native_approval, request_id, %ApprovalResponse{} = response} ->
        pending =
          case Map.fetch(pending, request_id) do
            {:ok, child_request_id} ->
              Subagent.respond(started.pid, child_request_id, response)
              Map.delete(pending, request_id)

            # An answer to something else — a question this turn asked before the child
            # existed. Dropped rather than forwarded: a response addressed to one request
            # is not an answer to another.
            :error ->
              pending
          end

        wait_for_subagent(
          state,
          call,
          spec,
          started,
          hook_context,
          effect_id,
          started_at,
          deadline,
          pending
        )

      :native_interrupt ->
        summary = settle_subagent(state, spec, started, :stopped)
        emit(state, :provider_event, subagent_event(Subagent.settled_payload(summary)))
        settle_tool_effect(state, effect_id, :refused, nil, 0)
        {:interrupted, %{state | interrupted?: true}}

      {:native_steer, text} ->
        wait_for_subagent(
          %{state | steer: state.steer ++ [text]},
          call,
          spec,
          started,
          hook_context,
          effect_id,
          started_at,
          deadline,
          pending
        )
    after
      # The backstop, not the deadline. `Subagent` runs the real one and settles itself
      # `timed_out`, which arrives here as an ordinary `{:settled, …}`; this fires only
      # when that process is itself wedged, and it still produces a summary rather than a
      # tool call that never returned.
      remaining ->
        summary = settle_subagent(state, spec, started, :timed_out)
        finish_subagent(state, call, spec, started, summary, hook_context, effect_id, started_at)
    end
  end

  defp finish_subagent(state, call, spec, started, summary, hook_context, effect_id, started_at) do
    emit(state, :provider_event, subagent_event(Subagent.settled_payload(summary)))
    state = fold_subagent_usage(state, spec, summary)

    # A foreground child is released the moment its summary is in hand: nothing can
    # collect it afterwards, and leaving it tracked would spend one of the parent's four
    # slots on a child that has already answered.
    _ = Subagent.stop(started.pid, :stopped)
    _ = release_subagent(state, spec.task_id)

    result =
      Tools.normalize_result_of(%{
        output: Subagent.render(summary),
        is_error: summary.status in [:failed, :timed_out]
      })

    settle_tool_effect(state, effect_id, result, System.monotonic_time(:millisecond) - started_at)
    {:continue, tool_result(state, call, append_context(result, hook_context))}
  end

  defp settle_subagent(_state, _spec, started, reason) do
    case Subagent.stop(started.pid, reason) do
      {:ok, summary} ->
        summary

      # A child whose own process is gone still owes the parent a terminal answer. This is
      # the least this runtime knows to be true about it, said as such — including *where*
      # it was, which `node/1` on the pid still answers for a node that has gone away.
      {:error, _unreachable} ->
        child_node = Map.get(started, :node) || node(started.pid)

        %{
          task_id: started.task_id,
          description: "subagent",
          provider_session_id: started.provider_session_id,
          session_dir: Map.get(started, :session_dir),
          status: reason,
          error: "the child's own process could not be reached for a summary",
          turns: 0,
          tool_calls: 0,
          files_changed: [],
          files_changed_count: 0,
          approvals_denied: 0,
          usage: %{input: 0, output: 0, cost: nil},
          text: "",
          turn_id: nil,
          worktree: Map.get(started, :worktree),
          workspace: Map.get(started, :workspace),
          node: child_node,
          remote: child_node != node(),
          background: false,
          depth: 0,
          tools: []
        }
    end
  end

  # I2/G3. The child's spend is the parent's spend: it was this session's turn that
  # decided to make it. Folding it into `state.usage` is what keeps `turn_completed`'s
  # totals true, and the `usage` event is what keeps a client's running cost true.
  #
  # The event deliberately carries **no** `context_used`/`context_window`: the child's
  # request size is a fact about the child's window, and the parent's meter is the one
  # thing on that event a session must not be able to lie about. `Native.Session` drops a
  # `usage` payload carrying `subagent_task_id` from its meter for the same reason.
  #
  # It carries the **child's** turn id, and that is arithmetic rather than bookkeeping.
  # `Ouroboros.Interactive.State.account_usage/3` reads two `usage` events of one turn as
  # a provider re-reporting a running total and keeps the field-wise maximum; a child's
  # spend is not a re-report of the parent's, it is more spend, so under the parent's turn
  # id the larger of the two would swallow the smaller. Under the child's — a real turn id,
  # of the turn that actually spent it — the plane accounts it as its own contribution and
  # adds it, which is what "folded into the session's usage" has to mean for `/cost` to be
  # true. Leaving it blank is not an option: `Jido.Harness.Session.EventStore`'s
  # `normalize_adapter_event/2` fills an absent turn id with the active one.
  defp fold_subagent_usage(state, spec, summary) do
    payload =
      %{
        "input_tokens" => summary.usage.input,
        "output_tokens" => summary.usage.output,
        "total_tokens" => summary.usage.input + summary.usage.output,
        "model" => spec.request_attrs.model,
        "subagent_task_id" => summary.task_id,
        "provider_session_id" => summary.provider_session_id
      }
      |> then(fn payload ->
        if is_number(summary.usage.cost),
          do: Map.put(payload, "cost_usd", summary.usage.cost),
          else: payload
      end)

    state.emit.(%{
      type: :usage,
      payload: payload,
      turn_id: Map.get(summary, :turn_id) || state.turn_id,
      request_id: nil
    })

    %{
      state
      | usage: %{
          input: state.usage.input + summary.usage.input,
          output: state.usage.output + summary.usage.output,
          cost: state.usage.cost + (summary.usage.cost || 0.0)
        }
    }
  end

  defp subagent_event(payload), do: Map.put(payload, "kind", "subagent")

  # The child's own approval payload, forwarded whole so a client renders it exactly as it
  # would any other, with one key added saying which child is asking. Adding rather than
  # rewriting is deliberate: a client that has never heard of subagents still shows the
  # right modal.
  defp subagent_approval(payload, spec) when is_map(payload) do
    Map.put(payload, "subagent", %{
      "task_id" => spec.task_id,
      "description" => spec.description,
      "provider_session_id" => spec.request_attrs.provider_session_id,
      # Which machine is asking. A person answering an approval relayed from another node
      # is authorizing a change to a filesystem that is not the one in front of them, and a
      # modal that did not say so would be asking the wrong question.
      "node" => Atom.to_string(spec.node)
    })
  end

  defp subagent_approval(_payload, spec),
    do: %{"kind" => "tool", "subagent" => %{"task_id" => spec.task_id}}

  defp subagent_handles(%{session_pid: pid}) when is_pid(pid) do
    %{
      lookup: fn task_id ->
        case session_call(pid, {:subagent_lookup, task_id}) do
          {:ok, child} when is_pid(child) -> {:ok, child}
          _absent -> :error
        end
      end,
      release: fn task_id -> session_call(pid, {:subagent_release, task_id}) end
    }
  end

  defp subagent_handles(_state), do: nil

  defp track_subagent(%{session_pid: pid}, spec, started) when is_pid(pid),
    do:
      session_call(
        pid,
        {:subagent_track, spec.task_id, started.pid,
         %{
           description: spec.description,
           background: spec.background,
           provider_session_id: started.provider_session_id,
           node: Map.get(started, :node) || spec.node
         }}
      )

  defp track_subagent(_state, _spec, _started), do: {:error, :no_session}

  defp release_subagent(%{session_pid: pid}, task_id) when is_pid(pid),
    do: session_call(pid, {:subagent_release, task_id})

  defp release_subagent(_state, _task_id), do: :ok

  defp subagent_counts(%{session_pid: pid}) when is_pid(pid) do
    case session_call(pid, :subagent_counts) do
      %{running: _running, tracked: _tracked} = counts -> counts
      _unreachable -> %{running: 0, tracked: 0}
    end
  end

  defp subagent_counts(_state), do: %{running: 0, tracked: 0}

  defp session_call(pid, message) do
    GenServer.call(pid, message, 5_000)
  catch
    :exit, reason -> {:error, {:session_unreachable, reason}}
  end

  # ---------------------------------------------------------------- the ledger (I1)

  # What admitted or refused one tool call, in the shape `EffectLedger`'s `authority` map
  # takes. `reason` names the *kind* of authority in one word a reader can scan a ledger
  # by; `constraints` carries the rest, bounded and content-free.
  defp authority(decision, reason, scope, actor, rule_ref, permission_entry_id, request_id \\ nil) do
    %{
      decision: decision,
      reason: reason,
      constraints:
        reject_nils(%{
          scope: scope,
          actor: actor,
          rule_id: rule_id(rule_ref),
          request_id: request_id
        }),
      permission_entry_id: permission_entry_id
    }
  end

  # A hook that resolved an engine `ask` is its own authority: it is either the operator's
  # user-scope hook or a repository hook they trusted. Nothing records it as a permission
  # decision today, so the entry says who admitted it and links no `:permission` id rather
  # than borrowing the engine's.
  #
  # A hook that agreed with an engine `allow` resolved nothing, and the entry keeps saying
  # the rule admitted the call — which is what happened.
  defp hook_allowed(nil),
    do: authority(:allow, "hook", :once, :hook, {:hook, :pre_tool_use}, nil)

  defp hook_allowed(authority), do: authority

  defp interrupted_authority,
    do: authority(:deny, "interrupted", :once, :runtime, {:interrupted, :approval_wait}, nil)

  defp rule_id(nil), do: nil
  defp rule_id(%{id: id}) when is_binary(id), do: id
  defp rule_id(rule) when is_binary(rule), do: rule
  defp rule_id({tag, value}) when is_atom(tag) and is_atom(value), do: "#{tag}:#{value}"
  defp rule_id({tag, value}) when is_atom(tag), do: "#{tag}:#{inspect(value)}"
  defp rule_id(rule), do: inspect(rule)

  # Embeds `node()` for the same reason every other id in this runtime does: an effect id
  # is read across a fleet, and a VM-local integer alone collides with the same one
  # allocated on another machine.
  defp tool_effect_id(state, call) do
    digest =
      :sha256
      |> :crypto.hash(
        :erlang.term_to_binary(
          {node(), state.session_id, state.provider_session_id, state.turn_id, call.id,
           System.system_time(:nanosecond), System.unique_integer([:positive, :monotonic])}
        )
      )
      |> Base.encode16(case: :lower)

    "tool-" <> binary_slice(digest, 0, 32)
  end

  # Exactly the two parameters `ledger.get` takes, so a client resolves the row it drew
  # without a second vocabulary to translate. The sequence is deliberately absent: it is
  # minted by the write, and this reference is emitted before the write so the row and the
  # entry cannot get out of order.
  defp emit_tool_call(state, call, effect_id) do
    emit(
      state,
      :tool_call,
      %{
        "name" => call.name,
        "call_id" => call.id,
        "input" => redact_desktop_input(call.name, call.input),
        "ledger_ref" => effect_id && ledger_ref(effect_id)
      }
      |> Map.merge(Sandbox.tool_call_marker(call.name, state.scope))
      |> reject_nils()
    )
  end

  defp ledger_ref(effect_id), do: %{"node" => Atom.to_string(node()), "id" => effect_id}

  # Checkpoint before run, and a hard gate rather than best effort: the whole claim a
  # `:tool_call` entry makes is that the call is accountable afterwards, and a call whose
  # attempt could not be written down is not.
  defp open_tool_effect(state, call, classified, effect_id, authority) do
    case safe_ledger(fn ->
           EffectLedger.record_started(
             tool_effect_attrs(state, call, classified, effect_id, authority)
           )
         end) do
      {:ok, _entry, _disposition} -> :ok
      other -> {:error, other}
    end
  end

  # A refusal is terminal the instant it is decided, so it is written as one entry rather
  # than as a start nothing would ever settle. Best effort, and deliberately: the call is
  # already refused, and failing to record a refusal cannot make it run.
  defp refuse_tool_effect(state, call, classified, effect_id, authority) do
    attrs =
      state
      |> tool_effect_attrs(call, classified, effect_id, authority)
      |> Map.put(:result, %{status: :refused})
      |> Map.put(:error, {:tool_call_refused, authority.reason})

    _ = safe_ledger(fn -> EffectLedger.record_denied(attrs) end)
    :ok
  end

  defp tool_effect_attrs(state, call, classified, effect_id, authority) do
    %{
      id: effect_id,
      effect: :tool_call,
      principal: principal(state),
      attempt:
        reject_nils(%{
          session_id: state.session_id,
          turn_id: state.turn_id,
          call_id: call.id,
          tool: classified.tool,
          provider: :native,
          subject: tool_subject(classified),
          node: node(),
          permission_entry_id: authority.permission_entry_id
        }),
      authority: authority |> Map.delete(:permission_entry_id) |> link_parent(state),
      cause: %{signal_type: cause_type(state), signal_id: effect_id}
    }
  end

  # G3. Which parent's authority this call ran under. It rides in `constraints` because
  # that is the one part of an entry `Ouroboros.Agent.EffectLedger` passes through whole,
  # and because it is true of the authority rather than of the subject: a child is
  # admitted to do something *because* its parent was, and this names which parent.
  defp link_parent(authority, %{subagent_parent: parent} = state) when is_binary(parent) do
    Map.update(
      authority,
      :constraints,
      %{},
      &Map.merge(&1 || %{}, %{subagent_parent: parent, subagent_task_id: state.subagent_task_id})
    )
  end

  defp link_parent(authority, _state), do: authority

  defp cause_type(%{subagent_parent: parent}) when is_binary(parent),
    do: "native.subagent.tool_call"

  defp cause_type(_state), do: "native.tool_call"

  # What the call is *about*, in identities. Paths and hostnames name things; a command
  # line and a tool's arguments are contents, so the command is a digest and the arguments
  defp tool_subject(classified) do
    context = Map.get(classified, :context, %{})

    %{}
    |> put_subject(:paths, Enum.filter(classified.paths, &is_binary/1))
    |> put_subject(:command_sha256, command_digest(classified.command))
    |> put_subject(:hosts, Map.get(classified, :domains, []))
    |> put_subject(:app, context[:app])
    |> put_subject(:desktop_action, context[:desktop_action])
    |> put_subject(:window_id, context[:window_id])
    |> Map.merge(mcp_subject(classified.tool))
  end

  defp put_subject(subject, _key, nil), do: subject
  defp put_subject(subject, _key, []), do: subject
  defp put_subject(subject, key, value), do: Map.put(subject, key, value)

  defp command_digest(command) when is_binary(command),
    do: :sha256 |> :crypto.hash(command) |> Base.encode16(case: :lower)

  defp command_digest(_command), do: nil

  # `mcp__server__tool` is the one name whose *shape* carries two identities. Splitting it
  # here means a ledger reader can ask "what did this session do through the linear
  # server" without parsing tool names, and it costs nothing when D4's MCP tools are not
  # loaded — an ordinary tool name simply has no `mcp__` prefix.
  defp mcp_subject("mcp__" <> rest) do
    case String.split(rest, "__", parts: 2) do
      [server, tool] when server != "" and tool != "" -> %{mcp_server: server, mcp_tool: tool}
      _unsplittable -> %{}
    end
  end

  defp mcp_subject(_tool), do: %{}

  # Settled against the tool's own result. `:timed_out` is inferred from the wall clock
  # rather than from the runner's message: `Tools.execute/4` reports a killed tool as an
  # ordinary error result, so elapsed time is the only structural evidence there is, and
  # the inference is stated here rather than presented as something the runner said.
  defp settle_tool_effect(state, effect_id, result, elapsed) when is_map(result) do
    bytes = byte_size(to_string(Map.get(result, :output, ""))) + image_bytes(result)

    status =
      cond do
        not Map.get(result, :is_error, false) -> :completed
        timed_out?(state, elapsed) -> :timed_out
        true -> :failed
      end

    settle_tool_effect(state, effect_id, status, elapsed, bytes)
  end

  defp settle_tool_effect(_state, effect_id, status, elapsed, bytes) do
    outcome = %{
      status: if(status == :completed, do: :ok, else: :failed),
      result: reject_nils(%{status: status, duration_ms: duration(elapsed), output_bytes: bytes})
    }

    outcome =
      if status == :completed,
        do: outcome,
        else: Map.put(outcome, :error, {:tool_call_not_completed, status})

    _ = safe_ledger(fn -> EffectLedger.settle(effect_id, outcome) end)
    :ok
  end

  defp timed_out?(%{tool_timeout_ms: limit}, elapsed)
       when is_integer(limit) and is_integer(elapsed),
       do: elapsed >= limit

  defp timed_out?(_state, _elapsed), do: false

  defp duration(elapsed) when is_integer(elapsed) and elapsed >= 0, do: elapsed
  defp duration(_elapsed), do: nil

  # What the model is told when the ledger could not record the call. Legible on purpose:
  # a refusal the model cannot distinguish from a tool failure is one it will retry.
  defp unrecordable(call, reason) do
    %{
      output:
        "Refused: the effect ledger could not record this `#{call.name}` call before it " <>
          "ran, so it did not run. A tool call nobody can account for afterwards is what " <>
          "that ledger exists to prevent. Ask the operator to check the runtime's effect " <>
          "ledger (#{inspect(reason)}).",
      is_error: true
    }
  end

  defp principal(%{session_id: session_id}) when is_binary(session_id) and session_id != "",
    do: "session:" <> session_id

  defp principal(%{provider_session_id: id}) when is_binary(id) and id != "",
    do: "native:" <> id

  defp principal(_state), do: "native"

  defp safe_ledger(fun) do
    fun.()
  rescue
    error -> {:error, {:effect_ledger_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:effect_ledger_failure, kind, inspect(reason)}}
  end

  # ---------------------------------------------------------------- control

  defp drain_control(state) do
    receive do
      :native_interrupt -> drain_control(%{state | interrupted?: true})
      {:native_steer, message} -> drain_control(%{state | steer: state.steer ++ [message]})
    after
      0 -> state
    end
  end

  # A steered message becomes an ordinary user message after the tool results it
  # interrupted, so the next model call reads it as the operator speaking mid-task.
  defp apply_steer(%{steer: []} = state), do: state

  defp apply_steer(state) do
    messages =
      state.messages ++
        Enum.map(state.steer, fn
          %{role: :user} = message -> message
          text when is_binary(text) -> %{role: :user, content: text}
        end)

    %{state | messages: messages, steer: []}
  end

  # ---------------------------------------------------------------- terminals

  defp complete(state, iterations) do
    state = run_checks(state)

    case settle(state) do
      {:ok, state} ->
        emit(state, :turn_completed, %{
          "status" => "completed",
          "iterations" => iterations,
          "input_tokens" => state.usage.input,
          "output_tokens" => state.usage.output,
          "cost_usd" => Float.round(state.usage.cost, 6)
        })

        {:ok, state}

      {:error, state, reason} ->
        checkpoint_failed(state, reason)
    end
  end

  defp interrupted(state) do
    state = %{state | interrupted?: true}

    case settle(state) do
      {:ok, state} ->
        emit(state, :turn_interrupted, %{"reason" => "interrupted"})
        {:ok, state}

      {:error, state, reason} ->
        checkpoint_failed(state, reason)
    end
  end

  defp fail(state, message, reason) do
    case settle(state) do
      {:ok, state} ->
        emit(state, :turn_failed, %{"error" => message, "reason" => reason})
        {:ok, state}

      {:error, state, checkpoint_reason} ->
        emit(state, :turn_failed, %{
          "error" =>
            message <>
              "; conversation checkpoint failed: " <> inspect(checkpoint_reason, limit: 6),
          "reason" => reason,
          "checkpoint_error" => inspect(checkpoint_reason, limit: 6)
        })

        {:ok, state}
    end
  end

  defp checkpoint_failed(state, reason) do
    emit(state, :turn_failed, %{
      "error" => "conversation checkpoint failed: #{inspect(reason, limit: 6)}",
      "reason" => "checkpoint_error"
    })

    {:ok, state}
  end

  # Everything that has to be true before the terminal event reaches a subscriber: the
  # file manifest written, the `Stop` hooks run, the conversation checkpointed. The
  # conversation goes last, because a `Stop` hook's `additionalContext` becomes part of
  # it and a checkpoint written before that would resume without it.
  defp settle(state) do
    state = record_turn_files(state)
    state = inject(state, Hooks.notify(state.hooks, :stop, hook_base(state)))

    case persist(state) do
      :ok -> {:ok, state}
      {:error, reason} -> {:error, state, reason}
    end
  end

  # `[checks]` — a project-declared typecheck or lint — runs once per turn, and only when
  # the turn actually changed a file. Its failing tail becomes an ordinary user message,
  # so the *next* model step reads it: R4's universal fallback, the thing OpenCode now
  # recommends over an LSP integration, and the one bound that matters is that it never
  # blocks and never extends the turn.
  defp run_checks(%{turn_paths: []} = state), do: state

  defp run_checks(state) do
    case Hooks.run_checks(state.hooks) do
      [] ->
        state

      failures ->
        inject(state, [
          "Project checks failed after this turn's file changes:\n" <> Enum.join(failures, "\n")
        ])
    end
  end

  defp record_turn_files(%{turn_paths: [], turn_commands: []} = state), do: state

  defp record_turn_files(state) do
    entries =
      Enum.map(state.turn_paths, fn path ->
        entry = Map.fetch!(state.turn_files, path)
        %{path: path, before: entry.before, after: entry.after}
      end)

    case Checkpoint.record_turn(state.session_dir, state.turn_id, entries,
           message_count: state.message_offset + length(state.messages),
           commands: state.turn_commands
         ) do
      {:ok, summary} ->
        emit(state, :provider_event, %{"kind" => "checkpoint", "turn" => summary})

      {:error, reason} ->
        emit(state, :provider_event, %{
          "kind" => "status",
          "message" =>
            "this turn's file checkpoint could not be written (#{inspect(reason)}), " <>
              "so it cannot be rewound"
        })
    end

    state
  end

  defp inject(state, []), do: state

  defp inject(state, lines) do
    %{state | messages: state.messages ++ [%{role: :user, content: injected_body(lines)}]}
  end

  defp injected([]), do: ""
  defp injected(lines), do: "\n" <> injected_body(lines)

  defp injected_body(lines) do
    lines
    |> Enum.join("\n")
    |> then(fn text ->
      if byte_size(text) <= @max_injected_context_bytes,
        do: text,
        else: binary_part(text, 0, @max_injected_context_bytes) <> "\n… (truncated)"
    end)
  end

  # The content-minimised payload every hook receives. It carries identifiers and the
  # workspace, never the prompt and never a file's contents: a hook is an external
  # process, and what crosses that boundary is the same thing the ledger records.
  defp hook_base(state) do
    %{
      "session_id" => state.session_id,
      "provider_session_id" => state.provider_session_id,
      "turn_id" => state.turn_id,
      "cwd" => state.scope.root,
      "workspace_trusted" => state.hooks && state.hooks.trusted?
    }
  end

  defp persist(%{checkpoint: nil}), do: :ok

  defp persist(state) do
    state.checkpoint.(%{
      messages: state.messages,
      reads: state.reads,
      session_grants: state.session_grants,
      rules_loaded: state.rules_loaded
    })
  end

  # ---------------------------------------------------------------- helpers

  defp tool_specs(%{tool_specs: specs}) when is_list(specs), do: specs
  defp tool_specs(state), do: build_tool_specs(state)

  # The workspace reaches the specs so `skill` can put its catalogue in its description.
  # Everything else's description is static.
  defp build_tool_specs(state),
    do:
      Tools.specs(state.allowed_tools, state.disallowed_tools,
        workspace: state.scope.root,
        subagent_depth: state.subagent_depth
      )

  defp signature(call), do: {call.name, call.input}

  defp invalid_call_message(message, attempts) when attempts > 1 do
    message <>
      " This exact invalid call has now failed #{attempts} times. Change its arguments or " <>
      "continue without this tool; repeating it again will stop the turn."
  end

  defp invalid_call_message(message, _attempts), do: message

  defp emit(state, type, payload, request_id \\ nil) do
    state.emit.(%{type: type, payload: payload, turn_id: state.turn_id, request_id: request_id})
    :ok
  end

  defp reject_nils(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)
  defp put_nonempty(map, _key, value) when value in [nil, [], %{}], do: map
  defp put_nonempty(map, key, value), do: Map.put(map, key, value)

  defp append_user_text(message, ""), do: message

  defp append_user_text(%{content: content} = message, text) when is_binary(content),
    do: %{message | content: content <> text}

  defp append_user_text(%{content: content} = message, text) when is_list(content),
    do: %{message | content: content ++ [%{type: :text, text: text}]}

  defp deadline(:infinity), do: :infinity
  defp deadline(ms), do: System.monotonic_time(:millisecond) + ms

  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp describe({:stream_failed, message}), do: message
  defp describe({:stream_exited, reason}), do: reason
  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  @doc """
  Builds a Harness event for the session owner, redacted at the live boundary.

  `Jido.Harness.EventStore` redacts again before journalling. This first pass protects
  live subscribers from a tool result that echoed a credential.
  """
  @spec to_event(map(), atom(), String.t() | nil) :: Jido.Harness.Event.t()
  def to_event(event, provider, provider_session_id) do
    Jido.Harness.Event.new!(
      type: event.type,
      provider: provider,
      provider_session_id: provider_session_id,
      turn_id: event.turn_id,
      request_id: event.request_id,
      payload: Jido.Harness.Redaction.redact(event.payload)
    )
  end

  @doc false
  @spec resolve_model(String.t() | nil) :: {:ok, String.t()} | {:error, term()}
  def resolve_model(model) when is_binary(model) and model != "", do: {:ok, model}

  def resolve_model(_unset) do
    case Model.configured_model() do
      model when is_binary(model) and model != "" ->
        {:ok, model}

      _unset ->
        {:error,
         {:no_model,
          "no model was given and #{Model.model_env()} is unset. " <>
            "Set it to a ReqLLM spec such as anthropic:claude-sonnet-5, or pass `model`."}}
    end
  end

  @doc false
  @spec max_iterations(map(), pos_integer() | nil) :: pos_integer()
  def max_iterations(options, max_turns) do
    from_options =
      case Map.get(options, :max_iterations) || Map.get(options, "max_iterations") do
        value when is_integer(value) and value > 0 -> value
        _unset -> nil
      end

    cond do
      from_options -> min(from_options, 500)
      is_integer(max_turns) and max_turns > 0 -> min(max_turns, 500)
      true -> @default_max_iterations
    end
  end

  @doc false
  @spec tool_timeout(map()) :: pos_integer()
  def tool_timeout(options) do
    case Map.get(options, :tool_timeout_ms) || Map.get(options, "tool_timeout_ms") do
      value when is_integer(value) and value > 0 -> min(value, 600_000)
      _unset -> @default_tool_timeout_ms
    end
  end

  @doc false
  @spec sandbox_mode(atom()) :: atom()
  def sandbox_mode(:default), do: :workspace_write
  def sandbox_mode(nil), do: :workspace_write
  def sandbox_mode(mode), do: mode

  @doc false
  @spec approval_mode(atom()) :: atom()
  def approval_mode(:default), do: :prompt
  def approval_mode(nil), do: :prompt
  def approval_mode(mode), do: mode

  @doc false
  @spec checkpoint_limit(map()) :: pos_integer()
  def checkpoint_limit(options), do: Checkpoint.limit(options)
end
