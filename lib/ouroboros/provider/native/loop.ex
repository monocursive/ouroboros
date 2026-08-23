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

  `max_iterations` (default 50) caps model round-trips per turn. `tool_timeout_ms` caps
  one tool. The doom-loop guard stops a turn on the third identical `(name, input)`
  call — OpenCode's rule, and the cheapest defence against a model that has found a
  loop it likes. Each bound fails the turn by name rather than running out quietly.

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
  alias Ouroboros.Provider.Native.Context
  alias Ouroboros.Provider.Native.Context.Instructions
  alias Ouroboros.Provider.Native.Context.Window
  alias Ouroboros.Provider.Native.CodeIntel
  alias Ouroboros.Provider.Native.Cost
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Permissions
  alias Ouroboros.Provider.Native.Sandbox
  alias Ouroboros.Provider.Native.Subagent
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.Agent, as: AgentTool
  alias Ouroboros.Provider.Native.Tools.AgentResult
  alias Ouroboros.Provider.Native.Tools.AskUser

  @default_max_iterations 50
  @default_tool_timeout_ms 120_000
  @doom_loop_repeats 3
  @max_injected_context_bytes 8 * 1024

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
  @spec run_turn(t(), String.t()) :: {:ok, t()}
  def run_turn(%__MODULE__{} = state, prompt) do
    state = %{
      state
      | hooks: state.hooks || Hooks.load(state.scope.root),
        tool_specs: build_tool_specs(state),
        turn_files: %{},
        turn_paths: [],
        turn_commands: []
    }

    prompt = prompt <> injected(Hooks.notify(state.hooks, :user_prompt_submit, hook_base(state)))
    state = %{state | messages: state.messages ++ [%{role: :user, content: prompt}]}

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
        case call_model(state) do
          {:ok, state, text, calls} ->
            state = append_assistant(state, text, calls)

            if calls == [] do
              complete(state, iteration)
            else
              case run_tools(state, calls) do
                {:continue, state} -> iterate(apply_steer(state), iteration + 1)
                {:interrupted, state} -> interrupted(state)
                {:failed, state, message, reason} -> fail(state, message, reason)
              end
            end

          {:error, state, reason} ->
            fail(state, "model call failed: #{describe(reason)}", "model_error")
        end
    end
  end

  # ---------------------------------------------------------------- model

  defp call_model(state) do
    request = %{
      model: state.model_spec,
      system: state.system,
      messages: state.messages,
      tools: tool_specs(state),
      reasoning_effort: state.reasoning_effort,
      max_tokens: nil
    }

    case Model.stream(state.model_module, request, []) do
      {:ok, stream} -> consume(state, stream)
      {:error, reason} -> {:error, state, reason}
    end
  end

  defp consume(state, stream) do
    {text, calls, usages} =
      Enum.reduce(stream, {[], [], []}, fn chunk, {text, calls, usages} ->
        case chunk do
          {:text, delta} when is_binary(delta) and delta != "" ->
            emit(state, :output_text_delta, %{"text" => delta})
            {[text, delta], calls, usages}

          {:thinking, delta} when is_binary(delta) and delta != "" ->
            emit(state, :thinking_delta, %{"text" => delta})
            {text, calls, usages}

          {:tool_call, call} ->
            {text, calls ++ [call], usages}

          {:usage, usage} ->
            {text, calls, usages ++ [usage]}

          _ignored ->
            {text, calls, usages}
        end
      end)

    final = IO.iodata_to_binary(text)
    if final != "", do: emit(state, :output_text_final, %{"text" => final})

    # Usage arrives in a provider's last meta chunk, but the assembled final message is
    # what a reader wants first. Emitting the accounting after the message keeps the
    # transcript in the order a person reads it, and costs nothing: both are terminal to
    # this model response.
    {:ok, Enum.reduce(usages, state, &record_usage(&2, &1)), final, calls}
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

  defp append_assistant(state, text, []) when text == "", do: state

  defp append_assistant(state, text, calls) do
    %{
      state
      | messages: state.messages ++ [%{role: :assistant, content: text, tool_calls: calls}]
    }
  end

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
          # Classified once, here, and handed to the gate: re-deriving it would run
          # `code_intel`'s rename preview a second time for nothing.
          classified = Tools.classify(call.name, call.input, state.scope)
          effect_id = tool_effect_id(state, call)
          emit_tool_call(state, call, effect_id)

          gated(state, call, module, classified, effect_id)
        end
    end
  end

  defp depth_capped?(state, module) when module in [AgentTool, AgentResult],
    do: is_integer(state.subagent_depth) and state.subagent_depth >= AgentTool.max_depth()

  defp depth_capped?(_state, _module), do: false

  defp gated(state, call, module, classified, effect_id) do
    case gate(state, call, classified) do
      {:allow, state, call, classified, hook_context, authority} ->
        case open_tool_effect(state, call, classified, effect_id, authority) do
          :ok ->
            # Two tools are answered by this process rather than in the tool task, and
            # both for the same reason: they block on something only this process can
            # reach. `ask_user` blocks on a human through the approval path; `agent`
            # blocks on a child session whose own approvals travel that same path.
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

      {:deny, state, message, classified, authority} ->
        refuse_tool_effect(state, call, classified, effect_id, authority)
        {:continue, tool_result(state, call, %{output: message, is_error: true})}

      {:interrupted, state, classified} ->
        refuse_tool_effect(state, call, classified, effect_id, interrupted_authority())
        {:interrupted, state}
    end
  end

  defp execute(state, call, module, classified, hook_context, effect_id) do
    context = %{
      scope: state.scope,
      session_dir: state.session_dir,
      reads: state.reads,
      # G3. `agent_result` collects a child the *session* holds, not one this turn owns,
      # so it is handed two closures over the session rather than a pid to call: the tool
      # never learns which process tracks what, and a run with no session gets `nil` and
      # says so instead of failing obscurely.
      subagents: subagent_handles(state)
    }

    # Checkpoint before write, always, and before the language server is asked anything:
    # the baseline is a convenience and the snapshot is the thing a rewind depends on.
    state = snapshot_before(state, classified.write_paths)
    baselines = CodeIntel.baseline(classified.write_paths, root: state.scope.root)

    started = System.monotonic_time(:millisecond)
    result = Tools.execute(module, call.input, context, state.tool_timeout_ms)
    elapsed = System.monotonic_time(:millisecond) - started

    # Settled before the result is broadcast, and against the tool's own output rather
    # than the annotated one: diagnostics and hook context are this runtime talking, and
    # counting them as the tool's bytes would misreport what ran.
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
          call.input,
          %{"output" => result.output, "is_error" => result.is_error},
          hook_base(state)
        ) ++ hook_context
      )

    # `tool_result` first so it sits directly under its `tool_call` — the pairing every
    # consumer keys on — and the operator-facing diff or plan follows it.
    state = tool_result(state, call, result)
    state = emit_changes(state, changes)
    state = emit_plan(state, Map.get(result, :plan))
    state = inject_rules(state, Map.get(result, :reads, %{}))

    {:continue, state}
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
    emit(state, :tool_result, %{
      "name" => call.name,
      "call_id" => call.id,
      "output" => result.output,
      "is_error" => result.is_error
    })

    %{
      state
      | messages:
          state.messages ++
            [
              %{
                role: :tool,
                tool_call_id: call.id,
                name: call.name,
                content: result.output,
                is_error: result.is_error
              }
            ]
    }
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
      case Hooks.pre_tool_use(state.hooks, classified.tool, call.input, hook_base(state)) do
        {:deny, hook_reason} ->
          ref = {:hook, :pre_tool_use}

          {:deny, state,
           "Refused: a PreToolUse hook denied this #{classified.tool} call: " <> hook_reason,
           classified,
           authority(:deny, "hook", :once, :rule, ref, record(state, :deny, :once, :rule, ref))}

        # A hook's `ask` outranks the *mode*, not just the rule: `auto_approve` swallowing
        # it would make the decision meaningless in the mode people actually run.
        {:ask, hook_reason, input, context} ->
          revise(state, call, classified, input, :ask_human, hook_reason, context, authority)

        # A hook that said `allow` resolves an engine `ask`. It can, because it is either
        # the operator's own user-scope hook or a repository hook the operator trusted —
        # the same two authorities a rule answers to. It can never resolve a `deny`,
        # because on a denial no hook was invoked at all.
        {:allow, input, context} ->
          revise(state, call, classified, input, :allow, reason, context, hook_allowed(authority))

        # Silence is not consent. A hook that only annotated or rewrote leaves the
        # engine's verdict exactly where it was.
        {:none, input, context} ->
          revise(state, call, classified, input, verdict, reason, context, authority)
      end
    else
      proceed(state, call, classified, verdict, reason, [], authority)
    end
  end

  # A hook that rewrote the input hands back a different call, so the engine sees the
  # call that will actually run and not the one the model proposed.
  defp revise(state, call, classified, input, verdict, reason, context, authority) do
    if input == call.input do
      # Unchanged arguments keep the classification already computed: re-deriving it
      # would run `code_intel`'s rename preview a second time for nothing.
      proceed(state, call, classified, verdict, reason, context, authority)
    else
      call = %{call | input: input}
      classified = Tools.classify(call.name, input, state.scope)

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
      classified.mode == :read ->
        {:allow, state, call, classified, context,
         authority(:allow, "read", :once, :runtime, {:mode, :read}, nil)}

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

    emit(
      state,
      :approval_requested,
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
        "reason" => reason_text(reason),
        "suggested_rule" =>
          Permissions.suggested_rule(classified.tool, classified.command, classified.paths)
      },
      request_id
    )

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
      deadline(state.approval_timeout_ms)
    )
  end

  defp wait_for_approval(state, call, request_id, classified, context, deadline) do
    remaining = remaining(deadline)

    receive do
      {:native_approval, ^request_id, %ApprovalResponse{decision: :approve} = response} ->
        state = grant(state, classified, response.scope)

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
        wait_for_approval(state, call, request_id, classified, context, deadline)

      :native_interrupt ->
        {:interrupted, %{state | interrupted?: true}, classified}

      {:native_steer, text} ->
        state = %{state | steer: state.steer ++ [text]}
        wait_for_approval(state, call, request_id, classified, context, deadline)
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

  defp new_request_id,
    do: "napp_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

  defp grant(state, classified, :session),
    do: %{state | session_grants: MapSet.put(state.session_grants, grant_key(classified))}

  defp grant(state, _classified, _once), do: state

  # A session-scope approval lives in this process only. It is deliberately *not* durable
  # here: the durable home for "always allow this" is a rule in
  # `Ouroboros.Control.Permissions`, and writing a second, weaker store beside it would
  # be the thing to delete when that engine lands.
  defp grant_key(classified) do
    {classified.tool, classified.command, Enum.sort(classified.paths)}
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
      context: %{
        approval_mode: state.approval_mode,
        sandbox_mode: state.scope.sandbox_mode,
        workspace: state.scope.root,
        turn_id: state.turn_id
      }
    }
  end

  defp approval_kind("bash"), do: "command"
  defp approval_kind(name) when name in ["write", "edit", "apply_patch"], do: "file_change"
  defp approval_kind(_name), do: "tool"

  defp reason_text(:no_engine),
    do: "no permission rule engine is configured on this node, so every gated tool asks"

  defp reason_text({:engine_error, message}),
    do: "the permission engine could not decide (#{message}), so this is being asked"

  defp reason_text(reason) when is_binary(reason), do: reason
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

      {:error, reason} ->
        refuse_subagent(
          state,
          call,
          hook_context,
          effect_id,
          "Refused: the subagent could not be started (#{inspect(reason)}). Nothing ran, " <>
            "and there is no task to collect."
        )
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
      # the least this runtime knows to be true about it, said as such.
      {:error, _unreachable} ->
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
        "model" => spec.request.model,
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
      "provider_session_id" => spec.request.provider_session_id
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
           provider_session_id: started.provider_session_id
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
  defp ledger_ref(effect_id), do: %{"node" => Atom.to_string(node()), "id" => effect_id}

  # C5. A `bash` call says which OS sandbox it runs under — `sandbox-exec`, `bwrap`, or
  # `none` — on the event a client draws, so "no OS sandbox" is a fact read off the row
  # rather than a guess about the node. Other tools carry no such key: this runtime runs
  # them itself, inside its own boundary.
  defp emit_tool_call(state, call, effect_id) do
    emit(
      state,
      :tool_call,
      %{
        "name" => call.name,
        "call_id" => call.id,
        "input" => call.input,
        "ledger_ref" => effect_id && ledger_ref(effect_id)
      }
      |> Map.merge(Sandbox.tool_call_marker(call.name, state.scope))
      |> reject_nils()
    )
  end

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
  # never appear at all.
  defp tool_subject(classified) do
    %{}
    |> put_subject(:paths, Enum.filter(classified.paths, &is_binary/1))
    |> put_subject(:command_sha256, command_digest(classified.command))
    |> put_subject(:hosts, Map.get(classified, :domains, []))
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
    bytes = byte_size(to_string(Map.get(result, :output, "")))

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
      {:native_steer, text} -> drain_control(%{state | steer: state.steer ++ [text]})
    after
      0 -> state
    end
  end

  # The steered text becomes an ordinary user message after the tool results it
  # interrupted, so the next model call reads it as the operator speaking mid-task.
  defp apply_steer(%{steer: []} = state), do: state

  defp apply_steer(state) do
    messages =
      state.messages ++ Enum.map(state.steer, &%{role: :user, content: &1})

    %{state | messages: messages, steer: []}
  end

  # ---------------------------------------------------------------- terminals

  defp complete(state, iterations) do
    state = state |> run_checks() |> settle()

    emit(state, :turn_completed, %{
      "status" => "completed",
      "iterations" => iterations,
      "input_tokens" => state.usage.input,
      "output_tokens" => state.usage.output,
      "cost_usd" => Float.round(state.usage.cost, 6)
    })

    {:ok, state}
  end

  defp interrupted(state) do
    state = %{state | interrupted?: true} |> settle()
    emit(state, :turn_interrupted, %{"reason" => "interrupted"})
    {:ok, state}
  end

  defp fail(state, message, reason) do
    state = settle(state)
    emit(state, :turn_failed, %{"error" => message, "reason" => reason})
    {:ok, state}
  end

  # Everything that has to be true before the terminal event reaches a subscriber: the
  # file manifest written, the `Stop` hooks run, the conversation checkpointed. The
  # conversation goes last, because a `Stop` hook's `additionalContext` becomes part of
  # it and a checkpoint written before that would resume without it.
  defp settle(state) do
    state = record_turn_files(state)
    state = inject(state, Hooks.notify(state.hooks, :stop, hook_base(state)))
    persist(state)
    state
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
           message_count: length(state.messages),
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

    :ok
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

  defp emit(state, type, payload, request_id \\ nil) do
    state.emit.(%{type: type, payload: payload, turn_id: state.turn_id, request_id: request_id})
    :ok
  end

  defp reject_nils(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) end)

  defp deadline(:infinity), do: :infinity
  defp deadline(ms), do: System.monotonic_time(:millisecond) + ms

  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp describe({:stream_failed, message}), do: message
  defp describe({:stream_exited, reason}), do: reason
  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  # ---------------------------------------------------------------- coding plane

  @doc """
  Runs one finite coding-plane request and returns its event stream.

  The loop runs in a task; the stream is that task's events. `Stream.resource/3` ties
  the task's life to the consumer, so a run the caller stops reading is torn down rather
  than left streaming into nobody's mailbox.
  """
  @spec run_stream(Jido.Harness.RunRequest.t(), map()) ::
          {:ok, Enumerable.t()} | {:error, term()}
  def run_stream(request, context) do
    with {:ok, state, provider_session_id} <- build_run_state(request, context) do
      turn_id = "turn_" <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

      {:ok,
       Stream.resource(
         fn -> start_run_task(state, request.prompt, turn_id) end,
         &next_run_event(&1, context.provider, provider_session_id),
         &stop_run_task/1
       )}
    end
  end

  # `async_nolink` deliberately: a loop that crashes must fail this run, not take the
  # harness run worker's stream consumer down with it. The monitor is what ends the
  # stream in that case, and the `:DOWN` reason becomes the run's failure.
  defp start_run_task(state, prompt, turn_id) do
    consumer = self()
    reference = make_ref()

    emit = fn event -> send(consumer, {:native_run_event, reference, event}) end

    task =
      Task.Supervisor.async_nolink(Jido.Harness.SessionTaskSupervisor, fn ->
        run_turn(%{state | emit: emit, turn_id: turn_id}, prompt)
      end)

    %{task: task, reference: reference, turn_id: turn_id, done?: false}
  end

  defp next_run_event(%{done?: true} = acc, _provider, _provider_session_id), do: {:halt, acc}

  defp next_run_event(acc, provider, provider_session_id) do
    reference = acc.reference
    task_ref = acc.task.ref

    receive do
      {:native_run_event, ^reference, event} ->
        harness_event = to_event(event, provider, provider_session_id)
        done? = event.type in [:turn_completed, :turn_failed, :turn_interrupted]
        {[harness_event], %{acc | done?: done?}}

      {^task_ref, {:ok, _state}} ->
        Process.demonitor(task_ref, [:flush])
        {[], %{acc | done?: true}}

      {:DOWN, ^task_ref, :process, _pid, :normal} ->
        {[], %{acc | done?: true}}

      {:DOWN, ^task_ref, :process, _pid, reason} ->
        event = %{
          type: :turn_failed,
          payload: %{"error" => "native loop crashed: #{inspect(reason)}", "reason" => "crash"},
          turn_id: acc.turn_id,
          request_id: nil
        }

        {[to_event(event, provider, provider_session_id)], %{acc | done?: true}}
    end
  end

  defp stop_run_task(%{task: task}) do
    _ = Task.shutdown(task, :brutal_kill)
    :ok
  end

  @doc """
  Builds the harness event for one loop event, redacted at this boundary.

  `Jido.Harness.EventStore` redacts again before anything is journaled, so this is
  belt and braces — but it is the same belt `Ouroboros.Provider.CodexAdapter` already
  wears, and for the same reason: a `bash` result is a normal tool result that this
  runtime puts on the wire, and a command that echoed `$ANTHROPIC_API_KEY` must not
  reach a live subscriber in the clear on its way to a journal that would have caught
  it. `Redaction.redact/1` covers this node's own sensitive environment values.
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

  defp build_run_state(request, context) do
    provider_session_id =
      request.provider_session_id || Paths.new_session_id()

    with {:ok, scope} <-
           Paths.scope(
             request.cwd,
             request.add_dirs,
             sandbox_mode(request.sandbox_mode)
           ),
         {:ok, model_spec} <- resolve_model(request.model),
         {:ok, prefix} <-
           Context.build(
             system_prompt: request.system_prompt,
             cwd: scope.root,
             add_dirs: scope.roots -- [scope.root],
             sandbox_mode: scope.sandbox_mode,
             approval_mode: approval_mode(request.approval_mode),
             tools: Tools.specs(request.allowed_tools, request.disallowed_tools),
             model_module: Model.module(),
             model_spec: model_spec,
             reasoning_effort: request.reasoning_effort
           ),
         {:ok, session_dir, _durable?} <- Paths.session_dir(provider_session_id) do
      options = Map.new(request.provider_options || %{})

      state = %__MODULE__{
        emit: fn _event -> :ok end,
        model_module: Model.module(),
        model_spec: model_spec,
        system: prefix.system,
        tool_specs: prefix.tools,
        context_window: prefix.context_window,
        rules: Context.rules(prefix),
        scope: scope,
        session_dir: session_dir,
        session_id: context.run_id,
        provider_session_id: provider_session_id,
        reasoning_effort: request.reasoning_effort,
        approval_mode: approval_mode(request.approval_mode),
        allowed_tools: request.allowed_tools,
        disallowed_tools: request.disallowed_tools,
        max_iterations: max_iterations(options, request.max_turns),
        tool_timeout_ms: tool_timeout(options)
      }

      {:ok, state, provider_session_id}
    end
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
