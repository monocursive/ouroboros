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
  """

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.CodeIntel
  alias Ouroboros.Provider.Native.Cost
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Model
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Permissions
  alias Ouroboros.Provider.Native.Prompt
  alias Ouroboros.Provider.Native.Tools
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
            "were not loaded: this workspace is not trusted. An operator can trust it with " <>
            "`config :ouroboros, :trusted_workspaces` or a `.ouroboros/trusted` file."
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

  defp record_usage(state, usage) do
    payload = Cost.payload(usage, state.model_spec)
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

  defp dispatch(state, call) do
    emit(state, :tool_call, %{
      "name" => call.name,
      "call_id" => call.id,
      "input" => call.input
    })

    case Tools.lookup(call.name, state.allowed_tools, state.disallowed_tools) do
      {:error, :unknown_tool} ->
        {:continue, tool_result(state, call, unknown_tool(call.name, state))}

      {:ok, module} ->
        case gate(state, call) do
          {:allow, state, call, classified, hook_context} ->
            # `ask_user` is answered on the approval channel rather than in the tool
            # task: it has to block on a human, and the approval path is the only thing
            # in this provider that can. See `Native.Tools.AskUser`.
            if Tools.interactive?(module),
              do: ask_question(state, call, hook_context),
              else: execute(state, call, module, classified, hook_context)

          {:deny, state, message} ->
            {:continue, tool_result(state, call, %{output: message, is_error: true})}

          {:interrupted, state} ->
            {:interrupted, state}
        end
    end
  end

  defp execute(state, call, module, classified, hook_context) do
    context = %{
      scope: state.scope,
      session_dir: state.session_dir,
      reads: state.reads
    }

    # Checkpoint before write, always, and before the language server is asked anything:
    # the baseline is a convenience and the snapshot is the thing a rewind depends on.
    state = snapshot_before(state, classified.write_paths)
    baselines = CodeIntel.baseline(classified.write_paths)

    result = Tools.execute(module, call.input, context, state.tool_timeout_ms)
    state = %{state | reads: Map.merge(state.reads, Map.get(result, :reads, %{}))}

    changes = Map.get(result, :changes, [])
    changed = Enum.flat_map(changes, fn change -> List.wrap(change["path"]) end)
    state = snapshot_after(state, changed)
    state = record_command(state, classified)

    result = append_diagnostics(result, changed, baselines)

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

    {:continue, state}
  end

  # The diagnostics report is appended only to a successful write. A failed edit has no
  # new state to describe, and appending anything after a failure is how a model comes to
  # read diagnostics as the failure itself (OpenCode #9102).
  defp append_diagnostics(%{is_error: true} = result, _changed, _baselines), do: result
  defp append_diagnostics(result, [], _baselines), do: result

  defp append_diagnostics(result, changed, baselines) do
    case CodeIntel.feedback(changed, baselines) do
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
  defp gate(state, call) do
    classified = Tools.classify(call.name, call.input, state.scope)

    case Permissions.evaluate(permission_request(state, classified)) do
      {:allow, rule} ->
        record(state, :approve, :once, :rule, rule)
        hooked(state, call, classified, :allow, nil)

      {:deny, rule} ->
        record(state, :deny, :once, :rule, rule)
        {:deny, state, Permissions.deny_message(call.name, rule)}

      {:ask, reason} ->
        hooked(state, call, classified, :ask, reason)
    end
  end

  defp hooked(state, call, classified, verdict, reason) do
    if Hooks.any?(state.hooks, :pre_tool_use, classified.tool) do
      case Hooks.pre_tool_use(state.hooks, classified.tool, call.input, hook_base(state)) do
        {:deny, hook_reason} ->
          record(state, :deny, :once, :rule, {:hook, :pre_tool_use})

          {:deny, state,
           "Refused: a PreToolUse hook denied this #{classified.tool} call: " <> hook_reason}

        # A hook's `ask` outranks the *mode*, not just the rule: `auto_approve` swallowing
        # it would make the decision meaningless in the mode people actually run.
        {:ask, hook_reason, input, context} ->
          revise(state, call, classified, input, :ask_human, hook_reason, context)

        # A hook that said `allow` resolves an engine `ask`. It can, because it is either
        # the operator's own user-scope hook or a repository hook the operator trusted —
        # the same two authorities a rule answers to. It can never resolve a `deny`,
        # because on a denial no hook was invoked at all.
        {:allow, input, context} ->
          revise(state, call, classified, input, :allow, reason, context)

        # Silence is not consent. A hook that only annotated or rewrote leaves the
        # engine's verdict exactly where it was.
        {:none, input, context} ->
          revise(state, call, classified, input, verdict, reason, context)
      end
    else
      proceed(state, call, classified, verdict, reason, [])
    end
  end

  # A hook that rewrote the input hands back a different call, so the engine sees the
  # call that will actually run and not the one the model proposed.
  defp revise(state, call, classified, input, verdict, reason, context) do
    if input == call.input do
      # Unchanged arguments keep the classification already computed: re-deriving it
      # would run `code_intel`'s rename preview a second time for nothing.
      proceed(state, call, classified, verdict, reason, context)
    else
      call = %{call | input: input}
      classified = Tools.classify(call.name, input, state.scope)

      case Permissions.evaluate(permission_request(state, classified)) do
        {:deny, rule} ->
          record(state, :deny, :once, :rule, rule)

          {:deny, state,
           "Refused: a PreToolUse hook rewrote this call's arguments and " <>
             Permissions.deny_message(call.name, rule)}

        {:allow, _rule} ->
          proceed(state, call, classified, verdict, reason, context)

        {:ask, engine_reason} ->
          proceed(state, call, classified, narrow(verdict), reason || engine_reason, context)
      end
    end
  end

  # A re-evaluated call that the engine now only allows conditionally cannot keep a
  # verdict of `allow` it earned before the rewrite.
  defp narrow(:ask_human), do: :ask_human
  defp narrow(_allow_or_ask), do: :ask

  defp proceed(state, call, classified, :allow, _reason, context),
    do: {:allow, state, call, classified, context}

  defp proceed(state, call, classified, :ask_human, reason, context),
    do: ask(state, call, classified, reason || :no_engine, context)

  defp proceed(state, call, classified, :ask, reason, context),
    do: decide(state, call, classified, reason || :no_engine, context)

  # What `:ask` means before a rule engine exists. A tool with no effect outside this
  # process — `read`, `plan` — runs; anything that writes a file or executes a command
  # asks. Fail-closed is about effects, and prompting for every file read would make the
  # provider unusable without making it safer: the model already has the transcript.
  defp decide(state, call, classified, reason, context) do
    cond do
      classified.mode == :read ->
        {:allow, state, call, classified, context}

      MapSet.member?(state.session_grants, grant_key(classified)) ->
        record(state, :approve, :session, :human, {:session_grant, classified.tool})
        {:allow, state, call, classified, context}

      state.approval_mode == :auto_approve ->
        record(state, :approve, :once, :rule, {:mode, :auto_approve})
        {:allow, state, call, classified, context}

      state.approval_mode == :auto_edit and auto_editable?(state, classified) ->
        record(state, :approve, :once, :rule, {:mode, :auto_edit})
        {:allow, state, call, classified, context}

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
        record(state, :approve, response.scope, :human, nil)
        {:allow, state, call, classified, context}

      {:native_approval, ^request_id, %ApprovalResponse{} = response} ->
        record(state, :deny, response.scope, :human, nil)

        {:deny, state,
         "Refused: the operator denied this #{classified.tool} call" <>
           reason_suffix(response.reason) <> "."}

      {:native_approval, _other_id, _response} ->
        wait_for_approval(state, call, request_id, classified, context, deadline)

      :native_interrupt ->
        {:interrupted, %{state | interrupted?: true}}

      {:native_steer, text} ->
        state = %{state | steer: state.steer ++ [text]}
        wait_for_approval(state, call, request_id, classified, context, deadline)
    after
      remaining ->
        record(state, :deny, :once, :rule, {:timeout, state.approval_timeout_ms})

        {:deny, state,
         "Refused: nobody answered the approval request within " <>
           "#{state.approval_timeout_ms} ms, so it was denied."}
    end
  end

  # ---------------------------------------------------------------- questions

  # `ask_user` rides the approval channel: the same `approval_requested` event, the same
  # `respond_approval` verb, the same wait, with `kind: "question"` so a client that has
  # learned about questions can render a picker and one that has not still shows a modal
  # whose approve-with-a-reason is the answer.
  defp ask_question(state, call, hook_context) do
    case AskUser.question(call.input) do
      {:error, :empty_question} ->
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
          deadline(state.approval_timeout_ms)
        )
    end
  end

  defp wait_for_answer(state, call, request_id, payload, hook_context, deadline) do
    remaining = remaining(deadline)

    receive do
      {:native_approval, ^request_id, %ApprovalResponse{} = response} ->
        result = payload |> AskUser.answer(response) |> Tools.normalize_result_of()
        {:continue, tool_result(state, call, append_context(result, hook_context))}

      {:native_approval, _other_id, _response} ->
        wait_for_answer(state, call, request_id, payload, hook_context, deadline)

      :native_interrupt ->
        {:interrupted, %{state | interrupted?: true}}

      {:native_steer, text} ->
        state = %{state | steer: state.steer ++ [text]}
        wait_for_answer(state, call, request_id, payload, hook_context, deadline)
    after
      remaining ->
        result =
          payload
          |> AskUser.unanswered(state.approval_timeout_ms)
          |> Tools.normalize_result_of()

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

  defp record(state, decision, scope, actor, rule_ref) do
    decision_id =
      "ndec_" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)

    _ =
      Permissions.record(decision_id, %{
        decision: decision,
        scope: scope,
        actor: actor,
        rule_ref: rule_ref,
        reason: nil,
        session_id: state.session_id,
        provider: :native
      })

    :ok
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
      session_grants: state.session_grants
    })

    :ok
  end

  # ---------------------------------------------------------------- helpers

  defp tool_specs(%{tool_specs: specs}) when is_list(specs), do: specs
  defp tool_specs(state), do: build_tool_specs(state)

  # The workspace reaches the specs so `skill` can put its catalogue in its description.
  # Everything else's description is static.
  defp build_tool_specs(state),
    do: Tools.specs(state.allowed_tools, state.disallowed_tools, workspace: state.scope.root)

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
         {:ok, system} <-
           Prompt.build(
             system_prompt: request.system_prompt,
             cwd: scope.root,
             add_dirs: scope.roots -- [scope.root],
             sandbox_mode: scope.sandbox_mode,
             approval_mode: approval_mode(request.approval_mode),
             tools: Tools.specs(request.allowed_tools, request.disallowed_tools)
           ),
         {:ok, model_spec} <- resolve_model(request.model),
         {:ok, session_dir, _durable?} <- Paths.session_dir(provider_session_id) do
      options = Map.new(request.provider_options || %{})

      state = %__MODULE__{
        emit: fn _event -> :ok end,
        model_module: Model.module(),
        model_spec: model_spec,
        system: system,
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
