defmodule Ouroboros.Interactive.Task.Approvals do
  @moduledoc false

  require Logger

  alias Jido.Harness.Session
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Interactive.{Event, State}
  alias Ouroboros.Interactive.Task
  alias Ouroboros.Workspace.Exec

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

  def request(runtime, request_ref, request, from) do
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

  def respond_external(runtime, request_id, response) do
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

    close_external_approval(runtime, request_id, decision, :human, reason, scope, effect_id)
  end

  def respond_provider(runtime, request_id, response) do
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

    reply =
      Task.with_harness_session(runtime, &Session.respond_approval(&1, request_id, response))

    {reply, Task.schedule_poll(runtime, 0)}
  end

  # ---------------------------------------------------------------------------
  # C2 — the external-approval path
  #
  # A managed transport such as Claude runs one process per turn and may declare no
  # approvals channel, so Harness cannot ask before a tool runs. Claude Code offers
  # `--permission-prompt-tool` instead; `ouro mcp-serve` is that tool's server.
  # Calls land here. The runtime relays; it does not decide, except where C1's rule
  # engine already decided or a bound was reached.
  # ---------------------------------------------------------------------------

  defp open_external_approval(runtime, request_ref, request, from) do
    request_id = "ouro-approval-" <> Jido.Signal.ID.generate!()
    verdict = evaluate_permission(runtime, request)

    case Task.emit_runtime_event(
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

  def close_external_approval(
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

    case Task.emit_runtime_event(runtime, :approval_resolved, payload,
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

  def permissions_engine(function, arity) do
    engine =
      Application.get_env(:ouroboros, :permissions_engine, @default_permissions_engine)

    if is_atom(engine) and not is_nil(engine) and Code.ensure_loaded?(engine) and
         function_exported?(engine, function, arity),
       do: engine
  end

  # Best effort by construction: the pending table is memory, so the durable trace of an
  # unanswered question is an `approval_requested` this runtime minted with no matching
  # `approval_resolved` after it. A journal trimmed to `event_limit` can have lost the
  # pair, and then there is nothing to close — which is the same honest silence as a
  # session whose events aged out.
  def deny_orphaned_external_approvals(runtime) do
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

    case Task.safe_ledger(write) do
      {:ok, _entry, _disposition} ->
        {effect_id, remember_approval_effect(runtime, request_id, effect_id)}

      other ->
        Logger.warning(
          "interactive session #{session.id} could not record the answer to approval " <>
            "#{request_id} in the effect ledger (#{inspect(Task.durable(other))}); the answer " <>
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
  def enrich_approval_resolved(
        %Event{type: :approval_resolved, request_id: request_id} = event,
        effects
      )
      when is_binary(request_id) do
    case Map.get(effects, request_id) do
      nil -> event
      effect_id -> %{event | payload: Map.put(event.payload, "ledger_ref", ledger_ref(effect_id))}
    end
  end

  def enrich_approval_resolved(event, _effects), do: event

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
end
