defmodule Ouroboros.Provider.Session.Dialect.Codex do
  @moduledoc """
  Wire mapping for the Codex app server.

  Every method, parameter and enum here is taken from the schema the protocol's own
  generator emits — `codex app-server generate-json-schema --out <dir>`, codex-cli
  0.147.0 — and the files it produced for the methods this dialect speaks are committed
  verbatim under `test/support/codex_schema/`, so the tests check frames against the
  schema rather than against a literal they also wrote.

  ## How an approval answer becomes two durable facts

  One human answer has to move two policies, or the "don't ask again" it offers is only
  half true. `scope: :session` on a command approval therefore does both:

    * **Codex's own policy** — this dialect's reply. When the request carried a
      `proposedExecpolicyAmendment`, the reply is
      `{"decision": {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": [...]}}}`,
      which amends the app server's execpolicy so commands matching that argv prefix stop
      being asked about. With no proposal in the request the reply is `acceptForSession`,
      which fills the app server's session approval cache with this one command instead.
    * **This runtime's own policy** — `Ouroboros.Control.Permissions.Seam.answered/4`,
      reached from `Session.Jsonl` on the same reply. It writes a `:session`-scope C1 rule
      through `Permissions.remember/4`, so the next identical request is answered by the
      engine and never reaches a human. That path is transport-neutral and shared with
      ACP; nothing about it is Codex-specific, which is why this dialect does not write
      rules itself.

  The two are deliberately the same scope and expire together: `Seam.forget_session/0`
  drops the rule when this transport terminates, and the app server's amendment and cache
  die with the thread. The C1 rule is derived from the command by `Permissions.suggest/1`
  (`Bash(git status *)`) while the amendment is the prefix Codex proposed
  (`["git", "status"]`) — two spellings of the same intent, each in the language of the
  policy it is written into.

  Only a human's answer can reach either. A rule that already says yes replies `accept`,
  the narrowest grant that answers the question, because widening a provider's own policy
  is not something a rule may do on a human's behalf.
  """

  @behaviour Ouroboros.Provider.Session.Dialect

  alias Jido.Harness.{Event, InteractionCapabilities, TurnRequest}
  alias Ouroboros.Control.Permissions.Seam

  @approval_methods [
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval"
  ]

  # The `localImage` input arm carries a path, not a declared media type, so which
  # attachments count as images is Ouroboros's own choice: these raster formats. Anything
  # else is treated as a file, which the union has no arm for; see `turn_input/1`.
  @image_extensions ~w(.png .jpg .jpeg .gif .webp)

  # One turn carries at most this many attachment items. The overflow is counted in the
  # trailing text item rather than dropped in silence.
  @max_attachment_items 64

  # What `turn_params/2` rebuilds from the session request on every turn, and therefore
  # exactly what a mid-session configuration change can move here.
  @configurable_fields [:model, :reasoning_effort, :approval_mode, :sandbox_mode]

  # An execpolicy amendment is an argv prefix. These bounds are what a prefix plausibly
  # is; a proposal outside them is refused rather than trimmed, because a trimmed prefix
  # allows strictly more than the one the app server offered.
  @max_amendment_tokens 32
  @max_amendment_token_bytes 256

  # How many filesystem entries a permissions escalation shows in the modal. The rest are
  # counted in `not_shown` rather than dropped without saying so.
  @max_permission_entries 32

  # `PermissionsRequestApprovalResponse` requires `permissions`, so a refusal is not an
  # absent field but an empty `GrantedPermissionProfile`: every optional grant withheld.
  @no_permissions %{"permissions" => %{}}

  @impl true
  def name, do: :app_server

  @impl true
  def ready_kind, do: "codex_app_server_ready"

  @impl true
  def unsupported_method_message,
    do: "Ouroboros serves no app-server methods on this connection"

  @impl true
  def capabilities do
    InteractionCapabilities.new!(
      transport: :app_server,
      process: :persistent,
      multi_turn: :native,
      follow_up: :managed,
      steer: :native,
      interrupt: :native,
      approvals: :native,
      multimodal: :native,
      dynamic_model: :managed,
      dynamic_configuration: :managed
    )
  end

  @impl true
  def command(request, context) do
    # `approval_request/2` sees only a method and params, so the session this process
    # speaks for is remembered here, in `Session.Jsonl.init/1`, where both are in hand.
    _ = Seam.bind(request, context, name())

    path =
      option(request.provider_options, :cli_path) ||
        Map.get(context.config, :cli_path) ||
        Map.get(context.config, "cli_path") ||
        "codex"

    {:ok, path, ["app-server", "--stdio"], %{}}
  end

  @impl true
  def envelope(message), do: message

  @impl true
  def initialize_params(_request) do
    %{
      "clientInfo" => %{
        "name" => "ouroboros",
        "title" => "Ouroboros",
        "version" => Application.spec(:ouroboros, :vsn) |> to_string()
      }
    }
  end

  @doc """
  The provider option that turns this dialect's handshake into a branch.

  Not a `Dialect` callback: `Dialect.verify!/1` pins an exact callback list, and a dialect
  whose protocol has no branch verb has nothing to answer here. `Ouroboros.Provider` asks
  for it by `function_exported?/3`, so `fork: :native` on the app-server transport is this
  dialect's own declaration rather than a table in the gateway.
  """
  @spec fork_option() :: {atom(), term()}
  def fork_option, do: {:fork, true}

  @doc """
  This dialect's declaration that the *provider* can fold its own thread.

  Read by `Ouroboros.Provider.compact_capability/1`, which is what
  `Ouroboros.Interactive.Task` branches on. The value names who does the work: `:provider`,
  never `:native` — the app server summarises its own thread and this runtime only asks,
  so the report it produces says so instead of borrowing the native path's token counts.
  """
  @spec compact_option() :: {atom(), atom()}
  def compact_option, do: {:compact, :provider}

  @doc """
  The frame that folds this thread's context, for a runtime that can route one here.

  **Nothing calls this yet, and no capability claims otherwise.** `interactive.compact`
  reaches `Ouroboros.Interactive.Task`, which gates compaction on
  `native_transport(session, :compact)` and refuses every other transport with
  `{:unsupported_on_transport, …}` — only a native session hands this runtime the
  conversation to fold. There is no `compact` key in `InteractionCapabilities` and none
  in `Ouroboros.Provider`'s public capability set, so a Codex session correctly reports
  no compaction today and this function changes nothing about that.

  It exists because the app server's half is knowable and now pinned:
  `thread/compact/start` takes `{threadId}` and answers `{}`
  (`v2/ThreadCompactStartParams.json`, codex-cli 0.147.0). Routing to it is one clause in
  `Task.handle_call({:compact, focus})` — beside the `native_transport/2` call, a branch
  that asks the session transport for this frame instead — plus a `:compact` derived
  capability in `Ouroboros.Provider` so the refusal stays declaration-shaped. Both are
  another agent's files this wave, so this is the half that could land honestly.

  `focus` has nowhere to go: the app server takes no focus argument, so a runtime that
  wires this up must refuse a focused compaction on this transport rather than quietly
  compact without it.
  """
  @spec compact_request(runtime :: map()) :: {:request, String.t(), map()} | {:error, term()}
  def compact_request(%{provider_session_id: thread_id}) when is_binary(thread_id),
    do: {:request, "thread/compact/start", %{"threadId" => thread_id}}

  def compact_request(_runtime), do: {:error, :session_not_open}

  @doc """
  The frame that asks the app server which models it offers, and the reader for its answer.

  **Not wired to `runtime.models`, and deliberately.** That method answers from
  `Ouroboros.Models.list/0` — a packaged `llm_db` snapshot, keyed by a static
  provider-to-catalogue table, with `source: "llm_db"` stated in the reply. It is a
  process-free read of a local catalogue. `model/list` is the opposite: it needs a live
  `codex app-server` on the other end of a thread, and its answer is what *this account*
  may use, including whether each model is hidden, its service tiers, and its supported
  reasoning efforts — things no static catalogue knows.

  Bridging them honestly needs a seam that does not exist: `Models.provider_models/1`
  has no hook for a transport to contribute rows, and folding live rows into a reply
  labelled `source: "llm_db"` would misdescribe where they came from. The seam worth
  building is a per-provider one — a `models/1` on the adapter, consulted when a session
  is open, with its own `source` — rather than a special case inside `runtime.models`.

  `limit` and `includeHidden` are sent only when stated, because the schema's own
  defaults are the server's to choose (`v2/ModelListParams.json`, codex-cli 0.147.0).
  """
  @spec model_list_request(keyword()) :: {:request, String.t(), map()}
  def model_list_request(options \\ []) do
    params =
      %{}
      |> maybe_put("limit", Keyword.get(options, :limit))
      |> maybe_put("cursor", Keyword.get(options, :cursor))

    params =
      case Keyword.get(options, :include_hidden) do
        hidden when is_boolean(hidden) -> Map.put(params, "includeHidden", hidden)
        _unstated -> params
      end

    {:request, "model/list", params}
  end

  @doc """
  Reads a `model/list` result into the rows a picker needs.

  The rows are under `data`, not `models` — `ModelListResponse` requires exactly that key,
  and the live app server answers with it. Every field but `id` is dropped when absent
  rather than shown as `nil`, so a row is what the server said and not a shape padded out
  to look complete. `next_cursor` is echoed so a caller can page.
  """
  @spec models(map()) :: %{models: [map()], next_cursor: String.t() | nil}
  def models(result) when is_map(result) do
    rows =
      case result["data"] do
        list when is_list(list) -> Enum.flat_map(list, &model_row/1)
        _absent -> []
      end

    %{models: rows, next_cursor: result["nextCursor"]}
  end

  def models(_result), do: %{models: [], next_cursor: nil}

  defp model_row(%{"id" => id} = model) when is_binary(id) do
    [
      %{
        id: id,
        model: model["model"],
        display_name: model["displayName"],
        description: model["description"],
        default: model["isDefault"] == true,
        hidden: model["hidden"] == true,
        default_reasoning_effort: model["defaultReasoningEffort"],
        input_modalities: model["inputModalities"] || []
      }
      |> Map.reject(fn {_key, value} -> is_nil(value) end)
    ]
  end

  defp model_row(_model), do: []

  # Three ways to open, and the request says which. `thread/fork` branches a thread's
  # history into a new thread id, taking `threadId` and optional `lastTurnId`/`ephemeral`
  # (https://developers.openai.com/codex/app-server, verified 2026-08-22); the fork
  # inherits the parent thread's settings, and `turn_params/2` supplies model, effort,
  # approval policy and sandbox on every turn regardless. `lastTurnId` is deliberately not
  # sent: `interactive.fork` branches at the tail, and choosing a turn to branch from is
  # the backtrack menu's question (B5), not this one's.
  @impl true
  def after_initialize(_result, request, _runtime) do
    {method, params} =
      cond do
        fork?(request) and is_binary(request.provider_session_id) ->
          {"thread/fork", %{"threadId" => request.provider_session_id}}

        is_binary(request.provider_session_id) ->
          {"thread/resume",
           Map.put(thread_params(request), "threadId", request.provider_session_id)}

        true ->
          {"thread/start", thread_params(request)}
      end

    {:handshake, [{:notify, "initialized", %{}}, {:open, method, params}]}
  end

  defp fork?(%{provider_options: options}) when is_map(options),
    do: option(options, :fork) == true

  defp fork?(_request), do: false

  @impl true
  def session_id(result), do: thread_id(result)

  @impl true
  def start_turn(turn, _turn_id, runtime) do
    {:request, "turn/start", turn_params(runtime, turn)}
  end

  @impl true
  def interrupt(%{provider_session_id: thread_id, provider_turn_id: turn_id})
      when is_binary(thread_id) and is_binary(turn_id) do
    {:request, "turn/interrupt", %{"threadId" => thread_id, "turnId" => turn_id}}
  end

  def interrupt(_runtime), do: :skip

  @impl true
  def close_signal(%{provider_session_id: thread_id, provider_turn_id: turn_id})
      when is_binary(thread_id) and is_binary(turn_id) do
    {:notify, "turn/interrupt", %{"threadId" => thread_id, "turnId" => turn_id}}
  end

  def close_signal(_runtime), do: :skip

  # `turn/steer` takes `threadId`, `expectedTurnId` and the same `input: UserInput[]` union
  # `turn/start` takes (`v2/TurnSteerParams.json`, codex-cli 0.147.0, committed under
  # `test/support/codex_schema/`), so a steer carries text and images exactly as a turn
  # does — `turn_input/1` builds both and there is no second rendering to drift.
  #
  # `expectedTurnId` is a *precondition*, not a label: the schema says the request fails
  # when it does not match the currently active turn. So a steer with no provider turn id
  # in hand is refused here by name rather than sent with a guess and failed on the wire.
  # `Jido.Harness.SessionWorker` already refuses a steer with no active turn
  # (`{:error, :no_active_turn}`); this is the same refusal one layer down, for the window
  # where the harness still has a turn and the app server has already ended it.
  @impl true
  def steer(%{provider_session_id: thread_id, provider_turn_id: turn_id}, turn, _request_id)
      when is_binary(thread_id) and is_binary(turn_id) do
    {:request, "turn/steer",
     %{
       "threadId" => thread_id,
       "expectedTurnId" => turn_id,
       "input" => turn_input(turn)
     }}
  end

  def steer(%{provider_session_id: thread_id}, _turn, _request_id) when is_binary(thread_id),
    do: {:error, :no_active_turn}

  def steer(_runtime, _turn, _request_id), do: {:error, :session_not_open}

  # An app-server thread has no "set these options" method: `turn/start` carries model,
  # effort, approval policy and sandbox policy on every turn, rebuilt from the session
  # request by `turn_params/2`. So a configuration change here sends nothing and is not
  # pretending to — it is accepted, the runtime moves its request, and the *next*
  # `turn/start` carries it. That is `dynamic_configuration: :managed` and the reason
  # `Ouroboros.Provider.session_configuration/3` answers `:next_turn` for this transport.
  # The turn already running keeps the policy it was started under, because that is what
  # the app server was told and nothing here can retract it.
  @impl true
  def configure(_runtime, changes) when is_map(changes) do
    case Enum.find(Map.keys(changes), &(&1 not in @configurable_fields)) do
      nil -> :ok
      field -> {:error, {:unsupported_configuration, field}}
    end
  end

  def configure(_runtime, _changes), do: {:error, :unsupported}

  # ── the runtime's own round trips ─────────────────────────────────────────────────

  # C4 wires C3's two pinned frames. `compact_request/1` and `model_list_request/1` still
  # hold the schema knowledge; this is only where a runtime verb reaches them.
  #
  # A `focus` is **refused**, not dropped. `ThreadCompactStartParams` has one field,
  # `threadId`, so there is nowhere for "keep the migration plan" to go; compacting anyway
  # would fold the thread on the app server's own terms while the operator was told theirs
  # were applied. A refusal that names the reason is the only answer that is true.
  @impl true
  def ask(:compact, args, runtime) do
    case Map.get(args, :focus) do
      focus when is_binary(focus) and focus != "" ->
        {:error,
         {:unsupported_on_transport,
          %{
            transport: :app_server,
            verb: :compact,
            reason: :focus_not_supported,
            message:
              "the Codex app server's `thread/compact/start` takes a thread id and nothing " <>
                "else, so a focus has nowhere to go. Compact without one, or move the " <>
                "session to a native transport where the fold is this runtime's own."
          }}}

      _unfocused ->
        compact_request(runtime)
    end
  end

  def ask(:models, args, _runtime) do
    model_list_request(
      limit: Map.get(args, :limit),
      cursor: Map.get(args, :cursor),
      include_hidden: Map.get(args, :include_hidden)
    )
  end

  def ask(_verb, _args, _runtime), do: {:error, :unsupported}

  # `thread/compact/start` answers `{}`; the fold itself arrives later as the
  # `thread/compacted` notification `handle_notification/4` already maps into the
  # transcript. So the report here is what this runtime actually knows at this moment —
  # that the app server accepted the request — and it says which side did the work rather
  # than borrowing the native path's token counts, which nothing measured.
  @impl true
  def answer(:compact, _result, _runtime),
    do: %{trigger: "manual", summarised: false, source: "codex:thread/compact/start"}

  def answer(:models, result, _runtime) do
    listed = models(result)
    %{source: "codex:model/list", models: listed.models, next_cursor: listed.next_cursor}
  end

  def answer(_verb, result, _runtime), do: result

  # The app server never calls the client: every server-to-client frame it sends is an
  # approval, which `approval_request/2` above answers. Refusing by name rather than by
  # omission is this behaviour's rule — a dialect that grows a client service later has to
  # say so here.
  @impl true
  def service_request(_method, _params, _runtime), do: :method_not_found

  # The one pre-tool seam the app server gives. `Ouroboros.Control.Permissions` answers
  # first; only what it leaves as `:ask` becomes an approval the human sees.
  #
  # A rule's own yes grants the *narrowest* thing that answers the question: `accept` for
  # this one command, and a `turn`-scoped grant for a permissions request. Widening the
  # provider's own policy is something only a human's "don't ask again" may do, so neither
  # `acceptForSession` nor an execpolicy amendment is reachable from here.
  @impl true
  def approval_request(method, params) when method in @approval_methods do
    case Seam.decide(:app_server, method, params, approval_payload(method, params)) do
      {:ask, payload} -> {:approval, payload, %{params: params, method: method}}
      {:allow, _rule} -> {:result, allow_result(method, params)}
      {:deny, _rule} -> {:result, deny_result(method)}
    end
  end

  def approval_request(_method, _params), do: :method_not_found

  # Two request families with two different answer shapes, so the stash's method decides
  # which one is spoken. `item/permissions/requestApproval` answers with a granted
  # profile and a grant scope; the command and file-change families answer with a
  # `decision`. Replying `{"decision": …}` to a permissions request is not a near miss —
  # `PermissionsRequestApprovalResponse` requires `permissions`, so it is a frame the app
  # server has no field to read.
  @impl true
  def approval_reply(response, stash) do
    case Map.get(stash, :method) do
      "item/permissions/requestApproval" -> permissions_reply(response, stash)
      _command_or_file_change -> %{"decision" => decision(response, stash)}
    end
  end

  @impl true
  def deny_reply(stash) do
    case Map.get(stash, :method) do
      "item/permissions/requestApproval" -> @no_permissions
      _command_or_file_change -> %{"decision" => "decline"}
    end
  end

  @impl true
  def handle_notification("turn/started", params, _raw, runtime) do
    [{:assign, %{provider_turn_id: turn_id(params) || runtime.provider_turn_id}}]
  end

  def handle_notification("turn/completed", params, _raw, runtime) do
    finish_turn(runtime, params)
  end

  def handle_notification("item/started", %{"item" => item} = params, raw, _runtime) do
    Enum.map(map_item_started(item, params, raw), &{:emit_event, &1})
  end

  def handle_notification("item/completed", %{"item" => item} = params, raw, _runtime) do
    Enum.map(map_item_completed(item, params, raw), &{:emit_event, &1})
  end

  def handle_notification("item/agentMessage/delta", params, raw, _runtime) do
    text = delta_text(params)

    if is_binary(text) and text != "" do
      [{:emit_event, event(:output_text_delta, %{"text" => text}, raw)}]
    else
      []
    end
  end

  def handle_notification("item/agent_message/delta", params, raw, runtime) do
    handle_notification("item/agentMessage/delta", params, raw, runtime)
  end

  def handle_notification("turn/diff/updated", params, raw, _runtime) do
    [{:emit_event, event(:file_change, %{"diff" => params["diff"] || params["delta"]}, raw)}]
  end

  def handle_notification("turn/plan/updated", params, raw, _runtime) do
    [
      {:emit_event,
       event(
         :plan_updated,
         %{"explanation" => params["explanation"], "plan" => params["plan"] || []},
         raw
       )}
    ]
  end

  def handle_notification(method, params, raw, _runtime)
      when method in ["thread/tokenUsage/updated", "thread.tokenUsage.updated"] do
    usage = params["usage"] || params["token_usage"]

    if is_map(usage) do
      input = usage["input_tokens"] || 0
      output = usage["output_tokens"] || 0

      [
        {:emit_event, event(:usage, Map.put_new(usage, "total_tokens", input + output), raw)}
      ]
    else
      []
    end
  end

  # The app server folding its own context. Surfaced as what it is rather than imitated:
  # this runtime never saw the conversation and has nothing to say about what was kept.
  # `thread/compacted` is the notification the schema marks deprecated in favour of the
  # `contextCompaction` item (see `map_item_completed/3`); both are read so a server on
  # either side of that change is understood.
  def handle_notification("thread/compacted", params, raw, _runtime) do
    [{:emit_event, event(:provider_event, compaction_payload(params["turnId"]), raw)}]
  end

  def handle_notification("thread/started", params, _raw, runtime) do
    [{:assign, %{provider_session_id: thread_id(params) || runtime.provider_session_id}}]
  end

  def handle_notification("serverRequest/resolved", _params, _raw, _runtime), do: []

  def handle_notification(method, _params, raw, _runtime) do
    [
      {:emit, :provider_event,
       %{"kind" => "codex_notification", "method" => method, "message" => raw}, []}
    ]
  end

  @impl true
  def handle_rpc({:turn, turn_id}, message, runtime) do
    case rpc_result(message) do
      {:ok, result} ->
        [{:assign, %{provider_turn_id: turn_id(result) || runtime.provider_turn_id}}]

      {:error, reason} ->
        active = if runtime.active_turn_id == turn_id, do: nil, else: runtime.active_turn_id

        [
          {:emit, :turn_failed, %{"error" => inspect(reason)}, [turn_id: turn_id]},
          {:assign, %{active_turn_id: active, provider_turn_id: nil}}
        ]
    end
  end

  def handle_rpc({:interrupt, _turn_id}, _message, _runtime), do: []

  # `TurnSteerResponse` is `{turnId}` — the turn the steered input joined. A steer that
  # failed its `expectedTurnId` precondition is the case worth saying out loud: the turn
  # ended between the harness's check and this frame, so the human's words went nowhere
  # and a silent `:ok` would have claimed otherwise.
  def handle_rpc({:steer, request_id}, message, runtime) do
    case rpc_result(message) do
      {:ok, result} ->
        [{:assign, %{provider_turn_id: steer_turn_id(result) || runtime.provider_turn_id}}]

      {:error, reason} ->
        [
          {:emit, :provider_event,
           %{"kind" => "steer_failed", "error" => error_text(reason) || inspect(reason)},
           [request_id: request_id]}
        ]
    end
  end

  def handle_rpc(pending, message, _runtime) do
    [
      {:emit, :provider_event,
       %{
         "kind" => "unexpected_rpc_completion",
         "pending" => inspect(pending),
         "message" => message
       }, []}
    ]
  end

  defp finish_turn(runtime, params) do
    turn_id = runtime.active_turn_id
    interrupted? = turn_id && MapSet.member?(runtime.interrupted_turns, turn_id)
    status = get_in(params, ["turn", "status"]) || params["status"]
    error = get_in(params, ["turn", "error"]) || params["error"]

    type =
      cond do
        interrupted? or status in ["interrupted", "cancelled"] -> :turn_interrupted
        status in ["failed", "error"] or not is_nil(error) -> :turn_failed
        true -> :turn_completed
      end

    payload =
      %{"status" => status || Atom.to_string(type)}
      |> maybe_put("error", error_text(error))

    emits =
      if turn_id, do: [{:emit, type, payload, [turn_id: turn_id]}], else: []

    emits ++
      [
        {:assign,
         %{
           active_turn_id: nil,
           provider_turn_id: nil,
           interrupted_turns: MapSet.delete(runtime.interrupted_turns, turn_id)
         }}
      ]
  end

  defp map_item_started(item, _params, raw) do
    case item_type(item) do
      type when type in ["commandExecution", "command_execution"] ->
        [command_tool_call(item, raw)]

      type when type in ["mcpToolCall", "mcp_tool_call"] ->
        [mcp_tool_call(item, raw)]

      _other ->
        []
    end
  end

  defp map_item_completed(item, _params, raw) do
    case item_type(item) do
      type when type in ["commandExecution", "command_execution"] ->
        [command_tool_result(item, raw)]

      type when type in ["mcpToolCall", "mcp_tool_call"] ->
        [mcp_tool_result(item, raw)]

      type when type in ["agentMessage", "agent_message"] ->
        text = item["text"]

        if is_binary(text) and text != "",
          do: [event(:output_text_final, %{"text" => text}, raw)],
          else: []

      type when type in ["reasoning"] ->
        text = item["text"] || item["summary"]

        if is_binary(text) and text != "",
          do: [event(:thinking_delta, %{"text" => text}, raw)],
          else: []

      type when type in ["fileChange", "file_change"] ->
        [event(:file_change, %{"changes" => item["changes"], "status" => item["status"]}, raw)]

      type when type in ["contextCompaction", "context_compaction"] ->
        [event(:provider_event, compaction_payload(nil), raw)]

      _other ->
        [event(:provider_event, %{"item_type" => item["type"] || "unknown"}, raw)]
    end
  end

  defp command_tool_call(item, raw) do
    event(
      :tool_call,
      %{
        "name" => "exec_command",
        "call_id" => item["id"] || "command",
        "input" => %{"cmd" => item["command"], "cwd" => item["cwd"]}
      },
      raw
    )
  end

  defp command_tool_result(item, raw) do
    event(
      :tool_result,
      %{
        "name" => "exec_command",
        "call_id" => item["id"] || "command",
        "output" => item["aggregatedOutput"] || item["aggregated_output"] || "",
        "is_error" =>
          item["exitCode"] not in [nil, 0] or item["exit_code"] not in [nil, 0] or
            item["status"] in ["failed", "declined"]
      },
      raw
    )
  end

  defp mcp_tool_call(item, raw) do
    event(
      :tool_call,
      %{
        "name" => item["tool"] || "mcp_tool",
        "call_id" => item["id"] || "mcp",
        "input" => item["arguments"] || %{}
      },
      raw
    )
  end

  defp mcp_tool_result(item, raw) do
    event(
      :tool_result,
      %{
        "call_id" => item["id"] || "mcp",
        "output" => item["result"] || item["error"] || "",
        "is_error" => not is_nil(item["error"]) or item["status"] in ["failed", "declined"]
      },
      raw
    )
  end

  # `source: "provider"` is the load-bearing field: it says this runtime was told a
  # compaction happened, not that it performed one. `interactive.context` reports what a
  # session can honestly say, and for every non-native transport that is what its events
  # carried — so a compaction it never ran must not look like one it did.
  defp compaction_payload(turn_id) do
    %{"kind" => "context_compacted", "source" => "provider", "turn_id" => turn_id}
    |> reject_nils()
  end

  defp approval_payload(method, params) do
    command = command_text(params)
    reason = params["reason"]
    cwd = params["cwd"]

    tool_call =
      %{"name" => approval_name(method), "command" => command, "cwd" => cwd}
      |> reject_nils()

    %{"tool_call" => tool_call, "reason" => reason, "kind" => approval_kind(method)}
    |> maybe_put("execpolicy_amendment", amendment(params))
    |> maybe_put("permissions", permissions_summary(method, params))
    |> reject_nils()
  end

  # `proposedExecpolicyAmendment` is the app server's own offer: the argv prefix that,
  # amended into its execpolicy, would stop it asking about commands like this one. It is
  # already the prefix rather than the command — `["git", "status"]`, not the whole line —
  # so passing it through is the content-minimised choice as well as the faithful one.
  #
  # Advertised **only when the request carries one**, because the extra answer it unlocks
  # is one this transport can honour only when there is an amendment to send. A malformed
  # or oversized proposal is not truncated to fit: a shortened prefix is a *wider* rule
  # than the one proposed, so it is dropped and the answer falls back to `acceptForSession`.
  defp amendment(params) when is_map(params) do
    case params["proposedExecpolicyAmendment"] do
      tokens when is_list(tokens) and tokens != [] -> bounded_amendment(tokens)
      _absent -> nil
    end
  end

  defp amendment(_params), do: nil

  defp bounded_amendment(tokens) do
    if length(tokens) <= @max_amendment_tokens and
         Enum.all?(tokens, &(is_binary(&1) and byte_size(&1) <= @max_amendment_token_bytes)) do
      tokens
    end
  end

  # What the escalation actually asks for, in the shape a modal can render: which paths
  # at which access, and whether the sandbox's network is being opened. Bounded, and the
  # count of what did not fit is stated rather than dropped in silence.
  defp permissions_summary("item/permissions/requestApproval", params) do
    profile = params["permissions"] || %{}
    filesystem = profile["fileSystem"] || %{}
    requested = filesystem_entries(filesystem)
    sent = Enum.take(requested, @max_permission_entries)

    %{
      "filesystem" => sent,
      "network" => get_in(profile, ["network", "enabled"]),
      "not_shown" => length(requested) - length(sent)
    }
    |> reject_nils()
  end

  defp permissions_summary(_method, _params), do: nil

  # `entries` is the current shape; `read`/`write` are the arrays the schema marks as
  # going away in its favour. Both are read, so an app server on either side of that
  # change is rendered rather than shown an empty list.
  defp filesystem_entries(filesystem) do
    entries =
      case filesystem["entries"] do
        list when is_list(list) -> Enum.map(list, &filesystem_entry/1)
        _absent -> []
      end

    legacy =
      Enum.flat_map(["read", "write"], fn access ->
        case filesystem[access] do
          list when is_list(list) ->
            for path <- list, is_binary(path), do: %{"access" => access, "path" => path}

          _absent ->
            []
        end
      end)

    Enum.reject(entries ++ legacy, &is_nil/1)
  end

  defp filesystem_entry(%{"access" => access, "path" => path}) when is_binary(access) do
    case permission_path(path) do
      nil -> nil
      rendered -> %{"access" => access, "path" => rendered}
    end
  end

  defp filesystem_entry(_entry), do: nil

  # `FileSystemPath` is a union of a literal path, a glob, and a named special location.
  # A special location is rendered as its own name rather than resolved: this runtime does
  # not know what the app server means by `project_roots`, and inventing a path for the
  # modal would put a directory in front of a human that nothing had verified.
  defp permission_path(%{"type" => "path", "path" => path}) when is_binary(path), do: path

  defp permission_path(%{"type" => "glob_pattern", "pattern" => pattern})
       when is_binary(pattern),
       do: pattern

  defp permission_path(%{"type" => "special", "value" => %{"kind" => kind}})
       when is_binary(kind),
       do: "<" <> kind <> ">"

  defp permission_path(path) when is_binary(path), do: path
  defp permission_path(_path), do: nil

  # A rule's yes, in each family's own narrowest shape.
  defp allow_result("item/permissions/requestApproval", params),
    do: %{"permissions" => requested_profile(params), "scope" => "turn"}

  defp allow_result(_method, _params), do: %{"decision" => "accept"}

  defp deny_result("item/permissions/requestApproval"), do: @no_permissions
  defp deny_result(_method), do: %{"decision" => "decline"}

  # Approving a permissions request grants exactly the profile that was requested and
  # nothing beside it, at the narrowest grant scope that answers the question Ouroboros
  # was asked: `PermissionGrantScope` is `turn | session`, which is the same distinction
  # `ApprovalResponse.scope` already draws between `:once` and `:session`, so the two map
  # one to one and neither widens the other.
  defp permissions_reply(%{decision: :approve} = response, stash) do
    %{
      "permissions" => requested_profile(Map.get(stash, :params) || %{}),
      "scope" => grant_scope(response)
    }
  end

  defp permissions_reply(_response, _stash), do: @no_permissions

  defp grant_scope(%{scope: :session}), do: "session"
  defp grant_scope(_response), do: "turn"

  defp requested_profile(params) when is_map(params) do
    case params["permissions"] do
      %{} = profile -> profile
      _absent -> %{}
    end
  end

  defp requested_profile(_params), do: %{}

  defp approval_name("item/fileChange/requestApproval"), do: "file_change"
  defp approval_name("item/permissions/requestApproval"), do: "permissions"
  defp approval_name(_method), do: "exec_command"

  defp approval_kind("item/fileChange/requestApproval"), do: "file_change"
  defp approval_kind("item/permissions/requestApproval"), do: "permissions"
  defp approval_kind(_method), do: "sandbox_escalation"

  defp command_text(params) when is_map(params) do
    cond do
      is_binary(params["command"]) -> params["command"]
      is_list(params["command"]) -> Enum.map_join(params["command"], " ", &to_string/1)
      is_binary(params["grantRoot"]) -> params["grantRoot"]
      true -> nil
    end
  end

  # "Don't ask again" is the one answer that may move a policy, and the app server offers
  # two ways to spell it. `acceptForSession` fills its session approval cache with *this*
  # command; `acceptWithExecpolicyAmendment` amends its execpolicy with the prefix it
  # proposed, so commands like this one stop being asked about at all. The second is only
  # reachable when the request proposed an amendment, which is the whole reason
  # `approval_payload/2` advertises it only then.
  #
  # Both halves land on one answer. This one moves Codex's own policy; the C1 rule that
  # stops *this runtime* asking is written by `Permissions.Seam.answered/4` from the same
  # `scope: :session`, transport-neutrally, for ACP and the app server alike. A session
  # rule and a session-scoped amendment also expire together — `Seam.forget_session/0`
  # drops the rule when this transport terminates, and the app server's cache dies with
  # the thread — so neither outlives the conversation the human answered in.
  defp decision(%{decision: :approve, scope: :session}, stash) do
    case amendment(Map.get(stash, :params) || %{}) do
      nil -> "acceptForSession"
      tokens -> %{"acceptWithExecpolicyAmendment" => %{"execpolicy_amendment" => tokens}}
    end
  end

  defp decision(%{decision: :approve}, _stash), do: "accept"
  defp decision(%{decision: :deny}, _stash), do: "decline"

  defp thread_params(request) do
    %{"cwd" => Path.expand(request.cwd)}
    |> maybe_put("model", request.model)
    |> put_approval(request.approval_mode)
    |> put_sandbox(request)
  end

  defp turn_params(runtime, turn) do
    %{
      "threadId" => runtime.provider_session_id,
      "input" => turn_input(turn)
    }
    |> maybe_put("model", turn_model(runtime, turn))
    |> maybe_put("effort", effort(turn.reasoning_effort || runtime.request.reasoning_effort))
    |> put_approval(runtime.request.approval_mode)
    |> put_sandbox(runtime.request)
  end

  # A per-turn `provider_options.model` wins; otherwise the turn carries the session's
  # own model. `TurnRequest.provider_options` defaults to an empty map, so the first
  # clause matches every turn — reading only it meant a session model reached
  # `thread/start` and never `turn/start`, which made a mid-session model change
  # unobservable to the provider even though the request had moved.
  defp turn_model(runtime, %{provider_options: options}) when is_map(options),
    do: option(options, :model) || runtime.request.model

  defp turn_model(runtime, _turn), do: runtime.request.model

  # `turn/start` takes `input: UserInput[]`, a tagged union. Its arms, verified against the
  # schema this protocol's own generator emits —
  # `codex app-server generate-json-schema --out <dir>` → `v2/TurnStartParams.json`,
  # `$defs.UserInput` (codex-cli 0.147.0), the same union published at
  # https://developers.openai.com/codex/app-server — are `text` (`text`, optional
  # `text_elements`), `image` (`url`), `localImage` (`path`), `audio`, `localAudio`,
  # `skill` (`name`,`path`) and `mention` (`name`,`path`). Only `type` plus the arm's own
  # required field are mandatory.
  #
  # Images therefore travel as `localImage` with the workspace-canonicalised path the
  # caller already authorised (`Ouroboros.Interactive.Task`; not re-validated here). No arm
  # carries a non-image file, so those attachments are *named*, not sent: they become
  # `@<path>` lines in a trailing text item, which tells the agent where the file is and
  # leaves the reading to its own tools. Nothing is uploaded, and the docs say so.
  defp turn_input(turn) do
    attachments = Enum.filter(attachments(turn), &is_binary/1)
    sent = Enum.take(attachments, @max_attachment_items)
    dropped = length(attachments) - length(sent)
    {images, files} = Enum.split_with(sent, &image_attachment?/1)

    [%{"type" => "text", "text" => TurnRequest.text(turn)}] ++
      Enum.map(images, &%{"type" => "localImage", "path" => &1}) ++
      mention_input(files, dropped)
  end

  defp attachments(%{attachments: attachments}) when is_list(attachments), do: attachments
  defp attachments(_turn), do: []

  defp image_attachment?(path),
    do: path |> Path.extname() |> String.downcase() |> Kernel.in(@image_extensions)

  defp mention_input([], 0), do: []

  defp mention_input(files, dropped) do
    named =
      case files do
        [] -> []
        _ -> ["Attached files (paths, not contents):" | Enum.map(files, &("@" <> &1))]
      end

    overflow =
      if dropped > 0,
        do: ["#{dropped} further attachments were not sent with this turn."],
        else: []

    [%{"type" => "text", "text" => Enum.join(named ++ overflow, "\n")}]
  end

  # AskForApproval and SandboxMode serialize with serde kebab-case. The tagged
  # sandboxPolicy object is camelCase (`type: workspaceWrite`). Mixing those is a
  # -32600, not a silent drop: `onFailure` / `workspaceWrite` refuse the handshake.
  # `on-failure` is gone from current Codex; auto_edit therefore asks on-request.
  defp put_approval(params, :prompt), do: Map.put(params, "approvalPolicy", "on-request")
  defp put_approval(params, :auto_edit), do: Map.put(params, "approvalPolicy", "on-request")
  defp put_approval(params, :auto_approve), do: Map.put(params, "approvalPolicy", "never")
  defp put_approval(params, _mode), do: params

  defp put_sandbox(params, request) do
    {key, value} = sandbox_field(request)
    Map.put(params, key, value)
  end

  defp sandbox_field(request) do
    case request.sandbox_mode do
      :read_only ->
        {"sandbox", "read-only"}

      :unrestricted ->
        {"sandbox", "danger-full-access"}

      mode when mode in [:workspace_write, :default, nil] ->
        workspace_write_field(request)

      _other ->
        {"sandbox", "workspace-write"}
    end
  end

  defp workspace_write_field(request) do
    dirs = extra_dirs(request)
    network = option(request.provider_options, :network_access_enabled)

    if dirs == [] and not is_boolean(network) do
      {"sandbox", "workspace-write"}
    else
      policy = %{"type" => "workspaceWrite"}
      policy = if dirs == [], do: policy, else: Map.put(policy, "writableRoots", dirs)
      policy = if is_boolean(network), do: Map.put(policy, "networkAccess", network), else: policy
      {"sandboxPolicy", policy}
    end
  end

  defp extra_dirs(%{add_dirs: dirs}) when is_list(dirs), do: Enum.filter(dirs, &is_binary/1)
  defp extra_dirs(_request), do: []

  defp effort(:low), do: "low"
  defp effort(:medium), do: "medium"
  defp effort(:high), do: "high"
  defp effort(_), do: nil

  defp event(type, payload, raw),
    do: Event.new!(type: type, provider: :codex, payload: payload, raw: raw)

  defp option(options, key) when is_map(options),
    do: Map.get(options, key) || Map.get(options, Atom.to_string(key))

  defp option(_options, _key), do: nil

  defp thread_id(%{"thread" => %{"id" => id}}) when is_binary(id), do: id
  defp thread_id(%{"id" => id}) when is_binary(id), do: id
  defp thread_id(_), do: nil

  defp turn_id(%{"turn" => %{"id" => id}}) when is_binary(id), do: id
  defp turn_id(%{"id" => id}) when is_binary(id), do: id
  defp turn_id(_), do: nil

  # `turn/steer` answers with a bare `turnId` rather than the `turn` object every other
  # result carries, so it gets its own reader instead of a looser `turn_id/1`.
  defp steer_turn_id(%{"turnId" => id}) when is_binary(id), do: id
  defp steer_turn_id(result), do: turn_id(result)

  defp item_type(%{"type" => type}) when is_binary(type), do: type
  defp item_type(_item), do: "unknown"

  defp delta_text(%{"delta" => delta}) when is_binary(delta), do: delta
  defp delta_text(%{"text" => text}) when is_binary(text), do: text
  defp delta_text(%{"item" => item}) when is_map(item), do: item["delta"] || item["text"]
  defp delta_text(_params), do: nil

  defp error_text(nil), do: nil
  defp error_text(%{"message" => message}) when is_binary(message), do: message
  defp error_text(message) when is_binary(message), do: message
  defp error_text(other), do: inspect(other)

  defp rpc_result(%{"error" => error}), do: {:error, error}
  defp rpc_result(%{"result" => result}), do: {:ok, result || %{}}
  defp rpc_result(message), do: {:error, {:invalid_rpc_response, message}}

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp reject_nils(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end
end
