defmodule Ouroboros.Provider.Session.Dialect.ACP do
  @moduledoc false

  @behaviour Ouroboros.Provider.Session.Dialect

  alias Jido.Harness.{ApprovalResponse, Event, InteractionCapabilities, TurnRequest}
  alias Ouroboros.Control.Permissions.Seam
  alias Ouroboros.Provider.Session.Diff

  # Bounds on what one ACP update may turn into. The wire applies no byte cap of its own
  # (a payload crosses the socket whole on every replay), so the dialect is where an
  # unbounded agent has to be cut down.
  @max_file_changes 64
  @max_commands 64
  @max_modes 32
  @max_label_chars 200

  @impl true
  def name, do: :acp

  @impl true
  def ready_kind, do: "acp_session_ready"

  @impl true
  def unsupported_method_message,
    do: "Ouroboros serves no ACP methods on this connection"

  @impl true
  def capabilities do
    InteractionCapabilities.new!(
      transport: :acp,
      process: :persistent,
      multi_turn: :native,
      follow_up: :managed,
      interrupt: :native,
      approvals: :native,
      multimodal: :native
    )
  end

  @impl true
  def command(request, context) do
    # `approval_request/2` sees only a method and params, so the session this process
    # speaks for is remembered here, in `Session.Jsonl.init/1`, where both are in hand.
    _ = Seam.bind(request, context, name())

    cli_path = option(request.provider_options, :cli_path)
    argv = option(request.provider_options, :argv) || ["acp"]

    case context.provider do
      :kimi ->
        {:ok, cli_path || configured_cli(context, "kimi"), argv,
         %{"KIMI_CODE_NO_AUTO_UPDATE" => "1"}}

      :opencode ->
        {:ok, cli_path || configured_cli(context, "opencode"), argv, %{}}

      _provider ->
        executable = cli_path || configured_cli(context, to_string(context.provider))
        {:ok, executable, argv, %{}}
    end
  end

  @impl true
  def envelope(%{"jsonrpc" => _} = message), do: message
  def envelope(message), do: Map.put(message, "jsonrpc", "2.0")

  # C4. Declared `true` because `service_request/3` and `Session.Service` serve them: a
  # client capability is a promise to answer, and one declared without a handler turns
  # every agent that believes it into a session that hangs on its first read. The two
  # halves land together or not at all — `test/provider/session_acp_test.exs` asserts
  # exactly that pairing so the declaration cannot outrun the code again.
  @impl true
  def initialize_params(_request) do
    %{
      "protocolVersion" => 1,
      "clientCapabilities" => %{
        "fs" => %{"readTextFile" => true, "writeTextFile" => true},
        "terminal" => true
      },
      "clientInfo" => %{
        "name" => "ouroboros",
        "title" => "Ouroboros",
        "version" => Application.spec(:ouroboros, :vsn) |> to_string()
      }
    }
  end

  @impl true
  def after_initialize(_result, request, _runtime) do
    params = %{"cwd" => request.cwd, "mcpServers" => mcp_servers(request.mcp_config)}

    {method, params} =
      if is_binary(request.provider_session_id) do
        {"session/load", Map.put(params, "sessionId", request.provider_session_id)}
      else
        {"session/new", params}
      end

    {:handshake, [{:open, method, params}]}
  end

  @impl true
  def session_id(result), do: result["sessionId"] || result["session_id"]

  @doc """
  Session modes carried by a `session/new` / `session/load` result.

  Not a `Dialect` callback: `Dialect.verify!/1` pins an exact callback list and the
  app-server dialect has nothing to say here. `Session.Jsonl` calls this when a dialect
  exports it, so the modes an ACP agent offers reach the client next to the ready event
  instead of being dropped with the rest of the open result.

  The ids are also *kept*, in the transport's own state, because they are the vocabulary
  `session/set_mode` has to be checked against. An agent's mode ids are its own invention;
  the only honest way to accept one from a client is to hold it to the list the agent just
  published, so a mode nobody announced is refused here rather than sent and hoped for.
  """
  @spec session_opened(term(), map()) :: [{:emit, atom(), map(), keyword()} | {:assign, map()}]
  def session_opened(result, _state) when is_map(result) do
    case modes_payload(result["modes"]) do
      nil ->
        []

      payload ->
        [{:emit, :provider_event, payload, []}, {:assign, %{available_modes: mode_ids(payload)}}]
    end
  end

  def session_opened(_result, _state), do: []

  defp mode_ids(%{"modes" => modes}) when is_list(modes),
    do: Enum.flat_map(modes, fn %{"id" => id} -> [id] end)

  defp mode_ids(_payload), do: []

  @impl true
  def start_turn(turn, _turn_id, runtime) do
    {:request, "session/prompt",
     %{
       "sessionId" => runtime.provider_session_id,
       "prompt" => prompt_blocks(turn, runtime.request.cwd)
     }}
  end

  @impl true
  def interrupt(%{provider_session_id: session_id}) when is_binary(session_id) do
    {:notify, "session/cancel", %{"sessionId" => session_id}}
  end

  def interrupt(_runtime), do: :skip

  @impl true
  def close_signal(runtime), do: interrupt(runtime)

  @impl true
  def steer(_runtime, _request, _request_id), do: {:error, :unsupported}

  # ACP's only configuration verb is `session/set_mode`, and its argument is a mode *id*
  # the agent itself invented and advertised on `session/new` — "ask", "architect",
  # "code", whatever that agent ships. Ouroboros's four normalized approval modes are not
  # those ids, and no bundled ACP agent publishes a mapping between them. Guessing one
  # would move a permission posture on the strength of a string that happened to look
  # right, which is the one class of mistake this runtime does not make.
  #
  # So this refuses, and the refusal is structural rather than special-cased: the ACP
  # transport declares no `dynamic_configuration` and no `configuration_options`, so
  # `Ouroboros.Provider.session_configuration/3` and the Harness worker both refuse
  # before reaching here.
  #
  # C4 adds the one honest way to move an ACP session's posture, and it is a different
  # key: `mode`, carrying the agent's *own* mode id, validated against the `availableModes`
  # that same agent published on `session/new`. It travels through `ask/3` rather than
  # here, because a mode change is a correlated round trip whose answer matters and this
  # callback's contract is a local `:ok`.
  @impl true
  def configure(_runtime, _changes), do: {:error, :unsupported}

  @doc """
  This dialect's declaration that a client may set the *agent's* own mode.

  Not a `Dialect` callback, for the reason `fork_option/0` is not one either:
  `Dialect.verify!/1` pins an exact callback list, and a transport that has nothing to say
  about modes should say it by not exporting this rather than by returning a `false`
  nobody reads. `Ouroboros.Provider.session_mode/2` looks for the export, so the
  capability is the dialect's own claim rather than a table somewhere else.

  The value names *whose* vocabulary the id comes from. `:agent_declared` is the whole
  honest answer here: Ouroboros neither defines these ids nor maps them onto its own
  approval modes — it forwards one the agent published and refuses one it did not.
  """
  @spec mode_option() :: {atom(), atom()}
  def mode_option, do: {:mode, :agent_declared}

  # ── the runtime's own round trips ─────────────────────────────────────────────────

  # `session/set_mode` takes `{sessionId, modeId}` and answers `{}`
  # (https://agentclientprotocol.com/protocol/session-modes, v1). The id is checked
  # against what the agent announced rather than sent hopefully: `availableModes` is the
  # whole vocabulary, and a client asking for a mode outside it is asking for something
  # this session cannot have.
  @impl true
  def ask(:set_mode, %{mode: mode}, runtime) when is_binary(mode) do
    available = Map.get(runtime, :available_modes) || []

    cond do
      not is_binary(runtime.provider_session_id) ->
        {:error, :session_not_open}

      available == [] ->
        {:error,
         {:unsupported_configuration,
          %{
            field: :mode,
            reason: :no_modes_announced,
            message:
              "this ACP agent announced no `availableModes` when the session opened, so it " <>
                "has no mode vocabulary to set. Modes are the agent's own; Ouroboros will " <>
                "not invent one."
          }}}

      mode not in available ->
        {:error,
         {:unsupported_configuration,
          %{
            field: :mode,
            reason: :unknown_mode,
            mode: mode,
            modes: available,
            message:
              "this ACP agent announced #{inspect(available)}; #{inspect(mode)} is not one of " <>
                "them and is refused rather than sent."
          }}}

      true ->
        {:request, "session/set_mode",
         %{"sessionId" => runtime.provider_session_id, "modeId" => mode}}
    end
  end

  def ask(:set_mode, _args, _runtime), do: {:error, {:invalid_configuration, %{field: :mode}}}

  # ACP publishes no compaction verb and no account-scoped model list. Both refuse by
  # name rather than by a catch-all, so a verb added to the runtime cannot be silently
  # swallowed here.
  def ask(verb, _args, _runtime) when verb in [:compact, :models], do: {:error, :unsupported}
  def ask(_verb, _args, _runtime), do: {:error, :unsupported}

  @impl true
  def answer(:set_mode, _result, _runtime), do: :ok
  def answer(_verb, result, _runtime), do: result

  # The one pre-tool seam ACP gives. `Ouroboros.Control.Permissions` answers first; only
  # what it leaves as `:ask` becomes an approval the human sees.
  @impl true
  def approval_request("session/request_permission" = method, params) do
    case Seam.decide(:acp, method, params, permission_payload(params)) do
      {:ask, payload} ->
        {:approval, payload, %{params: params, method: method}}

      {:allow, _rule} ->
        {:result, permission_result(params, seam_response(:approve, nil))}

      {:deny, rule} ->
        {:result, permission_result(params, seam_response(:deny, Seam.refusal(rule)))}
    end
  end

  def approval_request(_method, _params), do: :method_not_found

  # ── the services the client serves ───────────────────────────────────────────────
  #
  # C4. The other direction of ACP: the agent calling Ouroboros. Every one of these is
  # checked against the session this process speaks for before it becomes work — an agent
  # naming another session's id is asking about a conversation it is not in — and the
  # params are normalised here so `Session.Service` never has to read two spellings of a
  # field. What each one is then judged as is that module's table.
  @impl true
  def service_request(method, params, runtime) do
    with {:service, operation, args} <- service_plan(method, params) do
      if session_matches?(params, runtime),
        do: {:service, operation, args},
        else: {:service, :unknown_session, %{}}
    end
  end

  defp service_plan("fs/read_text_file", params) do
    {:service, :fs_read,
     %{
       path: params["path"],
       line: integer_or_nil(params["line"]),
       limit: integer_or_nil(params["limit"])
     }}
  end

  defp service_plan("fs/write_text_file", params),
    do: {:service, :fs_write, %{path: params["path"], content: params["content"]}}

  defp service_plan("terminal/create", params) do
    {:service, :terminal_create,
     %{
       command: params["command"],
       args: params["args"],
       env: params["env"],
       cwd: params["cwd"],
       output_byte_limit: integer_or_nil(params["outputByteLimit"] || params["output_byte_limit"])
     }}
  end

  defp service_plan("terminal/output", params), do: terminal_plan(:terminal_output, params)
  defp service_plan("terminal/wait_for_exit", params), do: terminal_plan(:terminal_wait, params)
  defp service_plan("terminal/kill", params), do: terminal_plan(:terminal_kill, params)
  defp service_plan("terminal/release", params), do: terminal_plan(:terminal_release, params)
  defp service_plan(_method, _params), do: :method_not_found

  defp terminal_plan(operation, params),
    do: {:service, operation, %{terminal_id: params["terminalId"] || params["terminal_id"]}}

  # An absent `sessionId` is accepted: the agent is talking down its own connection, which
  # serves exactly one session, and some agents omit it. A *wrong* one is not.
  defp session_matches?(params, runtime) do
    case params["sessionId"] || params["session_id"] do
      nil -> true
      id -> id == runtime.provider_session_id
    end
  end

  defp integer_or_nil(value) when is_integer(value), do: value
  defp integer_or_nil(_value), do: nil

  defp seam_response(decision, reason) do
    %ApprovalResponse{decision: decision, scope: :once, reason: reason, provider_options: %{}}
  end

  @impl true
  def approval_reply(response, stash), do: permission_result(stash[:params] || %{}, response)

  @impl true
  def deny_reply(stash) do
    response = %ApprovalResponse{
      decision: :deny,
      scope: :once,
      reason: "session closed",
      provider_options: %{}
    }

    permission_result(stash[:params] || %{}, response)
  end

  @impl true
  def handle_notification("session/update", params, raw, _runtime) do
    update = params["update"] || %{}
    Enum.map(map_update(update, raw), &{:emit_event, &1})
  end

  def handle_notification(method, _params, raw, _runtime) do
    [
      {:emit, :provider_event,
       %{"kind" => "acp_notification", "method" => method, "message" => raw}, []}
    ]
  end

  @impl true
  def handle_rpc({:turn, turn_id}, message, runtime) do
    interrupted? = MapSet.member?(runtime.interrupted_turns, turn_id)

    {type, payload} =
      case rpc_result(message) do
        {:ok, result} ->
          type =
            if interrupted? or result["stopReason"] == "cancelled",
              do: :turn_interrupted,
              else: :turn_completed

          {type, %{"stop_reason" => result["stopReason"]}}

        {:error, reason} ->
          type = if interrupted?, do: :turn_interrupted, else: :turn_failed
          {type, %{"error" => inspect(reason)}}
      end

    active = if runtime.active_turn_id == turn_id, do: nil, else: runtime.active_turn_id

    [
      {:emit, type, payload, [turn_id: turn_id]},
      {:assign,
       %{
         active_turn_id: active,
         interrupted_turns: MapSet.delete(runtime.interrupted_turns, turn_id)
       }}
    ]
  end

  def handle_rpc({:interrupt, _turn_id}, _message, _runtime), do: []

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

  # `user_message_chunk` deliberately stays in the catch-all. It is the agent echoing the
  # prompt Ouroboros itself just sent; normalising it to `:output_text_delta` would print
  # the user's own turn back into the transcript as agent output, and there is no event
  # type for "the agent's copy of what I said". `input_accepted` already carries the
  # authoritative text.
  defp map_update(%{"sessionUpdate" => type} = update, raw) do
    case type do
      "agent_message_chunk" -> text_event(:output_text_delta, update, raw)
      "agent_thought_chunk" -> text_event(:thinking_delta, update, raw)
      "tool_call" -> [event(:tool_call, update, raw) | file_change_events(update, raw)]
      "tool_call_update" -> [event(:tool_result, update, raw) | file_change_events(update, raw)]
      "plan" -> [event(:plan_updated, update, raw)]
      "usage_update" -> [event(:usage, Map.drop(update, ["sessionUpdate"]), raw)]
      "diff" -> diff_events([update], update, raw) |> or_else(update, raw)
      "available_commands_update" -> [commands_event(update, raw)]
      "current_mode_update" -> mode_events(update, raw) |> or_else(update, raw)
      _ -> [event(:provider_event, %{"kind" => "acp_update", "update" => update}, raw)]
    end
  end

  defp map_update(update, raw),
    do: [event(:provider_event, %{"kind" => "acp_update", "update" => update}, raw)]

  defp or_else([], update, raw),
    do: [event(:provider_event, %{"kind" => "acp_update", "update" => update}, raw)]

  defp or_else(events, _update, _raw), do: events

  # Where an ACP edit actually lives. The v1 schema
  # (https://agentclientprotocol.com/protocol/schema, tool calls at
  # https://agentclientprotocol.com/protocol/tool-calls) has no `diff` arm in the
  # `SessionUpdate` union; a file edit is a `{"type":"diff","path","oldText","newText"}`
  # block inside a tool call's `content`. Both are read: those content blocks, and a bare
  # `diff` update, which X8 named and which costs nothing to accept from an agent that
  # sends one.
  defp file_change_events(update, raw), do: diff_events(content_blocks(update), update, raw)

  defp content_blocks(%{"content" => content}) when is_list(content),
    do: Enum.filter(content, &match?(%{"type" => "diff"}, &1))

  defp content_blocks(_update), do: []

  defp diff_events(blocks, update, raw) do
    case blocks |> Enum.take(@max_file_changes) |> Enum.flat_map(&file_change/1) do
      [] ->
        []

      changes ->
        [event(:file_change, %{"changes" => changes, "status" => change_status(update)}, raw)]
    end
  end

  # The item-level `file_change` shape the client already parses: it reads `path` and the
  # +/- counts out of the unified text, so the diff has to be a real one with
  # `--- a/<path>` / `+++ b/<path>` headers rather than a summary. `Session.Diff` renders
  # it, because `Session.Service` must produce the same bytes for a write this runtime
  # performed on the agent's behalf and the two must not drift.
  defp file_change(%{"path" => path} = block) when is_binary(path),
    do: [Diff.change(path, block["oldText"], block["newText"])]

  defp file_change(_block), do: []

  defp change_status(%{"status" => status}) when is_binary(status), do: status
  defp change_status(_update), do: "completed"

  # Names and one-line descriptions only. A command's `input.hint` is the agent's own
  # prompt-completion detail and nothing here renders it yet.
  defp commands_event(update, raw) do
    commands =
      update
      |> list_field("availableCommands", "available_commands")
      |> Enum.take(@max_commands)
      |> Enum.flat_map(&command_entry/1)

    event(:provider_event, %{"kind" => "available_commands", "commands" => commands}, raw)
  end

  defp command_entry(%{"name" => name} = command) when is_binary(name),
    do: [%{"name" => label(name), "description" => label(command["description"])}]

  defp command_entry(_command), do: []

  # The schema calls this `currentModeId`; the session-modes guide's example writes
  # `modeId`. Read either rather than pick a side, and fall back to the catch-all when
  # neither is there, so an unrecognised shape stays visible as raw.
  defp mode_events(update, raw) do
    case first_binary([
           update["currentModeId"],
           update["current_mode_id"],
           update["modeId"],
           update["mode_id"]
         ]) do
      nil -> []
      id -> [event(:provider_event, %{"kind" => "mode", "mode" => label(id)}, raw)]
    end
  end

  defp modes_payload(modes) when is_map(modes) do
    current = first_binary([modes["currentModeId"], modes["current_mode_id"]])

    available =
      modes
      |> list_field("availableModes", "available_modes")
      |> Enum.take(@max_modes)
      |> Enum.flat_map(&mode_entry/1)

    if is_nil(current) and available == [],
      do: nil,
      else: %{"kind" => "modes", "mode" => current, "modes" => available}
  end

  defp modes_payload(_modes), do: nil

  defp mode_entry(%{"id" => id} = mode) when is_binary(id),
    do: [
      %{
        "id" => label(id),
        "name" => label(mode["name"]),
        "description" => label(mode["description"])
      }
    ]

  defp mode_entry(_mode), do: []

  defp list_field(map, camel, snake) when is_map(map) do
    case Map.get(map, camel) || Map.get(map, snake) do
      list when is_list(list) -> list
      _other -> []
    end
  end

  defp list_field(_map, _camel, _snake), do: []

  defp first_binary(values), do: Enum.find(values, &(is_binary(&1) and &1 != ""))

  defp label(text) when is_binary(text), do: String.slice(text, 0, @max_label_chars)
  defp label(_other), do: ""

  defp text_event(type, update, raw) do
    content = update["content"] || %{}
    text = content["text"] || update["text"]

    if is_binary(text),
      do: [event(type, %{"text" => text}, raw)],
      else: [event(:provider_event, update, raw)]
  end

  defp permission_payload(params) do
    %{
      "tool_call" => params["toolCall"] || params["tool_call"],
      "options" => params["options"] || []
    }
  end

  defp permission_result(params, response) do
    options = params["options"] || []
    option = select_permission_option(options, response)

    if option do
      %{
        "outcome" => %{
          "outcome" => "selected",
          "optionId" => option["optionId"] || option["option_id"]
        }
      }
    else
      %{"outcome" => %{"outcome" => "cancelled"}}
    end
  end

  defp select_permission_option(options, %{decision: :approve, scope: :session}) do
    find_option(options, ["allow_always", "allow_session", "always", "allow_once"])
  end

  defp select_permission_option(options, %{decision: :approve}) do
    find_option(options, ["allow_once", "allow", "approve", "allow_always"])
  end

  defp select_permission_option(options, %{decision: :deny, scope: :session}) do
    find_option(options, ["reject_always", "deny_always", "reject_once", "deny"])
  end

  defp select_permission_option(options, %{decision: :deny}) do
    find_option(options, ["reject_once", "deny", "reject", "reject_always"])
  end

  defp find_option(options, kinds) do
    Enum.find_value(kinds, fn kind ->
      Enum.find(options, fn option ->
        option["kind"] == kind or String.downcase(to_string(option["name"] || "")) == kind
      end)
    end)
  end

  defp prompt_blocks(%TurnRequest{} = request, cwd) do
    blocks =
      if request.content == [] do
        [%{"type" => "text", "text" => TurnRequest.text(request)}]
      else
        Enum.map(request.content, &stringify_keys/1)
      end

    blocks ++
      Enum.map(request.attachments, fn path ->
        path = Path.expand(path, cwd)
        %{"type" => "resource_link", "uri" => file_uri(path), "name" => Path.basename(path)}
      end)
  end

  defp configured_cli(context, default) do
    config = context.config
    config[:cli_path] || config["cli_path"] || default
  end

  defp option(options, key) when is_map(options),
    do: Map.get(options, key) || Map.get(options, Atom.to_string(key))

  defp option(_options, _key), do: nil

  defp mcp_servers(nil), do: []
  defp mcp_servers(value) when is_list(value), do: value
  defp mcp_servers(value) when is_map(value), do: Map.values(value)
  defp mcp_servers(_value), do: []

  defp stringify_keys(map) when is_map(map),
    do: Map.new(map, fn {key, value} -> {to_string(key), stringify_keys(value)} end)

  defp stringify_keys(list) when is_list(list), do: Enum.map(list, &stringify_keys/1)
  defp stringify_keys(value), do: value

  defp file_uri(path) do
    path = Path.expand(path)
    "file://" <> URI.encode(path)
  end

  defp event(type, payload, raw),
    do: Event.new!(type: type, provider: :acp, payload: payload, raw: raw)

  defp rpc_result(%{"error" => error}), do: {:error, error}
  defp rpc_result(%{"result" => result}), do: {:ok, result || %{}}
  defp rpc_result(message), do: {:error, {:invalid_rpc_response, message}}
end
