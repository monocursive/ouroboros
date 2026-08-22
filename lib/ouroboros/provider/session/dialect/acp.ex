defmodule Ouroboros.Provider.Session.Dialect.ACP do
  @moduledoc false

  @behaviour Ouroboros.Provider.Session.Dialect

  alias Jido.Harness.{ApprovalResponse, Event, InteractionCapabilities, TurnRequest}

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

  @impl true
  def initialize_params(_request) do
    %{
      "protocolVersion" => 1,
      "clientCapabilities" => %{
        "fs" => %{"readTextFile" => false, "writeTextFile" => false},
        "terminal" => false
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

  @impl true
  def configure(_runtime, _changes), do: {:error, :unsupported}

  @impl true
  def approval_request("session/request_permission", params),
    do: {:approval, permission_payload(params), %{params: params}}

  def approval_request(_method, _params), do: :method_not_found

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

  defp map_update(%{"sessionUpdate" => type} = update, raw) do
    case type do
      "agent_message_chunk" -> text_event(:output_text_delta, update, raw)
      "agent_thought_chunk" -> text_event(:thinking_delta, update, raw)
      "tool_call" -> [event(:tool_call, update, raw)]
      "tool_call_update" -> [event(:tool_result, update, raw)]
      "plan" -> [event(:plan_updated, update, raw)]
      "usage_update" -> [event(:usage, Map.drop(update, ["sessionUpdate"]), raw)]
      _ -> [event(:provider_event, %{"kind" => "acp_update", "update" => update}, raw)]
    end
  end

  defp map_update(update, raw),
    do: [event(:provider_event, %{"kind" => "acp_update", "update" => update}, raw)]

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
