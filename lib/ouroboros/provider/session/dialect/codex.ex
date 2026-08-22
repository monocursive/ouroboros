defmodule Ouroboros.Provider.Session.Dialect.Codex do
  @moduledoc false

  @behaviour Ouroboros.Provider.Session.Dialect

  alias Jido.Harness.{Event, InteractionCapabilities, TurnRequest}

  @approval_methods [
    "item/commandExecution/requestApproval",
    "item/fileChange/requestApproval",
    "item/permissions/requestApproval"
  ]

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
      interrupt: :native,
      approvals: :native,
      dynamic_model: :managed,
      dynamic_configuration: :managed
    )
  end

  @impl true
  def command(request, context) do
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

  @impl true
  def after_initialize(_result, request, _runtime) do
    {method, params} =
      if is_binary(request.provider_session_id) do
        {"thread/resume",
         Map.put(thread_params(request), "threadId", request.provider_session_id)}
      else
        {"thread/start", thread_params(request)}
      end

    {:handshake, [{:notify, "initialized", %{}}, {:open, method, params}]}
  end

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

  @impl true
  def steer(_runtime, _request, _request_id), do: {:error, :unsupported}

  @impl true
  def configure(_runtime, _changes), do: {:error, :unsupported}

  @impl true
  def approval_request(method, params) when method in @approval_methods,
    do: {:approval, approval_payload(method, params), %{params: params}}

  def approval_request(_method, _params), do: :method_not_found

  @impl true
  def approval_reply(response, _stash), do: %{"decision" => decision(response)}

  @impl true
  def deny_reply(_stash), do: %{"decision" => "decline"}

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

  defp approval_payload(method, params) do
    command = command_text(params)
    reason = params["reason"]
    cwd = params["cwd"]

    tool_call =
      %{"name" => approval_name(method), "command" => command, "cwd" => cwd}
      |> reject_nils()

    %{"tool_call" => tool_call, "reason" => reason, "kind" => approval_kind(method)}
    |> reject_nils()
  end

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

  defp decision(%{decision: :approve, scope: :session}), do: "acceptForSession"
  defp decision(%{decision: :approve}), do: "accept"
  defp decision(%{decision: :deny}), do: "decline"

  defp thread_params(request) do
    %{"cwd" => Path.expand(request.cwd)}
    |> maybe_put("model", request.model)
    |> put_approval(request.approval_mode)
    |> put_sandbox(request)
  end

  defp turn_params(runtime, turn) do
    %{
      "threadId" => runtime.provider_session_id,
      "input" => [%{"type" => "text", "text" => TurnRequest.text(turn)}]
    }
    |> maybe_put("model", turn_model(runtime, turn))
    |> maybe_put("effort", effort(turn.reasoning_effort || runtime.request.reasoning_effort))
    |> put_approval(runtime.request.approval_mode)
    |> put_sandbox(runtime.request)
  end

  defp turn_model(_runtime, %{provider_options: options}) when is_map(options),
    do: option(options, :model)

  defp turn_model(runtime, _turn), do: runtime.request.model

  defp put_approval(params, :prompt), do: Map.put(params, "approvalPolicy", "onRequest")
  defp put_approval(params, :auto_edit), do: Map.put(params, "approvalPolicy", "onFailure")
  defp put_approval(params, :auto_approve), do: Map.put(params, "approvalPolicy", "never")
  defp put_approval(params, _mode), do: params

  defp put_sandbox(params, request) do
    {key, value} = sandbox_field(request)
    Map.put(params, key, value)
  end

  defp sandbox_field(request) do
    case request.sandbox_mode do
      :read_only ->
        {"sandbox", "readOnly"}

      :unrestricted ->
        {"sandbox", "dangerFullAccess"}

      mode when mode in [:workspace_write, :default, nil] ->
        workspace_write_field(request)

      _other ->
        {"sandbox", "workspaceWrite"}
    end
  end

  defp workspace_write_field(request) do
    dirs = extra_dirs(request)
    network = option(request.provider_options, :network_access_enabled)

    if dirs == [] and not is_boolean(network) do
      {"sandbox", "workspaceWrite"}
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
