defmodule Ouroboros.Provider.Session.Dialect.ACP do
  @moduledoc false

  @behaviour Ouroboros.Provider.Session.Dialect

  alias Jido.Harness.{ApprovalResponse, Event, InteractionCapabilities, TurnRequest}

  # Bounds on what one ACP update may turn into. The wire applies no byte cap of its own
  # (a payload crosses the socket whole on every replay), so the dialect is where an
  # unbounded agent has to be cut down.
  @max_file_changes 64
  @max_commands 64
  @max_modes 32
  @max_label_chars 200

  # Either side of one edit above this and the diff is replaced by a note. `oldText` and
  # `newText` are whole file bodies; a line-wise diff of two 50 MB buffers is not a thing
  # to compute inside a session process, let alone to broadcast.
  @max_diff_bytes 1_048_576
  @diff_context 3

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

  @doc """
  Session modes carried by a `session/new` / `session/load` result.

  Not a `Dialect` callback: `Dialect.verify!/1` pins an exact callback list and the
  app-server dialect has nothing to say here. `Session.Jsonl` calls this when a dialect
  exports it, so the modes an ACP agent offers reach the client next to the ready event
  instead of being dropped with the rest of the open result.
  """
  @spec session_opened(term(), map()) :: [{:emit, atom(), map(), keyword()}]
  def session_opened(result, _state) when is_map(result) do
    case modes_payload(result["modes"]) do
      nil -> []
      payload -> [{:emit, :provider_event, payload, []}]
    end
  end

  def session_opened(_result, _state), do: []

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
  # `--- a/<path>` / `+++ b/<path>` headers, not a summary.
  defp file_change(%{"path" => path} = block) when is_binary(path) do
    old = block["oldText"]
    new = block["newText"]

    [
      %{
        "path" => path,
        "kind" => change_kind(old, new),
        "diff" => unified_diff(path, text_or_empty(old), text_or_empty(new))
      }
    ]
  end

  defp file_change(_block), do: []

  # ACP spells a new file as a null `oldText`.
  defp change_kind(nil, _new), do: "add"
  defp change_kind(_old, nil), do: "delete"
  defp change_kind(_old, _new), do: "update"

  defp change_status(%{"status" => status}) when is_binary(status), do: status
  defp change_status(_update), do: "completed"

  defp text_or_empty(text) when is_binary(text), do: text
  defp text_or_empty(_other), do: ""

  defp unified_diff(path, old, new) do
    header = "--- a/#{path}\n+++ b/#{path}\n"

    if byte_size(old) > @max_diff_bytes or byte_size(new) > @max_diff_bytes do
      header <> "@@ truncated: #{byte_size(old) + byte_size(new)} bytes @@\n"
    else
      header <> hunks(diff_lines(old), diff_lines(new))
    end
  end

  # Line-wise, via the stdlib. A trailing newline is normalised away and no
  # "\\ No newline at end of file" marker is emitted: the diff is for reading, not for
  # feeding back to `patch`.
  defp diff_lines(""), do: []

  defp diff_lines(text) do
    lines = String.split(text, "\n")
    if List.last(lines) == "", do: Enum.drop(lines, -1), else: lines
  end

  defp hunks(old_lines, new_lines) do
    rows =
      old_lines
      |> List.myers_difference(new_lines)
      |> numbered_rows()

    rows
    |> hunk_ranges()
    |> Enum.map_join(fn {from, to} -> render_hunk(Enum.slice(rows, from..to//1)) end)
  end

  defp numbered_rows(operations) do
    {rows, _old_line, _new_line} =
      Enum.reduce(operations, {[], 1, 1}, fn {tag, lines}, accumulator ->
        Enum.reduce(lines, accumulator, fn line, {rows, old_line, new_line} ->
          case tag do
            :eq -> {[{:eq, line, old_line, new_line} | rows], old_line + 1, new_line + 1}
            :del -> {[{:del, line, old_line, new_line} | rows], old_line + 1, new_line}
            :ins -> {[{:ins, line, old_line, new_line} | rows], old_line, new_line + 1}
          end
        end)
      end)

    Enum.reverse(rows)
  end

  defp hunk_ranges(rows) do
    total = length(rows)

    rows
    |> Enum.with_index()
    |> Enum.filter(fn {{tag, _line, _old, _new}, _index} -> tag != :eq end)
    |> Enum.map(fn {_row, index} ->
      {max(index - @diff_context, 0), min(index + @diff_context, total - 1)}
    end)
    |> Enum.reduce([], fn
      {from, to}, [{previous_from, previous_to} | rest] when from <= previous_to + 1 ->
        [{previous_from, max(previous_to, to)} | rest]

      range, ranges ->
        [range | ranges]
    end)
    |> Enum.reverse()
  end

  defp render_hunk(rows) do
    old_rows = Enum.filter(rows, fn {tag, _line, _old, _new} -> tag in [:eq, :del] end)
    new_rows = Enum.filter(rows, fn {tag, _line, _old, _new} -> tag in [:eq, :ins] end)

    header =
      "@@ -#{hunk_start(old_rows, :old)},#{length(old_rows)} " <>
        "+#{hunk_start(new_rows, :new)},#{length(new_rows)} @@\n"

    header <> Enum.map_join(rows, fn {tag, line, _old, _new} -> marker(tag) <> line <> "\n" end)
  end

  defp hunk_start([], _side), do: 0
  defp hunk_start([{_tag, _line, old, _new} | _rest], :old), do: old
  defp hunk_start([{_tag, _line, _old, new} | _rest], :new), do: new

  defp marker(:eq), do: " "
  defp marker(:del), do: "-"
  defp marker(:ins), do: "+"

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
