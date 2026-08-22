defmodule Ouroboros.Provider.Session.ACPTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Provider.Session.ACP
  alias Ouroboros.Provider.Session.Dialect.ACP, as: Dialect

  @transcript_cases """
    *'"method":"initialize"'*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"method":"session/new"'*)
      echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
      ;;
    *'"method":"session/prompt"'*)
      echo '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"text":"hello"}}}}'
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
  """

  @approval_cases """
    *'"method":"initialize"'*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"method":"session/new"'*)
      echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
      ;;
    *'"method":"session/prompt"'*)
      echo '{"jsonrpc":"2.0","id":99,"method":"session/request_permission","params":{"toolCall":{"name":"bash","command":"git commit -am wip"},"options":[{"kind":"allow_once","optionId":"once"},{"kind":"allow_always","optionId":"always"},{"kind":"reject_once","optionId":"deny"}]}}'
      ;;
    *'"optionId":"once"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"optionId":"deny"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"outcome":"cancelled"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled"}}'
      ;;
  """

  @unknown_method_cases """
    *'"method":"initialize"'*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"method":"session/new"'*)
      echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
      echo '{"jsonrpc":"2.0","id":42,"method":"session/foo","params":{}}'
      ;;
  """

  # An OpenCode-shaped edit: ACP v1 carries a file change as a `diff` content block on the
  # tool call, never as a `sessionUpdate` of its own.
  @edit_cases """
    *'"method":"initialize"'*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"method":"session/new"'*)
      echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1","modes":{"currentModeId":"build","availableModes":[{"id":"build","name":"Build","description":"Edit files"},{"id":"ask","name":"Ask","description":"Read only"}]}}}'
      ;;
    *'"method":"session/prompt"'*)
      echo '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"available_commands_update","availableCommands":[{"name":"test","description":"Run tests","input":{"hint":"pattern"}}]}}}'
      echo '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"current_mode_update","currentModeId":"ask"}}}'
      echo '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"call-1","status":"completed","content":[{"type":"diff","path":"/ws/lib/app.ex","oldText":"two","newText":"TWO"}]}}}'
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
  """

  test "handshake and a prompt produce ordinary transcript events" do
    executable = fake_acp(@transcript_cases)
    handle = open_session!(executable)

    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => "acp_session_ready"}}},
                   5_000

    assert :ok = ACP.send(handle, TurnRequest.new!("say hello"), "turn-1")

    delta = await_event(:output_text_delta)
    assert delta.payload["text"] == "hello"
    completed = await_event(:turn_completed)
    assert completed.turn_id == "turn-1"

    frames = logged(executable)
    assert Enum.any?(frames, &(&1["method"] == "initialize"))
    assert Enum.any?(frames, &(&1["method"] == "session/new"))
    assert Enum.find(frames, &(&1["method"] == "initialize"))["jsonrpc"] == "2.0"

    assert :ok = ACP.close(handle)
  end

  test "a permission request becomes the existing approval modal" do
    executable = fake_acp(@approval_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = ACP.send(handle, TurnRequest.new!("commit this"), "turn-1")
    approval = await_event(:approval_requested)
    assert approval.request_id == "99"
    assert get_in(approval.payload, ["tool_call", "command"]) == "git commit -am wip"

    assert :ok =
             ACP.respond_approval(
               handle,
               "99",
               ApprovalResponse.new!(decision: :approve, scope: :once)
             )

    completed = await_event(:turn_completed)
    assert completed.turn_id == "turn-1"

    accept =
      executable
      |> logged()
      |> Enum.find(&(&1["id"] == 99 and is_map(&1["result"])))

    assert get_in(accept, ["result", "outcome", "optionId"]) == "once"
    assert :ok = ACP.close(handle)
  end

  test "a method this dialect does not serve is method-not-found" do
    executable = fake_acp(@unknown_method_cases)
    handle = open_session!(executable)
    drain_ready()

    assert eventually(fn ->
             Enum.any?(logged(executable), fn frame ->
               frame["id"] == 42 and frame["error"]["code"] == -32601
             end)
           end),
           "unknown ACP methods must be refused: #{inspect(logged(executable))}"

    assert :ok = ACP.close(handle)
  end

  test "closing a session declines an in-flight permission request" do
    executable = fake_acp(@approval_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = ACP.send(handle, TurnRequest.new!("commit this"), "turn-1")
    assert %{request_id: "99"} = await_event(:approval_requested)
    assert :ok = ACP.close(handle)

    assert eventually(fn ->
             Enum.any?(logged(executable), fn frame ->
               frame["id"] == 99 and is_map(frame["result"])
             end)
           end),
           "close must answer the pending permission id: #{inspect(logged(executable))}"

    reply = Enum.find(logged(executable), &(&1["id"] == 99 and is_map(&1["result"])))
    assert get_in(reply, ["result", "outcome", "outcome"]) in ["selected", "cancelled"]
  end

  test "an ACP edit crosses the transport as a file_change, with its modes and commands" do
    executable = fake_acp(@edit_cases)
    handle = open_session!(executable)
    drain_ready()

    modes = await_provider_event("modes")
    assert modes.payload["mode"] == "build"

    assert modes.payload["modes"] == [
             %{"id" => "build", "name" => "Build", "description" => "Edit files"},
             %{"id" => "ask", "name" => "Ask", "description" => "Read only"}
           ]

    assert :ok = ACP.send(handle, TurnRequest.new!("rename it"), "turn-1")

    commands = await_provider_event("available_commands")
    assert commands.payload["commands"] == [%{"name" => "test", "description" => "Run tests"}]

    mode = await_provider_event("mode")
    assert mode.payload["mode"] == "ask"

    change = await_event(:file_change)
    assert change.payload["status"] == "completed"

    assert [%{"path" => "/ws/lib/app.ex", "kind" => "update", "diff" => diff}] =
             change.payload["changes"]

    assert diff =~ "--- a//ws/lib/app.ex"
    assert diff =~ "+++ b//ws/lib/app.ex"
    assert diff =~ "-two"
    assert diff =~ "+TWO"

    assert %{turn_id: "turn-1"} = await_event(:turn_completed)
    assert :ok = ACP.close(handle)
  end

  test "a diff content block keeps its tool_call_update and adds the file_change" do
    update = %{
      "sessionUpdate" => "tool_call_update",
      "toolCallId" => "call-1",
      "status" => "completed",
      "content" => [
        %{
          "type" => "diff",
          "path" => "lib/renamed/app.ex",
          "oldText" => "alpha\nbeta\ngamma\ndelta\n",
          "newText" => "alpha\nBETA\ngamma\ndelta\nepsilon\n"
        }
      ]
    }

    assert [tool_result, change] = mapped(update)
    assert tool_result.type == :tool_result
    assert tool_result.payload["toolCallId"] == "call-1"

    assert change.type == :file_change

    assert [%{"path" => "lib/renamed/app.ex", "kind" => "update", "diff" => diff}] =
             change.payload["changes"]

    # The client derives the path and the +/- counts from these headers alone.
    assert String.starts_with?(diff, "--- a/lib/renamed/app.ex\n+++ b/lib/renamed/app.ex\n@@ ")
    assert diff =~ "@@ -1,4 +1,5 @@"
    assert additions(diff) == 2
    assert deletions(diff) == 1
    assert diff =~ " gamma"
  end

  test "two edits far apart become two hunks with three lines of context" do
    old = Enum.map_join(1..12, "", &"line #{&1}\n")

    new =
      old
      |> String.replace("line 3\n", "line three\n")
      |> String.replace("line 11\n", "")

    update = %{
      "sessionUpdate" => "tool_call_update",
      "content" => [
        %{"type" => "diff", "path" => "lib/app.ex", "oldText" => old, "newText" => new}
      ]
    }

    assert [_tool_result, change] = mapped(update)
    assert [%{"diff" => diff}] = change.payload["changes"]

    # Verified against `diff -u -U3` on the same two buffers: same hunk headers, same body.
    assert diff == """
           --- a/lib/app.ex
           +++ b/lib/app.ex
           @@ -1,6 +1,6 @@
            line 1
            line 2
           -line 3
           +line three
            line 4
            line 5
            line 6
           @@ -8,5 +8,4 @@
            line 8
            line 9
            line 10
           -line 11
            line 12
           """
  end

  test "a new file is an add and a removed file is a delete" do
    added =
      mapped(%{
        "sessionUpdate" => "tool_call",
        "content" => [
          %{"type" => "diff", "path" => "new.ex", "oldText" => nil, "newText" => "one\ntwo\n"}
        ]
      })

    assert [%{type: :tool_call}, %{type: :file_change} = change] = added
    assert [%{"kind" => "add", "diff" => diff}] = change.payload["changes"]
    assert diff =~ "@@ -0,0 +1,2 @@"
    assert additions(diff) == 2

    removed =
      mapped(%{
        "sessionUpdate" => "tool_call_update",
        "content" => [
          %{"type" => "diff", "path" => "gone.ex", "oldText" => "one\ntwo\n", "newText" => nil}
        ]
      })

    assert [%{type: :tool_result}, %{type: :file_change} = change] = removed
    assert [%{"kind" => "delete", "diff" => diff}] = change.payload["changes"]
    assert diff =~ "@@ -1,2 +0,0 @@"
    assert deletions(diff) == 2
  end

  test "an oversized edit is a bounded note rather than a megabyte of diff" do
    old = String.duplicate("x\n", 600_000)
    new = old <> "tail\n"
    assert byte_size(old) > 1_048_576

    update = %{
      "sessionUpdate" => "tool_call_update",
      "content" => [%{"type" => "diff", "path" => "big.txt", "oldText" => old, "newText" => new}]
    }

    assert [_tool_result, change] = mapped(update)
    assert [%{"diff" => diff}] = change.payload["changes"]

    assert diff ==
             "--- a/big.txt\n+++ b/big.txt\n" <>
               "@@ truncated: #{byte_size(old) + byte_size(new)} bytes @@\n"
  end

  test "a bare diff update is mapped too" do
    update = %{
      "sessionUpdate" => "diff",
      "path" => "notes.md",
      "oldText" => "a\n",
      "newText" => "b\n"
    }

    assert [change] = mapped(update)
    assert change.type == :file_change
    assert [%{"path" => "notes.md", "kind" => "update"}] = change.payload["changes"]
  end

  test "commands arrive bounded: names and descriptions only, list capped" do
    commands =
      Enum.map(1..100, fn index ->
        %{
          "name" => "cmd-#{index}",
          "description" => String.duplicate("d", 400),
          "input" => %{"hint" => "secretish detail"}
        }
      end)

    update = %{"sessionUpdate" => "available_commands_update", "availableCommands" => commands}

    assert [event] = mapped(update)
    assert event.type == :provider_event
    assert event.payload["kind"] == "available_commands"
    assert length(event.payload["commands"]) == 64
    assert %{"name" => "cmd-1", "description" => description} = hd(event.payload["commands"])
    assert String.length(description) == 200
    refute Enum.any?(event.payload["commands"], &Map.has_key?(&1, "input"))
  end

  test "a mode change is a bounded payload; an unreadable one stays raw" do
    assert [event] =
             mapped(%{"sessionUpdate" => "current_mode_update", "currentModeId" => "plan"})

    assert event.payload == %{"kind" => "mode", "mode" => "plan"}

    # The session-modes guide's example spells the same field `modeId`.
    assert [alias_event] = mapped(%{"sessionUpdate" => "current_mode_update", "modeId" => "plan"})
    assert alias_event.payload == %{"kind" => "mode", "mode" => "plan"}

    assert [raw] = mapped(%{"sessionUpdate" => "current_mode_update"})
    assert raw.payload["kind"] == "acp_update"
  end

  test "a user_message_chunk stays an opaque provider event" do
    update = %{"sessionUpdate" => "user_message_chunk", "content" => %{"text" => "say hello"}}

    assert [event] = mapped(update)
    assert event.type == :provider_event
    assert event.payload["kind"] == "acp_update"
  end

  test "a session result without modes emits nothing extra" do
    assert Dialect.session_opened(%{"sessionId" => "sess-1"}, %{}) == []
    assert Dialect.session_opened(%{"sessionId" => "sess-1", "modes" => %{}}, %{}) == []
    assert Dialect.session_opened(:not_a_map, %{}) == []
  end

  defp mapped(update) do
    "session/update"
    |> Dialect.handle_notification(%{"update" => update}, %{"raw" => true}, %{})
    |> Enum.map(fn {:emit_event, event} -> event end)
  end

  defp additions(diff) do
    diff
    |> String.split("\n")
    |> Enum.count(&(String.starts_with?(&1, "+") and not String.starts_with?(&1, "+++")))
  end

  defp deletions(diff) do
    diff
    |> String.split("\n")
    |> Enum.count(&(String.starts_with?(&1, "-") and not String.starts_with?(&1, "---")))
  end

  defp await_provider_event(kind, timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_provider_event_until(kind, deadline)
  end

  defp await_provider_event_until(kind, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      flunk("did not receive a provider event of kind #{inspect(kind)}")
    end

    receive do
      {:session_adapter_event, %{type: :provider_event, payload: %{"kind" => ^kind}} = event} ->
        event

      {:session_adapter_event, _other} ->
        await_provider_event_until(kind, deadline)
    after
      remaining -> flunk("did not receive a provider event of kind #{inspect(kind)}")
    end
  end

  defp open_session!(executable) do
    request =
      SessionRequest.new!(
        cwd: File.cwd!(),
        provider_options: %{cli_path: executable}
      )

    context = %{
      session_id: "acp-session-#{System.unique_integer([:positive])}",
      provider: :opencode,
      owner: self(),
      adapter: Ouroboros.Provider.OpenCodeAdapter,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    assert {:ok, handle} = ACP.open(request, context)
    on_exit(fn -> if Process.alive?(handle), do: ACP.close(handle) end)
    handle
  end

  defp drain_ready do
    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => "acp_session_ready"}}},
                   5_000
  end

  defp await_event(type, timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_event_until(type, deadline)
  end

  defp await_event_until(type, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      flunk("did not receive #{inspect(type)}")
    end

    receive do
      {:session_adapter_event, %{type: ^type} = event} ->
        event

      {:session_adapter_event, _other} ->
        await_event_until(type, deadline)
    after
      remaining ->
        flunk("did not receive #{inspect(type)}")
    end
  end

  defp logged(executable) do
    case File.read(executable <> ".log") do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.map(&JSON.decode!/1)

      {:error, _reason} ->
        []
    end
  end

  defp eventually(condition, attempts \\ 40) do
    cond do
      condition.() ->
        true

      attempts > 0 ->
        Process.sleep(25)
        eventually(condition, attempts - 1)

      true ->
        false
    end
  end

  defp fake_acp(cases) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-acp-session-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    path = Path.join(dir, "acp-cli")

    File.write!(path, """
    #!/bin/sh
    log="$0.log"
    while IFS= read -r line; do
      printf '%s\\n' "$line" >> "$log"
      case "$line" in
    #{cases}
      esac
    done
    """)

    File.chmod!(path, 0o755)
    on_exit(fn -> File.rm_rf(dir) end)
    path
  end
end
