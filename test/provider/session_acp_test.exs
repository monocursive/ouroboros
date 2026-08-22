defmodule Ouroboros.Provider.Session.ACPTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Provider.Session.ACP

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
