defmodule Ouroboros.Provider.CodexSessionTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State
  alias Ouroboros.Provider.{CodexAdapter, CodexSession}

  # Transport `next_id` starts at 1: initialize, thread/start, turn/start. The fake must
  # echo those ids back. Approval uses a distinct server id so it cannot be mistaken for
  # any of those replies — the same routing bug the account connection already named.
  @transcript_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      echo '{"method":"thread/started","params":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
      echo '{"method":"turn/started","params":{"turn":{"id":"turn-prov-1"}}}'
      echo '{"method":"item/agentMessage/delta","params":{"delta":"hello"}}'
      echo '{"method":"item/completed","params":{"item":{"type":"agentMessage","text":"hello"}}}'
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
  """

  @approval_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
      echo '{"method":"item/started","params":{"item":{"type":"commandExecution","id":"cmd-1","command":"git commit -am wip","cwd":"/tmp/ws"}}}'
      echo '{"id":99,"method":"item/commandExecution/requestApproval","params":{"command":"git commit -am wip","cwd":"/tmp/ws","reason":"writes to .git"}}'
      ;;
    *'"decision":"acceptForSession"'*)
      echo '{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"cmd-1","command":"git commit -am wip","status":"completed","aggregatedOutput":"","exitCode":0}}}'
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"accept"'*)
      echo '{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"cmd-1","command":"git commit -am wip","status":"completed","aggregatedOutput":"","exitCode":0}}}'
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"decline"'*)
      echo '{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"cmd-1","command":"git commit -am wip","status":"declined","aggregatedOutput":"","exitCode":1}}}'
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
  """

  @unknown_method_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      echo '{"id":42,"method":"process/spawn","params":{}}'
      ;;
  """

  test "the interactive default is app-server; coding run stays on exec" do
    spec = CodexAdapter.spec()
    run = Jido.Harness.Adapters.Codex.spec()

    assert spec.default_session_transport == :app_server
    assert run.default_session_transport == :exec_jsonl_resume
    assert Enum.map(spec.session_transports, & &1.name) == [:app_server, :exec_jsonl_resume]
    assert :approval_mode in spec.normalized_options
    assert :sandbox_mode in spec.normalized_options
    assert hd(spec.session_transports).session_options == :adapter
    assert hd(spec.session_transports).capabilities.approvals == :native
  end

  test "the app-server transport declares multimodal, so a turn with an attachment validates" do
    transport = hd(CodexAdapter.spec().session_transports)

    # `turn_options: :adapter` inherits `:attachments` from the adapter; without the
    # capability the validator refused the same turn outright.
    assert transport.turn_options == :adapter
    assert :attachments in CodexAdapter.spec().normalized_options
    assert transport.capabilities.multimodal == :native

    assert Jido.Harness.InteractionCapabilities.supported?(transport.capabilities, :multimodal)
  end

  test "interactive Codex public state can complete an approval; coding cannot" do
    assert {:ok, session} = State.new("codex-session-public", provider: :codex)
    public = State.public(session)
    assert public.options.provider_execution.interactive_approvals
    assert public.options.provider_execution.escalation_behavior == :prompt

    assert {:ok, exec} =
             State.new("codex-session-exec", provider: :codex, transport: :exec_jsonl_resume)

    refute State.public(exec).options.provider_execution.interactive_approvals

    assert {:ok, task} = TaskState.new("codex-coding-public", "build", provider: :codex)
    refute TaskState.public(task).options.provider_execution.interactive_approvals

    assert TaskState.public(task).options.provider_execution.escalation_behavior ==
             :deny_when_provider_cannot_prompt
  end

  test "capability lookup still accepts prompt approvals and workspace-write" do
    assert {:ok, session} =
             State.new("codex-session-safety",
               provider: :codex,
               approval_mode: :prompt,
               sandbox_mode: :workspace_write
             )

    request = State.request(session)
    assert request.approval_mode == :prompt
    assert request.sandbox_mode == :workspace_write
  end

  test "handshake and a turn produce ordinary transcript events" do
    executable = fake_app_server(@transcript_cases)
    handle = open_session!(executable)

    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => "codex_app_server_ready"}}},
                   5_000

    assert :ok = CodexSession.send(handle, TurnRequest.new!("say hello"), "turn-1")

    delta = await_event(:output_text_delta)
    assert delta.payload["text"] == "hello"
    final = await_event(:output_text_final)
    assert final.payload["text"] == "hello"
    completed = await_event(:turn_completed)
    assert completed.turn_id == "turn-1"

    frames = logged(executable)
    initialize = Enum.find(frames, &(&1["method"] == "initialize"))
    thread = Enum.find(frames, &(&1["method"] == "thread/start"))
    turn = Enum.find(frames, &(&1["method"] == "turn/start"))

    assert initialize["id"] == 1
    assert thread["id"] == 2
    assert thread["params"]["approvalPolicy"] == "on-request"
    assert thread["params"]["sandbox"] == "workspace-write"
    assert turn["id"] == 3
    assert hd(turn["params"]["input"])["text"] == "say hello"

    assert :ok = CodexSession.close(handle)
  end

  test "a turn with attachments is accepted and reaches turn/start as input items" do
    executable = fake_app_server(@transcript_cases)
    handle = open_session!(executable)
    drain_ready()

    workspace = attachment_workspace()
    image = Path.join(workspace, "shot.PNG")
    notes = Path.join(workspace, "notes.md")
    File.write!(image, "not really a png, but a regular file")
    File.write!(notes, "# notes")

    turn = TurnRequest.new!(%{prompt: "look at this", attachments: [image, notes]})

    # The refusal X7 names lives in the harness validator, before any dialect runs.
    assert :ok =
             Jido.Harness.Session.RequestValidator.validate_turn_request(validator_state(), turn)

    assert :ok = CodexSession.send(handle, turn, "turn-1")
    assert %{turn_id: "turn-1"} = await_event(:turn_completed)

    input =
      executable
      |> logged()
      |> Enum.find(&(&1["method"] == "turn/start"))
      |> get_in(["params", "input"])

    assert [text, local_image, mentions] = input
    assert text == %{"type" => "text", "text" => "look at this"}
    assert local_image == %{"type" => "localImage", "path" => image}
    assert mentions["type"] == "text"
    assert mentions["text"] =~ "@" <> notes
    refute mentions["text"] =~ image

    assert :ok = CodexSession.close(handle)
  end

  test "a turn without attachments keeps the single text input item" do
    executable = fake_app_server(@transcript_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = CodexSession.send(handle, TurnRequest.new!("say hello"), "turn-1")
    assert %{turn_id: "turn-1"} = await_event(:turn_completed)

    input =
      executable
      |> logged()
      |> Enum.find(&(&1["method"] == "turn/start"))
      |> get_in(["params", "input"])

    assert input == [%{"type" => "text", "text" => "say hello"}]
    assert :ok = CodexSession.close(handle)
  end

  test "auto_edit asks on-request; extra writable roots keep camelCase sandboxPolicy" do
    executable = fake_app_server(@transcript_cases)

    handle =
      open_session!(executable,
        approval_mode: :auto_edit,
        add_dirs: ["/tmp/extra"],
        provider_options: %{cli_path: executable, network_access_enabled: true}
      )

    drain_ready()

    thread =
      executable
      |> logged()
      |> Enum.find(&(&1["method"] == "thread/start"))

    assert thread["params"]["approvalPolicy"] == "on-request"
    refute Map.has_key?(thread["params"], "sandbox")

    assert thread["params"]["sandboxPolicy"] == %{
             "networkAccess" => true,
             "type" => "workspaceWrite",
             "writableRoots" => ["/tmp/extra"]
           }

    assert :ok = CodexSession.close(handle)
  end

  test "a git-commit sandbox escalation becomes the existing approval modal" do
    executable = fake_app_server(@approval_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = CodexSession.send(handle, TurnRequest.new!("commit this"), "turn-1")

    approval = await_event(:approval_requested)
    assert approval.request_id == "99"
    assert approval.payload["kind"] == "sandbox_escalation"
    assert approval.payload["reason"] == "writes to .git"
    assert approval.payload["tool_call"]["command"] == "git commit -am wip"

    assert :ok =
             CodexSession.respond_approval(
               handle,
               "99",
               ApprovalResponse.new!(decision: :approve, scope: :once)
             )

    result = await_event(:tool_result)
    refute result.payload["is_error"]
    completed = await_event(:turn_completed)
    assert completed.turn_id == "turn-1"

    accept =
      executable
      |> logged()
      |> Enum.find(&(&1["id"] == 99 and is_map(&1["result"])))

    assert accept["result"] == %{"decision" => "accept"}
    assert :ok = CodexSession.close(handle)
  end

  test "declining a sandbox escalation ends the item rather than hanging the turn" do
    executable = fake_app_server(@approval_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = CodexSession.send(handle, TurnRequest.new!("commit this"), "turn-1")
    assert %{request_id: "99"} = await_event(:approval_requested)

    assert :ok =
             CodexSession.respond_approval(
               handle,
               "99",
               ApprovalResponse.new!(decision: :deny, scope: :session)
             )

    result = await_event(:tool_result)
    assert result.payload["is_error"]
    completed = await_event(:turn_completed)
    assert completed.turn_id == "turn-1"

    decline =
      executable
      |> logged()
      |> Enum.find(&(&1["id"] == 99 and is_map(&1["result"])))

    assert decline["result"] == %{"decision" => "decline"}
    assert :ok = CodexSession.close(handle)
  end

  test "closing a session declines an in-flight approval so Codex is not left waiting" do
    executable = fake_app_server(@approval_cases)
    handle = open_session!(executable)
    drain_ready()

    assert :ok = CodexSession.send(handle, TurnRequest.new!("commit this"), "turn-1")
    assert %{request_id: "99"} = await_event(:approval_requested)
    assert :ok = CodexSession.close(handle)

    assert eventually(fn ->
             Enum.any?(logged(executable), fn frame ->
               frame["id"] == 99 and frame["result"] == %{"decision" => "decline"}
             end)
           end),
           "close must decline the pending JSON-RPC id: #{inspect(logged(executable))}"
  end

  test "a method this session transport does not serve is method-not-found" do
    executable = fake_app_server(@unknown_method_cases)
    handle = open_session!(executable)
    drain_ready()

    assert eventually(fn ->
             Enum.any?(logged(executable), fn frame ->
               frame["id"] == 42 and frame["error"]["code"] == -32601
             end)
           end),
           "process/spawn must be refused: #{inspect(logged(executable))}"

    refusal = Enum.find(logged(executable), &(&1["id"] == 42))
    assert refusal["error"]["message"] =~ "serves no app-server methods"

    assert :ok = CodexSession.close(handle)
  end

  defp open_session!(executable, overrides \\ []) do
    request =
      SessionRequest.new!(
        Keyword.merge(
          [
            cwd: File.cwd!(),
            approval_mode: :prompt,
            sandbox_mode: :workspace_write,
            provider_options: %{cli_path: executable}
          ],
          overrides
        )
      )

    context = %{
      session_id: "codex-session-#{System.unique_integer([:positive])}",
      provider: :codex,
      owner: self(),
      adapter: CodexAdapter,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    assert {:ok, handle} = CodexSession.open(request, context)
    on_exit(fn -> if Process.alive?(handle), do: CodexSession.close(handle) end)
    handle
  end

  defp drain_ready do
    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => "codex_app_server_ready"}}},
                   5_000
  end

  defp attachment_workspace do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-codex-attachments-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end

  # Only the fields `validate_turn_request/2` reads. Building a live session would start a
  # second process for a check that is purely a function of capabilities and options.
  defp validator_state do
    struct(Jido.Harness.Session.State,
      provider: :codex,
      adapter: CodexAdapter,
      transport_spec: hd(CodexAdapter.spec().session_transports),
      request: SessionRequest.new!(cwd: File.cwd!())
    )
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

  defp fake_app_server(cases) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-codex-session-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    path = Path.join(dir, "codex")

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
