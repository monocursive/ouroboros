defmodule Ouroboros.Provider.PermissionsSeamTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Provider.{CodexAdapter, CodexSession}
  alias Ouroboros.Provider.Session.ACP

  # ── fixtures ───────────────────────────────────────────────────────────────────────

  @acp_cases """
    *'"method":"initialize"'*)
      echo '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
      ;;
    *'"method":"session/new"'*)
      echo '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
      ;;
    *'"method":"session/prompt"'*)
      echo '{"jsonrpc":"2.0","id":99,"method":"session/request_permission","params":{"toolCall":{"name":"bash","kind":"execute","title":"cargo test","rawInput":{"command":"cargo test --all"}},"options":[{"kind":"allow_once","optionId":"once"},{"kind":"allow_always","optionId":"always"},{"kind":"reject_once","optionId":"deny"}]}}'
      ;;
    *'"optionId":"once"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"optionId":"always"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"optionId":"deny"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
      ;;
    *'"outcome":"cancelled"'*)
      echo '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"cancelled"}}'
      ;;
  """

  @codex_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
      echo '{"id":99,"method":"item/commandExecution/requestApproval","params":{"command":"cargo test --all","cwd":"/tmp/ws","reason":"needs the network"}}'
      ;;
    *'"decision":"accept"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"acceptForSession"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"decline"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
  """

  setup do
    on_exit(fn -> Application.delete_env(:ouroboros, :permissions) end)
    :ok
  end

  # ── ACP ────────────────────────────────────────────────────────────────────────────

  describe "the ACP seam" do
    test "with no rule the approval reaches the human, carrying a rule it could write" do
      handle = open_acp!(fake_acp(@acp_cases))
      assert :ok = ACP.send(handle, TurnRequest.new!("run the tests"), "turn-1")

      approval = await_event(:approval_requested)
      assert approval.request_id == "99"
      # Everything the modal showed before still arrives...
      assert get_in(approval.payload, ["tool_call", "rawInput", "command"]) == "cargo test --all"
      assert is_list(approval.payload["options"])
      # ...plus the rule that would stop the question recurring.
      assert approval.payload["suggested_rule"] == "Bash(cargo test *)"
    end

    test "an allow rule answers the agent without ever asking a human" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(cargo *)", :allow}])
      executable = fake_acp(@acp_cases)
      handle = open_acp!(executable)

      assert :ok = ACP.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      # The permission id was answered with the agent's own allow option...
      reply = reply_to(executable, 99)
      assert get_in(reply, ["result", "outcome", "outcome"]) == "selected"
      assert get_in(reply, ["result", "outcome", "optionId"]) == "once"
      # ...and no approval was ever emitted.
      refute_received {:session_adapter_event, %{type: :approval_requested}}
    end

    test "a deny rule refuses the agent without ever asking a human" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(cargo *)", :deny}])
      executable = fake_acp(@acp_cases)
      handle = open_acp!(executable)

      assert :ok = ACP.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      reply = reply_to(executable, 99)
      assert get_in(reply, ["result", "outcome", "optionId"]) == "deny"
      refute_received {:session_adapter_event, %{type: :approval_requested}}
    end

    test "a human's session-scoped yes is recorded and becomes a rule" do
      executable = fake_acp(@acp_cases)
      {handle, session_id} = open_acp_with_id!(executable)

      assert :ok = ACP.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok =
               ACP.respond_approval(
                 handle,
                 "99",
                 ApprovalResponse.new!(%{decision: :approve, scope: :session})
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert eventually(fn ->
               match?({:ok, %{status: :ok}}, EffectLedger.get("approval-#{session_id}:99"))
             end),
             "the human's answer must reach the ledger"

      {:ok, entry} = EffectLedger.get("approval-#{session_id}:99")
      assert entry.effect == :permission
      assert entry.principal == session_id
      assert entry.result == %{decision: :approve, scope: :session, actor: :human, rule_id: nil}

      assert eventually(fn ->
               {:ok, rules} = Permissions.list(scope: :session)

               Enum.any?(
                 rules,
                 &(&1.session_id == session_id and &1.pattern == "Bash(cargo test *)")
               )
             end),
             "a session-scoped yes must become a session rule"

      Permissions.forget_session(session_id)
    end

    test "a once-scoped answer is recorded and writes no rule" do
      executable = fake_acp(@acp_cases)
      {handle, session_id} = open_acp_with_id!(executable)

      assert :ok = ACP.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok = ACP.respond_approval(handle, "99", ApprovalResponse.new!(:deny))
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert eventually(fn ->
               match?({:ok, %{status: :denied}}, EffectLedger.get("approval-#{session_id}:99"))
             end)

      {:ok, rules} = Permissions.list(scope: :session)
      refute Enum.any?(rules, &(&1.session_id == session_id))
    end
  end

  # ── Codex app-server ───────────────────────────────────────────────────────────────

  describe "the app-server seam" do
    test "with no rule the approval reaches the human, carrying a rule it could write" do
      handle = open_codex!(fake_app_server(@codex_cases))
      assert :ok = CodexSession.send(handle, TurnRequest.new!("run the tests"), "turn-1")

      approval = await_event(:approval_requested)
      assert approval.request_id == "99"
      assert approval.payload["kind"] == "sandbox_escalation"
      assert get_in(approval.payload, ["tool_call", "command"]) == "cargo test --all"
      assert approval.payload["suggested_rule"] == "Bash(cargo test *)"
    end

    test "an allow rule accepts for the app server without asking a human" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(cargo *)", :allow}])
      executable = fake_app_server(@codex_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert reply_to(executable, 99)["result"] == %{"decision" => "accept"}
      refute_received {:session_adapter_event, %{type: :approval_requested}}
    end

    test "a deny rule declines for the app server without asking a human" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(cargo *)", :deny}])
      executable = fake_app_server(@codex_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("run the tests"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert reply_to(executable, 99)["result"] == %{"decision" => "decline"}
      refute_received {:session_adapter_event, %{type: :approval_requested}}
    end

    test "a protected write is refused even where the operator allowed the command" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(echo *)", :allow}])

      cases = """
        *'"method":"initialize"'*)
          echo '{"id":1,"result":{"userAgent":"fake"}}'
          ;;
        *'"method":"thread/start"'*)
          echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
          ;;
        *'"method":"turn/start"'*)
          echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
          echo '{"id":99,"method":"item/commandExecution/requestApproval","params":{"command":"echo pwned > .git/hooks/pre-commit","cwd":"#{File.cwd!()}"}}'
          ;;
        *'"decision":"decline"'*)
          echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
          ;;
        *'"decision":"accept"'*)
          echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
          ;;
      """

      executable = fake_app_server(cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("write a hook"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert reply_to(executable, 99)["result"] == %{"decision" => "decline"}
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp open_acp!(executable), do: elem(open_acp_with_id!(executable), 0)

  defp open_acp_with_id!(executable) do
    session_id = "acp-seam-#{System.unique_integer([:positive])}"
    request = SessionRequest.new!(cwd: File.cwd!(), provider_options: %{cli_path: executable})

    context = %{
      session_id: session_id,
      provider: :opencode,
      owner: self(),
      adapter: Ouroboros.Provider.OpenCodeAdapter,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    assert {:ok, handle} = ACP.open(request, context)
    on_exit(fn -> if Process.alive?(handle), do: ACP.close(handle) end)
    drain_ready("acp_session_ready")
    {handle, session_id}
  end

  defp open_codex!(executable) do
    request =
      SessionRequest.new!(
        cwd: File.cwd!(),
        approval_mode: :prompt,
        sandbox_mode: :workspace_write,
        provider_options: %{cli_path: executable}
      )

    context = %{
      session_id: "codex-seam-#{System.unique_integer([:positive])}",
      provider: :codex,
      owner: self(),
      adapter: CodexAdapter,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    assert {:ok, handle} = CodexSession.open(request, context)
    on_exit(fn -> if Process.alive?(handle), do: CodexSession.close(handle) end)
    drain_ready("codex_app_server_ready")
    handle
  end

  defp drain_ready(kind) do
    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => ^kind}}},
                   5_000
  end

  defp await_event(type, timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_event_until(type, deadline)
  end

  defp await_event_until(type, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    if remaining <= 0, do: flunk("did not receive #{inspect(type)}")

    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event_until(type, deadline)
    after
      remaining -> flunk("did not receive #{inspect(type)}")
    end
  end

  defp reply_to(executable, id) do
    assert eventually(fn ->
             Enum.any?(logged(executable), &(&1["id"] == id and is_map(&1["result"])))
           end),
           "expected an answer to id #{id}: #{inspect(logged(executable))}"

    Enum.find(logged(executable), &(&1["id"] == id and is_map(&1["result"])))
  end

  defp logged(executable) do
    case File.read(executable <> ".log") do
      {:ok, contents} ->
        contents |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)

      {:error, _reason} ->
        []
    end
  end

  defp eventually(condition, attempts \\ 80) do
    cond do
      condition.() -> true
      attempts > 0 -> Process.sleep(25) && eventually(condition, attempts - 1)
      true -> false
    end
  end

  defp fake_acp(cases), do: fake_process("acp-cli", cases)
  defp fake_app_server(cases), do: fake_process("codex", cases)

  defp fake_process(name, cases) do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-seam-#{System.unique_integer([:positive])}")

    File.mkdir_p!(dir)
    path = Path.join(dir, name)

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
