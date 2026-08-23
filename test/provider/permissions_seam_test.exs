defmodule Ouroboros.Provider.PermissionsSeamTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Permissions
  alias Ouroboros.Provider.{CodexAdapter, CodexSession}
  alias Ouroboros.Provider.Session.ACP
  alias Ouroboros.Test.CodexSchema

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

  # `proposedExecpolicyAmendment` is the app server's own offer: the argv prefix that,
  # amended into its execpolicy, stops it asking about commands like this one
  # (`CommandExecutionRequestApprovalParams`, codex-cli 0.147.0).
  @amendment_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
      echo '{"id":99,"method":"item/commandExecution/requestApproval","params":{"itemId":"item-1","threadId":"thread-1","turnId":"turn-prov-1","startedAtMs":1,"command":"git status --short","cwd":"/tmp/ws","reason":"reads the index","proposedExecpolicyAmendment":["git","status"]}}'
      ;;
    *'"acceptWithExecpolicyAmendment"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"acceptForSession"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"accept"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"decision":"decline"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
  """

  # 33 tokens: one past `@max_amendment_tokens`, so nothing about this is a prefix.
  @oversized_amendment_cases String.replace(
                               @amendment_cases,
                               ~s("proposedExecpolicyAmendment":["git","status"]),
                               ~s("proposedExecpolicyAmendment":[) <>
                                 Enum.map_join(1..33, ",", &~s("t#{&1}")) <> "]"
                             )

  # `item/permissions/requestApproval` asks for a sandbox profile rather than a command:
  # `fileSystem.entries` are the paths, each a literal path, a glob, or a named special
  # location, and `network.enabled` opens the sandbox's network
  # (`PermissionsRequestApprovalParams`, codex-cli 0.147.0).
  @permissions_cases """
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{"userAgent":"fake"}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
      echo '{"id":99,"method":"item/permissions/requestApproval","params":{"itemId":"item-1","threadId":"thread-1","turnId":"turn-prov-1","startedAtMs":1,"cwd":"/tmp/ws","reason":"needs the vendor tree","permissions":{"fileSystem":{"entries":[{"access":"read","path":{"type":"path","path":"/tmp/ws/vendor"}},{"access":"write","path":{"type":"glob_pattern","pattern":"/tmp/ws/build/**"}}]},"network":{"enabled":true}}}}'
      ;;
    *'"permissions":{}'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"scope":"turn"'*)
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
      ;;
    *'"scope":"session"'*)
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

      # ...and dies with the session, which is what makes the scope mean what it says.
      assert :ok = ACP.close(handle)

      assert eventually(fn ->
               {:ok, rules} = Permissions.list(scope: :session)
               not Enum.any?(rules, &(&1.session_id == session_id))
             end),
             "a session rule must not outlive its session"
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

  # ── acceptWithExecpolicyAmendment ──────────────────────────────────────────────────

  describe "an execpolicy amendment the app server proposes" do
    test "is offered on the approval only when the request carries one" do
      handle = open_codex!(fake_app_server(@amendment_cases))
      assert :ok = CodexSession.send(handle, TurnRequest.new!("check the tree"), "turn-1")

      approval = await_event(:approval_requested)

      # The prefix, not the command line: `["git", "status"]` is what the app server
      # offered to stop asking about, and it is already content-minimised at the source.
      assert approval.payload["execpolicy_amendment"] == ["git", "status"]

      # Beside it, the rule *this* runtime would write for the same answer. The two are
      # the same intent in two policy languages, which is what makes one answer honest.
      assert approval.payload["suggested_rule"] == "Bash(git status *)"
    end

    test "is absent from an approval whose request proposed nothing" do
      handle = open_codex!(fake_app_server(@codex_cases))
      assert :ok = CodexSession.send(handle, TurnRequest.new!("run the tests"), "turn-1")

      approval = await_event(:approval_requested)
      refute Map.has_key?(approval.payload, "execpolicy_amendment")
      assert approval.payload["suggested_rule"] == "Bash(cargo test *)"
    end

    test "a session-scoped yes amends Codex's policy and writes the rule that stops the next ask" do
      executable = fake_app_server(@amendment_cases)
      {handle, session_id} = open_codex_with_id!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("check the tree"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok =
               CodexSession.respond_approval(
                 handle,
                 "99",
                 ApprovalResponse.new!(%{decision: :approve, scope: :session})
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      # Half one: Codex's own execpolicy, in the shape its schema declares.
      reply = reply_to(executable, 99)["result"]

      assert reply == %{
               "decision" => %{
                 "acceptWithExecpolicyAmendment" => %{"execpolicy_amendment" => ["git", "status"]}
               }
             }

      CodexSchema.assert_valid!(reply, "CommandExecutionRequestApprovalResponse")

      # Half two: this runtime's own policy. Without it the app server would stop asking
      # while Ouroboros kept asking, which is the half that would have made the offer a lie.
      assert eventually(fn ->
               {:ok, rules} = Permissions.list(scope: :session)

               Enum.any?(
                 rules,
                 &(&1.session_id == session_id and &1.pattern == "Bash(git status *)")
               )
             end),
             "a session-scoped yes must become a session rule"

      # And the rule answers, rather than merely existing: the next identical request is
      # decided by the engine and never reaches a human.
      assert {:allow, %{pattern: "Bash(git status *)"}} =
               Permissions.evaluate(%{
                 principal: %{session_id: session_id, provider: :codex, node: node()},
                 tool: "bash",
                 command: "git status --short",
                 paths: [],
                 mode: :execute,
                 domains: [],
                 context: %{}
               })
    end

    test "a once-scoped yes moves no policy at all" do
      executable = fake_app_server(@amendment_cases)
      {handle, session_id} = open_codex_with_id!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("check the tree"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok =
               CodexSession.respond_approval(
                 handle,
                 "99",
                 ApprovalResponse.new!(%{decision: :approve, scope: :once})
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert reply_to(executable, 99)["result"] == %{"decision" => "accept"}

      {:ok, rules} = Permissions.list(scope: :session)
      refute Enum.any?(rules, &(&1.session_id == session_id))
    end

    test "a proposal too large to be a command prefix is refused rather than trimmed" do
      executable = fake_app_server(@oversized_amendment_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("check the tree"), "turn-1")
      approval = await_event(:approval_requested)

      # Trimming would send a *shorter* prefix, which allows strictly more than the app
      # server offered. So the option is not advertised and the answer falls back.
      refute Map.has_key?(approval.payload, "execpolicy_amendment")

      assert :ok =
               CodexSession.respond_approval(
                 handle,
                 "99",
                 ApprovalResponse.new!(%{decision: :approve, scope: :session})
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert reply_to(executable, 99)["result"] == %{"decision" => "acceptForSession"}
    end

    test "a rule's own yes accepts, and never widens Codex's policy on a human's behalf" do
      Application.put_env(:ouroboros, :permissions, [{"Bash(git *)", :allow}])
      executable = fake_app_server(@amendment_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("check the tree"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert reply_to(executable, 99)["result"] == %{"decision" => "accept"}
      refute_received {:session_adapter_event, %{type: :approval_requested}}
    end
  end

  # ── item/permissions/requestApproval ───────────────────────────────────────────────

  describe "a permissions escalation" do
    test "reaches the human with the paths and network access it asks for" do
      handle = open_codex!(fake_app_server(@permissions_cases))
      assert :ok = CodexSession.send(handle, TurnRequest.new!("read the vendor tree"), "turn-1")

      approval = await_event(:approval_requested)
      assert approval.payload["kind"] == "permissions"

      assert approval.payload["permissions"] == %{
               "filesystem" => [
                 %{"access" => "read", "path" => "/tmp/ws/vendor"},
                 %{"access" => "write", "path" => "/tmp/ws/build/**"}
               ],
               "network" => true,
               "not_shown" => 0
             }

      assert approval.payload["reason"] == "needs the vendor tree"
    end

    test "grants exactly the profile requested, at the scope the human answered" do
      executable = fake_app_server(@permissions_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("read the vendor tree"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok =
               CodexSession.respond_approval(
                 handle,
                 "99",
                 ApprovalResponse.new!(%{decision: :approve, scope: :once})
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      reply = reply_to(executable, 99)["result"]

      # `PermissionGrantScope` is `turn | session`, the same distinction `:once` and
      # `:session` already draw — so `:once` grants for the turn and nothing longer.
      assert reply["scope"] == "turn"
      assert reply["permissions"]["network"] == %{"enabled" => true}
      assert length(reply["permissions"]["fileSystem"]["entries"]) == 2

      CodexSchema.assert_valid!(reply, "PermissionsRequestApprovalResponse")
    end

    test "grants nothing when refused, in the shape the schema requires" do
      executable = fake_app_server(@permissions_cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("read the vendor tree"), "turn-1")
      assert %{request_id: "99"} = await_event(:approval_requested)

      assert :ok = CodexSession.respond_approval(handle, "99", ApprovalResponse.new!(:deny))
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      # Not an absent field: `permissions` is required, so a refusal is an empty granted
      # profile — every optional grant withheld.
      reply = reply_to(executable, 99)["result"]
      assert reply == %{"permissions" => %{}}
      CodexSchema.assert_valid!(reply, "PermissionsRequestApprovalResponse")
    end

    test "is decided by a rule on the paths it names, without asking a human" do
      # Rooted in the session's own workspace rather than `/tmp`: paths are canonicalised
      # before they are matched, and on macOS `/tmp` canonicalises to `/private/tmp`, so a
      # rule written against the literal `/tmp` would never match what the engine sees.
      workspace = File.cwd!()

      cases = """
        *'"method":"initialize"'*)
          echo '{"id":1,"result":{"userAgent":"fake"}}'
          ;;
        *'"method":"thread/start"'*)
          echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
          ;;
        *'"method":"turn/start"'*)
          echo '{"id":3,"result":{"turn":{"id":"turn-prov-1","status":"inProgress"}}}'
          echo '{"id":99,"method":"item/permissions/requestApproval","params":{"itemId":"item-1","threadId":"thread-1","turnId":"turn-prov-1","startedAtMs":1,"cwd":"#{workspace}","permissions":{"fileSystem":{"entries":[{"access":"write","path":{"type":"path","path":"#{workspace}/vendor"}}]}}}}'
          ;;
        *'"permissions":{}'*)
          echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
          ;;
        *'"scope":"turn"'*)
          echo '{"method":"turn/completed","params":{"turn":{"id":"turn-prov-1","status":"completed"}}}'
          ;;
      """

      Application.put_env(:ouroboros, :permissions, [{"Edit(#{workspace}/**)", :deny}])
      executable = fake_app_server(cases)
      handle = open_codex!(executable)

      assert :ok = CodexSession.send(handle, TurnRequest.new!("read the vendor tree"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert reply_to(executable, 99)["result"] == %{"permissions" => %{}}
      refute_received {:session_adapter_event, %{type: :approval_requested}}
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

  defp open_codex!(executable), do: elem(open_codex_with_id!(executable), 0)

  defp open_codex_with_id!(executable) do
    session_id = "codex-seam-#{System.unique_integer([:positive])}"

    request =
      SessionRequest.new!(
        cwd: File.cwd!(),
        approval_mode: :prompt,
        sandbox_mode: :workspace_write,
        provider_options: %{cli_path: executable}
      )

    context = %{
      session_id: session_id,
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
    {handle, session_id}
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
