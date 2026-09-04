defmodule Ouroboros.Provider.Session.ServiceTest do
  use ExUnit.Case, async: false

  @moduledoc """
  C4. The other direction of ACP: an agent calling Ouroboros.

  Every test here drives a **real** `Session.Jsonl` process against a scripted ACP agent
  and asserts on the frames that crossed the wire, because the whole point of this slice
  is what an agent sees. The agent is a shell script that logs every client frame and
  reacts to it, so a reply the client writes is both the assertion target and the trigger
  for the agent's next request.
  """

  @moduletag :capture_log

  alias Jido.Harness.{ApprovalResponse, SessionRequest, TurnRequest}
  alias Ouroboros.Provider.Session.{ACP, Service}
  alias Ouroboros.Provider.Session.Dialect.ACP, as: Dialect

  setup do
    on_exit(fn ->
      Application.delete_env(:ouroboros, :permissions)
      Application.delete_env(:ouroboros, :native_sandbox)
      Application.delete_env(:ouroboros, :allow_unsandboxed_bash)
    end)

    workspace =
      Path.join(System.tmp_dir!(), "ouroboros-acp-service-#{System.unique_integer([:positive])}")

    File.mkdir_p!(Path.join(workspace, "lib"))
    on_exit(fn -> File.rm_rf(workspace) end)

    {:ok, workspace: workspace}
  end

  # ── declaration ────────────────────────────────────────────────────────────────────

  describe "the client capabilities the dialect declares" do
    test "fs and terminal are declared true, and every declared method has a handler" do
      params = Dialect.initialize_params(SessionRequest.new!(cwd: File.cwd!()))

      assert params["clientCapabilities"] == %{
               "fs" => %{"readTextFile" => true, "writeTextFile" => true},
               "terminal" => true
             }

      # The declaration is a promise to answer. Each method it promises must classify to a
      # service; a `:method_not_found` here would be a session that hangs on its first read.
      runtime = %{provider_session_id: "sess-1"}

      for method <- [
            "fs/read_text_file",
            "fs/write_text_file",
            "terminal/create",
            "terminal/output",
            "terminal/wait_for_exit",
            "terminal/kill",
            "terminal/release"
          ] do
        assert {:service, operation, _args} = Dialect.service_request(method, %{}, runtime),
               "#{method} is declared but not served"

        assert is_atom(operation)
      end

      assert Dialect.service_request("fs/delete", %{}, runtime) == :method_not_found
    end

    test "a frame naming another session's id is refused rather than served" do
      runtime = %{provider_session_id: "sess-1"}
      params = %{"sessionId" => "sess-2", "path" => "/etc/passwd"}

      assert {:service, :unknown_session, %{}} =
               Dialect.service_request("fs/read_text_file", params, runtime)

      assert {:reply, {:error, -32_602, message, _data}, _state, _actions} =
               Service.serve(Service.new(), :unknown_session, %{}, context("/tmp"))

      assert message =~ "not the one this connection serves"
    end
  end

  # ── fs/read_text_file ──────────────────────────────────────────────────────────────

  describe "fs/read_text_file" do
    test "reads a file inside the workspace and answers with its content", %{
      workspace: workspace
    } do
      File.write!(Path.join(workspace, "lib/app.ex"), "one\ntwo\nthree\n")

      executable =
        fake_acp(read_cases(Path.join(workspace, "lib/app.ex"), %{}))

      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"result" => %{"content" => "one\ntwo\nthree\n"}} = reply_to(executable, 50)
      assert :ok = ACP.close(handle)
    end

    test "honours line and limit as a window over the file", %{workspace: workspace} do
      File.write!(Path.join(workspace, "lib/app.ex"), "one\ntwo\nthree\nfour\n")

      executable =
        fake_acp(read_cases(Path.join(workspace, "lib/app.ex"), %{"line" => 2, "limit" => 2}))

      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"result" => %{"content" => "two\nthree"}} = reply_to(executable, 50)
      assert :ok = ACP.close(handle)
    end

    test "a path outside the workspace is refused after canonicalisation", %{
      workspace: workspace
    } do
      # A symlink inside the workspace pointing out of it is the case a lexical check
      # misses: `Workspace.Path` follows it before deciding, so this is refused.
      File.ln_s("/etc", Path.join(workspace, "escape"))

      executable = fake_acp(read_cases(Path.join(workspace, "escape/hosts"), %{}))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 50)
      assert message =~ "outside this session's workspace"
      assert :ok = ACP.close(handle)
    end

    test "a relative path that climbs out of the workspace is refused", %{workspace: workspace} do
      executable = fake_acp(read_cases("../../../../etc/hosts", %{}))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => code}} = reply_to(executable, 50)
      assert code in [-32_001, -32_002]
      assert :ok = ACP.close(handle)
    end

    test "a file larger than the read ceiling is refused rather than streamed", %{
      workspace: workspace
    } do
      path = Path.join(workspace, "big.txt")
      File.write!(path, String.duplicate("x", Service.limits().max_file_bytes + 1))

      executable = fake_acp(read_cases(path, %{}))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 50)
      assert message =~ "reads at most"
      assert :ok = ACP.close(handle)
    end
  end

  # ── fs/write_text_file ─────────────────────────────────────────────────────────────

  describe "fs/write_text_file" do
    test "an allow rule writes the file and emits a real unified diff", %{workspace: workspace} do
      Application.put_env(:ouroboros, :permissions, [{"Edit(**)", :allow}])
      path = Path.join(workspace, "lib/app.ex")
      File.write!(path, "alpha\nbeta\n")

      executable = fake_acp(write_cases(path, "alpha\nBETA\n"))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("edit it"), "turn-1")

      change = await_event(:file_change)
      assert change.payload["status"] == "completed"

      assert [%{"path" => "lib/app.ex", "kind" => "update", "diff" => diff}] =
               change.payload["changes"]

      assert diff =~ "--- a/lib/app.ex"
      assert diff =~ "-beta"
      assert diff =~ "+BETA"

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert %{"result" => %{}} = reply_to(executable, 51)
      assert File.read!(path) == "alpha\nBETA\n"
      assert :ok = ACP.close(handle)
    end

    test "a new file is an add, and the write creates it", %{workspace: workspace} do
      Application.put_env(:ouroboros, :permissions, [{"Write(**)", :allow}])
      path = Path.join(workspace, "lib/new.ex")

      executable = fake_acp(write_cases(path, "hello\n"))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("create it"), "turn-1")

      change = await_event(:file_change)
      assert [%{"path" => "lib/new.ex", "kind" => "add"}] = change.payload["changes"]
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert File.read!(path) == "hello\n"
      assert :ok = ACP.close(handle)
    end

    test "a deny rule answers the agent with an error and writes nothing", %{
      workspace: workspace
    } do
      Application.put_env(:ouroboros, :permissions, [{"Edit(**)", :deny}])
      path = Path.join(workspace, "lib/app.ex")
      File.write!(path, "alpha\n")

      executable = fake_acp(write_cases(path, "changed\n"))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("edit it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 51)
      assert message =~ "permission rule"
      assert File.read!(path) == "alpha\n"
      refute_received {:session_adapter_event, %{type: :approval_requested}}
      assert :ok = ACP.close(handle)
    end

    test "with no rule the write becomes an approval, and a yes performs it", %{
      workspace: workspace
    } do
      path = Path.join(workspace, "lib/app.ex")
      File.write!(path, "alpha\n")

      executable = fake_acp(write_cases(path, "approved\n"))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("edit it"), "turn-1")

      approval = await_event(:approval_requested)
      assert approval.request_id == "51"
      assert approval.payload["method"] == "fs/write_text_file"
      assert get_in(approval.payload, ["tool_call", "name"]) == "edit"
      assert get_in(approval.payload, ["tool_call", "title"]) == "write lib/app.ex"
      # The engine's own "don't ask again" pattern, computed from the request it decided:
      # the directory rather than the one file, so answering once covers the next edit in
      # the same place.
      # …and it names the *canonical* directory, because that is the path the service
      # resolved and the one a rule has to be written against.
      {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(workspace)
      assert approval.payload["suggested_rule"] == "Edit(#{Path.join(canonical, "lib")}/**)"

      assert :ok =
               ACP.respond_approval(
                 handle,
                 "51",
                 ApprovalResponse.new!(decision: :approve, scope: :once)
               )

      change = await_event(:file_change)
      assert [%{"kind" => "update"}] = change.payload["changes"]
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert %{"result" => %{}} = reply_to(executable, 51)
      assert File.read!(path) == "approved\n"
      assert :ok = ACP.close(handle)
    end

    test "a human's no answers the agent with an error rather than an empty success", %{
      workspace: workspace
    } do
      path = Path.join(workspace, "lib/app.ex")
      File.write!(path, "alpha\n")

      executable = fake_acp(write_cases(path, "refused\n"))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("edit it"), "turn-1")
      assert %{request_id: "51"} = await_event(:approval_requested)

      assert :ok =
               ACP.respond_approval(
                 handle,
                 "51",
                 ApprovalResponse.new!(decision: :deny, scope: :once, reason: "not that file")
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 51)
      assert message =~ "not that file"
      assert File.read!(path) == "alpha\n"
      assert :ok = ACP.close(handle)
    end

    test "a write larger than the ceiling is refused before anything reaches the disk", %{
      workspace: workspace
    } do
      Application.put_env(:ouroboros, :permissions, [{"Write(**)", :allow}])
      path = Path.join(workspace, "lib/huge.ex")
      oversized = String.duplicate("y", Service.limits().max_file_bytes + 1)

      assert {:reply, {:error, -32_001, message, _data}, _state, _actions} =
               Service.serve(
                 Service.new(),
                 :fs_write,
                 %{path: path, content: oversized},
                 context(workspace)
               )

      assert message =~ "writes at most"
      refute File.exists?(path)
    end
  end

  # ── the transcript ─────────────────────────────────────────────────────────────────

  describe "the transcript a service leaves" do
    test "every service is a content-minimised acp_service provider event", %{
      workspace: workspace
    } do
      File.write!(Path.join(workspace, "lib/app.ex"), "one\n")
      executable = fake_acp(read_cases(Path.join(workspace, "lib/app.ex"), %{}))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("read it"), "turn-1")

      event = await_provider_event("acp_service")
      assert event.payload["method"] == "fs/read_text_file"
      assert event.payload["outcome"] == "ok"
      # Workspace-relative, so no home directory reaches the transcript...
      assert event.payload["path"] == "lib/app.ex"
      # ...and never the file's contents.
      refute Map.has_key?(event.payload, "content")

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert :ok = ACP.close(handle)
    end

    test "a terminal event carries a digest and a bounded command, never more", %{
      workspace: workspace
    } do
      allow_unsandboxed_terminals!()
      Application.put_env(:ouroboros, :permissions, [{"Bash(echo *)", :allow}])

      executable = fake_acp(terminal_cases("echo", args: [String.duplicate("z", 400)]))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")

      event = await_provider_event("acp_service")
      assert event.payload["method"] == "terminal/create"
      assert String.length(event.payload["command"]) == 200
      assert String.length(event.payload["digest"]) == 16
      assert event.payload["sandbox"] == "none"

      assert :ok = ACP.close(handle)
    end
  end

  # ── terminals ──────────────────────────────────────────────────────────────────────

  describe "terminal/*" do
    test "create, wait, output and release carry one command's whole life", %{
      workspace: workspace
    } do
      allow_unsandboxed_terminals!()
      Application.put_env(:ouroboros, :permissions, [{"Bash(printf *)", :allow}])

      # `command` plus `args` is ACP's own shape, and the argument has spaces in it, so
      # this also pins that the argv survives the `/bin/sh -c` this runtime runs it under.
      executable = fake_acp(terminal_cases("printf", args: ["hello from the terminal"]))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"result" => %{"terminalId" => "term-1"}} = reply_to(executable, 60)
      assert %{"result" => %{"exitCode" => 0}} = reply_to(executable, 61)

      assert %{
               "result" => %{
                 "output" => output,
                 "truncated" => false,
                 "exitStatus" => exit_status
               }
             } =
               reply_to(executable, 62)

      assert output == "hello from the terminal"
      assert exit_status == %{"exitCode" => 0, "signal" => nil}
      assert %{"result" => %{}} = reply_to(executable, 63)
      assert :ok = ACP.close(handle)
    end

    test "output is bounded to the tail with truncated set", %{workspace: workspace} do
      allow_unsandboxed_terminals!()
      Application.put_env(:ouroboros, :permissions, [{"Bash(printf *)", :allow}])

      # 64 bytes asked for; the command writes 400, so only the newest bytes survive.
      executable =
        fake_acp(
          terminal_cases("printf",
            args: [String.duplicate("abcdefghij", 40)],
            output_byte_limit: 64
          )
        )

      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"result" => %{"output" => output, "truncated" => true}} = reply_to(executable, 62)
      assert byte_size(output) <= 64
      assert String.ends_with?(output, "abcdefghij")
      assert :ok = ACP.close(handle)
    end

    test "a Bash deny rule refuses a terminal exactly as it refuses the native shell", %{
      workspace: workspace
    } do
      Application.put_env(:ouroboros, :native_sandbox, :none)
      Application.put_env(:ouroboros, :permissions, [{"Bash(git push *)", :deny}])

      executable = fake_acp(terminal_cases("git", args: ["push", "--force", "origin", "main"]))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("push it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 60)
      assert message =~ "permission rule"
      assert :ok = ACP.close(handle)
    end

    test "with no rule a terminal becomes an approval, and a yes starts it", %{
      workspace: workspace
    } do
      allow_unsandboxed_terminals!()

      executable = fake_acp(terminal_cases("printf", args: ["ok"]))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")

      approval = await_event(:approval_requested)
      assert approval.request_id == "60"
      assert get_in(approval.payload, ["tool_call", "name"]) == "bash"
      assert get_in(approval.payload, ["tool_call", "command"]) == "printf ok"
      assert approval.payload["suggested_rule"] == "Bash(printf ok *)"

      assert :ok =
               ACP.respond_approval(
                 handle,
                 "60",
                 ApprovalResponse.new!(decision: :approve, scope: :once)
               )

      assert %{turn_id: "turn-1"} = await_event(:turn_completed)
      assert %{"result" => %{"terminalId" => "term-1"}} = reply_to(executable, 60)
      assert %{"result" => %{"output" => "ok"}} = reply_to(executable, 62)
      assert :ok = ACP.close(handle)
    end

    test "read_only on a node with no OS sandbox refuses the terminal", %{workspace: workspace} do
      Application.put_env(:ouroboros, :native_sandbox, :none)
      Application.put_env(:ouroboros, :permissions, [{"Bash(printf *)", :allow}])

      executable = fake_acp(terminal_cases("printf", args: ["ok"]))
      handle = open!(executable, workspace, sandbox_mode: :read_only)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 60)
      assert message =~ "read_only"
      assert message =~ "no OS sandbox"
      assert :ok = ACP.close(handle)
    end

    test "workspace_write on a node with no OS sandbox refuses the terminal", %{
      workspace: workspace
    } do
      Application.put_env(:ouroboros, :native_sandbox, :none)
      Application.put_env(:ouroboros, :allow_unsandboxed_bash, false)
      Application.put_env(:ouroboros, :permissions, [{"Bash(printf *)", :allow}])

      executable = fake_acp(terminal_cases("printf", args: ["ok"]))
      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")
      assert %{turn_id: "turn-1"} = await_event(:turn_completed)

      assert %{"error" => %{"code" => -32_001, "message" => message}} = reply_to(executable, 60)
      assert message =~ "workspace_write"
      assert message =~ "no OS sandbox"
      assert message =~ "OUROBOROS_ALLOW_UNSANDBOXED_BASH=1"
      assert :ok = ACP.close(handle)
    end

    test "a session holds at most the declared number of terminals", %{workspace: workspace} do
      state = %{Service.new() | live: Service.limits().max_terminals}

      assert {:reply, {:error, -32_001, message, data}, _state, _actions} =
               Service.serve(state, :terminal_create, %{command: "true"}, context(workspace))

      assert message =~ "already holds"
      assert data["limit"] == Service.limits().max_terminals
    end

    test "an unknown terminal id is refused rather than answered", %{workspace: workspace} do
      for operation <- [:terminal_output, :terminal_wait, :terminal_kill, :terminal_release] do
        assert {:reply, {:error, -32_602, message, _data}, _state, _actions} =
                 Service.serve(
                   Service.new(),
                   operation,
                   %{terminal_id: "term-99"},
                   context(workspace)
                 )

        assert message =~ "no such terminal"
      end
    end

    test "closing the session kills every terminal it started", %{workspace: workspace} do
      allow_unsandboxed_terminals!()
      Application.put_env(:ouroboros, :permissions, [{"Bash(sleep *)", :allow}])

      executable = fake_acp(terminal_cases("sleep", args: ["120"], stop_after: :create))

      handle = open!(executable, workspace)
      assert :ok = ACP.send(handle, TurnRequest.new!("run it"), "turn-1")

      assert eventually(fn -> reply_to(executable, 60) != nil end),
             "the terminal was never created: #{inspect(logged(executable))}"

      os_pid = terminal_os_pid(handle)
      assert is_integer(os_pid)
      assert alive?(os_pid), "the terminal child should be running before the session closes"

      assert :ok = ACP.close(handle)

      assert eventually(fn -> not alive?(os_pid) end),
             "closing the session must kill the terminals it started"
    end
  end

  # ── session/set_mode ───────────────────────────────────────────────────────────────

  describe "session/set_mode" do
    test "the transport forwards a mode the agent announced, and answers when it lands", %{
      workspace: workspace
    } do
      executable = fake_acp(mode_cases())
      handle = open!(executable, workspace)

      assert {:ok, :ok} =
               Ouroboros.Provider.Session.Jsonl.ask(handle, :set_mode, %{mode: "ask"})

      frame = Enum.find(logged(executable), &(&1["method"] == "session/set_mode"))
      assert frame["params"] == %{"sessionId" => "sess-1", "modeId" => "ask"}
      assert :ok = ACP.close(handle)
    end

    test "a mode the agent never announced is refused rather than sent", %{
      workspace: workspace
    } do
      executable = fake_acp(mode_cases())
      handle = open!(executable, workspace)

      assert {:error, {:unsupported_configuration, details}} =
               Ouroboros.Provider.Session.Jsonl.ask(handle, :set_mode, %{mode: "yolo"})

      assert details.reason == :unknown_mode
      assert details.modes == ["build", "ask"]
      refute Enum.any?(logged(executable), &(&1["method"] == "session/set_mode"))
      assert :ok = ACP.close(handle)
    end

    test "an agent that announced no modes at all has no vocabulary to be told", %{
      workspace: workspace
    } do
      executable = fake_acp(mode_cases(modes: false))
      handle = open!(executable, workspace)

      assert {:error, {:unsupported_configuration, details}} =
               Ouroboros.Provider.Session.Jsonl.ask(handle, :set_mode, %{mode: "ask"})

      assert details.reason == :no_modes_announced
      assert :ok = ACP.close(handle)
    end

    test "the ACP dialect declares agent-owned modes" do
      assert Dialect.mode_option() == {:mode, :agent_declared}

      for provider <- [:opencode, :kimi] do
        assert {:ok, %{applies: :now, settable: :any_time, ids: :agent_declared}} =
                 Ouroboros.Provider.session_mode(provider)
      end
    end

    test "the gateway carries mode as a sixth interactive.configure key" do
      {:ok, contract} = Ouroboros.Gateway.Methods.params("interactive.configure")
      mode = Enum.find(contract.params, &(&1.name == "mode"))

      assert mode.requirement == :optional
      # A string, not an enum: the allowed values belong to the agent, not to the gateway.
      assert mode.type == :string
      assert mode.note =~ "availableModes"
    end

    test "approval_mode and sandbox_mode stay refused on ACP by declaration" do
      for field <- [:approval_mode, :sandbox_mode] do
        assert {:error, {:unconfigurable_session, details}} =
                 Ouroboros.Provider.session_configuration(:opencode, %{field => :prompt})

        assert details.reason == :no_dynamic_configuration
      end
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp mode_cases(options \\ []) do
    modes =
      if Keyword.get(options, :modes, true) do
        ~s(,"modes":{"currentModeId":"build","availableModes":[{"id":"build","name":"Build"},{"id":"ask","name":"Ask"}]})
      else
        ""
      end

    """
      *'"method":"initialize"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
        ;;
      *'"method":"session/new"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"#{modes}}}'
        ;;
      *'"method":"session/set_mode"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":3,"result":{}}'
        ;;
    """
  end

  defp context(root),
    do: %{root: root, sandbox_mode: :workspace_write, turn_id: nil, rpc_id: 1}

  # An agent that reads one file when it is prompted, then finishes the turn once the
  # client has answered.
  defp read_cases(path, extra) do
    params = Map.merge(%{"sessionId" => "sess-1", "path" => path}, extra)

    """
      *'"method":"initialize"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
        ;;
      *'"method":"session/new"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
        ;;
      *'"method":"session/prompt"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":50,"method":"fs/read_text_file","params":#{JSON.encode!(params)}}'
        ;;
      *'"id":50'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
        ;;
    """
  end

  defp write_cases(path, content) do
    params = %{"sessionId" => "sess-1", "path" => path, "content" => content}

    """
      *'"method":"initialize"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
        ;;
      *'"method":"session/new"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
        ;;
      *'"method":"session/prompt"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":51,"method":"fs/write_text_file","params":#{JSON.encode!(params)}}'
        ;;
      *'"id":51'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
        ;;
    """
  end

  # create → wait_for_exit → output → release, each step triggered by the client's answer
  # to the one before it, so the whole lifecycle is one scripted conversation.
  defp terminal_cases(command, options) do
    create =
      %{"sessionId" => "sess-1", "command" => command}
      |> then(fn params ->
        case Keyword.get(options, :args) do
          nil -> params
          args -> Map.put(params, "args", args)
        end
      end)
      |> then(fn params ->
        case Keyword.get(options, :output_byte_limit) do
          nil -> params
          limit -> Map.put(params, "outputByteLimit", limit)
        end
      end)

    # Each step is triggered by the client's answer to the one before it, and the chain
    # runs to the end whether those answers were results or errors — so a refusal is
    # observed on the frame that carried it rather than by a turn that never completes.
    follow_on =
      if Keyword.get(options, :stop_after) == :create do
        """
          *'"id":60'*)
            printf '%s\\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
            ;;
        """
      else
        """
          *'"id":60'*)
            printf '%s\\n' '{"jsonrpc":"2.0","id":61,"method":"terminal/wait_for_exit","params":{"sessionId":"sess-1","terminalId":"term-1"}}'
            ;;
          *'"id":61'*)
            printf '%s\\n' '{"jsonrpc":"2.0","id":62,"method":"terminal/output","params":{"sessionId":"sess-1","terminalId":"term-1"}}'
            ;;
          *'"id":62'*)
            printf '%s\\n' '{"jsonrpc":"2.0","id":63,"method":"terminal/release","params":{"sessionId":"sess-1","terminalId":"term-1"}}'
            ;;
          *'"id":63'*)
            printf '%s\\n' '{"jsonrpc":"2.0","id":3,"result":{"stopReason":"end_turn"}}'
            ;;
        """
      end

    """
      *'"method":"initialize"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}'
        ;;
      *'"method":"session/new"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-1"}}'
        ;;
      *'"method":"session/prompt"'*)
        printf '%s\\n' '{"jsonrpc":"2.0","id":60,"method":"terminal/create","params":#{JSON.encode!(create)}}'
        ;;
    #{follow_on}
    """
  end

  # ACP terminal tests that exercise spawn, approval, and kill — not the fail-closed
  # sandbox decision — opt into the old unsandboxed path explicitly. The default
  # `workspace_write` + `:none` refusal is asserted on its own cases.
  defp allow_unsandboxed_terminals! do
    Application.put_env(:ouroboros, :native_sandbox, :none)
    Application.put_env(:ouroboros, :allow_unsandboxed_bash, true)
  end

  defp open!(executable, workspace, options \\ []) do
    request =
      SessionRequest.new!([cwd: workspace, provider_options: %{cli_path: executable}] ++ options)

    context = %{
      session_id: "acp-service-#{System.unique_integer([:positive])}",
      provider: :opencode,
      owner: self(),
      adapter: Ouroboros.Provider.OpenCodeAdapter,
      config: %{},
      process_manager: Jido.Harness.ProcessManager,
      telemetry_context: %{}
    }

    assert {:ok, handle} = ACP.open(request, context)
    on_exit(fn -> if Process.alive?(handle), do: ACP.close(handle) end)

    assert_receive {:session_adapter_event,
                    %{type: :provider_event, payload: %{"kind" => "acp_session_ready"}}},
                   5_000

    handle
  end

  defp terminal_os_pid(handle) do
    handle
    |> :sys.get_state()
    |> Map.fetch!(:services)
    |> Map.fetch!(:terminals)
    |> Map.values()
    |> List.first()
    |> case do
      nil -> nil
      terminal -> terminal.os_pid
    end
  end

  defp alive?(os_pid) do
    {_output, status} =
      System.cmd("/bin/kill", ["-0", Integer.to_string(os_pid)], stderr_to_stdout: true)

    status == 0
  end

  defp reply_to(executable, id) do
    executable
    |> logged()
    |> Enum.find(&(&1["id"] == id and (is_map(&1["result"]) or is_map(&1["error"]))))
  end

  defp await_event(type, timeout \\ 10_000) do
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

  defp await_provider_event(kind, timeout \\ 10_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    await_provider_event_until(kind, deadline)
  end

  defp await_provider_event_until(kind, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    if remaining <= 0, do: flunk("did not receive a provider event of kind #{inspect(kind)}")

    receive do
      {:session_adapter_event, %{type: :provider_event, payload: %{"kind" => ^kind}} = event} ->
        event

      {:session_adapter_event, _other} ->
        await_provider_event_until(kind, deadline)
    after
      remaining -> flunk("did not receive a provider event of kind #{inspect(kind)}")
    end
  end

  defp logged(executable) do
    case File.read(executable <> ".log") do
      {:ok, contents} ->
        contents
        |> String.split("\n", trim: true)
        |> Enum.flat_map(fn line ->
          case JSON.decode(line) do
            {:ok, frame} -> [frame]
            _partial -> []
          end
        end)

      {:error, _reason} ->
        []
    end
  end

  defp eventually(condition, attempts \\ 200) do
    cond do
      condition.() -> true
      attempts > 0 -> Process.sleep(25) && eventually(condition, attempts - 1)
      true -> false
    end
  end

  defp fake_acp(cases) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-acp-service-cli-#{System.unique_integer([:positive])}"
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
