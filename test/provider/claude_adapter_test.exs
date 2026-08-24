defmodule Ouroboros.Provider.ClaudeAdapterTest do
  @moduledoc """
  What Claude Code is actually launched with, read off the process spec.

  The adapter's whole job is two elements of argv and one JSON blob, so these tests take
  the same seam `Jido.Harness.Adapters.CLIStream` offers every adapter — a
  `process_manager` in the run context — and assert on the spec that would have been
  spawned. Nothing here starts a `claude`.

  The property under all of it: the bridge is present exactly when a person could be
  asked, and the argv is byte-identical to the pinned adapter's everywhere else.
  """

  use ExUnit.Case, async: false

  # The unbridged paths log the warning they are supposed to log; one of the tests below
  # reads it back deliberately.
  @moduletag :capture_log

  alias Jido.Harness.RunRequest
  alias Ouroboros.Provider
  alias Ouroboros.Provider.ClaudeAdapter

  defmodule SpecCapture do
    @moduledoc false

    def start_owned_process(spec, owner) do
      send(owner, {:claude_process_spec, spec})
      {:ok, "claude-process"}
    end

    def stream_process("claude-process"), do: {:ok, []}
  end

  setup do
    previous_binary = Application.get_env(:ouroboros, :ouro_binary)
    previous_gateway = Application.get_env(:ouroboros, :gateway)

    on_exit(fn ->
      restore(:ouro_binary, previous_binary)
      restore(:gateway, previous_gateway)
    end)

    :ok
  end

  describe "with no ouro binary on the node" do
    test "the argv is the pinned adapter's, to the element" do
      argv = argv_for(interactive_request(approval_mode: :prompt))

      refute "--permission-prompt-tool" in argv
      refute "--mcp-config" in argv
      assert argv == pinned_argv(interactive_request(approval_mode: :prompt))
    end

    test "the transport declares no approvals and the X1 refusal still stands" do
      assert %{approvals: false} = Provider.session_capabilities(:claude, :stream_json_resume)

      assert {:error, {:unsupported_approval_mode, refusal}} =
               Provider.safety_options(:claude, [approval_mode: :prompt], {:interactive, nil})

      assert refusal.reason == :no_approval_channel
      assert refusal.message =~ "declares no approvals channel"
    end
  end

  describe "with an ouro binary and a gateway" do
    setup :bridge_available

    test "an interactive session at :prompt is launched with the permission prompt tool",
         %{binary: binary, token_file: token_file} do
      argv = argv_for(interactive_request(approval_mode: :prompt))

      assert flag_value(argv, "--permission-prompt-tool") == "mcp__ouroboros__approve"
      assert flag_value(argv, "--permission-mode") == "default"

      # The flag comes before `--`, which is what separates options from the prompt.
      assert Enum.find_index(argv, &(&1 == "--permission-prompt-tool")) <
               Enum.find_index(argv, &(&1 == "--"))

      assert List.last(argv) == "do the thing"

      assert %{"mcpServers" => %{"ouroboros" => server}} =
               argv |> flag_value("--mcp-config") |> Jason.decode!()

      assert server["command"] == binary
      assert server["args"] == ["mcp-serve"]

      # The path to the credential, never the credential — the same posture every other
      # client already has.
      assert server["env"] == %{
               "OUROBOROS_GATEWAY_ADDR" => "127.0.0.1:4599",
               "OUROBOROS_GATEWAY_TOKEN_FILE" => token_file,
               "OUROBOROS_SESSION_ID" => "session-1",
               "OUROBOROS_SESSION_NODE" => "ouroboros@somewhere"
             }

      refute Enum.any?(argv, &String.contains?(&1, String.duplicate("t", 40)))
    end

    test ":default is bridged like :prompt, because Claude's own default mode asks" do
      argv = argv_for(interactive_request(approval_mode: :default))
      assert "--permission-prompt-tool" in argv
      assert "mcp__ouroboros__approve" in argv
    end

    test "the two auto modes are left exactly as they were" do
      for mode <- [:auto_edit, :auto_approve] do
        argv = argv_for(interactive_request(approval_mode: mode))

        refute "--permission-prompt-tool" in argv, "#{mode} was bridged"
        assert argv == pinned_argv(interactive_request(approval_mode: mode))
      end
    end

    test "the coding plane is untouched: there is no human loop there to ask" do
      argv =
        argv_for(
          request(
            approval_mode: :prompt,
            metadata: %{ouroboros_task_id: "task-1", ouroboros_node: "ouroboros@somewhere"}
          )
        )

      refute "--permission-prompt-tool" in argv
      refute "--mcp-config" in argv
    end

    test "a run with no Ouroboros metadata at all is not bridged" do
      argv = argv_for(request(approval_mode: :prompt, metadata: %{}))

      refute "--permission-prompt-tool" in argv
    end

    test "the transport declares native approvals, which lifts the X1 refusal" do
      assert %{approvals: :native} = Provider.session_capabilities(:claude, :stream_json_resume)

      assert {:ok, taken} =
               Provider.safety_options(:claude, [approval_mode: :prompt], {:interactive, nil})

      assert Keyword.get(taken, :approval_mode) == :prompt
    end

    test "a node-level MCP config that is a map merges; a string is refused out loud" do
      argv =
        argv_for(
          interactive_request(
            approval_mode: :prompt,
            mcp_config: %{"docs" => %{"command" => "docs-mcp"}}
          )
        )

      assert %{"mcpServers" => servers} = argv |> flag_value("--mcp-config") |> Jason.decode!()
      assert Map.keys(servers) |> Enum.sort() == ["docs", "ouroboros"]
      assert servers["docs"] == %{"command" => "docs-mcp"}

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          argv =
            argv_for(interactive_request(approval_mode: :prompt, mcp_config: ~s({"docs": {}})))

          refute "--permission-prompt-tool" in argv
        end)

      assert log =~ "unmergeable_mcp_config"
      assert log =~ "denied by claude --print without asking"
    end

    test "the composed server definition is readable without starting a provider",
         %{binary: binary} do
      assert %{"command" => ^binary, "args" => ["mcp-serve"], "env" => env} =
               ClaudeAdapter.mcp_server("session-2", "ouroboros@elsewhere")

      assert env["OUROBOROS_SESSION_ID"] == "session-2"
      assert env["OUROBOROS_SESSION_NODE"] == "ouroboros@elsewhere"
      assert ClaudeAdapter.prompt_tool() == "mcp__ouroboros__approve"
    end

    test "a bridged session carries the post-edit diagnostics hook and its environment",
         %{binary: binary, token_file: token_file} do
      argv = argv_for(interactive_request(approval_mode: :prompt))

      assert %{"hooks" => %{"PostToolUse" => [group]}} =
               argv |> flag_value("--settings") |> Jason.decode!()

      assert group["matcher"] == "Edit|Write|MultiEdit|NotebookEdit"
      assert [%{"type" => "command", "command" => command, "timeout" => 15}] = group["hooks"]

      # The bridge environment rides in the command string, quoted and through `env` so
      # that the operator's shell being fish is not this adapter's problem. It is the same
      # four values the MCP server definition carries, and the token is a *path* in both.
      assert String.starts_with?(command, "env OUROBOROS_GATEWAY_ADDR=")
      assert command =~ "OUROBOROS_GATEWAY_ADDR='127.0.0.1:4599'"
      assert command =~ "OUROBOROS_GATEWAY_TOKEN_FILE='#{token_file}'"
      assert command =~ "OUROBOROS_SESSION_ID='session-1'"
      assert command =~ "OUROBOROS_SESSION_NODE='ouroboros@somewhere'"
      assert String.ends_with?(command, "'#{binary}' hook post-tool-use")
      refute command =~ String.duplicate("t", 40)
    end

    test "an operator's own PostToolUse hooks are kept, not replaced" do
      argv =
        argv_for(
          interactive_request(
            approval_mode: :prompt,
            provider_options: %{
              settings: %{
                "hooks" => %{
                  "PostToolUse" => [%{"matcher" => "Bash", "hooks" => [%{"type" => "command"}]}]
                },
                "model" => "opus"
              }
            }
          )
        )

      assert %{"hooks" => %{"PostToolUse" => groups}, "model" => "opus"} =
               argv |> flag_value("--settings") |> Jason.decode!()

      assert Enum.map(groups, & &1["matcher"]) == ["Bash", "Edit|Write|MultiEdit|NotebookEdit"]
    end

    test "a settings value this adapter cannot merge leaves the approval bridge standing" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          argv =
            argv_for(
              interactive_request(
                approval_mode: :prompt,
                provider_options: %{settings: ~s({"model": "opus"})}
              )
            )

          # The half that asks a human still works; only the diagnostics line is lost.
          assert "--permission-prompt-tool" in argv
          assert flag_value(argv, "--settings") == ~s({"model": "opus"})
        end)

      assert log =~ "unmergeable_settings"
      assert log =~ "without a diagnostics line"
    end

    test "an unbridged session is launched with no hook at all" do
      for mode <- [:auto_edit, :auto_approve] do
        argv = argv_for(interactive_request(approval_mode: mode))
        refute Enum.any?(argv, &String.contains?(&1, "post-tool-use")), "#{mode} carried a hook"
      end

      argv = argv_for(request(approval_mode: :prompt, metadata: %{}))
      refute Enum.any?(argv, &String.contains?(&1, "post-tool-use"))
    end
  end

  # ---------------------------------------------------------------- plan mode (B2)

  describe "plan mode" do
    test "a planning run carries --permission-mode plan" do
      argv = argv_for(request(approval_mode: :default, provider_options: %{plan: true}))

      assert flag_value(argv, "--permission-mode") == "plan"
      assert List.last(argv) == "do the thing"

      # Before the separator, like every other flag this module splices in.
      assert Enum.find_index(argv, &(&1 == "--permission-mode")) <
               Enum.find_index(argv, &(&1 == "--"))
    end

    test "plan mode replaces whatever approval_mode chose, and only that" do
      for {mode, without} <- [
            {:prompt, "default"},
            {:auto_edit, "acceptEdits"},
            {:auto_approve, "bypassPermissions"}
          ] do
        plain = request(approval_mode: mode)
        planning = request(approval_mode: mode, provider_options: %{plan: true})

        assert flag_value(argv_for(plain), "--permission-mode") == without
        assert flag_value(argv_for(planning), "--permission-mode") == "plan"

        # Exactly one element differs: the mode. Nothing else about the session moved.
        assert ClaudeAdapter.with_plan_mode(argv_for(plain), true) == argv_for(planning)
      end
    end

    test "the key is read from provider_options in either spelling" do
      assert ClaudeAdapter.planning?(request(provider_options: %{plan: true}))
      assert ClaudeAdapter.planning?(request(provider_options: %{"plan" => true}))
      refute ClaudeAdapter.planning?(request(provider_options: %{plan: false}))
      refute ClaudeAdapter.planning?(request([]))
    end

    test "plan is a declared provider option, so the harness accepts it" do
      assert :plan in ClaudeAdapter.spec().provider_options
      # And the pinned adapter's six are still all there.
      assert Enum.all?(Jido.Harness.Adapters.Claude.spec().provider_options, fn option ->
               option in ClaudeAdapter.spec().provider_options
             end)
    end

    test "a run that is not planning is byte-identical to the pinned adapter's" do
      plain = request(approval_mode: :auto_edit)
      assert argv_for(plain) == pinned_argv(plain)
    end

    test "a planning run is bridged as well when a person could be asked" do
      bridge_available(%{})

      argv =
        argv_for(interactive_request(approval_mode: :prompt, provider_options: %{plan: true}))

      assert flag_value(argv, "--permission-mode") == "plan"
      assert flag_value(argv, "--permission-prompt-tool") == "mcp__ouroboros__approve"
    end
  end

  describe "the plan-mode declaration" do
    test "native applies plan mode now; claude applies it from the next turn" do
      assert {:ok, %{applies: :now, settable: :any_time, via: :native_session}} =
               Provider.plan_mode(:native)

      assert {:ok, %{applies: :next_turn, settable: :at_start, via: :provider_options}} =
               Provider.plan_mode(:claude)
    end

    test "every other transport refuses plan mode by declaration" do
      for provider <- [:gemini, :opencode, :amp, :kimi, :pi] do
        assert {:error, {:unsupported_configuration, refusal}} = Provider.plan_mode(provider),
               "#{provider} accepted plan mode"

        assert refusal.field == :plan
        assert refusal.reason == :transport_cannot_plan
        assert refusal.message =~ "declares no way to be told to plan"
      end
    end

    test "an unknown provider or transport is refused by name" do
      assert {:error, {:unsupported_configuration, %{reason: :unknown_provider}}} =
               Provider.plan_mode(:nobody)

      assert {:error, {:unsupported_configuration, %{reason: :unknown_session_transport}}} =
               Provider.plan_mode(:claude, :not_a_transport)
    end

    test "plan is not an interactive.configure field, and configure still refuses it" do
      assert {:error, {:invalid_configuration, refusal}} =
               Provider.session_configuration(:native, %{plan: true}, :native)

      assert refusal.reason == :unknown_field
      assert refusal.field == :plan
      assert refusal.fields == [:approval_mode, :model, :reasoning_effort, :sandbox_mode]
    end
  end

  test "with no ouro binary there is no hook to run" do
    argv = argv_for(interactive_request(approval_mode: :prompt))
    refute Enum.any?(argv, &String.contains?(&1, "post-tool-use"))
    refute "--settings" in argv
  end

  test "a binary that is not an executable regular file is not a binary" do
    path = Path.join(System.tmp_dir!(), "ouroboros-claude-adapter-not-executable")
    File.write!(path, "")
    File.chmod!(path, 0o600)
    on_exit(fn -> File.rm(path) end)

    Application.put_env(:ouroboros, :ouro_binary, path)
    assert %{approvals: false} = Provider.session_capabilities(:claude, :stream_json_resume)

    Application.put_env(:ouroboros, :ouro_binary, "relative/ouro")
    assert %{approvals: false} = Provider.session_capabilities(:claude, :stream_json_resume)
  end

  defp bridge_available(_context) do
    binary = Path.join(System.tmp_dir!(), "ouroboros-claude-adapter-test-ouro")
    File.write!(binary, "#!/bin/sh\nexit 0\n")
    File.chmod!(binary, 0o700)

    token_file = Path.join(System.tmp_dir!(), "ouroboros-claude-adapter-test.token")
    File.write!(token_file, String.duplicate("t", 40))
    File.chmod!(token_file, 0o600)

    Application.put_env(:ouroboros, :ouro_binary, binary)

    Application.put_env(:ouroboros, :gateway,
      token_file: token_file,
      port: 4599,
      bind: "127.0.0.1",
      data_dir: System.tmp_dir!()
    )

    on_exit(fn ->
      File.rm(binary)
      File.rm(token_file)
    end)

    {:ok, binary: binary, token_file: token_file}
  end

  defp interactive_request(opts) do
    request(
      Keyword.put_new(opts, :metadata, %{
        ouroboros_session_id: "session-1",
        ouroboros_node: "ouroboros@somewhere"
      })
    )
  end

  defp request(opts) do
    RunRequest.new!([prompt: "do the thing", cwd: File.cwd!(), model: "sonnet", env: %{}] ++ opts)
  end

  defp argv_for(request) do
    assert {:ok, stream} = ClaudeAdapter.run(request, context())
    assert [] = Enum.to_list(stream)
    assert_receive {:claude_process_spec, %{argv: argv}}

    argv
  end

  # The pinned adapter, run through the same seam, so "unchanged" is an equality rather
  # than a list of flags somebody remembered to check.
  defp pinned_argv(request) do
    assert {:ok, stream} = Jido.Harness.Adapters.Claude.run(request, context())
    assert [] = Enum.to_list(stream)
    assert_receive {:claude_process_spec, %{argv: argv}}

    argv
  end

  defp context do
    %{
      run_id: "run-claude-adapter",
      provider: :claude,
      config: %{},
      telemetry_context: %{},
      process_manager: SpecCapture,
      run_owner: self()
    }
  end

  defp flag_value(argv, flag) do
    case Enum.find_index(argv, &(&1 == flag)) do
      nil -> nil
      index -> Enum.at(argv, index + 1)
    end
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)
end
