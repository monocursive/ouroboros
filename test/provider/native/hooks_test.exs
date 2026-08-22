defmodule Ouroboros.Provider.Native.HooksTest do
  @moduledoc """
  The hook matrix: allow, deny, ask, `updatedInput`, `additionalContext`, timeout, and
  the untrusted repository.

  Every hook here is a real `/bin/sh` script run through the real runner, because the
  contract under test is a process contract — stdin, stdout, stderr, exit codes — and a
  stub of it would test nothing.

  Not `async`: the user scope is redirected through node configuration.
  """

  use ExUnit.Case, async: false

  alias Jido.Harness.ApprovalResponse
  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Provider.Native.Loop
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Test.NativeModelScript

  @moduletag :capture_log

  setup do
    root = Path.join(System.tmp_dir!(), "native-hooks-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.mkdir_p!(Path.join(root, "session"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    previous_user = Application.get_env(:ouroboros, :native_user_hooks_path)
    previous_trusted = Application.get_env(:ouroboros, :trusted_workspaces)

    # An absent user file by default: a test must never read, still less run, the
    # machine's own `~/.config/ouroboros/hooks.toml`.
    Application.put_env(
      :ouroboros,
      :native_user_hooks_path,
      Path.join(root, "no-user-hooks.toml")
    )

    on_exit(fn ->
      restore(:native_user_hooks_path, previous_user)
      restore(:trusted_workspaces, previous_trusted)
      File.rm_rf(root)
    end)

    {:ok, scope} = Paths.scope(workspace, [], :workspace_write)

    %{
      root: root,
      workspace: scope.root,
      scope: scope,
      session_dir: Path.join(root, "session")
    }
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp trust(workspace), do: Application.put_env(:ouroboros, :trusted_workspaces, [workspace])

  defp project_toml(workspace, body),
    do: File.write!(Path.join(workspace, "ouroboros.toml"), body)

  defp user_toml(root, body) do
    path = Path.join(root, "user-hooks.toml")
    File.write!(path, body)
    Application.put_env(:ouroboros, :native_user_hooks_path, path)
    path
  end

  defp script(root, name, body) do
    path = Path.join(root, name)
    File.write!(path, "#!/bin/sh\n" <> body)
    File.chmod!(path, 0o755)
    path
  end

  # ---------------------------------------------------------------- loop harness

  defp start_loop(context, script, overrides \\ []) do
    {model_spec, agent} = NativeModelScript.start(script)
    test = self()

    loop =
      struct!(
        %Loop{
          emit: fn event -> send(test, {:event, event}) end,
          model_module: NativeModelScript,
          model_spec: model_spec,
          system: "system",
          scope: context.scope,
          session_dir: context.session_dir,
          session_id: "sess-1",
          provider_session_id: "native-x-y",
          turn_id: "turn-1",
          approval_mode: :auto_approve,
          approval_timeout_ms: 2_000
        },
        overrides
      )

    {loop, agent}
  end

  defp run(loop) do
    parent = self()
    spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "do the thing")}) end)
  end

  defp collect(acc \\ []) do
    receive do
      {:event, %{type: type} = event}
      when type in [:turn_completed, :turn_failed, :turn_interrupted] ->
        Enum.reverse([event | acc])

      {:event, event} ->
        collect([event | acc])
    after
      20_000 -> flunk("no terminal turn event within 20s")
    end
  end

  defp tool_results(events),
    do: events |> Enum.filter(&(&1.type == :tool_result)) |> Enum.map(& &1.payload)

  @bash_script [
    [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo ran"}}}],
    [{:text, "done"}, {:finish, :stop}]
  ]

  # ================================================================ loading

  describe "loading" do
    test "reads project hooks only when the workspace is trusted", %{workspace: workspace} do
      project_toml(workspace, """
      [[hooks]]
      event = "PreToolUse"
      matcher = "Bash"
      command = "true"
      """)

      untrusted = Hooks.load(workspace)
      refute untrusted.trusted?
      assert untrusted.hooks == []
      assert untrusted.declined == 1

      trust(workspace)
      trusted = Hooks.load(workspace)
      assert trusted.trusted?
      assert [%{event: :pre_tool_use, scope: :workspace}] = trusted.hooks
      assert trusted.declined == 0
    end

    test "a `.ouroboros/trusted` marker in the workspace also trusts it", %{
      workspace: workspace
    } do
      project_toml(workspace, "[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n")
      refute Hooks.load(workspace).trusted?

      File.mkdir_p!(Path.join(workspace, ".ouroboros"))
      File.write!(Hooks.marker_path(workspace), "")

      assert Hooks.load(workspace).trusted?
    end

    test "the marker lives under `.ouroboros`, which the permission engine protects" do
      # The agent must not be able to trust its own repository. `.ouroboros` is a
      # protected segment, so every tool call that would create the marker is denied by
      # a node-scope rule before any human is asked.
      assert Hooks.marker_path("/w") == "/w/.ouroboros/trusted"

      assert Enum.any?(
               Ouroboros.Control.Permissions.Rules.protected_paths(),
               &String.contains?(&1, ".ouroboros")
             )
    end

    test "user-scope hooks are honoured without trust and come first", %{
      root: root,
      workspace: workspace
    } do
      user_toml(root, "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"user\"\n")
      project_toml(workspace, "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"project\"\n")
      trust(workspace)

      config = Hooks.load(workspace)
      assert Enum.map(config.hooks, & &1.command) == ["user", "project"]
      assert Enum.map(config.hooks, & &1.scope) == [:user, :workspace]
    end

    test "an unparseable file contributes an error and no hooks", %{workspace: workspace} do
      trust(workspace)
      project_toml(workspace, "this is not = = toml")

      config = Hooks.load(workspace)
      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "not valid TOML"
    end

    test "a malformed entry is named and the others still load", %{workspace: workspace} do
      trust(workspace)

      project_toml(workspace, """
      [[hooks]]
      event = "NoSuchEvent"
      command = "true"

      [[hooks]]
      event = "PreToolUse"

      [[hooks]]
      event = "PreToolUse"
      matcher = "([bad regex"
      command = "true"

      [[hooks]]
      event = "PostToolUse"
      command = "fine"
      """)

      config = Hooks.load(workspace)

      assert Enum.map(config.hooks, & &1.command) == ["fine"]
      assert length(config.errors) == 3
      assert Enum.any?(config.errors, &(&1 =~ "is not a hook event"))
      assert Enum.any?(config.errors, &(&1 =~ "has no `command`"))
      assert Enum.any?(config.errors, &(&1 =~ "not a regular expression"))
    end

    test "every documented event name is accepted", %{workspace: workspace} do
      trust(workspace)

      names = ~w(SessionStart SessionEnd UserPromptSubmit PreToolUse PostToolUse
                 PostToolUseFailure Stop PreCompact Notification FileChanged)

      project_toml(
        workspace,
        Enum.map_join(names, "\n", fn name ->
          "[[hooks]]\nevent = \"#{name}\"\ncommand = \"true\"\n"
        end)
      )

      config = Hooks.load(workspace)
      assert length(config.hooks) == length(names)
      assert Enum.uniq(Enum.map(config.hooks, & &1.event)) |> length() == length(names)
    end

    test "the matcher is anchored over the tool name", %{root: root, workspace: workspace} do
      user_toml(
        root,
        "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"bash|edit\"\ncommand = \"x\"\n"
      )

      config = Hooks.load(workspace)

      assert Hooks.any?(config, :pre_tool_use, "bash")
      assert Hooks.any?(config, :pre_tool_use, "edit")
      refute Hooks.any?(config, :pre_tool_use, "read")
      # Anchored: `bash` must not match `rebash`.
      refute Hooks.any?(config, :pre_tool_use, "rebash")
    end
  end

  # ================================================================ PreToolUse

  describe "PreToolUse" do
    test "exit 2 blocks the tool and stderr is the reason the model is told", context do
      trust(context.workspace)
      blocker = script(context.root, "block.sh", "echo 'no shell commands here' >&2\nexit 2\n")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      matcher = "bash"
      command = "#{blocker}"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["is_error"]
      assert result["output"] =~ "a PreToolUse hook denied"
      assert result["output"] =~ "no shell commands here"
      refute result["output"] =~ "ran"
    end

    test "JSON `permissionDecision: deny` blocks with its reason", context do
      trust(context.workspace)

      denier =
        script(context.root, "deny.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"policy forbids it"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{denier}"
      matcher = "bash"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["is_error"]
      assert result["output"] =~ "policy forbids it"
    end

    test "`ask` turns a mode-approved call into an approval the human must answer",
         context do
      trust(context.workspace)

      asker =
        script(context.root, "ask.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"check with me"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{asker}"
      matcher = "bash"
      """)

      # `auto_approve` would have run this without asking. The hook narrows it.
      {loop, _agent} = start_loop(context, @bash_script)
      pid = run(loop)

      request =
        receive do
          {:event, %{type: :approval_requested} = event} -> event
        after
          10_000 -> flunk("the hook's ask never reached a human")
        end

      assert request.payload["reason"] =~ "check with me"

      send(pid, {:native_approval, request.request_id, ApprovalResponse.new!(:approve)})
      [result] = tool_results(collect())

      refute result["is_error"]
      assert result["output"] =~ "ran"
    end

    test "`allow` resolves an ask that the mode would have put to a human", context do
      trust(context.workspace)

      allower =
        script(context.root, "allow.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"permissionDecision":"allow"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{allower}"
      matcher = "bash"
      """)

      # `:prompt` would ask a human for a command. The hook answers instead, and nothing
      # is emitted for anybody to answer.
      {loop, _agent} = start_loop(context, @bash_script, approval_mode: :prompt)
      run(loop)
      events = collect()

      assert Enum.filter(events, &(&1.type == :approval_requested)) == []
      [result] = tool_results(events)
      refute result["is_error"]
      assert result["output"] =~ "ran"
    end

    test "`updatedInput` replaces the arguments the tool actually runs with", context do
      trust(context.workspace)

      rewriter =
        script(context.root, "rewrite.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"updatedInput":{"command":"echo rewritten"}}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{rewriter}"
      matcher = "bash"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["output"] =~ "rewritten"
      refute result["output"] =~ "ran"
    end

    test "`additionalContext` is appended to the tool result", context do
      trust(context.workspace)

      annotator =
        script(context.root, "note.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"additionalContext":"the staging database is read-only today"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{annotator}"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      refute result["is_error"]
      assert result["output"] =~ "ran"
      assert result["output"] =~ "staging database is read-only today"
    end

    test "the hook is handed the Claude-compatible JSON on stdin", context do
      trust(context.workspace)
      capture = Path.join(context.root, "stdin.json")

      recorder = script(context.root, "record.sh", "cat > #{capture}\n")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{recorder}"
      matcher = "bash"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      collect()

      payload = capture |> File.read!() |> JSON.decode!()

      assert payload["hook_event_name"] == "PreToolUse"
      assert payload["tool_name"] == "bash"
      assert payload["tool_input"]["command"] == "echo ran"
      assert payload["session_id"] == "sess-1"
      assert payload["cwd"] == context.workspace
      # Content-minimised: the prompt is not a hook's business.
      refute Map.has_key?(payload, "prompt")
    end

    test "a hook that hangs is killed at its timeout and the tool still runs", context do
      trust(context.workspace)
      sleeper = script(context.root, "sleep.sh", "sleep 30\n")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{sleeper}"
      timeout_ms = 300
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      refute result["is_error"]
      assert result["output"] =~ "ran"
    end

    test "a hook that is broken never fails the tool", context do
      trust(context.workspace)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "/nonexistent/hook-binary --flags"

      [[hooks]]
      event = "PreToolUse"
      command = "echo 'not json at all'"

      [[hooks]]
      event = "PreToolUse"
      command = "exit 7"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      refute result["is_error"]
      assert result["output"] =~ "ran"
    end

    test "a repository's hooks do nothing at all when the workspace is untrusted",
         context do
      blocker = script(context.root, "block.sh", "echo blocked >&2\nexit 2\n")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{blocker}"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      events = collect()

      [result] = tool_results(events)
      refute result["is_error"]
      assert result["output"] =~ "ran"

      # And it says so, once, rather than leaving the operator to believe they ran.
      status = Enum.find(events, &(&1.type == :provider_event))
      assert status.payload["message"] =~ "this workspace is not trusted"
    end
  end

  # ================================================================ PostToolUse

  describe "PostToolUse" do
    test "its additionalContext lands on the result and it sees the response", context do
      trust(context.workspace)
      capture = Path.join(context.root, "post.json")

      recorder =
        script(context.root, "post.sh", """
        cat > #{capture}
        echo '{"hookSpecificOutput":{"additionalContext":"post ran"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PostToolUse"
      matcher = "bash"
      command = "#{recorder}"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["output"] =~ "post ran"

      payload = capture |> File.read!() |> JSON.decode!()
      assert payload["hook_event_name"] == "PostToolUse"
      assert payload["tool_response"]["is_error"] == false
      assert payload["tool_response"]["output"] =~ "ran"
    end

    test "a failing tool fires PostToolUseFailure instead", context do
      trust(context.workspace)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PostToolUse"
      command = "cat > /dev/null; echo '{\\"additionalContext\\":\\"success hook\\"}'"

      [[hooks]]
      event = "PostToolUseFailure"
      command = "cat > /dev/null; echo '{\\"additionalContext\\":\\"failure hook\\"}'"
      """)

      failing = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "exit 3"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, failing)
      run(loop)
      [result] = tool_results(collect())

      assert result["is_error"]
      assert result["output"] =~ "failure hook"
      refute result["output"] =~ "success hook"
    end

    test "a post hook cannot block: exit 2 becomes context, not a refusal", context do
      trust(context.workspace)
      blocker = script(context.root, "post-block.sh", "cat > /dev/null; echo late >&2; exit 2\n")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PostToolUse"
      command = "#{blocker}"
      """)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      refute result["is_error"]
      assert result["output"] =~ "PostToolUse hook reported"
      assert result["output"] =~ "late"
    end
  end

  # ================================================================ lifecycle

  describe "the turn's own events" do
    test "UserPromptSubmit context reaches the model with the prompt", context do
      trust(context.workspace)

      project_toml(context.workspace, """
      [[hooks]]
      event = "UserPromptSubmit"
      command = "cat > /dev/null; echo '{\\"additionalContext\\":\\"today is a release day\\"}'"
      """)

      {loop, agent} = start_loop(context, [[{:text, "ok"}, {:finish, :stop}]])
      run(loop)
      collect()

      [request] = NativeModelScript.requests(agent)
      [%{role: :user, content: content}] = request.messages

      assert content =~ "do the thing"
      assert content =~ "today is a release day"
    end

    test "Stop context is carried into the next turn's conversation", context do
      trust(context.workspace)

      project_toml(context.workspace, """
      [[hooks]]
      event = "Stop"
      command = "cat > /dev/null; echo '{\\"additionalContext\\":\\"remember to update the changelog\\"}'"
      """)

      {loop, _agent} = start_loop(context, [[{:text, "ok"}, {:finish, :stop}]])
      parent = self()
      spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "go")}) end)
      collect()

      assert_receive {:finished, {:ok, state}}, 10_000
      assert List.last(state.messages).content =~ "remember to update the changelog"
    end

    test "FileChanged fires with the paths that changed", context do
      trust(context.workspace)
      capture = Path.join(context.root, "changed.json")

      project_toml(context.workspace, """
      [[hooks]]
      event = "FileChanged"
      command = "cat > #{capture}"
      """)

      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "lib/b.ex", "content" => "x\n"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      run(loop)
      collect()

      payload = capture |> File.read!() |> JSON.decode!()
      assert payload["hook_event_name"] == "FileChanged"
      assert payload["paths"] == [Path.join(context.workspace, "lib/b.ex")]
    end
  end

  # ================================================================ [checks]

  describe "[checks]" do
    test "a failing check's tail is injected for the next model step", context do
      trust(context.workspace)

      project_toml(context.workspace, """
      [checks]
      typecheck = "echo 'lib/b.ex:1: undefined function'; exit 1"
      """)

      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "lib/b.ex", "content" => "x\n"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      parent = self()
      spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "go")}) end)
      collect()

      assert_receive {:finished, {:ok, state}}, 30_000
      last = List.last(state.messages)

      assert last.role == :user
      assert last.content =~ "Project checks failed"
      assert last.content =~ "typecheck"
      assert last.content =~ "undefined function"
    end

    test "a passing check injects nothing", context do
      trust(context.workspace)
      project_toml(context.workspace, "[checks]\ntypecheck = \"true\"\n")

      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "lib/b.ex", "content" => "x\n"}}}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      parent = self()
      spawn_link(fn -> send(parent, {:finished, Loop.run_turn(loop, "go")}) end)
      collect()

      assert_receive {:finished, {:ok, state}}, 30_000
      refute List.last(state.messages).content =~ "Project checks failed"
    end

    test "a turn that changed no file runs no check", context do
      trust(context.workspace)
      marker = Path.join(context.root, "ran-a-check")
      project_toml(context.workspace, "[checks]\ntypecheck = \"touch #{marker}\"\n")

      {loop, _agent} = start_loop(context, [[{:text, "nothing to do"}, {:finish, :stop}]])
      run(loop)
      collect()

      refute File.exists?(marker)
    end

    test "checks are repository-supplied commands, so an untrusted workspace runs none",
         context do
      marker = Path.join(context.root, "untrusted-check-ran")
      project_toml(context.workspace, "[checks]\ntypecheck = \"touch #{marker}; exit 1\"\n")

      config = Hooks.load(context.workspace)
      assert config.checks == []
      assert Hooks.run_checks(config) == []
      refute File.exists?(marker)
    end

    test "a check that hangs is a failure that says so, not a turn that never ends",
         context do
      trust(context.workspace)
      project_toml(context.workspace, "[checks]\nslow = \"sleep 30\"\n")

      config = Hooks.load(context.workspace)
      slow = Enum.map(config.checks, &%{&1 | timeout_ms: 300})

      assert [failure] = Hooks.run_checks(%{config | checks: slow})
      assert failure =~ "did not finish within 300 ms"
    end
  end

  # ================================================================ ordering

  describe "ordering against the permission engine" do
    test "a rule that denies is final: no PreToolUse hook is even invoked", context do
      trust(context.workspace)
      marker = Path.join(context.root, "hook-was-invoked")

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "touch #{marker}; cat > /dev/null; echo '{\\"hookSpecificOutput\\":{\\"permissionDecision\\":\\"allow\\"}}'"
      """)

      # A stub engine that denies everything, so the ordering claim is tested rather than
      # asserted: a hook cannot allow what a rule denied, because it never runs.
      previous = Application.get_env(:ouroboros, :permissions_engine)
      Application.put_env(:ouroboros, :permissions_engine, __MODULE__.DenyEverything)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :permissions_engine, previous),
          else: Application.delete_env(:ouroboros, :permissions_engine)
      end)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["is_error"]
      assert result["output"] =~ "denies bash"
      refute File.exists?(marker)
      refute result["output"] =~ "ran"
    end

    test "a hook cannot launder a denied command through updatedInput", context do
      trust(context.workspace)

      rewriter =
        script(context.root, "launder.sh", """
        cat > /dev/null
        echo '{"hookSpecificOutput":{"updatedInput":{"command":"echo laundered"}}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{rewriter}"
      """)

      previous = Application.get_env(:ouroboros, :permissions_engine)
      Application.put_env(:ouroboros, :permissions_engine, __MODULE__.DenyRewrites)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :permissions_engine, previous),
          else: Application.delete_env(:ouroboros, :permissions_engine)
      end)

      {loop, _agent} = start_loop(context, @bash_script)
      run(loop)
      [result] = tool_results(collect())

      assert result["is_error"]
      assert result["output"] =~ "rewrote this call's arguments"
      refute result["output"] =~ "laundered"
    end
  end

  defmodule DenyEverything do
    @moduledoc false
    def evaluate(_request), do: {:deny, %{scope: :node, id: "test-deny", pattern: "Bash(*)"}}
    def record(_id, _answer), do: :ok
  end

  defmodule DenyRewrites do
    @moduledoc false
    # Allows what the model proposed and denies what the hook substituted, which is the
    # only shape that can tell "re-evaluated" from "evaluated once".
    def evaluate(%{command: "echo laundered"}),
      do: {:deny, %{scope: :node, id: "test-deny", pattern: "Bash(*)"}}

    def evaluate(_request), do: {:allow, %{scope: :node, id: "test-allow", pattern: "Bash(*)"}}
    def record(_id, _answer), do: :ok
  end
end
