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

  # The `status` kind only. A turn emits other provider events — a checkpoint, for one —
  # and counting those as hook reports would make "said once" untestable.
  defp status_events(events),
    do:
      Enum.filter(
        events,
        &(&1.type == :provider_event and &1.payload["kind"] == "status")
      )

  # ------------------------------------------------- the hook-component budget (W5/W-F3)

  # A pool that reports a fixed `hook_components` and counts how many times it was asked.
  # A real one would need a helper on disk and a component to spend the budget on, and what
  # is under test here is the sentence and when it is said — not the pool's bookkeeping,
  # which `Ouroboros.Provider.Native.HooksComponentTest` holds against the real thing.
  defmodule BudgetPool do
    @moduledoc false
    use GenServer

    def start_link(used), do: GenServer.start_link(__MODULE__, used)

    @impl true
    def init(used), do: {:ok, %{used: used, calls: 0}}

    @impl true
    def handle_call(:status, _from, state) do
      status = %{
        phase: :ready,
        helper_path: "/fake/ouro-wasm",
        os_pid: 1,
        doctor: nil,
        instances: 0,
        owned: 0,
        pending_drops: 0,
        hook_components: state.used,
        broken_reason: nil
      }

      {:reply, status, %{state | calls: state.calls + 1}}
    end

    def handle_call(:calls, _from, state), do: {:reply, state.calls, state}
  end

  defp fake_pool(used) do
    {:ok, pid} = BudgetPool.start_link(used)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  # One component hook, declared far enough from this turn's events that nothing tries to
  # run it: what is being tested is the once-per-turn report, not an invocation.
  #
  # Untrusted by default, because that is what the budget counts. A trusted component hook —
  # the operator's own, or a workspace they named — is never budgeted, so a session holding
  # only those has nothing to be told about and never asks the pool.
  defp component_hooks(pool, trusted? \\ false) do
    %Hooks{
      hooks: [
        %{
          event: :pre_compact,
          matcher: nil,
          kind: :component,
          command: nil,
          component: "./hooks/vet.wasm",
          confine_to: nil,
          config: "",
          timeout_ms: 5_000,
          scope: :workspace,
          trusted: trusted?,
          cwd: nil,
          pool: pool
        }
      ],
      checks: [],
      trusted?: trusted?,
      declined: 0,
      errors: [],
      pool: pool
    }
  end

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

    test "an in-workspace marker cannot authorize repository commands", %{
      workspace: workspace
    } do
      project_toml(workspace, "[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n")
      File.mkdir_p!(Path.join(workspace, ".ouroboros"))
      File.write!(Path.join([workspace, ".ouroboros", "trusted"]), "")

      config = Hooks.load(workspace)
      refute config.trusted?
      assert config.hooks == []
      assert config.declined == 1

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

  # ================================================================ the matcher's bounds

  describe "the matcher is a repository-authored regular expression, and bounded like one" do
    test "a pattern carrying its own parenthesis cannot break out of the anchoring",
         %{root: root, workspace: workspace} do
      # The proved escape. `\A(?:` … `)\z` is string concatenation, so `a)|(x` anchored is
      # `\A(?:a)|(x)\z` — "starts with a" OR "ends with x" — which compiles, is not anchored,
      # and matches a tool name it was never meant to. The bare compile refuses it first:
      # unbalanced parentheses are not a regular expression on their own.
      user_toml(root, """
      [[hooks]]
      event = "PreToolUse"
      matcher = "a)|(x"
      command = "x"
      """)

      config = Hooks.load(workspace)

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "not a regular expression"

      # The line that proves it is the *anchoring* being defended and not just a parse: this
      # is the tool name the escaped pattern matched.
      refute Hooks.any?(config, :pre_tool_use, "anything x")
    end

    test "a pattern past the length bound is refused", %{root: root, workspace: workspace} do
      pattern = String.duplicate("a", 201)

      user_toml(root, """
      [[hooks]]
      event = "PreToolUse"
      matcher = "#{pattern}"
      command = "x"
      """)

      config = Hooks.load(workspace)

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "201 bytes; the limit is 200"
    end

    test "a catastrophically backtracking pattern is bounded, not waited on",
         %{root: root, workspace: workspace} do
      # `(a+)+$` against 41 characters that cannot match took 90 ms of this node — per tool
      # call, per hook that declared it, with the *model* choosing the subject. Under the
      # backtracking budget the same question is answered in under a millisecond, and the
      # answer is "no match", which is the direction that cannot loosen anything: a hook that
      # does not run cannot deny, and only a hook that ran can.
      user_toml(root, """
      [[hooks]]
      event = "PreToolUse"
      matcher = "(a+)+$"
      command = "x"
      """)

      config = Hooks.load(workspace)
      assert [%{matcher: %Regex{}}] = config.hooks

      subject = String.duplicate("a", 41) <> "!"

      {elapsed_us, matched?} =
        :timer.tc(fn -> Hooks.any?(config, :pre_tool_use, subject) end)

      refute matched?
      assert elapsed_us < 10_000, "the matcher took #{elapsed_us} us; the budget should bound it"

      # And an honest matcher still matches: the budget is three orders of magnitude above
      # what a tool name costs.
      assert Hooks.any?(config, :pre_tool_use, String.duplicate("a", 8))
    end
  end

  # ================================================================ the loader's own bounds

  describe "what a repository can grow, the loader takes and drops" do
    test "at most fifty hooks are taken", %{workspace: workspace} do
      # A cap the mutation matrix found unproved: deleting the take left sixty hooks loaded
      # and every test still green.
      trust(workspace)

      project_toml(
        workspace,
        Enum.map_join(1..60, "\n", fn n ->
          "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"echo #{n}\"\n"
        end)
      )

      config = Hooks.load(workspace)

      assert length(config.hooks) == 50
      # The first fifty in file order, so what is dropped is the tail and not a sample.
      assert List.first(config.hooks).command == "echo 1"
      assert List.last(config.hooks).command == "echo 50"
    end

    test "a declared timeout is clamped to the ceiling", %{workspace: workspace} do
      trust(workspace)

      project_toml(workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "true"
      timeout_ms = 999999999

      [[hooks]]
      event = "PreToolUse"
      command = "true"
      timeout_ms = 1500

      [[hooks]]
      event = "PreToolUse"
      command = "true"
      timeout_ms = -5
      """)

      config = Hooks.load(workspace)

      # Clamped, honoured, and defaulted: the three answers `timeout/1` has, so a mutation
      # that drops the `min` is caught by the first and one that drops the guard by the third.
      assert Enum.map(config.hooks, & &1.timeout_ms) == [600_000, 1_500, 60_000]
    end

    test "a config file past the byte cap is an error line and no hooks", %{
      workspace: workspace
    } do
      trust(workspace)

      # 256 KiB is the cap; a file one byte over it is read no further than its stat. Padded
      # with a comment so the bytes are TOML that *would* have parsed — what refuses this is
      # the size and nothing else.
      body =
        ~s([[hooks]]\nevent = "PreToolUse"\ncommand = "true"\n# ) <>
          String.duplicate("x", 256 * 1024)

      project_toml(workspace, body)

      config = Hooks.load(workspace)

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "the limit is #{256 * 1024}"
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

    test "a no-op desktop hook sees redaction without replacing the real typed text", context do
      trust(context.workspace)
      captured = Path.join(context.root, "desktop-hook-input.json")

      observer =
        script(context.root, "observe-desktop.sh", """
        cat > #{captured}
        echo '{}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PreToolUse"
      command = "#{observer}"
      matcher = "desktop_act"
      """)

      helper = Path.join(context.root, "ouro-computer-use")
      File.write!(helper, "#!/bin/sh\nexit 1\n")
      previous = Application.get_env(:ouroboros, :computer_use)
      Application.put_env(:ouroboros, :computer_use, enabled: true, helper_path: helper)

      on_exit(fn -> restore(:computer_use, previous) end)

      snapshot = %{
        state: %{
          "app" => %{"id" => "com.apple.calculator"},
          "window" => %{"id" => "w_1"},
          "nodes" => []
        },
        at: System.system_time(:millisecond)
      }

      pool = Ouroboros.Provider.Native.Desktop.Pool
      Ouroboros.Provider.Native.Desktop.Pool.remember_state(pool, context.session_dir, snapshot)

      assert Ouroboros.Provider.Native.Desktop.Pool.last_state(pool, context.session_dir) ==
               snapshot

      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "desktop_act",
             input: %{"action" => "type", "text" => "sk-live-secret"}
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} = start_loop(context, script)
      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = first}, 5_000
      send(pid, {:native_approval, first.request_id, ApprovalResponse.new!(:approve)})

      assert_receive {:event, %{type: :approval_requested} = sensitive}, 5_000
      assert sensitive.request_id != first.request_id
      assert sensitive.payload["reason"] =~ "password field or looks like a secret"
      refute Map.has_key?(sensitive.payload, "suggested_rule")

      hook_payload = JSON.decode!(File.read!(captured))
      assert hook_payload["tool_input"]["text_bytes"] == byte_size("sk-live-secret")
      refute Map.has_key?(hook_payload["tool_input"], "text")
      refute File.read!(captured) =~ "sk-live-secret"

      send(pid, {:native_approval, sensitive.request_id, ApprovalResponse.new!(:deny)})
      [_result] = tool_results(collect())
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

  # ================================================== the hook-component budget (W5/W-F3)

  describe "a spent hook-component budget is said once per turn" do
    test "a session with a component hook on a node whose budget is spent is told", context do
      budget = Ouroboros.Wasm.Pool.hook_component_budget()
      pool = fake_pool(budget)

      {loop, _agent} = start_loop(context, @bash_script, hooks: component_hooks(pool))

      run(loop)
      [status] = status_events(collect())

      assert status.payload["message"] =~
               "this workspace's component hooks can no longer load on this node"

      # The budget counts untrusted hook components, and the sentence an operator reads says
      # so — a line that named "hook components" would point at their own, which are never
      # budgeted and were never at risk.
      assert status.payload["message"] =~ "untrusted hook components (#{budget}) is spent"
      assert status.payload["message"] =~ "restart the wasm pool"
    end

    test "a session whose only component hook is trusted never asks the pool", context do
      # The budget is the untrusted lane's. An operator's own component hook — or one from a
      # workspace they trusted — is never counted against it, so there is nothing here to
      # warn about and no reason to read the pool's status at all.
      pool = fake_pool(Ouroboros.Wasm.Pool.hook_component_budget())

      {loop, _agent} = start_loop(context, @bash_script, hooks: component_hooks(pool, true))

      run(loop)

      assert status_events(collect()) == []
      assert GenServer.call(pool, :calls) == 0
    end

    test "room left in the budget says nothing at all", context do
      pool = fake_pool(Ouroboros.Wasm.Pool.hook_component_budget() - 1)

      {loop, _agent} = start_loop(context, @bash_script, hooks: component_hooks(pool))

      run(loop)

      assert status_events(collect()) == []
    end

    test "a session with no component hook never asks the pool anything", context do
      pool = fake_pool(Ouroboros.Wasm.Pool.hook_component_budget())

      {loop, _agent} =
        start_loop(context, @bash_script,
          hooks: %Hooks{
            hooks: [],
            checks: [],
            trusted?: true,
            declined: 0,
            errors: [],
            pool: pool
          }
        )

      run(loop)

      assert status_events(collect()) == []

      # The fast path is the claim, so it is the assertion: the pool was never asked. A
      # workspace with no component hook is the overwhelming majority, and a status line
      # that cost every one of them a `GenServer.call` would be the wrong trade.
      assert GenServer.call(pool, :calls) == 0
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

    test "desktop_act typed text is redacted on PostToolUseFailure", context do
      trust(context.workspace)
      capture = Path.join(context.root, "post-desktop.json")

      recorder =
        script(context.root, "post-desktop.sh", """
        cat > #{capture}
        echo '{"hookSpecificOutput":{"additionalContext":"post desktop"}}'
        """)

      project_toml(context.workspace, """
      [[hooks]]
      event = "PostToolUse"
      matcher = "desktop_act"
      command = "#{recorder}"

      [[hooks]]
      event = "PostToolUseFailure"
      matcher = "desktop_act"
      command = "#{recorder}"
      """)

      helper = Path.join(context.root, "ouro-computer-use")
      File.write!(helper, "#!/bin/sh\nexit 1\n")
      previous = Application.get_env(:ouroboros, :computer_use)
      Application.put_env(:ouroboros, :computer_use, enabled: true, helper_path: helper)
      on_exit(fn -> restore(:computer_use, previous) end)

      snapshot = %{
        state: %{
          "app" => %{"id" => "com.apple.calculator"},
          "window" => %{"id" => "w_1"},
          "nodes" => []
        },
        at: System.system_time(:millisecond)
      }

      pool = Ouroboros.Provider.Native.Desktop.Pool
      Ouroboros.Provider.Native.Desktop.Pool.remember_state(pool, context.session_dir, snapshot)

      assert Ouroboros.Provider.Native.Desktop.Pool.last_state(pool, context.session_dir) ==
               snapshot

      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "desktop_act",
             input: %{"action" => "type", "text" => "hello from the hook"}
           }}
        ],
        [{:text, "done"}, {:finish, :stop}]
      ]

      {loop, _agent} =
        start_loop(context, script,
          approval_mode: :ask,
          approval_timeout_ms: :infinity,
          desktop_runner: fn "act", _params, _timeout -> {:error, :broken} end
        )

      pid = run(loop)

      assert_receive {:event, %{type: :approval_requested} = ask}, 5_000
      send(pid, {:native_approval, ask.request_id, ApprovalResponse.new!(:approve)})

      [result] = tool_results(collect())
      assert result["output"] =~ "post desktop"

      payload = capture |> File.read!() |> JSON.decode!()
      assert payload["tool_input"]["text_bytes"] == byte_size("hello from the hook")
      refute Map.has_key?(payload["tool_input"], "text")
      refute File.read!(capture) =~ "hello from the hook"
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

    test "a command check that reached the struct untrusted is still not run", context do
      # The belt-and-braces guard at `run_check/3`, which the mutation matrix found unproved:
      # the test above proves `load/2` never *builds* an untrusted command check, so deleting
      # the guard changed nothing any test could see. This constructs the struct directly —
      # the shape a future loader bug, or a caller assembling its own configuration, would
      # produce — and the guard is the only thing between it and `sh -c` on this machine.
      #
      # Both readers, because the guard asks both: the configuration's trust and the entry's
      # own `trusted`, the field that also chooses the pool lane and the label. Either one
      # saying "repository-authored" is enough to refuse, and an entry that carries no answer
      # at all is read as untrusted.
      marker = Path.join(context.root, "belt-and-braces-check-ran")

      check = %{
        name: "typecheck",
        kind: :command,
        command: "touch #{marker}; exit 1",
        component: nil,
        confine_to: nil,
        config: "{}",
        timeout_ms: 5_000,
        trusted: false
      }

      untrusted = %Hooks{
        checks: [check],
        trusted?: false,
        workspace: context.workspace
      }

      assert Hooks.run_checks(untrusted) == []
      refute File.exists?(marker)

      # A trusted configuration is not enough on its own: the entry still says it came from a
      # repository, and that is the answer that wins.
      assert Hooks.run_checks(%{untrusted | trusted?: true}) == []
      refute File.exists?(marker)

      # Nor is an entry with no answer at all, which is read as untrusted.
      silent = %{untrusted | trusted?: true, checks: [Map.delete(check, :trusted)]}
      assert Hooks.run_checks(silent) == []
      refute File.exists?(marker)

      # Both agreeing runs it — so what the assertions above prove is the guard and not a
      # check that could never have run at all.
      both = %{untrusted | trusted?: true, checks: [%{check | trusted: true}]}
      assert [failure] = Hooks.run_checks(both)
      assert failure =~ "typecheck"
      assert File.exists?(marker)
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
