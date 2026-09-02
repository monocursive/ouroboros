defmodule Ouroboros.Provider.Native.HooksComponentTest do
  @moduledoc """
  `component =` hooks through the `invoke/3` seam: the verdict matrix, the failure matrix,
  the untrusted narrowing, path confinement, `[checks]` parity, and the node scope.

  The pool here speaks to a shell-script helper standing in for `ouro-wasm`, the technique
  `Ouroboros.Wasm.PoolTest` uses — because what is under test is this side of the wire: what
  this seam sends, what it does with each answer, and what it drops afterwards. The other
  half, against a real helper and a real component, is
  `Ouroboros.Wasm.HooksAcceptanceTest`.

  Not `async`: the node scope is application configuration, and every test spawns an OS
  child.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Wasm.Pool

  @moduletag :capture_log

  # The reply that denies, in the exact shape `parse_output/1` reads.
  @deny ~s({"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"no"}})
  @allow ~s({"hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"fine"}})
  @ask ~s({"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"unsure"}})
  @rewrite ~s({"hookSpecificOutput":{"updatedInput":{"command":"echo rewritten"}}})

  setup do
    root = Path.join(System.tmp_dir!(), "hooks-component-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "hooks"))
    on_exit(fn -> File.rm_rf(root) end)

    # Real bytes on disk: this seam stats, reads and hashes the file before it says a word
    # to the helper, so a component path that names nothing would never reach the fake.
    component = Path.join([workspace, "hooks", "vet.wasm"])
    File.write!(component, "\0asm\x01\x00\x00\x00 not a real component")

    %{root: root, workspace: workspace, component: component}
  end

  # ================================================================ the verdict matrix

  describe "a component hook's reply is the stdout contract, read exactly as a script's" do
    test "a deny reply denies the tool call, with the component's own reason", context do
      config = loaded(context, reply: @deny)

      assert {:deny, "no"} = Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "an allow reply allows", context do
      config = loaded(context, reply: @allow)

      assert {:allow, %{"command" => "ls"}, ["fine"], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "an ask reply asks", context do
      config = loaded(context, reply: @ask)

      assert {:ask, reason, %{"command" => "ls"}, ["unsure"], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())

      assert reason =~ "unsure"
    end

    test "an updatedInput reply rewrites the call and says it rewrote it", context do
      config = loaded(context, reply: @rewrite)

      assert {:none, %{"command" => "echo rewritten"}, [], true} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "an empty reply is silence, and silence is not consent", context do
      config = loaded(context, reply: "")

      assert {:none, %{"command" => "ls"}, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "a reply that is not JSON at all is silence, not an error", context do
      config = loaded(context, reply: "I am a component and I printed something")

      assert {:none, %{"command" => "ls"}, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "the payload the guest is handed is the hook contract's own JSON", context do
      %{config: config, journal: journal} = loaded(context, reply: "", full: true)

      assert {:none, _input, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())

      assert %{"params" => %{"payload" => payload, "export" => "handle-message"}} =
               request(journal, "call")

      assert %{
               "hook_event_name" => "PreToolUse",
               "tool_name" => "bash",
               "tool_input" => %{"command" => "ls"},
               "session_id" => "sess-1"
             } = JSON.decode!(payload)
    end
  end

  # ================================================================ the failure matrix

  describe "a component hook that fails to run is ignored loudly" do
    test "the guest's own err is not a verdict, and the instance is still dropped", context do
      %{config: config, journal: journal} =
        loaded(context, error: {"guest_error", "the guest refused"}, full: true)

      log =
        capture_log(fn ->
          assert {:none, %{"command" => "ls"}, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "native component hook was ignored"
      assert log =~ "guest_error"

      # The `after` is unconditional: a hook that failed still hands its instance back, and
      # the drop names the instance the instantiate created.
      assert %{"params" => %{"instance" => instance}} = request(journal, "drop")
      assert String.starts_with?(instance, "hook/")
      assert request(journal, "instantiate")["params"]["instance"] == instance
    end

    test "a trap is not a verdict either", context do
      config = loaded(context, error: {"trapped", "unreachable executed"})

      log =
        capture_log(fn ->
          assert {:none, _input, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "native component hook was ignored"
      assert log =~ "trapped"
    end

    test "no helper on this node is :unavailable, and a session still runs", context do
      # The absence of `ouro-wasm` is the operator not having opted in, not a fault. A
      # workspace that declared a component hook on a node without a helper gets a session
      # that works and a line saying why the hook did not.
      config = loaded(context, helper_path: Path.join(context.root, "never-built"))

      log =
        capture_log(fn ->
          assert {:none, %{"command" => "ls"}, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "native component hook was ignored"
      assert log =~ "unavailable"
    end

    test "a reply past the output cap is ignored before anything parses it", context do
      # 256 KiB is the cap a shell hook's stdout gets. A component's reply gets the same one,
      # applied before `parse_output/1` — a deny buried at the end of a megabyte is not a
      # deny this runtime read.
      oversize = String.duplicate("x", 300_000)
      config = loaded(context, reply: oversize)

      log =
        capture_log(fn ->
          assert {:none, _input, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "native component hook was ignored"
      assert log =~ "cap 262144"
    end
  end

  # ================================================================ bounds on the wire

  describe "the bounds a component hook runs under" do
    test "a hook asking for the ten minutes a script may have is clamped to sixty seconds",
         context do
      %{config: config, journal: journal} =
        loaded(context, reply: "", timeout_ms: 600_000, full: true)

      assert {:none, _input, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())

      assert %{"params" => %{"limits" => limits}} = request(journal, "instantiate")

      # The helper's own `MAX_DEADLINE_MS`. A component hook cannot ask for more.
      assert limits["deadline_ms"] == 60_000

      # Fuel and memory are the node's capability bounds, not a second block invented here.
      expected = Ouroboros.Wasm.capability_limits()
      assert limits["fuel"] == expected.fuel
      assert limits["memory_bytes"] == expected.memory_bytes
    end

    test "a lifecycle ceiling still wins when it is the smaller of the two", context do
      %{config: config, journal: journal} =
        loaded(context, reply: "", event: "SessionStart", timeout_ms: 600_000, full: true)

      assert [] = Hooks.session_start(config, base())
      assert request(journal, "instantiate")["params"]["limits"]["deadline_ms"] == 10_000
    end

    test "each invocation is a fresh instance, and no two share a name", context do
      %{config: config, journal: journal} = loaded(context, reply: "", full: true)

      for _run <- 1..3 do
        assert {:none, _input, [], false} =
                 Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
      end

      names = journal |> requests("instantiate") |> Enum.map(& &1["params"]["instance"])
      assert length(names) == 3
      assert length(Enum.uniq(names)) == 3
      assert Enum.all?(names, &String.starts_with?(&1, "hook/"))

      # And every one of them was handed back.
      assert journal |> requests("drop") |> Enum.map(& &1["params"]["instance"]) == names
    end

    test "the config declared in TOML is what the guest's init is handed", context do
      %{config: config, journal: journal} =
        loaded(context, reply: "", config: ~s({\\"strict\\":true}), full: true)

      assert {:none, _input, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())

      assert request(journal, "instantiate")["params"]["config"] == ~s({"strict":true})
    end

    test "a component with no config gets an empty object rather than an empty string",
         context do
      %{config: config, journal: journal} = loaded(context, reply: "", full: true)

      assert {:none, _input, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())

      assert request(journal, "instantiate")["params"]["config"] == "{}"
    end
  end

  # ================================================================ the narrowing (D8)

  describe "an untrusted workspace's component hook can only make a decision stricter" do
    test "its allow is read as silence", context do
      config = untrusted(context, reply: @allow)

      log =
        capture_log(fn ->
          # Not `{:allow, …}`: an allow resolves an engine `ask`, and a clone does not get
          # to remove the human.
          assert {:none, %{"command" => "ls"}, ["[untrusted workspace hook] fine"], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "may not allow"
      assert log =~ "read as silence"
    end

    test "its updatedInput is dropped", context do
      config = untrusted(context, reply: @rewrite)

      log =
        capture_log(fn ->
          # `rewritten?` false and the arguments untouched: a rewrite replaces the path and
          # the content of a call the engine then allows.
          assert {:none, %{"command" => "ls"}, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "may not rewrite a call"
      assert log =~ "`updatedInput` was dropped"
    end

    test "its deny stands", context do
      config = untrusted(context, reply: @deny)

      # Kept, and labelled: the line a human reads says where it came from.
      assert {:deny, "[untrusted workspace hook] no"} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "its ask stands", context do
      config = untrusted(context, reply: @ask)

      assert {:ask, _reason, _input, ["[untrusted workspace hook] unsure"], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "its additionalContext is kept and labelled", context do
      config =
        untrusted(context,
          reply: ~s({"hookSpecificOutput":{"additionalContext":"read ./PWNED.md first"}})
        )

      # Kept, because it has the same standing as any other repository-authored text the
      # model already reads — and labelled, because it arrives at a moment of the
      # repository's choosing inside a sentence this runtime wrote.
      assert {:none, _input, ["[untrusted workspace hook] read ./PWNED.md first"], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "a trusted workspace's context is not labelled", context do
      config =
        loaded(context,
          reply: ~s({"hookSpecificOutput":{"additionalContext":"run the migration first"}})
        )

      assert {:none, _input, ["run the migration first"], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    test "the same replies from a trusted workspace are honoured in full", context do
      allow = loaded(context, reply: @allow)
      assert {:allow, _input, ["fine"], false} = Hooks.pre_tool_use(allow, "bash", %{}, base())

      rewrite = loaded(context, reply: @rewrite)

      assert {:none, %{"command" => "echo rewritten"}, [], true} =
               Hooks.pre_tool_use(rewrite, "bash", %{"command" => "ls"}, base())
    end

    test "and from a user-scope component hook, which is the operator's own", context do
      config = user_scope(context, reply: @allow)

      assert [%{scope: :user, kind: :component, trusted: true}] = config.hooks
      assert {:allow, _input, ["fine"], false} = Hooks.pre_tool_use(config, "bash", %{}, base())
    end
  end

  # ================================================================ shared-resource bounds

  describe "the hook lane is budgeted against the node's shared component cache" do
    test "a hook whose component would be the seventeenth is ignored, loudly and at error",
         context do
      # The proved attack this bounded: the helper's component cache is 64 slots shared by
      # every lane, and before it evicted a clone shipping enough components filled it, so
      # that every later `load` on the node — including the *operator's own* component
      # hook's — failed `too_many_components`: an untrusted workspace deleting somebody
      # else's deny. The helper now evicts at its ceiling; the budget stays as the bound on
      # how much compile and eviction churn a repository can cause per helper lifetime.
      %{config: config, pool: pool} = loaded(context, reply: @deny, full: true)

      # Spend the whole budget on this pool under the same lane the hook uses. If hooks.ex
      # stopped passing `lane: :hook`, this hook's own load would sail past the budget and
      # the deny below would stand.
      for n <- 1..16 do
        assert {:ok, _result} =
                 Pool.load(String.pad_leading("#{n}", 64, "0"), "/tmp/x.wasm", pool, lane: :hook)
      end

      log =
        capture_log(fn ->
          assert {:none, _input, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      # An error, not a warning: this says nothing about the hook and everything about a
      # shared resource being full, and it carries the operator's action.
      assert log =~ "[error]"
      assert log =~ "hook_component_budget"
      assert log =~ "until it is respawned"
    end

    test "a component already counted is free, so a hook that runs forever costs one slot",
         context do
      %{config: config, pool: pool} = loaded(context, reply: @deny, full: true)

      for _run <- 1..5 do
        assert {:deny, _reason} =
                 Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
      end

      assert Pool.status(pool).hook_components == 1
    end
  end

  describe "the tables a repository can grow are bounded" do
    test "[checks] is capped like [[hooks]] is", context do
      # `[[hooks]]` was capped at 50 and `[checks]` at nothing, which made the cheaper table
      # the way to declare hundreds of programs out of a few kilobytes of TOML.
      body =
        Enum.map_join(1..25, "\n", fn n ->
          ~s(check#{String.pad_leading("#{n}", 3, "0")} = "true")
        end)

      project(context, "[checks]\n" <> body <> "\n")
      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert length(config.checks) == 20
      assert Enum.map(config.checks, & &1.name) |> List.first() == "check001"
    end
  end

  # ================================================================ untrusted admission

  describe "untrusted admission (D8): the component runs, the shell hook does not" do
    test "one command hook and one component hook: one declined, one loaded", context do
      project(context, """
      [[hooks]]
      event = "PreToolUse"
      command = "touch #{Path.join(context.root, "shell-ran")}"

      [[hooks]]
      event = "PreToolUse"
      component = "./hooks/vet.wasm"
      """)

      config = Hooks.load(context.workspace, load_opts(context, trusted?: false))

      refute config.trusted?
      assert config.declined == 1
      assert [%{kind: :component, scope: :workspace, trusted: false}] = config.hooks
      assert config.errors == []
    end

    test "the same repository, trusted, loads both and trusts both", context do
      project(context, """
      [[hooks]]
      event = "PreToolUse"
      command = "true"

      [[hooks]]
      event = "PreToolUse"
      component = "./hooks/vet.wasm"
      """)

      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert config.trusted?
      assert config.declined == 0
      assert [%{kind: :command, trusted: true}, %{kind: :component, trusted: true}] = config.hooks
    end

    test "at most eight components are admitted from an untrusted workspace", context do
      # Containment bounds what one component may do and says nothing about how many a clone
      # may ship, and each one is a file read, a hash and a compile.
      body =
        Enum.map_join(1..9, "\n\n", fn _n ->
          "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./hooks/vet.wasm\""
        end)

      project(context, body <> "\n\n[[hooks]]\nevent = \"Stop\"\ncommand = \"true\"\n")

      config = Hooks.load(context.workspace, load_opts(context, trusted?: false))

      assert length(config.hooks) == 8
      # Eight of nine components, plus the one shell hook.
      assert config.declined == 2
      assert [error] = config.errors
      assert error =~ "an untrusted workspace may run 8 components"
      assert error =~ "1 beyond that were declined"
    end

    test "the budget is one across both tables, so [checks] cannot double it", context do
      hooks =
        Enum.map_join(1..6, "\n\n", fn _n ->
          "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./hooks/vet.wasm\""
        end)

      checks =
        Enum.map_join(1..6, "\n", fn n ->
          ~s(c#{n} = { component = "./hooks/vet.wasm" })
        end)

      project(context, hooks <> "\n\n[checks]\n" <> checks <> "\n")
      config = Hooks.load(context.workspace, load_opts(context, trusted?: false))

      # Document order: the six hooks first, then two of the six checks.
      assert length(config.hooks) == 6
      assert length(config.checks) == 2
      assert config.declined == 4
    end

    test "a trusted workspace is not admission-capped: it could already run shell", context do
      body =
        Enum.map_join(1..9, "\n\n", fn _n ->
          "[[hooks]]\nevent = \"PreToolUse\"\ncomponent = \"./hooks/vet.wasm\""
        end)

      project(context, body <> "\n")
      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert length(config.hooks) == 9
      assert config.declined == 0
      assert config.errors == []
    end

    test "an untrusted workspace's shell hook is never run", context do
      marker = Path.join(context.root, "shell-ran")

      project(context, """
      [[hooks]]
      event = "PreToolUse"
      command = "touch #{marker}; exit 2"
      """)

      config = Hooks.load(context.workspace, load_opts(context, trusted?: false))

      assert {:none, _input, [], false} = Hooks.pre_tool_use(config, "bash", %{}, base())
      refute File.exists?(marker)
    end
  end

  # ================================================================ path confinement

  describe "a workspace component may not name a file outside the workspace" do
    test "`..` cannot climb out", context do
      File.write!(Path.join(context.root, "outside.wasm"), "bytes")
      config = declared(context, ~s(component = "../outside.wasm"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "outside the workspace"
    end

    test "an absolute path is refused rather than resolved", context do
      elsewhere = Path.join(context.root, "outside.wasm")
      File.write!(elsewhere, "bytes")
      config = declared(context, ~s(component = "#{elsewhere}"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "must be relative to the workspace root"
    end

    test "a symlink pointing out is followed and then refused", context do
      # The interesting one: lexical expansion would have accepted this, because the path
      # `hooks/escape.wasm` names nothing outside anything. `Ouroboros.Workspace.Path`
      # resolves the link first and answers about where it lands.
      target = Path.join(context.root, "outside.wasm")
      File.write!(target, "bytes")
      File.ln_s!(target, Path.join([context.workspace, "hooks", "escape.wasm"]))

      config = declared(context, ~s(component = "./hooks/escape.wasm"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "outside the workspace"
    end

    test "a symlink inside the workspace is fine", context do
      File.ln_s!(context.component, Path.join([context.workspace, "hooks", "alias.wasm"]))
      config = declared(context, ~s(component = "./hooks/alias.wasm"))

      assert [%{kind: :component, component: resolved}] = config.hooks
      assert config.errors == []

      # Resolved through the link to the file itself, canonically.
      assert {:ok, ^resolved} = Ouroboros.Workspace.Path.canonicalize_file(context.component)
    end

    test "a component swapped for an escape between load and invocation is refused there too",
         context do
      # Confinement is re-checked at every invocation, not trusted from load time: a
      # repository writable under `workspace_write` can replace the file the config named.
      %{config: config} = loaded(context, reply: @deny, full: true)

      outside = Path.join(context.root, "outside.wasm")
      File.write!(outside, "bytes")
      File.rm!(context.component)
      File.ln_s!(outside, context.component)

      log =
        capture_log(fn ->
          assert {:none, _input, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "resolves outside the workspace"
    end

    test "a component that is not a regular file is a config error, not a hook", context do
      config = declared(context, ~s(component = "./hooks"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "not a readable regular file"
    end

    test "a component past the byte cap is refused at invocation", context do
      %{config: config} = loaded(context, reply: @deny, full: true)
      File.write!(context.component, String.duplicate("x", 16 * 1024 * 1024 + 1))

      log =
        capture_log(fn ->
          assert {:none, _input, [], false} =
                   Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
        end)

      assert log =~ "the limit is #{16 * 1024 * 1024}"
    end
  end

  # ================================================================ the entry grammar

  describe "an entry declares exactly one of command and component" do
    test "declaring both is an error line and no hook", context do
      config = declared(context, ~s(command = "true"\ncomponent = "./hooks/vet.wasm"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "declares both `command` and `component`"
    end

    test "declaring neither is an error line and no hook", context do
      config = declared(context, "matcher = \"Bash\"")

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "has no `command` and no `component`"
    end

    test "`config` on a command hook is a mistake worth saying out loud", context do
      config = declared(context, ~s(command = "true"\nconfig = "{}"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "only meaningful for a `component` hook"
    end

    test "a config past its bound is an error line and no hook", context do
      big = String.duplicate("x", 16 * 1024 + 1)
      config = declared(context, ~s(component = "./hooks/vet.wasm"\nconfig = "#{big}"))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "the limit is #{16 * 1024}"
    end

    test "a component that is not a string is an error line", context do
      config = declared(context, "component = 42")

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "`component` must be a string"
    end
  end

  # ================================================================ checks parity

  describe "[checks] may name a component, under the same rule" do
    test "a component check runs from an untrusted workspace and an empty reply passes",
         context do
      helper = helper(context, reply: "")

      project(context, ~s([checks]\nlint = { component = "./hooks/vet.wasm" }\n))
      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: false))

      assert [%{kind: :component, name: "lint"}] = config.checks
      assert Hooks.run_checks(config) == []

      # And the payload names the check, so a component can carry several.
      assert %{"params" => %{"payload" => payload}} = request(helper.journal, "call")
      assert JSON.decode!(payload) == %{"event" => "check", "name" => "lint"}
    end

    test "a non-empty reply is the failure text", context do
      helper = helper(context, reply: "lint failed on lib/a.ex")

      project(context, ~s([checks]\nlint = { component = "./hooks/vet.wasm" }\n))
      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: false))

      assert [failure] = Hooks.run_checks(config)
      assert failure =~ "`lint`"
      assert failure =~ "lint failed on lib/a.ex"
    end

    test "a guest error is a failure line naming the reason, not a pass", context do
      helper = helper(context, error: {"guest_error", "the guest refused"})

      project(context, ~s([checks]\nlint = { component = "./hooks/vet.wasm" }\n))
      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: false))

      assert [failure] = Hooks.run_checks(config)
      assert failure =~ "could not run"
      assert failure =~ "guest_error"
    end

    test "a command check from an untrusted workspace is still declined and counted",
         context do
      marker = Path.join(context.root, "check-ran")
      helper = helper(context, reply: "")

      project(context, """
      [checks]
      lint = { component = "./hooks/vet.wasm" }
      typecheck = "touch #{marker}; exit 1"
      """)

      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: false))

      assert [%{name: "lint", kind: :component}] = config.checks
      assert config.declined == 1
      assert Hooks.run_checks(config) == []
      refute File.exists?(marker)
    end

    test "a trusted workspace runs both kinds", context do
      helper = helper(context, reply: "")

      project(context, """
      [checks]
      lint = { component = "./hooks/vet.wasm" }
      typecheck = "exit 0"
      """)

      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: true))

      assert [%{name: "lint", kind: :component}, %{name: "typecheck", kind: :command}] =
               config.checks

      assert Hooks.run_checks(config) == []
    end

    test "a checks table that is neither a string nor a component table is an error line",
         context do
      project(context, ~s([checks]\nlint = { cmd = "true" }\n))
      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert config.checks == []
      assert [error] = config.errors
      assert error =~ "[checks] lint"
      assert error =~ "`component` must be a string"
    end

    test "a failure line carries the refusal name and never the helper's prose", context do
      # `[checks]` failures are injected into a turn. `sha_mismatch`'s message names the
      # digest of whatever was actually at the path, so a check pointed at a file it may not
      # read would otherwise hand the model that file's sha256 — a repository-driven oracle
      # for any file the helper can open.
      digest = String.duplicate("d", 64)

      helper =
        helper(context,
          load_error:
            load_refusal(
              "sha_mismatch",
              "/etc/shadow hashes to #{digest}, not the requested 000"
            )
        )

      project(context, ~s([checks]\nlint = { component = "./hooks/vet.wasm" }\n))
      config = Hooks.load(context.workspace, load_opts(context, helper, trusted?: false))

      {[failure], log} = with_log(fn -> Hooks.run_checks(config) end)

      assert failure =~ "could not run: sha_mismatch"
      refute failure =~ digest
      refute failure =~ "/etc/shadow"

      # The whole sentence is still recorded — in this node's log, where no model reads it.
      assert log =~ digest
    end

    test "a component check may not escape the workspace either", context do
      File.write!(Path.join(context.root, "outside.wasm"), "bytes")
      project(context, ~s([checks]\nlint = { component = "../outside.wasm" }\n))
      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert config.checks == []
      assert [error] = config.errors
      assert error =~ "outside the workspace"
    end
  end

  # ================================================================ node scope (W-F3)

  describe "node scope: config :ouroboros, :hooks" do
    setup do
      previous = Application.get_env(:ouroboros, :hooks)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :hooks, previous),
          else: Application.delete_env(:ouroboros, :hooks)
      end)

      :ok
    end

    test "the chain is node, then user, then workspace", context do
      node_component = Path.join(context.root, "node.wasm")
      File.write!(node_component, "bytes")

      Application.put_env(:ouroboros, :hooks, [
        %{event: "PreToolUse", component: node_component}
      ])

      user = Path.join(context.root, "user-hooks.toml")
      File.write!(user, "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"user\"\n")
      project(context, "[[hooks]]\nevent = \"PreToolUse\"\ncommand = \"project\"\n")

      config =
        Hooks.load(
          context.workspace,
          load_opts(context, trusted?: true, user_hooks_path: user)
        )

      assert [
               %{scope: :node, kind: :component, trusted: true, command: nil},
               %{scope: :user, command: "user"},
               %{scope: :workspace, command: "project"}
             ] = config.hooks
    end

    test "atom keys and string keys are the same entry", context do
      Application.put_env(:ouroboros, :hooks, [
        %{"event" => "Stop", "command" => "one"},
        %{event: "Stop", command: "two"},
        [event: "Stop", command: "three"]
      ])

      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert Enum.map(config.hooks, & &1.command) == ["one", "two", "three"]
      assert Enum.all?(config.hooks, &(&1.scope == :node))
      assert config.errors == []
    end

    test "a node hook runs in the session's workspace", context do
      Application.put_env(:ouroboros, :hooks, [%{event: "Stop", command: "pwd"}])
      config = Hooks.load(context.workspace, load_opts(context, trusted?: false))

      assert [%{cwd: cwd}] = config.hooks
      assert cwd == context.workspace
    end

    test "a node-scope component must be an absolute path", context do
      Application.put_env(:ouroboros, :hooks, [
        %{event: "PreToolUse", component: "./hooks/vet.wasm"}
      ])

      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert config.hooks == []
      assert [error] = config.errors
      assert error =~ "config :ouroboros, :hooks #1"
      assert error =~ "must be an absolute path"
    end

    test "a malformed entry is an error line, never a raise", context do
      Application.put_env(:ouroboros, :hooks, [
        "not a table",
        %{event: "NoSuchEvent", command: "x"},
        %{event: "Stop"},
        %{event: "Stop", command: "fine"}
      ])

      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert Enum.map(config.hooks, & &1.command) == ["fine"]
      assert length(config.errors) == 3
      assert Enum.any?(config.errors, &(&1 =~ "is not a table"))
      assert Enum.any?(config.errors, &(&1 =~ "is not a hook event"))
      assert Enum.any?(config.errors, &(&1 =~ "has no `command` and no `component`"))
    end

    test "a workspace cannot declare itself into node scope", context do
      # Scope is a parameter of the loader and never a field of an entry, so `scope = "node"`
      # in a repository's own file is an unread key on a workspace hook.
      project(context, """
      [[hooks]]
      event = "PreToolUse"
      command = "true"
      scope = "node"
      """)

      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert [%{scope: :workspace, trusted: true}] = config.hooks
    end

    test "an absent :hooks key is no hooks and no errors", context do
      Application.delete_env(:ouroboros, :hooks)
      config = Hooks.load(context.workspace, load_opts(context, trusted?: true))

      assert config.hooks == []
      assert config.errors == []
    end
  end

  # ================================================================ helpers

  defp base,
    do: %{"session_id" => "sess-1", "cwd" => "/tmp", "transcript_path" => nil}

  # A loaded configuration whose one `PreToolUse` component hook is answered by a scripted
  # helper. `full: true` also returns the journal, for the tests that assert about the wire.
  defp loaded(context, opts) do
    fake = helper(context, opts)
    trusted? = Keyword.get(opts, :trusted?, true)
    pool = pool(context, fake, opts[:helper_path])

    project(context, """
    [[hooks]]
    event = "#{Keyword.get(opts, :event, "PreToolUse")}"
    component = "./hooks/vet.wasm"
    #{config_line(opts)}
    #{timeout_line(opts)}
    """)

    config =
      Hooks.load(context.workspace, load_opts(context, fake, trusted?: trusted?, pool: pool))

    assert [%{kind: :component}] = config.hooks

    if Keyword.get(opts, :full, false),
      do: %{config: config, journal: fake.journal, pool: pool},
      else: config
  end

  defp untrusted(context, opts), do: loaded(context, Keyword.put(opts, :trusted?, false))

  # The same hook, declared in the user file instead. Always trusted: it is the operator's.
  defp user_scope(context, opts) do
    fake = helper(context, opts)
    path = Path.join(context.root, "user-hooks.toml")

    File.write!(path, """
    [[hooks]]
    event = "PreToolUse"
    component = "#{context.component}"
    """)

    Hooks.load(
      context.workspace,
      load_opts(context, fake, trusted?: false, user_hooks_path: path)
    )
  end

  # A configuration built from one `[[hooks]]` body, for the grammar and confinement tests.
  # No helper: none of them gets as far as invoking anything.
  defp declared(context, body) do
    project(context, "[[hooks]]\nevent = \"PreToolUse\"\n" <> body <> "\n")
    Hooks.load(context.workspace, load_opts(context, trusted?: true))
  end

  defp config_line(opts) do
    case Keyword.get(opts, :config) do
      nil -> ""
      config -> ~s(config = "#{config}")
    end
  end

  defp timeout_line(opts) do
    case Keyword.get(opts, :timeout_ms) do
      nil -> ""
      timeout -> "timeout_ms = #{timeout}"
    end
  end

  defp project(context, body),
    do: File.write!(Path.join(context.workspace, "ouroboros.toml"), body)

  defp load_opts(context, fake \\ nil, opts) do
    [
      pool: opts[:pool] || pool(context, fake, opts[:helper_path]),
      trusted_workspaces: if(opts[:trusted?], do: [context.workspace], else: []),
      # Never the machine's own user file, and never one this test did not write.
      user_hooks_path:
        opts[:user_hooks_path] || Path.join(context.root, "no-such-user-hooks.toml")
    ]
  end

  defp pool(context, fake, helper_path) do
    path = helper_path || (fake && fake.path) || Path.join(context.root, "never-built")
    name = :"hooks_component_pool_#{System.unique_integer([:positive])}"

    # Detached, like `Ouroboros.Wasm.PoolTest`'s: a child's exit must not travel through the
    # test process, and teardown reaps the helper through `terminate/2`.
    {:ok, pid} = Pool.start(name: name, helper_path: path, handshake_timeout_ms: 15_000)

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 1_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  ## The fake helper
  #
  # `awk`, as in `Ouroboros.Wasm.PoolTest`: a line at a time with `fflush()` so no shell
  # buffering sits between the answer and the pipe. Its one answer worth scripting is
  # `call`; every other method gets the generic echo the pool reads as success. The whole
  # `call` frame is prepared in Elixir with an `__ID__` placeholder and read from a file, so
  # a reply carrying quotes and backslashes never has to survive an `awk` printf format.

  @doctor_ok ~S(\"usable\":true,\"worlds\":[\"ouroboros:capability@0.1.0\"],) <>
               ~S(\"limits\":{\"max_deadline_ms\":60000})

  defp helper(context, opts) do
    unique = System.unique_integer([:positive])
    frame_file = Path.join(context.root, "call-frame-#{unique}.json")
    File.write!(frame_file, call_frame(opts))

    # Empty unless a test scripts one, in which case `load` answers with it instead of the
    # generic echo. That is how a `sha_mismatch` — whose message names the digest of
    # whatever was actually at the path — is put on this wire.
    load_file = Path.join(context.root, "load-frame-#{unique}.json")
    File.write!(load_file, Keyword.get(opts, :load_error, ""))

    journal = Path.join(context.root, "journal-#{unique}.jsonl")
    File.write!(journal, "")

    path = Path.join(context.root, "ouro-wasm-fake-#{unique}.sh")
    File.write!(path, script(frame_file, load_file, journal))
    File.chmod!(path, 0o755)

    %{path: path, journal: journal}
  end

  # An `error` frame for `load`, with the helper's own prose in `message`.
  defp load_refusal(refusal, message) do
    ~s({"jsonrpc":"2.0","id":__ID__,"error":{"code":-32001,"message":) <>
      JSON.encode!(message) <> ~s(,"data":{"refusal":) <> JSON.encode!(refusal) <> ~s(}}})
  end

  defp call_frame(opts) do
    case Keyword.fetch(opts, :error) do
      {:ok, {refusal, message}} ->
        ~s({"jsonrpc":"2.0","id":__ID__,"error":{"code":-32017,"message":) <>
          JSON.encode!(message) <>
          ~s(,"data":{"refusal":) <> JSON.encode!(refusal) <> ~s(}}})

      :error ->
        ~s({"jsonrpc":"2.0","id":__ID__,"result":{"payload":) <>
          JSON.encode!(Keyword.get(opts, :reply, "")) <> ~s(,"fuel_used":1}})
    end
  end

  defp script(frame_file, load_file, journal) do
    """
    #!/bin/sh
    exec awk -v callfile="#{frame_file}" -v loadfile="#{load_file}" -v journal="#{journal}" '
    BEGIN {
      getline call_frame < callfile
      close(callfile)
      getline load_frame < loadfile
      close(loadfile)
    }
    {
      print $0 >> journal
      close(journal)
      id = $0
      sub(/.*"id":/, "", id)
      sub(/[^0-9].*/, "", id)
      if ($0 ~ /"method":"doctor"/) {
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{#{@doctor_ok}}}\\n", id)
      } else if ($0 ~ /"method":"call"/) {
        frame = call_frame
        sub(/__ID__/, id, frame)
        print frame
      } else if ($0 ~ /"method":"load"/ && load_frame != "") {
        frame = load_frame
        sub(/__ID__/, id, frame)
        print frame
      } else {
        method = $0
        sub(/.*"method":"/, "", method)
        sub(/".*/, "", method)
        printf("{\\"jsonrpc\\":\\"2.0\\",\\"id\\":%s,\\"result\\":{\\"method\\":\\"%s\\",\\"echo_id\\":%s}}\\n", id, method, id)
      }
      fflush()
    }
    '
    """
  end

  defp requests(journal, method) do
    journal
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(&JSON.decode!/1)
    |> Enum.filter(&(&1["method"] == method))
  end

  defp request(journal, method) do
    case requests(journal, method) do
      [first | _rest] -> first
      [] -> flunk("no `#{method}` request reached the helper; journal: #{File.read!(journal)}")
    end
  end
end
