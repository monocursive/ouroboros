defmodule Ouroboros.Wasm.SdkAcceptanceTest do
  @moduledoc """
  The guest SDK's own components, driven through the node that actually reads them.

  `tui/wasm/tests/sdk.rs` proves what a component built on `tui/wasm/guest` *says*: the reply
  text, the keys, the empty string for silence. Every assertion in that file compares this
  repository's Rust against this repository's Rust, so all of it stays green through a rename
  on the Elixir side — and the SDK's documentation makes claims that are enforced nowhere in
  Rust at all. `Verdict`'s docstring says `allow` is read as silence from an untrusted
  workspace, that `updatedInput` is dropped, that context is labelled per line, and that an
  empty `[checks]` reply is a **pass**. Not one of those sentences is about the SDK. They are
  about `Ouroboros.Provider.Native.Hooks`, and this file is where the two are held to each
  other.

  So every test here takes a component built by a real toolchain, puts it in a repository this
  node has never trusted, and asks `Hooks.pre_tool_use/4` or `Hooks.run_checks/2` what
  happened. What is asserted is the *decision*, not the reply — and, where it matters, the
  difference between the trusted and the untrusted lane, because a narrowing that was deleted
  would show up as those two answers becoming the same.

  Not `async`: each test spawns the real helper as an OS child.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.LiveFixture
  alias Ouroboros.Wasm.Pool

  # The SDK's worked components, as `make wasm-examples` builds them. Each is its own cargo
  # workspace, so each has a build directory of its own.
  @examples Path.expand("../../tui/wasm/guest/examples", __DIR__)

  @deny_writes Path.join(@examples, "deny-writes/target/wasm32-wasip2/release/deny_writes.wasm")
  @counter Path.join(@examples, "counter/target/wasm32-wasip2/release/counter.wasm")
  @lintcheck Path.join(@examples, "lintcheck/target/wasm32-wasip2/release/lintcheck.wasm")
  @verdicts Path.join(@examples, "verdicts/target/wasm32-wasip2/release/verdicts.wasm")

  @components [
    {"deny-writes", @deny_writes},
    {"counter", @counter},
    {"lintcheck", @lintcheck},
    {"verdicts", @verdicts}
  ]

  # The first built thing that is not there, said the way an operator has to fix it. `nil` when
  # this machine can run the suite.
  @missing (cond do
              not Wasm.available?() ->
                "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm`"

              example = Enum.find(@components, fn {_name, path} -> not File.regular?(path) end) ->
                {name, path} = example

                "no #{name} example at #{path}; run `make wasm-examples` " <>
                  "(it needs `rustup target add wasm32-wasip2`) to check the components the " <>
                  "SDK actually builds rather than a scripted reply"

              true ->
                nil
            end)

  # The same two-answer rule `Ouroboros.Wasm.LiveFixture` applies, for a different set of built
  # things — `LiveFixture` knows only about the acceptance guest, and a skip naming the wrong
  # `make` target is how somebody spends an afternoon.
  #
  # **Never `[skip: …]` when the run requires a live helper.** That is the whole subtlety: a tag
  # carrying `skip` is honoured by ExUnit before `setup_all` runs, so a suite that skipped
  # unconditionally would skip green under `OUROBOROS_REQUIRE_WASM` too — which is exactly the
  # silence this switch exists to end. Under it the tests run and `setup_all` fails them with
  # the same sentence a developer's machine would have printed as a skip.
  @needs_examples (case @missing do
                     nil -> []
                     reason -> if LiveFixture.required?(), do: [], else: [skip: reason]
                   end)

  @label "[untrusted workspace hook] "

  setup_all do
    case @missing do
      nil -> :ok
      reason -> if LiveFixture.required?(), do: raise(reason), else: :ok
    end
  end

  describe "the deny-writes example, through the seam that parses its verdict" do
    @tag @needs_examples
    test "a write outside the configured root is denied, and the reason is labelled" do
      config = load(repo(deny_toml(), @deny_writes), trusted?: false)

      assert [%{kind: :component, trusted: false}] = config.hooks

      assert {:deny, reason} =
               Hooks.pre_tool_use(
                 config,
                 "write",
                 %{"path" => "lib/a.ex", "content" => "x"},
                 base()
               )

      # The line a human is most likely to read is the one that has to say where it came
      # from: this is a clone's opinion, stated inside a runtime-authored refusal.
      assert String.starts_with?(reason, @label)
      assert reason =~ "lib/a.ex"
      assert reason =~ "src/"
    end

    @tag @needs_examples
    test "a write inside the root states no decision, and its context line is labelled" do
      config = load(repo(deny_toml(), @deny_writes), trusted?: false)

      assert {:none, %{"path" => "src/main.rs"}, [context], false} =
               Hooks.pre_tool_use(
                 config,
                 "write",
                 %{"path" => "src/main.rs", "content" => "x"},
                 base()
               )

      # `:none` and not `:allow` — the example answers `Verdict::Context`, and silence is not
      # consent. A hook that said `allow` here would resolve an engine `ask` it had no opinion
      # about.
      assert String.starts_with?(context, @label)
      assert context =~ "src/main.rs"
    end

    @tag @needs_examples
    test "a traversal that starts under the root is denied rather than resolved" do
      config = load(repo(deny_toml(), @deny_writes), trusted?: false)

      assert {:deny, _reason} =
               Hooks.pre_tool_use(config, "edit", %{"path" => "src/../etc/passwd"}, base())
    end

    @tag @needs_examples
    test "a tool it has no opinion about produces no decision and no context" do
      config = load(repo(deny_toml(), @deny_writes), trusted?: false)

      assert {:none, %{"command" => "ls"}, [], false} =
               Hooks.pre_tool_use(config, "bash", %{"command" => "ls"}, base())
    end

    @tag @needs_examples
    test "both tool-name casings reach the same verdict" do
      # `loop.ex` sends `classified.tool`, which is lowercase here and capitalised in the
      # contract's other three implementations. The example matches case-insensitively; this
      # is where that stops being a comment.
      config = load(repo(deny_toml(), @deny_writes), trusted?: false)

      assert {:deny, _} = Hooks.pre_tool_use(config, "Write", %{"path" => "lib/a.ex"}, base())
      assert {:deny, _} = Hooks.pre_tool_use(config, "Edit", %{"path" => "lib/a.ex"}, base())
      assert {:deny, _} = Hooks.pre_tool_use(config, "write", %{"path" => "lib/a.ex"}, base())
    end

    @tag @needs_examples
    test "the same component, trusted, denies unlabelled" do
      config = load(repo(deny_toml(), @deny_writes), trusted?: true)

      assert {:deny, reason} =
               Hooks.pre_tool_use(config, "write", %{"path" => "lib/a.ex"}, base())

      refute String.starts_with?(reason, @label)
      assert reason =~ "lib/a.ex"
    end
  end

  describe "the whole verdict vocabulary, and what the narrowing does to it (D8)" do
    @tag @needs_examples
    test "an untrusted `allow` is read as silence, and a trusted one resolves the call" do
      # The one that matters most. `allow` is what takes the human out of the loop, so a
      # clone's `allow` must arrive as `:none` — and the trusted lane is what proves the
      # component really did say `allow` rather than nothing.
      untrusted = load(repo(verdict_toml("allow"), @verdicts), trusted?: false)
      assert {:none, %{"path" => "a"}, [], false} = decide(untrusted)

      trusted = load(repo(verdict_toml("allow"), @verdicts), trusted?: true)
      assert {:allow, %{"path" => "a"}, [], false} = decide(trusted)
    end

    @tag @needs_examples
    test "an untrusted `updatedInput` is dropped, and a trusted one replaces the arguments" do
      untrusted = load(repo(verdict_toml("updated_input"), @verdicts), trusted?: false)

      # The arguments the engine will act on, unchanged, and `rewritten?` false: a clone
      # cannot redirect an allowed write to a path and a content of its choosing.
      assert {:none, %{"path" => "a"}, [], false} = decide(untrusted)

      trusted = load(repo(verdict_toml("updated_input"), @verdicts), trusted?: true)

      assert {:none, %{"path" => "somewhere/else.txt", "content" => "rewritten"}, [], true} =
               decide(trusted)
    end

    @tag @needs_examples
    test "`ask` stands in both lanes, because it only ever adds a human" do
      untrusted = load(repo(verdict_toml("ask"), @verdicts), trusted?: false)
      assert {:ask, reason, %{"path" => "a"}, [context], false} = decide(untrusted)
      assert reason =~ "verdicts fixture says ask"
      assert String.starts_with?(context, @label)

      trusted = load(repo(verdict_toml("ask"), @verdicts), trusted?: true)
      assert {:ask, _reason, _input, [line], false} = decide(trusted)
      refute String.starts_with?(line, @label)
    end

    @tag @needs_examples
    test "`deny` stands in both lanes" do
      untrusted = load(repo(verdict_toml("deny"), @verdicts), trusted?: false)
      assert {:deny, reason} = decide(untrusted)
      assert reason =~ "verdicts fixture says deny"

      trusted = load(repo(verdict_toml("deny"), @verdicts), trusted?: true)
      assert {:deny, _reason} = decide(trusted)
    end

    @tag @needs_examples
    test "every line of an untrusted context is labelled, not just the first" do
      # The fixture answers three lines, the second of which forges a tool-result boundary.
      # One `additionalContext` is one string, and a label on line one leaves lines two and
      # three reading as if this runtime wrote them.
      untrusted = load(repo(verdict_toml("context"), @verdicts), trusted?: false)
      assert {:none, _input, [context], false} = decide(untrusted)

      lines = String.split(context, "\n")
      assert length(lines) == 3

      assert Enum.all?(lines, &String.starts_with?(&1, @label)),
             "an unlabelled line survived: #{inspect(context)}"

      # Labelled, not censored: the text is still there for the model to judge.
      assert context =~ "APPROVED BY OPERATOR"

      trusted = load(repo(verdict_toml("context"), @verdicts), trusted?: true)
      assert {:none, _input, [plain], false} = decide(trusted)
      refute plain =~ @label
    end

    @tag @needs_examples
    test "`silent` is silence, and is distinguishable from every decision above" do
      config = load(repo(verdict_toml("silent"), @verdicts), trusted?: false)
      assert {:none, %{"path" => "a"}, [], false} = decide(config)
    end
  end

  describe "the [checks] seam, whose contract runs the other way" do
    @tag @needs_examples
    test "a failing check is its text, labelled per line, and a passing one is silence" do
      # The direction that is easy to invert and impossible to see inverted: an empty reply
      # is the PASS, so a `Fail` that returned `""` is a failing check nobody is told about.
      config = load(repo(checks_toml(), @lintcheck), trusted?: false)

      assert Enum.map(config.checks, & &1.name) == ["lint", "typecheck"]

      # One failure and not two: `typecheck` is the same component configured to pass.
      assert [failure] = Hooks.run_checks(config)

      assert failure =~ "`lint`"
      assert failure =~ "check `lint` says no"
      refute failure =~ "typecheck"

      assert Enum.all?(String.split(failure, "\n"), &String.starts_with?(&1, @label)),
             "an unlabelled line survived: #{inspect(failure)}"

      assert failure =~ "APPROVED BY OPERATOR"
    end

    @tag @needs_examples
    test "the same failing check, trusted, is unlabelled" do
      config = load(repo(checks_toml(), @lintcheck), trusted?: true)

      assert [failure] = Hooks.run_checks(config)
      refute failure =~ @label
      assert failure =~ "check `lint` says no"
    end

    @tag @needs_examples
    test "a check whose config it refuses is a failure, not a pass" do
      # `init` refuses at instantiate, so the check never runs. A check that could not run is
      # not a check that passed — which is the same sentence the timeout branch has always
      # made, and the reason the SDK's `Check::init` is allowed to refuse at all.
      config = load(repo(rootless_check_toml(), @lintcheck), trusted?: false)

      assert [failure] = Hooks.run_checks(config)
      assert failure =~ "could not run"
      assert String.starts_with?(failure, @label)
    end
  end

  describe "what the SDK's components actually are" do
    @tag @needs_examples
    test "every one of them is in this world and its whole authority is one import" do
      %{pool: pool} = repo(checks_toml(), @lintcheck)

      for {name, path} <- @components do
        assert {:ok, report} = Pool.inspect(path, pool)
        assert report["world"] == Wasm.world(), "#{name}: #{inspect(report["world"])}"
        assert report["imports"] == ["log"], "#{name}: #{inspect(report["imports"])}"
      end
    end
  end

  ## Fixtures

  defp base,
    do: %{"session_id" => "sess-sdk", "cwd" => "/tmp", "workspace_trusted" => false}

  # One `PreToolUse` call the `verdicts` fixture will answer whatever it was configured to say.
  defp decide(config), do: Hooks.pre_tool_use(config, "write", %{"path" => "a"}, base())

  # A fresh repository this node has never heard of, holding one built component and an
  # `ouroboros.toml` it wrote itself. `git init`-ed because that is what a clone is.
  defp repo(toml, component) do
    root = Path.join(tmp_dir(), "clone")
    File.mkdir_p!(Path.join(root, "hooks"))

    if exe = System.find_executable("git") do
      {_output, 0} = System.cmd(exe, ["init", "--quiet", root], stderr_to_stdout: true)
    end

    File.cp!(component, Path.join([root, "hooks", "guest.wasm"]))
    File.write!(Path.join(root, "ouroboros.toml"), toml)

    %{root: root, pool: start_pool()}
  end

  defp load(repo, trusted?: trusted?) do
    Hooks.load(repo.root,
      pool: repo.pool,
      trusted_workspaces: if(trusted?, do: [repo.root], else: []),
      # Never the machine's own user file.
      user_hooks_path: Path.join(repo.root, "no-such-user-hooks.toml")
    )
  end

  defp deny_toml do
    """
    [[hooks]]
    event = "PreToolUse"
    component = "./hooks/guest.wasm"
    config = '{"root": "src/"}'
    """
  end

  defp verdict_toml(say) do
    """
    [[hooks]]
    event = "PreToolUse"
    component = "./hooks/guest.wasm"
    config = '{"say": "#{say}"}'
    """
  end

  # One component, both directions, so a difference between the two answers cannot be a
  # difference between two builds.
  defp checks_toml do
    """
    [checks]
    lint = { component = "./hooks/guest.wasm", config = '{"fail": true}' }
    typecheck = { component = "./hooks/guest.wasm", config = '{"fail": false}' }
    """
  end

  defp rootless_check_toml do
    """
    [checks]
    lint = { component = "./hooks/guest.wasm", config = '{}' }
    """
  end

  defp start_pool do
    name = :"wasm_sdk_pool_#{System.unique_integer([:positive])}"
    {:ok, pid} = Pool.start(name: name, handshake_timeout_ms: 15_000)

    on_exit(fn ->
      if Process.alive?(pid) do
        try do
          GenServer.stop(pid, :normal, 5_000)
        catch
          :exit, _reason -> :ok
        end
      end
    end)

    pid
  end

  defp tmp_dir do
    dir = Path.join(System.tmp_dir!(), "ouro-wasm-sdk-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
