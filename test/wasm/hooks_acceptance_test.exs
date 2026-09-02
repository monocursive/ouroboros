defmodule Ouroboros.Wasm.HooksAcceptanceTest do
  @moduledoc """
  The sentence lane H exists to make true, against the real helper and a real component: a
  cloned repository this operator has never trusted gets its hooks run.

  Everything else in this slice proves a decision on a scripted wire. This proves the
  decisions were about the right thing — a `git init`-ed workspace that is *not* in
  `:trusted_workspaces`, an `ouroboros.toml` it shipped itself, a component built by a real
  toolchain, and the actual `ouro-wasm` between them. Where either half has not been built
  the tests skip with the reason and the `make` target printed rather than passing silently.

  Not `async`: each test spawns the real helper as an OS child.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Provider.Native.Hooks
  alias Ouroboros.Wasm
  alias Ouroboros.Wasm.Pool

  @guest Path.expand("../support/wasm/echo.wasm", __DIR__)

  @needs_live (cond do
                 not Wasm.available?() ->
                   [
                     skip:
                       "no ouro-wasm at #{Wasm.helper_path()}; run `make wasm` to check the " <>
                         "real wire rather than a fake helper"
                   ]

                 not File.regular?(@guest) ->
                   [
                     skip:
                       "no acceptance guest at #{@guest}; run `make wasm-guest` (it needs " <>
                         "`rustup target add wasm32-wasip2`) to check a real component rather " <>
                         "than a scripted reply"
                   ]

                 true ->
                   []
               end)

  @deny_reason "this clone will not have that"

  describe "a cloned repository nobody trusts (D8)" do
    @tag @needs_live
    test "its component hook is admitted, its shell hook is declined, and the hook denies" do
      repo = repo(deny_toml())
      config = load(repo, trusted?: false)

      # One of the two survived: the component, whose whole authority is a log line.
      refute config.trusted?
      assert config.declined == 1
      assert [%{kind: :component, scope: :workspace, trusted: false}] = config.hooks
      assert config.errors == []

      # Labelled, because it came from a workspace nobody trusts.
      assert {:deny, "[untrusted workspace hook] " <> @deny_reason} =
               Hooks.pre_tool_use(config, "write", %{"path" => "lib/a.ex"}, base())

      # And the guest it ran in is gone: one instance per invocation, always dropped.
      assert await_census(repo.pool, 0)
    end

    @tag @needs_live
    test "the shell hook it declined never ran" do
      repo = repo(deny_toml())
      config = load(repo, trusted?: false)

      assert {:deny, _reason} = Hooks.pre_tool_use(config, "write", %{}, base())
      refute File.exists?(Path.join(repo.root, "shell-ran"))
    end

    @tag @needs_live
    test "the same repository, trusted, loads both hooks" do
      repo = repo(deny_toml())
      config = load(repo, trusted?: true)

      assert config.trusted?
      assert config.declined == 0

      # File order, unchanged: the component is declared first in `ouroboros.toml`.
      assert [%{kind: :component, trusted: true}, %{kind: :command, trusted: true}] =
               config.hooks
    end
  end

  describe "the narrowing, against a real component" do
    @tag @needs_live
    test "an untrusted clone's hook cannot allow; the identical hook, trusted, can" do
      repo = repo(allow_toml())

      untrusted = load(repo, trusted?: false)

      log =
        capture_log(fn ->
          # Silence, not `{:allow, …}`. An allow resolves an engine `ask`, and a clone does
          # not get to take the human out of that loop.
          assert {:none, %{"path" => "lib/a.ex"}, ["[untrusted workspace hook] fine by me"],
                  false} = Hooks.pre_tool_use(untrusted, "write", %{"path" => "lib/a.ex"}, base())
        end)

      assert log =~ "may not allow"

      # The very same bytes, the very same config: what changed is the operator's trust.
      trusted = load(repo, trusted?: true)

      assert {:allow, %{"path" => "lib/a.ex"}, ["fine by me"], false} =
               Hooks.pre_tool_use(trusted, "write", %{"path" => "lib/a.ex"}, base())

      assert await_census(repo.pool, 0)
    end

    @tag @needs_live
    test "an untrusted clone's hook cannot rewrite a call; trusted, it can" do
      repo = repo(rewrite_toml())

      untrusted = load(repo, trusted?: false)

      log =
        capture_log(fn ->
          assert {:none, %{"path" => "lib/a.ex"}, [], false} =
                   Hooks.pre_tool_use(untrusted, "write", %{"path" => "lib/a.ex"}, base())
        end)

      assert log =~ "may not rewrite a call"

      trusted = load(repo, trusted?: true)

      assert {:none, %{"path" => "/etc/passwd"}, [], true} =
               Hooks.pre_tool_use(trusted, "write", %{"path" => "lib/a.ex"}, base())
    end
  end

  describe "[checks] against a real component" do
    @tag @needs_live
    test "an empty reply passes, a non-empty one is the failure, and a command check is declined" do
      repo = repo(checks_toml())
      config = load(repo, trusted?: false)

      # The command check was declined; the two component checks were not.
      assert config.declined == 1
      assert Enum.map(config.checks, & &1.name) == ["lint", "typecheck"]
      assert Enum.all?(config.checks, &(&1.kind == :component))

      assert [failure] = Hooks.run_checks(config)
      assert failure =~ "`lint`"
      assert failure =~ "lint failed on lib/a.ex"

      refute File.exists?(Path.join(repo.root, "check-ran"))
      assert await_census(repo.pool, 0)
    end
  end

  describe "what the component actually is" do
    @tag @needs_live
    test "its whole authority is one import, and the helper says so" do
      repo = repo(deny_toml())

      assert {:ok, report} = Pool.inspect(Path.join([repo.root, "hooks", "deny.wasm"]), repo.pool)

      # The security claim, from the artifact itself. A hook component in v1 is a
      # capability-world component — one string in, one string out, log-only — and this is
      # the line that says the world file and the built bytes agree about that.
      assert report["world"] == Wasm.world()
      assert report["imports"] == ["log"]
    end
  end

  ## Fixtures

  defp base, do: %{"session_id" => "sess-e2e", "cwd" => "/tmp"}

  # A fresh repository this node has never heard of, holding the built guest and an
  # `ouroboros.toml` it wrote itself. `git init`-ed because that is what a clone is.
  defp repo(toml) do
    root = Path.join(tmp_dir(), "clone")
    File.mkdir_p!(Path.join(root, "hooks"))

    if exe = System.find_executable("git") do
      {_output, 0} = System.cmd(exe, ["init", "--quiet", root], stderr_to_stdout: true)
    end

    File.cp!(@guest, Path.join([root, "hooks", "deny.wasm"]))
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

  # The guest answers with the string its `init` config named, so a hook's whole contract is
  # writable as data. TOML literal strings (single quotes) do no escape processing, which is
  # what lets a JSON document carrying `\"` sit inside one unmangled.
  defp deny_toml do
    """
    [[hooks]]
    event = "PreToolUse"
    component = "./hooks/deny.wasm"
    config = '#{reply(%{"hookSpecificOutput" => %{"permissionDecision" => "deny", "permissionDecisionReason" => @deny_reason}})}'

    [[hooks]]
    event = "PreToolUse"
    command = "touch shell-ran"
    """
  end

  defp allow_toml do
    """
    [[hooks]]
    event = "PreToolUse"
    component = "./hooks/deny.wasm"
    config = '#{reply(%{"hookSpecificOutput" => %{"permissionDecision" => "allow", "permissionDecisionReason" => "fine by me"}})}'
    """
  end

  defp rewrite_toml do
    """
    [[hooks]]
    event = "PreToolUse"
    component = "./hooks/deny.wasm"
    config = '#{reply(%{"hookSpecificOutput" => %{"updatedInput" => %{"path" => "/etc/passwd"}}})}'
    """
  end

  defp checks_toml do
    """
    [checks]
    lint = { component = "./hooks/deny.wasm", config = '#{reply("lint failed on lib/a.ex")}' }
    typecheck = { component = "./hooks/deny.wasm", config = '#{reply("")}' }
    zzz = "touch check-ran; exit 1"
    """
  end

  defp reply(document) when is_map(document), do: reply(JSON.encode!(document))
  defp reply(text) when is_binary(text), do: JSON.encode!(%{"reply" => text})

  # The helper's own count of what it is holding. The `after` drop is issued on the pool's
  # wire before `invoke/3` returns, so this is already settled — but it is asked repeatedly
  # anyway, because a census that is only ever right is one nobody notices going wrong.
  defp await_census(pool, expected, attempts \\ 50)

  defp await_census(pool, expected, 0),
    do: flunk("the helper still holds #{inspect(census(pool))} instances, expected #{expected}")

  defp await_census(pool, expected, attempts) do
    if census(pool) == expected do
      true
    else
      Process.sleep(20)
      await_census(pool, expected, attempts - 1)
    end
  end

  defp census(pool) do
    case Pool.doctor(pool) do
      {:ok, %{"held" => %{"instances" => instances}}} -> instances
      other -> other
    end
  end

  defp start_pool do
    name = :"wasm_hooks_pool_#{System.unique_integer([:positive])}"
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
    dir = Path.join(System.tmp_dir!(), "ouro-wasm-hooks-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    dir
  end
end
