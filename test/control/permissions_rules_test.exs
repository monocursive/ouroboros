defmodule Ouroboros.Control.PermissionsRulesTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Control.Permissions.{Request, Rule, Rules}

  # ── Precedence ─────────────────────────────────────────────────────────────────────

  describe "precedence" do
    test "deny beats ask beats allow, whatever the scopes" do
      request = pushing()

      assert {:allow, %{scope: :session}} =
               Rules.decide(request, [session_rule(:allow, "Bash(git *)")])

      assert {:ask, :rule} =
               Rules.decide(request, [
                 rule(:node, :allow, "Bash(git *)"),
                 session_rule(:ask, "Bash(git push *)")
               ])

      assert {:deny, %{scope: :session}} =
               Rules.decide(request, [
                 rule(:node, :allow, "Bash(git *)"),
                 rule(:user, :ask, "Bash(git *)"),
                 session_rule(:deny, "Bash(git push *)")
               ])
    end

    test "scope breaks ties only inside one decision rank" do
      request = pushing()

      assert {:deny, %{scope: :node, pattern: "Bash(git *)"}} =
               Rules.decide(request, [
                 session_rule(:deny, "Bash(git push *)"),
                 rule(:node, :deny, "Bash(git *)")
               ])

      assert {:allow, %{scope: :user, pattern: "Bash(git *)"}} =
               Rules.decide(request, [
                 session_rule(:allow, "Bash(git push *)"),
                 rule(:user, :allow, "Bash(git *)")
               ])
    end

    test "nothing matched is ask, not deny" do
      request = Request.new(%{tool: "bash", command: "cargo build", mode: :execute})
      assert {:ask, :no_rule} = Rules.decide(request, [])
      assert {:ask, :no_rule} = Rules.decide(request, [rule(:node, :allow, "Bash(git *)")])
    end

    test "a workspace rule applies only to its own workspace" do
      root = tmp_root("scoped-ws")
      other = tmp_root("scoped-other")
      on_exit(fn -> Enum.each([root, other], &File.rm_rf/1) end)

      request =
        Request.new(%{tool: "bash", command: "make", mode: :execute, context: %{workspace: root}})

      assert {:allow, _ref} =
               Rules.decide(request, [rule(:workspace, :allow, "Bash(make *)", workspace: root)])

      assert {:ask, :no_rule} =
               Rules.decide(request, [rule(:workspace, :allow, "Bash(make *)", workspace: other)])
    end

    test "a session rule applies only to its own session" do
      request =
        Request.new(%{
          tool: "bash",
          command: "make",
          mode: :execute,
          principal: %{session_id: "s-1"}
        })

      assert {:allow, _ref} =
               Rules.decide(request, [rule(:session, :allow, "Bash(make *)", session_id: "s-1")])

      assert {:ask, :no_rule} =
               Rules.decide(request, [rule(:session, :allow, "Bash(make *)", session_id: "s-2")])
    end
  end

  # ── Protected paths ────────────────────────────────────────────────────────────────

  describe "protected paths" do
    setup do
      root = tmp_root("protected")
      File.mkdir_p!(Path.join(root, ".git"))
      File.mkdir_p!(Path.join(root, ".ouroboros"))
      data_dir = tmp_root("protected-data")
      File.mkdir_p!(data_dir)

      previous = Application.get_env(:ouroboros, :data_dir)
      Application.put_env(:ouroboros, :data_dir, data_dir)

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :data_dir, previous),
          else: Application.delete_env(:ouroboros, :data_dir)

        File.rm_rf(root)
        File.rm_rf(data_dir)
      end)

      {:ok, root: root, data_dir: data_dir}
    end

    test "a write inside the node's worktree root is not protected, but its .git still is",
         %{data_dir: data_dir} do
      # D7 puts the workspaces it provisions under `<data_dir>/worktrees`; a session
      # running in one has to be able to write there, and nowhere else beneath the data
      # directory.
      worktree = Path.join(data_dir, "worktrees/repo/session")
      File.mkdir_p!(Path.join(worktree, ".git"))
      {:ok, worktree} = Ouroboros.Control.Permissions.Paths.canonicalize(worktree, nil)
      {:ok, data_dir} = Ouroboros.Control.Permissions.Paths.canonicalize(data_dir, nil)

      refute Rules.protected_write?(Path.join(worktree, "lib/a.ex"))
      assert Rules.protected_write?(Path.join(worktree, ".git/HEAD"))
      assert Rules.protected_write?(Path.join(data_dir, "sessions/s1/conversation.json"))
    end

    test "a write into .git is denied whatever the rules say", %{root: root} do
      request =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: [".git/config"],
          context: %{workspace: root}
        })

      assert {:deny, %{id: "protected-path", pattern: "**/.git/**"}} =
               Rules.decide(request, [rule(:node, :allow, "Write(**)")])
    end

    test "a redirect into .git is denied even when the command is harmless", %{root: root} do
      request =
        Request.new(%{
          tool: "bash",
          command: "echo pwned > .git/hooks/pre-commit",
          mode: :execute,
          context: %{workspace: root}
        })

      assert {:deny, %{id: "protected-path"}} =
               Rules.decide(request, [rule(:node, :allow, "Bash(echo *)")])
    end

    test "a write into .ouroboros or the data directory is denied", %{
      root: root,
      data_dir: data_dir
    } do
      ouroboros =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: [".ouroboros/state.json"],
          context: %{workspace: root}
        })

      assert {:deny, %{pattern: "**/.ouroboros/**"}} = Rules.decide(ouroboros, [])

      data =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: [Path.join(data_dir, "permissions/rules")]
        })

      assert {:deny, %{id: "protected-path"}} = Rules.decide(data, [])
    end

    test "reading a protected path is not protected", %{root: root} do
      request =
        Request.new(%{
          tool: "read",
          mode: :read,
          paths: [".git/config"],
          context: %{workspace: root}
        })

      assert {:allow, _ref} = Rules.decide(request, [rule(:node, :allow, "Read(**)")])
    end

    test "the protected list names itself" do
      paths = Rules.protected_paths()
      assert "**/.git/**" in paths
      assert "**/.ouroboros/**" in paths
      assert Enum.any?(paths, &String.ends_with?(&1, "/**"))
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────────────

  defp pushing do
    Request.new(%{
      tool: "bash",
      command: "git push",
      mode: :execute,
      principal: %{session_id: "s-precedence"}
    })
  end

  defp session_rule(decision, pattern),
    do: rule(:session, decision, pattern, session_id: "s-precedence")

  defp rule(scope, decision, pattern, extra \\ []) do
    {:ok, rule} =
      Rule.new(Enum.into(extra, %{scope: scope, decision: decision, pattern: pattern}))

    rule
  end

  defp tmp_root(name) do
    path =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-permissions-#{name}-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(path)
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(path)
    canonical
  end
end
