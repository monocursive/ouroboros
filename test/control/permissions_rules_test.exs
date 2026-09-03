defmodule Ouroboros.Control.PermissionsRulesTest.Fixture do
  @moduledoc false

  # A canonical, unique scratch directory. Shared by both modules in this file: the async
  # rules tests and the serial data-directory tests below.
  def tmp_root(name) do
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

defmodule Ouroboros.Control.PermissionsRulesTest do
  # Async: every test here builds its own request and its own rules, and touches nothing
  # global. The protected-path tests that need a node data directory set the global
  # `:ouroboros, :data_dir` key, so they live in `PermissionsRulesDataDirTest` below,
  # serial, rather than making this whole file serial.
  use ExUnit.Case, async: true

  import Ouroboros.Control.PermissionsRulesTest.Fixture

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
      on_exit(fn -> File.rm_rf(root) end)
      {:ok, root: root}
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

    test "a redirect on a high descriptor is denied too", %{root: root} do
      # `3>` writes the file and `1>&3` points stdout at it: an allowlist that only knew
      # `>`, `1>`, and `2>` read this line as a bare `echo`.
      request =
        Request.new(%{
          tool: "bash",
          command: "echo pwned 3>.git/config 1>&3",
          mode: :execute,
          context: %{workspace: root}
        })

      assert {:deny, %{id: "protected-path"}} =
               Rules.decide(request, [rule(:node, :allow, "Bash(echo *)")])
    end

    test "a clobbering >| redirect into .git is denied", %{root: root} do
      request =
        Request.new(%{
          tool: "bash",
          command: "echo pwned >| .git/config",
          mode: :execute,
          context: %{workspace: root}
        })

      assert {:deny, %{id: "protected-path"}} =
               Rules.decide(request, [rule(:node, :allow, "Bash(echo *)")])
    end

    test "a protected segment is recognised whatever its case", %{root: root} do
      # APFS and NTFS are case-insensitive by default, so `.GIT/HEAD` is `.git/HEAD`
      # there — and write/edit/apply_patch never cross an OS sandbox.
      assert Rules.protected_write?(Path.join(root, ".GIT/HEAD"))
      assert Rules.protected_write?(Path.join(root, ".Git/hooks/pre-commit"))
      assert Rules.protected_write?(Path.join(root, ".Ouroboros/state.json"))
      refute Rules.protected_write?(Path.join(root, "gitignore"))

      request =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: [".GIT/config"],
          context: %{workspace: root}
        })

      assert {:deny, %{id: "protected-path", pattern: "**/.git/**"}} =
               Rules.decide(request, [rule(:node, :allow, "Write(**)")])
    end

    test "a write into .ouroboros is denied", %{root: root} do
      request =
        Request.new(%{
          tool: "write",
          mode: :write,
          paths: [".ouroboros/state.json"],
          context: %{workspace: root}
        })

      assert {:deny, %{pattern: "**/.ouroboros/**"}} = Rules.decide(request, [])
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

  # ── Truncated commands ─────────────────────────────────────────────────────────────

  describe "truncated commands" do
    test "an allow rule cannot win over parts the parser never read" do
      # 64 readable `safe` parts plus a 65th the bound drops. The allow rule covers
      # everything matching ever saw; the line it is asked to permit is longer than that.
      command = [List.duplicate("safe", 64), "rm -rf /"] |> List.flatten() |> Enum.join(" && ")

      request = Request.new(%{tool: "bash", command: command, mode: :execute})

      assert {:ask, :truncated_request} =
               Rules.decide(request, [rule(:node, :allow, "Bash(safe *)")])
    end

    test "a command longer than the byte bound asks even under a covering allow" do
      command =
        "safe " <> String.duplicate("x", Ouroboros.Control.Permissions.Shell.max_command_bytes())

      request = Request.new(%{tool: "bash", command: command, mode: :execute})

      assert {:ask, :truncated_request} =
               Rules.decide(request, [rule(:node, :allow, "Bash(safe *)")])
    end

    test "the byte bound can cut a UTF-8 codepoint without crashing the engine" do
      # 8,191 ASCII bytes followed by a multi-byte grapheme straddles the 8,192-byte
      # boundary. Matching sees the valid prefix and the uninspected tail withdraws the
      # allow instead of raising in the shell parser.
      command = String.duplicate("s", 8_191) <> "é"
      request = Request.new(%{tool: "bash", command: command, mode: :execute})

      assert {:ask, :truncated_request} =
               Rules.decide(request, [rule(:node, :allow, "Bash(s*)")])
    end

    test "a deny rule still matches the readable prefix of a truncated line" do
      # The refused part is inside the bound this time: deny matches fail-closed over the
      # prefix, so truncation does not weaken them the way it withdraws an allow win.
      command = ["rm -rf /" | List.duplicate("safe", 64)] |> Enum.join(" && ")

      request = Request.new(%{tool: "bash", command: command, mode: :execute})

      assert {:deny, _ref} =
               Rules.decide(request, [rule(:node, :deny, "Bash(rm *)")])
    end

    test "exactly the bound of parts is judged whole, not truncated" do
      command = Enum.join(List.duplicate("safe", 64), " && ")
      request = Request.new(%{tool: "bash", command: command, mode: :execute})

      assert {:allow, _ref} =
               Rules.decide(request, [rule(:node, :allow, "Bash(safe *)")])
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
end

defmodule Ouroboros.Control.PermissionsRulesDataDirTest do
  # Not async: these set the global `:ouroboros, :data_dir` application key, which every
  # store, journal, and worktree test resolving the node data directory reads. An async
  # writer of that key poisons whichever async reader happens to run alongside it — seen
  # once in 3,044 runs as the Wasm store finding a data directory the suite never
  # configured. Every other rules test touches nothing global and stays async above.
  use ExUnit.Case, async: false

  import Ouroboros.Control.PermissionsRulesTest.Fixture

  alias Ouroboros.Control.Permissions.{Paths, Request, Rules}

  setup do
    root = tmp_root("protected")
    File.mkdir_p!(Path.join(root, ".git"))
    data_dir = tmp_root("protected-data")

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
    {:ok, worktree} = Paths.canonicalize(worktree, nil)
    {:ok, data_dir} = Paths.canonicalize(data_dir, nil)

    refute Rules.protected_write?(Path.join(worktree, "lib/a.ex"))
    assert Rules.protected_write?(Path.join(worktree, ".git/HEAD"))
    assert Rules.protected_write?(Path.join(data_dir, "sessions/s1/conversation.json"))
  end

  test "a write into the data directory is denied", %{data_dir: data_dir} do
    request =
      Request.new(%{
        tool: "write",
        mode: :write,
        paths: [Path.join(data_dir, "permissions/rules")]
      })

    assert {:deny, %{id: "protected-path"}} = Rules.decide(request, [])
  end

  test "a redirect cannot hide a protected path behind a missing parent", %{
    root: root,
    data_dir: data_dir
  } do
    relative_data_dir = "../" <> Path.basename(data_dir)

    request =
      Request.new(%{
        tool: "bash",
        command: "mkdir gap && echo pwned > gap/../#{relative_data_dir}/permissions/rules.json",
        mode: :execute,
        context: %{workspace: root}
      })

    assert request.write_paths == [Path.join(data_dir, "permissions/rules.json")]
    assert {:deny, %{id: "protected-path"}} = Rules.decide(request, [])
  end
end
