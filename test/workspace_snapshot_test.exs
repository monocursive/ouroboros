defmodule Ouroboros.WorkspaceSnapshotTest do
  use ExUnit.Case, async: true
  alias Ouroboros.Workspace.{Git, Snapshot}

  setup do
    {:ok, root} = Git.temp_directory()
    git!(root, ["init", "-q"])
    git!(root, ["config", "user.name", "Test"])
    git!(root, ["config", "user.email", "test@example.invalid"])
    File.write!(Path.join(root, "tracked.txt"), "initial\n")
    File.write!(Path.join(root, ".gitignore"), "ignored/\n")
    git!(root, ["add", "."])
    git!(root, ["commit", "-qm", "Initial"])
    on_exit(fn -> File.rm_rf(root) end)
    %{root: root}
  end

  test "captures staged, unstaged and untracked work without changing index or HEAD", %{
    root: root
  } do
    File.write!(Path.join(root, "tracked.txt"), "staged\n")
    git!(root, ["add", "tracked.txt"])
    File.write!(Path.join(root, "tracked.txt"), "unstaged\n")
    File.write!(Path.join(root, "new.txt"), "new\n")
    File.mkdir_p!(Path.join(root, "ignored"))
    File.write!(Path.join(root, "ignored/cache"), "ignored\n")
    before = state(root)
    assert {:ok, snapshot} = Snapshot.commit(root, "task-1")
    assert state(root) == before
    assert git!(root, ["show", snapshot.commit <> ":tracked.txt"]) == "unstaged"
    assert git!(root, ["show", snapshot.commit <> ":new.txt"]) == "new"
    assert {:error, _} = Git.run(root, ["show", snapshot.commit <> ":ignored/cache"])
    assert snapshot.untracked == ["new.txt"]
    assert git!(root, ["rev-parse", Snapshot.ref("task-1")]) == snapshot.commit
    assert byte_size(snapshot.repo_id) == 64
  end

  test "excludes tracked and untracked paths and deliveries", %{root: root} do
    File.write!(Path.join(root, "tracked.txt"), "staged exclusion")
    git!(root, ["add", "tracked.txt"])
    File.write!(Path.join(root, "tracked.txt"), "unstaged exclusion")

    File.write!(
      Path.join(root, "ouroboros.toml"),
      "[provision]\nexclude = [\"tracked.txt\", \"private*\"]\n"
    )

    File.write!(Path.join(root, "private.env"), "do not transfer")
    File.mkdir_p!(Path.join(root, ".ouroboros/deliver"))
    File.write!(Path.join(root, ".ouroboros/deliver/log"), "artifact")
    before = state(root)
    assert {:ok, snapshot} = Snapshot.commit(root, "task-exclude")
    assert state(root) == before
    files = git!(root, ["ls-tree", "-r", "--name-only", snapshot.commit])
    assert files =~ "ouroboros.toml"
    refute files =~ "tracked.txt"
    refute files =~ "private.env"
    refute files =~ "deliver"
  end

  test "captures materialized index-flagged files and preserves absent sparse entries", %{
    root: root
  } do
    for name <- ["assumed.txt", "skipped.txt", "absent.txt"] do
      File.write!(Path.join(root, name), "initial\n")
    end

    git!(root, ["add", "."])
    git!(root, ["commit", "-qm", "flag fixtures"])

    git!(root, [
      "sparse-checkout",
      "set",
      "--no-cone",
      "/tracked.txt",
      "/assumed.txt",
      "/.gitignore"
    ])

    git!(root, ["update-index", "--assume-unchanged", "assumed.txt"])
    git!(root, ["update-index", "--skip-worktree", "skipped.txt", "absent.txt"])
    refute File.exists?(Path.join(root, "absent.txt"))
    File.write!(Path.join(root, "assumed.txt"), "actual assumed edit\n")
    File.write!(Path.join(root, "skipped.txt"), "actual skipped edit\n")
    before = state(root)

    assert {:ok, snapshot} = Snapshot.commit(root, "task-index-flags")
    assert state(root) == before
    assert git!(root, ["show", snapshot.commit <> ":assumed.txt"]) == "actual assumed edit"
    assert git!(root, ["show", snapshot.commit <> ":skipped.txt"]) == "actual skipped edit"
    assert git!(root, ["show", snapshot.commit <> ":absent.txt"]) == "initial"
  end

  for filter <- ["clean", "process"] do
    test "snapshot disables repository #{filter} filters without altering config", %{root: root} do
      File.write!(Path.join(root, ".gitattributes"), "tracked.txt filter=review\n")

      git!(root, [
        "config",
        "filter.review.#{unquote(filter)}",
        "printf invoked > filter-ran; cat"
      ])

      git!(root, ["config", "filter.review.required", "true"])
      File.write!(Path.join(root, "tracked.txt"), "raw working content\n")
      index = File.read!(Path.join(root, ".git/index"))
      config = File.read!(Path.join(root, ".git/config"))

      result = Snapshot.commit(root, "task-filter-#{unquote(filter)}")
      refute File.exists?(Path.join(root, "filter-ran"))
      assert {:ok, snapshot} = result
      assert git!(root, ["show", snapshot.commit <> ":tracked.txt"]) == "raw working content"
      assert File.read!(Path.join(root, ".git/index")) == index
      assert File.read!(Path.join(root, ".git/config")) == config
    end
  end

  test "rehashes contents even when the index stat cache considers a file unchanged", %{
    root: root
  } do
    git!(root, ["config", "core.trustctime", "false"])
    git!(root, ["config", "core.checkStat", "minimal"])
    path = Path.join(root, "tracked.txt")
    stamp = {{2020, 1, 1}, {0, 0, 0}}
    File.touch!(path, stamp)
    git!(root, ["add", "tracked.txt"])
    File.write!(path, "updated\n")
    File.touch!(path, stamp)
    # Demonstrate the stale-cache precondition instead of relying on timing.
    assert {:ok, ""} = Git.run(root, ["diff", "--quiet"])
    before = state(root)

    assert {:ok, snapshot} = Snapshot.commit(root, "task-stat-cache")
    assert state(root) == before
    assert git!(root, ["show", snapshot.commit <> ":tracked.txt"]) == "updated"
  end

  test "works inside a detached worktree whose .git is a file", %{root: root} do
    path = Path.join(root, "child")
    git!(root, ["worktree", "add", "--detach", path, "HEAD"])
    File.write!(Path.join(path, "tracked.txt"), "child")
    before = state(path)
    assert {:ok, snapshot} = Snapshot.commit(path, "task-worktree")
    assert state(path) == before
    assert git!(root, ["show", snapshot.commit <> ":tracked.txt"]) == "child"
  end

  test "rejects invalid config and task IDs before capturing", %{root: root} do
    assert {:error, :invalid_snapshot_task_id} = Snapshot.commit(root, "../escape")
    File.write!(Path.join(root, "ouroboros.toml"), "[provision]\nexclude = [\"../escape\"]")
    assert {:error, :invalid_provision_excludes} = Snapshot.commit(root, "task-config")
  end

  test "snapshot bookkeeping never executes repository reference hooks", %{root: root} do
    hook = Path.join(root, ".git/hooks/reference-transaction")
    File.write!(hook, "#!/bin/sh\nprintf invoked > hook-ran\n")
    File.chmod!(hook, 0o755)
    assert {:ok, _} = Snapshot.commit(root, "task-hooks")
    assert {:ok, _} = Snapshot.release(root, "task-hooks")
    refute File.exists?(Path.join(root, "hook-ran"))
    refute File.exists?(Path.join(root, ".git/hook-ran"))
  end

  test "refuses an unborn repository with an actionable reason" do
    {:ok, root} = Git.temp_directory()
    on_exit(fn -> File.rm_rf(root) end)
    git!(root, ["init", "-q"])
    assert {:error, :snapshot_requires_a_commit} = Snapshot.commit(root, "task-unborn")
  end

  defp state(root) do
    # Disable optional locks: reading status must itself leave index bytes untouched.
    status = git!(root, ["--no-optional-locks", "status", "--porcelain=v1"])
    index = git!(root, ["rev-parse", "--path-format=absolute", "--git-path", "index"])
    {git!(root, ["rev-parse", "HEAD"]), File.read!(index), status}
  end

  defp git!(root, args) do
    {:ok, output} = Git.run(root, args)
    output
  end
end
