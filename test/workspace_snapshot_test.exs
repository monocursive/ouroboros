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
