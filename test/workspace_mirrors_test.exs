defmodule Ouroboros.WorkspaceMirrorsTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Workspace.{Bundle, Git, Mirrors, Provision, Returns, Snapshot, Worktree}

  setup do
    {:ok, root} = Git.temp_directory()
    repo = Path.join(root, "source")
    File.mkdir_p!(repo)
    git!(repo, ["init", "-q"])
    git!(repo, ["config", "user.name", "Test"])
    git!(repo, ["config", "user.email", "test@example.invalid"])
    # An incompressible base makes the incremental-transfer assertion meaningful.
    File.write!(Path.join(repo, "base"), :crypto.strong_rand_bytes(128 * 1024))
    git!(repo, ["add", "."])
    git!(repo, ["commit", "-qm", "Initial"])
    data = Path.join(root, "target-data")
    worktrees = Path.join(data, "worktrees")
    File.mkdir_p!(worktrees)
    old = Application.get_env(:ouroboros, :workspace_allowed_roots)
    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

    server =
      start_supervised!({Mirrors, name: nil, data_dir: data, worktree_opts: [root: worktrees]})

    returns = start_supervised!({Returns, name: nil, data_dir: Path.join(root, "parent-data")})

    rpc = fn _target, module, function, args, _timeout ->
      apply(module, function, args ++ [[server: server]])
    end

    on_exit(fn ->
      if old,
        do: Application.put_env(:ouroboros, :workspace_allowed_roots, old),
        else: Application.delete_env(:ouroboros, :workspace_allowed_roots)

      File.rm_rf(root)
    end)

    %{
      root: root,
      repo: repo,
      server: server,
      rpc: rpc,
      data: data,
      worktrees: worktrees,
      returns: returns
    }
  end

  test "ships dirty work, uses a target-owned worktree and reuses bundle basis", c do
    File.write!(Path.join(c.repo, "uncommitted"), "first")

    assert {:ok, first} =
             Provision.prepare(c.repo, node(), "task-first",
               returns_opts: [server: c.returns],
               rpc: c.rpc
             )

    assert {:ok, worktree} =
             Mirrors.worktree(first.repo_id, first.commit, first.task_id, server: c.server)

    assert File.read!(Path.join(worktree.root, "uncommitted")) == "first"
    assert worktree.provisioned
    assert worktree.root =~ "target-data/worktrees"
    assert {:ok, {:kept, :awaiting_return}} = Worktree.remove(worktree, root: c.worktrees)
    assert %{kept: [%{reason: :awaiting_return}]} = Worktree.reconcile(root: c.worktrees)

    File.write!(Path.join(c.repo, "uncommitted"), "second")

    assert {:ok, second} =
             Provision.prepare(c.repo, node(), "task-second",
               returns_opts: [server: c.returns],
               rpc: c.rpc
             )

    assert second.repo_id == first.repo_id
    assert second.basis == [first.commit]
    assert second.bytes < first.bytes / 2

    assert {:ok, second_tree} =
             Mirrors.worktree(second.repo_id, second.commit, second.task_id, server: c.server)

    assert File.read!(Path.join(second_tree.root, "uncommitted")) == "second"
  end

  test "serializes imports and rejects a mismatched digest", c do
    {snapshot, data, metadata} = bundle(c, "task-digest")
    metadata = %{metadata | sha256: String.duplicate("0", 64)}

    assert {:ok, token} =
             Mirrors.begin_import(snapshot.repo_id, metadata, node(), server: c.server)

    assert {:error, :mirror_import_busy} =
             Mirrors.begin_import(snapshot.repo_id, metadata, node(), server: c.server)

    assert {:error, :unexpected_chunk_offset} =
             Mirrors.put_chunk(token, 1, data, server: c.server)

    assert :ok = Mirrors.put_chunk(token, 0, data, server: c.server)

    assert {:error, :bundle_digest_mismatch} =
             Mirrors.finish_import(token, snapshot.commit, server: c.server)

    assert {:ok, []} = Mirrors.heads(snapshot.repo_id, server: c.server)
  end

  test "rejects corrupt Git content even with a matching digest", c do
    {:ok, snapshot} = Snapshot.commit(c.repo, "task-corrupt")
    path = Path.join(c.root, "invalid.bundle")
    File.write!(path, "not a git bundle")
    {:ok, metadata} = Bundle.metadata(path, snapshot.commit, snapshot.task_id)
    {:ok, token} = Mirrors.begin_import(snapshot.repo_id, metadata, node(), server: c.server)
    :ok = Mirrors.put_chunk(token, 0, File.read!(path), server: c.server)

    assert {:error, {:git, _, _}} =
             Mirrors.finish_import(token, snapshot.commit, server: c.server)

    assert {:ok, []} = Mirrors.heads(snapshot.repo_id, server: c.server)
  end

  test "bounds bundle size and releases a failed snapshot pin", c do
    assert {:error, {:bundle_too_large, 64}} =
             Provision.prepare(c.repo, node(), "task-cap",
               returns_opts: [server: c.returns],
               rpc: c.rpc,
               provision_max_bytes: 64
             )

    assert {:error, _} = Git.run(c.repo, ["rev-parse", "--verify", Snapshot.ref("task-cap")])
  end

  test "a timed-out transfer releases its snapshot pin and target import lock", c do
    rpc = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)

      if function == :put_chunk do
        send(self(), :chunk_accepted)
        Process.sleep(5_100)
        {:error, :provision_deadline_exceeded}
      else
        result
      end
    end

    assert {:error, :provision_deadline_exceeded} =
             Provision.prepare(c.repo, node(), "task-expiry",
               returns_opts: [server: c.returns],
               rpc: rpc,
               provision_deadline_ms: 5_000
             )

    assert_received :chunk_accepted
    assert {:error, _} = Git.run(c.repo, ["rev-parse", "--verify", Snapshot.ref("task-expiry")])
    {snapshot, _bytes, metadata} = bundle(c, "task-after-expiry")

    assert {:ok, token} =
             Mirrors.begin_import(snapshot.repo_id, metadata, node(), server: c.server)

    assert :ok = Mirrors.cancel_import(token, server: c.server)
  end

  test "reconciles only interrupted upload files at boot", c do
    directory = Path.join(c.root, "reconcile")
    File.mkdir_p!(Path.join(directory, "mirrors"))
    abandoned = Path.join(directory, "mirrors/incoming-old.part")
    kept = Path.join(directory, "mirrors/operator-file")
    File.write!(abandoned, "partial")
    File.write!(kept, "keep")
    {:ok, pid} = Mirrors.start_link(name: nil, data_dir: directory)
    refute File.exists?(abandoned)
    assert File.read!(kept) == "keep"
    GenServer.stop(pid)
  end

  test "refuses repository path traversal", c do
    assert {:error, :invalid_repository_id} = Mirrors.heads("../elsewhere", server: c.server)
  end

  test "preserves SHA-256 repository format when creating a mirror", c do
    repo = Path.join(c.root, "sha256-source")
    File.mkdir_p!(repo)
    git!(repo, ["init", "-q", "--object-format=sha256"])
    File.write!(Path.join(repo, "file"), "sha256 work")
    git!(repo, ["add", "."])

    git!(repo, [
      "-c",
      "user.name=Test",
      "-c",
      "user.email=test@example.invalid",
      "commit",
      "-qm",
      "Initial"
    ])

    assert {:ok, provision} =
             Provision.prepare(repo, node(), "task-sha256",
               returns_opts: [server: c.returns],
               rpc: c.rpc
             )

    assert byte_size(provision.commit) == 64

    assert {:ok, worktree} =
             Mirrors.worktree(provision.repo_id, provision.commit, provision.task_id,
               server: c.server
             )

    assert File.read!(Path.join(worktree.root, "file")) == "sha256 work"
  end

  test "an old peer without provisioning is refused by name" do
    assert {:error, {:provisioning_unavailable, target}} =
             Provision.rpc(
               node(),
               Ouroboros.NotInstalledProvisioner,
               :heads,
               [],
               System.monotonic_time(:millisecond) + 5_000
             )

    message =
      Ouroboros.Provider.Native.Tools.Agent.start_refusal(
        {:subagent_provision_failed, target, {:provisioning_unavailable, target}}
      )

    assert message =~ "release without provisioning"
    assert message =~ Atom.to_string(target)
  end

  defp bundle(c, task_id) do
    {:ok, snapshot} = Snapshot.commit(c.repo, task_id)
    path = Path.join(c.root, task_id <> ".bundle")
    git!(c.repo, ["bundle", "create", path, Snapshot.ref(task_id)])
    {:ok, metadata} = Bundle.metadata(path, snapshot.commit, task_id)
    {snapshot, File.read!(path), metadata}
  end

  defp git!(root, args) do
    {:ok, output} = Git.run(root, args)
    output
  end
end
