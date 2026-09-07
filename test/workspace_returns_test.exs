defmodule Ouroboros.WorkspaceReturnsTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Workspace.{
    Bundle,
    Deliveries,
    Git,
    Mirrors,
    Provision,
    Return,
    Returns,
    Snapshot,
    Worktree
  }

  setup do
    {:ok, root} = Git.temp_directory()
    repo = Path.join(root, "source")
    File.mkdir_p!(repo)

    for args <- [
          ["init", "-q"],
          ["config", "user.name", "Test"],
          ["config", "user.email", "test@example.invalid"]
        ],
        do: git!(repo, args)

    File.write!(Path.join(repo, "source.txt"), "initial")
    git!(repo, ["add", "."])
    git!(repo, ["commit", "-qm", "Initial"])
    File.write!(Path.join(repo, "source.txt"), "parent dirty")
    data = Path.join(root, "parent-data")
    worktrees = Path.join(root, "worker-data/worktrees")
    File.mkdir_p!(worktrees)
    old = Application.get_env(:ouroboros, :workspace_allowed_roots)
    Application.put_env(:ouroboros, :workspace_allowed_roots, [root])
    returns = start_supervised!({Returns, name: nil, data_dir: data})

    mirrors =
      start_supervised!(
        {Mirrors,
         name: nil, data_dir: Path.join(root, "worker-data"), worktree_opts: [root: worktrees]}
      )

    rpc = fn _target, module, function, args, _timeout ->
      server = if module == Mirrors, do: mirrors, else: returns
      apply(module, function, args ++ [[server: server]])
    end

    opts = [rpc: rpc, returns_opts: [server: returns]]
    {:ok, provision} = Provision.prepare(repo, node(), "task-return", opts)

    {:ok, worktree} =
      Mirrors.worktree(provision.repo_id, provision.commit, provision.task_id, server: mirrors)

    on_exit(fn ->
      if old,
        do: Application.put_env(:ouroboros, :workspace_allowed_roots, old),
        else: Application.delete_env(:ouroboros, :workspace_allowed_roots)

      File.rm_rf(root)
    end)

    %{
      root: root,
      repo: repo,
      data: data,
      worktrees: worktrees,
      returns: returns,
      mirrors: mirrors,
      provision: provision,
      worktree: worktree,
      rpc: rpc
    }
  end

  test "returns committed and dirty child work plus deliveries without touching parent HEAD or index",
       c do
    before = state(c.repo)
    File.write!(Path.join(c.worktree.path, "committed.txt"), "committed child")
    git!(c.worktree.path, ["add", "committed.txt"])

    git!(c.worktree.path, [
      "-c",
      "user.name=Child",
      "-c",
      "user.email=child@example.invalid",
      "commit",
      "-qm",
      "Child commit"
    ])

    File.write!(Path.join(c.worktree.path, "source.txt"), "dirty child")
    File.mkdir_p!(Path.join(c.worktree.path, ".ouroboros/deliver/reports"))
    File.write!(Path.join(c.worktree.path, ".ouroboros/deliver/reports/test.txt"), "tests passed")

    assert {:ok, receipt, retired} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: c.rpc,
               root: c.worktrees
             )

    assert retired["retired"] == "removed"
    refute File.exists?(c.worktree.path)
    assert state(c.repo) == before
    assert git!(c.repo, ["show", receipt.returned_ref <> ":source.txt"]) == "dirty child"
    assert git!(c.repo, ["show", receipt.returned_ref <> ":committed.txt"]) == "committed child"

    # The advertised single-commit cherry-pick must include the child's commits too,
    # not merely the dirty delta captured after its last commit.
    applied = Path.join(c.root, "apply-return")
    git!(c.repo, ["worktree", "add", "--detach", applied, c.provision.commit])
    git!(applied, ["cherry-pick", receipt.returned_commit])

    assert git!(applied, ["rev-parse", "HEAD^{tree}"]) ==
             git!(c.repo, ["rev-parse", receipt.returned_ref <> "^{tree}"])

    assert receipt.returned_files == [
             %{status: "A", path: "committed.txt"},
             %{status: "M", path: "source.txt"}
           ]

    assert [%{path: delivered, bytes: 12}] = receipt.deliveries
    assert File.read!(delivered) == "tests passed"
    assert delivered == Path.join(c.data, "deliveries/task-return/reports/test.txt")

    assert {:error, _} =
             Git.run(c.repo, ["rev-parse", "--verify", Snapshot.ref(c.provision.task_id)])

    assert {:ok, ^receipt} =
             Returns.acknowledge(
               c.provision.return_token,
               receipt.returned_commit,
               receipt.manifest,
               server: c.returns
             )

    assert {:error, :invalid_return_import} =
             Returns.begin_import(
               c.provision.return_token,
               :bundle,
               %{
                 task_id: c.provision.task_id,
                 commit: receipt.returned_commit,
                 bytes: 1,
                 sha256: String.duplicate("a", 64)
               },
               server: c.returns
             )

    refute Map.has_key?(Provision.remote_metadata(c.provision), :snapshot)
    refute inspect(Provision.remote_metadata(c.provision)) =~ c.repo
  end

  test "an ambiguous acknowledgment keeps all remote work and its snapshot pin", c do
    File.write!(Path.join(c.worktree.path, "source.txt"), "keep me")

    rpc = fn target, module, function, args, timeout ->
      if function == :acknowledge do
        assert {:ok, _} = c.rpc.(target, module, function, args, timeout)
        {:error, :connection_lost_after_ack}
      else
        c.rpc.(target, module, function, args, timeout)
      end
    end

    assert {:error, :connection_lost_after_ack} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees
             )

    assert File.read!(Path.join(c.worktree.path, "source.txt")) == "keep me"

    assert git!(c.worktree.path, ["rev-parse", "--verify", Snapshot.ref(c.provision.task_id)]) !=
             ""

    # A stripped public map must still hit the marker's awaiting-return guard.
    assert {:ok, {:kept, :awaiting_return}} =
             Worktree.remove(%{path: c.worktree.path, repository: c.worktree.repository},
               root: c.worktrees
             )
  end

  test "returns assumed-unchanged edits before removing the child worktree", c do
    git!(c.worktree.path, ["update-index", "--assume-unchanged", "source.txt"])
    File.write!(Path.join(c.worktree.path, "source.txt"), "must return this edit")

    assert {:ok, receipt, retired} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: c.rpc,
               root: c.worktrees
             )

    assert git!(c.repo, ["show", receipt.returned_ref <> ":source.txt"]) ==
             "must return this edit"

    assert retired["retired"] == "removed"
    refute File.exists?(c.worktree.path)
  end

  test "a late assumed-unchanged edit cannot authorize cleanup", c do
    rpc = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)

      if function == :acknowledge do
        git!(c.worktree.path, ["update-index", "--assume-unchanged", "source.txt"])
        File.write!(Path.join(c.worktree.path, "source.txt"), "unacknowledged edit")
      end

      result
    end

    assert {:ok, receipt, retired} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees
             )

    assert retired["retired"] == "kept"
    assert receipt.return_error =~ "changed_since_return"
    assert File.read!(Path.join(c.worktree.path, "source.txt")) == "unacknowledged edit"
  end

  test "overlapping returns wait for the repository and both complete", c do
    {:ok, second} =
      Provision.prepare(c.repo, node(), "task-second",
        rpc: c.rpc,
        returns_opts: [server: c.returns]
      )

    {:ok, second_tree} =
      Mirrors.worktree(second.repo_id, second.commit, second.task_id, server: c.mirrors)

    File.write!(Path.join(c.worktree.path, "first.txt"), "first result")
    File.write!(Path.join(second_tree.path, "second.txt"), "second result")
    owner = self()

    paused = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)

      if function == :begin_import and match?({:ok, _}, result) do
        send(owner, {:import_open, self()})

        receive do
          :resume -> :ok
        after
          10_000 -> flunk("return never resumed")
        end
      end

      result
    end

    first_task =
      Task.async(fn ->
        Return.finish(
          Worktree.public(c.worktree),
          Provision.remote_metadata(c.provision),
          rpc: paused,
          root: c.worktrees
        )
      end)

    assert_receive {:import_open, first_pid}, 10_000

    observed = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)
      if result == {:error, :return_repository_busy}, do: send(owner, :repository_busy)
      result
    end

    second_task =
      Task.async(fn ->
        Return.finish(
          Worktree.public(second_tree),
          Provision.remote_metadata(second),
          rpc: observed,
          root: c.worktrees
        )
      end)

    assert_receive :repository_busy, 10_000
    send(first_pid, :resume)
    assert {:ok, first_receipt, %{"retired" => "removed"}} = Task.await(first_task, 10_000)
    assert {:ok, second_receipt, %{"retired" => "removed"}} = Task.await(second_task, 10_000)
    assert git!(c.repo, ["show", first_receipt.returned_ref <> ":first.txt"]) == "first result"
    assert git!(c.repo, ["show", second_receipt.returned_ref <> ":second.txt"]) == "second result"
  end

  test "busy return retries remain bounded by the caller's deadline", c do
    owner = self()

    rpc = fn target, module, function, args, timeout ->
      if function == :begin_import do
        send(owner, :attempted_import)
        {:error, :return_repository_busy}
      else
        c.rpc.(target, module, function, args, timeout)
      end
    end

    started = System.monotonic_time(:millisecond)

    assert {:error, :provision_deadline_exceeded} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees,
               deadline: started + 2_000
             )

    assert_received :attempted_import
    assert System.monotonic_time(:millisecond) - started < 5_000
    assert File.dir?(c.worktree.path)
  end

  test "acknowledgment retries verify deliveries installed before a transient Git failure", c do
    Deliveries.prepare(c.worktree.path)
    File.write!(Path.join(c.worktree.path, ".ouroboros/deliver/report.txt"), "report")
    lock = Path.join(c.repo, ".git/refs/ouroboros/snapshots/#{c.provision.task_id}.lock")
    owner = self()

    rpc = fn target, module, function, args, timeout ->
      if function == :acknowledge, do: File.write!(lock, "")
      result = c.rpc.(target, module, function, args, timeout)

      if function == :acknowledge do
        File.rm!(lock)
        send(owner, {:acknowledge_args, args})
      end

      result
    end

    assert {:error, {:git, _, _}} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees
             )

    assert_received {:acknowledge_args, args}
    path = Path.join(c.data, "deliveries/#{c.provision.task_id}/report.txt")
    assert File.read!(path) == "report"

    File.write!(path, "edited")

    assert {:error, :delivery_manifest_mismatch} =
             apply(Returns, :acknowledge, args ++ [[server: c.returns]])

    assert File.read!(path) == "edited"
    assert File.dir?(c.worktree.path)
    File.write!(path, "report")
    assert {:ok, receipt} = apply(Returns, :acknowledge, args ++ [[server: c.returns]])
    assert receipt.acknowledged
    assert {:ok, ^receipt} = apply(Returns, :acknowledge, args ++ [[server: c.returns]])
  end

  test "a concurrent edit or delivery after capture prevents cleanup", c do
    File.write!(Path.join(c.worktree.path, "source.txt"), "captured")

    rpc = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)

      if function == :acknowledge,
        do: File.write!(Path.join(c.worktree.path, "source.txt"), "late edit")

      result
    end

    assert {:ok, receipt, retired} =
             Return.finish(Worktree.public(c.worktree), Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees
             )

    assert retired["retired"] == "kept"
    assert receipt.return_error =~ "changed_since_return"
    assert File.read!(Path.join(c.worktree.path, "source.txt")) == "late edit"
    assert git!(c.repo, ["show", receipt.returned_ref <> ":source.txt"]) == "captured"
  end

  test "a delivery changed after acknowledgment retains the worktree and captured artifact", c do
    Deliveries.prepare(c.worktree.path)
    path = Path.join(c.worktree.path, ".ouroboros/deliver/report.txt")
    File.write!(path, "captured report")

    rpc = fn target, module, function, args, timeout ->
      result = c.rpc.(target, module, function, args, timeout)
      if function == :acknowledge, do: File.write!(path, "later report")
      result
    end

    assert {:ok, receipt, retired} =
             Return.finish(
               Worktree.public(c.worktree),
               Provision.remote_metadata(c.provision),
               rpc: rpc,
               root: c.worktrees
             )

    assert retired["retired"] == "kept"
    assert receipt.return_error =~ "changed_since_return"
    assert File.read!(path) == "later report"
    assert [%{path: captured}] = receipt.deliveries
    assert File.read!(captured) == "captured report"
  end

  test "receiver verifies Git, not just a matching transport digest", c do
    fake = Path.join(c.root, "not-a-bundle")
    File.write!(fake, "not git objects")
    {:ok, metadata} = Bundle.metadata(fake, c.provision.commit, c.provision.task_id)

    assert {:error, :invalid_return_import} =
             Returns.begin_import(
               c.provision.return_token,
               :bundle,
               nil,
               server: c.returns
             )

    assert {:ok, token} =
             Returns.begin_import(c.provision.return_token, :bundle, metadata, server: c.returns)

    assert :ok = Returns.put_chunk(token, 0, File.read!(fake), server: c.returns)
    assert {:error, _} = Returns.finish_import(token, c.provision.commit, server: c.returns)

    assert {:error, _} =
             Git.run(c.repo, ["rev-parse", "--verify", Returns.ref(c.provision.task_id)])

    assert {:ok, _} =
             Git.run(c.repo, ["rev-parse", "--verify", Snapshot.ref(c.provision.task_id)])

    assert File.dir?(c.worktree.path)
  end

  test "return imports are serialized per repository and digest mismatches cannot publish a ref",
       c do
    {:ok, snapshot} = Snapshot.commit(c.worktree.path, c.provision.task_id, return_snapshot: true)
    archive = Path.join(c.root, "return.bundle")

    git!(c.worktree.path, [
      "bundle",
      "create",
      archive,
      Snapshot.ref(snapshot.task_id),
      "^" <> c.provision.commit
    ])

    {:ok, metadata} = Bundle.metadata(archive, snapshot.commit, snapshot.task_id)
    metadata = %{metadata | sha256: String.duplicate("0", 64)}

    assert {:ok, token} =
             Returns.begin_import(c.provision.return_token, :bundle, metadata, server: c.returns)

    assert {:error, :return_repository_busy} =
             Returns.begin_import(c.provision.return_token, :bundle, metadata, server: c.returns)

    assert :ok = Returns.put_chunk(token, 0, File.read!(archive), server: c.returns)

    assert {:error, :bundle_digest_mismatch} =
             Returns.finish_import(token, snapshot.commit, server: c.returns)

    assert {:error, _} = Git.run(c.repo, ["rev-parse", "--verify", Returns.ref(snapshot.task_id)])

    assert {:error, :unknown_return_capability} =
             Returns.begin_import("invented-root", :bundle, metadata, server: c.returns)
  end

  test "deliveries reject symlinks and oversized input before return", c do
    dir = Path.join(c.worktree.path, ".ouroboros/deliver")
    File.mkdir_p!(dir)
    File.ln_s!(Path.join(c.repo, "source.txt"), Path.join(dir, "link"))

    assert {:error, {:unsafe_delivery_path, "link"}} =
             Deliveries.capture(c.worktree.path, "task", c.provision.commit)

    File.rm!(Path.join(dir, "link"))
    File.write!(Path.join(dir, "one"), "one")
    File.write!(Path.join(dir, "two"), "two")
    assert {:ok, capture} = Deliveries.capture(c.worktree.path, "task", c.provision.commit)
    assert length(capture.files) == 2

    assert {:ok, _} =
             Deliveries.extract(capture.path, Path.join(c.root, "two-files"), capture.files)

    File.rm_rf!(capture.temporary)
    File.rm!(Path.join(dir, "one"))
    File.rm!(Path.join(dir, "two"))
    File.write!(Path.join(dir, "large"), String.duplicate("x", 101))

    assert {:error, {:deliveries_too_large, 100}} =
             Deliveries.capture(c.worktree.path, "task", c.provision.commit,
               deliver_max_bytes: 100
             )
  end

  test "receiver refuses tar traversal instead of writing outside its delivery directory", c do
    archive = Path.join(c.root, "hostile.tar")
    :ok = :erl_tar.create(String.to_charlist(archive), [{~c"../escape", "danger"}], [])
    target = Path.join(c.root, "extract")
    assert {:error, _} = Deliveries.extract(archive, target, [])
    refute File.exists?(Path.join(c.root, "escape"))
    refute File.exists?(target)
  end

  defp state(root) do
    index = git!(root, ["rev-parse", "--path-format=absolute", "--git-path", "index"])
    {git!(root, ["rev-parse", "HEAD"]), File.read!(index), git!(root, ["status", "--porcelain"])}
  end

  defp git!(root, args) do
    {:ok, output} = Git.run(root, args)
    output
  end
end
