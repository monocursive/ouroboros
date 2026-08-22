defmodule Ouroboros.WorkspaceWorktreeTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Worktree

  setup do
    root = Path.join(System.tmp_dir!(), "worktree-#{System.unique_integer([:positive])}")
    repo = Path.join(root, "repo")
    worktrees = Path.join(root, "worktrees")
    File.mkdir_p!(repo)
    File.mkdir_p!(worktrees)

    on_exit(fn -> File.rm_rf(root) end)

    %{root: root, repo: repo, worktrees: worktrees}
  end

  # ---------------------------------------------------------------- argv

  describe "argv is never a shell string" do
    test "create issues exactly these argument lists, in this order", context do
      {runner, log} = recording_runner(context)

      {:ok, _worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      calls = Agent.get(log, & &1) |> Enum.reverse()

      assert Enum.map(calls, &elem(&1, 0)) == [
               ["rev-parse", "--show-toplevel"],
               ["rev-parse", "HEAD"],
               [
                 "worktree",
                 "add",
                 "--detach",
                 Path.join([context.worktrees, tag(context.repo), "sess-1"]),
                 "deadbeef"
               ]
             ]
    end

    test "a session id that looks like a shell fragment is refused before any git runs",
         context do
      {runner, log} = recording_runner(context)

      for hostile <- ["a; rm -rf /", "$(whoami)", "../escape", "a\nb", "--force"] do
        assert {:error, {:invalid_worktree_session_id, ^hostile}} =
                 Worktree.create(context.repo, hostile, runner: runner, root: context.worktrees)
      end

      assert Agent.get(log, & &1) == []
    end

    test "a path with a space or a quote is one argument, not two", context do
      spaced = Path.join(context.root, "re po 'x'")
      File.mkdir_p!(spaced)
      {runner, log} = recording_runner(context, toplevel: spaced)

      {:ok, worktree} =
        Worktree.create(spaced, "sess-1", runner: runner, root: context.worktrees)

      [{_rev, _cwd}, {_head, _cwd2}, {add_args, cwd}] = Agent.get(log, & &1) |> Enum.reverse()

      {:ok, canonical_spaced} = Ouroboros.Workspace.Path.canonicalize(spaced)
      assert cwd == canonical_spaced
      assert length(add_args) == 5
      # git is handed the path this module constructed; `worktree.path` is what came back
      # after canonicalization, which on a macOS temp dir differs by the /private prefix.
      assert Enum.at(add_args, 3) == Path.join([context.worktrees, tag(spaced), "sess-1"])
      assert String.ends_with?(worktree.path, "/sess-1")
    end

    test "the dirty check and the removal are argv lists too", context do
      {runner, log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      Agent.update(log, fn _calls -> [] end)
      {:ok, :removed} = Worktree.remove(worktree, runner: runner, root: context.worktrees)

      assert Agent.get(log, & &1) |> Enum.reverse() |> Enum.map(&elem(&1, 0)) == [
               ["status", "--porcelain"],
               ["worktree", "remove", worktree.path]
             ]
    end
  end

  # ---------------------------------------------------------------- refusals

  describe "refusals" do
    test "a workspace that is not a git repository", context do
      runner = fn
        ["rev-parse", "--show-toplevel"], _cwd -> {:error, {128, "not a git repository"}}
        _args, _cwd -> {:ok, ""}
      end

      assert {:error, {:not_a_git_repository, _path}} =
               Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)
    end

    test "a dirty repository when the caller asked for clean", context do
      {runner, _log} = recording_runner(context, status: " M lib/a.ex\n")

      assert {:error, {:repository_dirty, _path}} =
               Worktree.create(context.repo, "sess-1",
                 runner: runner,
                 root: context.worktrees,
                 require_clean: true
               )
    end

    test "a dirty repository is fine when the caller did not ask for clean", context do
      {runner, _log} = recording_runner(context, status: " M lib/a.ex\n")

      assert {:ok, _worktree} =
               Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)
    end

    test "a path that already exists", context do
      {runner, _log} = recording_runner(context)
      File.mkdir_p!(Path.join([context.worktrees, tag(context.repo), "sess-1"]))

      assert {:error, {:worktree_exists, _path}} =
               Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)
    end

    test "a repository with no HEAD commit", context do
      runner = fn
        ["rev-parse", "--show-toplevel"], _cwd -> {:ok, context.repo <> "\n"}
        ["rev-parse", "HEAD"], _cwd -> {:error, {128, "unknown revision"}}
        _args, _cwd -> {:ok, ""}
      end

      assert {:error, {:no_head_commit, _path, _output}} =
               Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)
    end
  end

  # ---------------------------------------------------------------- lifecycle

  describe "create, canonicalize, and record" do
    test "the created path is canonical and recorded with its base commit", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      assert worktree.base_commit == "deadbeef"
      assert worktree.branch == nil
      assert worktree.session_id == "sess-1"
      assert String.ends_with?(worktree.path, "/sess-1")
      # Canonical: no symlink left in the string the lease machinery will be handed.
      assert {:ok, worktree.path} == Ouroboros.Workspace.Path.canonicalize(worktree.path)

      assert [recorded] = Worktree.list(root: context.worktrees)
      assert recorded.path == worktree.path
      assert recorded.base_commit == "deadbeef"
    end

    test "a workspace inside a repository gets the same subdirectory in the worktree",
         context do
      sub = Path.join(context.repo, "apps/web")
      File.mkdir_p!(sub)
      {runner, _log} = recording_runner(context, subdirs: ["apps/web"])

      {:ok, worktree} =
        Worktree.create(sub, "sess-1", runner: runner, root: context.worktrees)

      assert worktree.root == Path.join(worktree.path, "apps/web")
      assert String.starts_with?(worktree.root, worktree.path <> "/")
    end

    test "the marker survives a reread and forgets a removed worktree", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      assert Worktree.find(worktree.path, root: context.worktrees)
      {:ok, :removed} = Worktree.remove(worktree, runner: runner, root: context.worktrees)
      assert Worktree.find(worktree.path, root: context.worktrees) == nil
    end
  end

  describe "cleanup never destroys work" do
    test "a clean worktree is removed", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      assert {:ok, :removed} = Worktree.remove(worktree, runner: runner, root: context.worktrees)
    end

    test "a dirty worktree is kept, and says why", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      dirty = fn
        ["status", "--porcelain"], _cwd -> {:ok, "?? notes.md\n"}
        args, cwd -> runner.(args, cwd)
      end

      assert {:ok, {:kept, :dirty}} =
               Worktree.remove(worktree, runner: dirty, root: context.worktrees)

      assert File.dir?(worktree.path)
      assert Worktree.find(worktree.path, root: context.worktrees)
    end

    test "a status this runtime cannot read is treated as dirty", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      broken = fn
        ["status", "--porcelain"], _cwd -> {:error, {1, "boom"}}
        args, cwd -> runner.(args, cwd)
      end

      assert {:ok, {:kept, :dirty}} =
               Worktree.remove(worktree, runner: broken, root: context.worktrees)
    end

    test "git refusing the removal keeps it too", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      refusing = fn
        ["worktree", "remove", _path], _cwd -> {:error, {1, "is locked"}}
        args, cwd -> runner.(args, cwd)
      end

      assert {:ok, {:kept, {:git_failed, "is locked"}}} =
               Worktree.remove(worktree, runner: refusing, root: context.worktrees)
    end
  end

  describe "reconcile" do
    test "removes clean strays, reports dirty ones, forgets missing ones", context do
      {runner, _log} = recording_runner(context)

      {:ok, clean} =
        Worktree.create(context.repo, "clean", runner: runner, root: context.worktrees)

      {:ok, dirty} =
        Worktree.create(context.repo, "dirty", runner: runner, root: context.worktrees)

      {:ok, gone} = Worktree.create(context.repo, "gone", runner: runner, root: context.worktrees)
      File.rm_rf!(gone.path)

      selective = fn
        ["status", "--porcelain"], cwd ->
          if cwd == dirty.path, do: {:ok, " M a.ex\n"}, else: {:ok, ""}

        args, cwd ->
          runner.(args, cwd)
      end

      report = Worktree.reconcile(runner: selective, root: context.worktrees)

      assert report.removed == [clean.path]
      assert [%{path: kept_path, reason: :dirty}] = report.kept
      assert kept_path == dirty.path
      assert report.missing == [gone.path]

      assert Enum.map(Worktree.list(root: context.worktrees), & &1.path) == [dirty.path]
      assert File.dir?(dirty.path)
    end

    test "an empty marker is not an error", context do
      assert %{removed: [], kept: [], missing: []} =
               Worktree.reconcile(root: context.worktrees)
    end
  end

  # ---------------------------------------------------------------- leasing

  describe "the lease applies to the worktree" do
    setup context do
      name = :"worktree_manager_#{System.unique_integer([:positive])}"

      {:ok, _pid} =
        start_supervised(
          {Ouroboros.Workspace.Manager,
           name: name, allowed_roots: [context.root], recover_reservations: false}
        )

      %{manager: name}
    end

    test "a worktree can be leased and is contained by its own path", context do
      {runner, _log} = recording_runner(context)

      {:ok, worktree} =
        Worktree.create(context.repo, "sess-1", runner: runner, root: context.worktrees)

      assert {:ok, lease, _capability} =
               Workspace.acquire(worktree.root, "task-1", server: context.manager)

      assert lease.root == worktree.root
      assert Ouroboros.Workspace.Path.within?(worktree.root, worktree.path)
      refute Ouroboros.Workspace.Path.within?(worktree.root, context.repo)
    end

    test "two sessions on one repository do not conflict once each has its own worktree",
         context do
      {runner, _log} = recording_runner(context)

      {:ok, one} = Worktree.create(context.repo, "a", runner: runner, root: context.worktrees)
      {:ok, two} = Worktree.create(context.repo, "b", runner: runner, root: context.worktrees)

      assert {:ok, _lease_a, _cap_a} =
               Workspace.acquire(one.root, "task-a", server: context.manager)

      assert {:ok, _lease_b, _cap_b} =
               Workspace.acquire(two.root, "task-b", server: context.manager)
    end

    test "the same two sessions DO conflict on the bare repository", context do
      assert {:ok, _lease, _cap} =
               Workspace.acquire(context.repo, "task-a", server: context.manager)

      assert {:error, {:workspace_conflict, _conflicts}} =
               Workspace.acquire(context.repo, "task-b", server: context.manager)
    end
  end

  # ---------------------------------------------------------------- planes

  describe "the start option on both planes" do
    test "TaskState.new/4 accepts worktree: true and records the request", context do
      assert {:ok, task} =
               TaskState.new(
                 "t1",
                 "do a thing",
                 [workspace: context.repo, worktree: true],
                 :coding
               )

      assert task.worktree_requested
      assert task.worktree == nil
    end

    test "TaskState defaults to no worktree", context do
      {:ok, task} = TaskState.new("t1", "do a thing", [workspace: context.repo], :coding)
      refute task.worktree_requested
    end

    test "TaskState refuses a non-boolean", context do
      assert {:error, {:invalid_worktree, "yes"}} =
               TaskState.new("t1", "x", [workspace: context.repo, worktree: "yes"], :coding)
    end

    test "State.new/2 carries the option through the interactive plane", context do
      assert {:ok, session} = State.new("s1", workspace: context.repo, worktree: true)
      assert session.worktree_requested
      assert session.worktree == nil
    end

    test "State.new/2 defaults to no worktree", context do
      {:ok, session} = State.new("s1", workspace: context.repo)
      refute session.worktree_requested
    end
  end

  describe "provision/3 and retire/2" do
    setup context do
      previous = Application.get_env(:ouroboros, :workspace_allowed_roots)
      Application.put_env(:ouroboros, :workspace_allowed_roots, [context.root])

      on_exit(fn ->
        if previous,
          do: Application.put_env(:ouroboros, :workspace_allowed_roots, previous),
          else: Application.delete_env(:ouroboros, :workspace_allowed_roots)
      end)

      :ok
    end

    test "a record that did not ask is returned untouched", context do
      record = %{workspace: context.repo, worktree_requested: false, worktree: nil}
      assert {:ok, ^record} = Worktree.provision(record, "s1", root: context.worktrees)
    end

    test "a record that asked gets its workspace repointed at the worktree", context do
      {runner, _log} = recording_runner(context)
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}

      {:ok, provisioned} =
        Worktree.provision(record, "s1", runner: runner, root: context.worktrees)

      refute provisioned.workspace == context.repo
      assert provisioned.workspace == provisioned.worktree["root"]
      assert provisioned.worktree["base_commit"] == "deadbeef"
    end

    test "provisioning twice does not make a second worktree", context do
      {runner, _log} = recording_runner(context)
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}
      opts = [runner: runner, root: context.worktrees]

      {:ok, once} = Worktree.provision(record, "s1", opts)
      {:ok, twice} = Worktree.provision(once, "s1", opts)

      assert once == twice
      assert length(Worktree.list(root: context.worktrees)) == 1
    end

    test "a worktree root outside the allowed roots refuses with the fix in the message",
         context do
      Application.put_env(:ouroboros, :workspace_allowed_roots, [context.repo])
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}

      assert {:error, {:worktree_root_not_admitted, _root, message}} =
               Worktree.provision(record, "s1", root: context.worktrees)

      assert message =~ "workspace_allowed_roots"
    end

    test "retire records the outcome on the record", context do
      {runner, _log} = recording_runner(context)
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}
      opts = [runner: runner, root: context.worktrees]

      {:ok, provisioned} = Worktree.provision(record, "s1", opts)
      {:ok, retired, :removed} = Worktree.retire(provisioned, opts)

      assert retired.worktree["retired"] == "removed"
    end

    test "retire keeps a dirty worktree and says why on the record", context do
      {runner, _log} = recording_runner(context)
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}

      {:ok, provisioned} =
        Worktree.provision(record, "s1", runner: runner, root: context.worktrees)

      dirty = fn
        ["status", "--porcelain"], _cwd -> {:ok, "?? scratch\n"}
        args, cwd -> runner.(args, cwd)
      end

      {:ok, retired, {:kept, :dirty}} =
        Worktree.retire(provisioned, runner: dirty, root: context.worktrees)

      assert retired.worktree["retired"] == "kept"
      assert retired.worktree["retained_reason"] == "uncommitted changes"
      assert File.dir?(retired.worktree["path"])
    end

    test "retire on a record with no worktree is not applicable", context do
      record = %{workspace: context.repo, worktree_requested: false, worktree: nil}
      assert :not_applicable = Worktree.retire(record, root: context.worktrees)
    end

    test "retiring an already-retired record is a no-op, so it is never reported twice",
         context do
      {runner, _log} = recording_runner(context)
      record = %{workspace: context.repo, worktree_requested: true, worktree: nil}

      {:ok, provisioned} =
        Worktree.provision(record, "s1", runner: runner, root: context.worktrees)

      dirty = fn
        ["status", "--porcelain"], _cwd -> {:ok, "?? scratch\n"}
        args, cwd -> runner.(args, cwd)
      end

      {:ok, kept, {:kept, :dirty}} =
        Worktree.retire(provisioned, runner: dirty, root: context.worktrees)

      assert :not_applicable = Worktree.retire(kept, runner: dirty, root: context.worktrees)
    end
  end

  # ---------------------------------------------------------------- real git

  # The injected runner proves the argv; only a real `git` proves the argv is *right*.
  # This costs one process spawn and no inference, and it is the test that would have
  # caught an option `git` renamed under us.
  describe "against a real git" do
    setup context do
      if System.find_executable("git") do
        git = fn args -> System.cmd("git", args, cd: context.repo, stderr_to_stdout: true) end
        {_output, 0} = git.(["init", "--quiet", "-b", "main"])
        {_output, 0} = git.(["config", "user.email", "test@example.com"])
        {_output, 0} = git.(["config", "user.name", "Test"])
        File.write!(Path.join(context.repo, "a.txt"), "one\n")
        {_output, 0} = git.(["add", "a.txt"])
        {_output, 0} = git.(["commit", "--quiet", "-m", "first"])
        :ok
      else
        {:ok, skip: true}
      end
    end

    test "creates, contains, and removes a real worktree", context do
      if context[:skip] do
        :ok
      else
        {:ok, worktree} = Worktree.create(context.repo, "real-1", root: context.worktrees)

        assert File.regular?(Path.join(worktree.path, "a.txt"))
        assert byte_size(worktree.base_commit) == 40
        assert Ouroboros.Workspace.Path.within?(worktree.root, worktree.path)

        assert {:ok, :removed} = Worktree.remove(worktree, root: context.worktrees)
        refute File.dir?(worktree.path)
      end
    end

    test "refuses to remove a real worktree holding an untracked file", context do
      if context[:skip] do
        :ok
      else
        {:ok, worktree} = Worktree.create(context.repo, "real-2", root: context.worktrees)
        File.write!(Path.join(worktree.path, "scratch.txt"), "work in progress\n")

        assert {:ok, {:kept, :dirty}} = Worktree.remove(worktree, root: context.worktrees)
        assert File.regular?(Path.join(worktree.path, "scratch.txt"))

        # And reconcile leaves it exactly where it is.
        report = Worktree.reconcile(root: context.worktrees)
        assert [%{path: kept, reason: :dirty}] = report.kept
        assert kept == worktree.path
        assert File.regular?(Path.join(worktree.path, "scratch.txt"))
      end
    end

    test "refuses a directory that is not a repository at all", context do
      if context[:skip] do
        :ok
      else
        outside = Path.join(context.root, "not-a-repo")
        File.mkdir_p!(outside)

        assert {:error, {:not_a_git_repository, _path}} =
                 Worktree.create(outside, "real-3", root: context.worktrees)
      end
    end
  end

  # ---------------------------------------------------------------- helpers

  defp tag(path) do
    {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(path)

    :sha256
    |> :crypto.hash(canonical)
    |> Base.url_encode64(padding: false)
    |> binary_part(0, 16)
  end

  # A runner that records every `{argv, cwd}` and answers plausibly. `worktree add`
  # creates the directory the real git would, so the canonicalization and containment
  # checks downstream are exercised for real.
  defp recording_runner(context, opts \\ []) do
    {:ok, log} = Agent.start_link(fn -> [] end)
    toplevel = Keyword.get(opts, :toplevel, context.repo)
    status = Keyword.get(opts, :status, "")
    subdirs = Keyword.get(opts, :subdirs, [])

    runner = fn args, cwd ->
      Agent.update(log, &[{args, cwd} | &1])

      case args do
        ["rev-parse", "--show-toplevel"] ->
          {:ok, toplevel <> "\n"}

        ["rev-parse", "HEAD"] ->
          {:ok, "deadbeef\n"}

        ["status", "--porcelain"] ->
          {:ok, status}

        ["worktree", "add", "--detach", path, _commit] ->
          File.mkdir_p!(path)
          Enum.each(subdirs, &File.mkdir_p!(Path.join(path, &1)))
          {:ok, "Preparing worktree\n"}

        ["worktree", "remove", path] ->
          File.rm_rf!(path)
          {:ok, ""}

        _other ->
          {:ok, ""}
      end
    end

    {runner, log}
  end
end
