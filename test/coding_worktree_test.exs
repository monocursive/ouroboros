defmodule Ouroboros.CodingWorktreeTest do
  @moduledoc """
  The coding plane's D7 path, end to end, against a real `git`.

  `test/workspace_worktree_test.exs` proves the provisioner. This proves the *wiring*:
  that a `worktree: true` task is admitted on the worktree rather than the repository,
  that the request the provider receives carries the worktree as its `cwd`, and that the
  terminal transition removes a clean worktree and keeps a dirty one with the reason on
  the task's own log. Those three are the parts a unit test of the provisioner cannot see.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager
  alias Ouroboros.Workspace.Worktree

  @provider :ouroboros_test

  setup do
    if System.find_executable("git") do
      cleanup_test_runs()

      base =
        Path.join(
          System.tmp_dir!(),
          "ouroboros-coding-worktree-#{System.unique_integer([:positive, :monotonic])}"
        )

      repo = Path.join(base, "repo")
      worktrees = Path.join(base, "worktrees")
      File.mkdir_p!(repo)
      File.mkdir_p!(worktrees)
      init_repo(repo)

      start_supervised!(
        {Workspace,
         allowed_roots: [base],
         name: WorkspaceManager,
         id: {:coding_worktree_manager, System.unique_integer([:positive, :monotonic])}}
      )

      previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots)
      previous_data_dir = Application.get_env(:ouroboros, :data_dir)
      previous_providers = Application.get_env(:jido_harness, :providers)
      previous_provider_config = Application.get_env(:jido_harness, :provider_config)
      journal_dir = Path.join(base, "journal")

      # `admissible?/1` reads the same list the manager was started with, and the worktree
      # root has to be inside it — which is exactly the production requirement.
      Application.put_env(:ouroboros, :workspace_allowed_roots, [base])
      Application.put_env(:ouroboros, :data_dir, base)

      Application.put_env(
        :jido_harness,
        :providers,
        Map.put(empty_map_if_nil(previous_providers), @provider, HarnessAdapter)
      )

      Application.put_env(
        :jido_harness,
        :provider_config,
        previous_provider_config
        |> empty_map_if_nil()
        |> Map.put(@provider, %{test_pid: self(), retention: %{journal_dir: journal_dir}})
      )

      on_exit(fn ->
        cleanup_test_runs()
        restore(:ouroboros, :workspace_allowed_roots, previous_roots)
        restore(:ouroboros, :data_dir, previous_data_dir)
        restore(:jido_harness, :providers, previous_providers)
        restore(:jido_harness, :provider_config, previous_provider_config)
        File.rm_rf(base)
      end)

      {:ok, base: base, repo: repo, worktrees: worktrees}
    else
      {:ok, skip: true}
    end
  end

  test "a task runs in its own worktree and the provider is given it as cwd", context do
    unless context[:skip] do
      id = unique_id("worktree")
      {task_ref, _run_id, adapter, request} = start_controlled(id, context.repo)

      {:ok, task} = CodingSession.info(task_ref)

      assert task.worktree_requested
      assert is_map(task.worktree)
      assert task.worktree["base_commit"] != ""
      assert task.worktree["branch"] == nil
      refute task.workspace == context.repo
      assert task.workspace == task.worktree["root"]

      assert String.starts_with?(task.workspace, context.worktrees <> "/") or
               String.contains?(task.workspace, "/worktrees/")

      # The lease is on the worktree, not on the repository. That is the whole point:
      # a second task on the same repository would now find nothing to conflict with.
      assert [%{root: leased}] = Workspace.list()
      assert leased == task.workspace

      # The provider only ever sees `cwd`.
      assert request.cwd == task.workspace
      refute request.cwd == context.repo

      # And the worktree really is a checkout: the committed file is there.
      assert File.regular?(Path.join(task.workspace, "a.txt"))

      finish(task_ref, adapter)
    end
  end

  test "two tasks on one repository run side by side once each has a worktree", context do
    unless context[:skip] do
      first = unique_id("first")
      second = unique_id("second")

      {first_ref, _run_one, first_adapter, _one_request} = start_controlled(first, context.repo)

      {second_ref, _run_two, second_adapter, _two_request} =
        start_controlled(second, context.repo)

      {:ok, one} = CodingSession.info(first_ref)
      {:ok, two} = CodingSession.info(second_ref)

      refute one.workspace == two.workspace
      assert length(Workspace.list()) == 2

      finish(first_ref, first_adapter)
      finish(second_ref, second_adapter)
    end
  end

  test "without the option the task runs in the repository and keeps conflicting", context do
    unless context[:skip] do
      first = unique_id("bare-one")
      second = unique_id("bare-two")

      {first_ref, _run_id, adapter, _request} =
        start_controlled(first, context.repo, worktree: false)

      {:ok, task} = CodingSession.info(first_ref)

      assert task.worktree == nil
      assert task.workspace != nil

      assert {:error, {:workspace_admission_failed, {:workspace_conflict, _conflicts}}} =
               CodingSession.start("conflicting",
                 id: second,
                 provider: @provider,
                 workspace: context.repo
               )

      finish(first_ref, adapter)
    end
  end

  test "a clean worktree is removed when the task completes", context do
    unless context[:skip] do
      id = unique_id("clean")
      {task_ref, _run_id, adapter, _request} = start_controlled(id, context.repo)
      {:ok, running} = CodingSession.info(task_ref)
      path = running.worktree["path"]
      assert File.dir?(path)

      finish(task_ref, adapter)

      assert_eventually(fn -> not File.dir?(path) end)
      assert Worktree.find(path, root: Path.join(context.base, "worktrees")) == nil
    end
  end

  test "a worktree holding uncommitted work is kept, and the task's log says so", context do
    unless context[:skip] do
      id = unique_id("dirty")
      {task_ref, _run_id, adapter, _request} = start_controlled(id, context.repo)
      {:ok, running} = CodingSession.info(task_ref)
      path = running.worktree["path"]

      File.write!(Path.join(path, "scratch.txt"), "work in progress\n")

      assert {:ok, _backlog} = CodingSession.subscribe(task_ref)

      finish(task_ref, adapter)

      # The retention note is the last thing anyone learns about this task, so it reaches
      # the subscribers watching it rather than only the checkpoint.
      assert_receive {:ouroboros_coding_event, ^id, %{type: :worktree_retained}}, 2_000

      # Read the durable record rather than the coordinator: it retires itself shortly
      # after the terminal transition, and the checkpoint is what outlives it.
      {:ok, done} = Ouroboros.Coding.Store.get(id)
      assert File.regular?(Path.join(path, "scratch.txt"))
      assert done.worktree["retired"] == "kept"
      assert done.worktree["retained_reason"] == "uncommitted changes"

      retained = Enum.find(done.events, &(&1.type == :worktree_retained))

      assert retained,
             "no worktree_retained event; got #{inspect(Enum.map(done.events, & &1.type))}"

      assert retained.payload[:path] == path or retained.payload["path"] == path
    end
  end

  # ---------------------------------------------------------------- helpers

  defp init_repo(repo) do
    git = fn args -> System.cmd("git", args, cd: repo, stderr_to_stdout: true) end
    {_out, 0} = git.(["init", "--quiet", "-b", "main"])
    {_out, 0} = git.(["config", "user.email", "test@example.com"])
    {_out, 0} = git.(["config", "user.name", "Test"])
    File.write!(Path.join(repo, "a.txt"), "one\n")
    {_out, 0} = git.(["add", "a.txt"])
    {_out, 0} = git.(["commit", "--quiet", "-m", "first"])
    :ok
  end

  defp start_controlled(id, workspace, extra \\ [worktree: true]) do
    opts = Keyword.merge([id: id, provider: @provider, workspace: workspace], extra)

    assert {:ok, %TaskRef{id: ^id} = task_ref} = CodingSession.start("controlled task", opts)

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^id}} = request, adapter},
                   2_000

    assert_eventually(fn ->
      match?(
        {:ok, %TaskState{status: :running, harness_run_id: ^run_id}},
        CodingSession.info(task_ref)
      )
    end)

    {task_ref, run_id, adapter, request}
  end

  defp finish(task_ref, adapter) do
    :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 5_000)
  end

  defp cleanup_test_runs do
    @provider
    |> then(&Run.list(providers: [&1]))
    |> Enum.each(fn info ->
      unless RunInfo.terminal?(info) do
        _ = Run.cancel(info.run_id)
        _ = Run.await(info.run_id, 1_000)
      end

      _ = Run.prune(info.run_id)
    end)
  end

  defp assert_eventually(fun, attempts \\ 300)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      result when result in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      result ->
        result
    end
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore(app, key, nil), do: Application.delete_env(app, key)
  defp restore(app, key, value), do: Application.put_env(app, key, value)
end
