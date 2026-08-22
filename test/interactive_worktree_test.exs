defmodule Ouroboros.InteractiveWorktreeTest do
  @moduledoc """
  The interactive plane's D7 path, end to end, against a real `git`.

  The coding plane's twin lives in `test/coding_worktree_test.exs`. This one exists
  separately because the interactive plane does one thing the coding plane does not: it
  puts the retained-worktree fact on the session's *own* event log, in the same number
  space a client replays, and that is exactly the part that would silently rot.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager
  alias Ouroboros.Workspace.Worktree

  @provider :ouroboros_test

  setup do
    if System.find_executable("git") do
      cleanup_sessions()

      base =
        Path.join(
          System.tmp_dir!(),
          "ouroboros-interactive-worktree-#{System.unique_integer([:positive, :monotonic])}"
        )

      repo = Path.join(base, "repo")
      File.mkdir_p!(repo)
      File.mkdir_p!(Path.join(base, "worktrees"))
      init_repo(repo)

      start_supervised!(
        {Workspace,
         allowed_roots: [base],
         name: WorkspaceManager,
         id: {:interactive_worktree_manager, System.unique_integer([:positive, :monotonic])}}
      )

      previous = %{
        roots: Application.get_env(:ouroboros, :workspace_allowed_roots),
        data_dir: Application.get_env(:ouroboros, :data_dir),
        providers: Application.get_env(:jido_harness, :providers),
        provider_config: Application.get_env(:jido_harness, :provider_config)
      }

      journal_dir = Path.join(base, "journal")

      Application.put_env(:ouroboros, :workspace_allowed_roots, [base])
      Application.put_env(:ouroboros, :data_dir, base)

      Application.put_env(
        :jido_harness,
        :providers,
        Map.put(Map.new(previous.providers || %{}), @provider, HarnessAdapter)
      )

      Application.put_env(
        :jido_harness,
        :provider_config,
        previous.provider_config
        |> then(&Map.new(&1 || %{}))
        |> Map.put(@provider, %{test_pid: self(), retention: %{journal_dir: journal_dir}})
      )

      on_exit(fn ->
        cleanup_sessions()
        restore(:ouroboros, :workspace_allowed_roots, previous.roots)
        restore(:ouroboros, :data_dir, previous.data_dir)
        restore(:jido_harness, :providers, previous.providers)
        restore(:jido_harness, :provider_config, previous.provider_config)
        File.rm_rf(base)
      end)

      {:ok, base: base, repo: repo}
    else
      {:ok, skip: true}
    end
  end

  test "a session runs in its own worktree and the lease is taken on it", context do
    unless context[:skip] do
      id = unique_id("wt")

      assert {:ok, ref} =
               InteractiveSession.start(
                 id: id,
                 provider: @provider,
                 workspace: context.repo,
                 worktree: true
               )

      assert {:ok, %State{} = session} = InteractiveSession.info(ref)

      assert session.worktree_requested
      assert is_map(session.worktree)
      refute session.workspace == context.repo
      assert session.workspace == session.worktree["root"]
      assert File.regular?(Path.join(session.workspace, "a.txt"))

      assert [%{root: leased}] = Workspace.list()
      assert leased == session.workspace

      assert :ok = InteractiveSession.close(ref)
      assert_eventually(fn -> not File.dir?(session.worktree["path"]) end)
    end
  end

  test "a worktree holding uncommitted work is kept and said so on the session's log",
       context do
    unless context[:skip] do
      id = unique_id("dirty")

      assert {:ok, ref} =
               InteractiveSession.start(
                 id: id,
                 provider: @provider,
                 workspace: context.repo,
                 worktree: true
               )

      assert {:ok, %State{worktree: %{"path" => path}}} = InteractiveSession.info(ref)
      File.write!(Path.join(path, "scratch.txt"), "work in progress\n")

      assert :ok = InteractiveSession.close(ref)

      # The durable record outlives the coordinator, and it is what a client lists.
      assert_eventually(fn ->
        case Store.get(id) do
          {:ok, %State{worktree: %{"retired" => "kept"} = worktree} = closed} ->
            Enum.any?(closed.events, &(&1.type == :status)) and worktree["path"] == path

          _other ->
            false
        end
      end)

      {:ok, closed} = Store.get(id)

      assert closed.worktree["retained_reason"] == "uncommitted changes"
      assert File.regular?(Path.join(path, "scratch.txt"))

      retained =
        Enum.find(closed.events, fn event ->
          event.type == :status and payload(event, "kind") == "worktree_retained"
        end)

      assert retained,
             "no worktree_retained status event; got #{inspect(Enum.map(closed.events, & &1.type))}"

      assert payload(retained, "path") == path
      assert payload(retained, "reason") == "uncommitted changes"
      assert payload(retained, "message") =~ "git worktree remove"

      # And the marker still knows about it, so `reconcile/1` will report it after a boot.
      assert Worktree.find(path, root: Path.join(context.base, "worktrees"))
    end
  end

  test "without the option nothing is provisioned", context do
    unless context[:skip] do
      id = unique_id("bare")

      assert {:ok, ref} =
               InteractiveSession.start(id: id, provider: @provider, workspace: context.repo)

      assert {:ok, %State{worktree: nil, worktree_requested: false}} =
               InteractiveSession.info(ref)

      assert :ok = InteractiveSession.close(ref)
    end
  end

  # ---------------------------------------------------------------- helpers

  defp payload(event, key), do: Map.get(event.payload, key) || Map.get(event.payload, :"#{key}")

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

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  end

  defp assert_eventually(fun, attempts \\ 400)
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

  defp restore(app, key, nil), do: Application.delete_env(app, key)
  defp restore(app, key, value), do: Application.put_env(app, key, value)
end
