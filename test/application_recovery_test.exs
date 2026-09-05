defmodule Ouroboros.ApplicationRecoveryTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{Task, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Team
  alias Ouroboros.Team.{Snapshot, Store}
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @provider :ouroboros_test

  test "the model admission boundary owns every session that consumes its leases" do
    admission = Process.whereis(Ouroboros.Provider.Native.Model.Admission)
    ledger = Process.whereis(Ouroboros.Agent.EffectLedger)
    jido = Process.whereis(Ouroboros.Jido)

    assert is_pid(admission)
    assert is_pid(ledger)
    assert is_pid(jido)

    admission_monitor = Process.monitor(admission)
    ledger_monitor = Process.monitor(ledger)
    jido_monitor = Process.monitor(jido)
    Process.exit(admission, :kill)

    assert_receive {:DOWN, ^admission_monitor, :process, ^admission, :killed}, 1_000
    assert_receive {:DOWN, ^jido_monitor, :process, ^jido, _reason}, 2_000
    refute_receive {:DOWN, ^ledger_monitor, :process, ^ledger, _reason}, 300
    assert Process.alive?(ledger)
    assert Process.whereis(Ouroboros.Agent.EffectLedger) == ledger

    replacement_admission =
      assert_eventually(fn ->
        replacement(Ouroboros.Provider.Native.Model.Admission, admission)
      end)

    replacement_jido = assert_eventually(fn -> replacement(Ouroboros.Jido, jido) end)

    assert Process.alive?(replacement_admission)
    assert Process.alive?(replacement_jido)
  end

  test "the effect ledger owns the execution subtree beneath its durable boundary" do
    ledger = Process.whereis(Ouroboros.Agent.EffectLedger)
    jido = Process.whereis(Ouroboros.Jido)
    grants = Process.whereis(Ouroboros.Control.Grants)

    assert is_pid(ledger)
    assert is_pid(jido)
    assert is_pid(grants)

    ledger_monitor = Process.monitor(ledger)
    jido_monitor = Process.monitor(jido)
    grants_monitor = Process.monitor(grants)
    Process.exit(ledger, :kill)

    assert_receive {:DOWN, ^ledger_monitor, :process, ^ledger, :killed}, 1_000
    assert_receive {:DOWN, ^jido_monitor, :process, ^jido, _reason}, 2_000
    assert_receive {:DOWN, ^grants_monitor, :process, ^grants, _reason}, 2_000

    replacement_ledger =
      assert_eventually(fn -> replacement(Ouroboros.Agent.EffectLedger, ledger) end)

    replacement_jido = assert_eventually(fn -> replacement(Ouroboros.Jido, jido) end)

    replacement_grants =
      assert_eventually(fn -> replacement(Ouroboros.Control.Grants, grants) end)

    assert Process.alive?(replacement_ledger)
    assert Process.alive?(replacement_jido)
    assert Process.alive?(replacement_grants)
  end

  test "exhausting CodeIntel's restart budget leaves unrelated helpers and session owners alive" do
    code_intel = Process.whereis(Ouroboros.CodeIntel.Supervisor)

    unaffected = [
      Ouroboros.Wasm.Supervisor,
      Ouroboros.Provider.Native.Desktop.Supervisor,
      Ouroboros.Provider.Native.Mcp.Supervisor,
      Ouroboros.Interactive.TaskSupervisor
    ]

    before = Map.new(unaffected, &{&1, Process.whereis(&1)})
    assert Enum.all?(before, fn {_name, pid} -> is_pid(pid) end)

    for _attempt <- 1..11 do
      pool = Process.whereis(Ouroboros.CodeIntel.LspPool)
      assert is_pid(pool)
      Process.exit(pool, :kill)
      assert_eventually(fn -> replacement(Ouroboros.CodeIntel.LspPool, pool) end)
    end

    assert_eventually(fn -> replacement(Ouroboros.CodeIntel.Supervisor, code_intel) end)
    for {name, pid} <- before, do: assert(Process.whereis(name) == pid)
  end

  test "disabling automation retains coding and permission authorities" do
    previous = Application.get_env(:ouroboros, :automation_enabled)

    on_exit(fn ->
      :ok = Application.stop(:ouroboros)
      restore_env(:ouroboros, :automation_enabled, previous)
      {:ok, _} = Application.ensure_all_started(:ouroboros)
    end)

    :ok = Application.stop(:ouroboros)
    Application.put_env(:ouroboros, :automation_enabled, false)
    {:ok, _} = Application.ensure_all_started(:ouroboros)
    refute Process.whereis(Ouroboros.Orchestration.Scheduler)
    refute Process.whereis(Ouroboros.Control.Store)
    assert Process.whereis(Ouroboros.Coding.TaskSupervisor)
    assert Process.whereis(Ouroboros.Control.Permissions)
    assert Process.whereis(Ouroboros.Control.Grants)
    assert Ouroboros.status().availability.orchestration == :disabled
  end

  defmodule RefusingStorage do
    @moduledoc """
    A coding-task store that starts accepting writes and then refuses live ones.

    `{:error, :invalid_task_state}` is the store's own answer to a checkpoint it will not
    accept, and it is the one answer no amount of retrying can change. The gate it
    imitates makes the same exception for terminal tasks, which never build a request.
    """

    @tasks {__MODULE__, :tasks}
    @refuse {__MODULE__, :refuse}

    def reset do
      :persistent_term.put(@tasks, %{})
      :persistent_term.put(@refuse, false)
    end

    def refuse, do: :persistent_term.put(@refuse, true)

    def get_checkpoint(key, _opts),
      do: Map.get(:persistent_term.get(@tasks, %{}), key, :not_found)

    def put_checkpoint(key, tasks, _opts) do
      live? =
        Enum.any?(tasks, fn
          {_id, %TaskState{} = task} -> not TaskState.terminal?(task)
          _index -> false
        end)

      if :persistent_term.get(@refuse, false) and live? do
        {:error, :invalid_task_state}
      else
        :persistent_term.put(
          @tasks,
          Map.put(:persistent_term.get(@tasks, %{}), key, {:ok, tasks})
        )

        :ok
      end
    end
  end

  setup do
    cleanup_test_runs()

    previous_roots = Application.get_env(:ouroboros, :workspace_allowed_roots)
    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)

    base =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-application-recovery-#{System.unique_integer([:positive, :monotonic])}"
      )

    workspace = Path.join(base, "workspace")
    journal_dir = Path.join(base, "harness-journal")
    File.mkdir_p!(workspace)

    # The stores' tables outlive an :ouroboros restart on purpose, so a live session
    # record another test left behind — its workspace is that test's cwd, far outside the
    # root this module is about to restrict to — would make the restricted boot below
    # refuse the whole node over someone else's leftovers (the streaming suite hit the
    # same landmine and drives its own records terminal; this module cannot rely on every
    # predecessor doing so). Purged while the store processes are still up, because after
    # stop_application/0 there is nothing left to ask.
    purge_leftover_session_records()

    stop_application()
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace])

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous_provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    assert {:ok, _started} = Application.ensure_all_started(:ouroboros)

    on_exit(fn ->
      stop_application()
      cleanup_test_runs()
      restore_env(:ouroboros, :workspace_allowed_roots, previous_roots)
      restore_env(:jido_harness, :providers, previous_providers)
      restore_env(:jido_harness, :provider_config, previous_provider_config)
      File.rm_rf(base)
      assert {:ok, _started} = Application.ensure_all_started(:ouroboros)
    end)

    {:ok, workspace: workspace}
  end

  test "a node with no durable directory still starts the children behind its owner" do
    assert Application.get_env(:ouroboros, :data_dir) in [nil, ""]

    # The runtime boundary drops the owner of a directory this node does not have, and
    # nothing else: the provider cache behind it holds no durable state. Model admission
    # starts after the ledger, still without needing a data directory.
    assert Process.whereis(Ouroboros.RuntimeOwner) == nil
    assert is_pid(Process.whereis(Ouroboros.Provider.RuntimeCache))
    assert is_pid(Process.whereis(Ouroboros.Provider.Native.Model.Admission))
  end

  test "a killed coding registry preserves workspace exclusion while tasks recover", %{
    workspace: workspace
  } do
    task_id = unique_id("registry-recovery-task")

    assert {:ok, %TaskRef{id: ^task_id} = task_ref} =
             CodingSession.start("survive the coding registry restart",
               id: task_id,
               provider: @provider,
               workspace: workspace,
               workspace_mode: :exclusive
             )

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^task_id}}, adapter},
                   1_000

    root = Process.whereis(Ouroboros.Supervisor)
    registry = Process.whereis(Ouroboros.Coding.Registry)
    task_supervisor = Process.whereis(Ouroboros.Coding.TaskSupervisor)
    scheduler = Process.whereis(Ouroboros.Orchestration.Scheduler)
    old_task = Task.whereis(task_id)
    registry_monitor = Process.monitor(registry)
    task_monitor = Process.monitor(old_task)

    Process.sleep(2_100)

    Process.exit(registry, :kill)
    assert_receive {:DOWN, ^registry_monitor, :process, ^registry, :killed}, 1_000
    assert_receive {:DOWN, ^task_monitor, :process, ^old_task, _reason}, 2_000

    # The old coordinator's release is converted to a reservation atomically
    # because its durable task is still nonterminal. No empty-authority window
    # exists while the downstream registry/supervisor subtree restarts.
    assert Enum.any?(Workspace.list(), &(&1.task_id == task_id and &1.mode == :exclusive))

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(workspace, unique_id("registry-overlap"), mode: :exclusive)

    assert Enum.any?(conflicts, &(&1.task_id == task_id))

    replacement_registry =
      assert_eventually(fn -> replacement(Ouroboros.Coding.Registry, registry) end)

    replacement_task_supervisor =
      assert_eventually(fn -> replacement(Ouroboros.Coding.TaskSupervisor, task_supervisor) end)

    # A coding registry is authority for coding coordinators, not for automation.
    assert Process.whereis(Ouroboros.Orchestration.Scheduler) == scheduler

    assert Process.alive?(root)
    assert Process.alive?(replacement_registry)
    assert Process.alive?(replacement_task_supervisor)
    assert Process.alive?(scheduler)
    assert Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ouroboros))

    replacement_task = assert_eventually(fn -> safe_task_replacement(task_id, old_task) end)
    assert Process.alive?(replacement_task)

    assert_eventually(fn ->
      match?(
        {:ok, %TaskState{status: :running, harness_run_id: ^run_id}},
        safe_info(task_ref)
      )
    end)

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^task_id}}, _duplicate_adapter},
                   250

    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 2_000)
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "workspace authority recovery restores task, team, and post-recovery exclusion", %{
    workspace: workspace
  } do
    task_id = unique_id("exclusive-task")
    team_id = unique_id("active-team")
    worker_id = unique_id("active-worker")

    assert {:ok, %TaskRef{id: ^task_id} = task_ref} =
             CodingSession.start("survive the workspace authority restart",
               id: task_id,
               provider: @provider,
               workspace: workspace,
               workspace_mode: :exclusive
             )

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^task_id}}, adapter},
                   1_000

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    before =
      assert_eventually(fn ->
        case CodingSession.info(task_ref) do
          {:ok, %TaskState{status: :running, harness_run_id: ^run_id} = task} -> task
          _other -> false
        end
      end)

    old_manager = Process.whereis(WorkspaceManager)
    old_task = Task.whereis(task_id)
    old_team = Team.whereis(team_id)

    # Recovery deliberately ignores checkpoints younger than two seconds so a
    # just-created task cannot race its original coordinator during ordinary start.
    Process.sleep(2_100)

    manager_monitor = Process.monitor(old_manager)
    task_monitor = Process.monitor(old_task)
    team_monitor = Process.monitor(old_team)
    Process.exit(old_manager, :kill)

    assert_receive {:DOWN, ^manager_monitor, :process, ^old_manager, :killed}, 1_000
    assert_receive {:DOWN, ^task_monitor, :process, ^old_task, :shutdown}, 2_000
    assert_receive {:DOWN, ^team_monitor, :process, ^old_team, :shutdown}, 2_000

    replacement_manager =
      assert_eventually(fn -> replacement(WorkspaceManager, old_manager) end)

    # The replacement authority reconstructs fail-closed reservations directly
    # from durable task/session checkpoints before it accepts any new caller.
    assert Enum.any?(Workspace.list(), &(&1.task_id == task_id and &1.mode == :exclusive))

    assert {:error, {:workspace_conflict, immediate_conflicts}} =
             Workspace.acquire(workspace, unique_id("immediate-overlap"), mode: :exclusive)

    assert Enum.any?(immediate_conflicts, &(&1.task_id == task_id))

    replacement_task =
      assert_eventually(fn -> safe_task_replacement(task_id, old_task) end)

    replacement_team =
      assert_eventually(fn -> safe_team_replacement(team_id, old_team) end)

    recovered =
      assert_eventually(fn ->
        case safe_info(task_ref) do
          {:ok, %TaskState{status: :running, harness_run_id: ^run_id} = task} -> task
          _other -> false
        end
      end)

    assert recovered.workspace_lease_id != before.workspace_lease_id

    assert [%{task_id: ^task_id, mode: :exclusive, id: recovered_lease_id}] =
             Workspace.list()

    assert recovered_lease_id == recovered.workspace_lease_id

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(workspace, unique_id("overlapping-writer"), mode: :exclusive)

    assert Enum.any?(conflicts, &(&1.task_id == task_id and &1.id == recovered_lease_id))

    assert {:ok, %Snapshot{status: :active}} = Store.get(team_id)
    assert Team.state(replacement_team).status == :active
    assert Process.alive?(replacement_manager)
    assert Process.alive?(replacement_task)

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run,
                    %RunRequest{metadata: %{ouroboros_task_id: ^task_id}}, _duplicate_adapter},
                   250

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reattached"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(task_ref, 2_000)
    assert_eventually(fn -> Workspace.list() == [] end)
    assert :ok = Team.close(replacement_team)
  end

  test "a task this build cannot run fails alone while the node and its peers boot", %{
    workspace: workspace
  } do
    good_id = unique_id("loadable-task")
    bad_id = unique_id("version-skew-task")
    bad_workspace = Path.join(Path.dirname(workspace), "version-skew-workspace")
    File.mkdir_p!(bad_workspace)

    # The test is about request-format isolation, not two exclusive writers claiming
    # the same root. Keep both states admissible under the workspace-write default so
    # the intentionally unrequestable neighbour reaches its own failure boundary.
    Application.put_env(:ouroboros, :workspace_allowed_roots, [workspace, bad_workspace])

    profile =
      Ouroboros.AgentProfile.new!(id: "skewed-profile", base_prompt: "Act as a coding agent.")

    assert {:ok, good} =
             TaskState.new(good_id, "recover past a neighbour this build cannot run",
               provider: @provider,
               workspace: workspace
             )

    assert {:ok, bad} =
             TaskState.new(bad_id, "written by a newer prompt format",
               provider: @provider,
               workspace: bad_workspace,
               agent_profile: profile
             )

    # A trace stamped with a prompt format this build does not implement. It used to
    # fail `valid_tasks?/1` at load, stop the store, and take the whole `rest_for_one`
    # tree — every other task included — down with it.
    bad = %{bad | prompt_trace: Map.put(bad.prompt_trace, :version, 99)}

    checkpoint =
      Map.new([good, bad], fn task -> {task.id, %{task | updated_at: aged_timestamp()}} end)

    stop_application()

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(
               {:ouroboros, :coding_tasks, 1},
               checkpoint,
               table: :ouroboros_coding
             )

    assert {:ok, _started} = Application.ensure_all_started(:ouroboros)
    assert is_pid(Process.whereis(Ouroboros.Coding.Store))

    assert_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^good_id}}, adapter},
                   5_000

    failed =
      assert_eventually(fn ->
        case Ouroboros.Coding.Store.get(bad_id) do
          {:ok, %TaskState{status: :failed} = task} -> task
          _other -> false
        end
      end)

    assert failed.error ==
             {:unrequestable_task_state, {:unsupported_prompt_trace_version, 99}}

    assert Enum.any?(failed.events, &(&1.type == :task_start_failed))
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "recovered"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %TaskState{status: :completed}} =
             CodingSession.await(TaskRef.new(good_id), 2_000)

    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "an interactive session this build cannot run fails alone at adoption", %{
    workspace: workspace
  } do
    session_id = unique_id("version-skew-session")

    profile =
      Ouroboros.AgentProfile.new!(id: "skewed-session", base_prompt: "Act as a coding agent.")

    assert {:ok, session} =
             Ouroboros.Interactive.State.new(session_id,
               provider: @provider,
               workspace: workspace,
               agent_profile: profile
             )

    skewed = %{
      session
      | status: :idle,
        updated_at: aged_timestamp(),
        prompt_trace: Map.put(session.prompt_trace, :version, 99)
    }

    stop_application()

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(
               {:ouroboros, :interactive_sessions, 1},
               %{session_id => skewed},
               table: :ouroboros_interactive
             )

    assert {:ok, _started} = Application.ensure_all_started(:ouroboros)
    assert is_pid(Process.whereis(Ouroboros.Interactive.Store))

    failed =
      assert_eventually(fn ->
        case Ouroboros.Interactive.Store.get(session_id) do
          {:ok, %Ouroboros.Interactive.State{status: :failed} = state} -> state
          _other -> false
        end
      end)

    assert failed.error ==
             {:unrequestable_session_state, {:unsupported_prompt_trace_version, 99}}

    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "a permanently refused checkpoint ends the task instead of polling forever", %{
    workspace: workspace
  } do
    task_id = unique_id("refused-task")
    previous_storage = Application.get_env(:ouroboros, :coding_storage)
    on_exit(fn -> restore_env(:ouroboros, :coding_storage, previous_storage) end)

    stop_application()
    RefusingStorage.reset()
    Application.put_env(:ouroboros, :coding_storage, {RefusingStorage, []})
    assert {:ok, _started} = Application.ensure_all_started(:ouroboros)

    assert {:ok, %TaskRef{id: ^task_id} = task_ref} =
             CodingSession.start("refuse my next checkpoint",
               id: task_id,
               provider: @provider,
               workspace: workspace,
               workspace_mode: :exclusive
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^task_id}}, adapter},
                   1_000

    assert_eventually(fn ->
      Enum.any?(Workspace.list(), &(&1.task_id == task_id and &1.mode == :exclusive))
    end)

    waiter = Elixir.Task.async(fn -> CodingSession.await(task_ref, 5_000) end)

    # The store refuses this task from here on. Retrying cannot make a refused
    # checkpoint acceptable, so the task must end rather than poll forever with an
    # unanswered waiter and a held workspace.
    RefusingStorage.refuse()
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "refused"})

    assert {:ok, %TaskState{status: :failed, error: error}} =
             Elixir.Task.await(waiter, 5_000)

    assert error == {:unstorable_task_state, :rejected_by_store}
    assert {:ok, %TaskState{status: :failed}} = Ouroboros.Coding.Store.get(task_id)
    assert_eventually(fn -> Workspace.list() == [] end)
    assert :ok = HarnessAdapter.finish(adapter)
  end

  defp aged_timestamp,
    do: DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()

  defp safe_info(task_ref) do
    CodingSession.info(task_ref)
  rescue
    ArgumentError -> {:error, :registry_unavailable}
  catch
    :exit, _reason -> {:error, :owner_unavailable}
  end

  defp safe_task_replacement(task_id, old_task) do
    case Task.whereis(task_id) do
      task when is_pid(task) and task != old_task -> task
      _other -> false
    end
  rescue
    ArgumentError -> false
  end

  defp safe_team_replacement(team_id, old_team) do
    case Team.whereis(team_id) do
      team when is_pid(team) and team != old_team -> team
      _other -> false
    end
  rescue
    ArgumentError -> false
  end

  defp replacement(name, old_pid) do
    case Process.whereis(name) do
      pid when is_pid(pid) and pid != old_pid -> pid
      _other -> false
    end
  end

  defp cleanup_test_runs do
    Run.list(providers: [@provider])
    |> Enum.each(fn info ->
      unless RunInfo.terminal?(info) do
        _ = Run.cancel(info.run_id)
        _ = Run.await(info.run_id, 1_000)
      end

      _ = Run.prune(info.run_id)
    end)
  end

  defp stop_application do
    case Application.stop(:ouroboros) do
      :ok -> :ok
      {:error, {:not_started, :ouroboros}} -> :ok
    end
  end

  # Every record is deleted; a non-terminal one with a live coordinator is killed and
  # awaited first, because a coordinator checkpoints its terminal state and a delete that
  # raced that write would be re-inserted. A non-terminal record whose coordinator is
  # already gone has no writer left, so it is deleted as-is. Skipped entirely when the
  # application is down — the tables may hold records, but the restricted boot's recovery
  # is exactly what the tests below assert on, and with no store process there is no
  # seam to purge through.
  defp purge_leftover_session_records do
    if Process.whereis(Ouroboros.Interactive.Store) do
      Enum.each(Ouroboros.Interactive.Store.list(), fn session ->
        alive? = not is_nil(Ouroboros.Interactive.Task.whereis(session.id))

        if alive? and not Ouroboros.Interactive.State.terminal?(session) do
          _ = Ouroboros.InteractiveSession.kill(session.id)
          await_purged_terminal(:interactive, session.id)
        end

        _ = Ouroboros.Interactive.Store.delete(session.id)
      end)
    end

    if Process.whereis(Ouroboros.Coding.Store) do
      Enum.each(Ouroboros.Coding.Store.list(), fn task ->
        alive? = not is_nil(Ouroboros.Coding.Task.whereis(task.id))

        if alive? and not Ouroboros.Coding.TaskState.terminal?(task) do
          _ = Ouroboros.CodingSession.cancel(task.id)
          await_purged_terminal(:coding, task.id)
        end

        _ = Ouroboros.Coding.Store.delete(task.id)
      end)
    end
  end

  defp await_purged_terminal(plane, id, attempts \\ 200)

  defp await_purged_terminal(_plane, _id, 0),
    do: flunk("a leftover session never reached a terminal status under purge")

  defp await_purged_terminal(plane, id, attempts) do
    {store, terminal?} =
      case plane do
        :interactive -> {Ouroboros.Interactive.Store, &Ouroboros.Interactive.State.terminal?/1}
        :coding -> {Ouroboros.Coding.Store, &Ouroboros.Coding.TaskState.terminal?/1}
      end

    case store.get(id) do
      {:ok, record} ->
        if terminal?.(record) do
          :ok
        else
          Process.sleep(10)
          await_purged_terminal(plane, id, attempts - 1)
        end

      _other ->
        :ok
    end
  end

  defp assert_eventually(fun, attempts \\ 500)
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

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_env(application, key, nil), do: Application.delete_env(application, key)
  defp restore_env(application, key, value), do: Application.put_env(application, key, value)
end
