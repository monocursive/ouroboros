defmodule Ouroboros.ApplicationRecoveryTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Interactive.Ref
  alias Ouroboros.Interactive.State
  alias Ouroboros.Interactive.Task
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @provider :native

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

  setup context do
    cleanup_test_runs()

    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
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

    if context[:no_data_dir], do: Application.delete_env(:ouroboros, :data_dir)

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
      restore_env(:ouroboros, :data_dir, previous_data_dir)
      restore_env(:ouroboros, :workspace_allowed_roots, previous_roots)
      restore_env(:jido_harness, :providers, previous_providers)
      restore_env(:jido_harness, :provider_config, previous_provider_config)
      File.rm_rf(base)
      assert {:ok, _started} = Application.ensure_all_started(:ouroboros)
    end)

    {:ok, workspace: workspace}
  end

  @tag no_data_dir: true
  test "a node with no durable directory still starts the children behind its owner" do
    assert Application.get_env(:ouroboros, :data_dir) in [nil, ""]

    # The runtime boundary drops the owner of a directory this node does not have, and
    # nothing else. Model admission starts after the ledger, still without needing a data
    # directory.
    assert Process.whereis(Ouroboros.RuntimeOwner) == nil
    assert is_pid(Process.whereis(Ouroboros.Provider.Native.Model.Admission))
  end

  test "a killed interactive registry preserves workspace exclusion while sessions recover",
       %{workspace: workspace} do
    session_id = unique_id("registry-recovery-session")

    assert {:ok, %Ref{id: ^session_id} = ref} =
             InteractiveSession.start(
               id: session_id,
               provider: @provider,
               workspace: workspace,
               workspace_mode: :exclusive
             )

    assert {:ok, _turn} = InteractiveSession.send_message(ref, "survive the registry restart")

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{}, adapter}, 1_000

    root = Process.whereis(Ouroboros.Supervisor)
    registry = Process.whereis(Ouroboros.Interactive.Registry)
    task_supervisor = Process.whereis(Ouroboros.Interactive.TaskSupervisor)
    old_task = Task.whereis(session_id)
    registry_monitor = Process.monitor(registry)
    task_monitor = Process.monitor(old_task)

    Process.sleep(2_100)

    Process.exit(registry, :kill)
    assert_receive {:DOWN, ^registry_monitor, :process, ^registry, :killed}, 1_000
    assert_receive {:DOWN, ^task_monitor, :process, ^old_task, _reason}, 2_000

    # The old coordinator's release is converted to a reservation atomically because its
    # durable session is still nonterminal. No empty-authority window exists while the
    # downstream registry/supervisor subtree restarts.
    assert Enum.any?(
             Workspace.list(),
             &(&1.task_id == "interactive:" <> session_id and &1.mode == :exclusive)
           )

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(workspace, unique_id("registry-overlap"), mode: :exclusive)

    assert Enum.any?(conflicts, &(&1.task_id == "interactive:" <> session_id))

    replacement_registry =
      assert_eventually(fn -> replacement(Ouroboros.Interactive.Registry, registry) end)

    replacement_task_supervisor =
      assert_eventually(fn ->
        replacement(Ouroboros.Interactive.TaskSupervisor, task_supervisor)
      end)

    assert Process.alive?(root)
    assert Process.alive?(replacement_registry)
    assert Process.alive?(replacement_task_supervisor)
    assert Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ouroboros))

    replacement_task = assert_eventually(fn -> safe_task_replacement(session_id, old_task) end)
    assert Process.alive?(replacement_task)

    assert_eventually(fn ->
      match?({:ok, %State{}}, safe_info(ref))
    end)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reattached"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert :ok = InteractiveSession.kill(ref)
    assert_eventually(fn -> Workspace.list() == [] end)
  end

  test "workspace authority recovery restores the session and post-recovery exclusion", %{
    workspace: workspace
  } do
    session_id = unique_id("exclusive-session")

    assert {:ok, %Ref{id: ^session_id} = ref} =
             InteractiveSession.start(
               id: session_id,
               provider: @provider,
               workspace: workspace,
               workspace_mode: :exclusive
             )

    assert {:ok, _turn} =
             InteractiveSession.send_message(ref, "survive the workspace authority restart")

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{}, adapter}, 1_000

    before =
      assert_eventually(fn ->
        case InteractiveSession.info(ref) do
          {:ok, %State{workspace_lease_id: lease} = session} when is_binary(lease) -> session
          _other -> false
        end
      end)

    old_manager = Process.whereis(WorkspaceManager)
    old_task = Task.whereis(session_id)

    # Recovery deliberately ignores checkpoints younger than two seconds so a
    # just-created session cannot race its original coordinator during ordinary start.
    Process.sleep(2_100)

    manager_monitor = Process.monitor(old_manager)
    task_monitor = Process.monitor(old_task)
    Process.exit(old_manager, :kill)

    assert_receive {:DOWN, ^manager_monitor, :process, ^old_manager, :killed}, 1_000
    assert_receive {:DOWN, ^task_monitor, :process, ^old_task, :shutdown}, 2_000

    replacement_manager =
      assert_eventually(fn -> replacement(WorkspaceManager, old_manager) end)

    # The replacement authority reconstructs fail-closed reservations directly from
    # durable session checkpoints before it accepts any new caller.
    lease_key = "interactive:" <> session_id

    assert Enum.any?(Workspace.list(), &(&1.task_id == lease_key and &1.mode == :exclusive))

    assert {:error, {:workspace_conflict, immediate_conflicts}} =
             Workspace.acquire(workspace, unique_id("immediate-overlap"), mode: :exclusive)

    assert Enum.any?(immediate_conflicts, &(&1.task_id == lease_key))

    replacement_task = assert_eventually(fn -> safe_task_replacement(session_id, old_task) end)

    recovered =
      assert_eventually(fn ->
        case safe_info(ref) do
          {:ok, %State{workspace_lease_id: lease} = session}
          when is_binary(lease) and lease != before.workspace_lease_id ->
            session

          _other ->
            false
        end
      end)

    assert [%{task_id: ^lease_key, mode: :exclusive, id: recovered_lease_id}] = Workspace.list()
    assert recovered_lease_id == recovered.workspace_lease_id

    assert {:error, {:workspace_conflict, conflicts}} =
             Workspace.acquire(workspace, unique_id("overlapping-writer"), mode: :exclusive)

    assert Enum.any?(conflicts, &(&1.task_id == lease_key and &1.id == recovered_lease_id))

    assert Process.alive?(replacement_manager)
    assert Process.alive?(replacement_task)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "reattached"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert :ok = InteractiveSession.kill(ref)
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

  defp aged_timestamp,
    do: DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()

  defp safe_info(ref) do
    InteractiveSession.info(ref)
  rescue
    ArgumentError -> {:error, :registry_unavailable}
  catch
    :exit, _reason -> {:error, :owner_unavailable}
  end

  defp safe_task_replacement(session_id, old_task) do
    case Task.whereis(session_id) do
      task when is_pid(task) and task != old_task -> task
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
  end

  defp await_purged_terminal(plane, id, attempts \\ 200)

  defp await_purged_terminal(_plane, _id, 0),
    do: flunk("a leftover session never reached a terminal status under purge")

  defp await_purged_terminal(:interactive = plane, id, attempts) do
    {store, terminal?} =
      {Ouroboros.Interactive.Store, &Ouroboros.Interactive.State.terminal?/1}

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
