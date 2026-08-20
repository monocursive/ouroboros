defmodule Ouroboros.TeamReliabilityTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.Store, as: CodingStore
  alias Ouroboros.Coding.{TaskRef, TaskState}
  alias Ouroboros.Team
  alias Ouroboros.Team.Server
  alias Ouroboros.Team.Snapshot
  alias Ouroboros.Team.Store, as: TeamStore
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_test_runs()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    previous_start_retry = Application.get_env(:ouroboros, :delegation_start_retry_ms)
    journal_dir = unique_journal_dir()

    providers = Map.put(empty_map_if_nil(previous_providers), @provider, HarnessAdapter)

    provider_config =
      previous_provider_config
      |> empty_map_if_nil()
      |> Map.put(@provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })

    Application.put_env(:jido_harness, :providers, providers)
    Application.put_env(:jido_harness, :provider_config, provider_config)

    on_exit(fn ->
      cleanup_test_runs()
      restore_env(:jido_harness, :providers, previous_providers)
      restore_env(:jido_harness, :provider_config, previous_provider_config)
      restore_env(:ouroboros, :delegation_start_retry_ms, previous_start_retry)
      File.rm_rf(journal_dir)
    end)

    :ok
  end

  test "recovering a starting delegation degrades to polling instead of cancelling its run" do
    team_id = unique_id("resubscribe-team")
    worker_id = unique_id("resubscribe-worker")
    delegation_id = unique_id("resubscribe-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, delegation} =
             Team.delegate(team, worker_id, "survive a pruned cursor",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!(),
               event_limit: 1
             )

    coding_task_id = delegation.task_ref.id

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, adapter},
                   1_000

    # Freeze the live team so the checkpointed cursor cannot advance past the
    # floor the task is about to prune to.
    assert :ok = :sys.suspend(team)

    Enum.each(["one", "two", "three"], fn text ->
      assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => text})
    end)

    assert_eventually(fn ->
      match?(
        {:ok, %TaskState{event_floor: floor}} when floor > 0,
        CodingStore.get(coding_task_id)
      )
    end)

    # Model the same crash point as the recovery suite: intent checkpointed as
    # :starting with a cursor the task has since pruned away.
    assert {:ok, snapshot} = TeamStore.get(team_id)
    persisted = snapshot.delegations[delegation_id]

    assert :ok =
             TeamStore.put(%{
               snapshot
               | delegations:
                   Map.put(snapshot.delegations, delegation_id, %{
                     persisted
                     | status: :starting,
                       cursor: 0
                   })
             })

    monitor = Process.monitor(team)
    Process.exit(team, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^team, :killed}, 1_000

    replacement = await_replacement(team_id, team)

    assert_eventually(fn ->
      match?(
        %{status: :running, delivery_error: {:resubscribe_failed, {:cursor_pruned, _floor}}},
        Team.state(replacement).delegations[delegation_id]
      )
    end)

    refute_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 200
    assert Process.alive?(adapter)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "degraded"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok,
            %{
              status: :completed,
              result: %{run_id: ^run_id, text: "degraded"},
              delivery: :delivered
            }} = Team.await(replacement, delegation_id, 3_000)

    assert :ok = Team.close(replacement)
  end

  test "a runtime pid in a projection failure is sanitized before the checkpoint" do
    team_id = unique_id("sanitized-team")
    worker_id = unique_id("sanitized-worker")
    delegation_id = unique_id("sanitized-delegation")

    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    coordinator = Ouroboros.Mesh.whereis(team_id <> ":coordinator")
    assert is_pid(coordinator)
    assert :ok = :sys.suspend(coordinator)

    delegation =
      try do
        # A suspended coordinator makes `Jido.AgentServer.state/1` exit with a
        # reason carrying its PID, which the aggregate must never accept.
        assert {:ok, delegation} =
                 Team.delegate(team, worker_id, "sanitize a projection failure",
                   id: delegation_id,
                   provider: @provider,
                   workspace: File.cwd!()
                 )

        delegation
      after
        :sys.resume(coordinator)
      end

    assert delegation.status == :running

    assert {:projection_reconcile_failed,
            {:coordinator_owner_verification_failed, _coordinator_id, :exit,
             {:timeout, {GenServer, :call, [{:runtime_pid, runtime_node}, :get_state, _timeout]}}}} =
             delegation.delivery_error

    assert runtime_node == node()
    assert Process.alive?(team)

    assert {:ok, snapshot} = TeamStore.get(team_id)
    assert portable?(snapshot)
    assert snapshot.delegations[delegation_id].delivery_error == delegation.delivery_error

    assert_receive {:ouroboros_test_adapter_started, _run_id, _request, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "sanitized"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, delivery: :delivered}} =
             Team.await(team, delegation_id, 3_000)

    assert :ok = Team.close(team)
  end

  test "an unavailable coding owner is rejected before durable delegation intent" do
    team_id = unique_id("unavailable-team")
    worker_id = unique_id("unavailable-worker")
    delegation_id = unique_id("unavailable-delegation")
    coding_node = :"ouroboros-absent-owner@nowhere"

    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:error, {:invalid_coding_node, ^coding_node, :node_not_connected}} =
             Team.delegate(team, worker_id, "start against an unreachable owner",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!(),
               coding_node: coding_node
             )

    assert {:ok, snapshot} = TeamStore.get(team_id)
    refute Map.has_key?(snapshot.delegations, delegation_id)
    refute Map.has_key?(Team.state(team).delegations, delegation_id)
    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
    assert :ok = Team.close(team)
  end

  test "a repeated completion-check failure backs off without recheckpointing the aggregate" do
    team_id = unique_id("backoff-team")
    worker_id = unique_id("backoff-worker")
    delivered_id = unique_id("backoff-delivered")
    orphan_id = unique_id("backoff-orphan")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _delegation} =
             Team.delegate(team, worker_id, "deliver before the orphan is injected",
               id: delivered_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id, _request, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "delivered"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %{delivery: :delivered}} = Team.await(team, delivered_id, 2_000)

    assert {:ok, snapshot} = TeamStore.get(team_id)
    now = Snapshot.timestamp()

    orphan = %{
      snapshot.delegations[delivered_id]
      | id: orphan_id,
        task_ref: TaskRef.new(Snapshot.coding_task_id(team_id, orphan_id)),
        status: :running,
        cursor: 0,
        event_count: 0,
        last_event: nil,
        result: nil,
        error: nil,
        delivery: :pending,
        delivery_error: nil,
        created_at: now,
        updated_at: now
    }

    assert :ok =
             TeamStore.put(%{
               snapshot
               | delegations: Map.put(snapshot.delegations, orphan_id, orphan)
             })

    monitor = Process.monitor(team)
    Process.exit(team, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^team, :killed}, 1_000
    replacement = await_replacement(team_id, team)

    assert_eventually(fn ->
      match?(
        %{
          status: :running,
          delivery_error: {:completion_check_failed, {:coding_task_not_found, _}}
        },
        Team.state(replacement).delegations[orphan_id]
      )
    end)

    assert {:ok, settled} = TeamStore.get(team_id)
    Process.sleep(500)
    assert {:ok, later} = TeamStore.get(team_id)

    # An unchanged error term is not durable news: the aggregate must not be
    # rewritten once per retry while the failure persists.
    assert later.updated_at == settled.updated_at
    assert later.delegations[orphan_id].status == :running

    assert :ok = DynamicSupervisor.terminate_child(Ouroboros.Team.Supervisor, replacement)
    assert :ok = TeamStore.put(%{later | status: :closed, updated_at: Snapshot.timestamp()})
  end

  test "durability is reported per adapter and only a synced adapter claims host safety" do
    root = unique_dir("durability")
    on_exit(fn -> File.rm_rf(root) end)

    synced =
      start_store(:synced, {Ouroboros.Storage.DurableFile, path: Path.join(root, "synced")})

    unsynced = start_store(:unsynced, {Jido.Storage.File, path: Path.join(root, "unsynced")})

    assert TeamStore.durability(synced) == :synced_checkpoint
    assert TeamStore.durability(unsynced) == :durable_checkpoint

    synced_team = start_team(unique_id("synced-team"), store: synced)
    unsynced_team = start_team(unique_id("unsynced-team"), store: unsynced)

    assert %{
             durability: :synced_checkpoint,
             host_restart_safe?: true,
             process_restart_safe?: true
           } =
             Team.state(synced_team)

    assert %{durability: :durable_checkpoint, host_restart_safe?: false} =
             Team.state(unsynced_team)

    assert :ok = Team.close(synced_team)
    assert :ok = Team.close(unsynced_team)
  end

  defp start_store(label, storage) do
    name = String.to_atom("ouroboros_reliability_store_#{label}_#{unique_integer()}")

    start_supervised!(Supervisor.child_spec({TeamStore, name: name, storage: storage}, id: name))

    name
  end

  defp start_team(team_id, opts \\ []) do
    start_supervised!(
      {Server,
       Keyword.merge(
         [id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true],
         opts
       )}
    )
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

  defp await_replacement(team_id, previous, attempts \\ 200)
  defp await_replacement(_team_id, _previous, 0), do: flunk("team was not replaced")

  defp await_replacement(team_id, previous, attempts) do
    case Team.whereis(team_id) do
      pid when is_pid(pid) and pid != previous ->
        pid

      _other ->
        Process.sleep(10)
        await_replacement(team_id, previous, attempts - 1)
    end
  end

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end

  defp portable?(term) when is_pid(term) or is_port(term) or is_reference(term), do: false
  defp portable?(term) when is_function(term), do: false
  defp portable?(%_{} = struct), do: struct |> Map.from_struct() |> portable?()

  defp portable?(term) when is_map(term) do
    Enum.all?(term, fn {key, value} -> portable?(key) and portable?(value) end)
  end

  defp portable?(term) when is_list(term), do: Enum.all?(term, &portable?/1)
  defp portable?(term) when is_tuple(term), do: term |> Tuple.to_list() |> Enum.all?(&portable?/1)
  defp portable?(_term), do: true

  defp unique_journal_dir, do: unique_dir("journal")

  defp unique_dir(prefix),
    do: Path.join(System.tmp_dir!(), "ouroboros-team-reliability-#{prefix}-#{unique_integer()}")

  defp unique_id(prefix), do: "#{prefix}-#{unique_integer()}"

  defp unique_integer, do: System.unique_integer([:positive, :monotonic])

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(app, key, nil), do: Application.delete_env(app, key)
  defp restore_env(app, key, value), do: Application.put_env(app, key, value)
end
