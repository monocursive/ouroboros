defmodule Ouroboros.TeamTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.Event
  alias Ouroboros.Coding.Task, as: CodingTask
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Team
  alias Ouroboros.Team.Server
  alias Ouroboros.Team.Store, as: TeamStore
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_test_runs()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
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
      restore_env(:providers, previous_providers)
      restore_env(:provider_config, previous_provider_config)
      File.rm_rf(journal_dir)
    end)

    :ok
  end

  test "start returns an explicit error without the application team supervisor" do
    unless Process.whereis(Ouroboros.Team.Supervisor) do
      assert {:error, {:team_supervisor_unavailable, Ouroboros.Team.Supervisor}} =
               Team.start(id: unique_id("unmanaged-team"))
    end
  end

  test "team IDs are registered atomically and cannot share a coordinator" do
    team_id = unique_id("unique-team")

    assert {:ok, first_team} = Team.start(id: team_id)

    on_exit(fn ->
      if Process.alive?(first_team) do
        _ = DynamicSupervisor.terminate_child(Ouroboros.Team.Supervisor, first_team)
      end
    end)

    assert {:error, {:already_started, ^first_team}} = Team.start(id: team_id)
    assert {:ok, ^first_team} = Team.start_or_get(id: team_id)
    assert Process.alive?(first_team)
    assert [{^first_team, _value}] = Registry.lookup(Ouroboros.Team.Registry, team_id)
  end

  test "a coordinator ID has one serialized team owner under concurrent starts" do
    coordinator_id = unique_id("shared-coordinator")
    team_ids = [unique_id("coordinator-team-a"), unique_id("coordinator-team-b")]
    parent = self()

    starters =
      Enum.map(team_ids, fn team_id ->
        Task.async(fn ->
          send(parent, {:coordinator_starter_ready, self()})

          receive do: (:start ->
                         {team_id, Team.start(id: team_id, coordinator_id: coordinator_id)})
        end)
      end)

    starter_pids = Enum.map(starters, & &1.pid)

    Enum.each(starter_pids, fn pid ->
      assert_receive {:coordinator_starter_ready, ^pid}, 1_000
    end)

    Enum.each(starter_pids, &send(&1, :start))
    results = Enum.map(starters, &Task.await(&1, 2_000))

    assert [{winner_id, {:ok, winner}}] =
             Enum.filter(results, fn {_team_id, result} -> match?({:ok, _pid}, result) end)

    assert [
             {loser_id,
              {:error,
               {:coordinator_owner_conflict, ^coordinator_id, ^winner_id, requested_owner}}}
           ] =
             Enum.reject(results, fn {_team_id, result} -> match?({:ok, _pid}, result) end)

    assert requested_owner == loser_id
    assert Team.whereis(loser_id) == nil
    assert Process.alive?(winner)

    assert {:ok, coordinator_state} = Team.coordinator_state(winner)
    assert coordinator_state.agent_module == Ouroboros.Agent.Coordinator
    assert coordinator_state.agent.state.team_id == winner_id

    assert {:ok, %{status: :closed}} = TeamStore.get(loser_id)

    assert :ok = Team.close(winner)
    assert_eventually(fn -> Ouroboros.Mesh.whereis(coordinator_id) == nil end)
    Process.sleep(1_100)
    assert Team.whereis(loser_id) == nil
  end

  test "a coordinator-only crash restarts and reconstructs its owning team" do
    team_id = unique_id("coordinator-recovery-team")
    worker_id = unique_id("coordinator-recovery-worker")
    second_worker_id = unique_id("coordinator-recovery-worker")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id, role: "reviewer")

    coordinator = Ouroboros.Mesh.whereis(team_id <> ":coordinator")
    assert is_pid(coordinator)
    team_monitor = Process.monitor(team)

    Process.exit(coordinator, :kill)

    assert_receive {:DOWN, ^team_monitor, :process, ^team, {:coordinator_down, :killed}}, 1_000

    assert_eventually(fn ->
      replacement = Team.whereis(team_id)
      recovered_coordinator = Ouroboros.Mesh.whereis(team_id <> ":coordinator")

      if is_pid(replacement) and replacement != team and is_pid(recovered_coordinator) and
           recovered_coordinator != coordinator do
        try do
          match?({:ok, _coordinator_state}, Team.coordinator_state(replacement))
        catch
          :exit, _reason -> false
        end
      else
        false
      end
    end)

    replacement = Team.whereis(team_id)
    recovered_coordinator = Ouroboros.Mesh.whereis(team_id <> ":coordinator")
    assert {:ok, coordinator_state} = Team.coordinator_state(replacement)

    assert Process.alive?(replacement)
    assert coordinator_state.agent.state.team_id == team_id
    assert coordinator_state.agent.state.workers[worker_id].role == "reviewer"
    assert recovered_coordinator == Ouroboros.Mesh.whereis(team_id <> ":coordinator")

    assert {:ok, %{id: ^second_worker_id}} = Team.add_worker(replacement, second_worker_id)
    assert :ok = Team.close(replacement)
  end

  test "rejects malformed keyword options without crashing the team" do
    team_id = unique_id("validated-team")
    worker_id = unique_id("validated-worker")

    assert {:error, :invalid_team_options} = Team.start([:not_a_keyword])

    team =
      start_supervised!(
        {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
      )

    assert {:error, :invalid_worker_options} =
             Team.add_worker(team, worker_id, [:not_a_keyword])

    assert {:error, {:unknown_worker_option, :typo}} =
             Team.add_worker(team, worker_id, typo: true)

    assert Process.alive?(team)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:error, :invalid_delegation} =
             Team.delegate(team, worker_id, "do not start", [:not_a_keyword])

    assert Process.alive?(team)
    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
  end

  test "one worker cannot own two undelivered delegations" do
    team_id = unique_id("busy-team")
    worker_id = unique_id("busy-worker")
    first_id = unique_id("first-delegation")
    second_id = unique_id("second-delegation")

    team =
      start_supervised!(
        {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
      )

    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok,
            %{
              id: ^first_id,
              task_ref: %{id: first_coding_task_id},
              delivery: :pending
            }} =
             Team.delegate(team, worker_id, "first objective",
               id: first_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^first_coding_task_id}},
                    first_adapter},
                   1_000

    assert {:error, {:worker_busy, ^worker_id, ^first_id}} =
             Team.delegate(team, worker_id, "second objective",
               id: second_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    refute_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{prompt: "second objective"}, _adapter},
                   100

    assert :ok = HarnessAdapter.emit(first_adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(first_adapter)
    assert {:ok, %{delivery: :delivered}} = Team.await(team, first_id, 2_000)
  end

  test "caller-supplied delegation IDs are idempotent and conflicting reuse fails" do
    team_id = unique_id("idempotent-team")
    worker_id = unique_id("idempotent-worker")
    delegation_id = unique_id("idempotent-delegation")

    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    opts = [id: delegation_id, provider: @provider, workspace: File.cwd!()]

    assert {:ok, first} = Team.delegate(team, worker_id, "same objective", opts)
    coding_task_id = first.task_ref.id

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, adapter},
                   1_000

    assert {:ok, second} = Team.delegate(team, worker_id, "same objective", opts)
    assert second.task_ref == first.task_ref
    assert second.request_fingerprint == first.request_fingerprint

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run_id, _request, _adapter}, 100

    assert {:error, {:delegation_id_conflict, ^delegation_id}} =
             Team.delegate(team, worker_id, "different objective", opts)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{result: %{run_id: ^run_id}, delivery: :delivered}} =
             Team.await(team, delegation_id, 2_000)
  end

  test "the same public delegation ID remains isolated between teams" do
    team_a_id = unique_id("isolated-team-a")
    team_b_id = unique_id("isolated-team-b")
    worker_a_id = unique_id("isolated-worker-a")
    worker_b_id = unique_id("isolated-worker-b")
    delegation_id = unique_id("shared-public-delegation")
    team_a = start_team(team_a_id)
    team_b = start_team(team_b_id)

    assert {:ok, _worker} = Team.add_worker(team_a, worker_a_id)
    assert {:ok, _worker} = Team.add_worker(team_b, worker_b_id)

    assert {:ok, delegation_a} =
             Team.delegate(team_a, worker_a_id, "objective owned by team A",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_a,
                    %RunRequest{prompt: "objective owned by team A"}, _adapter_a},
                   1_000

    assert {:ok, delegation_b} =
             Team.delegate(team_b, worker_b_id, "different objective owned by team B",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_b,
                    %RunRequest{prompt: "different objective owned by team B"}, adapter_b},
                   1_000

    assert delegation_a.id == delegation_id
    assert delegation_b.id == delegation_id
    refute delegation_a.task_ref == delegation_b.task_ref
    refute run_a == run_b

    assert :ok = Team.cancel(team_a, delegation_id)
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_a}, 1_000
    refute_receive {:ouroboros_test_adapter_cancelled, ^run_b}, 100

    assert :ok = HarnessAdapter.emit(adapter_b, :output_text_final, %{"text" => "team B"})
    assert :ok = HarnessAdapter.finish(adapter_b)

    assert {:ok, %{status: :cancelled, delivery: :delivered}} =
             Team.await(team_a, delegation_id, 2_000)

    assert {:ok, %{status: :completed, result: %{text: "team B"}, delivery: :delivered}} =
             Team.await(team_b, delegation_id, 2_000)

    assert :ok = Team.close(team_a)
    assert :ok = Team.close(team_b)
  end

  test "setup compensation never cancels a task that fails ownership verification" do
    team_id = unique_id("foreign-task-team")
    worker_id = unique_id("foreign-task-worker")
    delegation_id = unique_id("foreign-task-delegation")
    coding_task_id = Ouroboros.Team.Snapshot.coding_task_id(team_id, delegation_id)
    team = start_team(team_id)

    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, foreign_ref} =
             Ouroboros.CodingSession.start("foreign objective",
               id: coding_task_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, foreign_run,
                    %RunRequest{prompt: "foreign objective"}, foreign_adapter},
                   1_000

    assert {:error,
            {:delegation_setup_failed, :coding_start,
             {:coding_task_owner_conflict, ^coding_task_id}}} =
             Team.delegate(team, worker_id, "team objective",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    refute_receive {:ouroboros_test_adapter_cancelled, ^foreign_run}, 100
    assert :ok = HarnessAdapter.emit(foreign_adapter, :output_text_final, %{"text" => "foreign"})
    assert :ok = HarnessAdapter.finish(foreign_adapter)
    assert {:ok, %{status: :completed}} = Ouroboros.CodingSession.await(foreign_ref, 2_000)

    assert {:ok, %{status: :failed, delivery: :delivered}} =
             Team.await(team, delegation_id, 2_000)

    assert :ok = Team.close(team)
  end

  test "durable request identity rejects runtime authority and secret-bearing values" do
    team_id = unique_id("authority-team")
    worker_id = unique_id("authority-worker")
    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:error, :non_durable_delegation_options} =
             Team.delegate(team, worker_id, "unsafe pid",
               id: unique_id("authority-delegation"),
               provider: @provider,
               workspace: File.cwd!(),
               system_prompt: self()
             )

    assert {:error, :secret_bearing_delegation_options} =
             Team.delegate(team, worker_id, "unsafe secret",
               id: unique_id("secret-delegation"),
               provider: @provider,
               workspace: File.cwd!(),
               system_prompt: "Bearer do-not-checkpoint-this"
             )

    assert Team.state(team).delegations == %{}
    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
  end

  test "a delegated agent profile keeps the prompt identity of the identical local task" do
    team_id = unique_id("profile-team")
    worker_id = unique_id("profile-worker")
    delegation_id = unique_id("profile-delegation")
    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    profile = delegation_profile()
    objective = "profiled objective"

    delegation_options = [
      id: delegation_id,
      provider: @provider,
      workspace: File.cwd!(),
      system_prompt: "Keep explanations concise.",
      allowed_tools: ["read_file"],
      agent_profile: profile
    ]

    result = Team.delegate(team, worker_id, objective, delegation_options)

    # The profile struct used to reach `portable_request?/1`'s map clause, raise
    # `Protocol.UndefinedError`, and return an error term with the whole profile in it.
    refute inspect(result) =~ "careful coding agent"
    assert {:ok, delegation} = result

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{} = request, adapter},
                   1_000

    assert {:ok, local} =
             TaskState.new(
               delegation.task_ref.id,
               objective,
               Keyword.drop(delegation_options, [:id])
             )

    assert {:ok, remote} = Ouroboros.CodingSession.info(delegation.task_ref)
    assert remote.prompt_trace == local.prompt_trace
    assert remote.prompt_trace.profile_digest == local.prompt_trace.profile_digest
    assert request.system_prompt == local.options.system_prompt
    assert request.system_prompt =~ "<ouroboros-agent-profile"
    assert request.system_prompt =~ "Keep explanations concise."
    assert request.metadata.ouroboros_prompt == local.prompt_trace

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %{status: :completed}} = Team.await(team, delegation_id, 2_000)
  end

  test "delegation errors carry no profile or prompt text" do
    team_id = unique_id("profile-error-team")
    worker_id = unique_id("profile-error-worker")
    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    missing_workspace = Path.join(System.tmp_dir!(), unique_id("missing-profile-workspace"))

    for {options, expected} <- [
          {[workspace: missing_workspace], {:invalid_workspace, missing_workspace}},
          {[system_prompt: self()], :non_durable_delegation_options},
          {[system_prompt: "Bearer do-not-checkpoint-this"], :secret_bearing_delegation_options}
        ] do
      result =
        Team.delegate(
          team,
          worker_id,
          "profiled failure",
          Keyword.merge(
            [
              id: unique_id("profile-error-delegation"),
              provider: @provider,
              workspace: File.cwd!(),
              agent_profile: delegation_profile()
            ],
            options
          )
        )

      assert {:error, ^expected} = result
      refute inspect(result) =~ "careful coding agent"
      refute inspect(result) =~ "Read a workspace file"
    end

    assert Team.state(team).delegations == %{}
    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
  end

  defp delegation_profile do
    Ouroboros.AgentProfile.new!(
      id: "delegated-profile",
      base_prompt: "Act as a careful coding agent.",
      tools: [%{name: "read_file", description: "Read a workspace file."}]
    )
  end

  test "an active team process is replaced and resumes one detached run" do
    team_id = unique_id("recover-team")
    worker_id = unique_id("recover-worker")
    delegation_id = unique_id("recover-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, before_crash} =
             Team.delegate(team, worker_id, "survive a team crash",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    coding_task_id = before_crash.task_ref.id

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, adapter},
                   1_000

    # Model the narrow crash point after CodingSession accepted the stable ID but
    # before the team advanced its intent from :starting to :running.
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
    assert is_pid(replacement)
    assert Process.alive?(replacement)

    assert Team.state(replacement).delegations[delegation_id].task_ref ==
             before_crash.task_ref

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run_id, _request, _adapter}, 150

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "recovered"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok,
            %{
              result: %{run_id: ^run_id, text: "recovered"},
              delivery: :delivered
            }} = Team.await(replacement, delegation_id, 2_000)

    assert :ok = Team.close(replacement)
  end

  test "cancellation intent is durable and still reaches terminal delivery" do
    team_id = unique_id("cancel-team")
    worker_id = unique_id("cancel-worker")
    delegation_id = unique_id("cancel-delegation")

    team = start_team(team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _delegation} =
             Team.delegate(team, worker_id, "cancel me durably",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id, _request, _adapter}, 1_000
    assert :ok = Team.cancel(team, delegation_id)
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000

    assert {:ok, %{status: :cancelled, delivery: :delivered}} =
             Team.await(team, delegation_id, 2_000)

    assert {:ok, snapshot} = TeamStore.get(team_id)
    assert is_binary(snapshot.delegations[delegation_id].cancellation_requested_at)
    assert snapshot.delegations[delegation_id].delivery == :delivered
  end

  test "terminal delivery is recovered idempotently from its durable checkpoint" do
    team_id = unique_id("terminal-recover-team")
    worker_id = unique_id("terminal-recover-worker")
    delegation_id = unique_id("terminal-recover-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _delegation} =
             Team.delegate(team, worker_id, "recover terminal delivery",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id, _request, adapter}, 1_000
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "terminal"})
    assert :ok = HarnessAdapter.finish(adapter)
    assert {:ok, %{delivery: :delivered}} = Team.await(team, delegation_id, 2_000)

    assert {:ok, snapshot} = TeamStore.get(team_id)
    terminal = snapshot.delegations[delegation_id]

    assert :ok =
             TeamStore.put(%{
               snapshot
               | delegations:
                   Map.put(snapshot.delegations, delegation_id, %{
                     terminal
                     | delivery: :delivering
                   })
             })

    monitor = Process.monitor(team)
    Process.exit(team, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^team, :killed}, 1_000
    replacement = await_replacement(team_id, team)

    assert {:ok,
            %{
              result: %{run_id: ^run_id, text: "terminal"},
              delivery: :delivered
            }} = Team.await(replacement, delegation_id, 2_000)

    assert {:ok, recovered} = TeamStore.get(team_id)
    assert recovered.delegations[delegation_id].delivery == :delivered
    assert portable?(recovered)
    assert :ok = Team.close(replacement)
  end

  test "a checkpointed starting intent creates its stable coding task during recovery" do
    team_id = unique_id("intent-recover-team")
    worker_id = unique_id("intent-recover-worker")
    completed_id = unique_id("completed-delegation")
    recovered_id = unique_id("recovered-intent")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _delegation} =
             Team.delegate(team, worker_id, "recover an unstarted intent",
               id: completed_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id, _request, first_adapter}, 1_000
    assert :ok = HarnessAdapter.emit(first_adapter, :output_text_final, %{"text" => "first"})
    assert :ok = HarnessAdapter.finish(first_adapter)
    assert {:ok, %{delivery: :delivered}} = Team.await(team, completed_id, 2_000)

    assert {:ok, snapshot} = TeamStore.get(team_id)
    completed = snapshot.delegations[completed_id]
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    starting = %{
      completed
      | id: recovered_id,
        task_ref:
          Ouroboros.Coding.TaskRef.new(
            Ouroboros.Team.Snapshot.coding_task_id(team_id, recovered_id)
          ),
        status: :starting,
        cursor: 0,
        event_count: 0,
        last_event: nil,
        result: nil,
        error: nil,
        delivery: :pending,
        delivery_error: nil,
        cancellation_requested_at: nil,
        created_at: now,
        updated_at: now
    }

    assert :ok =
             TeamStore.put(%{
               snapshot
               | delegations: Map.put(snapshot.delegations, recovered_id, starting)
             })

    monitor = Process.monitor(team)
    Process.exit(team, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^team, :killed}, 1_000
    replacement = await_replacement(team_id, team)
    recovered_coding_task_id = Ouroboros.Team.Snapshot.coding_task_id(team_id, recovered_id)

    assert_receive {:ouroboros_test_adapter_started, recovered_run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^recovered_coding_task_id}},
                    adapter},
                   1_000

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run, _request, _adapter}, 100
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "resumed"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok,
            %{
              result: %{run_id: ^recovered_run_id, text: "resumed"},
              delivery: :delivered
            }} = Team.await(replacement, recovered_id, 2_000)

    assert :ok = Team.close(replacement)
  end

  test "explicit close checkpoints closure, cancels work, and is not restarted" do
    team_id = unique_id("temporary-team")
    worker_id = unique_id("temporary-worker")
    delegation_id = unique_id("temporary-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert Server.child_spec(id: team_id).restart == :transient
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, %{task_ref: %{id: coding_task_id}}} =
             Team.delegate(team, worker_id, "cancel with the team",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, _adapter},
                   1_000

    monitor = Process.monitor(team)
    assert :ok = Team.close(team)
    assert_receive {:DOWN, ^monitor, :process, ^team, :normal}, 1_000
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000
    assert_eventually(fn -> Registry.lookup(Ouroboros.Team.Registry, team_id) == [] end)

    assert {:ok, %{status: :closed}} = TeamStore.get(team_id)
    assert {:error, :team_closed} = Team.start_or_get(id: team_id)

    refute Enum.any?(DynamicSupervisor.which_children(Ouroboros.Team.Supervisor), fn
             {_id, pid, _type, _modules} -> pid == team
           end)
  end

  test "close intent survives a crash while cancellation is unavailable" do
    team_id = unique_id("recover-closing-team")
    worker_id = unique_id("recover-closing-worker")
    delegation_id = unique_id("recover-closing-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, %{task_ref: %{id: coding_task_id}}} =
             Team.delegate(team, worker_id, "cancel after close recovery",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id, _request, _adapter}, 1_000

    coding_task = CodingTask.whereis(coding_task_id)
    assert is_pid(coding_task)
    assert :ok = :sys.suspend(coding_task)

    try do
      assert :ok = Team.close(team)

      assert {:ok, closing_snapshot} = TeamStore.get(team_id)
      assert closing_snapshot.status == :closing
      assert is_binary(closing_snapshot.delegations[delegation_id].cancellation_requested_at)

      team_monitor = Process.monitor(team)
      Process.exit(team, :kill)
      assert_receive {:DOWN, ^team_monitor, :process, ^team, :killed}, 1_000

      replacement = await_replacement(team_id, team)
      assert Process.alive?(replacement)
      assert {:ok, %{status: :closing}} = TeamStore.get(team_id)

      assert :ok = :sys.resume(coding_task)
      assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000

      assert_eventually(fn ->
        match?(
          {:ok,
           %{
             status: :closed,
             delegations: %{
               ^delegation_id => %{status: :cancelled, delivery: :delivered}
             }
           }},
          TeamStore.get(team_id)
        )
      end)

      assert_eventually(fn -> Team.whereis(team_id) == nil end)
    after
      if Process.alive?(coding_task), do: :sys.resume(coding_task)
    end
  end

  test "closing recovery cancels a delegation checkpointed before coding startup finished" do
    team_id = unique_id("recover-starting-close-team")
    worker_id = unique_id("recover-starting-close-worker")
    delegation_id = unique_id("recover-starting-close-delegation")

    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, _delegation} =
             Team.delegate(team, worker_id, "cancel a recovered starting intent",
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id, _request, _adapter}, 1_000

    recovery = Process.whereis(Ouroboros.Team.Recovery)
    assert is_pid(recovery)
    assert :ok = :sys.suspend(recovery)

    try do
      team_monitor = Process.monitor(team)
      assert :ok = DynamicSupervisor.terminate_child(Ouroboros.Team.Supervisor, team)
      assert_receive {:DOWN, ^team_monitor, :process, ^team, :shutdown}, 1_000

      assert {:ok, snapshot} = TeamStore.get(team_id)
      requested_at = Ouroboros.Team.Snapshot.timestamp()
      delegation = snapshot.delegations[delegation_id]

      assert :ok =
               TeamStore.put(%{
                 snapshot
                 | status: :closing,
                   delegations:
                     Map.put(snapshot.delegations, delegation_id, %{
                       delegation
                       | status: :starting,
                         cancellation_requested_at: requested_at,
                         updated_at: requested_at
                     }),
                   updated_at: requested_at
               })

      assert {:ok, recovered_team} = Team.start(id: team_id)
      assert is_pid(recovered_team)
      assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 1_000

      assert_eventually(fn ->
        match?({:ok, %{status: :closed}}, TeamStore.get(team_id)) and
          Team.whereis(team_id) == nil
      end)
    after
      if Process.alive?(recovery), do: :sys.resume(recovery)
    end
  end

  test "coordinates a detached coding run and delivers its persisted result" do
    team_id = unique_id("team")
    worker_id = unique_id("worker")
    delegation_id = unique_id("delegation")
    objective = "inspect the repository and report the result"

    team =
      start_supervised!(
        {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
      )

    assert {:ok, %{id: ^worker_id, node: worker_node}} =
             Team.add_worker(team, worker_id, role: "reviewer")

    assert worker_node == node()
    assert Team.state(team).workers[worker_id].hierarchy == :jido_child

    assert {:ok, coordinator_after_add} = Team.coordinator_state(team)

    assert %Jido.AgentServer.ChildInfo{id: ^worker_id, pid: worker_pid} =
             coordinator_after_add.children[{:worker, worker_id}]

    assert worker_pid == Ouroboros.Mesh.whereis(worker_id)

    assert {:ok, worker_after_add} = Ouroboros.Mesh.state(worker_id)
    assert worker_after_add.parent.id == coordinator_after_add.id
    assert worker_after_add.parent.pid == Ouroboros.Mesh.whereis(coordinator_after_add.id)

    parent = self()

    caller =
      spawn(fn ->
        result =
          Team.delegate(team, worker_id, objective,
            id: delegation_id,
            provider: @provider,
            workspace: File.cwd!()
          )

        send(parent, {:delegated, self(), result})
      end)

    caller_monitor = Process.monitor(caller)

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: coding_task_id}} = request,
                    adapter},
                   1_000

    assert request.prompt == objective

    # This may land in the atomic subscription backlog or on the live path. The
    # cursor contract makes the distinction irrelevant and prevents loss/duplication.
    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "backlog"})

    assert_receive {:delegated, ^caller,
                    {:ok,
                     %{
                       id: ^delegation_id,
                       worker_id: ^worker_id,
                       task_ref: %{id: ^coding_task_id},
                       status: :running,
                       delivery: :pending
                     }}},
                   1_000

    assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :normal}, 1_000
    assert Process.alive?(team)
    assert Process.alive?(adapter)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_delta, %{"text" => "live"})
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "done"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok,
            %{
              id: ^delegation_id,
              status: :completed,
              delivery: :delivered,
              result: %{run_id: ^run_id, status: :completed, text: "done"}
            } = delegation} = Team.await(team, delegation_id, 2_000)

    assert delegation.event_count >= 4
    assert %Event{type: :run_completed, sequence: cursor} = delegation.last_event
    assert delegation.cursor == cursor

    state = Team.state(team)
    assert state.id == team_id
    assert state.host_restart_safe? == false
    assert state.process_restart_safe? == true
    assert state.durability == :ephemeral_checkpoint
    assert state.waiter_count == 0
    assert state.delegations[delegation_id].delivery == :delivered
    refute Map.has_key?(state, :coordinator_pid)
    refute Map.has_key?(state.workers[worker_id], :pid)

    assert {:ok, worker_server_state} = Ouroboros.Mesh.state(worker_id)
    worker = worker_server_state.agent
    assert worker.state.status == :completed
    assert worker.state.current_task == delegation_id
    assert worker.state.last_answer.status == :completed
    assert worker.state.last_answer.result.text == "done"

    assert {:ok, coordinator_server_state} = Team.coordinator_state(team)
    coordinator = coordinator_server_state.agent
    assert coordinator.state.team_id == team_id
    assert coordinator.state.workers[worker_id].role == "reviewer"
    assert coordinator.state.workers[worker_id].hierarchy == :jido_child
    assert coordinator.state.active_count == 0
    assert coordinator.state.terminal_count == 1

    assert coordinator.state.delegations[delegation_id] == %{
             id: delegation_id,
             worker_id: worker_id,
             objective: objective,
             coding_task_id: coding_task_id,
             coding_node: Atom.to_string(node()),
             status: :completed,
             result: delegation.result,
             error: nil
           }

    assert %{
             type: :task_finalized,
             delegation_id: ^delegation_id,
             status: :completed
           } = coordinator.state.last_event
  end

  test "compensates the worker when coding setup fails after assignment" do
    team_id = unique_id("team-compensation")
    worker_id = unique_id("worker-compensation")
    delegation_id = unique_id("delegation-compensation")
    missing_workspace = Path.join(System.tmp_dir!(), unique_id("missing"))

    team =
      start_supervised!(
        {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
      )

    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:error, {:invalid_workspace, ^missing_workspace}} =
             Team.delegate(team, worker_id, "fail safely",
               id: delegation_id,
               provider: @provider,
               workspace: missing_workspace
             )

    assert {:ok, worker_server_state} = Ouroboros.Mesh.state(worker_id)
    assert worker_server_state.agent.state.status == :idle
    assert worker_server_state.agent.state.last_answer == nil

    refute Map.has_key?(Team.state(team).delegations, delegation_id)
    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
  end

  test "delegates to a remote Mesh worker and coding session on a real peer" do
    ensure_distributed!()

    peer_name = String.to_atom("ouroboros_team_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    assert {:ok, peer, peer_node} =
             :peer.start(%{name: peer_name, args: args, wait_boot: 15_000})

    journal_dir = unique_journal_dir()
    on_exit(fn -> :peer.stop(peer) end)
    on_exit(fn -> File.rm_rf(journal_dir) end)

    storage = {Jido.Storage.ETS, table: peer_name}

    :ok = :erpc.call(peer_node, Application, :put_env, [:ouroboros, :coding_storage, storage])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :jido_harness,
        :providers,
        %{@provider => HarnessAdapter}
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :jido_harness,
        :provider_config,
        %{
          @provider => %{
            test_pid: self(),
            retention: %{journal_dir: journal_dir}
          }
        }
      ])

    assert {:ok, _applications} =
             :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])

    team_id = unique_id("distributed-team")
    worker_id = unique_id("distributed-worker")
    delegation_id = unique_id("distributed-delegation")
    objective = "perform a distributed review"

    supervisor_id = {__MODULE__, team_id}

    team =
      start_supervised!({Server, id: team_id, supervisor_id: supervisor_id, cleanup_agents: true})

    assert {:ok,
            %{
              id: ^worker_id,
              node: ^peer_node,
              pid: remote_worker,
              hierarchy: :mesh_remote
            }} = Team.add_worker(team, worker_id, node: peer_node, role: "remote reviewer")

    assert node(remote_worker) == peer_node
    assert remote_worker in Ouroboros.Mesh.members(worker_id)

    assert {:ok, remote_worker_state} = Ouroboros.Mesh.state(worker_id)
    assert remote_worker_state.parent == nil
    assert remote_worker_state.agent.state.parent_id == team_id <> ":coordinator"

    assert {:ok, coordinator_before_delegation} = Team.coordinator_state(team)
    refute Map.has_key?(coordinator_before_delegation.children, {:worker, worker_id})

    assert coordinator_before_delegation.agent.state.workers[worker_id].hierarchy ==
             :mesh_remote

    assert {:ok,
            %{
              id: ^delegation_id,
              task_ref: %{id: coding_task_id, node: ^peer_node},
              status: :running
            }} =
             Team.delegate(team, worker_id, objective,
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, adapter},
                   2_000

    assert node(adapter) == peer_node
    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "remote done"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok,
            %{
              status: :completed,
              delivery: :delivered,
              result: %{run_id: ^run_id, text: "remote done"}
            }} = Team.await(team, delegation_id, 3_000)

    assert {:ok, completed_worker_state} = Ouroboros.Mesh.state(worker_id)
    assert completed_worker_state.agent.state.status == :completed
    assert completed_worker_state.agent.state.last_answer.result.text == "remote done"

    assert Team.state(team).workers[worker_id].hierarchy == :mesh_remote

    assert :ok = Team.close(team)
    assert_eventually(fn -> Ouroboros.Mesh.whereis(worker_id) == nil end)
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

  defp start_team(team_id) do
    start_supervised!(
      {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
    )
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

  defp portable?(term) when is_pid(term) or is_port(term) or is_reference(term), do: false
  defp portable?(term) when is_function(term), do: false
  defp portable?(%_{} = struct), do: struct |> Map.from_struct() |> portable?()

  defp portable?(term) when is_map(term) do
    Enum.all?(term, fn {key, value} -> portable?(key) and portable?(value) end)
  end

  defp portable?(term) when is_list(term), do: Enum.all?(term, &portable?/1)
  defp portable?(term) when is_tuple(term), do: term |> Tuple.to_list() |> Enum.all?(&portable?/1)
  defp portable?(_term), do: true

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_team_root_#{System.unique_integer([:positive])}")
      assert {:ok, _pid} = :net_kernel.start([name, :shortnames])
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

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-team-test-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
