defmodule Ouroboros.TeamOwnershipTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Coding.{Store, TaskRef, TaskState}
  alias Ouroboros.CodingSession
  alias Ouroboros.Team
  alias Ouroboros.Team.Server
  alias Ouroboros.Team.Store, as: TeamStore
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

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

  test "an identical foreign preclaim is neither adopted nor cancelled" do
    team_id = unique_id("preclaim-team")
    worker_id = unique_id("preclaim-worker")
    delegation_id = unique_id("preclaim-delegation")
    objective = "an identical request is still foreign"
    coding_task_id = Ouroboros.Team.Snapshot.coding_task_id(team_id, delegation_id)
    team = start_team(team_id)

    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, %TaskRef{id: ^coding_task_id} = foreign_ref} =
             CodingSession.start(objective,
               id: coding_task_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    assert_receive {:ouroboros_test_adapter_started, foreign_run, %RunRequest{prompt: prompt},
                    foreign_adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, objective)

    assert {:error,
            {:delegation_setup_failed, :coding_start,
             {:coding_task_owner_conflict, ^coding_task_id}}} =
             Team.delegate(team, worker_id, objective,
               id: delegation_id,
               provider: @provider,
               workspace: File.cwd!()
             )

    refute_receive {:ouroboros_test_adapter_cancelled, ^foreign_run}, 100

    assert {:ok, %TaskState{origin_digest: nil}} = CodingSession.info(foreign_ref)
    assert {:ok, %TaskState{origin_digest: nil}} = Store.get(coding_task_id)

    assert :ok = HarnessAdapter.emit(foreign_adapter, :output_text_final, %{"text" => "foreign"})
    assert :ok = HarnessAdapter.finish(foreign_adapter)
    assert {:ok, %TaskState{status: :completed}} = CodingSession.await(foreign_ref, 2_000)

    assert {:ok, %{status: :failed, delivery: :delivered}} =
             Team.await(team, delegation_id, 2_000)

    assert :ok = Team.close(team)
  end

  test "canonical workspace identity and provenance survive admission without public leakage" do
    base =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-team-ownership-#{System.unique_integer([:positive, :monotonic])}"
      )

    allowed = Path.join(base, "allowed")
    canonical_input = Path.join(allowed, "canonical")
    workspace_alias = Path.join(allowed, "workspace-alias")
    File.mkdir_p!(canonical_input)
    File.ln_s!("canonical", workspace_alias)
    assert {:ok, canonical} = Ouroboros.Workspace.Path.canonicalize(canonical_input)
    on_exit(fn -> File.rm_rf(base) end)

    start_supervised!(
      {Workspace,
       allowed_roots: [allowed],
       name: WorkspaceManager,
       id: {:team_ownership_workspace, System.unique_integer([:positive, :monotonic])}}
    )

    team_id = unique_id("canonical-team")
    worker_id = unique_id("canonical-worker")
    delegation_id = unique_id("canonical-delegation")
    team = start_team(team_id)

    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    assert {:ok, %{task_ref: %TaskRef{id: coding_task_id} = task_ref}} =
             Team.delegate(team, worker_id, "use a canonical workspace identity",
               id: delegation_id,
               provider: @provider,
               workspace: workspace_alias
             )

    assert_receive {:ouroboros_test_adapter_started, _run_id,
                    %RunRequest{metadata: %{ouroboros_task_id: ^coding_task_id}}, adapter},
                   1_000

    assert {:ok, %TaskState{workspace: ^canonical, origin_digest: nil}} =
             CodingSession.info(task_ref)

    assert {:ok, %TaskState{workspace: ^canonical, origin_digest: digest}} =
             Store.get(coding_task_id)

    assert is_binary(digest) and byte_size(digest) == 64

    assert {:ok, snapshot} = TeamStore.get(team_id)
    assert snapshot.delegations[delegation_id].coding_options.origin_digest == digest
    refute Map.has_key?(Team.state(team).delegations[delegation_id], :coding_options)
    refute Map.has_key?(Team.state(team).delegations[delegation_id], :origin_digest)

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "canonical"})
    assert :ok = HarnessAdapter.finish(adapter)

    assert {:ok, %{status: :completed, delivery: :delivered}} =
             Team.await(team, delegation_id, 2_000)

    assert :ok = Team.close(team)
  end

  defp start_team(team_id) do
    start_supervised!(
      {Server, id: team_id, supervisor_id: {__MODULE__, team_id}, cleanup_agents: true}
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

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-team-ownership-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix),
    do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp empty_map_if_nil(nil), do: %{}
  defp empty_map_if_nil(value), do: Map.new(value)

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
