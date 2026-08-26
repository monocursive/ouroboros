defmodule Ouroboros.Orchestration.TeamExecutorTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.{Run, RunInfo, RunRequest}
  alias Ouroboros.Orchestration.{Execution, Plan, Scheduler, Store, TeamExecutor}
  alias Ouroboros.Team
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test

  setup do
    cleanup_test_runs()
    old_providers = Application.get_env(:jido_harness, :providers)
    old_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(Map.new(old_providers || %{}), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(Map.new(old_config || %{}), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    team_id = unique_id("graph-team")
    worker_id = unique_id("graph-worker")
    assert {:ok, team} = Team.start(id: team_id)
    assert {:ok, _worker} = Team.add_worker(team, worker_id)

    suffix = System.unique_integer([:positive, :monotonic])
    store = String.to_atom("team_executor_store_#{suffix}")
    scheduler = String.to_atom("team_executor_scheduler_#{suffix}")

    start_supervised!(
      {Store,
       name: store,
       storage: {Jido.Storage.ETS, table: String.to_atom("team_executor_table_#{suffix}")},
       key: {:team_executor_test, suffix}}
    )

    context = %{scheduler: scheduler, store: store, team_id: team_id, worker_id: worker_id}
    start_scheduler(context)

    on_exit(fn ->
      case Team.whereis(team_id) do
        current when is_pid(current) -> Team.close(current)
        nil -> :ok
      end

      cleanup_test_runs()
      restore_env(:providers, old_providers)
      restore_env(:provider_config, old_config)
      File.rm_rf(journal_dir)
    end)

    {:ok, team: team, team_id: team_id, worker_id: worker_id, scheduler: scheduler, store: store}
  end

  defp start_scheduler(context) do
    start_supervised!(
      {Scheduler,
       name: context.scheduler,
       store: context.store,
       max_concurrency: 1,
       executor:
         {TeamExecutor,
          team_id: context.team_id,
          worker_id: context.worker_id,
          team_cancel_timeout_ms: 300,
          team_retry_backoff_ms: 10,
          team_retry_max_backoff_ms: 50}},
      restart: :temporary
    )
  end

  # The delegation a step owns, whichever attempt is offering it.
  defp delegation_id(plan_id, step_id), do: "orchestration:" <> plan_id <> ":" <> step_id

  test "runs a dependency chain through one team worker without duplicate delegations", context do
    assert {:ok, plan} =
             Plan.new(unique_id("team-plan"), [
               %{
                 id: "inspect",
                 input: %{
                   objective: "inspect the repository",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               },
               %{
                 id: "explain",
                 dependencies: ["inspect"],
                 input: %{
                   objective: "explain the result",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _running} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, first_run, %RunRequest{prompt: first_prompt},
                    first_adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(first_prompt, "inspect the repository")

    assert :ok = HarnessAdapter.emit(first_adapter, :output_text_final, %{"text" => "inspected"})
    assert :ok = HarnessAdapter.finish(first_adapter)

    assert_receive {:ouroboros_test_adapter_started, second_run,
                    %RunRequest{prompt: second_prompt}, second_adapter},
                   2_000

    assert Ouroboros.Test.Prompt.wrapped?(second_prompt, "explain the result")

    assert first_run != second_run
    assert :ok = HarnessAdapter.emit(second_adapter, :output_text_final, %{"text" => "explained"})
    assert :ok = HarnessAdapter.finish(second_adapter)

    completed =
      assert_eventually(fn ->
        case Scheduler.get(context.scheduler, plan.id) do
          {:ok, %{status: :completed} = completed} -> completed
          _other -> false
        end
      end)

    assert completed.steps["inspect"].result.delegation.result.text == "inspected"
    assert completed.steps["explain"].result.delegation.result.text == "explained"

    state = Team.state(context.team)
    assert map_size(state.delegations) == 2

    assert Enum.all?(state.delegations, fn {_id, delegation} ->
             delegation.delivery == :delivered
           end)
  end

  test "plan cancellation reaches the detached provider task", context do
    assert {:ok, plan} =
             Plan.new(unique_id("cancel-plan"), [
               %{
                 id: "long",
                 input: %{
                   objective: "keep running",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, run_id, %RunRequest{prompt: prompt},
                    _adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, "keep running")

    assert {:ok, %{status: :cancelled}} = Scheduler.cancel(context.scheduler, plan.id, :user_stop)
    assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 2_000

    assert_eventually(fn ->
      {:ok, current} = Scheduler.get(context.scheduler, plan.id)
      get_in(current.steps, ["long", Access.key(:cancellation), :status]) == :completed
    end)
  end

  test "cancellation follows the stable delegation through a team restart", context do
    assert {:ok, plan} =
             Plan.new(unique_id("restart-cancel-plan"), [
               %{
                 id: "long",
                 input: %{
                   objective: "cancel after the coordinator restarts",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, run_id, %RunRequest{prompt: prompt},
                    _adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, "cancel after the coordinator restarts")

    delegation_id = delegation_id(plan.id, "long")

    with_suspended_team_recovery(fn ->
      old_team = stop_team(context.team_id)

      assert {:ok, %{status: :cancelled}} =
               Scheduler.cancel(context.scheduler, plan.id, :restart_during_cancel)

      Process.sleep(50)
      assert Team.whereis(context.team_id) == nil
      assert {:ok, restarted_team} = Team.start(id: context.team_id)

      assert_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 2_000

      assert restarted_team != old_team

      cancellation =
        assert_eventually(fn ->
          {:ok, current} = Scheduler.get(context.scheduler, plan.id)

          case current.steps["long"].cancellation do
            %{status: :completed} = cancellation -> cancellation
            _other -> false
          end
        end)

      assert cancellation.outcome == :ok

      assert Team.state(restarted_team).delegations[delegation_id].cancellation_requested_at !=
               nil
    end)
  end

  test "unavailable team records cancellation as unconfirmed before scheduler timeout", context do
    assert {:ok, plan} =
             Plan.new(unique_id("unconfirmed-cancel-plan"), [
               %{
                 id: "long",
                 input: %{
                   objective: "remain active while cancellation is unconfirmed",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, run_id, %RunRequest{prompt: prompt},
                    adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(
             prompt,
             "remain active while cancellation is unconfirmed"
           )

    with_suspended_team_recovery(fn ->
      _old_team = stop_team(context.team_id)

      assert {:ok, %{status: :cancelled}} =
               Scheduler.cancel(context.scheduler, plan.id, :team_unavailable)

      cancellation =
        assert_eventually(fn ->
          {:ok, current} = Scheduler.get(context.scheduler, plan.id)

          case current.steps["long"].cancellation do
            %{status: :completed} = cancellation -> cancellation
            _other -> false
          end
        end)

      assert cancellation.outcome ==
               {:error, {:provider_cancellation_unconfirmed, :timeout}}

      assert {:ok, info} = Run.info(run_id)
      refute RunInfo.terminal?(info)
      refute_receive {:ouroboros_test_adapter_cancelled, ^run_id}, 100

      assert {:ok, _restarted_team} = Team.start(id: context.team_id)
      assert :ok = HarnessAdapter.finish(adapter)
    end)
  end

  test "reattaches to the same delegation after the team server restarts", context do
    assert {:ok, plan} =
             Plan.new(unique_id("restart-plan"), [
               %{
                 id: "survive",
                 input: %{
                   objective: "survive the coordinator restart",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _running} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{prompt: prompt},
                    adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, "survive the coordinator restart")

    delegation_id = delegation_id(plan.id, "survive")

    old_team = Team.whereis(context.team_id)
    monitor = Process.monitor(old_team)
    Process.exit(old_team, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^old_team, :killed}, 1_000

    restarted_team =
      assert_eventually(fn ->
        case Team.whereis(context.team_id) do
          team when is_pid(team) and team != old_team -> team
          _other -> false
        end
      end)

    recovered =
      assert_eventually(fn ->
        state = Team.state(restarted_team)

        case state.delegations[delegation_id] do
          %{status: :running} = delegation -> delegation
          _other -> false
        end
      end)

    assert recovered.id == delegation_id

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "survived"})
    assert :ok = HarnessAdapter.finish(adapter)

    completed =
      assert_eventually(fn ->
        case Scheduler.get(context.scheduler, plan.id) do
          {:ok, %{status: :completed} = completed} -> completed
          _other -> false
        end
      end)

    assert completed.steps["survive"].result.delegation.id == delegation_id
    assert completed.steps["survive"].result.delegation.result.text == "survived"
    assert completed.steps["survive"].attempt == 1
    assert map_size(Team.state(restarted_team).delegations) == 1

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run, _request, _adapter}, 250
  end

  test "a scheduler restart reattaches to the delegation rather than starting a second run",
       context do
    assert {:ok, plan} =
             Plan.new(unique_id("scheduler-restart-plan"), [
               %{
                 id: "survive",
                 input: %{
                   objective: "survive the scheduler restart",
                   options: [provider: @provider, workspace: File.cwd!()]
                 }
               }
             ])

    assert {:ok, _running} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:ouroboros_test_adapter_started, _run_id, %RunRequest{prompt: prompt},
                    adapter},
                   1_000

    assert Ouroboros.Test.Prompt.wrapped?(prompt, "survive the scheduler restart")

    {:ok, running} = Scheduler.get(context.scheduler, plan.id)
    first_token = running.steps["survive"].execution_token

    old_scheduler = Process.whereis(context.scheduler)
    Process.unlink(old_scheduler)
    Process.exit(old_scheduler, :kill)
    assert_eventually(fn -> Process.whereis(context.scheduler) == nil end)
    start_scheduler(context)

    # A new attempt with a new token, delegated under the step's own identity — so the
    # team answers with the delegation that is already running, not a second one.
    assert_eventually(fn ->
      case Scheduler.get(context.scheduler, plan.id) do
        {:ok, %{steps: %{"survive" => %{state: :running, execution_token: token}}}} ->
          is_binary(token) and token != first_token

        _other ->
          false
      end
    end)

    refute_receive {:ouroboros_test_adapter_started, _duplicate_run, _request, _adapter}, 250

    assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "survived"})
    assert :ok = HarnessAdapter.finish(adapter)

    completed =
      assert_eventually(fn ->
        case Scheduler.get(context.scheduler, plan.id) do
          {:ok, %{status: :completed} = completed} -> completed
          _other -> false
        end
      end)

    assert completed.steps["survive"].result.delegation.id ==
             delegation_id(plan.id, "survive")

    assert completed.steps["survive"].attempt == 2
    assert map_size(Team.state(context.team).delegations) == 1
  end

  test "distinguishes missing, closed, and permanent delegation failures", context do
    execution = %Execution{
      plan_id: unique_id("classification-plan"),
      step_id: "classify",
      token: unique_id("classification-token"),
      input: %{
        objective: "classify the team failure",
        options: [provider: @provider, workspace: File.cwd!()]
      },
      attempt: 1,
      state: :running,
      metadata: %{}
    }

    retry_opts = [
      team_retry_attempts: 0,
      team_retry_backoff_ms: 0,
      team_retry_max_backoff_ms: 0
    ]

    missing_team_id = unique_id("missing-team")

    assert {:error, {:team_not_found, ^missing_team_id}} =
             TeamExecutor.start(
               execution,
               context.scheduler,
               [team_id: missing_team_id, worker_id: context.worker_id] ++ retry_opts
             )

    closed_team_id = unique_id("closed-team")
    assert {:ok, closed_team} = Team.start(id: closed_team_id)
    assert :ok = Team.close(closed_team)
    assert_eventually(fn -> Team.whereis(closed_team_id) == nil end)

    assert {:error, {:team_closed, ^closed_team_id}} =
             TeamExecutor.start(
               execution,
               context.scheduler,
               [team_id: closed_team_id, worker_id: context.worker_id] ++ retry_opts
             )

    closing_team_id = unique_id("closing-team")
    assert {:ok, closing_team} = Team.start(id: closing_team_id)

    with_suspended_team_recovery(fn ->
      assert {:ok, closing_snapshot} = Ouroboros.Team.Store.get(closing_team_id)
      assert :ok = Ouroboros.Team.Store.put(%{closing_snapshot | status: :closing})
      assert ^closing_team = stop_team(closing_team_id)

      assert {:error, {:team_closing, ^closing_team_id}} =
               TeamExecutor.start(
                 execution,
                 context.scheduler,
                 [team_id: closing_team_id, worker_id: context.worker_id] ++ retry_opts
               )
    end)

    assert_eventually(fn ->
      match?({:ok, %{status: :closed}}, Ouroboros.Team.Store.get(closing_team_id))
    end)

    missing_worker_id = unique_id("missing-worker")

    assert {:error, {:worker_not_found, ^missing_worker_id}} =
             TeamExecutor.start(
               execution,
               context.scheduler,
               [team_id: context.team_id, worker_id: missing_worker_id] ++ retry_opts
             )

    refute_receive {:ouroboros_test_adapter_started, _run_id, _request, _adapter}, 100
  end

  test "rejects a cancellation window that can overrun the scheduler margin", context do
    execution = %Execution{
      plan_id: unique_id("cancel-window-plan"),
      step_id: "cancel",
      token: unique_id("cancel-window-token"),
      input: nil,
      attempt: 1,
      state: :running,
      metadata: %{}
    }

    assert {:error,
            {:invalid_team_retry_option, :team_cancel_timeout_ms, 4_001,
             {:expected_milliseconds, expected_range}}} =
             TeamExecutor.cancel(execution, :test,
               team_id: context.team_id,
               team_cancel_timeout_ms: 4_001
             )

    assert expected_range == 1..4_000
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

  defp stop_team(team_id) do
    team = Team.whereis(team_id)
    assert is_pid(team)
    monitor = Process.monitor(team)
    assert :ok = DynamicSupervisor.terminate_child(Ouroboros.Team.Supervisor, team)
    assert_receive {:DOWN, ^monitor, :process, ^team, _reason}, 1_000
    assert_eventually(fn -> Team.whereis(team_id) == nil end)
    team
  end

  defp with_suspended_team_recovery(fun) when is_function(fun, 0) do
    recovery = Process.whereis(Ouroboros.Team.Recovery)
    assert is_pid(recovery)
    assert :ok = :sys.suspend(recovery)

    try do
      fun.()
    after
      if Process.alive?(recovery), do: :sys.resume(recovery)
    end
  end

  defp assert_eventually(fun, attempts \\ 300)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-team-executor-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
