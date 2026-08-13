defmodule Ouroboros.Orchestration.SchedulerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Orchestration.{Plan, Scheduler, Store}
  alias Ouroboros.Orchestration.TestExecutor

  defmodule KindExecutor do
    @behaviour Ouroboros.Orchestration.Executor

    @impl true
    def start(execution, _scheduler, opts) do
      send(
        Keyword.fetch!(opts, :test_pid),
        {:kind_executor_started, Keyword.fetch!(opts, :tag), execution}
      )

      :ok
    end
  end

  setup do
    {:ok, _applications} = Application.ensure_all_started(:jido)

    suffix = System.unique_integer([:positive])
    table = String.to_atom("orchestration_test_#{suffix}")
    store_name = String.to_atom("orchestration_store_#{suffix}")
    scheduler_name = String.to_atom("orchestration_scheduler_#{suffix}")

    start_supervised!(
      {Store,
       name: store_name,
       storage: {Jido.Storage.ETS, table: table},
       key: {:orchestration_test, suffix}}
    )

    %{
      store: store_name,
      scheduler: scheduler_name,
      table: table,
      key: {:orchestration_test, suffix}
    }
  end

  test "dispatches fan-out/fan-in and enforces a global concurrency cap", context do
    start_scheduler(context, max_concurrency: 2, executor: true)

    plan =
      plan!("dag", [
        %{id: "root"},
        %{id: "left", dependencies: ["root"]},
        %{id: "right", dependencies: ["root"]},
        %{id: "join", dependencies: ["left", "right"]}
      ])

    assert {:ok, _plan} = Scheduler.submit(context.scheduler, plan)
    assert_receive {:execution_started, root}
    refute_receive {:execution_started, _other}, 20

    assert {:ok, after_root} =
             Scheduler.complete(context.scheduler, "dag", "root", root.token, :root_done)

    assert after_root.steps["left"].state in [:ready, :running]
    assert after_root.steps["right"].state in [:ready, :running]

    assert_receive {:execution_started, branch_a}
    assert_receive {:execution_started, branch_b}
    assert MapSet.new([branch_a.step_id, branch_b.step_id]) == MapSet.new(["left", "right"])
    refute_receive {:execution_started, _capped}, 20

    assert {:ok, _} =
             Scheduler.complete(
               context.scheduler,
               "dag",
               branch_a.step_id,
               branch_a.token,
               :done
             )

    refute_receive {:execution_started, %{step_id: "join"}}, 20

    assert {:ok, _} =
             Scheduler.complete(
               context.scheduler,
               "dag",
               branch_b.step_id,
               branch_b.token,
               :done
             )

    assert_receive {:execution_started, join}
    assert join.step_id == "join"

    assert {:ok, completed} =
             Scheduler.complete(context.scheduler, "dag", "join", join.token, :merged)

    assert completed.status == :completed
  end

  test "manual claims expose tokens and completion is idempotent", context do
    start_scheduler(context)
    assert {:ok, _} = Scheduler.submit(context.scheduler, plan!("manual", [%{id: "one"}]))

    assert {:ok, execution} = Scheduler.start(context.scheduler, "manual", "one")
    assert is_binary(execution.token)
    assert execution.attempt == 1

    assert {:ok, first} =
             Scheduler.complete(context.scheduler, "manual", "one", execution.token, %{ok: true})

    assert first.status == :completed

    assert {:ok, ^first} =
             Scheduler.complete(context.scheduler, "manual", "one", execution.token, %{ok: true})

    assert {:error, :completion_conflict} =
             Scheduler.complete(context.scheduler, "manual", "one", execution.token, :different)

    assert {:error, {:invalid_step_state, :completed}} =
             Scheduler.complete(context.scheduler, "manual", "one", "stale", %{ok: true})
  end

  test "failure blocks descendants, cancels running siblings, and records callback outcome",
       context do
    start_scheduler(context, max_concurrency: 2, executor: true)

    plan =
      plan!("failure", [
        %{id: "first"},
        %{id: "sibling"},
        %{id: "dependent", dependencies: ["first"]}
      ])

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan)
    assert_receive {:execution_started, first_execution}
    assert_receive {:execution_started, second_execution}

    failed = Enum.find([first_execution, second_execution], &(&1.step_id == "first"))

    assert {:ok, plan} =
             Scheduler.fail(context.scheduler, "failure", "first", failed.token, :tests_failed)

    assert plan.status == :failed
    assert plan.steps["first"].state == :failed
    assert plan.steps["dependent"].state == :blocked
    assert plan.steps["sibling"].state == :cancelled

    assert_receive {:execution_cancelled, sibling_execution, {:plan_failed, "first"}}
    assert sibling_execution.step_id == "sibling"

    assert_eventually(fn ->
      {:ok, current} = Scheduler.get(context.scheduler, "failure")
      get_in(current.steps, ["sibling", Access.key(:cancellation), :status]) == :completed
    end)
  end

  test "scheduler restart recovers running work with the same token", context do
    start_scheduler(context, executor: true)
    assert {:ok, _} = Scheduler.submit(context.scheduler, plan!("restart", [%{id: "step"}]))
    assert_receive {:execution_started, first}

    first_scheduler = Process.whereis(context.scheduler)
    Process.unlink(first_scheduler)
    Process.exit(first_scheduler, :kill)

    assert_eventually(fn -> Process.whereis(context.scheduler) == nil end)
    start_scheduler(context, executor: true)

    assert_receive {:execution_started, recovered}
    assert recovered.step_id == "step"
    assert recovered.token == first.token
    assert recovered.attempt == first.attempt
    assert recovered.recovered?

    assert {:ok, completed} =
             Scheduler.complete(context.scheduler, "restart", "step", recovered.token, :ok)

    assert completed.status == :completed
  end

  test "owner death requeues and redispatches the same execution identity", context do
    start_scheduler(context,
      executor: {TestExecutor, [test_pid: self(), spawn_owner: true]}
    )

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan!("owner", [%{id: "step"}]))
    assert_receive {:execution_started, first}
    scheduler_state = :sys.get_state(context.scheduler)
    {_ref, owner} = Map.fetch!(scheduler_state.owners, {"owner", "step"})
    Process.exit(owner, :kill)

    assert_receive {:execution_started, recovered}
    assert recovered.token == first.token
    assert recovered.attempt == first.attempt
    assert recovered.recovered?
  end

  test "a late completion for an orphaned token is still authoritative", context do
    start_scheduler(context)
    assert {:ok, _} = Scheduler.submit(context.scheduler, plan!("late", [%{id: "step"}]))

    owner = spawn(fn -> receive do: (:stop -> :ok) end)
    assert {:ok, execution} = Scheduler.start(context.scheduler, "late", "step", owner: owner)
    Process.exit(owner, :kill)

    assert_eventually(fn ->
      {:ok, current} = Scheduler.get(context.scheduler, "late")
      current.steps["step"].state == :ready
    end)

    assert {:ok, completed} =
             Scheduler.complete(context.scheduler, "late", "step", execution.token, :landed_late)

    assert completed.status == :completed
    assert completed.steps["step"].result == :landed_late
  end

  test "cancel persists before a bounded asynchronous cancellation callback", context do
    start_scheduler(context,
      cancel_timeout: 30,
      executor: {TestExecutor, [test_pid: self(), cancel_behavior: :hang]}
    )

    assert {:ok, _} = Scheduler.submit(context.scheduler, plan!("cancel", [%{id: "step"}]))
    assert_receive {:execution_started, execution}

    assert {:ok, cancelled} = Scheduler.cancel(context.scheduler, "cancel", :user_request)
    assert cancelled.status == :cancelled
    assert cancelled.steps["step"].cancellation.status == :pending
    assert_receive {:execution_cancelled, ^execution, :user_request}

    assert_eventually(fn ->
      {:ok, current} = Scheduler.get(context.scheduler, "cancel")
      cancellation = current.steps["step"].cancellation
      cancellation.status == :completed and cancellation.outcome == {:error, :timeout}
    end)
  end

  test "store restores the atomic plan aggregate after a process restart", context do
    plan = plan!("stored", [%{id: "one"}])
    assert :ok = Store.create(context.store, plan)
    assert {:ok, ^plan} = Store.get(context.store, "stored")

    stop_supervised!(Store)

    start_supervised!(
      {Store,
       name: context.store, storage: {Jido.Storage.ETS, table: context.table}, key: context.key}
    )

    assert {:ok, ^plan} = Store.get(context.store, "stored")
  end

  test "store rejects a stale aggregate replacement", context do
    plan = plan!("versioned", [%{id: "one"}])
    assert :ok = Store.create(context.store, plan)

    current = %{plan | version: 2, updated_at: plan.updated_at + 1, metadata: %{revision: 2}}
    assert :ok = Store.put(context.store, current)

    conflicting = %{plan | version: 2, updated_at: plan.updated_at + 2, metadata: %{revision: 3}}

    assert {:error, {:stale_plan_version, 2, 2}} =
             Store.put(context.store, conflicting)

    assert {:ok, ^current} = Store.get(context.store, "versioned")
  end

  test "a snapshot written before step kinds existed loads as coding", context do
    plan = plan!("legacy", [%{id: "one"}, %{id: "two", dependencies: ["one"]}])

    legacy = %{
      plan
      | steps: Map.new(plan.steps, fn {id, step} -> {id, Map.delete(step, :kind)} end)
    }

    refute Map.has_key?(legacy.steps["one"], :kind)

    stop_supervised!(Store)

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(context.key, %{"legacy" => legacy},
               table: context.table
             )

    start_supervised!(
      {Store,
       name: context.store, storage: {Jido.Storage.ETS, table: context.table}, key: context.key}
    )

    assert {:ok, loaded} = Store.get(context.store, "legacy")
    assert loaded.steps["one"].kind == :coding
    assert loaded.steps["two"].kind == :coding

    # The upgraded aggregate is a normal current-shape plan: it validates, and a
    # transition on top of it is accepted at the next version.
    assert Plan.validate(loaded) == :ok
    assert :ok = Store.put(context.store, %{loaded | version: loaded.version + 1})
  end

  test "a snapshot naming a kind this build does not know fails closed", context do
    plan = plan!("future", [%{id: "one"}])

    future = %{
      plan
      | steps: Map.new(plan.steps, fn {id, step} -> {id, Map.put(step, :kind, :teleport)} end)
    }

    stop_supervised!(Store)

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(context.key, %{"future" => future},
               table: context.table
             )

    test_pid = self()

    spawn(fn ->
      Process.flag(:trap_exit, true)

      result =
        Store.start_link(
          name: nil,
          storage: {Jido.Storage.ETS, table: context.table},
          key: context.key
        )

      send(test_pid, {:future_store_start, result})
    end)

    assert_receive {:future_store_start, {:error, :invalid_orchestration_checkpoint}}
  end

  test "submit refuses a plan whose kinds this scheduler cannot execute", context do
    start_scheduler(context, executor: true)

    forge_plan =
      plan!("forge-only", [
        %{
          id: "build",
          kind: :forge,
          input: %{module: "Ouroboros.Capability.Echo", source_path: "capabilities/echo.ex"}
        }
      ])

    assert {:error, {:unsupported_step_kinds, [:forge]}} =
             Scheduler.submit(context.scheduler, forge_plan)

    # Refused before the aggregate was persisted, so nothing has to be cleaned up.
    assert {:ok, []} = Scheduler.list(context.scheduler)
    assert :not_found = Store.get(context.store, "forge-only")

    assert {:ok, _plan} =
             Scheduler.submit(context.scheduler, plan!("coding-only", [%{id: "work"}]))
  end

  test "a scheduler with no executors accepts any kind and dispatches nothing", context do
    start_scheduler(context)

    plan =
      plan!("manual-forge", [
        %{
          id: "build",
          kind: :forge,
          input: %{module: "Ouroboros.Capability.Echo", source_path: "capabilities/echo.ex"}
        }
      ])

    assert {:ok, _plan} = Scheduler.submit(context.scheduler, plan)
    assert {:ok, execution} = Scheduler.start(context.scheduler, "manual-forge", "build")
    assert execution.kind == :forge

    assert {:ok, completed} =
             Scheduler.complete(
               context.scheduler,
               "manual-forge",
               "build",
               execution.token,
               :done
             )

    assert completed.status == :completed
  end

  test "dispatch resolves the executor from the step kind", context do
    start_scheduler(context,
      executors: %{
        coding: {KindExecutor, test_pid: self(), tag: :coding_adapter},
        forge: {KindExecutor, test_pid: self(), tag: :forge_adapter}
      }
    )

    plan =
      plan!("mixed", [
        %{id: "code", input: %{objective: "write it"}},
        %{
          id: "build",
          kind: :forge,
          dependencies: ["code"],
          input: %{module: "Ouroboros.Capability.Echo", source_path: "capabilities/echo.ex"}
        }
      ])

    assert {:ok, _plan} = Scheduler.submit(context.scheduler, plan)

    assert_receive {:kind_executor_started, :coding_adapter, coding}
    assert coding.step_id == "code"
    assert coding.kind == :coding
    refute_receive {:kind_executor_started, :forge_adapter, _execution}, 20

    assert {:ok, _plan} =
             Scheduler.complete(context.scheduler, "mixed", "code", coding.token, :written)

    assert_receive {:kind_executor_started, :forge_adapter, forge}
    assert forge.step_id == "build"
    assert forge.kind == :forge
  end

  test "store fails closed on a corrupt checkpoint", context do
    stop_supervised!(Store)

    assert :ok =
             Jido.Storage.ETS.put_checkpoint(context.key, %{bad: self()}, table: context.table)

    test_pid = self()

    spawn(fn ->
      Process.flag(:trap_exit, true)

      result =
        Store.start_link(
          name: nil,
          storage: {Jido.Storage.ETS, table: context.table},
          key: context.key
        )

      send(test_pid, {:corrupt_store_start, result})
    end)

    assert_receive {:corrupt_store_start, {:error, :invalid_orchestration_checkpoint}}
  end

  defp start_scheduler(context, opts \\ []) do
    opts = Keyword.put_new(opts, :executor, nil)

    opts =
      case Keyword.get(opts, :executor) do
        true -> Keyword.put(opts, :executor, {TestExecutor, test_pid: self()})
        _other -> opts
      end

    start_supervised!(
      {Scheduler,
       Keyword.merge(
         [name: context.scheduler, store: context.store, max_concurrency: 4],
         opts
       )},
      restart: :temporary
    )
  end

  defp plan!(id, steps) do
    {:ok, plan} = Plan.new(id, steps)
    plan
  end

  defp assert_eventually(fun, attempts \\ 100)

  defp assert_eventually(fun, attempts) when attempts > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(10)
      assert_eventually(fun, attempts - 1)
    end
  end

  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")
end
