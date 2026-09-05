defmodule Ouroboros.ControlTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Control
  alias Ouroboros.Control.{BlockingAdapter, JidoAI, Run, Server, Store}
  alias Ouroboros.Orchestration.{Plan, Scheduler}
  alias Ouroboros.Orchestration.Store, as: OrchestrationStore

  defmodule DeterministicAdapter do
    @behaviour Ouroboros.Control.Planner
    @behaviour Ouroboros.Control.Evaluator

    @impl true
    def plan(objective, context, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:planner_called, objective, context})
      respond(Keyword.fetch!(opts, :plans), context)
    end

    @impl true
    def evaluate(context, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:evaluator_called, context})
      respond(Keyword.fetch!(opts, :decisions), context)
    end

    defp respond(responses, context) do
      response =
        case Map.fetch(responses, {context.run_id, context.revision}) do
          {:ok, value} -> value
          :error -> Map.fetch!(responses, context.revision)
        end

      case response do
        {:error, _reason} = error -> error
        value -> {:ok, value}
      end
    end
  end

  defmodule BlockingCancelExecutor do
    @behaviour Ouroboros.Orchestration.Executor

    @impl true
    def start(execution, _scheduler, opts) do
      send(Keyword.fetch!(opts, :test_pid), {:control_execution_started, execution})
      :ok
    end

    @impl true
    def cancel(execution, reason, opts) do
      send(
        Keyword.fetch!(opts, :test_pid),
        {:control_execution_cancellation_pending, self(), execution, reason}
      )

      receive do
        {:complete_control_execution_cancellation, outcome} -> outcome
      end
    end
  end

  setup do
    {:ok, _applications} = Application.ensure_all_started(:jido)

    suffix = System.unique_integer([:positive, :monotonic])
    orchestration_table = String.to_atom("control_orchestration_#{suffix}")
    control_table = String.to_atom("control_runs_#{suffix}")
    orchestration_store = String.to_atom("control_orchestration_store_#{suffix}")
    control_store = String.to_atom("control_store_#{suffix}")
    scheduler = String.to_atom("control_scheduler_#{suffix}")
    server = String.to_atom("control_server_#{suffix}")
    orchestration_key = {:control_orchestration_test, suffix}
    control_key = {:control_test, suffix}

    start_supervised!(
      {OrchestrationStore,
       name: orchestration_store,
       storage: {Jido.Storage.ETS, table: orchestration_table},
       key: orchestration_key}
    )

    start_supervised!(
      {Store,
       name: control_store, storage: {Jido.Storage.ETS, table: control_table}, key: control_key}
    )

    start_supervised!({Scheduler, name: scheduler, store: orchestration_store})

    %{
      orchestration_table: orchestration_table,
      control_table: control_table,
      orchestration_store: orchestration_store,
      control_store: control_store,
      scheduler: scheduler,
      server: server,
      orchestration_key: orchestration_key,
      control_key: control_key
    }
  end

  test "public facade reports an unavailable control server without exiting" do
    missing = String.to_atom("missing_control_#{System.unique_integer([:positive])}")

    assert {:error, :control_disabled_or_unavailable} =
             Control.submit("objective", server: missing)

    assert {:error, :control_disabled_or_unavailable} = Control.get("missing", missing)
    assert {:error, :control_disabled_or_unavailable} = Control.list(missing)
    assert {:error, :control_disabled_or_unavailable} = Control.reconcile("missing", missing)

    assert {:error, :control_disabled_or_unavailable} =
             Control.cancel("missing", server: missing)
  end

  test "loads a cold valid adapter before checking its callbacks", context do
    module = Ouroboros.Control.UnloadedAdapter
    beam = :code.which(module)
    assert is_list(beam)
    _purged? = :code.purge(module)
    assert :code.delete(module)
    _purged? = :code.purge(module)
    refute Code.loaded?(module)

    start_supervised!(
      {Server,
       name: context.server,
       store: context.control_store,
       scheduler: context.scheduler,
       planner: module,
       evaluator: module,
       poll_interval: false}
    )

    assert Code.loaded?(module)

    assert {:ok, %Run{status: :planning}} =
             Server.submit(context.server, "cold-adapter", "load cold adapter", 0)

    run = await_run(context.server, "cold-adapter", &(&1.status == :running))
    assert {:ok, plan} = Scheduler.get(context.scheduler, run.current_plan_id)
    assert plan.steps["cold"].input == %{objective: "cold"}
  end

  test "normalizes structured output into a TeamExecutor-compatible plan without policy",
       _context do
    run_id = "team-contract"
    request_id = Run.request_id(run_id, :plan, 0)

    output = %{
      "steps" => [
        %{
          "id" => "inspect",
          "dependencies" => [],
          "input" => %{"objective" => "Inspect the target and report evidence"},
          "metadata" => %{}
        },
        %{
          "id" => "verify",
          "dependencies" => ["inspect"],
          "input" => %{"objective" => "Verify the reported evidence"},
          "metadata" => %{}
        }
      ]
    }

    assert {:ok, plan} = Server.normalize_plan(run_id, 0, request_id, output)
    assert Plan.validate(plan) == :ok

    assert plan.steps["inspect"].input == %{
             "objective" => "Inspect the target and report evidence"
           }

    assert plan.steps["verify"].dependencies == ["inspect"]

    assert Enum.all?(plan.steps, fn {_id, step} ->
             objective = step.input[:objective] || step.input["objective"]
             is_binary(objective) and String.trim(objective) != ""
           end)

    refute Enum.any?(plan.steps, fn {_id, step} ->
             Enum.any?(
               [:options, "options", :provider, "provider", :model, "model"],
               &Map.has_key?(step.input, &1)
             )
           end)

    assert {:error, {:objective_required, "bad"}} =
             Server.normalize_plan(run_id, 0, request_id, [
               %{id: "bad", input: %{objective: "   "}}
             ])

    assert {:error, {:runtime_policy_not_allowed, "bad"}} =
             Server.normalize_plan(run_id, 0, request_id, [
               %{id: "bad", input: %{objective: "Do work", options: [provider: :codex]}}
             ])

    assert {:error, {:runtime_policy_not_allowed, "bad"}} =
             Server.normalize_plan(run_id, 0, request_id, [
               %{
                 id: "bad",
                 input: %{objective: "Do work"},
                 metadata: %{worker_id: "model-selected-worker"}
               }
             ])
  end

  test "a planned forge step is refused while the control plane disallows it", context do
    refute Application.get_env(:ouroboros, :control_allow_forge_steps, false)

    forge_step = %{
      "id" => "build",
      "kind" => "forge",
      "dependencies" => [],
      "input" => %{
        "module" => "Ouroboros.Capability.Planned",
        "source_path" => "capabilities/planned.ex"
      }
    }

    # The step field itself is unknown while the flag is off, which is the same
    # refusal any other unrecognized field gets.
    assert {:error, :unknown_step_field} =
             Server.normalize_plan("blocked", 0, Run.request_id("blocked", :plan, 0), %{
               "steps" => [forge_step]
             })

    start_control(context, plans: %{{"blocked", 0} => %{"steps" => [forge_step]}}, decisions: %{})

    assert {:ok, %Run{status: :planning}} =
             Server.submit(context.server, "blocked", "forge without permission", 0)

    blocked = await_run(context.server, "blocked", &(&1.status == :failed))
    assert blocked.failure == {:invalid_plan, :unknown_step_field}
    assert {:ok, []} = Scheduler.list(context.scheduler)
  end

  test "an allowed forge step is validated, submitted, and dispatched as a forge step",
       context do
    allow_forge_steps!()

    stop_supervised!(Scheduler)

    start_supervised!(
      {Scheduler,
       name: context.scheduler,
       store: context.orchestration_store,
       executors: %{
         coding: {Ouroboros.Orchestration.TestExecutor, test_pid: self()},
         forge: {Ouroboros.Orchestration.TestExecutor, test_pid: self()}
       }}
    )

    request_id = Run.request_id("forge-run", :plan, 0)

    output = %{
      "steps" => [
        %{
          "id" => "author",
          "dependencies" => [],
          "input" => %{"objective" => "Write the capability source"}
        },
        %{
          "id" => "build",
          "kind" => "forge",
          "dependencies" => ["author"],
          "input" => %{
            "module" => "Ouroboros.Capability.Planned",
            "source_path" => "capabilities/planned.ex",
            "test_path" => "capabilities/planned_test.exs"
          }
        }
      ]
    }

    assert {:ok, normalized} = Server.normalize_plan("forge-run", 0, request_id, output)
    assert normalized.steps["author"].kind == :coding
    assert normalized.steps["build"].kind == :forge
    assert Plan.validate(normalized) == :ok

    # The same per-kind rules the plan applies are applied to the accepted plan:
    # runtime policy stays out of a forge step exactly as it stays out of a
    # coding step.
    assert {:error, {:invalid_step_input, "build", {:invalid_capability_module, "Kernel"}}} =
             Server.normalize_plan("forge-run", 0, request_id, [
               %{
                 id: "build",
                 kind: "forge",
                 input: %{module: "Kernel", source_path: "capabilities/planned.ex"}
               }
             ])

    assert {:error, {:invalid_step_input, "build", {:invalid_source_path, "../escape.ex"}}} =
             Server.normalize_plan("forge-run", 0, request_id, [
               %{
                 id: "build",
                 kind: "forge",
                 input: %{
                   module: "Ouroboros.Capability.Planned",
                   source_path: "../escape.ex"
                 }
               }
             ])

    assert {:error, {:runtime_policy_not_allowed, "build"}} =
             Server.normalize_plan("forge-run", 0, request_id, [
               %{
                 id: "build",
                 kind: "forge",
                 input: %{
                   module: "Ouroboros.Capability.Planned",
                   source_path: "capabilities/planned.ex"
                 },
                 metadata: %{nodes: [:node@host]}
               }
             ])

    start_control(context, plans: %{{"forge-run", 0} => output}, decisions: %{})

    assert {:ok, %Run{status: :planning}} =
             Server.submit(context.server, "forge-run", "forge a capability", 0)

    run = await_run(context.server, "forge-run", &(&1.status in [:running, :failed]))
    assert run.status == :running, inspect(run.failure)
    assert {:ok, plan} = Scheduler.get(context.scheduler, run.current_plan_id)
    assert plan.steps["build"].kind == :forge

    assert plan.steps["build"].input == %{
             "module" => "Ouroboros.Capability.Planned",
             "source_path" => "capabilities/planned.ex",
             "test_path" => "capabilities/planned_test.exs"
           }

    assert_receive {:execution_started, authoring}
    assert authoring.step_id == "author"
    assert authoring.kind == :coding

    assert {:ok, _plan} =
             Scheduler.complete(
               context.scheduler,
               run.current_plan_id,
               "author",
               authoring.token,
               :authored
             )

    assert_receive {:execution_started, forge}
    assert forge.step_id == "build"
    assert forge.kind == :forge
  end

  test "JidoAI correlates requests to the logical control run" do
    request_id = Run.request_id("logical-run", :plan, 0)

    assert JidoAI.execution_context(request_id, "logical-run") == %{
             request_id: request_id,
             run_id: "logical-run"
           }

    evaluation_id = Run.request_id("logical-run", :evaluate, 0)

    assert JidoAI.execution_context(evaluation_id, "logical-run") == %{
             request_id: evaluation_id,
             run_id: "logical-run"
           }
  end

  test "rejects malformed and cyclic planner output before scheduler submission", context do
    plans = %{
      {"malformed", 0} => %{steps: "not a list"},
      {"cyclic", 0} => [
        %{id: "a", dependencies: ["b"], input: %{objective: "a"}},
        %{id: "b", dependencies: ["a"], input: %{objective: "b"}}
      ]
    }

    start_control(context, plans: plans, decisions: %{})

    assert {:ok, %Run{status: :planning}} =
             Server.submit(context.server, "malformed", "malformed", 0)

    malformed = await_run(context.server, "malformed", &(&1.status == :failed))
    assert malformed.failure == {:invalid_plan, :invalid_steps}

    assert {:ok, %Run{status: :planning}} =
             Server.submit(context.server, "cyclic", "cyclic", 0)

    cyclic = await_run(context.server, "cyclic", &(&1.status == :failed))
    assert cyclic.failure == {:invalid_plan, :cyclic_dependencies}

    assert {:ok, []} = Scheduler.list(context.scheduler)
  end

  test "evaluates completed evidence, revises once, and accepts the revised plan", context do
    plans = %{
      0 => [%{id: "draft", input: %{objective: "draft"}}],
      1 => [%{id: "repair", input: %{objective: "repair"}}]
    }

    decisions = %{
      0 => {:revise, %{gap: "add verification"}},
      1 => {:accept, %{summary: "verified"}}
    }

    start_control(context, plans: plans, decisions: decisions)

    assert {:ok, first} =
             Control.submit("ship a verified change",
               id: "revision-run",
               max_revisions: 1,
               server: context.server
             )

    assert first.status == :planning

    assert_receive {:planner_called, "ship a verified change", first_context}

    first = await_run(context.server, first.id, &(&1.status == :running))
    assert first.revision == 0
    assert first.current_plan_id == Run.plan_id(first.id, 0)

    assert first_context.request_id == Run.request_id(first.id, :plan, 0)
    assert first_context.feedback == nil
    assert first_context.previous_plan == nil

    complete_step!(context.scheduler, first.current_plan_id, "draft", %{artifact: "v1"})

    assert {:ok, %Run{status: :evaluating}} = Server.reconcile(context.server, first.id)

    assert_receive {:evaluator_called, first_evaluation}
    assert_receive {:planner_called, "ship a verified change", revised_context}

    revised =
      await_run(context.server, first.id, &(&1.status == :running and &1.revision == 1))

    assert revised.revision == 1
    assert revised.previous_plan_id == first.current_plan_id
    assert revised.current_plan_id == Run.plan_id(first.id, 1)

    assert first_evaluation.evaluation_id == Run.request_id(first.id, :evaluate, 0)
    assert first_evaluation.plan.status == :completed
    assert first_evaluation.plan.steps["draft"].result == %{artifact: "v1"}

    assert revised_context.request_id == Run.request_id(first.id, :plan, 1)
    assert revised_context.feedback == %{gap: "add verification"}
    assert revised_context.previous_plan.status == :completed

    complete_step!(context.scheduler, revised.current_plan_id, "repair", %{artifact: "v2"})

    assert {:ok, %Run{status: :evaluating}} = Server.reconcile(context.server, first.id)
    assert_receive {:evaluator_called, _second_evaluation}

    completed = await_run(context.server, first.id, &(&1.status == :completed))
    assert completed.status == :completed
    assert completed.decision == :accept
    assert completed.result == %{summary: "verified"}
    assert completed.evidence_contract == nil
    assert Enum.map(completed.history, & &1.decision) == [:revise, :accept]

    assert {:ok, plans} = Scheduler.list(context.scheduler)

    assert MapSet.new(Enum.map(plans, & &1.id)) ==
             MapSet.new([Run.plan_id(first.id, 0), Run.plan_id(first.id, 1)])
  end

  test "accepts a terminal result with content-minimized evidence", context do
    digest = String.duplicate("b", 64)

    evidence_contract = %{
      "version" => 1,
      "evidence" => [
        %{
          "id" => "targeted-test",
          "kind" => "test",
          "outcome" => "pass",
          "digest" => digest,
          "recorded_at" => 1_700_000_000_000
        }
      ],
      "criteria" => [
        %{"id" => "verified", "status" => "met", "evidence_ids" => ["targeted-test"]}
      ],
      "claims" => [
        %{
          "id" => "change-works",
          "classification" => "observed",
          "status" => "supported",
          "statement_digest" => digest,
          "evidence_ids" => ["targeted-test"]
        }
      ]
    }

    start_control(context,
      plans: %{0 => [%{id: "work", input: %{objective: "work"}}]},
      decisions: %{0 => {:accept, %{summary: "verified"}, evidence_contract}}
    )

    assert {:ok, submitted} = Server.submit(context.server, "evidenced", "verify work", 0)
    run = await_run(context.server, submitted.id, &(&1.status == :running))
    complete_step!(context.scheduler, run.current_plan_id, "work", %{artifact: "digest-only"})
    assert {:ok, %Run{status: :evaluating}} = Server.reconcile(context.server, submitted.id)

    completed = await_run(context.server, submitted.id, &(&1.status == :completed))
    assert completed.evidence_contract.version == 1
    assert hd(completed.evidence_contract.evidence).kind == :test
    assert hd(completed.evidence_contract.claims).classification == :observed
    assert [%{evidence_contract_digest: history_digest}] = completed.history

    assert {:ok, ^history_digest} =
             Ouroboros.Control.EvidenceContract.digest(completed.evidence_contract)

    assert Run.validate(completed) == :ok
  end

  test "fails closed when evaluator requests revision beyond the budget", context do
    start_control(context,
      plans: %{0 => [%{id: "attempt", input: %{objective: "attempt"}}]},
      decisions: %{0 => {:revise, %{gap: "still incomplete"}}}
    )

    assert {:ok, submitted} = Server.submit(context.server, "bounded", "bounded objective", 0)
    assert_receive {:planner_called, _, _}

    run = await_run(context.server, submitted.id, &(&1.status == :running))

    complete_step!(context.scheduler, run.current_plan_id, "attempt", :done)

    assert {:ok, %Run{status: :evaluating}} = Server.reconcile(context.server, run.id)
    assert_receive {:evaluator_called, _context}

    failed = await_run(context.server, run.id, &(&1.status == :failed))
    assert failed.status == :failed
    assert failed.revision == 0

    assert failed.failure ==
             {:revision_budget_exhausted, 0, %{gap: "still incomplete"}}

    assert [%{decision: :revise}] = failed.history
    refute_receive {:planner_called, _, _}, 20

    assert {:ok, [_only_plan]} = Scheduler.list(context.scheduler)
  end

  test "recovers checkpointed submission and evaluation without duplicate plans", context do
    objective = "recover safely"
    {:ok, initial} = Run.new("recover-run", objective, 1)

    specs = [
      %{id: "work", dependencies: [], input: %{objective: objective}, metadata: %{}}
    ]

    plan_id = Run.plan_id(initial.id, 0)

    {:ok, plan} =
      Plan.new(plan_id, specs,
        metadata: %{
          control_run_id: initial.id,
          control_revision: 0,
          control_plan_fingerprint: Run.fingerprint(specs),
          planner_request_id: initial.planner_request_id
        }
      )

    pending =
      Run.transition(initial, %{
        status: :submitting,
        current_plan_id: plan.id,
        pending_plan: plan
      })

    assert :ok = Store.create(context.control_store, pending)
    assert {:ok, _scheduled} = Scheduler.submit(context.scheduler, plan)

    stop_supervised!(Store)
    restart_control_store(context)

    server_opts =
      control_opts(context,
        plans: %{0 => [%{id: "must-not-run", input: %{objective: "must not run"}}]},
        decisions: %{0 => {:accept, %{summary: "recovered"}}}
      )

    start_supervised!({Server, server_opts})

    assert_eventually(fn ->
      match?({:ok, %Run{status: :running}}, Server.get(context.server, initial.id))
    end)

    refute_receive {:planner_called, _, _}, 20
    assert {:ok, [only_plan]} = Scheduler.list(context.scheduler)
    assert only_plan.id == plan_id

    complete_step!(context.scheduler, plan_id, "work", %{landed: true})

    stop_supervised!(Server)
    start_supervised!({Server, server_opts})

    assert_receive {:evaluator_called, evaluation_context}, 1_000
    assert evaluation_context.evaluation_id == Run.request_id(initial.id, :evaluate, 0)
    assert evaluation_context.plan.steps["work"].result == %{landed: true}

    assert_eventually(fn ->
      case Server.get(context.server, initial.id) do
        {:ok, %Run{status: :completed, result: %{summary: "recovered"}} = run} -> run
        _other -> false
      end
    end)

    assert {:ok, [_same_plan]} = Scheduler.list(context.scheduler)
  end

  test "durable runs exclude runtime adapter processes and options", context do
    secret_marker = "adapter-secret-that-must-not-persist"

    start_control(context,
      plans: %{0 => [%{id: "safe", input: %{objective: "safe"}}]},
      decisions: %{0 => :accept},
      adapter_marker: secret_marker
    )

    assert {:ok, submitted} = Server.submit(context.server, "safe-run", "safe objective", 0)
    run = await_run(context.server, submitted.id, &(&1.status == :running))
    assert Run.validate(run) == :ok

    assert {:ok, persisted} = Store.get(context.control_store, run.id)
    binary = :erlang.term_to_binary(persisted)
    refute binary =~ secret_marker
    refute contains_runtime_handle?(persisted)
  end

  test "durably cancels a running plan and retries idempotently", context do
    start_control(context,
      plans: %{0 => [%{id: "work", input: %{objective: "work"}}]},
      decisions: %{0 => {:revise, "must never run"}}
    )

    assert {:ok, submitted} = Server.submit(context.server, "cancel-running", "cancel me", 1)
    assert_receive {:planner_called, "cancel me", _context}

    running = await_run(context.server, submitted.id, &(&1.status == :running))

    assert {:ok, cancelled} =
             Control.cancel(running.id,
               server: context.server,
               reason: %{source: :operator}
             )

    assert cancelled.status == :cancelled
    assert cancelled.decision == :cancelled
    assert cancelled.cancellation.status == :completed
    assert cancelled.cancellation.reason == %{source: :operator}
    assert cancelled.cancellation.plan_id == running.current_plan_id
    assert cancelled.cancellation.outcome.disposition == :cancelled

    assert cancelled.cancellation.outcome.execution_cancellation == %{
             status: :no_active_execution,
             steps: [
               %{
                 step_id: "work",
                 status: :no_active_execution
               }
             ]
           }

    assert Run.validate(cancelled) == :ok

    assert {:ok, plan} = Scheduler.get(context.scheduler, running.current_plan_id)
    assert plan.status == :cancelled

    assert {:ok, ^cancelled} =
             Control.cancel(running.id,
               server: context.server,
               reason: %{source: :operator}
             )

    assert {:error, {:cancellation_conflict, %{source: :operator}}} =
             Control.cancel(running.id, server: context.server, reason: :different)

    assert {:ok, ^cancelled} = Server.reconcile(context.server, running.id)
    refute_receive {:evaluator_called, _context}, 20
    refute_receive {:planner_called, _, _}, 20
  end

  test "records an active execution cancellation error as unconfirmed", context do
    start_control(context,
      plans: %{0 => [%{id: "work", input: %{objective: "work"}}]},
      decisions: %{0 => :accept}
    )

    assert {:ok, submitted} =
             Server.submit(context.server, "cancel-unconfirmed", "cancel uncertain work", 0)

    running = await_run(context.server, submitted.id, &(&1.status == :running))
    assert {:ok, _execution} = Scheduler.start(context.scheduler, running.current_plan_id, "work")

    assert {:ok, cancelled} =
             Server.cancel(context.server, running.id, %{source: :operator})

    assert cancelled.status == :cancelled

    assert cancelled.cancellation.outcome.execution_cancellation == %{
             status: :unconfirmed,
             steps: [
               %{
                 step_id: "work",
                 status: :unconfirmed,
                 outcome: :not_supported
               }
             ]
           }

    assert Run.validate(cancelled) == :ok
  end

  test "stays cancelling while execution callback is pending and recovers accepted evidence",
       context do
    stop_supervised!(Scheduler)

    start_supervised!(
      {Scheduler,
       name: context.scheduler,
       store: context.orchestration_store,
       executor: {BlockingCancelExecutor, test_pid: self()},
       cancel_timeout: 1_000}
    )

    adapter_opts = [
      plans: %{0 => [%{id: "work", input: %{objective: "work"}}]},
      decisions: %{0 => :accept}
    ]

    start_control(context, adapter_opts)

    assert {:ok, submitted} =
             Server.submit(context.server, "cancel-pending", "cancel active work", 0)

    assert_receive {:control_execution_started, execution}, 1_000
    running = await_run(context.server, submitted.id, &(&1.status == :running))
    assert execution.plan_id == running.current_plan_id

    assert {:ok, cancelling} = Server.cancel(context.server, running.id, :operator)
    assert cancelling.status == :cancelling
    assert cancelling.cancellation.status == :pending
    assert Run.validate(cancelling) == :ok

    assert_receive {:control_execution_cancellation_pending, callback, ^execution, :operator},
                   1_000

    assert {:ok, ^cancelling} = Store.get(context.control_store, running.id)

    stop_supervised!(Server)
    send(callback, {:complete_control_execution_cancellation, :ok})

    assert_eventually(fn ->
      case Scheduler.get(context.scheduler, running.current_plan_id) do
        {:ok, plan} -> plan.steps["work"].cancellation.status == :completed
        _other -> false
      end
    end)

    start_control(context, adapter_opts)

    cancelled = await_run(context.server, running.id, &(&1.status == :cancelled))

    assert cancelled.cancellation.reason == :operator

    assert cancelled.cancellation.outcome.execution_cancellation == %{
             status: :request_accepted,
             steps: [
               %{
                 step_id: "work",
                 status: :request_accepted,
                 outcome: :ok
               }
             ]
           }

    refute inspect(cancelled.cancellation.outcome) =~ "provider_stopped"
    assert Run.validate(cancelled) == :ok
  end

  test "restart resumes a checkpointed cancellation without planner or evaluator calls",
       context do
    start_control(context,
      plans: %{0 => [%{id: "work", input: %{objective: "work"}}]},
      decisions: %{0 => {:accept, :must_not_run}}
    )

    assert {:ok, submitted} =
             Server.submit(context.server, "cancel-restart", "stop safely", 0)

    assert_receive {:planner_called, "stop safely", _context}
    running = await_run(context.server, submitted.id, &(&1.status == :running))

    requested_at = System.system_time(:millisecond)

    cancelling =
      Run.transition(running, %{
        status: :cancelling,
        pending_plan: nil,
        evaluation_id: nil,
        decision: :cancelled,
        cancellation: %{
          status: :pending,
          reason: :shutdown,
          requested_at: requested_at,
          plan_id: running.current_plan_id
        }
      })

    assert Run.validate(cancelling) == :ok
    assert :ok = Store.put(context.control_store, cancelling)

    stop_supervised!(Server)

    start_supervised!(
      {Server,
       control_opts(context,
         plans: %{0 => [%{id: "must-not-run", input: %{objective: "must not run"}}]},
         decisions: %{0 => {:accept, :must_not_run}}
       )}
    )

    cancelled =
      assert_eventually(fn ->
        case Server.get(context.server, running.id) do
          {:ok, %Run{status: :cancelled} = run} -> run
          _other -> false
        end
      end)

    assert cancelled.cancellation.reason == :shutdown
    assert cancelled.cancellation.requested_at == requested_at
    assert cancelled.cancellation.outcome.disposition == :cancelled

    assert {:ok, plan} = Scheduler.get(context.scheduler, running.current_plan_id)
    assert plan.status == :cancelled
    refute_receive {:planner_called, _, _}, 20
    refute_receive {:evaluator_called, _context}, 20
  end

  test "rejects malformed cancellation requests without mutating state", context do
    start_control(context,
      plans: %{0 => [%{id: "safe", input: %{objective: "safe"}}]},
      decisions: %{0 => :accept}
    )

    assert {:ok, submitted} =
             Server.submit(context.server, "cancel-invalid", "stay intact", 0)

    assert_receive {:planner_called, "stay intact", _context}
    running = await_run(context.server, submitted.id, &(&1.status == :running))

    assert {:error, {:invalid_id, "bad id"}} =
             Control.cancel("bad id", server: context.server)

    assert {:error, :unserializable_cancellation_reason} =
             Control.cancel(running.id, server: context.server, reason: self())

    assert {:error, :invalid_options} = Control.cancel(running.id, [:not_keyword])
    assert {:error, :not_found} = Control.cancel("missing-run", server: context.server)
    assert {:ok, ^running} = Server.get(context.server, running.id)
  end

  test "a blocked planner does not block reading or cancelling another run", context do
    start_blocking_control(context, block_planning_for: ["wait indefinitely"])

    assert {:ok, independent_submission} =
             Server.submit(context.server, "independent", "finish independently", 0)

    independent =
      await_run(context.server, independent_submission.id, &(&1.status == :running))

    assert {:ok, blocked} =
             Server.submit(context.server, "blocked-planner", "wait indefinitely", 0)

    assert blocked.status == :planning

    assert_receive {:control_callback_blocked, :planner, worker, planner_context}
    assert planner_context.request_id == blocked.planner_request_id
    assert Process.alive?(worker)

    assert {:ok, ^independent} = Server.get(context.server, independent.id)

    assert {:ok, %Run{status: :cancelled}} =
             Server.cancel(context.server, independent.id, :operator)

    assert {:ok, %Run{status: :planning}} = Server.get(context.server, blocked.id)

    assert {:ok, blocked_cancelled} = Server.cancel(context.server, blocked.id, :operator)
    assert blocked_cancelled.status == :cancelled
    assert blocked_cancelled.cancellation.outcome == :not_submitted
    assert_eventually(fn -> not Process.alive?(worker) end)
  end

  test "a stale blocked evaluator result cannot resurrect a cancelled run", context do
    start_blocking_control(context, block_evaluation_for: ["stale-evaluation"])

    assert {:ok, submitted} =
             Server.submit(context.server, "stale-evaluation", "evaluate after work", 1)

    running = await_run(context.server, submitted.id, &(&1.status == :running))
    complete_step!(context.scheduler, running.current_plan_id, "work", :done)

    assert {:ok, %Run{status: :evaluating}} = Server.reconcile(context.server, running.id)

    assert_receive {:control_callback_blocked, :evaluator, worker, evaluation_context}
    assert evaluation_context.evaluation_id == Run.request_id(running.id, :evaluate, 0)

    server_pid = Process.whereis(context.server)
    :ok = :sys.suspend(server_pid)

    cancel_task =
      Task.async(fn -> Server.cancel(context.server, running.id, %{source: :operator}) end)

    assert_eventually(fn -> queued_cancel?(server_pid, running.id) end)

    send(worker, {:release_control_callback, {:ok, {:revise, "stale feedback"}}})
    assert_eventually(fn -> queued_callback_result?(server_pid, worker, running.id) end)

    :ok = :sys.resume(server_pid)

    assert {:ok, cancelled} = Task.await(cancel_task, 1_000)
    assert cancelled.status == :cancelled
    assert cancelled.revision == 0
    assert cancelled.cancellation.outcome.disposition == :already_terminal

    assert {:ok, ^cancelled} = Server.reconcile(context.server, running.id)
    assert_eventually(fn -> not Process.alive?(worker) end)

    Process.sleep(20)
    assert {:ok, ^cancelled} = Server.get(context.server, running.id)
    assert {:ok, [plan]} = Scheduler.list(context.scheduler)
    assert plan.id == running.current_plan_id
    assert plan.status == :completed
  end

  test "worker failure and server restart retry the same durable planning request", context do
    adapter_opts = [block_planning_for: ["recover blocked request"]]
    start_blocking_control(context, adapter_opts)

    assert {:ok, submitted} =
             Server.submit(context.server, "blocked-recovery", "recover blocked request", 0)

    assert_receive {:control_callback_blocked, :planner, first_worker, first_context}, 1_000
    Process.exit(first_worker, :kill)
    assert_eventually(fn -> not Process.alive?(first_worker) end)

    assert_receive {:control_callback_blocked, :planner, retry_worker, retry_context}, 1_000
    refute retry_worker == first_worker
    assert retry_context.request_id == first_context.request_id
    assert retry_context.revision == first_context.revision

    stop_supervised!(Server)
    assert_eventually(fn -> not Process.alive?(retry_worker) end)

    start_blocking_control(context, adapter_opts)

    assert_receive {:control_callback_blocked, :planner, recovered_worker, recovered_context},
                   1_000

    refute recovered_worker == retry_worker
    assert recovered_context.request_id == first_context.request_id
    assert recovered_context.revision == first_context.revision

    send(
      recovered_worker,
      {:release_control_callback,
       {:ok, [%{id: "recovered", input: %{objective: "recovered work"}}]}}
    )

    running = await_run(context.server, submitted.id, &(&1.status == :running))
    assert running.planner_request_id == first_context.request_id

    assert {:ok, [plan]} = Scheduler.list(context.scheduler)
    assert plan.id == Run.plan_id(running.id, 0)
    assert Map.has_key?(plan.steps, "recovered")
  end

  defp start_control(context, adapter_opts) do
    start_supervised!({Server, control_opts(context, adapter_opts)})
  end

  defp allow_forge_steps! do
    previous = Application.get_env(:ouroboros, :control_allow_forge_steps)
    Application.put_env(:ouroboros, :control_allow_forge_steps, true)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:ouroboros, :control_allow_forge_steps)
      else
        Application.put_env(:ouroboros, :control_allow_forge_steps, previous)
      end
    end)
  end

  defp start_blocking_control(context, adapter_opts) do
    adapter = {BlockingAdapter, Keyword.put(adapter_opts, :test_pid, self())}

    start_supervised!(
      {Server,
       name: context.server,
       store: context.control_store,
       scheduler: context.scheduler,
       planner: adapter,
       evaluator: adapter,
       poll_interval: false}
    )
  end

  defp control_opts(context, adapter_opts) do
    adapter_opts = Keyword.put(adapter_opts, :test_pid, self())
    adapter = {DeterministicAdapter, adapter_opts}

    [
      name: context.server,
      store: context.control_store,
      scheduler: context.scheduler,
      planner: adapter,
      evaluator: adapter,
      poll_interval: false
    ]
  end

  defp restart_control_store(context) do
    start_supervised!(
      {Store,
       name: context.control_store,
       storage: {Jido.Storage.ETS, table: context.control_table},
       key: context.control_key}
    )
  end

  defp complete_step!(scheduler, plan_id, step_id, result) do
    assert {:ok, execution} = Scheduler.start(scheduler, plan_id, step_id)

    assert {:ok, %Plan{} = plan} =
             Scheduler.complete(scheduler, plan_id, step_id, execution.token, result)

    plan
  end

  defp contains_runtime_handle?(term)
       when is_pid(term) or is_port(term) or is_reference(term) or is_function(term),
       do: true

  defp contains_runtime_handle?(term) when is_struct(term),
    do: term |> Map.from_struct() |> contains_runtime_handle?()

  defp contains_runtime_handle?(term) when is_map(term) do
    Enum.any?(term, fn {key, value} ->
      contains_runtime_handle?(key) or contains_runtime_handle?(value)
    end)
  end

  defp contains_runtime_handle?(term) when is_list(term),
    do: Enum.any?(term, &contains_runtime_handle?/1)

  defp contains_runtime_handle?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.any?(&contains_runtime_handle?/1)

  defp contains_runtime_handle?(_term), do: false

  defp await_run(server, id, predicate) do
    assert_eventually(fn ->
      case Server.get(server, id) do
        {:ok, %Run{} = run} -> if predicate.(run), do: run, else: false
        _other -> false
      end
    end)
  end

  defp queued_cancel?(server, id) do
    {:messages, messages} = Process.info(server, :messages)

    Enum.any?(messages, fn
      {:"$gen_call", _from, {:cancel, ^id, _reason}} -> true
      _other -> false
    end)
  end

  defp queued_callback_result?(server, worker, id) do
    {:messages, messages} = Process.info(server, :messages)

    Enum.any?(messages, fn
      {:control_request_result, ^worker, _delivery_ref, :evaluator, ^id, _request_id, _version,
       _result} ->
        true

      _other ->
        false
    end)
  end

  defp assert_eventually(fun, attempts \\ 100)
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
end
