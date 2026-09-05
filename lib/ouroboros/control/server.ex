defmodule Ouroboros.Control.Server do
  @moduledoc """
  Durable planner/evaluator control loop over public orchestration APIs.

  The server checkpoints intent before each external callback or scheduler
  submission. Planning and evaluation request IDs and orchestration plan IDs
  are deterministic, so restart recovery resumes the same logical operation.

  ## What a model may express

  A planned step carries an execution objective and graph dependencies. Nothing
  else: no provider, worker, workspace, sandbox, or approval policy, and no
  metadata. That is the trust boundary, and it is enforced here on the accepted
  plan rather than only in the prompt.

  `config :ouroboros, :control_allow_forge_steps` (default `false`) widens it by
  exactly one shape. When it is on, a step may declare `kind: "forge"` and carry
  an input of `module`, `source_path`, and optional `test_path`, validated against the same
  rules `Ouroboros.Orchestration.Plan` applies. The coding-step shape is
  untouched either way, and with the flag off a `kind` field is an unknown field
  like any other.

  Enabling the flag lets a plan *express* a forge step. It grants no authority to
  deploy: the forged artifact is still signed by whatever `:forge_signer` names —
  `Signer.Deny` unless an operator changed it — and still verified against each
  target node's trusted signers. A scheduler with no forge executor refuses the
  plan outright.
  """

  use GenServer

  alias Ouroboros.Control.{EvidenceContract, Run, Store}
  alias Ouroboros.Orchestration.{Plan, Scheduler, Serializable, Step}

  @terminal_plan_statuses [:completed, :failed, :blocked, :cancelled]
  @allowed_options [:name, :store, :scheduler, :planner, :evaluator, :poll_interval]

  @type server :: GenServer.server()
  @type adapter :: {module(), keyword()}

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name_option(name))
  end

  @spec submit(server(), String.t(), String.t(), non_neg_integer()) ::
          {:ok, Run.t()} | {:error, term()}
  def submit(server \\ __MODULE__, id, objective, max_revisions) do
    GenServer.call(server, {:submit, id, objective, max_revisions}, :infinity)
  end

  @spec get(server(), String.t()) :: {:ok, Run.t()} | :not_found
  def get(server \\ __MODULE__, id), do: GenServer.call(server, {:get, id})

  @spec list(server()) :: {:ok, [Run.t()]}
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @spec reconcile(server(), String.t()) :: {:ok, Run.t()} | {:error, term()}
  def reconcile(server \\ __MODULE__, id), do: GenServer.call(server, {:reconcile, id}, :infinity)

  @spec cancel(String.t()) :: {:ok, Run.t()} | {:error, term()}
  def cancel(id), do: cancel(__MODULE__, id, :cancelled)

  @spec cancel(String.t(), term()) :: {:ok, Run.t()} | {:error, term()}
  def cancel(id, reason), do: cancel(__MODULE__, id, reason)

  @spec cancel(server(), String.t(), term()) :: {:ok, Run.t()} | {:error, term()}
  def cancel(server, id, reason) do
    GenServer.call(server, {:cancel, id, reason}, :infinity)
  end

  @doc false
  @spec normalize_plan(String.t(), non_neg_integer(), String.t(), term()) ::
          {:ok, Plan.t()} | {:error, term()}
  def normalize_plan(run_id, revision, planner_request_id, output) do
    with true <- Plan.valid_id?(run_id) or {:error, {:invalid_id, run_id}},
         true <- (is_integer(revision) and revision >= 0) or {:error, :invalid_revision},
         true <-
           (is_binary(planner_request_id) and byte_size(planner_request_id) > 0) or
             {:error, :invalid_planner_request_id},
         {:ok, specs} <- normalize_plan_output(output),
         :ok <- validate_executable_steps(specs) do
      build_plan(run_id, revision, planner_request_id, specs)
    else
      {:error, _reason} = error -> error
    end
  end

  @impl true
  def init(opts) do
    with :ok <- validate_options(opts),
         {:ok, planner} <- normalize_adapter(Keyword.get(opts, :planner), :plan, 3),
         {:ok, evaluator} <- normalize_adapter(Keyword.get(opts, :evaluator), :evaluate, 2),
         {:ok, poll_interval} <- normalize_poll_interval(Keyword.get(opts, :poll_interval, 1_000)),
         {:ok, request_supervisor} <- Task.Supervisor.start_link() do
      state = %{
        store: Keyword.get(opts, :store, Store),
        scheduler: Keyword.get(opts, :scheduler, Scheduler),
        planner: planner,
        evaluator: evaluator,
        poll_interval: poll_interval,
        timer: nil,
        request_supervisor: request_supervisor,
        requests: %{},
        request_refs: %{}
      }

      {:ok, state, {:continue, :recover}}
    else
      {:error, reason} -> {:stop, reason}
    end
  rescue
    error -> {:stop, {:invalid_control_options, Exception.message(error)}}
  end

  @impl true
  def handle_continue(:recover, state) do
    state = reconcile_all(state)
    {:noreply, schedule_poll(state)}
  end

  @impl true
  def handle_call({:submit, id, objective, max_revisions}, _from, state) do
    {reply, state} =
      with {:ok, requested} <- Run.new(id, objective, max_revisions) do
        case safe_store_create(state.store, requested) do
          :ok -> {drive(requested, state), state}
          {:error, :already_exists} -> resume_matching(requested, state)
          {:error, reason} -> {{:error, {:storage_error, reason}}, state}
        end
      else
        {:error, _reason} = error -> {error, state}
      end

    {:reply, reply, state}
  end

  def handle_call({:get, id}, _from, state), do: {:reply, safe_store_get(state.store, id), state}
  def handle_call(:list, _from, state), do: {:reply, safe_store_list(state.store), state}

  def handle_call({:reconcile, id}, _from, state) do
    {reply, state} =
      case safe_store_get(state.store, id) do
        {:ok, run} -> {drive(run, state), state}
        :not_found -> {{:error, :not_found}, state}
        {:error, reason} -> {{:error, {:storage_error, reason}}, state}
      end

    {:reply, reply, state}
  end

  def handle_call({:cancel, id, reason}, _from, state) do
    {reply, state} =
      with :ok <- validate_cancellation_request(id, reason),
           {:ok, run} <- fetch_control_run(state.store, id) do
        reply = request_cancellation(run, reason, state)
        {reply, stop_run_requests(state, id)}
      else
        {:error, _reason} = error -> {error, state}
      end

    {:reply, reply, state}
  end

  @impl true
  def handle_info(:poll, state) do
    state = %{state | timer: nil} |> reconcile_all() |> schedule_poll()
    {:noreply, state}
  end

  def handle_info({:launch_request, kind, run_id, request_id, version, payload}, state)
      when kind in [:planner, :evaluator] do
    {:noreply, maybe_launch_request(state, kind, run_id, request_id, version, payload)}
  end

  def handle_info(
        {:control_request_result, pid, delivery_ref, kind, run_id, request_id, version, result},
        state
      ) do
    send(pid, {:control_request_ack, delivery_ref})
    key = {run_id, kind}

    case Map.get(state.requests, key) do
      %{pid: ^pid, request_id: ^request_id, version: ^version} ->
        state = drop_request(state, key, true)
        {:noreply, accept_request_result(state, kind, run_id, request_id, version, result)}

      _other ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.get(state.request_refs, ref) do
      nil ->
        {:noreply, state}

      key ->
        request = Map.fetch!(state.requests, key)
        state = drop_request(state, key, false)

        Process.send_after(
          self(),
          {:retry_request, request.run_id, request.kind, request.request_id, request.version},
          0
        )

        {:noreply, state}
    end
  end

  def handle_info({:retry_request, run_id, kind, request_id, version}, state) do
    case safe_store_get(state.store, run_id) do
      {:ok, run} ->
        if request_current?(run, kind, request_id, version), do: drive(run, state)

      _other ->
        :ok
    end

    {:noreply, state}
  end

  defp resume_matching(requested, state) do
    case safe_store_get(state.store, requested.id) do
      {:ok, existing}
      when existing.objective_fingerprint == requested.objective_fingerprint and
             existing.max_revisions == requested.max_revisions ->
        {drive(existing, state), state}

      {:ok, _existing} ->
        {{:error, {:run_id_conflict, requested.id}}, state}

      :not_found ->
        {{:error, {:storage_error, :created_run_missing}}, state}

      {:error, reason} ->
        {{:error, {:storage_error, reason}}, state}
    end
  end

  defp reconcile_all(state) do
    case safe_store_list(state.store) do
      {:ok, runs} ->
        runs
        |> Enum.reject(&(&1.status in [:completed, :failed, :cancelled]))
        |> Enum.each(&drive(&1, state))

      _error ->
        :ok
    end

    state
  end

  defp drive(%Run{status: :planning} = run, state) do
    case fetch_previous_plan(run, state) do
      {:ok, previous_plan} ->
        enqueue_request(:planner, run, run.planner_request_id, previous_plan)
        {:ok, run}

      :not_found ->
        fail_run(run, {:previous_plan_missing, run.previous_plan_id}, state)

      {:error, reason} ->
        {:error, {:scheduler_error, reason}}
    end
  end

  defp drive(%Run{status: :submitting, pending_plan: %Plan{} = plan} = run, state) do
    case safe_scheduler_submit(state.scheduler, plan) do
      {:ok, scheduled_plan} ->
        adopt_submitted(run, scheduled_plan, state)

      {:error, :already_exists} ->
        case safe_scheduler_get(state.scheduler, plan.id) do
          {:ok, existing} -> adopt_submitted(run, existing, state)
          :not_found -> {:error, {:scheduler_inconsistent, plan.id}}
          {:error, reason} -> {:error, {:scheduler_error, reason}}
        end

      {:error, reason} ->
        {:error, {:scheduler_error, reason}}
    end
  end

  defp drive(%Run{status: :submitting} = run, state),
    do: fail_run(run, :missing_pending_plan, state)

  defp drive(%Run{status: :running, current_plan_id: plan_id} = run, state) do
    case safe_scheduler_get(state.scheduler, plan_id) do
      {:ok, %Plan{status: status}} when status in @terminal_plan_statuses ->
        evaluation_id = Run.request_id(run.id, :evaluate, run.revision)

        next =
          Run.transition(run, %{
            status: :evaluating,
            evaluation_id: evaluation_id,
            pending_plan: nil
          })

        with :ok <- safe_store_put(state.store, next), do: drive(next, state)

      {:ok, %Plan{}} ->
        {:ok, run}

      :not_found ->
        fail_run(run, {:scheduler_plan_missing, plan_id}, state)

      {:error, reason} ->
        {:error, {:scheduler_error, reason}}
    end
  end

  defp drive(%Run{status: :evaluating, current_plan_id: plan_id} = run, state) do
    with {:ok, %Plan{} = plan} <- scheduler_plan(state.scheduler, plan_id),
         :ok <- ensure_terminal(plan) do
      enqueue_request(:evaluator, run, run.evaluation_id, plan)
      {:ok, run}
    else
      :not_found -> fail_run(run, {:scheduler_plan_missing, plan_id}, state)
      {:error, reason} -> {:error, {:scheduler_error, reason}}
    end
  end

  defp drive(%Run{status: :cancelling, current_plan_id: nil} = run, state) do
    finish_cancellation(run, :not_submitted, state)
  end

  defp drive(%Run{status: :cancelling, current_plan_id: plan_id} = run, state) do
    reason = run.cancellation.reason

    case safe_scheduler_cancel(state.scheduler, plan_id, reason) do
      {:ok, %Plan{} = plan} ->
        finish_scheduler_cancellation(run, plan, state)

      {:error, reason} when reason in [:plan_not_found, :not_found] ->
        finish_cancellation(run, :not_submitted, state)

      {:error, {:terminal_plan, _status}} ->
        reconcile_terminal_cancellation(run, state)

      {:error, reason} ->
        {:error, {:scheduler_error, reason}}
    end
  end

  defp drive(%Run{status: status} = run, _state)
       when status in [:completed, :failed, :cancelled],
       do: {:ok, run}

  defp request_cancellation(%Run{status: :cancelling} = run, reason, state) do
    if run.cancellation.reason == reason,
      do: drive(run, state),
      else: {:error, {:cancellation_conflict, run.cancellation.reason}}
  end

  defp request_cancellation(%Run{status: :cancelled} = run, reason, _state) do
    if run.cancellation.reason == reason,
      do: {:ok, run},
      else: {:error, {:cancellation_conflict, run.cancellation.reason}}
  end

  defp request_cancellation(%Run{status: status}, _reason, _state)
       when status in [:completed, :failed],
       do: {:error, {:terminal_run, status}}

  defp request_cancellation(%Run{} = run, reason, state) do
    cancellation = %{
      status: :pending,
      reason: reason,
      requested_at: System.system_time(:millisecond),
      plan_id: run.current_plan_id
    }

    cancelling =
      Run.transition(run, %{
        status: :cancelling,
        pending_plan: nil,
        evaluation_id: nil,
        feedback: nil,
        decision: :cancelled,
        result: nil,
        failure: nil,
        cancellation: cancellation
      })

    case safe_store_put(state.store, cancelling) do
      :ok -> drive(cancelling, state)
      {:error, reason} -> {:error, {:storage_error, reason}}
    end
  end

  defp finish_scheduler_cancellation(run, %Plan{status: status} = plan, state)
       when status in @terminal_plan_statuses do
    case safe_scheduler_get(state.scheduler, plan.id) do
      {:ok, %Plan{status: current_status} = current}
      when current_status in @terminal_plan_statuses ->
        case execution_cancellation_evidence(current) do
          :pending ->
            {:ok, run}

          {:complete, evidence} ->
            disposition = if current.status == :cancelled, do: :cancelled, else: :already_terminal

            finish_cancellation(
              run,
              %{
                disposition: disposition,
                plan_status: current.status,
                plan_version: current.version,
                execution_cancellation: evidence
              },
              state
            )
        end

      {:ok, %Plan{status: current_status}} ->
        {:error, {:scheduler_did_not_cancel, current_status}}

      :not_found ->
        {:error, {:scheduler_inconsistent, plan.id}}

      {:error, reason} ->
        {:error, {:scheduler_error, reason}}
    end
  end

  defp finish_scheduler_cancellation(_run, %Plan{status: status}, _state),
    do: {:error, {:scheduler_did_not_cancel, status}}

  defp execution_cancellation_evidence(plan) do
    entries =
      Enum.flat_map(plan.step_order, fn step_id ->
        step = Map.fetch!(plan.steps, step_id)

        case step.cancellation do
          nil -> []
          cancellation -> [execution_cancellation_entry(step_id, cancellation)]
        end
      end)

    if Enum.any?(entries, &(&1.status == :pending)) do
      :pending
    else
      status =
        cond do
          Enum.any?(entries, &(&1.status == :unconfirmed)) -> :unconfirmed
          Enum.any?(entries, &(&1.status == :request_accepted)) -> :request_accepted
          true -> :no_active_execution
        end

      {:complete, %{status: status, steps: entries}}
    end
  end

  defp execution_cancellation_entry(step_id, %{status: :pending}) do
    %{step_id: step_id, status: :pending}
  end

  defp execution_cancellation_entry(step_id, %{status: :not_required}) do
    %{step_id: step_id, status: :no_active_execution}
  end

  defp execution_cancellation_entry(step_id, %{status: :completed, outcome: :ok}) do
    %{step_id: step_id, status: :request_accepted, outcome: :ok}
  end

  defp execution_cancellation_entry(step_id, %{status: :completed} = cancellation) do
    %{
      step_id: step_id,
      status: :unconfirmed,
      outcome: Serializable.safe(Map.get(cancellation, :outcome, :missing_outcome))
    }
  end

  defp execution_cancellation_entry(step_id, cancellation) do
    %{
      step_id: step_id,
      status: :unconfirmed,
      outcome: {:invalid_scheduler_evidence, Serializable.safe(cancellation)}
    }
  end

  defp reconcile_terminal_cancellation(run, state) do
    case safe_scheduler_get(state.scheduler, run.current_plan_id) do
      {:ok, %Plan{} = plan} -> finish_scheduler_cancellation(run, plan, state)
      :not_found -> {:error, {:scheduler_inconsistent, run.current_plan_id}}
      {:error, reason} -> {:error, {:scheduler_error, reason}}
    end
  end

  defp finish_cancellation(run, outcome, state) do
    cancellation =
      Map.merge(run.cancellation, %{
        status: :completed,
        finished_at: System.system_time(:millisecond),
        outcome: outcome
      })

    cancelled =
      Run.transition(run, %{
        status: :cancelled,
        cancellation: cancellation,
        decision: :cancelled,
        pending_plan: nil,
        evaluation_id: nil,
        result: nil,
        failure: nil
      })

    persist_transition(cancelled, state)
  end

  defp enqueue_request(kind, run, request_id, payload) do
    send(self(), {:launch_request, kind, run.id, request_id, run.version, payload})
  end

  defp maybe_launch_request(state, kind, run_id, request_id, version, payload) do
    key = {run_id, kind}

    case Map.get(state.requests, key) do
      %{request_id: ^request_id, version: ^version} ->
        state

      nil ->
        launch_request_if_current(state, kind, run_id, request_id, version, payload)

      _stale ->
        state
        |> stop_request(key)
        |> launch_request_if_current(kind, run_id, request_id, version, payload)
    end
  end

  defp launch_request_if_current(state, kind, run_id, request_id, version, payload) do
    case safe_store_get(state.store, run_id) do
      {:ok, run} ->
        if request_current?(run, kind, request_id, version) do
          launch_request(state, kind, run, request_id, version, payload)
        else
          state
        end

      _other ->
        state
    end
  end

  defp launch_request(state, kind, run, request_id, version, payload) do
    parent = self()
    adapter = if kind == :planner, do: state.planner, else: state.evaluator

    case Task.Supervisor.start_child(state.request_supervisor, fn ->
           result = execute_request(kind, adapter, run, payload)
           delivery_ref = make_ref()

           send(
             parent,
             {:control_request_result, self(), delivery_ref, kind, run.id, request_id, version,
              result}
           )

           receive do
             {:control_request_ack, ^delivery_ref} -> :ok
           after
             5_000 -> :ok
           end
         end) do
      {:ok, pid} ->
        track_request(state, pid, kind, run, request_id, version)

      {:error, _reason} ->
        Process.send_after(
          self(),
          {:retry_request, run.id, kind, request_id, version},
          state.poll_interval || 1_000
        )

        state
    end
  end

  defp track_request(state, pid, kind, run, request_id, version) do
    ref = Process.monitor(pid)
    key = {run.id, kind}

    request = %{
      pid: pid,
      ref: ref,
      kind: kind,
      run_id: run.id,
      request_id: request_id,
      version: version
    }

    %{
      state
      | requests: Map.put(state.requests, key, request),
        request_refs: Map.put(state.request_refs, ref, key)
    }
  end

  defp execute_request(:planner, adapter, run, previous_plan) do
    context = %{
      run_id: run.id,
      revision: run.revision,
      request_id: run.planner_request_id,
      feedback: run.feedback,
      previous_plan: previous_plan
    }

    invoke_planner(adapter, run.objective, context)
  end

  defp execute_request(:evaluator, adapter, run, plan) do
    context = %{
      run_id: run.id,
      revision: run.revision,
      evaluation_id: run.evaluation_id,
      objective: run.objective,
      plan: plan
    }

    invoke_evaluator(adapter, context)
  end

  defp accept_request_result(state, kind, run_id, request_id, version, result) do
    case safe_store_get(state.store, run_id) do
      {:ok, run} ->
        if request_current?(run, kind, request_id, version) do
          apply_request_result(kind, run, result, state)
        end

      _other ->
        :ok
    end

    state
  end

  defp apply_request_result(:planner, run, result, state) do
    apply_planner_result(run, result, state)
  end

  defp apply_request_result(:evaluator, run, result, state) do
    with {:ok, %Plan{} = plan} <- scheduler_plan(state.scheduler, run.current_plan_id),
         :ok <- ensure_terminal(plan) do
      apply_evaluator_result(run, plan, result, state)
    else
      :not_found -> fail_run(run, {:scheduler_plan_missing, run.current_plan_id}, state)
      {:error, _reason} -> :ok
    end
  end

  defp request_current?(
         %Run{
           status: :planning,
           planner_request_id: request_id,
           version: version
         },
         :planner,
         request_id,
         version
       ),
       do: true

  defp request_current?(
         %Run{
           status: :evaluating,
           evaluation_id: request_id,
           version: version
         },
         :evaluator,
         request_id,
         version
       ),
       do: true

  defp request_current?(_run, _kind, _request_id, _version), do: false

  defp stop_run_requests(state, run_id) do
    state.requests
    |> Map.keys()
    |> Enum.filter(fn {request_run_id, _kind} -> request_run_id == run_id end)
    |> Enum.reduce(state, &stop_request(&2, &1))
  end

  defp stop_request(state, key) do
    case Map.get(state.requests, key) do
      nil ->
        state

      %{pid: pid} ->
        Process.exit(pid, :kill)
        drop_request(state, key, true)
    end
  end

  defp drop_request(state, key, demonitor?) do
    case Map.pop(state.requests, key) do
      {nil, _requests} ->
        state

      {%{ref: ref}, requests} ->
        if demonitor?, do: Process.demonitor(ref, [:flush])

        %{
          state
          | requests: requests,
            request_refs: Map.delete(state.request_refs, ref)
        }
    end
  end

  defp apply_planner_result(run, {:ok, output}, state) do
    with {:ok, plan} <-
           normalize_plan(run.id, run.revision, run.planner_request_id, output),
         next <-
           Run.transition(run, %{
             status: :submitting,
             current_plan_id: plan.id,
             pending_plan: plan,
             evaluation_id: nil,
             decision: nil,
             failure: nil
           }),
         :ok <- safe_store_put(state.store, next) do
      drive(next, state)
    else
      {:error, reason} -> fail_run(run, {:invalid_plan, Serializable.safe(reason)}, state)
    end
  end

  defp apply_planner_result(run, {:error, reason}, state) do
    fail_run(run, {:planner_failed, Serializable.safe(reason)}, state)
  end

  defp apply_evaluator_result(run, plan, {:ok, decision}, state) do
    apply_decision(run, plan, normalize_decision(decision), state)
  end

  defp apply_evaluator_result(run, _plan, {:error, reason}, state) do
    fail_run(run, {:evaluator_failed, Serializable.safe(reason)}, state)
  end

  defp adopt_submitted(run, plan, state) do
    if owned_plan?(plan, run) do
      next = Run.transition(run, %{status: :running, pending_plan: nil})

      with :ok <- safe_store_put(state.store, next), do: drive(next, state)
    else
      fail_run(run, {:plan_id_collision, plan.id}, state)
    end
  end

  defp apply_decision(run, plan, {:ok, :accept, result, evidence_contract}, state) do
    entry = history_entry(run, plan, :accept, result, evidence_contract)

    complete =
      Run.transition(run, %{
        status: :completed,
        decision: :accept,
        result: result,
        evidence_contract: evidence_contract,
        feedback: nil,
        history: run.history ++ [entry]
      })

    persist_transition(complete, state)
  end

  defp apply_decision(run, plan, {:ok, :accept, result}, state) do
    entry = history_entry(run, plan, :accept, result)

    complete =
      Run.transition(run, %{
        status: :completed,
        decision: :accept,
        result: result,
        feedback: nil,
        history: run.history ++ [entry]
      })

    persist_transition(complete, state)
  end

  defp apply_decision(run, plan, {:ok, :fail, reason}, state) do
    entry = history_entry(run, plan, :fail, reason)
    fail_run(run, {:evaluation_failed, reason}, state, run.history ++ [entry])
  end

  defp apply_decision(run, plan, {:ok, :revise, feedback}, state) do
    entry = history_entry(run, plan, :revise, feedback)
    history = run.history ++ [entry]

    if run.revision < run.max_revisions do
      revision = run.revision + 1

      revised =
        Run.transition(run, %{
          status: :planning,
          revision: revision,
          planner_request_id: Run.request_id(run.id, :plan, revision),
          evaluation_id: nil,
          previous_plan_id: plan.id,
          current_plan_id: nil,
          pending_plan: nil,
          feedback: feedback,
          decision: :revise,
          history: history
        })

      with :ok <- safe_store_put(state.store, revised), do: drive(revised, state)
    else
      fail_run(
        run,
        {:revision_budget_exhausted, run.max_revisions, feedback},
        state,
        history
      )
    end
  end

  defp apply_decision(run, _plan, {:error, reason}, state) do
    fail_run(run, {:invalid_evaluator_decision, Serializable.safe(reason)}, state)
  end

  defp build_plan(run_id, revision, planner_request_id, specs) do
    fingerprint = Run.fingerprint(fingerprint_specs(specs))

    Plan.new(Run.plan_id(run_id, revision), specs,
      metadata: %{
        control_run_id: run_id,
        control_revision: revision,
        control_plan_fingerprint: fingerprint,
        planner_request_id: planner_request_id
      }
    )
  end

  # The fingerprint covers exactly what is recomputed from the durable plan:
  # id, dependencies, input, and metadata. Kind is deliberately not part of it.
  # A control-produced plan's kind is already determined by the input schema its
  # validation enforced — a coding step cannot carry a forge input, or the other
  # way round — so including it would add no discrimination while changing the
  # fingerprint of every run checkpointed by an earlier build.
  defp fingerprint_specs(specs) do
    Enum.map(specs, fn spec ->
      %{
        id: spec.id,
        dependencies: spec.dependencies,
        input: spec.input,
        metadata: spec.metadata
      }
    end)
  end

  defp owned_plan?(%Plan{} = plan, run) do
    plan.id == run.current_plan_id and
      plan.metadata[:control_run_id] == run.id and
      plan.metadata[:control_revision] == run.revision and
      plan.metadata[:control_plan_fingerprint] == plan_fingerprint(plan)
  end

  defp plan_fingerprint(plan) do
    specs =
      Enum.map(plan.step_order, fn id ->
        step = Map.fetch!(plan.steps, id)

        %{
          id: step.id,
          dependencies: step.dependencies,
          input: step.input,
          metadata: step.metadata
        }
      end)

    Run.fingerprint(specs)
  end

  defp normalize_plan_output(%{steps: steps}), do: normalize_step_specs(steps)
  defp normalize_plan_output(%{"steps" => steps}), do: normalize_step_specs(steps)
  defp normalize_plan_output(steps) when is_list(steps), do: normalize_step_specs(steps)
  defp normalize_plan_output(_other), do: {:error, :invalid_planner_output}

  defp normalize_step_specs(steps) when is_list(steps) do
    Enum.reduce_while(steps, {:ok, []}, fn spec, {:ok, acc} ->
      case normalize_step_spec(spec) do
        {:ok, normalized} -> {:cont, {:ok, acc ++ [normalized]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp normalize_step_specs(_other), do: {:error, :invalid_steps}

  defp normalize_step_spec(spec) when is_list(spec) do
    if Keyword.keyword?(spec),
      do: normalize_step_spec(Map.new(spec)),
      else: {:error, :invalid_step}
  end

  defp normalize_step_spec(spec) when is_map(spec) do
    allowed = ["id", "dependencies", "input", "metadata", :id, :dependencies, :input, :metadata]
    allowed = if forge_steps_allowed?(), do: ["kind", :kind | allowed], else: allowed

    if Enum.any?(Map.keys(spec), &(&1 not in allowed)) do
      {:error, :unknown_step_field}
    else
      with {:ok, kind} <- Step.normalize_kind(field(spec, :kind)) do
        normalized = %{
          id: field(spec, :id),
          dependencies: field(spec, :dependencies, []),
          input: field(spec, :input),
          metadata: field(spec, :metadata, %{})
        }

        {:ok, put_step_kind(normalized, kind)}
      end
    end
  end

  defp normalize_step_spec(_other), do: {:error, :invalid_step}

  # A coding step's spec keeps exactly the shape it has always had, so the plan
  # fingerprint of an in-flight run written by an earlier build still matches
  # after this upgrade. Only a non-default kind adds a key.
  defp put_step_kind(spec, :coding), do: spec
  defp put_step_kind(spec, kind), do: Map.put(spec, :kind, kind)

  defp validate_executable_steps(specs) do
    Enum.reduce_while(specs, :ok, fn spec, :ok ->
      case Map.get(spec, :kind, :coding) do
        :coding -> validate_coding_step(spec)
        kind -> validate_planned_step(kind, spec)
      end
    end)
  end

  defp validate_coding_step(spec) do
    input = spec.input
    objective = if is_map(input), do: field(input, :objective)

    cond do
      not is_binary(objective) or String.trim(objective) == "" ->
        {:halt, {:error, {:objective_required, spec.id}}}

      MapSet.new(Map.keys(input)) not in [MapSet.new([:objective]), MapSet.new(["objective"])] ->
        {:halt, {:error, {:runtime_policy_not_allowed, spec.id}}}

      map_size(spec.metadata) > 0 ->
        {:halt, {:error, {:runtime_policy_not_allowed, spec.id}}}

      true ->
        {:cont, :ok}
    end
  end

  # The gate is re-checked on the accepted plan, not only where the field was
  # parsed, so no future normalization path can smuggle a kind past a disabled
  # flag. Input rules are the plan's own, so both entry points agree by
  # construction.
  defp validate_planned_step(kind, spec) do
    cond do
      not forge_steps_allowed?() ->
        {:halt, {:error, {:step_kind_not_allowed, spec.id, kind}}}

      map_size(spec.metadata) > 0 ->
        {:halt, {:error, {:runtime_policy_not_allowed, spec.id}}}

      true ->
        case Step.validate_input(kind, spec.input) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, {:invalid_step_input, spec.id, reason}}}
        end
    end
  end

  defp forge_steps_allowed?,
    do: Application.get_env(:ouroboros, :control_allow_forge_steps, false) == true

  defp normalize_decision(:accept), do: {:ok, :accept, :accepted}
  defp normalize_decision({:accept, result}), do: serializable_decision(:accept, result)

  defp normalize_decision({:accept, result, evidence_contract}) do
    with {:ok, result} <- serializable_value(result),
         {:ok, evidence_contract} <- EvidenceContract.normalize(evidence_contract) do
      {:ok, :accept, result, evidence_contract}
    else
      {:error, :unserializable_decision} = error -> error
      {:error, reason} -> {:error, {:invalid_evidence_contract, Serializable.safe(reason)}}
    end
  end

  defp normalize_decision({:revise, feedback}), do: serializable_decision(:revise, feedback)
  defp normalize_decision({:fail, reason}), do: serializable_decision(:fail, reason)

  defp normalize_decision(%{} = decision) do
    case {field(decision, :decision), field(decision, :feedback), field(decision, :result)} do
      {value, feedback, _result} when value in [:revise, "revise"] ->
        serializable_decision(:revise, feedback)

      {value, _feedback, result} when value in [:accept, "accept"] ->
        serializable_decision(:accept, result || :accepted)

      {value, feedback, _result} when value in [:fail, "fail"] ->
        serializable_decision(:fail, feedback)

      _other ->
        {:error, :invalid_decision}
    end
  end

  defp normalize_decision(_other), do: {:error, :invalid_decision}

  defp serializable_decision(kind, value) do
    case serializable_value(value) do
      {:ok, value} -> {:ok, kind, value}
      {:error, _reason} = error -> error
    end
  end

  defp serializable_value(value) do
    if Serializable.valid?(value),
      do: {:ok, value},
      else: {:error, :unserializable_decision}
  end

  defp history_entry(run, plan, decision, detail, evidence_contract \\ nil) do
    entry = %{
      revision: run.revision,
      plan_id: plan.id,
      plan_status: plan.status,
      evaluation_id: run.evaluation_id,
      decision: decision,
      detail: detail,
      evaluated_at: System.system_time(:millisecond)
    }

    if evidence_contract do
      {:ok, digest} = EvidenceContract.digest(evidence_contract)
      Map.put(entry, :evidence_contract_digest, digest)
    else
      entry
    end
  end

  defp fail_run(run, failure, state, history \\ nil) do
    failed =
      Run.transition(run, %{
        status: :failed,
        failure: failure,
        decision: :fail,
        pending_plan: nil,
        history: history || run.history
      })

    persist_transition(failed, state)
  end

  defp persist_transition(run, state) do
    case safe_store_put(state.store, run) do
      :ok -> {:ok, run}
      {:error, reason} -> {:error, {:storage_error, reason}}
    end
  end

  defp fetch_previous_plan(%Run{previous_plan_id: nil}, _state), do: {:ok, nil}

  defp fetch_previous_plan(%Run{previous_plan_id: id}, state) do
    safe_scheduler_get(state.scheduler, id)
  end

  defp scheduler_plan(scheduler, id), do: safe_scheduler_get(scheduler, id)

  defp ensure_terminal(%Plan{status: status}) when status in @terminal_plan_statuses, do: :ok
  defp ensure_terminal(%Plan{}), do: {:error, :plan_not_terminal}

  defp invoke_planner({module, opts}, objective, context) do
    safe_callback(fn -> module.plan(objective, context, opts) end)
  end

  defp invoke_evaluator({module, opts}, context) do
    safe_callback(fn -> module.evaluate(context, opts) end)
  end

  defp safe_callback(callback) do
    case callback.() do
      {:ok, _value} = ok -> ok
      {:error, _reason} = error -> error
      other -> {:error, {:invalid_callback_return, Serializable.safe(other)}}
    end
  rescue
    error -> {:error, {:callback_exception, error.__struct__}}
  catch
    kind, _reason -> {:error, {:callback_exit, kind}}
  end

  defp safe_scheduler_submit(server, plan),
    do: safe_call(fn -> Scheduler.submit(server, plan) end)

  defp safe_scheduler_get(server, id), do: safe_call(fn -> Scheduler.get(server, id) end)

  defp safe_scheduler_cancel(server, id, reason),
    do: safe_call(fn -> Scheduler.cancel(server, id, reason) end)

  defp safe_store_create(server, run), do: safe_call(fn -> Store.create(server, run) end)
  defp safe_store_put(server, run), do: safe_call(fn -> Store.put(server, run) end)
  defp safe_store_get(server, id), do: safe_call(fn -> Store.get(server, id) end)
  defp safe_store_list(server), do: safe_call(fn -> Store.list(server) end)

  defp safe_call(fun) do
    fun.()
  catch
    :exit, reason -> {:error, {:unavailable, Serializable.safe(reason)}}
  end

  defp validate_cancellation_request(id, reason) do
    cond do
      not Plan.valid_id?(id) -> {:error, {:invalid_id, id}}
      not Serializable.valid?(reason) -> {:error, :unserializable_cancellation_reason}
      true -> :ok
    end
  end

  defp fetch_control_run(store, id) do
    case safe_store_get(store, id) do
      {:ok, run} -> {:ok, run}
      :not_found -> {:error, :not_found}
      {:error, reason} -> {:error, {:storage_error, reason}}
    end
  end

  defp normalize_adapter({module, opts}, function, arity)
       when is_atom(module) and is_list(opts) do
    cond do
      not Keyword.keyword?(opts) -> {:error, {:invalid_adapter_options, module}}
      not Code.ensure_loaded?(module) -> {:error, {:adapter_not_loaded, module}}
      not function_exported?(module, function, arity) -> {:error, {:invalid_adapter, module}}
      true -> {:ok, {module, opts}}
    end
  end

  defp normalize_adapter(nil, function, _arity), do: {:error, {:adapter_required, function}}

  defp normalize_adapter(module, function, arity) when is_atom(module),
    do: normalize_adapter({module, []}, function, arity)

  defp normalize_adapter(other, _function, _arity), do: {:error, {:invalid_adapter, other}}

  defp normalize_poll_interval(false), do: {:ok, false}

  defp normalize_poll_interval(interval) when is_integer(interval) and interval > 0,
    do: {:ok, interval}

  defp normalize_poll_interval(_other), do: {:error, :invalid_poll_interval}

  defp schedule_poll(%{poll_interval: false} = state), do: state
  defp schedule_poll(%{timer: timer} = state) when is_reference(timer), do: state

  defp schedule_poll(state) do
    %{state | timer: Process.send_after(self(), :poll, state.poll_interval)}
  end

  defp validate_options(opts) do
    cond do
      not is_list(opts) or not Keyword.keyword?(opts) ->
        {:error, :invalid_options}

      unknown = Enum.find(Keyword.keys(opts), &(&1 not in @allowed_options)) ->
        {:error, {:unknown_option, unknown}}

      true ->
        :ok
    end
  end

  defp field(map, key, default \\ nil) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key), default)
    end
  end

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
