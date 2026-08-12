defmodule Ouroboros.Orchestration.Scheduler do
  @moduledoc """
  Durable dependency scheduler with explicit execution leases.

  The scheduler persists every state transition before invoking an executor.
  Runtime owner PIDs and monitors remain private. If a scheduler or owner dies,
  `:running` steps become `:ready` and are offered again with the same durable
  token, allowing an adapter to reconnect instead of starting duplicate work.

  Failure is fail-fast: descendants become `:blocked`; other unfinished work is
  cancelled, and running sibling executions receive the optional asynchronous
  executor cancellation callback.
  """

  use GenServer

  alias Ouroboros.Orchestration.{Execution, Plan, Serializable, Step, Store}

  @default_cancel_timeout 5_000
  @terminal_states [:completed, :failed, :cancelled, :blocked]

  @type server :: GenServer.server()

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name_option(name))
  end

  @spec submit(server(), Plan.t()) :: {:ok, Plan.t()} | {:error, term()}
  def submit(server \\ __MODULE__, %Plan{} = plan), do: GenServer.call(server, {:submit, plan})

  @spec get(server(), String.t()) :: {:ok, Plan.t()} | :not_found
  def get(server \\ __MODULE__, plan_id), do: GenServer.call(server, {:get, plan_id})

  @spec list(server()) :: {:ok, [Plan.t()]}
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @spec ready(server()) :: {:ok, [Execution.t()]}
  def ready(server \\ __MODULE__), do: GenServer.call(server, :ready)

  @spec execution(server(), String.t(), String.t()) ::
          {:ok, Execution.t()} | {:error, term()} | :not_found
  def execution(server \\ __MODULE__, plan_id, step_id) do
    GenServer.call(server, {:execution, plan_id, step_id})
  end

  @spec start(String.t(), String.t()) :: {:ok, Execution.t()} | {:error, term()}
  def start(plan_id, step_id) when is_binary(plan_id) and is_binary(step_id) do
    start(__MODULE__, plan_id, step_id, [])
  end

  @spec start(String.t(), String.t(), keyword()) ::
          {:ok, Execution.t()} | {:error, term()}
  def start(plan_id, step_id, opts)
      when is_binary(plan_id) and is_binary(step_id) and is_list(opts) do
    start(__MODULE__, plan_id, step_id, opts)
  end

  @spec start(server(), String.t(), String.t()) ::
          {:ok, Execution.t()} | {:error, term()}
  def start(server, plan_id, step_id), do: start(server, plan_id, step_id, [])

  @spec start(server(), String.t(), String.t(), keyword()) ::
          {:ok, Execution.t()} | {:error, term()}
  def start(server, plan_id, step_id, opts) do
    GenServer.call(server, {:start, plan_id, step_id, opts})
  end

  @spec complete(server(), String.t(), String.t(), String.t(), term()) ::
          {:ok, Plan.t()} | {:error, term()}
  def complete(server \\ __MODULE__, plan_id, step_id, token, result) do
    GenServer.call(server, {:complete, plan_id, step_id, token, result})
  end

  @spec fail(server(), String.t(), String.t(), String.t(), term()) ::
          {:ok, Plan.t()} | {:error, term()}
  def fail(server \\ __MODULE__, plan_id, step_id, token, reason) do
    GenServer.call(server, {:fail, plan_id, step_id, token, reason})
  end

  @spec cancel(String.t()) :: {:ok, Plan.t()} | {:error, term()}
  def cancel(plan_id) when is_binary(plan_id), do: cancel(__MODULE__, plan_id, :cancelled)

  @spec cancel(String.t(), term()) :: {:ok, Plan.t()} | {:error, term()}
  def cancel(plan_id, reason) when is_binary(plan_id), do: cancel(__MODULE__, plan_id, reason)

  @spec cancel(server(), String.t()) :: {:ok, Plan.t()} | {:error, term()}
  def cancel(server, plan_id), do: cancel(server, plan_id, :cancelled)

  @spec cancel(server(), String.t(), term()) :: {:ok, Plan.t()} | {:error, term()}
  def cancel(server, plan_id, reason) do
    GenServer.call(server, {:cancel, plan_id, reason})
  end

  @impl true
  def init(opts) do
    with :ok <- validate_options(opts),
         {:ok, max_concurrency} <- positive_integer(Keyword.get(opts, :max_concurrency, 4)),
         {:ok, cancel_timeout} <-
           positive_integer(Keyword.get(opts, :cancel_timeout, @default_cancel_timeout)),
         {:ok, executor} <- normalize_executor(Keyword.get(opts, :executor)),
         store <- Keyword.get(opts, :store, Store),
         callback_server <- Keyword.get(opts, :name, __MODULE__) || self(),
         {:ok, plans} <- safe_store_list(store),
         :ok <- recover_running(plans, store) do
      state = %{
        store: store,
        callback_server: callback_server,
        max_concurrency: max_concurrency,
        cancel_timeout: cancel_timeout,
        executor: executor,
        owner_refs: %{},
        owners: %{},
        cancellation_ops: %{},
        cancellation_refs: %{}
      }

      {:ok, state, {:continue, :resume}}
    else
      {:error, reason} -> {:stop, reason}
    end
  rescue
    error -> {:stop, {:invalid_scheduler_options, Exception.message(error)}}
  catch
    :exit, reason -> {:stop, {:orchestration_store_unavailable, reason}}
  end

  @impl true
  def handle_continue(:resume, state) do
    state = resume_pending_cancellations(state)
    {:noreply, dispatch_available(state)}
  end

  @impl true
  def handle_call({:submit, %Plan{} = plan}, _from, state) do
    case Store.create(state.store, plan) do
      :ok ->
        state = dispatch_available(state)
        {:reply, Store.get(state.store, plan.id), state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:get, plan_id}, _from, state) do
    {:reply, Store.get(state.store, plan_id), state}
  end

  def handle_call(:list, _from, state) do
    {:reply, Store.list(state.store), state}
  end

  def handle_call(:ready, _from, state) do
    executions =
      state.store
      |> ready_steps()
      |> Enum.map(fn {plan, step} -> execution_from(plan, step, step.execution_token != nil) end)

    {:reply, {:ok, executions}, state}
  end

  def handle_call({:execution, plan_id, step_id}, _from, state) do
    reply =
      with {:ok, plan} <- Store.get(state.store, plan_id),
           {:ok, step} <- fetch_step(plan, step_id) do
        {:ok, execution_from(plan, step, step.state == :ready and step.execution_token != nil)}
      end

    {:reply, reply, state}
  end

  def handle_call({:start, plan_id, step_id, opts}, _from, state) do
    with :ok <- validate_start_options(opts),
         :ok <- ensure_capacity(state),
         {:ok, plan} <- fetch_plan(state.store, plan_id),
         {:ok, step} <- fetch_step(plan, step_id),
         {:ok, updated_plan, execution} <- claim(plan, step),
         :ok <- Store.put(state.store, updated_plan) do
      state = monitor_owner(state, execution, Keyword.get(opts, :owner))
      {:reply, {:ok, execution}, state}
    else
      :not_found -> {:reply, {:error, :plan_not_found}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:complete, plan_id, step_id, token, result}, _from, state) do
    with true <- Serializable.valid?(result) or {:error, :unserializable_result},
         {:ok, plan} <- fetch_plan(state.store, plan_id),
         {:ok, step} <- fetch_step(plan, step_id),
         {:ok, updated_plan, transition} <- complete_step(plan, step, token, result),
         :ok <- persist_if_changed(state.store, plan, updated_plan) do
      state = if transition == :changed, do: clear_owner(state, plan_id, step_id), else: state
      state = dispatch_available(state)
      {:reply, {:ok, updated_plan}, state}
    else
      :not_found -> {:reply, {:error, :plan_not_found}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:fail, plan_id, step_id, token, reason}, _from, state) do
    reason = Serializable.safe(reason)

    with {:ok, plan} <- fetch_plan(state.store, plan_id),
         {:ok, step} <- fetch_step(plan, step_id),
         {:ok, updated_plan, transition, cancellations} <- fail_step(plan, step, token, reason),
         :ok <- persist_if_changed(state.store, plan, updated_plan) do
      state = if transition == :changed, do: clear_owner(state, plan_id, step_id), else: state
      state = clear_cancelled_owners(state, cancellations)
      state = launch_cancellations(state, cancellations)
      state = dispatch_available(state)
      {:reply, {:ok, updated_plan}, state}
    else
      :not_found -> {:reply, {:error, :plan_not_found}, state}
      {:error, error} -> {:reply, {:error, error}, state}
    end
  end

  def handle_call({:cancel, plan_id, reason}, _from, state) do
    reason = Serializable.safe(reason)

    with {:ok, plan} <- fetch_plan(state.store, plan_id),
         {:ok, updated_plan, cancellations} <- cancel_plan(plan, reason),
         :ok <- persist_if_changed(state.store, plan, updated_plan) do
      state = clear_cancelled_owners(state, cancellations)
      state = launch_cancellations(state, cancellations)
      state = dispatch_available(state)
      {:reply, {:ok, updated_plan}, state}
    else
      :not_found -> {:reply, {:error, :plan_not_found}, state}
      {:error, error} -> {:reply, {:error, error}, state}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    cond do
      execution = Map.get(state.owner_refs, ref) ->
        state = drop_owner_ref(state, ref, execution)
        {:noreply, recover_owner_execution(state, execution, reason)}

      operation_id = Map.get(state.cancellation_refs, ref) ->
        state = %{state | cancellation_refs: Map.delete(state.cancellation_refs, ref)}

        if Map.has_key?(state.cancellation_ops, operation_id) do
          Process.send_after(self(), {:missing_cancel_result, operation_id, reason}, 0)
        end

        {:noreply, state}

      true ->
        {:noreply, state}
    end
  end

  def handle_info({:cancel_result, operation_id, result}, state) do
    case Map.get(state.cancellation_ops, operation_id) do
      nil ->
        {:noreply, state}

      operation ->
        state =
          finish_cancellation_operation(state, operation_id, operation, Serializable.safe(result))

        {:noreply, state}
    end
  end

  def handle_info({:cancel_timeout, operation_id}, state) do
    case Map.get(state.cancellation_ops, operation_id) do
      nil ->
        {:noreply, state}

      operation ->
        Process.exit(operation.pid, :kill)
        state = finish_cancellation_operation(state, operation_id, operation, {:error, :timeout})
        {:noreply, state}
    end
  end

  def handle_info({:missing_cancel_result, operation_id, reason}, state) do
    case Map.get(state.cancellation_ops, operation_id) do
      nil ->
        {:noreply, state}

      operation ->
        outcome = {:error, {:callback_exited, Serializable.safe(reason)}}
        state = finish_cancellation_operation(state, operation_id, operation, outcome)
        {:noreply, state}
    end
  end

  defp dispatch_available(%{executor: nil} = state), do: state

  defp dispatch_available(state) do
    if running_count(state.store) < state.max_concurrency do
      case ready_steps(state.store) do
        [] -> state
        [{plan, step} | _rest] -> dispatch_step(state, plan, step)
      end
    else
      state
    end
  end

  defp dispatch_step(state, plan, step) do
    with {:ok, updated_plan, execution} <- claim(plan, step),
         :ok <- Store.put(state.store, updated_plan) do
      case invoke_start(state.executor, execution, state.callback_server) do
        {:ok, owner} when is_pid(owner) ->
          state
          |> monitor_owner(execution, owner)
          |> dispatch_available()

        :ok ->
          dispatch_available(state)

        {:error, reason} ->
          fail_dispatched_execution(state, updated_plan, execution, reason)

        other ->
          fail_dispatched_execution(
            state,
            updated_plan,
            execution,
            {:invalid_executor_return, other}
          )
      end
    else
      {:error, _reason} -> state
    end
  end

  defp fail_dispatched_execution(state, plan, execution, reason) do
    step = Map.fetch!(plan.steps, execution.step_id)
    reason = {:executor_start_failed, Serializable.safe(reason)}

    case fail_step(plan, step, execution.token, reason) do
      {:ok, failed_plan, :changed, cancellations} ->
        case Store.put(state.store, failed_plan) do
          :ok ->
            state
            |> clear_cancelled_owners(cancellations)
            |> launch_cancellations(cancellations)
            |> dispatch_available()

          {:error, _reason} ->
            state
        end

      _other ->
        state
    end
  end

  defp recover_owner_execution(state, execution, reason) do
    with {:ok, plan} <- fetch_plan(state.store, execution.plan_id),
         {:ok, %Step{state: :running, execution_token: token} = step} <-
           fetch_step(plan, execution.step_id),
         true <- token == execution.token,
         updated_step <- %{
           step
           | state: :ready,
             error: {:owner_down, Serializable.safe(reason)},
             started_at: nil
         },
         updated_plan <- update_step(plan, updated_step),
         :ok <- Store.put(state.store, updated_plan) do
      dispatch_available(state)
    else
      _other -> dispatch_available(state)
    end
  end

  defp claim(plan, %Step{state: :ready} = step) do
    recovered? = step.execution_token != nil
    token = step.execution_token || new_token()
    attempt = if recovered?, do: step.attempt, else: step.attempt + 1

    updated_step = %{
      step
      | state: :running,
        execution_token: token,
        attempt: attempt,
        error: nil,
        started_at: System.system_time(:millisecond)
    }

    updated_plan = update_step(plan, updated_step)
    {:ok, updated_plan, execution_from(updated_plan, updated_step, recovered?)}
  end

  defp claim(_plan, %Step{state: state}), do: {:error, {:step_not_ready, state}}

  defp complete_step(plan, step, token, result) do
    cond do
      step.state == :completed and step.execution_token == token and step.result == result ->
        {:ok, plan, :idempotent}

      step.state == :completed and step.execution_token == token ->
        {:error, :completion_conflict}

      step.state not in [:running, :ready] ->
        {:error, {:invalid_step_state, step.state}}

      is_nil(step.execution_token) or step.execution_token != token ->
        {:error, :stale_execution_token}

      true ->
        updated_step = %{
          step
          | state: :completed,
            result: result,
            error: nil,
            finished_at: System.system_time(:millisecond)
        }

        plan = plan |> update_step(updated_step) |> unlock_dependents()
        {:ok, plan, :changed}
    end
  end

  defp fail_step(plan, step, token, reason) do
    cond do
      step.state == :failed and step.execution_token == token and step.error == reason ->
        {:ok, plan, :idempotent, []}

      step.state == :failed and step.execution_token == token ->
        {:error, :failure_conflict}

      step.state not in [:running, :ready] ->
        {:error, {:invalid_step_state, step.state}}

      is_nil(step.execution_token) or step.execution_token != token ->
        {:error, :stale_execution_token}

      true ->
        now = System.system_time(:millisecond)
        descendants = descendants(plan, step.id)

        failed_step = %{step | state: :failed, error: reason, finished_at: now}
        plan = put_step_without_touch(plan, failed_step)

        {plan, cancellations} =
          Enum.reduce(plan.step_order, {plan, []}, fn id, {current_plan, cancelled} ->
            current = Map.fetch!(current_plan.steps, id)

            cond do
              id == step.id or current.state in @terminal_states ->
                {current_plan, cancelled}

              MapSet.member?(descendants, id) ->
                blocked = %{
                  current
                  | state: :blocked,
                    blocked_by: Enum.uniq(current.blocked_by ++ [step.id]),
                    error: {:dependency_failed, step.id},
                    finished_at: now
                }

                {put_step_without_touch(current_plan, blocked), cancelled}

              true ->
                {cancelled_step, maybe_execution} =
                  cancel_step(current_plan, current, {:plan_failed, step.id}, now)

                cancelled = if maybe_execution, do: [maybe_execution | cancelled], else: cancelled
                {put_step_without_touch(current_plan, cancelled_step), cancelled}
            end
          end)

        plan = %{
          plan
          | failure: %{step_id: step.id, reason: reason, at: now},
            updated_at: now,
            version: plan.version + 1
        }

        {:ok, derive_status(plan), :changed, Enum.reverse(cancellations)}
    end
  end

  defp cancel_plan(%Plan{status: :cancelled} = plan, _reason), do: {:ok, plan, []}

  defp cancel_plan(%Plan{status: status}, _reason) when status in [:completed, :failed, :blocked],
    do: {:error, {:terminal_plan, status}}

  defp cancel_plan(plan, reason) do
    now = System.system_time(:millisecond)

    {plan, cancellations} =
      Enum.reduce(plan.step_order, {plan, []}, fn id, {current_plan, cancelled} ->
        step = Map.fetch!(current_plan.steps, id)

        if step.state in [:pending, :ready, :running] do
          {cancelled_step, maybe_execution} = cancel_step(current_plan, step, reason, now)
          cancelled = if maybe_execution, do: [maybe_execution | cancelled], else: cancelled
          {put_step_without_touch(current_plan, cancelled_step), cancelled}
        else
          {current_plan, cancelled}
        end
      end)

    plan = %{
      plan
      | cancellation: %{reason: reason, at: now},
        status: :cancelled,
        updated_at: now,
        version: plan.version + 1
    }

    {:ok, plan, Enum.reverse(cancellations)}
  end

  defp cancel_step(plan, step, reason, now) do
    execution_active? = step.state == :running or is_binary(step.execution_token)

    cancellation = %{
      status: if(execution_active?, do: :pending, else: :not_required),
      reason: reason,
      requested_at: now
    }

    execution =
      if execution_active?,
        do: execution_from(plan, step, step.state == :ready),
        else: nil

    {%{
       step
       | state: :cancelled,
         error: {:cancelled, reason},
         cancellation: cancellation,
         finished_at: now
     }, execution}
  end

  defp unlock_dependents(plan) do
    steps =
      Enum.reduce(plan.step_order, plan.steps, fn id, steps ->
        step = Map.fetch!(steps, id)

        if step.state == :pending and
             Enum.all?(step.dependencies, &(Map.fetch!(steps, &1).state == :completed)) do
          Map.put(steps, id, %{step | state: :ready})
        else
          steps
        end
      end)

    plan |> Map.put(:steps, steps) |> derive_status()
  end

  defp descendants(plan, root_id) do
    dependents =
      Enum.reduce(plan.steps, %{}, fn {id, step}, acc ->
        Enum.reduce(step.dependencies, acc, fn dependency, nested ->
          Map.update(nested, dependency, [id], &[id | &1])
        end)
      end)

    collect_descendants(Map.get(dependents, root_id, []), dependents, MapSet.new())
  end

  defp collect_descendants([], _dependents, seen), do: seen

  defp collect_descendants([id | rest], dependents, seen) do
    if MapSet.member?(seen, id) do
      collect_descendants(rest, dependents, seen)
    else
      collect_descendants(rest ++ Map.get(dependents, id, []), dependents, MapSet.put(seen, id))
    end
  end

  defp update_step(plan, step) do
    plan
    |> put_step_without_touch(step)
    |> touch()
    |> derive_status()
  end

  defp put_step_without_touch(plan, step), do: %{plan | steps: Map.put(plan.steps, step.id, step)}

  defp touch(plan) do
    %{plan | updated_at: System.system_time(:millisecond), version: plan.version + 1}
  end

  defp derive_status(%Plan{cancellation: cancellation} = plan) when not is_nil(cancellation),
    do: %{plan | status: :cancelled}

  defp derive_status(%Plan{failure: failure} = plan) when not is_nil(failure),
    do: %{plan | status: :failed}

  defp derive_status(plan) do
    states = Map.values(plan.steps) |> Enum.map(& &1.state)

    status =
      cond do
        Enum.all?(states, &(&1 == :completed)) -> :completed
        :running in states -> :running
        :ready in states -> :ready
        Enum.all?(states, &(&1 in @terminal_states)) and :blocked in states -> :blocked
        true -> :pending
      end

    %{plan | status: status}
  end

  defp execution_from(plan, step, recovered?) do
    %Execution{
      plan_id: plan.id,
      step_id: step.id,
      token: step.execution_token,
      input: step.input,
      attempt: step.attempt,
      state: step.state,
      metadata: %{plan: plan.metadata, step: step.metadata},
      recovered?: recovered?
    }
  end

  defp monitor_owner(state, _execution, nil), do: state

  defp monitor_owner(state, execution, owner) when is_pid(owner) do
    key = {execution.plan_id, execution.step_id}
    state = clear_owner(state, execution.plan_id, execution.step_id)
    ref = Process.monitor(owner)

    %{
      state
      | owners: Map.put(state.owners, key, {ref, owner}),
        owner_refs: Map.put(state.owner_refs, ref, execution)
    }
  end

  defp clear_owner(state, plan_id, step_id) do
    key = {plan_id, step_id}

    case Map.pop(state.owners, key) do
      {nil, owners} ->
        %{state | owners: owners}

      {{ref, _pid}, owners} ->
        Process.demonitor(ref, [:flush])
        %{state | owners: owners, owner_refs: Map.delete(state.owner_refs, ref)}
    end
  end

  defp clear_cancelled_owners(state, executions) do
    Enum.reduce(executions, state, fn execution, acc ->
      clear_owner(acc, execution.plan_id, execution.step_id)
    end)
  end

  defp drop_owner_ref(state, ref, execution) do
    key = {execution.plan_id, execution.step_id}

    %{
      state
      | owners: Map.delete(state.owners, key),
        owner_refs: Map.delete(state.owner_refs, ref)
    }
  end

  defp launch_cancellations(state, executions) do
    Enum.reduce(executions, state, &launch_cancellation(&2, &1))
  end

  defp launch_cancellation(%{executor: nil} = state, execution) do
    record_cancellation_outcome(state.store, execution, :not_supported)
    state
  end

  defp launch_cancellation(%{executor: {module, opts}} = state, execution) do
    if function_exported?(module, :cancel, 3) do
      operation_id = make_ref()
      parent = self()
      reason = cancellation_reason(state.store, execution)

      {pid, monitor_ref} =
        spawn_monitor(fn ->
          result =
            try do
              module.cancel(execution, reason, opts)
            rescue
              error -> {:error, {:exception, Exception.message(error)}}
            catch
              kind, caught_reason -> {:error, {kind, Serializable.safe(caught_reason)}}
            end

          send(parent, {:cancel_result, operation_id, result})
        end)

      timer = Process.send_after(self(), {:cancel_timeout, operation_id}, state.cancel_timeout)

      operation = %{
        execution: execution,
        pid: pid,
        monitor_ref: monitor_ref,
        timer: timer
      }

      %{
        state
        | cancellation_ops: Map.put(state.cancellation_ops, operation_id, operation),
          cancellation_refs: Map.put(state.cancellation_refs, monitor_ref, operation_id)
      }
    else
      record_cancellation_outcome(state.store, execution, :not_supported)
      state
    end
  end

  defp finish_cancellation_operation(state, operation_id, operation, outcome) do
    Process.cancel_timer(operation.timer)
    Process.demonitor(operation.monitor_ref, [:flush])
    record_cancellation_outcome(state.store, operation.execution, outcome)

    %{
      state
      | cancellation_ops: Map.delete(state.cancellation_ops, operation_id),
        cancellation_refs: Map.delete(state.cancellation_refs, operation.monitor_ref)
    }
  end

  defp record_cancellation_outcome(store, execution, outcome) do
    with {:ok, plan} <- Store.get(store, execution.plan_id),
         {:ok,
          %Step{execution_token: token, cancellation: %{status: :pending} = cancellation} =
            step} <- fetch_step(plan, execution.step_id),
         true <- token == execution.token,
         updated_step <- %{
           step
           | cancellation:
               Map.merge(cancellation, %{
                 status: :completed,
                 outcome: Serializable.safe(outcome),
                 finished_at: System.system_time(:millisecond)
               })
         },
         updated_plan <- update_step(plan, updated_step) do
      Store.put(store, updated_plan)
    else
      _other -> :ok
    end
  end

  defp cancellation_reason(store, execution) do
    with {:ok, plan} <- Store.get(store, execution.plan_id),
         {:ok, %Step{cancellation: %{reason: reason}}} <- fetch_step(plan, execution.step_id) do
      reason
    else
      _other -> :cancelled
    end
  end

  defp resume_pending_cancellations(state) do
    case Store.list(state.store) do
      {:ok, plans} ->
        executions =
          for plan <- plans,
              id <- plan.step_order,
              step = Map.fetch!(plan.steps, id),
              step.state == :cancelled,
              match?(%{status: :pending}, step.cancellation),
              is_binary(step.execution_token),
              do: execution_from(plan, step, true)

        launch_cancellations(state, executions)

      _other ->
        state
    end
  end

  defp recover_running(plans, store) do
    Enum.reduce_while(plans, :ok, fn plan, :ok ->
      running? = Enum.any?(plan.steps, fn {_id, step} -> step.state == :running end)

      if running? do
        steps =
          Map.new(plan.steps, fn {id, step} ->
            if step.state == :running do
              {id, %{step | state: :ready, started_at: nil, error: :scheduler_recovered}}
            else
              {id, step}
            end
          end)

        recovered = plan |> Map.put(:steps, steps) |> touch() |> derive_status()

        case Store.put(store, recovered) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, {:recovery_persistence_failed, reason}}}
        end
      else
        {:cont, :ok}
      end
    end)
  end

  defp invoke_start({module, opts}, execution, scheduler) do
    try do
      module.start(execution, scheduler, opts)
    rescue
      error -> {:error, {:exception, Exception.message(error)}}
    catch
      kind, reason -> {:error, {kind, Serializable.safe(reason)}}
    end
  end

  defp ready_steps(store) do
    case Store.list(store) do
      {:ok, plans} ->
        for plan <- plans,
            plan.status in [:ready, :running, :pending],
            id <- plan.step_order,
            step = Map.fetch!(plan.steps, id),
            step.state == :ready,
            do: {plan, step}

      _other ->
        []
    end
  end

  defp running_count(store) do
    case Store.list(store) do
      {:ok, plans} ->
        Enum.reduce(plans, 0, fn plan, count ->
          count + Enum.count(plan.steps, fn {_id, step} -> step.state == :running end)
        end)

      _other ->
        0
    end
  end

  defp ensure_capacity(state) do
    if running_count(state.store) < state.max_concurrency,
      do: :ok,
      else: {:error, :max_concurrency_reached}
  end

  defp fetch_plan(store, id) do
    case Store.get(store, id) do
      {:ok, plan} -> {:ok, plan}
      :not_found -> :not_found
    end
  end

  defp fetch_step(plan, id) do
    case Map.fetch(plan.steps, id) do
      {:ok, step} -> {:ok, step}
      :error -> {:error, :step_not_found}
    end
  end

  defp persist_if_changed(_store, plan, plan), do: :ok
  defp persist_if_changed(store, _old_plan, new_plan), do: Store.put(store, new_plan)

  defp normalize_executor(nil), do: {:ok, nil}

  defp normalize_executor(module) when is_atom(module), do: normalize_executor({module, []})

  defp normalize_executor({module, opts}) when is_atom(module) and is_list(opts) do
    cond do
      not Keyword.keyword?(opts) -> {:error, :invalid_executor_options}
      not Code.ensure_loaded?(module) -> {:error, {:executor_not_loaded, module}}
      not function_exported?(module, :start, 3) -> {:error, {:invalid_executor, module}}
      true -> {:ok, {module, opts}}
    end
  end

  defp normalize_executor(_executor), do: {:error, :invalid_executor}

  defp positive_integer(value) when is_integer(value) and value > 0, do: {:ok, value}
  defp positive_integer(_value), do: {:error, :expected_positive_integer}

  defp validate_options(opts) do
    if Keyword.keyword?(opts), do: :ok, else: {:error, :invalid_options}
  end

  defp validate_start_options(opts) do
    cond do
      not Keyword.keyword?(opts) ->
        {:error, :invalid_options}

      Keyword.keys(opts) -- [:owner] != [] ->
        {:error, :unknown_options}

      not (is_nil(Keyword.get(opts, :owner)) or is_pid(Keyword.get(opts, :owner))) ->
        {:error, :invalid_owner}

      true ->
        :ok
    end
  end

  defp safe_store_list(store) do
    case Store.list(store) do
      {:ok, plans} -> {:ok, plans}
      other -> {:error, {:invalid_store_response, other}}
    end
  end

  defp new_token, do: Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
