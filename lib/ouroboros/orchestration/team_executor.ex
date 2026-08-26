defmodule Ouroboros.Orchestration.TeamExecutor do
  @moduledoc """
  Executes durable orchestration steps through an Ouroboros coding team.

  The step's durable identity — `{plan_id, step_id}` — becomes the delegation ID, so
  scheduler or adapter restarts reattach to the same detached coding task instead of
  launching a duplicate provider run. The execution token deliberately does not appear
  in it: a scheduler that restarts mints a fresh token for the same step, and a
  delegation named after the token would make that second offer a second provider run.
  Team processes are resolved from their logical ID at every retry boundary: a
  transient `Team.Server` restart therefore drops only the current waiter, not the
  durable delegation. A short-lived owner process is monitored by the scheduler; no PID
  enters the durable graph or team snapshot.

  Cancellation has a separate deadline capped at four seconds, leaving margin
  beneath the scheduler's default five-second callback timeout. `:ok` means the
  team durably accepted the request; every failure is explicitly reported as
  `:provider_cancellation_unconfirmed` and must not be read as provider
  termination.
  """

  @behaviour Ouroboros.Orchestration.Executor

  alias Ouroboros.Orchestration.{Execution, Scheduler, Serializable}
  alias Ouroboros.Team
  alias Ouroboros.Team.{Snapshot, Store}

  @default_retry_attempts 40
  @default_retry_backoff_ms 10
  @default_retry_max_backoff_ms 250
  @default_cancel_timeout_ms 4_000
  @max_cancel_timeout_ms 4_000

  @impl true
  def start(%Execution{} = execution, scheduler, opts) do
    with {:ok, team_id} <- required_binary(opts, :team_id),
         {:ok, worker_id} <- worker_id(execution, opts),
         {:ok, objective, delegation_opts} <- delegation_request(execution, opts),
         {:ok, retry_policy} <- retry_policy(opts),
         {:ok, await_timeout} <- await_timeout(opts),
         {:ok, _delegation} <-
           delegate_with_retry(
             team_id,
             worker_id,
             objective,
             Keyword.put(delegation_opts, :id, delegation_id(execution)),
             opts,
             retry_policy
           ) do
      owner =
        spawn(fn ->
          await_and_report(
            team_id,
            execution,
            scheduler,
            await_timeout,
            retry_policy
          )
        end)

      {:ok, owner}
    end
  end

  @impl true
  def cancel(%Execution{} = execution, _reason, opts) do
    with {:ok, team_id} <- required_binary(opts, :team_id),
         {:ok, retry_policy} <- retry_policy(opts),
         {:ok, cancel_timeout} <- cancel_timeout(opts) do
      cancel_with_retry(team_id, delegation_id(execution), retry_policy, cancel_timeout)
    end
  end

  # Durable, and stable across every attempt of the same step. Two offers of one step
  # name one delegation, whichever token either of them carries.
  defp delegation_id(%Execution{plan_id: plan_id, step_id: step_id}),
    do: "orchestration:" <> plan_id <> ":" <> step_id

  defp delegate_with_retry(team_id, worker_id, objective, delegation_opts, opts, policy) do
    retry_team_operation(
      team_id,
      :delegate,
      Keyword.fetch!(delegation_opts, :id),
      policy,
      fn team ->
        safe_team_call(fn -> Team.delegate(team, worker_id, objective, delegation_opts) end)
      end,
      fn -> maybe_start_team(team_id, opts) end
    )
  end

  defp worker_id(execution, opts) do
    value =
      get_in(execution.metadata, [:step, :worker_id]) ||
        input_value(execution.input, :worker_id) ||
        Keyword.get(opts, :worker_id)

    if is_binary(value) and String.trim(value) != "",
      do: {:ok, value},
      else: {:error, {:worker_id_required, execution.step_id}}
  end

  defp delegation_request(execution, opts) do
    objective =
      input_value(execution.input, :objective) ||
        if(is_binary(execution.input), do: execution.input)

    coding_opts =
      case input_value(execution.input, :options) do
        nil -> Keyword.get(opts, :coding_options, [])
        value -> value
      end

    cond do
      not is_binary(objective) or String.trim(objective) == "" ->
        {:error, {:objective_required, execution.step_id}}

      not is_list(coding_opts) or not Keyword.keyword?(coding_opts) ->
        {:error, {:invalid_coding_options, execution.step_id}}

      Enum.any?(Keyword.keys(coding_opts), &(&1 in [:id, :node])) ->
        {:error, {:reserved_coding_option, execution.step_id}}

      true ->
        {:ok, objective, coding_opts}
    end
  end

  defp await_and_report(team_id, execution, scheduler, timeout, retry_policy) do
    deadline = deadline(timeout)
    delegation_id = delegation_id(execution)

    result =
      retry_team_operation(
        team_id,
        :await,
        delegation_id,
        retry_policy,
        fn team -> Team.await(team, delegation_id, remaining_timeout(deadline)) end,
        fn -> classify_missing_team(team_id, deadline, :await) end,
        deadline
      )

    case result do
      {:ok, delegation}
      when delegation.status == :completed and delegation.delivery == :delivered ->
        _ =
          Scheduler.complete(scheduler, execution.plan_id, execution.step_id, execution.token, %{
            delegation: delegation
          })

      {:ok, delegation} ->
        _ =
          Scheduler.fail(scheduler, execution.plan_id, execution.step_id, execution.token, %{
            delegation: delegation,
            reason: :delegation_not_completed
          })

      {:error, reason} ->
        _ =
          Scheduler.fail(scheduler, execution.plan_id, execution.step_id, execution.token, reason)
    end
  end

  defp cancel_with_retry(team_id, delegation_id, retry_policy, cancel_timeout) do
    cancel_deadline = deadline(cancel_timeout)

    result =
      retry_team_operation(
        team_id,
        :cancel,
        delegation_id,
        retry_policy,
        fn team ->
          bounded_team_cancel(
            team,
            delegation_id,
            remaining_timeout(cancel_deadline)
          )
        end,
        fn -> classify_missing_team(team_id, cancel_deadline, :cancel) end,
        cancel_deadline
      )

    case result do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, {:provider_cancellation_unconfirmed, reason}}

      unexpected ->
        {:error,
         {:provider_cancellation_unconfirmed,
          {:unexpected_team_cancel_result, Serializable.safe(unexpected)}}}
    end
  end

  # Team.cancel/2 deliberately waits forever for the durable checkpoint. The
  # scheduler cancellation callback has its own five-second deadline, so run
  # that call in a linked helper and stop waiting at our earlier deadline. The
  # link also prevents an orphaned infinite call if the scheduler kills its
  # callback process. A timed-out request may still have reached the server;
  # callers therefore receive an explicit unconfirmed outcome.
  defp bounded_team_cancel(team, delegation_id, timeout)
       when is_integer(timeout) and timeout >= 0 do
    bounded_call(
      fn -> safe_team_call(fn -> Team.cancel(team, delegation_id) end) end,
      timeout,
      {:error, {:team_call_unavailable, :cancel_call_timeout}},
      fn reason -> {:error, {:team_call_unavailable, Serializable.safe(reason)}} end
    )
  end

  defp bounded_call(_fun, 0, timeout_result, _down_result), do: timeout_result

  defp bounded_call(fun, timeout, timeout_result, down_result)
       when is_function(fun, 0) and is_integer(timeout) and timeout > 0 and
              is_function(down_result, 1) do
    caller = self()
    request_ref = make_ref()

    {pid, monitor_ref} =
      :erlang.spawn_opt(
        fn ->
          result = fun.()
          send(caller, {request_ref, result})
        end,
        [:link, :monitor]
      )

    receive do
      {^request_ref, result} ->
        Process.demonitor(monitor_ref, [:flush])
        result

      {:DOWN, ^monitor_ref, :process, ^pid, reason} ->
        down_result.(reason)
    after
      timeout ->
        Process.unlink(pid)
        Process.exit(pid, :kill)
        Process.demonitor(monitor_ref, [:flush])
        timeout_result
    end
  end

  defp retry_team_operation(
         team_id,
         phase,
         delegation_id,
         policy,
         operation,
         missing_team,
         deadline \\ :infinity,
         attempt \\ 0
       ) do
    with :ok <- ensure_time_remaining(deadline) do
      case Team.whereis(team_id) do
        team when is_pid(team) ->
          case operation.(team) do
            {:error, :team_closing} ->
              {:error, {:team_closing, team_id}}

            {:error, {:team_unavailable, reason}} ->
              retry_or_exhaust(
                team_id,
                phase,
                delegation_id,
                policy,
                operation,
                missing_team,
                deadline,
                attempt,
                reason
              )

            {:error, {:team_call_unavailable, reason}} ->
              retry_or_exhaust(
                team_id,
                phase,
                delegation_id,
                policy,
                operation,
                missing_team,
                deadline,
                attempt,
                reason
              )

            {:error, :not_found} when phase in [:await, :cancel] ->
              classify_missing_delegation(
                team_id,
                phase,
                delegation_id,
                policy,
                operation,
                missing_team,
                deadline,
                attempt
              )

            result ->
              result
          end

        nil ->
          case missing_team.() do
            {:ok, team} when is_pid(team) ->
              retry_team_operation(
                team_id,
                phase,
                delegation_id,
                policy,
                operation,
                missing_team,
                deadline,
                attempt
              )

            {:retry, reason} ->
              retry_or_exhaust(
                team_id,
                phase,
                delegation_id,
                policy,
                operation,
                missing_team,
                deadline,
                attempt,
                reason
              )

            {:error, reason} ->
              {:error, reason}
          end
      end
    end
  end

  defp retry_or_exhaust(
         team_id,
         phase,
         delegation_id,
         policy,
         operation,
         missing_team,
         deadline,
         attempt,
         reason
       ) do
    case classify_missing_team(team_id, deadline, phase) do
      {:error, permanent_reason} ->
        {:error, permanent_reason}

      {:retry, classification_reason} ->
        if attempt < policy.attempts and time_remaining?(deadline) do
          Process.sleep(retry_delay(policy, attempt, deadline))

          retry_team_operation(
            team_id,
            phase,
            delegation_id,
            policy,
            operation,
            missing_team,
            deadline,
            attempt + 1
          )
        else
          {:error,
           {:team_restart_retry_exhausted, team_id, phase,
            Serializable.safe(reason || classification_reason)}}
        end
    end
  end

  defp classify_missing_delegation(
         team_id,
         phase,
         delegation_id,
         policy,
         operation,
         missing_team,
         deadline,
         attempt
       ) do
    case team_snapshot(team_id, deadline) do
      {:ok, %Snapshot{status: :closed}} ->
        {:error, {:team_closed, team_id}}

      {:ok, %Snapshot{status: status, delegations: delegations}}
      when status in [:active, :closing] ->
        if Map.has_key?(delegations, delegation_id) do
          retry_or_exhaust(
            team_id,
            phase,
            delegation_id,
            policy,
            operation,
            missing_team,
            deadline,
            attempt,
            :delegation_projection_recovering
          )
        else
          {:error, {:delegation_not_found, delegation_id}}
        end

      :not_found ->
        {:error, {:team_not_found, team_id}}

      {:error, reason} ->
        retry_or_exhaust(
          team_id,
          phase,
          delegation_id,
          policy,
          operation,
          missing_team,
          deadline,
          attempt,
          reason
        )
    end
  end

  defp maybe_start_team(team_id, opts) do
    if Keyword.get(opts, :start_team, false) do
      safe_team_call(fn -> Team.start_or_get(id: team_id) end)
      |> case do
        {:ok, team} when is_pid(team) -> {:ok, team}
        {:error, :team_closed} -> {:error, {:team_closed, team_id}}
        {:error, reason} -> classify_start_failure(team_id, reason)
      end
    else
      classify_missing_team(team_id, :infinity, :delegate)
    end
  end

  defp classify_start_failure(team_id, reason) do
    case classify_missing_team(team_id, :infinity, :delegate) do
      {:error, {:team_not_found, ^team_id}} -> {:retry, {:team_start_failed, reason}}
      classification -> classification
    end
  end

  defp classify_missing_team(team_id, deadline, phase) do
    case team_snapshot(team_id, deadline) do
      {:ok, %Snapshot{status: :active}} ->
        {:retry, {:team_restarting, team_id}}

      {:ok, %Snapshot{status: :closing}} when phase in [:await, :cancel] ->
        {:retry, {:team_restarting, team_id}}

      {:ok, %Snapshot{status: :closing}} ->
        {:error, {:team_closing, team_id}}

      {:ok, %Snapshot{status: :closed}} ->
        {:error, {:team_closed, team_id}}

      :not_found ->
        {:error, {:team_not_found, team_id}}

      {:error, reason} ->
        {:retry, {:team_store_unavailable, Serializable.safe(reason)}}
    end
  end

  defp team_snapshot(team_id, :infinity), do: fetch_team_snapshot(team_id)

  defp team_snapshot(team_id, deadline) when is_integer(deadline) do
    timeout = remaining_timeout(deadline)

    bounded_call(
      fn -> fetch_team_snapshot(team_id) end,
      timeout,
      {:error, {:team_store_deadline_exceeded, team_id}},
      fn reason -> {:error, {:team_store_call_unavailable, Serializable.safe(reason)}} end
    )
  end

  defp fetch_team_snapshot(team_id) do
    try do
      Store.get(team_id)
    rescue
      error -> {:error, {:team_store_exception, Exception.message(error)}}
    catch
      :exit, reason -> {:error, {:team_store_exit, Serializable.safe(reason)}}
    end
  end

  defp safe_team_call(fun) do
    try do
      fun.()
    rescue
      error -> {:error, {:team_call_failed, Exception.message(error)}}
    catch
      :exit, reason -> {:error, {:team_call_unavailable, Serializable.safe(reason)}}
    end
  end

  defp retry_policy(opts) do
    attempts = Keyword.get(opts, :team_retry_attempts, @default_retry_attempts)
    backoff = Keyword.get(opts, :team_retry_backoff_ms, @default_retry_backoff_ms)
    max_backoff = Keyword.get(opts, :team_retry_max_backoff_ms, @default_retry_max_backoff_ms)

    cond do
      not is_integer(attempts) or attempts < 0 ->
        {:error, {:invalid_team_retry_option, :team_retry_attempts, attempts}}

      not is_integer(backoff) or backoff < 0 ->
        {:error, {:invalid_team_retry_option, :team_retry_backoff_ms, backoff}}

      not is_integer(max_backoff) or max_backoff < backoff ->
        {:error, {:invalid_team_retry_option, :team_retry_max_backoff_ms, max_backoff}}

      true ->
        {:ok, %{attempts: attempts, backoff_ms: backoff, max_backoff_ms: max_backoff}}
    end
  end

  defp await_timeout(opts) do
    case Keyword.get(opts, :await_timeout, :infinity) do
      :infinity -> {:ok, :infinity}
      timeout when is_integer(timeout) and timeout >= 0 -> {:ok, timeout}
      timeout -> {:error, {:invalid_await_timeout, timeout}}
    end
  end

  defp cancel_timeout(opts) do
    timeout = Keyword.get(opts, :team_cancel_timeout_ms, @default_cancel_timeout_ms)

    if is_integer(timeout) and timeout > 0 and timeout <= @max_cancel_timeout_ms do
      {:ok, timeout}
    else
      {:error,
       {:invalid_team_retry_option, :team_cancel_timeout_ms, timeout,
        {:expected_milliseconds, 1..@max_cancel_timeout_ms}}}
    end
  end

  defp retry_delay(policy, attempt, deadline) do
    exponential = policy.backoff_ms * Integer.pow(2, min(attempt, 16))
    delay = min(exponential, policy.max_backoff_ms)

    case remaining_timeout(deadline) do
      :infinity -> delay
      remaining -> min(delay, remaining)
    end
  end

  defp deadline(:infinity), do: :infinity
  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout

  defp remaining_timeout(:infinity), do: :infinity

  defp remaining_timeout(deadline) do
    max(deadline - System.monotonic_time(:millisecond), 0)
  end

  defp ensure_time_remaining(:infinity), do: :ok

  defp ensure_time_remaining(deadline) do
    if time_remaining?(deadline), do: :ok, else: {:error, :timeout}
  end

  defp time_remaining?(:infinity), do: true
  defp time_remaining?(deadline), do: remaining_timeout(deadline) > 0

  defp input_value(input, key) when is_map(input) do
    Map.get(input, key) || Map.get(input, Atom.to_string(key))
  end

  defp input_value(_input, _key), do: nil

  defp required_binary(opts, key) do
    value = Keyword.get(opts, key)

    if is_binary(value) and String.trim(value) != "",
      do: {:ok, value},
      else: {:error, {key, :required}}
  end
end
