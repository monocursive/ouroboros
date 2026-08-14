defmodule Ouroboros.Coding.Task do
  @moduledoc false

  use GenServer, restart: :transient

  require Logger

  alias Jido.Harness.{Run, RunResult}
  alias Ouroboros.Coding.{Store, TaskState}
  alias Ouroboros.Workspace
  alias Ouroboros.Workspace.Manager, as: WorkspaceManager

  @poll_interval 25
  @replay_limit 100
  @terminal_retire_ms 100
  @workspace_reacquire_attempts 25
  @workspace_reacquire_delay_ms 4
  @retry_backoff_max_ms 5_000

  def child_spec(id) do
    %{
      id: {__MODULE__, id},
      start: {__MODULE__, :start_link, [id]},
      restart: :transient
    }
  end

  def start_link(id) when is_binary(id), do: GenServer.start_link(__MODULE__, id, name: via(id))

  def via(id), do: {:via, Registry, {Ouroboros.Coding.Registry, id}}

  def whereis(id) do
    case Registry.lookup(Ouroboros.Coding.Registry, id) do
      [{pid, _}] -> pid
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  catch
    :exit, _reason -> nil
  end

  @impl true
  def init(id) do
    case Store.get(id) do
      {:ok, %TaskState{node: owner} = task} when owner == node() ->
        if TaskState.terminal?(task) do
          {:ok, new_runtime(task), {:continue, :attach}}
        else
          case admit_workspace(task) do
            # A checkpoint this build cannot turn into a Harness request — a trace from a
            # newer prompt format, a prompt that is no longer a binary — fails as itself,
            # before any provider run, and releases what it holds. Refusing to boot over
            # it is what would take the node down.
            {:ok, runtime} ->
              case TaskState.unrequestable_reason(runtime.task) do
                nil -> {:ok, runtime, {:continue, :attach}}
                reason -> {:ok, runtime, {:continue, {:unrequestable, reason}}}
              end

            {:error, reason} ->
              {:stop, reason}
          end
        end

      {:ok, %TaskState{node: owner}} ->
        {:stop, {:wrong_owner, owner}}

      :not_found ->
        {:stop, :not_found}

      {:error, reason} ->
        {:stop, {:storage_error, reason}}
    end
  end

  @impl true
  def handle_continue(:attach, %{task: %TaskState{} = task} = runtime) do
    if TaskState.terminal?(task) do
      {:noreply, schedule_retire(runtime)}
    else
      {:noreply, attach_or_start(runtime)}
    end
  end

  def handle_continue({:unrequestable, reason}, runtime) do
    Logger.error(
      "coding task #{runtime.task.id} cannot build a request: #{inspect(reason)}; failing it"
    )

    {:noreply, fail_start(runtime, {:unrequestable_task_state, reason})}
  end

  @impl true
  def handle_call(:info, _from, runtime),
    do: {:reply, {:ok, TaskState.public(runtime.task)}, runtime}

  def handle_call({:replay, cursor, limit}, _from, runtime) do
    {:reply, replay_events(runtime.task, cursor, limit), runtime}
  end

  def handle_call({:subscribe, subscriber, cursor}, _from, runtime) do
    case subscription_events(runtime.task, cursor) do
      {:ok, backlog} ->
        runtime =
          if TaskState.terminal?(runtime.task),
            do: runtime,
            else: put_subscriber(runtime, subscriber)

        {:reply, {:ok, backlog}, runtime}

      {:error, reason} ->
        {:reply, {:error, reason}, runtime}
    end
  end

  def handle_call({:unsubscribe, subscriber}, _from, runtime) do
    {:reply, :ok, drop_subscriber(runtime, subscriber)}
  end

  def handle_call({:await, _request_ref}, _from, %{task: task} = runtime)
      when task.status in [:completed, :failed, :cancelled, :lost] do
    {:reply, {:ok, TaskState.public(task)}, runtime}
  end

  def handle_call({:await, request_ref}, from, runtime) do
    monitor = Process.monitor(elem(from, 0))
    waiters = Map.put(runtime.waiters, request_ref, {from, monitor})
    {:noreply, %{runtime | waiters: waiters}}
  end

  def handle_call(:cancel, _from, %{task: task} = runtime)
      when task.status in [:completed, :failed, :cancelled, :lost] do
    {:reply, :ok, runtime}
  end

  def handle_call(:cancel, _from, %{task: %TaskState{harness_run_id: nil}} = runtime) do
    {:reply, {:error, :not_started}, runtime}
  end

  def handle_call(:cancel, _from, %{task: task} = runtime) do
    reply = safe_run_call(fn -> Run.cancel(task.harness_run_id) end)
    runtime = schedule_poll(runtime, 0)
    {:reply, reply, runtime}
  end

  @impl true
  def handle_cast({:cancel_await, request_ref}, runtime) do
    {:noreply, drop_waiter(runtime, request_ref)}
  end

  @impl true
  def handle_info(:poll, runtime), do: {:noreply, poll(runtime)}

  # A waiter that arrives in the window between the terminal checkpoint and this
  # message used to strand the coordinator: nothing rescheduled retirement once it
  # had been declined.
  def handle_info(:retire, %{task: task} = runtime) do
    cond do
      not TaskState.terminal?(task) -> {:noreply, runtime}
      map_size(runtime.waiters) == 0 -> {:stop, :normal, runtime}
      true -> {:noreply, schedule_retire(runtime)}
    end
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, runtime) do
    runtime =
      case Map.pop(runtime.subscriber_monitors, monitor) do
        {nil, _} ->
          drop_waiter_by_monitor(runtime, monitor)

        {subscriber, monitors} ->
          %{
            runtime
            | subscribers: Map.delete(runtime.subscribers, subscriber),
              subscriber_monitors: monitors
          }
      end

    {:noreply, runtime}
  end

  def handle_info(_message, runtime), do: {:noreply, runtime}

  @impl true
  def terminate(_reason, runtime) do
    _ = release_workspace(runtime)
    :ok
  end

  defp new_runtime(task, lease \\ nil, capability \\ nil) do
    %{
      task: task,
      subscribers: %{},
      subscriber_monitors: %{},
      waiters: %{},
      workspace_lease: lease,
      workspace_capability: capability,
      retry: no_retry()
    }
  end

  defp no_retry, do: %{signature: nil, count: 0, delay: 0}

  defp admit_workspace(task) do
    if is_pid(Process.whereis(WorkspaceManager)) do
      case acquire_workspace(task, @workspace_reacquire_attempts) do
        {:ok, lease, capability} ->
          leased_task =
            task
            |> Map.put(:workspace, lease.root)
            |> Map.put(:workspace_mode, lease.mode)
            |> Map.put(:workspace_lease_id, lease.id)
            |> touch()

          case Store.put(leased_task) do
            :ok ->
              {:ok, new_runtime(leased_task, lease, capability)}

            # The store refuses a task it cannot run. Keep the lease rather than stop:
            # this task is about to fail as itself, and that failure is what releases the
            # workspace and clears the recovery reservation the lease just replaced.
            {:error, :invalid_task_state} ->
              {:ok, new_runtime(leased_task, lease, capability)}

            {:error, reason} ->
              _ = safe_workspace_release(lease.id, capability)
              {:error, {:storage_error, reason}}
          end

        {:error, reason} ->
          checkpoint_admission_failure(task, reason)
      end
    else
      {:ok, new_runtime(task)}
    end
  end

  defp acquire_workspace(task, attempts) do
    result =
      try do
        Workspace.acquire_managed(task.workspace, task.id, :coding,
          mode: task.workspace_mode,
          server: WorkspaceManager
        )
      catch
        :exit, reason -> {:error, {:workspace_manager_unavailable, reason}}
      end

    case result do
      {:error, {:workspace_conflict, conflicts}} = error when attempts > 0 ->
        if stale_own_lease?(conflicts, task.id) do
          Process.sleep(@workspace_reacquire_delay_ms)
          acquire_workspace(task, attempts - 1)
        else
          error
        end

      other ->
        other
    end
  end

  defp stale_own_lease?([_ | _] = conflicts, task_id) do
    Enum.all?(conflicts, &(Map.get(&1, :task_id) == task_id))
  end

  defp stale_own_lease?(_conflicts, _task_id), do: false

  defp checkpoint_admission_failure(task, reason) do
    redacted = Jido.Harness.Redaction.redact(reason)

    {failed_task, event} =
      append_internal(task, :workspace_admission_failed, %{error: inspect(redacted)})

    failed_task =
      failed_task
      |> Map.put(:status, :failed)
      |> Map.put(:error, {:workspace_admission_failed, redacted})
      |> touch()

    case Store.put(failed_task) do
      :ok ->
        {:error, {:workspace_admission_failed, redacted}}

      {:error, store_reason} ->
        {:error,
         {:workspace_admission_failed, redacted,
          {:failure_checkpoint_failed, store_reason, event.id}}}
    end
  end

  defp release_workspace(%{workspace_lease: nil} = runtime), do: runtime

  defp release_workspace(runtime) do
    _ = safe_workspace_release(runtime.workspace_lease.id, runtime.workspace_capability)
    %{runtime | workspace_lease: nil, workspace_capability: nil}
  end

  defp safe_workspace_release(lease_id, capability) do
    try do
      Workspace.release(lease_id, server: WorkspaceManager, capability: capability)
    catch
      :exit, _reason -> :ok
    end
  end

  defp attach_or_start(%{task: %TaskState{harness_run_id: run_id}} = runtime)
       when is_binary(run_id) do
    case safe_run_call(fn -> Run.info(run_id) end) do
      {:ok, _info} -> runtime |> clear_retry() |> schedule_poll(0)
      {:error, :not_found} -> lose(runtime, :harness_run_not_found)
      {:error, reason} -> retry_with_error(runtime, :harness_info_failed, reason)
    end
  end

  defp attach_or_start(runtime) do
    case find_adoptable_run(runtime.task.id) do
      {:ok, run_id} -> adopt(runtime, run_id)
      :not_found -> start_harness_run(runtime)
      {:error, reason} -> fail_start(runtime, reason)
    end
  end

  defp find_adoptable_run(task_id) do
    runs = safe_run_call(&Run.list/0)

    matches =
      if is_list(runs), do: runs, else: []

    matches =
      matches
      |> Enum.filter(fn info ->
        metadata = info.metadata || %{}

        Map.get(metadata, :ouroboros_task_id) == task_id or
          Map.get(metadata, "ouroboros_task_id") == task_id
      end)

    case {runs, matches} do
      {{:error, reason}, _matches} -> {:error, reason}
      {_runs, []} -> :not_found
      {_runs, [info]} -> {:ok, info.run_id}
      {_runs, infos} -> {:error, {:ambiguous_adoptable_runs, Enum.map(infos, & &1.run_id)}}
    end
  end

  defp start_harness_run(runtime) do
    task = runtime.task

    case TaskState.unrequestable_reason(task) do
      nil ->
        case safe_run_call(fn -> Run.start(task.provider, TaskState.request(task)) end) do
          {:ok, run_id} -> adopt(runtime, run_id)
          {:error, reason} -> fail_start(runtime, reason)
        end

      reason ->
        fail_start(runtime, {:unrequestable_task_state, reason})
    end
  end

  defp adopt(runtime, run_id) do
    task =
      runtime.task
      |> Map.put(:harness_run_id, run_id)
      |> Map.put(:status, :running)
      |> touch()

    case persist(runtime, task, []) do
      {:ok, runtime} -> schedule_poll(runtime, 0)
      {:error, runtime} -> schedule_attach(runtime)
    end
  end

  defp poll(%{task: task} = runtime) when task.status in [:completed, :failed, :cancelled, :lost],
    do: runtime

  defp poll(%{task: %TaskState{harness_run_id: nil}} = runtime), do: attach_or_start(runtime)

  defp poll(runtime) do
    task = runtime.task

    case safe_run_call(fn ->
           Run.replay(task.harness_run_id, cursor: task.cursor, limit: @replay_limit)
         end) do
      {:ok, [_ | _] = events} -> runtime |> clear_retry() |> persist_harness_events(events)
      {:ok, []} -> collect_result(runtime)
      {:error, :not_found} -> lose(runtime, :harness_run_not_found)
      {:error, reason} -> retry_with_error(runtime, :harness_replay_failed, reason)
    end
  end

  defp persist_harness_events(runtime, harness_events) do
    {task, events} =
      Enum.reduce(harness_events, {runtime.task, []}, fn %Jido.Harness.Event{} = harness_event,
                                                         {task, events} ->
        event = Ouroboros.Coding.Event.from_harness(task.id, task.next_sequence, harness_event)

        task =
          task
          |> Map.put(:cursor, harness_event.sequence)
          |> Map.put(
            :provider_session_id,
            harness_event.provider_session_id || task.provider_session_id
          )
          |> append_event(event)

        {task, [event | events]}
      end)

    events = Enum.reverse(events)

    case persist(runtime, touch(task), events) do
      {:ok, runtime} -> schedule_poll(runtime, 0)
      {:error, runtime} -> schedule_poll(runtime, @poll_interval)
    end
  end

  defp collect_result(runtime) do
    case safe_run_call(fn -> Run.await(runtime.task.harness_run_id, 0) end) do
      {:ok, %RunResult{} = result} ->
        # A run result becomes readable in the same provider transition that appends
        # the run's terminal event, so a result read here can be newer than the
        # mirrored event log. Finishing now would reply to an awaiter whose subsequent
        # replay is missing the terminal event it just waited for.
        if mirrored_through_result?(runtime),
          do: finish(runtime, result),
          else: runtime |> clear_retry() |> schedule_poll(@poll_interval)

      {:error, :timeout} ->
        runtime |> clear_retry() |> schedule_poll(@poll_interval)

      {:error, :not_found} ->
        lose(runtime, :harness_run_not_found)

      {:error, reason} ->
        retry_with_error(runtime, :harness_await_failed, reason)
    end
  end

  # Read the provider's cursor high-water mark *after* the result: whatever the
  # provider had emitted when the result existed is included in it, so a mirror that
  # has reached it has already checkpointed the run's terminal event. Anything still
  # missing is drained by the next poll, and a pruned event still advances the cursor,
  # so this defers a finish at most until the mirror catches up. An unreachable run
  # fails open — the next poll owns that diagnosis.
  defp mirrored_through_result?(runtime) do
    case safe_run_call(fn -> Run.info(runtime.task.harness_run_id) end) do
      {:ok, %{output_cursor: output_cursor}} -> runtime.task.cursor >= output_cursor
      _unavailable -> true
    end
  end

  defp finish(runtime, %RunResult{} = result) do
    task =
      runtime.task
      |> Map.put(:status, result.status)
      |> Map.put(
        :provider_session_id,
        result.provider_session_id || runtime.task.provider_session_id
      )
      |> Map.put(:result, result_summary(result))
      |> Map.put(:error, Jido.Harness.Redaction.redact(result.error))
      |> touch()

    case persist(runtime, task, []) do
      {:ok, runtime} -> runtime |> release_workspace() |> reply_waiters() |> schedule_retire()
      {:error, runtime} -> schedule_poll(runtime, @poll_interval)
    end
  end

  defp fail_start(runtime, reason) do
    redacted = Jido.Harness.Redaction.redact(reason)
    {task, event} = append_internal(runtime.task, :task_start_failed, %{error: inspect(redacted)})
    task = %{task | status: :failed, error: redacted} |> touch()

    case persist(runtime, task, [event]) do
      {:ok, runtime} -> runtime |> release_workspace() |> reply_waiters() |> schedule_retire()
      {:error, runtime} -> schedule_attach(runtime)
    end
  end

  defp lose(runtime, reason) do
    {task, event} = append_internal(runtime.task, :task_lost, %{reason: inspect(reason)})
    task = %{task | status: :lost, error: reason} |> touch()

    case persist(runtime, task, [event]) do
      {:ok, runtime} -> runtime |> release_workspace() |> reply_waiters() |> schedule_retire()
      {:error, runtime} -> schedule_poll(runtime, @poll_interval)
    end
  end

  # A wedged provider used to be retried every 25ms with one durable error event
  # per attempt: the retained event ring filled with error noise in minutes, evicting
  # real agent output past `event_floor` and rewriting the whole aggregate 40 times a
  # second. Back off, and only checkpoint an error the first time it is seen or when
  # it changes. The repeat count rides along on the next event that is written.
  defp retry_with_error(runtime, type, reason) do
    redacted = Jido.Harness.Redaction.redact(reason)
    {repeat?, runtime} = note_retry(runtime, {type, redacted})
    delay = runtime.retry.delay

    if repeat? do
      schedule_poll(runtime, delay)
    else
      payload = %{error: inspect(redacted), consecutive_errors: runtime.retry.count}
      {task, event} = append_internal(runtime.task, type, payload)

      case persist(runtime, touch(task), [event]) do
        {:ok, runtime} -> schedule_poll(runtime, delay)
        {:error, runtime} -> schedule_poll(runtime, delay)
      end
    end
  end

  defp note_retry(%{retry: retry} = runtime, signature) do
    repeat? = retry.count > 0 and retry.signature == signature

    delay =
      if retry.count == 0, do: @poll_interval, else: min(retry.delay * 2, @retry_backoff_max_ms)

    {repeat?, %{runtime | retry: %{signature: signature, count: retry.count + 1, delay: delay}}}
  end

  defp clear_retry(%{retry: %{count: 0}} = runtime), do: runtime
  defp clear_retry(runtime), do: %{runtime | retry: no_retry()}

  defp append_internal(task, type, payload) do
    event = Ouroboros.Coding.Event.internal(task.id, task.next_sequence, type, payload)
    {append_event(task, event), event}
  end

  defp append_event(task, event) do
    events = task.events ++ [event]
    overflow = max(length(events) - task.event_limit, 0)
    {discarded, events} = Enum.split(events, overflow)

    floor =
      case List.last(discarded) do
        nil -> task.event_floor
        discarded_event -> discarded_event.sequence
      end

    %{task | events: events, event_floor: floor, next_sequence: event.sequence + 1}
  end

  defp persist(runtime, task, events) do
    case Store.put(task) do
      :ok ->
        Enum.each(runtime.subscribers, fn {pid, _monitor} ->
          Enum.each(events, &send(pid, {:ouroboros_coding_event, task.id, &1}))
        end)

        {:ok, %{runtime | task: task}}

      # A refused checkpoint is not a storage outage. Polling cannot make a task the
      # store will not accept acceptable, and the old shared retry path left exactly
      # that task running forever: no waiter answered, no workspace released.
      {:error, :invalid_task_state} ->
        {:error, abandon(runtime, task)}

      {:error, _reason} ->
        {:error, runtime}
    end
  end

  defp abandon(%{task: %TaskState{status: status}} = runtime, _rejected)
       when status in [:completed, :failed, :cancelled, :lost],
       do: runtime

  # The refused state is not the one that gets recorded: it is the state the store just
  # rejected. What is recorded is the last accepted state, marked failed, which the store
  # accepts because a terminal task never builds another request.
  defp abandon(runtime, rejected) do
    reason =
      {:unstorable_task_state, TaskState.unrequestable_reason(rejected) || :rejected_by_store}

    Logger.error(
      "coding task #{runtime.task.id} was refused by the store: #{inspect(reason)}; failing it"
    )

    {task, event} =
      append_internal(runtime.task, :task_checkpoint_refused, %{error: inspect(reason)})

    task = %{task | status: :failed, error: reason} |> touch()

    runtime =
      case Store.put(task) do
        :ok ->
          Enum.each(runtime.subscribers, fn {pid, _monitor} ->
            send(pid, {:ouroboros_coding_event, task.id, event})
          end)

          %{runtime | task: task}

        # Even the terminal record was refused. The durable checkpoint stays as the store
        # last accepted it; this process still ends honestly rather than spinning.
        {:error, _reason} ->
          %{runtime | task: task}
      end

    runtime |> release_workspace() |> reply_waiters() |> schedule_retire()
  end

  defp replay_events(%TaskState{} = task, cursor, limit)
       when is_integer(cursor) and cursor >= 0 and is_integer(limit) and limit > 0 and
              limit <= 10_000 do
    if cursor < task.event_floor do
      {:error, {:cursor_pruned, task.event_floor}}
    else
      {:ok, task.events |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit)}
    end
  end

  defp replay_events(_task, cursor, limit),
    do: {:error, {:invalid_cursor_or_limit, cursor, limit}}

  defp subscription_events(%TaskState{} = task, cursor)
       when is_integer(cursor) and cursor >= 0 do
    if cursor < task.event_floor do
      {:error, {:cursor_pruned, task.event_floor}}
    else
      {:ok, Enum.filter(task.events, &(&1.sequence > cursor))}
    end
  end

  defp subscription_events(_task, cursor), do: {:error, {:invalid_cursor, cursor}}

  defp put_subscriber(runtime, subscriber) do
    runtime = drop_subscriber(runtime, subscriber)
    monitor = Process.monitor(subscriber)

    %{
      runtime
      | subscribers: Map.put(runtime.subscribers, subscriber, monitor),
        subscriber_monitors: Map.put(runtime.subscriber_monitors, monitor, subscriber)
    }
  end

  defp drop_subscriber(runtime, subscriber) do
    case Map.pop(runtime.subscribers, subscriber) do
      {nil, _} ->
        runtime

      {monitor, subscribers} ->
        Process.demonitor(monitor, [:flush])

        %{
          runtime
          | subscribers: subscribers,
            subscriber_monitors: Map.delete(runtime.subscriber_monitors, monitor)
        }
    end
  end

  defp drop_waiter(runtime, request_ref) do
    case Map.pop(runtime.waiters, request_ref) do
      {nil, _} ->
        runtime

      {{_from, monitor}, waiters} ->
        Process.demonitor(monitor, [:flush])
        %{runtime | waiters: waiters}
    end
  end

  defp drop_waiter_by_monitor(runtime, monitor) do
    case Enum.find(runtime.waiters, fn {_ref, {_from, waiter_monitor}} ->
           waiter_monitor == monitor
         end) do
      nil -> runtime
      {request_ref, _value} -> %{runtime | waiters: Map.delete(runtime.waiters, request_ref)}
    end
  end

  defp reply_waiters(runtime) do
    public_task = TaskState.public(runtime.task)

    Enum.each(runtime.waiters, fn {_request_ref, {from, monitor}} ->
      Process.demonitor(monitor, [:flush])
      GenServer.reply(from, {:ok, public_task})
    end)

    %{runtime | waiters: %{}}
  end

  defp schedule_poll(runtime, delay) do
    Process.send_after(self(), :poll, delay)
    runtime
  end

  defp schedule_attach(runtime) do
    Process.send_after(self(), :poll, @poll_interval)
    runtime
  end

  defp schedule_retire(runtime) do
    Process.send_after(self(), :retire, @terminal_retire_ms)
    runtime
  end

  defp touch(task), do: %{task | updated_at: DateTime.utc_now() |> DateTime.to_iso8601()}

  defp result_summary(result) do
    %{
      run_id: result.run_id,
      provider: result.provider,
      provider_session_id: result.provider_session_id,
      status: result.status,
      text: Jido.Harness.Redaction.redact(result.text),
      text_truncated?: result.text_truncated?,
      usage: Jido.Harness.Redaction.redact(result.usage),
      metadata: Jido.Harness.Redaction.redact(result.metadata)
    }
  end

  defp safe_run_call(fun) do
    try do
      fun.()
    rescue
      error -> {:error, {:harness_call_exception, error.__struct__, Exception.message(error)}}
    catch
      :exit, reason -> {:error, {:harness_call_exit, reason}}
    end
  end
end
