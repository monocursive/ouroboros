defmodule Ouroboros.Session.Recovery do
  @moduledoc "Recovery sweep and terminal retention shared by the two session planes."

  use GenServer

  @interval 1_000
  @restart_grace_seconds 2
  @prune_interval 60_000
  @default_retention_ms 7 * 24 * 60 * 60 * 1_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name_option(Keyword.get(opts, :name)))
  end

  @impl true
  def init(opts) do
    state = %{
      interval: Keyword.get(opts, :interval, @interval),
      prune_interval: Keyword.get(opts, :prune_interval, @prune_interval),
      last_prune: nil,
      store: Keyword.fetch!(opts, :store),
      task: Keyword.fetch!(opts, :task),
      registry: Keyword.fetch!(opts, :registry),
      supervisor: Keyword.fetch!(opts, :supervisor)
    }

    {:ok, state, {:continue, :recover}}
  end

  @impl true
  def handle_continue(:recover, state), do: {:noreply, tick(state)}

  @impl true
  def handle_info(:recover, state), do: {:noreply, tick(state)}

  def handle_info(_message, state), do: {:noreply, state}

  defp tick(state) do
    recover_tasks(state)
    state = sweep_terminal(state)
    schedule_recovery(state.interval)
    state
  end

  defp recover_tasks(state) do
    with registry when is_pid(registry) <- Process.whereis(state.registry),
         supervisor when is_pid(supervisor) <-
           Process.whereis(state.supervisor),
         tasks when is_list(tasks) <- safe_list_recoverable(state.store) do
      Enum.each(tasks, fn task ->
        if safe_whereis(state.task, task.id) == nil and recoverable?(task) do
          _ = recover_child(supervisor, state.task, task.id)
        end
      end)
    else
      _unavailable -> :ok
    end
  end

  # Admission can disappear independently of the coordinator supervisor. Isolate
  # the entire attempt, including acquisition and cleanup, from the shared sweep.
  defp recover_child(supervisor, task, id) do
    safe_start_child(supervisor, task, recovery_child(task, id))
  rescue
    _error -> {:error, :recovery_unavailable}
  catch
    :exit, _reason -> {:error, :recovery_unavailable}
  end

  # The projection carries only routing and lifecycle fields. Listing full task
  # states here would deep-copy every retained event list once per second.
  defp safe_list_recoverable(store) do
    store.list_recoverable()
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, _reason -> {:error, :store_unavailable}
  end

  defp safe_whereis(task, id) do
    task.whereis(id)
  rescue
    _error -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  defp safe_start_child(supervisor, Ouroboros.Interactive.Task = task, {id, lease, server}) do
    try do
      safe_start_child(supervisor, task, {id, lease}, :admitted)
    after
      safe_release(lease, server)
    end
  end

  defp safe_start_child(_supervisor, _task, :maintenance_refused),
    do: {:error, :maintenance_refused}

  defp safe_start_child(supervisor, task, id), do: safe_start_child(supervisor, task, id, :plain)

  defp safe_start_child(supervisor, task, id, _mode) do
    DynamicSupervisor.start_child(supervisor, {task, id})
  rescue
    _error -> {:error, :supervisor_unavailable}
  catch
    :exit, _reason -> {:error, :supervisor_unavailable}
  end

  defp safe_release(lease, server) do
    Ouroboros.Maintenance.Fence.release(lease, server)
  rescue
    _error -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  defp recovery_child(Ouroboros.Interactive.Task, id) do
    server =
      Application.get_env(:ouroboros, :maintenance_fence_server, Ouroboros.Maintenance.Fence)

    case Process.whereis(server) do
      nil ->
        id

      _pid ->
        operation_id =
          "coordinator-recovery:" <>
            (:crypto.hash(:sha256, id) |> Base.encode16(case: :lower))

        case Ouroboros.Maintenance.Fence.acquire_admission(operation_id, id, :current, server) do
          {:ok, lease} -> {id, lease, server}
          {:error, _reason} -> :maintenance_refused
        end
    end
  end

  defp recovery_child(_task, id), do: id

  defp schedule_recovery(interval), do: Process.send_after(self(), :recover, interval)

  defp recoverable?(task) do
    task.node == node() and not Map.get(task, :removed_provider?, false) and
      if(task.terminal?,
        do: retained_terminal?(task),
        else: old_enough_to_recover?(task.updated_at)
      )
  end

  # A terminal coordinator may die between checkpoint and acknowledgement. Recover
  # only for outstanding terminal delivery from the persisted generation.
  defp retained_terminal?(%{
         runtime_id: id,
         runtime_generation: generation,
         runtime_cursor: cursor
       }) do
    Ouroboros.Session.Delivery.state(id, generation, cursor) == :pending
  end

  defp retained_terminal?(_task), do: false

  defp old_enough_to_recover?(updated_at) do
    with {:ok, timestamp, _offset} <- DateTime.from_iso8601(updated_at) do
      DateTime.diff(DateTime.utc_now(), timestamp, :second) >= @restart_grace_seconds
    else
      _error -> true
    end
  end

  # Sweeping on the recovery tick keeps terminal retention in one supervised loop.
  # Throttle it separately so every recovery tick need not scan timestamps and publish
  # a reduced index.
  defp sweep_terminal(state) do
    now = System.monotonic_time(:millisecond)
    retention = retention_ms()

    if is_integer(retention) and due?(state.last_prune, now, state.prune_interval) do
      _ = safe_prune(state.store, retention)
      %{state | last_prune: now}
    else
      state
    end
  end

  defp due?(nil, _now, _interval), do: true
  defp due?(last_prune, now, interval), do: now - last_prune >= interval

  defp retention_ms do
    case Application.get_env(:ouroboros, :terminal_retention_ms, @default_retention_ms) do
      retention when is_integer(retention) and retention >= 0 -> retention
      _disabled -> nil
    end
  end

  defp safe_prune(store, retention) do
    store.prune_terminal(retention)
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, _reason -> {:error, :store_unavailable}
  end

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
