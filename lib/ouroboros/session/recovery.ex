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
      tasks
      |> Enum.filter(&recoverable?/1)
      |> Enum.each(fn task ->
        if safe_whereis(state.task, task.id) == nil do
          _ = safe_start_child(supervisor, state.task, task.id)
        end
      end)
    else
      _unavailable -> :ok
    end
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

  defp safe_start_child(supervisor, task, id) do
    DynamicSupervisor.start_child(supervisor, {task, id})
  rescue
    _error -> {:error, :supervisor_unavailable}
  catch
    :exit, _reason -> {:error, :supervisor_unavailable}
  end

  defp schedule_recovery(interval), do: Process.send_after(self(), :recover, interval)

  defp recoverable?(task) do
    task.node == node() and not task.terminal? and old_enough_to_recover?(task.updated_at)
  end

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
