defmodule Ouroboros.Coding.Recovery do
  @moduledoc false

  use GenServer

  alias Ouroboros.Coding.Store

  @interval 1_000
  @restart_grace_seconds 2
  @prune_interval 60_000
  @default_retention_ms 7 * 24 * 60 * 60 * 1_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name_option(Keyword.get(opts, :name, __MODULE__)))
  end

  @impl true
  def init(opts) do
    state = %{
      interval: Keyword.get(opts, :interval, @interval),
      prune_interval: Keyword.get(opts, :prune_interval, @prune_interval),
      last_prune: nil
    }

    {:ok, state, {:continue, :recover}}
  end

  @impl true
  def handle_continue(:recover, state), do: {:noreply, tick(state)}

  @impl true
  def handle_info(:recover, state), do: {:noreply, tick(state)}

  def handle_info(_message, state), do: {:noreply, state}

  defp tick(state) do
    recover_tasks()
    state = sweep_terminal(state)
    schedule_recovery(state.interval)
    state
  end

  defp recover_tasks do
    with registry when is_pid(registry) <- Process.whereis(Ouroboros.Coding.Registry),
         supervisor when is_pid(supervisor) <-
           Process.whereis(Ouroboros.Coding.TaskSupervisor),
         tasks when is_list(tasks) <- safe_list_recoverable() do
      tasks
      |> Enum.filter(&recoverable?/1)
      |> Enum.each(fn task ->
        if safe_whereis(task.id) == nil do
          _ = safe_start_child(supervisor, task.id)
        end
      end)
    else
      _unavailable -> :ok
    end
  end

  # The projection carries only routing and lifecycle fields. Listing full task
  # states here would deep-copy every retained event list once per second.
  defp safe_list_recoverable do
    Store.list_recoverable()
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, _reason -> {:error, :store_unavailable}
  end

  defp safe_whereis(id) do
    Ouroboros.Coding.Task.whereis(id)
  rescue
    _error -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  defp safe_start_child(supervisor, id) do
    DynamicSupervisor.start_child(supervisor, {Ouroboros.Coding.Task, id})
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

  # Terminal tasks are the only unbounded growth in this plane: nothing else ever
  # leaves the aggregate. Sweeping on the recovery tick keeps the retention policy
  # in one supervised loop, throttled so a one-second tick never becomes a
  # one-second whole-aggregate rewrite.
  defp sweep_terminal(state) do
    now = System.monotonic_time(:millisecond)
    retention = retention_ms()

    if is_integer(retention) and due?(state.last_prune, now, state.prune_interval) do
      _ = safe_prune(retention)
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

  defp safe_prune(retention) do
    Store.prune_terminal(retention)
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, _reason -> {:error, :store_unavailable}
  end

  defp name_option(nil), do: []
  defp name_option(name), do: [name: name]
end
