defmodule Ouroboros.Interactive.Recovery do
  @moduledoc false

  use GenServer

  alias Ouroboros.Interactive.{Store, Task}

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
    recover_sessions()
    state = sweep_terminal(state)
    schedule_recovery(state.interval)
    state
  end

  defp recover_sessions do
    case {Process.whereis(Ouroboros.Interactive.Registry),
          Process.whereis(Ouroboros.Interactive.TaskSupervisor), safe_list_recoverable()} do
      {registry, supervisor, sessions}
      when is_pid(registry) and is_pid(supervisor) and is_list(sessions) ->
        sessions
        |> Enum.filter(&recoverable?/1)
        |> Enum.each(fn session ->
          # Without the liveness check every live session pays for a failed
          # registration once per second, forever.
          if safe_whereis(session.id) == nil do
            _ = safe_start_child(supervisor, session.id)
          end
        end)

      _unavailable ->
        :ok
    end
  end

  defp recoverable?(session) do
    session.node == node() and not session.terminal? and
      old_enough_to_recover?(session.updated_at)
  end

  # A coordinator that was restarted moments ago is still reattaching. Recovery
  # only owns sessions whose owner has been gone long enough to be missing.
  defp old_enough_to_recover?(updated_at) do
    with {:ok, timestamp, _offset} <- DateTime.from_iso8601(updated_at) do
      DateTime.diff(DateTime.utc_now(), timestamp, :second) >= @restart_grace_seconds
    else
      _error -> true
    end
  end

  defp safe_whereis(id) do
    Task.whereis(id)
  rescue
    _error -> :unavailable
  catch
    :exit, _reason -> :unavailable
  end

  defp safe_start_child(supervisor, id) do
    case DynamicSupervisor.start_child(supervisor, {Task, id}) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, _reason} -> :ok
    end
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  # The projection carries only routing and lifecycle fields. Listing full session
  # states here would deep-copy every retained event list and turn map every tick.
  defp safe_list_recoverable do
    Store.list_recoverable()
  rescue
    _error -> {:error, :store_unavailable}
  catch
    :exit, reason -> {:error, reason}
  end

  defp schedule_recovery(interval), do: Process.send_after(self(), :recover, interval)

  # Terminal sessions are the only unbounded growth in this plane: nothing else
  # ever leaves the aggregate. Sweeping on the recovery tick keeps the retention
  # policy in one supervised loop, throttled so a one-second tick never becomes a
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
