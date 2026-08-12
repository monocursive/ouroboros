defmodule Ouroboros.Coding.Recovery do
  @moduledoc false

  use GenServer

  alias Ouroboros.Coding.{Store, TaskState}

  @interval 1_000
  @restart_grace_seconds 2

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(_opts), do: {:ok, %{}, {:continue, :recover}}

  @impl true
  def handle_continue(:recover, state) do
    recover_tasks()
    schedule_recovery()
    {:noreply, state}
  end

  @impl true
  def handle_info(:recover, state) do
    recover_tasks()
    schedule_recovery()
    {:noreply, state}
  end

  defp recover_tasks do
    with registry when is_pid(registry) <- Process.whereis(Ouroboros.Coding.Registry),
         supervisor when is_pid(supervisor) <-
           Process.whereis(Ouroboros.Coding.TaskSupervisor),
         tasks when is_list(tasks) <- safe_list() do
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

  defp safe_list do
    Store.list()
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

  defp schedule_recovery, do: Process.send_after(self(), :recover, @interval)

  defp recoverable?(task) do
    task.node == node() and not TaskState.terminal?(task) and
      old_enough_to_recover?(task.updated_at)
  end

  defp old_enough_to_recover?(updated_at) do
    with {:ok, timestamp, _offset} <- DateTime.from_iso8601(updated_at) do
      DateTime.diff(DateTime.utc_now(), timestamp, :second) >= @restart_grace_seconds
    else
      _error -> true
    end
  end
end
