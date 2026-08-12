defmodule Ouroboros.Orchestration.TestExecutor do
  @behaviour Ouroboros.Orchestration.Executor

  @impl true
  def start(execution, _scheduler, opts) do
    send(Keyword.fetch!(opts, :test_pid), {:execution_started, execution})

    if Keyword.get(opts, :spawn_owner, false) do
      {:ok, spawn(fn -> owner_loop(Keyword.fetch!(opts, :test_pid)) end)}
    else
      :ok
    end
  end

  @impl true
  def cancel(execution, reason, opts) do
    send(Keyword.fetch!(opts, :test_pid), {:execution_cancelled, execution, reason})

    case Keyword.get(opts, :cancel_behavior, :ok) do
      :hang -> receive do: (:never -> :ok)
      result -> result
    end
  end

  defp owner_loop(test_pid) do
    monitor_ref = Process.monitor(test_pid)

    receive do
      :stop -> :ok
      {:DOWN, ^monitor_ref, :process, ^test_pid, _reason} -> :ok
    end
  end
end
