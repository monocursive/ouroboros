defmodule Ouroboros.Orchestration.Executor do
  @moduledoc """
  Adapter boundary between durable orchestration and an execution runtime.

  `start/3` must return promptly after arranging asynchronous work. The worker
  reports through `Ouroboros.Orchestration.Scheduler.complete/5` or `fail/5`.
  Returning an owner PID lets the scheduler monitor it without persisting it.

  `cancel/3` is optional and is always invoked in a separate monitored process.
  Durable cancellation is committed first, so a slow adapter cannot prevent it.
  """

  alias Ouroboros.Orchestration.Execution

  @callback start(Execution.t(), GenServer.server(), keyword()) ::
              {:ok, pid()} | :ok | {:error, term()}

  @callback cancel(Execution.t(), term(), keyword()) :: term()

  @optional_callbacks cancel: 3
end
