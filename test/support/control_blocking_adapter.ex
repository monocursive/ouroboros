defmodule Ouroboros.Control.BlockingAdapter do
  @moduledoc false

  @behaviour Ouroboros.Control.Planner
  @behaviour Ouroboros.Control.Evaluator

  @impl true
  def plan(objective, context, opts) do
    if objective in Keyword.get(opts, :block_planning_for, []) do
      block(:planner, context, opts)
    else
      {:ok, [%{id: "work", input: %{objective: objective}}]}
    end
  end

  @impl true
  def evaluate(context, opts) do
    if context.run_id in Keyword.get(opts, :block_evaluation_for, []) do
      block(:evaluator, context, opts)
    else
      {:ok, :accept}
    end
  end

  defp block(kind, context, opts) do
    send(Keyword.fetch!(opts, :test_pid), {:control_callback_blocked, kind, self(), context})

    receive do
      {:release_control_callback, result} -> result
    end
  end
end
