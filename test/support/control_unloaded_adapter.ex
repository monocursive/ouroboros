defmodule Ouroboros.Control.UnloadedAdapter do
  @behaviour Ouroboros.Control.Planner
  @behaviour Ouroboros.Control.Evaluator

  @impl true
  def plan(_objective, _context, _opts),
    do: {:ok, [%{id: "cold", input: %{objective: "cold"}}]}

  @impl true
  def evaluate(_context, _opts), do: {:ok, :accept}
end
