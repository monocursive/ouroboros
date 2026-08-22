defmodule Ouroboros.Provider.Native.Tools.Plan do
  @moduledoc """
  Record the plan for the current task, replacing it wholesale.

  Not a to-do list the model keeps for itself — the point is the `plan_updated` event,
  which the TUI already renders as a task panel for Codex sessions and which this
  provider would otherwise never produce. Replace-wholesale is ACP's agent-plan
  semantics, and it is why there is no "add one item" call to get out of sync with.

  It touches no file and needs no permission: it produces an event and nothing else,
  which is also why it is not one of the four tools the sandbox and the permission
  engine reason about.

  Pi dropped built-in TODOs because "they confuse models" (R3 §8d), and Claude Code
  disabled `TodoWrite` by default on its newest models. That is a warning about making
  planning *mandatory*, not about offering a channel: nothing in the prompt tells the
  model it must plan first.
  """

  use Jido.Action,
    name: "plan",
    description:
      "Record the current plan. Replaces the whole plan; send every step each time. " <>
        "Optional — use it when a task has enough steps that the operator should see them.",
    schema: [
      steps: [
        type: {:list, :map},
        required: true,
        doc:
          "The full ordered plan. Each step is {\"step\": \"...\", " <>
            "\"status\": \"pending\"|\"in_progress\"|\"completed\"}."
      ],
      explanation: [type: :string, default: "", doc: "One line on what the plan is for."]
    ]

  @statuses ~w(pending in_progress completed)
  @max_steps 40

  @impl true
  def run(params, _context) do
    steps =
      params.steps
      |> Enum.take(@max_steps)
      |> Enum.map(&normalize_step/1)
      |> Enum.reject(&(&1["step"] == ""))

    {:ok,
     %{
       output: render(steps),
       is_error: false,
       plan: %{"plan" => steps, "explanation" => params.explanation}
     }}
  end

  defp normalize_step(step) when is_map(step) do
    %{
      "step" => step |> fetch(["step", "content", "title"]) |> to_text(),
      "status" => step |> fetch(["status", "state"]) |> to_status()
    }
  end

  defp normalize_step(step), do: %{"step" => to_text(step), "status" => "pending"}

  defp fetch(map, keys) do
    Enum.find_value(keys, fn key -> Map.get(map, key) || Map.get(map, String.to_atom(key)) end)
  end

  defp to_text(value) when is_binary(value), do: value |> String.trim() |> String.slice(0, 200)
  defp to_text(nil), do: ""
  defp to_text(value), do: value |> to_string() |> String.slice(0, 200)

  defp to_status(value) when is_binary(value) do
    if value in @statuses, do: value, else: "pending"
  end

  defp to_status(value) when is_atom(value) and not is_nil(value),
    do: to_status(Atom.to_string(value))

  defp to_status(_value), do: "pending"

  defp render([]), do: "Plan cleared."

  defp render(steps) do
    "Plan updated:\n" <>
      Enum.map_join(steps, "\n", fn step -> "  #{glyph(step["status"])} #{step["step"]}" end)
  end

  defp glyph("completed"), do: "✓"
  defp glyph("in_progress"), do: "●"
  defp glyph(_pending), do: "◌"
end
