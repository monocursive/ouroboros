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

  use Ouroboros.Action,
    name: "plan",
    description:
      "Record the current plan. Replaces the whole plan; send every step each time. " <>
        "Optional — use it when a task has enough steps that the operator should see them.",
    schema: [
      steps: [
        # The exact nested contract is `model_schema/0`. Runtime input stays `:any`
        # because model JSON uses string keys and NimbleOptions' `:map` type accepts
        # atom-keyed maps only; `run/2` deliberately normalizes both forms.
        type: {:list, :any},
        required: true,
        doc:
          "The full ordered plan. Each step is {\"step\": \"...\", " <>
            "\"status\": \"pending\"|\"in_progress\"|\"completed\"}."
      ],
      accept: [
        type: {:list, :string},
        default: [],
        doc:
          "Work-item IDs the owning parent accepts against their declared criteria and evidence."
      ],
      explanation: [type: :string, default: "", doc: "One line on what the plan is for."]
    ]

  @doc "The nested schema shown to the model; the keyword schema converter cannot name map fields."
  @spec model_schema() :: map()
  @impl true
  def model_schema do
    %{
      "type" => "object",
      "properties" => %{
        "steps" => %{
          "type" => "array",
          "description" => "The full ordered plan. Each step has text and one lifecycle status.",
          "items" => %{
            "type" => "object",
            "properties" => %{
              "step" => %{"type" => "string", "description" => "The work item."},
              "status" => %{
                "type" => "string",
                "enum" => ["pending", "in_progress", "completed"],
                "description" => "The work item's current lifecycle state."
              },
              "id" => %{"type" => "string", "description" => "Stable work-item identity."},
              "deliverable" => %{
                "type" => "string",
                "enum" => ["analysis", "implementation", "validation"]
              },
              "work_state" => %{
                "type" => "string",
                "enum" => [
                  "planned",
                  "investigating",
                  "blocked",
                  "change_proposed",
                  "checking",
                  "reviewing",
                  "accepted",
                  "failed"
                ]
              },
              "owner_task_id" => %{"type" => "string"},
              "criteria" => %{
                "type" => "array",
                "items" => %{"type" => "string"},
                "maxItems" => 16
              },
              "evidence" => %{
                "type" => "array",
                "items" => %{"type" => "string"},
                "maxItems" => 16
              },
              "child_settlement" => %{
                "type" => "string",
                "enum" => ["unsettled", "completed", "failed", "cancelled", "lost"]
              },
              "blocker" => %{
                "type" => "object",
                "properties" => %{
                  "type" => %{
                    "type" => "string",
                    "enum" => [
                      "missing_input",
                      "scope_too_broad",
                      "unsupported_environment",
                      "needs_parent_integration",
                      "dependency_failed",
                      "other"
                    ]
                  },
                  "resolvable_by_parent" => %{"type" => "boolean"},
                  "detail" => %{"type" => "string"}
                },
                "required" => ["type", "resolvable_by_parent"],
                "additionalProperties" => false
              },
              "acceptance" => %{
                "type" => "object",
                "properties" => %{
                  "actor" => %{"type" => "string"},
                  "basis" => %{"type" => "string", "enum" => ["model_judgment"]},
                  "deterministic" => %{"type" => "boolean", "enum" => [false]}
                },
                "required" => ["actor", "basis", "deterministic"],
                "additionalProperties" => false
              }
            },
            "required" => ["step", "status"],
            "additionalProperties" => false
          }
        },
        "explanation" => %{
          "type" => "string",
          "description" => "One line on what the plan is for."
        },
        "accept" => %{
          "type" => "array",
          "description" =>
            "Work-item IDs this owning parent accepts; acceptance requires criteria and evidence.",
          "items" => %{"type" => "string"},
          "maxItems" => 40
        }
      },
      "required" => ["steps"],
      "additionalProperties" => false
    }
  end

  @statuses ~w(pending in_progress completed)
  @max_steps 40

  alias Ouroboros.Provider.Native.WorkItem

  @impl true
  def run(params, context) do
    with {:ok, steps} <- normalize_steps(params.steps, params.accept != [], context),
         {:ok, steps} <- accept(steps, params.accept, context) do
      authority = retained_authority(steps, context)

      {:ok,
       %{
         output: render(steps),
         is_error: false,
         plan:
           %{"plan" => steps, "explanation" => params.explanation}
           |> maybe_authority(authority)
       }}
    else
      {:error, reason} ->
        {:ok, %{output: "Plan refused: #{describe(reason)}", is_error: true}}
    end
  end

  defp normalize_steps(steps, additive?, context) do
    if length(steps) > @max_steps do
      {:error, {:steps, :too_many}}
    else
      steps
      |> Enum.reduce_while({:ok, []}, fn step, {:ok, acc} ->
        case normalize_step(step, additive?, context) do
          {:ok, item} -> {:cont, {:ok, [item | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> then(fn
        {:ok, items} -> unique_items(Enum.reverse(items))
        error -> error
      end)
    end
  end

  defp unique_items(items) do
    ids = items |> Enum.map(& &1["id"]) |> Enum.reject(&is_nil/1)
    if length(ids) == length(Enum.uniq(ids)), do: {:ok, items}, else: {:error, {:id, :duplicate}}
  end

  defp normalize_step(step, additive?, context) do
    if accepted_step?(step) do
      retained =
        context
        |> Map.get(:current_plan, %{})
        |> Map.get("plan", [])
        |> Enum.find(&(&1["id"] == value(step, "id")))

      WorkItem.restore_accepted(step, retained)
    else
      if additive? or additive_step?(step) do
        if additive_step?(step) and is_map(step) and
             not (Map.has_key?(step, "id") or Map.has_key?(step, :id)) do
          {:error, {:id, :required}}
        else
          with {:ok, item} <- WorkItem.normalize_step(legacy(step)) do
            {:ok, apply_authority(item, context)}
          end
        end
      else
        {:ok, normalize_legacy_step(step)}
      end
    end
  end

  defp accepted_step?(step) when is_map(step), do: value(step, "work_state") == "accepted"
  defp accepted_step?(_step), do: false

  defp apply_authority(item, context) do
    case get_in(context, [:current_plan, "authority", item["id"]]) do
      %{"task_id" => task_id} -> Map.put(item, "owner_task_id", task_id)
      _ -> item
    end
  end

  defp retained_authority(steps, context) do
    ids = MapSet.new(steps, & &1["id"])

    context
    |> get_in([:current_plan, "authority"])
    |> case do
      authority when is_map(authority) -> Map.take(authority, MapSet.to_list(ids))
      _ -> %{}
    end
  end

  defp maybe_authority(plan, authority) when map_size(authority) == 0, do: plan
  defp maybe_authority(plan, authority), do: Map.put(plan, "authority", authority)

  defp value(map, key), do: Map.get(map, key) || Map.get(map, String.to_atom(key))

  defp additive_step?(step) when is_map(step) do
    fields =
      ~w(id deliverable work_state owner_task_id criteria evidence blocker child_settlement acceptance)

    Enum.any?(fields, &(Map.has_key?(step, &1) or Map.has_key?(step, String.to_atom(&1))))
  end

  defp additive_step?(_step), do: false

  defp normalize_legacy_step(step) when is_map(step) do
    %{
      "step" => step |> fetch(["step", "content", "title"]) |> to_text(),
      "status" => step |> fetch(["status", "state"]) |> to_status()
    }
  end

  defp normalize_legacy_step(step), do: %{"step" => to_text(step), "status" => "pending"}

  # Old callers could send strings and unknown legacy statuses. Keep that translation only
  # when no additive work-item field is present; additive callers receive strict refusals.
  defp legacy(step) when is_binary(step), do: %{"step" => step}

  defp legacy(step) when is_map(step) do
    additive =
      ~w(id deliverable work_state owner_task_id criteria evidence blocker child_settlement acceptance)

    if Enum.any?(additive, &(Map.has_key?(step, &1) or Map.has_key?(step, String.to_atom(&1)))) do
      step
    else
      status = fetch(step, ["status", "state"])
      if to_string(status || "pending") in @statuses, do: step, else: put_status(step, "pending")
    end
  end

  defp legacy(step), do: %{"step" => to_text(step)}

  defp put_status(step, status),
    do: step |> Map.drop([:status, :state, "state"]) |> Map.put("status", status)

  defp accept(steps, [], _context), do: {:ok, steps}

  defp accept(_steps, _ids, %{subagent_depth: depth}) when is_integer(depth) and depth > 0,
    do: {:error, {:acceptance, :child_cannot_accept}}

  defp accept(steps, ids, context) when is_list(ids) do
    if length(ids) > @max_steps or length(ids) != length(Enum.uniq(ids)) do
      {:error, {:acceptance, :invalid}}
    else
      do_accept(steps, ids, context)
    end
  end

  defp do_accept(steps, ids, context) do
    if length(ids) != length(Enum.filter(ids, &is_binary/1)) do
      {:error, {:acceptance, :invalid}}
    else
      actor = Map.get(context, :principal, "native-parent")

      Enum.reduce_while(ids, {:ok, steps}, fn id, {:ok, current} ->
        case Enum.find_index(current, &(&1["id"] == id)) do
          nil ->
            {:halt, {:error, {:acceptance, :unknown_item}}}

          index ->
            item = Enum.at(current, index)

            case owned_terminal(item, context) do
              {:ok, settlement} ->
                item = Map.put(item, "child_settlement", settlement)

                case WorkItem.accept(item, actor, item["evidence"]) do
                  {:ok, accepted} -> {:cont, {:ok, List.replace_at(current, index, accepted)}}
                  error -> {:halt, error}
                end

              error ->
                {:halt, error}
            end
        end
      end)
    end
  end

  defp owned_terminal(%{"id" => item_id, "owner_task_id" => task_id} = item, context) do
    binding = get_in(context, [:current_plan, "authority", item_id])

    with %{
           "task_id" => ^task_id,
           "digest" => digest,
           "state" => "settled",
           "receipt" => receipt
         } <- binding,
         true <- digest == WorkItem.authority_digest(item, parent_session(context)),
         %{
           "task_id" => ^task_id,
           "item_id" => ^item_id,
           "binding_digest" => ^digest,
           "settlement" => settlement
         } <- receipt,
         true <- settlement in ~w(completed failed cancelled lost) do
      {:ok, settlement}
    else
      %{"state" => "running"} -> {:error, {:acceptance, :child_not_terminal}}
      nil -> {:error, {:acceptance, :foreign_owner}}
      _ -> {:error, {:acceptance, :owner_item_mismatch}}
    end
  end

  defp owned_terminal(%{"owner_task_id" => _}, _context),
    do: {:error, {:acceptance, :foreign_owner}}

  defp owned_terminal(_item, _context), do: {:ok, "unsettled"}

  defp parent_session(%{provider_session_id: id}) when is_binary(id), do: id
  defp parent_session(%{principal: id}) when is_binary(id), do: id
  defp parent_session(_), do: "native-parent"

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

  defp describe({field, reason}), do: "#{field} #{reason}"
  defp describe(reason), do: inspect(reason)
end
