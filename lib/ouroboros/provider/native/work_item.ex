defmodule Ouroboros.Provider.Native.WorkItem do
  @moduledoc """
  Pure normalization and acceptance rules for bounded native-provider work items.

  The normalized map deliberately retains the legacy `"step"` and `"status"`
  fields. A legacy `"completed"` step becomes `"change_proposed"`, not
  `"accepted"`: process or plan settlement is not deliverable acceptance.
  Acceptance is a separate operation whose actor is a trusted caller argument.

  This module owns no persistence and performs no process or transport work.
  """

  @typedoc "Legacy plan lifecycle status: `pending`, `in_progress`, or `completed`."
  @type status :: String.t()

  @typedoc "Artifact class: `analysis`, `implementation`, or `validation`."
  @type deliverable :: String.t()

  @typedoc "Deliverable state from the closed vocabulary documented by this module."
  @type work_state :: String.t()

  @typedoc "A bounded, typed reason work cannot proceed."
  @type blocker :: %{required(String.t()) => String.t() | boolean()}

  @typedoc "Transport/child settlement; it never implies deliverable acceptance."
  @type child_settlement :: String.t()

  @typedoc "Canonical string-keyed work item returned by this module."
  @type t :: %{required(String.t()) => term()}

  @typedoc "A stable validation failure suitable for returning to an untrusted caller."
  @type reason :: {atom(), atom()}

  @statuses ~w(pending in_progress completed)
  @deliverables ~w(analysis implementation validation)
  @work_states ~w(planned investigating blocked change_proposed checking reviewing accepted failed)
  @settlements ~w(unsettled completed failed cancelled lost)
  @blocker_types ~w(missing_input scope_too_broad unsupported_environment needs_parent_integration dependency_failed other)

  @max_step_bytes 200
  @max_id_bytes 64
  @max_owner_bytes 128
  @max_actor_bytes 128
  @max_refs 16
  @max_ref_bytes 512
  @max_criteria 16
  @max_criterion_bytes 500
  @max_blocker_detail_bytes 500

  @aliases %{
    "step" => ["step", :step, "content", :content, "title", :title],
    "status" => ["status", :status, "state", :state],
    "id" => ["id", :id],
    "deliverable" => ["deliverable", :deliverable],
    "work_state" => ["work_state", :work_state],
    "owner_task_id" => ["owner_task_id", :owner_task_id],
    "criteria" => ["criteria", :criteria],
    "evidence" => ["evidence", :evidence],
    "blocker" => ["blocker", :blocker],
    "child_settlement" => ["child_settlement", :child_settlement]
  }
  @allowed_keys @aliases |> Map.values() |> List.flatten()

  @doc """
  Normalizes one legacy or additive plan step without side effects.

  Missing additive fields receive conservative defaults. IDs omitted by this pure compatibility
  normalizer are deterministically derived from text; the Plan boundary requires explicit IDs
  for additive campaign items while legacy display-only plans use their separate path.
  Unknown keys, explicit nulls, aliases supplied more than once, and values outside the
  documented bounds are rejected.
  """
  @spec normalize_step(map()) :: {:ok, t()} | {:error, reason()}
  def normalize_step(step) when is_map(step) do
    with :ok <- reject_unknown_keys(step),
         {:ok, text} <- required_text(step, "step", @max_step_bytes),
         {:ok, status} <- enum(step, "status", @statuses, "pending"),
         {:ok, id} <- optional_id(step, text),
         {:ok, deliverable} <- enum(step, "deliverable", @deliverables, "implementation"),
         {:ok, work_state} <- work_state(step, status),
         :ok <- compatible_status(status, work_state),
         {:ok, owner} <- optional_text(step, "owner_task_id", @max_owner_bytes, :identifier),
         {:ok, criteria} <- string_list(step, "criteria", @max_criteria, @max_criterion_bytes),
         {:ok, evidence} <- string_list(step, "evidence", @max_refs, @max_ref_bytes),
         {:ok, blocker} <- blocker(step),
         :ok <- compatible_blocker(work_state, blocker),
         {:ok, settlement} <- enum(step, "child_settlement", @settlements, "unsettled") do
      item = %{
        "id" => id,
        "step" => text,
        "status" => status,
        "deliverable" => deliverable,
        "work_state" => work_state,
        "criteria" => criteria,
        "evidence" => evidence,
        "child_settlement" => settlement
      }

      {:ok, item |> maybe_put("owner_task_id", owner) |> maybe_put("blocker", blocker)}
    end
  end

  def normalize_step(_step), do: {:error, {:step, :invalid}}

  @doc """
  Accepts an existing item using an actor supplied by trusted runtime code.

  The item must have at least one bounded acceptance criterion, and `evidence`
  must be a nonempty bounded list of references. Model-provided acceptance
  fields are not recognized by `normalize_step/1`; only this function can
  create `"acceptance"` and move the item to `"accepted"`.
  """
  @spec accept(map(), String.t(), [String.t()]) :: {:ok, t()} | {:error, reason()}
  def accept(item, trusted_actor, evidence) do
    with {:ok, normalized} <- normalize_step(item),
         :ok <- require_criteria(normalized["criteria"]),
         {:ok, actor} <- bounded_identifier(trusted_actor, @max_actor_bytes, :acceptance_actor),
         {:ok, refs} <- validate_string_list(evidence, @max_refs, @max_ref_bytes, :evidence),
         :ok <- require_evidence(refs) do
      {:ok,
       normalized
       |> Map.put("status", "completed")
       |> Map.put("work_state", "accepted")
       |> Map.put("evidence", refs)
       |> Map.put("acceptance", %{
         "actor" => actor,
         "decision_source" => "parent_model",
         "basis" => "model_judgment",
         "evidence_validation" => "unchecked_references",
         "deterministic" => false
       })}
    end
  end

  @doc "Restores only an accepted item that exactly matches authoritative retained plan state."
  @spec restore_accepted(map(), map()) :: {:ok, t()} | {:error, reason()}
  def restore_accepted(item, retained) when is_map(item) and is_map(retained) do
    if item == retained and retained["work_state"] == "accepted" and
         is_map(retained["acceptance"]) do
      {:ok, retained}
    else
      {:error, {:acceptance, :untrusted_replay}}
    end
  end

  def restore_accepted(_item, _retained), do: {:error, {:acceptance, :untrusted_replay}}

  @doc "Digest binding immutable delegation fields for one normalized work item."
  def authority_digest(%{} = item, parent_session) when is_binary(parent_session) do
    bound = %{
      "parent_session" => parent_session,
      "item_id" => item["id"],
      "step" => item["step"],
      "deliverable" => item["deliverable"],
      "criteria" => item["criteria"]
    }

    :crypto.hash(:sha256, :erlang.term_to_binary(bound, [:deterministic]))
    |> Base.encode16(case: :lower)
  end

  defp reject_unknown_keys(map) do
    if Enum.all?(Map.keys(map), &(&1 in @allowed_keys)),
      do: :ok,
      else: {:error, {:fields, :unknown}}
  end

  defp fetch(map, field) do
    present = Enum.filter(Map.fetch!(@aliases, field), &Map.has_key?(map, &1))

    case present do
      [] -> :missing
      [key] -> {:ok, Map.fetch!(map, key)}
      _ -> {:error, {field_atom(field), :conflicting}}
    end
  end

  defp required_text(map, field, max) do
    case fetch(map, field) do
      {:ok, value} -> bounded_text(value, max, field_atom(field))
      :missing -> {:error, {field_atom(field), :required}}
      error -> error
    end
  end

  defp optional_text(map, field, max, kind) do
    case fetch(map, field) do
      :missing -> {:ok, nil}
      {:ok, value} when kind == :identifier -> bounded_identifier(value, max, field_atom(field))
      {:ok, value} -> bounded_text(value, max, field_atom(field))
      error -> error
    end
  end

  defp bounded_text(value, max, field) when is_binary(value) do
    trimmed = String.trim(value)

    cond do
      not String.valid?(trimmed) -> {:error, {field, :invalid}}
      trimmed == "" -> {:error, {field, :empty}}
      byte_size(trimmed) > max -> {:error, {field, :too_large}}
      true -> {:ok, trimmed}
    end
  end

  defp bounded_text(_value, _max, field), do: {:error, {field, :invalid}}

  defp bounded_identifier(value, max, field) do
    with {:ok, text} <- bounded_text(value, max, field) do
      if Regex.match?(~r/\A[A-Za-z0-9][A-Za-z0-9._:-]*\z/, text),
        do: {:ok, text},
        else: {:error, {field, :invalid}}
    end
  end

  defp optional_id(map, text) do
    case fetch(map, "id") do
      :missing -> {:ok, derived_id(text)}
      {:ok, value} -> bounded_identifier(value, @max_id_bytes, :id)
      error -> error
    end
  end

  defp derived_id(text) do
    digest = :crypto.hash(:sha256, text) |> Base.encode16(case: :lower)
    "wi-" <> binary_part(digest, 0, 24)
  end

  defp enum(map, field, allowed, default) do
    case fetch(map, field) do
      :missing ->
        {:ok, default}

      {:ok, value} when is_atom(value) and not is_nil(value) ->
        enum_value(Atom.to_string(value), allowed, field)

      {:ok, value} ->
        enum_value(value, allowed, field)

      error ->
        error
    end
  end

  defp enum_value(value, allowed, field) when is_binary(value) do
    if value in allowed,
      do: {:ok, value},
      else: {:error, {field_atom(field), :invalid}}
  end

  defp enum_value(_value, _allowed, field), do: {:error, {field_atom(field), :invalid}}

  defp work_state(map, status) do
    default = %{
      "pending" => "planned",
      "in_progress" => "investigating",
      "completed" => "change_proposed"
    }

    enum(map, "work_state", @work_states -- ["accepted"], Map.fetch!(default, status))
  end

  defp compatible_status(status, state) do
    expected = %{
      "planned" => "pending",
      "investigating" => "in_progress",
      "blocked" => "pending",
      "change_proposed" => "completed",
      "checking" => "in_progress",
      "reviewing" => "in_progress",
      "failed" => "completed"
    }

    if Map.fetch!(expected, state) == status,
      do: :ok,
      else: {:error, {:status, :conflicting}}
  end

  defp string_list(map, field, max_count, max_bytes) do
    case fetch(map, field) do
      :missing -> {:ok, []}
      {:ok, value} -> validate_string_list(value, max_count, max_bytes, field_atom(field))
      error -> error
    end
  end

  defp validate_string_list(values, max_count, max_bytes, field) when is_list(values) do
    cond do
      length(values) > max_count ->
        {:error, {field, :too_many}}

      true ->
        Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
          case bounded_text(value, max_bytes, field) do
            {:ok, text} -> {:cont, {:ok, [text | acc]}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)
        |> case do
          {:ok, result} -> {:ok, Enum.reverse(result)}
          error -> error
        end
    end
  end

  defp validate_string_list(_values, _max_count, _max_bytes, field),
    do: {:error, {field, :invalid}}

  defp blocker(map) do
    case fetch(map, "blocker") do
      :missing -> {:ok, nil}
      {:ok, value} when is_map(value) -> normalize_blocker(value)
      {:ok, _value} -> {:error, {:blocker, :invalid}}
      error -> error
    end
  end

  defp normalize_blocker(map) do
    allowed = ["type", :type, "resolvable_by_parent", :resolvable_by_parent, "detail", :detail]

    with true <- Enum.all?(Map.keys(map), &(&1 in allowed)) || {:error, {:blocker, :unknown}},
         {:ok, type} <- blocker_field(map, "type", :required),
         true <- type in @blocker_types || {:error, {:blocker, :invalid}},
         {:ok, resolvable} <- blocker_field(map, "resolvable_by_parent", :required),
         true <- is_boolean(resolvable) || {:error, {:blocker, :invalid}},
         {:ok, detail} <- blocker_detail(map) do
      {:ok,
       %{"type" => type, "resolvable_by_parent" => resolvable}
       |> maybe_put("detail", detail)}
    else
      {:error, _reason} = error -> error
    end
  end

  defp blocker_field(map, name, :required) do
    keys = [name, field_atom(name)] |> Enum.filter(&Map.has_key?(map, &1))

    case keys do
      [key] -> {:ok, Map.fetch!(map, key)}
      [] -> {:error, {:blocker, :required}}
      _ -> {:error, {:blocker, :conflicting}}
    end
  end

  defp blocker_detail(map) do
    case blocker_field(map, "detail", :required) do
      {:ok, value} -> bounded_text(value, @max_blocker_detail_bytes, :blocker)
      {:error, {:blocker, :required}} -> {:ok, nil}
      error -> error
    end
  end

  defp compatible_blocker("blocked", nil), do: {:error, {:blocker, :required}}
  defp compatible_blocker("blocked", _blocker), do: :ok
  defp compatible_blocker(_state, nil), do: :ok
  defp compatible_blocker(_state, _blocker), do: {:error, {:blocker, :conflicting}}

  defp require_criteria([]), do: {:error, {:criteria, :required}}
  defp require_criteria(_criteria), do: :ok
  defp require_evidence([]), do: {:error, {:evidence, :required}}
  defp require_evidence(_evidence), do: :ok

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  # Static conversion only; never call String.to_atom/1 on model input.
  defp field_atom("step"), do: :step
  defp field_atom("status"), do: :status
  defp field_atom("id"), do: :id
  defp field_atom("deliverable"), do: :deliverable
  defp field_atom("work_state"), do: :work_state
  defp field_atom("owner_task_id"), do: :owner_task_id
  defp field_atom("criteria"), do: :criteria
  defp field_atom("evidence"), do: :evidence
  defp field_atom("blocker"), do: :blocker
  defp field_atom("child_settlement"), do: :child_settlement
  defp field_atom("type"), do: :type
  defp field_atom("resolvable_by_parent"), do: :resolvable_by_parent
  defp field_atom("detail"), do: :detail
end
