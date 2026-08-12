defmodule Ouroboros.Release.Journal do
  @moduledoc false

  @version 2
  @stages [:validated, :unpacked, :checked, :installed, :permanent]
  @operation_actions [:unpack, :check_install, :install, :make_permanent]
  @operation_outcomes [:pending, :succeeded, :failed, :interrupted_no_effect]

  @enforce_keys [:version, :mode, :next_sequence, :artifacts, :operations]
  defstruct @enforce_keys ++ [quarantine_reason: nil]

  @type t :: %__MODULE__{}

  @spec new() :: t()
  def new do
    %__MODULE__{
      version: @version,
      mode: :ready,
      next_sequence: 1,
      artifacts: %{},
      operations: []
    }
  end

  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{} = journal) do
    journal.version == @version and journal.mode in [:ready, :quarantined] and
      is_integer(journal.next_sequence) and journal.next_sequence > 0 and
      is_map(journal.artifacts) and is_list(journal.operations) and
      Enum.all?(journal.artifacts, &valid_artifact_entry?/1) and
      Enum.all?(journal.operations, &valid_operation?/1) and
      valid_relationships?(journal) and serializable?(journal)
  end

  def valid?(_journal), do: false

  @spec put_artifact(t(), map(), atom()) :: {:ok, t()} | {:error, term()}
  def put_artifact(%__MODULE__{} = journal, summary, stage) when stage in @stages do
    entry = %{
      artifact_id: summary.id,
      sha256: summary.sha256,
      package_name: summary.package_name,
      release_name: summary.release_name,
      version: summary.version,
      erts_version: summary.erts_version,
      inspection_policy: summary.inspection_policy,
      stage: stage,
      updated_at: now()
    }

    case Map.fetch(journal.artifacts, summary.sha256) do
      {:ok, existing} ->
        if same_artifact?(existing, entry),
          do: {:ok, journal},
          else: {:error, :release_artifact_identity_conflict}

      :error ->
        {:ok, put_in(journal.artifacts[summary.sha256], entry)}
    end
  end

  @spec advance(t(), String.t(), atom()) :: t()
  def advance(%__MODULE__{} = journal, sha256, stage) when stage in @stages do
    update_in(journal.artifacts[sha256], fn
      nil -> nil
      artifact -> %{artifact | stage: stage, updated_at: now()}
    end)
  end

  @spec append(t(), atom(), map(), atom(), term()) :: t()
  def append(%__MODULE__{} = journal, action, artifact, outcome, result)
      when action in @operation_actions and outcome in @operation_outcomes do
    operation = %{
      sequence: journal.next_sequence,
      action: action,
      artifact_id: artifact.id,
      sha256: artifact.sha256,
      release_name: artifact.release_name,
      version: artifact.version,
      outcome: outcome,
      result: sanitize(result),
      at: now()
    }

    %{
      journal
      | next_sequence: journal.next_sequence + 1,
        operations: trim(journal.operations ++ [operation])
    }
  end

  @spec update_latest_pending(t(), String.t(), atom(), atom(), term()) :: t()
  def update_latest_pending(%__MODULE__{} = journal, sha256, action, outcome, result)
      when outcome in @operation_outcomes do
    operations =
      journal.operations
      |> Enum.reverse()
      |> update_first(
        fn operation ->
          operation.sha256 == sha256 and operation.action == action and
            operation.outcome == :pending
        end,
        fn operation ->
          %{operation | outcome: outcome, result: sanitize(result), at: now()}
        end
      )
      |> Enum.reverse()

    %{journal | operations: operations}
  end

  @spec latest_pending(t()) :: map() | nil
  def latest_pending(%__MODULE__{} = journal) do
    journal.operations
    |> Enum.reverse()
    |> Enum.find(&(&1.outcome == :pending))
  end

  @spec quarantine(t(), term()) :: t()
  def quarantine(%__MODULE__{} = journal, reason) do
    %{journal | mode: :quarantined, quarantine_reason: sanitize(reason)}
  end

  @spec public(t()) :: map()
  def public(%__MODULE__{} = journal) do
    %{
      mode: journal.mode,
      quarantine_reason: journal.quarantine_reason,
      artifacts: journal.artifacts,
      operations: journal.operations
    }
  end

  defp valid_artifact_entry?({sha256, entry}) do
    is_binary(sha256) and byte_size(sha256) == 64 and is_map(entry) and
      entry.stage in @stages and entry.sha256 == sha256 and
      valid_inspection_policy?(entry.inspection_policy) and is_binary(entry.updated_at) and
      Enum.all?([:artifact_id, :package_name, :release_name, :version, :erts_version], fn key ->
        is_binary(Map.get(entry, key))
      end)
  end

  defp valid_operation?(operation) do
    is_map(operation) and is_integer(operation.sequence) and operation.sequence > 0 and
      operation.action in @operation_actions and operation.outcome in @operation_outcomes and
      is_binary(operation.artifact_id) and is_binary(operation.sha256) and
      is_binary(operation.release_name) and is_binary(operation.version) and
      is_binary(operation.at)
  end

  defp valid_relationships?(journal) do
    sequences = Enum.map(journal.operations, & &1.sequence)
    pending = Enum.count(journal.operations, &(&1.outcome == :pending))

    ordered_unique? = sequences == Enum.sort(sequences) and sequences == Enum.uniq(sequences)

    next_after_latest? =
      case List.last(sequences) do
        nil -> journal.next_sequence == 1
        latest -> journal.next_sequence == latest + 1
      end

    references_valid? =
      Enum.all?(journal.operations, fn operation ->
        case Map.fetch(journal.artifacts, operation.sha256) do
          {:ok, artifact} ->
            artifact.artifact_id == operation.artifact_id and
              artifact.release_name == operation.release_name and
              artifact.version == operation.version and
              operation_matches_stage?(operation, artifact.stage)

          :error ->
            false
        end
      end)

    quarantine_shape? =
      case journal.mode do
        :ready -> is_nil(journal.quarantine_reason)
        :quarantined -> not is_nil(journal.quarantine_reason)
      end

    ordered_unique? and next_after_latest? and pending <= 1 and references_valid? and
      quarantine_shape?
  end

  defp same_artifact?(existing, incoming) do
    keys = [
      :artifact_id,
      :sha256,
      :package_name,
      :release_name,
      :version,
      :erts_version,
      :inspection_policy
    ]

    Map.take(existing, keys) == Map.take(incoming, keys)
  end

  defp valid_inspection_policy?(policy) when is_list(policy) do
    Keyword.keyword?(policy) and
      Keyword.keys(policy) == [:max_archive_bytes, :max_metadata_bytes, :require_relup] and
      is_integer(policy[:max_archive_bytes]) and policy[:max_archive_bytes] > 0 and
      is_integer(policy[:max_metadata_bytes]) and policy[:max_metadata_bytes] > 0 and
      is_boolean(policy[:require_relup])
  end

  defp valid_inspection_policy?(_policy), do: false

  defp operation_matches_stage?(%{outcome: :pending, action: action}, stage) do
    pending_stage(action) == stage or
      (action in [:install, :make_permanent] and
         stage_rank(stage) >= stage_rank(completed_stage(action)))
  end

  defp operation_matches_stage?(%{outcome: :succeeded, action: action}, stage) do
    stage_rank(stage) >= stage_rank(completed_stage(action))
  end

  defp operation_matches_stage?(_operation, _stage), do: true

  defp pending_stage(:unpack), do: :validated
  defp pending_stage(:check_install), do: :unpacked
  defp pending_stage(:install), do: :checked
  defp pending_stage(:make_permanent), do: :installed

  defp completed_stage(:unpack), do: :unpacked
  defp completed_stage(:check_install), do: :checked
  defp completed_stage(:install), do: :installed
  defp completed_stage(:make_permanent), do: :permanent

  defp stage_rank(stage), do: Enum.find_index(@stages, &(&1 == stage))

  defp serializable?(value)
       when is_atom(value) or is_binary(value) or is_boolean(value) or is_number(value) or
              is_nil(value),
       do: true

  defp serializable?(value) when is_list(value), do: Enum.all?(value, &serializable?/1)

  defp serializable?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&serializable?/1)

  defp serializable?(%_{} = struct), do: struct |> Map.from_struct() |> serializable?()

  defp serializable?(value) when is_map(value) do
    Enum.all?(value, fn {key, item} -> serializable?(key) and serializable?(item) end)
  end

  defp serializable?(_value), do: false

  defp sanitize(value) do
    if serializable?(value), do: value, else: :redacted_nonserializable_result
  end

  defp update_first([item | rest], predicate, update) do
    if predicate.(item),
      do: [update.(item) | rest],
      else: [item | update_first(rest, predicate, update)]
  end

  defp update_first([], _predicate, _update), do: []

  defp trim(operations) when length(operations) > 100, do: Enum.take(operations, -100)
  defp trim(operations), do: operations

  defp now, do: DateTime.utc_now() |> DateTime.to_iso8601()
end
