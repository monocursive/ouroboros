defmodule Ouroboros.Control.EvidenceContract do
  @moduledoc """
  Content-minimized evidence attached to a terminal control decision.

  The contract records identifiers, classifications, outcomes, and SHA-256 digests,
  never the underlying command output, model prose, file content, or credential-bearing
  payload. Evidence payloads remain in the plane that owns them; a digest makes a later
  comparison possible without turning the control checkpoint into a second transcript.

  Input may use atom or string keys. `normalize/1` returns one canonical atom-keyed map
  and rejects unknown fields, duplicate IDs, dangling references, and unsupported enum
  values. IDs are caller supplied but transport-safe; digests are lowercase SHA-256 hex.
  """

  @id_regex ~r/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
  @digest_regex ~r/^[0-9a-f]{64}$/
  @classifications [:observed, :inferred, :assumed]
  @claim_statuses [:supported, :unsupported, :unknown]
  @criterion_statuses [:met, :not_met, :unknown]
  @evidence_kinds [:test, :diagnostic, :runtime, :ledger, :artifact, :operator]
  @evidence_outcomes [:pass, :fail, :ambiguous, :unverified]

  @type t :: %{
          version: 1,
          criteria: [map()],
          claims: [map()],
          evidence: [map()]
        }

  @spec normalize(term()) :: {:ok, t()} | {:error, term()}
  def normalize(contract) when is_map(contract) and not is_struct(contract) do
    with {:ok, fields} <- fields(contract, [:version, :criteria, :claims, :evidence]),
         :ok <- require_exact(fields, [:version, :criteria, :claims, :evidence], :contract),
         :ok <- require_version(fields.version),
         {:ok, evidence} <- normalize_list(fields.evidence, &normalize_evidence/1, :evidence),
         :ok <- unique_ids(evidence, :evidence),
         evidence_ids <- MapSet.new(Enum.map(evidence, & &1.id)),
         {:ok, criteria} <-
           normalize_list(fields.criteria, &normalize_criterion(&1, evidence_ids), :criteria),
         :ok <- require_nonempty(criteria, :criteria),
         :ok <- unique_ids(criteria, :criteria),
         {:ok, claims} <-
           normalize_list(fields.claims, &normalize_claim(&1, evidence_ids), :claims),
         :ok <- unique_ids(claims, :claims) do
      {:ok, %{version: 1, criteria: criteria, claims: claims, evidence: evidence}}
    end
  end

  def normalize(_contract), do: {:error, :invalid_evidence_contract}

  @spec valid?(term()) :: boolean()
  def valid?(contract), do: match?({:ok, _}, normalize(contract))

  @spec digest(term()) :: {:ok, String.t()} | {:error, term()}
  def digest(contract) do
    with {:ok, normalized} <- normalize(contract) do
      {:ok,
       :sha256
       |> :crypto.hash(:erlang.term_to_binary(normalized, [:deterministic]))
       |> Base.encode16(case: :lower)}
    end
  end

  defp normalize_evidence(value) do
    with {:ok, item} <- fields(value, [:id, :kind, :outcome, :digest, :recorded_at]),
         :ok <- require_exact(item, [:id, :kind, :outcome, :digest, :recorded_at], :evidence),
         :ok <- valid_id(item.id, :evidence),
         {:ok, kind} <- enum(item.kind, @evidence_kinds, :evidence_kind),
         {:ok, outcome} <- enum(item.outcome, @evidence_outcomes, :evidence_outcome),
         :ok <- valid_digest(item.digest),
         :ok <- valid_timestamp(item.recorded_at) do
      {:ok,
       %{
         id: item.id,
         kind: kind,
         outcome: outcome,
         digest: item.digest,
         recorded_at: item.recorded_at
       }}
    end
  end

  defp normalize_criterion(value, evidence_ids) do
    with {:ok, item} <- fields(value, [:id, :status, :evidence_ids]),
         :ok <- require_exact(item, [:id, :status, :evidence_ids], :criterion),
         :ok <- valid_id(item.id, :criterion),
         {:ok, status} <- enum(item.status, @criterion_statuses, :criterion_status),
         {:ok, references} <- references(item.evidence_ids, evidence_ids),
         :ok <- require_decisive_evidence(status, references, :criterion) do
      {:ok, %{id: item.id, status: status, evidence_ids: references}}
    end
  end

  defp normalize_claim(value, evidence_ids) do
    with {:ok, item} <-
           fields(value, [:id, :classification, :status, :statement_digest, :evidence_ids]),
         :ok <-
           require_exact(
             item,
             [:id, :classification, :status, :statement_digest, :evidence_ids],
             :claim
           ),
         :ok <- valid_id(item.id, :claim),
         {:ok, classification} <- enum(item.classification, @classifications, :classification),
         {:ok, status} <- enum(item.status, @claim_statuses, :claim_status),
         :ok <- valid_digest(item.statement_digest),
         {:ok, references} <- references(item.evidence_ids, evidence_ids),
         :ok <- require_decisive_evidence(status, references, :claim) do
      {:ok,
       %{
         id: item.id,
         classification: classification,
         status: status,
         statement_digest: item.statement_digest,
         evidence_ids: references
       }}
    end
  end

  defp fields(value, allowed) when is_map(value) and not is_struct(value) do
    Enum.reduce_while(value, {:ok, %{}}, fn {key, field_value}, {:ok, acc} ->
      case normalize_key(key, allowed) do
        {:ok, normalized} ->
          if Map.has_key?(acc, normalized),
            do: {:halt, {:error, {:duplicate_field, normalized}}},
            else: {:cont, {:ok, Map.put(acc, normalized, field_value)}}

        :error ->
          {:halt, {:error, {:unknown_field, key}}}
      end
    end)
  end

  defp fields(_value, _allowed), do: {:error, :invalid_evidence_item}

  defp normalize_key(key, allowed) when is_atom(key),
    do: if(key in allowed, do: {:ok, key}, else: :error)

  defp normalize_key(key, allowed) when is_binary(key) do
    case Enum.find(allowed, &(Atom.to_string(&1) == key)) do
      nil -> :error
      normalized -> {:ok, normalized}
    end
  end

  defp normalize_key(_key, _allowed), do: :error

  defp require_exact(map, keys, scope) do
    if MapSet.new(Map.keys(map)) == MapSet.new(keys),
      do: :ok,
      else: {:error, {:invalid_fields, scope}}
  end

  defp require_version(1), do: :ok
  defp require_version("1"), do: :ok
  defp require_version(version), do: {:error, {:unsupported_evidence_contract_version, version}}

  defp normalize_list(values, fun, scope) when is_list(values) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, acc} ->
      case fun.(value) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, reason} -> {:halt, {:error, {scope, reason}}}
      end
    end)
    |> then(fn
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end)
  end

  defp normalize_list(_values, _fun, scope), do: {:error, {:invalid_list, scope}}

  defp unique_ids(items, scope) do
    ids = Enum.map(items, & &1.id)
    if ids == Enum.uniq(ids), do: :ok, else: {:error, {:duplicate_id, scope}}
  end

  defp require_nonempty([], scope), do: {:error, {:empty, scope}}
  defp require_nonempty(_items, _scope), do: :ok

  defp valid_id(id, _scope) when is_binary(id) do
    if Regex.match?(@id_regex, id), do: :ok, else: {:error, {:invalid_id, id}}
  end

  defp valid_id(id, _scope), do: {:error, {:invalid_id, id}}

  defp valid_digest(digest) when is_binary(digest) do
    if Regex.match?(@digest_regex, digest), do: :ok, else: {:error, :invalid_digest}
  end

  defp valid_digest(_digest), do: {:error, :invalid_digest}

  defp valid_timestamp(value) when is_integer(value) and value >= 0, do: :ok
  defp valid_timestamp(_value), do: {:error, :invalid_recorded_at}

  defp enum(value, allowed, field) when is_atom(value) do
    if value in allowed do
      {:ok, value}
    else
      {:error, {invalid_enum_error(field), value}}
    end
  end

  defp enum(value, allowed, field) when is_binary(value) do
    case Enum.find(allowed, &(Atom.to_string(&1) == value)) do
      nil -> {:error, {invalid_enum_error(field), value}}
      normalized -> {:ok, normalized}
    end
  end

  defp enum(value, _allowed, field), do: {:error, {invalid_enum_error(field), value}}

  defp invalid_enum_error(:evidence_kind), do: :invalid_evidence_kind
  defp invalid_enum_error(:evidence_outcome), do: :invalid_evidence_outcome
  defp invalid_enum_error(:criterion_status), do: :invalid_criterion_status
  defp invalid_enum_error(:classification), do: :invalid_classification
  defp invalid_enum_error(:claim_status), do: :invalid_claim_status

  defp references(values, evidence_ids) when is_list(values) do
    missing = Enum.reject(values, &MapSet.member?(evidence_ids, &1))

    cond do
      not Enum.all?(values, &is_binary/1) ->
        {:error, :invalid_evidence_references}

      values != Enum.uniq(values) ->
        {:error, :duplicate_evidence_reference}

      missing != [] ->
        {:error, {:unknown_evidence, missing}}

      true ->
        {:ok, values}
    end
  end

  defp references(_values, _evidence_ids), do: {:error, :invalid_evidence_references}

  defp require_decisive_evidence(status, [], scope)
       when status in [:met, :not_met, :supported, :unsupported],
       do: {:error, {:missing_evidence, scope}}

  defp require_decisive_evidence(_status, _references, _scope), do: :ok
end
