defmodule Ouroboros.Storage.Records do
  @moduledoc """
  Per-record checkpoints with an authoritative versioned index.

  A new record is synced before publishing its id; deletion publishes the reduced index
  before removing orphan files. Existing records require one write. Migration leaves the
  legacy aggregate authoritative until every record is written. An ambiguous commit must
  stop the caller: neither rollback nor an in-memory success is justified.

  Owners supply record decoding and error names. Domain transitions and version checks
  belong to those owners. Individual unreadable records are quarantined; the index fails
  closed. The `:session` key tag preserves the existing interactive disk format.
  """
  require Logger

  def new(adapter, opts, key, errors, tag \\ :record),
    do: %{adapter: adapter, opts: opts, key: key, errors: errors, tag: tag}

  def load(repo, decode) do
    case call(repo, :get_checkpoint, [repo.key]) do
      :not_found -> {:ok, %{}}
      {:ok, %{version: 2, ids: ids}} -> load_index(repo, ids, decode)
      {:ok, records} when is_map(records) -> migrate(repo, records, decode)
      {:ok, _invalid} -> {:error, repo.errors.invalid}
      {:error, reason} -> {:error, {repo.errors.unreadable, reason}}
      other -> {:error, {:invalid_storage_response, other}}
    end
  end

  def put(repo, records, id, record) do
    with :ok <- write(repo, record_key(repo, id), %{id => record}) do
      if Map.has_key?(records, id) do
        :ok
      else
        case index(repo, Map.put(records, id, record)) do
          :ok ->
            :ok

          {:error, {:commit_outcome_unknown, _}} = ambiguous ->
            ambiguous

          {:error, _} = error ->
            _ = delete_record(repo, id)
            error
        end
      end
    end
  end

  def drop(repo, records, ids) do
    with :ok <- index(repo, Map.drop(records, ids)) do
      Enum.each(ids, &delete_record(repo, &1))
      :ok
    end
  end

  def reply(:ok, reply, _old, updated), do: {:reply, reply, updated}

  def reply({:error, {:commit_outcome_unknown, _} = reason}, _reply, old, _updated),
    do: {:stop, reason, {:error, reason}, old}

  def reply({:error, reason}, _reply, old, _updated), do: {:reply, {:error, reason}, old}

  def record_key(repo, id), do: {repo.key, repo.tag, 2, id}

  defp migrate(repo, records, decode) do
    with {:ok, records} <- decode_all(records, decode, repo.errors.invalid),
         :ok <- write_all(repo, records),
         :ok <- index(repo, records) do
      {:ok, records}
    else
      {:error, reason} when reason == repo.errors.invalid -> {:error, reason}
      {:error, reason} -> {:error, {repo.errors.migration, reason}}
    end
  end

  defp decode_all(records, decode, invalid) do
    Enum.reduce_while(records, {:ok, %{}}, fn {id, record}, {:ok, acc} ->
      case decode.(id, record) do
        {:ok, value} when is_binary(id) -> {:cont, {:ok, Map.put(acc, id, value)}}
        _invalid -> {:halt, {:error, invalid}}
      end
    end)
  end

  defp write_all(repo, records) do
    Enum.reduce_while(records, :ok, fn {id, record}, :ok ->
      case write(repo, record_key(repo, id), %{id => record}) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp load_index(repo, ids, decode) when is_list(ids) do
    if ids == Enum.uniq(ids) and Enum.all?(ids, &is_binary/1) do
      {records, bad} =
        Enum.reduce(ids, {%{}, []}, fn id, {records, bad} ->
          result =
            with {:ok, %{^id => record}} <- call(repo, :get_checkpoint, [record_key(repo, id)]),
                 do: decode.(id, record)

          case result do
            {:ok, value} -> {Map.put(records, id, value), bad}
            reason -> {records, [{id, reason} | bad]}
          end
        end)

      if bad == [] do
        {:ok, records}
      else
        Enum.each(bad, fn {id, reason} ->
          Logger.error(
            "checkpoint #{inspect(repo.key)} record #{id} could not be loaded (#{inspect(reason)}); quarantining it"
          )
        end)

        case index(repo, records) do
          :ok -> {:ok, records}
          {:error, reason} -> {:error, {repo.errors.quarantine, reason}}
        end
      end
    else
      {:error, repo.errors.invalid}
    end
  end

  defp load_index(repo, _ids, _decode), do: {:error, repo.errors.invalid}

  defp index(repo, records),
    do: write(repo, repo.key, %{version: 2, ids: records |> Map.keys() |> Enum.sort()})

  defp write(repo, key, value) do
    case call(repo, :put_checkpoint, [key, value]) do
      :ok -> :ok
      {:error, _} = error -> error
      other -> {:error, {:invalid_storage_response, other}}
    end
  end

  defp delete_record(repo, id), do: call(repo, :delete_checkpoint, [record_key(repo, id)])

  defp call(repo, function, args) do
    apply(repo.adapter, function, args ++ [repo.opts])
  rescue
    error -> {:error, {:adapter_exception, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:adapter_failure, kind, reason}}
  end
end
