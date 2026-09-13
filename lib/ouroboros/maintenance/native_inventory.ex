defmodule Ouroboros.Maintenance.NativeInventory do
  @moduledoc """
  Bounded freeze interface for Native.Session maintenance participants.

  Native owns mutable state. This module deterministically enumerates the public
  registry and enters each participant's generation/token-bound mailbox fence.
  """

  alias Ouroboros.Provider.Native.Session

  @max_sessions 10_000
  @max_id 128

  @spec snapshot(non_neg_integer(), keyword()) :: {:ok, map()} | {:error, term()}
  def snapshot(generation, opts \\ [])

  def snapshot(generation, opts) when is_integer(generation) and generation >= 0 do
    session = session_module(opts)

    try do
      with {:ok, token} <- token(opts),
           {:ok, pids} <- participants(opts),
           :ok <- bound(pids),
           {:ok, rows} <- map_rows(pids, generation, token, session),
           :ok <- unique(rows) do
        rows = Enum.sort_by(rows, &{&1.logical_id, &1.runtime_id})

        {:ok,
         %{
           generation: generation,
           rows: rows,
           root_digest: digest(Enum.map(rows, & &1.root_digest)),
           release: %{
             generation: generation,
             token: token,
             participants: pids,
             session_module: session
           }
         }}
      end
    rescue
      error -> {:error, {:native_inventory_unavailable, Exception.message(error)}}
    catch
      :exit, reason -> {:error, {:native_inventory_unavailable, reason}}
    after
      :ok
    end
  end

  def snapshot(_generation, _opts), do: {:error, :invalid_generation}

  @spec release(map()) :: :ok | {:error, term()}
  def release(%{generation: generation, token: token, participants: participants} = release)
      when is_list(participants) do
    session = Map.get(release, :session_module, Session)

    Enum.reduce(participants, :ok, fn {_logical_id, pid}, result ->
      case session.release_fence(pid, generation, token) do
        :ok -> result
        {:error, :stale_native_fence} -> result
        {:error, reason} -> {:error, {:native_fence_release_failed, reason}}
      end
    end)
  end

  def release(_release), do: {:error, :invalid_native_release}

  @spec release_all(non_neg_integer(), reference()) :: :ok | {:error, term()}
  def release_all(generation, token) do
    case participants() do
      {:ok, participants} ->
        release(%{generation: generation, token: token, participants: participants})

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec revalidate(map(), [map()]) :: :ok | {:error, term()}
  def revalidate(
        %{generation: generation, token: token, participants: participants} = release,
        rows
      )
      when is_list(participants) and is_list(rows) do
    session = Map.get(release, :session_module, Session)
    roots = Map.new(rows, &{&1.logical_id, &1.root_digest})

    Enum.reduce_while(participants, :ok, fn {logical_id, pid}, :ok ->
      with true <- Process.alive?(pid) || {:error, {:native_participant_died, logical_id}},
           {:ok, row} <- session.revalidate_fence(pid, generation, token, roots[logical_id]),
           true <- row.logical_id == logical_id || {:error, :native_identity_mismatch} do
        {:cont, :ok}
      else
        {:error, reason} -> {:halt, {:error, reason}}
        _ -> {:halt, {:error, :invalid_native_revalidation}}
      end
    end)
  catch
    :exit, reason -> {:error, {:native_participant_died, reason}}
  end

  def revalidate(_release, _rows), do: {:error, :invalid_native_release}

  defp participants(opts \\ []) do
    case Keyword.fetch(opts, :participants) do
      {:ok, entries} when is_list(entries) -> {:ok, entries}
      {:ok, _other} -> {:error, :invalid_native_participants}
      :error -> registered_participants()
    end
  end

  defp registered_participants do
    try do
      entries =
        Registry.select(Ouroboros.SessionRegistry, [
          {{{:logical, :"$1"}, :"$2", :_}, [], [{{:"$1", :"$2"}}]}
        ])

      if Enum.all?(entries, fn {id, pid} -> valid_id?(id) and is_pid(pid) end),
        do: {:ok, entries},
        else: {:error, :invalid_native_participant}
    rescue
      ArgumentError -> {:error, :native_registry_unavailable}
    end
  end

  defp map_rows(entries, generation, token, session) do
    Enum.reduce_while(entries, {:ok, []}, fn {logical_id, pid}, {:ok, acc} ->
      case participant(logical_id, pid, generation, token, session) do
        {:ok, row} ->
          {:cont, {:ok, [row | acc]}}

        {:error, reason} ->
          prepared_ids = MapSet.new(acc, & &1.logical_id)
          prepared = Enum.filter(entries, fn {id, _pid} -> MapSet.member?(prepared_ids, id) end)

          _ =
            release(%{
              generation: generation,
              token: token,
              participants: prepared,
              session_module: session
            })

          {:halt, {:error, reason}}
      end
    end)
  end

  defp participant(logical_id, pid, generation, token, session) do
    with {:ok, row} <- session.prepare_fence(pid, generation, token),
         true <- row.logical_id == logical_id || {:error, :native_identity_mismatch},
         true <-
           (valid_id?(row.runtime_id) and valid_id?(row.provider_session_id)) ||
             {:error, :invalid_native_identity},
         true <-
           row.fence_generation == generation || {:error, :native_generation_mismatch} do
      {:ok, row}
    else
      false -> {:error, :invalid_native_participant}
      {:error, _} = error -> error
      other -> {:error, {:invalid_native_evidence, other}}
    end
  end

  defp token(opts) do
    case Keyword.fetch(opts, :maintenance_token) do
      {:ok, token} when is_reference(token) -> {:ok, token}
      _ -> {:error, :native_fence_token_required}
    end
  end

  defp session_module(opts), do: Keyword.get(opts, :native_session_module, Session)

  defp bound(entries),
    do: if(length(entries) <= @max_sessions, do: :ok, else: {:error, :native_inventory_capacity})

  defp unique(rows) do
    keys = Enum.map(rows, &{&1.logical_id, &1.runtime_id, &1.provider_session_id})
    if Enum.uniq(keys) == keys, do: :ok, else: {:error, :duplicate_native_participant}
  end

  defp valid_id?(value),
    do: is_binary(value) and value != "" and byte_size(value) <= @max_id and String.valid?(value)

  defp digest(value),
    do:
      value
      |> :erlang.term_to_binary([:deterministic])
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
end
