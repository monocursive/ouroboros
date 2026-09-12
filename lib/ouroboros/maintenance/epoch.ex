defmodule Ouroboros.Maintenance.Epoch do
  @moduledoc """
  Durable, node-local write epoch reservations for cooperative maintenance.

  A writer reserves a stable write id and SHA-256 payload digest before publishing its
  payload, then commits that exact reservation. An identical reserve is idempotent;
  reuse of a write id with another digest is refused. `abort/3` exists only for a caller
  that explicitly asserts it has confirmed payload absence. This module does not inspect,
  publish, or reconcile payloads itself.

  Identities are never forgotten. `:max_entries` bounds the resident history; when it
  fills, finalized receipts move into an immutable durable index before space is reused.
  Pending reservations are never removed to make room. An old identity cannot become
  executable again, including when an indexed receipt is missing or unreadable.
  Persistence corruption or unavailability fails startup, and a failed mutation stops
  this owner rather than continuing from an in-memory state whose durable outcome may
  be unknown.
  """

  use GenServer

  alias Ouroboros.Storage.DurableFile
  alias Ouroboros.Maintenance.EpochReceipts

  @storage_key {:ouroboros, :maintenance_write_epoch, 1}
  @default_max_entries 4_096
  @max_id_bytes 128
  @sha256_bytes 64
  @statuses [:pending, :committed, :aborted]

  @type reservation :: %{write_id: String.t(), epoch: pos_integer(), payload_digest: String.t()}

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Durably reserves the next epoch, or returns the existing exact reservation."
  @spec reserve(String.t(), String.t(), GenServer.server()) ::
          {:ok, reservation()} | {:error, term()}
  def reserve(write_id, payload_digest, server \\ __MODULE__),
    do: GenServer.call(server, {:reserve, write_id, payload_digest})

  @doc "Durably commits the exact reservation identity."
  @spec commit(reservation(), GenServer.server()) :: :ok | {:error, term()}
  def commit(reservation, server \\ __MODULE__),
    do: GenServer.call(server, {:settle, reservation, :committed})

  @doc """
  Durably aborts an exact reservation after explicit caller-confirmed payload absence.

  The required third argument is deliberately literal: this owner cannot establish payload
  absence and does not pretend that it can. Any other confirmation value is refused.
  """
  @spec abort(reservation(), :payload_absence_confirmed, GenServer.server()) ::
          :ok | {:error, term()}
  def abort(reservation, confirmation, server \\ __MODULE__),
    do: GenServer.call(server, {:abort, reservation, confirmation})

  @doc "Returns an exact identity, including its status, from resident or archived history."
  @spec lookup(String.t(), GenServer.server()) :: {:ok, map()} | :not_found | {:error, term()}
  def lookup(write_id, server \\ __MODULE__), do: GenServer.call(server, {:lookup, write_id})

  @doc """
  Returns the epoch head, all pending identities, and bounded resident finalized history.

  `lookup/2` is authoritative for an individual write ID; finalized identities may have
  moved out of these lists into the immutable archive. `archived_entries` counts them.
  """
  @spec observe(GenServer.server()) :: map()
  def observe(server \\ __MODULE__), do: GenServer.call(server, :observe)

  @doc false
  def checkpoint_key, do: @storage_key

  @impl true
  def init(opts) do
    with {:ok, storage} <- storage(opts),
         {:ok, max_entries} <- max_entries(opts),
         {:ok, checkpoint} <- load(storage),
         :ok <- validate_checkpoint(checkpoint, max_entries, storage),
         {:ok, checkpoint} <- migrate(checkpoint, storage) do
      {:ok, %{storage: storage, max_entries: max_entries, checkpoint: checkpoint}}
    else
      {:error, reason} -> {:stop, {:maintenance_epoch_unavailable, reason}}
    end
  end

  @impl true
  def handle_call({:reserve, write_id, digest}, _from, state) do
    with :ok <- valid_write_id(write_id),
         :ok <- valid_digest(digest) do
      case lookup_entry(state, write_id) do
        {:ok, {^write_id, epoch, ^digest, status}} ->
          {:reply, {:ok, identity(write_id, epoch, digest, status)}, state}

        {:ok, {^write_id, _epoch, _other_digest, _status}} ->
          {:reply, {:error, :write_id_conflict}, state}

        :not_found ->
          reserve_fresh(state, write_id, digest)

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:lookup, write_id}, _from, state) do
    result =
      with :ok <- valid_write_id(write_id) do
        case lookup_entry(state, write_id) do
          {:ok, entry} -> {:ok, entry_identity(entry)}
          other -> other
        end
      end

    {:reply, result, state}
  end

  def handle_call({:settle, reservation, :committed}, _from, state) do
    settle(state, reservation, :committed)
  end

  def handle_call({:abort, _reservation, confirmation}, _from, state)
      when confirmation != :payload_absence_confirmed do
    {:reply, {:error, :payload_absence_confirmation_required}, state}
  end

  def handle_call({:abort, reservation, :payload_absence_confirmed}, _from, state) do
    settle(state, reservation, :aborted)
  end

  def handle_call(:observe, _from, state) do
    grouped = Enum.group_by(state.checkpoint.entries, &elem(&1, 3), &entry_identity/1)

    observation = %{
      epoch: state.checkpoint.epoch,
      pending: Map.get(grouped, :pending, []),
      committed: Map.get(grouped, :committed, []),
      aborted: Map.get(grouped, :aborted, []),
      retained_entries: length(state.checkpoint.entries),
      archived_entries: state.checkpoint.archived_entries,
      max_entries: state.max_entries
    }

    {:reply, observation, state}
  end

  defp settle(state, reservation, target) do
    with {:ok, write_id, epoch, digest} <- reservation_identity(reservation) do
      case lookup_entry(state, write_id) do
        {:ok, {^write_id, ^epoch, ^digest, :pending}} ->
          entries =
            Enum.map(state.checkpoint.entries, fn
              {^write_id, ^epoch, ^digest, :pending} -> {write_id, epoch, digest, target}
              entry -> entry
            end)

          persist_reply(state, %{state.checkpoint | entries: entries}, :ok)

        {:ok, {^write_id, ^epoch, ^digest, ^target}} ->
          {:reply, :ok, state}

        :not_found ->
          {:reply, {:error, :unknown_reservation}, state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}

        _other ->
          {:reply, {:error, :reservation_identity_mismatch}, state}
      end
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp reserve_fresh(state, write_id, digest) do
    case make_room(state) do
      {:ok, checkpoint} ->
        epoch = checkpoint.epoch + 1
        entry = {write_id, epoch, digest, :pending}
        checkpoint = %{checkpoint | epoch: epoch, entries: checkpoint.entries ++ [entry]}
        persist_reply(state, checkpoint, {:ok, identity(write_id, epoch, digest, :pending)})

      {:error, :epoch_capacity} ->
        {:reply, {:error, :epoch_capacity}, state}

      {:error, reason} ->
        persist_failure(state, reason)
    end
  end

  defp make_room(state) do
    checkpoint = state.checkpoint

    if length(checkpoint.entries) < state.max_entries do
      {:ok, checkpoint}
    else
      case Enum.find(checkpoint.entries, &(elem(&1, 3) != :pending)) do
        nil ->
          {:error, :epoch_capacity}

        entry ->
          with {:ok, root} <-
                 EpochReceipts.put(checkpoint.receipt_root, entry, state.storage) do
            {:ok,
             %{
               checkpoint
               | receipt_root: root,
                 archived_entries: checkpoint.archived_entries + 1,
                 entries: List.delete(checkpoint.entries, entry)
             }}
          end
      end
    end
  end

  defp lookup_entry(state, write_id) do
    case find_entry(state.checkpoint.entries, write_id) do
      nil -> EpochReceipts.lookup(state.checkpoint.receipt_root, write_id, state.storage)
      entry -> {:ok, entry}
    end
  end

  defp persist_reply(state, checkpoint, success_reply) do
    case DurableFile.put_checkpoint(@storage_key, checkpoint, state.storage) do
      :ok ->
        {:reply, success_reply, %{state | checkpoint: checkpoint}}

      {:error, reason} ->
        persist_failure(state, reason)
    end
  end

  defp persist_failure(state, reason),
    do: {:stop, {:maintenance_epoch_persist_failed, reason}, {:error, :epoch_unavailable}, state}

  defp load(storage) do
    case DurableFile.get_checkpoint(@storage_key, storage) do
      :not_found ->
        {:ok, %{schema: 2, epoch: 0, entries: [], receipt_root: nil, archived_entries: 0}}

      {:ok, checkpoint} ->
        {:ok, checkpoint}

      {:error, reason} ->
        {:error, {:checkpoint_unreadable, reason}}
    end
  end

  defp validate_checkpoint(
         %{schema: 1, epoch: epoch, entries: entries} = checkpoint,
         max_entries,
         _storage
       )
       when map_size(checkpoint) == 3 and is_integer(epoch) and epoch >= 0 and is_list(entries) do
    cond do
      length(entries) > max_entries ->
        {:error, :checkpoint_over_capacity}

      valid_entries?(entries, epoch) ->
        :ok

      true ->
        {:error, :malformed_checkpoint}
    end
  end

  defp validate_checkpoint(
         %{
           schema: 2,
           epoch: epoch,
           entries: entries,
           receipt_root: root,
           archived_entries: archived
         } = checkpoint,
         max_entries,
         storage
       )
       when map_size(checkpoint) == 5 and is_integer(epoch) and epoch >= 0 and
              is_list(entries) and is_integer(archived) and archived >= 0 do
    cond do
      length(entries) > max_entries ->
        {:error, :checkpoint_over_capacity}

      not (valid_resident_entries?(entries, epoch) and EpochReceipts.valid_root?(root)) ->
        {:error, :malformed_checkpoint}

      length(entries) + archived > epoch ->
        {:error, :malformed_checkpoint}

      true ->
        with {:ok, metadata} <- EpochReceipts.validate(root, epoch, storage),
             true <- metadata.count == archived,
             true <- max(metadata.max_epoch, last_epoch(entries)) == epoch,
             :ok <- validate_archive_separation(entries, root, storage) do
          :ok
        else
          false -> {:error, :malformed_checkpoint}
          {:error, _reason} = error -> error
        end
    end
  end

  defp validate_checkpoint(_checkpoint, _max_entries, _storage),
    do: {:error, :malformed_checkpoint}

  defp migrate(%{schema: 2} = checkpoint, _storage), do: {:ok, checkpoint}

  defp migrate(%{schema: 1} = checkpoint, storage) do
    migrated = Map.merge(checkpoint, %{schema: 2, receipt_root: nil, archived_entries: 0})

    case DurableFile.put_checkpoint(@storage_key, migrated, storage) do
      :ok -> {:ok, migrated}
      {:error, reason} -> {:error, {:checkpoint_migration_failed, reason}}
    end
  end

  defp validate_archive_separation(entries, root, storage) do
    Enum.reduce_while(entries, :ok, fn {write_id, _, _, _}, :ok ->
      case EpochReceipts.lookup(root, write_id, storage) do
        :not_found -> {:cont, :ok}
        {:ok, _entry} -> {:halt, {:error, :duplicate_archived_identity}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp valid_entries?(entries, epoch) do
    valid_resident_entries?(entries, epoch) and last_epoch(entries) == epoch
  end

  defp valid_resident_entries?(entries, epoch) do
    ids = Enum.map(entries, &entry_write_id/1)
    entry_epochs = Enum.map(entries, &entry_epoch/1)

    Enum.all?(entries, &valid_entry?/1) and Enum.uniq(ids) == ids and
      entry_epochs == Enum.sort(entry_epochs) and Enum.uniq(entry_epochs) == entry_epochs and
      Enum.all?(entry_epochs, &(&1 <= epoch))
  end

  defp last_epoch([]), do: 0
  defp last_epoch(entries), do: entries |> List.last() |> elem(1)

  defp valid_entry?({write_id, epoch, digest, status}) do
    valid_write_id(write_id) == :ok and is_integer(epoch) and epoch > 0 and
      valid_digest(digest) == :ok and status in @statuses
  end

  defp valid_entry?(_), do: false
  defp entry_write_id({write_id, _, _, _}), do: write_id
  defp entry_write_id(_), do: nil
  defp entry_epoch({_, epoch, _, _}), do: epoch
  defp entry_epoch(_), do: nil

  defp find_entry(entries, write_id), do: Enum.find(entries, &(elem(&1, 0) == write_id))

  defp identity(write_id, epoch, digest, _status),
    do: %{write_id: write_id, epoch: epoch, payload_digest: digest}

  defp entry_identity({write_id, epoch, digest, status}),
    do: Map.put(identity(write_id, epoch, digest, status), :status, status)

  defp reservation_identity(reservation)
       when is_map(reservation) and map_size(reservation) == 3 do
    case reservation do
      %{write_id: write_id, epoch: epoch, payload_digest: digest} ->
        with :ok <- valid_write_id(write_id),
             true <- is_integer(epoch) and epoch > 0,
             :ok <- valid_digest(digest) do
          {:ok, write_id, epoch, digest}
        else
          false -> {:error, :invalid_reservation}
          {:error, _reason} -> {:error, :invalid_reservation}
        end

      _ ->
        {:error, :invalid_reservation}
    end
  end

  defp reservation_identity(_), do: {:error, :invalid_reservation}

  defp valid_write_id(value) when is_binary(value) do
    if value != "" and byte_size(value) <= @max_id_bytes and String.valid?(value),
      do: :ok,
      else: {:error, :invalid_write_id}
  end

  defp valid_write_id(_), do: {:error, :invalid_write_id}

  defp valid_digest(value) when is_binary(value) and byte_size(value) == @sha256_bytes do
    if value =~ ~r/\A[0-9a-f]{64}\z/, do: :ok, else: {:error, :invalid_payload_digest}
  end

  defp valid_digest(_), do: {:error, :invalid_payload_digest}

  defp storage(opts) do
    configured =
      Keyword.get_lazy(opts, :storage, fn ->
        case Keyword.get(opts, :data_dir, Application.get_env(:ouroboros, :data_dir)) do
          path when is_binary(path) and path != "" ->
            {DurableFile, path: Path.join(path, "maintenance-epoch")}

          _ ->
            nil
        end
      end)

    case configured do
      {DurableFile, storage_opts} when is_list(storage_opts) ->
        if Keyword.keyword?(storage_opts),
          do: {:ok, storage_opts},
          else: {:error, :invalid_storage}

      _ ->
        {:error, :durable_storage_required}
    end
  end

  defp max_entries(opts) do
    case Keyword.get(opts, :max_entries, @default_max_entries) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, :invalid_max_entries}
    end
  end
end
