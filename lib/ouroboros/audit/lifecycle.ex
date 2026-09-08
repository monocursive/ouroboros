defmodule Ouroboros.Audit.Lifecycle do
  @moduledoc "Retention and holds are canonical governance events, independent of SQLite."
  alias Ouroboros.Audit.{Bundle, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal
  def stream, do: Journal.digest("ouroboros.audit.governance")

  def records(config) do
    with {:ok, scan} <- Store.read(Store.stream_path(config.root, stream())),
         do: {:ok, scan.records}
  end

  def state(config) do
    with {:ok, records} <- records(config) do
      {:ok,
       Enum.reduce(records, %{holds: %{}, purges: %{}}, fn record, acc ->
         target = record["target_stream"]

         case record["kind"] do
           "hold_changed" -> put_in(acc, [:holds, target], record["held"])
           "purge_authorized" -> put_in(acc, [:purges, target], record)
           _ -> acc
         end
       end)}
    end
  end

  def purged?(config, stream) do
    case state(config) do
      {:ok, state} -> Map.has_key?(state.purges, stream)
      _ -> true
    end
  end

  def authorized?(config, id, head, seq) do
    with {:ok, state} <- state(config), record when is_map(record) <- state.purges[id] do
      record["removed_head"] == head and record["removed_through"] == seq and
        witnessed?(record, config)
    else
      _ -> false
    end
  end

  defp witnessed?(_record, %{archive_required: false}), do: true

  defp witnessed?(record, config) do
    with {:ok, bytes} <-
           Durable.read(Path.join([config.root, "receipts", record["hash"] <> ".json"])),
         {:ok, receipt} <- JSON.decode(bytes) do
      Ouroboros.Audit.Archive.verify_receipt(receipt, record, config) == :ok
    else
      _ -> false
    end
  end

  def eligible(config, id, now \\ DateTime.utc_now()) do
    with true <- Store.valid_id?(id) and id != stream(),
         {:ok, governance} <- state(config),
         false <- Map.get(governance.holds, id, false),
         false <- Map.has_key?(governance.purges, id),
         {:ok, scan} <- Store.read(Store.stream_path(config.root, id)),
         last when is_map(last) <- List.last(scan.records),
         true <- last["kind"] == "session_closed",
         {:ok, at, _} <- DateTime.from_iso8601(last["at"]),
         true <- DateTime.diff(now, at, :second) >= config.retention_days * 86_400 do
      {:ok,
       %{
         head: scan.head,
         through: scan.verified_through,
         expired_at:
           DateTime.to_iso8601(DateTime.add(at, config.retention_days * 86_400, :second))
       }}
    else
      _ -> {:error, :stream_held_active_or_not_expired}
    end
  end

  # Only a synced canonical authorization permits deletion. A crash part-way through is
  # finished at the next startup before new execution. No symlink traversal is allowed.
  def recover(config) do
    with {:ok, state} <- state(config) do
      Enum.reduce_while(state.purges, :ok, fn {id, record}, :ok ->
        result =
          if witnessed?(record, config),
            do: remove_stream(config, id),
            else: {:error, :purge_receipt_unavailable}

        case result do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    end
  end

  def remove_stream(config, id) do
    with true <- Store.valid_id?(id),
         :ok <- remove_tree(Store.stream_path(config.root, id)),
         :ok <- remove_exports(config, id),
         :ok <- collect_blobs(config),
         :ok <- Durable.sync_directory(Path.join(config.root, "streams")),
         do: :ok
  end

  defp remove_exports(config, id) do
    root = Path.join(config.root, "exports")

    case File.ls(root) do
      {:error, :enoent} ->
        :ok

      {:ok, names} ->
        Enum.reduce_while(names, :ok, fn name, :ok ->
          with true <- Store.valid_id?(name),
               {:ok, bytes} <- Durable.read(Path.join([root, name, "manifest.json"])),
               {:ok, manifest} <- JSON.decode(bytes) do
            if Enum.any?(manifest["streams"], &(&1["stream_id"] == id)) do
              case remove_tree(Path.join(root, name)) do
                :ok -> {:cont, :ok}
                error -> {:halt, error}
              end
            else
              {:cont, :ok}
            end
          else
            _ -> {:halt, {:error, :export_inventory_unavailable}}
          end
        end)

      error ->
        error
    end
  end

  defp collect_blobs(config) do
    with {:ok, referenced} <-
           Enum.reduce_while(Store.streams(config.root), {:ok, MapSet.new()}, fn id, {:ok, acc} ->
             case Store.read(Store.stream_path(config.root, id)) do
               {:ok, scan} ->
                 {:cont, {:ok, MapSet.union(acc, MapSet.new(Bundle.blob_ids(scan.records)))}}

               error ->
                 {:halt, error}
             end
           end),
         {:ok, names} <- File.ls(Path.join(config.root, "blobs")) do
      Enum.reduce_while(names, :ok, fn name, :ok ->
        if Store.valid_id?(name) and not MapSet.member?(referenced, name) do
          case File.rm(Path.join([config.root, "blobs", name])) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
        else
          {:cont, :ok}
        end
      end)
    end
  end

  def remove_tree(path) do
    case File.lstat(path) do
      {:error, :enoent} ->
        :ok

      {:ok, %{type: :directory}} ->
        with :ok <- Durable.no_symlinks(path),
             {:ok, entries} <- File.ls(path),
             :ok <-
               Enum.reduce_while(entries, :ok, fn entry, :ok ->
                 case remove_tree(Path.join(path, entry)) do
                   :ok -> {:cont, :ok}
                   error -> {:halt, error}
                 end
               end),
             :ok <- File.rmdir(path),
             do: :ok

      {:ok, %{type: :regular}} ->
        File.rm(path)

      _ ->
        {:error, :unsafe_retention_path}
    end
  end
end
