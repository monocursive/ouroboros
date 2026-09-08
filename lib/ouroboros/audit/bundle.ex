defmodule Ouroboros.Audit.Bundle do
  @moduledoc "Portable evidence directories verified without execution or provider credentials."
  alias Ouroboros.Audit.{Config, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  def snapshot(config, selected \\ []) do
    streams = if selected == [], do: Store.streams(config.root), else: selected

    with true <- Enum.all?(streams, &Store.valid_id?/1),
         {:ok, entries} <- collect_streams(config, streams),
         {:ok, blobs} <- collect_blobs(config, entries),
         {:ok, receipts} <- collect_receipts(config, entries) do
      files = entries |> Map.merge(blobs) |> Map.merge(receipts)

      manifest = %{
        "version" => 1,
        "organization" => config.organization,
        "created_at" => DateTime.to_iso8601(DateTime.utc_now()),
        "policy" => Config.public(config) |> Journal.jsonable(),
        "scope" => if(selected == [], do: "node_inventory", else: "selected_streams"),
        "streams" =>
          Enum.map(streams, fn stream ->
            records = files["streams/#{stream}/00000000000000000001.ndjson"] |> decode_records()

            %{
              "stream_id" => stream,
              "through" => length(records),
              "head" =>
                case List.last(records) do
                  nil -> Journal.seed()
                  record -> record["hash"]
                end
            }
          end),
        "files" =>
          files
          |> Enum.map(fn {path, bytes} ->
            %{"path" => path, "bytes" => byte_size(bytes), "sha256" => sha(bytes)}
          end)
          |> Enum.sort_by(& &1["path"]),
        "integrity" => "self_contained_requires_external_trust_anchor"
      }

      {:ok, %{manifest: manifest, files: files}}
    else
      false -> {:error, :invalid_stream_id}
      error -> error
    end
  end

  def write(snapshot, destination) do
    with {:error, :enoent} <- File.lstat(destination),
         :ok <- Durable.directory(destination),
         :ok <- write_files(snapshot.files, destination),
         :ok <-
           Durable.atomic(
             Path.join(destination, "manifest.json"),
             Journal.canonical_json(snapshot.manifest)
           ) do
      {:ok, %{path: destination, manifest_sha256: Journal.digest(snapshot.manifest)}}
    else
      {:ok, _} -> {:error, :destination_exists}
      error -> error
    end
  end

  def verify(directory, expected_digest \\ nil) do
    with {:ok, %{type: :regular, size: size}} <- File.lstat(Path.join(directory, "manifest.json")),
         true <- size <= 16_777_216,
         {:ok, json} <- Durable.read(Path.join(directory, "manifest.json")),
         {:ok, %{"version" => 1, "files" => files, "streams" => streams} = manifest} <-
           JSON.decode(json),
         true <-
           is_list(files) and is_list(streams) and length(files) <= 100_000 and
             length(streams) <= 100_000,
         true <- Journal.canonical_json(manifest) == json,
         true <- is_nil(expected_digest) or sha(json) == expected_digest,
         true <- unique?(files, "path") and unique?(streams, "stream_id"),
         :ok <- verify_inventory(directory, files, streams),
         :ok <- verify_files(directory, files),
         :ok <- verify_streams(directory, streams),
         :ok <- verify_references(directory, streams, files) do
      {:ok,
       %{
         manifest_sha256: Journal.digest(manifest),
         streams: streams,
         files: length(files),
         integrity:
           if(expected_digest,
             do: "matches_supplied_trust_anchor",
             else: "self_consistent_unanchored"
           ),
         scope: manifest["scope"]
       }}
    else
      _ -> {:error, :audit_bundle_verification_failed}
    end
  rescue
    _ -> {:error, :audit_bundle_verification_failed}
  catch
    _, _ -> {:error, :audit_bundle_verification_failed}
  end

  defp collect_streams(config, streams) do
    Enum.reduce_while(streams, {:ok, %{}}, fn stream, {:ok, files} ->
      with {:ok, scanned} <- Store.read(Store.stream_path(config.root, stream)),
           false <- scanned.records == [] do
        bytes = Enum.map_join(scanned.records, &(Journal.canonical_json(&1) <> "\n"))
        {:cont, {:ok, Map.put(files, "streams/#{stream}/00000000000000000001.ndjson", bytes)}}
      else
        _ -> {:halt, {:error, :audit_stream_unavailable}}
      end
    end)
  end

  defp collect_receipts(config, entries) do
    entries
    |> Map.values()
    |> Enum.flat_map(&decode_records/1)
    |> Enum.reduce_while({:ok, %{}}, fn record, {:ok, acc} ->
      relative = "receipts/" <> record["hash"] <> ".json"

      case Durable.read(Path.join(config.root, relative)) do
        {:ok, bytes} -> {:cont, {:ok, Map.put(acc, relative, bytes)}}
        {:error, :enoent} when config.archive_required == false -> {:cont, {:ok, acc}}
        _ -> {:halt, {:error, :archive_receipt_unavailable}}
      end
    end)
  end

  defp collect_blobs(config, entries) do
    entries
    |> Map.values()
    |> Enum.flat_map(&decode_records/1)
    |> Enum.flat_map(&blob_ids/1)
    |> Enum.uniq()
    |> Enum.reduce_while({:ok, %{}}, fn id, {:ok, files} ->
      with true <- Store.valid_id?(id),
           {:ok, bytes} <- Durable.read(Path.join([config.root, "blobs", id])),
           true <- sha(bytes) == id do
        {:cont, {:ok, Map.put(files, "blobs/#{id}", bytes)}}
      else
        _ -> {:halt, {:error, :audit_blob_unavailable}}
      end
    end)
  end

  def blob_ids(%{"store" => "audit-v2", "blob" => id}), do: [id]
  def blob_ids(map) when is_map(map), do: map |> Map.values() |> Enum.flat_map(&blob_ids/1)
  def blob_ids(list) when is_list(list), do: Enum.flat_map(list, &blob_ids/1)
  def blob_ids(_), do: []

  defp write_files(files, directory) do
    Enum.reduce_while(files, :ok, fn {path, bytes}, :ok ->
      target = Path.join(directory, path)

      with true <- safe_path?(path),
           :ok <- Durable.directory(Path.dirname(target)),
           :ok <- Durable.atomic(target, bytes) do
        {:cont, :ok}
      else
        _ -> {:halt, {:error, :audit_export_failed}}
      end
    end)
  end

  defp unique?(entries, key), do: length(Enum.uniq_by(entries, & &1[key])) == length(entries)

  defp verify_inventory(directory, files, streams) do
    listed = MapSet.new(Enum.map(files, & &1["path"]))
    ids = MapSet.new(Enum.map(streams, & &1["stream_id"]))
    actual = inventory(directory, directory) |> MapSet.new() |> MapSet.delete("manifest.json")

    if actual == listed and
         Enum.all?(listed, fn path ->
           if String.starts_with?(path, "streams/"),
             do: MapSet.member?(ids, Enum.at(String.split(path, "/"), 1)),
             else: true
         end), do: :ok, else: {:error, :inventory_mismatch}
  end

  defp inventory(root, directory) do
    :ok = Durable.no_symlinks(directory)

    if directory != root and length(Path.split(Path.relative_to(directory, root))) > 2,
      do: throw(:unexpected_bundle_directory)

    Enum.flat_map(File.ls!(directory), fn name ->
      path = Path.join(directory, name)

      case File.lstat(path) do
        {:ok, %{type: :regular}} -> [Path.relative_to(path, root)]
        {:ok, %{type: :directory}} -> inventory(root, path)
        _ -> throw(:unsafe_bundle_path)
      end
    end)
  end

  defp verify_files(directory, files) do
    Enum.reduce_while(files, :ok, fn entry, :ok ->
      with true <- safe_path?(entry["path"]),
           :ok <- Durable.no_symlinks(Path.dirname(Path.join(directory, entry["path"]))),
           {:ok, bytes} <- Durable.read(Path.join(directory, entry["path"])),
           true <- byte_size(bytes) == entry["bytes"] and sha(bytes) == entry["sha256"] do
        {:cont, :ok}
      else
        _ -> {:halt, {:error, :file_mismatch}}
      end
    end)
  end

  defp verify_streams(directory, streams) do
    Enum.reduce_while(streams, :ok, fn entry, :ok ->
      with true <- Store.valid_id?(entry["stream_id"]),
           {:ok, scanned} <- Store.read(Store.stream_path(directory, entry["stream_id"])),
           true <- scanned.head == entry["head"] and scanned.verified_through == entry["through"] do
        {:cont, :ok}
      else
        _ -> {:halt, {:error, :stream_mismatch}}
      end
    end)
  end

  defp verify_references(directory, streams, files) do
    listed = MapSet.new(Enum.map(files, & &1["path"]))

    Enum.reduce_while(streams, :ok, fn entry, :ok ->
      {:ok, scanned} = Store.read(Store.stream_path(directory, entry["stream_id"]))
      ids = blob_ids(scanned.records)

      if Enum.all?(ids, &MapSet.member?(listed, "blobs/#{&1}")),
        do: {:cont, :ok},
        else: {:halt, {:error, :unlisted_blob}}
    end)
  end

  def safe_path?(path) when is_binary(path),
    do:
      Regex.match?(
        ~r/^(streams\/[a-f0-9]{64}\/[0-9]{20}\.ndjson|blobs\/[a-f0-9]{64}|receipts\/[a-f0-9]{64}\.json)$/,
        path
      )

  def safe_path?(_), do: false

  defp decode_records(bytes),
    do: bytes |> String.split("\n", trim: true) |> Enum.map(&JSON.decode!/1)

  defp sha(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
