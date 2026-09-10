defmodule Ouroboros.Audit.API do
  @moduledoc "Bounded investigation operations shared by the gateway, web and CLI."
  alias Ouroboros.Audit.{Archive, Bundle, Config, Index, Query, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  def call("status", _params) do
    {:ok,
     %{
       storage: Store.status(),
       index: Index.status(),
       exports: Ouroboros.Audit.Worker.status(),
       coverage: %{native: Ouroboros.Audit.coverage()}
     }}
  end

  def call(operation, params) do
    if Config.enabled?(),
      do: dispatch(operation, params, Config.current()),
      else: {:error, :audit_disabled}
  rescue
    _ -> {:error, :audit_operation_failed}
  catch
    _, _ -> {:error, :audit_operation_failed}
  end

  defp dispatch("search", params, config) do
    if config.index do
      case Index.search(params) do
        {:ok, _} = result -> result
        _ -> Query.search(params, config)
      end
    else
      Query.search(params, config)
    end
  end

  defp dispatch("show", %{"stream_id" => stream} = params, config) do
    with {:ok, detail} <- Query.show(stream, config) do
      since = params["since_seq"] || 0
      limit = params["limit"] || 100

      if is_integer(since) and since >= 0 and is_integer(limit) and limit in 1..500 do
        rows =
          detail.records
          |> Enum.filter(&(&1["seq"] > since))
          |> Enum.take(limit)
          |> bounded_records()

        calls =
          detail.calls
          |> Enum.filter(fn call -> call.start["seq"] > since end)
          |> Enum.take(limit)
          |> Enum.map(&Map.drop(&1, [:events, :start]))

        {:ok,
         Map.merge(detail, %{
           records: rows,
           calls: calls,
           next_seq:
             case List.last(rows) do
               nil -> nil
               row -> row["seq"]
             end
         })}
      else
        {:error, :invalid_audit_query}
      end
    end
  end

  defp dispatch("artifact", %{"stream_id" => stream, "blob" => blob}, config) do
    with true <- Store.valid_id?(stream) and Store.valid_id?(blob),
         {:ok, scanned} <- Store.read(Store.stream_path(config.root, stream)),
         true <- blob in Bundle.blob_ids(scanned.records),
         {:ok, value} <- Store.blob(config, %{"blob" => blob, "store" => "audit-v2"}) do
      encoded = Journal.canonical_json(value)

      if byte_size(encoded) <= 262_144,
        do: {:ok, %{value: value}},
        else: {:error, :artifact_requires_export}
    else
      _ -> {:error, :audit_artifact_unavailable}
    end
  end

  defp dispatch("export", params, _config), do: Store.export(List.wrap(params["stream_id"]))

  defp dispatch("download", %{"bundle_id" => id, "path" => path} = params, config) do
    offset = params["offset"] || 0

    with true <- Store.valid_id?(id),
         true <- is_integer(offset) and offset >= 0,
         {:ok, manifest_bytes} <-
           Durable.read(Path.join([config.root, "exports", id, "manifest.json"])),
         {:ok, manifest} <- JSON.decode(manifest_bytes),
         true <- path == "manifest.json" or Enum.any?(manifest["files"], &(&1["path"] == path)),
         true <- path == "manifest.json" or Bundle.safe_path?(path),
         target = Path.join([config.root, "exports", id, path]),
         :ok <- Durable.no_symlinks(Path.dirname(target)),
         {:ok, %{type: :regular, size: size}} <- File.lstat(target),
         true <- offset <= size,
         {:ok, fd} <- :file.open(String.to_charlist(target), [:read, :binary, :raw]) do
      try do
        case :file.pread(fd, offset, 65_536) do
          {:ok, bytes} ->
            {:ok,
             %{
               data: Base.encode64(bytes),
               offset: offset,
               next_offset: offset + byte_size(bytes),
               size: size,
               done: offset + byte_size(bytes) >= size
             }}

          :eof ->
            {:ok, %{data: "", offset: offset, next_offset: offset, size: size, done: true}}

          _ ->
            {:error, :audit_download_failed}
        end
      after
        :file.close(fd)
      end
    else
      _ -> {:error, :audit_download_refused}
    end
  end

  defp dispatch("hold", %{"stream_id" => stream, "held" => held, "reason" => reason}, _),
    do: Store.hold(stream, held, reason, Ouroboros.Audit.Identity.actor())

  defp dispatch("purge", %{"stream_id" => stream, "reason" => reason}, _),
    do: Store.purge(stream, reason, Ouroboros.Audit.Identity.actor())

  defp dispatch("retention", _, config), do: Ouroboros.Audit.Lifecycle.state(config)

  defp dispatch("reindex", _, _), do: Index.reindex()
  defp dispatch("flush", _, config), do: Archive.flush(config)

  defp dispatch("doctor", _, config) do
    with {:ok, rows} <- Query.events(config.root) do
      {:ok,
       %{
         streams: length(Store.streams(config.root)),
         events: length(rows),
         storage: Store.status(),
         index: Index.status(),
         archive_configured: config.archive != nil,
         operational_privacy: Config.public(config).operational_content,
         operational_inventory:
           Ouroboros.Audit.Content.inventory(Application.get_env(:ouroboros, :data_dir), config)
       }}
    end
  end

  defp dispatch(_, _, _), do: {:error, :invalid_audit_operation}

  defp bounded_records(records) do
    Enum.reduce_while(records, {[], 0}, fn record, {rows, used} ->
      size = byte_size(Journal.canonical_json(record))

      cond do
        size > 262_144 and rows == [] ->
          marker =
            Map.take(record, ~w(event_id stream_id seq kind at hash prev))
            |> Map.put("content_unavailable", "record_requires_export")

          {:halt, {[marker], 0}}

        used + size > 262_144 ->
          {:halt, {rows, used}}

        true ->
          {:cont, {[record | rows], used + size}}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end
end
