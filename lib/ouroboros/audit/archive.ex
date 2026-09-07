defmodule Ouroboros.Audit.Archive do
  @moduledoc "Customer-controlled custody protocol with pinned Ed25519 receipt verification."
  alias Ouroboros.Audit.{Bundle, Config, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  def deliver(_record, %{archive: nil}), do: :ok

  def deliver(record, config) do
    receipt_path = Path.join([config.root, "receipts", record["hash"] <> ".json"])

    case Durable.read(receipt_path) do
      {:ok, bytes} ->
        with {:ok, receipt} <- JSON.decode(bytes),
             :ok <- verify_receipt(receipt, record, config),
             do: :ok

      {:error, :enoent} ->
        upload(record, config, receipt_path)

      _ ->
        {:error, :archive_receipt_unreadable}
    end
  rescue
    _ -> {:error, :archive_unavailable}
  catch
    _, _ -> {:error, :archive_unavailable}
  end

  defp upload(record, config, receipt_path) do
    with {:ok, blobs} <- blobs(record, config),
         {:ok, receipt} <-
           send_record(%{"version" => 1, "record" => record, "blobs" => blobs}, config.archive),
         :ok <- verify_receipt(receipt, record, config),
         :ok <- Durable.atomic(receipt_path, Journal.canonical_json(receipt)) do
      :ok
    end
  end

  defp blobs(record, config) do
    Bundle.blob_ids(record)
    |> Enum.uniq()
    |> Enum.reduce_while({:ok, %{}}, fn id, {:ok, acc} ->
      with true <- Store.valid_id?(id),
           {:ok, bytes} <- Durable.read(Path.join([config.root, "blobs", id])) do
        {:cont, {:ok, Map.put(acc, id, Base.encode64(bytes))}}
      else
        _ -> {:halt, {:error, :archive_blob_unavailable}}
      end
    end)
  end

  defp send_record(payload, %{transport: module} = archive) when is_atom(module),
    do: module.deliver(payload, archive)

  defp send_record(payload, archive) do
    with :ok <- endpoint(archive.url),
         {:ok, %{status: status, body: body}} when status in [200, 201] <-
           Req.post(archive.url <> "/v1/events",
             json: payload,
             auth: {:bearer, archive.token},
             retry: false,
             redirect: false,
             receive_timeout: 15_000,
             connect_options: [timeout: 5_000]
           ) do
      {:ok, body}
    else
      _ -> {:error, :archive_unavailable}
    end
  end

  def endpoint(url) when is_binary(url) do
    case URI.parse(url) do
      %{scheme: "https", host: host, userinfo: nil, query: nil, fragment: nil}
      when is_binary(host) ->
        :ok

      %{scheme: "http", host: host, userinfo: nil, query: nil, fragment: nil}
      when host in ["127.0.0.1", "[::1]"] ->
        :ok

      _ ->
        {:error, :archive_requires_https}
    end
  end

  def endpoint(_), do: {:error, :archive_requires_https}

  def verify_receipt(%{"signature" => signature, "receipt" => receipt}, record, config)
      when is_map(receipt) do
    archive = config.archive

    with true <- receipt["version"] == 1,
         true <- receipt["organization"] == config.organization,
         true <- receipt["stream_id"] == record["stream_id"],
         true <- receipt["seq"] == record["seq"],
         true <- receipt["hash"] == record["hash"],
         key when is_binary(key) <- verification_key(archive, receipt["key_id"]),
         {:ok, accepted, _} <- DateTime.from_iso8601(receipt["accepted_at"]),
         {:ok, retained, _} <- DateTime.from_iso8601(receipt["retain_until"]),
         {:ok, recorded, _} <- DateTime.from_iso8601(record["at"]),
         true <- DateTime.diff(retained, recorded, :second) >= config.retention_days * 86_400,
         true <- DateTime.compare(retained, accepted) == :gt,
         {:ok, bytes} <- Base.decode64(signature),
         true <-
           :crypto.verify(:eddsa, :none, Journal.canonical_json(receipt), bytes, [
             key,
             :ed25519
           ]) do
      :ok
    else
      _ -> {:error, :invalid_archive_receipt}
    end
  end

  def verify_receipt(_, _, _), do: {:error, :invalid_archive_receipt}

  defp verification_key(archive, id) do
    if id == archive.key_id,
      do: archive.public_key,
      else: Map.get(Map.get(archive, :previous_keys, %{}), id)
  end

  def pending(config \\ Config.current()) do
    Enum.reduce_while(Store.streams(config.root), {:ok, []}, fn stream, {:ok, pending} ->
      case Store.read(Store.stream_path(config.root, stream)) do
        {:ok, result} ->
          missing =
            Enum.reject(result.records, fn record ->
              case Durable.read(Path.join([config.root, "receipts", record["hash"] <> ".json"])) do
                {:ok, bytes} ->
                  case JSON.decode(bytes) do
                    {:ok, receipt} -> verify_receipt(receipt, record, config) == :ok
                    _ -> false
                  end

                _ ->
                  false
              end
            end)

          {:cont, {:ok, pending ++ missing}}

        error ->
          {:halt, error}
      end
    end)
  end

  def reconcile(%{archive_required: false}), do: :ok

  def reconcile(config) do
    with {:ok, envelope} <- inventory(config),
         :ok <- verify_local_inventory(envelope["receipt"]["streams"], config),
         {:ok, _} <- flush(config),
         do: :ok
  end

  def inventory(config) do
    nonce = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    result =
      case config.archive do
        %{transport: module} = archive ->
          module.inventory(nonce, archive)

        archive ->
          case Req.post(archive.url <> "/v1/inventory",
                 json: %{nonce: nonce},
                 auth: {:bearer, archive.token},
                 retry: false,
                 redirect: false,
                 receive_timeout: 15_000,
                 connect_options: [timeout: 5_000]
               ) do
            {:ok, %{status: 200, body: body}} -> {:ok, body}
            _ -> {:error, :archive_unavailable}
          end
      end

    with {:ok, %{"receipt" => receipt, "signature" => signature} = envelope} <- result,
         true <- receipt["version"] == 1 and receipt["nonce"] == nonce,
         true <-
           receipt["organization"] == config.organization and
             receipt["writer_id"] == Config.writer_id(config),
         true <- receipt["key_id"] == config.archive.key_id,
         true <- is_list(receipt["streams"]),
         {:ok, bytes} <- Base.decode64(signature),
         true <-
           :crypto.verify(:eddsa, :none, Journal.canonical_json(receipt), bytes, [
             config.archive.public_key,
             :ed25519
           ]),
         id = Journal.digest(envelope),
         :ok <- Durable.directory(Path.join(config.root, "anchors")),
         :ok <-
           Durable.atomic(
             Path.join([config.root, "anchors", id <> ".json"]),
             Journal.canonical_json(envelope)
           ) do
      {:ok, envelope}
    else
      _ -> {:error, :archive_inventory_unverified}
    end
  rescue
    _ -> {:error, :archive_inventory_unavailable}
  end

  def verify_local_inventory(heads, config) do
    Enum.reduce_while(heads, :ok, fn entry, :ok ->
      with true <- Store.valid_id?(entry["stream_id"]),
           {:ok, scan} <- Store.read(Store.stream_path(config.root, entry["stream_id"])),
           record when is_map(record) <- Enum.find(scan.records, &(&1["seq"] == entry["seq"])),
           true <- record["hash"] == entry["hash"] do
        {:cont, :ok}
      else
        _ ->
          if Ouroboros.Audit.Lifecycle.authorized?(
               config,
               entry["stream_id"],
               entry["hash"],
               entry["seq"]
             ), do: {:cont, :ok}, else: {:halt, {:error, :anchored_evidence_missing_or_changed}}
      end
    end)
  end

  def flush(config \\ Config.current())
  def flush(%{archive: nil}), do: {:ok, 0}

  def flush(config) do
    with {:ok, records} <- pending(config) do
      Enum.reduce_while(records, {:ok, 0}, fn record, {:ok, count} ->
        case deliver(record, config) do
          :ok -> {:cont, {:ok, count + 1}}
          error -> {:halt, error}
        end
      end)
    end
  end
end
