defmodule Ouroboros.Audit.Store do
  @moduledoc """
  Single node-local writer for segmented, immutable evidence streams.

  Success acknowledges file and directory sync. A failed append poisons that writer's
  stream until restart/verification: a partial or ambiguously synced write must never
  be followed by a second record at the same sequence. Indexing is not on this path.
  """
  use GenServer
  alias Ouroboros.Audit.{Config, Record}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  @max_field_bytes 65_536
  @max_record_bytes 1_048_576

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  def append(stream, kind, fields, server \\ __MODULE__),
    do: GenServer.call(server, {:append, stream, kind, fields}, 30_000)

  def status(server \\ __MODULE__), do: GenServer.call(server, :status)
  def config(server \\ __MODULE__), do: GenServer.call(server, :config)

  def snapshot(streams \\ [], server \\ __MODULE__),
    do: GenServer.call(server, {:snapshot, streams}, 60_000)

  def export(streams \\ [], server \\ __MODULE__),
    do: GenServer.call(server, {:export, streams}, 60_000)

  def hold(stream, held, reason, actor, server \\ __MODULE__),
    do: GenServer.call(server, {:hold, stream, held, reason, actor}, 30_000)

  def purge(stream, reason, actor, server \\ __MODULE__),
    do: GenServer.call(server, {:purge, stream, reason, actor}, 60_000)

  def stream_id(session_dir), do: Journal.digest([to_string(node()), Path.expand(session_dir)])
  def stream_path(root, stream), do: Path.join([root, "streams", stream])

  @impl true
  def init(opts) do
    config = Config.new!(Keyword.get(opts, :config, Config.current()))
    state = %{config: config, streams: %{}, bytes: 0, hook: opts[:durability_hook], error: nil}

    if Config.enabled?(config) do
      with :ok <- Durable.directory(config.root),
           :ok <- Durable.no_symlinks(config.root),
           :ok <- Durable.directory(Path.join(config.root, "streams")),
           :ok <- Durable.directory(Path.join(config.root, "blobs")),
           :ok <- Durable.directory(Path.join(config.root, "receipts")),
           :ok <- Ouroboros.Audit.Archive.reconcile(config),
           :ok <- Ouroboros.Audit.Lifecycle.recover(config) do
        {:ok, %{state | bytes: disk_bytes(config.root)}}
      else
        error -> {:stop, {:audit_storage_unavailable, error}}
      end
    else
      {:ok, state}
    end
  end

  @impl true
  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  def handle_call({:snapshot, streams}, _from, state),
    do: {:reply, Ouroboros.Audit.Bundle.snapshot(state.config, streams), state}

  def handle_call({:export, streams}, _from, state) do
    alias Ouroboros.Audit.Bundle

    result =
      with {:ok, snapshot} <- Bundle.snapshot(state.config, streams),
           size =
             Enum.reduce(snapshot.files, 0, fn {_, bytes}, sum -> sum + byte_size(bytes) end) +
               byte_size(Journal.canonical_json(snapshot.manifest)),
           :ok <- capacity(state, size),
           :ok <- Durable.directory(Path.join(state.config.root, "exports")),
           id = Journal.digest(snapshot.manifest),
           {:ok, _} <- Bundle.write(snapshot, Path.join([state.config.root, "exports", id])) do
        {:ok, %{bundle_id: id, manifest: snapshot.manifest, manifest_sha256: id}}
      end

    {:reply, result, %{state | bytes: disk_bytes(state.config.root)}}
  end

  def handle_call({:hold, stream, held, reason, actor}, _, state) do
    if valid_id?(stream) and is_boolean(held) and is_binary(reason) and
         byte_size(reason) in 1..1000 and
         not Ouroboros.Audit.Lifecycle.purged?(state.config, stream) do
      case write(state, Ouroboros.Audit.Lifecycle.stream(), "hold_changed", %{
             "target_stream" => stream,
             "held" => held,
             "reason" => reason,
             "actor_id" => actor
           }) do
        {:ok, record, next} -> {:reply, {:ok, %{event_id: record["event_id"], held: held}}, next}
        {:error, reason, next} -> {:reply, {:error, reason}, next}
      end
    else
      {:reply, {:error, :invalid_hold_request}, state}
    end
  end

  def handle_call({:purge, stream, reason, actor}, _, state) do
    with true <- is_binary(reason) and byte_size(reason) in 1..1000,
         {:ok, eligible} <- Ouroboros.Audit.Lifecycle.eligible(state.config, stream) do
      fields = %{
        "target_stream" => stream,
        "reason" => reason,
        "actor_id" => actor,
        "removed_head" => eligible.head,
        "removed_through" => eligible.through,
        "expired_at" => eligible.expired_at
      }

      case write(state, Ouroboros.Audit.Lifecycle.stream(), "purge_authorized", fields) do
        {:ok, record, next} ->
          result =
            case Ouroboros.Audit.Lifecycle.remove_stream(state.config, stream) do
              :ok ->
                {:ok,
                 %{
                   event_id: record["event_id"],
                   scope: "retained_audit_and_server_exports",
                   operational_copies: "managed_by_session_retention",
                   external_copies: "independent_custodian_retention"
                 }}

              _ ->
                {:error, :purge_authorized_cleanup_pending}
            end

          {:reply, result,
           %{
             next
             | streams: Map.delete(next.streams, stream),
               bytes: disk_bytes(next.config.root)
           }}

        {:error, reason, next} ->
          {:reply, {:error, reason}, next}
      end
    else
      error ->
        {:reply, if(error == false, do: {:error, :invalid_purge_request}, else: error), state}
    end
  end

  def handle_call(:status, _from, state) do
    state =
      if Config.enabled?(state.config),
        do: %{state | bytes: disk_bytes(state.config.root)},
        else: state

    {:reply,
     %{
       policy: Config.public(state.config),
       policy_revision: Config.revision(state.config),
       bytes: state.bytes,
       capacity_bytes: state.config.capacity_bytes,
       error: state.error,
       durability:
         if(Config.enabled?(state.config), do: "file_and_directory_sync", else: "disabled"),
       integrity: "local_chain_requires_external_anchor",
       streams:
         if(Config.enabled?(state.config), do: length(streams(state.config.root)), else: 0),
       capacity_scope: "audit_directory_observed_at_last_status_or_commit",
       governance_reserve_bytes: min(div(state.config.capacity_bytes, 100), 65_536)
     }, state}
  end

  def handle_call({:append, stream, kind, fields}, _from, state) do
    cond do
      not Config.enabled?(state.config) ->
        {:reply, {:ok, nil}, state}

      not valid_id?(stream) ->
        {:reply, {:error, :invalid_stream_id}, state}

      Ouroboros.Audit.Lifecycle.purged?(state.config, stream) ->
        {:reply, {:error, :evidence_stream_retired}, state}

      not is_map(fields) ->
        {:reply, {:error, :invalid_record}, state}

      true ->
        case write(state, stream, kind, fields) do
          {:ok, record, next} -> {:reply, {:ok, record}, next}
          {:error, reason, next} -> {:reply, {:error, reason}, %{next | error: classify(reason)}}
        end
    end
  end

  defp write(state, stream, kind, fields) do
    state =
      Map.put(
        state,
        :governance_write,
        stream in [
          Ouroboros.Audit.Lifecycle.stream(),
          Journal.digest("ouroboros.audit.administration")
        ]
      )

    with {:ok, cursor} <- cursor(state, stream),
         false <- cursor.poisoned,
         record = Record.build(fields, kind, stream, cursor.seq + 1, cursor.hash, state.config),
         {:ok, record, blob_bytes} <- spill(record, state),
         line = Journal.canonical_json(record) <> "\n",
         :ok <-
           capacity(
             state,
             byte_size(line) + blob_bytes + if(state.config.archive_required, do: 2048, else: 0)
           ),
         true <- byte_size(line) <= @max_record_bytes,
         {:ok, cursor} <- segment(cursor, state.config, byte_size(line)),
         :ok <- Durable.append(cursor.path, line, state.hook),
         :ok <- required_receipt(record, state.config) do
      next = %{
        cursor
        | seq: record["seq"],
          hash: record["hash"],
          bytes: cursor.bytes + byte_size(line)
      }

      {:ok, record,
       %{
         state
         | streams: Map.put(state.streams, stream, next),
           bytes: state.bytes + byte_size(line) + blob_bytes + receipt_bytes(record, state.config)
       }}
    else
      {:error, reason} -> {:error, reason, poison(state, stream)}
      true -> {:error, :stream_requires_recovery, state}
      false -> {:error, :record_too_large, poison(state, stream)}
    end
  end

  defp required_receipt(record, %{archive_required: true} = config),
    do: Ouroboros.Audit.Archive.deliver(record, config)

  defp required_receipt(_, _), do: :ok

  defp receipt_bytes(record, config) do
    case File.lstat(Path.join([config.root, "receipts", record["hash"] <> ".json"])) do
      {:ok, %{type: :regular, size: size}} -> size
      _ -> 0
    end
  end

  defp cursor(state, stream) do
    case Map.fetch(state.streams, stream) do
      {:ok, cursor} ->
        {:ok, cursor}

      :error ->
        directory = stream_path(state.config.root, stream)

        with :ok <- Durable.directory(directory),
             {:ok, scanned} <- read(directory),
             :ok <- reconcile_stream(scanned.records, state.config) do
          files = segments(directory)
          path = List.last(files)
          bytes = if path, do: File.stat!(path).size, else: 0

          {:ok,
           %{
             directory: directory,
             path: path,
             bytes: bytes,
             seq: scanned.verified_through,
             hash: scanned.head,
             poisoned: false
           }}
        end
    end
  end

  defp reconcile_stream(records, %{archive_required: true} = config) do
    Enum.reduce_while(records, :ok, fn record, :ok ->
      case Ouroboros.Audit.Archive.deliver(record, config) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp reconcile_stream(_, _), do: :ok

  defp segment(%{path: path, bytes: bytes} = cursor, config, size)
       when is_nil(path) or bytes + size > config.segment_bytes do
    filename = String.pad_leading(to_string(cursor.seq + 1), 20, "0") <> ".ndjson"
    path = Path.join(cursor.directory, filename)

    case File.lstat(path) do
      {:error, :enoent} -> {:ok, %{cursor | path: path, bytes: 0}}
      _ -> {:error, :segment_already_exists}
    end
  end

  defp segment(cursor, _, _), do: {:ok, cursor}

  defp poison(state, stream) do
    # Even when the first write failed, do not trust a re-read in this runtime. Restart
    # establishes a new recovery boundary and verifies the committed sequence.
    cursor =
      Map.get(state.streams, stream, %{
        directory: stream_path(state.config.root, stream),
        path: nil,
        bytes: 0,
        seq: 0,
        hash: Journal.seed(),
        poisoned: true
      })

    %{state | streams: Map.put(state.streams, stream, %{cursor | poisoned: true})}
  end

  defp capacity(state, extra) do
    reserve =
      if Map.get(state, :governance_write, false),
        do: 0,
        else: min(div(state.config.capacity_bytes, 100), 65_536)

    if state.bytes + extra <= state.config.capacity_bytes - reserve,
      do: :ok,
      else: {:error, :audit_capacity_exhausted}
  end

  defp spill(record, state) do
    record
    |> Map.drop(["hash", "prev"])
    |> Enum.reduce_while({:ok, %{}, 0}, fn {key, value}, {:ok, body, bytes} ->
      encoded = Journal.canonical_json(value)

      if byte_size(encoded) > @max_field_bytes or
           (state.config.encryption_key_id != nil and Record.content_key?(key)) do
        with :ok <- capacity(state, bytes + byte_size(encoded) + 4096),
             {:ok, marker, added} <- put_blob(state.config, encoded, state.hook) do
          {:cont, {:ok, Map.put(body, key, marker), bytes + added}}
        else
          error -> {:halt, error}
        end
      else
        {:cont, {:ok, Map.put(body, key, value), bytes}}
      end
    end)
    |> case do
      {:ok, body, bytes} -> {:ok, Record.seal(body, record["prev"]), bytes}
      error -> error
    end
  end

  def put_blob(config, contents, hook \\ nil) do
    bytes = encrypt(contents, config)
    digest = :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
    path = Path.join([config.root, "blobs", digest])
    marker = %{"blob" => digest, "store" => "audit-v2", "bytes" => byte_size(contents)}

    case Durable.read(path) do
      {:ok, ^bytes} ->
        {:ok, marker, 0}

      {:error, :enoent} ->
        with :ok <- Durable.atomic(path, bytes, hook), do: {:ok, marker, byte_size(bytes)}

      _ ->
        {:error, :audit_blob_conflict}
    end
  end

  def blob(config, %{"blob" => digest, "store" => "audit-v2"}) do
    with true <- valid_id?(digest),
         {:ok, bytes} <- Durable.read(Path.join([config.root, "blobs", digest])),
         true <- Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) == digest,
         {:ok, clear} <- decrypt(bytes, config),
         {:ok, value} <- JSON.decode(clear),
         do: {:ok, value}
  end

  defp encrypt(bytes, %{encryption_key_id: nil}), do: bytes

  defp encrypt(bytes, config) do
    id = config.encryption_key_id
    nonce = :crypto.strong_rand_bytes(12)

    {cipher, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        Map.fetch!(config.encryption_keys, id),
        nonce,
        bytes,
        id,
        true
      )

    Journal.canonical_json(%{
      "encrypted" => "aes-256-gcm",
      "key_id" => id,
      "nonce" => Base.encode64(nonce),
      "tag" => Base.encode64(tag),
      "ciphertext" => Base.encode64(cipher)
    })
  end

  defp decrypt(bytes, config) do
    case JSON.decode(bytes) do
      {:ok, %{"encrypted" => "aes-256-gcm", "key_id" => id} = envelope} ->
        with {:ok, key} <- Map.fetch(config.encryption_keys, id),
             {:ok, nonce} <- Base.decode64(envelope["nonce"]),
             {:ok, tag} <- Base.decode64(envelope["tag"]),
             {:ok, cipher} <- Base.decode64(envelope["ciphertext"]),
             clear when is_binary(clear) <-
               :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, cipher, id, tag, false),
             do: {:ok, clear}

      _ ->
        {:ok, bytes}
    end
  rescue
    _ -> {:error, :audit_decryption_failed}
  end

  def read(directory) do
    Enum.reduce_while(
      segments(directory),
      {:ok, %{records: [], head: Journal.seed(), verified_through: 0}},
      fn path, {:ok, state} ->
        case read_segment(path, state) do
          {:ok, next} -> {:cont, {:ok, next}}
          error -> {:halt, error}
        end
      end
    )
    |> case do
      {:ok, state} -> {:ok, %{state | records: Enum.reverse(state.records)}}
      error -> error
    end
  end

  defp read_segment(path, state) do
    with true <-
           Path.basename(path) ==
             String.pad_leading(to_string(state.verified_through + 1), 20, "0") <> ".ndjson",
         {:ok, contents} <- Durable.read(path),
         true <- String.ends_with?(contents, "\n") do
      contents
      |> String.split("\n", trim: true)
      |> Enum.reduce_while({:ok, state}, fn line, {:ok, acc} ->
        with true <- byte_size(line) <= @max_record_bytes,
             {:ok, record} <- JSON.decode(line),
             true <- line == Journal.canonical_json(record),
             true <- Record.valid?(record, acc.verified_through + 1, acc.head),
             true <- record["stream_id"] == Path.basename(Path.dirname(path)),
             true <- record["event_id"] == record["stream_id"] <> ":" <> to_string(record["seq"]) do
          {:cont,
           {:ok,
            %{
              records: [record | acc.records],
              head: record["hash"],
              verified_through: record["seq"]
            }}}
        else
          _ -> {:halt, {:error, {:chain_broken, acc.verified_through + 1}}}
        end
      end)
    else
      false -> {:error, {:partial_segment, Path.basename(path)}}
      error -> error
    end
  end

  def streams(root) do
    case File.ls(Path.join(root, "streams")) do
      {:ok, entries} ->
        Enum.filter(entries, &valid_id?/1) |> Enum.sort()

      {:error, :enoent} ->
        []

      {:error, reason} ->
        raise File.Error, reason: reason, action: "list audit streams", path: root
    end
  end

  def segments(directory) do
    case File.ls(directory) do
      {:ok, names} ->
        names
        |> Enum.filter(&Regex.match?(~r/^\d{20}\.ndjson$/, &1))
        |> Enum.sort()
        |> Enum.map(&Path.join(directory, &1))

      {:error, :enoent} ->
        []

      {:error, reason} ->
        raise File.Error, reason: reason, action: "list audit segments", path: directory
    end
  end

  def valid_id?(value), do: is_binary(value) and Regex.match?(~r/^[a-f0-9]{64}$/, value)

  defp disk_bytes(path) do
    case File.lstat(path) do
      {:ok, %{type: :regular, size: size}} ->
        size

      {:ok, %{type: :directory}} ->
        File.ls!(path) |> Enum.reduce(0, &(disk_bytes(Path.join(path, &1)) + &2))

      _ ->
        0
    end
  end

  defp classify(reason) when is_atom(reason), do: to_string(reason)
  defp classify({reason, _}) when is_atom(reason), do: to_string(reason)
  defp classify(_), do: "audit_storage_failure"
end
