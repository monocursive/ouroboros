defmodule Ouroboros.Audit.Collector do
  @moduledoc """
  Independent, append-only custody service. Start in a separate OS account or host.
  It exposes no agent execution, management, delete, or key-retrieval endpoints.
  Filesystem administrators remain a trust boundary; use immutable storage for that threat.
  """
  use GenServer
  alias Ouroboros.Audit.{Bundle, Record, Store}
  alias Ouroboros.Audit.File, as: Durable
  alias Ouroboros.Provider.Native.Journal

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def accept(payload, token, server \\ __MODULE__),
    do: GenServer.call(server, {:accept, payload, token}, 30_000)

  def inventory(nonce, token, server \\ __MODULE__),
    do: GenServer.call(server, {:inventory, nonce, token}, 30_000)

  def authenticate(token, server \\ __MODULE__),
    do: GenServer.call(server, {:authenticate, token})

  def start_from_env do
    if Process.whereis(Ouroboros.Supervisor),
      do: raise("collector must run independently of the agent runtime")

    path = System.fetch_env!("OUROBOROS_COLLECTOR_CONFIG")
    import Bitwise
    :ok = Durable.no_symlinks(Path.dirname(path))
    {:ok, %{type: :regular, mode: mode, size: size}} = File.lstat(path)

    if band(mode, 0o077) != 0 or size > 1_048_576,
      do: raise("collector policy must be private and bounded")

    data = File.read!(path) |> JSON.decode!()
    {:ok, key} = Base.decode64(data["private_key"])
    if byte_size(key) != 32, do: raise("collector needs a 32-byte Ed25519 signing seed")
    {:ok, _} = Application.ensure_all_started(:bandit)

    opts = [
      root: data["root"],
      organization: data["organization"],
      writer_id: data["writer_id"],
      token_sha256: data["token_sha256"],
      key_id: data["key_id"],
      private_key: key,
      retention_days: data["retention_days"] || 90,
      capacity_bytes: data["capacity_bytes"] || 10_737_418_240
    ]

    Supervisor.start_link(
      [
        {__MODULE__, opts},
        {Bandit,
         plug: Ouroboros.Audit.Collector.Router, ip: {127, 0, 0, 1}, port: data["port"] || 4319}
      ],
      strategy: :one_for_all
    )
  end

  @impl true
  def init(opts) do
    state =
      Map.new(opts)
      |> Map.put_new(:retention_days, 90)
      |> Map.put_new(:capacity_bytes, 10_737_418_240)

    with true <- is_binary(state[:root]) and Path.type(state.root) == :absolute,
         true <- Store.valid_id?(state[:token_sha256]),
         true <-
           is_binary(state[:organization]) and is_binary(state[:writer_id]) and
             is_binary(state[:key_id]),
         true <- is_binary(state[:private_key]) and byte_size(state.private_key) == 32,
         true <- is_integer(state.retention_days) and state.retention_days > 0,
         true <- is_integer(state.capacity_bytes) and state.capacity_bytes > 0,
         :ok <- Durable.directory(state.root),
         :ok <- Durable.directory(Path.join(state.root, "streams")),
         :ok <- Durable.directory(Path.join(state.root, "blobs")),
         :ok <- Durable.directory(Path.join(state.root, "receipts")) do
      {:ok, state |> Map.put(:bytes, disk_bytes(state.root)) |> Map.put(:streams, %{})}
    else
      _ -> {:stop, :collector_configuration_invalid}
    end
  end

  @impl true
  def handle_call({:authenticate, token}, _, state),
    do: {:reply, authenticated?(token, state), state}

  def handle_call({:accept, payload, token}, _, state) do
    if authenticated?(token, state) do
      state = load_stream(state, payload)
      result = ingest(payload, state)

      next =
        case result do
          {:ok, _} -> remember(state, payload)
          _ -> %{state | bytes: disk_bytes(state.root), streams: %{}}
        end

      {:reply, result, next}
    else
      {:reply, {:error, :unauthenticated}, state}
    end
  end

  def handle_call({:inventory, nonce, token}, _, state) do
    result =
      with true <- authenticated?(token, state),
           true <- is_binary(nonce) and byte_size(nonce) in 32..128,
           {:ok, heads} <- heads(state.root) do
        receipt = %{
          "version" => 1,
          "organization" => state.organization,
          "writer_id" => state.writer_id,
          "key_id" => state.key_id,
          "nonce" => nonce,
          "streams" => heads,
          "generated_at" => DateTime.to_iso8601(DateTime.utc_now())
        }

        {:ok, sign(receipt, state)}
      else
        _ -> {:error, :inventory_unavailable}
      end

    {:reply, result, state}
  end

  # Cache only verified heads. Retries of old sequences re-read canonical history;
  # the normal append path does not re-parse every earlier chunk.
  defp load_stream(state, %{"record" => %{"stream_id" => stream}}) do
    if Store.valid_id?(stream) and not Map.has_key?(state.streams, stream) do
      case Store.read(Store.stream_path(state.root, stream)) do
        {:ok, scan} ->
          %{state | streams: Map.put(state.streams, stream, Map.drop(scan, [:records]))}

        _ ->
          state
      end
    else
      state
    end
  end

  defp load_stream(state, _), do: state

  defp remember(state, %{"record" => record, "blobs" => blobs}) do
    stream = record["stream_id"]
    previous = state.streams[stream]

    if previous && record["seq"] > previous.verified_through do
      # Conservatively reserve blob/receipt bytes even when content is deduplicated.
      added =
        byte_size(Journal.canonical_json(record)) + 1 + 4096 +
          Enum.reduce(blobs, 0, fn {_, encoded}, total ->
            total + div(byte_size(encoded) * 3, 4)
          end)

      %{
        state
        | bytes: state.bytes + added,
          streams:
            Map.put(state.streams, stream, %{
              verified_through: record["seq"],
              head: record["hash"]
            })
      }
    else
      state
    end
  end

  defp append_path(directory, sequence) do
    current = List.last(Store.segments(directory))

    if current && File.stat!(current).size < 4_194_304,
      do: current,
      else: Path.join(directory, String.pad_leading(to_string(sequence), 20, "0") <> ".ndjson")
  end

  defp ingest(%{"version" => 1, "record" => record, "blobs" => blobs}, state)
       when is_map(record) and is_map(blobs) do
    stream = record["stream_id"]
    line = Journal.canonical_json(record) <> "\n"

    with true <- Store.valid_id?(stream) and Store.valid_id?(record["hash"]),
         true <-
           record["organization"] == state.organization and record["writer_id"] == state.writer_id,
         true <- byte_size(line) <= 1_048_576,
         true <- record["event_id"] == stream <> ":" <> to_string(record["seq"]),
         {:ok, scanned} <- Map.fetch(state.streams, stream) do
      previous =
        if record["seq"] <= scanned.verified_through do
          {:ok, history} = Store.read(Store.stream_path(state.root, stream))
          Enum.find(history.records, &(&1["seq"] == record["seq"]))
        end

      cond do
        previous == record ->
          # A failed append sync or receipt may have left a complete record visible.
          # Re-establish durability (including blobs) before acknowledging that prefix.
          with {:ok, decoded} <- decode_blobs(blobs, record),
               :ok <- retain_blobs(decoded, state.root),
               :ok <- sync_retained(record, state.root) do
            issue_receipt(record, state)
          end

        previous != nil ->
          {:error, :conflicting_evidence}

        not Record.valid?(record, scanned.verified_through + 1, scanned.head) ->
          {:error, :evidence_out_of_order}

        true ->
          with {:ok, decoded} <- decode_blobs(blobs, record),
               total =
                 byte_size(line) +
                   Enum.reduce(decoded, 0, fn {_, bytes}, n -> n + byte_size(bytes) end) + 4096,
               true <- state.bytes + total <= state.capacity_bytes,
               :ok <- retain_blobs(decoded, state.root),
               directory = Store.stream_path(state.root, stream),
               :ok <- Durable.directory(directory),
               path = append_path(directory, record["seq"]),
               :ok <- Durable.append(path, line),
               {:ok, envelope} <- issue_receipt(record, state) do
            {:ok, envelope}
          else
            _ -> {:error, :custody_commit_failed}
          end
      end
    else
      _ -> {:error, :invalid_evidence}
    end
  rescue
    _ -> {:error, :invalid_evidence}
  end

  defp ingest(_, _), do: {:error, :invalid_evidence}

  defp sync_retained(record, root) do
    directory = Store.stream_path(root, record["stream_id"])

    paths =
      Store.segments(directory) ++
        Enum.map(Bundle.blob_ids(record), &Path.join([root, "blobs", &1]))

    Enum.reduce_while(paths, :ok, fn path, :ok ->
      # Empty append syncs the existing bytes and the parent directory without changing history.
      case Durable.append(path, "") do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp issue_receipt(record, state) do
    path = Path.join([state.root, "receipts", record["hash"] <> ".json"])

    case Durable.read(path) do
      {:ok, bytes} ->
        with :ok <- Durable.append(path, ""), do: JSON.decode(bytes)

      {:error, :enoent} ->
        now = DateTime.utc_now()
        {:ok, recorded, _} = DateTime.from_iso8601(record["at"])
        base = if DateTime.compare(now, recorded) == :lt, do: recorded, else: now

        receipt = %{
          "version" => 1,
          "organization" => state.organization,
          "stream_id" => record["stream_id"],
          "seq" => record["seq"],
          "hash" => record["hash"],
          "key_id" => state.key_id,
          "accepted_at" => DateTime.to_iso8601(now),
          "retain_until" =>
            DateTime.to_iso8601(DateTime.add(base, state.retention_days * 86_400, :second))
        }

        envelope = sign(receipt, state)
        with :ok <- Durable.atomic(path, Journal.canonical_json(envelope)), do: {:ok, envelope}

      _ ->
        {:error, :receipt_unavailable}
    end
  end

  defp decode_blobs(blobs, record) do
    expected = Bundle.blob_ids(record) |> MapSet.new()

    if MapSet.new(Map.keys(blobs)) == expected do
      Enum.reduce_while(blobs, {:ok, %{}}, fn {id, encoded}, {:ok, acc} ->
        with true <- Store.valid_id?(id),
             true <- is_binary(encoded) and byte_size(encoded) <= 89_478_488,
             {:ok, bytes} <- Base.decode64(encoded),
             true <- sha(bytes) == id do
          {:cont, {:ok, Map.put(acc, id, bytes)}}
        else
          _ -> {:halt, {:error, :invalid_blob}}
        end
      end)
    else
      {:error, :blob_inventory_mismatch}
    end
  end

  defp retain_blobs(blobs, root) do
    Enum.reduce_while(blobs, :ok, fn {id, bytes}, :ok ->
      path = Path.join([root, "blobs", id])

      result =
        case Durable.read(path) do
          {:ok, ^bytes} -> :ok
          {:error, :enoent} -> Durable.atomic(path, bytes)
          _ -> {:error, :blob_conflict}
        end

      if result == :ok, do: {:cont, :ok}, else: {:halt, result}
    end)
  end

  defp heads(root) do
    Enum.reduce_while(Store.streams(root), {:ok, []}, fn stream, {:ok, acc} ->
      case Store.read(Store.stream_path(root, stream)) do
        {:ok, scan} ->
          {:cont,
           {:ok,
            [%{"stream_id" => stream, "seq" => scan.verified_through, "hash" => scan.head} | acc]}}

        _ ->
          {:halt, {:error, :custody_corrupt}}
      end
    end)
  end

  defp authenticated?(token, state),
    do: is_binary(token) and :crypto.hash_equals(sha(token), state.token_sha256)

  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp sign(receipt, state),
    do: %{
      "receipt" => receipt,
      "signature" =>
        :crypto.sign(:eddsa, :none, Journal.canonical_json(receipt), [state.private_key, :ed25519])
        |> Base.encode64()
    }

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
end

defmodule Ouroboros.Audit.Collector.Router do
  @moduledoc false
  use Plug.Router
  plug :match
  plug :dispatch

  post "/v1/events" do
    respond(conn, fn token ->
      with {:ok, body, _} <-
             Plug.Conn.read_body(conn,
               length: 100_663_296,
               read_length: 1_048_576,
               read_timeout: 15_000
             ),
           {:ok, payload} <- JSON.decode(body),
           do: Ouroboros.Audit.Collector.accept(payload, token)
    end)
  end

  post "/v1/inventory" do
    respond(conn, fn token ->
      with {:ok, body, _} <- Plug.Conn.read_body(conn, length: 4096),
           {:ok, %{"nonce" => nonce}} <- JSON.decode(body),
           do: Ouroboros.Audit.Collector.inventory(nonce, token)
    end)
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp respond(conn, fun) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         true <- Ouroboros.Audit.Collector.authenticate(token),
         {:ok, payload} <- fun.(token) do
      conn
      |> put_resp_content_type("application/json")
      |> put_resp_header("cache-control", "no-store")
      |> send_resp(200, JSON.encode!(payload))
    else
      _ -> send_resp(conn, 409, "custody request refused")
    end
  rescue
    _ -> send_resp(conn, 409, "custody request refused")
  end
end
