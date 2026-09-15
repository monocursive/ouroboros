defmodule Ouroboros.Attachments do
  @moduledoc "Private, owner-local image uploads and immutable session attachment manifests."
  use GenServer
  alias Ouroboros.Audit.Content
  alias Ouroboros.Attachments.Normalizer

  @max_image 20 * 1024 * 1024
  @max_total 64 * 1024 * 1024
  @chunk 256 * 1024
  @max_chunks 4096
  @draft_ttl 86_400
  @upload_ttl 600
  @upload_lifetime 3600
  @quotas %{
    runtime_bytes: 10 * 1024 * 1024 * 1024,
    session_bytes: 2 * 1024 * 1024 * 1024,
    client_bytes: 256 * 1024 * 1024,
    staging_bytes: 1024 * 1024 * 1024
  }

  defp quotas do
    overrides = Application.get_env(:ouroboros, :attachment_quotas, []) |> Map.new()

    Map.merge(@quotas, Map.take(overrides, Map.keys(@quotas)), fn _key, default, value ->
      if is_integer(value) and value > 0, do: value, else: default
    end)
  end

  @public ~w(id media_type byte_size source_size width height sha256 display_name source state expires_at)
  @manifest ~w(id media_type byte_size source_size width height sha256 display_name source)

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  def limits,
    do: %{
      quotas: quotas(),
      max_image_bytes: @max_image,
      max_total_bytes: @max_total,
      max_entries: 32,
      max_upload_chunks: @max_chunks,
      chunk_bytes: @chunk,
      max_dimension: 16_384,
      max_pixels: 40_000_000,
      draft_ttl_seconds: @draft_ttl,
      client_draft_persistence:
        if(Ouroboros.Audit.Config.current().encryption_key_id, do: "ephemeral", else: "private")
    }

  def inherit(source, target, server \\ __MODULE__),
    do: GenServer.call(server, {:inherit, source, target})

  def available?, do: Process.whereis(__MODULE__) != nil and Normalizer.available?()

  # Stable across credential rotation, but scoped to this store and the authenticated
  # principal. This is a cache namespace, never an authorization credential.
  def recovery_namespace(actor, server \\ __MODULE__) do
    GenServer.call(server, {:recovery_namespace, actor})
  end

  def operation(operation, params, actor, server \\ __MODULE__),
    do: GenServer.call(server, {:operation, operation, params, actor}, 10_000)

  # Only the session coordinator uses this boundary. Public uploads never supply a
  # storage path or a trusted manifest. Reservations precede the durable turn intent.
  def reserve(session, turn, refs, legacy_count \\ 0, server \\ __MODULE__),
    do: GenServer.call(server, {:reserve, session, turn, refs, legacy_count})

  def content(session, refs, server \\ __MODULE__),
    do: GenServer.call(server, {:content, session, refs}, 10_000)

  def release_reservation(session, turn, refs, server \\ __MODULE__),
    do: GenServer.call(server, {:release, session, turn, refs})

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    data_dir =
      Keyword.get(opts, :data_dir) || Application.get_env(:ouroboros, :data_dir) ||
        Path.join(
          System.tmp_dir!(),
          "ouroboros-images-#{System.pid()}-#{System.unique_integer([:positive])}"
        )

    root = Path.join(data_dir, "attachments")

    with :ok <- private_directory(root),
         {:ok, recovery_id} <- recovery_identity(root),
         {:ok, names} <- File.ls(root) do
      records =
        Enum.reduce(names, %{}, fn name, acc ->
          if valid_id?(name) do
            case read_record(root, name) do
              {:ok, record} ->
                Map.put(acc, name, record)

              {:error, :enoent} ->
                # A crash before the first atomic manifest rename can leave only
                # temporary files. Never silently skip an unreadable durable manifest.
                path = Path.join(root, name)
                leftovers = File.ls!(path)

                if Enum.all?(leftovers, &String.starts_with?(&1, "manifest.tmp-")) do
                  File.rm_rf!(path)
                  acc
                else
                  raise "attachment manifest missing for #{name}"
                end

              _ ->
                raise "attachment manifest unreadable for #{name}"
            end
          else
            acc
          end
        end)

      # Decoder work is ephemeral and cannot survive its process. Staged encrypted
      # chunks can, so recovery allows the same upload to finish again.
      records =
        Map.new(records, fn {id, record} ->
          record =
            if record["state"] == "preparing",
              do: Map.put(record, "state", "uploading"),
              else: record

          {:ok, leftovers} = File.ls(Path.join(root, id))

          Enum.each(leftovers, fn name ->
            if String.starts_with?(name, "decode-"), do: File.rm_rf(Path.join([root, id, name]))
          end)

          {id, record}
        end)

      Process.send_after(self(), :sweep, 60_000)

      {:ok,
       %{
         root: root,
         recovery_id: recovery_id,
         quotas: quotas(),
         records: records,
         workers: %{},
         normalizer: Keyword.get(opts, :normalizer, Normalizer),
         clock: Keyword.get(opts, :clock, fn -> System.system_time(:second) end)
       }}
    else
      error -> {:stop, error}
    end
  end

  @impl true
  def handle_call({:recovery_namespace, actor}, _from, state) do
    {:reply, hash(state.recovery_id <> <<0>> <> actor), state}
  end

  def handle_call({:operation, op, params, actor}, _from, state) do
    state = sweep(state)
    {reply, state} = operate(op, params, actor, state)
    {:reply, reply, state}
  end

  def handle_call({:reserve, session, turn, refs, legacy}, _from, state) do
    with {:ok, records} <- resolve(state, session, refs),
         true <- length(records) + legacy <= 32 || {:error, :attachment_count_exceeded},
         true <-
           Enum.sum(Enum.map(records, & &1["byte_size"])) <= @max_total ||
             {:error, :attachment_too_large},
         true <-
           Enum.sum(Enum.map(records, & &1["source_size"])) <= @max_total ||
             {:error, :attachment_too_large} do
      {reply, next} =
        if is_nil(turn),
          do: {:ok, state},
          else:
            update_many(state, records, fn record ->
              Map.update!(record, "pins", &Enum.uniq([turn | &1]))
            end)

      {:reply,
       case reply do
         :ok -> {:ok, Enum.map(records, &Map.take(&1, @manifest))}
         error -> error
       end, next}
    else
      error -> {:reply, error, state}
    end
  end

  def handle_call({:inherit, source, target}, _from, state) do
    records =
      state.records |> Map.values() |> Enum.filter(&(bound?(&1, source) and &1["pins"] != []))

    {result, next} =
      update_many(state, records, fn record ->
        Map.put(
          record,
          "session_ids",
          Enum.uniq([target | Map.get(record, "session_ids", [record["session_id"]])])
        )
      end)

    {:reply, result, next}
  end

  def handle_call({:content, session, refs}, _from, state) do
    result =
      with {:ok, records} <- resolve(state, session, refs) do
        Enum.reduce_while(records, {:ok, []}, fn record, {:ok, acc} ->
          path = Path.join([state.root, record["id"], "content"])

          with {:ok, bytes} <- Content.read(path), true <- hash(bytes) == record["sha256"] do
            {:cont,
             {:ok,
              acc ++
                [
                  %{
                    type: :image,
                    path: path,
                    media_type: record["media_type"],
                    sha256: record["sha256"],
                    size: byte_size(bytes),
                    id: record["id"]
                  }
                ]}}
          else
            _ -> {:halt, {:error, :attachment_integrity_failed}}
          end
        end)
      end

    {:reply, result, state}
  end

  def handle_call({:release, session, turn, refs}, _from, state) do
    case resolve(state, session, refs) do
      {:ok, records} ->
        {reply, next} =
          update_many(
            state,
            records,
            &Map.update!(&1, "pins", fn pins -> List.delete(pins, turn) end)
          )

        {:reply, reply, next}

      error ->
        {:reply, error, state}
    end
  end

  defp operate("begin", p, actor, state) do
    identity = Enum.map(~w(client_id draft_id client_attachment_id attempt_id), &p[&1])

    existing =
      Enum.find_value(state.records, fn {_id, r} ->
        if r["actor"] == actor and r["identity"] == identity, do: r
      end)

    cond do
      state.normalizer == Normalizer and not Normalizer.available?() ->
        {{:error, :image_decoder_unavailable}, state}

      not Enum.all?(identity, &valid_label?/1) ->
        {{:error, :attachment_invalid}, state}

      not is_integer(p["byte_size"]) or p["byte_size"] <= 0 or p["byte_size"] > @max_image ->
        {{:error, :attachment_too_large}, state}

      not valid_label?(p["session_id"] || p["draft_id"]) ->
        {{:error, :attachment_invalid}, state}

      existing ->
        if existing["source_size"] == p["byte_size"] and existing["session_id"] == p["session_id"],
          do: {{:ok, status(existing)}, state},
          else: {{:error, :attachment_upload_conflict}, state}

      active_count(state, actor) >= 2 or active_count(state, nil) >= 8 ->
        {{:error, :attachment_busy}, state}

      not quota?(state, actor, p["byte_size"], p["session_id"]) ->
        {{:error, :attachment_quota}, state}

      true ->
        id = "att_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)
        now = state.clock.()

        record = %{
          "id" => id,
          "actor" => actor,
          "identity" => identity,
          "session_id" => p["session_id"],
          "draft_id" => p["draft_id"],
          "display_name" => name(p["display_name"]),
          "source" => source(p["source"]),
          "source_size" => p["byte_size"],
          "source_sha256" => nil,
          "state" => "uploading",
          "offset" => 0,
          "chunks" => [],
          "pins" => [],
          "created_at" => now,
          "updated_at" => now,
          "expires_at" => now + @upload_ttl
        }

        with :ok <- private_directory(Path.join(state.root, id)),
             {:ok, state} <- put(state, record) do
          {{:ok, status(record)}, state}
        else
          _ -> {{:error, :attachment_storage_failed}, state}
        end
    end
  end

  defp operate("append", p, actor, state) do
    with {:ok, record} <- owned(state, p["upload_id"], actor),
         true <- record["state"] == "uploading" || {:error, :attachment_not_uploading},
         offset when is_integer(offset) and offset >= 0 <- p["offset"],
         encoded when is_binary(encoded) and byte_size(encoded) <= div(@chunk + 2, 3) * 4 <-
           p["data"],
         {:ok, bytes} when byte_size(bytes) > 0 and byte_size(bytes) <= @chunk <-
           Base.decode64(encoded),
         true <-
           offset + byte_size(bytes) <= record["source_size"] || {:error, :attachment_too_large} do
      previous = Enum.find(record["chunks"], &(&1["offset"] == offset))

      cond do
        previous && previous["sha256"] == hash(bytes) && previous["size"] == byte_size(bytes) ->
          {{:ok, status(record)}, state}

        offset != record["offset"] ->
          {{:error, :attachment_upload_conflict}, state}

        length(record["chunks"]) >= @max_chunks ->
          {{:error, :attachment_upload_fragment_limit}, state}

        true ->
          path = chunk_path(state.root, record["id"], offset)

          with :ok <- atomic(path, Content.encode(bytes)),
               record = %{
                 record
                 | "offset" => offset + byte_size(bytes),
                   "updated_at" => state.clock.(),
                   "expires_at" => state.clock.() + @upload_ttl,
                   "chunks" =>
                     record["chunks"] ++
                       [
                         %{
                           "offset" => offset,
                           "size" => byte_size(bytes),
                           "sha256" => hash(bytes)
                         }
                       ]
               },
               {:ok, next} <- put(state, record) do
            {{:ok, status(record)}, next}
          else
            _ -> {{:error, :attachment_storage_failed}, state}
          end
      end
    else
      {:error, reason} -> {{:error, reason}, state}
      _ -> {{:error, :attachment_invalid}, state}
    end
  end

  defp operate("finish", p, actor, state) do
    with {:ok, record} <- owned(state, p["upload_id"], actor),
         true <- valid_hash?(p["sha256"]) || {:error, :attachment_invalid},
         true <- record["offset"] == record["source_size"] || {:error, :attachment_incomplete},
         true <-
           (is_nil(record["source_sha256"]) or record["source_sha256"] == p["sha256"]) ||
             {:error, :attachment_upload_conflict} do
      cond do
        record["state"] in ["ready", "preparing", "failed"] ->
          {{:ok, status(record)}, state}

        map_size(state.workers) >= 2 ->
          {{:error, :attachment_busy}, state}

        true ->
          record = %{record | "state" => "preparing", "source_sha256" => p["sha256"]}

          case put(state, record) do
            {:ok, next} ->
              paths =
                Enum.map(record["chunks"], &chunk_path(state.root, record["id"], &1["offset"]))

              root = Path.join(state.root, record["id"])
              normalizer = state.normalizer

              task =
                Task.async(fn ->
                  with {:ok, digest} <- digest_chunks(paths),
                       true <- digest == record["source_sha256"] do
                    normalizer.normalize(paths, root)
                  else
                    _ -> {:error, :attachment_integrity_failed}
                  end
                end)

              {{:ok, status(record)},
               %{next | workers: Map.put(next.workers, task.ref, {task.pid, record["id"]})}}

            _ ->
              {{:error, :attachment_storage_failed}, state}
          end
      end
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate("status", p, actor, state) do
    reply =
      with {:ok, r} <-
             authorized(state, p["upload_id"] || p["attachment_id"], actor, p["session_id"]),
           do: {:ok, status(r)}

    {reply, state}
  end

  defp operate("read", p, actor, state) do
    reply =
      with {:ok, r} <- authorized(state, p["attachment_id"], actor, p["session_id"]),
           true <- r["state"] == "ready" || {:error, :attachment_not_ready},
           variant when variant in ["content", "thumbnail"] <- p["variant"],
           offset when is_integer(offset) and offset >= 0 <- Map.get(p, "offset", 0),
           count when is_integer(count) and count > 0 and count <= @chunk <-
             Map.get(p, "length", @chunk),
           expected = if(variant == "content", do: r["sha256"], else: r["thumbnail_sha256"]),
           {:ok, bytes} <- verified_read(state.root, r["id"], variant, expected),
           true <- offset <= byte_size(bytes) || {:error, :attachment_invalid} do
        chunk = binary_part(bytes, offset, min(count, byte_size(bytes) - offset))

        {:ok,
         %{
           data: Base.encode64(chunk),
           offset: offset,
           next_offset: offset + byte_size(chunk),
           total: byte_size(bytes),
           sha256: expected,
           variant: variant,
           media_type: "image/png",
           eof: offset + byte_size(chunk) == byte_size(bytes)
         }}
      else
        {:error, reason} -> {:error, reason}
        _ -> {:error, :attachment_invalid}
      end

    {reply, state}
  end

  defp operate("discard", p, actor, state) do
    case owned(state, p["upload_id"] || p["attachment_id"], actor) do
      {:ok, r} ->
        if r["pins"] == [] do
          next = remove(state, r["id"])

          if Map.has_key?(next.records, r["id"]),
            do: {{:error, :attachment_storage_failed}, next},
            else: {{:ok, %{discarded: true}}, next}
        else
          {{:ok, %{discarded: true, retained: true}}, state}
        end

      _ ->
        {{:ok, %{discarded: true}}, state}
    end
  end

  defp operate("bind_draft", p, actor, state) do
    records =
      Enum.flat_map(state.records, fn {_id, r} ->
        if r["actor"] == actor and r["draft_id"] == p["draft_id"], do: [r], else: []
      end)

    if valid_label?(p["session_id"]) and session_quota?(state, records, p["session_id"]) and
         Enum.all?(records, &(&1["session_id"] in [nil, p["session_id"]])) do
      {result, next} = update_many(state, records, &Map.put(&1, "session_id", p["session_id"]))

      {case result do
         :ok -> {:ok, %{bound: true}}
         error -> error
       end, next}
    else
      {{:error, :attachment_not_authorized}, state}
    end
  end

  defp operate("touch_draft", p, actor, state) do
    records =
      Enum.flat_map(state.records, fn {_id, r} ->
        if r["actor"] == actor and r["draft_id"] == p["draft_id"] and r["state"] == "ready",
          do: [r],
          else: []
      end)

    {result, next} =
      update_many(
        state,
        records,
        &Map.merge(&1, %{
          "updated_at" => state.clock.(),
          "expires_at" => state.clock.() + @draft_ttl
        })
      )

    {case result do
       :ok -> {:ok, %{renewed: true}}
       error -> error
     end, next}
  end

  defp operate(_, _, _, state), do: {{:error, :attachment_invalid}, state}

  @impl true
  def handle_info({ref, result}, state) when is_reference(ref) do
    case Map.pop(state.workers, ref) do
      {nil, _} ->
        {:noreply, state}

      {{_pid, id}, workers} ->
        Process.demonitor(ref, [:flush])
        next = %{state | workers: workers}

        case next.records[id] do
          nil -> {:noreply, next}
          record -> {:noreply, complete(next, record, result)}
        end
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.workers, ref) do
      {nil, _} ->
        {:noreply, state}

      {{_, id}, workers} ->
        next = %{state | workers: workers}

        {:noreply,
         if(next.records[id],
           do: complete(next, next.records[id], {:error, :attachment_prepare_failed}),
           else: next
         )}
    end
  end

  def handle_info(:sweep, state) do
    Process.send_after(self(), :sweep, 60_000)
    {:noreply, state |> reconcile_pins() |> sweep()}
  end

  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    Enum.each(state.workers, fn {_ref, {pid, _id}} -> Process.exit(pid, :kill) end)
    :ok
  end

  defp complete(state, record, {:ok, result}) do
    root = Path.join(state.root, record["id"])

    with :ok <- atomic(Path.join(root, "content"), Content.encode(result.content)),
         :ok <- atomic(Path.join(root, "thumbnail"), Content.encode(result.thumbnail)),
         ready =
           Map.merge(record, %{
             "state" => "ready",
             "media_type" => "image/png",
             "width" => result.width,
             "height" => result.height,
             "byte_size" => byte_size(result.content),
             "sha256" => hash(result.content),
             "thumbnail_sha256" => hash(result.thumbnail),
             "expires_at" => state.clock.() + @draft_ttl
           }),
         {:ok, next} <- put(state, ready) do
      Enum.each(record["chunks"], &File.rm(chunk_path(state.root, record["id"], &1["offset"])))
      next
    else
      _ -> complete(state, record, {:error, :attachment_storage_failed})
    end
  end

  defp complete(state, record, {:error, reason}) do
    case put(state, Map.merge(record, %{"state" => "failed", "error" => safe_error(reason)})) do
      {:ok, next} -> next
      _ -> state
    end
  end

  defp resolve(state, session, refs) when is_list(refs) and length(refs) <= 32 do
    ids = Enum.map(refs, fn ref -> if is_map(ref), do: ref["id"] || ref[:id], else: nil end)

    if length(Enum.uniq(ids)) != length(ids) do
      {:error, :attachment_duplicate}
    else
      Enum.reduce_while(Enum.zip(ids, refs), {:ok, []}, fn {id, ref}, {:ok, acc} ->
        case state.records[id] do
          %{"state" => "ready"} = r ->
            expected = ref["sha256"] || ref[:sha256]

            cond do
              not bound?(r, session) ->
                {:halt, {:error, :attachment_not_ready}}

              r["pins"] == [] and r["expires_at"] < state.clock.() ->
                {:halt, {:error, :attachment_expired}}

              expected && expected != r["sha256"] ->
                {:halt, {:error, :attachment_integrity_failed}}

              true ->
                {:cont, {:ok, acc ++ [r]}}
            end

          _ ->
            {:halt, {:error, :attachment_not_ready}}
        end
      end)
    end
  end

  defp resolve(_, _, _), do: {:error, :attachment_invalid}

  defp bound?(record, session),
    do:
      is_binary(session) and
        (record["session_id"] == session or session in Map.get(record, "session_ids", []))

  defp owned(state, id, actor) do
    case state.records[id] do
      %{"actor" => ^actor} = r -> {:ok, r}
      _ -> {:error, :attachment_not_authorized}
    end
  end

  defp authorized(state, id, actor, session) do
    case state.records[id] do
      %{"pins" => [_ | _]} = r when is_binary(session) ->
        if bound?(r, session), do: {:ok, r}, else: owned(state, id, actor)

      _ ->
        owned(state, id, actor)
    end
  end

  defp status(r),
    do:
      Map.take(r, @public)
      |> Map.merge(%{
        "upload_id" => r["id"],
        "received" => r["offset"],
        "chunk_bytes" => @chunk,
        "error" => r["error"]
      })

  defp update_many(state, records, fun) do
    Enum.reduce_while(records, {:ok, state}, fn r, {:ok, next} ->
      case put(next, fun.(r)) do
        {:ok, updated} -> {:cont, {:ok, updated}}
        _ -> {:halt, {:error, next}}
      end
    end)
    |> case do
      {:ok, next} -> {:ok, next}
      {:error, next} -> {{:error, :attachment_storage_failed}, next}
    end
  end

  defp put(state, record) do
    with :ok <-
           atomic(
             Path.join([state.root, record["id"], "manifest"]),
             Content.encode(JSON.encode!(record))
           ) do
      {:ok, %{state | records: Map.put(state.records, record["id"], record)}}
    end
  end

  defp read_record(root, id) do
    with {:ok, bytes} <- Content.read(Path.join([root, id, "manifest"])),
         {:ok, %{"id" => ^id, "pins" => pins} = r} when is_list(pins) <- JSON.decode(bytes),
         true <-
           r["state"] in ["uploading", "preparing", "ready", "failed"] and
             is_integer(r["source_size"]) and r["source_size"] in 1..@max_image and
             is_integer(r["expires_at"]) and is_integer(r["created_at"]) and
             is_integer(r["offset"]) and is_list(r["chunks"]) and is_binary(r["actor"]) do
      {:ok, r}
    end
  end

  # Two verified immutable blobs cap the cache at 40 MiB. A 20 MiB image
  # downloaded over small gateway frames is decrypted and hashed once, not per frame.
  defp verified_read(root, id, variant, expected) do
    key = {id, variant, expected}
    cache = Process.get(:attachment_read_cache, [])

    case List.keyfind(cache, key, 0) do
      {^key, bytes} ->
        {:ok, bytes}

      nil ->
        with {:ok, bytes} <- Content.read(Path.join([root, id, variant])),
             true <- byte_size(bytes) <= @max_image and hash(bytes) == expected do
          Process.put(:attachment_read_cache, [{key, bytes} | Enum.take(cache, 1)])
          {:ok, bytes}
        else
          _ -> {:error, :attachment_integrity_failed}
        end
    end
  end

  defp session_quota?(state, records, session) do
    ids = MapSet.new(records, & &1["id"])

    state.records
    |> Map.values()
    |> Enum.filter(&(bound?(&1, session) or MapSet.member?(ids, &1["id"])))
    |> Enum.reduce(0, fn r, sum -> sum + (r["byte_size"] || @max_image) * 2 + 512 * 1024 end)
    |> Kernel.<=(state.quotas.session_bytes)
  end

  defp active_count(state, actor),
    do:
      Enum.count(state.records, fn {_, r} ->
        r["state"] in ["uploading", "preparing"] and (is_nil(actor) or r["actor"] == actor)
      end)

  defp quota?(state, actor, bytes, session) do
    reservation = bytes * 2 + @max_image * 2 + 512 * 1024

    totals =
      Enum.reduce(state.records, %{total: 0, personal: 0, staging: 0, session: 0}, fn {_, r},
                                                                                      acc ->
        staged = r["state"] != "ready"

        size =
          if staged,
            do: r["source_size"] * 2 + @max_image * 2 + 512 * 1024,
            else: (r["byte_size"] + 256 * 1024) * 2

        %{
          total: acc.total + size,
          personal: acc.personal + if(r["actor"] == actor and r["pins"] == [], do: size, else: 0),
          staging: acc.staging + if(staged, do: size, else: 0),
          session: acc.session + if(bound?(r, session), do: size, else: 0)
        }
      end)

    totals.total + reservation <= state.quotas.runtime_bytes and
      totals.personal + reservation <= state.quotas.client_bytes and
      totals.staging + reservation <= state.quotas.staging_bytes and
      totals.session + reservation <= state.quotas.session_bytes
  end

  # Storage is the authority; a closed conversation still retains its images. A
  # reservation with no remaining session is collected only after the draft grace period.
  defp reconcile_pins(state) do
    if Process.whereis(Ouroboros.Interactive.Store) do
      sessions = Ouroboros.Interactive.Store.list() |> Map.new(&{&1.id, &1})

      Enum.reduce(state.records, state, fn {_id, record}, next ->
        owners = Enum.uniq([record["session_id"] | Map.get(record, "session_ids", [])])

        retained =
          Enum.any?(owners, fn owner ->
            case sessions[owner] do
              nil ->
                false

              session ->
                owner != record["session_id"] or
                  Enum.any?(record["pins"], &Map.has_key?(session.turns, &1))
            end
          end)

        if record["pins"] != [] and not retained and
             record["created_at"] + @draft_ttl < state.clock.() do
          case put(next, Map.put(record, "pins", [])) do
            {:ok, updated} -> updated
            _ -> next
          end
        else
          next
        end
      end)
    else
      state
    end
  catch
    :exit, _ -> state
  end

  defp sweep(state) do
    Enum.reduce(state.records, state, fn {id, r}, next ->
      expired =
        r["expires_at"] < state.clock.() or
          (r["state"] in ["uploading", "preparing"] and
             r["created_at"] + @upload_lifetime < state.clock.())

      if r["pins"] == [] and expired, do: remove(next, id), else: next
    end)
  end

  defp remove(state, id) do
    workers =
      Enum.reduce(state.workers, %{}, fn {ref, {pid, worker_id}}, acc ->
        if worker_id == id do
          Process.unlink(pid)
          Process.exit(pid, :kill)
          Process.demonitor(ref, [:flush])
          acc
        else
          Map.put(acc, ref, {pid, worker_id})
        end
      end)

    Process.put(
      :attachment_read_cache,
      Enum.reject(Process.get(:attachment_read_cache, []), fn {{cached, _, _}, _} ->
        cached == id
      end)
    )

    case File.rm_rf(Path.join(state.root, id)) do
      {:ok, _} -> %{state | records: Map.delete(state.records, id), workers: workers}
      _ -> %{state | workers: workers}
    end
  end

  defp digest_chunks(paths) do
    Enum.reduce_while(paths, {:ok, :crypto.hash_init(:sha256)}, fn path, {:ok, ctx} ->
      case Content.read(path) do
        {:ok, bytes} -> {:cont, {:ok, :crypto.hash_update(ctx, bytes)}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, ctx} -> {:ok, :crypto.hash_final(ctx) |> Base.encode16(case: :lower)}
      error -> error
    end
  end

  defp chunk_path(root, id, offset), do: Path.join([root, id, "chunk-#{offset}"])
  defp hash(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
  defp valid_id?(id), do: is_binary(id) and Regex.match?(~r/\Aatt_[A-Za-z0-9_-]{32}\z/, id)
  defp valid_hash?(value), do: is_binary(value) and Regex.match?(~r/\A[0-9a-f]{64}\z/, value)

  defp valid_label?(value),
    do: is_binary(value) and byte_size(value) in 1..200 and String.valid?(value)

  defp name(value) when is_binary(value),
    do:
      value
      |> String.replace(~r/[\x00-\x1f\x7f-\x{009f}\x{202a}-\x{202e}\x{2066}-\x{2069}]/u, "")
      |> Path.basename()
      |> String.slice(0, 120)

  defp name(_), do: "image.png"
  defp source(value) when value in ["clipboard", "file_picker", "drop"], do: value
  defp source(_), do: "file_picker"
  defp safe_error(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp safe_error(_), do: "attachment_prepare_failed"

  defp private_directory(path) do
    with :ok <- File.mkdir_p(path),
         {:ok, %{type: :directory}} <- File.lstat(path),
         do: File.chmod(path, 0o700)
  end

  defp atomic(path, bytes), do: Ouroboros.Audit.File.atomic(path, bytes)

  defp recovery_identity(root) do
    path = Path.join(root, ".recovery-id")

    case File.lstat(path) do
      {:error, :enoent} ->
        id = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
        with :ok <- atomic(path, id), do: {:ok, id}

      {:ok, %{type: :regular, size: 64}} ->
        with {:ok, id} <- File.read(path),
             true <- valid_hash?(id),
             do: {:ok, id},
             else: (_ -> {:error, :attachment_recovery_identity_invalid})

      _ ->
        {:error, :attachment_recovery_identity_invalid}
    end
  end
end
