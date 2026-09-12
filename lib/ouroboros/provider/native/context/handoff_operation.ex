defmodule Ouroboros.Provider.Native.Context.HandoffOperation do
  @moduledoc false

  alias Ouroboros.Maintenance.Epoch

  @filename "handoff-operations.term"
  @limit 32

  def path(session_dir), do: Path.join(session_dir, @filename)

  def load(session_dir, opts \\ []) do
    target = path(session_dir)

    with :ok <- reconcile_pending_on_load(target, opts) do
      load_file(session_dir, target, opts)
    else
      {:error, reason} ->
        raise ArgumentError, "could not reconcile handoff operation store: #{inspect(reason)}"
    end
  end

  defp load_file(session_dir, target, opts) do
    case File.read(target) do
      {:ok, bytes} ->
        try do
          retained =
            bytes
            |> :erlang.binary_to_term([:safe])
            |> List.wrap()
            |> Enum.map(&validate!/1)

          recover? = Enum.any?(retained, &(&1.status in [:running, :committing]))
          entries = Enum.map(retained, &recover/1)

          operations = Map.new(entries, &{&1.id, &1})

          if map_size(operations) != length(entries),
            do: raise(ArgumentError, "duplicate handoff operation id")

          if recover? do
            writer =
              Application.get_env(:ouroboros, :native_handoff_recovery_writer, &rewrite/2)

            case invoke_writer(
                   writer,
                   session_dir,
                   operations,
                   opts,
                   {:recovery, recovery_id(operations)}
                 ) do
              {:ok, persisted} ->
                persisted

              {:error, reason} ->
                raise ArgumentError, "could not persist handoff recovery: #{inspect(reason)}"
            end
          else
            operations
          end
        rescue
          error ->
            raise ArgumentError, "invalid handoff operation store: #{Exception.message(error)}"
        end

      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        raise ArgumentError, "unreadable handoff operation store: #{inspect(reason)}"
    end
  end

  defp reconcile_pending_on_load(_target, opts) when not is_list(opts), do: :ok

  defp reconcile_pending_on_load(target, opts) do
    case Keyword.get(opts, :epoch_server) do
      nil ->
        :ok

      server ->
        with observation when is_map(observation) <- epoch_call(fn -> Epoch.observe(server) end) do
          pending =
            Enum.filter(
              observation.pending,
              &String.starts_with?(&1.write_id, epoch_prefix(target))
            )
            |> Enum.map(&Map.delete(&1, :status))

          Enum.reduce_while(pending, :ok, fn reservation, :ok ->
            case observe(target, reservation.payload_digest) do
              :exact ->
                case epoch_call(fn -> Epoch.commit(reservation, server) end) do
                  :ok ->
                    {:cont, :ok}

                  {:error, reason} ->
                    {:halt, {:error, {:maintenance_epoch_commit_failed, reason}}}
                end

              :absent ->
                case epoch_call(fn ->
                       Epoch.abort(reservation, :payload_absence_confirmed, server)
                     end) do
                  :ok -> {:cont, :ok}
                  {:error, reason} -> {:halt, {:error, {:maintenance_epoch_abort_failed, reason}}}
                end

              other ->
                {:halt, {:error, {:handoff_operation_outcome_unknown, other}}}
            end
          end)
        else
          {:error, reason} -> {:error, {:maintenance_epoch_unavailable, reason}}
          _ -> {:error, :invalid_epoch_observation}
        end
    end
  end

  def put(session_dir, operations, operation, opts \\ []) do
    if not Map.has_key?(operations, operation.id) and map_size(operations) >= @limit do
      {:error, :handoff_operation_capacity}
    else
      rewrite(
        session_dir,
        Map.put(operations, operation.id, operation),
        opts,
        {operation.id, operation.status}
      )
    end
  end

  defp rewrite(session_dir, operations),
    do: rewrite(session_dir, operations, [], :legacy_recovery)

  defp rewrite(session_dir, operations, opts, operation_identity) do
    target = path(session_dir)

    temporary =
      target <> ".tmp-" <> Base.url_encode64(:crypto.strong_rand_bytes(6), padding: false)

    bytes = encode_operations(operations)

    case Keyword.get(opts, :epoch_server) do
      nil ->
        publish(target, temporary, session_dir, bytes, operations)

      server ->
        epoch_publish(
          target,
          temporary,
          session_dir,
          bytes,
          operations,
          server,
          operation_identity
        )
    end
  end

  defp publish(target, temporary, session_dir, bytes, operations) do
    with :ok <- File.write(temporary, bytes, [:binary, :sync]),
         :ok <- File.chmod(temporary, 0o600),
         :ok <- File.rename(temporary, target),
         :ok <- Ouroboros.Audit.File.sync_directory(session_dir) do
      {:ok, operations}
    else
      {:error, reason} ->
        File.rm(temporary)
        {:error, {:handoff_operation_write_failed, reason}}
    end
  end

  defp epoch_publish(target, temporary, session_dir, bytes, operations, server, identity) do
    digest = sha256(bytes)

    write_id = epoch_write_id(target, identity)

    with {:ok, existing} <- reservation(server, write_id) do
      case existing do
        nil ->
          with {:ok, reserved} <- epoch_call(fn -> Epoch.reserve(write_id, digest, server) end),
               {:ok, operations} <- publish(target, temporary, session_dir, bytes, operations),
               :ok <- epoch_call(fn -> Epoch.commit(reserved, server) end) do
            {:ok, operations}
          else
            {:error, reason} -> reconcile_failure(target, digest, server, write_id, reason)
          end

        {:committed, %{payload_digest: ^digest} = reserved} ->
          case observe(target, reserved.payload_digest) do
            :exact -> decode_operations(target)
            other -> {:error, {:handoff_operation_committed_payload_invalid, other}}
          end

        %{payload_digest: ^digest} = reserved ->
          reconcile_existing(target, digest, server, reserved)

        _conflicting_identity ->
          {:error, {:maintenance_epoch, :write_id_conflict}}
      end
    end
  end

  defp reservation(server, write_id) do
    case epoch_call(fn -> Epoch.lookup(write_id, server) end) do
      :not_found -> {:ok, nil}
      {:ok, %{status: :pending} = item} -> {:ok, Map.delete(item, :status)}
      {:ok, %{status: :committed} = item} -> {:ok, {:committed, Map.delete(item, :status)}}
      {:ok, %{status: :aborted}} -> {:error, {:handoff_operation_already_settled, :aborted}}
      {:error, reason} -> {:error, {:maintenance_epoch_unavailable, reason}}
      _ -> {:error, :invalid_epoch_observation}
    end
  end

  defp reconcile_existing(_target, digest, _server, %{payload_digest: reserved_digest})
       when digest != reserved_digest,
       do: {:error, {:maintenance_epoch, :write_id_conflict}}

  defp reconcile_existing(target, digest, server, reserved) do
    case observe(target, digest) do
      :exact ->
        with :ok <- epoch_call(fn -> Epoch.commit(reserved, server) end),
             {:ok, operations} <- decode_operations(target),
             do: {:ok, operations}

      :absent ->
        with :ok <-
               epoch_call(fn -> Epoch.abort(reserved, :payload_absence_confirmed, server) end),
             do: {:error, :handoff_operation_payload_absent}

      other ->
        {:error, {:handoff_operation_outcome_unknown, other}}
    end
  end

  defp reconcile_failure(target, digest, server, write_id, reason) do
    with {:ok, reserved} <- reservation(server, write_id) do
      case {reserved, observe(target, digest)} do
        {%{}, :exact} -> reconcile_existing(target, digest, server, reserved)
        {%{}, :absent} -> reconcile_existing(target, digest, server, reserved)
        _ -> {:error, {:handoff_operation_outcome_unknown, reason}}
      end
    end
  end

  defp observe(path, digest) do
    case File.read(path) do
      {:ok, bytes} -> if sha256(bytes) == digest, do: :exact, else: :different
      {:error, :enoent} -> :absent
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_operations(path) do
    with {:ok, bytes} <- File.read(path) do
      operations = bytes |> :erlang.binary_to_term([:safe]) |> Map.new(&{&1.id, &1})
      {:ok, operations}
    end
  rescue
    _ -> {:error, :invalid_handoff_operation_store}
  end

  defp epoch_call(fun) do
    fun.()
  catch
    :exit, reason -> {:error, reason}
  end

  defp invoke_writer(writer, dir, operations, opts, identity) do
    if is_function(writer, 4),
      do: writer.(dir, operations, opts, identity),
      else: writer.(dir, operations)
  end

  defp recovery_id(operations), do: operations |> Map.keys() |> Enum.sort()
  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  defp epoch_prefix(target),
    do: "native-handoff/v1/" <> binary_part(sha256(target), 0, 16) <> "/"

  @doc false
  def epoch_write_id(target, identity),
    do:
      epoch_prefix(target) <>
        sha256(:erlang.term_to_binary({target, identity}, [:deterministic]))

  @doc false
  def encode_operations(operations),
    do: :erlang.term_to_binary(Map.values(operations), [:deterministic, {:compressed, 6}])

  defp validate!(%{id: id, fingerprint: fingerprint, status: status} = operation)
       when is_binary(id) and id != "" and byte_size(id) <= 128 and is_binary(fingerprint) and
              fingerprint != "" do
    case status do
      :running -> operation
      terminal when terminal in [:failed, :interrupted] -> require_error!(operation)
      retained when retained in [:prepared, :committing] -> require_packet!(operation)
      :ambiguous -> operation |> require_packet!() |> require_error!()
      :completed -> operation |> require_packet!() |> require_result!()
      _unknown -> raise ArgumentError, "invalid handoff operation status"
    end
  end

  defp validate!(_operation), do: raise(ArgumentError, "invalid handoff operation")

  defp require_packet!(
         %{
           child_id: child_id,
           packet: packet,
           packet_bytes: packet_bytes,
           files: files,
           files_in_packet: files_in_packet,
           files_omitted: files_omitted
         } = operation
       )
       when is_binary(child_id) and child_id != "" and is_binary(packet) and
              packet_bytes == byte_size(packet) and is_integer(files) and files >= 0 and
              is_integer(files_in_packet) and files_in_packet >= 0 and
              is_integer(files_omitted) and files_omitted >= 0 and
              files == files_in_packet + files_omitted do
    operation
  end

  defp require_packet!(_operation), do: raise(ArgumentError, "invalid retained handoff packet")

  defp require_result!(
         %{
           result: %{
             provider_session_id: child_id,
             packet_bytes: packet_bytes,
             files: files,
             files_in_packet: files_in_packet,
             files_omitted: files_omitted,
             parent: parent
           }
         } = operation
       )
       when child_id == operation.child_id and packet_bytes == operation.packet_bytes and
              files == operation.files and files_in_packet == operation.files_in_packet and
              files_omitted == operation.files_omitted and is_binary(parent) and parent != "",
       do: operation

  defp require_result!(_operation), do: raise(ArgumentError, "invalid completed handoff result")

  defp require_error!(%{error: error} = operation) when not is_nil(error), do: operation
  defp require_error!(_operation), do: raise(ArgumentError, "invalid terminal handoff operation")

  defp recover(%{status: :running} = operation) do
    Map.merge(operation, %{
      status: :interrupted,
      error: "the runtime stopped before the handoff packet was retained; use a new handoff id",
      finished_at: DateTime.utc_now()
    })
  end

  # The complete packet and allocated child ID make checkpoint creation retryable without
  # another summary inference.
  defp recover(%{status: :prepared} = operation), do: operation

  defp recover(%{status: :committing} = operation) do
    Map.merge(operation, %{
      status: :ambiguous,
      error:
        "native child checkpoint creation began before the runtime stopped; inspect the retained child id before any retry",
      finished_at: DateTime.utc_now()
    })
  end

  defp recover(operation), do: operation
end
