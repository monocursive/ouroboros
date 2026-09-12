defmodule Ouroboros.Maintenance.Inventory do
  @moduledoc """
  Bounded immutable inventory values and deterministic paging for the P4 fence contract.

  This module does not acquire an authoritative barrier or read any runtime authority. A
  caller must obtain rows, reservation observations, generation, and root digest while the
  relevant authorities are frozen. `freeze/2` validates and copies those values; `page/5`
  serves only that self-authenticating copy.
  """

  @max_items 10_000
  @max_page 100
  @max_id_bytes 128
  @max_node_bytes 255
  @max_root_bytes 4_096
  @max_lineage 64
  @max_checkpoint_bytes 1_099_511_627_776
  @digest ~r/\A[0-9a-f]{64}\z/
  @item_keys MapSet.new([
               :session_id,
               :generation,
               :checkpoint_sha256,
               :checkpoint_length,
               :owner_node,
               :process_generation,
               :lifecycle,
               :active_count,
               :queued_count,
               :workspace_reservation,
               :handoff_lineage
             ])
  @reservation_keys MapSet.new([:session_id, :generation, :root])
  @lineage_keys MapSet.new([:session_id, :node])

  @type snapshot :: map()

  @doc "Validates bounded local idle rows and freezes their deterministic sorted value."
  @spec freeze([map()], keyword()) :: {:ok, snapshot()} | {:error, term()}
  def freeze(rows, opts) when is_list(rows) and is_list(opts) do
    local_node = Keyword.get(opts, :local_node, Atom.to_string(node()))
    generation = Keyword.get(opts, :generation)
    root_digest = Keyword.get(opts, :root_digest)
    reservations = Keyword.get(opts, :reservations)
    max_items = Keyword.get(opts, :max_items, @max_items)

    with :ok <- valid_options(local_node, generation, root_digest, reservations, max_items),
         :ok <- within_bound(rows, max_items),
         {:ok, items} <- validate_items(rows, local_node),
         :ok <- unique_ids(items),
         :ok <- reservations_match(items, reservations),
         sorted <- Enum.sort_by(items, &{&1.session_id, &1.generation}),
         encoded <- Enum.map(sorted, &encode_item/1),
         digest <- complete_digest(encoded),
         token <- snapshot_token(generation, root_digest, digest, length(sorted)) do
      {:ok,
       %{
         schema: 1,
         token: token,
         generation: generation,
         root_digest: root_digest,
         total: length(sorted),
         items: sorted,
         encoded_items: encoded,
         digest: digest
       }}
    end
  end

  def freeze(_rows, _opts), do: {:error, :invalid_inventory}

  @doc "Returns a page bound to the supplied snapshot token, generation, and cursor."
  @spec page(snapshot(), String.t(), nil | String.t(), pos_integer(), non_neg_integer()) ::
          {:ok, map()} | {:error, term()}
  def page(snapshot, token, cursor, limit, generation) do
    with :ok <- valid_snapshot(snapshot),
         :ok <- equal(token, snapshot.token, :snapshot_token_mismatch),
         :ok <- equal(generation, snapshot.generation, :generation_mismatch),
         :ok <- valid_limit(limit),
         {:ok, offset} <- cursor_offset(cursor, snapshot),
         :ok <- valid_offset(offset, snapshot.total) do
      page_items = Enum.slice(snapshot.items, offset, limit)
      next_offset = offset + length(page_items)
      complete = next_offset == snapshot.total

      {:ok,
       %{
         items: page_items,
         cursor: cursor,
         next_cursor: if(complete, do: nil, else: make_cursor(next_offset, snapshot)),
         total: snapshot.total,
         snapshot: snapshot.token,
         generation: snapshot.generation,
         complete: complete,
         digest: if(complete, do: snapshot.digest, else: nil)
       }}
    end
  end

  defp valid_options(local_node, generation, root_digest, reservations, max_items) do
    cond do
      valid_text(local_node, @max_node_bytes) != :ok ->
        {:error, :invalid_local_node}

      not (is_integer(generation) and generation >= 0) ->
        {:error, :invalid_generation}

      not valid_digest?(root_digest) ->
        {:error, :invalid_root_digest}

      not is_map(reservations) ->
        {:error, :invalid_reservations}

      not (is_integer(max_items) and max_items > 0 and max_items <= @max_items) ->
        {:error, :invalid_inventory_bound}

      true ->
        :ok
    end
  end

  defp within_bound(rows, max_items) do
    if length(rows) <= max_items, do: :ok, else: {:error, :inventory_capacity}
  end

  defp validate_items(rows, local_node) do
    Enum.reduce_while(rows, {:ok, []}, fn item, {:ok, acc} ->
      case validate_item(item, local_node) do
        :ok -> {:cont, {:ok, [item | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  defp validate_item(item, local_node) when is_map(item) do
    with :ok <- exact_keys(item, @item_keys, :invalid_item_shape),
         :ok <- valid_text(item.session_id, @max_id_bytes),
         :ok <- non_negative(item.generation, :invalid_item_generation),
         true <- valid_digest?(item.checkpoint_sha256) || {:error, :invalid_checkpoint_digest},
         :ok <-
           bounded_integer(
             item.checkpoint_length,
             0,
             @max_checkpoint_bytes,
             :invalid_checkpoint_length
           ),
         :ok <- valid_text(item.owner_node, @max_node_bytes),
         true <- item.owner_node == local_node || {:error, :remote_owner},
         :ok <- positive(item.process_generation, :invalid_process_generation),
         true <- item.lifecycle == :idle || {:error, :nonidle_item},
         true <- (item.active_count == 0 and item.queued_count == 0) || {:error, :nonzero_work},
         :ok <- valid_reservation(item.workspace_reservation),
         :ok <- valid_lineage(item.handoff_lineage, local_node) do
      :ok
    else
      false -> {:error, :invalid_item}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_item(_item, _local_node), do: {:error, :invalid_item_shape}

  defp valid_reservation(nil), do: :ok

  defp valid_reservation(reservation) when is_map(reservation) do
    with :ok <- exact_keys(reservation, @reservation_keys, :invalid_reservation),
         :ok <- valid_text(reservation.session_id, @max_id_bytes),
         :ok <- non_negative(reservation.generation, :invalid_reservation),
         :ok <- valid_text(reservation.root, @max_root_bytes) do
      :ok
    end
  end

  defp valid_reservation(_reservation), do: {:error, :invalid_reservation}

  defp valid_lineage(lineage, local_node)
       when is_list(lineage) and length(lineage) <= @max_lineage do
    Enum.reduce_while(lineage, :ok, fn entry, :ok ->
      result =
        with true <- is_map(entry) || {:error, :invalid_handoff},
             :ok <- exact_keys(entry, @lineage_keys, :invalid_handoff),
             :ok <- valid_text(entry.session_id, @max_id_bytes),
             :ok <- valid_text(entry.node, @max_node_bytes),
             true <- entry.node == local_node || {:error, :remote_handoff} do
          :ok
        else
          {:error, reason} -> {:error, reason}
        end

      if result == :ok, do: {:cont, :ok}, else: {:halt, result}
    end)
  end

  defp valid_lineage(_lineage, _local_node), do: {:error, :invalid_handoff}

  defp unique_ids(items) do
    ids = Enum.map(items, & &1.session_id)
    if Enum.uniq(ids) == ids, do: :ok, else: {:error, :duplicate_session_id}
  end

  defp reservations_match(items, reservations) do
    expected = Map.new(items, &{&1.session_id, &1.workspace_reservation})
    if reservations == expected, do: :ok, else: {:error, :reservation_mismatch}
  end

  defp valid_snapshot(snapshot) when is_map(snapshot) do
    with %{
           schema: 1,
           token: token,
           generation: generation,
           root_digest: root,
           total: total,
           items: items,
           encoded_items: encoded,
           digest: digest
         } <- snapshot,
         true <- map_size(snapshot) == 8,
         true <-
           is_list(items) and is_list(encoded) and length(items) == total and
             length(encoded) == total and total <= @max_items,
         true <- Enum.map(items, &encode_item/1) == encoded,
         true <- complete_digest(encoded) == digest,
         true <- snapshot_token(generation, root, digest, total) == token do
      :ok
    else
      _ -> {:error, :invalid_snapshot}
    end
  rescue
    _ -> {:error, :invalid_snapshot}
  end

  defp valid_snapshot(_snapshot), do: {:error, :invalid_snapshot}

  defp cursor_offset(nil, _snapshot), do: {:ok, 0}

  defp cursor_offset(cursor, snapshot) when is_binary(cursor) do
    with {:ok, <<offset::unsigned-big-32, mac::binary-size(32)>>} <-
           Base.url_decode64(cursor, padding: false),
         true <- secure_equal(mac, cursor_mac(offset, snapshot)) do
      {:ok, offset}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  defp cursor_offset(_cursor, _snapshot), do: {:error, :invalid_cursor}

  defp valid_offset(offset, total) do
    if offset <= total, do: :ok, else: {:error, :invalid_cursor}
  end

  defp valid_limit(limit) when is_integer(limit) and limit >= 1 and limit <= @max_page, do: :ok
  defp valid_limit(_limit), do: {:error, :invalid_page_limit}

  defp make_cursor(offset, snapshot) do
    Base.url_encode64(<<offset::unsigned-big-32, cursor_mac(offset, snapshot)::binary>>,
      padding: false
    )
  end

  defp cursor_mac(offset, snapshot) do
    hash([
      "OUROBOROS-P4-INVENTORY-CURSOR-V1\0",
      hex!(snapshot.token),
      u64(snapshot.generation),
      u32(snapshot.total),
      u32(offset)
    ])
  end

  defp complete_digest(encoded) do
    hash(["OUROBOROS-P4-INVENTORY-V1\0" | Enum.map(encoded, &frame/1)]) |> hex()
  end

  defp snapshot_token(generation, root, digest, total) do
    hash([
      "OUROBOROS-P4-INVENTORY-SNAPSHOT-V1\0",
      u64(generation),
      hex!(root),
      hex!(digest),
      u32(total)
    ])
    |> hex()
  end

  defp encode_item(item) do
    [
      text(item.session_id),
      u64(item.generation),
      hex!(item.checkpoint_sha256),
      u64(item.checkpoint_length),
      text(item.owner_node),
      u64(item.process_generation),
      text(Atom.to_string(item.lifecycle)),
      u32(item.active_count),
      u32(item.queued_count),
      encode_reservation(item.workspace_reservation),
      u32(length(item.handoff_lineage)),
      Enum.map(item.handoff_lineage, fn entry -> [text(entry.session_id), text(entry.node)] end)
    ]
    |> IO.iodata_to_binary()
  end

  defp encode_reservation(nil), do: <<0>>

  defp encode_reservation(value),
    do: [<<1>>, text(value.session_id), u64(value.generation), text(value.root)]

  defp text(value), do: frame(value)
  defp frame(value), do: [u32(IO.iodata_length(value)), value]
  defp u32(value), do: <<value::unsigned-big-32>>
  defp u64(value), do: <<value::unsigned-big-64>>
  defp hash(iodata), do: :crypto.hash(:sha256, iodata)
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp hex!(value), do: Base.decode16!(value, case: :lower)

  defp exact_keys(map, keys, reason) do
    if Map.keys(map) |> MapSet.new() |> MapSet.equal?(keys), do: :ok, else: {:error, reason}
  end

  defp valid_text(value, max) when is_binary(value) do
    if value != "" and byte_size(value) <= max and String.valid?(value),
      do: :ok,
      else: {:error, :invalid_text}
  end

  defp valid_text(_value, _max), do: {:error, :invalid_text}
  defp valid_digest?(value), do: is_binary(value) and byte_size(value) == 64 and value =~ @digest
  defp non_negative(value, _reason) when is_integer(value) and value >= 0, do: :ok
  defp non_negative(_value, reason), do: {:error, reason}
  defp positive(value, _reason) when is_integer(value) and value > 0, do: :ok
  defp positive(_value, reason), do: {:error, reason}

  defp bounded_integer(value, min, max, _reason)
       when is_integer(value) and value >= min and value <= max, do: :ok

  defp bounded_integer(_value, _min, _max, reason), do: {:error, reason}
  defp equal(value, value, _reason), do: :ok
  defp equal(_left, _right, reason), do: {:error, reason}

  defp secure_equal(left, right) when byte_size(left) == byte_size(right),
    do: :crypto.hash_equals(left, right)

  defp secure_equal(_left, _right), do: false
end
