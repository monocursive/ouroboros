defmodule Ouroboros.Maintenance.EpochReceipts do
  @moduledoc false

  alias Ouroboros.Storage.DurableFile

  # A compressed immutable radix trie proves both presence and absence. A missing
  # referenced node is an error, never permission to reuse a forgotten write ID.
  # Nodes publish before the Epoch checkpoint adopts their root; abandoned nodes
  # from an interrupted publication are harmless and remain unreferenced.
  def lookup(nil, _write_id, _storage), do: :not_found

  def lookup(root, write_id, storage) do
    lookup_node(root, write_id, digest(write_id), storage, "")
  end

  def put(root, {write_id, _epoch, _digest, _status} = entry, storage) do
    insert(root, digest(write_id), entry, storage, "")
  end

  def validate(nil, _epoch, _storage), do: {:ok, %{count: 0, max_epoch: 0}}

  def validate(root, epoch, storage) do
    validate_tree(root, epoch, storage, "")
  end

  def valid_root?(nil), do: true
  def valid_root?(root), do: valid_hash?(root)

  @doc false
  def checkpoint_key(hash), do: {:ouroboros, :maintenance_epoch_receipt, 1, hash}

  defp lookup_node(root, write_id, key, storage, required_prefix) do
    with {:ok, node} <- load_node(root, storage, required_prefix) do
      case node do
        {:leaf, ^key, {^write_id, _, _, _} = entry} ->
          {:ok, entry}

        {:leaf, ^key, _entry} ->
          {:error, :receipt_key_collision}

        {:leaf, _other_key, _entry} ->
          :not_found

        {:branch, prefix, children} ->
          if String.starts_with?(key, prefix) do
            nibble = nibble_at(key, byte_size(prefix))

            case List.keyfind(children, nibble, 0) do
              {^nibble, child} ->
                lookup_node(child, write_id, key, storage, child_prefix(prefix, nibble))

              nil ->
                :not_found
            end
          else
            :not_found
          end
      end
    end
  end

  defp insert(nil, key, entry, storage, _required_prefix) do
    store_node({:leaf, key, entry}, storage)
  end

  defp insert(root, key, entry, storage, required_prefix) do
    with {:ok, node} <- load_node(root, storage, required_prefix) do
      case node do
        {:leaf, ^key, ^entry} ->
          {:ok, root}

        {:leaf, ^key, _other_entry} ->
          {:error, :receipt_identity_mismatch}

        {:leaf, other_key, _other_entry} ->
          split(root, other_key, key, entry, storage)

        {:branch, prefix, children} ->
          if String.starts_with?(key, prefix) do
            nibble = nibble_at(key, byte_size(prefix))

            child =
              case List.keyfind(children, nibble, 0) do
                {^nibble, existing} -> existing
                nil -> nil
              end

            with {:ok, next_child} <-
                   insert(child, key, entry, storage, child_prefix(prefix, nibble)) do
              next_children = List.keystore(children, nibble, 0, {nibble, next_child})
              store_node({:branch, prefix, Enum.sort(next_children)}, storage)
            end
          else
            split(root, prefix, key, entry, storage)
          end
      end
    end
  end

  defp split(old_root, old_key, key, entry, storage) do
    prefix = common_prefix(old_key, key)
    old_nibble = nibble_at(old_key, byte_size(prefix))
    new_nibble = nibble_at(key, byte_size(prefix))

    with {:ok, leaf} <- store_node({:leaf, key, entry}, storage) do
      children = Enum.sort([{old_nibble, old_root}, {new_nibble, leaf}])
      store_node({:branch, prefix, children}, storage)
    end
  end

  defp validate_tree(root, epoch, storage, required_prefix) do
    with {:ok, node} <- load_node(root, storage, required_prefix) do
      case node do
        {:leaf, _key, {_write_id, receipt_epoch, _digest, _status}} ->
          if receipt_epoch <= epoch,
            do: {:ok, %{count: 1, max_epoch: receipt_epoch}},
            else: {:error, :receipt_epoch_ahead}

        {:branch, prefix, children} ->
          Enum.reduce_while(children, {:ok, %{count: 0, max_epoch: 0}}, fn
            {nibble, child}, {:ok, accumulated} ->
              case validate_tree(child, epoch, storage, child_prefix(prefix, nibble)) do
                {:ok, child_metadata} ->
                  {:cont,
                   {:ok,
                    %{
                      count: accumulated.count + child_metadata.count,
                      max_epoch: max(accumulated.max_epoch, child_metadata.max_epoch)
                    }}}

                {:error, _reason} = error ->
                  {:halt, error}
              end
          end)
      end
    end
  end

  defp load_node(root, storage, required_prefix) do
    if valid_hash?(root) do
      case DurableFile.get_checkpoint(checkpoint_key(root), storage) do
        {:ok, node} ->
          if node_digest(node) == root and valid_node?(node, required_prefix),
            do: {:ok, node},
            else: {:error, :malformed_receipt_node}

        :not_found ->
          {:error, :receipt_node_missing}

        {:error, reason} ->
          {:error, {:receipt_node_unreadable, reason}}
      end
    else
      {:error, :invalid_receipt_root}
    end
  end

  defp store_node(node, storage) do
    root = node_digest(node)
    key = checkpoint_key(root)

    case DurableFile.get_checkpoint(key, storage) do
      {:ok, ^node} ->
        {:ok, root}

      {:ok, _different_node} ->
        {:error, :receipt_node_conflict}

      :not_found ->
        case DurableFile.put_checkpoint(key, node, storage) do
          :ok -> {:ok, root}
          {:error, reason} -> {:error, {:receipt_node_write_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:receipt_node_unreadable, reason}}
    end
  end

  defp valid_node?({:leaf, key, {write_id, epoch, payload_digest, status}}, prefix) do
    valid_hash?(key) and is_binary(write_id) and write_id != "" and
      byte_size(write_id) <= 128 and String.valid?(write_id) and key == digest(write_id) and
      String.starts_with?(key, prefix) and is_integer(epoch) and epoch > 0 and
      valid_hash?(payload_digest) and status in [:committed, :aborted]
  end

  defp valid_node?({:branch, prefix, children}, required_prefix)
       when is_binary(prefix) and is_list(children) do
    byte_size(prefix) < 64 and prefix =~ ~r/\A[0-9a-f]*\z/ and
      String.starts_with?(prefix, required_prefix) and length(children) in 2..16 and
      Enum.all?(children, fn
        {nibble, root} -> is_integer(nibble) and nibble in 0..15 and valid_hash?(root)
        _ -> false
      end) and children == Enum.sort(children) and
      length(Enum.uniq_by(children, &elem(&1, 0))) == length(children)
  end

  defp valid_node?(_node, _prefix), do: false

  defp valid_hash?(value) when is_binary(value),
    do: byte_size(value) == 64 and value =~ ~r/\A[0-9a-f]{64}\z/

  defp valid_hash?(_value), do: false
  defp digest(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
  defp node_digest(node), do: node |> :erlang.term_to_binary() |> digest()
  defp nibble_at(key, position), do: key |> binary_part(position, 1) |> String.to_integer(16)
  defp child_prefix(prefix, nibble), do: prefix <> binary_part("0123456789abcdef", nibble, 1)

  defp common_prefix(left, right) do
    length = common_prefix_length(left, right, 0)
    binary_part(left, 0, length)
  end

  defp common_prefix_length(<<same, left::binary>>, <<same, right::binary>>, length),
    do: common_prefix_length(left, right, length + 1)

  defp common_prefix_length(_left, _right, length), do: length
end
