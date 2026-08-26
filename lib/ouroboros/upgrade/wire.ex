defmodule Ouroboros.Upgrade.Wire do
  @moduledoc """
  Checkpoint terms that `[:safe]` `binary_to_term` can read in a VM that has not
  loaded this application.

  `Ouroboros.Storage.DurableFile` keeps `[:safe]` so a tampered file cannot intern
  atoms. That flag also refuses *legitimate* atoms a rebooted VM has not interned
  yet: a struct module, a policy reason, a node name the cluster has not connected
  to. Encoding those as tagged binaries at the journal boundary is what makes a
  production checkpoint loadable before the owning modules run — and still round-trip
  once they have.

  `true`, `false`, and `nil` stay atoms: every Erlang VM already has them.
  """

  @atom "__atom__"
  @struct "__struct__"
  @tuple "__tuple__"

  @doc "The form written to storage: binaries, numbers, lists, maps, and the three booleans."
  @spec dump(term()) :: term()
  def dump(term), do: encode(term)

  @doc """
  Rebuilds structs and atoms that this VM already knows.

  A name that is not interned stays a tagged map or a binary rather than being created.
  An already-decoded struct (a checkpoint written before this boundary existed) is
  returned as-is: `[:safe]` could only have produced it in a VM that had the module.
  """
  @spec load(term()) :: term()
  def load(%mod{} = struct) when is_atom(mod), do: struct
  def load(term), do: decode(term)

  defp encode(term) when term in [nil, true, false], do: term
  defp encode(term) when is_binary(term) or is_number(term), do: term
  # Same-VM resume handles, not reboot-stable. `[:safe]` accepts them when the node
  # name they carry is already interned, which it is on the node that wrote the journal.
  defp encode(term) when is_pid(term) or is_reference(term) or is_port(term), do: term
  defp encode(term) when is_atom(term), do: %{@atom => Atom.to_string(term)}

  defp encode(%mod{} = struct) when is_atom(mod) do
    struct
    |> Map.from_struct()
    |> Map.new(fn {key, value} -> {Atom.to_string(key), encode(value)} end)
    |> Map.put(@struct, Atom.to_string(mod))
  end

  defp encode(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {encode_key(key), encode(value)} end)
  end

  defp encode(tuple) when is_tuple(tuple) do
    %{@tuple => tuple |> Tuple.to_list() |> Enum.map(&encode/1)}
  end

  defp encode(list) when is_list(list) do
    if proper_list?(list),
      do: Enum.map(list, &encode/1),
      else: %{"__dropped__" => "improper_list"}
  end

  defp encode(other), do: %{"__dropped__" => inspect(other, limit: 8, printable_limit: 80)}

  defp encode_key(key) when is_atom(key), do: Atom.to_string(key)
  defp encode_key(key) when is_binary(key), do: key
  defp encode_key(key), do: encode(key)

  defp decode(%mod{} = struct) when is_atom(mod), do: struct

  defp decode(%{@atom => name}) when is_binary(name), do: existing(name, name)

  defp decode(%{@tuple => items}) when is_list(items) do
    items |> Enum.map(&decode/1) |> List.to_tuple()
  end

  defp decode(%{@struct => name} = map) when is_binary(name) do
    fields =
      map
      |> Map.delete(@struct)
      |> Map.new(fn {key, value} -> {decode_key(key), decode(value)} end)

    case existing_atom(name) do
      {:ok, mod} ->
        try do
          struct(mod, fields)
        rescue
          ArgumentError -> Map.put(fields, @struct, name)
          KeyError -> Map.put(fields, @struct, name)
        end

      :error ->
        Map.put(fields, @struct, name)
    end
  end

  defp decode(map) when is_map(map) do
    Map.new(map, fn {key, value} -> {decode_key(key), decode(value)} end)
  end

  defp decode(list) when is_list(list), do: Enum.map(list, &decode/1)
  defp decode(term), do: term

  defp decode_key(key) when is_binary(key), do: existing(key, key)
  defp decode_key(key), do: decode(key)

  defp existing(name, fallback) do
    case existing_atom(name) do
      {:ok, atom} -> atom
      :error -> fallback
    end
  end

  defp existing_atom(name) do
    {:ok, String.to_existing_atom(name)}
  rescue
    ArgumentError -> :error
  end

  defp proper_list?([]), do: true
  defp proper_list?([_head | tail]), do: proper_list?(tail)
  defp proper_list?(_improper), do: false
end
