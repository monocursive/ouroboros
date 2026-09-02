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

  ## Exactness

  `load(dump(term)) == term` whenever every atom in `term` is interned in the loading
  VM and every struct module is loaded there — the state the writing VM was in. That
  holds for map keys too: an atom key and a binary key that spell the same name are
  different keys before the boundary and stay different after it, so a signed manifest
  whose `metadata` carries a JSON-shaped map (`%{"greet" => "x"}`) hashes the same on
  both sides. A checkpoint is evidence of what was signed only if this boundary is
  exact, which is why exactness is a promise here and not a convenience.

  Two things are dropped on purpose, and marked where they stood: improper lists and
  terms with no external form (functions). Pids, references, and ports are written as
  they are — same-VM resume handles, not reboot-stable.

  ## The atom fallback

  A name the loading VM has *not* interned is carried, never created: an atom comes
  back as its name (a binary), a struct as a map still tagged with its module name.
  `Ouroboros.Upgrade.ModuleName` and the journals treat that binary as the fact it is —
  a module this node is not holding — rather than as corruption. One corner of the
  fallback: a map holding both `:x` and `"x"` as keys loads on such a VM as one key, the
  way `Map.new/1` resolves a duplicate.

  ## What the dumped term looks like

  Map keys are the one place the encoding has to say what a term *was*, because a
  binary key cannot be told apart from an atom key once both are binaries. A map whose
  keys are all atoms — a struct's fields, every journal's own record — is written as a
  map of bare names, the shape every checkpoint on disk already has and the shape a
  reader without this module can grep. Any other map — binary, integer, or tuple keys,
  a mix of kinds, or an atom key that spells one of this module's own tags — is written
  as `%{"__map__" => [[key, value], ...]}` with keys encoded exactly like values, so
  `:greet` is `%{"__atom__" => "greet"}` there and `"greet"` is `"greet"`. The pairs are
  sorted by key so one map dumps to one term.

  ## Checkpoints written before keys were tagged

  Earlier builds wrote every binary key bare, atom or not, and `load/1` resolved any
  bare key that named an existing atom. Those files still load, and they load the way
  they always did: a bare key becomes the atom it names when this VM has it. A string
  key in such a file that spells an interned atom (`"nil"`; an artifact id that happens
  to be a word) was ambiguous the moment it was written, and nothing here recovers it:
  the record was lossy, the reading is not. Nothing rewrites those files. The next
  checkpoint each owner writes is in the tagged form, and no owner's checkpoint version
  moves, because the form is self-describing: a bare-keyed map and a tagged one are
  told apart by shape, not by a version field. A build older than this one reads the
  tagged form as an ordinary map with a single `"__map__"` key — carried intact and
  written back unchanged, wrong in exactly the places this form makes right.
  """

  @atom "__atom__"
  @struct "__struct__"
  @tuple "__tuple__"
  @map "__map__"
  @dropped "__dropped__"

  # An atom key spelling one of these would read back as a tag, so a map holding one is
  # written in the pair form, where keys are encoded and the collision cannot happen.
  @tags [@atom, @struct, @tuple, @map, @dropped]

  @doc """
  The form written to storage: binaries, numbers, lists, maps, and the three booleans.

  Every atom other than those three is a tagged binary, every map key is either a bare
  atom name or an encoded key inside a `"__map__"` pair list, and nothing in the result
  needs an atom the reading VM does not already have.
  """
  @spec dump(term()) :: term()
  def dump(term), do: encode(term)

  @doc """
  Rebuilds structs and atoms that this VM already knows.

  Exact for what `dump/1` wrote (see the moduledoc): a binary key stays a binary, an
  atom key comes back as that atom, a tag-shaped user map comes back as the map it was.
  A name that is not interned stays a binary or a tagged map rather than being created.
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
    if bare_keys?(map) do
      Map.new(map, fn {key, value} -> {Atom.to_string(key), encode(value)} end)
    else
      pairs = map |> Enum.sort() |> Enum.map(fn {key, value} -> [encode(key), encode(value)] end)
      %{@map => pairs}
    end
  end

  defp encode(tuple) when is_tuple(tuple) do
    %{@tuple => tuple |> Tuple.to_list() |> Enum.map(&encode/1)}
  end

  defp encode(list) when is_list(list) do
    if proper_list?(list),
      do: Enum.map(list, &encode/1),
      else: %{@dropped => "improper_list"}
  end

  defp encode(other), do: %{@dropped => inspect(other, limit: 8, printable_limit: 80)}

  # A map's keys are written as bare names only when every one of them is an atom and
  # none of those names would read back as a tag.
  defp bare_keys?(map) do
    Enum.all?(map, fn {key, _value} -> is_atom(key) and Atom.to_string(key) not in @tags end)
  end

  defp decode(%mod{} = struct) when is_atom(mod), do: struct

  # A tag is exactly one key. A map that carries a tag's name next to other keys is not
  # something `dump/1` writes, and reading it as the tag would drop the other keys.
  defp decode(%{@atom => name} = tag) when is_binary(name) and map_size(tag) == 1,
    do: existing(name, name)

  defp decode(%{@tuple => items} = tag) when is_list(items) and map_size(tag) == 1 do
    items |> Enum.map(&decode/1) |> List.to_tuple()
  end

  defp decode(%{@map => pairs} = tag) when is_list(pairs) and map_size(tag) == 1 do
    if Enum.all?(pairs, &match?([_key, _value], &1)),
      do: Map.new(pairs, fn [key, value] -> {decode(key), decode(value)} end),
      else: decode_bare(tag)
  end

  defp decode(%{@dropped => reason} = tag) when is_binary(reason) and map_size(tag) == 1,
    do: tag

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
          UndefinedFunctionError -> Map.put(fields, @struct, name)
        end

      :error ->
        Map.put(fields, @struct, name)
    end
  end

  defp decode(map) when is_map(map), do: decode_bare(map)

  defp decode(list) when is_list(list), do: Enum.map(list, &decode/1)
  defp decode(term), do: term

  # Bare keys are atom names — or, in a checkpoint written before keys were tagged,
  # strings that cannot be told from them. Either way this is the reading they get.
  defp decode_bare(map) do
    Map.new(map, fn {key, value} -> {decode_key(key), decode(value)} end)
  end

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
