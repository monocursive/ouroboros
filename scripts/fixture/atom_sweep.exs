# Lists every atom the fixture's durable files carry, and marks the ones the reduced
# slice branches no longer spell.
#
#     FIXTURE_DATA_DIR=/abs/datadir \
#     REDUCED_WORKTREES=/abs/c1,/abs/c3,/abs/c5,/abs/c6 \
#       mix run --no-start scripts/fixture/atom_sweep.exs > sweep.tsv
#
# Nothing is written outside stdout, and the reduced worktrees are only read: presence is
# decided from the atom chunk of every `.beam` under each worktree's `_build/dev/lib`,
# plus every `.beam` in this host's OTP installation. That is the same set
# `String.to_existing_atom/1` would answer from with the whole tree loaded, computed
# without starting anything in a worktree this session must not touch.

data_dir = System.get_env("FIXTURE_DATA_DIR") || raise "FIXTURE_DATA_DIR is required"

worktrees =
  (System.get_env("REDUCED_WORKTREES") || "")
  |> String.split(",", trim: true)
  |> Enum.map(&String.trim/1)

wire_tag = "__atom__"

# ── every atom, and every wire-tagged atom name, in one term ──────────────────────────

defmodule Sweep do
  def walk(term, acc), do: collect(term, acc)

  defp collect(atom, {atoms, wired}) when is_atom(atom) do
    if atom in [nil, true, false], do: {atoms, wired}, else: {MapSet.put(atoms, atom), wired}
  end

  defp collect(map, acc) when is_map(map) and not is_struct(map) do
    case Map.to_list(map) do
      [{"__atom__", name}] when is_binary(name) ->
        {atoms, wired} = acc
        {atoms, MapSet.put(wired, name)}

      pairs ->
        Enum.reduce(pairs, acc, fn {k, v}, inner -> collect(v, collect(k, inner)) end)
    end
  end

  defp collect(%_{} = struct, acc) do
    {atoms, wired} = collect(struct.__struct__, acc)

    struct
    |> Map.from_struct()
    |> Enum.reduce({atoms, wired}, fn {k, v}, inner -> collect(v, collect(k, inner)) end)
  end

  defp collect(list, acc) when is_list(list),
    do: Enum.reduce(list, acc, &collect/2)

  defp collect(tuple, acc) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.reduce(acc, &collect/2)

  defp collect(_other, acc), do: acc

  def beam_atoms(paths) do
    Enum.reduce(paths, MapSet.new(), fn path, acc ->
      case :beam_lib.chunks(String.to_charlist(path), [:atoms]) do
        {:ok, {_module, [atoms: atoms]}} ->
          Enum.reduce(atoms, acc, fn {_index, atom}, inner -> MapSet.put(inner, atom) end)

        _unreadable ->
          acc
      end
    end)
  end
end

files =
  Path.wildcard(Path.join(data_dir, "**/*.term"))
  |> Enum.sort()

per_file =
  Enum.map(files, fn file ->
    {:ok, binary} = Ouroboros.Audit.Content.read(file)
    term = :erlang.binary_to_term(binary)
    {atoms, wired} = Sweep.walk(term, {MapSet.new(), MapSet.new()})
    {Path.relative_to(file, data_dir), atoms, wired}
  end)

candidates =
  per_file
  |> Enum.reduce(MapSet.new(), fn {_f, atoms, _w}, acc -> MapSet.union(acc, atoms) end)

otp_beams =
  :code.lib_dir()
  |> to_string()
  |> Path.join("*/ebin/*.beam")
  |> Path.wildcard()

otp_atoms = Sweep.beam_atoms(otp_beams)

presence =
  Map.new(worktrees, fn root ->
    beams = Path.wildcard(Path.join(root, "_build/dev/lib/*/ebin/*.beam"))
    {Path.basename(root), MapSet.union(otp_atoms, Sweep.beam_atoms(beams))}
  end)

IO.puts(
  "file\tatom\t" <> Enum.map_join(Enum.sort(Map.keys(presence)), "\t", & &1) <> "\tretired?"
)

Enum.each(per_file, fn {file, atoms, wired} ->
  atoms
  |> Enum.sort()
  |> Enum.each(fn atom ->
    marks =
      presence
      |> Enum.sort_by(fn {name, _set} -> name end)
      |> Enum.map(fn {_name, set} -> if MapSet.member?(set, atom), do: "yes", else: "NO" end)

    retired? = if Enum.any?(marks, &(&1 == "NO")), do: "RETIRED", else: ""
    IO.puts([file, "\t", inspect(atom), "\t", Enum.join(marks, "\t"), "\t", retired?])
  end)

  Enum.each(Enum.sort(wired), fn name ->
    IO.puts([
      file,
      "\t",
      "wire:" <> name,
      "\t",
      "wire",
      "\t",
      "wire",
      "\t",
      "wire",
      "\t",
      "wire",
      "\t",
      "wire-tagged"
    ])
  end)
end)

IO.puts(:stderr, "files: #{length(files)}  distinct atoms: #{MapSet.size(candidates)}")
