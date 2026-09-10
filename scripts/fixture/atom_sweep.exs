# Lists every atom the fixture's durable files carry, and marks the ones the reduced
# slice branches no longer spell.
#
#     FIXTURE_DATA_DIR=/abs/datadir \
#     REDUCED_WORKTREES=/abs/c1,/abs/c3,/abs/c5,/abs/c6 \
#       mix run --no-start scripts/fixture/atom_sweep.exs > sweep.tsv
#
# A column is named after its worktree's directory unless the entry is `name=/abs/path`,
# which is how the committed sweep names the integrated tree `core`.
#
# Nothing is written outside stdout, and the reduced worktrees are only read: presence is
# decided by loading every `.beam` under each worktree's `_build/dev/lib` into a throwaway
# VM — one that never decodes the fixture, so nothing it reads can intern a name — and
# asking `String.to_existing_atom/1` there. Nothing is started in the worktree. (The atom
# chunk of a `.beam` is not enough: it omits atoms that occur only inside compound
# literals, which is where a `@result_fields` map, a constraints table and the retired list
# itself keep theirs; a sweep that read only the chunk marked such names retired.)

data_dir = System.get_env("FIXTURE_DATA_DIR") || raise "FIXTURE_DATA_DIR is required"

worktrees =
  (System.get_env("REDUCED_WORKTREES") || "")
  |> String.split(",", trim: true)
  |> Enum.map(&String.trim/1)
  |> Enum.map(fn entry ->
    case String.split(entry, "=", parts: 2) do
      [name, root] -> {name, root}
      [root] -> {Path.basename(root), root}
    end
  end)

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

  # The names, as strings, that a fresh VM answers `String.to_existing_atom/1` for once every
  # module under `root/_build/dev/lib` is loaded. Run out of process so that this script's own
  # `binary_to_term/1` over the fixture — which creates every atom it meets — cannot leak.
  @probe """
  [names_file, root] = System.argv()

  root
  |> Path.join("_build/dev/lib/*/ebin")
  |> Path.wildcard()
  |> Enum.each(fn ebin ->
    Code.prepend_path(ebin)

    ebin
    |> Path.join("*.beam")
    |> Path.wildcard()
    |> Enum.each(fn beam -> beam |> Path.basename(".beam") |> String.to_atom() |> Code.ensure_loaded() end)
  end)

  names_file
  |> File.read!()
  |> String.split("\\n", trim: true)
  |> Enum.filter(fn name ->
    try do
      _ = String.to_existing_atom(name)
      true
    rescue
      ArgumentError -> false
    end
  end)
  |> Enum.join("\\n")
  |> IO.write()
  """

  def present(root, names_file) do
    {out, 0} = System.cmd("elixir", ["-e", @probe, names_file, root], stderr_to_stdout: false)
    out |> String.split("\n", trim: true) |> MapSet.new()
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

names_file =
  Path.join(
    System.tmp_dir!(),
    "atom-sweep-#{System.unique_integer([:positive, :monotonic])}.txt"
  )

File.write!(names_file, candidates |> Enum.map(&Atom.to_string/1) |> Enum.join("\n"))

presence =
  try do
    Map.new(worktrees, fn {name, root} -> {name, Sweep.present(root, names_file)} end)
  after
    File.rm(names_file)
  end

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
      |> Enum.map(fn {_name, set} ->
        if MapSet.member?(set, Atom.to_string(atom)), do: "yes", else: "NO"
      end)

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
