defmodule Ouroboros.Provider.Native.Tools.Ls do
  @moduledoc """
  List a directory, one level by default and never more than three.

  The bound is the whole design. `ls -R` on a repository root is a context window spent
  on `_build` and `node_modules`, and the model that asked for it did not want them: it
  wanted to know what is in a directory. So `depth` exists, it is capped at #{3},
  entries are capped at #{1_000}, and the noise directories every repository has are
  listed by name rather than descended into — the same set `grep`'s fallback skips, and
  marked in the output so their absence is a fact rather than a mystery.

  Directories are marked with a trailing `/`; regular files carry their size; anything
  else carries what it is, because a symlink the model treats as a file is a bug it will
  find three tool calls later.
  """

  use Jido.Action,
    name: "ls",
    description:
      "List the entries of a workspace directory. `depth` defaults to 1 and is capped " <>
        "at 3. Bounded to 1000 entries.",
    schema: [
      path: [
        type: :string,
        default: "",
        doc: "Directory to list. Defaults to the workspace root."
      ],
      depth: [
        type: :pos_integer,
        default: 1,
        doc: "How many levels to descend. 1 lists the directory itself. Maximum 3."
      ]
    ]

  alias Ouroboros.Provider.Native.Paths

  @max_depth 3
  @max_entries 1_000
  @skipped ~w(.git _build node_modules deps .elixir_ls target .venv __pycache__)

  @impl true
  def run(params, context) do
    with {:ok, path} <- target(params.path, context.scope),
         :ok <- directory(path) do
      depth = min(params.depth, @max_depth)
      {lines, _count, truncated?} = walk(path, depth, 1, {[], 0, false})

      {:ok,
       %{
         output: present(Enum.reverse(lines), truncated?, path, context.scope.root, depth),
         is_error: false
       }}
    else
      {:error, reason} -> {:ok, %{output: "ls failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp target("", scope), do: {:ok, scope.root}
  defp target(path, scope), do: Paths.resolve(path, scope)

  defp directory(path) do
    if File.dir?(path), do: :ok, else: {:error, {:not_a_directory, path}}
  end

  # `{lines, count, truncated?}` is threaded through the whole walk, so the entry cap is
  # global rather than per-directory: a tree of a thousand directories with one file each
  # is exactly as bounded as one directory with a thousand files.
  defp walk(directory, max_depth, level, acc) do
    case File.ls(directory) do
      {:ok, entries} ->
        entries
        |> Enum.sort()
        |> Enum.reduce_while(acc, fn entry, {lines, count, truncated?} ->
          if count >= @max_entries do
            {:halt, {lines, count, true}}
          else
            path = Path.join(directory, entry)
            line = render(path, entry, level)

            cond do
              entry in @skipped ->
                {:cont, {[line <> "  (not descended into)" | lines], count + 1, truncated?}}

              File.dir?(path) and not symlink?(path) and level < max_depth ->
                {:cont, walk(path, max_depth, level + 1, {[line | lines], count + 1, truncated?})}

              true ->
                {:cont, {[line | lines], count + 1, truncated?}}
            end
          end
        end)

      {:error, reason} ->
        {lines, count, truncated?} = acc
        line = "  (#{directory} is unreadable: #{:file.format_error(reason)})"
        {[line | lines], count + 1, truncated?}
    end
  end

  # A symlinked directory is listed but not entered: following one is how a bounded walk
  # becomes an unbounded one, and `Paths` already refuses anything the link points at
  # outside the workspace.
  defp symlink?(path) do
    match?({:ok, %File.Stat{type: :symlink}}, File.lstat(path))
  end

  defp render(path, entry, level) do
    indent = String.duplicate("  ", level - 1)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :directory}} -> indent <> entry <> "/"
      {:ok, %File.Stat{type: :regular, size: size}} -> indent <> entry <> "  (#{size} bytes)"
      {:ok, %File.Stat{type: :symlink}} -> indent <> entry <> "  (symlink)"
      {:ok, %File.Stat{type: type}} -> indent <> entry <> "  (#{type})"
      {:error, reason} -> indent <> entry <> "  (#{:file.format_error(reason)})"
    end
  end

  defp present([], _truncated?, path, root, _depth), do: "#{relative(path, root)} is empty."

  defp present(lines, truncated?, path, root, depth) do
    note =
      if truncated?,
        do: "\n(stopped at #{@max_entries} entries — list a subdirectory instead)",
        else: ""

    "#{relative(path, root)} (depth #{depth}):\n" <> Enum.join(lines, "\n") <> note
  end

  defp relative(path, root) do
    case Path.relative_to(path, root) do
      ^path -> path
      "" -> "."
      relative -> relative
    end
  end

  defp describe({:not_a_directory, path}), do: "#{path} is not a directory"
  defp describe(reason), do: Paths.describe_error(reason)
end
