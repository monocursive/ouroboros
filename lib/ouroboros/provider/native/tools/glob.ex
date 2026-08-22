defmodule Ouroboros.Provider.Native.Tools.Glob do
  @moduledoc """
  Find files by name pattern, newest first.

  `Path.wildcard/2` with `match_dot: true`, rooted at the workspace and then filtered
  back through `Ouroboros.Provider.Native.Paths` — the wildcard expander does not know
  about symlinks or containment, so every path it produces is judged again before it is
  reported. A pattern that would reach outside the workspace therefore returns fewer
  results rather than more, which is the direction a boundary check should fail.

  Sorted by modification time, newest first, because in a repository the file somebody
  is working on is the one they are asking about. Bounded at #{2_000} results with the
  count of what was dropped, which is the number Claude Code uses for the same tool.
  """

  use Jido.Action,
    name: "glob",
    description:
      "List workspace files matching a glob pattern such as `**/*.ex` or `lib/**/*_test.exs`, " <>
        "most-recently-modified first. Bounded to 2000 results.",
    schema: [
      pattern: [
        type: :string,
        required: true,
        doc: "A glob pattern, relative to `path` or to the workspace root."
      ],
      path: [
        type: :string,
        default: "",
        doc: "Directory to search from. Defaults to the workspace root."
      ]
    ]

  alias Ouroboros.Provider.Native.Paths

  @max_results 2_000
  # `**` over a large tree with the pattern anchored at the root is the one shape that
  # can take seconds; the expander is given a bounded number of candidates to consider
  # before the containment filter runs.
  @max_candidates 20_000

  @impl true
  def run(params, context) do
    with {:ok, root} <- target(params.path, context.scope),
         :ok <- usable(params.pattern) do
      matches =
        root
        |> Path.join(params.pattern)
        |> Path.wildcard(match_dot: true)
        |> Enum.take(@max_candidates)
        |> Enum.filter(&File.regular?/1)
        |> contained(context.scope)
        |> Enum.sort_by(&mtime/1, :desc)

      {:ok, present(matches, context.scope.root)}
    else
      {:error, reason} -> {:ok, %{output: "glob failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp target("", scope), do: {:ok, scope.root}
  defp target(path, scope), do: Paths.resolve(path, scope)

  # A `..` in the pattern is refused for the same reason `Paths.resolve/2` refuses one in
  # a path: for a pattern that does not resolve to an existing file there is no defined
  # meaning, and two rules about traversal is how a containment check grows a hole.
  defp usable(pattern) do
    cond do
      String.trim(pattern) == "" -> {:error, :empty_pattern}
      ".." in Path.split(pattern) -> {:error, {:path_traversal, pattern}}
      Path.type(pattern) == :absolute -> {:error, {:absolute_pattern, pattern}}
      true -> :ok
    end
  end

  defp contained(paths, scope) do
    Enum.filter(paths, fn path ->
      case Paths.resolve(path, scope) do
        {:ok, _canonical} -> true
        {:error, _refused} -> false
      end
    end)
  end

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      _gone -> 0
    end
  end

  defp present([], _root), do: %{output: "No files matched.", is_error: false}

  defp present(matches, root) do
    kept = Enum.take(matches, @max_results)
    dropped = length(matches) - length(kept)

    note =
      if dropped > 0,
        do: "\n(#{dropped} more matched and were not listed — narrow the pattern)",
        else: ""

    body = Enum.map_join(kept, "\n", &Path.relative_to(&1, root))

    %{output: "#{length(kept)} files:\n" <> body <> note, is_error: false}
  end

  defp describe(:empty_pattern), do: "the pattern is empty"

  defp describe({:absolute_pattern, pattern}),
    do: "#{pattern} is absolute. Give a pattern relative to the workspace or to `path`."

  defp describe(reason), do: Paths.describe_error(reason)
end
