defmodule Ouroboros.Provider.Native.Tools.Grep do
  @moduledoc """
  Search the workspace for a pattern — ripgrep when this host has it, an Elixir walk
  when it does not.

  Every leader's search tool is ripgrep (R3 §1.1), and for a reason: it honours
  `.gitignore`, skips binaries, and is an order of magnitude faster than walking a tree
  from the BEAM. It is also not guaranteed to be installed, and a tool that simply
  disappears on a host without it would make the agent's behaviour depend on the
  operator's toolbox. So there are two engines behind one schema, the result says which
  one answered, and the fallback applies the same bounds.

  The pattern goes to ripgrep as an argv element, never through a shell, so a regular
  expression full of quotes and semicolons is a regular expression and not a command.
  The Elixir fallback compiles the same pattern with `:re`, which is the same PCRE
  engine ripgrep's syntax mostly targets — "mostly" is stated in the result rather than
  smoothed over, because a pattern that means two things on two hosts is exactly the
  kind of silent difference this runtime refuses to ship.

  Bounded three ways, because a search is the cheapest way to fill a context window:
  #{200} matches total, 300 bytes of any one line, and a deadline. Beyond any of them
  the result says what it dropped.
  """

  use Jido.Action,
    name: "grep",
    description:
      "Search file contents for a regular expression, in the workspace. Returns " <>
        "matching lines with their paths and line numbers, newest-modified files " <>
        "first. Bounded to 200 matches. Use this for text; use `code_intel` for " <>
        "references, definitions, and renames.",
    schema: [
      pattern: [type: :string, required: true, doc: "The regular expression to search for."],
      path: [
        type: :string,
        default: "",
        doc: "File or directory to search. Defaults to the workspace root."
      ],
      glob: [
        type: :string,
        default: "",
        doc: "Only search files whose name matches this glob, for example `*.ex`."
      ],
      case_insensitive: [
        type: :boolean,
        default: false,
        doc: "Ignore case, like ripgrep's `-i`."
      ],
      line_numbers: [
        type: :boolean,
        default: true,
        doc: "Prefix each match with its line number, like ripgrep's `-n`."
      ]
    ]

  alias Ouroboros.Provider.Native.Exec
  alias Ouroboros.Provider.Native.Paths

  @max_matches 200
  @max_line_bytes 300
  @timeout_ms 20_000
  # A walked file larger than this is skipped by the fallback. ripgrep has its own
  # heuristics; the fallback's are stated so the two engines' silence has a reason.
  @max_file_bytes 2 * 1024 * 1024
  @max_files_walked 20_000

  @impl true
  def run(params, context) do
    with {:ok, root} <- target(params.path, context.scope),
         {:ok, regex} <- compile(params) do
      case engine() do
        {:ripgrep, executable} -> ripgrep(executable, params, root, context)
        :fallback -> fallback(regex, params, root, context)
      end
    else
      {:error, reason} -> {:ok, %{output: "grep failed: #{describe(reason)}", is_error: true}}
    end
  end

  @doc """
  Which engine will answer on this host.

  `config :ouroboros, :native_grep_engine, :fallback` forces the built-in walker even
  where ripgrep is installed. It exists because "the two engines answer the same
  question" is a claim this runtime makes in the tool's own output, and a claim nobody
  can exercise on a host that has ripgrep is a claim nobody checks.
  """
  @spec engine() :: {:ripgrep, String.t()} | :fallback
  def engine do
    case Application.get_env(:ouroboros, :native_grep_engine, :auto) do
      :fallback ->
        :fallback

      _auto ->
        case Exec.which("rg") do
          path when is_binary(path) -> {:ripgrep, path}
          nil -> :fallback
        end
    end
  end

  # ---------------------------------------------------------------- ripgrep

  defp ripgrep(executable, params, root, context) do
    args =
      ["--no-heading", "--color", "never", "--with-filename", "--max-count", "200"]
      |> then(&if params.line_numbers, do: &1 ++ ["--line-number"], else: &1)
      |> then(&if params.case_insensitive, do: &1 ++ ["--ignore-case"], else: &1)
      |> then(&if params.glob == "", do: &1, else: &1 ++ ["--glob", params.glob])
      |> Kernel.++(["--max-columns", Integer.to_string(@max_line_bytes)])
      |> Kernel.++(["--regexp", params.pattern, "--", root])

    case Exec.run(executable, args,
           cd: context.scope.root,
           timeout_ms: @timeout_ms,
           max_bytes: 4 * 1024 * 1024
         ) do
      {:ok, %{timed_out?: true}} ->
        {:ok,
         %{
           output: "grep timed out after #{@timeout_ms} ms. Narrow `path` or `glob`.",
           is_error: true
         }}

      # ripgrep exits 1 for "no matches", which is not an error for this tool.
      {:ok, %{status: status, output: output}} when status in [0, 1] ->
        {:ok, present(parse_ripgrep(output, context.scope.root), "ripgrep")}

      {:ok, %{status: status, output: output}} ->
        {:ok,
         %{
           output: "grep failed: ripgrep exited #{status}: #{String.slice(output, 0, 500)}",
           is_error: true
         }}

      {:error, reason} ->
        {:ok, %{output: "grep failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp parse_ripgrep(output, root) do
    output
    |> String.split("\n", trim: true)
    |> Enum.take(@max_matches + 1)
    |> Enum.flat_map(&parse_line(&1, root))
  end

  # `path:line:text` when line numbers are on, `path:text` when they are off. A path
  # containing a colon is why the split is bounded rather than greedy: the first field
  # is the path ripgrep printed, and it printed it relative to the directory we gave it.
  defp parse_line(line, root) do
    case String.split(line, ":", parts: 3) do
      [path, number, text] ->
        case Integer.parse(number) do
          {parsed, ""} -> [{relative(path, root), parsed, clip(text)}]
          _not_a_number -> [{relative(path, root), nil, clip(number <> ":" <> text)}]
        end

      [path, text] ->
        [{relative(path, root), nil, clip(text)}]

      _unparsable ->
        []
    end
  end

  # ---------------------------------------------------------------- fallback

  defp fallback(regex, params, root, context) do
    files =
      root
      |> walk(params.glob)
      |> Enum.take(@max_files_walked)

    matches =
      Enum.reduce_while(files, [], fn file, acc ->
        if length(acc) > @max_matches do
          {:halt, acc}
        else
          {:cont, acc ++ search_file(file, regex, params, context.scope.root)}
        end
      end)

    {:ok, present(matches, "the built-in walker (ripgrep is not on PATH)")}
  end

  defp search_file(path, regex, params, root) do
    with {:ok, %File.Stat{size: size}} when size <= @max_file_bytes <- File.stat(path),
         {:ok, content} <- File.read(path),
         true <- String.valid?(content) do
      content
      |> String.split("\n")
      |> Enum.with_index(1)
      |> Enum.filter(fn {line, _number} -> Regex.match?(regex, line) end)
      |> Enum.take(@max_matches)
      |> Enum.map(fn {line, number} ->
        {relative(path, root), if(params.line_numbers, do: number, else: nil), clip(line)}
      end)
    else
      _skipped -> []
    end
  end

  # Newest first, which is the ordering `glob` uses and the one that puts the file
  # somebody is working on at the top of the list.
  defp walk(root, glob) do
    if File.regular?(root) do
      if matches_glob?(root, glob), do: [root], else: []
    else
      root
      |> descend(0)
      |> Enum.filter(&matches_glob?(&1, glob))
      |> Enum.sort_by(&mtime/1, :desc)
    end
  end

  defp descend(_directory, depth) when depth > 20, do: []

  defp descend(directory, depth) do
    case File.ls(directory) do
      {:ok, entries} ->
        Enum.flat_map(entries, fn entry ->
          path = Path.join(directory, entry)

          cond do
            skip?(entry) -> []
            File.dir?(path) -> descend(path, depth + 1)
            File.regular?(path) -> [path]
            true -> []
          end
        end)

      {:error, _reason} ->
        []
    end
  end

  # Not a `.gitignore` reader — that is ripgrep's job and imitating it badly would be
  # worse than naming the four directories that are noise in every repository.
  defp skip?(entry),
    do: entry in [".git", "_build", "node_modules", "deps", ".elixir_ls", "target"]

  defp matches_glob?(_path, ""), do: true
  defp matches_glob?(path, glob), do: path |> Path.basename() |> match_pattern?(glob)

  defp match_pattern?(name, glob) do
    pattern =
      glob
      |> Regex.escape()
      |> String.replace("\\*", ".*")
      |> String.replace("\\?", ".")

    case Regex.compile("\\A" <> pattern <> "\\z") do
      {:ok, regex} -> Regex.match?(regex, name)
      {:error, _reason} -> false
    end
  end

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      _gone -> 0
    end
  end

  # ---------------------------------------------------------------- shared

  defp compile(params) do
    options = if params.case_insensitive, do: [:caseless], else: []

    case Regex.compile(params.pattern, options) do
      {:ok, regex} -> {:ok, regex}
      {:error, reason} -> {:error, {:bad_pattern, params.pattern, reason}}
    end
  end

  defp target("", scope), do: {:ok, scope.root}
  defp target(path, scope), do: Paths.resolve(path, scope)

  defp present([], engine),
    do: %{output: "No matches. (searched with #{engine})", is_error: false}

  defp present(matches, engine) do
    kept = Enum.take(matches, @max_matches)
    dropped = length(matches) - length(kept)

    body =
      Enum.map_join(kept, "\n", fn
        {path, nil, text} -> "#{path}: #{text}"
        {path, number, text} -> "#{path}:#{number}: #{text}"
      end)

    note =
      if dropped > 0 or length(matches) > @max_matches,
        do: "\n(stopped at #{@max_matches} matches — narrow the pattern, path, or glob)",
        else: ""

    %{
      output: "#{length(kept)} matches (#{engine}):\n" <> body <> note,
      is_error: false
    }
  end

  defp relative(path, root) do
    if Path.type(path) == :absolute, do: Path.relative_to(path, root), else: path
  end

  defp clip(text) when byte_size(text) <= @max_line_bytes, do: text

  defp clip(text),
    do: binary_part(text, 0, @max_line_bytes) <> " … (line truncated)"

  defp describe({:bad_pattern, pattern, reason}),
    do: "`#{pattern}` is not a usable regular expression: #{inspect(reason)}"

  defp describe({:spawn_failed, message}), do: message

  defp describe({:wrapper_unavailable, failure}),
    do: "the priv/provider-exec umask wrapper is unusable: #{inspect(failure)}"

  defp describe(reason), do: Paths.describe_error(reason)
end
