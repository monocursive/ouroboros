defmodule Ouroboros.Provider.Native.Tools.Edit do
  @moduledoc """
  Exact-string replacement with the guards and the recovery path the field learned it
  needs.

  The guards are Claude Code's, because they are the ones with published failure modes
  (R3 §1.2): the file must have been `read` in this session, a file changed since that
  read is refused rather than silently overwritten, and `old_string` must match exactly
  once unless `replace_all` is set.

  The recovery path is Aider's, because exact-match-only is the documented way to
  multiply editing errors ninefold, and Claude Code's own "file has been unexpectedly
  modified" false positives on CRLF and format-on-save are the reason a ladder exists
  at all:

    1. **exact** — a byte-for-byte search, which is also the only tier that can match
       inside a line;
    2. **trailing whitespace** — line-for-line with trailing whitespace ignored, which
       recovers an editor that stripped or added it;
    3. **indentation** — line-for-line with leading whitespace ignored too, re-indenting
       the replacement to the file's own indentation so the result is still correct.

  A tier below `exact` is reported in the tool result. An edit that only matched because
  whitespace was ignored is a fact the operator should be able to see in the transcript.

  When no tier matches, the failure names the closest lines in the file with their line
  numbers, so the next attempt is an informed one rather than a re-roll.
  """

  use Jido.Action,
    name: "edit",
    description:
      "Replace an exact string in a workspace file. Read the file first. `old_string` " <>
        "must appear exactly once unless `replace_all` is true.",
    schema: [
      path: [
        type: :string,
        required: true,
        doc: "Absolute path, or a path relative to the workspace root."
      ],
      old_string: [type: :string, required: true, doc: "The exact text to replace."],
      new_string: [type: :string, required: true, doc: "The replacement text."],
      replace_all: [
        type: :boolean,
        default: false,
        doc: "Replace every occurrence instead of requiring exactly one."
      ]
    ]

  alias Ouroboros.Provider.Native.Diff
  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools.Read

  @similar_lines 3

  @impl true
  def run(params, context) do
    with :ok <- writable(context.scope),
         {:ok, path} <- Paths.resolve(params.path, context.scope),
         {:ok, content} <- read(path),
         :ok <- read_before_edit(path, context),
         :ok <- unchanged_since_read(path, content, context),
         :ok <- distinct(params),
         {:ok, updated, tier, count} <- apply_edit(content, params, path) do
      case File.write(path, updated) do
        :ok ->
          relative = Path.relative_to(path, context.scope.root)
          {:ok, fingerprint} = Read.fingerprint(path)

          {:ok,
           %{
             output: summary(relative, count, tier),
             is_error: false,
             reads: %{path => fingerprint},
             changes: [Diff.change(path, relative, content, updated, :modify)]
           }}

        {:error, reason} ->
          {:ok, %{output: "edit failed: #{path}: #{:file.format_error(reason)}", is_error: true}}
      end
    else
      {:error, reason} -> {:ok, %{output: "edit failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp writable(%{sandbox_mode: :read_only}), do: {:error, :read_only_sandbox}
  defp writable(_scope), do: :ok

  defp read(path) do
    case File.read(path) do
      {:ok, content} -> {:ok, content}
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp distinct(%{old_string: same, new_string: same}), do: {:error, :identical_strings}
  defp distinct(_params), do: :ok

  defp read_before_edit(path, context) do
    if Map.has_key?(context.reads || %{}, path),
      do: :ok,
      else: {:error, {:not_read, path}}
  end

  # mtime, size, and hash together. mtime alone misses a same-second rewrite; size alone
  # misses a same-length change; the hash catches both and costs one read of a file this
  # tool has already read.
  defp unchanged_since_read(path, content, context) do
    case {Map.get(context.reads || %{}, path), File.stat(path, time: :posix)} do
      {%{hash: recorded}, {:ok, stat}} ->
        if Read.fingerprint(stat, content).hash == recorded,
          do: :ok,
          else: {:error, {:modified_since_read, path}}

      {_no_fingerprint, {:ok, _stat}} ->
        {:error, {:not_read, path}}

      {_recorded, {:error, reason}} ->
        {:error, {:unreadable, path, reason}}
    end
  end

  defp apply_edit(content, params, path) do
    case exact(content, params) do
      {:ok, updated, count} ->
        {:ok, updated, :exact, count}

      {:error, {:not_unique, count}} ->
        {:error, {:not_unique, count}}

      {:error, :no_match} ->
        case tolerant(content, params) do
          {:error, :no_match} -> {:error, {:no_match, path, params.old_string}}
          other -> other
        end
    end
  end

  defp exact(content, params) do
    case count_occurrences(content, params.old_string) do
      0 ->
        {:error, :no_match}

      1 ->
        {:ok, String.replace(content, params.old_string, params.new_string), 1}

      count when count > 1 ->
        if params.replace_all,
          do: {:ok, String.replace(content, params.old_string, params.new_string), count},
          else: {:error, {:not_unique, count}}
    end
  end

  defp count_occurrences(_content, ""), do: 0

  defp count_occurrences(content, needle),
    do: length(String.split(content, needle)) - 1

  # Both tolerant tiers work on whole lines: a whitespace-insensitive match inside a
  # line has no well-defined replacement boundary, and guessing one is how an edit tool
  # corrupts a file quietly.
  defp tolerant(content, params) do
    file_lines = String.split(content, "\n")
    needle_lines = String.split(params.old_string, "\n")

    Enum.reduce_while(
      [{:trailing_whitespace, &String.trim_trailing/1}, {:indentation, &String.trim/1}],
      {:error, :no_match},
      fn {tier, normalize}, _acc ->
        case match_windows(file_lines, needle_lines, normalize) do
          [] ->
            {:cont, {:error, :no_match}}

          [_first | _rest] = windows when length(windows) > 1 ->
            if params.replace_all do
              {:halt, replace_windows(file_lines, windows, needle_lines, params, tier)}
            else
              {:halt, {:error, {:not_unique, length(windows)}}}
            end

          windows ->
            {:halt, replace_windows(file_lines, windows, needle_lines, params, tier)}
        end
      end
    )
  end

  defp match_windows(file_lines, needle_lines, normalize) do
    size = length(needle_lines)
    normalized_needle = Enum.map(needle_lines, normalize)

    if size == 0 or size > length(file_lines) do
      []
    else
      0..(length(file_lines) - size)
      |> Enum.filter(fn index ->
        file_lines |> Enum.slice(index, size) |> Enum.map(normalize) == normalized_needle
      end)
      |> collapse_overlaps(size)
    end
  end

  # Two windows that overlap describe the same text twice; replacing both would apply
  # the edit inside its own output.
  defp collapse_overlaps(indexes, size) do
    Enum.reduce(indexes, [], fn index, acc ->
      case acc do
        [previous | _rest] when index - previous < size -> acc
        _disjoint -> [index | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp replace_windows(file_lines, windows, needle_lines, params, tier) do
    size = length(needle_lines)
    replacement_lines = String.split(params.new_string, "\n")

    updated =
      windows
      |> Enum.reverse()
      |> Enum.reduce(file_lines, fn index, lines ->
        replacement =
          case tier do
            :indentation ->
              reindent(replacement_lines, Enum.at(lines, index), List.first(needle_lines))

            _same_indentation ->
              replacement_lines
          end

        Enum.slice(lines, 0, index) ++ replacement ++ Enum.drop(lines, index + size)
      end)

    {:ok, Enum.join(updated, "\n"), tier, length(windows)}
  end

  # The needle was matched with its indentation ignored, so the replacement has to be
  # re-hung on the indentation the file actually uses, or the edit compiles to garbage.
  defp reindent(lines, file_line, needle_line) do
    file_indent = indent_of(file_line)
    needle_indent = indent_of(needle_line)

    Enum.map(lines, fn line ->
      stripped =
        if needle_indent != "" and String.starts_with?(line, needle_indent),
          do: binary_part(line, byte_size(needle_indent), byte_size(line) - byte_size(needle_indent)),
          else: line

      if String.trim(stripped) == "", do: stripped, else: file_indent <> stripped
    end)
  end

  defp indent_of(nil), do: ""

  defp indent_of(line) do
    case Regex.run(~r/\A[ \t]*/, line) do
      [indent] -> indent
      _none -> ""
    end
  end

  defp summary(relative, count, :exact),
    do: "Edited #{relative} (#{count} #{plural(count)})."

  defp summary(relative, count, tier),
    do:
      "Edited #{relative} (#{count} #{plural(count)}) — matched with #{tier(tier)} ignored, " <>
        "not byte-for-byte."

  defp tier(:trailing_whitespace), do: "trailing whitespace"
  defp tier(:indentation), do: "indentation"

  defp plural(1), do: "replacement"
  defp plural(_count), do: "replacements"

  defp describe(:read_only_sandbox),
    do: "this session runs with sandbox_mode: read_only, which refuses every edit"

  defp describe(:identical_strings), do: "old_string and new_string are identical"

  defp describe({:not_read, path}),
    do: "#{path} has not been read in this session. Call `read` on it first."

  defp describe({:modified_since_read, path}),
    do:
      "#{path} changed since it was read. Read it again, then re-issue the edit against " <>
        "the current content."

  defp describe({:not_unique, count}),
    do:
      "old_string appears #{count} times. Add surrounding lines until it is unique, or " <>
        "set replace_all: true."

  defp describe({:no_match, path, old_string}), do: no_match_message(path, old_string)
  defp describe({:unreadable, path, reason}), do: "#{path}: #{:file.format_error(reason)}"
  defp describe(reason), do: Paths.describe_error(reason)

  @doc """
  The failure a model can act on: the closest lines in the file, with their numbers.

  Aider's `find_similar_lines`. A bare "no match" invites the same call again; naming
  the line the file actually has turns the retry into a correction.
  """
  @spec no_match_message(String.t(), String.t()) :: String.t()
  def no_match_message(path, old_string) do
    anchor =
      old_string
      |> String.split("\n")
      |> Enum.find("", &(String.trim(&1) != ""))

    similar =
      case File.read(path) do
        {:ok, content} -> similar_lines(content, anchor)
        {:error, _reason} -> []
      end

    base =
      "old_string was not found in #{path}, in any whitespace tier."

    case similar do
      [] -> base
      lines -> base <> "\nClosest lines in the file:\n" <> Enum.join(lines, "\n")
    end
  end

  defp similar_lines(_content, ""), do: []

  defp similar_lines(content, anchor) do
    target = String.trim(anchor)

    content
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.map(fn {line, number} -> {String.jaro_distance(String.trim(line), target), number, line} end)
    |> Enum.filter(fn {score, _number, _line} -> score > 0.7 end)
    |> Enum.sort_by(fn {score, _number, _line} -> -score end)
    |> Enum.take(@similar_lines)
    |> Enum.map(fn {_score, number, line} -> "  #{number}: #{line}" end)
  end
end
