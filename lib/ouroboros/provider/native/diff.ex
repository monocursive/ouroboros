defmodule Ouroboros.Provider.Native.Diff do
  @moduledoc """
  A real unified diff for every `file_change` this provider emits.

  The TUI already renders unified diffs for Codex; emitting anything else would mean a
  native edit renders worse than a vendor's for no reason. `@@` hunk headers, three
  lines of context, `---`/`+++` headers with the workspace-relative path — the format
  `git diff` produces and every reviewer can read.

  The line difference is `List.myers_difference/2`, so a two-line change inside a large
  file produces two small hunks rather than a whole-file replacement. Content that is
  not valid UTF-8 is not diffed; it gets git's one-line binary summary, because a byte
  diff on the wire is neither reviewable nor bounded.
  """

  @context 3
  # A diff crosses the wire on every replay (§3.3 F7), so one change is bounded here
  # rather than at the client, and the truncation says so inside the diff.
  @max_bytes 128 * 1024
  # `List.myers_difference/2` is O(N × D): two thousand-line files that share almost
  # nothing take seconds, and two forty-thousand-line ones never finish. A generated
  # file rewritten whole is exactly that shape, so size is checked *before* the diff is
  # attempted rather than after it has already blocked the loop.
  @max_diff_lines 4_000
  @max_diff_bytes 1_000_000

  @doc """
  Renders a unified diff between two file contents.

  `kind` is `:add`, `:modify`, or `:delete` and decides only the `---`/`+++` headers.
  """
  @spec unified(String.t(), String.t() | nil, String.t() | nil, atom()) :: String.t()
  def unified(path, before_content, after_content, kind) do
    cond do
      binary_content?(before_content) or binary_content?(after_content) ->
        "Binary files #{old_label(path, kind)} and #{new_label(path, kind)} differ\n"

      before_content == after_content ->
        ""

      too_large?(before_content, after_content) ->
        summary(path, before_content, after_content, kind)

      true ->
        header = "--- #{old_label(path, kind)}\n+++ #{new_label(path, kind)}\n"
        body = before_content |> ops(after_content) |> hunks() |> Enum.map_join("", &render/1)
        truncate(header <> body)
    end
  end

  @doc "The `changes` entry a `file_change` event carries for one path."
  @spec change(String.t(), String.t(), String.t() | nil, String.t() | nil, atom()) :: map()
  def change(path, relative, before_content, after_content, kind) do
    {added, removed} = counts(before_content, after_content)

    %{
      "path" => path,
      "relative_path" => relative,
      "kind" => Atom.to_string(kind),
      "diff" => unified(relative, before_content, after_content, kind),
      "added_lines" => added,
      "removed_lines" => removed
    }
  end

  defp counts(before_content, after_content) do
    cond do
      binary_content?(before_content) or binary_content?(after_content) ->
        {0, 0}

      too_large?(before_content, after_content) ->
        {length(lines(after_content)), length(lines(before_content))}

      true ->
        script = ops(before_content, after_content)

        {Enum.count(script, &(elem(&1, 0) == :ins)), Enum.count(script, &(elem(&1, 0) == :del))}
    end
  end

  defp too_large?(before_content, after_content) do
    byte_size(before_content || "") > @max_diff_bytes or
      byte_size(after_content || "") > @max_diff_bytes or
      length(lines(before_content)) > @max_diff_lines or
      length(lines(after_content)) > @max_diff_lines
  end

  # Naming the shape of a change this runtime declined to compute is honest; a partial
  # diff of a file this size would be neither reviewable nor correct.
  defp summary(path, before_content, after_content, kind) do
    old_count = length(lines(before_content))
    new_count = length(lines(after_content))

    "--- #{old_label(path, kind)}\n+++ #{new_label(path, kind)}\n" <>
      "@@ file too large to diff inline @@\n" <>
      "-#{old_count} lines\n+#{new_count} lines\n" <>
      "(over #{@max_diff_lines} lines or #{@max_diff_bytes} bytes; read the file to review it)\n"
  end

  # A flat operation list with the line number each side stood at, which is everything
  # both the hunk grouping and the `@@` header need.
  defp ops(before_content, after_content) do
    before_content
    |> lines()
    |> List.myers_difference(lines(after_content))
    |> Enum.flat_map(fn {tag, values} -> Enum.map(values, &{tag, &1}) end)
    |> Enum.map_reduce({1, 1}, fn {tag, line}, {old_no, new_no} ->
      {{tag, line, old_no, new_no},
       {if(tag in [:eq, :del], do: old_no + 1, else: old_no),
        if(tag in [:eq, :ins], do: new_no + 1, else: new_no)}}
    end)
    |> elem(0)
  end

  # Changed lines within 2 * @context of each other share a hunk; anything further
  # apart starts a new one. That is the rule `diff -U3` follows.
  defp hunks(script) do
    changed =
      script
      |> Enum.with_index()
      |> Enum.filter(fn {{tag, _line, _old, _new}, _index} -> tag != :eq end)
      |> Enum.map(&elem(&1, 1))

    changed
    |> cluster()
    |> Enum.map(fn {first, last} ->
      start = max(first - @context, 0)
      stop = min(last + @context, length(script) - 1)
      Enum.slice(script, start..stop)
    end)
  end

  defp cluster([]), do: []

  defp cluster([first | rest]) do
    rest
    |> Enum.reduce([{first, first}], fn index, [{open, close} | done] ->
      if index - close <= 2 * @context + 1,
        do: [{open, index} | done],
        else: [{index, index}, {open, close} | done]
    end)
    |> Enum.reverse()
  end

  defp render([]), do: ""

  defp render([{_tag, _line, old_start, new_start} | _rest] = hunk) do
    old_count = Enum.count(hunk, fn {tag, _line, _old, _new} -> tag in [:eq, :del] end)
    new_count = Enum.count(hunk, fn {tag, _line, _old, _new} -> tag in [:eq, :ins] end)

    "@@ -#{start_of(old_start, old_count)},#{old_count} " <>
      "+#{start_of(new_start, new_count)},#{new_count} @@\n" <>
      Enum.map_join(hunk, "", &render_line/1)
  end

  # An empty side is written as the position *before* which the change happens, which
  # is what `git diff` emits for a pure insertion or a pure deletion.
  defp start_of(line_no, 0), do: max(line_no - 1, 0)
  defp start_of(line_no, _count), do: line_no

  defp render_line({:eq, line, _old, _new}), do: " " <> line <> "\n"
  defp render_line({:del, line, _old, _new}), do: "-" <> line <> "\n"
  defp render_line({:ins, line, _old, _new}), do: "+" <> line <> "\n"

  defp binary_content?(nil), do: false
  defp binary_content?(content) when is_binary(content), do: not String.valid?(content)
  defp binary_content?(_content), do: false

  defp lines(nil), do: []
  defp lines(""), do: []

  # "a\nb\n" is two lines, not three; "a\nb" is also two. The diff must not invent a
  # trailing blank for the first or lose the last line of the second.
  defp lines(content) do
    parts = String.split(content, "\n")

    case Enum.reverse(parts) do
      ["" | rest] -> Enum.reverse(rest)
      _no_trailing_newline -> parts
    end
  end

  defp old_label(_path, :add), do: "/dev/null"
  defp old_label(path, _kind), do: "a/#{path}"

  defp new_label(_path, :delete), do: "/dev/null"
  defp new_label(path, _kind), do: "b/#{path}"

  defp truncate(diff) when byte_size(diff) <= @max_bytes, do: diff

  defp truncate(diff) do
    binary_part(diff, 0, @max_bytes) <> "\n… diff truncated at #{@max_bytes} bytes\n"
  end
end
