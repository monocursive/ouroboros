defmodule Ouroboros.Provider.Session.Diff do
  @moduledoc """
  One unified diff renderer, for every `file_change` a session transport emits.

  Two callers need the same bytes and must not drift: `Dialect.ACP`, which turns an
  agent's own `diff` content block into a `file_change`, and
  `Ouroboros.Provider.Session.Service`, which turns a write *this runtime performed on
  the agent's behalf* into one. A client reads the path and the +/− counts out of the
  text, so both have to produce a real diff with `--- a/<path>` / `+++ b/<path>` headers
  rather than a summary.

  Line-wise, via the stdlib. A trailing newline is normalised away and no
  `\\ No newline at end of file` marker is emitted: the diff is for reading, not for
  feeding back to `patch`.

  Either side above `#{1_048_576}` bytes and the body is replaced by a note. `oldText`
  and `newText` are whole file bodies; a line-wise diff of two 50 MB buffers is not a
  thing to compute inside a session process, let alone to broadcast.
  """

  @max_diff_bytes 1_048_576
  @context 3

  @doc "The byte ceiling either side of one edit may reach before the body becomes a note."
  @spec max_bytes() :: pos_integer()
  def max_bytes, do: @max_diff_bytes

  @doc "ACP spells a new file as a null `oldText` and a removed one as a null `newText`."
  @spec kind(term(), term()) :: String.t()
  def kind(nil, _new), do: "add"
  def kind(_old, nil), do: "delete"
  def kind(_old, _new), do: "update"

  @doc """
  One file's change, in the item-level shape the client already parses.

  `old` and `new` may be `nil`; `kind/2` reads the nils before they are flattened, so an
  add and a delete stay distinguishable after the bodies become strings.
  """
  @spec change(String.t(), term(), term()) :: map()
  def change(path, old, new) when is_binary(path) do
    %{
      "path" => path,
      "kind" => kind(old, new),
      "diff" => unified(path, text_or_empty(old), text_or_empty(new))
    }
  end

  @doc "The unified diff of two whole file bodies, headers included."
  @spec unified(String.t(), String.t(), String.t()) :: String.t()
  def unified(path, old, new) when is_binary(old) and is_binary(new) do
    header = "--- a/#{path}\n+++ b/#{path}\n"

    if byte_size(old) > @max_diff_bytes or byte_size(new) > @max_diff_bytes do
      header <> "@@ truncated: #{byte_size(old) + byte_size(new)} bytes @@\n"
    else
      header <> hunks(lines(old), lines(new))
    end
  end

  defp text_or_empty(text) when is_binary(text), do: text
  defp text_or_empty(_other), do: ""

  defp lines(""), do: []

  defp lines(text) do
    split = String.split(text, "\n")
    if List.last(split) == "", do: Enum.drop(split, -1), else: split
  end

  defp hunks(old_lines, new_lines) do
    rows =
      old_lines
      |> List.myers_difference(new_lines)
      |> numbered_rows()

    rows
    |> hunk_ranges()
    |> Enum.map_join(fn {from, to} -> render_hunk(Enum.slice(rows, from..to//1)) end)
  end

  defp numbered_rows(operations) do
    {rows, _old_line, _new_line} =
      Enum.reduce(operations, {[], 1, 1}, fn {tag, lines}, accumulator ->
        Enum.reduce(lines, accumulator, fn line, {rows, old_line, new_line} ->
          case tag do
            :eq -> {[{:eq, line, old_line, new_line} | rows], old_line + 1, new_line + 1}
            :del -> {[{:del, line, old_line, new_line} | rows], old_line + 1, new_line}
            :ins -> {[{:ins, line, old_line, new_line} | rows], old_line, new_line + 1}
          end
        end)
      end)

    Enum.reverse(rows)
  end

  defp hunk_ranges(rows) do
    total = length(rows)

    rows
    |> Enum.with_index()
    |> Enum.filter(fn {{tag, _line, _old, _new}, _index} -> tag != :eq end)
    |> Enum.map(fn {_row, index} ->
      {max(index - @context, 0), min(index + @context, total - 1)}
    end)
    |> Enum.reduce([], fn
      {from, to}, [{previous_from, previous_to} | rest] when from <= previous_to + 1 ->
        [{previous_from, max(previous_to, to)} | rest]

      range, ranges ->
        [range | ranges]
    end)
    |> Enum.reverse()
  end

  defp render_hunk(rows) do
    old_rows = Enum.filter(rows, fn {tag, _line, _old, _new} -> tag in [:eq, :del] end)
    new_rows = Enum.filter(rows, fn {tag, _line, _old, _new} -> tag in [:eq, :ins] end)

    header =
      "@@ -#{hunk_start(old_rows, :old)},#{length(old_rows)} " <>
        "+#{hunk_start(new_rows, :new)},#{length(new_rows)} @@\n"

    header <> Enum.map_join(rows, fn {tag, line, _old, _new} -> marker(tag) <> line <> "\n" end)
  end

  defp hunk_start([], _side), do: 0
  defp hunk_start([{_tag, _line, old, _new} | _rest], :old), do: old
  defp hunk_start([{_tag, _line, _old, new} | _rest], :new), do: new

  defp marker(:eq), do: " "
  defp marker(:del), do: "-"
  defp marker(:ins), do: "+"
end
