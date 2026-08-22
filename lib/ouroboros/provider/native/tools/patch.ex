defmodule Ouroboros.Provider.Native.Tools.Patch do
  @moduledoc """
  The V4A patch format, parsed strictly and applied by context.

  V4A is Codex's edit format and, after `str_replace`, the most widely implemented one:
  Codex, OpenCode, Cline and Factory all take it (R3 §1.1). Its shape is a envelope of
  file sections, and its distinguishing property is that **it carries no line numbers** —
  a hunk is located by the text around it, which is what makes a patch survive a file
  that moved by four lines since the model read it.

      *** Begin Patch
      *** Add File: lib/new.ex
      +defmodule New do
      +end
      *** Update File: lib/old.ex
      *** Move to: lib/renamed.ex
      @@ defmodule Old do
         def value, do: 1
      -  def other, do: 2
      +  def other, do: 3
      *** End of File
      *** Delete File: lib/gone.ex
      *** End Patch

  `@@` optionally names the enclosing scope; several may stack to disambiguate a nested
  one. Body lines are prefixed with a space (context), `-` (removed) or `+` (added).
  `*** End of File` says the hunk runs to the end of the file.

  ## Strict about structure, tolerant about whitespace

  Parsing refuses anything it does not recognise: a missing envelope, an unknown `***`
  directive, a body line with no prefix, a hunk before any file section, a file section
  with no hunks, a duplicate path. A patch that half-parses is a patch that half-applies,
  and half-applying across several files is the failure this format exists to avoid.

  Application is the other way round, for the reason Aider published: exact-match-only
  multiplies editing errors ninefold. Each hunk is located with the same ladder
  `Ouroboros.Provider.Native.Tools.Edit` uses — exact lines, then trailing whitespace
  ignored, then indentation ignored with the replacement re-hung on the file's own
  indentation — and the tier that matched is reported. Hunks are located in order, each
  after the last, so two identical bodies in one file resolve to the two places they
  appear rather than twice to the first.

  Everything here is pure: no filesystem, no clock, no process. The corpus in
  `test/provider/native/apply_patch_test.exs` is the whole specification.
  """

  defmodule Hunk do
    @moduledoc "One `@@` section: its scope markers, its body, and whether it runs to EOF."
    defstruct markers: [], lines: [], eof?: false

    @type line :: {:context | :remove | :add, String.t()}
    @type t :: %__MODULE__{markers: [String.t()], lines: [line()], eof?: boolean()}
  end

  defmodule FileOp do
    @moduledoc "One file section of a patch."
    defstruct [:kind, :path, move_to: nil, content: nil, hunks: []]

    @type t :: %__MODULE__{
            kind: :add | :delete | :update,
            path: String.t(),
            move_to: String.t() | nil,
            content: String.t() | nil,
            hunks: [Hunk.t()]
          }
  end

  @begin "*** Begin Patch"
  @end_patch "*** End Patch"
  @end_of_file "*** End of File"
  @max_bytes 2 * 1024 * 1024
  @max_files 50

  @doc """
  Parses a V4A patch into its file sections.

  Every refusal names what was wrong and, where the position is knowable, the line it
  was on — a parser that answers `:invalid` teaches a model nothing.
  """
  @spec parse(term()) :: {:ok, [FileOp.t()]} | {:error, term()}
  def parse(text) when is_binary(text) and byte_size(text) <= @max_bytes do
    lines = text |> String.trim_trailing("\n") |> String.split("\n")

    with {:ok, body} <- envelope(lines),
         {:ok, files} <- sections(body, 2, [], nil),
         :ok <- distinct(files) do
      {:ok, files}
    end
  end

  def parse(text) when is_binary(text), do: {:error, {:patch_too_large, byte_size(text)}}
  def parse(other), do: {:error, {:not_a_patch, inspect(other)}}

  @doc "Every path a patch touches, in order, including move targets."
  @spec paths([FileOp.t()]) :: [String.t()]
  def paths(files) do
    Enum.flat_map(files, fn
      %FileOp{path: path, move_to: nil} -> [path]
      %FileOp{path: path, move_to: target} -> [path, target]
    end)
  end

  # ---------------------------------------------------------------- parsing

  defp envelope([first | rest]) do
    cond do
      String.trim_trailing(first) != @begin ->
        {:error, {:missing_begin, @begin}}

      rest == [] ->
        {:error, {:missing_end, @end_patch}}

      true ->
        case List.last(rest) |> String.trim_trailing() do
          @end_patch -> {:ok, Enum.drop(rest, -1)}
          _other -> {:error, {:missing_end, @end_patch}}
        end
    end
  end

  defp envelope([]), do: {:error, {:missing_begin, @begin}}

  defp sections([], _number, acc, current) do
    case close(current) do
      {:ok, nil} -> {:ok, Enum.reverse(acc)}
      {:ok, file} -> {:ok, Enum.reverse([file | acc])}
      {:error, _reason} = error -> error
    end
  end

  defp sections([line | rest], number, acc, current) do
    trimmed = String.trim_trailing(line)

    cond do
      directive?(trimmed, "*** Add File: ") ->
        start_section(:add, trimmed, "*** Add File: ", rest, number, acc, current)

      directive?(trimmed, "*** Delete File: ") ->
        start_section(:delete, trimmed, "*** Delete File: ", rest, number, acc, current)

      directive?(trimmed, "*** Update File: ") ->
        start_section(:update, trimmed, "*** Update File: ", rest, number, acc, current)

      trimmed == @end_of_file ->
        with {:ok, current} <- mark_eof(current, number),
             do: sections(rest, number + 1, acc, current)

      # `*** Move to:` is the one directive that belongs *inside* a section rather than
      # opening one, so it is matched here — before the catch-all below, which would
      # otherwise refuse it as unknown.
      directive?(trimmed, "*** Move to: ") ->
        with {:ok, current} <- move_to(current, trimmed, number),
             do: sections(rest, number + 1, acc, current)

      String.starts_with?(trimmed, "***") ->
        {:error, {:unknown_directive, number, trimmed}}

      current == nil ->
        {:error, {:content_before_any_file, number, line}}

      true ->
        with {:ok, current} <- body_line(current, line, number),
             do: sections(rest, number + 1, acc, current)
    end
  end

  defp directive?(line, prefix), do: String.starts_with?(line, prefix)

  defp start_section(kind, line, prefix, rest, number, acc, current) do
    path = line |> binary_part(byte_size(prefix), byte_size(line) - byte_size(prefix)) |> clean()

    cond do
      path == "" ->
        {:error, {:missing_path, number, line}}

      length(acc) >= @max_files ->
        {:error, {:too_many_files, @max_files}}

      true ->
        with {:ok, closed} <- close(current) do
          acc = if closed, do: [closed | acc], else: acc
          fresh = %FileOp{kind: kind, path: path, content: nil, hunks: []}

          case kind do
            :delete -> sections(rest, number + 1, acc, fresh)
            :add -> sections(rest, number + 1, acc, %{fresh | content: []})
            :update -> sections(rest, number + 1, acc, fresh)
          end
        end
    end
  end

  defp body_line(%FileOp{kind: :update} = file, line, number) do
    trimmed = String.trim_trailing(line)

    cond do
      String.starts_with?(trimmed, "@@") ->
        marker = trimmed |> binary_part(2, byte_size(trimmed) - 2) |> String.trim()
        {:ok, open_hunk(file, marker)}

      file.hunks == [] ->
        {:error, {:content_before_any_hunk, number, line}}

      true ->
        with {:ok, classified} <- classify(line, number),
             do: {:ok, push(file, classified)}
    end
  end

  defp body_line(%FileOp{kind: :add, content: content} = file, line, number) do
    case line do
      "+" <> rest -> {:ok, %{file | content: [rest | content]}}
      "" -> {:ok, %{file | content: ["" | content]}}
      other -> {:error, {:add_line_without_plus, number, other}}
    end
  end

  defp body_line(%FileOp{kind: :delete}, line, number),
    do: {:error, {:content_in_delete_section, number, line}}

  defp move_to(%FileOp{kind: :update, move_to: nil} = file, line, _number) do
    path = line |> String.replace_prefix("*** Move to: ", "") |> clean()

    if path == "",
      do: {:error, {:missing_move_target, line}},
      else: {:ok, %{file | move_to: path}}
  end

  defp move_to(%FileOp{kind: :update}, line, number),
    do: {:error, {:duplicate_move_to, number, line}}

  defp move_to(_not_an_update_section, line, number),
    do: {:error, {:move_to_outside_update, number, line}}

  # Markers are stored trimmed, because that is how they are used: a marker is matched
  # with `String.contains?` against the trimmed file line, so keeping the patch's own
  # indentation would only make a correct marker fail on a file indented differently.
  defp open_hunk(file, marker) do
    case file.hunks do
      # Consecutive `@@` lines with no body between them stack as scope markers for one
      # hunk, which is how V4A disambiguates a method inside a class.
      [%Hunk{lines: []} = open | rest] ->
        %{file | hunks: [%{open | markers: open.markers ++ [marker]} | rest]}

      hunks ->
        markers = if marker == "", do: [], else: [marker]
        %{file | hunks: [%Hunk{markers: markers} | hunks]}
    end
  end

  defp push(file, classified) do
    [%Hunk{} = open | rest] = file.hunks
    %{file | hunks: [%{open | lines: open.lines ++ [classified]} | rest]}
  end

  defp classify(" " <> rest, _number), do: {:ok, {:context, rest}}
  defp classify("-" <> rest, _number), do: {:ok, {:remove, rest}}
  defp classify("+" <> rest, _number), do: {:ok, {:add, rest}}
  # An editor that strips trailing whitespace turns a blank context line into an empty
  # one. Refusing that would refuse most real patches; it is the one prefix tolerated.
  defp classify("", _number), do: {:ok, {:context, ""}}
  defp classify(line, number), do: {:error, {:body_line_without_prefix, number, line}}

  defp mark_eof(nil, number), do: {:error, {:end_of_file_outside_section, number}}

  defp mark_eof(%FileOp{kind: :update, hunks: [open | rest]} = file, _number),
    do: {:ok, %{file | hunks: [%{open | eof?: true} | rest]}}

  defp mark_eof(_file, number), do: {:error, {:end_of_file_outside_hunk, number}}

  defp close(nil), do: {:ok, nil}

  defp close(%FileOp{kind: :add, content: content} = file),
    do: {:ok, %{file | content: content |> Enum.reverse() |> Enum.join("\n")}}

  defp close(%FileOp{kind: :delete} = file), do: {:ok, file}

  defp close(%FileOp{kind: :update, hunks: []} = file),
    do: {:error, {:update_without_hunks, file.path}}

  defp close(%FileOp{kind: :update, hunks: hunks} = file) do
    reversed = Enum.reverse(hunks)

    if Enum.any?(reversed, &(&1.lines == [])) do
      {:error, {:empty_hunk, file.path}}
    else
      {:ok, %{file | hunks: reversed}}
    end
  end

  defp distinct(files) do
    paths = Enum.map(files, & &1.path)

    case paths -- Enum.uniq(paths) do
      [] -> :ok
      [duplicate | _rest] -> {:error, {:duplicate_file, duplicate}}
    end
  end

  defp clean(path), do: path |> String.trim() |> String.trim_trailing("/")

  # ---------------------------------------------------------------- applying

  @doc """
  Applies one `:update` section's hunks to a file's content.

  `{:ok, new_content, tier}` where `tier` is `:exact`, `:trailing_whitespace`, or
  `:indentation` — the loosest tier any hunk needed, so the tool result can say the
  patch matched on something other than the bytes.
  """
  @spec apply_hunks(String.t(), FileOp.t()) ::
          {:ok, String.t(), atom()} | {:error, term()}
  def apply_hunks(content, %FileOp{kind: :update, hunks: hunks}) do
    lines = String.split(content, "\n")

    hunks
    |> Enum.reduce_while({:ok, lines, 0, :exact}, fn hunk, {:ok, lines, from, tier} ->
      case locate(lines, hunk, from) do
        {:ok, index, matched_tier} ->
          {replacement, consumed} = rewrite(lines, hunk, index, matched_tier)

          {:cont,
           {:ok,
            Enum.slice(lines, 0, index) ++
              replacement ++ Enum.drop(lines, index + consumed), index + length(replacement),
            loosest(tier, matched_tier)}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, lines, _from, tier} -> {:ok, Enum.join(lines, "\n"), tier}
      {:error, _reason} = error -> error
    end
  end

  def apply_hunks(_content, %FileOp{kind: kind}), do: {:error, {:not_an_update, kind}}

  @doc "The lines a hunk expects to find, for a failure message that can be acted on."
  @spec expected(Hunk.t()) :: [String.t()]
  def expected(%Hunk{lines: lines}) do
    for {kind, text} <- lines, kind in [:context, :remove], do: text
  end

  defp locate(lines, hunk, from) do
    needle = expected(hunk)

    if needle == [] do
      # A hunk that is nothing but additions attaches where its markers point, or at the
      # end of the file when it declares EOF.
      {:ok, anchor_only(lines, hunk, from), :exact}
    else
      start = max(anchor(lines, hunk, from), from)

      Enum.reduce_while(
        [
          {:exact, & &1},
          {:trailing_whitespace, &String.trim_trailing/1},
          {:indentation, &String.trim/1}
        ],
        {:error, {:hunk_not_found, hunk, needle}},
        fn {tier, normalize}, acc ->
          case find_window(lines, needle, start, normalize) do
            nil -> {:cont, acc}
            index -> {:halt, {:ok, index, tier}}
          end
        end
      )
    end
  end

  defp anchor_only(lines, %Hunk{eof?: true}, _from), do: length(lines)

  defp anchor_only(lines, hunk, from) do
    case anchor(lines, hunk, from) do
      index when index > from -> index
      _at_or_before -> min(from, length(lines))
    end
  end

  # The `@@` markers narrow where the search starts. They are advisory: a marker that
  # matches nothing leaves the search where it was rather than failing, because the body
  # is the authority and a stale scope name should not refuse a good hunk.
  defp anchor(_lines, %Hunk{markers: []}, from), do: from

  defp anchor(lines, %Hunk{markers: markers}, from) do
    Enum.reduce(markers, from, fn marker, position ->
      target = String.trim(marker)

      if target == "" do
        position
      else
        found =
          lines
          |> Enum.drop(position)
          |> Enum.find_index(&String.contains?(String.trim(&1), target))

        if found, do: position + found + 1, else: position
      end
    end)
  end

  defp find_window(lines, needle, start, normalize) do
    size = length(needle)
    total = length(lines)
    normalized = Enum.map(needle, normalize)

    if size == 0 or start > total - size do
      nil
    else
      start..(total - size)
      |> Enum.find(fn index ->
        lines |> Enum.slice(index, size) |> Enum.map(normalize) == normalized
      end)
    end
  end

  defp rewrite(lines, hunk, index, tier) do
    consumed = hunk |> expected() |> length()

    replacement =
      for {kind, text} <- hunk.lines, kind in [:context, :add] do
        text
      end

    {reindent(replacement, hunk, lines, index, tier), consumed}
  end

  # The hunk matched with its indentation ignored, so every line it writes back has to be
  # re-hung on the indentation the file actually uses — the same correction `Edit` makes,
  # and for the same reason: otherwise the tolerance produces code that does not compile.
  defp reindent(replacement, _hunk, _lines, _index, tier) when tier != :indentation,
    do: replacement

  defp reindent(replacement, hunk, lines, index, :indentation) do
    file_indent = lines |> Enum.at(index) |> indent_of()
    patch_indent = hunk |> expected() |> List.first() |> indent_of()

    Enum.map(replacement, fn line ->
      stripped =
        if patch_indent != "" and String.starts_with?(line, patch_indent),
          do:
            binary_part(line, byte_size(patch_indent), byte_size(line) - byte_size(patch_indent)),
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

  defp loosest(:indentation, _other), do: :indentation
  defp loosest(_current, :indentation), do: :indentation
  defp loosest(:trailing_whitespace, _other), do: :trailing_whitespace
  defp loosest(_current, :trailing_whitespace), do: :trailing_whitespace
  defp loosest(_current, _other), do: :exact

  # ---------------------------------------------------------------- refusals

  @doc "A refusal in words a model can act on."
  @spec describe(term()) :: String.t()
  def describe({:missing_begin, marker}), do: "the patch does not start with `#{marker}`"
  def describe({:missing_end, marker}), do: "the patch does not end with `#{marker}`"

  def describe({:unknown_directive, line, text}),
    do: "line #{line}: `#{text}` is not a V4A directive"

  def describe({:missing_path, line, text}), do: "line #{line}: `#{text}` names no path"

  def describe({:content_before_any_file, line, _text}),
    do: "line #{line}: content before any `*** Add/Delete/Update File:` directive"

  def describe({:content_before_any_hunk, line, _text}),
    do: "line #{line}: content before any `@@` hunk header in an Update section"

  def describe({:body_line_without_prefix, line, text}),
    do: "line #{line}: `#{clip(text)}` has no ` `, `-` or `+` prefix"

  def describe({:add_line_without_plus, line, text}),
    do: "line #{line}: `#{clip(text)}` is in an Add File section and must start with `+`"

  def describe({:content_in_delete_section, line, _text}),
    do: "line #{line}: a Delete File section takes no body"

  def describe({:update_without_hunks, path}),
    do: "the Update section for #{path} has no `@@` hunk"

  def describe({:empty_hunk, path}), do: "a `@@` hunk in the section for #{path} has no body"
  def describe({:duplicate_file, path}), do: "#{path} appears in more than one section"
  def describe({:duplicate_move_to, line, _text}), do: "line #{line}: a second `*** Move to:`"

  def describe({:move_to_outside_update, line, _text}),
    do: "line #{line}: `*** Move to:` belongs inside an `*** Update File:` section"

  def describe({:missing_move_target, text}), do: "`#{text}` names no move target"

  def describe({:end_of_file_outside_section, line}),
    do: "line #{line}: `#{@end_of_file}` outside a section"

  def describe({:end_of_file_outside_hunk, line}),
    do: "line #{line}: `#{@end_of_file}` outside a hunk"

  def describe({:too_many_files, limit}), do: "a patch may touch at most #{limit} files"

  def describe({:patch_too_large, bytes}),
    do: "the patch is #{bytes} bytes; the limit is #{@max_bytes}"

  def describe({:not_a_patch, value}), do: "#{value} is not patch text"
  def describe({:not_an_update, kind}), do: "a #{kind} section has no hunks to apply"
  def describe(reason), do: inspect(reason)

  defp clip(text) when byte_size(text) <= 120, do: text
  defp clip(text), do: binary_part(text, 0, 120) <> "…"
end
