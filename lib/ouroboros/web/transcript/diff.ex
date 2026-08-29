defmodule Ouroboros.Web.Transcript.DiffLine do
  @moduledoc "One line of a hunk body, with its `+`/`-`/space marker already removed."

  defstruct [:kind, :old_no, :new_no, text: ""]

  @type kind :: :context | :added | :removed | :meta
  @type t :: %__MODULE__{
          kind: kind(),
          old_no: pos_integer() | nil,
          new_no: pos_integer() | nil,
          text: String.t()
        }
end

defmodule Ouroboros.Web.Transcript.DiffHunk do
  @moduledoc "One `@@` block: where it starts on each side, and the body under it."

  alias Ouroboros.Web.Transcript.DiffLine

  defstruct old_start: 1, new_start: 1, section: "", lines: []

  @type t :: %__MODULE__{
          old_start: pos_integer(),
          new_start: pos_integer(),
          section: String.t(),
          lines: [DiffLine.t()]
        }
end

defmodule Ouroboros.Web.Transcript.DiffFile do
  @moduledoc """
  One file a patch touched.

  `additions` and `deletions` are **counted from the hunk bodies**, never quoted from the
  provider: a provider that summarises a 400-line patch and sends a 40-line excerpt would
  otherwise have this surface repeat a number it cannot see (`tui/src/ui/diff.rs:14-21`).
  """

  alias Ouroboros.Web.Transcript.DiffHunk

  defstruct [:old_path, path: "", status: :modified, hunks: [], additions: 0, deletions: 0]

  @type status :: :added | :deleted | :renamed | :modified | :binary
  @type t :: %__MODULE__{
          path: String.t(),
          old_path: String.t() | nil,
          status: status(),
          hunks: [DiffHunk.t()],
          additions: non_neg_integer(),
          deletions: non_neg_integer()
        }

  @doc "The one-letter mark git uses, so a reader who knows `git status` needs no legend."
  @spec mark(status() | t()) :: String.t()
  def mark(%__MODULE__{status: status}), do: mark(status)
  def mark(:added), do: "A"
  def mark(:deleted), do: "D"
  def mark(:renamed), do: "R"
  def mark(:modified), do: "M"
  def mark(:binary), do: "B"

  @doc "The status as a word."
  @spec label(status() | t()) :: String.t()
  def label(%__MODULE__{status: status}), do: label(status)
  def label(:added), do: "added"
  def label(:deleted), do: "deleted"
  def label(:renamed), do: "renamed"
  def label(:modified), do: "modified"
  def label(:binary), do: "binary"

  @doc "How many rows this file's body occupies: one per hunk header plus one per line."
  @spec rows(t()) :: non_neg_integer()
  def rows(%__MODULE__{hunks: hunks}),
    do: Enum.reduce(hunks, 0, fn hunk, total -> total + length(hunk.lines) + 1 end)
end

defmodule Ouroboros.Web.Transcript.Diff do
  @moduledoc """
  Unified diffs: parsed once, at projection time.

  A parse rather than a line filter, for the same reason the TUI has one
  (`tui/src/ui/diff.rs:1-21`): per-file grouping, line numbers, and per-file `+N −M` that
  were *counted* rather than quoted all need to know where a file starts, what a hunk
  claims, and which lines belong to which hunk.

  ## Deliberate omission

  The TUI's word-level `emphasis` ranges (`tui/src/ui/diff.rs:519-579`) are not ported.
  They are a paint-level affordance — which bytes of a paired `-`/`+` line to embolden —
  and carry no fact about the change. Every count, path, status and hunk boundary the
  projection asserts is here.
  """

  alias Ouroboros.Web.Transcript.{DiffFile, DiffHunk, DiffLine}

  # How many files one parse keeps. A patch touching more than this is a repository
  # operation, not a change to read in a transcript.
  @max_files 64
  # How many body lines one parse keeps across all files. The source text is already
  # capped at 128 KiB by the presentation; this bounds the row count a pathological
  # single-column patch could still reach.
  @max_lines 20_000

  @doc "Row budget for a collapsed diff cell."
  def compact_lines, do: 12

  defstruct files: [], truncated: false

  @type t :: %__MODULE__{files: [DiffFile.t()], truncated: boolean()}

  @doc """
  Parses unified-diff text.

  `fallback_path` names the file when the text carries no `---`/`+++` header of its own,
  which is how a provider that sends bare hunks arrives.
  """
  @spec parse(String.t(), String.t() | nil) :: t()
  def parse(text, fallback_path \\ nil) when is_binary(text) do
    parser =
      text
      |> String.split("\n")
      # CRLF: the carriage return belongs to the transport, not to the line.
      |> Enum.map(&String.replace_suffix(&1, "\r", ""))
      |> Enum.reduce_while(new_parser(), fn line, parser ->
        if parser.rows >= @max_lines do
          {:halt, %{parser | truncated: true}}
        else
          {:cont, line(parser, line)}
        end
      end)
      |> flush()

    files = Enum.reverse(parser.files)
    {files, truncated} = bound_files(files, parser.truncated)

    # Every `@@` line was written in a dialect this build cannot read, so the `---`/`+++`
    # pair above them is all that survived. Reporting a file with no hunks would draw a
    # header over an empty body; reporting nothing hands the text to the caller's verbatim
    # fallback, which shows the change as the provider wrote it.
    files =
      if parser.refused > 0 and Enum.all?(files, &(&1.hunks == [])) do
        []
      else
        files
      end

    %__MODULE__{files: Enum.map(files, &settle_file(&1, fallback_path)), truncated: truncated}
  end

  @doc "Every addition this parse counted, across all files."
  @spec additions(t()) :: non_neg_integer()
  def additions(%__MODULE__{files: files}),
    do: Enum.reduce(files, 0, fn file, total -> total + file.additions end)

  @doc "Every deletion this parse counted, across all files."
  @spec deletions(t()) :: non_neg_integer()
  def deletions(%__MODULE__{files: files}),
    do: Enum.reduce(files, 0, fn file, total -> total + file.deletions end)

  @doc "Whether the parse recognised no file at all."
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{files: files}), do: files == []

  defp bound_files(files, truncated) do
    if length(files) > @max_files do
      {Enum.take(files, @max_files), true}
    else
      {files, truncated}
    end
  end

  defp settle_file(file, fallback_path) do
    path = if file.path == "", do: fallback_path || "(path not reported)", else: file.path
    %{file | path: path, hunks: Enum.reverse(Enum.map(file.hunks, &settle_hunk/1))}
  end

  defp settle_hunk(hunk), do: %{hunk | lines: Enum.reverse(hunk.lines)}

  # ------------------------------------------------------------------------------------
  # The line machine
  # ------------------------------------------------------------------------------------

  defp new_parser do
    %{
      files: [],
      current: nil,
      truncated: false,
      rows: 0,
      # How many `@@` lines this parse could not read.
      refused: 0,
      # Inside the body of a hunk whose header was refused. Its lines belong to no hunk
      # this parse holds, and appending them to the one above would count another hunk's
      # changes as that one's.
      refusing: false
    }
  end

  defp flush(parser) do
    parser = %{parser | refusing: false}

    case parser.current do
      # A `diff --git` pair with no hunks and no status is a mode change or an empty
      # rename; it is still a file the turn touched.
      nil -> parser
      file -> %{parser | current: nil, files: [file | parser.files]}
    end
  end

  defp file(%{current: nil} = parser), do: {parser, %DiffFile{}}
  defp file(%{current: file} = parser), do: {parser, file}

  defp put_file(parser, file), do: %{parser | current: file}

  defp line(parser, "diff --git " <> rest) do
    parser = flush(parser)
    {old, new} = git_header_paths(rest)
    {parser, file} = file(parser)

    file = %{file | path: new || old || ""}

    file =
      if is_binary(old) and is_binary(new) and old != new do
        %{file | old_path: old, status: :renamed}
      else
        file
      end

    put_file(parser, file)
  end

  defp line(parser, "--- " <> rest) do
    # A second `---` inside a file that already has a body is the next file in a
    # headerless multi-file patch.
    parser =
      case parser.current do
        %DiffFile{hunks: [_ | _]} -> flush(parser)
        _otherwise -> parser
      end

    path = strip_prefix_path(rest)
    {parser, file} = file(parser)

    file =
      cond do
        is_nil(path) -> %{file | status: :added}
        is_nil(file.old_path) and file.status != :renamed -> %{file | old_path: path}
        true -> file
      end

    file = if file.path == "", do: %{file | path: path || ""}, else: file

    put_file(parser, file)
  end

  defp line(parser, "+++ " <> rest) do
    path = strip_prefix_path(rest)
    {parser, file} = file(parser)

    file =
      cond do
        is_nil(path) -> %{file | status: :deleted}
        file.status != :renamed or file.path == "" -> %{file | path: path}
        true -> file
      end

    put_file(parser, file)
  end

  defp line(parser, "@@" <> _rest = raw) do
    case hunk_header(raw) do
      nil ->
        %{parser | refusing: true, refused: parser.refused + 1}

      hunk ->
        {parser, file} = file(parser)

        %{parser | refusing: false, rows: parser.rows + 1}
        |> put_file(%{file | hunks: [hunk | file.hunks]})
    end
  end

  defp line(parser, raw) do
    cond do
      String.starts_with?(raw, "Binary files ") or String.starts_with?(raw, "GIT binary patch") ->
        {parser, file} = file(parser)
        file = %{file | status: :binary}
        file = if file.path == "", do: %{file | path: binary_path(raw) || ""}, else: file
        put_file(parser, file)

      String.starts_with?(raw, "new file mode") ->
        {parser, file} = file(parser)
        put_file(parser, %{file | status: :added})

      String.starts_with?(raw, "deleted file mode") ->
        {parser, file} = file(parser)
        put_file(parser, %{file | status: :deleted})

      String.starts_with?(raw, "rename from ") ->
        {parser, file} = file(parser)
        rest = String.replace_prefix(raw, "rename from ", "")
        put_file(parser, %{file | status: :renamed, old_path: rest})

      String.starts_with?(raw, "rename to ") ->
        {parser, file} = file(parser)
        rest = String.replace_prefix(raw, "rename to ", "")
        put_file(parser, %{file | status: :renamed, path: rest})

      # Only a line inside an open hunk is body. Everything else at this point — `index`,
      # mode lines, a commit message above the patch — is metadata this view ignores.
      parser.refusing ->
        parser

      true ->
        body(parser, raw)
    end
  end

  defp body(%{current: nil} = parser, _raw), do: parser
  defp body(%{current: %DiffFile{hunks: []}} = parser, _raw), do: parser

  defp body(parser, raw) do
    case classify(raw) do
      nil ->
        parser

      {kind, text} ->
        %DiffFile{hunks: [hunk | rest]} = file = parser.current

        {old_no, new_no, file} =
          case kind do
            :added ->
              {nil, next_no(hunk, :new), %{file | additions: file.additions + 1}}

            :removed ->
              {next_no(hunk, :old), nil, %{file | deletions: file.deletions + 1}}

            :context ->
              {next_no(hunk, :old), next_no(hunk, :new), file}

            :meta ->
              {nil, nil, file}
          end

        line = %DiffLine{kind: kind, old_no: old_no, new_no: new_no, text: text}
        hunk = %{hunk | lines: [line | hunk.lines]}

        %{parser | rows: parser.rows + 1, current: %{file | hunks: [hunk | rest]}}
    end
  end

  defp classify(<<?+, text::binary>>), do: {:added, text}
  defp classify(<<?-, text::binary>>), do: {:removed, text}
  defp classify(<<?\s, text::binary>>), do: {:context, text}
  defp classify(<<?\\, _rest::binary>> = raw), do: {:meta, raw}
  # A stripped-blank context line. Tools that trim trailing whitespace emit these
  # constantly, and reading one as "end of hunk" loses the rest of the file.
  defp classify(""), do: {:context, ""}
  defp classify(_raw), do: nil

  # The next old- or new-side number for a hunk, from its header plus what it already
  # holds. `hunk.lines` is reversed while parsing, which does not change the count.
  defp next_no(%DiffHunk{} = hunk, side) do
    used =
      Enum.count(hunk.lines, fn line ->
        case side do
          :old -> line.old_no != nil
          :new -> line.new_no != nil
        end
      end)

    case side do
      :old -> hunk.old_start + used
      :new -> hunk.new_start + used
    end
  end

  defp hunk_header("@@" <> rest) do
    case :binary.match(rest, "@@") do
      :nomatch ->
        nil

      {close, 2} ->
        ranges = binary_part(rest, 0, close)
        section = String.trim(binary_part(rest, close + 2, byte_size(rest) - close - 2))

        ranges
        |> String.split(~r/\s+/u, trim: true)
        |> Enum.reduce_while({1, 1}, fn token, {old_start, new_start} ->
          case hunk_range(token) do
            {?-, start} -> {:cont, {start, new_start}}
            {?+, start} -> {:cont, {old_start, start}}
            _unreadable -> {:halt, nil}
          end
        end)
        |> case do
          nil ->
            nil

          {old_start, new_start} ->
            %DiffHunk{old_start: old_start, new_start: new_start, section: section}
        end
    end
  end

  # By character, not by byte: a provider that wrote the Unicode minus in
  # `@@ −1,4 +1,6 @@` would otherwise split this token inside a code point.
  defp hunk_range(token) do
    case String.next_grapheme(token) do
      nil ->
        nil

      {sign, rest} ->
        digits = rest |> String.split(",", parts: 2) |> List.first()

        with true <- sign in ["-", "+"],
             {start, ""} <- Integer.parse(digits || ""),
             true <- start >= 0 do
          {if(sign == "-", do: ?-, else: ?+), start}
        else
          _unreadable -> nil
        end
    end
  end

  # `a/lib/app.ex\t2026-08-22` → `lib/app.ex`; `/dev/null` → `nil`.
  defp strip_prefix_path(rest) do
    path =
      rest
      |> String.split("\t", parts: 2)
      |> List.first()
      |> String.trim_trailing()

    if path == "/dev/null" or path == "" do
      nil
    else
      case path do
        "a/" <> tail -> tail
        "b/" <> tail -> tail
        path -> path
      end
    end
  end

  # `a/lib/app.ex b/lib/app.ex` → both halves. A path containing a space is ambiguous in
  # this header, so the split is taken at the ` b/` git always writes.
  defp git_header_paths(rest) do
    case :binary.match(rest, " b/") do
      {at, _length} ->
        tail = binary_part(rest, at + 1, byte_size(rest) - at - 1)

        {strip_prefix_path(binary_part(rest, 0, at)),
         strip_prefix_path(String.trim_leading(tail))}

      :nomatch ->
        case String.split(rest, ~r/\s+/u, trim: true) do
          [old, new | _rest] -> {strip_prefix_path(old), strip_prefix_path(new)}
          [old] -> {strip_prefix_path(old), nil}
          [] -> {nil, nil}
        end
    end
  end

  defp binary_path("Binary files " <> rest) do
    case :binary.match(rest, " and ") do
      {at, _length} -> strip_prefix_path(binary_part(rest, 0, at))
      :nomatch -> nil
    end
  end

  defp binary_path(_line), do: nil
end
