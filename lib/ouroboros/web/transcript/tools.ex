defmodule Ouroboros.Web.Transcript.ToolSummary do
  @moduledoc "One tool call in the field's vocabulary."

  defstruct shape: :other, verb: "", subject: "", outcome: ""

  @type t :: %__MODULE__{
          shape: Ouroboros.Web.Transcript.Tools.shape(),
          verb: String.t(),
          subject: String.t(),
          outcome: String.t()
        }

  @doc "The whole row as one string, for the exploration list and a plain-text export."
  @spec line(t()) :: String.t()
  def line(%__MODULE__{} = summary) do
    [summary.verb, summary.subject, summary.outcome]
    |> Enum.reject(&(String.trim(&1) == ""))
    |> Enum.join(" ")
  end
end

defmodule Ouroboros.Web.Transcript.Tools do
  @moduledoc """
  The two vendor tables, ported as data.

  ## What a tool call *is*, independent of what any one vendor called it

  Three naming systems reach this surface and none of them agrees with the others:
  Claude's tool names (`Read`, `Grep`, `Bash`, `mcp__server__tool`), ACP's `kind` enum
  (`read | edit | delete | move | search | execute | think | fetch | other`), and Codex's
  item types, which the runtime already normalises. Keying the summary on the shape rather
  than on any one of them is what lets a row read `Bash $ cargo test` whichever dialect
  produced it (`tui/src/ui/transcript_cells.rs:3691-3856`).

  ## Every claim is read off the call

  `summarise/1` states only what the call's own input or its result proves; nothing is
  inferred from the tool's name alone (`tui/src/ui/transcript_cells.rs:3858`).
  """

  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Transcript.{Cell, Text, ToolSummary}

  @tool_value_bytes 32 * 1024
  @tool_input_bytes 8 * 1024
  @tool_value_truncation "\n… tool value truncated; full value is available in event details"
  @tool_input_truncation " … full input is available in event details"

  @type shape ::
          :read
          | :edit
          | :write
          | :delete
          | :move
          | :grep
          | :glob
          | :list
          | :bash
          | :fetch
          | :web_search
          | :mcp
          | :think
          | :other

  @read ~w(read read_file readfile view view_file open cat notebookread notebook_read read_many_files)
  @edit ~w(edit edit_file editfile str_replace str_replace_editor str_replace_based_edit_tool
           apply_patch applypatch patch multiedit multi_edit update_file notebookedit
           notebook_edit file_change)
  @write ~w(write write_file writefile create create_file new_file)
  @delete ~w(delete delete_file remove remove_file rm)
  @move ~w(move move_file rename rename_file mv)
  @grep ~w(grep search rg ripgrep grep_search search_files codebase_search search_file_content)
  @glob ~w(glob find find_files file_search glob_file_search)
  @list ~w(ls list list_dir list_files list_directory readdir)
  @bash ~w(bash shell exec exec_command run_command runcommand command commandexecution
           command_execution terminal run_terminal_cmd bashoutput)
  @fetch ~w(fetch web_fetch webfetch url_fetch http curl)
  @web_search ~w(web_search websearch search_web google_web_search)
  @think ~w(think thinking sequentialthinking)

  @doc "The truncation marker a bounded tool value ends with."
  def value_truncation, do: @tool_value_truncation

  @doc """
  Whether this shape is filesystem exploration, and so belongs in a grouped cell.

  Reading, searching, listing and globbing only. An edit, a command, or a fetch is
  something the agent *did*, and folding those into a count would hide the actions a
  reader is watching for (`tui/src/ui/transcript_cells.rs:3723`).
  """
  @spec explores?(shape()) :: boolean()
  def explores?(shape), do: shape in [:read, :grep, :glob, :list]

  @doc "The verb a shape reads as, or `\"\"` for one with no vendor-neutral word."
  @spec verb(shape()) :: String.t()
  def verb(:read), do: "Read"
  def verb(:edit), do: "Edit"
  def verb(:write), do: "Write"
  def verb(:delete), do: "Delete"
  def verb(:move), do: "Move"
  def verb(:grep), do: "Grep"
  def verb(:glob), do: "Glob"
  def verb(:list), do: "List"
  def verb(:bash), do: "Bash"
  def verb(:fetch), do: "Fetch"
  def verb(:web_search), do: "Search"
  def verb(:mcp), do: "MCP"
  def verb(:think), do: "Think"
  def verb(:other), do: ""

  @doc "What a tool call is, from its name and — only as a fallback — ACP's `kind`."
  @spec shape_of(String.t(), String.t() | nil) :: shape()
  def shape_of(name, kind) when is_binary(name) do
    lower = name |> String.trim() |> String.downcase(:ascii)

    # MCP first: `mcp__linear__create_issue` would otherwise match `create`.
    if String.starts_with?(lower, "mcp__") or String.starts_with?(lower, "mcp.") do
      :mcp
    else
      case named_shape(String.replace(lower, [" ", "-"], "_")) do
        nil -> fallback_shape(lower, kind)
        shape -> shape
      end
    end
  end

  defp named_shape(name) do
    cond do
      name in @read -> :read
      name in @edit -> :edit
      name in @write -> :write
      name in @delete -> :delete
      name in @move -> :move
      name in @grep -> :grep
      name in @glob -> :glob
      name in @list -> :list
      name in @bash -> :bash
      name in @fetch -> :fetch
      name in @web_search -> :web_search
      name in @think -> :think
      true -> nil
    end
  end

  defp fallback_shape(lower, kind) do
    # Codex's `mcpToolCall` reaches this surface under the MCP tool's *own* name, which is
    # routinely `server.tool`. A dotted name that matched no verb above is that.
    if String.contains?(lower, ".") and not String.contains?(lower, " ") and
         not String.starts_with?(lower, ".") do
      :mcp
    else
      # ACP's `kind` is the fallback, not the first answer: an agent that sends both a
      # prose `title` and a `kind` is more specific in the title, and only the kind is an
      # enum.
      case kind_shape(kind) do
        nil -> :other
        shape -> shape
      end
    end
  end

  defp kind_shape(kind) when is_binary(kind) do
    case kind |> String.trim() |> String.downcase(:ascii) do
      "read" -> :read
      "edit" -> :edit
      "delete" -> :delete
      "move" -> :move
      "search" -> :grep
      "execute" -> :bash
      "think" -> :think
      "fetch" -> :fetch
      _unknown -> nil
    end
  end

  defp kind_shape(_kind), do: nil

  @doc "The per-tool summariser: verb, subject, outcome."
  @spec summarise(Cell.Tool.t()) :: ToolSummary.t()
  def summarise(%Cell.Tool{} = tool) do
    shape = shape_of(tool.name, tool.kind)
    input = tool.input
    output = if is_nil(tool.output), do: nil, else: value_text(tool.output)

    {subject, outcome} =
      case shape do
        :read ->
          {read_subject(input), counted(output, "line")}

        :edit ->
          {join(path_of(input), edit_stat(input)), ""}

        :write ->
          {path_of(input) || "", ""}

        shape when shape in [:delete, :move] ->
          {path_of(input) || "", ""}

        :grep ->
          {grep_subject(input), counted(output, "match")}

        :glob ->
          {field(input, ["pattern", "glob", "query", "filePattern", "path"]) || "",
           counted(output, "file")}

        :list ->
          {path_of(input) || "", counted(output, "entry")}

        :bash ->
          command = field(input, ["cmd", "command", "script", "shell_command"])
          {if(command, do: "$ #{command}", else: ""), exit_status(tool, input)}

        :fetch ->
          {field(input, ["url", "uri", "href", "link"]) || "", ""}

        :web_search ->
          query = field(input, ["query", "q", "search", "prompt"])
          {if(query, do: "\"#{query}\"", else: ""), ""}

        :mcp ->
          {mcp_subject(tool.name), ""}

        :think ->
          {"", ""}

        :other ->
          {tool_input(tool.name, input), ""}
      end

    %ToolSummary{
      shape: shape,
      verb: if(shape == :other, do: display_tool_name(tool.name), else: verb(shape)),
      subject: subject |> String.replace("\n", " ") |> String.trim(),
      outcome: outcome
    }
  end

  # `Read path:12-140`, from whatever the provider called its window.
  defp read_subject(input) do
    case path_of(input) do
      nil ->
        ""

      path ->
        offset = read_number(input, ["offset", "start_line", "startLine", "line", "from"])
        limit = read_number(input, ["limit", "count", "num_lines", "length"])
        last = read_number(input, ["end_line", "endLine", "to"])

        cond do
          offset && last -> "#{path}:#{offset}-#{last}"
          offset && limit && limit > 0 -> "#{path}:#{offset}-#{offset + limit - 1}"
          offset -> "#{path}:#{offset}"
          limit -> "#{path}:1-#{limit}"
          true -> path
        end
    end
  end

  # The first of these keys the map *holds*, converted — never the first that converts.
  defp read_number(input, keys) do
    case Presentation.first_value(input, keys) do
      {:ok, value} when is_integer(value) and value >= 0 ->
        value

      {:ok, value} when is_binary(value) ->
        case Integer.parse(value) do
          {parsed, ""} when parsed >= 0 -> parsed
          _otherwise -> nil
        end

      _otherwise ->
        nil
    end
  end

  # `(+3 −1)` for an anchored replacement, counted from the two strings the call carries.
  #
  # Only ever from strings this surface can see. An edit tool that describes its change
  # without carrying it gets no counts rather than a guess, and the authoritative numbers
  # arrive separately as the `file_change` event's diff.
  defp edit_stat(input) do
    old = first_leaf(input, ["old_string", "oldText", "old_str"])
    new = first_leaf(input, ["new_string", "newText", "new_str"])

    if is_nil(old) or is_nil(new) do
      nil
    else
      "(+#{count_lines(new)} −#{count_lines(old)})"
    end
  end

  defp count_lines(""), do: 0
  defp count_lines(text), do: Text.line_count(text)

  defp first_leaf(input, keys) when is_map(input) do
    Enum.find_value(keys, fn key ->
      case Map.fetch(input, key) do
        {:ok, value} -> Presentation.leaf_text(value)
        :error -> nil
      end
    end)
  end

  defp first_leaf(_input, _keys), do: nil

  # `"needle" in lib/`, in the shape Codex and Claude Code both print.
  defp grep_subject(input) do
    pattern = field(input, ["pattern", "query", "regex", "search", "q"])
    scope = field(input, ["path", "dir", "directory", "include", "glob", "in"])

    case {pattern, scope} do
      {nil, nil} -> ""
      {nil, scope} -> scope
      {pattern, nil} -> "\"#{pattern}\""
      {pattern, scope} -> "\"#{pattern}\" in #{scope}"
    end
  end

  # `MCP linear.create_issue` — the server and the tool, separated the way both dialects
  # write them.
  defp mcp_subject(name) do
    trimmed = String.trim(name)

    case trimmed do
      "mcp__" <> rest -> replace_once(rest, "__", ".")
      "mcp." <> rest -> replace_once(rest, "__", ".")
      other -> other
    end
  end

  defp replace_once(text, pattern, replacement) do
    case String.split(text, pattern, parts: 2) do
      [head, tail] -> head <> replacement <> tail
      [only] -> only
    end
  end

  # Gemini's `→ Returned N lines`, said only where the result is actually held.
  #
  # English, spelled out rather than derived: "matchs" is what `noun <> "s"` produces, and
  # a summary row that misspells its own unit reads as a machine talking to itself.
  defp counted(output, "match"), do: counted_with(output, "match", "matches")
  defp counted(output, "entry"), do: counted_with(output, "entry", "entries")
  defp counted(output, noun), do: counted_with(output, noun, noun <> "s")

  defp counted_with(nil, _singular, _plural), do: ""

  defp counted_with(output, singular, plural) do
    trimmed = String.trim_trailing(output, "\n")

    if trimmed == "" do
      "→ no #{plural}"
    else
      bounded = String.ends_with?(trimmed, String.trim_leading(@tool_value_truncation, "\n"))

      lines =
        trimmed
        |> Text.lines()
        |> Enum.count(&(String.trim(&1) != ""))

      lines = if bounded, do: max(lines - 1, 0), else: lines

      "→ #{lines}#{if bounded, do: "+", else: ""} #{if lines == 1 and not bounded, do: singular, else: plural}"
    end
  end

  # `exit 1` where a payload carried one, `failed` where only `is_error` did.
  #
  # The runtime's Codex dialect folds `exitCode` into `is_error` and does not forward the
  # number, so `failed` is the ordinary answer there and a numeric code appears only for a
  # provider that sends one.
  defp exit_status(tool, input) do
    code =
      ["exit_code", "exitCode", "status_code", "returncode"]
      |> Enum.find_value(fn key ->
        with :error <- fetch_in(tool.output, key), :error <- fetch_in(input, key) do
          nil
        else
          {:ok, value} -> {:found, value}
        end
      end)
      |> case do
        {:found, value} when is_integer(value) -> value
        {:found, value} when is_binary(value) -> parse_signed(value)
        _otherwise -> nil
      end

    cond do
      is_integer(code) -> "exit #{code}"
      tool.state == :failed -> "failed"
      true -> ""
    end
  end

  defp fetch_in(value, key) when is_map(value) and not is_struct(value), do: Map.fetch(value, key)
  defp fetch_in(_value, _key), do: :error

  defp parse_signed(text) do
    case Integer.parse(text) do
      {value, ""} -> value
      _otherwise -> nil
    end
  end

  defp path_of(input) do
    field(input, [
      "path",
      "file_path",
      "filePath",
      "file",
      "filename",
      "absolute_path",
      "abs_path",
      "uri",
      "target",
      "notebook_path"
    ])
  end

  @doc """
  The first of these keys that holds text, already bounded and flattened.

  Unlike `Presentation.first_value/2` this keeps looking past a key whose value is not
  usable text: it is choosing a *label*, not reading a named field.
  """
  @spec field(term(), [String.t()]) :: String.t() | nil
  def field(input, keys) when is_map(input) and not is_struct(input) do
    Enum.find_value(keys, fn key ->
      with {:ok, value} <- Map.fetch(input, key),
           text when is_binary(text) <- Presentation.leaf_text(value),
           trimmed when trimmed != "" <- String.trim(text) do
        Text.bounded_copy(
          String.replace(trimmed, "\n", " "),
          @tool_input_bytes,
          @tool_input_truncation
        )
      else
        _otherwise -> nil
      end
    end)
  end

  def field(_input, _keys), do: nil

  defp join(nil, nil), do: ""
  defp join(head, nil), do: head
  defp join(nil, tail), do: tail
  defp join(head, tail), do: "#{head} #{tail}"

  defp display_tool_name(name) when name in ["exec_command", "run_command", "bash", "shell"],
    do: "command"

  defp display_tool_name(name), do: String.replace(name, "_", " ")

  @doc "The one-line subject a tool row shows for a shape with no summariser of its own."
  @spec tool_input(String.t(), term()) :: String.t()
  def tool_input(name, input) do
    preferred =
      if shape_of(name, nil) == :bash do
        ["cmd", "command"]
      else
        ["path", "file", "query", "pattern", "url"]
      end

    # `leaf_text` also reads the gateway's wire markers, so an excerpted command reads as
    # its own prefix rather than as `{"_excerpt": …}`.
    preferred_text =
      Enum.find_value(preferred, fn key ->
        with {:ok, value} <- fetch_in(input, key),
             text when is_binary(text) <- Presentation.leaf_text(value),
             trimmed when trimmed != "" <- String.trim(text) do
          Text.bounded_copy(trimmed, @tool_input_bytes, @tool_input_truncation)
        else
          _otherwise -> nil
        end
      end)

    cond do
      is_binary(preferred_text) -> preferred_text
      is_nil(input) -> ""
      is_map(input) and not is_struct(input) and map_size(input) == 0 -> ""
      true -> Text.bounded_compact(input, @tool_input_bytes, @tool_input_truncation)
    end
  end

  @doc """
  A tool value as the text a row quotes.

  Prefers a `text` or `content` field, falls through arrays, and renders a wire marker as
  its label rather than as JSON (`tui/src/ui/transcript_cells.rs:3623`).
  """
  @spec value_text(term()) :: String.t()
  def value_text(value) do
    {rendered, _wrote} = append_value_text(value, "")
    rendered
  end

  defp append_value_text(value, rendered) do
    if String.ends_with?(rendered, @tool_value_truncation) do
      {rendered, true}
    else
      do_append_value_text(value, rendered)
    end
  end

  defp do_append_value_text(value, rendered) when is_binary(value),
    do: append_value_piece(rendered, value)

  defp do_append_value_text(nil, rendered), do: {rendered, false}

  defp do_append_value_text(value, rendered) when is_list(value) do
    Enum.reduce_while(value, {rendered, false}, fn item, {rendered, wrote} ->
      {rendered, item_wrote} = append_value_text(item, rendered)
      acc = {rendered, wrote or item_wrote}

      if String.ends_with?(rendered, @tool_value_truncation) do
        {:halt, acc}
      else
        {:cont, acc}
      end
    end)
  end

  defp do_append_value_text(value, rendered) when is_map(value) and not is_struct(value) do
    # A leaf the gateway replaced with a marker: render the label, never the JSON.
    case Presentation.wire_marker(value) do
      marker when is_binary(marker) ->
        append_value_piece(rendered, marker)

      nil ->
        preferred =
          case Map.fetch(value, "text") do
            {:ok, found} -> {:ok, found}
            :error -> Map.fetch(value, "content")
          end

        case preferred do
          {:ok, found} ->
            case append_value_text(found, rendered) do
              {rendered, true} ->
                {rendered, true}

              {rendered, false} ->
                append_value_piece(
                  rendered,
                  Text.bounded_compact(value, @tool_value_bytes, @tool_value_truncation)
                )
            end

          :error ->
            append_value_piece(
              rendered,
              Text.bounded_compact(value, @tool_value_bytes, @tool_value_truncation)
            )
        end
    end
  end

  defp do_append_value_text(value, rendered) do
    append_value_piece(
      rendered,
      Text.bounded_compact(value, @tool_value_bytes, @tool_value_truncation)
    )
  end

  defp append_value_piece(rendered, ""), do: {rendered, false}

  defp append_value_piece(rendered, value) do
    rendered =
      if rendered == "" do
        rendered
      else
        {rendered, _spent} =
          Text.append_bounded(rendered, "\n", @tool_value_bytes, @tool_value_truncation)

        rendered
      end

    {rendered, _spent} =
      Text.append_bounded(rendered, value, @tool_value_bytes, @tool_value_truncation)

    {rendered, true}
  end
end
