defmodule Ouroboros.Provider.Native.Tools.CodeIntel do
  @moduledoc """
  One tool, eleven questions: the nine navigation operations every agent converged on,
  plus on-demand `diagnostics` and a two-step `rename`.

  ## Why one tool and not eleven

  Eleven tool definitions cost eleven schemas in every request whether the model uses
  them or not — Anthropic measured 72K tokens of tool definitions before tool search
  (R3 §8d). OpenCode, Claude Code, Kilo and Kiro all landed on a single tool with an
  `operation` enum, and R4's synthesis names that as the recommendation.

  ## When it is worth using, said in the description

  Serena's own evaluation is blunt about the tradeoff: a cross-file rename takes one
  call here and nine with text editing, but a one-to-three-line edit sends ~550
  characters through Serena against ~120 through a plain edit, and "roughly 40–60% of a
  typical coding session" is out of its scope entirely. A benchmark on a 36K-LOC Java
  service reported four times the cost for a simple find-a-rule task. So the description
  the model reads says *when* — references, renames, multi-file work — and says to use
  `grep` and `read` for a simple lookup. That sentence is the finding.

  ## `rename` is preview then apply, and the apply is a write

  `operation: "rename"` previews: it asks the language server for the workspace edit and
  reports the files and counts, changing nothing. `operation: "rename_apply"` performs
  it, and it is classified as a `:write` touching every file in the edit, so it goes
  through the permission engine, the approval path, and the checkpoint exactly like
  `edit` does. A refactor that rewrites nine files without an approval would be the
  largest unreviewed effect in this provider.
  """

  use Jido.Action,
    name: "code_intel",
    description:
      "Ask the language server about code: definition, references, hover, " <>
        "document_symbols, workspace_symbols, implementation, prepare_call_hierarchy, " <>
        "incoming_calls, outgoing_calls, diagnostics, rename (preview), rename_apply. " <>
        "Positions are 0-based. Use this for references, call hierarchies, renames and " <>
        "multi-file work; use `grep` and `read` for a simple lookup — for small edits " <>
        "it costs more than it saves.",
    schema: [
      operation: [
        type: :string,
        required: true,
        doc:
          "One of: definition, references, hover, document_symbols, workspace_symbols, " <>
            "implementation, prepare_call_hierarchy, incoming_calls, outgoing_calls, " <>
            "diagnostics, rename, rename_apply."
      ],
      path: [
        type: :string,
        required: true,
        doc: "The file the question is about. Absolute, or relative to the workspace root."
      ],
      line: [type: :non_neg_integer, default: 0, doc: "0-based line. Ignored by symbol queries."],
      character: [
        type: :non_neg_integer,
        default: 0,
        doc: "0-based character within the line."
      ],
      query: [
        type: :string,
        default: "",
        doc: "Search text for workspace_symbols."
      ],
      new_name: [
        type: :string,
        default: "",
        doc: "The replacement identifier, for rename and rename_apply."
      ]
    ]

  alias Ouroboros.CodeIntel
  alias Ouroboros.Provider.Native.CodeIntel, as: Native
  alias Ouroboros.Provider.Native.Diff
  alias Ouroboros.Provider.Native.Paths

  @navigation ~w(definition references hover document_symbols workspace_symbols
                 implementation prepare_call_hierarchy incoming_calls outgoing_calls)
  @operations @navigation ++ ~w(diagnostics rename rename_apply)
  @max_items 100

  @doc "Every operation this tool answers, for the classifier and the tests."
  @spec operations() :: [String.t()]
  def operations, do: @operations

  @doc "The operations that write files. `rename_apply` and nothing else."
  @spec writing?(term()) :: boolean()
  def writing?(operation), do: operation == "rename_apply"

  @doc """
  The workspace paths a `rename_apply` would rewrite, for the permission engine.

  This runs a preview — one language-server round trip — before the gate, because a
  permission decision about "which files does this touch" cannot be made from a call
  that only names one of them. A preview that fails reports the addressed file alone,
  which is the narrowest honest answer.
  """
  @spec write_paths(map(), map()) :: [String.t()]
  def write_paths(input, scope) do
    with "rename_apply" <- Map.get(input, "operation"),
         {:ok, path} <- Paths.resolve(Map.get(input, "path"), scope),
         {:ok, preview} <-
           Native.rename_preview(
             path,
             integer(Map.get(input, "line")),
             integer(Map.get(input, "character")),
             to_string(Map.get(input, "new_name") || "")
           ) do
      preview.edits
      |> Enum.map(& &1.path)
      |> Enum.filter(&is_binary/1)
      |> Enum.flat_map(fn candidate ->
        case Paths.resolve(candidate, scope) do
          {:ok, resolved} -> [resolved]
          {:error, _outside} -> []
        end
      end)
      |> Enum.uniq()
      |> then(fn paths -> if paths == [], do: [path], else: paths end)
    else
      _not_a_rename_apply -> []
    end
  end

  @impl true
  def run(params, context) do
    with :ok <- known(params.operation),
         {:ok, path} <- Paths.resolve(params.path, context.scope) do
      dispatch(params.operation, path, params, context)
    else
      {:error, reason} ->
        {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
    end
  end

  # ---------------------------------------------------------------- dispatch

  defp dispatch("diagnostics", path, _params, context) do
    with {:ok, _version} <- CodeIntel.touch(path, :open) do
      case CodeIntel.diagnostics(path) do
        {:ok, %{items: items, counts: counts}} ->
          {:ok, %{output: render_diagnostics(path, items, counts, context), is_error: false}}

        {:pending, _version} ->
          {:ok,
           %{output: "#{relative(path, context)}: #{Native.no_data_line()}", is_error: false}}

        {:error, reason} ->
          {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
      end
    else
      {:error, reason} ->
        {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp dispatch("rename", path, params, context) do
    case Native.rename_preview(path, params.line, params.character, params.new_name) do
      {:ok, %{count: 0}} ->
        {:ok,
         %{
           output:
             "No rename is available at #{relative(path, context)}:#{params.line}:#{params.character}. " <>
               "Check the position, or the language server may not support rename here.",
           is_error: false
         }}

      {:ok, preview} ->
        {:ok, %{output: render_preview(preview, params.new_name), is_error: false}}

      {:error, reason} ->
        {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp dispatch("rename_apply", path, params, context) do
    with :ok <- writable(context.scope),
         {:ok, preview} <-
           Native.rename_preview(path, params.line, params.character, params.new_name),
         :ok <- non_empty(preview),
         :ok <- contained(preview, context.scope),
         {:ok, plans} <- Native.apply_preview(preview) do
      write_all(plans, context)
    else
      {:error, reason} ->
        {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
    end
  end

  defp dispatch(operation, path, params, context) do
    location = %{path: path, line: params.line, character: params.character}
    opts = if params.query == "", do: [], else: [query: params.query]

    case CodeIntel.request(String.to_existing_atom(operation), location, opts) do
      {:ok, %{items: items, truncated: truncated}} ->
        {:ok, %{output: render_items(operation, items, truncated, context), is_error: false}}

      {:error, reason} ->
        {:ok, %{output: "code_intel failed: #{describe(reason)}", is_error: true}}
    end
  end

  # ---------------------------------------------------------------- rename apply

  defp writable(%{sandbox_mode: :read_only}), do: {:error, :read_only_sandbox}
  defp writable(_scope), do: :ok

  defp non_empty(%{count: 0}), do: {:error, :nothing_to_rename}
  defp non_empty(_preview), do: :ok

  # Every file the server wants to rewrite is put through the same containment check as
  # a path the model typed. A language server that reports an edit in a dependency
  # outside the workspace is answered with a refusal, not a write.
  defp contained(%{edits: edits}, scope) do
    outside =
      Enum.filter(edits, fn edit ->
        not is_binary(edit.path) or match?({:error, _reason}, Paths.resolve(edit.path, scope))
      end)

    case outside do
      [] -> :ok
      [first | _rest] -> {:error, {:rename_outside_workspace, first.relative}}
    end
  end

  defp write_all(plans, context) do
    {written, failure} =
      Enum.reduce_while(plans, {[], nil}, fn plan, {done, nil} ->
        case File.write(plan.path, plan.after) do
          :ok -> {:cont, {[plan | done], nil}}
          {:error, reason} -> {:halt, {done, {plan.path, reason}}}
        end
      end)

    done = Enum.reverse(written)
    root = context.scope.root

    output =
      case failure do
        nil ->
          "Renamed across #{length(done)} #{plural(length(done), "file")}:\n" <>
            Enum.map_join(done, "\n", &("  " <> Path.relative_to(&1.path, root)))

        {path, reason} ->
          "code_intel failed partway: #{Path.relative_to(path, root)}: " <>
            "#{:file.format_error(reason)}. #{length(done)} files were already written " <>
            "and are in the session checkpoint."
      end

    {:ok,
     %{
       output: output,
       is_error: failure != nil,
       changes:
         Enum.map(
           done,
           &Diff.change(&1.path, Path.relative_to(&1.path, root), &1.before, &1.after, :modify)
         )
     }}
  end

  # ---------------------------------------------------------------- rendering

  defp render_preview(preview, new_name) do
    "Renaming to `#{new_name}` would change #{preview.count} " <>
      "#{plural(preview.count, "occurrence")} in #{length(preview.edits)} " <>
      "#{plural(length(preview.edits), "file")}:\n" <>
      Enum.map_join(preview.edits, "\n", fn edit ->
        "  #{edit.relative} (#{length(edit.replacements)})"
      end) <>
      "\nCall code_intel again with operation: \"rename_apply\" and the same position " <>
      "to perform it."
  end

  defp render_diagnostics(path, [], _counts, context),
    do: "#{relative(path, context)}: no diagnostics."

  defp render_diagnostics(path, items, counts, context) do
    kept = Enum.take(items, @max_items)
    more = length(items) - length(kept)

    header =
      "#{relative(path, context)}: #{counts[:error] || 0} errors, #{counts[:warning] || 0} warnings."

    body =
      Enum.map_join(kept, "\n", fn item ->
        "  #{item.range.start.line + 1}:#{item.range.start.character + 1} " <>
          "#{item.severity || "note"}: #{clip(item.message)}"
      end)

    header <> "\n" <> body <> if more > 0, do: "\n  +#{more} more", else: ""
  end

  defp render_items(operation, [], _truncated, _context),
    do: "#{operation}: nothing found."

  defp render_items(operation, items, truncated, context) do
    kept = Enum.take(items, @max_items)
    dropped = truncated + length(items) - length(kept)

    body = Enum.map_join(kept, "\n", &("  " <> render_item(&1, context)))

    "#{operation}: #{length(items)} #{plural(length(items), "result")}\n" <>
      body <> if dropped > 0, do: "\n  +#{dropped} more", else: ""
  end

  defp render_item(item, _context) when is_map(item) do
    location =
      case item do
        %{path: path, range: %{start: %{line: line, character: character}}} ->
          "#{path}:#{line}:#{character}"

        %{path: path} ->
          path

        _positionless ->
          ""
      end

    label =
      [Map.get(item, :name), Map.get(item, :kind), Map.get(item, :detail), Map.get(item, :text)]
      |> Enum.reject(&(is_nil(&1) or &1 == ""))
      |> Enum.map(&to_string/1)
      |> Enum.join(" · ")

    external = if Map.get(item, :external) == true, do: "  (outside the workspace)", else: ""

    [location, label]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("  ")
    |> Kernel.<>(external)
    |> clip()
  end

  defp render_item(item, _context), do: item |> inspect() |> clip()

  # ---------------------------------------------------------------- helpers

  defp known(operation) when is_binary(operation) do
    if operation in @operations,
      do: :ok,
      else: {:error, {:unknown_operation, operation}}
  end

  defp known(operation), do: {:error, {:unknown_operation, inspect(operation)}}

  defp relative(path, context), do: Path.relative_to(path, context.scope.root)

  defp integer(value) when is_integer(value) and value >= 0, do: value
  defp integer(_other), do: 0

  defp plural(1, word), do: word
  defp plural(_count, word), do: word <> "s"

  defp clip(text) when byte_size(text) <= 400, do: String.replace(text, "\n", " ")
  defp clip(text), do: clip(binary_part(text, 0, 400) <> "…")

  defp describe({:unknown_operation, operation}),
    do: "`#{operation}` is not an operation. Use one of: #{Enum.join(@operations, ", ")}."

  defp describe(:disabled), do: "code intelligence is switched off on this node"
  defp describe(:read_only_sandbox), do: "this session runs with sandbox_mode: read_only"
  defp describe(:nothing_to_rename), do: "the language server proposed no edits for that position"

  defp describe(:broken),
    do: "the language server for this file failed and is not being respawned"

  defp describe({:server_unavailable, server_id, hint}),
    do: "no `#{server_id}` on this host. #{hint}"

  defp describe({:unsupported_language, extension}),
    do: "no language server is registered for `#{extension}` files"

  defp describe({:rename_outside_workspace, path}),
    do:
      "the rename would change #{path}, which is outside this session's workspace. Nothing was written."

  defp describe({:rename_failed, message}), do: "the rename request failed: #{message}"

  defp describe({:multiline_rename_edit, line}),
    do: "the server returned a multi-line edit at line #{line}, which this tool does not apply"

  defp describe({:unreadable, path, reason}), do: "#{path}: #{:file.format_error(reason)}"
  defp describe(reason), do: Paths.describe_error(reason)
end
