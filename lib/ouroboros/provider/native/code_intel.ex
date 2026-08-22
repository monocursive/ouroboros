defmodule Ouroboros.Provider.Native.CodeIntel do
  @moduledoc """
  The native loop's whole relationship with `Ouroboros.CodeIntel`: a baseline before a
  write, bounded feedback after one, and `rename`.

  ## The feedback policy, and why each clause is here

  Every element below is copied from something that shipped, and most of them exist
  because the naive version produced a documented failure (R4 §2, Synthesis (a)):

    * **Edited files only.** Project-wide diagnostics after every edit is how a UI
      stalls (Claude Code v2.1.216).
    * **New-only, against a pre-edit baseline.** Pre-existing errors otherwise drown the
      one the edit just caused (Hermes).
    * **Version-gated, ≤ 5 s.** A diagnostic that describes the file *before* the write
      made Claude Code re-read files until v2.1.107 fixed it. `Ouroboros.CodeIntel`
      answers `{:pending, version}` rather than serving a stale cache, and the wait is
      bounded because a language server that is indexing must not be able to hold a turn.
    * **Errors always, warnings only when there are at most #{3} of them.** Gemini's
      unmerged PR gated `Edit` to errors; three is the point past which a warning list
      is a formatter's opinion rather than a finding.
    * **Capped at #{20}, then `+N more`.**
    * **`Edit applied.` on its own line, first.** OpenCode issue #9102: agents that saw
      diagnostics with no success line read the edit as failed and retried it. This is
      the single most important line in this module.
    * **Never blocking, never an error.** Everything below returns text or nothing. A
      language server cannot fail a write here, by construction: the write already
      happened before any of this runs.

  ## Silence versus "no LSP data"

  A file whose language has no server registered at all, or a node with code
  intelligence switched off, gets **nothing appended** — that is R4's silent fallback,
  and a note on every README edit would be noise the model has to read. A file whose
  server exists but did not answer — starting, broken, over budget, or simply slow —
  gets `(no LSP data for this file)`, because there the absence of findings is not
  evidence of correctness and the model should know the difference.
  """

  alias Ouroboros.CodeIntel
  alias Ouroboros.CodeIntel.Config
  alias Ouroboros.CodeIntel.Lsp.Server
  alias Ouroboros.CodeIntel.LspPool
  alias Ouroboros.CodeIntel.Registry

  @applied_line "Edit applied."
  @no_data "(no LSP data for this file)"
  @wait_ms 5_000
  @max_items 20
  @max_warnings 3
  @rename_timeout_ms 15_000

  @type baseline :: %{optional(String.t()) => {:ok, map()} | {:error, term()}}

  @doc """
  Captures the pre-edit diagnostics for every path a write is about to touch.

  Cheap and total: paths with no server contribute an error entry that
  `feedback/3` reads as "there was never anything to compare against".
  """
  @spec baseline([String.t()], keyword()) :: baseline()
  def baseline(paths, opts \\ [])

  def baseline(paths, opts) when is_list(paths) do
    if Config.enabled?() do
      paths
      |> Enum.uniq()
      |> Map.new(fn path -> {path, baseline_for(path, pool_opts(opts))} end)
    else
      %{}
    end
  end

  def baseline(_paths, _opts), do: %{}

  # A file that does not exist yet has no diagnostics, so its baseline is empty rather
  # than missing. The distinction matters: `:no_baseline` suppresses the report entirely,
  # and suppressing it for every newly created file would mean the one case where *every*
  # finding is genuinely new is the one case nothing is said.
  defp baseline_for(path, pool_opts) do
    if File.exists?(path),
      do: safely(fn -> CodeIntel.baseline(path, pool_opts) end),
      else: {:ok, %{items: [], version: 0, absent: true}}
  end

  @doc """
  The text appended to a successful `edit`/`write`/`apply_patch` result.

  `""` when nothing should be said at all. Otherwise it always begins with
  `#{@applied_line}` on its own line, and everything after that line is the diagnostics
  report for the paths that were written.
  """
  @spec feedback([String.t()], baseline(), keyword()) :: String.t()
  def feedback(paths, baselines, opts \\ [])

  def feedback([], _baselines, _opts), do: ""

  def feedback(paths, baselines, opts) do
    if Config.enabled?() do
      reports =
        paths
        |> Enum.uniq()
        |> Enum.map(&report(&1, Map.get(baselines, &1), opts))
        |> Enum.reject(&(&1 == :silent))

      case reports do
        [] -> ""
        found -> "\n" <> @applied_line <> "\n" <> Enum.join(found, "\n")
      end
    else
      ""
    end
  end

  # The pool admits a file only under a root it was told about. A session's workspace was
  # admitted by the lease that started it, so the native agent names it on every call —
  # without this, a node that configured no `:workspace_allowed_roots` (the default) would
  # answer `{:outside_workspace, _}` for every path and no diagnostic would ever appear.
  defp pool_opts(opts) do
    case Keyword.get(opts, :root) do
      root when is_binary(root) and root != "" -> [workspace_root: root]
      _unset -> []
    end
  end

  @doc "The literal line every diagnostics report follows. Public so tests can name it."
  @spec applied_line() :: String.t()
  def applied_line, do: @applied_line

  @doc "The literal fallback. Public for the same reason."
  @spec no_data_line() :: String.t()
  def no_data_line, do: @no_data

  # ---------------------------------------------------------------- one file

  defp report(path, baseline_entry, opts) do
    case safely(fn -> CodeIntel.touch(path, :changed, pool_opts(opts)) end) do
      {:ok, _version} ->
        diagnose(path, baseline_entry, opts)

      {:error, reason} ->
        if silent?(reason), do: :silent, else: line(path, @no_data)
    end
  end

  defp diagnose(path, baseline_entry, opts) do
    wait = Keyword.get(opts, :wait_ms, @wait_ms)

    case safely(fn -> CodeIntel.diagnostics(path, [wait_ms: wait] ++ pool_opts(opts)) end) do
      {:ok, %{items: items}} ->
        render(path, new_items(items, baseline_entry))

      {:pending, _version} ->
        line(path, @no_data)

      {:error, reason} ->
        if silent?(reason), do: :silent, else: line(path, @no_data)
    end
  end

  # The baseline is a set of `(severity, code, message, range)` keys. Comparing on the
  # range as well as the message is deliberate: an unchanged error that moved down three
  # lines because the edit added three lines *is* new information about where it is, but
  # reporting it would make every insertion look like it broke something. So the range is
  # excluded from the key and the message plus code carries identity.
  defp new_items(items, {:ok, %{items: previous}}) do
    seen = MapSet.new(previous, &key/1)
    Enum.reject(items, &MapSet.member?(seen, key(&1)))
  end

  # No usable baseline means everything would look new. Reporting a file's entire
  # pre-existing error list because the baseline call failed is exactly the noise this
  # policy exists to prevent, so nothing is reported and the file says so.
  defp new_items(_items, _no_baseline), do: :no_baseline

  defp key(item), do: {item.severity, item.code, item.message}

  defp render(path, :no_baseline), do: line(path, @no_data)

  defp render(path, []), do: line(path, "no new diagnostics")

  defp render(path, items) do
    errors = Enum.filter(items, &(&1.severity == :error))
    warnings = Enum.filter(items, &(&1.severity == :warning))

    selected = errors ++ if length(warnings) <= @max_warnings, do: warnings, else: []

    case selected do
      [] ->
        line(path, "#{length(warnings)} new warnings, not listed")

      chosen ->
        kept = Enum.take(chosen, @max_items)
        more = length(chosen) - length(kept)

        header =
          "#{path}: #{length(errors)} new #{plural(length(errors), "error")}" <>
            warning_note(warnings, selected)

        body = Enum.map_join(kept, "\n", &format_item/1)
        suffix = if more > 0, do: "\n  +#{more} more", else: ""

        header <> "\n" <> body <> suffix
    end
  end

  defp warning_note([], _selected), do: ""

  defp warning_note(warnings, selected) do
    if Enum.any?(selected, &(&1.severity == :warning)),
      do: ", #{length(warnings)} new #{plural(length(warnings), "warning")}",
      else: ", #{length(warnings)} new #{plural(length(warnings), "warning")} not listed"
  end

  defp format_item(item) do
    location = "#{item.range.start.line + 1}:#{item.range.start.character + 1}"
    code = if item.code, do: " [#{item.code}]", else: ""
    "  #{location} #{severity_label(item.severity)}#{code}: #{clip(item.message)}"
  end

  defp severity_label(:error), do: "error"
  defp severity_label(:warning), do: "warning"
  defp severity_label(other), do: to_string(other || "note")

  defp line(path, text), do: "#{path}: #{text}"

  defp plural(1, word), do: word
  defp plural(_count, word), do: word <> "s"

  defp clip(message) when byte_size(message) <= 300, do: String.replace(message, "\n", " ")
  defp clip(message), do: clip(binary_part(message, 0, 300) <> "…")

  # "There was never going to be data here" — a language with no registered server, a
  # server this host has not installed, a path outside a workspace, a file too large to
  # synchronise. None of these will change during the session, so a note on every edit
  # would be a permanent line of noise the model has to read. Everything else — starting,
  # broken, over budget, timed out — gets `#{@no_data}`, because there the absence of
  # findings is not evidence of correctness.
  defp silent?(:disabled), do: true
  defp silent?({:unsupported_language, _extension}), do: true
  defp silent?({:server_unavailable, _server_id, _hint}), do: true
  defp silent?({:outside_workspace, _path}), do: true
  defp silent?({:root_outside_workspace, _forced, _root}), do: true
  defp silent?({:no_project_root, _language, _markers}), do: true
  defp silent?({:document_too_large, _size, _limit}), do: true
  defp silent?({:not_a_regular_file, _path}), do: true
  defp silent?(_reason), do: false

  # ---------------------------------------------------------------- rename

  @doc """
  Previews a workspace-wide rename: the edits a language server would make, and nothing
  applied.

  `{:ok, %{edits: [%{path:, replacements: [...]}], count: n}}`. Serena's own evaluation
  is the reason this exists as one call: a cross-file rename it does in one, text editing
  does in nine.
  """
  @spec rename_preview(String.t(), non_neg_integer(), non_neg_integer(), String.t()) ::
          {:ok, map()} | {:error, term()}
  def rename_preview(path, line, character, new_name) do
    with :ok <- usable_name(new_name),
         {:ok, spec} <- Registry.resolve(path),
         {:ok, server} <- LspPool.checkout(LspPool, spec),
         {:ok, _version} <- LspPool.ensure_open(LspPool, spec),
         {:ok, result} <-
           Server.request(
             server,
             "textDocument/rename",
             %{
               "textDocument" => %{"uri" => Server.uri(spec.path)},
               "position" => %{"line" => line, "character" => character},
               "newName" => new_name
             },
             @rename_timeout_ms
           ) do
      {:ok, workspace_edit(result, spec.root)}
    end
  rescue
    error -> {:error, {:rename_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:rename_failed, inspect(reason)}}
  end

  @doc """
  Applies a preview produced by `rename_preview/4`, in memory, and returns the new
  content per file.

  It writes nothing. The caller writes, because the caller is the one that snapshots for
  the checkpoint and emits `file_change` — a rename that wrote behind the loop's back
  would be the one edit in this provider with no diff and no rewind.
  """
  @spec apply_preview(map()) ::
          {:ok, [%{path: String.t(), before: String.t(), after: String.t()}]} | {:error, term()}
  def apply_preview(%{edits: edits}) do
    Enum.reduce_while(edits, {:ok, []}, fn edit, {:ok, acc} ->
      case File.read(edit.path) do
        {:ok, content} ->
          case splice(content, edit.replacements) do
            {:ok, updated} ->
              {:cont, {:ok, acc ++ [%{path: edit.path, before: content, after: updated}]}}

            {:error, _reason} = error ->
              {:halt, error}
          end

        {:error, reason} ->
          {:halt, {:error, {:unreadable, edit.path, reason}}}
      end
    end)
  end

  def apply_preview(_other), do: {:error, :not_a_rename_preview}

  # LSP ranges are 0-based line/character over UTF-16 code units. Applying them from the
  # end backwards is what keeps earlier offsets valid while later ones are rewritten;
  # doing it forwards is the classic way a multi-edit rename corrupts a file.
  defp splice(content, replacements) do
    lines = String.split(content, "\n")

    replacements
    |> Enum.sort_by(fn r -> {r.start.line, r.start.character} end, :desc)
    |> Enum.reduce_while({:ok, lines}, fn replacement, {:ok, lines} ->
      case replace_range(lines, replacement) do
        {:ok, updated} -> {:cont, {:ok, updated}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, lines} -> {:ok, Enum.join(lines, "\n")}
      {:error, _reason} = error -> error
    end
  end

  defp replace_range(lines, %{start: start_position, end: end_position, text: text}) do
    cond do
      start_position.line != end_position.line ->
        {:error, {:multiline_rename_edit, start_position.line}}

      start_position.line >= length(lines) ->
        {:error, {:rename_edit_past_end, start_position.line}}

      true ->
        line = Enum.at(lines, start_position.line)
        head = String.slice(line, 0, start_position.character)
        tail = String.slice(line, end_position.character, String.length(line))
        {:ok, List.replace_at(lines, start_position.line, head <> text <> tail)}
    end
  end

  defp workspace_edit(nil, _root), do: %{edits: [], count: 0}

  defp workspace_edit(result, root) when is_map(result) do
    edits =
      cond do
        is_map(result["changes"]) ->
          Enum.map(result["changes"], fn {uri, list} -> file_edit(uri, list, root) end)

        is_list(result["documentChanges"]) ->
          Enum.flat_map(result["documentChanges"], fn
            %{"textDocument" => %{"uri" => uri}, "edits" => list} -> [file_edit(uri, list, root)]
            _other -> []
          end)

        true ->
          []
      end
      |> Enum.reject(&(&1.replacements == []))

    %{edits: edits, count: Enum.reduce(edits, 0, &(length(&1.replacements) + &2))}
  end

  defp workspace_edit(_result, _root), do: %{edits: [], count: 0}

  defp file_edit(uri, list, root) do
    path =
      case Server.path_from_uri(to_string(uri)) do
        {:ok, resolved} -> resolved
        :error -> nil
      end

    %{
      path: path,
      relative: if(is_binary(path), do: Path.relative_to(path, root), else: to_string(uri)),
      replacements:
        list
        |> List.wrap()
        |> Enum.flat_map(fn
          %{"range" => %{"start" => s, "end" => e}, "newText" => text} ->
            [%{start: position(s), end: position(e), text: to_string(text)}]

          _other ->
            []
        end)
    }
  end

  defp position(%{"line" => line, "character" => character})
       when is_integer(line) and is_integer(character),
       do: %{line: max(line, 0), character: max(character, 0)}

  defp position(_other), do: %{line: 0, character: 0}

  defp usable_name(name) when is_binary(name) do
    trimmed = String.trim(name)

    cond do
      trimmed == "" -> {:error, :empty_new_name}
      byte_size(trimmed) > 200 -> {:error, {:new_name_too_long, byte_size(trimmed)}}
      String.contains?(trimmed, "\n") -> {:error, :new_name_has_newline}
      true -> :ok
    end
  end

  defp usable_name(other), do: {:error, {:invalid_new_name, inspect(other)}}

  # Every call into `Ouroboros.CodeIntel` is wrapped, not because that module raises —
  # it documents that it does not — but because this is the one seam where a subsystem's
  # failure must not reach a file write that already succeeded.
  defp safely(function) do
    function.()
  rescue
    error -> {:error, {:code_intel_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:code_intel_failed, inspect(reason)}}
  end
end
