defmodule Ouroboros.Web.TranscriptExportController do
  @moduledoc """
  W3.2. One session's conversation as a file: plain text, or the events themselves.

  Port of `tui/src/ui/export.rs`, which is where the two forms and the reason for both are
  written down. Not a LiveView for the same reason `Ouroboros.Web.AuditBundleController`
  is not: it answers bytes, and it sits inside the authenticated scope so the cookie that
  opened the deck is the only thing that opens it.

  ## The events come from the gateway, not from the open LiveView

  A download is its own request with its own connection, and the deck's held window is a
  fact about one browser tab. So this reads the session through `interactive.replay` —
  `Ouroboros.Web.Call` like everything else — and builds an `Ouroboros.Web.Watch` out of
  the answer, which is what gives it the same floor inference, the same dividers and the
  same projection the page draws from. One reading, two renderings.

  ## Held in memory, and how much of it

  W3 fix wave (L3). The whole body is built before a byte is sent — `send_resp/3`, not
  `send_chunked/2` — so at the ceiling below this is roughly **ten megabytes** of iodata
  in this connection's process, once. That is the trade this route makes on purpose: one
  reading of the session produces both forms, the floor inference is the `Watch`'s own,
  and nothing is written to disk. A session past the ceiling does not grow it; the export
  stops and says it stopped.

  ## The bound, stated

  `interactive.replay` answers at most `Ouroboros.Gateway.Methods.Contract.replay_limit/0`
  events per call (500), so this pages from an exclusive cursor until a page comes back
  short — and stops at `#{40}` pages either way. That ceiling is not a detail to leave in
  the code: the text form's footer names how much is in the file and both forms carry an
  `x-ouroboros-export-extent` header saying it, because an export that looked complete and
  was not is worse than no export at all.

  ## Two forms, and what each promises

  * **text** — the same cells `Ouroboros.Web.Transcript.project/1` produces, with the
    render-time caps and the chrome gone, and a last line that is the only place this file
    makes a claim about completeness.
  * **ndjson** — one held event per line, exactly as `Ouroboros.Gateway.Wire` framed it,
    keys sorted so two exports of one session are the same bytes. **Nothing is added and
    nothing is reshaped**: a payload leaf the gateway excerpted travels as
    `{"_excerpt": …, "_bytes": n}`, because that is what a client was sent. Rewriting it as
    the prefix alone would produce a file that looked whole and was not.

  ## Scope

  `interactive.replay` is a read-scope method, so a read-scope endpoint exports exactly as
  an operate one does. `Ouroboros.Web.Call` is still the only thing that decides that: this
  module asks for the method and renders whatever answer comes back.
  """

  use Phoenix.Controller, formats: []

  import Plug.Conn

  alias Ouroboros.EventPresentation, as: Presentation
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Transcript.Entry
  alias Ouroboros.Web.Transcript.ToolSummary
  alias Ouroboros.Web.Transcript.Tools
  alias Ouroboros.Web.Watch

  # The planes this surface knows. A path segment is browser input and is matched against
  # this rather than turned into an atom.
  @planes %{"interactive" => :interactive}

  # How many `interactive.replay` pages one export will ask for. The product with the
  # method's own limit is the ceiling, and the file says where it stopped.
  @max_pages 40

  def show(conn, %{"plane" => plane, "id" => id} = params) do
    format = format_of(params)

    with {:ok, _plane} <- Map.fetch(@planes, plane),
         true <- is_binary(id) and id != "",
         {:ok, watch, truncated?} <- collect(conn, id) do
      {body, type, extension} =
        case format do
          :ndjson -> {ndjson(watch), "application/x-ndjson", "ndjson"}
          :text -> {text(watch, id, truncated?), "text/plain; charset=utf-8", "txt"}
        end

      conn
      |> put_resp_content_type(type, nil)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("x-ouroboros-export-extent", extent(watch, truncated?))
      |> put_resp_header(
        "content-disposition",
        ~s(attachment; filename="ouroboros-#{plane}-#{stem(id)}.#{extension}")
      )
      |> send_resp(200, body)
    else
      # The runtime's own words, under the status its own code means: a session this node
      # does not hold is a 404 and a runtime that could not answer is a 502. Mapping them
      # to one number would make a missing session look like an outage.
      {:error, :not_found, message} ->
        refuse(conn, 404, message)

      {:error, :upstream, message} ->
        refuse(conn, 502, message)

      _unknown ->
        refuse(conn, 404, "No such session on this runtime.")
    end
  end

  defp kind(code) do
    if code == Ouroboros.Gateway.Methods.code(:not_found), do: :not_found, else: :upstream
  end

  # An unknown `format` is the default rather than a refusal: the parameter names a
  # rendering, and a link that lost its query string should still hand back the transcript.
  defp format_of(%{"format" => "ndjson"}), do: :ndjson
  defp format_of(_params), do: :text

  defp refuse(conn, status, message) do
    conn
    |> put_resp_content_type("text/plain; charset=utf-8", nil)
    |> put_resp_header("cache-control", "no-store")
    |> send_resp(status, message <> "\n")
  end

  # ------------------------------------------------------------------------------------
  # Reading
  # ------------------------------------------------------------------------------------

  defp collect(conn, id) do
    scope = Config.for_endpoint(conn.private.phoenix_endpoint).scope
    session = conn.private[:ouroboros_web_session]

    page(scope, session, id, Watch.new(retain_history: true), 0, @max_pages)
  end

  defp page(_scope, _session, _id, watch, _cursor, 0), do: {:ok, watch, true}

  defp page(scope, session, id, watch, cursor, pages) do
    params = %{"id" => id, "cursor" => cursor, "limit" => Contract.replay_limit()}

    case Call.call(scope, "interactive.replay", params, session: session) do
      {:ok, events} when is_list(events) ->
        watch = Watch.backlog(watch, cursor, events)

        cond do
          # Short page: the runtime has nothing above this cursor.
          length(events) < Contract.replay_limit() -> {:ok, watch, false}
          Watch.newest(watch) <= cursor -> {:ok, watch, false}
          true -> page(scope, session, id, watch, Watch.newest(watch), pages - 1)
        end

      # The one upstream detail a client acts on rather than displays: history at or below
      # the floor is gone, so the export resumes there and the file says so.
      {:error, _code, _message, %{"reason" => "cursor_pruned", "floor" => floor}}
      when is_integer(floor) and floor > cursor ->
        page(scope, session, id, Watch.raise_floor(watch, floor), floor, pages - 1)

      {:error, code, message} ->
        {:error, kind(code), message}

      {:error, code, message, _data} ->
        {:error, kind(code), message}

      _unreadable ->
        {:error, :upstream, "The runtime answered a replay this build cannot read."}
    end
  end

  # ------------------------------------------------------------------------------------
  # NDJSON
  # ------------------------------------------------------------------------------------

  defp ndjson(watch) do
    watch
    |> Watch.entries()
    |> Enum.flat_map(fn
      %Entry.Event{event: event} -> [Presentation.encode_json(Wire.to_json(event)), "\n"]
      _divider -> []
    end)
    |> IO.iodata_to_binary()
  end

  # ------------------------------------------------------------------------------------
  # Text
  # ------------------------------------------------------------------------------------

  defp text(watch, id, truncated?) do
    entries = Watch.entries(watch)
    cells = Transcript.project(entries)

    body =
      case cells do
        [] -> ["Nothing has happened in this session yet.\n"]
        cells -> Enum.map(cells, &block/1)
      end

    IO.iodata_to_binary([header(watch, id), body, footer(watch, truncated?)])
  end

  defp header(watch, id) do
    [
      rule(),
      "ouroboros transcript · ",
      id,
      "\n",
      "#{Watch.size(watch)} events held#{range(watch)}\n",
      if(Watch.ended?(watch), do: "ended: #{watch.ended}\n", else: []),
      rule(),
      "\n"
    ]
  end

  # The last line, and the only place this file makes a claim about completeness.
  defp footer(watch, truncated?) do
    floor = Watch.floor(watch)

    [
      rule(),
      if floor > 0 do
        "incomplete: the runtime no longer retains all history through sequence #{floor}; " <>
          "previously received events are included where available\n"
      else
        "complete: no history was dropped from this session\n"
      end,
      if truncated? do
        "this export stopped at #{@max_pages * Contract.replay_limit()} events, which is " <>
          "this page's own ceiling; earlier or later events exist that are not in the file\n"
      else
        []
      end,
      if watch.undecodable > 0 do
        "#{watch.undecodable} event(s) this build could not decode are counted, not shown\n"
      else
        []
      end
    ]
  end

  # W3 fix wave (L2). **ASCII.** This is a header value, and a header is bytes: the
  # interpunct and the en dash the text form uses are two- and three-byte UTF-8 sequences
  # that a reader following RFC 9110's `field-value` grammar is entitled to refuse or
  # mangle. The file's own prose keeps its typography; the header does not need it.
  defp extent(watch, truncated?) do
    "#{Watch.size(watch)} events#{ascii_range(watch)}" <>
      if(Watch.floor(watch) > 0,
        do: "; nothing at or below #{Watch.floor(watch)} is in the file",
        else: ""
      ) <> if(truncated?, do: "; cut at this page's own ceiling", else: "")
  end

  defp ascii_range(watch) do
    case {Watch.floor(watch), Watch.newest(watch)} do
      {_floor, 0} -> ""
      {floor, newest} -> "; sequences #{floor + 1}-#{newest}"
    end
  end

  defp range(watch) do
    case {Watch.floor(watch), Watch.newest(watch)} do
      {_floor, 0} -> ""
      {floor, newest} -> " · sequences #{floor + 1}–#{newest}"
    end
  end

  defp rule, do: String.duplicate("─", 60) <> "\n"

  defp label(text), do: [text, "\n"]
  defp paragraph(text), do: [String.trim_trailing(to_string(text)), "\n\n"]

  # Pre-formatted content, one source line per output line: re-wrapping a unified diff
  # destroys it, and re-wrapping a stack trace turns a copyable artefact into something
  # that has to be repaired by hand (`tui/src/ui/export.rs:20-25`).
  defp verbatim(text) do
    text
    |> to_string()
    |> String.trim_trailing("\n")
    |> String.split("\n")
    |> Enum.map(&[&1, "\n"])
    |> Kernel.++(["\n"])
  end

  defp block(%Cell.Message{speaker: :you, text: text, images: images}) do
    [
      label("you"),
      paragraph(text),
      Enum.map(images, fn image ->
        paragraph(
          "[Image: #{image["display_name"] || "image"} · #{image["width"]} × #{image["height"]} · #{image["id"]}]"
        )
      end)
    ]
  end

  defp block(%Cell.Message{speaker: :agent, text: text, streaming: streaming}),
    do: [label(if(streaming, do: "agent · still writing", else: "agent")), paragraph(text)]

  defp block(%Cell.Thinking{text: text}), do: [label("thinking"), paragraph(text)]

  defp block(%Cell.Tool{} = tool) do
    summary = Tools.summarise(tool)
    [label("#{tool.name} · #{tool.state} · #{ToolSummary.line(summary)}"), "\n"]
  end

  # Grouping is a *display* decision. The export writes every grouped call out in full: a
  # reader who asked for the file asked for the calls, not for the count the pane showed
  # instead of them.
  defp block(%Cell.Exploration{} = group) do
    [
      label("exploration · #{Cell.Exploration.total(group)} call(s)"),
      Enum.map(group.calls, fn call ->
        label("  " <> ToolSummary.line(Tools.summarise(call)))
      end),
      if(group.overflow > 0, do: label("  and #{group.overflow} more"), else: []),
      "\n"
    ]
  end

  defp block(%Cell.CommandOutput{text: text}), do: [label("command output"), verbatim(text)]
  defp block(%Cell.File{path: path, kind: kind}), do: label("file · #{kind} #{path}")

  # The patch the provider sent, verbatim. Not the parse: the parse is what the *counts*
  # come from, and a diff re-emitted from it would be this surface's rendering of a change
  # rather than the change.
  defp block(%Cell.Diff{diff: %{text: text}}) when is_binary(text),
    do: [label("diff"), verbatim(text)]

  defp block(%Cell.Diff{}), do: label("diff · this build could not read the patch")

  defp block(%Cell.DiffStat{} = stat),
    do: label("#{stat.files} file(s) · +#{stat.additions} −#{stat.deletions}")

  defp block(%Cell.Status{label: text, detail: detail}),
    do: label(join(text, detail))

  defp block(%Cell.ChatNote{text: text}), do: [label(text), "\n"]

  defp block(%Cell.Runtime{} = runtime),
    do: [label(Cell.Runtime.text(runtime)), "\n"]

  defp block(%Cell.Plan{plan: plan}), do: [label("plan"), paragraph(plan_text(plan))]

  defp block(%Cell.Usage{usage: usage}), do: label("usage · " <> usage_line(usage))

  defp block(%Cell.Subagent{} = child),
    do: label("child agent · #{child.description || child.task_id || "unnamed"}")

  defp block(%Cell.Divider{text: text}), do: ["\n", label("— " <> text), "\n"]

  # A cell kind this build renders and this function has not been taught is a hole in the
  # file, so it is named rather than skipped.
  defp block(%module{}), do: label("[" <> inspect(module) <> "]")

  defp join(head, ""), do: head
  defp join(head, detail), do: head <> " — " <> detail

  defp plan_text(%{steps: steps, explanation: explanation}) when is_list(steps) do
    rows =
      Enum.map_join(steps, "\n", fn step ->
        "  " <>
          Presentation.PlanStatus.glyph(Map.get(step, :status)) <>
          " " <> to_string(Map.get(step, :text))
      end)

    case explanation do
      nil -> rows
      "" -> rows
      said -> said <> "\n" <> rows
    end
  end

  defp plan_text(plan), do: Presentation.compact(plan)

  # Absent fields stay absent: a zero this surface invented would be indistinguishable
  # from a zero a provider measured.
  defp usage_line(%{} = usage) do
    [:input_tokens, :output_tokens, :cached_tokens, :total_tokens, :cost_usd]
    |> Enum.flat_map(fn key ->
      case Map.get(usage, key) do
        nil -> []
        value -> ["#{key}=#{value}"]
      end
    end)
    |> case do
      [] -> "nothing reported"
      parts -> Enum.join(parts, " ")
    end
  end

  defp usage_line(usage), do: Presentation.compact(usage)

  # A session id becomes part of a filename, so only a name gets to describe one.
  defp stem(id) do
    case String.replace(id, ~r/[^A-Za-z0-9._-]/, "-") do
      "" -> "session"
      safe -> String.slice(safe, 0, 80)
    end
  end
end
