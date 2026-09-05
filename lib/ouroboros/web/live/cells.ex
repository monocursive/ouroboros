defmodule Ouroboros.Web.Live.Cells do
  @moduledoc """
  The projection's cells, as pixels.

  `Ouroboros.Web.Transcript` decides **what a cell says**; this module decides what it
  looks like. That split is load-bearing: the projection is locked to the Rust corpus by
  `Ouroboros.Web.CorpusParityTest`, so a word this module needed and invented would be a
  word the terminal client does not say. Nothing here computes a verb, a subject, an
  outcome, a count, or a status word — every one of those is read off the cell.

  ## The one colour rule, restated because this is where it would be broken

  `--attention-green` means "a person is needed here" and nothing else. Not success, not
  "done", not a checkmark, not the added lines of a diff. A completed tool call, a
  succeeded subagent, and a `+40` file are all **ink**; the emphasis a diff addition
  carries is a neutral one. The green appears in this surface in exactly one place, the
  needs-you glyph in the rail, and if it appears anywhere else that is a bug.

  ## Collapse budgets are the desktop's, unchanged

  Tool output folds at 12 lines into head 7 / tail 4
  (`docs/WEB.md` §4). Exploration groups fold to one row. Both expand, keyed by something
  stable — a `call_id`, a `task_id` — so a poll or a live delta cannot close a block a
  reader opened.

  ## Agent prose is untrusted

  Message text goes through `Ouroboros.Web.Live.Markdown`, which builds HTML from an
  allowlist. Everything else on this page is escaped by HEEx. Nothing here calls
  `raw/1` on anything a provider sent.
  """

  use Phoenix.Component

  alias Ouroboros.Web.Live.Markdown
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Transcript.Tools

  # The desktop's budget, ported: a body longer than this shows its head and its tail.
  @body_lines 12
  @body_head 7
  @body_tail 4

  @doc "The row budget a tool body folds at, and how it splits."
  @spec body_budget() :: {pos_integer(), pos_integer(), pos_integer()}
  def body_budget, do: {@body_lines, @body_head, @body_tail}

  @doc """
  One cell, dispatched on its struct.

  `expanded` is the set of keys a reader has opened; `key/2` mints them.
  """
  attr :cell, :any, required: true
  attr :index, :integer, required: true
  attr :expanded, :any, required: true
  attr :plane, :atom, required: true
  attr :session_id, :string, required: true

  def cell(%{cell: %Cell.Message{}} = assigns), do: message(assigns)
  def cell(%{cell: %Cell.Thinking{}} = assigns), do: thinking(assigns)
  def cell(%{cell: %Cell.Plan{}} = assigns), do: plan(assigns)
  def cell(%{cell: %Cell.Usage{}} = assigns), do: usage(assigns)
  def cell(%{cell: %Cell.Tool{}} = assigns), do: tool(assigns)
  def cell(%{cell: %Cell.Exploration{}} = assigns), do: exploration(assigns)
  def cell(%{cell: %Cell.CommandOutput{}} = assigns), do: command_output(assigns)
  def cell(%{cell: %Cell.File{}} = assigns), do: file(assigns)
  def cell(%{cell: %Cell.Image{}} = assigns), do: image(assigns)
  def cell(%{cell: %Cell.Diff{}} = assigns), do: diff(assigns)
  def cell(%{cell: %Cell.DiffStat{}} = assigns), do: diffstat(assigns)
  def cell(%{cell: %Cell.Status{}} = assigns), do: status(assigns)
  def cell(%{cell: %Cell.ChatNote{}} = assigns), do: chat_note(assigns)
  def cell(%{cell: %Cell.Runtime{}} = assigns), do: runtime(assigns)
  def cell(%{cell: %Cell.Subagent{}} = assigns), do: subagent(assigns)
  def cell(%{cell: %Cell.Divider{}} = assigns), do: divider(assigns)

  @doc """
  The key one collapsible block is remembered by.

  A `call_id` and a `task_id` are the runtime's own identifiers and survive a re-projection;
  an index does not, so the cells that have no identifier of their own say so by using one
  and are honestly a little fragile under a floor raise. The two blocks a reader actually
  sits inside — a tool's output and a child agent's row — are the stable ones.
  """
  @spec key(atom(), term()) :: String.t()
  def key(kind, id), do: "#{kind}:#{id}"

  # ------------------------------------------------------------------------------------
  # Messages
  # ------------------------------------------------------------------------------------

  defp message(%{cell: %Cell.Message{speaker: :you}} = assigns) do
    ~H"""
    <div class="ouro-cell ouro-said ouro-said-you">
      <div class="ouro-bubble">{@cell.text}</div>
    </div>
    """
  end

  defp message(assigns) do
    assigns = assign(assigns, :html, Markdown.to_html(assigns.cell.text))

    ~H"""
    <div class={["ouro-cell", "ouro-said", "ouro-said-agent", @cell.streaming && "ouro-streaming"]}>
      <div class="ouro-prose">{@html}</div>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Thinking — three states, and the projection decided which
  # ------------------------------------------------------------------------------------

  defp thinking(%{cell: %Cell.Thinking{state: :collapsed}} = assigns) do
    ~H"""
    <div class="ouro-cell ouro-thinking ouro-thinking-collapsed">
      <span class="ouro-quiet-label">thought</span>
      <span class="ouro-quiet">{@cell.lines} {plural(@cell.lines, "line")}</span>
    </div>
    """
  end

  defp thinking(%{cell: %Cell.Thinking{state: :tail}} = assigns) do
    assigns = assign(assigns, :tail, tail_lines(assigns.cell.text, 3))

    ~H"""
    <div class="ouro-cell ouro-thinking ouro-thinking-tail">
      <span class="ouro-quiet-label">thinking</span>
      <pre class="ouro-thinking-text">{Enum.join(@tail, "\n")}</pre>
    </div>
    """
  end

  defp thinking(assigns) do
    ~H"""
    <div class="ouro-cell ouro-thinking ouro-thinking-full">
      <span class="ouro-quiet-label">thought</span>
      <pre class="ouro-thinking-text">{@cell.text}</pre>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Tools
  # ------------------------------------------------------------------------------------

  defp tool(assigns) do
    summary = Tools.summarise(assigns.cell)
    body = output_lines(assigns.cell.output)
    open = MapSet.member?(assigns.expanded, key(:tool, assigns.cell.call_id || assigns.index))

    assigns =
      assigns
      |> assign(:summary, summary)
      |> assign(:body, body)
      |> assign(:open, open)
      |> assign(:block, key(:tool, assigns.cell.call_id || assigns.index))
      |> assign(:elapsed, Cell.Tool.elapsed(assigns.cell))

    ~H"""
    <div class={["ouro-cell", "ouro-tool", "ouro-tool-#{@cell.state}"]}>
      <div class="ouro-tool-row">
        <span class="ouro-tool-mark" aria-hidden="true">{tool_mark(@cell.state)}</span>
        <span class="ouro-tool-verb">{@summary.verb}</span>
        <span class="ouro-tool-subject">{@summary.subject}</span>
        <span :if={@summary.outcome != ""} class="ouro-tool-outcome">{@summary.outcome}</span>
        <span :if={@elapsed} class="ouro-tool-elapsed">{Transcript.duration(@elapsed)}</span>
      </div>
      <.body :if={@body != []} lines={@body} open={@open} block={@block} />
    </div>
    """
  end

  # A running call is an open mark, a settled one is closed, a failed one is a cross. Words
  # rather than colour would be the projection's job; this is the glyph beside them.
  defp tool_mark(:running), do: "◌"
  defp tool_mark(:completed), do: "●"
  defp tool_mark(:failed), do: "✕"

  @doc """
  A monospace block that folds at the budget.

  Head and tail rather than head alone, because the end of a command's output is where its
  verdict is and a fold that hid it would hide the reason a reader opened the block.
  """
  attr :lines, :list, required: true
  attr :open, :boolean, required: true
  attr :block, :string, required: true

  def body(assigns) do
    count = length(assigns.lines)
    over_budget = count > @body_lines
    folded = not assigns.open and over_budget

    assigns =
      assigns
      |> assign(:folded, folded)
      |> assign(:over_budget, over_budget)
      |> assign(:count, count)
      |> assign(:head, if(folded, do: Enum.take(assigns.lines, @body_head), else: assigns.lines))
      |> assign(:tail, if(folded, do: Enum.take(assigns.lines, -@body_tail), else: []))
      |> assign(:hidden, count - @body_head - @body_tail)

    ~H"""
    <div class="ouro-body">
      <pre class="ouro-body-text">{Enum.join(@head, "\n")}</pre>
      <button
        :if={@folded}
        type="button"
        class="ouro-fold"
        phx-click="expand"
        phx-value-block={@block}
      >
        … {@hidden} more {plural(@hidden, "line")}
      </button>
      <pre :if={@folded} class="ouro-body-text">{Enum.join(@tail, "\n")}</pre>
      <button
        :if={@open and @over_budget}
        type="button"
        class="ouro-fold"
        phx-click="collapse"
        phx-value-block={@block}
      >
        fold {@count} {plural(@count, "line")}
      </button>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Exploration — eight filesystem lookups, one row
  # ------------------------------------------------------------------------------------

  defp exploration(assigns) do
    block = key(:explore, assigns.index)

    assigns =
      assigns
      |> assign(:block, block)
      |> assign(:open, MapSet.member?(assigns.expanded, block))
      |> assign(:total, Cell.Exploration.total(assigns.cell))
      |> assign(:failed, Cell.Exploration.failed(assigns.cell))

    ~H"""
    <div class="ouro-cell ouro-explore">
      <button
        type="button"
        class="ouro-explore-row"
        phx-click={if @open, do: "collapse", else: "expand"}
        phx-value-block={@block}
      >
        <span class="ouro-tool-mark" aria-hidden="true">{if @cell.done, do: "●", else: "◌"}</span>
        <span class="ouro-tool-verb">Explored</span>
        <span class="ouro-tool-subject">{@total} {plural(@total, "call")}</span>
        <span :if={@failed > 0} class="ouro-tool-outcome">{@failed} failed</span>
      </button>
      <div :if={@open} class="ouro-explore-calls">
        <div :for={call <- @cell.calls} class="ouro-tool-row">
          <span class="ouro-tool-mark" aria-hidden="true">{tool_mark(call.state)}</span>
          <span class="ouro-tool-line">{Tools.summarise(call) |> summary_line()}</span>
        </div>
        <div :if={@cell.overflow > 0} class="ouro-quiet">
          and {@cell.overflow} more not listed
        </div>
      </div>
    </div>
    """
  end

  defp summary_line(summary), do: Transcript.ToolSummary.line(summary)

  # ------------------------------------------------------------------------------------
  # Command output, files, images
  # ------------------------------------------------------------------------------------

  defp command_output(assigns) do
    assigns =
      assigns
      |> assign(:lines, String.split(assigns.cell.text, "\n"))
      |> assign(:block, key(:command, assigns.index))
      |> assign(:open, MapSet.member?(assigns.expanded, key(:command, assigns.index)))

    ~H"""
    <div class="ouro-cell ouro-command">
      <.body lines={@lines} open={@open} block={@block} />
    </div>
    """
  end

  defp file(assigns) do
    ~H"""
    <div class="ouro-cell ouro-file">
      <span class="ouro-file-kind">{@cell.kind || "changed"}</span>
      <span class="ouro-file-path">{@cell.path}</span>
    </div>
    """
  end

  # The picture where there is a digest to fetch it by, and the projection's own label
  # where there is not. Never both: a caption under a screenshot the reader can see is
  # noise, and the label exists precisely for the case where they cannot.
  defp image(assigns) do
    ~H"""
    <figure class="ouro-cell ouro-image">
      <img
        :if={@cell.sha}
        src={Ouroboros.Web.Route.artifact(@plane, @session_id, @cell.sha)}
        alt={Cell.Image.label(@cell)}
        loading="lazy"
        width={@cell.pixels && elem(@cell.pixels, 0)}
        height={@cell.pixels && elem(@cell.pixels, 1)}
      />
      <figcaption :if={is_nil(@cell.sha)} class="ouro-quiet">{Cell.Image.label(@cell)}</figcaption>
    </figure>
    """
  end

  # ------------------------------------------------------------------------------------
  # Diffs
  # ------------------------------------------------------------------------------------

  defp diff(assigns) do
    assigns = assign(assigns, :parsed, assigns.cell.parsed)

    ~H"""
    <.parsed_diff parsed={@parsed} pending={@cell.pending_approval} />
    """
  end

  @doc """
  One parsed diff, drawn.

  Public because the approval card draws the same patch: a request to write a file and the
  transcript entry for having written it are the same bytes, and two renderers for them
  would be two chances to disagree about what a hunk is. The card parses
  `Approval.Detail`'s text with `Ouroboros.Web.Transcript.Diff.parse/2` and hands the
  result here.
  """
  attr :parsed, :any, required: true
  attr :pending, :boolean, default: false

  def parsed_diff(assigns) do
    ~H"""
    <div class={["ouro-cell", "ouro-diff", @pending && "ouro-diff-pending"]}>
      <div :for={file <- @parsed.files} class="ouro-diff-file">
        <div class="ouro-diff-head">
          <span class="ouro-diff-mark" title={Transcript.DiffFile.label(file)}>
            {Transcript.DiffFile.mark(file)}
          </span>
          <span class="ouro-diff-path">{file.path}</span>
          <span :if={file.old_path} class="ouro-quiet">from {file.old_path}</span>
          <span class="ouro-diff-plus">+{file.additions}</span>
          <span class="ouro-diff-minus">−{file.deletions}</span>
        </div>
        <div :for={hunk <- file.hunks} class="ouro-hunk">
          <div class="ouro-hunk-head">
            <span>{hunk_head(hunk)}</span>
            <span :if={hunk.section != ""} class="ouro-hunk-section">{hunk.section}</span>
          </div>
          <div :for={line <- hunk.lines} class={["ouro-line", "ouro-line-#{line.kind}"]}>
            <span class="ouro-gutter ouro-gutter-old">{line.old_no}</span>
            <span class="ouro-gutter ouro-gutter-new">{line.new_no}</span>
            <span class="ouro-line-mark" aria-hidden="true">{line_mark(line.kind)}</span>
            <span class="ouro-line-text">{line.text}</span>
          </div>
        </div>
      </div>
      <p :if={@parsed.truncated} class="ouro-quiet">
        this diff is longer than the transcript will draw
      </p>
    </div>
    """
  end

  # The hunk's own header, rebuilt rather than quoted: the parse already read these two
  # numbers out of the `@@` line, and rendering the provider's string back would put
  # unparsed provider text on the page.
  defp hunk_head(hunk), do: "@@ −#{hunk.old_start} +#{hunk.new_start} @@"

  defp line_mark(:added), do: "+"
  defp line_mark(:removed), do: "−"
  defp line_mark(:meta), do: "\\"
  defp line_mark(_context), do: " "

  defp diffstat(assigns) do
    ~H"""
    <div class="ouro-cell ouro-diffstat">
      <span>{@cell.files} {plural(@cell.files, "file")}</span>
      <span class="ouro-diff-plus">+{@cell.additions}</span>
      <span class="ouro-diff-minus">−{@cell.deletions}</span>
      <span :if={@cell.in_excerpt} class="ouro-quiet">in the excerpt shown</span>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Status, notes, runtime blocks, subagents, dividers
  # ------------------------------------------------------------------------------------

  defp status(assigns) do
    raw = assigns.cell.detail

    detail =
      cond do
        assigns.cell.tone == :error -> friendly_error(raw)
        assigns.cell.label == "Approval needed" -> "Waiting for your decision."
        is_binary(raw) and (String.starts_with?(raw, "{") or String.starts_with?(raw, "[")) -> ""
        true -> raw
      end

    assigns =
      assigns
      |> assign(:raw_detail, raw)
      |> assign(:detail, detail)
      |> assign(
        :technical?,
        is_binary(raw) and raw != "" and raw != detail
      )

    ~H"""
    <div class={["ouro-cell", "ouro-status", tone(@cell.tone)]}>
      <span class="ouro-status-label">{@cell.label}</span>
      <span :if={@detail != ""} class="ouro-status-detail">{@detail}</span>
      <details :if={@technical?} class="ouro-technical">
        <summary>Technical details</summary>
        <pre>{@raw_detail}</pre>
      </details>
    </div>
    """
  end

  defp friendly_error(detail) when is_binary(detail) do
    down = String.downcase(detail)

    cond do
      String.contains?(down, ["server_is_overloaded", "currently overloaded", "overloaded"]) ->
        "The AI service is temporarily busy. Try the message again."

      String.contains?(down, ["authentication", "unauthorized", "credential", "api key"]) ->
        "The AI provider needs to be connected again."

      true ->
        "The agent stopped unexpectedly."
    end
  end

  defp friendly_error(_detail), do: "The agent stopped unexpectedly."

  defp chat_note(assigns) do
    diagnostic? =
      String.starts_with?(assigns.cell.text, [
        "session started",
        "session ready",
        "session idle",
        "provider event",
        "run started"
      ])

    assigns = assign(assigns, :diagnostic?, diagnostic?)

    ~H"""
    <details :if={@diagnostic?} class="ouro-cell ouro-chat-note ouro-diagnostic">
      <summary>{diagnostic_label(@cell.text)}</summary>
      <span>{@cell.text}</span>
    </details>
    <div :if={not @diagnostic?} class="ouro-cell ouro-chat-note">{@cell.text}</div>
    """
  end

  defp diagnostic_label("session started" <> _), do: "Session opened"
  defp diagnostic_label("session ready" <> _), do: "Agent connected"
  defp diagnostic_label("session idle" <> _), do: "Ready for a message"
  defp diagnostic_label("run started" <> _), do: "Agent started"
  defp diagnostic_label(_), do: "Provider details"

  defp runtime(assigns) do
    ~H"""
    <div class={["ouro-cell", "ouro-runtime", tone(@cell.tone)]}>
      <div class="ouro-runtime-head">
        <span class="ouro-runtime-label">{@cell.label}</span>
        <span :if={@cell.detail != ""} class="ouro-runtime-detail">{@cell.detail}</span>
      </div>
      <pre :if={@cell.body != []} class="ouro-body-text">{Enum.join(@cell.body, "\n")}</pre>
    </div>
    """
  end

  defp subagent(assigns) do
    block = key(:subagent, assigns.cell.task_id || assigns.index)

    assigns =
      assigns
      |> assign(:block, block)
      |> assign(:open, MapSet.member?(assigns.expanded, block))
      |> assign(:rows, Cell.Subagent.rows(assigns.cell))

    ~H"""
    <div class={["ouro-cell", "ouro-subagent", tone(Cell.Subagent.tone(@cell))]}>
      <button
        type="button"
        class="ouro-subagent-row"
        phx-click={if @open, do: "collapse", else: "expand"}
        phx-value-block={@block}
      >
        <span class="ouro-subagent-mark" aria-hidden="true">{Cell.Subagent.marker()}</span>
        <span class="ouro-subagent-headline">{Cell.Subagent.headline(@cell)}</span>
        <span class="ouro-subagent-detail">{Cell.Subagent.detail(@cell)}</span>
      </button>
      <div :if={@open and @rows != []} class="ouro-subagent-rows">
        <div :for={row <- @rows} class="ouro-quiet">{row}</div>
      </div>
    </div>
    """
  end

  defp plan(assigns) do
    ~H"""
    <div class="ouro-cell ouro-plan">
      <p :if={@cell.plan.explanation} class="ouro-plan-explanation">{@cell.plan.explanation}</p>
      <ol class="ouro-plan-steps">
        <li :for={step <- @cell.plan.steps} class={"ouro-step-#{step.status}"}>
          <span class="ouro-step-glyph" aria-hidden="true">{step_glyph(step.status)}</span>
          <span class="ouro-step-text">{step.text}</span>
          <span :if={step.priority} class="ouro-quiet">{step.priority}</span>
        </li>
      </ol>
      <p :if={@cell.plan.step_count > length(@cell.plan.steps)} class="ouro-quiet">
        {@cell.plan.step_count - length(@cell.plan.steps)} more steps not shown
      </p>
    </div>
    """
  end

  # Ink, all three. A finished step is not an attention state.
  defp step_glyph(:completed), do: "●"
  defp step_glyph(:in_progress), do: "◐"
  defp step_glyph(_pending), do: "○"

  defp usage(assigns) do
    ~H"""
    <div class="ouro-cell ouro-usage">
      <span :if={@cell.usage.input_tokens}>{@cell.usage.input_tokens} in</span>
      <span :if={@cell.usage.output_tokens}>{@cell.usage.output_tokens} out</span>
      <span :if={@cell.usage.cached_tokens}>{@cell.usage.cached_tokens} cached</span>
      <span :if={@cell.usage.total_tokens}>{@cell.usage.total_tokens} total</span>
      <span :if={@cell.usage.cost_usd}>${format_cost(@cell.usage.cost_usd)}</span>
    </div>
    """
  end

  defp divider(assigns) do
    ~H"""
    <div class={["ouro-cell", "ouro-divider", tone(@cell.tone), "ouro-divider-#{@cell.kind}"]}>
      <span :if={@cell.text != ""}>{@cell.text}</span>
    </div>
    <details :if={@cell.recap} class="ouro-result">
      <summary>
        Review result
        <span>{length(@cell.recap.tools)} recorded tool {plural(length(@cell.recap.tools), "call")}</span>
      </summary>
      <a :if={not is_nil(@cell.recap.reply)} href={"#cells-cell-#{@cell.recap.reply}"}>Read the agent’s reply</a>
      <p class="ouro-quiet">
        Activity recorded in this view. Open a call to inspect its output.
      </p>
      <ul :if={@cell.recap.tools != []}>
        <li :for={tool <- Enum.take(@cell.recap.tools, 8)}>
          <a href={"#cells-cell-#{tool.index}"}>{tool.label}</a> · {tool.state}
        </li>
      </ul>
      <p :if={length(@cell.recap.tools) > 8} class="ouro-quiet">
        {length(@cell.recap.tools) - 8} more calls in the transcript.
      </p>
      <p :if={@cell.recap.files == []} class="ouro-quiet">
        No file changes were reported in this view.
      </p>
      <ul :if={@cell.recap.files != []} aria-label="Files in the recorded activity">
        <li :for={file <- @cell.recap.files}>
          <a href={"#cells-cell-#{file.index}"}>{file.path}</a>
        </li>
      </ul>
      <p :if={@cell.recap.unfinished_steps > 0}>
        {@cell.recap.unfinished_steps} plan {plural(@cell.recap.unfinished_steps, "step")} not marked complete.
      </p>
      <p>Review the reply and activity, then add your next instruction below.</p>
    </details>
    """
  end

  # ------------------------------------------------------------------------------------

  # The projection's four tones, as classes. `:success` is deliberately not green — see
  # the moduledoc — and resolves to ink.
  defp tone(:success), do: "ouro-tone-success"
  defp tone(:warning), do: "ouro-tone-warning"
  defp tone(:error), do: "ouro-tone-error"
  defp tone(_muted), do: "ouro-tone-muted"

  defp plural(1, word), do: word
  defp plural(_count, word), do: word <> "s"

  defp tail_lines(text, count) do
    text |> String.split("\n") |> Enum.take(-count)
  end

  defp output_lines(nil), do: []

  defp output_lines(output) do
    case output |> Tools.value_text() |> String.trim_trailing() do
      "" -> []
      text -> String.split(text, "\n")
    end
  end

  defp format_cost(cost) when is_number(cost),
    do: :erlang.float_to_binary(cost * 1.0, decimals: 4)

  defp format_cost(_cost), do: "?"
end
