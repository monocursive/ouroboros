defmodule Ouroboros.Web.Live.ContextPanel do
  @moduledoc """
  W3.7. What `interactive.context` answered, with `source` as the first line.

  Port of `Overlay::Context` and `SessionContext` (`tui/src/model/native.rs:210-320`,
  `tui/src/ui/app/native.rs:237-300`).

  ## `source` decides what the rest of it means

  `native` means the session counted these figures itself and every field below may be
  present. `usage` means they are what the provider's own `usage` events reported and
  nothing more was known. The panel says which it is reading and then draws only what that
  source can honestly fill: **the native headings are absent rather than empty**, because a
  heading with nothing under it reads as "this session has none", which is a different
  claim from "nobody counted".

  ## Nothing is inferred

  An absent number stays absent. `share/1` answers `nil` unless *both* halves were
  reported — a percentage built from a window nobody named would be a measurement this
  page invented — and the meter divides `context_used`, never the session's cumulative
  `total_tokens`, which crosses its own window many times over in a long conversation
  (`docs/TUI.md:2213-2218`).

  Pure: `read/1` takes the reply and answers a map. The call is the LiveView's.
  """

  use Phoenix.Component

  alias Ouroboros.EventPresentation.Compaction

  # How many rows of one list this surface holds, matching `native::MAX_ROWS`.
  @max_rows 512

  @doc """
  `interactive.context`'s answer as the fields this panel draws.

  Every key is optional and every default is the honest one: absent stays absent. In
  process the values arrive as Elixir terms with atom keys and atom values (`source` is
  `:native`); across JSON they are strings. Both are read.
  """
  @spec read(term()) :: map() | nil
  def read(answer) when is_map(answer) and not is_struct(answer) do
    %{
      source: text(answer, :source),
      session_id: text(answer, :session_id),
      provider: text(answer, :provider),
      transport: text(answer, :transport),
      model: text(answer, :model),
      provider_session_id: text(answer, :provider_session_id),
      context_window: count(answer, :context_window),
      context_used: count(answer, :context_used),
      context_state: text(answer, :context_state),
      total_tokens: count(answer, :total_tokens),
      handed_off_from: text(answer, :handed_off_from),
      handed_off_to: text(answer, :handed_off_to),
      prefix_fingerprint: text(answer, :prefix_fingerprint),
      keep_recent_tokens: count(answer, :keep_recent_tokens),
      messages: count(answer, :messages),
      compaction_thrashing: at(answer, :compaction_thrashing) == true,
      compactions:
        answer |> list(:compactions) |> Enum.take(@max_rows) |> Enum.map(&compaction/1),
      archive_ids: strings(answer, :archive_ids),
      instruction_files: strings(answer, :instruction_files),
      instruction_files_dropped:
        answer
        |> list(:instruction_files_dropped)
        |> Enum.take(@max_rows)
        |> Enum.flat_map(&dropped/1),
      instruction_bytes: count(answer, :instruction_bytes),
      tools: strings(answer, :tools)
    }
  end

  def read(_unreadable), do: nil

  @doc "Whether this answer came from a session that counted its own context."
  @spec native?(map() | nil) :: boolean()
  def native?(%{source: source}), do: source == "native"
  def native?(_absent), do: false

  @doc """
  How full the window is, where both halves were reported.

  `nil` rather than a guess: a provider that named no window gets no percentage
  (`tui/src/model/native.rs:313-320`).
  """
  @spec share(map() | nil) :: non_neg_integer() | nil
  def share(%{context_window: window, context_used: used})
      when is_integer(window) and window > 0 and is_integer(used),
      do: min(div(used * 100, window), 999)

  def share(_unmeasured), do: nil

  @doc """
  The vitals meter's two numbers, where this answer carried both.

  Shaped as the deck's own `context/1` already shapes them so the two are interchangeable,
  and `nil` where nothing was measured — a meter drawn from one half would be a bar this
  page invented the length of.
  """
  @spec meter(map() | nil) :: %{percent: String.t(), label: String.t()} | nil
  def meter(%{context_window: window, context_used: used} = reading)
      when is_integer(window) and window > 0 and is_integer(used) do
    percent = min(used / window * 100, 100)

    %{
      percent: :erlang.float_to_binary(percent * 1.0, decimals: 1),
      label: window_label(reading)
    }
  end

  def meter(_unmeasured), do: nil

  @doc """
  One compaction report, wherever it appears.

  The same shape in three places — the `compactions` list of a `/context` answer,
  `interactive.compact`'s own reply, and the durable `compaction` provider event the
  transcript already projects — so there is one decoder for it and
  `Ouroboros.Web.Transcript.compaction_block/1` draws all three the same way.
  """
  @spec compaction(term()) :: Compaction.t()
  def compaction(report) when is_map(report) do
    %Compaction{
      trigger: text(report, :trigger),
      turn: count(report, :turn),
      archived_messages: count(report, :archived_messages),
      archive_id: text(report, :archive_id),
      elided_tool_results: count(report, :elided_tool_results),
      summary_tokens: count(report, :summary_tokens),
      before_tokens: count(report, :before_tokens),
      after_tokens: count(report, :after_tokens),
      summarised: at(report, :summarised) == true
    }
  end

  def compaction(_unreadable), do: %Compaction{}

  defp dropped(entry) when is_map(entry) do
    case text(entry, :path) do
      nil -> []
      path -> [%{path: path, bytes: count(entry, :bytes), reason: text(entry, :reason)}]
    end
  end

  defp dropped(_other), do: []

  defp strings(map, key) do
    map
    |> list(key)
    |> Enum.take(@max_rows)
    |> Enum.flat_map(fn
      value when is_binary(value) -> if String.trim(value) == "", do: [], else: [value]
      value when is_atom(value) and value not in [nil, true, false] -> [Atom.to_string(value)]
      _unreadable -> []
    end)
  end

  defp at(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end

  defp text(map, key) do
    case at(map, key) do
      value when is_binary(value) ->
        case String.trim(value) do
          "" -> nil
          trimmed -> trimmed
        end

      value when is_atom(value) and value not in [nil, true, false] ->
        Atom.to_string(value)

      _absent ->
        nil
    end
  end

  defp count(map, key) do
    case at(map, key) do
      value when is_integer(value) and value >= 0 -> value
      _absent -> nil
    end
  end

  defp list(map, key) do
    case at(map, key) do
      value when is_list(value) -> value
      _absent -> []
    end
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  attr :context, :any, required: true
  attr :error, :any, default: nil

  def panel(assigns) do
    assigns =
      assigns
      |> assign(:native?, native?(assigns.context))
      |> assign(:share, share(assigns.context))

    ~H"""
    <dialog
      id="ouro-context"
      class="ouro-session-dialog ouro-context"
      aria-modal="true"
      aria-labelledby="ouro-context-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-context-title">Context</h2>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <p :if={is_nil(@context)} class="ouro-quiet">
          Nothing has been read for this session yet.
        </p>

        <div :if={@context}>
          <%!-- The first line, because it decides what every line under it means. --%>
          <p class="ouro-context-source">
            <span class="ouro-picker-label">Source</span>
            <span class="ouro-mono">{@context.source || "not reported"}</span>
          </p>
          <p :if={@native?} class="ouro-quiet">
            This session counted these figures itself.
          </p>
          <p :if={not @native?} class="ouro-quiet">
            A subset: these are what the provider's own usage reports carried, and nothing
            more was known. The headings a native session fills are absent rather than empty.
          </p>

          <dl class="ouro-context-facts">
            <div class="ouro-vital">
              <dt>Window</dt>
              <dd>
                <div
                  :if={@share}
                  class="ouro-meter"
                  role="img"
                  aria-label={"#{@context.context_used} of #{@context.context_window} tokens"}
                >
                  <div class="ouro-meter-fill" style={"width: #{min(@share, 100)}%"}></div>
                </div>
                <span class="ouro-mono">
                  {window_label(@context)}
                </span>
              </dd>
            </div>
            <div :if={@context.context_state} class="ouro-vital">
              <dt>Measurement</dt>
              <dd class="ouro-mono">{@context.context_state}</dd>
            </div>
            <div class="ouro-vital">
              <dt>Total tokens</dt>
              <dd class="ouro-mono">{@context.total_tokens || "not reported"}</dd>
            </div>
            <div class="ouro-vital">
              <dt>Model</dt>
              <dd class="ouro-mono">{@context.model || "not reported"}</dd>
            </div>
            <div class="ouro-vital">
              <dt>Transport</dt>
              <dd class="ouro-mono">{@context.transport || "not reported"}</dd>
            </div>
            <div :if={@context.handed_off_from} class="ouro-vital">
              <dt>Handed off from</dt>
              <dd class="ouro-mono">{@context.handed_off_from}</dd>
            </div>
            <div :if={@context.handed_off_to} class="ouro-vital">
              <dt>Handed off to</dt>
              <dd class="ouro-mono">{@context.handed_off_to}</dd>
            </div>
          </dl>

          <%!-- Native only. Absent, never empty: see the moduledoc. --%>
          <div :if={@native?} class="ouro-context-native">
            <div :if={@context.prefix_fingerprint} class="ouro-vital">
              <dt>Prefix fingerprint</dt>
              <dd class="ouro-mono">{@context.prefix_fingerprint}</dd>
            </div>
            <div :if={@context.messages} class="ouro-vital">
              <dt>Messages</dt>
              <dd class="ouro-mono">{@context.messages}</dd>
            </div>

            <p :if={@context.compaction_thrashing} class="ouro-rewind-warning" role="alert">
              This session compacted again within three turns and the runtime stopped rather
              than looping.
            </p>

            <section :if={@context.compactions != []}>
              <h3>Compactions</h3>
              <ul>
                <li :for={fold <- @context.compactions}>{Compaction.describe(fold)}</li>
              </ul>
            </section>

            <section :if={@context.archive_ids != []}>
              <h3>Archives</h3>
              <ul class="ouro-mono">
                <li :for={id <- @context.archive_ids}>{id}</li>
              </ul>
            </section>

            <section :if={@context.instruction_files != []}>
              <h3>Instruction files loaded</h3>
              <ul class="ouro-mono">
                <li :for={path <- @context.instruction_files}>{path}</li>
              </ul>
            </section>

            <section :if={@context.instruction_files_dropped != []}>
              <h3>Instruction files dropped</h3>
              <ul>
                <li :for={file <- @context.instruction_files_dropped}>
                  <span class="ouro-mono">{file.path}</span>
                  <span :if={file.bytes}>· {file.bytes} bytes</span>
                  <span :if={file.reason}>— {file.reason}</span>
                </li>
              </ul>
            </section>
          </div>
        </div>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end

  @doc "The meter's own words: both halves, one half, or that nobody counted."
  @spec window_label(map()) :: String.t()
  def window_label(%{context_used: used, context_window: window})
      when is_integer(used) and is_integer(window),
      do: "#{used} / #{window} tokens"

  def window_label(%{context_used: used}) when is_integer(used),
    do: "#{used} tokens used · no window reported"

  def window_label(%{context_window: window}) when is_integer(window),
    do: "window #{window} tokens · nothing measured yet"

  def window_label(_unmeasured), do: "not reported"
end
