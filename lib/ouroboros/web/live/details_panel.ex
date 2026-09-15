defmodule Ouroboros.Web.Live.DetailsPanel do
  @moduledoc """
  W3.1. The event ledger this view holds, as the wire objects it holds them as.

  Port of `tui/src/ui/details.rs`. The transcript is a *projection*: a `tool_result` is
  three lines of a cell and a `usage` event is a number in the vitals. This is the other
  reading — every event the watch retains, in sequence, with the whole object underneath
  it — and it is the only place on this surface where nothing has been decided about what
  an event means.

  ## The object is the one the runtime framed, not a re-derivation

  Each row's body is `Ouroboros.Gateway.Wire.to_json/1` of the held event: the same
  encoding, under the same `event_leaf_bytes` cap, that a terminal client on a socket
  would have received. That is deliberate and it is the point of the excerpt seam below —
  a web view that rendered the *unbounded* in-process struct would be showing something no
  other client can see and calling it the event.

  ## The excerpt seam (X6)

  A string leaf over the cap arrives as `%{"_excerpt" => prefix, "_bytes" => n}`. Where an
  event's tree holds one, this offers a fetch: `interactive.event_detail {id, sequence}`
  re-encodes that one event under `detail_leaf_bytes` instead. The answer replaces the
  tree **for this view only** — the transcript's own projection keeps reading the capped
  event it absorbed, because the fetched copy is a fact about one reader's screen and not
  about the session's history (`tui/src/ui/details.rs:17-31`).

  ## A row costs a line; only an open one costs a tree

  W3 fix wave (L4). `Wire.to_json/1` walks a whole event and bounds every string leaf in
  it, and a session holding two thousand of them paid that on **every render** — a poll
  every three seconds, a keystroke in the palette — to draw a summary line for each and a
  tree for none. The summary is cheap and is built for every row; the object is derived
  only for the rows that are open, which is what `expanded` already said.

  ## Dividers are never hidden

  A floor, a gap, a note and the end-of-stream marker are part of the ledger: they say
  where history is missing. A panel that dropped them would look complete and would not
  be. They are rendered from the same `Ouroboros.Web.Transcript.Entry` list the transcript
  draws from, so the two cannot disagree about where a hole is.

  Pure: `rows/2` and `pretty/1` take data and answer data. Nothing here calls a runtime.
  """

  use Phoenix.Component

  alias Ouroboros.EventPresentation, as: Presentation
  alias Ouroboros.Gateway.Wire
  alias Ouroboros.Web.Transcript.Entry

  # How many characters of an event's summary the collapsed row carries
  # (`tui/src/ui/details.rs:57`).
  @summary_cells 120

  @typedoc """
  One drawn row: an event, or one of the transcript's own dividers.

  `object` is `nil` on a collapsed row and the wire tree on an open one — see the
  moduledoc for why it is not built for every row.
  """
  @type row ::
          {:event,
           %{
             sequence: non_neg_integer(),
             kind: String.t(),
             summary: String.t(),
             expanded: boolean(),
             fetched: boolean(),
             excerpted: boolean(),
             object: term() | nil
           }}
          | {:divider, String.t()}

  @doc """
  The rows this watch produces, given what is open and what has been fetched.

  `state` is `%{expanded: MapSet.t(), fetched: %{sequence => object}}`. An event's object
  is the fetched one where there is one and the capped one otherwise, which is the whole
  of "replacing that one event's tree for this view only".
  """
  @spec rows([Entry.t()], map()) :: [row()]
  def rows(entries, state) when is_list(entries) and is_map(state) do
    expanded = Map.get(state, :expanded) || MapSet.new()
    fetched = Map.get(state, :fetched) || %{}

    Enum.map(entries, fn
      %Entry.Event{event: event} -> event_row(event, expanded, fetched)
      %Entry.Floor{sequence: sequence} -> {:divider, floor_text(sequence)}
      %Entry.Gap{from: from, to: to} -> {:divider, gap_text(from, to)}
      %Entry.Note{} = note -> {:divider, Entry.Note.text(note)}
      %Entry.Ended{status: status} -> {:divider, "stream ended (#{status}) — no further events"}
    end)
  end

  defp event_row(event, expanded, fetched) do
    sequence = Map.get(event, :sequence)
    open? = MapSet.member?(expanded, sequence)
    detail = Map.get(fetched, sequence)

    # Only an open row pays for its tree. A collapsed one is a sequence, a kind and a
    # line, all of which come off the event as it already is.
    object = if open?, do: detail || Wire.to_json(event)

    {:event,
     %{
       sequence: sequence,
       kind: event |> Map.get(:type) |> to_string(),
       summary: event |> summary() |> one_line() |> truncate(@summary_cells),
       expanded: open?,
       fetched: not is_nil(detail),
       excerpted: open? and excerpted?(object),
       object: object
     }}
  end

  @doc """
  The one line a collapsed row carries.

  `payload.text` where there is one, and otherwise every field as `key=value` with the
  keys sorted — `Event::summary` (`tui/src/model.rs:487-502`) through the same
  `EventPresentation.compact/1` the transcript quotes values with.
  """
  @spec summary(map()) :: String.t()
  def summary(event) do
    payload = Map.get(event, :payload)

    case payload do
      %{"text" => text} when is_binary(text) ->
        text

      payload when is_map(payload) and map_size(payload) == 0 ->
        ""

      payload when is_map(payload) ->
        payload
        |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
        |> Enum.map_join(" ", fn {key, value} -> "#{key}=#{Presentation.compact(value)}" end)

      nil ->
        ""

      other ->
        Presentation.compact(other)
    end
  end

  @doc """
  Whether this tree holds a leaf the gateway could only excerpt.

  The question the fetch control is drawn from, asked of the object actually on screen: a
  tree that came back from `interactive.event_detail` may still hold one, because
  `detail_leaf_bytes` is a larger cap and not an absent one, and offering the fetch again
  is honest where it is.
  """
  @spec excerpted?(term()) :: boolean()
  def excerpted?(%{"_excerpt" => _prefix}), do: true
  def excerpted?(value) when is_map(value), do: Enum.any?(value, fn {_k, v} -> excerpted?(v) end)
  def excerpted?(value) when is_list(value), do: Enum.any?(value, &excerpted?/1)
  def excerpted?(_leaf), do: false

  @doc """
  One JSON tree as indented text, object keys sorted.

  Sorted for the same reason `EventPresentation.encode_json/1` sorts: two readings of one
  event have to produce the same text, and a rendering that followed a map's own iteration
  order would not. Two spaces per level, and a string is JSON-escaped rather than pasted —
  this text is agent prose and goes into a `<pre>` HEEx escapes.
  """
  @spec pretty(term()) :: String.t()
  def pretty(value), do: value |> encode(0) |> IO.iodata_to_binary()

  defp encode(value, _depth) when is_map(value) and map_size(value) == 0, do: "{}"
  defp encode([], _depth), do: "[]"

  defp encode(value, depth) when is_map(value) and not is_struct(value) do
    pad = indent(depth + 1)

    inner =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, item} ->
        [pad, JSON.encode!(to_string(key)), ": ", encode(item, depth + 1)]
      end)
      |> Enum.intersperse(",\n")

    ["{\n", inner, "\n", indent(depth), "}"]
  end

  defp encode(value, depth) when is_list(value) do
    pad = indent(depth + 1)

    inner =
      value
      |> Enum.map(fn item -> [pad, encode(item, depth + 1)] end)
      |> Enum.intersperse(",\n")

    ["[\n", inner, "\n", indent(depth), "]"]
  end

  # A struct is not a JSON value. Nothing reaches here from `Wire.to_json/1`, which walks
  # every struct away, but a caller handing this something else gets the term named rather
  # than a crash inside a template.
  defp encode(%_struct{} = value, _depth), do: JSON.encode!(inspect(value))

  defp encode(value, _depth) when is_atom(value) and value not in [nil, true, false],
    do: JSON.encode!(Atom.to_string(value))

  defp encode(value, _depth), do: JSON.encode!(value)

  defp indent(0), do: ""
  defp indent(depth), do: String.duplicate("  ", depth)

  defp floor_text(sequence),
    do: "history truncated below #{sequence} — the runtime no longer retains it"

  defp gap_text(from, to), do: "#{to - from + 1} events missing (#{from}..#{to}) — replaying"

  defp one_line(text) do
    text
    |> String.replace(~r/[\x00-\x1f\x7f]/u, " ")
    |> String.trim()
  end

  defp truncate(text, cells) do
    if String.length(text) <= cells, do: text, else: String.slice(text, 0, cells - 1) <> "…"
  end

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @doc """
  The panel. `rows` is `rows/2`'s answer; `fetching` is the sequence a fetch is in flight
  for, which is nothing on this surface because `Ouroboros.Web.Call` is synchronous in the
  view's own process — kept as an attribute so the control can say so if that changes.
  """
  attr :rows, :list, required: true
  attr :error, :any, default: nil

  def panel(assigns) do
    ~H"""
    <dialog
      id="ouro-details"
      class="ouro-session-dialog ouro-details"
      aria-modal="true"
      aria-labelledby="ouro-details-title"
      phx-hook="Modal"
      data-cancel-event="w3-close"
    >
      <div class="ouro-session-dialog-form">
        <h2 id="ouro-details-title">Event details</h2>
        <p class="ouro-quiet">
          Every event this page is holding, as the runtime framed it. The transcript above is
          a reading of these; this is the record.
        </p>

        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>

        <p :if={@rows == []} class="ouro-quiet">
          This page holds no events for this session yet.
        </p>

        <ol class="ouro-details-list">
          <li :for={{row, at} <- Enum.with_index(@rows)} class="ouro-details-item">
            <p :if={match?({:divider, _text}, row)} class="ouro-details-divider">
              {elem(row, 1)}
            </p>

            <div :if={match?({:event, _fields}, row)} class="ouro-details-event">
              <button
                type="button"
                class="ouro-details-head"
                phx-click="w3-details-toggle"
                phx-value-sequence={elem(row, 1).sequence}
                aria-expanded={to_string(elem(row, 1).expanded)}
                aria-controls={"ouro-details-body-#{at}"}
              >
                <span class="ouro-mono ouro-details-seq">{elem(row, 1).sequence}</span>
                <span class="ouro-mono ouro-details-kind">{elem(row, 1).kind}</span>
                <span class="ouro-details-summary">{elem(row, 1).summary}</span>
              </button>

              <div :if={elem(row, 1).expanded} id={"ouro-details-body-#{at}"}>
                <p :if={elem(row, 1).fetched} class="ouro-quiet">
                  Fetched whole for this page. The transcript still reads the event it was sent.
                </p>
                <button
                  :if={elem(row, 1).excerpted and not elem(row, 1).fetched}
                  type="button"
                  class="ouro-quiet-button"
                  phx-click="w3-details-fetch"
                  phx-value-sequence={elem(row, 1).sequence}
                  phx-disable-with="Fetching…"
                >
                  Fetch the whole event
                </button>
                <pre class="ouro-details-json ouro-mono">{pretty(elem(row, 1).object)}</pre>
              </div>
            </div>
          </li>
        </ol>

        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button" phx-click="w3-close">Close</button>
        </div>
      </div>
    </dialog>
    """
  end
end
