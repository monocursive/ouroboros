defmodule Ouroboros.Web.Live.DeckLive do
  @moduledoc """
  The operator deck: what needs you, what you are reading, and what it is costing.

  Three columns, and the middle one is the reason the other two exist. The left rail is
  the fleet's whole session list triaged into three groups
  (`Ouroboros.Web.Live.Rail`); the centre is one session's transcript, subscribed live;
  the right is that session's vitals.

  ## Subscription lives in this process, not in a task

  Both planes register `self()` and monitor it, so the subscribe call has to come from the
  process that wants the events — the same rule `Ouroboros.Gateway.Conn` follows, and the
  reason this one method does not go through `Ouroboros.Web.Call`. Everything else here
  does. Unsubscribe is automatic: when this LiveView dies, the plane's monitor fires and
  the registration goes with it, which is also what makes crash-and-remount a working
  repair rather than a leak.

  ## Three things go wrong and one thing is done about it

  A remount, the coordinator's `:DOWN`, and `{:error, {:cursor_pruned, floor}}` are three
  different failures with one repair: `subscribe(cursor)`, where the cursor is the
  contiguous high-water mark `Ouroboros.Web.Watch` maintains. `resubscribe/1` is that
  function and there is no second path.

  A mailbox the plane outran is a fourth cause of the same hole. In-process there is no
  `stream.lagged` frame: this view measures `Process.info(self(), :message_queue_len)`
  against `Watch.window/0` on live events and the coalesced flush, drops what is already
  queued, and resubscribes from the cursor. Crash-and-remount would also empty the
  mailbox; resubscribe keeps the page.

  A terminal session is checked for **immediately** after the backlog arrives, because it
  answers a backlog and silently declines the registration — without the check this view
  would sit forever waiting for live events from a conversation that ended an hour ago.

  ### One thing the TUI does that this does not

  The terminal client loops — replay, and if it progressed and a gap remains, replay again
  — because the gateway's `*.replay` verb answers at most `REPLAY_LIMIT` events per frame.
  In-process there is no such limit: `subscription_events/2` returns **every** retained
  event above the cursor in one call (`interactive/task.ex:2301`, bounded only by the
  session's own `event_limit`). So one subscribe closes the whole gap, and a loop here
  would be a second round that could only ever answer nothing. `Watch.has_gap?/1` is still
  the question to ask if that ever stops being true.

  ## Coalescing, and why it is not optional

  A streaming turn sends one message per text delta. Re-projecting the whole ledger per
  delta would spend the ledger's length on every keystroke the model types, so a delta
  schedules a flush at most every 80ms and the projection runs once per flush. Live
  events are absorbed immediately — only the *drawing* is coalesced, so nothing is at risk
  if the view dies between a delta and its flush.

  ## Polling is bounded by what is on screen

  The TUI's rule — "only the visible tab refreshes" — becomes "only a mounted view polls,
  for what it draws". The lists and `runtime.status` refresh every 3 seconds while
  mounted, one in flight at a time, and stop when the tab closes. Providers and models are
  not fetched here at all; they belong to a picker this slice does not have.

  ## Mutations are serial because this process is

  Every operator verb goes through `Ouroboros.Web.Call`, which is synchronous in *this*
  process: the task it supervises is awaited here, so a second click cannot start a second
  call while the first is in flight — LiveView delivers events one at a time and this one
  blocks. That is the "one in-flight mutation at a time" rule, and it is a property of the
  design rather than a flag somebody has to remember to set. What the flag would not have
  caught is the *second click that lands after the first returns*, so a send carries a
  caller-owned `turn_id` derived from the draft: resending the same `{id, input, turn_id}`
  adopts the same turn rather than starting a second one, which is the protocol's own
  answer to double submission. The button also wears `phx-disable-with`, which is the part
  a person sees.

  ## Auto-approve is this view's, and only this view's

  The toggle lives in socket state and is never written down: a preference that survived a
  reload would be a standing grant nobody remembers making. While it is on, every pending
  request that is **not** a question or a plan exit is answered
  `{approve, once, actor: "automation"}` — the terminal client's exact carve-outs, read
  through the one predicate both surfaces share. Answered request ids are remembered so a
  replay after a repair cannot answer the same request twice.

  ## The needs-you bell pushes an edge, and decides nothing

  Four rules stand between a session needing somebody and a banner appearing on their
  screen, and this process can only know one of them. Whether the bell is on, whether the
  browser granted permission, and whether anybody is actually looking at the tab are all
  facts about a browser; they live in `app.js`. What lives here is the edge — which
  sessions have just *entered* the needs-you group — pushed as `needs-you` and left alone.

  What was already waiting when the page opened is recorded rather than announced, so a
  deck opened in a background tab does not post one banner per pending approval on arrival
  and a reconnect does not do it again. A request auto-approve answered never rings at all:
  the bell runs after `auto_answer/1`, which records the request before its call goes out.

  ## What this slice does not do

  Starting a session is W6; its control is a link to a page that lands with it.
  """

  use Phoenix.LiveView

  require Logger

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Commands
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Layouts
  alias Ouroboros.Web.Live.ApprovalCard
  alias Ouroboros.Web.Live.Cells
  alias Ouroboros.Web.Live.ImageAttachments
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Live.LoadingState
  alias Ouroboros.Web.Live.Palette
  alias Ouroboros.Web.Live.Rail
  # ui-parity W3
  alias Ouroboros.Web.Live.BacktrackDialog
  alias Ouroboros.Web.Live.ContextPanel
  alias Ouroboros.Web.Live.DetailsPanel
  alias Ouroboros.Web.Live.McpPanel
  alias Ouroboros.Web.Live.RewindDialog
  alias Ouroboros.Web.Live.VerbDialogs
  alias Ouroboros.Web.NeedsYou
  alias Ouroboros.Web.Presentation
  alias Ouroboros.Web.Route
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Approval
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Watch

  @poll_interval 3_000
  @coalesce 80
  @planes %{"interactive" => :interactive}

  # A turn state nothing has been read from yet, so the composer has something to draw
  # before a session is open.
  @quiet_turn %{running?: false, spoke?: false, failed?: false, turn_id: nil, queued: 0}

  # ui-parity W2. The composer's own state that is not a draft: the model catalogue (never
  # fetched on the poll), the search over it, and a per-turn effort armed for exactly one
  # send. Held as one map so the palette's query, which changes on every keystroke, does
  # not re-render the transcript's column with it.
  @composer_extras %{models: nil, model_query: "", next_effort: nil}

  # ui-parity W3. Everything this slice's panels hold, in one map carrying the
  # `{plane, id}` it was read for — see the block above `# ui-parity W2` for why.
  @w3 %{
    subject: nil,
    # Which panel owns the screen: `:details`, `:backtrack`, `:rewind`, `:context`,
    # `:mcp`, `:compact`, `:handoff`, `:export`, or nothing.
    panel: nil,
    # The runtime's own words for whatever the open panel last asked, and a line for what
    # one of these verbs did. Both are this conversation's, both are cleared with it.
    error: nil,
    notice: nil,
    # W3.1. Which events are open, and which have been fetched whole *for this view*.
    details: %{expanded: MapSet.new(), fetched: %{}},
    # W3.4. Two screens, and the list the second one indexes into.
    points: [],
    choice: 0,
    what: "both",
    screen: :choose,
    outcome: nil,
    # W3.7. `interactive.context`'s answer, which the vitals meter reads too.
    reading: nil,
    # W3.9. `mcp.list`'s answer, read fresh on every open.
    mcp: nil,
    # W3.8. A refused `!`, held on the composer where the offer to fix it belongs.
    shell: nil
  }

  # ------------------------------------------------------------------------------------
  # Lifecycle
  # ------------------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:scope, Config.for_endpoint(socket.endpoint).scope)
      |> assign(:page_title, "Sessions")
      |> assign(:rows, [])
      |> assign(:session_query, "")
      |> assign(:list_error, nil)
      |> assign(:status, nil)
      |> assign(:polling?, false)
      |> assign(:open, nil)
      |> assign(:drafts, %{})
      |> assign(:draft_key, nil)
      |> assign(:image_refs, [])
      |> assign(:sessions_visible?, false)
      |> assign(:watch, nil)
      |> assign(:info, nil)
      |> assign(:monitor, nil)
      |> assign(:flush_scheduled?, false)
      |> assign(:subscribe_error, nil)
      |> assign(:expanded, MapSet.new())
      |> assign(:cells, %{})
      |> assign(:history_start, nil)
      |> assign(:history_anchor, nil)
      |> assign(:cell_targets, %{})
      |> assign(:session_action, nil)
      |> assign(:session_action_error, nil)
      |> assign(:truncated, 0)
      # The serving runtime's method list, read once: it is the same list `hello` answers
      # for a terminal client and it cannot change while this process lives.
      |> assign(:methods, Methods.names())
      # Every needs-you key this view has already rung for. See `announce_needs_you/1`.
      |> assign(:announced, MapSet.new())
      # ui-parity W2
      |> assign(%{palette: nil, shortcuts?: false, composer_extras: @composer_extras})
      # ui-parity W3. One map, carrying the conversation it was read for; see `w3/1`.
      |> assign(:w3, @w3)
      |> reset_session_state()
      |> stream(:cells, [])

    # The first paint is server-rendered and has to have content in it: a deck that showed
    # an empty rail until a socket connected would flash empty on every navigation.
    socket = refresh(socket)

    # What was already waiting when this page opened is not something that *started*
    # needing a person, so it is recorded rather than announced. Without this a deck opened
    # in a background tab would post one banner per pending approval on arrival, and a
    # reconnect would do it again.
    socket = seed_needs_you(socket)

    if connected?(socket), do: schedule_poll()

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    case opened(params) do
      {plane, id} -> {:noreply, open(socket, plane, id)}
      :none -> {:noreply, close(socket)}
    end
  end

  # `/s/:plane/:id` names the session in the path. `?open=<plane>:<id>` is the same request
  # made by a page that navigated here rather than patched — the new-session form, which
  # cannot `live_patch` across a `live_session` boundary — and it opens the same session by
  # the same route rather than a second one.
  defp opened(%{"plane" => plane, "id" => id}) when is_binary(id) and id != "" do
    case Map.get(@planes, plane) do
      nil -> :none
      known -> {known, id}
    end
  end

  defp opened(%{"open" => open}) when is_binary(open) do
    case String.split(open, ":", parts: 2) do
      [plane, id] -> opened(%{"plane" => plane, "id" => id})
      _malformed -> :none
    end
  end

  defp opened(_params), do: :none

  # ------------------------------------------------------------------------------------
  # Events from the browser
  # ------------------------------------------------------------------------------------

  # ui-parity W3
  #
  # The verbs the parity matrix still had a dash under on the web side: the event ledger,
  # the transcript export, backtrack and fork, rewind, compact, handoff, context, `!` and
  # the MCP list. Four rules hold across all of them, and they are the same four W2's
  # block states:
  #
  #   * **the catalogue decides what exists** and `run_command/2` asks it again before
  #     doing anything, so a panel opened from a row that went stale cannot run.
  #   * **every wire call is the terminal client's call**, parameter for parameter. Where
  #     this file sends something the TUI does not, that is a defect, not a dialect.
  #   * **a refusal is rendered in the runtime's own words.** Nothing here paraphrases one
  #     and nothing here claims an outcome the runtime did not report — a handoff whose
  #     ceiling expired says the outcome is unknown rather than that a child is ready.
  #   * **what an operator's own verb answered is a note in the conversation**, pushed
  #     through `Ouroboros.Web.Watch.note/3` as `{:local, block}` and deduped against the
  #     runtime's durable record of the same act by the key it carries. That is the
  #     projection's own mechanism (`Ouroboros.Web.Transcript.project_with_ids/1`), not a
  #     second rendering path beside it.
  #
  # ## One assign, keyed by the conversation it is about
  #
  # Everything below lives in `:w3`, and the map carries the `{plane, id}` it was read
  # for. `w3/1` hands back the default for any other session, so opening a second
  # conversation cannot show it the first one's context reading, rewind points or open
  # panel — and nothing had to be added to `reset_session_state/1` to make that true.

  # ui-parity W3. `@w3` is declared above, beside `@composer_extras`: a module
  # attribute has to exist before `mount/1` reads it.

  # The state for the session that is actually open. A reading taken in one conversation
  # is not a fact about the next one, so a stale subject answers the default rather than
  # the previous session's panel.
  defp w3(%{open: open, w3: %{subject: open} = state}) when not is_nil(open), do: state
  defp w3(_stale_or_closed), do: @w3

  defp put_w3(socket, changes) do
    state =
      socket.assigns
      |> w3()
      |> Map.merge(Map.new(changes))
      |> Map.put(:subject, socket.assigns.open)

    assign(socket, :w3, state)
  end

  # A modal owns the screen while it is open, and these refuse to appear over another for
  # exactly the reason W2's palette does: a confirmation is a question awaiting an answer
  # and nothing may act behind it.
  defp open_w3(%{assigns: %{session_action: action}} = socket, _panel) when not is_nil(action),
    do: socket

  defp open_w3(socket, panel) do
    socket
    |> close_palette()
    |> assign(:shortcuts?, false)
    |> put_w3(panel: panel, error: nil, notice: nil)
  end

  defp close_w3(socket), do: put_w3(socket, panel: nil, error: nil, notice: nil)

  # W3 fix wave (M5). A confirmation is a question awaiting an answer and **nothing acts
  # behind one** — the rule `open_w3/2` and `run_command/2` already hold, applied to the
  # handlers a hand-made `phx-click` reaches directly. It is not only that a verb would
  # run unseen: a handoff patches the page to the child, so the dialog underneath would be
  # left asking about a session the operator is no longer looking at.
  defp acting(%{assigns: %{session_action: action}} = socket, _fun) when not is_nil(action),
    do: {:noreply, socket}

  defp acting(socket, fun), do: {:noreply, fun.(socket)}

  # W3 fix wave (L5). The meter follows the conversation: `context_used` moves with every
  # turn, so a reading taken once and kept forever is a number that was true and is not.
  # Only where a reading already exists — a page that never asked is not made to ask by a
  # turn finishing — and only on the boundary, which is one call per turn rather than one
  # per delta.
  defp refresh_reading(socket, event) do
    if Map.get(event, :type) == :turn_completed and not is_nil(w3(socket.assigns).reading),
      do: read_context(socket, false),
      else: socket
  end

  # A `phx-value-sequence` arrives as a string and names an event position. Parsed here,
  # once, so no handler below has to decide what a browser meant by `"12abc"`.
  defp with_sequence(socket, sequence, fun) do
    case Integer.parse(to_string(sequence)) do
      {at, ""} when at > 0 -> fun.(socket, at)
      _unreadable -> socket
    end
  end

  defp w3_error(socket, refusal),
    do: put_w3(socket, error: refusal_message(refusal))

  # ---------------------------------------------------------------- W3.1 Event details

  # The ledger this view is holding, as rows. Never filtered: a floor, a gap and a note
  # say where history is missing, and a panel that dropped them would look complete.
  defp details_rows(assigns) do
    case assigns.watch do
      %Watch{} = watch -> DetailsPanel.rows(Watch.entries(watch), w3(assigns).details)
      _absent -> []
    end
  end

  defp toggle_detail(socket, sequence) do
    details = w3(socket.assigns).details

    expanded =
      if MapSet.member?(details.expanded, sequence),
        do: MapSet.delete(details.expanded, sequence),
        else: MapSet.put(details.expanded, sequence)

    put_w3(socket, details: %{details | expanded: expanded})
  end

  # X6. `interactive.event_detail {id, sequence}` re-encodes one event under the larger
  # `detail_leaf_bytes` cap. The answer replaces that event's tree **for this view only**:
  # the transcript keeps projecting the capped event it absorbed, because the fetched copy
  # is a fact about one reader's screen and not about the session's history
  # (`tui/src/ui/details.rs:17-31`).
  defp fetch_detail(%{assigns: %{open: {:interactive, id}}} = socket, sequence) do
    if Commands.available?(socket.assigns, "conversation.details") do
      params =
        socket
        |> session_params(:interactive, id)
        |> Map.put("sequence", sequence)

      case call(socket, "interactive.event_detail", params) do
        {:ok, event} ->
          details = w3(socket.assigns).details

          put_w3(socket,
            error: nil,
            details: %{
              details
              | fetched: Map.put(details.fetched, sequence, event),
                expanded: MapSet.put(details.expanded, sequence)
            }
          )

        refusal ->
          w3_error(socket, refusal)
      end
    else
      socket
    end
  end

  defp fetch_detail(socket, _sequence), do: socket

  # ------------------------------------------------------------------ W3.2 Export

  # A download is its own request, so this names a URL rather than calling anything.
  #
  # W3 fix wave (M4). **Not a redirect.** `redirect(external: …)` is `window.location`,
  # and the one answer that carries no `content-disposition` is a refusal — a 404 for a
  # session this node no longer holds, a 502 for a runtime that could not answer — so the
  # operator was navigated out of the deck by the failure case and lost the page they were
  # reading. The browser opens an anchor instead: `ouro-open` clicks one it made itself,
  # `target="_blank"` so a refusal lands beside the deck rather than over it.
  defp export_url(%{assigns: %{open: {plane, id}}}, format) when format in ~w(text ndjson),
    do: Route.session(plane, id) <> "/export?format=" <> format

  defp export_url(_closed, _format), do: nil

  defp export_to(socket, format) do
    case export_url(socket, format) do
      nil -> socket
      url -> push_event(socket, "ouro-open", %{url: url})
    end
  end

  # ------------------------------------------------------- W3.3 Backtrack and fork

  defp backtrack_turns(assigns) do
    case assigns.watch do
      %Watch{} = watch ->
        BacktrackDialog.recent_user_turns(Watch.entries(watch), BacktrackDialog.entries())

      _absent ->
        []
    end
  end

  # "Edit and resend as a new turn": the chosen message's text goes into the composer and
  # **nothing is removed**. Deliberately not called a rewind — the transcript is unchanged
  # and the provider's context is unchanged, and a control that implied otherwise would be
  # the rewind that silently under-delivers.
  defp backtrack_edit(socket, sequence) do
    turns = backtrack_turns(socket.assigns)

    case Enum.find(turns, fn {at, _text} -> at == sequence end) do
      {_at, text} ->
        if Commands.resendable?(socket.assigns) do
          socket
          |> put_draft(text)
          |> push_event("draft-replace", %{key: socket.assigns.draft_key, text: text})
          |> put_w3(
            panel: nil,
            error: nil,
            notice: "That message is in the composer as a new turn. Nothing earlier was removed."
          )
        else
          socket
        end

      nil ->
        socket
    end
  end

  # `interactive.fork {id, node}`, and the notice says the same thing the dialog does:
  # the verb takes a session and no message, so where the branch starts is the transport's
  # decision and this page does not claim to know it
  # (`tui/src/ui/app/session.rs:1078-1115`).
  defp fork(%{assigns: %{open: {:interactive, id}}} = socket) do
    if Commands.forkable?(socket.assigns) do
      case call(socket, "interactive.fork", session_params(socket, :interactive, id)) do
        {:ok, child} -> opened_child(socket, child, id, "forked from")
        refusal -> w3_error(socket, refusal)
      end
    else
      socket
    end
  end

  defp fork(socket), do: socket

  # ------------------------------------------------------------------- W3.4 Rewind

  defp open_rewind(%{assigns: %{open: {:interactive, id}}} = socket) do
    case call(socket, "interactive.rewind_points", session_params(socket, :interactive, id)) do
      {:ok, answer} ->
        points = RewindDialog.points(answer)

        socket
        |> open_w3(:rewind)
        |> put_w3(
          points: points,
          choice: max(length(points) - 1, 0),
          what: "both",
          screen: :choose,
          outcome: nil
        )

      refusal ->
        socket |> open_w3(:rewind) |> w3_error(refusal) |> put_w3(points: [], screen: :choose)
    end
  end

  defp open_rewind(socket), do: socket

  # **`to_turn` is the turn's 1-based position, not its id.** `interactive.rewind`'s
  # parameter contract admits either, but `InteractiveSession.rewind/3` guards
  # `is_integer`, so a turn id is refused as `invalid_rewind` before it reaches the
  # session. The position is exactly what the dialog already knows, having just been
  # handed the list it indexes into (`tui/src/ui/app/native.rs:423-486`).
  defp rewind_confirm(%{assigns: %{open: {:interactive, id}}} = socket) do
    state = w3(socket.assigns)

    with true <- Commands.available?(socket.assigns, "conversation.rewind"),
         true <- Call.available?(socket.assigns.scope, "interactive.rewind"),
         # W3 fix wave. The points survive a close so reopening does not re-ask the
         # runtime, but the *verb* belongs to the dialog that states the warning: a
         # confirm with no dialog on screen is a confirmation nobody was ever shown.
         true <- state.panel == :rewind,
         true <- state.screen == :confirm,
         point when not is_nil(point) <- Enum.at(state.points, state.choice),
         true <- RewindDialog.what?(state.what) do
      to_turn = state.choice + 1

      params =
        socket
        |> session_params(:interactive, id)
        |> Map.merge(%{"to_turn" => to_turn, "what" => state.what})

      case call(socket, "interactive.rewind", params) do
        {:ok, answer} ->
          outcome = RewindDialog.outcome(answer)
          label = point.turn_id || "turn #{to_turn}"

          socket
          |> push_local(%Cell.Runtime{
            label: "Rewound to #{label} (#{state.what})",
            detail: RewindDialog.describe(outcome),
            tone: if(outcome.unrestorable == [], do: :muted, else: :warning)
          })
          |> put_w3(screen: :done, outcome: outcome, error: nil)
          |> refresh()

        refusal ->
          w3_error(socket, refusal)
      end
    else
      _ungated -> socket
    end
  end

  defp rewind_confirm(socket), do: socket

  # ------------------------------------------------------------------ W3.5 Compact

  # `interactive.compact {id, focus?}`, then a fresh `interactive.context`: a fold resets
  # `context_used` and rotates the prefix fingerprint, and a meter inferred from the
  # report would be a number nobody measured (`docs/TUI.md:2196`).
  defp compact(%{assigns: %{open: {:interactive, id}}} = socket, focus) do
    if Commands.available?(socket.assigns, "conversation.compact") do
      focus = String.trim(to_string(focus))

      params =
        socket
        |> session_params(:interactive, id)
        |> then(fn params ->
          if focus == "", do: params, else: Map.put(params, "focus", focus)
        end)

      case call(socket, "interactive.compact", params) do
        {:ok, report} ->
          socket
          |> push_local(Transcript.compaction_block(ContextPanel.compaction(report)))
          |> put_w3(panel: nil, error: nil)
          |> read_context(false)
          |> refresh_info()

        refusal ->
          w3_error(socket, refusal)
      end
    else
      socket
    end
  end

  defp compact(socket, _focus), do: socket

  # ------------------------------------------------------------------ W3.6 Handoff

  # `interactive.handoff {id, prompt?, handoff_id}`. The child's id is caller-owned for
  # the same reason a fork's would be: the verb's ceiling can fire after the child exists,
  # and a client that had to mint a second id to find out would start a second session
  # instead of finding the first. So the child is opened on either answer, and the line
  # says which of the two happened (`tui/src/ui/app/native.rs:165-232`).
  defp handoff(%{assigns: %{open: {:interactive, id}}} = socket, prompt) do
    if Commands.available?(socket.assigns, "session.handoff") do
      prompt = String.trim(to_string(prompt))
      child = minted_id("handoff")

      params =
        socket
        |> session_params(:interactive, id)
        |> Map.put("handoff_id", child)
        |> then(fn params ->
          if prompt == "", do: params, else: Map.put(params, "prompt", prompt)
        end)

      case call(socket, "interactive.handoff", params) do
        {:ok, answer} ->
          opened_child(socket, answer, id, "handed off from")

        # W3 fix wave (H1). **The code decides, not the marker.** `outcome: "unknown"`
        # travels on two different answers: a ceiling that fired *after* the call was
        # dispatched, where the child may well exist under the id this page minted — and
        # an `owner_unavailable`, where the owning machine was offline and nothing was
        # dispatched at all (`gateway/methods/safe.ex:100-114`). Opening a minted child
        # for the second is this page inventing a session. Only the timeout code opens
        # it, which is the rule `tui/src/ui/app/answers.rs:781-790` reads.
        {:error, code, message, %{"outcome" => "unknown"}} = refusal ->
          if code == Methods.code(:upstream_timeout) do
            open_named_child(
              socket,
              child,
              "#{message} — opening #{child}, which is the id this page asked for."
            )
          else
            w3_error(socket, refusal)
          end

        refusal ->
          w3_error(socket, refusal)
      end
    else
      socket
    end
  end

  defp handoff(socket, _prompt), do: socket

  # A caller-owned id for a child session: unguessable, this surface's own, and inside the
  # 128 UTF-8 bytes the contract admits.
  defp minted_id(kind),
    do: "web-#{kind}-" <> (:crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower))

  # Both a fork and a handoff answer in `interactive.start`'s shape. `ready` is read for
  # what it is: `false` is a child that exists and is not up yet, which is worth opening
  # and worth saying.
  defp opened_child(socket, answer, parent, relation) when is_map(answer) do
    child = Map.get(answer, "id") || Map.get(answer, :id)
    ready? = Map.get(answer, "ready", Map.get(answer, :ready, true))

    if is_binary(child) and child != "" do
      said =
        if ready? == false do
          "#{relation} #{parent}: #{child} was accepted and is not ready yet; it is open and " <>
            "will fill in."
        else
          "#{relation} #{parent}: this is the child, #{child}."
        end

      open_named_child(socket, child, said)
    else
      put_w3(socket,
        panel: nil,
        error:
          "The runtime accepted that but named no child session, so there is nothing to open."
      )
    end
  end

  defp opened_child(socket, _unreadable, _parent, _relation),
    do: put_w3(socket, error: "The runtime answered something this build cannot read.")

  # The line is recorded against the *child*, because that is the page it belongs on and
  # `w3/1` hands back the default for any other session.
  defp open_named_child(socket, child, said) do
    socket
    |> refresh()
    |> assign(:w3, %{@w3 | subject: {:interactive, child}, notice: said})
    |> push_patch(to: Route.session(:interactive, child))
  end

  # ------------------------------------------------------------------ W3.7 Context

  # `interactive.context {id}`. `show?` opens the panel when the answer lands; otherwise
  # the numbers only refresh the meter, which is what a compaction asks for.
  defp read_context(%{assigns: %{open: {:interactive, id}}} = socket, show?) do
    if Call.available?(socket.assigns.scope, "interactive.context") do
      case call(socket, "interactive.context", session_params(socket, :interactive, id)) do
        {:ok, answer} ->
          socket = put_w3(socket, reading: ContextPanel.read(answer), error: nil)
          if show?, do: open_w3(socket, :context), else: socket

        refusal ->
          if show?, do: socket |> open_w3(:context) |> w3_error(refusal), else: socket
      end
    else
      socket
    end
  end

  defp read_context(socket, _show?), do: socket

  # ------------------------------------------------------------ W3.8 Operator shell

  # A draft beginning with `!` is claimed here and **never becomes a turn**. It is routed
  # to `workspace.exec {id, command}`, which runs it through `/bin/sh -c` in the session's
  # admitted workspace on its owner node — which is what the composer says before Enter is
  # pressed, because it is the one thing about `!` a person cannot infer from the screen
  # (`tui/src/ui/app/native.rs:492-546`).
  defp operator_shell(%{assigns: %{open: {:interactive, id}}} = socket, command) do
    command = String.trim(command)

    cond do
      not Commands.shell_offered?(socket.assigns) ->
        socket

      command == "" ->
        assign(socket, :composer_error, "Type a command after the !.")

      true ->
        params =
          socket
          |> session_params(:interactive, id)
          |> Map.put("command", command)

        case call(socket, "workspace.exec", params) do
          {:ok, result} ->
            socket
            |> push_local(shell_block(command, result))
            |> put_draft("", false)
            |> assign(:composer_error, nil)
            |> put_w3(shell: nil)
            |> push_event("draft-sent", %{key: socket.assigns.draft_key, text: "!" <> command})

          refusal ->
            shell_refused(socket, command, refusal)
        end
    end
  end

  defp operator_shell(socket, _command), do: socket

  @doc """
  Which machine and which directory a `!` will run in, in the words the composer uses.

  Said **before** Enter is pressed, every time, because it is the one thing about `!` a
  person cannot infer from the screen: not here, but on the session's owner node, in the
  workspace the agent is editing (`tui/src/ui/app/native.rs:548-562`). Where the runtime
  named neither, it says that rather than naming this browser's machine.
  """
  # The words for a machine this runtime never named. Said rather than "this computer",
  # which is what `Presentation.node_label/2` answers for an unnamed BEAM and the one
  # thing a `!` band must not claim.
  @owner_machine "this session's owner machine"

  @spec shell_where(term(), term(), list()) :: String.t()
  def shell_where(row, info, roster \\ []) do
    # W3 fix wave (M1). `node_label/2` answers "this computer" for an unnamed BEAM, which
    # is the whole of what this sentence exists to deny: `!` runs *there*, in the session's
    # workspace, not in the browser. Treated as a sentinel and replaced with the terminal
    # client's own fallback (`App::shell_where`, `tui/src/ui/app/native.rs:548-562`).
    node =
      case row do
        %Rail.Row{node: node} when not is_nil(node) -> owner_words(node, roster)
        _absent -> @owner_machine
      end

    workspace =
      (is_map(info) && Map.get(info, :workspace)) ||
        case row do
          %Rail.Row{workspace: workspace} -> workspace
          _absent -> nil
        end

    case workspace do
      path when is_binary(path) and path != "" -> "#{node}, in #{path}"
      _unreported -> node
    end
  end

  # How many characters of a command the block's label carries
  # (`tui/src/ui/app/native.rs:43`).
  @command_label 96

  # The reply as the transcript's own runtime block. Keyed on the digest the runtime
  # returned, so its durable `operator_shell` provider event is not drawn a second time in
  # the thinner form the ledger keeps — the reply wins because it carries the elapsed
  # time, the spill path and the command's own text, none of which the ledger records.
  defp shell_block(command, result) when is_map(result) do
    exit_status = Map.get(result, :exit_status, Map.get(result, "exit_status"))
    timed_out = Map.get(result, :timed_out, Map.get(result, "timed_out")) == true
    duration = Map.get(result, :duration_ms, Map.get(result, "duration_ms"))
    bytes = Map.get(result, :output_bytes, Map.get(result, "output_bytes"))
    output = Map.get(result, :output, Map.get(result, "output"))
    spilled = Map.get(result, :spilled, Map.get(result, "spilled"))
    spill_error = Map.get(result, :spill_error, Map.get(result, "spill_error"))
    digest = Map.get(result, :command_digest, Map.get(result, "command_digest"))

    facts =
      [
        case exit_status do
          0 -> "exit 0"
          status when is_integer(status) -> "exit #{status}"
          _unreported -> "no exit status"
        end,
        if(timed_out, do: "timed out"),
        if(is_integer(duration), do: elapsed_word(duration)),
        if(is_integer(bytes), do: "#{bytes} bytes"),
        if(is_binary(spilled), do: "full output at #{spilled}"),
        if(is_binary(spill_error), do: "the rest could not be written: #{spill_error}")
      ]
      |> Enum.reject(&is_nil/1)

    %Cell.Runtime{
      label: "$ " <> String.slice(command, 0, @command_label),
      detail: Enum.join(facts, " · "),
      body: if(is_binary(output), do: Transcript.body_rows(output), else: []),
      # A non-zero exit is a *result*, not a fault: `grep` finding nothing is not a broken
      # command. Only a timeout or a non-zero status is drawn as one, which is the
      # distinction the terminal client keeps.
      tone: if(timed_out or exit_status != 0, do: :warning, else: :muted),
      key: if(is_binary(digest), do: digest)
    }
  end

  defp owner_words(node, roster) do
    said = Presentation.node_label(node, roster)

    if said == Presentation.this_computer() or said == "not reported",
      do: @owner_machine,
      else: said
  end

  defp elapsed_word(ms) when ms < 1_000, do: "#{ms}ms"
  defp elapsed_word(ms) when ms < 60_000, do: "#{div(ms, 1_000)}s"
  defp elapsed_word(ms), do: "#{div(ms, 60_000)}m #{rem(div(ms, 1_000), 60)}s"

  # A refusal stays **on the composer**, not in a notice that expires: the refusal and the
  # offer to fix it belong on screen together.
  #
  # `["shell_refused", detail]` is the one shape that grows a permissions offer. Every
  # other refusal this verb can give — a closed session, a blank command, a ledger that
  # could not record the attempt — reaches the ordinary composer error, because there is
  # no rule to offer for it (`tui/src/ui/app/native.rs:600-663`).
  defp shell_refused(socket, command, refusal) do
    case shell_refusal_detail(refusal) do
      nil ->
        socket
        |> put_draft("!" <> command, false)
        |> assign(:composer_error, refusal_message(refusal))
        |> put_w3(shell: nil)

      detail ->
        # W3 fix wave (L7). The session's own workspace first and the payload's as the
        # fallback, which is the order the terminal client reads them in
        # (`tui/src/ui/app/native.rs:640-645`): the refusal describes an attempt, and the
        # session is what the rule would be scoped to.
        workspace = session_workspace(socket) || detail["workspace"]

        {rule, missing} =
          Transcript.suggested_rule(detail["suggested_rule"], socket.assigns.methods, workspace)

        socket
        |> put_draft("!" <> command, false)
        |> assign(:composer_error, nil)
        |> put_w3(
          shell: %{
            reason: detail["reason"],
            # The runtime's own sentence, never this surface's paraphrase of it.
            message: detail["message"] || refusal_message(refusal),
            denied_by: denied_by(detail["denied_by"]),
            suggested_rule: detail["suggested_rule"],
            rule: rule,
            missing: missing
          }
        )
    end
  end

  # `Ouroboros.Gateway.Wire` encodes an Elixir tuple as a JSON array, so a tagged runtime
  # refusal is always a two-element `[tag, detail]`. Matching on the tag rather than on
  # the presence of `suggested_rule` is what keeps the offer from appearing beside a
  # refusal that has nothing to do with permissions.
  defp shell_refusal_detail({:error, _code, _message, ["shell_refused", detail]})
       when is_map(detail),
       do: detail

  defp shell_refusal_detail(_other), do: nil

  # The engine answers with a whole rule record; the pattern is the half worth naming, and
  # its id is the fallback for a store that returned no pattern.
  defp denied_by(rule) when is_map(rule), do: rule["pattern"] || rule["id"]
  defp denied_by(rule) when is_binary(rule), do: rule
  defp denied_by(_absent), do: nil

  # The one-key answer to a refusal: write the rule the engine itself suggested, through
  # exactly the code path the approval card's "Remember" uses — same `permissions.add`
  # params, same workspace scoping, same notice.
  defp remember_shell_rule(socket) do
    case w3(socket.assigns).shell do
      %{rule: %Approval.Rule{} = rule} ->
        socket |> add_rule(rule) |> put_w3(shell: nil)

      _no_offer ->
        socket
    end
  end

  # ------------------------------------------------------------------ W3.9 MCP list

  # Routed to the node the *session* runs on, because a server runs where its session
  # does, and narrowed by the workspace it names — without which the answer is only the
  # servers already running, and the entries this node configured but never started, and
  # every entry the loader refused, are missing (`tui/src/ui/app/native.rs:687-742`).
  defp open_mcp(socket) do
    params =
      %{}
      |> maybe_put("node", mcp_node(socket))
      |> maybe_put("workspace", session_workspace(socket))

    socket = open_w3(socket, :mcp)

    case call(socket, "mcp.list", params) do
      {:ok, answer} -> put_w3(socket, mcp: McpPanel.read(answer), error: nil)
      refusal -> socket |> put_w3(mcp: nil) |> w3_error(refusal)
    end
  end

  defp mcp_node(%{assigns: %{open: {plane, id}}} = socket) do
    case owner(socket, plane, id) do
      nil -> nil
      owner -> Atom.to_string(owner)
    end
  end

  defp mcp_node(_closed), do: nil

  defp maybe_put(params, _key, nil), do: params
  defp maybe_put(params, _key, ""), do: params
  defp maybe_put(params, key, value), do: Map.put(params, key, to_string(value))

  # ------------------------------------------------------------------------------------
  # What an operator's own verb answered, recorded where they asked it
  # ------------------------------------------------------------------------------------

  # `Watch.note/3` anchors the block at the newest sequence held, which is where a reader
  # looking at the transcript would otherwise see an unexplained jump. `redraw/2` is the
  # projection's own entry point; nothing here draws a cell of its own.
  defp push_local(%{assigns: %{watch: %Watch{}}} = socket, %Cell.Runtime{} = block) do
    socket
    |> update(:watch, &Watch.note(&1, {:local, block}))
    |> redraw(:reset)
  end

  defp push_local(socket, _block), do: socket

  # ------------------------------------------------------------------------------------
  # W3.10 — the two gates the composer's own controls were missing
  # ------------------------------------------------------------------------------------

  # Whether a send may reach the runtime at all, asked of the same four facts the composer
  # is drawn from. `focused/1` renders the form only where all of them hold, so an event
  # arriving without them did not come from a control — and the honest answer to a click
  # that did not happen is to do nothing.
  defp sendable?(assigns) do
    match?({:interactive, _id}, Map.get(assigns, :open)) and
      Map.get(assigns, :scope) == :operate and
      Call.available?(:operate, "interactive.send_message") and
      not ended?(assigns, row(assigns.rows, assigns.open))
  end

  # ------------------------------------------------------------------------------------
  # W3 — the one render insertion
  # ------------------------------------------------------------------------------------

  @doc false
  @spec w3_panels_assigns(map()) :: map()
  def w3_panels_assigns(assigns) do
    state = w3(assigns)

    %{
      w3: state,
      # Built only for the panel that is open. `Watch.entries/1` walks the whole held
      # ledger, and doing it on every three-second poll to draw nothing would be the one
      # cost this panel could impose on a page nobody opened it from.
      rows: if(state.panel == :details, do: details_rows(assigns), else: []),
      turns: if(state.panel == :backtrack, do: backtrack_turns(assigns), else: []),
      can_fork: Commands.forkable?(assigns),
      can_resend: Commands.resendable?(assigns),
      machines: machines(assigns.status),
      # A `<dialog>` owns the screen: two of them stacked leaves the lower one in the top
      # layer with nothing listening for its `cancel`, so `Esc` stops working. The palette,
      # the shortcut sheet and a confirmation all outrank these.
      blocked:
        not is_nil(assigns.palette) or assigns.shortcuts? or not is_nil(assigns.session_action),
      # W3 fix wave (M4). The dialog links rather than pushes: a refusal carries no
      # `content-disposition`, and a redirect would have taken the deck with it.
      text_url: export_url(%{assigns: assigns}, "text"),
      ndjson_url: export_url(%{assigns: assigns}, "ndjson")
    }
  end

  @doc """
  Every panel this slice draws, and the line one of its verbs left behind.

  One element next to `Palette.overlays/1` for the same reason that one is there: a
  `<dialog>` belongs at the top of the document rather than inside the column it is about,
  and the browser owns the modality, the backdrop and the focus trap.
  """
  attr :w3, :map, required: true
  attr :rows, :list, default: []
  attr :turns, :list, default: []
  attr :can_fork, :boolean, default: false
  attr :can_resend, :boolean, default: false
  attr :machines, :list, default: []
  attr :blocked, :boolean, default: false
  attr :text_url, :any, default: nil
  attr :ndjson_url, :any, default: nil

  def w3_panels(assigns) do
    ~H"""
    <div id="ouro-w3">
      <p :if={@w3.notice} class="ouro-w3-notice" role="status">{@w3.notice}</p>

      <DetailsPanel.panel
        :if={not @blocked and @w3.panel == :details}
        rows={@rows}
        error={@w3.error}
      />

      <BacktrackDialog.dialog
        :if={not @blocked and @w3.panel == :backtrack}
        turns={@turns}
        can_fork={@can_fork}
        can_resend={@can_resend}
        error={@w3.error}
      />

      <RewindDialog.dialog
        :if={not @blocked and @w3.panel == :rewind}
        screen={@w3.screen}
        points={@w3.points}
        choice={@w3.choice}
        what={@w3.what}
        outcome={@w3.outcome}
        error={@w3.error}
      />

      <ContextPanel.panel
        :if={not @blocked and @w3.panel == :context}
        context={@w3.reading}
        error={@w3.error}
      />

      <McpPanel.panel
        :if={not @blocked and @w3.panel == :mcp}
        mcp={@w3.mcp}
        machines={@machines}
        error={@w3.error}
      />

      <VerbDialogs.compact :if={not @blocked and @w3.panel == :compact} error={@w3.error} />
      <VerbDialogs.handoff :if={not @blocked and @w3.panel == :handoff} error={@w3.error} />
      <VerbDialogs.export
        :if={not @blocked and @w3.panel == :export}
        text_url={@text_url}
        ndjson_url={@ndjson_url}
      />
    </div>
    """
  end

  # ui-parity W2
  #
  # The command palette, the shortcut sheet, and the four verbs this slice added to the
  # composer. Two rules hold across all of them:
  #
  #   * **the palette runs the page's own events.** A row that "interrupts" forwards to
  #     the same `handle_event("interrupt", …)` clause the button reaches, through
  #     `forward/3`. Nothing is reimplemented beside a control, so the two cannot drift —
  #     and every gate, refusal and re-read the control already had applies unchanged.
  #   * **a row is checked twice.** `Ouroboros.Web.Commands.available/1` decides what is
  #     drawn, and `run_command/2` asks the same question again before doing anything: a
  #     modal left open while a turn completed must not run a verb that stopped being
  #     possible while nobody was looking.
  #
  # The helpers come first only because Elixir wants every `handle_event/3` clause in one
  # run, and this slice's clauses sit immediately above the ones that were already here.

  # ---------------------------------------------------------------------- The palette

  # A modal owns the screen while it is open, and this one refuses to appear over
  # another. Two `<dialog>`s stacked is not a cosmetic problem: `palette-run` forwards
  # `session-action`, which would rewrite the confirmation underneath into a different
  # question about a different session with no click of the operator's in between. The
  # browser half refuses the keystroke; this half refuses the event, because a hand-made
  # `palette-open` must not be able to do what the key cannot.
  defp open_palette(%{assigns: %{session_action: action}} = socket) when not is_nil(action),
    do: socket

  defp open_palette(socket) do
    socket
    |> assign(:shortcuts?, false)
    |> assign(:palette, %{query: "", selected: 0, rows: Commands.available(socket.assigns)})
  end

  defp close_palette(socket), do: assign(socket, :palette, nil)

  defp open_shortcuts(%{assigns: %{session_action: action}} = socket) when not is_nil(action),
    do: socket

  defp open_shortcuts(socket), do: socket |> close_palette() |> assign(:shortcuts?, true)

  defp filter_palette(%{assigns: %{palette: nil}} = socket, _query), do: socket

  defp filter_palette(socket, query) do
    query = String.slice(query, 0, 120)
    rows = socket.assigns |> Commands.available() |> Commands.search(query)

    assign(socket, :palette, %{query: query, selected: 0, rows: rows})
  end

  defp move_palette(%{assigns: %{palette: nil}} = socket, _direction), do: socket

  defp move_palette(%{assigns: %{palette: palette}} = socket, direction) do
    last = max(length(palette.rows) - 1, 0)

    selected =
      if direction == "next",
        do: min(palette.selected + 1, last),
        else: max(palette.selected - 1, 0)

    assign(socket, :palette, %{palette | selected: selected})
  end

  # The second gate, and a third one in front of it.
  #
  # A confirmation dialog is a question awaiting an answer, and the palette must not act
  # behind one: every `session-action` row would rewrite the dialog underneath into a
  # different question about a different session. The browser half already refuses the
  # keys; a hand-made `palette-run` is refused here for the same reason.
  defp run_command(%{assigns: %{session_action: action}} = socket, _id) when not is_nil(action),
    do: socket

  defp run_command(socket, id) do
    if Commands.available?(socket.assigns, id), do: command(socket, id), else: socket
  end

  # One `handle_event` clause, called rather than copied. `forward/3` is what makes a
  # palette row and the control beside it the same code path.
  defp forward(socket, event, params \\ %{}) do
    {:noreply, socket} = handle_event(event, params, socket)
    socket
  end

  defp command(socket, "session.new"), do: push_navigate(socket, to: "/new")
  defp command(socket, "session.switch"), do: reveal(socket, ".ouro-rail-search input")
  defp command(socket, "session.rename"), do: session_action(socket, "rename")
  defp command(socket, "session.end"), do: session_action(socket, "close")
  defp command(socket, "session.delete"), do: session_action(socket, "delete")

  defp command(socket, id) when id in ["turn.send", "turn.queue"],
    do: push_event(socket, "composer-submit", %{key: socket.assigns.draft_key})

  # Deliberately a reveal rather than a send. A steer must carry the words in the box,
  # and what this process holds is the draft as of the last 400ms debounce — see
  # `Ouroboros.Web.Live.Composer`'s note on the second submit button. So the row focuses
  # the control and the operator presses it.
  defp command(socket, "turn.steer"), do: reveal(socket, "[data-ouro-steer]")

  defp command(socket, "turn.interrupt"), do: forward(socket, "interrupt")
  defp command(socket, "turn.retry"), do: forward(socket, "retry")
  defp command(socket, "turn.auto_approve"), do: forward(socket, "auto_approve")
  defp command(socket, "turn.plan"), do: configure_plan(socket)

  defp command(socket, "turn.effort"),
    do: reveal(socket, ~s([phx-click="configure"][phx-value-field="reasoning_effort"]))

  defp command(socket, "turn.sandbox"),
    do: reveal(socket, ~s([phx-click="configure"][phx-value-field="sandbox_mode"]))

  defp command(socket, "turn.model"), do: socket |> fetch_models() |> reveal(".ouro-model-select")
  defp command(socket, "turn.approval"), do: reveal(socket, ".ouro-approval")
  defp command(socket, "conversation.copy"), do: copy_last(socket, :rendered)
  defp command(socket, "conversation.copy_source"), do: copy_last(socket, :source)

  defp command(%{assigns: %{open: {plane, id}}} = socket, "conversation.history"),
    do: forward(socket, "load-history", %{"session" => "#{plane}:#{id}"})

  defp command(socket, "runtime.status"), do: push_navigate(socket, to: "/status")
  defp command(socket, "runtime.audit"), do: push_navigate(socket, to: "/audit")
  defp command(socket, "client.settings"), do: push_navigate(socket, to: "/settings")
  defp command(socket, "client.theme"), do: push_event(socket, "ouro-chrome", %{control: "theme"})
  defp command(socket, "client.shortcuts"), do: open_shortcuts(socket)

  defp command(socket, "client.notifications"),
    do: push_event(socket, "ouro-chrome", %{control: "bell"})

  # ui-parity W3. Every row here either opens one of this slice's panels or runs a verb
  # whose only argument is the session — the ones that take words of their own (a
  # compaction's focus, a handoff's prompt) open a dialog to be given them, for the same
  # reason `turn.steer` reveals a control rather than pressing it.
  defp command(socket, "conversation.details"), do: open_w3(socket, :details)
  defp command(socket, "conversation.export"), do: open_w3(socket, :export)
  defp command(socket, "conversation.backtrack"), do: open_w3(socket, :backtrack)
  defp command(socket, "conversation.rewind"), do: open_rewind(socket)
  defp command(socket, "conversation.compact"), do: open_w3(socket, :compact)
  defp command(socket, "conversation.context"), do: read_context(socket, true)
  defp command(socket, "session.fork"), do: fork(socket)
  defp command(socket, "session.handoff"), do: open_w3(socket, :handoff)
  defp command(socket, "runtime.mcp"), do: open_mcp(socket)

  # `!` takes a command line, so the row leads to the box it is typed in. The composer
  # says where it will run the moment the draft starts with one.
  defp command(socket, "turn.shell"), do: reveal(socket, "#ouro-composer-input")

  defp command(socket, _unrunnable), do: socket

  defp session_action(%{assigns: %{open: {plane, id}}} = socket, action),
    do:
      forward(socket, "session-action", %{
        "action" => action,
        "plane" => to_string(plane),
        "id" => id
      })

  defp session_action(socket, _action), do: socket

  # A control the palette can only lead to, because it takes an argument this list has no
  # way to carry. The browser opens whatever disclosure it is inside and focuses it.
  defp reveal(socket, selector), do: push_event(socket, "ouro-reveal", %{selector: selector})

  # Two different strings, and only the one that was asked for is sent. The Markdown is
  # this process's — it is what the model wrote. The rendered words are the browser's, and
  # are read back out of the prose it already drew rather than re-derived here, because a
  # second renderer would be a second answer to what the message says.
  defp copy_last(socket, which) do
    case Commands.last_agent_message(socket.assigns) do
      nil ->
        socket

      {dom_id, source} ->
        case which do
          :source -> push_event(socket, "ouro-copy", %{text: source})
          :rendered -> push_event(socket, "ouro-copy", %{selector: "##{dom_id} .ouro-prose"})
        end
    end
  end

  # The rail in drawn order: triaged, filtered by the search box, then group by group —
  # the same three steps `render/1` and `rail/1` take, so `]` lands on the row underneath.
  defp move_rail(socket, direction) do
    ordered =
      socket.assigns.rows
      |> Rail.triaged(pending(socket.assigns))
      |> filter_sessions(socket.assigns.session_query)
      |> then(fn triaged ->
        for group <- Rail.groups(),
            entry <- triaged,
            entry.group == group,
            do: {entry.row.plane, entry.row.id}
      end)

    case rail_target(ordered, socket.assigns.open, direction) do
      nil -> socket
      {plane, id} -> push_patch(socket, to: Route.session(plane, id))
    end
  end

  defp rail_target([], _open, _direction), do: nil

  defp rail_target(ordered, open, direction) do
    case {Enum.find_index(ordered, &(&1 == open)), direction} do
      {nil, "next"} -> List.first(ordered)
      {nil, "prev"} -> List.last(ordered)
      {at, "next"} -> Enum.at(ordered, min(at + 1, length(ordered) - 1))
      {at, "prev"} -> Enum.at(ordered, max(at - 1, 0))
    end
  end

  # ------------------------------------------------------------------- Steer and plan

  defp steer(%{assigns: %{open: {:interactive, _id}}} = socket, "") do
    assign(socket, :composer_error, "Write something before steering the turn.")
  end

  defp steer(%{assigns: %{open: {:interactive, id}}} = socket, text) do
    if steer_offered?(socket.assigns) do
      params =
        socket
        |> session_params(:interactive, id)
        |> Map.put("input", turn_input(socket, text))

      case call(socket, "interactive.steer", params) do
        # No caller-owned id and no `last_send`: a steer is an injection into a call that
        # is already running, and the gateway's own table says it has no idempotency
        # (`methods/contract.ex:727-734`). So it is never adopted and never retried here.
        {:ok, _accepted} ->
          socket
          |> put_draft("", false)
          |> clear_next_effort()
          |> assign(:composer_error, nil)
          |> push_event("draft-sent", %{key: socket.assigns.draft_key, text: text})

        refusal ->
          refused(socket, text, refusal_message(refusal))
      end
    else
      socket
    end
  end

  defp steer(socket, _text), do: socket

  # The same predicate the catalogue row is gated by, asked again here. A form field and
  # a `phx-value-*` are both browser input: the Steer button appearing on screen is not
  # what makes a steer legal, `Commands.steerable?/1` is — an open and unfinished
  # session, a turn actually running, the verb served at this scope, and a transport that
  # did not declare it cannot be steered.
  defp steer_offered?(assigns), do: Commands.steerable?(assigns)

  defp configure_plan(%{assigns: %{open: {:interactive, id}}} = socket) do
    if reconfigurable?(socket.assigns) do
      want = not planning?(socket.assigns)
      params = socket |> session_params(:interactive, id) |> Map.put("plan", want)

      case call(socket, "interactive.configure", params) do
        {:ok, _configured} -> socket |> assign(:composer_error, nil) |> refresh_info()
        refusal -> assign(socket, :composer_error, refusal_message(refusal))
      end
    else
      socket
    end
  end

  defp configure_plan(socket), do: socket

  defp planning?(assigns), do: assigns |> Commands.options() |> Map.get(:plan) == true

  # The two halves `interactive.configure` is gated by, and the reason they are two: the
  # runtime declares `dynamic_model` and `dynamic_configuration` separately, and a
  # transport that can be re-pointed at a model may still refuse every other change
  # (`lib/ouroboros/provider.ex:16-27`; the terminal client reads the pair at
  # `tui/src/ui/app/session.rs:1576-1580`). Silence is offered; only a declared `false`
  # withholds. `ended?/2` is asked because a finished conversation takes no configuration
  # at all and draws none of these controls.
  defp reconfigurable?(assigns), do: Commands.configurable?(assigns, :configuration)
  defp remodelable?(assigns), do: Commands.configurable?(assigns, :model)

  # ----------------------------------------------------------------- The model picker

  # A `<select>`'s value is browser input, exactly as a `phx-value-choice` is, so it is
  # matched against the rows this page actually drew rather than passed through to a
  # closed envelope.
  defp configure_model(%{assigns: %{open: {:interactive, id}}} = socket, model) do
    model = String.trim(model)

    if offered_model?(socket.assigns, model) and remodelable?(socket.assigns) do
      params = socket |> session_params(:interactive, id) |> Map.put("model", model)

      case call(socket, "interactive.configure", params) do
        # Nothing assigned optimistically: the label moves when the next read says it
        # moved, which is the rule the sandbox and thinking pickers already follow.
        {:ok, _configured} -> socket |> assign(:composer_error, nil) |> refresh_info()
        refusal -> assign(socket, :composer_error, refusal_message(refusal))
      end
    else
      socket
    end
  end

  defp configure_model(socket, _model), do: socket

  defp offered_model?(assigns, model) do
    case assigns.composer_extras.models do
      rows when is_list(rows) -> Enum.any?(rows, &(&1.id == model))
      _unfetched_or_refused -> false
    end
  end

  # Re-fetched after a refusal as well as when nothing has been read: one transient
  # `runtime.models` failure must not leave the picker dead for the life of the page. A
  # successful read is kept for the session it was read in — `reset_session_state/1`
  # drops it when a different conversation is opened, because a catalogue and the search
  # typed into it are that conversation's, not this tab's.
  defp fetch_models(%{assigns: %{composer_extras: %{models: nil}}} = socket),
    do: read_models(socket)

  defp fetch_models(%{assigns: %{composer_extras: %{models: {:error, _refused}}}} = socket),
    do: read_models(socket)

  defp fetch_models(socket), do: socket

  defp read_models(socket) do
    if Call.available?(socket.assigns.scope, "runtime.models") do
      case call(socket, "runtime.models", %{}) do
        {:ok, catalogue} -> put_extra(socket, :models, Composer.model_rows(catalogue))
        refusal -> put_extra(socket, :models, {:error, refusal_message(refusal)})
      end
    else
      put_extra(
        socket,
        :models,
        {:error, "this build does not serve runtime.models, so there is no catalogue to list"}
      )
    end
  end

  # ---------------------------------------------------------------- The per-turn effort

  defp arm_effort(socket, "session"),
    do: socket |> assign(:last_send, nil) |> clear_next_effort()

  defp arm_effort(socket, choice) do
    if choice in reasoning_efforts(socket.assigns) and is_binary(socket.assigns.draft_key),
      do:
        socket
        |> assign(:last_send, nil)
        |> put_extra(:next_effort, {socket.assigns.draft_key, choice}),
      else: socket
  end

  defp clear_next_effort(socket), do: put_extra(socket, :next_effort, nil)

  # Keyed by the conversation it was armed for. A per-turn effort is a decision about the
  # next thing said *here*; carrying it into whatever session is opened next would be this
  # page applying a setting to a conversation nobody chose it for — and nothing clears
  # this view's per-session state on a switch except the key it is held under.
  defp armed_effort(assigns),
    do: armed_for(assigns.composer_extras, assigns.draft_key)

  defp armed_for(%{next_effort: {key, effort}}, key), do: effort
  defp armed_for(_extras, _key), do: nil

  # B4. The bare string for a plain prompt, the gateway's object form the moment there is
  # something in it a string could not carry — `TurnInput::to_value`,
  # `tui/src/model.rs:2789-2815`. Sending the object for every turn would rewrite the wire
  # for nothing.
  defp turn_input(socket, text) do
    refs = Map.get(socket.assigns, :image_refs, [])
    effort = armed_effort(socket.assigns)

    if refs == [] and is_nil(effort) do
      text
    else
      %{"prompt" => text}
      |> then(fn input ->
        if refs == [], do: input, else: Map.put(input, "image_attachments", refs)
      end)
      |> then(fn input ->
        if effort, do: Map.put(input, "reasoning_effort", effort), else: input
      end)
    end
  end

  defp put_extra(socket, key, value),
    do: update(socket, :composer_extras, &Map.put(&1, key, value))

  @impl true
  def handle_event("palette-toggle", _params, socket) do
    {:noreply, if(socket.assigns.palette, do: close_palette(socket), else: open_palette(socket))}
  end

  def handle_event("palette-open", _params, socket), do: {:noreply, open_palette(socket)}
  def handle_event("palette-close", _params, socket), do: {:noreply, close_palette(socket)}

  def handle_event("palette-filter", %{"query" => query}, socket) when is_binary(query),
    do: {:noreply, filter_palette(socket, query)}

  def handle_event("palette-filter", _params, socket), do: {:noreply, socket}

  def handle_event("palette-move", %{"direction" => direction}, socket)
      when direction in ["next", "prev"],
      do: {:noreply, move_palette(socket, direction)}

  def handle_event("palette-move", _params, socket), do: {:noreply, socket}

  # A click names its row; `Enter` runs whatever `↑↓` left selected.
  def handle_event("palette-run", %{"id" => id}, socket) when is_binary(id),
    do: {:noreply, socket |> close_palette() |> run_command(id)}

  def handle_event(
        "palette-run",
        _params,
        %{assigns: %{palette: %{rows: rows, selected: at}}} = socket
      ) do
    case Enum.at(rows, at) do
      nil -> {:noreply, close_palette(socket)}
      command -> {:noreply, socket |> close_palette() |> run_command(command.id)}
    end
  end

  def handle_event("palette-run", _params, socket), do: {:noreply, socket}

  def handle_event("shortcuts-open", _params, socket),
    do: {:noreply, open_shortcuts(socket)}

  def handle_event("shortcuts-close", _params, socket),
    do: {:noreply, assign(socket, :shortcuts?, false)}

  # ------------------------------------------------------------------------------------
  # ui-parity W3
  #
  # Every clause below is reached from a control this slice drew, and every one of them
  # re-asks the catalogue's own question before it calls anything: `phx-click` is browser
  # input, and a panel left open while a turn completed must not run a verb that stopped
  # being possible while nobody was looking.
  # ------------------------------------------------------------------------------------

  def handle_event("w3-close", _params, socket), do: {:noreply, close_w3(socket)}

  def handle_event("w3-details-toggle", %{"sequence" => sequence}, socket),
    do: {:noreply, with_sequence(socket, sequence, &toggle_detail/2)}

  def handle_event("w3-details-fetch", %{"sequence" => sequence}, socket),
    do: {:noreply, with_sequence(socket, sequence, &fetch_detail/2)}

  # The format is matched against the two this dialog drew before anything closes: a
  # `phx-value-format` is browser input, and a row that navigated nowhere while dismissing
  # the dialog would look like a download that failed silently.
  def handle_event("w3-export", %{"format" => format}, socket) do
    acting(socket, fn socket ->
      if format in ["text", "ndjson"] and
           Commands.available?(socket.assigns, "conversation.export"),
         do: socket |> close_w3() |> export_to(format),
         else: socket
    end)
  end

  def handle_event("w3-backtrack-edit", %{"sequence" => sequence}, socket),
    do: acting(socket, fn socket -> with_sequence(socket, sequence, &backtrack_edit/2) end)

  def handle_event("w3-backtrack-fork", _params, socket), do: acting(socket, &fork/1)

  def handle_event("w3-rewind-pick", %{"choice" => choice}, socket) do
    case Integer.parse(to_string(choice)) do
      {at, ""} when at >= 0 ->
        state = w3(socket.assigns)

        if at < length(state.points),
          do: {:noreply, put_w3(socket, choice: at, screen: :confirm, error: nil)},
          else: {:noreply, socket}

      _unreadable ->
        {:noreply, socket}
    end
  end

  # A `phx-value-what` is browser input and `interactive.rewind`'s `what` is a closed
  # enum, so it is matched against the three this dialog drew rather than passed through.
  def handle_event("w3-rewind-what", %{"what" => what}, socket) do
    if RewindDialog.what?(what),
      do: {:noreply, put_w3(socket, what: what)},
      else: {:noreply, socket}
  end

  def handle_event("w3-rewind-back", _params, socket),
    do: {:noreply, put_w3(socket, screen: :choose, error: nil)}

  def handle_event("w3-rewind-confirm", _params, socket),
    do: acting(socket, &rewind_confirm/1)

  def handle_event("w3-compact", params, socket),
    do: acting(socket, &compact(&1, Map.get(params, "focus", "")))

  def handle_event("w3-handoff", params, socket),
    do: acting(socket, &handoff(&1, Map.get(params, "prompt", "")))

  def handle_event("w3-shell-remember", _params, socket),
    do: acting(socket, &remember_shell_rule/1)

  def handle_event("w3-shell-dismiss", _params, socket),
    do: {:noreply, put_w3(socket, shell: nil)}

  # A `phx-value-*` this slice never drew. Same answer the approval handlers give: do
  # nothing, rather than crash a view and make an operator's transcript remount.
  def handle_event("w3-" <> _unknown, _params, socket), do: {:noreply, socket}

  # `[` and `]` walk the rail in the order it is drawn — triaged, filtered by the search
  # box, group by group. A patch rather than a navigation, exactly as clicking the row is.
  def handle_event("rail-move", %{"direction" => direction}, socket)
      when direction in ["next", "prev"],
      do: {:noreply, move_rail(socket, direction)}

  def handle_event("rail-move", _params, socket), do: {:noreply, socket}

  # B3. Steer is the composer's second submit button, so the draft rides the form rather
  # than the debounced copy this process happens to be holding. Placed above the ordinary
  # `send` clause and matched on the verb the button carries: a form submitted without it
  # is an ordinary send and falls through untouched.
  def handle_event("send", %{"verb" => "steer", "message" => text} = params, socket)
      when is_binary(text) do
    socket =
      cond do
        not current_composer?(socket, params) ->
          socket

        ImageAttachments.refs(params) != {:ok, []} ->
          assign(
            socket,
            :composer_error,
            "Images can be queued with Send; steering accepts text only."
          )

        true ->
          steer(socket, String.trim_trailing(text))
      end

    {:noreply, socket}
  end

  # B2. Plan mode is not a Harness configuration key, and which transports can enter it
  # mid-life is the runtime's to say. Nothing is predicted here: the answer is read back
  # and a refusal is rendered in the runtime's own words, which is what the terminal
  # client does (`tui/src/ui/app/session.rs:1236-1318`).
  def handle_event("configure-plan", _params, socket), do: {:noreply, configure_plan(socket)}

  def handle_event("configure-model", %{"model" => model}, socket) when is_binary(model),
    do: {:noreply, configure_model(socket, model)}

  def handle_event("configure-model", _params, socket), do: {:noreply, socket}

  def handle_event("model-search", %{"query" => query}, socket) when is_binary(query),
    do: {:noreply, put_extra(socket, :model_query, String.slice(query, 0, 120))}

  def handle_event("model-search", _params, socket), do: {:noreply, socket}

  # The catalogue is fetched when the disclosure is opened and never again, and never on
  # the three-second cadence — `/new`'s own rule for the same list.
  def handle_event("composer-settings", _params, socket) do
    if remodelable?(socket.assigns),
      do: {:noreply, fetch_models(socket)},
      else: {:noreply, socket}
  end

  # B4. An effort for the next send and only that one, after which the session's own
  # picker is back in charge.
  def handle_event("effort-next-turn", %{"choice" => choice}, socket) when is_binary(choice),
    do: {:noreply, arm_effort(socket, choice)}

  def handle_event("effort-next-turn", _params, socket), do: {:noreply, socket}

  # The Markdown one agent message was written in. Only a cell this view is actually
  # holding — `phx-value-cell` is browser input, and a cell nobody drew is a message
  # nobody was shown. The rendered half never comes through here: the browser reads that
  # off the prose it already drew.
  def handle_event("copy-source", %{"cell" => id}, socket) when is_binary(id) do
    case Map.get(socket.assigns.cells, id) do
      %{cell: %Cell.Message{speaker: :agent, text: text}} ->
        {:noreply, push_event(socket, "ouro-copy", %{text: text})}

      _undrawn_or_not_a_message ->
        {:noreply, socket}
    end
  end

  def handle_event("copy-source", _params, socket), do: {:noreply, socket}

  # A fold changes what every cell renders as, not what any cell *is*, so the whole stream
  # is rewritten rather than diffed: the projection did not move, the drawing did.
  def handle_event("expand", %{"block" => block}, socket),
    do: {:noreply, socket |> update(:expanded, &MapSet.put(&1, block)) |> redraw(:reset)}

  def handle_event("collapse", %{"block" => block}, socket),
    do: {:noreply, socket |> update(:expanded, &MapSet.delete(&1, block)) |> redraw(:reset)}

  def handle_event("load-history", %{"session" => session}, socket) do
    case socket.assigns.open && Enum.join(Tuple.to_list(socket.assigns.open), ":") do
      ^session when not is_nil(session) ->
        {:noreply, redraw(socket, :older)}

      _closed_or_stale ->
        {:noreply, socket}
    end
  end

  def handle_event("load-history", _params, socket), do: {:noreply, socket}

  # The rail is an operator's index, not a second source of truth. Filtering changes only
  # which already-triaged rows are drawn; it never changes their order, their group, or the
  # currently open session. The short ceiling keeps a hand-crafted browser event from
  # turning a quiet search field into unbounded LiveView state.
  def handle_event("filter-sessions", %{"query" => query}, socket) when is_binary(query) do
    {:noreply, assign(socket, :session_query, String.slice(query, 0, 120))}
  end

  def handle_event("filter-sessions", _params, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # The composer
  # ------------------------------------------------------------------------------------

  # The draft is held server-side so a refusal can hand it back verbatim, and so a live
  # delta landing under the cursor cannot take it away. Debounced at the element: this
  # costs one round trip per pause in typing, not one per keystroke.
  #
  # A change also forgets the last send, which is what makes a deliberate repeat of the
  # same words a second turn while a double-click stays one — see `submission_for/2`.
  def handle_event("image-action", params, socket) do
    id =
      case socket.assigns.open do
        {:interactive, id} -> id
        _ -> nil
      end

    {:reply,
     ImageAttachments.action(socket, params, socket.assigns.draft_key, mcp_node(socket), id),
     socket}
  end

  def handle_event("draft", %{"message" => text} = params, socket) when is_binary(text) do
    socket = if current_composer?(socket, params), do: put_draft(socket, text), else: socket
    {:noreply, socket}
  end

  def handle_event("draft", _params, socket), do: {:noreply, socket}

  def handle_event("send", %{"message" => text} = params, socket) when is_binary(text) do
    socket =
      if current_composer?(socket, params) do
        id =
          case socket.assigns.open do
            {:interactive, id} -> id
            _ -> nil
          end

        case ImageAttachments.bind(socket, params, id, mcp_node(socket)) do
          {:ok, refs} ->
            socket |> assign(:image_refs, refs) |> send_turn(String.trim_trailing(text))

          {:error, message} ->
            assign(socket, :composer_error, message)
        end
      else
        socket
      end

    {:noreply, socket}
  end

  def handle_event(
        "retry",
        _params,
        %{
          assigns: %{
            open: {:interactive, id},
            info: %{last_turn: %{id: source, status: :failed, retryable: true}}
          }
        } = socket
      ) do
    params = socket |> session_params(:interactive, id) |> Map.put("source_turn_id", source)

    socket =
      case call(socket, "interactive.retry_turn", params) do
        {:ok, _turn} -> socket |> assign(:composer_error, nil) |> refresh_info()
        refusal -> assign(socket, :composer_error, refusal_message(refusal))
      end

    {:noreply, socket}
  end

  def handle_event("retry", _params, socket), do: {:noreply, socket}

  def handle_event("toggle-sessions", _params, socket),
    do: {:noreply, update(socket, :sessions_visible?, &(!&1))}

  def handle_event("interrupt", _params, %{assigns: %{open: {:interactive, id}}} = socket) do
    params = session_params(socket, :interactive, id)

    socket =
      case call(socket, "interactive.interrupt", params) do
        {:ok, _stopped} -> assign(socket, :composer_error, nil)
        refusal -> assign(socket, :composer_error, refusal_message(refusal))
      end

    {:noreply, socket}
  end

  def handle_event("interrupt", _params, socket), do: {:noreply, socket}

  # One handler for both pickers, because they are one call with a different key. The
  # field is matched against the two this surface offers rather than passed through: a
  # `phx-value-field` is browser input, and `interactive.configure` is a closed envelope.
  def handle_event("configure", %{"field" => field, "choice" => choice}, socket)
      when field in ["sandbox_mode", "reasoning_effort"] do
    {:noreply, configure(socket, field, choice)}
  end

  def handle_event(
        "session-action",
        %{"action" => action, "plane" => plane, "id" => id},
        socket
      )
      when action in ["rename", "close", "delete"] do
    with {:ok, plane} <- Map.fetch(@planes, plane),
         row when not is_nil(row) <- row(socket.assigns.rows, {plane, id}),
         true <- session_action_allowed?(socket, action, row) do
      {:noreply,
       socket
       |> assign(:session_action, %{action: action, row: row})
       |> assign(:session_action_error, nil)}
    else
      _invalid -> {:noreply, socket}
    end
  end

  def handle_event("session-action-cancel", _params, socket) do
    {:noreply, socket |> assign(:session_action, nil) |> assign(:session_action_error, nil)}
  end

  def handle_event(
        "session-rename",
        %{"title" => title},
        %{assigns: %{session_action: %{action: "rename", row: row}}} = socket
      ) do
    title = String.trim(title)

    if title == "" do
      {:noreply, assign(socket, :session_action_error, "Enter a session name.")}
    else
      params =
        socket
        |> session_params(:interactive, row.id)
        |> Map.put("title", title)

      {:noreply, finish_session_action(socket, "interactive.rename", params)}
    end
  end

  def handle_event(
        "session-delete",
        _params,
        %{assigns: %{session_action: %{action: "delete", row: row}}} = socket
      ) do
    if session_action_allowed?(socket, "delete", row) do
      method = "#{row.plane}.delete"
      params = session_params(socket, row.plane, row.id)
      {:noreply, finish_session_action(socket, method, params, deleted: {row.plane, row.id})}
    else
      {:noreply, assign(socket, :session_action_error, "Only terminal sessions can be deleted.")}
    end
  end

  def handle_event(
        "session-close",
        _params,
        %{assigns: %{session_action: %{action: "close", row: row}}} = socket
      ) do
    if session_action_allowed?(socket, "close", row) do
      params = session_params(socket, :interactive, row.id)
      {:noreply, finish_session_action(socket, "interactive.close", params)}
    else
      {:noreply, assign(socket, :session_action_error, "Only running sessions can be ended.")}
    end
  end

  def handle_event(event, _params, socket)
      when event in ["session-action", "session-rename", "session-close", "session-delete"],
      do: {:noreply, socket}

  def handle_event("configure", _params, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Approvals
  # ------------------------------------------------------------------------------------

  def handle_event(
        "respond",
        %{"request" => id, "decision" => decision, "scope" => scope},
        socket
      )
      when decision in ["approve", "deny"] and scope in ["once", "session"] do
    {:noreply, respond(socket, id, %{"decision" => decision, "scope" => scope})}
  end

  # A vendor option answers as whatever the locked decision table says it means; an
  # `ask_user` option answers with its own words, as the `reason` the tool reads the answer
  # from. An option with neither is never given a button — so reaching here with one is a
  # browser sending something this page did not draw, and nothing is sent for it.
  def handle_event("respond_option", %{"request" => id, "option" => index}, socket) do
    with request when not is_nil(request) <- request(socket, id),
         {index, ""} <- Integer.parse(index),
         response when is_map(response) <- ApprovalCard.option_response(request, index) do
      {:noreply, respond(socket, id, response)}
    else
      _unmapped ->
        {:noreply,
         notice(
           socket,
           :error,
           "this build cannot map that option onto an answer, so it sent nothing"
         )}
    end
  end

  # B2. The explicit choice rides `provider_options`; the `decision`/`scope` beside it are
  # the fallback mapping, so a runtime that reads the choice and one that does not settle
  # the same way. A runtime that refuses the key outright gets the same answer without it.
  def handle_event("plan_choice", %{"request" => id, "choice" => choice}, socket) do
    case Approval.PlanChoice.parse(choice) do
      nil ->
        {:noreply,
         notice(socket, :error, "this build does not know that plan answer, so it sent nothing")}

      parsed ->
        {decision, scope} = Approval.PlanChoice.decision(parsed)
        fallback = %{"decision" => to_string(decision), "scope" => to_string(scope)}

        response =
          Map.put(fallback, "provider_options", %{
            "choice" => Approval.PlanChoice.as_string(parsed)
          })

        {:noreply, respond(socket, id, response, fallback)}
    end
  end

  def handle_event("remember", %{"request" => id}, socket),
    do: {:noreply, remember(socket, id)}

  # Turning it on flushes what is already waiting; turning it off answers nothing and
  # un-answers nothing. Both directions are idempotent because the answered set is.
  #
  # The gate is recomputed here rather than read off an assign, because an assign is a
  # record of what was *drawn* and this event does not have to have come from anything
  # drawn. A browser can send any `phx-click` on any socket: at read scope the toggle is
  # never rendered, and without this a forged click flipped the flag and ran `auto_answer/1`
  # on behalf of a scope that may not answer an approval at all. The `session` param is
  # checked for the same reason — a click carrying some other session's id is not a click
  # on this page's control.
  def handle_event("auto_approve", params, socket) do
    if auto_approve_allowed?(socket, params) do
      socket = update(socket, :auto_approve?, &(not &1))
      {:noreply, auto_answer(socket)}
    else
      {:noreply, socket}
    end
  end

  # A `phx-value-*` this page never drew. Every clause above matches on the values it
  # renders, so anything reaching here is browser input that did not come from a control —
  # and the honest response to a click that did not happen is to do nothing, not to crash
  # the view and make an operator's transcript remount.
  def handle_event(event, _params, socket)
      when event in ["send", "respond", "respond_option", "plan_choice", "remember"],
      do: {:noreply, socket}

  # The same two facts the toggle is drawn from: this endpoint's scope may answer an
  # approval, and this session is the one the page has open.
  defp auto_approve_allowed?(%{assigns: %{open: {plane, _id}}} = socket, params) do
    socket.assigns.scope == :operate and
      Call.available?(:operate, "#{plane}.respond_approval") and
      current_session?(socket, params)
  end

  defp auto_approve_allowed?(_closed, _params), do: false

  defp current_session?(%{assigns: %{open: {plane, id}}}, %{"session" => session}),
    do: session == "#{plane}:#{id}" or session == id

  defp current_session?(_socket, _params), do: true

  # ------------------------------------------------------------------------------------
  # Messages
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_info(:poll, socket) do
    schedule_poll()
    {:noreply, socket |> refresh() |> recover_subscription() |> announce_needs_you()}
  end

  def handle_info({:ouroboros_interactive_event, id, event}, socket) do
    case resync_if_mailbox_lagged(socket) do
      {:lagged, socket} -> {:noreply, socket}
      :ok -> {:noreply, live_event(socket, :interactive, id, event)}
    end
  end

  def handle_info({:ouroboros_interactive_resync, _id, _cursor}, socket),
    do: {:noreply, recover_from_mailbox_lag(socket)}

  def handle_info(:flush, socket) do
    case resync_if_mailbox_lagged(socket) do
      {:lagged, socket} -> {:noreply, socket}
      :ok -> {:noreply, socket |> assign(:flush_scheduled?, false) |> redraw(:delta)}
    end
  end

  # A coordinator can retire because the session ended or disappear because its
  # supervisor is restarting it. Ask the durable session before deciding which happened.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{assigns: %{monitor: ref}} = socket) do
    {:noreply, socket |> assign(:monitor, nil) |> recover_subscription() |> redraw(:reset)}
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket), do: {:noreply, socket}

  def handle_info(_message, socket), do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Lists and status
  # ------------------------------------------------------------------------------------

  defp schedule_poll, do: Process.send_after(self(), :poll, @poll_interval)

  # One refresh at a time. The calls are synchronous in this process, so the guard is
  # belt-and-braces against a future async path rather than a race that exists today —
  # but a second list landing on top of an in-flight one is exactly the bug that would be
  # invisible until a fleet node hung.
  defp refresh(%{assigns: %{polling?: true}} = socket), do: socket

  defp refresh(socket) do
    socket = assign(socket, :polling?, true)
    scope = socket.assigns.scope
    session = socket.assigns[:web_session]

    {rows, error} = sessions(scope, session)

    socket
    |> assign(:polling?, false)
    |> assign(:rows, rows)
    |> assign(:list_error, error)
    |> assign(:status, runtime_status(scope, session))
    |> refresh_info()
    |> assign_page_title()
  end

  defp sessions(scope, session) do
    list(scope, "interactive.list", &Rail.from_interactive/1, session)
  end

  defp list(scope, method, to_row, session) do
    case Call.call(scope, method, %{}, session: session) do
      {:ok, sessions} when is_list(sessions) -> {Enum.map(sessions, to_row), nil}
      {:ok, _other} -> {[], "#{method} answered something this build cannot read"}
      {:error, _code, message} -> {[], message}
      {:error, _code, message, _data} -> {[], message}
    end
  end

  defp runtime_status(scope, session) do
    case Call.call(scope, "runtime.status", %{}, session: session) do
      {:ok, status} when is_map(status) -> status
      _refused -> nil
    end
  end

  # The open session's vitals, which are one call deeper than a row. Refreshed on the list
  # cadence because a context meter that only moved when the page was reloaded would be a
  # number nobody could trust.
  defp refresh_info(%{assigns: %{open: nil}} = socket), do: assign(socket, :info, nil)

  defp refresh_info(%{assigns: %{open: {plane, id}}} = socket) do
    params = session_params(socket, plane, id)

    case Call.call(socket.assigns.scope, "interactive.info", params,
           session: socket.assigns[:web_session]
         ) do
      {:ok, info} when is_map(info) -> assign(socket, :info, info)
      _refused -> socket
    end
  end

  # `node` where the list named an owner, so a cross-node read is routed rather than
  # answered locally and wrongly. Absent where it did not: the runtime's own default is
  # this node, which is the right guess when there is nothing better.
  defp session_params(socket, plane, id) do
    case owner(socket, plane, id) do
      nil -> %{"id" => id}
      owner -> %{"id" => id, "node" => Atom.to_string(owner)}
    end
  end

  defp session_action_allowed?(socket, "rename", row) do
    row.plane == :interactive and socket.assigns.scope == :operate and
      Call.available?(:operate, "interactive.rename")
  end

  defp session_action_allowed?(socket, "close", row) do
    row.plane == :interactive and socket.assigns.scope == :operate and
      not Rail.terminal?(row.status) and Call.available?(:operate, "interactive.close")
  end

  defp session_action_allowed?(socket, "delete", row) do
    socket.assigns.scope == :operate and Rail.terminal?(row.status) and
      Call.available?(:operate, "#{row.plane}.delete")
  end

  defp finish_session_action(socket, method, params, opts \\ []) do
    case call(socket, method, params) do
      {:ok, _answer} ->
        socket =
          if Keyword.get(opts, :deleted) == socket.assigns.open do
            close(socket)
          else
            socket
          end

        socket
        |> assign(:session_action, nil)
        |> assign(:session_action_error, nil)
        |> refresh()

      refused ->
        assign(socket, :session_action_error, refusal_message(refused))
    end
  end

  defp owner(socket, plane, id) do
    Enum.find_value(socket.assigns.rows, fn row ->
      if row.plane == plane and row.id == id, do: row.node
    end)
  end

  # ------------------------------------------------------------------------------------
  # Opening a session: subscribe, check terminality, monitor
  # ------------------------------------------------------------------------------------

  defp open(%{assigns: %{open: {plane, id}}} = socket, plane, id),
    do: assign(socket, :sessions_visible?, false)

  defp open(socket, plane, id) do
    socket
    |> close()
    |> assign(:open, {plane, id})
    |> assign(:sessions_visible?, false)
    |> restore_draft(plane, id)
    |> assign(:watch, Watch.new(retain_history: true))
    |> resubscribe()
    |> refresh_info()
    |> assign_page_title()
  end

  defp close(socket) do
    socket = demonitor(socket)

    # Told rather than left to the monitor: this process may well stay alive and open a
    # different session, and a plane still holding it as a subscriber would keep sending.
    with {plane, id} <- socket.assigns.open,
         ref when not is_nil(ref) <- ref(socket, plane, id) do
      _ = Methods.unsubscribe(plane, ref)
    end

    socket
    |> assign(:open, nil)
    |> assign(:draft_key, nil)
    |> assign(:watch, nil)
    |> assign(:info, nil)
    |> assign(:subscribe_error, nil)
    |> assign(:cells, %{})
    |> assign(:history_start, nil)
    |> assign(:history_anchor, nil)
    |> assign(:cell_targets, %{})
    |> assign(:truncated, 0)
    |> reset_session_state()
    |> stream(:cells, [], reset: true)
  end

  defp assign_page_title(%{assigns: %{open: nil}} = socket),
    do: assign(socket, :page_title, "Sessions")

  defp assign_page_title(%{assigns: %{open: open, rows: rows}} = socket) do
    title =
      case row(rows, open) do
        nil -> "Session"
        session -> Rail.title(session)
      end

    assign(socket, :page_title, title)
  end

  # The one repair.
  #
  # Remount, `:DOWN`, and a pruned cursor all land here, and the only thing that changes
  # between them is the cursor — which the watch already knows, because it is the
  # contiguous high-water mark and not the newest thing held.
  #
  # **Never from the dead render.** A page load renders twice: once over HTTP into a
  # throwaway process, then again in the process that owns the socket. Both planes
  # *register the caller* and monitor it, so subscribing in the first one hands the plane a
  # subscriber that is already dying — a registration to clean up and a coordinator call
  # (possibly an `:erpc` to another machine) bought for a process that will never receive
  # an event. The first paint therefore carries the rail and the session's header but an
  # empty transcript, which fills the moment the socket is up.
  defp resubscribe(%{assigns: %{open: nil}} = socket), do: socket

  defp resubscribe(%{assigns: %{open: {plane, id}, watch: watch}} = socket) do
    if connected?(socket), do: subscribe(socket, plane, id, watch), else: socket
  end

  defp recover_subscription(%{assigns: %{open: nil}} = socket), do: socket

  defp recover_subscription(%{assigns: %{monitor: monitor}} = socket) when is_reference(monitor),
    do: socket

  defp recover_subscription(%{assigns: %{open: {plane, id}}} = socket) do
    ref = ref(socket, plane, id)

    case Methods.session(plane, ref) do
      {:ok, status, true} ->
        update(socket, :watch, &Watch.ended(&1, to_string(status)))

      _live_or_temporarily_unavailable ->
        resubscribe(socket)
    end
  end

  defp subscribe(socket, plane, id, watch) do
    ref = ref(socket, plane, id)
    cursor = Watch.cursor(watch)

    case Methods.subscribe(plane, ref, cursor) do
      {:ok, events} when is_list(events) ->
        socket
        |> assign(:subscribe_error, nil)
        |> assign(:watch, Watch.backlog(watch, cursor, events))
        |> check_terminal(plane, ref)
        |> monitor(plane, ref)
        |> redraw(:reset)

      # The runtime no longer retains history below `floor`. Raise it — which places the
      # divider where the hole is rather than at the top — and go round again through this
      # same function, which is why the prune arm is three lines and not a second
      # implementation.
      {:error, _code, _message, %{"reason" => "cursor_pruned", "floor" => floor}}
      when is_integer(floor) and floor > cursor ->
        socket
        |> assign(:watch, Watch.raise_floor(watch, floor))
        |> resubscribe()

      {:error, _code, message} ->
        assign(socket, :subscribe_error, message)

      {:error, _code, message, _data} ->
        assign(socket, :subscribe_error, message)

      other ->
        Logger.error("web subscribe answered #{inspect(other, limit: 5)}")
        assign(socket, :subscribe_error, "this session could not be read")
    end
  end

  # A terminal session answers the backlog and silently declines the registration. Asked
  # immediately, because without it this view waits forever on a stream that already ended.
  defp check_terminal(socket, plane, ref) do
    case Methods.session(plane, ref) do
      {:ok, status, true} -> update(socket, :watch, &Watch.ended(&1, to_string(status)))
      _live_or_unreadable -> socket
    end
  end

  # A subscription is only as alive as the process it is registered with. Its `:DOWN` is
  # the end of the stream, and monitoring is how this view learns that rather than
  # discovering it by never hearing anything again.
  defp monitor(socket, plane, ref) do
    case Methods.coordinator(plane, ref) do
      pid when is_pid(pid) -> assign(socket, :monitor, Process.monitor(pid))
      # No coordinator: either it already retired (a terminal session, which
      # `check_terminal/3` has just recorded) or it cannot be reached from here.
      _absent -> socket
    end
  end

  defp demonitor(%{assigns: %{monitor: ref}} = socket) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    assign(socket, :monitor, nil)
  end

  defp demonitor(socket), do: socket

  defp ref(socket, plane, id) do
    owner = owner(socket, plane, id) || node()

    case plane do
      :interactive -> Ouroboros.Interactive.Ref.new(id, owner)
    end
  end

  # ------------------------------------------------------------------------------------
  # Live events
  # ------------------------------------------------------------------------------------

  # In-process the plane sends unconditionally. A mailbox at `Watch.window/0` triggers
  # a batched repair, so the discarded queue is a hole — the same
  # hole a `stream.lagged` frame names on the wire. Drop what is queued and resubscribe
  # from the cursor rather than dying: that is the `:DOWN` repair, and it keeps the page.
  defp resync_if_mailbox_lagged(socket) do
    case Process.info(self(), :message_queue_len) do
      {:message_queue_len, len} ->
        if Watch.mailbox_lagged?(len), do: {:lagged, recover_from_mailbox_lag(socket)}, else: :ok

      _gone ->
        :ok
    end
  end

  defp recover_from_mailbox_lag(%{assigns: %{watch: nil}} = socket) do
    drop_queued_plane_events()
    assign(socket, :flush_scheduled?, false)
  end

  defp recover_from_mailbox_lag(socket) do
    drop_queued_plane_events()

    socket
    |> assign(:flush_scheduled?, false)
    |> demonitor()
    |> update(:watch, &Watch.note(&1, :client_dropped))
    |> resubscribe()
  end

  defp drop_queued_plane_events do
    receive do
      {:ouroboros_interactive_event, _id, _event} -> drop_queued_plane_events()
    after
      0 -> :ok
    end
  end

  # Absorbed now, drawn later. A streaming turn is one message per delta, and the whole
  # cost of this surface under load is whether that message re-projects the ledger.
  defp live_event(%{assigns: %{open: {plane, id}}} = socket, plane, id, event) do
    socket
    |> update(:watch, &Watch.absorb(&1, event))
    |> schedule_flush()
    # ui-parity W3 fix wave (L5). One `interactive.context` per completed turn, and only
    # where this page has already read one: a meter pinned to the reading taken twenty
    # turns ago is a measurement presented as current.
    |> refresh_reading(event)
  end

  # An event for a session this view is no longer reading. It arrives because unsubscribe
  # and a message already in flight race, which is not a fault.
  defp live_event(socket, _plane, _id, _event), do: socket

  defp schedule_flush(%{assigns: %{flush_scheduled?: true}} = socket), do: socket

  defp schedule_flush(socket) do
    Process.send_after(self(), :flush, @coalesce)
    assign(socket, :flush_scheduled?, true)
  end

  # ------------------------------------------------------------------------------------
  # Operator verbs
  #
  # Every one of them goes through `Ouroboros.Web.Call` and none of them touches a plane.
  # They are written here rather than in the components because a component that could
  # call the runtime would be a second authorization surface.
  # ------------------------------------------------------------------------------------

  defp reset_session_state(socket) do
    socket
    # ui-parity W2: the catalogue, the search typed into it and an armed per-turn effort
    # all belong to the conversation they were read or chosen in. Carrying them into the
    # next one would be this page applying a decision to a session nobody made it for.
    |> assign(:composer_extras, @composer_extras)
    |> assign(:draft, "")
    |> assign(:composer_error, nil)
    |> assign(:approval_notice, nil)
    |> assign(:approvals, [])
    |> assign(:pinned_detail, nil)
    |> assign(:answered, MapSet.new())
    |> assign(:last_send, nil)
    |> assign(:turn, @quiet_turn)
    # Automation does not follow a reader from one conversation into another. The toggle
    # is this view's, and a view showing a different session is answering different
    # questions than the one it was switched on for.
    |> assign(:auto_approve?, false)
  end

  defp call(socket, method, params) do
    Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session])
  end

  # The runtime's own words, never this surface's paraphrase of them.
  defp refusal_message({:error, _code, message}) when is_binary(message), do: message
  defp refusal_message({:error, _code, message, _data}) when is_binary(message), do: message

  defp notice(socket, tone, text),
    do: assign(socket, :approval_notice, %{tone: tone, text: text})

  # ---------------------------------------------------------------------------- Sending

  # ui-parity W3 (W3.8, W3.10). Two questions in front of the dispatch that was here:
  #
  #   * **a draft beginning with `!` is never a turn.** It is the operator's own command
  #     and it goes to `workspace.exec`, which is what the composer has already said it
  #     will do (`docs/TUI.md:2247-2252`). Asked first, so no gate below can turn one into
  #     a message by accident.
  #   * **a send is re-checked against the four facts the composer is drawn from.** The
  #     form exists only where all of them hold, so a `send` arriving without them did not
  #     come from a control — and until this, an undrawn event reached the runtime to be
  #     refused there. W2's steer clause already re-asked its button's condition; this is
  #     the same rule on the verb beside it.
  defp send_turn(socket, text) when is_binary(text) do
    cond do
      String.starts_with?(text, "!") and Map.get(socket.assigns, :image_refs, []) != [] ->
        assign(socket, :composer_error, "Remove the images before running a shell command.")

      String.starts_with?(text, "!") ->
        operator_shell(socket, String.slice(text, 1..-1//1))

      # A plane with no composer keeps the sentence it always had, below.
      not match?({:interactive, _id}, socket.assigns.open) ->
        dispatch_turn(socket, text)

      sendable?(socket.assigns) ->
        dispatch_turn(socket, text)

      true ->
        socket
    end
  end

  defp dispatch_turn(%{assigns: %{open: {:interactive, _id}, image_refs: []}} = socket, "") do
    assign(socket, :composer_error, "Write a message before sending.")
  end

  defp dispatch_turn(%{assigns: %{open: {:interactive, id}}} = socket, text) do
    {turn_id, input} = submission_for(socket, text)

    params =
      socket
      |> session_params(:interactive, id)
      # ui-parity W2: `turn_input/2` is the bare prompt unless a per-turn effort is armed.
      |> Map.merge(%{"input" => input, "turn_id" => turn_id})

    socket =
      socket
      |> assign(:last_send, {text, turn_id})
      |> assign(:last_send_input, input)

    method = Composer.verb(socket.assigns.turn, session_status(socket))

    case call(socket, method, params) do
      {:ok, _turn} ->
        sent(socket)

      # The runtime knows better than this view did, and says which verb to use. The same
      # params go back under it: the refusal carries `outcome: not_dispatched`, so nothing
      # was created and the caller-owned turn id is still free.
      {:error, _code, message, %{"retry_with" => retry}} when is_binary(retry) ->
        if retry in socket.assigns.methods do
          case call(socket, retry, params) do
            {:ok, _turn} -> sent(socket)
            refusal -> refused(socket, text, refusal_message(refusal))
          end
        else
          refused(socket, text, message)
        end

      refusal ->
        refused(socket, text, refusal_message(refusal))
    end
  end

  defp dispatch_turn(socket, _text) do
    assign(
      socket,
      :composer_error,
      "This task runs to completion and does not accept messages. Use the terminal client to control it."
    )
  end

  defp sent(socket) do
    {text, _id} = socket.assigns.last_send

    socket
    |> put_draft("", false)
    # ui-parity W2: a per-turn effort rode this send and is spent.
    |> clear_next_effort()
    |> assign(:composer_error, nil)
    |> push_event("draft-sent", %{
      key: socket.assigns.draft_key,
      text: text,
      images: Map.get(socket.assigns, :image_refs, [])
    })
    |> assign(:image_refs, [])
  end

  defp current_composer?(socket, params),
    do: Map.get(params, "session_key", socket.assigns.draft_key) == socket.assigns.draft_key

  defp put_draft(socket, text, forget_send \\ true) do
    socket =
      socket
      |> assign(:draft, text)
      |> update(:drafts, &Map.put(&1, socket.assigns.draft_key, text))

    if forget_send, do: assign(socket, :last_send, nil), else: socket
  end

  defp restore_draft(socket, plane, id) do
    # A digest isolates drafts by authenticated browser session, owner and conversation;
    # the cookie's credential itself never reaches storage or the DOM.
    key =
      :crypto.hash(
        :sha256,
        :erlang.term_to_binary(
          {socket.assigns[:web_session], owner(socket, plane, id), plane, id}
        )
      )
      |> Base.url_encode64(padding: false)

    socket |> assign(:draft_key, key) |> assign(:draft, Map.get(socket.assigns.drafts, key, ""))
  end

  # The draft is handed back exactly as it was typed. A composer that cleared itself on a
  # refusal would lose the one thing the operator could not get back.
  defp refused(socket, text, message),
    do: socket |> put_draft(text, false) |> assign(:composer_error, message)

  # Repeated submits without a draft or effort edit reuse the entire accepted envelope.
  # A successful send spends the effort override, but a duplicate must still carry it:
  # the runtime deduplicates by both input and turn_id. Images come from each form submit,
  # so changing those also starts a new turn even if no text change event has arrived.
  defp submission_for(%{assigns: %{last_send: {text, turn_id}}} = socket, text) do
    input = Map.get(socket.assigns, :last_send_input, text)
    previous_refs = if is_map(input), do: Map.get(input, "image_attachments", []), else: []

    if previous_refs == Map.get(socket.assigns, :image_refs, []),
      do: {turn_id, input},
      else: {new_turn_id(), turn_input(socket, text)}
  end

  defp submission_for(socket, text), do: {new_turn_id(), turn_input(socket, text)}

  defp new_turn_id do
    "web-" <>
      (:crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower))
  end

  # ------------------------------------------------------------------------ Configuring

  defp configure(%{assigns: %{open: {:interactive, id}}} = socket, field, choice) do
    # ui-parity W3.10. The same question the picker is drawn from, asked again: a
    # `phx-value-field` is browser input, and a transport that declared
    # `dynamic_configuration: false` draws no picker to have clicked.
    if allowed_choice?(socket.assigns, field, choice) and reconfigurable?(socket.assigns) do
      params = socket |> session_params(:interactive, id) |> Map.put(field, choice)

      case call(socket, "interactive.configure", params) do
        {:ok, _configured} ->
          # Nothing is assigned optimistically. The picker's mark is drawn from what the
          # next read reports, so a transport that quietly declined the change cannot
          # leave this page claiming it happened.
          socket |> assign(:composer_error, nil) |> refresh_info()

        refusal ->
          assign(socket, :composer_error, refusal_message(refusal))
      end
    else
      socket
    end
  end

  defp configure(socket, _field, _choice), do: socket

  defp allowed_choice?(_assigns, "sandbox_mode", choice), do: choice in Composer.sandbox_modes()

  defp allowed_choice?(assigns, "reasoning_effort", choice),
    do: choice in reasoning_efforts(assigns)

  defp allowed_choice?(_assigns, _field, _choice), do: false

  # -------------------------------------------------------------------------- Approving

  defp respond(socket, request_id, response, fallback \\ nil)

  # Only a request this view is actually holding. `phx-value-request` is browser input, and
  # an id nobody drew is an answer to a question nobody was shown.
  defp respond(%{assigns: %{open: {plane, id}}} = socket, request_id, response, fallback) do
    if request(socket, request_id) do
      send_response(socket, plane, id, request_id, response, fallback)
    else
      socket
    end
  end

  defp respond(socket, _request_id, _response, _fallback), do: socket

  defp send_response(socket, plane, id, request_id, response, fallback) do
    method = "#{plane}.respond_approval"

    params =
      socket
      |> session_params(plane, id)
      |> Map.merge(%{"request_id" => request_id, "response" => response})

    # Recorded before the call, not after: what this set is for is stopping automation
    # answering the same request twice, and a refusal is not proof the first answer did
    # not land.
    socket = update(socket, :answered, &MapSet.put(&1, request_id))

    case call(socket, method, params) do
      {:ok, _answered} ->
        assign(socket, :approval_notice, nil)

      refusal ->
        # Any refusal, not only `-32602`. A runtime with no `provider_options` in its
        # gateway envelope refuses with one code; one whose plane's response schema
        # predates the key refuses inside `InteractiveSession` with another. Neither
        # answered the request — `respond_approval` is not an outcome-unknown verb — so
        # one retry of the strictly weaker answer is safe, and a refusal that was about
        # something else refuses the retry too and *that* is what gets rendered.
        if is_map(fallback) do
          plan_fallback(socket, method, params, fallback)
        else
          notice(socket, :error, refusal_message(refusal))
        end
    end
  end

  # B2. A runtime that will not take `provider_options` still takes the four-way answer
  # the choice degrades to, and it settles the session the same way. Said once rather than
  # dropped silently, because what is lost with the key is the follow-up prompt.
  defp plan_fallback(socket, method, params, fallback) do
    case call(socket, method, Map.put(params, "response", fallback)) do
      {:ok, _answered} ->
        notice(
          socket,
          :warning,
          "this runtime does not take a plan choice, so the answer went as its four-way equivalent"
        )

      refusal ->
        notice(socket, :error, refusal_message(refusal))
    end
  end

  defp request(socket, request_id),
    do: Enum.find(socket.assigns.approvals, &(&1.request_id == request_id))

  defp detail_of(nil), do: nil
  defp detail_of(%Approval{} = request), do: Approval.detail(request)

  # Every pending request that is not a question or a plan exit.
  # `Transcript.question?/1` is the whole carve-out and it is the locked module's, so the
  # rail's inline answers and this cannot disagree about what a permission is.
  defp auto_answer(%{assigns: %{auto_approve?: true, open: {_plane, _id}}} = socket) do
    if connected?(socket) do
      Enum.reduce(socket.assigns.approvals, socket, fn request, socket ->
        cond do
          Transcript.question?(request) ->
            socket

          MapSet.member?(socket.assigns.answered, request.request_id) ->
            socket

          true ->
            respond(socket, request.request_id, %{
              "decision" => "approve",
              "scope" => "once",
              "actor" => "automation"
            })
        end
      end)
    else
      socket
    end
  end

  defp auto_answer(socket), do: socket

  # ------------------------------------------------------------------- Needs-you alerts

  # The server half of the topbar bell, and it is deliberately the smaller half.
  #
  # Three rules decide whether a notification is posted, and only one of them is knowable
  # here: **which sessions have just started needing somebody**. Whether anybody is looking
  # at the tab (Page Visibility), whether the bell is even on, and whether the browser
  # granted permission are all facts about a browser, and they live in `app.js`. So this
  # pushes the *edge* and says nothing about what should be done with it.
  #
  # The edge is computed against the same triage the rail draws — `Rail.triaged/2` with this
  # view's held approvals — rather than against a second notion of "needs you" kept beside
  # it. A page that notified about a group it was not drawing would be worse than one that
  # did not notify at all.
  #
  # A key that leaves the group is forgotten, so a session that needs a person again later
  # rings again. A key that is still pending is never re-pushed. `app.js` keeps its own
  # permanent set on top of this, because a LiveView remount re-seeds these assigns and a
  # repair is not a new request.
  defp seed_needs_you(socket),
    do: assign(socket, :announced, socket |> needs_you() |> NeedsYou.keys())

  defp announce_needs_you(socket) do
    current = needs_you(socket)
    fresh = NeedsYou.fresh(current, socket.assigns.announced)

    socket = assign(socket, :announced, NeedsYou.keys(current))

    if connected?(socket) and fresh != [],
      do: push_event(socket, "needs-you", %{sessions: fresh}),
      else: socket
  end

  # One entry per session in the needs-you group, keyed by the thing that identifies the
  # *ask* wherever one is actually known.
  #
  # For the open session this view holds the requests, so the key is the `request_id` — the
  # id the whole approval path is idempotent on, and the one W8 asks the bell not to repeat.
  # For every other row the rail's evidence is the session's own `awaiting_approval` status
  # and there is no request id on this side of the wire at all: `interactive.list` does not
  # carry one. Those are keyed `<plane>:<id>`, which is the finest grain that exists here.
  # Stated rather than papered over — a second ask on an unopened session is one
  # notification, not two, and closing that would take a list verb that answered request
  # ids.
  defp needs_you(%{assigns: assigns}) do
    # `:answered` is written *before* the call goes out (`send_response/6`), which is why
    # a request auto-approve handled is already excluded here even though it stays in
    # `:approvals` until the plane's resolution event arrives.
    NeedsYou.sessions(assigns.rows,
      pending: pending(assigns),
      approvals: Map.get(assigns, :approvals, []),
      answered: Map.get(assigns, :answered, MapSet.new()),
      open: Map.get(assigns, :open)
    )
  end

  # ------------------------------------------------------------------------ Remembering

  defp remember(socket, request_id) do
    with request when not is_nil(request) <- request(socket, request_id),
         detail = Approval.detail(request),
         {%Approval.Rule{} = rule, nil} <-
           Transcript.suggested_rule(
             detail.suggested_rule,
             socket.assigns.methods,
             session_workspace(socket)
           ) do
      add_rule(socket, rule)
    else
      {nil, reason} when is_binary(reason) -> notice(socket, :error, reason)
      _no_rule -> socket
    end
  end

  # A `Capability(…)` remember is user-scoped by design (W13): a capability is deployed to
  # a node by the rollout plane, and a session that has not chosen a project folder could
  # otherwise never remember an answer about one. Every other pattern is scoped to the
  # workspace the gate already proved this session names.
  defp add_rule(%{assigns: %{open: {plane, id}}} = socket, %Approval.Rule{} = rule) do
    params =
      if String.starts_with?(rule.pattern, "Capability(") do
        %{"scope" => "user", "pattern" => rule.pattern, "decision" => "allow"}
      else
        %{
          "scope" => "workspace",
          "pattern" => rule.pattern,
          "decision" => "allow",
          "workspace" => rule.workspace
        }
      end

    params =
      case owner(socket, plane, id) do
        nil -> params
        owner -> Map.put(params, "node", Atom.to_string(owner))
      end

    case call(socket, "permissions.add", params) do
      {:ok, _rule} -> notice(socket, :success, "saved: #{rule.pattern}")
      refusal -> notice(socket, :error, refusal_message(refusal))
    end
  end

  defp add_rule(socket, _rule), do: socket

  # ----------------------------------------------------------------- What the row knows

  defp session_status(%{assigns: %{open: open}} = socket) when not is_nil(open) do
    from_info = socket.assigns.info && Map.get(socket.assigns.info, :status)

    from_row =
      case row(socket.assigns.rows, open) do
        %Rail.Row{status: status} -> status
        _unknown -> nil
      end

    from_info || from_row
  end

  defp session_status(_socket), do: nil

  defp session_workspace(%{assigns: %{open: open}} = socket) when not is_nil(open) do
    from_info = socket.assigns.info && Map.get(socket.assigns.info, :workspace)

    from_row =
      case row(socket.assigns.rows, open) do
        %Rail.Row{workspace: workspace} -> workspace
        _unknown -> nil
      end

    from_info || from_row
  end

  defp session_workspace(_socket), do: nil

  # The posture the session reported, and `nil` where nothing did — which is what makes
  # the sandbox picker absent rather than defaulted. Takes assigns rather than the socket
  # because the render is the only caller and it has no socket.
  defp reported(assigns, key) do
    options = (assigns.info && Map.get(assigns.info, :options)) || %{}

    case Map.get(options, key) do
      nil -> nil
      value -> to_string(value)
    end
  end

  defp reasoning_efforts(assigns) do
    open_row = row(assigns.rows, assigns.open)
    model = reported(assigns, :model) || (open_row && open_row.model)

    Ouroboros.Models.reasoning_efforts(model)
  end

  # ------------------------------------------------------------------------------------
  # Projection into the stream
  # ------------------------------------------------------------------------------------

  defp redraw(%{assigns: %{watch: nil}} = socket, _mode), do: socket

  defp redraw(socket, mode) do
    entries = Watch.entries(socket.assigns.watch)
    projected = Transcript.project_with_ids(entries)
    total = length(projected)

    positions =
      projected |> Enum.with_index() |> Map.new(fn {item, index} -> {item.id, index} end)

    # Reconcile the loaded boundary by identity. Replay can insert cells before it or
    # remove a gap without changing which message the reader has already loaded.
    start = history_start(socket.assigns, positions, total)
    start = if mode == :older, do: max(start - Transcript.chat_page_size(), 0), else: start

    cells =
      projected
      |> Enum.drop(start)
      |> Enum.with_index(start)
      |> Map.new(fn {item, index} -> {item.id, Map.put(item, :index, index)} end)

    # Approvals come off the whole held ledger, not off the drawn window: a request that
    # scrolled past the redraw budget is still a request nobody has answered.
    approvals = Watch.pending_approvals(socket.assigns.watch)

    socket =
      socket
      |> assign(:history_start, start)
      |> assign(:history_anchor, projected |> Enum.at(start) |> then(&(&1 && &1.id)))
      |> assign(:cell_targets, Map.new(positions, fn {id, index} -> {index, id} end))
      |> assign(:truncated, start)
      |> assign(:approvals, approvals)
      # Read once here rather than twice per render. `Approval.detail/1` parses the
      # request's patch, and a poll every three seconds plus a flush every eighty
      # milliseconds is not the cadence to re-parse a diff on.
      |> assign(:pinned_detail, detail_of(List.first(approvals)))
      |> assign(:turn, Composer.turn_state(entries))

    socket =
      case mode do
        :reset -> reset_stream(socket, cells)
        _delta_or_older -> patch_stream(socket, cells)
      end

    # Every path that changes what is pending ends here, so automation has exactly one
    # place to look and the backlog flush on enable is the same code as the live one.
    # The bell runs *after* it, deliberately: a request auto-approve answered on the
    # operator's behalf never needed them, so it must never ring.
    socket |> auto_answer() |> announce_needs_you()
  end

  defp history_start(%{history_start: nil}, _positions, total),
    do: max(total - Transcript.chat_page_size(), 0)

  defp history_start(%{history_start: 0}, _positions, _total), do: 0

  defp history_start(assigns, positions, total) do
    Map.get(positions, assigns.history_anchor) ||
      Enum.find_value(items(assigns.cells), &Map.get(positions, &1.id)) ||
      min(assigns.history_start, total)
  end

  # A reconnect or fold rebuilds the stream, retaining every surviving cell's identity.
  defp reset_stream(socket, cells) do
    socket
    |> stream(:cells, items(cells), reset: true)
    |> assign(:cells, cells)
  end

  # The ordinary case: a few deltas landed and one cell at the end changed. Only what
  # differs is sent, which is the whole reason this pane uses a stream.
  defp patch_stream(socket, cells) do
    previous = socket.assigns.cells

    # Remove obsolete gaps before inserting into the new positions.
    socket =
      Enum.reduce(Map.keys(previous) -- Map.keys(cells), socket, fn id, socket ->
        stream_delete_by_dom_id(socket, :cells, "cells-#{id}")
      end)

    socket =
      items(cells)
      |> Enum.with_index()
      |> Enum.reduce(socket, fn {item, position}, socket ->
        if Map.get(previous, item.id) == item do
          socket
        else
          stream_insert(socket, :cells, item, at: position)
        end
      end)

    assign(socket, :cells, cells)
  end

  defp items(cells), do: cells |> Map.values() |> Enum.sort_by(& &1.index)

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    open_row = row(assigns.rows, assigns.open)
    {rule, rule_refusal} = rule_offer(assigns)
    triaged = Rail.triaged(assigns.rows, pending(assigns))

    assigns =
      assigns
      |> assign(:triaged, filter_sessions(triaged, assigns.session_query))
      |> assign(:machines, machines(assigns.status))
      |> assign(:roster, fleet_roster(assigns.status))
      |> assign(:today, today(assigns.rows))
      |> assign(:activity, activity(assigns))
      |> assign(:open_row, open_row)
      |> assign(:rule, rule)
      |> assign(:rule_refusal, rule_refusal)
      |> assign(
        :row_status,
        (assigns.info && Map.get(assigns.info, :status)) || row_status(open_row)
      )
      |> assign(
        :sandbox,
        reported(assigns, :sandbox_mode) ||
          (open_row && open_row.sandbox_mode &&
             to_string(open_row.sandbox_mode))
      )
      |> assign(:effort, reported(assigns, :reasoning_effort))
      |> assign(:reasoning_efforts, reasoning_efforts(assigns))
      |> assign(:ended?, ended?(assigns, open_row))
      # ui-parity W3
      |> assign(:w3_panels, w3_panels_assigns(assigns))
      |> assign(:reading, w3(assigns).reading)
      |> assign(:shell_refusal, w3(assigns).shell)

    ~H"""
    <div class={[
      "ouro-deck",
      @open && "ouro-session-open",
      @sessions_visible? && "ouro-sessions-visible"
    ]}>
      <Layouts.topbar current={:sessions} machines={@machines} today={@today} />

      <%!-- ui-parity W2 --%>
      <Palette.overlays palette={@palette} sheet={@shortcuts?} />

      <%!-- ui-parity W3 --%>
      <.w3_panels {@w3_panels} />

      <button
        :if={@open}
        type="button"
        class="ouro-session-nav ouro-quiet-button"
        phx-click="toggle-sessions"
        aria-expanded={to_string(@sessions_visible?)}
        aria-controls="session-rail"
      >
        {if @sessions_visible?, do: "← Back to conversation", else: "← Sessions"}
      </button>

      <div class="ouro-columns">
        <.rail
          triaged={@triaged}
          open={@open}
          error={@list_error}
          activity={@activity}
          approvals={@approvals}
          answerable={@scope == :operate}
          scope={@scope}
          query={@session_query}
          roster={@roster}
        />

        <main class="ouro-focus">
          <.focused
            :if={@open}
            open={@open}
            row={@open_row}
            info={@info}
            error={@subscribe_error}
            truncated={@truncated}
            targets={@cell_targets}
            expanded={@expanded}
            streams={@streams}
            approvals={@approvals}
            detail={@pinned_detail}
            notice={@approval_notice}
            rule={@rule}
            rule_refusal={@rule_refusal}
            auto_approve={@auto_approve?}
            draft={@draft}
            draft_key={@draft_key}
            composer_error={@composer_error}
            turn={@turn}
            status={@row_status}
            sandbox={@sandbox}
            effort={@effort}
            efforts={@reasoning_efforts}
            scope={@scope}
            ended={@ended?}
            extras={@composer_extras}
            roster={@roster}
            reading={@reading}
            shell={@shell_refusal}
          />
          <.nothing_open
            :if={is_nil(@open)}
            counts={Rail.counts(@triaged)}
            query={@session_query}
          />
        </main>

        <%!-- The third column the moduledoc and seven `.ouro-columns > .ouro-vitals` rules
              have always described (review §3.2). It is a child of `.ouro-columns` so those
              rules apply; below 1100px the same stylesheet hides it and shows the
              disclosure `focused/1` draws under the composer instead. --%>
        <.vitals
          :if={@open}
          info={@info}
          row={@open_row}
          session_id={@open |> elem(1)}
          roster={@roster}
          reading={@reading}
        />
      </div>

      <.session_action_dialog action={@session_action} error={@session_action_error} />
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # The rail
  # ------------------------------------------------------------------------------------

  attr :triaged, :list, required: true
  attr :open, :any, required: true
  attr :error, :any, required: true
  attr :activity, :map, required: true
  attr :approvals, :list, default: []
  attr :answerable, :boolean, default: false
  attr :scope, :atom, default: :read
  attr :query, :string, default: ""
  attr :roster, :list, default: []

  def rail(assigns) do
    counts = Rail.counts(assigns.triaged)

    assigns =
      assigns
      |> assign(:counts, counts)
      # Three headings over three "nothing here" lines is three times the furniture for one
      # fact (review §3.1). Where any group has rows the per-group line still earns its
      # place — it says which of the three is empty, which is information.
      |> assign(:empty?, Enum.all?(Map.values(counts), &(&1 == 0)))

    ~H"""
    <nav id="session-rail" class="ouro-rail" aria-label="sessions">
      <div class="ouro-rail-head">
        <div>
          <span class="ouro-rail-kicker">Workspace</span>
          <h2>Sessions</h2>
        </div>
        <span class="ouro-rail-total ouro-mono">{length(@triaged)}</span>
      </div>

      <form id="session-search" class="ouro-rail-search-form" phx-change="filter-sessions">
        <label class="ouro-rail-search">
          <input
            type="search"
            name="query"
            value={@query}
            placeholder="Search sessions"
            aria-label="Search sessions"
            autocomplete="off"
            phx-debounce="150"
          />
          <kbd>/</kbd>
        </label>
      </form>

      <p :if={@error} class="ouro-refusal">{@error}</p>

      <p :if={@empty?} class="ouro-group-empty ouro-rail-empty">
        {if @query in [nil, ""], do: "No sessions yet", else: "No sessions match"}
      </p>

      <section
        :for={group <- Rail.groups()}
        :if={not @empty?}
        class={"ouro-group ouro-group-#{group}"}
      >
        <%!-- An `h3`, under the rail's own `h2`: these are subsections of "Sessions", and
              one heading style per rank (W1.8) is only true if the ranks are right. --%>
        <h3 class="ouro-group-head">
          {Rail.label(group)}
          <span :if={group == :needs_you and @counts[group] > 0} class="ouro-count">
            {@counts[group]}
          </span>
        </h3>

        <p :if={@counts[group] == 0} class="ouro-group-empty">
          {if @query == "", do: "nothing here", else: "no matches"}
        </p>

        <.rail_row
          :for={entry <- Enum.filter(@triaged, &(&1.group == group))}
          entry={entry}
          open={@open}
          activity={@activity}
          approvals={@approvals}
          answerable={@answerable}
          scope={@scope}
          roster={@roster}
        />
      </section>
    </nav>
    """
  end

  defp filter_sessions(triaged, query) when query in [nil, ""], do: triaged

  defp filter_sessions(triaged, query) when is_binary(query) do
    needle = query |> String.trim() |> String.downcase()

    if needle == "" do
      triaged
    else
      Enum.filter(triaged, fn %{row: row} ->
        [
          Rail.title(row),
          row.id,
          row.workspace,
          row.provider,
          row.model,
          row.status,
          row.plane,
          row.node
        ]
        |> Enum.reject(&is_nil/1)
        |> Enum.map_join(" ", &to_string/1)
        |> String.downcase()
        |> String.contains?(needle)
      end)
    end
  end

  attr :entry, :map, required: true
  attr :open, :any, required: true
  attr :activity, :map, required: true
  attr :approvals, :list, default: []
  attr :answerable, :boolean, default: false
  attr :scope, :atom, default: :read
  attr :roster, :list, default: []

  def rail_row(assigns) do
    row = assigns.entry.row
    selected? = assigns.open == {row.plane, row.id}

    assigns =
      assigns
      |> assign(:row, row)
      |> assign(:selected?, selected?)
      |> assign(:href, Route.session(row.plane, row.id))
      |> assign(
        :line,
        line(
          assigns.entry.group,
          row,
          Map.get(assigns.activity, {row.plane, row.id}),
          assigns.roster
        )
      )
      |> assign(:age_in_line?, age_in_line?(assigns.entry.group, row))
      |> assign(:answers, inline_answers(assigns, selected?))
      |> assign(
        :can_rename,
        row.plane == :interactive and Call.available?(assigns.scope, "interactive.rename")
      )
      |> assign(
        :can_close,
        row.plane == :interactive and not Rail.terminal?(row.status) and
          Call.available?(assigns.scope, "interactive.close")
      )
      |> assign(
        :can_delete,
        Rail.terminal?(row.status) and Call.available?(assigns.scope, "#{row.plane}.delete")
      )

    ~H"""
    <div id={"session-row-#{@row.plane}-#{@row.id}"} class="ouro-row-wrap">
      <%!-- `true` rather than `page`: the page being read is named once, by the top bar's
            Sessions link. This row is the current item *within* the rail, which is what
            `aria-current="true"` says; two elements claiming to be the current page tells
            a screen-reader user there are two. --%>
      <.link
        patch={@href}
        aria-current={@selected? && "true"}
        class={[
          "ouro-row",
          "ouro-row-#{@entry.group}",
          @selected? && "ouro-row-open",
          (@entry.group == :settled and Rail.failed?(@row)) && "ouro-row-failed"
        ]}
      >
        <.glyph group={@entry.group} failed={Rail.failed?(@row)} />
        <span class="ouro-row-body">
          <span class="ouro-row-title">{Rail.title(@row)}</span>
          <span class="ouro-row-line">{@line}</span>
        </span>
        <span :if={not @age_in_line?} class="ouro-row-age ouro-mono">{age(@row.updated_at)}</span>
      </.link>
      <details
        :if={@can_rename or @can_close or @can_delete}
        id={"session-actions-#{@row.plane}-#{@row.id}"}
        class="ouro-row-actions"
        data-ouro-disclosure={"actions:#{@row.plane}:#{@row.id}"}
      >
        <summary aria-label={"Actions for #{Rail.title(@row)}"}>⋯</summary>
        <div class="ouro-row-action-menu">
          <button
            :if={@can_rename}
            type="button"
            class="ouro-row-action"
            phx-click="session-action"
            phx-value-action="rename"
            phx-value-plane={@row.plane}
            phx-value-id={@row.id}
            aria-label={"Rename #{Rail.title(@row)}"}
          >
            Rename
          </button>
          <button
            :if={@can_close}
            type="button"
            class="ouro-row-action ouro-row-action-danger"
            phx-click="session-action"
            phx-value-action="close"
            phx-value-plane={@row.plane}
            phx-value-id={@row.id}
            aria-label={"End #{Rail.title(@row)}"}
          >
            End
          </button>
          <button
            :if={@can_delete}
            type="button"
            class="ouro-row-action ouro-row-action-danger"
            phx-click="session-action"
            phx-value-action="delete"
            phx-value-plane={@row.plane}
            phx-value-id={@row.id}
            aria-label={"Delete #{Rail.title(@row)}"}
          >
            Delete
          </button>
        </div>
      </details>
    </div>
    <ApprovalCard.inline :for={request <- @answers} request={request} />
    """
  end

  # Two buttons on a row, for a plain permission and nothing else. A question and a plan
  # exit carry a decision a one-line row never showed, so those rows stay
  # a link into the session — `Approval.question?/1` draws that line, once, for both
  # surfaces. Outside the link element on purpose: a button inside an anchor is markup no
  # browser agrees about.
  defp inline_answers(%{answerable: true, approvals: approvals}, true) when is_list(approvals),
    do: Enum.filter(approvals, &ApprovalCard.inline?/1)

  defp inline_answers(_assigns, _selected?), do: []

  attr :action, :any, required: true
  attr :error, :any, required: true

  def session_action_dialog(assigns) do
    ~H"""
    <dialog
      :if={@action}
      id="session-action-dialog"
      class="ouro-session-dialog"
      aria-modal="true"
      aria-labelledby="session-action-title"
      phx-hook="Modal"
    >
      <form
        :if={@action.action == "rename"}
        phx-submit="session-rename"
        class="ouro-session-dialog-form"
      >
        <h2 id="session-action-title">Rename session</h2>
        <label for="session-title">Session name</label>
        <input
          id="session-title"
          name="title"
          class="ouro-new-input"
          value={Rail.title(@action.row)}
          required
          autofocus
        />
        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>
        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="session-action-cancel">
            Cancel
          </button>
          <button type="submit" class="ouro-button" phx-disable-with="Renaming…">Rename</button>
        </div>
      </form>
      <form
        :if={@action.action == "close"}
        phx-submit="session-close"
        class="ouro-session-dialog-form"
      >
        <h2 id="session-action-title">End session</h2>
        <p>
          End <strong>{Rail.title(@action.row)}</strong>? Its transcript remains available,
          but it cannot receive more messages.
        </p>
        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>
        <div class="ouro-session-dialog-actions">
          <button
            type="button"
            class="ouro-button-quiet"
            phx-click="session-action-cancel"
            autofocus
          >
            Keep session
          </button>
          <button type="submit" class="ouro-button ouro-button-danger" phx-disable-with="Ending…">
            End session
          </button>
        </div>
      </form>

      <form
        :if={@action.action == "delete"}
        phx-submit="session-delete"
        class="ouro-session-dialog-form"
      >
        <h2 id="session-action-title">Delete session</h2>
        <p>
          Permanently delete <strong>{Rail.title(@action.row)}</strong>? This cannot be undone.
        </p>
        <p :if={@error} class="ouro-refusal" role="alert">{@error}</p>
        <div class="ouro-session-dialog-actions">
          <button type="button" class="ouro-button-quiet" phx-click="session-action-cancel">
            Cancel
          </button>
          <button
            type="submit"
            class="ouro-button ouro-button-danger"
            phx-disable-with="Deleting…"
          >
            Delete
          </button>
        </div>
      </form>
    </dialog>
    """
  end

  # The three glyphs, which are the same ring at three stages of closing.
  #
  # An open arc is work in progress, a closed ring is settled, and the arc with the eye is
  # the one that needs a person. The green is spent **only** on that eye — see
  # `Ouroboros.Web.Live.Cells` — and a failed session is the danger tone on the ring,
  # never a fourth colour.
  attr :group, :atom, required: true
  attr :failed, :boolean, default: false

  def glyph(%{group: :needs_you} = assigns) do
    ~H"""
    <svg
      class="ouro-glyph ouro-glyph-needs"
      viewBox="0 0 16 16"
      width="16"
      height="16"
      aria-hidden="true"
    >
      <circle
        cx="8"
        cy="8"
        r="6"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-dasharray="29 9"
        transform="rotate(-64 8 8)"
      />
      <circle cx="13.4" cy="5.4" r="2.2" fill="var(--attention-green)" />
    </svg>
    """
  end

  def glyph(%{group: :at_work} = assigns) do
    ~H"""
    <svg
      class="ouro-glyph ouro-glyph-work"
      viewBox="0 0 16 16"
      width="16"
      height="16"
      aria-hidden="true"
    >
      <circle
        cx="8"
        cy="8"
        r="6"
        fill="none"
        stroke="currentColor"
        stroke-width="1.6"
        stroke-dasharray="26 12"
        transform="rotate(-90 8 8)"
      />
    </svg>
    """
  end

  def glyph(assigns) do
    ~H"""
    <svg
      class={["ouro-glyph", "ouro-glyph-settled", @failed && "ouro-glyph-failed"]}
      viewBox="0 0 16 16"
      width="16"
      height="16"
      aria-hidden="true"
    >
      <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6" />
    </svg>
    """
  end

  # ------------------------------------------------------------------------------------
  # The focused session
  # ------------------------------------------------------------------------------------

  attr :open, :any, required: true
  attr :row, :any, required: true
  attr :info, :any, required: true
  attr :error, :any, required: true
  attr :truncated, :integer, required: true
  attr :targets, :map, default: %{}
  attr :expanded, :any, required: true
  attr :streams, :map, required: true
  attr :approvals, :list, required: true
  attr :detail, :any, required: true
  attr :notice, :any, required: true
  attr :rule, :any, required: true
  attr :rule_refusal, :any, required: true
  attr :auto_approve, :boolean, required: true
  attr :draft, :string, required: true
  attr :composer_error, :any, required: true
  attr :turn, :map, required: true
  attr :status, :any, required: true
  attr :sandbox, :any, required: true
  attr :effort, :any, required: true
  attr :efforts, :list, required: true
  attr :scope, :atom, required: true
  attr :ended, :boolean, required: true
  attr :draft_key, :string, required: true
  # ui-parity W2. The composer state that is not the draft, in one attr: this component
  # only carries it through.
  attr :extras, :map, default: %{models: nil, model_query: "", next_effort: nil}
  attr :roster, :list, default: []
  # ui-parity W3. `interactive.context`'s own answer, where one has been read, and a `!`
  # the runtime refused. This component only carries them through.
  attr :reading, :any, default: nil
  attr :shell, :any, default: nil

  def focused(assigns) do
    {plane, id} = assigns.open
    operate? = assigns.scope == :operate
    agent_loading? = agent_loading?(assigns)

    assigns =
      assigns
      |> assign(:plane, plane)
      |> assign(:session_id, id)
      |> assign(:unrestricted?, unrestricted?(assigns.row, assigns.info))
      |> assign(:pinned, List.first(assigns.approvals))
      |> assign(:also_waiting, max(length(assigns.approvals) - 1, 0))
      |> assign(:operate?, operate?)
      |> assign(:can_answer, operate? and Call.available?(:operate, "#{plane}.respond_approval"))
      |> assign(:can_remember, operate? and Call.available?(:operate, "permissions.add"))
      |> assign(
        :can_send,
        plane == :interactive and operate? and
          Call.available?(:operate, "interactive.send_message")
      )
      |> assign(
        :can_interrupt,
        plane == :interactive and operate? and Call.available?(:operate, "interactive.interrupt")
      )
      |> assign(
        # ui-parity W3.10. The pair the runtime declares separately, read separately: a
        # transport that said `dynamic_configuration: false` takes no sandbox and no
        # thinking change, and W2 already withheld the palette rows for it. The pickers
        # were still drawn, and a drawn control that always fails is worse than none.
        :can_configure,
        plane == :interactive and operate? and
          Call.available?(:operate, "interactive.configure") and
          Commands.capability_offered?(assigns, :dynamic_configuration)
      )
      |> assign(
        :can_retry,
        operate? and not assigns.ended and not assigns.turn.running? and retryable?(assigns.info)
      )
      |> assign(:agent_loading?, agent_loading?)
      |> assign(:loading_id, loading_id(plane, id))
      |> assign(:node, node_of(assigns.row))
      # ui-parity W2
      |> assign(
        :can_steer,
        plane == :interactive and operate? and Call.available?(:operate, "interactive.steer") and
          Commands.capability_offered?(assigns, :steer)
      )
      |> assign(:planning?, Commands.options(assigns) |> Map.get(:plan) == true)
      |> assign(
        :can_plan,
        plane == :interactive and operate? and not assigns.ended and
          Call.available?(:operate, "interactive.configure") and
          Commands.capability_offered?(assigns, :dynamic_configuration)
      )
      |> assign(
        :can_model,
        plane == :interactive and operate? and not assigns.ended and
          Call.available?(:operate, "interactive.configure") and
          Commands.capability_offered?(assigns, :dynamic_model)
      )
      |> assign(:next_effort, armed_for(assigns.extras, assigns.draft_key))

    ~H"""
    <header class="ouro-focus-head">
      <h1 class="ouro-focus-title">{@row && Rail.title(@row)}</h1>
      <p class="ouro-focus-meta ouro-mono">
        {meta_line(@row)}
        <span :if={@unrestricted?} class="ouro-tag-full">full access</span>
      </p>
    </header>

    <p :if={@error} class="ouro-refusal">{@error}</p>

    <div
      id="transcript"
      class="ouro-transcript"
      phx-hook="ScrollPin"
      data-session={"#{@plane}:#{@session_id}"}
      data-history-start={@truncated}
      role="log"
      aria-live="polite"
      aria-relevant="additions text"
      aria-label="Session transcript"
      tabindex="0"
    >
      <div :if={@truncated > 0} class="ouro-history-loader">
        <button
          type="button"
          class="ouro-quiet-button"
          phx-click="load-history"
          phx-value-session={"#{@plane}:#{@session_id}"}
          phx-disable-with="Loading earlier messages…"
        >
          Load earlier messages
        </button>
      </div>
      <div id="transcript-cells" phx-update="stream">
        <div :for={{dom_id, item} <- @streams.cells} id={dom_id} data-history-cell={item.index}>
          <Cells.cell
            cell={item.cell}
            index={item.index}
            identity={item.id}
            targets={@targets}
            expanded={@expanded}
            plane={@plane}
            session_id={@session_id}
            node={@node}
          />
        </div>
      </div>
    </div>

    <div :if={@agent_loading?} class="ouro-agent-loading">
      <LoadingState.loading id={@loading_id} label="Agent working" variant={:drive} />
    </div>

    <ApprovalCard.card
      :if={@pinned && @detail && @can_answer}
      request={@pinned}
      detail={@detail}
      node={@node}
      rule={@rule}
      rule_refusal={@rule_refusal}
      notice={@notice}
      also_waiting={@also_waiting}
      can_remember={@can_remember}
    />

    <Composer.composer
      :if={@plane == :interactive}
      draft={@draft}
      draft_key={@draft_key}
      image_node={@node}
      image_session_id={@session_id}
      error={@composer_error}
      turn={display_turn(@turn, @info)}
      status={@status}
      sandbox={@sandbox}
      effort={@effort}
      efforts={@efforts}
      can_send={@can_send}
      can_interrupt={@can_interrupt}
      can_configure={@can_configure}
      ended={@ended}
      can_retry={@can_retry}
      can_steer={@can_steer}
      can_plan={@can_plan}
      can_model={@can_model}
      plan={@planning?}
      next_effort={@next_effort}
      model={@info && Map.get(Map.get(@info, :options) || %{}, :model)}
      models={@extras.models}
      model_query={@extras.model_query}
      shell={@shell}
      shell_where={shell_where(@row, @info, @roster)}
    />

    <%!-- The status row the TUI's footer has had all along: the two standing postures a
          reader has to be able to see without opening anything (review §3.2, §5.4.3). It
          is a sibling of the composer rather than a child because `composer.ex` belongs to
          W2; `.ouro-composer-status` is styled to read as the card's own bottom edge. --%>
    <.composer_status_row
      :if={@plane == :interactive}
      sandbox={@sandbox}
      unrestricted={@unrestricted?}
      auto_approve={@auto_approve}
      can_answer={@can_answer}
    />

    <details class="ouro-vitals-mobile" data-ouro-disclosure={"details:#{@session_id}"}>
      <summary>Session details</summary>
      <.vitals info={@info} row={@row} session_id={@session_id} roster={@roster} reading={@reading} />
    </details>
    """
  end

  @doc """
  The composer's bottom edge: what this session is allowed to do, and who is answering.

  Both facts were one click behind "Session details" on every viewport until W1
  (`docs/design-qa/ui-review-2026-09-15.md` §3.2). They are the two standing risks the
  terminal client keeps permanently in its footer, and neither is a thing a person should
  have to remember to go and check.

  ## Why the posture is usually not spelled here

  The composer's own "Change" summary already states the file-access posture one line
  above, and the vitals state it a third time. Three statements of one fact in one band is
  noise, and at 375px it pushed the toggle's caption off the edge. So the row carries the
  toggle, and names the posture only when it is `unrestricted` — the one posture that is a
  standing risk rather than a setting, and the one the amber tag exists for. Everything
  else is already on screen.
  """
  attr :sandbox, :any, required: true
  attr :unrestricted, :boolean, required: true
  attr :auto_approve, :boolean, required: true
  attr :can_answer, :boolean, required: true

  def composer_status_row(assigns) do
    ~H"""
    <div class="ouro-composer-status">
      <span :if={@unrestricted} class="ouro-composer-status-fact">
        <span class="ouro-composer-status-label">File access</span>
        <span class="ouro-mono ouro-tag-full">{Composer.word(@sandbox)}</span>
      </span>

      <.auto_approve_toggle :if={@can_answer} on={@auto_approve} />
    </div>
    """
  end

  # Warning-toned because that is what it is: a control that answers questions on the
  # operator's behalf. It says how long it lasts on its own face, because the honest answer
  # — until this tab is closed or another session is opened — is not something a reader
  # should have to know from a document.
  attr :on, :boolean, required: true

  def auto_approve_toggle(assigns) do
    ~H"""
    <div class={["ouro-auto", @on && "ouro-auto-on"]}>
      <button
        type="button"
        class="ouro-quiet-button"
        phx-click="auto_approve"
        aria-pressed={to_string(@on)}
      >
        {if @on,
          do: "Routine actions are allowed automatically",
          else: "Automatically allow routine actions"}
      </button>
      <span class="ouro-quiet">
        Only for this session while it is open. Questions and screen control still ask you.
      </span>
    </div>
    """
  end

  defp node_of(%Rail.Row{node: node}) when not is_nil(node), do: to_string(node)
  defp node_of(_absent), do: nil

  defp retryable?(%{status: :idle, last_turn: %{status: :failed, retryable: true}}), do: true
  defp retryable?(_), do: false

  defp display_turn(turn, info) do
    if not turn.running? and match?(%{status: :idle, last_turn: %{status: :failed}}, info),
      do: %{turn | failed?: true},
      else: turn
  end

  # A running turn is work by the agent until it becomes a request for the operator. The
  # approval list is fresher than the three-second status poll, while the status exclusion
  # covers an opened session whose request event fell below the retained cursor.
  defp agent_loading?(assigns) do
    not assigns.ended and assigns.approvals == [] and
      assigns.status not in [:awaiting_approval, "awaiting_approval"] and
      Composer.working?(assigns.turn, assigns.status)
  end

  # Hooks need stable, valid DOM ids. Session ids are runtime input and may contain bytes
  # that do not belong in one, so the browser sees only a short URL-safe digest.
  defp loading_id(plane, id) do
    digest =
      :crypto.hash(:sha256, "#{plane}:#{id}")
      |> Base.url_encode64(padding: false)
      |> binary_part(0, 12)

    "agent-loading-#{digest}"
  end

  attr :counts, :map, required: true
  attr :query, :string, default: ""

  def nothing_open(assigns) do
    total = assigns.counts |> Map.values() |> Enum.sum()
    searching? = assigns.query not in [nil, ""]

    # The eyebrow was "A little direction. A lot of possibility." on a console that
    # otherwise refuses to say anything unmeasured (review §3.1). What it says now is a
    # count this page already holds.
    eyebrow =
      cond do
        searching? and total == 0 -> "No sessions match"
        searching? -> "#{total} #{if total == 1, do: "session", else: "sessions"} match"
        total == 0 -> "No sessions on this runtime"
        true -> "#{total} #{if total == 1, do: "session", else: "sessions"} on this runtime"
      end

    assigns = assigns |> assign(:total, total) |> assign(:eyebrow, eyebrow)

    ~H"""
    <div class="ouro-empty">
      <span class="ouro-empty-eyebrow">{@eyebrow}</span>
      <h1 class="ouro-empty-head">What would you like to make?</h1>
      <p :if={@counts[:needs_you] > 0}>
        {@counts[:needs_you]} {if @counts[:needs_you] == 1, do: "session needs", else: "sessions need"} you.
      </p>
      <p :if={@total > 0 and @counts[:needs_you] == 0}>
        Continue a conversation, or give a new idea a place to start.
      </p>
      <p :if={@total == 0}>
        Choose a project, describe a result, and work through it together.
      </p>
      <a href="/new" class="ouro-button">Start a new session</a>
      <div class="ouro-starters" aria-label="Ideas to get started">
        <a href="/new?starter=explain">Understand a project <span>Find your way around the code</span></a>
        <a href="/new?starter=review">Review a change <span>Catch issues before they ship</span></a>
        <a href="/new?starter=build">Build something <span>Turn an idea into a first version</span></a>
      </div>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Vitals
  # ------------------------------------------------------------------------------------

  attr :info, :any, required: true
  attr :row, :any, required: true
  attr :session_id, :string, default: nil
  attr :roster, :list, default: []
  # ui-parity W3.7. What `interactive.context` answered for this session, where it has
  # been asked. The meter prefers it because it is the *measurement*: a list row's usage
  # is reduced by the runtime to tokens and cost and carries no window at all.
  attr :reading, :any, default: nil

  def vitals(assigns) do
    usage = (assigns.info && Map.get(assigns.info, :usage)) || %{}
    options = (assigns.info && Map.get(assigns.info, :options)) || %{}

    assigns =
      assigns
      |> assign(:usage, usage)
      |> assign(:options, options)
      |> assign(:context, ContextPanel.meter(assigns.reading) || context(usage))
      |> assign(:unrestricted?, unrestricted?(assigns.row, assigns.info))

    ~H"""
    <aside class="ouro-vitals" aria-label="session vitals">
      <.vital
        label="Model"
        value={
          Map.get(@options, :model) || (@row && @row.model) || "Chosen by provider · not reported"
        }
      />

      <div class="ouro-vital">
        <dt>Context</dt>
        <dd>
          <div :if={@context} class="ouro-meter" role="img" aria-label={@context.label}>
            <div class="ouro-meter-fill" style={"width: #{@context.percent}%"}></div>
          </div>
          <span class="ouro-mono">{(@context && @context.label) || "not reported"}</span>
        </dd>
      </div>

      <.vital label="Tokens" value={Map.get(@usage, :total_tokens)} />
      <.vital label="Cost" value={cost(Map.get(@usage, :cost_usd))} />

      <div class="ouro-vital">
        <dt>File access</dt>
        <dd class={["ouro-mono", @unrestricted? && "ouro-tag-full"]}>
          {sandbox_word(@options, @row)}
        </dd>
      </div>

      <.vital label="Machine" value={Presentation.node_label(@row && @row.node, @roster)} />
      <.vital label="Provider" value={@row && @row.provider} />
      <.vital label="Replay" value={replay_word(@options)} />
      <.vital label="Workspace" value={@row && @row.workspace} />

      <%!-- `rail.ex:165-166` has always said the session's stable id is "in session
            details"; until W1 it was nowhere but the URL (review §3.2). A `<code>` rather
            than an `<input>`: a fixed-width field truncated the id
            (`browser-history-replay-desk…`), and an id a reader cannot see whole is not
            the id. `user-select: all` makes one click select the lot.

            Integrator line: the clipboard belongs to `app.js`, so the copy *button* lands
            with the shared clipboard hook in a later slice; a control that did nothing
            would be worse than a value a reader can select. --%>
      <div :if={@session_id} class="ouro-vital">
        <dt>Session id</dt>
        <dd><code class="ouro-mono ouro-vital-id">{@session_id}</code></dd>
      </div>

      <%!-- ui-parity W3. An ordinary link rather than a `phx-click`: the response carries
            `content-disposition: attachment`, so the browser saves the file and stays on
            this page. The palette's own row offers the events form beside this one. --%>
      <div :if={@session_id} class="ouro-vital">
        <dt>Transcript</dt>
        <dd>
          <a href={"/s/interactive/#{Route.segment(@session_id)}/export?format=text"}>Export</a>
        </dd>
      </div>
    </aside>
    """
  end

  attr :label, :string, required: true
  attr :value, :any, required: true

  def vital(assigns) do
    ~H"""
    <div class="ouro-vital">
      <dt>{@label}</dt>
      <dd class="ouro-mono">{present(@value)}</dd>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Presentation helpers — none of them decides a word the projection owns
  # ------------------------------------------------------------------------------------

  defp row(_rows, nil), do: nil

  defp row(rows, {plane, id}),
    do: Enum.find(rows, &(&1.plane == plane and &1.id == id))

  # The approvals the open session is waiting on, so its rail row triages as needing a
  # person the moment one arrives rather than when the next poll happens to see the status.
  #
  # One session, because this view holds one subscription. Every other row reaches
  # `NEEDS YOU` through its declared `awaiting_approval` status and can only be opened —
  # the rail cannot offer an inline answer to a request it has not read.
  defp pending(%{open: {plane, id}, approvals: approvals}) when is_list(approvals),
    do: %{{plane, id} => length(approvals)}

  defp pending(_assigns), do: %{}

  defp row_status(%Rail.Row{status: status}), do: status
  defp row_status(_absent), do: nil

  # A session that will produce no further events takes no further messages either, from
  # either proof: the stream said so, or the row's status did.
  defp ended?(assigns, row) do
    watched = assigns.watch && Watch.ended?(assigns.watch)
    listed = row && Rail.terminal?(row.status)

    watched == true or listed == true
  end

  # The locked gate, asked once per render for the pinned request. Its two halves are a
  # rule to offer or the sentence naming why there is none, and this passes it the two
  # facts only the deck has: what this runtime serves, and what workspace this session
  # named.
  defp rule_offer(%{pinned_detail: %Approval.Detail{} = detail} = assigns) do
    workspace =
      (assigns.info && Map.get(assigns.info, :workspace)) ||
        case row(assigns.rows, assigns.open) do
          %Rail.Row{workspace: workspace} -> workspace
          _unknown -> nil
        end

    Transcript.suggested_rule(detail.suggested_rule, assigns.methods, workspace)
  end

  defp rule_offer(_assigns), do: {nil, nil}

  # Self is always connected — it is the machine answering this request — and every other
  # machine is filled iff `connected_nodes` names it.
  #
  # The roster comes from the cluster's own last-known directory where the status carries
  # one, because that is the only place a machine that is *expected and absent* exists:
  # `connected_nodes` by construction lists only machines that are up, so a deck standing
  # on it alone could never draw a hollow dot. Before a first status there are no dots at
  # all rather than dots claiming everything is down — unknown is not offline.
  @doc false
  # Public only so the roster half can be asserted: `runtime.status` answers this node's
  # real cluster, and there is no way to give it a two-machine fleet from a test.
  def machines(nil), do: []

  def machines(status) do
    self_node = to_string(Map.get(status, :node, node()))
    connected = status |> Map.get(:connected_nodes, []) |> List.wrap() |> Enum.map(&to_string/1)
    roster = fleet_roster(status)

    known =
      roster
      |> Enum.map(&to_string(Map.get(&1, :node, "")))
      |> Enum.reject(&(&1 == ""))

    ([self_node] ++ connected ++ known)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn name ->
      # The label is computed here, where the roster is, rather than in the bar: two
      # machines in one fleet share a release name (`ouro@alpha`, `ouro@beta`), and a bar
      # that shortened both to "ouro" would put the same word under two dots.
      %{
        name: name,
        label: Presentation.node_label(name, roster),
        connected?: name == self_node or name in connected
      }
    end)
  end

  # The cluster's own last-known directory, where the status carries one. It is also the
  # only place a machine has a name somebody chose, which is why every node label on this
  # page is resolved against it.
  defp fleet_roster(status) when is_map(status) do
    status
    |> Map.get(:cluster, %{})
    |> then(&if(is_map(&1), do: Map.get(&1, :fleet, %{}), else: %{}))
    |> then(&if(is_map(&1), do: Map.get(&1, :machines, []), else: []))
    |> List.wrap()
  end

  defp fleet_roster(_status), do: []

  # Today's totals, summed off rows this view already has. Cheap because it is arithmetic
  # over the list the rail is drawing anyway; UTC because that is what the runtime writes,
  # and the tooltip says so rather than implying a local day.
  defp today(rows) do
    prefix = Date.utc_today() |> Date.to_iso8601()

    rows
    |> Enum.filter(fn row ->
      is_binary(row.updated_at) and String.starts_with?(row.updated_at, prefix)
    end)
    |> Enum.reduce(%{tokens: nil, cost: nil}, fn row, acc ->
      %{
        tokens: add(acc.tokens, row.total_tokens),
        cost: add(acc.cost, row.cost_usd)
      }
    end)
    |> then(fn totals -> %{totals | cost: cost(totals.cost)} end)
  end

  defp add(nil, nil), do: nil
  defp add(total, nil), do: total
  defp add(nil, value) when is_number(value), do: value
  defp add(total, value) when is_number(total) and is_number(value), do: total + value
  defp add(total, _value), do: total

  defp cost(nil), do: nil
  defp cost(value) when is_number(value), do: :erlang.float_to_binary(value * 1.0, decimals: 4)
  defp cost(_value), do: nil

  # The one line under a row's title.
  #
  # `activity` is what the *watched* session is doing this second, taken off the cells
  # already projected. Every other row falls back to provider · machine, because a rail
  # cannot know what an unwatched session is doing and a line that guessed would be the
  # one thing on this page a reader could not trust.
  defp line(:needs_you, row, activity, roster), do: activity || ask_line(row, roster)

  # An idle row carries its age in the line rather than only in the right-hand column,
  # because "idle" alone says nothing a reader can act on — how long it has been idle is
  # the whole content of the row. The column is dropped for these rows so the age is not
  # printed twice; `age_in_line?/2` is the one place that decision is made.
  defp line(:settled, %Rail.Row{status: :idle} = row, _activity, _roster) do
    case age(row.updated_at) do
      "" -> Rail.outcome(row)
      age -> "#{Rail.outcome(row)} · #{age}"
    end
  end

  defp line(:settled, row, _activity, _roster) do
    case row.error do
      nil -> Rail.outcome(row)
      error -> "#{Rail.outcome(row)} — #{brief(error)}"
    end
  end

  defp line(_at_work, row, activity, roster), do: activity || provider_line(row, roster)

  defp age_in_line?(:settled, %Rail.Row{status: :idle}), do: true
  defp age_in_line?(_group, _row), do: false

  defp ask_line(row, roster) do
    case row.status do
      :awaiting_approval -> "waiting on your answer"
      :idle -> "waiting for your next message"
      _other -> provider_line(row, roster)
    end
  end

  # The newest cell that says what is happening: a tool call, or a loud status line. Read
  # off the projection rather than off the raw ledger so the words are the ones the
  # transcript is showing, and nothing here mints a phrase the corpus does not pin.
  # `:cells` is a **map** from cell id to `%{id:, cell:, index:}` — assigned `%{}` at mount
  # and `Map.new/2` on every redraw. The `when is_list(cells)` guard this carried until W1
  # could therefore never match, so every rail row fell back to `provider · machine` and
  # nothing on the rail distinguished a session doing work from one sitting still
  # (`docs/design-qa/ui-review-2026-09-15.md` §3.2). Newest first, by the index the redraw
  # assigned, and the `Cell` struct is unwrapped because `activity_of/1` reads cells rather
  # than the envelopes they are held in.
  defp activity(%{open: {plane, id}, cells: cells}) when is_map(cells) do
    line =
      cells
      |> Map.values()
      |> Enum.sort_by(& &1.index, :desc)
      |> Enum.find_value(&activity_of(&1.cell))

    case line do
      nil -> %{}
      line -> %{{plane, id} => line}
    end
  end

  defp activity(_assigns), do: %{}

  # Only a call that has **not** settled. `activity` is what the watched session is doing
  # *this second*, so a tool that completed two turns ago is history: the rail would have
  # said "Bash $ mix compile" in the present tense while a new turn streamed prose. A
  # settled call falls through to the next-newest running thing, and from there to the
  # projection's own status line or to `provider · machine`.
  defp activity_of(%Cell.Tool{state: :running} = tool) do
    case tool |> Transcript.Tools.summarise() |> Transcript.ToolSummary.line() do
      "" -> nil
      line -> line
    end
  end

  # `done` is set on every exploration group except the last one in the transcript
  # (`Transcript.project/1`), so `done: false` is the group still being added to.
  defp activity_of(%Cell.Exploration{done: false} = cell) do
    "exploring · #{Cell.Exploration.total(cell)} calls"
  end

  defp activity_of(%Cell.Status{label: label}) when label != "", do: label
  defp activity_of(_cell), do: nil

  # "provider · machine", where the machine is what a person would call it rather than the
  # BEAM's node atom — ground rule 6, and the reason `nonode@nohost` used to sit on every
  # unwatched row. A row with no node at all still says nothing about one.
  defp provider_line(row, roster) do
    machine = row.node && Presentation.node_label(row.node, roster)

    [row.provider, machine]
    |> Enum.reject(&is_nil/1)
    |> Enum.map_join(" · ", &to_string/1)
  end

  defp meta_line(nil), do: ""

  defp meta_line(row) do
    [provider_name(row.provider), row.workspace && Path.basename(row.workspace)]
    |> Enum.reject(&is_nil/1)
    |> Enum.map_join(" · ", &to_string/1)
  end

  # A record written before the reduction still names the provider it ran under, and it is
  # still listed with its history; the name it carries is drawn as it was stored.
  defp provider_name(:native), do: "Ouroboros AI"
  defp provider_name(provider), do: provider

  # `unrestricted` is the one sandbox posture worth a tag: it is the session that can do
  # anything, and a reader who did not notice would be reading a transcript without
  # knowing what it was allowed to do.
  defp unrestricted?(row, info) do
    options = (info && Map.get(info, :options)) || %{}

    sandbox = Map.get(options, :sandbox_mode) || (row && row.sandbox_mode)

    to_string(sandbox || "") == "unrestricted"
  end

  # R3/D10. Whether this session kept a turn journal, read off the capabilities the
  # projection already carries rather than asked for separately. `nil` — and so an em dash
  # — where the provider or transport did not resolve, because "not answered" and "not
  # replayable" are different facts and a vital that spelled them the same would be the
  # lie this capability exists to prevent. The rail *row* badge is deliberately not here:
  # `Rail.Row` carries no capabilities field, and REPLAY.md §7.3 records that divergence.
  defp replay_word(options) do
    case options |> Map.get(:capabilities) |> then(&(&1 || %{})) |> Map.get(:replay) do
      true -> "yes"
      false -> "no"
      nil -> nil
      other -> to_string(other)
    end
  end

  defp sandbox_word(options, row) do
    case Map.get(options, :sandbox_mode) || (row && row.sandbox_mode) do
      nil -> "Not reported"
      mode -> Composer.word(to_string(mode))
    end
  end

  # Measured, never derived: both numbers come from the session's own usage account, and
  # a report that carries only one of them gets no meter at all.
  defp context(usage) do
    with window when is_integer(window) and window > 0 <- Map.get(usage, :context_window),
         used when is_integer(used) and used >= 0 <- Map.get(usage, :context_used) do
      percent = min(used / window * 100, 100)

      %{
        percent: :erlang.float_to_binary(percent * 1.0, decimals: 1),
        label: "#{used} / #{window}"
      }
    else
      _unreported -> nil
    end
  end

  defp present(nil), do: "—"
  defp present(""), do: "—"
  defp present(value) when is_binary(value), do: value
  defp present(value), do: to_string(value)

  defp brief(error) do
    error |> inspect(limit: 3) |> String.slice(0, 120)
  end

  # Coarse on purpose: a rail redrawn every three seconds with a second-accurate age would
  # rewrite every row on every poll for information nobody reads that closely.
  defp age(nil), do: ""

  defp age(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, at, _offset} -> ago(DateTime.diff(DateTime.utc_now(), at, :second))
      _unparseable -> ""
    end
  end

  defp age(_timestamp), do: ""

  defp ago(seconds) when seconds < 60, do: "now"
  defp ago(seconds) when seconds < 3_600, do: "#{div(seconds, 60)}m"
  defp ago(seconds) when seconds < 86_400, do: "#{div(seconds, 3_600)}h"
  defp ago(seconds), do: "#{div(seconds, 86_400)}d"
end
