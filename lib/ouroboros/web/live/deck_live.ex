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
  request that is **not** a question, a plan exit, or a Computer Use ask is answered
  `{approve, once, actor: "automation"}` — the terminal client's exact carve-outs, read
  through the one predicate both surfaces share. Answered request ids are remembered so a
  replay after a repair cannot answer the same request twice.

  ## What this slice does not do

  Starting a session is W6; its control is a link to a page that lands with it.
  """

  use Phoenix.LiveView

  require Logger

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.ApprovalCard
  alias Ouroboros.Web.Live.Cells
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Approval
  alias Ouroboros.Web.Transcript.Cell
  alias Ouroboros.Web.Watch

  @poll_interval 3_000
  @coalesce 80
  @planes %{"interactive" => :interactive, "coding" => :coding}

  # A turn state nothing has been read from yet, so the composer has something to draw
  # before a session is open.
  @quiet_turn %{running?: false, spoke?: false, turn_id: nil, queued: 0}

  # ------------------------------------------------------------------------------------
  # Lifecycle
  # ------------------------------------------------------------------------------------

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:scope, Config.for_endpoint(socket.endpoint).scope)
      |> assign(:rows, [])
      |> assign(:list_error, nil)
      |> assign(:status, nil)
      |> assign(:polling?, false)
      |> assign(:open, nil)
      |> assign(:watch, nil)
      |> assign(:info, nil)
      |> assign(:monitor, nil)
      |> assign(:flush_scheduled?, false)
      |> assign(:subscribe_error, nil)
      |> assign(:expanded, MapSet.new())
      |> assign(:cells, [])
      |> assign(:drawn, 0)
      |> assign(:truncated, 0)
      # The serving runtime's method list, read once: it is the same list `hello` answers
      # for a terminal client and it cannot change while this process lives.
      |> assign(:methods, Methods.names())
      |> reset_session_state()
      |> stream(:cells, [])

    # The first paint is server-rendered and has to have content in it: a deck that showed
    # an empty rail until a socket connected would flash empty on every navigation.
    socket = refresh(socket)

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

  # A fold changes what every cell renders as, not what any cell *is*, so the whole stream
  # is rewritten rather than diffed: the projection did not move, the drawing did.
  @impl true
  def handle_event("expand", %{"block" => block}, socket),
    do: {:noreply, socket |> update(:expanded, &MapSet.put(&1, block)) |> redraw(:reset)}

  def handle_event("collapse", %{"block" => block}, socket),
    do: {:noreply, socket |> update(:expanded, &MapSet.delete(&1, block)) |> redraw(:reset)}

  # ------------------------------------------------------------------------------------
  # The composer
  # ------------------------------------------------------------------------------------

  # The draft is held server-side so a refusal can hand it back verbatim, and so a live
  # delta landing under the cursor cannot take it away. Debounced at the element: this
  # costs one round trip per pause in typing, not one per keystroke.
  #
  # A change also forgets the last send, which is what makes a deliberate repeat of the
  # same words a second turn while a double-click stays one — see `turn_id_for/2`.
  def handle_event("draft", %{"message" => text}, socket) when is_binary(text),
    do: {:noreply, socket |> assign(:draft, text) |> assign(:last_send, nil)}

  def handle_event("draft", _params, socket), do: {:noreply, socket}

  def handle_event("send", %{"message" => text}, socket) when is_binary(text),
    do: {:noreply, send_turn(socket, String.trim_trailing(text))}

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
  def handle_event("auto_approve", _params, socket) do
    socket = update(socket, :auto_approve?, &(not &1))
    {:noreply, auto_answer(socket)}
  end

  # A `phx-value-*` this page never drew. Every clause above matches on the values it
  # renders, so anything reaching here is browser input that did not come from a control —
  # and the honest response to a click that did not happen is to do nothing, not to crash
  # the view and make an operator's transcript remount.
  def handle_event(event, _params, socket)
      when event in ["send", "respond", "respond_option", "plan_choice", "remember"],
      do: {:noreply, socket}

  # ------------------------------------------------------------------------------------
  # Messages
  # ------------------------------------------------------------------------------------

  @impl true
  def handle_info(:poll, socket) do
    schedule_poll()
    {:noreply, refresh(socket)}
  end

  def handle_info({:ouroboros_interactive_event, id, event}, socket),
    do: {:noreply, live_event(socket, :interactive, id, event)}

  def handle_info({:ouroboros_coding_event, id, event}, socket),
    do: {:noreply, live_event(socket, :coding, id, event)}

  def handle_info(:flush, socket) do
    {:noreply, socket |> assign(:flush_scheduled?, false) |> redraw(:delta)}
  end

  # The coordinator a subscription is registered with went away, which is the only way
  # this view learns that no further events are coming. Not an error and not a reason to
  # resubscribe on a loop: a retired coordinator is a session that ended.
  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{assigns: %{monitor: ref}} = socket) do
    socket =
      socket
      |> assign(:monitor, nil)
      |> update(:watch, &Watch.ended(&1, ended_status(socket)))
      |> redraw(:reset)

    {:noreply, socket}
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
  end

  # Both planes, each refused independently: a coding list that failed must not empty a
  # rail the interactive list answered for.
  defp sessions(scope, session) do
    {interactive, first} = list(scope, "interactive.list", &Rail.from_interactive/1, session)
    {coding, second} = list(scope, "coding.list", &Rail.from_coding/1, session)

    {interactive ++ coding, first || second}
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
    method = if plane == :interactive, do: "interactive.info", else: "coding.info"
    params = session_params(socket, plane, id)

    case Call.call(socket.assigns.scope, method, params, session: socket.assigns[:web_session]) do
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

  defp owner(socket, plane, id) do
    Enum.find_value(socket.assigns.rows, fn row ->
      if row.plane == plane and row.id == id, do: row.node
    end)
  end

  # ------------------------------------------------------------------------------------
  # Opening a session: subscribe, check terminality, monitor
  # ------------------------------------------------------------------------------------

  defp open(%{assigns: %{open: {plane, id}}} = socket, plane, id), do: socket

  defp open(socket, plane, id) do
    socket
    |> close()
    |> assign(:open, {plane, id})
    |> assign(:watch, Watch.new())
    |> resubscribe()
    |> refresh_info()
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
    |> assign(:watch, nil)
    |> assign(:info, nil)
    |> assign(:subscribe_error, nil)
    |> assign(:cells, [])
    |> assign(:drawn, 0)
    |> assign(:truncated, 0)
    |> reset_session_state()
    |> stream(:cells, [], reset: true)
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
      :coding -> Ouroboros.Coding.TaskRef.new(id, owner)
    end
  end

  # The status a `:DOWN` stands for.
  #
  # The plane's own word where something still carries one — a coordinator retires *after*
  # its checkpoint says why, so `interactive.info`'s last answer and the rail row are both
  # ahead of this view. Never re-asked: `info` would restart the coordinator that just
  # retired, which is a side effect a divider has no business causing. The generic word
  # when neither knows, and never a guess at success or failure.
  defp ended_status(%{assigns: %{open: {plane, id}}} = socket) do
    from_info = socket.assigns.info && Map.get(socket.assigns.info, :status)

    from_row =
      case Enum.find(socket.assigns.rows, &(&1.plane == plane and &1.id == id)) do
        %Rail.Row{status: status} -> status
        _unknown -> nil
      end

    case from_info || from_row do
      status when is_atom(status) and not is_nil(status) -> to_string(status)
      _unknown -> "ended"
    end
  end

  defp ended_status(_socket), do: "ended"

  # ------------------------------------------------------------------------------------
  # Live events
  # ------------------------------------------------------------------------------------

  # Absorbed now, drawn later. A streaming turn is one message per delta, and the whole
  # cost of this surface under load is whether that message re-projects the ledger.
  defp live_event(%{assigns: %{open: {plane, id}}} = socket, plane, id, event) do
    socket
    |> update(:watch, &Watch.absorb(&1, event))
    |> schedule_flush()
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

  defp refusal_message(other) do
    Logger.error("web verb answered #{inspect(other, limit: 5)}")
    "the runtime answered something this build cannot read"
  end

  defp notice(socket, tone, text),
    do: assign(socket, :approval_notice, %{tone: tone, text: text})

  # ---------------------------------------------------------------------------- Sending

  defp send_turn(%{assigns: %{open: {:interactive, _id}}} = socket, "") do
    assign(socket, :composer_error, "write a message before sending")
  end

  defp send_turn(%{assigns: %{open: {:interactive, id}}} = socket, text) do
    turn_id = turn_id_for(socket, text)

    params =
      socket
      |> session_params(:interactive, id)
      |> Map.merge(%{"input" => text, "turn_id" => turn_id})

    socket = assign(socket, :last_send, {text, turn_id})
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

  defp send_turn(socket, _text) do
    assign(
      socket,
      :composer_error,
      "this plane runs to completion and takes no messages; the terminal client has its controls"
    )
  end

  defp sent(socket), do: socket |> assign(:draft, "") |> assign(:composer_error, nil)

  # The draft is handed back exactly as it was typed. A composer that cleared itself on a
  # refusal would lose the one thing the operator could not get back.
  defp refused(socket, text, message),
    do: socket |> assign(:draft, text) |> assign(:composer_error, message)

  # A second click of the same words with no typing in between is the same turn; anything
  # else is a new one. The runtime does the deduplicating — `{id, input, turn_id}` repeated
  # returns the turn it already has — so this only has to decide when the id is the same.
  defp turn_id_for(%{assigns: %{last_send: {text, turn_id}}}, text), do: turn_id

  defp turn_id_for(_socket, _text) do
    "web-" <>
      (:crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower))
  end

  # ------------------------------------------------------------------------ Configuring

  defp configure(%{assigns: %{open: {:interactive, id}}} = socket, field, choice) do
    if allowed_choice?(field, choice) do
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

  defp allowed_choice?("sandbox_mode", choice), do: choice in Composer.sandbox_modes()
  defp allowed_choice?("reasoning_effort", choice), do: choice in Composer.efforts()
  defp allowed_choice?(_field, _choice), do: false

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

  # Every pending request that is not a question, a plan exit, or a Computer Use ask.
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

  # Computer Use remember is user-scoped by design (D4): the grant is "this app, from this
  # operator", which is not a fact about a directory. Every other pattern is scoped to the
  # workspace the gate already proved this session names.
  defp add_rule(%{assigns: %{open: {plane, id}}} = socket, %Approval.Rule{} = rule) do
    params =
      if String.starts_with?(rule.pattern, "ComputerUse(") do
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

  # ------------------------------------------------------------------------------------
  # Projection into the stream
  # ------------------------------------------------------------------------------------

  defp redraw(%{assigns: %{watch: nil}} = socket, _mode), do: socket

  defp redraw(socket, mode) do
    entries = Watch.entries(socket.assigns.watch)
    window = Transcript.chat_entry_window()
    total = length(entries)
    truncated = max(total - window, 0)
    cells = entries |> Enum.take(-window) |> Transcript.project()

    # Approvals come off the whole held ledger, not off the drawn window: a request that
    # scrolled past the redraw budget is still a request nobody has answered.
    approvals = Watch.pending_approvals(socket.assigns.watch)

    socket =
      socket
      |> assign(:truncated, truncated)
      |> assign(:approvals, approvals)
      # Read once here rather than twice per render. `Approval.detail/1` parses the
      # request's patch, and a poll every three seconds plus a flush every eighty
      # milliseconds is not the cadence to re-parse a diff on.
      |> assign(:pinned_detail, detail_of(List.first(approvals)))
      |> assign(:turn, Composer.turn_state(entries))

    socket =
      case mode do
        :reset -> reset_stream(socket, cells)
        :delta -> patch_stream(socket, cells)
      end

    # Every path that changes what is pending ends here, so automation has exactly one
    # place to look and the backlog flush on enable is the same code as the live one.
    auto_answer(socket)
  end

  # Everything changed underneath the list — a different session, a reopened block, a
  # floor that moved every index. Cheaper and more honest than diffing a list whose
  # positions no longer mean what they did.
  defp reset_stream(socket, cells) do
    socket
    |> stream(:cells, items(cells), reset: true)
    |> assign(:cells, cells)
    |> assign(:drawn, length(cells))
  end

  # The ordinary case: a few deltas landed and one cell at the end changed. Only what
  # differs is sent, which is the whole reason this pane uses a stream.
  defp patch_stream(socket, cells) do
    previous = socket.assigns.cells
    previous_by_index = previous |> Enum.with_index() |> Map.new(fn {cell, i} -> {i, cell} end)

    socket =
      cells
      |> Enum.with_index()
      |> Enum.reduce(socket, fn {cell, index}, socket ->
        if Map.get(previous_by_index, index) == cell do
          socket
        else
          stream_insert(socket, :cells, item(cell, index), at: index)
        end
      end)

    socket =
      Enum.reduce(length(cells)..(socket.assigns.drawn - 1)//1, socket, fn index, socket ->
        stream_delete_by_dom_id(socket, :cells, "cells-cell-#{index}")
      end)

    socket
    |> assign(:cells, cells)
    |> assign(:drawn, length(cells))
  end

  defp items(cells), do: cells |> Enum.with_index() |> Enum.map(fn {c, i} -> item(c, i) end)

  defp item(cell, index), do: %{id: "cell-#{index}", index: index, cell: cell}

  # ------------------------------------------------------------------------------------
  # Render
  # ------------------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    open_row = row(assigns.rows, assigns.open)
    {rule, rule_refusal} = rule_offer(assigns)

    assigns =
      assigns
      |> assign(:triaged, Rail.triaged(assigns.rows, pending(assigns)))
      |> assign(:machines, machines(assigns.status))
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
      |> assign(:ended?, ended?(assigns, open_row))

    ~H"""
    <div class="ouro-deck">
      <.top_bar machines={@machines} today={@today} />

      <div class="ouro-columns">
        <.rail
          triaged={@triaged}
          open={@open}
          error={@list_error}
          activity={@activity}
          approvals={@approvals}
          answerable={@scope == :operate}
        />

        <main class="ouro-focus">
          <.focused
            :if={@open}
            open={@open}
            row={@open_row}
            info={@info}
            error={@subscribe_error}
            truncated={@truncated}
            expanded={@expanded}
            streams={@streams}
            approvals={@approvals}
            detail={@pinned_detail}
            notice={@approval_notice}
            rule={@rule}
            rule_refusal={@rule_refusal}
            auto_approve={@auto_approve?}
            draft={@draft}
            composer_error={@composer_error}
            turn={@turn}
            status={@row_status}
            sandbox={@sandbox}
            effort={@effort}
            scope={@scope}
            ended={@ended?}
          />
          <.nothing_open :if={is_nil(@open)} counts={Rail.counts(@triaged)} />
        </main>

        <.vitals :if={@open} info={@info} row={@open_row} />
      </div>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # The top bar
  # ------------------------------------------------------------------------------------

  attr :machines, :list, required: true
  attr :today, :map, required: true

  def top_bar(assigns) do
    ~H"""
    <header class="ouro-topbar">
      <span class="ouro-wordmark">Ouroboros</span>

      <a class="ouro-presence" role="group" aria-label="machines" href="/machines">
        <span
          :for={machine <- @machines}
          class={["ouro-dot", machine.connected? && "ouro-dot-on"]}
          title={"#{machine.name} — #{if machine.connected?, do: "connected", else: "not connected"}"}
        >
          <span class="ouro-visually-hidden">{machine.name}</span>
        </span>
      </a>

      <div class="ouro-topbar-right">
        <span :if={@today.tokens} class="ouro-today ouro-mono" title="sessions updated today, UTC">
          {@today.tokens} tokens<span :if={@today.cost}> · ${@today.cost}</span>
        </span>
        <span class="ouro-pill">
          <span class="ouro-pill-on">Connected</span>
          <span class="ouro-pill-off">Reconnecting</span>
        </span>
        <a class="ouro-button" href="/new">
          New session
        </a>
      </div>
    </header>
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

  def rail(assigns) do
    assigns = assign(assigns, :counts, Rail.counts(assigns.triaged))

    ~H"""
    <nav class="ouro-rail" aria-label="sessions">
      <p :if={@error} class="ouro-refusal">{@error}</p>

      <section :for={group <- Rail.groups()} class={"ouro-group ouro-group-#{group}"}>
        <h2 class="ouro-group-head">
          {Rail.label(group)}
          <span :if={group == :needs_you and @counts[group] > 0} class="ouro-count">
            {@counts[group]}
          </span>
        </h2>

        <p :if={@counts[group] == 0} class="ouro-group-empty">nothing here</p>

        <.rail_row
          :for={entry <- Enum.filter(@triaged, &(&1.group == group))}
          entry={entry}
          open={@open}
          activity={@activity}
          approvals={@approvals}
          answerable={@answerable}
        />
      </section>
    </nav>
    """
  end

  attr :entry, :map, required: true
  attr :open, :any, required: true
  attr :activity, :map, required: true
  attr :approvals, :list, default: []
  attr :answerable, :boolean, default: false

  def rail_row(assigns) do
    row = assigns.entry.row
    selected? = assigns.open == {row.plane, row.id}

    assigns =
      assigns
      |> assign(:row, row)
      |> assign(:selected?, selected?)
      |> assign(:href, "/s/#{row.plane}/#{row.id}")
      |> assign(
        :line,
        line(assigns.entry.group, row, Map.get(assigns.activity, {row.plane, row.id}))
      )
      |> assign(:age_in_line?, age_in_line?(assigns.entry.group, row))
      |> assign(:answers, inline_answers(assigns, selected?))

    ~H"""
    <.link
      patch={@href}
      class={[
        "ouro-row",
        "ouro-row-#{@entry.group}",
        @entry.depth == 1 && "ouro-row-nested",
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
    <ApprovalCard.inline :for={request <- @answers} request={request} />
    """
  end

  # Two buttons on a row, for a plain permission and nothing else. A question, a plan exit
  # and a Computer Use ask carry a decision a one-line row never showed, so those rows stay
  # a link into the session — `Approval.question?/1` draws that line, once, for both
  # surfaces. Outside the link element on purpose: a button inside an anchor is markup no
  # browser agrees about.
  defp inline_answers(%{answerable: true, approvals: approvals}, true) when is_list(approvals),
    do: Enum.filter(approvals, &ApprovalCard.inline?/1)

  defp inline_answers(_assigns, _selected?), do: []

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
  attr :scope, :atom, required: true
  attr :ended, :boolean, required: true

  def focused(assigns) do
    {plane, id} = assigns.open
    operate? = assigns.scope == :operate

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
        :can_configure,
        plane == :interactive and operate? and Call.available?(:operate, "interactive.configure")
      )
      |> assign(:node, node_of(assigns.row))

    ~H"""
    <header class="ouro-focus-head">
      <h1 class="ouro-focus-title">{@row && Rail.title(@row)}</h1>
      <p class="ouro-focus-meta ouro-mono">
        {meta_line(@row)}
        <span :if={@unrestricted?} class="ouro-tag-full">full access</span>
      </p>
    </header>

    <p :if={@error} class="ouro-refusal">{@error}</p>

    <p :if={@truncated > 0} class="ouro-quiet ouro-truncation">
      the {@truncated} earlier entries this view holds are not drawn
    </p>

    <div id="transcript" class="ouro-transcript" phx-update="stream" phx-hook="ScrollPin">
      <div :for={{dom_id, item} <- @streams.cells} id={dom_id}>
        <Cells.cell
          cell={item.cell}
          index={item.index}
          expanded={@expanded}
          plane={@plane}
          session_id={@session_id}
        />
      </div>
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

    <.auto_approve_toggle :if={@can_answer} on={@auto_approve} />

    <Composer.composer
      :if={@plane == :interactive}
      draft={@draft}
      error={@composer_error}
      turn={@turn}
      status={@status}
      sandbox={@sandbox}
      effort={@effort}
      can_send={@can_send}
      can_interrupt={@can_interrupt}
      can_configure={@can_configure}
      ended={@ended}
    />
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
        {if @on, do: "Auto-approve is on", else: "Auto-approve"}
      </button>
      <span class="ouro-quiet">
        this view only · never a question, a plan exit, or a Computer Use ask
      </span>
    </div>
    """
  end

  defp node_of(%Rail.Row{node: node}) when not is_nil(node), do: to_string(node)
  defp node_of(_absent), do: nil

  attr :counts, :map, required: true

  def nothing_open(assigns) do
    ~H"""
    <div class="ouro-empty">
      <h1 class="ouro-empty-head">Nothing open</h1>
      <p :if={@counts[:needs_you] > 0}>
        {@counts[:needs_you]} {if @counts[:needs_you] == 1, do: "session needs", else: "sessions need"} you.
      </p>
      <p :if={@counts[:needs_you] == 0}>Pick a session from the rail to read it.</p>
    </div>
    """
  end

  # ------------------------------------------------------------------------------------
  # Vitals
  # ------------------------------------------------------------------------------------

  attr :info, :any, required: true
  attr :row, :any, required: true

  def vitals(assigns) do
    usage = (assigns.info && Map.get(assigns.info, :usage)) || %{}
    options = (assigns.info && Map.get(assigns.info, :options)) || %{}

    assigns =
      assigns
      |> assign(:usage, usage)
      |> assign(:options, options)
      |> assign(:context, context(usage))
      |> assign(:unrestricted?, unrestricted?(assigns.row, assigns.info))

    ~H"""
    <aside class="ouro-vitals" aria-label="session vitals">
      <.vital label="Model" value={Map.get(@options, :model) || (@row && @row.model)} />

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
        <dt>Sandbox</dt>
        <dd class={["ouro-mono", @unrestricted? && "ouro-tag-full"]}>
          {sandbox_word(@options, @row)}
        </dd>
      </div>

      <.vital label="Machine" value={@row && @row.node} />
      <.vital label="Provider" value={@row && @row.provider} />
      <.vital label="Workspace" value={@row && @row.workspace} />
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
  defp machines(nil), do: []

  defp machines(status) do
    self_node = to_string(Map.get(status, :node, node()))
    connected = status |> Map.get(:connected_nodes, []) |> List.wrap() |> Enum.map(&to_string/1)

    known =
      status
      |> Map.get(:cluster, %{})
      |> Map.get(:fleet, %{})
      |> Map.get(:machines, [])
      |> List.wrap()
      |> Enum.map(&to_string(Map.get(&1, :node, "")))
      |> Enum.reject(&(&1 == ""))

    ([self_node] ++ connected ++ known)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn name ->
      %{name: name, connected?: name == self_node or name in connected}
    end)
  end

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
  defp line(:needs_you, row, activity), do: activity || ask_line(row)

  # An idle row carries its age in the line rather than only in the right-hand column,
  # because "idle" alone says nothing a reader can act on — how long it has been idle is
  # the whole content of the row. The column is dropped for these rows so the age is not
  # printed twice; `age_in_line?/2` is the one place that decision is made.
  defp line(:settled, %Rail.Row{status: :idle} = row, _activity) do
    case age(row.updated_at) do
      "" -> "idle"
      age -> "idle · #{age}"
    end
  end

  defp line(:settled, row, _activity) do
    case row.error do
      nil -> Rail.outcome(row)
      error -> "#{Rail.outcome(row)} — #{brief(error)}"
    end
  end

  defp line(_at_work, row, activity), do: activity || provider_line(row)

  defp age_in_line?(:settled, %Rail.Row{status: :idle}), do: true
  defp age_in_line?(_group, _row), do: false

  defp ask_line(row) do
    case row.status do
      :awaiting_approval -> "waiting on your answer"
      :idle -> "waiting for your next message"
      _other -> provider_line(row)
    end
  end

  # The newest cell that says what is happening: a tool call, or a loud status line. Read
  # off the projection rather than off the raw ledger so the words are the ones the
  # transcript is showing, and nothing here mints a phrase the corpus does not pin.
  defp activity(%{open: {plane, id}, cells: cells}) when is_list(cells) do
    case Enum.reverse(cells) |> Enum.find_value(&activity_of/1) do
      nil -> %{}
      line -> %{{plane, id} => line}
    end
  end

  defp activity(_assigns), do: %{}

  defp activity_of(%Cell.Tool{} = tool) do
    case tool |> Transcript.Tools.summarise() |> Transcript.ToolSummary.line() do
      "" -> nil
      line -> line
    end
  end

  defp activity_of(%Cell.Exploration{} = cell) do
    "exploring · #{Cell.Exploration.total(cell)} calls"
  end

  defp activity_of(%Cell.Status{label: label}) when label != "", do: label
  defp activity_of(_cell), do: nil

  defp provider_line(row) do
    [row.provider, row.node]
    |> Enum.reject(&is_nil/1)
    |> Enum.map_join(" · ", &to_string/1)
  end

  defp meta_line(nil), do: ""

  defp meta_line(row) do
    [row.provider, row.node, row.workspace]
    |> Enum.reject(&is_nil/1)
    |> Enum.map_join(" · ", &to_string/1)
  end

  # `unrestricted` is the one sandbox posture worth a tag: it is the session that can do
  # anything, and a reader who did not notice would be reading a transcript without
  # knowing what it was allowed to do.
  defp unrestricted?(row, info) do
    options = (info && Map.get(info, :options)) || %{}

    sandbox = Map.get(options, :sandbox_mode) || (row && row.sandbox_mode)

    to_string(sandbox || "") == "unrestricted"
  end

  defp sandbox_word(options, row) do
    case Map.get(options, :sandbox_mode) || (row && row.sandbox_mode) do
      nil -> "not reported"
      mode -> mode |> to_string() |> String.replace("_", " ")
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
