defmodule Ouroboros.Web.NeedsYou do
  @moduledoc """
  Which sessions have just *entered* the needs-you group, and the hook that lets any page
  say so.

  ## Why this is not the deck's alone any more

  The bell is in the one top bar, so it is on `/new`, `/settings`, `/status` and `/audit`
  as well as on the deck. Until this module existed, `push_event("needs-you", …)` was
  written in `DeckLive` and nowhere else, so a bell switched on while reading `/audit`
  asked the browser for notification permission and then never rang — a control promising
  something the page it sat on could not do. `attach_hook/4` here gives every spoke the
  same three-second `interactive.list` poll and the same edge computation, so the promise
  is kept wherever the bar is drawn.

  The deck does **not** use the hook. It holds a live subscription and recomputes on every
  redraw, so its bell fires the moment a request arrives rather than up to three seconds
  later; what it shares is this module's arithmetic, below, so there is one definition of
  "has just entered the group" rather than two that can drift.

  ## The edge, and what it is keyed on

  `sessions/2` returns one entry per needs-you row, keyed by the thing that identifies the
  *ask* wherever one is known: the `request_id` for a session whose requests the caller is
  holding, and `<plane>:<id>` for every other row, because `interactive.list` carries no
  request id. `group` is always the session, because that is what a banner is *about* —
  `app.js` hands it to the browser as the notification tag, so three asks on one session
  replace each other into one banner instead of stacking three that say the same words.

  A key that leaves the group is forgotten, so a session that needs a person again later
  rings again. A key still in the group is never re-pushed. `app.js` keeps its own
  permanent set on top of this, because a remount re-seeds these assigns and a repair is
  not a new request.
  """

  import Phoenix.Component, only: [assign: 3]
  import Phoenix.LiveView, only: [attach_hook: 4, connected?: 1, push_event: 3]

  alias Ouroboros.Web.Call
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Rail

  @poll_interval 3_000

  @typedoc "One needs-you entry, as `app.js` reads it."
  @type entry :: %{key: String.t(), group: String.t(), title: String.t()}

  # ------------------------------------------------------------------------------------
  # The arithmetic, shared with the deck
  # ------------------------------------------------------------------------------------

  @doc """
  Every session in the needs-you group, one entry per ask.

  Options, all of which only the deck has: `:pending` (the per-session unanswered count
  the rail triages on), `:approvals` (the requests the caller holds for `:open`),
  `:answered` (request ids already responded to) and `:open` (the `{plane, id}` the
  caller is subscribed to). With none of them this is the view from a page that has only
  `interactive.list`: one entry per row, keyed by the session.
  """
  @spec sessions([Rail.Row.t()], keyword()) :: [entry()]
  def sessions(rows, opts \\ []) when is_list(rows) and is_list(opts) do
    pending = Keyword.get(opts, :pending, %{})
    approvals = Keyword.get(opts, :approvals, [])
    answered = Keyword.get(opts, :answered, MapSet.new())
    open = Keyword.get(opts, :open)

    rows
    |> Rail.triaged(pending)
    |> Enum.filter(&(&1.group == :needs_you))
    |> Enum.flat_map(&entries(&1.row, open, approvals, answered))
  end

  defp entries(row, open, approvals, answered) do
    group = "#{row.plane}:#{row.id}"
    title = Rail.title(row)

    case {open, approvals} do
      {{plane, id}, [_first | _rest]} when {plane, id} == {row.plane, row.id} ->
        # A request this caller has answered is one nobody needs to be told about, whether
        # the answer came from a click or from automation.
        approvals
        |> Enum.reject(&MapSet.member?(answered, &1.request_id))
        |> Enum.map(&%{key: &1.request_id, group: group, title: title})

      _not_the_open_session ->
        [%{key: group, group: group, title: title}]
    end
  end

  @doc "The keys of a set of entries, which is what an announcement is remembered by."
  @spec keys([entry()]) :: MapSet.t()
  def keys(entries) when is_list(entries), do: MapSet.new(entries, & &1.key)

  @doc "The entries whose key has not been announced yet — the edge, and nothing else."
  @spec fresh([entry()], MapSet.t()) :: [entry()]
  def fresh(entries, announced) when is_list(entries),
    do: Enum.reject(entries, &MapSet.member?(announced, &1.key))

  # ------------------------------------------------------------------------------------
  # The hook every spoke attaches
  # ------------------------------------------------------------------------------------

  @doc "How often a spoke asks. The deck's own poll runs at the same cadence."
  @spec poll_interval() :: pos_integer()
  def poll_interval, do: @poll_interval

  @doc """
  `on_mount {Ouroboros.Web.NeedsYou, :bell}` — poll for the needs-you edge and push it.

  What was already waiting when the page opened is **recorded rather than announced**, so
  a page opened in a background tab does not post one banner per pending approval on
  arrival and a reconnect does not do it again. Only the edge after that is pushed.

  A refused or unreadable `interactive.list` leaves the announced set alone and rings
  nothing: a page that cannot see the group must not claim it is empty.
  """
  def on_mount(:bell, _params, _session, socket) do
    socket = assign(socket, :needs_you_announced, MapSet.new())

    socket =
      attach_hook(socket, :needs_you, :handle_info, fn
        :needs_you_poll, socket -> {:halt, socket |> announce() |> schedule()}
        _message, socket -> {:cont, socket}
      end)

    if connected?(socket), do: {:cont, socket |> seed() |> schedule()}, else: {:cont, socket}
  end

  defp schedule(socket) do
    Process.send_after(self(), :needs_you_poll, @poll_interval)
    socket
  end

  defp seed(socket) do
    case list(socket) do
      {:ok, rows} -> assign(socket, :needs_you_announced, rows |> sessions() |> keys())
      :unreadable -> socket
    end
  end

  defp announce(socket) do
    case list(socket) do
      {:ok, rows} ->
        entries = sessions(rows)
        edge = fresh(entries, socket.assigns.needs_you_announced)
        socket = assign(socket, :needs_you_announced, keys(entries))

        if edge == [], do: socket, else: push_event(socket, "needs-you", %{sessions: edge})

      :unreadable ->
        socket
    end
  end

  defp list(socket) do
    scope = Config.for_endpoint(socket.endpoint).scope

    case Call.call(scope, "interactive.list", %{}, session: socket.assigns[:web_session]) do
      {:ok, sessions} when is_list(sessions) ->
        {:ok, Enum.map(sessions, &Rail.from_interactive/1)}

      _refused_or_unreadable ->
        :unreadable
    end
  end
end
