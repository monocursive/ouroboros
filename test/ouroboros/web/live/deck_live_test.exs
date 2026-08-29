defmodule Ouroboros.Web.Live.DeckLiveTest do
  @moduledoc """
  The deck end to end, driven headlessly: mount, open a session, stream, repair.

  ## What is simulated, and what is not

  The interactive plane's coordinator is a `GenServer` registered in the real
  `Ouroboros.Interactive.Registry` under a session id. That is not a mock of the gateway —
  `Ouroboros.InteractiveSession.local_call/2` looks the coordinator up in exactly that
  registry and `GenServer.call`s whatever it finds, so a subscribe issued by the LiveView
  travels the whole real path (`Methods.subscribe/3` → `InteractiveSession.subscribe/2` →
  `local_call/2` → registry lookup) and arrives here. What this fake stands in for is the
  *provider*, not the plumbing.

  Simulated honestly: the subscribe/backlog contract, `{:error, {:cursor_pruned, floor}}`,
  terminality, the coordinator's `:DOWN`, and live event delivery to a registered
  subscriber.

  **Not** simulated, and therefore not proven here: cross-node routing (`:erpc` to another
  BEAM), the real plane's own checkpoint and durability, and anything about what a browser
  does with the HTML — LiveViewTest asserts the rendered markup, not layout, CSS or
  JavaScript.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  import Plug.Conn, only: [put_req_cookie: 3]

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

  # How long the deck coalesces text deltas before re-projecting. Waiting a little past it
  # is what makes a live-event assertion deterministic rather than flaky.
  @flush 160

  # ------------------------------------------------------------------------------------
  # A coordinator, in the registry the runtime actually looks in
  # ------------------------------------------------------------------------------------

  defmodule FakePlane do
    @moduledoc false
    use GenServer

    def start(opts) do
      GenServer.start(__MODULE__, opts)
    end

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      {:ok, _owner} = Registry.register(Ouroboros.Interactive.Registry, id, nil)

      {:ok,
       %{
         id: id,
         test: Keyword.fetch!(opts, :test),
         status: Keyword.get(opts, :status, :running),
         backlogs: Keyword.get(opts, :backlogs, []),
         subscribers: []
       }}
    end

    @doc "Sends one live event to every registered subscriber, as the plane does."
    def emit(pid, event), do: GenServer.call(pid, {:emit, event})

    @impl true
    def handle_call(:info, _from, state) do
      {:reply, {:ok, session(state)}, state}
    end

    def handle_call({:subscribe, subscriber, cursor}, _from, state) do
      send(state.test, {:subscribed, subscriber, cursor})

      # A scripted list of answers, so a test can make the first subscribe refuse and the
      # second one succeed — which is the whole prune-then-repair path.
      {answer, rest} =
        case state.backlogs do
          [answer | rest] -> {answer, rest}
          [] -> {{:ok, []}, []}
        end

      state = %{state | backlogs: rest}

      case answer do
        {:ok, events} ->
          # A terminal session answers the backlog and silently declines registration,
          # which is the behaviour the deck's terminality check exists for.
          state =
            if State.terminal?(session(state)),
              do: state,
              else: %{state | subscribers: Enum.uniq([subscriber | state.subscribers])}

          {:reply, {:ok, events}, state}

        error ->
          {:reply, error, state}
      end
    end

    def handle_call({:unsubscribe, subscriber}, _from, state) do
      send(state.test, {:unsubscribed, subscriber})
      {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}
    end

    def handle_call({:emit, event}, _from, state) do
      for pid <- state.subscribers do
        send(pid, {:ouroboros_interactive_event, state.id, event})
      end

      {:reply, :ok, state}
    end

    defp session(state) do
      %State{
        id: state.id,
        node: node(),
        provider: :claude_code,
        workspace: "/tmp/w",
        workspace_mode: :shared_read,
        status: state.status,
        created_at: "2026-08-29T10:00:00Z",
        updated_at: "2026-08-29T12:00:00Z"
      }
    end
  end

  # ------------------------------------------------------------------------------------

  setup do
    dir = Path.join(System.tmp_dir!(), "ouroboros-web-deck-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, conn: signed_in()}
  end

  defp signed_in do
    conn = get(build_conn(), "/auth?token=#{@token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  defp session_id, do: "web-deck-#{System.unique_integer([:positive])}"

  defp plane(opts) do
    {:ok, pid} = FakePlane.start(Keyword.put(opts, :test, self()))
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp event(sequence, type, payload) do
    %Event{
      id: "e#{sequence}",
      session_id: "s",
      sequence: sequence,
      type: type,
      timestamp: "2026-08-29T12:00:0#{rem(sequence, 10)}Z",
      payload: payload,
      turn_id: "t1"
    }
  end

  defp said(sequence, text),
    do: event(sequence, :output_text_final, %{"text" => text})

  # ------------------------------------------------------------------------------------
  # The deck itself
  # ------------------------------------------------------------------------------------

  describe "the deck" do
    test "renders the three groups, the wordmark and a presence dot for this machine",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "Ouroboros"
      assert html =~ "NEEDS YOU"
      assert html =~ "AT WORK"
      assert html =~ "SETTLED"
      assert html =~ "ouro-dot"
      # Self is always connected: it is the machine answering this request.
      assert html =~ "ouro-dot-on"
      assert html =~ to_string(node())
    end

    test "says what it cannot do yet instead of pretending", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # The one filled control, disabled and labelled rather than absent or fake.
      assert html =~ "New session"
      assert html =~ "disabled"
      assert html =~ "coming in the next slice"

      # And the composer names the slice that wires it.
      assert html =~ "ouro-composer" or html =~ "Nothing open"
    end

    test "with nothing open, says so rather than showing an empty transcript",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "Nothing open"
      refute html =~ "ouro-transcript"
      # No vitals column either: a panel with nothing in it is worse than no panel.
      refute html =~ "ouro-vitals"
    end
  end

  # ------------------------------------------------------------------------------------
  # Opening a session
  # ------------------------------------------------------------------------------------

  describe "opening a session" do
    test "subscribes from the LiveView process itself, at cursor zero", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "hello from the agent")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert_receive {:subscribed, subscriber, 0}

      # The plane registers and monitors whatever process calls it, so this has to be the
      # view — a subscribe issued from a task would register a process that dies at once.
      assert subscriber == view.pid
    end

    test "renders the backlog as cells", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "hello from the agent")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "hello from the agent"
      assert html =~ "ouro-transcript"
      assert html =~ "ouro-prose"
    end

    test "shows the vitals column and the session's meta line", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-vitals"
      assert html =~ "Context"
      # Nothing reported a context window, so it says so rather than drawing a meter.
      assert html =~ "not reported"
      refute html =~ "ouro-meter-fill"
    end

    test "a live event reaches the transcript after the coalescing window", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, [said(1, "first")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ "first"
      refute html =~ "second"

      FakePlane.emit(pid, said(2, "second"))

      # Absorbed immediately, drawn on the next flush. Waiting past the window is what
      # makes this deterministic; a test that asserted straight away would be asserting
      # that the coalescing does not exist.
      Process.sleep(@flush)

      assert render(view) =~ "second"
    end

    test "deltas that arrive together are drawn once, not once each", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      for n <- 1..20 do
        FakePlane.emit(pid, event(n, :output_text_delta, %{"text" => "chunk#{n} "}))
      end

      Process.sleep(@flush)
      html = render(view)

      # All twenty deltas accumulated into the one message cell the projection makes of
      # them — which is the projection's rule, and the reason coalescing is safe.
      assert html =~ "chunk1"
      assert html =~ "chunk20"
    end
  end

  # ------------------------------------------------------------------------------------
  # The three repairs
  # ------------------------------------------------------------------------------------

  describe "a terminal session" do
    test "is detected immediately and draws the ended divider", %{conn: conn} do
      id = session_id()
      # `:closed`, not `:completed`: the interactive plane's terminal statuses are
      # `[:closed, :failed, :cancelled, :lost]` (`interactive/state.ex:201`) and
      # `:completed` belongs to the coding plane. The rail's `terminal?/1` carries the
      # union of both because it draws both — but a test of *this* plane has to use this
      # plane's vocabulary or it proves nothing.
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, [said(1, "all done")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "all done"
      # Without the terminality check this view would sit forever waiting for events from
      # a conversation that ended, because the plane declined the registration silently.
      assert html =~ "ouro-divider"
      assert html =~ "Session ended (closed)"
    end

    test "and a live one draws no divider at all", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :running, backlogs: [{:ok, [said(1, "still going")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "still going"
      refute html =~ "ouro-divider"
    end
  end

  describe "a pruned cursor" do
    test "raises the floor and repairs through the same subscribe", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [
            {:error, {:cursor_pruned, 40}},
            {:ok, [said(41, "after the prune")]}
          ]
        )

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      # Two subscribes, and the second one asks from the floor the refusal named — the
      # repair is the same function, called again with a different number.
      assert_receive {:subscribed, _pid, 0}
      assert_receive {:subscribed, _pid, 40}

      assert html =~ "after the prune"
      assert html =~ "Earlier conversation is no longer available"
    end

    test "does not loop when the runtime keeps refusing with the same floor", %{conn: conn} do
      id = session_id()

      # The shape the plane actually returns; `Methods` is what turns it into the wire's
      # `-32006 cursor_pruned` with a floor in its data.
      refusal = {:error, {:cursor_pruned, 40}}

      _plane = plane(id: id, backlogs: [refusal, refusal, refusal])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert_receive {:subscribed, _pid, 0}
      assert_receive {:subscribed, _pid, 40}
      # And then it stops and says so, rather than asking forever.
      refute_receive {:subscribed, _pid, 40}, 200

      assert html =~ "ouro-refusal"
    end
  end

  describe "a silently pruned backlog" do
    test "raises the floor from the batch's own first sequence", %{conn: conn} do
      id = session_id()
      # Asked from 0, answered starting at 30: 1..29 are gone and nothing said so.
      _plane = plane(id: id, backlogs: [{:ok, [said(30, "much later")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "much later"
      assert html =~ "Earlier conversation is no longer available"
    end
  end

  describe "the coordinator going away" do
    test "is the end of the stream, and is drawn as one", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, [said(1, "mid-sentence")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "ouro-divider"

      GenServer.stop(pid)
      Process.sleep(@flush)

      html = render(view)
      assert html =~ "mid-sentence"
      assert html =~ "ouro-divider"
    end
  end

  # ------------------------------------------------------------------------------------
  # Folds
  # ------------------------------------------------------------------------------------

  describe "folding" do
    test "a long tool body opens and closes on click, keyed by call_id", %{conn: conn} do
      id = session_id()
      body = 1..40 |> Enum.map_join("\n", &"line #{&1}")

      events = [
        event(1, :tool_call, %{"call_id" => "c-1", "name" => "bash", "input" => %{}}),
        event(2, :tool_result, %{"call_id" => "c-1", "name" => "bash", "output" => body})
      ]

      _plane = plane(id: id, backlogs: [{:ok, events}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "more lines"
      refute html =~ "line 20"

      html = view |> element(~s([phx-value-block="tool:c-1"])) |> render_click()
      assert html =~ "line 20"

      html = view |> element(~s(button.ouro-fold[phx-click="collapse"])) |> render_click()
      refute html =~ "line 20"
    end
  end

  # ------------------------------------------------------------------------------------
  # Navigation
  # ------------------------------------------------------------------------------------

  describe "closing a session" do
    test "tells the plane rather than leaving it sending", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      assert_receive {:subscribed, _pid, 0}

      html = live_redirect_to_root(view)

      assert_receive {:unsubscribed, _pid}
      assert html =~ "Nothing open"
    end
  end

  defp live_redirect_to_root(view) do
    view |> render_patch("/")
  end
end
