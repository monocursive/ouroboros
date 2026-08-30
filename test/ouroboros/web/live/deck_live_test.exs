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

  The operator verbs travel the same whole path. `interactive.send_message` reaches
  `{:send_turn, mode, turn_id, input, opts}` here only after
  `Ouroboros.Web.Call` → `Methods.invoke/2` → the closed-envelope validator →
  `InteractiveSession` → the registry, so an envelope assertion made against what arrives
  at this GenServer is an assertion the gateway accepted it. A params shape the table
  refuses never gets here at all; it comes back as `-32602` and the test sees a refusal
  instead of a message.

  **Not** simulated, and therefore not proven here: cross-node routing (`:erpc` to another
  BEAM), the real plane's own checkpoint and durability, and anything about what a browser
  does with the HTML — LiveViewTest asserts the rendered markup, not layout, CSS or
  JavaScript. In particular Enter-to-send, the textarea's autosizing, and
  `phx-disable-with` are `app.js` and the browser's, and are on the live-pass list rather
  than proven here.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Mix.Tasks.Ouroboros.Gateway.Golden
  alias Ouroboros.Interactive.Event
  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Transcript
  alias Ouroboros.Web.Transcript.Cell

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

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
         # What the session *reports* about itself, which is what makes a picker present
         # or absent. Empty by default, because the absent case is the one a defaulted
         # fixture would quietly stop testing.
         options: Keyword.get(opts, :options, %{}),
         workspace: Keyword.get(opts, :workspace, "/tmp/w"),
         # A scripted answer per verb, popped one at a time: `[{:error, …}, {:ok, …}]` is
         # how a refusal-then-retry is written without a mock framework.
         answers: Keyword.get(opts, :answers, %{}),
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

    # The operator verbs. Each one reports what arrived and answers whatever the test
    # scripted, so the assertion is on the params the gateway let through rather than on a
    # recorded call this file invented the shape of.
    def handle_call({:send_turn, mode, turn_id, input, opts}, _from, state) do
      send(state.test, {:sent, mode, turn_id, input, opts})
      answer(state, :turn, {:ok, %{turn_id: turn_id, status: :running}})
    end

    def handle_call({:respond_approval, request_id, response}, _from, state) do
      send(state.test, {:responded, request_id, response})
      answer(state, :approval, {:ok, %{request_id: request_id}})
    end

    def handle_call({:interrupt, turn}, _from, state) do
      send(state.test, {:interrupted, turn})
      answer(state, :interrupt, {:ok, %{interrupted: true}})
    end

    def handle_call({:configure, changes}, _from, state) do
      send(state.test, {:configured, changes})
      answer(state, :configure, {:ok, %{changed: changes}})
    end

    defp answer(state, key, default) do
      case Map.get(state.answers, key, []) do
        [scripted | rest] ->
          {:reply, scripted, %{state | answers: Map.put(state.answers, key, rest)}}

        [] ->
          {:reply, default, state}
      end
    end

    defp session(state) do
      %State{
        id: state.id,
        node: node(),
        provider: :claude_code,
        workspace: state.workspace,
        workspace_mode: :shared_read,
        status: state.status,
        options: state.options,
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

  # A durable row, so a test of the *rail* is testing the list the deck actually draws
  # rather than a fixture beside it. `interactive.list` reads the store and nothing else.
  #
  # The store is global to the node and this row is real, which makes the cleanup part of
  # the fixture rather than tidiness. Two rules, both of which this file got wrong first:
  #
  #   * the workspace has to exist. `Ouroboros.Workspace.Manager` recovers every live
  #     session's lease at boot and refuses to start on a path that is not there, so a row
  #     naming a directory nobody made takes the *next* application restart in the suite
  #     down with it — and `Ouroboros.ApplicationRecoveryTest` restarts the application.
  #   * the row has to be closed before it can be removed. `Store.delete/1` refuses a
  #     session that is not terminal, so a plain delete leaves the row exactly where it
  #     would do that damage.
  defp listed(id, opts \\ []) do
    workspace =
      Keyword.get_lazy(opts, :workspace, fn ->
        dir =
          Path.join(System.tmp_dir!(), "ouroboros-web-ws-#{System.unique_integer([:positive])}")

        File.mkdir_p!(dir)
        on_exit(fn -> File.rm_rf(dir) end)
        dir
      end)

    session = %State{
      id: id,
      node: node(),
      # A title without a source is not a valid record — `valid_title?/1` refuses the pair
      # rather than either half — so the two travel together or not at all.
      title: Keyword.get(opts, :title),
      title_source: if(Keyword.get(opts, :title), do: :human),
      provider: :claude_code,
      workspace: workspace,
      workspace_mode: :shared_read,
      status: Keyword.get(opts, :status, :running),
      # `runtime_exposure: false` is what makes a session with no runtime snapshot a
      # *valid* durable record rather than an unrequestable one — the store refuses
      # anything else, and this row exists to be listed, not to be resumed.
      options: opts |> Keyword.get(:options, %{}) |> Map.put(:runtime_exposure, false),
      created_at: "2026-08-29T10:00:00Z",
      updated_at: "2026-08-29T12:00:00Z"
    }

    :ok = Ouroboros.Interactive.Store.create(session)

    on_exit(fn ->
      :ok = Ouroboros.Interactive.Store.put(%{session | status: :closed})
      :ok = Ouroboros.Interactive.Store.delete(id)
    end)

    session
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

  defp asked(sequence, request_id, payload),
    do: %{event(sequence, :approval_requested, payload) | request_id: request_id}

  defp answered(sequence, request_id, decision),
    do: %{event(sequence, :approval_resolved, %{"decision" => decision}) | request_id: request_id}

  # One corpus approval, as an event this session asked. The payload is the fixture's own
  # bytes — the same object `Ouroboros.Web.CorpusParityTest` and the Rust corpus read — so
  # a card asserted against it is asserted against the shape both toolchains are locked to,
  # not against a payload this file made up.
  defp corpus(name, sequence, request_id) do
    payload =
      name
      |> Golden.path()
      |> File.read!()
      |> JSON.decode!()
      |> get_in(["params", "event", "payload"])

    asked(sequence, request_id, payload)
  end

  # The permission engine runs in this environment and `permissions.add` really writes, so
  # a test that exercises the remember row takes its rules back out again. Matched on the
  # directory's own name rather than the path handed in: the engine stores the resolved
  # path, and on this platform `/tmp` resolves through a symlink.
  defp rules_for(workspace) do
    leaf = Path.basename(workspace)

    case Ouroboros.Control.Permissions.list(scope: :workspace) do
      {:ok, rules} -> Enum.filter(rules, &String.ends_with?(&1.workspace || "", leaf))
      _unavailable -> []
    end
  end

  defp forget_rules(workspace) do
    for rule <- rules_for(workspace) do
      Ouroboros.Control.Permissions.remove(:workspace, rule.id)
    end
  end

  defp submit(view, text) do
    view |> form("#composer", %{"message" => text}) |> render_submit()
  end

  defp type(view, text) do
    view |> form("#composer", %{"message" => text}) |> render_change()
  end

  defp occurrences(haystack, needle),
    do: haystack |> String.split(needle) |> length() |> Kernel.-(1)

  # The events of one ordinary settling turn: deltas, then the notes and the usage row
  # that land between the last delta and the final text.
  defp settling_turn do
    [
      event(1, :output_text_delta, %{"text" => "The answer "}),
      event(2, :output_text_delta, %{"text" => "is 42."}),
      event(3, :provider_event, %{"kind" => "compaction"}),
      event(4, :usage, %{"input_tokens" => 10, "output_tokens" => 5}),
      event(5, :output_text_final, %{"text" => "The answer is 42."}),
      event(6, :turn_completed, %{})
    ]
  end

  # What one `project/1` pass over those events produces, so a live-path assertion can be
  # written against the projection itself rather than against a number somebody would have
  # to keep in step with it.
  defp projected(events) do
    events
    |> Enum.map(&%Ouroboros.Web.Transcript.Entry.Event{event: &1})
    |> Ouroboros.Web.Transcript.project()
  end

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

      # The one filled control now leads to the form's own page, and the presence
      # dots to the machines page — real links whose pages land with their own
      # slices and 404 honestly until then.
      assert html =~ "New session"
      assert html =~ ~s(href="/new")
      assert html =~ ~s(href="/machines")

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
  # Needs-you notifications (W8)
  #
  # The server half only. Three of the four rules that decide whether a banner actually
  # appears — the bell being on, the tab being hidden, the browser having granted
  # permission — are facts about a browser and live in `app.js`, which nothing in this tree
  # executes. What is asserted here is the one rule the server owns: *which* sessions have
  # just started needing somebody, and that it says so exactly once each.
  #
  # UNVERIFIED by this file: `document.hidden` gating, the permission re-check, the
  # `new Notification` call, and that clicking one focuses the tab.
  # ------------------------------------------------------------------------------------

  describe "needs-you notifications" do
    test "what was already waiting when the page opened is not announced", %{conn: conn} do
      # Otherwise a deck opened in a background tab posts one banner per pending approval
      # on arrival, and every reconnect does it again.
      id = session_id()
      _row = listed(id, status: :awaiting_approval)

      {:ok, view, html} = live(conn, "/")

      assert html =~ id
      refute_push_event(view, "needs-you", %{}, 50)
    end

    test "a session that enters the group is announced once, by name", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      # Nothing needed anybody when this page opened.
      refute_push_event(view, "needs-you", %{}, 50)

      id = session_id()
      _row = listed(id, status: :awaiting_approval, title: "Rewire the listener")

      poll(view)

      assert_push_event(view, "needs-you", %{sessions: sessions})
      assert [%{key: key, group: group, title: "Rewire the listener"}] = sessions
      assert key == "interactive:#{id}"

      # The group is what a banner is about; `app.js` hands it to the browser as the
      # notification tag so two asks on one session do not stack two banners.
      assert group == "interactive:#{id}"

      # And not again while it is still waiting. A standing ask is one notification.
      poll(view)
      refute_push_event(view, "needs-you", %{}, 50)
    end

    test "a session that leaves the group and comes back rings again", %{conn: conn} do
      id = session_id()
      row = listed(id, status: :awaiting_approval)

      {:ok, view, _html} = live(conn, "/")
      poll(view)
      refute_push_event(view, "needs-you", %{}, 50)

      # Answered: out of the group.
      :ok = Ouroboros.Interactive.Store.put(%{row | status: :running})
      poll(view)

      # Asked again: the same session, a new ask, and a person who should hear about it.
      :ok = Ouroboros.Interactive.Store.put(%{row | status: :awaiting_approval})
      poll(view)

      assert_push_event(view, "needs-you", %{sessions: [%{key: key}]})
      assert key == "interactive:#{id}"
    end

    test "a row that is merely running is never announced", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      _row = listed(session_id(), status: :running)
      poll(view)

      refute_push_event(view, "needs-you", %{}, 50)
    end

    test "the open session is keyed by request id, not by session id", %{conn: conn} do
      # The one place a request id exists on this side of the wire: the view is holding the
      # requests for the session it has open. Everything else is keyed `<plane>:<id>`,
      # because `interactive.list` does not carry one.
      id = session_id()
      _row = listed(id, status: :running)

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, [asked(1, "req-web-bell", %{"kind" => "command", "command" => "ls"})]}]
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert_push_event(view, "needs-you", %{sessions: [session]})
      assert session.key == "req-web-bell"

      # And its group is still the session, so a second ask on the same conversation
      # replaces this banner instead of stacking beside it.
      assert session.group == "interactive:#{id}"
    end

    test "a request auto-approve answered never rings", %{conn: conn} do
      # Auto-approve runs first and records the request in `:answered` *before* the call
      # goes out, so the bell that runs after it has nothing left to say. A banner for
      # something the page already handled would be the worst kind of noise.
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      FakePlane.emit(pid, corpus("event_approval_requested_permission", 1, "r1"))
      flush(view)

      assert_receive {:responded, "r1", %{actor: :automation}}
      refute_push_event(view, "needs-you", %{}, 50)
    end
  end

  # The list cadence, driven rather than waited for: the deck polls every three seconds and
  # a test that slept for one would be three seconds slower for every case here.
  defp poll(view) do
    send(view.pid, :poll)
    render(view)
  end

  # The coalescing clock, driven the same way. This file used to sleep past the deck's
  # 80ms window instead, and that flaked under full-suite load: the window opens when the
  # view *absorbs* the event, so a nap measured from the emit runs out before the timer
  # was even set whenever the view sits unscheduled for a while first. Driving it needs no
  # clock at all — `FakePlane.emit/2` is a call the plane answers only after sending to
  # its subscribers, so the event is queued on the view before emit returns, a :flush
  # sent here queues behind it, and `render/1` pings the view before reading. Mailbox
  # order is the whole guarantee. The real timer still fires afterwards; a :flush with
  # nothing new to draw is the deck's ordinary cadence, not an artifact of the test.
  defp flush(view) do
    send(view.pid, :flush)
    render(view)
  end

  defp assert_eventually(fun, attempts \\ 200)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
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

    # R3/D10. The replay badge on the web's focused pane. Three renders, because the three
    # states say different things and the one that matters most is the third: a session
    # whose provider declared nothing is "—", not "no". Deliberately *not* a rail-row
    # badge — `Rail.Row` carries no capabilities field and REPLAY.md §7.3 records that as
    # a deferred divergence rather than a gap nobody noticed.
    test "the Replay vital reports what the session's capabilities say", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{capabilities: %{replay: true, fork: :native}}
        )

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "Replay"
      assert html =~ ~r/Replay<\/dt>\s*<dd[^>]*>\s*yes/
    end

    test "a session on a provider that cannot replay says so rather than staying blank",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, []}], options: %{capabilities: %{replay: false}})

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~r/Replay<\/dt>\s*<dd[^>]*>\s*no/
    end

    test "a session whose provider declared nothing is unanswered, not unreplayable",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{})

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      # "not answered" and "not replayable" are different facts, and the vital that spelled
      # them the same would be exactly the lie this capability exists to prevent.
      assert html =~ ~r/Replay<\/dt>\s*<dd[^>]*>\s*—/
    end

    test "a live event reaches the transcript after the coalescing window", %{conn: conn} do
      id = session_id()

      # Sentinels that embed the session id, because the page is more than the transcript:
      # the rail beside it lists the node's real stores, and by the time a full-suite run
      # reaches this file those hold other tests' leftovers — ids like "second-delegation",
      # objectives like "second objective". A page-wide match on a bare "second" is a match
      # against all of that (seed 486710 failed exactly there, on the mount refute below).
      first = "first delta of #{id}"
      second = "second delta of #{id}"
      pid = plane(id: id, backlogs: [{:ok, [said(1, first)]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ first
      refute html =~ second

      FakePlane.emit(pid, said(2, second))

      # Absorbed immediately, drawn on the next flush — which the test delivers rather
      # than waits for. Asserting straight away would be asserting that the coalescing
      # does not exist; sleeping past the window was a bet that the view absorbed the
      # event within 80ms of the emit, and the timer only starts at the absorb, so
      # full-suite load lost it.
      assert flush(view) =~ second
    end

    test "a later event that rewrites an earlier cell rewrites it in place", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      # An approval resolution does not append a cell — it rewrites the status cell the
      # request made, found by `request_id`. That is the case the delta path has to get
      # right: the changed cell is not the last one, and the ones after it must not move.
      FakePlane.emit(pid, said(1, "before the ask"))

      FakePlane.emit(
        pid,
        %{
          event(2, :approval_requested, %{"kind" => "permission", "command" => "rm -rf /"})
          | request_id: "req-1"
        }
      )

      asked = flush(view)
      assert asked =~ "before the ask"

      FakePlane.emit(
        pid,
        %{
          event(3, :approval_resolved, %{"decision" => "denied"})
          | request_id: "req-1"
        }
      )

      resolved = flush(view)

      # The earlier cell changed, the earlier-still one did not, and nothing duplicated.
      assert resolved =~ "before the ask"
      assert resolved != asked
      assert length(Regex.scan(~r/before the ask/, resolved)) == 1
    end

    test "a settling turn does not add a stream row the projection did not ask for",
         %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      events = settling_turn()
      {deltas, rest} = Enum.split(events, 2)

      for e <- deltas, do: FakePlane.emit(pid, e)

      assert occurrences(flush(view), "The answer is 42.") == 1

      for e <- rest, do: FakePlane.emit(pid, e)

      html = flush(view)
      cells = projected(events)

      # The live path must render exactly what one `project/1` pass over the same events
      # produces: no extra row, no stale row, no row the patch forgot to remove. Asserted
      # against the projection rather than against a literal, so it stays true when the
      # projection changes — including when the duplicate this pins is fixed upstream.
      assert occurrences(html, ~s(data-phx-stream)) == length(cells)

      assert occurrences(html, "The answer is 42.") ==
               Enum.count(cells, &match?(%Cell.Message{speaker: :agent}, &1))
    end

    # A live browser pass found the agent's answer rendered twice after a turn settled.
    # It was never a stream-keying fault — the test above proves the live path draws
    # exactly the cells `project/1` returns — so the fix went into the projection on both
    # sides, guarded by `a_final_settles_the_draft_a_note_flushed_early` in
    # `corpus_parity_test.exs` and its Rust twin.
    #
    # This stays as the deck's own end of that contract: whatever the projection does, the
    # answer reaches an operator once.
    test "a settled answer is drawn once, whatever arrived between the draft and its final" do
      cells = projected(settling_turn())
      answers = Enum.filter(cells, &match?(%Cell.Message{speaker: :agent}, &1))

      assert length(answers) == 1

      assert hd(answers).text == "The answer is 42."
      refute hd(answers).streaming
    end

    test "deltas that arrive together are drawn once, not once each", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      for n <- 1..20 do
        FakePlane.emit(pid, event(n, :output_text_delta, %{"text" => "chunk#{n} "}))
      end

      html = flush(view)

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
    test "resubscribes to a restarted coordinator without ending the stream", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, [said(1, "mid-sentence")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "ouro-divider"

      GenServer.stop(pid)
      refute render(view) =~ "ouro-divider"

      _replacement = plane(id: id, backlogs: [{:ok, [said(2, "after restart")]}])
      send(view.pid, :poll)

      assert_receive {:subscribed, _subscriber, 1}
      assert_eventually(fn -> render(view) =~ "after restart" end)
      refute render(view) =~ "ouro-divider"
      assert render(view) =~ "mid-sentence"
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

  # ------------------------------------------------------------------------------------
  # W4 — the composer
  # ------------------------------------------------------------------------------------

  describe "the composer" do
    test "sends an idle session's draft as a plain-string input", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      submit(view, "ship it")

      # The common case of the closed envelope: `input` is the prompt itself, not an
      # object with a `prompt` key. A caller-owned turn id rides beside it.
      assert_receive {:sent, :message, turn_id, "ship it", []}
      assert is_binary(turn_id)
    end

    test "queues into a running turn with the follow-up verb", %{conn: conn} do
      id = session_id()
      # Idle by its polled status, so the verb can only have come from the ledger.
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      FakePlane.emit(pid, event(1, :turn_started, %{}))

      # The button says what will happen before it happens.
      assert flush(view) =~ "Queue"

      submit(view, "and also this")
      assert_receive {:sent, :follow_up, _turn_id, "and also this", []}
    end

    test "a completed turn puts the session back on the sending verb", %{conn: conn} do
      id = session_id()
      # Still `:running` by its polled status: the ledger is the fresher evidence and this
      # is where that matters, because the status poll is three seconds behind.
      pid = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      FakePlane.emit(pid, event(2, :turn_completed, %{}))
      flush(view)

      submit(view, "next")
      assert_receive {:sent, :message, _turn_id, "next", []}
    end

    test "takes the runtime's correction when it names the queueing verb", %{conn: conn} do
      id = session_id()

      # The plane's own busy shape. `Methods` turns it into the refusal that carries
      # `retry_with: "interactive.follow_up"` and `outcome: "not_dispatched"`.
      _plane =
        plane(
          id: id,
          status: :idle,
          backlogs: [{:ok, []}],
          answers: %{turn: [{:error, {:turn_dispatch_failed, :busy}}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      html = submit(view, "squeeze this in")

      assert_receive {:sent, :message, first, "squeeze this in", []}
      assert_receive {:sent, :follow_up, second, "squeeze this in", []}

      # Nothing was created by the refused attempt, so the same caller-owned id is reused
      # rather than a second one minted.
      assert first == second
      refute html =~ "ouro-composer-refusal"
    end

    test "keeps the draft and renders the refusal in the runtime's own words", %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, status: :idle, backlogs: [{:ok, []}], answers: %{turn: [{:error, :nope}]})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      html = submit(view, "a draft worth keeping")

      assert html =~ "the runtime refused the call"
      # The one thing an operator cannot get back is what they typed.
      assert html =~ "a draft worth keeping"
    end

    test "an empty draft is refused here rather than at the runtime", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      html = submit(view, "   ")

      assert html =~ "write a message before sending"
      refute_receive {:sent, _mode, _turn, _input, _opts}, 100
    end

    test "a second click of the same words is the same turn", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      submit(view, "again")
      submit(view, "again")

      assert_receive {:sent, :message, first, "again", []}
      assert_receive {:sent, :message, second, "again", []}

      # Not deduplicated here — the runtime's `{id, input, turn_id}` idempotency is what
      # collapses them, and this is the client's half of that bargain.
      assert first == second
    end

    test "typing between two sends makes them two turns", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      submit(view, "again")
      type(view, "again")
      submit(view, "again")

      assert_receive {:sent, :message, first, "again", []}
      assert_receive {:sent, :message, second, "again", []}
      assert first != second
    end

    test "interrupts the running turn", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "Interrupt"

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      assert flush(view) =~ "Interrupt"

      view |> element("button", "Interrupt") |> render_click()

      # `:active` is the plane's word for "whichever turn is running now", which is the
      # only thing this button can mean.
      assert_receive {:interrupted, :active}
    end

    test "draws the durable queue depth the runtime published", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "ouro-chip"

      FakePlane.emit(pid, event(1, :queue_changed, %{"queued_turns" => 2}))
      assert flush(view) =~ "2 queued"

      # The runtime's own count, so it comes back down when the runtime says so rather
      # than when this page thinks a turn was taken. Asserted on the chip's class, because
      # the projection has its own sentence about the queue in the transcript above and
      # the two must not be confused for each other.
      FakePlane.emit(pid, event(2, :queue_changed, %{"queued_turns" => 0}))
      refute flush(view) =~ "ouro-chip"
    end

    test "a terminal session takes no messages and says so", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, []}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "takes no further messages"
      refute html =~ ~s(id="composer")
    end
  end

  # ------------------------------------------------------------------------------------
  # W4 — the pickers
  # ------------------------------------------------------------------------------------

  describe "the sandbox picker" do
    test "is absent when the session reported no posture", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{})

      {:ok, _html_view, html} = live(conn, "/s/interactive/#{id}")

      # Absent, not defaulted: a picker showing `workspace_write` because nothing said
      # otherwise would be this page inventing a security posture.
      refute html =~ "Sandbox ·"
      # The thinking picker is a preference, not a permission, so it is always offered —
      # with the honest label for having been told nothing.
      assert html =~ "Thinking · Default"
    end

    test "is present, marked and amber where the session reported unrestricted",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{sandbox_mode: :unrestricted})

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "Sandbox · unrestricted"
      assert html =~ "ouro-picker-warn"
      assert html =~ "ouro-picker-on"
    end

    test "configures through the closed envelope and does not move the mark itself",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{sandbox_mode: :read_only})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html =
        view
        |> element(~s(button[phx-value-field="sandbox_mode"][phx-value-choice="unrestricted"]))
        |> render_click()

      assert_receive {:configured, %{sandbox_mode: :unrestricted}}

      # The session still reports `read_only`, so the label still says `read_only`. The
      # mark follows the re-read, never the click.
      assert html =~ "Sandbox · read only"
      refute html =~ "Sandbox · unrestricted"
    end

    test "renders a configure refusal verbatim", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{sandbox_mode: :read_only},
          answers: %{configure: [{:error, {:unavailable, "this transport cannot change that"}}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html =
        view
        |> element(~s(button[phx-value-field="sandbox_mode"][phx-value-choice="unrestricted"]))
        |> render_click()

      assert html =~ "this transport cannot change that"
    end

    test "the thinking picker sends only what the envelope accepts", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{reasoning_effort: :low})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ "Thinking · low"

      view
      |> element(~s(button[phx-value-field="reasoning_effort"][phx-value-choice="high"]))
      |> render_click()

      assert_receive {:configured, %{reasoning_effort: :high}}

      # `default` is a label for having been told nothing, never a value to send: the
      # envelope accepts `low`, `medium` and `high` and nothing else.
      refute html =~ ~s(phx-value-choice="default")
    end
  end

  # ------------------------------------------------------------------------------------
  # W5 — the approval card
  # ------------------------------------------------------------------------------------

  describe "the approval card" do
    test "draws a permission's command, cwd, reason and rule and nothing else",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-approval"
      assert html =~ "git push --force origin main"
      assert html =~ "/srv/repo"
      assert html =~ "no permission rule engine is configured on this node"
      assert html =~ "Bash(git push *)"

      # Sections this payload does not carry are simply not there.
      refute html =~ "ouro-approval-diff"
      refute html =~ "ouro-approval-edits"
      refute html =~ "ouro-approval-subagent"
      refute html =~ "ouro-approval-locations"
    end

    test "offers the four the envelope accepts when the provider offered none",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      for label <- ["Allow once", "Allow for session", "Deny once", "Deny for session"] do
        assert html =~ label
      end
    end

    test "names the machine a subagent asked from, because it is not this one",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_subagent", 1, "r1")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "asked by subagent audit the parser (task-subagent-000000000001)"
      assert html =~ "ouroboros@worker"
      # `toolCall.locations` is absent here; the payload's own `paths` is not that field
      # and is not drawn as if it were.
      refute html =~ "ouro-approval-locations"
    end

    test "a sandbox escalation wears the warning tone", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, [corpus("event_approval_requested_sandbox_escalation", 1, "r1")]}]
        )

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-approval-warn"
      assert html =~ "sandbox escalation"
      assert html =~ "cargo build --release"
    end

    test "a plan exit offers its own three choices and none of the four", %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_plan_exit", 1, "r1")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "Yes, auto-accept edits"
      assert html =~ "Yes, manual approvals"
      assert html =~ "No, keep planning"
      assert html =~ "Land the golden corpus before the renderer."
      refute html =~ "Allow for session"
    end

    test "a diff on the request is drawn with the transcript's own diff renderer",
         %{conn: conn} do
      id = session_id()

      request =
        asked(1, "r1", %{
          "kind" => "write",
          "tool_call" => %{"name" => "edit", "cwd" => "/srv/repo"},
          "diff" => """
          --- a/lib/one.ex
          +++ b/lib/one.ex
          @@ -1,2 +1,2 @@
          -old
          +new
           kept
          """
        })

      _plane = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-approval-diff"
      assert html =~ "lib/one.ex"
      # Counted from the hunk body, which is the whole reason the card reuses the
      # transcript's parse rather than computing a second one.
      assert html =~ "+1"
      assert html =~ "−1"
    end

    test "an ACP edit block is described rather than re-derived into a patch",
         %{conn: conn} do
      id = session_id()

      request =
        asked(1, "r1", %{
          "kind" => "write",
          "tool_call" => %{
            "name" => "edit",
            "locations" => [%{"path" => "/srv/repo/lib/one.ex"}],
            "content" => [
              %{
                "type" => "diff",
                "path" => "lib/one.ex",
                "oldText" => "old",
                "newText" => "newer"
              }
            ]
          }
        })

      _plane = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "lib/one.ex · update · 3 → 5 bytes"
      assert html =~ "/srv/repo/lib/one.ex"
    end

    test "an option this build cannot map is text, never a button", %{conn: conn} do
      id = session_id()

      request =
        asked(1, "r1", %{
          "kind" => "permission",
          "tool_call" => %{"name" => "bash", "command" => "ls"},
          "options" => [
            %{"optionId" => "a", "name" => "Sure", "kind" => "allow_once"},
            %{"optionId" => "z", "name" => "Do something novel", "kind" => "teleport"}
          ]
        })

      _plane = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "Do something novel — this build cannot map this option onto an answer"
      refute html =~ ~s(phx-value-option="1")

      view |> element(~s(button[phx-value-option="0"])) |> render_click()

      # The locked decision table's answer for `allow_once`, and nothing the label implied.
      assert_receive {:responded, "r1", %{decision: :approve, scope: :once}}
    end
  end

  # ------------------------------------------------------------------------------------
  # W5 — answering
  # ------------------------------------------------------------------------------------

  describe "answering an approval" do
    test "sends the exact closed envelope", %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      view
      |> element(~s(button[phx-value-decision="approve"][phx-value-scope="session"]))
      |> render_click()

      # No actor: a person answered, and `human` is the default the envelope states
      # rather than a word this surface sends.
      assert_receive {:responded, "r1", response}
      assert response.decision == :approve
      assert response.scope == :session
      refute Map.has_key?(response, :actor)
      # Absent, not empty-and-meaningful: `%{}` is `Jido.Harness.ApprovalResponse`'s own
      # default for the key this answer never set.
      assert response.provider_options == %{}
    end

    test "a plan choice rides provider_options with its fallback answer beside it",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_plan_exit", 1, "r1")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      view |> element(~s(button[phx-value-choice="keep_planning"])) |> render_click()

      assert_receive {:responded, "r1", response}
      assert response.decision == :deny
      assert response.scope == :once
      assert response.provider_options == %{"choice" => "keep_planning"}
    end

    test "a runtime refusing provider_options gets the four-way answer instead",
         %{conn: conn} do
      id = session_id()

      # `-32602` is what a build with no `provider_options` in its envelope answers, and
      # it is the one refusal the plan answer degrades through.
      _plane =
        plane(
          id: id,
          backlogs: [{:ok, [corpus("event_approval_requested_plan_exit", 1, "r1")]}],
          answers: %{approval: [{:error, {:invalid_approval_response, :no_provider_options}}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html = view |> element(~s(button[phx-value-choice="auto_edit"])) |> render_click()

      assert_receive {:responded, "r1", first}
      assert first.provider_options == %{"choice" => "auto_edit"}

      assert_receive {:responded, "r1", second}
      assert second.decision == :approve
      assert second.scope == :session
      assert second.provider_options == %{}

      # Said once rather than dropped silently: what is lost with the key is the follow-up.
      assert html =~ "four-way equivalent"
    end

    test "a second answer to the same request renders the runtime's refusal", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}],
          answers: %{approval: [{:ok, %{}}, {:error, :approval_not_pending}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      first =
        view
        |> element(~s(button[phx-value-decision="approve"][phx-value-scope="once"]))
        |> render_click()

      refute first =~ "ouro-approval-notice"

      second =
        view
        |> element(~s(button[phx-value-decision="approve"][phx-value-scope="once"]))
        |> render_click()

      assert second =~ "the runtime refused the call"
      assert second =~ "ouro-tone-error"
    end

    test "an id this page never drew answers nothing", %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      render_click(view, "respond", %{
        "request" => "a-request-nobody-was-shown",
        "decision" => "approve",
        "scope" => "once"
      })

      refute_receive {:responded, _id, _response}, 100
    end

    test "a decision this page never drew answers nothing", %{conn: conn} do
      id = session_id()

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      # And does not take the view down with it: a malformed `phx-value-*` is a click that
      # did not happen, not a crash an operator loses their transcript to.
      render_click(view, "respond", %{
        "request" => "r1",
        "decision" => "maybe",
        "scope" => "once"
      })

      refute_receive {:responded, _id, _response}, 100
      assert render(view) =~ "ouro-approval"
    end

    test "the card goes when the resolution lands", %{conn: conn} do
      id = session_id()
      request = corpus("event_approval_requested_permission", 1, "r1")
      pid = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ "ouro-approval"

      FakePlane.emit(pid, answered(2, "r1", "approved"))

      refute flush(view) =~ "ouro-approval-answers"
    end
  end

  # ------------------------------------------------------------------------------------
  # W5 — the rail's inline answers
  # ------------------------------------------------------------------------------------

  describe "the rail's inline answers" do
    test "offers two buttons for a plain permission", %{conn: conn} do
      id = session_id()
      _listed = listed(id)

      _plane =
        plane(id: id, backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      # The row triaged into NEEDS YOU because this view is holding an unanswered request
      # for it, which is the only door into that group besides the declared status.
      assert html =~ "ouro-row-needs_you"
      assert html =~ "ouro-inline-answers"

      view |> element(".ouro-inline-answers button", "Deny") |> render_click()

      # Only `once` from a row: a session-scoped allow is a decision the card exists to
      # show the command for.
      assert_receive {:responded, "r1", %{decision: :deny, scope: :once}}
    end

    for {name, fixture} <- [
          {"a question", "event_approval_requested_question"},
          {"a plan exit", "event_approval_requested_plan_exit"}
        ] do
      test "does not offer #{name}, which opens the session instead", %{conn: conn} do
        id = session_id()
        _listed = listed(id)
        _plane = plane(id: id, backlogs: [{:ok, [corpus(unquote(fixture), 1, "r1")]}])

        {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

        assert html =~ "ouro-row-needs_you"
        refute html =~ "ouro-inline-answers"
      end
    end

    test "does not offer a Computer Use ask", %{conn: conn} do
      id = session_id()
      _listed = listed(id)

      request =
        asked(1, "r1", %{
          "kind" => "permission",
          "tool_call" => %{"name" => "desktop_act", "command" => "click"}
        })

      _plane = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-row-needs_you"
      refute html =~ "ouro-inline-answers"
    end
  end

  # ------------------------------------------------------------------------------------
  # W5 — auto-approve
  # ------------------------------------------------------------------------------------

  describe "auto-approve" do
    test "answers an ordinary permission as automation, once", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      FakePlane.emit(pid, corpus("event_approval_requested_permission", 1, "r1"))
      flush(view)

      assert_receive {:responded, "r1", %{decision: :approve, scope: :once, actor: :automation}}
    end

    test "flushes the backlog the moment it is switched on", %{conn: conn} do
      id = session_id()

      backlog = [
        corpus("event_approval_requested_permission", 1, "r1"),
        asked(2, "r2", %{
          "kind" => "permission",
          "tool_call" => %{"name" => "bash", "command" => "ls"}
        })
      ]

      _plane = plane(id: id, backlogs: [{:ok, backlog}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      refute_receive {:responded, _id, _response}, 100

      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      assert_receive {:responded, "r1", %{actor: :automation}}
      assert_receive {:responded, "r2", %{actor: :automation}}
    end

    for {name, request} <- [
          {"a question", {"event_approval_requested_question", nil}},
          {"a plan exit", {"event_approval_requested_plan_exit", nil}}
        ] do
      test "never answers #{name}", %{conn: conn} do
        {fixture, _} = unquote(Macro.escape(request))
        id = session_id()
        _plane = plane(id: id, backlogs: [{:ok, [corpus(fixture, 1, "r1")]}])

        {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
        view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

        refute_receive {:responded, _id, _response}, 150
      end
    end

    for tool <- ["desktop_state", "desktop_act"] do
      test "never answers a #{tool} ask", %{conn: conn} do
        id = session_id()

        request =
          asked(1, "r1", %{
            "kind" => "permission",
            "tool_call" => %{"name" => unquote(tool), "command" => "look"}
          })

        _plane = plane(id: id, backlogs: [{:ok, [request]}])

        {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
        view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

        refute_receive {:responded, _id, _response}, 150
      end
    end

    test "answers one request once, however often the ledger replays it", %{conn: conn} do
      id = session_id()
      request = corpus("event_approval_requested_permission", 1, "r1")
      pid = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      assert_receive {:responded, "r1", _response}

      # The same event again, which is exactly what a repair's overlapping backlog
      # delivers. The watch absorbs it idempotently and the answered set refuses a second
      # answer for it.
      FakePlane.emit(pid, request)
      FakePlane.emit(pid, said(2, "unrelated"))
      flush(view)

      refute_receive {:responded, "r1", _response}, 150
    end

    test "toggling it off answers nothing further", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()
      html = view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      refute html =~ "Auto-approve is on"

      FakePlane.emit(pid, corpus("event_approval_requested_permission", 1, "r1"))
      flush(view)

      refute_receive {:responded, _id, _response}, 150
    end
  end

  # ------------------------------------------------------------------------------------
  # W5 — the suggested rule
  # ------------------------------------------------------------------------------------

  describe "the suggested rule" do
    test "writes the runtime's pattern into the session's own workspace", %{conn: conn} do
      id = session_id()
      # A workspace of this test's own, because the rule this writes is real and lands in
      # this node's permission store.
      workspace = "/tmp/ouroboros-web-rule-#{System.unique_integer([:positive])}"
      on_exit(fn -> forget_rules(workspace) end)

      _plane =
        plane(
          id: id,
          workspace: workspace,
          backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}]
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "Bash(git push *)"
      assert html =~ "Remember for this workspace"

      html = view |> element(~s(button[phx-click="remember"])) |> render_click()

      assert html =~ "saved: Bash(git push *)"

      # The rule the engine actually holds, not the sentence the card drew about it.
      assert [rule] = rules_for(workspace)
      assert rule.pattern == "Bash(git push *)"
      assert rule.decision == :allow
      assert rule.scope == :workspace
    end

    test "names why there is no offer when the session names no workspace", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          workspace: nil,
          backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}]
        )

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "this session names no workspace, so there is no scope to save the rule in"
      refute html =~ "Remember for this workspace"
    end

    test "offers nothing at all where the runtime suggested no pattern", %{conn: conn} do
      id = session_id()

      request =
        asked(1, "r1", %{
          "kind" => "permission",
          "tool_call" => %{"name" => "bash", "command" => "ls"}
        })

      _plane = plane(id: id, backlogs: [{:ok, [request]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-approval"
      refute html =~ "Remember for this workspace"
      # No pattern is not a refusal to explain; there is simply nothing to offer, and the
      # gate says so by naming no reason.
      refute html =~ "there is no scope to save the rule in"
    end

    # The third refusal is unreachable through the deck by construction — this build's
    # `Methods.names/0` always contains `permissions.add`, and the deck passes that list
    # rather than one a test could shorten. Asserted against the gate directly so the
    # sentence stays covered.
    test "names a runtime that does not serve permissions.add" do
      assert {nil, reason} = Transcript.suggested_rule("Bash(ls:*)", ["interactive.list"], "/w")
      assert reason == "this runtime does not serve permissions.add, so the rule cannot be saved"
    end

    test "a Computer Use pattern is user-scoped and needs no workspace" do
      assert {rule, nil} =
               Transcript.suggested_rule(
                 "ComputerUse(Safari)",
                 Ouroboros.Gateway.Methods.names(),
                 nil
               )

      assert rule.pattern == "ComputerUse(Safari)"
      assert rule.workspace == ""
    end
  end
end
