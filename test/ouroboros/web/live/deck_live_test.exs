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
  alias Ouroboros.Web.Live.Composer
  alias Ouroboros.Web.Live.DeckLive
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
         last_turn: Keyword.get(opts, :last_turn),
         provider: Keyword.get(opts, :provider, :native),
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

    def handle_call({:retry_turn, source}, _from, state) do
      send(state.test, {:retried, source})

      {:reply, {:ok, %{id: "retry-#{source}", status: :running}},
       %{state | last_turn: %{id: "retry-#{source}", status: :running, retryable: false}}}
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

    # ui-parity W2. A steer carries no `turn_id`: the gateway's table says so
    # (`methods/contract.ex` `interactive.steer`), and an assertion that one never
    # arrives here is an assertion the envelope was built the way the contract describes.
    def handle_call({:steer, input, opts}, _from, state) do
      send(state.test, {:steered, input, opts})
      answer(state, :steer, {:ok, %{accepted: true}})
    end

    def handle_call(:close, _from, state) do
      send(state.test, {:closed, state.id})

      with {:ok, session} <- Ouroboros.Interactive.Store.get(state.id) do
        :ok = Ouroboros.Interactive.Store.put(%{session | status: :closed})
      end

      {:reply, {:ok, %{id: state.id, status: :closed}}, %{state | status: :closed}}
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
        provider: state.provider,
        workspace: state.workspace,
        workspace_mode: :shared_read,
        status: state.status,
        options: state.options,
        last_turn: state.last_turn,
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
    freeze_recovery()

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

  # The recovery sweep, parked for the test's lifetime. A row `listed/2` plants is exactly
  # what `Ouroboros.Session.Recovery` exists to restart: this node's, a provider this build
  # serves, not terminal, and last touched long before the sweep's two-second grace. Left
  # running, its one-second tick starts a real coordinator for the row, which opens a
  # native runtime and rewrites the row — `:idle`, a `runtime_id`, a fresh `updated_at` —
  # over whatever the test just `put`. That write is what emptied the needs-you group
  # between a test's `awaiting_approval` and its `poll/1` (the bell never rang, and the
  # wait ended with nothing in the mailbox but the sign-in's 302), and what made a row's
  # `on_exit` delete refuse the row it had just closed.
  #
  # `:sys.suspend/1` holds the sweep without stopping it. The resume is registered here,
  # before any row's cleanup, and `on_exit` runs last-registered first: every row is
  # closed and deleted before the sweep ticks again.
  defp freeze_recovery do
    case Process.whereis(Ouroboros.Interactive.Recovery) do
      nil ->
        :ok

      pid ->
        :ok = :sys.suspend(pid)
        on_exit(fn -> if Process.alive?(pid), do: :sys.resume(pid) end)
    end
  end

  # A durable row, so a test of the *rail* is testing the list the deck actually draws
  # rather than a fixture beside it. `interactive.list` reads the store and nothing else.
  #
  # The store is global to the node and this row is real, which makes the cleanup part of
  # the fixture rather than tidiness. Three rules, all of which this file got wrong first:
  #
  #   * the workspace has to exist. `Ouroboros.Workspace.Manager` recovers every live
  #     session's lease at boot and refuses to start on a path that is not there, so a row
  #     naming a directory nobody made takes the *next* application restart in the suite
  #     down with it — and `Ouroboros.ApplicationRecoveryTest` restarts the application.
  #   * the row has to be closed before it can be removed. `Store.delete/1` refuses a
  #     session that is not terminal, so a plain delete leaves the row exactly where it
  #     would do that damage.
  #   * the recovery sweep has to be held while the row exists (`freeze_recovery/0`, from
  #     `setup`). To the sweep this row is a coordinator's orphaned record, and it starts
  #     one — which then rewrites the row under the test.
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
      provider: :native,
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

  # ui-parity W2. The order the rail actually drew, and which session the focus column
  # is actually showing — both read off the page rather than recomputed here, so a test of
  # `[`/`]` is a test of what an operator would see move.
  defp drawn_rail(html) do
    ~r/id="session-row-interactive-([^"]+)"/
    |> Regex.scan(html)
    |> Enum.map(fn [_whole, id] -> id end)
  end

  defp open_session(html) do
    case Regex.run(~r/data-session="interactive:([^"]+)"/, html) do
      [_whole, id] -> id
      nil -> nil
    end
  end

  defp palette_selection(html) do
    case Regex.run(~r/id="ouro-palette-row-([^"]+)"[^>]*aria-selected="true"/, html) do
      [_whole, id] -> id
      nil -> nil
    end
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
      # A row, because W1.7 collapses the three headings into one line on a rail that holds
      # nothing at all — the headings are only worth their space once one of them is
      # telling a reader which group is empty.
      _listed = listed(session_id(), status: :running)

      {:ok, _view, html} = live(conn, "/")

      assert html =~ "Ouroboros"
      assert html =~ "NEEDS YOU"
      assert html =~ "AT WORK"
      assert html =~ "SETTLED"
      assert html =~ "ouro-dot"
      # Self is always connected: it is the machine answering this request.
      assert html =~ "ouro-dot-on"
      # W1.6: named the way a person would name it, never as the BEAM's node atom.
      # A full `mix test` may have named this BEAM already (a distributed module runs
      # first), and then the presence dot carries that machine's label instead.
      if node() == :nonode@nohost do
        assert html =~ "this computer"
      else
        refute html =~ to_string(node())
      end

      refute html =~ "nonode@nohost"
    end

    # F4. The presence dots are the one place two machines stand side by side, so they are
    # the one place a collapsed label is unreadable. The roster is `runtime.status`'s own
    # `cluster.fleet.machines`, and a real one cannot be conjured from a test — so the
    # projection is driven directly.
    test "two machines in one fleet get two words, from the roster where it has them" do
      roster = [
        %{node: :ouro@alpha, machine: "the build box"},
        %{node: :ouro@beta, machine: "the spare"}
      ]

      status = %{
        node: :ouro@alpha,
        connected_nodes: [:ouro@beta],
        cluster: %{fleet: %{machines: roster}}
      }

      labels = DeckLive.machines(status) |> Enum.map(& &1.label)

      assert Enum.sort(labels) == ["the build box", "the spare"]

      # And with no roster at all they are still two words rather than the release name
      # twice.
      bare =
        DeckLive.machines(%{node: :ouro@alpha, connected_nodes: [:ouro@beta]})
        |> Enum.map(& &1.label)

      assert Enum.sort(bare) == ["alpha", "beta"]
    end

    test "carries the one top bar, with the connection pill on it", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ ~s(class="ouro-topbar")

      for href <- ["/", "/new", "/settings", "/audit", "/status"] do
        assert html =~ ~s(href="#{href}"), "the deck's top bar does not link to #{href}"
      end

      # The pill the CSS swaps between "Connected" and "Reconnecting" is still the deck's,
      # with the classes and the live-region attributes `app.css` and a screen reader both
      # read it by.
      assert html =~ ~s(class="ouro-pill")
      assert html =~ ~s(role="status")
      assert html =~ ~s(aria-live="polite")
      assert html =~ "Reconnecting"
    end

    test "says what it cannot do yet instead of pretending", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      # The one filled control leads to the form's own page. The presence dots are a
      # readout of cluster connectivity, not a link: there is no page behind them.
      assert html =~ "New session"
      assert html =~ ~s(href="/new")
      refute html =~ ~s(href="/machines")

      # And the composer names the slice that wires it.
      assert html =~ "ouro-composer" or html =~ "What would you like to make?"
    end

    test "with nothing open, says so rather than showing an empty transcript",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ "What would you like to make?"
      refute html =~ "ouro-transcript"
      # No vitals column either: a panel with nothing in it is worse than no panel.
      refute html =~ "ouro-vitals"
    end

    # W1.7. "A little direction. A lot of possibility." was marketing copy on a console
    # that otherwise refuses to say anything unmeasured
    # (`docs/design-qa/ui-review-2026-09-15.md` §3.1). What stands there now is a count this
    # page already holds — the eyebrow is the only line that changed, so the rest of the
    # empty state is still the same page.
    test "the empty deck states a count rather than a slogan", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      refute html =~ "A little direction"
      refute html =~ "A lot of possibility"

      assert Regex.run(
               ~r/ouro-empty-eyebrow">\s*(No sessions|\d+ sessions?) on this runtime/,
               html
             ),
             "the empty deck's eyebrow does not state how many sessions this runtime has"
    end

    test "a search that matches nothing says so in the eyebrow", %{conn: conn} do
      _listed = listed(session_id(), status: :running)

      {:ok, view, _html} = live(conn, "/")

      html =
        view
        |> form("#session-search", %{"query" => "no-session-is-called-this-xyzzy"})
        |> render_change()

      # The eyebrow itself, not merely the words: the rail's collapsed line says the same
      # thing, so a bare `=~` would pass with the eyebrow deleted.
      assert Regex.run(~r/ouro-empty-eyebrow">\s*No sessions match/, html),
             "the empty state's eyebrow does not say that nothing matched"

      # And the rail collapses with it: one line rather than three empty headings.
      refute html =~ "nothing here"
    end

    test "filters the rail without changing session order or closing the focused pane",
         %{conn: conn} do
      first = session_id()
      second = session_id()
      _alpha = listed(first, status: :idle, title: "Alpha migration")
      _beta = listed(second, status: :idle, title: "Beta rollout")

      {:ok, view, html} = live(conn, "/s/interactive/#{first}")
      assert html =~ "Alpha migration"
      assert html =~ "Beta rollout"

      filtered = view |> form("#session-search", query: "beta") |> render_change()

      refute has_element?(view, ".ouro-rail", "Alpha migration")
      assert has_element?(view, ".ouro-rail", "Beta rollout")
      assert filtered =~ ~s(<h1 class="ouro-focus-title">Alpha migration</h1>)

      restored = view |> form("#session-search", query: "") |> render_change()
      assert restored =~ "Alpha migration"
      assert restored =~ "Beta rollout"
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

      # Pinned, so only this session's own re-entry satisfies the wait.
      key = "interactive:#{id}"
      assert_push_event(view, "needs-you", %{sessions: [%{key: ^key}]}, 500)
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

    # W1.2. `activity/1` guarded `when is_list(cells)` while `:cells` has been a map since
    # the stream landed, so the clause could never match and every row on the rail fell
    # back to "provider · machine" — nothing distinguished a session doing work from one
    # sitting still (`docs/design-qa/ui-review-2026-09-15.md` §3.2).
    test "the rail row for the open session says what it is doing", %{conn: conn} do
      id = session_id()
      _listed = listed(id, status: :running)

      # A shell call rather than a read: `Tools.explores?/1` folds reads, greps, globs and
      # listings into one `Exploration` cell, and the row this test is about is the one a
      # single tool produces.
      tool =
        event(1, :tool_call, %{
          "call_id" => "c1",
          "name" => "bash",
          "input" => %{"command" => "mix test"}
        })

      _plane = plane(id: id, backlogs: [{:ok, [tool]}])

      # The expected words are the projection's own, read through the same two functions
      # the rail reads them through: nothing here mints a phrase the corpus does not pin.
      expected =
        [tool]
        |> projected()
        |> Enum.find_value(fn
          %Cell.Tool{} = cell ->
            cell |> Transcript.Tools.summarise() |> Transcript.ToolSummary.line()

          _other ->
            nil
        end)

      assert is_binary(expected) and expected != ""

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, ".ouro-row-line", expected),
             "the rail row does not say what the open session is doing"

      # And not the fallback it used to be stuck on.
      refute has_element?(view, ".ouro-row-line", "native ·")
    end

    # PROOF A, adopted. A needs-you row reports the projection's own status line rather
    # than the rail's "waiting on your answer", because the projection is what the
    # transcript beside it is showing. Kept as a regression test: the words are the
    # corpus's, and nothing here mints a phrase.
    test "a needs-you row reports the projection's own words", %{conn: conn} do
      id = session_id()
      _listed = listed(id, status: :awaiting_approval)

      tool =
        event(1, :tool_call, %{
          "call_id" => "c1",
          "name" => "bash",
          "input" => %{"command" => "mix compile"}
        })

      _plane =
        plane(
          id: id,
          status: :awaiting_approval,
          backlogs: [{:ok, [tool, corpus("event_approval_requested_permission", 2, "r1")]}]
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, ".ouro-row-line", "Approval needed")
    end

    # PROOF B, inverted. `activity` is what the session is doing *this second*: a tool that
    # settled two turns ago is history, and the rail reported it in the present tense while
    # a new turn streamed prose.
    test "a tool that has already finished is not what the session is doing", %{conn: conn} do
      id = session_id()
      _listed = listed(id, status: :running)

      events = [
        event(1, :tool_call, %{
          "call_id" => "c1",
          "name" => "bash",
          "input" => %{"command" => "mix compile"}
        }),
        event(2, :tool_result, %{"call_id" => "c1", "output" => "ok"}),
        event(3, :output_text_final, %{"text" => "Compiled."}),
        event(4, :turn_completed, %{}),
        event(5, :input_text, %{"text" => "now write the docs"}),
        event(6, :output_text_delta, %{"text" => "Writing the docs "})
      ]

      _plane = plane(id: id, backlogs: [{:ok, events}])

      # The fixture has to actually settle, or this proves nothing.
      assert Enum.any?(projected(events), &match?(%Cell.Tool{state: :completed}, &1)),
             "the fixture's tool did not settle"

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      refute has_element?(view, ".ouro-row-line", "mix compile"),
             "the rail still names a tool that finished two turns ago"
    end

    # CONTROL, adopted: prepending older cells must not change which cell is newest. The
    # index the redraw assigns is what `activity/1` sorts on, and it is assigned over the
    # whole projection rather than over the drawn window.
    test "loading earlier messages does not change what the row reports", %{conn: conn} do
      id = session_id()
      _listed = listed(id, status: :running)

      old = for n <- 1..60, do: said(n, "line #{n}")

      newest =
        event(61, :tool_call, %{
          "call_id" => "c9",
          "name" => "bash",
          "input" => %{"command" => "mix format"}
        })

      _plane = plane(id: id, backlogs: [{:ok, old ++ [newest]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      assert has_element?(view, ".ouro-row-line", "mix format")

      render_click(view, "load-history", %{})

      assert has_element?(view, ".ouro-row-line", "mix format"),
             "prepending older cells changed which cell counts as newest"
    end

    test "the newest cell wins the rail row's line", %{conn: conn} do
      # Newest first, by the index the redraw assigned — a rail that reported the *first*
      # tool of a long turn would be reporting history.
      id = session_id()
      _listed = listed(id, status: :running)

      first =
        event(1, :tool_call, %{
          "call_id" => "c1",
          "name" => "bash",
          "input" => %{"command" => "mix compile"}
        })

      second =
        event(2, :tool_call, %{
          "call_id" => "c2",
          "name" => "bash",
          "input" => %{"command" => "mix format"}
        })

      _plane = plane(id: id, backlogs: [{:ok, [first, second]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, ".ouro-row-line", "mix format")
      refute has_element?(view, ".ouro-row-line", "mix compile")
    end

    # W1.3. Both of these were one click behind "Session details" on every viewport
    # (review §3.2). They are the two standing postures the terminal client keeps
    # permanently in its footer.
    test "auto-approve sits on the composer, not behind a disclosure", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{sandbox_mode: :workspace_write})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(
               view,
               ~s(.ouro-composer-status button[phx-click="auto_approve"])
             ),
             "the auto-approve toggle is not on the composer's status row"

      refute has_element?(view, ~s(details button[phx-click="auto_approve"])),
             "the auto-approve toggle is still behind a disclosure"
    end

    test "the status row states the posture only when it is the one that is a risk",
         %{conn: conn} do
      # The composer's own "Change" summary states the posture one line above and the
      # vitals state it a third time; three statements of one fact in one band is noise,
      # and at 375px it pushed the toggle's caption off the edge. `unrestricted` is the
      # exception because it is a standing risk rather than a setting.
      ordinary = session_id()

      _plane =
        plane(id: ordinary, backlogs: [{:ok, []}], options: %{sandbox_mode: :workspace_write})

      {:ok, view, _html} = live(conn, "/s/interactive/#{ordinary}")

      refute has_element?(view, ".ouro-composer-status", "File access"),
             "the status row repeats a posture the composer already states"

      full = session_id()

      _full_plane =
        plane(id: full, backlogs: [{:ok, []}], options: %{sandbox_mode: :unrestricted})

      {:ok, full_view, _html} = live(conn, "/s/interactive/#{full}")

      assert has_element?(full_view, ".ouro-composer-status", "File access")

      assert has_element?(
               full_view,
               ".ouro-composer-status .ouro-tag-full",
               "Full computer access"
             )
    end

    test "a session that reported no posture is not given one on the status row",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      refute has_element?(view, ".ouro-composer-status", "File access")
      assert has_element?(view, ~s(.ouro-composer-status button[phx-click="auto_approve"]))
    end

    test "the vitals are a column of `.ouro-columns`, and carry the session id",
         %{conn: conn} do
      # Seven `.ouro-columns > .ouro-vitals` rules in `app.css` and the moduledoc's own
      # "three columns" described a panel that was only ever rendered inside a `<details>`
      # under the composer. The disclosure stays for narrow viewports; the column is what
      # those rules were written for.
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, ".ouro-columns > .ouro-vitals"),
             "the vitals are not a column of the deck's grid"

      # Whole, and selectable in one click: a fixed-width `<input>` truncated it, and an
      # id a reader cannot see all of is not the id.
      assert has_element?(view, ".ouro-vitals .ouro-vital-id", id),
             "the vitals do not carry the session id"

      assert html =~ id
    end

    # F1. The panel is in the document twice \u2014 once as the third column, once inside the
    # narrow-viewport disclosure \u2014 because which one a reader gets is a viewport question
    # and this surface has no JavaScript that could move a single node between them. What
    # must be true is that exactly one of the two is *displayed* at any width, and that is
    # the stylesheet's job: `stylesheet_test.exs` holds the rule that turns the disclosure
    # on only inside the 1100px block. Here: one of each, and no third.
    test "the vitals are drawn once as a column and once as the narrow disclosure",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html |> String.split(~s(class="ouro-vitals")) |> length() == 3,
             "the vitals panel is in the document a number of times other than twice"

      assert has_element?(view, ".ouro-columns > .ouro-vitals")
      assert has_element?(view, "details.ouro-vitals-mobile .ouro-vitals")

      # And the disclosure holds nothing else: the toggle moved to the composer's status
      # row, so "Session details" is the vitals and only the vitals.
      refute has_element?(view, ~s(details.ouro-vitals-mobile button[phx-click="auto_approve"]))
    end

    # W1.6. Ground rule 6, at the one vital that names a machine.
    test "the machine vital names the computer rather than the Erlang node", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~r/Machine<\/dt>\s*<dd[^>]*>\s*this computer/
      refute html =~ "nonode@nohost"
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
      # `[:closed, :failed, :cancelled, :lost]`, and this test has to use that vocabulary
      # or it proves nothing.
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

      # Five seconds, not the 100 ms default: `handle_info(:poll, …)`
      # (`lib/ouroboros/web/live/deck_live.ex:458-461`) runs the whole synchronous
      # `refresh/1` — `interactive.list`, `runtime_status`, `refresh_info` — *before*
      # `recover_subscription/1`, so on a loaded machine the resubscribe is late rather
      # than absent, and a 100 ms bound measures the machine instead of the recovery.
      # The claim under test is that it happens at all, and from the right cursor.
      assert_receive {:subscribed, _subscriber, 1}, 5_000
      assert_eventually(fn -> render(view) =~ "after restart" end)
      refute render(view) =~ "ouro-divider"
      assert render(view) =~ "mid-sentence"
    end
  end

  # ------------------------------------------------------------------------------------
  # Folds
  # ------------------------------------------------------------------------------------

  describe "scrollable history" do
    test "projects a whole long response before paging, including events beyond the watch window",
         %{conn: conn} do
      id = session_id()

      deltas =
        for n <- 1..2_100,
            do: event(n, :output_text_delta, %{"text" => "review-part-#{n}; "})

      _plane = plane(id: id, backlogs: [{:ok, deltas ++ [said(2_101, "")]}])
      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      text = view |> element("#transcript") |> render()

      assert text =~ "review-part-1;"
      assert text =~ "review-part-2100;"
      refute has_element?(view, "button[phx-click=load-history]")
    end

    test "loads every earlier page in order with stable ids and retains it during new output",
         %{conn: conn} do
      id = session_id()
      events = for n <- 1..125, do: said(n, "history-message-#{n};")
      pid = plane(id: id, backlogs: [{:ok, events}])
      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, "#cells-event-76-0", "history-message-76;")
      refute has_element?(view, "#cells-event-75-0")

      view |> element("button[phx-click=load-history]") |> render_click()
      assert has_element?(view, "#cells-event-26-0", "history-message-26;")
      assert has_element?(view, "#cells-event-76-0", "history-message-76;")

      FakePlane.emit(pid, said(126, "newest-message;"))
      flush(view)
      assert has_element?(view, "#cells-event-26-0", "history-message-26;")
      assert has_element?(view, "#cells-event-126-0", "newest-message;")

      view |> element("button[phx-click=load-history]") |> render_click()
      refute has_element?(view, "button[phx-click=load-history]")

      html = view |> element("#transcript-cells") |> render()

      assert Regex.scan(~r/data-history-cell="(\d+)"/, html, capture: :all_but_first) ==
               Enum.map(0..125, &[to_string(&1)])

      for n <- 1..125, do: assert(occurrences(html, "history-message-#{n};") == 1)

      # Neither duplicate requests at the start nor an ordinary refresh hide history.
      render_hook(view, "load-history", %{"session" => "interactive:#{id}"})
      poll(view)
      assert has_element?(view, "#cells-event-1-0", "history-message-1;")
    end

    test "replayed gaps preserve the loaded boundary and message identities", %{conn: conn} do
      id = session_id()
      events = for n <- Enum.to_list(1..20) ++ Enum.to_list(31..100), do: said(n, "message-#{n};")
      pid = plane(id: id, backlogs: [{:ok, events}])
      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      assert has_element?(view, "#transcript[data-history-start='41']")
      assert has_element?(view, "#cells-event-71-0[data-history-cell='61']", "message-71;")

      for n <- 21..30, do: FakePlane.emit(pid, said(n, "message-#{n};"))
      flush(view)
      assert has_element?(view, "#transcript[data-history-start='50']")
      assert has_element?(view, "#cells-event-51-0", "message-51;")
      refute has_element?(view, "#cells-event-50-0")
      assert has_element?(view, "#cells-event-71-0[data-history-cell='70']", "message-71;")
      view |> element("button[phx-click=load-history]") |> render_click()
      html = view |> element("#transcript-cells") |> render()

      assert Regex.scan(~r/id="cells-event-(\d+)-0"/, html, capture: :all_but_first) ==
               Enum.map(1..100, &[to_string(&1)])
    end

    test "a gap repaired inside loaded history inserts messages in chronological order", %{
      conn: conn
    } do
      id = session_id()
      events = for n <- [1, 2, 5, 6], do: said(n, "message-#{n};")
      pid = plane(id: id, backlogs: [{:ok, events}])
      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      assert has_element?(view, "#cells-gap-3-0")
      for n <- [3, 4], do: FakePlane.emit(pid, said(n, "message-#{n};"))
      flush(view)
      refute has_element?(view, "#cells-gap-3-0")
      html = view |> element("#transcript-cells") |> render()

      assert Regex.scan(~r/id="cells-event-(\d+)-0"/, html, capture: :all_but_first) ==
               Enum.map(1..6, &[to_string(&1)])
    end

    test "resets pagination on session changes and ignores a previous session's request",
         %{conn: conn} do
      first = session_id()
      second = session_id()
      events = for n <- 1..100, do: said(n, "history-message-#{n};")
      _first = plane(id: first, backlogs: [{:ok, events}])
      _second = plane(id: second, backlogs: [{:ok, events}])
      {:ok, view, _html} = live(conn, "/s/interactive/#{first}")
      view |> element("button[phx-click=load-history]") |> render_click()
      assert has_element?(view, "#cells-event-1-0")

      render_patch(view, "/s/interactive/#{second}")
      assert has_element?(view, "#cells-event-51-0")
      refute has_element?(view, "#cells-event-1-0")
      render_hook(view, "load-history", %{"session" => "interactive:#{first}"})
      refute has_element?(view, "#cells-event-1-0")
    end
  end

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
      assert html =~ "What would you like to make?"
    end
  end

  defp live_redirect_to_root(view) do
    view |> render_patch("/")
  end

  # ------------------------------------------------------------------------------------
  # W4 — the composer
  # ------------------------------------------------------------------------------------

  describe "the composer" do
    test "shows a timed loader only while the agent owns the next action", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "ouro-loading-state"

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      working = flush(view)

      assert working =~ "ouro-loading-state"
      assert working =~ "Agent working"
      assert working =~ ~s(phx-hook="ElapsedTimer")

      FakePlane.emit(pid, event(2, :turn_completed, %{}))
      refute flush(view) =~ "ouro-loading-state"
    end

    test "does not call waiting on the operator agent work", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          status: :awaiting_approval,
          backlogs: [{:ok, [corpus("event_approval_requested_permission", 1, "r1")]}]
        )

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "ouro-approval"
      refute html =~ "ouro-loading-state"
    end

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

      assert html =~ "Write a message before sending."
      refute_receive {:sent, _mode, _turn, _input, _opts}, 100
    end

    test "a failed first message offers a durable retry when opened later", %{conn: conn} do
      id = session_id()

      _pid =
        plane(
          id: id,
          status: :idle,
          last_turn: %{id: "first", status: :failed, retryable: true},
          backlogs: [
            {:ok,
             [
               event(1, :turn_started, %{}),
               event(2, :turn_failed, %{"error" => "server_is_overloaded"})
             ]}
          ]
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      html = flush(view)

      assert html =~ "The agent stopped before completing the last message."
      assert html =~ "Retry last message"

      view |> element(~s(button[phx-click="retry"])) |> render_click()
      assert_receive {:retried, "first"}
      refute has_element?(view, ~s(button[phx-click="retry"]))
    end

    test "drafts belong to their session and stale form events cannot cross sessions", %{
      conn: conn
    } do
      first = session_id()
      second = session_id()
      plane(id: first, status: :idle)
      plane(id: second, status: :idle)
      {:ok, view, _} = live(conn, "/s/interactive/#{first}")

      key =
        view
        |> element(~s(input[name="session_key"]))
        |> render()
        |> then(&Regex.run(~r/value="([^"]+)"/, &1))
        |> List.last()

      view |> form("#composer", message: "Keep this draft") |> render_change()
      render_patch(view, "/s/interactive/#{second}")
      refute render(view) =~ "Keep this draft"
      render_change(view, "draft", %{"message" => "Late draft", "session_key" => key})
      render_submit(view, "send", %{"message" => "Wrong session", "session_key" => key})
      refute_receive {:sent, _, _, _, _}, 50
      refute render(view) =~ "Late draft"
      view |> form("#composer", message: "Second draft") |> render_change()
      render_patch(view, "/s/interactive/#{first}")
      assert has_element?(view, "textarea", "Keep this draft")
      render_patch(view, "/s/interactive/#{second}")
      assert has_element?(view, "textarea", "Second draft")
    end

    test "an empty draft disables the visible send control", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~r/<button[^>]*data-ouro-send[^>]*disabled/
    end

    test "a running session can be ended through a modal confirmation", %{conn: conn} do
      id = session_id()
      listed(id)
      _plane = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/")

      dialog =
        view
        |> element(~s(button[phx-value-action="close"][phx-value-id="#{id}"]))
        |> render_click()

      assert dialog =~ "End session"
      assert dialog =~ ~s(phx-hook="Modal")
      assert dialog =~ ~s(aria-modal="true")
      refute dialog =~ ~r/<dialog[^>]*\sopen(?:\s|>)/

      html = render_submit(view, "session-close", %{})
      assert_receive {:closed, ^id}

      refute has_element?(
               view,
               ~s(button[phx-value-action="close"][phx-value-id="#{id}"])
             )

      assert html =~ ~s(phx-value-action="delete")
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
      refute html =~ "File access ·"
      # The thinking picker is a preference, not a permission, so it is always offered —
      # with the honest label for having been told nothing.
      assert html =~ "Thinking · Session default"
    end

    test "is present, marked and amber where the session reported unrestricted",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{sandbox_mode: :unrestricted})

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "File access · Full computer access"
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
      assert html =~ "File access · Read only"
      refute html =~ "File access · Full computer access"
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

    test "a native session offers and configures Sol's extended thinking levels", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          provider: :native,
          backlogs: [{:ok, []}],
          options: %{
            model: "openai_codex:gpt-5.6-sol",
            reasoning_effort: :high
          }
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ ~s(phx-value-choice="xhigh")
      assert html =~ ~s(phx-value-choice="max")

      view
      |> element(~s(button[phx-value-field="reasoning_effort"][phx-value-choice="max"]))
      |> render_click()

      assert_receive {:configured, %{reasoning_effort: :max}}
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
      assert html =~ "File access request"
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
      # Absent, not empty-and-meaningful: `%{}` is `Ouroboros.Session.ApprovalResponse`'s own
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

    # PROOF C, inverted. A browser can send any `phx-click` on any socket, so the gate is
    # recomputed from the scope and the open session rather than read off an assign that
    # only records what was *drawn*. A click carrying some other session's id is not a
    # click on this page's control.
    test "a click naming a session this page does not have open does nothing", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      refute render(view) =~ "Routine actions are allowed automatically"

      render_click(view, "auto_approve", %{"session" => "some-other-session"})

      refute render(view) =~ "Routine actions are allowed automatically",
             "a forged click flipped a control that answers on the operator's behalf"

      # And the page's own control still works.
      render_click(view, "auto_approve", %{})
      assert render(view) =~ "Routine actions are allowed automatically"
    end

    # PROOF D, adopted: the grant is this view's and this session's, and opening another
    # session starts again from off. A preference that survived would be a standing grant
    # nobody remembers making.
    test "opening another session starts again from off", %{conn: conn} do
      a = session_id()
      b = session_id()
      _pa = plane(id: a, backlogs: [{:ok, []}])
      _pb = plane(id: b, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{a}")
      render_click(view, "auto_approve", %{})
      assert render(view) =~ "Routine actions are allowed automatically"

      {:ok, second, _html} = live(conn, "/s/interactive/#{b}")
      refute render(second) =~ "Routine actions are allowed automatically"
    end

    test "toggling it off answers nothing further", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      view |> element(~s(button[phx-click="auto_approve"])) |> render_click()
      html = view |> element(~s(button[phx-click="auto_approve"])) |> render_click()

      refute html =~ "Routine actions are allowed automatically"

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

      assert html =~ "Choose a project folder before saving an approval rule for this session."
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
      refute html =~ "Choose a project folder before saving an approval rule"
    end

    # The third refusal is unreachable through the deck by construction — this build's
    # `Methods.names/0` always contains `permissions.add`, and the deck passes that list
    # rather than one a test could shorten. Asserted against the gate directly so the
    # sentence stays covered.
    test "explains when this node cannot save an approval rule" do
      assert {nil, reason} = Transcript.suggested_rule("Bash(ls:*)", ["interactive.list"], "/w")
      assert reason == "This Ouroboros node cannot save approval rules."
    end

    test "a Capability pattern is user-scoped and needs no workspace" do
      assert {rule, nil} =
               Transcript.suggested_rule(
                 "Capability(vet)",
                 Ouroboros.Gateway.Methods.names(),
                 nil
               )

      assert rule.pattern == "Capability(vet)"
      assert rule.workspace == ""
    end
  end

  # ------------------------------------------------------------------------------------
  # ui-parity W2 — the palette, the keyboard, copy, steer, model, per-turn effort, plan
  # ------------------------------------------------------------------------------------

  describe "the command palette" do
    test "lists the five groups once each, in the parity plan's order", %{conn: conn} do
      id = session_id()
      # A session with something in it, so every one of the five groups has a row: the
      # Conversation group exists only where there is a message to copy.
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, [said(1, "the answer")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      # Closed until asked for: nothing of the palette is in the first paint.
      refute html =~ ~s(id="ouro-palette")

      html = view |> element("button[phx-click='palette-open']") |> render_click()

      assert html =~ ~s(id="ouro-palette")

      headings =
        Regex.scan(~r{<p class="ouro-palette-group"[^>]*>([^<]+)</p>}, html)
        |> Enum.map(fn [_whole, label] -> String.trim(label) end)

      assert headings == ["Session", "Turn", "Conversation", "Runtime", "Client"]

      # Every heading exactly once, which is the collision the TUI palette review named.
      assert headings == Enum.uniq(headings)
    end

    test "draws the slash spelling and the shortcut beside each row", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      html = view |> render_hook("palette-open", %{})

      assert html =~ ~s(<span class="ouro-palette-label">New session</span>)
      assert html =~ ~s(<span class="ouro-palette-slash ouro-mono">/new</span>)
      assert html =~ "<kbd>n</kbd>"
      assert html =~ ~s(<span class="ouro-palette-slash ouro-mono">/status</span>)
    end

    test "toggles: a second ctrl+k closes what the first opened", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      assert render_hook(view, "palette-toggle", %{}) =~ ~s(id="ouro-palette")
      refute render_hook(view, "palette-toggle", %{}) =~ ~s(id="ouro-palette")
    end

    test "Esc closes it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      render_hook(view, "palette-open", %{})
      refute render_hook(view, "palette-close", %{}) =~ ~s(id="ouro-palette")
    end

    test "filters in this process, keeping group order", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      render_hook(view, "palette-open", %{})

      html =
        view
        |> form("#ouro-palette form", %{"query" => "theme"})
        |> render_change()

      assert html =~ "Change the colour theme"
      assert html =~ ">Client</p>"
      refute html =~ ~s(phx-value-id="session.new")
      refute html =~ ">Session</p>"
    end

    test "the arrows move the selection and Enter runs what they left on it", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      render_hook(view, "palette-open", %{})

      # "New session" is the first row of the first group, so it is selected on open.
      assert palette_selection(render(view)) == "session.new"

      moved = palette_selection(render_hook(view, "palette-move", %{"direction" => "next"}))
      assert moved != nil and moved != "session.new"

      assert palette_selection(render_hook(view, "palette-move", %{"direction" => "prev"})) ==
               "session.new"

      # The top does not wrap round to the bottom: a held arrow key stops at the end.
      render_hook(view, "palette-move", %{"direction" => "prev"})
      assert palette_selection(render(view)) == "session.new"

      # Enter on the selected row: `/new` is a navigation, and this is the whole of
      # "each command maps to an existing event or a push_navigate".
      assert {:error, {:live_redirect, %{to: "/new"}}} =
               view |> form("#ouro-palette form", %{"query" => ""}) |> render_submit()
    end

    test "a row that went stale while the modal was open runs nothing", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      html = render_hook(view, "palette-open", %{})
      assert html =~ "Interrupt the running turn"

      # The turn settles under the open palette. The second gate in `run_command/2` is
      # the only thing between a stale row and a call the runtime would have refused.
      FakePlane.emit(pid, event(2, :turn_completed, %{}))
      flush(view)

      render_hook(view, "palette-run", %{"id" => "turn.interrupt"})
      refute_receive {:interrupted, _turn}, 100
    end

    test "the shortcut sheet lists only keys this page binds", %{conn: conn} do
      {:ok, view, html} = live(conn, "/")

      refute html =~ ~s(id="ouro-shortcuts")

      html = render_hook(view, "shortcuts-open", %{})

      assert html =~ ~s(id="ouro-shortcuts")
      assert html =~ "<kbd>⌘K</kbd>"
      assert html =~ "<kbd>[</kbd>"
      # The two keys docs/WEB.md used to claim and nothing ever bound.
      refute html =~ "⌘N"
      refute html =~ "⌘."

      refute render_hook(view, "shortcuts-close", %{}) =~ ~s(id="ouro-shortcuts")
    end

    test "the keyboard hook is mounted so the document keys have somewhere to push",
         %{conn: conn} do
      {:ok, _view, html} = live(conn, "/")

      assert html =~ ~s(id="ouro-keys")
      assert html =~ ~s(phx-hook="Keys")
    end
  end

  describe "[ and ] on the rail" do
    test "walk the rail in the order it drew, one row per press", %{conn: conn} do
      listed(session_id(), title: "Alpha", status: :running)
      listed(session_id(), title: "Beta", status: :running)

      # Read the order off the very view that will do the moving. The list is refreshed
      # on the poll, so a second view mounted a moment later is a second list.
      {:ok, view, html} = live(conn, "/")
      [first, second | _rest] = drawn_rail(html)

      render_hook(view, "rail-move", %{"direction" => "next"})
      assert assert_patch(view) == "/s/interactive/#{first}"
      assert open_session(render(view)) == first

      render_hook(view, "rail-move", %{"direction" => "next"})
      assert assert_patch(view) == "/s/interactive/#{second}"
      assert open_session(render(view)) == second

      render_hook(view, "rail-move", %{"direction" => "prev"})
      assert assert_patch(view) == "/s/interactive/#{first}"
      assert open_session(render(view)) == first
    end

    test "stop at the ends rather than wrapping round", %{conn: conn} do
      listed(session_id(), title: "Alpha", status: :running)
      listed(session_id(), title: "Beta", status: :running)

      {:ok, view, html} = live(conn, "/")
      last = html |> drawn_rail() |> List.last()

      render_hook(view, "rail-move", %{"direction" => "prev"})
      assert assert_patch(view) == "/s/interactive/#{last}"

      render_hook(view, "rail-move", %{"direction" => "next"})
      assert open_session(render(view)) == last
    end
  end

  describe "copying a message" do
    test "every settled agent message wears both controls", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "The answer is 42.")]}])

      {:ok, _view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~s(phx-hook="Clipboard")
      assert html =~ ~s(data-ouro-copy="rendered")
      assert html =~ ~s(phx-click="copy-source")
    end

    test "copy source sends the Markdown the model wrote, not the rendered words",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "# Heading\n\nand **bold**.")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      # The page shows the rendered heading, and the raw Markdown is nowhere in the DOM.
      assert html =~ "<h1>Heading</h1>"
      refute html =~ "# Heading"

      [_whole, cell] = Regex.run(~r{phx-value-cell="([^"]+)"}, html)

      render_click(view, "copy-source", %{"cell" => cell})
      assert_push_event(view, "ouro-copy", %{text: "# Heading\n\nand **bold**."})
    end

    test "a cell id this view never drew copies nothing", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "hello")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      render_click(view, "copy-source", %{"cell" => "event-9999-0"})
      refute_push_event(view, "ouro-copy", _nothing)
    end

    test "the palette copies the last message two ways, and neither is the other",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "first"), said(2, "**last**")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      render_hook(view, "palette-run", %{"id" => "conversation.copy_source"})
      assert_push_event(view, "ouro-copy", %{text: "**last**"})

      # The rendered half is read out of the prose the browser already drew: this process
      # holds Markdown, and a second renderer here would be a second answer.
      render_hook(view, "palette-run", %{"id" => "conversation.copy"})
      assert_push_event(view, "ouro-copy", %{selector: selector})
      assert selector =~ ".ouro-prose"
    end
  end

  describe "steer" do
    test "offers the button while a turn runs and sends the steer envelope", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ ~s(data-ouro-steer)

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      assert flush(view) =~ ~s(data-ouro-steer)

      view
      |> form("#composer", %{"message" => "use the smaller fixture"})
      |> render_submit(%{"verb" => "steer"})

      # `interactive.steer`'s closed envelope is `{id, input, node}` and carries no
      # `turn_id` — the harness mints the request id inside its own worker, so there is
      # no caller-keyed idempotency to manufacture.
      assert_receive {:steered, "use the smaller fixture", []}
      refute_receive {:sent, _mode, _turn, _input, _opts}, 100
    end

    test "is absent where the session declared it cannot be steered", %{conn: conn} do
      id = session_id()

      pid =
        plane(
          id: id,
          status: :idle,
          backlogs: [{:ok, []}],
          options: %{capabilities: %{steer: false}}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))

      assert flush(view) =~ "Interrupt"
      refute flush(view) =~ ~s(data-ouro-steer)
    end

    test "is offered where the runtime said nothing at all about steering", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}], options: %{capabilities: %{}})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))

      # Silence is an older gateway, not a refusal.
      assert flush(view) =~ ~s(data-ouro-steer)
    end

    test "renders a refusal in the composer's own slot, keeping the draft", %{conn: conn} do
      id = session_id()

      pid =
        plane(
          id: id,
          status: :idle,
          backlogs: [{:ok, []}],
          answers: %{steer: [{:error, {:unavailable, "this turn is past the point of steering"}}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      html =
        view
        |> form("#composer", %{"message" => "too late"})
        |> render_submit(%{"verb" => "steer"})

      assert html =~ "ouro-composer-refusal"
      assert html =~ "this turn is past the point of steering"
      assert html =~ "too late"
    end
  end

  describe "changing the model mid-session" do
    test "fetches the catalogue when the row opens and never on the poll", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{model: "openai_codex:gpt-5.6-sol"})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      # Nothing is listed before the disclosure is opened.
      refute html =~ "ouro-model-select"
      assert html =~ "Model · openai_codex:gpt-5.6-sol"

      html = render_click(view, "composer-settings", %{})

      assert html =~ "ouro-model-select"
      assert html =~ "<option"
    end

    test "configures through the closed envelope and does not move the label itself",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{model: "already-running"})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_click(view, "composer-settings", %{})

      %{id: offered} = hd(Composer.model_rows(Ouroboros.Models.list()))

      html =
        view
        |> element("form[phx-change='configure-model']")
        |> render_change(%{"model" => offered})

      assert_receive {:configured, %{model: ^offered}}

      # The session still reports what it reported. The label follows the re-read.
      assert html =~ "Model · already-running"
    end

    test "a model this page never offered is not sent", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{model: "already-running"})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_click(view, "composer-settings", %{})

      # A `<select>`'s value is browser input, exactly as a `phx-value-choice` is.
      render_change(view, "configure-model", %{"model" => "not-in-the-catalogue"})
      refute_receive {:configured, _changes}, 100
    end

    test "the search narrows the rows and always keeps the running model", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{})

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_click(view, "composer-settings", %{})

      before = render(view) |> occurrences("<option")

      html =
        view
        |> form(".ouro-model-search", %{"query" => "zzzz-no-such-model"})
        |> render_change()

      assert occurrences(html, "<option") < before
    end
  end

  describe "the per-turn effort" do
    test "rides the structured envelope for one send, then forgets", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}], options: %{})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ "next turn:"

      html =
        view
        |> element(~s(button[phx-click="effort-next-turn"][phx-value-choice="high"]))
        |> render_click()

      assert html =~ "next turn: high"

      submit(view, "think about this")

      # `TurnInput::to_value`: the object form the moment there is something in it a
      # string could not carry, and the prompt beside it rather than instead of it.
      assert_receive {:sent, :message, _turn,
                      %{prompt: "think about this", reasoning_effort: :high}, []}

      # Spent. The next send is the bare string again, which is what the overwhelmingly
      # common turn has always put on the wire.
      refute render(view) =~ "next turn:"

      submit(view, "and this")
      assert_receive {:sent, :message, _turn, "and this", []}
    end

    test "a plain send with nothing armed stays a plain string", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      submit(view, "ship it")

      assert_receive {:sent, :message, _turn, "ship it", []}
    end

    test "Session default clears it without sending anything", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      view
      |> element(~s(button[phx-click="effort-next-turn"][phx-value-choice="low"]))
      |> render_click()

      html = render_click(view, "effort-next-turn", %{"choice" => "session"})

      refute html =~ "next turn:"
      refute_receive {:configured, _changes}, 100
    end

    test "an effort this model does not advertise is never armed", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html = render_click(view, "effort-next-turn", %{"choice" => "ludicrous"})
      refute html =~ "next turn:"

      submit(view, "ship it")
      assert_receive {:sent, :message, _turn, "ship it", []}
    end
  end

  describe "plan mode" do
    test "toggles through interactive.configure and says Planning while it is on",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{plan: true})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ">Planning<" or html =~ "Planning"
      assert html =~ ~s(phx-click="configure-plan" aria-pressed="true")

      render_click(view, "configure-plan", %{})

      # Off, because the session reported it was on: the toggle acts on what the operator
      # can see rather than on a posture this page assumed.
      assert_receive {:configured, %{plan: false}}
    end

    test "enters plan mode from a session that reported it was not planning", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ ">Planning<"

      view |> element(~s(button[phx-click="configure-plan"])) |> render_click()
      assert_receive {:configured, %{plan: true}}
    end

    test "renders the runtime's refusal verbatim rather than guessing", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          answers: %{
            configure: [
              {:error, {:unavailable, "this transport carries the plan posture on every launch"}}
            ]
          }
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html = render_click(view, "configure-plan", %{})

      assert html =~ "this transport carries the plan posture on every launch"
    end
  end

  describe "the composer's key hints" do
    test "names the send key and the stop key on the controls themselves", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert has_element?(view, "[data-ouro-send] kbd[aria-hidden=true]", "⏎")
      assert html =~ "<kbd>⌘K</kbd>"

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      working = flush(view)

      assert has_element?(view, "[data-ouro-interrupt] kbd[aria-hidden=true]", "esc")
      assert working =~ "data-ouro-interrupt"
    end
  end
end
