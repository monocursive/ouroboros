defmodule Ouroboros.Web.Live.DeckLiveW3Test do
  @moduledoc """
  W3 on the deck: the remaining verbs, each proved by the wire call it makes.

  The fake coordinator below answers the same `GenServer.call` messages
  `Ouroboros.InteractiveSession` sends, so every test here goes through the real gateway
  method table, the real parameter contract and `Ouroboros.Web.Call` — which is the only
  way to prove that what travels is what the terminal client sends. Where a message is
  asserted on, its shape is the assertion: `{:rewind, 2, "files"}` is a claim about the
  wire, not about this page.

  `@tag scope: :read` moves the whole endpoint to read scope for one test, because the
  scope is fixed at boot (`Ouroboros.Web.Call`) and a flag flipped mid-test would be
  testing a hole.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("w", 40)
  @cookie "_ouroboros_web"

  # ------------------------------------------------------------------------------------
  # The fake coordinator
  # ------------------------------------------------------------------------------------

  defmodule Plane do
    @moduledoc false
    use GenServer

    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      {:ok, _owner} = Registry.register(Ouroboros.Interactive.Registry, id, nil)

      {:ok,
       %{
         id: id,
         test: Keyword.fetch!(opts, :test),
         status: Keyword.get(opts, :status, :running),
         options: Keyword.get(opts, :options, %{}),
         workspace: Keyword.get(opts, :workspace, "/tmp/w"),
         backlog: Keyword.get(opts, :backlog, []),
         answers: Keyword.get(opts, :answers, %{}),
         subscribers: []
       }}
    end

    @impl true
    def handle_call(:info, _from, state), do: {:reply, {:ok, session(state)}, state}

    def handle_call({:subscribe, subscriber, _cursor}, _from, state) do
      {:reply, {:ok, state.backlog},
       %{state | subscribers: Enum.uniq([subscriber | state.subscribers])}}
    end

    def handle_call({:unsubscribe, subscriber}, _from, state),
      do: {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}

    # A bounded window of the backlog, the way the plane answers one: exclusive cursor.
    def handle_call({:replay, cursor, limit}, _from, state) do
      send(state.test, {:replayed, cursor, limit})

      window =
        state.backlog
        |> Enum.filter(&(&1.sequence > cursor))
        |> Enum.take(limit)

      {:reply, {:ok, window}, state}
    end

    def handle_call(:rewind_points, _from, state),
      do: answer(state, :rewind_points, {:ok, []})

    def handle_call({:rewind, to_turn, what}, _from, state) do
      send(state.test, {:rewound, to_turn, what})
      answer(state, :rewind, {:ok, %{restored: [], unrestorable: [], turns: [], messages: 0}})
    end

    def handle_call({:compact, focus}, _from, state) do
      send(state.test, {:compacted, focus})
      answer(state, :compact, {:ok, %{trigger: "manual", archived_messages: 1}})
    end

    def handle_call(:context, _from, state), do: answer(state, :context, {:ok, %{source: :usage}})

    def handle_call({:handoff_plan, prompt, child}, _from, state) do
      send(state.test, {:handoff_planned, prompt, child})
      {:reply, {:error, :handoff_refused_by_this_fake}, state}
    end

    def handle_call({:fork_plan, child, overrides}, _from, state) do
      send(state.test, {:fork_planned, child, overrides})
      {:reply, {:error, :fork_refused_by_this_fake}, state}
    end

    def handle_call({:exec_plan, command}, _from, state) do
      send(state.test, {:exec_planned, command})
      answer(state, :exec_plan, {:error, {:shell_refused, %{reason: :no_plan_scripted}}})
    end

    def handle_call({:exec_settled, effect_id, _outcome}, _from, state) do
      send(state.test, {:exec_settled, effect_id})
      {:reply, :ok, state}
    end

    def handle_call(message, _from, state) do
      send(state.test, {:unexpected, message})
      {:reply, {:error, :not_scripted}, state}
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
        provider: :native,
        workspace: state.workspace,
        workspace_mode: :shared_read,
        status: state.status,
        options: state.options,
        created_at: "2026-09-15T10:00:00Z",
        updated_at: "2026-09-15T12:00:00Z"
      }
    end
  end

  # ------------------------------------------------------------------------------------
  # Harness
  # ------------------------------------------------------------------------------------

  setup context do
    dir = Path.join(System.tmp_dir!(), "ouro-w3-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: Map.get(context, :scope, :operate))
    start_supervised!({Ouroboros.Web, config: config, server: false})

    conn = get(build_conn(), "/auth?token=#{@token}")
    {:ok, conn: put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)}
  end

  defp session_id, do: "w3-#{System.unique_integer([:positive])}"

  defp plane(opts) do
    {:ok, pid} = Plane.start(Keyword.put(opts, :test, self()))
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  # A durable row, so the rail names an owner node and `session_params/3` routes.
  defp listed(id, opts \\ []) do
    session = %State{
      id: id,
      node: node(),
      title: Keyword.get(opts, :title, "W3"),
      title_source: :human,
      provider: :native,
      workspace: Keyword.get(opts, :workspace, "/tmp/w"),
      workspace_mode: :shared_read,
      status: Keyword.get(opts, :status, :running),
      options: opts |> Keyword.get(:options, %{}) |> Map.put(:runtime_exposure, false),
      created_at: "2026-09-15T10:00:00Z",
      updated_at: "2026-09-15T12:00:00Z"
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
      timestamp: "2026-09-15T12:00:0#{rem(sequence, 10)}Z",
      payload: payload,
      turn_id: "t1"
    }
  end

  defp said(sequence, text), do: event(sequence, :output_text_final, %{"text" => text})
  defp asked(sequence, text), do: event(sequence, :input_accepted, %{"text" => text})

  defp steered(sequence, text),
    do: event(sequence, :input_accepted, %{"text" => text, "kind" => "steer"})

  defp open_deck(conn, id) do
    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
    view
  end

  defp run(view, id), do: render_hook(view, "palette-run", %{"id" => id})

  # Scopes an assertion to one panel. The whole page also holds the transcript, and a
  # steer the dialog is supposed to exclude is still a cell in the conversation above it.
  defp dialog_html(html, id) do
    case Regex.run(~r{<dialog[^>]*id="#{id}".*?</dialog>}s, html) do
      [whole] -> whole
      nil -> ""
    end
  end

  defp offered_rows(html) do
    ~r/id="ouro-palette-row-([^"]+)"/
    |> Regex.scan(html)
    |> Enum.map(&List.last/1)
  end

  # ------------------------------------------------------------------------------------
  # W3.1 — the event ledger
  # ------------------------------------------------------------------------------------

  describe "W3.1 event details" do
    test "lists one row per held event, and never hides a divider", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      # A backlog starting at 4 proves a prune: the watch raises its floor and the panel
      # has to say so.
      _plane = plane(id: id, backlog: [said(4, "after the hole"), said(5, "and then")])

      view = open_deck(conn, id)
      html = run(view, "conversation.details")

      assert html =~ ~s(id="ouro-details")
      assert html =~ "output_text_final"
      assert html =~ "after the hole"
      assert html =~ "history truncated below 3"
    end

    test "expands one event to the wire object the runtime framed", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [said(1, "hello")])

      view = open_deck(conn, id)
      run(view, "conversation.details")
      html = render_click(view, "w3-details-toggle", %{"sequence" => "1"})

      assert html =~ "ouro-details-json"
      # `Gateway.Wire` tags the struct and keeps the envelope, which is the whole point:
      # this is the object a socket client was sent, not a re-derivation of it.
      assert html =~ "_struct"
      assert html =~ "output_text_final"
    end

    test "a fetch asks interactive.event_detail for that exact sequence", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [said(7, "capped")])

      view = open_deck(conn, id)
      run(view, "conversation.details")
      render_click(view, "w3-details-fetch", %{"sequence" => "7"})

      # `with_event_detail` is `replay` with a window of one from an exclusive cursor.
      assert_receive {:replayed, 6, 1}, 500
    end

    test "a sequence the browser made up asks the runtime nothing", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [said(1, "hello")])

      view = open_deck(conn, id)
      run(view, "conversation.details")

      render_click(view, "w3-details-fetch", %{"sequence" => "not-a-number"})
      render_click(view, "w3-details-toggle", %{"sequence" => "-4"})

      refute_receive {:replayed, _cursor, 1}, 300
      assert Process.alive?(view.pid)
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.2 — export
  # ------------------------------------------------------------------------------------

  describe "W3.2 export" do
    test "the vitals disclosure carries a link to the file", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      html = render(open_deck(conn, id))
      assert html =~ "/s/interactive/#{id}/export?format=text"
    end

    test "the palette row offers both forms and says what each holds", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      html = run(view, "conversation.export")

      assert html =~ ~s(id="ouro-export")
      assert html =~ "Readable text"
      assert html =~ "NDJSON"
      assert html =~ "nothing added"
    end

    test "a format this page never drew navigates nowhere", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "conversation.export")
      render_click(view, "w3-export", %{"format" => "sqlite"})

      assert Process.alive?(view.pid)
      assert render(view) =~ ~s(id="ouro-export")
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.3 — backtrack and fork
  # ------------------------------------------------------------------------------------

  describe "W3.3 backtrack" do
    test "lists the user's own turns and excludes steers", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          backlog: [
            asked(1, "the first thing"),
            said(2, "an answer"),
            steered(3, "a steer nobody backtracks to"),
            asked(4, "the second thing")
          ]
        )

      view = open_deck(conn, id)
      dialog = view |> run("conversation.backtrack") |> dialog_html("ouro-backtrack")

      assert dialog =~ "the first thing"
      assert dialog =~ "the second thing"

      # The steer is a cell in the transcript above — it happened — and it is not a turn
      # to go back to, so it is not in this list.
      refute dialog =~ "a steer nobody backtracks to"
    end

    test "says in words that nothing is removed, and that the runtime picks the branch",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [asked(1, "go")])

      view = open_deck(conn, id)
      html = run(view, "conversation.backtrack")

      assert html =~ "Nothing between here and there"
      assert html =~ "Where the branch starts is the transport"
      assert html =~ "does not promise it begins at the message you"
    end

    test "edit and resend puts the message in the composer and sends nothing", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [asked(3, "the earlier message")])

      view = open_deck(conn, id)
      run(view, "conversation.backtrack")
      html = render_click(view, "w3-backtrack-edit", %{"sequence" => "3"})

      assert html =~ "the earlier message"
      assert html =~ "Nothing earlier was removed"
      refute_receive {:unexpected, _message}, 200
    end

    test "a fork sends interactive.fork with the session and no message", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [asked(1, "go")])

      view = open_deck(conn, id)
      run(view, "conversation.backtrack")
      render_click(view, "w3-backtrack-fork", %{})

      # The verb takes a session and a routing node, which is exactly why this client
      # promises nothing about where the branch starts.
      assert_receive {:fork_planned, _child, overrides}, 1_000
      assert overrides.to_turn == nil
      assert overrides.model == nil
    end

    test "and a transport that declared fork: false gets no fork control", %{conn: conn} do
      id = session_id()
      _row = listed(id, options: %{capabilities: %{fork: false}})
      _plane = plane(id: id, options: %{capabilities: %{fork: false}}, backlog: [asked(1, "go")])

      view = open_deck(conn, id)
      html = run(view, "conversation.backtrack")

      refute html =~ ~s(phx-click="w3-backtrack-fork")
      refute "session.fork" in offered_rows(render_hook(view, "palette-open", %{}))

      # And the handler asks the same question the button is drawn from.
      render_click(view, "w3-backtrack-fork", %{})
      refute_receive {:fork_planned, _child, _overrides}, 300
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.4 — rewind
  # ------------------------------------------------------------------------------------

  describe "W3.4 rewind" do
    defp points do
      [
        %{
          "turn_id" => "t-one",
          "at" => "2026-09-15T11:00:00Z",
          "files" => 2,
          "paths" => ["a.ex", "b.ex"],
          "commands" => 0,
          "restorable" => 2,
          "dropped_turns" => 0
        },
        %{
          "turn_id" => "t-two",
          "at" => "2026-09-15T11:30:00Z",
          "files" => 3,
          "paths" => ["c.ex"],
          "commands" => 2,
          "restorable" => 1,
          "dropped_turns" => 0
        }
      ]
    end

    test "screen one carries every row's own warning, before anything is chosen",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, points()}]})

      view = open_deck(conn, id)
      html = run(view, "conversation.rewind")

      assert html =~ "2 shell commands ran in it"
      assert html =~ "2 of 3 files have no snapshot"
      # And nothing has been sent.
      refute_receive {:rewound, _to_turn, _what}, 200
    end

    test "screen two repeats the warning and offers the three-way choice", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, points()}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      html = render_click(view, "w3-rewind-pick", %{"choice" => "1"})

      assert html =~ "2 shell commands ran in it"
      assert html =~ "the files and the conversation"
      assert html =~ "the files only"
      assert html =~ "the conversation only"
      refute_receive {:rewound, _to_turn, _what}, 200
    end

    test "only the second confirm sends, and to_turn is the 1-based position",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, points()}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-pick", %{"choice" => "1"})
      render_click(view, "w3-rewind-what", %{"what" => "files"})
      render_click(view, "w3-rewind-confirm", %{})

      # Position 1 in the list is turn 2 on the wire, and `what` is the word chosen.
      assert_receive {:rewound, 2, :files}, 1_000
    end

    test "a confirm before the second screen sends nothing", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, points()}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-confirm", %{})

      refute_receive {:rewound, _to_turn, _what}, 300
    end

    test "a `what` this dialog never drew is refused rather than passed through",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, points()}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-pick", %{"choice" => "0"})
      render_click(view, "w3-rewind-what", %{"what" => "everything"})
      render_click(view, "w3-rewind-confirm", %{})

      # The closed enum held: `both` is what the dialog still had selected.
      assert_receive {:rewound, 1, :both}, 1_000
    end

    test "restored and unrestorable are drawn as two blocks and never merged",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            rewind_points: [{:ok, points()}],
            rewind: [
              {:ok,
               %{
                 restored: [%{path: "kept.ex", action: "restored"}],
                 unrestorable: [%{path: "lost.ex", reason: "no snapshot was taken"}],
                 turns: ["t-two"],
                 messages: 4
               }}
            ]
          }
        )

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-pick", %{"choice" => "1"})
      html = render_click(view, "w3-rewind-confirm", %{})

      assert html =~ "Restored"
      assert html =~ "kept.ex"
      assert html =~ "Could not be restored"
      assert html =~ "lost.ex"
      assert html =~ "no snapshot was taken"

      # And the conversation records what the operator's own verb did.
      assert html =~ "Rewound to t-two"
    end

    test "a runtime refusal is rendered in the runtime's own words", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{rewind_points: [{:error, {:unavailable, "no checkpoints here"}}]}
        )

      view = open_deck(conn, id)
      html = run(view, "conversation.rewind")

      assert html =~ "no checkpoints here"
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.5 — compact
  # ------------------------------------------------------------------------------------

  describe "W3.5 compact" do
    test "sends interactive.compact with the focus and draws the report as a block",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            compact: [
              {:ok,
               %{
                 trigger: "manual",
                 archived_messages: 12,
                 elided_tool_results: 3,
                 before_tokens: 900,
                 after_tokens: 120,
                 archive_id: "arch-1"
               }}
            ]
          }
        )

      view = open_deck(conn, id)
      run(view, "conversation.compact")

      html =
        view
        |> element(~s(form[phx-submit="w3-compact"]))
        |> render_submit(%{"focus" => "the migration"})

      assert_receive {:compacted, "the migration"}, 1_000

      # The transcript's own compaction block, not a second rendering beside it.
      assert html =~ "Compacted, at your request"
      assert html =~ "archived 12 messages"
      assert html =~ "900 → 120 tokens"
    end

    test "a blank focus is absent rather than an empty string", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "conversation.compact")
      render_click(view, "w3-compact", %{"focus" => "   "})

      assert_receive {:compacted, nil}, 1_000
    end

    test "and the context is re-read afterwards rather than inferred", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            compact: [{:ok, %{trigger: "manual"}}],
            context: [{:ok, %{source: :native, context_used: 120, context_window: 1000}}]
          }
        )

      view = open_deck(conn, id)
      run(view, "conversation.compact")
      html = render_click(view, "w3-compact", %{"focus" => ""})

      # The meter now reads what the verb measured, not what the list row carried.
      assert html =~ "120 / 1000 tokens"
    end

    test "a transport that is not native is offered no compaction at all", %{conn: conn} do
      id = session_id()
      _row = listed(id, options: %{capabilities: %{transport: "managed"}})
      _plane = plane(id: id, options: %{capabilities: %{transport: "managed"}})

      view = open_deck(conn, id)
      refute "conversation.compact" in offered_rows(render_hook(view, "palette-open", %{}))

      run(view, "conversation.compact")
      render_click(view, "w3-compact", %{"focus" => ""})
      refute_receive {:compacted, _focus}, 300
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.6 — handoff
  # ------------------------------------------------------------------------------------

  describe "W3.6 handoff" do
    test "mints the child's id itself and sends it with the prompt", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "session.handoff")

      view
      |> element(~s(form[phx-submit="w3-handoff"]))
      |> render_submit(%{"prompt" => "finish the migration"})

      assert_receive {:handoff_planned, "finish the migration", child}, 2_000
      assert is_binary(child) and String.starts_with?(child, "web-handoff-")
      assert byte_size(child) <= 128
    end

    test "says the parent keeps running before it is pressed", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      html = run(view, "session.handoff")

      assert html =~ "keeps running"
    end

    test "a refusal is the runtime's own words, and no child is opened", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "session.handoff")
      html = render_click(view, "w3-handoff", %{"prompt" => ""})

      assert html =~ "the runtime refused the call"
      assert render(view) =~ ~s(id="ouro-handoff")
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.7 — context
  # ------------------------------------------------------------------------------------

  describe "W3.7 context" do
    test "the first line is source, and a non-native answer is labelled a subset",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            context: [
              {:ok,
               %{
                 source: :usage,
                 transport: "managed",
                 total_tokens: 1234,
                 context_used: nil,
                 context_window: nil
               }}
            ]
          }
        )

      view = open_deck(conn, id)
      html = run(view, "conversation.context")

      assert html =~ "Source"
      assert html =~ "usage"
      assert html =~ "A subset"
      # The native headings are absent rather than empty.
      refute html =~ "Prefix fingerprint"
      refute html =~ "Instruction files loaded"
    end

    test "a native answer carries the fingerprint, the meter and the instruction files",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            context: [
              {:ok,
               %{
                 source: :native,
                 transport: :native,
                 context_used: 4_000,
                 context_window: 16_000,
                 context_state: :measured,
                 prefix_fingerprint: "abc123",
                 messages: 42,
                 compactions: [%{trigger: "manual", archived_messages: 2}],
                 archive_ids: ["arch-7"],
                 instruction_files: ["/w/AGENTS.md"],
                 instruction_files_dropped: [
                   %{path: "/w/BIG.md", bytes: 900_000, reason: "over the budget"}
                 ]
               }}
            ]
          }
        )

      view = open_deck(conn, id)
      html = run(view, "conversation.context")

      assert html =~ "native"
      assert html =~ "abc123"
      assert html =~ "4000 / 16000 tokens"
      assert html =~ "arch-7"
      assert html =~ "/w/AGENTS.md"
      assert html =~ "/w/BIG.md"
      assert html =~ "over the budget"
      assert html =~ "archived 2 messages"
    end

    test "the vitals meter reads the same answer once it has been asked", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{context: [{:ok, %{source: :native, context_used: 50, context_window: 200}}]}
        )

      view = open_deck(conn, id)
      refute render(view) =~ "50 / 200 tokens"

      run(view, "conversation.context")
      html = render_click(view, "w3-close", %{})

      assert html =~ "50 / 200 tokens", "the vitals meter is still inferring rather than reading"
    end

    test "a window with only one half reported gets no bar", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(id: id, answers: %{context: [{:ok, %{source: :native, context_used: 50}}]})

      view = open_deck(conn, id)
      html = run(view, "conversation.context")

      assert html =~ "no window reported"
      refute html =~ "ouro-meter-fill"
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.8 — the operator shell
  # ------------------------------------------------------------------------------------

  describe "W3.8 `!`" do
    test "the composer says where a `!` will run before Enter is pressed", %{conn: conn} do
      id = session_id()
      _row = listed(id, workspace: "/tmp/the-workspace")
      _plane = plane(id: id, workspace: "/tmp/the-workspace")

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "!ls"}) |> render_change()

      assert html =~ "runs this on"
      assert html =~ "/tmp/the-workspace"
      assert html =~ "not a message to the agent"
    end

    test "and an ordinary draft says nothing of the kind", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "hello!"}) |> render_change()

      refute html =~ "ouro-shell-where"
    end

    test "sending one runs workspace.exec and never a turn", %{conn: conn} do
      id = session_id()
      workspace = Path.join(System.tmp_dir!(), "ouro-w3-ws-#{System.unique_integer([:positive])}")
      File.mkdir_p!(workspace)
      on_exit(fn -> File.rm_rf(workspace) end)

      _row = listed(id, workspace: workspace)

      _plane =
        plane(
          id: id,
          workspace: workspace,
          answers: %{
            exec_plan: [
              {:ok,
               %{
                 effect_id: "eff-1",
                 cwd: workspace,
                 timeout_ms: 10_000,
                 spill_dir: workspace
               }}
            ]
          }
        )

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "!echo w3-was-here"}) |> render_submit()

      assert_receive {:exec_planned, "echo w3-was-here"}, 5_000
      assert_receive {:exec_settled, "eff-1"}, 5_000
      # Never a turn: nothing reached `send_message`.
      refute_receive {:unexpected, {:send_turn, _mode, _id, _input, _opts}}, 200

      # The reply is drawn through the transcript's own runtime block.
      assert html =~ "$ echo w3-was-here"
      assert html =~ "exit 0"
      assert html =~ "w3-was-here"
    end

    test "a shell_refused shows the runtime's message, the rule and the suggestion",
         %{conn: conn} do
      id = session_id()
      _row = listed(id, workspace: "/tmp/the-workspace")

      _plane =
        plane(
          id: id,
          workspace: "/tmp/the-workspace",
          answers: %{
            exec_plan: [
              {:error,
               {:shell_refused,
                %{
                  reason: :rule_denied,
                  workspace: "/tmp/the-workspace",
                  denied_by: %{scope: :workspace, id: "r-1", pattern: "Bash(rm:*)"},
                  suggested_rule: "Bash(echo:*)",
                  message: "the permission engine denied this command"
                }}}
            ]
          }
        )

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "!echo hi"}) |> render_submit()

      assert html =~ "the permission engine denied this command"
      assert html =~ "Bash(rm:*)"
      assert html =~ "Bash(echo:*)"
      assert html =~ "Remember for this workspace"
      # And the draft is handed back exactly as it was typed.
      assert html =~ "!echo hi"
    end

    test "Remember calls permissions.add the way the approval card's does", %{conn: conn} do
      id = session_id()
      _row = listed(id, workspace: "/tmp/the-workspace")

      _plane =
        plane(
          id: id,
          workspace: "/tmp/the-workspace",
          answers: %{
            exec_plan: [
              {:error,
               {:shell_refused,
                %{
                  reason: :rule_denied,
                  workspace: "/tmp/the-workspace",
                  suggested_rule: "Bash(echo:*)",
                  message: "denied"
                }}}
            ]
          }
        )

      view = open_deck(conn, id)
      view |> form("#composer", %{"message" => "!echo hi"}) |> render_submit()

      # The rule store is the real one; what matters is that the verb was reached and the
      # offer is gone afterwards rather than left standing over a written rule.
      html = render_click(view, "w3-shell-remember", %{})
      refute html =~ "Remember for this workspace"
    end

    test "a refusal with no suggested rule grows no offer", %{conn: conn} do
      id = session_id()
      _row = listed(id, workspace: "/tmp/the-workspace")

      _plane =
        plane(
          id: id,
          workspace: "/tmp/the-workspace",
          answers: %{
            exec_plan: [
              {:error,
               {:shell_refused, %{reason: :not_permitted, message: "this session may not"}}}
            ]
          }
        )

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "!echo hi"}) |> render_submit()

      assert html =~ "this session may not"
      refute html =~ "Remember for this workspace"
    end

    test "a bare `!` asks the runtime nothing", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      html = view |> form("#composer", %{"message" => "!   "}) |> render_submit()

      assert html =~ "Type a command after the !"
      refute_receive {:exec_planned, _command}, 300
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.9 — MCP
  # ------------------------------------------------------------------------------------

  describe "W3.9 MCP servers" do
    test "reads the node's list fresh and offers no control that changes it", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      html = run(view, "runtime.mcp")

      assert html =~ ~s(id="ouro-mcp")
      assert html =~ "MCP servers"
      # Nothing here starts, stops or restarts anything.
      refute html =~ "phx-click=\"w3-mcp-restart\""
      refute html =~ "Restart"
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.10 — the gates the composer was missing
  # ------------------------------------------------------------------------------------

  describe "W3.10 dynamic_configuration" do
    test "a declared false withholds the sandbox and thinking pickers", %{conn: conn} do
      id = session_id()

      options = %{
        sandbox_mode: :workspace_write,
        capabilities: %{dynamic_configuration: false}
      }

      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      html = render(open_deck(conn, id))

      refute html =~ ~s(phx-value-field="sandbox_mode")
      refute html =~ ~s(phx-value-field="reasoning_effort")
    end

    test "and the handler refuses the click the picker never drew", %{conn: conn} do
      id = session_id()

      options = %{
        sandbox_mode: :workspace_write,
        capabilities: %{dynamic_configuration: false}
      }

      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      view = open_deck(conn, id)

      render_click(view, "configure", %{"field" => "sandbox_mode", "choice" => "unrestricted"})
      refute_receive {:unexpected, {:configure, _changes}}, 300
    end

    test "silence keeps both pickers, because a gateway that said nothing set no ceiling",
         %{conn: conn} do
      id = session_id()
      options = %{sandbox_mode: :workspace_write}
      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      html = render(open_deck(conn, id))

      assert html =~ ~s(phx-value-field="sandbox_mode")
      assert html =~ ~s(phx-value-field="reasoning_effort")
    end

    test "and a model-only transport keeps its model picker", %{conn: conn} do
      id = session_id()

      options = %{
        sandbox_mode: :workspace_write,
        capabilities: %{dynamic_configuration: false, dynamic_model: "native"}
      }

      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      html = render(open_deck(conn, id))

      refute html =~ ~s(phx-value-field="sandbox_mode")
      assert html =~ "ouro-composer-settings"
    end
  end

  describe "W3.10 send_turn re-checks what the composer is drawn from" do
    test "an ended session takes no hand-made send", %{conn: conn} do
      id = session_id()
      _row = listed(id, status: :closed)
      _plane = plane(id: id, status: :closed)

      view = open_deck(conn, id)
      refute render(view) =~ ~s(id="composer")

      render_submit(view, "send", %{"message" => "speak to the dead"})
      refute_receive {:unexpected, {:send_turn, _mode, _turn, _input, _opts}}, 300
    end
  end

  # ------------------------------------------------------------------------------------
  # W3.12 — read scope
  # ------------------------------------------------------------------------------------

  describe "at read scope" do
    @tag scope: :read
    test "no mutating W3 row is drawn", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      offered = offered_rows(render_hook(view, "palette-open", %{}))

      for row <- ~w(session.fork session.handoff turn.shell conversation.compact
                    conversation.rewind) do
        refute row in offered, "#{row} is drawn at read scope"
      end
    end

    @tag scope: :read
    test "and a hand-made event for any of them is a no-op", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)

      render_click(view, "w3-compact", %{"focus" => "anything"})
      render_click(view, "w3-backtrack-fork", %{})
      render_click(view, "w3-handoff", %{"prompt" => "anything"})
      render_click(view, "w3-rewind-confirm", %{})
      render_submit(view, "send", %{"message" => "!echo forged"})

      refute_receive {:compacted, _focus}, 300
      refute_receive {:fork_planned, _child, _overrides}, 100
      refute_receive {:handoff_planned, _prompt, _child}, 100
      refute_receive {:rewound, _to_turn, _what}, 100
      refute_receive {:exec_planned, _command}, 100

      assert Process.alive?(view.pid)
    end

    @tag scope: :read
    test "but the three reading verbs still work", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [said(1, "hello")])

      view = open_deck(conn, id)
      offered = offered_rows(render_hook(view, "palette-open", %{}))

      for row <- ~w(conversation.details conversation.export conversation.context runtime.mcp) do
        assert row in offered, "#{row} is withheld at read scope and its method is read-scope"
      end

      assert run(view, "conversation.details") =~ ~s(id="ouro-details")
    end
  end

  # ------------------------------------------------------------------------------------
  # State belongs to the conversation it was read in
  # ------------------------------------------------------------------------------------

  describe "panel state" do
    test "does not follow a reader into the next session", %{conn: conn} do
      first = session_id()
      second = session_id()
      _row_one = listed(first, title: "First")
      _row_two = listed(second, title: "Second")

      _plane_one =
        plane(
          id: first,
          answers: %{context: [{:ok, %{source: :native, context_used: 7, context_window: 9}}]}
        )

      _plane_two = plane(id: second)

      view = open_deck(conn, first)
      assert run(view, "conversation.context") =~ "7 / 9 tokens"

      html = render_patch(view, "/s/interactive/#{second}")

      refute html =~ ~s(id="ouro-context")
      refute html =~ "7 / 9 tokens"
    end

    test "and a panel never opens over a confirmation nobody has answered", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Alpha")
      _plane = plane(id: id)

      view = open_deck(conn, id)

      render_click(view, "session-action", %{
        "action" => "rename",
        "plane" => "interactive",
        "id" => id
      })

      html = run(view, "conversation.details")

      assert html =~ ~s(id="session-action-dialog")
      refute html =~ ~s(id="ouro-details")
    end
  end
end
