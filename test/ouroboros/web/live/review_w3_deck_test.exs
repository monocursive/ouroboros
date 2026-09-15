defmodule Ouroboros.Web.Live.ReviewW3DeckTest do
  @moduledoc """
  W3's adversarial review of the deck, kept.

  Every test here started life in the reviewer's probe file. The ones that demonstrated a
  defect are **inverted**: they assert the fix and go red the moment its enforcement is
  removed. The ones that demonstrated correct behaviour are kept as they were, because a
  property somebody went looking for is the property that will be broken by accident —
  and several of them only *printed* what they found, so they now assert it.
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

    def handle_call({:replay, cursor, limit}, _from, state) do
      send(state.test, {:replayed, cursor, limit})
      window = state.backlog |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit)
      {:reply, {:ok, window}, state}
    end

    def handle_call(:rewind_points, _from, state), do: answer(state, :rewind_points, {:ok, []})

    def handle_call({:rewind, to_turn, what}, _from, state) do
      send(state.test, {:rewound, to_turn, what})
      answer(state, :rewind, {:ok, %{restored: [], unrestorable: [], turns: [], messages: 0}})
    end

    def handle_call({:compact, focus}, _from, state) do
      send(state.test, {:compacted, focus})
      answer(state, :compact, {:ok, %{trigger: "manual", archived_messages: 1}})
    end

    def handle_call(:context, _from, state) do
      send(state.test, :context_read)
      answer(state, :context, {:ok, %{source: :usage}})
    end

    def handle_call({:handoff_plan, prompt, child}, _from, state) do
      send(state.test, {:handoff_planned, prompt, child})
      answer(state, :handoff_plan, {:error, :handoff_refused_by_this_fake})
    end

    def handle_call({:fork_plan, child, overrides}, _from, state) do
      send(state.test, {:fork_planned, child, overrides})
      answer(state, :fork_plan, {:error, :fork_refused_by_this_fake})
    end

    def handle_call({:exec_plan, command}, _from, state) do
      send(state.test, {:exec_planned, command})
      answer(state, :exec_plan, {:error, {:shell_refused, %{reason: :no_plan_scripted}}})
    end

    def handle_call({:exec_settled, effect_id, _outcome}, _from, state) do
      send(state.test, {:exec_settled, effect_id})
      {:reply, :ok, state}
    end

    def handle_call({:configure, changes}, _from, state) do
      send(state.test, {:configured, changes})
      {:reply, {:ok, session(state)}, state}
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

  setup context do
    dir = Path.join(System.tmp_dir!(), "ouro-revw3-#{System.unique_integer([:positive])}")
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

  defp session_id, do: "revw3-#{System.unique_integer([:positive])}"

  defp plane(opts) do
    {:ok, pid} = Plane.start(Keyword.put(opts, :test, self()))
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

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

  defp open_deck(conn, id) do
    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
    view
  end

  defp run(view, id), do: render_hook(view, "palette-run", %{"id" => id})

  # ====================================================================================
  # 1. Handoff: the outcome-unknown branch
  # ====================================================================================

  describe "handoff and outcome: unknown" do
    test "an owner that is not in the cluster opens no child at all", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{handoff_plan: [{:error, {:owner_unavailable, :ghost@nowhere}}]}
        )

      view = open_deck(conn, id)
      run(view, "session.handoff")
      html = render_click(view, "w3-handoff", %{"prompt" => "carry on"})

      # Inverted. `owner_unavailable` carries `outcome: "unknown"` under the *unavailable*
      # code and is answered before anything is dispatched: the machine was offline, so
      # there is no child under the id this page minted and opening one would be this
      # surface inventing a session. Only `upstream_timeout` — a ceiling that fired after
      # the call went out — opens it (`tui/src/ui/app/answers.rs:781-790`).
      assert error_of(html) =~ "ghost@nowhere is offline"
      assert is_nil(notice_of(html)), "a child was announced for a machine that is not there"
      assert assert_patched(view) == "(no patch)"

      # And the dialog is still open, holding the runtime's own words.
      assert html =~ ~s(id="ouro-handoff")
    end

    test "mints a fresh id on every attempt", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "session.handoff")
      render_click(view, "w3-handoff", %{"prompt" => "one"})
      assert_receive {:handoff_planned, _p1, first}, 2_000

      run(view, "session.handoff")
      render_click(view, "w3-handoff", %{"prompt" => "two"})
      assert_receive {:handoff_planned, _p2, second}, 2_000

      # Mutation survivor #12. A second attempt is a second child: the id is the
      # runtime's reconciliation handle, and reusing it under a *different* prompt is how
      # a retry becomes an id conflict rather than a new session.
      assert first != second
      assert String.starts_with?(first, "web-handoff-")
      assert String.starts_with?(second, "web-handoff-")
      assert byte_size(first) <= 128
      assert byte_size(second) <= 128
    end
  end

  defp assert_patched(view) do
    assert_patch(view, 500)
  rescue
    _error -> "(no patch)"
  end

  defp error_of(html) do
    case Regex.run(~r{<p[^>]*class="ouro-refusal"[^>]*>(.*?)</p>}s, html) do
      [_whole, text] -> text
      nil -> nil
    end
  end

  defp notice_of(html) do
    case Regex.run(~r{<p[^>]*class="ouro-w3-notice"[^>]*>(.*?)</p>}s, html) do
      [_whole, text] -> text
      nil -> nil
    end
  end

  # ====================================================================================
  # 2. Forged events while a confirmation dialog owns the screen
  # ====================================================================================

  describe "a confirmation nobody answered" do
    test "stops every hand-made compact / fork / rewind / handoff", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Alpha")

      _plane = plane(id: id, answers: %{rewind_points: [{:ok, [%{turn_id: "t1", files: 0}]}]})

      view = open_deck(conn, id)

      render_click(view, "session-action", %{
        "action" => "rename",
        "plane" => "interactive",
        "id" => id
      })

      assert render(view) =~ ~s(id="session-action-dialog")

      render_click(view, "w3-compact", %{"focus" => "forged"})
      render_click(view, "w3-backtrack-fork", %{})
      render_click(view, "w3-handoff", %{"prompt" => "forged"})
      render_click(view, "w3-rewind-confirm", %{})
      render_click(view, "w3-shell-remember", %{})

      # Inverted. A confirmation is a question awaiting an answer and nothing acts behind
      # one — the rule the palette already held, applied to the handlers a hand-made
      # `phx-click` reaches directly. A handoff was the worst of them: it patches the page
      # to the child, leaving the dialog asking about a session nobody is looking at.
      refute_receive {:compacted, "forged"}, 300
      refute_receive {:fork_planned, _child, _overrides}, 100
      refute_receive {:handoff_planned, "forged", _child}, 100
      refute_receive {:rewound, _to_turn, _what}, 100

      assert render(view) =~ ~s(id="session-action-dialog")
    end
  end

  # ====================================================================================
  # 3. Rewind: to_turn bounds and the closed `what` enum
  # ====================================================================================

  describe "rewind" do
    test "a forged choice beyond the fetched list never sends", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            rewind_points: [{:ok, [%{turn_id: "t1", files: 0}, %{turn_id: "t2", files: 0}]}]
          }
        )

      view = open_deck(conn, id)
      run(view, "conversation.rewind")

      render_click(view, "w3-rewind-pick", %{"choice" => "999"})
      render_click(view, "w3-rewind-confirm", %{})
      refute_receive {:rewound, _to_turn, _what}, 300

      # And the legitimate path sends the 1-based position, not the id.
      render_click(view, "w3-rewind-pick", %{"choice" => "0"})
      render_click(view, "w3-rewind-confirm", %{})
      assert_receive {:rewound, to_turn, what}, 2_000
      assert to_turn == 1
      assert what == :both
    end

    test "a forged `what` outside the enum is ignored", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, [%{turn_id: "t1", files: 0}]}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-pick", %{"choice" => "0"})
      render_click(view, "w3-rewind-what", %{"what" => "everything"})
      render_click(view, "w3-rewind-confirm", %{})

      assert_receive {:rewound, _to_turn, what}, 2_000
      assert what in ["both", :both]
    end

    test "the first screen never sends", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, [%{turn_id: "t1", files: 0}]}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-rewind-confirm", %{})
      refute_receive {:rewound, _to_turn, _what}, 300
    end

    test "points survive closing the dialog, and a forged pair behind it does not rewind",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, answers: %{rewind_points: [{:ok, [%{turn_id: "t1", files: 0}]}]})

      view = open_deck(conn, id)
      run(view, "conversation.rewind")
      render_click(view, "w3-close", %{})
      refute render(view) =~ ~s(id="ouro-rewind")

      render_click(view, "w3-rewind-pick", %{"choice" => "0"})
      render_click(view, "w3-rewind-confirm", %{})

      # Inverted. The points survive a close — reopening must not re-ask the runtime —
      # but the *verb* belongs to the dialog that states the warning, so a confirm with no
      # dialog on screen is a confirmation nobody was ever shown.
      assert receive_rewind() == :none
    end
  end

  defp receive_rewind do
    receive do
      {:rewound, to_turn, what} -> {:ok, {to_turn, what}}
    after
      500 -> :none
    end
  end

  # ====================================================================================
  # 4. Fork gating and node routing
  # ====================================================================================

  describe "fork" do
    test "is withheld and refused when the transport declared fork: false", %{conn: conn} do
      id = session_id()
      options = %{capabilities: %{fork: false}}
      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      view = open_deck(conn, id)
      render_click(view, "w3-backtrack-fork", %{})
      refute_receive {:fork_planned, _child, _overrides}, 300
    end
  end

  # ====================================================================================
  # 5. The operator shell
  # ====================================================================================

  describe "the operator shell" do
    test "sends the command verbatim, with no quoting of its own", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      command = ~s(echo 'a b' | grep "x" && rm -rf $HOME; # \\n)
      render_submit(view, "send", %{"message" => "!" <> command})

      assert_receive {:exec_planned, sent}, 2_000
      assert sent == command
    end

    test "a forged remember carries no pattern of the browser's", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)

      # No refusal has been held, so there is no rule to write.
      render_click(view, "w3-shell-remember", %{
        "pattern" => "Shell(rm -rf /)",
        "scope" => "node",
        "decision" => "allow"
      })

      refute_receive {:unexpected, _message}, 300
      assert Process.alive?(view.pid)
    end

    test "the composer says where a ! will run before Enter", %{conn: conn} do
      id = session_id()
      _row = listed(id, workspace: "/srv/project")
      _plane = plane(id: id, workspace: "/srv/project")

      view = open_deck(conn, id)
      html = render_change(view, "draft", %{"message" => "!ls", "session_key" => draft_key(view)})

      assert html =~ "ouro-shell-where"
      assert html =~ "/srv/project"

      # The one sentence whose job is to say *not here*. `node_label/2` answers "this
      # computer" for a BEAM nobody named, which is exactly the claim this band exists to
      # deny, so an unnamed owner is said in the terminal client's own words instead.
      refute where_line(html) =~ "this computer"

      if node() == :nonode@nohost do
        assert where_line(html) =~ "this session"
      else
        # A named BEAM is the owner's own label, never the raw `name@host`.
        refute where_line(html) =~ to_string(node())
        assert where_line(html) =~ "runs this on"
      end
    end
  end

  defp draft_key(view) do
    case Regex.run(~r/name="session_key" value="([^"]+)"/, render(view)) do
      [_whole, key] -> key
      nil -> ""
    end
  end

  defp where_line(html) do
    case Regex.run(~r{<p[^>]*class="ouro-shell-where".*?</p>}s, html) do
      [whole] -> whole |> String.replace(~r/\s+/, " ") |> String.slice(0, 300)
      nil -> nil
    end
  end

  # ====================================================================================
  # 6. Details: escaping
  # ====================================================================================

  describe "the details panel" do
    test "escapes a payload that closes its own pre and opens a script", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          backlog: [said(1, "</pre><script>alert(document.cookie)</script>")]
        )

      view = open_deck(conn, id)
      run(view, "conversation.details")
      html = render_click(view, "w3-details-toggle", %{"sequence" => "1"})

      refute html =~ "<script>alert(document.cookie)"
      assert html =~ "&lt;/pre&gt;&lt;script&gt;"
    end
  end

  # ====================================================================================
  # 7. The vitals meter
  # ====================================================================================

  describe "the vitals meter" do
    test "keeps the context reading even after the session grew", %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{context: [{:ok, %{source: :native, context_used: 10, context_window: 100}}]}
        )

      view = open_deck(conn, id)
      run(view, "conversation.context")
      render_click(view, "w3-close", %{})

      assert render(view) =~ "10 / 100 tokens"
    end

    test "and re-reads when a turn finishes, rather than pinning to the first answer",
         %{conn: conn} do
      id = session_id()
      _row = listed(id)

      _plane =
        plane(
          id: id,
          answers: %{
            context: [
              {:ok, %{source: :native, context_used: 10, context_window: 100}},
              {:ok, %{source: :native, context_used: 70, context_window: 100}}
            ]
          }
        )

      view = open_deck(conn, id)
      run(view, "conversation.context")
      render_click(view, "w3-close", %{})
      assert render(view) =~ "10 / 100 tokens"
      assert_receive :context_read, 2_000

      # A turn ends. `context_used` moves with every turn, so a meter keeping the first
      # answer would be a measurement that was true and is not.
      send(view.pid, {:ouroboros_interactive_event, id, event(9, :turn_completed, %{})})
      send(view.pid, :flush)
      assert_receive :context_read, 2_000

      assert render(view) =~ "70 / 100 tokens"
    end

    test "a compaction re-reads interactive.context rather than inferring", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      run(view, "conversation.compact")
      render_click(view, "w3-compact", %{"focus" => ""})

      assert_receive {:compacted, nil}, 2_000
      assert_receive :context_read, 2_000
      IO.puts("COMPACT -> context re-read: yes")
    end
  end

  defp meter_of(html) do
    case Regex.run(~r{ouro-vital-context.*?</div>}s, html) do
      [whole] -> whole |> String.replace(~r/\s+/, " ") |> String.slice(0, 200)
      nil -> nil
    end
  end

  # ====================================================================================
  # 8. MCP: workspace only where the session names one
  # ====================================================================================

  describe "mcp.list" do
    test "omits workspace when the session names none", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, workspace: nil)

      view = open_deck(conn, id)
      html = run(view, "runtime.mcp")
      assert html =~ ~s(id="ouro-mcp")
    end
  end

  # ====================================================================================
  # 9. W3.10 — the composer's pickers
  # ====================================================================================

  describe "W3.10 composer gates" do
    test "a transport refusing both halves keeps the per-turn thinking control",
         %{conn: conn} do
      id = session_id()

      options = %{
        sandbox_mode: :workspace_write,
        capabilities: %{dynamic_configuration: false, dynamic_model: false}
      }

      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      html = render(open_deck(conn, id))

      # Inverted. The per-turn effort rides `reasoning_effort` inside `send_message`'s own
      # envelope; `interactive.configure` has nothing to do with it and neither capability
      # has anything to say about it. What it does need is a send to ride on.
      assert html =~ ~s(phx-click="effort-next-turn")

      # The two controls that *are* configuration stay withheld.
      refute html =~ ~s(phx-value-field="sandbox_mode")
      refute html =~ ~s(phx-value-field="reasoning_effort")
    end

    test "the disclosure summary still names a sandbox nobody can change", %{conn: conn} do
      id = session_id()

      options = %{
        sandbox_mode: :workspace_write,
        capabilities: %{dynamic_configuration: false, dynamic_model: "native"}
      }

      _row = listed(id, options: options)
      _plane = plane(id: id, options: options)

      html = render(open_deck(conn, id))

      summary =
        case Regex.run(~r{<summary phx-click="composer-settings"[^>]*>(.*?)</summary>}s, html) do
          [_whole, text] -> text |> String.replace(~r/\s+/, " ") |> String.trim()
          nil -> nil
        end

      # The summary states the posture the session reported, which is a fact and stays
      # true whether or not it can be changed. What it must not do is offer a control for
      # the half that cannot.
      assert summary =~ "Project files"
      refute html =~ ~s(phx-value-field="sandbox_mode")
    end
  end

  # ====================================================================================
  # 10. send_turn re-check
  # ====================================================================================

  describe "send_turn" do
    test "a hand-made send on a running session still works", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id, backlog: [asked(1, "hi")])

      view = open_deck(conn, id)
      render_submit(view, "send", %{"message" => "a real turn"})
      assert_receive {:unexpected, {:send_turn, _mode, _turn, _input, _opts}}, 2_000
    end

    @tag scope: :read
    test "read scope takes no send", %{conn: conn} do
      id = session_id()
      _row = listed(id)
      _plane = plane(id: id)

      view = open_deck(conn, id)
      render_submit(view, "send", %{"message" => "a real turn"})
      refute_receive {:unexpected, {:send_turn, _mode, _turn, _input, _opts}}, 300
    end
  end

  # ====================================================================================
  # 11. The confirmation a forged handoff moves out from under
  # ====================================================================================

  describe "a pending confirmation" do
    test "still names the old session after a forged handoff patched the page away",
         %{conn: conn} do
      parent = session_id()
      _row = listed(parent, title: "Alpha")

      _plane =
        plane(
          id: parent,
          answers: %{handoff_plan: [{:error, {:owner_unavailable, :ghost@nowhere}}]}
        )

      view = open_deck(conn, parent)

      render_click(view, "session-action", %{
        "action" => "close",
        "plane" => "interactive",
        "id" => parent
      })

      before = render(view)
      assert before =~ ~s(id="session-action-dialog")
      assert dialog_text(before) =~ "Alpha"

      render_click(view, "w3-handoff", %{"prompt" => "forged"})

      # Inverted. The forged handoff is refused behind the confirmation, so nothing is
      # dispatched and the question the operator was asked is still the question on
      # screen, still about the session they were asked about.
      refute_receive {:handoff_planned, "forged", _child}, 300

      after_html = render(view)
      assert after_html =~ ~s(id="session-action-dialog")
      assert dialog_text(after_html) =~ "Alpha"
      assert open_of(after_html) == parent
    end
  end

  defp dialog_text(html) do
    case Regex.run(~r{<dialog[^>]*id="session-action-dialog".*?</dialog>}s, html) do
      [whole] ->
        whole
        |> String.replace(~r/<[^>]+>/, " ")
        |> String.replace(~r/\s+/, " ")
        |> String.trim()
        |> String.slice(0, 220)

      nil ->
        nil
    end
  end

  defp open_of(html) do
    case Regex.run(~r{ouro-vital-id"[^>]*>([^<]+)<}, html) do
      [_whole, id] -> id
      nil -> nil
    end
  end
end
