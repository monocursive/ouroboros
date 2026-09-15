defmodule Ouroboros.Web.Live.DeckLiveW2Test do
  @moduledoc """
  The regressions W2's adversarial review left behind.

  Every test here started life in the reviewer's exploit file. The ones that demonstrated
  a defect are **inverted**: they now assert the fix and fail the moment it is removed.
  The ones that demonstrated correct behaviour are kept as they were, because a property
  somebody had to go looking for is exactly the property that will be broken by accident.

  `Ouroboros.Web.Live.DeckLiveTest` covers the ordinary paths; this file covers the ones
  reached by a hand-made event, a stale modal, a transport that declared a refusal, and
  agent prose written to be hostile.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Commands
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Composer

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

  defmodule FakePlane do
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
         backlogs: Keyword.get(opts, :backlogs, []),
         options: Keyword.get(opts, :options, %{}),
         last_turn: Keyword.get(opts, :last_turn),
         provider: Keyword.get(opts, :provider, :native),
         workspace: Keyword.get(opts, :workspace, "/tmp/w"),
         answers: Keyword.get(opts, :answers, %{}),
         subscribers: []
       }}
    end

    def emit(pid, event), do: GenServer.call(pid, {:emit, event})

    @impl true
    def handle_call(:info, _from, state), do: {:reply, {:ok, session(state)}, state}

    def handle_call({:subscribe, subscriber, cursor}, _from, state) do
      send(state.test, {:subscribed, subscriber, cursor})

      {answer, rest} =
        case state.backlogs do
          [answer | rest] -> {answer, rest}
          [] -> {{:ok, []}, []}
        end

      state = %{state | backlogs: rest}

      case answer do
        {:ok, events} ->
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
      {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}
    end

    def handle_call({:emit, event}, _from, state) do
      for pid <- state.subscribers,
          do: send(pid, {:ouroboros_interactive_event, state.id, event})

      {:reply, :ok, state}
    end

    def handle_call({:send_turn, mode, turn_id, input, opts}, _from, state) do
      send(state.test, {:sent, mode, turn_id, input, opts})
      answer(state, :turn, {:ok, %{turn_id: turn_id, status: :running}})
    end

    def handle_call({:retry_turn, source}, _from, state) do
      send(state.test, {:retried, source})
      {:reply, {:ok, %{id: "retry-#{source}", status: :running}}, state}
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

  setup do
    dir = Path.join(System.tmp_dir!(), "ouro-rev-w2-#{System.unique_integer([:positive])}")
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

  defp session_id, do: "rev-w2-#{System.unique_integer([:positive])}"

  defp plane(opts) do
    {:ok, pid} = FakePlane.start(Keyword.put(opts, :test, self()))
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp listed(id, opts \\ []) do
    workspace =
      Keyword.get_lazy(opts, :workspace, fn ->
        dir = Path.join(System.tmp_dir!(), "ouro-rev-w2-ws-#{System.unique_integer([:positive])}")
        File.mkdir_p!(dir)
        on_exit(fn -> File.rm_rf(dir) end)
        dir
      end)

    session = %State{
      id: id,
      node: node(),
      title: Keyword.get(opts, :title),
      title_source: if(Keyword.get(opts, :title), do: :human),
      provider: :native,
      workspace: workspace,
      workspace_mode: :shared_read,
      status: Keyword.get(opts, :status, :running),
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

  defp said(sequence, text), do: event(sequence, :output_text_final, %{"text" => text})

  defp flush(view) do
    send(view.pid, :flush)
    render(view)
  end

  defp submit(view, text),
    do: view |> form("#composer", %{"message" => text}) |> render_submit()

  defp occurrences(haystack, needle),
    do: haystack |> String.split(needle) |> length() |> Kernel.-(1)

  defp dialog_html(html) do
    case Regex.run(~r{<dialog[^>]*id="session-action-dialog".*?</dialog>}s, html) do
      [whole] -> whole
      nil -> ""
    end
  end

  defp selected(html) do
    case Regex.run(~r/id="ouro-palette-row-([^"]+)"[^>]*aria-selected="true"/, html) do
      [_whole, row] -> row
      nil -> nil
    end
  end

  defp transcript_html(html) do
    case Regex.run(~r{<div id="transcript".*?</main>}s, html) do
      [whole] -> whole
      nil -> ""
    end
  end

  # ------------------------------------------------------------------------------------
  # The palette never appears over another modal
  # ------------------------------------------------------------------------------------

  describe "the palette and an open confirmation" do
    test "will not open over a confirmation nobody has answered", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Alpha", status: :running)
      _plane = plane(id: id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      html =
        render_click(view, "session-action", %{
          "action" => "rename",
          "plane" => "interactive",
          "id" => id
        })

      assert html =~ ~s(id="session-action-dialog")

      # This is what `Keys.onKeyDown` pushes for ⌘K. The browser half already refuses the
      # keystroke while another dialog is open; this half refuses the event, so a
      # hand-made push cannot do what the key cannot.
      html = render_hook(view, "palette-toggle", %{})

      assert html =~ ~s(id="session-action-dialog")
      refute html =~ ~s(id="ouro-palette")

      # `palette-open` is the same question asked by the composer's trigger button.
      refute render_hook(view, "palette-open", %{}) =~ ~s(id="ouro-palette")
      refute render_hook(view, "shortcuts-open", %{}) =~ ~s(id="ouro-shortcuts")
    end

    test "so it cannot swap that confirmation's subject under the operator", %{conn: conn} do
      open_id = session_id()
      other_id = session_id()
      _open_row = listed(open_id, title: "Open session", status: :running)
      _other_row = listed(other_id, title: "Some other session", status: :closed)
      _plane = plane(id: open_id, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{open_id}")

      # The operator asks to delete a different, terminal session from the rail.
      html =
        render_click(view, "session-action", %{
          "action" => "delete",
          "plane" => "interactive",
          "id" => other_id
        })

      assert html =~ "Some other session"

      # ⌘K over it, then "End this session" — which is about the *open* session. The
      # palette is not there to run, and the dialog is left asking what it asked.
      render_hook(view, "palette-toggle", %{})
      html = render_hook(view, "palette-run", %{"id" => "session.end"})

      dialog = dialog_html(html)
      assert dialog =~ "Some other session"
      refute dialog =~ "End session"
      refute dialog =~ "Open session"
    end

    test "opening the palette closes the shortcut sheet rather than stacking on it",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")

      assert render_hook(view, "shortcuts-open", %{}) =~ ~s(id="ouro-shortcuts")

      html = render_hook(view, "palette-open", %{})
      assert html =~ ~s(id="ouro-palette")
      refute html =~ ~s(id="ouro-shortcuts")

      # And the other way round.
      html = render_hook(view, "shortcuts-open", %{})
      assert html =~ ~s(id="ouro-shortcuts")
      refute html =~ ~s(id="ouro-palette")
    end
  end

  # ------------------------------------------------------------------------------------
  # An ended session takes no instruction, and is offered none
  # ------------------------------------------------------------------------------------

  describe "the Turn group on an ended session" do
    test "withholds effort, model, plan and auto-approve, which the composer also draws not",
         %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Finished", status: :closed)
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, [said(1, "the last word")]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ "This session has ended"
      refute html =~ ~s(phx-click="configure-plan")
      refute html =~ ~s(phx-value-field="reasoning_effort")

      offered = offered_rows(render_hook(view, "palette-open", %{}))

      for row <- ~w(turn.effort turn.model turn.plan turn.auto_approve) do
        refute row in offered, "#{row} is offered on a session that has ended"
      end

      # And a hand-made run of one issues nothing.
      render_hook(view, "palette-run", %{"id" => "turn.plan"})
      refute_receive {:configured, _changes}, 300
    end

    test "the send rows are withheld too, which is the comparison", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Finished", status: :closed)
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      offered = offered_rows(render_hook(view, "palette-open", %{}))

      refute "turn.send" in offered
      refute "turn.queue" in offered
      refute "turn.steer" in offered
      refute "session.end" in offered
      assert "session.delete" in offered
    end
  end

  # ------------------------------------------------------------------------------------
  # dynamic_model and dynamic_configuration, read exactly as `steer` is
  # ------------------------------------------------------------------------------------

  describe "the two configuration capabilities" do
    test "a transport that declared dynamic_model: false gets no model picker",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{
            model: "already-running",
            capabilities: %{steer: false, dynamic_model: false, dynamic_configuration: false}
          }
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      refute html =~ "data-ouro-steer"

      html = render_click(view, "composer-settings", %{})
      refute html =~ "ouro-model-select"

      # And the handler re-asks, so a hand-made change is not a way round the absent
      # control. `interactive.configure` is served; the transport is what refused.
      %{id: offered} = hd(Composer.model_rows(Ouroboros.Models.list()))
      render_change(view, "configure-model", %{"model" => offered})
      refute_receive {:configured, _changes}, 300
    end

    test "and the palette lists neither model nor the configuration rows for it",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{
            sandbox_mode: :read_only,
            capabilities: %{dynamic_model: false, dynamic_configuration: false}
          }
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      offered = offered_rows(render_hook(view, "palette-open", %{}))

      refute "turn.model" in offered
      refute "turn.plan" in offered
      refute "turn.effort" in offered
      refute "turn.sandbox" in offered
    end

    test "the plan toggle is neither drawn nor dispatched where it was declared off",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{plan: false, capabilities: %{dynamic_configuration: false}}
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ ~s(phx-click="configure-plan")

      render_click(view, "configure-plan", %{})
      refute_receive {:configured, _changes}, 300
    end

    test "silence about either key keeps both controls, as an older gateway would",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          backlogs: [{:ok, []}],
          options: %{model: "already-running", capabilities: %{steer: :native}}
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~s(phx-click="configure-plan")
      offered = offered_rows(render_hook(view, "palette-open", %{}))

      assert "turn.model" in offered
      assert "turn.plan" in offered
      assert "turn.effort" in offered
    end

    test "a session with no capabilities map at all keeps them too", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, []}], options: %{model: "m"})

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      assert html =~ ~s(phx-click="configure-plan")
      assert render_click(view, "composer-settings", %{}) =~ "ouro-model-select"
      _ = view
    end
  end

  # ------------------------------------------------------------------------------------
  # The armed per-turn effort, everywhere it travels
  # ------------------------------------------------------------------------------------

  describe "the armed per-turn effort" do
    test "rides a queued interactive.follow_up, not just the first send", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      render_click(view, "effort-next-turn", %{"choice" => "high"})
      submit(view, "queue this")

      assert_receive {:sent, mode, _turn, input, _opts}
      assert mode == :follow_up
      assert input == %{prompt: "queue this", reasoning_effort: :high}
    end

    test "survives a refusal, exactly as the terminal client's does", %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          status: :idle,
          backlogs: [{:ok, []}],
          answers: %{turn: [{:error, {:unavailable, "the provider is unavailable"}}]}
        )

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_click(view, "effort-next-turn", %{"choice" => "high"})

      html = submit(view, "first try")
      assert html =~ "the provider is unavailable"
      assert_receive {:sent, :message, _turn, %{reasoning_effort: :high}, _opts}

      # A refusal hands the draft back and leaves the arming where it was — the terminal
      # client restores `composer.reasoning_effort` from the same restored draft
      # (`tui/src/ui/app/session.rs:2257`). It stays on screen, so it is never silent.
      assert render(view) =~ "next turn: high"

      submit(view, "something completely different")

      assert_receive {:sent, :message, _turn,
                      %{prompt: "something completely different", reasoning_effort: :high}, _opts}
    end

    test "M10: is not carried into a different session's send", %{conn: conn} do
      first = session_id()
      second = session_id()
      _a = listed(first, title: "Alpha", status: :idle)
      _b = listed(second, title: "Beta", status: :idle)
      _pa = plane(id: first, status: :idle, backlogs: [{:ok, []}])
      _pb = plane(id: second, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{first}")
      render_click(view, "effort-next-turn", %{"choice" => "high"})

      render_patch(view, "/s/interactive/#{second}")
      refute render(view) =~ "next turn:"

      submit(view, "in the other session")
      assert_receive {:sent, :message, _turn, "in the other session", _opts}
    end

    test "rides a steer as well, because the TUI's envelope does", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      render_click(view, "effort-next-turn", %{"choice" => "high"})

      view
      |> form("#composer", %{"message" => "steer with effort"})
      |> render_submit(%{"verb" => "steer"})

      assert_receive {:steered, input, _opts}
      assert input == %{prompt: "steer with effort", reasoning_effort: :high}
    end

    test "M12: a steer spends the arming just as a send does", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      render_click(view, "effort-next-turn", %{"choice" => "high"})

      view |> form("#composer", %{"message" => "one"}) |> render_submit(%{"verb" => "steer"})
      assert_receive {:steered, %{reasoning_effort: :high}, _opts}
      refute render(view) =~ "next turn:"

      view |> form("#composer", %{"message" => "two"}) |> render_submit(%{"verb" => "steer"})
      assert_receive {:steered, "two", _opts}
    end

    test "M11/M12: an armed effort is spent by the send that carried it", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_click(view, "effort-next-turn", %{"choice" => "high"})

      submit(view, "one")
      assert_receive {:sent, :message, _t1, %{reasoning_effort: :high}, _o1}

      submit(view, "two")
      assert_receive {:sent, :message, _t2, "two", _o2}
    end

    test "M16: an effort no model advertises is not armed even by a hand-made event",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      html = render_click(view, "effort-next-turn", %{"choice" => "ludicrous"})
      refute html =~ "next turn:"

      submit(view, "go")
      assert_receive {:sent, :message, _turn, "go", _opts}
    end

    test "M17: a plain turn is still the bare string on the wire", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      submit(view, "plain")
      assert_receive {:sent, :message, _turn, input, _opts}
      assert is_binary(input)
    end
  end

  # ------------------------------------------------------------------------------------
  # The model catalogue belongs to the session it was read in
  # ------------------------------------------------------------------------------------

  describe "the model catalogue" do
    test "is dropped when a different conversation is opened", %{conn: conn} do
      first = session_id()
      second = session_id()
      _a = listed(first, title: "Alpha", status: :idle)
      _b = listed(second, title: "Beta", status: :idle)
      _pa = plane(id: first, status: :idle, backlogs: [{:ok, []}], options: %{model: "a-model"})
      _pb = plane(id: second, status: :idle, backlogs: [{:ok, []}], options: %{model: "b-model"})

      {:ok, view, _html} = live(conn, "/s/interactive/#{first}")
      html = render_click(view, "composer-settings", %{})
      assert html =~ "ouro-model-select"

      render_patch(view, "/s/interactive/#{second}")

      # Nothing has opened the disclosure in this conversation, so nothing has been read
      # for it — the picker is absent rather than pre-populated from somewhere else.
      refute render(view) =~ "ouro-model-select"
      assert render_click(view, "composer-settings", %{}) =~ "ouro-model-select"
    end

    test "and so is a search typed into it", %{conn: conn} do
      first = session_id()
      second = session_id()
      _a = listed(first, title: "Alpha", status: :idle)
      _b = listed(second, title: "Beta", status: :idle)
      _pa = plane(id: first, status: :idle, backlogs: [{:ok, []}])
      _pb = plane(id: second, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{first}")
      render_click(view, "composer-settings", %{})
      before = occurrences(render(view), "<option")

      view |> form("#ouro-model-search", %{"query" => "zzzz-no-such-model"}) |> render_change()
      assert occurrences(render(view), "<option") < before

      render_patch(view, "/s/interactive/#{second}")
      html = render_click(view, "composer-settings", %{})

      refute html =~ "zzzz-no-such-model"
      assert occurrences(html, "<option") == before
    end

    test "a refused read is tried again rather than left dead for the page's life",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      # There is no way to make `runtime.models` refuse from here, so the refusal is
      # written straight into the view's own state and the recovery is what is asserted:
      # the next opening of the disclosure reads again.
      :sys.replace_state(view.pid, fn state ->
        put_in(state.socket.assigns.composer_extras.models, {:error, "the catalogue is away"})
      end)

      assert render_click(view, "composer-settings", %{}) =~ "ouro-model-select"
    end
  end

  # ------------------------------------------------------------------------------------
  # What `palette-run` is bound to
  # ------------------------------------------------------------------------------------

  describe "palette-run" do
    test "is gated by the catalogue rather than by what is in the DOM", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      render_hook(view, "palette-open", %{})
      html = view |> form("#ouro-palette-form", %{"query" => "theme"}) |> render_change()
      refute html =~ ~s(phx-value-id="turn.interrupt")

      # Deliberate: a filter is a view, not a permission, and `n` runs `session.new`
      # with the palette shut. `Commands.available?/2` is the gate, and it is asked here.
      render_hook(view, "palette-run", %{"id" => "turn.interrupt"})
      assert_receive {:interrupted, _turn}, 500
    end

    test "runs nothing the catalogue would not have drawn", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      # No turn is running, so no row for either exists at any filter.
      render_hook(view, "palette-run", %{"id" => "turn.interrupt"})
      render_hook(view, "palette-run", %{"id" => "not.a.command"})

      refute_receive {:interrupted, _turn}, 200
      assert Process.alive?(view.pid)
    end

    test "M19: the selection clamps at both ends", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      render_hook(view, "palette-open", %{})

      for _ <- 1..40, do: render_hook(view, "palette-move", %{"direction" => "next"})
      assert Process.alive?(view.pid)
      bottom = selected(render(view))
      assert bottom != nil

      for _ <- 1..40, do: render_hook(view, "palette-move", %{"direction" => "prev"})
      assert selected(render(view)) == "session.new"

      for _ <- 1..40, do: render_hook(view, "palette-move", %{"direction" => "next"})
      assert selected(render(view)) == bottom
    end

    test "M13/M14: a hand-made query cannot become unbounded view state", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      render_hook(view, "palette-open", %{})

      long = String.duplicate("x", 5_000)
      render_change(view, "palette-filter", %{"query" => long})
      render_change(view, "model-search", %{"query" => long})

      html = render(view)
      refute html =~ String.duplicate("x", 200)
    end
  end

  # ------------------------------------------------------------------------------------
  # Hostile agent prose through the copy paths
  # ------------------------------------------------------------------------------------

  describe "hostile agent prose" do
    test "cannot put script, javascript: or an on* attribute into the copy controls",
         %{conn: conn} do
      hostile =
        "<script>alert(1)</script>\n\n[x](javascript:alert(2))\n\n" <>
          "<img src=x onerror=alert(3)>\n\n<div class=\"ouro-prose\">decoy</div>"

      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, hostile)]}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      drawn = transcript_html(html)
      refute drawn =~ "<script"
      refute drawn =~ "javascript:"
      refute drawn =~ "onerror="

      # Exactly one `.ouro-prose` in the cell: the hostile wrapper was stripped, so the
      # Clipboard hook cannot be pointed at a decoy element.
      assert occurrences(drawn, ~s(class="ouro-prose")) == 1

      [_whole, cell] = Regex.run(~r{phx-value-cell="([^"]+)"}, html)
      assert cell =~ ~r/\A[A-Za-z0-9_\-]+\z/

      render_click(view, "copy-source", %{"cell" => cell})
      assert_push_event(view, "ouro-copy", %{text: text})
      assert text == hostile

      render_hook(view, "palette-run", %{"id" => "conversation.copy"})
      assert_push_event(view, "ouro-copy", %{selector: selector})
      assert selector =~ ~r/\A#cells-[A-Za-z0-9_\-]+ \.ouro-prose\z/
    end

    test "H9: a message still being written is copyable from neither the cell nor the palette",
         %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      FakePlane.emit(pid, event(1, :turn_started, %{}))
      FakePlane.emit(pid, event(2, :output_text_delta, %{"text" => "half a sen"}))
      html = flush(view)

      assert html =~ "ouro-streaming"
      refute html =~ ~s(phx-click="copy-source")

      render_hook(view, "palette-open", %{})
      refute render(view) =~ "Copy the last message"

      render_hook(view, "palette-run", %{"id" => "conversation.copy_source"})
      refute_push_event(view, "ouro-copy", _nothing)

      # It becomes copyable the moment it is finished.
      FakePlane.emit(pid, event(3, :output_text_final, %{"text" => "half a sentence, whole"}))
      assert flush(view) =~ ~s(phx-click="copy-source")
    end

    test "M09: copy-source answers only for a cell this view drew", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, backlogs: [{:ok, [said(1, "real")]}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      render_click(view, "copy-source", %{"cell" => "event-4242-0"})
      refute_push_event(view, "ouro-copy", _nothing)
    end

    test "M20: the copy rows are about what the agent said, not what the operator typed",
         %{conn: conn} do
      id = session_id()

      _plane =
        plane(
          id: id,
          status: :idle,
          backlogs: [{:ok, [event(1, :input_accepted, %{"text" => "what I typed"})]}]
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ "what I typed"

      render_hook(view, "palette-open", %{})
      refute render(view) =~ "Copy the last message"

      render_hook(view, "palette-run", %{"id" => "conversation.copy_source"})
      refute_push_event(view, "ouro-copy", _nothing)
    end
  end

  # ------------------------------------------------------------------------------------
  # Forwarding
  # ------------------------------------------------------------------------------------

  describe "forwarding" do
    test "auto_approve from the palette really answers the backlog", %{conn: conn} do
      id = session_id()

      _pid =
        plane(
          id: id,
          status: :awaiting_approval,
          backlogs: [
            {:ok,
             [
               %{
                 event(1, :approval_requested, %{
                   "tool" => "bash",
                   "arguments" => %{"command" => "rm -rf /"}
                 })
                 | request_id: "req-1"
               }
             ]}
          ]
        )

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      assert html =~ "ouro-approval"

      render_hook(view, "palette-run", %{"id" => "turn.auto_approve"})
      assert_receive {:responded, "req-1", _response}, 500
    end

    test "every row the catalogue names answers {:noreply, socket}", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Alpha", status: :running)
      _plane = plane(id: id, status: :running, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      navigations = ~w(session.new runtime.status runtime.audit client.settings)

      for command <- Commands.all(), command.id not in navigations do
        render_hook(view, "palette-run", %{"id" => command.id})
        assert Process.alive?(view.pid), "#{command.id} took the view down"
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # The shortcut sheet
  # ------------------------------------------------------------------------------------

  describe "the shortcut sheet" do
    test "lists every key it binds and nothing it does not", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/")
      html = render_hook(view, "shortcuts-open", %{})

      for key <- ["⌘K", "?", "/", "n", "[", "]", "↑", "↓", "⏎", "esc"] do
        assert html =~ "<kbd>#{key}</kbd>", "the sheet does not list #{key}"
      end

      refute html =~ "⌘N"
      refute html =~ "⌘."
    end

    test "the palette's window-keydown spans exist only while it is open", %{conn: conn} do
      {:ok, view, html} = live(conn, "/")

      refute html =~ ~s(phx-window-keydown="palette-move")

      assert render_hook(view, "palette-open", %{}) =~ ~s(phx-window-keydown="palette-move")
      refute render_hook(view, "palette-close", %{}) =~ ~s(phx-window-keydown="palette-move")
    end
  end

  # ------------------------------------------------------------------------------------
  # The steer handler asks the button's own question
  # ------------------------------------------------------------------------------------

  describe "the steer handler's own gate" do
    test "refuses a session with no turn running, which the button never offers",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")

      refute html =~ "data-ouro-steer"

      view
      |> form("#composer", %{"message" => "steer an idle session"})
      |> render_submit(%{"verb" => "steer"})

      refute_receive {:steered, _input, _opts}, 300
    end

    test "refuses a session that has already ended", %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Closed", status: :closed)
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, []}])

      {:ok, view, html} = live(conn, "/s/interactive/#{id}")
      refute html =~ ~s(id="composer")

      render_submit(view, "send", %{"verb" => "steer", "message" => "speak to the dead"})
      refute_receive {:steered, _input, _opts}, 300
    end

    test "M06: a declared steer: false is enforced by the handler, not only by the button",
         %{conn: conn} do
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
      html = flush(view)

      refute html =~ "data-ouro-steer"

      render_submit(view, "send", %{"verb" => "steer", "message" => "steer anyway"})
      refute_receive {:steered, _input, _opts}, 300
    end

    test "M08: a steer from a stale composer is refused by the session key", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      render_submit(view, "send", %{
        "verb" => "steer",
        "message" => "meant for another conversation",
        "session_key" => "a-key-this-page-never-minted"
      })

      refute_receive {:steered, _input, _opts}, 300
    end

    test "and so is the ordinary send clause, which W3.10 closed",
         %{conn: conn} do
      id = session_id()
      _row = listed(id, title: "Closed", status: :closed)
      _plane = plane(id: id, status: :closed, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

      # The composer is not drawn on an ended session at all, so this event could only
      # have been hand-made.
      refute render(view) =~ ~s(id="composer")
      render_submit(view, "send", %{"message" => "speak to the dead"})

      # Inverted. Until W3.10, `send_turn/2` let an undrawn event reach the runtime to be
      # refused there; it now re-asks the four facts the composer is drawn from, exactly
      # as W2's steer clause re-asks its button's condition.
      refute_receive {:sent, _mode, _turn, "speak to the dead", _opts}, 300
    end
  end

  # ------------------------------------------------------------------------------------
  # The palette's steer leads to the control; it does not press it
  # ------------------------------------------------------------------------------------

  describe "the palette's steer" do
    test "reveals the composer's Steer button instead of sending the stale draft",
         %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      # One debounced `phx-change` lands. In a browser the next 400ms of typing has not,
      # and a steer carrying this instead of what is in the box is the one mistake this
      # verb must not make.
      view |> form("#composer", %{"message" => "the old draft"}) |> render_change()

      render_hook(view, "palette-run", %{"id" => "turn.steer"})

      refute_receive {:steered, _input, _opts}, 300
      assert_push_event(view, "ouro-reveal", %{selector: "[data-ouro-steer]"})
    end

    test "is offered with an empty draft, because it is a way to the control", %{conn: conn} do
      id = session_id()
      pid = plane(id: id, status: :idle, backlogs: [{:ok, []}])

      {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
      FakePlane.emit(pid, event(1, :turn_started, %{}))
      flush(view)

      assert "turn.steer" in offered_rows(render_hook(view, "palette-open", %{}))
    end
  end

  defp offered_rows(html) do
    ~r/phx-value-id="([^"]+)"/
    |> Regex.scan(html)
    |> Enum.map(fn [_whole, row] -> row end)
  end
end

defmodule Ouroboros.Web.Live.DeckLiveReadScopeTest do
  @moduledoc """
  W2 at read scope.

  The endpoint's scope is fixed at boot and a cookie never carries it, so this is a whole
  second `Ouroboros.Web` rather than a flag — which is also why it is a module of its own
  rather than a test that restarts the one above it.

  Every mutating verb this slice added is asked twice here: is it drawn, and does its
  event do anything when pushed by hand. The second question is the one that matters, and
  it is the one no test asked before the review.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.DeckLiveW2Test.FakePlane

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

  setup do
    dir = Path.join(System.tmp_dir!(), "ouro-w2-read-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :read)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    conn = get(build_conn(), "/auth?token=#{@token}")
    {:ok, conn: put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)}
  end

  defp session_id, do: "w2-read-#{System.unique_integer([:positive])}"

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

  defp said(sequence, text), do: event(sequence, :output_text_final, %{"text" => text})

  defp flush(view) do
    send(view.pid, :flush)
    render(view)
  end

  test "no mutating row is drawn and none can be run", %{conn: conn} do
    id = session_id()
    pid = plane(id: id, status: :running, backlogs: [{:ok, [said(1, "hello")]}])

    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
    FakePlane.emit(pid, event(2, :turn_started, %{}))
    flush(view)

    html = render_hook(view, "palette-open", %{})

    offered =
      ~r/phx-value-id="([^"]+)"/
      |> Regex.scan(html)
      |> Enum.map(fn [_whole, row] -> row end)

    for forbidden <- ~w(session.new session.rename session.end session.delete turn.interrupt
                        turn.steer turn.send turn.queue turn.model turn.plan turn.effort
                        turn.sandbox turn.auto_approve turn.retry turn.approval) do
      refute forbidden in offered, "read scope was offered #{forbidden}"
      render_hook(view, "palette-run", %{"id" => forbidden})
    end

    refute_receive {:interrupted, _turn}, 200
    refute_receive {:configured, _changes}, 100
    refute_receive {:sent, _mode, _turn, _input, _opts}, 100
    refute_receive {:steered, _input, _opts}, 100
    refute_receive {:responded, _id, _response}, 100

    # What a reader may still do is still there.
    assert "runtime.status" in offered
    assert "client.theme" in offered
    assert "conversation.copy" in offered
  end

  test "M21/M22/M23: the events themselves are no-ops, not merely undrawn", %{conn: conn} do
    id = session_id()
    pid = plane(id: id, status: :running, backlogs: [{:ok, [said(1, "hello")]}])

    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
    FakePlane.emit(pid, event(2, :turn_started, %{}))
    flush(view)

    render_click(view, "configure-plan", %{})
    render_change(view, "configure-model", %{"model" => "anything-at-all"})
    render_click(view, "composer-settings", %{})
    render_submit(view, "send", %{"verb" => "steer", "message" => "steer at read scope"})

    refute_receive {:configured, _changes}, 200
    refute_receive {:steered, _input, _opts}, 100

    # `composer-settings` reads no catalogue either: the picker it would fill is one this
    # scope may never use.
    refute render(view) =~ "ouro-model-select"
  end

  test "the composer draws no steer, no plan toggle and no model picker", %{conn: conn} do
    id = session_id()
    _pid = plane(id: id, status: :running, backlogs: [{:ok, [said(1, "hello")]}])

    {:ok, view, html} = live(conn, "/s/interactive/#{id}")

    refute html =~ "data-ouro-steer"
    refute html =~ "configure-plan"
    refute html =~ "ouro-model-select"

    render_click(view, "composer-settings", %{})
    refute render(view) =~ "ouro-model-select"
  end
end
