defmodule Ouroboros.Web.Live.ComposerSubmissionTest do
  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("s", 40)

  # Observe the normalized input at the real gateway/coordinator boundary.
  defmodule Plane do
    use GenServer

    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts) do
      state = Map.new(opts)
      {:ok, _} = Registry.register(Ouroboros.Interactive.Registry, state.id, nil)
      {:ok, state}
    end

    @impl true
    def handle_call(:info, _from, state) do
      session = %State{
        id: state.id,
        node: node(),
        provider: :native,
        workspace: "/tmp/w",
        workspace_mode: :shared_read,
        status: state.status,
        options: %{},
        created_at: "2026-09-15T10:00:00Z",
        updated_at: "2026-09-15T10:00:00Z"
      }

      {:reply, {:ok, session}, state}
    end

    def handle_call({:subscribe, _, _}, _from, state), do: {:reply, {:ok, []}, state}
    def handle_call({:unsubscribe, _}, _from, state), do: {:reply, :ok, state}

    def handle_call({:send_turn, mode, turn_id, input, opts}, _from, state) do
      send(state.test, {:sent, mode, turn_id, input, opts})

      case state.answers do
        [answer | rest] -> {:reply, answer, %{state | answers: rest}}
        [] -> {:reply, {:ok, %{turn_id: turn_id, status: :running}}, state}
      end
    end
  end

  setup do
    dir = Path.join(System.tmp_dir!(), "ouro-composer-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    start_supervised!(
      {Ouroboros.Web, config: Config.new!(data_dir: dir, scope: :operate), server: false}
    )

    conn = get(build_conn(), "/auth?token=#{@token}")

    {:ok,
     conn:
       put_req_cookie(build_conn(), "_ouroboros_web", conn.resp_cookies["_ouroboros_web"].value)}
  end

  defp open_session(conn, opts \\ []) do
    id = "composer-#{System.unique_integer([:positive])}"

    {:ok, pid} =
      Plane.start(
        id: id,
        test: self(),
        status: Keyword.get(opts, :status, :idle),
        answers: Keyword.get(opts, :answers, [])
      )

    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    {:ok, view, _} = live(conn, "/s/interactive/#{id}")
    view
  end

  defp submit(view, extra \\ %{}),
    do: render_submit(view, "send", Map.merge(%{"message" => "inspect this"}, extra))

  test "palette send and queue request the browser form instead of dispatching a stale draft", %{
    conn: conn
  } do
    for {status, command} <- [{:idle, "turn.send"}, {:running, "turn.queue"}] do
      view = open_session(conn, status: status)
      render_hook(view, "draft", %{"message" => "old debounced text"})
      render_hook(view, "palette-run", %{"id" => command})
      key = :sys.get_state(view.pid).socket.assigns.draft_key
      assert_push_event(view, "composer-submit", %{key: ^key})
      refute_received {:sent, _, _, _, _}
    end
  end

  test "duplicate submits retain the spent effort and original turn id", %{conn: conn} do
    view = open_session(conn)
    render_click(view, "effort-next-turn", %{"choice" => "high"})
    submit(view)
    assert_receive {:sent, :message, turn_id, input, []}
    assert input == %{prompt: "inspect this", reasoning_effort: :high}
    refute render(view) =~ "next turn: high"

    submit(view)
    assert_receive {:sent, :message, ^turn_id, ^input, []}
  end

  test "a refused send retries the same effort envelope and identity", %{conn: conn} do
    view = open_session(conn, answers: [{:error, :busy}])
    render_click(view, "effort-next-turn", %{"choice" => "high"})
    submit(view)
    assert_receive {:sent, :message, turn_id, input, []}
    assert input.reasoning_effort == :high
    submit(view)
    assert_receive {:sent, :message, ^turn_id, ^input, []}
  end

  test "a deliberate text edit starts a new turn with the session effort", %{conn: conn} do
    view = open_session(conn)
    render_click(view, "effort-next-turn", %{"choice" => "high"})
    submit(view)
    assert_receive {:sent, :message, first, _, []}
    render_hook(view, "draft", %{"message" => "inspect this"})
    submit(view)
    assert_receive {:sent, :message, second, "inspect this", []}
    refute first == second
  end

  test "explicit effort choices start new turns even with identical text", %{conn: conn} do
    for choice <- ["high", "session"] do
      view = open_session(conn)
      render_click(view, "effort-next-turn", %{"choice" => "high"})
      submit(view)
      assert_receive {:sent, :message, first, _, []}
      render_click(view, "effort-next-turn", %{"choice" => choice})
      submit(view)
      assert_receive {:sent, :message, second, input, []}
      refute first == second

      assert input ==
               if(choice == "high",
                 do: %{prompt: "inspect this", reasoning_effort: :high},
                 else: "inspect this"
               )
    end
  end

  test "duplicate image forms retain effort but changing images starts a new turn", %{conn: conn} do
    view = open_session(conn)
    render_click(view, "effort-next-turn", %{"choice" => "high"})
    refs = [%{"id" => "att_abcdefghijklmnopqrstuvwx12345678"}]
    params = %{"images_json" => JSON.encode!(refs), "images_draft" => "composer-regression"}
    submit(view, params)
    assert_receive {:sent, :message, first, input, []}
    assert input.image_attachments == refs
    assert input.reasoning_effort == :high
    submit(view, params)
    assert_receive {:sent, :message, ^first, ^input, []}

    changed = [%{"id" => "att_abcdefghijklmnopqrstuvwx12345679"}]
    submit(view, %{params | "images_json" => JSON.encode!(changed)})
    assert_receive {:sent, :message, second, changed_input, []}
    refute first == second
    assert changed_input == %{prompt: "inspect this", image_attachments: changed}
  end
end
