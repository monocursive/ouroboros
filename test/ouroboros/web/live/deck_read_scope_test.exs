defmodule Ouroboros.Web.Live.DeckReadScopeTest do
  @moduledoc """
  The deck served at read scope: what it draws, and what it refuses to do anyway.

  Its own file because the scope is a property of the endpoint, fixed at boot
  (`Ouroboros.Web.Call`), so a read-scope deck needs its own `Ouroboros.Web` under its own
  data directory rather than a flag flipped mid-test.

  The case it exists for is the adversarial review's PROOF E: auto-approve answers
  approvals on the operator's behalf, its control is never rendered at read scope, and
  until this the server still flipped it — and ran `auto_answer/1` — for any browser that
  sent the `phx-click` anyway.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("v", 40)
  @cookie "_ouroboros_web"

  # The smallest coordinator this file needs: one that registers where
  # `Ouroboros.InteractiveSession.local_call/2` looks, answers `:info`, and accepts a
  # subscription with an empty backlog. Its own rather than the deck suite's, so this file
  # runs on its own.
  defmodule Plane do
    @moduledoc false
    use GenServer

    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      {:ok, _owner} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
      {:ok, %{id: id, subscribers: []}}
    end

    @impl true
    def handle_call(:info, _from, state), do: {:reply, {:ok, session(state)}, state}

    def handle_call({:subscribe, subscriber, _cursor}, _from, state),
      do: {:reply, {:ok, []}, %{state | subscribers: Enum.uniq([subscriber | state.subscribers])}}

    def handle_call({:unsubscribe, subscriber}, _from, state),
      do: {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}

    defp session(state) do
      %State{
        id: state.id,
        node: node(),
        provider: :native,
        workspace: "/tmp/w",
        workspace_mode: :shared_read,
        status: :running,
        options: %{},
        created_at: "2026-09-15T10:00:00Z",
        updated_at: "2026-09-15T12:00:00Z"
      }
    end
  end

  setup do
    dir = Path.join(System.tmp_dir!(), "ouroboros-web-read-#{System.unique_integer([:positive])}")
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

  defp open_session(conn) do
    id = "web-read-#{System.unique_integer([:positive])}"
    {:ok, pid} = Plane.start(id: id)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")
    view
  end

  test "is never shown the auto-approve toggle", %{conn: conn} do
    view = open_session(conn)

    refute has_element?(view, ~s(button[phx-click="auto_approve"])),
           "read scope is offered a control that answers on the operator's behalf"

    refute render(view) =~ "Automatically allow routine actions"
  end

  test "a forged click cannot turn it on either", %{conn: conn} do
    # PROOF E, inverted. Nothing is drawn either way, so the assertion is on the state the
    # server holds: the flag, and therefore `auto_answer/1`, must not run for a scope that
    # may not answer an approval at all.
    view = open_session(conn)

    render_click(view, "auto_approve", %{})

    refute :sys.get_state(view.pid).socket.assigns.auto_approve?,
           "a read-scope client flipped the automatic-approval grant"
  end

  test "and the page still reads", %{conn: conn} do
    # The refusal is the control, not the page: a read-scope viewer still gets the
    # transcript and the top bar.
    view = open_session(conn)
    html = render(view)

    assert html =~ "ouro-transcript"
    assert html =~ "ouro-topbar"
    assert html =~ "read scope"
  end
end
