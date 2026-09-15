defmodule Ouroboros.Web.NeedsYouTest do
  @moduledoc """
  The needs-you edge, and the promise the bell makes on every page that draws it.

  The bell moved into the shared top bar in W1.1, and the adversarial review found that
  `push_event("needs-you", …)` existed only in `DeckLive`: a bell switched on while
  reading `/settings` asked the browser for notification permission and then never rang.
  `Ouroboros.Web.NeedsYou` is the repair — one edge computation, and a hook every spoke
  attaches — so these tests drive a real edge on a spoke rather than assert the markup.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Live.Rail
  alias Ouroboros.Web.NeedsYou

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("b", 40)
  @cookie "_ouroboros_web"

  # Every page that draws the bar, and therefore the bell.
  @spokes ["/new", "/settings", "/status", "/audit"]

  setup do
    dir = Path.join(System.tmp_dir!(), "ouroboros-web-bell-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    conn = get(build_conn(), "/auth?token=#{@token}")
    {:ok, conn: put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)}
  end

  # A durable row, cleaned up the way the store insists on: closed, then deleted.
  defp listed(status) do
    id = "web-bell-#{System.unique_integer([:positive])}"

    workspace =
      Path.join(System.tmp_dir!(), "ouroboros-bell-ws-#{System.unique_integer([:positive])}")

    File.mkdir_p!(workspace)
    on_exit(fn -> File.rm_rf(workspace) end)

    session = %State{
      id: id,
      node: node(),
      provider: :native,
      workspace: workspace,
      workspace_mode: :shared_read,
      status: status,
      options: %{runtime_exposure: false},
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

  defp row(id, status),
    do: %Rail.Row{plane: :interactive, id: id, status: status, provider: :native}

  # ------------------------------------------------------------------------------------
  # The arithmetic
  # ------------------------------------------------------------------------------------

  describe "sessions/2" do
    test "one entry per needs-you row, keyed by the session where no ask is known" do
      rows = [row("waiting", :awaiting_approval), row("busy", :running)]

      assert [%{key: "interactive:waiting", group: "interactive:waiting"}] =
               NeedsYou.sessions(rows)
    end

    test "the requests a caller is holding are the keys for the session it has open" do
      rows = [row("open", :awaiting_approval)]

      entries =
        NeedsYou.sessions(rows,
          pending: %{{:interactive, "open"} => 2},
          approvals: [%{request_id: "r1"}, %{request_id: "r2"}],
          open: {:interactive, "open"}
        )

      assert Enum.map(entries, & &1.key) == ["r1", "r2"]

      # And the group is the session, so three asks replace each other into one banner
      # rather than stacking three that say the same words.
      assert Enum.map(entries, & &1.group) == ["interactive:open", "interactive:open"]
    end

    test "a request already answered is not something anybody needs telling about" do
      rows = [row("open", :awaiting_approval)]

      entries =
        NeedsYou.sessions(rows,
          pending: %{{:interactive, "open"} => 2},
          approvals: [%{request_id: "r1"}, %{request_id: "r2"}],
          answered: MapSet.new(["r1"]),
          open: {:interactive, "open"}
        )

      assert Enum.map(entries, & &1.key) == ["r2"]
    end
  end

  describe "fresh/2" do
    test "only what has just entered the group" do
      entries = [%{key: "a"}, %{key: "b"}]

      assert NeedsYou.fresh(entries, MapSet.new(["a"])) == [%{key: "b"}]
      assert NeedsYou.fresh(entries, NeedsYou.keys(entries)) == []
    end
  end

  # ------------------------------------------------------------------------------------
  # The promise, on the pages that make it
  # ------------------------------------------------------------------------------------

  describe "the hook every spoke attaches" do
    test "a session that starts waiting while a spoke is open rings there", %{conn: conn} do
      for path <- @spokes do
        {:ok, view, _html} = live(conn, path)

        session = listed(:awaiting_approval)

        send(view.pid, :needs_you_poll)
        _rendered = render(view)

        key = "interactive:#{session.id}"

        assert_push_event(view, "needs-you", %{sessions: pushed})

        assert Enum.any?(pushed, &(&1.key == key)),
               "#{path} did not ring for a session that started waiting"
      end
    end

    test "what was already waiting when the page opened is recorded, not announced",
         %{conn: conn} do
      # A spoke opened in a background tab must not post one banner per pending approval
      # on arrival, and a reconnect must not do it again.
      _already = listed(:awaiting_approval)

      {:ok, view, _html} = live(conn, "/settings")

      send(view.pid, :needs_you_poll)
      _rendered = render(view)

      refute_push_event(view, "needs-you", %{}, 50)
    end

    test "a session that is merely busy rings nothing", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/status")

      _busy = listed(:running)

      send(view.pid, :needs_you_poll)
      _rendered = render(view)

      refute_push_event(view, "needs-you", %{}, 50)
    end

    test "the same ask is never pushed twice", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/audit")

      _waiting = listed(:awaiting_approval)

      send(view.pid, :needs_you_poll)
      _first = render(view)
      assert_push_event(view, "needs-you", %{sessions: _pushed})

      send(view.pid, :needs_you_poll)
      _second = render(view)
      refute_push_event(view, "needs-you", %{}, 50)
    end
  end
end
