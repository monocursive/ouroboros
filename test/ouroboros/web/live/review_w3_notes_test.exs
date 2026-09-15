defmodule Ouroboros.Web.Live.ReviewW3NotesTest do
  @moduledoc """
  W3's adversarial review, on the two places a verb's own record went missing.

  Both started life in the reviewer's probe file and both are **inverted**: they printed a
  defect and they now assert the fix, so deleting either enforcement turns them red.

  `Ouroboros.Web.Watch` keyed one note per sequence, and the anchor a local block takes is
  the newest sequence *held* — so two operator verbs run inside one event-free window
  shared an anchor and the second silently replaced the first. A compaction run after a
  rewind erased the rewind's own record of what it could not restore, which is the one
  half of that answer a person has to act on.

  The MCP row was drawn with no session open, where the panel's state has no subject and
  the row therefore ran and drew nothing.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("w", 40)
  @cookie "_ouroboros_web"

  # Its own coordinator rather than the deck review's, so this file runs on its own.
  defmodule Plane do
    @moduledoc false
    use GenServer

    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      {:ok, _owner} = Registry.register(Ouroboros.Interactive.Registry, id, nil)
      {:ok, %{id: id, test: Keyword.fetch!(opts, :test), subscribers: []}}
    end

    @impl true
    def handle_call(:info, _from, state) do
      {:reply,
       {:ok,
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
        }}, state}
    end

    def handle_call({:subscribe, subscriber, _cursor}, _from, state),
      do: {:reply, {:ok, []}, %{state | subscribers: Enum.uniq([subscriber | state.subscribers])}}

    def handle_call({:unsubscribe, subscriber}, _from, state),
      do: {:reply, :ok, %{state | subscribers: state.subscribers -- [subscriber]}}

    def handle_call(:rewind_points, _from, state),
      do: {:reply, {:ok, [%{"turn_id" => "t1", "files" => 0}]}, state}

    def handle_call({:rewind, to_turn, what}, _from, state) do
      send(state.test, {:rewound, to_turn, what})

      {:reply,
       {:ok,
        %{
          restored: [],
          unrestorable: [%{path: "not-checkpointed.ex", reason: "no snapshot was taken"}],
          turns: ["t1"],
          messages: 3
        }}, state}
    end

    def handle_call({:compact, focus}, _from, state) do
      send(state.test, {:compacted, focus})
      {:reply, {:ok, %{trigger: "manual", archived_messages: 4}}, state}
    end

    def handle_call(:context, _from, state), do: {:reply, {:ok, %{source: :usage}}, state}
    def handle_call(_message, _from, state), do: {:reply, {:error, :not_scripted}, state}
  end

  setup do
    dir = Path.join(System.tmp_dir!(), "ouro-revnote-#{System.unique_integer([:positive])}")
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

  defp listed(id) do
    session = %State{
      id: id,
      node: node(),
      title: "Notes",
      title_source: :human,
      provider: :native,
      workspace: "/tmp/w",
      workspace_mode: :shared_read,
      status: :running,
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

  # ------------------------------------------------------------------------------------

  test "two operator verbs in one quiet window both keep their block", %{conn: conn} do
    id = "revnote-#{System.unique_integer([:positive])}"
    _row = listed(id)

    {:ok, pid} = Plane.start(id: id, test: self())
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    {:ok, view, _html} = live(conn, "/s/interactive/#{id}")

    # A rewind, whose block is anchored at the newest sequence held — zero, because this
    # session has delivered no events at all.
    render_hook(view, "palette-run", %{"id" => "conversation.rewind"})
    render_click(view, "w3-rewind-pick", %{"choice" => "0"})
    render_click(view, "w3-rewind-confirm", %{})
    assert_receive {:rewound, _to, _what}, 2_000

    assert render(view) =~ "Rewound to t1"

    # A compaction, whose block wants the same anchor.
    render_hook(view, "palette-run", %{"id" => "conversation.compact"})
    render_click(view, "w3-compact", %{"focus" => ""})
    assert_receive {:compacted, nil}, 2_000

    html = render(view)

    # Inverted. Both acts happened, so both are in the conversation: one anchor holds a
    # list, oldest first. Until this, the compaction's note wrote over the rewind's and
    # the record of a file that could not be put back was gone.
    assert html =~ "Rewound to t1",
           "the compaction's note replaced the rewind's at the same anchor"

    assert html =~ "Compacted"
    assert html =~ "archived 4 messages"

    # And in that order, because that is the order they happened in.
    assert :binary.match(html, "Rewound to t1") < :binary.match(html, "Compacted")
  end

  test "the MCP row is not offered on a deck with no session open", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/")

    offered =
      ~r/id="ouro-palette-row-([^"]+)"/
      |> Regex.scan(render_hook(view, "palette-open", %{}))
      |> Enum.map(&List.last/1)

    # Inverted. `mcp.list` is routed to the node the *session* runs on and narrowed by the
    # workspace it names, and the panel's own state is keyed by the open conversation — so
    # with nothing open the row ran and drew nothing at all, which is the one thing a
    # palette row must never do.
    refute "runtime.mcp" in offered

    after_run = render_hook(view, "palette-run", %{"id" => "runtime.mcp"})
    refute after_run =~ ~s(id="ouro-mcp")
    assert Process.alive?(view.pid)
  end
end
