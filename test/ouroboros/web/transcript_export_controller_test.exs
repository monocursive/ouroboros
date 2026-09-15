defmodule Ouroboros.Web.TranscriptExportControllerTest do
  @moduledoc """
  W3.2. The two files, and the claims each of them is allowed to make.

  The route reads the session through the real gateway method — the fake coordinator
  below answers `{:replay, cursor, limit}` exactly as the plane does — so the paging, the
  bound and the floor inference are all exercised rather than stubbed. What is asserted is
  what a person would find in the file: the events, in order, with nothing added to the
  NDJSON and a last line in the text that says how complete it is.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Plug.Conn, only: [get_resp_header: 2, put_req_cookie: 3]

  alias Ouroboros.Interactive.Event
  alias Ouroboros.Interactive.State
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("x", 40)
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
         events: Keyword.get(opts, :events, []),
         pruned: Keyword.get(opts, :pruned)
       }}
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

    # A floor the runtime no longer retains, answered exactly once and for cursor 0 only —
    # which is the shape a client actually meets.
    def handle_call({:replay, 0, _limit}, _from, %{pruned: floor} = state)
        when is_integer(floor) do
      {:reply, {:error, {:cursor_pruned, floor}}, %{state | pruned: nil}}
    end

    def handle_call({:replay, cursor, limit}, _from, state) do
      send(state.test, {:replayed, cursor, limit})

      window =
        state.events
        |> Enum.filter(&(&1.sequence > cursor))
        |> Enum.take(limit)

      {:reply, {:ok, window}, state}
    end

    def handle_call(_message, _from, state), do: {:reply, {:error, :not_scripted}, state}
  end

  setup do
    dir = Path.join(System.tmp_dir!(), "ouro-export-#{System.unique_integer([:positive])}")
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

  defp session_id, do: "export-#{System.unique_integer([:positive])}"

  defp plane(opts) do
    {:ok, pid} = Plane.start(Keyword.put(opts, :test, self()))
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)
    pid
  end

  defp event(sequence, type, payload) do
    %Event{
      id: "e#{sequence}",
      session_id: "s",
      sequence: sequence,
      type: type,
      timestamp: "2026-09-15T12:00:00Z",
      payload: payload,
      turn_id: "t1"
    }
  end

  defp asked(sequence, text), do: event(sequence, :input_accepted, %{"text" => text})
  defp said(sequence, text), do: event(sequence, :output_text_final, %{"text" => text})

  defp export(conn, id, format), do: get(conn, "/s/interactive/#{id}/export?format=#{format}")

  # ------------------------------------------------------------------------------------
  # Text
  # ------------------------------------------------------------------------------------

  describe "the text form" do
    test "is the conversation in order, with a header and a completeness line", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [asked(1, "what changed?"), said(2, "three files did")])

      conn = export(conn, id, "text")
      body = response(conn, 200)

      assert response_content_type(conn, :txt) =~ "text/plain"
      assert body =~ "ouroboros transcript · #{id}"
      assert body =~ "2 events held · sequences 1–2"

      # In order, and each speaker named.
      assert body =~ "you\nwhat changed?"
      assert body =~ "agent\nthree files did"
      assert String.split(body, "what changed?") |> length() == 2

      # The last line, and the only place this file claims anything about completeness.
      assert body =~ "complete: no history was dropped from this session"
    end

    test "says so when the runtime no longer retains the beginning", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(9, "after the hole")], pruned: 8)

      body = conn |> export(id, "text") |> response(200)

      assert body =~ "incomplete: the runtime no longer retains all history through sequence 8"
      refute body =~ "complete: no history was dropped"
    end

    test "an empty session says that rather than pretending to be a transcript",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [])

      body = conn |> export(id, "text") |> response(200)
      assert body =~ "Nothing has happened in this session yet."
    end

    test "is offered as a download and is never cached", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "hi")])

      conn = export(conn, id, "text")

      assert [disposition] = get_resp_header(conn, "content-disposition")
      assert disposition =~ "attachment"
      assert disposition =~ "ouroboros-interactive-#{id}.txt"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    test "and the extent travels in a header, for either form, in ASCII", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "hi"), said(2, "there")])

      for format <- ~w(text ndjson) do
        conn = export(conn, id, format)
        assert [extent] = get_resp_header(conn, "x-ouroboros-export-extent")
        assert extent == "2 events; sequences 1-2"

        # W3 fix wave (L2). A header is bytes, and the typography the file's own prose
        # uses is two- and three-byte UTF-8 a header reader may refuse or mangle.
        assert extent == for(<<c <- extent>>, c < 128, into: "", do: <<c>>)
      end
    end
  end

  # ------------------------------------------------------------------------------------
  # NDJSON
  # ------------------------------------------------------------------------------------

  describe "the ndjson form" do
    test "is one held event per line, and nothing else at all", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [asked(1, "one"), said(2, "two")])

      conn = export(conn, id, "ndjson")
      body = response(conn, 200)

      assert [content_type] = get_resp_header(conn, "content-type")
      assert content_type =~ "application/x-ndjson"

      lines = body |> String.split("\n", trim: true)
      assert length(lines) == 2

      # No header, no footer, no trailing summary: whether history was pruned is a fact
      # about the file rather than a record in it.
      refute body =~ "complete:"
      refute body =~ "ouroboros transcript"

      for line <- lines do
        assert {:ok, decoded} = JSON.decode(line)
        assert is_map(decoded)
        assert is_integer(decoded["sequence"])
      end
    end

    test "keys are sorted, so two exports of one session are the same bytes", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "hi")])

      first = conn |> export(id, "ndjson") |> response(200)
      second = conn |> export(id, "ndjson") |> response(200)

      assert first == second
      [line] = String.split(first, "\n", trim: true)
      keys = line |> JSON.decode!() |> Map.keys()
      assert keys == Enum.sort(keys)
    end

    test "carries the envelope the runtime framed, `_struct` and all", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "hi")])

      body = conn |> export(id, "ndjson") |> response(200)
      decoded = body |> String.split("\n", trim: true) |> hd() |> JSON.decode!()

      assert decoded["type"] == "output_text_final"
      assert decoded["payload"]["text"] == "hi"
      assert decoded["_struct"] =~ "Interactive.Event"
    end
  end

  # ------------------------------------------------------------------------------------
  # Paging, the bound, and refusals
  # ------------------------------------------------------------------------------------

  describe "reading the session" do
    test "pages from an exclusive cursor at the method's own limit", %{conn: conn} do
      id = session_id()
      limit = Ouroboros.Gateway.Methods.Contract.replay_limit()
      events = for sequence <- 1..(limit + 3), do: said(sequence, "line #{sequence}")
      _plane = plane(id: id, events: events)

      body = conn |> export(id, "ndjson") |> response(200)

      assert_receive {:replayed, 0, ^limit}, 2_000
      assert_receive {:replayed, ^limit, ^limit}, 2_000

      assert body |> String.split("\n", trim: true) |> length() == limit + 3
    end

    test "a pruned cursor raises the floor and resumes there", %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(9, "after")], pruned: 8)

      body = conn |> export(id, "ndjson") |> response(200)

      assert_receive {:replayed, 8, _limit}, 2_000
      assert body |> String.split("\n", trim: true) |> length() == 1
    end

    test "an unknown plane is not found", %{conn: conn} do
      conn = get(conn, "/s/team/anything/export?format=text")
      assert response(conn, 404) =~ "No such session"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    test "a session this node does not hold is a 404 in the runtime's own words",
         %{conn: conn} do
      id = session_id()
      # No coordinator is registered at all, so the plane answers for itself.
      conn = export(conn, id, "text")
      body = response(conn, 404)

      assert body =~ "no such record on this node"
      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    test "an unreadable format falls back to the transcript rather than refusing",
         %{conn: conn} do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "hi")])

      body = conn |> export(id, "parquet") |> response(200)
      assert body =~ "ouroboros transcript"
    end
  end

  # ------------------------------------------------------------------------------------
  # The door
  # ------------------------------------------------------------------------------------

  describe "authentication" do
    test "a request with no cookie never reaches the controller" do
      id = session_id()
      _plane = plane(id: id, events: [said(1, "secret")])

      conn = get(build_conn(), "/s/interactive/#{id}/export?format=ndjson")

      refute conn.status == 200
      refute to_string(conn.resp_body) =~ "secret"
    end
  end
end
