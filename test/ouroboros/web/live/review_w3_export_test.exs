defmodule Ouroboros.Web.ReviewW3ExportTest do
  @moduledoc """
  W3's adversarial review of the export route, kept as regressions.

  None of these found a defect in what the route *does* — the ceiling holds, the filename
  cannot carry a header injection, a traversal in `format` is never reflected, and the
  door is the cookie. They are kept because each is a property somebody had to go looking
  for, and two of them are mutation survivors the reviewer named: the 40-page ceiling
  (#2) and `stem/1` against a session id full of metacharacters (#3).

  The `IO.puts` the probes carried are assertions now.
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
         # `:endless` makes every page a full one, forever: the shape a ceiling exists for.
         endless: Keyword.get(opts, :endless, false),
         calls: 0
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

    def handle_call({:replay, cursor, limit}, _from, %{endless: true} = state) do
      send(state.test, {:replayed, cursor, limit})

      window =
        for n <- 1..limit, do: event(cursor + n, :output_text_final, %{"text" => "line"})

      {:reply, {:ok, window}, %{state | calls: state.calls + 1}}
    end

    def handle_call({:replay, cursor, limit}, _from, state) do
      send(state.test, {:replayed, cursor, limit})

      window = state.events |> Enum.filter(&(&1.sequence > cursor)) |> Enum.take(limit)
      {:reply, {:ok, window}, %{state | calls: state.calls + 1}}
    end

    def handle_call(:calls, _from, state), do: {:reply, state.calls, state}
    def handle_call(_message, _from, state), do: {:reply, {:error, :not_scripted}, state}

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
  end

  setup context do
    dir = Path.join(System.tmp_dir!(), "ouro-rev-export-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: Map.get(context, :scope, :read))
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

  # ------------------------------------------------------------------------------------

  test "the 40-page ceiling holds against a runtime that never runs out", %{conn: conn} do
    id = session_id()
    pid = plane(id: id, endless: true)

    conn = get(conn, "/s/interactive/#{id}/export?format=ndjson")
    body = response(conn, 200)

    lines = body |> String.split("\n", trim: true) |> length()
    calls = GenServer.call(pid, :calls)

    assert [extent] = get_resp_header(conn, "x-ouroboros-export-extent")

    # Mutation survivor #2. A runtime that never runs out is the shape a ceiling exists
    # for: the export stops at its own bound and the file says it stopped, rather than
    # paging until this process runs out of memory.
    assert calls <= 40
    assert lines == 20_000
    assert extent =~ "cut at this page's own ceiling"

    # W3 fix wave (L2). A header is bytes: no interpunct, no en dash.
    assert extent == "20000 events; sequences 1-20000; cut at this page's own ceiling"
    assert extent == for(<<c <- extent>>, c < 128, into: "", do: <<c>>)
  end

  test "the text footer says it was cut when the ceiling fired", %{conn: conn} do
    id = session_id()
    _pid = plane(id: id, endless: true)

    body = conn |> get("/s/interactive/#{id}/export?format=text") |> response(200)
    assert body =~ "this export stopped at 20000 events"
  end

  test "a session id full of header metacharacters cannot escape content-disposition",
       %{conn: conn} do
    # Phoenix decodes the path segment, so this reaches the controller as one binary
    # holding a quote, a CR, an LF and a slash.
    nasty = ~s(a"b) <> "\r\nX-Injected: yes\r\n" <> "../../etc/passwd"
    _pid = plane(id: nasty, events: [event(1, :output_text_final, %{"text" => "hi"})])
    encoded = nasty |> URI.encode_www_form() |> String.replace("+", "%20")

    conn = get(conn, "/s/interactive/#{encoded}/export?format=text")

    [disposition] = get_resp_header(conn, "content-disposition")

    # Mutation survivor #3. A session id becomes part of a filename, so only a name gets
    # to describe one: everything outside `[A-Za-z0-9._-]` is replaced before it reaches
    # the header, which is what keeps a CRLF out of a response and a `../` out of a path.
    refute disposition =~ "\r"
    refute disposition =~ "\n"
    refute disposition =~ "/"
    refute disposition =~ ~s(\") <> "b"
    assert get_resp_header(conn, "x-injected") == []
  end

  test "format is never reflected into the response", %{conn: conn} do
    id = session_id()
    _pid = plane(id: id, events: [event(1, :output_text_final, %{"text" => "hi"})])

    conn = get(conn, "/s/interactive/#{id}/export?format=../../x")
    body = response(conn, 200)

    [_type] = get_resp_header(conn, "content-type")
    [disposition] = get_resp_header(conn, "content-disposition")

    refute body =~ "../../x"
    assert disposition =~ ".txt"
  end

  test "html in an event body is never served as html", %{conn: conn} do
    id = session_id()

    _pid =
      plane(
        id: id,
        events: [event(1, :output_text_final, %{"text" => "</pre><script>alert(1)</script>"})]
      )

    conn = get(conn, "/s/interactive/#{id}/export?format=text")
    [type] = get_resp_header(conn, "content-type")
    body = response(conn, 200)

    assert type =~ "text/plain"
    # text/plain is the defence; the bytes are the agent's own and travel verbatim.
    assert body =~ "<script>alert(1)</script>"
  end

  test "a payload holding a newline stays one ndjson object per line", %{conn: conn} do
    id = session_id()

    _pid =
      plane(
        id: id,
        events: [
          event(1, :output_text_final, %{"text" => "one\ntwo\nthree"}),
          event(2, :output_text_final, %{"text" => "next"})
        ]
      )

    body = conn |> get("/s/interactive/#{id}/export?format=ndjson") |> response(200)
    lines = String.split(body, "\n", trim: true)

    assert length(lines) == 2
    assert String.ends_with?(body, "\n")
    for line <- lines, do: assert({:ok, _} = JSON.decode(line))
  end

  test "no cookie is a 401 and never the transcript" do
    id = session_id()
    _pid = plane(id: id, events: [event(1, :output_text_final, %{"text" => "secret"})])

    conn = get(build_conn(), "/s/interactive/#{id}/export?format=ndjson")

    assert conn.status == 401
    refute to_string(conn.resp_body) =~ "secret"
    assert conn.resp_cookies == %{}
  end

  test "a forged cookie is a 401" do
    id = session_id()
    _pid = plane(id: id, events: [event(1, :output_text_final, %{"text" => "secret"})])

    conn =
      build_conn()
      |> put_req_cookie(@cookie, "not-a-signed-session")
      |> get("/s/interactive/#{id}/export?format=ndjson")

    assert conn.status == 401
    refute to_string(conn.resp_body) =~ "secret"
  end

  @tag scope: :read
  test "a read-scope cookie exports in full (replay is a read method)", %{conn: conn} do
    id = session_id()
    _pid = plane(id: id, events: [event(1, :output_text_final, %{"text" => "readable"})])

    body = conn |> get("/s/interactive/#{id}/export?format=text") |> response(200)
    assert body =~ "readable"
  end
end
