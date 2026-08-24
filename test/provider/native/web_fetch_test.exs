defmodule Ouroboros.Provider.Native.WebFetchTest do
  @moduledoc """
  `web_fetch` against a listener on this machine's loopback.

  No network: the server is thirty lines of `:gen_tcp` in this file, so the tests are
  hermetic and every response shape — a redirect to another host, a body past the cap, a
  page of HTML — is produced deliberately rather than found on the internet.
  """

  use ExUnit.Case, async: true

  alias Ouroboros.Provider.Native.Paths
  alias Ouroboros.Provider.Native.Tools
  alias Ouroboros.Provider.Native.Tools.WebFetch

  setup do
    root = Path.join(System.tmp_dir!(), "native-fetch-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    {:ok, scope} = Paths.scope(root, [], :workspace_write)
    %{scope: scope, context: %{scope: scope, session_dir: root, reads: %{}}}
  end

  # ---------------------------------------------------------------- listener

  defp listen(handler) do
    {:ok, socket} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(socket)

    pid =
      spawn_link(fn ->
        serve(socket, handler)
      end)

    on_exit(fn ->
      Process.exit(pid, :kill)
      :gen_tcp.close(socket)
    end)

    port
  end

  defp serve(socket, handler) do
    case :gen_tcp.accept(socket) do
      {:ok, client} ->
        request = read_request(client, "")
        :gen_tcp.send(client, handler.(request))
        :gen_tcp.close(client)
        serve(socket, handler)

      {:error, _closed} ->
        :ok
    end
  end

  defp read_request(client, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      case :gen_tcp.recv(client, 0, 5_000) do
        {:ok, data} -> read_request(client, acc <> data)
        {:error, _reason} -> acc
      end
    end
  end

  defp response(status, headers, body) do
    head =
      "HTTP/1.1 #{status} X\r\n" <>
        Enum.map_join(headers, "", fn {k, v} -> "#{k}: #{v}\r\n" end) <>
        "Content-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n"

    head <> body
  end

  defp fetch(port, path, context, extra \\ %{}) do
    input = Map.merge(%{"url" => "http://127.0.0.1:#{port}#{path}"}, extra)
    Tools.execute(WebFetch, input, context, 30_000)
  end

  # ---------------------------------------------------------------- tests

  describe "fetching" do
    test "returns a text body with its status and content type", %{context: context} do
      port =
        listen(fn _request ->
          response(
            200,
            [{"Content-Type", "text/plain; charset=utf-8"}],
            "hello from the listener"
          )
        end)

      result = fetch(port, "/", context)

      refute result.is_error
      assert result.output =~ "HTTP 200"
      assert result.output =~ "text/plain"
      assert result.output =~ "hello from the listener"
    end

    test "converts HTML to text and says it did", %{context: context} do
      html = """
      <!doctype html><html><head><style>body{color:red}</style>
      <script>var x = "<not text>";</script></head>
      <body><h1>Title</h1><p>First &amp; second.</p><p>Third&#33;</p></body></html>
      """

      port = listen(fn _request -> response(200, [{"Content-Type", "text/html"}], html) end)
      result = fetch(port, "/page", context)

      refute result.is_error
      assert result.output =~ "HTML converted to text"
      assert result.output =~ "Title"
      assert result.output =~ "First & second."
      assert result.output =~ "Third!"
      refute result.output =~ "color:red"
      refute result.output =~ "var x"
    end

    test "a 404 distinguishes a missing resource from a transport failure", %{context: context} do
      port = listen(fn _request -> response(404, [], "nope") end)
      result = fetch(port, "/missing", context)

      assert result.is_error
      assert result.output =~ "HTTP 404 X from http://127.0.0.1:#{port}/missing"
      assert result.output =~ "The server was reached"
      assert result.output =~ "Verify the exact path and version/ref"
      assert result.output =~ "do not retry the unchanged URL"
      refute result.output =~ "web_fetch failed"
    end

    test "another non-2xx status carries the URL, reason phrase, and response body", %{
      context: context
    } do
      port = listen(fn _request -> response(503, [], "try later") end)
      result = fetch(port, "/unavailable", context)

      assert result.is_error

      assert result.output ==
               "HTTP 503 X from http://127.0.0.1:#{port}/unavailable. try later"

      refute result.output =~ "web_fetch failed"
    end

    test "the byte cap bites and is reported", %{context: context} do
      body = String.duplicate("a", 40_000)
      port = listen(fn _request -> response(200, [{"Content-Type", "text/plain"}], body) end)

      result = fetch(port, "/big", context, %{"max_bytes" => 1_000})

      refute result.is_error
      assert result.output =~ "body truncated at the byte cap"
      assert byte_size(result.output) < 5_000
    end
  end

  describe "redirects" do
    test "a same-host redirect is followed", %{context: context} do
      port =
        listen(fn request ->
          if String.contains?(request, "GET /start") do
            response(302, [{"Location", "/finish"}], "")
          else
            response(200, [{"Content-Type", "text/plain"}], "arrived")
          end
        end)

      result = fetch(port, "/start", context)

      refute result.is_error
      assert result.output =~ "arrived"
    end

    test "a redirect to another host is reported and NOT followed", %{context: context} do
      port =
        listen(fn _request ->
          response(302, [{"Location", "http://example.invalid/elsewhere"}], "")
        end)

      result = fetch(port, "/leaving", context)

      assert result.is_error
      assert result.output =~ "different host"
      assert result.output =~ "It was not followed"
      assert result.output =~ "example.invalid"
    end

    test "a redirect loop on one host stops at the cap", %{context: context} do
      port = listen(fn _request -> response(302, [{"Location", "/loop"}], "") end)
      result = fetch(port, "/loop", context)

      assert result.is_error
      assert result.output =~ "redirects on one host"
    end

    test "a redirect with no Location is refused", %{context: context} do
      port = listen(fn _request -> response(302, [], "") end)
      result = fetch(port, "/nowhere", context)

      assert result.is_error
      assert result.output =~ "redirected without a Location"
    end
  end

  describe "refusals that need no listener" do
    test "only http and https", %{context: context} do
      for url <- ["file:///etc/passwd", "ftp://example.com/x", "gopher://x"] do
        result = Tools.execute(WebFetch, %{"url" => url}, context, 5_000)
        assert result.is_error
        assert result.output =~ "not a scheme this tool fetches"
      end
    end

    test "a relative or nonsense URL is refused before any socket is opened", %{
      context: context
    } do
      for url <- ["/just/a/path", "example.com/no-scheme", ""] do
        result = Tools.execute(WebFetch, %{"url" => url}, context, 5_000)
        assert result.is_error
      end
    end
  end

  describe "the permission engine sees the host" do
    test "web_fetch is a network call whose domain is the URL's host", %{scope: scope} do
      classified =
        Tools.classify("web_fetch", %{"url" => "https://docs.example.com/a/b?c=d"}, scope)

      assert classified.mode == :network
      assert classified.domains == ["docs.example.com"]
      assert classified.write_paths == []
    end

    test "a URL with no readable host reports no domain, so no WebFetch rule can match it", %{
      scope: scope
    } do
      assert Tools.classify("web_fetch", %{"url" => "not a url"}, scope).domains == []
      assert Tools.classify("web_fetch", %{"url" => nil}, scope).domains == []
      assert WebFetch.host("https://a.example.com") == "a.example.com"
      assert WebFetch.host("ftp://a.example.com") == nil
    end
  end

  describe "the HTML stripper" do
    test "drops script and style bodies whole" do
      assert WebFetch.strip_html("<style>a{b:c}</style>x<script>evil()</script>y") == "x y"
    end

    test "decodes the named entities and numeric references" do
      assert WebFetch.strip_html("&lt;tag&gt; &amp; &quot;q&quot; &#39;a&#39; &#65;") ==
               "<tag> & \"q\" 'a' A"
    end

    test "collapses whitespace and keeps block boundaries as newlines" do
      assert WebFetch.strip_html("<p>one</p><p>two</p>") == "one\ntwo"
      assert WebFetch.strip_html("a    \t   b") == "a b"
    end

    test "is total on input that is not really HTML" do
      assert is_binary(WebFetch.strip_html("<<<>>> &#999999999; <b"))
    end
  end
end
