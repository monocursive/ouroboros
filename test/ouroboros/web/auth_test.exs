defmodule Ouroboros.Web.AuthTest do
  @moduledoc """
  The token-for-cookie exchange, and the one page everything else gets.

  These dispatch through the real endpoint rather than calling the plug directly, because
  half of what is being asserted is the pipeline around it: that `Plug.Session` set the
  flags this plug asked for, that a refusal reaches the browser before the router, and
  that no response leaves without `Referrer-Policy`.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Plug.Conn, only: [get_resp_header: 2]

  alias Ouroboros.Web.Auth
  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-auth-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)

    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, config: config, data_dir: dir}
  end

  describe "the exchange" do
    test "the right token buys a cookie and nothing else" do
      conn = get("/auth?token=#{@token}")

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/"]

      # The response body is empty: the token bought a redirect, not a page, so nothing
      # rendered from a URL that has a credential in it.
      assert conn.resp_body == ""

      cookie = conn.resp_cookies[@cookie]

      assert is_binary(cookie.value)
      assert cookie.http_only, "a script must not be able to read an operator's session"
      assert cookie.same_site == "Lax"

      # And the URL that carried the token must not be cached or referred anywhere.
      assert get_resp_header(conn, "cache-control") == ["no-store"]
      assert get_resp_header(conn, "referrer-policy") == ["no-referrer"]
    end

    test "the cookie it minted opens the page" do
      cookie = sign_in()

      conn =
        build_conn()
        |> put_req_cookie(@cookie, cookie)
        |> dispatch(@endpoint, :get, "/")

      assert conn.status == 200
      assert conn.resp_body =~ "Ouroboros"
      # W3 replaced W0's status page at `/` with the deck; this assertion follows the
      # route rather than the page it used to serve. What it is checking has not changed:
      # that the cookie reached a LiveView which reached the runtime and got an answer
      # back — the machine's own name in the presence row is that answer.
      assert conn.resp_body =~ "NEEDS YOU"
      assert conn.resp_body =~ to_string(node())
    end

    test "a second exchange mints a different session rather than adopting the first" do
      assert sign_in() != sign_in()
    end

    test "only GET reaches the exchange" do
      conn = dispatch(build_conn(), @endpoint, :post, "/auth?token=#{@token}")

      assert conn.status == 401
      assert conn.resp_cookies == %{}
    end
  end

  describe "the one refusal" do
    test "a wrong token and a missing token are indistinguishable" do
      missing = get("/auth")
      wrong = get("/auth?token=#{String.duplicate("x", 40)}")
      # Same length as the real credential, and a prefix of it: neither a length check
      # nor an early-exit comparison may show through.
      prefix = get("/auth?token=#{String.slice(@token, 0, 39)}")

      for conn <- [missing, wrong, prefix] do
        assert conn.status == 401
        assert conn.resp_body == missing.resp_body
        assert conn.resp_cookies == %{}, "a refusal handed a stranger a cookie"
      end
    end

    test "an unauthenticated request for any page gets the same page" do
      gate = get("/auth")

      for path <- ["/", "/nope", "/anything/at/all"] do
        conn = get(path)

        assert conn.status == 401
        assert conn.resp_body == gate.resp_body
        assert conn.resp_cookies == %{}
      end
    end

    test "the LiveView socket is refused at the handshake, not at the mount" do
      # `plug :socket_dispatch` runs above every plug in the endpoint, so this path never
      # reaches `Ouroboros.Web.Auth` and cannot be answered with the page. What it must
      # not do is hand a stranger a socket to hold; see `Ouroboros.Web.LiveSocket`.
      conn = get("/live/websocket")

      refute conn.status == 200
      assert conn.resp_cookies == %{}
    end

    test "the page names the client that can produce a fresh link" do
      body = get("/").resp_body

      assert body =~ "ouro web"
      assert body =~ "Ouroboros"

      # And nothing else. It must not describe the runtime it is guarding.
      refute body =~ @token
      refute body =~ to_string(node())
    end

    test "a cookie this endpoint did not sign is not a session" do
      conn =
        build_conn()
        |> put_req_cookie(@cookie, "forged-by-somebody-else")
        |> dispatch(@endpoint, :get, "/")

      assert conn.status == 401
    end

    test "every refusal carries Referrer-Policy too" do
      assert get_resp_header(get("/"), "referrer-policy") == ["no-referrer"]
    end
  end

  describe "the comparison" do
    test "matches only the whole token, and is blind to how it differs" do
      assert Auth.token_matches?(@token, @token)

      refute Auth.token_matches?(String.slice(@token, 0, 39), @token)
      refute Auth.token_matches?(@token <> "x", @token)
      refute Auth.token_matches?(String.duplicate("x", 40), @token)
      refute Auth.token_matches?("", @token)
    end

    test "anything that is not a token at all is refused rather than crashing" do
      refute Auth.token_matches?(nil, @token)
      refute Auth.token_matches?(["array", "of", "params"], @token)
      refute Auth.token_matches?(%{"nested" => "map"}, @token)
    end
  end

  describe "the static assets" do
    test "are served before the token check so the refusal page is not naked" do
      conn = get("/web/app.css")

      assert conn.status == 200
      assert conn.resp_body =~ "--attention-green"
      assert get_resp_header(conn, "referrer-policy") == ["no-referrer"]
    end

    test "and nothing outside the four names is reachable" do
      assert get("/web/app.js").status == 200
      assert get("/web/phoenix.min.js").status == 200
      assert get("/web/phoenix_live_view.min.js").status == 200

      # Plug.Static declines anything not on the list, which then reaches the auth plug.
      assert get("/web/web.secret").status == 401
    end
  end

  defp get(path), do: dispatch(build_conn(), @endpoint, :get, path)

  defp sign_in do
    "/auth?token=#{@token}"
    |> get()
    |> Map.fetch!(:resp_cookies)
    |> Map.fetch!(@cookie)
    |> Map.fetch!(:value)
  end
end
