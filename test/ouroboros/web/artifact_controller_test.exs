defmodule Ouroboros.Web.ArtifactControllerTest do
  @moduledoc """
  The one route on this surface that answers bytes.

  Three things are being defended, and they fail differently:

    * **the door.** An `<img>` is a plain GET and browsers make them constantly. It must
      be behind the same cookie as the deck, with no signed URL and no second credential —
      a URL carrying its own authority is a URL that ends up in history and in a `Referer`.
    * **the digest.** 64 lowercase hex characters, checked here as well as upstream. It is
      the only thing between a path parameter and the filesystem, and two independent
      checks is what the gateway's own exposure refusal does for the same reason.
    * **the caching.** A sha-addressed URL can never point at different bytes, so it is
      immutable and private — and a refusal must never be cached at all, or a screenshot
      that was not staged yet stays missing for a year.

  These dispatch conns straight into the endpoint, which is what proves the pipeline
  around the controller rather than just the controller.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Plug.Conn, only: [put_req_cookie: 3, get_resp_header: 2]

  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("t", 40)
  @cookie "_ouroboros_web"
  @sha String.duplicate("a", 64)

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-artifact-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, cookie: sign_in()}
  end

  defp sign_in do
    conn = get(build_conn(), "/auth?token=#{@token}")
    conn.resp_cookies[@cookie].value
  end

  defp fetch(cookie, path) do
    build_conn() |> put_req_cookie(@cookie, cookie) |> dispatch(@endpoint, :get, path)
  end

  describe "the door" do
    test "a request with no cookie gets the one unauthenticated page, not a 404" do
      # The distinction matters: a 404 would confirm the route exists and let a stranger
      # probe digests. `Ouroboros.Web.Auth` answers first, above the router.
      conn = dispatch(build_conn(), @endpoint, :get, "/artifact/interactive/s1/#{@sha}")

      assert conn.status == 401
      assert conn.resp_body =~ "ouro web"
    end

    test "a cookie signed by nobody is refused the same way", %{cookie: _cookie} do
      conn =
        build_conn()
        |> put_req_cookie(@cookie, "not-a-real-cookie")
        |> dispatch(@endpoint, :get, "/artifact/interactive/s1/#{@sha}")

      assert conn.status == 401
    end

    test "an authenticated request reaches the controller", %{cookie: cookie} do
      conn = fetch(cookie, "/artifact/interactive/s1/#{@sha}")

      # No artifact is staged in this data directory, so the honest answer is 404 — but it
      # is the *controller's* 404, which is what proves the request got past the door.
      assert conn.status == 404
      assert conn.resp_body =~ "no such artifact"
    end
  end

  describe "the digest" do
    test "anything that is not 64 lowercase hex is refused as a miss", %{cookie: cookie} do
      for sha <- [
            "short",
            String.duplicate("A", 64),
            String.duplicate("a", 63),
            String.duplicate("a", 65),
            String.duplicate("g", 64)
          ] do
        conn = fetch(cookie, "/artifact/interactive/s1/#{sha}")

        assert conn.status == 404, "#{sha} was not refused"
      end
    end

    test "a traversal attempt is a miss and never a path", %{cookie: cookie} do
      # The router will not even match most of these; the ones it does are refused by the
      # shape check. Either way nothing reaches the filesystem.
      for sha <- ["..%2f..%2fetc%2fpasswd", "..", "%2e%2e"] do
        conn = fetch(cookie, "/artifact/interactive/s1/#{sha}")

        assert conn.status == 404
      end
    end
  end

  describe "the plane" do
    test "only the two that exist are addressable", %{cookie: cookie} do
      assert fetch(cookie, "/artifact/interactive/s1/#{@sha}").status == 404
      assert fetch(cookie, "/artifact/coding/s1/#{@sha}").status == 404
      assert fetch(cookie, "/artifact/teams/s1/#{@sha}").status == 404
      assert fetch(cookie, "/artifact/Interactive/s1/#{@sha}").status == 404
    end
  end

  describe "a staged artifact" do
    setup %{cookie: cookie} do
      # `Desktop.artifact/2` with no session id searches the live pool's session dirs, so
      # a real staged file needs a real pool holding a real directory. This is the only
      # way to exercise the success path without inventing a seam the runtime does not
      # have — and the success path is the whole reason the route exists.
      staging =
        Path.join(System.tmp_dir!(), "ouroboros-desktop-#{System.unique_integer([:positive])}")

      File.mkdir_p!(Path.join(staging, "desktop"))
      on_exit(fn -> File.rm_rf(staging) end)

      # Started under the singleton name, because that is the one `artifact/2` looks up.
      # `start/1` rather than `start_link/1` so a pool crash does not take the test with
      # it — the module's own docs say tests use it for exactly that.
      pool =
        case Ouroboros.Provider.Native.Desktop.Pool.start(
               name: Ouroboros.Provider.Native.Desktop.Pool
             ) do
          {:ok, pid} -> pid
          {:error, {:already_started, pid}} -> pid
        end

      on_exit(fn -> if Process.alive?(pool), do: GenServer.stop(pool) end)

      Ouroboros.Provider.Native.Desktop.Pool.remember_state(pool, staging, %{})

      bytes = <<0x89, ?P, ?N, ?G, 13, 10, 26, 10, "not really a png">>
      sha = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
      File.write!(Path.join([staging, "desktop", "#{sha}.png"]), bytes)

      {:ok, cookie: cookie, sha: sha, bytes: bytes}
    end

    test "is served with its own bytes and an immutable, private cache", ctx do
      conn = fetch(ctx.cookie, "/artifact/interactive/s1/#{ctx.sha}")

      assert conn.status == 200
      assert conn.resp_body == ctx.bytes
      assert get_resp_header(conn, "content-type") == ["image/png; charset=utf-8"]

      # The address *is* the content, so the browser may keep it forever — and `private`
      # because a shared cache has no business holding an operator's screen.
      assert get_resp_header(conn, "cache-control") == ["private, max-age=31536000, immutable"]
      assert get_resp_header(conn, "x-content-type-options") == ["nosniff"]
    end

    test "and a neighbouring digest is still a miss", ctx do
      other = String.duplicate("b", 64)

      assert fetch(ctx.cookie, "/artifact/interactive/s1/#{other}").status == 404
    end

    test "but not to a request that never presented a cookie", ctx do
      conn = dispatch(build_conn(), @endpoint, :get, "/artifact/interactive/s1/#{ctx.sha}")

      assert conn.status == 401
      refute conn.resp_body == ctx.bytes
    end
  end

  describe "caching" do
    test "a refusal is never cached", %{cookie: cookie} do
      conn = fetch(cookie, "/artifact/interactive/s1/#{@sha}")

      assert get_resp_header(conn, "cache-control") == ["no-store"]
    end

    test "and every response on this surface carries the referrer policy", %{cookie: cookie} do
      conn = fetch(cookie, "/artifact/interactive/s1/#{@sha}")

      assert get_resp_header(conn, "referrer-policy") == ["no-referrer"]
    end
  end
end
