defmodule Ouroboros.Web.StatusLiveTest do
  @moduledoc """
  `/status`: the page an operator loads when the deck itself is what looks broken.

  Until W1 nothing linked to it (`grep href="/status"` came back empty), it was titled
  "Advanced · Runtime" after a settings section this surface does not have, it duplicated
  half of Settings → "Runtime & security", and it drew `nonode@nohost` as its first fact
  (`docs/design-qa/ui-review-2026-09-15.md` §3.1, §3.5).
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("r", 40)
  @cookie "_ouroboros_web"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-status-#{System.unique_integer([:positive])}")

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

  test "is called what its heading calls it, in the tab as well", %{conn: conn} do
    {:ok, view, html} = live(conn, "/status")

    assert html =~ "<h1>\n  Runtime status\n</h1>" or html =~ "Runtime status"
    assert page_title(view) =~ "Runtime status"
    refute page_title(view) =~ "Advanced"
  end

  test "carries the one top bar and is reachable from it", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/status")

    assert html =~ ~s(class="ouro-topbar")

    for href <- ["/", "/new", "/settings", "/audit", "/status"] do
      assert html =~ ~s(href="#{href}"), "the status top bar does not link to #{href}"
    end

    # And the bar marks this page as the one being read, which is the whole of "linked
    # from the topbar" being true rather than merely present.
    assert html =~ ~r/href="\/status"[^>]*aria-current="page"/
  end

  test "cross-links the boot-owned half of the same picture", %{conn: conn} do
    # W1.5's call: the two pages keep their own facts and name each other rather than one
    # of them quietly dropping rows. `/status` is the live node; `/settings` is how this
    # installation is configured.
    {:ok, _view, html} = live(conn, "/status")

    assert html =~ ~s(href="/settings#runtime")
  end

  test "never spells an Erlang node name", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/status")

    refute html =~ "nonode@nohost"
    assert html =~ "this computer"
  end

  test "refreshing answers again without changing what it claims", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/status")

    html = render_click(view, "refresh", %{})

    assert html =~ "Runtime status"
    refute html =~ "nonode@nohost"
  end
end
