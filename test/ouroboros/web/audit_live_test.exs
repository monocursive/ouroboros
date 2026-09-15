defmodule Ouroboros.Web.AuditLiveTest do
  @moduledoc """
  `/audit`: what the page says when there is nothing to investigate, and how it gets there.

  The review found the page opening with the raw atom `Audit operation failed:
  :audit_disabled` whenever recording was off, on a surface whose whole subject is
  evidence a person is meant to be able to read
  (`docs/design-qa/ui-review-2026-09-15.md` §3.5). It also had no route to any other page
  except a breadcrumb (§3.1).
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Config

  @endpoint Ouroboros.Web.Endpoint

  @token String.duplicate("a", 40)
  @cookie "_ouroboros_web"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-audit-#{System.unique_integer([:positive])}")

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

  # Recording off, which is the state that produced the raw atom.
  defp audit_disabled do
    previous = Application.get_env(:ouroboros, :audit, [])
    Application.put_env(:ouroboros, :audit, Keyword.put(previous, :mode, :standard))
    on_exit(fn -> Application.put_env(:ouroboros, :audit, previous) end)
  end

  test "carries the one top bar and keeps its breadcrumb under it", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/audit")

    assert html =~ ~s(class="ouro-topbar")

    for href <- ["/", "/new", "/settings", "/audit", "/status"] do
      assert html =~ ~s(href="#{href}"), "the audit top bar does not link to #{href}"
    end

    assert html =~ ~r/href="\/audit"[^>]*aria-current="page"/
  end

  test "an evidence stream carries the same bar", %{conn: conn} do
    audit_disabled()

    {:ok, _view, html} = live(conn, "/audit/no-such-stream")

    assert html =~ ~s(class="ouro-topbar")
    assert html =~ ~s(href="/status")
  end

  test "recording being off is a sentence, not an atom", %{conn: conn} do
    audit_disabled()

    {:ok, _view, html} = live(conn, "/audit")

    refute html =~ ":audit_disabled",
           "the page still prints the runtime's own atom at a reader"

    assert html =~ "Audit recording is disabled on this runtime",
           "the page does not say, in words, why there is nothing to search"

    # The half the gateway wrote for a person ("Audit operation failed") is kept: it is
    # what the runtime said, and only the inspected atom after it was never addressed to
    # anybody. What must not survive is the atom.
    assert html =~ "Audit operation failed: Audit recording is disabled on this runtime."
  end

  test "no numeric protocol code reaches the page", %{conn: conn} do
    audit_disabled()

    {:ok, _view, html} = live(conn, "/audit")

    refute html =~ "-32004"
    refute html =~ "-32"
  end
end
