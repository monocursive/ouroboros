defmodule Ouroboros.Audit.WebTest do
  use ExUnit.Case, async: false
  @moduletag :capture_log
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  alias Ouroboros.Audit.{Config, Store}
  alias Ouroboros.Provider.Native.Journal
  @endpoint Ouroboros.Web.Endpoint

  setup do
    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "ouro-audit-web-#{System.unique_integer([:positive])}")
    Ouroboros.DataDir.ensure_private!(root)
    token = "test-audit-web-token-12345678901234567890"
    File.write!(Path.join(root, "gateway.token"), token)
    File.chmod!(Path.join(root, "gateway.token"), 0o600)
    previous = Application.get_env(:ouroboros, :audit)
    :ok = Supervisor.terminate_child(Ouroboros.Supervisor, Store)
    config = Config.new!(mode: :local, capture: :full, root: Path.join(root, "evidence"))
    Application.put_env(:ouroboros, :audit, config)
    start_supervised!({Store, config: config})

    start_supervised!(
      {Ouroboros.Web,
       config: Ouroboros.Web.Config.new!(data_dir: root, scope: :operate), server: false}
    )

    stream = Journal.digest("web-session")

    {:ok, _} =
      Store.append(stream, "session_opened", %{
        "session_id" => "example-session",
        "actor_id" => "alice"
      })

    {:ok, _} =
      Store.append(stream, "model_call", %{
        "model" => "example-model",
        "request" => "<script>alert('unsafe')</script>",
        "ledger_effect_id" => "effect",
        "turn_id" => "turn"
      })

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :audit, previous),
        else: Application.delete_env(:ouroboros, :audit)

      Supervisor.restart_child(Ouroboros.Supervisor, Store)
      File.rm_rf(root)
    end)

    auth = build_conn() |> get("/auth?token=#{token}")

    conn =
      build_conn() |> put_req_cookie("_ouroboros_web", auth.resp_cookies["_ouroboros_web"].value)

    %{conn: conn, root: root, stream: stream}
  end

  test "search and call details render escaped evidence and unknown outcomes", ctx do
    assert {:ok, view, html} = live(ctx.conn, "/audit")
    assert html =~ "Investigate execution"
    assert view |> form("form", %{"actor_id" => "alice"}) |> render_submit() =~ "example-model"
    assert {:ok, detail, html} = live(ctx.conn, "/audit/#{ctx.stream}")
    assert html =~ "1 calls have no recorded terminal outcome"
    assert html =~ "&lt;script&gt;"
    refute html =~ "<script>alert"

    assert detail |> element("button", "Prepare export") |> render_click() =~
             "Download evidence bundle"
  end

  test "browser bundle download contains a verifiable tar with safe paths", ctx do
    assert {:ok, bundle} = Store.export([ctx.stream])
    conn = get(ctx.conn, "/audit-bundle/#{bundle.bundle_id}")
    assert conn.status == 200
    assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store"]
    {:ok, entries} = :erl_tar.extract({:binary, conn.resp_body}, [:memory])
    assert Enum.any?(entries, fn {name, _} -> to_string(name) == "manifest.json" end)

    assert Enum.all?(entries, fn {name, _} ->
             to_string(name) == "manifest.json" or
               Ouroboros.Audit.Bundle.safe_path?(to_string(name))
           end)
  end
end
