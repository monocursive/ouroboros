defmodule Ouroboros.Web.Live.SettingsLiveTest do
  @moduledoc """
  The settings page's hierarchy and the two things it may change: session defaults and
  runtime-owned provider credentials.

  The tests deliberately never begin a subscription login or make a provider request.
  They prove the local UI contract and private persistence boundary, not an external
  account grant.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Prefs

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("s", 40)
  @cookie "_ouroboros_web"

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-settings-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    token_path = Path.join(dir, "gateway.token")
    File.write!(token_path, @token)
    File.chmod!(token_path, 0o600)
    on_exit(fn -> File.rm_rf(dir) end)

    config = Config.new!(data_dir: dir, scope: :operate)
    start_supervised!({Ouroboros.Web, config: config, server: false})

    {:ok, conn: signed_in(), data_dir: dir}
  end

  defp signed_in do
    conn = get(build_conn(), "/auth?token=#{@token}")
    put_req_cookie(build_conn(), @cookie, conn.resp_cookies[@cookie].value)
  end

  test "groups editable defaults, connections, catalogue, and boot configuration", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/settings")

    assert html =~ "Session defaults"
    assert html =~ "AI connections"
    assert html =~ "Subscriptions"
    assert html =~ "API credentials"
    assert html =~ "Providers &amp; models"
    assert html =~ "Runtime &amp; security"
    assert html =~ "Environment only"
    assert html =~ "Secrets stay on the runtime"
    assert html =~ "data-ouro-theme"

    refute html =~ ~r/sk-(ant-)?[A-Za-z0-9_-]{12}/
    refute html =~ ~r/xai-[A-Za-z0-9_-]{12}/
  end

  test "environment-backed keys are not manageable from settings", %{conn: conn} do
    previous_anthropic = System.get_env("ANTHROPIC_API_KEY")
    previous_xai = System.get_env("XAI_API_KEY")
    System.put_env("ANTHROPIC_API_KEY", "sk-ant-settings-must-not-render")
    System.put_env("XAI_API_KEY", "xai-settings-must-not-render")

    on_exit(fn ->
      restore_env("ANTHROPIC_API_KEY", previous_anthropic)
      restore_env("XAI_API_KEY", previous_xai)
    end)

    {:ok, view, html} = live(conn, "/settings")

    assert html =~ "Environment only"
    refute html =~ "sk-ant-settings-must-not-render"
    refute html =~ "xai-settings-must-not-render"
    refute has_element?(view, "button[phx-click=open-anthropic-key]")
    refute has_element?(view, "button[phx-click=open-xai-key]")
  end

  test "saves stated session defaults without starting a session", %{conn: conn, data_dir: dir} do
    {:ok, view, _html} = live(conn, "/settings")

    render_click(view, "pick-sandbox", %{"mode" => "read_only"})

    html =
      view
      |> form("#session-defaults", %{
        "provider" => "native",
        "model_choice" => "runtime_default",
        "model_search" => "",
        "workspace" => dir,
        "effort" => ""
      })
      |> render_submit()

    assert html =~ "Session defaults saved for this Ouroboros runtime."

    assert Prefs.read(dir) == %{
             "provider" => "native",
             "sandbox_mode" => "read_only",
             "workspace" => dir
           }
  end

  test "opens managed key forms without putting a credential into the page", %{conn: conn} do
    previous_anthropic = System.get_env("ANTHROPIC_API_KEY")
    previous_xai = System.get_env("XAI_API_KEY")
    System.delete_env("ANTHROPIC_API_KEY")
    System.delete_env("XAI_API_KEY")

    on_exit(fn ->
      restore_env("ANTHROPIC_API_KEY", previous_anthropic)
      restore_env("XAI_API_KEY", previous_xai)
    end)

    {:ok, view, _html} = live(conn, "/settings")

    html = render_click(view, "open-anthropic-key", %{})
    assert html =~ ~s/id="anthropic-key-dialog"/
    assert html =~ ~s/type="password"/
    refute html =~ "anthropic_api_key="

    html = render_click(view, "cancel-anthropic-key", %{})
    refute html =~ ~s/id="anthropic-key-dialog"/

    html = render_click(view, "open-xai-key", %{})
    assert html =~ ~s/id="xai-key-dialog"/
    assert html =~ ~s/type="password"/
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
