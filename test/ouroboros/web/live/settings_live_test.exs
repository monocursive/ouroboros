defmodule Ouroboros.Web.Live.SettingsLiveTest do
  @moduledoc """
  The settings page's hierarchy and the two things it may change: session defaults and
  runtime-owned model credentials.

  There is one provider — `native`, in this runtime's own process — so nothing here picks
  between providers; what it stores are the model, folder and posture a new session starts
  with, and the API keys that runtime holds for each model vendor.

  The tests deliberately never begin a subscription login or make a model request. They
  prove the local UI contract and private persistence boundary, not an external account
  grant.
  """

  use ExUnit.Case, async: false

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias Ouroboros.Web.Config
  alias Ouroboros.Web.Prefs

  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("s", 40)
  @cookie "_ouroboros_web"

  defmodule FailedCredentialReport do
    def available?, do: true
    def credential_report, do: raise("credential probe failed")
  end

  setup do
    dir =
      Path.join(System.tmp_dir!(), "ouroboros-web-settings-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(dir)
    Ouroboros.Test.FirstUseIsolation.setup(dir, Ouroboros.Provider.Native.Model.ReqLLM)
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
    {:ok, view, html} = live(conn, "/settings")

    assert has_element?(view, "#connection-grok", "Not connected")
    assert has_element?(view, "#connection-grok", "grok login")
    assert has_element?(view, "#connection-grok img[src='/web/providers/grok.svg']")

    [connections, defaults] =
      Enum.map(["id=\"connections\"", "id=\"defaults\""], &(:binary.match(html, &1) |> elem(0)))

    assert connections < defaults
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
        "model_choice" => "runtime_default",
        "model_search" => "",
        "workspace" => dir,
        "effort" => ""
      })
      |> render_submit()

    assert html =~ "Session defaults saved for this Ouroboros runtime."

    assert Prefs.read(dir) == %{
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

  test "refresh discovers a Grok sign-in, renewal and removal without exposing tokens", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, "/settings")
    path = Application.fetch_env!(:ouroboros, :grok_auth_file)
    write_grok(path, DateTime.utc_now() |> DateTime.add(3600) |> DateTime.to_iso8601())
    html = render_click(view, "refresh-connections")
    assert has_element?(view, "#connection-grok", "Connected locally")
    refute html =~ "grok-settings-secret-canary"
    refute html =~ "refresh-settings-secret-canary"
    assert has_element?(view, "[id='credential-xAI-XAI_API_KEY']", "Not configured")

    write_grok(path, "2020-01-01T00:00:00Z")
    render_click(view, "refresh-connections")
    assert has_element?(view, "#connection-grok", "Sign in again")
    File.rm!(path)
    render_click(view, "refresh-connections")
    assert has_element?(view, "#connection-grok", "Not connected")
  end

  test "API key save updates its own connection and stays out of HTML", %{conn: conn} do
    {:ok, view, _} = live(conn, "/settings")
    render_click(view, "open-xai-key")

    html =
      view
      |> form("#xai-key-form", %{"xai_api_key" => "xai-settings-secret-canary"})
      |> render_submit()

    assert has_element?(view, "[id='credential-xAI-XAI_API_KEY']", "Key stored")
    assert has_element?(view, "#connection-grok", "Not connected")
    refute html =~ "xai-settings-secret-canary"

    assert File.read!(Application.fetch_env!(:ouroboros, :xai_api_key_file)) ==
             "xai-settings-secret-canary"
  end

  test "unavailable and invalid credentials have distinct states" do
    for {state, expected} <- [{"unavailable", "Status unavailable"}, {"invalid", "Sign in again"}] do
      html =
        render_component(&Ouroboros.Web.Live.SettingsLive.grok_subscription_card/1,
          credential: %{present: false, credential_state: state}
        )

      assert html =~ expected
      refute html =~ "Not connected"
    end
  end

  test "view-only stored keys do not claim to be environment-owned" do
    html =
      render_component(&Ouroboros.Web.Live.SettingsLive.credential_card/1,
        provider: "xAI",
        env: "XAI_API_KEY",
        managed: false,
        read_only: true,
        credential: %{present: true, source: "stored", credential_state: "present"}
      )

    assert html =~ "Key stored"
    assert html =~ "view-only"
    refute html =~ "phx-click=\"open-xai-key\""
  end

  test "legacy credential presence does not invent an environment source" do
    html =
      render_component(&Ouroboros.Web.Live.SettingsLive.credential_card/1,
        provider: "OpenAI",
        env: "OPENAI_API_KEY",
        managed: false,
        credential: %{present: true, source: nil, credential_state: "present"}
      )

    assert html =~ "Key configured"
    refute html =~ "Environment key"
  end

  test "configured additional providers stay visible outside the setup disclosure", %{conn: conn} do
    System.put_env("GOOGLE_API_KEY", "google-settings-canary")
    {:ok, view, html} = live(conn, "/settings")
    assert has_element?(view, "#credential-Google-GOOGLE_API_KEY", "Environment key")
    refute has_element?(view, "#other-provider-credentials #credential-Google-GOOGLE_API_KEY")
    refute html =~ "google-settings-canary"
  end

  defp write_grok(path, expires) do
    credential = %{
      "key" => "grok-settings-secret-canary",
      "refresh_token" => "refresh-settings-secret-canary",
      "auth_mode" => "oidc",
      "oidc_issuer" => "https://auth.x.ai",
      "oidc_client_id" => "b1a00492-073a-47ea-816f-4c329264a828",
      "expires_at" => expires
    }

    File.write!(
      path,
      JSON.encode!(%{"https://auth.x.ai::b1a00492-073a-47ea-816f-4c329264a828" => credential})
    )

    File.chmod!(path, 0o600)
  end

  test "a missing or failed report clears stale connection certainty and recovers", %{conn: conn} do
    write_grok(
      Application.fetch_env!(:ouroboros, :grok_auth_file),
      DateTime.utc_now() |> DateTime.add(3600) |> DateTime.to_iso8601()
    )

    {:ok, view, _} = live(conn, "/settings")
    assert has_element?(view, "#connection-grok", "Connected locally")

    for model <- [FailedCredentialReport, Ouroboros.Test.BrowserModel] do
      Application.put_env(:ouroboros, :native_model_module, model)
      render_click(view, "refresh-connections")
      assert has_element?(view, "#connection-grok", "Status unavailable")
      refute has_element?(view, "#connection-grok", "Checking")
      refute has_element?(view, "#connection-grok", "Connected locally")

      assert has_element?(
               view,
               ".ouro-settings-connections-summary",
               "Connection status unavailable"
             )
    end

    Application.put_env(:ouroboros, :native_model_module, Ouroboros.Provider.Native.Model.ReqLLM)
    render_click(view, "refresh-connections")
    assert has_element?(view, "#connection-grok", "Connected locally")
    refute has_element?(view, "#connections [role=alert]")
  end

  defp restore_env(name, nil), do: System.delete_env(name)
  defp restore_env(name, value), do: System.put_env(name, value)
end
