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

  # W1.1 / W1.5 / W1.6 — navigation, the split with `/status`, and internals as words.
  test "carries the one top bar, and keeps its own breadcrumb under it", %{conn: conn} do
    {:ok, _view, html} = live(conn, "/settings")

    assert html =~ ~s(class="ouro-topbar")

    for href <- ["/", "/new", "/settings", "/audit", "/status"] do
      assert html =~ ~s(href="#{href}"), "the settings top bar does not link to #{href}"
    end

    # Under it, not instead of it.
    assert html =~ "← Sessions"

    breadcrumb = :binary.match(html, "← Sessions") |> elem(0)
    bar = :binary.match(html, ~s(class="ouro-topbar")) |> elem(0)
    assert bar < breadcrumb, "the breadcrumb is above the top bar"
  end

  test "runtime facts name the computer and point at the page that owns the rest",
       %{conn: conn} do
    # §3.5: `/settings` showed `nonode@nohost`. §3.1: it duplicated half of `/status`.
    # W1.5's call is to keep the node here (it is the installation this page describes) and
    # to send node role, connected machines and the live session count to `/status` rather
    # than ask the same runtime the same question twice.
    {:ok, _view, html} = live(conn, "/settings")

    refute html =~ "nonode@nohost"
    assert html =~ "Runtime node"
    assert html =~ "this computer"
    refute html =~ "Node role"
    assert html =~ ~s(href="/status")
  end

  # W1.4. `/new` builds the model control with `NewSession.model_field/2`, which keeps the
  # current choice as a row of its own when the catalogue snapshot does not list it; this
  # page used `/1` in three places (`settings_live.ex:363`, `:378`, and its render), so a
  # remembered model outside the snapshot was drawn as free text and — once it had been
  # promoted to a catalogue choice — reset to the runtime default by any other edit
  # (review §3.5).
  test "a remembered model the catalogue does not list survives an edit to another field",
       %{conn: conn, data_dir: dir} do
    :ok = Prefs.write(dir, %{"model" => "vendor:unlisted-model-9"})

    {:ok, view, html} = live(conn, "/settings")

    # Drawn as its own row, with the runtime's own caveat on it, rather than as a
    # "Custom model…" box that says nothing about where the id came from.
    assert html =~ "vendor:unlisted-model-9"

    assert html =~ "Current choice; catalogue metadata unavailable",
           "the remembered model is not offered as a row of its own"

    assert has_element?(
             view,
             ~s(#session-defaults option[value="catalog:vendor:unlisted-model-9"])
           )

    # And touching a different field leaves it alone.
    after_edit =
      view |> form("#session-defaults", %{"workspace" => dir}) |> render_change()

    assert after_edit =~ "Using vendor:unlisted-model-9"

    refute after_edit =~ "Ouroboros will choose the recommended model",
           "an edit to the workspace reset the remembered model to the runtime default"

    # The writer agrees with the control: saving keeps the model it is drawing.
    view |> form("#session-defaults", %{"workspace" => dir}) |> render_submit()
    assert Prefs.read(dir)["model"] == "vendor:unlisted-model-9"
  end

  # The reviewer's CONTROL, adopted: the two arities really do differ on the case W1.4 is
  # about. Without it, a test that only drives the page could pass against a `/1` that had
  # quietly started keeping the row.
  test "model_field/1 loses the remembered id that /2 keeps" do
    {:ok, catalogue} = Ouroboros.Web.Call.call(:read, "runtime.models", %{})

    form = %Ouroboros.Web.Live.NewSession{
      Ouroboros.Web.Live.NewSession.new()
      | model_choice: Ouroboros.Web.Live.NewSession.choice("catalog:vendor:unlisted-model-9")
    }

    one = Ouroboros.Web.Live.NewSession.model_field(catalogue)
    two = Ouroboros.Web.Live.NewSession.model_field(catalogue, form)

    refute Ouroboros.Web.Live.NewSession.offers?(one, form.model_choice),
           "model_field/1 already offers the remembered model, so W1.4 changed nothing"

    assert Ouroboros.Web.Live.NewSession.offers?(two, form.model_choice),
           "model_field/2 does not keep the remembered model"
  end

  # `field/1` is the second call site, and this is the test that holds it: `save-defaults`
  # builds `start_params/2` from it, so a field without the remembered row writes no model
  # at all — even though the page was drawing one a moment earlier.
  test "a sandbox change then Save keeps the remembered model byte for byte",
       %{conn: conn, data_dir: dir} do
    :ok = Prefs.write(dir, %{"model" => "vendor:unlisted-model-9"})

    {:ok, view, html} = live(conn, "/settings")
    assert html =~ "vendor:unlisted-model-9"

    render_click(view, "pick-sandbox", %{"mode" => "unrestricted"})
    view |> form("#session-defaults", %{}) |> render_submit()

    prefs = Prefs.read(dir)
    assert prefs["model"] == "vendor:unlisted-model-9"
    assert prefs["sandbox_mode"] == "unrestricted"
  end

  # F12. Three different facts, three different words. A status that answered without a
  # `:node` key did not report one; a status that answered `nonode@nohost` reported that it
  # has no name; and no status at all is still loading. Spelling the first as "this
  # computer" would be the page claiming something nothing said.
  test "a runtime node is loading, unreported, or a machine — and they read differently" do
    alias Ouroboros.Web.Live.SettingsLive

    assert SettingsLive.runtime_node(nil) == "Loading…"
    assert SettingsLive.runtime_node(%{role: :standalone}) == "Not reported"
    assert SettingsLive.runtime_node(%{node: :nonode@nohost}) == "this computer"
    assert SettingsLive.runtime_node(%{node: :ouro@alpha}) == "alpha"
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
