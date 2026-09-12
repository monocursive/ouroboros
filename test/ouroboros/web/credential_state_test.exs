defmodule Ouroboros.Web.CredentialStateTest do
  use ExUnit.Case, async: false
  import Phoenix.ConnTest
  import Phoenix.LiveViewTest
  alias Ouroboros.Web.Live.{NewSession, AccountConnection}
  alias Ouroboros.Provider.OpenAIAuth
  @endpoint Ouroboros.Web.Endpoint
  @token String.duplicate("c", 40)
  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    Ouroboros.DataDir.ensure_private!(dir)
    Ouroboros.Test.FirstUseIsolation.setup(dir)
    Application.put_env(:ouroboros, :account_adapter, OpenAIAuth)
    File.write!(Path.join(dir, "gateway.token"), @token)
    File.chmod!(Path.join(dir, "gateway.token"), 0o600)

    start_supervised!(
      {Ouroboros.Web,
       config: Ouroboros.Web.Config.new!(data_dir: dir, scope: :operate), server: false}
    )

    conn = get(build_conn(), "/auth?token=" <> @token) |> recycle()
    %{conn: conn, path: OpenAIAuth.credential_path()}
  end

  test "real account method and both operator pages distinguish absence, invalid and unavailable",
       %{conn: conn, path: path} do
    for {content, copy, state} <- [
          {nil, "No local ChatGPT credential material", "absent"},
          {"SECRET corrupt store", "credential store is malformed", "invalid"},
          {JSON.encode!(%{"openai-codex" => %{"access" => "SECRET"}}),
           "Provider acceptance and model access are not verified", "present"}
        ] do
      if content, do: File.write!(path, content)
      assert {:ok, account} = Ouroboros.Web.Call.call(:operate, "account.read", %{})
      assert account["credentialState"] == state

      for route <- ["/new", "/settings"] do
        {:ok, view, html} = live(conn, route)
        html = account_page(view, route, html)
        assert html =~ copy
        refute html =~ "SECRET"
        refute html =~ path
        GenServer.stop(view.pid)
      end
    end

    File.rm!(path)
    File.mkdir!(path)

    for route <- ["/new", "/settings"] do
      {:ok, view, html} = live(conn, route)
      html = account_page(view, route, html)
      assert html =~ "Status unavailable"
      assert html =~ "does not mean credentials are missing"
      refute html =~ "No local ChatGPT credential material"
      GenServer.stop(view.pid)
    end
  end

  defp account_page(view, "/new", _html),
    do: render_change(view, "change", %{"model_choice" => "catalog:openai_codex:gpt-5.6-sol"})

  defp account_page(_view, _route, html), do: html

  test "an externally initiated login remains followed across an unavailable observation" do
    socket = %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        account: %{"login" => %{"status" => "pending"}},
        login: nil,
        polling_account?: false
      }
    }

    fail = fn _, _, _ -> {:error, -32004, "unavailable"} end
    failed = AccountConnection.poll(socket, fail, 60_000)
    assert failed.assigns.polling_account?
    assert NewSession.account_card(failed.assigns.account, nil).state == :waiting
    failed_again = AccountConnection.poll(failed, fail, 60_000)
    assert failed_again.assigns.polling_account?

    success = %{
      "credentialState" => "present",
      "account" => %{"type" => "chatgpt"},
      "login" => %{"status" => "succeeded"}
    }

    recovered = AccountConnection.poll(failed_again, fn _, _, _ -> {:ok, success} end, 60_000)
    refute recovered.assigns.polling_account?
    assert NewSession.account_card(recovered.assigns.account, nil).state == :connected
  end

  test "failed observation clears stale certainty without dropping a pending login" do
    account = %{"account" => %{"type" => "chatgpt"}, "credentialState" => "present"}

    socket = %Phoenix.LiveView.Socket{
      assigns: %{__changed__: %{}, account: account, login: nil, polling_account?: false}
    }

    fail = fn _, _, _ -> {:error, -32004, "SECRET internal path"} end
    unavailable = AccountConnection.read(socket, fail)
    assert NewSession.account_card(unavailable.assigns.account, nil).state == :unavailable
    refute inspect(unavailable.assigns.account) =~ "SECRET"
    refute NewSession.usable?(unavailable.assigns.account)

    login = %{login_id: "fixture", code: "ABCD", url: "https://example.test"}
    socket = Phoenix.Component.assign(socket, :login, login)
    failed_poll = AccountConnection.poll(socket, fail, 60_000)
    assert failed_poll.assigns.login == login
    assert NewSession.account_card(failed_poll.assigns.account, login).state == :waiting
    restored = AccountConnection.poll(failed_poll, fn _, _, _ -> {:ok, account} end, 60_000)
    assert restored.assigns.login == nil
    assert NewSession.account_card(restored.assigns.account, nil).state == :connected
    assert NewSession.account_card(%{"requiresOpenaiAuth" => false}, nil).state == :connected
    assert NewSession.account_card(nil, nil).state == :checking
  end
end
