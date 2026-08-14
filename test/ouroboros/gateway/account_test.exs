defmodule Ouroboros.Gateway.AccountTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Gateway.Methods

  test "the account surface is advertised with read and operate scopes" do
    table = Methods.table()

    assert table["account.read"].scope == :read
    assert table["account.login.start"].scope == :operate
    assert table["account.login.cancel"].scope == :operate
    assert table["account.logout"].scope == :operate
  end

  test "reads account state and starts either supported managed ChatGPT flow" do
    assert {:ok, %{"requiresOpenaiAuth" => true, "account" => nil}} =
             Methods.invoke("account.read", %{})

    assert {:ok, %{"loginId" => "browser-login", "authUrl" => auth_url}} =
             Methods.invoke("account.login.start", %{"flow" => "browser"})

    assert auth_url =~ "chatgpt.com"

    assert {:ok,
            %{
              "loginId" => "device-login",
              "verificationUrl" => verification_url,
              "userCode" => "ABCD-1234"
            }} = Methods.invoke("account.login.start", %{"flow" => "device_code"})

    assert verification_url == "https://auth.openai.com/codex/device"
  end

  test "cancels and logs out without accepting unknown fields" do
    assert {:ok, %{"cancelled" => "login-1"}} =
             Methods.invoke("account.login.cancel", %{"login_id" => "login-1"})

    assert {:ok, %{}} = Methods.invoke("account.logout", %{})

    assert {:error, -32602, message} = Methods.invoke("account.read", %{"refresh" => true})
    assert message =~ "unsupported fields"

    assert {:error, -32602, message} =
             Methods.invoke("account.login.start", %{"flow" => "oauth-ish"})

    assert message =~ "browser or device_code"
  end
end
