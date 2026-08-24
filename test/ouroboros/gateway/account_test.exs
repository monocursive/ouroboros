defmodule Ouroboros.Gateway.AccountTest do
  # The failure cases below configure the shared account adapter, which is application
  # state rather than this process's.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Test.OpenAIAccountAdapter

  test "the account surface is advertised with read and operate scopes" do
    table = Methods.table()

    assert table["account.read"].scope == :read
    assert table["account.login.start"].scope == :operate
    assert table["account.login.complete"].scope == :operate
    assert table["account.login.cancel"].scope == :operate
    assert table["account.logout"].scope == :operate
  end

  test "reads account state and starts either supported managed ChatGPT flow" do
    assert {:ok, %{"requiresOpenaiAuth" => true, "account" => nil}} =
             Methods.invoke("account.read", %{})

    assert {:ok, %{"loginId" => "browser-login", "authUrl" => auth_url}} =
             Methods.invoke("account.login.start", %{"flow" => "browser"})

    assert auth_url =~ "auth.openai.com"

    assert {:ok,
            %{
              "loginId" => "device-login",
              "verificationUrl" => verification_url,
              "userCode" => "ABCD-1234"
            }} = Methods.invoke("account.login.start", %{"flow" => "device_code"})

    assert verification_url == "https://auth.openai.com/codex/device"

    assert {:ok, %{}} =
             Methods.invoke("account.login.complete", %{
               "login_id" => "browser-login",
               "code" => "auth-code",
               "state" => "oauth-state"
             })
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

  describe "a boundary that fails is answered in the terms it failed in" do
    setup do
      on_exit(&OpenAIAccountAdapter.succeed/0)
      :ok
    end

    test "every account method maps timeout, unavailable, and upstream refusal" do
      # Every account method can produce these failures, so each method is asked.
      methods = [
        {"account.read", %{}},
        {"account.login.start", %{"flow" => "browser"}},
        {"account.login.complete",
         %{"login_id" => "login-1", "code" => "code", "state" => "state"}},
        {"account.login.cancel", %{"login_id" => "login-1"}},
        {"account.logout", %{}}
      ]

      for {method, params} <- methods do
        OpenAIAccountAdapter.fail({:error, {:timeout, "account/read"}})
        assert {:error, -32005, message} = Methods.invoke(method, params)
        assert message == "OpenAI authentication timed out during account/read"

        OpenAIAccountAdapter.fail(
          {:error, {:unavailable, "the OpenAI account service is not running on this node"}}
        )

        assert {:error, -32004, message} = Methods.invoke(method, params)
        assert message == "the OpenAI account service is not running on this node"

        OpenAIAccountAdapter.fail({:error, {:upstream, "the OAuth server refused the request"}})
        assert {:error, -32006, message, data} = Methods.invoke(method, params)
        assert message == "the runtime failed the call"
        assert data == ["openai_auth", "the OAuth server refused the request"]
      end
    end
  end
end
