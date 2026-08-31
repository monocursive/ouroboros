defmodule Ouroboros.Gateway.AccountTest do
  # The failure cases below configure the shared account adapter, which is application
  # state rather than this process's.
  use ExUnit.Case, async: false

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Test.GrokAccountAdapter
  alias Ouroboros.Test.OpenAIAccountAdapter

  test "the account surface is advertised with read and operate scopes" do
    table = Methods.table()

    assert table["account.read"].scope == :read
    assert table["account.login.start"].scope == :operate
    assert table["account.login.complete"].scope == :operate
    assert table["account.login.cancel"].scope == :operate
    assert table["account.logout"].scope == :operate
    assert table["credentials.anthropic.set"].scope == :operate
    assert table["grok.account.read"].scope == :read
    assert table["grok.account.login.start"].scope == :operate
    assert table["grok.account.login.cancel"].scope == :operate
    assert table["credentials.xai.set"].scope == :operate
  end

  test "stores an xAI key through a one-way, closed parameter boundary" do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-gateway-xai-#{System.unique_integer([:positive])}")

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "xai.key")
    previous_path = Application.get_env(:ouroboros, :xai_api_key_file)
    previous_key = System.get_env("XAI_API_KEY")
    Application.put_env(:ouroboros, :xai_api_key_file, path)
    System.delete_env("XAI_API_KEY")

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:ouroboros, :xai_api_key_file, previous_path),
        else: Application.delete_env(:ouroboros, :xai_api_key_file)

      if previous_key,
        do: System.put_env("XAI_API_KEY", previous_key),
        else: System.delete_env("XAI_API_KEY")

      File.rm_rf(root)
    end)

    secret = "xai-gateway-must-not-return"

    assert {:ok, %{provider: :xai, env: "XAI_API_KEY", present: true, source: :stored} = reply} =
             Methods.invoke("credentials.xai.set", %{"api_key" => secret})

    refute inspect(reply) =~ secret
    assert File.read!(path) == secret

    assert {:error, -32602, message} =
             Methods.invoke("credentials.xai.set", %{"api_key" => "xai bad"})

    assert message =~ "whitespace"

    assert {:error, -32602, message} =
             Methods.invoke("credentials.xai.set", %{"api_key" => secret, "label" => "mine"})

    assert message =~ "unsupported fields"
  end

  test "stores an Anthropic key through a one-way, closed parameter boundary" do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-gateway-anthropic-#{System.unique_integer([:positive])}"
      )

    Ouroboros.DataDir.ensure_private!(root)
    path = Path.join(root, "anthropic.key")
    previous_path = Application.get_env(:ouroboros, :anthropic_api_key_file)
    previous_key = System.get_env("ANTHROPIC_API_KEY")
    previous_workspace = System.get_env("ANTHROPIC_WORKSPACE_ID")
    Application.put_env(:ouroboros, :anthropic_api_key_file, path)
    System.delete_env("ANTHROPIC_API_KEY")
    System.delete_env("ANTHROPIC_WORKSPACE_ID")

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:ouroboros, :anthropic_api_key_file, previous_path),
        else: Application.delete_env(:ouroboros, :anthropic_api_key_file)

      if previous_key,
        do: System.put_env("ANTHROPIC_API_KEY", previous_key),
        else: System.delete_env("ANTHROPIC_API_KEY")

      if previous_workspace,
        do: System.put_env("ANTHROPIC_WORKSPACE_ID", previous_workspace),
        else: System.delete_env("ANTHROPIC_WORKSPACE_ID")

      File.rm_rf(root)
    end)

    secret = "sk-ant-gateway-must-not-return"

    assert {:ok,
            %{
              provider: :anthropic,
              env: "ANTHROPIC_API_KEY",
              present: true,
              source: :stored,
              workspace_configured: true
            } = reply} =
             Methods.invoke("credentials.anthropic.set", %{
               "api_key" => secret,
               "workspace_id" => "wrkspc_Gateway123"
             })

    refute inspect(reply) =~ secret
    assert reply.workspace_configured

    assert %{
             "api_key" => ^secret,
             "workspace_id" => "wrkspc_Gateway123"
           } = Jason.decode!(File.read!(path))

    assert {:ok, %{workspace_configured: true}} =
             Methods.invoke("credentials.anthropic.set", %{
               "workspace_id" => "wrkspc_Replacement456"
             })

    assert %{
             "api_key" => ^secret,
             "workspace_id" => "wrkspc_Replacement456"
           } = Jason.decode!(File.read!(path))

    assert {:error, -32602, message} =
             Methods.invoke("credentials.anthropic.set", %{
               "api_key" => secret,
               "label" => "mine"
             })

    assert message =~ "unsupported fields"

    assert {:error, -32602, message} =
             Methods.invoke("credentials.anthropic.set", %{"api_key" => "sk-ant bad"})

    assert message =~ "whitespace"

    assert {:error, -32602, message} =
             Methods.invoke("credentials.anthropic.set", %{
               "workspace_id" => "not-a-workspace"
             })

    assert message =~ "wrkspc_-prefixed"
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

  test "reads and starts the first-party Grok device flow" do
    on_exit(&GrokAccountAdapter.reset/0)
    GrokAccountAdapter.disconnected()

    assert {:ok, %{"requiresGrokAuth" => true, "account" => nil}} =
             Methods.invoke("grok.account.read", %{})

    assert {:ok,
            %{
              "loginId" => "grok-device",
              "verificationUrl" => verification_url,
              "userCode" => "WXYZ-5678"
            }} = Methods.invoke("grok.account.login.start", %{})

    assert verification_url =~ "auth.x.ai"

    assert {:ok, %{"cancelled" => "grok-device"}} =
             Methods.invoke("grok.account.login.cancel", %{"login_id" => "grok-device"})

    assert {:error, -32602, message} =
             Methods.invoke("grok.account.login.start", %{"flow" => "browser"})

    assert message =~ "unsupported fields"
  end

  describe "a boundary that fails is answered in the terms it failed in" do
    setup do
      on_exit(&OpenAIAccountAdapter.succeed/0)
      on_exit(&GrokAccountAdapter.reset/0)
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

    test "Grok account failures keep their provider attribution" do
      GrokAccountAdapter.fail({:error, {:timeout, "grok/login"}})

      assert {:error, -32005, "Grok authentication timed out during grok/login"} =
               Methods.invoke("grok.account.login.start", %{})

      GrokAccountAdapter.fail({:error, {:upstream, "the device code was refused"}})

      assert {:error, -32006, "the runtime failed the call", data} =
               Methods.invoke("grok.account.login.start", %{})

      assert data == ["grok_auth", "the device code was refused"]
    end
  end
end
