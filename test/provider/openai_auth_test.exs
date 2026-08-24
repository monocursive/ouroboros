defmodule Ouroboros.Provider.OpenAIAuthTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.OpenAIAuth

  defmodule FakeHTTP do
    def post_json(url, body, _timeout) do
      notify({:post_json, url, body})

      cond do
        String.ends_with?(url, "/api/accounts/deviceauth/usercode") ->
          {:ok, 200, [],
           %{"device_auth_id" => "device-1", "user_code" => "ABCD", "interval" => 0}}

        String.ends_with?(url, "/api/accounts/deviceauth/token") ->
          {:ok, 200, [],
           %{"authorization_code" => "device-code", "code_verifier" => "device-verifier"}}
      end
    end

    def post_form(url, body, _timeout) do
      notify({:post_form, url, body})
      {:ok, 200, [], token_response()}
    end

    defp token_response do
      claims = %{
        "email" => "operator@example.com",
        "https://api.openai.com/auth" => %{
          "chatgpt_account_id" => "account-1",
          "chatgpt_plan_type" => "pro"
        }
      }

      payload = claims |> JSON.encode!() |> Base.url_encode64(padding: false)

      %{
        "id_token" => "header.#{payload}.signature",
        "access_token" => "header.#{payload}.signature",
        "refresh_token" => "refresh-secret",
        "expires_in" => 3_600
      }
    end

    defp notify(message) do
      if pid = Application.get_env(:ouroboros, :openai_auth_test_pid), do: send(pid, message)
    end
  end

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-openai-auth-#{System.unique_integer([:positive])}")

    path = Path.join(root, "oauth.json")
    File.mkdir_p!(root)
    Application.put_env(:ouroboros, :openai_auth_test_pid, self())
    System.delete_env("OPENAI_API_KEY")

    on_exit(fn ->
      Application.delete_env(:ouroboros, :openai_auth_test_pid)
      System.delete_env("OPENAI_API_KEY")
      File.rm_rf(root)
    end)

    %{path: path}
  end

  test "device-code login persists a ReqLLM-compatible private credential", %{path: path} do
    server =
      start_supervised!(
        {OpenAIAuth,
         name: nil,
         credential_path: path,
         issuer: "https://issuer.test",
         http: FakeHTTP,
         device_min_interval_ms: 0,
         device_poll_margin_ms: 0,
         device_timeout_ms: 5_000}
      )

    assert {:ok,
            %{
              "loginId" => login_id,
              "verificationUrl" => "https://issuer.test/codex/device",
              "userCode" => "ABCD"
            }} = OpenAIAuth.login(:device_code, server)

    assert is_binary(login_id)
    assert_receive {:post_json, "https://issuer.test/api/accounts/deviceauth/usercode", _}

    assert eventually(fn ->
             match?({:ok, %{"account" => %{"type" => "chatgpt"}}}, OpenAIAuth.read(server))
           end)

    assert {:ok, account} = OpenAIAuth.read(server)
    assert account["account"]["email"] == "operator@example.com"
    assert account["account"]["planType"] == "pro"
    refute inspect(account) =~ "refresh-secret"

    assert {:ok, stat} = File.stat(path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600

    assert {:ok, credential} = ReqLLM.OAuth.resolve(:openai_codex, oauth_file: path)
    assert credential.account_id == "account-1"
    assert credential.token =~ "header."
  end

  test "browser PKCE validates state and completes without a CLI", %{path: path} do
    server =
      start_supervised!(
        {OpenAIAuth,
         name: nil,
         credential_path: path,
         issuer: "https://issuer.test",
         http: FakeHTTP,
         browser_port: 0}
      )

    assert {:ok, %{"loginId" => login_id, "authUrl" => url}} =
             OpenAIAuth.login(:browser, server)

    query = URI.parse(url).query |> URI.decode_query()
    assert query["code_challenge_method"] == "S256"
    assert query["originator"] == "ouroboros"

    assert {:error, :invalid_oauth_state} =
             OpenAIAuth.complete(login_id, "browser-code", "wrong-state", server)

    assert {:ok, %{}} =
             OpenAIAuth.complete(login_id, "browser-code", query["state"], server)

    assert_receive {:post_form, "https://issuer.test/oauth/token", fields}
    assert fields["code"] == "browser-code"
    assert fields["code_verifier"] != ""

    assert {:ok, credential} = ReqLLM.OAuth.resolve(:openai_codex, oauth_file: path)
    assert credential.account_id == "account-1"
    refute File.read!(path) =~ "browser-code"

    assert {:ok, %{}} = OpenAIAuth.logout(server)
    assert {:error, _reason} = ReqLLM.OAuth.resolve(:openai_codex, oauth_file: path)
  end

  defp eventually(fun, attempts \\ 100) do
    cond do
      fun.() -> true
      attempts > 0 -> Process.sleep(10) && eventually(fun, attempts - 1)
      true -> false
    end
  end
end
