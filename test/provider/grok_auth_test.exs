defmodule Ouroboros.Provider.GrokAuthTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.GrokAuth

  setup do
    root =
      Path.join(System.tmp_dir!(), "ouroboros-grok-auth-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)
    executable = Path.join(root, "fake-grok")
    auth_path = Path.join(root, "auth.json")

    on_exit(fn -> File.rm_rf(root) end)

    %{root: root, executable: executable, auth_path: auth_path}
  end

  test "projects an existing subscription credential without exposing its tokens", %{
    auth_path: path
  } do
    write_auth(path, "existing-secret", "subscriber@example.test")

    assert GrokAuth.credential_present?(path: path)

    start_supervised!({GrokAuth, name: :existing_grok_auth, auth_path: path})
    assert {:ok, read} = GrokAuth.read(:existing_grok_auth)

    assert read["account"] == %{
             "type" => "grok_subscription",
             "label" => "subscriber@example.test"
           }

    assert read["requiresGrokAuth"] == false
    refute inspect(read) =~ "existing-secret"
  end

  test "an API-key entry is not mistaken for subscription access", %{auth_path: path} do
    File.write!(
      path,
      Jason.encode!(%{
        "xai::api_key" => %{"key" => "xai-secret", "auth_mode" => "api_key"}
      })
    )

    File.chmod!(path, 0o600)
    refute GrokAuth.credential_present?(path: path)
  end

  test "device login returns only the verification URL and code, then observes CLI storage",
       %{root: root, executable: executable, auth_path: path} do
    script = """
    #!/bin/sh
    printf '\nTo sign in, open this URL in your browser:\n\n'
    printf '  https://auth.x.ai/device?user_code=WXYZ-5678\n\n'
    printf 'Confirm this code in your browser:\n\n  WXYZ-5678\n'
    sleep 0.05
    printf '%s' '{"https://auth.x.ai":{"key":"cli-secret","auth_mode":"oidc","email":"new@example.test"}}' > "$GROK_HOME/auth.json"
    chmod 600 "$GROK_HOME/auth.json"
    printf '\n✓ Signed in as new@example.test\n'
    """

    File.write!(executable, script)
    File.chmod!(executable, 0o700)

    start_supervised!(
      {GrokAuth,
       name: :device_grok_auth,
       executable: executable,
       auth_path: path,
       env: %{"GROK_HOME" => root}}
    )

    assert {:ok,
            %{
              "loginId" => login_id,
              "verificationUrl" => "https://auth.x.ai/device?user_code=WXYZ-5678",
              "userCode" => "WXYZ-5678"
            } = reply} = GrokAuth.login(:device_grok_auth)

    refute inspect(reply) =~ "cli-secret"
    assert eventually(fn -> GrokAuth.credential_present?(path: path) end)
    assert {:ok, read} = GrokAuth.read(:device_grok_auth)
    assert read["account"]["label"] == "new@example.test"
    assert read["login"]["loginId"] == login_id
    refute inspect(read) =~ "cli-secret"
  end

  test "ignores a non-xAI HTTPS URL printed before the device verification link",
       %{root: root, executable: executable, auth_path: path} do
    script = """
    #!/bin/sh
    printf 'See https://evil.example/phish for help\\n'
    printf 'https://auth.x.ai/device?user_code=WXYZ-5678\\nWXYZ-5678\\n'
    sleep 0.05
    printf '%s' '{"https://auth.x.ai":{"key":"cli-secret","auth_mode":"oidc","email":"new@example.test"}}' > "$GROK_HOME/auth.json"
    chmod 600 "$GROK_HOME/auth.json"
    """

    File.write!(executable, script)
    File.chmod!(executable, 0o700)

    start_supervised!(
      {GrokAuth,
       name: :allowlist_grok_auth,
       executable: executable,
       auth_path: path,
       env: %{"GROK_HOME" => root}}
    )

    assert {:ok, %{"verificationUrl" => "https://auth.x.ai/device?user_code=WXYZ-5678"}} =
             GrokAuth.login(:allowlist_grok_auth)
  end

  test "a relative grok_auth_file is ignored rather than resolved against cwd" do
    previous = Application.get_env(:ouroboros, :grok_auth_file)
    Application.put_env(:ouroboros, :grok_auth_file, "relative/auth.json")

    on_exit(fn ->
      if previous,
        do: Application.put_env(:ouroboros, :grok_auth_file, previous),
        else: Application.delete_env(:ouroboros, :grok_auth_file)
    end)

    refute GrokAuth.credential_path() == Path.expand("relative/auth.json")
    assert GrokAuth.credential_path(path: "relative/auth.json") == nil
  end

  test "a pending login can be cancelled without returning CLI output", %{
    root: root,
    executable: executable,
    auth_path: path
  } do
    script = """
    #!/bin/sh
    printf 'https://auth.x.ai/device?user_code=ABCD-1234\nABCD-1234\n'
    sleep 30
    """

    File.write!(executable, script)
    File.chmod!(executable, 0o700)

    start_supervised!(
      {GrokAuth,
       name: :cancel_grok_auth,
       executable: executable,
       auth_path: path,
       env: %{"GROK_HOME" => root}}
    )

    assert {:ok, %{"loginId" => login_id}} = GrokAuth.login(:cancel_grok_auth)
    assert {:ok, %{}} = GrokAuth.cancel(login_id, :cancel_grok_auth)
    assert {:ok, %{"login" => %{"status" => "idle"}}} = GrokAuth.read(:cancel_grok_auth)
  end

  defp write_auth(path, secret, email) do
    File.write!(
      path,
      Jason.encode!(%{
        "https://auth.x.ai" => %{
          "key" => secret,
          "refresh_token" => "refresh-#{secret}",
          "auth_mode" => "oidc",
          "email" => email
        }
      })
    )

    File.chmod!(path, 0o600)
  end

  defp eventually(fun, attempts \\ 50)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    if fun.() do
      true
    else
      Process.sleep(10)
      eventually(fun, attempts - 1)
    end
  end
end
