defmodule Ouroboros.Provider.CodexAppServerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.CodexAppServer

  test "initializes once, reads the account, and follows a managed device-code login" do
    executable = fake_app_server()

    server = start_supervised!({CodexAppServer, name: nil, executable: executable})

    assert {:ok,
            %{
              "account" => %{"type" => "chatgpt", "planType" => "pro"},
              "login" => %{"status" => "idle"}
            }} = CodexAppServer.read(server)

    assert {:ok,
            %{
              "type" => "chatgptDeviceCode",
              "loginId" => "login-1",
              "verificationUrl" => "https://auth.openai.com/codex/device",
              "userCode" => "ABCD-1234",
              "login" => %{"status" => "pending", "flow" => "device_code"}
            }} = CodexAppServer.login(:device_code, server)

    assert {:ok, %{"login" => %{"status" => "succeeded"}}} = CodexAppServer.read(server)
    assert {:ok, %{}} = CodexAppServer.logout(server)
  end

  test "a missing Codex executable is a named availability error" do
    server =
      start_supervised!(
        {CodexAppServer,
         name: nil, executable: Path.join(System.tmp_dir!(), "ouroboros-no-such-codex")}
      )

    assert {:error, {:unavailable, message}} = CodexAppServer.read(server)
    assert message =~ "Codex is not installed on the runtime host"
  end

  defp fake_app_server do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-codex-app-server-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    path = Path.join(dir, "codex")

    File.write!(
      path,
      """
      #!/bin/sh
      while IFS= read -r line; do
        case "$line" in
          *'"method":"initialize"'*)
            echo '{"id":0,"result":{"userAgent":"fake"}}'
            ;;
          *'"id":1,'*'"method":"account/read"'*)
            echo '{"id":1,"result":{"account":{"type":"chatgpt","planType":"pro"},"requiresOpenaiAuth":true}}'
            ;;
          *'"method":"account/login/start"'*)
            echo '{"id":2,"result":{"type":"chatgptDeviceCode","loginId":"login-1","verificationUrl":"https://auth.openai.com/codex/device","userCode":"ABCD-1234"}}'
            echo '{"method":"account/login/completed","params":{"loginId":"login-1","success":true,"error":null}}'
            ;;
          *'"id":3,'*'"method":"account/read"'*)
            echo '{"id":3,"result":{"account":{"type":"chatgpt","planType":"pro"},"requiresOpenaiAuth":true}}'
            ;;
          *'"method":"account/logout"'*)
            echo '{"id":4,"result":{}}'
            ;;
        esac
      done
      """
    )

    File.chmod!(path, 0o755)
    on_exit(fn -> File.rm_rf(dir) end)
    path
  end
end
