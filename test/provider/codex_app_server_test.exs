defmodule Ouroboros.Provider.CodexAppServerTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Provider.CodexAppServer

  # `rest_for_one` makes child order a blast radius. This process owns a port to a program
  # that can die, and nothing downstream rebuilds from what it knows, so it belongs in the
  # operator-surface tail beside the gateway rather than above the planes: a crash-looping
  # `codex` must not restart a single live session, and with the default 3-in-5s restart
  # intensity it must not be able to take the node down either.
  test "is supervised in the tail, after cluster formation and every plane" do
    start_order =
      Ouroboros.Supervisor
      |> Supervisor.which_children()
      # A non-dynamic supervisor keeps its children in reverse start order.
      |> Enum.reverse()
      |> Enum.map(fn {id, _pid, _type, _modules} -> id end)

    codex = index!(start_order, {CodexAppServer, CodexAppServer})
    cluster = index!(start_order, Ouroboros.Cluster)

    assert codex > cluster

    for plane <- [
          Ouroboros.Release.Runtime,
          Ouroboros.Coding.Recovery,
          Ouroboros.Interactive.Recovery,
          Ouroboros.Team.Recovery,
          Ouroboros.Orchestration.Scheduler
        ] do
      assert codex > index!(start_order, plane),
             "the account boundary starts before #{inspect(plane)}, so its crash restarts it"
    end

    # The gateway is its only caller, so the gateway — and nothing else — may start after
    # it. Anything else appearing here would be a durable owner placed downstream of a
    # child whose crash it now depends on.
    assert start_order |> Enum.drop(codex + 1) |> Enum.all?(&(&1 == Ouroboros.Gateway))
  end

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

  defp index!(order, id) do
    case Enum.find_index(order, &(&1 == id)) do
      nil -> flunk("#{inspect(id)} is not supervised by Ouroboros.Supervisor on this node")
      index -> index
    end
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
