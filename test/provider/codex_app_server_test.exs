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

  describe "a failed connection leaves nothing running" do
    test "an app-server that never answers initialize is timed out and closed" do
      executable = fake_app_server("")

      server = start_supervised!({CodexAppServer, name: nil, executable: executable})
      caller = Task.async(fn -> CodexAppServer.read(server) end)

      assert eventually(fn -> server_ports(server) != [] end),
             "the request never opened a port"

      # The module's own initialize deadline, delivered rather than waited out.
      send(server, {:request_timeout, 0})

      assert {:error, {:timeout, "initialize"}} = Task.await(caller, 5_000)
      assert Process.alive?(server)
      assert server_ports(server) == []
      assert_no_orphans(executable)
    end

    test "an app-server that refuses to initialize is closed" do
      executable =
        fake_app_server("""
          *'"method":"initialize"'*)
            echo '{"id":0,"error":{"code":-32000,"message":"unsupported client"}}'
            ;;
        """)

      server = start_supervised!({CodexAppServer, name: nil, executable: executable})

      assert {:error, {:upstream, message}} = CodexAppServer.read(server)
      assert message =~ "unsupported client"
      assert Process.alive?(server)
      assert server_ports(server) == []
      assert_no_orphans(executable)
    end

    test "three refused reads leave three fewer processes than they started" do
      executable =
        fake_app_server("""
          *'"method":"initialize"'*)
            echo '{"id":0,"error":{"code":-32000,"message":"unsupported client"}}'
            ;;
        """)

      server = start_supervised!({CodexAppServer, name: nil, executable: executable})

      for _attempt <- 1..3 do
        assert {:error, {:upstream, _message}} = CodexAppServer.read(server)
      end

      # `account.read` is a `:read`-scope gateway method. Before this, each failed read
      # left a live `codex` process nobody could reach or stop.
      assert server_ports(server) == []
      assert_no_orphans(executable)
    end
  end

  defp index!(order, id) do
    case Enum.find_index(order, &(&1 == id)) do
      nil -> flunk("#{inspect(id)} is not supervised by Ouroboros.Supervisor on this node")
      index -> index
    end
  end

  defp server_ports(server) do
    Enum.filter(Port.list(), fn port ->
      match?({:connected, ^server}, Port.info(port, :connected))
    end)
  end

  # A fake lives at a path unique to its test, so anything still running under that path
  # is an app-server whose connection was abandoned rather than closed.
  defp assert_no_orphans(executable) do
    assert eventually(fn -> orphans(executable) == [] end),
           "a Codex app-server outlived its connection: #{inspect(orphans(executable))}"
  end

  defp orphans(executable) do
    {listing, _status} = System.cmd("ps", ["-A", "-ww", "-o", "pid=,command="])

    listing
    |> String.split("\n", trim: true)
    |> Enum.filter(&String.contains?(&1, executable))
  end

  defp eventually(condition, attempts \\ 40) do
    cond do
      condition.() ->
        true

      attempts > 0 ->
        Process.sleep(25)
        eventually(condition, attempts - 1)

      true ->
        false
    end
  end

  @default_cases """
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
  """

  # Every fake answers on stdout and records what it was sent, so a test can assert on the
  # client half of the protocol as well as the server half.
  defp fake_app_server(cases \\ @default_cases) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-codex-app-server-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    path = Path.join(dir, "codex")

    File.write!(path, """
    #!/bin/sh
    log="$0.log"
    while IFS= read -r line; do
      printf '%s\\n' "$line" >> "$log"
      case "$line" in
    #{cases}
      esac
    done
    """)

    File.chmod!(path, 0o755)
    on_exit(fn -> File.rm_rf(dir) end)
    path
  end
end
