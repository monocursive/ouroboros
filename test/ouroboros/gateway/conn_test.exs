defmodule Ouroboros.Gateway.ConnTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods

  @token String.duplicate("k", 40)
  @receive_timeout 2_000

  setup context do
    start_supervised!({Task.Supervisor, name: :gateway_conn_test_tasks})

    start_supervised!({DynamicSupervisor, strategy: :one_for_one, name: :gateway_conn_test_conns})

    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: Map.get(context, :scope, :read),
        max_frame: Map.get(context, :max_frame, 1_024)
      )

    {client, conn} = connect(config)

    on_exit(fn -> :gen_tcp.close(client) end)

    %{client: client, conn: conn, config: config}
  end

  # A real socket pair, so framing, ownership transfer, and `packet: :line` are exercised
  # rather than mocked. Only the listener's bind is skipped.
  defp connect(config) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :gateway_conn_test_conns,
        {Conn, socket: server, config: config, task_supervisor: :gateway_conn_test_tasks}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)

    {client, conn}
  end

  defp send_frame(client, frame) do
    :ok = :gen_tcp.send(client, [JSON.encode_to_iodata!(frame), ?\n])
  end

  defp recv_frame(client, timeout \\ @receive_timeout) do
    # A response frame is bounded by what the runtime has to say, not by the inbound
    # limit: `runtime.providers` alone is tens of kilobytes on one line.
    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, timeout) do
      {:ok, line} -> JSON.decode!(String.trim_trailing(line, "\n"))
      {:error, reason} -> {:error, reason}
    end
  end

  defp hello(client, overrides \\ %{}) do
    params = Map.merge(%{"token" => @token, "protocol" => 1, "client" => "test"}, overrides)

    send_frame(client, %{"jsonrpc" => "2.0", "id" => "h", "method" => "hello", "params" => params})

    recv_frame(client)
  end

  defp error_code(frame), do: frame["error"]["code"]

  describe "the handshake" do
    test "a valid hello reports what this build actually serves", %{client: client} do
      response = hello(client)

      assert response["id"] == "h"
      assert response["result"]["protocol"] == 1
      assert response["result"]["scope"] == "read"
      assert response["result"]["node"] == Atom.to_string(node())
      assert response["result"]["role"] == "core"
      assert response["result"]["server"] =~ ~r/^\d+\.\d+\.\d+/
      assert response["result"]["methods"] == Methods.names()
      assert "runtime.status" in response["result"]["methods"]
      assert "hello" in response["result"]["methods"]
    end

    test "a wrong token is refused and the socket closes", %{client: client, conn: conn} do
      assert error_code(hello(client, %{"token" => String.duplicate("x", 40)})) == -32001

      assert recv_frame(client) == {:error, :closed}
      refute Process.alive?(conn)
    end

    test "a missing token learns nothing more specific than 'unauthenticated'", %{
      client: client
    } do
      response = hello(client, %{"token" => nil})

      assert error_code(response) == -32001
      refute response["error"]["message"] =~ "params"
    end

    test "a protocol the server does not speak is told which one it does", %{client: client} do
      response = hello(client, %{"protocol" => 2})

      assert error_code(response) == -32002
      assert response["error"]["data"] == %{"server_protocol" => 1}
      assert recv_frame(client) == {:error, :closed}
    end

    test "any method before hello is refused and closes the connection", %{client: client} do
      send_frame(client, %{"jsonrpc" => "2.0", "id" => 1, "method" => "runtime.status"})

      assert error_code(recv_frame(client)) == -32001
      assert recv_frame(client) == {:error, :closed}
    end

    test "hello cannot be replayed to change anything", %{client: client} do
      assert hello(client)["result"]

      assert error_code(hello(client)) == -32600
    end

    test "a connection that never says hello is reaped when its deadline fires", %{
      client: client,
      conn: conn
    } do
      # Firing the deadline directly rather than sleeping through the real 10s: what is
      # under test is that an unauthenticated connection does not survive it.
      ref = Process.monitor(conn)
      send(conn, :hello_timeout)

      assert_receive {:DOWN, ^ref, :process, ^conn, :normal}, @receive_timeout
      assert recv_frame(client) == {:error, :closed}
    end

    test "a connection that did say hello is not reaped by a stale deadline", %{
      client: client,
      conn: conn
    } do
      assert hello(client)["result"]

      send(conn, :hello_timeout)
      send_frame(client, %{"jsonrpc" => "2.0", "id" => 1, "method" => "agents.list"})

      assert recv_frame(client)["id"] == 1
      assert Process.alive?(conn)
    end
  end

  describe "malformed input is answered, never crashed on" do
    setup %{client: client} do
      assert hello(client)["result"]
      :ok
    end

    test "invalid JSON is a parse error and the connection survives", %{client: client} do
      :ok = :gen_tcp.send(client, "{not json at all\n")

      assert error_code(recv_frame(client)) == -32700

      # Still usable.
      send_frame(client, %{"jsonrpc" => "2.0", "id" => 2, "method" => "agents.list"})
      assert recv_frame(client)["id"] == 2
    end

    test "a JSON value that is not an object is refused", %{client: client} do
      :ok = :gen_tcp.send(client, "[1,2,3]\n")

      assert error_code(recv_frame(client)) == -32600
    end

    test "a request without an id has nowhere to be answered, and says so", %{client: client} do
      send_frame(client, %{"jsonrpc" => "2.0", "method" => "agents.list"})

      response = recv_frame(client)
      assert response["id"] == nil
      assert error_code(response) == -32600
    end

    test "params that are not an object are a parameter error", %{client: client} do
      send_frame(client, %{
        "jsonrpc" => "2.0",
        "id" => 3,
        "method" => "agents.state",
        "params" => ["a"]
      })

      assert error_code(recv_frame(client)) == -32602
    end

    test "a method this build does not serve is -32601", %{client: client} do
      # Deliberately absent from the catalog rather than merely unimplemented: its `from`
      # would be caller-supplied, and the effects plane made principals non-spoofable.
      # "Not served" and "refused by scope" are different answers and stay different.
      send_frame(client, %{"jsonrpc" => "2.0", "id" => 4, "method" => "mesh.send_message"})

      response = recv_frame(client)
      assert error_code(response) == -32601
      assert response["error"]["message"] =~ "mesh.send_message"
    end

    test "a required id parameter is validated before any plane is called", %{client: client} do
      send_frame(client, %{
        "jsonrpc" => "2.0",
        "id" => 5,
        "method" => "agents.state",
        "params" => %{"id" => ""}
      })

      assert error_code(recv_frame(client)) == -32602
    end

    test "a replay limit past the ceiling is refused rather than clamped", %{client: client} do
      send_frame(client, %{
        "jsonrpc" => "2.0",
        "id" => 6,
        "method" => "interactive.replay",
        "params" => %{"id" => "nope", "cursor" => 0, "limit" => 5_000}
      })

      response = recv_frame(client)
      assert error_code(response) == -32602
      assert response["error"]["message"] =~ "500"
    end
  end

  @tag max_frame: 1_024
  test "a frame past the limit is answered and the connection closed", %{client: client} do
    assert hello(client)["result"]

    payload =
      JSON.encode!(%{
        "jsonrpc" => "2.0",
        "id" => 9,
        "method" => "agents.state",
        "params" => %{"id" => String.duplicate("z", 4_000)}
      })

    :ok = :gen_tcp.send(client, [payload, ?\n])

    response = recv_frame(client)
    assert error_code(response) == -32700
    assert response["error"]["message"] =~ "OUROBOROS_GATEWAY_MAX_FRAME"
    assert recv_frame(client) == {:error, :closed}
  end

  test "responses correlate by id, so a slow method never holds a fast one", %{client: client} do
    assert hello(client)["result"]

    # `runtime.providers` shells out to probe every installed provider executable and
    # takes seconds; `agents.list` reads a process group and takes microseconds. Sent in
    # that order, the fast one still comes back first — which is the whole point of
    # dispatching to tasks and correlating by id instead of answering in arrival order.
    send_frame(client, %{"jsonrpc" => "2.0", "id" => "slow", "method" => "runtime.providers"})
    send_frame(client, %{"jsonrpc" => "2.0", "id" => "fast", "method" => "agents.list"})

    first = recv_frame(client, 20_000)
    second = recv_frame(client, 20_000)

    assert first["id"] == "fast"
    assert second["id"] == "slow"
    assert Enum.all?([first, second], &Map.has_key?(&1, "result"))
  end

  test "fleet status and doctor are readable, actionable, and never expose the cookie", %{
    client: client
  } do
    assert hello(client)["result"]

    send_frame(client, %{"jsonrpc" => "2.0", "id" => "fleet", "method" => "fleet.status"})
    status = recv_frame(client)["result"]

    assert status["local_node"] == Atom.to_string(node())
    assert is_list(status["machines"])
    assert status["summary"]["connected"] >= 1
    assert status["security"]["cookie"] in ["set", "unset"]

    encoded_status = JSON.encode!(status)
    refute encoded_status =~ Atom.to_string(:erlang.get_cookie())

    send_frame(client, %{"jsonrpc" => "2.0", "id" => "doctor", "method" => "fleet.doctor"})
    doctor = recv_frame(client)["result"]

    assert is_boolean(doctor["healthy?"])
    assert Enum.all?(doctor["checks"], &is_binary(&1["message"]))
    refute JSON.encode!(doctor) =~ Atom.to_string(:erlang.get_cookie())
  end

  test "the listener's scope is what the connection reports and enforces", %{config: config} do
    assert config.scope == :read
    assert Methods.permits?(:read, %{scope: :read, timeout: 1_000})
    refute Methods.permits?(:read, %{scope: :operate, timeout: 1_000})
    assert Methods.permits?(:operate, %{scope: :operate, timeout: 1_000})
  end

  @tag scope: :operate
  test "an operate listener says so in its handshake", %{client: client} do
    assert hello(client)["result"]["scope"] == "operate"
  end
end
