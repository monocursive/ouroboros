defmodule Ouroboros.Gateway.IntegrationTest do
  use ExUnit.Case, async: false

  import Bitwise
  import ExUnit.CaptureIO

  alias Ouroboros.Gateway
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Listener
  alias Ouroboros.Mesh
  alias Ouroboros.Upgrade.NodeExecutor

  @token String.duplicate("g", 48)
  @receive_timeout 5_000

  @moduletag :tmp_dir
  @moduletag :capture_log

  setup %{tmp_dir: tmp_dir} = context do
    File.chmod!(tmp_dir, 0o700)
    config = Config.new!(token: @token, data_dir: tmp_dir, port: 0)

    start_supervised!({Gateway, config: config, ready_application: context[:ready_application]})

    port = Listener.port()
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    on_exit(fn -> :gen_tcp.close(client) end)

    %{client: client, port: port, data_dir: tmp_dir}
  end

  defp call(client, method, params \\ %{}, id \\ nil) do
    id = id || System.unique_integer([:positive])

    :ok =
      :gen_tcp.send(client, [
        JSON.encode_to_iodata!(%{
          "jsonrpc" => "2.0",
          "id" => id,
          "method" => method,
          "params" => params
        }),
        ?\n
      ])

    recv(client)
  end

  defp recv(client, timeout \\ @receive_timeout) do
    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, timeout) do
      {:ok, line} -> JSON.decode!(String.trim_trailing(line, "\n"))
      {:error, reason} -> {:error, reason}
    end
  end

  defp hello(client) do
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "integration"})
  end

  test "the bound port is published where a client can find it", %{
    data_dir: data_dir,
    port: port
  } do
    path = Listener.publication_path(data_dir)

    assert File.exists?(path)

    published = path |> File.read!() |> JSON.decode!()

    assert published["port"] == port
    assert published["protocol"] == 1
    assert published["node"] == Atom.to_string(node())
    assert published["scope"] == "read"
    assert published["pid"] == String.to_integer(System.pid())

    # This listener's token came from `OUROBOROS_GATEWAY_TOKEN`, so there is no file to
    # name and the key is absent rather than present-and-wrong.
    refute Map.has_key?(published, "token_file")

    # The file names a live listener and sits next to durable state, so it is not
    # readable by other users on the host.
    assert (File.stat!(path).mode &&& 0o777) == 0o600
  end

  @tag :tmp_dir
  test "a token file is published by path so a client can find the credential", %{
    tmp_dir: tmp_dir
  } do
    token_path = Path.join(tmp_dir, "token")
    File.write!(token_path, String.duplicate("t", 48))
    File.chmod!(token_path, 0o600)

    data_dir = Path.join(tmp_dir, "published")

    start_supervised!(
      {Gateway,
       name: :gateway_token_file_test,
       listener: :gateway_token_file_test_listener,
       conn_supervisor: :gateway_token_file_test_conns,
       task_supervisor: :gateway_token_file_test_tasks,
       config: Config.new!(token_file: token_path, data_dir: data_dir, port: 0)},
      id: :gateway_token_file_test
    )

    published =
      data_dir |> Listener.publication_path() |> File.read!() |> JSON.decode!()

    assert published["token_file"] == token_path

    # The path, and only the path. A client reads the file this names; anything that read
    # `gateway.json` would otherwise be holding the credential itself.
    refute published |> Map.values() |> Enum.any?(&(&1 == String.duplicate("t", 48)))
  end

  @tag :tmp_dir
  test "a boot nobody configured says on stdout where it is and how to attach", %{
    tmp_dir: tmp_dir
  } do
    # Its own directory: the gateway this module's setup started publishes into `tmp_dir`
    # itself, and two listeners sharing a data directory would trade `gateway.json`.
    data_dir = Path.join(tmp_dir, "defaulted")

    config =
      Config.new!(
        token_file: Path.join(data_dir, "gateway.token"),
        token_generate: true,
        data_dir: data_dir,
        scope: :operate,
        port: 0
      )

    # The notice is written by the listener process, so it has to be started from this
    # process for the captured group leader to be the one it inherits.
    output =
      capture_io(fn ->
        {:ok, listener} =
          Listener.start_link(
            name: :gateway_notice_listener,
            config: config,
            conn_supervisor: :gateway_notice_conns,
            task_supervisor: :gateway_notice_tasks
          )

        send(self(), {:bound, Listener.port(listener)})
        GenServer.stop(listener)
      end)

    assert_received {:bound, port}

    assert output =~ "single-machine"
    assert output =~ data_dir
    assert output =~ "127.0.0.1:#{port}"
    assert output =~ "operate"
    assert output =~ "gateway.json"
    assert output =~ "gateway.token"
    assert output =~ "ouro"

    # Where to look, never what to present. The token is in the 0600 file this names.
    refute output =~ config.token
  end

  test "a listener that was configured on purpose prints nothing to stdout", %{tmp_dir: tmp_dir} do
    output =
      capture_io(fn ->
        {:ok, listener} =
          Listener.start_link(
            name: :gateway_quiet_listener,
            config: Config.new!(token: @token, data_dir: Path.join(tmp_dir, "quiet"), port: 0),
            conn_supervisor: :gateway_quiet_conns,
            task_supervisor: :gateway_quiet_tasks
          )

        GenServer.stop(listener)
      end)

    assert output == ""
  end

  @tag :tmp_dir
  test "a pinned port briefly held by another socket is rebound once the holder leaves", %{
    tmp_dir: tmp_dir
  } do
    data_dir = Path.join(tmp_dir, "pinned-retry")

    # The holder stands in for a kernel-assigned ephemeral port on the pinned number:
    # bound at the moment the gateway starts, gone moments later. This is the enrollment
    # race observed on a real fleet machine — the boot must outlast it, not die on it.
    {:ok, holder} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(holder)

    release = Task.async(fn -> Process.sleep(400) == :ok and :gen_tcp.close(holder) end)

    {:ok, listener} =
      Listener.start_link(
        name: :gateway_pinned_retry_listener,
        config: Config.new!(token: @token, data_dir: data_dir, port: port),
        conn_supervisor: :gateway_pinned_retry_conns,
        task_supervisor: :gateway_pinned_retry_tasks,
        listen_retry: [budget_ms: 5_000, interval_ms: 50]
      )

    Task.await(release)
    assert Listener.port(listener) == port

    published = data_dir |> Listener.publication_path() |> File.read!() |> JSON.decode!()
    assert published["port"] == port

    GenServer.stop(listener)
  end

  @tag :tmp_dir
  test "a pinned port held past the rebind budget still fails with the honest reason", %{
    tmp_dir: tmp_dir
  } do
    data_dir = Path.join(tmp_dir, "pinned-honest")

    {:ok, holder} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(holder)

    # A refused init exits the linked starter too; trapping keeps the refusal observable
    # as a return value, which is exactly what a supervisor would see.
    Process.flag(:trap_exit, true)

    assert {:error, {:gateway_listen_failed, "127.0.0.1", ^port, :eaddrinuse}} =
             Listener.start_link(
               name: :gateway_pinned_exhausted_listener,
               config: Config.new!(token: @token, data_dir: data_dir, port: port),
               conn_supervisor: :gateway_pinned_exhausted_conns,
               task_supervisor: :gateway_pinned_exhausted_tasks,
               listen_retry: [budget_ms: 200, interval_ms: 50]
             )

    :gen_tcp.close(holder)
  end

  test "the publication is removed when the gateway stops gracefully", %{data_dir: data_dir} do
    path = Listener.publication_path(data_dir)
    assert File.exists?(path)

    stop_supervised!(Gateway)

    refute File.exists?(path)
  end

  @tag ready_application: :ouroboros_gateway_readiness_test
  test "requests wait for the owning application to finish starting", %{client: client} do
    application = :ouroboros_gateway_readiness_test

    :ok = :application.load({:application, application, vsn: ~c"1", modules: []})

    on_exit(fn ->
      Application.stop(application)
      :application.unload(application)
    end)

    :ok =
      :gen_tcp.send(client, [
        JSON.encode_to_iodata!(%{
          "jsonrpc" => "2.0",
          "id" => "before-start",
          "method" => "hello",
          "params" => %{"token" => @token, "protocol" => 1}
        }),
        ?\n
      ])

    assert recv(client, 50) == {:error, :timeout}
    :ok = Application.start(application)
    assert %{"id" => "before-start", "result" => %{"protocol" => 1}} = recv(client)
  end

  test "hello then runtime.status returns a tree, not an opaque blob", %{client: client} do
    id = "agent-#{System.unique_integer([:positive])}"
    assert {:ok, _pid} = Mesh.start_agent(id, role: "reviewer")
    on_exit(fn -> Mesh.stop_agent(id) end)

    assert hello(client)["result"]["protocol"] == 1

    status = call(client, "runtime.status")["result"]

    assert status["node"] == Atom.to_string(node())
    assert status["role"] == "core"

    # The whole point of the per-leaf walk: `status` embeds `Mesh.list_agents/0`, whose
    # maps carry pids. `Serializable.safe/1` would have replaced this entire tree with
    # one string.
    refute Map.has_key?(status, "_opaque")
    assert is_map(status["availability"])
    assert status["availability"]["mesh"] == "available"
    assert status["availability"]["hot_upgrade"] == "available"

    # Availability is tri-state, and the client renders all three; what matters here is
    # that it arrives as a word rather than as an inspect string.
    assert status["availability"]["control"] in ["available", "unavailable", "disabled"]

    assert agent = Enum.find(status["agents"], &(&1["id"] == id))
    assert agent["node"] == Atom.to_string(node())
    assert agent["replicas"] == 1
    assert agent["pid"]["_opaque"] =~ "#PID<"

    assert is_list(status["coding_tasks"])
    assert is_list(status["interactive_sessions"])
    assert is_list(status["teams"])
    assert is_binary(status["upgrade"]["mode"])
  end

  test "a plane that is not running is -32004 and the connection survives it", %{client: client} do
    assert hello(client)["result"]

    assert is_binary(call(client, "upgrade.status")["result"]["mode"])

    executor = Process.whereis(NodeExecutor)

    # `NodeExecutor.status/0` is a bare `GenServer.call`, so an absent executor *exits*
    # the caller. Unregistering the name reproduces that precisely without terminating a
    # supervised child and triggering the rest_for_one restarts below it.
    Process.unregister(NodeExecutor)

    on_exit(fn ->
      if is_nil(Process.whereis(NodeExecutor)), do: Process.register(executor, NodeExecutor)
    end)

    response = call(client, "upgrade.status")
    assert response["error"]["code"] == -32004

    # The exit reason survives as data rather than as a message a client has to parse.
    assert ["noproc", ["GenServer", "call", _arguments]] = response["error"]["data"]

    Process.register(executor, NodeExecutor)

    # Same connection, immediately afterwards.
    assert is_binary(call(client, "upgrade.status")["result"]["mode"])
    assert is_list(call(client, "agents.list")["result"])
  end

  test "two clients are independent", %{port: port, client: client} do
    {:ok, other} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    on_exit(fn -> :gen_tcp.close(other) end)

    assert hello(client)["result"]
    assert hello(other)["result"]

    # One client presenting a bad token loses only its own socket.
    {:ok, third} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)

    :ok =
      :gen_tcp.send(third, [
        JSON.encode_to_iodata!(%{
          "jsonrpc" => "2.0",
          "id" => 1,
          "method" => "hello",
          "params" => %{"token" => "wrong", "protocol" => 1}
        }),
        ?\n
      ])

    assert recv(third)["error"]["code"] == -32001
    assert recv(third) == {:error, :closed}

    # Both surviving connections still answer. What they answer is whatever the shared
    # runtime holds at this moment, which the rest of the suite is free to change.
    assert is_list(call(client, "agents.list")["result"])
    assert is_list(call(other, "teams.list")["result"])
  end

  @documented_codes [
    -32700,
    -32600,
    -32601,
    -32602,
    -32001,
    -32002,
    -32003,
    -32004,
    -32005,
    -32006,
    -32007
  ]

  test "every method this build advertises answers something documented", %{client: client} do
    methods = hello(client)["result"]["methods"]

    # `hello` is answered by the connection and `runtime.providers` shells out;
    # `runtime.shutdown` is excluded because this listener is read-scoped *today* and a
    # loop that calls every advertised verb must not become a loop that stops the node
    # running the suite the day someone changes the scope in this setup. Everything else
    # has to come back as a result or as one of the documented error codes — including the
    # operate verbs, which this read listener answers -32003. A method in the handshake's
    # list that answers -32601 is a table that drifted away from its handlers.
    for method <- methods -- ["hello", "runtime.providers", "runtime.shutdown"] do
      params = %{"id" => "absent", "principal" => "nobody", "module" => "Ouroboros"}
      response = call(client, method, params)

      case response do
        %{"result" => _result} ->
          :ok

        %{"error" => error} ->
          assert error["code"] != -32601, "#{method} is advertised but not served"
          assert error["code"] in @documented_codes, "#{method} answered an undocumented code"

        other ->
          flunk("#{method} answered #{inspect(other)}")
      end
    end
  end
end
