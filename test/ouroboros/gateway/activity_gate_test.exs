defmodule Ouroboros.Gateway.ActivityGateTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  # ADOPTED EXPLOIT (review of a97f2dfb, HIGH-3): parameter shapes against the idle gate.
  #
  # `runtime.shutdown` is answered by the connection rather than by a dispatch task, and
  # a connection-answered method never reached `Contract.validate/2`. Its params were
  # declared `{:open, …}` and the connection type-checked exactly one key, so a
  # misspelled or differently-cased opt-in — `requireIdle` — was not a refusal, it was an
  # unconditional stop of a node that was genuinely working.
  #
  # Every case here runs against a node that is busy in a way the gate can see, so a stop
  # that gets through is the parameter's doing and not the counter's.

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.NativeModelScript

  @token String.duplicate("g", 40)
  @receive_timeout 10_000

  setup do
    start_supervised!({Task.Supervisor, name: :w1b_gate_tasks})
    start_supervised!({DynamicSupervisor, strategy: :one_for_one, name: :w1b_gate_conns})

    {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
    root = Path.join(tmp, "w1b-gate-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(workspace)

    previous =
      Map.new(
        [:native_data_dir, :native_model_module],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    :ok =
      Supervisor.terminate_child(
        Ouroboros.Interactive.Supervisor,
        Ouroboros.Interactive.Recovery
      )

    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    test_pid = self()
    Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [test_pid, :node_stop]})

    on_exit(fn ->
      Application.delete_env(:ouroboros, :gateway_stop_mfa)

      Enum.each(previous, fn
        {key, nil} -> Application.delete_env(:ouroboros, key)
        {key, value} -> Application.put_env(:ouroboros, key, value)
      end)

      Supervisor.restart_child(Ouroboros.Interactive.Supervisor, Ouroboros.Interactive.Recovery)
      File.rm_rf!(root)
    end)

    %{workspace: workspace, client: elem(connect(), 0), session: nil}
  end

  # A node holding a turn the model has not answered yet, asserted rather than assumed.
  defp busy!(workspace) do
    test_pid = self()

    hold = fn _request ->
      send(test_pid, {:model_entered, self()})

      receive do
        :release -> [{:text, "done"}, {:finish, :stop}]
      after
        20_000 -> [{:text, "abandoned"}, {:finish, :stop}]
      end
    end

    {model, agent} = NativeModelScript.start([hold])
    id = "w1b-gate-#{System.unique_integer([:positive])}"

    assert {:ok, _} =
             Methods.invoke("interactive.start", %{
               "id" => id,
               "workspace" => workspace,
               "model" => model,
               "worktree" => false,
               "runtime_exposure" => false
             })

    on_exit(fn -> InteractiveSession.close(id) end)
    assert {:ok, _} = InteractiveSession.send_message(id, "hold here", id: "w1b-busy")
    assert_receive {:model_entered, _pid}, @receive_timeout
    assert Methods.activity(conn_supervisor: :w1b_gate_conns)["idle"] == false

    on_exit(fn ->
      send(agent, :release)
      InteractiveSession.await(id, "w1b-busy", @receive_timeout)
    end)

    id
  end

  test "a misspelled opt-in is a refusal naming the key, never a stop", context do
    _id = busy!(context.workspace)
    client = context.client
    assert hello(client)["result"]

    response =
      call(client, "runtime.shutdown", %{"requireIdle" => true, "require-idle" => true})

    assert response["error"]["code"] == -32602
    assert response["error"]["message"] =~ "unsupported fields: require-idle, requireIdle"
    assert response["error"]["message"] =~ "it accepts require_idle"
    refute Map.has_key?(response, "result")
    refute_receive :node_stop, 200
  end

  test "any unknown key is refused, even beside a correct opt-in", context do
    _id = busy!(context.workspace)
    client = context.client
    assert hello(client)["result"]

    response = call(client, "runtime.shutdown", %{"require_idle" => true, "unrelated" => "x"})

    assert response["error"]["code"] == -32602
    assert response["error"]["message"] =~ "unsupported fields: unrelated"
    refute_receive :node_stop, 200
  end

  test "a duplicated key keeps the first member, and the gate holds", context do
    _id = busy!(context.workspace)
    client = context.client
    assert hello(client)["result"]

    # Hand-built frame: two `require_idle` members in one object. Elixir's JSON decoder
    # keeps the first, so a smuggled second `false` cannot turn the gate off.
    raw =
      ~s({"jsonrpc":"2.0","id":"dup","method":"runtime.shutdown",) <>
        ~s("params":{"require_idle":true,"require_idle":false}})

    response = send_raw(client, raw)

    assert response["error"]["code"] == -32004
    assert response["error"]["data"]["reason"] == "runtime_busy"
    refute_receive :node_stop, 200
  end

  test "a require_idle that is not a boolean is refused, whatever it is", context do
    _id = busy!(context.workspace)
    client = context.client
    assert hello(client)["result"]

    for value <- ["true", "yes", 1, nil, [true], %{"value" => true}] do
      response = call(client, "runtime.shutdown", %{"require_idle" => value})

      assert response["error"]["code"] == -32602,
             "#{inspect(value)} must not be a boolean; got #{inspect(response)}"

      assert response["error"]["message"] =~ "require_idle"
    end

    refute_receive :node_stop, 200
  end

  test "the refusal names no session, path or workspace", context do
    id = busy!(context.workspace)
    client = context.client
    assert hello(client)["result"]

    response = call(client, "runtime.shutdown", %{"require_idle" => true})
    encoded = JSON.encode!(response)

    refute encoded =~ id
    refute encoded =~ context.workspace
    assert response["error"]["data"]["activity"]["running_turns"] == 1
    assert response["error"]["data"]["activity"]["busy_sessions"] == 1
  end

  test "the other connection-answered verbs are validated too", context do
    client = context.client
    assert hello(client)["result"]

    response = call(client, "interactive.subscribe", %{"id" => "nope", "cursr" => 1})

    assert response["error"]["code"] == -32602
    assert response["error"]["message"] =~ "cursr"
  end

  # ---------------------------------------------------------------------------

  defp connect do
    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: :operate,
        allow_shutdown: true
      )

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :w1b_gate_conns,
        {Conn,
         socket: server,
         config: config,
         task_supervisor: :w1b_gate_tasks,
         conn_supervisor: :w1b_gate_conns}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)
    on_exit(fn -> :gen_tcp.close(client) end)

    {client, conn}
  end

  defp hello(client) do
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "w1b-gate"})
  end

  defp call(client, method, params) do
    id = System.unique_integer([:positive])

    send_raw(
      client,
      JSON.encode!(%{"jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params})
    )
  end

  defp send_raw(client, line) do
    :ok = :gen_tcp.send(client, [line, ?\n])
    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, @receive_timeout) do
      {:ok, response} -> JSON.decode!(String.trim_trailing(response, "\n"))
      {:error, reason} -> {:error, reason}
    end
  end
end
