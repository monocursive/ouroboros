defmodule Ouroboros.Gateway.OperateTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  @moduletag :capture_log

  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods

  @token String.duplicate("o", 40)
  @receive_timeout 2_000

  setup context do
    start_supervised!({Task.Supervisor, name: :gateway_operate_test_tasks})

    start_supervised!(
      {DynamicSupervisor, strategy: :one_for_one, name: :gateway_operate_test_conns}
    )

    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: Map.get(context, :scope, :operate),
        allow_shutdown: Map.get(context, :allow_shutdown, false)
      )

    {client, conn} = connect(config)
    on_exit(fn -> :gen_tcp.close(client) end)

    %{client: client, conn: conn, config: config}
  end

  defp connect(config) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :gateway_operate_test_conns,
        {Conn, socket: server, config: config, task_supervisor: :gateway_operate_test_tasks}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)

    {client, conn}
  end

  defp call(client, method, params \\ %{}) do
    id = System.unique_integer([:positive])

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
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "operate-test"})
  end

  defp operate_methods do
    Methods.table()
    |> Enum.filter(fn {_name, entry} -> entry.scope == :operate end)
    |> Enum.map(fn {name, _entry} -> name end)
    |> Enum.sort()
  end

  describe "scope is the gate, and it is closed by default" do
    @describetag scope: :read

    test "every operate method is refused on a read listener", %{client: client} do
      assert hello(client)["result"]["scope"] == "read"

      # Enumerated from the table rather than listed here: a verb added with
      # `scope: :operate` is covered the moment it exists, and a verb that quietly loses
      # its scope fails this.
      for method <- operate_methods() do
        response = call(client, method)

        assert response["error"]["code"] == -32003, "#{method} was not refused under read scope"
        assert response["error"]["message"] =~ "OUROBOROS_GATEWAY_SCOPE=read"
      end

      # The connection survives every refusal.
      assert is_list(call(client, "agents.list")["result"])
    end

    test "a refused operate call never reaches a handler", %{client: client} do
      assert hello(client)["result"]

      log =
        capture_log(fn ->
          assert call(client, "interactive.kill", %{"id" => "whatever"})["error"]["code"] ==
                   -32003
        end)

      # No audit line, because there was no operate call — only an attempt.
      refute log =~ "gateway operate"
    end

    test "the read listener still advertises the operate methods it will refuse", %{
      client: client
    } do
      # A client feature-gates on `hello`, and hiding the verbs would make a read listener
      # look like an older build rather than like a listener with less authority.
      methods = hello(client)["result"]["methods"]

      for method <- operate_methods(), do: assert(method in methods)
    end
  end

  describe "an operate listener" do
    test "answers operate verbs, and refuses their parameters honestly", %{client: client} do
      assert hello(client)["result"]["scope"] == "operate"

      assert call(client, "interactive.kill", %{"id" => "no-such-session"})["error"]["code"] in [
               -32004,
               -32006,
               -32007
             ]

      assert call(client, "interactive.send_message", %{"id" => "x"})["error"]["code"] == -32602
      assert call(client, "teams.close", %{})["error"]["code"] == -32602
      assert call(client, "coding.start", %{})["error"]["code"] == -32602
    end

    test "an option outside the allowlist is refused rather than dropped", %{client: client} do
      assert hello(client)["result"]

      response =
        call(client, "interactive.start", %{"provider" => "codex", "env" => %{"KEY" => "value"}})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "env"

      # Naming the accepted set is what turns a refusal into something a client author can
      # act on without reading this build's source.
      assert response["error"]["message"] =~ "sandbox_mode"
    end

    test "an unknown provider is a parameter error, not a new atom", %{client: client} do
      assert hello(client)["result"]

      response =
        call(client, "interactive.start", %{"provider" => "definitely_not_a_provider_atom"})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "must name a provider this node serves"

      # The atom table is never garbage collected, so "was it refused" is not the whole
      # question — "did the refusal cost an atom" is the other half, and this is the only
      # way to ask it that other tests running in the same VM cannot perturb.
      assert_raise ArgumentError, fn ->
        String.to_existing_atom("definitely_not_a_provider_atom")
      end
    end

    test "an enum value outside the schema is refused", %{client: client} do
      assert hello(client)["result"]

      response = call(client, "coding.start", %{"objective" => "x", "sandbox_mode" => "yolo"})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "workspace_write"
    end

    test "an approval response outside the allowlist is refused", %{client: client} do
      assert hello(client)["result"]

      for response <- ["maybe", %{"decision" => "approve", "provider_options" => %{"a" => 1}}] do
        answer =
          call(client, "interactive.respond_approval", %{
            "id" => "session",
            "request_id" => "request",
            "response" => response
          })

        assert answer["error"]["code"] == -32602
        assert answer["error"]["message"] =~ "approve"
      end
    end

    test "every operate call leaves one audit line naming the call and not its contents", %{
      client: client
    } do
      assert hello(client)["result"]

      log =
        capture_log(fn ->
          assert call(client, "control.submit", %{
                   "objective" => "a secret objective nobody should read in a log"
                 })
        end)

      lines = log |> String.split("\n") |> Enum.filter(&(&1 =~ "gateway operate"))

      assert [line] = lines
      assert line =~ "control.submit"
      assert line =~ "peer=127.0.0.1:"
      assert line =~ ~r/params=[0-9a-f]{16}/
      refute line =~ "a secret objective"
    end

    test "read methods leave no audit line", %{client: client} do
      assert hello(client)["result"]

      log = capture_log(fn -> assert call(client, "agents.list")["result"] end)

      refute log =~ "gateway operate"
    end
  end

  describe "runtime.shutdown needs a permission beyond its scope" do
    test "an operate listener without the flag is refused", %{client: client} do
      assert hello(client)["result"]

      response = call(client, "runtime.shutdown")

      assert response["error"]["code"] == -32003
      assert response["error"]["message"] =~ "OUROBOROS_GATEWAY_ALLOW_SHUTDOWN=1"
    end

    @tag allow_shutdown: true
    test "with the flag, the node stops only after the acknowledgement is written", %{
      client: client
    } do
      test_pid = self()

      # The stop is indirected exactly so this can be observed without stopping the VM
      # running the suite. What is under test is the *ordering*: by the time the stop
      # fires, the client's frame has already left this process.
      Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [test_pid, :node_stop]})
      on_exit(fn -> Application.delete_env(:ouroboros, :gateway_stop_mfa) end)

      assert hello(client)["result"]

      log =
        capture_log(fn ->
          response = call(client, "runtime.shutdown")

          assert response["result"]["stopping"] == true
          assert response["result"]["node"] == Atom.to_string(node())

          assert_receive :node_stop, @receive_timeout
        end)

      assert log =~ "gateway accepted runtime.shutdown"
    end
  end
end
