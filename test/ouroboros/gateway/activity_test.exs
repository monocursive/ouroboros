defmodule Ouroboros.Gateway.ActivityTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Attachments
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.NativeModelScript

  @token String.duplicate("a", 40)
  @receive_timeout 5_000

  # The counters this suite asserts on are node-global, so every one of them is asserted
  # as a *delta* against a baseline taken in the same test. A stray coordinator left by an
  # earlier case then moves both numbers equally instead of deciding the result, and the
  # one place a bare value is asserted — the idle baseline — fails loudly if the node was
  # not quiet to begin with.

  defmodule HeldDecoder do
    @moduledoc false

    # A normalizer that stops inside the attachment service's worker task and says so, so
    # a test can read `attachment_normalizations` while one is genuinely in flight rather
    # than while a sleep hopes it is.
    def normalize(_paths, _root) do
      send(Agent.get(:w1b_activity_decoder_owner, & &1), {:normalizing, self()})

      receive do
        :release -> {:ok, %{content: "ok", thumbnail: "ok", width: 1, height: 1}}
      after
        4_000 -> {:error, :attachment_integrity_failed}
      end
    end
  end

  setup context do
    start_supervised!({Task.Supervisor, name: :gateway_activity_test_tasks})

    start_supervised!(
      {DynamicSupervisor, strategy: :one_for_one, name: :gateway_activity_test_conns}
    )

    if context[:sessions] do
      {:ok, tmp} = Ouroboros.Workspace.Path.canonicalize(System.tmp_dir!())
      root = Path.join(tmp, "w1b-activity-#{System.unique_integer([:positive])}")
      workspace = Path.join(root, "workspace")
      File.mkdir_p!(workspace)

      previous =
        Map.new(
          [:native_data_dir, :native_model_module],
          &{&1, Application.get_env(:ouroboros, &1)}
        )

      # The supervised recovery sweep adopts durable rows it did not start. A serial case
      # that plants and holds one has to freeze it, or the sweep reopens the session under
      # this test's feet (see the ExUnit flake notes on recovery adoption).
      :ok =
        Supervisor.terminate_child(
          Ouroboros.Interactive.Supervisor,
          Ouroboros.Interactive.Recovery
        )

      Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "native"))
      Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

      on_exit(fn ->
        Enum.each(previous, fn
          {key, nil} -> Application.delete_env(:ouroboros, key)
          {key, value} -> Application.put_env(:ouroboros, key, value)
        end)

        Supervisor.restart_child(
          Ouroboros.Interactive.Supervisor,
          Ouroboros.Interactive.Recovery
        )

        File.rm_rf!(root)
      end)

      %{workspace: workspace}
    else
      %{}
    end
  end

  # ---------------------------------------------------------------------------
  # The shape itself

  describe "the summary" do
    test "counts an idle node, names nothing unknown, and says so" do
      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["unknown"] == []
      assert summary["idle"] == true
      assert summary["running_turns"] == 0
      assert summary["queued_turns"] == 0
      assert summary["attachment_transfers"] == 0
      assert summary["attachment_normalizations"] == 0
      assert summary["operator_clients"] == 0

      assert Enum.sort(Map.keys(summary)) ==
               Enum.sort(~w(
                 idle running_turns queued_turns attachment_transfers
                 attachment_normalizations operator_clients unknown
               ))
    end

    test "a read listener serves it over the wire, with the counters as JSON" do
      {client, _conn} = connect(scope: :read)
      assert hello(client)["result"]["scope"] == "read"

      result = call(client, "runtime.activity")["result"]

      assert result["unknown"] == []
      assert result["idle"] == true

      # The connection asking is a connection: this counter includes its own caller, which
      # is exactly why it does not decide `idle`.
      assert result["operator_clients"] == 1
      assert result["running_turns"] == 0
    end

    test "unsupported params are refused before dispatch" do
      {client, _conn} = connect(scope: :read)
      assert hello(client)["result"]

      response = call(client, "runtime.activity", %{"machine" => "elsewhere"})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "unsupported fields: machine"
    end
  end

  # ---------------------------------------------------------------------------
  # Turns

  describe "turns" do
    @tag sessions: true
    test "a turn the model is still answering is a running turn", context do
      before = Methods.activity(conn_supervisor: :gateway_activity_test_conns)
      assert before["idle"] == true

      {id, agent} = start_held_turn(context)

      assert_receive {:model_entered, _pid}, @receive_timeout

      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["running_turns"] == before["running_turns"] + 1
      assert summary["queued_turns"] == before["queued_turns"]
      assert summary["unknown"] == []
      assert summary["idle"] == false

      release(agent, id)
    end

    @tag sessions: true
    test "a follow-up sent behind it is a queued turn", context do
      before = Methods.activity(conn_supervisor: :gateway_activity_test_conns)
      {id, agent} = start_held_turn(context)
      assert_receive {:model_entered, _pid}, @receive_timeout

      assert {:ok, _} = InteractiveSession.follow_up(id, "and then this", id: "w1b-queued")

      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["running_turns"] == before["running_turns"] + 1
      assert summary["queued_turns"] == before["queued_turns"] + 1
      assert summary["idle"] == false

      release(agent, id)
    end

    @tag sessions: true
    test "a session that stops answering makes both turn counters unknown", context do
      {id, agent} = start_held_turn(context)
      assert_receive {:model_entered, _pid}, @receive_timeout

      runtime = native_runtime(id)
      :sys.suspend(runtime)
      on_exit(fn -> if Process.alive?(runtime), do: :sys.resume(runtime) end)

      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["running_turns"] == nil
      assert summary["queued_turns"] == nil
      assert "running_turns" in summary["unknown"]
      assert "queued_turns" in summary["unknown"]

      # Everything the node *could* answer is still answered; only the sources that did
      # not are blank, which is the difference between a hole and a zero.
      assert summary["operator_clients"] == 0
      assert summary["idle"] == nil

      :sys.resume(runtime)
      release(agent, id)
    end
  end

  # ---------------------------------------------------------------------------
  # Attachments

  describe "attachment work" do
    setup do
      root =
        Path.join(System.tmp_dir!(), "w1b-attachments-#{System.unique_integer([:positive])}")

      test_pid = self()
      {:ok, _owner} = Agent.start_link(fn -> test_pid end, name: :w1b_activity_decoder_owner)

      server =
        start_supervised!({Attachments, name: nil, data_dir: root, normalizer: HeldDecoder})

      on_exit(fn -> File.rm_rf(root) end)
      %{attachments: server}
    end

    test "an upload that has begun and not finished is a transfer in flight", %{
      attachments: server
    } do
      assert %{"attachment_transfers" => 0, "idle" => true} = summary(server)

      {:ok, %{"upload_id" => _id}} = begin_upload(server, "two pixels")

      assert %{"attachment_transfers" => 1, "attachment_normalizations" => 0, "idle" => false} =
               summary(server)
    end

    test "a decoder task still running is a normalization in flight", %{attachments: server} do
      bytes = "two pixels"
      {:ok, %{"upload_id" => id}} = begin_upload(server, bytes)

      {:ok, _} =
        Attachments.operation(
          "append",
          %{"upload_id" => id, "offset" => 0, "data" => Base.encode64(bytes)},
          "owner",
          server
        )

      {:ok, _} =
        Attachments.operation(
          "finish",
          %{"upload_id" => id, "sha256" => hash(bytes)},
          "owner",
          server
        )

      assert_receive {:normalizing, worker}, @receive_timeout

      assert %{"attachment_normalizations" => 1, "attachment_transfers" => 0, "idle" => false} =
               summary(server)

      send(worker, :release)
    end

    test "a service that is there and does not answer is unknown", %{attachments: server} do
      pid = GenServer.whereis(server)
      :sys.suspend(pid)
      on_exit(fn -> if Process.alive?(pid), do: :sys.resume(pid) end)

      assert %{
               "attachment_transfers" => nil,
               "attachment_normalizations" => nil,
               "idle" => nil,
               "unknown" => unknown
             } = summary(server)

      assert "attachment_transfers" in unknown
      assert "attachment_normalizations" in unknown

      :sys.resume(pid)
    end

    test "a service that is not there holds nothing, which is zero and not unknown" do
      assert %{
               "attachment_transfers" => 0,
               "attachment_normalizations" => 0,
               "unknown" => [],
               "idle" => true
             } = summary(:w1b_attachments_that_never_started)
    end
  end

  # ---------------------------------------------------------------------------
  # Clients

  describe "operator clients" do
    test "every connection this listener serves is counted, and none of them is work" do
      {first, _} = connect(scope: :read)
      assert hello(first)["result"]

      assert %{"operator_clients" => 1, "idle" => true} =
               Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      {second, _} = connect(scope: :read)
      assert hello(second)["result"]

      # Two clients attached, and the node is still idle: the proposal's own restart
      # transition expects attached UIs to be interrupted and to reconnect.
      assert %{"operator_clients" => 2, "idle" => true} =
               Methods.activity(conn_supervisor: :gateway_activity_test_conns)
    end

    test "a connection supervisor this build cannot find is unknown, not zero" do
      summary = Methods.activity(conn_supervisor: :w1b_conns_that_never_started)

      assert summary["operator_clients"] == nil
      assert summary["unknown"] == ["operator_clients"]
      assert summary["idle"] == nil

      # The counter that is unknown is the one nothing could read. Every other source
      # answered, and answered zero.
      assert summary["running_turns"] == 0
    end
  end

  # ---------------------------------------------------------------------------
  # The gate

  describe "runtime.shutdown require_idle" do
    @tag sessions: true
    test "refuses a busy runtime before it writes anything", context do
      {client, _conn} = connect(scope: :operate, allow_shutdown: true)
      assert hello(client)["result"]

      {id, agent} = start_held_turn(context)
      assert_receive {:model_entered, _pid}, @receive_timeout

      # Any stop that got through would send this; nothing may.
      Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [self(), :node_stop]})
      on_exit(fn -> Application.delete_env(:ouroboros, :gateway_stop_mfa) end)

      response = call(client, "runtime.shutdown", %{"require_idle" => true})

      assert response["error"]["code"] == -32004
      assert response["error"]["data"]["reason"] == "runtime_busy"
      assert response["error"]["data"]["activity"]["idle"] == false
      assert response["error"]["data"]["activity"]["running_turns"] >= 1
      refute Map.has_key?(response, "result")
      refute_receive :node_stop, 200

      release(agent, id)
    end
  end

  # ---------------------------------------------------------------------------

  defp summary(attachments) do
    Methods.activity(attachments: attachments, conn_supervisor: :gateway_activity_test_conns)
  end

  defp begin_upload(server, bytes) do
    Attachments.operation(
      "begin",
      %{
        "client_id" => "w1b",
        "draft_id" => "draft",
        "client_attachment_id" => "entry",
        "attempt_id" => "attempt",
        "byte_size" => byte_size(bytes),
        "session_id" => "session"
      },
      "owner",
      server
    )
  end

  defp hash(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)

  # A session whose model has entered its one scripted response and is waiting to be let
  # go. The turn is genuinely in flight for as long as the test holds it: the native
  # session process itself stays responsive, which is what makes the running count
  # readable at all.
  defp start_held_turn(context) do
    test_pid = self()

    hold = fn _request ->
      send(test_pid, {:model_entered, self()})

      receive do
        :release -> [{:text, "done"}, {:finish, :stop}]
      after
        4_000 -> [{:text, "abandoned"}, {:finish, :stop}]
      end
    end

    {model, agent} = NativeModelScript.start([hold])
    id = "w1b-activity-#{System.unique_integer([:positive])}"

    assert {:ok, _} =
             Methods.invoke("interactive.start", %{
               "id" => id,
               "workspace" => context.workspace,
               "model" => model,
               "worktree" => false,
               "runtime_exposure" => false
             })

    on_exit(fn -> InteractiveSession.close(id) end)

    assert {:ok, _} = InteractiveSession.send_message(id, "hold here", id: "w1b-running")

    {id, agent}
  end

  defp release(agent, id) do
    send(agent, :release)
    InteractiveSession.await(id, "w1b-running", @receive_timeout)
    _ = InteractiveSession.close(id)
    :ok
  end

  defp native_runtime(id) do
    {:ok, state} = InteractiveStore.get(id)
    [{pid, _}] = Registry.lookup(Ouroboros.SessionRegistry, {:runtime, state.runtime_id})
    pid
  end

  # ---------------------------------------------------------------------------
  # A real socket pair, the way the other gateway suites connect: only the listener's
  # bind is skipped, and the connection is told which supervisor it belongs to exactly as
  # `Ouroboros.Gateway.Listener` tells it.

  defp connect(opts) do
    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: Keyword.get(opts, :scope, :read),
        allow_shutdown: Keyword.get(opts, :allow_shutdown, false)
      )

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :gateway_activity_test_conns,
        {Conn,
         socket: server,
         config: config,
         task_supervisor: :gateway_activity_test_tasks,
         conn_supervisor: :gateway_activity_test_conns}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)
    on_exit(fn -> :gen_tcp.close(client) end)

    {client, conn}
  end

  defp hello(client) do
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "activity-test"})
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

    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, @receive_timeout) do
      {:ok, line} -> JSON.decode!(String.trim_trailing(line, "\n"))
      {:error, reason} -> {:error, reason}
    end
  end
end
