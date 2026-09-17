defmodule Ouroboros.Gateway.FleetDeploymentTest do
  # `async: false`: moves `config :ouroboros, :data_dir`, `config :ouroboros, :audit` and the
  # `OUROBOROS_PROCESS_ID_HELPER` environment variable, all node-global.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Audit.Config, as: AuditConfig
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake

  @token String.duplicate("g", 40)
  @receive_timeout 5_000

  @deployment_methods ~w(
    fleet.deployment.prepare fleet.deployment.start fleet.deployment.authenticate
    fleet.deployment.confirm_host fleet.deployment.cancel fleet.deployment.resume
  )

  setup do
    start_supervised!({Task.Supervisor, name: :fleet_deployment_test_tasks})

    start_supervised!(
      {DynamicSupervisor, strategy: :one_for_one, name: :fleet_deployment_test_conns}
    )

    root = Path.join(System.tmp_dir!(), "ogw2b#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    fake_dir = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      audit: Application.get_env(:ouroboros, :audit),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)

    on_exit(fn ->
      restore(:data_dir, previous.data_dir)
      restore(:audit, previous.audit)

      if previous.ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous.ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      File.rm_rf!(root)
    end)

    %{root: root, fake_dir: fake_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # ---------------------------------------------------------------------------
  # The table itself

  describe "the method table" do
    test "serves every verb the proposal's method family names, at the scope it names" do
      table = Methods.table()

      assert table["fleet.devices"].scope == :read
      assert table["fleet.deployment.status"].scope == :read

      for method <- @deployment_methods do
        assert table[method].scope == :operate, "#{method} must be operate-scoped"
      end
    end

    test "every one of them refuses an unknown parameter before dispatch" do
      for method <- ["fleet.devices", "fleet.deployment.status" | @deployment_methods] do
        assert {:invalid, message} = Contract.validate(method, %{"unexpected" => true})
        assert message =~ "unsupported fields: unexpected"
      end
    end

    test "a ceiling breach on the two verbs that change another machine is unknown, not failure" do
      table = Methods.table()

      assert table["fleet.deployment.start"].outcome == :unknown
      assert table["fleet.deployment.cancel"].outcome == :unknown

      # And not on the ones where the gateway giving up really does mean nothing happened.
      refute Map.get(table["fleet.devices"], :outcome)
      refute Map.get(table["fleet.deployment.status"], :outcome)
    end
  end

  # ---------------------------------------------------------------------------
  # Scope

  describe "scope" do
    test "a read listener serves the inventory and the status read", context do
      arrange_devices(context, ~s({"devices": [], "discovery": {"code": "ok"}}\n))
      client = connected(scope: :read)

      result = call(client, "fleet.devices")["result"]

      assert result["devices"] == []
      assert result["host"]["capabilities"]["deploy"] == false

      # Status of an operation nobody started is a not-found, not a scope refusal.
      assert call(client, "fleet.deployment.status", %{"operation_id" => "00aa11bb22cc33dd"})[
               "error"
             ]["code"] == -32_007
    end

    test "a read listener refuses every mutation with -32003", _context do
      client = connected(scope: :read)

      for method <- @deployment_methods do
        error = call(client, method, %{})["error"]
        assert error["code"] == -32_003, "#{method} must be refused at read scope"
        assert error["message"] =~ method
      end
    end

    test "an operate listener gets past scope and lands on the parameters", _context do
      client = connected(scope: :operate)

      # No `ouro`, so the deepest these can get is a named refusal — never -32003.
      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      error = call(client, "fleet.deployment.prepare", %{})["error"]
      assert error["code"] == -32_602
      assert error["message"] =~ "params.target is required"
    end
  end

  # ---------------------------------------------------------------------------
  # Identities

  describe "with identities configured" do
    test "an operator reads membership but is refused the network inventory", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "operator-token")

      # The membership subset an operator keeps lives in `fleet.status`, and only there.
      assert call(client, "fleet.status")["result"]
      assert call(client, "fleet.doctor")["result"]

      # The identity rules are scope-independent, so the read-scoped members of the family
      # are refused for the same reason the mutations are: a tailnet inventory is every
      # machine on an operator's private network, and an operation's steps are a
      # deployment's business.
      for method <- ["fleet.devices", "fleet.deployment.status" | @deployment_methods] do
        assert call(client, method, %{})["error"]["code"] == -32_003,
               "#{method} must need an administrator"
      end
    end

    test "an auditor is refused the inventory too", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "auditor-token")

      for method <- ["fleet.devices", "fleet.deployment.status" | @deployment_methods] do
        assert call(client, method, %{})["error"]["code"] == -32_003,
               "#{method} must need an administrator"
      end
    end

    test "an administrator reaches the verbs", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "administrator-token")

      assert call(client, "fleet.devices")["result"]["host"]

      # Past the gate, onto the parameters — which is what "reaches the verb" means. The
      # read-scoped status reaches its own refusal, not the identity's.
      assert call(client, "fleet.deployment.prepare", %{})["error"]["code"] == -32_602

      assert call(client, "fleet.deployment.status", %{"operation_id" => "00aa11bb22cc33dd"})[
               "error"
             ]["code"] == -32_007
    end
  end

  describe "with no identities configured" do
    test "the local owner is the administrator, which is the single-machine posture",
         context do
      arrange_devices(context, ~s({"devices": []}\n))
      Application.delete_env(:ouroboros, :audit)

      client = connected(scope: :operate)

      assert call(client, "fleet.devices")["result"]["host"]
      assert call(client, "fleet.deployment.prepare", %{})["error"]["code"] == -32_602
    end
  end

  # ---------------------------------------------------------------------------
  # The whole lifecycle over a real listener

  describe "over a listener" do
    test "prepare, challenge, authenticate, start and cancel", context do
      %{worker: worker} = arrange_worker(context)
      client = connected(scope: :operate)

      prepared = call(client, "fleet.deployment.prepare", prepare_params())["result"]
      operation = prepared["operation_id"]
      assert String.match?(operation, ~r/\A[0-9a-f]{16}\z/)
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      status = call(client, "fleet.deployment.status", %{"operation_id" => operation})["result"]
      assert status["source"] == "worker"
      assert status["attached"] == true

      :ok = FleetWorkerFake.challenge(worker, "pw", "password", %{"attempt" => 1})
      await_challenge(client, operation, "pw")

      answered =
        call(client, "fleet.deployment.authenticate", %{
          "operation_id" => operation,
          "challenge" => "pw",
          "secret" => "listener-secret-01"
        })["result"]

      assert answered["accepted"] == true
      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"]["secret"] == "listener-secret-01"

      :ok = FleetWorkerFake.challenge(worker, "rev", "review", %{"plan" => %{"steps" => []}})
      await_challenge(client, operation, "rev")

      started =
        call(client, "fleet.deployment.start", %{
          "operation_id" => operation,
          "plan_digest" => "abc123",
          "idempotency_key" => "key-listener"
        })["result"]

      assert started["accepted"] == true

      cancelled =
        call(client, "fleet.deployment.cancel", %{"operation_id" => operation})["result"]

      assert cancelled["cancelled"] == true

      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "a second listener connection is a second session and cannot answer the challenge",
         context do
      %{worker: worker} = arrange_worker(context)
      first = connected(scope: :operate)
      second = connected(scope: :operate)

      operation =
        call(first, "fleet.deployment.prepare", prepare_params())["result"]["operation_id"]

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = FleetWorkerFake.challenge(worker, "pw", "password")
      await_challenge(first, operation, "pw")

      # Same identity, same scope, same machine — a different connection. Seam S4 binds a
      # challenge to the session it was issued to, and this is that session's neighbour.
      error =
        call(second, "fleet.deployment.authenticate", %{
          "operation_id" => operation,
          "challenge" => "pw",
          "secret" => "second-connection-secret"
        })["error"]

      assert error["code"] == -32_003
      assert error["data"]["reason"] == "challenge_not_bound"

      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
      assert FleetWorkerFake.refusals(worker) == 0

      # The connection it *was* issued to still answers.
      assert call(first, "fleet.deployment.authenticate", %{
               "operation_id" => operation,
               "challenge" => "pw",
               "secret" => "first-connection-secret"
             })["result"]["accepted"] == true
    end

    test "a stale challenge answered twice is refused with a stable reason", context do
      %{worker: worker} = arrange_worker(context)
      client = connected(scope: :operate)

      operation =
        call(client, "fleet.deployment.prepare", prepare_params())["result"]["operation_id"]

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = FleetWorkerFake.challenge(worker, "pw", "password")
      await_challenge(client, operation, "pw")

      assert call(client, "fleet.deployment.authenticate", %{
               "operation_id" => operation,
               "challenge" => "pw",
               "secret" => "one"
             })["result"]

      error =
        call(client, "fleet.deployment.authenticate", %{
          "operation_id" => operation,
          "challenge" => "pw",
          "secret" => "two"
        })["error"]

      assert error["code"] == -32_006
      assert error["data"]["reason"] == "challenge_consumed"
    end

    test "an expired challenge carries its own reason code", context do
      %{worker: worker} = arrange_worker(context)
      client = connected(scope: :operate)

      operation =
        call(client, "fleet.deployment.prepare", prepare_params())["result"]["operation_id"]

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      past = DateTime.utc_now() |> DateTime.add(-30, :second) |> DateTime.to_iso8601()
      :ok = FleetWorkerFake.challenge(worker, "old", "password", %{"expires_at" => past})
      await_challenge(client, operation, "old")

      error =
        call(client, "fleet.deployment.authenticate", %{
          "operation_id" => operation,
          "challenge" => "old",
          "secret" => "too-late"
        })["error"]

      assert error["data"]["reason"] == "challenge_expired"
    end

    test "resume brings back an operation whose worker is gone", context do
      %{worker: _worker} = arrange_worker(context)
      client = connected(scope: :operate)

      operation =
        call(client, "fleet.deployment.prepare", prepare_params())["result"]["operation_id"]

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      # The worker wrote its journal before it died, which is the only reason there is
      # anything to resume.
      write_journal(context.root, operation, %{
        "operation" => operation,
        # Seam S5's owner. A listener that authenticated with the local token resolves to
        # `local-owner`, which is what `Audit.Identity.actor/0` answers for this caller.
        "owner" => "local-owner",
        "kind" => "add",
        "state" => "interrupted"
      })

      assert {:ok, pid} = Ouroboros.Fleet.Deployment.client(operation)
      reference = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, @receive_timeout

      status = call(client, "fleet.deployment.status", %{"operation_id" => operation})["result"]
      assert status["source"] == "journal"
      assert status["state"] == "interrupted"

      resumed = call(client, "fleet.deployment.resume", %{"operation_id" => operation})["result"]
      assert resumed["operation_id"] == operation
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      status = call(client, "fleet.deployment.status", %{"operation_id" => operation})["result"]
      assert status["source"] == "worker"
    end

    test "an unknown `ouro` is a named unavailability rather than a crash", _context do
      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
      client = connected(scope: :operate)

      error = call(client, "fleet.devices")["error"]
      assert error["code"] == -32_004
      assert error["data"]["reason"] == "ouro_path_unknown"

      error = call(client, "fleet.deployment.prepare", prepare_params())["error"]
      assert error["data"]["reason"] == "ouro_path_unknown"
    end

    test "an operation id that is not one is refused before any path is built", _context do
      client = connected(scope: :operate)

      error =
        call(client, "fleet.deployment.status", %{"operation_id" => "../../../etc/passwd"})[
          "error"
        ]

      assert error["code"] == -32_602
      assert error["data"]["reason"] == "invalid_operation"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

  defp prepare_params do
    %{"target" => %{"address" => "100.64.12.44"}, "ssh_user" => "deploy"}
  end

  defp arrange_devices(context, document) do
    ouro = FleetOuroFake.write!(context.fake_dir, devices: document)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    ouro
  end

  defp arrange_worker(context) do
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    socket_path = Path.join([context.root, "deploy", "w.sock"])

    worker =
      start_supervised!(
        {FleetWorkerFake,
         [
           socket_path: socket_path,
           cap: cap,
           instance: instance,
           operation_file: FleetOuroFake.operation_file(context.fake_dir),
           owner: self()
         ]},
        id: {FleetWorkerFake, System.unique_integer([:positive])}
      )

    ouro =
      FleetOuroFake.write!(context.fake_dir,
        spawn_line: FleetWorkerFake.spawn_line(worker),
        cap: cap
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    %{worker: worker, ouro: ouro}
  end

  defp configure_identities(context) do
    identities = [
      identity("olive", ["operator"], "operator-token"),
      identity("adele", ["administrator"], "administrator-token"),
      identity("aster", ["auditor"], "auditor-token")
    ]

    config =
      AuditConfig.new!(
        mode: :local,
        capture: :full,
        root: Path.join(context.root, "evidence"),
        writer_id: "w2b-gateway-test",
        identities: identities
      )

    Application.put_env(:ouroboros, :audit, config)
    config
  end

  defp identity(id, roles, token) do
    %{
      "id" => id,
      "roles" => roles,
      "token_sha256" => :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    }
  end

  defp connected(opts) do
    token = Keyword.get(opts, :token, @token)
    client = connect(opts)

    assert call(client, "hello", %{
             "token" => token,
             "protocol" => 1,
             "client" => "w2b-test"
           })["result"]

    client
  end

  defp connect(opts) do
    config =
      Config.new!(
        token: @token,
        data_dir: System.tmp_dir!(),
        scope: Keyword.get(opts, :scope, :read)
      )

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :fleet_deployment_test_conns,
        {Conn,
         socket: server,
         config: config,
         task_supervisor: :fleet_deployment_test_tasks,
         conn_supervisor: :fleet_deployment_test_conns}
      )

    :ok = :gen_tcp.controlling_process(server, conn)
    send(conn, :socket_ready)
    on_exit(fn -> :gen_tcp.close(client) end)

    client
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
      {:error, reason} -> flunk("the listener did not answer #{method}: #{inspect(reason)}")
    end
  end

  defp await_challenge(client, operation, challenge) do
    Enum.reduce_while(1..50, :missing, fn _attempt, _acc ->
      status = call(client, "fleet.deployment.status", %{"operation_id" => operation})["result"]

      if status && Enum.any?(status["challenges"], &(&1["challenge"] == challenge)) do
        {:halt, :ok}
      else
        Process.sleep(20)
        {:cont, :missing}
      end
    end)
    |> case do
      :ok -> :ok
      :missing -> flunk("the broker never recorded challenge #{challenge}")
    end
  end

  defp write_journal(root, operation, document) do
    dir = Path.join([root, "deploy"])
    File.mkdir_p!(dir)
    path = Path.join(dir, operation <> ".json")
    File.write!(path, JSON.encode!(document))
    File.chmod!(path, 0o600)
  end
end
