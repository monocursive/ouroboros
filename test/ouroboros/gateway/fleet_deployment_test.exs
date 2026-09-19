defmodule Ouroboros.Gateway.FleetDeploymentTest do
  @moduledoc """
  The `fleet.*` verbs over a real listener, against a real port program.

  What this suite is for is the wire: the method table, the scope and identity gates, the
  parameters each verb refuses, and the lifecycle a client actually drives —
  `start` → `respond` → `respond` → `respond` → `status`, with `cancel` and `resume` beside
  it. The program at the other end is `test/support/fleet_frames_fake.sh`, written to §8.
  """

  # `async: false`: moves `config :ouroboros, :data_dir`, `config :ouroboros, :audit`, the
  # web config and the `OUROBOROS_*` environment, all node-global.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Audit.Config, as: AuditConfig
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Gateway.Methods.Contract
  alias Ouroboros.Test.FleetFramesFake

  @token String.duplicate("g", 40)
  @receive_timeout 5_000

  @mutations ~w(
    fleet.deployment.start fleet.deployment.respond
    fleet.deployment.cancel fleet.deployment.resume
  )

  setup do
    start_supervised!({Task.Supervisor, name: :fleet_deployment_test_tasks})

    start_supervised!(
      {DynamicSupervisor, strategy: :one_for_one, name: :fleet_deployment_test_conns}
    )

    root = Path.join(System.tmp_dir!(), "ogw2b#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    bin = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      audit: Application.get_env(:ouroboros, :audit),
      # The deploy blockers read this, and a case that reconfigures the endpoint to prove one
      # of them would otherwise leave it set for every case after it.
      web: Application.get_env(:ouroboros, :web),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)
    FleetFramesFake.install!(bin, devices: ~s({"devices":[],"discovery":{"code":"ok"}}\n))

    on_exit(fn ->
      reap_workers()
      Process.sleep(150)
      FleetFramesFake.uninstall!()
      restore(:data_dir, previous.data_dir)
      restore(:audit, previous.audit)
      restore(:web, previous.web)

      if previous.ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous.ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      _ = File.rm_rf(root)
    end)

    %{root: root, bin: bin}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp reap_workers do
    supervisor = Ouroboros.Fleet.Deployment.WorkerSupervisor

    supervisor
    |> DynamicSupervisor.which_children()
    |> Enum.each(fn {_id, pid, _type, _modules} ->
      if is_pid(pid), do: DynamicSupervisor.terminate_child(supervisor, pid)
    end)
  catch
    :exit, _not_running -> :ok
  end

  # ---------------------------------------------------------------------------
  # The table itself

  describe "the method table" do
    test "serves the §9 family, at the scope §9 names, and nothing it deleted" do
      table = Methods.table()

      assert table["fleet.devices"].scope == :read
      assert table["fleet.deployment.status"].scope == :read

      for method <- @mutations do
        assert table[method].scope == :operate, "#{method} must be operate-scoped"
      end

      for gone <- ~w(fleet.deployment.prepare fleet.deployment.authenticate
                     fleet.deployment.confirm_host) do
        refute Map.has_key?(table, gone), "#{gone} is deleted by fleet-kiss §9"
      end

      # And the three that are unchanged.
      for kept <- ~w(fleet.status fleet.doctor fleet.tags fleet.forget_session_owner) do
        assert Map.has_key?(table, kept)
      end
    end

    test "every one of them refuses an unknown parameter before dispatch" do
      for method <- ["fleet.devices", "fleet.deployment.status" | @mutations] do
        assert {:invalid, message} = Contract.validate(method, %{"unexpected" => true})
        assert message =~ "unsupported fields: unexpected"
      end
    end

    test "a ceiling breach on the verbs that change another machine is unknown, not failure" do
      table = Methods.table()

      for method <- ~w(fleet.deployment.start fleet.deployment.respond
                       fleet.deployment.cancel) do
        assert table[method].outcome == :unknown
      end

      refute Map.get(table["fleet.devices"], :outcome)
      refute Map.get(table["fleet.deployment.status"], :outcome)
    end

    test "the operation parameter is named `operation`, as §9 writes it" do
      assert {:invalid, message} = Contract.validate("fleet.deployment.status", %{})
      assert message =~ "operation"

      assert Contract.validate("fleet.deployment.status", %{"operation" => "00aa11bb22cc33dd"}) ==
               :ok
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
      assert is_boolean(result["host"]["capabilities"]["deploy"])
      # §9: the inventory loses `issuer`, and with it the whole question of who may admit.
      refute Map.has_key?(result["host"], "issuer")

      # Status of an operation nobody started is a not-found, not a scope refusal.
      assert call(client, "fleet.deployment.status", %{"operation" => "00aa11bb22cc33dd"})[
               "error"
             ]["code"] == -32_007
    end

    test "a read listener refuses every mutation with -32003", _context do
      client = connected(scope: :read)

      for method <- @mutations do
        error = call(client, method, %{})["error"]
        assert error["code"] == -32_003, "#{method} must be refused at read scope"
        assert error["message"] =~ method
      end
    end

    test "an operate listener gets past scope and lands on the parameters", _context do
      client = connected(scope: :operate)

      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      error = call(client, "fleet.deployment.start", %{})["error"]
      assert error["code"] == -32_602
      assert error["message"] =~ "params.target is required for an add"
    end
  end

  # ---------------------------------------------------------------------------
  # Identities

  describe "with identities configured" do
    test "an operator reads membership but is refused the network inventory", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "operator-token")

      assert call(client, "fleet.status")["result"]
      assert call(client, "fleet.doctor")["result"]

      for method <- ["fleet.devices", "fleet.deployment.status" | @mutations] do
        assert call(client, method, %{})["error"]["code"] == -32_003,
               "#{method} must need an administrator"
      end
    end

    test "an auditor is refused the inventory too", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "auditor-token")

      for method <- ["fleet.devices", "fleet.deployment.status" | @mutations] do
        assert call(client, method, %{})["error"]["code"] == -32_003,
               "#{method} must need an administrator"
      end
    end

    test "an administrator reaches the verbs", context do
      arrange_devices(context, ~s({"devices": []}\n))
      configure_identities(context)

      client = connected(scope: :operate, token: "administrator-token")

      assert call(client, "fleet.devices")["result"]["host"]
      assert call(client, "fleet.deployment.start", %{})["error"]["code"] == -32_602

      assert call(client, "fleet.deployment.status", %{"operation" => "00aa11bb22cc33dd"})[
               "error"
             ]["code"] == -32_007
    end

    test "a second administrator answers the first one's prompt, which §10 is explicit about",
         context do
      configure_identities(context)
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())

      adele = connected(scope: :operate, token: "administrator-token")
      operation = start_add(adele)
      await_challenge(adele, operation, "hold-1")

      # A different connection, a different session, the same runtime. Before fleet-kiss this
      # was `challenge_not_bound` and the way out was a takeover.
      other = connected(scope: :operate, token: "administrator-token")

      assert call(other, "fleet.deployment.respond", %{
               "operation" => operation,
               "challenge" => "hold-1",
               "accept" => true
             })["result"]["accepted"] == true
    end
  end

  describe "with no identities configured" do
    test "the local owner is the administrator, which is the single-machine posture",
         context do
      arrange_devices(context, ~s({"devices": []}\n))
      Application.delete_env(:ouroboros, :audit)

      client = connected(scope: :operate)

      assert call(client, "fleet.devices")["result"]["host"]
      assert call(client, "fleet.deployment.start", %{})["error"]["code"] == -32_602
    end
  end

  # ---------------------------------------------------------------------------
  # The whole lifecycle over a real listener

  describe "over a listener" do
    test "start, host trust, password, review, steps and done", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())
      client = connected(scope: :operate)

      started = call(client, "fleet.deployment.start", start_params())["result"]
      operation = started["operation"]
      assert String.match?(operation, ~r/\A[0-9a-f]{16}\z/)
      # §9 answers `{operation}`; `operation_id` was the socket protocol's spelling.
      refute Map.has_key?(started, "operation_id")

      await_challenge(client, operation, "trust-1")

      status = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]
      assert status["source"] == "worker"
      assert status["running"] == true
      assert status["kind"] == "add"
      assert status["challenge"]["kind"] == "host_trust"
      # One challenge, not a list of them.
      refute Map.has_key?(status, "challenges")
      refute Map.has_key?(status, "done")
      refute Map.has_key?(status, "worker_exit")

      assert call(client, "fleet.deployment.respond", %{
               "operation" => operation,
               "challenge" => "trust-1",
               "accept" => true
             })["result"]["accepted"] == true

      await_challenge(client, operation, "secret-1")

      assert call(client, "fleet.deployment.respond", %{
               "operation" => operation,
               "challenge" => "secret-1",
               "secret" => "a password nobody stores"
             })["result"]["accepted"] == true

      await_challenge(client, operation, "review-1")

      review = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]
      assert review["challenge"]["kind"] == "review"
      assert is_list(review["challenge"]["metadata"]["plan"])
      # No digest and no idempotency key: approving is answering the challenge.
      refute Map.has_key?(review["challenge"], "plan_digest")

      assert call(client, "fleet.deployment.respond", %{
               "operation" => operation,
               "challenge" => "review-1",
               "accept" => true
             })["result"]["accepted"] == true

      final = await_state(client, operation, "completed")

      assert Enum.map(final["steps"], & &1["step"]) ==
               ~w(inspect install join service start connect)
    end

    test "cancel stops the operation and the journal says so afterwards", context do
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      operation = start_add(client)
      await_challenge(client, operation, "hold-1")

      assert call(client, "fleet.deployment.cancel", %{"operation" => operation})["result"]

      final = await_state(client, operation, "cancelled")
      assert final["state"] == "cancelled"
    end

    test "resume runs the program again for an operation nothing is holding", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step inspect ok seen",
        "exit 3"
      ])

      client = connected(scope: :operate)

      operation = start_add(client)
      await_source(client, operation, "journal")

      status = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]
      assert status["running"] == false
      assert status["last_error"]["reason"] == "worker_exited"

      FleetFramesFake.write_scenario!(context.bin, [
        "step inspect skipped already done",
        "done completed picked up where it left off"
      ])

      assert call(client, "fleet.deployment.resume", %{"operation" => operation})["result"][
               "operation"
             ] == operation

      assert await_state(client, operation, "completed")
    end

    test "respond refuses two answers at once, and neither of them alone when it asks",
         context do
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      operation = start_add(client)
      await_challenge(client, operation, "hold-1")

      both =
        call(client, "fleet.deployment.respond", %{
          "operation" => operation,
          "challenge" => "hold-1",
          "accept" => true,
          "secret" => "no"
        })["error"]

      assert both["code"] == -32_602
      assert both["message"] =~ "two answers"

      neither =
        call(client, "fleet.deployment.respond", %{
          "operation" => operation,
          "challenge" => "hold-1"
        })["error"]

      assert neither["code"] == -32_602

      # A host-trust challenge is not answered with a secret.
      mismatch =
        call(client, "fleet.deployment.respond", %{
          "operation" => operation,
          "challenge" => "hold-1",
          "secret" => "no"
        })["error"]

      assert mismatch["data"]["reason"] == "challenge_kind_mismatch"

      # And none of those reached the program.
      refute Enum.any?(FleetFramesFake.responses(context.bin), &String.contains?(&1, "\"no\""))
    end

    test "an operation id that is not one is refused before anything touches a path",
         _context do
      client = connected(scope: :operate)

      for method <- ~w(fleet.deployment.status fleet.deployment.cancel fleet.deployment.resume) do
        error = call(client, method, %{"operation" => "../../etc/passwd"})["error"]
        assert error["data"]["reason"] == "invalid_operation", "#{method} accepted a path"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # The three kinds

  describe "start kinds" do
    test "a setup takes no target and names this host when the caller did not", context do
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      operation =
        call(client, "fleet.deployment.start", %{"kind" => "setup"})["result"]["operation"]

      await_challenge(client, operation, "hold-1")

      argv = FleetFramesFake.argv(context.bin)
      assert Enum.take(argv, 2) == ["fleet", "setup"]
      assert "--machine" in argv
      refute "--user" in argv
      refute Enum.any?(argv, &String.contains?(&1, "@"))
      assert Enum.take(argv, -3) == ["--frames", "--operation", operation]
    end

    test "an add without a machine name is refused, and says where a name comes from",
         _context do
      client = connected(scope: :operate)

      error =
        call(client, "fleet.deployment.start", %{
          "target" => %{"address" => "100.64.12.44"},
          "ssh_user" => "deploy"
        })["error"]

      assert error["code"] == -32_602
      assert error["message"] =~ "suggested_machine"
    end

    test "an add without an address is refused rather than sent a peer id as one", _context do
      client = connected(scope: :operate)

      error =
        call(client, "fleet.deployment.start", %{
          "target" => %{"peer_id" => "n1234", "machine" => "pi"},
          "ssh_user" => "deploy"
        })["error"]

      assert error["code"] == -32_602
      assert error["message"] =~ "params.target.address is required"
    end

    test "a leave names a member of this machine's profile, and never an address", context do
      write_profile(context.root, [
        %{"machine" => "studio", "host" => "100.64.0.1", "node" => "ouro@100.64.0.1"},
        %{"machine" => "buildbox", "host" => "100.64.12.44", "node" => "ouro@100.64.12.44"}
      ])

      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      operation =
        call(client, "fleet.deployment.start", %{
          "kind" => "leave",
          "target" => %{"machine" => "buildbox"},
          "ssh_user" => "deploy"
        })["result"]["operation"]

      await_challenge(client, operation, "hold-1")

      assert FleetFramesFake.argv(context.bin) == [
               "fleet",
               "leave",
               "--machine",
               "buildbox",
               "--user",
               "deploy",
               "--port",
               "22",
               "--frames",
               "--operation",
               operation
             ]
    end

    test "a leave of a machine that is not a member is refused with the list printed",
         context do
      write_profile(context.root, [
        %{"machine" => "studio", "host" => "100.64.0.1", "node" => "ouro@100.64.0.1"}
      ])

      client = connected(scope: :operate)

      error =
        call(client, "fleet.deployment.start", %{
          "kind" => "leave",
          "target" => %{"machine" => "nowhere"},
          "ssh_user" => "deploy"
        })["error"]

      assert error["code"] == -32_602
      assert error["message"] =~ "is not in this machine's fleet"
      assert error["message"] =~ "studio"
    end

    test "a leave matches a member's name the way the rest of the fleet matches names",
         context do
      write_profile(context.root, [
        %{"machine" => "BuildBox", "host" => "100.64.12.44", "node" => "ouro@100.64.12.44"}
      ])

      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      assert call(client, "fleet.deployment.start", %{
               "kind" => "leave",
               "target" => %{"machine" => "buildbox"},
               "ssh_user" => "deploy"
             })["result"]["operation"]
    end
  end

  # ---------------------------------------------------------------------------
  # The operations listing

  describe "the operations listing" do
    test "names the device each open operation belongs to, and whether it is running",
         context do
      arrange_devices(context, ~s({"devices": []}\n))

      write_journal(context.root, "aa11bb22cc33dd44", %{
        "schema" => 2,
        "operation" => "aa11bb22cc33dd44",
        "kind" => "add",
        "state" => "waiting",
        "created_at" => "2026-09-17T10:00:00Z",
        "updated_at" => "2026-09-17T10:05:00Z",
        "target" => %{
          "machine" => "build-linux",
          "address" => "100.64.12.44",
          "ssh_user" => "deploy",
          "port" => 2222,
          "host_fingerprint" => "SHA256:abc",
          "os" => "linux"
        }
      })

      client = connected(scope: :operate)
      [operation] = call(client, "fleet.devices")["result"]["operations"]

      assert operation["operation"] == "aa11bb22cc33dd44"
      assert operation["kind"] == "add"
      assert operation["state"] == "waiting"
      assert operation["running"] == false
      # §9 replaces `owner`/`attached` with `running`, because there is no owner any more.
      refute Map.has_key?(operation, "owner")
      refute Map.has_key?(operation, "attached")

      # The four fields that put it on a row, and only those.
      assert operation["target"] == %{
               "machine" => "build-linux",
               "address" => "100.64.12.44",
               "ssh_user" => "deploy",
               "port" => 2222
             }
    end

    test "an operation with no target, and one whose journal cannot be read, still render",
         context do
      arrange_devices(context, ~s({"devices": []}\n))

      write_journal(context.root, "1122334455667788", %{
        "schema" => 2,
        "operation" => "1122334455667788",
        "kind" => "setup",
        "state" => "running"
      })

      File.write!(Path.join([context.root, "deploy", "99aabbccddeeff00.json"]), "{ not json")

      client = connected(scope: :operate)
      operations = call(client, "fleet.devices")["result"]["operations"]

      setup = Enum.find(operations, &(&1["operation"] == "1122334455667788"))
      assert setup["kind"] == "setup"
      assert setup["target"] == nil
      assert setup["readable"] == true

      broken = Enum.find(operations, &(&1["operation"] == "99aabbccddeeff00"))
      assert broken["readable"] == false
      assert broken["reason"] == "journal_unreadable"

      for row <- operations do
        for field <- ~w(operation kind state created_at updated_at target readable running) do
          assert Map.has_key?(row, field), "#{field} missing from #{inspect(row)}"
        end
      end
    end
  end

  # ---------------------------------------------------------------------------
  # A disabled button is a rendering; this is the boundary

  describe "deploy blockers" do
    test "a cleartext bind blocks every kind, because each of them writes something",
         context do
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      Application.put_env(:ouroboros, :web, enabled: true, bind: "0.0.0.0", allow_remote: true)

      for params <- [start_params(), %{"kind" => "setup"}] do
        error = call(client, "fleet.deployment.start", params)["error"]
        assert error["data"]["reason"] == "deploy_blocked"
        assert "cleartext_web_bind" in error["data"]["blockers"]
      end
    end

    test "a dev runtime blocks a setup and nothing else", context do
      FleetFramesFake.write_scenario!(context.bin, hold_scenario())
      client = connected(scope: :operate)

      previous = Application.get_env(:ouroboros, :dev_runtime)
      Application.put_env(:ouroboros, :dev_runtime, true)
      on_exit(fn -> Application.put_env(:ouroboros, :dev_runtime, previous) end)

      error = call(client, "fleet.deployment.start", %{"kind" => "setup"})["error"]
      assert error["data"]["blockers"] == ["dev_runtime"]

      assert call(client, "fleet.deployment.start", start_params())["result"]["operation"]
    end

    test "every blocker this host has is named at once", context do
      client = connected(scope: :operate)

      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
      Application.put_env(:ouroboros, :web, enabled: true, bind: "0.0.0.0", allow_remote: true)

      error = call(client, "fleet.deployment.start", start_params())["error"]

      assert error["code"] == -32_003
      assert Enum.sort(error["data"]["blockers"]) == ["cleartext_web_bind", "ouro_path_unknown"]
      # `no_ca_key` went with the per-member PKI: every member holds the bundle.
      refute "no_ca_key" in error["data"]["blockers"]
      _ = context
    end

    test "an operation already under way cannot be advanced on a host that became blocked",
         context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state waiting",
        "challenge pw password {}",
        "await pw",
        "done completed answered"
      ])

      client = connected(scope: :operate)
      operation = start_add(client)
      await_challenge(client, operation, "pw")

      # The endpoint is reconfigured under a running deployment. The credential must not be
      # accepted after that, which is the whole point of deciding on the bind.
      Application.put_env(:ouroboros, :web, enabled: true, bind: "0.0.0.0", allow_remote: true)

      for {method, params} <- [
            {"fleet.deployment.respond",
             %{"operation" => operation, "challenge" => "pw", "secret" => "blocked-secret"}},
            {"fleet.deployment.resume", %{"operation" => operation}}
          ] do
        error = call(client, method, params)["error"]

        assert error["data"]["reason"] == "deploy_blocked", "#{method} was not blocked"
        assert "cleartext_web_bind" in error["data"]["blockers"]
      end

      refute Enum.any?(
               FleetFramesFake.responses(context.bin),
               &String.contains?(&1, "blocked-secret")
             )

      # Stopping one is always allowed: an operator must be able to end a deployment on a
      # host that may no longer start one.
      assert call(client, "fleet.deployment.cancel", %{"operation" => operation})["result"]
    end
  end

  # ---------------------------------------------------------------------------
  # The network's answer and the runtime's are two different questions

  describe "live cluster facts on device rows" do
    @devices_with_member ~s({"devices": [
      {"name": "buildbox", "machine": "buildbox", "os": "linux", "address": "100.64.12.44",
       "online": false, "last_seen": null, "path": "unknown",
       "state": "fleet_member_not_visible", "action": "diagnose"},
      {"name": "stranger", "machine": null, "os": "linux", "address": "100.64.12.77",
       "online": true, "last_seen": null, "path": "direct",
       "state": "discovered_installation_unknown", "action": "deploy Ouroboros"}
    ]}\n)

    test "a member this runtime is connected to says so, even when discovery cannot see it",
         context do
      arrange_devices(context, @devices_with_member)

      client = connected(scope: :operate)
      rows = call(client, "fleet.devices")["result"]["devices"]

      member = Enum.find(rows, &(&1["machine"] == "buildbox"))

      assert Map.has_key?(member, "connected")
      assert Map.has_key?(member, "compatible")
      assert Map.has_key?(member, "runtime_running")
      assert Map.has_key?(member, "last_probe")

      # Discovery's own facts are untouched: they answer a different question.
      assert member["online"] == false
      assert member["path"] == "unknown"

      stranger = Enum.find(rows, &(&1["address"] == "100.64.12.77"))
      assert stranger["connected"] == nil
      assert stranger["compatible"] == nil
      assert stranger["runtime_running"] == nil
      assert stranger["state"] == "discovered_installation_unknown"
    end

    test "a connected member's row becomes fleet_member_connected", context do
      local =
        Ouroboros.Cluster.fleet_status().machines
        |> Enum.find(&(&1[:state] == :local))
        |> Map.get(:machine)

      assert is_binary(local)

      arrange_devices(context, ~s({"devices": [
        {"name": "#{local}", "machine": "#{local}", "os": "linux", "address": "100.64.12.9",
         "online": false, "last_seen": null, "path": "unknown",
         "state": "fleet_member_not_visible", "action": "diagnose"}
      ]}\n))

      client = connected(scope: :operate)
      [row] = call(client, "fleet.devices")["result"]["devices"]

      assert row["connected"] == true
      assert row["compatible"] == true
      assert row["runtime_running"] == true
      assert is_binary(row["last_probe"])
      assert row["state"] == "fleet_member_connected"
      assert row["online"] == false
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

  # A scenario that raises one challenge and then waits, so a case can read a *live*
  # operation rather than race its ending.
  defp hold_scenario do
    ["state waiting", "challenge hold-1 host_trust {}", "await hold-1", "done completed held"]
  end

  defp start_params do
    %{
      "target" => %{"address" => "100.64.12.44", "machine" => "build-linux"},
      "ssh_user" => "deploy"
    }
  end

  defp start_add(client) do
    call(client, "fleet.deployment.start", start_params())["result"]["operation"]
  end

  defp arrange_devices(context, document) do
    FleetFramesFake.write_devices!(context.bin, document)
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
    poll("challenge #{challenge}", fn ->
      status = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]

      if status && status["challenge"] && status["challenge"]["challenge"] == challenge,
        do: status,
        else: nil
    end)
  end

  defp await_state(client, operation, state) do
    poll("state #{state}", fn ->
      status = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]

      if status && status["state"] == state, do: status, else: nil
    end)
  end

  defp await_source(client, operation, source) do
    poll("source #{source}", fn ->
      status = call(client, "fleet.deployment.status", %{"operation" => operation})["result"]

      if status && status["source"] == source, do: status, else: nil
    end)
  end

  defp poll(what, fun) do
    Enum.reduce_while(1..120, nil, fn _attempt, _acc ->
      case fun.() do
        nil ->
          Process.sleep(25)
          {:cont, nil}

        found ->
          {:halt, found}
      end
    end)
    |> case do
      nil -> flunk("never reached: #{what}")
      found -> found
    end
  end

  # This machine's own profile, which is the closed set a `leave` may name. The shape is
  # `fleet::Profile`'s, cut to what this side reads.
  defp write_profile(root, members) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "profile.json")

    File.write!(
      path,
      JSON.encode!(%{
        "schema" => 2,
        "fleet_id" => "f0000000000000000000000000000000",
        "name" => "home",
        "machine" => "studio",
        "host" => "100.64.0.1",
        "node" => "ouro@100.64.0.1",
        "role" => "core",
        "dist_port" => 13_700,
        "members" => members
      })
    )

    File.chmod!(path, 0o600)
    path
  end

  defp write_journal(root, operation, document) do
    dir = Path.join([root, "deploy"])
    File.mkdir_p!(dir)
    path = Path.join(dir, operation <> ".json")
    File.write!(path, JSON.encode!(document))
    File.chmod!(path, 0o600)
  end
end
