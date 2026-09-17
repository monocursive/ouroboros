defmodule Ouroboros.Fleet.DeploymentTest do
  # `async: false`: every case here moves `config :ouroboros, :data_dir` and the
  # `OUROBOROS_PROCESS_ID_HELPER` environment variable, both of which are node-global, and
  # drives the application's own supervised broker rather than a private copy of it.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Fleet.Deployment.Frame
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher
  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake

  @receive_timeout 5_000
  @devices_fixture "test/support/fixtures/fleet_devices.json"

  setup do
    # Short, because the socket the worker listens on lives under this directory and
    # `sun_path` is 104 bytes on this platform. A long scratch path is the difference
    # between a passing suite and `:enametoolong`.
    root = Path.join(System.tmp_dir!(), "ow2b#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)

    fake_dir = Path.join(root, "bin")

    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
    previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    previous_web = Application.get_env(:ouroboros, :web)

    Application.put_env(:ouroboros, :data_dir, root)

    on_exit(fn ->
      restore(:data_dir, previous_data_dir)
      restore(:web, previous_web)

      if previous_ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      File.rm_rf!(root)
    end)

    %{root: root, fake_dir: fake_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  # ---------------------------------------------------------------------------
  # Seam S1: where `ouro` is

  describe "the launcher seam" do
    test "runs the absolute executable the launcher exported", context do
      ouro = FleetOuroFake.write!(context.fake_dir, devices: ~s({"devices": []}\n))
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

      assert {:ok, output} = Launcher.run(["fleet", "devices", "--json"], 5_000)
      assert output =~ "devices"
      assert FleetOuroFake.argv(context.fake_dir) == ["fleet", "devices", "--json"]
    end

    test "never falls back to PATH, even when the same executable is on it", context do
      ouro = FleetOuroFake.write!(context.fake_dir, devices: ~s({"devices": []}\n))
      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      # The file exists, is executable, is named `ouro`, and its directory is on PATH. The
      # only thing missing is the variable the launcher sets — and that is the whole seam.
      previous_path = System.get_env("PATH")
      System.put_env("PATH", context.fake_dir <> ":" <> (previous_path || ""))
      on_exit(fn -> if previous_path, do: System.put_env("PATH", previous_path) end)

      assert File.stat!(ouro).type == :regular
      assert System.find_executable("ouro") == ouro

      assert {:error, {:ouro_path_unknown, :missing}} =
               Launcher.run(["fleet", "devices", "--json"], 5_000)
    end

    test "refuses a relative path and a symlink", context do
      ouro = FleetOuroFake.write!(context.fake_dir)

      System.put_env("OUROBOROS_PROCESS_ID_HELPER", "bin/ouro")
      assert {:error, {:ouro_path_unknown, :not_absolute}} = Launcher.executable()

      link = Path.join(context.fake_dir, "ouro-link")
      File.ln_s!(ouro, link)
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", link)

      assert {:error, {:ouro_path_unknown, :not_executable_regular_file}} =
               Launcher.executable()
    end

    test "kills the child when the deadline expires rather than waiting for it", context do
      ouro = FleetOuroFake.write!(context.fake_dir, sleep: 5, devices: "{}\n")
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

      started = System.monotonic_time(:millisecond)
      assert {:error, :ouro_timeout} = Launcher.run(["fleet", "devices", "--json"], 300)
      assert System.monotonic_time(:millisecond) - started < 3_000
    end

    test "reports a nonzero exit with its status and bounded output", context do
      ouro = FleetOuroFake.write!(context.fake_dir, exit_status: 3)
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

      assert {:error, {:ouro_failed, 3, _output}} =
               Launcher.run(["fleet", "devices", "--json"], 5_000)
    end
  end

  # ---------------------------------------------------------------------------
  # fleet.devices

  describe "the devices inventory" do
    test "passes the fixture through and adds this host's identity", context do
      arrange_devices(context, File.read!(Path.join(project_root(), @devices_fixture)))

      assert {:ok, inventory} = Deployment.devices()

      assert inventory["fleet_protocol_revision"] == 5
      assert inventory["discovery"]["code"] == "ok"
      assert length(inventory["devices"]) == 5

      states = Enum.map(inventory["devices"], & &1["state"])

      assert states == [
               "this_device_without_profile",
               "discovered_installation_unknown",
               "peer_offline",
               "unsupported_platform",
               "no_usable_ipv4"
             ]

      assert inventory["host"]["hostname"]
      assert inventory["host"]["os"] in ["darwin", "linux", "unix"]
      assert inventory["operations"] == []
    end

    test "names a key it does not read rather than passing it through", context do
      arrange_devices(context, File.read!(Path.join(project_root(), @devices_fixture)))

      assert {:ok, inventory} = Deployment.devices()

      # The fixture's provenance note. It is reported by name and its contents never appear.
      assert inventory["unknown"] == ["_fixture"]
      refute Map.has_key?(inventory, "_fixture")
    end

    test "a runtime with no CA key cannot deploy, and says which reasons apply", context do
      arrange_devices(context, ~s({"devices": []}\n))

      assert {:ok, %{"host" => host}} = Deployment.devices()

      assert host["issuer"] == false
      assert host["capabilities"]["deploy"] == false
      assert "no_ca_key" in host["capabilities"]["reasons"]
    end

    test "a CA key on this machine makes it an issuer, and deploy becomes available",
         context do
      arrange_devices(context, ~s({"devices": []}\n))
      write_ca_key(context.root)

      assert {:ok, %{"host" => host}} = Deployment.devices()

      assert host["issuer"] == true
      assert host["capabilities"] == %{"deploy" => true, "reasons" => []}
    end

    test "a cleartext non-loopback web bind refuses credential entry on this host", context do
      arrange_devices(context, ~s({"devices": []}\n))
      write_ca_key(context.root)

      Application.put_env(:ouroboros, :web,
        enabled: true,
        bind: {10, 0, 0, 5},
        allow_remote: true
      )

      assert {:ok, %{"host" => host}} = Deployment.devices()
      assert host["capabilities"]["deploy"] == false
      assert "cleartext_web_bind" in host["capabilities"]["reasons"]

      # The same endpoint on loopback is the documented remote posture — `tailscale serve`
      # or a reverse proxy in front of it — and the server sees the same loopback peer.
      Application.put_env(:ouroboros, :web, enabled: true, bind: {127, 0, 0, 1})

      assert {:ok, %{"host" => host}} = Deployment.devices()
      assert host["capabilities"]["deploy"] == true
    end

    test "an unknown `ouro` is a named refusal rather than a PATH lookup", _context do
      System.delete_env("OUROBOROS_PROCESS_ID_HELPER")
      assert {:error, {:ouro_path_unknown, :missing}} = Deployment.devices()
    end

    test "output that is not a JSON object is refused", context do
      arrange_devices(context, "not json at all\n")
      assert {:error, :devices_unreadable} = Deployment.devices()
    end

    test "the ten-second ceiling is the broker's, not the command's", context do
      arrange_devices(context, "{}\n", sleep: 5)
      assert {:error, :ouro_timeout} = Deployment.devices(timeout: 250)
    end
  end

  # ---------------------------------------------------------------------------
  # The worker connection

  describe "prepare" do
    test "spawns a worker, attaches with the capability, and answers an operation id",
         context do
      %{worker: worker, ouro_dir: ouro_dir} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())

      assert String.match?(operation, ~r/\A[0-9a-f]{16}\z/)
      assert_receive {:fake_worker, %{"op" => "attach"} = attach}, @receive_timeout
      assert attach["subject"] == "adele"
      assert attach["session"] == "session-one"
      assert FleetWorkerFake.refusals(worker) == 0

      argv = FleetOuroFake.argv(ouro_dir)
      assert ["fleet", "worker", "start", "--operation", ^operation | rest] = argv
      assert "--data-dir" in rest
      assert context.root in rest
    end

    test "the request reaches the worker as argv and carries no credential", context do
      arrange_worker(context)

      assert {:ok, _} =
               Deployment.prepare(
                 %{
                   "target" => %{"address" => "100.64.12.44"},
                   "ssh_user" => "deploy",
                   "port" => 2222,
                   "identity" => %{"kind" => "key", "ref" => "~/.ssh/id_ed25519"},
                   "install_path" => nil,
                   "data_dir" => nil,
                   "service" => true
                 },
                 bound()
               )

      argv = FleetOuroFake.argv(context.fake_dir)
      assert "--request-json" in argv
      request = argv |> Enum.at(Enum.find_index(argv, &(&1 == "--request-json")) + 1)
      decoded = JSON.decode!(request)

      assert decoded["ssh_user"] == "deploy"
      assert decoded["port"] == 2222
      assert decoded["identity"] == %{"kind" => "key", "ref" => "~/.ssh/id_ed25519"}

      # An identity is a reference. Nothing that could be key material is on this argv.
      refute request =~ "BEGIN"
      refute request =~ "secret"
    end

    test "refuses to attach when the worker's instance is not the one that was printed",
         context do
      %{worker: worker, ouro_dir: ouro_dir} = arrange_worker(context)

      FleetOuroFake.put_spawn_line!(
        ouro_dir,
        JSON.encode!(%{
          "socket" => Path.join([context.root, "fleet", "deploy", "w.sock"]),
          "instance" => "0000000000000000"
        }) <> "\n"
      )

      assert {:error, {:attach_failed, :instance_mismatch}} =
               Deployment.prepare(request(), bound())

      # The fake accepted the attach; this runtime is the side that refused it, which is
      # the point of seam S2 — a recycled pid answering on a recycled path is not the
      # worker that was started.
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "refuses a capability file anybody on this machine could read", context do
      arrange_worker(context, cap_mode: 0o644)

      assert {:error, :capability_unusable} = Deployment.prepare(request(), bound())
    end

    test "refuses when the worker has published no capability at all", context do
      arrange_worker(context, cap_mode: nil)

      assert {:error, :capability_missing} = Deployment.prepare(request(), bound())
    end

    test "a worker that prints nothing readable is not connected to", context do
      arrange_worker(context)
      FleetOuroFake.put_spawn_line!(context.fake_dir, "this is not a JSON line\n")

      assert {:error, {:worker_spawn_failed, :unreadable_worker_line}} =
               Deployment.prepare(request(), bound())
    end
  end

  # ---------------------------------------------------------------------------
  # Challenges, and what they are bound to

  describe "challenge binding" do
    setup context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      %{worker: worker, operation: operation}
    end

    test "a password challenge is answered by the session it was issued to", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "ch-1", "password", %{"target" => "build-linux"})
      await_challenge(operation, "ch-1")

      assert {:ok, reply} =
               Deployment.authenticate(operation, "ch-1", "hunter2-unique", bound())

      assert reply["accepted"] == true

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "ch-1"} = frame},
                     @receive_timeout

      assert frame["response"]["secret"] == "hunter2-unique"
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "another session's answer never reaches the worker", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "ch-2", "password")
      await_challenge(operation, "ch-2")

      assert {:error, :challenge_not_bound} =
               Deployment.authenticate(operation, "ch-2", "other-tab-secret", %{
                 subject: "adele",
                 session: "session-two"
               })

      # The same identity in a second browser tab is a different session, and the frame was
      # never written: the fake refuses what it did not expect, and it saw nothing at all.
      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "another identity's answer never reaches the worker either", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "ch-3", "password")
      await_challenge(operation, "ch-3")

      assert {:error, :challenge_not_bound} =
               Deployment.authenticate(operation, "ch-3", "someone-elses-secret", %{
                 subject: "orson",
                 session: "session-one"
               })

      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "an expired challenge is refused", %{worker: worker, operation: operation} do
      past = DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.to_iso8601()
      :ok = FleetWorkerFake.challenge(worker, "ch-4", "password", %{"expires_at" => past})
      await_challenge(operation, "ch-4")

      assert {:error, :challenge_expired} =
               Deployment.authenticate(operation, "ch-4", "too-late", bound())

      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
    end

    test "a challenge is consumed when it is sent, so there is no second guess", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "ch-5", "password")
      await_challenge(operation, "ch-5")

      assert {:ok, _} = Deployment.authenticate(operation, "ch-5", "first-guess", bound())
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      assert {:error, :challenge_consumed} =
               Deployment.authenticate(operation, "ch-5", "second-guess", bound())

      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "a host-trust challenge cannot be answered with a password, or the other way round",
         %{worker: worker, operation: operation} do
      :ok =
        FleetWorkerFake.challenge(worker, "ch-6", "host_trust", %{
          "address" => "100.64.12.44",
          "algorithm" => "ed25519",
          "sha256_fingerprint" => "SHA256:abc"
        })

      await_challenge(operation, "ch-6")

      assert {:error, :challenge_kind_mismatch} =
               Deployment.authenticate(operation, "ch-6", "not-a-host-key", bound())

      assert {:ok, _} = Deployment.confirm_host(operation, "ch-6", true, bound())

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "ch-6"} = frame},
                     @receive_timeout

      assert frame["response"] == %{"accept" => true}
    end

    test "a challenge the worker bound to somebody else is never recorded", %{
      worker: worker,
      operation: operation
    } do
      :ok =
        FleetWorkerFake.challenge(worker, "ch-7", "password", %{
          "bound_to" => %{"subject" => "orson", "session" => "session-nine"}
        })

      Process.sleep(100)

      assert {:ok, snapshot} = Deployment.status(operation)
      assert snapshot["challenges"] == []

      assert {:error, :challenge_not_bound} =
               Deployment.authenticate(operation, "ch-7", "nope", bound())
    end

    test "the worker's own refusal keeps the worker's reason", %{
      worker: worker,
      operation: operation
    } do
      :ok =
        FleetWorkerFake.challenge(worker, "ch-8", "passphrase", %{"key_label" => "id_ed25519"})

      await_challenge(operation, "ch-8")
      :ok = FleetWorkerFake.refuse_next(worker, "passphrase_rejected")

      assert {:error, {:worker_refused, "passphrase_rejected", _detail}} =
               Deployment.authenticate(operation, "ch-8", "wrong-passphrase", bound())
    end
  end

  # ---------------------------------------------------------------------------
  # Disconnects and frame bounds

  describe "a worker that goes away" do
    test "drops the pending challenge, and the next answer is refused", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = FleetWorkerFake.challenge(worker, "ch-drop", "password")
      await_challenge(operation, "ch-drop")

      assert {:ok, client} = Deployment.client(operation)
      reference = Process.monitor(client)
      :ok = FleetWorkerFake.drop_connection(worker)
      assert_receive {:DOWN, ^reference, :process, ^client, _reason}, @receive_timeout

      # The connection died with the challenge on it. The secret has nowhere to go, and
      # nothing about the operation claims otherwise.
      assert {:error, :no_worker} =
               Deployment.authenticate(operation, "ch-drop", "never-sent", bound())
    end

    test "a frame past the cap ends that connection and leaves the broker up", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      broker = Process.whereis(Ouroboros.Fleet.Deployment)
      assert {:ok, client} = Deployment.client(operation)
      reference = Process.monitor(client)

      :ok = FleetWorkerFake.emit_oversize(worker)

      assert_receive {:DOWN, ^reference, :process, ^client, _reason}, @receive_timeout
      assert Process.alive?(broker)
      assert Process.whereis(Ouroboros.Fleet.Deployment) == broker

      # And the broker still answers, which is the part a crash would have taken away.
      assert Deployment.operations(context.root) == []
    end

    test "the frame cap is enforced on the way out as well", _context do
      assert {:error, {:frame_too_large, size}} =
               Frame.encode(%{
                 "v" => 1,
                 "id" => "x",
                 "op" => "respond",
                 "response" => %{
                   "secret" => String.duplicate("x", 1024 * 1024 + 8)
                 }
               })

      assert size > Frame.max_bytes()
    end
  end

  # ---------------------------------------------------------------------------
  # The journal, with no worker

  describe "an interrupted operation" do
    test "status comes from the journal, marked as the journal's", context do
      operation = plant_journal(context.root, "awaiting_auth")

      assert {:ok, snapshot} = Deployment.status(operation)

      assert snapshot["source"] == "journal"
      assert snapshot["attached"] == false
      assert snapshot["state"] == "awaiting_auth"
      assert snapshot["kind"] == "add"
      assert [%{"step" => "inspect", "outcome" => "ok"}] = snapshot["steps"]
    end

    test "a journal field this build does not know is dropped, and so is anything that reads like a credential",
         context do
      operation = random_operation()

      write_journal(context.root, operation, %{
        "operation" => operation,
        "state" => "interrupted",
        "steps" => [%{"step" => "install", "outcome" => "ok", "ssh_password" => "leaked"}],
        "target" => %{"host" => "build-linux", "cookie" => "leaked"},
        "some_future_field" => "leaked"
      })

      assert {:ok, snapshot} = Deployment.status(operation)

      encoded = JSON.encode!(snapshot)
      refute encoded =~ "leaked"
      refute Map.has_key?(snapshot, "some_future_field")
      assert snapshot["target"] == %{"host" => "build-linux"}
    end

    test "an operation nobody started is not found", _context do
      assert {:error, :unknown_operation} = Deployment.status(random_operation())
    end

    test "an operation id that is not an operation id is refused before any path is built",
         _context do
      for candidate <- ["../../etc/passwd", "a/b", "", "NOT-HEX", String.duplicate("a", 65)] do
        assert {:error, :invalid_operation} = Deployment.status(candidate),
               "#{inspect(candidate)} must not be accepted as an operation id"
      end
    end

    test "the operations listing names every journal, readable or not", context do
      readable = plant_journal(context.root, "interrupted")
      broken = random_operation()
      File.write!(Journal.path(context.root, broken), "{ this is not json")

      listed = Deployment.operations(context.root)

      assert Enum.find(listed, &(&1["operation"] == readable))["readable"] == true
      assert Enum.find(listed, &(&1["operation"] == readable))["attached"] == false

      unreadable = Enum.find(listed, &(&1["operation"] == broken))
      assert unreadable["readable"] == false
      assert unreadable["reason"] == "journal_unreadable"
    end
  end

  describe "resume" do
    test "spawns a new worker for an interrupted operation", context do
      operation = plant_journal(context.root, "interrupted")
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => ^operation}} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      assert FleetWorkerFake.refusals(worker) == 0

      assert {:ok, snapshot} = Deployment.status(operation)
      assert snapshot["source"] == "worker"
      assert snapshot["attached"] == true
    end

    test "refuses an operation that already has a worker", context do
      operation = plant_journal(context.root, "interrupted")
      arrange_worker(context)

      assert {:ok, _} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      assert {:error, :already_attached} = Deployment.resume(operation, bound())
    end

    test "refuses a finished operation and one whose journal records no state", context do
      finished = plant_journal(context.root, "completed")
      arrange_worker(context)

      assert {:error, :operation_finished} = Deployment.resume(finished, bound())

      stateless = random_operation()
      write_journal(context.root, stateless, %{"operation" => stateless, "kind" => "add"})
      assert {:error, :operation_state_unknown} = Deployment.resume(stateless, bound())
    end
  end

  describe "cancel" do
    test "reaches the worker and reports its residue", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      assert {:ok, reply} = Deployment.cancel(operation)
      assert reply["cancelled"] == true
      assert reply["residue"] == []

      assert_receive {:fake_worker, %{"op" => "cancel"}}, @receive_timeout
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "an operation with no worker cannot be cancelled through one", context do
      operation = plant_journal(context.root, "interrupted")
      assert {:error, :no_worker} = Deployment.cancel(operation)
    end
  end

  describe "start" do
    setup context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      %{worker: worker, operation: operation}
    end

    test "answers the review challenge with the digest that was reviewed", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "review-1", "review", %{"plan" => %{"steps" => []}})
      await_challenge(operation, "review-1")

      assert {:ok, _} = Deployment.start(operation, "sha-of-the-plan", "key-1", bound())

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "review-1"} = frame},
                     @receive_timeout

      assert frame["response"] == %{"approve" => true, "plan_digest" => "sha-of-the-plan"}
    end

    test "the same idempotency key replays without touching the worker again", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "review-2", "review", %{})
      await_challenge(operation, "review-2")

      assert {:ok, first} = Deployment.start(operation, "sha", "key-2", bound())
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      assert {:ok, ^first} = Deployment.start(operation, "sha", "key-2", bound())
      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
    end

    test "a different key against a running operation is refused", %{
      worker: worker,
      operation: operation
    } do
      :ok = FleetWorkerFake.challenge(worker, "review-3", "review", %{})
      await_challenge(operation, "review-3")

      assert {:ok, _} = Deployment.start(operation, "sha", "key-a", bound())
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      assert {:error, :operation_in_progress} =
               Deployment.start(operation, "sha", "key-b", bound())
    end

    test "an operation with no plan waiting cannot be started", %{operation: operation} do
      assert {:error, :no_review_pending} =
               Deployment.start(operation, "sha", "key-none", bound())
    end
  end

  describe "events" do
    test "reach a subscriber and stop when it goes away", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = Deployment.subscribe(operation)
      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "awaiting_auth"})

      assert_receive {:ouroboros_fleet_deployment, ^operation,
                      %{"event" => "state", "state" => "awaiting_auth"}},
                     @receive_timeout

      assert {:ok, %{"state" => "awaiting_auth"}} = Deployment.status(operation)

      :ok = Deployment.unsubscribe(operation)
      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "deploying"})
      refute_receive {:ouroboros_fleet_deployment, ^operation, _event}, 300
    end

    test "a worker event carrying something that reads like a credential is scrubbed",
         context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = Deployment.subscribe(operation)

      :ok =
        FleetWorkerFake.emit(worker, %{
          "event" => "log",
          "line" => "connecting to build-linux",
          "ssh_password" => "should-never-be-here"
        })

      assert_receive {:ouroboros_fleet_deployment, ^operation, event}, @receive_timeout
      assert event["line"] == "connecting to build-linux"
      refute Map.has_key?(event, "ssh_password")

      assert {:ok, snapshot} = Deployment.status(operation)
      refute JSON.encode!(snapshot) =~ "should-never-be-here"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

  defp bound, do: %{subject: "adele", session: "session-one"}

  defp request do
    %{
      "target" => %{"address" => "100.64.12.44"},
      "ssh_user" => "deploy",
      "port" => 22,
      "identity" => nil,
      "install_path" => nil,
      "data_dir" => nil,
      "service" => true
    }
  end

  defp arrange_devices(context, document, opts \\ []) do
    ouro = FleetOuroFake.write!(context.fake_dir, [devices: document] ++ opts)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    ouro
  end

  # Starts the fake worker, then writes a fake `ouro` that hands the broker that worker's
  # socket and instance and writes the capability file for whatever operation id the broker
  # mints. Both halves of seam S2 are real here: the executable and the socket.
  defp arrange_worker(context, opts \\ []) do
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    socket_path = Path.join([context.root, "fleet", "deploy", "w.sock"])

    assert byte_size(socket_path) < 104,
           "the fixture's socket path is longer than sun_path: #{socket_path}"

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
      FleetOuroFake.write!(
        context.fake_dir,
        Keyword.merge(
          [
            spawn_line: FleetWorkerFake.spawn_line(worker),
            cap: cap
          ],
          opts
        )
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    %{worker: worker, ouro: ouro, ouro_dir: context.fake_dir, cap: cap, instance: instance}
  end

  defp await_challenge(operation, id) do
    Enum.reduce_while(1..50, :missing, fn _attempt, _acc ->
      case Deployment.status(operation) do
        {:ok, %{"challenges" => challenges}} ->
          if Enum.any?(challenges, &(&1["challenge"] == id)) do
            {:halt, :ok}
          else
            Process.sleep(20)
            {:cont, :missing}
          end

        _other ->
          Process.sleep(20)
          {:cont, :missing}
      end
    end)
    |> case do
      :ok -> :ok
      :missing -> flunk("the broker never recorded challenge #{id}")
    end
  end

  defp random_operation, do: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  defp plant_journal(root, state) do
    operation = random_operation()

    write_journal(root, operation, %{
      "operation" => operation,
      "kind" => "add",
      "state" => state,
      "created_at" => "2026-09-17T10:00:00Z",
      "updated_at" => "2026-09-17T10:05:00Z",
      "target" => %{"hostname" => "build-linux", "address" => "100.64.12.44", "port" => 22},
      "steps" => [%{"step" => "inspect", "outcome" => "ok", "at" => "2026-09-17T10:01:00Z"}]
    })

    operation
  end

  defp write_journal(root, operation, document) do
    dir = Journal.deploy_dir(root)
    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    path = Journal.path(root, operation)
    File.write!(path, JSON.encode!(document))
    File.chmod!(path, 0o600)
    path
  end

  defp write_ca_key(root) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "ca-key.pem")
    File.write!(path, "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n")
    File.chmod!(path, 0o600)
    path
  end

  defp project_root, do: File.cwd!()
end
