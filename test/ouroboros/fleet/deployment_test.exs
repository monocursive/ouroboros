defmodule Ouroboros.Fleet.DeploymentTest do
  # `async: false`: every case here moves `config :ouroboros, :data_dir` and the
  # `OUROBOROS_PROCESS_ID_HELPER` environment variable, both of which are node-global, and
  # drives the application's own supervised broker rather than a private copy of it.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  import ExUnit.CaptureLog

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

    # An `add` needs this host to be able to issue a member certificate, and `prepare` now
    # enforces that rather than only reporting it. These suites deploy onto other machines,
    # so they are issuers.
    File.mkdir_p!(Path.join(root, "fleet"))
    ca = Path.join([root, "fleet", "ca-key.pem"])
    File.write!(ca, "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n")
    File.chmod!(ca, 0o600)

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

      # `prepare` requires a machine name and will not invent one, so the name a surface
      # offers has to survive this trip verbatim. Every row carries one — the Rust side
      # slugs the display name whatever the state — and a row nothing can be deployed to
      # simply has nothing to do with it.
      assert Enum.map(inventory["devices"], & &1["suggested_machine"]) == [
               "operator-laptop",
               "build-linux",
               "old-pi",
               "pocket-phone",
               "ipv6-only-box"
             ]

      for device <- inventory["devices"],
          do: assert(Map.has_key?(device, "suggested_machine"))
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

      # The suite's setup makes this host an issuer, because almost every case here deploys
      # onto another machine. This one is about the machine that cannot.
      File.rm!(Path.join([context.root, "fleet", "ca-key.pem"]))

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

    test "the argv carries only the operation id and the data directory", context do
      arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Deployment.prepare(detailed_request(), bound())

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      argv = FleetOuroFake.argv(context.fake_dir)

      # `ps` is readable by every local account on both platforms this ships to. A target
      # hostname and an SSH account name are not secrets in the sense the spec's one list
      # means, but publishing them to every shell on the box buys nothing, so the command
      # line is the operation and the directory and nothing else.
      assert argv ==
               ["fleet", "worker", "start", "--operation", operation, "--data-dir", context.root]
    end

    test "the request reaches the worker as a private file it then unlinks", context do
      arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Deployment.prepare(detailed_request(), bound())

      # What the worker actually saw: a 0600 file, whole, with the request in it.
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      body = FleetOuroFake.request_body(context.fake_dir)
      assert FleetOuroFake.request_mode(context.fake_dir) == "600"
      decoded = JSON.decode!(body)

      assert decoded["ssh_user"] == "deploy"
      assert decoded["ssh_port"] == 2222
      assert decoded["identity"] == %{"kind" => "key", "path" => "~/.ssh/id_ed25519"}
      assert decoded["address"] == "100.64.12.44"
      assert decoded["machine"] == "build-linux"

      # Stamped by the launcher, which is the only thing that knows both: the id was minted
      # a moment earlier, and the schema is a fact about the wire.
      assert decoded["operation"] == operation
      assert decoded["schema"] == 1

      # An identity is a reference. Nothing that could be key material is in this file.
      refute body =~ "BEGIN"
      refute body =~ "secret"

      # Canonical: sorted keys, no whitespace, so the same request twice is the same bytes.
      assert body == JSON.encode!(JSON.decode!(body)) |> canonical_of()
      assert String.starts_with?(body, ~s({"address":))

      # And it is the worker's to consume: gone once the launch succeeded.
      refute File.exists?(Journal.request_path(context.root, operation))
    end

    test "a file the worker never read is left for it, not reclaimed", context do
      arrange_worker(context, keep_request: true)

      assert {:ok, %{"operation_id" => operation}} =
               Deployment.prepare(detailed_request(), bound())

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      # The launch succeeded, so the request belongs to the worker even if it has not got
      # to it yet. A broker that tidied here would be racing the process it just started.
      path = Journal.request_path(context.root, operation)

      assert File.exists?(path)

      assert File.stat!(Journal.request_path(context.root, operation)).mode |> Bitwise.band(0o777) ==
               0o600
    end

    test "a launch that fails leaves no request behind", context do
      arrange_worker(context, exit_status: 3, keep_request: true)

      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Deployment.prepare(detailed_request(), bound())

      assert {:attach_failed, {:worker_spawn_failed, {:ouro_failed, 3, _output}}} =
               await_error(operation)

      # Nothing is coming to read it, so the launcher takes it back. The deploy directory
      # holds no request file at all afterwards.
      deploy = Journal.deploy_dir(context.root)
      assert File.ls!(deploy) |> Enum.filter(&String.ends_with?(&1, ".request.json")) == []
    end

    test "a resume writes no request at all", context do
      operation = plant_journal(context.root, "interrupted")
      arrange_worker(context, keep_request: true)

      assert {:ok, _} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      # The worker already has its journal. Re-stating a target here would be a second
      # chance to state a different one.
      refute File.exists?(Journal.request_path(context.root, operation))
      assert FleetOuroFake.request_body(context.fake_dir) == nil

      assert FleetOuroFake.argv(context.fake_dir) ==
               ["fleet", "worker", "start", "--operation", operation, "--data-dir", context.root]
    end

    test "refuses to attach when the worker's instance is not the one that was printed",
         context do
      %{worker: worker, ouro_dir: ouro_dir} = arrange_worker(context)

      FleetOuroFake.put_spawn_line!(
        ouro_dir,
        JSON.encode!(%{
          "socket" => Path.join([context.root, "deploy", "w.sock"]),
          "instance" => "0000000000000000"
        }) <> "\n"
      )

      # `prepare` answers as soon as the process exists — the handshake is no longer run
      # inside the broker's call — so the refusal arrives as the operation's state rather
      # than as this call's return.
      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Deployment.prepare(request(), bound())

      assert await_error(operation) == {:attach_failed, :instance_mismatch}

      # The fake accepted the attach; this runtime is the side that refused it, which is
      # the point of seam S2 — a recycled pid answering on a recycled path is not the
      # worker that was started.
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "refuses a capability file anybody on this machine could read", context do
      arrange_worker(context, cap_mode: 0o644)

      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Deployment.prepare(request(), bound())

      assert {:attach_failed, :capability_unusable} = await_error(operation)
    end

    test "refuses when the worker has published no capability at all", context do
      arrange_worker(context, cap_mode: nil)

      # Retried for a bounded moment first — the capability and the socket are written in an
      # order this side does not control — and the refusal carries the worker's own log, which
      # is the only place the reason for it can be.
      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Deployment.prepare(request(), bound())

      assert {:attach_failed, {:capability_missing, detail}} = await_error(operation)
      assert detail =~ ".log"
    end

    test "a worker that prints nothing readable is not connected to", context do
      arrange_worker(context)
      FleetOuroFake.put_spawn_line!(context.fake_dir, "this is not a JSON line\n")

      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Deployment.prepare(request(), bound())

      assert {:attach_failed, {:worker_spawn_failed, :unreadable_worker_line}} =
               await_error(operation)
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

      assert {:ok, snapshot} = Deployment.status(operation, bound())
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
      assert Deployment.operations(context.root) == {[], 0}
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

      assert {:ok, snapshot} = Deployment.status(operation, bound())

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

      assert {:ok, snapshot} = Deployment.status(operation, bound())

      encoded = JSON.encode!(snapshot)
      refute encoded =~ "leaked"
      refute Map.has_key?(snapshot, "some_future_field")
      assert snapshot["target"] == %{"host" => "build-linux"}
    end

    test "an operation nobody started is not found", _context do
      assert {:error, :unknown_operation} = Deployment.status(random_operation(), bound())
    end

    test "an operation id that is not an operation id is refused before any path is built",
         _context do
      for candidate <- ["../../etc/passwd", "a/b", "", "NOT-HEX", String.duplicate("a", 65)] do
        assert {:error, :invalid_operation} = Deployment.status(candidate, bound()),
               "#{inspect(candidate)} must not be accepted as an operation id"
      end
    end

    test "past the cap, the newest are kept rather than the lexically smallest", context do
      # Operation ids are random hex. Sorting the *file names* and taking the first 200 read
      # an arbitrary sample of every operation this machine had ever run and presented it as
      # the current ones — so this plants ids whose lexical order is the reverse of their
      # ages, which is the case that told the two apart.
      total = 220

      newest =
        for index <- 1..total do
          # `f…` sorts last and is oldest; `0…` sorts first and is newest.
          operation =
            (index
             |> Integer.to_string(16)
             |> String.downcase()
             |> String.pad_leading(15, "0")) <>
              if(index <= 20, do: "f", else: "0")

          created =
            "2026-09-#{String.pad_leading(Integer.to_string(rem(index, 28) + 1), 2, "0")}T" <>
              "#{String.pad_leading(Integer.to_string(rem(index, 24)), 2, "0")}:00:00Z"

          write_journal(context.root, operation, %{
            "operation" => operation,
            "owner" => "adele",
            "kind" => "add",
            "state" => "interrupted",
            "created_at" => created
          })

          case DateTime.from_iso8601(created) do
            {:ok, datetime, _offset} ->
              File.touch!(Journal.path(context.root, operation), DateTime.to_unix(datetime))

            _unreadable ->
              :ok
          end

          {created, operation}
        end
        |> Enum.sort(:desc)
        |> Enum.take(200)
        |> Enum.map(&elem(&1, 1))

      {listed, reported} = Deployment.operations(context.root)

      assert reported == total, "the total must count what was cut, not what was kept"
      assert length(listed) == 200
      assert Enum.map(listed, & &1["operation"]) == newest
    end

    test "the operations listing names every journal, readable or not", context do
      readable = plant_journal(context.root, "interrupted")
      broken = random_operation()
      File.write!(Journal.path(context.root, broken), "{ this is not json")

      {listed, total} = Deployment.operations(context.root)
      assert total == 2

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

      assert {:ok, snapshot} = Deployment.status(operation, bound())
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

      assert {:ok, reply} = Deployment.cancel(operation, bound())
      assert reply["cancelled"] == true
      assert reply["residue"] == []

      assert_receive {:fake_worker, %{"op" => "cancel"}}, @receive_timeout
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "an operation with no worker cannot be cancelled through one", context do
      operation = plant_journal(context.root, "interrupted")
      assert {:error, :no_worker} = Deployment.cancel(operation, bound())
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
    test "a session can stop and restart event delivery without dropping its presence", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = Deployment.subscribe(operation, "events-tab")
      settle(operation)
      :ok = Deployment.unsubscribe(operation)
      settle(operation)
      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "awaiting_auth"})
      refute_receive {:ouroboros_fleet_deployment, ^operation, _event}, 300

      :ok = Deployment.subscribe(operation, "events-tab")
      settle(operation)
      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "deploying"})

      assert_receive {:ouroboros_fleet_deployment, ^operation,
                      %{"event" => "state", "state" => "deploying"}},
                     @receive_timeout
    end

    test "reach a subscriber and stop when it goes away", context do
      %{worker: worker} = arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = Deployment.subscribe(operation)
      :ok = FleetWorkerFake.emit(worker, %{"event" => "state", "state" => "awaiting_auth"})

      assert_receive {:ouroboros_fleet_deployment, ^operation,
                      %{"event" => "state", "state" => "awaiting_auth"}},
                     @receive_timeout

      assert {:ok, %{"state" => "awaiting_auth"}} = Deployment.status(operation, bound())

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

      assert {:ok, snapshot} = Deployment.status(operation, bound())
      refute JSON.encode!(snapshot) =~ "should-never-be-here"
    end
  end

  # ---------------------------------------------------------------------------
  # A challenge's session binding may not outlive the session

  describe "a session that goes away" do
    setup context do
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), tab("a"))
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      # The shape the web surface has: one process per browser tab, subscribed to the
      # operation under that tab's id, which is what a credential challenge binds to.
      tab_a = subscriber(operation, "tab-a")

      :ok = FleetWorkerFake.challenge(worker, "rev", "review", %{"plan" => %{"steps" => []}})
      await_challenge(operation, "rev", tab("a"))

      Map.merge(context, %{worker: worker, operation: operation, tab_a: tab_a})
    end

    test "lets the surviving tab answer the prompts that come after the one it took over", %{
      operation: operation,
      tab_a: tab_a,
      worker: worker
    } do
      # The live reproduction, which the first release did not cover. A removal asks twice:
      # the review, and then the password for the member being removed. Releasing only the
      # challenge that was open let tab B press Remove and then refused it the password,
      # because the connection was still stamping every new challenge with tab A.
      close(tab_a)
      settle(operation)

      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "rev"}},
                     @receive_timeout

      # Step two: the worker asks for the password *after* the tab that started this was
      # already gone.
      :ok = FleetWorkerFake.challenge(worker, "pw", "password", %{"attempt" => 1})
      await_challenge(operation, "pw", tab("b"))

      assert {:ok, %{"accepted" => true}} =
               Deployment.authenticate(operation, "pw", "typed-in-the-second-tab", tab("b"))

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"]["secret"] == "typed-in-the-second-tab"
      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "binds to the tab that took over, so a third tab is a second tab again", %{
      operation: operation,
      tab_a: tab_a,
      worker: worker
    } do
      close(tab_a)
      settle(operation)

      # Tab B answers, and in doing so says it is the tab holding this operation now.
      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "rev"}},
                     @receive_timeout

      :ok = FleetWorkerFake.challenge(worker, "pw", "password", %{"attempt" => 1})
      await_challenge(operation, "pw", tab("b"))

      # So the window the release opened is shut again: the next prompt is tab B's, not
      # every tab this administrator has.
      assert {:error, :challenge_not_bound} =
               Deployment.authenticate(operation, "pw", "from-a-third-tab", tab("c"))

      refute_receive {:fake_worker, %{"op" => "respond"}}, 300

      assert {:ok, %{"accepted" => true}} =
               Deployment.authenticate(operation, "pw", "from-the-tab-that-took-over", tab("b"))
    end

    test "keeps the binding while a second process still speaks for that session", %{
      operation: operation,
      tab_a: tab_a
    } do
      # The reconnect a LiveView does: the browser drops the socket, the new one mounts under
      # the *same* tab id and subscribes, and only then does the old process's `:DOWN` land.
      # For that moment two subscribers name session A, and releasing on the first of them to
      # die would hand a live tab's prompt to any other tab this administrator has open.
      #
      # Mutating the `Enum.any?` guard in `release_session/2` away passed every other case
      # here, because every other case has exactly one subscriber per session.
      tab_a_again = subscriber(operation, "tab-a")
      unsubscribe(tab_a_again, operation)

      close(tab_a)
      settle(operation)

      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      # The tab that is still there answers, which is what says the refusal above was the
      # binding holding rather than the challenge having gone.
      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-a", tab("a"))

      # And when the last one goes, it releases as it always did.
      close(tab_a_again)
      settle(operation)
    end

    test "leaves the prompt alone while that tab is still there", %{operation: operation} do
      # This is the property the binding exists for and the one this change must not undo: a
      # second tab open at the same time is not the tab that was asked.
      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-live", tab("b"))

      # And the tab it was issued to still answers, which is what says the refusal above was
      # about the session rather than about the challenge.
      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-a", tab("a"))
    end

    test "unbinds the prompt when the tab is closed, so the next one can answer it", %{
      operation: operation,
      tab_a: tab_a,
      worker: worker
    } do
      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-early", tab("b"))

      close(tab_a)
      settle(operation)

      # Same person, another tab. The operation is not stranded behind a prompt bound to a
      # browser tab that no longer exists.
      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      assert_receive {:fake_worker, %{"op" => "respond", "challenge" => "rev"}},
                     @receive_timeout

      assert FleetWorkerFake.refusals(worker) == 0
    end

    test "unbinds the session and not the identity", %{operation: operation, tab_a: tab_a} do
      close(tab_a)
      settle(operation)

      # A second administrator is exactly what the identity half of the binding is for, and
      # it does not lapse with a tab: `resume` with `takeover` is still the only way in.
      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-bruno", %{
                 subject: "bruno",
                 session: "tab-b"
               })

      # And the prompt is still there for the operator it belongs to.
      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-b", tab("b"))
    end

    test "releases a password prompt too, and it is still answerable exactly once", %{
      operation: operation,
      tab_a: tab_a,
      worker: worker
    } do
      # The kind with a secret on it. Nothing of the credential is in play here — the tab
      # that was asked never typed one, and the worker is still waiting — so there is no
      # unconsumed secret to strand and every reason to let the operator answer from the
      # tab they still have.
      :ok = FleetWorkerFake.challenge(worker, "pw", "password", %{"attempt" => 1})
      await_challenge(operation, "pw", tab("a"))

      close(tab_a)
      settle(operation)

      assert {:ok, %{"accepted" => true}} =
               Deployment.authenticate(operation, "pw", "typed-in-the-second-tab", tab("b"))

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"]["secret"] == "typed-in-the-second-tab"

      # Releasing the session does not release the once-only rule.
      assert {:error, :challenge_consumed} =
               Deployment.authenticate(operation, "pw", "a-second-guess", tab("c"))
    end

    test "says which challenge it unbound, and says it once", %{
      operation: operation,
      tab_a: tab_a
    } do
      log =
        capture_log(fn ->
          close(tab_a)
          settle(operation)
        end)

      assert log =~ "fleet deployment challenge operation=#{operation}"
      assert log =~ "challenge=rev"
      assert log =~ "outcome=session_released"
    end

    test "an unsubscribe retains the binding only until the tab goes away", %{
      operation: operation,
      tab_a: tab_a
    } do
      # A page that unsubscribed is a page that is still there and can subscribe again — a
      # closed drawer, not a closed tab. Only a dead process is evidence that nobody is left
      # to answer.
      unsubscribe(tab_a, operation)
      settle(operation)

      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      close(tab_a)
      settle(operation)

      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-after-close", tab("b"))
    end

    test "a subscriber that named no session releases nothing", %{
      operation: operation,
      tab_a: tab_a
    } do
      # The listener's shape: a connection subscribes without a per-tab id. Its going away
      # says nothing about which session may answer, so nothing is released — including by
      # the tab that is still open beside it.
      anonymous = subscriber(operation, nil)
      close(anonymous)
      settle(operation)

      assert {:error, :challenge_not_bound} =
               Deployment.start(operation, "digest", "key-b", tab("b"))

      # And the tab that did name one still releases when *it* goes.
      close(tab_a)
      settle(operation)

      assert {:ok, %{"accepted" => true}} =
               Deployment.start(operation, "digest", "key-b2", tab("b"))
    end
  end

  # ---------------------------------------------------------------------------
  # Spawn does not stall the broker; a timeout does not discard the request

  describe "an asynchronous spawn" do
    test "does not stall fleet.devices or operations/1 behind a slow launcher", context do
      arrange_worker(context, spawn_sleep: 3)

      parent = self()

      _preparer =
        spawn(fn ->
          send(parent, {:prepared, Deployment.prepare(request(), bound())})
        end)

      Process.sleep(150)
      started = System.monotonic_time(:millisecond)
      assert {:ok, _inventory} = Deployment.devices()
      {_summaries, _total} = Deployment.operations(context.root)
      elapsed = System.monotonic_time(:millisecond) - started

      assert elapsed < 400, "devices/operations waited #{elapsed} ms behind a 3s spawn"
      assert_receive {:prepared, {:ok, %{"state" => "spawning"}}}, 1_000
    end

    test "a second resume cannot stall unrelated reads behind the client's slow spawn",
         context do
      arrange_worker(context, spawn_sleep: 3)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      resumer = Task.async(fn -> Deployment.resume(operation, bound()) end)

      Process.sleep(100)
      started = System.monotonic_time(:millisecond)
      assert {:ok, _inventory} = Deployment.devices()
      {_summaries, _total} = Deployment.operations(context.root)
      elapsed = System.monotonic_time(:millisecond) - started

      assert elapsed < 1_000, "devices/operations waited #{elapsed} ms behind another resume"
      assert {:error, :already_attached} = Task.await(resumer, @receive_timeout)
    end

    test "a spawn timeout does not unlink the request the grandchild may still be reading",
         context do
      ouro =
        FleetOuroFake.write!(context.fake_dir,
          spawn_sleep: 5,
          spawn_line: "{}\n",
          cap: nil
        )

      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
      operation = random_operation()

      assert {:error, {:worker_spawn_failed, :ouro_timeout}} =
               Launcher.spawn_worker(operation, context.root, request(), 300)

      assert File.exists?(Journal.request_path(context.root, operation)),
             "a spawn timeout deleted the request a detached worker may still be reading"
    end

    test "a canary environment variable does not reach the child", context do
      ouro = FleetOuroFake.write!(context.fake_dir, devices: ~s({"devices": []}\n))
      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
      System.put_env("FLEET_CANARY_SECRET", "should-never-reach-the-worker")

      on_exit(fn -> System.delete_env("FLEET_CANARY_SECRET") end)

      assert {:ok, _output} = Launcher.run(["fleet", "devices", "--json"], 5_000)
      env = FleetOuroFake.env(context.fake_dir)
      refute env =~ "FLEET_CANARY_SECRET"
      assert env =~ "PATH="
    end
  end

  describe "journal listing and retention" do
    test "an unchanged file is not parsed again", context do
      operation = plant_journal(context.root, "completed")
      path = Journal.path(context.root, operation)
      {first, 1, cache} = Journal.list(context.root)
      {:ok, %File.Stat{mtime: mtime, size: size}} = File.lstat(path)

      File.write!(path, String.duplicate("x", size))
      File.touch!(path, unix_stat_mtime(mtime))
      {second, 1, _cache} = Journal.list(context.root, cache)

      assert hd(first)["readable"] == true
      assert second == first
    end

    test "completed and cancelled journals older than 30 days are pruned, failed are kept",
         context do
      old = DateTime.to_unix(~U[2020-01-01 00:00:00Z])
      now = DateTime.to_unix(~U[2026-09-17 00:00:00Z])

      completed = plant_journal(context.root, "completed")
      cancelled = plant_journal(context.root, "cancelled")
      failed = plant_journal(context.root, "failed")
      interrupted = plant_journal(context.root, "interrupted")

      File.touch!(Journal.path(context.root, completed), old)
      File.touch!(Journal.path(context.root, cancelled), old)
      File.touch!(Journal.path(context.root, failed), old)
      File.touch!(Journal.path(context.root, interrupted), old)

      request = Journal.request_path(context.root, interrupted)
      File.write!(request, "{}")

      Journal.prune(context.root, now: now, attached: [])

      refute File.exists?(Journal.path(context.root, completed))
      refute File.exists?(Journal.path(context.root, cancelled))
      assert File.exists?(Journal.path(context.root, failed))
      assert File.exists?(Journal.path(context.root, interrupted))
      assert File.exists?(request)
    end

    test "keeps the newest 50 terminal records and skips a live client", context do
      now = System.system_time(:second)

      ids =
        Enum.map(1..55, fn n ->
          operation = plant_journal(context.root, "completed")
          File.touch!(Journal.path(context.root, operation), now - n)
          operation
        end)

      attached = List.last(ids)
      Journal.prune(context.root, now: now, attached: [attached])

      remaining =
        File.ls!(Journal.deploy_dir(context.root))
        |> Enum.filter(&String.ends_with?(&1, ".json"))
        |> Enum.reject(&String.ends_with?(&1, ".request.json"))

      assert length(remaining) == 51
      assert (attached <> ".json") in remaining
    end
  end

  # ---------------------------------------------------------------------------
  # What a worker that died before it could say anything left behind

  describe "the worker log's line sanitiser" do
    @escape <<0x1B>>
    @bell <<0x07>>

    test "strips escape sequences whole, so a worker cannot paint its own sentence" do
      # `String.printable?/1` counts `\e` as printable, which is how this went through
      # untouched: an operator reading the tail in a terminal saw a sentence in a colour the
      # worker chose, next to the sentences this build wrote.
      assert Journal.scrub_line("worker died #{@escape}[1;31mSPOOFED#{@escape}[0m", 300) ==
               "worker died SPOOFED"

      # An operating-system command — a window title, and everything up to its terminator.
      assert Journal.scrub_line("title #{@escape}]0;evil#{@bell}after", 300) == "title after"

      # A two-character escape with no sequence after it, and the eight-bit CSI that skips
      # the escape prefix altogether: the byte a terminal would act on is gone either way.
      assert Journal.scrub_line("reset#{@escape}c done", 300) == "reset done"
      refute Journal.scrub_line("eight bit #{<<0xC2, 0x9B>>}mSPOOFED", 300) =~ <<0xC2, 0x9B>>
    end

    test "strips C0, DEL and C1 but keeps a tab" do
      assert Journal.scrub_line("bell#{@bell}and#{<<0x08>>}back", 300) == "bellandback"
      assert Journal.scrub_line("del#{<<0x7F>>}ete", 300) == "delete"
      assert Journal.scrub_line("c1#{<<0xC2, 0x85>>}next", 300) == "c1next"

      # A tab is layout, not control, and a log tail that loses its columns is harder to
      # read rather than safer.
      assert Journal.scrub_line("keep\ta tab", 300) == "keep\ta tab"
    end

    test "discards credential-bearing diagnostics regardless of value quoting" do
      for line <- [
            "ssh_password=hunter2 was passed",
            "ssh --password hunter2 host",
            "sshpass -p hunter2 ssh deploy@host",
            "sshpass -phunter2 ssh deploy@host",
            "echo hunter2 | sudo -S systemctl restart ouro",
            ~s(password="alpha beta"),
            ~s(password='alpha beta'),
            ~s(password="alpha beta),
            ~S(password=alpha\ beta),
            ~s({"password":"alpha-beta"}),
            ~s(error: {"ssh_password": "alpha beta", "status": "failed"}),
            ~S({"token":"alpha \"beta\" gamma"}),
            ~s({'private_key': 'alpha beta'}),
            ~s(ssh --password "alpha beta" host),
            ~s(sshpass -p "alpha beta" ssh host),
            ~s(sshpass -p'alpha beta' ssh host),
            ~s(printf '%s' 'alpha beta' | sudo -S command)
          ] do
        assert Journal.scrub_line(line, 300) == "[redacted credential-bearing diagnostic]"
      end
    end

    test "leaves an ordinary diagnostic alone, which is the whole point of showing it" do
      for line <- [
            "connecting to 100.64.12.44 port 22",
            "bind: path is 112 bytes, the limit is 104",
            "ssh: debug1: reading configuration data /etc/ssh/ssh_config",
            "echo done | tee /tmp/x",
            "password authentication failed"
          ] do
        assert Journal.scrub_line(line, 300) == line
      end
    end
  end

  describe "worker_exit" do
    test "an unfinished journal carries the last three sanitized lines of the worker's log",
         context do
      operation = plant_journal(context.root, "inspecting")

      write_worker_log(context.root, operation, [
        "connecting to 100.64.12.44",
        "",
        "ssh: debug1: reading configuration",
        "   ",
        "ssh_password=hunter2 was passed to the child",
        "error: socket path /very/long/path.sock is #{String.duplicate("x", 600)} bytes"
      ])

      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert snapshot["source"] == "journal"
      assert [first, second, third] = snapshot["worker_exit"]["last_lines"]

      # Blank lines are not evidence, so they are not three of the three.
      assert first == "ssh: debug1: reading configuration"

      # The log is whatever the worker printed, and a worker that printed a password is a
      # worker bug that must not become a browser's problem. The whole line is replaced.
      assert second == "[redacted credential-bearing diagnostic]"
      refute second =~ "hunter2"

      # And a line nobody bounded is bounded here: 300 characters, not 600.
      assert String.length(third) == 300
      assert String.starts_with?(third, "error: socket path")
    end

    test "JSON and quoted secrets never reach the public worker log tail", context do
      operation = plant_journal(context.root, "inspecting")

      write_worker_log(context.root, operation, [
        ~s({"password":"alpha-beta"}),
        ~s(password="alpha beta"),
        ~s(sshpass -p "alpha beta" ssh host)
      ])

      assert {:ok, snapshot} = Deployment.status(operation, bound())

      assert snapshot["worker_exit"]["last_lines"] ==
               List.duplicate("[redacted credential-bearing diagnostic]", 3)
    end

    test "a truncated credential line is discarded without hiding complete diagnostics",
         context do
      operation = plant_journal(context.root, "inspecting")
      secret_line = "password=" <> String.duplicate("S", 9_000)

      for {suffix, expected} <- [
            {"", []},
            {"\nssh: connection closed\n", ["ssh: connection closed"]}
          ] do
        File.write!(Journal.log_path(context.root, operation), secret_line <> suffix)
        assert {:ok, snapshot} = Deployment.status(operation, bound())
        assert snapshot["worker_exit"]["last_lines"] == expected
      end
    end

    test "a worker log that is not text, and one that is enormous, are both answers",
         context do
      operation = plant_journal(context.root, "installing")

      # 64 KiB of padding, so only the tail is ever read, and a final line whose bytes are
      # not UTF-8 at all.
      File.write!(Journal.log_path(context.root, operation), [
        String.duplicate("padding line\n", 5_000),
        "the last readable line\n",
        <<0xFF, 0xFE, "binary", 0x00, "\n">>
      ])

      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert [_padding, "the last readable line", last] = snapshot["worker_exit"]["last_lines"]

      assert last == "..binary."
      assert String.valid?(last)
    end

    test "a finished operation, and one with no log at all, say so rather than guessing",
         context do
      finished = plant_journal(context.root, "completed")
      write_worker_log(context.root, finished, ["this is not news"])

      assert {:ok, snapshot} = Deployment.status(finished, bound())
      assert snapshot["worker_exit"] == nil

      cancelled = plant_journal(context.root, "cancelled")
      assert {:ok, snapshot} = Deployment.status(cancelled, bound())
      assert snapshot["worker_exit"] == nil

      # An unfinished operation whose worker left no log at all is not an unfinished
      # operation with no explanation: the list is empty and the field is still there.
      silent = plant_journal(context.root, "inspecting")
      assert {:ok, snapshot} = Deployment.status(silent, bound())
      assert snapshot["worker_exit"] == %{"last_lines" => []}
    end

    test "a live worker's snapshot carries the field as null", context do
      arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert snapshot["source"] == "worker"
      assert Map.has_key?(snapshot, "worker_exit")
      assert snapshot["worker_exit"] == nil
    end

    test "a worker that goes away before it attaches is read from the journal at once",
         context do
      arrange_worker(context)
      assert {:ok, %{"operation_id" => operation}} = Deployment.prepare(request(), bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      write_journal(context.root, operation, %{
        "operation" => operation,
        "owner" => "adele",
        "kind" => "add",
        "state" => "inspecting"
      })

      write_worker_log(context.root, operation, ["bind: path is 112 bytes, the limit is 104"])

      # The client dies and the next read follows it immediately, so the broker's monitor
      # message may or may not have been handled yet. Both orderings have to answer the
      # same thing: answering `worker_unavailable` for that window is what left the page
      # saying nothing while the reason was already on disk (review finding 5).
      assert {:ok, client} = Deployment.client(operation)
      Process.exit(client, :kill)

      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert snapshot["source"] == "journal"

      assert snapshot["worker_exit"]["last_lines"] == [
               "bind: path is 112 bytes, the limit is 104"
             ]
    end
  end

  # ---------------------------------------------------------------------------
  # The one blocker that is about this runtime rather than about this fleet

  describe "the dev_runtime blocker" do
    setup context do
      # `test/test_helper.exs` declares this suite a packaged runtime so that every other
      # case can drive a local setup. This is the case that asks what the runtime itself
      # answers, so it puts the key back the way a person's machine has it.
      declared = Application.get_env(:ouroboros, :dev_runtime)
      Application.delete_env(:ouroboros, :dev_runtime)
      on_exit(fn -> Application.put_env(:ouroboros, :dev_runtime, declared) end)

      write_ca_key(context.root)
      arrange_devices(context, ~s({"devices": []}\n))
      context
    end

    test "is a reason on a Mix runtime, which is what this suite is", context do
      assert Code.ensure_loaded?(Mix)

      reasons = Deployment.host(context.root)["capabilities"]["reasons"]
      assert "dev_runtime" in reasons

      # Appended rather than inserted: a surface renders this list and a test names it.
      assert List.last(reasons) == "dev_runtime"
    end

    test "blocks setup and nothing else" do
      assert {:error, {:deploy_blocked, blockers}} = Deployment.unblocked("setup")
      assert "dev_runtime" in blockers

      # `add` and `leave` act on another machine's installation. This runtime's inability to
      # boot under a fleet profile says nothing about theirs.
      assert Deployment.unblocked("add") == :ok
      assert Deployment.unblocked("leave") == :ok

      # And a kind this build cannot name is treated as one of those two rather than as a
      # setup: `start` and `authenticate` reach here with the journal's kind, which is nil
      # for an operation whose journal has not been written yet.
      assert Deployment.unblocked(nil) == :ok
    end

    test "is exempted by kind, and the exemptions are the ones the contract names" do
      all = ["no_data_dir", "no_ca_key", "ouro_path_unknown", "cleartext_web_bind", "dev_runtime"]

      assert Deployment.exempt(all, "setup") ==
               ["no_data_dir", "ouro_path_unknown", "cleartext_web_bind", "dev_runtime"]

      assert Deployment.exempt(all, "leave") ==
               ["no_data_dir", "ouro_path_unknown", "cleartext_web_bind"]

      assert Deployment.exempt(all, "add") ==
               ["no_data_dir", "no_ca_key", "ouro_path_unknown", "cleartext_web_bind"]
    end
  end

  # ---------------------------------------------------------------------------
  # The roster a leave names a member out of

  describe "the roster" do
    test "is this machine's fleet profile, matched the way the fleet matches names", context do
      write_profile(context.root, [
        %{"machine" => "BuildBox", "host" => "100.64.12.44", "node" => "ouro@buildbox"},
        %{"machine" => "old-pi", "host" => "100.64.12.10", "node" => "ouro@old-pi"}
      ])

      assert Deployment.roster(context.root) == [
               %{"machine" => "BuildBox", "host" => "100.64.12.44"},
               %{"machine" => "old-pi", "host" => "100.64.12.10"}
             ]

      # `tui/src/fleet.rs` matches roster names case-insensitively, and an operator whose
      # profile carries a mixed-case entry from an older build has to be able to name it.
      assert {:ok, %{"host" => "100.64.12.44"}} =
               Deployment.roster_member("buildbox", context.root)

      assert Deployment.roster_member("nowhere", context.root) == :error
    end

    test "is empty rather than an error for a machine that has no fleet", context do
      assert Deployment.roster(context.root) == []

      File.write!(Path.join([context.root, "fleet", "profile.json"]), "{ not json")
      assert Deployment.roster(context.root) == []
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

  describe "live acceptance regressions" do
    test "named CLI journals appear after a fresh listing and can be read", context do
      assert {[], 0} = Deployment.operations(context.root)
      operation = "pi-manual-20260918"

      write_journal(context.root, operation, %{
        "operation" => operation,
        "kind" => "add",
        "state" => "completed",
        "created_at" => "2026-09-18T20:00:00Z",
        "target" => %{"machine" => "raspberrypi"}
      })

      assert {[%{"operation" => ^operation}], 1} = Deployment.operations(context.root)
      assert {:ok, %{"state" => "completed"}} = Deployment.status(operation, bound())

      for invalid <- ["short", "-operation", "operation-", "op--test", "op.test00", "UPPERCASE"] do
        assert {:error, :invalid_operation} = Journal.validate_operation(invalid)
      end
    end

    test "step updates replace running events and retain progress after reattachment", context do
      operation = plant_journal(context.root, "interrupted")
      %{worker: worker} = arrange_worker(context)
      assert {:ok, _} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      for outcome <- ["started", "started", "ok"] do
        FleetWorkerFake.emit(worker, %{
          "event" => "step",
          "machine" => "vps",
          "step" => "install_binary",
          "outcome" => outcome
        })
      end

      settle(operation)
      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert Enum.count(snapshot["steps"], &(&1["step"] == "install_binary")) == 1

      assert Enum.any?(
               snapshot["steps"],
               &(&1["step"] == "install_binary" and &1["outcome"] == "ok")
             )

      assert Enum.any?(snapshot["steps"], &(&1["step"] == "inspect" and &1["outcome"] == "ok"))
    end

    test "a journal's owner still gates reads while its worker is attaching", context do
      operation = plant_journal(context.root, "interrupted")
      outsider = %{subject: "orson", session: "tab-b"}
      assert {:error, :operation_not_yours} = Deployment.status(operation, outsider)

      cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
      socket_path = Path.join([context.root, "deploy", "late.sock"])

      ouro =
        FleetOuroFake.write!(context.fake_dir,
          spawn_line:
            JSON.encode!(%{"socket" => socket_path, "instance" => "1234567890abcdef"}) <> "\n",
          cap: cap
        )

      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
      assert {:ok, _} = Deployment.resume(operation, bound())
      assert {:ok, pid} = Deployment.client(operation)
      on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

      assert {:ok, %{"owner" => "adele", "attached" => false}} =
               Deployment.status(operation, bound())

      assert {:error, :operation_not_yours} = Deployment.status(operation, outsider)
    end

    test "CLI history is readable without silently taking over its mutations", context do
      operation = plant_journal(context.root, "failed")
      {:ok, document} = Journal.read(context.root, operation)

      write_journal(
        context.root,
        operation,
        Map.put(document, "owner", System.get_env("USER") || System.get_env("LOGNAME"))
      )

      assert {:ok, %{"source" => "journal", "state" => "failed"}} =
               Deployment.status(operation, bound())

      arrange_worker(context)
      assert {:error, :operation_not_yours} = Deployment.resume(operation, bound())
    end

    test "Retry retires a finished attached worker immediately", context do
      operation = plant_journal(context.root, "failed")
      %{worker: worker} = arrange_worker(context)
      assert {:ok, _} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      FleetWorkerFake.emit(worker, %{
        "event" => "done",
        "ok" => false,
        "state" => "failed",
        "detail" => "start refused"
      })

      settle(operation)
      assert {:ok, _} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
    end
  end

  defp bound, do: %{subject: "adele", session: "session-one"}

  # The shape `Ouroboros.Gateway.Methods` builds and `fleet_setup::OperationRequest` reads.
  # The worker refuses unknown keys, so a test that invented its own shape here would be
  # testing a file nothing can parse.
  defp detailed_request do
    %{
      "kind" => "add",
      "machine" => "build-linux",
      "address" => "100.64.12.44",
      "ssh_user" => "deploy",
      "ssh_port" => 2222,
      "identity" => %{"kind" => "key", "path" => "~/.ssh/id_ed25519"},
      "service" => true
    }
  end

  # Re-encoding a decoded document through the same sorting rule the launcher uses. If the
  # file were not canonical, this would differ from it.
  defp canonical_of(json) do
    json |> JSON.decode!() |> canonical() |> IO.iodata_to_binary()
  end

  defp canonical(value) when is_map(value) do
    inner =
      value
      |> Enum.sort_by(fn {key, _value} -> to_string(key) end)
      |> Enum.map(fn {key, inner} ->
        [JSON.encode_to_iodata!(to_string(key)), ?:, canonical(inner)]
      end)
      |> Enum.intersperse(?,)

    [?{, inner, ?}]
  end

  defp canonical(value) when is_list(value),
    do: [?[, value |> Enum.map(&canonical/1) |> Enum.intersperse(?,), ?]]

  defp canonical(value), do: JSON.encode_to_iodata!(value)

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
    socket_path = Path.join([context.root, "deploy", "w.sock"])

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

  # One browser tab's binding: the same operator, a different per-tab session id.
  defp tab(id), do: %{subject: "adele", session: "tab-#{id}"}

  # A stand-in for the LiveView that a browser tab runs: one process, subscribed to the
  # operation under that tab's session, which stays alive until the tab is closed.
  defp subscriber(operation, session) do
    test = self()

    pid =
      spawn(fn ->
        send(test, {:subscribed, self(), Deployment.subscribe(operation, session)})
        loop()
      end)

    assert_receive {:subscribed, ^pid, :ok}, @receive_timeout
    pid
  end

  defp loop do
    receive do
      {:unsubscribe, operation, from} ->
        send(from, {:unsubscribed, self(), Deployment.unsubscribe(operation)})
        loop()

      _other ->
        loop()
    end
  end

  # The tab is closed. Waiting for this process's own `:DOWN` is what makes the next line
  # deterministic: both monitor messages are generated by the same exit, so by the time this
  # one has arrived the client's is already in its mailbox, ahead of anything sent after.
  defp close(pid) do
    reference = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, @receive_timeout
    :ok
  end

  defp unsubscribe(pid, operation) do
    send(pid, {:unsubscribe, operation, self()})
    assert_receive {:unsubscribed, ^pid, :ok}, @receive_timeout
    :ok
  end

  # One round trip through the client process, so everything already in its mailbox — the
  # monitor message `close/1` just produced — has been handled before the next assertion.
  defp settle(operation) do
    assert {:ok, pid} = Deployment.client(operation)
    assert {:ok, _snapshot} = Ouroboros.Fleet.Deployment.Client.snapshot(pid)
    :ok
  end

  defp await_challenge(operation, id, binding \\ nil) do
    binding = binding || bound()

    Enum.reduce_while(1..50, :missing, fn _attempt, _acc ->
      case Deployment.status(operation, binding) do
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

  # The handshake runs in the client's own `handle_continue`, so its failure shows up a
  # moment after `prepare` answered. The broker keeps the reason; this waits for it.
  defp await_error(operation) do
    Enum.reduce_while(1..400, nil, fn _attempt, _acc ->
      case Deployment.status(operation, bound()) do
        {:error, {:attach_failed, reason}} ->
          {:halt, {:attach_failed, reason}}

        _other ->
          Process.sleep(20)
          {:cont, nil}
      end
    end)
  end

  defp unix_stat_mtime({{year, month, day}, {hour, minute, second}}) do
    {:ok, naive} = NaiveDateTime.new(year, month, day, hour, minute, second)
    naive |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix()
  end

  defp unix_stat_mtime(seconds) when is_integer(seconds), do: seconds

  defp random_operation, do: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

  defp plant_journal(root, state) do
    operation = random_operation()

    write_journal(root, operation, %{
      "operation" => operation,
      "owner" => "adele",
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

  defp write_worker_log(root, operation, lines) do
    dir = Journal.deploy_dir(root)
    File.mkdir_p!(dir)
    File.chmod!(dir, 0o700)
    path = Journal.log_path(root, operation)
    File.write!(path, Enum.map(lines, &[&1, ?\n]))
    File.chmod!(path, 0o600)
    path
  end

  defp write_profile(root, members) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "profile.json")

    File.write!(
      path,
      JSON.encode!(%{
        "schema" => 1,
        "fleet_id" => "f0000000000000000000000000000000",
        "name" => "home",
        "machine" => "studio",
        "host" => "100.64.0.1",
        "node" => "ouro@studio",
        "role" => "issuer",
        "members" => members
      })
    )

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
