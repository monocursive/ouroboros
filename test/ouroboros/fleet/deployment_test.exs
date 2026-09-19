defmodule Ouroboros.Fleet.DeploymentTest do
  @moduledoc """
  The broker and its worker process against a real port program.

  The program is `test/support/fleet_frames_fake.sh`, a fake `ouro` that speaks §8 on its own
  stdio and writes a real schema-2 journal. It is a *real executable at a real absolute path*
  rather than a function seam, because the thing under test is exactly that mechanism: the
  broker resolves `OUROBOROS_PROCESS_ID_HELPER`, opens a port on it, and decodes what comes
  back one line at a time.
  """

  # `async: false`: moves `config :ouroboros, :data_dir`, `:dev_runtime` and the
  # `OUROBOROS_*` environment, all node-global, and drives the named broker singleton.
  use ExUnit.Case, async: false

  @moduletag :capture_log

  import ExUnit.CaptureLog

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Worker
  alias Ouroboros.Test.FleetFramesFake

  @secret "correct horse battery staple"

  setup do
    root = Path.join(System.tmp_dir!(), "okd#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    bin = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      dev_runtime: Application.get_env(:ouroboros, :dev_runtime),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)
    # A packaged runtime, so `setup` is not refused for being a checkout. Every other kind is
    # exempt from that blocker anyway; this is what lets a `setup` case exist at all.
    Application.put_env(:ouroboros, :dev_runtime, false)

    FleetFramesFake.install!(bin, devices: ~s({"devices":[],"discovery":{"code":"ok"}}\n))

    on_exit(fn ->
      # Close every port this case left open. The program then reads stdin EOF and finishes
      # on its own, which is the property §8 asks for — so the removal below waits for it and
      # then does not insist, because a directory a still-finishing program is writing into
      # is a temporary file and not a failed assertion.
      reap_workers()
      Process.sleep(150)

      FleetFramesFake.uninstall!()
      restore(:data_dir, previous.data_dir)
      restore(:dev_runtime, previous.dev_runtime)

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
  # The argv, which is the request (§6)

  describe "argv/2" do
    test "an add is a destination, a name, a port and the frames flags" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "raspberrypi",
                   "address" => "100.83.203.10",
                   "ssh_user" => "monocursive",
                   "port" => 22
                 },
                 "0123456789abcdef"
               )

      assert argv == [
               "fleet",
               "add",
               "monocursive@100.83.203.10",
               "--machine",
               "raspberrypi",
               "--port",
               "22",
               "--frames",
               "--operation",
               "0123456789abcdef"
             ]
    end

    test "an add carries the paths, the identity and --no-service where they were asked for" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "pi",
                   "address" => "100.83.203.10",
                   "ssh_user" => "deploy",
                   "port" => 2222,
                   "identity" => %{"kind" => "key", "ref" => "/home/me/.ssh/id_ed25519"},
                   "install_path" => "/usr/local/bin/ouro",
                   "data_dir" => "/srv/ouroboros",
                   "service" => false
                 },
                 "0123456789abcdef"
               )

      assert argv == [
               "fleet",
               "add",
               "deploy@100.83.203.10",
               "--machine",
               "pi",
               "--port",
               "2222",
               "--key",
               "/home/me/.ssh/id_ed25519",
               "--install-path",
               "/usr/local/bin/ouro",
               "--data-dir",
               "/srv/ouroboros",
               "--no-service",
               "--frames",
               "--operation",
               "0123456789abcdef"
             ]
    end

    test "a setup names this machine and optionally its address, and never an account" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{"kind" => "setup", "machine" => "studio", "address" => "100.64.0.1"},
                 "0123456789abcdef"
               )

      assert argv == [
               "fleet",
               "setup",
               "--machine",
               "studio",
               "--address",
               "100.64.0.1",
               "--frames",
               "--operation",
               "0123456789abcdef"
             ]

      assert {:ok, bare} =
               Deployment.argv(%{"kind" => "setup", "machine" => "studio"}, "0123456789abcdef")

      refute "--address" in bare
    end

    test "a leave names the machine and the account, and never an address" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "leave",
                   "machine" => "pi",
                   "ssh_user" => "deploy",
                   "port" => 22,
                   "identity" => %{"kind" => "password"}
                 },
                 "0123456789abcdef"
               )

      assert argv == [
               "fleet",
               "leave",
               "--machine",
               "pi",
               "--user",
               "deploy",
               "--port",
               "22",
               "--ask-password",
               "--frames",
               "--operation",
               "0123456789abcdef"
             ]

      refute Enum.any?(argv, &String.contains?(&1, "@"))
    end

    test "nothing that begins with a hyphen ever becomes a word on the command line" do
      for field <- ["address", "ssh_user", "install_path", "data_dir"] do
        request =
          %{
            "kind" => "add",
            "machine" => "pi",
            "address" => "100.83.203.10",
            "ssh_user" => "deploy",
            "port" => 22
          }
          |> Map.put(field, "--data-dir")

        assert {:error, {:invalid_request, message}} =
                 Deployment.argv(request, "0123456789abcdef")

        assert message =~ "not a flag"
      end
    end

    test "a machine name is held to the shape the program accepts" do
      for name <- ["-pi", "pi pi", "", String.duplicate("p", 41), "pi/../etc"] do
        assert {:error, {:invalid_request, _message}} =
                 Deployment.argv(
                   %{
                     "kind" => "add",
                     "machine" => name,
                     "address" => "1.2.3.4",
                     "ssh_user" => "x",
                     "port" => 22
                   },
                   "0123456789abcdef"
                 )
      end
    end

    test "an operation id this runtime would not touch a path with is refused" do
      assert {:error, :invalid_operation} =
               Deployment.argv(
                 %{"kind" => "setup", "machine" => "studio"},
                 "../../etc/passwd"
               )
    end
  end

  # ---------------------------------------------------------------------------
  # The whole of one deployment

  describe "a deployment that works" do
    test "runs start → host trust → password → review → steps → done", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, operation} = start_add()
      :ok = Deployment.subscribe(operation)

      assert %{"kind" => "host_trust", "challenge" => "trust-1"} =
               challenge = await_challenge(operation, "trust-1")

      # What the broker actually exec'd, which is the contract the Rust slice is held to.
      assert FleetFramesFake.argv(context.bin) == [
               "fleet",
               "add",
               "deploy@100.100.7.1",
               "--machine",
               "fixture-target",
               "--port",
               "22",
               "--frames",
               "--operation",
               operation
             ]

      assert challenge["metadata"]["sha256_fingerprint"] =~ "SHA256:"
      assert {:ok, %{"source" => "worker", "running" => true}} = Deployment.status(operation)

      assert {:ok, %{"accepted" => true}} =
               Deployment.respond(operation, "trust-1", %{"accept" => true})

      assert %{"kind" => "password"} = await_challenge(operation, "secret-1")

      assert {:ok, %{"accepted" => true}} =
               Deployment.respond(operation, "secret-1", %{"secret" => @secret})

      assert %{"kind" => "review"} = review = await_challenge(operation, "review-1")

      assert review["metadata"]["plan"] == [
               "Install ouro 0.1.10 (Linux arm64) to /usr/local/bin/ouro",
               "Join fixture as fixture-target",
               "Start at login as a user service",
               "Remember fixture-target on this machine"
             ]

      assert {:ok, %{"accepted" => true}} =
               Deployment.respond(operation, "review-1", %{"accept" => true})

      # The subscriber saw the frames rather than being told to poll for them, and the `done`
      # frame is where the summary is — by the time a *status* read says `completed` the
      # program may already have exited, which is the journal's answer and not the worker's.
      assert_receive {:ouroboros_fleet_deployment, ^operation, %{"event" => "challenge"}}, 5_000

      assert_receive {:ouroboros_fleet_deployment, ^operation,
                      %{
                        "event" => "done",
                        "state" => "completed",
                        "summary" => "fixture-target joined this fleet"
                      }},
                     5_000

      assert {:ok, final} = await_state(operation, "completed")
      assert final["plan"] != []

      assert Enum.map(final["steps"], & &1["step"]) ==
               ~w(inspect install join service start connect)

      assert Enum.all?(final["steps"], &(&1["state"] == "ok"))
    end

    test "the secret reaches the program's stdin and nothing else", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")
      {:ok, _} = Deployment.respond(operation, "trust-1", %{"accept" => true})
      await_challenge(operation, "secret-1")

      log =
        capture_log(fn ->
          {:ok, _} = Deployment.respond(operation, "secret-1", %{"secret" => @secret})
        end)

      # It arrived, which is what makes the absences below evidence rather than a tautology.
      assert Enum.any?(FleetFramesFake.responses(context.bin), &String.contains?(&1, @secret))

      # And it is nowhere this runtime keeps anything.
      refute log =~ @secret
      assert log =~ "fleet deployment respond operation=#{operation} challenge=secret-1"

      broker = :sys.get_state(Deployment)
      refute inspect(broker, limit: :infinity, printable_limit: :infinity) =~ @secret

      {:ok, worker} = Deployment.worker(operation)
      dump = :sys.get_state(worker)
      refute inspect(dump, limit: :infinity, printable_limit: :infinity) =~ @secret

      # `format_status/1` is what OTP's crash report prints, and it prints neither the last
      # message nor the state.
      status =
        Worker.format_status(%{
          message: {:respond, "secret-1", %{"secret" => @secret}},
          state: dump
        })

      refute inspect(status, limit: :infinity, printable_limit: :infinity) =~ @secret

      # A `:sensitive` process keeps its mailbox out of `Process.info/2` as well.
      assert Process.info(worker, :messages) in [nil, {:messages, []}]

      assert {:ok, snapshot} = Deployment.status(operation)
      refute inspect(snapshot, limit: :infinity, printable_limit: :infinity) =~ @secret
    end
  end

  # ---------------------------------------------------------------------------
  # The ways it stops

  describe "stopping" do
    test "a cancel mid-way ends the operation at a safe boundary", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")

      assert {:ok, %{"cancelling" => true}} = Deployment.cancel(operation)
      assert {:ok, final} = await_state(operation, "cancelled")
      assert final["state"] == "cancelled"

      # The program recorded it durably too, so the answer survives the worker process.
      await_no_worker(operation)
      assert %{"state" => "cancelled"} = FleetFramesFake.journal(context.root, operation)

      assert {:ok, %{"source" => "journal", "state" => "cancelled"}} =
               Deployment.status(operation)
    end

    test "an answer past a challenge's expiry is refused before anything is written", context do
      System.put_env("OUROBOROS_FAKE_EXPIRES", "2000-01-01T00:00:00Z")

      FleetFramesFake.write_scenario!(context.bin, [
        "state waiting",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "done failed challenge_expired"
      ])

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")

      assert {:error, :challenge_expired} =
               Deployment.respond(operation, "trust-1", %{"accept" => true})

      refute Enum.any?(FleetFramesFake.responses(context.bin), &String.contains?(&1, "trust-1"))
    end

    test "an answer to a challenge the operation is not waiting on is named", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")

      assert {:error, :unknown_challenge} =
               Deployment.respond(operation, "somebody-elses", %{"accept" => true})

      assert {:error, :challenge_kind_mismatch} =
               Deployment.respond(operation, "trust-1", %{"secret" => @secret})

      assert {:ok, _} = Deployment.respond(operation, "trust-1", %{"accept" => true})

      assert {:error, :challenge_consumed} =
               Deployment.respond(operation, "trust-1", %{"accept" => true})
    end

    test "a program that exits without a done frame says so rather than inventing an end",
         context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step inspect ok reachable",
        "stderr ssh: connect to host 100.100.7.1 port 22: Connection refused",
        "exit 3"
      ])

      {:ok, operation} = start_add()
      await_no_worker(operation)

      assert {:ok, status} = Deployment.status(operation)
      assert status["source"] == "journal"
      # The journal's own last word, which is `running`: nothing said it finished.
      assert status["state"] == "running"
      assert status["last_error"]["reason"] == "worker_exited"
      assert status["last_error"]["detail"] =~ "status 3"
      # And what it printed, from the file that is the only record a program that died early
      # leaves behind.
      assert Enum.any?(status["log"], &(&1 =~ "Connection refused"))
    end
  end

  # ---------------------------------------------------------------------------
  # What the program may write, and what it may not

  describe "frames this build refuses" do
    test "a line past the 1 MiB cap is refused and the rest of it is not measured", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "bigline",
        "step inspect ok reachable",
        "challenge hold-1 host_trust {}",
        "await hold-1"
      ])

      {:ok, operation} = start_add()
      # The program is still holding the operation, so this is the *worker's* answer: a
      # protocol fault is what this runtime observed and not something the journal knows.
      await_challenge(operation, "hold-1")

      assert {:ok, status} = Deployment.status(operation)
      assert status["source"] == "worker"
      assert status["last_error"]["reason"] == "worker_frame_too_large"
      # The frames after it are still read: one bad line ends that line, not the operation.
      assert Enum.map(status["steps"], & &1["step"]) == ["inspect"]
    end

    test "a line that is not JSON is named and does not end the operation", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "raw this is not a frame",
        "step inspect ok reachable",
        "challenge hold-1 host_trust {}",
        "await hold-1"
      ])

      {:ok, operation} = start_add()
      await_challenge(operation, "hold-1")

      assert {:ok, status} = Deployment.status(operation)
      assert status["last_error"]["reason"] == "worker_answered_nothing"
      assert status["last_error"]["detail"] == "not JSON"
      assert Enum.map(status["steps"], & &1["step"]) == ["inspect"]
    end

    test "a JSON line that is not one of the five events is counted rather than forwarded",
         context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "raw {\"event\":\"gossip\",\"line\":\"hello\"}",
        "challenge hold-1 host_trust {}",
        "await hold-1"
      ])

      {:ok, operation} = start_add()
      :ok = Deployment.subscribe(operation)
      await_challenge(operation, "hold-1")

      assert {:ok, status} = Deployment.status(operation)
      assert status["last_error"]["reason"] == "worker_answered_nothing"
      refute_received {:ouroboros_fleet_deployment, ^operation, %{"event" => "gossip"}}
    end
  end

  # ---------------------------------------------------------------------------
  # Resume, and the property the whole design rests on

  describe "resume" do
    test "runs the same command line again against the journal the program left", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step inspect ok reachable",
        "exit 3"
      ])

      {:ok, operation} = start_add()
      await_no_worker(operation)
      assert {:ok, %{"source" => "journal"}} = Deployment.status(operation)

      FleetFramesFake.write_scenario!(context.bin, [
        "step inspect skipped already done",
        "step install ok /usr/local/bin/ouro",
        "done completed fixture-target joined this fleet"
      ])

      assert {:ok, %{"operation" => ^operation}} = Deployment.resume(operation)

      assert FleetFramesFake.argv(context.bin) == [
               "fleet",
               "add",
               "deploy@100.100.7.1",
               "--machine",
               "fixture-target",
               "--port",
               "22",
               "--frames",
               "--operation",
               operation
             ]

      assert {:ok, final} = await_state(operation, "completed")
      assert Enum.map(final["steps"], & &1["step"]) == ["inspect", "install"]
    end

    test "is refused while a process is holding the operation, and after it finished",
         context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")

      assert {:error, :already_attached} = Deployment.resume(operation)

      {:ok, _} = Deployment.cancel(operation)
      await_no_worker(operation)

      assert {:error, :operation_finished} = Deployment.resume(operation)
    end

    test "is refused for an operation nobody started" do
      assert {:error, :unknown_operation} = Deployment.resume("0123456789abcdef")
      assert {:error, :invalid_operation} = Deployment.resume("../etc")
    end
  end

  describe "the port program outlives the process that opened it" do
    test "killing the worker closes its stdin and the program finishes on its own", context do
      marker = Path.join(context.root, "after-eof")

      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        # `await` returns on stdin EOF too, and from here on the program writes its journal
        # and stops writing frames — which is the whole of §8's "survives".
        "step install ok after stdin closed",
        "done completed finished without anybody watching",
        "stderr finished after stdin EOF"
      ])

      {:ok, operation} = start_add()
      await_challenge(operation, "trust-1")

      {:ok, worker} = Deployment.worker(operation)
      reference = Process.monitor(worker)
      Process.exit(worker, :kill)
      assert_receive {:DOWN, ^reference, :process, ^worker, :killed}, 5_000

      # Nothing is holding the operation any more, so the journal is the answer — and it
      # keeps changing, because the program is still running.
      await_journal(context.root, operation, "completed")

      assert %{"state" => "completed", "steps" => steps} =
               FleetFramesFake.journal(context.root, operation)

      assert Enum.any?(steps, &(&1["step"] == "install" and &1["state"] == "ok"))
      assert File.exists?(marker) == false
      assert File.read!(Journal.log_path(context.root, operation)) =~ "after stdin EOF"

      assert {:ok, %{"source" => "journal", "state" => "completed", "running" => false}} =
               Deployment.status(operation)
    end
  end

  # ---------------------------------------------------------------------------
  # The lists

  describe "operations/1" do
    test "lists the journal directory and says which of them a process is holding", context do
      FleetFramesFake.write_scenario!(context.bin, FleetFramesFake.happy_add())

      {:ok, live} = start_add()
      await_challenge(live, "trust-1")

      assert {rows, total} = Deployment.operations(context.root)
      assert total >= 1
      row = Enum.find(rows, &(&1["operation"] == live))
      assert row["kind"] == "add"
      assert row["running"] == true
      assert row["target"]["machine"] == "fixture-target"
      assert row["last_error"] == nil

      {:ok, _} = Deployment.cancel(live)
      await_no_worker(live)

      {rows, _total} = Deployment.operations(context.root)
      assert Enum.find(rows, &(&1["operation"] == live))["running"] == false
    end

    test "a failed operation's row carries the journal's own last_error", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step inspect failed the target refused the connection",
        "error ssh_unavailable the target refused the connection",
        "done failed fixture-target was not added"
      ])

      {:ok, operation} = start_add()
      await_no_worker(operation)

      {rows, _total} = Deployment.operations(context.root)
      row = Enum.find(rows, &(&1["operation"] == operation))

      assert row["state"] == "failed"
      # A list that says `failed` and nothing else sends an operator into a drawer to find
      # out what a line could have told them.
      assert row["last_error"] == %{
               "reason" => "ssh_unavailable",
               "detail" => "the target refused the connection"
             }
    end
  end

  describe "devices/1" do
    test "answers the inventory with no issuer on it and the host's blockers", context do
      FleetFramesFake.write_devices!(context.bin, %{
        "discovery" => %{"code" => "ok"},
        "devices" => [%{"machine" => "pi", "state" => "fleet_member", "address" => "100.64.0.2"}],
        "something_a_later_ouro_prints" => 5
      })

      assert {:ok, inventory} = Deployment.devices(data_dir: context.root)

      refute Map.has_key?(inventory["host"], "issuer")
      assert inventory["host"]["capabilities"]["reasons"] == []
      refute "no_ca_key" in inventory["host"]["capabilities"]["reasons"]
      # A key this build does not read is named rather than passed through.
      assert "something_a_later_ouro_prints" in inventory["unknown"]
      assert [%{"machine" => "pi"}] = inventory["devices"]
    end

    test "a dev runtime blocks a setup and nothing else", context do
      Application.put_env(:ouroboros, :dev_runtime, true)

      assert {:ok, inventory} = Deployment.devices(data_dir: context.root)
      assert inventory["host"]["capabilities"]["reasons"] == ["dev_runtime"]
      assert inventory["host"]["capabilities"]["deploy"] == false

      assert {:error, {:deploy_blocked, ["dev_runtime"]}} = Deployment.unblocked("setup")
      assert :ok = Deployment.unblocked("add")
      assert :ok = Deployment.unblocked("leave")
    end
  end

  # ---------------------------------------------------------------------------

  defp start_add do
    Deployment.start(%{
      "kind" => "add",
      "machine" => "fixture-target",
      "address" => "100.100.7.1",
      "ssh_user" => "deploy",
      "port" => 22
    })
    |> case do
      {:ok, %{"operation" => operation}} -> {:ok, operation}
      other -> flunk("the broker refused a start: #{inspect(other)}")
    end
  end

  defp await_challenge(operation, id) do
    poll("challenge #{id}", fn ->
      case Deployment.status(operation) do
        {:ok, %{"challenge" => %{"challenge" => ^id} = challenge}} -> challenge
        _not_yet -> nil
      end
    end)
  end

  defp await_state(operation, state) do
    {:ok,
     poll("state #{state}", fn ->
       case Deployment.status(operation) do
         {:ok, %{"state" => ^state} = status} -> status
         _not_yet -> nil
       end
     end)}
  end

  defp await_no_worker(operation) do
    poll("no worker for #{operation}", fn ->
      case Deployment.worker(operation) do
        {:error, :no_worker} -> :gone
        _still_here -> nil
      end
    end)
  end

  defp await_journal(root, operation, state) do
    poll("journal #{state}", fn ->
      case FleetFramesFake.journal(root, operation) do
        %{"state" => ^state} = journal -> journal
        _not_yet -> nil
      end
    end)
  end

  defp poll(what, fun) do
    Enum.reduce_while(1..200, nil, fn _attempt, _acc ->
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
end
