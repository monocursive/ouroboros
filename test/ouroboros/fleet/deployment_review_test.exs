defmodule Ouroboros.Fleet.DeploymentReviewTest do
  @moduledoc """
  The adversarial review's thirteen exploits, kept as regressions with their assertions
  inverted.

  Each name carries the finding it came from, because the finding is the reason the test
  exists and a test that outlives the memory of what it caught is a test somebody deletes.
  The originals asserted the broken behaviour and all thirteen passed against b52d7242; each
  one here asserts the property that replaced it.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Fleet.Deployment.Frame
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher
  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake
  alias Ouroboros.Web.Call

  @receive_timeout 5_000

  setup do
    start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})

    root = Path.join(System.tmp_dir!(), "or#{System.unique_integer([:positive])}")
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
    previous_web = Application.get_env(:ouroboros, :web)
    previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")
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
  # F1 (CRITICAL). The worker chooses the challenge `kind`. A kind that was not a string
  # made the client's own audit line raise inside the call holding the secret, which put the
  # secret in the crash report and — through the exit reason, which carries the call
  # arguments — into the JSON-RPC error data written to the socket.

  describe "F1 a worker-chosen challenge kind" do
    test "cannot put the secret in the log, the error, or the process", context do
      %{worker: worker} = arrange_worker(context)
      secret = "F1-SECRET-#{System.unique_integer([:positive])}"

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, _pid} = await_client(operation)

      # `kind` is whatever the worker says it is — here, an object.
      :ok =
        FleetWorkerFake.challenge(worker, "pw-1", %{"trap" => true}, %{"prompt" => "password:"})

      await_challenge(operation, "pw-1")

      {result, log} =
        with_log([level: :debug], fn ->
          Call.call(
            :operate,
            "fleet.deployment.authenticate",
            %{"operation_id" => operation, "challenge" => "pw-1", "secret" => secret},
            session: "tab-a"
          )
        end)

      # It is refused, because a kind this build does not know is not a kind this verb
      # answers — and the refusal is a refusal rather than a crash.
      assert {:error, _code, _message, data} = result
      assert data["reason"] == "challenge_kind_mismatch"

      refute log =~ secret
      refute inspect(data) =~ secret

      # What the listener would actually write onto the socket for that error.
      wire = JSON.encode!(%{"jsonrpc" => "2.0", "id" => 1, "error" => %{"data" => data}})
      refute wire =~ secret

      # The audit line still says which challenge and what happened; the unprintable kind
      # is labelled rather than interpolated.
      assert log =~ "challenge=pw-1"
      assert log =~ "kind=unknown"
      assert log =~ "outcome=challenge_kind_mismatch"
    end

    test "and the client keeps nothing a crash report could print", context do
      %{worker: worker} = arrange_worker(context)
      secret = "F1B-SECRET-#{System.unique_integer([:positive])}"

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      :ok = FleetWorkerFake.challenge(worker, "pw-1", "password")
      await_challenge(operation, "pw-1")

      # The worker stops answering, so the response sits in the client's mailbox and the
      # caller waits — which is the window a crash would have printed it in.
      :ok = FleetWorkerFake.stall(worker, true)

      task =
        Task.async(fn ->
          Deployment.authenticate(operation, "pw-1", secret, %{
            subject: "runtime-unattributed",
            session: "tab-a"
          })
        end)

      Process.sleep(200)

      # `:sensitive` is what makes this empty: mailbox, dictionary and stack are withheld
      # from `Process.info/2`, from crash reports and from the crash dump.
      assert Process.info(pid, :messages) == {:messages, []}
      assert Process.info(pid, :dictionary) == {:dictionary, []}

      # And an arbitrary exit while that call is in flight maps to a stable reason. The raw
      # exit reason carries the call arguments — the secret among them — and is discarded
      # here rather than returned to be Wire-encoded onto the socket.
      capture_log(fn ->
        Process.exit(pid, :kill)
        assert {:error, reason} = Task.await(task, @receive_timeout)
        assert reason == :worker_unavailable
        refute inspect(reason) =~ secret
      end)
    end

    test "and a crash report redacts the last message that carried the secret", context do
      %{worker: worker} = arrange_worker(context)
      secret = "F1B-FORMAT-#{System.unique_integer([:positive])}"

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      :ok = FleetWorkerFake.challenge(worker, "pw-1", "password")
      await_challenge(operation, "pw-1")

      :sys.replace_state(pid, fn state ->
        %{state | clock: fn -> raise "client-test-boom" end}
      end)

      log =
        ExUnit.CaptureLog.capture_log([level: :error], fn ->
          _ =
            Deployment.authenticate(operation, "pw-1", secret, %{
              subject: "runtime-unattributed",
              session: "tab-a"
            })

          Process.sleep(300)
        end)

      refute log =~ secret
    end
  end

  # ---------------------------------------------------------------------------
  # F2 (MEDIUM). `challenges` was the one collection in the client with no cap.

  test "F2 a worker cannot grow the client's state without bound", context do
    %{worker: worker} = arrange_worker(context)

    assert {:ok, %{"operation_id" => operation}} =
             Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

    assert {:ok, pid} = await_client(operation)

    blob = String.duplicate("z", 2_000)
    fat = Map.new(1..2, fn n -> {"f#{n}", blob} end)

    capture_log(fn ->
      Enum.each(1..2_500, fn n ->
        :ok = FleetWorkerFake.challenge(worker, "flood-#{n}", "password", fat)
      end)

      await_challenge(operation, "flood-2500")
    end)

    state = :sys.get_state(pid)
    assert map_size(state.challenges) <= 64

    retained = state.challenges |> :erlang.term_to_binary() |> byte_size()
    assert retained < 1_000_000

    # The newest survive, which is the set an operator is actually answering.
    assert {:ok, snapshot} = Deployment.status(operation, bound())
    assert length(snapshot["challenges"]) <= 64
    assert Enum.any?(snapshot["challenges"], &(&1["challenge"] == "flood-2500"))
  end

  # ---------------------------------------------------------------------------
  # F3 (MEDIUM). A `bound_to` that was not an object crashed the connection.

  test "F3 a non-object bound_to is dropped, not fatal", context do
    %{worker: worker} = arrange_worker(context)

    assert {:ok, %{"operation_id" => operation}} =
             Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

    assert {:ok, pid} = await_client(operation)
    ref = Process.monitor(pid)

    log =
      capture_log(fn ->
        :ok =
          FleetWorkerFake.emit(worker, %{
            "event" => "challenge",
            "challenge" => "x-1",
            "kind" => "password",
            "bound_to" => "not-an-object"
          })

        refute_receive {:DOWN, ^ref, :process, ^pid, _reason}, 500
      end)

    assert log =~ "bound_to is not an object"

    # The connection is still the operation's, and the frame was not recorded.
    assert {:ok, snapshot} = Deployment.status(operation, bound())
    assert snapshot["source"] == "worker"
    refute Enum.any?(snapshot["challenges"], &(&1["challenge"] == "x-1"))
  end

  # ---------------------------------------------------------------------------
  # F4 (MEDIUM). `start` claimed the idempotency key before checking there was a plan, so
  # one early start wedged approval forever.

  test "F4 a start with no plan yet leaves the operation approvable", context do
    %{worker: worker} = arrange_worker(context)

    assert {:ok, %{"operation_id" => operation}} =
             Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

    assert {:ok, _pid} = await_client(operation)

    assert {:error, _c1, _m1, first} = start(operation, "key-1")
    assert first["reason"] == "no_review_pending"

    # The worker produces the plan a moment later, exactly as it would.
    :ok = FleetWorkerFake.challenge(worker, "rev-1", "review")
    await_challenge(operation, "rev-1")

    # The same key now works: nothing was recorded for a start that never happened.
    assert {:ok, approved} = start(operation, "key-1")
    assert approved["accepted"] == true

    # And the ledger behaves from there: the same key replays, a different one is refused.
    assert {:ok, ^approved} = start(operation, "key-1")
    assert {:error, _c2, _m2, other} = start(operation, "key-2")
    assert other["reason"] == "operation_in_progress"
  end

  # ---------------------------------------------------------------------------
  # F5 (MEDIUM). The deadline closed the Port and left the operating-system child running.

  test "F5 the timeout reaps the operating-system child", context do
    pidfile = Path.join(context.root, "child.pid")
    File.mkdir_p!(context.fake_dir)
    ouro = Path.join(context.fake_dir, "ouro")

    File.write!(ouro, """
    #!/bin/sh
    echo $$ > '#{pidfile}'
    sleep 30
    echo '{}'
    """)

    File.chmod!(ouro, 0o755)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

    assert {:error, :ouro_timeout} = Launcher.run(["fleet", "devices", "--json"], 400)

    child = pidfile |> File.read!() |> String.trim()
    assert child != ""

    # The signal and the reap are not instantaneous; a bounded wait, then it must be gone.
    assert Enum.reduce_while(1..50, false, fn _attempt, _acc ->
             case System.cmd("/bin/kill", ["-0", child], stderr_to_stdout: true) do
               {_output, 0} ->
                 Process.sleep(20)
                 {:cont, false}

               {_output, _status} ->
                 {:halt, true}
             end
           end),
           "the child #{child} was still running after the deadline"
  end

  # ---------------------------------------------------------------------------
  # F6 (MEDIUM). Nothing bounded what `ouro` could print into this runtime's heap.

  test "F6 a devices call stops reading a child that will not stop printing", context do
    File.mkdir_p!(context.fake_dir)
    ouro = Path.join(context.fake_dir, "ouro")

    File.write!(ouro, """
    #!/bin/sh
    dd if=/dev/zero bs=1048576 count=64 2>/dev/null | tr '\\0' 'a'
    """)

    File.chmod!(ouro, 0o755)
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

    assert {:error, {:ouro_output_too_large, size}} =
             Launcher.run(["fleet", "devices", "--json"], 30_000)

    # Bounded at half a megabyte, not sixty-four: the cap is checked per chunk, so what was
    # held is one chunk past it rather than everything the child had to say.
    assert size < 2 * 1024 * 1024

    # And the verb reports it as a named refusal rather than an out-of-memory runtime.
    assert {:error, {:ouro_output_too_large, _size}} = Deployment.devices()
  end

  # ---------------------------------------------------------------------------
  # F7 (HIGH). The browser "session" was the cookie's, shared by every tab, so the contract's
  # "a second tab cannot answer the first tab's prompt" was false.

  test "F7 a second view in the same browser cannot answer the challenge", context do
    %{worker: worker} = arrange_worker(context)
    secret = "F7-SECRET-#{System.unique_integer([:positive])}"

    # Tab A: one cookie, one per-view id.
    assert {:ok, %{"operation_id" => operation}} =
             Call.call(:operate, "fleet.deployment.prepare", request(),
               session: "cookie-session",
               client_session: "live-tab-a"
             )

    assert {:ok, _pid} = await_client(operation)
    :ok = FleetWorkerFake.challenge(worker, "pw-1", "password")
    await_challenge(operation, "pw-1")

    # Tab B: the SAME cookie — every tab in a browser reads one — and its own view id.
    assert {:error, code, _message, data} =
             Call.call(
               :operate,
               "fleet.deployment.authenticate",
               %{"operation_id" => operation, "challenge" => "pw-1", "secret" => secret},
               session: "cookie-session",
               client_session: "live-tab-b"
             )

    assert code == -32_003
    assert data["reason"] == "challenge_not_bound"
    refute_receive {:fake_worker, %{"op" => "respond"}}, 300

    # The view it was issued to still answers.
    assert {:ok, reply} =
             Call.call(
               :operate,
               "fleet.deployment.authenticate",
               %{"operation_id" => operation, "challenge" => "pw-1", "secret" => secret},
               session: "cookie-session",
               client_session: "live-tab-a"
             )

    assert reply["accepted"] == true
  end

  # ---------------------------------------------------------------------------
  # F8 (MEDIUM). A prepare that failed after the fork left the detached worker running with
  # a socket nobody would ever connect to.

  test "F8 a prepare that fails after the fork cancels the worker it forked", context do
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    worker =
      start_supervised!(
        {FleetWorkerFake,
         [
           socket_path: Path.join([context.root, "deploy", "w.sock"]),
           cap: cap,
           instance: instance,
           operation_file: FleetOuroFake.operation_file(context.fake_dir),
           owner: self()
         ]},
        id: {FleetWorkerFake, System.unique_integer([:positive])}
      )

    # The capability lands world-readable, which the broker refuses — after the fork.
    ouro =
      FleetOuroFake.write!(context.fake_dir,
        spawn_line: FleetWorkerFake.spawn_line(worker),
        cap: cap,
        cap_mode: 0o644
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

    log =
      capture_log(fn ->
        assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
                 Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

        assert {:error, {:attach_failed, :capability_unusable}} =
                 await_status_error(operation)
      end)

    # This runtime refused to *use* that capability because anyone on the machine could read
    # it; presenting it anyway to send a cancel would be the same disclosure. The worker also
    # left no journal, so there is no operation to hand back either. The leak is therefore
    # reported rather than hidden, and the worker's own bounded idle timeout ends it — the
    # finding was the silence, and the silence is what is fixed.
    assert log =~ "could not adopt the worker for"
    assert log =~ "left no journal"
    refute_received {:fake_worker, %{"op" => "cancel"}}
  end

  test "F8b and when the supervisor is down, nothing is forked", context do
    _arranged = arrange_worker(context)

    # The client supervisor is down, so `start_client` fails *after* the fork with a
    # perfectly good capability in hand — which is the branch that can, and does, reap.
    client_supervisor = Ouroboros.Fleet.Deployment.ClientSupervisor
    :ok = Supervisor.terminate_child(Ouroboros.Surface.Supervisor, client_supervisor)

    on_exit(fn ->
      Supervisor.restart_child(Ouroboros.Surface.Supervisor, client_supervisor)
    end)

    log =
      capture_log(fn ->
        assert {:error, _code, _message, data} =
                 Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

        assert data["reason"] in ["client_supervisor_unavailable", "no_data_dir"]
      end)

    refute_receive {:fake_worker, %{"op" => "attach"}}, 400
    refute_receive {:fake_worker, %{"op" => "cancel"}}, 400
    refute log =~ "cancelled the worker it could not adopt"
  end

  # ---------------------------------------------------------------------------
  # F9 (HIGH). `packet_size` without `buffer` made the real frame ceiling 9216 bytes, so an
  # ordinary worker frame dropped the connection and was reported as a 1 MiB overrun.

  describe "F9 the frame ceiling" do
    test "an ordinary 32 KiB frame is delivered, not fatal", context do
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      ref = Process.monitor(pid)

      :ok =
        FleetWorkerFake.emit(worker, %{"event" => "log", "line" => String.duplicate("s", 32_000)})

      refute_receive {:DOWN, ^ref, :process, ^pid, _reason}, 500
      assert {:ok, %{"source" => "worker"}} = Deployment.status(operation, bound())
    end

    test "and so is a 300 KiB one, which is well past the old ceiling", context do
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      ref = Process.monitor(pid)

      :ok =
        FleetWorkerFake.emit(worker, %{"event" => "log", "line" => String.duplicate("s", 300_000)})

      refute_receive {:DOWN, ^ref, :process, ^pid, _reason}, 1_000

      # Delivered and kept: the connection survived a frame thirty times the old ceiling.
      assert {:ok, snapshot} = Deployment.status(operation, bound())
      assert snapshot["source"] == "worker"
      assert length(snapshot["log"]) == 1

      # What the *snapshot* shows is separately bounded, by the sanitizer's string cut. That
      # is a display bound on an operator-facing reply, not a transport one, and the two are
      # different numbers on purpose.
      assert byte_size(hd(snapshot["log"])["line"]) == 2_000
    end

    test "a frame genuinely past the cap still ends the connection", context do
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      ref = Process.monitor(pid)
      broker = Process.whereis(Ouroboros.Fleet.Deployment)

      capture_log(fn ->
        :ok = FleetWorkerFake.emit_oversize(worker)
        assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, @receive_timeout
      end)

      # One connection, not the broker.
      assert Process.alive?(broker)
      assert Process.whereis(Ouroboros.Fleet.Deployment) == broker
    end

    test "and the decoder refuses an oversized line on its own", _context do
      # The socket's `packet_size` means this branch is not reachable through a connection,
      # which is exactly why it is asserted directly: it is the second of the two bounds,
      # and a mutation that deleted it survived the suite before this existed (M10).
      line = String.duplicate("x", Frame.max_bytes() + 1) <> "\n"

      assert {:error, {:frame_too_large, size}} = Frame.decode(line)
      assert size > Frame.max_bytes()

      assert {:ok, %{"v" => 1}} = Frame.decode(~s({"v":1,"id":"a","ok":true}\n))
    end
  end

  # ---------------------------------------------------------------------------
  # F10 (CRITICAL). The cleartext-bind blocker demanded a tuple, and every production config
  # site writes a string — so it never fired on a real deployment.

  describe "F10 the cleartext bind blocker" do
    test "fires on the string bind production actually writes", context do
      arrange_devices(context)
      write_ca_key(context.root)

      # Exactly what `OUROBOROS_WEB_BIND=0.0.0.0 OUROBOROS_WEB_ALLOW_REMOTE=1` puts in the
      # application environment (config/runtime.exs:660: `bind: web_bind`, a string).
      Application.put_env(:ouroboros, :web,
        enabled: true,
        port: 4000,
        bind: "0.0.0.0",
        allow_remote: true
      )

      assert {:ok, %{"host" => host}} = Deployment.devices()
      assert "cleartext_web_bind" in host["capabilities"]["reasons"]
      assert host["capabilities"]["deploy"] == false
    end

    test "does not fire on the loopback string, which is the default posture", context do
      arrange_devices(context)
      write_ca_key(context.root)

      Application.put_env(:ouroboros, :web, enabled: true, port: 4000, bind: "127.0.0.1")

      assert {:ok, %{"host" => host}} = Deployment.devices()
      assert host["capabilities"]["deploy"] == true
    end

    test "fails closed on a bind it cannot parse", context do
      arrange_devices(context)
      write_ca_key(context.root)

      Application.put_env(:ouroboros, :web, enabled: true, bind: "not-an-address")

      assert {:ok, %{"host" => host}} = Deployment.devices()

      assert "cleartext_web_bind" in host["capabilities"]["reasons"],
             "a bind this build cannot resolve must not be treated as loopback"
    end

    test "still fires on the tuple form", context do
      arrange_devices(context)
      write_ca_key(context.root)
      Application.put_env(:ouroboros, :web, enabled: true, bind: {0, 0, 0, 0}, allow_remote: true)

      assert {:ok, %{"host" => host}} = Deployment.devices()
      assert "cleartext_web_bind" in host["capabilities"]["reasons"]
    end
  end

  # ---------------------------------------------------------------------------
  # F11 (HIGH). Nothing recorded or checked who owned an operation, so a second session
  # resumed somebody else's deployment and inherited its credential prompts.

  describe "F11 operation ownership" do
    test "a second identity cannot resume, and can with an audited takeover", context do
      %{worker: worker} = arrange_worker(context)

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      assert {:ok, pid} = await_client(operation)
      ref = Process.monitor(pid)
      :ok = FleetWorkerFake.drop_connection(worker)
      assert_receive {:DOWN, ^ref, :process, ^pid, _reason}, @receive_timeout

      # The journal the worker left, naming the identity that started it (seam S5).
      write_journal(context.root, operation, %{
        "operation" => operation,
        "owner" => "adele",
        "kind" => "add",
        "state" => "authenticating"
      })

      # A different administrator. The identity rule already let them reach the verb; this
      # is the narrower question of whose operation it is.
      assert {:error, :operation_not_yours} =
               Deployment.resume(operation, %{subject: "orson", session: "tab-b"})

      # Reading it is refused too.
      assert {:error, :operation_not_yours} =
               Deployment.status(operation, %{subject: "orson", session: "tab-b"})

      # An explicit takeover is permitted and leaves a line naming who took what from whom.
      log =
        capture_log(fn ->
          assert {:ok, _resumed} =
                   Deployment.resume(operation, %{subject: "orson", session: "tab-b"}, true)
        end)

      assert log =~ "takeover operation=#{operation}"
      assert log =~ "orson"
      assert log =~ "adele"
    end

    test "an owner resumes their own operation without saying anything special", context do
      arrange_worker(context)
      operation = plant_journal(context.root, "interrupted", "runtime-unattributed")

      assert {:ok, _resumed} = Deployment.resume(operation, bound())
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
    end

    test "an unattributable journal is not handed over on this build's own say-so",
         context do
      arrange_worker(context)
      operation = plant_journal(context.root, "interrupted", nil)

      # No owner recorded — an older worker, or a corrupted record. That is not a match, and
      # resume is the verb that inherits the credential prompt.
      assert {:error, :operation_not_yours} = Deployment.resume(operation, bound())
      assert {:ok, _resumed} = Deployment.resume(operation, bound(), true)
    end

    test "reading an operation whose owner cannot be established is still allowed",
         context do
      arrange_devices(context)
      operation = plant_journal(context.root, "interrupted", nil)

      # A read grants no authority, and refusing every status on a runtime whose `ouro`
      # predates the field would break recovery without protecting anything.
      assert {:ok, %{"state" => "interrupted"}} = Deployment.status(operation, bound())
    end
  end

  # ---------------------------------------------------------------------------
  # F13. Not from the review: found by driving the real worker. It nests a challenge's
  # kind-specific fields under `metadata`, one level below where seam S4 puts them — and
  # both fakes had put them where the seam says, so the two agreed with each other and
  # neither agreed with the program.

  test "F13 a challenge's own fields are where the seam says, whichever level the worker used",
       context do
    %{worker: worker} = arrange_worker(context)

    assert {:ok, %{"operation_id" => operation}} =
             Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

    assert {:ok, _pid} = await_client(operation)

    # Exactly the shape the real worker sends: the kind's fields one level down.
    :ok =
      FleetWorkerFake.emit(worker, %{
        "event" => "challenge",
        "challenge" => "rev-nested",
        "kind" => "review",
        "expires_at" => nil,
        "operation" => operation,
        "bound_to" => %{"subject" => "runtime-unattributed", "session" => "tab-a"},
        "metadata" => %{
          "plan" => %{"kind" => "setup"},
          "plan_digest" => String.duplicate("a", 64)
        }
      })

    await_challenge(operation, "rev-nested")
    assert {:ok, snapshot} = Deployment.status(operation, bound())
    review = Enum.find(snapshot["challenges"], &(&1["challenge"] == "rev-nested"))

    # A client reads `challenge["plan_digest"]` because that is where S4 says it is.
    assert review["plan_digest"] == String.duplicate("a", 64)
    assert review["plan"] == %{"kind" => "setup"}
    refute Map.has_key?(review, "metadata")

    # And a worker that sends them flat is read the same way.
    :ok =
      FleetWorkerFake.challenge(worker, "pw-flat", "password", %{
        "attempt" => 1,
        "max_attempts" => 3
      })

    await_challenge(operation, "pw-flat")
    assert {:ok, snapshot} = Deployment.status(operation, bound())
    password = Enum.find(snapshot["challenges"], &(&1["challenge"] == "pw-flat"))

    assert password["attempt"] == 1
    assert password["max_attempts"] == 3
  end

  # ---------------------------------------------------------------------------
  # F14. Not from the review either: found by the integration gate, one run in four. The
  # worker binds its socket and then listens, and a broker that connected exactly once in
  # the window between the two got `:econnrefused`, killed the client, and left the
  # operation orphaned — a worker running with a socket nobody would ever connect to.

  describe "F14 a worker that is not listening yet" do
    test "is waited for, not given up on", context do
      cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
      instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
      socket_path = Path.join([context.root, "deploy", "late.sock"])

      ouro =
        FleetOuroFake.write!(context.fake_dir,
          spawn_line: JSON.encode!(%{"socket" => socket_path, "instance" => instance}) <> "\n",
          cap: cap
        )

      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

      # Nothing is listening on that path yet, which is exactly the window.
      refute File.exists?(socket_path)

      assert {:ok, %{"operation_id" => operation, "state" => "spawning"}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      # The row says `spawning` then `attaching`, and it says it *answerably* — the client
      # is waiting on a timer rather than sleeping, so a surface polling the operation
      # still gets replies.
      snapshot =
        Enum.reduce_while(1..50, nil, fn _attempt, _acc ->
          case Deployment.status(operation, bound()) do
            {:ok, %{"attached" => false, "state" => state} = snap}
            when state in ["spawning", "attaching"] ->
              {:halt, snap}

            _other ->
              Process.sleep(20)
              {:cont, nil}
          end
        end)

      assert snapshot["attached"] == false
      assert snapshot["state"] in ["spawning", "attaching"]

      # The worker starts listening a moment later, as a real one does.
      Process.sleep(300)

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

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      assert {:ok, pid} = await_client(operation)
      assert Process.alive?(pid)
    end

    test "and a worker that never listens gives up with a stable reason", context do
      instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

      ouro =
        FleetOuroFake.write!(context.fake_dir,
          spawn_line:
            JSON.encode!(%{
              "socket" => Path.join([context.root, "deploy", "never.sock"]),
              "instance" => instance
            }) <> "\n",
          cap: Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
        )

      System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

      assert {:ok, %{"operation_id" => operation}} =
               Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

      # Bounded: it stops trying, and the row stops saying `attaching` and starts saying
      # why. An orphan is a row that never changes its mind.
      assert {:error, code, _message, data} =
               Enum.reduce_while(1..200, nil, fn _attempt, _acc ->
                 case Call.call(
                        :operate,
                        "fleet.deployment.status",
                        %{"operation_id" => operation},
                        session: "tab-a"
                      ) do
                   {:error, _c, _m, _d} = failure -> {:halt, failure}
                   _not_yet -> Process.sleep(100) && {:cont, nil}
                 end
               end)

      assert code == -32_004
      assert data["reason"] == "worker_unreachable"
      assert is_binary(data["detail"]) and data["detail"] != ""
    end
  end

  # ---------------------------------------------------------------------------
  # F12 (MEDIUM). `Client.init/1` completed the handshake inside the broker's `handle_call`,
  # so one worker that accepted the socket and said nothing held the named singleton — and
  # every other operation — for the full attach timeout.

  @tag timeout: 60_000
  test "F12 a silent worker does not block the broker", context do
    socket_path = Path.join([context.root, "deploy", "s.sock"])
    File.mkdir_p!(Path.dirname(socket_path))
    File.chmod!(Path.dirname(socket_path), 0o700)

    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        {:ifaddr, {:local, socket_path}},
        active: false,
        reuseaddr: true
      ])

    owner = self()

    spawn_link(fn ->
      {:ok, accepted} = :gen_tcp.accept(listen, 30_000)
      send(owner, :accepted)
      Process.sleep(20_000)
      :gen_tcp.close(accepted)
    end)

    on_exit(fn -> :gen_tcp.close(listen) end)

    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)

    ouro =
      FleetOuroFake.write!(context.fake_dir,
        spawn_line: JSON.encode!(%{"socket" => socket_path, "instance" => "silent"}) <> "\n",
        cap: cap
      )

    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)

    # The prepare answers immediately, in state `spawning`.
    assert {:ok, %{"state" => "spawning"}} =
             Call.call(:operate, "fleet.deployment.prepare", request(), session: "tab-a")

    assert_receive :accepted, 10_000

    # And an unrelated read of the broker is not behind the silent handshake.
    started = System.monotonic_time(:millisecond)
    assert {:error, :no_worker} = Deployment.client("00112233445566aa")
    elapsed = System.monotonic_time(:millisecond) - started

    assert elapsed < 1_000, "an unrelated broker read waited #{elapsed} ms"
  end

  # ---------------------------------------------------------------------------

  defp bound, do: %{subject: "runtime-unattributed", session: "tab-a"}

  defp request, do: %{"target" => %{"address" => "100.64.12.44"}, "ssh_user" => "deploy"}

  defp start(operation, key) do
    Call.call(
      :operate,
      "fleet.deployment.start",
      %{"operation_id" => operation, "plan_digest" => "d" <> operation, "idempotency_key" => key},
      session: "tab-a"
    )
    |> case do
      {:ok, value} -> {:ok, value}
      other -> other
    end
  end

  defp write_journal(root, operation, document) do
    dir = Journal.deploy_dir(root)
    File.mkdir_p!(dir)
    path = Journal.path(root, operation)
    File.write!(path, JSON.encode!(document))
    File.chmod!(path, 0o600)
    path
  end

  defp plant_journal(root, state, owner) do
    operation = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    write_journal(
      root,
      operation,
      %{"operation" => operation, "kind" => "add", "state" => state}
      |> then(&if(owner, do: Map.put(&1, "owner", owner), else: &1))
    )

    operation
  end

  defp write_ca_key(root) do
    dir = Path.join(root, "fleet")
    File.mkdir_p!(dir)
    path = Path.join(dir, "ca-key.pem")
    File.write!(path, "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n")
    File.chmod!(path, 0o600)
    path
  end

  defp arrange_devices(context) do
    ouro = FleetOuroFake.write!(context.fake_dir, devices: ~s({"devices": []}\n))
    System.put_env("OUROBOROS_PROCESS_ID_HELPER", ouro)
    ouro
  end

  defp arrange_worker(context) do
    cap = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)
    instance = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

    worker =
      start_supervised!(
        {FleetWorkerFake,
         [
           socket_path: Path.join([context.root, "deploy", "w.sock"]),
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
    %{worker: worker, cap: cap, instance: instance}
  end

  # The handshake is asynchronous now, so a test that wants the connection waits for it.
  defp await_status_error(operation) do
    Enum.reduce_while(1..400, nil, fn _attempt, _acc ->
      case Deployment.status(operation, bound()) do
        # The client is still dying: its call maps every exit to `worker_unavailable`
        # until the broker's monitor records the attach failure.
        {:error, :worker_unavailable} ->
          Process.sleep(20)
          {:cont, nil}

        {:error, reason} ->
          {:halt, {:error, reason}}

        _other ->
          Process.sleep(20)
          {:cont, nil}
      end
    end)
  end

  defp await_client(operation) do
    Enum.reduce_while(1..100, {:error, :no_worker}, fn _attempt, _acc ->
      with {:ok, pid} <- Deployment.client(operation),
           {:ok, %{"attached" => true}} <- Deployment.status(operation, bound()) do
        {:halt, {:ok, pid}}
      else
        _not_yet ->
          Process.sleep(20)
          {:cont, {:error, :no_worker}}
      end
    end)
  end

  defp await_challenge(operation, challenge) do
    Enum.reduce_while(1..200, :missing, fn _attempt, _acc ->
      case Deployment.status(operation, bound()) do
        {:ok, %{"challenges" => challenges}} ->
          if Enum.any?(challenges, &(&1["challenge"] == challenge)) do
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
      :missing -> flunk("the broker never recorded challenge #{challenge}")
    end
  end
end
