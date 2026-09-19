defmodule Ouroboros.Fleet.DeploymentAdversarialTest do
  @moduledoc """
  Slice KE adversarial review. Every test here is a *finding*, not a regression guard: each
  one asserts the behaviour the implementation has today and names in its message the
  behaviour the contract asked for. A test that goes red after a fix is the fix landing.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log
  @moduletag :ke_review

  import ExUnit.CaptureLog

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Fleet.Deployment.Journal
  alias Ouroboros.Fleet.Deployment.Launcher
  alias Ouroboros.Fleet.Deployment.Worker
  alias Ouroboros.Gateway.AuditLine
  alias Ouroboros.Test.FleetFramesFake

  setup do
    root = Path.join(System.tmp_dir!(), "okdadv#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    bin = Path.join(root, "bin")

    previous = %{
      data_dir: Application.get_env(:ouroboros, :data_dir),
      dev_runtime: Application.get_env(:ouroboros, :dev_runtime),
      ouro: System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    }

    Application.put_env(:ouroboros, :data_dir, root)
    Application.put_env(:ouroboros, :dev_runtime, false)

    FleetFramesFake.install!(bin, devices: ~s({"devices":[],"discovery":{"code":"ok"}}\n))

    on_exit(fn ->
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
    Ouroboros.Fleet.Deployment.WorkerSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.each(fn {_id, pid, _type, _modules} ->
      if is_pid(pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.Fleet.Deployment.WorkerSupervisor, pid)
    end)
  catch
    :exit, _not_running -> :ok
  end

  defp await(fun, timeout \\ 3_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_await(fun, deadline)
  end

  defp do_await(fun, deadline) do
    case fun.() do
      {:ok, value} ->
        value

      _not_yet ->
        if System.monotonic_time(:millisecond) < deadline do
          Process.sleep(25)
          do_await(fun, deadline)
        else
          flunk("condition never became true")
        end
    end
  end

  # ---------------------------------------------------------------------------
  # F1 — argv construction
  # ---------------------------------------------------------------------------

  describe "F1 argv/2 under attacker values" do
    test "an ssh_user carrying its own @ reaches the destination word whole" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "pi",
                   "address" => "100.64.0.2",
                   "ssh_user" => "root@attacker.example",
                   "port" => 22
                 },
                 "0123456789abcdef"
               )

      assert Enum.at(argv, 2) == "root@attacker.example@100.64.0.2",
             "`word/2` never refuses an `@`, so the destination word carries two of them " <>
               "and which host is contacted is decided by whichever end the CLI splits on"
    end

    test "a tab inside a word is not one of the four characters `word/2` refuses" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "pi",
                   "address" => "100.64.0.2\tmore",
                   "ssh_user" => "deploy",
                   "port" => 22
                 },
                 "0123456789abcdef"
               )

      assert Enum.at(argv, 2) == "deploy@100.64.0.2\tmore",
             "the multi-word check names \\n \\r \\0 and space; \\t \\v \\f and U+00A0 are " <>
               "not in it"
    end

    test "install_path and data_dir may traverse" do
      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "pi",
                   "address" => "100.64.0.2",
                   "ssh_user" => "deploy",
                   "port" => 22,
                   "install_path" => "../../../../etc/cron.d/ouro",
                   "data_dir" => "../../root/.ssh"
                 },
                 "0123456789abcdef"
               )

      assert "--install-path" in argv and "../../../../etc/cron.d/ouro" in argv
      assert "--data-dir" in argv and "../../root/.ssh" in argv
    end

    test "an identity ref that is a directory is passed as --key" do
      dir = Path.join(System.tmp_dir!(), "okdkey#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf(dir) end)

      assert {:ok, argv} =
               Deployment.argv(
                 %{
                   "kind" => "add",
                   "machine" => "pi",
                   "address" => "100.64.0.2",
                   "ssh_user" => "deploy",
                   "port" => 22,
                   "identity" => %{"kind" => "key", "ref" => dir}
                 },
                 "0123456789abcdef"
               )

      assert ["--key", dir] == Enum.slice(argv, Enum.find_index(argv, &(&1 == "--key")), 2)
    end

    test "the refusals that do hold" do
      base = %{"kind" => "add", "machine" => "pi", "address" => "a", "ssh_user" => "u"}
      id = "0123456789abcdef"

      for {label, request} <- [
            {"machine with a leading hyphen", %{base | "machine" => "-rf"}},
            {"address that is a flag", %{base | "address" => "--machine"}},
            {"ssh_user that is a flag", %{base | "ssh_user" => "--data-dir"}},
            {"address with a newline", %{base | "address" => "a\n--machine"}},
            {"address with a space", %{base | "address" => "a --machine"}},
            {"address with a NUL", %{base | "address" => "a\0b"}},
            {"port 0", Map.put(base, "port", 0)},
            {"port 65536", Map.put(base, "port", 65_536)},
            {"port as a string", Map.put(base, "port", "22")},
            {"kind outside the enum", %{base | "kind" => "nuke"}},
            {"machine over 40 characters", %{base | "machine" => String.duplicate("a", 41)}},
            {"unicode machine", %{base | "machine" => "π"}},
            {"identity kind outside the enum",
             Map.put(base, "identity", %{"kind" => "hsm", "ref" => "x"})}
          ] do
        assert {:error, {:invalid_request, _why}} = Deployment.argv(request, id),
               "#{label} should be refused"
      end
    end
  end

  # ---------------------------------------------------------------------------
  # F2 — OUROBOROS_DATA_DIR for the bounded reads
  # ---------------------------------------------------------------------------

  describe "F2 child_env" do
    test "a bounded read inherits OUROBOROS_DATA_DIR from the OS environment" do
      System.put_env("OUROBOROS_DATA_DIR", "/not/this/runtimes/data/dir")
      on_exit(fn -> System.delete_env("OUROBOROS_DATA_DIR") end)

      env = Launcher.child_env()

      assert {~c"OUROBOROS_DATA_DIR", ~c"/not/this/runtimes/data/dir"} in env,
             "`Launcher.run/3` (fleet devices --json, and every other bounded read) uses " <>
               "`child_env/0`, which stamps nothing: the child is told whatever the daemon " <>
               "happened to inherit rather than `Application.get_env(:ouroboros, :data_dir)`"
    end

    test "a worker's environment does stamp the data dir it was given" do
      env = Launcher.child_env("/the/runtimes/dir")
      assert {~c"OUROBOROS_DATA_DIR", ~c"/the/runtimes/dir"} in env
      assert Enum.count(env, &(elem(&1, 0) == ~c"OUROBOROS_DATA_DIR")) == 1
    end
  end

  # ---------------------------------------------------------------------------
  # F3 — resume rebuilds a different command line
  # ---------------------------------------------------------------------------

  describe "F3 resume after a runtime restart" do
    test "the rebuilt argv silently drops --key and --no-service", context do
      started =
        %{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 2222,
          "identity" => %{"kind" => "key", "ref" => "/home/me/.ssh/deploy_ed25519"},
          "service" => false
        }

      {:ok, first} = Deployment.argv(started, "0123456789abcdef")
      assert "--key" in first
      assert "--no-service" in first

      # What a runtime that restarted has instead: the journal, which §6 gives no field for
      # either the identity or the service.
      journal = %{
        "kind" => "add",
        "target" => %{
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 2222
        },
        "paths" => %{}
      }

      rebuilt_request = %{
        "kind" => journal["kind"],
        "machine" => journal["target"]["machine"],
        "address" => journal["target"]["address"],
        "ssh_user" => journal["target"]["ssh_user"],
        "port" => journal["target"]["port"],
        "install_path" => journal["paths"]["install_path"],
        "data_dir" => journal["paths"]["data_dir"]
      }

      {:ok, second} = Deployment.argv(rebuilt_request, "0123456789abcdef")

      refute "--key" in second,
             "the identity is gone, so the resume authenticates as somebody else"

      refute "--no-service" in second,
             "the operator declined a startup service; the resume installs one"

      # And nothing in the reply says so. `resume/1` answers `{operation}` and no more.
      _ = context
    end

    test "the whole loop: a real resume off the journal drops --no-service", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step inspect ok reachable",
        "error connect_failed the target refused the connection",
        "state failed",
        "done failed could not connect"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22,
          "identity" => %{"kind" => "key", "ref" => "/home/me/.ssh/id_ed25519"},
          "service" => false
        })

      first_argv = await(fn -> if FleetFramesFake.argv(context.bin) != [], do: {:ok, :yes} end)
      assert first_argv == :yes
      argv_one = FleetFramesFake.argv(context.bin)
      assert "--no-service" in argv_one
      assert "--key" in argv_one

      # Wait for the operation to reach `failed` in the journal and for the worker to go.
      await(fn ->
        case Deployment.status(operation) do
          {:ok, %{"state" => "failed"}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      await(fn ->
        case Deployment.worker(operation) do
          {:error, :no_worker} -> {:ok, :yes}
          _other -> nil
        end
      end)

      # Forget the command line exactly as a restarted runtime would, without touching the
      # journal on disk.
      :sys.replace_state(Deployment, fn state -> %{state | argv: %{}} end)

      FleetFramesFake.write_scenario!(context.bin, ["state running", "done completed ok"])
      assert {:ok, %{"operation" => ^operation}} = Deployment.resume(operation)

      argv_two =
        await(fn ->
          current = FleetFramesFake.argv(context.bin)
          if current != argv_one, do: {:ok, current}
        end)

      refute "--no-service" in argv_two,
             "a resume of an operation the operator started with `service: false` installs " <>
               "a startup service on their machine, and the answer to `.resume` says nothing"

      refute "--key" in argv_two
    end
  end

  # ---------------------------------------------------------------------------
  # F4 — the broker's argv map grows without bound
  # ---------------------------------------------------------------------------

  describe "F4 broker state" do
    test "every operation ever started keeps its argv forever", context do
      FleetFramesFake.write_scenario!(context.bin, ["state running", "done completed ok"])

      ids =
        for n <- 1..6 do
          {:ok, %{"operation" => id}} =
            Deployment.start(%{
              "kind" => "add",
              "machine" => "pi#{n}",
              "address" => "100.64.0.#{n}",
              "ssh_user" => "deploy",
              "port" => 22
            })

          id
        end

      # Wait for every worker to be gone: `operations` empties, `exits` is capped at 32.
      await(
        fn ->
          state = :sys.get_state(Deployment)
          if state.operations == %{}, do: {:ok, state}
        end,
        8_000
      )

      state = :sys.get_state(Deployment)

      # `state.operations` empties and `state.exits` is capped at 32. `state.argv` is capped
      # by nothing at all — and because the broker is a runtime-lifetime singleton, the map
      # already carries every operation every earlier case in this run started.
      assert map_size(state.argv) >= 6
      for id <- ids, do: assert(Map.has_key?(state.argv, id))
      assert map_size(state.exits) <= 32

      flunk(
        "`state.argv` is written by `open/4` and deleted by nothing: not on `:DOWN`, not " <>
          "by `trim_exits/2`, not by `retain/1`, not when the journal is pruned. It holds " <>
          "#{map_size(state.argv)} command lines after this case, against " <>
          "#{map_size(state.operations)} live operations and a capped " <>
          "#{map_size(state.exits)} remembered exits. Each entry is a full argv including " <>
          "`--key <path>` and the SSH destination."
      )
    end
  end

  # ---------------------------------------------------------------------------
  # F5 — the worker's crash reason reaches the broker's log
  # ---------------------------------------------------------------------------

  describe "F5 a worker that crashes holding a secret" do
    test "the broker logs the raw exit reason, which carries the call arguments", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {\"user\":\"deploy\",\"target\":\"100.64.0.2\"}",
        "await secret-1",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "secret-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      secret = "sentinel-#{System.unique_integer([:positive])}-hunter2"

      log =
        capture_log(fn ->
          # A message shaped like a respond that no `handle_call/3` clause matches. The
          # module's two belts — `:sensitive` and `format_status/1` — are aimed at the
          # crash dump and at OTP's own terminate report. Neither touches the exit reason,
          # and the broker interpolates that reason into a log line on `:DOWN`.
          catch_exit(GenServer.call(pid, {:respond, "secret-1", %{"secret" => secret}, :extra}))
          Process.sleep(400)
        end)

      refute log =~ secret,
             "a crash while a secret is an argument of the failing call must not put the " <>
               "secret in the daemon log; `Deployment.handle_info/2`'s " <>
               "`inspect(reason)` is where it lands"
    end

    test "a SIGKILL with the secret genuinely in flight leaks nothing", context do
      # The literal scenario: the program is not reading its stdin, the write blocks in
      # `Port.command/2` with the secret as an argument, and the process is killed there.
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {}",
        "sleep 10"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "secret-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      # Past the 64 KiB pipe buffer of a program that never reads, and under the frame cap.
      secret = "inflight-#{System.unique_integer([:positive])}-" <> String.duplicate("x", 300_000)

      log =
        capture_log(fn ->
          caller = spawn(fn -> Worker.respond(pid, "secret-1", %{"secret" => secret}) end)
          Process.sleep(200)
          Process.exit(pid, :kill)
          Process.sleep(400)
          Process.exit(caller, :kill)
        end)

      refute log =~ "inflight-", "a SIGKILL must not print the argument being written"
      assert log =~ "lost its worker: :killed"
    end

    test "the belts cover the report's message and state, and not its stacktrace", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {}",
        "await secret-1",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      marker = "marker-#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          catch_exit(GenServer.call(pid, {:respond, "c", %{"secret" => marker}, :extra}))
          Process.sleep(400)
        end)

      # The two belts the moduledoc names do hold exactly where it says they do.
      assert log =~ "Last message (from", "the terminate report was written"
      assert log =~ ":redacted", "`format_status/1` replaced the message and the state"

      # And the stacktrace, which neither belt touches, prints the argument list in full.
      assert log =~ marker,
             "an Erlang `function_clause` stacktrace carries the real arguments, so the " <>
               "raised exception and the exit reason both name the secret even though " <>
               "`:sensitive` and `format_status/1` scrubbed the mailbox and the state"

      assert log =~ "handle_call({:respond,"
    end
  end

  # ---------------------------------------------------------------------------
  # F6 — Logger injection through the client's own `challenge`
  # ---------------------------------------------------------------------------

  describe "F6 log injection" do
    test "a newline in `challenge` forges a line in the worker's audit log", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "trust-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      forged = "trust-1\ngateway operate fleet.deployment.respond params=redacted FORGED"

      log =
        capture_log(fn ->
          Worker.respond(pid, forged, %{"accept" => true})
          Process.sleep(100)
        end)

      refute log =~ "FORGED",
             "`Worker.audit/3` interpolates the caller's own `challenge` string into a " <>
               "Logger line without stripping control characters"
    end

    test "AuditLine.params lets a newline through into the audit line" do
      line =
        AuditLine.params("fleet.deployment.respond", %{
          "operation" => "0123456789abcdef",
          "challenge" => "c\nweb operate fleet.deployment.start params=deadbeefdeadbeef FORGED",
          "secret" => "never"
        })
        |> IO.iodata_to_binary()

      refute line =~ "\n",
             "`scalar/1` caps at 128 characters and does nothing else, so an allowlisted " <>
               "key is a way to write whole lines into the operator's log"

      refute line =~ "never"
    end
  end

  # ---------------------------------------------------------------------------
  # F7 — the journal projection carries terminal escapes and credential text
  # ---------------------------------------------------------------------------

  describe "F7 journal projection" do
    test "last_error.detail keeps its ANSI escapes", context do
      operation = "adversarial0001"
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)

      spoof = "\e[2J\e[1;31mSPOOFED: your fleet is compromised\e[0m"

      File.write!(
        Path.join(deploy, operation <> ".json"),
        JSON.encode!(%{
          "schema" => 2,
          "operation" => operation,
          "kind" => "add",
          "state" => "failed",
          "steps" => [%{"step" => "install", "state" => "failed", "detail" => spoof}],
          "plan" => [spoof],
          "last_error" => %{"reason" => "install_failed", "detail" => spoof}
        })
      )

      assert {:ok, document} = Journal.read(context.root, operation)

      assert document["last_error"]["detail"] =~ "\e[",
             "`sanitize/1` bounds and drops credential-named keys but never strips control " <>
               "characters; `scrub_line/2` (which does) is applied to the stderr tail only"

      assert hd(document["steps"])["detail"] =~ "\e["
      assert hd(document["plan"]) =~ "\e["
    end

    test "a credential in a journal *value* is not redacted the way one in a log line is",
         context do
      operation = "adversarial0002"
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)

      leak = "sshpass -p hunter2 ssh deploy@100.64.0.2"

      File.write!(
        Path.join(deploy, operation <> ".json"),
        JSON.encode!(%{
          "schema" => 2,
          "operation" => operation,
          "kind" => "add",
          "state" => "failed",
          "last_error" => %{"reason" => "ssh_failed", "detail" => leak}
        })
      )

      assert {:ok, document} = Journal.read(context.root, operation)

      # The same text as a log line is refused outright.
      assert Journal.scrub_line(leak, 300) == "[redacted credential-bearing diagnostic]"

      assert document["last_error"]["detail"] == "[redacted credential-bearing diagnostic]",
             "the four free-text secret shapes are matched in `scrub_line/2` and nowhere " <>
               "else, so the journal's own strings pass through whole"
    end

    test "the bounds that do hold", context do
      operation = "adversarial0003"
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)
      path = Path.join(deploy, operation <> ".json")

      deep = Enum.reduce(1..50, "bottom", fn _n, acc -> %{"next" => acc} end)

      File.write!(
        path,
        JSON.encode!(%{
          "schema" => 2,
          "operation" => operation,
          "kind" => "add",
          "state" => "running",
          "owner" => "a name §1 deleted",
          "roster" => ["also deleted"],
          "plan_digest" => "and this",
          "steps" => for(n <- 1..10_000, do: %{"step" => "s#{n}", "state" => "ok"}),
          "target" => %{
            "machine" => String.duplicate("m", 100_000),
            "cookie" => "session=abc",
            "nested" => %{"password" => "hunter2"}
          },
          "residue" => [deep]
        })
      )

      assert {:ok, document} = Journal.read(context.root, operation)
      assert length(document["steps"]) == 200
      assert String.length(document["target"]["machine"]) == 2_000

      # §6's field list and nothing else: the two names §9 and §1 deleted cannot come back
      # by a journal carrying them.
      refute Map.has_key?(document, "owner")
      refute Map.has_key?(document, "roster")
      refute Map.has_key?(document, "plan_digest")

      refute Map.has_key?(document["target"], "cookie")
      refute Map.has_key?(document["target"]["nested"], "password")
      assert inspect(document["residue"]) =~ "truncated: nested deeper than"

      # Over the cap and a symlink are both refused.
      File.write!(path, String.duplicate("x", 1024 * 1024 + 1))

      assert {:error, {:journal_unreadable, :not_a_regular_file_or_too_large}} =
               Journal.read(context.root, operation)

      link = Path.join(deploy, "adversarial0004.json")
      File.rm(link)
      File.ln_s!(path, link)

      assert {:error, {:journal_unreadable, :not_a_regular_file_or_too_large}} =
               Journal.read(context.root, "adversarial0004")
    end
  end

  # ---------------------------------------------------------------------------
  # F8 — the port lifecycle
  # ---------------------------------------------------------------------------

  describe "F8 port lifecycle" do
    test "a line over the cap is one fault, not two frames", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "bigline",
        "step install ok after the oversize line",
        # The program stays up, so the snapshot below is the worker's and not the journal's.
        "sleep 5",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      # Generous: the fake writes its 1 MiB line one character at a time in `awk`.
      snapshot =
        await(
          fn ->
            case Worker.snapshot(pid) do
              {:ok, %{"steps" => [_one | _rest]} = snapshot} -> {:ok, snapshot}
              _other -> nil
            end
          end,
          20_000
        )

      assert snapshot["last_error"]["reason"] == "worker_frame_too_large"
      assert length(snapshot["steps"]) == 1, "the tail of the oversize line is not a frame"
      assert hd(snapshot["steps"])["step"] == "install"
    end

    test "killing the worker leaves the program running and the broker forgets it", context do
      marker = Path.join(context.root, "survived")

      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "step install ok -"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "trust-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      Process.exit(pid, :kill)

      await(fn ->
        case Deployment.worker(operation) do
          {:error, :no_worker} -> {:ok, :yes}
          _other -> nil
        end
      end)

      # The program read stdin EOF and finished, writing the step it was about to write.
      journal =
        await(
          fn ->
            case FleetFramesFake.journal(context.root, operation) do
              %{"steps" => [_ | _]} = document -> {:ok, document}
              _other -> nil
            end
          end,
          5_000
        )

      assert hd(journal["steps"])["step"] == "install"
      _ = marker

      assert {:ok, %{"source" => "journal", "running" => false}} = Deployment.status(operation)
    end

    test "two starts for the same target run two programs", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1"
      ])

      request = %{
        "kind" => "add",
        "machine" => "pi",
        "address" => "100.64.0.2",
        "ssh_user" => "deploy",
        "port" => 22
      }

      assert {:ok, %{"operation" => first}} = Deployment.start(request)
      assert {:ok, %{"operation" => second}} = Deployment.start(request)
      assert first != second

      await(fn ->
        with {:ok, _a} <- Deployment.worker(first), {:ok, _b} <- Deployment.worker(second) do
          {:ok, :yes}
        else
          _not_yet -> nil
        end
      end)

      flunk(
        "nothing in the broker or the gateway refuses a second `start` against a machine " <>
          "an operation is already deploying to: #{first} and #{second} are both live " <>
          "`ouro fleet add deploy@100.64.0.2 --machine pi`"
      )
    end
  end

  # ---------------------------------------------------------------------------
  # F8b — resume starts a second program for an operation that is still running
  # ---------------------------------------------------------------------------

  describe "F8b resume against a live program" do
    test "a resume after the worker is gone runs a second program for one operation",
         context do
      # §8's program survives its worker: on stdin EOF it finishes the operation and keeps
      # writing the journal. `resume/1` refuses `already_attached` only out of the broker's
      # own in-memory registry, which a restarted runtime — and `orphans/1` — has emptied.
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "sleep 3",
        "step install ok the first program finished its work",
        "done completed the first program"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "trust-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      os_pid = :sys.get_state(pid).os_pid
      assert is_integer(os_pid)

      # Exactly what `Deployment.init/1`'s `orphans/1` does to every worker a restarted
      # broker inherits, and what `terminate/2` is written for.
      :ok = DynamicSupervisor.terminate_child(Ouroboros.Fleet.Deployment.WorkerSupervisor, pid)

      await(fn ->
        case Deployment.worker(operation) do
          {:error, :no_worker} -> {:ok, :yes}
          _other -> nil
        end
      end)

      assert alive?(os_pid),
             "§8's program is meant to outlive its worker; if it did not, this test proves " <>
               "nothing and the port lifecycle is the finding instead"

      # The journal still says `running`, which is what makes it resumable.
      assert {:ok, %{"state" => "running", "running" => false}} = Deployment.status(operation)

      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "step install ok the SECOND program",
        "done completed the second program"
      ])

      assert {:ok, %{"operation" => ^operation}} = Deployment.resume(operation),
             "resume is refused only by the broker's own registry, so it cannot see the " <>
               "program that is still running"

      second =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, second} -> {:ok, second}
            _other -> nil
          end
        end)

      assert :sys.get_state(second).os_pid != os_pid

      assert alive?(os_pid),
             "two `ouro fleet add … --operation #{operation}` processes are now running " <>
               "against one machine and writing one journal file"
    end

    test "resume of a finished operation, an unknown id and a malformed id", context do
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)

      File.write!(
        Path.join(deploy, "adversarial0009.json"),
        JSON.encode!(%{
          "schema" => 2,
          "operation" => "adversarial0009",
          "kind" => "add",
          "state" => "completed"
        })
      )

      File.write!(
        Path.join(deploy, "adversarial0010.json"),
        JSON.encode!(%{"schema" => 2, "operation" => "adversarial0010", "kind" => "add"})
      )

      assert {:error, :operation_finished} = Deployment.resume("adversarial0009")
      assert {:error, :operation_state_unknown} = Deployment.resume("adversarial0010")
      assert {:error, :unknown_operation} = Deployment.resume("adversarial0011")
      assert {:error, :invalid_operation} = Deployment.resume("../../etc/passwd")
      assert {:error, :invalid_operation} = Deployment.resume("UPPERCASE1234")
      assert {:error, :invalid_operation} = Deployment.resume("short")
    end
  end

  defp alive?(os_pid) do
    {_out, status} =
      System.cmd("/bin/kill", ["-0", Integer.to_string(os_pid)], stderr_to_stdout: true)

    status == 0
  end

  # ---------------------------------------------------------------------------
  # F9 — challenges
  # ---------------------------------------------------------------------------

  describe "F9 challenges" do
    setup context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {\"user\":\"deploy\"}",
        "await secret-1",
        "challenge review-1 review {\"plan\":[\"Install ouro\"]}",
        "await review-1",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "secret-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      %{operation: operation, pid: pid}
    end

    test "accept to a password is a kind mismatch and is never written", context do
      assert {:error, :challenge_kind_mismatch} =
               Worker.respond(context.pid, "secret-1", %{"accept" => true})

      assert FleetFramesFake.responses(context.bin) == []
    end

    test "a secret to a review is a kind mismatch", context do
      assert {:ok, _accepted} =
               Worker.respond(context.pid, "secret-1", %{"secret" => "hunter2"})

      await(fn ->
        case Worker.snapshot(context.pid) do
          {:ok, %{"challenge" => %{"challenge" => "review-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      assert {:error, :challenge_kind_mismatch} =
               Worker.respond(context.pid, "review-1", %{"secret" => "hunter2"})
    end

    test "answering twice is challenge_consumed, and an id nobody issued is unknown",
         context do
      assert {:ok, _accepted} =
               Worker.respond(context.pid, "secret-1", %{"secret" => "hunter2"})

      assert {:error, :challenge_consumed} =
               Worker.respond(context.pid, "secret-1", %{"secret" => "again"})

      assert {:error, :unknown_challenge} =
               Worker.respond(context.pid, "never-issued", %{"secret" => "x"})
    end

    test "the secret reaches the program's stdin exactly once", context do
      assert {:ok, _accepted} =
               Worker.respond(context.pid, "secret-1", %{"secret" => "hunter2"})

      lines =
        await(fn ->
          case FleetFramesFake.responses(context.bin) do
            [_one | _rest] = lines -> {:ok, lines}
            _other -> nil
          end
        end)

      assert Enum.count(lines, &(&1 =~ "hunter2")) == 1
    end
  end

  describe "F9b an expired challenge" do
    test "a secret typed after expires_at is refused before it is written", context do
      System.put_env("OUROBOROS_FAKE_EXPIRES", "2000-01-01T00:00:00Z")
      on_exit(fn -> System.delete_env("OUROBOROS_FAKE_EXPIRES") end)

      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {}",
        "await secret-1",
        "done completed ok"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "secret-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      assert {:error, :challenge_expired} =
               Worker.respond(pid, "secret-1", %{"secret" => "too-late"})

      assert FleetFramesFake.responses(context.bin) == []

      # And it stays refused rather than becoming `challenge_consumed`.
      assert {:error, :challenge_expired} =
               Worker.respond(pid, "secret-1", %{"secret" => "too-late"})
    end
  end

  # ---------------------------------------------------------------------------
  # F10 — the secret is not in any process's state
  # ---------------------------------------------------------------------------

  describe "F10 where the secret is not" do
    test "not in the worker's state, mailbox or :sys.get_status", context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge secret-1 password {}",
        "await secret-1",
        "sleep 5"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "secret-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      secret = "sentinel-#{System.unique_integer([:positive])}"
      assert {:ok, _ok} = Worker.respond(pid, "secret-1", %{"secret" => secret})

      refute inspect(:sys.get_state(pid), limit: :infinity) =~ secret
      refute inspect(:sys.get_status(pid), limit: :infinity) =~ secret
      refute inspect(Process.info(pid, :messages), limit: :infinity) =~ secret
      refute inspect(Process.info(pid, :dictionary), limit: :infinity) =~ secret
      refute inspect(:sys.get_state(Deployment), limit: :infinity) =~ secret
    end
  end

  # ---------------------------------------------------------------------------
  # F11 — fleet.devices (§9's row)
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # F10b — what a worker does with the frames it is given
  #
  # Both cases below are mutations the slice's own suite does not kill: removing the
  # `@states` guard from `put_state/2`, and dropping `Journal.scrub_line/2` from
  # `put_log/2`. The second is where the whole terminal-escape defence lives for a live
  # operation, because a journal answer's log comes from a different function entirely.
  # ---------------------------------------------------------------------------

  describe "F10b frames in" do
    setup context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        # Not one of §8's five. The program is this runtime's own `ouro`, so a state outside
        # them is a mismatched installation, not a new value to render.
        "raw {\"event\":\"state\",\"state\":\"<script>alert(1)</script>\"}",
        "log \\u001b[2J\\u001b[1;31mSPOOFED: your fleet is compromised\\u001b[0m",
        "log sshpass -p hunter2 ssh deploy@100.64.0.2",
        "raw {\"event\":\"log\",\"line\":\"a line with a newline \\u000a and a tab \\u0009\"}",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "sleep 6"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      snapshot =
        await(fn ->
          case Worker.snapshot(pid) do
            {:ok, %{"log" => log} = snapshot} when length(log) >= 3 -> {:ok, snapshot}
            _other -> nil
          end
        end)

      %{operation: operation, pid: pid, snapshot: snapshot}
    end

    test "a state outside §8's five does not become the operation's state", context do
      assert context.snapshot["state"] in ~w(running waiting completed failed cancelled)
      refute context.snapshot["state"] =~ "script"
    end

    test "a worker answer says `running` from the port it actually holds", context do
      # §9 replaces `owner`/`attached` with this one boolean, and it is the difference
      # between "this is happening" and "this is what was last written down".
      assert context.snapshot["source"] == "worker"
      assert context.snapshot["running"] == true

      # Wait for the challenge, so the refusal below is `write/2`'s and not `authorize/3`'s.
      await(fn ->
        case Worker.snapshot(context.pid) do
          {:ok, %{"challenge" => %{"challenge" => "trust-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      # Same process, no port: the field follows the port and not the process.
      :sys.replace_state(context.pid, fn state -> %{state | port: nil} end)
      assert {:ok, %{"running" => false, "source" => "worker"}} = Worker.snapshot(context.pid)

      # And an answer with no port to write it to is refused rather than reported accepted.
      assert {:error, :worker_unavailable} =
               Worker.respond(context.pid, "trust-1", %{"accept" => true})
    end

    test "a log frame is stripped of escapes, controls and credential shapes", context do
      log = context.snapshot["log"]

      for line <- log do
        refute line =~ "\e", "an escape survived: #{inspect(line)}"
        refute line =~ "\n", "a newline survived: #{inspect(line)}"
        # Sequences go whole, so no `[1;31m` is left behind where the escape used to be.
        # The words between them stay, which is the documented intent.
        refute line =~ "[2J", "an escape's tail survived: #{inspect(line)}"
        refute line =~ "[1;31m", "an escape's tail survived: #{inspect(line)}"
      end

      assert Enum.any?(log, &(&1 == "SPOOFED: your fleet is compromised")),
             "the sentence itself is kept, stripped of the colour it chose"

      assert Enum.any?(log, &(&1 == "[redacted credential-bearing diagnostic]")),
             "the sshpass line reached a subscriber as itself: #{inspect(log)}"

      # Every line is bounded at the 300 the worker asks for.
      for line <- log, do: assert(String.length(line) <= 300)
    end
  end

  # ---------------------------------------------------------------------------
  # F12 — cancel answers neither §9's `{state}` nor the residue its own text promises
  # ---------------------------------------------------------------------------

  describe "F12 cancel and residue" do
    test "the reply has no state and no residue, and no status answer carries one either",
         context do
      FleetFramesFake.write_scenario!(context.bin, [
        "state running",
        "challenge trust-1 host_trust {}",
        "await trust-1",
        "sleep 6"
      ])

      {:ok, %{"operation" => operation}} =
        Deployment.start(%{
          "kind" => "add",
          "machine" => "pi",
          "address" => "100.64.0.2",
          "ssh_user" => "deploy",
          "port" => 22
        })

      pid =
        await(fn ->
          case Deployment.worker(operation) do
            {:ok, pid} -> {:ok, pid}
            _other -> nil
          end
        end)

      await(fn ->
        case Worker.snapshot(pid) do
          {:ok, %{"challenge" => %{"challenge" => "trust-1"}}} -> {:ok, :yes}
          _other -> nil
        end
      end)

      assert {:ok, reply} = Deployment.cancel(operation)

      # §9's table: `fleet.deployment.cancel` | operate | `operation` | `{state}`.
      assert Map.has_key?(reply, "state"),
             "the reply is #{inspect(reply)}; §9 says the answer is `{state}` and the " <>
               "contract text says it reports residue"

      assert Map.has_key?(reply, "residue")
    end

    test "a journal that records residue does not put it in the status answer", context do
      operation = "adversarial0020"
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)

      File.write!(
        Path.join(deploy, operation <> ".json"),
        JSON.encode!(%{
          "schema" => 2,
          "operation" => operation,
          "kind" => "add",
          "state" => "cancelled",
          "residue" => ["a partial install at /usr/local/bin/ouro.partial"]
        })
      )

      # `Journal.sanitize/1` keeps it — `residue` is in §6's field list and in `@fields`.
      assert {:ok, document} = Journal.read(context.root, operation)
      assert document["residue"] == ["a partial install at /usr/local/bin/ouro.partial"]

      assert {:ok, status} = Deployment.status(operation)

      assert Map.has_key?(status, "residue"), """
      `Deployment.journal_status/1` projects ten keys and `residue` is not one of them, and
      `Worker.view/1` has none either. So the only thing that ever fills the page's
      "What this left behind" panel (devices_live.ex:1953) is `reply["residue"]` from a
      cancel — and `Worker.cancel/1` answers `%{"cancelling" => true}`. The panel cannot be
      drawn by any path. Status keys: #{inspect(Map.keys(status))}
      """
    end
  end

  describe "F11 fleet.devices" do
    test "capabilities.reasons keeps §9's order and dev_runtime is setup-only", context do
      Application.put_env(:ouroboros, :dev_runtime, true)

      assert %{"capabilities" => %{"deploy" => false, "reasons" => reasons}} =
               Deployment.host(context.root)

      assert reasons == ["dev_runtime"]
      assert Deployment.unblocked("add") == :ok
      assert Deployment.unblocked("leave") == :ok
      assert {:error, {:deploy_blocked, ["dev_runtime"]}} = Deployment.unblocked("setup")

      # A kind this build cannot name is *not* exempt, which is the safe direction.
      assert Deployment.unblocked("something-new") == :ok

      assert Deployment.exempt(["dev_runtime", "no_data_dir"], "setup") ==
               ["dev_runtime", "no_data_dir"]

      assert Deployment.exempt(["dev_runtime", "no_data_dir"], "add") == ["no_data_dir"]
    end

    test "operations is cut at 200 with the total beside it, and unknown names the rest",
         context do
      deploy = Journal.deploy_dir(context.root)
      File.mkdir_p!(deploy)

      for n <- 1..205 do
        id = "adv" <> String.pad_leading(Integer.to_string(n), 6, "0")

        File.write!(
          Path.join(deploy, id <> ".json"),
          JSON.encode!(%{
            "schema" => 2,
            "operation" => id,
            "kind" => "add",
            "state" => "failed",
            "created_at" =>
              "2026-09-#{String.pad_leading(Integer.to_string(rem(n, 28) + 1), 2, "0")}T00:00:00Z",
            "target" => %{
              "machine" => "pi",
              "address" => "100.64.0.2",
              "ssh_user" => "deploy",
              "port" => 22
            },
            # Keys §6 does not name never reach a client, so neither `owner` nor `attached`
            # can come back on an operation row.
            "owner" => "somebody",
            "attached" => true
          })
        )
      end

      FleetFramesFake.write_devices!(context.bin, %{
        "devices" => [
          %{"machine" => "pi", "issuer" => "old", "owner" => "someone", "attached" => true}
        ],
        "discovery" => %{"code" => "ok"},
        "issuer" => "a top-level key this build does not read",
        "something_new" => 1
      })

      assert {:ok, inventory} = Deployment.devices(data_dir: context.root)

      assert length(inventory["operations"]) == 200
      assert inventory["operations_total"] == 205
      assert inventory["unknown"] == ["issuer", "something_new"]

      row = hd(inventory["operations"])
      refute Map.has_key?(row, "owner")
      refute Map.has_key?(row, "attached")
      assert Map.has_key?(row, "running")
      assert row["target"]["machine"] == "pi"

      # A *device* row is `ouro fleet devices --json` verbatim, so anything the binary
      # prints inside one comes straight through — including the three names §9 and §12 say
      # the answer loses.
      device = hd(inventory["devices"])

      assert device["issuer"] == "old" and device["owner"] == "someone" and
               device["attached"] == true,
             "§12 says `fleet.devices` loses `issuer`; it is dropped at the top level and " <>
               "passed through inside a device row"
    end
  end
end
