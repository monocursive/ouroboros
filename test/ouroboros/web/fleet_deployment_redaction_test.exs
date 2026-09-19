defmodule Ouroboros.Web.FleetDeploymentRedactionTest do
  @moduledoc """
  The one place a deployment secret crosses this runtime.

  The spec's "Secret handling and authorization" section is a single list of places a
  password or passphrase may never appear, and it names `Web.Call` and gateway parameter
  digests among them — *even hashed*. So this asserts two different things, because either
  one alone would be a comfortable lie:

    * **Instrumentation.** `Ouroboros.Gateway.AuditLine.digest/2` emits a telemetry event
      before it returns. Driving `fleet.deployment.respond` with a unique secret must produce
      no digest event for that method at all, and no emitted digest may equal the digest
      those exact parameters would have produced. That is a statement about the hashing
      function's inputs rather than about the log's contents.
    * **The log itself.** A unique secret must not appear in any captured line, on the
      success path, the refusal path or the failure path, through either surface.

  A test that only searched the log would pass against a build that hashed the password into
  it, which is the failure mode the spec calls out by name.

  What is *not* asserted any more is a session binding. §10 of
  `docs/proposals/fleet-kiss.md` deletes it: a challenge is answered by whoever is an
  administrator on this runtime, so `session_unbound` and `challenge_not_bound` are gone and
  the refusal a second caller gets is about the *challenge* rather than about who they are.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Fleet.Deployment
  alias Ouroboros.Gateway.AuditLine
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Test.FleetFramesFake
  alias Ouroboros.Web.Call

  @method "fleet.deployment.respond"
  @token String.duplicate("r", 40)
  @receive_timeout 5_000

  setup do
    start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})
    start_supervised!({Task.Supervisor, name: :redaction_test_tasks})
    start_supervised!({DynamicSupervisor, strategy: :one_for_one, name: :redaction_test_conns})

    root = Path.join(System.tmp_dir!(), "orw2b#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    bin = Path.join(root, "bin")

    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
    previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    Application.put_env(:ouroboros, :data_dir, root)
    FleetFramesFake.install!(bin, devices: ~s({"devices":[]}\n))

    on_exit(fn ->
      reap_workers()
      Process.sleep(150)
      FleetFramesFake.uninstall!()

      if previous_data_dir,
        do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
        else: Application.delete_env(:ouroboros, :data_dir)

      if previous_ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      _ = File.rm_rf(root)
    end)

    %{root: root, bin: bin}
  end

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
  # The rule itself

  describe "the redaction rule" do
    test "names exactly one method, and it is the one that carries a credential" do
      assert AuditLine.redacted() == [@method]
      assert AuditLine.redacted?(@method)
      refute AuditLine.redacted?("fleet.deployment.start")
      refute AuditLine.redacted?("interactive.start")
    end

    test "the redacted line names the operation and the challenge, and nothing else" do
      line =
        AuditLine.params(@method, %{
          "operation" => "0011223344556677",
          "challenge" => "pw-1",
          "secret" => "a-very-unique-secret-value"
        })
        |> IO.iodata_to_binary()

      assert line == "redacted operation=0011223344556677 challenge=pw-1"
      refute line =~ "a-very-unique-secret-value"
    end

    test "an allowlisted key of an unexpected shape is named rather than printed" do
      line =
        AuditLine.params(@method, %{"operation" => %{"nested" => "surprise"}, "challenge" => nil})
        |> IO.iodata_to_binary()

      assert line == "redacted operation=unreadable challenge=absent"
      refute line =~ "surprise"
    end

    test "every other method still gets the digest both surfaces have always written" do
      params = %{"id" => "s-1", "command" => "ls"}
      assert AuditLine.params("workspace.exec", params) == AuditLine.digest(params)
    end

    test "Phoenix's own parameter filter covers both credential words" do
      filtered =
        Phoenix.Logger.filter_values(%{
          "password" => "p",
          "passphrase" => "q",
          "secret" => "r",
          "ssh_user" => "deploy"
        })

      assert filtered == %{
               "password" => "[FILTERED]",
               "passphrase" => "[FILTERED]",
               "secret" => "[FILTERED]",
               "ssh_user" => "deploy"
             }
    end
  end

  # ---------------------------------------------------------------------------
  # Instrumentation

  describe "the digest never receives the secret" do
    test "no digest event is emitted for the respond method, on any outcome", context do
      secret = "instrumented-secret-#{System.unique_integer([:positive])}"
      params = %{"operation" => "00aa11bb22cc33dd", "challenge" => "pw-1", "secret" => secret}

      # Computed before the probe is attached, so this call is not one of the samples. If
      # anything on the respond path ever hashes these parameters, this is the value that
      # would come out of it.
      forbidden = AuditLine.digest(params)
      events = probe()

      # Three outcomes, one method: an operation that does not exist, a malformed one, and
      # one whose data directory is gone. None of them may reach the digest.
      assert {:error, _code, _message, _data} = web_call(params)
      assert {:error, _code, _message, _data} = web_call(%{params | "operation" => "zzzz"})

      Application.delete_env(:ouroboros, :data_dir)
      assert {:error, _code, _message, _data} = web_call(params)
      Application.put_env(:ouroboros, :data_dir, context.root)

      samples = collect(events)

      refute Enum.any?(samples, &(&1.method == @method)),
             "the audit digest was computed for #{@method}"

      refute Enum.any?(samples, &(&1.digest == forbidden)),
             "the digest of the parameters carrying the secret was emitted"
    end

    test "the probe is not inert: an ordinary operate method does reach the digest" do
      events = probe()

      assert {:error, _code, _message} = Call.call(:operate, "permissions.add", %{})

      samples = collect(events)
      assert Enum.any?(samples, &(&1.method == "permissions.add"))
    end
  end

  # ---------------------------------------------------------------------------
  # The log

  describe "the secret in the log" do
    test "is absent on the success path, through the browser surface", context do
      FleetFramesFake.write_scenario!(context.bin, password_scenario())
      secret = "web-success-secret-#{System.unique_integer([:positive])}"

      operation = start_add()
      await_challenge(operation, "pw")

      log =
        capture_log(fn ->
          assert {:ok, %{"accepted" => true}} =
                   web_call(%{"operation" => operation, "challenge" => "pw", "secret" => secret})
        end)

      # It arrived, which is what makes the absences below evidence rather than a tautology.
      assert Enum.any?(FleetFramesFake.responses(context.bin), &String.contains?(&1, secret))

      refute log =~ secret
      assert log =~ "web operate #{@method} params=redacted"
      assert log =~ "operation=#{operation}"
      assert log =~ "challenge=pw"
      # The kind and the outcome are logged by the process that knows them.
      assert log =~ "kind=password"
      assert log =~ "outcome=sent"
    end

    test "is absent on a refusal, through the listener", context do
      FleetFramesFake.write_scenario!(context.bin, password_scenario())
      secret = "listener-refused-secret-#{System.unique_integer([:positive])}"

      client = connected(:operate)
      operation = call(client, "fleet.deployment.start", request())["result"]["operation"]
      await_challenge(operation, "pw")

      log =
        capture_log(fn ->
          error =
            call(client, @method, %{
              "operation" => operation,
              "challenge" => "not-the-open-one",
              "secret" => secret
            })["error"]

          assert error["data"]["reason"] == "unknown_challenge"
        end)

      refute log =~ secret
      assert log =~ "gateway operate #{@method} params=redacted"
      assert log =~ "outcome=unknown_challenge"
      refute Enum.any?(FleetFramesFake.responses(context.bin), &String.contains?(&1, secret))
    end

    test "is absent when nothing is holding the operation", _context do
      secret = "unavailable-secret-#{System.unique_integer([:positive])}"
      client = connected(:operate)

      log =
        capture_log(fn ->
          error =
            call(client, @method, %{
              "operation" => "00aa11bb22cc33dd",
              "challenge" => "pw",
              "secret" => secret
            })["error"]

          assert error["data"]["reason"] == "no_worker"
        end)

      refute log =~ secret
      assert log =~ "params=redacted"
    end

    test "is absent from the operation's own status and from every process that saw it",
         context do
      FleetFramesFake.write_scenario!(context.bin, password_scenario())
      secret = "status-secret-#{System.unique_integer([:positive])}"

      operation = start_add()
      :ok = Deployment.subscribe(operation)
      await_challenge(operation, "pw")

      assert {:ok, _} = Deployment.respond(operation, "pw", %{"secret" => secret})

      # Nothing the operation can be asked about afterwards holds it, and neither does the
      # process that sent it: the response is an argument on the way to the pipe and is never
      # written into state.
      assert {:ok, snapshot} = Deployment.status(operation)
      refute JSON.encode!(snapshot) =~ secret

      assert {:ok, worker} = Deployment.worker(operation)

      refute inspect(:sys.get_state(worker), limit: :infinity, printable_limit: :infinity) =~
               secret

      broker = :sys.get_state(Process.whereis(Deployment))
      refute inspect(broker, limit: :infinity, printable_limit: :infinity) =~ secret

      # And nothing the subscriber was sent, either.
      assert_receive {:ouroboros_fleet_deployment, ^operation, frame}, @receive_timeout
      refute JSON.encode!(frame) =~ secret
    end
  end

  # ---------------------------------------------------------------------------
  # The browser surface is held to the same boundary

  describe "deploy blockers through Web.Call" do
    test "a cleartext bind refuses the credential path before the program hears of it",
         context do
      FleetFramesFake.write_scenario!(context.bin, password_scenario())

      Application.put_env(:ouroboros, :web, enabled: true, bind: "0.0.0.0", allow_remote: true)
      on_exit(fn -> Application.delete_env(:ouroboros, :web) end)

      secret = "blocked-secret-#{System.unique_integer([:positive])}"

      log =
        capture_log(fn ->
          assert {:error, code, _message, data} =
                   Call.call(:operate, "fleet.deployment.start", request(),
                     session: "web-session-1"
                   )

          assert code == -32_003
          assert data["reason"] == "deploy_blocked"
          assert "cleartext_web_bind" in data["blockers"]

          # And the credential verb itself, which is the one that matters: this is the
          # decision the spec makes on the bind, so it has to hold where the secret is.
          assert {:error, -32_003, _m, blocked} =
                   web_call(%{
                     "operation" => "00aa11bb22cc33dd",
                     "challenge" => "pw",
                     "secret" => secret
                   })

          assert blocked["reason"] == "deploy_blocked"
        end)

      # The refusal is still a redacted line: being blocked is no reason to start logging it.
      refute log =~ secret
      assert log =~ "params=redacted"
      assert FleetFramesFake.responses(context.bin) == []
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

  defp password_scenario do
    [
      "state waiting",
      "challenge pw password {\"user\":\"deploy\",\"target\":\"100.64.12.44\",\"attempt\":1,\"max_attempts\":3}",
      "await pw",
      "done completed answered"
    ]
  end

  defp probe do
    events = :ets.new(:digest_probe, [:public, :duplicate_bag])
    handler = "w2b-digest-probe-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:ouroboros, :gateway, :audit, :digest],
      fn _event, _measurements, metadata, table ->
        :ets.insert(table, {:sample, metadata})
      end,
      events
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    events
  end

  defp collect(events) do
    events |> :ets.tab2list() |> Enum.map(fn {:sample, metadata} -> metadata end)
  end

  defp web_call(params, opts \\ []) do
    Call.call(:operate, @method, params, Keyword.put_new(opts, :session, "web-session-1"))
  end

  defp request do
    %{
      "target" => %{"address" => "100.64.12.44", "machine" => "build-linux"},
      "ssh_user" => "deploy"
    }
  end

  defp start_add do
    {:ok, %{"operation" => operation}} =
      Deployment.start(%{
        "kind" => "add",
        "machine" => "build-linux",
        "address" => "100.64.12.44",
        "ssh_user" => "deploy",
        "port" => 22
      })

    operation
  end

  defp await_challenge(operation, challenge) do
    Enum.reduce_while(1..120, :missing, fn _attempt, _acc ->
      case Deployment.status(operation) do
        {:ok, %{"challenge" => %{"challenge" => ^challenge}}} ->
          {:halt, :ok}

        _not_yet ->
          Process.sleep(25)
          {:cont, :missing}
      end
    end)
    |> case do
      :ok -> :ok
      :missing -> flunk("the runtime never recorded challenge #{challenge}")
    end
  end

  defp connected(scope) do
    client = connect(scope)

    assert call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "w2b"})[
             "result"
           ]

    client
  end

  defp connect(scope) do
    config = Config.new!(token: @token, data_dir: System.tmp_dir!(), scope: scope)

    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(listen)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listen, 1_000)
    :ok = :gen_tcp.close(listen)

    {:ok, conn} =
      DynamicSupervisor.start_child(
        :redaction_test_conns,
        {Conn,
         socket: server,
         config: config,
         task_supervisor: :redaction_test_tasks,
         conn_supervisor: :redaction_test_conns}
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
end
