defmodule Ouroboros.Web.FleetDeploymentRedactionTest do
  @moduledoc """
  Acceptance item 16, for the one place a deployment secret crosses this runtime.

  The spec's "Secret handling and authorization" section is a single list of places a
  password or passphrase may never appear, and it names `Web.Call` and gateway parameter
  digests among them — *even hashed*. So this asserts two different things, because either
  one alone would be a comfortable lie:

    * **Instrumentation.** `Ouroboros.Gateway.AuditLine.digest/2` emits a telemetry event
      before it returns. Driving the authenticate path with a unique secret must produce no
      digest event for that method at all, and no emitted digest may equal the digest those
      exact parameters would have produced. That is a statement about the hashing function's
      inputs rather than about the log's contents.
    * **The log itself.** A unique secret must not appear in any captured line, on the
      success path, the refusal path or the failure path, through either surface.

  A test that only searched the log would pass against a build that hashed the password into
  it, which is the failure mode the spec calls out by name.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Gateway.AuditLine
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Test.FleetOuroFake
  alias Ouroboros.Test.FleetWorkerFake
  alias Ouroboros.Web.Call

  @method "fleet.deployment.authenticate"
  @token String.duplicate("r", 40)
  @receive_timeout 5_000

  setup do
    start_supervised!({Task.Supervisor, name: Ouroboros.Web.TaskSupervisor})
    start_supervised!({Task.Supervisor, name: :redaction_test_tasks})
    start_supervised!({DynamicSupervisor, strategy: :one_for_one, name: :redaction_test_conns})

    root = Path.join(System.tmp_dir!(), "orw2b#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o700)
    fake_dir = Path.join(root, "bin")

    previous_data_dir = Application.get_env(:ouroboros, :data_dir)
    previous_ouro = System.get_env("OUROBOROS_PROCESS_ID_HELPER")
    Application.put_env(:ouroboros, :data_dir, root)

    on_exit(fn ->
      if previous_data_dir,
        do: Application.put_env(:ouroboros, :data_dir, previous_data_dir),
        else: Application.delete_env(:ouroboros, :data_dir)

      if previous_ouro,
        do: System.put_env("OUROBOROS_PROCESS_ID_HELPER", previous_ouro),
        else: System.delete_env("OUROBOROS_PROCESS_ID_HELPER")

      File.rm_rf!(root)
    end)

    %{root: root, fake_dir: fake_dir}
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
          "operation_id" => "0011223344556677",
          "challenge" => "pw-1",
          "secret" => "a-very-unique-secret-value"
        })
        |> IO.iodata_to_binary()

      assert line == "redacted operation_id=0011223344556677 challenge=pw-1"
      refute line =~ "a-very-unique-secret-value"
    end

    test "an allowlisted key of an unexpected shape is named rather than printed" do
      line =
        AuditLine.params(@method, %{
          "operation_id" => %{"nested" => "surprise"},
          "challenge" => nil
        })
        |> IO.iodata_to_binary()

      assert line == "redacted operation_id=unreadable challenge=absent"
      refute line =~ "surprise"
    end

    test "every other method still gets the digest both surfaces have always written" do
      params = %{"id" => "s-1", "command" => "ls"}
      assert AuditLine.params("workspace.exec", params) == AuditLine.digest(params)
    end

    test "Phoenix's own parameter filter covers both credential words" do
      # Asserted through the filter rather than against the configured list: Phoenix compiles
      # that list into a matcher at boot, and the behaviour is what a form actually gets.
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
    test "no digest event is emitted for the authenticate method, on any outcome", context do
      secret = "instrumented-secret-#{System.unique_integer([:positive])}"

      params = %{
        "operation_id" => "00aa11bb22cc33dd",
        "challenge" => "pw-1",
        "secret" => secret
      }

      # Computed before the probe is attached, so this call is not one of the samples. If
      # anything on the authenticate path ever hashes these parameters, this is the value
      # that would come out of it.
      forbidden = AuditLine.digest(params)

      arrange_devices(context)
      events = probe()

      # Three outcomes, one method: an operation that does not exist, a malformed one, and
      # one whose data directory is gone. None of them may reach the digest.
      assert {:error, _code, _message, _data} = web_call(params)
      assert {:error, _code, _message, _data} = web_call(%{params | "operation_id" => "zzzz"})

      Application.delete_env(:ouroboros, :data_dir)
      assert {:error, _code, _message, _data} = web_call(params)
      Application.put_env(:ouroboros, :data_dir, context.root)

      samples = collect(events)

      refute Enum.any?(samples, &(&1.method == @method)),
             "the audit digest was computed for #{@method}"

      refute Enum.any?(samples, &(&1.digest == forbidden)),
             "the digest of the parameters carrying the secret was emitted"
    end

    test "a call that arrives with no client session cannot answer a challenge at all",
         context do
      arrange_devices(context)

      # `Web.Call` installs the authenticated browser session; a caller that supplies none
      # gets no binding, and a binding is what a challenge is answered against. Failing
      # closed is the only safe direction: a shared "unattributed" session would let two
      # unbound callers answer each other's credential prompts.
      assert {:error, code, _message, data} =
               Call.call(:operate, @method, %{
                 "operation_id" => "00aa11bb22cc33dd",
                 "challenge" => "pw",
                 "secret" => "no-session-secret"
               })

      assert code == -32_003
      assert data["reason"] == "session_unbound"
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
      %{worker: worker} = arrange_worker(context)
      secret = "web-success-secret-#{System.unique_integer([:positive])}"

      {:ok, %{"operation_id" => operation}} =
        Ouroboros.Fleet.Deployment.prepare(request(), %{
          subject: "runtime-unattributed",
          session: "web-session-1"
        })

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      await_attached(operation)
      :ok = FleetWorkerFake.challenge(worker, "pw", "password", %{"attempt" => 1})
      await_challenge(operation, "pw")

      log =
        capture_log(fn ->
          assert {:ok, %{"accepted" => true}} =
                   web_call(
                     %{"operation_id" => operation, "challenge" => "pw", "secret" => secret},
                     session: "web-session-1"
                   )
        end)

      assert_receive {:fake_worker, %{"op" => "respond"} = frame}, @receive_timeout
      assert frame["response"]["secret"] == secret

      refute log =~ secret
      assert log =~ "web operate #{@method} params=redacted"
      assert log =~ "operation_id=#{operation}"
      assert log =~ "challenge=pw"
      # The kind and the outcome are logged by the process that knows them.
      assert log =~ "kind=password"
      assert log =~ "outcome=sent"
    end

    test "is absent on a refusal, through the listener", context do
      %{worker: worker} = arrange_worker(context)
      secret = "listener-refused-secret-#{System.unique_integer([:positive])}"

      first = connected(:operate)
      second = connected(:operate)

      operation =
        call(first, "fleet.deployment.prepare", request())["result"]["operation_id"]

      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout
      await_attached(operation)
      :ok = FleetWorkerFake.challenge(worker, "pw", "password")
      await_challenge(operation, "pw")

      log =
        capture_log(fn ->
          error =
            call(second, @method, %{
              "operation_id" => operation,
              "challenge" => "pw",
              "secret" => secret
            })["error"]

          assert error["data"]["reason"] == "challenge_not_bound"
        end)

      refute log =~ secret
      assert log =~ "gateway operate #{@method} params=redacted"
      assert log =~ "outcome=challenge_not_bound"
      refute_receive {:fake_worker, %{"op" => "respond"}}, 300
    end

    test "is absent when the whole plane is unavailable", context do
      secret = "unavailable-secret-#{System.unique_integer([:positive])}"
      arrange_devices(context)
      client = connected(:operate)

      log =
        capture_log(fn ->
          error =
            call(client, @method, %{
              "operation_id" => "00aa11bb22cc33dd",
              "challenge" => "pw",
              "secret" => secret
            })["error"]

          assert error["data"]["reason"] == "no_worker"
        end)

      refute log =~ secret
      assert log =~ "params=redacted"
    end

    test "is absent from the operation's own status and event stream", context do
      %{worker: worker} = arrange_worker(context)
      secret = "status-secret-#{System.unique_integer([:positive])}"

      bound = %{subject: "runtime-unattributed", session: "web-session-2"}
      {:ok, %{"operation_id" => operation}} = Ouroboros.Fleet.Deployment.prepare(request(), bound)
      assert_receive {:fake_worker, %{"op" => "attach"}}, @receive_timeout

      :ok = Ouroboros.Fleet.Deployment.subscribe(operation)
      :ok = FleetWorkerFake.challenge(worker, "pw", "password")
      await_challenge(operation, "pw")

      assert {:ok, _} = Ouroboros.Fleet.Deployment.authenticate(operation, "pw", secret, bound)
      assert_receive {:fake_worker, %{"op" => "respond"}}, @receive_timeout

      # Nothing the operation can be asked about afterwards holds it, and neither does the
      # process that sent it: the response is an argument on the way to the socket and is
      # never written into state.
      assert {:ok, snapshot} = Ouroboros.Fleet.Deployment.status(operation, bound())
      refute JSON.encode!(snapshot) =~ secret

      assert {:ok, client} = Ouroboros.Fleet.Deployment.client(operation)

      refute inspect(:sys.get_state(client), limit: :infinity, printable_limit: :infinity) =~
               secret

      broker = :sys.get_state(Process.whereis(Ouroboros.Fleet.Deployment))
      refute inspect(broker, limit: :infinity, printable_limit: :infinity) =~ secret
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers

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
    %{"target" => %{"address" => "100.64.12.44"}, "ssh_user" => "deploy"}
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
    %{worker: worker, ouro: ouro}
  end

  defp bound, do: %{subject: "runtime-unattributed", session: "web-session-1"}

  # The handshake runs in the client's own process now, so a fake that writes a challenge the
  # moment `prepare` answers writes it into a socket nobody has accepted yet.
  defp await_attached(operation) do
    Enum.reduce_while(1..100, :missing, fn _attempt, _acc ->
      case Ouroboros.Fleet.Deployment.status(operation, bound()) do
        {:ok, %{"attached" => true}} -> {:halt, :ok}
        _not_yet -> tick()
      end
    end)
  end

  defp await_challenge(operation, challenge) do
    Enum.reduce_while(1..50, :missing, fn _attempt, _acc ->
      case Ouroboros.Fleet.Deployment.status(operation, bound()) do
        {:ok, %{"challenges" => challenges}} ->
          if Enum.any?(challenges, &(&1["challenge"] == challenge)),
            do: {:halt, :ok},
            else: tick()

        _other ->
          tick()
      end
    end)
    |> case do
      :ok -> :ok
      :missing -> flunk("the broker never recorded challenge #{challenge}")
    end
  end

  defp tick do
    Process.sleep(20)
    {:cont, :missing}
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
