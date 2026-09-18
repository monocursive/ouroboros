defmodule Ouroboros.Gateway.ActivityTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Attachments
  alias Ouroboros.Gateway.Activity
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Conn
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.Store, as: InteractiveStore
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Provider.Native.Session, as: NativeSession
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
          [:native_data_dir, :native_model_module, :native_compaction_task_starter],
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

      if context[:compaction] do
        # The session's own seam for starting the fold. A worker that reports in and then
        # waits is a compaction that is genuinely in flight for as long as the test holds
        # it — no sleeping, and no guessing whether the fold already finished.
        test_pid = self()

        Application.put_env(:ouroboros, :native_compaction_task_starter, fn _fun ->
          {:ok,
           spawn(fn ->
             send(test_pid, {:compacting, self()})

             receive do
               :release -> :ok
             after
               15_000 -> :ok
             end
           end)}
        end)
      end

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
      assert summary["busy_sessions"] == 0
      assert summary["in_flight_methods"] == 0
      assert summary["attachment_transfers"] == 0
      assert summary["attachment_normalizations"] == 0
      assert summary["operator_clients"] == 0
      assert summary["silent_sessions"] == 0

      assert Enum.sort(Map.keys(summary)) ==
               Enum.sort(~w(
                 idle running_turns queued_turns busy_sessions in_flight_methods
                 attachment_transfers attachment_normalizations operator_clients
                 silent_sessions unknown
               ))
    end

    test "a read listener serves it over the wire, with the counters as JSON" do
      {client, _conn} = connect(scope: :read)
      assert hello(client)["result"]["scope"] == "read"

      # The verb is allowed to answer from the cache, so this primes it with a fresh walk
      # first. That is the whole difference between the two callers: a reader may have a
      # quarter-second-old picture, and the gate below may not.
      assert Methods.activity(conn_supervisor: :gateway_activity_test_conns)["idle"] == true
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
      assert summary["busy_sessions"] == before["busy_sessions"] + 1
      assert summary["unknown"] == []
      assert summary["idle"] == false

      release(agent, id)
    end

    # ADOPTED EXPLOIT (review of a97f2dfb, HIGH-2). A compaction is held open by the
    # native session with no active turn and an empty queue, and the session's own
    # `fence_idle/1` already refused to call that idle. Reading only `active_turn_id` and
    # `queued_turns` therefore reported a fold in flight as a quiet node — and the stop
    # cancels the fold. The session now publishes the same predicate as `busy?`.
    @tag sessions: true
    @tag compaction: true
    test "a compaction in flight is a busy session, though no turn is running", context do
      before = Methods.activity(conn_supervisor: :gateway_activity_test_conns)
      assert before["idle"] == true

      id = start_session(context, [[{:text, "hi"}, {:finish, :stop}]])

      assert {:ok, _operation} =
               InteractiveSession.compact_start(id, "w1b-fold-#{System.unique_integer()}")

      assert_receive {:compacting, worker}, @receive_timeout
      assert Process.alive?(worker)

      runtime = native_runtime(id)
      assert {:ok, info} = NativeSession.call(runtime, :runtime_info, 5_000)

      # Not a race against a finished fold, and not a turn: this is the case the old
      # counters could not see.
      assert is_nil(info.active_turn_id)
      assert info.queued_turns == 0
      assert info.busy?

      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["running_turns"] == before["running_turns"]
      assert summary["queued_turns"] == before["queued_turns"]
      assert summary["busy_sessions"] == before["busy_sessions"] + 1
      assert summary["unknown"] == []
      assert summary["idle"] == false

      # The two predicates are one function, and this is the caller-visible proof: the
      # verb that consults `fence_idle/1` agrees with the counter.
      assert {:error, :native_session_busy} =
               NativeSession.call(runtime, {:prepare_fence, 1, "w1b-token"}, 5_000)

      send(worker, :release)
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
      assert summary["busy_sessions"] == before["busy_sessions"] + 1
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

    # Review of a97f2dfb, LOW-1: the comment claimed an expired-but-unswept upload kept
    # counting and the predicate dropped it. The predicate is the decision — an upload
    # past its TTL is one this service has already decided to drop — and this is the test
    # that says so, planted through the service's own `:clock` seam.
    test "an upload past its TTL is not in flight, even before the sweep removes it" do
      root = Path.join(System.tmp_dir!(), "w1b-expiry-#{System.unique_integer([:positive])}")
      {:ok, clock} = Agent.start_link(fn -> 1_000_000 end)
      on_exit(fn -> File.rm_rf(root) end)

      server =
        start_supervised!(
          {Attachments,
           name: nil,
           data_dir: root,
           normalizer: HeldDecoder,
           clock: fn -> Agent.get(clock, & &1) end},
          id: :w1b_expiring_attachments
        )

      {:ok, _} = begin_upload(server, "two pixels")
      assert %{"attachment_transfers" => 1, "idle" => false} = summary(server)

      # Past the upload TTL, and nothing has swept: `activity` deliberately does not, so
      # this is the predicate being asserted and not the sweep.
      Agent.update(clock, &(&1 + 100_000))

      assert %{"attachment_transfers" => 0, "unknown" => [], "idle" => true} = summary(server)
    end
  end

  # ---------------------------------------------------------------------------
  # Method calls in flight
  #
  # ADOPTED EXPLOIT (review of a97f2dfb, HIGH-1). `workspace.exec` runs the shell in the
  # *caller's* process — the gateway dispatch task or the LiveView's `Web.Call` — and
  # never in a session, so no session counter could ever see it. A four-second permitted
  # shell read `idle: true` and `require_idle` stopped the node under it.

  describe "operate calls in flight" do
    @tag sessions: true
    test "a shell this node is running is work, and the gate refuses under it", context do
      before = Methods.activity(conn_supervisor: :gateway_activity_test_conns)
      assert before["idle"] == true

      id = start_session(context, [[{:text, "never used"}, {:finish, :stop}]])
      allow_shell(context)

      marker = Path.join(context.workspace, "shell-finished")
      test_pid = self()

      shell =
        Task.async(fn ->
          send(test_pid, :shell_dispatched)

          Methods.invoke("workspace.exec", %{
            "id" => id,
            "command" => "sh -c 'sleep 3; touch #{marker}'"
          })
        end)

      assert_receive :shell_dispatched, @receive_timeout
      await_in_flight(before["in_flight_methods"] + 1)

      summary = Methods.activity(conn_supervisor: :gateway_activity_test_conns)

      assert summary["in_flight_methods"] == before["in_flight_methods"] + 1
      assert summary["unknown"] == []
      assert summary["idle"] == false

      # No session can see this: it is the method call that is the work.
      assert summary["running_turns"] == before["running_turns"]
      assert summary["busy_sessions"] == before["busy_sessions"]
      refute File.exists?(marker), "the shell must still be running for this to prove anything"

      {client, _conn} = connect(scope: :operate, allow_shutdown: true)
      assert hello(client)["result"]
      Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [test_pid, :node_stop]})
      on_exit(fn -> Application.delete_env(:ouroboros, :gateway_stop_mfa) end)

      response = call(client, "runtime.shutdown", %{"require_idle" => true})

      assert response["error"]["code"] == -32004
      assert response["error"]["data"]["reason"] == "runtime_busy"
      assert response["error"]["data"]["activity"]["in_flight_methods"] >= 1
      refute_receive :node_stop, 200

      assert {:ok, _outcome} = Task.await(shell, 15_000)
      assert File.exists?(marker), "the shell really did run"

      # And when it is over, the node is quiet again — the ledger is not a leak.
      assert Methods.activity(conn_supervisor: :gateway_activity_test_conns)["idle"] == true
    end

    @tag sessions: true
    test "the same call through Ouroboros.Web.Call is the same work", context do
      before = Methods.activity(conn_supervisor: :gateway_activity_test_conns)
      id = start_session(context, [[{:text, "never used"}, {:finish, :stop}]])
      allow_shell(context)

      test_pid = self()

      shell =
        Task.async(fn ->
          send(test_pid, :web_dispatched)

          Ouroboros.Web.Call.call(
            :operate,
            "workspace.exec",
            %{"id" => id, "command" => "sh -c 'sleep 2'"},
            task_supervisor: :gateway_activity_test_tasks
          )
        end)

      assert_receive :web_dispatched, @receive_timeout
      await_in_flight(before["in_flight_methods"] + 1)

      assert Methods.activity(conn_supervisor: :gateway_activity_test_conns)["idle"] == false

      Task.await(shell, 15_000)
    end

    test "a read call is not work, so a client polling status cannot make a node busy" do
      test_pid = self()

      reader =
        Task.async(fn ->
          send(test_pid, :reading)
          Methods.invoke("runtime.status", %{})
        end)

      assert_receive :reading, @receive_timeout
      Task.await(reader, @receive_timeout)

      assert Methods.activity(conn_supervisor: :gateway_activity_test_conns)["idle"] == true
    end

    test "the ledger is swept by liveness, because a killed task runs no after block" do
      before = Activity.in_flight()
      dead = spawn(fn -> :ok end)
      ref = Process.monitor(dead)
      assert_receive {:DOWN, ^ref, :process, ^dead, _reason}, @receive_timeout

      # Exactly the row a dispatch task killed for outliving its ceiling leaves behind.
      :ets.insert(:ouroboros_gateway_in_flight, {{dead, make_ref()}, "workspace.exec"})

      assert Activity.in_flight() == before
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

    # The gate is opt-in, and it has to stay opt-in: `ouro stop` and every client that
    # predates this parameter send no parameter at all and expect the stop they always
    # got. A default of `true` would be a silent behaviour change on a busy node, and
    # nothing else in this suite would notice it.
    @tag sessions: true
    test "without the parameter a busy node still stops, because the gate is opt-in",
         context do
      {client, _conn} = connect(scope: :operate, allow_shutdown: true)
      assert hello(client)["result"]

      {id, agent} = start_held_turn(context)
      assert_receive {:model_entered, _pid}, @receive_timeout
      assert Methods.activity(conn_supervisor: :gateway_activity_test_conns)["idle"] == false

      test_pid = self()
      Application.put_env(:ouroboros, :gateway_stop_mfa, {Kernel, :send, [test_pid, :node_stop]})
      on_exit(fn -> Application.delete_env(:ouroboros, :gateway_stop_mfa) end)

      response = call(client, "runtime.shutdown")

      assert response["result"]["stopping"] == true
      assert_receive :node_stop, @receive_timeout

      release(agent, id)
    end
  end

  # ---------------------------------------------------------------------------
  # The listener's own wiring

  describe "a connection the listener made" do
    test "counts the clients of the listener that made it, not of a default name" do
      data_dir =
        Path.join(System.tmp_dir!(), "w1b-listener-#{System.unique_integer([:positive])}")

      File.mkdir_p!(data_dir)
      File.chmod!(data_dir, 0o700)
      on_exit(fn -> File.rm_rf(data_dir) end)

      config =
        Config.new!(token: @token, data_dir: data_dir, scope: :read, allow_shutdown: false)

      start_supervised!(
        {Ouroboros.Gateway,
         name: :w1b_listener_gateway,
         config: config,
         listener: :w1b_listener,
         conn_supervisor: :w1b_listener_conns,
         task_supervisor: :w1b_listener_tasks}
      )

      port = Ouroboros.Gateway.Listener.port(:w1b_listener)
      {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)
      on_exit(fn -> :gen_tcp.close(client) end)

      assert hello(client)["result"]

      # The name reaches the connection only because `Gateway.Listener` hands it over with
      # the socket. Stop it doing that and this reads `null`, because
      # `Ouroboros.Gateway.ConnSupervisor` is not running in this suite.
      assert call(client, "runtime.activity")["result"]["operator_clients"] == 1
    end
  end

  # ---------------------------------------------------------------------------

  defp summary(attachments) do
    Methods.activity(attachments: attachments, conn_supervisor: :gateway_activity_test_conns)
  end

  # The operator shell is permission-gated; these cases are about the idle gate and not
  # about the permission one, so the command is allowed by an explicit workspace rule.
  defp allow_shell(context) do
    {:ok, workspace_root} = Ouroboros.Workspace.Path.canonicalize(context.workspace)

    {:ok, rule} =
      Ouroboros.Control.Permissions.add(%{
        scope: :workspace,
        decision: :allow,
        pattern: "Bash(sh *)",
        workspace: workspace_root
      })

    on_exit(fn -> Ouroboros.Control.Permissions.remove(:workspace, rule.id) end)
    :ok
  end

  # A dispatched call is in flight once its own process has registered, which happens
  # inside `Methods.invoke/2` rather than in the caller. Waiting on the ledger itself is
  # the seam; sleeping would only hope.
  defp await_in_flight(expected, remaining \\ 200)

  defp await_in_flight(expected, 0),
    do: flunk("the ledger never reached #{expected}; it is #{inspect(Activity.in_flight())}")

  defp await_in_flight(expected, remaining) do
    if Activity.in_flight() >= expected do
      :ok
    else
      Process.sleep(10)
      await_in_flight(expected, remaining - 1)
    end
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

    {id, agent} = start_session(context, [hold], agent: true)

    assert {:ok, _} = InteractiveSession.send_message(id, "hold here", id: "w1b-running")

    {id, agent}
  end

  defp start_session(context, script, opts \\ []) do
    {model, agent} = NativeModelScript.start(script)
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

    if Keyword.get(opts, :agent, false), do: {id, agent}, else: id
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
