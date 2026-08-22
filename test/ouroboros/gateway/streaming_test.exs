defmodule Ouroboros.Gateway.StreamingTest do
  use ExUnit.Case, async: false

  alias Jido.Harness.Run
  alias Jido.Harness.RunInfo
  alias Jido.Harness.RunRequest
  alias Jido.Harness.Session
  alias Jido.Harness.SessionInfo
  alias Ouroboros.Gateway
  alias Ouroboros.Gateway.Config
  alias Ouroboros.Gateway.Listener
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Test.SessionHarnessAdapter

  @moduletag :tmp_dir
  @moduletag :capture_log

  @token String.duplicate("s", 48)
  @provider :ouroboros_test
  # Same run adapter behavior, but its sessions declare a steer-capable transport —
  # the managed transport the base adapter synthesizes has no `steer`, which is why
  # steer paths need this twin.
  @session_provider :ouroboros_test_session
  # A ceiling, not a pace: every wait exits early on its condition. The full suite runs
  # this file alongside 100+ seconds of sync tests, and a starved scheduler has pushed
  # first-event latency past 5s before — the budget must absorb that without flaking.
  @receive_timeout 15_000

  setup context do
    File.chmod!(context.tmp_dir, 0o700)
    cleanup_sessions()
    cleanup_runs()
    cleanup_stores()

    old_providers = Application.get_env(:jido_harness, :providers)
    old_config = Application.get_env(:jido_harness, :provider_config)
    journal_dir = unique_journal_dir()

    Application.put_env(
      :jido_harness,
      :providers,
      Map.merge(Map.new(old_providers || %{}), %{
        @provider => HarnessAdapter,
        @session_provider => SessionHarnessAdapter
      })
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      old_config
      |> then(&Map.new(&1 || %{}))
      |> Map.merge(%{
        @provider => %{test_pid: self(), retention: %{journal_dir: journal_dir}},
        @session_provider => %{test_pid: self(), retention: %{journal_dir: journal_dir}}
      })
    )

    config =
      Config.new!(
        token: @token,
        data_dir: context.tmp_dir,
        port: 0,
        scope: :operate,
        queue_limit: Map.get(context, :queue_limit, 1_000)
      )

    start_supervised!({Gateway, config: config})

    {:ok, client} =
      :gen_tcp.connect({127, 0, 0, 1}, Listener.port(), [:binary, active: false], 1_000)

    on_exit(fn ->
      :gen_tcp.close(client)
      cleanup_sessions()
      cleanup_runs()
      cleanup_stores()
      restore_env(:providers, old_providers)
      restore_env(:provider_config, old_config)
      File.rm_rf(journal_dir)
    end)

    assert hello(client)["result"]["scope"] == "operate"

    %{client: client}
  end

  describe "subscribing" do
    test "returns the backlog and then streams live events as notifications", %{client: client} do
      {ref, id} = start_session()

      backlog = call(client, "interactive.subscribe", %{"id" => id, "cursor" => 0})["result"]

      # The backlog is the durable, redacted record after the cursor — the same events
      # `interactive.replay` would answer with, delivered atomically with the registration
      # so nothing can fall between the two.
      assert Enum.map(backlog, & &1["type"]) == [
               "session_started",
               "session_ready",
               "session_idle"
             ]

      assert Enum.map(backlog, & &1["sequence"]) == [1, 2, 3]
      assert Enum.all?(backlog, &(&1["_struct"] == "Ouroboros.Interactive.Event"))
      assert Enum.all?(backlog, &(&1["session_id"] == id))

      adapter = send_message(ref, "look around")
      assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "all quiet"})

      event = await_event(client, "interactive.event", "output_text_final")

      assert event["params"]["id"] == id
      assert event["params"]["event"]["payload"]["text"] == "all quiet"
      assert event["params"]["event"]["sequence"] > 3

      assert :ok = HarnessAdapter.finish(adapter)
    end

    test "dispatches the typed turn envelope without breaking string turns", %{client: client} do
      {ref, id} = start_session()

      outside =
        Path.join(
          System.tmp_dir!(),
          "ouro-gateway-outside-#{System.unique_integer([:positive, :monotonic])}.txt"
        )

      File.write!(outside, "not admitted")
      on_exit(fn -> File.rm(outside) end)

      refused =
        call(client, "interactive.send_message", %{
          "id" => id,
          "turn_id" => "escaped-attachment",
          "input" => %{"prompt" => "inspect", "attachments" => [outside]}
        })

      assert refused["error"]["code"] == -32_006
      assert refused["error"]["data"] == ["attachment_outside_workspace", outside]

      response =
        call(client, "interactive.send_message", %{
          "id" => id,
          "turn_id" => "typed-turn",
          "input" => %{"prompt" => "inspect the typed envelope"}
        })

      assert response["result"]["id"] == "typed-turn"

      assert_receive {:ouroboros_test_adapter_started, _run, %RunRequest{prompt: prompt},
                      adapter},
                     @receive_timeout

      assert Ouroboros.Test.Prompt.wrapped?(prompt, "inspect the typed envelope")

      assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "typed"})
      assert :ok = HarnessAdapter.finish(adapter)
      assert {:ok, %{status: :completed}} = InteractiveSession.await(ref, "typed-turn", 2_000)
    end

    test "a cursor above the backlog is honored rather than replayed from zero", %{
      client: client
    } do
      {_ref, id} = start_session()

      assert call(client, "interactive.subscribe", %{"id" => id, "cursor" => 2})["result"]
             |> Enum.map(& &1["sequence"]) == [3]
    end

    test "unsubscribing stops the notifications", %{client: client} do
      {ref, id} = start_session()

      assert call(client, "interactive.subscribe", %{"id" => id})["result"]
      assert call(client, "interactive.unsubscribe", %{"id" => id})["result"] == "ok"

      adapter = send_message(ref, "quietly")
      assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "unheard"})
      assert :ok = HarnessAdapter.finish(adapter)

      # A round trip after the emission: if a notification were coming it would be ahead
      # of this response in the socket, because one connection has one writer.
      assert call(client, "interactive.list")["result"]
    end

    test "same explicit id on another owner is refused without dropping the watched stream", %{
      client: client
    } do
      {_ref, id} = start_session()
      assert is_list(call(client, "interactive.subscribe", %{"id" => id})["result"])

      # The event envelope identifies a stream by plane + id, so two owners with the same
      # caller-supplied id cannot be multiplexed honestly on one connection. Add a
      # last-known offline owner to the directory and prove Conn refuses that collision
      # before calling its plane. This exercises the protocol rule without inventing a
      # second provider run merely to obtain the node identity.
      monitor = Process.whereis(Ouroboros.Cluster.Monitor)
      original_monitor_state = :sys.get_state(monitor)
      other_owner = :"ouroboros-collision-owner@test"

      :sys.replace_state(monitor, fn state ->
        local = Map.fetch!(state.machines, node())

        other = %{
          local
          | node: other_owner,
            machine: "collision-owner",
            state: :offline,
            expected?: false,
            last_down_at: DateTime.utc_now() |> DateTime.to_iso8601(),
            down_reason: "test_offline"
        }

        %{state | machines: Map.put(state.machines, other_owner, other)}
      end)

      on_exit(fn ->
        if Process.alive?(monitor),
          do: :sys.replace_state(monitor, fn _ -> original_monitor_state end)
      end)

      collision =
        call(client, "interactive.subscribe", %{
          "id" => id,
          "node" => Atom.to_string(other_owner)
        })

      assert collision["error"]["code"] == -32_004
      assert collision["error"]["message"] =~ "another machine"

      # Naming the colliding owner on unsubscribe is a no-op, not permission to tear down
      # the local stream that actually owns this plane + id slot.
      assert call(client, "interactive.unsubscribe", %{
               "id" => id,
               "node" => Atom.to_string(other_owner)
             })["result"] == "ok"

      assert Map.has_key?(:sys.get_state(conn_pid(client)).subscriptions, {:interactive, id})
      assert call(client, "interactive.unsubscribe", %{"id" => id})["result"] == "ok"
    end

    test "unsubscribing from a session this connection never watched starts nothing", %{
      client: client
    } do
      # A durable session with no coordinator running. `InteractiveSession.unsubscribe/1`
      # would start one to ask it to forget a registration it never had.
      {ref, id} = start_session()
      assert :ok = InteractiveSession.kill(ref)
      await_terminal(id)
      await_retired(id)

      assert call(client, "interactive.unsubscribe", %{"id" => id})["result"] == "ok"
      assert is_nil(Ouroboros.Interactive.Task.whereis(id))
    end

    test "an id that is not a session is a typed error, not a hang", %{client: client} do
      response = call(client, "interactive.subscribe", %{"id" => "no-such-session"})

      assert response["error"]["code"] in [-32004, -32006, -32007]
    end

    test "a malformed cursor is refused before the plane is called", %{client: client} do
      response = call(client, "interactive.subscribe", %{"id" => "x", "cursor" => -1})

      assert response["error"]["code"] == -32602
      assert response["error"]["message"] =~ "cursor"
    end
  end

  describe "the coding plane streams through the same machinery" do
    test "its events arrive as coding.event and name the task the way its struct does", %{
      client: client
    } do
      {ref, id} = start_coding_task()

      backlog = call(client, "coding.subscribe", %{"id" => id, "cursor" => 0})["result"]
      assert is_list(backlog)

      assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, @receive_timeout
      assert :ok = HarnessAdapter.emit(adapter, :output_text_final, %{"text" => "objective met"})

      event = await_event(client, "coding.event", "output_text_final")

      # The notification's `id` is the task, under the name every other method uses; the
      # struct inside it calls the same value `task_id`. A client decoding these needs
      # both spellings, which is why the golden fixture carries them.
      assert event["params"]["id"] == id
      assert event["params"]["event"]["task_id"] == id
      assert event["params"]["event"]["_struct"] == "Ouroboros.Coding.Event"

      assert call(client, "coding.unsubscribe", %{"id" => id})["result"] == "ok"
      assert :ok = HarnessAdapter.finish(adapter)
      _ = ref
    end
  end

  describe "a stream that has already ended" do
    test "a terminal session answers the backlog and then stream.ended", %{client: client} do
      {ref, id} = start_session()
      assert :ok = InteractiveSession.kill(ref)
      status = await_terminal(id)

      backlog = call(client, "interactive.subscribe", %{"id" => id, "cursor" => 0})["result"]
      assert is_list(backlog)

      # The plane returns the backlog and silently declines the registration for a terminal
      # session. Without this notification a client would render a live session forever.
      ended = recv(client)

      assert ended["method"] == "stream.ended"
      assert ended["params"]["id"] == id
      assert ended["params"]["plane"] == "interactive"
      assert ended["params"]["status"] == Atom.to_string(status)
    end

    test "a coordinator that dies under a live subscription ends the stream", %{client: client} do
      {ref, id} = start_session()

      assert call(client, "interactive.subscribe", %{"id" => id})["result"]

      # A crash rather than a retirement, because the registration is lost either way and
      # the restarted coordinator has no memory of this connection. Nothing else would
      # tell the client that the events simply stopped.
      coordinator = Ouroboros.Interactive.Task.whereis(id)
      Process.exit(coordinator, :kill)

      ended = recv(client)

      assert ended["method"] == "stream.ended"
      assert ended["params"]["id"] == id
      assert ended["params"]["status"] == "unknown"

      # And the connection is fine: resubscribing is the client's next move.
      assert call(client, "interactive.list")["result"]
      _ = ref
    end
  end

  describe "a cursor below the retained window" do
    test "surfaces the floor so the client can restart from it", %{client: client} do
      # `event_limit: 1` is the smallest retention the plane accepts, so the floor rises
      # with every event and a cursor of zero is pruned almost immediately.
      {_ref, id} = start_session(event_limit: 1)

      pruned = call(client, "interactive.subscribe", %{"id" => id, "cursor" => 0})

      assert pruned["error"]["code"] == -32006
      assert pruned["error"]["data"]["reason"] == "cursor_pruned"
      assert pruned["error"]["data"]["floor"] > 0

      # `replay` answers the same shape, because a client's resync path and its subscribe
      # path have to branch on one thing rather than two.
      replayed = call(client, "interactive.replay", %{"id" => id, "cursor" => 0})

      assert replayed["error"]["code"] == -32006
      assert replayed["error"]["data"]["reason"] == "cursor_pruned"

      # Resuming from the floor is accepted, which is what makes the error actionable.
      assert is_list(
               call(client, "interactive.subscribe", %{
                 "id" => id,
                 "cursor" => pruned["error"]["data"]["floor"]
               })["result"]
             )
    end
  end

  describe "backpressure" do
    @tag queue_limit: 4
    test "events are dropped, counted, and reconciled exactly by replay", %{client: client} do
      {ref, id} = start_session()

      backlog = call(client, "interactive.subscribe", %{"id" => id})["result"]

      # Suspending the writer is what a peer that stopped reading looks like from this
      # process, without depending on a kernel buffer size to decide when. Frames pile up
      # unacknowledged, the queue crosses the limit, and event frames start being dropped.
      writer = writer_pid(client)
      :erlang.suspend_process(writer)

      adapter = send_message(ref, "say a lot")

      for index <- 1..60 do
        assert :ok =
                 HarnessAdapter.emit(adapter, :output_text_final, %{
                   "text" => "chunk #{index} " <> String.duplicate("x", 512)
                 })
      end

      assert :ok = HarnessAdapter.finish(adapter)

      # `finish` returned when the stub accepted it, not when the plane has the turn:
      # the coordinator ingests events from the harness on poll ticks, and under load
      # that replay lags the adapter by whole seconds. The reconciliation below is
      # answered from the plane's retained history, so the history must hold every
      # output and the turn's completion before the count is taken. Once it does,
      # mailbox order does the rest: each event notification reaches the connection
      # ahead of any writer acknowledgement the resume releases, so every drop is
      # counted before the queue drains and `stream.lagged` is flushed.
      await_ingested(id, 60)
      await_lagging(client)

      :erlang.resume_process(writer)

      {events, lagged} = drain_until_lagged(client)

      assert lagged["params"]["id"] == id
      assert lagged["params"]["plane"] == "interactive"
      assert lagged["params"]["dropped"] > 0
      assert lagged["params"]["last_sequence"] >= lagged["params"]["dropped"]

      # The reconciliation the whole design turns on: the backlog the subscribe answered
      # with, plus whatever notifications arrived, plus whatever `replay` answers from the
      # last sequence actually seen, is the complete contiguous history. Not "roughly" —
      # exactly, and with a gap in the middle that the client closed by asking.
      seen =
        Enum.map(backlog, & &1["sequence"]) ++
          Enum.map(events, & &1["params"]["event"]["sequence"])

      cursor = Enum.max(seen)

      replayed =
        call(client, "interactive.replay", %{"id" => id, "cursor" => cursor, "limit" => 500})[
          "result"
        ]

      reconciled = seen ++ Enum.map(replayed, & &1["sequence"])

      assert reconciled == Enum.sort(reconciled)
      assert reconciled == Enum.to_list(1..Enum.max(reconciled))
      assert length(reconciled) > 60
    end

    @tag queue_limit: 4
    test "a client that stops reading stalls only itself", %{client: client} do
      {ref, id} = start_session()

      {:ok, other} =
        :gen_tcp.connect({127, 0, 0, 1}, Listener.port(), [:binary, active: false], 1_000)

      on_exit(fn -> :gen_tcp.close(other) end)
      assert hello(other)["result"]

      # Both watch the same session. There is no shared state between connections, and
      # this is the test that says so out loud rather than leaving it to the diagram.
      assert call(client, "interactive.subscribe", %{"id" => id})["result"]
      assert call(other, "interactive.subscribe", %{"id" => id})["result"]

      :erlang.suspend_process(writer_pid(client))

      adapter = send_message(ref, "talk")

      for index <- 1..40 do
        assert :ok =
                 HarnessAdapter.emit(adapter, :output_text_final, %{
                   "text" => "chunk #{index} " <> String.duplicate("y", 512)
                 })
      end

      assert :ok = HarnessAdapter.finish(adapter)

      # The healthy connection is unaffected: it receives its events and answers its
      # requests while the other one's queue is overflowing.
      assert await_event(other, "interactive.event", "output_text_final", 400)
      assert is_list(call(other, "interactive.list")["result"])

      :erlang.resume_process(writer_pid(client))
    end

    @tag queue_limit: 4
    test "responses are never dropped, and a peer that stops reading them is closed", %{
      client: client
    } do
      writer = writer_pid(client)
      conn = conn_pid(client)
      monitor = Process.monitor(conn)
      :erlang.suspend_process(writer)

      # Beyond the inbound bound each of these is refused `-32004`, and every answer —
      # refusal or result — is a response frame, which is never dropped. With the writer
      # suspended the whole way, 400 unacknowledged responses must cross the hard cap, and
      # past it the only honest move left is to close. The suspension holds until the
      # close is observed: a writer resumed mid-flood acknowledges frames as fast as the
      # connection queues them, the cap is never crossed, and staying open becomes the
      # correct behavior rather than the failure this test exists to rule out.
      for index <- 1..400 do
        :ok =
          :gen_tcp.send(client, [
            JSON.encode_to_iodata!(%{
              "jsonrpc" => "2.0",
              "id" => index,
              "method" => "runtime.providers"
            }),
            ?\n
          ])
      end

      assert_receive {:DOWN, ^monitor, :process, ^conn, :normal}, @receive_timeout

      # Released only now, so the suspended writer can drain, fail its write against the
      # closed socket, and exit rather than leak.
      :erlang.resume_process(writer)
    end

    @tag queue_limit: 4
    test "unsubscribing while lagged does not emit stream.lagged", %{client: client} do
      {ref, id} = start_session()
      assert call(client, "interactive.subscribe", %{"id" => id})["result"]

      writer = writer_pid(client)
      :erlang.suspend_process(writer)

      adapter = send_message(ref, "overflow")

      for index <- 1..40 do
        assert :ok =
                 HarnessAdapter.emit(adapter, :output_text_final, %{
                   "text" => "chunk #{index} " <> String.duplicate("z", 512)
                 })
      end

      assert :ok = HarnessAdapter.finish(adapter)
      await_ingested(id, 40)
      await_lagging(client)

      request_id = System.unique_integer([:positive])

      :ok =
        :gen_tcp.send(client, [
          JSON.encode_to_iodata!(%{
            "jsonrpc" => "2.0",
            "id" => request_id,
            "method" => "interactive.unsubscribe",
            "params" => %{"id" => id}
          }),
          ?\n
        ])

      await_unsubscribed(client, id)

      :erlang.resume_process(writer)
      assert await_response(client, request_id)["result"] == "ok"
      assert is_list(call(client, "interactive.list")["result"])

      assert call(client, "interactive.subscribe", %{"id" => id})["result"]
      refute lagged_subscription?(conn_pid(client))
    end
  end

  describe "steering" do
    test "a steer is quoted by its own accepted event, durably", %{client: client} do
      {ref, id} = start_session([], @session_provider)

      assert call(client, "interactive.subscribe", %{"id" => id, "cursor" => 0})["result"]

      send_message(ref, "start the work")

      # Steering needs a turn to steer: the worker refuses `:no_active_turn` otherwise.
      steered = call(client, "interactive.steer", %{"id" => id, "input" => "go left"})
      assert is_binary(steered["result"])

      steer_event = await_steer_event(client)
      event = steer_event["params"]["event"]
      assert event["payload"]["kind"] == "steer"
      assert event["payload"]["text"] == "go left"

      # The text survives replay from zero: it lives in the durable projected row,
      # not only in the live notification.
      replayed =
        call(client, "interactive.replay", %{"id" => id, "cursor" => 0, "limit" => 500})[
          "result"
        ]

      assert Enum.any?(replayed, fn e ->
               e["type"] == "input_accepted" and e["payload"]["kind"] == "steer" and
                 e["payload"]["text"] == "go left"
             end)

      assert Enum.any?(replayed, fn e ->
               e["type"] == "input_accepted" and e["payload"]["kind"] == "message" and
                 e["payload"]["text"] == "start the work"
             end)
    end

    test "steering without an active turn names the refusal instead of hanging", %{
      client: client
    } do
      {ref, id} = start_session([], @session_provider)
      wait_until_harness_attached(ref)

      refused = call(client, "interactive.steer", %{"id" => id, "input" => "too early"})
      assert refused["error"]["code"] == -32006
    end
  end

  defp start_session(opts \\ [], provider \\ @provider)

  defp start_session(opts, provider) do
    id = "gateway-stream-#{System.unique_integer([:positive, :monotonic])}"

    assert {:ok, ref} =
             InteractiveSession.start(
               [
                 id: id,
                 provider: provider,
                 workspace: File.cwd!(),
                 approval_mode: :prompt,
                 sandbox_mode: :read_only
               ] ++ opts
             )

    {ref, id}
  end

  defp start_coding_task do
    id = "gateway-coding-#{System.unique_integer([:positive, :monotonic])}"

    assert {:ok, ref} =
             Ouroboros.CodingSession.start("inspect the workspace",
               id: id,
               provider: @provider,
               workspace: File.cwd!()
             )

    {ref, id}
  end

  defp send_message(ref, input) do
    assert {:ok, _turn} = InteractiveSession.send_message(ref, input)

    assert_receive {:ouroboros_test_adapter_started, _run, _request, adapter}, @receive_timeout

    adapter
  end

  defp await_event(client, method, type, attempts \\ 50)

  defp await_event(_client, method, type, 0),
    do: flunk("no #{method} of type #{type} arrived")

  defp await_event(client, method, type, attempts) do
    frame = recv(client)

    if frame["method"] == method and frame["params"]["event"]["type"] == type do
      frame
    else
      await_event(client, method, type, attempts - 1)
    end
  end

  # The message acceptance and the steer acceptance are both `input_accepted`; only
  # the steer row carries `kind: "steer"`, so read past everything else.
  defp await_steer_event(client, attempts \\ 50)

  defp await_steer_event(_client, 0), do: flunk("no steered input_accepted arrived")

  defp await_steer_event(client, attempts) do
    frame = recv(client)
    event = frame["params"]["event"] || %{}

    if frame["method"] == "interactive.event" and event["type"] == "input_accepted" and
         event["payload"]["kind"] == "steer" do
      frame
    else
      await_steer_event(client, attempts - 1)
    end
  end

  # Session start returns before the coordinator has attached the Harness session; a
  # steer sent in that window is `:session_not_started`, not `:no_active_turn`.
  defp wait_until_harness_attached(ref, attempts \\ 100)

  defp wait_until_harness_attached(_ref, 0), do: flunk("session never attached a provider")

  defp wait_until_harness_attached(ref, attempts) do
    case InteractiveSession.info(ref) do
      {:ok, %{harness_session_id: id}} when is_binary(id) ->
        :ok

      _other ->
        Process.sleep(25)
        wait_until_harness_attached(ref, attempts - 1)
    end
  end

  # Reads until the lag notification arrives, keeping every event frame seen on the way so
  # the reconciliation can be checked against what the client actually received.
  defp drain_until_lagged(client, events \\ [], attempts \\ 200)

  defp drain_until_lagged(_client, _events, 0), do: flunk("no stream.lagged arrived")

  defp drain_until_lagged(client, events, attempts) do
    case recv(client) do
      %{"method" => "stream.lagged"} = lagged ->
        {Enum.reverse(events), lagged}

      %{"method" => "interactive.event"} = event ->
        drain_until_lagged(client, [event | events], attempts - 1)

      _other ->
        drain_until_lagged(client, events, attempts - 1)
    end
  end

  defp await_lagging(client, attempts \\ 2_000)
  defp await_lagging(_client, 0), do: flunk("the outbound queue never overflowed")

  defp await_lagging(client, attempts) do
    if lagged_subscription?(conn_pid(client)) do
      :ok
    else
      Process.sleep(10)
      await_lagging(client, attempts - 1)
    end
  end

  defp lagged_subscription?(pid) do
    Enum.any?(:sys.get_state(pid).subscriptions, fn {_key, sub} -> sub.dropped > 0 end)
  end

  defp await_unsubscribed(client, id, attempts \\ 2_000)
  defp await_unsubscribed(_client, _id, 0), do: flunk("unsubscribe was never applied")

  defp await_unsubscribed(client, id, attempts) do
    if Map.has_key?(:sys.get_state(conn_pid(client)).subscriptions, {:interactive, id}) do
      Process.sleep(10)
      await_unsubscribed(client, id, attempts - 1)
    else
      :ok
    end
  end

  # Found by the client socket's own local port rather than by taking the only child, so a
  # test with two connections open addresses the one it means.
  defp conn_pid(client) do
    {:ok, {_address, port}} = :inet.sockname(client)

    Ouroboros.Gateway.ConnSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_id, pid, _type, _modules} -> pid end)
    |> Enum.find(&match?({_address, ^port}, :sys.get_state(&1).peer))
    |> case do
      nil -> flunk("no connection is serving that client socket")
      pid -> pid
    end
  end

  defp writer_pid(client), do: :sys.get_state(conn_pid(client)).writer

  defp await_terminal(id, attempts \\ 200)
  defp await_terminal(_id, 0), do: flunk("the session never reached a terminal status")

  defp await_terminal(id, attempts) do
    case InteractiveSession.info(id) do
      {:ok, %{status: status}} when status in [:closed, :failed, :cancelled, :lost] ->
        status

      _other ->
        Process.sleep(10)
        await_terminal(id, attempts - 1)
    end
  end

  defp await_retired(id, attempts \\ 200)
  defp await_retired(_id, 0), do: flunk("the coordinator never retired")

  defp await_retired(id, attempts) do
    if is_nil(Ouroboros.Interactive.Task.whereis(id)) do
      :ok
    else
      Process.sleep(10)
      await_retired(id, attempts - 1)
    end
  end

  # The harness cleanup is asynchronous from the planes' point of view: a coordinator
  # only notices its harness session vanished on a poll tick, and until that tick lands
  # its store record is non-terminal. The stores' ETS belongs to :jido, not :ouroboros,
  # so such a record outlives this module and every restart of the application — and
  # ApplicationRecoveryTest boots Workspace.Manager against each non-terminal record it
  # finds, under allowed roots that do not include the workspace these sessions ran in.
  # One leaked record fails that boot and everything after it. So every record is driven
  # terminal, its coordinator retired, and the record deleted before the module lets go.
  defp cleanup_stores do
    Enum.each(Ouroboros.Interactive.Store.list(), fn session ->
      unless Ouroboros.Interactive.State.terminal?(session) do
        _ = InteractiveSession.kill(session.id)
        await_terminal(session.id)
      end

      await_retired(session.id)
      _ = Ouroboros.Interactive.Store.delete(session.id)
    end)

    Enum.each(Ouroboros.Coding.Store.list(), fn task ->
      unless Ouroboros.Coding.TaskState.terminal?(task) do
        _ = Ouroboros.CodingSession.cancel(task.id)
        await_coding_terminal(task.id)
      end

      await_coding_retired(task.id)
      _ = Ouroboros.Coding.Store.delete(task.id)
    end)
  end

  defp await_coding_terminal(id, attempts \\ 200)
  defp await_coding_terminal(_id, 0), do: flunk("the coding task never reached a terminal status")

  defp await_coding_terminal(id, attempts) do
    case Ouroboros.Coding.Store.get(id) do
      {:ok, task} ->
        if Ouroboros.Coding.TaskState.terminal?(task) do
          :ok
        else
          Process.sleep(10)
          await_coding_terminal(id, attempts - 1)
        end

      _other ->
        :ok
    end
  end

  defp await_coding_retired(id, attempts \\ 200)
  defp await_coding_retired(_id, 0), do: flunk("the coding coordinator never retired")

  defp await_coding_retired(id, attempts) do
    if is_nil(Ouroboros.Coding.Task.whereis(id)) do
      :ok
    else
      Process.sleep(10)
      await_coding_retired(id, attempts - 1)
    end
  end

  # Polls the plane's durable record until the whole turn is there: every output the
  # adapter emitted and the turn's own completion. 1,500 attempts is the same ceiling
  # philosophy as @receive_timeout — the wait exits on its condition, and the budget
  # only has to absorb a starved scheduler without flaking.
  defp await_ingested(id, outputs, attempts \\ 1_500)
  defp await_ingested(_id, _outputs, 0), do: flunk("the plane never ingested the whole turn")

  defp await_ingested(id, outputs, attempts) do
    ingested? =
      case Ouroboros.Interactive.Store.get(id) do
        {:ok, session} ->
          Enum.count(session.events, &(&1.type == :output_text_final)) >= outputs and
            Enum.any?(session.turns, fn {_turn_id, turn} ->
              Ouroboros.Interactive.State.terminal_turn?(turn)
            end)

        _other ->
          false
      end

    if ingested? do
      :ok
    else
      Process.sleep(10)
      await_ingested(id, outputs, attempts - 1)
    end
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

    await_response(client, id)
  end

  # Notifications interleave with responses on one socket, so a caller waiting for an
  # answer has to skip past the stream rather than mistake it for one.
  defp await_response(client, id, attempts \\ 200)
  defp await_response(_client, id, 0), do: flunk("no response for request #{inspect(id)}")

  defp await_response(client, id, attempts) do
    case recv(client) do
      %{"id" => ^id} = response -> response
      _other -> await_response(client, id, attempts - 1)
    end
  end

  defp recv(client, timeout \\ @receive_timeout) do
    :ok = :inet.setopts(client, packet: :line, active: false, buffer: 1_048_576)

    case :gen_tcp.recv(client, 0, timeout) do
      {:ok, line} -> JSON.decode!(String.trim_trailing(line, "\n"))
      {:error, reason} -> flunk("the connection answered #{inspect(reason)}")
    end
  end

  defp hello(client) do
    call(client, "hello", %{"token" => @token, "protocol" => 1, "client" => "streaming-test"})
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  end

  defp cleanup_runs do
    @provider
    |> then(&Run.list(providers: [&1]))
    |> Enum.each(fn info ->
      unless RunInfo.terminal?(info) do
        _ = Run.cancel(info.run_id)
        _ = Run.await(info.run_id, 1_000)
      end

      _ = Run.prune(info.run_id)
    end)
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-gateway-stream-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp restore_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
