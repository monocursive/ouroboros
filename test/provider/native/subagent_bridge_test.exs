defmodule Ouroboros.Provider.Native.SubagentBridgeTest do
  use ExUnit.Case, async: false
  alias Ouroboros.Provider.Native.SubagentBridge
  alias Ouroboros.Test.NativeModelScript

  defmodule Owner do
    use GenServer
    def start_link(args), do: GenServer.start_link(__MODULE__, args)

    def init({id, test, request}) do
      Registry.register(Ouroboros.Interactive.Registry, id, nil)
      {:ok, %{id: id, test: test, request: request}}
    end

    def handle_call(:subagent_bridge_state, _, state),
      do:
        {:reply,
         {:ok,
          %{
            provider_session_id: state.request.provider_session_id,
            principal_id: state.id
          }}, state}

    def handle_call({:configure, changes}, _, state),
      do: {:reply, :ok, %{state | request: Map.merge(state.request, changes)}}

    def handle_call({:session, session}, _, state),
      do: attach_session(session, state)

    def handle_call(:session, _, state), do: {:reply, state[:session], state}

    def handle_call({:request_approval, _, request}, from, state) do
      send(state.test, {:approval, request, from})
      {:noreply, state}
    end

    def handle_info({:session_output, _runtime, _generation, _cursor}, state),
      do: {:noreply, drain_session(state)}

    def handle_info(_event, state), do: {:noreply, state}

    def handle_cast({:subagent_bridge_event, event}, state) do
      send(state.test, {:bridge_event, event})
      {:noreply, state}
    end

    defp attach_session(session, state) do
      {:ok, attachment, _info} = Ouroboros.Session.attach(session, self(), 0)
      state = Map.merge(state, %{session: session, attachment: attachment, cursor: 0, events: []})
      {:reply, :ok, drain_session(state)}
    end

    defp drain_session(%{attachment: attachment, cursor: cursor} = state) do
      case Ouroboros.Session.drain(attachment, cursor, 500) do
        {:ok, [], _} ->
          state

        {:ok, events, _} ->
          cursor = List.last(events).sequence
          updated = %{state | cursor: cursor, events: state.events ++ events}
          :ok = Ouroboros.Session.ack(attachment, cursor)
          updated

        {:error, :not_found} ->
          state
      end
    end

    defp drain_session(state), do: state
  end

  setup do
    root = Path.join(System.tmp_dir!(), "bridge-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)

    saved =
      Map.new(
        [:native_data_dir, :native_model_module, :native_model, :native_user_hooks_path],
        &{&1, Application.get_env(:ouroboros, &1)}
      )

    env = System.get_env("OUROBOROS_NATIVE_MODEL")
    System.delete_env("OUROBOROS_NATIVE_MODEL")
    Application.put_env(:ouroboros, :native_data_dir, Path.join(root, "data"))
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    {model, script} = NativeModelScript.start([[{:text, "child answer"}, {:finish, :stop}]])
    Application.put_env(:ouroboros, :native_model, model)

    on_exit(fn ->
      Enum.each(saved, fn {key, value} ->
        if value == nil,
          do: Application.delete_env(:ouroboros, key),
          else: Application.put_env(:ouroboros, key, value)
      end)

      if env,
        do: System.put_env("OUROBOROS_NATIVE_MODEL", env),
        else: System.delete_env("OUROBOROS_NATIVE_MODEL")

      File.rm_rf(root)
    end)

    %{root: root, script: script}
  end

  # The owner holds a real `Provider.Native.Session`, because that is the only thing a
  # child can run on: there is one provider, its session lives in this VM, and the bridge
  # reuses it rather than opening anything of its own. The scripted model is what keeps the
  # session deterministic; everything else about it is the real transport.
  defp owner(context, opts \\ %{}) do
    id = "bridge-owner-#{System.unique_integer([:positive])}"

    attrs =
      Map.merge(
        %{
          provider: :native,
          model: Application.get_env(:ouroboros, :native_model),
          cwd: context.root,
          approval_mode: :auto_approve,
          sandbox_mode: :read_only,
          env: %{},
          env_mode: :overlay,
          metadata: %{ouroboros_session_id: id}
        },
        opts
      )

    {:ok, request} = Ouroboros.Session.Request.new(attrs)
    {:ok, pid} = Owner.start_link({id, self(), request})

    {:ok, runtime_id} = Ouroboros.Session.open(id, request)
    {:ok, runtime} = Ouroboros.Session.info(runtime_id)
    session = runtime.pid

    provider_session_id = runtime.provider_session_id
    :ok = GenServer.call(pid, {:configure, %{provider_session_id: provider_session_id}})
    :ok = GenServer.call(pid, {:session, session})

    on_exit(fn ->
      SubagentBridge.close(pid)

      if Process.alive?(session),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, session)

      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    {id, pid}
  end

  test "gateway spawn retries reuse one child, collection is scoped, and request IDs cannot change meaning",
       context do
    {id, owner} = owner(context)
    {:ok, runtime} = owner |> GenServer.call(:session) |> Ouroboros.Session.info()

    params = %{
      "id" => id,
      "request_id" => "spawn-1",
      "input" => %{"prompt" => "read", "background" => true}
    }

    assert {:ok, reply} = Ouroboros.Gateway.Methods.invoke("subagent.spawn", params)
    assert reply["is_error"] == false or reply[:is_error] == false
    assert {:ok, ^reply} = Ouroboros.Gateway.Methods.invoke("subagent.spawn", params)

    assert_receive {:bridge_event,
                    %{
                      type: :provider_event,
                      payload: %{"phase" => "spawned", "task_id" => task_id}
                    }},
                   5_000

    refute_receive {:bridge_event, %{type: :provider_event, payload: %{"phase" => "spawned"}}},
                   100

    {other, _} = owner(context)

    assert {:ok, %{is_error: true, output: unknown}} =
             SubagentBridge.call(other, "collect-1", "agent_result", %{
               "task_id" => task_id,
               "wait_ms" => 0
             })

    assert unknown =~ "No subagent"

    assert {:ok, %{is_error: false, output: result}} =
             SubagentBridge.call(id, "collect-1", "agent_result", %{
               "task_id" => task_id,
               "wait_ms" => 5_000
             })

    assert result =~ "child answer"

    assert {:error, :request_id_conflict} =
             SubagentBridge.call(id, "spawn-1", "agent", %{"prompt" => "different"})

    assert NativeModelScript.call_count(context.script) == 1

    assert {:ok, entries} =
             Ouroboros.Agent.EffectLedger.list(
               principal: "session:" <> runtime.runtime_id,
               effect: :tool_call
             )

    assert Enum.any?(entries, &(&1.attempt.tool == "agent"))
  end

  # The child inherits the parent session's live posture, because it runs on the parent's
  # own transport. A tool the parent was not allowed is not one a bridged spawn can reach,
  # and a planning parent cannot spawn at all.
  test "the child inherits the live parent's tool restrictions", context do
    {id, _owner} = owner(context, %{allowed_tools: ["read"]})

    assert {:ok, %{is_error: true}} =
             SubagentBridge.call(id, "first", "agent_result", %{"task_id" => "missing"})

    assert {:ok, %{is_error: true, output: refused}} =
             SubagentBridge.call(id, "second", "agent", %{"prompt" => "read"})

    assert refused =~ "not a tool"
    assert NativeModelScript.call_count(context.script) == 0
  end

  test "a planning parent cannot spawn a child", context do
    {id, _owner} = owner(context, %{plan: true})

    assert {:ok, %{is_error: true, output: planning}} =
             SubagentBridge.call(id, "third", "agent", %{"prompt" => "plan", "background" => true})

    assert planning =~ "plan mode"
    assert NativeModelScript.call_count(context.script) == 0
  end

  test "native tool hook blocks the vendor spawn before any model invocation", context do
    hook = Path.join(context.root, "block.sh")
    File.write!(hook, "#!/bin/sh\necho bridge-hook-denial >&2\nexit 2\n")
    File.chmod!(hook, 0o755)
    config = Path.join(context.root, "hooks.toml")

    File.write!(
      config,
      "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"agent\"\ncommand = \"#{hook}\"\n"
    )

    Application.put_env(:ouroboros, :native_user_hooks_path, config)
    {id, _} = owner(context)

    assert {:ok, %{is_error: true, output: text}} =
             SubagentBridge.call(id, "hook", "agent", %{"prompt" => "blocked"})

    assert text =~ "bridge-hook-denial"
    assert NativeModelScript.call_count(context.script) == 0
  end

  test "tool dispatch leaves the owner responsive and coordinator death removes its bridge while preserving the runtime",
       context do
    {id, owner} = owner(context, %{approval_mode: :prompt})

    pending =
      Task.async(fn ->
        SubagentBridge.call(id, "approve", "agent", %{"prompt" => "child", "background" => true})
      end)

    assert_receive {:approval, _request, from}, 5_000
    assert :ok = GenServer.call(owner, {:configure, %{sandbox_mode: :read_only}})
    GenServer.reply(from, {:ok, %{response: %{decision: :approve, scope: :once}}})
    assert {:ok, %{is_error: false}} = Task.await(pending, 10_000)
    [{bridge, _}] = Registry.lookup(Ouroboros.Interactive.Registry, {SubagentBridge, owner})
    session = :sys.get_state(bridge).session
    monitor = Process.monitor(bridge)
    GenServer.stop(owner)
    assert_receive {:DOWN, ^monitor, :process, ^bridge, _}, 5_000
    assert Process.alive?(session)
    assert {:ok, info} = Ouroboros.Session.info(session)
    assert info.logical_id == id
  end

  for stop_kind <- [:deadline, :interrupt, :owner] do
    @tag approval_stop_kind: stop_kind
    test "unanswered foreground approval does not block #{stop_kind} and is cancelled",
         %{approval_stop_kind: stop_kind} = context do
      {model, _script} =
        NativeModelScript.start([
          [
            {:tool_call,
             %{id: "write", name: "write", input: %{"path" => "out.txt", "content" => "x"}}}
          ],
          [{:text, "done"}, {:finish, :stop}]
        ])

      Application.put_env(:ouroboros, :native_model, model)

      {id, owner} =
        owner(context, %{
          approval_mode: :prompt,
          sandbox_mode: :workspace_write,
          approval_timeout_ms: 30_000
        })

      pending =
        Task.async(fn ->
          SubagentBridge.call(id, "pending-child", "agent", %{
            "prompt" => "write",
            "deadline_ms" => if(stop_kind == :deadline, do: 1_000, else: 30_000)
          })
        end)

      assert_receive {:approval, _, parent_approval}, 5_000
      GenServer.reply(parent_approval, {:ok, %{response: %{decision: :approve, scope: :once}}})
      assert_receive {:approval, %{relay_payload: %{"subagent" => _}}, {relay, _}}, 5_000
      relay_monitor = Process.monitor(relay)
      [{bridge, _}] = Registry.lookup(Ouroboros.Interactive.Registry, {SubagentBridge, owner})
      session = :sys.get_state(bridge).session

      case stop_kind do
        :interrupt ->
          assert :ok = Ouroboros.Test.NativeSessionFixture.interrupt(session, :active)
          assert {:error, :interrupted} = Task.await(pending, 5_000)

        :owner ->
          GenServer.stop(owner)
          assert {:error, {:bridge_unavailable, _}} = Task.await(pending, 5_000)

        :deadline ->
          assert {:ok, %{is_error: true, output: output}} = Task.await(pending, 5_000)
          assert output =~ "timed_out"
      end

      # No human answer is needed to finish, and the approval coordinator's monitored
      # caller dies so it can close the obsolete request through its normal DOWN path.
      assert_receive {:DOWN, ^relay_monitor, :process, ^relay, _}, 5_000

      if stop_kind != :owner do
        assert :sys.get_state(bridge).relays == %{}
        assert :sys.get_state(bridge).task == nil
      end

      refute File.exists?(Path.join(context.root, "out.txt"))
    end
  end

  test "the child runs on the live parent transport and its child registry", context do
    {id, owner} = owner(context)
    session = GenServer.call(owner, :session)

    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(id, "spawn", "agent", %{
               "prompt" => "child",
               "background" => true
             })

    [{bridge, _}] = Registry.lookup(Ouroboros.Interactive.Registry, {SubagentBridge, owner})

    # The bridge opens nothing of its own: there is one provider, its session is in this
    # VM, and the child is registered under it.
    assert %{session: ^session} = :sys.get_state(bridge)

    assert_receive {:bridge_event, %{payload: %{"phase" => "spawned", "task_id" => task_id}}},
                   5_000

    assert {:ok, %{is_error: false, output: result}} =
             SubagentBridge.call(id, "collect", "agent_result", %{
               "task_id" => task_id,
               "wait_ms" => 5_000
             })

    assert result =~ "child answer"
  end

  test "real interactive coordinator supplies live posture and refuses new work immediately after close",
       context do
    model = Application.fetch_env!(:ouroboros, :native_model)

    {:ok, session} =
      Ouroboros.InteractiveSession.start(
        id: "real-bridge-#{System.unique_integer([:positive])}",
        provider: :native,
        workspace: context.root,
        model: model,
        approval_mode: :auto_approve
      )

    on_exit(fn -> Ouroboros.InteractiveSession.close(session) end)

    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(session.id, "spawn", "agent", %{
               "prompt" => "child",
               "background" => true
             })

    assert {:ok, _} = Ouroboros.InteractiveSession.configure(session, %{plan: true})

    assert {:ok, %{is_error: true, output: refused}} =
             SubagentBridge.call(session.id, "plan", "agent", %{"prompt" => "cannot execute"})

    assert refused =~ "plan mode"
    assert :ok = Ouroboros.InteractiveSession.close(session)

    assert {:error, _} =
             SubagentBridge.call(session.id, "after-close", "agent", %{"prompt" => "must not run"})
  end

  test "full spawn receipt capacity still permits child collection", context do
    {id, owner} = owner(context)
    input = %{"prompt" => "child", "background" => true}
    assert {:ok, original} = SubagentBridge.call(id, "spawn", "agent", input)

    assert_receive {:bridge_event, %{payload: %{"phase" => "spawned", "task_id" => task_id}}},
                   5_000

    [{bridge, _}] = Registry.lookup(Ouroboros.Interactive.Registry, {SubagentBridge, owner})

    :sys.replace_state(bridge, fn state ->
      cache =
        Enum.reduce(1..127, state.cache, fn n, cache ->
          Map.put(cache, "old-spawn-#{n}", {{"agent", <<n>>}, {:ok, original}})
        end)

      cache =
        Enum.reduce(1..128, cache, fn n, cache ->
          Map.put(cache, "old-result-#{n}", {{"agent_result", <<n>>}, {:ok, original}})
        end)

      %{state | cache: cache}
    end)

    assert {:error, :bridge_request_capacity} =
             SubagentBridge.call(id, "over-cap", "agent", input)

    assert {:ok, ^original} = SubagentBridge.call(id, "spawn", "agent", input)

    assert {:ok, %{is_error: false, output: text}} =
             SubagentBridge.call(id, "collect", "agent_result", %{
               "task_id" => task_id,
               "wait_ms" => 5_000
             })

    assert text =~ "child answer"
    assert map_size(:sys.get_state(bridge).cache) == 256
  end

  test "collecting an existing child does not require a native default to remain configured",
       context do
    {id, _owner} = owner(context)

    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(id, "spawn", "agent", %{
               "prompt" => "child",
               "background" => true
             })

    assert_receive {:bridge_event, %{payload: %{"phase" => "spawned", "task_id" => task_id}}},
                   5_000

    Application.delete_env(:ouroboros, :native_model)

    assert {:ok, %{is_error: false, output: result}} =
             SubagentBridge.call(id, "result", "agent_result", %{
               "task_id" => task_id,
               "wait_ms" => 5_000
             })

    assert result =~ "child answer"

    # And a new child still starts, because it runs on the parent's live transport rather
    # than on whatever the node's default happens to be at that moment.
    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(id, "new-spawn", "agent", %{"prompt" => "another child"})
  end
end
