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
            request: state.request,
            provider: state.request[:provider] || :claude,
            provider_session_id: state.request[:provider_session_id] || "vendor-session",
            principal_id: state.id
          }}, state}

    def handle_call({:configure, changes}, _, state),
      do: {:reply, :ok, %{state | request: Map.merge(state.request, changes)}}

    def handle_call({:request_approval, _, request}, from, state) do
      send(state.test, {:approval, request, from})
      {:noreply, state}
    end

    def handle_info(_event, state), do: {:noreply, state}

    def handle_cast({:subagent_bridge_event, event}, state) do
      send(state.test, {:bridge_event, event})
      {:noreply, state}
    end
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

  defp owner(context, opts \\ %{}) do
    id = "bridge-owner-#{System.unique_integer([:positive])}"

    request =
      Map.merge(
        %{
          cwd: context.root,
          model: "sonnet",
          approval_mode: :auto_approve,
          sandbox_mode: :read_only,
          metadata: %{ouroboros_session_id: id}
        },
        opts
      )

    {:ok, pid} = Owner.start_link({id, self(), request})

    on_exit(fn ->
      SubagentBridge.close(pid)
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    {id, pid}
  end

  test "gateway spawn retries reuse one child, collection is scoped, and request IDs cannot change meaning",
       context do
    {id, _owner} = owner(context)

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
             Ouroboros.Agent.EffectLedger.list(principal: "session:" <> id, effect: :tool_call)

    assert Enum.any?(entries, &(&1.attempt.tool == "agent"))
  end

  test "live parent tool restrictions and planning posture replace the sidecar's opening posture",
       context do
    {id, owner} = owner(context)

    assert {:ok, %{is_error: true}} =
             SubagentBridge.call(id, "first", "agent_result", %{"task_id" => "missing"})

    :ok = GenServer.call(owner, {:configure, %{allowed_tools: ["Read"]}})

    assert {:ok, %{is_error: true, output: refused}} =
             SubagentBridge.call(id, "second", "agent", %{"prompt" => "read"})

    assert refused =~ "not a tool"
    assert NativeModelScript.call_count(context.script) == 0

    :ok =
      GenServer.call(owner, {:configure, %{allowed_tools: nil, provider_options: %{plan: true}}})

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

  test "tool dispatch leaves the owner responsive during approval and terminates its sidecar on owner death",
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
    monitor = Process.monitor(session)
    GenServer.stop(owner)
    assert_receive {:DOWN, ^monitor, :process, ^session, _}, 5_000
  end

  test "unknown vendor allowlist entries never become unrestricted native defaults", context do
    assert {:ok, request} =
             SubagentBridge.native_request(%{
               provider: :claude,
               request: %{
                 cwd: context.root,
                 allowed_tools: ["Bash(git status)"],
                 disallowed_tools: ["Bash(rm *)"]
               }
             })

    assert request.allowed_tools == ["unavailable_vendor_tool:Bash(git status)"]
    assert request.disallowed_tools == ["bash"]

    assert {:error, :unsupported_bridge_tool} =
             Ouroboros.Provider.Native.Loop.run_tool(%Ouroboros.Provider.Native.Loop{}, %{
               name: "bash"
             })
  end

  test "gateway rejects caller posture and stop cannot address a different session's child",
       context do
    {id, _} = owner(context)

    assert {:error, -32602, _} =
             Ouroboros.Gateway.Methods.invoke("subagent.spawn", %{
               "id" => id,
               "request_id" => "bad",
               "input" => %{"prompt" => "x"},
               "approval_mode" => "auto_approve"
             })

    assert {:ok, reply} =
             Ouroboros.Gateway.Methods.invoke("subagent.stop", %{
               "id" => id,
               "request_id" => "stop",
               "task_id" => "another-session-child"
             })

    assert reply["is_error"] == true or reply[:is_error] == true
    assert NativeModelScript.call_count(context.script) == 0
  end

  test "native caller reuses the live parent transport and its child registry", context do
    provider_id = "native-bridge-reuse-#{System.unique_integer([:positive])}"
    {id, owner} = owner(context, %{provider: :native, provider_session_id: provider_id})
    model = Application.fetch_env!(:ouroboros, :native_model)

    request =
      Jido.Harness.SessionRequest.new!(%{
        provider: :native,
        cwd: context.root,
        model: model,
        provider_session_id: provider_id,
        approval_mode: :auto_approve
      })

    {:ok, session} =
      Ouroboros.Provider.Native.Session.open(
        request,
        %{
          session_id: id,
          provider: :native,
          owner: owner,
          adapter: Ouroboros.Provider.Native,
          config: %{},
          process_manager: Jido.Harness.ProcessManager,
          telemetry_context: %{}
        }
      )

    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(id, "spawn", "agent", %{
               "prompt" => "child",
               "background" => true
             })

    [{bridge, _}] = Registry.lookup(Ouroboros.Interactive.Registry, {SubagentBridge, owner})
    assert %{session: ^session, owned?: false} = :sys.get_state(bridge)
    assert GenServer.call(session, :subagent_counts).tracked == 1

    assert_receive {:bridge_event, %{payload: %{"phase" => "spawned", "task_id" => task_id}}},
                   5_000

    assert {:ok, _} = GenServer.call(session, {:subagent_lookup, task_id})

    assert {:ok, %{is_error: false}} =
             SubagentBridge.call(id, "stop", "agent_result", %{
               "task_id" => task_id,
               "stop" => true
             })

    assert GenServer.call(session, :subagent_counts).tracked == 0
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

    assert {:error, {:no_model, _}} =
             SubagentBridge.call(id, "new-spawn", "agent", %{"prompt" => "needs a model"})
  end
end
