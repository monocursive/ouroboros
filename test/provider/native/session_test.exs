defmodule Ouroboros.Provider.Native.SessionTest do
  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Checkpoint
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-session-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)
    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)

    # The model module is node configuration, never a session option — a request that
    # could name the module the runtime calls would be arbitrary code execution behind
    # `interactive.start`. A test therefore configures the node, exactly as an operator
    # would point a node at a different client.
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      File.rm_rf(root)
    end)

    %{root: root, workspace: workspace, data_dir: data_dir}
  end

  defp restore(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore(key, value), do: Application.put_env(:ouroboros, key, value)

  defp open(context, script, overrides \\ %{}) do
    {model_spec, agent} = NativeModelScript.start(script)

    request =
      SessionRequest.new!(
        Map.merge(
          %{
            provider: :native,
            cwd: context.workspace,
            model: model_spec,
            approval_mode: :auto_approve,
            approval_timeout_ms: 2_000
          },
          overrides
        )
      )

    session_context = %{
      session_id: "sess-#{System.unique_integer([:positive])}",
      provider: :native,
      owner: self(),
      adapter: Ouroboros.Provider.Native,
      config: %{},
      process_manager: Jido.Harness.ProcessDriver.Erlexec,
      telemetry_context: %{}
    }

    {:ok, handle} = Session.open(request, session_context)
    on_exit(fn -> if Process.alive?(handle), do: Session.close(handle) end)
    %{handle: handle, agent: agent, model_spec: model_spec, request: request}
  end

  defp collect_until(type, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> Enum.reverse([event | acc])
      {:session_adapter_event, event} -> collect_until(type, [event | acc])
    after
      15_000 -> flunk("no #{type} within 15s; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp await_event(type) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event(type)
    after
      15_000 -> flunk("no #{type} within 15s")
    end
  end

  @simple_script [
    [{:text, "hello"}, {:usage, %{input_tokens: 5, output_tokens: 2}}, {:finish, :stop}]
  ]

  describe "open and close" do
    test "reports a native provider_session_id and a ready event", context do
      %{handle: handle} = open(context, @simple_script)

      ready = await_event(:provider_event)
      assert ready.payload["kind"] == "native_ready"
      assert String.starts_with?(ready.provider_session_id, "native-")
      assert Process.alive?(handle)
    end

    test "refuses a provider_session_id that could become a path", context do
      {model_spec, _agent} = NativeModelScript.start([])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          provider_session_id: "../../etc/passwd"
        })

      session_context = %{
        session_id: "sess-bad",
        provider: :native,
        owner: self(),
        adapter: Ouroboros.Provider.Native,
        config: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec,
        telemetry_context: %{}
      }

      assert {:error, _reason} = Session.open(request, session_context)
    end

    test "refuses to open with no model and no OUROBOROS_NATIVE_MODEL", context do
      request = SessionRequest.new!(%{provider: :native, cwd: context.workspace})

      session_context = %{
        session_id: "sess-no-model",
        provider: :native,
        owner: self(),
        adapter: Ouroboros.Provider.Native,
        config: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec,
        telemetry_context: %{}
      }

      assert {:error, {:no_model, message}} = Session.open(request, session_context)
      assert message =~ "OUROBOROS_NATIVE_MODEL"
    end

    test "close emits session_closed and stops the process", context do
      %{handle: handle} = open(context, @simple_script)
      await_event(:provider_event)

      assert :ok = Session.close(handle)
      closed = await_event(:session_closed)
      assert closed.payload["reason"] == "closed"
      refute Process.alive?(handle)
    end
  end

  describe "turns" do
    test "runs a turn and emits the loop's events with the session's provider id", context do
      %{handle: handle} = open(context, @simple_script)
      ready = await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      events = collect_until(:turn_completed)

      assert Enum.map(events, & &1.type) == [
               :turn_started,
               :output_text_delta,
               :output_text_final,
               :usage,
               :turn_completed
             ]

      assert Enum.all?(events, &(&1.turn_id == "turn-1"))
      assert Enum.all?(events, &(&1.provider_session_id == ready.provider_session_id))
    end

    test "refuses a second turn while one is running", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "sleep 1"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("first"), "turn-1")
      assert {:error, :busy} = Session.send(handle, TurnRequest.new!("second"), "turn-2")

      collect_until(:turn_completed)
      assert :ok = Session.send(handle, TurnRequest.new!("third"), "turn-3")
    end

    test "a second turn sees the first turn's messages", context do
      script = [
        [{:text, "first answer"}, {:finish, :stop}],
        [{:text, "second answer"}, {:finish, :stop}]
      ]

      %{handle: handle, agent: agent} = open(context, script)
      await_event(:provider_event)

      Session.send(handle, TurnRequest.new!("one"), "turn-1")
      collect_until(:turn_completed)

      Session.send(handle, TurnRequest.new!("two"), "turn-2")
      collect_until(:turn_completed)

      [_first, second] = NativeModelScript.requests(agent)

      assert Enum.map(second.messages, & &1.role) == [:user, :assistant, :user]
      assert List.last(second.messages).content == "two"
    end
  end

  describe "steer, interrupt, approvals, configure" do
    test "steer is refused with no active turn and delivered when there is one", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:text, "acknowledged"}, {:finish, :stop}]
      ]

      %{handle: handle, agent: agent} = open(context, script)
      await_event(:provider_event)

      assert {:error, :no_active_turn} =
               Session.steer(handle, TurnRequest.new!("too early"), "req-0")

      Session.send(handle, TurnRequest.new!("go"), "turn-1")
      await_event(:tool_call)
      assert :ok = Session.steer(handle, TurnRequest.new!("also check the tests"), "req-1")

      collect_until(:turn_completed)

      [_first, second] = NativeModelScript.requests(agent)
      assert List.last(second.messages) == %{role: :user, content: "also check the tests"}
    end

    test "interrupt stops the turn and is refused when nothing is running", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:tool_call, %{id: "c2", name: "bash", input: %{"command" => "echo two"}}}],
        [{:text, "never"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert {:error, :not_active} = Session.interrupt(handle, :active)

      Session.send(handle, TurnRequest.new!("go"), "turn-1")
      await_event(:tool_call)
      assert :ok = Session.interrupt(handle, "turn-1")

      events = collect_until(:turn_interrupted)
      assert List.last(events).payload["reason"] == "interrupted"

      # The session is usable again afterwards.
      assert {:error, :not_active} = Session.interrupt(handle, :active)
    end

    test "an approval request is routed to the loop and resolved", context do
      script = [
        [
          {:tool_call,
           %{id: "c1", name: "write", input: %{"path" => "lib/new.ex", "content" => "hi\n"}}}
        ],
        [{:text, "wrote it"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script, %{approval_mode: :prompt})
      await_event(:provider_event)

      Session.send(handle, TurnRequest.new!("write it"), "turn-1")
      ask = await_event(:approval_requested)

      assert ask.turn_id == "turn-1"
      assert is_binary(ask.request_id)

      assert {:error, :unknown_request} =
               Session.respond_approval(handle, "not-a-request", %ApprovalResponse{
                 decision: :approve,
                 scope: :once
               })

      assert :ok =
               Session.respond_approval(handle, ask.request_id, %ApprovalResponse{
                 decision: :approve,
                 scope: :once
               })

      collect_until(:turn_completed)
      assert File.read!(Path.join(context.workspace, "lib/new.ex")) == "hi\n"
    end

    test "configure changes the model, mode, and sandbox for the next turn", context do
      {other_spec, other_agent} =
        NativeModelScript.start([[{:text, "from the new model"}, {:finish, :stop}]])

      %{handle: handle} = open(context, @simple_script)
      await_event(:provider_event)

      assert :ok = Session.configure(handle, %{model: other_spec, approval_mode: :prompt})
      assert :ok = Session.configure(handle, %{sandbox_mode: :read_only})

      assert {:error, {:unsupported_configuration, :nonsense, 1}} =
               Session.configure(handle, %{nonsense: 1})

      Session.send(handle, TurnRequest.new!("go"), "turn-1")
      collect_until(:turn_completed)

      assert NativeModelScript.call_count(other_agent) == 1
    end

    test "a sandbox change takes effect on the next tool call, not the next turn", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "echo one"}}}],
        [{:text, "done"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.configure(handle, %{sandbox_mode: :read_only})
      Session.send(handle, TurnRequest.new!("go"), "turn-1")

      events = collect_until(:turn_completed)
      result = Enum.find(events, &(&1.type == :tool_result))
      assert result.payload["is_error"]
      assert result.payload["output"] =~ "read_only"
    end
  end

  describe "payload discipline" do
    test "a tool result that echoed a credential is redacted before it is emitted", context do
      System.put_env("OUROBOROS_NATIVE_SESSION_API_KEY", "sk-live-do-not-emit-me")
      on_exit(fn -> System.delete_env("OUROBOROS_NATIVE_SESSION_API_KEY") end)

      # `Jido.Harness.Redaction` caches this node's sensitive environment per process,
      # and the session process is started below, after the variable is set.
      script = [
        [
          {:tool_call,
           %{
             id: "c1",
             name: "bash",
             input: %{"command" => "echo $OUROBOROS_NATIVE_SESSION_API_KEY"}
           }}
        ],
        [{:text, "printed it"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      Session.send(handle, TurnRequest.new!("print the key"), "turn-1")
      events = collect_until(:turn_completed)

      result = Enum.find(events, &(&1.type == :tool_result))
      assert result.payload["output"] =~ "[REDACTED]"
      refute inspect(Enum.map(events, & &1.payload)) =~ "sk-live-do-not-emit-me"
    end
  end

  describe "resume" do
    test "restores the conversation from the checkpoint after the process is killed", context do
      script = [
        [{:text, "first answer"}, {:finish, :stop}],
        [{:text, "after the restart"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      Session.send(handle, TurnRequest.new!("remember this"), "turn-1")
      collect_until(:turn_completed)

      {:ok, checkpoint_path, durable?} = Checkpoint.locate(provider_session_id)
      assert durable?
      assert File.exists?(checkpoint_path)

      # Kill the transport the way a BEAM restart would.
      Process.exit(handle, :kill)
      refute Process.alive?(handle)

      # A second session, same script agent, resuming by id.
      {model_spec, agent} = NativeModelScript.start([[{:text, "resumed"}, {:finish, :stop}]])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          provider_session_id: provider_session_id
        })

      session_context = %{
        session_id: "sess-resumed",
        provider: :native,
        owner: self(),
        adapter: Ouroboros.Provider.Native,
        config: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec,
        telemetry_context: %{}
      }

      {:ok, resumed} = Session.open(request, session_context)
      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)

      again = await_event(:provider_event)
      assert again.provider_session_id == provider_session_id

      Session.send(resumed, TurnRequest.new!("what did I say?"), "turn-2")
      collect_until(:turn_completed)

      [request] = NativeModelScript.requests(agent)

      assert Enum.map(request.messages, & &1.role) == [:user, :assistant, :user]
      assert Enum.at(request.messages, 0).content == "remember this"
      assert Enum.at(request.messages, 1).content == "first answer"
    end

    test "a corrupt checkpoint refuses the resume rather than starting empty under that id",
         context do
      %{handle: handle} = open(context, @simple_script)
      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      collect_until(:turn_completed)
      Session.close(handle)

      {:ok, checkpoint_path, _durable?} = Checkpoint.locate(provider_session_id)
      payload = checkpoint_path |> File.read!() |> JSON.decode!()
      File.write!(checkpoint_path, JSON.encode!(%{payload | "messages" => []}))

      {model_spec, _agent} = NativeModelScript.start([])

      request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: context.workspace,
          model: model_spec,
          provider_session_id: provider_session_id
        })

      session_context = %{
        session_id: "sess-corrupt",
        provider: :native,
        owner: self(),
        adapter: Ouroboros.Provider.Native,
        config: %{},
        process_manager: Jido.Harness.ProcessDriver.Erlexec,
        telemetry_context: %{}
      }

      assert {:error, {:checkpoint_unusable, :checkpoint_digest_mismatch}} =
               Session.open(request, session_context)
    end

    test "the checkpoint is written before the terminal turn event reaches the owner", context do
      %{handle: handle} = open(context, @simple_script)
      ready = await_event(:provider_event)
      {:ok, checkpoint_path, _durable?} = Checkpoint.locate(ready.provider_session_id)

      Session.send(handle, TurnRequest.new!("hi"), "turn-1")

      # The assertion is the ordering: by the time `turn_completed` is observable, the
      # file already holds this turn.
      await_event(:turn_completed)
      assert {:ok, messages} = Checkpoint.read(checkpoint_path)
      assert Enum.any?(messages, &(&1[:content] == "hi"))
    end

    test "the checkpoint file is private", context do
      %{handle: handle} = open(context, @simple_script)
      ready = await_event(:provider_event)

      Session.send(handle, TurnRequest.new!("hi"), "turn-1")
      await_event(:turn_completed)

      {:ok, checkpoint_path, _durable?} = Checkpoint.locate(ready.provider_session_id)
      {:ok, %File.Stat{mode: mode}} = File.stat(checkpoint_path)
      assert Bitwise.band(mode, 0o777) == 0o600
    end
  end
end
