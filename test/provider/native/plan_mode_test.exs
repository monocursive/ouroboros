defmodule Ouroboros.Provider.Native.PlanModeTest do
  @moduledoc """
  B2's runtime half, driven through the real session transport with a scripted model.

  Nothing here stubs the permission layer or the loop: a planning session is opened, a
  write is attempted, the plan-exit approval is answered, and the write is attempted
  again. The properties under test are the ones a person would notice — the refusal says
  "planning", the question offers three answers, the answer actually changes the session,
  and "keep planning" changes nothing.

  Not `async`: the data directory and the model module are node configuration.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.ApprovalResponse
  alias Jido.Harness.SessionRequest
  alias Jido.Harness.TurnRequest
  alias Ouroboros.Provider.Native.Session
  alias Ouroboros.Test.NativeModelScript

  setup do
    root = Path.join(System.tmp_dir!(), "native-plan-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    previous_hooks = Application.get_env(:ouroboros, :native_user_hooks_path)

    Application.put_env(:ouroboros, :native_data_dir, data_dir)
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)
    Application.put_env(:ouroboros, :native_user_hooks_path, Path.join(root, "no-hooks.toml"))

    on_exit(fn ->
      restore(:native_data_dir, previous_dir)
      restore(:native_model_module, previous_model)
      restore(:native_user_hooks_path, previous_hooks)
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
            approval_timeout_ms: 5_000,
            provider_options: %{plan: true}
          },
          overrides
        )
      )

    session_context = %{
      session_id: "sess-plan-#{System.unique_integer([:positive])}",
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

  defp await_event(type, timeout \\ 15_000) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> event
      {:session_adapter_event, _other} -> await_event(type, timeout)
    after
      timeout -> flunk("no #{type} within #{timeout}ms")
    end
  end

  defp collect_until(type, acc \\ []) do
    receive do
      {:session_adapter_event, %{type: ^type} = event} -> Enum.reverse([event | acc])
      {:session_adapter_event, event} -> collect_until(type, [event | acc])
    after
      15_000 -> flunk("no #{type} within 15s; got #{inspect(Enum.map(acc, & &1.type))}")
    end
  end

  defp drain do
    receive do
      {:session_adapter_event, _event} -> drain()
    after
      0 -> :ok
    end
  end

  # The worker journals; a harness-driven test reads the journal rather than a mailbox.
  defp await_replay(session_id, predicate, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 15_000
    {:ok, events} = Jido.Harness.Session.replay(session_id, cursor: 0, limit: 500)

    cond do
      predicate.(events) ->
        events

      System.monotonic_time(:millisecond) > deadline ->
        flunk("condition never held; saw #{inspect(Enum.map(events, & &1.type))}")

      true ->
        Process.sleep(20)
        await_replay(session_id, predicate, deadline)
    end
  end

  defp write_call(id, path, content),
    do: {:tool_call, %{id: id, name: "write", input: %{"path" => path, "content" => content}}}

  defp plan_call(id),
    do:
      {:tool_call,
       %{
         id: id,
         name: "plan",
         input: %{
           "steps" => [%{"step" => "read lib/a.ex", "status" => "completed"}],
           "explanation" => "the shape of the change"
         }
       }}

  # ---------------------------------------------------------------- the posture

  describe "the read-only posture" do
    test "plan mode refuses a write with a refusal that names planning", context do
      script = [
        [write_call("c1", "lib/b.ex", "nope")],
        [{:text, "I could not write."}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      result = await_event(:tool_result)

      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "plan mode"
      assert result.payload["output"] =~ "record your plan with the `plan` tool"
      refute File.exists?(Path.join(context.workspace, "lib/b.ex"))
    end

    test "plan mode refuses a command with the same refusal", context do
      script = [
        [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => "touch nope"}}}],
        [{:text, "no shell"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      result = await_event(:tool_result)

      assert result.payload["is_error"] == true
      assert result.payload["output"] =~ "plan mode"
      assert result.payload["output"] =~ "refuses every execute"
    end

    test "plan mode still lets the model read", context do
      script = [
        [{:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}],
        [{:text, "read it"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      result = await_event(:tool_result)

      assert result.payload["is_error"] == false
      assert result.payload["output"] =~ "defmodule A"
    end

    test "a planning turn declares the mode and the sandbox it is actually running under",
         context do
      script = [[{:text, "planning"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      started = await_event(:turn_started)

      assert started.payload["approval_mode"] == "plan"
      assert started.payload["sandbox_mode"] == "read_only"
    end

    test "the write tools stay in the list so their refusal can name planning", context do
      # Deliberate, and the reason is in `Session`'s own comment: the loop resolves a call
      # against `disallowed_tools`, so a tool removed from the list would come back as
      # "not a tool in this session" rather than as a refusal that says why. The prompt
      # names them instead.
      script = [[{:text, "planning"}, {:finish, :stop}]]
      %{handle: handle, agent: agent} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      started = await_event(:turn_started)

      assert "write" in started.payload["tools"]
      assert [%{system: system, tools: tools} | _rest] = NativeModelScript.requests(agent)

      # The list the model is shown and the list the prompt describes are the same list.
      assert Enum.map(tools, & &1.name) == started.payload["tools"]
      assert system =~ "`write`, `edit`, `apply_patch`, `bash`"
    end

    test "the system prompt tells the model to plan and stop", context do
      script = [[{:text, "planning"}, {:finish, :stop}]]
      %{handle: handle, agent: agent} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      collect_until(:approval_requested)

      assert [%{system: system} | _rest] = NativeModelScript.requests(agent)
      assert system =~ "## Plan mode"
      assert system =~ "produce a plan and\nstop"
    end

    test "a sandbox_mode change while planning is recorded and not applied", context do
      script = [[{:text, "planning"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.configure(handle, %{sandbox_mode: :workspace_write})
      assert {:ok, state} = Session.plan_state(handle)

      assert state.plan == true
      assert state.sandbox_mode == :read_only
      assert state.sandbox_after_plan == :workspace_write
    end
  end

  # ---------------------------------------------------------------- the exit

  describe "the plan-exit approval" do
    test "the plan-exit approval carries the three choices", context do
      script = [[plan_call("c1")], [{:text, "that is the plan"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert request.payload["kind"] == "plan_exit"
      assert request.payload["plan_source"] == "plan_tool"

      assert request.payload["plan"]["plan"] == [
               %{"step" => "read lib/a.ex", "status" => "completed"}
             ]

      assert Enum.map(request.payload["options"], & &1["optionId"]) ==
               ["auto_edit", "prompt", "keep_planning"]

      assert Enum.map(request.payload["options"], & &1["kind"]) ==
               ["allow_always", "allow_once", "reject_once"]

      # The turn is held open on purpose: the harness worker denies an approval whose turn
      # is no longer its active one, so a question raised after `turn_completed` would be
      # auto-denied as stale.
      assert request.turn_id == "turn-1"
      refute_received {:session_adapter_event, %{type: :turn_completed}}
    end

    test "the question falls back to the final message when the model ignored the plan tool",
         context do
      script = [
        [{:text, "Step one: rename the module. Step two: update callers."}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert request.payload["kind"] == "plan_exit"
      assert request.payload["plan_source"] == "message"
      assert request.payload["message"] =~ "Step one: rename the module"
      refute Map.has_key?(request.payload, "plan")
    end

    test "a turn that produced nothing completes without asking", context do
      script = [[{:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      completed = await_event(:turn_completed)

      assert completed.turn_id == "turn-1"
      assert {:ok, %{awaiting_plan_exit: false, plan: true}} = Session.plan_state(handle)
    end

    test "answering auto_edit reconfigures the session and the turn then completes",
         context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "auto_edit"}
                 })
               )

      exit_event = await_event(:provider_event)
      assert exit_event.payload["kind"] == "plan_exit"
      assert exit_event.payload["choice"] == "auto_edit"
      assert exit_event.payload["applied"] == true
      assert exit_event.payload["plan"] == false
      assert exit_event.payload["approval_mode"] == "auto_edit"
      assert exit_event.payload["sandbox_mode"] == "workspace_write"

      completed = await_event(:turn_completed)
      assert completed.turn_id == "turn-1"

      assert {:ok, %{plan: false, approval_mode: :auto_edit, sandbox_mode: :workspace_write}} =
               Session.plan_state(handle)
    end

    test "after auto_edit a write succeeds", context do
      script = [
        [plan_call("c1")],
        [{:text, "planned"}, {:finish, :stop}],
        [write_call("c2", "lib/b.ex", "defmodule B do\nend\n")],
        [{:text, "written"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "auto_edit"}
                 })
               )

      await_event(:turn_completed)
      drain()

      assert :ok = Session.send(handle, TurnRequest.new!("now build it"), "turn-2")
      result = await_event(:tool_result)

      assert result.payload["is_error"] == false
      assert File.read!(Path.join(context.workspace, "lib/b.ex")) == "defmodule B do\nend\n"
    end

    test "answering prompt sets manual approvals", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "prompt"}
                 })
               )

      await_event(:turn_completed)

      assert {:ok, %{plan: false, approval_mode: :prompt, sandbox_mode: :workspace_write}} =
               Session.plan_state(handle)
    end

    test "keep_planning leaves everything as it was", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)
      assert {:ok, before} = Session.plan_state(handle)

      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{
                   decision: :deny,
                   provider_options: %{"choice" => "keep_planning"}
                 })
               )

      exit_event = await_event(:provider_event)
      assert exit_event.payload["choice"] == "keep_planning"
      assert exit_event.payload["applied"] == false

      await_event(:turn_completed)

      assert {:ok, after_answer} = Session.plan_state(handle)
      assert after_answer.plan == before.plan
      assert after_answer.approval_mode == before.approval_mode
      assert after_answer.sandbox_mode == before.sandbox_mode
      assert after_answer.awaiting_plan_exit == false
    end

    test "a client that can only approve or deny still reaches the three answers", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      # `approve` with `scope: :session` is what today's TUI sends for the row whose
      # provider option declares `kind: "allow_always"`, which is the auto_edit row.
      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{decision: :approve, scope: :session})
               )

      exit_event = await_event(:provider_event)
      assert exit_event.payload["choice"] == "auto_edit"
    end

    test "a follow-up supplied with the answer runs as the rest of the same turn", context do
      script = [
        [plan_call("c1")],
        [{:text, "planned"}, {:finish, :stop}],
        [write_call("c2", "lib/b.ex", "built\n")],
        [{:text, "built it"}, {:finish, :stop}]
      ]

      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      request = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 request.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "auto_edit", "follow_up" => "now build it"}
                 })
               )

      exit_event = await_event(:provider_event)
      assert exit_event.payload["follow_up"] == true

      # The same turn continues rather than a second one starting: the harness worker's
      # active turn is still `turn-1`, so its approvals still route and its terminal event
      # still finishes the turn it dispatched.
      started = await_event(:turn_started)
      assert started.turn_id == "turn-1"

      completed = await_event(:turn_completed)
      assert completed.turn_id == "turn-1"
      assert File.read!(Path.join(context.workspace, "lib/b.ex")) == "built\n"
    end

    test "nobody answering leaves the session planning and completes the turn", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script, %{approval_timeout_ms: 250})
      await_event(:provider_event)

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      await_event(:approval_requested)

      unanswered = await_event(:provider_event)
      assert unanswered.payload["status"] == "plan_exit_unanswered"

      await_event(:turn_completed)
      assert {:ok, %{plan: true, awaiting_plan_exit: false}} = Session.plan_state(handle)
    end
  end

  # ---------------------------------------------------------------- durability

  describe "durability" do
    test "plan mode survives a resume", context do
      script = [[{:text, "planning"}, {:finish, :stop}]]
      %{handle: handle, request: request} = open(context, script)
      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      assert :ok = Session.close(handle)
      await_event(:session_closed)
      drain()

      {model_spec, _agent} =
        NativeModelScript.start([[{:text, "still planning"}, {:finish, :stop}]])

      resumed_request =
        SessionRequest.new!(%{
          provider: :native,
          cwd: request.cwd,
          model: model_spec,
          approval_mode: :auto_approve,
          provider_session_id: provider_session_id
        })

      {:ok, resumed} =
        Session.open(resumed_request, %{
          session_id: "sess-plan-resumed",
          provider: :native,
          owner: self(),
          adapter: Ouroboros.Provider.Native,
          config: %{},
          process_manager: Jido.Harness.ProcessDriver.Erlexec,
          telemetry_context: %{}
        })

      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)

      # Nothing in the resumed request says "plan": the posture came off disk.
      refute Map.has_key?(resumed_request.provider_options, :plan)
      assert {:ok, %{plan: true, sandbox_mode: :read_only}} = Session.plan_state(resumed)
    end

    test "leaving plan mode survives a resume too", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]
      %{handle: handle, request: request} = open(context, script)
      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      approval = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 approval.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "prompt"}
                 })
               )

      await_event(:turn_completed)
      assert :ok = Session.close(handle)
      drain()

      {model_spec, _agent} = NativeModelScript.start([])

      {:ok, resumed} =
        Session.open(
          SessionRequest.new!(%{
            provider: :native,
            cwd: request.cwd,
            model: model_spec,
            provider_session_id: provider_session_id
          }),
          %{
            session_id: "sess-plan-resumed-2",
            provider: :native,
            owner: self(),
            adapter: Ouroboros.Provider.Native,
            config: %{},
            process_manager: Jido.Harness.ProcessDriver.Erlexec,
            telemetry_context: %{}
          }
        )

      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)

      # And the answer itself survives. The resumed request says nothing about approvals,
      # so it defaults to `:prompt`; the session comes back at `:prompt` because that is
      # what a person chose, not because that is the default.
      assert {:ok, %{plan: false, approval_mode: :prompt}} = Session.plan_state(resumed)
    end

    test "the plan-exit answer outlives a restart the request would have overruled", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]

      %{handle: handle, request: request} =
        open(context, script, %{approval_mode: :prompt, provider_options: %{plan: true}})

      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      approval = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 approval.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "auto_edit"}
                 })
               )

      await_event(:turn_completed)
      assert :ok = Session.close(handle)
      drain()

      {model_spec, _agent} = NativeModelScript.start([])

      # The interactive plane rebuilds a resumed request from its own durable options, so
      # this is exactly the request a restart produces: `approval_mode: :prompt`, the mode
      # the session *started* in, with no memory of the answer.
      {:ok, resumed} =
        Session.open(
          SessionRequest.new!(%{
            provider: :native,
            cwd: request.cwd,
            model: model_spec,
            approval_mode: :prompt,
            provider_session_id: provider_session_id
          }),
          %{
            session_id: "sess-plan-answered",
            provider: :native,
            owner: self(),
            adapter: Ouroboros.Provider.Native,
            config: %{},
            process_manager: Jido.Harness.ProcessDriver.Erlexec,
            telemetry_context: %{}
          }
        )

      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)
      assert {:ok, %{plan: false, approval_mode: :auto_edit}} = Session.plan_state(resumed)
    end

    test "an explicit approval_mode change supersedes the plan-exit answer", context do
      script = [[plan_call("c1")], [{:text, "planned"}, {:finish, :stop}]]

      %{handle: handle, request: request} =
        open(context, script, %{approval_mode: :prompt, provider_options: %{plan: true}})

      ready = await_event(:provider_event)
      provider_session_id = ready.provider_session_id

      assert :ok = Session.send(handle, TurnRequest.new!("plan it"), "turn-1")
      approval = await_event(:approval_requested)

      assert :ok =
               Session.respond_approval(
                 handle,
                 approval.request_id,
                 ApprovalResponse.new!(%{
                   decision: :approve,
                   provider_options: %{"choice" => "auto_edit"}
                 })
               )

      await_event(:turn_completed)
      assert :ok = Session.configure(handle, %{approval_mode: :auto_approve})
      assert :ok = Session.close(handle)
      drain()

      {model_spec, _agent} = NativeModelScript.start([])

      {:ok, resumed} =
        Session.open(
          SessionRequest.new!(%{
            provider: :native,
            cwd: request.cwd,
            model: model_spec,
            approval_mode: :auto_approve,
            provider_session_id: provider_session_id
          }),
          %{
            session_id: "sess-plan-superseded",
            provider: :native,
            owner: self(),
            adapter: Ouroboros.Provider.Native,
            config: %{},
            process_manager: Jido.Harness.ProcessDriver.Erlexec,
            telemetry_context: %{}
          }
        )

      on_exit(fn -> if Process.alive?(resumed), do: Session.close(resumed) end)

      # The file no longer names a mode, so the request decides — which is the only way
      # `interactive.configure` can stay the authority it is everywhere else.
      assert {:ok, %{approval_mode: :auto_approve}} = Session.plan_state(resumed)
    end
  end

  # ---------------------------------------------------------------- the verb

  describe "plan_mode/2" do
    test "turning plan mode on mid-session forces read_only and remembers what it displaced",
         context do
      script = [[{:text, "hello"}, {:finish, :stop}]]

      %{handle: handle} =
        open(context, script, %{provider_options: %{}, sandbox_mode: :workspace_write})

      await_event(:provider_event)

      assert {:ok, %{plan: false, sandbox_mode: :workspace_write}} = Session.plan_state(handle)
      assert :ok = Session.plan_mode(handle, true)

      assert {:ok, %{plan: true, sandbox_mode: :read_only, sandbox_after_plan: :workspace_write}} =
               Session.plan_state(handle)

      assert :ok = Session.plan_mode(handle, false)
      assert {:ok, %{plan: false, sandbox_mode: :workspace_write}} = Session.plan_state(handle)
    end

    # The mode the provider now offers by name is displaced and restored like any other.
    # Plan mode outranks full access — it has to, or a session an operator put into
    # planning would still hold an unsandboxed shell — and leaving must give it back
    # rather than quietly downgrading the session to `workspace_write`.
    test "plan mode displaces :unrestricted and hands it back on the way out", context do
      script = [[{:text, "hello"}, {:finish, :stop}]]

      %{handle: handle} =
        open(context, script, %{provider_options: %{}, sandbox_mode: :unrestricted})

      await_event(:provider_event)

      assert {:ok, %{plan: false, sandbox_mode: :unrestricted}} = Session.plan_state(handle)
      assert :ok = Session.plan_mode(handle, true)

      assert {:ok, %{plan: true, sandbox_mode: :read_only, sandbox_after_plan: :unrestricted}} =
               Session.plan_state(handle)

      assert :ok = Session.plan_mode(handle, false)
      assert {:ok, %{plan: false, sandbox_mode: :unrestricted}} = Session.plan_state(handle)
    end

    test "a session started in plan mode still restores :unrestricted when it leaves",
         context do
      script = [[{:text, "hello"}, {:finish, :stop}]]

      %{handle: handle} =
        open(context, script, %{
          provider_options: %{plan: true},
          sandbox_mode: :unrestricted
        })

      await_event(:provider_event)

      assert {:ok, %{plan: true, sandbox_mode: :read_only}} = Session.plan_state(handle)
      assert :ok = Session.plan_mode(handle, false)
      assert {:ok, %{plan: false, sandbox_mode: :unrestricted}} = Session.plan_state(handle)
    end

    test "plan mode is reachable and durable through the harness worker", context do
      # The end-to-end check the unit tests above cannot make: driven through
      # `Jido.Harness.Session` rather than by calling the transport's callbacks, because
      # the worker is the thing that would deny a plan-exit approval as *stale* if the
      # terminal event had gone out first. Plan → question → auto_edit → a write that
      # succeeds, with the worker's own bookkeeping intact throughout.
      script = [
        [plan_call("c1")],
        [{:text, "that is the plan"}, {:finish, :stop}],
        [write_call("c2", "lib/built.ex", "defmodule Built do\nend\n")],
        [{:text, "built"}, {:finish, :stop}]
      ]

      {model_spec, _agent} = NativeModelScript.start(script)

      {:ok, session_id} =
        Jido.Harness.Session.start(:native, %{
          cwd: context.workspace,
          model: model_spec,
          approval_mode: :prompt,
          approval_timeout_ms: 10_000,
          provider_options: %{plan: true}
        })

      on_exit(fn -> Jido.Harness.Session.close(session_id) end)

      {:ok, turn_id} = Jido.Harness.Session.send_message(session_id, "plan the change")
      events = await_replay(session_id, &Enum.any?(&1, fn e -> e.type == :approval_requested end))
      ask = Enum.find(events, &(&1.type == :approval_requested))

      assert ask.payload["kind"] == "plan_exit"
      assert ask.turn_id == turn_id

      # The failure this whole design avoids: the worker denies an approval whose turn is
      # no longer its active one, and it says so with this event.
      refute Enum.any?(events, fn event ->
               event.type == :provider_event and
                 event.payload["kind"] == "stale_approval_denied"
             end)

      assert {:ok, %{state: :awaiting_approval}} = Jido.Harness.Session.info(session_id)

      assert :ok =
               Jido.Harness.Session.respond_approval(session_id, ask.request_id, %{
                 decision: :approve,
                 scope: :session
               })

      events = await_replay(session_id, &Enum.any?(&1, fn e -> e.type == :turn_completed end))

      exit_event =
        Enum.find(events, &(&1.type == :provider_event and &1.payload["kind"] == "plan_exit"))

      assert exit_event.payload["choice"] == "auto_edit"
      assert {:ok, result} = Jido.Harness.Session.await(session_id, turn_id, 15_000)
      assert result.status == :completed

      # And the posture really changed: the write that plan mode refused now applies with
      # no approval at all, because `auto_edit` is what the operator chose.
      {:ok, second} = Jido.Harness.Session.send_message(session_id, "now build it")
      assert {:ok, %{status: :completed}} = Jido.Harness.Session.await(session_id, second, 15_000)

      assert File.read!(Path.join(context.workspace, "lib/built.ex")) ==
               "defmodule Built do\nend\n"
    end

    test "leaving plan mode rebuilds the prefix", context do
      script = [[{:text, "hello"}, {:finish, :stop}]]
      %{handle: handle} = open(context, script)
      await_event(:provider_event)

      assert {:ok, %{prefix_fingerprint: planning}} = Session.info(handle)
      assert :ok = Session.plan_mode(handle, false)
      assert {:ok, %{prefix_fingerprint: building}} = Session.info(handle)

      refute planning == building
    end
  end
end
