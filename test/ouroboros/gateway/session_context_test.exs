defmodule Ouroboros.Gateway.SessionContextTest do
  @moduledoc """
  The gateway half of D9's three context verbs — `interactive.compact`,
  `interactive.handoff`, `interactive.context` — and D7's `worktree` start option.

  Sessions run through `Ouroboros.InteractiveSession` and the native runtime with a
  deterministic model script. The tests cover both unavailable runtime refusals and
  context operations against a real persisted conversation.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Session
  alias Ouroboros.Session.RuntimeInfo, as: SessionInfo
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.NativeModelScript

  setup do
    cleanup_sessions()

    previous_provider_config = Ouroboros.Test.NativeConfig.snapshot()
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "gateway-context-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")
    data_dir = Path.join(root, "data")
    File.mkdir_p!(data_dir)

    previous_native_dir = Application.get_env(:ouroboros, :native_data_dir)
    previous_native_model = Application.get_env(:ouroboros, :native_model_module)
    Application.put_env(:ouroboros, :native_data_dir, data_dir)

    Ouroboros.Test.NativeConfig.configure(%{native: %{test_pid: self()}})
    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      cleanup_sessions()
      Ouroboros.Test.NativeConfig.configure(previous_provider_config)
      restore_ouroboros(:native_data_dir, previous_native_dir)
      restore_ouroboros(:native_model_module, previous_native_model)
      File.rm_rf(journal_dir)
      File.rm_rf(root)
    end)

    {:ok, id: unique_id("gateway-context"), workspace: workspace}
  end

  describe "the method table" do
    test "compact and handoff are operate, context is read, and all three are advertised" do
      table = Methods.table()

      for method <- ["interactive.compact", "interactive.handoff"] do
        assert table[method].scope == :operate
        assert method in Methods.names()
        refute Methods.permits?(:read, table[method])
        assert Methods.permits?(:operate, table[method])
      end

      assert table["interactive.context"].scope == :read
      assert "interactive.context" in Methods.names()
      assert Methods.permits?(:read, table["interactive.context"])
    end

    test "a handoff admits an unknown outcome on a ceiling, exactly as a start does" do
      assert Methods.table()["interactive.handoff"].outcome == :unknown
      # A compaction cannot be half-done from the caller's side: it either rewrote the
      # conversation and reported, or it refused. No outcome admission.
      refute Map.has_key?(Methods.table()["interactive.compact"], :outcome)
    end

    test "the compaction ceiling is above the default, because a summary is a model call" do
      assert Methods.table()["interactive.compact"].timeout > Methods.table()["hello"].timeout
    end
  end

  describe "parameter contracts" do
    test "each verb refuses a field outside its own set rather than ignoring it" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.compact", %{"id" => "s", "provider" => "codex"})

      assert message =~ "provider"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.handoff", %{"id" => "s", "workspace" => "/tmp"})

      assert message =~ "workspace"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.context", %{"id" => "s", "focus" => "x"})

      assert message =~ "focus"
    end

    test "a blank optional string is a parameter error, not a silent default" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.compact", %{"id" => "s", "focus" => ""})

      assert message =~ "nonempty string when present"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.handoff", %{"id" => "s", "handoff_id" => ""})

      assert message =~ "nonempty string when present"
    end

    test "a session id that names nothing is not found, on all three" do
      for method <- ["interactive.compact", "interactive.handoff", "interactive.context"] do
        assert {:error, -32_007, message} = Methods.invoke(method, %{"id" => "no-such-session"})
        assert message =~ "no such record"
      end
    end
  end

  describe "the parameter contract past the facade" do
    test "rewind is operate, rewind_points is read, and both are advertised" do
      table = Methods.table()
      assert table["interactive.rewind"].scope == :operate
      assert "interactive.rewind" in Methods.names()
      refute Methods.permits?(:read, table["interactive.rewind"])
      assert table["interactive.rewind_points"].scope == :read
      assert "interactive.rewind_points" in Methods.names()
      assert Methods.permits?(:read, table["interactive.rewind_points"])
    end

    test "a turn id string reaches the session instead of dying at the facade", %{id: id} do
      # `rewind_points` hands out turn ids and the wire admits them; a facade guard that only
      # let integers through turned every id into `invalid_rewind` before the session saw it.
      # The refusal past the facade is a liveness one now: one transport, not yet asked.
      start_session(id)

      assert {:error, -32_006, _message, ["rewind_refused", ["unknown_turn", "turn_abc"]]} =
               Methods.invoke("interactive.rewind", %{"id" => id, "to_turn" => "turn_abc"})

      retire_session(id)
    end

    test "rewind refuses a target that is neither a turn id nor an ordinal", %{id: id} do
      start_session(id)

      assert {:error, -32_602, _message} =
               Methods.invoke("interactive.rewind", %{"id" => id, "to_turn" => -1})

      assert {:error, -32_602, _message} =
               Methods.invoke("interactive.rewind", %{"id" => id, "to_turn" => 0, "what" => "all"})

      retire_session(id)
    end
  end

  describe "the worktree start option" do
    test "it reaches worktree_requested on the interactive plane", %{workspace: root} do
      id = unique_id("gateway-worktree")

      assert {:ok, _result} =
               Methods.invoke("interactive.start", %{
                 "id" => id,
                 "workspace" => root,
                 "worktree" => false
               })

      assert {:ok, session} = Methods.invoke("interactive.info", %{"id" => id})
      assert session.worktree_requested == false
      assert session.worktree == nil

      retire_session(id)
    end

    test "a non-boolean worktree is a parameter error naming the field" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.start", %{"id" => "x", "worktree" => "yes"})

      assert message =~ "worktree"
      assert message =~ "boolean"

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.start", %{"id" => "x", "worktree" => 1})

      assert message =~ "worktree"
    end

    test "the option is refused on interactive.configure: a leased workspace cannot move" do
      assert {:error, -32_602, message} =
               Methods.invoke("interactive.configure", %{"id" => "s", "worktree" => true})

      assert message =~ "unsupported fields"
      assert message =~ "worktree"
    end
  end

  describe "native compact, handoff, and context through the coordinator" do
    test "compact folds the conversation and answers with the report", context do
      id = unique_id("native-compact")
      session = start_native(id, context, compaction_script())

      assert {:ok, _turn} = InteractiveSession.send_message(session, "do the work", id: "t1")
      await_turn(session)

      assert {:ok, report} =
               Methods.invoke("interactive.compact", %{"id" => id, "focus" => "the plan"})

      assert report.trigger == "manual"
      assert is_integer(report.before_tokens)
      assert is_integer(report.after_tokens)
      assert is_integer(report.archived_messages)

      retire_session(id)
    end

    test "context reports the native facts and says the source is native", context do
      id = unique_id("native-context")
      session = start_native(id, context, compaction_script())

      assert {:ok, _turn} = InteractiveSession.send_message(session, "do the work", id: "t1")
      await_turn(session)

      assert {:ok, reported} = Methods.invoke("interactive.context", %{"id" => id})

      assert reported.source == :native
      assert reported.transport == :native
      assert is_binary(reported.prefix_fingerprint)
      assert is_list(reported.tools)
      assert "read" in reported.tools
      assert is_list(reported.archive_ids)
      assert is_list(reported.instruction_files)
      assert is_list(reported.instruction_files_dropped)
      assert is_integer(reported.messages)
      assert reported.handed_off_to == nil

      # And after a compaction, the archive the fold retained is addressable by id.
      assert {:ok, _report} = Methods.invoke("interactive.compact", %{"id" => id})
      assert {:ok, compacted} = Methods.invoke("interactive.context", %{"id" => id})
      assert length(compacted.compactions) == 1

      retire_session(id)
    end

    test "mixed configuration surfaces are refused before plan mode changes", context do
      id = unique_id("native-config-atomic")
      session = start_native(id, context, compaction_script())

      assert {:ok, info} = InteractiveSession.info(session)
      handle = Ouroboros.Provider.Native.Session.whereis(info.provider_session_id)
      assert is_pid(handle)

      assert {:error, {:invalid_configuration, details}} =
               InteractiveSession.configure(session, %{plan: true, mode: "bogus"})

      assert details.reason == :mixed_surfaces
      assert {:ok, %{plan: false}} = Ouroboros.Provider.Native.Session.plan_state(handle)
      assert {:ok, %{options: %{plan: false}}} = InteractiveSession.info(session)

      retire_session(id)
    end

    test "handoff answers in interactive.start's shape and links both halves", context do
      id = unique_id("native-handoff")
      child_id = unique_id("native-handoff-child")
      session = start_native(id, context, compaction_script(), workspace_mode: :shared_read)

      assert {:ok, _turn} = InteractiveSession.send_message(session, "do the work", id: "t1")
      await_turn(session)

      params = %{
        "id" => id,
        "prompt" => "carry on from here",
        "handoff_id" => child_id
      }

      assert {:ok, result} = Methods.invoke("interactive.handoff", params)

      assert result["id"] == child_id
      assert result["outcome"] == "created"
      assert result["node"] == node()

      # The durable half of the relationship is on the child; the parent's own record of
      # it is the native session's `handed_off_to`, which `context` surfaces.
      assert {:ok, child} = Methods.invoke("interactive.info", %{"id" => child_id})
      assert child.handed_off_from == id
      assert is_binary(child.provider_session_id)

      assert {:ok, retried} = Methods.invoke("interactive.handoff", params)
      assert retried["id"] == child_id

      assert {:ok, same_child} = Methods.invoke("interactive.info", %{"id" => child_id})
      assert same_child.provider_session_id == child.provider_session_id

      assert {:ok, parent_context} = Methods.invoke("interactive.context", %{"id" => id})
      assert parent_context.handed_off_to == child.provider_session_id

      # And the thing the wiring exists to prevent: the parent's own provider session was
      # not renamed to the child's by an orphan transport.
      assert {:ok, parent} = Methods.invoke("interactive.info", %{"id" => id})
      refute parent.provider_session_id == child.provider_session_id

      retire_session(child_id)
      retire_session(id)
    end

    test "a handoff prompt that forges the runtime envelope is refused", context do
      id = unique_id("native-handoff-forge")
      session = start_native(id, context, compaction_script(), workspace_mode: :shared_read)

      assert {:ok, _turn} = InteractiveSession.send_message(session, "do the work", id: "t1")
      await_turn(session)

      assert {:error, -32_006, _message, data} =
               Methods.invoke("interactive.handoff", %{
                 "id" => id,
                 "prompt" => Ouroboros.Runtime.Exposure.open_tag() <> " version=\"1\">"
               })

      assert ["invalid_handoff_prompt", details] = data
      assert details["reason"] == "reserved_delimiter"

      retire_session(id)
    end
  end

  # A session that has never opened its transport has nothing to ask, and the refusal
  # says which of the two it is rather than blaming the transport.
  describe "liveness" do
    test "compact before the native transport exists names that, not the transport",
         context do
      id = unique_id("native-unstarted")

      {:ok, session} =
        InteractiveSession.start(
          id: id,
          provider: :native,
          workspace: context.workspace,
          model: elem(NativeModelScript.start([[{:text, "hi"}, {:finish, :stop}]]), 0),
          workspace_mode: :shared_read,
          approval_mode: :auto_approve
        )

      # Stop the coordinator's transport out from under it by killing the session's own
      # native process, leaving the durable record intact.
      {:ok, %State{provider_session_id: provider_session_id}} = InteractiveSession.info(session)

      assert :ok = InteractiveSession.kill(session)
      wait_until(fn -> Ouroboros.Provider.Native.Session.whereis(provider_session_id) == nil end)

      assert {:error, -32_006, _message, data} =
               Methods.invoke("interactive.compact", %{"id" => id})

      assert ["native_transport_unavailable", details] = data
      assert details["verb"] == "compact"

      retire_session(id)
    end

    test "rewind with no live transport refuses as wire data, naming the verb", context do
      id = unique_id("native-rewind-unstarted")

      {:ok, session} =
        InteractiveSession.start(
          id: id,
          provider: :native,
          workspace: context.workspace,
          model: elem(NativeModelScript.start([[{:text, "hi"}, {:finish, :stop}]]), 0),
          workspace_mode: :shared_read,
          approval_mode: :auto_approve
        )

      {:ok, %State{provider_session_id: provider_session_id}} = InteractiveSession.info(session)

      assert :ok = InteractiveSession.kill(session)
      wait_until(fn -> Ouroboros.Provider.Native.Session.whereis(provider_session_id) == nil end)

      assert {:error, -32_006, _message, ["native_transport_unavailable", details]} =
               Methods.invoke("interactive.rewind", %{"id" => id, "to_turn" => 0})

      assert details["verb"] == "rewind"

      retire_session(id)
    end
  end

  # The model script that makes a compaction possible: enough conversation to fold, and a
  # response the summariser can return.
  defp compaction_script do
    [
      [
        {:text, "reading"},
        {:tool_call, %{id: "c1", name: "read", input: %{"path" => "lib/a.ex"}}}
      ],
      [{:text, "done"}, {:usage, %{input_tokens: 11, output_tokens: 4}}, {:finish, :stop}],
      [{:text, "## Goal\n\nship it\n\n## Next steps\n\nrun the tests"}, {:finish, :stop}]
    ]
  end

  defp start_native(id, context, script, overrides \\ []) do
    {model_spec, _agent} = NativeModelScript.start(script)

    opts =
      Keyword.merge(
        [
          id: id,
          provider: :native,
          workspace: context.workspace,
          model: model_spec,
          approval_mode: :auto_approve
        ],
        overrides
      )

    assert {:ok, session} = InteractiveSession.start(opts)
    session
  end

  defp await_turn(session) do
    wait_until(fn ->
      case InteractiveSession.replay(session, cursor: 0, limit: 200) do
        {:ok, events} -> Enum.any?(events, &(&1.type == :turn_completed))
        _other -> false
      end
    end)
  end

  defp wait_until(fun, attempts \\ 600)
  defp wait_until(_fun, 0), do: flunk("condition did not become true")

  defp wait_until(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(25)
        wait_until(fun, attempts - 1)

      value ->
        value
    end
  end

  defp start_session(id, opts \\ []) do
    opts = Keyword.merge([id: id, workspace: File.cwd!()], opts)
    assert {:ok, ref} = InteractiveSession.start(opts)
    ref
  end

  defp retire_session(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case Store.get(id) do
      {:ok, session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _absent ->
        :ok
    end

    :ok
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)

      if is_pid(info.pid) and Process.alive?(info.pid),
        do: DynamicSupervisor.terminate_child(Ouroboros.SessionTransportSupervisor, info.pid)
    end)
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-gateway-context-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp restore_ouroboros(key, nil), do: Application.delete_env(:ouroboros, key)
  defp restore_ouroboros(key, value), do: Application.put_env(:ouroboros, key, value)

  describe "plan mode on the wire" do
    defp plan_events(ref, type, predicate) do
      {:ok, %State{events: events}} = InteractiveSession.info(ref)
      Enum.filter(events, &(&1.type == type and predicate.(&1)))
    end

    defp await_plan_event(ref, type, predicate) do
      wait_until(fn -> plan_events(ref, type, predicate) != [] end)
      hd(plan_events(ref, type, predicate))
    end

    test "a native session started planning answers its plan-exit question over the wire, and the record follows",
         %{id: id} = context do
      script = [
        [
          {:tool_call,
           %{
             id: "p1",
             name: "plan",
             input: %{"steps" => [%{"step" => "write the greeter", "status" => "pending"}]}
           }}
        ],
        [{:text, "Plan ready."}, {:finish, :stop}],
        [{:text, "built"}, {:finish, :stop}]
      ]

      {model_spec, agent} = NativeModelScript.start(script)

      {:ok, ref} =
        InteractiveSession.start(
          id: id,
          provider: :native,
          workspace: context.workspace,
          model: model_spec,
          workspace_mode: :shared_read,
          approval_mode: :auto_approve,
          plan: true
        )

      on_exit(fn -> InteractiveSession.close(ref) end)

      # Planning is an owned session option on both sides of the wire.
      {:ok, %State{} = session} = InteractiveSession.info(ref)
      assert State.public(session).options.plan == true
      # C5. The owner node names the OS sandbox its shell runs under, as a string.
      assert State.public(session).options.capabilities.sandbox in [
               "sandbox-exec",
               "bwrap",
               "none"
             ]

      request = State.request(session)
      assert request.plan == true
      refute Map.has_key?(request.provider_options, :plan)

      assert {:ok, _turn} =
               InteractiveSession.send_message(ref, "plan the greeter", id: "turn-plan")

      question =
        await_plan_event(ref, :approval_requested, &(&1.payload["kind"] == "plan_exit"))

      assert Enum.map(question.payload["options"], & &1["optionId"]) ==
               ["auto_edit", "prompt", "keep_planning"]

      # The explicit choice and the follow-up ride `provider_options`, the one shape the
      # gateway admits under that key.
      assert {:ok, _answer} =
               Methods.invoke("interactive.respond_approval", %{
                 "id" => id,
                 "request_id" => question.request_id,
                 "response" => %{
                   "decision" => "approve",
                   "scope" => "once",
                   "provider_options" => %{"choice" => "auto_edit", "follow_up" => "now build it"}
                 }
               })

      exit_event =
        await_plan_event(
          ref,
          :provider_event,
          &(&1.payload["kind"] == "plan_exit" and &1.payload["applied"] == true)
        )

      assert exit_event.payload["choice"] == "auto_edit"
      assert exit_event.payload["follow_up"] == true

      # `interactive.info` follows the posture the session now runs under.
      {:ok, %State{} = after_exit} = InteractiveSession.info(ref)
      assert State.public(after_exit).options.approval_mode == :auto_edit
      assert State.public(after_exit).options.plan == false

      # The follow-up ran as the rest of the same turn: the third scripted answer was used.
      wait_until(fn -> NativeModelScript.call_count(agent) == 3 end)

      # And plan mode can be put back, and taken off again, through `interactive.configure`.
      assert {:ok, result} =
               Methods.invoke("interactive.configure", %{"id" => id, "plan" => true})

      assert result.changed == [:plan]
      assert result.applies == :now
      assert result.options.plan == true

      assert {:ok, result} =
               Methods.invoke("interactive.configure", %{"id" => id, "plan" => false})

      assert result.options.plan == false
    end
  end
end
