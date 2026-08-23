defmodule Ouroboros.InteractiveApprovalLedgerTest do
  @moduledoc """
  I1 — the human answer, in the durable effect ledger, on every provider.

  `Ouroboros.Control.Permissions` already records what the rule engine decided. What these
  tests pin is the other half: the answer a *person* gave, which no rule can reconstruct
  afterwards, recorded before it is forwarded anywhere, whichever way the question was
  asked — the `ouro mcp-serve` bridge, a transport with its own approvals channel, or the
  native agent's own loop.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.HarnessAdapter
  alias Ouroboros.Test.NativeModelScript

  @provider :ouroboros_test
  @receive_timeout 5_000

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    previous_model = Application.get_env(:ouroboros, :native_model_module)
    journal_dir = unique_journal_dir()

    root = Path.join(System.tmp_dir!(), "approval-ledger-#{System.unique_integer([:positive])}")
    workspace = Path.join(root, "workspace")
    File.mkdir_p!(Path.join(workspace, "lib"))
    File.write!(Path.join(workspace, "lib/a.ex"), "defmodule A do\n  def x, do: 1\nend\n")

    Application.put_env(
      :jido_harness,
      :providers,
      Map.put(map_or_empty(previous_providers), @provider, HarnessAdapter)
    )

    Application.put_env(
      :jido_harness,
      :provider_config,
      Map.put(map_or_empty(previous_provider_config), @provider, %{
        test_pid: self(),
        retention: %{journal_dir: journal_dir}
      })
    )

    Application.put_env(:ouroboros, :native_model_module, NativeModelScript)

    on_exit(fn ->
      cleanup_sessions()
      restore_harness_env(:providers, previous_providers)
      restore_harness_env(:provider_config, previous_provider_config)

      case previous_model do
        nil -> Application.delete_env(:ouroboros, :native_model_module)
        module -> Application.put_env(:ouroboros, :native_model_module, module)
      end

      File.rm_rf(journal_dir)
      File.rm_rf(root)
    end)

    {:ok, id: unique_id("approval-ledger"), workspace: workspace}
  end

  describe "the Claude bridge (interactive.request_approval)" do
    test "one entry per human answer, written before the caller is told", %{id: id} do
      ref = start_bridge_session(id)

      request_approval(ref, %{
        "tool_name" => "Bash",
        "input" => %{"command" => "rm -rf ./build"},
        "tool_use_id" => "toolu_1"
      })

      requested = await_event(ref, :approval_requested)

      assert :ok =
               InteractiveSession.respond_approval(ref, requested.request_id, %{
                 decision: :approve,
                 scope: :once
               })

      assert_receive {:approval_answer, {:ok, _answer}}, @receive_timeout

      assert [entry] = approvals(id)
      assert entry.status == :ok
      assert entry.effect == :approval
      assert entry.principal == "session:" <> id
      assert entry.attempt.request_id == requested.request_id
      assert entry.attempt.tool == "Bash"
      assert entry.attempt.provider == @provider
      assert entry.attempt.node == node()
      assert entry.result == %{decision: :allow, scope: :once, actor: :human, origin: "external"}
      assert entry.authority.decision == :allow
      assert entry.authority.reason == "human"

      # The command line is a digest and nothing else.
      assert entry.attempt.subject.command_sha256 ==
               :sha256 |> :crypto.hash("rm -rf ./build") |> Base.encode16(case: :lower)

      refute inspect(entry) =~ "rm -rf"

      retire_session(id)
    end

    test "the resolution event names the entry ledger.get takes", %{id: id} do
      ref = start_bridge_session(id)

      request_approval(ref, %{"tool_name" => "Read", "input" => %{"file_path" => "lib/a.ex"}})
      requested = await_event(ref, :approval_requested)

      assert :ok =
               InteractiveSession.respond_approval(ref, requested.request_id, %{
                 decision: :approve,
                 scope: :once
               })

      resolved = await_event(ref, :approval_resolved)
      ref_field = resolved.payload["ledger_ref"]

      assert ref_field["node"] == Atom.to_string(node())
      assert {:ok, entry} = EffectLedger.get(ref_field["id"])
      assert entry.effect == :approval
      assert entry.attempt.request_id == requested.request_id

      retire_session(id)
    end

    test "a denial is a terminal denied entry that says who denied it", %{id: id} do
      ref = start_bridge_session(id)

      request_approval(ref, %{"tool_name" => "Write", "input" => %{"file_path" => "lib/a.ex"}})
      requested = await_event(ref, :approval_requested)

      assert :ok =
               InteractiveSession.respond_approval(ref, requested.request_id, %{
                 decision: :deny,
                 scope: :once,
                 reason: "not in this workspace"
               })

      assert_receive {:approval_answer, {:ok, _answer}}, @receive_timeout

      assert [entry] = approvals(id)
      assert entry.status == :denied
      assert entry.result.decision == :deny
      assert entry.error.classification == :approval_denied
      # The reason a person typed is the one thing here that is prose. It stays out.
      refute inspect(entry) =~ "not in this workspace"

      retire_session(id)
    end

    test "a caller that answers without a person says so, and a rule it wrote is named",
         %{id: id} do
      ref = start_bridge_session(id)

      request_approval(ref, %{"tool_name" => "Bash", "input" => %{"command" => "ls"}})
      requested = await_event(ref, :approval_requested)

      assert :ok =
               InteractiveSession.respond_approval(ref, requested.request_id, %{
                 decision: :approve,
                 scope: :session,
                 actor: :headless,
                 rule_id: "rule-42"
               })

      assert_receive {:approval_answer, {:ok, _answer}}, @receive_timeout

      assert [entry] = approvals(id)
      assert entry.result.actor == :headless
      assert entry.result.scope == :session
      assert entry.result.rule_id == "rule-42"

      retire_session(id)
    end

    test "an answer to a request this session never asked writes nothing", %{id: id} do
      ref = start_bridge_session(id)

      assert :ok !=
               InteractiveSession.respond_approval(ref, "not-a-request", %{decision: :approve})

      assert approvals(id) == []

      retire_session(id)
    end
  end

  describe "a transport with its own approvals channel" do
    test "the answer is recorded before it is forwarded, and stamps the resolution",
         %{id: id, workspace: workspace} do
      ref = start_transport_session(id, workspace)
      adapter = start_turn(ref)

      HarnessAdapter.emit(
        adapter,
        :approval_requested,
        %{
          "kind" => "command",
          "tool_call" => %{"name" => "bash", "command" => "git push --force"},
          "paths" => []
        },
        request_id: "req-transport-1"
      )

      await_event_with(ref, :approval_requested, "req-transport-1")

      assert :ok =
               InteractiveSession.respond_approval(ref, "req-transport-1", %{
                 decision: :approve,
                 scope: :session
               })

      assert [entry] = approvals(id)
      assert entry.effect == :approval
      assert entry.attempt.request_id == "req-transport-1"
      assert entry.attempt.tool == "bash"
      assert entry.attempt.provider == @provider
      assert entry.result.origin == "provider"
      assert entry.result.scope == :session
      assert entry.result.actor == :human

      assert entry.attempt.subject.command_sha256 ==
               :sha256 |> :crypto.hash("git push --force") |> Base.encode16(case: :lower)

      refute inspect(entry) =~ "git push"

      # The provider emits its own resolution; the coordinator stamps it with the entry.
      HarnessAdapter.emit(adapter, :approval_resolved, %{"decision" => "approve"},
        request_id: "req-transport-1"
      )

      resolved = await_event_with(ref, :approval_resolved, "req-transport-1")
      assert resolved.payload["ledger_ref"]["id"] == entry.id
      assert resolved.payload["ledger_ref"]["node"] == Atom.to_string(node())

      HarnessAdapter.finish(adapter)
      retire_session(id)
    end
  end

  describe "the native agent" do
    test "a human answer and the tool it admitted are both in the ledger",
         %{id: id, workspace: workspace} do
      command = "echo hello-#{System.unique_integer([:positive, :monotonic])}"
      digest = :sha256 |> :crypto.hash(command) |> Base.encode16(case: :lower)

      {model_spec, _agent} =
        NativeModelScript.start([
          [{:tool_call, %{id: "c1", name: "bash", input: %{"command" => command}}}],
          [{:text, "done"}, {:finish, :stop}]
        ])

      assert {:ok, ref} =
               InteractiveSession.start(
                 id: id,
                 provider: :native,
                 workspace: workspace,
                 model: model_spec,
                 approval_mode: :prompt
               )

      on_exit(fn -> InteractiveSession.close(ref) end)

      assert {:ok, _turn} = InteractiveSession.send_message(ref, "run it", id: "turn-1")

      requested = await_event(ref, :approval_requested)
      assert requested.payload["tool_call"]["name"] == "bash"

      assert :ok =
               InteractiveSession.respond_approval(ref, requested.request_id, %{
                 decision: :approve,
                 scope: :once
               })

      assert [approval] = approvals(id)
      assert approval.attempt.request_id == requested.request_id
      assert approval.attempt.provider == :native
      assert approval.result.decision == :allow
      assert approval.result.actor == :human
      assert approval.result.origin == "provider"

      assert approval.attempt.subject.command_sha256 == digest

      # And the call the answer admitted is recorded on its own, settled by the loop. Its
      # principal is the Harness session id — the same one `:permission` entries use, and
      # not the Ouroboros session id above — so it is found by its subject.
      tool_call =
        assert_eventually(fn ->
          {:ok, entries} = EffectLedger.list(effect: :tool_call, limit: 500)

          Enum.find(entries, fn entry ->
            get_in(entry.attempt, [:subject, :command_sha256]) == digest and
              entry.status == :ok
          end)
        end)

      assert tool_call.attempt.tool == "bash"
      assert tool_call.result.status == :completed
      assert tool_call.authority.reason == "human"
      assert tool_call.authority.constraints.actor == :human

      retire_session(id)
    end
  end

  # ------------------------------------------------------------------ helpers

  defp approvals(id), do: ledger(id, :approval)

  defp ledger(id, effect) do
    {:ok, entries} = EffectLedger.list(principal: "session:" <> id, effect: effect, limit: 100)
    Enum.sort_by(entries, & &1.started_sequence)
  end

  defp start_bridge_session(id) do
    assert {:ok, ref} =
             InteractiveSession.start(
               id: id,
               provider: @provider,
               workspace: File.cwd!(),
               approval_mode: :prompt
             )

    ref
  end

  defp start_transport_session(id, workspace) do
    assert {:ok, ref} =
             InteractiveSession.start(
               id: id,
               provider: @provider,
               workspace: workspace,
               approval_mode: :prompt
             )

    ref
  end

  defp start_turn(ref) do
    assert {:ok, _turn} = InteractiveSession.send_message(ref, "do it", id: "turn-1")
    assert_receive {:ouroboros_test_adapter_started, _run_id, _request, adapter}, @receive_timeout
    adapter
  end

  defp request_approval(ref, request) do
    test_pid = self()

    spawn(fn ->
      answer =
        InteractiveSession.request_approval(ref, %{
          tool_name: request["tool_name"],
          input: request["input"],
          tool_use_id: request["tool_use_id"],
          cwd: request["cwd"]
        })

      send(test_pid, {:approval_answer, answer})
    end)
  end

  defp replay(ref) do
    case InteractiveSession.replay(ref, cursor: 0, limit: 500) do
      {:ok, events} -> events
      _unavailable -> []
    end
  end

  defp await_event(ref, type) do
    assert_eventually(fn -> ref |> replay() |> Enum.filter(&(&1.type == type)) |> List.last() end)
  end

  defp await_event_with(ref, type, request_id) do
    assert_eventually(fn ->
      ref
      |> replay()
      |> Enum.find(&(&1.type == type and &1.request_id == request_id))
    end)
  end

  defp assert_eventually(fun, attempts \\ 600)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true within 6s")

  defp assert_eventually(fun, attempts) do
    case fun.() do
      value when value in [false, nil] ->
        Process.sleep(10)
        assert_eventually(fun, attempts - 1)

      value ->
        value
    end
  end

  defp retire_session(id) do
    case Task.whereis(id) do
      pid when is_pid(pid) ->
        DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)

      _absent ->
        :ok
    end

    case Store.get(id) do
      {:ok, %State{} = session} ->
        _ = Store.put(%{session | status: :cancelled})
        _ = Store.delete(id)

      _absent ->
        :ok
    end
  end

  defp cleanup_sessions do
    Session.list()
    |> Enum.each(fn info ->
      unless SessionInfo.terminal?(info), do: Session.kill(info.session_id)
      _ = Session.prune(info.session_id)
    end)
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end

  defp unique_journal_dir do
    Path.join(
      System.tmp_dir!(),
      "ouroboros-approval-ledger-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_harness_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_harness_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
