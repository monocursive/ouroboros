defmodule Ouroboros.Test.AllowEverythingPermissions do
  @moduledoc """
  A C1 stand-in that allows, so a test can prove the engine is consulted before a human.

  `Ouroboros.Control.Permissions` lands in its own slice. What this module pins is the
  contract the coordinator calls through — `evaluate/1` answering `{:allow, rule}`,
  `{:deny, rule}`, or `{:ask, reason}`, with `record/2` taking the verdict — and the fact
  that an `:allow` never reaches a person.
  """

  def evaluate(%{tool_name: "Read"}), do: {:allow, "Read(**)"}
  def evaluate(%{tool_name: "Bash", input: %{"command" => "rm -rf /"}}), do: {:deny, "Bash(rm *)"}
  def evaluate(_subject), do: {:ask, :no_rule}

  def record(subject, verdict) do
    case Process.whereis(:external_approval_engine_probe) do
      pid when is_pid(pid) -> send(pid, {:permission_recorded, subject, verdict})
      nil -> :ok
    end

    :ok
  end

  def suggest(%{tool_name: name}, _verdict) when is_binary(name), do: "#{name}(*)"
  def suggest(_subject, _verdict), do: nil
end

defmodule Ouroboros.InteractiveExternalApprovalTest do
  @moduledoc """
  C2's runtime half: a tool call a managed transport cannot ask about, asked anyway.

  `interactive.request_approval` is how `ouro mcp-serve` — the stdio MCP server Claude
  Code is handed as its `--permission-prompt-tool` — reaches the session coordinator. The
  invariants these tests pin are the ones a permission prompt is worth nothing without:
  the question is durable before the caller waits on it, the answer is a human's or the
  engine's, and *every* other outcome is a denial that says which one it was.
  """

  use ExUnit.Case, async: false

  alias Jido.Harness.{Session, SessionInfo}
  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{State, Store, Task}
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Test.AllowEverythingPermissions
  alias Ouroboros.Test.HarnessAdapter

  @provider :ouroboros_test
  @receive_timeout 5_000

  setup do
    cleanup_sessions()

    previous_providers = Application.get_env(:jido_harness, :providers)
    previous_provider_config = Application.get_env(:jido_harness, :provider_config)
    previous_engine = Application.get_env(:ouroboros, :permissions_engine)
    journal_dir = unique_journal_dir()

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

    # Absent unless a test says otherwise: with no engine on the node every request is
    # `:ask`, which is the posture this runtime ships in until C1 lands.
    Application.delete_env(:ouroboros, :permissions_engine)

    on_exit(fn ->
      cleanup_sessions()
      restore_harness_env(:providers, previous_providers)
      restore_harness_env(:provider_config, previous_provider_config)

      case previous_engine do
        nil -> Application.delete_env(:ouroboros, :permissions_engine)
        engine -> Application.put_env(:ouroboros, :permissions_engine, engine)
      end

      File.rm_rf(journal_dir)
    end)

    {:ok, id: unique_id("external-approval")}
  end

  test "an approved request becomes a durable question, then an allow", %{id: id} do
    ref = start_session(id)

    caller = request_approval(ref, %{"tool_name" => "Write", "input" => %{"file_path" => "a.ex"}})

    requested = await_event(ref, :approval_requested)

    assert requested.payload["kind"] == "permissions"
    assert requested.payload["origin"] == "external"
    assert requested.payload["request_id"] == requested.request_id
    assert requested.payload["tool_call"]["name"] == "Write"
    assert requested.payload["tool_call"]["input"] == %{"file_path" => "a.ex"}
    assert is_binary(requested.request_id)

    # No engine is loaded, so nothing has been decided: the request is open and the
    # caller is still waiting on a person.
    refute_receive {:approval_answer, _answer}, 100

    assert :ok =
             InteractiveSession.respond_approval(ref, requested.request_id, %{
               decision: :approve,
               scope: :once
             })

    assert_receive {:approval_answer, {:ok, answer}}, @receive_timeout
    assert answer.decision == :allow
    assert answer.source == :human
    assert answer.request_id == requested.request_id
    refute Process.alive?(caller)

    resolved = await_event(ref, :approval_resolved)
    assert resolved.request_id == requested.request_id
    assert resolved.payload["decision"] == "approve"
    assert resolved.payload["source"] == "human"
    assert resolved.payload["origin"] == "external"

    # The runtime's own rows keep the session's numbering strictly increasing and do not
    # consume a Harness sequence, so the provider's next event still arrives.
    events = replay(ref)
    sequences = Enum.map(events, & &1.sequence)
    assert sequences == Enum.sort(sequences)
    assert sequences == Enum.uniq(sequences)

    retire_session(id)
  end

  test "a denial carries the reason the person gave", %{id: id} do
    ref = start_session(id)

    request_approval(ref, %{"tool_name" => "Bash", "input" => %{"command" => "rm -rf ."}})
    requested = await_event(ref, :approval_requested)

    assert :ok =
             InteractiveSession.respond_approval(ref, requested.request_id, %{
               decision: :deny,
               scope: :once,
               reason: "not in this workspace"
             })

    assert_receive {:approval_answer, {:ok, answer}}, @receive_timeout
    assert answer.decision == :deny
    assert answer.reason == "not in this workspace"

    resolved = await_event(ref, :approval_resolved)
    assert resolved.payload["decision"] == "deny"
    assert resolved.payload["reason"] == "not in this workspace"

    retire_session(id)
  end

  test "a question nobody answers is denied at the session's own deadline", %{id: id} do
    ref = start_session(id, approval_timeout_ms: 1_000)

    request_approval(ref, %{"tool_name" => "Bash", "input" => %{"command" => "sleep 1"}})
    requested = await_event(ref, :approval_requested)

    assert_receive {:approval_answer, {:ok, answer}}, @receive_timeout
    assert answer.decision == :deny
    assert answer.source == :timeout
    assert answer.reason =~ "1000ms"

    resolved = await_event(ref, :approval_resolved)
    assert resolved.request_id == requested.request_id
    assert resolved.payload["source"] == "timeout"

    retire_session(id)
  end

  test "the ninth outstanding question is denied rather than queued", %{id: id} do
    ref = start_session(id, approval_timeout_ms: 60_000)

    for index <- 1..8 do
      request_approval(ref, %{"tool_name" => "Write", "input" => %{"n" => index}})
    end

    await_events(ref, :approval_requested, 8)

    assert {:ok, answer} =
             InteractiveSession.request_approval(ref, %{
               tool_name: "Write",
               input: %{"n" => 9},
               tool_use_id: nil,
               cwd: nil
             })

    assert answer.decision == :deny
    assert answer.source == :capacity
    assert answer.reason =~ "8 unanswered approval requests"

    # And the bound is a bound, not a ceiling that leaks: nothing was recorded for the
    # request that was turned away.
    assert length(events_of(ref, :approval_requested)) == 8

    retire_session(id)
  end

  test "a coordinator restart denies what it can no longer answer", %{id: id} do
    ref = start_session(id, approval_timeout_ms: 600_000)

    request_approval(ref, %{"tool_name" => "Write", "input" => %{"file_path" => "b.ex"}})
    requested = await_event(ref, :approval_requested)

    pid = Task.whereis(id)
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, @receive_timeout

    # The caller's call died with the coordinator; what matters is that the journal does
    # not go on claiming an open question after the revival.
    assert_receive {:approval_answer, {:error, _reason}}, @receive_timeout

    resolved =
      assert_eventually(fn ->
        Enum.find(
          events_of(ref, :approval_resolved),
          &(&1.request_id == requested.request_id)
        )
      end)

    assert resolved.payload["decision"] == "deny"
    assert resolved.payload["source"] == "coordinator_restart"

    retire_session(id)
  end

  test "the permission engine answers before any human does", %{id: id} do
    Process.register(self(), :external_approval_engine_probe)
    Application.put_env(:ouroboros, :permissions_engine, AllowEverythingPermissions)
    ref = start_session(id)

    assert {:ok, allowed} =
             InteractiveSession.request_approval(ref, %{
               tool_name: "Read",
               input: %{"file_path" => "mix.exs"},
               tool_use_id: "toolu_1",
               cwd: File.cwd!()
             })

    assert allowed.decision == :allow
    assert allowed.source == :engine
    assert allowed.reason == "Read(**)"
    assert_receive {:permission_recorded, %{tool_name: "Read"}, %{decision: :allow}}, 500

    assert {:ok, denied} =
             InteractiveSession.request_approval(ref, %{
               tool_name: "Bash",
               input: %{"command" => "rm -rf /"},
               tool_use_id: "toolu_2",
               cwd: File.cwd!()
             })

    assert denied.decision == :deny
    assert denied.source == :engine
    assert denied.reason == "Bash(rm *)"

    # Both were recorded in the journal as asked and answered, without a modal ever
    # opening, and the engine's "don't ask again" line rides the request.
    [read_request, bash_request] = events_of(ref, :approval_requested)
    assert read_request.payload["suggested_rule"] == "Read(*)"
    assert read_request.payload["tool_use_id"] == "toolu_1"
    assert bash_request.payload["suggested_rule"] == "Bash(*)"

    assert [read_resolved, bash_resolved] = events_of(ref, :approval_resolved)
    assert read_resolved.payload["decision"] == "approve"
    assert read_resolved.payload["source"] == "engine"
    assert bash_resolved.payload["decision"] == "deny"

    Process.unregister(:external_approval_engine_probe)
    retire_session(id)
  end

  describe "the gateway verb" do
    test "carries the round trip end to end", %{id: id} do
      ref = start_session(id)
      test_pid = self()

      spawn(fn ->
        send(
          test_pid,
          {:invoked,
           Methods.invoke("interactive.request_approval", %{
             "id" => id,
             "request" => %{
               "tool_name" => "Edit",
               "input" => %{"file_path" => "lib/a.ex"},
               "tool_use_id" => "toolu_gateway",
               "cwd" => File.cwd!()
             }
           })}
        )
      end)

      requested = await_event(ref, :approval_requested)
      assert requested.payload["tool_use_id"] == "toolu_gateway"
      assert requested.payload["tool_call"]["cwd"] == File.cwd!()

      assert {:ok, _acknowledged} =
               Methods.invoke("interactive.respond_approval", %{
                 "id" => id,
                 "request_id" => requested.request_id,
                 "response" => "approve"
               })

      assert_receive {:invoked, {:ok, answer}}, @receive_timeout

      assert answer == %{
               "decision" => "allow",
               "request_id" => requested.request_id,
               "source" => "human",
               "reason" => nil
             }

      retire_session(id)
    end

    test "refuses a request that is not one", %{id: id} do
      ref = start_session(id)

      assert {:error, -32_602, message} =
               Methods.invoke("interactive.request_approval", %{"id" => id, "request" => %{}})

      assert message =~ "params.request"

      assert {:error, -32_602, _unknown_field} =
               Methods.invoke("interactive.request_approval", %{
                 "id" => id,
                 "request" => %{"tool_name" => "Read", "provider_options" => %{"x" => 1}}
               })

      assert {:error, -32_602, _bad_input} =
               Methods.invoke("interactive.request_approval", %{
                 "id" => id,
                 "request" => %{"tool_name" => "Read", "input" => "not an object"}
               })

      _unused = ref
      retire_session(id)
    end

    test "is an operate verb with a fifteen-minute ceiling" do
      assert %{scope: :operate, timeout: 900_000} =
               Map.fetch!(Methods.table(), "interactive.request_approval")

      assert "interactive.request_approval" in Methods.names()
    end
  end

  defp start_session(id, opts \\ []) do
    assert {:ok, ref} =
             InteractiveSession.start(
               [
                 id: id,
                 provider: @provider,
                 workspace: File.cwd!(),
                 approval_mode: :prompt
               ] ++ opts
             )

    ref
  end

  # The caller side of the bridge: a process that blocks in `request_approval/2` exactly
  # as `ouro mcp-serve`'s gateway call does, and reports whatever it is finally told.
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

  defp events_of(ref, type), do: ref |> replay() |> Enum.filter(&(&1.type == type))

  defp await_event(ref, type) do
    assert_eventually(fn -> ref |> events_of(type) |> List.last() end)
  end

  defp await_events(ref, type, count) do
    assert_eventually(fn ->
      events = events_of(ref, type)
      if length(events) >= count, do: events
    end)
  end

  defp assert_eventually(fun, attempts \\ 400)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

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
      "ouroboros-external-approval-journal-#{System.unique_integer([:positive, :monotonic])}"
    )
  end

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"

  defp map_or_empty(nil), do: %{}
  defp map_or_empty(value), do: Map.new(value)

  defp restore_harness_env(key, nil), do: Application.delete_env(:jido_harness, key)
  defp restore_harness_env(key, value), do: Application.put_env(:jido_harness, key, value)
end
