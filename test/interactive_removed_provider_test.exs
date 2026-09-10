defmodule Ouroboros.InteractiveRemovedProviderTest do
  @moduledoc """
  A session record naming a provider this build no longer serves is **history this build
  can show and cannot run**. It loads and lists with its whole transcript; it reserves no
  workspace; it never enters the poll path, so no verb can fail it through a scheduled poll;
  every mutating verb is refused by name without a checkpoint; and `close`/`kill` end it at
  the terminal `:closed` state — not `:failed` — after which `delete` works by the
  operator's explicit choice.

  These are the C2 review's F1/F2/F3 against a seeded record. The verb-by-verb drive against
  a fresh copy of the integration fixture — one boot per verb, and the 60-second no-loop
  watch on `Interactive.Recovery` — is `report-c2-fix.md`'s fixture evidence; this file is
  the regression guard that keeps the seams honest.
  """

  use ExUnit.Case, async: false

  @moduletag :capture_log

  alias Ouroboros.Gateway.Methods
  alias Ouroboros.Interactive.{Ref, State, Store}
  alias Ouroboros.Interactive.Task, as: InteractiveTask
  alias Ouroboros.InteractiveSession
  alias Ouroboros.Workspace

  @removed :claude

  setup do
    on_exit(&cleanup_seeded/0)
    :ok
  end

  describe "the record itself" do
    test "loads and lists through Interactive.Store, and answers read verbs from history" do
      id = seed_removed_provider()
      ref = Ref.new(id)

      assert Enum.any?(Store.list(), &(&1.id == id and &1.provider == @removed))

      # `info` answers from the held record, without a provider.
      assert {:ok, public} = InteractiveSession.info(ref)
      assert public.status == :idle

      # A read verb that needs a live transport says so as structured data rather than
      # crashing: there is no transport, and the record cannot open one.
      assert {:error, {:native_transport_unavailable, %{verb: :journal}}} =
               InteractiveSession.journal(ref)
    end
  end

  describe "every mutating verb is refused by name, with no checkpoint" do
    setup do
      id = seed_removed_provider()
      {:ok, id: id, ref: Ref.new(id)}
    end

    test "steer / interrupt / rename / configure / compact / handoff / fork / turns", %{
      id: id,
      ref: ref
    } do
      before = fetch!(id)

      refusals = [
        InteractiveSession.steer(ref, "go"),
        InteractiveSession.interrupt(ref),
        InteractiveSession.rename(ref, "a new title"),
        InteractiveSession.configure(ref, approval_mode: :auto_approve),
        InteractiveSession.compact(ref),
        InteractiveSession.handoff(ref, "carry on"),
        InteractiveSession.fork(ref),
        InteractiveSession.send_message(ref, "hello"),
        InteractiveSession.follow_up(ref, "and then"),
        InteractiveSession.retry_turn(ref, "some-turn")
      ]

      for reply <- refusals do
        assert {:error, {:provider_removed, @removed, message}} = reply
        assert message =~ "`:native` is the only provider"
      end

      # Not a byte of the record changed, and it is still exactly :idle — no verb failed it
      # and none rewrote its title through a refused checkpoint.
      after_drive = fetch!(id)
      assert after_drive.status == :idle
      assert after_drive == before
    end
  end

  describe "close and kill end it at :closed, and only then does delete work" do
    test "close transitions to :closed (not :failed) and delete removes it" do
      id = seed_removed_provider()
      ref = Ref.new(id)

      # Delete is refused while the record is non-terminal, exactly as for any session.
      assert {:error, {:session_not_terminal, :idle}} = InteractiveSession.delete(ref)

      assert :ok = InteractiveSession.close(ref)

      closed = fetch!(id)
      assert closed.status == :closed
      assert closed.error == nil
      refute State.terminal?(%{closed | status: :idle})
      assert State.terminal?(closed)

      assert :ok = InteractiveSession.delete(ref)
      assert Store.get(id) == :not_found
    end

    test "kill ends the same record the same way" do
      id = seed_removed_provider()
      ref = Ref.new(id)

      assert :ok = InteractiveSession.kill(ref)
      assert %State{status: :closed, error: nil} = fetch!(id)
      assert :ok = InteractiveSession.delete(ref)
    end
  end

  describe "it reserves no workspace (F2)" do
    test "the recovery manager mints no reservation for it, and its root stays acquirable" do
      root = tmp_root("reservation")
      workspace = Path.join(root, "claude")
      id = seed_removed_provider(workspace: workspace, isolate: true)

      manager_name = :"removed_provider_manager_#{System.unique_integer([:positive])}"

      start_supervised!(
        {Workspace,
         allowed_roots: [root], name: manager_name, recover_reservations: true, id: manager_name}
      )

      # No claim of any kind names the removed-provider session, and the summary agrees.
      claims = Workspace.list(server: manager_name)
      refute Enum.any?(claims, &(&1.task_id == "interactive:" <> id))
      assert Workspace.summary(server: manager_name).recovery_reservation_count == 0

      # A brand-new session can take the workspace the legacy record named, because nothing
      # is holding it.
      assert {:ok, _lease, _capability} =
               Workspace.acquire_managed(workspace, "interactive:brand-new-session", :interactive,
                 mode: :exclusive,
                 server: manager_name
               )
    end
  end

  describe "Interactive.Recovery skips it (F3)" do
    test "the recovery projection marks it non-recoverable, so no coordinator is forced" do
      id = seed_removed_provider()

      projection = Enum.find(Store.list_recoverable(), &(&1.id == id))
      assert projection.removed_provider? == true

      # And a coordinator started on demand holds it rather than retiring: it is the
      # read-only holder, alive until close, not a process that fires a dead retire timer.
      assert {:ok, _} = InteractiveSession.info(Ref.new(id))
      coordinator = InteractiveTask.whereis(id)
      assert is_pid(coordinator)
      Process.sleep(250)
      assert InteractiveTask.whereis(id) == coordinator
      assert fetch!(id).status == :idle
    end
  end

  describe "the four refusal lanes, on the wire (F8)" do
    setup do
      id = seed_removed_provider()
      {:ok, id: id}
    end

    test "journal and rewind refuse as well-formed native_transport_unavailable", %{id: id} do
      assert {:error, -32_006, _message, ["native_transport_unavailable", journal]} =
               Methods.invoke("interactive.journal", %{"id" => id})

      assert journal["verb"] == "journal"

      assert {:error, -32_006, _message, ["native_transport_unavailable", rewind]} =
               Methods.invoke("interactive.rewind", %{"id" => id, "to_turn" => 0})

      assert rewind["verb"] == "rewind"
    end

    test "handoff refuses as well-formed provider_removed wire data", %{id: id} do
      assert {:error, -32_006, _message, ["provider_removed", "claude", detail]} =
               Methods.invoke("interactive.handoff", %{"id" => id, "prompt" => "carry on"})

      assert detail =~ "`:native` is the only provider"
    end

    test "replay_verify refuses as well-formed wire data rather than crashing", %{id: id} do
      assert {:error, code, _message, _data} =
               Methods.invoke("interactive.replay_verify", %{"id" => id})

      assert is_integer(code)
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────────────────

  # Ids seeded this test, so cleanup can find them without walking the whole store.
  defp seeded_ids, do: Process.get(:seeded_ids, [])

  defp seed_removed_provider(opts \\ []) do
    id = "removed-provider-#{System.unique_integer([:positive, :monotonic])}"
    workspace = Keyword.get_lazy(opts, :workspace, fn -> Path.join(tmp_root("ws"), "claude") end)
    record = removed_provider_record(id, workspace)

    if Keyword.get(opts, :isolate, false) do
      # The reservation manager reads the whole store at init and fails closed on a claim
      # whose root is outside its allowed roots, so this record must be the only one it sees.
      original = :sys.get_state(Store).sessions
      Process.put(:store_sessions_snapshot, original)
      :sys.replace_state(Store, fn state -> %{state | sessions: %{id => record}} end)
    else
      :sys.replace_state(Store, fn state ->
        %{state | sessions: Map.put(state.sessions, id, record)}
      end)
    end

    Process.put(:seeded_ids, [id | seeded_ids()])
    id
  end

  defp removed_provider_record(id, workspace) do
    File.mkdir_p!(workspace)
    {:ok, base} = State.new(id, provider: :native, workspace: workspace)

    record =
      base
      |> Map.put(:provider, @removed)
      |> Map.put(:node, node())
      |> Map.put(:status, :idle)
      |> Map.put(:error, nil)
      |> Map.put(:prompt_trace, nil)
      |> Map.put(:runtime_snapshot, nil)
      |> Map.put(:events, [])
      |> Map.put(:turns, %{})
      |> Map.put(:options, %{})

    true = State.loadable?(record)
    false = State.requestable?(record)
    record
  end

  defp fetch!(id) do
    assert {:ok, record} = Store.get(id)
    record
  end

  defp tmp_root(tag) do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-removed-provider-#{tag}-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)
    root
  end

  defp cleanup_seeded do
    for id <- seeded_ids() do
      if pid = InteractiveTask.whereis(id) do
        _ = DynamicSupervisor.terminate_child(Ouroboros.Interactive.TaskSupervisor, pid)
      end
    end

    case Process.get(:store_sessions_snapshot) do
      nil ->
        :sys.replace_state(Store, fn state ->
          %{state | sessions: Map.drop(state.sessions, seeded_ids())}
        end)

      snapshot ->
        :sys.replace_state(Store, fn state -> %{state | sessions: snapshot} end)
    end
  rescue
    _error -> :ok
  catch
    :exit, _reason -> :ok
  end
end
