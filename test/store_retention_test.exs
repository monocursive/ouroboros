defmodule Ouroboros.StoreRetentionTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Coding.Store, as: CodingStore
  alias Ouroboros.Coding.TaskState
  alias Ouroboros.Interactive.State
  alias Ouroboros.Interactive.Store, as: InteractiveStore

  @provider :ouroboros_test

  setup do
    on_exit(fn -> Application.delete_env(:ouroboros, :terminal_retention_ms) end)
    :ok
  end

  describe "coding store" do
    test "delete refuses a live task and accepts a terminal one" do
      id = unique_id("coding-delete")
      assert :ok = CodingStore.create(task(id))

      assert {:error, {:task_not_terminal, :starting}} = CodingStore.delete(id)
      assert {:ok, %TaskState{}} = CodingStore.get(id)

      assert :ok = CodingStore.put(%{task(id) | status: :completed})
      assert :ok = CodingStore.delete(id)
      assert :not_found = CodingStore.get(id)
      assert :not_found = CodingStore.delete(id)
    end

    test "prune_terminal removes only terminal entries older than the retention" do
      old_id = unique_id("coding-old")
      fresh_id = unique_id("coding-fresh")
      live_id = unique_id("coding-live")

      assert :ok =
               CodingStore.create(%{task(old_id) | status: :completed, updated_at: hours_ago(2)})

      assert :ok = CodingStore.create(%{task(fresh_id) | status: :completed})
      assert :ok = CodingStore.create(%{task(live_id) | updated_at: hours_ago(2)})

      assert {:ok, pruned} = CodingStore.prune_terminal(60_000)

      assert old_id in pruned
      refute fresh_id in pruned
      refute live_id in pruned

      assert :not_found = CodingStore.get(old_id)
      assert {:ok, %TaskState{}} = CodingStore.get(fresh_id)
      assert {:ok, %TaskState{}} = CodingStore.get(live_id)

      assert {:error, {:invalid_retention, :forever}} = CodingStore.prune_terminal(:forever)

      assert :ok = CodingStore.put(%{task(live_id) | status: :cancelled})
      assert :ok = CodingStore.delete(live_id)
      assert :ok = CodingStore.delete(fresh_id)
    end

    test "get_summary projects completion without the event list" do
      id = unique_id("coding-summary")
      events = [Ouroboros.Coding.Event.internal(id, 1, :task_lost, %{reason: "boom"})]

      assert :ok =
               CodingStore.create(%{
                 task(id)
                 | status: :failed,
                   events: events,
                   next_sequence: 2,
                   cursor: 1,
                   result: %{status: :failed},
                   error: :boom
               })

      assert {:ok, summary} = CodingStore.get_summary(id)

      assert summary == %{
               id: id,
               node: node(),
               status: :failed,
               terminal?: true,
               result: %{status: :failed},
               error: :boom,
               updated_at: summary.updated_at
             }

      refute Map.has_key?(summary, :events)
      assert :not_found = CodingStore.get_summary(unique_id("absent"))
      assert :ok = CodingStore.delete(id)
    end

    test "list_recoverable projects routing and lifecycle only" do
      id = unique_id("coding-projection")
      assert :ok = CodingStore.create(task(id))

      assert entry = Enum.find(CodingStore.list_recoverable(), &(&1.id == id))
      assert entry.node == node()
      assert entry.status == :starting
      refute entry.terminal?
      assert is_binary(entry.updated_at)
      assert Map.keys(entry) |> Enum.sort() == [:id, :node, :status, :terminal?, :updated_at]

      assert :ok = CodingStore.put(%{task(id) | status: :completed})
      assert :ok = CodingStore.delete(id)
    end
  end

  describe "interactive store" do
    setup do
      name = :"interactive_store_#{System.unique_integer([:positive, :monotonic])}"

      pid =
        start_supervised!(
          {InteractiveStore,
           name: name,
           key: {:ouroboros, :interactive_sessions_test, name},
           storage: {Jido.Storage.ETS, table: name}}
        )

      {:ok, store: pid}
    end

    test "delete refuses a live session and accepts a terminal one", %{store: store} do
      id = unique_id("interactive-delete")
      assert :ok = InteractiveStore.create(session(id), store)

      assert {:error, {:session_not_terminal, :starting}} = InteractiveStore.delete(id, store)
      assert {:ok, %State{}} = InteractiveStore.get(id, store)

      assert :ok = InteractiveStore.put(%{session(id) | status: :closed}, store)
      assert :ok = InteractiveStore.delete(id, store)
      assert :not_found = InteractiveStore.get(id, store)
      assert :not_found = InteractiveStore.delete(id, store)
    end

    test "prune_terminal removes only terminal entries older than the retention", %{store: store} do
      old_id = unique_id("interactive-old")
      fresh_id = unique_id("interactive-fresh")
      live_id = unique_id("interactive-live")

      assert :ok =
               InteractiveStore.create(
                 %{session(old_id) | status: :closed, updated_at: hours_ago(2)},
                 store
               )

      assert :ok = InteractiveStore.create(%{session(fresh_id) | status: :closed}, store)
      assert :ok = InteractiveStore.create(%{session(live_id) | updated_at: hours_ago(2)}, store)

      assert {:ok, pruned} = InteractiveStore.prune_terminal(60_000, store)
      assert Enum.sort(pruned) == [old_id]

      assert :not_found = InteractiveStore.get(old_id, store)
      assert {:ok, %State{}} = InteractiveStore.get(fresh_id, store)
      assert {:ok, %State{}} = InteractiveStore.get(live_id, store)

      assert {:error, {:invalid_retention, -1}} = InteractiveStore.prune_terminal(-1, store)
    end

    test "list_recoverable projects routing and lifecycle only", %{store: store} do
      id = unique_id("interactive-projection")
      assert :ok = InteractiveStore.create(session(id), store)

      assert [entry] = InteractiveStore.list_recoverable(store)
      assert entry.id == id
      assert entry.node == node()
      assert entry.status == :starting
      refute entry.terminal?
      assert Map.keys(entry) |> Enum.sort() == [:id, :node, :status, :terminal?, :updated_at]
    end
  end

  describe "interactive store boot" do
    @tag :capture_log
    test "a session checkpoint nobody can read is quarantined, not fatal" do
      path =
        Path.join(
          System.tmp_dir!(),
          "ouroboros-interactive-store-#{System.unique_integer([:positive, :monotonic])}"
        )

      on_exit(fn -> File.rm_rf(path) end)

      key = {:ouroboros, :interactive_sessions_test, :quarantine}
      storage = {Ouroboros.Storage.DurableFile, path: path}
      survivor = unique_id("interactive-survivor")
      corrupt = unique_id("interactive-corrupt")

      store = start_interactive_store!(:quarantine_first, key, storage)
      assert :ok = InteractiveStore.create(session(survivor), store)
      assert :ok = InteractiveStore.create(session(corrupt), store)
      stop_supervised!(:quarantine_first)

      truncate_session_checkpoint!(path, corrupt)

      # Booting is not all-or-nothing: one session nobody can read must not refuse the
      # interactive plane, and everything `rest_for_one` starts after it, to the operator.
      store = start_interactive_store!(:quarantine_second, key, storage)

      assert {:ok, %State{id: ^survivor}} = InteractiveStore.get(survivor, store)
      assert :not_found = InteractiveStore.get(corrupt, store)
      assert [%State{id: ^survivor}] = InteractiveStore.list(store)

      # The rebuilt index no longer claims the quarantined session, so the next boot
      # does not have to rediscover it.
      assert {:ok, %{version: 2, ids: [^survivor]}} =
               Ouroboros.Storage.DurableFile.get_checkpoint(key, path: path)
    end
  end

  defp start_interactive_store!(id, key, storage) do
    start_supervised!({InteractiveStore, name: nil, key: key, storage: storage}, id: id)
  end

  defp truncate_session_checkpoint!(path, id) do
    file =
      [path, "checkpoints", "*.term"]
      |> Path.join()
      |> Path.wildcard()
      |> Enum.find(fn file ->
        match?(%{^id => _session}, :erlang.binary_to_term(File.read!(file), [:safe]))
      end)

    assert is_binary(file)
    File.write!(file, "half a checkpoint")
  end

  describe "recovery retention sweep" do
    test "prunes expired terminal coding tasks on the recovery tick" do
      id = unique_id("coding-swept")
      keep_id = unique_id("coding-kept")

      assert :ok = CodingStore.create(%{task(id) | status: :completed, updated_at: hours_ago(2)})
      assert :ok = CodingStore.create(task(keep_id))

      Application.put_env(:ouroboros, :terminal_retention_ms, 60_000)

      start_supervised!(
        {Ouroboros.Coding.Recovery, name: nil, interval: 20, prune_interval: 0},
        id: :coding_retention_sweeper
      )

      assert_eventually(fn -> CodingStore.get(id) == :not_found end)
      assert {:ok, %TaskState{}} = CodingStore.get(keep_id)

      assert :ok = CodingStore.put(%{task(keep_id) | status: :cancelled})
      assert :ok = CodingStore.delete(keep_id)
    end

    test "prunes expired terminal interactive sessions on the recovery tick" do
      id = unique_id("interactive-swept")

      assert :ok =
               Ouroboros.Interactive.Store.create(%{
                 session(id)
                 | status: :closed,
                   updated_at: hours_ago(2)
               })

      Application.put_env(:ouroboros, :terminal_retention_ms, 60_000)

      start_supervised!(
        {Ouroboros.Interactive.Recovery, name: nil, interval: 20, prune_interval: 0},
        id: :interactive_retention_sweeper
      )

      assert_eventually(fn -> Ouroboros.Interactive.Store.get(id) == :not_found end)
    end

    test "a nil retention disables the sweep" do
      id = unique_id("coding-retained")

      assert :ok = CodingStore.create(%{task(id) | status: :completed, updated_at: hours_ago(2)})
      Application.put_env(:ouroboros, :terminal_retention_ms, nil)

      start_supervised!(
        {Ouroboros.Coding.Recovery, name: nil, interval: 20, prune_interval: 0},
        id: :coding_retention_disabled
      )

      Process.sleep(150)
      assert {:ok, %TaskState{status: :completed}} = CodingStore.get(id)
      assert :ok = CodingStore.delete(id)
    end
  end

  defp task(id) do
    {:ok, task} =
      TaskState.new(id, "retention fixture", provider: @provider, workspace: File.cwd!())

    task
  end

  defp session(id) do
    {:ok, session} = State.new(id, provider: @provider, workspace: File.cwd!())
    session
  end

  defp hours_ago(hours) do
    DateTime.utc_now() |> DateTime.add(-hours * 3600, :second) |> DateTime.to_iso8601()
  end

  defp assert_eventually(fun, attempts \\ 200)
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

  defp unique_id(prefix), do: "#{prefix}-#{System.unique_integer([:positive, :monotonic])}"
end
