defmodule Ouroboros.StoreRetentionTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Interactive.State
  alias Ouroboros.Interactive.Store, as: InteractiveStore

  @provider :native

  setup do
    on_exit(fn -> Application.delete_env(:ouroboros, :terminal_retention_ms) end)
    :ok
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
      # A native record is recoverable; `removed_provider?` is the lifecycle fact that
      # keeps `Session.Recovery` from restarting a record naming a provider this build lost.
      refute entry.removed_provider?

      assert Map.keys(entry) |> Enum.sort() ==
               [:id, :node, :removed_provider?, :status, :terminal?, :updated_at]
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
      id = unique_id("interactive-retained")

      assert :ok =
               Ouroboros.Interactive.Store.create(%{
                 session(id)
                 | status: :closed,
                   updated_at: hours_ago(2)
               })

      Application.put_env(:ouroboros, :terminal_retention_ms, nil)

      start_supervised!(
        {Ouroboros.Interactive.Recovery, name: nil, interval: 20, prune_interval: 0},
        id: :interactive_retention_disabled
      )

      Process.sleep(150)
      assert {:ok, %State{status: :closed}} = Ouroboros.Interactive.Store.get(id)
      assert :ok = Ouroboros.Interactive.Store.delete(id)
    end
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
