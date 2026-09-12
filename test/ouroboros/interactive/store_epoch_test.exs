defmodule Ouroboros.Interactive.StoreEpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Storage.ETS

  defmodule FaultStorage do
    def get_checkpoint(key, opts), do: Agent.get(opts[:pid], &Map.get(&1.disk, key, :not_found))

    def put_checkpoint(key, value, opts) do
      Agent.get_and_update(opts[:pid], fn state ->
        fail? = state.fail_key == key
        result = if fail?, do: {:error, {:commit_outcome_unknown, :injected}}, else: :ok
        disk = Map.put(state.disk, key, {:ok, value})
        {result, %{state | disk: disk, writes: state.writes ++ [{key, value}], fail_key: nil}}
      end)
    end

    def delete_checkpoint(key, opts),
      do: Agent.update(opts[:pid], &%{&1 | disk: Map.delete(&1.disk, key)})
  end

  setup do
    root = Path.join(System.tmp_dir!(), "store-epoch-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    epoch = start_supervised!({Epoch, name: nil, data_dir: root})
    table = String.to_atom("store_epoch_#{System.unique_integer([:positive])}")

    store =
      start_supervised!({Store, name: nil, storage: {ETS, table: table}, epoch_server: epoch})

    on_exit(fn -> File.rm_rf(root) end)
    %{epoch: epoch, store: store}
  end

  test "create and put reserve and commit exact durable payload identities", ctx do
    {:ok, state} = State.new("epoch-session", workspace: File.cwd!())
    assert :ok = Store.create(state, ctx.store)
    assert :ok = Store.put(%{state | status: :closed}, ctx.store)

    observation = Epoch.observe(ctx.epoch)
    assert observation.pending == []
    assert length(observation.committed) == 2

    assert Enum.all?(
             observation.committed,
             &String.starts_with?(&1.write_id, "interactive-store/v1/")
           )

    assert Enum.all?(observation.committed, &(byte_size(&1.payload_digest) == 64))
  end

  test "create retry is side-effect free even when caller bytes differ", ctx do
    {:ok, state} = State.new("epoch-retry", workspace: File.cwd!())
    assert :ok = Store.create(state, ctx.store)
    assert {:error, :already_exists} = Store.create(state, ctx.store)
    assert length(Epoch.observe(ctx.epoch).committed) == 1

    changed = %{state | status: :closed}
    assert {:error, :already_exists} = Store.create(changed, ctx.store)
    assert length(Epoch.observe(ctx.epoch).committed) == 1
    assert {:ok, ^state} = Store.get(state.id, ctx.store)
  end

  test "delete has stable exact identity and absent retry adds no epoch", ctx do
    {:ok, state} = State.new("epoch-delete", workspace: File.cwd!())
    assert :ok = Store.create(%{state | status: :closed}, ctx.store)
    assert :ok = Store.delete(state.id, ctx.store)
    committed = Epoch.observe(ctx.epoch).committed
    assert length(committed) == 2
    assert Enum.any?(committed, &String.contains?(&1.write_id, "/delete/"))
    assert :not_found = Store.delete(state.id, ctx.store)
    assert Epoch.observe(ctx.epoch).committed == committed
  end

  test "prune covers the complete deterministic record-set mutation once", ctx do
    old = DateTime.add(DateTime.utc_now(), -10, :second)

    for id <- ["epoch-prune-a", "epoch-prune-b"] do
      {:ok, state} = State.new(id, workspace: File.cwd!())

      assert :ok =
               Store.create(
                 %{state | status: :closed, updated_at: DateTime.to_iso8601(old)},
                 ctx.store
               )
    end

    assert {:ok, ids} = Store.prune_terminal(1_000, ctx.store)
    assert Enum.sort(ids) == ["epoch-prune-a", "epoch-prune-b"]
    committed = Epoch.observe(ctx.epoch).committed
    assert length(committed) == 3
    assert Enum.count(committed, &String.contains?(&1.write_id, "/prune/")) == 1
    assert {:ok, []} = Store.prune_terminal(1_000, ctx.store)
    assert Epoch.observe(ctx.epoch).committed == committed
  end

  @tag capture_log: true
  test "multi-record prune ambiguity reconciles exact published membership after restart", ctx do
    storage = start_supervised!({Agent, fn -> %{disk: %{}, writes: [], fail_key: nil} end})
    key = {:fault_store, System.unique_integer([:positive])}

    {:ok, store} =
      Store.start_link(
        name: nil,
        storage: {FaultStorage, pid: storage},
        key: key,
        epoch_server: ctx.epoch
      )

    Process.unlink(store)
    old = DateTime.utc_now() |> DateTime.add(-10, :second) |> DateTime.to_iso8601()

    for id <- ["fault-prune-a", "fault-prune-b"] do
      {:ok, state} = State.new(id, workspace: File.cwd!())
      assert :ok = Store.create(%{state | status: :closed, updated_at: old}, store)
    end

    Agent.update(storage, &%{&1 | fail_key: key})
    monitor = Process.monitor(store)
    assert {:error, {:commit_outcome_unknown, :injected}} = Store.prune_terminal(1_000, store)
    assert_receive {:DOWN, ^monitor, :process, ^store, _reason}
    assert [_pending] = Epoch.observe(ctx.epoch).pending

    writes_before = Agent.get(storage, &length(&1.writes))

    {:ok, recovered} =
      Store.start_link(
        name: nil,
        storage: {FaultStorage, pid: storage},
        key: key,
        epoch_server: ctx.epoch
      )

    Process.unlink(recovered)
    assert Store.list(recovered) == []
    assert Epoch.observe(ctx.epoch).pending == []
    assert Agent.get(storage, &length(&1.writes)) == writes_before
    GenServer.stop(recovered)
  end
end
