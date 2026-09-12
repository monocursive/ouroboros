defmodule Ouroboros.Maintenance.BarrierTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Interactive.{State, Store}
  alias Ouroboros.Maintenance.{Barrier, Epoch, Inventory}
  alias Ouroboros.Workspace.Manager

  defp empty_native(generation, _opts),
    do: {:ok, %{generation: generation, rows: [], root_digest: digest([])}}

  setup do
    root =
      Path.join(System.tmp_dir!(), "maintenance-barrier-#{System.unique_integer([:positive])}")

    File.mkdir_p!(root)

    epoch = start_supervised!({Epoch, name: nil, data_dir: root})
    workspace = start_supervised!({Manager, name: nil, allowed_roots: [File.cwd!()]})

    store =
      start_supervised!(
        {Store,
         name: nil,
         storage:
           {Ouroboros.Storage.ETS,
            table:
              String.to_atom("maintenance_barrier_store_#{System.unique_integer([:positive])}")}}
      )

    ledger =
      start_supervised!(
        {EffectLedger,
         name: nil,
         storage:
           {Ouroboros.Storage.ETS,
            table:
              String.to_atom("maintenance_barrier_effects_#{System.unique_integer([:positive])}")}}
      )

    ids =
      for kind <- ["closed", "active"],
          do: "barrier-#{kind}-#{System.unique_integer([:positive])}"

    on_exit(fn ->
      File.rm_rf(root)
    end)

    %{ids: ids, epoch: epoch, workspace: workspace, ledger: ledger, store: store}
  end

  test "freezes authoritative terminal Store state and serves its bound page", %{
    ids: [id | _],
    epoch: epoch,
    workspace: workspace,
    ledger: ledger,
    store: store
  } do
    {:ok, state} = State.new(id, workspace: File.cwd!())
    assert :ok = Store.create(%{state | status: :closed}, store)

    assert {:ok, barrier} =
             Barrier.freeze(7,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: &empty_native/2
             )

    assert barrier.write_epoch == 0
    snapshot = barrier.snapshot
    assert {:ok, page} = Inventory.page(snapshot, snapshot.token, nil, 100, 7)
    assert page.complete
    assert Enum.any?(page.items, &(&1.session_id == id))
  end

  test "refuses nonterminal Store state and pending durable writes", %{
    ids: [_, id],
    epoch: epoch,
    workspace: workspace,
    ledger: ledger,
    store: store
  } do
    {:ok, state} = State.new(id, workspace: File.cwd!())
    assert :ok = Store.create(state, store)

    assert {:error, {:nonterminal_session, ^id}} =
             Barrier.freeze(1,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: &empty_native/2
             )

    assert :ok = Store.put(%{state | status: :cancelled}, store)

    digest = :crypto.hash(:sha256, "payload") |> Base.encode16(case: :lower)
    assert {:ok, _reservation} = Epoch.reserve("pending", digest, epoch)

    assert {:error, :pending_epoch_write} =
             Barrier.freeze(1,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: &empty_native/2
             )
  end

  test "refuses an unsettled effect participant", %{
    epoch: epoch,
    workspace: workspace,
    ledger: ledger,
    store: store
  } do
    attrs = %{
      id: "barrier-effect",
      principal: "actor",
      effect: :tool_call,
      attempt: %{tool: "read"},
      cause: %{signal_id: "signal", signal_type: "tool.call"},
      authority: %{decision: :granted}
    }

    assert {:ok, effect, :created} = EffectLedger.record_started(attrs, ledger)

    assert {:error, {:unsettled_effect, "barrier-effect", :started}} =
             Barrier.freeze(1,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: &empty_native/2
             )

    assert effect.status == :started
  end

  test "refuses Native activity and participants absent from Store", %{
    epoch: epoch,
    workspace: workspace,
    ledger: ledger,
    store: store
  } do
    active = fn generation, _opts ->
      {:ok,
       %{
         generation: generation,
         root_digest: digest(:active),
         rows: [
           %{
             logical_id: "native-live",
             active_count: 1,
             queued_count: 2,
             unresolved_count: 1
           }
         ]
       }}
    end

    assert {:error, {:native_activity, "native-live", 1, 2, 1}} =
             Barrier.freeze(1,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: active
             )

    orphan = fn generation, _opts ->
      {:ok,
       %{
         generation: generation,
         root_digest: digest(:orphan),
         rows: [
           %{
             logical_id: "native-orphan",
             active_count: 0,
             queued_count: 0,
             unresolved_count: 0
           }
         ]
       }}
    end

    assert {:error, {:native_participant_without_store, "native-orphan"}} =
             Barrier.freeze(1,
               epoch: epoch,
               workspace: workspace,
               ledger: ledger,
               store: store,
               native_inventory: orphan
             )
  end

  defp digest(value),
    do:
      value
      |> :erlang.term_to_binary([:deterministic])
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
end
