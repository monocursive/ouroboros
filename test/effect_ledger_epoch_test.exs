defmodule Ouroboros.Agent.EffectLedgerEpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Storage.DurableFile

  setup do
    root = Path.join(System.tmp_dir!(), "ledger-epoch-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    epoch = start_supervised!({Epoch, name: nil, data_dir: root})
    storage = {DurableFile, path: Path.join(root, "ledger")}
    ledger = start_supervised!({EffectLedger, name: nil, storage: storage, epoch_server: epoch})
    on_exit(fn -> File.rm_rf(root) end)
    %{epoch: epoch, ledger: ledger, storage: storage}
  end

  test "admission and result reserve and commit exact bounded identities", ctx do
    attrs = attrs("covered-effect")

    assert {:ok, started, :created} = EffectLedger.record_started(attrs, ctx.ledger)

    assert {:ok, settled, :updated} =
             EffectLedger.settle(
               attrs.id,
               %{status: :ok, result: %{agent_id: "peer"}},
               ctx.ledger
             )

    assert started.sequence == 1
    assert settled.sequence == 2
    observation = Epoch.observe(ctx.epoch)
    assert observation.pending == []
    assert length(observation.committed) == 2

    assert Enum.all?(
             observation.committed,
             &String.starts_with?(&1.write_id, "effect-ledger/v1/")
           )

    assert Enum.all?(observation.committed, &(byte_size(&1.write_id) <= 128))
    assert Enum.all?(observation.committed, &(byte_size(&1.payload_digest) == 64))
  end

  test "identical retries do not allocate another epoch and conflicts remain refused", ctx do
    attrs = attrs("stable-effect")
    assert {:ok, _entry, :created} = EffectLedger.record_started(attrs, ctx.ledger)
    assert {:ok, _entry, :existing} = EffectLedger.record_started(attrs, ctx.ledger)
    assert length(Epoch.observe(ctx.epoch).committed) == 1

    conflict = put_in(attrs, [:attempt, :agent], "other")

    assert {:error, {:effect_id_conflict, "stable-effect"}} =
             EffectLedger.record_started(conflict, ctx.ledger)

    assert length(Epoch.observe(ctx.epoch).committed) == 1
  end

  test "durable production configuration requires a supervised epoch", ctx do
    old = Application.get_env(:ouroboros, :data_dir)
    Application.put_env(:ouroboros, :data_dir, elem(ctx.storage, 1)[:path])

    on_exit(fn ->
      if old,
        do: Application.put_env(:ouroboros, :data_dir, old),
        else: Application.delete_env(:ouroboros, :data_dir)
    end)

    assert {:error, {:maintenance_epoch_required, _child}} =
             start_supervised(
               {EffectLedger, name: nil, storage: ctx.storage, epoch_server: nil},
               id: make_ref()
             )
  end

  defp attrs(id) do
    %{
      id: id,
      effect: :stop_agent,
      principal: "actor",
      attempt: %{agent: "peer"},
      authority: %{decision: :granted},
      cause: %{signal_id: "signal-#{id}"}
    }
  end
end
