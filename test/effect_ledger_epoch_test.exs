defmodule Ouroboros.Agent.EffectLedgerEpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Storage.DurableFile

  defmodule ReservedEpochProxy do
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

    @impl true
    def init(opts) do
      {:ok,
       %{epoch: Keyword.fetch!(opts, :epoch), mode: Keyword.fetch!(opts, :mode), reserved: nil}}
    end

    @impl true
    def handle_call({:reserve, write_id, digest}, _from, state) do
      with {:ok, reservation} <- Epoch.reserve(write_id, digest, state.epoch),
           :ok <- finalize(state, reservation) do
        {:reply, {:ok, reservation}, %{state | reserved: reservation}}
      else
        error -> {:reply, error, state}
      end
    end

    def handle_call({:lookup, write_id}, _from, %{mode: :mismatched_lookup} = state) do
      result =
        case Epoch.lookup(write_id, state.epoch) do
          {:ok, receipt} -> {:ok, %{receipt | epoch: receipt.epoch + 1}}
          other -> other
        end

      {:reply, result, state}
    end

    def handle_call(:reserved, _from, state), do: {:reply, state.reserved, state}

    def handle_call(request, _from, state),
      do: {:reply, GenServer.call(state.epoch, request), state}

    defp finalize(%{mode: :aborted, epoch: epoch}, reservation),
      do: Epoch.abort(reservation, :payload_absence_confirmed, epoch)

    defp finalize(%{mode: :committed, epoch: epoch}, reservation),
      do: Epoch.commit(reservation, epoch)

    defp finalize(%{mode: :mismatched_lookup}, _reservation), do: :ok
  end

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

  test "an aborted reservation refuses admission before changing the durable ledger", ctx do
    assert {:ok, baseline, :created} =
             EffectLedger.record_denied(attrs("aborted-baseline"), ctx.ledger)

    {ledger, proxy} = ledger_with_epoch_proxy(ctx, :aborted)
    before = checkpoint_snapshot(ctx.storage)
    attempted = attrs("aborted-admission")

    assert {:error,
            {:effect_ledger_checkpoint_failed, {:maintenance_epoch, :reservation_aborted}}} =
             EffectLedger.record_started(attempted, ledger)

    assert checkpoint_snapshot(ctx.storage) == before
    assert :not_found = EffectLedger.get(attempted.id, ledger)
    assert {:ok, ^baseline} = EffectLedger.get(baseline.id, ledger)
    assert_proxy_receipt(proxy, ctx.epoch, :aborted)
    assert Epoch.observe(ctx.epoch).pending == []
  end

  test "a committed reservation cannot publish a payload that is absent from the durable ledger",
       ctx do
    {ledger, proxy} = ledger_with_epoch_proxy(ctx, :committed)
    before = checkpoint_snapshot(ctx.storage)
    assert before.payload == :not_found
    attempted = attrs("committed-absent-admission")

    assert {:error,
            {:effect_ledger_checkpoint_failed, {:maintenance_epoch, :committed_payload_mismatch}}} =
             EffectLedger.record_started(attempted, ledger)

    assert checkpoint_snapshot(ctx.storage) == before
    assert :not_found = EffectLedger.get(attempted.id, ledger)
    assert {:ok, []} = EffectLedger.list([], ledger)
    assert_proxy_receipt(proxy, ctx.epoch, :committed)
    assert Epoch.observe(ctx.epoch).pending == []
  end

  test "a committed reservation cannot replace another durable ledger payload", ctx do
    assert {:ok, baseline, :created} =
             EffectLedger.record_denied(attrs("committed-baseline"), ctx.ledger)

    {ledger, proxy} = ledger_with_epoch_proxy(ctx, :committed)
    before = checkpoint_snapshot(ctx.storage)
    assert {:ok, _payload} = before.payload
    assert map_size(before.files) == 1
    attempted = attrs("committed-other-admission")

    assert {:error,
            {:effect_ledger_checkpoint_failed, {:maintenance_epoch, :committed_payload_mismatch}}} =
             EffectLedger.record_started(attempted, ledger)

    assert checkpoint_snapshot(ctx.storage) == before
    assert :not_found = EffectLedger.get(attempted.id, ledger)
    assert {:ok, ^baseline} = EffectLedger.get(baseline.id, ledger)
    assert_proxy_receipt(proxy, ctx.epoch, :committed)
    assert Epoch.observe(ctx.epoch).pending == []
  end

  test "a mismatched lookup identity refuses publication and preserves the real pending reservation",
       ctx do
    {ledger, proxy} = ledger_with_epoch_proxy(ctx, :mismatched_lookup)
    before = checkpoint_snapshot(ctx.storage)
    attempted = attrs("mismatched-lookup-admission")

    assert {:error,
            {:effect_ledger_checkpoint_failed,
             {:maintenance_epoch, :reservation_identity_mismatch}}} =
             EffectLedger.record_started(attempted, ledger)

    assert checkpoint_snapshot(ctx.storage) == before
    assert :not_found = EffectLedger.get(attempted.id, ledger)
    assert {:ok, []} = EffectLedger.list([], ledger)
    receipt = assert_proxy_receipt(proxy, ctx.epoch, :pending)
    assert Epoch.observe(ctx.epoch).pending == [receipt]
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

  defp ledger_with_epoch_proxy(ctx, mode) do
    stop_supervised!(EffectLedger)
    proxy = start_supervised!({ReservedEpochProxy, epoch: ctx.epoch, mode: mode})

    ledger =
      start_supervised!({EffectLedger, name: nil, storage: ctx.storage, epoch_server: proxy})

    {ledger, proxy}
  end

  defp assert_proxy_receipt(proxy, epoch, status) do
    reservation = GenServer.call(proxy, :reserved)
    assert is_map(reservation)
    assert {:ok, receipt} = Epoch.lookup(reservation.write_id, epoch)
    assert receipt == Map.put(reservation, :status, status)
    receipt
  end

  defp checkpoint_snapshot({DurableFile, opts}) do
    files =
      opts
      |> Keyword.fetch!(:path)
      |> Path.join("checkpoints/*.term")
      |> Path.wildcard()
      |> Map.new(fn path -> {path, File.read!(path)} end)

    %{payload: DurableFile.get_checkpoint(EffectLedger.checkpoint_key(), opts), files: files}
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
