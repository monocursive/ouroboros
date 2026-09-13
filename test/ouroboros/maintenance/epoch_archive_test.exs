defmodule Ouroboros.Maintenance.EpochArchiveTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.{Epoch, EpochReceipts}
  alias Ouroboros.Storage.DurableFile

  @moduletag :capture_log

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-epoch-archive-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, storage_opts: [path: root]}
  end

  test "sustained writes keep resident history bounded and preserve every terminal identity",
       ctx do
    server = start_epoch!(ctx.storage_opts)

    reservations =
      for number <- 1..48 do
        write_id = "write-#{number}"
        assert {:ok, reservation} = Epoch.reserve(write_id, digest(write_id), server)
        assert reservation.epoch == number

        status = if rem(number, 2) == 0, do: :aborted, else: :committed
        assert :ok = settle(server, reservation, status)
        assert %{pending: [], retained_entries: retained, max_entries: 2} = Epoch.observe(server)
        assert retained <= 2
        {reservation, status}
      end

    assert {:ok, %{schema: 2, epoch: 48, archived_entries: 46, entries: entries}} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    assert length(entries) == 2
    GenServer.stop(server)
    restarted = start_epoch!(ctx.storage_opts)

    for {reservation, status} <- reservations do
      expected = Map.put(reservation, :status, status)
      assert {:ok, ^expected} = Epoch.lookup(reservation.write_id, restarted)

      assert {:ok, ^reservation} =
               Epoch.reserve(reservation.write_id, reservation.payload_digest, restarted)

      assert {:error, :write_id_conflict} =
               Epoch.reserve(reservation.write_id, digest("different payload"), restarted)

      assert :ok = settle(restarted, reservation, status)
      opposite = if status == :committed, do: :aborted, else: :committed
      assert {:error, :reservation_identity_mismatch} = settle(restarted, reservation, opposite)
    end

    assert %{epoch: 48, pending: [], retained_entries: 2} = Epoch.observe(restarted)
    assert :not_found = Epoch.lookup("never-reserved", restarted)
    assert {:ok, %{epoch: 49}} = Epoch.reserve("next", digest("next"), restarted)
  end

  test "full pending history refuses allocation and only a finalized identity can be archived",
       ctx do
    server = start_epoch!(ctx.storage_opts)
    assert {:ok, first} = Epoch.reserve("first", digest("first"), server)
    assert {:ok, second} = Epoch.reserve("second", digest("second"), server)
    assert {:error, :epoch_capacity} = Epoch.reserve("third", digest("third"), server)
    assert %{epoch: 2, retained_entries: 2} = Epoch.observe(server)

    assert :ok = Epoch.commit(second, server)
    assert {:ok, third} = Epoch.reserve("third", digest("third"), server)
    assert third.epoch == 3
    assert {:ok, archived} = Epoch.lookup("second", server)
    assert archived == Map.put(second, :status, :committed)

    assert %{pending: pending, retained_entries: 2} = Epoch.observe(server)
    assert pending == Enum.map([first, third], &Map.put(&1, :status, :pending))
    assert {:error, :epoch_capacity} = Epoch.reserve("fourth", digest("fourth"), server)
  end

  test "a missing referenced receipt cannot turn an old identity into a fresh reservation", ctx do
    assert_receipt_damage_refused(ctx, :missing)
  end

  test "a structurally valid receipt with altered content is rejected by its committed hash",
       ctx do
    assert_receipt_damage_refused(ctx, :corrupt)
  end

  test "a full schema one checkpoint migrates without forgetting committed or aborted identities",
       ctx do
    first = {"legacy-committed", 1, digest("first"), :committed}
    second = {"legacy-aborted", 2, digest("second"), :aborted}

    assert :ok =
             DurableFile.put_checkpoint(
               Epoch.checkpoint_key(),
               %{schema: 1, epoch: 2, entries: [first, second]},
               ctx.storage_opts
             )

    server = start_epoch!(ctx.storage_opts)
    assert {:ok, %{epoch: 1, status: :committed}} = Epoch.lookup("legacy-committed", server)
    assert {:ok, %{epoch: 2, status: :aborted}} = Epoch.lookup("legacy-aborted", server)
    assert {:ok, third} = Epoch.reserve("new-third", digest("third"), server)
    assert third.epoch == 3
    assert :ok = Epoch.commit(third, server)
    assert {:ok, %{epoch: 4}} = Epoch.reserve("new-fourth", digest("fourth"), server)

    assert {:ok, %{schema: 2, epoch: 4, archived_entries: 2, entries: entries}} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    assert length(entries) == 2
    GenServer.stop(server)
    restarted = start_epoch!(ctx.storage_opts)

    for {write_id, epoch, payload_digest, status} <- [first, second] do
      reservation = %{write_id: write_id, epoch: epoch, payload_digest: payload_digest}
      expected = Map.put(reservation, :status, status)
      assert {:ok, ^expected} = Epoch.lookup(write_id, restarted)
      assert {:ok, ^reservation} = Epoch.reserve(write_id, payload_digest, restarted)
      assert :ok = settle(restarted, reservation, status)
    end

    assert {:error, :reservation_identity_mismatch} =
             Epoch.commit(
               %{write_id: "legacy-aborted", epoch: 2, payload_digest: digest("second")},
               restarted
             )

    assert %{epoch: 4} = Epoch.observe(restarted)
  end

  test "receipt publication without the new root checkpoint leaves allocation unchanged after restart",
       ctx do
    server = start_epoch!(ctx.storage_opts)
    assert {:ok, first} = Epoch.reserve("first", digest("first"), server)
    assert :ok = Epoch.commit(first, server)
    assert {:ok, second} = Epoch.reserve("second", digest("second"), server)
    assert :ok = Epoch.commit(second, server)

    assert {:ok, %{receipt_root: nil, archived_entries: 0} = before_failure} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    GenServer.stop(server)
    renames = start_supervised!({Agent, fn -> 0 end})

    # With an empty archive, the first rename publishes its single leaf. The second
    # would publish the new root and epoch together; refuse it before the old checkpoint
    # is replaced, leaving an immutable orphan that restart must not treat as authority.
    hook = fn
      :before_rename ->
        Agent.get_and_update(renames, fn count ->
          result = if count == 1, do: {:error, :injected_before_epoch_rename}, else: :ok
          {result, count + 1}
        end)

      _stage ->
        :ok
    end

    failing = start_epoch!(Keyword.put(ctx.storage_opts, :durability_hook, hook))
    monitor = Process.monitor(failing)
    assert {:error, _} = Epoch.reserve("third", digest("third"), failing)
    assert_receive {:DOWN, ^monitor, :process, ^failing, _}, 1_000
    assert Agent.get(renames, & &1) == 2

    assert {:ok, ^before_failure} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    orphan = {:leaf, digest("first"), {"first", 1, digest("first"), :committed}}
    orphan_hash = orphan |> :erlang.term_to_binary() |> digest()

    assert {:ok, ^orphan} =
             DurableFile.get_checkpoint(
               EpochReceipts.checkpoint_key(orphan_hash),
               ctx.storage_opts
             )

    restarted = start_epoch!(ctx.storage_opts)
    assert %{epoch: 2, retained_entries: 2} = Epoch.observe(restarted)
    assert :not_found = Epoch.lookup("third", restarted)
    assert {:ok, ^first} = Epoch.reserve("first", digest("first"), restarted)
    assert {:ok, ^second} = Epoch.reserve("second", digest("second"), restarted)
    assert {:ok, third} = Epoch.reserve("third", digest("third"), restarted)
    assert third.epoch == 3
    assert :ok = Epoch.commit(third, restarted)
    assert {:ok, %{epoch: 1, status: :committed}} = Epoch.lookup("first", restarted)
  end

  test "failure after the aggregate rename recovers the published root and pending allocation",
       ctx do
    server = start_epoch!(ctx.storage_opts)
    assert {:ok, first} = Epoch.reserve("first", digest("first"), server)
    assert :ok = Epoch.commit(first, server)
    assert {:ok, second} = Epoch.reserve("second", digest("second"), server)
    assert :ok = Epoch.commit(second, server)
    GenServer.stop(server)
    directory_syncs = start_supervised!({Agent, fn -> 0 end})

    # The archive leaf becomes durable first. The aggregate checkpoint's rename then
    # succeeds, but its directory sync has an unknown outcome: restart must use the
    # authoritative checkpoint it reads, including the already allocated third epoch.
    hook = fn
      :before_directory_sync ->
        Agent.get_and_update(directory_syncs, fn count ->
          result = if count == 1, do: {:error, :injected_before_epoch_directory_sync}, else: :ok
          {result, count + 1}
        end)

      _stage ->
        :ok
    end

    failing = start_epoch!(Keyword.put(ctx.storage_opts, :durability_hook, hook))
    monitor = Process.monitor(failing)
    assert {:error, _} = Epoch.reserve("third", digest("third"), failing)

    assert_receive {:DOWN, ^monitor, :process, ^failing,
                    {:maintenance_epoch_persist_failed,
                     {:commit_outcome_unknown, :injected_before_epoch_directory_sync}}},
                   1_000

    assert Agent.get(directory_syncs, & &1) == 2

    assert {:ok, %{epoch: 3, archived_entries: 1, receipt_root: root, entries: entries}} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    assert is_binary(root)
    third_digest = digest("third")
    assert {"third", 3, third_digest, :pending} in entries

    assert {:ok, {:leaf, _, {"first", 1, _, :committed}}} =
             DurableFile.get_checkpoint(EpochReceipts.checkpoint_key(root), ctx.storage_opts)

    restarted = start_epoch!(ctx.storage_opts)
    third = %{write_id: "third", epoch: 3, payload_digest: third_digest}
    expected_pending = Map.put(third, :status, :pending)
    assert {:ok, ^expected_pending} = Epoch.lookup("third", restarted)
    assert {:ok, ^third} = Epoch.reserve("third", third_digest, restarted)
    assert {:ok, ^first} = Epoch.reserve("first", digest("first"), restarted)
    assert {:ok, %{status: :committed, epoch: 1}} = Epoch.lookup("first", restarted)
    assert %{epoch: 3, pending: [^expected_pending]} = Epoch.observe(restarted)
    assert :ok = Epoch.commit(third, restarted)
    assert %{epoch: 3, pending: []} = Epoch.observe(restarted)
  end

  test "an intact branch cannot hide a missing referenced child during lookup or startup", ctx do
    server = start_epoch!(ctx.storage_opts)

    for write_id <- ["first", "second", "third", "fourth"] do
      assert {:ok, reservation} = Epoch.reserve(write_id, digest(write_id), server)
      assert :ok = Epoch.commit(reservation, server)
    end

    assert {:ok, %{receipt_root: root, archived_entries: 2} = checkpoint} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    root_key = EpochReceipts.checkpoint_key(root)

    assert {:ok, {:branch, _, [{_, child_hash} | _]} = branch} =
             DurableFile.get_checkpoint(root_key, ctx.storage_opts)

    child_key = EpochReceipts.checkpoint_key(child_hash)

    assert {:ok, {:leaf, _, {write_id, _, payload_digest, :committed}}} =
             DurableFile.get_checkpoint(child_key, ctx.storage_opts)

    assert :ok = DurableFile.delete_checkpoint(child_key, ctx.storage_opts)
    assert {:ok, ^branch} = DurableFile.get_checkpoint(root_key, ctx.storage_opts)
    assert {:error, _} = Epoch.lookup(write_id, server)
    assert {:error, _} = Epoch.reserve(write_id, payload_digest, server)
    GenServer.stop(server)
    assert {:error, _} = start_supervised(epoch_spec(ctx.storage_opts))

    assert {:ok, ^checkpoint} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)
  end

  defp assert_receipt_damage_refused(ctx, damage) do
    server = start_epoch!(ctx.storage_opts)

    for write_id <- ["first", "second", "third"] do
      assert {:ok, reservation} = Epoch.reserve(write_id, digest(write_id), server)
      assert :ok = Epoch.commit(reservation, server)
    end

    assert {:ok, %{receipt_root: root, archived_entries: 1} = checkpoint} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    key = EpochReceipts.checkpoint_key(root)

    assert {:ok, {:leaf, key_hash, {"first", 1, payload_digest, :committed}}} =
             DurableFile.get_checkpoint(key, ctx.storage_opts)

    assert payload_digest == digest("first")

    case damage do
      :missing ->
        assert :ok = DurableFile.delete_checkpoint(key, ctx.storage_opts)

      :corrupt ->
        assert :ok =
                 DurableFile.put_checkpoint(
                   key,
                   {:leaf, key_hash, {"first", 1, digest("altered"), :committed}},
                   ctx.storage_opts
                 )
    end

    assert {:error, _} = Epoch.lookup("first", server)
    assert {:error, _} = Epoch.reserve("first", digest("first"), server)

    assert {:ok, ^checkpoint} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)

    GenServer.stop(server)
    assert {:error, _} = start_supervised(epoch_spec(ctx.storage_opts))

    assert {:ok, ^checkpoint} =
             DurableFile.get_checkpoint(Epoch.checkpoint_key(), ctx.storage_opts)
  end

  defp start_epoch!(storage_opts), do: start_supervised!(epoch_spec(storage_opts))

  defp epoch_spec(storage_opts) do
    %{
      id: make_ref(),
      start:
        {Epoch, :start_link, [[name: nil, max_entries: 2, storage: {DurableFile, storage_opts}]]},
      restart: :temporary
    }
  end

  defp settle(server, reservation, :committed), do: Epoch.commit(reservation, server)

  defp settle(server, reservation, :aborted),
    do: Epoch.abort(reservation, :payload_absence_confirmed, server)

  defp digest(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
