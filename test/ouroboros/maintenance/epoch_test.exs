defmodule Ouroboros.Maintenance.EpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Storage.DurableFile

  setup do
    root =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-maintenance-epoch-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, storage: {DurableFile, path: root}}
  end

  test "reservation is durable, monotonic, and exact retries are idempotent", %{storage: storage} do
    server = start_epoch!(storage)
    digest = digest("one")

    assert {:ok, first} = Epoch.reserve("write-1", digest, server)
    assert first == %{write_id: "write-1", epoch: 1, payload_digest: digest}
    assert {:ok, ^first} = Epoch.reserve("write-1", digest, server)
    assert {:error, :write_id_conflict} = Epoch.reserve("write-1", digest("other"), server)

    GenServer.stop(server)
    restarted = start_epoch!(storage)
    assert {:ok, ^first} = Epoch.reserve("write-1", digest, restarted)
    assert {:ok, %{epoch: 2}} = Epoch.reserve("write-2", digest("two"), restarted)
  end

  test "pending reservations commit exactly and observation is fence-suitable", %{
    storage: storage
  } do
    server = start_epoch!(storage)
    {:ok, reservation} = Epoch.reserve("write-1", digest("payload"), server)

    assert %{epoch: 1, pending: [%{status: :pending}], committed: [], aborted: []} =
             Epoch.observe(server)

    assert {:error, :reservation_identity_mismatch} =
             Epoch.commit(%{reservation | epoch: 2}, server)

    assert {:error, :reservation_identity_mismatch} =
             Epoch.commit(%{reservation | payload_digest: digest("forged")}, server)

    assert {:error, :unknown_reservation} =
             Epoch.commit(%{reservation | write_id: "unknown"}, server)

    assert :ok = Epoch.commit(reservation, server)
    assert :ok = Epoch.commit(reservation, server)

    assert %{epoch: 1, pending: [], committed: [committed]} = Epoch.observe(server)
    assert committed.status == :committed
    assert Map.drop(committed, [:status]) == reservation
  end

  test "abort requires truthful explicit absence confirmation and is terminal", %{
    storage: storage
  } do
    server = start_epoch!(storage)
    {:ok, reservation} = Epoch.reserve("write-1", digest("payload"), server)

    assert {:error, :payload_absence_confirmation_required} =
             Epoch.abort(reservation, :not_checked, server)

    assert :ok = Epoch.abort(reservation, :payload_absence_confirmed, server)
    assert :ok = Epoch.abort(reservation, :payload_absence_confirmed, server)
    assert {:error, :reservation_identity_mismatch} = Epoch.commit(reservation, server)

    assert %{epoch: 1, pending: [], committed: [], aborted: [%{status: :aborted}]} =
             Epoch.observe(server)

    GenServer.stop(server)
    restarted = start_epoch!(storage)
    assert %{epoch: 1, aborted: [%{write_id: "write-1"}]} = Epoch.observe(restarted)
  end

  test "retention capacity fails closed and survives restart", %{storage: storage} do
    server = start_epoch!(storage, max_entries: 2)
    assert {:ok, first} = Epoch.reserve("write-1", digest("one"), server)
    assert :ok = Epoch.commit(first, server)
    assert {:ok, _second} = Epoch.reserve("write-2", digest("two"), server)
    assert {:error, :epoch_capacity} = Epoch.reserve("write-3", digest("three"), server)
    assert {:ok, ^first} = Epoch.reserve("write-1", digest("one"), server)

    GenServer.stop(server)
    restarted = start_epoch!(storage, max_entries: 2)
    assert %{epoch: 2, retained_entries: 2, max_entries: 2} = Epoch.observe(restarted)
    assert {:error, :epoch_capacity} = Epoch.reserve("write-3", digest("three"), restarted)
  end

  test "malformed and unreadable persistence fail startup", %{root: root, storage: storage} do
    assert :ok =
             DurableFile.put_checkpoint(
               Epoch.checkpoint_key(),
               %{schema: 1, epoch: 9, entries: []},
               path: root
             )

    assert_start_refused(storage, {:maintenance_epoch_unavailable, :malformed_checkpoint})

    [path] = Path.wildcard(Path.join([root, "checkpoints", "*.term"]))
    File.write!(path, "not a durable checkpoint")

    assert_start_refused(
      storage,
      {:maintenance_epoch_unavailable, {:checkpoint_unreadable, :invalid_term}}
    )
  end

  test "stored entries above the configured bound fail startup", %{root: root, storage: storage} do
    entries = [
      {"write-1", 1, digest("one"), :committed},
      {"write-2", 2, digest("two"), :pending}
    ]

    assert :ok =
             DurableFile.put_checkpoint(
               Epoch.checkpoint_key(),
               %{schema: 1, epoch: 2, entries: entries},
               path: root
             )

    assert_start_refused(
      storage,
      {:maintenance_epoch_unavailable, :checkpoint_over_capacity},
      max_entries: 1
    )
  end

  defp start_epoch!(storage, opts \\ []) do
    {:ok, pid} = Epoch.start_link(Keyword.merge([name: nil, storage: storage], opts))
    pid
  end

  defp assert_start_refused(storage, reason, opts \\ []) do
    previous = Process.flag(:trap_exit, true)

    assert {:error, ^reason} =
             Epoch.start_link(Keyword.merge([name: nil, storage: storage], opts))

    receive do
      {:EXIT, _pid, ^reason} -> :ok
    after
      0 -> :ok
    end

    Process.flag(:trap_exit, previous)
  end

  defp digest(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
