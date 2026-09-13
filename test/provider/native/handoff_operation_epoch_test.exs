defmodule Ouroboros.Provider.Native.HandoffOperationEpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Provider.Native.Context.HandoffOperation

  setup do
    dir = Path.join(System.tmp_dir!(), "handoff-epoch-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    epoch = start_supervised!({Epoch, name: nil, data_dir: Path.join(dir, "epoch")})
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir, epoch: epoch, path: HandoffOperation.path(dir)}
  end

  test "ordinary put reserves exact bytes and commits", ctx do
    operation = operation("h1", :failed)

    assert {:ok, %{"h1" => ^operation}} =
             HandoffOperation.put(ctx.dir, %{}, operation, epoch_server: ctx.epoch)

    [entry] = Epoch.observe(ctx.epoch).committed
    assert entry.payload_digest == sha256(File.read!(ctx.path))
    assert String.starts_with?(entry.write_id, "native-handoff/v1/")
  end

  test "load commits exact pending publication without rewriting", ctx do
    operation = operation("h2", :failed)
    operations = %{operation.id => operation}
    bytes = HandoffOperation.encode_operations(operations)
    write_id = HandoffOperation.epoch_write_id(ctx.path, {operation.id, operation.status})
    assert {:ok, _} = Epoch.reserve(write_id, sha256(bytes), ctx.epoch)
    File.write!(ctx.path, bytes)
    inode = File.stat!(ctx.path).inode

    assert %{"h2" => ^operation} = HandoffOperation.load(ctx.dir, epoch_server: ctx.epoch)
    assert Epoch.observe(ctx.epoch).pending == []
    assert File.stat!(ctx.path).inode == inode
  end

  test "load aborts pending publication after confirmed absence", ctx do
    write_id = HandoffOperation.epoch_write_id(ctx.path, {"h3", :running})
    assert {:ok, _} = Epoch.reserve(write_id, String.duplicate("b", 64), ctx.epoch)

    assert %{} = HandoffOperation.load(ctx.dir, epoch_server: ctx.epoch)
    assert [%{write_id: ^write_id}] = Epoch.observe(ctx.epoch).aborted
    refute File.exists?(ctx.path)
  end

  test "load retains pending mismatch and refuses", ctx do
    write_id = HandoffOperation.epoch_write_id(ctx.path, {"h4", :running})
    assert {:ok, _} = Epoch.reserve(write_id, String.duplicate("c", 64), ctx.epoch)
    File.write!(ctx.path, "different")

    assert_raise ArgumentError, ~r/outcome_unknown/, fn ->
      HandoffOperation.load(ctx.dir, epoch_server: ctx.epoch)
    end

    assert [%{write_id: ^write_id}] = Epoch.observe(ctx.epoch).pending
    assert File.read!(ctx.path) == "different"
  end

  test "archived handoff commit retries without rewriting and cannot recreate missing payload",
       ctx do
    epoch =
      start_supervised!(
        {Epoch, name: nil, data_dir: Path.join(ctx.dir, "bounded"), max_entries: 1},
        id: :bounded_epoch
      )

    operation = operation("archived", :failed)
    assert {:ok, operations} = HandoffOperation.put(ctx.dir, %{}, operation, epoch_server: epoch)
    bytes = File.read!(ctx.path)
    inode = File.stat!(ctx.path).inode
    assert {:ok, filler} = Epoch.reserve("filler", sha256("filler"), epoch)
    assert :ok = Epoch.commit(filler, epoch)
    assert %{archived_entries: 1} = Epoch.observe(epoch)

    assert {:ok, ^operations} = HandoffOperation.put(ctx.dir, %{}, operation, epoch_server: epoch)
    assert File.stat!(ctx.path).inode == inode
    assert File.read!(ctx.path) == bytes

    assert {:error, {:maintenance_epoch, :write_id_conflict}} =
             HandoffOperation.put(ctx.dir, %{}, %{operation | error: "changed"},
               epoch_server: epoch
             )

    assert File.read!(ctx.path) == bytes

    File.rm!(ctx.path)

    assert {:error, {:handoff_operation_committed_payload_invalid, :absent}} =
             HandoffOperation.put(ctx.dir, %{}, operation, epoch_server: epoch)

    refute File.exists?(ctx.path)
  end

  test "changed handoff bytes cannot settle a different pending payload", ctx do
    operation = operation("conflicting", :failed)
    original = HandoffOperation.encode_operations(%{operation.id => operation})
    id = HandoffOperation.epoch_write_id(ctx.path, {operation.id, operation.status})
    assert {:ok, pending} = Epoch.reserve(id, sha256(original), ctx.epoch)
    changed = %{operation | error: "changed"}
    bytes = HandoffOperation.encode_operations(%{changed.id => changed})
    File.write!(ctx.path, bytes)

    assert {:error, {:maintenance_epoch, :write_id_conflict}} =
             HandoffOperation.put(ctx.dir, %{}, changed, epoch_server: ctx.epoch)

    assert File.read!(ctx.path) == bytes
    assert {:ok, %{status: :pending}} = Epoch.lookup(pending.write_id, ctx.epoch)
  end

  defp operation(id, status),
    do: %{id: id, fingerprint: "fingerprint", status: status, error: "failed"}

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
