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

  defp operation(id, status),
    do: %{id: id, fingerprint: "fingerprint", status: status, error: "failed"}

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
