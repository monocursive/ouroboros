defmodule Ouroboros.Provider.Native.CheckpointEpochTest do
  use ExUnit.Case, async: true

  alias Ouroboros.Maintenance.Epoch
  alias Ouroboros.Provider.Native.Checkpoint

  setup do
    root = Path.join(System.tmp_dir!(), "checkpoint-epoch-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    epoch = start_supervised!({Epoch, name: nil, data_dir: root})
    on_exit(fn -> File.rm_rf(root) end)

    %{epoch: epoch, path: Path.join(root, "conversation.json")}
  end

  test "reserves exact published bytes before publication and commits", ctx do
    messages = [%{role: :user, content: "durable"}]

    assert {:ok, conversation_digest} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: {:session, "s1", :turn, "t1"}
             )

    [reservation] = Epoch.observe(ctx.epoch).committed
    bytes = File.read!(ctx.path)

    assert reservation.payload_digest == sha256(bytes)
    assert byte_size(reservation.write_id) <= 128
    assert String.starts_with?(reservation.write_id, "native-checkpoint/v1/")
    assert {:ok, %{digest: ^conversation_digest}} = Checkpoint.snapshot(ctx.path)
  end

  test "epoch integration requires operation identity and does not publish", ctx do
    assert {:error, :checkpoint_operation_identity_required} =
             Checkpoint.write(ctx.path, [], epoch_server: ctx.epoch)

    refute File.exists?(ctx.path)
    assert Epoch.observe(ctx.epoch).retained_entries == 0
  end

  test "pending exact final bytes reconcile by commit without rewriting", ctx do
    messages = [%{role: :user, content: "same bytes"}]
    identity = {:handoff, "operation-1"}

    assert {:ok, digest} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    bytes = File.read!(ctx.path)
    stat = File.stat!(ctx.path, time: :posix)
    committed = hd(Epoch.observe(ctx.epoch).committed)

    # A second Epoch supplies the crash-recovered pending identity while the exact final
    # bytes remain. The writer must observe and commit; it must not replay publication.
    root2 = Path.join(Path.dirname(ctx.path), "second-epoch")
    {:ok, epoch2} = Epoch.start_link(name: nil, data_dir: root2)
    on_exit(fn -> if Process.alive?(epoch2), do: GenServer.stop(epoch2) end)
    assert {:ok, _reservation} = Epoch.reserve(committed.write_id, sha256(bytes), epoch2)

    assert {:ok, ^digest} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: epoch2,
               operation_identity: identity
             )

    assert File.stat!(ctx.path, time: :posix).inode == stat.inode
    assert File.read!(ctx.path) == bytes
    assert Epoch.observe(epoch2).pending == []
  end

  test "an exact retry after commit succeeds without rewriting", ctx do
    messages = [%{role: :user, content: "stable retry"}]
    identity = {:session, "s1", :close}

    assert {:ok, digest} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    bytes = File.read!(ctx.path)
    inode = File.stat!(ctx.path).inode

    assert {:ok, ^digest} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    assert File.read!(ctx.path) == bytes
    assert File.stat!(ctx.path).inode == inode
    assert length(Epoch.observe(ctx.epoch).committed) == 1
  end

  test "pending confirmed absence aborts and never blindly publishes", ctx do
    identity = {:fork, "operation-2"}
    write_id = write_id(ctx.path, identity)
    messages = [%{role: :user, content: "must not appear"}]
    assert {:ok, _} = Epoch.reserve(write_id, payload_digest(ctx.path, messages), ctx.epoch)

    assert {:error, :checkpoint_payload_absent} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    refute File.exists?(ctx.path)
    assert [%{write_id: ^write_id}] = Epoch.observe(ctx.epoch).aborted
  end

  test "archived terminal identities still prevent checkpoint publication", ctx do
    epoch =
      start_supervised!(
        {Epoch,
         name: nil, data_dir: Path.join(Path.dirname(ctx.path), "bounded"), max_entries: 1},
        id: :bounded_epoch
      )

    messages = [%{role: :user, content: "retained"}]
    opts = [epoch_server: epoch, operation_identity: :archived_checkpoint]
    assert {:ok, digest} = Checkpoint.write(ctx.path, messages, opts)
    bytes = File.read!(ctx.path)
    inode = File.stat!(ctx.path).inode
    assert {:ok, filler} = Epoch.reserve("filler", sha256("filler"), epoch)
    assert :ok = Epoch.commit(filler, epoch)
    assert %{archived_entries: 1} = Epoch.observe(epoch)

    assert {:ok, ^digest} = Checkpoint.write(ctx.path, messages, opts)
    assert File.stat!(ctx.path).inode == inode
    assert File.read!(ctx.path) == bytes

    assert {:error, {:maintenance_epoch, :write_id_conflict}} =
             Checkpoint.write(ctx.path, [%{role: :user, content: "changed"}], opts)

    assert File.read!(ctx.path) == bytes

    File.rm!(ctx.path)
    assert {:error, _} = Checkpoint.write(ctx.path, messages, opts)
    refute File.exists?(ctx.path)

    absent_id = write_id(ctx.path, :archived_abort)
    assert {:ok, absent} = Epoch.reserve(absent_id, sha256("absent"), epoch)
    assert :ok = Epoch.abort(absent, :payload_absence_confirmed, epoch)
    assert {:ok, _} = Epoch.reserve("later", sha256("later"), epoch)

    assert {:error, {:checkpoint_operation_already_settled, :aborted}} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: epoch,
               operation_identity: :archived_abort
             )

    refute File.exists?(ctx.path)
  end

  test "pending mismatched final bytes remain pending and are never overwritten", ctx do
    identity = {:session, "s2", :turn, "t2"}
    write_id = write_id(ctx.path, identity)
    messages = [%{role: :user, content: "replacement"}]
    assert {:ok, _} = Epoch.reserve(write_id, payload_digest(ctx.path, messages), ctx.epoch)
    File.write!(ctx.path, "other durable bytes")

    assert {:error, :checkpoint_payload_outcome_unknown} =
             Checkpoint.write(ctx.path, messages,
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    assert File.read!(ctx.path) == "other durable bytes"
    assert [%{write_id: ^write_id}] = Epoch.observe(ctx.epoch).pending
  end

  test "a changed retry cannot settle an older pending checkpoint or report its digest", ctx do
    original = [%{role: :user, content: "original"}]
    identity = :conflicting_pending
    expected_digest = payload_digest(ctx.path, original)

    assert {:ok, pending} =
             Epoch.reserve(write_id(ctx.path, identity), expected_digest, ctx.epoch)

    assert {:ok, _} = Checkpoint.write(ctx.path, original, updated_at: "1970-01-01T00:00:00Z")
    bytes = File.read!(ctx.path)

    assert {:error, {:maintenance_epoch, :write_id_conflict}} =
             Checkpoint.write(ctx.path, [%{role: :user, content: "changed"}],
               epoch_server: ctx.epoch,
               operation_identity: identity
             )

    assert File.read!(ctx.path) == bytes
    assert {:ok, %{status: :pending}} = Epoch.lookup(pending.write_id, ctx.epoch)
  end

  defp payload_digest(path, messages) do
    expected = path <> ".expected"
    assert {:ok, _} = Checkpoint.write(expected, messages, updated_at: "1970-01-01T00:00:00Z")
    bytes = File.read!(expected)
    File.rm!(expected)
    sha256(bytes)
  end

  defp write_id(path, identity) do
    encoded = :erlang.term_to_binary({path, identity}, [:deterministic])
    "native-checkpoint/v1/" <> sha256(encoded)
  end

  defp sha256(bytes),
    do: bytes |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
end
