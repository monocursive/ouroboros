defmodule Ouroboros.Upgrade.EpochTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.{Artifact, Epoch, NodeExecutor}
  alias Ouroboros.Upgrade.Rollout.Registry

  @module Ouroboros.Capability.EpochProbe

  setup do
    ensure_distributed!()
    on_exit(fn -> unload(@module) end)
    :ok
  end

  test "allocates above the highest epoch any target node reports" do
    peer_node = start_app_peer!()
    binary = compile_capability!()

    local = NodeExecutor.status().last_epoch
    peer_epoch = local + 1_000

    # Move one node's journal well ahead of the other's. The forge has to notice.
    assert {:ok, token} =
             :erpc.call(peer_node, NodeExecutor, :prepare, [
               introduce_artifact!(binary, peer_epoch)
             ])

    assert {:ok, receipt} = :erpc.call(peer_node, NodeExecutor, :commit, [token])
    assert :erpc.call(peer_node, NodeExecutor, :status, []).last_epoch == peer_epoch

    storage = ets_storage()

    assert {:ok, allocated} = Epoch.next([node(), peer_node], storage: storage)
    assert allocated == peer_epoch + 1

    # Nothing was deployed with the number above, and nothing on either node moved. The
    # next allocation must still be a different number: an epoch is spent when it is
    # allocated, not when it is used.
    assert {:ok, next} = Epoch.next([node(), peer_node], storage: storage)
    assert next == allocated + 1
    assert {:ok, ^next} = Epoch.watermark(storage: storage)

    assert :ok = :erpc.call(peer_node, NodeExecutor, :rollback, [receipt])
  end

  test "a node whose status cannot be read is a refusal, not a zero" do
    storage = ets_storage()

    assert {:error, {:epoch_status_unavailable, unreadable}} =
             Epoch.next([node(), :"nobody@nowhere-#{System.unique_integer([:positive])}"],
               storage: storage
             )

    assert map_size(unreadable) > 0

    # The failed allocation left no watermark behind, so a real allocation afterwards is
    # not pushed forward by an attempt that never produced a number.
    assert {:ok, 0} = Epoch.watermark(storage: storage)
    assert {:error, {:invalid_nodes, []}} = Epoch.next([], storage: storage)
  end

  test "allocates above a target's lane-W watermark when the driver changes" do
    name = String.to_atom("epoch_target_registry_#{System.unique_integer([:positive])}")

    {:ok, registry} =
      Registry.start_link(
        name: name,
        storage:
          {Jido.Storage.ETS,
           table: String.to_atom("epoch_target_claims_#{System.unique_integer([:positive])}")}
      )

    on_exit(fn -> if Process.alive?(registry), do: GenServer.stop(registry) end)

    claim = %{
      artifact_id: "previous-driver",
      epoch: 50_000,
      component_sha256: String.duplicate("a", 64)
    }

    assert :ok = Registry.admit_wasm_epoch(claim, name)

    assert {:ok, 50_001} =
             Epoch.next([node()], storage: ets_storage(), wasm_epoch_registry: name)
  end

  test "a watermark that survives the store's restart is not reissued" do
    directory = temporary_directory!()
    storage = {Ouroboros.Storage.DurableFile, path: directory}

    assert {:ok, allocated} = Epoch.next([node()], storage: storage)
    assert allocated > 0

    # The number is on disk before it is returned. Everything the forge does with it —
    # building, signing, deploying — happens after this point, so a crash anywhere in
    # there cannot bring the number back.
    assert File.dir?(Path.join(directory, "checkpoints"))
    assert {:ok, ^allocated} = Epoch.watermark(storage: storage)

    # Restarting the store is reading the same path again: the adapter holds no state of
    # its own, and the node statuses have not moved.
    assert {:ok, ^allocated} =
             Epoch.watermark(storage: {Ouroboros.Storage.DurableFile, path: directory})

    assert {:ok, reallocated} =
             Epoch.next([node()], storage: {Ouroboros.Storage.DurableFile, path: directory})

    assert reallocated > allocated
    assert {:ok, ^reallocated} = Epoch.watermark(storage: storage)
  end

  test "a watermark this build cannot read is refused rather than treated as zero" do
    {adapter, adapter_opts} = storage = ets_storage()
    assert :ok = adapter.put_checkpoint(epoch_key(), :nonsense, adapter_opts)

    assert {:error, {:corrupt_epoch_watermark, :nonsense}} = Epoch.watermark(storage: storage)

    assert {:error, {:corrupt_epoch_watermark, :nonsense}} =
             Epoch.next([node()], storage: storage)
  end

  defp epoch_key, do: {:ouroboros, :forge_epoch, 1}

  defp introduce_artifact!(binary, epoch) do
    {:ok, artifact} =
      Artifact.build([{@module, binary, disposition: :introduce}], epoch: epoch)

    artifact
  end

  defp compile_capability! do
    source = """
    defmodule #{inspect(@module)} do
      @vsn 1
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{@module, binary}] = Code.compile_string(source, "epoch_capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    unload(@module)
    binary
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp ets_storage do
    {Jido.Storage.ETS, table: String.to_atom("epoch_test_#{System.unique_integer([:positive])}")}
  end

  defp temporary_directory! do
    directory =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-epoch-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end

  defp start_app_peer! do
    peer_name = String.to_atom("ouroboros_epoch_peer_#{System.unique_integer([:positive])}")
    args = Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    {:ok, peer, peer_node} = :peer.start(%{name: peer_name, args: args, wait_boot: 20_000})
    on_exit(fn -> :peer.stop(peer) end)

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :upgrade_trust_policy,
        [allow_unsigned: true]
      ])

    :ok =
      :erpc.call(peer_node, Application, :put_env, [
        :ouroboros,
        :coding_storage,
        {Jido.Storage.ETS, table: peer_name}
      ])

    {:ok, _applications} = :erpc.call(peer_node, Application, :ensure_all_started, [:ouroboros])
    peer_node
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      name = String.to_atom("ouroboros_epoch_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([name, :shortnames])
    end
  end
end
