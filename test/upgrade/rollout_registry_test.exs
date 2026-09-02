defmodule Ouroboros.Upgrade.RolloutRegistryTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Upgrade.Coordinator.{DeploymentReceipt, NodeReceipt}
  alias Ouroboros.Upgrade.Rollout
  alias Ouroboros.Upgrade.Rollout.Registry

  @module Ouroboros.Capability.Recorded

  test "records a rollout and refuses transitions that would lose information" do
    registry = start_registry!()

    assert {:ok, entry} = Registry.deploying(attrs(), registry)
    assert entry.state == :deploying
    assert entry.module == @module
    assert entry.created_at == entry.updated_at

    assert {:error, {:already_recorded, _id}} =
             Registry.deploying(attrs(entry.artifact_id), registry)

    assert {:error, {:unknown_rollout, "nope"}} = Registry.mark("nope", :live, [], registry)
    assert {:error, {:invalid_state, :wat}} = Registry.mark(entry.artifact_id, :wat, [], registry)

    assert {:ok, live} =
             Registry.mark(entry.artifact_id, :live, [detail: %{note: "healthy"}], registry)

    assert live.state == :live
    assert live.detail == %{note: "healthy"}
    assert live.updated_at >= live.created_at
    assert Registry.live(registry) == [live]

    # A live rollout can still be rolled back or discovered to be ambiguous later.
    assert {:ok, rolled_back} = Registry.mark(entry.artifact_id, :rolled_back, [], registry)
    assert rolled_back.state == :rolled_back
    assert Registry.live(registry) == []

    # Going backwards would claim knowledge nobody has: a rolled-back rollout that is
    # somehow live again is a new deployment, not an edit to this record.
    assert {:error, {:invalid_transition, :rolled_back, :live}} =
             Registry.mark(entry.artifact_id, :live, [], registry)

    assert {:ok, quarantined} = Registry.mark(entry.artifact_id, :quarantined, [], registry)
    assert quarantined.state == :quarantined

    # Quarantine has no automatic exit here, exactly as it has none in the node executor.
    for state <- [:live, :rolled_back, :deploying, :superseded] do
      assert {:error, {:invalid_transition, :quarantined, ^state}} =
               Registry.mark(entry.artifact_id, state, [], registry)
    end

    assert [%{artifact_id: id}] = Registry.history(@module, registry)
    assert id == entry.artifact_id
    assert Registry.history(Ouroboros.Capability.Unrelated, registry) == []
  end

  test "marking a module live supersedes the overlapping champion" do
    registry = start_registry!()
    {:ok, champion} = Registry.deploying(attrs(), registry)
    {:ok, live_champion} = Registry.mark(champion.artifact_id, :live, [], registry)
    {:ok, challenger} = Registry.deploying(attrs(), registry)

    assert {:ok, live_challenger} = Registry.mark(challenger.artifact_id, :live, [], registry)
    assert live_challenger.state == :live
    assert Registry.live(registry) == [live_challenger]

    assert {:ok, superseded} = Registry.get(champion.artifact_id, registry)
    assert superseded.state == :superseded
    assert superseded.detail == %{replaced_by: live_challenger.artifact_id}
    assert live_champion.state == :live

    assert {:error, {:invalid_transition, :superseded, :live}} =
             Registry.mark(champion.artifact_id, :live, [], registry)
  end

  test "rejects malformed records rather than storing a rollout nobody can interpret" do
    registry = start_registry!()

    assert {:error, {:missing_attribute, :artifact_id}} =
             Registry.deploying(Map.delete(attrs(), :artifact_id), registry)

    assert {:error, {:invalid_attribute, :epoch, 0}} =
             Registry.deploying(%{attrs() | epoch: 0}, registry)

    assert {:error, {:invalid_attribute, :nodes, []}} =
             Registry.deploying(%{attrs() | nodes: []}, registry)

    assert {:error, {:invalid_attribute, :module, "not-a-module"}} =
             Registry.deploying(%{attrs() | module: "not-a-module"}, registry)

    assert Registry.list(registry) == []
  end

  describe "lane W's epoch watermark" do
    test "refuses an epoch this register has already seen, in any state" do
      registry = start_registry!()

      {:ok, first} = Registry.deploying(wasm_attrs(epoch: 70), registry)

      # Equal is stale: the number was spent by the entry that has it.
      assert {:error, {:stale_epoch, 70, 70}} =
               Registry.deploying(wasm_attrs(epoch: 70), registry)

      assert {:error, {:stale_epoch, 60, 70}} =
               Registry.deploying(wasm_attrs(epoch: 60), registry)

      assert {:ok, _second} = Registry.deploying(wasm_attrs(epoch: 71), registry)

      # Every state counts, including the ones that are finished history: a `:rolled_back`
      # entry's number was still spent, so a later manifest may not reuse it.
      {:ok, _rolled_back} = Registry.mark(first.artifact_id, :rolled_back, [], registry)

      assert {:error, {:stale_epoch, 71, 71}} =
               Registry.deploying(wasm_attrs(epoch: 71), registry)
    end

    test "the check is inside the checkpoint, so concurrent callers cannot both record" do
      # The read-then-write this replaced: every caller read an empty register, every one
      # saw its epoch as fresh against `highest = 0`, and every one checkpointed. Here the
      # check and the write are the same serialized message.
      #
      # The epochs are *identical* on purpose, which is what makes the assertion
      # order-independent: whichever message the register handles first, every later one's
      # epoch is no longer greater than what it now holds. With descending epochs the
      # outcome would legitimately depend on arrival order and the test would prove nothing.
      registry = start_registry!()

      results =
        1..8
        |> Enum.map(fn _attempt ->
          Task.async(fn -> Registry.deploying(wasm_attrs(epoch: 70), registry) end)
        end)
        |> Task.await_many(5_000)

      assert Enum.count(results, &match?({:ok, _entry}, &1)) == 1
      assert Enum.count(results, &match?({:error, {:stale_epoch, 70, 70}}, &1)) == 7
      assert [%Registry.Entry{epoch: 70}] = Registry.list(registry)
    end

    test "lane B is not held to it and does not raise it" do
      registry = start_registry!()

      # A BEAM rollout carries no component sha. Its epochs are the node executor's
      # business, and they neither refuse each other here nor move lane W's watermark.
      {:ok, _a} = Registry.deploying(attrs(nil, epoch: 900), registry)
      {:ok, _b} = Registry.deploying(attrs(nil, epoch: 100), registry)
      {:ok, _c} = Registry.deploying(attrs(nil, epoch: 100), registry)

      assert {:ok, entry} = Registry.deploying(wasm_attrs(epoch: 1), registry)
      assert entry.epoch == 1
    end

    test "a malformed component sha is refused before anything is recorded" do
      registry = start_registry!()

      assert {:error, {:invalid_attribute, :component_sha256, "nope"}} =
               Registry.deploying(wasm_attrs(component_sha256: "nope"), registry)

      assert {:error, {:invalid_attribute, :component_sha256, :sha}} =
               Registry.deploying(wasm_attrs(component_sha256: :sha), registry)

      assert Registry.list(registry) == []
    end
  end

  test "a failed checkpoint is a failed rollout, not an in-memory one" do
    directory = temporary_directory!()

    hook = fn
      :before_write -> {:error, :disk_full}
      _event -> :ok
    end

    registry =
      start_registry!(
        storage: {Ouroboros.Storage.DurableFile, path: directory, durability_hook: hook}
      )

    # The caller must be able to treat this as "nothing happened", because the deployment
    # it was about to authorize has not started.
    assert {:error, {:rollout_checkpoint_failed, :disk_full}} =
             Registry.deploying(attrs(), registry)

    assert Registry.list(registry) == []
    assert Registry.durability(registry) == :synced_checkpoint
  end

  test "a checkpoint this build cannot interpret is preserved, not overwritten" do
    Process.flag(:trap_exit, true)
    directory = temporary_directory!()
    storage = {Ouroboros.Storage.DurableFile, path: directory}
    {adapter, adapter_opts} = storage

    assert :ok =
             adapter.put_checkpoint(
               Registry.checkpoint_key(),
               %{version: 99, rollouts: %{}},
               adapter_opts
             )

    assert {:error, {:unsupported_rollout_checkpoint, 99}} =
             Registry.start_link(name: unique_name(), storage: storage)

    assert {:ok, %{version: 99}} =
             adapter.get_checkpoint(Registry.checkpoint_key(), adapter_opts)
  end

  test "a checkpoint written before evaluation existed is widened, not refused" do
    directory = temporary_directory!()
    storage = {Ouroboros.Storage.DurableFile, path: directory}
    {adapter, adapter_opts} = storage

    # Exactly what a version-1 build wrote: an entry with no `eval_report` field at all.
    legacy = %{Map.delete(entry!(), :eval_report) | state: :live}
    refute Map.has_key?(legacy, :eval_report)

    :ok =
      adapter.put_checkpoint(
        Registry.checkpoint_key(),
        %{version: 1, rollouts: %{legacy.artifact_id => legacy}},
        adapter_opts
      )

    name = unique_name()
    {:ok, pid} = Registry.start_link(name: name, storage: storage)
    # The registry is linked to the test process, so it can die between an
    # aliveness check and the stop; catching the exit is the only raceless form.
    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end)

    assert {:ok, restored} = Registry.get(legacy.artifact_id, name)
    assert restored.state == :live
    assert restored.module == @module
    assert restored.source_sha256 == legacy.source_sha256
    assert restored.created_at == legacy.created_at

    # `nil` is the honest value: that rollout was never evaluated, because nothing could
    # evaluate it. It is not an empty report and does not read like one.
    assert restored.eval_report == nil

    assert {:ok, marked} =
             Registry.mark(legacy.artifact_id, :rolled_back, [eval_report: %{passed: 0}], name)

    assert marked.eval_report == %{passed: 0}
  end

  test "an entry this build cannot read is refused rather than repaired" do
    Process.flag(:trap_exit, true)
    directory = temporary_directory!()
    storage = {Ouroboros.Storage.DurableFile, path: directory}
    {adapter, adapter_opts} = storage

    # A version this build has never heard of, and a version-1 entry that is not an entry:
    # neither is something to coerce into a rollout record nobody wrote.
    for rollouts <- [
          %{"a" => %{artifact_id: "a", state: :live}},
          %{"a" => Map.delete(entry!("a"), :state)}
        ] do
      :ok =
        adapter.put_checkpoint(
          Registry.checkpoint_key(),
          %{version: 1, rollouts: rollouts},
          adapter_opts
        )

      assert {:error, :invalid_rollout_checkpoint} =
               Registry.start_link(name: unique_name(), storage: storage)
    end
  end

  test "an eval report the store cannot hold is marked as such, never truncated" do
    registry = start_registry!()
    {:ok, entry} = Registry.deploying(attrs(), registry)

    oversized = %{results: List.duplicate(%{reason: String.duplicate("x", 1_000)}, 50)}

    assert {:ok, live} =
             Registry.mark(entry.artifact_id, :live, [eval_report: oversized], registry)

    assert %{eval_report: :too_large, bytes: bytes} = live.eval_report
    assert bytes > 32_768

    # A report holding something only this VM can interpret is not a report a durable
    # store may keep pretending to hold.
    assert {:ok, rolled_back} =
             Registry.mark(
               entry.artifact_id,
               :rolled_back,
               [eval_report: %{owner: self()}],
               registry
             )

    assert %{eval_report: :unportable, rendered: rendered} = rolled_back.eval_report
    assert is_binary(rendered)

    # Marking again without a report keeps the one that justified the previous mark
    # rather than quietly erasing the evidence.
    assert {:ok, quarantined} = Registry.mark(entry.artifact_id, :quarantined, [], registry)
    assert quarantined.eval_report == rolled_back.eval_report
  end

  test "survives its own restart with the rollouts it recorded" do
    directory = temporary_directory!()
    storage = {Ouroboros.Storage.DurableFile, path: directory}
    name = unique_name()

    {:ok, first} = Registry.start_link(name: name, storage: storage)
    {:ok, entry} = Registry.deploying(attrs(), name)
    {:ok, _live} = Registry.mark(entry.artifact_id, :live, [], name)
    GenServer.stop(first)

    {:ok, second} = Registry.start_link(name: name, storage: storage)
    assert {:ok, restored} = Registry.get(entry.artifact_id, name)
    assert restored.state == :live
    assert restored.module == @module
    GenServer.stop(second)
  end

  test "ambiguity is never recorded as a rollback" do
    proven =
      deployment(%{
        a@host: %NodeReceipt{node: :a@host, recovery: :rolled_back},
        b@host: %NodeReceipt{node: :b@host, recovery: :aborted}
      })

    assert {:rolled_back, detail} = Rollout.settled_state(proven)
    assert detail.nodes == %{a@host: :rolled_back, b@host: :aborted}

    # One node that never proved anything outranks every node that did.
    ambiguous =
      deployment(%{
        a@host: %NodeReceipt{node: :a@host, recovery: :rolled_back},
        b@host: %NodeReceipt{node: :b@host, recovery: :quarantined}
      })

    assert {:quarantined, _detail} = Rollout.settled_state(%{ambiguous | recovery: :quarantined})

    # Even with every node reporting a proven recovery, a deployment whose own recovery
    # is not complete is not a proven rollback.
    assert {:quarantined, _detail} = Rollout.settled_state(%{proven | recovery: :incomplete})
    assert {:quarantined, _detail} = Rollout.settled_state(%{proven | recovery: :quarantined})

    # A recovery state this build does not recognize is treated as ambiguity, not as
    # success: an unknown answer is not a proof.
    unknown =
      deployment(%{a@host: %NodeReceipt{node: :a@host, recovery: :something_new_and_unclear}})

    assert {:quarantined, _detail} = Rollout.settled_state(unknown)
  end

  defp deployment(node_receipts) do
    %DeploymentReceipt{
      id: "deployment-#{System.unique_integer([:positive])}",
      artifact_id: "artifact-#{System.unique_integer([:positive])}",
      epoch: 1,
      nodes: Map.keys(node_receipts),
      node_receipts: node_receipts,
      outcome: :health_failed,
      recovery: :complete,
      started_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }
  end

  # A fully-formed entry built the way the registry itself builds one, so a checkpoint
  # test is about the checkpoint rather than about hand-written struct literals.
  defp entry!(artifact_id \\ nil) do
    registry = start_registry!()
    {:ok, entry} = Registry.deploying(attrs(artifact_id), registry)
    entry
  end

  defp attrs(artifact_id \\ nil, overrides \\ []) do
    %{
      artifact_id: artifact_id || "artifact-#{System.unique_integer([:positive])}",
      module: @module,
      epoch: System.unique_integer([:positive, :monotonic]),
      nodes: [node()],
      source_sha256: String.duplicate("a", 64),
      test_report: %{total: 1, failures: 0}
    }
    |> Map.merge(Map.new(overrides))
  end

  # A lane-W rollout: a binary module name under the one accepted prefix, and a component
  # sha, which is what makes this register apply its epoch watermark to it at all.
  defp wasm_attrs(overrides) do
    %{
      artifact_id: "wasm-artifact-#{System.unique_integer([:positive])}",
      module: "wasm/greeter",
      epoch: 1,
      nodes: [node()],
      component_sha256: String.duplicate("c", 64)
    }
    |> Map.merge(Map.new(overrides))
  end

  defp start_registry!(opts \\ []) do
    name = unique_name()

    storage =
      Keyword.get_lazy(opts, :storage, fn ->
        {Jido.Storage.ETS,
         table: String.to_atom("rollout_registry_#{System.unique_integer([:positive])}")}
      end)

    {:ok, pid} = Registry.start_link(name: name, storage: storage)
    # The registry is linked to the test process, so it can die between an
    # aliveness check and the stop; catching the exit is the only raceless form.
    on_exit(fn ->
      try do
        GenServer.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end)

    name
  end

  defp unique_name do
    String.to_atom("rollout_registry_server_#{System.unique_integer([:positive])}")
  end

  defp temporary_directory! do
    directory =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-rollout-registry-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end
end
