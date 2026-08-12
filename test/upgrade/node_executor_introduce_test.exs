defmodule Ouroboros.Upgrade.NodeExecutorIntroduceTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.{Artifact, NodeExecutor}

  setup do
    on_exit(fn ->
      :code.soft_purge(UpgradeCounter)
      :code.load_file(UpgradeCounter)
      :code.soft_purge(UpgradeCounter)
    end)

    :ok
  end

  test "introduces a module that never existed and unloads it on rollback" do
    module = Ouroboros.Capability.Introduced
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    base_epoch = System.unique_integer([:positive, :monotonic])

    stale = introduce_artifact!(module, binary, base_epoch)
    artifact = introduce_artifact!(module, binary, base_epoch + 1)

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    assert apply(module, :hello, []) == :world
    assert :code.which(module) == ~c"ouroboros://#{module}"

    status = NodeExecutor.status(server: server)
    assert status.mode == :ready
    assert status.last_epoch == base_epoch + 1
    assert [%{modules: [^module]}] = status.rollback_receipts

    # Epoch monotonicity is decided before the artifact is even inspected, so an
    # introduction cannot be replayed behind a newer transition.
    assert {:error, {:stale_epoch, ^base_epoch, epoch}} =
             NodeExecutor.prepare(stale, server: server)

    assert epoch == base_epoch + 1

    # Committed, the name is taken: a second introduction of the same module is now a
    # replacement wearing the wrong label.
    repeat = introduce_artifact!(module, binary, base_epoch + 2)

    assert {:error, {:module_already_present, ^module}} =
             NodeExecutor.prepare(repeat, server: server)

    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert_absent(module)
    assert NodeExecutor.status(server: server).rollback_receipts == []

    stop_isolated_executor(executor)
  end

  test "commits one artifact that both replaces a module and introduces another" do
    module = Ouroboros.Capability.MixedTransition
    capability_binary = compile_capability!(module)
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    {:ok, counter} = start_supervised({UpgradeCounter, 6})

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary, old_binary: old_binary, stateful: true},
                 {module, capability_binary, disposition: :introduce}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)
    assert UpgradeCounter.version() == 2
    assert UpgradeCounter.value(counter) == {2, 12}
    assert apply(module, :hello, []) == :world

    # One rollback, two inverses: the replacement goes back to its preimage and the
    # introduction goes away entirely.
    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert UpgradeCounter.version() == 1
    assert UpgradeCounter.value(counter) == {1, 6}
    assert_absent(module)

    executor = restart_isolated_executor!(server, executor, storage)
    assert %{mode: :ready} = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "rollback reports code still in use instead of killing the process running it" do
    module = Ouroboros.Capability.InUseIntroduction
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    observer = register_observer!()

    artifact = introduce_artifact!(module, binary)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    blocker = spawn(fn -> apply(module, :block, [observer]) end)
    assert_receive {:blocked, ^blocker}, 5_000

    assert {:error, {:rollback_failed, {:ok, {:error, {:introduced_code_in_use, ^module}}, :ok}},
            :quarantined} = NodeExecutor.rollback(receipt, server: server)

    assert Process.alive?(blocker)

    status = NodeExecutor.status(server: server)
    assert status.mode == :quarantined
    assert status.quarantine_reason == {:rollback_failed, :reconciliation_required}

    assert Enum.any?(status.operations, fn operation ->
             operation.operation == :rollback and operation.outcome == :failed and
               operation.reason == :rollback_failed
           end)

    # The journal still expects the committed module, and the module is now retired but
    # not reclaimed, so quarantine cannot be cleared on the strength of a failed unload.
    assert {:error, {:reconciliation_failed, {:module_unavailable, ^module}}} =
             NodeExecutor.reconcile_quarantine(server: server)

    send(blocker, :release)
    wait_until_dead!(blocker)

    # Nothing was destroyed: once the process leaves the code, the unload completes.
    assert :code.soft_purge(module)
    assert_absent(module)

    stop_isolated_executor(executor)
  end

  test "rollback of an introduction already unloaded out of band still reaches absence" do
    module = Ouroboros.Capability.AlreadyUnloaded
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    artifact = introduce_artifact!(module, binary)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    unload_capability(module)
    assert_absent(module)

    # Rollback wants the module gone, and it is gone. Reporting failure here would
    # quarantine a node whose end state is exactly the intended one; an unload done
    # behind this executor is caught by startup reconciliation instead.
    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert_absent(module)

    executor = restart_isolated_executor!(server, executor, storage)
    assert %{mode: :ready, rollback_receipts: []} = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "promote succeeds although an introduction has no retired version to purge" do
    module = Ouroboros.Capability.PromotedIntroduction
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    artifact = introduce_artifact!(module, binary)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    assert :ok = NodeExecutor.promote(receipt, server: server)
    assert apply(module, :hello, []) == :world

    status = NodeExecutor.status(server: server)
    assert status.mode == :ready
    assert status.rollback_receipts == []

    assert Enum.any?(
             status.operations,
             &(&1.operation == :promote and &1.outcome == :promoted)
           )

    assert {:error, :unknown_receipt, :unchanged} = NodeExecutor.rollback(receipt, server: server)

    stop_isolated_executor(executor)
    unload_capability(module)
  end

  test "restart reconciles a committed introduction and a rolled-back one" do
    module = Ouroboros.Capability.RestartedIntroduction
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    epoch = System.unique_integer([:positive, :monotonic])

    artifact = introduce_artifact!(module, binary, epoch)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    executor = restart_isolated_executor!(server, executor, storage)

    assert %{mode: :ready, last_epoch: ^epoch, rollback_receipts: [_retained]} =
             NodeExecutor.status(server: server)

    assert {:ok, ^receipt} = NodeExecutor.receipt(receipt.id, server: server)
    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert_absent(module)

    # After the rollback the correct expectation is absence, and a restart that fails
    # closed on a correct system would be a bug in exactly the same way as one that
    # accepts a wrong system.
    executor = restart_isolated_executor!(server, executor, storage)
    assert %{mode: :ready, last_epoch: ^epoch} = NodeExecutor.status(server: server)

    # Absence is a checked expectation, not a missing one: put the name back behind the
    # executor and the next restart refuses to come up ready.
    assert {:module, ^module} = :code.load_binary(module, ~c"capability_resurrected.beam", binary)
    executor = restart_isolated_executor!(server, executor, storage)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:startup_reconciliation, {:module_unexpectedly_present, ^module}}
           } = NodeExecutor.status(server: server)

    unload_capability(module)
    assert :ok = NodeExecutor.reconcile_quarantine(server: server)
    assert %{mode: :ready} = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "a restart during a write-ahead rollback reads absence as the expected identity" do
    module = Ouroboros.Capability.InterruptedRollback
    binary = compile_capability!(module)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    artifact = introduce_artifact!(module, binary)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    journal = :sys.get_state(executor).journal

    # The record `rollback/2` writes before it touches code. Its module identities are
    # what this node should be holding once the rollback finishes, which for an
    # introduction is nothing at all.
    intent = %{
      journal
      | next_sequence: journal.next_sequence + 1,
        operations:
          journal.operations ++
            [
              %{
                sequence: journal.next_sequence,
                operation: :rollback,
                outcome: :rolling_back,
                artifact_id: artifact.id,
                epoch: artifact.epoch,
                occurred_at: DateTime.utc_now() |> DateTime.to_iso8601(),
                receipt_id: receipt.id,
                migration_count: 0,
                modules: [%{module: module, md5: :non_existing}]
              }
            ]
    }

    {adapter, adapter_opts} = storage
    key = {:ouroboros, :upgrade_node_executor, node()}
    assert :ok = adapter.put_checkpoint(key, intent, adapter_opts)

    # The rollback never ran, so the module is still loaded where the record says it
    # should be gone. A well-formed record read as garbage would have said
    # `:corrupt_checkpoint` instead.
    executor = restart_isolated_executor!(server, executor, storage)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:startup_reconciliation, {:module_unexpectedly_present, ^module}}
           } = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
    unload_capability(module)

    # Absence now matches the record, which leaves only the interrupted operation itself
    # as the reason this node cannot come up ready.
    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:startup_reconciliation, {:incomplete_operation, :rollback}}
           } = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "a journal written by an older executor version is quarantined, not coerced" do
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    journal = :sys.get_state(executor).journal
    assert journal.version == 2
    stop_isolated_executor(executor)

    {adapter, adapter_opts} = storage
    key = {:ouroboros, :upgrade_node_executor, node()}
    assert :ok = adapter.put_checkpoint(key, %{journal | version: 1}, adapter_opts)

    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{mode: :quarantined, quarantine_reason: {:corrupt_checkpoint, :unsupported_version}} =
             NodeExecutor.status(server: server)

    # Fail closed and keep the evidence: an executor that cannot read a journal must not
    # overwrite it with one it can.
    assert {:ok, %{version: 1}} = adapter.get_checkpoint(key, adapter_opts)

    stop_isolated_executor(executor)
  end

  defp introduce_artifact!(module, binary, epoch \\ nil) do
    assert {:ok, artifact} =
             Artifact.build([{module, binary, disposition: :introduce}],
               epoch: epoch || System.unique_integer([:positive, :monotonic])
             )

    artifact
  end

  defp compile_capability!(module) do
    source = """
    defmodule #{inspect(module)} do
      @vsn 1

      def hello, do: :world

      def block(observer) do
        send(Process.whereis(observer), {:blocked, self()})

        receive do
          :release -> :ok
        end
      end
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{^module, binary}] = Code.compile_string(source, "capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads the result. The lane may only ever be handed a name the VM has
    # never heard of, so prove that before the binary reaches it.
    unload_capability(module)
    on_exit(fn -> unload_capability(module) end)
    binary
  end

  defp unload_capability(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp assert_absent(module) do
    assert :code.which(module) == :non_existing
    assert :code.get_object_code(module) == :error
    refute :erlang.function_exported(module, :hello, 0)
    :ok
  end

  defp register_observer! do
    name = String.to_atom("upgrade_introduce_observer_#{System.unique_integer([:positive])}")
    Process.register(self(), name)
    on_exit(fn -> if Process.whereis(name) == self(), do: Process.unregister(name) end)
    name
  end

  defp wait_until_dead!(pid) do
    reference = Process.monitor(pid)
    assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, 5_000
    :ok
  end

  defp object_code!(module) do
    {^module, binary, _filename} = :code.get_object_code(module)
    binary
  end

  defp compile_v2!(old_binary) do
    source = """
    defmodule Ouroboros.Test.UpgradeCounter do
      @vsn 2
      use GenServer

      def start_link(initial), do: GenServer.start_link(__MODULE__, initial)
      def value(pid), do: GenServer.call(pid, :value)
      def version, do: 2

      @impl true
      def init(initial), do: {:ok, %{schema_vsn: 2, count: initial}}

      @impl true
      def handle_call(:value, _from, state), do: {:reply, {state.schema_vsn, state.count}, state}

      @impl true
      def code_change(1, state, _extra) do
        {:ok, %{state | schema_vsn: 2, count: state.count * 2}}
      end

      def code_change({:down, 2}, state, _extra) do
        {:ok, %{state | schema_vsn: 1, count: div(state.count, 2)}}
      end
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{UpgradeCounter, binary}] = Code.compile_string(source, "upgrade_counter_introduce_v2.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads. Put the declared base back so the replacement half of a mixed
    # artifact proves its preimage is the code this node is running.
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} =
             :code.load_binary(UpgradeCounter, ~c"upgrade_counter_v1.beam", old_binary)

    assert :code.soft_purge(UpgradeCounter)
    binary
  end

  defp unique_ets_storage do
    table = String.to_atom("upgrade_introduce_journal_#{System.unique_integer([:positive])}")
    {Jido.Storage.ETS, table: table}
  end

  defp start_isolated_executor!(storage, server \\ nil) do
    server =
      server || String.to_atom("upgrade_introduce_executor_#{System.unique_integer([:positive])}")

    assert {:ok, executor} =
             NodeExecutor.start_link(
               name: server,
               storage: storage,
               trust_policy: [allow_unsigned: true]
             )

    Process.unlink(executor)
    {server, executor}
  end

  defp restart_isolated_executor!(server, executor, storage) do
    stop_isolated_executor(executor)
    {^server, executor} = start_isolated_executor!(storage, server)
    executor
  end

  defp stop_isolated_executor(executor) do
    if Process.alive?(executor), do: GenServer.stop(executor)
    :ok
  end
end
