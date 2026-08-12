defmodule Ouroboros.Upgrade.NodeExecutorTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.{Artifact, NodeExecutor, Verifier}

  defmodule UnrelatedServer do
    @moduledoc false
    use GenServer

    def start_link(_opts), do: GenServer.start_link(__MODULE__, :ok)

    @impl true
    def init(:ok), do: {:ok, %{}}
  end

  defmodule ControlledStorage do
    @moduledoc false
    @behaviour Jido.Storage

    @impl true
    def get_checkpoint(_key, opts) do
      Agent.get(Keyword.fetch!(opts, :controller), fn state ->
        case state.get_result do
          :checkpoint ->
            if is_nil(state.checkpoint), do: :not_found, else: {:ok, state.checkpoint}

          result ->
            result
        end
      end)
    end

    @impl true
    def put_checkpoint(_key, checkpoint, opts) do
      Agent.get_and_update(Keyword.fetch!(opts, :controller), fn state ->
        case state.put_results do
          [result | rest] ->
            next = %{state | put_results: rest}
            {result, if(result == :ok, do: %{next | checkpoint: checkpoint}, else: next)}

          [] ->
            {:ok, %{state | checkpoint: checkpoint}}
        end
      end)
    end

    @impl true
    def delete_checkpoint(_key, _opts), do: :ok

    @impl true
    def load_thread(_thread_id, _opts), do: {:error, :unsupported}

    @impl true
    def append_thread(_thread_id, _entries, _opts), do: {:error, :unsupported}

    @impl true
    def delete_thread(_thread_id, _opts), do: {:error, :unsupported}
  end

  setup do
    # Each successful rollback removes the retained version, but a failed assertion
    # should not poison later tests with a third-version load.
    on_exit(fn ->
      :code.soft_purge(UpgradeCounter)
      :code.load_file(UpgradeCounter)
      :code.soft_purge(UpgradeCounter)
    end)

    :ok
  end

  test "hot-upgrades state in place and rolls code and state back" do
    {:ok, pid} = start_supervised({UpgradeCounter, 7})
    assert UpgradeCounter.value(pid) == {1, 7}
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary,
                  old_binary: old_binary, stateful: true, migration_extra: %{}}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact, migrations: [{UpgradeCounter, pid, %{}}])

    assert {:ok, receipt} = NodeExecutor.commit(token)
    assert Process.alive?(pid)
    assert UpgradeCounter.version() == 2
    assert UpgradeCounter.value(pid) == {2, 14}

    assert :ok = NodeExecutor.rollback(receipt)
    assert Process.alive?(pid)
    assert UpgradeCounter.version() == 1
    assert UpgradeCounter.value(pid) == {1, 7}
  end

  test "rejects tampering and refuses to patch the upgrade authority" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    [beam] = artifact.modules
    tampered = %{artifact | modules: [%{beam | sha256: String.duplicate("0", 64)}]}

    assert {:error, {:module_verification_failed, UpgradeCounter}} =
             Verifier.verify(tampered, allow_unsigned: true)

    executor_binary = object_code!(NodeExecutor)

    assert {:ok, forbidden} =
             Artifact.build(
               [{NodeExecutor, executor_binary, old_binary: executor_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:immutable_control_module, NodeExecutor}} =
             Verifier.verify(forbidden, allow_unsigned: true)
  end

  test "requires trusted signatures under the production trust policy" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    signed = Artifact.sign(artifact, "test-signer", private_key)

    assert :ok = Verifier.verify(signed, trusted_signers: %{"test-signer" => public_key})
    assert {:error, {:untrusted_signer, "test-signer"}} = Verifier.verify(signed, [])
    assert {:error, :signature_required} = Verifier.verify(artifact, [])
  end

  test "malformed signature policies and public requests fail without crashing the executor" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    malformed = %{artifact | signature: %{signer: "broken", value: <<1, 2, 3>>}}
    executor = Process.whereis(NodeExecutor)

    assert {:error, {:invalid_signature, "broken"}} =
             Verifier.verify(malformed, trusted_signers: %{"broken" => <<1>>})

    assert {:error, :invalid_trusted_signers} =
             Verifier.verify(malformed, trusted_signers: :invalid)

    assert {:error, :invalid_options} = NodeExecutor.prepare(artifact, %{timeout: 1})
    assert {:error, :invalid_commit, :unchanged} = NodeExecutor.commit(:not_a_token)
    assert {:error, :invalid_receipt, :unchanged} = NodeExecutor.rollback(%{})
    assert {:error, :invalid_receipt} = NodeExecutor.promote(%{})
    assert Process.whereis(NodeExecutor) == executor
    assert Process.alive?(executor)
  end

  test "rejects non-boolean stateful declarations and migrations for stateless modules" do
    {:ok, pid} = start_supervised({UpgradeCounter, 4})
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:error, {:invalid_stateful, :yes}} =
             Artifact.build([
               {UpgradeCounter, new_binary, old_binary: old_binary, stateful: :yes}
             ])

    assert {:ok, stateless} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:migration_for_stateless_module, [UpgradeCounter]}} =
             NodeExecutor.prepare(stateless, migrations: [{UpgradeCounter, pid}])
  end

  test "binds each migration to its real OTP callback module and portable extra data" do
    {:ok, counter} = start_supervised({UpgradeCounter, 4})
    {:ok, unrelated} = start_supervised(UnrelatedServer)
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary,
                  old_binary: old_binary, stateful: true, migration_extra: %{operation: :double}}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:migration_target_module_mismatch, UpgradeCounter, actual_callback_module}} =
             NodeExecutor.prepare(artifact, migrations: [{UpgradeCounter, unrelated}])

    assert actual_callback_module == UnrelatedServer

    assert {:error, {:invalid_migration_extra, UpgradeCounter}} =
             NodeExecutor.prepare(artifact, migrations: [{UpgradeCounter, counter, self()}])

    assert {:error, {:migration_extra_mismatch, UpgradeCounter}} =
             NodeExecutor.prepare(artifact, migrations: [{UpgradeCounter, counter, %{}}])

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               migrations: [{UpgradeCounter, counter, %{operation: :double}}]
             )

    assert :ok = NodeExecutor.abort(token)
  end

  test "requires complete stateful migrations and cannot commit prepared epochs backwards" do
    {:ok, pid} = start_supervised({UpgradeCounter, 3})
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    base_epoch = System.unique_integer([:positive, :monotonic])

    assert {:ok, older} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: base_epoch
             )

    assert {:error, {:missing_stateful_migrations, [UpgradeCounter]}} =
             NodeExecutor.prepare(older)

    assert {:error, {:duplicate_migration_pid, ^pid}} =
             NodeExecutor.prepare(older,
               migrations: [{UpgradeCounter, pid}, {UpgradeCounter, pid}]
             )

    assert {:ok, older_token} =
             NodeExecutor.prepare(older, migrations: [{UpgradeCounter, pid}])

    assert {:ok, newer} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: base_epoch + 1
             )

    assert {:error, {:upgrade_in_progress, [%{artifact_id: artifact_id, epoch: ^base_epoch}]}} =
             NodeExecutor.prepare(newer, migrations: [{UpgradeCounter, pid}])

    assert artifact_id == older.id
    assert :ok = NodeExecutor.abort(older_token)

    assert {:ok, newer_token} = NodeExecutor.prepare(newer, migrations: [{UpgradeCounter, pid}])

    assert {:ok, receipt} = NodeExecutor.commit(newer_token)

    assert {:error, {:stale_epoch, ^base_epoch, committed_epoch}} =
             NodeExecutor.prepare(older, migrations: [{UpgradeCounter, pid}])

    assert committed_epoch == base_epoch + 1
    assert UpgradeCounter.version() == 2
    assert :ok = NodeExecutor.rollback(receipt)

    assert %{last_epoch: ^committed_epoch} = NodeExecutor.status()
  end

  test "restart preserves a committed epoch and receipt, rejects stale work, and rolls back" do
    {:ok, counter} = start_supervised({UpgradeCounter, 9})
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    epoch = System.unique_integer([:positive, :monotonic])
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: epoch
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)
    assert UpgradeCounter.value(counter) == {2, 18}

    executor = restart_isolated_executor!(server, executor, storage)

    assert %{mode: :ready, last_epoch: ^epoch, rollback_receipts: [retained]} =
             NodeExecutor.status(server: server)

    assert retained.artifact_id == artifact.id
    refute Map.has_key?(retained, :id)
    assert {:ok, ^receipt} = NodeExecutor.receipt(receipt.id, server: server)
    assert :not_found = NodeExecutor.receipt("missing", server: server)

    assert {:ok, ^receipt} = NodeExecutor.commit(token, server: server)

    assert {:error, {:stale_epoch, ^epoch, ^epoch}} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert UpgradeCounter.value(counter) == {1, 9}

    assert {:error, {:commit_already_finalized, :rolled_back}, :unchanged} =
             NodeExecutor.commit(token, server: server)

    assert %{mode: :ready, last_epoch: ^epoch, rollback_receipts: []} =
             NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "a prepared opaque loader reservation is journaled as lost across restart" do
    {:ok, counter} = start_supervised({UpgradeCounter, 2})
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    executor = restart_isolated_executor!(server, executor, storage)
    status = NodeExecutor.status(server: server)

    assert status.mode == :ready
    assert status.prepared == []
    assert Enum.any?(status.operations, &(&1.outcome == :lost_on_restart))
    refute inspect(status) =~ token
    assert {:error, :unknown_token, :unchanged} = NodeExecutor.commit(token, server: server)
    assert :ok = NodeExecutor.abort(token, server: server)

    stop_isolated_executor(executor)
  end

  test "historical aborted and lost reservations remain valid after a newer commit" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    base_epoch = System.unique_integer([:positive, :monotonic])

    artifact = fn epoch ->
      {:ok, value} =
        Artifact.build(
          [{UpgradeCounter, new_binary, old_binary: old_binary}],
          epoch: epoch
        )

      value
    end

    assert {:ok, aborted_token} =
             NodeExecutor.prepare(artifact.(base_epoch), server: server)

    assert :ok = NodeExecutor.abort(aborted_token, server: server)

    assert {:ok, _lost_token} =
             NodeExecutor.prepare(artifact.(base_epoch + 1), server: server)

    executor = restart_isolated_executor!(server, executor, storage)

    committed = artifact.(base_epoch + 2)
    assert {:ok, committed_token} = NodeExecutor.prepare(committed, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(committed_token, server: server)

    executor = restart_isolated_executor!(server, executor, storage)

    assert %{mode: :ready, last_epoch: last_epoch} = NodeExecutor.status(server: server)
    assert last_epoch == committed.epoch
    assert :ok = NodeExecutor.rollback(receipt, server: server)

    stop_isolated_executor(executor)
  end

  test "startup quarantines when loaded code no longer matches the durable journal" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    epoch = System.unique_integer([:positive, :monotonic])

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: epoch
             )

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, _receipt} = NodeExecutor.commit(token, server: server)
    assert UpgradeCounter.version() == 2

    stop_isolated_executor(executor)
    restore_v1!(old_binary)
    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{mode: :quarantined, quarantine_reason: reason, last_epoch: ^epoch} =
             NodeExecutor.status(server: server)

    assert match?({:startup_reconciliation, {:module_hash_mismatch, UpgradeCounter}}, reason)

    assert {:error, {:executor_quarantined, ^reason}} =
             NodeExecutor.prepare(artifact, server: server)

    assert {:error, {:executor_quarantined, ^reason}, :quarantined} =
             NodeExecutor.commit("not-a-real-token", server: server)

    stop_isolated_executor(executor)
  end

  test "malformed and unreadable checkpoints start inspectable but fail closed" do
    controller = start_storage_controller!(checkpoint: %{corrupt: true})
    storage = {ControlledStorage, controller: controller}
    {server, executor} = start_isolated_executor!(storage)

    assert %{mode: :quarantined, quarantine_reason: {:corrupt_checkpoint, :invalid_checkpoint}} =
             NodeExecutor.status(server: server)

    stop_isolated_executor(executor)

    Agent.update(controller, fn state ->
      %{state | checkpoint: nil, get_result: {:error, :permission_denied}}
    end)

    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{mode: :quarantined, quarantine_reason: {:journal_read_failed, _reason}} =
             NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "a well-shaped but internally inconsistent checkpoint is quarantined" do
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    journal = :sys.get_state(executor).journal
    stop_isolated_executor(executor)

    digest = String.duplicate("a", 64)

    inconsistent = %{
      journal
      | token_outcomes: %{
          digest => %{
            artifact_id: "forged",
            epoch: 1,
            outcome: :prepared,
            receipt_id: nil
          }
        }
    }

    {adapter, adapter_opts} = storage
    key = {:ouroboros, :upgrade_node_executor, 1, node()}
    assert :ok = adapter.put_checkpoint(key, inconsistent, adapter_opts)
    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:corrupt_checkpoint, :invalid_journal_relationships}
           } = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "a restart during a write-ahead commit is quarantined and names a code mismatch" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    state = :sys.get_state(executor)
    digest = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)
    reservation = Map.fetch!(state.journal.reservations, digest)

    intent = %{
      state.journal
      | last_epoch: artifact.epoch,
        reservations: %{},
        token_outcomes: %{
          digest => %{
            artifact_id: artifact.id,
            epoch: artifact.epoch,
            outcome: :committing,
            receipt_id: nil
          }
        },
        next_sequence: state.journal.next_sequence + 1,
        operations:
          state.journal.operations ++
            [
              %{
                sequence: state.journal.next_sequence,
                operation: :commit,
                outcome: :committing,
                artifact_id: artifact.id,
                epoch: artifact.epoch,
                occurred_at: DateTime.utc_now() |> DateTime.to_iso8601(),
                token_digest: digest,
                module_count: 1,
                migration_count: 0,
                modules: [%{module: UpgradeCounter, md5: hd(artifact.modules).md5}],
                artifact: artifact,
                migrations: []
              }
            ]
    }

    {adapter, adapter_opts} = storage
    key = {:ouroboros, :upgrade_node_executor, 1, node()}
    assert :ok = adapter.put_checkpoint(key, intent, adapter_opts)
    assert reservation.artifact_id == artifact.id

    executor = restart_isolated_executor!(server, executor, storage)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:startup_reconciliation, {:module_hash_mismatch, UpgradeCounter}}
           } = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  test "restart resumes a validated migration target stranded by an executor crash" do
    {:ok, counter} = start_supervised({UpgradeCounter, 5})
    old_binary = object_code!(UpgradeCounter)
    observer = String.to_atom("upgrade_crash_observer_#{System.unique_integer([:positive])}")
    Process.register(self(), observer)
    on_exit(fn -> if Process.whereis(observer) == self(), do: Process.unregister(observer) end)

    new_binary = compile_blocking_v2!(old_binary, observer)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary,
                  old_binary: old_binary,
                  stateful: true,
                  migration_extra: {:block_for_restart_test, observer}}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [
                 {UpgradeCounter, counter, {:block_for_restart_test, observer}}
               ]
             )

    caller = self()

    spawn(fn ->
      result =
        try do
          NodeExecutor.commit(token, server: server, process_timeout: 30_000)
        catch
          :exit, reason -> {:exit, reason}
        end

      send(caller, {:crashed_commit_result, result})
    end)

    assert_receive {:blocking_code_change_entered, ^counter}, 5_000
    Process.exit(executor, :kill)
    assert_receive {:crashed_commit_result, {:exit, _reason}}, 5_000

    send(counter, {:continue_blocking_code_change, counter})
    assert_receive {:blocking_code_change_returning, ^counter}, 5_000

    {^server, restarted} = start_isolated_executor!(storage, server)
    status = NodeExecutor.status(server: server)

    assert status.mode == :quarantined

    assert status.quarantine_reason ==
             {:startup_reconciliation, {:incomplete_operation, :commit}}

    assert restart_operation =
             Enum.find(status.operations, fn operation ->
               operation.operation == :restart and
                 operation.outcome == :pending_targets_resumed
             end)

    assert restart_operation.migration_count == 1
    refute Map.has_key?(restart_operation, :migrations)
    refute inspect(status) =~ inspect(counter)

    assert UpgradeCounter.value(counter) == {2, 5}
    stop_isolated_executor(restarted)
  end

  test "restart never resumes a live PID whose callback identity mismatches the WAL binding" do
    {:ok, counter} = start_supervised({UpgradeCounter, 3})
    {:ok, unrelated} = start_supervised(UnrelatedServer)
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    state = :sys.get_state(executor)
    digest = :crypto.hash(:sha256, token) |> Base.encode16(case: :lower)

    intent = %{
      state.journal
      | last_epoch: artifact.epoch,
        reservations: %{},
        token_outcomes: %{
          digest => %{
            artifact_id: artifact.id,
            epoch: artifact.epoch,
            outcome: :committing,
            receipt_id: nil
          }
        },
        next_sequence: state.journal.next_sequence + 1,
        operations:
          state.journal.operations ++
            [
              %{
                sequence: state.journal.next_sequence,
                operation: :commit,
                outcome: :committing,
                artifact_id: artifact.id,
                epoch: artifact.epoch,
                occurred_at: DateTime.utc_now() |> DateTime.to_iso8601(),
                token_digest: digest,
                module_count: 1,
                migration_count: 1,
                modules: [%{module: UpgradeCounter, md5: hd(artifact.modules).md5}],
                artifact: artifact,
                migrations: [
                  %NodeExecutor.Migration{module: UpgradeCounter, pid: unrelated}
                ]
              }
            ]
    }

    {adapter, adapter_opts} = storage
    key = {:ouroboros, :upgrade_node_executor, 1, node()}
    assert :ok = adapter.put_checkpoint(key, intent, adapter_opts)
    assert :ok = :sys.suspend(unrelated)
    on_exit(fn -> if Process.alive?(unrelated), do: :sys.resume(unrelated) end)

    executor = restart_isolated_executor!(server, executor, storage)
    status = NodeExecutor.status(server: server)

    assert status.quarantine_reason ==
             {:startup_reconciliation, {:pending_target_module_mismatch, UpgradeCounter}}

    assert Enum.any?(status.operations, fn operation ->
             operation.operation == :restart and
               operation.outcome == :pending_target_resume_failed
           end)

    assert {:status, ^unrelated, {:module, :gen_server}, [_dictionary, :suspended | _rest]} =
             :sys.get_status(unrelated, 1_000)

    assert :ok = :sys.resume(unrelated)
    stop_isolated_executor(executor)
  end

  test "commit journal failure compensates code and state before quarantining" do
    {:ok, counter} = start_supervised({UpgradeCounter, 7})
    {controller, storage, server, executor} = start_controlled_executor!()
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    epoch = System.unique_integer([:positive, :monotonic])

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: epoch
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    fail_next_write_then_allow_quarantine(controller)

    assert {:error, {:journal_persist_failed, :storage_unavailable, :commit_compensated},
            :rolled_back} = NodeExecutor.commit(token, server: server)

    assert UpgradeCounter.version() == 1
    assert UpgradeCounter.value(counter) == {1, 7}

    assert %{mode: :quarantined, last_epoch: ^epoch, rollback_receipts: []} =
             NodeExecutor.status(server: server)

    assert_persisted_quarantine(controller)
    stop_isolated_executor(executor)
    assert storage == {ControlledStorage, controller: controller}
  end

  test "prepare does not issue a bearer token when its journal write fails" do
    controller = start_storage_controller!()
    storage = {ControlledStorage, controller: controller}
    {server, executor} = start_isolated_executor!(storage)
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    Agent.update(controller, &%{&1 | put_results: [{:error, :disk_full}]})

    assert {:error, {:journal_persist_failed, :storage_unavailable}} =
             NodeExecutor.prepare(artifact, server: server)

    assert UpgradeCounter.version() == 1
    assert NodeExecutor.status(server: server).prepared == []
    assert Agent.get(controller, & &1.checkpoint) == nil
    stop_isolated_executor(executor)
  end

  test "an isolated executor normalizes its storage from application configuration" do
    controller = start_storage_controller!()
    configured = {ControlledStorage, controller: controller}
    previous = Application.get_env(:ouroboros, :upgrade_storage)
    Application.put_env(:ouroboros, :upgrade_storage, configured)

    on_exit(fn ->
      if is_nil(previous) do
        Application.delete_env(:ouroboros, :upgrade_storage)
      else
        Application.put_env(:ouroboros, :upgrade_storage, previous)
      end
    end)

    server = String.to_atom("upgrade_executor_#{System.unique_integer([:positive])}")

    assert {:ok, executor} =
             NodeExecutor.start_link(name: server, trust_policy: [allow_unsigned: true])

    Process.unlink(executor)
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert is_binary(token)
    assert Agent.get(controller, & &1.checkpoint).reservations != %{}
    assert :ok = NodeExecutor.abort(token, server: server)
    stop_isolated_executor(executor)
  end

  test "rollback journal failure reports reconciliation required and persists quarantine" do
    {:ok, counter} = start_supervised({UpgradeCounter, 8})
    {controller, _storage, server, executor} = start_controlled_executor!()
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary, stateful: true}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, counter}]
             )

    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)
    fail_next_write_then_allow_quarantine(controller)

    assert {:error, {:journal_persist_failed, :storage_unavailable, :reconciliation_required},
            :quarantined} = NodeExecutor.rollback(receipt, server: server)

    assert UpgradeCounter.version() == 1
    assert UpgradeCounter.value(counter) == {1, 8}
    assert %{mode: :quarantined, rollback_receipts: []} = NodeExecutor.status(server: server)
    assert_persisted_quarantine(controller)
    stop_isolated_executor(executor)
  end

  test "promote journal failure never reports success after purging the retired version" do
    {controller, _storage, server, executor} = start_controlled_executor!()
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)
    fail_next_write_then_allow_quarantine(controller)

    assert {:error, {:journal_persist_failed, :storage_unavailable, :reconciliation_required}} =
             NodeExecutor.promote(receipt, server: server)

    assert UpgradeCounter.version() == 2
    assert %{mode: :quarantined, rollback_receipts: []} = NodeExecutor.status(server: server)
    assert_persisted_quarantine(controller)
    stop_isolated_executor(executor)
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
    [{UpgradeCounter, binary}] = Code.compile_string(source, "upgrade_counter_v2.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Code.compile_string/2 necessarily loads its result. Restore the v1 test fixture
    # so Artifact.build/2 can prove its declared base matches the running code.
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} =
             :code.load_binary(UpgradeCounter, ~c"upgrade_counter_v1.beam", old_binary)

    assert :code.soft_purge(UpgradeCounter)
    binary
  end

  defp compile_blocking_v2!(old_binary, observer) do
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
      def code_change(1, state, {:block_for_restart_test, #{inspect(observer)}}) do
        send(Process.whereis(#{inspect(observer)}), {:blocking_code_change_entered, self()})

        receive do
          {:continue_blocking_code_change, pid} when pid == self() ->
            send(Process.whereis(#{inspect(observer)}), {:blocking_code_change_returning, self()})
            {:ok, %{state | schema_vsn: 2}}
        end
      end

      def code_change({:down, 2}, state, _extra) do
        {:ok, %{state | schema_vsn: 1}}
      end
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)

    [{UpgradeCounter, binary}] =
      Code.compile_string(source, "upgrade_counter_blocking_v2.ex")

    Code.put_compiler_option(:ignore_module_conflict, previous)
    restore_v1!(old_binary)
    binary
  end

  defp unique_ets_storage do
    table = String.to_atom("upgrade_journal_#{System.unique_integer([:positive])}")
    {Jido.Storage.ETS, table: table}
  end

  defp start_isolated_executor!(storage, server \\ nil) do
    server = server || String.to_atom("upgrade_executor_#{System.unique_integer([:positive])}")

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

  defp restore_v1!(old_binary) do
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} =
             :code.load_binary(UpgradeCounter, ~c"upgrade_counter_v1.beam", old_binary)

    assert :code.soft_purge(UpgradeCounter)
    :ok
  end

  defp start_storage_controller!(overrides \\ []) do
    initial =
      Map.merge(
        %{checkpoint: nil, get_result: :checkpoint, put_results: []},
        Map.new(overrides)
      )

    start_supervised!({Agent, fn -> initial end},
      id: {:storage_controller, System.unique_integer([:positive])}
    )
  end

  defp start_controlled_executor! do
    controller = start_storage_controller!()
    storage = {ControlledStorage, controller: controller}
    {server, executor} = start_isolated_executor!(storage)
    {controller, storage, server, executor}
  end

  defp fail_next_write_then_allow_quarantine(controller) do
    Agent.update(controller, &%{&1 | put_results: [:ok, {:error, :disk_full}, :ok]})
  end

  defp assert_persisted_quarantine(controller) do
    assert Agent.get(controller, & &1.checkpoint).mode == :quarantined
  end
end
