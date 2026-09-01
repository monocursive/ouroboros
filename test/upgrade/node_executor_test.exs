defmodule Ouroboros.Upgrade.NodeExecutorTest do
  use ExUnit.Case, async: false

  alias Ouroboros.Test.UpgradeCounter
  alias Ouroboros.Upgrade.{Artifact, Beam, NodeExecutor, Verifier, Wire}

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

  test "refuses to patch any module that enforces this lane's guarantees" do
    # Protecting only the loader leaves the enforcement path open: one patch against the
    # journal writer makes every durable write a silent no-op, one against the release
    # authorizer unlocks the durable lane, and the control plane decides what is patched
    # at all. The forge and deploy entry points are protected for the symmetric reason —
    # a signed replacement of the surfaces that *trigger* the lane is as good as forging
    # it, so they are held to the same refusal as the surfaces that gate it.
    for module <- [
          NodeExecutor,
          Verifier,
          Ouroboros.Storage.DurableFile,
          Ouroboros.Release.Authorizer.Deny,
          Ouroboros.Release.Journal,
          Ouroboros.Control.Store,
          Ouroboros.Agent.Effects,
          Ouroboros.Agent.Effects.Runner,
          Ouroboros.Orchestration.ForgeExecutor,
          Ouroboros.Runtime.Capabilities,
          Ouroboros.Mesh,
          Ouroboros.Mesh.Directory,
          Ouroboros.Provider.Native,
          Ouroboros.Provider.Native.Paths,
          Ouroboros.Provider.Native.Tools.SafeWrite,
          Ouroboros.Workspace,
          Ouroboros.Workspace.Path,
          Ouroboros.Application,
          Ouroboros.Application.RegistryOwner
        ] do
      binary = object_code!(module)

      assert {:ok, artifact} =
               Artifact.build(
                 [{module, binary, old_binary: binary}],
                 epoch: System.unique_integer([:positive, :monotonic])
               )

      assert {:error, {:immutable_control_module, ^module}} =
               Verifier.verify(artifact, allow_unsigned: true)
    end
  end

  test "refuses to patch the operator surface, whether it exists on this node or not" do
    # The gateway decides which connections may drive this lane at all. An auth check that
    # can be hot-patched is no auth at all, so the namespace is protected the same way the
    # modules behind it are — including names this VM has never loaded, which is what a
    # patch aimed at a node that has the gateway running would look like from here.
    module = Ouroboros.Gateway.Sneak
    binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    assert {:ok, introduction} = introduce_artifact!(module, binary)

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(introduction, allow_unsigned: true)

    # And once such a module is loaded, the replacement path refuses it on the same check,
    # before anything about the binary is inspected.
    assert {:module, ^module} = :code.load_binary(module, ~c"gateway_sneak.beam", binary)

    assert {:ok, replacement} =
             Artifact.build(
               [{module, binary, old_binary: binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(replacement, allow_unsigned: true)
  end

  test "refuses to patch native containment and workspace admission, loaded or not" do
    module = Ouroboros.Provider.Native.Sneak
    binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    assert {:ok, introduction} = introduce_artifact!(module, binary)

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(introduction, allow_unsigned: true)

    assert {:module, ^module} = :code.load_binary(module, ~c"native_sneak.beam", binary)

    assert {:ok, replacement} =
             Artifact.build(
               [{module, binary, old_binary: binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(replacement, allow_unsigned: true)
  end

  test "refuses to patch the WebAssembly container, loaded or not" do
    # `Ouroboros.Wasm.` is the machinery that contains lane-W capabilities: the helper pool
    # that owns the wasmtime process, the store that decides which bytes a sha names, and the
    # wrapper agent a component answers messages inside. The container must not be
    # hot-patchable by the thing it contains (docs/WASM.md D10) — and the namespace is
    # protected here even though `Ouroboros.Mesh` will now *start* an agent in it, which is
    # the order those two lines have to land in.
    module = Ouroboros.Wasm.Sneak
    binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    assert {:ok, introduction} = introduce_artifact!(module, binary)

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(introduction, allow_unsigned: true)

    assert {:module, ^module} = :code.load_binary(module, ~c"wasm_sneak.beam", binary)

    assert {:ok, replacement} =
             Artifact.build(
               [{module, binary, old_binary: binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:error, {:immutable_control_module, ^module}} =
             Verifier.verify(replacement, allow_unsigned: true)

    # And the modules that are actually there, not only a name shaped like one.
    for shipped <- [Ouroboros.Wasm.Capability, Ouroboros.Wasm.Pool, Ouroboros.Wasm.Store] do
      shipped_binary = object_code!(shipped)

      assert {:ok, artifact} =
               Artifact.build(
                 [{shipped, shipped_binary, old_binary: shipped_binary}],
                 epoch: System.unique_integer([:positive, :monotonic])
               )

      assert {:error, {:immutable_control_module, ^shipped}} =
               Verifier.verify(artifact, allow_unsigned: true)
    end
  end

  test "rejects on-load code in the new binary and in the rollback preimage" do
    probe = Ouroboros.Test.OnLoadProbe
    plain_binary = compile_probe!(probe, "")
    on_load_binary = compile_probe!(probe, "@on_load :__probe_init__")

    on_exit(fn ->
      :code.soft_purge(probe)
      :code.delete(probe)
      :code.soft_purge(probe)
    end)

    # The old attribute lookup could only ever answer "no": `-on_load` is a Code-chunk
    # construct and never reaches the attributes chunk.
    assert {:ok, {^probe, [attributes: attributes]}} =
             :beam_lib.chunks(on_load_binary, [:attributes])

    refute Keyword.has_key?(attributes, :on_load)

    assert {:ok, %{on_load?: true}} = Beam.inspect_binary(on_load_binary)
    assert {:ok, %{on_load?: false}} = Beam.inspect_binary(plain_binary)

    assert {:error, {:forbidden_beam_feature, ^probe, :on_load}} =
             Beam.build(probe, on_load_binary, old_binary: plain_binary)

    # Rollback loads the preimage with `:code.load_binary/3`, which would run its
    # on-load function, so the preimage is not exempt.
    assert {:error, {:forbidden_beam_feature, ^probe, :on_load}} =
             Beam.build(probe, plain_binary, old_binary: on_load_binary)

    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    smuggled = %{artifact | modules: [on_load_beam(probe, on_load_binary)]}

    assert {:error, {:forbidden_beam_feature, ^probe}} =
             Verifier.verify(smuggled, allow_unsigned: true)
  end

  test "introduces only absent modules, and only under the capability namespace" do
    module = Ouroboros.Capability.AlreadyPresent
    binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    assert {:ok, artifact} = introduce_artifact!(module, binary)
    assert :ok = Verifier.verify(artifact, allow_unsigned: true)

    # The same artifact, once the name is taken. An introduction that would quietly
    # become a replacement is the failure this gate exists to prevent.
    assert {:module, ^module} = :code.load_binary(module, ~c"capability_present.beam", binary)

    assert {:error, {:module_already_present, ^module}} =
             Verifier.verify(artifact, allow_unsigned: true)

    unload_capability(module)
    assert :ok = Verifier.verify(artifact, allow_unsigned: true)

    # A module absent from the module table but reachable on the code path is present as
    # far as this lane cares: the next `Code.ensure_loaded/1` would resurrect it.
    directory = publish_beam!(module, binary)
    assert :code.which(module) != :non_existing
    refute :code.get_object_code(module) == :error

    assert {:error, {:module_already_present, ^module}} =
             Verifier.verify(artifact, allow_unsigned: true)

    assert true = :code.del_path(directory)
    assert :ok = Verifier.verify(artifact, allow_unsigned: true)

    outsider = Ouroboros.Test.IntroducedOutsideNamespace
    outsider_binary = compile_capability!(outsider)
    assert {:ok, unnamespaced} = introduce_artifact!(outsider, outsider_binary)

    assert {:error, {:capability_namespace_required, ^outsider}} =
             Verifier.verify(unnamespaced, allow_unsigned: true)

    # The protected set outranks the namespace rule: a forged control module is refused
    # as a control module, not as a badly named capability.
    forged = Ouroboros.Upgrade.ForgedLoader
    forged_binary = compile_capability!(forged)
    assert {:ok, control} = introduce_artifact!(forged, forged_binary)

    assert {:error, {:immutable_control_module, ^forged}} =
             Verifier.verify(control, allow_unsigned: true)
  end

  test "introduced binaries are held to every new-binary gate and to the trust policy" do
    module = Ouroboros.Capability.OnLoadIntroduction
    plain_binary = compile_capability!(module)
    on_load_binary = compile_capability!(module, "@on_load :__probe_init__")
    on_exit(fn -> unload_capability(module) end)

    assert {:error, {:forbidden_beam_feature, ^module, :on_load}} =
             Beam.introduce(module, on_load_binary)

    assert {:ok, artifact} = introduce_artifact!(module, plain_binary)
    smuggled = %{artifact | modules: [%{hd(artifact.modules) | binary: on_load_binary}]}

    assert {:error, {:module_verification_failed, ^module}} =
             Verifier.verify(smuggled, allow_unsigned: true)

    forged = %{
      artifact
      | modules: [introduced_beam(module, on_load_binary)]
    }

    assert {:error, {:forbidden_beam_feature, ^module}} =
             Verifier.verify(forged, allow_unsigned: true)

    # Loading a module that never existed is not a lesser act than replacing one, so it
    # is not exempt from the signature policy either.
    assert {:error, :signature_required} = Verifier.verify(artifact, [])

    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    signed = Artifact.sign(artifact, "test-signer", private_key)
    assert :ok = Verifier.verify(signed, trusted_signers: %{"test-signer" => public_key})

    # The disposition is inside the signed manifest, so a signature covers how each
    # module is loaded and not only its bytes.
    assert %{modules: [%{disposition: :introduce}]} = Artifact.manifest(artifact)
  end

  test "verifies an artifact that both replaces and introduces modules" do
    module = Ouroboros.Capability.MixedIntroduction
    capability_binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)

    assert {:ok, mixed} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary, old_binary: old_binary},
                 {module, capability_binary, disposition: :introduce}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert :ok = Verifier.verify(mixed, allow_unsigned: true)

    # A stale base in the replacement half still fails the whole artifact.
    [replacement, introduction] = mixed.modules
    tampered = %{mixed | modules: [%{replacement | old_sha256: String.duplicate("0", 64)}]}

    assert {:error, {:module_verification_failed, UpgradeCounter}} =
             Verifier.verify(tampered, allow_unsigned: true)

    assert introduction.disposition == :introduce
    assert introduction.old_binary == nil
  end

  test "an introduction declares no state to migrate and carries no preimage" do
    module = Ouroboros.Capability.StatelessIntroduction
    binary = compile_capability!(module)
    on_exit(fn -> unload_capability(module) end)

    assert {:error, :stateful_introduction} = Beam.introduce(module, binary, stateful: true)

    assert {:error, :migration_extra_for_introduced_module} =
             Beam.introduce(module, binary, migration_extra: %{})

    assert {:error, :preimage_for_introduced_module} =
             Beam.introduce(module, binary, old_binary: binary)

    assert {:error, {:invalid_disposition, ^module, :replace_maybe}} =
             Artifact.build([{module, binary, disposition: :replace_maybe}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, beam} = Beam.introduce(module, binary)
    assert beam.disposition == :introduce
    assert beam.stateful == false

    assert [beam.old_filename, beam.old_binary, beam.old_sha256, beam.old_md5, beam.old_vsn] ==
             [nil, nil, nil, nil, nil]

    # A hand-forged struct claiming to be an introduction while carrying a preimage is
    # refused rather than silently treated as one or the other.
    assert {:ok, artifact} = introduce_artifact!(module, binary)

    contradictory = %{
      artifact
      | modules: [%{hd(artifact.modules) | old_binary: binary, old_sha256: Beam.sha256(binary)}]
    }

    assert {:error, {:invalid_introduction, ^module}} =
             Verifier.verify(contradictory, allow_unsigned: true)
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

    assert {:error, {:journal_unloaded, {:corrupt_checkpoint, :invalid_checkpoint}}} =
             NodeExecutor.reconcile_quarantine(server: server)

    stop_isolated_executor(executor)

    Agent.update(controller, fn state ->
      %{state | checkpoint: nil, get_result: {:error, :permission_denied}}
    end)

    {^server, executor} = start_isolated_executor!(storage, server)

    assert %{mode: :quarantined, quarantine_reason: {:journal_read_failed, _reason}} =
             NodeExecutor.status(server: server)

    assert {:error, {:journal_unloaded, {:journal_read_failed, _reason}}} =
             NodeExecutor.reconcile_quarantine(server: server)

    stop_isolated_executor(executor)
  end

  test "an unreadable checkpoint is never reconciled away nor overwritten" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    controller = start_storage_controller!()
    storage = {ControlledStorage, controller: controller}
    {server, executor} = start_isolated_executor!(storage)
    epoch = System.unique_integer([:positive, :monotonic])

    assert {:ok, artifact} =
             Artifact.build([{UpgradeCounter, new_binary, old_binary: old_binary}], epoch: epoch)

    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    committed = stored_checkpoint(controller)
    assert committed.last_epoch == epoch
    assert Map.has_key?(committed.receipts, receipt.id)

    stop_isolated_executor(executor)
    Agent.update(controller, &%{&1 | get_result: {:error, :permission_denied}})
    {^server, executor} = start_isolated_executor!(storage, server)

    # The placeholder journal this executor came up on satisfies every reconciliation
    # check vacuously, so reconciliation has to refuse on the read failure itself.
    assert %{mode: :quarantined, last_epoch: 0, rollback_receipts: []} =
             NodeExecutor.status(server: server)

    assert {:error, {:journal_unloaded, {:journal_read_failed, _reason}}} =
             NodeExecutor.reconcile_quarantine(server: server)

    preserved = stored_checkpoint(controller)
    assert preserved.last_epoch == epoch
    assert Map.has_key?(preserved.receipts, receipt.id)

    stop_isolated_executor(executor)
    Agent.update(controller, &%{&1 | get_result: :checkpoint})
    {^server, executor} = start_isolated_executor!(storage, server)

    # The replay defence survived, because the record it reads did.
    assert %{mode: :ready, last_epoch: ^epoch} = NodeExecutor.status(server: server)

    assert {:error, {:stale_epoch, ^epoch, ^epoch}} =
             NodeExecutor.prepare(artifact, server: server)

    stop_isolated_executor(executor)
  end

  test "the journal keeps one expectation per module however often it is patched" do
    old_binary = object_code!(UpgradeCounter)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    for _round <- 1..3 do
      new_binary = compile_v2!(old_binary)

      assert {:ok, artifact} =
               Artifact.build([{UpgradeCounter, new_binary, old_binary: old_binary}],
                 epoch: System.unique_integer([:positive, :monotonic])
               )

      assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
      assert {:ok, receipt} = NodeExecutor.commit(token, server: server)
      assert :ok = NodeExecutor.rollback(receipt, server: server)
    end

    # Expectations are keyed by module and replaced, not appended: the map is bounded by
    # how many distinct modules this node has patched, not by how often.
    journal = :sys.get_state(executor).journal
    assert Map.keys(journal.expected_modules) == [UpgradeCounter]
    assert journal.receipts == %{}

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
    key = {:ouroboros, :upgrade_node_executor, node()}
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
    key = {:ouroboros, :upgrade_node_executor, node()}
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
    key = {:ouroboros, :upgrade_node_executor, node()}
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
    assert stored_checkpoint(controller).reservations != %{}
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

  test "a failed resume compensates first and keeps rollback material journaled" do
    observer = String.to_atom("upgrade_resume_observer_#{System.unique_integer([:positive])}")
    Process.register(self(), observer)
    on_exit(fn -> if Process.whereis(observer) == self(), do: Process.unregister(observer) end)

    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_blocking_v2!(old_binary, observer)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    extra = {:block_for_restart_test, observer}

    # Unsupervised targets: one is killed on purpose and must stay dead so the commit
    # discovers the loss where the executor resumes, not where it migrates.
    {:ok, first} = GenServer.start(UpgradeCounter, 3)
    {:ok, second} = GenServer.start(UpgradeCounter, 5)
    on_exit(fn -> Enum.each([first, second], &stop_if_alive/1) end)

    assert {:ok, artifact} =
             Artifact.build(
               [
                 {UpgradeCounter, new_binary,
                  old_binary: old_binary, stateful: true, migration_extra: extra}
               ],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    assert {:ok, token} =
             NodeExecutor.prepare(artifact,
               server: server,
               migrations: [{UpgradeCounter, first, extra}, {UpgradeCounter, second, extra}]
             )

    caller = self()

    spawn(fn ->
      result = NodeExecutor.commit(token, server: server, process_timeout: 30_000)
      send(caller, {:commit_result, result})
    end)

    assert_receive {:blocking_code_change_entered, ^first}, 5_000
    send(first, {:continue_blocking_code_change, first})
    assert_receive {:blocking_code_change_returning, ^first}, 5_000
    assert_receive {:blocking_code_change_entered, ^second}, 5_000
    Process.exit(first, :kill)
    send(second, {:continue_blocking_code_change, second})
    assert_receive {:blocking_code_change_returning, ^second}, 5_000

    assert_receive {:commit_result, {:error, {:resume_failed, _errors, _recovery}, :quarantined}},
                   15_000

    # Compensation still ran: the surviving target is downgraded and the node is back on
    # its preimage even though the transition failed.
    assert UpgradeCounter.version() == 1
    assert UpgradeCounter.value(second) == {1, 5}

    status = NodeExecutor.status(server: server)
    assert status.mode == :quarantined
    assert status.quarantine_reason == {:commit_recovery_failed, :rollback_material_retained}

    [old_md5] = Enum.map(artifact.modules, & &1.old_md5)
    failed = Enum.find(status.operations, &(&1.operation == :commit and &1.outcome == :failed))
    assert failed.modules == [%{module: UpgradeCounter, md5: old_md5}]
    refute Map.has_key?(failed, :artifact)
    refute Map.has_key?(failed, :migrations)

    # The write-ahead record was the only durable copy of the preimages. A failure that
    # left code mutated must not be the thing that deletes them.
    # Module names cross the checkpoint boundary as binaries, so the VM that reads this
    # record back does not have to have interned the name to decode it.
    retained = retained_commit_operation!(storage)

    assert [%{module: "Elixir.Ouroboros.Test.UpgradeCounter", old_binary: ^old_binary}] =
             retained.artifact.modules

    assert Enum.map(retained.migrations, & &1.pid) == [first, second]

    executor = restart_isolated_executor!(server, executor, storage)

    assert %{
             mode: :quarantined,
             quarantine_reason: {:commit_recovery_failed, :rollback_material_retained}
           } = NodeExecutor.status(server: server)

    assert %{artifact: %Artifact{}} = retained_commit_operation!(storage)
    stop_isolated_executor(executor)
  end

  test "a quarantined executor refuses rollback and promote until state matches again" do
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
    assert {:ok, receipt} = NodeExecutor.commit(token, server: server)

    stop_isolated_executor(executor)
    restore_v1!(old_binary)
    {^server, executor} = start_isolated_executor!(storage, server)

    reason = {:startup_reconciliation, {:module_hash_mismatch, UpgradeCounter}}
    assert %{mode: :quarantined, quarantine_reason: ^reason} = NodeExecutor.status(server: server)

    # Startup proved loaded code disagrees with the journal. Mutating it further, or
    # discarding its preimages through a promote, is exactly what must not be possible.
    assert {:error, {:executor_quarantined, ^reason}, :quarantined} =
             NodeExecutor.rollback(receipt, server: server)

    assert {:error, {:executor_quarantined, ^reason}} =
             NodeExecutor.promote(receipt, server: server)

    assert {:error, {:reconciliation_failed, {:module_hash_mismatch, UpgradeCounter}}} =
             NodeExecutor.reconcile_quarantine(server: server)

    assert %{mode: :quarantined} = NodeExecutor.status(server: server)

    load_binary!(new_binary, ~c"upgrade_counter_v2.beam")
    assert :ok = NodeExecutor.reconcile_quarantine(server: server)

    status = NodeExecutor.status(server: server)
    assert status.mode == :ready
    assert status.quarantine_reason == nil

    assert Enum.any?(
             status.operations,
             &(&1.operation == :quarantine and &1.outcome == :cleared)
           )

    assert {:error, :not_quarantined} = NodeExecutor.reconcile_quarantine(server: server)
    assert :ok = NodeExecutor.rollback(receipt, server: server)
    assert UpgradeCounter.version() == 1

    stop_isolated_executor(executor)
  end

  test "a reservation whose token was lost is inspectable and releasable by artifact" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)
    base_epoch = System.unique_integer([:positive, :monotonic])

    build = fn epoch ->
      assert {:ok, artifact} =
               Artifact.build(
                 [{UpgradeCounter, new_binary, old_binary: old_binary}],
                 epoch: epoch
               )

      artifact
    end

    artifact = build.(base_epoch)
    assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)

    artifact_id = artifact.id
    status = NodeExecutor.status(server: server)

    assert [%{artifact_id: ^artifact_id, epoch: ^base_epoch, prepared_at: prepared_at}] =
             status.prepared

    assert is_binary(prepared_at)
    refute inspect(status) =~ token

    # Without the lost token the node would answer this way forever.
    assert {:error,
            {:upgrade_in_progress, [%{artifact_id: ^artifact_id, prepared_at: ^prepared_at}]}} =
             NodeExecutor.prepare(build.(base_epoch + 1), server: server)

    assert {:error, {:unknown_reservation, "no-such-artifact"}} =
             NodeExecutor.abort_prepared_reservation("no-such-artifact", server: server)

    assert {:error, :invalid_artifact_id} = NodeExecutor.abort_prepared_reservation(:not_a_binary)
    assert :ok = NodeExecutor.abort_prepared_reservation(artifact_id, server: server)
    # A coordinator that never learned the first attempt's outcome may repeat it.
    assert :ok = NodeExecutor.abort_prepared_reservation(artifact_id, server: server)

    assert NodeExecutor.status(server: server).prepared == []
    assert {:error, :unknown_token, :unchanged} = NodeExecutor.commit(token, server: server)

    assert {:ok, later_token} = NodeExecutor.prepare(build.(base_epoch + 2), server: server)
    assert :ok = NodeExecutor.abort(later_token, server: server)

    stop_isolated_executor(executor)
  end

  test "the operations log is bounded without dropping pending or rollback evidence" do
    old_binary = object_code!(UpgradeCounter)
    new_binary = compile_v2!(old_binary)
    storage = unique_ets_storage()
    {server, executor} = start_isolated_executor!(storage)

    assert {:ok, artifact} =
             Artifact.build(
               [{UpgradeCounter, new_binary, old_binary: old_binary}],
               epoch: System.unique_integer([:positive, :monotonic])
             )

    for _attempt <- 1..60 do
      assert {:ok, token} = NodeExecutor.prepare(artifact, server: server)
      assert :ok = NodeExecutor.abort(token, server: server)
    end

    journal = :sys.get_state(executor).journal
    sequences = Enum.map(journal.operations, & &1.sequence)

    assert length(journal.operations) == 100
    assert journal.next_sequence == 121
    assert sequences == Enum.sort(sequences)
    assert sequences == Enum.uniq(sequences)
    assert List.first(sequences) == 21

    # A trimmed history is still a valid journal on the next restart.
    executor = restart_isolated_executor!(server, executor, storage)
    assert %{mode: :ready} = NodeExecutor.status(server: server)

    stop_isolated_executor(executor)
  end

  defp object_code!(module) do
    {^module, binary, _filename} = :code.get_object_code(module)
    binary
  end

  defp stop_if_alive(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
    :ok
  end

  defp retained_commit_operation!({adapter, adapter_opts}) do
    key = {:ouroboros, :upgrade_node_executor, node()}
    assert {:ok, wire} = adapter.get_checkpoint(key, adapter_opts)
    journal = Wire.load(wire)

    assert operation =
             Enum.find(
               journal.operations,
               &(&1.operation == :commit and &1.outcome == :failed)
             )

    operation
  end

  defp compile_probe!(module, attribute) do
    source = """
    defmodule #{inspect(module)} do
      #{attribute}
      def __probe_init__, do: :ok
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{^module, binary}] = Code.compile_string(source, "on_load_probe.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads, and the verifier rejects any module that still has retired code.
    assert :code.soft_purge(module)
    binary
  end

  defp introduce_artifact!(module, binary) do
    Artifact.build([{module, binary, disposition: :introduce}],
      epoch: System.unique_integer([:positive, :monotonic])
    )
  end

  defp compile_capability!(module, attribute \\ "") do
    source = """
    defmodule #{inspect(module)} do
      @vsn 1
      #{attribute}
      def __probe_init__, do: :ok
      def hello, do: :world
    end
    """

    previous = Code.get_compiler_option(:ignore_module_conflict)
    Code.put_compiler_option(:ignore_module_conflict, true)
    [{^module, binary}] = Code.compile_string(source, "capability.ex")
    Code.put_compiler_option(:ignore_module_conflict, previous)

    # Compiling loads. An introduction is only an introduction if the name is free, so
    # every fixture starts by proving the VM has never heard of it.
    unload_capability(module)
    binary
  end

  defp unload_capability(module) do
    :code.delete(module)
    :code.soft_purge(module)
    assert :code.which(module) == :non_existing
    assert :code.get_object_code(module) == :error
    :ok
  end

  defp publish_beam!(module, binary) do
    directory =
      Path.join(
        System.tmp_dir!(),
        "ouroboros_capability_path_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(directory)
    File.write!(Path.join(directory, "#{module}.beam"), binary)
    on_exit(fn -> File.rm_rf!(directory) end)
    charlist = String.to_charlist(directory)
    assert true = :code.add_patha(charlist)
    on_exit(fn -> :code.del_path(charlist) end)
    charlist
  end

  defp introduced_beam(module, binary) do
    assert {:ok, info} = Beam.inspect_binary(binary)

    %Beam{
      module: module,
      filename: ~c"capability.beam",
      binary: binary,
      sha256: Beam.sha256(binary),
      md5: info.md5,
      vsn: info.vsn,
      old_filename: nil,
      old_binary: nil,
      old_sha256: nil,
      old_md5: nil,
      old_vsn: nil,
      disposition: :introduce
    }
  end

  defp on_load_beam(module, binary) do
    assert {:ok, info} = Beam.inspect_binary(binary)

    %Beam{
      module: module,
      filename: ~c"on_load_probe.beam",
      binary: binary,
      sha256: Beam.sha256(binary),
      md5: info.md5,
      vsn: info.vsn,
      old_filename: ~c"on_load_probe.beam",
      old_binary: binary,
      old_sha256: Beam.sha256(binary),
      old_md5: info.md5,
      old_vsn: info.vsn
    }
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

  defp restore_v1!(old_binary), do: load_binary!(old_binary, ~c"upgrade_counter_v1.beam")

  defp load_binary!(binary, filename) do
    assert :code.soft_purge(UpgradeCounter)

    assert {:module, UpgradeCounter} = :code.load_binary(UpgradeCounter, filename, binary)

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
    assert stored_checkpoint(controller).mode == :quarantined
  end

  defp stored_checkpoint(controller) do
    controller
    |> Agent.get(& &1.checkpoint)
    |> Wire.load()
  end
end
