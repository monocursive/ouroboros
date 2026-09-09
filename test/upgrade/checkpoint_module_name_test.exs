defmodule Ouroboros.Upgrade.CheckpointModuleNameTest do
  @moduledoc """
  What a capability's name looks like on disk, and who can read it back.

  Production storage is `Ouroboros.Storage.DurableFile`, which decodes with
  `binary_to_term/2` in `[:safe]` mode. A name that is an atom in the VM that wrote a
  checkpoint and nowhere else cannot be decoded by the VM that has to read it after a
  restart — the store reports corruption for a name it has simply never heard of, and a
  registry or signer that refuses to boot takes the node with it. The register and the
  signing journal both still hold such names: a rollout the removed BEAM lane recorded
  (docs/proposals/core.md §4 A1) names a module atom, and reading one back must stay a
  fact rather than a corruption report.

  In-process tests cannot catch this: unloading code does not remove its name from the
  atom table, so this VM can always read back a name it once created. The peer test below
  is the only one that reproduces the condition, on a node that has never interned the
  name at all.
  """

  use ExUnit.Case, async: false

  alias Ouroboros.Storage.DurableFile
  alias Ouroboros.Upgrade.Rollout.Registry
  alias Ouroboros.Upgrade.Signing.{Journal, Service}
  alias Ouroboros.Upgrade.Wire

  @probe "Elixir.Ouroboros.Capability.RestartProbe"
  @signer_id "checkpoint-probe-key"

  describe "in process" do
    test "a rollout checkpoint stores the module name as a binary and resolves it back" do
      module = forged_module!()
      directory = tmp_dir!()
      storage = {DurableFile, path: directory}
      name = unique_name()

      {:ok, first} = Registry.start_link(name: name, storage: storage)

      {:ok, entry} =
        Registry.deploying(
          %{artifact_id: "rollout-probe", module: module, epoch: 1, nodes: [node()]},
          name
        )

      assert entry.module == module
      GenServer.stop(first)

      assert {:ok, wire} =
               DurableFile.get_checkpoint(Registry.checkpoint_key(), path: directory)

      assert [%{module: @probe}] = Map.values(Wire.load(wire).rollouts)

      # This VM still knows the name, so it comes back as the module it names, and
      # `history/2` finds it by either form.
      {:ok, second} = Registry.start_link(name: name, storage: storage)
      assert {:ok, restored} = Registry.get("rollout-probe", name)
      assert restored.module == module
      assert [%{artifact_id: "rollout-probe"}] = Registry.history(module, name)
      GenServer.stop(second)
    end

    test "a signing journal stores the module name as a binary and resolves it back" do
      module = forged_module!()
      directory = tmp_dir!()
      storage = {DurableFile, path: directory}

      write_signing_journal!(storage, module)

      assert {:ok, wire} =
               DurableFile.get_checkpoint(Service.checkpoint_key(), path: directory)

      # The file itself carries the name as a binary. This VM still knows it, so
      # `from_wire/1` resolves the atom the journal was written with.
      assert dumped_signing_module(wire) == @probe
      assert %Journal{decisions: [%{modules: [%{module: ^module}]}]} = Journal.from_wire(wire)

      service = start_signer!(storage)
      assert {:ok, [%{modules: [%{module: ^module}]}]} = Service.decisions(service)
    end
  end

  @tag timeout: 180_000
  test "a peer that never interned the name still loads every checkpoint" do
    # Named before anything is written, so the node names inside these checkpoints are
    # names the peer will know.
    ensure_distributed!()

    module = forged_module!()
    directory = tmp_dir!()
    storage = {DurableFile, path: directory}

    write_rollout!(storage, module)
    write_signing_journal!(storage, module)

    peer = start_peer!()

    # The condition this whole boundary exists for. Everything below runs on a VM where
    # the name is a string and nothing more — including the owning journal modules, which
    # used to have to be loaded before `[:safe]` decode would even accept the file.
    refute peer_knows?(peer, @probe)

    assert {:ok, rollout_wire} =
             :erpc.call(peer, DurableFile, :get_checkpoint, [
               Registry.checkpoint_key(),
               [path: directory]
             ])

    assert is_map(rollout_wire)
    refute is_struct(rollout_wire)

    assert {:ok, signing_wire} =
             :erpc.call(peer, DurableFile, :get_checkpoint, [
               Service.checkpoint_key(),
               [path: directory]
             ])

    assert is_map(signing_wire)
    refute is_struct(signing_wire)

    # Starting the owners loads their modules and resolves the dumped term. The forged
    # name stays a binary: there is no compiled `#{@probe}` on this peer's code path.
    assert {:ok, registry} =
             :erpc.call(peer, GenServer, :start, [
               Registry,
               [storage: storage],
               [name: :checkpoint_probe_registry]
             ])

    assert [%{module: @probe, epoch: 1}] =
             :erpc.call(peer, Registry, :list, [:checkpoint_probe_registry])

    assert :ok = :erpc.call(peer, GenServer, :stop, [registry])

    assert {:ok, signer} =
             :erpc.call(peer, GenServer, :start, [
               Service,
               [key_path: write_key!(), signer_id: @signer_id, storage: storage],
               [name: :checkpoint_probe_signer]
             ])

    assert {:ok, [%{artifact_id: "signing-probe", modules: [%{module: @probe}]}]} =
             :erpc.call(peer, Service, :decisions, [:checkpoint_probe_signer])

    assert :ok = :erpc.call(peer, GenServer, :stop, [signer])

    # Reading the checkpoints resolved nothing into the peer's atom table, which is the
    # other half of the promise: an unresolvable name is carried, not interned.
    refute peer_knows?(peer, @probe)
  end

  defp write_rollout!(storage, module) do
    name = unique_name()
    {:ok, registry} = Registry.start_link(name: name, storage: storage)

    {:ok, _entry} =
      Registry.deploying(
        %{artifact_id: "rollout-probe", module: module, epoch: 1, nodes: [node()]},
        name
      )

    GenServer.stop(registry)
  end

  # Recorded through the journal itself rather than by asking the service to refuse an
  # artifact. A refusal reason names atoms the policy module owns, and whether those are
  # interned is a question about how the reading VM loaded its own code — a real question,
  # but a different one from the forged name this test is about, and one that would
  # otherwise be the thing that failed here.
  defp write_signing_journal!({adapter, adapter_opts}, module) do
    journal =
      Journal.record(Journal.new(), %{
        artifact_id: "signing-probe",
        epoch: 1,
        modules: [%{module: module, disposition: :introduce, sha256: String.duplicate("a", 64)}],
        requester: node(),
        signer_id: @signer_id,
        decision: :issued
      })

    :ok = adapter.put_checkpoint(Service.checkpoint_key(), Journal.to_wire(journal), adapter_opts)
  end

  # A name created at runtime, in this VM only — the shape a checkpoint the removed BEAM
  # lane wrote carries.
  defp forged_module! do
    module = String.to_atom(@probe)
    on_exit(fn -> unload(module) end)
    unload(module)
    module
  end

  defp start_signer!(storage) do
    start_supervised!(
      {Service, name: nil, key_path: write_key!(), signer_id: @signer_id, storage: storage},
      id: {Service, System.unique_integer([:positive])}
    )
  end

  defp write_key!(seed \\ :crypto.strong_rand_bytes(32)) do
    path = Path.join(tmp_dir!(), "signer-#{System.unique_integer([:positive])}.key")
    File.write!(path, seed)
    File.chmod!(path, 0o600)
    path
  end

  defp ensure_distributed! do
    unless Node.alive?() do
      root = String.to_atom("ouroboros_checkpoint_root_#{System.unique_integer([:positive])}")
      {:ok, _pid} = :net_kernel.start([root, :shortnames])
    end

    :ok
  end

  defp start_peer! do
    ensure_distributed!()
    name = String.to_atom("ouro-checkpoint-#{System.unique_integer([:positive])}")

    {:ok, peer, peer_node} =
      :peer.start(%{
        name: name,
        args: Enum.flat_map(:code.get_path(), &[~c"-pa", &1]),
        wait_boot: 60_000
      })

    on_exit(fn ->
      try do
        :peer.stop(peer)
      catch
        _kind, _reason -> :ok
      end
    end)

    peer_node
  end

  defp dumped_signing_module(wire) do
    decisions = wire["decisions"] || wire[:decisions] || []

    case decisions do
      [%{"modules" => [%{"module" => name} | _]} | _] -> name
      [%{modules: [%{module: name} | _]} | _] -> name
      _missing -> nil
    end
  end

  # Asked with a binary on purpose: sending the atom would intern it on the peer and
  # destroy the only condition this test is about.
  defp peer_knows?(peer, name) do
    :erpc.call(peer, String, :to_existing_atom, [name])
    true
  rescue
    _error -> false
  catch
    _kind, _reason -> false
  end

  defp unload(module) do
    :code.delete(module)
    :code.soft_purge(module)
    :ok
  end

  defp unique_name do
    String.to_atom("checkpoint_module_name_#{System.unique_integer([:positive])}")
  end

  defp tmp_dir! do
    directory =
      Path.join(System.tmp_dir!(), "ouroboros-checkpoint-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end
end
