defmodule Ouroboros.Storage.CheckpointQuarantineTest do
  @moduledoc """
  A checkpoint this build cannot decode must not take the node down with it.

  `Ouroboros.Storage.DurableFile` decodes with `binary_to_term/2` in `[:safe]` mode, which
  refuses to *create* an atom. `Ouroboros.Control.Grants` and
  `Ouroboros.Agent.EffectLedger` both write plain terms — no `Ouroboros.Upgrade.Wire`
  boundary — and the removed BEAM forge lane put **runtime-minted capability module atoms**
  into both: a `:forge` grant's `constraints.modules`, and a `forge` ledger entry's
  `attempt.module` / `result.module`. Those names were never in this repo's source, so no
  build can intern them; every such file fails to decode on every VM, forever. Both stores
  are `:core` children under a `rest_for_one` root, so a `{:stop, _}` from either is a node
  that does not boot.

  The bytes below were written by a separate VM (`test/support/retired_atoms/README.md`),
  because an in-process reproduction cannot exist: a VM that once created the name can
  always read it back, and writing the name as a literal anywhere the suite compiles would
  intern it in this VM too. **Never write that name as an atom in this file.**
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Ouroboros.Agent.EffectLedger
  alias Ouroboros.Control.Grants
  alias Ouroboros.Storage.DurableFile

  @probe "Elixir.Ouroboros.Capability.ForgedGrantProbe"
  @fixtures "test/support/retired_atoms"

  setup do
    # The precondition the whole file rests on. If this ever fails, something in the suite
    # has interned the name and every assertion below is vacuous.
    refute interned?(@probe), "#{@probe} is interned in the test VM; the fixtures prove nothing"
    :ok
  end

  describe "Control.Grants" do
    test "a checkpoint holding a runtime-minted capability atom is quarantined and the authority boots empty" do
      directory = tmp_dir!()
      bytes = File.read!(Path.join(@fixtures, "grants_forge_capability_atom.checkpoint.term"))
      path = install!(directory, Grants.checkpoint_key(), bytes)

      # These bytes really are the hazard, on this VM, right now.
      assert {:error, :invalid_term} =
               DurableFile.get_checkpoint(Grants.checkpoint_key(), path: directory)

      name = unique_name("grants")

      log =
        capture_log(fn ->
          start_supervised!({Grants, name: name, storage: {DurableFile, path: directory}},
            id: name
          )
        end)

      # Deny-by-default, reached from the direction that narrows: the principal that held
      # the forge grant holds nothing, and neither does anybody else.
      assert Grants.list("agent-1", name) == []
      refute Grants.granted?("agent-1", :forge, %{module: "wasm/probe"}, name)
      refute Grants.granted?("agent-1", :start_agent, %{module: Ouroboros.Agent.Worker}, name)

      assert_quarantined!(directory, path, bytes, log, Grants.checkpoint_key())

      # A grant written now checkpoints over the absent file, and the quarantined bytes
      # are not disturbed by it.
      assert {:ok, _grant} = Grants.grant("agent-1", :forge, %{modules: ["wasm/probe"]}, name)
      assert Grants.granted?("agent-1", :forge, %{module: "wasm/probe"}, name)
      assert File.read!(quarantined!(directory)) == bytes

      refute interned?(@probe)
    end

    test "a checkpoint that is unreadable for any other reason still stops the authority" do
      directory = tmp_dir!()
      # A directory where the checkpoint belongs: `File.read/1` answers `:eisdir`, which
      # says nothing about whether this build could interpret the bytes.
      File.mkdir_p!(checkpoint_path(directory, Grants.checkpoint_key()))

      assert {:error, {{:grant_checkpoint_unreadable, :eisdir}, _spec}} =
               start_supervised(
                 {Grants, name: unique_name("grants"), storage: {DurableFile, path: directory}}
               )

      assert Path.wildcard(Path.join(directory, "checkpoints/*.quarantined-*")) == []
    end
  end

  describe "Agent.EffectLedger" do
    test "a checkpoint holding a runtime-minted capability atom is quarantined and the ledger starts a new history" do
      directory = tmp_dir!()

      bytes =
        File.read!(Path.join(@fixtures, "effect_ledger_forge_capability_atom.checkpoint.term"))

      path = install!(directory, EffectLedger.checkpoint_key(), bytes)

      assert {:error, :invalid_term} =
               DurableFile.get_checkpoint(EffectLedger.checkpoint_key(), path: directory)

      name = unique_name("effect_ledger")

      log =
        capture_log(fn ->
          start_supervised!(
            {EffectLedger, name: name, storage: {DurableFile, path: directory}},
            id: name
          )
        end)

      assert {:ok, []} = EffectLedger.list([], name)

      assert %{retained: 0, in_flight: 0, durability: :synced_checkpoint} =
               EffectLedger.status(name)

      assert_quarantined!(directory, path, bytes, log, EffectLedger.checkpoint_key())

      # The new history is a whole history: sequence 1 again, and `ledger.export`'s chain is
      # computed over the entries of one answer from a published seed rather than continued
      # from a stored head, so it is a complete chain over what this node holds and claims
      # nothing about what it does not.
      assert {:ok, entry, :created} =
               EffectLedger.record_started(
                 %{
                   id: "effect-after-quarantine",
                   effect: :forge,
                   principal: "agent-1",
                   attempt: %{module: "wasm/probe"},
                   authority: %{decision: :granted, reason: :granted},
                   cause: %{}
                 },
                 name
               )

      assert entry.sequence == 1
      assert entry.started_sequence == 1
      assert File.read!(quarantined!(directory)) == bytes

      refute interned?(@probe)
    end

    test "a checkpoint that is unreadable for any other reason still stops the ledger" do
      directory = tmp_dir!()
      File.mkdir_p!(checkpoint_path(directory, EffectLedger.checkpoint_key()))

      assert {:error, {{:effect_ledger_checkpoint_unreadable, :eisdir}, _spec}} =
               start_supervised(
                 {EffectLedger,
                  name: unique_name("effect_ledger"), storage: {DurableFile, path: directory}}
               )

      assert Path.wildcard(Path.join(directory, "checkpoints/*.quarantined-*")) == []
    end
  end

  describe "DurableFile.get_checkpoint_or_quarantine/2" do
    test "a readable checkpoint is returned and nothing moves" do
      directory = tmp_dir!()
      key = {:ouroboros, :quarantine_probe, 1}
      :ok = DurableFile.put_checkpoint(key, %{version: 1, fine: true}, path: directory)

      assert {:ok, %{version: 1, fine: true}} =
               DurableFile.get_checkpoint_or_quarantine(key, path: directory)

      assert Path.wildcard(Path.join(directory, "checkpoints/*.quarantined-*")) == []
    end

    test "an absent checkpoint is absent, not quarantined" do
      directory = tmp_dir!()

      assert :not_found =
               DurableFile.get_checkpoint_or_quarantine({:ouroboros, :quarantine_probe, 1},
                 path: directory
               )

      assert Path.wildcard(Path.join(directory, "checkpoints/*.quarantined-*")) == []
    end

    test "bytes that are not a term at all are quarantined too" do
      directory = tmp_dir!()
      key = {:ouroboros, :quarantine_probe, 1}
      bytes = "this was never a term"
      path = install!(directory, key, bytes)

      log =
        capture_log(fn ->
          assert :not_found = DurableFile.get_checkpoint_or_quarantine(key, path: directory)
        end)

      assert_quarantined!(directory, path, bytes, log, key)
    end
  end

  defp assert_quarantined!(directory, path, bytes, log, key) do
    # Moved aside, not rewritten and not removed.
    refute File.exists?(path)
    quarantined = quarantined!(directory)
    assert File.read!(quarantined) == bytes
    assert byte_size(File.read!(quarantined)) == byte_size(bytes)

    # `.term` is kept so the file stays inside `Audit.Content.inventory/2`'s glob.
    assert Path.extname(quarantined) == ".term"
    assert Path.basename(quarantined) =~ ~r/\.quarantined-\d+(-[A-Za-z0-9_-]+)?\.term$/

    # Exactly one error line, and it names the file and the reason.
    lines = log |> String.split("\n") |> Enum.filter(&(&1 =~ "quarantining it at"))
    assert length(lines) == 1
    [line] = lines
    assert line =~ "[error]"
    assert line =~ path
    assert line =~ quarantined
    assert line =~ ":invalid_term"
    assert line =~ inspect(key)
  end

  defp quarantined!(directory) do
    assert [quarantined] = Path.wildcard(Path.join(directory, "checkpoints/*.quarantined-*"))
    quarantined
  end

  # The path `DurableFile` computes for a key, reproduced here so a fixture can be dropped
  # exactly where the store will look for it.
  defp checkpoint_path(directory, key) do
    hash =
      :sha256
      |> :crypto.hash(:erlang.term_to_binary(key))
      |> Base.url_encode64(padding: false)

    Path.join([Path.expand(directory), "checkpoints", hash <> ".term"])
  end

  defp install!(directory, key, bytes) do
    path = checkpoint_path(directory, key)
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, bytes)
    path
  end

  # Asked with a binary on purpose: naming the atom would create it and destroy the only
  # condition these tests are about.
  defp interned?(name) do
    _atom = String.to_existing_atom(name)
    true
  rescue
    ArgumentError -> false
  end

  defp unique_name(prefix),
    do: String.to_atom("#{prefix}_quarantine_#{System.unique_integer([:positive, :monotonic])}")

  defp tmp_dir! do
    directory =
      Path.join(
        System.tmp_dir!(),
        "ouroboros-quarantine-#{System.unique_integer([:positive, :monotonic])}"
      )

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf(directory) end)
    directory
  end
end
