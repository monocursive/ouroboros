# Capture ONLY with pre-J3 BEAMs: elixir -pa '_build/test/lib/*/ebin' scripts/fixture/build_j3_fixture.exs
# Synthetic baseline; never regenerate this fixture with the replacement implementation.
alias Ouroboros.Storage.DurableFile
root = Path.expand("test/support/j3_fixture/data")
if File.exists?(root), do: raise("refusing to replace captured baseline")
Application.load(:ouroboros)
{:ok, _} = Application.ensure_all_started(:jido_signal)
DurableFile.ensure_build_loaded()
# Reviewed static name in the old synthetic grants; never mint names from stored bytes.
legacy_module = :"Elixir.Ouroboros.Capability.FixtureProbe"
IO.inspect(legacy_module, label: "synthetic source tag")
tmp = Path.join(System.tmp_dir!(), "j3-capture-#{System.unique_integer([:positive])}")
File.mkdir_p!(tmp)

:ok =
  :erl_tar.extract(~c"test/support/integration_fixture/fixture-datadir.tar.gz", [
    :compressed,
    {:cwd, String.to_charlist(tmp)}
  ])

File.mkdir_p!(root)

stores = [
  {"grants", {:ouroboros, :agent_grants, 1}},
  {"permissions", {:ouroboros, :control_permissions, 1}},
  {"policy-promotion", {:ouroboros, :policy_promotion, 1}},
  {"capabilities", {:ouroboros, :capability_rollouts, 1}},
  {"forge-epochs", {:ouroboros, :forge_epoch, 1}},
  {"signing-journal", Ouroboros.Upgrade.Signing.Service.checkpoint_key()}
]

for {leaf, key} <- stores do
  source = Path.join([tmp, "fixture-datadir", leaf])
  {:ok, value} = DurableFile.get_checkpoint(key, path: source)

  value =
    if leaf == "grants" do
      # The prior corpus deliberately exercises unknown runtime-minted names. This corpus
      # holds known names only; keep the original corpus's quarantine gate unchanged.
      update_in(value.grants, &Map.delete(&1, {"agent-fixture-capability", :forge}))
    else
      value
    end

  :ok = DurableFile.put_checkpoint(key, value, path: Path.join(root, leaf))
end

{:ok, signal} =
  Jido.Signal.new(
    "ouroboros.agent.message",
    %{
      from: "j3-sender",
      body: "Historical body",
      correlation_id: "j3-correlation",
      causation_id: "j3-cause"
    },
    source: "/j3-fixture",
    subject: "j3-recipient",
    id: "019930a0-0000-7000-8000-000000000003",
    time: "2026-09-10T00:00:00Z"
  )

errors = [
  Jido.Action.Error.validation_error("historical invalid input", %{field: :path}),
  Jido.Action.Error.execution_error("historical execution failure", %{reason: :timeout}),
  Jido.Action.Error.config_error("historical invalid config", %{}),
  Jido.Action.Error.timeout_error("historical timeout", %{timeout: 123}),
  Jido.Action.Error.internal_error("historical internal error", %{})
]

{:ok, artifact} =
  Ouroboros.Wasm.Artifact.build(
    <<0, "asm", 0x0D, 0x00, 0x01, 0x00, "j3-synthetic-component">>,
    name: "j3-history",
    epoch: 3,
    imports: [],
    metadata: %{
      author: "synthetic fixture",
      test_report: %{failures: 0, extra: %{signal: signal, error: hd(errors)}}
    }
  )

{public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)

signature =
  :crypto.sign(
    :eddsa,
    :none,
    Ouroboros.Wasm.Artifact.signing_payload(artifact, "j3-fixture-signer"),
    [private_key, :ed25519]
  )

artifact = %{artifact | signature: %{signer: "j3-fixture-signer", value: signature}}
{:ok, historical_agent} = Jido.Agent.new(id: "j3-old-agent", state: %{provider: :claude})

historical_instruction =
  Jido.Instruction.new!(%{
    id: "j3-old-instruction",
    action: Ouroboros.Provider.Native.Tools.Read,
    params: %{path: "/synthetic/j3"},
    context: %{},
    opts: []
  })

legacy = %{
  "signed_manifest" => artifact,
  "signed_manifest_wire" => Ouroboros.Upgrade.Wire.dump(artifact),
  "keyed_history" => %{
    historical_agent => "retired",
    Map.from_struct(historical_agent) => "plain"
  },
  "public_key" => public_key,
  signal: signal,
  errors: errors,
  agent: historical_agent,
  instruction: historical_instruction
}

key = {:ouroboros, :interactive_sessions, 1}
{:ok, index} = DurableFile.get_checkpoint(key, path: "test/support/j2_fixture/data/interactive")

for id <- index.ids do
  record_key = {key, :session, 2, id}

  {:ok, record} =
    DurableFile.get_checkpoint(record_key, path: "test/support/j2_fixture/data/interactive")

  record =
    update_in(record[id].events, fn [event] ->
      [%{event | payload: Map.put(event.payload, "j3", legacy)}]
    end)

  :ok = DurableFile.put_checkpoint(record_key, record, path: Path.join(root, "interactive"))
end

:ok = DurableFile.put_checkpoint(key, index, path: Path.join(root, "interactive"))
ledger_key = Ouroboros.Agent.EffectLedger.checkpoint_key()

{:ok, ledger} =
  DurableFile.get_checkpoint(ledger_key, path: "test/support/j2_fixture/data/effect-ledger")

ledger =
  update_in(ledger.entries, fn [entry] ->
    [%{entry | error: Map.put(entry.error, :legacy, legacy)}]
  end)

:ok = DurableFile.put_checkpoint(ledger_key, ledger, path: Path.join(root, "effect-ledger"))

files = Path.wildcard(Path.join(root, "**/*.term"))

hashes =
  Map.new(files, fn path ->
    {Path.relative_to(path, root),
     :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)}
  end)

File.write!(Path.join(Path.dirname(root), "SHA256.json"), JSON.encode!(hashes))

walk = fn walk, value, acc ->
  cond do
    is_atom(value) ->
      MapSet.put(acc, Atom.to_string(value))

    is_map(value) ->
      Enum.reduce(Map.to_list(value), acc, fn {k, v}, a -> walk.(walk, v, walk.(walk, k, a)) end)

    is_list(value) ->
      Enum.reduce(value, acc, &walk.(walk, &1, &2))

    is_tuple(value) ->
      Enum.reduce(Tuple.to_list(value), acc, &walk.(walk, &1, &2))

    true ->
      acc
  end
end

atoms =
  Enum.reduce(files, MapSet.new(), fn path, acc ->
    {:ok, bytes} = Ouroboros.Audit.Content.read(path)
    walk.(walk, :erlang.binary_to_term(bytes, [:safe]), acc)
  end)

File.write!(Path.join(Path.dirname(root), "atoms.txt"), Enum.sort(atoms) |> Enum.join("\n"))

versions =
  Map.new([:jido, :jido_action, :jido_signal], fn app ->
    Application.load(app)
    {Atom.to_string(app), to_string(Application.spec(app, :vsn))}
  end)

revision = System.get_env("J3_BASELINE_REV") || elem(System.cmd("git", ["rev-parse", "HEAD"]), 0)

File.write!(
  Path.join(Path.dirname(root), "BASELINE.json"),
  JSON.encode!(%{
    revision: String.trim(revision),
    versions: versions,
    elixir: System.version(),
    otp: to_string(:erlang.system_info(:otp_release)),
    files: length(files),
    synthetic: true
  })
)

File.rm_rf!(tmp)
IO.puts("J3 captured #{length(files)} checkpoints across eight stores")
