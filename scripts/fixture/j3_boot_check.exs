# Fresh-VM, read-only boot of the pre-J3 corpus. Run through j3_boot_gate.sh.
root = System.fetch_env!("J3_FIXTURE_COPY")

manifest =
  Path.expand("../../test/support/j3_fixture/SHA256.json", __DIR__)
  |> File.read!()
  |> JSON.decode!()

hash = fn path -> :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower) end

for {relative, expected} <- manifest do
  unless hash.(Path.join(root, relative)) == expected,
    do: raise("baseline bytes changed: #{relative}")
end

for path <- :code.get_path(),
    beam <- Path.wildcard(Path.join(to_string(path), "Elixir.Jido*.beam")) do
  raise("retired executable is available: #{beam}")
end

stores = [
  interactive_storage: "interactive",
  effect_ledger_storage: "effect-ledger",
  grants_storage: "grants",
  permissions_storage: "permissions",
  policy_promotion_storage: "policy-promotion",
  capability_storage: "capabilities",
  epoch_storage: "forge-epochs",
  signing_journal_storage: "signing-journal"
]

for {key, leaf} <- stores do
  Application.put_env(
    :ouroboros,
    key,
    {Ouroboros.Storage.DurableFile, path: Path.join(root, leaf)}
  )
end

Application.put_env(:ouroboros, :workspace_allowed_roots, [root])

{:ok, _} = Application.ensure_all_started(:ouroboros)

for {app, _, _} <- Application.started_applications() do
  if Atom.to_string(app) in ~w(jido jido_action jido_signal jido_ai jido_harness),
    do: raise("retired application is running: #{app}")
end

for tag <- Ouroboros.Storage.SessionMigration.legacy_structs() do
  unless :code.which(tag) == :non_existing, do: raise("retired constructor is available: #{tag}")
end

alias Ouroboros.Storage.DurableFile

read = fn leaf, key ->
  {:ok, value} = DurableFile.get_checkpoint(key, path: Path.join(root, leaf))
  value
end

sessions = Ouroboros.Interactive.Store.list()

expected_ids =
  ~w(idle running queued awaiting_approval terminal resumed forked removed_provider)
  |> Enum.map(&("j2-fixture-" <> &1))

unless Enum.sort(Enum.map(sessions, & &1.id)) == Enum.sort(expected_ids),
  do: raise("session loss")

for session <- sessions do
  kind = String.replace_prefix(session.id, "j2-fixture-", "")

  unless session.runtime_id == "legacy-runtime-#{kind}" and
           session.provider_session_id == "native-conversation-#{kind}",
         do: raise("historical identity changed")

  unless session.usage.total_tokens == 10 and session.created_at == "2026-09-10T00:00:00Z",
    do: raise("usage or timestamp changed")

  [event] = session.events
  legacy = event.payload["j3"]

  unless map_size(legacy["keyed_history"]) == 2 and
           Enum.sort(Map.values(legacy["keyed_history"])) == ["plain", "retired"],
         do: raise("historical map keys collided")

  signed = legacy["signed_manifest"]
  decoded_wire = Ouroboros.Upgrade.Wire.load(legacy["signed_manifest_wire"])
  unless decoded_wire == signed, do: raise("historical signed Wire representation changed")

  unless Ouroboros.Upgrade.Wire.load(Ouroboros.Upgrade.Wire.dump(signed)) == signed,
    do: raise("signed manifest no longer round-trips after dependency removal")

  unless :crypto.verify(
           :eddsa,
           :none,
           Ouroboros.Wasm.Artifact.signing_payload(signed, "j3-fixture-signer"),
           signed.signature.value,
           [legacy["public_key"], :ed25519]
         ),
         do: raise("historical signed manifest changed")

  unless legacy.signal.id == "019930a0-0000-7000-8000-000000000003" and
           legacy.signal.data.body == "Historical body" and
           legacy.signal.data.correlation_id == "j3-correlation" and
           legacy.signal.data.causation_id == "j3-cause" and
           legacy.signal.time == "2026-09-10T00:00:00Z",
         do: raise("historical message changed")

  unless not is_struct(legacy.signal) and not is_struct(legacy.agent) and
           not is_struct(legacy.instruction),
         do: raise("retired data tag not normalized")

  unless Enum.map(legacy.errors, & &1.message) == [
           "historical invalid input",
           "historical execution failure",
           "historical invalid config",
           "historical timeout",
           "historical internal error"
         ],
         do: raise("historical action errors changed")

  unless Enum.all?(legacy.errors, &(not is_struct(&1))), do: raise("retired error not normalized")

  unless event.payload["legacy"].approval.decision == :deny,
    do: raise("historical approval changed")

  unless legacy.agent.state.provider == :claude, do: raise("retired provider value changed")
end

{:ok, entries} = Ouroboros.Agent.EffectLedger.list(limit: 500)
unless length(entries) == 1, do: raise("ledger loss")
[entry] = entries

unless entry.id == "j2-fixture-ledger-error" and entry.status == :failed and
         entry.attempt.tool == "read" and entry.error.legacy.signal.data.body == "Historical body",
       do: raise("effect outcome changed")

grants = read.("grants", Ouroboros.Control.Grants.checkpoint_key()).grants

actual_grants =
  grants
  |> Map.keys()
  |> Enum.map(&elem(&1, 0))
  |> Enum.uniq()
  |> Enum.flat_map(&Ouroboros.Control.Grants.list/1)
  |> Map.new(&{{&1.principal, &1.effect}, &1})

unless actual_grants == grants and map_size(grants) == 7, do: raise("grants changed")

{:ok, rules} = Ouroboros.Control.Permissions.list()
unless length(rules) == 22, do: raise("permission loss")

unless Enum.count(rules, &(&1.kind == :computer_use)) == 5,
  do: raise("retired permissions changed")

unless Ouroboros.Upgrade.Epoch.watermark() == {:ok, 3}, do: raise("epoch changed")
rollouts = Ouroboros.Upgrade.Rollout.Registry.list()

unless Enum.sort(Enum.map(rollouts, & &1.artifact_id)) == [
         "artifact-fixture-beam",
         "artifact-fixture-wasm"
       ],
       do: raise("rollout identity loss")

policy = Ouroboros.Control.PolicyPromotion.status()
unless "bash" in policy.allowable_tools, do: raise("policy promotion loss")

expected_policy =
  read.("policy-promotion", Ouroboros.Control.PolicyPromotion.checkpoint_key()).record

unless Map.take(policy, Map.keys(expected_policy)) == expected_policy,
  do: raise("policy evidence, timestamps or identity changed")

journal =
  read.("signing-journal", Ouroboros.Upgrade.Signing.Service.checkpoint_key())
  |> Ouroboros.Upgrade.Signing.Journal.from_wire()

unless Ouroboros.Upgrade.Signing.Journal.valid?(journal) and
         Enum.map(journal.decisions, &{&1.lane, &1.decision}) == [beam: :refused, wasm: :refused],
       do: raise("signing history loss")

unless Ouroboros.Mesh.list_agents() == [], do: raise("history read launched a capability")

unless Registry.count(Ouroboros.Interactive.Registry) == 0,
  do: raise("history read launched a session")

unless Ouroboros.Workspace.list() == [], do: raise("history read reserved a workspace")

for {relative, expected} <- manifest do
  unless hash.(Path.join(root, relative)) == expected,
    do: raise("history read rewrote #{relative}")
end

unless length(Path.wildcard(Path.join(root, "**/*.term"))) == map_size(manifest),
  do: raise("read added or quarantined a checkpoint")

unless Path.wildcard(Path.join(root, "**/*quarantined*")) == [],
  do: raise("valid corpus quarantined")

IO.puts(
  "J3 BOOT: 8 stores, 16 checkpoints, 8 sessions, action/message history retained, no retired BEAMs, no effects, no rewrite, no quarantine"
)

:ok = Application.stop(:ouroboros)
