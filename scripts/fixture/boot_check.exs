# Boots this build against a copy of the fixture data directory and counts what loaded.
#
#     OUROBOROS_PROCESS_ID_HELPER=/abs/ouro \
#     OUROBOROS_DATA_DIR=/abs/copy OUROBOROS_FLEET_ID=<24 hex> \
#     FIXTURE_WORKSPACES_ROOT=/abs/fixture-workspaces \
#       mix run --no-start scripts/fixture/boot_check.exs
#
# It writes nothing to the directory beyond what booting a node writes (the ownership
# marker and, if audit is on, its own reconciliation), so run it against a copy. Every
# count it prints is read back out of a store that had to decode its checkpoint to answer.
#
# The reduced tree runs this same script against the same copy. A store that stops the
# boot fails here loudly; a store that quarantines a record shows up as a smaller count.

data_dir = Application.get_env(:ouroboros, :data_dir)
unless is_binary(data_dir), do: raise("OUROBOROS_DATA_DIR is required")

leaf = fn name -> Path.join(data_dir, name) end
durable = fn name -> {Ouroboros.Storage.DurableFile, path: leaf.(name)} end

for {key, name} <- [
      coding_storage: "coding",
      interactive_storage: "interactive",
      team_storage: "teams",
      orchestration_storage: "orchestration",
      control_storage: "control",
      grants_storage: "grants",
      policy_promotion_storage: "policy-promotion",
      permissions_storage: "permissions",
      effect_ledger_storage: "effect-ledger",
      upgrade_storage: "upgrades",
      release_storage: "release-journal",
      capability_storage: "capabilities",
      epoch_storage: "forge-epochs",
      signing_journal_storage: "signing-journal"
    ] do
  Application.put_env(:ouroboros, key, durable.(name))
end

Application.put_env(:ouroboros, :audit,
  mode: :local,
  capture: :metadata,
  root: leaf.("audit"),
  index: true,
  segment_bytes: 4_096,
  organization: "ouroboros-core-fixture",
  writer_id: "core-fixture"
)

workspaces_root =
  System.get_env("FIXTURE_WORKSPACES_ROOT") ||
    Path.join(Path.dirname(data_dir), "fixture-workspaces")

File.mkdir_p!(workspaces_root)
Application.put_env(:ouroboros, :workspace_allowed_roots, [workspaces_root])

started_at = System.monotonic_time(:millisecond)

case Application.ensure_all_started(:ouroboros) do
  {:ok, _apps} ->
    IO.puts("BOOT: ok (#{System.monotonic_time(:millisecond) - started_at} ms)")

  {:error, reason} ->
    IO.puts("BOOT: FAILED\n#{inspect(reason, pretty: true, limit: :infinity)}")
    System.halt(1)
end

# Read first, while the tree is exactly as the boot left it: `Ouroboros.status/0`'s
# `availability` is a liveness check on named children, so it has to be taken before the
# resume loops are stopped below.
status = Ouroboros.status()

# The recovery loops would resume the sessions this directory holds; the question here is
# whether the checkpoints decode, not whether a provider is reachable. The sweep runs once
# inside `Ouroboros.Session.Recovery.init/1`, before the boot returns, and it adopts only
# records whose `node` is this node's: under the node name that wrote the directory
# (`nonode@nohost`) the coordinators are already resuming sessions and appending to them
# by the time the store is read below, so the counts are a snapshot of a moving system;
# under any other node name — which is what a data directory copied to another machine
# looks like — nothing is adopted and the counts are the files'. `scripts/fixture/boot_gate.sh`
# boots under its own name for that reason.
Enum.each(
  [
    {Ouroboros.Interactive.Supervisor, Ouroboros.Interactive.Recovery},
    {Ouroboros.Coding.Supervisor, Ouroboros.Coding.Recovery}
  ],
  fn {supervisor, child} ->
    # A plane the reduction deleted has no supervisor; skip it rather than exit.
    if is_pid(Process.whereis(supervisor)), do: _ = Supervisor.terminate_child(supervisor, child)
  end
)

safe = fn label, fun ->
  value =
    try do
      fun.()
    rescue
      error -> {:raised, Exception.message(error)}
    catch
      kind, reason -> {kind, reason}
    end

  IO.puts("#{label}: #{inspect(value, limit: :infinity, printable_limit: 400)}")
  value
end

IO.puts("\n── durability ─────────────────────────────────────────────")
safe.("permissions.durability", fn -> Ouroboros.Control.Permissions.status().durability end)
safe.("grants.durability", fn -> Ouroboros.Control.Grants.durability() end)
safe.("ledger.durability", fn -> Ouroboros.Agent.EffectLedger.durability() end)

IO.puts("\n── counts ─────────────────────────────────────────────────")

safe.("permission rules (stored + node)", fn ->
  {:ok, rules} = Ouroboros.Control.Permissions.list()

  %{
    total: length(rules),
    by_scope: rules |> Enum.frequencies_by(& &1.scope),
    by_kind: rules |> Enum.frequencies_by(& &1.kind)
  }
end)

safe.("grants", fn ->
  ["agent-fixture", "agent-fixture-capability", "agent-fixture-wasm"]
  |> Enum.flat_map(&Ouroboros.Control.Grants.list/1)
  |> Enum.map(fn g -> {g.principal, g.effect, g.constraints} end)
end)

safe.("effect ledger entries", fn ->
  {:ok, entries} = Ouroboros.Agent.EffectLedger.list(limit: 500)

  %{
    total: length(entries),
    by_effect: Enum.frequencies_by(entries, & &1.effect),
    by_status: Enum.frequencies_by(entries, & &1.status)
  }
end)

safe.("ledger status", fn -> Ouroboros.Agent.EffectLedger.status() end)

safe.("interactive sessions", fn ->
  Ouroboros.Interactive.Store.list()
  |> Enum.map(fn s ->
    %{
      id: s.id,
      provider: s.provider,
      status: s.status,
      events: length(s.events),
      turns: map_size(s.turns),
      delegations: map_size(Map.get(s, :delegations) || %{})
    }
  end)
  |> Enum.sort_by(& &1.id)
end)

safe.("coding tasks", fn -> Ouroboros.Coding.Store.list() |> Enum.map(& &1.id) end)
safe.("teams", fn -> Ouroboros.Team.Store.list() |> Enum.map(& &1.id) end)

safe.("orchestration plans", fn ->
  {:ok, plans} = Ouroboros.Orchestration.Store.list()
  Enum.map(plans, fn p -> {p.id, p.status, Map.keys(p.steps) |> Enum.sort()} end)
end)

safe.("control runs", fn ->
  {:ok, runs} = Ouroboros.Control.Store.list()
  Enum.map(runs, fn r -> {r.id, r.status} end)
end)

# One plane per call. On a tree that deleted the coding plane, asking for both inside one
# `safe` would hide whether the session-owner checkpoint — the one file that carries the
# retired `:coding` atom — decodes at all.
safe.("cluster session owners (interactive)", fn ->
  Ouroboros.Cluster.session_owners(:interactive)
end)

safe.("cluster session owners (coding)", fn -> Ouroboros.Cluster.session_owners(:coding) end)

safe.("rollout registry", fn ->
  Ouroboros.Upgrade.Rollout.Registry.list()
  |> Enum.map(fn e -> {e.artifact_id, e.module, e.state} end)
end)

safe.("forge epoch watermark", fn -> Ouroboros.Upgrade.Epoch.watermark() end)

safe.("node executor status", fn -> Ouroboros.Upgrade.NodeExecutor.status() end)

safe.("policy promotion", fn -> Ouroboros.Control.PolicyPromotion.status() end)
safe.("policy evidence", fn -> Ouroboros.Control.PolicyEvidence.count() end)

safe.("audit status", fn ->
  Ouroboros.Audit.Store.status() |> Map.take([:streams, :bytes, :error, :durability])
end)

safe.("signing journal", fn ->
  storage = {Ouroboros.Storage.DurableFile, path: leaf.("signing-journal")}
  {adapter, opts} = Jido.Storage.normalize_storage(storage)

  case adapter.get_checkpoint(Ouroboros.Upgrade.Signing.Service.checkpoint_key(), opts) do
    {:ok, checkpoint} ->
      decoded = Ouroboros.Upgrade.Wire.load(checkpoint)

      decoded
      |> Map.get(:decisions, Map.get(decoded, "decisions", []))
      |> Enum.map(fn d ->
        {Map.get(d, :lane) || Map.get(d, "lane"), Map.get(d, :decision) || Map.get(d, "decision")}
      end)

    other ->
      other
  end
end)

IO.puts("\n── Ouroboros.status/0 (taken before the resume loops were stopped) ──")

IO.puts(
  inspect(
    Map.take(status, [
      :node,
      :role,
      :availability,
      :coding_tasks,
      :interactive_sessions,
      :teams,
      :orchestration_plans,
      :effect_ledger,
      :control
    ]),
    pretty: true,
    limit: :infinity,
    printable_limit: 400
  )
)

IO.puts("\nstopping ...")
:ok = Application.stop(:ouroboros)
IO.puts("BOOT CHECK COMPLETE")
