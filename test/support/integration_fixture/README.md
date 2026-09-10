# The integration fixture

`fixture-datadir.tar.gz` is a data directory written by `dev` at `3bc8887` — the last
commit before [the core reduction](../../../docs/proposals/core.md) — holding every
durable shape the reduction retired: permission rules of every pattern kind that build
had, grants naming the deleted agent modules, an effect ledger with the deleted runner's
whole error vocabulary, interactive sessions with a delegation record and a vendor
provider, a coding task, a team, an orchestration plan, a control run, a lane-B and a
lane-W rollout, a node-executor receipt for a capability compiled at runtime, a release
journal, and the cluster's session-owner checkpoint for both planes. It is the input to
`make boot-gate`, the reduction's integration gate: this tree has to boot it.

| | |
|---|---|
| sha256 | `3d76a84e7d6bac1af3ad40288985e12d62d7454ff5488b4be542e0b016259793` |
| size | 30 025 bytes; 101 tar entries under `fixture-datadir/`; 51 files, 23 `.term` checkpoints |
| written by | Elixir 1.20.2, OTP 29, `nonode@nohost`, `MIX_ENV=dev`, on macOS, 2026-09-09 |
| written with | `scripts/fixture/build_fixture.exs` at commit `2600c68` on branch `core-fixture` (`3bc8887` plus that commit) |
| fleet id | `0123456789abcdef01234567` — `Ouroboros.Cluster` reads a session-owner checkpoint written under any other fleet identity as `:fleet_mismatch` and loads it empty |
| atom sweep | `atom-sweep.tsv`, every atom in every checkpoint, marked against this tree (below) |

Seventeen of its twenty-eight recorded shapes went through the plane's own writing
function; eleven went through the store's public API in the writer's exact shape because
the writer needed a plane that cannot run in one `mix run` VM. `.fixture-provenance.tsv`
inside the directory says which is which, row by row.

## What is in it

`Ouroboros.Storage.DurableFile` names a checkpoint
`<leaf>/checkpoints/<url-safe-base64 of sha256(term_to_binary(key))>.term`, so the file
names are opaque. What each store held when it was written:

| leaf | store on `dev` | held | on this tree |
|---|---|---|---|
| `permissions/` | `Control.Permissions` | 22 rules (user 20, workspace 1, session 1), five of them `ComputerUse(…)` | decodes; the five retired kinds match nothing |
| `grants/` | `Control.Grants` | 8 grants, one naming the runtime-minted `Ouroboros.Capability.FixtureProbe` | **quarantined by name**, the one `[error]` line; no grants |
| `effect-ledger/` | `Agent.EffectLedger` | 18 entries: delegate 8, permission 3, start_agent 2, tool_call 2, forge 1, approval 1, policy_promotion 1 | decodes, all 18 |
| `interactive/` | `Interactive.Store` | 4 sessions: native, delegating (1 delegation), a `provider: :claude` record, read-only | all four load and list; the `:claude` one is history, never run |
| `fleet/cluster-directory/` | `Ouroboros.Cluster` | interactive and coding owner sets | decodes; the retired `:coding` key is ignored |
| `policy-promotion/`, `policy/evidence.ndjson` | `Control.PolicyPromotion`, `Control.PolicyEvidence` | `Bash(mix test *)` promoted on `bash`; 1 evidence row | as written |
| `capabilities/`, `signing-journal/`, `forge-epochs/` | `Rollout.Registry`, `Signing.Journal`, `Upgrade.Epoch` | 2 rollouts (lane B, lane W), 2 refusals, watermark 3 | as written; wire-encoded, so the lane-B module reads back as a string |
| `coding/`, `teams/`, `orchestration/`, `control/`, `upgrades/`, `release-journal/` | the deleted planes | one record each | never opened |
| `audit/`, `mirrors/`, `fleet/profile.json` | `Audit.Store`, `Workspace.Mirrors`, the fleet profile | 2 streams over 17 segments; a bare repository with a real bundle; JSON | as written; no atom in any of them |

The full file-by-file map, the provenance of every shape, and the five defects the fixture
found in `dev` itself are in the record this directory was cut from
(`scratchpad/core/fixture/MANIFEST.md`); the two that matter for reading a gate log are
that `dev`'s own effect-ledger boot was a coin flip under interactive code loading, and
that the runtime-minted capability atom in the grants file can be held by no list.

## The gate

```sh
make boot-gate                 # ten plain boots and ten --preload-modules boots, fresh copy each
BOOT_GATE_RUNS=1 make boot-gate
```

`scripts/fixture/boot_gate.sh` verifies the sha256, finds the `ouro` binary
`Ouroboros.RuntimeOwner` requires before it opens durable state
(`OUROBOROS_PROCESS_ID_HELPER`, else `tui/target/release/ouro`, else `tui/target/debug/ouro`,
else it builds a debug one), extracts the tarball under `_build/boot-gate/`, and runs
`scripts/fixture/boot_check.exs` against a fresh copy per boot in the development
environment — the one the record was taken in, and the one where the helper is required
exactly as it is on a packaged node. It fails on any `BOOT: FAILED` and on any count that
differs from the block below. `make test` runs it.

**Every boot runs under a node name of the gate's own**, `boot-gate-<mode>-<n>@<host>`,
never the `nonode@nohost` that wrote the directory. `Session.Recovery` adopts only records
whose `node` is this node's, and `Workspace.Manager` reserves only for those. Under the
writer's name the recovery sweep — which runs inside `Recovery.init/1`, before the boot
returns — is already resuming the three native sessions and appending to them when the
store is read: the native record's harness session is gone, so its coordinator starts a
fresh one and appends a `status` event, and given a few hundred milliseconds more the
sessions carry four and five events, the native one is `:failed`, and the audit has four
streams. Every earlier gate read that moving system at an early instant and recorded
`native: 2 events`; this gate read `1` once in twenty on the same bytes, which is what a
snapshot is. Under its own name the runtime does what it does with a data directory that
moved machines: it loads everything, adopts nothing, and the counts are the files'. It
also means the absolute workspace paths the records hold need not exist, which is what
makes the gate runnable on any host.

### The expected block

Every boot, in both modes, must read:

```
BOOT: ok
permissions / grants / ledger durability   :synced_checkpoint, all three
permission rules      22   user 20, workspace 1, session 1
                           computer_use 5, bash 3, tool 3, mcp 2, capability 2, forge 2,
                           read 1, write 1, edit 1, web_fetch 1, tool_param 1
grants                []   the file is quarantined — the one [error] line below
effect ledger         18   delegate 8, permission 3, start_agent 2, tool_call 2,
                           forge 1, approval 1, policy_promotion 1
                           ok 10, denied 5, failed 3
ledger status              next_sequence 28, retained 18, in_flight 0, ambiguous 0
interactive sessions   4   fixture-session-claude      :idle  events 0  provider :claude
                           fixture-session-delegating  :idle  events 1  provider :native
                           fixture-session-native      :idle  events 1  provider :native  turns 1
                           fixture-session-read-only   :idle  events 0  provider :native
cluster session owners (interactive)   {:ok, MapSet.new(["ouro-fixture@fixture.invalid"])}
rollout registry       2   artifact-fixture-beam  "Elixir.Ouroboros.Capability.FixtureProbe"  :live
                           artifact-fixture-wasm  "wasm/counter"                               :live
forge epoch watermark      {:ok, 3}
policy promotion           "Bash(mix test *)", allowable_tools ["bash"]
policy evidence            records 1
audit status               streams 2, bytes 227277, error nil
signing journal            [beam: :refused, wasm: :refused]
availability               interactive, effect_ledger, cluster, mesh, workspace — all :available
[error] lines          1   checkpoint {:ouroboros, :agent_grants, 1} … could not be decoded
                           (:invalid_term); quarantining it at …/<hash>.quarantined-<unix>.term
                           and starting from no checkpoint
on disk                    exactly one grants/checkpoints/*.quarantined-*.term in the copy
BOOT CHECK COMPLETE
```

Six lines read `{:raised, …}` on this tree and are expected: `coding tasks`, `teams`,
`orchestration plans`, `control runs`, `cluster session owners (coding)` and
`node executor status` ask for planes the reduction deleted, and the script's `safe`
wrapper reports the module that is gone rather than exiting. They are not `[error]` lines.

Two counts differ from `dev`'s own baseline on the same bytes, and both are the point:
`grants` is `[]` here and 8 there, because the runtime-minted name in one grant loaded on
`dev` only because the deleted node executor interned it first; and `teams` is a raised
line here and was already `0` there, because `dev` could never decode its own team record.

### Booting it as the node that wrote it

`scripts/fixture/boot_check.exs` can also be run by hand under `nonode@nohost`
(`mix run --no-start scripts/fixture/boot_check.exs` with the same environment), which is
the same-machine upgrade: the recovery sweep adopts the three native sessions and resumes
them. Two things follow. The counts are then a snapshot of a moving system, as described
above. And the four session records hold absolute workspace paths under the generator's
scratchpad, `…/scratchpad/core/fixture/fixture-workspaces/{native,delegating,read-only,…}`;
`Workspace.Manager` refuses to boot a non-terminal record of this node whose root it cannot
canonicalise through the filesystem or that is outside `workspace_allowed_roots`
(`{:invalid_workspace_recovery_state, "interactive:…", {:workspace_outside_allowed_roots, …}}`),
which is the manager doing its job, so those directories have to exist and
`FIXTURE_WORKSPACES_ROOT` has to name their parent. The gate does neither, on purpose.

## Regenerating it, on a checkout of `3bc8887`

The generator only runs on the tree that has the planes it writes, so it runs on
`core-fixture` — `3bc8887` plus commit `2600c68`, which is `scripts/fixture/` as first
committed — never here. Nothing is read from an existing directory.

```sh
git worktree add /tmp/ouroboros-fixture core-fixture
cd /tmp/ouroboros-fixture && mix deps.get && mix compile

OUROBOROS_PROCESS_ID_HELPER=/abs/path/to/ouro \
OUROBOROS_DATA_DIR=/abs/new/fixture-datadir \
OUROBOROS_FLEET_ID=0123456789abcdef01234567 \
FIXTURE_WORKSPACES_ROOT=/abs/new/fixture-workspaces \
  mix run --no-start scripts/fixture/build_fixture.exs

tar -czf fixture-datadir.tar.gz -C /abs/new fixture-datadir
shasum -a 256 fixture-datadir.tar.gz
```

A regenerated directory has new timestamps, ids and workspace paths, so its sha256 is a
new one: replace the value here and in `boot_gate.sh`, run the gate on `core-fixture`
first (`scripts/fixture/boot_check.exs` is the same script) to record the baseline, and
then here. The counts above should not change; if they do, the generator changed.

## The atom sweep

`atom-sweep.tsv` lists every atom in every checkpoint — 562 (file, atom) rows, 266
distinct atoms — with one column per tree it was checked against and a `RETIRED` mark on
each atom that tree no longer spells. Presence is decided by loading every `.beam` under
the tree's `_build/dev/lib` into a throwaway VM that never decodes the fixture and asking
`String.to_existing_atom/1` there — not by reading the atom chunk of each `.beam`, which
omits atoms that occur only inside compound literals (a `@result_fields` map, the retired
list itself) and so marks names retired that the build spells. The committed sweep was
taken against this tree, labelled `core`:

```sh
tar -xzf test/support/integration_fixture/fixture-datadir.tar.gz -C /tmp
FIXTURE_DATA_DIR=/tmp/fixture-datadir REDUCED_WORKTREES=core=$PWD \
  mix run --no-start scripts/fixture/atom_sweep.exs > test/support/integration_fixture/atom-sweep.tsv
```

How to read a `RETIRED` row: if the file belongs to a store this tree opens —
`permissions/`, `grants/`, `effect-ledger/`, `interactive/`, `fleet/cluster-directory/`,
`policy-promotion/` — the atom is either in `Ouroboros.Storage.RetiredAtoms`, or it is a
name no build can spell (`Ouroboros.Capability.FixtureProbe`, a node name) and the
quarantine covers it. A `RETIRED` row in `coding/`, `teams/`, `orchestration/`, `control/`,
`upgrades/` or `release-journal/` is a store nothing opens; those rows are why the
directory holds them. `wire-tagged` rows went through `Upgrade.Wire` and cost nothing.
`test/storage/retired_atoms_test.exs` guards the list from the other direction, with
captured bytes of its own.
