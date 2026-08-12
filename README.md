# Ouroboros

Ouroboros is an experimental BEAM-native runtime for coding-agent teams. It uses
OTP supervision and Erlang distribution for lifecycle and communication, Jido for
inspectable agent/action/signal primitives, and Jido Harness for normalized coding
provider execution.

This repository is an executable architecture slice, not yet a Claude Code-class
product. It currently proves:

- supervised Jido agents addressed by logical ID across connected BEAM nodes;
- typed task and message routing over ordinary Erlang PIDs;
- detached Codex, Claude, Gemini, and other CLI runs through one normalized API;
- durable one-shot and interactive session checkpoints, exclusive-cursor replay,
  cancellation, multi-turn follow-up, and coordinator crash recovery;
- durable supervised teams that rebuild local or remote Jido projections and
  reattach in-flight coding tasks after a team crash;
- a dependency scheduler with fan-out/fan-in, global concurrency, stable execution
  tokens, failure/cancellation propagation, and a real Team execution adapter;
- an opt-in durable control plane that turns an objective into a validated DAG,
  evaluates terminal evidence, revises within a fixed budget, and cancels durably;
- optional symlink-safe workspace admission with read-sharing/write exclusion;
- a bounded, signed BEAM hot-patch lane with a durable node journal, cluster health
  gates, rollback, promotion, restart reconciliation, and explicit quarantine;
- offline OTP release metadata/archive validation plus a deny-by-default,
  write-ahead-journaled `:release_handler` control boundary; and
- real two-node behavior in tests using an OTP `:peer` OS process.

It does **not** yet provide partition-safe placement, durable provider execution
across a full BEAM/host restart, an independently operated build/signing service,
aggregate cost budgets, or a polished terminal UI. The OTP release adapter is
implemented, but a real packaged-release install/reboot rehearsal remains an external
deployment gate.

## Why Jido

Ouroboros deliberately does not reimplement agent structs, actions, CloudEvents-style
signals, AgentServer supervision, or coding-provider CLI adapters. Those come from
[Jido](https://jido.run/) and the pinned upstream
[`jido_harness`](https://github.com/agentjido/jido_harness) commit in `mix.exs`.
Ouroboros owns the boundaries those libraries do not: distribution-aware identity,
durable domain state, reliable replay/subscription, team delivery, workspace
admission, and upgrade policy.

## Run it

The project currently targets Elixir 1.20 and OTP 29.

```sh
mix deps.get
mix test
iex -S mix
```

Probe a provider without starting a paid inference:

```elixir
Ouroboros.provider_status(:codex)
Ouroboros.providers()
```

Start a safe read-only coding task:

```elixir
{:ok, task} =
  Ouroboros.CodingSession.start("Inspect this project and report the riskiest gap",
    provider: :codex,
    workspace: File.cwd!(),
    sandbox_mode: :read_only,
    approval_mode: :prompt
  )

{:ok, backlog} = Ouroboros.CodingSession.subscribe(task, cursor: 0)

receive do
  {:ouroboros_coding_event, task_id, event} ->
    IO.inspect({task_id, event.type, event.payload})
end

{:ok, final_state} = Ouroboros.CodingSession.await(task, 300_000)
```

For iterative work, use a durable interactive session. A stable logical turn ID
makes retries idempotent, while the returned reference routes over distribution:

```elixir
{:ok, session} =
  Ouroboros.InteractiveSession.start(
    id: "review-session",
    provider: :codex,
    workspace: File.cwd!()
  )

{:ok, first} =
  Ouroboros.InteractiveSession.send_message(
    session,
    "Inspect the supervision tree",
    id: "inspect"
  )

{:ok, _result} = Ouroboros.InteractiveSession.await(session, first.id, 300_000)

{:ok, _queued} =
  Ouroboros.InteractiveSession.follow_up(
    session,
    "Now propose the smallest fix",
    id: "fix"
  )
```

`steer/3`, `respond_approval/3`, and `interrupt/2` route to native Harness
capabilities when the selected provider transport supports them.

Control-plane calls (`info/1`, `replay/2`, `subscribe/2`, `cancel/1`, `steer/3`,
`respond_approval/3`, `interrupt/2`) are bounded by
`:ouroboros, :session_call_timeout` so one wedged coordinator cannot freeze every
caller; `await` keeps the caller's own timeout. If a provider session closes while a
dispatched turn never resolves, the turn is settled as `:ambiguous` with
`{:unresolved_at_session_close, turn_id}` after
`:ouroboros, :interactive_unresolved_turn_deadline_ms` — the provider work may have
happened, and the session is released rather than polled forever.

Writing is opt-in. A provider can only edit the workspace when the caller explicitly
selects a write-capable provider policy, for example `sandbox_mode: :workspace_write`.
These normalized flags configure the provider CLI; they are not a substitute for an
OS/container sandbox when executing untrusted work.

Per-run environment maps are rejected because task requests are checkpointed. Put
provider credentials in the service environment or a dedicated secret boundary,
never in task options. Persisted normalized event payloads are redacted before they
enter the Ouroboros store.

To enforce workspace admission, configure existing roots before application start:

```elixir
config :ouroboros, workspace_allowed_roots: ["/srv/agent-worktrees"]
```

The task coordinator acquires a lease before Harness can start or adopt a run.
Read-only tasks default to `:shared_read`; write-capable tasks to `:exclusive`.
Nonterminal durable tasks reserve their roots while a coordinator, registry, or the
workspace manager is being rebuilt, and only the exact registered recovery owner can
claim a reservation. These leases are node-local admission, not distributed consensus.

## Agent mesh

```elixir
{:ok, reviewer} = Ouroboros.Mesh.start_agent("reviewer", role: "reviewer")

{:ok, agent} =
  Ouroboros.Mesh.send_message("root", "reviewer", %{request: "inspect mix.exs"})

{:ok, task_id, agent} =
  Ouroboros.Mesh.assign_task("root", "reviewer", "Find dependency risks")
```

Start on a connected node with `Ouroboros.Mesh.start_agent_on/3`. The directory uses
a named `:pg` scope and monitors local Jido processes. `:global.trans/2` narrows
duplicate-start races in a healthy connected cluster; it is explicitly not a
partition-safe consensus protocol.

Visibility is eventually consistent. `whereis/1` and `members/1` qualify a remote entry
by node connectivity, not by remote process liveness, because probing the owner would
make every lookup a network call. A returned pid is an observation, not a guarantee: a
remote agent can already be dead while `:pg` propagates its leave. Mesh calls therefore
never exit the caller — a dead, unreachable, or slow target returns
`{:error, {:agent_call_failed, kind, reason}}`, and remote placement or shutdown
failures return `{:error, {:remote_start_failed, node, {kind, reason}}}` and
`{:error, {:remote_stop_failed, {kind, reason}}}`.

`start_agent/2` is a remote-reachable start surface, since `:erpc` from any connected
node can invoke it and pick the `:agent` module. Startable modules are restricted to the
`Ouroboros.Agent.` and `Ouroboros.Capability.` namespaces — the latter reserved for
agents forged at runtime — plus any module listed in
`config :ouroboros, mesh_allowed_agent_modules: [...]`. Anything else is refused with
`{:error, {:agent_module_not_allowed, module}}`. An `:initial_state` map option is
merged over the `:role`/`:objective`/`:parent_id` trio so runtime-defined agents can
seed their own schema keys.

Coding task references include their owner node. Calls made with a task reference are
routed through `:erpc`; a disconnected owner returns `{:owner_unavailable, node}`
instead of incorrectly marking its provider run lost. A bare task ID intentionally
means “on this node.”

## Agent teams

```elixir
{:ok, team} = Ouroboros.Team.start(id: "review-team")
{:ok, worker} = Ouroboros.Team.add_worker(team, "reviewer", node: node())

{:ok, delegation} =
  Ouroboros.Team.delegate(team, worker.id, "Review this repository",
    provider: :codex,
    workspace: File.cwd!()
  )

{:ok, delivered} = Ouroboros.Team.await(team, delegation.id, 300_000)
```

Local workers use Jido's real parent/child hierarchy. Because Jido 2.3.3 checks
adopted PIDs with local-only `Process.alive?/1`, remote workers are represented as
`:mesh_remote` relationships while assignment, execution, events, result delivery,
and cleanup cross the distributed boundary. A worker accepts one active delegation.
Team snapshots contain logical IDs and task references, never PIDs. An abnormal team
restart recreates or adopts its Jido projections, resumes each persisted cursor, and
retries terminal delivery without duplicating the provider run. `Team.close/1` first
checkpoints a recoverable `:closing` state and cancellation intent; it becomes
`:closed` and cleans up only after every delegation reaches durable delivery. Public
delegation IDs are local to a team; the underlying coding-task identity is
deterministically namespaced by team and delegation and bound to a private random
origin digest, so a matching foreign task cannot be adopted or cancelled. Coordinator
ownership is claimed inside the Jido agent, monitored, and reverified before signals
or cleanup.

Recovery never compensates a run it merely failed to resubscribe to: a pruned cursor
or unreachable owner degrades that delegation to polling the durable coding
checkpoint, with the reason recorded. Only a fresh `delegate/4` fails fast. Because
the coding-task ID is deterministic, an unreachable owner during startup keeps the
delegation `:starting` and retries within `:delegation_start_retry_ms` (default five
minutes); the durable failure after that bound explicitly records that provider-side
work may exist unconfirmed. `add_worker/3` and `delegate/4` are bounded by
`:team_call_timeout` (default 60s) so one wedged peer cannot freeze the local control
plane. `Team.state/1` reports durability as `:ephemeral_checkpoint`,
`:durable_checkpoint`, or `:synced_checkpoint`, and only the synced level reports
`host_restart_safe?: true` — the default file adapter does not `fsync`.

## Durable orchestration

```elixir
alias Ouroboros.Orchestration.{Plan, Scheduler}

{:ok, plan} =
  Plan.new("review-and-fix", [
    %{id: "review", input: %{objective: "Review the repository"}},
    %{id: "fix", dependencies: ["review"], input: %{objective: "Implement the fix"}},
    %{id: "verify", dependencies: ["fix"], input: %{objective: "Run focused checks"}}
  ])

{:ok, _} = Scheduler.submit(plan)
```

The scheduler persists before dispatch, caps concurrency, unlocks fan-out/fan-in,
uses stable execution tokens across owner or scheduler restart, and propagates
failure and cancellation. Configure `:orchestration_team_id` plus a default worker,
or put a `worker_id` in each step's metadata, to execute ready steps through
`Ouroboros.Orchestration.TeamExecutor`. Without an executor, callers can explicitly
claim and complete steps through `Scheduler.start/4` and `complete/5`.

## Autonomous control

`Ouroboros.Control` adds a durable planner/evaluator loop above the scheduler. It is
disabled by default so application startup cannot make an inference call. Enable it
only with explicit adapters and runtime execution policy:

```elixir
config :ouroboros,
  control_enabled: true,
  control_planner: {Ouroboros.Control.JidoAI, model: :planning, max_steps: 8},
  control_evaluator: {Ouroboros.Control.JidoAI, model: :reasoning},
  orchestration_team_id: "review-team",
  orchestration_worker_id: "reviewer",
  orchestration_coding_options: [
    provider: :codex,
    workspace: "/srv/agent-worktrees/project",
    sandbox_mode: :workspace_write,
    approval_mode: :prompt
  ]
```

```elixir
{:ok, run} =
  Ouroboros.Control.submit("Repair the failing tests and verify the change",
    id: "repair-42",
    max_revisions: 2
  )

{:ok, current} = Ouroboros.Control.get(run.id)
{:ok, cancelled} = Ouroboros.Control.cancel(run.id, reason: :operator_stop)
```

Planning and evaluation requests, plan IDs, revision history, and cancellation intent
are checkpointed. Model-produced steps may supply only a nonblank execution
objective; provider, worker, sandbox, and approval policy stay in trusted runtime
configuration. A run remains `:cancelling` while execution callbacks are pending;
its terminal cancellation evidence distinguishes no active work, a cancellation
request accepted by the execution plane, and an unconfirmed request. Acceptance is
not represented as proof that a provider process has stopped. Stable request IDs
support correlation, not provider-side exactly-once billing: a crash after a model
response and before its checkpoint can repeat a call.

## Hot code evolution

The fast lane accepts precompiled BEAM binaries only:

```elixir
{:ok, artifact} =
  Ouroboros.Upgrade.Artifact.build(
    [
      {MyAgent, new_beam,
       old_binary: current_beam,
       stateful: true,
       migration_extra: %{schema: 2}}
    ],
    epoch: 42
  )

signed = Ouroboros.Upgrade.Artifact.sign(artifact, "release-key", private_key)

{:ok, token} =
  Ouroboros.Upgrade.NodeExecutor.prepare(signed,
    migrations: [{MyAgent, pid, %{schema: 2}}]
  )

{:ok, receipt} = Ouroboros.Upgrade.NodeExecutor.commit(token)
```

The verifier rejects stale preimages, runtime mismatches, unsigned production
artifacts, consolidated protocols, sticky modules, and the modules that enforce this
lane's guarantees: everything under `Ouroboros.Upgrade.*`, `Ouroboros.Storage.*`,
`Ouroboros.Release.*`, and `Ouroboros.Control.*`, plus the application root and its
registry owner. On-load functions are detected by asking the code server to prepare
the batch, in both the new binary and the preimage the rollback path would load back.

### Introducing new modules

An entry's `:disposition` chooses between replacing a loaded module (`:replace`, the
default) and loading one that has never existed in this VM (`:introduce`). One artifact
may mix both, and they commit and roll back together:

```elixir
{:ok, artifact} =
  Ouroboros.Upgrade.Artifact.build(
    [
      {MyAgent, new_beam, old_binary: current_beam},
      {Ouroboros.Capability.Summarize, forged_beam, disposition: :introduce}
    ],
    epoch: 43
  )
```

An introduction has no preimage: every `old_*` field is `nil`, it cannot declare
`stateful: true` or a `migration_extra` (there are no processes to migrate yet), and
rolling it back means unloading the module — `:code.delete/1` followed by a soft purge.
Nothing is ever brutally purged, so a process still executing introduced code produces
`{:introduced_code_in_use, module}` and quarantine rather than a kill. The disposition
is part of the signed manifest, so a signature covers how each module is loaded, not
only its bytes.

Two extra gates apply. The module must be genuinely absent — unloaded, unreachable on
the code path, and not something the node's journal already expects to be present — and
its name must live under `Ouroboros.Capability.`, the namespace `Ouroboros.Mesh` already
reserves for agents forged at runtime.

Loading a new module is **not** safer than replacing one. Any accepted BEAM runs with
full ambient VM authority whichever disposition carried it; the namespace rule is policy
that keeps a new module from silently taking an existing name, not a sandbox, and it
constrains nothing about what the module may then do.

NIF loading is detected only as a static import of `:erlang.load_nif/2`. A module that
resolves that call at runtime is not detected, and no static check would make it so;
this is the policy gate being a policy gate, not a sandbox.

Commit uses OTP's prepared loading plus explicit `:sys.suspend/2`,
`:sys.change_code/5`, and resume. Rollback restores both process state and the
preimage without brutal purge.

Cluster rollout is explicit and best-effort, not a distributed transaction:

```elixir
{:ok, deployment} =
  Ouroboros.Upgrade.Coordinator.deploy(signed, [node() | Node.list()],
    migrations: %{node() => [{MyAgent, pid}]},
    health_check: {MyHealth, :ready?, []}
  )

Ouroboros.Upgrade.Coordinator.promote(deployment)
```

An ambiguous remote outcome is quarantined, never described as rolled back. An
ambiguous *prepare* holds a reservation whose token the lost reply was carrying, so
compensation releases it by artifact id through
`NodeExecutor.abort_prepared_reservation/2` instead of leaving the node unable to
prepare anything again. Fast patches are fully privileged inside their VM: the
verifier is a policy gate, not a security sandbox. Independent authorization and
signing should live outside the patchable application, ideally on a separate loader
node or service.

Epoch, receipts, expected module identities, write-ahead operations, and quarantine
state are durably journaled. After a rolled-back introduction the expected identity is
`:non_existing`: absence is a checked expectation rather than a missing one, so a name
that reappears behind the executor's back fails closed exactly like a wrong hash. A
journal this build cannot interpret is quarantined with its evidence intact rather than
coerced or replaced. On executor restart, opaque prepared loader terms are
declared lost. If a commit was interrupted while stateful processes may be suspended,
the journal's verified migration targets are resumed only after their live callback
modules match; the incomplete commit then remains in inspectable quarantine. Committed
module hashes and retained migration processes are also reconciled, and any mismatch
fails closed. A successful code mutation is never reported before its checkpoint;
journal failure triggers compensation or an explicit reconciliation-required outcome.

A commit that fails after code is already visible first attempts the same compensation
a failed migration gets. If that compensation cannot complete, the terminal journal
record keeps the artifact and its migration targets, so the preimages remain restorable
from the journal alone. A quarantined executor refuses every mutating call, rollback
and promote included; `NodeExecutor.reconcile_quarantine/1` re-runs the startup checks
and clears the quarantine only when loaded code matches the journal again, otherwise
returning the diagnostics unchanged.

This lane changes a running node only. Reboot-persistent changes and ERTS upgrades
still require `.appup`/`.relup` release handling; Mix releases do not generate hot
upgrades automatically. See [Architecture](docs/ARCHITECTURE.md).

## Durable OTP releases

The release lane is distinct from fast BEAM patches:

```elixir
alias Ouroboros.Release.{Artifact, RelupBuilder, Runtime}

{:ok, relup} =
  RelupBuilder.build("/staging/ouroboros-0.2.0", ["/staging/ouroboros-0.1.0"], [])

# A controlled packager writes relup.encoded into the release staging tree and
# creates the final .tar.gz. Ouroboros then inspects that exact archive in memory.
{:ok, package} = Artifact.inspect_package("/srv/releases/ouroboros-0.2.0.tar.gz")
{:ok, ^package} = Runtime.inspect_package("/srv/releases/ouroboros-0.2.0.tar.gz")
```

Inspection checks archive paths/types/sizes, `.rel`, `start.boot`, `relup`, and
`.appup` consistency without extracting or loading code. Runtime mutation requires an
ephemeral capability from an independently configured `Release.Authorizer`; the
shipped authorizer denies every mutation. Authorized `unpack`, `check_install`,
`install`, and `make_permanent` operations are write-ahead journaled and reconciled
against `:release_handler.which_releases/0` after restart. Before unpack, the one
verified archive snapshot is durably published under its SHA-256 name; OTP receives a
same-inode alias whose name is derived from the validated top-level `.rel`. The release
directory must be writable only by the deployment identity. An ambiguous result
quarantines the lane.

The tests exercise real archives and a deterministic handler adapter. They do not
prove an actual embedded release installation, restart continuation, ERTS change, or
reboot permanence. Those require a deployment-specific release fixture and rehearsal.

## Production configuration

Production startup requires a durable directory:

```sh
export OUROBOROS_DATA_DIR=/var/lib/ouroboros
export OUROBOROS_WORKSPACE_ROOTS=/srv/agent-worktrees
export OUROBOROS_UPGRADE_TRUSTED_SIGNERS="release-key:$(base64 < release-key.pub)"
MIX_ENV=prod mix release
```

Production fails closed on unsigned patches. `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` is the
injection point for trusted Ed25519 public keys: comma-separated
`signer_id:base64_ed25519_public_key` entries, each key exactly 32 raw bytes. A
malformed or duplicated entry stops the boot rather than quietly narrowing the trusted
set, and an unset variable trusts nobody, so every artifact is rejected until keys are
supplied by the deployment's configuration boundary. Release and fast-patch journals use
a file-and-parent-directory-synced checkpoint adapter; the other domain aggregates use
single-owner atomic file checkpoints.

## Current limits

- The default domain stores are ETS in development/test and one atomic file-backed
  aggregate in production. Release and fast-patch mutation journals add file and
  directory sync before acknowledging a checkpoint. All remain single-node ownership,
  not transactional HA databases.
- Terminal coding tasks and interactive sessions are the only durable state that is
  ever retired. Their recovery loops sweep entries older than
  `:ouroboros, :terminal_retention_ms` (seven days by default, `nil` disables the
  sweep), and `Store.delete/1` refuses anything non-terminal. Team, orchestration,
  control, upgrade, and release aggregates still only accumulate; sizing them is an
  operator concern until each plane grows its own retention policy.
- Harness runs survive callers and Ouroboros coordinator crashes, but not a full
  Harness application/BEAM/host restart. Ouroboros retains the task and reports
  `:lost`; automated resume/retry policy is future work.
- Provider installation, authentication, billing, and actual repository effects are
  external gates. The test suite uses a deterministic adapter and does not spend an
  inference call.
- `jido_harness` 2.0 is pinned from Git because it is not currently published on Hex.
- Team, orchestration, interactive-session, control, upgrade, and release state is
  restart-persistent in production's configured stores. Only the two mutation journals
  use the stronger synced adapter; none of these single-node aggregates is HA consensus.
- Interactive Harness processes, like detached runs, do not survive a full BEAM or
  host restart. Durable Ouroboros intent remains inspectable, but the local session
  becomes `:lost` unless the provider process still exists.
- Workspace admission is node-local and does not provision worktrees or an OS
  sandbox. Shared filesystems need one routed authority or consensus.
- Autonomous evaluation is implemented with bounded revisions and step count, but
  aggregate token/cost/time budgets, independent policy approval, and behavioral
  regression scoring remain.
- Release metadata construction, archive inspection, authorization, and journaling are
  implemented; full tar assembly and a real `HandlerAdapter.OTP` reboot rehearsal are
  deployment gates.
- There is no polished terminal UX yet. `Ouroboros.status/0` is the inspectable API
  snapshot and reports per-plane availability separately from empty result lists.

The next architecture steps and stop conditions are tracked in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
