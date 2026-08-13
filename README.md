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
- a signing service on a role-isolated node: the key read at boot from a file that node
  mounts, an independent policy applied to the whole artifact before any signature
  exists, and a durable journal of every decision;
- offline OTP release metadata/archive validation plus a deny-by-default,
  write-ahead-journaled `:release_handler` control boundary;
- a token-authenticated loopback operator gateway, and `ouro` — one binary that carries
  a release, extracts it, starts it, and attaches to it, or attaches to one already
  running somewhere else; and
- real two-node behavior in tests using an OTP `:peer` OS process.

It does **not** yet provide partition-safe placement, durable provider execution
across a full BEAM/host restart, signing custody outside the cluster's distribution
trust domain, or aggregate cost budgets. The OTP release adapter is implemented, but a
real packaged-release install/reboot rehearsal remains an external deployment gate.

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

## Terminal UI

`ouro` is the terminal client, in `tui/`. It does two different jobs and the difference
matters: it can **spawn** a runtime — start one as a child process, own its lifecycle,
and attach to it — or it can **attach** to one somebody else started, on this host or
through a tunnel.

```sh
ouro                    # spawn a runtime, or adopt one already running here, then attach
ouro daemon             # spawn only: print the port, pid, and token file, then exit
ouro attach             # connect to the runtime published in this data directory
ouro attach --addr 127.0.0.1:4560 --token-file ~/.ouro-token
ouro new --provider claude --workspace .   # start a session and drop into the UI
ouro stop               # ask the runtime this client started to shut down
ouro version            # client version, embedded release version and digest, protocol
ouro --dev              # start `mix run --no-halt` in this checkout instead
```

Build it from a checkout. ERTS is not cross-compiled, so the binary is only valid for
the machine that built it:

```sh
make ouro    # mix release, then that tarball baked into tui/target/release/ouro
make dist    # the same, copied to dist/ouro-<version>-<target triple>
```

There is no `--token` flag anywhere, deliberately: a secret on a command line is
readable by every process on the host for as long as the command runs. A spawning client
writes 32 bytes of OS randomness to a 0600 file beside `gateway.json` and tells the
gateway the path.

### How a client finds a runtime

The runtime binds an ephemeral port and publishes it to `gateway.json` in
`OUROBOROS_DATA_DIR`, alongside its pid, protocol version, and scope. Nothing
pre-chooses a port, so two daemons cannot race for a number one of them picked in
advance. That file is removed on graceful shutdown and left behind by a kill, which is
why it carries a pid: a publication whose pid is dead is stale and is replaced, and a
publication whose pid is *alive* is never overwritten — a daemon this client cannot talk
to is something to report, not something to resolve by starting a second one on top of
it.

A `--dev` daemon gets its own data directory (`ouroboros-dev`), because a development
runtime and a real one that shared `gateway.json` would each be discoverable as the
other.

### Attaching to a server over SSH

The gateway is cleartext and binds loopback. The supported way to reach a remote one is
to forward the port rather than to open the listener:

```sh
# On the server, once: note the port and the token file.
ouro daemon

# On the laptop.
ssh -N -L 4560:127.0.0.1:<port> ops@host &
scp ops@host:~/.local/share/ouroboros/gateway.token /tmp/remote.token
ouro attach --addr 127.0.0.1:4560 --token-file /tmp/remote.token
```

`OUROBOROS_GATEWAY_BIND` can put the listener on a real interface, but the runtime
refuses that boot unless `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` is also set, because the
token and every payload after it would cross the wire in the clear. The refusal names
the tunnel first on purpose.

### What a spawned runtime inherits

`ouro` sets the gateway posture (`OUROBOROS_GATEWAY=1`, scope `operate`, port `0`, the
token file path, `OUROBOROS_DATA_DIR`) and otherwise hands the child the environment it
was called with. On a laptop it also sets `OUROBOROS_DIST=none`: no epmd, no
distribution listener, no cookie on the host at all.

That default steps aside for a real deployment. If the calling environment already
carries `OUROBOROS_CLUSTER_STRATEGY` or `OUROBOROS_NODE`, the cluster variables pass
through untouched and distribution stays on — `rel/env.sh.eex` refuses the combination
of clustering and `OUROBOROS_DIST=none` outright, and an operator who configured a
cluster did not ask a terminal client to reconsider it. Everything else about an
existing server workflow is unchanged, because nothing else is set.

### Keys

`?` opens the help with the current key map. It is the authority; a README that listed
bindings would be the second place they are written down and the first place they go
stale.

### Honest limits

- **The token is transport authentication, not a sandbox.** It decides who may open a
  connection and at what scope. It does not constrain what the runtime does once a
  connection is open: an `operate`-scope client can drive sessions and agents, and the
  gateway's authority is the runtime's authority.
- **Loopback is the security boundary.** The protocol has no transport encryption.
  `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` does not add any — it only stops the runtime from
  refusing to bind a non-loopback address. Use the tunnel.
- **The view is single-node.** The client speaks to exactly one gateway and renders that
  node's state. Connected peers appear as names; their sessions, agents, and plans do
  not. Cross-node listing is deferred, not hidden.
- **In attach mode there are no logs.** A spawning client pipes the runtime's output
  into a bounded ring it can show you. A client that attached to a process it did not
  start has no access to that process's stdout — the logs live wherever the spawner put
  them (`journalctl`, `daemon.log`, a container log driver).
- **`ouro attach` with no arguments only finds runtimes that published locally.** A
  deployment configured with `OUROBOROS_GATEWAY_TOKEN` in the service environment, or
  one whose `OUROBOROS_DATA_DIR` this user cannot read, is reachable only by naming
  `--addr` and `--token-file` explicitly. There is no discovery beyond the file.
- The UI is new. The gateway protocol has one version and one implementation of each
  half; `hello.protocol` is the entire compatibility contract, and a mismatch prints
  both numbers rather than guessing.

## Agent mesh

```elixir
{:ok, reviewer} = Ouroboros.Mesh.start_agent("reviewer", role: "reviewer")

{:ok, agent} =
  Ouroboros.Mesh.send_message("root", "reviewer", %{request: "inspect mix.exs"})

{:ok, task_id, agent} =
  Ouroboros.Mesh.assign_task("root", "reviewer", "Find dependency risks")
```

Start on a connected node with `Ouroboros.Mesh.start_agent_on/3`. The target is checked
before anything is placed on it: it must be connected and running this runtime in the
`core` role, or the call returns `{:error, {:placement_refused, node, reason}}` — see
[Running a cluster](#running-a-cluster) for what that check is and, more importantly,
what it is not. The directory uses a named `:pg` scope and monitors local Jido
processes. `:global.trans/2` narrows duplicate-start races in a healthy connected
cluster; it is explicitly not a partition-safe consensus protocol.

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

### Heterogeneous plans

A step declares a kind. `:coding` is the default; `:forge` compiles one capability
module and deploys it through the upgrade lane:

```elixir
{:ok, plan} =
  Plan.new("close-the-loop", [
    %{id: "author", input: %{objective: "Write the capability and its tests"}},
    %{
      id: "build",
      kind: :forge,
      dependencies: ["author"],
      input: %{
        module: "Ouroboros.Capability.Echo",
        source_path: "capabilities/echo.ex"
      }
    }
  ])
```

A forge step says only *what* to build. Where source is read from, which nodes
receive it, and which signer is asked stay in trusted runtime configuration:

```elixir
config :ouroboros,
  orchestration_forge_options: [
    workspace: "/srv/agent-worktrees/project",
    nodes: [:"app@host-a", :"app@host-b"],
    signer_id: "release-signer"
  ]
```

Executors are resolved per kind, and `Scheduler.submit/2` refuses a plan naming a
kind it cannot execute before persisting anything — so a forge step never reaches a
deployment that has no forge executor. `Ouroboros.Orchestration.ForgeExecutor` reads
the source under a shared-read workspace lease and uses the durable rollout registry
as its reattachment anchor: a module already live with the same source digest on the
same nodes completes the step without forging again, and an unsettled `:deploying`
record fails the attempt rather than deploying a second time. Plans written before
step kinds existed load as `:coding`.

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
configuration.

`control_allow_forge_steps: true` additionally lets a plan express a forge step
carrying exactly a capability module name and a workspace-relative source path. The
coding-step schema is unchanged by that flag, and the server validates an accepted
plan against the same per-kind rules `Plan.new/3` applies. It is permission to
*describe* a build, not to deploy one: the artifact is still signed by whatever
`:forge_signer` names — the shipped default refuses — and still verified against each
target node's trusted signers. A run remains `:cancelling` while execution callbacks are pending;
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
verifier is a policy gate, not a security sandbox. Independent authorization and signing
live outside the patchable application, on a `signer` node — see
[The signing service](#the-signing-service).

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

## Forging new capabilities

The forge is the path from agent-authored *source* to a live agent module. It is one
call, and every stage of it can refuse:

```elixir
{:ok, source} =
  Ouroboros.Upgrade.Forge.Source.new(
    module: Ouroboros.Capability.Echo,
    author: "planner-agent",
    source: capability_source,
    test_source: capability_test_source
  )

{:ok, signed} = Ouroboros.Upgrade.Forge.forge(source, nodes: nodes, signer_id: "release-key")

{:ok, rollout} = Ouroboros.Upgrade.Rollout.deploy(signed, Ouroboros.Capability.Echo, nodes)
# => rollout.state == :live, and the module is running on every node in `nodes`
```

What happens between those two calls:

1. **Parse-only hygiene.** `Forge.Source.validate/1` reads the module name, parses the
   source and its tests with `Code.string_to_quoted/1`, and walks both ASTs for
   constructs a capability has no business containing: `@on_load`, protocol definitions,
   `Code.*`, `:code.*`, `File.*`, `System.cmd/2`, `Port`, `:os.cmd/1`, `Node.*`, `:erpc`,
   `:rpc`, `Application.put_env/3`, `:persistent_term`, `:ets.give_away/3`,
   `:erlang.load_nif/2`, and spawning onto a named node. Nothing is evaluated or
   compiled, so a rejected source leaves `:code.which/1` answering `:non_existing`.
2. **An isolated build peer.** `Forge.BuildPeer` starts an OTP `:peer` with
   `connection: :standard_io` and `-start_epmd false`. That peer is not distributed —
   `node()` inside it is `:nonode@nohost` — so the candidate compiles and runs its own
   tests where the production cluster is unreachable. The peer is stopped in an `after`
   block on every path, including the build deadline expiring
   (`config :ouroboros, :forge_build_timeout`, 60s by default).
3. **An epoch nobody can reuse.** `Ouroboros.Upgrade.Epoch.next/2` reads `last_epoch`
   from every target node, allocates one above the highest, and writes that number
   durably *before* returning it. A forge that dies between allocating and deploying
   burns the number instead of reissuing it. A node whose status cannot be read is a
   refusal, not a zero.
4. **A signature the forge cannot produce for itself.** `config :ouroboros,
   :forge_signer` names the module asked to sign. The shipped default,
   `Forge.Signer.Deny`, refuses everything; `Forge.Signer.Remote` submits the whole
   artifact to a signing service on a `:signer` node. See
   [The signing service](#the-signing-service).
5. **A health-gated rollout.** `Rollout.deploy/4` checkpoints `:deploying` durably
   before any node is touched, then deploys with
   `health_check: {Rollout.Probe, :ready?, [module]}`. On each target the probe starts
   the new module as a throwaway mesh agent, sends it one synthetic signal, checks the
   answer, and stops it. One failing probe rolls the deployment back everywhere.
6. **An evaluation gate, when the artifact declares one.** Between commit and promotion,
   `Rollout.Evaluation.run/3` drives the artifact's own probe set on every target.

The rollout is recorded in `Ouroboros.Upgrade.Rollout.Registry` as `:deploying`,
`:live`, `:rolled_back`, or `:quarantined`. The last two are never confused: only a
deployment whose every node *proved* it compensated is recorded as rolled back, and any
ambiguity — a lost reply, a node that never answered — is recorded as quarantined.

### Evaluation gates

A health probe proves the new module is alive. That is enough to *modify* a running
system and not enough to *improve* one. An evaluation spec is the missing evidence, and
it is data rather than code, so it can live inside the signed manifest next to the bytes
it judges:

```elixir
eval = %{
  probes: [
    %{input: %{op: "ping"}, expect: {:contains, "ping"}},
    %{input: "again", expect: {:state_matches, :messages_received, 2}}
  ],
  budget_ms: 5_000,
  max_latency_ms: 2_000,
  required: :all
}

{:ok, signed} = Forge.forge(source, nodes: nodes, signer_id: "release-key", eval: eval)
signed.metadata.forge.eval
# => the validated spec, inside the manifest the signature covers

{:ok, rollout} = Rollout.deploy(signed, Ouroboros.Capability.Echo, nodes)
rollout.eval_report.nodes[hd(nodes)]
# => %{passed: 2, failed: 0, total_ms: 3, satisfied?: true, failures: [], ...}
```

Expectations are terms, not functions: `:any_reply`, `{:equals, value}`,
`{:contains, substring}` on the rendered reply, and `{:state_matches, key, value}` read
out of the agent's state through `Ouroboros.Mesh.state/1`. Every probe input and
expectation must be portable, the whole spec is size-bounded, and anything else is
refused by `Evaluation.validate/1` before a build peer boots.

`Rollout.deploy/4` runs the spec on every target through a bounded `:erpc` after the
commit and before the promote — while the rollback material still exists — and then

- every node satisfies its spec → `Coordinator.promote/2`, registry `:live`, report
  recorded;
- any node does not → `Coordinator.rollback/2`, and the usual proof rule decides
  `:rolled_back` or `:quarantined`;
- any node's answer is *ambiguous* — transport fault, deadline, unrecognized shape →
  compensation is still attempted and the record is `:quarantined` regardless of how
  cleanly it succeeded. An evaluation nobody received is not evidence of anything.

With no spec, none of this runs and the behaviour is exactly what it was.

### Champion and challenger

`compare: true` deploys a capability *upgrade*: a `:replace` beam for a module already
live. The same spec runs against the current version on every target first, and the
challenger is promoted only if it passes at least as many probes and stays within
`config :ouroboros, :capability_eval_regression_budget` (1.2×) of the champion's total
time. Both reports land in the registry entry. A replacement is accepted through this
path and no other, because promoting a new version of a live capability without
measuring the one it displaces discards the only baseline that will ever exist.

### Honest limits

- **The deny list is hygiene, not a sandbox.** It catches accidents. It cannot catch a
  macro that expands into the same constructs after the walk has finished, `apply/3`
  with a runtime module, or a name built by `Module.concat/1`. The boundaries that do
  work are the build peer's isolation, the verifier's checks on the loading node, and
  the `Ouroboros.Capability.` namespace policy — and even those are policy, not a jail:
  a loaded capability has exactly the same ambient VM authority as any other module.
- **The build peer is process isolation, not OS isolation.** It runs as the same user
  with the same filesystem and network reach. It cannot talk to the cluster; it can
  still write files the build user can write. Compiling genuinely hostile source needs a
  container or VM around the peer, on a host that is not the production host.
- **The build peer must match its targets.** The artifact is verified against the
  loading node's exact OTP release, Elixir version, and system architecture. Starting
  the peer from this VM's own executable and code path is what makes that true here; a
  remote build service has to establish it another way.
- **Key custody belongs outside the patchable application.** `Forge.Signer.Local` reads
  an Ed25519 key from configuration, which is fine for a dev loop and for tests. In
  production it would put the key inside the blast radius of the code it authorizes: an
  agent that can patch this application can read anything this application can read.
  [The signing service](#the-signing-service) is the shipped alternative — and it
  narrows custody rather than achieving it, because a signer node is still a connected
  cluster member.
- **One module per capability.** A forged capability is exactly one BEAM. The sandbox
  rejects a source that compiles to more, because an artifact carrying one binary cannot
  satisfy references to helper modules no target node has loaded. Helpers must already
  exist on the targets — the shipped `Ouroboros.Agent.Worker.ReceiveMessage` action, for
  example, is a legitimate route target for a forged agent.
- **The probe is liveness; the evaluation is the declared spec and nothing more.** The
  probe proves a capability starts, answers one message, and stops. A report proves the
  probes somebody wrote held, once, on each target, against a throwaway instance. It
  says nothing about inputs nobody wrote a probe for, and `total_ms` is wall-clock on a
  shared VM — a champion/challenger comparison over a handful of probes measures the
  probe set, not production behaviour. Cost models, canary cohorts on real traffic, and
  statistical significance are still external.
- **An `:eval` override is not signed.** A spec in `metadata.forge.eval` is covered by
  the signature; one passed to `Rollout.deploy/4` is the caller's word. Both are
  validated identically, which is a statement about runnability, not about authority.

## The signing service

Everything above is the agent's side of the seam. This is the other side: the piece that
makes "an agent cannot approve its own patch" a property of where code runs rather than a
policy someone remembered to configure.

`Ouroboros.Upgrade.Signing.Service` runs **only** on a `:signer`-role node, whose whole
supervision tree is that process and cluster formation. It loads its key at boot, applies
its own policy to the whole artifact, journals every decision durably, and only then
answers.

### Standing one up

```sh
# On the signer host — 32 raw bytes, or their base64. Never in config, never in a release.
head -c 32 /dev/urandom > /etc/ouroboros/signer.seed && chmod 600 /etc/ouroboros/signer.seed

OUROBOROS_NODE_ROLE=signer
OUROBOROS_SIGNER_KEY_PATH=/etc/ouroboros/signer.seed
OUROBOROS_SIGNER_ID=release-key
OUROBOROS_SIGNING_REQUIRE_EVAL=true    # recommended; see below
```

A `:signer` node with no readable key, an unparseable key, no signer id, or an unusable
journal **refuses to boot**. That is deliberate: a signer that starts anyway and errors
per request is indistinguishable, from the outside, from a signer that is deliberately
denying — and those two need very different responses.

Ask it for the public half and give it to the core nodes:

```elixir
{:ok, info} = :erpc.call(:"signer-1@10.0.0.30", Ouroboros.Upgrade.Signing.Service, :public_info, [])
info.trusted_signers_entry
# => "release-key:aG93ZHkgdGhlcmUsIHRoaXMgaXMgbm90IGEgcmVhbCBrZXk="
```

```sh
# On every core host.
OUROBOROS_SIGNING_NODE=signer-1@10.0.0.30
OUROBOROS_UPGRADE_TRUSTED_SIGNERS="release-key:aG93ZHkgdGhlcmUsIHRoaXMgaXMgbm90IGEgcmVhbCBrZXk="
```

Naming `OUROBOROS_SIGNING_NODE` is what configures `Forge.Signer.Remote`; leave it unset
and the forge keeps the shipped `Deny`. Nothing else about forging changes.

### What the signer checks before a signature exists

The forge hands over the **whole artifact**, not just the payload it wants signed — a
payload is a hash of a manifest, and a manifest is a set of claims. `Signing.Policy`
recomputes the claims:

- **the manifest against the bytes.** sha256, md5, module name, and `vsn` are recomputed
  from every BEAM actually submitted (and from the pre-image of a `:replace`), and the
  same offline gates the loading node applies are applied here: the `-on_load` probe via
  `:code.prepare_loading/1`, static `:erlang.load_nif/2` imports, protocol markers. A
  requester that precomputed a flattering manifest is refused on arithmetic;
- **the namespace, structurally.** Every module must be under `Ouroboros.Capability.`.
  There is no configuration that widens this, so there is no code path on a signer node
  that produces a signature for a control-plane module, whoever asks and however they
  ask;
- **provenance.** `metadata.forge` must carry a `source_sha256` and a test report with
  zero failures and at least one pass. Green-because-everything-was-skipped is refused;
- **declared evaluation criteria**, when `:signing_require_eval` is on: the artifact must
  carry a `Rollout.Evaluation` spec the signer can validate. This is the switch that
  turns "this capability declared, inside its own signature, how it would be judged" into
  a precondition of being signed at all;
- **rate**, per requester per minute, in a sliding window.

Every refusal is a typed `{:refused, reason}`, and every one of them is journaled.

What the signer deliberately does **not** check is anything only a target VM knows: epoch
*ordering* (a signer has no view of any cluster's watermark — it checks only that the
number is a positive integer), whether a `:replace` pre-image is current, and whether an
introduced module is really absent. Those belong to the node executor and survive the
signature untouched.

### Every decision, before every answer

```elixir
{:ok, decisions} = :erpc.call(signer, Ouroboros.Upgrade.Signing.Service, :decisions, [])
# => [%{sequence: 1, artifact_id: "019f…", epoch: 42, decision: :issued,
#       modules: [%{module: Ouroboros.Capability.Echo, disposition: :introduce, sha256: "…"}],
#       requester: :"core-1@10.0.0.11", signer_id: "release-key", findings: %{…}, at: "…"}]
```

Refusals are recorded for the same reason issuances are: a log with only successes
cannot tell "nobody asked" from "something asked two thousand times and was turned away".
The entry is checkpointed through `:signing_journal_storage` — a synced
`Storage.DurableFile` in production — **before** the signature is returned, and a journal
that will not accept the entry is a refusal to sign. The one asymmetry is deliberate and
one-directional: the journal may record an issuance whose reply was lost in transit,
never a signature that reached a requester without a record.

### Honest limits

- **A signer node is still a connected cluster member.** Any node that completes the
  distribution handshake — cookie, and TLS if configured — can `:erpc` into the signing
  service exactly like the forge does, and can do everything else `:erpc` allows on that
  host. What it gets from the service is a *policy decision*: the namespace rule has no
  bypass for any caller. TLS distribution and role isolation narrow this surface. They do
  not eliminate it, and true air-gapped custody — a key on a host that is not a cluster
  member, reached over a narrow audited channel — remains outside this runtime.
- **The requester is self-reported.** The client sends its own node name; the service
  journals it as a claim. The per-requester rate limit therefore bounds accidents, retry
  storms, and honest clients, not an adversary who can vary it.
- **The policy cannot re-run the build.** It proves the submitted bytes are internally
  consistent and correctly namespaced, and that a test report claiming green arrived with
  them. The link between that report and those bytes is the forge's assertion, carried
  inside the signed metadata.
- **There is no human in it.** "Independent" here means independent of the patchable
  application, not independent of the cluster. A review queue is a different thing, and
  this is not one.
- **Key material is redacted, not protected.** The keypair is wrapped in a struct whose
  `Inspect` implementation prints `[REDACTED]`, so a crash report or a logged state
  cannot leak it by accident. Anything running on the signer node can still read the
  process state directly. The boundary that matters is the host, not the struct.

## Agent effects

Everything above is something an *operator* can call. `Ouroboros.Agent.Effects` is the
same set of powers reached by an agent, from inside a signal handler, one grant at a
time:

```elixir
# Nothing is permitted until somebody says so, effect by effect and target by target.
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :forge, modules: [Ouroboros.Capability.Echo])
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :deploy, nodes: nodes)
{:ok, _grant} = Ouroboros.Control.Grants.grant("planner", :start_agent, modules: [Ouroboros.Capability.Echo])

{:ok, signal} =
  Ouroboros.Signals.EffectForgeCapability.new(%{
    from: "planner",
    module: Ouroboros.Capability.Echo,
    source: capability_source,
    test_source: capability_test_source,
    nodes: nodes
  })

{:ok, _agent} = Jido.AgentServer.call(Ouroboros.Mesh.whereis("planner"), signal)
```

Six effects, each with the one allow-list it is checked against: `:start_agent` and
`:forge` take `modules:`, `:stop_agent` and `:send_message` take `agents:`, `:delegate`
takes `teams:`, and `:deploy` takes `nodes:`. Every value may be `:any` or an explicit
list. `granted?/3` is asked about the *concrete attempt*, so a grant to forge
`Ouroboros.Capability.Echo` refuses a request to forge anything else, and a deploy is
refused unless every named node is admitted.

What each effect run does, in order:

1. **Identifies the actor from server-side state.** The principal is the agent's own
   `id`, read from the agent struct the agent server holds. The `from` field on the
   signal is recorded as `claimed_from` and authorizes nothing, so one agent cannot
   spend another's grants by claiming its name.
2. **Asks the authority.** `Ouroboros.Control.Grants` is deny-by-default and durable:
   ETS in development, a synced file checkpoint in production, written before it is
   acknowledged. A refusal is `{:error, {:effect_denied, effect, reason}}`, which Jido
   turns into an error directive — the agent logs it and keeps running.
3. **Runs it off the agent's process, under a deadline.** Effects execute in a
   supervised task bounded by `config :ouroboros, :effect_timeout` (120s). A forge takes
   longer than an agent server should ever sit still, so the signal returns immediately
   and the outcome arrives later.
4. **Records it.** Every attempt — permitted, refused, failed, or timed out — lands in
   the agent's `last_effects` ring alongside the principal, the attempt, and the
   outcome. Artifacts a forge produced are kept in `state.forged`, which is what a
   later `:deploy` resolves; a deploy cannot ship bytes that arrived any other way.

Grants are also why `Ouroboros.Control.Grants` lives where it does. The fast patch lane
refuses to load an artifact naming any `Ouroboros.Control.*` module, so a capability an
agent forged cannot patch the authority that decided it could forge.

### Honest limits

- **This is not a sandbox, and grants are not a capability system.** They gate the
  action layer: the signals a well-behaved agent flow travels through. Any loaded BEAM
  can call `Ouroboros.Mesh.start_agent/2`, `Ouroboros.Upgrade.Forge.forge/2`, or
  `Ouroboros.Control.Grants.grant/3` directly, without an effect action anywhere in
  sight. The boundaries that hold against code that does not cooperate are the
  verifier's namespace policy, artifact signing, and the isolated build peer.
- **An agent cannot widen its own authority through this surface**, because no grant
  effect exists. That is a property of the surface, not of the VM.
- **The authority is node-local.** Each node runs its own `Grants` process over its own
  checkpoint, so an agent granted `:forge` on one node is not granted it on another.
  Like every other store here, that is single-node ownership rather than a replicated
  policy service.
- **A failed revocation leaves the grant standing** and says so. An authority that
  forgot a grant it could not durably forget would hand it back at the next restart, so
  an unacknowledged revocation has not happened.
- **The trail is a ring, not a ledger.** `last_effects` keeps the most recent 20
  entries and `state.forged` the most recent 5 artifacts; both die with the agent.
  Durable effect audit belongs in a store, and is not implemented.

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

Node identity, role, cluster formation, and distribution transport are covered
separately in [Running a cluster](#running-a-cluster).

The forge signs with whatever `config :ouroboros, :forge_signer` names, and the shipped
default refuses to sign anything. Set `OUROBOROS_SIGNING_NODE` to a `:signer` node and
that becomes `Forge.Signer.Remote`, which submits the whole artifact to a key this
application cannot read — see [The signing service](#the-signing-service) for standing
one up. Configuring `Forge.Signer.Local` in production would instead put the key in the
configuration of the application whose code it authorizes, which is the same as letting
the agent approve its own code.

| Variable                                  | Read by | Meaning                                                    |
| ----------------------------------------- | ------- | ---------------------------------------------------------- |
| `OUROBOROS_SIGNER_KEY_PATH`               | signer  | file holding the Ed25519 seed: 32 raw bytes or their base64 |
| `OUROBOROS_SIGNER_ID`                     | signer  | the identity this node signs as; must match the trusted-signers entry |
| `OUROBOROS_SIGNING_REQUIRE_EVAL`          | signer  | `true` refuses to sign an artifact declaring no evaluation spec |
| `OUROBOROS_SIGNING_RATE_LIMIT_PER_MINUTE` | signer  | admissions per requester per minute (default 30)           |
| `OUROBOROS_SIGNING_NODE`                  | core    | the signer node the forge submits to; unset keeps `Signer.Deny` |
| `OUROBOROS_SIGNING_CALL_TIMEOUT_MS`       | core    | signing deadline (default 15000)                           |

A node booted with `OUROBOROS_NODE_ROLE=signer` refuses to start unless the key path
names a readable file and the signer id is set — checked once in `config/runtime.exs`
with a message naming the variable, and again by the service when it loads the key.

Production fails closed on unsigned patches. `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` is the
injection point for trusted Ed25519 public keys: comma-separated
`signer_id:base64_ed25519_public_key` entries, each key exactly 32 raw bytes. A
malformed or duplicated entry stops the boot rather than quietly narrowing the trusted
set, and an unset variable trusts nobody, so every artifact is rejected until keys are
supplied by the deployment's configuration boundary. Release and fast-patch journals use
a file-and-parent-directory-synced checkpoint adapter; the other domain aggregates use
single-owner atomic file checkpoints.

## Running a cluster

Until now every node in this README connected because something outside it said so.
`Ouroboros.Cluster` owns the other half: which tree a node boots, and how it finds the
others.

### Node roles

A node boots exactly one role, from `OUROBOROS_NODE_ROLE` (default `core`):

| Role      | Supervision tree                                   | What it is for                          |
| --------- | -------------------------------------------------- | --------------------------------------- |
| `core`    | the full runtime — mesh, teams, sessions, journals, scheduler, control plane | running work |
| `builder` | cluster formation only                              | compiling forged capabilities off the production host |
| `signer`  | cluster formation plus `Upgrade.Signing.Service`    | holding the signing key, policy, and decision journal where nothing else on the host can reach them |

A `builder` and a `signer` run *this same release*, booted differently. That is not
convenience: the forge's artifact is verified against the loading node's exact OTP
release, Elixir version, and architecture, so a builder that is not runtime-identical to
its targets produces BEAMs every target rejects. One artifact, one runtime, three roles.

An unrecognized role refuses the boot rather than falling back to `core`. So does a
`signer` whose key is missing or malformed — see
[The signing service](#the-signing-service).

```sh
OUROBOROS_NODE_ROLE=builder    # this host only compiles
```

Point a core node at a builder and forge builds relocate with no other change:

```sh
OUROBOROS_FORGE_BUILDER_NODE=builder-1@builder-1
```

The build still happens inside a non-distributed `:peer` — it simply happens on the
builder's host now. A builder that is unreachable, not running this runtime, or not
actually in the `builder` role is refused with
`{:error, {:forge_builder_refused, node, reason}}` rather than silently building
locally.

### Formation

`OUROBOROS_CLUSTER_STRATEGY` is `none` by default; nothing forms until you name one.

| Strategy | Variables                                                             |
| -------- | --------------------------------------------------------------------- |
| `none`   | —                                                                     |
| `epmd`   | `OUROBOROS_CLUSTER_HOSTS` (comma-separated node names)                |
| `gossip` | `OUROBOROS_CLUSTER_GOSSIP_SECRET`, `OUROBOROS_CLUSTER_GOSSIP_PORT` (both optional) |
| `dns`    | `OUROBOROS_CLUSTER_DNS_QUERY`, `OUROBOROS_CLUSTER_DNS_BASENAME` (defaults to this node's name) |

`OUROBOROS_CLUSTER_RECONNECT_MS` (default 5000) is the retry interval, not a deadline —
it is what makes boot order irrelevant. A strategy that is named but missing its
variables refuses the boot; it does not quietly run unformed.

### Distribution TLS

Cleartext Erlang distribution puts the shared cookie, and everything after it, on the
wire. Generate a private CA and one certificate per node:

```sh
# One CA for the cluster. Only nodes holding a certificate it signed can handshake.
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.pem -subj "/CN=ouroboros-dist-ca"

# One key and certificate per node.
openssl req -newkey rsa:4096 -nodes -keyout core-1.key -out core-1.csr \
  -subj "/CN=core-1"
openssl x509 -req -in core-1.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -out core-1.pem
```

The `ssl_dist_optfile` is an Erlang term file — one list, ending in a period, with a
`server` and a `client` section. Both sides must verify, or only half the handshake is
authenticated:

```erlang
%% /etc/ouroboros/dist_tls.conf
[{server, [{certfile, "/etc/ouroboros/tls/core-1.pem"},
           {keyfile,  "/etc/ouroboros/tls/core-1.key"},
           {cacertfile, "/etc/ouroboros/tls/ca.pem"},
           {verify, verify_peer},
           {fail_if_no_peer_cert, true},
           {versions, ['tlsv1.3']}]},
 {client, [{certfile, "/etc/ouroboros/tls/core-1.pem"},
           {keyfile,  "/etc/ouroboros/tls/core-1.key"},
           {cacertfile, "/etc/ouroboros/tls/ca.pem"},
           {verify, verify_peer},
           {versions, ['tlsv1.3']}]}].
```

`vm.args` is a static file the emulator reads with `-args_file`: it has no shell and no
runtime interpolation. So the distribution flags are read from the **build**
environment and baked into the artifact:

```sh
export OUROBOROS_DIST_TLS=1
export OUROBOROS_DIST_TLS_OPTFILE=/etc/ouroboros/dist_tls.conf
export OUROBOROS_DIST_PORT_MIN=9100   # optional: pin the listener for a firewall
export OUROBOROS_DIST_PORT_MAX=9105
MIX_ENV=prod mix release
```

`OUROBOROS_DIST_TLS=1` without an optfile fails the build rather than producing a
release that cannot start distribution. The same flags are rendered into
`remote.vm.args` so `bin/ouroboros remote`, `rpc`, and `stop` can still reach the node;
the port pinning deliberately is not, because a remote shell must not bind the port the
running node already holds.

At boot, `config/runtime.exs` reads the transport the VM is actually running. A node
that forms a cluster over cleartext distribution refuses to start unless
`OUROBOROS_ALLOW_INSECURE_DIST=1` says that is intended.

### Three nodes

One image, three roles:

```yaml
# docker-compose.yml — built with OUROBOROS_DIST_TLS=1
x-node: &node
  image: ouroboros:0.1.0
  command: ["/app/bin/ouroboros", "start"]
  volumes: ["./tls:/etc/ouroboros/tls:ro", "./dist_tls.conf:/etc/ouroboros/dist_tls.conf:ro"]

x-env: &env
  OUROBOROS_COOKIE: ${OUROBOROS_COOKIE:?set a cookie}
  OUROBOROS_DATA_DIR: /var/lib/ouroboros
  OUROBOROS_CLUSTER_STRATEGY: epmd
  OUROBOROS_CLUSTER_HOSTS: core-1@core-1,core-2@core-2,builder-1@builder-1

services:
  core-1:
    <<: *node
    hostname: core-1
    environment:
      <<: *env
      OUROBOROS_NODE: core-1@core-1
      OUROBOROS_NODE_ROLE: core
      OUROBOROS_FORGE_BUILDER_NODE: builder-1@builder-1

  core-2:
    <<: *node
    hostname: core-2
    environment:
      <<: *env
      OUROBOROS_NODE: core-2@core-2
      OUROBOROS_NODE_ROLE: core
      OUROBOROS_FORGE_BUILDER_NODE: builder-1@builder-1

  builder-1:
    <<: *node
    hostname: builder-1
    environment:
      <<: *env
      OUROBOROS_NODE: builder-1@builder-1
      OUROBOROS_NODE_ROLE: builder
```

`bin/ouroboros` refuses a blank `OUROBOROS_NODE` or `OUROBOROS_COOKIE` before the VM
starts, and refuses a short name, because `RELEASE_DISTRIBUTION=name` needs `name@host`.
Without that refusal the release would fall back to the release name and to the random
cookie baked into `releases/COOKIE` at build time — a cluster secret nobody chose and
nobody can rotate.

Once up, `Ouroboros.status()` reports the local role, the roles it can see, the
formation strategy, and the distribution posture (`security.cookie` is `:set` or
`:unset`, never the cookie itself):

```elixir
Ouroboros.Cluster.role()               #=> :core
Ouroboros.Cluster.nodes_by_role(:core) #=> [:"core-1@core-1", :"core-2@core-2"]
Ouroboros.status().cluster.security    #=> %{distributed: true, proto_dist: :inet_tls, tls: true, cookie: :set}
```

Topology churn is logged as it happens, with the arriving node's role, because
`Node.list/0` can show what is connected now but never what left.

### Honest limits

- **The cookie and TLS are transport authentication, not authorization.** They decide
  who may complete the distribution handshake. They decide nothing about what a node
  may then do — and the answer is *everything*. Any connected node can `:erpc` any
  exported function on any other node, load code, read that node's application
  environment (including a configured signing key), and kill its processes.
- **Placement checks are misconfiguration detection.** `Mesh.start_agent_on/3` and a
  team's `:node` option refuse a target that is not a connected `core` node running this
  runtime, and the forge refuses a builder that is not in the `builder` role. That stops
  work being sent where it cannot run. It stops nothing a hostile connected node decides
  to do, because that node never has to call these functions at all. The same is true of
  the `Ouroboros.Capability.` namespace policy and the protected-module list.
- **Roles reduce blast radius; they do not contain a compromise.** A builder holds no
  teams, sessions, journals, grants, or control plane, so compromising it yields a
  compiler rather than a fleet. A signer holds one process, whose policy refuses a
  control-plane patch to every caller alike — but the host is still a fully authorized
  cluster member, so a connected node can call the signing service, and can reach the
  signer's VM by every other route `:erpc` offers. Real containment needs the build and
  signing hosts outside the cluster's trust domain entirely, reached by something
  narrower than Erlang distribution.
- **Formation is not fencing.** libcluster connects nodes. It has no quorum, no
  partition policy, and no opinion about a node that comes back with stale state.
  `:global.trans/2` narrows duplicate-start races in a *healthy connected* cluster and
  is not partition-safe consensus.
- **The distribution flags are baked at build time.** Changing TLS or the port range
  means building a new release, or pointing `RELEASE_VM_ARGS` at a file you maintain.
- **EPMD is still in the path** for the `epmd` and `dns` strategies: its port (4369)
  has to be reachable even when the distribution listener is pinned elsewhere.

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
- Cluster formation is implemented (libcluster: static epmd, gossip, DNS polling) and
  off by default, and nodes boot a role-shaped tree. Formation is not fencing: there is
  no quorum, no partition policy, and no reconciliation of a node that returns with
  stale state. Role separation reduces blast radius and does not contain a compromised
  node, which retains full `:erpc` authority over every node it is connected to.
- The forge compiles and tests candidate capabilities in an isolated, non-distributed
  build peer, and that peer can now run on a least-privileged `builder` node. It still
  shares that host's user, filesystem, and network, and a builder is still a fully
  authorized cluster member. Real OS sandboxing is external. Capability rollout records
  accumulate; only settled `:rolled_back` entries are pruned when the store exceeds
  `:ouroboros, :capability_rollout_limit`.
- Signing runs on a `signer` node: the key is read at boot from a file that host mounts,
  an independent policy recomputes the full artifact and structurally refuses anything
  outside `Ouroboros.Capability.`, and every decision is journaled durably before a
  signature is returned. What is still external is custody *outside the distribution
  trust domain* — a signer node is a connected cluster member, so any node that
  completes the handshake can call the service and reach that VM by other routes. The
  requester identity behind the rate limit is self-reported, and there is no human
  review queue. Signing decisions accumulate up to
  `:ouroboros, :signing_journal_limit`, then trim oldest-first.
- Evaluation gates run a signed, declarative probe set on every target between commit
  and promotion, and champion/challenger holds a replacement to the version it displaces
  on pass count and total time. What that does not do: model cost, sample real traffic,
  run a canary cohort, or say anything statistically meaningful about wall-clock over a
  handful of probes. `:capability_eval_regression_budget` defaults to 1.2× for that
  reason, and a report is evidence about the declared spec and nothing else.
- Agent effect grants are node-local, deny-by-default, and durable per node. They
  constrain the agent action layer and nothing below it: loaded code reaches the same
  public APIs directly. The effect audit trail is a bounded in-memory ring on the acting
  agent, so it does not survive that agent. Per-principal rate and cost budgets, a
  replicated policy authority, and a durable effect log are not implemented.
- Release metadata construction, archive inspection, authorization, and journaling are
  implemented; full tar assembly and a real `HandlerAdapter.OTP` reboot rehearsal are
  deployment gates.
- The terminal client is new, and it is a client: `ouro` renders one node through the
  gateway, at the scope that node's listener was booted with, over a cleartext loopback
  socket. Its token authenticates a connection and sandboxes nothing; there is no
  cross-node view, no log stream to an attached client, and no discovery beyond
  `gateway.json`. `Ouroboros.status/0` remains the inspectable API snapshot underneath
  it, and still reports per-plane availability separately from empty result lists.
- CI exists as two GitHub Actions workflows and has never run: this repository has no
  git remote, so no push, pull request, or tag has ever reached a runner. The four-target
  release matrix is a statement about ERTS — a release is only valid on the OS and
  architecture that built it — not a record of four builds that happened.

The next architecture steps and stop conditions are tracked in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
