# Ouroboros architecture

## Definition of done for this slice

This slice is complete when all of the following are executable and tested:

1. A logical Jido worker can be supervised locally and addressed from another BEAM
   node through a typed signal.
2. A provider-neutral coding request can outlive its caller, emit durable ordered
   events, be replayed without gaps, survive its Ouroboros coordinator crashing, and
   resolve to explicit completed/failed/cancelled/lost state.
3. A compatible BEAM module can be loaded with an explicit state migration and rolled
   back in place, while policy-protected control modules reject self-patching.
4. A durable DAG and opt-in planner/evaluator can dispatch through a supervised team,
   revise within a fixed budget, and preserve cancellation intent across restart.
5. A complete OTP upgrade archive can be inspected and its `:release_handler`
   lifecycle can be gated and journaled through an injected deterministic adapter.
6. Agent-authored source for a new capability module can be validated without being
   evaluated, compiled and tested in an isolated non-distributed build peer, signed
   through a seam the forge cannot satisfy itself, stamped with a durably allocated
   epoch, deployed behind a per-node health probe, held to a declarative evaluation spec
   carried inside its own signature, and — when the probe or that spec fails — rolled
   back to absence on every node, or quarantined when the evidence is ambiguous.
7. An agent driven only by typed signals can do all of that itself — start and stop mesh
   agents, message them, delegate through a team, forge a capability and deploy it —
   with every attempt authorized against a durable deny-by-default grant for the
   concrete target, identified from server-side agent state rather than the signal,
   bounded so no effect blocks the agent, and recorded whether it ran or was refused.
8. Nodes form a cluster without anyone connecting them by hand, boot a role-shaped tree
   (`:core` full, `:builder` formation-only, `:signer` formation plus the signing
   service), refuse to place work on a node that cannot run it, relocate forge builds
   onto a least-privileged builder, and ship as one release whose node identity, cookie,
   and distribution transport are explicit and fail closed on the distributed path —
   told nothing at all, the release boots a standalone single-machine posture instead,
   with distribution off and no cookie in existence.
9. The signing authority runs on a `:signer` node rather than inside the application it
   authorizes: the key is read at boot from a file that node mounts, an independent
   policy recomputes the whole submitted artifact and refuses anything outside
   `Ouroboros.Capability.`, and every decision — issued and refused — is durably
   journaled before any signature is returned.
10. The documentation distinguishes those proofs from partition tolerance, full-host
    provider durability, billing, real repository effects, OS-level sandboxing of
    generated code, signing custody *outside the distribution trust domain*, evaluation
    beyond a declared spec, a real packaged-release install/reboot rehearsal, any claim
    that effect grants sandbox loaded code, and any claim that node roles, placement
    checks, or signer isolation constrain a node that has already completed the
    distribution handshake.

The first nine are local implementation claims backed by deterministic tests. None
imply the external claims in item ten.

## Planes and ownership

### Cluster plane

`Ouroboros.Cluster` owns two things nothing else may decide: which tree this node boots,
and how it finds the others.

Role (`:core`, `:builder`, `:signer`) is resolved once, at application start, before any
child is supervised — an unrecognized role raises rather than booting the privileged
tree. `:core` starts the full runtime. `:builder` starts formation and nothing else,
because a forge build is `:peer.start/1` plus a call. `:signer` starts formation and one
process: `Upgrade.Signing.Service`, which holds the key, applies the signing policy, and
journals every decision. That process leads the `rest_for_one` chain on a signer, so the
node is not askable before its key is loaded, and it refuses to boot — key missing,
malformed, unidentified, or journal unusable — rather than starting into a state where
denial and misconfiguration look identical.

Formation is libcluster, off by default, selected by `OUROBOROS_CLUSTER_STRATEGY`. It
sits at the *tail* of the application's `rest_for_one` chain on purpose: it connects and
observes, and nothing downstream rebuilds state from it, so a discovery strategy's crash
must not restart the durable owners above it.

Invariant: role is a placement fact, not an authority boundary. Every check that reads a
remote role also requires the target to be connected and running this runtime, and the
answer is only ever an observation about a cooperative cluster — see "Safety
boundaries".

### Team plane

`Ouroboros.Mesh` owns logical IDs and placement. Each member is a real
`Jido.AgentServer` under `Ouroboros.Jido` supervision. A local directory monitors the
PID and joins it to `{:ouroboros_agent, logical_id}` in a named `:pg` scope.

Typed Jido signals are the team protocol. Cross-node calls work because Erlang PIDs
and monitors are distribution-native. `:erpc` is used when an operation must execute
inside a selected node's ownership boundary.

Invariant: a PID is an observation, not durable identity. Callers retain logical IDs
or coding task references, never persist PIDs.

`Ouroboros.Team.Server` owns one inspectable Jido coordinator, local Jido children,
explicit remote Mesh members, and delivery of persisted coding results. Remote worker
relationships are marked `:mesh_remote` because Jido 2.3.3's child-adoption liveness
check is local-only. One worker has at most one active delegation. Team state remains
in a serializable `Team.Snapshot` checkpoint containing logical IDs, nodes, task
references, cursors, and results—but never runtime PIDs. A crashed server rebuilds or
adopts agent projections, atomically resubscribes each in-flight coding task, and
retries terminal delivery. Public delegation IDs are scoped to their team; an internal
SHA-256 identity over team and delegation names the CodingSession, while a private
random origin digest proves the task was created by that delegation before adoption or
cancellation. Coordinator startup is a serialized claim in the Jido agent, and every
adoption, signal, and cleanup path rechecks the exact module/team/coordinator owner.
The coordinator is monitored. Deliberate closure moves through a durable `:closing`
state that retries cancellation and terminal delivery before cleanup.

Above teams, `Ouroboros.Orchestration.Scheduler` owns a durable dependency graph.
It persists claims before invoking an executor, caps cluster-local concurrency,
unlocks fan-out/fan-in, and propagates failure and cancellation. A stable execution
token survives owner or scheduler restart; `TeamExecutor` reuses that token as the
team delegation ID, from which Team derives the namespaced CodingSession identity.
This closes the local checkpoint/start retry window while the same Harness journal is
queryable; it is not provider-side exactly-once billing across a full VM or host loss.

A plan is heterogeneous. Each step declares a kind — `:coding`, or `:forge` for one
compile-and-deploy of a capability module — and the scheduler resolves one executor per
kind. Per-kind input schemas are enforced in `Plan`, so a forge step carries exactly a
capability-namespaced module name and a contained relative source path and nothing that
could choose a workspace, a node, or a signer. `submit/2` refuses a plan naming a kind
this scheduler cannot execute before the plan is persisted; a scheduler with no
executors is manual mode and accepts any kind because the caller drives every step.
Snapshots written before kinds existed load as `:coding`, and a kind this build does not
know is refused rather than coerced.

`Ouroboros.Orchestration.ForgeExecutor` runs forge steps through `Upgrade.Forge` and
`Upgrade.Rollout`, reading source under a shared-read workspace lease. Forging is not
naturally idempotent, so the durable rollout registry is the reattachment anchor: a
module already `:live` with the same source digest on the same nodes completes the step
without a second build or epoch, and a `:deploying` record — ambiguity — fails the
attempt with a retryable error rather than deploying twice. The check is not atomic with
the build that follows it; what makes a lost race explicit rather than silent is
underneath, in monotonic epochs and a node's refusal to introduce a module it already
has.

`Ouroboros.Control.Server` owns the objective-level loop. It checkpoints deterministic
planning/evaluation request IDs, the candidate plan, revision history, and cancellation
intent. Provider callbacks run outside the server so one slow inference does not block
inspection or cancellation of other runs. Generated plans may contain only execution
objectives and graph dependencies; trusted runtime configuration supplies worker,
provider, workspace, sandbox, and approval policy. Jido.AI is the production adapter,
but is opt-in and disabled at application startup by default. Cancellation remains
pending until the scheduler has durable per-step callback evidence; that evidence says
whether no execution existed, a request was accepted, or provider termination remains
unconfirmed. It never equates request acceptance with an observed provider exit.

`:control_allow_forge_steps` (default false) widens what a plan may express by exactly
one shape: a step of kind `forge` whose input is a capability module name and a
workspace-relative source path. The coding-step schema is unchanged by the flag, both
planner branches refuse unrecognized keys, and the server re-validates the accepted plan
against the same per-kind rules `Plan` applies. Enabling it grants no deployment
authority: the forged artifact is still signed by whatever `:forge_signer` names —
`Signer.Deny` in production unless an operator changed it — and still verified against
each target node's trusted signers, and a scheduler with no forge executor refuses the
plan outright.

### Coding execution plane

`Jido.Harness` owns provider processes, provider-specific argv/protocol mapping,
normalized events, cancellation, and short-lived retained journals. Ouroboros does
not wrap those CLIs in a second tool loop.

`Ouroboros.CodingSession` owns domain truth:

- the objective, workspace, provider, owner node, and normalized request policy;
- the Harness run ID and provider resume ID;
- a durable exclusive Harness cursor and a separate Ouroboros event sequence;
- bounded redacted replay, terminal result, and explicit loss state; and
- node-aware info/replay/subscribe/await/cancel routing.

One `Ouroboros.Coding.Task` GenServer serializes transitions for a task. It explicitly
polls `Jido.Harness.Run.replay/2`, persists cursor plus projected events in one
checkpoint, and only then broadcasts them. `subscribe/2` registers and snapshots the
backlog in that same process, eliminating the replay-then-subscribe race.

When workspace roots are configured, that same coordinator owns a symlink-resolved
lease before it inspects or starts Harness. Read-only work shares a root; write work
is exclusive against overlapping roots. The private release capability is never
checkpointed. A coordinator crash releases via monitoring, then recovery reacquires
before reattachment. Durable nonterminal owners become fail-closed recovery
reservations across manager or downstream-registry restart; only the exact registered
coordinator can claim one. This authority is node-local.

The coordinator scans live Harness metadata before starting a missing run. That
closes the crash window between `Run.start/2` and saving the returned run ID, where an
unconditional retry could otherwise launch duplicate billable work.

Harness run ownership is node-local. A disconnected remote owner is unavailable; a
run becomes lost only when its confirmed owner reports `:not_found`.

`Ouroboros.InteractiveSession` applies the same ownership model to Harness sessions.
It checkpoints session configuration, logical turn intents, Harness turn IDs,
redacted events, terminal results, and an exclusive cursor. Multi-turn follow-ups,
native steering, approval responses, and interruption remain provider-capability
gated. A coordinator restart reattaches to the same live Harness session; a full
Harness/BEAM restart cannot reconstruct the provider process and resolves to `:lost`.

### Evolution plane

`Ouroboros.Upgrade.NodeExecutor` is a policy-protected node-local authority. It accepts
signed, content-addressed bundles of already compiled BEAMs and their exact
preimages. Compilation and tests belong in an isolated build peer, never inside the
production loader.

Fast-lane transaction:

1. Verify runtime, signature, exact base hashes, policy, epoch, and module features.
2. Ask the code server to prepare the complete batch.
3. Suspend only declared stateful processes.
4. Atomically finish loading the batch.
5. Invoke explicit `code_change/3` migrations and resume.
6. Run health checks through the cluster coordinator.
7. Promote with soft purge, or downgrade state and restore preimages.

Never brutal-purge. If retired code remains on a process stack, quarantine the node
and retain rollback material. Retention is literal: when a commit fails at or after the
point where code became visible and compensation cannot finish, the terminal journal
record keeps the artifact and its migration targets rather than clearing the only
durable copy of the preimages.

Each module in an artifact carries a disposition. `:replace` is the transaction above.
`:introduce` loads a module that has never existed in this VM: no preimage is captured,
step 7 inverts to an unload (`:code.delete/1` then soft purge), and the identity the
node then expects for that module is `:non_existing` — a checked expectation, so a name
that reappears fails closed like a wrong hash would. Introduced modules cannot be
declared stateful, because a module nothing is running has no state to migrate, and the
retained rollback material for one is only its name: there are no preimage bytes to
keep when the way back is an unload. Unloading is not exempt from the no-brutal-purge
rule, so a process still executing introduced code yields
`{:introduced_code_in_use, module}` and quarantine. A single artifact may mix both
dispositions and commits or rolls back as one transition.

An introduction is additionally required to be absent — unloaded, unreachable on the
code path, and not already expected by the journal — and to be named under
`Ouroboros.Capability.`, the namespace `Ouroboros.Mesh` reserves for agents forged at
runtime. Neither rule makes introducing a module safer than replacing one. Any accepted
BEAM has full ambient VM authority however it arrived; the namespace gate only prevents
a new module from silently occupying an existing name.

Policy protects the modules that make these guarantees enforceable, not just the loader:
`Ouroboros.Upgrade.*`, `Ouroboros.Storage.*` (a patched journal writer makes every
write a silent no-op), `Ouroboros.Release.*` (the durable lane's authorizer), and
`Ouroboros.Control.*` (which decides what gets patched), plus the application root and
its registry owner. On-load functions are detected by preparing the batch, because
`-on_load` lives in the Code chunk and never appears among a module's attributes; the
preimage is probed too, since rollback loads it with `:code.load_binary/3`.

The coordinator performs parallel prepare/commit, compensating abort/rollback,
optional health checks, promotion, and status across explicit connected nodes. It is
best-effort rather than atomic: ambiguous transport outcomes are quarantined. A
single executor preparation is reserved at a time, commit revalidates policy/base and
epoch, stateful declarations require migrations, and epoch monotonicity survives
rollback and executor restart.

This is not a security boundary against malicious loaded code. Any accepted BEAM has
ambient VM authority and can call the code server or mutate processes. NIF loading is
detected as a static import of `:erlang.load_nif/2` only; a runtime-resolved call is
not detected, and the import check is a policy gate rather than a proof. Independent
signing/authorization belongs outside the patchable application, preferably on a
separate least-privileged loader node.

The node executor durably journals write-ahead operations, monotonic epoch, retained
rollback receipts, expected loaded hashes, and quarantine. The journal key is not
versioned, so a checkpoint this build cannot interpret is read and quarantined with its
evidence preserved instead of disappearing behind a `:not_found` while the node's code is
already patched. Opaque OTP prepared-code
terms are intentionally not persisted and become `lost_on_restart`. A reservation whose
prepare reply was lost can be released by artifact id, so an ambiguous prepare does not
wedge the node; status reports the reservation's artifact, epoch, and prepare time.
Restart verifies loaded module identities and migration-process liveness; mismatches
fail closed. For an interrupted commit, the verified artifact and migration targets in
the write-ahead record let restart resume matching live callback processes before
retaining the incomplete operation in quarantine. Post-mutation journal failures trigger
immediate compensation where possible and otherwise leave an explicit
reconciliation-required quarantine.

Above the coordinator, `Ouroboros.Upgrade.Forge` owns the path from agent-authored
source to a signed artifact, and `Ouroboros.Upgrade.Rollout` owns the path from that
artifact to a live, health-gated capability. Both live under `Ouroboros.Upgrade.*` and
are therefore inside the protected set: what the forge produces can never patch the
forge.

Forge stages, each with its own named refusal:

1. `Forge.Source.validate/1` is parse-only. It checks the `Ouroboros.Capability.` name,
   parses source and tests with `Code.string_to_quoted/1`, requires exactly one
   top-level module matching the declared one, and walks both ASTs for `@on_load`,
   protocol definitions, `Code.*`, `:code.*`, `File.*`, `:file.*`, `System.cmd/shell`,
   `Port`, `:os.cmd`, `Node.*`, `:erpc`, `:rpc`, `Application.put_env`,
   `:persistent_term`, `:ets.give_away`, `:erlang.load_nif`, and node-explicit spawns.
   Nothing is evaluated, so a rejected source has defined nothing.
2. `Forge.BuildPeer` compiles and runs the candidate's own tests inside an OTP `:peer`
   started with `connection: :standard_io` and `-start_epmd false`. That peer is not
   distributed, so generated code has no distribution with which to reach the cluster.
   One deadline covers boot, compile, and tests; the peer is stopped in an `after` block
   on every path. `Forge.Sandbox` runs inside it and returns only plain serializable
   terms.
3. `Upgrade.Epoch.next/2` reads `last_epoch` from every target, allocates above the
   maximum, and persists the allocation durably *before* returning it, so a crash
   between allocation and use burns a number rather than reissuing one. An unreadable
   node is a refusal, not a zero. `:global.trans/4` serializes allocations in a
   connected cluster; it is not partition-safe, and the defence that does not depend on
   coordination is the target's own epoch monotonicity check.
4. `Forge.Signer` is the seam the agent cannot supply for itself. The forge never holds
   a key; it asks the configured module and the default refuses everything. The
   behaviour has two callbacks: `sign/2` takes the canonical payload, and the optional
   `sign_artifact/2` takes the whole artifact. The forge prefers the second whenever a
   signer exports it, because a payload is a hash of a manifest and a signer holding
   only the hash cannot check the manifest against the bytes it describes.
   `Forge.Signer.Remote` implements it; `Deny` and `Local` do not and are unchanged.

### Signing plane

`Upgrade.Signing.Service` is the other side of that seam, and it runs where the forge
does not: on a `:signer`-role node whose supervision tree contains this process and
cluster formation. Three properties make it independent rather than merely remote.

**The key is outside the patchable application.** It is read at `init/1` from the file
named by `OUROBOROS_SIGNER_KEY_PATH` (32 raw bytes or their base64), derived into an
Ed25519 keypair, and held in process state wrapped in a struct whose `Inspect`
implementation redacts it — so a crash report, a logged state, or an interpolated
exception cannot print it. `public_info/0` publishes the public half and renders the
exact `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry a core node needs; there is no accessor
for the private half anywhere. `Forge.Signer.Local`, still shipped for dev loops, reads
its key from the configuration of the application it authorizes, which is precisely the
arrangement this replaces.

**The policy sees the whole artifact.** `Signing.Policy.Default` recomputes every
manifest claim from the BEAM bytes submitted — module name, sha256, md5, `vsn`, the
`:code.prepare_loading/1` on-load probe, static `:erlang.load_nif/2` imports, protocol
markers — for the new binary and, on a `:replace`, its pre-image. It requires every
module to be under `Ouroboros.Capability.`, with no configuration that widens that; it
requires `metadata.forge` to carry a `source_sha256` and a test report with no failures
and at least one pass; and under `:signing_require_eval` it requires a
`Rollout.Evaluation` spec it can validate. What it deliberately does *not* check is
anything only a target VM knows: epoch ordering (a signer has no view of any cluster's
watermark), pre-image currency, and module absence. Those stay with the executor and
survive the signature entirely. Every failure is `{:refused, reason}`; nothing raises
across the boundary, because an exception reaching the caller through `:erpc` would be
indistinguishable from transport ambiguity.

**Every decision is journaled before it is answered.** `Signing.Journal` is a bounded
record of issuances *and* refusals — artifact id, epoch, modules and dispositions,
requester, decision, reason, findings — checkpointed through
`:signing_journal_storage` (`Storage.DurableFile` in production) before the reply is
sent. A journal that will not accept the entry is a refusal to sign. The one asymmetry
is deliberate: the journal may record an issuance whose reply was lost, never a
signature that was returned without a record.

`Forge.Signer.Remote` is the client. It resolves the target from `:node` or
`:signing_node`, requires `Cluster.ensure_role(node, :signer)` before submitting, sends
the artifact plus an advisory payload over a bounded `:erpc`, and converts every
transport outcome into a typed error. The advisory payload is cross-checked and
discarded: the signature is always over bytes the service derives itself, so a
disagreement means version skew and stops the deployment rather than producing a
signature over bytes the requester did not expect.

Admission control sits in front of all of it: a per-requester sliding-window rate limit
and a maximum submitted artifact size. The requester is self-reported and journaled as a
claim, so the limit bounds accidents and retry storms rather than adversaries — see
"Safety boundaries" for what a connected node can do regardless.

`Rollout.deploy/4` checkpoints `:deploying` in the durable `Rollout.Registry` before any
node is mutated, deploys with `health_check: {Rollout.Probe, :ready?, [module]}`,
promotes on success, and classifies failure from the deployment's own recovery evidence.
The probe starts the introduced module as a throwaway mesh agent, sends one synthetic
signal, checks the answer, and stops it — and converts every exception, exit, and throw
into a health *result*, because an uncaught error would reach the coordinator as
transport ambiguity and quarantine a node the probe merely failed to satisfy. Only a
deployment whose every node proved compensation is recorded `:rolled_back`; anything
ambiguous is `:quarantined`, which has no automatic exit.

### Evaluation gates

The probe answers "is it alive". `Rollout.Evaluation` answers "did it do what it was
forged to do", which is the difference between a system that modifies itself and one
that improves. A spec is a bounded map of probes — a portable input and a data
expectation (`:any_reply`, `{:equals, v}`, `{:contains, s}`, `{:state_matches, k, v}`) —
plus `budget_ms`, an optional `max_latency_ms` gate, and `required`. It is data because
it lives in `metadata.forge.eval` *inside* the signed manifest: the criteria travel with
the bytes they judge, a rewritten spec invalidates the signature, and a future external
signer can require their presence. A closure could satisfy none of that.

The gate runs between commit and promote, while every node still holds its rollback
material. `Evaluation.run/3` starts one throwaway mesh agent per node and drives the
probes through it in order, so state expectations mean something; it enforces the
artifact's own budget, and — like the probe, and for the same reason — it converts every
exception, exit, and throw into a probe *result* rather than letting one escape into
`:erpc` and become transport ambiguity. `Rollout` then promotes if every node satisfied
its spec, rolls back if any node did not, and quarantines if any node's answer was
ambiguous — attempting compensation either way, but never recording an unevaluated
rollout as cleanly withdrawn. The registry entry carries a bounded `eval_report`: counts,
timings, and the first few failures per node, with an oversized or unportable report
replaced by a marker rather than truncated into something that reads like evidence. That
field is why the registry checkpoint is version 2; a version-1 checkpoint is widened on
read (absent report becomes `nil`) and anything else is still refused.

`compare: true` extends this to capability *upgrades*. A `:replace` beam for a live
module is admitted through this path and no other: the same spec runs against the current
version on every target first, and the challenger is promoted only if it passes at least
as many probes within `:capability_eval_regression_budget` of the champion's total time.
Both reports are recorded. This measures the declared probe set, twice, on a shared VM —
not production behaviour, not cost, and not with enough samples for the timing half to
mean much.

The isolation here is process-level and policy-level, never OS-level. The build peer
shares the host's user, filesystem, and network; the deny list is defeated by any macro,
`apply/3`, or runtime-built module name; and a forged capability that reaches a node runs
with the same ambient authority as every other module on it.

Quarantine is a refusal, not a warning: prepare, commit, rollback, and promote are all
gated on it, so a node whose loaded code provably disagrees with its journal cannot be
mutated further or have its preimages discarded by a promote.
`reconcile_quarantine/1` is the only exit and replays the same startup checks against
current state, journaling the transition when everything matches and returning
diagnostics when it does not. The operations log is bounded, except for pending
write-ahead records and records still carrying rollback material.

### Agent effect plane

`Ouroboros.Agent.Effects` is the layer at which an agent acts rather than projects. Six
Jido actions — start agent, stop agent, send message, delegate, forge, deploy — are
routed from typed signals on `Ouroboros.Agent.Worker` and call the same public APIs an
operator would. Everything else the agent does remains a pure state projection.

Each effect run is the same four steps, owned by `Ouroboros.Agent.Effects.Runner`:

1. The principal is `context.agent.id`, read from the agent struct the agent server
   owns. Jido drops `:agent`, `:state`, `:signal`, and `:agent_server_pid` from any
   caller-supplied action context, so the identity cannot be supplied by the sender. The
   signal's `from` is recorded as `claimed_from` and authorizes nothing.
2. `Ouroboros.Control.Grants.granted?/3` is asked about the concrete attempt — this
   module, this team, these nodes. It is deny-by-default: no entry, an attempt outside
   the allow-list, an attempt that does not name what the allow-list reads, a malformed
   call, and an unreachable authority are all refusals. Grants are checkpointed before
   they are acknowledged, and a revocation whose write fails leaves the grant standing
   rather than forgetting something it could not durably forget.
3. The work runs in a supervised task bounded by `:ouroboros, :effect_timeout`, never on
   the agent's own process. A forge boots a build peer, compiles, and runs a
   capability's tests; that is far longer than an agent server should block and longer
   than Jido's own action deadline.
4. The outcome settles back as `Ouroboros.Signals.EffectSettled`. Delivering it as a
   call is what orders it: a call arriving while the requesting call is still in flight
   queues behind it, so the in-flight registration written by the request's return value
   is always applied before the outcome that settles it. Refusals never start a runner
   and are cast instead, because a nested call would queue behind the very call it is
   inside.

Grants live under `Ouroboros.Control.` deliberately. That prefix is in the verifier's
protected set, so the fast lane refuses an artifact that would replace or introduce the
authority gating it: a capability an agent forged cannot patch the thing that decided it
could forge.

`state.forged` is what a `:deploy` resolves, and it is written only by settling an
in-flight effect this agent minted. A deploy therefore cannot ship bytes that arrived
any other way — and even then the artifact is re-verified and its signature re-checked
on every loading node.

The durable lane is separate. `Release.Metadata` builds and validates `.rel`, `.appup`,
and `relup` terms; `RelupBuilder` invokes `:systools.make_relup` without writing;
`Release.Artifact` validates a completed archive offline. `Release.Runtime` then gates
`unpack_release`, `check_install_release`, `install_release`, and `make_permanent`
behind ephemeral external authorization and a durable write-ahead journal. The default
authorizer denies mutation. Unpack publishes the exact verified bytes under a synced,
content-addressed name and gives OTP a same-inode alias matching the archive's validated
top-level `.rel`; operating-system ownership of that directory is part of the trust
boundary. Release and fast-patch journals sync both checkpoint file and parent directory
before acknowledging success. Tests use real tar archives and a deterministic adapter;
they do not execute a live embedded-release upgrade or reboot. Only that externally
rehearsed lane can prove restart persistence or an ERTS change.

## Failure model

| Failure | Current behavior | Required next behavior |
| --- | --- | --- |
| Starting caller exits | Harness run and coding coordinator continue | Done |
| Coding coordinator crashes | Supervisor restarts it; durable cursor reattaches | Done |
| Interactive coordinator crashes | Reattaches to live Harness session and turn IDs | Done |
| Harness/BEAM/host restarts | Task checkpoint remains; missing local run becomes `:lost` | Explicit resume/retry policy |
| Remote owner disconnects | Returns `owner_unavailable`; does not corrupt state | Retry/backoff and operator view |
| Network partition during placement | `:global` cannot guarantee one owner | Consensus lease/admission service |
| Store write fails | Cursor is not advanced and events are not broadcast | Backpressure/health alarms |
| Workspace/registry owner restarts | Nonterminal durable roots remain reserved until the registered owner reclaims them | Cross-node consensus authority |
| Fast patch migration fails | Reverse migrated state and restore preimages, or quarantine while keeping the artifact and preimages journaled | Done; release persistence remains separate |
| Fast patch resume fails after loading | Compensate first; quarantine with retained rollback material only if compensation fails | Done |
| Fast patch prepare reply is lost | Reservation is released by artifact id; no code was loaded | Done |
| Introduced module is still running on rollback | `{:introduced_code_in_use, module}` and quarantine; never a brutal purge | Done |
| Introduced module reappears after rollback | Restart reconciliation fails closed against the expected `:non_existing` identity | Done |
| Forged capability fails its health probe | Every committed node is rolled back, the module is absent again, and the registry records `:rolled_back` | Done |
| Forged capability fails its signed evaluation spec | Rolled back before promotion, while the rollback material still exists, with the failing report recorded | Done |
| Evaluation is unreachable, slow, or answers a shape this build cannot read | Compensation is attempted and the registry records `:quarantined`, never `:rolled_back` | Operator reconciliation tooling |
| Challenger capability regresses the probe set against the live champion | Rolled back with both reports; the champion keeps running | Cost models, canary cohorts, statistical significance |
| Evaluation criteria are rewritten after signing | The manifest signature fails on every loading node | Done |
| Capability rollout outcome is ambiguous anywhere | Registry records `:quarantined` and never `:rolled_back` | Operator reconciliation tooling |
| Forge crashes between allocating an epoch and using it | The number is durably spent and never reissued | Done |
| Build peer boot, compile, or tests hang | One deadline covers all three; the callback is killed and the peer stopped | Done |
| Build peer compiles hostile source | The peer cannot reach the cluster; it can still reach the build host | Container/VM boundary with resource and network limits |
| Ungranted agent requests an effect | Refused as `{:effect_denied, effect, reason}` and recorded; the agent stays alive and nothing reaches the world | Done |
| Effect signal claims another agent's identity | The principal comes from server-side agent state; the claim is recorded as `claimed_from` and buys nothing | Done |
| Effect outruns its deadline | The work is killed at `:effect_timeout` and settles as a failure; the agent's process was never blocked | Done |
| Grant checkpoint write fails | The grant is refused and never applied; a failed revocation leaves the grant standing and reports the error | Operator retry tooling |
| Effect authority is unreachable | Every attempt is refused; there is no path that fails open | Replicated policy authority |
| Team process crashes | Snapshot recovery adopts agents/tasks and resumes delivery | Done on one owner node |
| Scheduler or executor owner crashes | Same token is offered again for idempotent reattachment | Done on one owner node |
| Control process crashes | Durable request/plan/cancel intent is reconciled; stable IDs reused | Provider billing can still duplicate after response-before-checkpoint loss |
| Node restarts after fast patch | Original release boots | Build and rehearse the implemented OTP release lane |
| Release mutation result is ambiguous | Journal enters quarantine; no false success | Operator reconciliation and deployment rehearsal |

## Safety boundaries

- Development/test permits unsigned local patch tests. Production never does. Trusted
  keys arrive through `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`; boot fails on a malformed
  entry and an unset variable trusts nobody.
- Upgrade policy rejects the upgrade, storage, release, and control namespaces, the
  application root and its registry owner, on-load code, consolidated protocols, and
  sticky modules. It rejects statically imported `:erlang.load_nif/2`, which a
  runtime-resolved call evades. Loaded code remains VM-privileged.
- Newly introduced modules must be absent and named under `Ouroboros.Capability.`. Both
  rules are policy about names, not a sandbox: an introduced module is exactly as
  privileged as a replacement, and the gate only stops a new module from taking a name
  that already means something.
- Forge source validation is parse-only hygiene against accidents, not a sandbox. Macro
  expansion, `apply/3`, and runtime-built module names all defeat it by construction. The
  build peer is isolated from the cluster, not from the build host.
- The forge holds no signing key and constructs no signature. `:forge_signer` defaults to
  a module that refuses, and a signer whose key lives in this application's configuration
  (`Signer.Local`) lets the agent approve its own code. `Signing.Service` on a `:signer`
  node moves the key onto a host the patchable application does not run on, applies an
  independent policy to the full artifact before a signature exists, and journals every
  decision durably before answering. That is a narrower blast radius, not custody: the
  signer node is a connected cluster member, so any node that completes the distribution
  handshake can call the same service the forge calls. What such a node gets is a policy
  decision — the `Ouroboros.Capability.` namespace rule has no bypass for any caller,
  and the per-requester rate limit is keyed on a self-reported claim. Custody outside the
  distribution trust domain remains external.
- Agent effect grants gate the *action layer* — the typed signals a well-behaved agent
  flow travels through — and are deny-by-default, durable, and checked against the
  concrete attempt. They are not a sandbox and not a capability system. Any loaded BEAM
  can call `Ouroboros.Mesh.start_agent/2`, `Ouroboros.Upgrade.Forge.forge/2`, or
  `Ouroboros.Control.Grants.grant/3` directly without passing an effect action at all,
  because it retains full ambient VM authority. The hard boundaries remain the verifier's
  namespace policy, artifact signing whose production default refuses, and the isolated
  build peer.
- No effect exists for granting, so an agent cannot widen its own authority through this
  surface. That is a property of the surface, not of the VM, which is why the authority
  itself is fast-patch-protected and why signing approval belongs outside this
  application.
- The authority is node-local: one `Grants` process per node over that node's own
  checkpoint. An agent granted an effect on one node is not granted it on another, and
  nothing replicates or reconciles the two.
- Coding requests default to workspace write and prompt approval where the provider can
  enforce it; a provider that cannot is refused at creation rather than silently
  downgraded, and the downgrade has to be typed out (`sandbox_mode: :default`).
  Read-only is explicit (`sandbox_mode: :read_only`). Interactive sessions instead omit
  an unenforceable default and run under the provider's own behavior.
- Provider flags do not replace an OS sandbox. Untrusted coding work needs a separate
  worktree/container/VM boundary with resource and network limits.
- Inline environment maps are rejected rather than persisted. Event payloads and
  result tails are redacted before checkpointing. Objectives and provider-specific
  options are durable domain data and must not contain secrets.
- Distribution must use authenticated, encrypted transport outside a trusted local
  network; Erlang cookies alone are not an adequate internet-facing boundary. The
  release renders `-proto_dist inet_tls` and an `ssl_dist_optfile` when it is built with
  `OUROBOROS_DIST_TLS=1`, and a node that forms a cluster over cleartext distribution
  refuses to boot unless `OUROBOROS_ALLOW_INSECURE_DIST=1` says so.
- Cookie and TLS are transport authentication, not authorization. They decide who may
  complete the handshake and nothing about what follows: every connected node holds full
  `:erpc` authority over every other, including loading code, reading application
  environment, and killing processes. `Ouroboros.Cluster`'s role checks — placement onto
  `:core` nodes, forge builds onto `:builder` nodes — are misconfiguration detection
  above that fact, in exactly the same sense as the `Ouroboros.Capability.` namespace
  policy. A hostile connected node never calls those functions at all.
- Node role narrows blast radius rather than containing a compromise. A `:builder` node
  boots cluster formation and nothing else; a `:signer` node adds only the signing
  service. Neither holds teams, sessions, journals, grants, or a control plane, and both
  remain fully authorized members of the cluster. Containment requires the build and
  signing hosts outside the cluster's trust domain, reached through something narrower
  than Erlang distribution.
- The OTP releases directory is deployment-owned infrastructure. Content addressing,
  exclusive links, and fsync do not defend against another OS principal that can replace
  files in that directory.

## Roadmap to a competitive coding system

### Milestone 1: reliable single-task execution

- deterministic provider-contract tests;
- real CLI fixture tests for argv, JSONL, process ownership, cancellation, and
  timeout behavior;
- append-oriented durable event store instead of rewriting an aggregate task map;
- isolated worktree provisioning, explicit network policy, and durable cleanup;
- budgets, retries, idempotency keys, telemetry, and operator diagnostics.

Stop condition: repeated crash/reattach/timeout/cancel tests show no duplicate run,
lost acknowledged event, leaked OS process, or ambiguous terminal state.

### Milestone 2: durable teams

- planner/evaluator policy above coordinator, workers, and correlated delivery
  (implemented as an explicit opt-in control plane);
- durable team DAG, dependencies, fan-out/fan-in, cancellation propagation, and
  result provenance (implemented with stable execution/delegation identities);
- capability-aware scheduling across nodes (bounded local scheduling is implemented);
- consensus-backed ownership leases for partition behavior.

Stop condition: multi-node fault injection proves deterministic ownership and replay
through worker, coordinator, and network failures.

### Milestone 3: safe self-improvement

Implemented:

- isolated build peers that compile and test candidate source changes
  (`Forge.BuildPeer` + `Forge.Sandbox`: a non-distributed `:peer` with a bounded overall
  deadline, always stopped, returning only serializable terms);
- a signing seam the forge cannot satisfy for itself (`Forge.Signer`, defaulting to
  `Deny`), with the artifact re-verified against trusted keys on every loading node;
- a signing *service* on the other side of that seam (`Upgrade.Signing.Service` on a
  `:signer` node, reached by `Forge.Signer.Remote`): the key read at boot from a file
  that node mounts and never leaves its process, an independent policy that recomputes
  the whole submitted artifact and structurally refuses anything outside
  `Ouroboros.Capability.`, an optional requirement that the artifact declare a valid
  evaluation spec, a per-requester rate limit, and a durable journal of every decision
  that must be acknowledged before a signature is returned. A signer node with no
  readable key refuses to boot;
- durable, crash-safe epoch allocation above every target node's journal
  (`Upgrade.Epoch`);
- a durable deployment-level cluster journal above the durable node executors
  (`Rollout.Registry`), checkpointed before any mutation, which never records ambiguity
  as a rollback;
- health-gated rollout with real rollback proof (`Rollout` + `Rollout.Probe`): a forged
  capability starts as a mesh agent and answers a signal on every target, or the whole
  deployment is compensated and the module is absent again everywhere;
- declarative, signed evaluation gates between commit and promotion
  (`Rollout.Evaluation`): a probe set that lives inside the signed manifest, is run on
  every target while rollback material still exists, and decides promote, rollback, or —
  on any ambiguous answer — quarantine; plus champion/challenger comparison for
  capability upgrades, holding a replacement to the pass count and total time of the
  version it displaces;
- an agent-reachable effect surface for all of the above (`Agent.Effects`), gated by a
  durable deny-by-default authority (`Control.Grants`) that is checked against the
  concrete attempt, identifies the actor from server-side state rather than the signal,
  bounds every effect, and records each one. An agent driven only by signals can forge a
  capability, deploy it, start it, and message it — and can be refused at any of those
  steps without dying;
- least-privileged builder and signer nodes (`Ouroboros.Cluster`): one release, one
  runtime, three roles. A `:builder`/`:signer` node boots cluster formation and nothing
  else — no teams, sessions, stores, scheduler, or control plane — and
  `:forge_builder_node` relocates the build peer onto one without changing anything
  about the build. The builder must be runtime-identical to its targets, because the
  verifier checks the artifact's OTP/Elixir/architecture triple on every loading node;
  that constraint is *why* a builder is a role of the same release rather than a
  separate service;
- formation itself (libcluster: static epmd, gossip, DNS polling), off by default, plus
  a release whose distribution posture is explicit: long names, a refused blank
  node/cookie, optional TLS distribution baked into `vm.args`, and a boot that fails
  closed when a clustering node ends up on cleartext distribution.

Still external:

- **authority that is not node-local.** `Control.Grants` is one process per node over
  that node's own checkpoint. There is no replicated policy service, no per-principal
  rate or cost budget, and no durable effect log: the audit trail is a bounded ring in
  the acting agent's state and dies with it.

- **signing custody outside the distribution trust domain.** The service now exists and
  is real: the key lives on a `:signer` node, in one process, read from a file that node
  mounts, and an independent policy decides on the full artifact before any signature is
  produced. An agent that patches a core node cannot read that key, and cannot obtain a
  signature for a control-plane module at any price, because no code path on the signer
  produces one. What remains external is the rest of custody. A signer node is still a
  connected cluster member: a node that completes the distribution handshake can call
  the signing service directly, and can also do everything else `:erpc` allows on that
  host. Role isolation and TLS distribution narrow that surface; they do not close it.
  The per-requester rate limit is keyed on a self-reported claim. And there is no human
  in the loop — the policy is mechanical, so "independent" here means independent of the
  patchable application, not independent of the cluster. An HSM, a review queue, or a
  signing host reached over something narrower than Erlang distribution are all still
  outside this codebase.
- **real OS sandboxing.** The build peer is isolated from the *cluster*, not from the
  *host*: same user, same filesystem, same network. A `:builder` node moves that host
  off the production path, which is worth doing and is not containment — the builder
  remains inside the distribution trust domain. Compiling untrusted source safely needs
  a container or VM boundary with resource and network limits. The source deny list is
  hygiene against accidents and is defeated by any macro expansion, `apply/3`, or
  runtime-constructed module name.
- **partition behavior.** Formation connects nodes; it does not fence them. There is no
  quorum, no partition policy, and no reconciliation for a node that returns with stale
  state. Role and placement checks are observations about a *connected* cluster.
- **evaluation beyond the declared spec.** The gate that exists runs criteria somebody
  wrote and signed, on a throwaway instance, on each target, once. It decides promotion
  automatically and compares a challenger to its champion, which is real. What it is not
  is a measurement of production behaviour: there is no cost model, no canary cohort on
  real traffic, no repetition, and wall-clock over a handful of probes carries little
  signal, which is why the regression budget is deliberately loose. An artifact that
  declares no spec is still promoted on liveness alone — unless the signer was
  configured with `:signing_require_eval`, which refuses to sign one at all. That switch
  exists and defaults to off; what does not exist is any judgement about whether a
  declared spec is a *good* spec.
- **package assembly and reboot rehearsal** around the implemented `.appup`/`.relup`
  metadata/inspection lane. A forged capability lives in the running VM only; a restart
  boots the original release without it.

Stop condition: the agent can propose a change, but cannot authorize its own patch;
every rollout has a reproducible artifact, independent approval, canary evidence,
rollback proof, and a reboot-persistent release.

### Milestone 4: product differentiation

The BEAM advantage is not “another prompt loop.” It is long-lived, inspectable,
fault-contained teams: live process topology, typed event provenance, supervision,
node placement, resumable multi-provider sessions, and controlled behavior evolution.
Compared with a conventional single-process coding CLI, Ouroboros can keep several
logical workers and workflows alive, route them across connected nodes, recover each
plane from its own durable checkpoint, and evolve behavior through separately gated
fast-patch and release lanes. The product surface should expose those properties
directly through a terminal UI and API rather than hiding them behind one opaque chat
transcript.

That architecture creates promising future capabilities:

- live topology and fault-domain views instead of one transcript;
- long-running specialist teams that retain independent cursors and provenance;
- canary or cohort rollout of a behavior patch with health gates and retained rollback;
- evaluator-driven repair loops whose execution identity survives coordinator churn;
- heterogeneous provider workers selected by capability or policy; and
- build/sign/loader services an agent cannot self-approve. The least-privileged *roles*
  exist, forge builds already relocate onto a builder node, and the signing authority is
  a real service on a signer node with its own key and its own policy; what remains is
  moving those hosts outside the distribution trust domain, so that reaching them is a
  narrow request rather than full `:erpc` authority in both directions.

## Primary references

- [Jido documentation](https://jido.run/docs/getting-started/elixir-developers)
- [Erlang code loading](https://www.erlang.org/doc/apps/kernel/code.html)
- [Elixir `GenServer.code_change/3`](https://hexdocs.pm/elixir/GenServer.html#c:code_change/3)
- [OTP release handling](https://www.erlang.org/doc/system/release_handling.html)
- [SASL `release_handler`](https://www.erlang.org/doc/apps/sasl/release_handler.html)
- [Mix release hot-upgrade limitation](https://hexdocs.pm/mix/Mix.Tasks.Release.html#module-hot-code-upgrades)
