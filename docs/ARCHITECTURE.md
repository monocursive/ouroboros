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
6. The documentation distinguishes those proofs from partition tolerance, full-host
   provider durability, billing, real repository effects, and a real packaged-release
   install/reboot rehearsal.

The first five are local implementation claims backed by deterministic tests. None
imply the external claims in item six.

## Planes and ownership

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
rollback receipts, expected loaded hashes, and quarantine. Opaque OTP prepared-code
terms are intentionally not persisted and become `lost_on_restart`. A reservation whose
prepare reply was lost can be released by artifact id, so an ambiguous prepare does not
wedge the node; status reports the reservation's artifact, epoch, and prepare time.
Restart verifies loaded module identities and migration-process liveness; mismatches
fail closed. For an interrupted commit, the verified artifact and migration targets in
the write-ahead record let restart resume matching live callback processes before
retaining the incomplete operation in quarantine. Post-mutation journal failures trigger
immediate compensation where possible and otherwise leave an explicit
reconciliation-required quarantine.

Quarantine is a refusal, not a warning: prepare, commit, rollback, and promote are all
gated on it, so a node whose loaded code provably disagrees with its journal cannot be
mutated further or have its preimages discarded by a promote.
`reconcile_quarantine/1` is the only exit and replays the same startup checks against
current state, journaling the transition when everything matches and returning
diagnostics when it does not. The operations log is bounded, except for pending
write-ahead records and records still carrying rollback material.

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
- Coding requests default to read-only and prompt approval. Write access is explicit.
- Provider flags do not replace an OS sandbox. Untrusted coding work needs a separate
  worktree/container/VM boundary with resource and network limits.
- Inline environment maps are rejected rather than persisted. Event payloads and
  result tails are redacted before checkpointing. Objectives and provider-specific
  options are durable domain data and must not contain secrets.
- Distribution must use authenticated, encrypted transport outside a trusted local
  network; Erlang cookies alone are not an adequate internet-facing boundary.
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

- isolated build peers that compile and test candidate source changes;
- policy review and signing outside the patchable agent application;
- durable deployment-level cluster journal above the now durable node executors;
- package assembly around the implemented `.appup`/`.relup` metadata/inspection lane,
  followed by real embedded-release install and reboot rehearsal;
- evaluation gates comparing behavior, cost, latency, and regressions before rollout.

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
- remote, least-privileged build/sign/loader services that an agent cannot self-approve.

## Primary references

- [Jido documentation](https://jido.run/docs/getting-started/elixir-developers)
- [Erlang code loading](https://www.erlang.org/doc/apps/kernel/code.html)
- [Elixir `GenServer.code_change/3`](https://hexdocs.pm/elixir/GenServer.html#c:code_change/3)
- [OTP release handling](https://www.erlang.org/doc/system/release_handling.html)
- [SASL `release_handler`](https://www.erlang.org/doc/apps/sasl/release_handler.html)
- [Mix release hot-upgrade limitation](https://hexdocs.pm/mix/Mix.Tasks.Release.html#module-hot-code-upgrades)
