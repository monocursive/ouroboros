# J2: Replace Harness with an Ouroboros session contract

Status: proposed implementation specification, 2026-09-10. No implementation is
included. Baseline: `dev` at `d6cc85309141111b6ae1ae3852b254a30092f426`.

Implement after [J1](remove-jido-ai.md). [J3](replace-jido-core.md) removes the
remaining Jido core primitives. This slice removes `jido_harness` completely while
keeping the core agent/action/signal/storage dependency intact.

## 1. Outcome

The existing interactive coordinator speaks directly to the native execution
process through an owned session contract. Ouroboros owns request validation,
turn scheduling, approval bookkeeping, event delivery, cancellation, and recovery.
There is no intermediate general-purpose provider worker or provider registry.

Preserve the existing public `InteractiveSession` and gateway behavior, including
remote subagents, history, usage, approval relays, configuration, planning, fork,
handoff, compaction, and verified replay. Preserve persistence-before-broadcast.

This is a runtime migration, not a new agent loop. `Native.Loop`, model adapters,
permission decisions, workspace admission, and the effect ledger retain their roles.

## 2. Evidence and current responsibilities

The current path is:

```text
Interactive.Task -> Jido.Harness.SessionWorker -> Native.Session -> Native.Loop
```

- [`Interactive.Task`](../../lib/ouroboros/interactive/task.ex) owns durable domain
  state, workspace admission, public subscriptions, and projected events.
- [`Native.Session`](../../lib/ouroboros/provider/native/session.ex) owns the
  conversation, turn execution task, provider checkpoint, and native controls.
- Harness owns intervening session/turn bookkeeping, queues, timeouts, approval
  tracking, retained events, registries, and execution supervisors. Its event stream
  is polled and copied into the coordinator's durable record.
- [`Provider`](../../lib/ouroboros/provider.ex) supports only `:native`, but still
  derives declarations from Harness. Several native controls bypass that contract.

Replacing imports alone would conceal the same architecture under new names. Move
responsibilities into the two existing owners and remove the intermediate process.

## 3. Scope and exclusions

In scope: all live Harness references, its config and startup dependencies, request
and event types, test doubles, redaction, process-signal helpers, retained-event
delivery, lifecycle bookkeeping, and old-data decoding touched by its removal.

Do not restore CLI providers, add a provider plugin framework, merge the coordinator
and execution owner into one blocking GenServer, alter model/permission policy, or
remove user-facing controls. Do not add an exactly-once claim for external effects.
Do not combine this with the J3 storage or mesh rewrite.

## 4. Ownership and supervision

The final execution path is:

```text
InteractiveSession / gateway
              |
       Interactive.Task       durable domain state, public events, admission
              |
        Native.Session        live runtime, queue, approval waiters, output buffer
              |
          Native.Loop         model and tools, existing journal and checkpoints
```

`Ouroboros.Session` is a facade and contract, not a third worker. Add owned
`Ouroboros.Session.Request`, `TurnRequest`, `ApprovalResponse`, `RuntimeEvent`, and
`RuntimeInfo` types only for data that crosses this boundary. Reuse existing
domain event/state types where their meaning is identical. Keep the runtime ID,
native conversation ID, and public logical session ID distinct in the contract;
the migration must not confuse a transport restart with a new conversation.

Move execution tasks and native transports under Ouroboros-owned task/dynamic
supervisors. A coordinator crash must leave its live execution owner discoverable;
a ledger, admission, permission, or other upstream authority restart must stop its
dependent execution processes according to the existing fail-closed restart order.
Put the coordinator and execution owner in separate supervised failure domains
below those authorities. Test the actual tree, not just its child-spec names.

## 5. Internal contract

These operation names and semantics are the implementation target. Keep node-aware
routing in the existing session/interactive routing layer; the facade below acts
on the owner node. Public gateway method signatures remain unchanged.

| Operation | Contract |
|---|---|
| `open(logical_id, request)` | After admission and durable start intent, create or find the one live runtime for that logical ID; repeated identical starts return the same runtime, conflicting requests fail |
| `attach(runtime_id, coordinator, cursor)` | Verify the registered coordinator, monitor it, replace its old attachment, and return an ephemeral attachment plus current runtime generation/info |
| `info(runtime_id)` | Read status, active/queued turn IDs, pending approvals, native conversation ID, generation, and output high-water mark |
| `submit(runtime_id, turn_id, mode, request)` | Accept `:message`/`:follow_up` using the coordinator's durable turn ID; deduplicate identical retries, reject a conflicting fingerprint |
| `steer(runtime_id, request_id, request)` | Deliver once at the existing safe boundary; retain the distinction from queued follow-up |
| `respond_approval(runtime_id, request_id, response)` | Resolve only the matching pending request; duplicates cannot execute an effect twice |
| `configure(runtime_id, changes)` | Apply supported native settings in the established order; report applied state or a specific failure |
| `interrupt(runtime_id, turn_id)` | Preserve cooperative interruption and current queued-turn behavior; do not confuse request acceptance with terminal completion |
| `close(runtime_id)` / `kill(runtime_id)` | Preserve graceful versus forced shutdown, child cleanup, and terminal outcome semantics |
| `drain(attachment, after_cursor, limit)` | Return an ordered contiguous batch or an explicit retained-range gap, scoped to a runtime generation |
| `ack(attachment, cursor)` | Release only output that the coordinator has already checkpointed; stale attachments/generations cannot advance acknowledgement |

Existing native operations for plan mode, context, compaction, fork, handoff,
journal, and rewind remain available through this owned boundary. Public
`await/replay/subscribe/list` continue to use the coordinator's durable domain view;
they must not expose runtime output that has not been persisted there.

Requests preserve current defaults, timeouts, bounds, multimodal/prompt validation,
reasoning-effort handling, and refusal messages. Native planning becomes an explicit
owned setting; it no longer needs to masquerade as a Harness provider option.
This changes internal representation, not the user-visible permission policy.

## 6. Event delivery and persistence

### One event origin for each fact

Before implementation, enumerate every Harness-generated lifecycle marker and its
consumer. Assign its replacement to `Native.Session` or `Interactive.Task`.
`session_started`, readiness, accepted input, queue changes, turn start, approval
resolution, and terminal events must each have exactly one producer. Preserve
current event payloads, text enrichment, usage folding, IDs, public ordering,
detail/excerpt projection, and audit provenance. Do not retain double emission and
deduplicate it later as the primary design.

### Push as a wakeup; acknowledgement after checkpoint

The live execution owner retains unacknowledged events in a queue bounded by count
and encoded bytes. This buffer is transport state; the coordinator's checkpoint
remains the public event authority. The native execution journal and conversation
checkpoint retain their existing distinct purposes.

1. `Native.Session` appends an event and assigns a generation-local cursor.
2. It sends at most one pending cursor notification to its attached coordinator.
3. The coordinator drains a bounded batch after its durable cursor, projects it,
   and checkpoints events, turn outcomes, usage, and cursor in one commit.
4. Only a successful commit permits acknowledgement, public broadcast, or a waiter
   reply claiming the corresponding outcome. A repeated batch is not folded twice.
5. Acknowledgement advances buffer retention; rearm the notification if unread
   output remains. Attaching always drains from the durable cursor before waiting.

The runtime never synchronously calls the coordinator while servicing an operation
the coordinator is waiting on. A full buffer backpressures the producer without
blocking the runtime's interrupt/kill/approval handlers or accumulating unbounded
messages. Bound individual event size and outstanding producer submissions too;
a bounded queue with an unbounded upstream mailbox does not satisfy this contract.
Use a small injected limit in tests and named production limits derived from the
current payload/retention bounds; record the chosen values in the implementation.

Persist the runtime identity, generation, consumed cursor, and public event sequence
together. A new runtime generation may reset its private cursor, but the public
sequence never goes backwards. Old-generation notifications and acknowledgements
cannot advance a replacement runtime or cause a batch to be counted twice. Preserve
the existing durable sequence-offset behavior when reading resumed legacy records.

A failed checkpoint sends no acknowledgement and publishes none of that batch.
An uncertain commit outcome remains uncertain: reload/reconcile before proceeding,
and never turn it into permission to repeat an external effect. A crash after the
checkpoint but before acknowledgement causes a harmless redrain. Reconnecting
clients replay durable output; notification delivery is not an exactly-once promise.

There is no 25 ms active polling loop in the final path. Attachment handshakes and
monitors handle missed notifications and death; any recovery timer must have a named
failure purpose. Delete old polling helpers only when no other caller remains.

## 7. Recovery and effect ordering

| Failure point | Required behavior |
|---|---|
| Before durable start/turn intent | No execution starts |
| Start/submit accepted, coordinator dies before saving acknowledgement | Reattach by logical identity and reconcile the same turn ID; no duplicate model/tool dispatch |
| Coordinator dies with live runtime | Reacquire/reconcile admission, attach, and drain; preserve the active turn and output still retained |
| Runtime dies or whole node restarts | Use existing native checkpoint/resume policy; unprovable in-flight work becomes interrupted/lost/ambiguous as appropriate, never automatic effect replay |
| Runtime buffer disappears before public persistence | Surface a gap/ambiguity using durable intent and checkpoint/journal evidence; never invent missing events or a successful outcome |
| Durable commit succeeds before public notification | History contains the event; reconnect/replay recovers it without double-counting usage |
| Remote owner disconnects | Report unavailability; do not start a replacement child on another node merely because the owner cannot be reached |
| Intentional close/kill | Remains intentional and terminal; recovery must not restart it |

Native conversation checkpoints still precede terminal turn publication. The effect
ledger still records intent before model/tool dispatch, and its refusal still
prevents dispatch. Do not equate idempotent submission within a live generation
with exactly-once effects across a host crash. Preserve the current automatic-resume
attempt limit and explicit failure paths.

## 8. Approvals, remote children, and configuration

The runtime owns live approval waiters; the coordinator owns durable public approval
records and effect references. Preserve request identity, tool arguments, authority,
deadline, and parent/child correlation through the existing relay. Approval answers
must pass the current authorization and ledger gates before releasing an effect.

Duplicate, stale, wrong-session, expired, or wrong-generation answers cannot release
another waiter. Timeout/orphan behavior remains deny-by-default. Denial, interrupt,
and close clear the appropriate waiters and stop their blocked work. An approval
answered remotely still resolves on the child's owner node.

Keep remote spawn deduplication by task ID, placement checks, depth/concurrency
bounds, remote worktree leases, parent-loss cleanup, and result collection after
foreground completion. Replace direct uses of Harness's named supervisors in
`Native.Subagent`, `SubagentBridge`, `Run`, and `Session`; local registered names
must not accidentally target the parent's supervisor when the child is remote.

Configuration retains its existing applied-state ordering: a rejected or failed
runtime change must not be recorded as successfully applied. Preserve plan posture,
grants, model settings, and resume metadata through restart and fork.

## 9. Utilities and dependency closure

Move redaction into `Ouroboros.Redaction`, with the same observable treatment of
credential-shaped keys, strings, nested values, and explicitly supplied secrets.
Audit every use in storage, events, audit records, WASM policy, runtime exposure,
and authentication paths. Do not weaken redaction to make fixtures easier to match.

Move the small erlexec process-signal wrapper into the existing native execution
module or a focused owned helper. Retain `erlexec` and its reviewed macOS patch;
Harness removal is not evidence that process-group handling or the patch is obsolete.
Declare still-used packages such as JSON/schema/telemetry libraries directly when
they would otherwise remain only accidentally transitive.

Replace native provider configuration with an Ouroboros-owned configuration read.
Inventory config files, runtime readers, test overrides, fixtures, and documentation
together. Remove the vendor registry, unused generic run/process APIs, temporary
adapters, and Harness-only error/struct conversions once the final callers move.

## 10. Durable data and rollout

Capture a synthetic baseline data directory before changing types. Include idle,
running, queued, awaiting-approval, terminal, resumed, forked, and removed-provider
records, plus usage, ledger errors, and nested legacy request/event structs.

Read legacy `harness_session_id`, `harness_turn_id`, `provider_session_id`, and cursor
offset fields. Preserve historical IDs and events. Use an explicit decoder/versioned
migration for renamed internal fields; opening/listing history must not rewrite it
or take a workspace lease. Removed providers remain readable history and cannot run.
Old live PIDs are never durable identity or a supported cross-binary handoff.

Audit atoms and struct tags that disappear with the dependency. Load a finite,
reviewed compatibility vocabulary before safe decoding and explicitly normalize
known legacy data shapes without calling missing struct modules. Unknown input
must not create atoms or load arbitrary modules. Quarantine remains available for
actually unreadable data, not as a substitute for migrating valid baseline records.

Deploy with stopped/drained runtimes and copied/backed-up data; this spec does not
promise live hot migration or mixed-version cluster execution. Increment the existing
[`Cluster` fleet protocol revision](../../lib/ouroboros/cluster.ex) for this incompatible
internal contract; reuse its placement checks instead of adding a second version
negotiation system. Verify every remote start/control entry point refuses an
incompatible peer before dispatch. Code revert
alone is not a data rollback once new-format checkpoints exist; use a verified
backward reader or the pre-migration backup on a stopped runtime.

## 11. Slices and acceptance

1. Freeze public lifecycle traces, data fixtures, request/approval validation, and
   failure outcomes; enumerate the complete Harness import/call/config inventory.
2. Introduce owned types and facade; move consumers behind it while the existing
   backend still runs. This is a temporary migration seam, not a shipped backend choice.
3. Move scheduling, waiters, events, supervisors, and utility responsibilities into
   Ouroboros. Drive the native process directly with scripted model/tool doubles.
4. Switch the coordinator, resume paths, and remote children. Add acknowledged event
   delivery and remove the polling path; never execute both runtimes for comparison.
5. Migrate old data readers, remove Harness and stale compiled artifacts, verify a
   fresh dependency build, and update current architecture/protocol documentation.

Acceptance must include these adversarial cases:

- Exactly one start/terminal marker and correctly correlated tool/approval events.
- Coordinator crashes before/after submit, drain, checkpoint, ack, and notification.
- A blocked/failed/uncertain checkpoint never releases unpersisted public output.
- Full buffers, oversized events, slow subscribers, and repeated reattachments stay
  bounded while interruption and approval denial remain responsive.
- Runtime and whole-node restarts preserve history/resume policy and expose unknown
  effects honestly; a killed session does not resurrect.
- Remote starts retried across reply loss produce one child; approvals execute only
  there; parent death, disconnect, return collection, and lease cleanup retain behavior.
- Configuration failure, approval timeout, and stale answers cannot broaden authority.
- Old data boots with Harness absent, under both lazy and preloaded module order.

Use the existing interactive, native session/harness-session, approval-ledger,
deadline, resume, journal/replay, subagent, and remote-subagent suites as the starting
contracts. Adapt their entry points without deleting behavioral assertions. Run
`make test`, `make dialyzer`, golden/protocol drift checks, and browser journeys
covering streamed output, approval, interrupt, reconnect, and history. Retain the
existing boot corpus and add the pre-J2 corpus; run both on fresh copies.

Completion requires `jido_harness` absent from the lock, clean build, and production
application graph; no live imports or supervisor/config references; unchanged public
protocol fixtures except separately justified compatibility additions; all failure
gates passing. Report session process counts and idle wakeups before/after under
the same scripted workload. A speedup is optional; deleting the third session worker
and the active poll loop is structural acceptance evidence.
