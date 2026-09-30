# Ledger v1: durable local admission, first execution slice

This specification implements the first vertical slice of [North Star §5](../../north-star.md#5-ouro-ledger)
and its [launch handshake](../../north-star.md#71-process-tree-and-admission).
It does not declare milestone 2 complete. The jail still builds and runs without
the ledger; the ledger consumes its existing receipts, control frames and audit
events without attaching a probe or inventing an observation.

The current slice provides a single local writer, stable preparation identities,
one birth-identified launch owner, durable admission before gate release,
authenticated event ingestion, canonical settlement, opt-in bounded captures,
inspection, local chain verification and conservative orphan reconciliation.
Linux execution is the acceptance target. macOS clients can read the local
protocol and verify stores, but native launch ownership currently refuses because
its birth-identity mechanism has not been implemented.

## 1. Processes and authority

`ouro-ledger serve` owns `<data>/ledger/writer.lock` with a nonblocking exclusive
`flock` for its entire process lifetime. A second writer refuses before opening
the serving socket. The daemon accepts Unix connections at
`<data>/ledger/serve.sock`, owned by the daemon's effective uid and mode 0600.
The data and run directories are owned mode 0700; regular files are owned mode
0600, opened with `O_NOFOLLOW` and `O_CLOEXEC`, and must have exactly one hard link.
Run ids are generated `run_` plus 32 lower-case UUID hexadecimal digits. Caller
ids never become path components. Unsafe final symlinks, permissions and run ids
refuse. This is local same-user operator authority, not managed tenant isolation.

Linux sockets authenticate uid and pid with `SO_PEERCRED`. The daemon reads the
peer's `/proc/<pid>/stat` start time and boot id and stores those as birth
identity. Request bodies cannot select a role or an actor. `prepare` and orphan
reconciliation are authenticated operator requests; `show`, `runs`, `verify` and
`doctor` have reader authority. Managed project-scoped access decisions are a
later milestone and are not provided by these same-user roles.

The owner durably claims a prepared attempt. Its uid, pid, start time and boot id
are immutable. Another process cannot claim it, including a new process that
reuses its pid. A dead owner is reconciled, never relaunched. A surviving owner
can reconnect after daemon restart and reacquire role capabilities for the same
birth identity. This does not authorize another execution.

The daemon returns independent owner and producer secrets over the authenticated
private socket. Each is bound to one run, one role and the owner's birth identity.
The secrets remain in memory and never enter child arguments, environment or
files. Only a random non-secret token id is stored in provenance. Reissuing a
pair revokes the preceding pair. The first slice's producer channel is an owner
relay of the direct jail child's inherited private trace fd. Its provenance
truthfully names the socket peer as the owner and `role: producer`; it does not
claim that the jail is the socket peer. The jail receives no ledger capability.

Under an enforced jail, the store, socket and owner memory remain outside the
contained child's authority. Linux conformance must prove this using the actual
jail and a scripted child. Under `none`, same-user hostile code can modify the
store or inspect the owner: all projections and verification continue to say
`child_protection: unprotected`. Local hash consistency does not upgrade that
label or establish external custody.

## 2. Bounded transport and writer queue

Socket requests and responses are JSON with a four-byte unsigned big-endian
length prefix. The JSON payload must be between 1 and 1,048,576 bytes. Unknown
request/envelope fields refuse. Peer-provided `actor` or `role` is not an
authorization mechanism. Each socket has two-second read and write timeouts.
The daemon allows at most 32 live connection handlers and a 32-entry bounded
writer queue. The writer serializes requests; a full queue refuses and a timed-out
reply does not roll back a persisted request.

A caller that loses a reply retries the same request id and exact immutable
payload. Success returns the original `{seq, digest}`; conflicting payloads
refuse. Socket timeout means an unknown request outcome until the caller retries
or inspects the record. It is never permission to release the gate or start a
second child.

## 3. Preparation and one execution

Preparation payloads record profile, policy digest, argv digest, resolved
capability requirements, jail image identity, I/O mode and capture configuration.
They do not contain raw argv or copied environment values. A prepare request id
durably maps to one generated run id and attempt id. An identical retry returns
the same run; a different payload refuses.

The selected jail must be a regular native ELF executable without group/world
write permission, at most 256 MiB. The owner pins its inode by an open descriptor
and hashes it before and after policy resolution. Before admission it hashes the
direct live jail's `/proc/<pid>/exe` and compares that digest with preparation.
Linux's executing-image write exclusion protects this final binding while the
jail waits on the closed gate. Any mismatch refuses before gate release.

`run` checks the run state and obtains its exclusive launch lease before spawning
the jail. A replay that already has an owner or admission does not launch again.
The owner creates the private trace, control and closed gate channels. The jail
is its direct child; Linux parent-death setup and the existing jail supervisor
provide the contained lifetime mechanism. Detached fleet-independent ownership
is outside this slice.

The jail emits its prepared receipt while execution is still blocked. Admission
refuses unless the receipt schema, phase, attempt id, argv digest, policy digest
and resolved requirements match durable preparation. The complete prepared
receipt is included in the canonical admission record. The writer synchronizes
that record and its projection before acknowledging. Only that acknowledgement
permits one gate release. A gate write failure or lost acknowledgement never
justifies launching another child.

The owner relays the jail's source events without changing their attempt ids,
source sequence numbers or observations. Source events are parsed using the
shared jail event type, checked against its semantic rules and restricted to
the current jail operation inventory. Producers cannot emit `intent.*`,
`net.dns` or `limit.hit` as new claimed observations. Per-source sequences start
at 1; exact replays return their original acknowledgement, conflicts refuse,
and missing source numbers are durably recorded before strict evidence returns
a failure with no success acknowledgement. Retries retain that failure. The
best-effort store representation retains degraded gaps for future reconciliation;
the launch path does not yet enable that mode. A later receipt cannot erase a
writer-established gap.

After verified jail settlement, the owner appends the matching terminal receipt
and the observed outcome. A run admitted by the ledger can also settle a proved
target exec failure: the jail's final receipt has `phase: refused`,
`outcome.kind: exec_error`, `exec_observed: false`, and a verified empty lifetime
boundary with `verification_scope: attempt_tree`. The canonical ledger intent
is still `settled`; it records a known terminal failure rather than success.
`denied` is reserved for refusal before ledger admission. This exception retains
the original attempt, policy, argv and requirements binding, strict source loss
checks, and the final receipt digest correlation with trace and control. A lost
or unverified boundary still produces `outcome_unknown`. Source operation
outcomes remain on their source events and never become the run's terminal
outcome. Tree exit and durable settlement remain separate.
Failure to acknowledge settlement leaves it pending; an observed local exit
does not fabricate a durable acknowledgement. Owner loss records
`outcome_unknown` without claiming that the tree is dead or an effect did not
occur. The first slice uses strict evidence: daemon or ingestion loss stops the
owner from releasing a new gate and triggers termination for an admitted child.
Best-effort continuation with a reconciled bounded pending queue is deferred.

## 4. Store and canonical record

The first slice uses one nonrotating `events-0001.ndjson` stream per run and an
atomic `run.json` projection. Preparation and owner bookkeeping records have
`schema: ouro.ledger.event/1`, `run_id`, `attempt_id`, `seq`, `prev`,
`received_at`, `provenance`, `kind`, `request_id`, `body` and, for owner intents,
`effect_id`. Canonical source records retain `schema: ouro.event/1` and every
original source field directly on the record, adding `run_id`, `seq`, `prev`,
`received_at`, `provenance`, `kind: source` and the derived replay request id.
They do not nest or replace the frozen source envelope.
Preparation and ownership are in the same ordered stream as admission and
observations, so recovery can rebuild immutable identities from one authority.
The [record schema](ledger-v1/record.schema.json) accepts the writer fields and
pins the two record kinds. The [source schema](ledger-v1/source.schema.json)
extends the frozen producer's properties; its projection back to the source
is checked against the unmodified jail producer schema.

`kind` is `prepared`, `owner_claimed`, `admitted`, `denied`, `source`, `settled`,
`note` or `outcome_unknown`. Sequence starts at 1. The first `prev` is null;
each subsequent `prev` is `sha256:` plus lower-case SHA-256 over the preceding
record's canonical UTF-8 bytes, excluding its newline. The shared integer-only
RFC 8785 encoder sorts keys by UTF-16 order, rejects floating-point values and
does not normalize strings. A record ends with exactly one LF. The digest
returned in an acknowledgement uses the same preimage. The first record is
durable preparation; ownership, request and effect replay maps are reconstructed
from these records. One request id has one original payload and receipt. An
effect id cannot silently be rebound to another request or payload.

`run.json` is a disposable projection containing the original payload, immutable
owner, current state/outcome, coverage, selected capture status, receipt values
and chain head. It is rebuilt from verified canonical records at daemon startup.
The current implementation embeds receipt values in canonical records rather
than separately storing mutable receipt pointers. A SQLite query index,
rotating segment manifests and signed bundles are deferred.

The owner reads the jail's canonical receipt at
`<data>/attempts/<attempt_id>/jail.json`. It does not request another receipt copy
inside the shared state root; the jail's receipt-copy fence forbids that path.
Admission and final intent records embed the validated receipt before their
acknowledgement. The run's `receipts/` directory is reserved for future bundles.

## 5. Acknowledgements, failure and recovery

Every successful mutation follows this order:

1. Encode and validate the bounded canonical record without changing state.
2. Append its exact bytes and LF to the private stream.
3. `fsync` the stream.
4. Write a new private projection, `fsync` it, rename to `run.json`, and `fsync`
   the containing directory.
5. Synchronize the run directory before returning `{seq, digest}`.

The parent ledger directory is synchronized when a run directory is created.
No index is in the acknowledgement path. A persistence error, including ENOSPC,
an interrupted write or an ambiguous sync, poisons the stream. No further
acknowledgement or dependent dispatch is allowed in that process. Poisoned state
renders pending settlement and an explicit unknown with degraded evidence.

Recovery reads with a bounded frame buffer, checks exact canonical bytes,
schema/run/attempt identity, monotonic sequence, `prev` and state transitions.
It does not truncate a partial tail or rewrite historical bytes to manufacture
a valid chain. An incomplete, oversized, malformed or conflicting stream stays
poisoned with a verification finding. Ambiguous preparation identity also blocks
new preparations. Complete records surviving a crash rebuild the original replay
receipt and the projection; a retry is synchronized before acknowledgement.

`verify` reports `local_consistency`, `coverage` and `child_protection` separately.
A valid chain is local consistency only: deletion of a complete terminal suffix
by an uncontained same-user attacker has no external witness in this slice.
Source gaps remain explicit even when the hash chain is consistent.

## 6. Captures and privacy

Output capture is opt-in. The default cap is 1,048,576 bytes per selected stream.
The owner drains output continuously, stores at most the cap, discards subsequent
bytes, and records total observed bytes, stored bytes and `truncated`. A cap does
not block the child. Unselected streams are `not_captured`. Captures may contain
secrets; the opt-in is recorded in preparation and the final canonical evidence.
Foreground forwarding has a separate queue capped at 1 MiB per selected stream.
A full or disconnected queue stops the tree and records an unknown outcome with
incomplete capture. Final forwarding has a two-second drain deadline so it
cannot block the owner's evidence and lifetime loop.
Default metadata uses argv digests and existing jail-redacted observation fields.
The ledger does not archive vendor state. Capture retention enforcement and
structured minimization options remain future work.

Selected foreground streams are forwarded through separate queues of at most
128 chunks of 8192 bytes each (1 MiB queued per stream). Queue overflow or a lost
sink fails strict execution; forwarding completion has a two-second grace.
Capture or forwarding failure records incomplete capture evidence and an unknown
run outcome when the writer is reachable. Batch output uses independent sinks.

## 7. Acceptance and remaining milestone 2 scope

The Rust store tests exercise process-lifetime writer exclusion; lost replies
and recovery; immutable prepare/request/effect identities; reserved admission
metadata; interrupted tails retained without truncation; injected ENOSPC, stream
sync, projection and directory-sync failures; source replay/gaps; conservative
owner-loss reconciliation; safe final paths and frame limits; and the persistent
unprotected label for `none`. Protocol tests cover forged role/attempt/peer
capabilities, caller identity fields, and interrupted or oversized transport.
These are deterministic fault injections, not a physical full-disk experiment.

Linux execution tests must run the real jail through its closed gate, prove no
duplicate launch on replay/lost reply, exercise daemon/owner death and record
capture truncation. A macOS unit-suite pass is not Linux containment evidence.
The [contract validator](ledger-v1/validate_contract.py) checks versioned schemas
and fixtures only; it makes no runtime or custody claim.

Milestone 2 is still gated on the full North Star durability suite and these
unimplemented verbs/features: `append` for independent operator intents,
`tail`, `query`, `diff`, `bundle`, `hold`, `release`, `gc`, `export`, retained
deduplication/chain anchors, pagination, segment manifests, SQLite projection,
best-effort outage reconciliation, capture retention, signed bundles and the
historical-custody migration at removal of the in-tree stores. Managed
single-worker submission additionally needs its own principal, authorization,
provenance and project-scoped reader gates. None is implied by this slice.

## 8. Linux quickstart

Build both local executables from the repository root:

```sh
cargo +1.98.1 build --release -p ouro-jail -p ouro-ledger
```

Use a private data directory outside the workspace. Substitute absolute paths
for your checkout and workspace in this example:

```sh
mkdir -m 700 /tmp/ouro-ledger-data
mkdir -m 700 /tmp/ouro-ledger-work
/absolute/checkout/target/release/ouro-ledger \
  --data-dir /tmp/ouro-ledger-data run --request-id quickstart-1 \
  --jail-bin /absolute/checkout/target/release/ouro-jail \
  --jail tool --workspace /tmp/ouro-ledger-work --io batch \
  --capture stdout --capture-limit 32 --json -- \
  /bin/sh -c 'printf "recorded child output\\n"'
```

The daemon starts on demand. Read `run_id` from the JSON response, then inspect
its independent outcome, coverage, protection and chain results:

```sh
/absolute/checkout/target/release/ouro-ledger \
  --data-dir /tmp/ouro-ledger-data show run_REPLACE_WITH_RETURNED_ID --json
/absolute/checkout/target/release/ouro-ledger \
  --data-dir /tmp/ouro-ledger-data verify run_REPLACE_WITH_RETURNED_ID --json
```

Batch JSON control has independent output sinks and is not mixed with raw child
output. Foreground I/O is the inherited default when `--io` is omitted; this
slice requires batch mode for `run --json`. Repeating the exact request uses its
durable run identity and does not execute a settled child again. Local Linux
capability requirements still apply: a refused jail preparation is a refusal,
not a reason to switch to `none` silently.
