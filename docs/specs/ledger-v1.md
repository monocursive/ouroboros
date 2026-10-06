# Ledger v1: durable local admission and bounded evidence readers

This specification implements the first vertical slice of [North Star §5](../../north-star.md#5-ouro-ledger)
and its [launch handshake](../../north-star.md#71-process-tree-and-admission).
It does not declare milestone 2 complete. The jail still builds and runs without
the ledger; the ledger consumes its existing receipts, control frames and audit
events without attaching a probe or inventing an observation.

The current slice provides a single local writer, stable preparation identities,
one birth-identified launch owner, durable admission before gate release,
authenticated event ingestion, canonical settlement, opt-in bounded captures,
inspection, local chain verification, conservative orphan reconciliation,
bounded single-run evidence queries, exact canonical NDJSON export, optional
detached batch ownership on a provisioned Linux systemd user manager, rotating
canonical segments, durable replay anchors, a rebuildable SQLite projection and
restartable reader cursors. Operator holds, a bounded retention preview and
whole-run pruning with retained replay identities and chain anchors are available.
Independent operator intents and resumable live tail are also available.
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
identity. Request bodies cannot select a role or an actor. `prepare`, independent
`append` and orphan reconciliation are authenticated operator requests;
`show`, `runs`, `tail`, `verify` and
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
provide the contained lifetime mechanism. Foreground ownership stays attached
to its invoking process; optional detached ownership follows §3.1.

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

### 3.1 Detached batch ownership

`run --io batch --detach` requires an existing, reachable systemd user manager
with lingering enabled. It never enables lingering or changes host policy.
`doctor --json` reports mechanism availability without starting a writer; an
absent writer reports `ready: false`, separately from `detached_owner.available`.
No unsupported host falls back
to a foreground process or a double fork.

The writer and each launch owner run in separate transient user services.
The writer service name is derived from the canonical data-directory path;
owner service names are random. The submitter verifies the bootstrap peer's
kernel uid, birth identity and the user manager's `MainPID` before transferring
the request. An existing session-bound writer refuses detached submission;
finish its active work and stop it before switching to a service writer.
The owner connects to the independent writer without an on-demand fallback.

Launch options, working directory and the submitting process's environment
cross a private, bounded Unix socket. They are not written to files, unit
arguments, unit environment properties or the journal. The owner restores its
environment before starting threads. Unit commands contain only the ledger
executable, data-directory or bootstrap path, and unit identity. Rendezvous
sockets are removed after connection. The child retains the jail's ordinary
environment and descriptor restrictions.

The immutable request records `owner_lifetime: systemd_user_service` and batch
I/O. The reply identifies a durably claimed owner; it does **not** assert that
the child has executed or settled. Losing that reply does not cancel the owner.
Replaying the same request returns the same run or refuses a conflicting plan;
it never creates a second jail for an owned, terminal or unknown attempt.
The batch owner keeps draining bounded captures without client descriptors.

`wait RUN --timeout SECONDS --json` reads until a durable terminal record and
returns its outcome code. Timeout or client loss does not cancel the run.
`cancel RUN --json` requests a detached owner's stop through a birth-checked
Linux pidfd. Its `stop_requested` response leaves settlement pending. The owner
forwards cancellation to its direct jail child and drains final evidence;
only a corroborated receipt establishes tree death. Owner death keeps the
existing parent-death chain, and `settle-orphans` records unknown outcomes
without re-executing work. Writer death retains strict fail-closed behavior.

For example, on a provisioned worker:

```sh
ouro-ledger --data-dir "$HOME/.local/share/ouro-batch" run \
  --request-id build-001 --io batch --detach --json \
  --workspace "$PWD" --limit wall=60s --capture stdout --capture stderr \
  -- /bin/sh -c 'make test'
ouro-ledger --data-dir "$HOME/.local/share/ouro-batch" wait RUN_ID --json
```

This is local operator authority on Linux. Remote callers can invoke the CLI
over their existing SSH access; restricted managed ingress, project ACLs,
artifact transfer and the managed submission client remain separate work.

### 3.2 Independent operator intents

`append --run RUN --request-id ID --kind admitted|denied|settled|note
[--effect ID] --body-file FILE [--json]` records an explicit operator assertion.
Its canonical kind is `operator_intent`; `body.kind` names the operator decision
and `body.fields` preserves the supplied JSON object. The writer derives
`provenance.role: operator` and the authenticated peer identity. No capability
token is needed or accepted on this same-user operator interface.

These assertions do not authorize a jail launch, change run state, settle the
launch owner's attempt, update coverage/protection, or become source events.
For example, an operator `settled` assertion about a report does not mean the
contained command finished. Owner admission and settlement still require their
existing authenticated lifecycle and corroborating jail receipts. Inspection
and export distinguish the two kinds of record without inferring execution.
Operator intents appear in tail and export; source-class queries continue to
select observations and owner denials.

Lifecycle decisions require an effect id. An effect can be admitted then settled,
or denied before admission. Repeated or conflicting decisions under new request
ids refuse; a retry of the same request and exact immutable payload returns the
original `{seq, digest}`, even after later decisions and writer restart. Notes
may omit an effect id; supplying one reserves a single note identity for that
effect. Operator effect indexes cannot collide with caller request ids or owner
effect indexes. Request ids remain unique across a run's mutations.

An admitted operator effect without settlement protects both history and
captures from GC (`operator_effect_pending`), including after restart. A note
cannot clear that protection. Once settled, the ordinary retention rules apply.
Pruning retains prior intent receipts for identical retries and refuses new
intents. This assertion mechanism does not provide external custody or prove
that an external effect happened.

The CLI reads at most 64 KiB of JSON; the writer independently bounds the
canonical body to 64 KiB. The body must be an object and cannot supply reserved
identity fields (`actor`, `role`, `provenance`, `run_id`, `attempt_id`, `seq`,
`prev`, `received_at`, `token_id`). Explicit operator metadata is stored as
provided; no process environment, argv or model payload is captured automatically.
Ambiguous writes use the existing poisoning and recovery barriers. Preserve the
request id and exact body when retrying an uncertain result.

The [append request schema](ledger-v1/append-request.schema.json) and
[canonical record schema](ledger-v1/record.schema.json) describe this interface.
Writers predating `operator_intent` cannot read these records and must not write
such stores.

## 4. Store and canonical record

The store uses ordered `events-0001.ndjson`, `events-0002.ndjson`, … segments
per run, a durable `segments.json` manifest and an atomic `run.json` projection.
Before an append would exceed 64 MiB, the writer creates the next segment
exclusively, synchronizes the empty file and run directory, then appends the
whole record there. A record never spans files. Sealed files stay unchanged.
Existing larger legacy files are preserved and rotate on the next append.
The current bound is 4,096 segments per run; reaching it refuses new appends
without deleting history. Preparation and owner bookkeeping records have
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
`note`, `outcome_unknown`, `hold` or `release`. Sequence starts at 1. The first `prev` is null;
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
than separately storing mutable receipt pointers.

`segments.json` version 2 anchors each segment in order: filename, committed
byte length, first and last global sequence, SHA-256 over its exact bytes
including LF delimiters, and last record digest. The manifest also holds one
ordered replay-identity digest across the entire run. Global `seq` and `prev`
continue across every segment boundary; filenames and sequence ranges must
be contiguous. The manifest is bounded to 2 MiB. The replay preimage is a
length-prefixed canonical record containing request/effect identity, immutable payload digest
and the original append receipt. Recovery checks that prefix before promoting
complete unacknowledged tails. A shorter or changed prefix poisons the stream;
historical bytes are never truncated or rewritten. Legacy single-segment
streams without a manifest, and version 1 manifests, are verified and migrated at startup without changing canonical bytes.
Multiple segments require an anchor. Recovery accepts at most one unlisted
successor of a fully anchored predecessor: an empty file resumes an interrupted
rotation, and a complete valid tail recovers its original receipts. Missing,
reordered, unsafe or altered segments, extra unlisted files, interrupted frames,
and growth of a sealed predecessor poison the run. Recovery never creates a
missing committed segment or removes a partial successor. Deleting both history
and its same-user anchor has no external witness; manifests do not upgrade
`none` protection.
The [segment schema](ledger-v1/segments.schema.json) fixes the manifest encoding.

`<data>/ledger/index.sqlite` is a disposable SQLite projection of run metadata.
The writer rebuilds it from recovered canonical streams at startup and updates
it after handing off the durable response. Index errors are reported separately
by `doctor`; they cannot authorize execution, poison a sound canonical stream
or revoke a durable append receipt. SQLite lock contention fails immediately,
so an unavailable projection does not stall the next writer request.
Pruned runs recover their replay identities from the retained GC anchor described
in §8. Portable bundles and explicit signer verification are described in §8.4–8.5.

The owner reads the jail's canonical receipt at
`<data>/attempts/<attempt_id>/jail.json`. It does not request another receipt copy
inside the shared state root; the jail's receipt-copy fence forbids that path.
Admission and final intent records embed the validated receipt before their
acknowledgement. Portable bundles extract receipts from those canonical records;
they never trust a loose receipt copy in the run's `receipts/` directory.

## 5. Acknowledgements, failure and recovery

Every successful mutation follows this order:

1. Encode and validate the bounded canonical record without changing state.
2. If necessary, create and synchronize the next segment and its directory;
   append the exact record bytes and LF to the private active segment.
3. `fsync` the stream.
4. Write a new private projection, `fsync` it, rename to `run.json`, and `fsync`
   the containing directory.
5. Atomically write and synchronize the segment/replay manifest and run directory
   before returning `{seq, digest}`. Update the disposable SQLite projection separately.

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
receipt. Startup synchronizes every verified segment through the same descriptor
used to read it before publishing the repaired projection or promoted manifest.
A recovery sync failure refuses startup; no recovered retry can be acknowledged before that barrier.

`verify` reports `local_consistency`, `coverage` and `child_protection` separately.
A valid chain is local consistency only: deleting both history and its same-user
manifest anchor has no external witness in this slice.
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
The ledger does not archive vendor state. Whole-run GC removes inventoried
stdout/stderr captures with canonical history; separate capture-age policies and
structured minimization options remain future work.

Selected foreground streams are forwarded through separate queues of at most
128 chunks of 8192 bytes each (1 MiB queued per stream). Queue overflow or a lost
sink fails strict execution; forwarding completion has a two-second grace.
Capture or forwarding failure records incomplete capture evidence and an unknown
run outcome when the writer is reachable. Batch output uses independent sinks.

## 7. Bounded evidence readers

`query` reads one run at a time through the authenticated local writer. Select
exactly one class: `--execs`, `--paths`, `--hosts` or `--denials`. It returns the
stored records, preserving their source fields, sequence, stage and provenance;
it does not combine them into inferred actions or reconstruct file contents.

| Selector | Included records |
|---|---|
| `--execs` | Source `proc.exec` and `proc.exit` events |
| `--paths` | Source filesystem mutations and `fs.deny` events |
| `--hosts` | Source network and proxy events, with their separate coverage classes |
| `--denials` | Source events whose decision is deny, `fs.deny`, and owner `denied` records |

An owner denial is an attributed admission decision, not an observed syscall.
`--stage attempt|result` filters the original source stage and excludes owner
records that have no source stage. The frozen source contract has these two
stages; `decision` is a separate field. `--since` is inclusive and `--until`
exclusive on the writer's `received_at`, not the source clock. Both bounds use
whole-second UTC `YYYY-MM-DDTHH:MM:SSZ`. Dates must be valid and, when both bounds
are present, `since` must precede `until`; equal or reversed bounds refuse.

The page reports the run state, snapshot chain head, bounded coverage summary,
`child_protection`, local consistency and stream health independently. An empty
selection with unsupported or unobserved coverage says unobserved; it does not
say that no action occurred. A `none` run remains unprotected. These local
reader labels do not establish external custody or managed project authorization.
The coverage summary includes `selection_status`: it is `unobserved` if any
selected class lacks active coverage, including a mix of active and unsupported
classes. This label does not erase known records returned by the query.

`local_consistency` covers accepted records in the pinned snapshot checked so
far. It is not a fresh check of the entire current file. Retrying the most recent
cursor returns its cached, previously verified page even if the file has since
changed. Reading a new page checks the live path, snapshot length and remaining
record digests. Use `verify` for a fresh whole-stream check.

Query pages default to 100 records and accept limits from 1 through 1,000. Each
request scans at most 128 KiB and 32 frames, and returns at most 128 KiB of query
records. Consequently an empty page can still have a continuation cursor:
the scan may not yet have reached matching records. A legal matching record
that cannot fit in the query response is identified by sequence and byte size;
the cursor does not advance past it. Use exact NDJSON export to retrieve it.

Pagination pins one run, filter, limit and snapshot head `(head_seq, head_digest)`.
Later appends are outside that snapshot. The most recently consumed continuation
cursor can be retried for the identical page; older positions refuse rather than
retaining an unbounded page cache. Cursors are opaque reader positions, not
bearer authorization.
The writer retains at most 32 reader sessions, with a ten-minute expiry. Reader
positions persist as bounded private checksummed checkpoints under
`<data>/ledger/readers/`. A checkpoint is synchronized before its page is returned.
Restoration synchronizes the validated checkpoint descriptor and its directory
again before acknowledging a retry, including after an earlier rename whose
directory synchronization failed.
Restarting the writer preserves the snapshot and the most recent page retry,
including partially exported records. Checkpoints retain positions and response
digests, not copies of event payloads or captured output. An expired, corrupt
or unsafe checkpoint, replaced canonical segment inode, or changed pinned
history refuses explicitly. Starting again creates a fresh snapshot; do not append that output
to a partial export from the old snapshot.
Safe corrupt checkpoint files consume bounded session capacity until their
filesystem timestamp expires, but do not block fresh snapshots or other cursors.
Unsafe files or an overfull checkpoint directory still refuse housekeeping.
Restoring a cursor uses canonical boundaries already verified during writer
recovery, reconstructs at most one existing 1 MiB frame, and replays one ordinary
bounded page to corroborate the prior response. Snapshot state, protection and
bounded coverage labels must also match their canonical sequence anchor; the
selection label is derived from that coverage. It does not rescan the history.
Checkpoints are at most 32 KiB each and the checkpoint directory scan is bounded.
Version 2 checkpoints bind a digest of the ordered snapshot segment identities
and byte boundaries. Logical byte offsets remain stable across rotation, so
readers keep their original snapshot as later files are added. Version 1
checkpoints still restore a snapshot wholly within the first segment. The
reader keeps one active stream descriptor and checks at most 4,096 segment
identities per page; it does not concatenate history into memory or hold every
segment open. Validation and cursor restoration use transient descriptors.

Cross-run queries accept up to eight explicit, unique runs:
`query --run A --run B --execs --json`. The [query envelope](ledger-v1/query.schema.json)
contains independent `pages` and per-run `problems`; each page retains its own
snapshot, coverage, protection, stage and original provenance. There is no
atomic snapshot across runs. The same filters and per-run limit apply to every
selected run. Resume each unfinished run with `--resume RUN=POSITION`, using
that page's `next_cursor`. Omit finished runs from the next request. A selected
run without a resume position starts a new snapshot; it does not implicitly
continue a previous invocation. The existing single-run `--cursor` and output
shape remain supported. Any failed or inconsistent page makes the CLI exit
nonzero while retaining successful pages. Omit `--run` to use filtered run
discovery, described below.

`diff A B --json` compares **event counts**, grouped by class, source, operation,
stage, decision and the complete source outcome. It does not compare paths,
hosts, process identities, event order or field values; equal counts do not
establish equivalent behavior. Owner and operator intents and wrapper receipt
notes are excluded. Audit `net` and `proxy.net` remain separate classes. Each
changed bucket carries counts and the first contributing canonical sequence
and original provenance from each side; these references are examples, not a
list of every contributing record.

The [comparison report](ledger-v1/diff.schema.json) retains both snapshot heads,
coverage summaries and protection labels. A class is comparable only when both
snapshots are terminal (`settled` or `denied`), completely read without a
consistency failure, have active gap-free coverage for that class, and declare
the same nonempty source set. Global or ledger gaps make all classes
incomparable. Unknown, pruned, corrupt, active or unsupported evidence never
becomes a count of zero on an allegedly comparable side. `comparison_status`
is `comparable`, `partial` or `incomparable`; `complete` describes successful
snapshot reads, independently of class comparability. A failed read or exhausted
budget returns an incomplete report and exits nonzero; differences themselves
do not make the command fail.

Comparison uses the existing bounded, pinned reader and parses verified NDJSON
incrementally. Each side is capped at 64 MiB, 4,096 pages, 4,096 distinct count
buckets, 8 MiB of keys and 8 KiB per key; the invocation has a 120-second read
budget (checked between socket calls). Output pages default to 100 changes,
accept `--limit 1..1000`, and cap serialized change objects at 128 KiB. Resume
with `--after` from `next_after`. Each output invocation rereads the two streams
and refuses if either head or the ordered run selection changed. The position
is not authority and conveys no additional retention pin; ordinary reader pins
and expiry still apply. Snapshots are taken independently when each read starts.

`diff A B --by targets --json` additionally groups observations by their stored
**target labels**, using `mode: target_counts`. Default `--by counts` retains the
existing count-only behavior and output shape. Both retain the complete source
outcome, operation, stage and decision in each key. Target positions also bind
the comparison mode; a position from one mode cannot continue another.

`target_scope` records the supported operations: executable paths for `proc.exec`,
filesystem paths for create/write/unlink/deny, both ordered endpoints for rename
(including denied rename), and original proxy destination strings. Path kinds,
byte-valued path representations, digest reasons and `path_basis` are preserved
exactly, along with optional `action` and `attempted_operation` fields. No path
normalization, host resolution or decoding of digested external names occurs.
Workspace and scratch labels remain relative to each run's own roots. Equal
labels do not establish the same file, executable image, content or remote peer.
Process IDs, timestamps, proxy request IDs and resolved proxy addresses are not
target keys. Process exits have no executable target observation and are outside
this mode; audit network and limit classes are explicitly unsupported for target
comparison. Count-only mode still compares those observations when covered.

A missing, unavailable or incomplete required path (including either rename
endpoint), or a missing/empty proxy destination, makes that entire class
incomparable for target mode. Each side reports `unavailable_targets` with the
count and first canonical sequence/provenance reference for affected classes.
This does not alter the original coverage report. For example, a relative
shell path can be recorded as `relative_to_unobserved_cwd`; a complete argument
snapshot does not make that an identified workspace path. Explicit absolute
arguments under a known root can yield workspace-relative labels. Healthy
classes can still be compared; an empty change list must be read with the per-class status. Oversized
target keys fail under the existing 8 KiB key/8 MiB aggregate budgets, never get
truncated or silently omitted. The ordinary snapshot, corruption, read budget,
output pagination and protection rules above apply to both modes.

`export RUN --ndjson` reads all records, including preparation and owner intents.
It writes the exact stored canonical UTF-8 bytes and LF delimiters to stdout,
without reserialization, new fields or a new hash chain. No receipt side files,
capture contents or vendor state are included. Status goes to stderr; `--json`
emits NDJSON status events, not a single JSON value. A `checkpoint` event follows
each fully written and flushed page and includes the next cursor; a `finished`
event carries the final consistency, coverage, protection and stream labels.
Preserve the status stream alongside the exported records.

Export validates a complete record before releasing its bytes in chunks of at
most 64 KiB. This supports a legal canonical record up to the existing 1 MiB
frame bound without widening the socket response bound. It preserves the same
snapshot head across chunks and supports `--cursor` within the live reader
session. To resume after interrupted output, preserve exactly the stdout prefix
identified by the last checkpoint's `bytes_written`, then append the resumed
output to that prefix. Discard any later partial stdout, which has no checkpoint;
otherwise retrying can duplicate bytes. `bytes_written` counts only the current
CLI invocation. Truncated, noncanonical or corrupt history is never silently skipped:
only its explicitly verified prefix can be returned, completion remains
incomplete, and the CLI exits nonzero. A transport or cursor failure prints an
escaped diagnostic and may have no JSON completion record. Partial stdout from a failed export must
not be presented as a complete snapshot. `done` means the reader reached its
snapshot boundary, not that the agent succeeded or the attempt settled.

The [read request schema](ledger-v1/read-request.schema.json),
[reader page schema](ledger-v1/read.schema.json) and
[export status schema](ledger-v1/export.schema.json) describe this bounded local
interface. Their fixtures are document contracts, not a production contract
freeze or proof of an external custody boundary.

### 7.1 Live tail

`tail RUN [--cursor CURSOR] [--json]` returns one bounded page from the beginning
or the supplied byte position. `tail -f RUN` polls for later records until
interrupted; `--timeout SECONDS` optionally bounds that follow interval.
It follows after launch settlement too, because later operator records remain
possible. It connects to the existing writer and never starts a writer as a
side effect of reading. Transport loss may end the command; resume explicitly
with the last fully consumed page's cursor after the writer is available again.

Each JSON page carries the observed head, launch state, bounded coverage,
protection, local consistency, canonical `ndjson` fragments and `next_cursor`.
`--json` emits one page per line; default output is formatted JSON. Idle follow
polls do not repeatedly print empty pages. Concatenating the `ndjson` fields
preserves exact canonical bytes, including source provenance and sequence.
`scanned_through_seq` counts fully emitted records; a page can end within a
record. Consume or discard each page as a whole, and save its cursor only after
its output is committed to your sink. A cursor is a position, not a new snapshot
or a bearer credential. Retrying it reads the same prefix but may include later
appends and a newer head.

The reader returns at most 64 KiB of UTF-8 fragments, reads at most 32 frames
and normally scans at most 128 KiB per call. One larger legal record is verified
whole (at most the existing 1 MiB frame bound) before emitting any of its bytes;
subsequent fragments reverify it. Positions bind the run, completed sequence and
digest, plus a partial record's digest and UTF-8 byte boundary. They survive
segment rotation and writer restart without storing payloads or checkpoint files.
Each read validates at most the existing 4,096 segment identities. Following
uses bounded polling instead of occupying the writer queue with a waiting read.

`caught_up` means only that this page reached the head observed by that call.
`stream_status: complete` describes a terminal launch record, not success or an
immutable final history. Local consistency covers the returned bytes against
the writer's accepted history; prior bytes skipped by a cursor are not freshly
reverified. Use `verify` for a whole-history check. Damaged bytes, unsafe files,
unexpected trailing data, poisoned streams and uncorroborated positions refuse
explicitly. This reader does not pin retention: use an operator hold if history
must remain available. Pruning between polls causes refusal, never silent
skipping or a reset to another stream.

The [tail request](ledger-v1/tail-request.schema.json) and
[tail page](ledger-v1/tail.schema.json) schemas describe these bounded reads.

### 7.2 Run catalog and filtered discovery

`runs --json` returns a [catalog envelope](ledger-v1/catalog.schema.json), replacing
the earlier full-record array. Each summary preserves the accepted run identity,
chain head, state, recorded outcome, protection, bounded coverage, launch name,
tags and pruning markers. It omits full payloads, receipts and capture contents.
Use `show RUN` for the full record. `evidence_status: available` describes the
writer's accepted projection; catalog listing does not freshly verify disk bytes.
Poisoned runs are explicitly ambiguous with degraded coverage and unknown outcome;
pruned runs retain their original labels and retained-history marker.

Filter with `--launch NAME`, repeated `--tag TAG` (all must match), `--outcome`
(`pending`, `refused`, `exited`, `signaled`, `exec_error` or `unknown`), and
`--since` / `--until`. Run time bounds select **last accepted writer activity**,
including later operator records, using inclusive/exclusive whole-second UTC
bounds. They do not select by launch start time or source event clock.

`run --launch NAME --tag blue --tag qa ...` records the explicitly selected
launch profile name and sorted tags in the immutable preparation payload. Tags
are at most sixteen unique ASCII identifiers, each 1–64 bytes, using letters,
digits, `_`, `.`, `:` and `-`. They are operator metadata, not authorization or
attested producer observations. Legacy preparations remain unchanged: absent
launch names and tags appear as `null` and `[]`; no labels are inferred from
workspace paths or vendor state. Changing labels on the same request ID refuses.

Catalog pages default to 25 summaries, accept `--limit 1..100`, and cap serialized
summary bytes at 128 KiB. They use canonical run-ID order, not time order.
Each call scans at most 16,384 stored runs; a larger catalog refuses explicitly,
while explicit run readers remain available. The legacy socket `runs` endpoint
is retained only for at most 100 full records within a 128 KiB serialization
budget; larger responses instruct callers to use catalog pagination.

Resume with the returned `next_after` as `--after`, keeping the same filters and
limit. The bounded position binds normalized filters, the last run ID and a
fingerprint of all matching summaries and heads. Restart/retry preserves the
selection while those summaries remain unchanged. Any matching addition, new
record, changed label or pruning marker invalidates continuation and requires a
fresh discovery; changes to excluded runs do not. Positions confer no authority
or retention hold and do not create new persistent sessions.

`query --execs --launch NAME --tag blue --outcome exited --json` discovers runs
without explicit IDs. It returns one ordinary bounded event page from one run
per invocation in a [discovery envelope](ledger-v1/discovery.schema.json).
Use `--run-since` / `--run-until` for run activity; existing `--since` / `--until`
still filter individual records. Continue using `--after` until `done` is true.
The position binds the matching catalog, event filters, limit, current run and
ordinary reader position. Every page checks that its run and snapshot head match
the selected catalog summary. Explicit `--run` cannot be combined with catalog
filters or `--after`; its existing `--cursor` and `--resume` remain supported.

Every run preserves its own coverage, protection and original source attribution.
There is no atomic cross-run snapshot. Opening the first page of a run uses a new
reader: retry preserves content and head but may return a new reader token.
Subsequent pages retain ordinary snapshot pins, expiry and restart/retry rules.
The catalog itself adds no GC pin. A changed matching head refuses continuation,
including on an active run; restart discovery or use an explicit run reader to
keep a snapshot across appends. Failed or pruned reads return an explicit problem
and a position for the next run when one exists. Corrupt pages preserve their
failure labels. Either condition exits nonzero; `done` describes traversal, not
success. Oversized records retain the existing blocked reader continuation and
must be retrieved through export. An empty matching catalog has no run or page.

The [catalog request](ledger-v1/catalog-request.schema.json) and
[discovery request](ledger-v1/discovery-request.schema.json) schemas describe
these interfaces. Their JSON positions are local continuation data, not portable
custody proofs or signed capabilities.

## 8. Retention policies, holds and pruning

`hold RUN [--request-id ID]` and `release RUN [--request-id ID]` append canonical
operator records through the authenticated local writer. Their bodies are empty;
the peer supplies neither provenance nor an effect id. Owner and producer
capabilities cannot emit these kinds. One operator hold covers the run and its
captures. `show` includes `holds: ["operator"]` while held; an absent `holds`
field means no hold, including in legacy projections. Replay rebuilds this field
from canonical records, never from a mutable projection. Older ledger binaries
cannot read the new record kinds and must not be used to write these stores.

Each mutation returns the request id and its original append receipt. If no id
is supplied, the CLI generates one and includes it in an error diagnostic if the
outcome is uncertain. Retry that same command with the same id. Replaying an old
hold after a release returns the old receipt without reinstating the hold;
replaying an old release after a new hold likewise leaves the current hold intact.
Reusing an id for the opposite operation refuses. Holds work on active and
terminal runs, including unknown outcomes, and share the ordinary append,
rotation, synchronization and recovery barriers.

```sh
ouro-ledger hold RUN_ID --request-id keep-investigation-1 --json
ouro-ledger gc --dry-run --json
ouro-ledger release RUN_ID --request-id release-investigation-1 --json
```

The writer reads the operator's `~/.config/ouro/config.toml` (or
`$OURO_CONFIG_DIR/config.toml`) at startup. Restart the writer after changing it;
clients cannot replace an existing writer's configuration by changing their own
environment. Detached writer services preserve an explicit absolute
`OURO_CONFIG_DIR`. A missing file uses 90 days for history and captures. Invalid,
oversized, linked or group/other-writable configuration refuses startup rather
than silently selecting defaults. A `[ledger]` section is also accepted by the
jail, which does not apply retention itself.

```toml
[ledger]
retain = "90d"
capture_retain = "7d"
```

Create this file with mode `0600` (for example,
`chmod 600 ~/.config/ouro/config.toml`, adjusting a relocated path).

Both values accept whole days `1d..36500d`. Omitted `capture_retain` follows the
resolved history policy; an explicit capture policy cannot exceed history
retention. This keeps capture bytes from outliving the records that explain
them. `doctor` includes the writer's configured days. `gc --retain-days N` and
`--capture-retain-days N` override their respective settings for one invocation;
the resolved pair is validated together and reported in the plan/result. No
configuration setting schedules automatic deletion.

`gc --dry-run` returns one page described by the
[GC plan schema](ledger-v1/gc-plan.schema.json), with separate history/capture
cutoffs, candidate flags and keep reasons. A page defaults to 25 runs,
at most 100; pass `next_after` as `--after RUN_ID` to continue in run-id order.
Each page reflects current writer state, not a cross-page frozen snapshot or a
reusable deletion authorization. The preview requires an existing writer:
it does not start recovery, rebuild the index, create reader directories, expire
checkpoints, append records or delete files.

Candidates must have a recorded, known terminal outcome, no operator hold, no
reader pin, no poisoned state and an unchanged manifest/segment layout. Active
runs and `outcome_unknown` are retained. Age starts at the latest canonical
writer receipt time, including later notes and hold/release records, rather than
producer timestamps or filesystem modification times. Clock regression cannot
shorten that interval; unsupported or future activity times retain the run.
At the exact cutoff a run has completed its retention interval.

Live reader checkpoints pin their run for the normal ten-minute retry lifetime,
including completed pages whose replies may have been lost. Pins survive writer
restart. Recent corrupt or interrupted checkpoints whose run cannot be established,
unsafe paths and an oversized checkpoint directory conservatively block all
candidates. The preview reads at most 64 checkpoint entries of at most 32 KiB
each, and at most 4,096 segment descriptors per run. It leaves even expired
checkpoints untouched.

The response explains each retained run through `keep_reasons`, and preserves
its chain head and `child_protection`. It always says `dry_run: true`,
`deletion_supported: true` and `verification_required: true`. A candidate is a
retention assessment against accepted writer state and current layout; the
preview does not hash all canonical bytes again or inventory capture sizes.

`gc` without `--dry-run` deletes eligible captures or whole-run history through
the existing writer. It uses the same retention policy and pagination and returns a
[GC result](ledger-v1/gc-result.schema.json) with `pruned`, `captures_pruned`, `kept`, `failed` and
`next_after`. Whole-run expiry takes precedence when both are eligible. A per-run failure gives a nonzero CLI exit; other runs in the page
can have completed. Repeating GC returns the same retained receipt for an
already-pruned run. Receipt counters describe the original inventory, not fresh
bytes removed by each retry. This is an explicit operation, not automatic expiry.

Deletion requires a quiescent writer: an owned prepared or admitted run refuses
the entire operation. Full verification runs on the single writer, so a launch
must finish or be reconciled first. The deletion response timeout is five minutes;
a timeout does not cancel work already accepted. Retry GC or restart the writer
to resolve an uncertain result. A page is not an atomic transaction across runs.

For each eligible run the writer replays and verifies all canonical segments,
compares their chain, state and replay identities against accepted writer state,
and inventories exact segment bytes and selected stdout/stderr captures. It then
publishes a canonical, checksummed [GC anchor](ledger-v1/gc-anchor.schema.json)
as `gc.json`: synchronize the temporary file, rename it, then synchronize the run
directory **before any unlink**. This retained authority holds the original run
metadata, segment manifest, immutable request/effect receipts, payload digests,
operator identity, retention times and exact file hashes, sizes and inode/device
identities. It does not retain canonical event bodies or captured stream bytes.
Metadata and embedded jail receipts remain; pruning is not a full data-erasure
guarantee or an external custody proof.

Only named canonical segments and `artifacts/stdout.bin`/`stderr.bin` in that
inventory may be removed. The writer rechecks owned private directories, regular
unlinked files, identity, size and contents before unlinking through a pinned
parent directory. Symlinks, hard links, changed bytes or unexpected segments
refuse. There is no recursive deletion; run directories, `segments.json`, replay
anchors, projections, reader checkpoints and other files remain. Inventory is
bounded to 4,096 segments of at most 1 GiB each, two captures of at most 16 MiB
each, 65,536 replay-map entries and 16 MiB of retained metadata. Oversized runs
are retained with an error. These bounds do not change normal segment rotation.

After unlinking, file-parent directories are synchronized before publication of
the matching [completion marker](ledger-v1/gc-complete.schema.json),
`gc-done.json`. Restart resumes a pending inventory, accepting authorized missing
members and refusing changed or reappearing files. Corrupt retained authority
refuses writer startup rather than recreating preparation identities from absent
history. Unknown outcomes, holds and live reader pins never enter this protocol.

`show` and `runs` preserve terminal state, outcome, chain head and protection,
with `history.state: pruning|pruned`. Collected captures report `pruned`, zero
`stored_bytes` and their original `pruned_bytes`. Exact preparation, owner,
request and effect replays remain stable; new mutations refuse after the anchor
is durable. Query/export refuse with an explicit pruned-history error. `verify`
reports zero available events and the history marker: its local consistency
result covers retained metadata, matching completion and projection, not deleted
event bytes. The original `none` label remains `unprotected`.

### 8.1 Capture-only expiry

Before history is eligible, GC can remove the selected stdout/stderr captures
while preserving canonical events, manifests, replay identities and all query
and export bytes. The same known-terminal-outcome, hold, reader-pin, clock and
layout checks apply. Empty selected captures are still inventoried and removed;
unselected streams are not candidates. Both captured streams share one policy.
Age uses the latest canonical writer activity, just like history retention.

The writer verifies canonical history and inventories at most two regular,
owned, unlinked capture files of at most 16 MiB each. It synchronizes the
checksummed [capture inventory](ledger-v1/capture-gc-anchor.schema.json) as
`captures-gc.json` before unlinking anything. That inventory binds the terminal
canonical chain, original capture metadata, operator, times, policy and exact
file hashes/inodes. Its size is capped at 64 KiB. It cannot name canonical
segments or arbitrary paths. Restart validates the anchor against canonical
history and resumes the inventory; changed files, unsafe links, missing authority
and reappearing completed files refuse deletion. Corrupt canonical history
keeps its existing poisoned-stream behavior and cannot authorize capture deletion.

A synchronized [completion marker](ledger-v1/capture-gc-complete.schema.json),
`captures-gc-done.json`, follows the unlink and directory-sync barriers.
`run.json` exposes a separate `capture_history` marker (`pruning` or `pruned`);
event `history` stays absent until whole-run pruning. Collected streams report
`pruned`, zero stored bytes and their original `pruned_bytes`. The projection
and SQLite index can be rebuilt from canonical history and the capture anchor.
`verify` reports incomplete deletion without resuming it. New mutations refuse
while capture deletion is pending; completed capture expiry permits later holds,
notes and eventual whole-run pruning. It does not change canonical activity time.
The capture anchors remain after whole-run pruning so loss or reappearance is
still detectable. Downgrading these stores to a writer that does not understand
capture-pruning anchors is unsupported. Existing `none` protection labels remain unchanged.

Capture receipts describe the original inventory, not bytes removed by a retry.
After completed capture expiry, subsequent previews report `captures_pruned`
(and no new capture candidate); whole-run deletion continues to use its own
retention clock. A reader's checkpoint protects both history and captures even
though canonical export contains no capture bytes.

## 8.4. Unsigned portable evidence bundles

```sh
ouro-ledger bundle RUN --output /absolute/new-bundle [--capture stdout] [--capture stderr] --json
ouro-ledger verify-bundle /absolute/new-bundle --json
```

`bundle` connects to an existing writer and exports one pinned snapshot. The
new private directory contains exact canonical records concatenated into
`events.ndjson`, a canonical `receipts.json` array extracted from embedded
admission/final records, and `bundle.json`. Optional `stdout.bin` and
`stderr.bin` are included only when explicitly selected. No vendor state,
SQLite index, credentials, raw argv or environment is discovered or copied.
Selected output and explicit record bodies can contain secrets.

The [manifest](ledger-v1/bundle.schema.json) inventories each member's length and
SHA-256. Its `run` is replayed from the exported records and describes that
historical snapshot, including capture selection, truncation, incomplete output,
coverage gaps and protection. It does not claim that captures omitted from the
bundle remain available in the source store. Capture hashes have the explicit
basis `bundle_time`: original capture content hashes are not part of the launch
receipt. A capture hash proves consistency of the packaged bytes, not that the
node's owner left them unchanged before packaging.

Creation requires complete, locally consistent canonical history; already
pruned history refuses. A default bundle can still export canonical records
after capture-only expiry; explicitly selecting a missing capture refuses.
Captures require terminal recorded metadata, an authorized stdout/stderr
selection, and the exact recorded size. A running or prepared snapshot can be
bundled without captures. Receipt copies and all snapshot labels are rechecked
through the same schema, transition, chain and receipt-binding validation used
by store recovery. Segment layout is reassembled for portability; the original
physical segment manifest is not copied or represented as a separate witness.
The writer validates its source segment anchors before emitting the snapshot.

Bounds are 64 MiB of canonical records, 10,000 records, 20,000 reader pages,
16 MiB per selected capture, 4 MiB each for JSON metadata/receipts, and a
300-second work budget checked between reads and before publication. The
writer's 600-second reader pin protects both history and captures while the
bundle is assembled. A socket failure or budget exhaustion leaves no published
bundle. Files are synchronized in a private staging directory and published
with a no-replace atomic rename, then the parent is synchronized. A failure of
that final parent sync reports the uncertain durable publication explicitly.

`verify-bundle` is offline and read-only, even when the node data directory no
longer exists. It accepts only the flat allowlisted inventory, rejects symbolic
and hard links, nonregular files, extra/missing members, oversized data and
noncanonical/interrupted records, and hashes the same bytes it semantically
replays. Hash-consistent changes to projection labels or receipt copies refuse
unless they match canonical history. The
[verification report](ledger-v1/bundle-verification.schema.json) separates
`local_consistency`, original coverage, and `child_protection`. A consistent
`none` run remains `unprotected`.

The v1 format is **unsigned**, with `external_custody: false`. Someone able to
rewrite the complete bundle can recompute its hashes. Neither this manifest nor
its digest establishes a trusted signer, independent witness, current storage
availability, managed authorization or production readiness. The signed v2 format is described below; historical-custody migration remains
a separate milestone.

## 8.5. Explicit node signing and pinned verification

```sh
# Choose a directory outside agent workspaces. Nothing is generated implicitly.
ouro-ledger bundle-keygen --output /private/node-signing-key --json
ouro-ledger bundle RUN --output /absolute/new-bundle --capture stdout \
  --signing-key /private/node-signing-key/private-key.pk8 --json
# Obtain this public key separately from the node operator.
ouro-ledger verify-bundle /absolute/new-bundle \
  --trusted-key /trusted/node-public-key.json --json
```

Key provisioning is explicit and refuses an existing destination. A new 0700
identity directory contains a 0600 Ed25519 PKCS#8 v2 private key and a canonical
[public-key record](ledger-v1/signer.schema.json) in `public-key.json`. The
`key_id` is SHA-256 of the 32 raw public-key bytes. Signing requires an owned,
private, regular, single-link key file in a private directory, read through
pinned descriptors with no symbolic-link following and a 4 KiB input bound.
Public pins have the same bound and file/link checks, but can be publicly readable.
No SSH, release, fleet or ambient credential is reused, and keys are never
silently generated, replaced, copied into bundles or sent to the writer.

Signed bundles use the [v2 manifest](ledger-v1/bundle-v2.schema.json):
`schema: ouro.ledger.bundle/2`, `authenticity: signed`. All v1 record, receipt,
capture, resource, publication and offline replay rules still apply. One
mandatory [signature envelope](ledger-v1/bundle-signature.schema.json),
`signature.json`, is added to the flat directory. It is bounded to 4 KiB and
contains the algorithm, raw public key, key fingerprint, manifest digest and
64-byte signature, encoded as lowercase hexadecimal. It is not a data inventory
member. Old unsigned v1 bundles and verification reports remain supported.

The signed message is the ASCII bytes `ouro.ledger.bundle-signature/1`, one NUL
byte, then the **exact canonical `bundle.json` bytes including its final LF**.
This domain binds the schema, authentication mode, complete historical run
projection and all member hashes. Ed25519 uses the existing locked `ring`
implementation; no custom signature primitive or prehash mode is introduced.
The verifier checks the signature over the same manifest value whose member
bytes and canonical replay it verifies. Missing signatures, changed manifests,
unsupported algorithms, malformed identities and mismatched member bytes refuse.

Without `--trusted-key`, a valid signed bundle reports `signature.valid: true`
and `signature.trust: untrusted`. Its bundled public key identifies the claimed
signer but supplies no trust. With that option, the command requires a valid
signature from **exactly that independently supplied public key**, reports
`trust: pinned`, and rejects unsigned bundles, removed signatures, downgraded
manifests and substituted signers. The signing command itself pins the public
key derived from its explicitly supplied private key when checking publication.
The [v2 verification report](ledger-v1/bundle-verification-v2.schema.json)
keeps signer verification separate from coverage and `child_protection`.

A node key identifies a signer, not hardware, a managed principal, trustworthy
capture contents before packaging, current storage, a timestamp authority or an
independent witness. `external_custody` remains false, and `none` remains
unprotected even with a pinned signature. An operator holding the private key
can sign fabricated history. To rotate a key, provision a new directory and
communicate its public key through the operator's trusted channel; verification
never learns new trust from a bundle. Revocation, certificate chains, key escrow,
managed identity and independent custody are outside this slice.

## 9. Acceptance and remaining milestone 2 scope

The Rust store tests exercise process-lifetime writer exclusion; lost replies
and recovery; immutable prepare/request/effect identities; reserved admission
metadata; interrupted tails retained without truncation; injected ENOSPC, stream
sync, projection and directory-sync failures; source replay/gaps; conservative
owner-loss reconciliation; safe final paths and frame limits; and the persistent
unprotected label for `none`. Protocol tests cover forged role/attempt/peer
capabilities, caller identity fields, and interrupted or oversized transport.
These are deterministic fault injections, not a physical full-disk experiment.
The [October 4 storage/recovery record](ledger-v1/evidence/2026-10-04-storage/README.md)
documents the initial manifest/replay anchors, disposable index recovery and
durable cursor restart/retry tests, with working-tree source hashes and platform
limits. The
[October 5 rotation record](ledger-v1/evidence/2026-10-05-rotation/README.md)
covers multi-segment continuity, rotation failures and reader restoration.
The [October 5 pruning record](ledger-v1/evidence/2026-10-05-pruning/README.md)
covers hold/reader retention, deletion boundaries, retained replay identities,
changed-file refusal and actual CLI pruning of a synthetic aged run.
The [October 6 retention-policy record](ledger-v1/evidence/2026-10-06-retention-policy/README.md)
adds persistent settings, capture-only deletion/recovery and a real detached
launch using a custom policy on the VPS.
The [October 6 operator and tail record](ledger-v1/evidence/2026-10-06-operator-tail/README.md)
covers independent effect decisions, pending-effect retention, lost replies,
bounded live reads and operator appends during an actual contained launch.
The [October 6 cross-run record](ledger-v1/evidence/2026-10-06-cross-run/README.md)
covers independent query continuation, bounded count comparisons, coverage
incomparability and a real protected-versus-unprotected launch comparison.
The [October 6 discovery record](ledger-v1/evidence/2026-10-06-discovery/README.md)
covers bounded run catalogs, combined filters, restart-safe selection, stale
head refusal and automatic traversal of per-run evidence pages.
The [October 6 target-comparison record](ledger-v1/evidence/2026-10-06-target-comparison/README.md)
covers recorded path and proxy target grouping, unavailable-identity handling,
mode-bound pagination and canonical references from real contained launches.
The [October 6 portable-bundle record](ledger-v1/evidence/2026-10-06-portable-bundles/README.md)
covers unsigned snapshots, selected captures, tampering refusal and offline
verification of actual Linux bundles on Linux and macOS after source deletion.
The [October 6 signed-bundle record](ledger-v1/evidence/2026-10-06-bundle-signing/README.md)
covers explicit signing identities, pinned and untrusted verification, downgrade
refusal, independent OpenSSL checks and Linux-to-macOS verification.
The [October 6 Raspberry Pi catch-up record](ledger-v1/evidence/2026-10-06-pi-catch-up/README.md)
validates all those current ledger features natively on ARM64, including all
21 real launch tests, signed-bundle portability and the installed commands.

Linux execution tests must run the real jail through its closed gate, prove no
duplicate launch on replay/lost reply, exercise daemon/owner death and record
capture truncation. A macOS unit-suite pass is not Linux containment evidence.
The [October 2 lifecycle record](ledger-v1/evidence/2026-10-02-detached/README.md)
adds actual SSH disconnect/reconnect, independent writer/owner services,
bounded capture draining, cancellation and strict writer-loss checks.
Portable reader tests exercise class/stage/time filtering, bounded pages,
snapshot/cursor identity, exact canonical export bytes and damaged-prefix
reporting. CLI integration tests use the actual daemon and reader subprocesses;
they do not launch a jail or establish Linux containment.
The [contract validator](ledger-v1/validate_contract.py) checks versioned schemas
and fixtures only; it makes no runtime or custody claim.

Milestone 2 is still gated on the full North Star durability suite and these
unimplemented features: best-effort outage reconciliation and the
historical-custody migration at removal of the in-tree stores. Managed
single-worker submission additionally needs its own principal, authorization,
provenance and project-scoped reader gates. None is implied by this slice.

## 10. Linux quickstart

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
/absolute/checkout/target/release/ouro-ledger \
  --data-dir /tmp/ouro-ledger-data query --run run_REPLACE_WITH_RETURNED_ID \
  --execs --stage result --limit 100 --json
/absolute/checkout/target/release/ouro-ledger \
  --data-dir /tmp/ouro-ledger-data export run_REPLACE_WITH_RETURNED_ID \
  --ndjson --json > records.ndjson 2> export-status.ndjson
```

Batch JSON control has independent output sinks and is not mixed with raw child
output. Foreground I/O is the inherited default when `--io` is omitted; this
slice requires batch mode for `run --json`. Repeating the exact request uses its
durable run identity and does not execute a settled child again. Local Linux
capability requirements still apply: a refused jail preparation is a refusal,
not a reason to switch to `none` silently.
