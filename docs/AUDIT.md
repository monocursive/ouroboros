# Traceability and audit

Ouroboros can retain correlated evidence for native model and tool invocations. Audit is
opt-in. The default installation keeps its existing operational ledger and journal.
Audited execution uses a separate, append-only evidence lifecycle; rewind and checkpoint
pruning cannot discard those records.

| Mode | Recording failure | Extra infrastructure |
| --- | --- | --- |
| `standard` (default) | Existing runtime behavior | None |
| `local` | Execution can continue; storage errors and unresolved calls are visible | Local evidence directory |
| `required` | Refuses dispatch or stops dependent execution when required recording fails | Same directory; named identities and encryption keys |

SQLite is an optional **metadata index**, never the evidence authority. Set `index: true`
to enable it. It is bundled in the release: no SQLite CLI, database server or separate
migration command is needed. Deleting a damaged index and running `ouro audit reindex`
rebuilds it from evidence. Index failure falls back to canonical scans. Give each fleet
node its own local disk and index; do not share a SQLite file over NFS. See the upstream
[SQLite deployment guidance](https://sqlite.org/whentouse.html) and
[WAL constraints](https://sqlite.org/wal.html).

## Enable local recording

Create an absolute policy file outside every agent workspace, owned by the runtime
operator, with mode `0600`; keep its containing directory private and free of symlinks.
For example `/etc/ouroboros/audit.json`:

```json
{
  "mode": "local",
  "capture": "metadata",
  "root": "/var/lib/ouroboros-audit",
  "index": true,
  "organization": "example-firm",
  "writer_id": "workstation-01",
  "capacity_bytes": 1073741824,
  "retention_days": 90
}
```

Set `OUROBOROS_AUDIT_CONFIG=/etc/ouroboros/audit.json` in the runtime service environment
and restart it. The runtime creates private directories and files. `OUROBOROS_AUDIT_MODE`
can override the mode at startup; these are administrator-controlled service settings,
not workspace or session settings. With no policy environment variables audit stays off.
Keep `writer_id` stable across restarts and unique per node; never clone an active writer's
identity to another writer. Restart to apply a changed policy. Every record carries its
policy digest; session openings retain the public policy snapshot. Identity policy
changes affect the digest without publishing token fingerprints or encryption material.

## Required recording and identities

Use `mode: "required"` and add encryption and named identities to the policy:

```json
{
  "mode": "required",
  "capture": "full",
  "root": "/var/lib/ouroboros-audit",
  "index": true,
  "organization": "example-firm",
  "writer_id": "workstation-01",
  "encryption_key_id": "content-2026-09",
  "encryption_keys": {"content-2026-09": "BASE64_32_RANDOM_BYTES"},
  "identities": [
    {"id": "alice", "token_sha256": "SHA256_OF_ALICES_RANDOM_TOKEN", "roles": ["operator", "approver", "auditor"]},
    {"id": "audit-admin", "token_sha256": "SHA256_OF_ADMIN_RANDOM_TOKEN", "roles": ["administrator"]}
  ]
}
```

The placeholders deliberately fail validation. Generate independent random tokens and
32-byte content keys with your secret manager, store only token SHA-256 fingerprints in
the policy, and give each person their own token through a secure channel. Existing
`ouro --token-file`/gateway and browser sign-in use those tokens. No organization identity
is inferred from a browser session ID. Optional `expires_at` is an ISO 8601 timestamp.
Tokens are checked against the active policy on each request and stream delivery; native
execution checks that its initiating actor still has an execution role before each new
model/tool dispatch. The service configuration is the authority; deployment automation
must restart the runtime after editing it. A running process using embedded application
configuration can also install an updated policy explicitly.

| Role | Access |
| --- | --- |
| `operator` | Normal session reads and execution |
| `approver` | Approval and interactive response operations |
| `auditor` | Audit search, details, payload reads and exports |
| `administrator` | All operations, including hold/release, purge and index/archive maintenance |

Roles are organization-wide on one trusted deployment. This is not tenant isolation or
SSO. Erlang distribution peers and local BEAM code are administrator trust boundaries.
Restrict those separately, and use the existing gateway and web transport protections.
The standard/local single-user fallback remains available only when no identities are
configured. Required environment configuration rejects missing identities or encryption.

Required recording supports the native provider. Vendor agents, MCP,
WASM capabilities and component hooks do not currently
meet its full recording/containment contract and cannot execute through that profile.
Native reads, writes, edits, patches, shell, search, web fetch, questions, plans, skills
and supported native subagents retain runtime-boundary evidence. Shells require an OS
backend that fences both reads and network: workspace access is allowed, access to audit
storage/configuration is blocked, and shell network including loopback is denied. This
also means a shell command cannot make an unobserved model request using runtime secrets.
It is still a process invocation record, not tracing every internal syscall.

Agent workspaces must be disjoint from the evidence/configuration and runtime state
roots. The default worktree location inside runtime state therefore cannot be used as a
required-mode workspace: use a separately provisioned, admitted workspace. Remote native
execution checks the destination's organization, required policy, capture and custody
floor before handoff. The initiating identity must exist and be active on that node.

The packaged fleet launcher preserves explicit `OUROBOROS_AUDIT_CONFIG` and
`OUROBOROS_AUDIT_MODE` settings. The automatic `fleet service install` template does not
yet persist audit policy: it refuses an audit-configured installation instead of silently
dropping the policy. Use an operator-managed service with these environment settings and
the packaged `ouro service-run` command, or an operator-managed release. Verify
`ouro audit status` on every node after startup; editing only an interactive shell's
environment does not reconfigure an already running service.

## Evidence and privacy

Each event has a stable stream/sequence ID, predecessor hash, canonical-body SHA-256,
wall-clock time, node/writer/organization, runtime versions, capture policy and policy
digest. Logical effects, physical attempts, turns and tool calls have distinct links.
Session records link actor, parent session/task, fork and workspace. The operational
effect ledger continues to own execution admission and ambiguous-effect recovery.

Native requests retain the projected model input and the parsed final HTTP request
before its transport dispatch, with a SHA-256 digest and byte count of the exact body
sent. JSON whitespace and key ordering are represented canonically in evidence; capture
and redaction policy still apply to the retained content. Audited transport disables automatic retry, caching and
WebSocket reuse so hidden library attempts cannot bypass that boundary. Chunks are
committed as they arrive, before delivery. Terminal records include normalized usage and
provider metadata where supplied; absent usage/cost remains unknown. No price estimate
or provider-internal reasoning is fabricated. Tool evidence includes proposals, effective
validated input, authority, dispatch, process output, raw tool response, model-visible
result, and available before/after file snapshots. Hooks and escalated attempts have
separate records. A crash between dispatch and a recorded result leaves an **unknown**
outcome; replay does not silently rerun that effect.

| Capture | Retained audit content |
| --- | --- |
| `metadata` | Allowlisted operational fields; inputs/outputs explicitly withheld |
| `redacted` | Credential-key removal and known-secret text redaction; encoded binary artifacts explicitly withheld |
| `full` | Supported content with credential-key/text redaction; binary artifacts retained as encoded data |

Redaction is not a universal PII detector. Full-mode binary artifacts are opaque to text
redaction and may retain sensitive content. Metadata still contains potentially sensitive
identifiers, workspace paths, tool/model names and timings. Review those with the firm's
own policy. Content above the inline limit uses content-addressed blobs. When a key is
configured, content fields are encrypted with AES-256-GCM before persistence; keys are
absent from exports. Rotate by selecting a new `encryption_key_id` while retaining old
keys for reads. Losing an old key loses access to its content, even though hashes remain
verifiable.

**Capture policy applies to retained audit evidence. Operational state still needs the
conversation to resume.** A configured key encrypts new durable plane checkpoints,
native conversations, rewind manifests/blobs, compaction archives, staged attachments and
screenshots, and full shell-output files. Native image readers decrypt before checking the
original content digest. It does not encrypt
workspace files, OS logs, swap, provider-side records or pre-existing state. `ouro audit
doctor` reports plaintext/unreadable managed operational files under the configured data
directory. Custom storage adapters or `native_data_dir` overrides require their own
inventory. Review existing legacy journals and runtime logs separately.

For an existing installation, stop the runtime, make a protected backup, then scan and
encrypt managed operational state offline from the source checkout:

```sh
mix run --no-start scripts/audit-maintenance.exs scan /absolute/data /absolute/audit.json
mix run --no-start scripts/audit-maintenance.exs encrypt /absolute/data /absolute/audit.json
```

The migration rewrites only recognized managed content files, not credentials, workspace
files or canonical audit streams. It is restartable and uses atomic encrypted writes.
Migration tightens managed file permissions to owner-only, including legacy artifacts.
Retain keys with the backup. Existing plaintext journal/log copies and custom storage
must be handled under the organization's own retention procedure before claiming a fully
protected deployment. Full-disk encryption and process/OS access controls remain necessary.

## Investigate and export

Open **Audit** in the web navigation (`/audit`). Filter by session, actor, event kind,
model/tool and time. Follow a stream to its call outcomes, ordered records and referenced
artifacts. Content is rendered as escaped text. The web view displays storage policy,
coverage, unknown outcomes and errors, and downloads an authenticated evidence tar.

The same operations are available through `ouro audit` and typed `audit.*` gateway methods:

```sh
ouro audit status
ouro audit doctor
ouro audit search --actor-id alice --limit 50
ouro audit show STREAM_ID --since-seq 0 --limit 100
ouro audit artifact STREAM_ID BLOB_ID
ouro audit export ./incident-evidence --stream-id STREAM_ID
ouro audit verify ./incident-evidence --expected-digest MANIFEST_SHA256
ouro audit verify ./incident-evidence --trusted-keys ./custodian-public-keys.json
ouro audit restore ./incident-evidence ./restored-evidence --expected-digest MANIFEST_SHA256
```

Use the audit command's connection flags (`--addr`, `--token-file`, `--machine`) for a
specific listener or fleet node. `verify` and `restore` are completely offline: no gateway,
daemon start, provider credentials, tools or model replay. The digest must come through
an independent trusted channel; trusting a digest from the same compromised directory
establishes only consistency. A trusted-key file is a JSON map such as
`{"custody-2026-09":"BASE64_ED25519_PUBLIC_KEY"}`, obtained from the custodian separately.
With `--trusted-keys`, **every event** must have a valid bound receipt from a supplied key.
This validates the signed custody statements; a separately trusted manifest/inventory is
still needed to prove the export contains all expected streams or later events.

Exports contain exact canonical records, referenced ciphertext/plaintext blobs, available
receipts and a hashed manifest. They exclude SQLite, authentication tokens and encryption
keys. Manifest-last writes make interrupted downloads/restores invalid. Verification
rejects extra files, duplicate inventories, traversal, symlinks, malformed/partial records,
modified hashes, missing blobs and mismatched heads. Restore creates a new evidence
folder; it never overwrites runtime state or restores an executable session. Investigation
responses are bounded; oversized artifacts require export. Search results may lag the
canonical writer while indexing catches up.

## Independent custody

For an independent witness, add to the runtime policy:

```json
{
  "archive_required": true,
  "archive": {
    "url": "https://custody.example.internal",
    "token_file": "/etc/ouroboros/custody.token",
    "key_id": "custody-2026-09",
    "public_key": "BASE64_ED25519_PUBLIC_KEY",
    "previous_keys": {"custody-2026-08": "BASE64_PREVIOUS_PUBLIC_KEY"}
  }
}
```

Merge these fields into the policy, not a second policy file. The token file must be
private. HTTPS is required except loopback HTTP for testing. With `archive_required`, the
writer waits for a signed durable receipt before acknowledging each event, including
before any dependent dispatch. Collector outage therefore stops required work. Without
that flag, the background worker retries missing receipts with bounded batches/backoff;
inspect `status` or run `ouro audit flush`. OTLP export can run alongside this but is never
accepted as a custody acknowledgment.

The included collector runs **outside the agent runtime**, preferably on another host
and OS account. It holds the Ed25519 signing seed; the agent holds only the pinned public
key and append credential. Configure `OUROBOROS_COLLECTOR_CONFIG` to a private JSON file
with `root`, `organization`, `writer_id`, `token_sha256`, `key_id`, `private_key` (base64
32-byte signing seed), `retention_days`, `capacity_bytes`, and optional `port` (4319).
Use one collector instance per writer identity. From an assembled release:

```sh
bin/ouroboros eval 'Ouroboros.Audit.Collector.start_from_env(); Process.sleep(:infinity)'
```

Do not use the ordinary `start` command for this service. Bind its loopback listener to a
TLS reverse proxy with request limits, run it as a dedicated account, and keep its root
on protected local storage. The service has authenticated append and fresh signed
inventory endpoints, with no delete, agent execution or key-retrieval API. It rejects
out-of-order/conflicting records and verifies blobs before acknowledging. Duplicate
requests are idempotent. A crash after storing an event but before returning its receipt
can be recovered by retrying that same event.

On required-custody startup the runtime challenges the collector for a fresh nonce-bound
inventory and compares previously witnessed heads before admitting new work. This
catches truncation or whole-stream deletion unless an independently witnessed purge
permits it. Old public keys can remain pinned for historical receipt verification after
rotation; fresh inventories must use the current key. Back up the collector root and
signing keys separately from the agent host. A filesystem administrator can still rewrite
local storage: deploy immutable storage and independent monitoring if that administrator
is in the threat model. A self-hosted hash chain alone is not immutable evidence.

## Retention, holds and recovery

```sh
ouro audit hold STREAM_ID --reason 'Incident review'
ouro audit hold STREAM_ID --release --reason 'Review closed'
ouro audit retention
ouro audit purge STREAM_ID --reason 'Retention expired'
ouro audit reindex
```

Purge requires an administrator, an explicitly closed stream, elapsed retention and no
hold. Its durable governance authorization records the removed head before deletion; in
required custody it also needs a valid custodian receipt. Recovery finishes interrupted
cleanup. The retired stream ID cannot be reused. Purge removes that audit stream,
unreferenced local audit blobs and server-generated export copies containing the stream;
the SQLite projection catches up. Governance records and receipt metadata remain.
Operational session checkpoints, downloaded exports, backups and the independent
custodian have separate retention owners; this command does not claim global erasure.
Active/crashed streams are deliberately ineligible until their lifecycle is resolved.

Capacity pressure never trims or rechains audit history. A small reserve is kept for
administrative/governance records. Byte accounting includes observed local audit files;
background index/archive growth and real filesystem exhaustion also require a volume
quota and monitoring. On storage failure, halt required workloads, preserve the evidence
and logs, free capacity outside retained evidence or enlarge the volume, then restart and
verify. An ambiguously synced stream is poisoned for the current writer. A partial or
corrupt tail is refused on restart, not silently repaired. Restore an independently
verified backup and reconcile custody; never delete a tail merely to make execution start.
Keep protected evidence snapshots plus encrypted operational backups for complete disaster
recovery. The audit restore command restores evidence only.

## Telemetry and operating limits

Optional `otlp_endpoint: "https://collector.example.internal/v1/traces"` emits metadata-only
OTLP/HTTP JSON derived from canonical events. It carries deterministic trace/span IDs and
no prompt/output payloads. Delivery is at least once with durable watermarks; consumers
should deduplicate. Telemetry failure does not invalidate locally committed evidence or
required custody. The encoding follows the upstream
[OTLP JSON specification](https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding).

This first implementation targets a workstation or small private fleet, not a central
multi-tenant data platform. Local append is serialized; required custody adds a network
round trip per event. Index ingestion is incremental and SQL search is bounded, but
unindexed scans, stream details, verification, retention inventory and export assembly
still read retained history in memory. Bound archive size and stream length accordingly;
large organizations should benchmark representative workloads before setting retention.
The default capacity is 1 GiB, segments 4 MiB, inline fields 64 KiB, records 1 MiB,
investigation pages at most 500 records and download chunks 64 KiB. No sampling is applied
to canonical events.

Run the synthetic storage benchmark with `mix run --no-start scripts/audit-benchmark.exs
1000`. It reports synced append percentiles, index/search time and disk consumption and
verifies the resulting records. See the [implementation validation record](proposals/traceability-implementation.md)
for measured results and tested environments. Customer TLS, identity/key operations,
backup recovery, OS isolation and production load remain deployment acceptance work;
this feature does not assert certification or model correctness.

Skills are checked against protected paths during both discovery and loading, including
symlink targets. Skills stored beneath the protected Ouroboros configuration directory
are unavailable while audit is enabled; use project skills or configure
`native_user_skills_dir` outside protected storage.
