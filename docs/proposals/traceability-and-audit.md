# Traceability and audit improvement plan

Status: **proposal**, 2026-09-07. Based on source inspection of `dev` at `4aeee8f`.
This document proposes work; it does not claim that the controls below are implemented
or validated in production.

## Direction and scope

Make Ouroboros an inspectable execution runtime for firms that need to establish what
an agent was asked, what it sent to a model, which tools it invoked, under whose
authority, and what evidence supports the reported outcome.

The initial product should serve one organization running a local machine or private
fleet. Keep the existing installation usable without a database server or external
service. Add an optional audit profile, with a firm-managed setting that requires
recording before execution. Treat shared multi-tenant hosting as a later product.

The proposed promise is:

> Every supported model and tool invocation made through Ouroboros has a correlated
> evidence record. Required audit mode refuses new invocations when it cannot durably
> save the evidence required by policy. Investigations show missing, withheld, expired,
> and externally unobservable evidence explicitly.

This is a guarantee about controlled execution and evidence. It does not establish
model correctness, reveal provider-internal reasoning, or make an arbitrary shell
process or third-party agent fully observable. Those boundaries belong in capability
admission and the investigation interface.

## Current foundations and gaps

The following are verified source facts, not new production acceptance results.

| Existing component | Useful foundation | Gap for the proposed product |
| --- | --- | --- |
| [`Agent.EffectLedger`](../../lib/ouroboros/agent/effect_ledger.ex) | Records admitted effects before execution; records authority and refusals; restores unfinished attempts as ambiguous. | Node-local, content-minimized, mutable settlement, bounded to 1,000 terminal entries by default; whole-checkpoint writes. It is an operational authority record, not a long-term evidence archive. |
| [`Native.Inference`](../../lib/ouroboros/provider/native/inference.ex) | Gates native model calls and links outcomes to journal records. Native turn and summarization paths already use it. | Settlement is best effort. Long-term content and outcome completeness depend on another store. |
| [`Native.Journal`](../../lib/ouroboros/provider/native/journal.ex) | NDJSON, stored hash chain, per-record sync, explicit gaps, large-field blob references. | Recording failures allow execution to continue; the default 64 MiB budget drops old turns and rechains survivors. Blobs share rewind storage and its lifecycle. |
| [`Native.Loop`](../../lib/ouroboros/provider/native/loop.ex) | Records model provenance, normalized responses, tool results, approvals and injected context. | Model chunks accumulate in memory before the final `model_result` append. A crash can lose partial output. Tool results record the message after enrichment; audit also needs the original tool-boundary result. |
| [`Native.Model.ReqLLM`](../../lib/ouroboros/provider/native/model/req_llm.ex) | Projects requests for digests, normalizes response metadata, defaults model retries to zero. | A projected request is not a complete captured transport request. Establish coverage of effective provider options, actual requests, errors, overrides and every physical retry. |
| [`Prompt.Trace`](../../lib/ouroboros/prompt/trace.ex), [`Native.Replay`](../../lib/ouroboros/provider/native/replay.ex) | Prompt version/digest provenance and recorded execution through replay seams. | Digests alone cannot reconstruct content. Replay has named boundaries, including some compaction, fork and multimodal cases. See the as-built section of [REPLAY.md](../REPLAY.md). |
| [`Provider`](../../lib/ouroboros/provider.ex) | Explicit provider capabilities; vendor transports do not claim native replay. | A vendor transcript cannot establish every internal model or tool call. Audit coverage needs its own granular capability contract. |
| [`Web.Auth`](../../lib/ouroboros/web/auth.ex), [`Gateway.Conn`](../../lib/ouroboros/gateway/conn.ex) | Authenticated local access. | A listener token or browser session does not establish which employee approved an action. Organization identity and role enforcement need a separate design. |

Build on these boundaries. Keep the effect ledger's content minimization and recovery
role. Avoid converting UI events or ordinary logs into the audit authority.

## What an investigator should be able to establish

One call detail should answer these questions without manually correlating files:

- **Origin:** task, session, turn, parent agent, delegation, fleet node, initiating
  human/service identity, and the actor that approved or changed policy.
- **Model request:** requested model and provider, reported resolved model/version
  when supplied, effective generation settings, endpoint without credentials, SDK and
  runtime versions, system instructions, messages, attachment references, and tools
  offered to the model. Distinguish a transport capture from a normalized projection.
- **Model outcome:** ordered response chunks, tool proposals, finish reason, partial
  stream/error/cancellation, provider request/response IDs, timing and reported usage.
  Record price-table version and label computed costs as estimates; missing usage is
  unknown rather than zero. Include compaction, handoff and any future auxiliary calls.
- **Tool execution:** original proposal, effective arguments after hooks, tool and
  schema/version identity, cwd, relevant declared sandbox/network constraints, approval
  decision, start, stdout/stderr or structured output, exit/result status, affected
  resources, and available before/after artifacts. Distinguish the tool's original
  response from the result subsequently supplied to the model.
- **Authority:** which policy revision and rule admitted or denied the action, which
  hook changed it, approval scope and expiry, and whether enforcement succeeded.
- **Evidence quality:** capture policy, omissions and reasons, durable recording point,
  retention deadline, archive acknowledgment, integrity verification and unresolved
  outcomes. A call may have complete metadata but withheld content.

Give logical calls, physical attempts and stream chunks separate identities. A retry
is a new attempt under the same call; a fallback model is a separately identified
attempt with its own configuration. Propagate trace and parent IDs through native
subagents, teams, fleet dispatch, MCP and background work. Preserve forks and rewinds
as new linked history rather than rewriting what happened.

## Optional behavior with enforceable guarantees

Separate **capture policy**, **failure policy**, and **storage destination**. They are
different decisions. SQLite availability must not determine the audit guarantee.

| Profile | Behavior | Deployment |
| --- | --- | --- |
| Standard, default | Preserve today's ledger, replay and retention behavior. Extended audit is disabled; no claim of complete archival history. | Existing package and data directory. |
| Local audit, opt-in | Extended call records and investigation; explicit best-effort recording and gap status. Default to metadata; organization-approved content capture is a separate setting. | Local journal; optional embedded SQLite search index. No server. |
| Required audit, opt-in | Persist policy-required evidence before dispatch; stop new dependent work on recording failure; enforce retention and supported-adapter admission. | The same local installation, optionally with a customer-controlled remote archive. |

These are proposed profiles, not existing configuration keys. An organization should
configure the required floor outside the writable repository. Workspace settings and
agents may narrow permissions, but cannot turn audit off, reduce capture requirements,
or select an unsupported adapter. Record policy changes and use the same admission
rules for TUI, web, gateway, coding runs, interactive sessions and remote children.

For metadata-only capture, call content is explicitly unavailable. For content capture,
support approved redacted content and restricted full content where permitted. Show
what this means for replay before enabling the policy. The policy must govern the
existing journal, checkpoints, blobs, exports, search indexes and diagnostic copies;
adding a metadata-only audit index while another store retains full prompts is not a
metadata-only storage posture. Changes do not retroactively sanitize legacy data.

## Storage recommendation

**First evolve the existing journal into the canonical evidence record for audited
execution. Add SQLite as a rebuildable local investigation index. Defer PostgreSQL
until a central service or measured workload requires it.**

This keeps deployment small, reuses the existing replay investment and avoids making
two independent stores jointly responsible for proving one call happened.

| Choice | Assessment |
| --- | --- |
| Versioned journal with scan-based inspection | Lowest additional deployment cost; portable exports and straightforward append history. Cross-session search needs indexing as volume grows. |
| Journal plus embedded SQLite index | Recommended first database use. Indexed investigation without database provisioning; a lost index can be rebuilt from retained evidence. Adds a native dependency to release packaging. |
| SQLite as the canonical audit store | Credible alternative if a short prototype shows that journal rotation, catalog and retention work would cost more. Requires replay adaptation and a deliberate source-of-truth migration; do not support two canonical backends initially. |
| PostgreSQL behind an audit service | Revisit for central organization search, concurrent ingestion, access controls and operational scale. Adds service configuration, credentials, migrations and backups. |
| External archive / SIEM / telemetry backend | Useful destination for evidence custody or operations. Only a destination with defined durable receipts and retention can satisfy an archive requirement. |

SQLite is designed for embedded local storage. WAL allows concurrent readers with one
writer; keep all direct database access on the same host and use a local volume. Fleet
nodes must not open one SQLite file on a shared filesystem. See SQLite's
[deployment guidance](https://sqlite.org/whentouse.html) and
[WAL constraints](https://sqlite.org/wal.html).

Implementation details to settle in the storage prototype:

- Evolve `Native.Journal` behind a narrow audit-recording boundary. Audited sessions use
  versioned records that replay can consume; do not duplicate full payloads into a
  second parallel log. Retain a reader for legacy journals and label imported history
  as legacy, with its original gaps and limits.
- Use append-only segments with sequence bounds and hashes linked to prior segments.
  Seal and rotate segments without rewriting retained evidence. Maintain a durable
  catalog for node/session streams, including policy, approval and administration
  events outside a native turn. Lifecycle corrections are additional events.
- Keep evidence blobs under audit retention ownership, separated from rewind eviction.
  Persist a blob and its directory entry before acknowledging a record that references
  it. Restrict permissions and isolate deduplication by organization/security domain.
- Populate SQLite asynchronously from committed events. Commit indexed rows and the
  ingestion cursor together; deduplicate by stable event ID. Show the indexed watermark
  and lag. An index failure degrades search, while canonical evidence remains readable.
- Start with projections for `sessions`, `calls`, `attempts`, `events`, `artifacts`,
  `policy_decisions` and `archive_receipts`. Index task/session IDs, actor, time, model,
  tool, outcome and parent relationships. Make full-text content indexing opt-in.
- Ship the pinned SQLite engine/driver inside supported release artifacts; end users
  should not install the SQLite CLI or a compiler. Validate macOS/Linux packaging and
  actual dependency size before committing to the driver. Keep a no-index path.
- Make canonical backup, restore and offline export work without SQLite. If copying an
  active index is useful, use a supported snapshot mechanism such as SQLite's
  [backup API](https://sqlite.org/backup.html); otherwise rebuild it. Maintain archive
  consistency across the catalog, journal segments, blobs and receipts.

Keep runtime checkpoints and the operational effect ledger unchanged initially.
Replacing every persistence mechanism would enlarge this project without improving the
first investigator workflow. The ledger's write amplification can be addressed later
if measurements identify it as a bottleneck.

## Required recording semantics

Use one auditable invocation coordinator around the existing model/tool seams:

1. Assign immutable call/attempt IDs and resolve the effective capture and execution
   policies. Record refusals and approval decisions with trusted actor provenance.
2. Obtain the existing authority admission, then durably save a dispatch-intent record
   and all required request/argument artifacts. Do not dispatch without both gates.
3. Dispatch the model or tool. Record transport retries at the actual request boundary;
   prohibit invisible SDK retries when that boundary cannot be instrumented.
4. Persist response/output chunks in bounded batches, with sequence and byte offsets.
   In required mode, persist before presenting a batch as durable evidence or allowing
   it to trigger downstream work. Label any live uncommitted preview as provisional.
5. Persist terminal outcome and required artifacts before reporting audited completion
   or starting dependent effects. Correlate ledger settlement; reconcile an interrupted
   settlement by stable IDs on recovery.

There is no atomic transaction between local disk and an external tool/provider.
An intent followed by a crash may mean the call was never sent or that it completed
remotely. Recover it as **outcome unknown**, then reconcile using provider request IDs,
idempotency keys or observed external state where possible. Do not automatically retry
an ambiguous side effect or call it successful because a process exited.

If persistence fails after execution has begun, preserve the committed prefix, stop
new dependent work, attempt safe cancellation, and expose the unresolved attempt on
recovery. Bytes received but not committed before a crash cannot be recovered by a
promise. Bounded chunk capture reduces that window; it does not eliminate it.

Required local recording and required remote custody are separate policies. With
asynchronous export, publish the last remotely acknowledged sequence and the unarchived
window. If remote custody is mandatory, await the relevant durable acknowledgment at
the execution/completion gates. An outage then blocks work rather than silently
downgrading the guarantee. Test disk-full, timeout and recovery behavior explicitly.

## Privacy, integrity and organization controls

Capture and access controls belong in the first design, because prompts, source files,
tool output and screenshots can be sensitive evidence.

- Exclude transport credentials and authorization headers by construction. Use
  schema-aware capture and redaction before persistence/export, with a recorded policy
  version. Treat secret detection as a fallible additional filter. Keep omission
  reasons visible, and avoid exposing hashes of guessable secrets in public metadata.
- Keep audit data outside agent workspaces and exclude it from tool mounts, credential
  environments and ordinary search. File mode `0600` alone cannot protect evidence
  from a tool running as the same OS user; required deployments need an enforced
  process/sandbox boundary or separate writer service and restricted access.
- Introduce employee/service identities and separate operator, approver, auditor and
  administrator permissions for shared deployments. Obtain actor IDs from verified
  authentication, not request payloads. Carry identity across gateway and fleet hops.
  An externally supplied identity header is trustworthy only behind an authenticated,
  enforced proxy boundary.
- Audit evidence viewing, exporting, policy changes and deletions. Do not recursively
  create an access event every time the indexer reads its own access stream. Prevent
  unauthorized reads even when a caller knows an artifact ID or journal path.
- Define retention separately for metadata and payloads, plus holds, capacity limits
  and audited deletion. Purging must cover indexes, blobs, replicas and backup policy.
  At capacity, required mode pauses rather than silently trimming retained evidence.
  Rotate before the limit and expose remaining capacity to the operator.
- For full sensitive payloads, evaluate envelope encryption with customer-owned keys,
  key rotation and restricted decrypt permissions. Local encryption does not protect
  against an attacker who also controls the runtime and its accessible decryption key.

A local hash chain detects edits only relative to a trusted reference. An administrator
who can replace the journal can also recompute its chain, and deleting a valid suffix
can leave a valid shorter chain. Persist segment manifests and stream inventories with
sequence ranges and periodically anchor their digests outside the execution host.
Signed receipts or an independently controlled retention archive can make later
modification, truncation and whole-stream deletion detectable for the anchored range.

Signing keys and the archive authority must sit outside the agent/fleet execution trust
domain. A signing process on the same broadly trusted BEAM cluster is insufficient
separation for this claim. The verifier must show the anchored range and time, its trust
root, any missing streams, and the current unanchored tail. Integrity establishes what
was preserved, not whether the original event was truthful on an already compromised
host. Do not market generic regulatory compliance or tamper-proof storage from this.

## Investigation surface and integrations

Use the existing web interface for detailed investigations and TUI/CLI for discovery,
status and direct call inspection. Provide stable deep links from a task or approval
to the relevant call. Reading archived evidence must not require a live provider
process or API credentials.

The main workflow is **find a task → follow its call tree → inspect an attempt → open
its authority and artifacts → verify/export evidence**. Filter by actor, node, model,
tool, time, resource and status. Show the actual model input at a selected iteration,
including context removed later by compaction. Compare the proposed tool arguments,
executed arguments and returned model message.

Present coverage as separate dimensions: invocation visibility, content availability,
outcome certainty, retention, integrity and archive custody. Avoid a single green
“audited” badge masking unavailable content or a provider that exposes only transcripts.

Proposed CLI operations: `ouro audit status`, `search`, `show`, `export`, `verify`,
`reindex` and `doctor`. These are future commands. An export contains a versioned
manifest, records, authorized artifacts, policy revisions, completeness boundaries and
available external receipts. Offline verification checks hashes, references, sequence
coverage and signatures without running tools or calling a model. Replay remains
recorded re-execution; asking a model again is a fork.

Add opt-in OpenTelemetry export as a derived integration. Keep the internal evidence
schema versioned independently: the upstream GenAI event conventions are currently
marked Development and input/output content capture is opt-in. See the
[OpenTelemetry GenAI event specification](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-events.md).
Sampling and exporter outages may affect operational telemetry; they must not sample
away canonical audit records. Do not export sensitive content to a third party by
default.

## Delivery sequence and acceptance gates

| Phase | Deliverable | Acceptance gate |
| --- | --- | --- |
| 0. Contract and storage prototype | Coverage matrix for both execution planes and each adapter; threat model; event schema; journal/index prototype; packaged-driver check. | A native call chain can be investigated offline. Document exactly which transport data is captured. Decide journal versus SQLite authority once, based on measured write/retention complexity. |
| 1. Complete native call evidence | Correlated attempts, effective model request capture, tool-boundary records, chunk persistence, summarizers, approvals, native children and fleet links. | Success, failure, cancellation, denial, retry, compaction and child execution all produce linked records. A test provider/tool records actual invocations independently and matches the audit records. No inaccessible path may claim full coverage. |
| 2. Usable local audit | Versioned segments, retained blobs, optional SQLite index, search, detail, offline export/verify and visible capture controls. | An investigator can explain a changed file from its triggering input, model call, tool arguments, authority and result. Evidence survives restart; deleting/rebuilding the index preserves the same retained investigation results. |
| 3. Required audit and firm pilot | Admission/failure policy, protected audit storage, actor identity and roles for shared use, retention, backup/restore, administrative/access audit. | No supported invocation dispatches without required durable intent and artifacts. Kill/disk-full/permission-error tests expose unknown outcomes and prevent dependent effects. Agents cannot weaken policy, read the protected archive or bypass the declared execution boundary. |
| 4. Independent custody and central operations | Customer-controlled archive, durable upload cursors, external anchors, fleet completeness, optional central search and OTel export. | Disconnect/reconnect, duplicate uploads, node loss and archive unavailability obey policy. Modification, suffix removal and missing anchored streams fail verification. Restore and key rotation are rehearsed. |

Phase 1 and 2 form a useful native-first preview. Do not present that preview as the
firm-managed guarantee until phase 3 passes. Require phase 4 for claims about evidence
surviving execution-host compromise or loss. Vendor process adapters remain visibly
limited until independently tested instrumentation proves their coverage; required
full-call policies refuse those adapters.

Acceptance fixtures should also include MCP errors, hooks that rewrite arguments,
operator shell commands, malformed/partial streams, attachments, multimodal results,
rewind/fork, session deletion, schema upgrades and disabled-audit compatibility. Use
synthetic sensitive data to check every persistence/export path. Test outbound-call
bypass within the supported sandbox: a shell command or MCP server may invoke its own
model, so recording the outer call alone is not full downstream visibility. Either
restrict such routes, integrate them, or mark them unsupported under the selected policy.

Benchmark no-audit overhead, p95 durable-append latency, bytes per call, concurrent
session throughput, search latency, index lag, memory/backpressure and restore time.
Set release budgets after representative measurements; do not invent throughput or
storage guarantees in advance. Add a storage estimator from actual metadata, content
and artifact volumes before a firm selects a retention period.

The pilot demonstration should use one bounded investigation: identify a file change,
trace it to the exact captured model input and approved tool call, repeat with a crash
and a recording failure, then export and verify the record on a separate machine.
Record supported platform, filesystem, provider versions and deployment configuration
with the evidence. Local tests alone are not evidence of a successful customer rollout.

## Recommended first commitment

Prioritize the native execution path and the first offline investigation/export. Make
SQLite optional and embedded, using it for search first. Build required recording as a
policy on that same architecture. Introduce a database server only when a central
deployment or measured load justifies the operational cost.

Defer a multi-tenant SaaS control plane, arbitrary SQL backend support, a generic log
pipeline rewrite, and claims of full visibility inside opaque provider processes.
The first release is complete when its stated scope is inspectable, its gaps are
visible, and its failure behavior matches its guarantee.
