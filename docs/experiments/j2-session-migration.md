# J2 session migration evidence

The baseline capture ran on 2026-09-10 using existing pre-J2 compiled modules,
before recompiling modified source. This document records the captured facts and
the replacement ownership reviewed against the old Harness source.

## Lifecycle origin inventory

Every runtime marker passes through `Native.Session` into its retained output,
then through `Interactive.Task`'s durable projection. `Interactive.Event`,
`EventPresentation`, gateway detail/excerpt encoding, web, and TUI consume that
single persisted domain stream. The coordinator enriches payloads and records
domain facts; it does not reproduce the execution owner's markers.

| Fact | Pre-J2 producer | Replacement producer | Coordinator consumer |
| --- | --- | --- | --- |
| `session_started` | `SessionWorker.init/1` | `Native.Session` initialization | readiness/history |
| `session_ready` | `SessionWorker` after transport open | `Native.Session` initialization | readiness/history |
| `session_idle` | worker open and `Lifecycle.finish_turn` | `Native.Session` readiness and terminal transition | session status/history |
| `input_accepted`, message | `Lifecycle.start_turn` | `Native.Session` accepted dispatch | durable turn correlation and original prompt enrichment |
| `input_accepted`, steer | `SessionWorker` successful steer | `Native.Session` accepted steering request | durable steer text enrichment |
| `turn_queued` | worker follow-up | `Native.Session` queue insertion | durable turn status |
| `queue_changed` | `EventStore.append_queue_changed` on insert/remove/cancel | `Native.Session` queue mutation | history and public queue projection |
| `turn_started` | `Lifecycle.start_turn`; worker discarded loop's duplicate | `Native.Session` accepted dispatch, with the loop's duplicate suppressed at its source boundary | turn correlation/status |
| `approval_requested` | native transport or loop; worker retained and armed deadline | `Native.Session` live waiter registration | durable pending record and effect identity |
| `approval_resolved` | worker response/timeout and `Lifecycle.deny_pending_approvals` | `Native.Session` matching waiter resolution | approval-ledger enrichment and pending-record removal |
| `turn_completed`, `turn_failed`, `turn_interrupted` | native terminal consumed by `Lifecycle.finish_turn`; worker manufactured interrupt/timeout endings | `Native.Session` checkpointed turn settlement | turn outcomes, usage, durable waiter replies |
| `session_closed`, `session_failed`, `session_cancelled` | `Lifecycle.terminate_session` / `fail_session` | `Native.Session` terminal transition | intentional terminal state, lease release and history |
| replay-gap `provider_event` | `EventStore.prepend_gap` | explicit generation-scoped `drain` gap; coordinator records honest ambiguity | recovery/history |

The coordinator's separate approval channel (for requests originating outside a
native waiter) continues to own its own request/resolution pair. Native approval
resolution must not also produce a coordinator-authored pair for that same fact.
Domain-only resume/status, configure, fork, handoff, retry and operator-shell
events remain coordinator facts. Native output text, tool calls/results, planning,
usage and provider notes retain their existing loop/native origins.

Captured simple-turn order was:

```text
session_started, session_ready, session_idle, provider_event(native_ready),
input_accepted, turn_started, output_text_delta, output_text_final,
turn_completed, session_idle
```

## Stored-data contract

The additional baseline bytes are under `test/support/j2_fixture/data`, with the
writer, manifest, and provenance next to them. The previous core-reduction corpus
is unchanged. `Storage.RetiredAtoms` explicitly interns known retired struct tags,
renamed fields, and their checkpoint vocabulary before safe decoding. It neither
creates input-selected atoms nor asks retired modules to load.

`Storage.SessionMigration` normalizes reviewed legacy request/event/error/result
tags into plain maps, reconstructs only the owned `Interactive.State` and
`Interactive.Event` types, and migrates legacy runtime/turn IDs in memory.
`provider_session_id` keeps its native conversation meaning. Legacy private cursor
is `cursor - sequence_offset`; public sequence and historical event IDs remain
unchanged. New checkpoints use format version 2. Unknown future versions fail the
reader instead of dropping fields. A list/open does not rewrite valid v2-indexed
history; original bytes are checked by both the migration test and the boot gate.
Legacy native `provider_options.plan` moves to the explicit owned `plan` setting
in memory; an existing explicit setting wins. New runtime generations, cursors,
record versions, and close intents are validated before a record becomes durable
authority.

## Fleet boundary

Fleet protocol revision advances from 3 to 4, using `Cluster`'s existing runtime
compatibility tuple. `Session.Routing` checks `Cluster.ensure_placeable/1` before
any remote start, gateway start, await, request-approval relay or local-control
dispatch. Thus the public routing layer rejects old peers before invoking their
session API. Direct remote subagent start/control/cleanup paths use the same check
on the child's owner node; no alternate version negotiation is introduced.

Runtime replacement is a stopped/drained deployment with copied/backed-up data.
Mixed-version execution and old live PIDs are unsupported. Reverting code does not
roll back new-format checkpoints: use the verified backup on a stopped runtime.

## Scripted topology and wakeup baseline

`scripts/fixture/j2_workload.exs` creates one interactive session, waits 1.5 seconds
for idle cadence to settle, observes it for 2 seconds, then runs a no-network model
that yields two chunks with 250 ms delay each and observes the next 800 ms. It
counts receive-traced `:poll` messages and actual session-process initial calls.

Pre-J2 invocation used `MIX_ENV=test mix run --no-compile --no-start` and explicitly
restored the original native provider registration because source configuration
was already being migrated. Existing compiled runtime code remained unchanged.

| Measurement | Pre-J2 | Owned contract |
| --- | ---: | ---: |
| Interactive coordinators | 1 | 1 |
| Harness session workers | 1 | 0 |
| Native execution sessions | 1 | 1 |
| Poll wakeups over 2 seconds idle | 2 | 0 |
| Poll wakeups in 800 ms covering the 500 ms turn | 26 | 0 |
| All coordinator receives over 2 seconds idle | 6 | 0 |
| All coordinator receives in the active observation | 104 | 39 |

The owned-contract measurement ran with the same script and produced the same
lifecycle type order. This is structural evidence, not a speed claim. Timing
counts can vary with VM scheduling. The middle worker and active poll loop are
absent; model/tool execution has not been benchmarked for speed.

Both boot corpora passed 20 full application boots each (10 lazy, 10 preloaded)
on fresh copies. All recorded original-corpus counts matched; the J2 corpus kept
eight sessions and its nested ledger error with unchanged original bytes and no
quarantine.

## Focused acceptance evidence

The focused delivery, notification, timer, and legacy-reader run passed 42
tests. It exercised a blocked checkpoint, a refused write followed by successful
retry, and an actually written checkpoint with an uncertain reply. None released
the pending batch to public subscribers or acknowledged it before successful
persistence; uncertainty stopped the dependent native runtime through the actual
authority restart order. Coordinator kills before and after the write reattached
the existing runtime and retained one terminal event and one usage fold. A kill
after acknowledgement kept the same durable event IDs without another model call.

The slow-subscriber test prefilled a mailbox with 1,000 messages and then observed
one resync notification and removal of the subscription. Another 21 persisted
runtime events did not grow that mailbox. Idle and active receive traces verify
notification-driven delivery and no recurring polling timer. The old cadence
implementation and its obsolete arithmetic tests are removed; the independently
used timer cancellation tests remain.

The native planning suite passed 26 tests, preserving plan posture, live approval
identity, and one `turn_started` across plan continuation. The focused child/fork
run passed 10 tests, including same-task launch deduplication and removal of the
completed child's runtime registration while its collected summary remains usable.

After removing stale Harness dependency directories, an additional lazy and
preloaded J2 boot each passed. Those checks explicitly verify that every retired
module tag is absent from the code path, not merely absent from started apps.
The original boot archive and tracked public protocol fixtures remain unchanged.
The complete local gates below were run again after the implementation was frozen.


The final recovery-focused run passed 18 tests, including retries of a refused
resume-adoption checkpoint using the same idle replacement, intentional kill while
that adoption is pending, and terminal-checkpoint recovery that releases native
output without rewriting public history or dispatching a model call. Exact-ID
correlation also settles a delayed accepted turn on its original ambiguous intent
without assigning it to a newer unrelated intent. The queued recovery test gates
its scripted producer until both turns are accepted, so buffer saturation cannot
race test setup.

The final scripted workload reproduced both process counts and all measured
wakeup counts above, including 39 coordinator receives and three coalesced output
notifications in the active observation.


## Build and surface gates

- Fresh production dependency build: passed using
  `MIX_BUILD_PATH=_build/j2-clean-prod MIX_ENV=prod mix compile`, then recompiled
  the final source in both that clean tree and the normal production build.
- Isolated production application boot: passed with a fresh private data directory
  and the trusted process-incarnation helper. All 337 Ouroboros modules were
  inspected for BEAM imports: zero Harness imports. Harness was absent from all
  67 loaded applications and its retired session module was not loadable.
- `make dialyzer`: passed; 31 findings matched the existing suppression file,
  with zero unnecessary suppressions and no additions to that file.
- `make golden protocol-docs`: passed with no public fixture or protocol-doc drift.
- `npm run test:browser`: all six desktop/mobile journeys passed. The added journey
  drives real native streaming, write approval, cooperative interruption, page
  reload, and persisted history using a deterministic model with no network calls.

This is source, local build, scripted runtime, and loopback peer evidence. No
live fleet deployment or paid model execution was performed. New-format data
rollout still requires the stopped/drained and backed-up procedure above.


## Retired dependency surface

| Previous surface and consumers | Owned replacement |
| --- | --- |
| Session start/info/list, submit, steer, approval, configure, interrupt, close and result/event reads in the interactive coordinator and remote children | `Ouroboros.Session` over the existing `Native.Session`; public history and waiters remain coordinator-owned |
| Session worker bookkeeping, execution task supervisor and transport supervisor | Scheduling/output/waiters in `Native.Session`; owned execution supervisors separated from coordinator recovery |
| Session/turn requests, approval responses, runtime events/info and errors | Explicit `Ouroboros.Session` boundary types; unused generic run/process APIs and `Native.Run` removed |
| Provider registry, adapter/spec/capability structs and vendor configuration | Pure native declarations and `config :ouroboros, :native_provider`; no provider registry process |
| Redaction in state, events, audit, runtime exposure, WASM policy and authentication | `Ouroboros.Redaction`, with existing observable redaction retained |
| Erlexec process signaling | `Native.ProcessSignal`; direct pinned `erlexec` dependency and reviewed macOS patch retained |
| Active/idle polling cadence | Coalesced output notifications, monitored attachments and named failure retries; unrelated Timer users retained |
| Retired durable struct tags and runtime/turn aliases | Finite compatibility vocabulary and versioned in-memory `Storage.SessionMigration`; public wire aliases preserved |
| Harness adapter/RPC test doubles | Scripted native models and attachment collectors over the real facade; narrow failure-only runtime stubs |

Source/config/lock scans and the compiled-import check above close this inventory.
Legacy fixture writers deliberately retain old constructor names as provenance;
production keeps only literal, reviewed legacy tags in the decoder vocabulary.


## Final complete gate

`make test` completed successfully with exit status 0 on the frozen implementation:

| Gate | Result |
| --- | --- |
| Elixir formatting and development script checks | Passed |
| Elixir suite | 3,726 passed, 14 skipped |
| Original data corpus | 20 successful fresh-copy boots: 10 lazy, 10 preloaded |
| Pre-J2 data corpus | 20 successful fresh-copy boots: 10 lazy, 10 preloaded |
| Rust default configuration | 1,505 passed across 40 groups, zero ignored |
| Rust `embed` configuration | 1,514 passed across 40 groups, zero ignored |
| Rust formatting | Passed |
| Clippy, all targets, default and `embed`, warnings denied | Both passed |

The separately run Dialyzer, golden/protocol, browser, fresh production build,
and compiled application graph checks also exited successfully. No public protocol
fixture changes were needed.
