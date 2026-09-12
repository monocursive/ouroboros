# Self-development wrap-up — 12–13 September 2026

The native Ouroboros run produced useful changes and concrete regressions, but needed
supervision to finish. On the operator's instruction, Codex stopped that run, preserved
its uncommitted work, and took over implementation and final review. Work remains on
`codex/self-improvements`; nothing has been pushed or published.

## Structural corrections

| Problem exposed by the run | Correction |
| --- | --- |
| A coordinator's automatic restart reused an admission lease its caller had already released, exhausting its supervisor's restart budget. | Admitted coordinators recover through the supervised sweep with fresh session-bound admission. The execution generation and supervisor remain intact. Acquisition and release failures are isolated to one attempt. |
| Runtime existence was treated as proof of pending delivery, retaining unrelated generations and repeatedly recovering records that could not be acknowledged. | The native owner publishes a small generation, terminal-delivery and output-cursor projection before notification and after acknowledgement. Recovery and retention share that projection without synchronous calls from the durable store into execution. |
| Terminal retention could delete the sole checkpoint before acknowledgement while admission was closed. | Matching, checkpointed terminal delivery pins the record until acknowledgement. Unknown or newer output is retained with an explicit refusal, and does not cause repeated recovery. No unseen output is acknowledged. |
| Admission fixtures depended on a particular application startup mode; peer tests depended on host DNS despite a loopback-only mapper. | Fixtures acquire genuine admission in both application modes with distinct supervisor child IDs. Historical-fork coverage uses an actual persisted historical record instead of racing live reconciliation. `test-isolated.sh --loopback-peers` supplies explicit private resolver/interface settings while preserving canonical distributed assertions and caller-owned HOME/mapper lifecycle. |
| A readiness test released a port and assumed it remained absent. Incomplete NAMES responses were reported as wrong protocol; connection errors as absence. | Tests retain their listeners and use deterministic absence coverage. Only connection refusal establishes absence. Inconclusive protocol results may retry only during owned startup; incumbent reuse and retirement remain fail-closed. Probes share their lifecycle deadline. |

The complete source run exposed additional structural defects, which were fixed before
another complete run:

| Further finding | Correction |
| --- | --- |
| One store interpreted every writer's pending reservation as its own, either blocking unrelated writes or committing a foreign reservation with coincidentally matching bytes. | Interactive-store recovery now recognizes only its existing `interactive-store/v1/` namespace. Foreign matching and mismatching digests remain untouched; genuine own pending work still blocks unrelated changes and permits exact reconciliation. |
| The maintenance epoch permanently refused all new write IDs after 4,096 reservations. | The resident journal stays bounded, while finalized identities move into an immutable Merkle radix index. A single durable checkpoint publishes the new index root, retained rows and next epoch together. Missing referenced nodes refuse lookup; absence is established by the committed tree, never inferred from a missing receipt file. Pending reservations cannot be evicted for capacity. |
| Checkpoint and handoff retries could reuse an operation ID with changed bytes and report or settle the wrong outcome. | Requested bytes must match the reserved digest before reconciliation. Committed and aborted identities remain authoritative after archival, and a missing committed payload is not recreated. |
| A journal retry could adopt a new in-memory hash while reconciling an older persisted line; a staged gap could then bypass recovery. | Conflicting retries refuse, and a failed epoch-backed handle remains locked until reopened. Reopen reconciles the persisted line before subsequent appends; a regression verifies the complete resulting chain. |
| A store or effect-ledger retry could publish an aborted operation, or overwrite newer state using a previously committed write ID. | Publication now requires an authoritative pending reservation. A committed retry only observes an already-equal durable payload; an aborted or mismatching terminal identity cannot write. |
| A plan-exit continuation reused the first loop execution's checkpoint ID while keeping the same public turn. | The checkpoint identity also includes the session's loop ordinal. The operator still sees one turn, and the final durable transcript includes its follow-up. |
| Private compaction/quarantine repositories shared the application's epoch, and a recovery test allowed only the sweep's grace period without its next tick. | Fixtures now own durable epochs and clean up their exact native processes. Maintenance participant-death cases isolate their participants, default registry discovery has separate coverage, and the crash test allows the existing bounded sweep interval. |

The index deliberately retains lifetime identities and immutable nodes on disk. Its
resident history is bounded; total disk usage grows with writes, and startup validates
the complete reachable archive. This is not a disk-retention feature. Schema-1 data is
migrated without dropping identities; older software cannot read schema 2 and refuses
startup. Downgrading requires an independently retained pre-migration data copy. The
single-owner storage assumption remains in force.

The intentional Fable prompt and loop design is retained. The native session edit adds
delivery publication; it does not replace that prompting or cache-prefix work.

## Benchmark interpretation

Separate product failures from benchmark failures. The coordinator restart failure was
a reproduced product defect. Hostname mismatch and the missing in-memory test fence were
test prerequisites. The Python evidence runner's allocation-sampling race, false success
after monitoring failure, and false timeout accounting belonged to the benchmark runner.
Its corrected synthetic cases retain direct exit and cleanup results.

The native turn also spent substantial effort on static reviews and evidence management:
one peer/readiness analysis used 15 iterations and 92 tool calls, took 541 seconds and
wrote 31,995 bytes. Two follow-up reviews were stopped at takeover without final reports.
Those are incomplete reviews, not successful clearance. This run demonstrates the value
of narrow ownership, stable review inputs, executable regression cases and explicit
terminal outcomes; it does not establish unattended self-development readiness.

## Verification and release limits

Validation receipts for the takeover are retained under
`tmp/roadmap-implementation-20260911/public-preview-integration-turn52-01/root-wrapup/`.
Failed attempts remain alongside corrected results. Counts from overlapping runs must not
be added. Independent reviews inspected source; test execution was coordinated separately.

| Completed takeover check | Result |
| --- | --- |
| Isolated recovery, delivery, retention, gateway, model and actual peer coverage (`recovery-final`) | 50 passed |
| Ordinary in-memory startup fixtures (`plain-final`) | 31 passed |
| Native session contracts, interactive sessions, approvals, application recovery and fence (`session-contracts`) | 106 passed |
| Final Rust EPMD readiness, preflight, retirement and runtime lifecycle selection (`rust-epmd-final`) | 21 passed |
| Rust Clippy, all targets with `embed`, warnings denied | Passed |
| Elixir compile, warnings as errors; changed-file formatting; shell syntax and isolation script regression checks | Passed |

The broader native-provider and interactive run reported two maintenance-fence integration
failures before reaching its 180-second command limit. A later full-log audit found those
failures; the initial wrap-up summary had reported only the timeout. Its wrapper returned
124; the child's zero exit during shutdown does not make that run a pass. No complete suite
result was obtained in that run. Dialyzer was not rerun in that first phase because
the private checkout had no PLT. Initial failed regression attempts
were corrected and retained, including the macOS accepted-socket nonblocking behavior,
the duplicate fixture child ID and the live-versus-historical fixture race.

The final EPMD selection excludes the protected endpoint and uses retained test listeners
for protocol fixtures. Production preflight and post-retirement absence checks still use
test-allocated or previously owned ports after release; continuous socket reservation is
not claimed. An earlier inherited watch test could probe fixed port 65300 before its child
exit was observed; that fixture was subsequently corrected and the full selection rerun.

The four implementation commits are `66d14ebb` (admission/model fixtures), `f4bc0fbc`
(peer isolation), `8176525d` (EPMD readiness/lifecycle) and `ac9bbb4d` (recovery/delivery).
The validation checkout retained its earlier private Git HEAD while explicit source bytes
were mirrored into it; passing tests do not imply that private Git HEAD was advanced.

The subsequent source campaign is recorded separately under `root-readiness/` and
`root-final/` beside those receipts. Its first complete Elixir run finished with
4,021/4,033 passing and 14 skipped: one quarantine isolation failure and eleven
compaction failures caused by the shared epoch reaching its lifetime limit. Those
failures prompted the fixes above; they are retained, not recategorized as timeouts.
A broader native selection also exposed the recovery-test deadline and was corrected.

Completed follow-up checks include 70 quarantine/compaction tests, 13 store-scoping
and retention tests, and 191 maintenance, archive, writer, compaction and interactive
regressions. Formatting, packaging/isolation/development scripts and Clippy in both
feature sets passed. The three historical data corpora completed all 60 boots, followed
by the runtime-graph check. That boot result predates the final epoch-index changes;
its candidate rerun is recorded separately.

The full Rust default and embed suites completed. Default reported 1,532 passes but
included 45 explicit early-return skip messages because optional runtime and WASM
fixtures were absent; that number is not component execution coverage. The helper-backed
embed run reported 1,541 passes, with three optional real-runtime early-return skips.
Helper and echo-guest bytes were reused only after verifying unchanged input source and
exact prior artifact hashes. Five current WASM examples were built afresh with the locked
offline toolchain. These are component checks, not fresh preview binaries.

The additional local commits are `c351ab54` (maintenance/recovery fixtures), `cdb3ccd5`
(private Rust endpoints), `4098e953` (private quarantine/compaction epochs), `d7d007c5`
(store namespace), `519df544` (lifetime receipt index and retry integrity), and `717f663d`
(terminal-write fences and plan-continuation checkpoint identities). `7e0e7f5c` removes three unreachable
branches reported by warnings-as-errors compilation and Dialyzer.

The next full run, at implementation checkpoint `519df544`, finished with 4,048/4,049
passing and 14 skipped. Its one failure exposed the plan continuation's reused
checkpoint identity. That correction and the two terminal-publication fences passed
124 focused regressions before commit `717f663d`. Warnings-as-errors compilation,
formatting and Dialyzer then passed after the unreachable-branch cleanup. The existing
27 Dialyzer exclusions were retained unchanged. Its PLT was an independent private copy;
forced reconciliation replaced the original checkout paths before analysis. Final
candidate `7e0e7f5c` then passed the complete Elixir suite: **4,055 passed, 14 skipped**
in 753.2 seconds (756.9 seconds including the wrapper). The 14 skips are 12 Linux-only
Bubblewrap cases on this Mac and two unavailable precompiled version/target-skew
fixtures. No model calls were made. The same code then passed all **60 historical-data
boots** and the runtime-graph check in 138.5 seconds. The complete constituent source
gates passed as isolated commands; this does not claim one monolithic `make test` run.
The compact candidate receipt is `root-candidate/validation-summary.json`.

Newer native output beyond a terminal durable checkpoint remains
`session_delivery_uncheckpointed` for explicit reconciliation. This is a deliberate
boundary on automatic acknowledgement, not a claim that lost history can be recovered.

Source validation is distinct from installed-product and release validation. This wrap-up
does not produce fresh cross-platform binaries or repeat authenticated first-use journeys.
Historical Linux tests established the stock Bubblewrap failure and the narrow distro
AppArmor opt-in; they do not certify the current source as a released binary. No Intel Mac
is available, and Intel CI publication remains unapproved. The earlier incomplete provider
policy reviews remain incomplete. The protected original runtime was not promoted. The final source archive and per-file
manifest are generated from the complete committed tree, with private state, logs and
caches excluded. They are reviewable source artifacts, not installed-preview acceptance.
