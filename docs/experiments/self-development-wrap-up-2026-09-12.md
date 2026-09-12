# Self-development wrap-up — 12 September 2026

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

The broader native-provider and interactive run reached its 180-second command limit.
Its wrapper returned 124; the child's zero exit during shutdown does not make that run a
pass. No complete suite result was obtained. Dialyzer was not rerun: the private checkout
had no PLT, and this wrap-up did not bootstrap one. Initial failed regression attempts
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

Newer native output beyond a terminal durable checkpoint remains
`session_delivery_uncheckpointed` for explicit reconciliation. This is a deliberate
boundary on automatic acknowledgement, not a claim that lost history can be recovered.

Source validation is distinct from installed-product and release validation. This wrap-up
does not produce fresh cross-platform binaries or repeat authenticated first-use journeys.
Historical Linux tests established the stock Bubblewrap failure and the narrow distro
AppArmor opt-in; they do not certify the current source as a released binary. No Intel Mac
is available, and Intel CI publication remains unapproved. The earlier incomplete provider
policy reviews remain incomplete. The protected original runtime was not promoted.
