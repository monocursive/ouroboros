# Ledger durability acceptance audit, 2026-10-07

Runtime baseline: `8d82d17e9d88d62dd88fe4b976f679f67fe1ff35`.
Final native vendor-state check: `1b7e4ac2c63e2b93c5906ca943eef9813b11ab38`.
Only the integration test and its module declaration differ between these
revisions; production ledger and frozen Jail inputs are unchanged.
[source.json](source.json) binds the exact Git archive used for the extended
suite; [source.sha256](source.sha256) binds its 419 inputs. The final archive
was synchronized by content into the existing `ouro-vendor-89e61694` host
checkouts: only the changed test was replaced, preserving warm build outputs.
The source manifests are checked before and after every run. Uncommitted audit
documentation was excluded from that archive.

## Raspberry Pi catch-up

The Pi returned online and passed the original pending-journal revision's full
187-test suite, including 72 native owner fault cases, 66 lifecycle crash
cases and 27 real launch tests. There were no failures, ignored tests or skips.
The [original revision's result](../2026-10-07-pending-journal/pi/summary.json)
and [log](../2026-10-07-pending-journal/pi/ledger.log) remain attached to that
revision. The earlier offline check is retained as historical evidence.

## Acceptance audit and added check

The [acceptance map](../../durability-acceptance.md) now cross-checks all five
runtime properties and every clause of North Star §5.4's acceptance paragraph.
The missing integration check was vendor-state cleanup in a real ledger-owned
launch whose outcome becomes unknown.

The added [test](../../../../../crates/ouro-ledger/tests/launch_linux/vendor_state.rs)
uses a private fixture launch profile and an actual contained shell. It first
proves that the child created a vendor-state file. It then finishes normally,
SIGKILLs the real writer, or SIGKILLs the real owner. Each path requires verified
empty-tree evidence, absence of vendor state and a durable cleanup-complete
record. Normal exit settles; both faults remain `outcome_unknown`. Replay must
retain the same run/attempt/head and one execution. The private state content
must not appear in canonical metadata.

The first full VPS run exposed a synchronization bug in the new test, recorded
in [first-full-suite.log](fixture-correction/first-full-suite.log): it read the
cleanup record immediately after the terminal receipt. Jail deliberately
persists a terminal receipt with cleanup pending before removing state and
recording completion. After owner death there is no foreground join to wait
for those publications. The corrected test waits up to 20 seconds for both
state removal and durable completion; it does not accept missing evidence or
change Jail behavior. All 28 real-launch tests then passed in the
[corrected suite](fixture-correction/corrected-launch-suite.log), followed by
[20 repetitions / 60 cleanup scenarios](fixture-correction/stress.json).

The [first extended Pi run](pi-first-run/ledger.log) exposed another incorrect
test assumption: a real writer SIGKILL can interrupt a canonical frame. The
[diagnostic rerun](fixture-correction/pi-interrupted-frame-diagnostic.log)
reported exactly `oversized or interrupted canonical frame; bytes retained`.
That is the required §5.4.3 refusal, not a cleanup failure or a false settlement.
The final test permits that one verification problem only for writer death,
requires a nonempty bounded tail without a terminating newline, an unknown
outcome and degraded coverage, and proves verification/replay preserve every
canonical byte. Any other inconsistency still fails. Normal exit and owner
death must verify consistently. No production behavior was changed.

## Extended committed-source validation

Both native hosts use the existing
[validation script](../2026-10-06-writer-outage/validate-native.sh), Rust 1.98.1,
`OURO_CONFORMANCE=1`, `RUST_TEST_NOCAPTURE=1`, and a delegated user scope. The
script checks source hashes before/after, builds production ledger, runs
Clippy with warnings denied and the full suite, and records doctor and binary
hashes. [verify-results.py](verify-results.py) requires 188 passing tests,
zero failures/ignored tests/skips, exact pending-fault coverage, all three
cleanup scenarios and no test controls in the production ledger binary.

- x86_64 VPS: 188 tests passed, no failures, ignored tests or skips.
  [Summary](linux/summary.json), [full log](linux/ledger.log).
- Raspberry Pi: 188 tests passed, no failures, ignored tests or skips.
  [Summary](pi/summary.json), [full log](pi/ledger.log).
  [Ten additional repetitions](pi/vendor-state-final-stress.json) passed all
  30 cleanup scenarios, including one actual interrupted canonical frame.
  The [stress log](pi/vendor-state-final-stress.log) confirms its retained bytes
  and honest verification refusal.

Formatting, local Clippy, ledger contracts, I02 and the unchanged Jail freeze
are recorded under [local](local/). Local macOS is a compile/refusal lane for
ledger launches, not Linux execution proof.

## Separate CI anomaly

The earlier macOS Rust job at `d05b37f6` failed in the unchanged proxy test
`n04_stop_closes_a_tunnel_to_a_silent_destination`: shutdown accounted for one
missing result. The [failure excerpt](local/prior-ci-failure-excerpt.log) is
retained. A local [single run](local/proxy-stop-single.log) and
[100 subprocess repetitions](local/proxy-stop-reproduction.json) passed.
No causal diagnosis or proxy repair is claimed. The old retry was superseded
by the new commits. At the [recorded CI check](ci.json), both macOS and Ubuntu
Rust jobs and the contracts workflow passed at `89e61694`; the serialized
reference-host conformance workflow was still queued. The proxy failure did
not recur in that complete hosted Rust run. This is not a claim that the earlier
intermittent failure has a diagnosed cause.

## Limits and next slice

These are deterministic I/O failures and process-crash tests, not physical
power-loss tests. The Pi's doctor still reports unavailable memory/swap cgroups
and UNIX socket diagnostics; its `agent` networking/mediation probes refuse.
The validated ledger launches use supported `tool` and explicit `none` profiles.
No boot, kernel, network or installed-command configuration was changed.

This completes the audit's missing scripted-child integration check. It does
not declare all of milestone 2 complete. The acceptance map records absent
`show --with-transcript`, opt-in argv capture, foreground `--control-fd` and
structured `--redact` contracts. Bounded opt-in transcript display is the next
implementation slice. Legacy historical custody remains an obligation before
the later §9 cut; new signed bundles do not fulfill that obligation. Managed
authorization and real-agent/provider acceptance remain separate gates.
