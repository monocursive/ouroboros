# Bounded transcript display — 2026-10-07

Implementation: `e6239ffb7ee27204b298d6f36ec6b9257a146de8`.
[source.json](source.json) identifies the Git archive and
[source.sha256](source.sha256) binds its 423 runtime, test and contract inputs.
Only changed content was copied into the existing native test checkouts;
each full suite checks every input hash before and after execution.

## Behavior and proof

`ouro-ledger show RUN --with-transcript` returns a versioned show envelope
containing the unchanged run projection and explicit transcript information.
Ordinary `show` remains metadata only. The reader consumes at most 64 KiB per
terminal stdout/stderr stream and returns reversible ASCII byte escapes.
Capture truncation and display truncation have separate fields. Unselected,
incomplete, pruned and unavailable captures keep explicit labels. Live and
unfinalized captures expose no bytes. Capture contents are unverified local
artifacts; the display does not upgrade outcome, coverage or child protection.

Five portable store tests cover bounded worst-case escaping, binary/control
bytes, empty captures, capture versus display loss, live/unfinalized artifacts,
retention, missing files, wrong sizes, symlinks at each child directory,
hard links, FIFOs, directories, public permissions and invalid recorded paths.
A real CLI/socket test checks opt-in behavior and unchanged metadata.

Two new native tests launch actual children. Both `tool` and `none` exercise
capture/display truncation, stdout/stderr separation, invalid UTF-8, terminal
controls, JSON/pretty output, missing captures and unchanged canonical events.
The second test verifies live and killed-owner output remains incomplete and
the killed owner's outcome stays unknown. The existing fault and lifecycle
matrices also run in full, including vendor cleanup and writer restart.

The [CLI probe](probe-cli.py) independently runs a real captured child and
saves the actual show response. Both native responses are checked against
[show.schema.json](../../show.schema.json). Probe contents are deliberate
test bytes, not application data or credentials.

## Validation

The native [validation script](../2026-10-06-writer-outage/validate-native.sh)
uses Rust 1.98.1, `OURO_CONFORMANCE=1`, `RUST_TEST_NOCAPTURE=1`, private fixtures
and a delegated user scope. [verify-results.py](verify-results.py) checks test
counts, all 72 owner fault cases, all 66 lifecycle cases, transcript/cleanup
markers, pre/post source hashes, binary hashes and absence of test controls
from the production ledger binary.

- VPS: **196 passed**, zero failed, ignored or skipped.
  [Summary](linux/summary.json), [full log](linux/ledger.log),
  [actual CLI response](linux/transcript-cli.json).
- Raspberry Pi: **196 passed**, zero failed, ignored or skipped.
  [Summary](pi/summary.json), [full log](pi/ledger.log),
  [actual CLI response](pi/transcript-cli.json).
- Local macOS: **163 passed**, zero failed or ignored.
  [Summary](local/summary.json), [full log](local/ledger.log).
  Linux launch tests are compiled out on macOS.

Formatting, Clippy, contract validation, links, I02 and the unchanged Jail
freeze also pass. Test binaries use existing native caches; installed commands
and device kernel configuration are not changed by this validation.

## Earlier CI timeout

The preceding revision `db887219` failed reference conformance in
`best_effort_writer_restart_reconciles_bounded_overflow_without_reexecution`:
[original excerpt](ci/prior-failure-excerpt.log). It also timed out on the fifth
extra VPS repetition after the full `e6239ffb` suite had passed:
[reproduction log](ci/reproduced-timeout.log). The original assertion identified
neither the specific pending-journal wait nor its final state. That historical
failure remains recorded separately from the passing transcript suite.

Failure-only diagnostics then reproduced the exact wait after writer restart:
the journal remained active with 32 buffered events and overflow set.
[Canonical verification](ci/diagnosed-interrupted-frame.log) reported only
`oversized or interrupted canonical frame; bytes retained`. SIGKILL had cut
a canonical frame. Recovery correctly refused to reconcile pending evidence;
the test incorrectly waited for a successful journal clear.

`a0133a748f3115e1825ac49a97c393055afd338a` corrects that assertion, with no
production change. Clean history must still recover and settle as before.
Only the exact interrupted-frame diagnosis permits the alternate outcome:
nonzero owner/replay results, an unknown outcome, degraded coverage, verified
empty child tree, one execution and unchanged canonical bytes and chain.
Other verification failures still fail. Timeout diagnostics now identify
the caller, journal state and canonical verification result.
[corrected-source.json](corrected-source.json) and
[corrected-source.sha256](corrected-source.sha256) bind this test-only revision.

Both corrected full suites pass **196 tests**, with zero failures, ignored
tests or skips: [VPS](linux-corrected/summary.json),
[Pi](pi-corrected/summary.json). Their production binary hashes are identical
to the implementation validation above.

The corrected test then passes [100 VPS repetitions](linux-corrected/stress-summary.json)
and [50 Pi repetitions](pi-corrected/stress-summary.json), covering 300 profile
scenarios in total. Each host encounters **two actual interrupted frames**;
all four exercise the conservative refusal assertions successfully. The full
[VPS stress log](linux-corrected/pending-restart-stress.log) and
[Pi stress log](pi-corrected/pending-restart-stress.log) retain every result.
The original failed attempts are preserved above; no production recovery
behavior was weakened to obtain these passes.

## Scope

These are scripted-child, local store and native Linux execution checks.
They do not establish physical power-loss behavior, real-agent/provider
compatibility, managed readiness or external custody. Pi capabilities retain
their existing limitations. Opt-in raw argv capture, foreground control-FD
output and explicit redaction remain separate milestone-2 work.
