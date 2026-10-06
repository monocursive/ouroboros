# Lifecycle persistence and launch crashes, 2026-10-06

Tested implementation: `e7c7a1693fcd111cea6d3934d438b1928712a82b` on `dev`.
[source.json](source.json) identifies the clean Git archive;
[source.sha256](source.sha256) binds 416 source, test and contract inputs.
Native hosts use separate source directories and their existing Rust 1.98.1
build caches. The unchanged Jail/fixture binaries and rebuilt ledger binary
are hashed in each host's validation directory.

## Behavior

A preparation whose write failed could previously return an `Ok` response to
the same request while the stream was still poisoned. The writer now refuses
that acknowledgement until recovery, matching append and owner-claim behavior.
The existing owner-claim guard already prevented execution from that poisoned
preparation; this fixes the preparation acknowledgement contract.

The [storage matrices](../../../../../crates/ouro-ledger/src/store/lifecycle_tests.rs)
exercise preparation, owner claim, admission, source append and settlement at
fourteen persistence cuts. There are 70 injected I/O failures and 70 actual
SIGKILLs of isolated writer subprocesses. Every case checks that its intended
hook was reached. Live retries refuse ambiguous writes; restart preserves all
canonical bytes. Complete tails recover without duplicate records; incomplete
frames remain poisoned and cannot acquire a new sequence or preparation.

The [native matrix](../../../../../crates/ouro-ledger/src/store/lifecycle_tests/launch.rs)
uses the production ledger launch owner and real Jail against a writer in the
library test executable. It runs 66 scenarios: all fourteen persistence cuts
at admission and settlement in both evidence modes, plus lost successful
replies for all five lifecycle mutations in each mode. Checks include:

- No target execution when admission acknowledgement is lost.
- Verified tree termination, including refused preparation at the closed gate.
- Conservative unknown outcomes for ambiguous settlement; recovery of complete
  canonical settlement and valid best-effort local-exit evidence.
- The same run/attempt identity and no second execution after production-writer
  restart and CLI replay. A lost preparation reply leaves an unowned attempt
  that may execute once when retried.
- No truncation or extension of a partial canonical frame.

Fault instrumentation is compiled only under `cfg(test)`. The production owner,
jail and restarted writer have no test control environment switch or fault IPC.
The normal test suite runs every parent test; there are no ignored helper tests.

## Validation procedure and results

Native validation reuses the committed
[validate-native.sh](../2026-10-06-writer-outage/validate-native.sh) with
`RUST_TEST_NOCAPTURE=1`, inside `systemd-run --user --scope`. Its arguments are
the clean archive directory, pinned toolchain `bin` directory and existing build
cache. It verifies source hashes before and after, builds production ledger,
runs Clippy with warnings denied, executes the full ledger suite with
`OURO_CONFORMANCE=1`, records Jail doctor and checks executable hashes.

[verify-results.py](verify-results.py) checks every exit status, the complete
66-case native set, test totals, absence of skips, and unchanged binary hashes.
It also checks that test worker configuration and kill-hook strings are absent
from the production ledger executable. It writes each host's `summary.json`.

- macOS: 153 tests passed, including both 70-case storage matrices; no failures
  or ignored tests. [Validation](macos/validation.json), [full log](macos/ledger.log).
- x86_64 VPS: 182 tests passed, including the 66-case native matrix and all 27
  existing real launch tests; no failures, ignored tests or skips.
  [Summary](linux/summary.json), [full log](linux/ledger.log).
- Raspberry Pi ARM64: 182 tests passed, including the 66-case native matrix and
  all 27 existing real launch tests; no failures, ignored tests or skips.
  [Summary](pi/summary.json), [full log](pi/ledger.log).

Formatting, Clippy, the ledger contract validator, I02 and the milestone-1
freeze check pass. This change does not alter the frozen Jail build inputs.

## Limits and next gate

The injected write failures are deterministic ENOSPC/EIO errors, including an
actual partial canonical write; they are not a physical full-disk experiment.
SIGKILL validates process crash/restart behavior, not loss of power or storage
hardware caches. This run does not change the Pi kernel or installed command
symlinks. Its existing profile/capability limits remain documented in the
[Pi catch-up record](../2026-10-06-pi-catch-up/README.md).

The [acceptance map](../../durability-acceptance.md) keeps the full North Star
§5.4 gate open. Next is interruption coverage for pending-journal/local-exit
replacement itself. Historical custody at the removal cut, managed project
authorization and real-agent/provider acceptance remain separate obligations.
