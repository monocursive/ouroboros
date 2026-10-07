# Pending journals and local-exit persistence, 2026-10-07

Tested implementation: `8d82d17e9d88d62dd88fe4b976f679f67fe1ff35` on `dev`.
[source.json](source.json) binds its clean Git archive;
[source.sha256](source.sha256) binds 418 runtime, test and contract files.

## Repairs and regression proof

The launch owner now remembers local completion only after the save call
returns success. Previously, its error handler reread the pending file: a
successful rename followed by a directory-sync error could leave a readable
completion, suppress the unknown-outcome record and subsequently be settled
by the still-available writer. File presence did not prove that the owner's
save had succeeded.

The [negative control](negative-control/negative-control.json) temporarily
restored that old completion check from `1e1bea66` in the isolated VPS preflight
source directory. The same native test then failed at
`error/pending.completion/snapshot.before_directory_sync`: it observed `settled`
where `outcome_unknown` was required. The [full log](negative-control/negative-control.log)
records this expected failure. Both changed source files were restored, and
their hashes were compared with the fixed local source before clean validation.

Journal reads now validate the complete snapshot, then synchronize the pinned
file and directory before recovery can import, clear or acknowledge its data.
Either sync failure refuses recovery and preserves the journal and canonical
history. A complete unacknowledged snapshot can still be adopted after these
fresh barriers and receipt/control/source validation. A temporary
`owner-pending.next` is never promoted. This distinguishes conservative handling
of a live owner's observed save error from recovery after process death or a
writer outage where no canonical acknowledgement was possible.

Cleanup retains `owner-pending.lock` for the run directory's lifetime. Deleting
that inode while holding its flock allowed another opener to acquire a
different lock before cleanup finished. The retained file is empty and bounded
to one per run; it is not a pending journal or a settlement record.

## Validation

The [journal tests](../../../../../crates/ouro-ledger/src/pending/crash_tests.rs)
exercise initialization, outage marking, source buffering, local completion,
reconciliation clear and cleanup. There are 44 injected I/O failures and 44
actual SIGKILL cases, plus repeated file/directory recovery-sync failures and
a regression proving cleanup retains the same mutex inode. Recovery preserves
canonical prefixes and stable identities and does not duplicate imported records.

The [native owner matrix](../../../../../crates/ouro-ledger/src/pending/crash_tests/launch.rs)
runs 72 cases against the production writer and jail. Only the launch owner is
instrumented in the library test executable. Both I/O errors and SIGKILLs cover
each owner snapshot and cleanup boundary. Outage/source cases kill the actual
writer after the target starts. Checks prove the gate stays closed when journal
initialization fails, the jail verifies tree termination, terminal outcomes
remain conservative, and production CLI replay never executes another child.
Observation is enabled to independently confirm execution of short targets.

Native validation uses the committed
[validate-native.sh](../2026-10-06-writer-outage/validate-native.sh) with
`RUST_TEST_NOCAPTURE=1`, inside `systemd-run --user --scope`. Arguments are the
clean source directory, pinned Rust 1.98.1 toolchain `bin`, and the existing
build-cache directory. It checks source hashes before/after, builds production
ledger, runs Clippy with warnings denied and the full suite with
`OURO_CONFORMANCE=1`, and records doctor output and executable hashes.
[verify-results.py](verify-results.py) checks exits, case coverage, test totals,
binary hashes and absence of fault controls from production ledger.

- macOS: 157 tests passed, no failures or ignored tests.
  [Validation](macos/validation.json), [full log](macos/ledger.log).
- x86_64 VPS: 187 tests passed, including all 72 pending-owner fault cases,
  the existing 66 lifecycle crash cases and all 27 other real launch tests.
  No failures, ignored tests or skips. [Summary](linux/summary.json),
  [full log](linux/ledger.log).
- Raspberry Pi: the same clean revision passed all 187 tests after the host
  returned online on October 7, including the same 72 pending-owner cases,
  66 lifecycle cases and 27 real launch tests. No failures, ignored tests or
  skips. [Summary](pi/summary.json), [full log](pi/ledger.log),
  [host environment](pi/environment.txt).
  The [earlier availability check](pi-availability.json) is retained as the
  historical offline result; it does not describe this completed validation.

Formatting, local Clippy, contracts, I02 and the milestone-1 freeze check pass.
The frozen Jail inputs are unchanged. Production binaries have no fault-control
environment variable or IPC operation; all hooks are under `cfg(test)`.

## Limits and remaining work

The I/O errors are deterministic ENOSPC/EIO injection. SIGKILL tests process
crashes, not physical power loss or storage-controller cache behavior. The Pi
result above directly validates this revision; the earlier
[Pi lifecycle result](../2026-10-06-lifecycle-crashes/README.md) remains bound
to its own recorded revision.
No installed host commands, kernel settings or network configuration were changed.

The subsequent [§5.4 acceptance audit](../../durability-acceptance.md) adds
explicit vendor-state cleanup checks and identifies the remaining CLI/privacy
contracts. Historical custody at
the removal cut, managed authorization and real-agent/provider acceptance
remain separate requirements; milestone 2 is not declared complete here.
