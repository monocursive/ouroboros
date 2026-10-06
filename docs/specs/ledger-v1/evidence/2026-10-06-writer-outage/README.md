# Best-effort writer-outage recovery, 2026-10-06

Tested implementation: `704f6bcbbe1bbd30410be76d9121cafe57577d02` on `dev`.
[source.json](source.json) binds the clean Git archive; [source.sha256](source.sha256)
binds 411 runtime, test and contract inputs. Native validation uses separate
source directories and the hosts' existing pinned Rust 1.98.1 build caches.
The unchanged Jail executables are recorded by hash alongside the new ledger
executables. The milestone-1 freeze still matches its tested build inputs.

## Behavior under test

Durable admission remains necessary before execution. After admission,
`--evidence best-effort` buffers pending source records in a private, synchronized
journal when the writer connection fails. The journal retains at most 32 events
and 256 KiB in its prefix, then bounded source tails that expose dropped source
sequence intervals. Reconciliation records permanent degraded coverage and
explicit recovery provenance. Source envelopes and replay identities stay intact.

An already durable canonical settlement is returned on retry. Otherwise the
owner's local exit record must corroborate the terminal control, receipt and
final trace before the writer records settlement. An absent or invalid local
exit leaves the outcome unknown. A writer restart cannot start another child.

## Validation

The native procedure is [validate-native.sh](validate-native.sh). Run it inside
`systemd-run --user --scope` with the source directory, pinned toolchain bin
directory, and existing build-cache directory as its three arguments. It checks
source hashes before and after, builds the ledger, runs Clippy with warnings
denied, runs the full ledger suite with `OURO_CONFORMANCE=1`, records Jail doctor
output, and verifies executable hashes. It does not skip any ledger tests.

- macOS: 151 tests passed; Clippy, formatting, schemas, links, I02 and the freeze
  check passed. See [macos/validation.json](macos/validation.json).
- x86_64 VPS: 179 tests passed, including 27 real launch tests; no failures or
  ignored tests. See [linux/ledger.log](linux/ledger.log).
- Raspberry Pi ARM64: 179 tests passed, including 27 real launch tests; no
  failures or ignored tests. See [pi/ledger.log](pi/ledger.log).

The six added native cases cover writer restart with bounded overflow (`tool`
and `none`), local completion while the writer remains absent, a recomputed
journal checksum around forged terminal control, an actual filesystem
replacement error while the child is alive, a kernel `RLIMIT_FSIZE` write limit
that prevents local exit persistence, and owner death without an exit record.
The existing strict writer-loss and durable admission tests remain in the suite.

Storage tests preserve pending evidence across injected canonical write,
partial-write, synchronization, projection, manifest and directory-sync failures.
A poisoned canonical stream cannot acknowledge or discard its pending journal.
Lost-reply cases replay already durable source and reconciliation records across
restart without adding a second canonical record. Journal tests also cover
process-birth rebinding, unsafe links/modes, concurrent locking and bounded tails.

## Portable proof

[smoke.py](smoke.py) performs real `tool` and `none` launches, kills the writer
after durable admission, lets the child finish while it is unavailable, and
restarts the writer after the launch owner exits. It checks one child execution,
one outage marker, known settlement, persistent degraded coverage and exact
captured output. The owner initially returns an error reporting pending
canonical reconciliation; it does not fabricate a settled response.

Each native `smoke/` directory retains the admitted run, local exit journal,
reconciled run, canonical portable bundle and offline verification result.
The writer is stopped before portable verification. The macOS directory also
records verification of bundles copied from the native hosts. `none` remains
unprotected in all projections and exported evidence.

## Limits

This is process-kill, restart, bounded-overflow and filesystem-failure evidence.
It does not establish physical power-loss durability, external custody, managed
authorization, or real-agent/provider acceptance. The Pi's existing kernel
limitations remain: positive `agent`, Landlock and required memory ceilings are
outside its capabilities, as documented in the
[Pi catch-up record](../2026-10-06-pi-catch-up/README.md).
The full milestone-2 durability gate and historical-custody migration remain open.
