# Persistent retention and capture expiry, 2026-10-06

Tested implementation: `2dd1c3b4` on `dev`. The tracked source snapshot is bound
by `source.sha256` and checked in `source-postcheck.log`, before the final
evidence, specification links and tested-freeze metadata were added.
This is another ledger milestone-2 slice, not completion of that milestone.

## Behavior

- The local writer loads `[ledger] retain` and `capture_retain` from the
  operator configuration at startup. Missing settings retain history and
  captures for 90 days. Invalid settings refuse startup. Explicit capture
  retention cannot exceed history retention. CLI overrides are per invocation.
- GC remains an explicit operation. Dry runs report separate history/capture
  cutoffs, candidate flags and keep reasons. Active/unknown runs, holds and
  reader snapshots protect both kinds of data.
- Capture-only expiry writes and synchronizes an exact file inventory before
  unlinking selected stdout/stderr files. Canonical event bytes, replay
  identities, query/export results and the history retention clock stay intact.
  A separate completion marker and `capture_history` projection describe it.
- Restart completes interrupted inventories. Changed files, symlinks, hard
  links, forged chain anchors and reappearing files cannot authorize deletion.
  Verification reads pending state without resuming deletion. Once captures
  are pruned, later operator holds and eventual whole-run pruning still work.
- The shared configuration parser is included in the Jail build-input manifest.
  This changed the frozen input digest and requires new reference conformance
  plus a separately refreshed tested freeze.

## Tests

The store suite injects failures at eight capture-deletion boundaries, using
both stdout and stderr so interruption between unlinks is covered. It checks
recovery, pending-state mutation refusal, canonical-byte preservation, full
history pruning after capture expiry, empty selected files, and unsafe or
changed inventories. These are deterministic fault injections, not physical
power-loss tests.

The real CLI/socket test creates a synthetic aged canonical fixture, starts
an actual writer, edits the configuration, proves the running writer keeps its
original settings, restarts it, and observes the new settings. It then expires
captures, restarts again, verifies consistency and compares exact NDJSON export
bytes with the original fixture. This fixture does not launch a jail.

The native Linux conformance suite additionally exercises real jail launches,
owner/writer loss, replay and capture draining through the existing launch tests.
Local macOS workspace results prove portable behavior only; sandboxed macOS
execution remains disabled.

## Development findings

The first standalone Linux follow-up rejected its test configuration under the
host's umask `0002`. The writer correctly refused group-writable settings;
fixtures now explicitly create mode `0600`. The passing native follow-up uses
that same umask. The earlier full conformance run was cancelled after this
finding; its partial log is development evidence, not a passing run.
A first detached smoke used a fixture path longer than the Unix-socket limit;
it refused before any run was prepared. The shorter fixture paths passed.

## Validation records

Local workspace validation at `d25f1329` passed 1,135 tests with seven explicit
ignored cases. `local/source-d25f1329.sha256` binds that snapshot. Later changes
expose the writer policy in CLI `doctor` (`9af59b47`) and make fixtures independent
of the host umask (`2dd1c3b4`). All seven CLI tests and the configuration test
were rerun natively on Linux; their compiled source matches
`native-cli/source.sha256`. They also passed locally with strict Clippy.
`doctor-cli-source.sha256` binds those follow-up implementation and fixture
files at the final source revision.

The separate detached VPS smoke runs a real contained command, proves one
execution across replay, bounds stdout to eight bytes, and verifies that the
independent writer preserves its startup retention settings. The follow-up
also checks CLI `doctor` reports those settings. Both exact binary hashes are
recorded; that smoke uses the unchanged Jail binary from `d25f1329` and the
updated ledger CLI. Test-owned writer services were stopped afterwards.

Hosted Rust CI (Ubuntu and macOS, including the Linux ARM64 and Intel macOS
compile-only checks) and contracts pass at `2dd1c3b4`. Native reference
conformance passed 1,883 tests across 83 result blocks, with zero failures and
no live capability skips. Sixteen ignored entries are evidence generators,
subprocess helpers invoked by their driver tests, an external Unicode dataset
and a documentation example. The three release executable hashes verified.
The Linux acceptance report has 39 passing gates and seven passing gates with
recorded limits; four gates contain macOS clauses outside this lane, and A01
still requires a real agent. The
[contracts run](https://github.com/monocursive/ouroboros/actions/runs/37441425173),
[Rust workflow](https://github.com/monocursive/ouroboros/actions/runs/37441425168)
and [reference-host conformance](https://github.com/monocursive/ouroboros/actions/runs/37441425131)
refer to the implementation commit.

The tested Jail freeze was regenerated from `reference/doctor.json`, whose
clean release build identifies `2dd1c3b4` and the current frozen input digest.
`local/freeze-refresh.log`, `local/freeze-check.log` and
`local/portable-freeze.log` record its regeneration and validation.
Only trailing whitespace in the human-readable gate and host reports was
removed; `reference/text-normalization.json` records original artifact and
committed hashes. Structured evidence and the test log are unchanged.

The Raspberry Pi was unavailable for this run: SSH timed out and Tailscale
reported it offline (last seen 2026-10-06 05:40 UTC). Previous ARM64 results are
not evidence for this change. Cross-compilation, when reported by CI, is not a
substitute for native tests. No kernel, boot or host-network settings were changed.

Remaining ledger work includes independent operator append, live tail,
cross-run queries/comparison, signed bundles and best-effort outage recovery.
Managed-worker authorization and real-agent/provider acceptance remain separate.
