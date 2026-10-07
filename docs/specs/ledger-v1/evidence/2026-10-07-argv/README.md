# Bounded opt-in argv capture — 2026-10-07

Implementation: `fc6727044c185fd0898d58033cc15d6321552846`.
[source.json](source.json) identifies the Git archive;
[source.sha256](source.sha256) binds its 426 runtime, test and contract inputs.
Only changed content was copied into the existing native test checkouts.
Every full suite checks those inputs before and after execution. The following
evidence commit adds proof files and updates two documentation pages; runtime,
test and schema inputs remain those of the implementation revision.

## Behavior and proof

`run --capture argv` stores a private `artifacts/argv.bin` with NUL-delimited
native argument bytes, including the executable. Empty and non-UTF-8 arguments
are preserved. The existing capture limit applies independently to each selected
artifact, including zero; truncation can occur inside an argument. Metadata
records encoding, argument count, limit, observed/stored bytes and truncation.

The owner synchronizes argv after Jail preparation and before durable admission
and gate release. Admission retains its metadata even if the owner later dies.
It describes the requested command, not proof of execution or a known outcome.
The owner records only argv metadata in canonical events. Ordinary show, queries
and canonical export do not read the artifact. Transcript display and bundle
export each require explicit selection.
The artifact participates in both capture-only and whole-run retention.

Five added portable tests cover every byte truncation boundary, empty and
non-UTF-8 arguments, exact prefixes after short writes and simulated ENOSPC,
private permissions, refused overwrite and symlink storage, signed/unsigned
bundle selection and tampering, and both retention paths with argv alone or
all three artifacts. The existing transcript transport-bound test now checks
worst-case escaping across all three artifacts.

Two added native tests exercise `tool` and `none` with real children. They check
default privacy, exact native bytes, zero/partial/full caps, explicit bundle
selection, unchanged canonical metadata and one execution after request replay.
Owner SIGKILL retains the complete admission capture while the tree is proven
empty and the outcome stays unknown. The existing signed-launch test now
exports all three artifacts and verifies offline after removing the source
store and private signing key. Existing pending-journal and lifecycle fault
matrices run in full.

The separate [CLI probe](probe-cli.py) saves actual argv display, signed bundle,
verification and canonical event responses. [validate-cli.py](validate-cli.py)
checks these against the schemas and canonical byte encoding. Probe bytes are
deliberate test strings, not credentials or application data. The probe requires
a delegated scope and private fixture writer; only that writer is stopped.

## Validation

The native [validation script](../2026-10-06-writer-outage/validate-native.sh)
uses Rust 1.98.1, `OURO_CONFORMANCE=1`, `RUST_TEST_NOCAPTURE=1`, private fixtures
and a delegated user scope. [verify-results.py](verify-results.py) checks all
exit statuses, test counts, 72 pending-owner fault cases, 66 lifecycle cases,
argv/transcript/vendor-cleanup markers, production binary hashes and absence
of test instrumentation. Source hash checks must pass before and after.

- VPS: **203 passed**, zero failed, ignored or skipped.
  [Summary](linux/summary.json), [full log](linux/ledger.log),
  [actual CLI response](linux/argv-cli.json).
- Raspberry Pi: **203 passed**, zero failed, ignored or skipped.
  [Summary](pi/summary.json), [full log](pi/ledger.log),
  [actual CLI response](pi/argv-cli.json).
- Local macOS: **168 passed**, zero failed or ignored.
  [Summary](local/summary.json), [full log](local/ledger.log).
  Linux launch tests are compiled out on macOS.

Formatting, Clippy, contracts, links, I02 and the unchanged Jail freeze pass.
This validates test builds on the existing machines; installed commands and
kernel configuration are unchanged. No production release is made.

## Scope

These results establish scripted-child behavior and native filesystem/process
handling on the tested hosts. They do not establish physical power-loss safety,
real-agent/provider compatibility, managed readiness or external custody.
Capture bytes remain local artifacts, with bundle-time content hashes;
transcript display does not upgrade their integrity or the run outcome.
Foreground control-FD output and explicit structured redaction remain separate
milestone-2 work.
