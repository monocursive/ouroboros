# Detached local ownership, 2026-10-02

This implements the Linux session-survival prerequisite in
[ledger §3.1](../../../ledger-v1.md#31-detached-batch-ownership). A provisioned
lingering systemd user manager owns independent writer and launch-owner services.
There is no host configuration change, fleet scheduler or managed authorization.

## Live results

- All **15 Linux launch integration tests** passed, including six new detached
  cases. The full ledger library, CLI and evidence-reader suites also passed
  (`linux-full-ledger-final.log`). Native macOS ledger tests passed; Linux launch
  tests are not compiled there (`native-ledger-final.log`).
- Killing the submitting SSH client after the ownership reply, opening a new SSH
  connection and submitting the same request returned the same run and owner.
  The fixture appended exactly one execution marker and finished its command.
  Submission took 1.468 seconds; reconnect, completion and verification took
  11.158 seconds total, including an intentional eight-second child sleep.
- The child wrote 5,000 stdout bytes. The owner kept draining after the 64-byte
  capture cap; the record reports 5,000 observed bytes, 64 stored and truncation.
  Local consistency verification passed. `owned.json`, `replay.json`,
  `settled.json`, `verification.json` and `ssh-disconnect.json` preserve results.
- Cancellation requests a birth-checked stop and produces a receipt establishing
  an empty tree. Killing the owner stops the tree; reconciliation records
  `outcome_unknown` and replay does not execute again. Killing the writer stops
  the attempt without silently launching a replacement writer.
- A session-bound existing writer refuses detached submission. The writer
  outlives individual owner services. `doctor` checks readiness without creating
  a foreground writer. Raw launch options and caller environment travel through
  the private bounded bootstrap socket, not a spool file or service command.

The development source hashes are saved in `development-source-sha256.json`.
The SSH record pins the exact debug ledger and retained optimized jail binary
hashes. The jail source-input digest is the one in the
[October 2 baseline](../../../jail-v1/evidence/2026-10-02-baseline/README.md).
These development measurements precede the subsequent committed-workspace CI
run; they are not release performance numbers.

The [final committed-workspace validation](../../../jail-v1/evidence/2026-10-02-final/README.md)
at `52b54603` passed hosted Linux/macOS CI and the complete optimized reference
suite, including all 15 ledger launch tests. Its updated freeze also covers the
observer allocation-accounting correction discovered during CI.

## Failed attempts retained

The first focused run exposed rejection of the new `owner_lifetime` request
field by the store's strict validator. The validator and immutable replay tests
were corrected; the second and third focused logs pass.

The first full Linux ledger invocation did not pin `OURO_FIXTURE_BIN`. Its
harness tried to compile a fixture in `/tmp`, exhausted that filesystem's quota,
and caused 13 launch failures. Only that inactive temporary build directory was
removed. The final invocation pins the existing fixture and jail binaries,
uses the scrubbed system PATH and passes every test. No quota was increased
or disabled to obtain a pass.

## Remaining acceptance

This is a scripted child under local operator authority. No code or prompt was
sent to a model service in this measurement. The real coding-agent task needs
the user's agent/service selection. Managed ingress, project ACLs, scoped model
access and bounded remote artifact transfer remain unimplemented. Cross-run
queries, retention, signed bundles and best-effort recovery still keep the full
ledger milestone open. Native macOS execution remains unavailable.
