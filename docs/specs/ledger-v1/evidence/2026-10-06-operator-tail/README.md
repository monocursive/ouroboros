# Independent operator intents and live tail, 2026-10-06

Implementation: `9fc690e5a5eb2174ebbf59d5f0b7079362fe44a8` on `dev`.
The follow-up `9f021b25` registers exact pagination homonyms in the existing I02
vendor-name scan. It does not change runtime behavior or weaken the scanner's
file/line matching. The final evidence commit follows these two commits.

## Behavior

- `append` records authenticated operator assertions with independent effect
  admission, denial and settlement. These do not mutate launch state, ownership,
  jail coverage or child protection, and never masquerade as source observations.
- Request/effect conflicts refuse. Identical requests retain their original
  receipts across later decisions, restart and whole-run pruning. Pending
  admitted operator effects protect history and captures from GC.
- `tail` returns bounded canonical fragments and resumable byte positions;
  `tail -f` follows later appends. Rotation, partial UTF-8 records and writer
  restart preserve exact bytes. Cursors confer no authority and do not pin GC.
  Damaged, ambiguous or pruned history refuses instead of silently skipping it.
- The body bound is 64 KiB. Tail output is at most 64 KiB per call, with at most
  32 frames and normally 128 KiB scanned. A larger legal record is verified whole
  within the existing 1 MiB frame bound before any fragment is returned.

## Validation

| Layer | Result | Scope |
|---|---|---|
| Local macOS ledger suite | 105 passed, 0 failed, 0 ignored | Portable behavior; Linux launch tests excluded |
| Native VPS ledger suite | 122 passed, 0 failed, 0 ignored, no skips | Release build, `OURO_CONFORMANCE=1`, including 16 actual Linux launch tests |
| New fault/reader unit tests | 6 passed in both suites | Eight append fault boundaries; effect replay and conflicts; forged positions; changed files; partial records; rotation, restart and GC |
| Real CLI/socket tests | 9 passed in both suites | Includes concurrent retries after a lost reply, actual follow output, late appends and restart |
| Strict ledger Clippy, formatting, I02 | Passed | The I02 test checks exact exceptions still reject unrelated files and appended vendor tokens |
| Contracts, documentation links, tested Jail freeze | Passed | No frozen Jail input changed; these checks do not claim deployment or release readiness |

The new native launch test appends operator admission and settlement while a
real contained shell waits on a workspace marker. It confirms the run remains
owned and admitted by its launch owner, then releases the shell, observes actual
owner settlement and compares all tail bytes with canonical history. Producer
exec observations retain their original provenance. The existing live tests
also cover child access refusal, detached ownership, cancellation, writer/owner
loss, bounded capture and one execution across replay.

These fault tests inject persistence failures; they are not physical power-loss
or disk-full experiments. Tail consistency covers returned records against
accepted history, not a fresh verification of bytes skipped by a supplied
position. Operator assertions are claims from the authenticated local operator,
not proof of an external effect or a substitute for managed authorization.

## Evidence identity

`source.json` binds the clean native source archive to the implementation commit.
`implementation.sha256` binds the ledger runtime, tests, schemas and fixtures
before the final evidence link was added. `linux/source.sha256` and
`linux/source-check.log` cover the native source tree before/after validation.
The I02 follow-up changes only its reviewed homonym list; compiled ledger inputs
remain those of the implementation commit.

`linux/validate.sh` is the exact native runner. It uses the existing VPS release
cache, builds the current Jail, fixture and ledger binaries, runs `doctor` and
executes the full ledger suite inside the provisioned Ubuntu user's systemd
scope. `linux/validation.exit` is zero; `linux/binaries.sha256` binds the three
release executables. `linux/doctor.json` records a clean optimized build with
frozen input digest `sha256:d5a0e965cfba1184b72d88370771812dd9544d31a52316bec75e4a4b15b881b6`.
That digest matches the existing tested Jail freeze. This ledger-only slice
therefore leaves the reference-host freeze at tested revision `2dd1c3b4`;
`local/freeze-check.log` verifies that it remains current.

The Raspberry Pi SSH connection still timed out. No native ARM64 validation is
claimed for this change. No kernel, boot or host-network settings were changed.

Cross-run queries, comparisons, signed bundles, best-effort outage recovery,
historical custody migration and managed project authorization remain open.
