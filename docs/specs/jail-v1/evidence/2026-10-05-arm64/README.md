# Native ARM64 Jail validation, 2026-10-05

The implementation and native test source is commit
`2d88db2295eecff139e983cf3206f7e222ac12d9` on `dev`.
This record extends the earlier ledger pruning test, whose Pi launch failures
remain preserved under `ledger-v1/evidence/2026-10-05-pruning/native/pi`.

## Changes

- Native aarch64 syscall tables for containment, observer narrowing and Unix
  peer mediation. Independent native libc checks cover the baseline table and
  all 99 named fixture syscalls. The 13 ARM64 closed-set rows name actual kernel
  calls; absent legacy x86 calls are never invented.
- ARM64 ptrace register access, syscall cancellation through NT_ARM_SYSTEM_CALL,
  EPERM return injection, and signal-frame/restart handling. Live cases include
  EINTR, SA_RESTART, ignored signals, alternate stacks, rewritten frames and
  non-leader exec transitions.
- Absent default runtime paths such as Debian ARM64's `/lib64` no longer become
  required operator binds. Existing roots are pinned and grants still fail
  closed on other errors.
- Agent preflight now performs an AF_UNIX socket-diagnostics query. Merely
  opening NETLINK_SOCK_DIAG succeeds without CONFIG_UNIX_DIAG and previously
  let an agent launch whose same-attempt pathname IPC could not work.
- The freeze records each architecture's filter and observer tables separately.

## Raspberry Pi host boundary

Raspberry Pi 4 Model B Rev 1.2; Debian 13.7; Linux 6.18.50+rpt-rpi-v8;
Rust 1.98.1; bubblewrap 0.12.0. The final tests run natively with release
optimization and OURO_CONFORMANCE=1, one test thread per binary.

The host has `cgroup_disable=memory`, CONFIG_SECURITY_LANDLOCK unset, and
CONFIG_UNIX_DIAG unset. `tool` and `none` run; required memory ceilings,
requested Landlock domains, and `agent` refuse before executing the child.
The test checks child markers are absent on refusal. No kernel, boot settings
or default user toolchain were changed.

The positive Landlock fixture test is explicitly excluded on this kernel;
its negative path is exercised, and the positive path runs on the VPS.
Positive agent and build conformance belongs to the VPS lane. This is not
full-profile Pi conformance or native macOS execution acceptance.

`development/pi-missing-unix-diag.log` is the preserved failed development
run that exposed the missing kernel feature (two N05 failures). It predates
preflight enforcement and is not final acceptance evidence.

## Final results

- Pi: **790 tests passed, 0 failed**, one ignored evidence-table generator.
  This includes 508 Jail unit tests, 44 targeted live tests, both tool/none
  syscall matrices, 13 native freeze tests, 109 fixture unit tests, seven
  strace identity tests, and all 106 ledger tests (15 real launches).
  Strict Clippy, release build, source checks and binary verification passed.
  `doctor` for the default tool profile is ready; agent doctor exits 125 with
  `unix_socket_diagnostics_unavailable`.
- Local Apple Silicon macOS: **1,127 workspace tests passed, 0 failed**, seven
  explicitly ignored cases (generator, subprocess helpers, external Unicode
  dataset and documentation example). Linux tests are target-excluded here.
  Strict Clippy, Intel macOS compilation with warnings denied, dependency
  policy, contract checks and links passed.
- Reference x86_64 VPS: **1,875 tests passed, 0 failed**, 16 explicit ignored
  generators/helpers/dataset/doc cases and no live runtime skips. The full
  conformance driver passed for `20261005T194940Z-2d88db2295ee`, including doctor
  manifest comparison, plain-SSH tool/none smoke, I01/I02, contracts and binary
  verification. Its gate report has 39 passes and seven passes with documented
  limits; four macOS rows belong to another lane and A01 still needs a real
  agent/provider. This is the normal scope of reference-host conformance.
  [Hosted run](https://github.com/monocursive/ouroboros/actions/runs/37365762696).
- Hosted Rust workflow attempt 1 could not obtain either Ubuntu or macOS
  runners. GitHub's exact annotations are retained under `local/`; neither
  job executed a test. A retry was requested. This is separate from the real
  native runs above.

## Provenance

`pi/source.sha256` binds the tested source/contract snapshot, including both
architectures' checked-in tables. Source checks before and after the run must
agree. `pi/binaries.sha256` binds the three native binaries. The doctor records
its compiled input digest, exact tested revision and clean-build claim.
The runner records every stage exit, plus the expected 125 from agent doctor.
The source manifest describes the tested commit, before the final evidence-only
freeze refresh. `freeze-check.log` verifies that the reference binary's measured
inputs match both this source tree and its ancestor commit; the Pi binary has
exactly that same input digest. Both architecture tables remain independently
pinned. The final freeze is checked again natively, with the Pi source snapshot
restored afterwards so its original source manifest stays reproducible.
Unit evidence generators remain ignored by ordinary test runs; this does not
represent a skipped live capability test.

All ledger histories, socket listeners, processes and fault injections belong
to the test fixtures. The work does not claim physical power-loss durability,
managed-worker authorization, provider acceptance or a public release.
