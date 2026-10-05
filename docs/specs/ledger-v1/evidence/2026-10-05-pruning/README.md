# October 5 ledger whole-run pruning

This slice adds explicit `gc` deletion after the earlier operator holds and
retention preview. It verifies eligible canonical history, persists a bounded
retained authority, then removes only inventoried canonical segments and selected
stdout/stderr captures. No user ledger data was used for these tests.

## Behavior checked

- Known terminal runs age from their latest canonical writer timestamp. Recent,
  held, unknown-outcome and live-reader runs stay intact. Active launch owners
  refuse deletion for the entire writer. Completed reader pages pin history for
  their retry lifetime; expired in-memory readers release their file descriptors.
- Full canonical replay must agree with accepted state, segment anchors and
  immutable receipts before publication of `gc.json`. The file and its containing
  directory are synchronized before unlink. Each file is checked again for
  identity, length and content immediately before removal through its pinned
  parent directory.
- Restart recovers eight injected boundaries: before authority publication,
  after its sync, before and after unlink, after directory sync, before completion
  publication, after completion sync, and before projection persistence. The
  retained replay map and original segment manifest remain identical. These are
  deterministic failure injections, not physical power-loss experiments.
- Modified canonical bytes, modified captures, a symlinked capture directory,
  corrupt retained authority and files reappearing after completion refuse.
  Unrelated sentinel bytes remain intact. Recovery does not fall back to creating
  a new preparation identity when pruned authority is damaged.
- Original preparation, request, source and effect receipts survive pruning and
  restart. Conflicting payloads and new mutations refuse. Repeated GC returns the
  original receipt without counting it as a new removal. Event note bodies and
  captured stream bytes are absent from retained authority.
- `show` preserves terminal state, outcome, chain head and the `none` profile's
  unprotected label. Capture metadata marks deleted bytes as pruned. Query/export
  explicitly refuse pruned history; `verify` reports zero available events and
  scopes its consistency result to retained metadata and completion.
- Actual CLI/daemon subprocesses prune synthetic aged exec-failure history,
  restart, preserve preparation identity, reject export and verify retained
  metadata. Schema fixtures reject unsafe inventory paths, contradictory receipt
  states, ineligible runs and oversized capture inventories.

## Local validation

`OURO_CONFORMANCE=1 cargo +1.98.1 test -p ouro-ledger -- --test-threads=1`
passes **90 tests, 0 failed, 0 ignored**, with no runtime skip markers. This adds
five store tests and one CLI test to the prior retention snapshot; the boundary
test exercises eight fault positions. Logs are in `macos-ledger-tests.log`.
Strict ledger Clippy, both Jail and ledger contract validators, formatting, I02
and the tested Jail freeze gate pass. No Jail build input or dependency changed.

`source.sha256` binds 535 source/contract files at base revision
`5b0b5531628f8612c43c0873cb3a9261c293b847` with working-tree changes. The previous
retention evidence remains a historical snapshot of preview-only behavior.
These local results are not hosted CI evidence for a new commit.

## Native Linux x86_64 validation

The supplied x86_64 VPS ran the same 535-file source snapshot with Rust 1.98.1,
release optimization, `OURO_CONFORMANCE=1` and one test thread. All **106 ledger
tests passed, 0 failed, 0 ignored**, with no runtime skip markers, including all
**15 real jail launch tests**. Release build, strict Clippy and the real jail
doctor (`ready=true`) pass. Source hashes before and after execution agree; all
three product binary hashes pass. The aggregate validation exit is zero.

Logs and doctor output are under `native/linux/`; `validation.json` records the
counts and scope. `validate-linux.sh` records the runner and `runner.sha256` binds
it. The isolated checkout's build output was removed after evidence retrieval;
its source and logs remain available on the test VPS. No user ledger was pruned.

## Raspberry Pi ARM64 validation

The same 535-file snapshot was built and tested natively on a Raspberry Pi 4
Model B Rev 1.2, Debian 13, kernel `6.18.50+rpt-rpi-v8`. Release build and strict
Clippy pass with the pinned Rust 1.98.1 toolchain installed in the isolated test
directory. The default user environment was not changed.

**91 tests pass; 15 launch tests fail at the required capability preflight; none
are ignored or silently skipped.** All GC, store, reader, CLI and storage-recovery
tests pass. The aggregate test exit is 101. The jail doctor exits 125 with
`ready=false`: `closed_set_observation` and `syscall_filter` report
`unsupported_architecture`. Their current syscall tables are x86_64-only, as
declared in [Jail v1 §3.2](../../../jail-v1.md#32-initial-support-matrix). Host namespaces,
ptrace attach and delegated CPU/pids cgroups probe successfully; configuration
changes cannot supply the missing ARM64 implementation.

An additional direct CLI check confirms that both `tool` and `none` strict
ledger launches refuse before executing the child. The initial attempt to run
`none` also refused because ledger admission requires closed-set observation.
For both profiles, retries preserve the exact run, attempt, chain and refusal
outcome, and `verify` reports local consistency with `child_protection=unprotected`.
These are refusal checks, not successful child execution or containment proof.

The [Pi result](native/pi/validation.json), raw test failures, doctor, source and
binary hash checks, toolchain installation log and refusal receipts are under
`native/pi/`. `validate-pi.sh` and `smoke-arm64-refusal.py` record the commands;
`runner.sha256` binds the scripts. The shell runner stops at the failed test gate,
so doctor and post-run source/binary checks were collected separately. Original
failure logs and exit codes are retained. The private Pi checkout, toolchain and
compiled binaries are retained for repeat validation. This adds native ARM64
ledger/GC evidence; it does not add ARM64 launch acceptance.

## Scope

Pruning is explicit and whole-run only; persistent retention configuration and
separate capture policies remain pending. Directories, metadata, embedded jail
receipts, reader checkpoints and unrelated files are retained. This is not full
data erasure. Retained local checksums are not signatures or external custody.
The implementation does not establish managed-worker authorization, provider
compatibility or native macOS containment. The single writer must be quiescent
for deletion; a transport timeout leaves the result uncertain and recoverable.
