# Ledger storage and restart recovery, 2026-10-04

This records working-tree validation of the storage/recovery slice of
[ledger v1](../../../ledger-v1.md), performed before committing and pushing it.
`source.sha256` and `mac-source.sha256` bind the initial ledger implementation and
tests to the same files on the local Mac and the supplied ARM64 Mac. The matching
`source-final.sha256` and `mac-source-final.sha256` bind the final recovery-sync,
lost-reply-test and Linux launch-fixture corrections, plus contextual owner I/O
diagnostics. `linux-final2-source.sha256` also binds 261 build-source and contract
files; its ledger hashes match both Macs. A later reader-checkpoint security
review (final section) changed `reader.rs`, `store.rs` and `cli_local.rs` again;
`review-reader-current-source.sha256` binds the current tree and supersedes those
manifests for the files it lists. `review-source.sha256` binds the final 261-file
build-source and schema snapshot used for the two final Mac suites.

## Implemented behavior

- `segments.json` durably anchors the canonical stream bytes, sequence, chain
  head and ordered immutable replay identities. Startup verifies that prefix,
  synchronizes the same verified canonical descriptor, promotes complete
  unacknowledged tails and reconstructs their original receipts. A recovery-sync
  failure refuses startup before repaired projections or manifests are published.
  Truncated or changed anchored history stays poisoned; recovery never repairs it
  by truncating bytes. Existing manifest-free streams migrate after verification.
- `index.sqlite` is a private bounded disposable run projection, rebuilt from
  canonical history. Updates happen after response handoff. Index corruption,
  unsafe paths or update failure cannot authorize a launch or revoke an append
  acknowledgement. `doctor` reports index availability independently.
- Reader checkpoints persist before responses. Query and exact NDJSON export
  continue across writer restart, including within a record and after a lost
  socket reply. Snapshot/filter/limit bindings and latest-page retry remain stable.
  Forged, corrupt, unsafe, expired or inode-replaced checkpoints refuse. A failed
  manifest proof cannot restore a clean consistency label.

There is still one canonical segment per run. Rotation, retention-pruned replay
identities, cross-run queries, retention/GC, signed bundles and best-effort launch
continuation remain outside this slice. No managed authorization, real-agent
compatibility or native macOS launch support is established.

## Native validation

Rust 1.98.1 was used on both Macs. `mac-host.txt` records the supplied host.

- Local workspace: **1,100 passed, 7 documented ignored cases, zero skip markers**
  (`local-workspace.log`). Ignored cases include subprocess helpers, the deliberate
  evidence generator, the optional Unicode normalization corpus and a doc example;
  they are not successful execution claims.
- Supplied Mac workspace: **1,100 passed, 7 intentionally ignored, zero skip
  markers** (`mac-workspace-corrected.log`).
- Final ledger suites: **64 passed** on each Mac (`local-ledger-storage-final.log`,
  `mac-ledger-storage-final.log`), including nine actual daemon-reader integration tests
  and nine storage/restart integration tests. Linux launch tests do not compile
  on macOS. The broad workspace invocations precede the final four-file ledger
  correction; both final ledger suites and strict workspace Clippy were rerun.
- Workspace strict Clippy, formatting, dependency/advisory/license policy,
  both document contracts, I02 and documentation links passed. Intel macOS
  cross-target checking passed (`cross-macos-intel-storage-final.log`); this is compilation only.

The first local recovery-sync rerun exposed a race in the lost socket reply
test (`local-ledger-recovery-sync.log`): closing before daemon accept can prevent
secure peer attribution, so the request was never accepted. The corrected test
keeps the socket unread until the checkpoint proves durable acceptance, drops
the unread reply, restarts the daemon and requires exact prior-page replay.
The final suites pass with that acceptance boundary. The initial Clippy finding
in the new regression was corrected to use the iterator's reverse search.

## Linux validation

The supplied x86-64 VPS used Rust 1.98.1, a delegated systemd user scope,
`OURO_CONFORMANCE=1`, pinned real jail/fixture release binaries and the system
PATH. The final launcher and complete command environment are retained in
`linux-final2-launcher.sh`, `linux-validate-ledger-final2.sh` and
`linux-validation-env.txt`.

- Final release ledger suite: **80 passed, zero failed, ignored or skipped**
  (`linux-ledger-final2.log`, `linux-ledger-final2-summary.json`). This includes
  **all 15 real launch tests**, nine daemon-reader integrations and nine storage
  integrations. One extra unit test is Linux-only, so the non-launch total is
  65 rather than the Macs' 64. The final suite runs with one test thread.
- Real jail doctor, strict workspace Clippy, I02, all 261 final source hashes
  and all three product hashes passed. Their individual exit files and aggregate
  `linux-final2-validation.exit` are zero.
- The earlier broad workspace invocation passed all Jail targets but finished
  **1,842 passed, one failed, 16 intentionally ignored, zero skipped**
  (`linux-test-corrected.log`, `linux-workspace-summary.json`). Its sole failure
  was the ledger `explicit_none` launch. The final ledger suite above follows
  the correction; the broad workspace suite was not rerun.

The original Linux launcher used `nohup`, which inherited ignored signals and
correctly tripped a signal-preservation regression (`linux-test.log`). The
corrected launcher uses the repository's `setsid` pattern and records `SigIgn: 0`.

The `explicit_none` failure reproduced in both the broad and focused ledger
runs. Contextual owner diagnostics identified a missing canonical jail receipt.
Read-only host metadata then showed existing trusted launch profiles in the
operator's default configuration (`linux-host-config-filenames.txt`). The Jail
correctly refuses unprotected execution exposing trusted configuration before
allocating attempt state. The launch fixture now creates its own private empty
configuration and passes `OURO_CONFIG_DIR`; the affected test and all final
launches pass. The operator's configuration and the Jail refusal rule were
unchanged. Failed invocations and intermediate source hashes remain recorded.

## Mac resource-exhaustion test correction

The first two supplied-Mac workspace invocations failed the existing proxy N04
test (`mac-workspace.log`, `mac-workspace-final.log`). The helper assumed a Unix
connection queued while `accept` fails with `EMFILE` would remain pending. Three
isolated probes on the supplied Darwin host instead found client EOF and no
pending connection after descriptors were released (`mac-emfile-probe.log`).

The test now accepts only empty EOF on that original Mac client, retries one
fresh CONNECT after capacity returns, and verifies a real connected/relayed
result. Partial or malformed responses and read errors still fail. Linux behavior,
resource limits and product implementation are unchanged. Three focused supplied
Mac repetitions and the subsequent complete workspace invocation passed.

## Release freeze

Bundled SQLite changes `Cargo.lock`, one of the frozen jail build inputs. The
freeze was regenerated for this tree and the stale tested section was removed
(`freeze-regenerate.log`). `freeze --check` deliberately fails because there is
no new clean committed tested build (`freeze-check.log`). Working-tree tests and
source hashes are development proof; they do not replace that release gate or
hosted CI for a committed revision. These invocations ran before the changes
were committed and pushed; no clean committed tested freeze is established.

## Reader checkpoint security review

An external review of durable reader recovery ran against this slice after the
freeze work above. Its harness builds a standalone crate against the working
tree (`review-reader-external-repro.rs`), injects directory-fsync EIO through a
dylib interposer (`review-reader-sync-interposer.c`) and forges private
same-user checkpoints with recomputed checksums; `review-reader-external-repro.sh`
drives the matrix and `review-reader-harness.sha256` binds the harness.

The first reproduction (`review-reader-before.log`; no source hash was captured
for that run) found two defects. A checkpoint retry was acknowledged while the
readers-directory fsync still failed, and a same-user checkpoint whose template
labels were rewritten with a recomputed checksum restored forged protection or
state with a clean consistency label. Both were fixed: retry and restore now
re-flush the validated checkpoint descriptor and its directory before
acknowledging, reader-directory creation re-establishes its parent namespace
durability (`review-reader-parent-sync.log`), and snapshot state, protection and
bounded coverage labels are anchored per canonical sequence and corroborated on
restore, with the selection label derived from that coverage. The corrected
harness run (`review-reader-after.log`) shows refusals for the sync-fault retry,
the parent-sync barrier and forged labels, state and coverage.

A second bypass was then discovered against that fix
(`review-reader-zero-head-before.log`, bound by
`review-reader-zero-head-before-source.sha256`): starting from an issued current
cursor, replacing the checkpoint's snapshot, position and template with an empty
zero-record snapshot and recomputing the checksum passed the sequence-zero
corroboration vacuously, returning a clean `settled`, `enforced`, done page for
an unprotected prepared run. The fix makes an empty snapshot-head claim
corroborate genuine canonical emptiness through the store: no restorable
checkpoint has a clean empty snapshot, because streams open at durable
preparation and empty or broken streams stay poisoned. A replay position before
the first record keeps its structural no-predecessor check. The permanent
regression `durable_reader_refuses_a_rechecksummed_empty_snapshot_template`
failed before and passes after this change, and the rerun harness
(`review-reader-after.log`, 2026-10-04T17:58:56Z) refuses all four forgery
modes including the empty snapshot; `review-reader-current-source.sha256`
regenerated by that run binds the fixed tree. Both bypasses required private
same-user checkpoint write access; neither is evidence about external custody
or managed authorization.

An earlier Linux review validation ran against the post-first-fix tree
(`linux-review-pre-empty-*`: 85 ledger tests passed including all 15 real
launches, real jail doctor, 359-file source binding, all exit codes zero).
That run predates the empty-snapshot fix; its logs and hashes remain preserved
separately from the final native reruns.

The review also found that rusqlite's default five-second lock wait stalled the
sole writer past the next request's two-second timeout, even though the first
durable reply had already been handed off. SQLite now fails immediately on lock
contention. The daemon regression holds `BEGIN IMMEDIATE` on the disposable
index and verifies accepted preparation, a responsive next request, exact replay,
independent index unavailability and unchanged canonical bytes. It failed before
the correction and passes afterward.

## Final review validation

- Local Mac and supplied ARM64 Mac: **70 ledger tests passed on each**, zero
  failures, ignored tests or skip markers (`local-review-ledger.log`,
  `mac-review-ledger.log`, their summary and exit files). Both source checks match
  all 261 entries in `review-source.sha256`.
- Linux release suite: **86 passed**, including **all 15 real launch tests**,
  zero failures, ignored tests or skip markers (`linux-review-ledger.log`,
  `linux-review-summary.json`). Build, ledger, real jail doctor and aggregate
  validation exits are zero. All 359 source/control hashes match before and
  after the run and against the local tree; all three product hashes pass.
  The signal-clean systemd scope and pinned binaries are recorded in
  `linux-review-validation-env.txt` and the review launcher and validator.
  Only the isolated build directories were removed after evidence retrieval.
- The external reader matrix passes both injected namespace-sync failures,
  retries after fault removal, exact reply replay, safe corruption isolation and
  all four metadata forgery cases. The forgery cases require private same-user
  write access; this proof does not establish external custody.
- Strict workspace Clippy, formatting, I02 including exact-exception negative
  coverage, and both schema/fixture contracts pass (`local-review-*`).

The broader workspace and Jail suite results above precede these ledger-only
review corrections. The ledger suites and workspace static checks were repeated;
the broader runtime suite was not repeated. Rotation, retention and the clean
committed release freeze remain outside this evidence.
