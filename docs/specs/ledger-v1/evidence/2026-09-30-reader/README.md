# Bounded evidence reader acceptance, 2026-09-30

The tested source checkpoint is `d80854e4b2ba2b2fd355a6c0f7249189524951b0`.
This record covers the single-run reader and canonical NDJSON export described
in [Ledger v1 §7](../../../ledger-v1.md#7-bounded-evidence-readers).
It does not complete milestone 2 or establish managed-worker authorization.

## Native macOS checks

The [native source and toolchain summary](native/summary.json) records the exact
SHA-256 of all 21 changed files and the native ledger executable. Source contents
matched the clean checkpoint. The [package test log](native/native-test.log)
records 40 passes, zero failures and zero ignored tests: 33 library tests,
two preparation/inspection CLI tests and five reader CLI tests. Linux launch
tests are compiled out on this platform.

The new cases exercise attributed operation/stage/time filters, bounded scans,
snapshot preservation after later appends, cursor replay and scope refusal,
explicit restart expiry, large UTF-8/escaped records, unsupported/degraded
coverage, and corrupt or interrupted streams. Real daemon/CLI cases also prove
exact canonical export bytes, checkpoint resume, live unexpected-tail detection
and nonzero failure when the export's stdout pipe closes.

[All-targets Clippy](native/native-clippy.log), [formatting](native/fmt.log),
[ledger contracts](native/ledger-contract.log), and
[documentation links](native/link-validation.log) passed. The
[jail freeze check](native/freeze-check.log) and all 12
[portable freeze tests](native/portable-freeze.log) passed; this slice changes
no jail, shared-record or frozen build input.

## Linux reference-host checks

The [host/toolchain record](linux/host-metadata.json) identifies Ubuntu 26.04.1
LTS on x86_64, kernel 7.0.0-31, with Rust 1.98.1.
The [Linux summary](linux/summary.json) and [raw test log](linux/test.log)
record 50 passes, zero failures, zero ignored tests and zero live skips:
34 library tests, two local CLI tests, five reader CLI tests and nine actual
jail launch tests. The [driver](linux/remote-test.sh) used an isolated release
target, pinned the ledger executable after test precompilation and enabled
`OURO_CONFORMANCE=1`. Its actual suite had a 300-second bound.

The [source archive digest](linux/source-archive.sha256) identifies the exact
clean checkpoint; all 11 [package source hashes](linux/ledger-source.sha256)
were independently compared with that revision. The measured Linux ledger
SHA-256 is `afde80226dfa468b7e561f1128c2f392b31f60eec7d5975857f54f5846356d3c`.
It was [unchanged throughout the actual tests](linux/ledger-binary-check.txt).

Live launches used the retained jail from the
[previous full acceptance](../../../jail-v1/evidence/2026-09-30-ledger/README.md):
SHA-256 `cdf8a182680ef500dfb8e9983e5fea863f95b5b72c4734703cf3c14d7a9ca602`.
The jail, fixture and previous acceptance products remained unchanged
[before](linux/frozen-products-before.txt) and
[after](linux/frozen-products-after.txt) the run. This is targeted ledger
validation, not a new full jail conformance run.

The exact ledger, reader-test and real-launch-test executables are retained
outside Git with their [digests](linux/retained-products.sha256), alongside the
source archive at `/tmp/ouro-ledger-query-export-linux-20260930`. Executables
and source archives are not part of this evidence commit.
The [cleanup proof](linux/cleanup.json) confirms that only this run's source and
build directories were removed, retained products stayed identical, and no
owned processes remained.

## Reader limits

Each request scans at most 128 KiB and 32 frames. Query output is capped at
128 KiB; a larger matching record stops with an explicit oversized-record
result. Export verifies a full frame before returning exact UTF-8 chunks of at
most 64 KiB, including legal records near the existing 1 MiB frame bound.

Cursors bind one run, filter, limit and snapshot. The daemon retains at most
32 sessions for ten minutes and caches one prior response. Restart, expiry,
scope changes and stale positions refuse. Resume uses the same live session
and exactly the byte prefix recorded by its checkpoint; durable resume is later
milestone work. Consistency describes the accepted snapshot records checked so
far. Coverage, unknown outcomes and protection from the child remain separate.
