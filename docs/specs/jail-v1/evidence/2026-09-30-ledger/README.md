# Jail and first-ledger acceptance — 2026-09-30

The complete workspace passed reference-host Linux conformance at clean commit
`a9f8129acb718ed9d05986a4729db69ecf4b5094`, after extracting the shared records
crate and adding the first local ledger slice. The jail's current milestone-1
freeze names this tested build; `freeze-check.txt` verifies the source inputs,
tested revision and unchanged frozen inputs.

## Full workspace and jail freeze

- Linux: **1,787 passed, zero failed, 16 documented ignored**, 79 test groups;
  no live skips under `OURO_CONFORMANCE=1` and serial execution. All nine real
  ledger execution cases passed in this run.
- Native ARM64 macOS: **1,060 passed, zero failed, seven documented ignored**,
  79 test groups, with actual invocation metadata in `macos-test.log`.
  This is portable/inspection evidence; native contained execution is disabled.
- Combined acceptance: all **50 noncredential gates** pass, comprising 43 pass
  and seven pass with existing named limits. `combined-gates.json` has no
  problems or warnings. The A01 real-agent gate is recorded separately in the
  [clean-VM onboarding report](../../../../benchmarks/jail/onboarding-2026-09-30.md).
- Workspace formatting, strict Clippy, warnings-denied x86_64 macOS compilation,
  Linux ledger cross-Clippy, dependency policy, contract validators, document
  links and the I02 vendor scan pass. Cross-target checks are compile evidence.

The driver precompiled release tests before measuring the executables and then
checked their hashes after the entire suite. `binaries-check.txt` reports all
three unchanged. The I02 cargo invocation caused a later library recompile,
but the post-suite guard confirms that product executable bytes did not change.
The original measurement is preserved, without a replacement doctor report.

| Product | Tested SHA-256 |
|---|---|
| ouro-jail | `cdf8a182680ef500dfb8e9983e5fea863f95b5b72c4734703cf3c14d7a9ca602` |
| ouro-fixture | `db28b45b243369ec17add3f04bd642d7dc3c63350a6ba999e1b38ca8c85a5696` |
| ouro-ledger | `c6f3a0feda78ef6d088dbecd2168feda158f38ede8005001b158c85132ff28a9` |

The jail doctor reports Rust 1.98.1, optimization level 3, debug assertions off,
Linux x86_64, a clean tested revision and build input digest
`sha256:aff986001cf72b911bb2bdc8fa85bca0056069ae7a9bafadca76e7878739d79c`.
The host is Ubuntu 26.04.1, kernel `7.0.0-31-generic`, bubblewrap 0.11.1, with
the expected delegated controllers. `doctor.json` and `host-manifest.txt` name
the measured capability limits.

Exact products and a source archive were retained outside the repository before
the later ledger-only retest. `retained-products.json` binds their hashes and
the tested source archive. Raw collected logs retain their original bytes.

## Ledger follow-up

Commit `d1a368587e1ca53450153035dba3c9a61ed50946` changes the Linux capture
writer to count every successful short write before a later disk error. It also
clarifies managed gateway and detached-owner prerequisites in documentation.
The jail, shared records, wire schemas and frozen build inputs are unchanged.
Its separate Linux package rerun passed **37 tests, zero failed, zero ignored**:
26 library cases, two CLI cases and nine real launch cases, under
`OURO_CONFORMANCE=1`. The new injected partial-write test retains the exact
prefix count after ENOSPC. `ledger-retest/summary.json`, the raw log, source
hashes and invocation script bind this result to the named source archive;
the package file hashes independently match that commit.

The follow-up ledger executable SHA-256 is
`ad432a7aac8485ace942bf63c7aa17f0b8313eea6aed2c75d8241f4777e28d36`.
Frozen product copies remain unchanged, as checked separately in
`ledger-retest/frozen-products-check.txt`. The original full-workspace ledger
hash above remains the correct hash for that earlier run. Current native and
Linux compile checks also accept the capture fix. The 12 portable freeze tests
pass after recording the tested freeze.

## Scope

This is the first local ledger slice, including durable admission, source
ingestion, exact replay, bounded capture and conservative owner-loss handling.
The [ledger specification](../../../ledger-v1.md) lists remaining milestone-2
work. Persistence and partial-disk failure cases use controlled fault injection.
The [managed pilot preparation](../../../../benchmarks/managed/pilot-plan-2026-09-30.md)
names the deployment decisions and implementation gates still open.
