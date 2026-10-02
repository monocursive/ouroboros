# File observation and explicit resource ceilings — 2026-10-01

Read workload time falls from **24.53 ms to 6.10 ms (4.02× faster)**;
whole-command time falls from 149.95 ms to 130.38 ms (13.1% lower).
Write observation remains expensive and did not improve in this run.

This follow-up implements a Linux read-only-open fast path, an independent
swap ceiling, and admission for operator-provisioned storage/inode ceilings.
It compares the new working-tree binary with the previous frozen Ouroboros
binary on the same VPS. Greywall and Anthropic Sandbox Runtime are not rerun
here; their earlier measurements remain in the [comparison report](README.md).

## What changed

Normal contained runs handle read-only `open` and `openat` calls entirely in
seccomp, avoiding a ptrace stop. Flags come from the kernel's syscall argument
copy. Write, create, truncate and temporary-file intent still stops. Learning
keeps the full observer, as does pointer-based `openat2`. The `none` profile
also keeps its existing filter. Receipts identify the installed filter digest
and whether the fast path was enabled. Kernel-filtered read-only opens are
not included in the tracer's `filtered_readonly_opens` counter.

`--limit swap=0` disables swap through `memory.swap.max`; positive byte
ceilings are also supported. RAM remains a separate `mem` limit. Application
requires a successful write and exact readback. Missing required controls
refuse. Limit-hit evidence uses `memory.swap.events:max`; `fail` alone can
mean host-wide swap exhaustion and is not attributed to this ceiling. See
the [kernel's cgroup memory interface](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files).

`--limit storage=8MiB --limit inodes=64` can admit a pre-provisioned tmpfs
with those bounds. Before target release, Ouroboros inspects every writable
mount in the prepared child namespace and sums each distinct filesystem's
total kernel capacity once. Workspace, scratch, extra writable grants and
vendor state must all fit. Bind aliases share the same budget. Existing data
and other writers on a shared volume consume that budget too. These are
whole-volume ceilings, not per-directory quotas or reserved free space.

The target cannot allocate regular files through `/dev/shm`: `/dev` is
read-only for storage-bounded runs. The ordinary device bindings remain
usable. `none` and agent variants that can create new mounts refuse storage
ceilings. Unsupported, oversized or unbounded writable mounts refuse before
the target executes. No workspace is copied or silently made disposable.

Storage limits concern allocated file data; sparse-file apparent length,
anonymous/memfd memory, output sinks outside the sandbox and remote effects
are outside that bound. Use `mem` for charged RAM, including tmpfs metadata.
The inode ceiling does not bound hard-link directory entries. Ordinary
disk-backed project quotas and automatic volume provisioning remain absent.

## Measurement method

The host is the existing Ubuntu 26.04.1 VPS: Linux 7.0.0-31, x86_64, four
AMD EPYC-Milan vCPUs, 3.7 GiB RAM, 8 GiB swap and bubblewrap 0.11.1. Tests and
benchmarks run as unprivileged `ouro-ci`; only creation/removal of the private
8 MiB / 64 inode test tmpfs requires the operator account. Builds and the
serial live suite finish before timing begins.

[The runner](observe_limits.py) uses three discarded warmup rounds and 30
measured rounds, shuffling direct/before/after and read/write pairs with seed
20261001. Each read workload opens 1,000 files of 4 KiB; each write workload
writes 1,000 files of 1 KiB. Counts and checksums must match, and write outputs
are checked externally. Sandbox runs need a settled zero-exit receipt, empty
tree and no coverage gaps; write runs also need at least 1,000 observed file
write events. Caches are warm and writes are not fsync durability benchmarks.
Both in-child workload time and complete CLI time are retained.

The baseline binary's SHA-256 is
`cdf8a182680ef500dfb8e9983e5fea863f95b5b72c4734703cf3c14d7a9ca602`,
the frozen binary from the September 30 comparison. The final implementation's
build-input digest is
`sha256:7663f80d23066163f3c304636d0b3b0ae2f5fed20e5dbd691578ff257e5505f0`.
The working tree is uncommitted; the build reports null revision/dirty fields
and is identified by its measured input digest and binary hash. This is not
a new release freeze.

## Results

Milliseconds, **median / p95** (p95 uses the nearest rank of 30 samples):

| Work | Direct | Before | After |
|---|---:|---:|---:|
| Read workload | 4.20 / 5.49 | 24.53 / 28.32 | 6.10 / 7.68 |
| Complete read command | 5.21 / 6.76 | 149.95 / 173.36 | 130.38 / 141.36 |
| Write workload | 8.57 / 11.03 | 66.29 / 75.05 | 67.25 / 85.03 |
| Complete write command | 9.67 / 12.38 | 195.74 / 206.49 | 195.97 / 221.41 |

Read work is now 1.45× direct execution. Write work is still 7.84× direct,
and its p95 is worse in this sample; there is no write-performance win here.
The earlier proposed ≤2× workload target is met for reads on this fixture
and remains unmet for writes. These are warm-cache microbenchmarks on one
shared host, not agent-task throughput or general latency guarantees.
Maximum sampled one-minute host load was 0.95 on four vCPUs.

The ten resource checks in the runner passed:

| Probe | Observation on | Observation off |
|---|---|---|
| Fill the 8 MiB volume | ENOSPC, zero free blocks, `storage.hit=true` | Same |
| Exhaust the 64 inode volume | ENOSPC, zero free inodes, `inodes.hit=true` | Same |
| Touch 96 MiB with `mem=64MiB, swap=0` | OOM cause, RAM hit, empty tree; exit 137 | OOM cause, RAM hit, empty tree; exit 1, exact child outcome unknown |

Three admission probes request ceilings below the actual byte or inode
capacity, including an oversized shared `/tmp` workspace (the raw label is
`unbounded`; that filesystem is actually bounded above the request). All
return 125 without executing the target marker. A fourth probe verifies
`/dev/shm` refuses regular file creation with EROFS. A separate
[ext4 workspace probe](results/2026-10-01/observation-limits/disk-refusal.json)
also returns 125 before target execution because the writable filesystem is
not a bounded tmpfs. Thus 11 resource checks passed in total.

The OOM probes do **not** establish a swap-hit counter increment:
`swap.applied=true`, but `swap.hit=false` in both receipts. The kernel accepted
and read back the zero swap ceiling; RAM's OOM evidence and verified tree
death establish the allocation outcome. Storage/inode hit fields remain
null when no saturation was sampled. No negative hit claim is inferred
from a missing sample.

## Validation and evidence

- Local workspace tests: 1,075 passed, zero failed, seven ignored. The 65
  affected portable policy/receipt/freeze tests also pass after the final
  receipt-schema update.
- The serial Linux workspace run with `OURO_CONFORMANCE=1` reports 1,807
  passes, one fixture failure and 16 ignored tests. The failure was the alias
  test placing its own executable on a read-only mount. After binding it
  into the fixture's private `/tmp`, that test passes in a focused rerun
  (one pass, one ignored private helper). No runtime code changed after the
  workspace run. All seven limit types are exercised together in a live
  receipt test, with observation both on and off.
- Strict workspace/all-target Clippy passes on Linux and macOS. Formatting,
  whitespace, all three document-contract validators and documentation links
  pass. The final doctor reports the swap probe available.
- The generated freeze's source pins are updated and its stale tested-run
  section is removed. **`cargo xtask freeze --check` remains red:** a clean
  committed build and its formal conformance record are still required.
  Neither a successful microbenchmark nor the binary's schema-level `frozen`
  flag certifies that release gate.

[Raw runs](results/2026-10-01/observation-limits/runs.json),
[medians](results/2026-10-01/observation-limits/performance.json),
[build and harness hashes](results/2026-10-01/observation-limits/metadata.json),
[completion record](results/2026-10-01/observation-limits/complete.json),
[doctor](results/2026-10-01/observation-limits/doctor-final.json),
[Linux workspace log](results/2026-10-01/observation-limits/final-tests-v2.log),
[corrected fixture rerun](results/2026-10-01/observation-limits/alias-final.log)
and [Clippy](results/2026-10-01/observation-limits/clippy-final.log) are retained
with the per-run receipts and the executed harness. The private tmpfs was
unmounted after measurement; source, binaries and results remain outside it.

## Reproduction

Provide an isolated, operator-owned tmpfs mounted with `size=8m,nr_inodes=64`
and writable by the benchmark identity. The runner uses only its `ws` and
`scratch` subdirectories for resource probes. Keep the before/after binaries
and a new results directory outside that volume. Place `workload.c` beside
the runner, then run without concurrent builds or suites on the host:

```sh
python3 observe_limits.py \
  --root /tmp/ouro-measurement-new \
  --volume /path/to/private-bounded-tmpfs \
  --before /path/to/previous/ouro-jail \
  --after /path/to/current/ouro-jail
```

The runner checks that neither binary changes during measurement and saves
the exact harness, fixture, binary hashes, build provenance, commands,
stdout/stderr, receipts and raw timings. Remove the private test mount after
the run; retain the results outside it.
