# Write observation and disk quotas — 2026-10-01

Write workload time falls from **77.41 to 74.61 ms (3.6% lower)** in the paired
60-round measurement. Whole-command latency changes little; ptrace remains
expensive for write-heavy work.

This follow-up reduces pathname work in the Linux write observer and adds
admission for disk-backed user hard quotas. It builds on the earlier
[read-observation and resource-limit work](observation-and-limits-2026-10-01.md).
The changes and evidence are from an uncommitted working tree, not a release
freeze or a new competitive benchmark.

## Write observation

The observer still pairs syscall entry and exit, rechecks pathname memory,
and corroborates successful opens against the kernel's descriptor path.
It now reads a short first pathname chunk, bounds reads to a page, compares
the captured bytes and terminating NUL without allocating another pathname,
and compares path components without allocating component vectors. Descriptor
path bytes are moved out of the OS string instead of copied.

These changes reduce copying and allocation. They do not remove write
events, entry/exit checks or coverage gaps. A focused regression checks empty,
short, long and page-boundary paths, a changed terminator, and unreadable memory.
The existing path-corroboration and concurrent-argument tests remain in the suite.

The initial perf sample showed substantial time in ptrace/wait scheduling.
Remote memory reads and descriptor-path reads were smaller contributors.
This optimization cannot remove the dominant scheduling cost of a synchronous
ptrace observer.

## Disk-backed quotas

The same `--limit storage=8MiB --limit inodes=64` options now accept
operator-provisioned ext4/XFS **user hard quotas**. Ouroboros reads the
caller's quota and verifies that both accounting and enforcement are active.
It never enables quotas, changes host limits or creates volumes itself.

Admission inspects every writable mount, counts each filesystem once, and
requires the sum of hard budgets to fit the requested ceilings. Workspace,
scratch and extra writable grants all count. Existing files anywhere on the
filesystem charged to the same uid consume the same budget; this is not a
per-attempt reservation. A dedicated worker uid and volume provide a useful
operational boundary. See the [setup guide](../../guide.md#bound-ram-swap-and-writable-storage).

Every writable disk inode must belong to that uid. The ownership walk has a
shared 100000-entry budget, a depth limit and the preparation deadline. It
does not follow symlinks and exempts read-only submounts. New hard links are
denied with `EPERM` for storage-bounded runs, preventing a foreign-owned inode
from being imported from a read-only grant. Renames and ordinary file writes
remain available. These baseline seccomp denials precede ptrace, so the native
receipt declares that hard-link denials have no observer event.

Root identities, idmapped writable mounts, missing hard limits, soft limits
alone, disabled enforcement and XFS realtime layouts refuse. XFS realtime
blocks have separate accounting, so ordinary block quotas cannot establish
the requested ceiling there. Project quotas and automatic provisioning remain
unsupported. Kernel interfaces: [quota permissions and operations](https://github.com/torvalds/linux/blob/v6.19/fs/quota/quota.c),
[quota status ABI](https://github.com/torvalds/linux/blob/v6.19/include/uapi/linux/dqblk_xfs.h),
[XFS geometry](https://github.com/torvalds/linux/blob/v6.19/fs/xfs/libxfs/xfs_fs.h).

Enforcement works with observation on or off. The runtime rechecks the quota
while running and kills the tree if its hard limits change or enforcement
becomes unavailable. The final receipt carries `storage_enforcement_lost`
and the native reason. Saturation of an admitted volume establishes `hit=true`;
it does not establish that this attempt alone filled the aggregate capacity.
Otherwise `hit=null`
remains unknown, since a transient `EDQUOT` can occur between samples.

## Measurement and verification

The reference VPS is Ubuntu 26.04.1, Linux 7.0.0-31, four EPYC vCPUs and
bubblewrap 0.11.1. Commands execute as unprivileged `ouro-ci`. The operator
creates disposable loop filesystems solely for quota tests. Root filesystem
quota settings and host sysctls are unchanged.

The paired workload uses 1000 reads of 4 KiB and 1000 writes of 1 KiB, with
three warmup rounds, 60 measured rounds and a fixed shuffled order. Output counts, checksums and
file contents are checked; sandbox receipts must settle successfully, report
an empty tree and have no coverage gaps. Write runs must report at least 1000
write-family observations. These are warm-cache writes without fsync.

The baseline is the prior read-optimized binary, SHA-256
`17f08ce44da99a9f4e561290655d32e53a6eafbcec960d66dc2ed09c50f971ef`.
The final source-input digest is
`sha256:f5a3d1816d5ae070fc9af25c51075ab11ecf22fde57d80696f6a98c976150f94`.
The local and Linux builds agree on that digest. Measurements use an optimized
Linux binary built with Rust 1.98.1.
Its SHA-256 is `8b3d8356398b229614bc7227a6c44bd51c2bb69c5e429785d0e7aada04d55a0f`.

Milliseconds, **median / p95**, with nearest-rank p95:

| Work | Direct | Before | After |
|---|---:|---:|---:|
| Read workload | 4.54 / 6.16 | 6.73 / 8.47 | 6.90 / 9.36 |
| Complete read command | 5.83 / 7.66 | 148.52 / 165.31 | 147.48 / 166.93 |
| Write workload | 9.17 / 12.18 | 77.41 / 91.99 | 74.61 / 90.70 |
| Complete write command | 10.40 / 13.57 | 216.98 / 241.64 | 215.51 / 241.39 |

The median paired write-work ratio is 0.967 after/before, with a 95% percentile
bootstrap interval of **0.950–0.993** (10000 resamples of paired rounds, seed
20261001). That supports a small improvement on this fixture. The write CLI
interval is **0.961–1.033**, spanning no change. Read work's point estimate is
2.5% slower; its paired interval, **0.965–1.104**, also spans no change. The
sample does not establish a read regression or a whole-command speedup.
[Analysis script](analyze_write_quotas.py) and
[raw analysis](results/2026-10-01/write-quotas/performance/analysis.json) retain the method.

All **360 measured samples** and 18 warmups completed with valid outputs.
Write work remains **8.13× direct execution**, above the earlier ≤2× workload
target. Maximum sampled one-minute load was 1.78 on four vCPUs. The shared VPS
was slower overall than the earlier read-optimization run, so the comparison
uses the paired baseline here rather than mixing medians across runs.

The [quota runner](disk_quotas.py) uses a disposable loop mount and changes
only that volume's test-user quota. It checks byte/inode exhaustion, disabled
observation, hard links, aliases, ownership, read-only exceptions, insufficient
ceilings, soft-only quotas and quota changes during execution. It requires
root for fixture configuration; every jail command runs as the ordinary test user.

## Validation

- Local workspace: **1076 passed, 0 failed, 7 ignored**.
- Linux workspace, `OURO_CONFORMANCE=1`, one test thread, systemd user scope
  and the reference harness's system-only PATH: **1812 passed, 0 failed,
  16 ignored**. Both platforms pass Clippy with warnings denied.
- **41 disk quota checks passed:** 20 on ext4, 18 on XFS, plus refusal with
  XFS enforcement disabled, XFS realtime storage, and an idmapped ext4 bind.
  The ext4 cases also verify combined accounting across two filesystems.
- New live cases establish `EDQUOT` for bytes and inodes with observation on
  and off, foreign-owner refusal even through a second writable alias,
  writable-parent/read-only-child handling, and tree termination after quota
  changes with the reason recorded in the receipt.
- The benchmark's ten tmpfs, swap, refusal and `/dev/shm` regression probes
  passed. All **303 saved receipts** pass both schema and semantic validation.

An initial Linux suite invocation outside the required systemd scope failed
the existing cgroup-availability assertion in `s11_wall_expiry_separate_run`.
The final run uses the reference harness's scope and passes that check and the
entire suite. The idmapped fixture initially tried to create directories as
an unmapped root identity and failed during setup; provisioning through the
source mount fixed the fixture, and the intended runtime refusal passed.

`cargo xtask freeze` refreshes source pins, but `freeze --check` remains red
because no committed tested freeze is recorded. These measurements do not
replace that release gate. The disposable loop and tmpfs fixtures are removed
after validation; host quota policy is unchanged.

Raw evidence: [results directory](results/2026-10-01/write-quotas/).
