# Ouro file denial and startup: before/after benchmark

The regular-file denial bug is fixed on Linux x86_64 and ARM64. Startup work now
shares one fresh namespace probe sandbox per measurement call. The paired no-op
medians fell from 138.6 to 115.7ms on the VPS and 321.7 to 288.6ms on the Pi:
16.5% and 10.3% reductions in the ratio of medians. This keeps strict observation,
the original policies, containment, receipts, journals and empty-tree settlement.
Pi writes remain noisy with a worse after median; no improvement is claimed there.

The [original comparison](../../competitors/README.md), its selected results and
archive are unchanged. This rerun retains 198 native small-task invocations,
144 container small-task invocations, 57 workflows and
4620 valid scored timing samples across 154 buckets.
The extra old-Ouro arm contributes 420 samples; it controls for host/time drift.
Setup pilots, excluded observation-off diagnostics and unavailable launches remain
in the [complete audit](analysis/all-datasets-audit.json). The unchanged Mac VM
preview contributes 12 additional diagnostic samples, separate from scored lanes.

## Implementation and file-denial proof

The old implementation mounted a directory tmpfs over every denied path. A
regular file inside a visible parent caused bubblewrap setup to fail, exit 125.
The patch classifies denial targets and overlays files with empty descriptor data,
mode 000 and a read-only bind, after every grant. Directory masks remain sealed
tmpfs mounts; ancestor denials subsume nested masks. No denied source contents
are read or altered. Missing descriptors and setup errors refuse execution.
The live regression checks read-only and writable parents, readable siblings,
direct and symlink reads, writes, truncation, chmod, unchanged original content,
the actual read-only mount receipt and an empty process tree.

Both hosts reproduce before exit 125 and after exit 0/FILE-DENIAL-PASS, with the
original canary unchanged. Raw probe evidence: [VPS](results/vps/file-denial/),
[Pi](results/pi/file-denial/). The VPS receipt records four denied write-open
events and no coverage gaps; this count does not imply coverage of every read or
chmod operation. The observer's declared closed set is unchanged.

User, PID and network namespace capability probes previously spawned separate
sandboxes to consume the same status report. They now share one fresh sandbox
inside a call while each validator retains its checks and timeout/error behavior.
There is no persistent capability cache. Boundary readbacks, observer attachment,
filter verification, mount pinning, cgroups, leases, journals and settlement remain.
[Source patch](source.patch) and [file hashes](source-files.json) bind this result
to the four uncommitted source files, based on c364e3cb3678eb9120901f71bf3881d85e3c4911.
The backend's descriptor mount mechanism is documented in
[bubblewrap's manual](https://github.com/containers/bubblewrap/blob/v0.11.0/bwrap.xml).

## Paired Ouro measurements

Each host/workload has 30 interleaved old/new pairs after three discarded warmups,
with the original operation counts, checksums, fixtures and seed. Policies match
by digest. All 840 old/new samples have strict observation on, enforced containment,
observed exec, attached ptrace/linux-closed-v1, unchanged coverage statuses, no
gaps and empty-tree settlement. Every writes sample observes all 1,000 writes.
The descriptive bootstrap interval resamples round-pair changes 10,000 times;
it is not a claim about every machine or a multiple-comparison-adjusted result.

| Host | Work | Before median / p95 (ms) | After median / p95 (ms) | Paired median change, 95% interval (ms) |
|---|---|---:|---:|---:|
| vps | noop | 138.6 / 154.8 | 115.7 / 134.9 | -15.2 [-27.4, -11.2] |
| vps | python | 177.2 / 200.6 | 156.9 / 180.6 | -15.9 [-25.2, -11.3] |
| vps | git | 191.1 / 207.1 | 168.1 / 189.6 | -21.6 [-30.4, -15.9] |
| vps | reads | 143.5 / 159.3 | 125.9 / 147.3 | -17.9 [-23.9, -13.8] |
| vps | writes | 288.1 / 334.2 | 276.6 / 297.8 | -22.6 [-30.9, -8.1] |
| vps | spawn | 259.4 / 296.6 | 239.1 / 266.5 | -19.6 [-30.1, -11.4] |
| vps | cpu | 162.1 / 184.9 | 146.2 / 158.7 | -15.7 [-20.0, -10.6] |
| pi | noop | 321.7 / 372.6 | 288.6 / 369.0 | -27.1 [-45.0, -17.3] |
| pi | python | 457.6 / 566.7 | 421.1 / 543.0 | -38.2 [-48.3, -26.2] |
| pi | git | 462.1 / 492.1 | 429.2 / 544.2 | -29.2 [-38.5, -20.3] |
| pi | reads | 328.0 / 404.7 | 291.9 / 353.3 | -34.3 [-50.5, -25.8] |
| pi | writes | 672.0 / 1247.6 | 773.2 / 1317.3 | -3.2 [-38.0, 305.8] |
| pi | spawn | 516.3 / 662.3 | 481.9 / 582.2 | -38.5 [-46.4, -20.5] |
| pi | cpu | 396.0 / 416.1 | 363.1 / 429.7 | -29.8 [-47.2, -23.7] |

The median paired ratios give no-op reductions 10.9% VPS and 8.5% Pi; these differ
from the ratios of separate medians above. Pi writes: 672.0 -> 773.2ms median,
paired median change -3.2ms with interval [-38.0,305.8]. This is inconclusive.
Some Pi p95 values also worsen despite lower medians. No sample was rerun or
dropped to improve these results. [CSV](analysis/paired/paired-startup.csv),
[JSON and receipt validation](analysis/paired/paired-startup.json).

## Same competitor and coding lanes

Client versions, models, task prompts/checks, policy roles, deadlines and product
versions match the [original methods](../../competitors/METHODS.md). Models remain
Claude Sonnet 4.5 for Claude/OpenCode and gpt-6.1-sol with low reasoning for Codex.
The coding profiles use writable workspaces, private client state, read-only
installations and default-deny egress with required provider destinations.
No additional login was needed. Secrets stay on the hosts and are excluded or
redacted from public evidence. Competitor sources and host restrictions were
not changed. Exact host, executable and image provenance accompany each export.

Historical-before -> after native no-op median (ms), separate from the paired
source attribution above:

| Host | Direct | MXC | Ouro observed | Greywall |
|---|---|---|---|---|
| vps | 1.1 -> 1.1 | 21.0 -> 20.1 | 170.9 -> 115.7 | 1684.2 -> 1659.6 |
| pi | 1.8 -> 1.8 | 23.7 -> 23.7 | 310.4 -> 288.6 | 1793.9 -> 1795.5 |
| mac | 2.8 -> 2.7 | 16.7 -> 16.7 | unavailable | unavailable |

Each small-task cell is three tasks twice, with fresh repositories/state and
independent checks. Agent elapsed times include provider/model latency, so they
measure compatibility rather than isolated sandbox startup. Native wrappers and
container lifecycles remain separate classes. Each Docker/OpenShell pair uses
the same image, clients, UID and recorder; new image tags retain the earlier
references. The recorder also captures CSV source files omitted by an earlier
artifact recorder, without changing prompts or checks.

| Host / client | Direct | Ouro | MXC | Greywall | OpenShell fresh | OpenShell warm |
|---|---|---|---|---|---|---|
| vps / claude | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |
| vps / opencode | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |
| vps / codex | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |
| pi / claude | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 0/6 -> 0/6 | unavailable |
| pi / opencode | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 0/6 -> 0/6 | unavailable |
| pi / codex | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 6/6 -> 6/6 | 0/6 -> 0/6 | unavailable |
| mac / claude | 6/6 -> 6/6 | unavailable | 6/6 -> 6/6 | 0/6 -> 0/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |
| mac / opencode | 6/6 -> 6/6 | unavailable | 6/6 -> 6/6 | 0/6 -> 0/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |
| mac / codex | 6/6 -> 6/6 | unavailable | 0/6 -> 0/6 | 0/6 -> 0/6 | 6/6 -> 6/6 | 6/6 -> 6/6 |

All Ouro small-task and workflow invocations on Linux pass their supplied and
hidden checks with strict observation and no declared coverage-class gaps. Fourteen
Claude receipts retain pre-existing audit-only path_claim_unverified diagnostics
(classes=[]); before receipts have the same diagnostic type. Counts vary with
the model's commands. These receipts are not described as wholly gap-free.
OpenCode/Codex have no observer diagnostics. The detailed comparison is in
[coding observation before/after](analysis/final/coding-observation-before-after.json).
Mac native Ouro remains unavailable;
the unchanged offline VM preview is not evidence for this Linux patch. Greywall
Mac syntax refusal and MXC Mac Codex CFPreferences failure remain visible. Pi
OpenShell startup availability is tested afresh and reported separately; a failed
startup never becomes a successful timing. Docker is its positive control.

Workflows preserve the 15-turn Claude limit and require exit 0 even if a patch
passes tests. All failures are in [workflow-failures.json](analysis/comparison/workflow-failures.json)
and the [full before/after workflow table](analysis/comparison/workflow-tables.md).
All seven workloads for every available product/class are in the
[performance tables](analysis/comparison/performance-tables.md),
[before/after CSVs](analysis/comparison/) and [selected raw-source index](analysis/final/selected-results.json).
The original [full feature matrix](../../competitors/feature-matrix.md) is retained;
its file-denial failure is superseded by this patch and the [feature follow-up](feature-matrix.md).

## Validation and limits

Rust 1.98.1 release builds and Linux Clippy pass on both architectures. Each Linux
unit suite passes 564 tests with 2 ignored. All 46 VPS review_linux tests pass;
the new live file regression passes on both hosts. Local portable units pass 267
with 1 ignored, and local Clippy passes. Actual before/after doctor capability
statuses match on both Linux hosts. The full VPS Linux test run retains these
environment/provenance failures: two pinned AppArmor/host status assertions;
the nested-user-namespace expectation for the pinned host; and two stale saved
preview-evidence checks. The earlier unscoped cgroup assertion also fails with
the old binary and passes in the repository-standard systemd user scope. No
assertion, freeze record or restriction was relaxed to hide a failure.

These are provisioned benchmark machines, as documented originally. The VPS's
AppArmor namespace override and byte-identical bubblewrap copy predate this
follow-up. The Pi still lacks memory-controller/Landlock availability and uses
the previously provisioned exact-kernel Unix diagnostics module. Native agent
passes are not a security certification, full pinned-host conformance or release
readiness. Fresh release freeze/provenance evidence has not been issued.

The Mac duplicate-provider import failed before any task. Linux pilot client
symlinks traversed an ungranted intermediate benchmark directory and produced
ENOENT. Direct-to-install links restore the original layout without changing
bytes or widening grants. All modes/tasks/repetitions for affected clients were
rerun in new directories; individual valid failures were not retried. Exact
selections and hashes are recorded, and every pilot remains. A missing Mac
extra-probe script and a missing VPS gateway link failed before execution; the
unchanged script/binary were linked or copied before continuing. Pi warm
availability pilot names exceeded the 19-character limit; corrected checks use
short names after the measured phase. The VPS Codex image hit ENOSPC before
any task: omitting a redundant chmod copy-up layer preserves verified input
permissions and bytes while avoiding duplication. Failed builder artifacts remain.

Export manifests verify 7034 files and retain
1462 referenced Ouro journals, with none missing.
All 42 selected native Ouro coding/workflow receipts have been checked. Own
completed build caches were removed only after binary equality checks, with
cleanup manifests. The VPS completed source checkout was backed up locally and
all 7,893 files verified before reclaiming it during the remaining agent phase.
The VPS follow-up proxy store was compressed and hash-verified
before removing its plaintext copy; the credential-bearing archive stays private
on that host. Temporary gateways/proxies are stopped. Evidence is sanitized;
credentials, private homes/state, proxy databases and CA private keys are excluded.
The original private stores and logins remain on the hosts for reuse.

## Reuse

Use [METHODS.md](METHODS.md) and [harness](harness/) to rerun the same protocol.
[Exact tested executables](binaries/README.md) retain old and patched Ouro for
both Linux architectures, with hashes matched to the doctor reports.
[Host export archives](archives/) preserve raw results, source snapshots, logs,
patches, receipts, journal coverage and executable/image hashes. [Final bundle](benchmark-after-2026-10-11.tar.gz) and
[SHA256SUMS](SHA256SUMS) cover this whole follow-up. Pair it with the unchanged original
benchmark archive for historical before results. No commit or push was made.
