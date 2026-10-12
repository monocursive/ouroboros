# Ouro versus Greywall, OpenShell and MXC: measured position

Analysis date: 2026-10-12. Measurements: 2026-10-11, before and after the Linux
file-denial/startup patch. This analysis covers the tested versions and
configurations: Ouro 0.1.0 development source, Greywall 0.3.7/Greyproxy 0.4.5,
OpenShell 0.1.3 and MXC 1.0.0. It does not describe every backend or newer release.

Ouro's clearest measured advantages are Linux execution evidence, explicit
resource-limit refusal, and substantially lower launch latency than Greywall.
MXC is usually faster; OpenShell offers a working retained container workflow
and online Mac execution that Ouro did not demonstrate. Linux client
compatibility is strong, but it is largely shared by the competitors.

The [before report](competitors/README.md) and
[after report](competitors-after/2026-10-11/README.md) retain raw results,
methods, exclusions, hashes, exact binaries and archives. Those finalized
directories have not been rewritten for this analysis. Statements in their
reports about an uncommitted patch or no push describe the measurement snapshot.

## Performance

Native per-command no-op launch medians, milliseconds; 30 valid repetitions per
cell. Direct execution is the control. Ouro runs with strict observation enabled.

| Host | Direct | MXC | Ouro before, paired arm | Ouro after | Greywall after |
|---|---:|---:|---:|---:|---:|
| VPS, Linux x86_64 | 1.1 | 20.1 | 138.6 | 115.7 | 1659.6 |
| Pi, Linux ARM64 | 1.8 | 23.7 | 321.7 | 288.6 | 1795.5 |
| Mac, M2 Pro | 2.7 | 16.7 | unavailable | unavailable | unavailable |

The patch reduces the ratio of old/new Ouro no-op medians by **16.5% on the VPS**
and **10.3% on the Pi**. Interleaved pair differences support a real startup
improvement on these hosts: median changes -15.2ms, bootstrap 95% interval
[-27.4, -11.2], and -27.1ms [-45.0, -17.3], respectively. The median of paired
percentage reductions is 10.9%/8.5%; it is a different statistic. Historical
original medians of 170.9/310.4ms are retained separately and should not be used
to attribute the whole historical difference to this patch.

Against Greywall, Ouro's no-op takes **14.3 times less time on the VPS** and
**6.2 times less on the Pi**. Ouro has a lower median for all seven native
workloads: Greywall/Ouro median ratios range 6.2-14.3 on the VPS and 3.5-6.2 on
the Pi. These are launch-plus-work measurements for a per-command wrapper with
an already running proxy, not Greywall's entire installation or long-lived
agent startup. This is a substantial advantage when commands are short.

Against MXC, Ouro's no-op takes **5.8 times as long on the VPS** and **12.2 times
as long on the Pi**, approximately 96ms/265ms additional elapsed time. Ouro is
slower in all seven VPS workloads and six of seven Pi workloads. The remaining
Pi buffered-write median is 773.2ms for Ouro versus 923.3ms for MXC; it is too
variable to establish a storage advantage. Ouro's own paired Pi write median
worsened from 672.0 to 773.2ms, with paired-change interval [-38.0, 305.8]ms.
No write improvement is claimed. Git and CPU Pi p95 also worsen despite lower
medians. The workload does not fsync, and SD-card/cache behavior matters.

All 840 paired Ouro timing samples keep the same policy digests, strict
observation, enforced containment, attached ptrace/linux-closed-v1, declared
coverage, no gaps and empty-tree settlement. Every write sample records all
1,000 expected writes. Sharing a fresh namespace status probe removes duplicate
setup work; no persistent capability cache or observer bypass was added.

OpenShell has a different boundary and lifecycle, so its numbers belong in a
separate table. Fresh means create/execute/delete; retained means execute in an
already running sandbox. Each lane has a matched Docker control and 30 valid
repetitions per available cell.

| Host | Docker fresh | OpenShell fresh | Docker retained exec | OpenShell retained exec |
|---|---:|---:|---:|---:|
| VPS | 267.6ms | 913.3ms | 60.3ms | 69.2ms |
| Pi | 1033.5ms | unavailable | 156.5ms | unavailable |
| Mac | 216.7ms | 677.2ms | 27.5ms | 54.1ms |

Ouro's 115.7ms VPS per-command launch is faster than OpenShell's 913.3ms fresh
lifecycle but slower than its 69.2ms retained exec. Neither comparison is a
like-for-like security or lifecycle ranking. OpenShell's reusable environment
amortizes creation cost; Ouro's demonstrated lane starts and settles a process
tree for every invocation. A retained Ouro lane was not measured. Pi OpenShell
fails before payload execution, including three corrected warm-start checks;
it contributes availability failures rather than successful timings.

Evidence: [all workload medians/p95 and raw sources](competitors-after/2026-10-11/analysis/final/performance.csv),
[paired statistics and receipt checks](competitors-after/2026-10-11/analysis/paired/paired-startup.json),
[complete historical comparison](competitors-after/2026-10-11/analysis/comparison/performance-tables.md).

## Features and isolation

| Area | Where Ouro leads in this test | Where Ouro trails or remains unproven |
|---|---|---|
| Inspectable evidence | Strict receipts bind policy, executable, containment, observer coverage, process lifetime and durable attempt journals. All referenced journals are retained. | This is a stronger inspectable proof surface in the exercised lane, not proof that competitors cannot audit. Greywall's privileged eBPF, OpenShell OCSF/OTLP and platform-specific MXC audit options were not compared. |
| File denial | Fixed regular-file denial works under both RO/RW visible parents; content is unreadable, mutations fail, siblings work and original data remains unchanged. Greywall's tested parent denyWrite/child denyRead combination still re-exposes denied reads. | MXC's tested denied-path checks also work. Greywall's minimal-rule follow-up avoids its precedence issue, so this is a specific configuration defect, not a claim that every Greywall denial fails. OpenShell uses container path rules, a different boundary. |
| Resource ceilings | Explicit wall/PID/memory/swap/CPU limits have readbacks and refusal when required enforcement is unavailable. The VPS memory probe enforces its cap; Pi memory requests refuse instead of proceeding unbounded. | No automatic memory/CPU/storage/inode ceiling was added. Explicit storage/inode limits on the unbounded workspace refuse; this does not demonstrate a working quota there. OpenShell enforces requested CPU/memory through Docker on VPS/Mac. Greywall/MXC lack common memory/CPU/PID ceilings in these tested native interfaces. |
| Process lifetime | Ouro settles an empty tree after root exit on Linux and records it. The Mac MXC heartbeat persists after wrapper return under Seatbelt. | Linux Greywall and MXC also stop the heartbeat. MXC's Mac descendant remains subject to Seatbelt; persistence is not an observed escape. OpenShell deliberately separates retained sandbox lifetime from exec return. |
| Network | Tested host TCP/signals are denied; the offline tool policy also blocks the explicitly visible Unix socket that Greywall/MXC allow on Linux. | Host TCP/signals are also denied by the other native wrappers. A visible socket connection is not an ungranted-path escape. OpenShell's container egress restrictions work where provisioning succeeds. The desired IPC policy determines which behavior is appropriate. |
| Credentials and operator workflow | The exercised Ouro profiles support all three clients using private state and required provider destinations. | Ouro used environment/staged credentials here. Greywall exercised automatic proxy placeholders; OpenShell exercised provider handles, endpoint binding and bootstrap/refresh. Ouro's optional vault was not measured, so superiority in secret brokerage or operator UI is not established. |
| Platform and persistence | Linux x86_64 and ARM64 work, including the Pi where OpenShell fails startup. | Ouro has no tested native Mac/online Mac agent lane or Windows backend. MXC runs Claude/OpenCode natively on Mac; OpenShell runs all three via Docker/OrbStack. Ouro's offline Mac VM preview takes about 34 seconds and is not an online agent benchmark. Other documented competitor backends remain untested. |

These are provisioned benchmark hosts: VPS AppArmor namespace overrides and a
byte-identical bubblewrap copy, and the Pi's exact-kernel Unix diagnostics module,
predate the patch. Pi memory-controller/Landlock availability is absent. These
results should not be presented as untouched-distribution deployment proof.

Evidence: [measured feature follow-up](competitors-after/2026-10-11/feature-matrix.md),
[original audited feature matrix and versioned source notes](competitors/feature-matrix.md),
[doctor, journals and safety verification](competitors-after/2026-10-11/analysis/final/evidence-verification.json).

## Coding clients and reliability

Ouro passes **36/36 small tasks and 6/6 workflows** across Claude Code,
OpenCode and Codex on the VPS/Pi. The supplied tests, hidden checks, unchanged
test files and successful exit are all required. Strict observation remains
enabled. Fourteen Claude receipts retain baseline audit-only
`path_claim_unverified` diagnostics with `classes=[]`; they are not described as
wholly gap-free. OpenCode/Codex have no observer diagnostics, and declared
coverage-class statuses/gaps are unchanged in all 42 selected Ouro receipts.

| Product/lane | Linux small tasks | Linux workflows | Mac small tasks / workflows |
|---|---:|---:|---|
| Ouro native | 36/36 | 6/6 | unavailable |
| MXC native | 36/36 | 6/6 | 12/18 and 2/3; Codex CFPreferences failure |
| Greywall native | 36/36 | 5/6 | 0/18 and 0/3; tested Seatbelt syntax rejected |
| OpenShell fresh, VPS | 18/18 | 3/3 | 18/18 and 3/3 |
| OpenShell retained, VPS | 18/18 | 3/3 | 18/18 and 3/3 |
| OpenShell fresh, Pi | 0/18 | 0/3 | not applicable |

The corrected Pi retained-start lane cannot provision a sandbox, so it has no
coding calls. Docker controls pass on all hosts. Greywall's one Linux workflow
failure reaches the fixed Claude 15-turn cap despite passing tests/hidden
checks. The historical run had a corresponding MXC/VPS turn-cap failure that
does not repeat. These model-dependent differences do not demonstrate that
Ouro makes an agent better at coding. Agent elapsed times include provider
latency and variable model commands; pure launch timings above are more useful
for comparing sandbox overhead.

Evidence: [native coding](competitors-after/2026-10-11/analysis/final/native-agents.csv),
[container coding](competitors-after/2026-10-11/analysis/final/container-agents.csv),
[all workflows and retained failures](competitors-after/2026-10-11/analysis/comparison/workflow-tables.md),
[before/after observer diagnostics](competitors-after/2026-10-11/analysis/final/coding-observation-before-after.json).

## What to prioritize next

1. Reduce the remaining fresh-launch cost, especially ARM64, while retaining
   exact coverage and empty-tree proof. MXC's 20-24ms baseline is the useful
   overhead target; Ouro is still 96-265ms above it in the no-op lane.
2. Diagnose Pi buffered-write variance and the worsened Git/CPU tail latencies
   before claiming broad performance gains. Keep paired trials, failures and
   observed operation counts.
3. Exercise an online Mac VM workflow and a retained environment if these are
   product goals. OpenShell currently demonstrates both client coverage on Mac
   and a faster retained exec lane in this test.
4. Benchmark Ouro's vault/provider handling against Greywall substitution and
   OpenShell providers. The current evidence does not settle secret exposure,
   refresh reliability or operator effort.
5. Refresh pinned-host conformance and release freeze evidence before making a
   readiness claim. Linux release builds, Clippy, 564 unit tests per host and
   all 46 VPS review tests pass, but the broader Linux run retains documented
   host/provenance failures and no fresh release freeze has been issued.

The supported conclusion is a capable Linux jail with substantially improved
startup, a repaired file-denial path and unusually inspectable execution proof.
It is not yet the fastest native wrapper or the broadest cross-platform agent
environment in this comparison.
