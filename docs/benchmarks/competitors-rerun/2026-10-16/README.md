# Ukai, Greywall, OpenShell 0.1.4 and MXC benchmark rerun

Measured on the same supplied VPS, Raspberry Pi and Mac as the
[2026-10-11 comparison](../../competitors/README.md), on 2026-10-16. The
protocol, workloads, tasks, checkers and pass rules are that corpus'
([methods](../../competitors/METHODS.md), with this corpus'
[deltas](METHODS.md)): the jail runs as the renamed Ukai `ukai-jail`
0.1.0 from clean source `af2837946a523269eb5cef099d1af80f6da216de`, and
OpenShell moves to its 0.1.4 release. Greywall 0.3.7 / Greyproxy 0.4.5,
MXC 1.0.0 and the three clients are unchanged versions, so their arms
are comparable across the two corpora.

Headline:

- Ukai's fixed-workload cost dropped by roughly half on both Linux hosts
  since 2026-10-11 while every guarantee checked stayed on: VPS no-op
  median 91.9 ms (was 170.9 ms), Pi 232.0 ms (was 310.4 ms), with
  strict receipts, empty-tree settlement and no coverage gaps required
  of every counted sample. The direction matches the direct-cgroup
  bootstrap pilots recorded in `credentials/2026-10-13-next`; this is
  the first full seven-workload, three-client measurement of it.
- OpenShell 0.1.4 still fails sandbox startup on the Pi
  (`ControlSupervisorStartFailed`, supervisor `--version` executes
  standalone) — the 0.1.3 finding reproduces. Where it starts, 0.1.4 is
  faster to create (VPS ephemeral no-op median 869 ms vs 1024 ms; Mac
  598 ms vs 708 ms) and meets every containment probe 0.1.3 met:
  fresh/warm egress to the host canary blocked, memory ceiling killed
  at the limit, RO-workspace policy denied `/work` while Docker's
  positive control wrote it.
- The 2026-10-11 platform findings reproduce exactly: Mac Greywall
  exits 65 (Seatbelt kleene star), Mac MXC Codex fails during
  CFPreferences synchronization while its direct control passes, Mac
  MXC shows the system-Python/Git Seatbelt startup anomaly, and Pi
  Docker ignores its memory request (missing controller) while Ukai
  refuses the request and enforces what the host supports.
- Coding compatibility is a near-complete sweep: every small-task cell
  on the VPS and Pi is 6/6 across all arms including Greywall, all
  108 VPS+Mac container cells pass, and the only failures are the two
  known Mac platform defects plus one strict 15-turn-cap failure.

## Versions and hosts

| Item | Tested version / environment |
|---|---|
| Ukai Jail | `ukai-jail` 0.1.0, clean source `af2837946…`, frozen provenance, Rust 1.98.1 release build per Linux host |
| Greywall / Greyproxy | 0.3.7 / 0.4.5 (unchanged installs) |
| OpenShell | 0.1.4 side-by-side; per-host mTLS gateways `os14-vps`/`os14-pi`/`os14-mac`, docker driver, supervisor/sandbox runtime images 0.1.4; fixture image reused from 2026-10-11 |
| MXC | 1.0.0; bubblewrap on Linux, Seatbelt on Mac (unchanged installs) |
| Clients | Claude Code 2.1.295; OpenCode 1.19.0; Codex 0.159.2 (unchanged) |
| Models | Claude/OpenCode: claude-sonnet-4-5; Codex: gpt-6.1-sol, low reasoning effort |
| VPS | Ubuntu 26.04.1, kernel 7.0.0-31, x86_64, four EPYC vCPUs; the natural-expiry soak ran throughout at idle CPU |
| Pi | Debian 13, kernel 6.18.50+rpt-rpi-v8, ARM64; no memory controller/Landlock |
| Mac | macOS 27.0.1, M2 Pro; Docker Desktop socket as recorded |

## Fixed local work

Median full-command wall time in milliseconds; 30 measured samples per
bucket after three discarded warmups, shuffled with seed 20261016,
validated against the same-host direct control (operation count and
checksum; Ukai additionally receipt/coverage-checked):

| Host | Native direct | MXC | Ukai observed | Greywall |
|---|---:|---:|---:|---:|
| vps | 1.0 | 19.5 | 91.9 | 1585.9 |
| pi | 1.8 | 23.6 | 232.0 | 1790.7 |
| mac | 2.6 | 16.7 | unsupported | unavailable |

Container lifecycle (no-op medians, ms; full tables in
[analysis/performance-tables.md](analysis/performance-tables.md)):

| Host | Docker fresh | Docker warm | OpenShell fresh | OpenShell warm |
|---|---:|---:|---:|---:|
| vps | 255.5 | 59.8 | 869.2 | 67.0 |
| pi | 993.2 | 151.1 | unavailable | unavailable |
| mac | 222.6 | 28.4 | 597.8 | 54.3 |

Pi writes-workload variance is SD-card contention shared by every arm
including the uncontained control (direct writes median 879 ms, p95
3458 ms), as in the prior corpus. Observation-off Ukai stays a
diagnostic: unconfirmed for noop/reads-class launches on both Linux
hosts, counted nowhere.

## Coding compatibility

Small tasks: three tasks × two repetitions per client/arm, shuffled
order, fresh repositories, unchanged supplied tests, independent hidden
checks; pass requires exit 0, no timeout and all checks. Workflow: one
inventory-CLI run per client/arm.

| Host / client | Direct | Ukai | MXC | Greywall | Docker | OpenShell fresh | OpenShell warm |
|---|---:|---:|---:|---:|---:|---:|---:|
| vps / claude | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |
| vps / opencode | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |
| vps / codex | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 |
| pi / claude | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | unavailable | unavailable |
| pi / opencode | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | unavailable | unavailable |
| pi / codex | 6/6 | 6/6 | 6/6 | 6/6 | 6/6 | unavailable | unavailable |
| mac / claude | 6/6 | unsupported | 6/6 | 0/6 | 6/6 | 6/6 | 6/6 |
| mac / opencode | 6/6 | unsupported | 6/6 | 0/6 | 6/6 | 6/6 | 6/6 |
| mac / codex | 6/6 | unsupported | 0/6 | 0/6 | 6/6 | 6/6 | 6/6 |

Workflow results:

| Host / class | Failures |
|---|---|
| vps native (12 runs) | 1/12: claude/mxc hit the shared 15-turn cap with exit 1 after its patch passed all visible tests and hidden checks — a strict failure, as classified in 2026-10-11 |
| vps container (9) | none |
| pi native (12) / container (3) | none |
| mac native (9) | 3/9 Greywall (exit 65, syntax) and codex/mxc (CFPreferences) |
| mac container (9) | none |

Median wall-clock per successful small run (client+wrapper included) is
in [analysis/coding-tables.md](analysis/coding-tables.md); n=6 and
network variability prevent productivity rankings, as before. Ukai's
medians sit between MXC and Greywall on every host (for example VPS
claude: direct 21.5 s, mxc 21.4 s, ukai 24.0 s, greywall 34.5 s).

## Limits and canaries

- Ukai on the VPS enforces wall 1 s (SIGTERM), memory 64 MiB (SIGKILL),
  PIDs (13 forks then EAGAIN under the delegated cgroup, unchanged from
  2026-10-11) and refuses storage/inode ceilings on the unbounded
  workspace; CPU completes under the 25 % ceiling. On the Pi it
  enforces wall/PIDs/CPU and refuses memory without the controller.
- MXC enforces its 1,000 ms process timeout on all three hosts and
  exposes no shared memory/CPU/PID ceilings. Greywall exposes none.
- Container memory: on the Mac both Docker (137) and OpenShell 0.1.4
  (137) kill the 320 MiB allocation at the 128 MiB ceiling; unbounded
  controls complete. On the Pi Docker warns and ignores the request.
- Filesystem policy: OpenShell 0.1.4 with the RO-workspace policy
  denies the `/work` write (EPERM) and allows `/tmp`; plain Docker's
  positive control writes both. Egress: plain Docker reaches the host
  canary on all three hosts; OpenShell fresh and warm sandboxes block
  it on the VPS and Mac, matching 0.1.3.
- Safety canaries (private-dir read/write, symlink, hardlink, host
  TCP/unix-socket/signal) reran with the native suites; Ukai and MXC
  deny the private canaries on Linux, Greywall's denyRead+denyWrite
  interaction is unchanged and its minimal-configuration variant is
  preserved in the raw `summary.json` of each native lane.

## Deployment notes

- VPS `kernel.apparmor_restrict_unprivileged_userns` was at the
  restored stock value 1; the native suite and the coding cohort each
  ran with it set to 0 — the 2026-10-11 setting — and it was restored
  to 1 afterwards (`raw/vps/vps-userns-*.txt`,
  `raw/vps/vps-agents-userns-*.txt`). All arms of a cohort share one
  setting; nothing else on the host changed.
- A stale greyproxy from the completed `bench-ouro-startup` corpus was
  found owning the 4305x ports before the clean coding runs; it was
  stopped and is recorded in [the exclusions](#excluded-attempts).
- OpenShell 0.1.4's new requirements were satisfied without weakening
  anything: launch-scoped sandbox authentication (gateway-minted JWT),
  `guest_tls_ca`, and the trusted `supervisor:0.1.4`/`sandbox:0.1.4`
  runtime images pulled from the vendor registry.
- Codex credentials on the VPS and Pi were re-staged from the
  still-valid authorized Mac cache (read-only copies; the original
  grant, the same one the natural-expiry soak watches, expires
  2026-10-23 09:22:33 UTC). Expiry was recorded through the provider
  update before any timed work.

## Excluded attempts

Retained under `raw/` with their `-failed`/`-partial` suffixes, never
pooled:

- VPS `v5-*-userns1-failed`, `stale-v5-*-rerun`: the first battery
  launched after the perf script had restored the userns restriction,
  and against the stale startup-corpus greyproxy whose MITM CA the
  clients rightly rejected. All three batches were rerun clean.
- Pi `v5-opencode-rerun-symlink-failed`: the first Pi `bin/` used
  per-binary symlinks; `opencode` resolves through a second symlink
  outside the granted roots, so wrapper arms saw ENOENT. Rerun with
  real copied binaries.
- Mac `os14-smoke` (9/9 passed): retained setup verification, excluded
  from scored buckets per the prior corpus' convention.
- The VPS claude/mxc workflow turn-cap failure is scored as a failure,
  not excluded.

## Evidence

Raw results are under `raw/<host>/`; generated tables and the selected
dataset with per-file SHA-256 under `analysis/`
([selected-results.json](analysis/selected-results.json)). Runs retain
prompts, stdout/stderr, patches, resulting files, checker verdicts,
redacted wrapper configs, proxy/gateway health records and receipts.
Bulk raw evidence beyond the ~66 MB retained here (full host exports,
host snapshots, journals) is packaged separately as a release asset;
see `bundle.json`. The natural-expiry soak, the credential-corpus
gateway and all prior corpora on the hosts were left untouched.
