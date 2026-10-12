# Ouroboros Jail vs Greywall vs NVIDIA OpenShell vs Microsoft MXC — 2026-10-11

Performance, safety and feature benchmark of four AI-agent sandboxing products on
three machines, plus a coding-agent task battery (OpenCode, Claude Code, Codex)
run under each wrapper where supported.

**Products and versions**

| Product | Version | Kind |
|---|---|---|
| Ouroboros Jail | built from `c364e3cb` (= release 0.1.0-rc.1 inputs + the docker-nsfs mountinfo fix), release profile, frozen | per-command namespace wrapper |
| Greywall | 0.3.7 (+ Greyproxy 0.4.5) | per-command wrapper + proxy |
| NVIDIA OpenShell | 0.1.3 (deb install, Docker 29.1.3 driver) | gateway + container sandbox |
| Microsoft MXC | 1.0.0 (npm `@microsoft/mxc-sdk` executors: `lxc-exec`, `mxc-exec-mac`) | SDK/executor, bubblewrap + seatbelt backends |
| ouro-vm | 0.1.0-preview.1 (signed DMG) | disposable Linux VM on Apple Silicon |

**Hosts**

| Host | Hardware/OS | Lanes |
|---|---|---|
| VPS `vps-450b3fe8` | Ubuntu 26.04.1, kernel 7.0.0-31, x86_64, 4× EPYC-Milan vCPU, 3.7 GiB, bubblewrap 0.11.1 | full wrapper suite + OpenShell container lane + agent battery |
| Raspberry Pi | Debian 13 (trixie), kernel 6.18.50+rpt-rpi-v8, aarch64, 4 cores, 3.7 GiB | wrapper suite + opencode battery |
| Mac `muetdhiver2` | macOS 27.0.1 (26A434), Apple M2 Pro, 10 CPU, 16 GiB | wrapper suite (mxc seatbelt, greywall-mac, ouro-vm) + codex battery |

Ouro-jail on the VPS initially refused to run after Docker was installed
(`relative mountinfo path` on Docker's nsfs mount at `/run/docker/netns/default`);
the tested build includes the fix (`f7fbf552`, released after 0.1.0-rc.1).
Both Linux hosts run the same pinned build — see `metadata.json` digests in each
result directory.

## Method

- **Wrapper suite** (`harness/suite.py`, adapted from the 2026-09-30 method):
  seven fixed workloads (no-op, Python startup, `git status`, 1,000 reads,
  1,000 writes, 100 child spawns, 20M integer ops), 3 discarded warmups, 30
  measured rounds, interleaved with seed 20261011. Every sample retains argv,
  stdout, stderr, exit, wall time, in-child work time and host load. Successful
  work must match the direct control's count and checksum; write outputs are
  also checked host-side. A wrapper×workload pair that cannot complete
  successfully (e.g. `ouro --observe off` cannot confirm very short execs) is
  recorded unavailable for that pair, never counted as fast.
- **Safety probes**: private read/write, read-only write, symlink read/write,
  hardlink read, host TCP, host Unix socket, host signal, detached descendant
  after wrapper exit, and ten Linux syscall reachability diagnostics.
- **OpenShell container lane** (`harness/openshell_lane.py`): same seven
  workloads baked into an `ubuntu:24.04` image; lanes are plain `docker run`
  (container baseline), `sandbox create --no-keep` per command (full lifecycle)
  and `sandbox exec` into one retained sandbox (warm). Container writes are
  validated by in-container completion records. Egress probe: container → host
  canary via the docker bridge.
- **ouro-vm lane** (`harness/ouro_vm_lane.py`): POSIX-shell workloads in the
  disposable offline Linux VM, validated from returned workspace files.
- **Agent battery** (`harness/agentbench.py`): three fixed tasks (add function +
  tests, fix off-by-one bug, yaml→json refactor) in fresh git repos, identical
  prompts and model (`claude-sonnet-4-5` for Claude Code/OpenCode; Codex on its
  ChatGPT login), objective checker (unit tests + required content), wrappers:
  direct / ouro-jail (`agent` profile + launch profile + `--allow-host`) /
  greywall (deny-by-default fs + greyproxy allowlist + `--inject` credentials) /
  MXC (bubblewrap with resolved-IP egress allowlist on Linux; seatbelt on macOS).
  The Anthropic key is held in a 0600 file on each host and never written to
  results.

Raw records: `results/2026-10-11/{vps,pi,mac}/…` (launches.ndjson, summary.json,
receipts, tables, logs). Reproduction scripts: `harness/`.

## Performance — wrapper suite, VPS x86_64

Wall-time **median ms** (p95 in `results/2026-10-11/vps/vps-perf2-table.txt`):

| Workload | Direct | MXC | Ouro obs-on | Ouro obs-off | Greywall |
|---|---:|---:|---:|---:|---:|
| No-op | 1.0 | 19.5 | 129 | unavailable¹ | 1589 |
| Python | 38.6 | 68.1 | 176 | 180 | 1637 |
| Git status | 41.3 | 68.3 | 172 | 185 | 1639 |
| 1,000 reads | 5.6 | 20.3 | 139 | unavailable¹ | 1596 |
| 1,000 writes | 64.8 | 118.3 | 274 | 216 | 1656 |
| 100 children | 73.0 | 118.0 | 246 | 213 | 1664 |
| Integer compute | 25.6 | 68.2 | 155 | 163 | 1605 |

¹ `--observe off` cannot confirm execution of sub-100 ms commands
(`exec_unconfirmed`, exit 1) — a current product limitation, recorded not
hidden.

**In-child work time** (the part that does not amortize): Ouro observation-on
adds +57 % on spawns (114.5 vs 72.0 ms) and +116 % on writes (137.2 vs 63.5 ms);
observation-off is ≈ direct (71.7 vs 63.5 ms writes). MXC and Greywall add no
work-phase cost. Startup: MXC ≈ +18 ms; Ouro ≈ +128 ms; Greywall ≈ +1.6 s
(constant; TUN/socat setup on every launch).

## Performance — Raspberry Pi aarch64

| Workload | Direct | MXC | Ouro obs-on | Ouro obs-off | Greywall |
|---|---:|---:|---:|---:|---:|
| No-op | 1.8 | 23.6 | 309 | unavailable | 1806 |
| Python | 137.5 | 172.0 | 443 | 439 | 1936 |
| Git status | 145.7 | 172.0 | 458 | 447 | 1935 |
| 1,000 reads | 12.7 | 39.7 | 325 | 321 | 1805 |
| 1,000 writes | 877.6 | 923.2 | 598² | 1193² | 2676 |
| 100 children | 133.3 | 172.1 | 507 | 445 | 1922 |
| Integer compute | 82.2 | 121.8 | 389 | 395 | 1868 |

² The Pi's workspace sits on its SD card; the jail's private mount makes the
same writes land on a faster backing store (874–876 ms in-jail work vs 876 ms
direct on SD, 238 ms work observed-on inside the namespace). This is a
backing-store artifact, not a CPU speedup.

## Performance — Mac arm64

| Workload | Direct | MXC (seatbelt) | Greywall | Ouro native |
|---|---:|---:|---|---|
| No-op | 2.5 | 16.7 | ✗ broken³ | refused (exit 125) |
| Python | 34.1 | 1769 | ✗ | — |
| Git status | 44.6 | 3443 | ✗ | — |
| 1,000 reads | 22.1 | 58.0 | ✗ | — |
| 1,000 writes | 47.5 | 100.2 | ✗ | — |
| 100 children | 145.7 | 202.6 | ✗ | — |
| Integer compute | 21.1 | 58.6 | ✗ | — |

³ Greywall 0.3.7's macOS build fails every run with
`sandbox-exec: unsupported syntax: kleene star` (reproduced 2026-10-11 on
macOS 27.0.1; identical to the 2026-09-30 record). MXC seatbelt shows extreme
work-phase costs for Python (52× direct) and git status (77×) while file I/O
cases stay near-native.

**ouro-vm (VM class, same Mac)**: every attempt boots a fresh offline Linux VM —
median 34.4–34.5 s per attempt (noop/writes/reads/spawn shells), i.e. ~34 s
fixed cost per disposable command; guest work itself is shell-speed.

## Performance — OpenShell container lane (VPS)

| Workload | docker run | create --no-keep (ephemeral) | exec (warm sandbox) |
|---|---:|---:|---:|
| No-op | 272 | 915 | 68 |
| Python | 287 | 894 | 114 |
| Git status | 333 | 935 | 123 |
| 1,000 reads | 271 | 925 | 102 |
| 1,000 writes | 371 | 989 | 181 |
| 100 children | 329 | 888 | 148 |
| Integer compute | 279 | 888 | 97 |

Warm `sandbox exec` is cheaper than a raw `docker run` of the same image (the
sandbox stays up); each ephemeral create+run+delete costs ~0.9 s. This is a
different isolation class (container/VM), listed separately by design.

## Safety — bounded probes

VPS wrapper suite (identical outcomes on the Pi for the same arms):

| Probe | Ouro | Greywall | MXC |
|---|---|---|---|
| Private read / write | Denied | Denied | Denied |
| Read-only write | Denied | Denied | Denied |
| Symlink read/write, hardlink read | Denied | Denied | Denied |
| Host TCP | Denied | Denied | Denied |
| **Host Unix socket** | **Denied** | **Denied** | **Allowed** |
| Host signal (SIGUSR1 to canary) | Denied | Denied | Denied |
| Detached descendant after wrapper exit | Stopped | Stopped | Stopped |
| Syscall reachability | 10/10 denied (9 EPERM + clone3 ENOSYS) | ptrace/mount/bpf/keyctl denied; **nested `unshare(CLONE_NEWUSER)` succeeds** | **no syscall filtering** (returns match direct) |

OpenShell lane egress probe: a plain `docker run` container reaches a host
canary through the docker bridge (1/1); OpenShell sandboxes (ephemeral and warm)
do not (0 accepts) — the default policy blocks container→host egress.

Mac: MXC seatbelt denied all nine boundary probes, but **detached descendants
survived** wrapper exit (heartbeat still growing after 300 ms), matching the
prior 2026-09-30 observation for Anthropic's SRT on macOS.

## Agent battery

Three fixed tasks (add function + tests, fix off-by-one bug, yaml→json refactor)
in fresh git repos; identical prompts; model pinned to `claude-sonnet-4-5`
(Codex on its existing ChatGPT login); objective checker = unit tests + required
content. 2 runs per task per lane.

**Success rate and median wall time**

| Host | Agent | Direct | Ouro (`agent` + launch profile) | Greywall | MXC | OpenShell |
|---|---|---|---|---|---|---|
| VPS x86_64 | Claude Code 2.1.295 | 6/6 · 20.6 s | **6/6 · 19.3 s** | 0/6¹ | 0/6² | — |
| VPS x86_64 | OpenCode 1.19.0 | 6/6 · 34.1 s | **6/6 · 28.8 s** | 0/6¹ | 0/6² | **6/6 · 26.9 s** |
| Pi arm64 | OpenCode 1.19.0 | 6/6 · 47.7 s | **6/6 · 49.4 s (+3.5 %)** | 0/6¹ | **6/6 · 53.5 s (+12 %)** | — |
| Mac arm64 | Codex 0.159.2 | 6/6 · 28.2 s | refused³ | — | 0/6⁴ | — |

¹ Greywall on unprivileged Linux has **no working network path**: TUN setup
needs CAP_NET_ADMIN; the fallback to proxy env vars is ignored by
bun-based agents, and even plain `curl` inside the sandbox cannot resolve DNS
(reproduced with a live greyproxy; agents retry for ~2–3 min then fail).
² MXC on Ubuntu 26.04 first refuses (unprivileged userns restricted by
AppArmor; needs `sysctl kernel.apparmor_restrict_unprivileged_userns=0`), and
after enabling it DNS stays broken: the host runs systemd-resolved
(127.0.0.53 stub) which is unreachable inside the bubblewrap netns, and MXC
v1 provides no resolver rewrite (curl repro: `Could not resolve host`). The
Pi (Debian, externally-reachable resolver) passes 6/6 with the same config —
so the lane is host-resolver-dependent, not workload-dependent.
³ Native macOS execution refused (exit 125) by design; the ouro-vm preview has
no network adapter, so online agents cannot run in it.
⁴ Codex's startup fails under the MXC seatbelt backend
(`failed to synchronize managed preferences`, CFPreferences/Mach IPC); neither
`extraMachLookups` grants nor disabling Codex's own sandbox nor a staged
writable CODEX_HOME resolves it.

**OpenShell agent lane**: OpenCode 1.19.0 inside a container sandbox under a
policy allowing only `api.anthropic.com` (plus Landlock grants for the agent
tree), ephemeral `--no-keep` per task: **6/6 tasks pass, median 26.9 s** —
parity with the direct lane. Two operational notes from bringing the lane up:
OpenShell warns that a key passed with `--env` is readable by the agent (their
documented hardening is a provider instead), and a non-TTY canonical process
must redirect stdin or `opencode run` blocks on it forever.

**Headline**: with fully contained, observed, receipted runs — including
credential confinement (the key enters via the launch profile, never the
inherited environment) and destination-granted networking — Ouroboros completes
12/12 agent tasks on the VPS at direct-mode speed (medians 19.3 s vs 20.6 s and
28.8 s vs 34.1 s; differences are within run-to-run noise) and 6/6 on the Pi at
+3.5 %. MXC passes only where the host resolver is reachable from its netns
(Pi: 6/6 at +12 %). Greywall's agent lanes could not reach the network at all
on these unprivileged hosts. Every ouro agent run produced a settled receipt
with zero coverage gaps (validated in `agent-runs.ndjson` rows).
- **Only Ouroboros** offers required-and-verified resource ceilings (wall, pids,
  memory+swap, cpu, storage/inodes). Greywall has none by design; OpenShell has
  container cpu/memory only; MXC has timeout only (plus WSLC sizing).
- **Only OpenShell** formally verifies policy changes (SMT prover) and offers
  fleet/K8s deployment, GPU allocation and OCSF audit export.
- **Hostname-level network policy with credential vaulting** exists in Ouro
  (origin-binding bridge, vault placeholders), Greywall (greyproxy rules +
  MITM substitution) and OpenShell (providers + approved endpoints). **MXC v1
  has no hostname rules at all** (CIDR/ports only) — agent API access required
  caller-resolved IP allowlists on Linux and was impossible to scope on macOS
  (seatbelt rejects destination rules; the Mac codex lane ran with egress
  default-allow).
- **Audit receipts with explicit coverage gaps** are unique to Ouro
  (`jail.json` + `trace.ndjson`, strict evidence). Greywall audits at the proxy
  (dashboard/REST + LLM conversation tracking); MXC emits local JSON-line audit
  records; OpenShell exports OCSF.
- **Learning**: Ouro `learn` (evidence-derived RO paths + denied destinations),
  Greywall `--learning` (strace/eslogger profiles), OpenShell advisor +
  auto-approval gated by the prover, MXC Windows-only audit mode.

## Host changes made during the benchmark

- VPS: installed `docker.io` (29.1.3), OpenShell 0.1.3 deb + user gateway,
  `slirp4netns`; set `kernel.apparmor_restrict_unprivileged_userns=0` (needed
  for MXC's network-enabled bubblewrap mode on Ubuntu 26.04; left set — restore
  with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1` if
  desired). Docker's nsfs mount additionally required the post-rc.1 ouro
  mountinfo fix (noted above).
- Pi: installed `socat`, `slirp4netns`, `iptables`; greyproxy 0.4.5 binary.
- Mac: installed `ouro-vm` 0.1.0-preview.1, greywall 0.3.7, `mxc-exec-mac`.
- The Anthropic key lives in `~/bench-ouro/anthropic.key` (mode 0600) on the
  VPS and Pi; it is not present in any result file.

## Reproduce

```sh
# per host (see harness/ for the exact scripts used):
python3 harness/suite.py --root R --out OUT --samples 30 --warmup 3          # wrapper suite
python3 harness/openshell_lane.py --root R --out OUT --samples 10 --warmup 1 # OpenShell lane (needs gateway+docker)
python3 harness/ouro_vm_lane.py --root R --out OUT --samples 3              # ouro-vm (Apple Silicon)
python3 harness/agentbench.py --root R --out OUT --agents … --modes …       # agent battery
python3 harness/summarize.py OUT                                            # recompute medians from raw
```

Installations are pinned by SHA-256 in each run's `metadata.json`
(`hashes`) — greywall 0.3.7 tarballs verified against the release
`checksums.txt`, MXC 1.0.0 from the npm tarball, OpenShell 0.1.3 deb with the
gateway version confirmed over its API, ouro built from the pinned commit.
