# Jail v1 backend and observer evaluation (J0 report)

Status: **not started.** Skeleton checked in 2026-09-22 so the report has a
fixed shape. Every value below is `not_started` except the manual host manifest
in §1, collected 2026-09-22. Nothing else here is a measurement,
a selection, or evidence that any candidate passes any gate. A value becomes a
claim only when the host manifest and the raw fixture output it cites exist in
this directory. Shape and gates: [jail-v1.md §5](../jail-v1.md#5-backend-and-observer-feasibility-gate),
§16 J0, and north star D8.

## 1. Reference host manifest

Produced by `doctor --json` on the operator-provisioned x86_64 VPS
([§3.2](../jail-v1.md#32-initial-support-matrix)).

| Field | Value |
|---|---|
| Virtualization (must be a VM with its own kernel; container-based hosts are ineligible) | kvm (`systemd-detect-virt`), 4 vCPU, 3.7 GiB RAM, 8 GiB swap file; manual 2026-09-22 |
| Kernel release and build | `7.0.0-31-generic` `#31-Ubuntu SMP PREEMPT_DYNAMIC Sat Aug  1 04:26:38 UTC 2026` after the operator applied pending updates and rebooted on 2026-09-22 (the pre-reboot manifest showed 7.0.0-28); BTF present; `CONFIG_BPF_SYSCALL=y CONFIG_BPF_JIT=y CONFIG_DEBUG_INFO_BTF=y`; manual 2026-09-22 |
| Distribution and package versions: bubblewrap, selected backend, hashes | Ubuntu 26.04.1 LTS, systemd 259 (259.5-0ubuntu3.4); bubblewrap 0.11.1 (manual 2026-09-22, post-reboot); selected backend and hashes not_started |
| cgroup v2 delegation from the operator session; controllers pids, memory, cpu | cgroup2fs; `user@1001.service` for the `ouro-ci` conformance account present with `cpu memory pids` in controllers and subtree_control; account has no sudo, lingering on, `CapEff` 0 (manual 2026-09-22, [evidence/reference-host-2026-09-22-ouro-ci.txt](evidence/reference-host-2026-09-22-ouro-ci.txt)) |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 (manual 2026-09-22); `unshare -U true` from a login shell succeeds |
| `kernel.unprivileged_bpf_disabled` | 2 (manual 2026-09-22) |
| `kernel.perf_event_paranoid` | 4 (manual 2026-09-22; Ubuntu's extra level, no `perf_event_open` without CAP_PERFMON) |
| `kernel.yama.ptrace_scope` | 1 (manual 2026-09-22); `kernel.io_uring_disabled` 0 |
| Kernel options | `SECURITY_LANDLOCK`, `SECCOMP_FILTER`, `USER_NS`, `SECURITY_APPARMOR`, `CGROUPS`, `BPF_LSM` all `y` (manual 2026-09-22, [evidence](evidence/bwrap-nesting-probe-2026-09-22-ouro-ci.txt)) |
| Operator-installed AppArmor profile: name, executables granted `userns` | none installed; AppArmor enabled with Ubuntu's `bwrap-userns-restrict`, `unprivileged_userns`, `lxc-usernsexec` files and `bwrap`, `unpriv_bwrap` loaded; the legacy `ouroboros-sandbox-fleet` profile was removed 2026-09-22 (manual) |
| Tracing capability provisioning: mechanism (ambient via unit / file caps) and set | not_started; login shell `CapEff` is 0 (manual 2026-09-22) |
| Raw `doctor --json` output location | not_started; manual collection by [host-manifest.sh](host-manifest.sh): [evidence/reference-host-2026-09-22.txt](evidence/reference-host-2026-09-22.txt) as the administrator account and [evidence/reference-host-2026-09-22-ouro-ci.txt](evidence/reference-host-2026-09-22-ouro-ci.txt) as `ouro-ci`, the account conformance runs under |

### 1.1 Unprivileged bubblewrap on the reference host

Measured 2026-09-22 as `ouro-ci`, no operator change to AppArmor or sysctls
([evidence](evidence/bwrap-probe-2026-09-22-ouro-ci.txt)). This is a
functionality probe of the mechanism the D9 lane builds on, not a §15 gate.

| Check | Result |
|---|---|
| bubblewrap 0.11.1 starts with `--unshare-all` | pass; the sandboxed process runs under Ubuntu's stacked profile `bwrap//&unpriv_bwrap (enforce)` |
| `--ro-bind` holds: a write under `/usr` fails with EROFS and leaves nothing | pass |
| tmpfs write, PID namespace, `NoNewPrivs=1`, `CapEff=0` inside | pass |
| `--unshare-net` blocks a connect | pass (ENETUNREACH) |
| A nested user namespace inside the sandbox | pass (`unshare -U true` exits 0) |
| seccomp | none installed unless a filter is passed (`Seccomp: 0`); loading one through `--seccomp` works (`Seccomp: 2`, `NoNewPrivs: 1`) |
| A nested user or mount namespace inside the sandbox (`unshare -Urm`) | fail, EPERM: every child runs under the stacked `bwrap//&unpriv_bwrap` profile, and `unpriv_bwrap` carries `audit deny capability`, so a process inside has no capabilities even in a new user namespace ([evidence](evidence/bwrap-nesting-probe-2026-09-22-ouro-ci.txt), profile text included) |
| bubblewrap inside bubblewrap, which sandbox-runtime and Greywall both do | fail: the inner bubblewrap cannot create its namespaces |
| Not measured | pathname-socket isolation (§10) and what the distribution profile denies beyond capabilities |

Consequence for D9 on this host: one containment layer, which is all `tool`
and `build` need, works under the distribution profile with no operator
change. The `agent` profile's nesting requirement (§4.6, §9.2) does not. It
needs the operator-installed scoped AppArmor profile D9 names, giving the
jail's launcher a profile without the capability denial, or the host-wide
sysctl change that sandbox-runtime's README recommends; both are host policy
the specification leaves to the operator. Which one, and its exact text, is
the next enforcement measurement. Until it passes S03, `agent` refuses on
this host, as §4.6 requires.

On the legacy tree's Ubuntu 24.04 hosted runners the apt bubblewrap could not
apply its mounts without a sysctl change; on this 26.04.1 host it can, under
the distribution's own profile. J0 reruns this probe whenever that profile,
bubblewrap or the kernel changes.

## 2. Observer privilege model (measured first)

| Measurement | Result | Evidence |
|---|---|---|
| Smallest capability set that attaches the eBPF candidate | not_started | |
| Attach points and kernel/configuration dependencies | not_started | |
| Descendant tracking across fork, exec, PID namespace; PID reuse | not_started | |
| Event loss accounting under the §11.4 bounds | not_started | |
| Child cannot reacquire tracing privileges (X06) | not_started | |
| Interference: AppArmor userns restriction, `perf_event_paranoid`, `unprivileged_bpf_disabled`; operator resolution | not_started | |
| Result: `attaches` or `blocked` | not_started | |

### 2.1 Fallback candidates (only if the eBPF candidate is blocked)

| Candidate | Closed-set coverage (§11.2) | Overhead | Known limits observed | Result |
|---|---|---|---|---|
| ptrace tracer with `SECCOMP_RET_TRACE` narrowing | not_started | not_started | not_started | not_started |
| `fanotify` (filesystem classes only; cannot alone satisfy the set) | not_started | not_started | not_started | not_started |

## 3. Enforcement candidates

| Candidate | Pinned revision | License | Binary/package hashes | Transitive executables and runtime dependencies |
|---|---|---|---|---|
| sandbox-runtime (`srt`) | tag `v0.0.77` = `6fa731368807419ee157f9a3fac955fefe1019c6` (released 2026-09-18); `main` head `ddbeb74711c4097014ef3056791efa83f553116c` on 2026-09-21 ([evidence](evidence/candidates-2026-09-22.txt)) | Apache-2.0 | not_started; npm package `@anthropic-ai/sandbox-runtime` 0.0.77, hashes recorded at install | TypeScript on Node `>=20.11.0`; four direct npm dependencies (`@pondwader/socks5-server`, `commander`, `node-forge`, `zod`) plus a `vendor/` directory; transitive set not_started |
| Greywall | tag `v0.3.7` = `5581056d0523bfa244d8061008744ed9f72a0361` (released 2026-06-01); `main` head `60ab1b5bfd41c1683220435a85fc116dc29fd04f` on 2026-08-13 ([evidence](evidence/candidates-2026-09-22.txt)) | Apache-2.0 | not_started; goreleaser binaries, hashes recorded at install | Go module, Linux and macOS per its description; transitive set not_started |
| Legacy sandbox | `f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82` (fixtures and code to inspect, not an oracle) | n/a | n/a | n/a |

Per-candidate results for §5.1 criteria 1–8: pass, fail or unsupported, each
with fixture evidence.

| Criterion | `srt` | Greywall | Legacy sandbox |
|---|---|---|---|
| 1 Closed filesystem view, protected paths, network mediation, seccomp | not_started | not_started | not_started |
| 2 Literal argv and paths, including spaces, quotes, newlines, non-UTF-8 | not_started | not_started | not_started |
| 3 Real prepared gate, visible process identity, reliable exec failure | not_started | not_started | not_started |
| 4 Outside supervisor, observable descendants, nested sandbox behavior | not_started | not_started | not_started |
| 5 Deadline, signal, parent-death, verified tree termination | not_started | not_started | not_started |
| 6 Required limits, fd closure, environment and credential isolation | not_started | not_started | not_started |
| 7 Dependency footprint, startup, memory, integration size, license, maintenance | not_started | not_started | not_started |
| 8 Reusable macOS mechanisms without dictating shared policy | not_started | not_started | not_started |
| Unix-socket host-peer isolation mechanism (S03, N05) | not_started | not_started | not_started |

### 3.1 Documented mechanisms at the pinned tags

Documentation, not measurement ([mechanisms](evidence/candidates-mechanisms-2026-09-22.txt),
[user-namespace notes](evidence/candidates-userns-notes-2026-09-22.txt)).
It informs criteria 4 and 7; a criterion passes only with fixture evidence.

- **sandbox-runtime**: Linux bubblewrap with user, network and PID namespaces;
  HTTP and SOCKS5 proxies on the host reached over Unix sockets bridged by
  `socat`; seccomp only to block Unix sockets (x86_64 and aarch64); optional
  experimental TLS termination; Seatbelt on macOS; Windows alpha. Runtime
  needs Node 20.11 or later plus `socat`. Its documentation describes no
  resource limits and no receipt. Its answer to the Ubuntu 24.04+ restriction
  is the host-wide sysctl `kernel.apparmor_restrict_unprivileged_userns=0`.
  Its violation monitor reads seccomp and proxy events; it is not a syscall
  sensor in the D10 sense.
- **Greywall**: Go. Linux bubblewrap plus Landlock, seccomp BPF, `socat`
  bridges and a D-Bus proxy; Seatbelt on macOS. Network policy is delegated
  entirely to an external SOCKS5 proxy (GreyProxy) reached through a
  `tun2socks` TUN device, and Greywall downloads and installs that proxy from
  GitHub releases. Its eBPF "violation monitoring" is a generated `bpftrace`
  script started after the command, filtering `pid >= sandbox pid` on
  `sys_exit_*` tracepoints, needing CAP_BPF or root. That is the shape D10
  rules out as the sensor: it attaches after exec, does not track descendants
  and reports denials only. The extra proxy service and downloaded binaries
  count under criterion 7.

## 4. Performance (§5.2 budgets)

At least 30 launches each, observation on and off. Budgets: under 250 ms p95
added warm startup and under 20% median overhead on the fixed workload.
Exceeding one requires a recorded adjustment before backend freeze.

| Workload | Observe | Startup p95 added | Wall median overhead | Peak RSS | Event count | Losses |
|---|---|---|---|---|---|---|
| No-op command | on | not_started | not_started | not_started | not_started | not_started |
| No-op command | off | not_started | not_started | not_started | not_started | not_started |
| Descendant-heavy fixture | on | not_started | not_started | not_started | not_started | not_started |
| Descendant-heavy fixture | off | not_started | not_started | not_started | not_started | not_started |
| Fixed file-operation workload | on | not_started | not_started | not_started | not_started | not_started |
| Fixed file-operation workload | off | not_started | not_started | not_started | not_started | not_started |

## 5. Gap-to-gate table

| Gate (jail-v1 §15 ID) | Selected integration status | Gap | Plan |
|---|---|---|---|
| (empty until a candidate is measured) | | | |

## 6. Decision

Selected enforcement integration: none. Selected observer: none. Named
blockers: none recorded, because nothing has been measured. Raw fixture
locations: none.
