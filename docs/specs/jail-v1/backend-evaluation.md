# Jail v1 backend and observer evaluation (D8 record)

Status: **recorded 2026-09-25** (jail-v1 revision 19). Selected enforcement
integration: the native Rust adapter over unprivileged bubblewrap 0.11.1,
seccomp and cgroup v2 delegation that J1 to J4 implement. Selected observer:
the ptrace tracer in the supervisor, narrowed to the closed set
`linux-closed-v1` by a `SECCOMP_RET_TRACE` filter. `srt` 0.0.77 and Greywall
0.3.7 are disqualified by named failures, each backed by a fixture run on the
stock reference host ([evidence](evidence/d8-candidates-2026-09-24-ouro-ci.txt)).
eBPF is withdrawn from the v1 contract. §4 records the milestone performance
measurement and the operator's adjustment of the fixed-workload budget.

A value below is a claim only where the evidence it cites exists in this
directory. A criterion a candidate's named failure left unevaluated says so; it
is never read as a pass. Shape and gates:
[jail-v1.md §5](../jail-v1.md#5-backend-and-observer-feasibility-gate), §16 J0,
and north star D8. This document was the J0 report's skeleton from 2026-09-22;
its J0 measurements are kept below.

## 1. Reference host manifest

Since J5, `doctor --json` produces the host manifest, `ouro.jail.doctor/1`
([schema](jail-doctor.schema.json); a measured example from the reference host
is [examples/doctor-linux.json](examples/doctor-linux.json)). Every
conformance run records it as `doctor.json`, and the milestone freeze copies
its host object ([milestone-1-freeze.toml](milestone-1-freeze.toml)). The rows
below are the J0 manual collection, kept as the record the decision was taken
on, with the J5 values where they differ.

| Field | Value |
|---|---|
| Virtualization (must be a VM with its own kernel; container-based hosts are ineligible) | kvm (`systemd-detect-virt`), 4 vCPU, 3.7 GiB RAM, 8 GiB swap file; manual 2026-09-22; `doctor` records `virtualization`, `cpus_online` and `memory` since J5 |
| Kernel release and build | `7.0.0-31-generic` `#31-Ubuntu SMP PREEMPT_DYNAMIC Sat Aug  1 04:26:38 UTC 2026` after the operator applied pending updates and rebooted on 2026-09-22 (the pre-reboot manifest showed 7.0.0-28); BTF present; `CONFIG_BPF_SYSCALL=y CONFIG_BPF_JIT=y CONFIG_DEBUG_INFO_BTF=y`; manual 2026-09-22 |
| Distribution and package versions: bubblewrap, selected backend, hashes | Ubuntu 26.04.1 LTS, systemd 259 (259.5-0ubuntu3.4); bubblewrap 0.11.1 at `/usr/bin/bwrap`, SHA-256 `523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6` (`doctor --json`, 2026-09-24, [example](examples/doctor-linux.json)); the same path, hash and version in the milestone run ([doctor](evidence/j5-doctor-2026-09-25-ouro-ci.json)) and in `milestone-1-freeze.toml` `[tested]` |
| cgroup v2 delegation from the operator session; controllers pids, memory, cpu | cgroup2fs; `user@1001.service` for the `ouro-ci` conformance account present with `cpu memory pids` in controllers and subtree_control; account has no sudo, lingering on, `CapEff` 0 (manual 2026-09-22, [evidence/reference-host-2026-09-22-ouro-ci.txt](evidence/reference-host-2026-09-22-ouro-ci.txt)) |
| `kernel.apparmor_restrict_unprivileged_userns` | 1 (manual 2026-09-22); `unshare -U true` from a login shell succeeds |
| `kernel.unprivileged_bpf_disabled` | 2 (manual 2026-09-22) |
| `kernel.perf_event_paranoid` | 4 (manual 2026-09-22; Ubuntu's extra level, no `perf_event_open` without CAP_PERFMON) |
| `kernel.yama.ptrace_scope` | 1 (manual 2026-09-22); `kernel.io_uring_disabled` 0 |
| Kernel options | `SECURITY_LANDLOCK`, `SECCOMP_FILTER`, `USER_NS`, `SECURITY_APPARMOR`, `CGROUPS`, `BPF_LSM` all `y` (manual 2026-09-22, [evidence](evidence/bwrap-nesting-probe-2026-09-22-ouro-ci.txt)) |
| Operator-installed AppArmor profile: name, executables granted `userns` | none installed; AppArmor enabled with Ubuntu's `bwrap-userns-restrict`, `unprivileged_userns`, `lxc-usernsexec` files and `bwrap`, `unpriv_bwrap` loaded; the legacy `ouroboros-sandbox-fleet` profile was removed 2026-09-22 (manual) |
| Tracing capability provisioning | None. The ptrace observer needs no capability under the default `ptrace_scope=1` of Ubuntu, Debian, Fedora and Arch. The file-capability path J0 described for eBPF is withdrawn with eBPF (§2). Login shell `CapEff` is 0 (manual 2026-09-22); `doctor` reports the operator identity category, `unprivileged` for `ouro-ci` |
| Raw `doctor --json` output location | The milestone conformance run `20260925T065639Z-027de7d284b1`: [evidence/j5-doctor-2026-09-25-ouro-ci.json](evidence/j5-doctor-2026-09-25-ouro-ci.json), with the manual [host manifest](evidence/j5-host-manifest-2026-09-25-ouro-ci.txt) of the same run. Manual collections before `doctor` existed: [evidence/reference-host-2026-09-22.txt](evidence/reference-host-2026-09-22.txt) as the administrator account and [evidence/reference-host-2026-09-22-ouro-ci.txt](evidence/reference-host-2026-09-22-ouro-ci.txt) as `ouro-ci` |

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

Consequence for D9 on this host: one containment layer, which every
contained profile uses, works under the distribution profile with no operator
change. A user namespace nested inside it does not.

Decision 2026-09-22 (superseding the same day's sysctl decision): the jail
requires no host configuration, and this host stays stock so that conformance
proves it. `agent`'s nesting is therefore the unprivileged kind: an inner
Landlock domain works inside one bwrap layer (measured 2026-09-22 as
`ouro-ci`: `landlock_restrict_self` succeeded, a granted write succeeded, an
ungranted read was denied, `unshare -Urm` in the same layer was EPERM), and
inner seccomp filters stack on the outer ones
([evidence/landlock-nesting-probe-2026-09-22-ouro-ci.txt](evidence/landlock-nesting-probe-2026-09-22-ouro-ci.txt),
which also records Landlock ABI 8 accepting filesystem bits 0–15, network
bits 0–1 and scope bits 0–1 only: no pathname-socket control, which is why
N05 uses seccomp user-notification mediation). Nested user namespaces are an
optional capability that `doctor` measures; on this host they stay
unavailable and `agent` runs without them (jail-v1 §9.2, revision 9).
The restriction itself is specific to Ubuntu 24.04 and later; Debian 13,
Fedora and Arch ship usable unprivileged user namespaces by default. The
portable install story is therefore: `doctor` detects that nested namespaces
are unusable and names the one distribution-specific remediation; the tools
never apply it.

On the legacy tree's Ubuntu 24.04 hosted runners the apt bubblewrap could not
apply its mounts without a sysctl change; on this 26.04.1 host it can, under
the distribution's own profile. The probe is rerun whenever that profile,
bubblewrap or the kernel changes; since J5 the freeze file pins the
bubblewrap hash and version a conformance run tested.

## 2. Observer privilege model (measured first)

Order revised 2026-09-22 for portability: the ptrace tracer in §2.1 was
measured first because it needs no host provisioning on any mainstream
distribution. It passes the closed set, so it is the selected observer.

eBPF is **withdrawn from v1** (operator decision 2026-09-24, jail-v1 §5.2): its
attachment needs `CAP_BPF`, `CAP_PERFMON` and tracefs access provisioned on
the host, which the zero-host-configuration requirement excludes, and the
reference host could therefore never test it. It was never attached, so the
rows below are not measurements of it.

| Measurement | Result | Evidence |
|---|---|---|
| Smallest capability set that attaches the eBPF candidate | not evaluated: withdrawn (needs host provisioning) | |
| Attach points and kernel/configuration dependencies | not evaluated: withdrawn | |
| Descendant tracking across fork, exec, PID namespace; PID reuse | not evaluated for eBPF; for ptrace see O02 in the [acceptance map](acceptance-map.toml) | |
| Event loss accounting under the §11.4 bounds | not evaluated for eBPF; for ptrace see O03 | |
| Child cannot reacquire tracing privileges (X06) | not evaluated for eBPF; for the shipped jail see X06 | |
| Interference: AppArmor userns restriction, `perf_event_paranoid`, `unprivileged_bpf_disabled`; operator resolution | Unprovisioned attach is refused: as `ouro-ci`, bpftrace 0.25 fails reading `/sys/kernel/tracing/available_events` (permission denied), so tracefs access is part of the provisioning question, not only CAP_BPF/CAP_PERFMON. No operator resolution: v1 provisions nothing | [ptrace probe §1](evidence/ptrace-probe-2026-09-22-ouro-ci.txt) |
| Result: `attaches` or `blocked` | blocked without host provisioning; withdrawn | |

### 2.1 ptrace tracer (measured first, selected) and the fanotify supplement

| Candidate | Closed-set coverage (§11.2) | Overhead | Known limits observed | Result |
|---|---|---|---|---|
| ptrace tracer with `SECCOMP_RET_TRACE` narrowing (stand-in: strace 6.19 `-f --seccomp-bpf`) | Attaches as `ouro-ci` with zero provisioning under `ptrace_scope=1`, including through bubblewrap's user and PID namespaces and its `unpriv_bwrap` confinement; sees the target's `execve` (with the PATH-search ENOENTs), `openat` with `O_CREAT`, `renameat2`, `unlinkat`, and the exec of each descendant, each with its return value and host pid; 15,000 of 15,000 closed-set events on the file workload, no loss by construction | Medians of 5 runs, strace as an upper bound (it decodes and formats every event): no-op 0.00→0.01 s; 200 fork+exec 0.14→0.21 s (+50%); 5,000 create/rename/unlink 0.15→0.78 s (+420%). Without narrowing: 0.03, 0.44, 1.25 s | Two stops per traced call even when narrowed; setup helpers (bubblewrap's own calls) appear before the target and need tagging as helpers; PID reuse and thread-group exit semantics not exercised | **Selected.** The purpose-built tracer (branch `j0-tracer-spike`, [evidence](evidence/tracer-spike-2026-09-22-ouro-ci.txt)) reproduces the same events through bubblewrap with exactly two stops per closed-set call (30,220 stops for 15,109 events) and zero gaps, and costs what strace costs: +31% on fork+exec, +440% on the syscall-dense file workload. The cost is the kernel's ptrace stop, about 22 µs each on this virtual host, not decoding. The productized tracer (J1 to J4) is tested against O01–O06 through the [acceptance map](acceptance-map.toml); the budget is adjusted (§4) |
| `fanotify` (filesystem classes only; cannot alone satisfy the set) | not evaluated: the tracer covers the whole closed set | not evaluated | not evaluated | not needed |

## 3. Enforcement candidates

| Candidate | Pinned revision | License | Binary/package hashes | Transitive executables and runtime dependencies |
|---|---|---|---|---|
| sandbox-runtime (`srt`) | tag `v0.0.77` = `6fa731368807419ee157f9a3fac955fefe1019c6` (released 2026-09-18); `main` head `ddbeb74711c4097014ef3056791efa83f553116c` on 2026-09-21 ([evidence](evidence/candidates-2026-09-22.txt)) | Apache-2.0 | npm `@anthropic-ai/sandbox-runtime` 0.0.77, integrity `sha512-uOe6kkAbo91r5shXXBxZ1DKbOpWmnXkNDDujXrFJRaHSG7D7s8b7Yfsu0pGDkYFgKZ2ECtVCNisl6pCYcaMF7A==`; Node v24.21.0 `fd8e59d5…cb2d6` (publisher checksums; [evidence](evidence/d8-candidates-2026-09-24-ouro-ci.txt)) | Node `>=20.11.0`; four direct npm dependencies (`@pondwader/socks5-server`, `commander`, `node-forge`, `zod`) plus a `vendor/` directory with a prebuilt `apply-seccomp` helper; at run time `socat` and ripgrep (`rg`), neither installed on the stock host ("Sandbox dependencies not available: ripgrep (rg) not found, socat not installed") |
| Greywall | tag `v0.3.7` = `5581056d0523bfa244d8061008744ed9f72a0361` (released 2026-06-01); `main` head `60ab1b5bfd41c1683220435a85fc116dc29fd04f` on 2026-08-13 ([evidence](evidence/candidates-2026-09-22.txt)) | Apache-2.0 | release tarball `1a340a90…c5c7ff`, binary `9968afd2…e8f950` (release checksums; [evidence](evidence/d8-candidates-2026-09-24-ouro-ci.txt)) | Go binary; at run time `socat` (required, not installed on the stock host) and GreyProxy, an external proxy service `greywall setup` downloads; optional `xdg-dbus-proxy` and `secret-tool` |
| Legacy sandbox | `f3b2dbfd5a92aa28a8f72dfcb9f2214ebf22ec82` (fixtures and code to inspect, not an oracle) | n/a | n/a | an Elixir module of the legacy runtime: needs BEAM |

Each candidate was run on 2026-09-24 as `ouro-ci` on the stock host, with
nothing installed: every tool lived in `~/j5/d8` and was removed afterwards,
and the missing runtime packages were unpacked there from the Ubuntu archive
(`apt-get download`, `dpkg -x`) rather than installed. The fixture was a
trivial command, then what an agent sandbox does inside the jail (a nested
user namespace and a nested bubblewrap), then each candidate's own monitoring
of a denied write ([fixture runs](evidence/d8-candidates-2026-09-24-ouro-ci.txt)).

Named failures:

- **`srt` 0.0.77 cannot run `true` on the stock host.** With `socat` and
  ripgrep supplied, every command, `true` included, fails before it starts:
  `apply-seccomp: write /proc/self/setgroups (nested userns is
  capability-restricted; caller must provide CAP_SYS_ADMIN): Permission
  denied`. Its debug output shows the step: it wraps the command in bubblewrap
  and then applies its Unix-socket seccomp filter through a helper that needs
  a user namespace nested inside that layer, which the distribution's
  `unpriv_bwrap` profile denies (§1.1). Its documented answer is the host-wide
  sysctl `kernel.apparmor_restrict_unprivileged_userns=0`, which is host
  configuration.
- **Greywall 0.3.7 needs host setup, has no network path on the stock host,
  and observes nothing the jail could own.** It refuses to start without
  `socat`, and `greywall check` asks for `sudo apt install socat` and a
  downloaded GreyProxy. With `socat` supplied, a trivial command runs, but its
  network path cannot be built: `ioctl(TUNSETIFF): Operation not permitted`,
  `Cannot find device "tun0"`, and egress fails to resolve. Its monitor mode
  (`-m`) reported neither a file creation nor a write it denied itself, and
  its learning mode is strace-based and relaxes the sandbox (its own warning).
  It therefore offers no jail-owned observation (north star D10), which is
  the documented shape of its `bpftrace` monitor as well (§3.1).
- **The legacy sandbox is not a standalone candidate.** It is an Elixir
  module that runs inside the legacy BEAM runtime, and I01 requires the jail to
  pass with no BEAM installed. It was not run; jail-v1 §5.1 keeps it as a
  source of fixtures and code to inspect.

Per-candidate results for §5.1 criteria 1–8. "Not evaluated" names the failure
that made the criterion moot; it is not a pass. The selected integration's
column points at the gates that test it; its results are the acceptance
verdict of the milestone run ([J5 authority](j5-authority.md)).

| Criterion | `srt` 0.0.77 | Greywall 0.3.7 | Legacy sandbox | Selected: native bubblewrap adapter |
|---|---|---|---|---|
| 1 Closed filesystem view, protected paths, network mediation, seccomp | fail: its seccomp step cannot be applied on the stock host, so no command runs | fail for network mediation: its TUN path cannot be created and its proxy is an external service; the rest not evaluated | not evaluated: needs BEAM (I01) | F01–F04, S01–S04, N01–N05 |
| 2 Literal argv and paths, including spaces, quotes, newlines, non-UTF-8 | not evaluated: disqualified (cannot run `true`) | not evaluated: disqualified (host setup, no jail-owned observation) | not evaluated: needs BEAM | X01, P01 |
| 3 Real prepared gate, visible process identity, reliable exec failure | not evaluated: disqualified | not evaluated: disqualified | not evaluated: needs BEAM | X02–X04, I03 |
| 4 Outside supervisor, observable descendants, nested sandbox behavior | fail: its own nesting (seccomp helper in a nested user namespace) is denied | fail: its monitor reports neither a creation nor a denied write, so descendants are not observable by it; a nested bubblewrap inside it fails as it does inside the jail (the host denies nested user namespaces) | not evaluated: needs BEAM | S03, O01–O06, X06 |
| 5 Deadline, signal, parent-death, verified tree termination | not evaluated: disqualified | not evaluated: disqualified | not evaluated: needs BEAM | L01, L02, X07 |
| 6 Required limits, fd closure, environment and credential isolation | not evaluated: disqualified; its documentation describes no resource limits | not evaluated: disqualified | not evaluated: needs BEAM | L03, L04, X06, C01, C02 |
| 7 Dependency footprint, startup, memory, integration size, license, maintenance | fail on a stock host: Node, `socat` and ripgrep are required and absent; Apache-2.0 | fail on a stock host: `socat` and a downloaded proxy service; Apache-2.0 | fail: the BEAM runtime | bubblewrap only (a distribution package on `PATH`); startup and memory in §4 |
| 8 Reusable macOS mechanisms without dictating shared policy | not evaluated (Seatbelt, documentation only) | not evaluated (Seatbelt, documentation only) | not evaluated | none reused; native macOS execution is later work (jail-v1 §3.3) |
| Unix-socket host-peer isolation mechanism (S03, N05) | not evaluated: disqualified (its mechanism is a seccomp Unix-socket block) | not evaluated: disqualified | not evaluated | seccomp user-notification mediation of `connect` under `agent` (jail-v1 §10) |

### 3.1 Documented mechanisms at the pinned tags

Documentation, not measurement ([mechanisms](evidence/candidates-mechanisms-2026-09-22.txt),
[user-namespace notes](evidence/candidates-userns-notes-2026-09-22.txt)).
It informs criteria 4 and 7; the named failures above are the fixture evidence.

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

Why a native adapter rather than reuse (jail-v1 §5.1: "A thin native Rust
adapter over bubblewrap/seccomp is permitted only when a named failure or
measured integration cost justifies the missing mechanism"): both candidates
wrap the same bubblewrap the adapter drives, and each fails on the stock host
at a mechanism the jail must own (a nested namespace for its seccomp step; a
host-installed proxy and TUN device; an after-the-fact monitor instead of a
sensor in the supervisor). None offers a prepared gate, a receipt, resource
limits or an outside observer to reuse.

## 4. Performance (§5.2 budgets)

Measured 2026-09-25, 07:19 to 07:27 UTC, on the reference host as `ouro-ci`,
at the final milestone revision `027de7d2`, with the `ouro-jail` binary the
conformance run tested (SHA-256 `aa2d77aa…724677`), by
`cargo xtask perf run --launches 30 --warmup 1 --max-load 3.0 --revision 027de7d2…`
started from a plain SSH session (the harness re-runs itself under
`systemd-run --user --scope` for the scope session). Evidence:
[summary.md](evidence/perf-2026-09-25-ouro-ci/summary.md),
[parameters.json](evidence/perf-2026-09-25-ouro-ci/parameters.json),
[host.json](evidence/perf-2026-09-25-ouro-ci/host.json),
[passes.ndjson](evidence/perf-2026-09-25-ouro-ci/passes.ndjson), and the raw
records `launches.ndjson` (1,302 records, SHA-256 `5447d292…d99db1e1`),
stored compressed as `launches.ndjson.xz` beside them;
`cargo xtask perf summarize --dir` recomputes the summary. The 1-minute load
before the measured launches was 1.41 / 1.67 / 2.03 (minimum, median,
maximum) on 4 CPUs, under the run's 3.0 threshold. All 42 arms have 30 valid
launches and none excluded, so every cell has a verdict. An earlier run at
`4380241f` gave the same verdicts; it is superseded by this one.

Definitions (jail-v1 §5.2): startup runs from the launcher's reading before
`fork` to the target's first reading; work is the target's own workload phase;
teardown runs from the target's end to the launcher's reading after `wait4`;
post-start is work plus teardown; wall is startup plus post-start. Overhead is
the subject's median over direct execution's median, minus one. Workloads:
no-op, 200 fork+exec descendants, and the fixed file workload of 5,000
create/rename/unlink rounds (15,000 closed-set calls).

Budgets and the recorded adjustment (operator decision 2026-09-25; jail-v1
§5.2): the startup budget stays, under 250 ms p95 added warm startup; the
fixed-workload budget becomes a measured ceiling on the jail's own overhead,
`--observe off` against direct, of at most 50% median post-start; the work
phase and end-to-end wall are reported; observation cost is reported per
workload with no budget. As first written, the budget was under 20% median
overhead on the fixed workload. It is missed: `tool`'s own post-start overhead
is 39.5% (plain) and 40.3% (scope), about 20 points over, and its work phase
alone is 29.6% and 28.9% over direct.

### 4.1 The jail's own overhead: `tool`, `--observe off` against direct (budgeted)

Median / p95 where two values are given. Peak RSS is the supervisor's sampled
high-water mark (KiB). The no-op's percentages divide by a direct median of
about 0.2 ms and are not meaningful; its 30 `exec_unconfirmed` launches are
the observation-off limit of jail-v1 §6.4 (valid, flagged: the target's own
output proves it ran), which is also why its receipts carry 30 errors.

| Session | Workload | Valid (excl.) | Added startup ms | p95 added startup < 250 ms | Added teardown ms | Work overhead | Post-start overhead (≤ 50%) | Wall overhead (reported) | Peak RSS KiB |
|---|---|---|---|---|---|---|---|---|---|
| plain | no-op | 30 (0) | 109.2 / 122.1 | pass | 22.5 / 24.1 | n/a | n/a | n/a | 7464 / 7576 |
| plain | descendant-heavy | 30 (0) | 109.0 / 118.9 | pass | 18.9 / 24.0 | −0.8% | 12.4% | 75.1% | 7480 / 7612 |
| plain | fixed file workload | 30 (0) | 111.0 / 128.1 | pass | 19.4 / 24.2 | 29.6% | **39.5%** (pass) | 99.9% | 7486 / 7652 |
| scope | no-op | 30 (0) | 95.2 / 109.0 | pass | 22.6 / 23.5 | n/a | n/a | n/a | 7536 / 7664 |
| scope | descendant-heavy | 30 (0) | 90.6 / 101.3 | pass | 18.6 / 24.2 | −1.0% | 8.9% | 65.7% | 7482 / 7668 |
| scope | fixed file workload | 30 (0) | 91.5 / 109.1 | pass | 18.6 / 23.2 | 28.9% | **40.3%** (pass) | 90.7% | 7470 / 7616 |

With observation on (`tool`, against direct) the p95 added startup is 139.0,
128.1 and 132.3 ms (plain) and 123.9, 109.2 and 107.7 ms (scope) for the three
workloads, so the startup budget holds with the observer too; all 12 `tool`
cells are between 101 and 139 ms. The informational profiles against direct
with observation off, on the fixed workload: `agent` 42.0% (plain) and 42.5%
(scope) post-start, p95 added startup 164.0 and 128.5 ms; `none` 3.1% and
5.8% post-start, 68.7 and 50.2 ms. The supervisor's sampled peak RSS (median)
is 7,248 to 7,590 KiB for `tool` and `none` and 7,852 to 8,004 KiB for
`agent`, observation on or off; the target's own peak is 3,854 to 4,016 KiB in
every arm.

Attribution ([evidence](evidence/perf-2026-09-25-attribution-ouro-ci.txt)),
measured at revision `4380241f`, before the late fixes; it measures
bubblewrap and the distribution's AppArmor confinement, which those commits
did not change. On a quiet host, 15 interleaved launches per arm after a
warm-up, the fixed workload's work phase: direct 155.4 ms; bubblewrap alone
with the `tool` profile's namespaces and no seccomp filter, still under
Ubuntu's `bwrap-userns-restrict`/`unpriv_bwrap` AppArmor confinement, 185.0 ms
(+19.0%); `ouro-jail run --profile tool --observe off` 189.9 ms (+22.2%).
About 19 of the jail's 22 points are bubblewrap's containment as the stock
distribution confines it; the jail's filter and supervisor add about 3. The
experiment does not separate the user namespace, the mount namespace and
AppArmor from each other, and the harness reads higher under its own
workspace layout and sampling (+28.9% to +29.6% at `027de7d2`).

### 4.2 Observation cost: `--observe on` against off and against direct (reported)

Median overhead of observation, `--observe on` against `--observe off` of the
same profile (work phase / post-start), and `--observe on` against direct
(work phase), from the summary's "Observation cost", "`--observe on` against
direct" and informational tables. Event counts are exact in every launch: 402
`exec` results for the descendant-heavy workload and 15,000 `fs.write` results
for the fixed one; no observer or coverage gap, no incomplete trace and no
excluded launch in any arm.

| Session | Profile | Workload | On vs off: work | On vs off: post-start | On vs direct: work |
|---|---|---|---|---|---|
| plain | tool | descendant-heavy | 50.2% | 36.0% | 49.0% |
| plain | tool | fixed file workload | 310.9% | 283.5% | 432.6% |
| plain | agent | descendant-heavy | 48.5% | 34.9% | 47.3% |
| plain | agent | fixed file workload | 320.6% | 286.5% | 445.8% |
| plain | none | descendant-heavy | 75.0% | 66.5% | 75.6% |
| plain | none | fixed file workload | 389.3% | 375.6% | 389.1% |
| scope | tool | descendant-heavy | 50.4% | 39.9% | 48.9% |
| scope | tool | fixed file workload | 306.0% | 274.7% | 423.4% |
| scope | agent | descendant-heavy | 49.0% | 34.8% | 48.2% |
| scope | agent | fixed file workload | 302.1% | 265.3% | 417.3% |
| scope | none | descendant-heavy | 76.1% | 69.6% | 77.2% |
| scope | none | fixed file workload | 390.6% | 363.6% | 389.6% |

Reading: on the fixed workload the observer multiplies the work phase by
about five (179.5 ms direct against 955.9 ms observed under `tool`, plain
session), which is J0's two ptrace stops per closed-set call at this call
rate. The descendant-heavy workload (402 results) costs about 47% to 77% on
its work phase. No-op launches record two `exec` results and their overheads
divide by a near-zero work phase. The cost scales with the closed-set call
rate; a representative workload (a build or a test run) is later work.

### 4.3 Preliminary numbers from the ptrace stand-in (J0)

Five runs each as `ouro-ci`, medians, strace 6.19 as the tracer, `/usr/bin/time`
resolution 0.01 s ([evidence](evidence/ptrace-probe-2026-09-22-ouro-ci.txt)).
Not the §4 measurement: fewer launches, a stand-in tracer, no RSS.

| Workload | Untraced | strace, narrowed | Purpose-built tracer, narrowed | Purpose-built, every syscall |
|---|---|---|---|---|
| No-op command | 0.00 s | 0.01 s | 0.01 s | 0.02 s |
| 200 fork+exec descendants | 0.13–0.14 s | 0.21–0.22 s | 0.17 s | 0.40 s |
| 5,000 create/rename/unlink (15,000 closed-set calls) | 0.15 s | 0.78–0.84 s | 0.81 s | 1.17 s |

Two runs of the strace probe and the spike harness
([strace](evidence/ptrace-probe-2026-09-22-ouro-ci.txt),
[spike](evidence/tracer-spike-2026-09-22-ouro-ci.txt)); ranges show the two
runs. Reading: the purpose-built tracer costs what strace costs, so the price
is the two ptrace stops per traced call (a seccomp stop and an exit stop,
measured at 30,220 stops for 15,109 events), about 22 µs per stop on this
virtual host, not decoding. Narrowing halves the cost; nothing in user space
removes it. The file workload is a worst case at about 100,000 closed-set
calls per second; observation cost scales with that rate, which is why it is
reported per workload rather than budgeted.

## 5. Gap-to-gate table

The authoritative per-clause state is [acceptance-map.toml](acceptance-map.toml)
and the milestone run's verdict
([evidence/j5-gates-2026-09-25.txt](evidence/j5-gates-2026-09-25.txt), run
`20260925T065639Z-027de7d284b1`: every noncredential gate passes, seven with
recorded limits). The
gaps of the selected integration that the map records as limits, or that
depend on the host:

| Gate (jail-v1 §15 ID) | Selected integration status | Gap | Plan |
|---|---|---|---|
| L02 | Supervisor death during bubblewrap's startup is closed by the outside watcher where the attempt has an execution leaf | bubblewrap 0.11.1 clears an inherited `PR_SET_PDEATHSIG` before arming its own; without an execution leaf (no lingering) a supervisor killed in that window can leave the namespace init, and under `agent` its bridge, alive (measured first in the J1 review: about 2 in 20 tries) | Named limit (jail-v1 §9.3); lingering or a delegated user scope closes it |
| S03 | A Landlock and seccomp inner sandbox works inside `agent` | A namespace inner sandbox needs a nested user namespace, which the stock host denies | Named limit; the permissive filter variant is unit-tested only |
| X05 | EOF reaches the caller as in direct execution under `none` | Under the contained profiles bubblewrap's outer process and namespace init hold the stdio they hand the target until the jail exits | Named limit (jail-v1 §8.3) |
| L03 | The required and preferred branches are proved on a real leaf through the library | A leaf without the pids controller cannot be produced through `run` without reconfiguring the account's shared user-manager tree | Named limit ([J5 authority](j5-authority.md), Known gaps) |
| L04 | The execution wall and the preparation and gate budgets run on `CLOCK_BOOTTIME` | A real suspend or clock step cannot be produced by the unprivileged account | Simulated on a real run with an `LD_PRELOAD` clock shim; the kernel's suspend path is not exercised |
| O02, C03 | Birth identity on every live result | PID reuse needs `CAP_SYS_ADMIN` in the pid namespace | Simulated by a unit-level hook (jail-v1 §11.3) |
| all | Linux x86_64 on the reference host | Every syscall table is x86_64's | Other architectures compile and refuse before preparation (jail-v1 §3.2); aarch64 is a later lane |

## 6. Decision

Selected enforcement integration: the native Rust adapter in `ouro-jail` over
unprivileged bubblewrap 0.11.1 (the one on the operator's `PATH`, resolved once
to an absolute canonical path and recorded with its SHA-256 by `doctor` and the
freeze), seccomp filters whose digests the freeze pins, and cgroup v2
delegation through the user manager. It is the "thin native Rust adapter over
bubblewrap/seccomp" of jail-v1 §5.1, justified by the named failures in §3.

Selected observer: the ptrace tracer compiled into `ouro-jail`, narrowed by a
`SECCOMP_RET_TRACE` filter to `linux-closed-v1` (narrowing-filter digest in
[milestone-1-freeze.toml](milestone-1-freeze.toml)), with the unix-peer
mediator's results for `agent`'s `connect`. Its build provenance is the
binary's (`version --json` `build`).

Not selected: `srt` 0.0.77 and Greywall 0.3.7 (named failures, §3), the legacy
sandbox (needs BEAM), eBPF (withdrawn from v1: host provisioning), `fanotify`
(not needed).

Named blockers: none for the selected path. Named limits: §5 and
[J5 authority](j5-authority.md). Performance (§4): the startup budget (under
250 ms p95 added warm startup) is met in every judged cell. The fixed-workload
budget of 20% is missed, and by the operator decision of 2026-09-25 is
replaced by a measured ceiling on the jail's own overhead of at most 50%
median post-start (`tool` 39.5% and 40.3%), with bubblewrap's containment
under the distribution's AppArmor confinement named as the dominant cost;
observation cost is reported per workload with no budget. Raw fixture
locations: the `evidence/` files cited above.
