# ouro-jail vs greywall — benchmark and posture comparison, 2026-09-28

Historical run. The [2026-09-30 comparison](benchmarks/sandboxes/README.md)
retains current same-host samples, work-phase costs, a separately labelled
Anthropic compatibility lane and native Mac results. In particular, similar
no-op timings do not establish that observation is free for file-heavy work.

Same host, same workloads, same day: `ouro-jail` at HEAD `2c8f28dc`
(binary SHA-256 `af47af46…`, rebuilt on-host) against greywall v0.3.7
(release tarball, checksum-verified, commit `5581056d`) with greyproxy
0.4.5, both installed at `~/.local/bin`.

## Environment and method

- Reference host `ubuntu@37.59.114.70`: Ubuntu 26.04.1, kernel
  7.0.0-31-generic x86_64, 4 vCPU, 3.8 GiB RAM, bwrap 0.11.1, linger on,
  AppArmor userns restriction on — the stock, unprivileged,
  no-host-configuration class both tools target.
- Timing: `hyperfine -N -i --warmup 2 --min-runs 30`, one invocation per
  command (cold per-run cost included for both tools — each is a
  per-invocation product). Overhead factor = sandboxed mean / baseline
  mean, greywall's own published metric.
- Workloads in `~/benchws` (git repo, 2 000 files): `true`
  (spawn-only), `python3 -c pass` (interpreter), `git status` (real
  tool), 100-file write loop (fs-heavy write), `grep -r` over 1 000
  files (fs-heavy read).
- ouro-jail rows: `ouro-jail run --profile tool -- …` with observation
  on (default) and `--observe off`. greywall rows: `greywall -- …`
  (default profile: cwd rw, network denied).
- Scripts and raw JSON: `~/bench.sh`, `~/spotcheck.sh`,
  `/tmp/bench-results/*.json` on the host.

## Performance

| Workload | baseline | ouro-jail (obs on) | ouro-jail (obs off) | greywall |
|---|---|---|---|---|
| `true` | 0.7 ms | 124 ms (**186x**) | 135 ms (203x) | 1 612 ms (**2 430x**) |
| `python3 -c pass` | 14 ms | 141 ms (**9.8x**) | 147 ms (10.2x) | 1 647 ms (**114x**) |
| `git status` | 4.7 ms | 133 ms (**28x**) | 133 ms (28x) | 1 640 ms (**346x**) |
| 100-file write | 9.0 ms | 141 ms (**16x**) | 136 ms (15x) | 1 615 ms (**180x**) |
| `grep -r` 1 000 files | 1.3 ms | 127 ms (**96x**) | 135 ms (103x) | 1 638 ms (**1 247x**) |

- **ouro-jail's fixed per-invocation cost is ~124–147 ms** (preparation,
  boundary, state, receipts); greywall's is **~1.6 s** on this host —
  10–11x more per command, so ouro-jail is uniformly ~11x cheaper at
  every workload.
- **The closed-set observer is free at this scale**: obs-on ≈ obs-off
  within noise (±10 ms) on every workload — the ptrace observer's cost
  is inside the setup-dominated budget; evidence costs nothing here.
- Fairness notes: greywall's own CI numbers (EPYC runner) show 215 ms
  cold `true`; on this VPS the TUN layer fails (see below) and its
  per-run setup retries, which inflates the 1.6 s. Even against their
  best published number (215 ms), ouro-jail is ~1.7x cheaper; on the
  shared reference host as measured, ~11x.
- Both products' overhead is fixed cost: for real agent runs it
  amortizes to nothing (see end-to-end below).

## End-to-end: opencode 1.18.32, A01 task ("Create greeting.txt")

| Setup | Time | Result |
|---|---|---|
| No sandbox | 7.7 s | greeting.txt written |
| **ouro-jail `--launch opencode` (agent profile)** | **8.1 s (+4.8 %)** | greeting.txt written, receipt settled, every coverage class active |
| greywall `--auto-profile --profile opencode` | ~2 s (fails) | `Error: Cannot connect to API` — no file |

**On a stock unprivileged host, an agent cannot run under greywall at
all**: its network path needs a TUN device inside the sandbox
(`TUNSETIFF: Operation not permitted` unprivileged) and its socat
bridges never come up — every mode fails closed (`default`, `--allow`,
`--watch`, and explicit `-x socks5h://localhost:43052` all refuse or
DNS-fail). greywall's own docs acknowledge the fallback is proxy env
vars, which only proxy-aware tools honor. ouro-jail's bridge is
userspace, needs no privilege, and carried the model API session
end-to-end.

## Security posture spot-check (pass-5 probe subset, same binaries)

Both tools' filesystem and PID-namespace containment held: default read
of `~/.ssh`, writes outside the workspace, and host-process visibility
were all denied; the mount/hardlink class was stopped.

| Probe | ouro-jail (tool/agent) | greywall 0.3.7 (default and profile) |
|---|---|---|
| `mount` | EPERM (filter) | reached kernel (ENOENT from args) |
| `unshare(CLONE_NEWUSER)` | EPERM (filter) | **succeeds** — nested userns created |
| `unshare(CLONE_NEWNS)` after userns | unreachable | EPERM (host AppArmor, not greywall) |
| `clone3` | ENOSYS (filter) | reached kernel (EFAULT) |
| `ptrace(TRACEME)` | EPERM (filter) | **succeeds** |
| `process_vm_readv` | EPERM (filter) | reached kernel |
| `pidfd_getfd` | EPERM (filter) | reached kernel (EBADF on fd) |
| `io_uring_setup` | EPERM (filter) | reached kernel (EFAULT) |
| `bpf`, `keyctl`, `setns` | EPERM (filter) | reached kernel (EINVAL/EBADF) |
| `perf_event_open`, `kexec_load` | EPERM (filter) | EPERM (kernel capability gate) |
| `open(/etc/shadow)` | ENOENT (not in view) | EACCES |
| `open(/proc/1/environ)` | opens the sandbox's own pidns init | EACCES |
| rename-replace sandbox's own binary via rw grant | **possible (pass-5 C3)** | blocked by accident: EBUSY, the binary is a bind mount (the Landlock wrapper's own plumbing) |
| rename-replace *another* operator binary in the same granted dir | possible (C3) | **also possible** (demonstrated on the ouro-jail binary; restored) |
| persistent config plant | guarded (pass-4 B1 fix; `none` residual C2) | n/a — no persistent config exists until a profile is saved (untested) |

Reading: greywall's 27-syscall deny list (their docs) did not deny any
of the escape-class calls empirically — in both default and
`--profile opencode` modes the calls reached the kernel and were stopped
only by capability checks, AppArmor, or argument luck. That matches
their stated threat model ("not designed to be a strong isolation
boundary against actively malicious code"); ouro-jail's filter denies
the whole class flatly, and its observer would record the attempts.

Capability differences that matter operationally:

- **Resource limits**: ouro-jail has cgroup-backed pids/mem/cpu/wall
  ceilings; greywall has none (documented out of scope).
- **Evidence**: ouro-jail produces per-run receipts (exec, fs, net,
  limits coverage with named gaps); greywall has monitor mode and proxy
  logs, no per-run attestation.
- **Network egress policy**: ouro-jail enforces an allowlist at its own
  bridge (pass-5 C1 found the CDN Host-swap bypass); greywall delegates
  to greyproxy, untestable here (network non-functional).
- **Threat model**: ouro-jail is specified for hostile containment;
  greywall is defense-in-depth for semi-trusted commands.

## Verdict

On the one host both products nominally target — a stock, unprivileged
Linux box — ouro-jail runs the reference agent workload end-to-end at
+4.8 % over unsandboxed, with syscall-flat denial of the escape class,
resource ceilings and receipts, at ~124–147 ms per invocation. greywall
0.3.7 on the same host cannot give any agent network access at all,
costs ~1.6 s per invocation, and its seccomp layer did not deny the
escape-class syscalls empirically — its filesystem/PID containment and
its self-protection held, and its Landlock/bwrap layering is real, but
by its own documentation it is a weaker boundary for a different
(semi-trusted) threat model.

## Artifacts (on the VPS)

- `~/bench.sh`, `/tmp/bench-results/*.json` — timing suite and raw data.
- `~/spotcheck.sh`, `/tmp/spotcheck.log` — posture probes and results.
- `/tmp/a5_gwsys(.c)`, `/tmp/a5_mnt2(.c)` — syscall and mount-chain
  probes.
- Host state verified clean after the C3-analog demo (both binaries
  restored, no planted files).
