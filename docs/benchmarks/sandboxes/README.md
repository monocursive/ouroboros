# Ouroboros, Greywall and Anthropic Sandbox Runtime — 2026-09-30

**Later October 1 follow-up:** [write observation and disk quotas](write-observation-and-disk-quotas-2026-10-01.md)
records a 3.6% paired write-work reduction and 41 live checks for ext4/XFS user
hard quotas. It retains the substantial ptrace write overhead as an open limit.

**October 1 follow-up:** [read observation and explicit resource ceilings](observation-and-limits-2026-10-01.md)
records a 4.02× read-work improvement, separate swap limits and bounded tmpfs
storage/inode admission. Writes remain expensive. That working-tree result
does not replace this report's frozen-build competitive measurements.

Ouroboros completes all seven measured Linux CLI workloads faster than
Greywall (5.1–9.8×) and Anthropic's **relaxed Unix-socket compatibility
profile** (1.4–2.9×). It also denies the tested syscall surface and prevents
a visible workspace socket from reaching an owned host service. Greywall and
the relaxed Anthropic profile reach that service in all three trials.

**The goal of leading on both platforms is not achieved.** Ouroboros refuses
native macOS execution. Anthropic's normal profile runs there and protects
the file, signal and socket canaries, although its detached descendant
continues running after the wrapper exits. Ouroboros's Linux observation also
adds substantial work-phase overhead to file operations.

These are bounded empirical results on two hosts, not an escape-proof
guarantee, a release conformance gate, or an end-to-end agent benchmark.

## Hosts, products and policy

| Host | Configuration |
|---|---|
| VPS | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64, four AMD EPYC-Milan vCPUs, 3.7 GiB RAM, 8 GiB swap, bubblewrap 0.11.1; user `ubuntu`, existing lingering user service |
| Remote Mac | macOS 27.0.1 build 26A434, Darwin 27.0.0, Apple M2 Pro, ten CPUs, 16 GiB RAM; user `monocursive` |

Both hosts were accessed using existing SSH key authentication. The benchmark
does not contain passwords, SSH keys, vendor authentication state or real
secret fixtures. Host security settings, SIP, AppArmor and capabilities were
not changed. Installations and probes lived in private benchmark directories.

- **Ouroboros:** Linux `ouro-jail` release build from the tested freeze at
  `a9f8129acb718ed9d05986a4729db69ecf4b5094`, SHA-256
  `cdf8a182680ef500dfb8e9983e5fea863f95b5b72c4734703cf3c14d7a9ca602`.
  Optimized, observation on, strict evidence, `tool` policy. The native Mac
  build is also optimized; it reports no embedded revision and refuses
  execution. Both report the same source-input digest
  `sha256:aff986001cf72b911bb2bdc8fa85bca0056069ae7a9bafadca76e7878739d79c`.
  At the time of these measurements, the repository's jail build inputs matched
  the frozen implementation; later ledger commits were not relabelled as a
  newly tested jail binary. The October 1 follow-ups identify their own builds.
- **[Greywall 0.3.7](https://github.com/GreyhavenHQ/greywall/releases/tag/v0.3.7):**
  checksum-verified upstream release archives, embedded commit
  `5581056d0523bfa244d8061008744ed9f72a0361`. This remained the latest release
  when checked. Its explicit configuration grants the workspace, denies the
  secret canary and grants one read-only fixture. `allowLocalOutbound` and
  `allowAllUnixSockets` are false. A private deny-only proxy endpoint replaces
  any real Greyproxy instance; `--no-network-rules` prevents global policy
  changes. No interactive or auto-selected agent profile is used.
- **[Anthropic Sandbox Runtime 0.0.78](https://github.com/anthropics/sandbox-runtime):**
  npm version pinned, exact transitive lock retained, Node 24.21.0. Reads from
  user and temporary roots are denied except the workspace, read-only fixture
  and required read-only seccomp helper. Network allowlist is empty, local
  binding is false, and weaker nested/network isolation flags are false.
  The Linux **`srt-unix-compat`** lane explicitly adds
  `allowAllUnixSockets=true`, disabling its Unix-socket seccomp helper. It is
  separate evidence and a weaker policy, never the normal-profile result.

The normal Anthropic Linux profile refused at its seccomp helper with
`write /proc/self/setgroups ... Permission denied` on this capability-restricted
host. Ripgrep was first missing, and the helper initially needed a read grant
under the temporary installation path; both harness/dependency problems were
corrected before the retained run. The final refusal is reproduced with those
dependencies present. No host restriction was disabled to make it run.

Greywall launches payloads on Linux but emits TUN/device setup permission
errors on every run. Its macOS release fails with
`sandbox-exec: unsupported syntax: kleene star`, including an independent
`/usr/bin/true` run. These failures are host/release observations, not claims
that the products fail on all Linux or macOS installations.

## Method and timing results

Each available arm runs seven fixed workloads, three discarded warmup rounds
and **30 measured rounds**. Arm/workload pairs are shuffled per round with seed
20260930. Every sample retains command arguments, stdout, stderr, exit,
completion record, elapsed time, in-child work time and host load. Successful
work must match the direct control's operation count and checksum; write
outputs are also checked externally. Ouroboros additionally needs a settled
zero-exit receipt, an empty attempt tree and no coverage gaps.

The C fixtures perform: one completed no-op, reads of 1,000 × 4 KiB files,
writes of 1,000 × 1 KiB files, 100 sequential fork/exec/wait children, and
20 million fixed integer operations. Python startup and real `git status`
also produce completion records. Each CLI starts fresh; filesystem/library
caches are warm. Timings include setup, work and teardown, with no persistent
worker amortization. Failed launches are unavailable arms, never fast wins.

Maximum observed one-minute load was 1.30 in the Greywall run and 1.51 in
the Anthropic compatibility run on four CPUs; on the ten-CPU Mac it was 2.29.
Shared-host scheduling noise remains possible. These are two separate Linux
runs, and no speed ratio compares the VPS with the Mac.

Linux with Greywall, milliseconds **median / p95**:

| Workload | Direct | Ouroboros, observed | Greywall | Greywall/Ouro median |
|---|---:|---:|---:|---:|
| No-op | 1.0 / 2.0 | 110.6 / 139.7 | 1079.1 / 1109.4 | 9.76× |
| Python | 38.4 / 41.6 | 150.3 / 168.0 | 1115.1 / 1156.1 | 7.42× |
| Git status | 42.4 / 53.7 | 164.4 / 184.0 | 1119.1 / 1151.6 | 6.81× |
| 1,000 file reads | 5.5 / 6.7 | 138.8 / 150.1 | 1080.1 / 1130.2 | 7.78× |
| 1,000 file writes | 9.7 / 11.4 | 183.8 / 202.3 | 1087.3 / 1116.0 | 5.92× |
| 100 spawned children | 72.5 / 78.9 | 227.1 / 254.6 | 1149.9 / 1179.8 | 5.06× |
| Integer computation | 25.4 / 27.1 | 137.3 / 155.4 | 1101.8 / 1132.5 | 8.02× |

Linux with Anthropic's **relaxed Unix-socket profile**, milliseconds
**median / p95**:

| Workload | Direct | Ouroboros, observed | SRT Unix compatibility | SRT/Ouro median |
|---|---:|---:|---:|---:|
| No-op | 1.0 / 1.3 | 109.0 / 126.0 | 310.8 / 333.4 | 2.85× |
| Python | 38.3 / 44.2 | 156.9 / 177.1 | 313.6 / 376.1 | 2.00× |
| Git status | 42.1 / 47.3 | 162.5 / 187.4 | 276.0 / 381.6 | 1.70× |
| 1,000 file reads | 5.2 / 6.0 | 136.0 / 150.7 | 321.5 / 342.5 | 2.36× |
| 1,000 file writes | 9.3 / 12.1 | 181.5 / 195.8 | 328.2 / 347.8 | 1.81× |
| 100 spawned children | 71.0 / 75.9 | 222.4 / 240.1 | 317.0 / 415.5 | 1.43× |
| Integer computation | 25.4 / 26.5 | 134.1 / 147.1 | 340.1 / 354.3 | 2.54× |

On the Mac, the normal Anthropic profile completed all seven workloads.
Its median CLI times were 105.3 ms no-op, 197.0 ms Python, 208.8 ms Git,
117.2 ms reads, 149.7 ms writes, 254.4 ms children and 123.9 ms computation.
Ouroboros (125) and Greywall (65) refused; they have no successful native
timing row. All three retained timing datasets independently validate with
zero invalid measurement samples.

**The work-phase loss matters.** In the Greywall run, Ouroboros's read work
takes 24.35 ms versus 4.49 ms direct (5.4×), writes 68.68 ms versus 8.63 ms
(8.0×), and child spawning 118.56 ms versus 71.08 ms (1.7×). Computation is
24.36 ms versus 24.27 ms. Startup wins do not make observation free, and
long file-heavy jobs do not simply amortize this away. The
[older comparison](../../benchmark-2026-09-28-greywall.md) is historical and
does not establish this work-phase cost.

## Bounded safety results

| Probe | Ouroboros Linux | Greywall Linux | SRT Linux Unix compatibility | SRT Mac normal |
|---|---|---|---|---|
| Private read, read symlink, hardlink read | Denied | Denied | Denied | Denied |
| Host write and write symlink | Private namespace copy only; host unchanged | Private namespace copy only; host unchanged | Private namespace copy only; host unchanged | Denied |
| Read-only fixture write | Denied | Denied | Denied | Denied |
| Host TCP, hidden host Unix socket, signal to host canary | Denied | Denied | Denied | Denied |
| **Visible workspace socket → owned host service, three repetitions** | **Denied 3/3; zero accepts** | **Reached 3/3** | **Reached 3/3, relaxed policy** | **Denied 3/3; zero accepts** |
| Detached descendant after normal wrapper return | Stopped | Stopped | Stopped | **Still writing heartbeat after 300 ms** |
| Ten Linux syscall diagnostics | Nine EPERM, `clone3` ENOSYS | Same returns as direct control | Same returns as direct control | Not a Linux test |

The visible-socket probe uses an owned echo server bound inside the writable
workspace. A successful request plus a host-side accept establishes the
boundary crossing; it does not assume access to Docker, credentials, a
privileged service or arbitrary host files. Greywall's configuration explicitly
sets `allowAllUnixSockets=false`; the Anthropic compatibility result is the
expected tradeoff of setting it true. Anthropic's normal Linux profile stays
unavailable, not a containment failure.

The ten syscall diagnostics are `unshare(CLONE_NEWUSER)`, `ptrace(TRACEME)`,
`mount`, `clone3`, `process_vm_readv`, `pidfd_getfd`, `io_uring_setup`, `bpf`,
`keyctl`, and `setns`, each in a fresh, short-lived child. Ouroboros denies
them according to its filter. Greywall and relaxed SRT create the nested
user namespace and allow TRACEME. Other calls mostly use invalid arguments:
their errors establish kernel reachability, **not successful exploitation**.
The zero-vector `process_vm_readv` result likewise reads no host memory.

All nine direct canary controls succeed, and their direct detached child
survives. Protected writes are judged by host-side bytes, not solely by a
child's successful open into its private `/tmp`. Lifecycle fixtures self-expire
after three seconds; they test normal wrapper exit, not supervisor death,
machine reboot, independent custody or every descendant race.

The [Greywall threat model](https://github.com/GreyhavenHQ/greywall/blob/v0.3.7/docs/security-model.md)
targets semi-trusted commands rather than a strong hostile-code boundary.
This report compares observed behavior without replacing that threat model
with a universal security score. No proxy origin policy, credential vault,
kernel zero-day, throughput or model-connected agent result is claimed here.

## Resource ceilings and remaining exposure

The resource fixtures are bounded to a two-second sleep, 32 one-second
children, and an 80 MiB touched allocation. Direct controls complete them.
Ouroboros's requested one-second wall ceiling terminates the sleeper with
`wall_expiry`, an empty tree and a hit receipt. A required `pids=16` permits
13 fixture children plus the charged helpers, then returns EAGAIN and records
the hit. Greywall and the native Mac SRT controls finish the two-second sleep
and all 32 children; no equivalent ceiling was requested from those CLIs.

**A memory ceiling is not a combined allocation/swap ceiling.** With
`mem=64MiB`, Ouroboros applies `memory.max` and records a hit, yet the 80 MiB
allocation completes. The accounting follow-up reports 22,008 KiB of VmSwap.
This agrees with cgroup v2's separate memory and swap controls; it does not
prove a hard 64 MiB virtual-memory or RSS bound. The binary measured here does not set
`memory.swap.max` for this request. See the
[kernel cgroup documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files).
Disk/inode, swap, CPU throttling and supervisor-death denial-of-service claims
need their own measured bounds.

## Next implementation targets

1. **Reduce observation work cost.** Profile the tracer/consumer path against
   these complete fixtures. A candidate optimization is a kernel-side
   read-only-open fast path for register-sourced flags, keeping learning and
   mutable `openat2` flags on the observed path. Preserve argument verification,
   strict gap handling, per-run evidence and tree checks. Target ≤2× direct
   work time for the read/write fixtures first; this is a proposed target,
   not an achieved or substituted spec gate.
2. **Reduce preparation cost.** The observed no-op is about 110 ms. Separate
   capability probes, filesystem preparation, attachment and settlement with
   the existing phase harness before choosing a change. Target median <50 ms
   and p95 <75 ms on this same host, without stale security capability caches.
3. **Bound swap and writable growth explicitly.** Specify and verify a
   separate swap ceiling and storage/inode budget, including unavailable-
   controller refusal and hit evidence; do not silently change what `mem`
   currently means.
4. **Close the native Mac lifetime gate.** Preserve execution refusal until
   a supported mechanism proves whole-tree cleanup and custodian-death
   behavior. Fast Seatbelt launch alone does not close the
   [documented native mechanism failures](../jail/macos-native-mechanisms.md).
5. **Expand the competitive matrix.** Add owned allowed/denied network origins,
   streaming and build workloads, peak charged memory/CPU measurements, and
   real agent tasks with an approved model service. Include stronger isolation
   classes as separate VM/container lanes instead of mixing their boundaries
   into these per-command wrapper ratios.

Runtime code and the tested jail freeze are unchanged by this benchmark.
Any optimization needs new exact-source evidence and the required conformance
rerun before it replaces the frozen jail.

## Reproduce and inspect evidence

[Setup](setup.py) installs checksum-pinned Greywall/Node/ripgrep and the pinned
npm package privately, with lifecycle scripts disabled. The npm locks retained
below identify the transitive packages. [Comparison](compare.py),
[C workloads](workload.c), [canary fixtures](payload.py),
[syscall diagnostics](syscalls.c), [resource runner](resources.py), and
[visible-socket runner](workspace_socket.py) contain the executed method.
[Summary](summarize.py) recomputes from raw records and withholds comparisons
on failed/missing work, missing/duplicate rounds, incomplete receipts, changed
binary bytes or a raw-data digest mismatch. Its damaged-evidence tests pass.

```sh
benchmark_root=$(mktemp -d /tmp/ouro-sandbox.XXXXXX)
python3 docs/benchmarks/sandboxes/setup.py --root "$benchmark_root" \
  --lock docs/benchmarks/sandboxes/results/2026-09-30/linux/package-lock.json
mkdir -p "$benchmark_root/harness" "$benchmark_root/bin"
cp docs/benchmarks/sandboxes/*.py docs/benchmarks/sandboxes/*.c "$benchmark_root/harness/"
cp /path/to/optimized/ouro-jail "$benchmark_root/bin/"
python3 "$benchmark_root/harness/compare.py" --root "$benchmark_root" \
  --out "$benchmark_root/results" --samples 30 --warmup 3
python3 docs/benchmarks/sandboxes/summarize.py "$benchmark_root/results"
# Separate, explicitly relaxed Linux comparison:
python3 "$benchmark_root/harness/compare.py" --root "$benchmark_root" \
  --out "$benchmark_root/results-srt-unix-compat" --samples 30 --warmup 3 \
  --srt-allow-unix --tools direct,ouro-jail,srt-unix-compat
python3 "$benchmark_root/harness/resources.py" --root "$benchmark_root" \
  --out "$benchmark_root/resources"
python3 "$benchmark_root/harness/workspace_socket.py" --root "$benchmark_root" \
  --out "$benchmark_root/workspace-socket"
```

Run the suites sequentially on a host. The Mac uses `/usr/bin/python3`; the
Linux tool profile uses the existing unprivileged user cgroup facilities.
Retained `tested-harness` copies match the per-run source hashes, including
the normal runs before the compatibility CLI option was added.

- [Linux Greywall-run summary](results/2026-09-30/linux/summary.json),
  [raw launches](results/2026-09-30/linux/launches.ndjson),
  [safety](results/2026-09-30/linux/safety.json).
- [Linux SRT compatibility summary](results/2026-09-30/linux-srt-unix-compat/summary.json),
  [raw launches](results/2026-09-30/linux-srt-unix-compat/launches.ndjson),
  [safety](results/2026-09-30/linux-srt-unix-compat/safety.json).
- [Mac summary](results/2026-09-30/macos/summary.json),
  [raw launches](results/2026-09-30/macos/launches.ndjson),
  [safety](results/2026-09-30/macos/safety.json).
- Resource records, workspace-socket trials, receipts, exact policy files,
  dependency locks, build metadata, tested driver copies, cleanup records and
  file digests are beside those summaries.
