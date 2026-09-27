# Ouroboros-jail security audit — 2026-09-27 (fourth pass)

Auditor goal: full security review of `ouro-jail` at HEAD `b3c1648c`
("Third audit: record the post-fix verification in the report"; the code
audited is commit `17960a9f`'s fixes at their recorded freeze), with the
objective of making an opencode agent escape the `agent` profile. This pass
re-verified every third-audit fix live, attacked the fix code itself as new
surface, and hunted new vectors with five parallel static audits plus live
adversarial testing.

## Environment

- Test host: `ubuntu@37.59.114.70` (the reference host: Ubuntu 26.04.1,
  kernel 7.0.0-31-generic x86_64, bwrap 0.11.1,
  `kernel.yama.ptrace_scope=1` except during the A4 re-verification,
  AppArmor userns restriction on, linger enabled for `ubuntu`;
  `kernel.io_uring_disabled=0` — io_uring is seccomp-denied instead).
- Binary rebuilt on-host from `b3c1648c`
  (`cargo build --release -p ouro-jail`), SHA-256
  `559da8410e15ae3e9feecfd1cddb11868ea0cca6171ba888dc82ea40f8078f4f`,
  installed at `~/.local/bin/ouro-jail`.
- OpenCode 1.18.32 at `~/.opencode/bin`, bundled launch profile at
  `~/.config/ouro/launch/opencode.toml`.
- Baseline first: the A01 reproduction (`ouro-jail run --launch opencode …
  "Create a file named greeting.txt …"`) exited 0 in 12 s, `greeting.txt`
  written, receipt `settled`, every coverage class active (`exec` 128,
  `fs.write` 13060, `net` 31, `proxy.net` 31), no gaps.
- Method: five parallel static audits (policy/credentials/gc/records,
  tracer/observer, containment boundary, bridge/proxy/mediation,
  lifetime/limits/identity) plus live adversarial testing from inside
  `--profile agent`, `--profile tool`, `--profile none` and
  `--launch opencode` runs. PoCs are under `~/a4ws` on the host.

## Verdict

**No containment escape found.** The namespace + bind-mount + seccomp +
mediation boundary again held against everything this pass threw at it.
The headline finding is **B1 (demonstrated end-to-end): the operator's
`config.toml` is a trusted, widening policy layer that no isolation guard
covers** — one pointed `--rw` file grant over it lets a jailed child rewrite
the operator's defaults for every later run: observation off, arbitrary
read-only grants (`~/.ssh` demonstrated), and arbitrary egress (a planted
`network.allow` carried a `CONNECT` + TLS session end-to-end). This is the
same trust-break the third audit's A2 fix closed for the launch directory,
one file over, with strictly larger effect. B2 (live-demonstrated
misroute) shows a compat-ABI `seccomp(NEW_LISTENER)` under `none` is
recorded as a bounded `foreign_abi` interval instead of the open-ended
`child_notification_listener` gap. The rest are guard gaps, receipt
semantics and hygiene.

## Findings

### B1 (High, demonstrated end-to-end) — `<config>/config.toml` is a trusted widening layer no guard isolates; a jailed child can plant it with one file grant

The third audit's A2 fix added `check_launch_isolation`
(supervisor.rs:2244-2275), which refuses child-visible roots overlapping
`launch_directory(config_dir)` = `<config>/launch` on every run. But the
operator config is a **different file in the same directory**:
`resolve_plan` reads `<config_dir>/config.toml` on **every** run
(supervisor.rs:255-259) through `read_operator_file`
(supervisor.rs:685-691) — a plain `read_to_string` with no identity
checks (contrast the hardened `read_project_file` directly below it:
no-follow, capped, regular-file-only). The parsed `OperatorConfig` enters
resolution as `LayerOrigin::OperatorConfig`, a trusted, non-narrowing
layer (policy.rs:608, 1240), and its `[jail]` table can set
`filesystem.read_write`/`read_only` grants, `network.allow`,
`limits`, `observation.mode` (config.rs:136-186) — and `jail.profile`.

Every guard passes a file grant over it: `check_launch_isolation` compares
only `<config>/launch` (`launch_dir.starts_with(config.toml)` is false);
`check_state_isolation` covers the data root only; `validate_receipt_path`
covers the receipt copy only. The grant's source must exist to be pinned,
so the prerequisite is an operator who uses (or pre-creates) a
`config.toml` — the same pointed-grant prerequisite class the third audit
judged for A2.

Demonstrated live, three runs:

1. `ouro-jail run --profile agent --rw ~/.config/ouro/config.toml -- …`
   (file pre-created empty by the operator): the child wrote
   `[jail.observation] mode="off"`, `[jail.network]
   allow=["example.com:443"]`, `[jail.filesystem]
   read_only=["/home/ubuntu/.ssh"]` into the operator config. No refusal,
   `settled`, exit 0.
2. A later, completely plain `--profile tool` run: `/home/ubuntu/.ssh`
   (including `authorized_keys`) was bound read-only **into the sandbox**
   and listed, and observation was off — every coverage class `unsupported`,
   the run `exec_unconfirmed`. The receipt certifies nothing while the
   child reads the operator's SSH directory.
3. A later plain `--profile agent` run: `CONNECT example.com:443` through
   the bridge returned `200 Connection established`, and a full TLS +
   HTTP session to example.com succeeded — an egress channel to a host
   **the child chose**, not the operator.

Impact: durable, run-independent policy takeover — grants, egress and
observation all become child-controlled — from one over-broad file grant
at any earlier time. The codebase refuses the identical shape for the
data root, the launch directory and the receipt; `config.toml` was missed.
Addenda found while verifying: the read follows symlinks and has no size
cap (a child-grown multi-gigabyte `config.toml` is read unbounded into
the supervisor; the project file's `read_capped` hardening exists and is
unused here).

Fix direction: extend the isolation guard to the whole config directory
(or at minimum `config.toml` and the launch directory) on every run, and
load it through a no-follow, identity-checked, capped read mirroring
`launch_profile::load`/`read_project_file`.

### B2 (Medium, live-demonstrated misroute) — a compat-ABI `seccomp(NEW_LISTENER)`/`clone(CLONE_UNTRACED)` under `none` is classified as a bounded `foreign_abi` gap, not the open-ended listener gap

`handle_entry` (tracer/session.rs:1431-1451) returns `InFlight::Foreign`
at the architecture check before the listener test can match, because the
listener test only knows the x86_64 number 317 — the same blind spot
exists for `clone`/`CLONE_UNTRACED` (i386 nr 120). The reference host
**does accept the i386 `int 0x80` ABI** (live: i386 `getpid` returned a
real pid), and the third audit itself recorded that host as
i386-capable. Live under `--profile none`: repeated
`int 0x80` `seccomp(SET_MODE_FILTER, NEW_LISTENER)` attempts
(EFAULT with a truncated 64-bit prog pointer, then EINVAL with a valid
low mapping) each ended the run with `evidence_lost … foreign_abi` —
a **bounded** interval — and never the open-ended
`child_notification_listener` gap the native-ABI path produces. A
successful listener reply (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) would let
the child pass any syscall with no trace stop while the receipt presents
the hole as closed [the successful-fd step is static inference from the
tracer audit; the misroute itself is demonstrated]. Contained profiles
are unreachable — live under `agent` the same probe returned `EPERM`
(seccomp.rs denies foreign ABIs first), and the foreign-ABI stop still
degrades the receipt.

Fix direction: before the early foreign return, recognize the compat
rows — i386 `seccomp`=354 (flags in `args[1]`), i386 `clone`=120, x32
`seccomp`=317|X32, x32 `clone`=56|X32 — and route them to
`InFlight::Listener`/`UntracedDescendant`; or classify any successful
foreign-ABI seccomp as the open-ended listener gap.

### B3 (Low, static) — `kernel_exe` strips a literal ` (deleted)` suffix, allowing a false-positive TargetExec

`tracer/proc.rs:78-90` truncates a link ending in ` (deleted)` before the
exact-bytes match in `is_target_image` (observed.rs:193-215). A decoy
named `tool (deleted)` beside the operator's `./tool`, reached through a
child-created symlink, makes the stripped kernel link equal the target
image, so an exec of the decoy **confirms the target ran**. Reachability
is narrow (workspace-relative exec; the launcher also canonicalizes
candidates at plan time, which narrows but does not close it). All other
directions fail closed (`exec_image_mismatch`). Fix: compare raw and
stripped forms, confirming only on the raw match, or corroborate by
inode.

### B4 (Low, static) — the isolation guards are lexical; mount aliases are invisible to them

`check_state_isolation`, `check_launch_isolation` and
`validate_receipt_path` canonicalize and compare paths only;
`state::mount_alias::forbidden_identities` (which computes bind-alias
identities from mountinfo) exists and is used by the credential and
launch-file checks, but not by these guards. A bind-mount alias of the
state root (receipts, `jail-state.json`, vendor-state secret copies)
inside a child-visible root would be invisible — the state root has no
identity-based backstop anywhere. Caveat: creating the alias is an
operator act (the operator is trusted), so this is defense-in-depth
against operator mistake, not a child-driven bypass. Fix: run the alias
identities through the same guards.

### B5 (Low, static) — `Lease::acquire` opens `jail.lock` without `O_NOFOLLOW` after a path-based check

state.rs:962 (found independently by two audits): the lstat-then-open
window allows a same-uid racer to swap a symlink in, locking a foreign
inode (two supervisors on one attempt — an I04 break) or creating an
attacker-chosen file through a dangling symlink. The state root is not
child-visible (B4's alias would be the way in), so exploitation needs a
prior foothold; `probe_existing` does the same check correctly. Fix: open
with `O_NOFOLLOW` and re-verify identity post-open.

### B6 (Low, static) — the wall limit is parsed twice; the receipt's claim and the release-time enforcement can diverge

uncontained.rs:1545-1547 and platform.rs:2959-2962 each parse the wall
value at release time independently of the receipt's unconditional wall
claim (~uncontained.rs:841-860). Latent divergence only (both parses see
the same immutable snapshot today). Fix: parse once, share the value.

### B7 (Low, environment-dependent) — the `/run` grant refusal is tmpfs-conditional

The A3 fix refuses tmpfs mounts at or beneath `/run` by fstype; on a host
where `/run` (or a subtree) is not tmpfs — some distros mount
`/run/user/<uid>` differently — only the mount-topology devtmpfs branch
remains. The reference host is unaffected (verified: `--ro /run`,
`--rw /run/user/1000`, `--ro /dev`, `--rw /dev` all refuse
`policy_widening`). Fix: key the refusal on the path prefix `/run` as
well, not only the fstype.

### B8 (Info) — S10-drift class: capability-gated syscalls that reach the kernel

Live with correct numbers: the `xattrat` family, SysV IPC
(`shmget`/`shmat`/`semget`), `clock_settime`-class and `setxattrat`
reach the kernel (EINVAL/EFAULT) rather than being denied outright —
inside the userns they are stopped by absent capabilities, which is
unreachability, not a deny (the repo's own S10 rationale). `kexec_*`,
`finit_module`, `perf_event_open`, `bpf`, `io_uring_*`, the new mount
API, `pidfd_open/getfd`, `process_vm_*`, `kcmp`, keyring, quotactl
family, `open_by_handle_at`, `fanotify_init`, `setns`, `mount`,
`umount2`, `pivot_root`, `swapon/off`, `reboot`, hostname/domain,
`TIOCSTI` are all `EPERM`/`ENOSYS` as frozen.

### B9 (Info) — receipt/accounting hygiene from the parallel audits

- `narrowing_filter_digest` names the canonical filter, not the
  per-attempt bytes actually installed (the trace-data word differs);
  digest.rs's stated contract no longer holds (tracer audit F3).
- `filtered_readonly_opens` still reaches no receipt — the A1 fix's
  third item; mitigated because every memory-sourced read-only `openat2`
  now emits a `memory_flags_unverified` gap, so the invisible count covers
  only register-sourced (provably immutable) verdicts (tracer audit F4).
- The bridge's rejection report undercounts when the report socket is
  full; sockaddr paths longer than the `sockaddr_un` field are truncated
  before classification (bridge audit).
- The pathname A-B-A residual on non-exec covered calls remains open
  (audit 3 accepted it after the flags variant); descendant execs still
  carry the snapshot pathname without kernel corroboration (§11.3
  documented).
- `resolv.conf` `options sortlist` entries survive the sanitized copy
  (boundary audit; resolver-order influence only).

## What was attacked and held (live)

- **Third-audit fixes re-verified**: A1 — `race9` at calibrated timings
  now aborts `evidence_lost memory_flags_unverified` (D1=50µs) or
  `argument_snapshot_unstable` (naive/other timings); nothing silent.
  A2 — `--rw ~/.config/ouro` refuses `unsafe_config_path`. A3 —
  `/dev`, `/run`, `/run/user/1000`, `/proc`, `/proc/sys` grants all
  refuse `policy_widening`. A4 — at `ptrace_scope=0` (flipped and
  restored), every `/proc/<bridge>/{mem,environ,fd,maps,auxv}` open is
  `EACCES`. A6 — operator errors render control characters escaped.
  quotactl/quotactl_fd — `EPERM`.
- **Syscall surface with header-verified numbers**: full privilege,
  mount, pidfd, keyring, ptrace, io_uring, perf, bpf, module, kexec,
  handle, quota, fanotify, namespace and time families — `EPERM` or
  `ENOSYS` as frozen (a first probe's "allowed" rows turned out to be
  the probe's own i386/x86_64 number mixups; corrected against
  `unistd_64.h`, the jail's tables are right). `io_uring_setup` is
  denied, so the per-op seccomp bypass class is closed.
- **Hardlink escape of read-only grants**: `link()` from a `--ro` grant
  of operator-uid files into the writable workspace (the audit-1 probe
  only ever tried root-owned system files) — `EXDEV` every time: each
  grant is its own bind mount and the kernel refuses links across
  mounts. The `chmod`-through-the-alias variant is unreachable with it.
- **Network**: the raw bridge battery — LF-only endings, leading/double
  spaces, double `Host`, CL/TE on CONNECT, HTTP/1.0, absolute-URI,
  pipelined second CONNECT, origin-form GET, TLS bytes as request,
  300-byte label, 70 KB header (`431`), uppercase, trailing dot,
  userinfo, percent/punycode hosts, IPv6 literals, `:0`/`:0443`/
  `:65536`/`:4430` ports — every one `400`/`403` fail-closed; allowed
  CONNECTs to the profile's three hosts relay real TLS end-to-end.
  Direct `connect("/run/ouro/proxy/proxy.sock")` from a non-bridge
  process: `EACCES` (bridge-only identity pinning holds). Egress outside
  the allowlist: `403`.
- **Limits**: `--limit wall=3s` killed a `sleep 30` at 3.1 s;
  `--limit pids=10` stopped a 200-process fork storm.
- **Receipt integrity**: a `--receipt` path inside a child-visible root
  is refused before exec.
- **opencode red-team**: the hostile escape prompt (namespace, proxy
  bypass, bridge ptrace, symlink/hardlink escape, out-of-workspace
  writes) was refused by the model; no escape artifact on the host;
  receipt `settled` with every class active.
- **Static (five parallel audits)**: bwrap plan ordering/aliasing,
  protected-path scans, fd map and CLOEXEC coverage, env construction,
  filter arch gating and stacking, mediation TOCTOU (pinned-node
  connect, RESOLVE_IN_ROOT, cwd identity), sockdiag parse, proxy
  admission/accounting/chunked revalidation/resolver policy, credential
  staging and cleanup, gc/reconcile identity checks, records redaction,
  cgroup read-back, parent-death watcher fd hygiene, `none` verdicts —
  all re-verified with no bypass found beyond the findings above.

## Artifacts (on the VPS)

- `~/a4ws/` — probes and PoCs: `a4_sysprobe(.c)`, `a4_t2.c` (corrected
  number probe), `a4_sweep.c`, `a4_i386d.c` (B2), `a4_net.py`,
  `a4_net2.py` (bridge battery), `a4_memtest.py` (A4), `race9` (A1
  regression), `a4_cfg*.sh` (B1 plant scripts), `a4_redteam.sh`.
- Receipts: `/tmp/a4-*.json`; B1 receipts `/tmp/a4-c1.json` (plant run),
  `/tmp/a4-c2.json` (observation-off tool run), `/tmp/a4-c3.json`
  (planted-allow agent run).
- The planted `~/.config/ouro/config.toml` was removed after the demo
  (the operator's original `launch/` directory untouched);
  `ptrace_scope` restored to 1 (verified); no host files modified
  outside `~/a4ws` and `~/ouroboros/target`.

## Recommended fix order

1. B1 — isolate and identity-check the config directory on every run
   (the launch-directory guard exists to copy); cap the read.
2. B2 — classify compat-ABI seccomp/clone rows as the open-ended gaps.
3. B3 — raw-link exec corroboration (or inode).
4. B4, B5 — alias-aware guards; `O_NOFOLLOW` lease open.
5. B6, B7 — single wall parse; path-pinned `/run` refusal.
6. B8, B9 — deny-list the capability-gated stragglers; digest the
   installed filter bytes; surface `filtered_readonly_opens`; note the
   bridge accounting truncations.
