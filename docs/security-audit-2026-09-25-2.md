# Ouroboros-jail security audit — 2026-09-25 (second pass)

Auditor goal: full security review of `ouro-jail` at `fc25c45c` (the same-day
fix commit for the first audit's F1/F2/F5), with the objective of making an
opencode agent escape the `agent` profile. This pass re-attacked the fixed
surfaces and hunted new vectors.

## Environment

- Test host: `ubuntu@37.59.114.70` (the reference host: Ubuntu 26.04.1,
  kernel 7.0.0-31-generic x86_64, bwrap 0.11.1, `kernel.yama.ptrace_scope=1`,
  AppArmor userns restriction on, linger enabled for `ubuntu`).
- Binary rebuilt on-host from `fc25c45c` (`cargo build --release -p ouro-jail`),
  SHA-256 `b43a2ede5ad49c70b89dc9a66970961efc8d5a056754eb8efb9b0c0981ba98fa`,
  installed at `~/.local/bin/ouro-jail` (byte-identical to the previously
  deployed image, confirming the host was already running the post-fix tree).
- OpenCode 1.18.32 at `~/.opencode/bin`, bundled launch profile at
  `~/.config/ouro/launch/opencode.toml`.
- Baseline A01 reproduction passed first: `ouro-jail run --launch opencode …`
  → exit 0, workspace file written, every coverage class `active`, `gaps: []`.
- Method: four parallel static source audits (bwrap plan, network mediator/
  bridge/proxy, tracer/seccomp, lifecycle/credentials) plus live adversarial
  testing from inside `--profile agent` and `--launch opencode` runs.

## Verdict

**No containment escape found.** The namespace + bind-mount + seccomp +
mediation boundary held against everything tried. However, the first audit's
F1 fix has a **demonstrated bypass on a path it does not cover** (S1 below):
mutation opens that the observer skips at entry as "read-only" are never
followed to an exit, so the exit re-read never runs and a raced `openat2`
performs a covered mutation with **no event and no gap** while the receipt
certifies full coverage. Several integrity/hygiene findings follow, one of
them (S4) leaving credential bytes on disk indefinitely.

## Findings

### S1 (High, audit integrity — demonstrated) — the openat2 read-only skip is a silent suppression path that F1's exit re-read does not cover
`tracer/session.rs` `handle_entry` decides "read-only" from the **entry-time**
`open_how.flags` read (session.rs:1449-1460, `capture_flags` 2229-2237) and
then resumes the tracee without following it to an exit (the read-only-skip
tail, ~1088). The F1 exit re-read (`arguments_stable`) only exists for calls
that are followed; a skipped call can never produce an event or a
`argument_snapshot_unstable` gap.

PoC `race7.c` (workspace): a CLONE_VM sibling flips `open_how.flags` from
`O_RDONLY` to `O_RDWR|O_CREAT|O_TRUNC` exactly once, timed to land in the
entry-stop → kernel-execution gap (the same window the first audit's `race4`
won ~50% of the time).

- Jailed run, 5000 attempts: **kernel applied the writable open 4984 times**
  (each verified by a successful `write()`), trace recorded **4958
  `fs.create` events** (`fs.unlink` 5001, nothing else), receipt: every
  coverage class `active`, **`gaps: []`, no `argument_snapshot_unstable`
  anywhere** — strict evidence passes. 26 covered mutations (≈0.5% of raced
  calls) vanished with no trace. An attacker retries until its own
  side-effect oracle (the write succeeding) confirms the win; ~1000 raced
  calls hide one mutation with >99% probability, and each win is silent.
- Register-flags `open/openat/creat` are immune (flags in pt_regs); only
  `openat2`'s memory-resident flags are affected. Unreadable `open_how`
  still fails closed (`flags_unavailable` gap).
- Fix direction: follow every `openat2` to its exit so `arguments_stable`
  covers the skip decision (the cost is one more stop per read-only openat2),
  or re-read flags immediately before the resume decision and treat a
  disagreement as a gap.

### S2 (Medium, audit integrity — demonstrated) — the child can forge the bridge's report channel through `/proc/<bridge>/fd/2`
The bridge's stderr is the write end of the supervisor's report pipe
(`agent.rs:73-75`), and the bridge is a same-uid peer visible in the jail's
PID namespace (pid 4, `/run/ouro/jail __bridge`). YAMA gates
`PTRACE_MODE_ATTACH`, not `/proc/<pid>/fd/<n>` opens in read/write mode, so
the target can open `/proc/4/fd/2` `O_WRONLY` (live: success) and write
arbitrary bytes; `drain_bridge_report` (agent.rs:577-588) counts **raw bytes**
as `rejected_at_capacity` with no origin check. Live PoC (`forge.c`): 777
bytes written → settled receipt records `"rejected_at_capacity": 777`. The
child can also hold the write end open indefinitely (pipe-EOF semantics).
Containment unaffected. Fix direction: make the bridge non-dumpable
(`PR_SET_DUMPABLE=0`, like the supervisor) so `/proc/<bridge>/fd/*` requires
ptrace-mode access and fails EACCES; optionally credential the channel.

### S3 (Medium, boundary integrity — demonstrated) — a child-authored workspace `ouro.toml` can mask the jail's own plumbing
`deny_read` is always admitted from the untrusted project layer ("a denial
can only remove authority", policy.rs:1280-1282) and renders as a tmpfs mask
**after** every infrastructure mount (bwrap.rs:974-981, 1040-1044). A prior
jailed run can therefore plant `[jail.filesystem] deny_read =
["/run/ouro/proxy"]` in the workspace. Live: the next `--profile agent` run
in that workspace sees `/run/ouro/proxy` as an **empty directory**
(`proxy.sock` gone), the receipt's network `helpers` become `null` (no bridge
record) while `net`/`proxy.net` coverage still reports `active`. The same
mechanism masks `/run/ouro/jail` (the bridge's own exec path), `/tmp`, or
`/proc`. No authority is gained — it is a child-to-next-run availability and
record-integrity weapon inside the operator's workspace. Fix direction:
refuse masks whose destination resolves to `/run/ouro/*` or shadows an
already-emitted staged/infrastructure mount.

### S4 (Medium, credential hygiene — demonstrated) — a supervisor killed mid-preparation leaves staged credential copies on disk forever; `gc` cannot remove them
Vendor state (including `copy_rw` secrets, 0600) is created between the
attempt claim and the prepared receipt; the execution leaf is only registered
later inside `platform.prepare`. A SIGKILL in that window leaves
`<data>/attempts/<id>/vendor-state/<dest>` with no terminal receipt and no
leaf, and `gc`'s permission logic then has no arm that ever cleans it
(`cleanup.rs:566-584` requires a terminal receipt or a gc-verified leaf;
`gc.rs:1039-1047` settles `not_recorded` without establishing the tree).
Live: 5 runs with the wrapper SIGKILLed at a random early moment → **4/5
retained `vendor-state/cred/auth.json`**; a subsequent `ouro-jail gc` scanned
217 attempts and did not touch them. Same-uid readable only, but the bytes
outlive the attempt indefinitely. Fix direction: let gc treat
claimed-but-never-prepared attempts (owner dead, boundary pending in jail
state, no leaf ever registered) as cleanup-permitted, as the supervisor
already does for its own refusal path.

### S5 (Medium, receipt semantics — demonstrated) — `applied.filesystem.protected_coverage: "existing_and_root"` is recorded for profiles that requested and enforce no protected coverage
`prepare_mounts` skips the protected scan entirely when
`coverage == ProtectedCoverage::None` (platform.rs:2686-2690) — which is the
`agent` and `build` baseline — yet `read_applied` feeds the untouched empty
aggregate to `scan_coverage` (platform.rs:1542, 2183-2191), which returns
`"existing_and_root"`. Live: agent-baseline and `--launch opencode` receipts
both carry `protected_coverage: "existing_and_root"` with zero protected
binds in the mount table. The statement is vacuously true (no segments were
requested) but conflates "nothing requested" with "verified existing"; any
downstream consumer (managed teams plans to rely on receipts) cannot tell
them apart. Fix direction: emit a distinct value (`none`/`not_required`)
when coverage==None.

### S6 (Low–Medium) — the receipt publishes the SHA-256 of every `copy_rw` credential's exact bytes
`records.rs:1139-1148` carries `CredentialRecord.digest` for every staged
credential; `copy_rw` always digests the copied bytes. Live: staged a fake
credential, receipt digest `b14889d4…` == `sha256(file bytes)`. Receipts are
the artifact meant to be shared (CI logs, `--receipt PATH` copies), so anyone
a receipt reaches can verify offline guesses of low-entropy secrets.
High-entropy API tokens are unaffected. Fix direction: HMAC with an
attempt-local key kept in jail state, or degrade to a length/none+reason.

### S7 (Low–Medium, environment-dependent) — the ptrace-class cousins are not denied, and the boundary silently depends on `ptrace_scope=1`
`pidfd_open(434)`, `pidfd_getfd(438)`, `pidfd_send_signal(424)`,
`process_madvise(440)`, `kcmp(312)` are absent from `DENY_EPERM`
(seccomp.rs:85-123) while `ptrace`/`process_vm_*` are denied. On this host
(scope=1) the kernel refuses them (live: `pidfd_getfd(bridge,fd)` → EPERM for
all fds, `process_vm_readv(bridge)` EPERM). The jail only *records*
`kernel.yama.ptrace_scope` in the doctor manifest and never requires it; on a
scope-0 host a same-uid target can `pidfd_getfd` the visible bridge's
descriptors, including its proxy connection — a direct proxy client that
bypasses the F2 bridge-only pin and the bridge's connection budget (the proxy
allowlist still applies to every request). Fix direction: deny 424/434/438/
440 (the sandbox has no legitimate child-side use for them), or refuse to
run when `ptrace_scope == 0`.

### S8 (Low, hardening) — `exec_confirmed` skips the exit re-read, so `proc.exec` pathnames stay single-fetch
`handle_exit` runs `arguments_stable` only when `!pending.exec_confirmed`
(session.rs:1766); a successful exec's pathname snapshot is asserted without
re-verification (post-exec the old address space is gone, so a re-read is
impossible — the gap is inherent). A CLONE_VM sibling rewriting the pathname
between the entry stop and the kernel's `copy_filename` can make the trace
name an image that never executed. Live `race6.c` (3000 racing execs):
**0 kernel-side flips observed** (vs ≈1.6% for openat2 flags) — the
`getname` window is too tight to win here today. The launcher's own exec is
cross-checked against pre-resolved candidates and the launcher is
single-threaded, so only inner execs of the target are exposed. Fix
direction: treat exec path snapshots as weaker claims (like incomplete
paths), or verify the execed inode at the exec event.

### S9 (Low, accepted-limit confirmation) — F1's residual "mutate-and-restore" double-fetch
The exit re-read can be satisfied by restoring the original bytes after the
kernel's copy (entry=A, kernel=B, exit=A). Not observed in testing
(`race5.c`: 324 kernel-side flag flips, 330 detected instabilities, **0
stable-but-wrong records**; every flip was either truthfully recorded or
flagged `argument_snapshot_unstable`, and strict mode aborts on the first
gap). A determined attacker with a side-effect oracle could still win the
three-way race occasionally; this is the inherent limit of a passive
observer. Fix direction (if wanted): post-state verification (inode
identity) for create-class events.

### S10 (Low, deny-list drift) — the baseline is a deny list with default ALLOW; newer syscalls pass by default
Everything not named is `SECCOMP_RET_ALLOW` (seccomp.rs:320). Live inside
`agent`: `statmount`, `listmount`, `lsm_get_self_attr`, `lsm_list_modules`,
`mseal`, `memfd_secret`, `fchmodat2`, `cachestat`, `pidfd_open(self)` all
implemented and permitted. None is privilege-bearing today on this host
(probed; all fail or behave benignly), and `statmount`/`listmount` only see
the jail's own mount namespace — but `seccomp.rs:84` claims "every mount
interface old and new" is denied, which `statmount`/`listmount` contradict,
and any future kernel syscall ships allowed by default. Fix direction: add
the missing names (and the S7 set) or switch the posture for
unknown-but-recent nr ranges.

### S11 (Low, disclosure) — `/proc/self/mountinfo` discloses host path spellings
Path-form binds record their host source in the child's mountinfo: the
workspace, `/usr`, the per-attempt scratch (leaking the state-root layout
and attempt id, e.g.
`…/.local/share/ouro/attempts/att_<id>/scratch → /tmp`), and `/dev/sda1` as
the backing device. Contents are not reachable; layout is. (The fd-form
handoff hides these from the argv, not from mountinfo.)

### S12 (Low, semantics) — `deny_read` masks are writable tmpfs
The mask rendered for a denied path is a plain `--tmpfs` (never
`--remount-ro`'d), owned by the child's uid. Live: `touch` inside the masked
`/run/ouro/proxy` succeeds. Host content is covered, but the child gains
free ephemeral scratch at every denied path, invisible to the operator and
outside every limit view (limits are pids/mem/cpu only).

### S13 (Low, availability) — same-uid bridge interference and mediation pressure
- `kill(bridge, SIGSTOP/SIGKILL)` succeeds from the target (same uid;
  signal syscalls not denied): SIGSTOP pauses relay service, SIGKILL ends
  it (verified: target completes, supervisor records the helper note —
  fail-closed, no route to the proxy). After death the target can rebind
  `127.0.0.1:3128` and impersonate the bridge for co-resident processes of
  the same attempt (the mediator refuses the pinned dead identity for
  everyone, so no host egress is gained).
- A connect flood keeps the four mediator workers busy (bounded 2 s each)
  and serializes full-netns sock-diag dumps under one mutex — supervisor CPU
  the attempt cgroup never charges. Live 32 000-connect storm: every connect
  answered `EACCES`, no queue loss, coverage honest. Strict mode converts
  any loss into a reported gap and aborts.

### S14 (Info) — the narrowing trace-data constant is public and forgeable
A child-installed seccomp filter returning `RET_TRACE|0x4f4a` on an allowed
syscall passes the tracer's own-filter test and raises
`unexpected_trace_stop` gaps — the child can keep its receipt's coverage
classes degraded, but enforcement is unaffected (ERRNO/USER_NOTIF outrank
TRACE). Fix direction: randomize the trace data per run.

## What was attacked and held (live)

- **Prior fixes re-verified**: F2 bridge-only proxy
  (`connect("/run/ouro/proxy/proxy.sock")` → EACCES `proxy_bridge_only`);
  sanitized `/etc/resolv.conf` (no search domains in-jail); credential
  `nlink==1` refusal paths untouched by this pass's testing.
- **F1 fix on followed calls**: `race5` double-flip (spinner alternating
  `O_RDONLY`/`O_WRONLY|O_CREAT`): 324 kernel-applied writable opens, 330
  `argument_snapshot_unstable` gaps, 3 truthful stable records, **0 phantom
  or silently-suppressed events on the followed path**; strict mode aborts
  at the first gap (the suppression that works is the *skip path*, S1).
- **fd hygiene**: target starts with exactly fd 0,1,2 (pipes) — no listener
  (18), sockdiag (19) or report (20) leak; bridge holds exactly 4 fds.
- **Bridge hard-attack**: `pidfd_getfd` (all fds), `process_vm_readv`,
  `ptrace(ATTACH)` → EPERM; `/proc/<bridge>/fd/N` opens succeed only for
  pipes/files (S2), sockets ENXIO; `open("/proc/<bridge>/root/…")` confined
  to the same mount view; `kill -9 1` (namespace init) is a no-op.
- **Network**: abstract AF_UNIX connect → ECONNREFUSED (netns-scoped, no
  allow observed); AF_UNIX DGRAM EPERM; AF_NETLINK/AF_PACKET EAFNOSUPPORT;
  raw sockets EPERM (no CAP_NET_RAW); netns loopback-only (empty route
  table, only the bridge's listener in `/proc/net/tcp`); 32 000-connect
  mediation storm fully answered with honest accounting; proxy CONNECT
  allowlist untouched by this pass (static re-audit: parser, IDNA,
  resolution and answer-policy rules verified sound, no bypass found).
- **Peer isolation**: a second concurrent attempt's netns shows only its own
  bridge listener; per-attempt pidns shows only pid 1 (bwrap), self, and the
  bridge.
- **opencode red-team** (`--launch opencode`): hostile escape prompt refused
  by the model; sanitized probe run blocked at opencode's own permission
  system (`external_directory` auto-reject) and at the jail boundary
  (`fs.deny` events recorded); no jail-level anomaly.

## Static-audit notes (not live-demonstrated)

- The child runs as the operator's own uid (no uid mapping step); the mount
  table is the only wall between the child and the operator's uid-owned
  files — by design, but worth stating in operator docs.
- Workspace contents can force refusals of *later* runs (protected-scan
  limits, symlinked `.git`): availability lever for the `tool` profile.
- Placeholder creation mutates the operator's live repo (empty `.git` /
  `.ouroboros`); a crashed supervisor leaves them behind (recorded side
  effect per jail-v1:1218-1220).
- `Lease::acquire` opens `jail.lock` without `O_NOFOLLOW` after a
  symlink-refusing check (same-uid race window, lease confusion only).
- Operator `--profile FILE` / `config.toml` are read without the launch
  profile's no-follow/ownership walk (trusted-operator assumption; pointing
  them at a child-writable file hands the child policy authorship).
- The mediator's design is notably strong: `CONTINUE` is never used for a
  security decision, the supervisor performs the connect itself on the
  pidfd-duplicated socket from its own sockaddr snapshot, notification ids
  are revalidated, and the proxy node is matched by pinned `(st_dev,st_ino)`
  plus the bridge's `(tgid,start_ticks)`.

## Artifacts (on the VPS)

- `~/a01ws/{race5,race6,race7,forge,probes2,bridgeattack,storm,abs,fdcheck,recon2}(.c)`
  — PoCs and probes (all in the audit workspace).
- Receipts `/tmp/audit2-*.json`; traces under
  `~/.local/share/ouro/attempts/att_*/trace.ndjson` (newest: the race7 run).
- Test credential `~/.audit2-cred.json`, launch profile
  `~/.config/ouro/launch/audit2cred.toml` and the four retained
  credential-attempt dirs were removed after the audit.

## Recommended fix order

1. S1 — follow every `openat2` to exit (silent suppression of covered
   mutations; same trust class as the first audit's F1).
2. S4 — gc arm for claimed-but-never-prepared attempts (credential bytes on
   disk forever).
3. S3 — refuse `deny_read` masks over `/run/ouro/*` / staged mounts.
4. S2 — non-dumpable bridge (closes the report-channel forgery and the
   `/proc/<bridge>/fd` surface).
5. S7 — deny the pidfd/ptrace-cousin syscalls or gate on `ptrace_scope≠0`.
6. S5, S6, S8, S10, S12 — receipt semantics, digest oracle, exec-path
   claims, deny-list drift, read-only masks.

## Remediation (2026-09-25, same day)

Every actionable finding was fixed in the working tree, the evidence tables
and the freeze were regenerated on the reference host, and each fix was
verified live with the audit's own PoCs.

### S1 — fixed: every `openat2` is followed to its exit
`handle_entry` no longer skips an `openat2` classified read-only at entry
when the flags came from tracee memory (`FlagSource::OpenHow`); the call is
admitted as a verification follow with a flags-only `Pending`, and
`handle_exit` re-reads the flags through the F1 machinery: unstable →
`argument_snapshot_unstable` gap; stable read-only → the filtered counter, no
event. Register-sourced flags (`open/openat/creat`) keep the entry-time skip
(the kernel consumes the saved pt_regs). Unit test added beside the F1 one.
Verified live with `race7`: pre-fix, 4984 kernel-applied mutations vs 4958
recorded events (26 silent, `gaps: []`, strict evidence passing); post-fix,
the same race yields `argument_snapshot_unstable` gaps, degraded coverage and
`evidence_lost` — nothing is silent.

### S2 — fixed: the report channel is a `SOCK_SEQPACKET` pair
`spawn_bridge` creates a `SOCK_SEQPACKET|SOCK_NONBLOCK` socketpair instead of
a pipe; the supervisor's take verifies `Kind::Socket`; the bridge's stderr
keeps its role (one datagram per report byte). A socket cannot be reopened
through `/proc/<pid>/fd` (ENXIO), so the forgery path is closed without
hiding the bridge from the supervisor's discovery. Verified live: `forge`
now gets ENXIO where it wrote 777 forged bytes.

### S3 — fixed: masks over the plumbing are refused
Both the policy layer (`masks_boundary_plumbing` refuses `/`, `/run`,
`/run/ouro` and beneath, for every origin) and the plan renderer
(`PlanError::MaskedBoundaryPlumbing`) refuse a `deny_read` mask that would
shadow the jail binary, the proxy directory or staged state. Verified live:
the planted `ouro.toml` now refuses with `invalid_config` instead of
silently removing the next run's proxy socket.

### S4 — fixed: gc cleans never-prepared attempts
`never_charged_tree`: an owner `decide` established dead, no leaf ever
registered and **no receipt ever written** (a receipt, even one claiming an
unverified tree, keeps the conservative retention) proves no cgroup was ever
created, which permits the vendor-state cleanup exactly like a
verified-empty leaf. Verified live: 5/5
SIGKILLed staging runs cleaned by the next `gc` (pre-fix: 4/5 retained
forever).

### S5 — fixed: coverage that was never requested reads `none`
`read_applied` emits `protected_coverage: "none"` when the snapshot requested
`ProtectedCoverage::None` (agent/build), instead of running the vacuous walk
 verdict. Verified live on agent and launch-profile receipts.

### S6 — fixed: receipts carry no credential digest
Receipt rows are `digest: null` with `digest_unavailable_reason:
"receipt_verifier_withheld"` for both modes; the digest staging computed is
recorded in jail state's private provenance (`content_digest`), where the
operator alone can verify it. Verified live: receipt withholds, jail state
matches `sha256` of the staged bytes.

### S7+S10 — fixed: the ptrace-class cousins and mount readers are denied
`DENY_EPERM` gains `pidfd_send_signal` (424), `pidfd_open` (434),
`pidfd_getfd` (438), `process_madvise` (440), `kcmp` (312), `move_pages`
(279), `migrate_pages` (256), `statmount` (457) and `listmount` (458), so
the boundary no longer depends on `kernel.yama.ptrace_scope` for the
bridge's descriptors. Evidence tables regenerated (agent baseline 72
instructions) and the freeze updated. Verified live: all listed probes now
EPERM inside the jail, and the A01 opencode regression still passes (the
runtimes in the sandbox did not need them).

### S12 — fixed: masks are sealed read-only
The renderer emits `--tmpfs <path> --remount-ro <path>` for every mask.
Verified live: writing inside a masked directory fails with `EROFS`.

### S14 — fixed: per-attempt narrowing trace data
The supervisor draws a random nonzero u16 per attempt, passes it to the
launcher through a pre-written pipe at fd 9 (`--trace-data-fd`; the value
never appears in argv, which `/proc/1/cmdline` exposes to the target), and
to the tracer through `TracerConfig::trace_data`; `stop_not_ours` compares
against that value. The canonical constant remains the frozen evidence
program. A child echoing the public constant now manufactures a gap instead
of forging one; brute-forcing the sixteen bits costs one visible gap per
wrong guess and strict evidence fails on the first.

### Documented as limits (no code change)
- S8 (exec pathname is entry-only): inherent — post-`PTRACE_EVENT_EXEC` the
  old address space is gone; 0/3000 live wins. Spec §11.3 notes the claim's
  basis.
- S9 (mutate-and-restore double-fetch): the accepted passive-observer limit;
  0 observed in testing.
- S11 (mountinfo and `/proc/1/cmdline` host-path disclosure): a property of
  bind mounts and pid-1's argv; layout only, contents unreachable.
- S13 (same-uid bridge signals, in-attempt impersonation, mediation
  pressure): fail-closed availability; the receipt names the helper's end.

### Post-fix verification (reference host)

- Clippy clean and portable tests 220/220 on both targets; the evidence
  tables and `milestone-1-freeze.toml` regenerated on the reference host from
  the fix revision (`cargo xtask freeze --doctor`).
- Full Linux suite (`cargo test -p ouro-jail --release --no-fail-fast`):
  every binary green except `conformance_j1::s11_wall_expiry`,
  `review_linux::r9_explicit_pids` and `j5_lifetime::x07` — the three
  pre-existing baseline failures the first audit already showed failing
  identically on pristine `d7c0d36b` from a plain SSH session (the
  conformance lane runs them under `ouro-ci` with lingering). `j5_lifetime`
  run serially: 20/21, `x07` only; the other parallel-run failures in that
  binary pass serially, as the first audit also observed.
- A01 regression, re-run on the final binary: opencode 1.18.32 under
  `--launch opencode` → exit 0, file written, `settled`, every coverage class
  active.
- All audit PoCs re-run on the final binary: `race7` (gaps, not silence),
  `forge` (ENXIO), `ouro.toml` mask (refusal), `credkill` (gc completes,
  nothing retained), `probes2` (EPERM set), mask writes (EROFS), receipts
  (`none`, `receipt_verifier_withheld`, private digest in jail state).
