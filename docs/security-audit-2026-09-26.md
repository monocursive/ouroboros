# Ouroboros-jail security audit — 2026-09-26 (third pass)

Auditor goal: full security review of `ouro-jail` at HEAD `8cd02527`
(code-identical to `dd194ac0`; the two commits between them touch only
evidence tables and documents), with the objective of making an opencode
agent escape the `agent` profile. This pass re-attacked the surfaces the
first two audits hardened and hunted new vectors.

## Environment

- Test host: `ubuntu@37.59.114.70` (the reference host: Ubuntu 26.04.1,
  kernel 7.0.0-31-generic x86_64, bwrap 0.11.1, `kernel.yama.ptrace_scope=1`
  except during the A4 demonstration, AppArmor userns restriction on,
  linger enabled for `ubuntu`).
- Binary rebuilt on-host from `8cd02527` (`cargo build --release -p ouro-jail`),
  SHA-256 `88825fb1ba3ace44982969df5f43acee31e7757a706de81a6c6d8d1da5b4fa75`,
  installed at `~/.local/bin/ouro-jail`.
- OpenCode 1.18.32 at `~/.opencode/bin`, bundled launch profile at
  `~/.config/ouro/launch/opencode.toml`.
- Baseline A01 reproduction passed first: `ouro-jail run --launch opencode …`
  → exit 0, reply delivered, every coverage class active.
- Method: four parallel static source audits (bwrap/launch/platform,
  seccomp/tracer, network mediation/bridge/proxy, policy/credentials/gc)
  plus live adversarial testing from inside `--profile agent`, `--profile
  tool` and `--launch opencode` runs. All PoCs are in `~/a3ws` on the host.

## Verdict

**No containment escape found.** The namespace + bind-mount + seccomp +
mediation boundary held against everything this pass threw at it, including
the operator-grant corners this pass added. However, the second audit's
accepted "mutate-and-restore" residual (S9) is **demonstrated exploitable
here** (A1: silent covered mutation with a clean receipt), and a planted
launch profile exfiltrated an operator secret end-to-end after one over-broad
`--rw` grant (A2). The rest are guard gaps, environment-dependent hardening
holes and hygiene items.

## Findings

### A1 (High, audit integrity — demonstrated) — the A-B-A flags race turns S9's accepted residual into a silent, receipt-invisible mutation

`tracer/session.rs` re-reads pointed arguments at the syscall exit
(`arguments_stable`) and compares against the entry snapshot; a disagreement
is an `argument_snapshot_unstable` gap. A sibling thread that flips the bytes
for the kernel's copy and **restores them before the exit stop** satisfies
both reads: entry `O_RDONLY`, kernel `O_RDWR|O_CREAT|O_TRUNC`, exit
`O_RDONLY`. The call is then counted as a stable read-only open
(`filtered_readonly_opens`, session.rs:1806-1816 — a counter no receipt
surfaces) with **no event, no gap, and no coverage degradation**.

PoC `race9.c` (calibrated single flip per call: spinner waits `D1` ns,
sets writable for `D2` ns, restores; oracle = a successful `write()` through
the returned descriptor):

- Fine sweep (55 `D1` values × 2 `D2` values × 3 reps ≈ 330 jailed runs,
  one raced `openat2` each): **24 runs completed with `applied=1` and no
  `evidence_lost`** (≈7% win rate; wins spread over `D1` = 6–60 µs, i.e.
  ptrace stop jitter).
- Winning run's trace: exactly three audit events — `proc.exec`, `fs.unlink`
  (the PoC's own cleanup unlink of the file whose creation was never seen),
  `proc.exit`. Receipt: every coverage class `active`, `gaps: []`,
  strict evidence passes. The kernel created and received a byte in a file
  the observer certified it never touched.
- The naive spinner (audit 2's `race5` shape, flags toggling continuously)
  is caught within a few calls (`argument_snapshot_unstable` →
  `evidence_lost`); only the calibrated flip-and-restore wins silently.
- Same trust class as first-audit F1 and second-audit S1: containment is
  untouched (the mutation happens inside the workspace), but the receipt is
  the product's core claim, and an agent with a side-effect oracle (its own
  `write()` succeeding) can retry silently.

Two adjacent weaknesses in the same machinery (static, from the parallel
audit):

- `handle_exit` runs the stability check only when `!pending.exec_confirmed`
  (session.rs:1818): a **confirmed exec's pathname is asserted from the entry
  snapshot alone**, so the same race names an image that never executed while
  `TargetExec` confirmation (observed.rs:229-238) still fires. Not won live
  (audit 2's race6: 0/3000; the `getname` window is tighter than the
  `open_how` copy), but unguarded by construction.
- `filtered_readonly_opens` is invisible in receipts (platform.rs:1846-1862
  surfaces only abandoned_tracees/unreaped/panicked), so even the honest
  count of "read-only verdicts we re-verified" is unauditable.

Fix direction: a memory-flags `openat2` cannot be verified by re-reading —
treat it as gapped-by-construction (one `argument_snapshot_unstable`-class
gap per call, or a classed event with `flags_verified:false`) instead of a
silent filter; corroborate confirmed execs against `/proc/<pid>/exe` at
`PTRACE_EVENT_EXEC`; surface `filtered_readonly_opens`.

### A2 (Medium, demonstrated end-to-end) — a jailed child can plant a launch profile that a later run stages operator secrets with

The data root refuses child-visible overlap (`unsafe_state_path` — verified
live: `--ro ~/.local/share/ouro` as workspace/grant is refused), but the
**config dir has no such guard**: `check_outside_writable` runs only when a
launch profile is actually loaded, and only over that file's own chain
(supervisor.rs:562-566); `check_state_isolation` covers the data dir only
(supervisor.rs:2215-2240). Every `load()` check on a profile file (uid,
mode 0600, nlink 1, no-follow walk — launch_profile.rs:532-652) is
satisfiable by the jailed child itself, which runs as the operator's uid.

Demonstrated live, two runs:

1. `ouro-jail run --profile agent --rw ~/.config/ouro -- …` (no `--launch`,
   nothing refuses the grant): the child wrote
   `~/.config/ouro/launch/planted.toml` — `jail = "agent"`, a
   `copy_rw` credential with `source = "~/.audit3-secret"`, `dest = "k/…"`,
   and a `network.allow` entry.
2. `ouro-jail run --launch planted -- …` **staged the operator's secret into
   vendor state and the child printed it** (`FAKE-SECRET-a3-9f2c` at
   `~/k/id_ed25519`). The planted `network.allow` would enter as a
   non-narrowing operator-grant layer the same way.

Impact: durable credential exfiltration plus host grants on future launches,
one over-broad `--rw` grant earlier. The codebase already refuses the
identical shape for the data root and for the loaded profile's own file —
the asymmetry is unintended. Fix direction: refuse child-writable grants
overlapping the config/launch directory on **every** run (identity and
mount-alias based, mirroring `check_state_isolation`), or pin installed
profile digests and refuse mismatches.

### A3 (Medium, guard gap — partially demonstrated) — the pseudo-fs grant refusal misses devtmpfs and the host runtime tree

`is_pseudo_fs_magic` (policy.rs:1610-1619) names only proc/sysfs/cgroup(2);
`refuse_pseudo_fs_grants` (platform.rs:2577-2634) checks only that set and
the /proc//sys/cgroupfs mount topology, and grant destinations are never
re-checked the way masks are (`shadows_plumbing` applies to `masked` only,
bwrap.rs:1013-1016; extra binds render after bwrap's own /proc and /dev
rows, bwrap.rs:875-901).

Live results:

- `--ro /dev` under `--profile tool`: **accepted — the host devtmpfs is
  mounted over the sandbox's private /dev** (full listing: `dri`,
  `btrfs-control`, `cuse`, `dma_heap`, `disk/`, …). Device I/O is then
  whatever the operator's uid can open — on a desktop (dri, kvm, snd,
  hidraw, uinput) this is a real containment break under one grant. Under
  `agent` the same grant fails closed *accidentally* (the bridge never
  appears: the shadowed /dev breaks its spawn); `--rw /dev` under `tool`
  also refused, but only because the protected-scan tried to create
  `/dev/.git` (EACCES) — both refusals are accidents, not guards.
- `--rw /run/user/1000`: **accepted** — the operator's runtime tree is
  writable and readable from the jail (host tmpfs: RAM fill, same-uid file
  tampering, disclosure of whatever lives there). The scariest consequence
  is **contained**: a session-bus connect is refused by the AF_UNIX mediator
  (live: `connect(/run/user/1000/bus)` → `EACCES`, both via `dbus-send` and
  a raw socket), and `tool`/`build` deny AF_UNIX outright. The remaining
  exposure is files, not sockets.
- `--ro` of the state root: refused correctly (`unsafe_state_path`) — the
  parallel audit's claim that it binds was wrong; the data-dir guard holds.

Fix direction: extend the grant refusals to devtmpfs sources and to
`/dev`, `/run`, `/run/user/<uid>` destinations (and sources), mirroring the
/proc//sys/cgroupfs refusal; re-check grant destinations against the mount
table the plan itself emits.

### A4 (Low, demonstrated, environment-dependent) — the bridge is dumpable; on a `ptrace_scope=0` host the target writes its memory

Only the supervisor sets `PR_SET_DUMPABLE=0` (supervisor.rs:1341-1361); the
bridge never does, and `/proc/<bridge>/fd`, `environ`, `maps` are all
child-readable on this host (verified live — the bridge is visible in the
pidns as pid 4). `/proc/<bridge>/mem` access is `open()`+`write()`, not a
deniable syscall, so the S7 deny list does not cover it; Yama is the only
gate, and the repo's own S7 standard says the boundary must not lean on
`kernel.yama.ptrace_scope`.

Demonstrated live: with `ptrace_scope` flipped to 0 (and restored to 1
after), a jailed python process opened `/proc/4/mem` `O_RDWR`, wrote 8 bytes
into the bridge's heap and read them back (`PWNED-A3`); at scope 1 the same
open is `EACCES`. A hijacked bridge is the one context the mediator trusts
(its `(tgid, start_ticks)` is the authorized proxy identity, unixpeer/
live.rs:561-589) and it runs deliberately untraced (launch.rs:316-322) —
code injection there restores the F2-class raw-proxy-client position
(skipping the bridge's accounting and budget) and executes unobserved
syscalls in the shared mount namespace. The proxy's per-request allowlist
still applies to every connection it makes, so this is mediation/bridge
integrity, not egress. Fix direction: `PR_SET_DUMPABLE=0` in `bridge_main`
(blocks `PTRACE_MODE_ATTACH` at every Yama scope), or refuse `agent` when
`ptrace_scope == 0`.

### A5 (Low, demonstrated) — wrong narrowing-trace-data guesses are invisible, contradicting the S14 mitigation's stated economics

A child-installed filter returning `RET_TRACE|0x1111` on an allowed
non-closed-set syscall (live: `getpid`, 10 calls) produces ten tracer stops
that are silently continued: the receipt shows no gap, no
`unexpected_trace_stop`, and `requested_by_other_filters` is not surfaced
anywhere (only `limits[].requested` matches a receipt grep). The S14
rationale in code and spec ("every wrong guess … is itself a visible gap …
brute-forcing the sixteen bits costs one visible gap per wrong guess") is
therefore inverted: probing the 15-bit space is free and unthrottled; only a
**hit** degrades loudly (that core property still holds). Fix direction:
count wrong-data stops into a loss counter/gap, or correct the comments.

### A6 (Low, demonstrated) — untrusted project-config strings reach the operator's terminal verbatim

`[jail.limits] wall = "\u001b]52;c;aGVsbG8=\u0007"` in the workspace's
`ouro.toml` makes the operator's stderr carry the raw OSC-52 sequence
(live: `cat -v` shows ``^[]52;c;aGVsbG8=^G`` inside the refusal message).
A terminal that honors OSC 52 gets its clipboard rewritten ("aGVsbG8=" is
"hello"); CR/LF/ESC permit log-line spoofing. Echo points: config.rs
363-367/381-384/425-427/445-468 and policy.rs 1275-1294 via
`write_error_line` (records.rs:578-596) and lib.rs:16-28. JSON surfaces are
serde-escaped and safe; the run still refuses. Fix direction: strip or
escape control characters in `write_error_line` and diagnostic renderings.

### A7 (Low/Info, demonstrated) — availability and drift notes

- **No storage ceiling**: limits are pids/mem/cpu/wall only; the child wrote
  2 GiB to `/tmp` (per-attempt scratch on the host root filesystem) in
  2.8 s — 773 MB/s straight onto `/` (93%→95% full). A jailed run can
  starve the host and the jail's own state store. Not named in §2's limits.
- **`oom_score_adj` of pid 1 and the bridge is child-writable** (live:
  `=1000` write to `/proc/1/…` and `/proc/4/…` succeeds; same-uid). Under
  host memory pressure the child can aim the OOM killer at the namespace
  init or the bridge. Same-uid interference class (S13), weaker.
- **`quotactl_fd` (443) is not denied** (live: passes the filter, fails
  EBADF) — S10 drift; unreachable today (its fds come only from denied
  syscalls) but exactly the "new kernel surface ships allowed" class the
  seccomp.rs:157-166 rationale names. `quotactl` (179) likewise.
- Bridge `accept()` can busy-spin at the fd ceiling (bridge.rs:296-341,
  EMFILE return leaves the listener readable) — self-inflicted, in-attempt
  CPU only; nothing re-checks RLIMIT_NOFILE against the bridge budget.
- `discover_bridge`'s listening read-back reads `/proc/<pid>/net/tcp` only,
  not `tcp6` (agent.rs:858-893) — completeness gap in verifying a trusted
  helper (the bridge binds v4 loopback only).

### A8 (Info) — confirmed-by-design observations

- Metadata mutations (`chmod`/`fchmodat`/`fchmodat2`/setxattr family incl.
  the new `xattrat` numbers) are outside `linux-closed-v1` — a child can
  strip permissions/xattrs on any same-uid file with at most a mutation-open
  event. Consistent with the §11.2 set; the fchmodat2/xattrat numbers are
  new-kernel surface of the S10 class.
- `memfd_secret` (447) is allowed and degrades tracer argument reads
  loudly (`path_unreadable`/gaps) — no silent break.
- A child can stack its own `RET_ERRNO` filter above the tracer's to make
  closed-set calls fail unobserved — only *failures* can be hidden (ERRNO
  outranks TRACE); successful mutations always stop. Worth a doc line.
- The contained child's environment is built, not inherited (live:
  `ANTHROPIC_API_KEY`/`AWS_*` in the operator env do not reach `agent`;
  only LANG/TERM/TZ pass through, PATH/TMPDIR fixed). `none` inherits minus
  `OURO_*` (documented).
- The launch-profile `copy_rw` grammar may name any operator-readable
  secret as a source — §12 defines this (an installed profile is trusted);
  noted because A2 shows how that trust can be manufactured.

## What was attacked and held (live)

- **Prior fixes re-verified**: proxy socket bridge-only
  (`connect("/run/ouro/proxy/proxy.sock")` → `EACCES`); `/proc/1/mem`,
  `/proc/4/mem` `EACCES` at scope 1; sanitized resolv view; `/tmp`
  per-attempt fresh (marker gone next attempt); masks over `/run/ouro`
  refused (planted `ouro.toml` → `invalid_config`); trace budget fail-closed
  (a 16-thread mediation/connect storm aborted the attempt
  `evidence_lost` in ~2 s rather than overflowing).
- **Syscall surface**: full probe of the mount/namespace/privilege/io_uring/
  ptrace-class/keyring/module/time families — every frozen deny is `EPERM`,
  `clone3` `ENOSYS`, exotic socket families `EAFNOSUPPORT`/`EPROTONOSUPPORT`
  (kernel-level), `AF_UNIX` DGRAM refused, `TIOCSTI` `EPERM`, `/dev/tty`
  `ENXIO` (no controlling terminal), no `/sys`, cgroupfs, `/dev/mem`,
  `/dev/sda1`, `/dev/console` in view; `PR_SET_PTRACER_ANY` succeeds but
  only authorizes peers inside the pidns.
- **Network**: egress and metadata `ENNETUNREACH` (netns has only loopback);
  UDP dead; `127.0.0.2`/`::1` connects permitted by mediation but land
  nowhere; abstract AF_UNIX names netns-scoped; pathname connects to
  unknown/unpinned nodes (including via workspace symlinks and
  `/proc/4/root`) refused `EACCES`; `sendto` on unconnected stream
  `EOPNOTSUPP`; empty/oversized sockaddr forms refused. Proxy parser:
  uppercase/trailing-dot/suffix/prefix/IDN-lookalike/`0443`/`4430`/no-port/
  absolute-URI/userinfo/space-pad/NUL/decimal-IPv4 CONNECT and every Host/
  method/framing confusion → 400/403 fail-closed; answer policy (frozen IANA
  deny table, all-or-nothing answer sets, connect-to-approved-only, one
  resolution per request) re-verified in source — no rebinding window.
- **Liveness**: moderate-rate mediation storm (4 threads) under
  `--limit wall=12s` → tree killed at 12.0 s (exit 143), supervisor healthy.
- **fd hygiene**: target starts with fd 0/1/2 only (the launcher's fd 9
  trace-data pipe and all mediation/bridge fds are closed before exec);
  bridge holds exactly four fds, all `/dev/null` or sockets (`/proc` fd
  opens `ENXIO`).
- **opencode red-team**: the hostile escape prompt is refused by the model
  (as in both prior audits); the boundary itself is what the probes above
  exercise.
- **Static (parallel audits)**: narrowing enforcement (per-field monotone
  predicates, identity-based untrusted walks, ranked network modes,
  limit-raise refusal), credential staging (no-follow walks, post-open
  identity re-verify, `nlink==1`, O_EXCL dests, 16 MiB budget, staging
  before any child exists), vendor-state cleanup (anchored, identity-checked,
  mount-crossing refusal), gc (identity-gated leaves, receipt-less
  never-prepared arm, no unchecked unlink), state persistence (atomic
  replacement, unguessable ids, O_NOFOLLOW reads), records redaction (argv
  digest, env names only, withheld digests), x32/arch gating, clone/exec
  pairing, group-stop and restart handling — all re-verified with no
  bypass found.

## Artifacts (on the VPS)

- `~/a3ws/{a3_probe,a3_net.py,a3_med.py,a3_med2.py,a3_storm(.c),race9(.c),
  a3_trace.c,a3_mem.py}` — probes and PoCs; receipts under `/tmp/r9/WIN-*`
  (24 silent A-B-A wins), sweep logs `/tmp/r9sweep{2,3,4}.log`.
- Planted launch profile, fake secret and test `ouro.toml` files removed;
  `ptrace_scope` restored to 1 (verified).

## Recommended fix order

1. A1 — stop certifying memory-flags `openat2` as silently read-only;
   gapped-by-construction (or classed `flags_verified:false` events), plus
   exec corroboration via `/proc/<pid>/exe`.
2. A2 — refuse child-writable grants over the config/launch dir on every
   run (the data-root guard already exists to copy).
3. A3 — extend grant refusals to devtmpfs and the host runtime trees.
4. A4 — `PR_SET_DUMPABLE=0` for the bridge.
5. A5, A6 — wrong-guess accounting; control-character stripping.
6. A7 — disk ceiling consideration, oom_score_adj hardening, `quotactl_fd`
   deny, bridge RLIMIT check.

## Remediation (2026-09-27)

Every actionable finding was fixed in the working tree and verified live on
the reference host with this audit's own PoCs. The spec is revision 22.

- **A1** — a stable read-only verdict on memory-resident `openat2` flags is
  now one `memory_flags_unverified` gap of the call's classes plus a
  counter, never a silent filter; a confirmed exec carries the kernel's own
  image (`/proc/<tid>/exe` at the exec stop), the target-exec confirmation
  follows it, and an entry snapshot contradicted by the kernel records an
  `exec_image_mismatch` gap and confirms nothing. Verified live: `race9`
  (the calibrated A-B-A PoC that won silently 24/330 before) now aborts
  `evidence_lost memory_flags_unverified` with nothing silent; the exec
  confirmation works through symlinked spellings (`/bin/true` →
  `/usr/bin/true`) via canonicalized candidates; plain runs stay
  `settled`, all classes active, no gaps.
- **A2** — `check_launch_isolation` refuses any child-visible root
  overlapping the launch directory on every run (`unsafe_config_path`,
  key `OURO_CONFIG_DIR`), mirroring the state-root rule. Verified live:
  the planting grant (`--rw ~/.config/ouro`) refuses before exec.
- **A3** — the pseudo-filesystem grant refusal now covers devtmpfs (by
  mount topology; devtmpfs shares tmpfs's statfs magic, so the mount list
  is the operative guard) and tmpfs at or beneath `/run`, and refuses
  grants equal to, beneath, or containing such mounts (the audit probe's
  `/dev/shm` case caught the descendant gap in the first cut). Verified
  live: `--ro /dev`, `--ro /run`, `--rw /run/user/1000`, `--rw /dev` all
  refuse `policy_widening` before pinning.
- **A4** — the supervisor seals the bridge over the report pair after
  discovery; the bridge parks until the seal, then sets
  `PR_SET_DUMPABLE=0` before serving its first client (an unsealed bridge
  exits; a supervisor death fails the wait). Verified live at
  `ptrace_scope=0`: `/proc/4/mem` open is now `EACCES` (was a verified
  write); the bridge's `oom_score_adj` write is refused (the namespace
  init remains same-uid reachable — documented as a named limit).
- **A5** — `lifetime.native.details.requested_by_other_filters` carries
  the wrong-guess count; the three inverted comments now state the true
  property. Verified live with a corrected probe (5 stops → 5). The
  finding's original live evidence was retracted: the audit's first probe
  had an inverted BPF arch-match and issued no stops at all; the static
  finding (counter unsurfaced) stood.
- **A6** — `write_error_line` and `diag!` escape C0/DEL/C1 characters
  (`<U+001B>` form). Verified live: the OSC-52 `wall` limit renders
  escaped, no raw ESC/BEL reaches the terminal.
- **A7** — `quotactl`/`quotactl_fd` joined `DENY_EPERM` (both `EPERM`
  live; evidence tables and freeze regenerated); the bridge backs off
  100 ms on resource-exhausted `accept()` instead of spinning; the
  listening read-back also checks `tcp6` (a pre-existing port-format bug
  in the v6 path was caught and fixed in passing); the storage ceiling
  and metadata-mutation scope are documented as named limits (§2, §11.2).

Post-fix verification: the full Linux suite on the reference host passes
every binary except the three pre-existing plain-session baseline failures
both earlier audits also showed (`conformance_j1::s11_wall_expiry`,
`review_linux::r9_explicit_pids`, `j5_lifetime::x07` — cgroup-delegation
and leaf checks that need the lingering `ouro-ci` lane) and the
parallel-load-sensitive lifetime tests, which pass serially; clippy clean
and the macOS lane green including the byte-for-byte seccomp-table tests;
the A01 opencode regression re-run (`settled`, every coverage class active,
no gaps — the fix costs honest runs nothing, since no runtime in the
sandbox issues read-only `openat2`); the evidence tables and
`milestone-1-freeze.toml` regenerated from the fixed binary
(`cargo xtask freeze`).
