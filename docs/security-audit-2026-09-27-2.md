# Ouroboros-jail security audit — 2026-09-27 (fifth pass)

Auditor goal: full security review of `ouro-jail` at HEAD `2c8f28dc`
("Freeze at the fourth-audit fix revision"), with the objective of making
an opencode agent escape the `agent` profile. This pass re-verified every
fourth-audit fix live, attacked the fix code itself as new surface, ran
five parallel static audits (fix code, boundary, tracer, agent network,
lifetime/state) plus live adversarial testing on the reference host.

## Environment

- Test host: `ubuntu@37.59.114.70` (the reference host: Ubuntu 26.04.1,
  kernel 7.0.0-31-generic x86_64, bwrap 0.11.1, linger enabled,
  `kernel.yama.ptrace_scope=1`, AppArmor userns restriction on).
- Binary rebuilt on-host from `2c8f28dc`, SHA-256
  `af47af4679f394c5772dc485bbe9460e0bacc4cf8145a013ff99bdbf11dbebaa`,
  installed at `~/.local/bin/ouro-jail`.
- OpenCode 1.18.32 at `~/.opencode/bin`, launch profile at
  `~/.config/ouro/launch/opencode.toml`.
- Baseline first: the A01 reproduction (`ouro-jail run --launch opencode …`
  "Create a file named greeting.txt …") from a git-repo workspace exited 0
  in 18 s, `greeting.txt` written (a non-repo workspace makes opencode
  fail on `$install/.gitignore` — contained correctly, EROFS/ENOENT).
- Method: five parallel static audits plus live adversarial testing from
  inside `--profile agent`, `--profile tool`, `--profile none` and
  `--launch opencode` runs. Probes and PoCs under `~/a5ws` on the host.

## Verdict

**No filesystem or privilege escape from a contained profile was found.**
The namespace + bind + seccomp + mediation boundary held against
everything this pass threw at it, including the new-kernel surface. The
headline findings are trust-boundary and evidence breaks, three of them
demonstrated end-to-end:

- **C1 (High, demonstrated): the bridge's allowlist is IP-granular, not
  origin-granular.** `CONNECT registry.npmjs.org:80` (allowlisted) opens
  a tunnel to the CDN edge; the HTTP `Host` header inside the tunnel
  selects the real origin. A GET with `Host: example.com` returned the
  live Example Domain body (`Server: cloudflare`); a POST with `Host:
  example.net` reached that origin (405 from its application). Every
  allowlisted host on a shared CDN edge (Cloudflare, Fastly) is
  effectively an allowlist of that CDN's whole customer set for
  plaintext HTTP — a full read/exfil channel to origins the operator
  never named, and the receipt's `proxy.net` evidence records only the
  allowed CONNECT destination (`example.com` appears nowhere in the
  receipt). Host-only allowlist entries admit ports 443 **and** 80.
  Demonstrated both synthetically and model-driven: an opencode run
  asked to use its bash tool performed the two-stage swap and reported
  the foreign origin's 200.
- **C2 (Medium, demonstrated): the fourth audit's B1 guard's
  child-visibility model is wrong for `none`.** `check_config_isolation`
  compares child-visible *policy roots*, but a `--profile none` child
  sees the whole host. A `none` run planted
  `[jail.network] allow=["example.org:443"]` +
  `[jail.observation] mode="off"` into `~/.config/ouro/config.toml` with
  no refusal; the next, completely plain `--profile agent` run then
  CONNECTed through the bridge to `example.org:443` (`200 Connection
  established`) with observation off. Same end-state as B1, reached
  through a profile whose receipt merely says `child_protection:
  unprotected`.
- **C3 (High-class impact, Medium prerequisite, demonstrated
  end-to-end): nothing isolates the supervisor binary or the resolved
  bubblewrap.** One `--rw ~/.local/bin` grant (not refused by any guard)
  let a `tool`-profile child rename-replace `ouro-jail` (`ETXTBSY`
  blocks in-place writes but not `rename`); the operator's very next
  `ouro-jail` invocation executed the child's wrapper **outside any
  containment**. Same one-pointed-grant prerequisite class as B1 (which
  was rated High), strictly larger effect: durable operator-uid code
  execution. The bwrap half needs an operator-writable backend location
  (stock `/usr/bin/bwrap` is root-owned; `bootstrap_main` execs the
  resolved pathname with no identity re-check, watch.rs:191-198).

## Findings

### C1 (High, demonstrated end-to-end) — bridge allowlist is destination-IP-granular; CDN Host-header swap reaches arbitrary co-tenant origins; evidence blind to the inner destination

The proxy checks the CONNECT authority (`proxy/http.rs`: strict parser,
Host must equal target after normalization — all re-verified live: the
one-stage swap `CONNECT npmjs:80` + `Host: example.com` is correctly
`400`). It cannot check anything after `200 Connection established` —
and on port 80 of a CDN edge, the byte that selects the origin is the
Host header of the *tunneled* request.

Demonstrated, three stages:

1. `CONNECT registry.npmjs.org:80` (matching Host) → `200 Connection
   established`; then `GET / HTTP/1.1` `Host: example.com` inside the
   tunnel → `200 OK`, `Server: cloudflare`, full Example Domain body.
2. `POST /` `Host: example.net` → `405 Method Not Allowed` **from
   example.net's origin** — arbitrary-method HTTP to a foreign origin.
3. Under `--launch opencode`, opencode's bash tool ran the two-stage
   script and reported the swapped-origin `200 OK` response line.

Ports: with a host-only allow entry, CONNECT to 443 and 80 succeeds
(8080/4443/8443 refused `403` by the bridge). The bundled opencode
profile's `allow = ["opencode.ai", "models.opencode.ai",
"registry.npmjs.org"]` entries are host-only, so port 80 is open to
every run.

Impact: confidentiality break of the agent profile's "allowed hosts
only" promise — exfiltration to and content fetch from any origin
sharing an edge IP with an allowlisted host (any attacker-controlled
domain on the same CDN), invisible to the receipt (`proxy.net` records
the CONNECT destination only; verified: `example.com` appears nowhere in
the attempt receipt). Not a host compromise.

Fix direction: refuse plaintext ports (80) for host-only entries unless
the entry names the port; or hold the tunnel closed until the first
inbound bytes (SNI for TLS, Host for HTTP) are inspected and matched
against the entry; at minimum, document that allowlist entries are
IP/CDN-granular and record the limitation in the receipt.

### C2 (Medium, demonstrated end-to-end) — the B1 config guard does not model `none`'s real filesystem visibility; a `none` run plants the trusted widening layer

`check_config_isolation` (supervisor.rs:2389-2424) refuses child-visible
*roots* overlapping the config directory, and `child_visible_roots`
(supervisor.rs:2211-2233) enumerates workspace, host scratch and rw/ro
grants — under `none` the child's real visibility is the entire host
filesystem, which the enumeration does not model. The guard therefore
passes while the child can write `~/.config/ouro/config.toml`
(`read_operator_file`'s identity checks — operator uid, 0600, single
link — are all satisfiable by the same-uid uncontained child).

Demonstrated live: the `none` run planted the config (echoed back its
own plant); the next plain `--profile agent` run, with no
`--allow-host`, got `CONNECT example.org:443 → 200 Connection
established` through the bridge and ran with `observation mode=off`.
Every later contained run inherits child-chosen egress and blind
observation until the operator notices the file.

Severity is bounded by `none`'s explicit uncontained opt-out for the
planting run itself — but the widening persists into *contained* runs
the operator did not opt out of, which is exactly the harm B1 was filed
against. Fix direction: under `none`, treat every guarded tree
(config, launch, state, receipt) as child-visible for the isolation
guards, or bind a supervisor-held snapshot of the config instead of
re-reading the live file; at minimum refuse `none` runs while a
`config.toml` exists.

### C3 (Medium, demonstrated end-to-end) — no isolation guard covers the supervisor binary or the resolved bubblewrap; one rw grant over either replaces the code the next run executes outside the boundary

`check_state_isolation`, `check_launch_isolation`,
`check_config_isolation` and `validate_receipt_path` guard the four data
trees. Nothing guards `current_exe()` or the canonicalized bwrap path
(`resolved_bwrap`, platform.rs:179-197) against `child_visible_roots`;
`bootstrap_main` (watch.rs:191-198) execs the resolved pathname with no
identity re-check or fd-exec — in contrast to every bind source, which
is pinned by openat2 descriptor and swap-verified before spawn.

Demonstrated live: `--profile tool --rw /home/ubuntu/.local/bin`
accepted; the child `cp`'d the binary to `ouro-jail.real`, wrote a
wrapper, and `mv`'d it over `ouro-jail` (in-place write hits `ETXTBSY`,
rename does not); the operator's next `ouro-jail version` executed the
child's wrapper outside any jail. Restored immediately after.

Same one-pointed-grant prerequisite class as B1 (High): the operator
must grant rw over a directory containing the supervisor (or a
writable bwrap). Effect is strictly larger than B1's policy takeover:
arbitrary operator-uid code, run-independent, jailed and unjailed
invocations alike. Fix direction: add both binary identities to the
isolation guards (refuse child-visible roots containing them) and exec
bwrap through a pinned, identity-verified descriptor.

### C4 (Medium, demonstrated) — the B2 fix misses compat-ABI `clone3`: an i386 `clone3(CLONE_UNTRACED)` under `none` executes and the receipt records a bounded `foreign_abi` gap instead of the open-ended `untraced_descendant` gap

The narrowing filter refuses the *native* `clone3` (435) with ENOSYS
precisely because its flags live in memory a BPF filter cannot read —
but the filter's first rule sends every non-x86_64 architecture to
`SECCOMP_RET_TRACE` before any number comparison (tracer/filter.rs
`build_into` out[1]), and `compat_special` (session.rs:1403-1436) knows
only i386/x32 `seccomp` (354/317) and `clone` (120/56). i386 `clone3`
is also 435; x32 spells it 435|0x40000000. Under `none` the baseline's
arch-EPERM does not exist, so the call stops at the tracer, is followed
as `InFlight::Foreign`, and executes.

Demonstrated live: the PoC mapped a low page, wrote
`clone_args{flags=CLONE_UNTRACED, exit_signal=SIGCHLD}` and issued
`int 0x80` with eax=435. Output: `UNTRACED CHILD alive, pid=2139145`
(the clone child returns 0 and printed from inside the untraced
descendant). The receipt: outcome `signaled`, errors
`[evidence_lost]`, `foreign_abi` present, `untraced_descendant`
**absent** — the bounded class, with coverage reasserted after one
counted interval, while a process the observer never attached to was
alive inside the run. Contained profiles are not reachable: live under
`agent` the same PoC returned EPERM (baseline denies the foreign arch
first) — same scope as B2 itself, receipt-integrity class.

Found independently by two of the five static audits (fix-code and
boundary) and confirmed live here. Fix direction: refuse the compat
`clone3` numbers in the filter before the architecture branch, or
classify any foreign-arch `clone3` success as the open-ended
`Untraced` gap.

### C5 (Low, demonstrated) — the resolv.conf sanitizer fails open on a non-UTF-8 host file, binding the host file verbatim

On an unreadable host resolv.conf the child inherits EACCES (verified),
but on a readable file whose bytes are not UTF-8 the sanitizer cannot
parse and the run proceeds with the **host file bound verbatim**:
verified live with a planted binary-junk resolv.conf — the child's
`/etc/resolv.conf` carried `search corp.internal evil.example` and the
raw non-UTF-8 bytes, the exact host-fact disclosure audit 2's F5
hardening exists to strip. Impact bounded (the child's resolver is
unreachable in its netns; the file itself is the disclosure). Fix:
fail closed (refuse the run or ship an empty nameserver file).

### C6 (Low, demonstrated) — the workspace and scratch never pass the pseudo-filesystem grant refusal

`refuse_pseudo_fs_grants` runs on `extra_ro_binds`/`extra_rw_binds`
only (platform.rs:906-907); the workspace and scratch base rows are
built inside `BwrapPlan::mount_table` and never checked. Live:
`--workspace /dev/shm` ran and the child wrote the host's shared
memory (`/dev/shm/a5shm` appeared on the host) — a rw channel into a
host-visible tmpfs. `--workspace /run/user/1000`, `--workspace /proc`
and `--workspace /tmp` all **failed closed** on this host, but by
accident of the protected-segment scan hitting unreadable entries
(`cannot read /run/user/1000/systemd/inaccessible/dir: EACCES` →
`missing_capability` refusal), not by the guard. Operator-act (the
child cannot choose the workspace), guard-asymmetry class. Fix: run
the workspace and scratch sources through the same refusal.

### C7 (Low, static) — `alias_conflict` only follows mounts on the guarded tree's own device; a cross-device submount is invisible

`conflict_in_mounts` (state/mount_alias.rs:203-240) skips every
mountinfo entry whose `dev` differs from the guarded tree's containing
mount; the sibling `alias_identities` (~145-155) extends to submounts
on other devices. An operator bind of a second filesystem mounted
*inside* the state/config/launch tree into a child-visible root evades
the alias guard. Operator-assisted (both mounts are operator acts) —
the same trust class B4 was filed under. Fix: give
`conflict_in_mounts` the submount walk `alias_identities` already has.

### C8 (Low, static) — the B1 read-hardening covered `config.toml` only; `--profile FILE` is still a plain `read_to_string`

supervisor.rs ~316-321: unbounded, symlink-following, no regular-file
check — a fifo blocks resolution indefinitely (outside the prepare
budget), a symlink to `/dev/zero` grows without bound. Impact capped
by the layer's `narrowing: true` semantics (no grants, no egress, no
observation-off; `extends = "none"` refuses): a supervisor DoS for an
operator who points `--profile` at a child-visible path. Fix: route it
through `read_operator_file`'s hardened reader.

### C9 (Low-Medium, static) — protected-coverage scan race: a `.git` created between readdir and mount is missed while the receipt claims `existing_and_root`

`fs.rs walk()` reads each directory's entries once and never rechecks;
between the workspace readdir and bwrap's spawn (a multi-second window:
pinning, placeholders, fd map), a *concurrent* run's child can create
`<ws>/.git` in a directory whose entries were already consumed. It gets
no ro-bind, and as a root-level literal it also dodges the
`absent_root_literals` placeholder. The receipt then certifies
`protected_coverage: existing_and_root` for a launch-time-existing,
writable segment — plantable with `.git/hooks/*` that the operator's
next `git commit` executes outside the jail. Same-run children cannot
hit the window (they do not exist during the scan). Fix: re-stat
scanned directories after the walk and before spawn, or reword the
claim to snapshot semantics.

### C10 (Info) — kernel 7.0 syscall drift against the default-allow baseline

Live-probed under `agent` with header-verified numbers:

- `settimeofday` (164) — EPERM from the kernel's capability check, not
  from the filter: the one member of the time-adjustment family B8's
  fix did not add to `DENY_EPERM` (`adjtimex`/`clock_settime`/
  `clock_adjtime` are there).
- `open_tree_attr` (467) — **succeeded** (returned an fd); inert today
  (`move_mount`/`fsconfig` are EPERM) but it is mount-API surface the
  spec's "every mount interface old and new" rationale says should not
  ship allowed by accident.
- `listns` (470), `file_getattr` (468), the `xattrat` family (463-466)
  — reach the kernel (EFAULT/EINVAL), i.e. allowed by the filter.
- `file_setattr` (469) — allowed by the filter but the read-only-mount
  check holds: `setattr(NODUMP|projid)` on an ro-granted file returned
  `EROFS` (verified with the correct 24-byte `struct file_attr` ABI);
  `chmod` by path is `EROFS` as well.
- `fanotify_init` (300) — kernel EPERM (capability), unreachability
  not a deny, the standing S10 class.

### C11 (Info) — hygiene from the parallel audits

- A same-uid child can `SIGSTOP` the bridge or the namespace init: a
  silent self-DoS the exit-only helper note never reports (agent-net
  audit).
- The receipt's `--receipt` copy at a path that *becomes* child-visible
  through a later grant is a cross-run caveat, not a same-run hole
  (lifetime audit).
- `create_private_dir` in platform.rs accepts a pre-existing directory
  without identity/mode checks, unlike state.rs's (boundary audit);
  unreachable behind the isolation guards.

## What was attacked and held (live)

- **Fourth-audit fixes re-verified**: B1 — `--ro`/`--rw` over the config
  directory and over `config.toml` itself all refuse
  (`unsafe_config_path`); an honest 0600 config loads and applies;
  `OURO_CONFIG_DIR` inside the workspace refuses; a group-writable
  planted config refuses to load. B5/B6/B7/B9 read solid (statics;
  state lease, wall parse, `/run` refusal including the `--ro /run`
  grant, dual digests). B3's inode-first exec corroboration: two
  independent audits found no false-confirm path.
- **Mediation battery (agent)**: direct `connect` to
  `/run/ouro/proxy/proxy.sock` → `EACCES`; via a symlink planted in
  vendor state → `EACCES`; nonexistent path under `/run/ouro` →
  `EACCES`; `/run/ouro/../` spelling → `EACCES`; overlong address →
  refused; socketpair and abstract sockets (own netns) work. The
  mediator's dup-and-pinned-connect design (no
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, address copied from the parked
  child, connect performed on the duplicate to an inode-pinned node)
  survives argument-race attempts by construction.
- **Bridge battery**: the one-stage Host mismatch is `400` (parser
  strictness held); `CONNECT example.org:443` (not allowlisted) →
  `403`.
- **Hardlink shield**: `link()` and `linkat(AT_EMPTY_PATH)` from an
  ro-granted file into the writable workspace → both `EXDEV`.
- **New-kernel setattr**: `file_setattr` on an ro grant → `EROFS`
  (kernel check holds on the brand-new API).
- **`--workspace /proc` and `/run/user/1000`**: refused (by the
  protected-scan fail-closed, C6's accident — not exploitable today).
- **opencode red-team (model-driven)**: the hostile-fetch task executed
  only through the C1 channel — every in-boundary probe (direct proxy
  socket, symlink mediation, out-of-workspace writes) was refused by
  the mechanisms above.
- **Static (five parallel audits)**: bind-source pinning and TOCTOU,
  fd hygiene/CLOEXEC on every spawn path, environment construction and
  PATH, policy layering and TOML parsing (duplicate keys, overflow),
  scratch freshness, limits parsing, credential staging, gc
  reconciliation identity checks, records redaction, cgroup identity
  pinning, watcher fd hygiene, sockdiag strict parsing, proxy
  admission/chunked revalidation/resolver policy, tracer stop-type
  handling/restart codes/compat decoding/pid reuse — all re-verified
  with no additional bypass beyond the findings above.

## Artifacts (on the VPS)

- `~/a5ws/` — probes and PoCs: `a5_sysprobe(.c)` (drift sweep),
  `a5_fsx2.c` (file_setattr ABI), `a5_battery.py` (mediation + ports),
  `a5_verify.py`, `a5_stage2.py` (C1 two-stage swap), `a5_c3(.c)` (C4
  clone3), `a5_linkat(.c)`, plus the supervisor-replacement demo
  commands (C3, in the transcript).
- Receipts: `/tmp/a5-c3.json` (C4). C1 receipts under
  `~/.local/share/ouro/attempts/att_ff76a291…` and `att_fe431079…`.
- Host state restored and verified after every demo: supervisor binary
  restored (`~/.local/bin` holds only `ouro-jail`), planted config
  removed, resolv.conf restored (systemd stub), `/dev/shm`, `/tmp`,
  `/run/user/1000` markers removed, `ptrace_scope` untouched.

## Recommended fix order

1. C1 — bind allowlist entries to origin, or close plaintext ports /
   inspect the tunnel's first bytes; record the granularity honestly.
2. C3 — isolate the supervisor and bwrap identities like the config
   tree; exec bwrap by pinned descriptor.
3. C4 — refuse or open-end the compat `clone3` spellings.
4. C2 — model `none`'s real visibility in the config/launch/state
   guards (or snapshot the config).
5. C6, C7 — pseudo-fs check for workspace/scratch; cross-device alias
   walk.
6. C9, C5, C8 — post-scan re-stat; resolv fail-closed; hardened
   profile read.
7. C10 — add `settimeofday` (164) and the 463-471 surface to the deny
   table or the documented exclusions.
