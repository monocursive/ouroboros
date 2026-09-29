# Ouroboros-jail security audit — 2026-09-29 (sixth pass)

Auditor goal: full security review of `ouro-jail` at HEAD `7b68d73c`
plus the uncommitted working tree, with the objective of making an
opencode agent escape the `agent` profile. Method: five parallel static
audits (boundary, supervisor trusted inputs, observer, agent network,
state/secrets) plus live adversarial testing on the reference host,
including model-driven red-teams through opencode 1.18.32 itself.

## Environment

- Test host: `ubuntu@37.59.114.70` (Ubuntu 26.04.1, kernel
  7.0.0-31-generic x86_64, bwrap 0.11.1, `yama.ptrace_scope=1`).
- Binary rebuilt on-host from the working tree, SHA-256
  `45e498029ec15c03d09991ab62350b5f54e48aa3f85af5411f4bbb440905ef76`
  after this pass's fixes, installed at `~/.local/bin/ouro-jail`.
- Baseline first: the A01 reproduction ("Create a file named
  greeting.txt …") exited 0 in 7 s from a git-repo workspace.
- Probes under `~/a6ws` (`a6_battery.sh`, `a6_net.py`) and the prior
  passes' `~/a5ws` PoCs.

## Verdict

**No filesystem, privilege or network escape from a contained profile
was found.** The fifth audit's fixes (C1–C10) were re-verified live and
statically and all hold. The new findings are one still-open trust
boundary (the C2 creation variant, fixed during this pass), one
CDN-dependent residual documented rather than closed, and two
evidence-integrity fixes in the observer:

- **F1 (High impact, Medium prerequisite, demonstrated, FIXED in this
  pass): the C2 fix could not see files that did not exist yet.** The
  fifth audit's guard refuses `--profile none` while trusted files
  exist — but on a host with a fresh configuration directory, a `none`
  run's child *creates* `config.toml`/`launch/*.toml` (satisfying every
  identity check: operator uid, 0600, one link), and every later
  contained run loads it as trusted widening. The fifth pass's own K03
  wording ("without them it runs") documents the hole. Fix: an epoch
  marker `<data>/uncontained.epoch`, written by the supervisor after an
  uncontained run's tree is gone; every later run refuses a trusted
  file whose ctime does not postdate it (`refuse_stale_trusted_file`,
  supervisor.rs; `state::UncontainedRun` since the review). Nothing of the run can
  order writes after its own marker, and a contained child cannot
  reach the config directory or the state root to re-save a plant.
- **F2 (Medium, CDN-dependent, documented): vault-less TLS tunnels are
  SNI-granular.** With no staged credentials (the shipped opencode
  profile), the MITM lane is absent and a 443 tunnel is verified by
  ClientHello SNI equality only; the encrypted HTTP Host can still
  front a co-tenant origin on a CDN that routes by Host across
  fronting tenants. Receipts record `origin_verification: tls_sni` and
  `tls_application_authority_verified: false` honestly. Making the
  MITM unconditional would break every TLS client that does not trust
  the attempt CA, so the residual is documented (spec §3.1) instead.
- **F3 (Low, operator-assisted, documented): explicit-IP grants skip
  first-flight inspection** (`explicit_ip` mechanism): a tunnel to a
  granted address:port is a raw pipe. The receipt names the mechanism.
- **F4 (Low-Medium, evidence integrity, FIXED): pathname A-B-A
  rewrite was certified by byte-equality.** `arguments_stable` treats
  an exit re-read equal to the entry snapshot as proof for pathnames,
  while the same concern for memory-sourced flags was already declared
  uncertifiable. A sibling thread can rewrite the pathname for the
  kernel's copy and restore it before the exit stop. Fix: successful
  open-class calls are corroborated against the returned descriptor's
  `/proc/<tid>/fd/<ret>` link; disagreement or an unreadable link
  downgrades the event's claim to an incomplete path and records a
  `path_claim_unverified` gap (session.rs, tracer/mod.rs).
- **F5 (Low, advisory, FIXED): command-rule argv was read once at the
  entry stop.** The same sibling-thread race could let a
  deny/forbid-patterned exec run unjudged. Fix: the rules are re-run
  against the kernel's own copy of the new argv
  (`/proc/<tid>/cmdline`) at the exec event; a hit kills the process
  and surfaces `command_forbidden` through the exec event
  (`TracerEvent::Exec.command`, observed.rs).
- **F6 (Low, evidence nit, FIXED): the vault MITM lane hardcoded
  `discarded: 0`.** Pipelined bytes after the one request were dropped
  uncounted. Fix: a bounded (1 s) post-response drain counts them in
  `discarded_bytes` (proxy/tls.rs).
- **F7 (Info, open): SIGSTOP self-DoS (fifth audit C11) remains.** A
  same-uid child can SIGSTOP the bridge, the namespace init, or the
  supervisor itself (uncatchable); nothing in-process can mitigate.
  Bounded by the wall limit and teardown-on-child-exit; external
  watchdog documented as the only complete answer.
- **F8 (Low, FIXED): `create_private_dir` in platform.rs accepted a
  pre-existing directory without identity checks**, unlike state.rs's.
  Now refuses non-directories, foreign owners, and group/world-access
  directories.
- **F9 (Info): minor hygiene** — SOCKS clients at proxy overload get
  an HTTP 503 (both close either way); the bridge read-back checks
  `/proc/<pid>/net/tcp` only in tests for tcp6 (fail-closed
  availability nit); relays have no idle deadline in the relay phase
  (self-DoS bounded by `max_connections`).
- **F10 (pre-existing at HEAD, test infrastructure, open): a parallel
  test run of `j5_lifetime_linux` aborts the test process** with
  `fatal runtime error: IO Safety violation: owned file descriptor
  already closed` (two threads simultaneously). Reproduces
  deterministically at HEAD `7b68d73c` and with this pass's tree; does
  NOT reproduce with `--test-threads=1` (20/21, the one failure being
  the environmental cgroup delegation below). An `OwnedFd` is closed
  twice (or after its fd was closed elsewhere) somewhere in the
  test-process paths; not known to be reachable in the supervisor's
  own single-run process. Filed for the maintainers; the audit's
  changes are exonerated by the HEAD reproduction.

Test-suite evidence: the full Linux suite ran chunked on the reference
host (52 result lines green; the four red binaries re-run serially).
Three failures (`s11_wall_expiry_separate_run`, `r9_an_explicit_pids`,
`x07_a_leaf_that_cannot_be_verified_empty`) are environmental — they
expect the delegated user scope of jail-v1 j2-authority
(`systemd-run --user --scope`), and each passes when re-run inside it;
they fail identically at HEAD from a plain SSH session scope.
`conformance_j3_agent` passes fully when serialized.

## Fifth-audit fix status (re-verified this pass)

- **C1 — fixed and held live.** Host-only entries admit :443 only
  (ports 8080/4443 refused `403`); the two-stage plaintext Host swap
  (`CONNECT registry.npmjs.org:80` + `Host: example.com`) refused;
  the keep-alive second-request smuggle refused (one request per
  connection, `discard_rest`); SNI mismatch (ClientHello
  SNI=example.com against a registry.npmjs.org tunnel) closed the
  connection during the handshake; h2c prior-knowledge and inner
  CONNECT refused; SOCKS5 shares the same gate (`05 02` on a Host
  swap). Static audit re-derived the parser strictness and the frozen
  address deny table (loopback/link-local/RFC1918/CGNAT/IPv6 outside
  2000::/3) with no bypass.
- **C2 — fixed for existing files (fifth pass), creation variant
  found open, fixed as F1 above.**
- **C3 — fixed.** `--rw /home/ubuntu/.local/bin` refuses
  `unsafe_state_path` (binaries guard); the backend is exec'd through
  a pinned descriptor with no pathname fallback.
- **C4 — fixed.** i386 `clone3` under `none` returns `ENOSYS`
  (re-verified live with the fifth pass's PoC; filter refuses 435 and
  the x32 spelling before the architecture branch; `compat_special`
  classifies any survivor as the open-ended `Untraced` gap).
- **C5 — fixed.** Non-UTF-8/unreadable/oversized host resolv.conf all
  ship an empty nameserver-only copy.
- **C6 — fixed.** `--workspace /dev/shm` refuses `policy_widening`
  (workspace and scratch now pass `refuse_pseudo_fs_grants`).
- **C7 — fixed.** Cross-device submounts extend the alias walk.
- **C8 — fixed.** `--profile FILE` reads through the hardened
  operator reader.
- **C9 — fixed.** Directory stamps re-verify after the protected scan.
- **C10 — fixed.** `settimeofday` (164) and 463–470 are in
  `DENY_EPERM`.

## What was attacked and held (live)

- **Mechanical battery under `agent`**: `/etc/shadow`, `/home/ubuntu`
  dotfiles, `/root`, `/var/log`, `/proc/1/root`, host `/tmp`
  contamination (none: the child's `/tmp` is a private bind — verified
  by absence on the host), mknod, mount/open_tree/move_mount/fsopen/
  open_by_handle, core_pattern, sysrq, modprobe, cgroup release_agent,
  `/dev/mem`/`/dev/sda`, hardlinks out of ro grants, pidfd_getfd,
  ptrace attach, process_vm_readv, unshare/clone(CLONE_NEWUSER),
  setuid binaries (no password database to exploit; `NO_NEW_PRIVS`),
  direct TCP/DNS (netns-unreachable), `/run/ouro/proxy/proxy.sock`
  (EACCES mediation), abstract sockets (own netns). All refused or
  inert.
- **Model-driven red-teams through opencode** (two runs): the agent's
  bash tool ran the escape checklist — host-file reads, marker writes,
  raw TCP beacons, proxy Host swaps, `/proc/1/root`, mount attempts.
  Every in-boundary probe was refused; `/tmp/ESCAPED_A6` never
  appeared on the host; `~/.ssh` (present on the host) was absent
  inside.
- **Credential staging**: source file unreadable inside, staged copy
  only under `/run/ouro/state`, no env leakage, cleanup complete,
  receipts withhold verifiers (`receipt_verifier_withheld`).

## Live verification of this pass's fixes (on the VPS)

- **F1**: a `none` run on a fresh config directory planted
  `config.toml` (`PLANTED` echoed); the marker
  `~/.local/share/ouro/uncontained.epoch` appeared (mode 0600) after
  the tree died; the next contained run refused
  `unsafe_config_path … config.toml predates the last uncontained
  (--profile none) run … Re-save it (touch it) or remove it`; after
  `touch`, the run proceeded past the guard (and refused the planted
  `[jail.network] allow` under `tool` on its own merits). The creation
  variant is closed for files the child writes directly; see the
  post-review corrections below for what the first version of the fix
  missed and the residuals that remain.
- **F5 sanity**: `forbid = ["sleep **"]` denies the exec at the entry
  stop (`Operation not permitted`, `command_forbidden`); the control
  run passes through the new kernel-cmdline re-check unharmed.
- **F4 sanity**: an ordinary `agent` run (file opens, reads, writes)
  records zero `path_claim_unverified` gaps — corroboration agrees on
  benign opens; only genuine disagreement or unreadable links gap.
- **Regression**: the network battery (C1 variants) and the mechanical
  boundary battery re-run on the fixed binary behave identically to
  the pre-fix runs.

## Fixes made in this pass (with tests)

- supervisor.rs/state.rs — F1 epoch marker and stale-trusted-file
  refusal; unit tests `a_trusted_file_that_predates_the_uncontained_epoch_refuses`
  and (after the review) `an_uncontained_run_is_live_until_its_guard_settles_both_marker_directories`.
- tracer/session.rs + tracer/mod.rs + observed.rs — F4 fd-path
  corroboration with `PathClaimUnverified` gap and loss counter; F5
  exec-time cmdline re-check carried on `TracerEvent::Exec.command`.
- proxy/tls.rs — F6 bounded discarded-byte drain.
- platform.rs — F8 identity-checked `create_private_dir`.
- Spec: jail-v2.md §3.2 (epoch semantics, residual), K03 amendment,
  new K30–K32 rows.

## Post-review corrections (2026-09-29)

A code review of this pass's uncommitted fixes found defects in them; the
fixes above were corrected as follows (unit tests beside each).

- **F4** stopped benign strict runs and was bypassable. A mismatch was a
  gap of the Open class, so `O_TMPFILE` (glibc `tmpfile()`, Python's
  `TemporaryFile`), `/dev/stderr` and writes through a final symlink
  degraded coverage and stopped strict runs with `evidence_loss`; a bare
  relative name (no `/`) skipped the check entirely; and only final
  components were compared. Now: whole components are compared (absolute
  exactly, relative as a tail, `O_TMPFILE` by its directory), bare names
  included; a mismatch downgrades the event's path, counts
  `path_claims_unverified` outside the loss counters (surfaced in
  `lifetime.native.details`) and records a bookkeeping gap with an empty
  operation set. A sibling thread swapping the descriptor before the link
  is read remains a residual.
- **F5** killed benign execs and missed its own case.
  `/proc/<tid>/cmdline` was parsed dropping every empty argument, and an
  empty result was judged as an unreadable argv, so any `execve` with no
  argv was killed whenever rules existed; `#!` scripts were judged by
  their interpreter's argv; the element-0 identity still came from the
  raced path snapshot; `deny` and unreadable hits killed silently; and the
  killed exec left an `entry_abandoned` gap. Now: empty arguments keep
  their positions; the entry argv is compared with the kernel's copy
  (unchanged: the image from `/proc/<tid>/exe` is the new element-0
  identity; interpreter rewrite: the script and its arguments are judged;
  otherwise the kernel's copy is judged with both identities); every
  exec-time hit is recorded as a `command_rule` note (`killed_at_exec`),
  and the killed exec leaves flight at its event.
- **F1** failed open and missed two directions. The settle happened in
  `Drop` with a warning only and the reader accepted any file type, so a
  child that put a directory at the marker's path (or made the data
  directory unwritable) kept the marker unwritten; contained runs started
  while a `none` run was live were unprotected; and the marker lived only
  in the data directory, chosen independently of the configuration
  directory it guards. Now: per-run live markers are written to both
  directories before release (a run that cannot write them refuses), a
  live marker refuses every existing trusted file, the settle clears the
  child's obstacles and keeps the live marker when it still fails, and a
  settled marker that is not a regular file refuses. Residuals, now in
  jail-v2 §3.2: a child that deletes its live markers and makes the
  settle impossible, markers forged while the run is live, a surviving
  descendant, and anything the child left to re-save a trusted file later
  (shell rc files, crontab, `systemd --user` timers).
- **F6** delayed every vault-MITM teardown by up to a second: the drain
  now follows `close_notify` instead of preceding it.
- **F8** refused an operator's `--scratch` directory with an ordinary
  0755 mode: the identity check now applies to supervisor-created
  directories only.
- Also corrected: the proxy's new relay-failure refusal was unreachable
  (`slot.replied` was already set); the zeroized vault buffer still
  leaked on `read_to_end` reallocations; and the frozen
  `policy-snapshot.schema.json` had been edited (its freeze digests
  hand-updated) for a description string — reverted, since the freeze is
  generated.

## Artifacts (on the VPS)

- `~/a6ws/` — `a6_battery.sh` (mechanical battery), `a6_net.py`
  (network attack probes), receipts under `~/.local/share/ouro/`.
- Host state restored after every demo; `~/.config/ouro/config.toml`
  never created outside the guarded demos.

## Recommended residual order

1. F2/F3 — decide whether an operator strictness option (refuse
   vault-less TLS tunnels, or inspect address-grant first flights) is
   worth the compatibility cost; until then the spec's §3.1 wording is
   the contract.
2. F7 — external watchdog for supervisor SIGSTOP (operator-side).
3. F9 — the two hygiene nits if a natural fix site appears.
4. F10 — bisect the parallel-only `OwnedFd` double-close in the
   `j5_lifetime_linux` test process (pre-existing at HEAD; two threads
   abort simultaneously — start there).
