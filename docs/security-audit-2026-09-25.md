# Ouroboros-jail security audit — 2026-09-25

Auditor goal: full security review of `ouro-jail` (jail-v1, revision `d7c0d36b`),
with the objective of making an opencode agent escape the `agent` profile.

## Environment

- Test host: `ubuntu@37.59.114.70` (the reference host itself: Ubuntu 26.04.1,
  kernel 7.0.0-31-generic x86_64, bwrap 0.11.1, yama ptrace_scope=1, AppArmor
  userns restriction on, linger enabled for `ubuntu`).
- Binary built on-host from `d7c0d36b` (`cargo build --release -p ouro-jail`),
  SHA-256 `cb82dbe640f76e7ff1f66965f84ebb5ad637be6683ef8c378d158a7288e63397`,
  installed at `~/.local/bin/ouro-jail`.
- OpenCode 1.18.32 at `~/.opencode/bin`, bundled launch profile copied to
  `~/.config/ouro/launch/opencode.toml`.
- Baseline A01 reproduction passed: `ouro-jail run --launch opencode --ro
  ~/.opencode/bin -- ~/.opencode/bin/opencode run "…"` → exit 0, file written,
  receipt settled, all coverage classes active.

## Verdict

**No containment escape found.** After static review (4 parallel source audits:
bwrap plan, agent network/mediation, seccomp/observer, credentials/lifecycle)
and live adversarial testing from inside the jail, the containment boundary
(namespaces + bind-mount view + seccomp baselines + mediation) held against
every attempted escape. The findings below are integrity/hygiene issues, one
demonstrated audit-integrity race, and several documented-limit confirmations.

## Live attack results (all from inside `--profile agent`)

### Filesystem — held
- Symlinks to host paths (`/home/ubuntu/.ssh/…`, `/etc/shadow`, `/proc/1/root/…`): ENOENT (closed view).
- `../../..` traversal: confined to sandbox tmpfs root.
- Writes to `/etc/passwd`, `/usr/...`, `/proc/sys/kernel/hostname`, `core_pattern`: EACCES/EROFS.
- `link()` from ro system files: EXDEV/EPERM; `mknod`: EPERM; `chroot/mount/unshare/setns/pivot_root/fsopen family`: EPERM (baseline denies).
- `open_by_handle_at`, `name_to_handle_at`, `userfaultfd`, `bpf`, `perf_event_open`, `io_uring_*`, `keyctl`, `syslog(2)`: EPERM.
- `clone3`: ENOSYS; `clone(CLONE_UNTRACED)`: EPERM; `TIOCSTI`: EPERM.

### Process — held
- uid 1000, all capability sets empty, `NoNewPrivs:1`, `Seccomp:2` with 3 stacked filters.
- PID 1 is bwrap's sandbox init; bridge double-forked (reparented to init), so `/proc/<bridge>/mem` is YAMA-blocked (EACCES) from the target.
- `/proc/<peer>/environ|fd|maps` of bwrap-init/bridge readable (same uid, read-class) — contents are env-cleared, nothing sensitive.
- Fork bomb under `--limit pids=32`: "Cannot fork", contained. Wall `--limit wall=5s` killed the tree at ~5 s (exit 143).
- Supervisor SIGKILL mid-run: outside watcher killed bwrap + whole cgroup leaf; no survivors (`gc` then reconciled state and removed leaves).

### Network — held
- Bridge `127.0.0.1:3128` reachable in-netns only; `CONNECT 127.0.0.1:22` → 403 `host_not_allowed`.
- Host unix sockets (`/run/systemd/journal/socket`, `/var/run/docker.sock`, `/run/ouro/state/...`, workspace paths): EACCES from the mediator (no listener in attempt netns).
- `AF_NETLINK`/`AF_PACKET`: EAFNOSUPPORT (family allow-list).
- UDP `sendto(127.0.0.53:53)` succeeds at syscall level but the netns is private (no resolver) — DNS dead in-jail, resolution happens host-side in the proxy.
- `tool` profile: AF_UNIX denied outright (socket creation fails), no bridge.

### opencode red-team — held
- Hostile prompt (free model) refused; reframed diagnostics run: `curl example.com`/`ifconfig.me` → `host_not_allowed`; `getent` → dead DNS; `/dev/tcp/127.0.0.1/22` → refused; `ls /home` → skeleton dirs; `/etc/passwd` read blocked by opencode's own permission system (`external_directory` auto-reject).

## Findings

### F1 (Medium, integrity) — openat2 argument-snapshot TOCTOU lets the child corrupt/suppress audit events while strict evidence still reports "no gaps"
`tracer/session.rs` reads pointed argument structs (e.g. `openat2`'s `struct
open_how` flags) via `process_vm_readv` at the syscall-entry stop; the kernel
re-reads the struct from user memory after the tracer resumes. A malicious
child can race the struct between the two reads.
Demonstrated live (`race4` PoC, 8 s, ~500k openat2 calls against `/etc/passwd`):
kernel-applied mutations 250,441 vs recorded WR-classified events 250,593 —
≥152 phantom events (recorded mutation that the kernel applied as read-only),
and by symmetry real mutations recorded as read-only are suppressed entirely
(`fs.read` is not a coverage class). Receipt: every coverage class `active`,
`gaps: []`, strict evidence passes. Containment is unaffected (mount-level
enforcement), but audit records can silently misreport what the child did.
Fix direction: pin argument structs by copying them into kernel-trusted memory
before the stop (e.g. have the launcher pre-copy via a blocked syscall), or
treat pointed-struct syscalls whose args the child can still mutate as
`coverage_gapped` by construction.

### F2 (Low–Medium, design carve-out) — the host proxy socket is directly connectable by the target
`unixpeer/live.rs:563` admits the authorized proxy by pinned `(st_dev, st_ino)`
regardless of connector. Verified live: `connect("/run/ouro/proxy/proxy.sock")`
succeeds from the target, bypassing the bridge entirely (raw HTTP spoken
directly to the outside proxy). The proxy still enforces destination rules, so
this is not an egress escape, but (a) the "only through the bridge" mental
model is wrong, (b) bridge-level accounting/`no_proxy` semantics can be
skipped, and (c) the child can hold the proxy's per-attempt connection budget
(128) hostage. Spec §10 words this as "except the authorized proxy", so it is
by design — worth documenting more loudly.

### F3 (Low, integrity) — mediated non-AF_UNIX connects run in the supervisor's LSM context
Documented in code (`NON_UNIX_NOTE`): an inner sandbox's Landlock network
denials do not compose through the mediator (the supervisor performs the
connect). Inner seccomp denials do compose. Affects inner-vendor-sandbox
fidelity, not the outer boundary.

### F4 (Low, hygiene) — transient leaked fd at target startup
Twice observed: an O_PATH fd on `/proc/<pid>/fd` (bridge-adjacent pid)
transiently present in the target's fd table at startup, closed shortly after
(reproduced under `/bin/sh -c` and seen vanishing between two syscalls under
python). No impact demonstrated: openat through it is YAMA-gated and the
referenced process holds nothing privileged. Unexplained; worth an fd-hygiene
look at the launcher's bridge-identity tie (`agent.rs` discover_bridge path).

### F5 (Info, documented limits confirmed live)
- Credential staging: staged file readable by the child at
  `/run/ouro/state/...` (0600), trivially copyable to the persistent workspace
  (`stolen.txt` survived settlement). The secret never appeared in receipt,
  trace, or state. This is the documented "copies made elsewhere" limit —
  operators must treat any staged credential as disclosed to the agent.
- `/etc/resolv.conf` inside the jail is the host's stub config: leaks host
  search domains (observed `tail826b0.ts.net openstacklocal`) — minor info
  disclosure.
- `copy_rw` credential sources lack the `nlink==1` check `bind_ro` enforces
  (source hardlinks could yield divergent copies) — operator-side hardening.
- Scout-noted: domain-fronting inside CONNECT tunnels (allowlist is
  name-based; shared-IP CDNs), and DNS-label exfiltration through wildcard
  allow rules via the host resolver — both inherent to an L7-name allowlist.
- Supervisor killed during bwrap startup without a delegated leaf (no linger)
  can orphan the namespace init — closed on this host by the scope step
  (`supervisor_scope: entered`) and the outside watcher; verified.

## What was attacked and held (summary)
bwrap argv construction (all six namespaces, O_PATH-pinned binds, `--bind-fd`
handoff, `--remount-ro /`, private `/proc`+`/dev`), seccomp baselines
(arch/x32 fail-closed, mount/ns/io_uring/ptrace/keyring/TIOCSTI denies),
AF_UNIX mediation (inode-pinned, sockdiag-validated, `RESOLVE_IN_ROOT`),
seccomp listener suppression attempt (kernel EBUSY: the mediation filter holds
the per-task notification role — verified live, matches spec §10), proxy
parser (strict CRLF/framing/Host rules), cgroup limits and tree kill,
watcher-on-supervisor-death, gc reconciliation, credential redaction.

## Artifacts (on the VPS)
- `~/work/a01/{attack,attack2}.c`, `recon.sh` — probe binaries.
- `~/work/red2/{race4.c,blind.c}` — TOCTOU PoC and listener-suppression PoC.
- Receipts/traces under `/tmp/r*.json`, `/tmp/trace*.ndjson`, `/tmp/red*.json`.
- Fake credential removed; `ocred` launch profile removed.

## Remediation (2026-09-25, same day)

All actionable findings were fixed in the working tree and verified on the
reference host. F4 was retracted after reproduction analysis.

### F1 — fixed: exit re-read of pointed arguments
`tracer/session.rs` now stores the entry-stop registers in `Pending` and, at
the syscall exit, re-reads every pointed argument the event asserts
(`open_how.flags`, pathnames, socket address family) and compares it with the
entry snapshot. Any disagreement — including memory that can no longer be
read — drops the event and records one `argument_snapshot_unstable` gap of
that call's classes (`GapReason` + `LossCounters.argument_snapshot_unstable`).
Registers are exempt (the kernel consumes the saved pt_regs). Spec updated:
jail-v1 revision 20, §§11.3–11.4.

### F2 — fixed: the proxy socket is bridge-only
`unixpeer/live.rs` admits the authorized proxy node only when the notifying
thread group matches the bridge's pinned `(tgid, start_ticks)`
(`MediatorHandle::restrict_authorized_connector`, set by `agent.rs`
`discover_bridge`; `None` until then, so the refusal is fail-closed). A target
naming `/run/ouro/proxy/proxy.sock` now gets `EACCES`
(`proxy_bridge_only`); the bridge's accounting and its fail-closed budget can
no longer be skipped. Spec §10 and operating.md updated.

### F4 — retracted: audit artifact, not a defect
The "transient fd on `/proc/<pid>/fd`" was the observing process's own
directory handle: `ls`/`os.listdir` opens `/proc/self/fd` (its own fd 3), and
`readlink` materializes the target as `/proc/<own-pid>/fd`. It appears in the
listing and is closed when the listing ends. No launcher fd leaks; verified by
the dash/python reproductions and by `exec`-form targets showing fd 3 closed.

### F5 — fixed: resolver view and credential link rule
- `/etc/resolv.conf` is now a sanitized per-attempt copy
  (`stage_sanitized_resolv_conf` in `platform.rs`, `BwrapPlan::resolv_source`):
  nameservers kept, `search`/`domain` lines dropped. Verified live: the
  in-jail file no longer contains the host's search domains.
- Credential sources must have exactly one link in **either** mode
  (`check_mode` in `credentials.rs`): a hardlinked `copy_rw` source now
  refuses with `credential_unavailable` ("exactly one link"), verified live.
- Domain-fronting and DNS-label exfil are inherent to name-based allowlists;
  documented in spec §10 as such.

## Post-fix verification (all on the reference host)

- **Full test suite** (`cargo test -p ouro-jail --release --no-fail-fast`):
  every binary passes except `conformance_j1::s11_wall_expiry`,
  `review_linux::r9_explicit_pids`, and `j5_lifetime::x07_leaf` — all three
  fail identically on the **pristine `d7c0d36b` baseline** in this SSH
  session (cgroup-delegation probes and leaf verification from a plain
  session scope; the conformance lane runs these under `ouro-ci` with
  lingering). The other `j5_lifetime` failures seen in the parallel full run
  pass when run serially or individually (parallel-test interference under
  load). Clippy clean.
- **F1 re-verified with the original PoC** (`race4`, openat2 flags race on
  `/etc/passwd`): ~500k raced calls → 4 stable events, the rest recorded as
  `argument_snapshot_unstable` gaps, `fs.write` degraded, and strict
  evidence exits 1 (`evidence_lost`) instead of certifying falsified
  snapshots. The pre-fix binary recorded 250,593 WR-classified events for
  250,441 kernel-applied mutations with `gaps: []`.
- **F2 re-verified**: `connect("/run/ouro/proxy/proxy.sock")` from the target
  → `EACCES` (was: Success, raw HTTP to the proxy); the bridge path still
  relays (403 `host_not_allowed` for denied destinations).
- **A01 regression**: opencode 1.18.32 under `--launch opencode` → exit 0,
  file written, every coverage class active (exec 128, fs.write 8,479, net
  30, proxy.net 30), `supervisor_scope: entered`, vendor-state cleanup
  complete.
- **Tests updated for the intentional behavior changes**: `n05_host_peers`
  and `j5_boundary` N05 (direct proxy connect now refused, denial counted),
  `n04_header_overflow` and `review_the_bridge_budget` (saturation driven
  through the bridge; the proxy's own 503 is no longer target-reachable),
  `j4_o06_racing_pathname` (raced calls are stable events plus
  `argument_snapshot_unstable` gaps accounting for every call), `m2`
  credential link refusal in both modes, plus new unit tests
  (`pointed_arguments_are_reverified_at_the_exit`,
  `a_credential_source_must_have_exactly_one_link`).
