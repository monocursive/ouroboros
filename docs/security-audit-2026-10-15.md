# Security audit 2026-10-15 — post-rename (Ukai) full review

Eighth pass. First after the ouro→ukai rename. Scope: renamed source tree at
`549569975` (`dev`), release-built on the reference VPS and cross-built on a
Raspberry Pi; the macOS VM preview (`ouro-vm 0.1.0-preview.1`) receives its
first audit coverage; installer supply chain re-reviewed; ledger (`ukai-ledger`)
receives its first adversarial protocol test.

Hosts: the reference VPS (Ubuntu 26.04.1, kernel 7.0.0-31, bwrap 0.11.1,
x86_64), the Raspberry Pi (RPi OS 13, kernel 6.18.50, aarch64), the Mac
(macOS 27.0.1, Apple Silicon, ouro-vm preview). Addresses and accounts are
withheld from the committed copy; they are in the session record.
Build: `cargo build --release -p ukai-jail` / `-p ukai-ledger`, rustc 1.98.1,
`ukai-jail 0.1.0`, build inputs `sha256:54c52eb2…f14de8313a2`.

Method: six static review slices (policy/grants, bwrap/mounts, seccomp/tracer,
supervisor/lifecycle, records/ledger/vault, proxy/SOCKS5/bridge) plus one VM
slice, then adversarial dynamic tests chosen to avoid the seven prior passes'
already-tried techniques (§2 of the consolidated history). Probes preserved in
`docs/security-audit-2026-10-15-probes/`.

## §Findings

### H2′ (High) — relative-path `#!` targets are falsely killed as `exec_image_mismatch`

Regression-narrowed remnant of pass-7 H2. The `ShebangImage` confirmation
machinery added for H2 only works when the script's execve spelling is
absolute:

- `crates/ukai-jail/src/platform/linux/tracer/proc.rs:110-113` —
  `shebang_image` returns `None` when the script spelling does not begin with
  `/`.
- `crates/ukai-jail/src/platform/linux/observed.rs:303-309` —
  `script_kernel_confirms` requires the kernel-argv script slot to equal both
  the path snapshot and the candidate *byte-for-byte*. For a relative spelling
  (`./s.sh`) the only byte-equal candidate is the relative one, whose
  `ShebangImage` is `None`; the canonicalized candidate has usable evidence
  but never byte-equals the snapshot.

Live result (tool and agent profiles, x86_64 and aarch64):

```sh
printf '#!/bin/sh\necho OK\n' > s.sh && chmod +x s.sh
ukai-jail run --profile tool --workspace "$PWD" --limit wall=10s -- ./s.sh
# ukai-jail: error evidence_lost at running [inspect_state]:
#   the closed-set observer lost coverage: exec_image_mismatch
```

The absolute spelling (`$PWD/s.sh`) confirms cleanly, so `exec_candidates`'
canonical form is the only working path. Consequences:

1. **Availability**: every `./configure`, `./node_modules/.bin/*`, `npm`/`pip`
   shim invocation pattern dies under default strict evidence.
2. **Nondeterministic enforcement**: the strict-mode SIGTERM races the script;
   observed both `signaled:15 cause:evidence_loss` (killed before output) and
   the script running to completion (`exited:0`) with the same gap recorded.
   Short hostile scripts can finish their body before the kill lands (the exec
   still happened inside the jail; no containment impact, but the strict-
   evidence contract "kill on evidence loss" is not upheld deterministically).

The receipt records the gap honestly (no spoofing). Fix direction: resolve the
relative candidate through `/proc/<tid>/root` + `/proc/<tid>/cwd` for the
shebang read, or compare the kernel-argv slot by resolved identity instead of
raw bytes.

### L1 (High for ledger consumers) — `serve.sock` authenticates by uid only; any same-uid process fabricates durable *verified* runs

`crates/ukai-ledger/src/daemon.rs:447-449` (per-connection auth is
`SO_PEERCRED` uid equality), `daemon.rs:731-751` (`ClaimOwner` hands owner +
producer tokens to any same-uid peer), `store/stream/rules.rs:97-107` (receipt
validation compares only against the run's own Prepare payload — which the
same peer supplied). Demonstrated live on the VPS with
`docs/security-audit-2026-10-15-probes/forge_ledger.py`:

```
prepare:    ok   (run_feed5dbd…, attempt att_3e35d5a1…)
claim_owner: ok   owner_token 7d027a23… producer_token …
admitted:    ok   seq 3, digest sha256:bd99256e…
verify:      local_consistency: true, problems: []
show:        child_protection: enforced   ← from the attacker's receipt
```

The forged receipt was the repo's own checked-in example
(`docs/specs/jail-v1/examples/receipt-prepared.json`) with `attempt_id`
rewritten; every schema the validator needs is public and frozen, so assembly
is trivial. `settled` needed one more field to pass the frozen schema, but
`admitted` + verified chain already stand. Companion issue (same root):
`Request::Append` operator intents carry **no token at all**
(`daemon.rs:719-730`, `store/operator.rs:60-85`) — a same-uid process can
durably append a false `denied` intent against a victim run (ReviewRecords P2).

The jailed child cannot reach `<data>` (verified: attempt state is never
bound), so this is not a containment escape; it is integrity-of-evidence
failure against every downstream consumer of `ukai-ledger verify`/exports/
signed bundles. Fix direction: bind owner capability to something the forger
cannot supply (handshake with the pinned jail image, or a per-run secret
delivered out-of-band), and token operator intents.

### M1 (Medium) — `--profile none` child can delete the epoch markers that date trusted files

Pass-6 F1's guard writes `uncontained.<attempt>.live` markers
(`state/uncontained.rs:156-158`, armed `supervisor/attempt.rs:391-399`) and
refuses trusted files while any is live (`supervisor.rs:1189-1207`). The
markers are ordinary operator-uid files and a `none` child shares the uid and
sees the whole host: it can unlink them, then plant `~/.config/ukai/config.toml`
with widening grants (`network.allow`, `observation.mode = "off"`). A contained
run started concurrently resolves `uncontained_epoch` to "no live marker" and
the planted file's fresh ctime passes `refuse_stale_trusted_file`
(`supervisor.rs:1200-1207`); `epoch.live.is_empty() && epoch.settled.is_none()`
returns `Ok` unconditionally (`supervisor.rs:1189`). Source-review finding
(ReviewSupervisor), consistent with the documented jail-v2 §3.2 residuals but a
simpler defeat than the "re-save later" scenario the module doc names. Fail-
closed direction: the arming supervisor re-verifies its live markers each poll
and records deletion as integrity loss. Companion P3 (Low): `Drop`'s
`remove_dir_all` on a child-planted obstacle at the settled-marker path is
unbounded (`state/uncontained.rs:239-243`).

### Low cluster (source-review, plausible, not individually live-verified)

| ID | Where | Summary |
|---|---|---|
| B1 | `mounts.rs:646-750` | `--ro` grants do not seal a rw submount mounted beneath the source; precondition is operator host configuration (loop mounts), receipt records the submount honestly. |
| B2 | `bwrap.rs:604-608,696-697` | `--dev-bind` binds by path (no `--dev-bind-fd` upstream); the one row outside the "nothing is ever bound by path" invariant; race needs host root. |
| V1 | `vm/run.py:377-378` | Copy-back `mkdir(parents=True)` follows pre-existing intermediate symlinks; needs a same-uid host helper (no guest-only path). |
| V2 | `vm/run.py:525-526` | Containment check one-directional: workspace nested inside `--out` allowed; guest copy-back seeds new files into the input tree (`xb` prevents clobber). |
| V3 | `vm/guest.py:215-223` | Any guest-created symlink/special file in workspace kills the whole copy-back (`controller_error`); **live-confirmed on the Mac**: hostile symlink → attempt `failed`, zero export, nothing outside `out/`. Contained self-DoS. |
| V4 | `vm/prepare.py:113-130` | NAT bootstrap window apt traffic is plain HTTP (GPG-signed; replay of still-signed stale metadata possible) frozen into the shipped image. |
| P1 | `proxy/tls.rs:316-334` | Vault HTTPS to IPv6-literal destinations fails closed (`rcgen` SAN parsing of bracketed literal) — availability only. |
| P2 | `proxy/tls.rs:245-249` | TLS-lane head reads reset the 30s I/O timeout without the documented 300s lane lifetime; self-scoped slot hold. |
| S1 | `tracer/` (table pinned) | Deny table audited against kernel 7.0.0-31's full syscall set (846 entries incl. i386/x32): no dangerous new surface ships allowed (`mseal`, `map_shadow_stack`, `cachestat`, `lsm_*` are benign or capability-gated; `open_tree_attr`/`file_*`/`listns`/`*xattrat` are denied). Informational, closes the sweep. |

## §Verified held (dynamic, this pass)

| Check | Result | Where |
|---|---|---|
| Parent environment leaks | `--clearenv` holds; sentinel env absent | VPS tool |
| `/proc/1/root`, `/proc` topology | pid-ns isolated (`/proc/1` = bwrap init); my initial "LEAK" readout was probe error | VPS + Pi |
| `mount`, `umount2`, `unshare(CLONE_NEW*)`, `setns`, `chroot`, `pivot_root`, mount-API | denied (seccomp EPERM) | both arches |
| `io_uring_setup/enter/register` | EPERM before any opcode submission — kernel-context SQE bypass unavailable | both arches |
| `execveat(memfd)` + `execve(/proc/self/fd)` | EPERM (x86_64); on aarch64 the memfd shebang executed but stayed inside the jail (descendant exec; no target-confirm bypass) | both arches |
| `seccomp(NEW_LISTENER)` child listener | **agent: EBUSY live** (refutes this pass's candidate bypass — the code's premise holds on kernel 7.0); tool: denied | both arches |
| Hard-link write into `--ro` grants / protected `.git` | **EXDEV** — `link(2)` across bind mounts fails by kernel design even on one superblock (refutes this pass's candidate High) | VPS, both grant shapes |
| H1 stdio redirect (`>> /dev/stdin` on host file) | held — relay via supervisor-owned pipe, host file untouched | VPS |
| Proxy forbidden-address (DNS→loopback/metadata via `nip.io`, decimal-IP) | 403 refused; allowed host TLS 200; plaintext on TLS-only grant 403 — `check_answers` + frozen IANA table behave | VPS agent |
| Rename regression: `OURO_*` env, `~/.config/ouro`, `/run/ouro` | all ignored; no legacy trust path survives the rename | VPS |
| Mac `ouro-vm`: clean run | delivers `built.txt`, attempt `completed` | Mac |
| Mac hostile workspace (symlink) | attempt `failed`, no export outside `out/`, no symlink materialized | Mac |
| Installer supply chain | pinned SHA-256 verified pre-extraction, HTTPS-only no-downgrade, `tar -xO` member extraction, symlink-refusing destinations, atomic rename, fail-closed record mismatch | source |

## §Refuted candidate findings (recorded for hygiene)

1. **RO-bind hard-link escape** (static High): kernel returns EXDEV for
   cross-mount `link(2)` even within one superblock; both `--ro` grant and
   protected-`.git` shapes tested live.
2. **Agent connect-mediation bypass via child `USER_NOTIF` + `CONTINUE`**
   (static, confidence 0.8): installing a second listener filter over the
   launcher's mediation filter returns EBUSY on kernel 7.0.0-31 (x86_64) and
   6.18.50 (aarch64); unjailed control install succeeds, so the probe was
   sound. The code comment's premise is empirically true here; re-check if a
   kernel ever lifts the EBUSY.
3. **`/proc/1/root` host read** (dynamic alarm): `/proc/1` inside the pid
   namespace is the jail's own init; not a leak.

## §Remediation (2026-10-16, same tree)

| Finding | Fix | Live verification |
|---|---|---|
| H2′ | `tracer/proc.rs` `shebang_image` reads a relative script spelling through the tracee's `cwd` magic link (exec does not change cwd; the kernel resolved the same spelling against it). The raw candidate then carries `#!` evidence and byte-matches the kernel's argv slot. | VPS + Pi: `./script` under `tool` and `agent` runs, `settled exited 0`, `gaps: []`; absolute spelling and `sh -c` unchanged. |
| L1 | In-model (the daemon documents "Authenticated same-user Unix ingress"), but the claim surface was silent: every `VerifyReport` now states `authenticity: "bounded_by_local_uid"` (`protocol.rs`, threaded through `verification.rs`/`pruning.rs`). | `ukai-ledger verify` prints the bound on every report, including fabricated runs. |
| P2 (ReviewRecords) | **Refuted live**: token-free `Append` operator intents never change run state or projections (`rules.rs` applies projections only to owner records; `operator.rs:1` documents it; verified live — state stayed `admitted` after a token-free `denied` intent). No fix required. | See §Refuted. |
| M1 | `UncontainedRun` pins each live marker with an `O_PATH` handle; the supervision loop checks `st_nlink == 0` every iteration (`attempt.rs` `between_waits`), rewrites a deleted marker at once, and marks integrity lost in the receipt; the settled marker records `loss`, and `uncontained_epoch` then refuses every existing trusted file until the operator checks and clears it. | VPS: child deleted markers + planted config → live warning, `settled … loss` marker, next `tool` run refuses the planted config ("cannot be trusted"); after operator clears the marker the normal per-file checks apply. |
| B1 | `mounts.rs` `refuse_writable_submounts_under`: any `--ro` grant (and the ro runtime roots) with a non-`ro` mountinfo row strictly beneath its resolved source refuses (`PolicyWidening`/`Configuration`). | Unit tests (rw submount refuses naming it; ro submounts and rw grants unaffected). |
| P1 | `vault.rs`: IP-literal destinations build `SanType::IpAddress` and `ServerName::from(IpAddr)` — no bracketed-DNS misparse; DNS names byte-identical. | Loopback-handshake tests for V4/V6/DNS. |
| P2′ (TLS lane) | `tls.rs` `read_response` clamps each head read to the lane's remaining lifetime and fails at its end. | Dripping-upstream test ends at the lifetime. |
| P3 | `settle`'s obstacle removal is bounded (`remove_bounded`: depth 64, 10k entries); past the bound settle fails and the live marker stays (fail-closed). | Unit test: small obstacle cleared, 10,001-entry obstacle leaves the epoch refusing. |
| V1 | `vm/run.py` `export()`: openat-style `O_NOFOLLOW` dir_fd walk; symlink components and final names refuse. | VM suite (56 tests). |
| V2 | `vm/run.py` `execute()`: symmetric nesting check — workspace inside `--out` refuses. | VM suite. |

Residual, documented rather than fixed: the M1 detection is poll-cadence detection, not a
promise (§9.3's stated philosophy) — deletion between two supervision ticks leaves a
sub-second window; the M1 pin is taken just after the marker's seam write (the write
replaces the inode by rename, so it cannot pin), leaving a same-width window in which an
equally timed swap pins a replacement and the original's deletion goes unrecorded —
forensics only, since what refuses trusted files is a live marker at the path, whatever
inode it is, and an unpinned marker reads as a loss; B2 (`--dev-bind` by-path) needs an
upstream `--dev-bind-fd`; V3 (symlink kills copy-back delivery) is contained self-DoS; V4
(NAT-window apt replay) is GPG-bounded and inherent to the image build.

## §Test-environment note (2026-10-16)

`conformance_j1::s11_wall_expiry_separate_run` fails when the suite is run
from a bare SSH session scope: its expected-value `cgroup_pids` probe inspects
the *caller's* cgroup and reports `cgroup_unavailable` outside the delegated
`user@1000.service` subtree. The same test passes under
`systemd-run --user --scope` and under the lingering CI account's user
manager, and the pre-rename tree at `2c8f28dc` fails identically from a bare
session — a harness precondition (run the suite from a delegated scope), not a
regression. `platform::linux::bridge` has one load-sensitive accept-backlog
assertion that flakes under full-suite parallelism (passes in isolation and in
most full runs, pre- and post-fix).

## §Verdict

No containment escape from a contained profile was achieved — consistent with
all seven prior passes. The jail's kernel-boundary posture held against every
new technique this pass brought (io_uring opcode bypass, kernel-7 syscall
surface sweep, cross-mount hard links, child seccomp listeners, memfd exec,
DNS-rebinding-shaped SSRF). The genuine weaknesses are elsewhere:

1. **H2′** — the pass-7 H2 fix is incomplete for relative-path scripts; strict
   evidence kills legitimate work nondeterministically. Fix before the rename-
 era release: this is the default path of every npm/pip-style agent CLI.
2. **L1** — the ledger cannot defend its own evidence against the user's own
   uid; if `ukai-ledger` is meant to prove anything to a third party, its
   socket protocol needs a capability the forger cannot mint.
3. **M1** — the `none`-profile epoch guard is defeated by marker deletion;
   cheap hardening available (re-verify live markers each poll).

Recommended order: H2′ → L1 → M1 → Low cluster as touched.

## §Artifacts

- Probes: `docs/security-audit-2026-10-15-probes/` (iouring2.c, memfd_exec.c,
  notif_bypass.c, forge_ledger.py, ssrf_probe.py, rename_regression.sh,
  h1_reverify.sh, h2_reverify.sh, sysnum_sweep.sh, battery.sh).
- VPS: `~/ukai-review` (built tree), `~/secrev` (runs, receipts, sweep),
  `~/ukai-review-probes/`.
- Pi: `~/ukai-review` (aarch64 build), `~/ukai-review-probes/`.
