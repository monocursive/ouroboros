# Ouroboros-jail full review — 2026-10-08 (seventh pass)

Reviewer goal: a full review of `ouro-jail` at HEAD `44a7a950` (local `dev`,
nine commits ahead of `origin/dev` = `d0bc346d`; those nine have not been
through hosted CI). The sixth audit reviewed `7b68d73c`. This pass covers
everything since then (90 commits, about 3.6k changed lines in
`crates/ouro-jail/src`): native aarch64, syscall-delivery coalescing,
read/write observation fast paths, swap, storage and inode ceilings, the Unix
socket diagnostics preflight, the `ouro-records` split and the
release-candidate tooling. It also re-reviews the whole jail against the
jail-v1 invariants I01–I12.

## Environment and method

- **Static review.** Seven parallel reviewers read disjoint scopes, framed as
  claim verification against jail-v1/v2:
  1. aarch64 ABI and tables
  2. observer evidence semantics
  3. containment and resource ceilings
  4. agent network and vault
  5. supervisor, trusted inputs and state
  6. records, receipts and public claims
  7. tests, conformance and release tooling
- **Sub-reviews.** Three of them checked every acceptance-map row against its
  cited test bodies. A fourth listed enforcement points that it predicted no
  test would catch.
- **Verification.** I verified every High and Medium finding myself, in code
  and, where it could be run, live.
- **Live host.** `ubuntu@37.59.114.70`: Ubuntu 26.04.1, kernel
  7.0.0-31-generic x86_64, bwrap 0.11.1, `yama.ptrace_scope=1`.
  - The HEAD tree was built in `~/a7ws/src`, separate from the installed
    `~/.local/bin/ouro-jail`, which was left untouched.
  - Rust 1.98.1 release build with `OURO_BUILD_REVISION=44a7a950`.
  - The root filesystem was 95% full (4.3 GB free), so only `ouro-jail` and
    `ouro-fixture` were built, not the workspace.
- **Raspberry Pi.** Unreachable (its tunnel refused connections). aarch64 was
  reviewed statically and against the recorded Pi evidence.
- **Live test suite.** The full `ouro-jail` suite ran under CI conditions:
  `OURO_CONFORMANCE=1`, `--test-threads=1`, a delegated user scope, and a
  scrubbed `PATH`. Result: **1330 passed, 0 failed, 15 ignored** across 61
  binaries. All 15 ignored tests are helpers, deliberate bless jobs, or the
  NFC table test.
- **Live batteries.** The sixth pass's mechanical battery (`a6_battery.sh`)
  ran under `--profile agent`. The network probes (`a6_net.py`) ran under
  `agent --allow-host registry.npmjs.org`. Every probe was refused or inert
  as before: host files, the mount family, `open_by_handle_at`, `pidfd_*`,
  ptrace, `process_vm_*`, `unshare`/`clone(NEWUSER)`, direct TCP/DNS, and the
  proxy socket (EACCES). The C1 Host swap, keep-alive smuggle, SNI mismatch,
  ports 8080/4443, SOCKS Host swap, h2c and inner CONNECT were all refused.
  The receipt reported `enforced` with every class `active` and no gaps.
- **Mutation testing.** Mutation runs were done on the same host against the
  relevant test binaries; see the mutation section.

## Verdict

**No containment escape through the mount plan, syscall filters or network
mediation was found.** The boundary held every live probe, and the network
path held every origin-binding attack.

Two **High** findings were demonstrated live:

- **H1 (operator-assisted).** A regular-file stdio redirect is a reopenable
  handle. A contained child under `tool` or `agent` wrote to a host file
  outside every grant by reopening `/dev/stdin`. The receipt reported
  coverage `active` with no gap.
- **H2 (pre-existing since the third audit's A1 fix).** Any `#!` script run
  directly as the target is killed under the default strict evidence mode,
  because of a false `exec_image_mismatch`. This affects every npm- or
  pip-installed agent CLI.

The Medium findings are honesty defects in receipts and build provenance, a
terminal-injection regression of a fixed audit class, a negative swap claim,
and a design gap in `agent`'s `.git` handling. The suite is green, but the mutation runs show that many enforcement points
can be deleted without any test noticing:

- 20 of 23 Linux-host mutations survived.
- Five of them, applied together, survived the whole suite. That includes
  reintroducing the 2026-09-25-2 S1 silent-suppression path and deleting the
  exec-time kill.
- On the portable mutation runs, most survived. Among them: the vault's
  scheme binding, the ECH refusal, and the uncontained-epoch
  newest-marker rule.

## Findings

### H1 (High, operator-assisted, demonstrated, pre-existing) — a regular-file stdio redirect gives the child a reopenable handle with the operator's full permission on that file

- **Where.** `platform.rs` `validate_stdio` (≈2423–2481) refuses sockets,
  directories, anonymous inodes and files under the state root. It passes
  every other regular file through to bwrap and the target unchanged. The
  sandbox has its own `/proc`, and bwrap's `/dev/stdin` points to
  `/proc/self/fd/0`.
- **Mechanism.** Reopening that magic link checks only the inode's permission
  and the original (host, read-write) mount. The descriptor's open mode plays
  no part.
- **Reproduction:**

  ```
  printf 'original\n' > ~/a7ws/outside.txt
  ouro-jail run --profile tool  --workspace ~/a7ws/ws -- /bin/sh -c 'printf "WRITTEN-BY-tool\n"  >> /dev/stdin' < ~/a7ws/outside.txt
  ouro-jail run --profile agent --workspace ~/a7ws/ws -- /bin/sh -c 'printf "WRITTEN-BY-agent\n" >> /dev/stdin' < ~/a7ws/outside.txt
  ```

  Both runs exited 0, and `outside.txt` now ends with both lines.
- **Receipt.** `fs.write` is `active`, count 1, with no gap. The only event
  is an `fs.create` whose path is `{"kind":"unavailable","reason":"path_truncated"}`.
- **What breaks:**
  - The §9.1 closed view: the write lands outside the mount plan.
  - The §6.4 storage ceiling: the write is not charged against it. §6.4
    exempts only operator-owned *output* sinks.
  - The trust boundary, if the redirected file is a trusted input such as
    `config.toml` or a launch profile. The same reopen also lets the child
    read the earlier contents of a `>>`-redirected stdout or stderr file.
- **Doc gap.** §8.3 allows "operator-selected ordinary file redirects". No
  document says that this grants write-and-truncate authority over the
  file's inode. `agent < prompt.md` is an ordinary invocation.
- **Fix direction.** For contained profiles, relay regular-file stdio through
  supervisor-owned pipes. The open mode of the passed descriptor cannot be
  narrowed after the fact. At minimum, refuse writable regular-file stdin, and
  screen the config and launch directories as `validate_stdio` already
  screens the state root.
- **Regression test.** The reproduction above, asserting the file is
  unchanged.

### H2 (High, demonstrated, pre-existing since 2026-09-26 A1) — `#!` targets are killed under strict with a false `exec_image_mismatch`

- **Where:**
  - `launch.rs:785-810` `exec_candidate_bytes` lists only the script and its
    canonical path.
  - At the exec stop, `/proc/<tid>/exe` is the interpreter
    (`session.rs:1551-1557`, `proc.rs:79-103`).
  - `observed.rs:326-341` finds no candidate matching it and records
    `ExecImageMismatch`, then `CoverageLost`.
  - `platform.rs` emits `evidence_lost`, and the supervisor stops the run.
    Strict is every profile's default.
- **Reproduced on HEAD and on the installed 2026-09-29 binary:**

  | Invocation | Result |
  |---|---|
  | `./s.sh` (`#!/bin/sh`), `tool` or `agent` | SIGTERM before the script's first line runs; rc 1 |
  | `./p.py` (`#!/usr/bin/env python3`), `tool` | killed the same way |
  | `./s.sh` with `--evidence best-effort` | runs, exits 1 with `evidence_lost` |
  | `/bin/sh ./s.sh` | succeeds |

- **Why it matters.** npm-installed CLIs are `#!/usr/bin/env node` scripts,
  pip console scripts are `#!python` scripts, and some launchers are shell
  wrappers. That likely covers most of the 14 bundled launch profiles'
  agents. Recorded compatibility exists only for OpenCode, a native binary.
  The gap also blames a rewrite that never happened (I06).
- **Fix direction.** The F5 exec-time recheck already handles `#!` scripts by
  checking for the interpreter rewrite. Apply the same rule to target
  confirmation. Confirm when the kernel image is the interpreter named by the
  candidate's `#!` line (resolved in the tracee root, or a binfmt_misc match)
  and the kernel cmdline carries the candidate in the script slot.
- **Regression test.** A live strict run of a `#!` target asserting
  `exec_observed`, no gaps and exit 0. The unit test
  `the_kernel_image_decides_the_exec_confirmation` currently treats this
  shape as an attack.

### M1 (Medium, demonstrated, regression of the 2026-09-26 A6 class) — `explain` prints untrusted project-config strings raw

`main.rs:412-420` prints `reference.to_display()` with `println!`. A
workspace `ouro.toml` with
`deny_read = ["sec\u001b]52;c;SGVsbG8=\u0007ret"]` makes
`ouro-jail explain --profile tool --workspace …` write a raw ESC (`033`) and
BEL to stdout (verified with `od -c` on the host). That is an OSC-52
clipboard write from a malicious repository, triggered by the command the
README suggests. A6 was fixed only in `write_error_line` and `diag!`.

Same class, Info: `tail --json` passes DEL and C1 characters through (serde
does not escape them), and `escape_control` does not cover bidi `Cf`
characters in child-chosen names.

**Fix.** Escape every text-mode stdout renderer.

### M2 (Medium, code-verified, new since 7b68d73c) — the `limits` coverage class is always `active` with a definite count

`audit.rs:832-838` `limits_class()` hard-codes `status: Active,
observed_count: Some(limit_hits)`, and no writer ever degrades it. Hit
evidence is missing in three places:

- by design for storage and inodes (`hit: None`, positive-only sampling);
- after `invalidate_hits()` when cgroup counters become unreadable;
- in `uncontained.rs`, when the leaf scan fails.

§11.4: "Missing hit evidence makes coverage degraded and the count null."
`resource_ceilings_linux.rs:58` asserts `hit` is null but never checks
`coverage.limits`.

### M3 (Medium, demonstrated, new) — swap `hit: false` is a negative claim nothing establishes

`cgroup.rs:671` starts every applied row at `hit: Some(false)`. Swap hits
come only from `memory.swap.events:max`, which reclaim rarely raises.

Live: `--limit mem=64MiB --limit swap=16MiB` and a 200 MiB `bytearray`. The
run was OOM-killed, `mem` hit `true`, and swap hit `false`, although 200 MiB
cannot fit in 64 + 16 MiB. The same happened with `swap=0`.

**Fix.** Start swap `hit` as unknown. Set it `true` on a `max` delta or a
sampled `swap.current >= swap.max`.

### M4 (Medium, code-verified, pre-existing; new release tooling relies on it) — the build-input digest omits two compiled-in inputs

These two files are compiled into the binary:

- `docs/specs/jail-v1/network-addresses.json`, via `include_str!` in
  `network/address.rs:16`;
- `crates/ouro-jail/data/uts46_unicode17_tables.rs`, via `include!` in
  `network/unicode.rs:10`.

Neither is under `INPUT_DIR` or in `profiles/inputs.rs`, so neither is part
of build.rs's `dirty=false` git check, and the UTS46 tables are not in
`FROZEN_PATHSPECS` either. A binary built from edited copies reports the
clean revision's `inputs` digest and `dirty: false`, and
`prepare_release.py verify_build` accepts it.

This breaks `build_provenance.rs`'s "a digest of the files the binary is
built from". The current freeze conclusion still holds, because neither file
changed between `d972bb0d` and `d9d27227`.

**Fix.** Add both files to the inputs, plus a test that every `include!` or
`include_str!` target is an input.

### M5 (Medium, design, documented as a fact but not as a consequence) — `agent` leaves the workspace `.git` writable

`profiles.rs:100-102` gives `agent` no protected segments, while `tool`
protects `.git` and `.ouroboros`. The guide says "Git metadata is writable".
It does not say that a contained run can plant `.git/hooks/*`,
`core.hooksPath` or `core.fsmonitor`, which then run with the operator's full
authority on their next `git` command *outside* the jail. The launch
profiles themselves add no persistence points (no rc files, crontab or user
units; checked).

**Recommendation.** Under `agent`, protect at least `.git/hooks` and
`.git/config`; objects and refs can stay writable so commits work. Or state
the consequence next to the profile table.

### M6 (Medium, process) — jail-v2 K rows are not computed from the suite, and enforcement points are untested

jail-v2 §2 requires each milestone's acceptance rows to be "computed from the
suite's own output". Nothing implements that for the K rows:

- `gates.rs:60` reads only jail-v1 §15.
- `acceptance-map.toml` has no K rows.
- The K tests (`command_rules_linux`, `resource_ceilings_linux`,
  `native_capabilities_linux`, `j5_arch_refusal_linux`, `portable_learning`,
  `portable_freeze`, …) can be deleted without any verdict changing.
- K31 has no live test: `killed_at_exec` appears in no integration test.
- K21's live test checks EPERM but not the `command_denied` note.
- The K table in `benchmarks/jail/README.md` is maintained by hand.

See the mutation table below for the enforcement points this leaves
unguarded.

### Low

- **L1 (R3-3, new).** Once storage enforcement is lost, `sample_limits`
  returns before `leaf.sample()` for the rest of the run. That includes the
  forced samples that attribute an OOM, so later pids/mem/swap/cpu hits are
  dropped while their rows still say `hit: false` (`platform.rs:3360-3370`).
- **L2 (R3-4, new).** Storage-loss reporting has three problems:
  - no `errors[]` entry, and the row keeps `applied: true`;
  - a loss found after the target's own end still becomes `outcome.cause`,
    against §6.4;
  - on XFS, a `chmod 000` of the child's own writable mount root makes the
    per-sample `/proc/self/fd` reopen fail, which is reported as
    "enforcement lost".
- **L3 (R3-5, new).** tmpfs capacity is never re-verified after admission. A
  host-side remount to `size=0` reads as a *hit*, not a loss.
- **L4 (R3-6).** The NamespaceInner agent variant can mount cgroup2 in its
  own namespaces and rewrite its leaf's controls where cgroup2 lacks
  `nsdelegate`. Controls are never re-read. The reference host never selects
  this variant.
- **L5 (R3-7).** `seccomp.rs:4-6` claims "every rule here has a live test".
  Many rules have none: `userfaultfd`, `*_handle_at`, `syslog`,
  `pidfd_send_signal`, `process_madvise`, `kcmp`, `*_pages`, `statmount`,
  `listmount`, `quotactl*`, the clock setters, 463–470, and the storage
  `link`/`linkat` rule. They are pinned only by the byte-for-byte table
  tests.
- **L6 (R3-8).** `doctor` and `--label-only` report `limit:storage` and
  `limit:inodes` as available from unrelated probes. `run` then refuses on a
  host without a bounded tmpfs or quota.
- **L7 (R2-2, new with F4).** The descriptor check strips ` (deleted)` from
  `/proc/<tid>/fd/<ret>` without checking `st_nlink == 0`. A decoy named
  `README.md (deleted)` plus the A-B-A pathname race yields an `fs.write`
  claim for `README.md` with `path_complete: true` and no
  `path_claim_unverified`.
- **L8 (R2-3).** The F4 descriptor check covers opens only. Non-open path
  operations (rename, unlink, mkdir, mknod, link, symlink, truncate, failed
  exec, connect) get only byte-stability re-reads. Yet jail-v1 §11.3 says the
  exit re-read turns any such mutation into an `argument_snapshot_unstable`
  gap. Amend §11.3 and name the residual.
- **L9 (R2-4).** `observed::stop` treats any `lifecycle_dropped > 0` as an
  all-class `queue_full` loss from 0 to the end of the run, including
  emit-time drops that already carry their own gap.
- **L10 (R2-5).** Command-rule verdicts ride on droppable lifecycle facts.
  Under queue pressure, the process is still killed or denied, but the
  `command_rule` note can be lost, and a best-effort `forbid` then does not
  stop the run.
- **L11 (R6-4).** In 16336791, `jail-receipt` and `policy-snapshot` schemas
  were re-blessed in place under the same identifiers. jail-v1 §13 forbids
  that, while jail-v2 §0 and the `frozen-schemas.toml` header allow it.
  `canonicalization.md` still describes the pre-swap, pre-storage policy
  shape, so an independent implementation cannot reproduce current digests.
  Reconcile the rule.
- **L12 (R6-5).** Stale or mislabelled public numbers:
  - `followup-2026-10-08.md` labels `post_start_overhead_pct` medians
    (34.1/293.6/42.1/285.5%) as "File work". The summary's
    `work_overhead_pct` is 25.3/319.6/28.1/324.5%, so observation-on cost is
    understated by 26–39 points. `roadmap.md:87-88` repeats the mislabel.
  - README and roadmap call the superseded validation "current".
  - `operating.md`'s limit list omits swap, storage and inodes.
- **L13 (R6-6).** At the 64-gap bound, a new open-ended gap is merged into a
  closed `coalesced_losses` interval (`audit.rs:696-705`).
- **L14 (R7-3, new in d972bb0d).** The conformance transfer lists untracked
  files (`--others`), and nothing ignores `.env` or `*.pem`. macOS openrsync
  ignores the `--exclude` defence for `--files-from`. Untracked test files are
  compiled into a run labelled clean.
- **L15 (R7-4).** A passing test's `eprintln!("skipped: …")` is swallowed by
  libtest, so the driver's skip scan cannot see it
  (`review_linux.rs:2068`).
- **L16 (R7-5).** `install.sh` accepts any older validly-signed release: no
  version in the archive names or manifest, and no downgrade check.
  `install.sh` itself is not in the signed manifest. `package.py` signs every
  archive in `--out`.
- **L17 (R7-6).** `native_capabilities_linux::a_requested_landlock_domain_…`
  never invokes `ouro-jail`; it runs the fixture directly.
- **L18 (R1-1, aarch64, plausible).** On arm64, `do_signal` restores x0
  before `get_signal`. A forged SIGTRAP, sent with `rt_sigqueueinfo` to its
  own process during the restart Decision step, satisfies
  `handler_ucontext`'s `x0 == delivered && sp aligned` test and fabricates an
  `EINTR` result. Fix: also require `pc` to be neither the restart nor the
  continue address.
- **L19 (R1-2).** `j5_boundary_linux.rs:1870,2138` use raw x86 number 101
  for ptrace. On aarch64 that is `nanosleep`, so those assertions pass
  without calling ptrace. Not yet run on the Pi.
- **L20 (R4-1).** Only ECH codepoint `0xfe0d` is refused. ESNI `0xffce` and
  draft ECH `0xfe08`–`0xfe0c` pass with a `tls_sni` claim. This is inside
  the accepted F2 residual, and the receipt stays honest.
- **L21 (R4-2).** Plaintext absolute-form HTTP to a `:443` grant is allowed;
  network-rules.md implies plaintext needs an explicit port-80 grant.
- **L22 (acceptance map).** Clauses whose cited tests do not assert the
  clause:
  - X06.4: the `pidfd_getfd` leg never runs, because `pidfd_open` is denied
    first. The property *is* caught elsewhere; see M01.
  - S02.7: the ancestor case is never driven.
  - F02.4: the test builds its own `.ouroboros` placeholders.
  - F04.3: only the depth refusal goes through `run`.
  - P01.2: the reordering reverses one-element sets, so it reorders nothing.
  - C01.2: the `copy_rw` digest is never read.
  - R01.7: the enforced-phase receipt is never validated.
  - R01.6: the event-kind list misses `command_rule`, `learning_read` and
    the extra `fs.deny` operations.
  - O03.2: the seam bypasses the real unmatched-exit branch.
  - O06.5: there is no assertion that a race occurred.
  - N05.4: no test creates late aliases.
  - L04.4: the production clock closure is untested.

### Info

- **F10 root cause.** `j5_lifetime_linux.rs:60-81` hard-codes fds 100/101 and
  does `fcntl` then `dup2` with no lock. Parallel tests cross-wire or
  double-close the control pipes. This is test-only; the supervisor is
  exonerated. Fix: a static mutex, or `F_DUPFD`.
- **Manifest coverage.** The capability manifest pins probes only. Derived
  requirement rows are printed, not compared.
- **Reproducibility.** The "reproducible release candidates" claim covers
  archive packaging only. The binary has no `--remap-path-prefix`, and the C
  toolchain used by `ring` is not recorded.
- **`ouro-ledger` config.** `ouro-ledger` reads the shared `config.toml` with
  a hardened reader but without the uncontained-epoch guard. A `none`-planted
  `[ledger] retain` would be honoured. The impact is weaker than what `none`
  already concedes.
- **aarch64 notes:**
  - arm64 single-step traps arrive as `SI_USER`; unreachable today.
  - AArch32 restart frames are judged with x86 rules; this can only
    over-report.
  - The aarch64 tables are pinned only on aarch64 hardware.
  - `aarch64_be` builds are accepted (they fail closed).
  - Several module comments still say "x86_64 only".
- **Network notes:**
  - An HTTP/1.0 request with no Host is labelled `http_host`.
  - A SOCKS IPv4-mapped literal is matched before normalisation; this fails
    closed.
- **Receipt and trace notes:**
  - With `observe=off`, the wrapper source is `supported` while `limits` is
    `active`.
  - `send_control` drops an oversized frame uncounted.
  - The `gc` cleanup rewrite leaves the trace ending on the previous receipt
    revision.
  - JCS integers above 2^53 are not RFC 8785.
- **Containment notes:**
  - `RUNTIME_ROOTS` also binds `/sbin`, `/lib32` and `/libx32`.
  - The boundary read-back checks `CapEff` only.
  - `check_binary_isolation` is path-based, so a hard-link alias passes
    (ETXTBSY likely blocks use).
- **Observer labels:**
  - `exec_image_mismatch` gap intervals use raw `CLOCK_BOOTTIME`.
  - A `deny_exec` register failure is labelled `foreign_abi`.
  - An unreadable tgid attributes results to `pid = tid`.

### Refuted

- **"No aarch64 seccomp test has ever executed on aarch64."** Refuted. The
  2026-10-05 Pi unit log (`evidence/2026-10-05-arm64/pi/unit.log`) shows
  `baseline_numbers_match_the_native_libc_table`, both byte-for-byte filter
  tests and the storage hard-link test passing natively, and `seccomp.rs` and
  `abi.rs` are unchanged since. What remains true: CI's aarch64 job only
  compiles, so aarch64 regressions are caught only by manual Pi runs.
- **The aarch64 syscall numbers.** All 395 number sites match libc 0.2.189
  for both ABIs; 0 errors. The 13-row aarch64 closed set covers every x86_64
  operation through its `*at` form, and all eight published tables
  re-render byte-identically.

## Mutation testing

Each mutation was applied to the HEAD tree on the reference host. The jail
and fixture were rebuilt, and the named test binaries were run with
`OURO_CONFORMANCE=1` and `--test-threads=1`. SURVIVED means every named
binary stayed green.

Each mutation's source file was restored afterwards; the restored tree
matched local HEAD byte for byte (sha256). The build log shows every
mutation was compiled into both the binaries and the test executables.

**3 of 23 killed, 20 survived.**

| ID | Mutation (file) | Claim it guards | Binaries run | Result |
|---|---|---|---|---|
| M01 | drop `pidfd_open`/`pidfd_getfd` from `DENY_EPERM` (seccomp.rs) | X06.4, §9.2 | j5_boundary, review, conformance_j3_agent | **killed** by `review_the_target_cannot_reach_into_the_bridge` (not by X06.4's cited test) |
| M02 | delete the gap on the real unmatched-exit branch (session.rs ~1951) | O03.2, §11.4 | j5_boundary, observer, observer_regression, j4_loss, lib | **survived** |
| M03 | disable the "no hard ceiling for a requested resource" refusal (storage.rs ~177) | §6.4 | resource_ceilings, lib | **survived** |
| M05 | exec recheck: changed-argv branch returns `None` (session.rs) | K31 | command_rules, lib | **killed** (lib unit tests) |
| M06 | pseudo-fs mountinfo arm drops proc/sysfs/cgroup (platform.rs ~2906) | S02.7 | j5_pseudofs, linux_mechanisms, review, lib | **survived** |
| M07 | skip the `.ouroboros` absent-literal placeholder (platform.rs ~3086) | F02.4 | linux_mechanisms, review, j5_boundary | **survived** |
| M08 | bypass the exit re-read (`arguments_stable`) call site (session.rs ~2096) | O06.5 | j4_tracer_precision, observer, observer_regression, j4_loss, lib | **killed** (lib) |
| M09 | protected scan `max_entries = usize::MAX` (platform.rs ~3046) | F04.3 | j5_boundary, linux_mechanisms, lib | **survived** |
| M10 | `copy_rw` credential digest → `None` (credentials.rs ~463) | C01.2 | conformance_j3_agent, conformance_j3_credentials, portable_launch, lib | **survived** |
| M12 | no `command_rule` note on entry denial (audit.rs) | K21 | command_rules, lib | **survived** |
| B01 | delete the workspace pseudo-fs refusal (platform.rs ~990) | §9.1 | j5_pseudofs, linux_mechanisms, review, j5_boundary | **survived** |
| B02 | delete the scratch pseudo-fs refusal (platform.rs ~995) | §9.1 | same | **survived** |
| B03 | `tool_baseline_with_storage(false)`: hard links allowed under storage | §6.4 "no hard link" | resource_ceilings, linux_mechanisms, lib | **survived** |
| B04 | receipt's `narrowing_filter_digest_installed` always names the learning filter | I06 | observer, j4_closed_set, j5_records, portable_learning, lib | **survived** |
| B05 | drop `invalidate_hits()` on unreadable cgroup counters (platform.rs ~3386) | §11.4 | resource_ceilings, conformance_j2, linux_mechanisms, lib | **survived** |
| B06 | never arm the uncontained epoch markers (supervisor.rs ~1566) | jail-v2 §3.2 / audit 6 F1 | conformance_j3_none, review, portable_launch, lib | **survived** |
| B07 | epoch guard `<=` → `<` (equal ctime accepted) (supervisor.rs ~864) | audit 6 F1 | lib | **survived** |
| B08 | delete the exec-time `SIGKILL` (session.rs ~1564) | K31 | command_rules, lib | **survived** |
| B09 | delete the kill of an exec refused an in-flight slot (session.rs ~1758) | K31 / jail-v2 §7.2 | j4_loss, command_rules, lib | **survived** |
| B10 | read-only `openat2` filtered at entry (session.rs ~1718), i.e. reintroducing audit 2026-09-25-2 S1 | §11.4, S1 | observer, j4_tracer_precision, observer_regression, lib | **survived** |
| B11 | F4 descriptor check skipped for fd 0 (`rval > 0`) | audit 6 F4 | observer, observer_regression, j4_tracer_precision, lib | **survived** |
| B12 | drop the bwrap `mode & 0o022` check (fs.rs ~713) | §9.1 backend pin | j5_bwrap_resolution, linux_mechanisms, lib | **survived** |
| B13 | x86 handler-entry test drops `rax == 0` (sys.rs ~420) | §11.2 restarts | j4_tracer_precision, observer_regression, lib | **survived** |

**Whole-suite confirmation.** The table above ran only the named binaries.
To make sure no other binary catches them, the five most security-relevant
survivors were applied together and the **full** `ouro-jail` suite was run
under CI conditions:

- B01: workspace pseudo-fs refusal deleted;
- B03: storage link-deny wiring disabled;
- B06: epoch markers never armed;
- B08: exec-time kill deleted;
- B10: read-only `openat2` filtered at entry.

Result: **1330 passed, 0 failed, 15 ignored**, the same as the unmutated
tree. The mutations touch unrelated code, so each survives the whole suite.

**Portable mutations.** These ran on macOS, on a scratch copy of the tree
with its own target directory, against every portable test of `ouro-jail`
and `ouro-records`, plus `ouro-ledger` for records mutations. **26 of 31
survived.** Most relevant:

- **G2, gc.rs:1072.** Drop `receipt_is_none` from the "tree never existed"
  test. gc then deletes vendor state for a dead owner with an enforced
  receipt but no registered leaf, which breaks audit 2026-09-25-2 S4. A
  probe test kills it.
- **S1, state.rs:153.** The epoch takes the *last* directory's marker
  instead of the newest. A `config.toml` written between a newer data-dir
  marker and an older config-dir marker is then trusted. A probe test kills
  it.
- **T1, trace.rs:174.** `last_healthy_ns` advances after a failed write, so
  the loss interval starts after the lost frame (§13.3). A probe test kills
  it.
- **S2, state.rs:174-179.** An unreadable marker directory (0o300) is
  skipped instead of refusing, which hides live markers.
- **G4, gc.rs:1209.** Lost integrity no longer retains a name-only leaf's
  scratch.
- **R1, semantic.rs:522.** The source comparison of `trace_loss_recorded` is
  removed.
- **R5, jcs.rs:113.** Uppercase `\u001B`: digest drift that goes unnoticed
  because the fixture harness includes the same `jcs.rs`.
- **G5, gc.rs:2255.** gc unlinks a symlink or FIFO named like a temp file.
- **J1, J3, J4, journal.rs.** `tail` accepts a torn final frame and an
  oversized frame, and does not validate `--attempt`, so `../x` is accepted.
- **T4, trace.rs:806.** `FdSink` does not latch `Lost` after an oversized
  frame.
- **L1, learn.rs:129.** The `/`, `/etc`, `/home`… refusal list can be
  emptied.

Network, vault, credentials and config were tested the same way, against the
full portable suite on a scratch copy. Control mutations were killed, so the
harness detects failures. Survivors, all present-and-correct checks with no
test:

- **vault.rs:30.** Scheme binding. Dropping it lets an `https://host` secret
  be injected into plaintext `http://host:443` (absolute-form, or CONNECT
  followed by a plaintext first flight). This is the jail-v2 §6.3 opt-in.
- **origin.rs:191.** The ECH and duplicate-extension refusals, which jail-v2
  §6.2 requires.
- **vault.rs:154.** Authorization-only placement: a placeholder in
  `X-Api-Key` would be rewritten into `Authorization`.
- **tls.rs:63, 79, 88.** The 32 KiB decrypted-header bound, and the chunked
  and Expect refusals. The Expect match changed to header-name matching
  after the last audit and has no test.
- **config.rs:241-247.** A project `[jail.commands]` refusal. Without it the
  rules are silently dropped.
- **policy.rs:1305.** The `deny_read` boundary-plumbing refusal (audit
  2026-09-25-2 S3). On Linux it is masked by bwrap's
  `MaskedBoundaryPlumbing`, which is also untested.
- **launch_profile.rs:524-540.** The vault-mode grammar refusals. No test
  parses `mode = "vault"`.
- **capability.rs:165.** `Swap`, `Mem` and `Cpu` requiring the execution
  boundary; only `Pids` is tested.
- **commands.rs.** forbid/deny precedence and the 64-rule and 4096-byte
  bounds.

Killed: the settle chmod, the one-loss-note rule, torn-drain → Broken, and
the JCS escape threshold. The probe tests are in the session scratch
(`r7/agentF/repo`) and can be adopted as regressions.

**What the survivors mean.** Every survivor guards a behaviour that held
live on the unmutated build where I could check it: the workspace and
scratch pseudo-fs refusals, and the refusal before exec. So none of these is
a present defect. They are enforcement points that the next refactor could
silently delete.

Highest priority:

- **B10:** a silent-suppression path the project already fixed once.
- **B08 and B09:** K31 enforcement.
- **B03:** the storage claim.
- **B06 and B07:** the audit-6 F1 guard, which has no end-to-end test.

## Checked and held

- **Boundary.** Arch-first filters on every program, x32/i386/AArch32
  refusal, and C4 (i386 `clone3`) intact. Pseudo-fs refusal for
  workspace and scratch was verified live: a cgroupfs directory and
  `/dev/shm` were refused with `policy_widening`. Mount sources are pinned by
  descriptor. The cgroup namespace is rooted at the leaf.
- **Observer.**
  - The read-only fast path covers only register-sourced opens; `openat2`
    is always followed.
  - The 250 µs coalescing is bounded by the caller's budget, once per drain,
    with order preserved (I07 holds).
  - The queue charge and credit are symmetric.
  - Every loss counter is paired with a gap.
  - F4 and F5 are intact apart from L7 and L10.
  - aarch64 register handling uses entry-captured arguments; `orig_x0` is
    handled correctly.
- **Network.**
  - Notify-ID revalidation before and after fd duplication; the allowed
    connect uses the pinned node.
  - The sockdiag preflight does a real `UDIAG_SHOW_VFS` dump and fails
    closed.
  - Origin binding holds the upstream closed until first-flight inspection.
  - HTTP and ClientHello parsing are strict; one request per connection.
  - The frozen address table is correct, with no re-resolution between check
    and connect.
  - The vault substitutes only on an exact origin match, and buffers are
    zeroized.
- **Trusted inputs.**
  - F1 epoch markers: live and settled, both directories, fail-closed.
  - B1 hardened reader intact.
  - Launch-profile narrowing refused in both directions.
  - `learn` never adopts writes.
  - Every target spawn runs `close_range_cloexec` (I03).
  - GC never follows child links (I12).
- **Records.**
  - `none` is `unprotected` on every path (I08).
  - The `ouro-records` move is verbatim.
  - JCS key order and escapes are correct.
  - Trace sinks are prefix-only after loss.
  - No CI result is claimed for the unpushed commits.

## Recommended order

1. **H1:** relay or refuse regular-file stdio for contained profiles, and
   document what a redirect grants.
2. **H2:** make target-exec confirmation accept `#!` scripts. Then record
   compatibility rows for at least one npm-shim agent.
3. **M1:** escape `explain` and every text renderer.
4. **M2 and M3:** degrade `limits` when hit evidence is missing, and make
   swap `hit` unknown until established.
5. **M4:** add the two compiled-in files to the build inputs.
6. **M6 and the surviving mutations:** add the missing live tests (K31
   kill-at-exec, storage link denial, unbounded-volume refusal, epoch guard
   end-to-end, unmatched exit) and compute K rows.
7. **M5:** protect `.git/hooks` and `.git/config` under `agent`, or document
   the persistence consequence.
8. The Low items, in the listed order.

## Artifacts (on the VPS)

`~/a7ws/`:

- `src/`: the HEAD tree;
- `suite.log`: the full suite;
- `agent-battery.*` and `agent-net.*`: the live batteries;
- `script.json`, `stdin.json`, `stdin-trace.ndjson` and `swap-*.json`: the
  H1, H2 and M3 demonstrations;
- `mut*.jsonl` and `mutlogs/`: the mutation runs.

The installed `~/.local/bin/ouro-jail` and `~/.config/ouro` were not
modified. `~/a7ws/outside.txt` is the H1 target and is scratch.
