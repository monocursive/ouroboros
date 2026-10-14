# Code-quality fixes — 2026-10-14

What branch `quality` does about [the review of the same day](code-quality-review-2026-10-14.md).
`quality` starts at `dev` 35869fe86. It is local and unpushed.

## How the work was done

- **Packages.** Each fix package was written by one implementer, in its own worktree.
- **Review.** Each package then went to an adversarial reviewer. The reviewer re-read the diff, reverted fixes to check that the new tests catch them (mutation testing), and reproduced defects live where it could.
- **Fix-ups.** A finding from review went back to the implementer as a fix-up. Then the package was cherry-picked or merged into `quality`.
- **Gates at every integration:**
  - `cargo fmt`;
  - clippy `-D warnings` on macOS and on aarch64 Linux (ouro-dev);
  - the I02 vendor-name scan;
  - `cargo test -p xtask`;
  - the contract validators;
  - the live suites, run inside a delegated cgroup scope with `--nocapture`, so that a skip cannot pass silently.

## Status by review section

| Review section | Status |
|---|---|
| §2 fix-first defects (28) | All fixed. Every behavioural fix carries a test that fails without it; the documentation-only items carry none. |
| §3 Origins rendezvous | Fixed: authority bound to the socket by its 4-tuple, the check order, the closer thread, typed refusal reasons. An end-to-end `binaries`-bound vault test now passes on x86_64. |
| §4.1 parallel implementations | One run loop for the contained boundary and for `none` (`running.rs`). One launcher gate. One mountinfo parser, one accounts lookup and one `/proc` reader per field. One `sys` home for fd/poll/sleep helpers. One GC deletion core and one atomic replace in the ledger. The narrowing filter is derived from the closed-set rows. sha2 replaces the hand-rolled SHA-256. |
| §4.2 stringly-typed data | Typed seam vocabulary: `Integrity`, `BoundaryKind`, `VerificationScope`, `LimitCause`. Typed policy vocabulary: `CredentialMode`, `NetworkMode`, `Requirement`, one `LimitKey` projection. Typed `JailState`. Typed ledger run state, status and poison, and a typed `LedgerError`. `ErrorObject.code` and `.stage` are typed but still read unknown spellings. Wire bytes are unchanged. |
| §4.3 size | `run_inner` 950 → 38 lines (`Attempt`). `resolve` 383 → 88. `platform.rs` 6,886 → 554. `tracer/session.rs` became a module of 12 files. `store.rs` 5,675 → 61. `run_owned` 395 → 34, with admission as a typestate. `main::execute` is one exhaustive dispatch. `render_markdown` 405 → 14. |
| §4.4 comments and markers | `// J… begin/end` markers and process labels are gone from production code, and the false claims the review listed are corrected. Some milestone wording remains in acceptance-map notes and in test names (`j4_w3_*`), which the map cites. |
| §4.5 `unsafe`, errors, poison | Every `unsafe` block in the workspace has a SAFETY comment, and `clippy::undocumented_unsafe_blocks = "deny"`. One documented poison rule (`crate::sync`). One effective-uid helper. |
| §4.6 dead code | Dead and test-only public API removed or narrowed: about 80 re-exports, several modules, and `BwrapPlan.protected`. |
| §6.13 tests | Every record a test reads goes through the frozen contract; the accessors' fields are private, and a refusing contract is tested. One `ScriptedPlatform`. C fixtures live in files, and the aarch64 ports now run instead of skipping. Bless is behind `OURO_BLESS=1`. A sentinel proves each self-exec helper actually ran. Named bounds and `eventually` cover 86 → 24 hand-rolled waits (the rest are deliberate). Two load-dependent trace tests are now deterministic. |
| §6.14 repository | `[workspace.dependencies]` (`Cargo.lock` byte-identical). Fleet: refuses bad input without restarting the node, bounds every worker subprocess by the caller's deadline, asks for status concurrently, `rpc/2`. VM runner: every attempt ends with a terminal record. CI: cache and SHA pins; shellcheck. Evidence-store guard and retired duplicate archives, with no history rewrite. |

## Defects found during the fix wave (not in the review)

The adversarial reviewers found these. Each is fixed with a test unless the entry says otherwise.

- **The descriptor-limit raise reached the sandboxed program.**
  - *Cause:* the mount-descriptor budget raised the soft `RLIMIT_NOFILE` before spawning. The target then saw 1,048,576 instead of the operator's 1,024.
  - *Fix:* the launcher restores the operator's soft limit before exec, in every profile including `none`.
- **A soft limit of 256 or less made every observed run refuse.** The supervisor's descriptors are reserved from 256 up.
- **The TLS lane spun on a vanished client.** It used a whole core for up to 300 s, then blamed its own deadline.
- **Receipts over 4 MiB.**
  - *Before:* a large policy, mount table or `none` environment could claim an attempt and end with no `jail.json`.
  - *Now:* everything a receipt must hold is bounded before the claim, and again after preparation. A refused receipt is fitted by cutting messages, never by dropping the errors that explain it.
  - *Also fixed:* a `none` run with more than 1,024 environment names used to write a receipt that fails the frozen schema.
- **Ledger.**
  - `verify` could hide a rewritten accepted record behind a "foreign bytes" finding.
  - A transient EMFILE was recorded as a permanent `journal_unreadable` unknown outcome.
  - A persistent journal errno was retried for ever.
  - The off-writer verify, bundle projection rule 1 and protocol-mismatch handling each gained the tests their reviewer asked for.
- **Git metadata under `agent`.**
  - Fixed: the hooks and config of *existing nested* repositories, and of a granted `<repo>/.git`, were writable.
  - Not fixable with mounts: a deliberate run can still plant `.git/commondir`, edit a submodule's config, or move `.git` aside. The guide (section "Git metadata under `agent`") and jail-v1 §9.1 now say so plainly, and a test pins each limit.
- **The vault CA and the sanitized `resolv.conf` were re-pinned by path after being written.** They are now bound only through the pin of the file written (`PinnedBind::write`). The CA no longer lives in sandbox-writable vendor state.
- **Origins and the proxy.** The authority race on a reused 4-tuple is closed, as is a `SO_LINGER` close hang.

## Behaviour an operator may notice

- **Under `agent`:**
  - Existing nested repositories' `.git/hooks` and `.git/config`, and submodule hooks, are read-only.
  - A `.git` symlink anywhere in the workspace refuses the run. The refusal names the paths.
  - `git submodule deinit` cannot unregister a submodule inside a run, because the root `.git/config` is protected.
- **Refusals before the claim.** An oversized plan is refused as `invalid_config` before an attempt is claimed: more than 1 MiB of mount table, more than 1,024 inherited environment names, or a projected receipt over the bound. `explain`, `doctor` and `--label-only` agree with `run`.
- **`explain`** text now prints every limit, including swap, storage and inodes.
- **Ledger:**
  - Bytes after a live writer's accepted history are reported as `corrupt`, no longer as `incomplete`.
  - `verify-bundle` reports `projection_rule`; this is an additive re-bless.
  - `doctor` reports a writer of another protocol as `incompatible`.
- **Fleet:** the wire is `ouro.fleet.rpc/2`. Refusals carry a `detail`.
- **Fixture:** a stop after a step has run exits 4, no longer 2 (usage).

## Decisions for the owner

1. **Git metadata after an `agent` run.** Mounts cannot stop a deliberate run from planting `commondir`, editing a module's config, or replacing `.git`. The practical option is a check after each run that records changes to git metadata in the receipt (detection, not prevention). A sketch is in the platform review (`rv-plat4`). This needs an additive receipt field.
2. **POL-19.** Folding the 16 near-identical launch profiles into bundle fragments adds one provenance line per profile. The alternative is a product change: profile inheritance, or fragments that can set state keys. The freeze generator also does not yet expand bundles.
3. **The ledger's SQLite projection.** Nothing reads it, but the spec requires it (L8, the doctor `index` field). Its cost is now bounded. Dropping it would remove rusqlite and about 540 lines.
4. **Smaller ones:**
   - Line-number citations (`jail-v1.md:N`) in frozen schema descriptions need a re-bless to fix.
   - The guide and roadmap pages link to `blob/dev`.
   - X02.6 and X02.7 now close in the Linux lane (`a261810f5`).
   - The macOS runner is pinned to `macos-15`.
   - The evidence for the `binaries` pin (the 2026-10-13 origin-race probe) names the source before the proxy split; `vault/origin.rs` itself is unchanged. A probe rerun would bind it to the current tree.

## Still open

- `freeze --check` reports only that no tested run is recorded. Recording one needs a conformance run on the reference host as `ouro-ci`.
- `unix_peer_linux` and `l01_a_fork_burst_is_fully_reaped` need `--test-threads=1`: one shared abstract socket name, and a test-wide subreaper.
- Small items: a failed loss correction names the first receipt's revision. The pre-claim and post-prepare environment reads can drift; the second check catches it. A launcher `SIGPIPE`/sigmask restore failure is still reported as an exec failure. Under `tool`, a nested repository's parent can be moved aside.

## Verification at 025b6b108

- **macOS:** `cargo test --workspace` — 100 binaries, 1528 passed, 0 failed. Freeze tree part matches. Both contract validators pass. Fleet 27/0.
- **aarch64 Linux (ouro-dev), delegated scope, whole workspace:** 2513 passed, 21 failed, 15 skips.
  - The base `dev` (1e282629b), run the same way, gave 2075 passed, 42 failed, 34 skips. No test fails now that passed at the base.
  - The 21 remaining failures all fail at the base too, and each is an aarch64 or ouro-dev host fact: x86_64-pinned tables and syscall numbers, AppArmor and nesting, OrbStack mountinfo for k16, `minisign` for k27, and h1 with observation off.
  - Every skip names a reference-host property.
- **x86_64 reference host, delegated scope:** 2533 passed, 2 failed.
  - Both failures are signal-disposition tests that see the run's `nohup`; both pass in the foreground.
  - With `OURO_CONFORMANCE=1`, every reference-host suite passes with 0 skips, including the `binaries`-bound vault test.
