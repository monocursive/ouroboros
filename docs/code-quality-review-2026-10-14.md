# Code-quality review — 2026-10-14

Scope: the whole repository at `dev` HEAD `35869fe86`, plus the uncommitted
working-tree change (`crates/ouro-jail/src/proxy/mod.rs`,
`crates/ouro-jail/src/vault/origin.rs`) and the untracked
`docs/benchmarks/credentials/2026-10-13-next/` evidence. Focus: code
quality (maintainability, duplication, abstraction, error handling, comment
accuracy, tests, repository hygiene). Correctness and honesty defects found on
the way are reported first, because they outrank style.

## Method

- **Parallel reviewers.** Fourteen read-only reviewers covered disjoint slices:
  1. supervisor and lifecycle
  2. state, gc and trace
  3. policy, config and network rules
  4. proxy, vault and bridge, plus the uncommitted diff
  5. Linux platform core
  6. sandbox mechanisms (bwrap, seccomp, cgroup, storage)
  7. tracer and observer
  8. audit, probe, scope and `none`
  9. ledger store
  10. ledger service and `ouro-records`
  11. xtask
  12. ouro-fixture
  13. integration tests
  14. repository hygiene, CI, Python/shell tooling, fleet and website

  They reported about 360 findings.
- **Lead verification.** I re-read the code behind every High finding and every
  correctness or honesty claim listed in §2 (marked **V**). The other findings
  are the reviewers' code-checked claims (marked **R**). PLAUSIBLE items say
  what would confirm them.
- **Tooling.** `cargo clippy -W clippy::pedantic -W clippy::nursery` ran on
  macOS. It finds 61 functions over 100 lines, and nothing alarming beyond
  that. A line-window duplicate detector ran over all Rust sources.
- **Caveats.**
  - Linux-only code could not be linted from this Mac; ring and sqlite need
    Linux C headers.
  - Nothing was run live. No finding below was reproduced on the VPS or the
    Pi.
  - TR1 (aarch64) in particular needs a Pi reproduction before and after the
    fix.

## 1. Verdict

The code is careful where it was audited hardest:
- descriptor-anchored filesystem work (`state/anchored.rs`, `cleanup.rs`,
  `reconcile.rs`);
- the seccomp assembler and its interpreter-driven tests;
- the persistence seam with named crash points;
- pure, table-tested verdict functions;
- bounded I/O nearly everywhere;
- SAFETY comments on about 90% of `unsafe` blocks in the jail.

Three patterns undermine that care, and together they explain most of the
defects in §2:

1. **The same mechanism is implemented several times, and the copies have
   already diverged.**
   - Contained versus `none` run loops: an audit fix landed in one only (AU1).
   - mountinfo parsers: 4.
   - Two argv digests under one field name (SUP-02).
   - Two cBPF toolchains and four interpreters.
   - Nine "private file" checks in the ledger.
   - Five atomic-replace implementations.
   - Three `getpwuid_r` wrappers.
   - Two IPv6 CIDR canonicalizers that disagree.
2. **Domain vocabulary crosses module boundaries as strings or untyped JSON.**
   Each new variant then reaches some sites and misses others:
   - integrity, boundary and verification scope (`"verified"`, `"lost"`,
     `"pending"`);
   - credential mode and network mode;
   - requirements parsed back by `starts_with`;
   - mount kinds;
   - ledger run states;
   - stream health classified by substring (LG1);
   - gc actions derived from report text;
   - `jail-state.json` edited through `serde_json::Value`.
3. **God functions and god files.**
   - `run_inner` is 1,112 lines and `Boundary::create` is 829.
   - `platform.rs`, `tracer/session.rs` and `supervisor.rs` are each over
     5,000 lines.
   - Nobody can review these whole, and every audit fix adds another block to
     them. LP1, the placeholder leak, is a direct consequence: no single scope
     owns cleanup.

Separately, the repository is 98% evidence by weight (§6.14). And 560–650
milestone markers (`// J3-agent begin` / `end`) are left in the code, have
already detached one doc comment, and are unbalanced in four tag families.

## 2. Fix first: verified correctness and honesty defects

Severity is the impact on the product's honesty invariant or on the operator,
not on style. **V** = re-read by the lead.

| # | Sev | Area | Defect | Where | Fix |
|---|---|---|---|---|---|
| 1 | High | policy → proxy | The L21 rule (plaintext HTTP requires an explicitly named port) does nothing in a real `agent` run. `HostRule::canonical` always writes `host:443`; `agent.rs:318` rebuilds the proxy rules from those strings, so every rule re-parses as `explicit_port: true`. The test builds `Rules` from raw strings and misses this path. Four bundled launch profiles also write `:443` explicitly. **V** | `network.rs:376-402`, `policy.rs:1660`, `platform/linux/agent.rs:318`, `proxy/mod.rs:1137`, `tests/portable_proxy.rs:791` | Hand the typed `Vec<HostRule>` to the proxy, or encode "port implied" in the canonical form (a frozen-schema change). Make `covers` respect `explicit_port`. Add a snapshot-to-proxy test. |
| 2 | High | tracer, aarch64 | The L18 handler-entry guard excludes `site.ip` and `site.ip+4`. `site.ip` is already the address *after* `svc`, and the restart pc is `site.ip-4` (`session.rs:365-367`), so a forged SIGTRAP at the restart address still passes on arm64. **V** (reading only) | `tracer/session.rs:2383`, `tracer/sys.rs:455-476` | Pass `(site.ip - 4, site.ip)`, rename the parameters, add a synthetic-regs unit test, and repeat the L18 reproduction on the Pi. |
| 3 | High | limits coverage | The M2 fix (2026-10-08) landed only in the `none` path. In a contained run, unreadable cgroup counters null every `hit` but never record a limits gap, so `limits` stays `active` with a definite count. The `shared` module's doc says "one copy, so the two boundaries cannot drift". **V** | `platform/linux/platform.rs:3964-3968` vs `uncontained.rs:1259-1273`; `platform.rs:4728` | Add one `counters_lost(leaf, audit, reason)` and call it from both paths. See also §4.1. |
| 4 | High | receipt | With `agent` and `--limit storage` (UnprivilegedInner), the receipt's `agent.baseline_filter_digest` is the filter *without* the link/linkat rules, while the installed filter and `applied.syscalls.digest` include them. One receipt makes two contradicting claims about the installed filter. **V** | `platform/linux/agent.rs:313, 897-900`, `platform.rs:1155` | Take the digest from the installed `filter.digest()`. Delete the unused `AgentNet::baseline_digest()`. Add an agent + storage conformance case. |
| 5 | High | receipt / events | The command-rule `argv_digest` is `sha256(le_len‖bytes…)`, with no domain tag and no argc. The spec's `argv_digest` (`ouro-records/src/canonical.rs:72-88`) is `"ouro.jail.argv/1"\0 U64BE(argc) {U64BE(len) bytes}`. The same field name carries two values that never match. An unreadable argv yields the sentinel `"unavailable"`, not `null` with a reason. **V** | `commands.rs:54-59`, `platform/linux/audit.rs:312` | Call `canonical::argv_digest`, and use `Option` plus a reason. |
| 6 | High | operator workspace | `prepare_mounts` creates `.git` and `.ouroboros` placeholder directories in the operator's workspace. `Placeholder` has no `Drop`, and about 25 `?` exits later in `Boundary::create` drop them. A refused run (filter build, render, F04 swap refusal, spawn, cgroup placement) therefore leaves empty `.git` or `.ouroboros` behind, and no receipt records it. **V** | `platform.rs:1128-1461`, `bwrap.rs:163, 240-300` | Add a `PlaceholderSet` guard that removes the placeholders on drop unless it has been moved into `Boundary`. |
| 7 | High | milestone gate | `freeze --check` uses `recorded_tree.starts_with(tree)`, although its doc says "exactly". A freeze file that still records a schema or profile the generator no longer emits therefore passes. Recorded `verification`, `host`, `rustc` and similar fields are never compared. **V** | `crates/xtask/src/freeze.rs:1065`, `:19-21` | Compare the whole file for equality, and compare the recorded verification list. |
| 8 | High | ledger runner | When a foreground terminal is slower than the agent, the 128-chunk tee queue overflows. `forward` then errors, the run is terminated, and it is recorded `outcome_unknown`. A 2 s `finish` timeout downgrades a clean run the same way. Run survival depends on terminal throughput. **V** | `ouro-ledger/src/runner.rs:456-477, 1066, 1098` | On overflow, stop forwarding and keep capturing, recording dropped bytes. Treat a `finish` timeout as a delivery fact, not an owner failure. |
| 9 | Medium | ledger daemon | One `accept()` error (EMFILE, ECONNABORTED, …) ends the accept thread. The writer loop then sees `Disconnected`, `serve` returns `Ok(())`, and the writer exits 0. **V** | `ouro-ledger/src/daemon.rs:315-317, 372-376` | Retry transient errnos. Treat accept-thread death as an error. |
| 10 | Medium | ledger honesty | Stream health is classified by substring. A poison text containing `invalid`, `mismatch`, `noncanonical` or `violates` is `corrupt`; anything else is `incomplete`. Integrity violations such as "mixed attempt identity", "duplicate request id" and "receipt belongs to a different attempt" are therefore reported as `incomplete`. Snapshot trust is gated by `problem.contains("manifest")`. **V** | `ouro-ledger/src/reader.rs:649-655`, `store.rs:1059, 1270` | `Poison { kind: PoisonKind, detail }`, classified at each push site. |
| 11 | Medium | receipt time base | The `exec_image_mismatch` gap is stamped with raw `CLOCK_BOOTTIME`. Every other gap is epoch-relative, and coalescing can stretch a merged interval far past the run. **V** | `platform/linux/observed.rs:392-399` | Use `elapsed_since_start_ns()`, as `observed.rs:560` does. Add one `clock::since_epoch_ns()`. |
| 12 | Medium | gc honesty | `managed_scratch_present` returns `None` both for "not managed" and for "policy unreadable", and `is_none_or` then lets gc record `gc_finished` while managed scratch may still exist. **V** | `gc.rs:1977-1984, 1638`; same pattern in `cleanup.rs:652-660` | `enum Scratch { Managed(..), Operator, Unknown(..) }`, where `Unknown` blocks `finished`. |
| 13 | Medium | durability | The uncontained-run marker re-implements temp+fsync+rename outside the persistence seam and swallows the directory fsync, then unlinks the live marker. Its doc says "then the directory fsync". **V** | `state.rs:306-330, 266-268` | Use `TempWrite::create_at(Site::…)`, so a failed directory sync fails the settle. |
| 14 | Medium | policy | `~/` in a launch profile's `[filesystem]` grants is never expanded: the expansion closure omits `LayerOrigin::LaunchProfile`, so `~/x` becomes `<config>/launch/~/x`. The same file does expand `~/` for credential sources. **V** | `policy.rs:1320-1325`, `launch_profile.rs:919` | Add `LayerOrigin::expands_home()`, plus a test. |
| 15 | Medium | I07 bounds | Settlement removes managed scratch with `std::fs::remove_dir_all`, which is unbounded, fails on child-made 0500 directories and leaves the attempt `pending`. The bounded, anchored `cleanup::remove_managed_dir` exists but only gc uses it. **V** | `supervisor.rs:2368-2403` | Call `cleanup::remove_managed_dir`. |
| 16 | Medium | proxy honesty | The TLS lane starts a second 300 s window in `pump`, so a connection can live about 600 s. When the proxy's own deadline expires, the receipt records `EndReason::UpstreamError`. **V** | `proxy/tls.rs:158, 327-343` | One lifetime `Instant`, and `EndReason::Deadline`. |
| 17 | Medium | perf evidence | The fixture's `perf-launch` result is untyped `json!`. xtask reads it into ten `#[serde(default)]` structs and never checks the schema, so a renamed key becomes `timed_out: false` or `exec_ns: 0` in §5 evidence. **V** | `ouro-fixture/src/ops.rs:2798-2833`, `xtask/src/perf.rs:352-471` | One shared Serialize/Deserialize type, no defaults, schema assert. |
| 18 | Medium | evidence gate | `vm/check_install.py` appends `passed: True` for `payload-tamper` before `assert not destination.exists()`. If that assert fails, `finally` still writes `"passed": true`. **V** | `crates/ouro-jail/vm/check_install.py:26-58` | Record the postcondition in the result. |
| 19 | Medium | privilege check | The bridge privilege check treats an unreadable `CapEff` as "no capabilities": `"".chars().all(..)` is true. `platform.rs` guards the empty case; `agent.rs` does not. **V** | `platform/linux/agent.rs:541-543` vs `platform.rs:1756-1779` | One `Privilege::read(pid)`, where empty means refuse. |
| 20 | Medium | I01 | `open_control(args)?` and `open_trace(..)?` run after `claim_attempt`, so their failure leaves a claimed attempt with no receipt. The module doc says "every early exit goes through `refuse`". **V** | `supervisor.rs:1226, 1276-1277` | Open the sinks before the claim, or let `refuse` work without a trace. |
| 21 | Medium | pseudo-fs guard | `pseudo_fs_mount_points` returns an empty list (not even `/run`) when mountinfo is unreadable, so `refuse_pseudo_fs_grants` fails open. Related: several `applied.*` read-backs return empty facts on read error. **V** | `platform.rs:3425-3427, 3053-3058, 3122-3125` | Return `io::Result` and refuse. |
| 22 | Medium | budget | Linux `prepare` starts a fresh `Deadline::after(PREPARE_BUDGET)`, and the constant is re-declared. Steps 1–5 can therefore take about 60 s against §8.2's 30 s. **V** | `platform/linux/platform.rs:103, 589`; `supervisor.rs:51, 1471` | Carry the remaining deadline in `PreparedPlan`. |
| 23 | Medium | host facts | `getgrgid_r` uses a fixed 16 KiB buffer and `continue`s on ERANGE, so a large `sudo` or `docker` group drops out and a privileged operator is classified `unprivileged`. **R** | `platform/linux/host.rs:487-511` | Retry with a growing buffer; otherwise report `Unknown`. |
| 24 | Medium | proxy reasons | `Reason::OriginUnverified` (spec: first-flight routing-name failure) is also used for a malformed placeholder header, any client TLS read failure, an upstream handshake failure and a mid-stream TLS error, and a test codifies it. **R** | `vault.rs:323, 352, 358`; `proxy/tls.rs:116, 151, 298, 509`; `vault.rs:792` | Add `CredentialPlacementDenied`, `ClientClosed` and `UpstreamProtocol`. |
| 25 | Low | ledger CLI | `ouro-ledger version` resolves the data dir first, so it fails without `HOME`, or with a relative `XDG_DATA_HOME`. **V** | `ouro-ledger/src/main.rs:785` | Handle `Version` before `data_dir`. |
| 26 | Low | fixture | `exit <code>` reports `code` but calls `process::exit(code)`, which truncates modulo 256. `exit 256` reports 256 and exits 0. **V** | `ouro-fixture/src/cli.rs:517`, `ops.rs:412-420` | `code: u8`. |
| 27 | High | test coverage claim | `j5-authority.md:470-472` says "Since J5-C every live reader checks receipts, traces and control transcripts against the frozen schemas and the semantic rules". It doesn't. `fn settled(run)` exists in 7 test files at 4 strengths. `conformance_j2`'s copy checks receipts only, and five files read traces or control transcripts without `check_trace`/`check_control`. A trace with a `source_seq` hole would pass them. **V** | `crates/ouro-jail/tests/*.rs` (`settled` ×7), `docs/specs/jail-v1/j5-authority.md:470` | One `common::settled` built on `assert_run_records`. Correct the sentence until the code matches. |
| 28 | High | developer loop | `tests/portable_release_evidence.rs` (not platform-gated) requires `release-preview-current.json`'s recorded VM build inputs to equal this build's `OURO_BUILD_INPUTS`, a digest of every file under `crates/ouro-jail/src`. Any source edit, including the current uncommitted one, makes `cargo test` red on both CI legs until a fresh clean-VM run is recorded. **V** | `crates/ouro-jail/tests/portable_release_evidence.rs:12-40`, `docs/benchmarks/jail/verify_preview_evidence.py:20` | Move it to `xtask gates --linux-release`, or gate it behind `OURO_RELEASE_EVIDENCE=1` with `skip_or_fail`. |

Further latent fail-open defaults, each reachable only through an unusual
failure (all **R**):
- `SO_DOMAIN` read failure goes to the raw-connect branch (`unixpeer/live.rs:557-565`).
- `audit::class_of` catch-all `_ => FsWrite` (`audit.rs:1158-1170`).
- `summary(.., attached = true)` passed as a literal at both call sites (`audit.rs:860`).
- Missing tracer summary defaults to "no loss" (`platform.rs:4520`).
- A failed `deny_exec` is recorded as a `ForeignAbi` gap over every class (`tracer/session.rs:1850, 2087`).

## 3. The uncommitted change: `Origins` rendezvous

**Purpose.** It fixes the 3/228 `credential_process_denied` OAuth refreshes
in `analysis/oauth-process-binding-investigation.json`. The cause was that the
sealed bridge's preamble can reach the proxy before the connect worker
publishes the pinned process. The red/green evidence in
`validation/origin-race-*` is real. The recorded source hashes match today's
working tree (`origin.rs` a65c3aec, `proxy/mod.rs` 73ba0df4), so **any edit
below invalidates them and needs a probe re-run.** Because of §2 #28, this
change also makes `portable_release_evidence` fail until a new clean-VM
preview run is retained.

**The core protocol is sound** (V):
- `publish` and `stop` change the predicate and notify under the `entries`
  lock.
- `wait_timeout` releases the lock atomically, and spurious wakeups loop.
- `begin_stop` calls `origins.stop()` without holding the registry lock, and
  `receive` never takes that lock.

What to change before committing:

1. **Wrong check order (Medium, V).** At `origin.rs:286-292` the deadline is
   checked before the table. If `read_exact` used the 2 s, or `wait_timeout`
   timed out just as `publish` won the lock, a published authority is refused
   (`credential_process_denied`, the symptom being fixed). Its pin is then held
   until a later prune at least 10 s later. Order: stopped, then `remove`, then
   deadline.
2. **A miss now costs 2 s (Medium, V).** In profiles with process bindings,
   every bridged connection whose key is never published waits the full 2 s,
   holding an admission slot and a handler thread, then proceeds with `None`.
   A key is never published when:
   - `prepare` hits the pin budget (and a pin is taken for *every* mediated
     AF_INET or AF_INET6 connect before `decide`, `unixpeer/live.rs:518-524`);
   - the table holds 128 entries;
   - the executable changed between `prepare` and `connected`.

   The receipt then says "process denied" where the truth is "dropped at a
   cap". Consider having the mediator always publish an outcome for the key
   (an explicit negative), or at least use a distinct reason.
3. **Stop is recorded as a denial (Low, V).** A waiter woken by `stop` returns
   `Ok(None)` and carries on serving. An EOF before the preamble maps to
   `CredentialProcessDenied` instead of `Stopping` or no-request.
4. **`stopped` is an `AtomicBool` beside the mutex that guards it (Low).**
   Correctness depends on every write happening under `entries`. Put
   `stopped: bool` in a `Mutex<Table>`, and drop the now-stale
   `#[cfg_attr(not(linux), allow(dead_code))]` on `entries` and `published`;
   both are used on every target now.
5. **Magic numbers (Low).**
   - The `2 s` literal appears twice: the read timeout is a fresh 2 s per
     `read`, not the time remaining.
   - The `10 s` retain closure appears twice, verbatim.
   - `128` appears three times, including `proxy/mod.rs:651`.
   - The ports `3128`/`3129` and the loopback address are re-typed from
     `bridge.rs`.
6. **Duplicated helpers (Low).** `capture_reserved` open-codes `pidfd_open`
   with an `as i32` cast, although `identity::pidfd_open` returns an
   `OwnedFd`. `alive()` re-implements a zero-timeout poll. The `_file` field is
   read, so its name is wrong.
7. **Tests (Low).**
   - The first new test re-implements the `configured()`, `bridge()` and
     `prepare_self()` helpers defined just above it. It was written before
     them (see `origin-race-before-02/source-source-origin.rs`).
   - The 100 ms "still waiting" probes pass vacuously if the thread has not
     reached the wait yet.
   - One test sleeps a real 2 s and asserts `< 5 s`.
   - Tests hand-build the preamble instead of round-tripping `preamble()`.
   - `bridge::serve` hard-codes `credential_origin = false`, so the
     preamble-injection path has no unit test.
   - Fix: a waiter counter under `#[cfg(test)]`, an injectable budget, and a
     shared `encode(key)`.
8. **Evidence hygiene (Low).**
   - `before-02/` and `fixed-01/` neither copy the probe script nor record its
     hash.
   - `native_origin_probe.py:43` names copies `source-`+basename, which
     produced `source-source-origin.rs`.
   - `dirty` and `synthetic_protocol_unit_test` are hard-coded `True`.
   - `before-01-quota/result.json` still says `expected_exit_observed: true`
     for a run that never compiled.
   - `before-01/` holds only a source copy.

## 4. Systemic patterns

### 4.1 Parallel implementations that have diverged

| Mechanism | Copies | Divergence already present |
|---|---|---|
| Contained vs `none` run loop | ~9 functions/blocks: `pump_error`, `check_wall`, `check_grace`, `hard_kill`, `sample`, `read_applied` limits, privileged refusal, … | M2 fix in one only (§2 #3); `check_exec_without_tracer` guards differ |
| "Launcher blocked on release" gate | 3 (`uncontained.rs:1478`, `platform.rs:1678`, `probe.rs:1332`) | Only one checks the fd. The justification "never a read" is stale since S14 added a read of `--trace-data-fd`. PLAUSIBLE load-dependent early pass |
| mountinfo parsers | 4 (`platform.rs:3063, 3423`, `storage.rs:245`, `state/mount_alias.rs:67`) | Caps of 1 MiB, 4 MiB and none (1024 rows); escape handling lenient vs strict; P01.8 escape fix reached only one |
| `/proc/<pid>/stat` field parsers | 5 production (`identity.rs` ×3, `tracer/proc.rs:400`, `ouro-ledger/src/daemon.rs:585`) | Two public APIs for birth time, used interchangeably |
| argv digest | 2 (`commands.rs`, `canonical.rs`) | Different construction under one name (§2 #5) |
| cBPF | `bpf.rs` assembler vs `tracer/filter.rs` hand offsets (`as u8`, `debug_assert!(n <= 235)` only); 4 interpreters | Stated reason ("allocation-free") does not hold in production (`launch.rs:375-386`) |
| SHA-256 | `tracer/digest.rs` (200 lines, hand-rolled) vs `sha2` | Justification "observer depends on std+libc only" is false today |
| Clocks | `tracer/clock.rs` (returns 0 on failure) vs `clock.rs` (panics) | Plus three `Deadline` types for one concept |
| Accounts | `getpwuid_r` ×3 (`state.rs:579`, `host.rs:390`, `scope.rs:688`), all fixed 16 KiB, no ERANGE retry; `getgrgid_r` | §2 #23 |
| fd and syscall helpers | `pidfd_open` ×3, `set_nonblocking` ×5, write-all loops ×5, `pipe2` ×5, raw `close_range` ×2, raw `poll` ×8+, `nap` ×3, errno readers ×4 | One inline write loop reads a stale errno when `n == 0` (`platform.rs:1272-1291`) |
| No-follow directory iteration | `fdopendir` loops ×4 (`fs.rs`, `bwrap.rs`, `anchored.rs`, `reconcile.rs`) | Only `anchored::Dir::names` rewinds a shared offset; the others rely on fresh fds |
| `/` no-follow walks | 3 (`credentials.rs:702`, `launch_profile.rs:730`, `learn.rs:221`) | `learn.rs` skips identity checks |
| Durable replace | Jail: `TempWrite` and the marker (§2 #13). Ledger: 5 (`manifest.rs`, `store.rs`, `pruning.rs`, `reader.rs`, `pending.rs`) | `write_projection` leaks its temp file on error |
| "Owned private file" (ledger) | 9 helpers incl. two `private_directory` and two `safe_file` with different semantics | `bundle::files::private` skips `is_file`/nlink; `store.rs:122` is path-based (TOCTOU) |
| Proxy-dir removal | `gc_removal` vs `removal` (`state.rs:1782, 1899`) | Disagree on Failed vs Retained and on reason codes |
| GC deletion protocol (ledger) | `pruning.rs` vs `capture_pruning.rs` (~150 lines) | Code that unlinks evidence; any hardening must land twice |
| Policy helpers | path normalizers ×2, `~/` expanders ×2, IPv6 CIDR canonicalizers ×2, vault env-name mangling ×2, sha256-hex ×4+, bounded-read+hash ×3 | One `~/` expander falls back silently and the other refuses; one CIDR canonicalizer keeps host bits (two digests for one network) |
| Trusted-file readers | 3 (`supervisor::read_operator_file`, `launch_profile::load`, `state::read_capped`) | Three mode rules: a `config.toml` at 0664 is refused on a umask-002 host |
| Launcher argv | built by `bwrap.rs:1282` (7 positional params), parsed by `launch.rs:138`, patched by `platform.rs:1194` (`insert(2, …)`), plus `uncontained.rs:579` and `probe.rs:1305` | No round-trip test |
| Records helpers | `xtask/stamp.rs` re-implements `ouro-records` date code; fixture includes `jcs.rs` by `#[path]` and re-implements the receipt digest and a weaker `trace_guard` | `trace_guard` ignores `attempt_id` |

`platform::shared` (`platform.rs:4728-4785`) says "each body stays above, in
one copy, so the two boundaries cannot drift apart". That is the opposite of
the truth, and should be the first thing a fix PR deletes or makes true.

### 4.2 Stringly-typed and untyped domain data

- **Lifecycle verdicts.** `integrity`, `boundary` and `verification_scope` are
  `String` across the Platform seam and in `ouro-records`. There are about 30
  literal comparisons (`gc.rs:978` decides a kill on `== "lost"`;
  `cleanup.rs:598` gates vendor-state deletion). Stop causes are written twice
  (a cause string and `StopReason`); no platform reads the reason's value.
- **Policy vocabulary.**
  - Credential mode is a `String` (about 16 comparisons; `"vault"` has no
    constant).
  - `NetworkSnapshot.mode` is a `String` although `NetworkMode` exists.
  - Requirements are `format!("limit:{}")` strings re-parsed with
    `starts_with` in 5 places.
  - The seven-key `LimitKey` → field projection is written out seven times.
- **Linux mechanisms.**
  - Mount kinds are `&'static str` (63 literals). Descriptors are matched to
    rows by position across three files, and `render` ends in
    `unreachable!("mount table kind")`.
  - Limit keys and storage mechanisms are strings, with silent `_ =>`
    fallbacks.
  - Probe names are registered in five places.
- **Observer.** Operations are classified by `&str` with a catch-all, while
  `observer::ClosedOperation` (typed, with `coverage_class()`) has no users.
  The tracer's per-thread state is two `Option`s and a `bool`; in-flight
  accounting is 12 `saturating_sub(1)` against one `+= 1`.
- **Ledger.**
  - `RunRecord.state`, `settlement` and `child_protection` are `String`, and
    the terminal triple is spelled 10 times.
  - `LedgerError(pub String)`: 367 constructions, with `ErrorKind` lost.
  - 344 `json!(` in non-test code.
  - About 30 `ouro.ledger.*` schema ids exist only as bare literals.
  - `version --json` lists an incomplete set as `"schema_frozen": true`.
- **Untyped records.**
  - `jail-state.json` is edited through 24 `state["…"]` index writes and read
    by 4 hand-written parsers, with string-versus-number drift for `dev` and
    `ino`.
  - gc decides on its own report text (`starts_with("removed ")`,
    `owner.starts_with(OWNER_DEAD)`).
  - xtask reads receipts as `Value` with fail-open defaults (142 index reads)
    although `ouro_records::Receipt` is typed with `deny_unknown_fields`.

Serde `rename_all` enums keep every wire byte identical, so none of this
needs a schema change.

### 4.3 Size

| Function | Lines | Note |
|---|---|---|
| `supervisor::run_inner` | 1,112 (845 code) | `#[allow(too_many_lines)]`; 15 copy-pasted `return Ok(refuse(…))` tails, 6 with abort+teardown |
| `linux::Boundary::create` | 829 | the only `#[allow]` in its file; 17 phases (LP2 split table) |
| `xtask::perf::render_markdown` | 396 | |
| `ouro-ledger::runner::run_owned` | 395 | Linux-only; honesty-critical admission ordering inside a 140-line closure |
| `supervisor::resolve_plan` | 409 (337 code) | |
| `ouro-ledger::main::execute` | 352 | two-phase dispatch with `unreachable!()` arms |
| `xtask::freeze::tree_part`, `conformance::drive` | 300, 282 | |
| `uncontained::create` | 280 | |
| `launch_profile::parse`, `policy::apply_layer` | 288, 274 | |
| `tracer::session::handle_exit`, `exec_transition` | 236, 188 | |

Files: `platform.rs` 5,916, `tracer/session.rs` 5,196 (single
`impl Session` of about 2,200 lines), `supervisor.rs` 5,171, `ledger/store.rs`
4,985 (3,080 of which are inline tests), `xtask/perf.rs` 4,624. Each reviewer
proposed a split along seams already marked in the code; the strongest are
summarized in §5.

### 4.4 Comments and process scaffolding

- **Markers.** 564–650 `// J… begin` / `// J… end` markers (the count depends
  on the regex) across 33 files.
  - Unbalanced families: J3-agent 92/91 (`unixpeer/live.rs`), J3-launch 72/71
    (`platform.rs`), J5-D 16/17 (`seccomp.rs`), J4-R 3/4 (`ouro-records`).
  - The J5-C insertion at `supervisor.rs:2284-2298` detached
    `degrade_trace_coverage`'s doc comment, which now documents
    `stream_classes`.
  - Markers split `match` arms, struct literals and enum bodies, and
    `is_operator_grant` was contorted into `matches! || matches!` so a marker
    fits between the halves.
  - Remove them in one mechanical commit; git keeps the provenance.
- **Stale or false claims.** These matter because the product is the honesty
  invariant:
  - "exactly" (`freeze.rs:19`);
  - "one copy, cannot drift" (`platform.rs:4729`);
  - "every early exit goes through refuse" (`supervisor.rs:9`);
  - "Every rule here is pinned byte-for-byte by the table tests"
    (`seccomp.rs:3`; storage variants are not);
  - "Every `unsafe` block … lives here" (`tracer/sys.rs:4`, `proxy/sys.rs:2`);
  - "`execvp`s the target" (`launch.rs:13`; it is `execve`);
  - the tcp6 read-back doc in `agent.rs` (reverted in 7b68d73cf);
  - "wave 2 wires this into the agent profile" (`proxy/mod.rs:5`);
  - "`crates/ouro-jail` does not exist in this worktree"
    (`ouro-fixture/tests/harness_gate.rs:3`);
  - "J0 has not selected eBPF" (`Cargo.toml:1`; the crate does not exist);
  - "`none` … not implemented in this slice" (`platform.rs:803`, unreachable);
  - `.gitattributes` "Preserve collected evidence bytes" (`-whitespace` does
    not stop EOL conversion);
  - the `ouro_fleet` `Epmd` moduledoc describing a non-existent `vm.args` and
    launcher;
  - x86-only wording left behind by the aarch64 port in about 10 places;
  - 14 `jail-v1.md:N` citations in `ouro-records/src/records/semantic.rs` that
    point at unrelated lines.
- **Density.** Comments are 24% of non-blank lines in `ouro-jail`, but 2% in
  `ouro-ledger`, which has almost no doc comments and 116 `unsafe` sites
  against 33 SAFETY comments. The ledger reads like a different codebase.
  Audit history (148 lines in the tracer alone) is better kept in
  `docs/security-audit-*.md`, with short ids in code.

### 4.5 `unsafe`, errors, poison, numbers

- **`unsafe`.** About 90% of jail blocks are documented. Undocumented ones
  cluster in:
  - `watch.rs` (10 of 14);
  - `fs.rs` and `cgroup.rs` (11);
  - `tracer/session.rs` (4 raw `kill`, unchecked, beside the checked
    `sys::kill`);
  - the uncommitted `origin.rs` (4);
  - the ledger (about 80).

  82 `unsafe { libc::geteuid() }`-style one-liners in 45 files could share
  `state::effective_uid()`. Enable `clippy::undocumented_unsafe_blocks =
  "deny"` in `[workspace.lints]`; `clippy::all` does not include it.
- **Errors.** 48 `Result<_, String>` in the jail, 34 in xtask, the ledger's
  single string error, and 175 `map_err(|_| …)`. `errno_name` returns `"E?"`
  for unknown values, and its inverse table has 24 of 52 entries.
- **Mutex poison.** The policy is spelled four ways: a `lock()` helper,
  `|e| e.into_inner()`, `PoisonError::into_inner`, and a local `poison`.
  `persist::Shared` treats poison three different ways in three methods.
- **Magic numbers.**
  - Ports 3128/3129 appear in 4 files.
  - 128 appears in 5 places, 65536 seven times, and 16 MiB eight times in the
    ledger.
  - `lease_poll_ms: 100` is a receipt literal disconnected from the three
    intervals it describes.
  - Budget numbers are hard-coded in perf report prose next to the constants
    that decide the verdicts.

### 4.6 Visibility and dead code

Dead or test-only public code:
- `GcReport`/`GcEntry`/`supervisor::gc`, a lossy legacy projection used only
  by 4 test files;
- `cleanup::resume`;
- `vendor_state_removal_implemented()`, which always returns true;
- `requested_limits`;
- `platform::Unimplemented`;
- `Client::gc_plan`, `Client::gc` and `comparison::compare` in the ledger;
- `Request::Runs`, which is only used by tests;
- the cgroup `try_leaf` API, test-only and contradicting its own doc;
- the `release`/`release_reporting_teardown` circular defaults, which exist
  only for test fakes;
- six unused narrowing-filter variants.

`pub mod` everywhere hides this from the dead-code lint. `pub mod linux` is
ungated, and seven `linux` submodules compile on macOS.

## 5. Refactor plan, in payoff order

1. **Fix §2 #1–8, #27–28 and the uncommitted-change items 1–3 first.** Each
   is small. #2 needs a Pi run; #1 may need a frozen-schema decision. #28 (the
   release-evidence test in plain `cargo test`) pulls a clean-VM run into
   every source edit; much of the recent "retain … evidence" commit stream
   comes from this coupling.
2. **"Implement once" sweep (mechanical, about 1,500 lines removed).**
   - Make `sys.rs` the single home for fd, syscall and time helpers.
   - One mountinfo parser and one `/proc` stat parser in `identity.rs`.
   - An accounts module with ERANGE retry.
   - Route every directory walk through `state::anchored::Dir`.
   - `bpf::Asm` for the narrowing filter; delete `tracer/digest.rs`.
   - A shared run-loop `RunState` for contained and `none`.
   - In the ledger: one `fsx` module (`euid()`, `open_private`), one
     `atomic_replace`, and one anchored-deletion core for both GC paths.
   - Route `commands` through `canonical::argv_digest`, settlement through
     `cleanup::remove_managed_dir`, and `register_boundary_in_state` through
     `update_attempt_state`.
   - Then turn on `undocumented_unsafe_blocks`.
3. **Typed vocabulary at the seams (wire-compatible).**
   - Seam enums: `Integrity`, `BoundaryKind`, `VerificationScope`,
     `CredentialMode`, `NetworkMode`, `Requirement`, `MountKind`, internal
     `LimitKey`.
   - `ClosedOperation`, now actually used, with no catch-all.
   - Ledger enums: `RunState`, `StreamStatus`, `PoisonKind`.
   - A typed `JailState` record.
   - Typed perf-launch results and receipts in xtask.
4. **Break up the god functions with ownership.**
   - `run_inner`: an `Attempt` context that owns `refuse` and
     `abort_and_refuse`, then prepare / gate / supervise / settle. This makes
     I01 checkable by construction.
   - `Boundary::create`: typed phases (`MountPlan`, `Channels`, `Spawned`,
     `Discovered`) with RAII guards (`PlaceholderSet`, `KillOnDrop` with a
     fresh `TREE_BUDGET`).
   - `tracer/session.rs` becomes a directory module.
   - `proxy/mod.rs` splits into types / server / conn.
   - `run_owned` in the ledger.
5. **Strip the milestone markers** in one commit, restoring the detached doc
   comment.
6. **Evidence storage (§6.14).** Stop the growth without rewriting history.
7. **Test-support modules per crate** (§6.13):
   - `common::settled` and `common::validators()` everywhere;
   - `common/sim.rs` with one `ScriptedPlatform`;
   - `common/observer.rs`, with the C moved to `tests/fixtures/*.c`;
   - a cached `common::delegated_leaf()`;
   - `common::eventually` with named bounds;
   - `common::rerun_self` that asserts the helper ran;
   - an `ouro-ledger/tests/common`.

   Move the portable config/CLI tests out of `macos_refusal.rs`, and the
   evidence "bless" out of `#[ignore]`.

## 6. Findings by area

Condensed; IDs refer to the reviewer reports (prefix = slice). Severity:
H/M/L.

### 6.1 Supervisor, CLI, cleanup (SUP)

- **H SUP-01** `run_inner` 1,112 lines; 15 copy-pasted refusal tails. Fix: an
  `Attempt` context.
- **H SUP-02** argv digest (§2 #5).
- **H SUP-03** unbounded scratch removal (§2 #15).
- **M SUP-04** preparation budget does not cross the seam (§2 #22).
- **M SUP-05** I01 doc overclaims (§2 #20).
- **M SUP-06** the seam's wall `Deadline` is not the deadline on Linux;
  `supervisor.rs:1833, 2969` comments are false there; three deadline types.
- **M SUP-07** `register_boundary_in_state` re-implements
  `update_attempt_state`. `claim_attempt` publishes
  `to_vec_pretty(..).unwrap_or_default()`. `"ouro.jail.state/1"` appears in
  4 files.
- **M SUP-08/09** three trusted-file readers; three near-identical
  `check_*_isolation` functions.
- **M SUP-10** lifecycle strings and parallel stop causes.
- **M SUP-11** circular `release` defaults.
- **M SUP-12** dead `GcReport` projection.
- **M SUP-13** markers.
- **M SUP-14** post-resolve snapshot mutations re-digested by hand; no
  provenance for the commands and learning changes. POL-3 has the same root.
- **L SUP-15–26:**
  - dead code;
  - `send_control` ignores `record`;
  - `main.rs` duplicates the schema table and capability line, and has
    inconsistent exit fallbacks (125 vs 1);
  - `cli.rs` "five verbs" over seven, and `observe`/`evidence` as strings;
  - `journal.rs` unchecked `flock` errors;
  - `commands::check` re-tokenizes patterns on every exec and silently skips
    a bad pattern;
  - `doctor` computes launch identities unconditionally;
  - `RECEIPT_COPY_MAX` 8 MiB vs gc's 4 MiB `RECORD_MAX`.

### 6.2 State, gc, trace (ST)

- **H ST1** `jail-state.json` untyped (§4.2).
- **M ST2** marker fsync (§2 #13).
- **M ST3** `gc_finished` while scratch is unknown (§2 #12).
- **M ST4** `gc.rs` should be three modules. `decide_named` copies `decide`;
  `visit` has 8 parameters.
- **M ST5** gc parses its own report text, and one check is always true
  (`gc.rs:1072`).
- **M ST6** the two proxy-dir removals disagree.
- **M ST7** `state.rs` mixes about ten concerns.
- **M ST8** four mountinfo parsers.
- **M ST9** `ClosedOperation` is dead; `STREAM_CLASSES` re-spells class names.
- **M ST10** `FdSink` lets a reserve note through after an earlier reserve
  note was refused (`FileSink` latches `Closed`), which is the J5-C hole.
- **M ST11** queued nonblocking writer duplicated (`FdSink` vs `ControlSink`);
  loss ledger duplicated.
- **M ST13** three no-follow walks.
- **M ST16** layout literals: `"placeholders"` in 5 files, `STATE_MAX`
  duplicated.
- **M ST17** passwd/group FFI ×3.
- **L ST12, ST14–25:**
  - `pub unsafe fn from_raw_fd`;
  - `Dir` conflates a readable directory with an `O_PATH` handle;
  - `names(max)` truncates silently;
  - 7 durable-write entry points;
  - tautological tests;
  - `Persister::drop` sleep-polls;
  - test-seam parsers ×3, plus one lenient one (`gc::seam_max_entries`
    accepts `" 4"`);
  - `(u64, u64)` identities (66 in the crate) and a `{0,0}` sentinel.

### 6.3 Policy, config, launch profiles, credentials, network (POL)

- **H POL-1** L21 (§2 #1).
- **M-H POL-2** `~/` (§2 #14).
- **M POL-3** the "immutable" snapshot is mutated after resolve.
- **M POL-4/5** credential mode, network mode and requirements are strings.
- **M POL-6** `LimitKey` projection ×7; adding a limit touches about 10
  sites.
- **M POL-7** `apply_layer` and `parse` are too long; a string `kind` is used
  as an enum.
- **M POL-8** `Layer.narrowing` and `key_prefix` are derivable from `origin`;
  forbidden keys are enforced three ways.
- **M POL-9** `doctor` reports vault credentials as available when staging
  will refuse them (`source_not_private`, oversize, refresh, pin).
- **M POL-10** stale docs ("four" env vars vs five, a non-existent parameter,
  case-insensitive vs case-sensitive reserved names, ...).
- **M POL-11/12** two path normalizers, two `~/` expanders, and two CIDR
  canonicalizers that disagree on host bits and leading zeros.
- **L-M POL-13–24:**
  - launch provenance is placeholder-then-patch;
  - canonical sort paths are JSON pointers that silently no-op;
  - magic 65536;
  - three bounded-read+hash copies;
  - `credentials::within` misreports a spawn failure;
  - `learn.rs` parses events untyped and has a no-op check;
  - 11 of 14 launch TOMLs are identical except for `name` (use the existing
    bundle-fragment mechanism);
  - environment-name sets synchronized by hand;
  - weak tests;
  - `network.allow` validated against the pre-layer mode (PLAUSIBLE).
- **Good:** the IDNA/UTS 46 implementation is justified by the exact version
  pin, uses a hash-pinned generator, and is tested against every line of
  `IdnaTestV2`.

### 6.4 Proxy, vault, bridge (PX)

Uncommitted-change items are in §3.
- **M PX8** `OriginUnverified` misuse (§2 #24).
- **M PX9** the `lease_poll_ms` receipt literal.
- **M PX10** the vault env-name mangling ×2 (paired with a collision guard
  that would check the wrong thing if they drift).
- **M PX11** the RFC 9110 tchar set ×3; five ad-hoc re-parsers of
  `forward_head`.
- **M PX12** five functions of 140–244 lines; tuple parameters used to dodge
  `too_many_arguments`.
- **M PX13** `transport == "socks5"` ×6; raw SOCKS reply bytes; the
  verification mechanism as `&'static str`.
- **M PX14** TLS lane (§2 #16).
- **M PX15** ports and the loopback address re-typed; changing a bridge port
  silently disables process binding.
- **M PX16** a bridge preamble failure is counted as a capacity rejection and
  also produces a proxy denial.
- **L PX17–25:**
  - stale module docs;
  - 5 unsafe blocks without SAFETY; `RawFd` where `BorrowedFd` belongs;
  - the stored bridge pid is never compared;
  - `Monitor` and `Watch` duplicate a ticker;
  - the audit callback runs under the credential state lock;
  - test-only `pub` API;
  - `relay.rs` duplicated scaffolding, and `join().unwrap_or((0,0))` hides a
    panic;
  - `exchange_token` error labels set too early.

### 6.5 Linux platform core (LP)

- **H LP1** placeholder leak (§2 #6).
- **H LP2** `create` 829 lines; `platform.rs` split table: `requirements.rs`,
  `stdio.rs` (~390 lines), `mounts.rs` (~850), `verdict.rs` (shared with
  `none`), `boundary.rs`, `running.rs`, and about 250 lines left in
  `platform.rs`.
- **M LP3** the wall ceiling is parsed after the release byte is written
  (latent).
- **M LP4/5** fail-open or empty read-backs (§2 #21).
- **M LP6** post-spawn cleanup ×5 with a spent reap budget, which can leave a
  zombie.
- **M LP7** helper duplication (§4.1).
- **M LP8** stale exec-path comments (`execvp`, the list of calls, the
  `getppid` SAFETY note, "five" vs four namespaces...).
- **M LP9** `errno_name` returns `"E?"`.
- **M LP10** launcher argv ×3.
- **M LP11** fd layout spread over four modules, with wrong comments
  (`BRIDGE_REPORT_FD == PINNED_FD_BASE == 20`); collisions are caught by a
  runtime `assert!`.
- **M LP12** verdict strings.
- **M LP13** sentinel-initialized `Boundary` (`init_pid: -1`,
  `boot_id: ""`, `mode: "pending"`).
- **M LP14** pidfd discipline inconsistent; a missing init pidfd silently
  skips SIGTERM.
- **M LP15** three shutdown sequences; four copied `ReleaseFailure` builders.
- **M LP16** `create_private_dir` is a divergent copy without the ancestor
  walk.
- **M LP18** the post-exit stdio drain busy-spins against 250 ms.
- **M LP19** `finish_captured` waits for exit before reading pipes (deadlock
  above 64 KiB of output).
- **L LP20–28:**
  - requirement strings;
  - vault CA bound by host path against the module's own rule;
  - `sleep_for` gives EINVAL at 1 s or more;
  - dead code;
  - errno endianness differs between pipes;
  - weak tests;
  - 153 markers.

### 6.6 Sandbox mechanisms (MX)

- **H MX-01** filter digest (§2 #4).
- **H MX-02** mount kinds and positional descriptor mapping (§4.2).
- **M MX-03** `BwrapPlan` has 27 public fields; tri-state
  `workspace_access: Option<bool>`; paired `Option`s.
- **M MX-04** `render` 213 lines, `mount_table` 168, `admit` 160, `walk` 157.
- **M MX-05** launcher argv.
- **M MX-06** the tcp6 doc and a test pin reverted behavior; the error names
  only 3128.
- **M MX-07** storage seccomp variants are not table-pinned, though the doc
  says they are; 8 new deny entries lack rationale.
- **M MX-08** receipt facts re-typed: `"127.0.0.1:3129"` and `5000`.
- **M MX-10** `CapEff` (§2 #19).
- **M MX-11/12/13** directory iteration ×4; hand-rolled `openat2`; mountinfo.
- **M MX-14** `getgrgid_r` (§2 #23).
- **M MX-15** `bwrap --version` has no deadline inside the preparation budget.
- **M MX-16** cgroup `try_leaf` is test-only and its cleanup swallows errors.
- **M MX-17** limit keys and mechanisms as strings with silent `_` fallbacks.
- **M MX-19** freeze pins a re-implementation of each profile's plan, not the
  production one.
- **L:**
  - the bridge seal protocol is magic bytes (`b'v'`, `b's'`, `b'o'`);
  - tmpfs capacity is computed twice;
  - a misplaced doc;
  - 12 unsafe blocks without SAFETY;
  - stale `CONTRACT §3.6` citations to documents that never existed;
  - `seccomp.rs:783` asserts `< 32*1024` while the assembler allows exactly
    4096 instructions (32768 bytes), so it panics at the limit;
  - x86 syscall numbers in arch-aware tests;
  - two cgroup containment predicates that disagree on `""`;
  - bridge discovery busy-polls `/proc` every 200 µs.

### 6.7 Tracer and observer (TR)

- **H TR1** aarch64 guard (§2 #2).
- **H TR2** clock base (§2 #11).
- **H TR3** `session.rs` → directory module: `outbox`, `restart`, `args`,
  `evidence`, `owed`, `seams`.
- **M TR4** typed task state; a single `release_slot()`.
- **M TR5** a failed `deny_exec` is recorded as `ForeignAbi`.
- **M TR6** raw `kill`s.
- **M TR7** second cBPF toolchain.
- **M TR8** hand-rolled SHA-256.
- **M TR9** the `ProcView` seam is bypassed and `/proc` is read twice per
  exec stop, so exec evidence cannot be unit-tested through `Session`.
- **M TR10** the dead `monotonic_ns` field is on the wrong base.
- **M TR11** duplicate `/proc` helpers and clocks.
- **M-L TR12** the closed-set table is not the single source of truth: the
  filter matches rows by name.
- **L TR13–23:**
  - 21 audit-arch literals;
  - an incomplete `binfmt_misc` model (offset, `P` flag; PLAUSIBLE);
  - filter API sprawl;
  - a failed wake-handler install would let shutdown kill the supervisor;
  - stale x86-only comments;
  - `gap_reasons_have_distinct_names` lists 22 of 25;
  - fallback intervals `0..0`;
  - `finish` mislabels undelivered results;
  - a decoy `Tracer` in `Drop`;
  - test fakes ×3 and session constructors ×4.

### 6.8 Audit, probe, scope, uncontained (AU)

- **H AU1** M2 fix in one path (§2 #3).
- **H AU2** the `shared` doc is false; ~9 run-loop bodies are copied.
- **M AU3** launch gate ×3 at two strengths.
- **M AU4** `class_of` catch-all.
- **M AU5** hard-coded summary claims patched by later layers.
- **M AU6** a relative path joined to a cwd ending in `" (deleted)"`
  (PLAUSIBLE).
- **M AU7** `SO_DOMAIN` fails open.
- **M AU8** an unchecked `fcntl` and a comment contradicting the measured
  NOTIF_RECV behavior.
- **M AU9** three structs for one mediated connect, with `unreachable!` in
  `Verdict::Undelivered`.
- **M AU10** `uncontained::create` 280 lines; 9 state bools; a `-1` pid
  sentinel.
- **M AU11** `integrity` string.
- **M AU12** `/proc` parsers.
- **M AU13** probe registry in 5 places.
- **M AU15** `watch.rs` unsafe hygiene and bare fd numbers 3/4/5.
- **L-M:**
  - doctor evidence claims a ceiling it did not configure;
  - dead `lost_frames`;
  - stale SAFETY and doc comments;
  - `dup2(.., 55)` in a multithreaded test binary;
  - the mediator's fd ownership is split;
  - the doctor agent probe leaks threads;
  - `last_errno` ×4;
  - `PTRACE_SEIZE` and `NETLINK_SOCK_DIAG` duplicated;
  - `Host::lingering` defaults to the authorizing answer;
  - `UDIAG_SHOW_NAME` requested but never read.

### 6.9 Ledger store (LS)

- **H LS1** substring poison classification (§2 #10).
- **H LS2** the GC deletion protocol is duplicated.
- **M LS3** `apply_record` writes `outcome` three times. The last write labels
  a reconciler's own unknown as `observed_child_outcome`, which is visible in
  fleet evidence.
- **M LS4** "none cannot claim enforced" has no effective test; the test is
  vacuous, and deleting the check leaves the suite green.
- **M LS5** 120 bare `.is_err()` vs 12 message checks.
- **M LS6** `validate_payload` hand-copies `request.schema.json` while the
  compiled validator is unused. Drift would brick writer startup.
- **M LS7** the SQLite projection is write-only. It costs a full-record clone
  per request and an fsync transaction per run, and one external reader
  disables it until restart.
- **M LS8** two fault-injection mechanisms (63 `#[cfg(test)]` lines in
  production code), while the jail already has a typed seam.
- **M LS9** `store.rs` is a god module. The `store/` split is by file, not by
  encapsulation (16 files `use super::*` and mutate private fields).
- **M LS10** "private" checks ×9.
- **M LS11** stringly run-state machine.
- **M LS12** frame checks ×3.
- **M LS13** write path and recovery validate differently, so a record could
  be acknowledged and then poison the stream at the next start.
- **M LS14** orphan reconciliation swallows errors and retries silently every
  second.
- **M LS15** test infrastructure duplicated (`peer()` ×5, the `"aaaa…"` token
  ×55).
- **L LS16–25:**
  - temp leak;
  - magic numbers;
  - validators duplicated;
  - the 18-field `Stream` literal ×3;
  - a dead `jail_profile` read;
  - unsafe without SAFETY;
  - `create_dir` then chmod (umask window);
  - unconditional startup rewrites (4+ fsyncs per run, every start);
  - API shapes.

### 6.10 Ledger service, `ouro-records`, `ouro` (LG)

- **H LG1** = LS1.
- **H LG2** `verify(None)` re-reads and re-hashes every stream on the single
  writer thread under a 2 s client timeout, and `doctor` calls it. On a large
  store this can starve a strict owner's heartbeat and fail a live run.
  PLAUSIBLE threshold; mechanism confirmed.
- **H LG3** tee (§2 #8).
- **M LG4** accept error (§2 #9).
- **M LG5** no protocol version; a decode failure is a silent close.
- **M LG6** `run_owned` 395 lines.
- **M LG7** the unknown-outcome body ×4.
- **M LG8** launch resolution ×2 with different validation.
- **M LG9** run-state literals.
- **M LG10** record vocabulary re-spelled. `selection_status` and
  `class_reason` already differ.
- **M LG11** three whole-snapshot pagers with different consistency checks.
- **M LG12** `LedgerError(String)`.
- **M LG13** `main::execute` 352 lines; `version` bug.
- **M LG14** dead public API.
- **M LG15/16** "private" helpers; format validators ×3–4.
- **M LG17/18** checkpoint scans ×2. Every read page rescans all checkpoints
  with about 3 fsyncs on the writer thread (PLAUSIBLE cost).
- **M LG19** jail and ledger define the operator-config envelope and data-dir
  rules separately. The ledger honors `XDG_DATA_HOME`; the jail does not.
- **M LG20** 14 stale `jail-v1.md:N` citations.
- **M LG21** `version --json` overclaims "schema_frozen".
- **L LG22–30:**
  - `ErrorObject.code` and `stage` as `String`;
  - wrapper-note constructors ×4;
  - native-string codec ×2;
  - an unmatched `// J4-R end`;
  - `copy_hash` duplicates `CheckedReader`;
  - `ouro` ignores `--json` and `--signal` and prints errors unescaped
    (cf. A6);
  - a raw `EAGAIN` surfaces to the user;
  - a 5 ms busy-poll owner loop;
  - the bounded-read idiom ×17.

### 6.11 xtask (XT)

- **H XT1** `freeze --check` (§2 #7).
- **M XT2** `drive()` `?` paths skip `summary.txt`, `decide()` and the remote
  cleanup report.
- **M XT3** `test.log` is parsed by two parsers with different nested-run
  rules.
- **M XT4** receipts are read as untyped JSON with fail-open defaults; a typed
  `Receipt` exists.
- **M XT5** six functions over 180 lines.
- **M XT6** budget numbers hard-coded in prose.
- **M XT7** revision parsed ×4, with a `0000…+dirty` sentinel.
- **M XT8** git call sites ×6–7 and process runners ×3.
- **M XT9** driver-check names ×3.
- **M XT10** gate-status rule ×2; release scope written as clause ids in Rust.
- **M XT11** the I02 scan scope and the dependency-pin scope disagree:
  ledger and records dependencies are never reviewed.
- **L-M XT12** 3 stale I02 homonym allowlist entries; nothing checks the TSV
  against the tree.
- **L-M XT13–16:**
  - `stamp.rs` duplicates the date code;
  - `sha256` shells out to `sha256sum` (null if absent) while `sha2` is a
    dependency;
  - freeze scrapes Rust source for public constants and `#[path]`-includes
    `build_provenance.rs` a third time;
  - `perf::launch` swallows the evidence copies its report promises.
- **L XT17–25:**
  - contradictory "kept/not created" output;
  - `"n/a%%"`;
  - a 17-field `Option` bag;
  - prose-matching tests;
  - crate attribution by cargo print order;
  - a stale `Cargo.toml` description;
  - pid-named temp dirs;
  - workflow duplication;
  - p95 definitions differ from the Python harnesses (nearest-rank vs
    interpolation), so cross-family p95s are not comparable.

### 6.12 ouro-fixture (FX)

- **H FX1** perf-launch (§2 #17).
- **H→M FX2** the oracle re-implements product contracts already exported by
  `ouro-records` (`#[path]` include of `jcs.rs`, digest, a weaker
  `trace_guard`, schema constants ×3).
- **M FX3** the stand-in jail has drifted: stage `"gating"` is not an
  `ErrorStage`; stale "ouro-jail does not exist" docs.
- **M FX4** three tests exercise a re-implementation, not production code.
- **M FX5/6** `ops.rs` is dispatcher, library and perf launcher in one; the
  harness has two methods of about 170 lines.
- **M FX7** boolean soup on `open(path, via, create, trunc, write, rdwr,
  mode)`.
- **M FX8** `Usage = String` mixes usage and runtime failures; `script` exits
  2 after side effects.
- **M FX9** overclaiming comments.
- **M FX10** `fixture_lines()` silently drops non-JSON lines, so an absence
  assertion can pass vacuously.
- **M FX11** `Spawned` has no `Drop`, so a panicking test leaves the jail
  running.
- **M FX12/13** in-crate duplication; two syscall-availability sources keyed
  by string.
- **L:**
  - `connect` bypasses the raw layer;
  - `exit` truncation (§2 #26);
  - `fds` claims complete after scanning nothing;
  - a per-tick receipt re-parse in the sampler;
  - errno lost through name round-trips;
  - errno spelling differs across crates;
  - dead code;
  - 28 markers;
  - a weak ignore-term test;
  - duplicated test helpers that do not strip proxy variables.
- **Cast audit:** real truncation only in `exit`, Darwin `mode_t` and one
  pre-guard cast. The rest are bounded by contract and can be made explicit
  with `const` asserts and `try_from`.

### 6.13 Integration tests (TS)

There are 988 `#[test]` functions in about 75k lines.

- **H TS1** Copies of the record-check helpers have drifted, and a spec claim
  is false (§2 #27). `fn settled(run)` is defined in 7 files at 4 strengths.
  Files that read traces or control transcripts without checking them:
  `conformance_j1`, `j4_records_linux`, `j4_trace_linux` (the R03 delivery
  file never checks `source_seq` for holes), `j5_process_linux` and
  `review_linux`.
- **H TS2** The release-evidence check runs in the plain `cargo test` (§2
  #28).
- **M TS3** 11 hand-written simulated `Platform` impls (about 1,000 lines).
  The boot-id literal appears 8 times.
- **M TS4** About 3,000 lines of C helpers embedded as Rust strings in 6
  files. `report` and `mode_launch` are each defined 5 times. Build dirs
  under `/tmp` are keyed by pid and never removed.
- **M TS5** Schema registries are built in 12 places, and 8 skip the
  duplicate-`$id` guard that the J5-C review added to `common::load_schemas`.
  Several re-parse every schema and `Box::leak` a `Registry` on every call.
- **M TS6** 12 copies of the delegated-leaf precondition probe, with
  different composition and no caching. All pass the placeholder
  `Path::new("bwrap")`. `enum Profile` is duplicated instead of using
  `ProfileName`.
- **M TS7** Host-pinned AppArmor assertions bypass
  `common::reference_host()`, and have already failed on another host.
- **M TS8** About 25 platform-independent `explain`/config/CLI tests live in
  the macOS-only `macos_refusal.rs`, so they never run on Linux, the only
  shipping platform.
- **M TS9** `#[ignore]` means three things: self-exec helpers, a "bless"
  that rewrites the checked-in closed-set evidence, and external data. So
  `--include-ignored` is destructive.
- **M TS10** A self-exec parent passes when its helper did not run (0 tests
  matched). Only 1 of 10 sites checks for "1 passed".
- **M TS13** A stale premise: "Linux refuses `agent` (wave 2 enables it)".
  The test probably passes now because PATH is missing (PLAUSIBLE).
- **L TS11** `tests/tmp_matcher_probe.rs` is a committed debug probe with no
  assertions (**V**).
- **L TS12** Test names claim more than they assert (`r2_exec_failures_are_distinguishable`
  never asserts distinctness).
- **L TS14** Stale shared docs: "all three Linux test binaries" when 53 files
  use `common`; "Live tests need `OURO_CONFORMANCE=1`". Fixed `/tmp` names
  collide across runs.
- **L TS15–20:**
  - ledger tests have no `common` module (`Process` ×3) and hand-roll pidfd
    calls;
  - 34 of 171 test `unsafe` blocks have no SAFETY comment;
  - inert `#![allow(clippy::too_many_lines)]` attributes;
  - 31 of 64 files are named by milestone or audit rather than feature, with
    colliding prefixes (`r05_` row vs `r5_` review vs `r10_` regression);
  - 110 `thread::sleep`, 80 hand-rolled deadline loops, and 388 duration
    literals against 9 named bounds;
  - 14 bare `is_err()` asserts on tamper detection;
  - an unchecked `find -printf` status.
- **Test-only hooks in the product.** 12 `OURO_JAIL_TEST_*` seams are read by
  the release binary. This is by design and recorded by prefix scan.
  `tracer/session.rs:567` overclaims that "the release binary is unaffected".
  Integration tests reach about 90 internal paths, which forces every module
  in `lib.rs` to be `pub`.
- **Good:**
  - consistent `skip_or_fail` with `OURO_CONFORMANCE=1` turning skips into
    failures;
  - specific assertions (exact errno, per-class coverage, inode identity,
    pidfd liveness);
  - races asserted as exercised;
  - named, justified bounds in `j5_lifetime_linux.rs`;
  - the ledger launch suite's feature-named `#[path]` submodules are the
    model to follow.

### 6.14 Repository hygiene, CI, tooling, fleet, website (RH)

- **H RH-01 Evidence weight.** 60,802 of 63,108 tracked files are
  `docs/benchmarks` (1.87 GiB checked out). They are 438 of the 443 MiB
  reachable from `dev`; code is about 9 MiB. Each comparison corpus is
  committed twice, as an extracted tree and as a tarball of that tree (39
  archives, 381 MiB raw, about 338 MiB packed; split into parts to dodge
  GitHub's limit), with nested archives a third time. Also:
  - 34,600 paths repeat an existing blob;
  - 10,218 files are empty;
  - `fixture.py` is copied 46 times;
  - 14 ELF binaries are committed (111 MiB);
  - 392 MiB was added on 2026-10-12 alone.

  **Do not rewrite history:** 4,778 evidence JSONs name commit SHAs. Instead:
  - Keep narrative, analysis, SHA256SUMS and a `bundle.json`
    `{url, sha256, bytes, files}` in git.
  - Move bundles and binaries to release assets under immutable
    `evidence/...` tags.
  - Add `xtask evidence verify`.
  - Store one harness copy per hash.
  - Add a CI size guard.
- **M RH-02** 14 unreferenced probes at the repo root. `a6_battery.sh` is
  0755 and writes `/proc/sysrq-trigger` with no guard; others hard-code
  `/home/ubuntu`. Move them under their audit's docs, or delete them.
- **M RH-03** four installers. Root and website copies are kept equal by a
  test, but refreshed by a manual copy. The website is deployed from the
  local tree, outside CI. Root and `dist` share about 100 lines, and the full
  SemVer test corpus covers only `dist`.
- **M RH-04** 178 `assert` statements in gate scripts. Under `-O` or
  `PYTHONOPTIMIZE` they vanish, and the scripts print PASS.
- **M RH-05** `check_install.py` (§2 #18).
- **M RH-06** `.gitattributes` comments overclaim; use `-text` on evidence.
- **M RH-07** conformance copies 121 MiB per run via a deny-list. Use an
  allowlist.
- **M RH-08** no build cache in CI; `cargo-deny` is compiled from source on
  both legs.
- **M RH-10** no `[workspace.dependencies]` (clap `"4"` vs `"4.6.6"`, ...),
  missing `rust-version.workspace`, stale `Cargo.toml` header.
- **M RH-12** `vm/run.py execute()` 250 lines with about 15 state flags; a
  `TypeError` escapes and leaves a non-terminal `attempt.json`.
- **M RH-17** fleet: bad client input raises, so the GenServer stops and
  `:one_for_all` restarts the node's Lock, Worker and Controller. The error is
  mislabeled "persistence unknown".
- **M RH-18** fleet: `Port.close` on timeout does not kill the OS process.
- **M RH-19** fleet `Epmd` moduledoc describes non-existent infrastructure.
- **L-M:**
  - workflow inconsistencies (no `timeout-minutes` on contracts, no
    dependabot for SHA pins, floating runner images, mixed shell defaults);
  - deny.toml has no `[sources]` section;
  - VM limits ×2;
  - `package.py` overwrites `source_sha256` semantics;
  - `TARGETS` ×4, still listing Darwin;
  - release coordinates hard-coded 78 times in 19 files;
  - fleet version map ×5, and a version mismatch is reported as "retry";
  - fleet status over 4,096 jobs inside one call;
  - absolute host paths in 6,500 evidence files;
  - the website links `blob/dev` docs from a release page;
  - no UTS46 regeneration drift check.

## 7. What is notably good

- **Descriptor discipline.** `state/anchored.rs`, `cleanup.rs` and
  `reconcile.rs`:
  - validated single-component names;
  - `O_PATH` plus identity re-verification;
  - bounded, mount-refusing traversal with a stated termination bound and a
    seeded hostile-tree test.
- **Seccomp.**
  - a label-resolving assembler that rejects bad jumps;
  - verdict tests driven by an interpreter;
  - byte-pinned evidence tables;
  - architecture checked before the syscall number;
  - x32 denied;
  - numbers cross-checked against libc on both architectures.
- **Testability by design.**
  - The persistence seam's named `Site`/`CrashPoint`.
  - `gc::decide` as a pure probe protocol.
  - The scope `Host` trait with a scripted fake.
  - Recorded `OURO_JAIL_TEST_*` seams that can only shrink limits.
  - SIGKILL crash matrices in the ledger.
- **Honesty mechanics.**
  - Every unverifiable fact becomes a named gap.
  - "The kernel rejected it too" stops a tracee from manufacturing loss.
  - `verdict()` cannot produce `tree_empty = Some(false)`.
  - `ResultSlot` guarantees one result per proxy connection, even across
    panics.
  - Text renderers escape untrusted strings.
- **Bounds everywhere.** Reads use `take(N+1)`; frame caps on both protocol
  sides; in-flight and backlog bounds in the tracer; bounded resolver queues.
- **Low `unwrap` surface.** 77 `unwrap`/`expect` calls outside tests, none
  reachable from input.
- **Release pipeline and installer.**
  - whole-script function;
  - pinned hashes checked before extraction;
  - downgrade and symlink refusal;
  - ELF machine checks;
  - signed plan;
  - assets re-hashed after publication;
  - SHA-pinned actions with `contents: read`;
  - skipped tests surfaced in the job summary.
- **The uncommitted fix's process.** It was developed red, then green, with
  hash-bound evidence and an explicit failure attribution for the quota run.

## 8. Numbers

| Metric | Value |
|---|---|
| Rust code lines in `src/` (non-blank, non-comment, incl. inline unit tests) | jail ≈ 61k, ledger ≈ 19k, xtask ≈ 13k, fixture ≈ 11k, records ≈ 2k |
| Integration tests | ≈ 80k lines (jail ≈ 70k) |
| Comment share (non-blank lines) | jail 24%, records 33%, fixture 15%, xtask 9%, ledger 2% |
| Functions over 100 lines (macOS-visible) | 61, plus about 20 Linux-only |
| `unsafe` vs SAFETY | jail 467/423, ledger 116/33, fixture 222/211 |
| Milestone markers | 564–650 (regex-dependent) in 33+ files |
| Trivial `unsafe { libc::geteuid() }`-style calls | 82 in 45 files |
| `let _ =` in src | 495 (most benign teardown) |
| `unwrap`/`expect` outside tests | 77 |
| Duplicate code, production (12-line window) | 259 normalized lines (low) |
| Duplicate code, tests (15-line window) | ≈ 1,100 normalized lines, plus ≈ 3,000 lines of C helpers embedded in 6 files |
| `#[test]` functions | 988 in ouro-jail and ouro-ledger integration tests |
| Repo pack | 2.55 GiB total (legacy included); `dev` 443 MiB, of which evidence is 438 MiB |
