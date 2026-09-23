# Jail v1 review resolutions

Revision 2, 2026-09-21. These are specification repairs and checked document
fixtures. Every kernel/backend/agent acceptance gate still requires a real
implementation and measured conformance; none is claimed passed here.

| Review issue | Resolution | Contract / acceptance |
|---|---|---|
| Host pathname Unix sockets cross network namespaces | Require host-peer isolation for pre-existing and late-created sockets, while preserving same-attempt IPC; refuse agent when the backend cannot prove it | §§5.1, 10; S02–S03, N05 |
| io_uring can bypass socket syscall restrictions | Deny setup/enter/register on all contained profiles and inherit no ring fd; do not expand observation claims | §9.2; S04 |
| None cgroup migration and settlement | Separate target exit from population; add registered-boundary scope, detected-integrity-loss handling and migration fixtures without promising detection of all uncontained effects | §§9.3, 13.2; R05–R06 |
| Directory operations lack coverage assignment | Map create/write/rename/unlink to fs.write; denied connect maps to fs.deny with attempted_operation | §§11.2, 11.4; O01, O03, O05 |
| proc.exit conflates threads and processes | Require final thread-group termination after witnessed exec, including leader-exits-first and non-leader exec fixtures | §11.2; O02 |
| Proxy endpoint can be replaced | Move socket out of scratch, pin its protected directory/identity, and preserve the trusted bridge view under child/nested mount changes | §10; N05 |
| Proxy numeric-address and IDNA ambiguity | Freeze IDNA processing and conservative prefix data; normalize mapped IPv6, reject obsolete/ambiguous forms, declare network-specific translation assumptions | network-rules.md and address fixtures; N03 |
| Preferred pids vs required cgroup confusion | One defaults table; explicit limits required, built-in pids preferred; a cgroup does not imply its pids controller exists | §6.4; L03 |
| Prepared/refused receipt overclaims | Constrain actual boundary/application, add scope/integrity, correct pre-boundary refusal and add prepared fixtures | §13.2 and receipt schema; R01 |
| Unknown exec with known empty boundary | Preserve valid settled/unknown; proved exec errors remain refused | §13.2; R01 |
| Canonical digest bytes incomplete | Exact snapshot schema, native-string codec, domain/NUL framing, U64BE argv framing and TOML/JCS/hash golden vectors | canonicalization.md; P01 |
| Credentials absent from schema | Required staged-input provenance array with id/mode/digest or reason, forbidding source paths | §12 and receipt schema; C01, R01 |
| Native path bytes rejected by receipt schema | Shared UTF-8/base64 representation for mount paths, grant values and private snapshot values; semantic canonical-codec checks | canonicalization.md and byte-path example; P01, O06, R01 |
| limit_hit and remediation fields drift | Per-limit hit plus outcome cause/signal; required remediation category; remove stale parent receipt sketch | §§6.4, 13.2 and north-star §4.8–4.9; R01 |
| Shared event inventory mistaken for jail authority | Separate jail producer schema; reserve net.dns, limit.hit and intent.* from jail writers while preserving future owner envelope | §13.1; R01 |
| Audit decisions overclaim enforcement knowledge | All audit decisions null; proxy decisions remain explicit | §§11.2, 13.1 and event schema; R01 |
| Proxy coverage masks disabled audit coverage | Separate net and proxy.net, fixed source mapping and unsupported/null rules | §11.4 and receipt schema; O05, R01 |
| Config and launch grammar gaps | Define operator/project wrappers, launch location, state_subdirs creation and LD_*/DYLD_* rejection | §§6.2–6.3, 12; P02, C01 |
| Inspection exits, gate ending and label-only combinations | Explicit command exit codes, exactly one LF then EOF, incompatible gate/id flags refused | §§6.1, 6.4, 8.2; X02, M03 |
| Suspend and libc ambiguity | BOOTTIME/continuous suspend semantics; glibc conformance fallback and independently tested other runtimes | §§6.4, 9.2; L04, S01 |
| Attempt-id grammar | UUIDv4 version/variant, lowercase, same validation for managed IDs; no authority from possession | §7 and schemas; X02, R01 |
| Milestone placement | macOS build/refusal gates at J1; agent-specific tests at J3, GC at J4 | §16 |

The fixes intentionally retain optional built-in pids, legitimate internal Unix
IPC, the closed observer set and unprotected none semantics. J0 must report a
named blocker if a containment requirement cannot be implemented; this document
does not select an unmeasured mechanism or silently weaken those requirements.

## Revision 4 findings (2026-09-22)

Process and host findings from the 2026-09-22 review of the tooling tree. None
changes a containment or record contract; each names where the resolution lives.

| Review finding | Resolution | Contract / acceptance |
|---|---|---|
| D8 undated and nothing of J0 started; report path referenced but absent | D8 scheduled as J0 with the observer measured first; skeleton report checked in with every value `not_started`; revisions before J0's report limited to corrections and measurements | North star D8, §8; jail §5, §16; backend-evaluation.md |
| Initial x86_64 lane versus available hardware | Reference host fixed as an operator-provisioned x86_64 VPS running its own kernel; container-based hosts ineligible; host manifest fields enumerated; aarch64 a later lane | North star D9; jail §3.2 |
| Preserved-history links depend on an unpushed ref | `legacy` and tag `thesis-4-preserved` at f3b2dbfd must reach the remote before `dev` is replaced there | North star §9, §12; jail §18 |
| D2 archive not created | D2 restated: `legacy` plus the tag at the same commit is the archive; no `thesis-4` branch | North star D2, §9 |
| Observer provisioning on Ubuntu 24.04 is the critical path | Measured first in J0; provisioning mechanisms and smallest capability set recorded; ptrace and fanotify named as fallbacks with their limits; blocked observer is a valid J0 exit and never licenses `--observe off` for J1 | North star §11; jail §§3.2, 5.2, 16 |

## Revision 5 decisions (2026-09-22)

| Decision | Resolution | Contract / acceptance |
|---|---|---|
| Reference host runs Ubuntu 26.04 LTS, not the 24.04 revision 4 pinned | Re-pinned to the release the host runs; first manifest collected read-only by `host-manifest.sh` and checked in under `evidence/`; `doctor --json` supersedes it | North star D9; jail §3.2 |
| Repository layout for the whole north star | One workspace: `crates/` per process with fixed split rules, `fleet/` outside Cargo, contracts and evidence under `docs/specs/`; bootstrap files added, no crate | North star D7; jail §4 |
| Conformance runner model | Hosted runner drives the host over SSH as non-sudo `ouro-ci`; push/dispatch only; job fails once `Cargo.toml` exists until the driver runs | Jail §3.2, §16; `.github/workflows/conformance.yml` |


## J1 review findings (2026-09-22)

Two adversarial reviews of the first implementation slices (portable core,
Linux ptrace observer) found defects and spec ambiguities. Defects are fixed
in the implementation with regression tests; the ambiguities are resolved
here and in revision 8 of the specification.

| Finding | Resolution |
|---|---|
| Untrusted `ouro.toml` re-granted a denied subtree through a symlink or a case variant; a deeper grant overrode a denial | §6.3: identity comparison for untrusted layers, denial wins at any depth |
| An unreadable or non-regular `ouro.toml` silently discarded the narrowing layer | §6.3: only a missing file means no narrowing |
| The §6.3 example profile refused when stored in the config directory | §6.3: relative paths resolve against the file; the example narrows the workspace beside it |
| §6.4 "Required by observer" read as "always" | §6.4: required by a cgroup-filtering observer or an explicit tree limit |
| An unverified tree after exec was reported as `refused` on the control channel | §8.2: `refused` only before release; new terminal kind `unsettled` |
| `applied.network.mode` for a pre-boundary refusal: `pending` for contained profiles; the `none` fixture and schema say `host` | §13.2: `pending`, except `none`, whose mode is `host` by definition |
| `policy.grants` was always empty | §13.2: the explicit operator grants beyond the baseline |
| `explain --json` printed environment values | §6.1: names only |
| Budgets used the plain monotonic clock while the receipt could name a boot-time deadline | §13.2: the receipt names the clock it uses; suspend semantics are L04 (J2) |
| `mknod`, `mknodat` and `truncate` were inside the native ABI, outside the closed set and not denied | §11.2: the closed set has 22 rows; `ftruncate` named as excluded |
| The event queue bound was a count the child could turn into 125 MiB | §11.4: bytes |
| Queue gaps named no class | §11.4: gaps name the dropped operations' classes |
| A child could stop its own strict attempt with unreadable arguments | §11.4: kernel-rejected arguments are unavailable metadata, not loss |
| A read-only open that failed produced no event and the text read as "uncounted" | §11.2: read denials are excluded, not uncounted |
| "Protected supervisor state" for stdio was read as this attempt's directory | §8.3: the whole runtime state root; an uninspectable descriptor refuses |
| A workspace beneath the scratch mount point left a path skeleton inside managed scratch | §9.1: recorded as the backend's side effect |
| A proved exec failure used `outcome.kind = refused` | §13.2: `exec_error` with the errno |
| Scratch removal at settlement was a precondition, not an obligation | §14.2: removed at settlement after verified tree death, retained otherwise |
| A supervisor killed during bubblewrap's startup leaves an orphaned outer bubblewrap holding stdio (bubblewrap clears the inherited parent-death signal) | §9.3: recorded limit; closing it is scheduled with L02 (J2) |

## Revision 6 findings (2026-09-22, the branch review of J1)

Findings from the full review of `dev` @ 3cb5a538 (PR #43). Each row names the
fix that landed and the contract or test that pins it.

| Review finding | Resolution | Contract / acceptance |
|---|---|---|
| Known-operation result loss reported as bookkeeping: EntryAbandoned/TraceesAbandoned gaps carried `OpSet::EMPTY`, suppressing the §11.4 strict stop and class degradation | Every abandonment gap names the abandoned entry's operation (or the union of still-alive pendings at force stop) | §11.4; O03; `r31_an_entry_destroyed_by_an_exec_names_its_operation` |
| `--args` payload written to a fresh pipe before spawn deadlocked the supervisor on payloads over the pipe capacity, unbounded and uninterruptible | bwrap spawns first and blocks reading ARGS_FD; the payload is written with the reader alive, and a reader that dies surfaces as EPIPE teardown, not a hang | §2 I07; `r9_a_large_option_tail_does_not_deadlock_the_supervisor` |
| P03 (mid-run policy-edit invariance, I11) had no test anywhere | Gated-run test edits the workspace `ouro.toml` between prepared and release and pins digest and applied-mount equality | §6.2, §7; P03; `r9_a_mid_run_policy_edit_cannot_widen_the_attempt` |
| Source-identity pinning unwired: `PinnedPath` dead code, protected binds raced validation→mount by path | Protected segments and the workspace are pinned by `O_PATH|O_NOFOLLOW` handles, verified at mount handoff, and bound by descriptor (`--ro-bind-fd`) up to the spawn map's reserved range | §9.1; F02, F04 |
| Required protected coverage recorded, never enforced; symlinked root literals downgraded silently; `all_descendants` never refused | A scan that cannot certify `existing_and_root` refuses before exec; `all_descendants` refuses on Linux with 125 | §2 I02; north-star §4.4; `r9_a_symlinked_root_git_refuses_rather_than_downgrade`, `r9_all_descendants_coverage_refuses_on_linux` |
| Operator `--rw`/`--ro`/`--deny-read`/`protected_segments` resolved into policy but silently unenforced by the plan | Read-only grants bind, host-rooted writable grants bind, denied subtrees are masked with a tmpfs, operator segments extend the protected walk | §6.1, north-star §4.2–4.3; `r9_deny_read_grants_are_enforced_as_masks` |
| Explicit pids/mem/cpu ceilings passed their capability probe and ran unenforced on delegating hosts | Explicit non-wall ceilings refuse pre-exec in this slice (limits are J2); preferred ceilings keep the record-and-run shape | §6.4, §2 I02; `r9_an_explicit_pids_ceiling_refuses_until_it_can_be_enforced` |
| Strict mode never stopped on trace-sink loss; audit counts stayed active for undelivered frames; the external queue was dropped unrecorded at exit | Sink loss reaches the supervision loop as evidence loss (strict stops), undelivered frames degrade their class and null its count, and a bounded terminal drain records what it cannot deliver | §13.2–13.3, §11.4; R03, R04 |
| `monotonic_ns` and gap intervals used three incompatible time bases and `Instant` (no suspend) | One supervisor-start `CLOCK_BOOTTIME` epoch feeds the wrapper journal, the audit writer and every tracer gap interval | §6.4, §13.1 |
| Lifecycle (Exec) backlog bypassed the §11.4 byte budget (~71 MiB worst case) | Lifecycle events are admitted against the byte budget with a critical-event reserve; over-budget Exec drops are gaps naming the exec class | §11.4 |
| `jail-state.json` omitted the §7 identity (boot id, owner birth, boundary) and the claim skipped the parent-directory sync | The claim records owner birth identity and syncs its parent; the boundary is registered in state once prepared | §7 |
| §5.2 privilege boundary unimplemented | euid-0 and mismatched-UID supervisors refuse pre-exec; the file-capability eBPF path still requires the capability-clearing contract before it lands | §5.2 |
| `config.toml` could select `none`, and its paths anchored one directory too high | Config `none` refuses with the `jail.profile` key path; paths anchor to the directory containing `config.toml` | §6.1–6.2; `config_toml_may_not_select_the_none_profile`, `config_toml_paths_anchor_to_the_config_directory` |
| CLI `~/` expansion, uncanonical `translation_prefixes`, doctor's extra flags, stale redaction doc | CLI paths are cwd-relative; prefixes are parsed and re-rendered as RFC 5952 CIDRs before the digest; doctor takes only its §6.1 flags; the doc states the redaction contract only | §6.1–6.3; portable policy/macos refusal tests |
| Defense-in-depth syscalls missing; `EINPROGRESS` rendered `E?` | `userfaultfd`, `open_by_handle_at`, `name_to_handle_at`, `syslog` join the deny table; the errno table names `EINPROGRESS` | §9.2; S01 |
| Audit path fields diverged from the documented nested `{kind, value}` shape | The emitter matches `examples/event-open.json`; conformance assertions follow | §11.3, §13.1; R01 |
| Birth-identity events collected and discarded; execveat's dirfd dropped on confirmed exec | `Exec` carries its dirfd into classification; per-pid birth identity on every audit event remains open for the J4 evidence work | §11.3 |
| CI: mutable action tags (including in the job holding the host key), no job timeout, silent whole-job skip when unconfigured, deny.toml unenforced | Actions pinned by SHA; conformance job has a 45-minute timeout and a loud not-configured notice; `cargo deny check` runs in `rust` | §16; W-series findings |
| README claimed nothing was implemented and J0 was all `not_started` | README states the J0/J1 landing and what J1 enforces | — |
| P04's credential-special-files sub-clause had no code path in J1 | Scoped to J3 in §16; J1 refuses credential-bearing launch profiles fail-closed | §16 |

The per-attempt cgroup and parent-death deferrals above are resolved by
[J2 authority](j2-authority.md): explicit ceilings enforce when the corresponding
controller/placement/kill probes succeed, and otherwise refuse.

Still deferred with reasons: receipt-fsync on a worker
thread with the 5-second budget (§13.3 — the synchronous write is bounded by
the filesystem; the thread split lands with J4's failure-injection work where
it can be tested); per-pid birth identity on audit events (J4).

## Revision 9 decision (2026-09-22, stock hosts)

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| `agent` required nested user namespaces, which stock Ubuntu 24.04+ denies inside bubblewrap, so it needed a host sysctl or AppArmor profile | The operator requires no host configuration. `agent` guarantees unprivileged nesting (Landlock, seccomp, `no_new_privs`), measured working inside one bwrap layer; nested user namespaces are an optional, measured host capability; where unavailable `agent` runs and an inner namespace sandbox fails visibly; the reference host stays stock | jail-v1 §§3.2, 9.2, 14.1; S03, J3 row; north-star D9, §§4.3, 4.6, 11; backend-evaluation §1.1; manifest `nested_user_namespace` |

## Revision 10 decisions (2026-09-23, J3 reviews)

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| N05 needs a mechanism; kernel 7.0 has no native pathname-peer restriction (Landlock ABI 8) | Seccomp user-notification mediation of `connect`, pathname peers allowed only when bound by a listener in the attempt's network namespace, connect through a pinned handle, datagram AF_UNIX refused, fail closed; named limits recorded | §10; N05, S03; evidence/unixpeer-spike-2026-09-22-ouro-ci.txt |
| A mediated non-Unix or abstract connect does not compose an inner Landlock network rule | Accepted as a named limit confined to the attempt's network namespace; `CONTINUE` is never used for a security decision because a sibling thread can swap the descriptor | §10 |
| One hostile hostname could make the supervisor do unbounded IDNA work | Length limits checked before encoding; per-request work bounded | §10; N04 |
| Proxy deadlines, request framing and numeric grants were ambiguous | Absolute header deadline, per-phase resolve/connect deadlines, one request per connection, numeric grants apply to any resolving name | §10; network-rules.md |
| `--launch` silently replaced the config-selected profile | Explicit precedence; a base conflict refuses | §6.1 |
| `bind_ro` digest trusted a read-only mount of a writable filesystem; credential sources could sit inside a child-writable grant | Digest only on immutable filesystems; sources inside writable grants and multiply-linked `bind_ro` sources refuse | §12; C01 |
| Vendor-state location and its protected-literal coverage were unstated | `/run/ouro/state`; attempt-private roots excluded from `existing_and_root` | §9.1 |

## Revision 11 decisions (2026-09-23, J3 integration)

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| A network namespace does not isolate every socket family the kernel offers | Contained profiles create sockets only in AF_UNIX (per profile), AF_INET and AF_INET6; others fail EAFNOSUPPORT | §9.2; N01 |
| Every contained target started with SIGPIPE ignored (inherited from the launcher's runtime) | The launcher restores exactly what the jail changed (SIGPIPE, the inherited mask); operator dispositions pass through | §9.2; X06 |
| The bridge's own connects could be counted as the target's; its death note fired on every teardown; proxy death and mediation-queue loss were not tied to strict evidence | Bridge attributed by pinned identity; death noted only before settlement; proxy death and mediation overflow are evidence loss (strict stops) | §§10, 11.4; N04 |
| `none` could silently drop a narrowing restriction; unsettled runs without exec were labelled `enforced` | Unapplicable restrictions refuse; such runs stay `prepared` | §§8.1, 9.3; R05, R06 |
| A crashed attempt's proxy directory was never collected | `gc` removes it through the socket identity recorded at bind | §14.2 |
| A test-only queue knob and launch-profile reserved names were unstated | Documented | §§6.2, 12 |

## Revision 12 decisions (2026-09-23, the first real agent run)

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| The unix-peer mediator refused every connect from a worker thread (`seccomp_notif.pid` is a thread; `pidfd_open` refuses a non-leader) | Open the notifying thread itself (`PIDFD_THREAD`); on older kernels use the leader only when `kcmp` shows a shared descriptor table, else refuse | §10; N05 (`n05_connects_from_worker_threads_are_mediated_like_any_other`) |
| Stock Ubuntu homes (umask 002, user private groups) made the default state root and credential sources look shared-writable | Group write is "others" only when the group is not the owner's private group | §§6.2, 12 |
| No real agent run was recorded | OpenCode 1.18.32 under `agent` on the stock reference host, recorded with its receipt | A01; agent-compatibility.md |

## Revision 13 decisions (2026-09-23, opening J4)

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| §8.2 said `refused` is sent only before release, while §8.1 counts a failed target exec after release as a pre-exec failure (refused) | `refused` is sent while the target has not executed, including a failed exec after release; after a target exec the terminal message is `settled` or `unsettled` | §§8.1, 8.2; X04 |

## Revision 14 decisions (2026-09-23, J4 record, observer, lifecycle and trace defects)

Found by reading the code; each was reproduced by a failing test before the fix.

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| `gc`, including `--dry-run`, created `jail.lock` in every attempt root it probed, and a pre-created managed root then refused its first attempt with `attempt_exists` | `gc` locks only an existing `jail.lock` (read-only, no follow, nonblocking) and never creates one; a root without a lock is retained untouched and reported | §14.2; C03 (`j4_d3_*` in `portable_j4_records.rs`) |
| A receipt revision became visible before its number was spent, so a failed extra copy or directory sync reused it | The revision is spent before the canonical rename; revisions increase strictly and may skip | §13.2; R02 (`j4_d4_*`) |
| A later wall expiry or strict evidence loss overwrote `outcome.cause`, while the platform kept the first stop reason | The first stop reason the supervisor acted on stays the cause; later ones are recorded as limit hits and errors | §6.4; R04 (`j4_d5_*`) |
| Credentials kept the resolver's `id` order and environment bindings their name order, while canonicalization sorts every array by canonical bytes | Keyed collections sort by their elements' canonical bytes; no golden digest moved (the P01 fixture has no launch group and its binding names sort the same either way; the bundled launch profiles' id order equals their dest order) | canonicalization.md; P01 (`j4_d7_keyed_collections_sort_by_their_canonical_bytes`) |
| A child could install its own seccomp notification listener in `tool`, `build` or `none`; it outranks the observer's trace stop, so a continued closed-set call ran with no event while coverage read active | `tool` and `build` refuse a listener (EPERM); in every observed profile the observer stops on a listener request and a granted one is a `child_notification_listener` gap in every class; filters that only refuse are a named exclusion; a trace stop another filter requested is continued, not a loss | §§9.2, 11.4; O01, O03 (`j4_d1_*`, live and unit); the `tool` baseline digest moves to `3d2fc443…` |
| In `none` the observer's filter let other ABIs (i386, x32) through, so their closed-set calls went unobserved while coverage read active | The observer stops on every call under another ABI, never decodes it, and records a `foreign_abi` gap unless the kernel answered ENOSYS | §11.2; O01 (`j4_d2_*`); r27 now expects the foreign label |
| The observer's queue checked its count cap before the exemption for critical facts, so a full backlog dropped a target's exit | Exit, untraced-child exit and observer-end facts pass every cap; gaps past a cap merge into one summary per reason | §11.4; O03 (`j4_d6_*`) |
| Killing `doctor` left probe processes on pid 1: the agent probe's `ouro-jail run` was not tied to `doctor`, and three forked probe children armed no parent-death signal or did not re-check the parent after arming it | Every probe child arms the signal and leaves at once if its parent is already gone; the agent probe's jail keeps §9.3's no-leaf limit when `doctor` runs outside a delegated scope (a later review measured `r7` failing 5 of 25 there, 0 of 25 inside a scope) | §14.1; `r7_doctor_leaves_no_orphaned_fixture_process` (failed in the J4 conformance run, 3 in 10 alone) |
| A supervisor killed during bubblewrap's startup made the watcher kill only the outer process, and the namespace init, whose own parent-death signal was not armed yet, stayed alive until `gc` | Where the attempt has an execution leaf, the watcher holds its `cgroup.kill` and kills the whole leaf, then the backend (without a leaf the limit remains and is recorded in §9.3); a dead supervisor decides even when the backend ended first (bubblewrap's parent-death signal follows the thread that started it); the supervisor releases the watcher when it sees the backend's end, and an unreleased watcher waits a 500 ms grace for the supervisor's death | §9.3; L02 (`j4_lifecycle_linux.rs`, 7 tests: supervisor death, both at once, backend first, released, unreleased grace, release pipe closed, and the real run's wiring) |
| A local trace write that failed part-way (disk full, file-size limit) left a torn frame, and later frames were appended after it (N2) | Writes go to explicit offsets; a failed write is truncated back to the last frame boundary, or the sink closes | §13.3; R03 (`j4_r03_a_failed_local_write_never_leaves_a_partial_frame_mid_file`) |
| The external sink copied its whole queue on each flush, so flush cost grew with the backlog (N3) | Whole frames are queued and written from the front frame's offset | §13.3; R03 (`j4_r03_flush_cost_does_not_grow_with_the_queue`) |
| After a trace loss, ordinary frames were still accepted after the hole and the loss note could be refused | A lost sink keeps a prefix: only reserve notes follow, and the first loss writes one `coverage_gap` note with reserve priority | §13.3; R03 (`j4_r03_after_*`, `j4_r03_a_coverage_gap_note_*`) |
| The harness failed a whole run on a torn last trace line, and nothing defined "recognizable" (S8) | `trace::read_frames` classifies a trace as complete, visibly incomplete or corrupt, and the harness uses it | §13.3; R03 (`j4_r03_a_torn_last_trace_line_is_reported_not_a_failed_run`) |

## Revision 15 decisions (2026-09-23, J4 first wave: records, GC, closed set, loss)

Each row was reproduced by a failing test before its fix unless it says otherwise. Persistence sites: P1 claim of `jail-state.json`, P2 `policy.json`, P3 vendor/credential/proxy-directory state, P4 boundary registration, P5 prepared receipt, P6 enforced receipt, P7 integrity-loss receipt, P8 pending receipt, P9 terminal receipt, P10 refused receipt, P11 cleanup record, P12 gc resume (and, for now, gc's reconciliation records), P13 gc's proxy-directory record.

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| No persistence failure (disk full, short write, sync, rename, directory sync) or crash was injected at any site | Every durable write names its site; each site is tested under each fault and crashed at each named point (`OURO_JAIL_TEST_ABORT_AT`) | §§6.2, 7; R02 (`j4_r02_every_site_under_every_fault_leaves_valid_records`, `j4_r02_a_crash_at_each_replacement_leaves_a_valid_prior_file`, which replaces the sleep-timed r8 test, N10) |
| The claim was created empty and then written, so `jail-state.json` was briefly unparseable in every run and a short write left it truncated | Written and synced under a temporary name, published by an exclusive link | §7; R02 (same tests; `portable_state::j4_r02_an_exclusive_publication_never_replaces_an_existing_file`) |
| A failed boundary registration wrote a refused receipt claiming enforced containment with nothing applied, which the schema rejects | The applied mechanisms are read before registration | §7; R02 |
| A failed `policy.json` write returned with no refused receipt (N6) | It refuses through the ordinary refusal path | §7; R02 (`j4_n6_a_failed_policy_write_refuses_with_a_refused_receipt`) |
| Persistence failures exited 1 before exec and some after exec exited 0 (S5) | `state_write_failed` before exec is a refusal (125); after exec a tool error (1) | §6.4; R02 |
| A stalled sync held the supervision loop for 30 s; no persistence worker existed | One persistence worker with a 5-second no-progress budget; a stall or failure stops the child with `state_write_failed` and acknowledges nothing | §13.3; R02 (`j4_r02_a_stalled_sync_never_delays_the_wall`, `j4_r02_persistence_that_cannot_finish_in_5s_stops_the_child_unacknowledged`) |
| Control was never polled or drained, and undelivered messages were not counted (N4) | Polled every iteration, a final drain bounded by 1 s without progress, every undelivered frame counted and printed | §13.3; R03 (`j4_r03_control_backpressure_*`, `j4_n4_*`) |
| The run's reported error took the last error in two arms (D5 remainder) | The first error wins, as `outcome.cause` does | §6.4; R04 (`j4_d5_a_second_evidence_loss_*`, `j4_d5_a_later_persistence_failure_*`) |
| Test seams were recorded ad hoc (S9) | Every `OURO_JAIL_TEST_*` variable set is recorded by prefix in jail state and native details | §6.2 (`j4_s9_every_test_seam_in_force_is_recorded`) |
| Six coverage-status rules, row 4 of the tuple table and the Python semantic checks had no negative or Rust counterpart (R01) | 12 corpus negatives, a row-4 test and a Rust `semantic_receipt` used on every product receipt the tests write | R01 (not defects: pass on the base) |
| gc could lock a `jail.lock` a supervisor had just created and not yet locked; that supervisor then refused `attempt_exists` (191 of 9104 acquisitions on the base) | gc locks only claimed roots; an unclaimed root is retained and reported with exit 0 (N5) | §14.2; C03 (`portable_gc`: `gc_never_contends_for_the_lease_of_an_unclaimed_root`, `a_supervisor_taking_its_lease_is_never_refused…`, `an_unclaimed_root_without_state_…`) |
| gc cleaned a corrupt or foreign-platform attempt, followed a symlinked entry or `attempts/`, bounded removals but not its listing, and never touched a cgroup | Corrupt and foreign attempts are retained and reported; symlinks are skipped or refused; the bound is per invocation, listing included (S7); a positively identified populated orphan leaf of this boot is killed, verified empty and removed; other boots, live owners and unverifiable leaves are never acted on; records go to jail state and gc's report (S6) | §14.2; C03 (`portable_gc`, 16 tests; `j4_gc_linux`, 7 live tests) |
| A child could create an untraced descendant with `clone(CLONE_UNTRACED)` (N1) | Contained baselines refuse it (EPERM); in `none` it is an `untraced_descendant` gap and the observer's filter answers `clone3` with ENOSYS. Digests: `tool` `d07af277…`, `agent` unprivileged `6f7b5d4c…`, namespace `da4883af…`, narrowing filter `9e631015…` | §9.2; O01 (`j4_clone_untraced_refused_in_contained`, `j4_clone_untraced_is_a_gap_in_none`) |
| Audit events carried no birth identity, so a recycled tid could not be told apart (S1) | `fields.pid_start_ticks` on every audit result; PID reuse is not forced live on a stock host, a unit-level hook simulates it | §11.3; O02 (`j4_o02_*`) |
| A successful exec's event did not name its call, and the closed-set table was not published | `fields.syscall` on `proc.exec`; `evidence/closed-set-x86_64.txt` generated from the build and checked against a live receipt's narrowing-filter digest | §11.2; O01 (`j4_o01_every_variant_is_one_event_per_result_{tool,build,none,agent}`, `j4_closed_set_the_published_table_is_the_one_this_build_traces`) |
| Two fixture modes were never called (N8) and two r6 tests asserted nothing (N9) | The modes run; the tests assert what they are named for | O01, O06 (pass on the base: coverage, not defects) |
| Nested namespaces (S10) | `none` running the host's bubblewrap, traced one layer down, is the measured limit | §11.3; O02 (`j4_o02_a_nested_pid_namespace_under_none_keeps_host_attribution`) |
| The observer's bounds in force were not recorded in the receipt | `observer_plan` in native details: backend, in-flight, queue bytes and events, path snapshot and event maxima, `kernel_ring_bytes: null`, test seams | §11.4; O03 (`j4_observer_plan_is_recorded`) |
| O03 names eBPF losses (map exhaustion, ring loss, unmatched exit) that the ptrace observer does not have (S2) | Map exhaustion is the in-flight bound, ring loss the user-space queue; an unmatched exit is unreachable by construction, proved at the tracer seam; two shrink-only seams drive exhaustion through the product | §§6.2, 11.4; O03, O05 (`j4_o03_*`, `j4_o05_directory_operation_losses_degrade_fs_write`) |
| Strict/best-effort, first cause, labels and denied-connect counting had no end-to-end tests on the ptrace path | Portable and live tests for each (they pass on the base; mutations turn each red) | R04, O05 (`j4_r04_*`, `j4_o05_*`) |
| `review_settlement_itself_produces_no_helper_note` failed intermittently with `entry_abandoned` | The test raced its own background child's `execve` against settlement; it now waits until the child is asleep. The teardown loss itself is real: a call in flight when its thread is killed may have had its effect | R04 (`j4_r04_a_call_in_flight_at_teardown_is_loss_{tool,none}`) |

## Revision 16 decisions (2026-09-23, J4 second wave and its reviews)

Wave 2 fixed what wave 1's slices and the adversarial reviews found; each row was reproduced by a failing test first unless it says otherwise. Persistence sites added: P14 gc's reconciliation records, P15 the execution leaf's name before `mkdir`, P16 its device and inode right after.

| Issue | Resolution | Contract / acceptance |
|---|---|---|
| A loss the platform queued during settlement never reached `errors[]` or the exit code: strict runs exited 0 with classes reading degraded (14 of 15 on the base) | Any evidence class degraded in the observer's final account is an `evidence_lost` error and exit 1, in either mode | §11.4; R04 (`j4_r04_a_call_in_flight_at_teardown_is_loss_*`, 25/25 per profile; `j4_w2s_r1_*`) |
| A loss processed after the target's own end became `outcome.cause` beside a natural exit | Recorded and exit 1, but never a stop request or the cause | §6.4; R04 (`j4_w2s_r2_*`; the platform flag is proved portably only: the live ordering is rare) |
| The execution leaf was created before anything registered it, so a crash there leaked a leaf gc could never find (N7) | Registered by name before `mkdir` (P15) and by identity right after (P16); gc reads it from state; a name-only leaf is removed when empty, never killed | §§7, 14.2; C03 (`j4_r02_*` crash points P15/P16, `portable_gc` N7 cases) |
| gc's records shared P12; a dead attempt's temporary files stayed; vendor cleanup escaped gc's bound (S7); gc's own verified kill did not permit vendor cleanup | P14; temp files of the root records removed under the lease of a dead owner and reported; resumption charged to the bound; gc's verified-kill record permits cleanup, lost integrity refuses | §14.2; C03 (`portable_gc`, `portable_persistence`) |
| An unsettled attempt's final receipt note was normal priority, so after a trace loss the trace never ended on it; a receipt written after an already-handled trace loss kept the wrapper `supported` (trace review) | The terminal note is always reserve priority; every receipt after a known loss carries the degraded wrapper and one extended gap per class | §13.3 (`portable_w2s_trace`) |
| A `jail.receipt` note's digest was over the product's own compact serialization, which a consumer could reproduce only with the writer's field order; the spec did not say what bytes it covers | `sha256:` over the receipt's RFC 8785 canonical bytes, recomputable from `jail.json`; the harness includes the product's serializer by path and checks every live trace's final note against the final receipt | §13.1, canonicalization.md (`portable_unsettled_phase::the_receipt_note_names_the_receipt_by_its_canonical_digest`, red before; `Run::trace_events()`) |
| The terminal trace drain could give up with a frame half written and then write the gap and receipt notes after its torn bytes, a corrupt stream (adversarial review, reproduced live 1 run in 3) | A partial frame on the wire ends the external stream: nothing more is written, and the consumer sees a visibly incomplete last line | §13.3 (`j4_r03_a_drain_that_gives_up_mid_frame_writes_nothing_after_it`) |
| The trace-cap seam accepted `+8192` and `08192` (trace review) | Plain decimal digits only | §6.2 (`j4_r03_the_trace_cap_seam_can_only_shrink`) |
| A covered call interrupted by a handler without `SA_RESTART` left no result and no gap while coverage read active (O-2) | A restart code is not a result; the observer single-steps to the kernel's decision: re-entry, `EINTR` at the handler (for `ERESTARTSYS` from the saved frame), death (nothing), or a `restart_unresolved` gap | §11.2; O01, O03 (`j4_tracer_precision_linux`, 16 live tests) |
| A full in-flight table counted read-only opens outside the closed set as loss (O-1) | Calls are classified before the in-flight bound | §11.4; O03, O05 (exact counts in `j4_o03_*`, `j4_o05_*`) |
| A tracee killed at its seccomp stop recorded a gap in every class although the kernel skipped the call (O-3; 7 of 40 races on the base) | Killed at an unresumed entry stop: no call, no loss; killed after resume or at the exit stop: one `entry_abandoned` gap of its own classes | §11.4; O03 (`j4_o3_*`) |
| The published table did not say `io_uring` is allowed and unobserved under `none` (observer review; the review found no defect in the filters or attribution) | Stated per profile; no digest moved | §§9.2, 11.2 (`j4_closed_set_the_published_table_is_the_one_this_build_traces`) |
| `n04_proxy_death_*` could pick another run's `proxy.sock` from the host-wide socket table | Only the listener whose inode is in the supervisor's own fd table; exactly one, or an error | N04 (a decoy test fails the old rule) |
| Live tests schema-validated receipts but never ran the semantic checks; a torn or receipt-less trace passed as complete; a macOS fixture test failed on `ENOTCONN` from a close landing mid-send (38 of 1200 under load) | `semantic_receipt` after every live schema check (no product receipt failed it); `Run::trace_events()` requires the final receipt's note with its digest; `ENOTCONN` accepted for a failed write on non-Linux only | R01, R03 (test rigs) |
| Supervisor death during bubblewrap's startup still left the namespace init alive where the attempt has no execution leaf (a supervisor outside a delegated scope); the spec claimed the leaf kill unconditionally; no test pinned the release byte (lifecycle review) | The limit is stated in §9.3 (6 of 20 synchronized kills outside a scope, 0 of 20 inside); a code change for the no-leaf case is an open decision; the release test now runs with the backend alive | §9.3; L02 (`j4_a_released_watcher_leaves_without_killing`) |
