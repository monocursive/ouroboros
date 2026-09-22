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
