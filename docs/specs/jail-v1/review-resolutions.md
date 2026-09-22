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
