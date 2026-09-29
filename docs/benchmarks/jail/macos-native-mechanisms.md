# Native macOS lifetime investigation

Date: 2026-09-29. This is mechanism research, not a completed macOS backend.

There are stronger native primitives than process groups. The most promising
supported direction is **Seatbelt plus macOS 27's descendant-scoped Endpoint
Security client and audit-token signalling**. It still needs an entitled binary
and a demonstrated solution for the death of the process holding the client.
Do not claim `tree_empty` or weaken the current contract on this evidence.

The [runner](macos_native.py), [C fixture](macos_native.c), and
[raw results](results/macos-native-mechanisms.json) are reproducible on this Mac:

```sh
python3 docs/benchmarks/jail/macos_native.py --samples 10 --out /tmp/native-results.json
```

The output path must be new. The test uses temporary jobs in the logged-in
user's launchd domain, outside `~/Library/LaunchAgents`. It removes each job
and kills only fixture processes using their audit tokens. Each descendant
also has a 20-second emergency lifetime. No root, persistent service, signing
entitlement, security-setting change, or VM is used.

## Findings

| Mechanism | Actual result or API contract | Implication |
|---|---|---|
| Seatbelt syscall filter | Direct `setsid` and `setpgid` return `EPERM`. Both `posix_spawn(SETPGROUP)` and `posix_spawn(SETSID)` still succeed under the same filter. | Blocking those two syscalls does not pin descendants to a group or session. |
| Also deny `posix_spawn` | Ordinary spawn fails. Node 22.22.3 cannot execute `/usr/bin/true` with `child_process.execFileSync`; it reports `EPERM`. | This trades away normal agent subprocess support. It is not a general native backend. |
| Temporary launchd job | On job-root `SIGKILL` and on `launchctl bootout`, `setsid` and double-fork descendants remain active. | Moving group cleanup into launchd does not solve detachment or supervisor death. |
| Kernel coalitions | Each job receives its own coalition. Its detached descendants retain membership after reparenting to PID 1. Reading membership succeeds; direct `coalition_create` returns `EPERM`. | Membership is stronger than process ancestry scans, but the caller cannot manage coalitions directly. |
| Coalition termination | Published XNU implements a request for an empty notification; existing members can still fork. It is not a kill operation. | Do not treat `coalition_terminate` as an equivalent of `cgroup.kill`. |
| kqueue descendant tracking | `EVFILT_PROC` with `NOTE_TRACK` returns `ENOTSUP` (45). | A per-PID watcher cannot inherit recursive tracking through this API. |
| Audit-token signalling | A deliberately wrong PID version returns `ESRCH` without killing the fixture; the correct token kills it during cleanup. | Useful protection against PID reuse. This does not discover or contain descendants. |
| `es_new_descendants_client` | Present in the installed macOS 27 SDK/runtime. The locally built test receives `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` (3). | A real candidate, but live event delivery and lifetime enforcement remain untested. |

Across all 20 launchd trials, both detached descendants and the child that
ignored `SIGTERM` in the original group remained live at the two-second
checkpoint. The ordinary child in the original group exited in every trial.
Both detached children continued writing heartbeats between the one-second
and two-second checkpoints in every trial. All survivors were subsequently
killed by the fixture runner and every temporary launchd job was removed.

The syscall escape is consistent with published XNU: `posix_spawn` performs
group/session changes inside its own syscall, without going through separate
`setpgid`/`setsid` syscall entry points. See
[spawn attribute handling](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L4482).
The live tests, rather than that source inspection alone, establish the bypass
on this newer kernel.

Apple describes coalitions as inherited, immutable membership managed by
launchd. Its source checks privileged coalition membership before management
operations; being an ordinary owner of a job is insufficient. The termination
operation arms notification and permits existing members to fork.
See [coalition design](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/doc/observability/coalitions.md),
[management checks and termination semantics](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_coalition.c#L95),
and [termination implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/coalition.c#L2174).

An external custodian could use coalition membership to recover orphaned
processes. That is worth distinguishing from ordinary parent-PID polling, but
a repeated scan-and-signal loop still needs proofs for concurrent forks,
complete enumeration, safe process identity, and the custodian's own death.
It also depends on private inspection ABI. Those proofs were not established
here; adding such a recovery service is not the small, proven replacement the
spec needs.

The installed `launchd.plist(5)` describes `AbandonProcessGroup=false` in terms
of the original process group. The tests explicitly use that setting and an
`ExitTimeOut` of one second. Each survival check records heartbeat progress
at 0.2, 0.5, 1 and 2 seconds after the stop request, then checks the same kernel
process identity. These are active descendants, not zombies mistaken for
running processes. The fixture requests 10 ms sleeps, but launchd scheduling
coalesced them to longer intervals; the runner uses measured elapsed time,
not a heartbeat count, to establish the observation window.

For kqueue, the published
[kernel implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_event.c#L1097)
also explicitly rejects `NOTE_TRACK`. Audit-token signalling is declared in
the installed public `libproc.h`; the
[libproc wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c#L487)
returns an errno value directly. The test changes the token's PID version;
it does not force actual PID wraparound on the user's Mac.

## What macOS 27 changes

Apple's [descendant client API](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:))
scopes events to the caller and its existing and future descendants. The
installed SDK explicitly removes root and TCC approval requirements, while
retaining `com.apple.developer.endpoint-security.client`. This corrects the
earlier blanket assumption that all Endpoint Security use requires root and
Full Disk Access. The release and signing process would have to support the
restricted entitlement; a local entitlement plist is not an Apple grant.

Three distinctions matter:

1. Fork has a **notification**, not a public `AUTH_FORK` event in this SDK.
   Tracking events does not itself stop process creation during teardown.
2. `es_sync_client` puts a marker in the delivery queue. It can support a drain
   protocol, but does not freeze the target tree. It also invokes outstanding
   sync blocks when the client is destroyed, so a callback alone cannot prove
   successful final delivery. See
   [queue synchronization](https://developer.apple.com/documentation/endpointsecurity/es_sync_client(_:_:)).
3. `ES_DEADLINE_MISS_MODE_FAIL_CLOSED` denies timed-out authorization operations
   and authorization messages dropped because a queue is full. It is not a
   documented kill-all-on-client-death facility. See
   [deadline handling](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:)).

Do not substitute undocumented exports such as `es_enable_fail_closed` for a
published contract merely because their symbols exist in the SDK stub.

On a normally protected Mac, testing the prototype requires an
Apple-entitled executable. For development before approval,
[Apple documents](https://developer.apple.com/system-extensions/) temporarily
disabling SIP. The [development VM procedure](macos-development.md) keeps this
exception inside a disposable macOS 27 guest; it does not establish readiness
for normally protected Macs. The prototype should
create the descendant client and subscribe **before** starting the workload;
use audit-token identities for signals; enforce Seatbelt independently of
event delivery; and track gaps, forks, execs and exits through a bounded drain.
It must prove all of the following before becoming the J11 backend:

- `setsid`, double fork, spawn attributes and a bounded concurrent fork storm
  cannot evade termination or create a falsely empty receipt.
- Killing the workload supervisor and, separately, the ES custodian cannot
  leave workload descendants running. An ordinary watchdog whose own death
  removes enforcement is insufficient.
- Queue loss, client disconnect, startup failure, stale identities and a
  failed drain produce refusal/unknown and retain private state, never a false
  clean receipt. Prove actual PID reuse separately from the token mismatch test.
- Normal Node, shell, Git and OpenCode subprocesses work without a fork/exec
  shim. Measure launch and termination overhead only after correctness passes.

The current Mac backend continues to refuse contained execution. The
development experiment below tests the native ES API inside a VM; it does
not introduce a VM execution backend.

## Prepared ES prototype

The [ES custodian](macos_es.c) and [builder/test runner](macos_es.py) now compile
against the installed SDK. The runner creates an app bundle for an embedded
provisioning profile, using Apple's documented app-wrapped helper layout.
There is no additional production backend or runtime switch.

The live signing check found a valid Developer ID Application identity for
Monocursive (`64SGQ348QJ`) and no ES entitlement in any of 14 local profiles.
The operator confirmed that Apple approval has not been obtained. Both the
ad-hoc app and the Developer ID-signed app pass signature verification and
return capability error 3. Requesting a real `touch` command returns 125
without creating its marker or opening the workload log. A real provisioning
profile lacking ES authorization is rejected before building/signing an app.
See [saved signing/refusal evidence](results/macos-es-entitlement.json).
Separately, the prototype's Seatbelt signal rule compiles and permits signalling
a child in the same sandbox while denying `SIGTERM` to an owned fixture outside
it. Those real signal tests used no ES client and are not ES lifecycle evidence.

The prepared entitled branch subscribes before spawning, releases the root
from `POSIX_SPAWN_START_SUSPENDED` after observing its audit token, captures
fork/exec/exit notifications and sequence gaps, and attempts bounded cleanup
using audit-token signals. The runner has separate wall-expiry, cancellation,
workload-supervisor-death and ES-custodian-death cases. It checks known fixture
processes independently before doing emergency cleanup. A custodian-death
survivor fails the gate; runner cleanup cannot turn that into a pass.

The [SIP-disabled development experiment](macos-development.md) now records
real ES event handling without Apple approval. Its corrected 40-case run
observed every known fixture token and exit in all 30 surviving-custodian
cases, with independently empty fixture trees. All ten custodian-death cases
left all five fixture processes alive. A signal-zero liveness-probe bug was
also found and fixed; the initial refusals and diagnostic runs are retained.
The prototype always reports `lifetime_contract_verified: false`.
Concurrent fork-storm, real PID reuse, event-loss injection, the complete
final-drain protocol, general agent compatibility and a separate
custodian-death enforcement mechanism remain further proof work; this
collector alone does not supply that mechanism.

The operator submitted the [entitlement request](endpoint-security-request.md)
on 2026-09-29; Apple's confirmation gives request ID `S9YJTLLH28`. Approval is
pending. The record includes the proposed App ID, intended scope, and the exact
command to embed an approved profile and run the real tests. Signing the app
does not substitute for Apple's entitlement grant. No host root, TCC, SIP,
system-extension installation, or production release setting was changed.
The disposable guest already had SIP disabled; its Ethernet service was
disabled before the fixtures ran.

## Evidence limits and timings

Host: Apple silicon, macOS 27.0 build `26A428`, Darwin `27.0.0` / XNU
`13432.1.9`, Xcode 27.0 build `27A266a`. The raw result records compiler,
source/binary hashes, SDK/header hashes, process identities, exact policies,
capability returns, heartbeat progress, all samples and cleanup checks.

There are ten samples for each launchd action, with no discarded warmups.
Readiness includes launchctl bootstrap, sandbox-exec and fixture initialization.
Root-death timing includes signalling/removal plus the external identity query.
Neither measures successful tree teardown: detached members survive. The
profiles deliberately allow default operations to isolate lifecycle behavior;
they do not validate filesystem, network or Mach isolation.

| Case, ten samples each | Readiness median / p95 | Root death median / p95 |
|---|---:|---:|
| Job-root `SIGKILL` | 42.94 / 54.38 ms | 4.94 / 5.65 ms |
| `launchctl bootout` | 42.66 / 52.31 ms | 10.13 / 13.23 ms |

These are instrumented prototype timings, not a benchmark of a working jail
backend. Final survival observations occurred 2000.52–2005.37 ms after the stop
request. The timed calls do not include the runner's later survivor cleanup.

The public XNU source inspected is `xnu-12377.1.9`, commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`, older than this Mac's kernel.
Source conclusions are separated from current SDK contracts and live probes.
The ES entitlement denial prevents any claim of live ES event coverage,
custodian-death cleanup, or ES performance. No Linux behavior changed in this
investigation, so the earlier SSH evidence remains separate.
