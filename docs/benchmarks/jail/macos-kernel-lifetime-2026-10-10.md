# Native macOS kernel lifetime investigation — 2026-10-10

**The macOS cleanup blocker remains unresolved.** A kernel mechanism kills
already attached debugger targets when the debugger dies, but its protection
does not cover children created afterward. The isolated VM reproduced that
escape in every fork/spawn case. Native `ouro-jail run` remains disabled.

The [inherited Mach follow-up](macos-mach-lifetime-2026-10-10.md) finds real
handler inheritance, but handler-owner death still permits execution and the
workload can clear its handler. The kernel fatal-port interface was absent on
the tested release kernel. Neither closes the native lifetime gate.

The [native service follow-up](macos-native-services-2026-10-10.md) tests actual
LaunchServices/XPC application coalitions and a root launchd recovery prototype.
It finds service-death survivors and a stopped-custodian recovery failure.

The earlier [reciprocal ES experiment](macos-reciprocal-custody.md) handles one
custodian's death or pause, but both custodians dying leaves workloads running.
This follow-up investigated whether a kernel lifetime boundary could close that
remaining failure while [Apple entitlement request S9YJTLLH28](endpoint-security-request.md)
is pending. Approval alone would not remove the demonstrated lifetime failure.

## Mechanisms examined

| Mechanism | Finding | Lifetime implication |
| --- | --- | --- |
| Inherited kernel coalitions | Membership survives detachment, but management is restricted and termination requests an empty notification. | No documented per-job kill-on-owner-loss operation was identified. |
| `proc_setpcontrol(PROC_SETPC_TERMINATE)` | The installed SDK describes the caller's resource-starvation control. | This is not a parent/client-death trigger. |
| `proc_terminate_all_rsr` | Published XNU iterates sudden-termination eligible processes globally. | It supplies neither a private workload scope nor inherited owner lifetime. It was not invoked. |
| ES fail-closed deadline mode | Apple documents authorization timeout and queue-overflow handling. The existing live test permits execution after both clients disappear. | It does not establish a persistent lifetime boundary. |
| `ptrace(PT_ATTACHEXC)` | Published XNU kills traced targets on debugger exit. The live root control confirms it for attached fixture members. | Useful per-process behavior; late fork/spawn children survive. |

Primary sources: Apple's [coalition design](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/doc/observability/coalitions.md),
[coalition management checks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_coalition.c#L95),
[termination implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/coalition.c#L2174),
[sudden-termination implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L3724),
[debugger-exit SIGKILL](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2411),
[fork initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_fork.c#L1028),
and Apple's [ES deadline-mode contract](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode(_:_:)).
The installed SDK's `usr/include/libproc.h` and `sys/ptrace.h` were also inspected.
The exported private ES symbol `es_enable_fail_closed` has no public SDK
declaration here; no private calling convention was guessed or invoked.

The inspected Apple XNU snapshot is commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` (12377), older than the guest's
13432 kernel. These sources motivated the experiment; **live observations
establish behavior on the tested guest**. URLs and content hashes are retained
in [the source manifest](results/macos-ptrace-lifetime-2026-10-10/apple-sources.json).
Absence of a suitable documented operation in this investigation is not proof
that every possible Apple mechanism is impossible.

## Prototype and results

[The C helper](macos_ptrace_lifetime.c) attaches with `PT_ATTACHEXC`, waits for
each stop, resumes the target and records readiness. It performs no userspace
cleanup and has no exit or SIGTERM cleanup handler. An independent
[Python runner](macos_ptrace_lifetime.py) kills or pauses the debugger through
an audit token, then snapshots each workload birth identity before emergency
cleanup. Each fixture has a separate 20-second emergency timeout; observations
occurred about 533–725 ms after fault injection.

Ten repetitions of eight cases produced **80 complete trials**:

| Fault / workload | Known fixture empty before runner cleanup | Observed behavior |
| --- | --- | --- |
| Debugger SIGKILL after attaching all five fixture members | 10/10 | Root, ordinary child, SIGTERM-resistant child, `setsid` child and double-fork daemon all died. |
| Debugger SIGSTOP with the same five attached members | 0/10 | Debugger was stopped; all five members remained alive and all four child heartbeats advanced. |
| Root attached, then ordinary `fork`, then debugger SIGKILL | 0/10 | Root died; late child survived and continued writing. |
| Root attached, then child `setsid`, then debugger SIGKILL | 0/10 | Root died; detached late child survived and continued writing. |
| Root attached, then double fork, then debugger SIGKILL | 0/10 | Root died; daemon survived and continued writing. |
| Root attached, then `posix_spawn(SETPGROUP)`, then debugger SIGKILL | 0/10 | Root died; child in a new group survived and continued writing. |
| Root attached, then `posix_spawn(SETSID)`, then debugger SIGKILL | 0/10 | Root died; child in a new session survived and continued writing. |
| Root attached, then child `PT_DENY_ATTACH`, then debugger SIGKILL | 0/10 | Child's deny-attach call succeeded; root died and child continued writing. |

This demonstrates 50 attached-member deaths and **60 surviving late children**
in the six creation cases. It does not prove death of an arbitrary tree.
The ordinary guest account (UID 501) was denied attachment with `EPERM`, so the
complete series ran as a **root control**, not an ordinary-user qualification.
That [negative control](results/macos-ptrace-lifetime-2026-10-10/ordinary-user/results.json)
and its [cleanup record](results/macos-ptrace-lifetime-2026-10-10/ordinary-user/01-registered_death/result.json)
are retained. The [initial refusal diagnostic](results/macos-ptrace-lifetime-2026-10-10/initial-user-diagnostic/results.json)
also remains separate from the successful root control series.

Attaching each child after an ES fork notification would leave a window in
which it already exists without this kernel protection. If all observers die
in that window, no surviving helper can attach it. The controlled late-child
tests expose this missing inheritance without relying on an event-loss race.
The deny-attach case also demonstrates a child that is not automatically traced
and opts out before any later attach attempt. Blocking ordinary fork/spawn
would require a different compatibility contract and was not selected as a fix.

The helper checks the target PID version before attachment. **`ptrace` itself
takes a PID, so that precheck is not an atomic PID-version-fenced attach.**
Emergency signals use audit tokens; liveness checks compare the recorded
unique process identity. The inspection ABI is research-only. Detach handling,
concurrent-fork teardown, actual PID reuse, sleep/wake, signing/debugger
authorization and compatibility with real agents remain unqualified.

## Environment and evidence

The retained `ouro-jail-es-dev` Tart VM ran macOS 27.0 build 26A428, SDK 27.0,
XNU 13432.1.9, four virtual CPUs and 8 GiB RAM. Guest SIP was already disabled;
authenticated root remained enabled. Guest Ethernet was disabled and there was
no default route. No host folders, clipboard, USB devices, credentials or
signing keys were shared. See [guest isolation](results/macos-ptrace-lifetime-2026-10-10/guest-isolation.txt)
and [recorded settings](results/macos-ptrace-lifetime-2026-10-10/results.json).
Normal SIP and an approved signing/authorization configuration still require
separate qualification.

The protected-host runner [refused before creating its requested output directory](results/macos-ptrace-lifetime-2026-10-10/host-refusal.stderr).
Host SIP remained enabled [before](results/macos-ptrace-lifetime-2026-10-10/host-sip-before.txt)
and [after](results/macos-ptrace-lifetime-2026-10-10/host-sip-after.txt).
The final [independent cleanup audit](results/macos-ptrace-lifetime-2026-10-10/final-cleanup-audit.json)
found zero live processes among 340 recorded fixture/debugger birth identities
from the formal series, exploratory root control and refusal diagnostics, and
no remaining commands from the experiment directories. Cleanup follows the
counterexample snapshots and never counts as kernel lifetime success.
The [VM was stopped](results/macos-ptrace-lifetime-2026-10-10/vm-stopped.txt).

The [raw results](results/macos-ptrace-lifetime-2026-10-10/results.json) retain
registration identities, debugger/workload events, heartbeat sizes, independent
before-cleanup snapshots and verified emergency cleanup for every trial.
Both C programs compiled with `-Wall -Wextra -Werror`. Exact tested sources and
[matching post-run source/binary hashes](results/macos-ptrace-lifetime-2026-10-10/after-hashes.json)
are retained. The [summary validator](macos_ptrace_lifetime_summary.py) checks
provenance, the complete case matrix, registration, kernel identities, liveness,
continued work and the preserved counterexamples.
Its [18 regression tests](test_macos_ptrace_lifetime_summary.py) run without
macOS libraries or live workloads. The [validated summary](results/macos-ptrace-lifetime-2026-10-10/summary.json)
keeps both `native_execution_ready` and `lifetime_contract_verified` false.

## Reproduce and next decision

In the isolated guest described by the [development runbook](macos-development.md),
copy the five files from `tested-source` into one directory, then use a new
output directory:

```sh
sudo -n python3 macos_ptrace_lifetime.py --samples 10 --out /tmp/ptrace-lifetime-new
```

The completed mechanism experiment returns **125** because the native lifetime
contract has not passed. An attachment refusal is retained as a failed
experiment; it must not be counted as a completed series. Summarize transferred
evidence without starting workloads:

```sh
python3 docs/benchmarks/jail/macos_ptrace_lifetime_summary.py \
  docs/benchmarks/jail/results/macos-ptrace-lifetime-2026-10-10/results.json \
  --after-hashes docs/benchmarks/jail/results/macos-ptrace-lifetime-2026-10-10/after-hashes.json \
  --out /tmp/ptrace-lifetime-summary.json
```

The next useful Apple technical question is whether a supported native facility
can establish a workload scope **before its first instruction**, inherit it
atomically across fork/spawn/exec, prevent workload removal from that scope,
and terminate or stop execution throughout that scope when every userspace
custodian disappears. Scope destruction must also handle concurrent creation
and provide a verifiable final drain. No follow-up was sent to Apple here.

If Apple cannot provide that contract, a VM lifetime boundary is an architectural
alternative requiring its own implementation and acceptance evidence. These
tests use a VM for isolation; they do not implement a VM execution backend.
The native Rust refusal backend and the public Linux release are unchanged.
