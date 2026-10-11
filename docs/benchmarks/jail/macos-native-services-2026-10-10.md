# Native macOS service lifetime investigation — 2026-10-10

**The cleanup blocker remains open.** LaunchServices and embedded XPC services
provide a real application coalition and service lifetime. They do not terminate
the tested workload descendants when the application and service disappear.
A temporary root launchd service can restart and recover seven recorded
processes after a crash, but a stopped custodian is not restarted. That recovery
prototype does not establish a kernel-enforced workload boundary.

This extends the [ptrace investigation](macos-kernel-lifetime-2026-10-10.md) and
[inherited Mach investigation](macos-mach-lifetime-2026-10-10.md).
The production macOS execution refusal remains in place.

## Embedded XPC and LaunchServices

Apple's [XPC documentation](https://developer.apple.com/documentation/xpc)
describes a per-client service lifetime tied to its application. The
[XPC service guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
describes `ServiceType=Application` and `JoinExistingSession`: a service normally
receives a separate audit session, or can join its caller's session.

The [C helper](macos_xpc_lifetime.c) and [runner](macos_xpc_lifetime.py) create
a fresh app bundle with an embedded service, ad-hoc sign both bundles, verify
their signatures, and launch through LaunchServices. The service launches the
ordinary-user fixture through Seatbelt. Neither the app nor service implements
workload cleanup. Connection error handlers only log errors.

Each fixture contains seven known processes: the root, a plain child, a
`SIGTERM`-ignoring child, a `setsid` child, a double-fork daemon, and children
created with `posix_spawn(SETPGROUP)` and `posix_spawn(SETSID)`. Audit tokens,
coalitions and session identifiers are recorded before fault injection.

| Fault | Private audit session: 3 trials | Shared audit session: 3 trials |
|---|---|---|
| App killed | App and XPC service dead; all 7 workload members survive | Same |
| Service killed | App remains alive; all 7 workload members survive | Same |
| App and service killed | Both dead; all 7 workload members survive | Same |
| App stopped | App remains stopped; all 7 workload members survive | Same |
| Service stopped | Service remains stopped; all 7 workload members survive | Same |

These [30 formal trials](results/macos-xpc-lifetime-2026-10-10/private-session/summary.json)
include [both audit-session settings](results/macos-xpc-lifetime-2026-10-10/shared-session/summary.json).
Every trial has a separate LaunchServices application coalition. All descendants
retain the app's coalition and the service's selected audit session despite
detachment. The documented app-to-service lifetime works when the app is killed;
it does not extend to the workload tree.

Six descendant heartbeats advance after every fault. A surviving child then
executes `/usr/bin/touch`; successful spawn, reaping, exit status zero and the
new marker are recorded in **all 30 trials**. Two additional
[long-observation trials](results/macos-xpc-lifetime-2026-10-10/long-observation/summary.json)
kill the app, or both app and service. All seven descendants still survive and
execute the new command at the **8.4-second** checkpoint, before their own
20-second emergency alarms.

An [initial direct-launch smoke](results/macos-xpc-lifetime-2026-10-10/direct-initial/results.json)
also left all seven workload members alive. The first LaunchServices attempt
[failed readiness](results/macos-xpc-lifetime-2026-10-10/launchservices-initial-diagnostic/results.json)
because its host did not inherit the launcher's stdout. That failed attempt is
retained separately and contributes no formal trials. Recording the host's
identity in its own file fixed the oracle; the
[corrected smoke](results/macos-xpc-lifetime-2026-10-10/launchservices-corrected-smoke/results.json)
then reproduced the survivor results before the formal runs.

## Root launchd recovery prototype

Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
documents restart via `KeepAlive`. The installed `launchd.plist(5)` specifies
that process-group cleanup covers the job's original group. It also specifies
that `StartInterval` skips a firing if the job is already running; adding a
periodic start does not provide a watchdog for an existing stopped process.

The [recovery runner](macos_launchd_recovery.py) bootstraps a temporary system
job from a root-owned plist outside `LaunchDaemons`, with
`KeepAlive={SuccessfulExit:false}`, `ThrottleInterval=1`,
`AbandonProcessGroup=false` and `SessionCreate=true`. A root custodian launches
the same fixture after dropping its groups and credentials to guest UID 501.
Its journal and source copy remain protected from that workload's writes.
This is Unix ownership separation for a fixed fixture. The permissive research
Seatbelt profile does not qualify filesystem policy or resistance to privilege
escalation on the development guest.

The first custodian writes a closed-set journal of the seven fixture identities.
On restart, the replacement signals those identities through audit tokens and
verifies their death. It does not launch another workload. A successful recovery
exits normally, ending the restart condition.

| Fault | Formal result |
|---|---|
| Root custodian killed | Replacement custodian appears; all 7 recorded workload processes are dead at the roughly 3.1-second checkpoint, in 3/3 trials. |
| Root custodian stopped | No replacement appears; all 7 workload processes remain alive and execute a new command, in 3/3 trials. |

The [six formal trials](results/macos-launchd-recovery-2026-10-10/formal/summary.json)
and [initial smoke](results/macos-launchd-recovery-2026-10-10/initial-smoke/results.json)
are retained. This demonstrates useful **automatic crash recovery of known
members**, not complete-tree lifetime. Unregistered later children, journal
loss and concurrent fork during teardown are not covered by this prototype.
The stopped-custodian result is already sufficient to reject it as the boundary.

A dedicated UID could help locate processes, but does not itself supply owner
lifetime or an atomic drain. In the pinned published XNU source,
[`kill(-1)`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sig.c#L1675)
uses [`proc_iterate`](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L4024):
it collects a PID list, skips processes being forked, and releases the process
list lock before callbacks. This is source inspection of XNU 12377, older than
the tested 13432 kernel, and does not prove a supported atomic UID boundary.
No global broadcast signal, new account, or UID reuse was attempted.

## Isolation and evidence checks

The retained Tart guest ran macOS 27.0 build 26A428, XNU 13432.1.9, SDK 27.0,
with Ethernet disabled, no default route, no host shares, clipboard, audio, USB,
credentials or signing keys. The guest's pre-existing SIP-disabled setting was
required by the runners. These are development mechanism tests, not normal-SIP
or approved-signature qualification.

The protected-host runners refused before creating their output directories:
[XPC refusal](results/macos-xpc-lifetime-2026-10-10/host-refusal.stderr) and
[root-service refusal](results/macos-launchd-recovery-2026-10-10/host-refusal.stderr).
Host SIP remained enabled [before](results/macos-xpc-lifetime-2026-10-10/host-sip-before.txt)
and [after](results/macos-xpc-lifetime-2026-10-10/host-sip-after.txt).
The [independent final audit](results/macos-xpc-lifetime-2026-10-10/final-cleanup-audit.json)
found all **454 recorded identities gone**, all **8 temporary system jobs
removed**, and no matching research workload command lines left. The unrecorded
host in the failed LaunchServices diagnostic is covered only by that command-line
absence check, not a fabricated audit-token identity. The
[VM is stopped](results/macos-xpc-lifetime-2026-10-10/vm-stopped.txt).

Before-cleanup snapshots are distinct from the runner's emergency cleanup.
No compiled binaries are included in public evidence. Exact tested source
copies, source/binary hashes before and after, plist settings, service logs,
post-fault execution controls and signature verification are retained. The
[portable validator](macos_native_service_summary.py) checks the formal matrices
and refuses native readiness claims. Its
[26 regression tests](test_macos_native_service_summary.py) include source and
binary mismatches, identity tampering, missing trials, missing owner-death
controls, and substitution of emergency cleanup for the measured result.

The [Apple technical question](apple-lifetime-question.md) was
[submitted through code-level support on 2026-10-11](apple-lifetime-support-2026-10-11.md);
Apple's response is pending. A supported inherited scope with owner-loss enforcement and a verifiable
drain is still required; these results do not establish that no Apple facility
can provide it.
