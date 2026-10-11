# Native macOS inherited Mach lifetime investigation — 2026-10-10

**The native cleanup blocker remains open.** A Mach exception handler installed
before launch really is inherited across the tested fork/spawn/exec paths.
However, its owner's death does not stop normal execution, and a workload can
remove the inherited handler. An additional kernel fatal-port interface was
absent on the tested release kernel. Neither supplies the required boundary.

This continues the [kernel lifetime investigation](macos-kernel-lifetime-2026-10-10.md).
Native `ouro-jail run` stays disabled; the public Linux release is unchanged.

## Kernel source and API investigation

The complete published Apple XNU tree at commit
`f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` was searched. Its
[archive URL and SHA256](results/macos-mach-lifetime-2026-10-10/apple-archive.json)
are retained. This 12377 snapshot predates the guest's 13432 kernel; conclusions
about the guest below rely on actual tests.

Apple's [fatal-port implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L8642)
allocates a current-task identity token and kills that task on its no-senders
callback. The [sysctl interface](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_generic.c#L3238)
and Apple's [self-release test](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/tests/task_fatal_port.c)
identify `machdep.task_get_fatal_port`. A **size-only query**, without requesting
a port, returned `ENOENT` (2) here. Its kill behavior was therefore not tested
live or treated as an available application API. The visible implementation
also binds one current task rather than an inherited workload scope.

Apple's [IPC task initialization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/ipc_tt.c#L258)
copies exception handlers from the parent. The installed SDK exposes the task
exception APIs, `mach_port_construct`, `MPO_EXCEPTION_PORT` and
`EXCEPTION_IDENTITY_PROTECTED`. The older published
[Mach manual](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/man/task_set_exception_ports.html)
discusses syscall exceptions, but the published
[ARM64 Mach dispatch](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/bsd_arm64.c#L212)
dispatches normal traps directly. This warranted a live control instead of
assuming those exception masks intercept every normal syscall.

## Prototype and live results

The [helper](macos_mach_lifetime.c) creates an exception receive port and installs
it on the custodian **before forking the workload root**. It requests
`EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL | EXC_MASK_BREAKPOINT` (448), with
identity-protected 64-bit delivery. The root and children inspect inherited
kernel handler state. No later per-PID attachment is needed. Only the custodian
holds the receive right; it performs no workload cleanup.

The [runner](macos_mach_lifetime.py) records live handler state, kills that owner
using an audit token, asks survivors to inspect handler state again, and
independently snapshots fixture birth identities. Heartbeats exercise file
writes, waits and Mach thread-port operations. Emergency cleanup follows the
survival checks and never counts as lifetime success. Each fixture and the
custodian have a 20-second emergency alarm.

Three repetitions of eight cases produced **24 complete trials**:

| Case | Observed kernel state and execution | Repetitions |
| --- | --- | --- |
| Workload root only, owner killed | Live inherited mask 448 became dead mask 448; root continued work | 3/3 |
| Ordinary fork, owner killed | Root and child inherited live handlers; both continued work with dead handlers | 3/3 |
| Child `setsid`, owner killed | Root and detached child continued work with dead inherited handlers | 3/3 |
| Double fork, owner killed | Root and daemon continued work with dead inherited handlers | 3/3 |
| `posix_spawn(SETPGROUP)`, owner killed | Root and exec'd child continued work with dead inherited handlers | 3/3 |
| `posix_spawn(SETSID)`, owner killed | Root and exec'd child continued work with dead inherited handlers | 3/3 |
| Child clears handler, owner killed | Child first had mask 448, then successfully cleared it and continued with no handler | 3/3 |
| Breakpoint control, owner alive | Root deliberately trapped; owner received a kernel exception, then root died after the prototype dropped the request | 3/3 |

All **39 known workload processes** in the 21 owner-death trials stayed alive
and advanced heartbeats after the owner died. No normal syscall exception was
delivered during these trials. Handler inheritance is real; it is not persistent
execution authorization and does not trigger process death.

The three breakpoint controls received real kernel exception messages (ID 2408)
while the owner remained alive. Those deaths establish working exception
delivery; **they are not successful owner-death cleanup trials**. The
[validator](macos_mach_lifetime_summary.py) keeps their purpose distinct.

## Scope, diagnostics and cleanup

The isolated Tart guest ran macOS 27.0 build 26A428, SDK 27.0 and XNU 13432.1.9.
The complete series used the **ordinary guest account, UID/EUID 501**. Guest SIP
was already disabled, with no Apple-approved profile. Ethernet was disabled
and no default route existed. No host folders, credentials, signing keys,
clipboard or USB devices were shared. See the
[guest check](results/macos-mach-lifetime-2026-10-10/mach-guest-check.json) and
[full environment record](results/macos-mach-lifetime-2026-10-10/results.json).
Normally protected Macs still need separate qualification.

Initial attempts to register a foreign exception port returned
`KERN_INVALID_RIGHT` (17), including root and identity-protected controls.
These refused setups retain exact source snapshots and cleanup evidence in
`diagnostics`; they do not establish owner-death behavior. Installing a locally
created handler on the custodian before fork produced the complete series.
The seven-case smoke and intermediate 21-case series are also retained. The
final series adds verified pre-removal state and a positive delivery control.

The protected-host runner [refused before creating its output directory](results/macos-mach-lifetime-2026-10-10/mach-host-refusal.stderr).
An independent [final audit](results/macos-mach-lifetime-2026-10-10/final-cleanup-audit.json)
found no live processes among **156 recorded fixture/custodian identities**
from all completed and diagnostic runs, and no remaining experiment commands.
The [VM is stopped](results/macos-mach-lifetime-2026-10-10/vm-stopped.txt).
Host SIP remained enabled [before](results/macos-mach-lifetime-2026-10-10/host-sip-before.txt)
and [after](results/macos-mach-lifetime-2026-10-10/host-sip-after.txt).

Inspect the [raw results](results/macos-mach-lifetime-2026-10-10/results.json),
[matching post-run source/binary hashes](results/macos-mach-lifetime-2026-10-10/after-hashes.json)
and [validated summary](results/macos-mach-lifetime-2026-10-10/summary.json).
Both programs compiled with `-Wall -Wextra -Werror`. The
[17 evidence regression tests](test_macos_mach_lifetime_summary.py) reject
missing controls, lost counterexamples, changed provenance/identities and false
readiness claims. They run without macOS libraries or live workloads.

Copy the seven exact `tested-source` files into one directory in the isolated
guest from the [development runbook](macos-development.md), then reproduce with:

```sh
python3 macos_mach_lifetime.py --samples 3 --out /tmp/mach-lifetime-new
```

A completed experiment returns 125, keeping `lifetime_contract_verified` and
`native_execution_ready` false. These trials do not qualify complete-tree
enumeration, filesystem/network/Mach-service containment, real agents or normal
SIP production behavior.

The missing facility must combine inheritance with immutable scope membership
and kernel enforcement when all userspace owners disappear. No suitable
supported native facility was found here. A precise
[Apple technical question](apple-lifetime-question.md) was
[submitted through code-level support on 2026-10-11](apple-lifetime-support-2026-10-11.md);
Apple's response is pending. A VM execution boundary remains
an architectural alternative needing its own implementation and proof.
