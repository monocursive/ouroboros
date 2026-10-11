# Apple technical question: inherited workload lifetime

**Submitted through Apple code-level support on 2026-10-11.** This is the original
draft; the [submission record](apple-lifetime-support-2026-10-11.md) preserves the
exact form text and confirmation. Apple's acknowledgement confirms
**Case-ID: 22799543**; the technical response is pending.
Related entitlement request: **S9YJTLLH28**, submitted
2026-09-29 for `com.apple.developer.endpoint-security.client`, Monocursive team
`64SGQ348QJ`, proposed identifier `com.monocursive.ouroboros.jail`.
See the [saved request](endpoint-security-request.md).

We are building a contained developer workload runner. Before advertising native
macOS support, we need a supported lifetime boundary covering normal arbitrary
fork/spawn/exec descendants, including detached sessions and double-fork daemons.
Execution must remain contained when every userspace custodian dies, rather
than relying on a surviving process to enumerate and kill descendants.

Does macOS provide a supported facility that can:

1. Establish an immutable workload scope before its first instruction and
   atomically inherit membership through fork/spawn/exec, without modifying the
   workload or preventing ordinary Node, shell and Git subprocess behavior?
2. Stop or terminate every member after loss of the final control owner, with
   enforcement retained in the kernel and no userspace callback required?
3. Handle concurrent creation during teardown and expose a verifiable final
   drain, using stable process identities rather than PID-only scans?

Our development evidence on macOS 27.0 build 26A428, XNU 13432.1.9, includes:

- Descendant-scoped ES clients observe the tested subtree. Reciprocal custodians
  handle either client's loss, but killing both leaves all known members
  running. Uncached fail-closed AUTH_EXEC permits a survivor to execute a new
  command after both clients disappear. See
  [200 reciprocal-custody trials](macos-reciprocal-custody.md).
- `PT_ATTACHEXC` gives kernel-enforced debugger-death cleanup for attached
  targets, but later fork/spawn children survive. See
  [80 debugger-lifetime trials](macos-kernel-lifetime-2026-10-10.md).
- A locally installed, identity-protected Mach exception handler is inherited
  through the tested fork/spawn/exec paths. Owner death changes it to a dead
  handler without stopping normal execution; a child can clear it. Breakpoint
  controls confirm real kernel exception delivery. See
  [24 Mach-lifetime trials](macos-mach-lifetime-2026-10-10.md).
- Published XNU contains per-task fatal-port no-senders cleanup, but
  `machdep.task_get_fatal_port` is absent on this tested release kernel. We have
  not treated it as a supported application API.
- LaunchServices creates a real application coalition, and XPC service lifetime
  follows app death. However, all seven workload descendants survive, retain
  coalition membership and can execute a new command. Shared and private audit
  sessions both fail; eight-second follow-ups also retain all seven survivors.
  A temporary root launchd service restarts and reaps seven recorded processes
  after a crash, but does not restart a stopped custodian. See
  [native-service trials](macos-native-services-2026-10-10.md).

These are isolated SIP-disabled tests, not normal-SIP qualification. We
understand the ES entitlement is separate from a lifetime guarantee. Please
clarify whether an approved descendant-scoped ES deployment can provide that
owner-loss guarantee through a documented API, whether another supported
facility is appropriate, or whether meeting this contract requires a VM boundary.
