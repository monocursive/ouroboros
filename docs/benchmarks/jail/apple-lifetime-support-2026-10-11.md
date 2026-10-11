# Apple code-level support submission — 2026-10-11

**Submitted and confirmed by Apple.** The confirmation page displayed:
“Your request has been sent.” No case number was shown on the page. The
acknowledgement email supplied by the user confirms **Case-ID: 22799543**.
Apple is reviewing whether to manage the request by email or direct it to the
Developer Forums; no technical answer has arrived in this acknowledgement.

- Submitted at: 2026-10-11T07:59:50.854Z (09:59 CEST).
- Channel: [Apple Developer code-level support](https://developer.apple.com/contact/request/code-level-support/).
- Team: Monocursive, `64SGQ348QJ`.
- Code-level support case: `22799543`; include the full line
  `Case-ID: 22799543` in follow-up emails.
- Related ES entitlement request: `S9YJTLLH28`.
- Category: Problems with an Apple framework API in my app.
- Development environment: 27.0 (27A266a), SDK 27.0; 27.0.1 (26A434); packaging build only.
- Runtime: 27.0 (26A428), XNU 13432.1.9; isolated VM.
- App name: Ouroboros / ouro-jail.
- Supporting project: 192 C source lines; Xcode Debug build succeeded with
  `-Wall -Wextra -Werror`. The packaged project was not run in the VM.
- Attachment status: **Sent with the follow-up reply** to `dts-help@apple.com`
  for `Case-ID: 22799543` on 2026-10-11. Fastmail confirmed "Message sent" and
  displayed the reply as Sent with a 9 KB `FocusedLifetime.zip` attachment.

The local receipt, exact form payload, build log, screenshot and prepared ZIP
are under `evidence/apple-code-level-support-2026-10-11/` (ignored local evidence).
`FocusedLifetime.zip` is 8,951 bytes, SHA256
`9015de13d5d49490444f8f7a6ba86587e939aede52adc08f41131a305c43d6a0`.
It contains the focused source project and a clearly labelled selection of
original VM logs. No credentials, signing keys or binary are included.

## Acknowledgement and sent follow-up

The acknowledgement labels the platform as **iOS**, although the runtime field
and question explicitly describe macOS. The reason for that label is unknown.
It also omits the literal directory placeholders from the reproduction text:
`FocusedLifetime --custodian <directory> double-fork` became
`FocusedLifetime --custodian double-fork`, and the two marker paths lost their
directory prefix. The exact sent text below remains unchanged as provenance.

The follow-up text is preserved locally as
`evidence/apple-code-level-support-2026-10-11/follow-up-22799543.txt`, clarifying
macOS and using quoted shell variables rather than angle-bracket placeholders.
It and `FocusedLifetime.zip` were **sent** to `dts-help@apple.com` at
2026-10-11T08:05:57.526Z. The reply preserves the original email thread and the full
`Case-ID: 22799543` line. The verified body matches the prepared follow-up.
The local sent receipt and screenshot are `follow-up-send.json` and
`follow-up-sent.png` in the same evidence directory. Apple's technical response
remains pending.

## Title sent

macOS: supported process-tree lifetime boundary after supervisor loss

## Description sent

We are building Ouroboros, a contained developer workload runner. Before advertising native macOS support, we need a supported lifetime boundary covering normal arbitrary fork/spawn/exec descendants, including detached sessions and double-fork daemons. Execution must remain contained when every userspace custodian dies, rather than relying on a surviving process to enumerate and kill descendants.

Does macOS provide a supported facility that can:

1. Establish an immutable workload scope before its first instruction and atomically inherit membership through fork/spawn/exec, without modifying the workload or preventing ordinary Node, shell and Git subprocess behavior?
2. Stop or terminate every member after loss of the final control owner, with enforcement retained in the kernel and no userspace callback required?
3. Handle concurrent creation during teardown and expose a verifiable final drain, using stable process identities rather than PID-only scans?

Our development evidence on macOS 27.0 build 26A428, XNU 13432.1.9, includes:

- Descendant-scoped Endpoint Security clients observe the tested subtree. Reciprocal custodians handle either client's loss, but killing both leaves all known members running. Uncached fail-closed AUTH_EXEC permits a survivor to execute a new command after both clients disappear (200 reciprocal-custody trials).
- PT_ATTACHEXC gives kernel-enforced debugger-death cleanup for attached targets, but later fork/spawn children survive (80 debugger-lifetime trials).
- A locally installed, identity-protected Mach exception handler is inherited through the tested fork/spawn/exec paths. Owner death changes it to a dead handler without stopping normal execution; a child can clear it. Breakpoint controls confirm real kernel exception delivery (24 Mach-lifetime trials).
- Published XNU contains per-task fatal-port no-senders cleanup, but machdep.task_get_fatal_port is absent on this tested release kernel. We have not treated it as a supported application API.
- LaunchServices creates a real application coalition, and XPC service lifetime follows app death. However, all seven workload descendants survive, retain coalition membership and can execute a new command. Shared and private audit sessions both fail; eight-second follow-ups also retain all seven survivors. A temporary root launchd service restarts and reaps seven recorded processes after a crash, but does not restart a stopped custodian (native-service trials).

These are isolated SIP-disabled tests, not normal-SIP qualification. We understand the Endpoint Security entitlement is separate from a lifetime guarantee. Please clarify whether an approved descendant-scoped ES deployment can provide that owner-loss guarantee through a documented API, whether another supported facility is appropriate, or whether meeting this contract requires a VM boundary.

Related entitlement request: S9YJTLLH28, submitted 2026-09-29 for com.apple.developer.endpoint-security.client, Monocursive team 64SGQ348QJ, proposed identifier com.monocursive.ouroboros.jail. This is a code/API lifetime question, not an entitlement status inquiry.

A focused C command-line Xcode project (192 source lines) packages the existing Mach probe. It builds with Xcode 27.0, SDK 27.0, -Wall -Wextra -Werror, without signing or third-party libraries. The original probe was run in the isolated VM; this newly packaged Xcode project has been build-checked only. We can send its ZIP and the original experiment logs by reply to your acknowledgement email.

## Steps to reproduce sent

Focused Mach API reproduction (source project prepared for attachment by reply):

1. Build FocusedLifetime.xcodeproj, scheme FocusedLifetime, Debug. The sample is a C command-line tool using mach_port_construct, task_set_exception_ports and task_get_exception_ports. No Endpoint Security entitlement is needed for this focused Mach test.
2. Run only in an isolated disposable macOS VM. The helper checks kern.hv_vmm_present and refuses a non-virtualized host. Every fixture process has a 20-second emergency alarm. No security-setting change is part of these instructions.
3. Create a fresh temporary directory. Start FocusedLifetime --custodian <directory> double-fork, recording the direct child owner PID and its stdout. The owner creates its local exception receive port, installs EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL | EXC_MASK_BREAKPOINT with EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES before forking the workload, and has no workload cleanup callback.
4. Wait for workload.jsonl, create <directory>/trigger and allow the detached descendant to start. Inspect workload.jsonl for successful setup and inherited live handler state (mask 448).
5. SIGKILL only the owner launched by the test; wait for that direct child to exit. Create <directory>/after-owner-loss and inspect the workload log again.
6. Original observed result: inherited handler state becomes dead (mask 448), but root and detached daemon stay alive and their heartbeat files continue to grow across repeated reads. The fixture alarms later terminate them; timeout cleanup does not count as lifetime enforcement.
7. Repeat in fresh directories with modes root, fork, setsid, spawn-group, spawn-session and clear-exception. A separate breakpoint-control run with the owner left alive confirms real kernel exception delivery; resulting target death is not owner-loss cleanup.

Expected contract: a documented kernel-owned boundary prevents continued execution by every inherited member after all control owners disappear, without enumerating descendants after the fact or requiring workload cooperation. We are asking which supported macOS API meets that contract, not asserting that exception ports promise it.

Original full research environment: isolated Tart VM, macOS 27.0 (26A428), XNU 13432.1.9, SDK 27.0, ordinary guest UID 501 for Mach tests; guest SIP already disabled; no Apple-approved ES profile; network disabled and no host shares or credentials. The packaged project was built separately on macOS 27.0.1 (26A434), Xcode 27.0 (27A266a), without running host workloads.
