# macOS VM preview package qualification — 11 October 2026

This is a separate offline Linux-on-Mac developer preview, version
`0.1.0-preview.1`. It does not qualify the native macOS Jail backend or change
the published Linux release. The candidate has not been published or pushed.
Implementation: [VM sources and usage](../../../crates/ouro-jail/vm/README.md).

## Teardown change

The [original prototype](macos-linux-vm-2026-10-11.md) left Apple's VM service
allocated when both Python launcher and Swift VZ client were suspended, even
though the independent guest controller emptied the Linux workload cgroup.

A native C custodian now owns the VZ client as an unreaped child. A three-second
lease bounds launcher stalls. Its continuous Mach clock includes sleep, though
whole-host sleep/wake is not qualified by these tests. The client observes
custodian death through an inherited pipe. The launcher requires acknowledgements
from the custodian and can kill the exact VZ client using its kernel audit token;
it does not rediscover or signal a potentially reused PID after reparenting.
The guest still kills and verifies its Linux workload subtree before poweroff.

The test matrix begins with one live command and six detached descendants. It
identifies Apple's exact VM service through that attempt's open disk descriptor.
The verdict requires service disappearance within the original bounded deadline,
before any test cleanup. Cleanup of stopped test controllers is recorded
separately and is not counted as evidence of autonomous VM teardown.

During development, a custodian-only stall revealed that direct launcher/client
communication could keep going without the custodian. The acknowledgement check
fixed that. The first packaged matrix then refused a simultaneous-death injection
because automatic cleanup had already removed its second target. The injector
now stages both targets as stopped before killing them. Failed exploratory
results remain under the ignored local evidence directory; they were not
relabeled as passes.

## Package and installation

The offline DMG contains a frozen Python 3.13.13 launcher, native VZ client and
custodian, a compressed pinned Ubuntu ARM64 guest, licenses, preview notes and
source. Mach-O files use Developer ID Application: Monocursive (64SGQ348QJ) with
hardened runtime. Only the VZ client has the virtualization entitlement; no
Endpoint Security, debugger, JIT, or library-validation exception is requested.
The final artifact and measurements are listed below.

The Bash installer pins the SHA-256 of its manifest, validates every listed
file, expands and checks the raw image, and installs into a private versioned
per-user directory. It needs no sudo, Python, Swift, Rust, Homebrew or Minisign.
A symlink exposes `ouro-vm`. `doctor` checks hashes and virtualization support;
it never substitutes for a real guest execution receipt.

The five real-installer checks cover a prefix containing spaces, duplicate
installation refusal, preservation of an unrelated command, tampered manifest
rejection, and tampered payload rejection. They run with only system commands
on PATH. Twelve unit regressions cover file boundaries, receipts, invalid owner
identities and image expansion cleanup. Bash syntax and ShellCheck also pass.

## Functional scope and limits

Both final `build` and `tool` runs require verified Linux receipts and VM stop
acknowledgements. Build testing checks Unicode and shell-metacharacter argv,
blocked networking, copied output files and untouched original input. Tool
testing checks protected system-path refusal, writes to the disposable workspace,
and propagation of exit code 23. Both profiles intentionally permit writes to
the guest workspace copy; the early preview note describing tool as read-only
was corrected before the final package.

Actual VM execution is measured on Apple Silicon macOS 27.0.1 with host SIP
and Gatekeeper enabled. A fresh, separate macOS 27 Tart clone is used for
installation checks. Its inherited SIP-disabled and Gatekeeper-disabled settings
were restored before testing, using Recovery for SIP. Host security settings
and the earlier native-research VM were not changed. No host folder, clipboard,
audio, USB accessory, signing identity or private credential is shared with it.
The clone includes developer utilities, but installation and command checks use
only the system PATH and the package's bundled runtime.

Tart rejects nested virtualization for macOS guests; the test Mac reports
`kern.hv_support=0`. Therefore its installation checks cannot qualify Linux VM
execution inside a Mac VM. Real execution and fault injection use the physical
host; no second physical Mac has been qualified.

This preview is restricted to Apple Silicon and macOS 27+, offline Linux ARM64
commands, small regular-file workspaces, `tool`/`build`, and explicit wall limits.
It does not run Xcode, macOS binaries, native Apple SDKs, online agents or provider
workloads. VM startup is around 22 seconds on the measured host.

If all three host controllers are suspended together, prompt host-resource
teardown remains outside the qualified fault model. The independent guest lease
is intended to terminate its workload, but no universal kernel-enforced lifetime
claim follows from the host fault measurements. Whole-host sleep/wake, kernel
failure, arbitrary guest compromise and native macOS process-tree cleanup remain
unqualified. The Apple support investigation remains separate.

## Final artifact and measured results

Artifact (local, ignored by Git):
`evidence/macos-vm-package-2026-10-11/candidate-02/ouro-vm-0.1.0-preview.1-macos-arm64.dmg`

- Size: 536,341,282 bytes (511.5 MiB).
- Final stapled SHA-256: `f3a85e14987228bb5271956ce19bb4cb57272c24235b6f8b98db51b68e0c54a0`.
- Apple notarization: **Accepted**, submission `e922f3a3-ce4e-41ed-8fee-549183180ce7`.
- Staple, staple validation, and host Gatekeeper DMG assessment: passed.
- Five real installer scenarios and twelve unit regressions: passed.
- Both packaged functional runs: completed, verified Linux cleanup, acknowledged
  VM stop, original inputs unchanged, disposable disks removed.
- Fourteen packaged fault cases: passed; no emergency VM-service kill was needed.

[Package provenance](results/macos-vm-preview-package-2026-10-11/package.json),
[distribution checks](results/macos-vm-preview-package-2026-10-11/distribution-checks.json),
[installer results](results/macos-vm-preview-package-2026-10-11/installer-summary.json),
[functional results](results/macos-vm-preview-package-2026-10-11/functional-summary.json),
[fault provenance](results/macos-vm-preview-package-2026-10-11/packaged-faults-02/provenance.json),
and [complete fault results](results/macos-vm-preview-package-2026-10-11/packaged-faults-02/summary.json)
are retained in the repository. Large images and frozen runtime files remain in
ignored local evidence, not Git.

| Fault | VM service gone after injection | Verdict |
|---|---:|---|
| `wall` | 2.762 s | passed |
| `cancel` | 0.070 s | passed |
| `launcher_kill` | 0.012 s | passed |
| `launcher_stop` | 1.973 s | passed |
| `helper_kill` | 0.018 s | passed |
| `helper_stop` | 1.652 s | passed |
| `both_kill` | 0.024 s | passed |
| `service_kill` | 0.013 s | passed |
| `service_stop` | 4.029 s | passed |
| `both_stop` | 3.010 s | passed |
| `custodian_kill` | 0.012 s | passed |
| `custodian_stop` | 1.415 s | passed |
| `custodian_helper_pair` | 1.524 s | passed |
| `custodian_launcher_pair` | 2.141 s | passed |

`service_stop` includes an intentional four-second suspension followed by
resumption; its result does not claim host resource reclamation while Apple's
VM service itself is stopped. `wall` uses a three-second guest wall budget, with
timing measured after the six detached children report readiness. Each final
case was measured once; these are bounded observations, not statistical
reliability estimates. The original `both_stop` blocker is now **3.010 seconds**
with the original autonomous service-disappearance requirement intact.

The fresh Mac installation initially encountered **App Store only** policy after
the test setup enabled Gatekeeper globally. It rejected the DMG despite correctly
identifying its notarization. Completing setup with **App Store & Known
Developers**, keeping SIP and Gatekeeper enabled, admitted the unchanged DMG.
No artifact-specific override or quarantine removal was used. The inherited
image had originally disabled Gatekeeper entirely; this is a protected test
fixture, not a change to the physical host's security policy.

An additional `spctl --type execute` check on the bare CLI returned
`errSecCSNotAppLike`; this is recorded, not treated as an accepted app-bundle
assessment. Apple documents that result as valid code that is not app-like
([result code](https://developer.apple.com/documentation/security/errseccsnotapplike)).
The actual distribution check is the signed/stapled DMG assessment, plus strict
signature verification with the explicit `notarized` requirement for the CLI,
Python runtime and native helpers, and real execution of the installed CLI.
The CLI's `doctor` checks every installed hash and reports virtualization false
inside this Mac VM. A real run refuses with VZErrorDomain code 2 and exit 125,
rather than falling back to host execution.

The final protected-VM installation sequence completed with exit 0:
[stdout](results/macos-vm-preview-package-2026-10-11/test-mac-qualified.stdout),
[signature and notarization checks](results/macos-vm-preview-package-2026-10-11/test-mac-qualified.stderr).
The [qualification summary](results/macos-vm-preview-package-2026-10-11/qualification.json)
keeps unsupported nested execution, native Mac containment, and publication
separate from the passed preview checks.
