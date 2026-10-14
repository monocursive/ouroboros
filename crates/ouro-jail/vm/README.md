# macOS Linux VM preview

The [0.1.0-preview.1 release](https://github.com/monocursive/ouroboros/releases/tag/ouro-vm-v0.1.0-preview.1) runs
the published Linux ARM64 Jail in a disposable VM on an Apple Silicon Mac.
It does not execute macOS programs or change the native macOS backend's refusal.
The [11 October measurements](../../../docs/benchmarks/jail/macos-linux-vm-2026-10-11.md)
record the earlier prototype and its simultaneous-suspension failure. The current
custodian fixes that case; new package measurements are recorded separately.

Install with the [public Bash installer](https://ouroboros.monocursive.com/install.sh)
and follow the [Mac quickstart](../../../docs/guide.md#macos-vm-preview).
The released DMG is the exact signed, notarized, stapled package from the
[qualification record](../../../docs/benchmarks/jail/macos-vm-preview-package-2026-10-11.md).
Its embedded source and readme retain the pre-publication candidate wording;
current availability is recorded in the public release notes.

The first scope is offline `tool` and `build` commands. Each attempt gets two
virtual CPUs, 2 GiB VM memory, a private 6 GiB sparse disk, and the Linux jail's
required 512 MiB memory, zero swap, 64-process and explicit wall-time limits.
There is no VM network adapter during an attempt, host directory sharing,
credential forwarding, interactive stdin or agent/provider integration.
The `build` profile explicitly grants the disposable workspace copy read/write;
this grant is recorded in the Linux policy and receipt.

`prepare.py` downloads a dated Ubuntu 26.04 ARM64 image and the current public
Linux archive named in `dist/release.json` (`0.1.0-rc.2`; the published
`0.1.0-preview.1` DMG carries `0.1.0-rc.1`), checks embedded SHA-256 pins, and
prepares the guest.
Only that setup VM has NAT networking, for Ubuntu package installation. Package
versions are recorded inside the guest; apt repositories are not snapshot-pinned,
so this is not a reproducible release-image builder. It requires Python 3.11+,
Xcode command-line tools and `qemu-img` (only for image conversion). No host sudo,
SIP change, Endpoint Security permission or production signing key is used.
The helper is locally ad-hoc signed with Apple's ordinary virtualization
entitlement. The measured host is macOS 27.0.1; other versions are unqualified.

From the repository root:

```sh
python3 crates/ouro-jail/vm/prepare.py --out evidence/my-vm-image
mkdir -p /tmp/ouro-vm-workspace
printf 'hello\n' > /tmp/ouro-vm-workspace/input.txt
python3 crates/ouro-jail/vm/run.py \
  --image evidence/my-vm-image \
  --workspace /tmp/ouro-vm-workspace \
  --out evidence/my-vm-attempt \
  --profile tool --wall 30 -- \
  /bin/sh -c 'cat input.txt; printf "created in Linux\n" > output.txt'
```

Use new output directories for image preparation and every attempt. The image
directory is private trusted state: the launcher verifies its saved disk and
helper hashes before boot, and clones rather than boots the base disk.

The command is transported as a byte argv, never interpolated into a shell.
The example invokes a shell explicitly. Stdout/stderr are relayed; the command's
exit status is returned only after a verified Linux receipt and acknowledged VM
stop. Interruptions or incomplete evidence return 125. An interrupted run does
not invent a successful guest receipt.

Input transfer currently accepts regular files only: at most 5,000 files,
512 KiB per file and 32 MiB total. Symlinks, devices and FIFOs are refused.
`.git`, `target`, `node_modules`, `.venv`, `__pycache__` and `.DS_Store` are
excluded at every level. Empty directories are not preserved. The input
workspace is copied, never mounted or modified in place.

Results remain in `<out>/workspace/` for review and manual adoption. The
launcher never extracts guest tar paths or creates guest-provided symlinks.
`<out>/evidence/` holds the unmodified Linux receipt; `attempt.json` separately
records the Mac transport and VM termination. A transport record does not claim
native macOS enforcement. Normal runs discard the disposable disk. Abrupt
launcher death can leave a disk in its evidence directory; that is stored data,
not a resumed VM. Do not boot or reuse such disks.

## Lifetime design and checks

The Python launcher drives a sequenced heartbeat through the Swift VZ helper
and a virtio socket. The root-owned guest controller powers the entire guest
off after two seconds without a valid heartbeat. Before shutdown it writes
Linux `user.slice/cgroup.kill` and checks `cgroup.events` for an empty subtree.
The launcher also requires
timely acknowledgements and stops the VM if guest supervision fails. systemd
watches the guest controller independently. The child runs unprivileged inside
the existing Linux jail and cannot access the host control socket or controller.

The helper watches caller EOF and termination signals, and uses `VZVirtualMachine.stop`
for unconditional teardown. No VM state save, resume or restart path is exposed.
These mechanisms require fault measurements; merely booting a VM does not prove
owner-loss cleanup.

```sh
python3 -m unittest discover -s crates/ouro-jail/vm -p 'test_*.py'
python3 crates/ouro-jail/vm/check.py \
  --image evidence/my-vm-image --out evidence/my-vm-faults --repeat 3
```

The fault runner starts a live workload with six detached descendants. It
identifies the exact Apple VM service by its open attempt-disk descriptor, then
tests wall expiry, cancellation, launcher/helper death and stalls, simultaneous
launcher/helper death, and VM-service death and suspension/resumption. It
records the service's disappearance **before** emergency test cleanup.
That establishes loss of the tested VM's execution service; it is not a proof
against arbitrary kernel failures or every possible guest-resumption race.

The native C custodian owns the VZ client as an unreaped child and kills it
when the launcher's three-second lease expires. A pipe held only by the
custodian lets the VZ client detect custodian death. The launcher requires
custodian acknowledgements within 1.5 seconds and can terminate the exact VZ
client through `proc_signal_with_audittoken`, including after reparenting; PID
reuse cannot target a replacement process. The custodian uses continuous Mach
time, which includes host sleep. There is no automatic restart or VM resumption.

The fault matrix also checks custodian death/stall and suspension of each pair
of the three host controllers. Freezing all three simultaneously can still
retain VM resources until one resumes; the guest's independent lease kills the
workload. These are bounded empirical fault checks, not a universal kernel-owned
lifetime claim. Whole-host sleep/wake, kernel failure, arbitrary guest compromise
and nested execution in a macOS guest are not qualified. Native macOS acceptance
clauses and the public Linux release gates remain unchanged.

## Packaged preview

`ouro-vm` bundles Python; consumers do not need Python, Swift, Rust or Homebrew.
The signed DMG contains an offline installer with a pinned SHA-256 manifest,
the signed VZ client/custodian, compressed pinned guest image, licenses and this
source. The installer uses a per-user version directory and never needs sudo.
Read [PREVIEW.txt](PREVIEW.txt) for installation, command examples and limits.
Apple Silicon / macOS 27+ is the package's minimum; measured execution is on
macOS 27.0.1. Intel Macs and native macOS workloads are not included.

Build from a trusted prepared image whose seed hash and every source hash
recorded by `prepare.py` match the committed `vm/` tree. Uncommitted changes
there stop the build, and only committed files are archived as the preview
source. A Developer ID Application identity must be available in Keychain:

```sh
uv venv --python 3.13 evidence/vm-build-env
uv pip sync --python evidence/vm-build-env/bin/python --require-hashes \
  crates/ouro-jail/vm/requirements-build.txt
evidence/vm-build-env/bin/python crates/ouro-jail/vm/package.py \
  --image evidence/my-vm-image --out evidence/my-vm-package \
  --jail-archive evidence/my-vm-image/cache/jail.tar.gz \
  --identity 'Developer ID Application: YOUR ORGANIZATION (TEAMID)'
```

`package.py` signs all Mach-O runtime files with hardened runtime, and grants
only the VZ client `com.apple.security.virtualization`. Submit the resulting
DMG with `xcrun notarytool submit --keychain-profile <profile> --wait`, retain the
result, then `xcrun stapler staple` and `xcrun stapler validate` the accepted DMG.
Verify `spctl --assess --type open --context context:primary-signature <dmg>`;
compute the final DMG SHA-256 only after stapling. A package build alone does
not establish notarization, installation or execution proof.

Run the fault matrix against the installed frozen executable:

```sh
python3 crates/ouro-jail/vm/check.py \
  --image ~/.local/share/ouro-vm/0.1.0-preview.1/image \
  --executable ~/.local/bin/ouro-vm \
  --out evidence/vm-packaged-faults --repeat 1
```

## Preview transport contract

`ouro.vm.image-build/1` records the immutable prepared raw disk, seed and signed
helpers by SHA-256. A fresh APFS clone is used per attempt. Host-to-helper JSON
lines contain `write` (base64 guest bytes) or `stop`. The helper emits `owner`
with its audit token, boot/connection events, base64 `data`, and stop/error events.
The guest protocol accepts sequential `ping`, regular-file `put`, one `run`, and
`cancel`; it returns `ready`, exact-sequence `pong`, `put`, `running`, stdout/stderr,
regular `file` messages and `done`. No second run or general privileged command
is accepted. Limits and validation are enforced independently at both ends.

`ouro.vm.attempt/1` is a Mac orchestration record. Its guest receipt remains
`ouro.jail.receipt/1` with Linux platform and original enforcement evidence.
`ouro.vm.install-check/1` is only package/host prerequisite validation. These
records must not be substituted for each other or presented as native Mac proof.

Apple references: [Virtualization](https://developer.apple.com/documentation/virtualization),
[virtualization entitlement](https://developer.apple.com/documentation/virtualization/adding-the-virtualization-entitlement-to-your-project),
[unconditional stop](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop(completionhandler:)).
