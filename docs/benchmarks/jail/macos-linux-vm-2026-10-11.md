# macOS Linux VM prototype — 2026-10-11

The [local prototype](../../../crates/ouro-jail/vm/README.md) runs the published
Linux ARM64 Jail inside Apple's Virtualization framework on this Mac. Both
`tool` and `build` commands completed with enforced containment, a verified
empty Linux process tree, returned output files, and an acknowledged VM stop.
It is not a published macOS release and does not implement native macOS execution.

The final VM-service teardown matrix is **9 passed, 1 failed**. Simultaneously
suspending the Mac launcher and its Swift helper leaves Apple's VM service
allocated. The guest now explicitly kills its Linux workload cgroup and verifies
it empty before requesting poweroff. That closes the observed workload-cleanup
gap in this case, but does not make the retained host resource disappear.
Resuming the controllers releases the VM service. The stricter teardown check
remains failed; no native macOS acceptance clause or Linux release gate is waived.

## Implementation and scope

`prepare.py` verifies pinned downloads, builds an ad-hoc signed Swift VZ helper,
and boots a setup guest to install bubblewrap and an unprivileged `ouro` account
with delegated cgroups. `run.py` clones that prepared disk, transfers a selected
workspace through a virtio socket, and starts the unchanged Linux release
binary. Byte argv transport preserves arguments without shell interpolation.

The execution VM has no IP network adapter or host directory sharing. Only the
setup guest has NAT for package installation. Execution uses two virtual CPUs,
2 GiB VM memory, a 6 GiB private sparse disk, a 512 MiB jail memory ceiling,
zero swap, 64-process ceiling, and an explicit wall deadline. The offline scope
currently excludes interactive stdin, provider credentials and networked agents.
The copied workspace is explicitly writable under `build`; host input files
remain untouched. File-transfer limits and excluded directories are listed in
the prototype README.

The launcher drives a sequenced guest lease, requiring acknowledgements. Caller
EOF or signals stop the VM through VZ. A root guest controller expires the lease
after two seconds without a valid heartbeat, kills `user.slice` with
`cgroup.kill`, verifies `cgroup.events` reports `populated 0`, then powers off.
The Linux jail independently provides its existing process-tree enforcement.
A systemd watchdog supervises the guest controller. VM save/restore and automatic
restart are not exposed.

## Measured environment

- Host: Apple M5 Pro, macOS 27.0.1 (26A434), SIP enabled. No host security settings
  changed. The separate `ouro-jail-es-dev` macOS research VM remained stopped.
- Guest: Ubuntu 26.04.1, Linux `7.0.0-38-generic`, ARM64, bubblewrap 0.11.1.
- Linux binary: public `0.1.0-rc.1` archive, SHA-256
  `100d0e8e78d27c08372b18352de987da447f157ef75c8ebeac0cf5e24dd0400a`.
- Ubuntu input: dated 20261009 minimal image, SHA-256
  `4e86a7819b4cc7b4a9c2e719dec3e0a723c4a2788dc3f23f17641cba7f5ca216`.
- The final prepared image and source hashes are in
  [image metadata](results/macos-linux-vm-2026-10-11/image-v3-image.json) and
  [fault-run provenance](results/macos-linux-vm-2026-10-11/final-faults/provenance.json).
  This is local image provenance, not a reproducible or signed public image.

## Functional checks

The final [tool attempt](results/macos-linux-vm-2026-10-11/tool-final/attempt.json)
and [build attempt](results/macos-linux-vm-2026-10-11/build-03/attempt.json)
both returned exit 0. They verified Linux execution, literal arguments containing
spaces, shell metacharacters and Unicode, absence of the Mac home path, blocked
external networking, and returned a new JSON file. The input workspace still
contained only its original fixture. The unmodified Linux receipts are retained
beside each attempt and independently report enforced containment, empty-tree
integrity and completed cleanup.

Readiness was about 22.2 seconds for each final functional run on this active
developer machine. This is a two-sample startup observation, not a performance
qualification or comparison with native Jail execution.

Nine portable regression tests pass for byte-preserving file transfer, excluded
directories, symlinks, FIFOs, size bounds, path traversal and rejection of
unverified receipts. The Swift helper compiled with warnings treated as errors;
Python compilation, document links and whitespace checks passed. The portable
tests were added to the contracts workflow; they do not boot a VM in CI.

## Fault results

Every trial starts a live fixture with six detached children. The runner locates
the exact Apple VM service by its open attempt-disk descriptor and checks process
identity before signaling it. Measurements below end before emergency test
cleanup. Times run from fault injection to observed service disappearance.

| Fault | VM service gone autonomously | Measured interval |
| --- | --- | --- |
| Three-second guest wall budget | Yes; Linux receipt verifies empty tree | 2.756 s from readiness |
| Cancellation | Yes | 0.065 s |
| Launcher killed | Yes | 0.129 s |
| Launcher suspended | Yes; guest cgroup also verified empty | 1.951 s |
| Swift helper killed | Yes | 0.011 s |
| Swift helper suspended | Yes; guest cgroup also verified empty | 6.708 s |
| Launcher and helper killed | Yes | 0.128 s |
| Apple VM service killed | Yes | 0.012 s |
| Apple VM service suspended for four seconds, then resumed | Yes after resumption | 4.039 s, including suspension |
| Launcher and helper both suspended | **No at the eight-second checkpoint**; guest cgroup verified empty | Service released after host resumption |

The complete [final matrix](results/macos-linux-vm-2026-10-11/final-faults/summary.json)
includes the failed case. Its console witness records `workload_tree_empty`
before the host controllers resume. A separate
[combined-stall trial](results/macos-linux-vm-2026-10-11/combined-stall-v3/00-both_stop/result.json)
observed the same behavior. Guest workload termination and Mac VM-service
resource release are different proof claims. Service resumption is an explicit
fault-recovery action, not autonomous cleanup, and is not credited as a pass.

The prior image passed 27 trials, three for each of the first nine cases;
[all results](results/macos-linux-vm-2026-10-11/faults-02/summary.json) are retained.
Those trials predate the explicit guest cgroup kill and are not substituted for
the final-image measurements. Initial failures are retained too: the fault
harness first rejected Python's startup re-exec as an identity change, the first
build-profile attempt lacked the explicit copied-workspace grant, and the first
combined suspension exposed the retained VM service. None is silently excluded
from its original cohort.

The matrix checks selected live failures, not arbitrary combinations of guest
and host faults, system sleep/wake, all resumption races, stress/resource
exhaustion, or complete release conformance. The test runner conservatively
marks the combined-stall trial as requiring cleanup/recovery even where resuming
the controllers releases the service before its final emergency kill loop.

## Before a public preview

Keep this as a source prototype while defining and reviewing the VM preview's
own lifetime contract, including suspended-controller resource retention. Then
complete guest-controller crash/watchdog and Mac sleep/wake coverage, package a
native launcher, produce and pin the release image with its required notices,
sign/notarize the Mac distribution, integrate the installer, and test on a clean
Mac without build tools. The current website and public installer remain
Linux-only. Apple's Endpoint Security entitlement and native cleanup question
remain separate work.

Reproduction commands and prerequisites are in the
[prototype README](../../../crates/ouro-jail/vm/README.md). Raw evidence excludes
large disk images, EFI stores and redundant encoded transport logs;
[metadata](results/macos-linux-vm-2026-10-11/metadata.json) records that boundary.
