# Endpoint Security development before approval

Follow-up: the [2026-09-30 reciprocal-custody experiment](macos-reciprocal-custody.md)
measured independent clients surviving either custodian's failure. Simultaneous
loss still leaves workloads running, including with fail-closed AUTH_EXEC.
The original single-client results below remain historical evidence.

Apple's [system extension guidance](https://developer.apple.com/system-extensions/)
explicitly permits testing while an entitlement request is under review by
temporarily disabling System Integrity Protection. There is no automatically
available Endpoint Security development entitlement equivalent to DriverKit's;
[Apple DTS](https://developer.apple.com/forums/thread/831307) distinguishes
approved development signing from the reduced-protection test workflow.

Use a disposable macOS 27 Tart VM for this experiment. The host retains SIP,
and no operator credentials, signing keys or host directories are shared.
The current descendant-scoped API requires macOS 27, so an older guest cannot
validate it.

## Preparation

The tested Tart version is 2.38.0. The
[Cirrus image templates](https://github.com/cirruslabs/macos-image-templates)
publish the macOS 27 base image used here. Pin the image used for the recorded
tests rather than relying on a changing `latest` tag:

```sh
TART_NO_AUTO_PRUNE=1 tart clone \
  ghcr.io/cirruslabs/macos-golden-gate-base@sha256:9a2f20d179d6418a128dcb76c593588ea85a263dbfa286e757db63f3d949af7c \
  ouro-jail-es-dev
tart set ouro-jail-es-dev --cpu 4 --memory 8192 --display 1280x900 --no-display-refit
tart run ouro-jail-es-dev --no-clipboard --no-audio --no-usb-accessories
```

The pinned image already has SIP disabled. Its authenticated root remains
enabled, and its `boot-args` value is empty. Check the actual guest settings;
do not assume every image has these defaults. For a guest with SIP enabled,
Tart's [`--recovery` workflow](https://tart.run/faq/#disk-resizing) allows
`csrutil disable` in the **guest Recovery terminal**, followed by a guest
restart. Never run that command in host Recovery for this experiment. No SIP
or AMFI setting is changed by the Python runner.

The guest's Ethernet service was disabled before copying or running the
fixtures. Commands still work through the Tart guest agent's VM socket:

```sh
tart exec ouro-jail-es-dev sudo -n networksetup -setnetworkserviceenabled Ethernet off
tart exec ouro-jail-es-dev networksetup -getnetworkserviceenabled Ethernet
```

The installed Tart's `--net-host` option required a privileged Softnet helper
and failed before starting a VM. The recorded test instead used the disabled
guest Ethernet service: `en0` was inactive and no default route was present.

Copy only `macos_es.c`, `macos_es.py`, `macos_native.c` and `macos_native.py`
into the guest. The base image includes the Tart guest agent, allowing
`tart exec` without enabling host file sharing or adding SSH credentials.

## Probe and lifecycle tests

Inside the guest, check `sw_vers`, `sysctl -n kern.hv_vmm_present` and
`csrutil status`, then run:

```sh
python3 macos_es.py --development-vm --out /tmp/ouro-es-development
```

This mode requires a virtual machine and fully disabled SIP, uses an ad-hoc
signature claiming the ES entitlement, and accepts no Apple signing identity
or provisioning profile. It records SDK/build information, the guest's SIP
state and `approved_entitlement: false`. Without the flag, the existing
approved-profile and ordinary capability/refusal paths remain available.

The host's real negative check refuses this mode before creating an output
directory. The first guest run succeeded at client creation and reached all
four lifecycle cases, without an Apple profile or a root process.

The first gate is the actual `es_new_descendants_client` return value. Only
success releases a fixture. Subsequent trials check wall expiry, cancellation,
workload-supervisor death and ES-custodian death. The runner checks known
fixture processes before its emergency cleanup; that cleanup cannot count as
successful lifecycle enforcement.

These results can guide implementation while Apple reviews the request.
They cannot establish J11 release readiness: repeat successful cases with SIP
enabled and an Apple-approved profile, and retain the complete lifecycle,
event-loss and adversarial requirements in the specification.

## Recorded results — 2026-09-29

The guest and host both ran macOS 27.0 build 26A428. The guest used SDK 27.0,
four virtual CPUs and 8 GiB RAM. The ES helper ran as UID 501 with an ad-hoc
signature claiming the ES entitlement, no provisioning profile and no Apple
signing key. Client creation returned success, and live fork, exec and exit
events were received. [Guest settings](results/macos-es-development/guest-settings.txt),
[guest networking](results/macos-es-development/guest-network.txt),
[host SIP](results/macos-es-development/host-sip.txt) and
[host refusal](results/macos-es-development/host-refusal.json) are recorded.

The [initial 40-case series](results/macos-es-development/summary.json) found
three integrity refusals despite empty fixture trees. The
[diagnostic run](results/macos-es-development/diagnostics/trial-03.json)
identified `proc_signal_with_audittoken(token, 0)` returning `EINVAL` while
members awaited exit events. Signal zero is not a valid liveness probe for
this API. The prototype now counts observed members after draining ES events;
unexpected signal errors remain fatal and are recorded explicitly. Initial
failures and diagnostic evidence are retained separately from the rerun.

The [corrected series](results/macos-es-development/rerun/summary.json) contains
ten repetitions of each case, with no excluded samples:

| Case | Known fixture tree empty before runner cleanup | Readiness p50 / p95 | Custodian teardown p50 / p95 |
| --- | --- | --- | --- |
| Two-second wall expiry | 10/10 | 68.08 / 92.76 ms | 1.27 / 86.38 ms |
| Cancellation | 10/10 | 39.06 / 104.44 ms | 0.85 / 0.97 ms |
| Workload-root SIGKILL | 10/10 | 67.74 / 94.48 ms | 1.01 / 72.26 ms |
| ES-custodian SIGKILL | 0/10; all five processes survived | 48.28 / 96.26 ms | No custodian teardown |

Each runner invocation performs all four cases. To repeat the series inside
the guest, use a new output parent and run it ten times. The expected current
result is `lifetime_gate_failed` with exit 125 because the custodian-death case
fails, even when all other cases succeed. Inspect each case's exit and
integrity fields as well as that overall status.

Readiness includes helper launch, ES subscription and suspended release through
all fixture registrations. Teardown is the custodian's kill/drain interval;
the workload-root death case still waits for the two-second wall deadline, so
it is not an immediate root-death response measurement. The runner's independent
observation interval is also preserved in every raw case. The custodian-death
snapshots occurred about 2.03–2.15 seconds after the kill request. All survivor cleanup
was checked afterward, but that emergency cleanup does not pass the gate.

These are small mechanism measurements inside a VM on a working developer
machine, not quiet-host production performance measurements. With ten samples,
nearest-rank p95 is the maximum. Build time and the initial exploratory probe
are excluded from readiness; no measured rerun sample is removed. Raw records
bind the helper, runner and fixtures by SHA-256.

For all 30 cases in which the custodian survived, independent fixture audit
tokens appeared in the ES fork/exec stream and in exit events, event sequences
were contiguous, the root was reaped, and no integrity error was reported.
This does not cover concurrent fork storms, event-loss injection, actual PID
reuse, hostile attempts to attack the custodian, or the complete final-drain
protocol required by the specification.

Development is unblocked; production native execution remains gated. The next
design problem is ensuring custody survives a custodian crash or kill, or
providing a kernel-owned mechanism that stops the entire workload when custody
is lost. Apple entitlement approval does not supply that missing behavior.

The `ouro-jail-es-dev` VM was shut down cleanly after evidence collection and
is retained for further development tests. Its Ethernet service remains disabled.
