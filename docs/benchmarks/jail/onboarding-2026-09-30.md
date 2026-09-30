# Fresh Linux VM onboarding — 2026-09-30

**K27's local clean-VM workflow passes in 67.32 seconds** on a new Ubuntu
26.04.1 x86_64 VM without Rust. A signed artifact from clean revision
`41d8c230716877b5da6e6db3220017b7eb685344` installs without a TTY, runs contained
`true`, and runs real OpenCode 1.18.32 with the embedded `opencode` profile.
The agent writes exactly `hello\n`; its receipt settles with enforced
containment, verified lifetime integrity, `tree_empty: true`, and every
coverage class active without gaps.

This closes the **local** onboarding part of [J7/K27](../../specs/jail-v2.md).
Release coordinates, the production signing identity, public release artifacts
and Homebrew publication remain deferred. An ephemeral test key signs the
local artifact; its public key in the evidence is not a production trust root.

## What ran

| Item | Measured value |
|---|---|
| Jail revision | `41d8c230716877b5da6e6db3220017b7eb685344`, clean |
| Jail source-input digest | `sha256:f5486df5891709f837825bb55d051275c42b2e634165caeb239919247cc0cbfb` |
| Installed binary SHA-256 | `1b52abdbd326eb0b422ba7638b4b3fb0fdc0fd0b72628a7a125184b5571037cd` |
| Build | Rust 1.98.1; optimized level 3; debug assertions off; `x86_64-unknown-linux-gnu` |
| Guest | Ubuntu 26.04.1; Linux `7.0.0-34-generic`; glibc 2.43 |
| Backend | Distribution bubblewrap 0.11.1; ptrace closed-set observation |
| Installer verifier | Distribution minisign 0.12 |
| VM | QEMU 11.1.1, x86_64 TCG emulation, 2 vCPUs, 3,072 MiB RAM, new 12 GiB QCOW2 overlay |
| Host | ARM64 macOS 27.0; no host security-policy changes |
| OpenCode | 1.18.32, official Linux x64 baseline artifact, no credentials |
| Model | `opencode/big-pickle`, advertised free when checked on 2026-09-30 |

The base image is Canonical's [2026-09-27 Ubuntu 26.04 cloud
image](https://cloud-images.ubuntu.com/resolute/20260927/). Its SHA-256 is
`8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`, checked
against Canonical's HTTPS-served checksum manifest. A new NoCloud instance,
new writable overlay and new SSH key establish a genuine fresh VM rather
than a container or another account on an existing machine. No repository
source or operator credentials enter the guest.

The guest bootstrap installs ordinary distribution prerequisites:
`bubblewrap`, `minisign`, `curl`, `ca-certificates`, `perl` (for `shasum`),
`git`, and `python3`. It takes **160.58 seconds**, measured separately from
the user workflow. The guest has no `cargo`, `rustc`, or `rustup` before or
after the run, and no preexisting jail or OpenCode installation. No sysctl,
AppArmor rule, privileged helper or service is configured by the installer
or the test. CPU emulation makes these compatibility/onboarding timings;
they are not jail performance benchmarks.

## Timed user workflow

The timer starts immediately before the non-TTY signed installation from a
local artifact directory. It includes signature/checksum verification,
installation, provenance checks, creating an empty git workspace, contained
`true`, downloading/verifying OpenCode, unpacking it, querying its version,
and the first contained agent result. Artifact transfer into the VM and
distribution prerequisite setup precede this timer.

| Step | Seconds | Result |
|---|---:|---|
| Signed non-TTY installation | 1.89 | Exit 0; exact clean build |
| Contained `/usr/bin/true` | 0.69 | Exit 0; enforced containment; settled empty tree |
| OpenCode download | 2.40 | Verified official artifact SHA-256 |
| OpenCode version command | 7.20 | `1.18.32` |
| Contained OpenCode A01 | 46.23 | Exit 0; `greeting.txt` is exactly `hello\n` |
| **Whole workflow, including other setup/unpacking** | **67.32** | **Under ten minutes** |

The launch uses the bundled profile and the documented read-only grant for
the vendor installation:

```sh
~/.local/bin/ouro-jail run --launch opencode \
  --workspace ~/onboarding-project --ro ~/.opencode/bin --limit wall=300s -- \
  ~/.opencode/bin/opencode run --model opencode/big-pickle \
  'Create greeting.txt containing exactly hello followed by a newline. Do not read any other file or use the network yourself.'
```

The official [OpenCode Zen pricing page](https://opencode.ai/docs/zen/)
listed Big Pickle as free at the time of this test. The test uses an empty
project and an ordinary fixture prompt, without a paid account or credential.
The [official release artifact](https://github.com/anomalyco/opencode/releases/tag/v1.18.32)
SHA-256 is `763af386ef88a8cab18df00fcf055690e5a55e31a7088beabe02307142a6adce`.

After the timed workflow, all 14 embedded launch profiles return `ready: true`
under `doctor --launch`. Corrupted-archive and corrupted-signature upgrades
both fail nonzero and preserve the installed binary's digest. A valid upgrade
then succeeds without a TTY. Those checks are recorded separately from the
67.32-second timer.

The guest keeps its default `Linger=no`. The receipt records
`supervisor_scope.state: unavailable`, `reason_code: no_linger`; preferred
delegated cgroup controls are unavailable. The successful settled attempt
proves its own empty tree. This onboarding run does not test supervisor death
during startup or extend the delegated reference-host lifecycle claim to
this configuration.

## Refusals retained

- **Ubuntu 22.04:** the exact reference-built GNU binary requires
  `GLIBC_2.39`; the fresh guest provides glibc 2.35 and the loader refuses it.
  Ubuntu 22.04's archive also has no `minisign` package. This platform is not
  supported by the tested artifact.
- **Ubuntu 24.04:** signed installation succeeds, but stock bubblewrap 0.9.0
  fails directly with `loopback: Failed RTM_NEWADDR: Operation not permitted`.
  The stock AppArmor user-namespace restriction is enabled and there is no
  bubblewrap profile. `doctor` records the failed namespace probes; contained
  `true` refuses before target release. The runner preserves the refusal and
  does not change security policy to obtain a passing result.
- The first Ubuntu 24.04 runner also could not read the root-owned bootstrap
  log after collecting guest evidence. The harness now uses read-only `sudo`
  to collect that log. The diagnostic rerun records the underlying sandbox
  refusal independently.

These refusals constrain the supported platform claim; success on Ubuntu
26.04 does not establish generic Linux distribution compatibility.

## Evidence and reproduction

The [VM record](results/onboarding-2026-09-30/ubuntu26/vm.json) contains the
image digest, resources, launch arguments, bootstrap time and cleanup result.
The [workflow record](results/onboarding-2026-09-30/ubuntu26/guest/result.json),
[true receipt](results/onboarding-2026-09-30/ubuntu26/guest/true-jail.json),
[OpenCode receipt](results/onboarding-2026-09-30/ubuntu26/guest/opencode-jail.json),
[OpenCode trace](results/onboarding-2026-09-30/ubuntu26/guest/opencode-trace.ndjson)
and [workspace output](results/onboarding-2026-09-30/ubuntu26/guest/greeting.txt)
bind the result to what ran. Installer failure/upgrade logs, signed manifests,
doctor JSON and complete bootstrap/console logs are beside them. Disposable
VMs and private SSH/signing keys have been removed; no binary archive or
private key is checked into the evidence directory.

Earlier failures remain in [Ubuntu 22 preflight](results/onboarding-2026-09-30/ubuntu22-preflight/vm.json),
[first Ubuntu 24 run](results/onboarding-2026-09-30/attempt-1/guest/result.json),
and the [Ubuntu 24 diagnostic run](results/onboarding-2026-09-30/ubuntu24-diagnosis/guest/failure-doctor.stdout).

Use [the VM harness](onboarding_vm.py), which invokes
[the guest harness](onboarding_guest.py). Supply the exact clean optimized
binary and a locally downloaded, checksum-verified Canonical image:

```sh
python3 docs/benchmarks/jail/onboarding_vm.py \
  --image /path/to/resolute-server-cloudimg-amd64.img \
  --image-sha256 8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2 \
  --image-url https://cloud-images.ubuntu.com/resolute/20260927/resolute-server-cloudimg-amd64.img \
  --binary /path/to/clean-41d8c230/ouro-jail \
  --revision 41d8c230716877b5da6e6db3220017b7eb685344 \
  --out /path/to/new-evidence-directory
```

Host prerequisites are QEMU, `qemu-img`, OpenSSH, minisign, Python 3.11+
and a NoCloud ISO creator (`hdiutil` on macOS; `genisoimage` on Linux).
Linux hosts with accessible KVM can select `--accelerator kvm`; this recorded
run uses TCG. Missing VM/tool prerequisites produce an explicit blocker.
The harness refuses a container substitute, rejects dirty/mismatched builds,
retains failed-run receipts, and cleans up the guest and private keys.
