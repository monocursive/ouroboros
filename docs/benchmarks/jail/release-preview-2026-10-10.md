# Linux developer preview acceptance — 10 October 2026

The developer release targets GNU/Linux x86_64 and ARM64. Native macOS execution
remains unsupported. The explicit `--linux-release` verdict retains all shared,
Linux and macOS refusal requirements; it reports the five native macOS clauses
below as unsupported. The full-spec verdict still fails their untested status.

## Acceptance evidence

| Clause | Linux release disposition | Proof |
|---|---|---|
| K03.4 | Live CLI tested | Both a trusted config and a launch profile refuse `none`, name the file and prevent exec; removing them permits an observed unprotected run. |
| K10.1 | Live CLI tested | Non-TTY and cancelled adoption refuse. A real PTY drives consent, concurrent-edit refusal, atomic inode replacement and the next run's exact adopted grant. |
| K11.1 | Recorded real-vendor run, replay tested | OpenCode 1.18.32 performs the file task under `learn`; every proposed grant is checked against its exact event citations, receipt bytes and coverage. |
| K16.1 | Live CLI tested | Empty vault origins refuse before exec. A loopback HTTP fixture substitutes the placeholder, records `never_staged` with no digest, exposes no fixture secret in evidence and removes vendor state. |
| K19.1 | Live CLI tested | Follow emits before settlement within 1.5 seconds, completes promptly and equals the settled journal. |
| K20.1 | Live CLI and portable CLI tested | Live/replayed output equals the journal; a valid noncanonical JSON fixture retains whitespace and Unicode escape spellings byte-identically. |
| K22.2 | Unsupported | Native macOS command-rule execution is outside the distributed platform. Linux rule-cap checks remain required. |
| K23.1 | Unsupported | Native macOS execution and resource-limit enforcement remain open. |
| K24.1 | Unsupported | Native macOS network containment remains open. |
| K26.1 | Unsupported | No native macOS A01 support row is claimed. |
| K27.1 and K27.2 | Native installation tested; recorded clean VM replay tested | Real Minisign/corruption tests run without a terminal. Fresh VM installation, contained `true` and the real OpenCode file task complete in 62.2 seconds. |
| K29.1 | Unsupported | Native macOS descendant lifetime and entitlement evidence remain open. |

The live cases are in [release_preview_linux.rs](../../../crates/ouro-jail/tests/release_preview_linux.rs)
and [preview_gates.py](preview_gates.py). The byte-preservation fixture is in
[portable_tail.rs](../../../crates/ouro-jail/tests/portable_tail.rs). The
[acceptance map](../../specs/jail-v1/acceptance-map.toml) names the exact tests;
untested Linux clauses and failed macOS refusal tests still block publication.

## Optimized reference suite and XFS fixture

The clean optimized suite at `5441e6c96be6fca9d60384d87383ab17a251c74d`
passed 2,089 tests with zero failures. Its first
[conformance workflow](https://github.com/monocursive/ouroboros/actions/runs/38065597642)
failed the acceptance check because an existing privileged XFS test was missing
from the map's reviewed ignored set. This was not a test failure. The corrected
map pins that fixture requirement; replay over the original Linux and
[macOS refusal logs](https://github.com/monocursive/ouroboros/actions/runs/38065597671)
passes every noncredential gate in the Linux release scope. Final publication
still requires passing CI and actual reference conformance on the release commit.

The [XFS test log](results/release-preview-2026-10-10/xfs/test.log) independently
records the ignored test passing as `ouro-ci`, using the same clean optimized
test executable. A disposable 512 MiB loopback XFS volume enforced a 32 MiB user
block ceiling and 128-inode ceiling. The test checks hard-quota admission,
sampling and descriptor survival after directory permissions become mode 000.
[Mount](results/release-preview-2026-10-10/xfs/mount.txt),
[quota](results/release-preview-2026-10-10/xfs/quota.txt) and
[executable digest](results/release-preview-2026-10-10/xfs/binary.sha256)
records retain the fixture facts. The volume was unmounted and removed after
the test; the non-sudo conformance account does not provision mounts itself.

## Published release verification

The [public Linux preview](https://github.com/monocursive/ouroboros/releases/tag/ouro-jail-v0.1.0-rc.1)
is built from `06a48d5a2de89d5d0ebffa84a9561d034cdd8b5d`.
[Rust](https://github.com/monocursive/ouroboros/actions/runs/38068176764),
[contracts](https://github.com/monocursive/ouroboros/actions/runs/38068176775),
[reference conformance](https://github.com/monocursive/ouroboros/actions/runs/38068176785)
and [native packaging](https://github.com/monocursive/ouroboros/actions/runs/38068189013)
passed at that exact commit. Reference conformance passed 2,089 tests with zero
failures and no acceptance-map problems. The dedicated release key signed both
native packages; all eight public assets matched the reviewed candidate after
unauthenticated download.

The signed candidate installed on the Ubuntu reference host and Debian 13 Pi.
Both ran the guide's file-writing command and settled with enforced containment,
verified empty trees and exact raw journal replay. The downloaded GitHub draft
assets matched every candidate byte, and a second draft installation passed on
x86_64. The Pi became unreachable before a second draft check; no second ARM64
draft or public-network run is claimed.

A new [public-install VM](results/release-preview-2026-10-10/public-install/vm.json)
then downloaded the published Bash bootstrap anonymously, checked its expected
digest, installed the signed x86_64 package, and ran the guide's first command.
The [result](results/release-preview-2026-10-10/public-install/result.json) and
[settled receipt](results/release-preview-2026-10-10/public-install/jail.json)
bind the actual public executable SHA256
`feab1ead8951955f8aa79f0cc7a48de323672e7bac176fae563ec693dc9ca819`
to the release revision and inputs.
[Before](results/release-preview-2026-10-10/public-install/rust-absence-before.txt)
and [after](results/release-preview-2026-10-10/public-install/rust-absence-after.txt)
checks found no cargo, rustc or rustup. No production key entered the guest; the
VM and temporary SSH key were destroyed. Dependency setup and waiting for
publication are recorded separately, with no timing or performance claim.

## Fresh VM learning record

[VM metadata](results/release-preview-2026-10-10/vm.json) and
[workflow result](results/release-preview-2026-10-10/guest/result.json) record a
new Ubuntu 26.04.1 x86_64 overlay, Linux 7.0.0-34, under local QEMU TCG. No Rust
toolchain or operator credentials were installed. The image was checked against
SHA256 `8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2`.
The VM/dependency bootstrap took 141.7 seconds before the user-workflow clock.
The 62.2-second clock includes signed installation and agent download through
the first sandboxed OpenCode result. It is onboarding evidence, not a performance
benchmark or an agent reliability matrix.

The tested optimized binary was built from clean commit
`16ee37fe174757c3671b6e616657e8ad10a0ad1a` with Rust 1.98.1:

- Jail inputs: `sha256:2989fb4983dedf8e8c4ea75744cce9eb8ac64c5dacf5985e366ce13a5279c225`.
- Executable SHA256: `8be3cd792877b2225b4021620714c4c852011ea08f007402cbb908be793dcd5e`.
- OpenCode: pinned 1.18.32, `opencode/big-pickle`, no credential, bundled `opencode` profile, observation on, strict evidence.
- Signing identity: disposable test key. The production private key never entered the VM.

The acceptance changes modify tests, evidence and release tooling; Jail runtime
inputs are unchanged. Replay tests require the recorded inputs to equal the
currently compiled Jail's inputs. Native release packages still require clean
builds at the actual release commit and successful exact-commit CI.

Both contained workloads settled with verified empty trees and complete active
closed-set coverage. All fourteen bundled profiles returned successful doctor
reports. Corrupted archives and signatures refused while preserving the existing
install; a valid upgrade succeeded. The successful VM needed no provider retry.
Earlier attempts retained local failure evidence, including a provider Bad
Request and corrections to the harness. This single successful fixture does not
establish general provider or agent reliability; support remains experimental.

## Learning result and replay checks

The [proposal](results/release-preview-2026-10-10/guest/opencode-learned.toml)
proposes only `/etc/nsswitch.conf`, cites the observed denied read and grants no
network destinations or parent directory. Its receipt digest, revision, event
counts and coverage match the [settled receipt](results/release-preview-2026-10-10/guest/opencode-learn-jail.json)
and [journal](results/release-preview-2026-10-10/guest/opencode-learn-trace.ndjson).
The separate fixture read was denied but had no qualifying absolute-path
learning note, so it was not proposed. The warning and coverage describe an
observed subset, not all the program's needs. Nothing was adopted automatically.

[verify_preview_evidence.py](verify_preview_evidence.py) verifies both records.
Its [negative tests](test_preview_evidence.py) reject stale inputs, an installed
Rust toolchain, a ten-minute timeout, accepted corruption, failed vendor exit,
changed receipt bytes, invented grants, rewritten coverage and mixed attempts.
The [portable Rust tests](../../../crates/ouro-jail/tests/portable_release_evidence.rs)
run the verifier with the compiled Jail input digest on every CI platform.

Reproduce on a new disposable VM using the verified image and a clean native
binary with these inputs:

```sh
python3 docs/benchmarks/jail/onboarding_vm.py \
  --image /private/ubuntu26.img \
  --image-url https://cloud-images.ubuntu.com/resolute/20260927/resolute-server-cloudimg-amd64.img \
  --image-sha256 8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2 \
  --binary /private/bin/ouro-jail \
  --revision 16ee37fe174757c3671b6e616657e8ad10a0ad1a \
  --inputs sha256:2989fb4983dedf8e8c4ea75744cce9eb8ac64c5dacf5985e366ce13a5279c225 \
  --out /private/preview-onboarding
```

The [release procedure](../../RELEASING.md) requires reference-host conformance,
a tested freeze, both native packages and production-key signing before public
availability is claimed. ARM64 installation and host limits are evaluated
separately; the x86_64 VM record is not ARM64 conformance evidence.

## SHA-256-pinned public installer

Later on 10 October 2026, the live [Bash installer](https://ouroboros.monocursive.com/install.sh)
was changed to embed the SHA-256 hashes of both existing RC1 Linux archives and
install directly. It needs no Minisign and executes no downloaded installer.
Anonymous downloads of both archives matched the embedded pins:

- x86_64: `9413e8fd0cea1417c1ba47e5e0fad07edf3a26b8615e68a5aa642662f1209da8`.
- ARM64: `100d0e8e78d27c08372b18352de987da447f157ef75c8ebeac0cf5e24dd0400a`.

The updated website installer SHA-256 is
`4acfb0b4580c71f6016fcac25ad4517d6aa73ec3a562d5664d858957bee6db2a`.
A second fresh Ubuntu 26.04.1 QEMU VM downloaded that exact live website script,
installed the public x86_64 archive, passed `doctor --profile tool`, and ran the
guide's first contained command. Minisign, Cargo, rustc and rustup were absent
before and after the workflow. The installed binary SHA-256 remained
`feab1ead8951955f8aa79f0cc7a48de323672e7bac176fae563ec693dc9ca819`, with
release source `06a48d5a2de89d5d0ebffa84a9561d034cdd8b5d` and the same build-input
digest as the original published package. The receipt was settled and enforced,
with an empty verified process tree; `tail --json` matched the raw journal.
The VM and temporary SSH key were destroyed.

The [VM record](results/release-preview-2026-10-10/sha256-install/vm.json),
[dependency absence before](results/release-preview-2026-10-10/sha256-install/dependency-absence-before.txt)
and [after](results/release-preview-2026-10-10/sha256-install/dependency-absence-after.txt),
[workflow result](results/release-preview-2026-10-10/sha256-install/result.json),
[receipt](results/release-preview-2026-10-10/sha256-install/jail.json), and
[live site checks](results/release-preview-2026-10-10/sha256-install/live-site.json)
retain the proof. ARM64 selection and offline checksum rejection passed local
installer tests. The Pi was offline during this follow-up, so no new native ARM64
installation is claimed. Its original candidate installation remains recorded above.

The 28 distribution tests passed, including a changed archive with a matching
remote checksum manifest, offline installation, HTTPS mirrors, unsupported and
unpinned versions, downgrade handling, interrupted input, and preserved existing
files. ShellCheck and the documentation link checker passed. The release tag,
binaries and original eight signed assets remain unchanged; the GitHub release
page points users to the current website installer.
