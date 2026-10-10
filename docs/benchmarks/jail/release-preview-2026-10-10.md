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

## Fresh VM record

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
