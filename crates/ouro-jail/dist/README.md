# Local release tooling

Publication coordinates and the production signing identity are not configured.
These tools package an existing binary and verify installation locally; they do
not claim a published release or build the four target binaries.

Build with explicit provenance, then package with an operator-selected key:

```sh
OURO_BUILD_REVISION=$(git rev-parse HEAD) OURO_BUILD_DIRTY=true \
  cargo +1.98.1 build --release -p ouro-jail
python3 crates/ouro-jail/dist/package.py \
  --binary target/release/ouro-jail --target aarch64-apple-darwin \
  --out /path/to/artifacts --signing-key /path/to/signing.key
```

Use the actual target triple of the supplied binary. Set `OURO_BUILD_DIRTY=false`
only for a clean checkout. A later invocation against the same artifact directory
signs a manifest covering every staged target archive.

Installation requires `minisign`, `tar`, `shasum`, and `curl` for HTTPS downloads.
It installs no backend or system packages. Obtain the public key through a trusted
channel; downloading a key beside an archive does not authenticate that archive.

```sh
sh crates/ouro-jail/dist/install.sh \
  --from-dir /path/to/artifacts --public-key 'TRUSTED_MINISIGN_PUBLIC_KEY' \
  --prefix /path/to/bin
```

Use `--base-url https://...` instead of `--from-dir` for published artifacts.
Use `--upgrade` to replace an existing installation without a TTY. Failure to
verify the signed manifest or archive checksum preserves the installed binary.
The distribution includes the project license and the CA-data license notice.

The [2026-09-30 fresh-VM onboarding report](../../../docs/benchmarks/jail/onboarding-2026-09-30.md)
records signed non-TTY installation, contained `true`, a real OpenCode run and
corruption/upgrade checks on a clean Ubuntu 26.04 VM without Rust. The tested
reference-built GNU artifact refuses on Ubuntu 22.04 (glibc mismatch), and
stock Ubuntu 24.04's bubblewrap namespace setup fails under its default policy;
the report retains those limits. Public releases and production signing remain
operator choices.

Run the installer regression with an ephemeral test key:

```sh
python3 crates/ouro-jail/dist/test_install.py target/release/ouro-jail
```

## Prepare the Linux release candidate

The selected destination is `monocursive/ouroboros`, initially Linux x86_64 and
ARM64. Preparation produces local files and never creates a GitHub release.
A Homebrew tap and native macOS execution are outside this first distribution.

Build the same clean commit on each native host with the pinned Rust toolchain.
Set `OURO_BUILD_REVISION` to that commit and `OURO_BUILD_DIRTY=false` only after
checking the checkout. Run the applicable native validation before staging.
The `stage` command executes the supplied binary's `version --json`, checks its
ELF architecture and requires the named clean, optimized build-input digest:

```sh
python3 crates/ouro-jail/dist/prepare_release.py stage \
  --binary target/release/ouro-jail --target x86_64-unknown-linux-gnu \
  --revision "$TESTED_REVISION" --inputs "$TESTED_INPUTS" --out /private/stage-x86
# On the Pi, use --target aarch64-unknown-linux-gnu and a separate output directory.
```

Copy the two staged directories to the release operator's machine. Archive
bytes are deterministic across source-file timestamps and locations. Assembly
requires exactly one artifact per architecture and verifies archive contents,
native build records, source inputs and binary hashes before preparing a draft:

```sh
python3 crates/ouro-jail/dist/prepare_release.py assemble \
  --stage /private/stage-x86 --stage /private/stage-arm \
  --revision "$TESTED_REVISION" --inputs "$TESTED_INPUTS" \
  --version 0.1.0-rc.1 --out /private/release-candidate
```

`0.1.0-rc.1` is an example candidate version, not a published tag. The resulting
`release-plan.json` records the repository, proposed tag, commit, hashes and
remaining publication blockers. `RELEASE_NOTES.md` preserves the current host
and agent-compatibility limits. Native artifact records are builder attestations;
review the trusted build environment and its conformance evidence before signing.

For signed assembly, use a fresh output directory and add `--signing-key` with
the operator's private key path and `--public-key` with the independently trusted
public key. Assembly verifies its own signature before reporting success. It
never generates, uploads or stores a private key. The production key, custody,
backup and trusted public-key distribution must be chosen by the operator.

Before publication, review the exact candidate, its validation record and host
support notes. Then create a draft release in the selected repository using the
plan's exact commit and proposed tag, upload the two archives and signed manifest,
and verify installation from those draft assets. Public publication is a separate
operator action. GitHub's [release procedure](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
describes the distinction between saving a draft and publishing it.

```sh
python3 -m unittest discover -s crates/ouro-jail/dist -p test_release.py
```

These tests include real ephemeral signatures, wrong-key rejection, archive and
binary tampering, architecture/build mismatch, missing/duplicate targets and
archive reproducibility. They do not establish public release availability.

The Pi host used for ARM64 validation lacks memory cgroups. Its default `build`
profile requires a memory ceiling and refuses before execution; `tool` and
`agent` validation must not be presented as support for that profile.
