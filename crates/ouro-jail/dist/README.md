# Signed release tooling

The first developer preview targets `monocursive/ouroboros`, with
`ouro-jail-vVERSION` tags and Linux x86_64/ARM64 packages. The dedicated production
identity is [release.pub](release.pub); no public Jail release is claimed yet.
See the [publication procedure](../../../docs/RELEASING.md) for the Bash entry
point, native `release-candidate` workflow, and draft/publish verification helper.
The standalone packager below remains useful for local inspection packages.

Build with explicit provenance, then package with an operator-selected key:

```sh
OURO_BUILD_REVISION=$(git rev-parse HEAD) OURO_BUILD_DIRTY=true \
  cargo +1.98.1 build --release -p ouro-jail
python3 crates/ouro-jail/dist/package.py \
  --binary target/release/ouro-jail --target aarch64-apple-darwin \
  --version 0.1.0-rc.1 --out /path/to/artifacts --signing-key /path/to/signing.key
```

Use the actual target triple of the supplied binary. Set `OURO_BUILD_DIRTY=false`
only for a clean checkout. The release version is part of the archive name. One
invocation signs exactly its own outputs: the manifest covers the archive it
created and the `install.sh` copy it stages beside it, never archives an
earlier run left in the same directory.

Installation requires `minisign`, `tar`, `sha256sum` or `shasum`, and `curl` for HTTPS downloads.
It installs no backend or system packages. Obtain the public key through a trusted
channel; downloading a key beside an archive does not authenticate that archive.

```sh
sh crates/ouro-jail/dist/install.sh \
  --from-dir /path/to/artifacts --public-key 'TRUSTED_MINISIGN_PUBLIC_KEY' \
  --prefix /path/to/bin
```

Use `--base-url https://...` instead of `--from-dir` for published artifacts.
Use `--upgrade` to replace an existing installation without a TTY. The
installer selects the manifest's single archive for the host platform, checks
the signed archive release version against the installed release record, and
refuses a downgrade unless `--allow-downgrade` is given. The signed manifest
covers `install.sh` itself, and the installer refuses to run when it does not
match that signed copy. Failure to verify the signed manifest or archive
checksum preserves the installed binary. The distribution includes the project
license and the CA-data license notice.

`ouro-jail.release` records the installed release coordinate and binary digest;
the installer refuses a record that no longer matches the binary. Reinstall
with `--upgrade --allow-downgrade` to recover from an interrupted replacement
or a manual binary change, using the authenticated release. The Cargo
package version alone cannot distinguish RC releases. Older installations
without this record use the binary's reported version. Prerelease comparison
follows SemVer identifier ordering, including numeric RC identifiers.

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
  --revision "$TESTED_REVISION" --inputs "$TESTED_INPUTS" \
  --version 0.1.0-rc.1 --out /private/stage-x86
# On the Pi, use --target aarch64-unknown-linux-gnu and a separate output directory.
```

The staged archive name carries that release version, and assembly refuses
artifacts staged for a different one.

Copy the two staged directories to the release operator's machine. Archive
bytes are deterministic across source-file timestamps and locations. Assembly
requires exactly one artifact per architecture, staged for the release version
being assembled, and verifies archive contents, native build records, source
inputs and binary hashes before preparing a draft. The signed manifest covers
both archives, `install.sh`, the public `bootstrap.sh`, release notes and plan:

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
plan's exact commit and proposed tag with `publish_release.py draft`, and verify
installation from its checked assets. `publish_release.py publish` rechecks CI,
the tested freeze, tag and every remote asset before public publication, then
checks unauthenticated downloads. GitHub's [release procedure](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
describes the distinction between saving a draft and publishing it.

```sh
python3 -m unittest discover -s crates/ouro-jail/dist -p test_release.py
```

These tests include real ephemeral signatures, wrong-key rejection, archive and
binary tampering, architecture/build mismatch, missing/duplicate targets and
archive reproducibility; the installer regression covers per-invocation
manifest coverage, installer tampering, downgrade refusal and corrupt
archive/signature rejection. They do not establish public release availability.

The Pi host used for ARM64 validation lacks memory cgroups. Its default `build`
profile requires a memory ceiling and refuses before execution; `tool` and
`agent` validation must not be presented as support for that profile.
