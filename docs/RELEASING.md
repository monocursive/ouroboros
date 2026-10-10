# Publish an Ouroboros Jail developer preview

[Ouroboros Jail 0.1.0-rc.1](https://github.com/monocursive/ouroboros/releases/tag/ouro-jail-v0.1.0-rc.1)
was published on 10 October 2026 from
`06a48d5a2de89d5d0ebffa84a9561d034cdd8b5d`. All eight signed assets were
downloaded anonymously and matched the reviewed candidate. The
[acceptance and public-install record](benchmarks/jail/release-preview-2026-10-10.md)
retains CI, native host checks and a fresh VM installation without Rust.

The first distribution is `ouro-jail` for Linux x86_64 and ARM64 in
`monocursive/ouroboros`. Tags use `ouro-jail-vVERSION`, starting with
`ouro-jail-v0.1.0-rc.1`. This keeps the archived runtime's `v0.1.x` releases
separate. The fleet, ledger, Homebrew and macOS execution are outside this package.

The Bash entry point adapts `legacy:install.sh`: explicit versions, HTTPS,
architecture detection, no sudo or compiler, and installation to `~/.local/bin`.
It embeds the SHA-256 hash for each Linux archive, verifies the selected archive
before extracting or executing it, and installs it directly. Users need Bash,
curl, tar, and sha256sum or shasum; Minisign is not an installation dependency.
A downgrade requires `--allow-downgrade`.

Never direct Jail users to `releases/latest/download/install.sh`: that installs
the archived runtime. The current public preview command is:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://ouroboros.monocursive.com/install.sh | bash
```

The HTTPS-served script is the trust anchor for the embedded hashes. A mirror
or a downloaded checksum manifest cannot replace those pins. `--from-dir DIR`
also checks the same pinned archive offline. `--version` and `--bin-dir` are
accepted through `bash -s -- ...`; versions without embedded pins refuse before
any download.

To publish a new installer, assemble the reviewed native archives below. Assembly
sets the default release and embeds both archive hashes in `bootstrap.sh`, while
retaining previously pinned releases. After publication, copy that reviewed
bootstrap to root `install.sh` and `website/public/install.sh`, update the docs,
and deploy the website. Verify the website script's bytes and an actual public
installation. Never discover a trusted hash from a mutable remote manifest at
install time.

The original immutable RC1 GitHub `bootstrap.sh` and low-level `install.sh`
remain signed historical assets and still require Minisign. The live website
and current repository installer provide the dependency-free SHA-256 path.
The release binaries and their tag are unchanged.

Maintainer candidate signing and publication checks still use the
[dedicated release public key](../crates/ouro-jail/dist/release.pub), created on
10 October 2026. Users of the current installer do not need this key.
Its private half is stored outside the repository at
`~/.config/ouroboros/release-keys/ouro-jail-2026-10-10.key`, in a mode-0700 directory
with file mode 0600. It is unencrypted for local noninteractive signing; maintain
a private backup for future releases. Private key material is never sent to CI.

## Linux-only release scope

On 10 October 2026, the Linux evidence gaps were closed by live CLI tests,
native signed-install tests and a recorded fresh-VM OpenCode workflow. The
[acceptance record](benchmarks/jail/release-preview-2026-10-10.md) gives each
clause's disposition and raw evidence. Future releases require the exact-commit
validation and publication steps below.

Use `cargo xtask gates --linux-release` and
`cargo xtask conformance --linux-release` for this developer preview. This fixed
scope reports K22.2, K23.1, K24.1, K26.1 and K29.1 **unsupported** because native
macOS execution is not distributed. The full verdict without the flag continues
to fail those untested clauses. Every Linux clause, shared test and macOS
execution-refusal test remains required; no failing Linux test is waived.
The signed release plan binds this scope and both native Linux targets.

## Prepare and validate

Commit and review the release tree. Require `rust`, `contracts` and the actual
`conformance` reference-host job to pass on that exact commit. The reference host
needs at least 4 GiB free for a release build. Record successful conformance with
`cargo xtask freeze --doctor`, then require
`cargo +1.98.1 run -q -p xtask -- freeze --check` to pass. A tree-only freeze,
skipped reference host or an older passing run is insufficient.

Set the reviewed coordinates and production key:

```sh
release_version=0.1.0-rc.1
release_revision=$(git rev-parse HEAD)
release_public_key=$(sed -n '2p' crates/ouro-jail/dist/release.pub)
release_private_key="$HOME/.config/ouroboros/release-keys/ouro-jail-2026-10-10.key"
```

Build the same clean checkout or Git archive on both native Linux hosts with
Rust 1.98.1. A Git archive avoids macOS `._` metadata entering release inputs:

```sh
OURO_BUILD_REVISION="$release_revision" OURO_BUILD_DIRTY=false \
  cargo +1.98.1 build --locked --release -p ouro-jail
target/release/ouro-jail version --json
python3 crates/ouro-jail/dist/test_install.py target/release/ouro-jail
```

Set `release_inputs` from `build.inputs` in the version output. Stage each binary
on its native host; staging executes `version --json` and checks architecture,
revision, optimization, toolchain and source inputs:

```sh
python3 crates/ouro-jail/dist/prepare_release.py stage \
  --binary target/release/ouro-jail --target x86_64-unknown-linux-gnu \
  --revision "$release_revision" --inputs "$release_inputs" \
  --version "$release_version" --out /private/stage-x86
```

Use `aarch64-unknown-linux-gnu` and `/private/stage-arm` on ARM64. Both records
must name the same inputs and revision. Retain native doctor, contained-command,
receipt and installation evidence. Host limits remain in the release notes;
installation alone does not establish enforcement support.

Alternatively, run the `release-candidate` Actions workflow on the chosen commit,
or push its tag. Native Ubuntu x86_64 and ARM64 jobs exercise installation using
temporary keys, stage both packages, and upload an **unsigned** candidate.
Download the native stages for local signing:

```sh
gh run download RUN_ID --repo monocursive/ouroboros \
  --name native-x86_64-unknown-linux-gnu --dir /private/stage-x86
gh run download RUN_ID --repo monocursive/ouroboros \
  --name native-aarch64-unknown-linux-gnu --dir /private/stage-arm
```

## Sign and inspect

Assembly uses a fresh directory and signs both archives, the low-level
installer, the pinned Bash bootstrap, release notes and provenance plan:

```sh
python3 crates/ouro-jail/dist/prepare_release.py assemble \
  --stage /private/stage-x86 --stage /private/stage-arm \
  --revision "$release_revision" --inputs "$release_inputs" \
  --version "$release_version" --out /private/release-candidate \
  --signing-key "$release_private_key" --public-key "$release_public_key"
python3 crates/ouro-jail/dist/publish_release.py check \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

Review the plan, support notes and validation evidence. Native records are
builder attestations; signatures do not replace conformance. Test the SHA-256-pinned
bootstrap on both native hosts without Minisign available to the user:

```sh
bash /private/release-candidate/bootstrap.sh \
  --from-dir /private/release-candidate --bin-dir "$HOME/.local/bin"
ouro-jail version --json
ouro-jail doctor --profile tool --json
```

Run the [user guide's first command](guide.md#run-your-first-command), inspect its
settled receipt and preserve unavailable capabilities.

## Draft and publish

Once source, candidate and validation agree, push the exact tag and create a draft:

```sh
git tag -a "ouro-jail-v$release_version" "$release_revision" \
  -m "Ouroboros Jail $release_version developer preview"
git push origin "ouro-jail-v$release_version"
python3 crates/ouro-jail/dist/publish_release.py draft \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

The helper requires a clean tree at the candidate commit, tested freeze,
successful exact-commit CI, live reference conformance and the correct remote
tag. It creates a prerelease draft with exactly eight assets, downloads every
draft asset and verifies its bytes. It never overwrites an existing release.
Smoke-test installation from those downloaded draft assets on both native hosts.

After reviewing that concrete draft and its evidence:

```sh
python3 crates/ouro-jail/dist/publish_release.py publish \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

This rechecks the gates and draft bytes, publishes with `--latest=false`, then
downloads all public assets without authentication and verifies their digests.
If public verification fails after GitHub accepts publication, the release may
already be public. Inspect it and rerun `verify`; do not assume rollback:

```sh
python3 crates/ouro-jail/dist/publish_release.py verify \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

Verify the public installer and first command on a clean supported Linux host.
Then update the README, guide and website with the real release link, trusted
archive hashes and host requirements. GitHub's [release procedure](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
documents draft and prerelease behavior.

## Local checks

```sh
shellcheck install.sh crates/ouro-jail/dist/install.sh
python3 -m unittest discover -s crates/ouro-jail/dist -p test_bootstrap.py
python3 -m unittest discover -s crates/ouro-jail/dist -p test_publish.py
python3 -m unittest discover -s crates/ouro-jail/dist -p test_release.py
python3 -m unittest discover -s crates/ouro-jail/dist -p test_versions.py
python3 crates/ouro-jail/dist/test_install.py target/release/ouro-jail
```

Bootstrap tests use pinned fixture archives and local download adapters, with
Minisign calls forced to fail. Maintainer tests use temporary signing keys.
They cover installation,
upgrade/downgrade, truncated pipes, tampering, signed provenance and publication
gates; they do not establish public availability.
