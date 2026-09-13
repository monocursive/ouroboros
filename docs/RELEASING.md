# Installing and releasing Ouroboros

Ouroboros uses version tags and GitHub Releases. Each release contains four native
`ouro` executables with the Elixir runtime, Erlang/OTP and WebAssembly helper embedded,
an `install.sh`, and `SHA256SUMS`. Users do not need Elixir, Rust or a compiler.

## Install

Latest stable version:

```sh
curl -fsSL https://github.com/monocursive/ouroboros/releases/latest/download/install.sh | bash
```

The Bash installer detects the machine, resolves the latest stable tag once, downloads
that tag's binary and verifies its SHA-256 checksum before installing `~/.local/bin/ouro`.
It prints a PATH command if needed. It does not use sudo, edit shell profiles, configure
model accounts, or start/stop the runtime. For a different destination, append
`-s -- --bin-dir /absolute/path` to `bash`.

Install a specific version, including an older release or a release candidate (replace
`v0.1.3` with a published tag):

```sh
curl -fsSL https://github.com/monocursive/ouroboros/releases/download/v0.1.3/install.sh | bash -s -- --version v0.1.3
```

For inspection before execution, download `install.sh`, read it, then run
`bash install.sh --version v0.1.3`. All versions and their checksums remain on the
[Releases page](https://github.com/monocursive/ouroboros/releases). The installer accepts
`--help`, `--version`, and `--bin-dir`; it refuses an existing symlink at the destination.
It trusts the official GitHub repository and HTTPS. SHA-256 detects corrupt or mismatched
downloads; it is not a separate publisher signature or macOS notarization.

## Platforms and prerequisites

| Download suffix | Native build runner | Installation target |
|---|---|---|
| `aarch64-apple-darwin` | `macos-15` | Apple Silicon macOS |
| `x86_64-apple-darwin` | `macos-15-intel` | Intel macOS |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` | ARM64 GNU/Linux with glibc 2.39+ |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` | x86-64 GNU/Linux with glibc 2.39+ |

Use macOS 15 or newer, or Ubuntu 24.04 as the Linux baseline. Each release tests its
exact runner OS; these builds do not establish compatibility with every newer OS or
Linux distribution. Alpine/musl, Windows and 32-bit systems have no binary release.
On Rosetta terminals the installer selects the native Apple Silicon binary.

The installer needs Bash 3.2+, curl, standard Unix utilities and either `sha256sum` or
`shasum`. A Linux runtime also needs its normal system shared libraries (including
OpenSSL 3, libstdc++ and ncurses/tinfo). Shell containment on Linux needs bubblewrap
and permission to create its namespaces. See [PREVIEW.md](PREVIEW.md) for distro setup,
the opt-in Ubuntu AppArmor configuration, model connection and first-use checks.
No installer changes those system policies. Git is needed for repository work.

For a manual download, verify the selected binary against `SHA256SUMS`, rename it
to `ouro`, and run `chmod +x ouro` before moving it into a directory on your PATH.

The release smoke boots outside the checkout with a system-only PATH and a fresh data
directory. It checks the embedded version, runtime startup, helper presence and native
target, unauthenticated web refusal, and authenticated shutdown. On macOS it also rejects
non-system absolute native-library dependencies. Full model-backed tasks and OS coverage
are separate from this packaging gate; the [preview record](PREVIEW.md) tracks those.

## Upgrade, older versions and removal

Official standalone releases starting with 0.1.3 can upgrade themselves:

```sh
ouro update --check  # No files changed; exit 10 means an update is available.
ouro update          # Install a newer stable release at this executable's location.
```

The updater verifies SHA-256, checks that the downloaded executable runs and reports
the selected version, and replaces the binary atomically. It needs curl, but no
checkout, compiler, model account, or running runtime. It never automatically
downgrades or restarts active work. `--check` exits 0 when current/ahead and 1 on
failure; a successful update exits 0. A local build can check but cannot replace
itself. Run as the installation's owner without sudo. Recognized package-manager
stores and directories writable by other users are refused; use that manager or
install a standalone copy in a directory you own. Updates on other fleet machines
and their runtime restarts are coordinated separately.

Finish active work, run `ouro stop`, then run `ouro` again to activate the installed
runtime. The process-identity helpers stay compatible with older running runtimes;
updating the binary alone does not update already-loaded BEAM code.

Version 0.1.2 and older binaries without `update` need one installer rerun to acquire
the command. The installer also remains the recovery path and supports choosing an
explicit older release with `--version`. Stop the runtime before using that path.
Avoid running the installer and `ouro update` concurrently. Updater processes
coordinate through a permanent `.ouro-update-*.lock` file beside the executable;
do not remove that file while an update is running.

The verified replacement is renamed into place atomically;
a failed download or checksum leaves the installed executable unchanged. `ouro version`
shows both the client and embedded runtime version. Run `ouro` again to start that version.
An already running runtime continues using its old code until stopped.

Choosing an older binary does not migrate persistent data backwards. Before upgrading,
stop the runtime and back up your data/configuration (normally
`~/.local/share/ouroboros` and `~/.config/ouroboros`, or your configured locations).
Restore a compatible backup or use a separate `OUROBOROS_DATA_DIR` when returning to an
older release. Check the [changelog](../CHANGELOG.md) for upgrade notes and data
compatibility changes.

To remove the default installation, stop the runtime and delete `~/.local/bin/ouro`.
Your configuration, credentials, sessions and extracted runtime cache remain available.

## Cut a release

Work integrates through `dev`; stable releases come from commits on `main`. Release
candidates may come from commits on `dev` or `main`. Use:

- `vX.Y.Z` for a stable release, for example `v0.1.3`.
- `vX.Y.Z-alpha.N`, `vX.Y.Z-beta.N`, or `vX.Y.Z-rc.N` for a prerelease.

No leading zeroes, moving major-version tags or build-metadata suffixes. Never move a
published tag or replace its assets. A correction gets a new version.

1. Set the **same version without `v`** in `mix.exs`, `tui/Cargo.toml`, and the
   `name = "ouro"` package entry in `tui/Cargo.lock`.
   The helper and guest SDK have their own package versions; do not bump them merely
   to rename an Ouroboros release.
2. Move the relevant `Unreleased` entries in
   [CHANGELOG.md](../CHANGELOG.md) into a section with the release version and date
   (`YYYY-MM-DD`). Include any compatibility changes and required upgrade steps.
   Keep an `Unreleased` section and update its comparison link to start at the new
   tag. Run `python3 scripts/release.py check v0.1.3` and `make release-packaging-test`,
   review the changes, and land the version and changelog through the normal branch
   process. GitHub's generated PR list complements the curated changelog; future
   release pages link to the changelog at their tag.
3. On the reviewed release commit, create and push an annotated tag:

   ```sh
   git tag -a v0.1.3 -m "Ouroboros 0.1.3"
   git push origin v0.1.3
   ```

4. Watch the **Release** workflow. It validates the tag/version/branch, runs the existing
   CI at the tag, builds on all four native machines and smoke-tests each packaged binary.
   Only when every job passes does it create a draft, upload all six assets and publish
   it with generated notes. A missing target blocks the whole release.

Prereleases never become latest. A stable backport older than an already published stable
version also leaves latest unchanged. Older assets remain directly downloadable by tag;
the seven-day Actions artifact retention does not apply to published release assets.

No custom tokens, signing secrets or external hosting are required. The repository is
public; standard native runners are used. Build jobs have read-only repository permissions;
only the publication job receives `contents: write`. New release actions are pinned to
commit SHAs and covered by the existing Dependabot configuration. Toolchain versions
match CI (Elixir 1.20, OTP 29, Rust 1.95); keep the two workflow version blocks in sync.

The native build job sets `OUROBOROS_SELF_UPDATE=1` while building the embedded
binary. Normal `cargo build` and `make ouro` leave self-update disabled. This marker
is a distribution policy, not a signature. The release workflow passes
`--require-self-update` to `scripts/release-smoke.py` to reject a packaged binary
that omitted the marker. Each release also runs the updater's real replacement
transaction against a copied packaged artifact and checks the older runtime
helper/shutdown contract before publication.

As a one-time repository hardening step, enable **immutable releases** in GitHub's
release settings. Draft-first publication is compatible with that setting:
[GitHub's immutable release guidance](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
The workflow itself already refuses to overwrite a published release.

## Retry or diagnose

If a build fails, no release is published. Re-run failed jobs for a transient failure.
If a code correction is needed, commit it and use a new tag. To rerun an existing tag
explicitly: `gh workflow run release.yml --ref v0.1.3` (the workflow must also be known
on the default branch). Dispatching a branch is refused.

A publication failure can leave an unpublished draft. Rerunning the publication job
resumes that draft, replaces its expected uploads and checks its full asset list before
publishing. An unexpected extra draft asset must be removed before retrying. A published
release is never modified by a retry. Keep release cuts sequential: GitHub concurrency
keeps one running and one pending publication job.

Local packaging checks:

```sh
make release-packaging-test
make ouro
python3 scripts/release-smoke.py tui/target/release/ouro 0.1.3 aarch64-apple-darwin
```

Use the actual native target in the last command. The smoke does no model work and needs
no account. Its default mode accepts local builds with self-update disabled, while
still requiring `update --check` to work without creating files.
`make release-packaging-test` also runs the smoke-harness policy and cleanup regressions
with CLI doubles; these are separate from native packaged-binary qualification.

To reproduce the official build policy and old-runtime compatibility checks locally:

```sh
OUROBOROS_SELF_UPDATE=1 make ouro
python3 scripts/release-smoke.py tui/target/release/ouro 0.1.3 aarch64-apple-darwin --require-self-update
python3 scripts/update-smoke.py tui/target/release/ouro 0.1.3 aarch64-apple-darwin
```

Use the candidate's actual version and native target. The update smoke downloads and
checksum-verifies published 0.1.2, so that command needs network access. Both scripts
use disposable installations and profiles. After attempting a daemon start, they
require authenticated shutdown acceptance and confirmation that the runtime stopped
before deleting the profile. Missing `gateway.json`, a failed stop, or an incomplete
shutdown response cannot establish that the runtime is gone: the check fails and
retains its directory for inspection. All other failed smoke runs also retain state.

Production builds use fresh hosted checkouts; untracked local `dist/` files and
development caches are never release inputs.
