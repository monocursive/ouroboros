# `ouro update`

Status: implemented; first release version is 0.1.3.
Date: 2026-09-13.
Baseline: `bcfc3ea5`, published version 0.1.2.

Implementation: `tui/src/update.rs`, `tui/src/update/{transport,install}.rs`, and
the early CLI dispatch. The installer remains the bootstrap path. Official builds
opt in through `OUROBOROS_SELF_UPDATE=1`; this flag has no effect at runtime.

Local qualification on Apple Silicon macOS passed with the actual packaged
candidate: verified replacement, published 0.1.2's process-identity and recovery-lock
helpers, continued old-runtime access, authenticated shutdown, and recovery of an
empty durable session after restart. This uses published 0.1.2 and the working
candidate, which still carries version 0.1.2; no new release tag was created.
The first upward version transition is also covered by deterministic update fixtures.
`scripts/update-smoke.py` and the packaged replacement test now gate all four native
release builds. Their Linux and Intel runner results require the release workflow;
local macOS evidence does not establish those results.

Validation on this branch: 1,551 Rust tests passed without `embed`, 1,568 with
`embed`, and fmt/clippy passed for both configurations. The updater's 15 unit and
4 CLI tests were also exercised directly, including a corrected concurrent
temporary-directory fixture. Installer tests (17), release tests (14), and the
five packaging recipe cases passed. The native package smoke additionally checks
that its read-only update check creates no files. Official release jobs pass
`--require-self-update` to require the build marker; the default smoke mode accepts
ordinary local embedded builds with self-update disabled.

Review corrections: both native smoke scripts require authenticated shutdown
acceptance and a confirmed stopped process before cleaning up an attempted runtime's
profile. Missing gateway publication is not shutdown evidence. The regression harness
in `scripts/test-release-smoke.py` covers retained state after missing publication,
startup/stop failures and incomplete shutdown responses, plus local versus official
build policy. It runs in CI and `make release-packaging-test`; CLI doubles exercise
the harness decisions, while the native smoke scripts provide runtime evidence.
After these corrections, all seven regression tests and the full packaging test
target passed. Apple Silicon native smoke passed for both a local embedded build
with self-update disabled and an official-policy build with it enabled; the
published 0.1.2 to working-candidate runtime compatibility smoke also passed again.

## Outcome

A user with a standalone release binary runs `ouro update` to install the latest
stable release at the same executable path. The command reports what changed and
how to activate the new runtime. It works without a checkout, model account, or
running BEAM runtime.

The first version has two commands:

```sh
ouro update          # Install a newer stable release, if available.
ouro update --check  # Report availability without downloading the binary or writing files.
```

Calling `update` authorizes replacing this executable; there is no extra prompt.
Progress is plain text on stderr and the result is on stdout, usable without a TTY.

## Behavior

| Situation | Result |
| --- | --- |
| A newer stable version exists | Download, verify, and atomically replace this executable. |
| Installed version equals latest | Report already current; skip the binary download. |
| Installed version is newer than latest | Report ahead of stable; never downgrade automatically. |
| A prerelease is installed | Use semantic version ordering; promote to the corresponding stable version when available, never go backwards. |
| `--check` finds a newer version | Print installed/latest versions and the update command; write nothing. |
| Network, validation, or replacement fails before commit | Report the failed step; leave the existing executable intact. |
| An update is already in progress for this path | Fail promptly with a retry instruction. |
| Destination is unsupported or not writable | Explain the path and reason; never invoke sudo or install a second copy elsewhere. |

Exit codes: `0` for an installed update, already-current/ahead result, or a check
finding no update; `10` for `--check` finding an update; `1` for an operational
failure; clap retains `2` for invalid arguments. Model update results explicitly
and map them at the CLI boundary, independently of `ouro run`'s exit type.

Example output (versions illustrative):

```text
Updated ouro 0.1.3 -> 0.1.4
Executable: /Users/example/.local/bin/ouro
If a runtime is running, finish active work, run `ouro stop`, then start `ouro` again.
```

The restart sentence is conditional guidance, not a claim that runtime state was
inspected. Do not print that a runtime was upgraded merely because a file changed.

## Scope and installation identity

Support the four existing release targets: Apple Silicon and Intel macOS, and
ARM64 and x86-64 GNU/Linux. Match installer eligibility, including glibc 2.39+,
the macOS 15 baseline, and native ARM selection under Rosetta.

Resolve the executable through the OS, resolve its canonical destination, and
display that destination before downloading. Never select a destination from
`which ouro` or assume `~/.local/bin`. Preserve a caller's symlink alias and replace
only its validated regular-file target. A versioned filename remains that filename.
Validate ownership, file type, parent directory, permissions, and file identity;
reject elevated/set-ID execution and ambiguous or changed destinations.

Embed an explicit self-update eligibility flag in official release builds, set by
the release workflow. Ordinary `cargo build` and `make ouro` builds default to
ineligible, so development artifacts are not overwritten with public releases.
Reject mutation with `--dev`; read-only checks can compare a local build's package
version but must label it as a local build, not an installed official artifact.
The eligibility flag is a distribution policy marker, not cryptographic provenance.

Package-manager integration is outside v1. Refuse recognized managed stores such
as Homebrew Cellar and Nix store destinations, and provide installer/build guidance
for ineligible builds. Do not claim that path inspection detects every possible
third-party package manager. User-owned symlink aliases to standalone artifacts
remain supported.

Explicit versions, downgrades, repair/reinstall, automatic rollback, prerelease
channels, background checks, automatic restart, and fleet-wide upgrades remain
separate work. The existing installer retains its `--version` path. Updating one
machine does not update its peers; fleet users still coordinate runtime versions.

## Release discovery and download

Implement the updater in Rust using the existing published assets. Do not download
and execute an installer script. Keep `install.sh` as the bootstrap/manual path;
share release-format test cases so its rules and the updater cannot silently diverge.

1. Resolve the official repository's `/releases/latest` redirect exactly once.
   Require the final URL to name that repository's `/releases/tag/vX.Y.Z` with the
   existing stable-tag grammar. Compare with a direct `semver` dependency, already
   present transitively in the lockfile. Malformed tags fail explicitly.
2. Freeze that tag for both downloads. The binary name remains
   `ouro-{version}-{target}`; its checksum comes from the same tag's `SHA256SUMS`.
   Missing stable releases or missing target assets are errors, with no fallback
   to a different version, architecture, mirror, or prerelease.
3. Use `curl` through a structured process argument list, consistent with current
   installer prerequisites. Disable automatic curl config loading with `--disable`
   as the first argument. Require HTTPS for requests and redirects, retain TLS
   verification, bound redirects and timeouts, and send no GitHub/model credentials.
   Preserve ordinary proxy support. A missing curl produces a clear prerequisite
   error. This avoids adding an HTTP/TLS dependency stack solely for updating.
4. Bound captured output and stream binary bytes into staging while hashing with
   the already-used `ring` SHA-256 implementation. Initial limits: 64 KiB for the
   checksum manifest, 1 GiB for a binary, 15 seconds to connect, 10 minutes per
   download attempt, and at most three attempts. Reset staging and digest state
   between attempts; cancel and reap children on timeout or Ctrl-C.
5. Require exactly one manifest entry for the expected filename and a valid SHA-256
   value. Reject duplicates, missing entries, malformed data, truncated downloads,
   oversized responses, and digest mismatches. Download redirects may use GitHub's
   HTTPS asset delivery hosts; the release tag must stay pinned.

`--check` performs release discovery and comparison only. It does not need a writable
installation, create an update lock, fetch a binary, discover runtime paths, load
model credentials, or start a runtime.

The trust model remains official GitHub releases over HTTPS plus SHA-256 integrity
checks. Checksums are not independent publisher signatures. Signing/key rotation
would require a separate release-distribution design.

## Replacement transaction

1. For an available update, acquire a crash-releasing advisory lock on a permanent
   sibling lock file scoped to the canonical executable path. Use a no-follow,
   ownership-checked file open. A loser fails promptly; never unlink the lock inode.
2. Revalidate the destination after taking the lock and again before commit. A
   process whose executable was replaced while it waited must not overwrite the
   newer installation. Track the destination descriptor's identity and content as
   needed; do not treat the running process's package version as the current file's
   version after a concurrent replacement.
3. Create a private, randomly named staging file in the destination directory with
   exclusive creation. Stream and verify the download, set executable permissions,
   and flush the completed file. Do not truncate or modify the current executable.
4. After checksum verification, run the staged executable's `--version` with a
   short timeout and bounded output. Require the selected version. This catches
   wrong architecture, loader failures, and incorrectly labelled assets before
   replacement without booting a runtime. Embedded-version parity remains a release
   packaging gate.
5. Rename the staged file over the validated destination on the same filesystem,
   then synchronize the parent directory where supported. Rename is the commit
   point. A post-commit durability/reporting failure must say the new file is
   installed, rather than falsely promising that nothing changed or rolling back
   over someone else's update.
6. Clean up owned staging files on handled failures and interruption, then release
   the advisory lock. A hard kill may leave a staging file; never sweep arbitrary
   siblings as cleanup. Retained runtime extraction caches are not update debris.

The advisory lock coordinates `ouro update` processes. The existing shell installer
and arbitrary external file writers do not participate; concurrent manual installs
are unsupported. Validate identity to catch observed changes, but do not claim
that an advisory lock prevents uncooperative writers or makes hostile writable
directories safe.

## Running runtime contract

Dispatch `update` before `Paths::discover`, preference loading, or UI setup in
`main.rs`, while preserving argument validation such as rejecting `--continue`
with a subcommand. Updating must remain usable when runtime configuration is broken.

The command replaces the file on disk and does not stop, restart, signal, or migrate
any runtime. Existing terminal processes and BEAM code stay at their current version.
Use the existing `ouro stop` command when the user chooses to restart; preserve its
authenticated shutdown behavior. Configuration, sessions, credentials, data
directories, and extracted runtime releases are not modified by updating.

There is one essential compatibility gate: BEAM receives the installed executable
path through `OUROBOROS_PROCESS_ID_HELPER`. An older runtime can invoke the new
binary's `process-birth` and `hold-runtime-recovery-lock` commands after replacement.
Keep their command/output and lock contracts backward compatible and test that
scenario with an actual older release. Also verify that the new client's `ouro stop`
can shut down that runtime. If either contract breaks, live binary replacement is
not qualified for that release; resolve the compatibility issue before shipping.
Leaving already-loaded BEAM code untouched is insufficient evidence by itself.

## Implementation sequence

1. **CLI and pure release rules.** Add `UpdateArgs` in `tui/src/cli.rs`, early dispatch
   in `tui/src/main.rs`, and `tui/src/update.rs` exported from `lib.rs`. Define typed
   outcomes, semantic comparison, asset selection, checksums, and eligibility.
   Wire build metadata through `tui/build.rs` and `.github/workflows/release.yml`.
2. **Read-only check and transport.** Add bounded curl execution and implement
   `--check`, with deterministic fixtures for redirects, versions, and failures.
   Keep test injection internal; ship no environment variable that changes the
   trusted repository or disables verification.
3. **Transactional installation.** Add path validation, locking, streaming hashing,
   staging validation, atomic replacement, cleanup, and plain progress/results.
   Split `update.rs` into focused transport/install modules only if its size warrants it.
4. **Distribution and lifecycle qualification.** Add integration tests and native
   package smoke coverage; update `README.md`, `docs/RELEASING.md`, and generated
   release notes in `scripts/publish-release.sh` with the new upgrade path.

## Validation and acceptance

- Unit tests cover semantic ordering including prereleases, strict stable tags,
  target selection including Rosetta, and exact checksum-entry matching.
- CLI integration tests exercise `--check` and updates in a temporary installation:
  writable custom paths, spaces/non-ASCII names, symlink aliases, versioned filenames,
  local-build refusal, permission failures, and invalid flag combinations.
- Failure tests cover unavailable releases, hostile redirects, HTTP/TLS/timeouts,
  missing/oversized/corrupted artifacts, disk-write failure, candidate startup failure,
  concurrent updaters, changed destinations, failed rename, post-commit sync failure,
  cancellation, and lock recovery after process death. Assert old bytes and mode
  survive pre-commit failures; assert accurate reporting after commit.
- Prove `--check` writes nothing and updater invocation never starts a daemon or
  modifies data/config/cache. Test with missing and malformed runtime configuration.
- Add shared installer/updater fixtures for accepted tags, asset names, checksums,
  and target eligibility; retain `scripts/test-install.py` coverage.
- Run focused updater tests first, then Rust fmt/clippy/tests with and without
  `embed`, plus `make release-packaging-test`. The regular CI remains the release gate.
- Extend native release smoke on all four existing runners to exercise replacement
  of a copied executable and verify the resulting client/embedded version and startup.
  Use a local fixture downloader/test harness for unpublished candidates, without
  creating public tags or adding a production trust bypass. Separate release-resolution
  tests from actual candidate-byte replacement, which must exercise the real filesystem.
- Test old BEAM + newly replaced helper commands, authenticated stop, restart into
  the new embedded runtime, and durable-session recovery using disposable profiles.
  Do not claim model/fleet compatibility merely from successful local startup.

Completion means the command upgrades a standalone installation on each supported
native target, is a no-op when current, preserves the previous executable on
pre-commit failure, and reports runtime activation honestly.

## Rollout

Implement on a `codex/` branch based on `dev`, then use the existing reviewed
`dev` -> `main` release process. Do not change published tags or release assets.

Users on 0.1.2 or any older binary without `update` rerun the installer once to
acquire the first release containing this feature. Subsequent releases use
`ouro update`. Keep the installer documented for initial installs and recovery.

## References

- Current behavior: `install.sh`, `scripts/test-install.py`, `scripts/release.py`,
  `docs/RELEASING.md`, and `scripts/release-smoke.py`.
- Runtime helper contract: `tui/src/runtime.rs` and `lib/ouroboros/runtime_owner.ex`.
- [Rust executable-path semantics](https://doc.rust-lang.org/std/env/fn.current_exe.html):
  symlink and renamed-executable behavior differs by platform; path discovery alone
  is not sufficient validation.
- [Rust rename semantics](https://doc.rust-lang.org/std/fs/fn.rename.html): stage on
  the destination filesystem because cross-filesystem rename is unsupported.
- [curl command documentation](https://curl.se/docs/manpage.html): configuration,
  HTTPS redirect restrictions, timeouts, and subprocess download behavior.
