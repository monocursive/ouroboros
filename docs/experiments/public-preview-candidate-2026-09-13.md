# Public preview candidate — 13 September 2026

There is now a local macOS Apple Silicon executable built from the complete committed
source at `8dd05e17f0c2f8fb253353dbfa9d297cd206821c`, version `0.1.0`. It is reviewable,
but the four-platform public developer preview is **not ready to publish**. Current
authenticated coding journeys and the remaining platform evidence are still missing.
Nothing was pushed, published, signed for distribution, or promoted to the protected
running host. The former native self-development loop remains stopped.

## Artifact identity

The retained local bundle is
`tmp/roadmap-implementation-20260911/public-preview-integration-turn52-01/root-release/candidate-8dd05e17/`.
It includes `ouro`, the embedded Mix tarball, the complete source archive,
`candidate.json`, a per-file source manifest and verified `SHA256SUMS`.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| macOS ARM64 `ouro` | 32,205,008 | `feff17b5718e1bf7584479e71a58df6f9bbf8cc80e33cf3f192b78a2a9e13356` |
| Embedded `ouroboros-0.1.0.tar.gz` | 23,333,851 | `0968bb94a34c039a320e494846d155ba7dce79a34a6448741b9bc6ee9abd8d60` |
| Complete source archive | 6,003,322 | `c5c57b04583c3005df8102a97293fb5cc5e8dd94dd66feaec2d31b4248736301` |

The executable is the deployment entry point. The Mix tarball is its intermediate
payload. No old `dist/` binary is substituted for this candidate. The source archive
contains all 1,147 tracked files, with content and executable modes verified against
Git; untracked logs, credentials, runtime state and caches are excluded.

The canonical `make ouro` recipe ran in a private Git checkout with fresh production
and release output, private cached locked dependencies, and offline Cargo/Hex access.
The cache correction was subsequently rebuilt through the same recipe. Source and
dependency locks remained unchanged. The recorded toolchain is Rust 1.95.0,
Elixir 1.20.2, OTP 29.0.2 / ERTS 17.0.2, Apple clang 21.0.0 and macOS 26.6.2.
This records a build recipe and exact artifacts; bit-identical independent rebuilds
and compatibility with earlier macOS versions have not been established.

## Additional correction and review

Packaging review found that extraction caches used only eight digest characters and
accepted release-shaped directories without a completed extraction identity. Commit
`8dd05e17` uses the entire digest and a version/digest completion marker published
atomically with the extracted directory. Warm reuse stays a quick lookup; it does
not hash the complete payload or detect later payload tampering.

The adversarial review also found a delayed invalid-cache observer could delete a
concurrent extractor's completed result, and that regular files or dangling symlinks
could permanently prevent repair. Cold extraction now holds a permanent cache-local
lock through revalidation, repair and publication, with a 30-second acquisition bound.
Invalid file/link entries are removed without following their targets. Both reviewers
finished the bounded source review; this does not clear earlier provider-policy reviews.

All 17 extraction regressions passed, including prefix collisions, missing or mismatched
markers, concurrent repair, occupied entries, lock contention and rename winners.
Release-profile Clippy passed for all targets with `embed`, warnings denied. Formatting
passed. The complete constituent source gates at baseline `a853f707` remain documented
in the [implementation record](self-development-wrap-up-2026-09-12.md); they were not
repeated or relabeled as a complete suite run after this isolated Rust correction.

## Installed checks

The exact candidate passed a fresh private HOME/XDG/data installation with a system-only
runtime PATH. It joined no BEAM cluster and used no model or copied credential.

- The full embedded tarball occurs in the executable. All 2,890 extracted payload files
  match their archive contents. The packaged Phoenix/LiveView assets match the dependencies.
- All 25 native executables/libraries are ARM64. Their actual load dependencies use
  macOS system libraries, with no unresolved `@rpath` or Homebrew/toolchain dependencies.
  The Exqlite NIF's build-host install ID is metadata, not a runtime load dependency.
- The bundled Wasmtime 48.0.1 helper reported usable for `aarch64-apple-darwin`.
- The actual terminal rendered, then restored the terminal and exited through Ctrl-Q
  and its disconnect confirmation. This is startup/lifecycle evidence, not visual UX review.
- The browser front door refused an unauthenticated request with HTTP 401.
- Both private runtime incarnations accepted authenticated shutdown and their exits
  were observed. Warm-cache restart produced a new process-birth identity.
- The packaged `Tools.Bash` passed read-only and workspace-write checks plus five
  protected-file controls under Seatbelt, with normal-JIT OTP and distribution disabled.

Receipts and logs are retained in `root-release/` beside the bundle. Failed attempts
are preserved: an existing test tar header added a trailing NUL until its declared
size was corrected; an initial runner invocation used the wrong relative path; and
the first PTY smoke omitted the quit dialog confirmation. That failed smoke's runtime
was explicitly stopped. The corrected smoke used another fresh environment and passed.

## Remaining release requirements

The exact binary still needs ordinary ChatGPT/Astra-xhigh sign-in, a real repository
read/edit/check task with reviewable approvals, retained-session recovery and an
authenticated browser journey. Earlier successful model work belongs to older artifacts.
An empty runtime restart is not durable task-recovery proof.

Linux ARM64 and x86-64 need current-source binaries and their complete installed
journeys; historical Bubblewrap/AppArmor evidence is retained but does not certify
this source. macOS Intel remains in scope without a host or executed hosted workflow.
No unanswered request to push an earlier revision authorizes uploading this candidate.

Existing provider-policy blocks and incomplete reviews remain open. Epoch schema 2
requires a pre-migration backup for downgrade, retains lifetime write identities on
disk, and validates its reachable archive at startup. Newer output beyond a terminal
durable checkpoint still requires explicit reconciliation. These boundaries and the
intentional Fable prompt/loop contribution remain unchanged by the packaging correction.
