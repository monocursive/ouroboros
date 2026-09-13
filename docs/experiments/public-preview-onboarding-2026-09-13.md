# Public preview onboarding follow-up — 13 September 2026

Local macOS ARM64 candidate `bc3a24ad80dc69255f48e1a4465af21918cbdc3c` contains the
onboarding and account-recovery corrections below. The four-platform public developer
preview remains incomplete. No source or binary was pushed, published or promoted to
the protected runtime. The native self-development benchmark remains stopped, and the
intentional Fable prompt and loop work is retained.

## Findings and structural corrections

| Finding | Correction |
| --- | --- |
| Recommended ChatGPT models omitted the sign-in card because the form intentionally sends no model override. An installed browser exposed the mismatch. | Readiness uses the effective runtime model while the request and saved preferences preserve the omitted override. |
| A blank or whitespace Custom value also omits the model, allowing the same default-model gate to be bypassed. | Every omitted model payload resolves the known runtime default for readiness. Explicit API models and unknown defaults retain their existing behavior. |
| A direct submit could bypass the disabled button and create a session without local ChatGPT readiness. | A shared server-side check precedes session creation and initial-message sending, including idempotent retries. Missing or unavailable local metadata refuses the request. This does not verify provider acceptance or model access. |
| A late account observation could mark credentials unavailable after a start was pinned. The retry guard then refused while the locked form prevented reconnecting or refreshing. | Connect, Cancel and account-only refresh remain available outside the disabled task fieldset. The computer, model, project, initial message and request identity remain pinned. |
| Two first-use test modules relied on a restrictive inherited umask for ExUnit-created directories. | The fixtures set their own temporary directories to mode `0700` before production validation. Production still refuses pre-existing unsafe data directories. |

The common issue was conflating operator intent with effective runtime behavior, and
conflating immutable task parameters with mutable account recovery. The correction
keeps those responsibilities separate within the existing form and account components.
Adversarial review identified the blank-Custom bypass and pinned-recovery trap; its
final bounded review found no remaining actionable issue in this patch. This does not
clear earlier provider-policy blocks or incomplete reviews.

The broader admission, durable identity, retry, delivery and readiness corrections are
recorded in the [implementation wrap-up](self-development-wrap-up-2026-09-12.md).

## Validation

The four affected new-session, credential-state, first-use and preference suites passed:
**121 tests**. Full Elixir compilation with warnings as errors and changed-file formatting
also passed. Regressions include forged default/blank-Custom submissions with no session
created, and both pinned-start and pinned-first-message states recovering their account
without accepting forged task changes. New-session login/recovery regressions use the
existing fake adapter; credential-state checks use synthetic private stores with the
production reader. No real provider authentication is asserted.

Failed attempts are retained: three credential-state fixtures initially refused mode
`0755` directories, formatting caught one multiline expression, and compilation caught
a redundant template condition. The corrected final checks passed. The prior complete
source suites remain attributed to their earlier revisions; they were not rerun or
relabelled as complete-suite coverage for this isolated onboarding patch.

`make ouro` passed in **88.22 seconds** in the private checkout, using its locked cached
dependencies and offline Cargo/Hex access. All **1,148 tracked files** and executable
modes matched the committed source. Toolchain: Rust 1.95.0, Elixir 1.20.2, OTP 29.0.2 /
ERTS 17.0.2, on macOS 26.6.2. This is a recorded build recipe, not an independently
demonstrated bit-identical rebuild or earlier-macOS compatibility claim.

The exact binary passed a fresh private HOME/XDG/data installation with system-only
runtime PATH, without joining a BEAM cluster or copying credentials:

- Full embedded tarball verification and all **2,890** extracted files matched.
- All **25** native executables/libraries were ARM64 with only system load dependencies.
- The bundled Wasmtime 48.0.1 helper was usable for `aarch64-apple-darwin`.
- The terminal rendered and exited through Ctrl-Q and its disconnect confirmation.
- Unauthenticated web access returned HTTP 401. Warm restart produced a new process
  birth; both installed-smoke runtime incarnations accepted shutdown and exited.
- Actual packaged shell read-only/workspace-write checks and five protected-file
  Seatbelt controls passed under normal-JIT OTP.
- A separate fresh installed browser preserved the CLI workspace and displayed the
  required ChatGPT connection immediately. Empty and whitespace Custom stayed gated;
  an explicit API model did not require ChatGPT. Its browser closed and its owned
  runtime accepted authenticated shutdown and exited. No model turn was submitted.

## Artifact identity

The retained local bundle is
`tmp/roadmap-implementation-20260911/public-preview-integration-turn52-01/root-journey/candidate-bc3a24ad/`.
It contains the executable, embedded tarball, complete Git source archive, manifests,
this release record and `SHA256SUMS`. The earlier `8dd05e17` bundle is preserved separately.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| macOS ARM64 `ouro` | 32,205,008 | `12c965990ff6226585b27244fd03c9eae009c8559f7902f7c5c3da4a36c48a3a` |
| Embedded `ouroboros-0.1.0.tar.gz` | 23,335,051 | `dc1c6afb4d0eebab0ae5ff7c901c6b13c8e8b5f3729c9f7a636d07e18249be62` |
| Complete source archive | 6,007,754 | `c7afbbb860156990d6b8f0152a1c130cb290b7247bcf1c698fc4e75cb0b2c9c7` |

The helper SHA256 is `3b8d57b69f5c4af1e82515b847d5efe71f249fb9ab2ba39918c6a383641edd1c`.
Later documentation commits do not change the binary's source identity. Receipts,
failed attempts, screenshot and resource measurements are retained under `root-journey/`.

## Remaining release prerequisites

An ordinary device-login flow was opened on the preceding `8dd05e17` candidate; it
remained Waiting for the bounded interaction window. Its login was cancelled, private
browser closed, and owned runtime shutdown and exit verified. No authenticated model
task ran. The current candidate still needs actual ChatGPT/Astra-xhigh sign-in, useful
read/edit/check work, reviewable approvals and retained-task recovery. Startup or an
empty restart does not establish those journeys.

Linux ARM and x86 need current-source builds and installed journeys. Five retained
public inputs were rehashed against their saved manifests. The known historical x86
guest alone occupied 3.78 GiB, exceeding what can be admitted alongside current
artifacts under the existing 4 GiB aggregate private allocation. A bounded increase is
awaiting the operator's decision; no replacement guest, download or installation was
launched in this follow-up. Historical AppArmor/Bubblewrap evidence remains distinct
from current-source qualification.

No Intel Mac is available. The opt-in hosted check has not run. The unanswered request
to push `8dd05e17` does not authorize pushing this newer candidate. Existing review
blocks and the schema-2 migration, lifetime identity retention and explicit terminal
delivery reconciliation limits remain as recorded in the implementation wrap-up.
