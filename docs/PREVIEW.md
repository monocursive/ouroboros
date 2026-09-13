# Developer preview: source build and first use

**Candidate preparation, not a published release or a supported binary download.**
Ouroboros is an experimental runtime for coding work: durable BEAM sessions and
recorded effects, native subagents with worktree ownership, OS-sandboxed shell and
WebAssembly authority, and model-authored improvements under evidence and human
signing, merge and promotion. A successful coding turn is not proof of autonomous
self-improvement or safe unattended operation.

## Platform and delivery contract

Build `ouro` on the OS and architecture that will run it. It embeds BEAM/ERTS and
the WebAssembly helper; the intermediate Mix tarball alone is not the supported
deployment unit. [Tag-based releases and a Bash installer](RELEASING.md) are now prepared;
the first hosted binary release has not been published. There is no automatic runtime
updater or package-manager release. Do not use old `dist/` files as current release artifacts.

| Target | Current evidence, not a compatibility promise |
|---|---|
| macOS Apple Silicon | Candidate `bc3a24ad` has a committed-source build, verified embedded/extracted payloads, system-only native library dependencies, terminal startup, unauthenticated web refusal, owned restart/shutdown, packaged Seatbelt controls and fresh-browser model connection checks on macOS 26.6.2. Standard ChatGPT sign-in and Astra/xhigh read/edit/check/resume were demonstrated on older artifacts; those journeys have not been repeated on this candidate. |
| Linux x86-64 GNU | Frozen `82a4c2dd` selected-source build passed in a full-system Ubuntu 24.04.5 x86-64 guest with normal-JIT OTP 29; install, PTY, web 401 and stop passed. A later TCG guest reused that binary, executed the corrected public AppArmor setup/rollback blocks and passed actual packaged shell controls; rollback restored stock/product refusal and actual guest exit was recorded. Full model-backed task/auth/recovery/browser qualification remains open. |
| Linux AArch64 GNU | Older selected-source build and container/HVF install, PTY, web 401 and stop passed; initial namespace probes refused. Later Ubuntu 24.04.5 ARM64 HVF guests proved the opt-in distro AppArmor correction and an ordinary ChatGPT-authenticated browser read/edit/check task with bwrap and once approvals. Useful work survived an owned idle restart; replay is bounded by the original failed inference. These are older-artifact observations, not an exact-current-source build/journey. |
| macOS Intel | No current dedicated build/install evidence. An [opt-in hosted Intel build/smoke workflow](INTEL_MACOS.md) is prepared locally but has not run; ordinary authenticated task/recovery/browser evidence is also missing. Not yet qualified as a preview target. |

macOS and Linux are the implemented OS families. No minimum macOS version, glibc
floor or general Linux distribution range has yet been qualified. Windows, WSL,
musl and other targets are not established support. Accessing the local web UI
from a browser does not establish runtime support for that browser's device.
Before a public candidate claims any target, its release record must contain the
per-target checks below. Missing checks must not be labeled passed.

The four targets above are the qualification scope of this source preview, not
four completed support certifications. macOS Intel remains in that scope with no
dedicated evidence; it is not silently dropped. The goal of a useful preview across
these targets is **not complete** merely because installation front doors work.

### Candidate notes (2026-09-13, after implementation wrap-up)

Version **0.1.0**, binary candidate **`bc3a24ad80dc69255f48e1a4465af21918cbdc3c`** on
`codex/self-improvements`, superseding binary candidate `8dd05e17f0c2f8fb253353dbfa9d297cd206821c`.
This integrates admission/recovery and pending-delivery fixes, private test authorities,
EPMD readiness corrections, and durable lifetime write identities with stricter retry
checks. Extracted releases now use the complete artifact digest and a completion marker;
concurrent cache repairs recheck under a bounded lock. The intentional Fable prompt/cache
work is retained. See the
[implementation and validation record](experiments/self-development-wrap-up-2026-09-12.md).
The [current candidate and onboarding record](experiments/public-preview-onboarding-2026-09-13.md)
identifies the exact source, binary, embedded tarball and installed checks. The
[earlier candidate record](experiments/public-preview-candidate-2026-09-13.md) retains
the extraction-cache findings and its separate artifact identities. Later documentation
commits do not change the binary's source identity. This remains a local candidate;
its commits, source archive and binaries have not been published.

Recommended ChatGPT models and blank Custom input now show the same connection
requirement as an explicit subscription model. The submit handler also checks local
credential readiness, while an omitted model remains omitted from the request and
saved preferences. During an uncertain start or failed first message, ChatGPT connection
recovery remains available on the pinned computer without changing the original task.

**Data-format boundary:** starting this code migrates an existing maintenance epoch to
schema 2. Older builds refuse that format, so retain an independent pre-upgrade data
copy before testing an existing installation. The epoch keeps bounded resident history
and archives finalized identities on disk; it never forgets old write IDs to make room.
Disk usage grows with lifetime writes, and startup checks the reachable archive. The
fresh macOS installation smoke passed; upgrade and authenticated work journeys on
this candidate remain open.

Build from a fresh checkout at the recorded candidate revision using the
[source recipe below](#obtain-and-build) and its checked-in dependency locks.
The source boundary is that revision's complete Git tracked tree, not a tar of a
developer's working directory. A source archive must identify its commit, member
paths/modes and digest separately; it excludes untracked runtime state, private
reports and caches. Optional Git/worktree benchmarks need a Git checkout, not just
an extracted archive. A source recipe is not a byte-reproducible binary guarantee.

**What works in the captured macOS journey:** ordinary ChatGPT sign-in, native
Astra/xhigh read/edit/check work on a real small repository, an honest missing-
approver denial followed by one exact approval, five recipe checks under Seatbelt,
and retained work after an owned restart and model resume. This is separate from
the clean-source build, not an exact-current-HEAD installation journey or evidence
for every model. Terminal and local-browser entry points remain part of the preview.

Local integrated source checkpoint `588dca58` was reconstructed from Git and built
on macOS arm64. The earlier macOS first-use binary was built from an explicit
448-file working-tree snapshot, not that commit: only README wording differs among
those selected inputs. Its two live task turns verified before restart; after
restart replay reports a `resumed_conversation` boundary. A successful new model
resume is not deterministic verification beyond that boundary.

The Linux ARM64 build used 869 selected working-tree inputs at `d0122723`, digest
`9e89a8766f2520fa00d72c79bbcdad19c3c9cde0f5de6b0d76ae38068532994f`.
Of those inputs, 868 matched `588dca58`; only this guide changed. This comparison
does not prove new-input completeness or relabel the build as that commit. The
produced binary SHA-256 is
`4841e6fbed1e1feda4abf625b4dc1d0cfc08d315793d40ad8de7637a80d91986`.
The later ARM64 HVF guest reused exactly that binary; it did not compile source.

The x86-64 full-system build used **863 selected files** from
`82a4c2ddaf04be29ae9db08f8cc08e507d43a01b`, selected manifest SHA-256
`1e9d2bb23e99fae964d9c41819e656f93c59fd0af313ac01f1e2c7874678598c`.
`make ouro` passed in **47m39.828s** with Elixir/Mix 1.20.2, OTP 29 / ERTS 17.0.5
(normal JIT) and Rust 1.95.0. The retained binary SHA-256 is
`d8dc487cd6676af167921a7731f1783d1f3e71b5d842ac26c7948ad3dbf1d47c`.
Its installed-copy and exported-artifact hashes matched. Both full-system guests
ran Ubuntu 24.04.5, Linux 6.8.0-139 and glibc 2.39, but only those guest ABIs were
exercised. The x86 install used a clean runtime PATH in the build guest, not a
separate clean OS image. Neither selected-source set proves full candidate input
completeness. Earlier user-space AMD64 OTP failures remain separate failed attempts,
not the outcome of the successful full-system build.

**Historical Linux refusal:** each initial full-system guest ran one stock
`bwrap --ro-bind / / --unshare-net --dev /dev --proc /proc -- /bin/true` probe and got
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. No bypass or retry
followed in those runs. The exact denying policy was not isolated then; the x86
diagnostic additionally could not find `sysctl` on its restricted PATH.

**Subsequent bounded correction:** new Ubuntu 24.04.5 ARM64 HVF and x86-64 TCG
guests independently matched the
refusal to AppArmor's `unprivileged_userns` transition and `setpcap`/`net_admin`
denials. Administrator-authorized activation of the exact Ubuntu experimental
`bwrap-userns-restrict` profile restored the stock probe and actual packaged
`Tools.Bash` execution using the respective older binaries above, without a source change
or rebuild. Read-only/outside/pre-existing protected-file writes, network isolation
with a positive control, zero child CapPrm/CapEff/CapBnd sets and `NoNewPrivs: 1`,
nested-child and unrelated-unprivileged-userns denials were checked on both.
Global AppArmor userns restriction stayed `1`; removing only the profile restored
the original stock refusal. The x86 run also reconfirmed actual product refusal
after rollback. Both guests exited normally. The x86 run executed the corrected
public acquisition, activation and rollback blocks unchanged, separately from the
no-model product harnesses; it did not execute the interactive examples.
This is a deployment-policy correction, not proof of an
implementation defect or general production support: the distro profile is opt-in,
experimental/unsupported and disabled by default. See the
[preflight, administrator setup, verification and rollback recipe](LINUX_BUBBLEWRAP.md).

**Subsequent ARM64 useful task:** a separate bounded Ubuntu HVF guest installed the
same older `4841e6fb…` binary and used the approved AppArmor profile. Normal ChatGPT
sign-in and authenticated browser use succeeded. Its native Astra/xhigh candidate
worked on the complete 1,126-file source tree at `826aeb0e`, not the executable's
build inputs. It authored only five added Makefile lines and eleven CONTRIBUTING
lines to expose the existing check as `make release-packaging-test`, with help and
prerequisites. The candidate ran the original script before editing and the new
target afterward: each reported five recipe cases passed, exit 0. Help, exact diff,
whitespace and final scope checks passed through actual bwrap shell calls with
`workspace_write`, prompt mode and nine once approvals. The existing script, full
`make test` gate and product-build recipes were not changed; producer-stub recipe
checks are not real binary builds. Independent native packaging review found no
necessary correction. Native main adopted the exact resulting file bytes in
`7cc87827` and separately passed the focused target, help and whitespace locally.
The installed candidate authored/tested; the Codex supervisor inspected/approved
exact actions through the normal browser under user authority, rather than editing
source or replacing candidate tests. The runtime's browser actor label is not proof
that those clicks were made directly by a human.

The initial browser task failed in about **26 ms with zero tools**, reporting generic
`model_error`. An initial registry probe was uninitialized, not a diagnosis of that
failure; initialized lookup/options/projection checks passed. One no-tools request
through the same production adapter succeeded in **4.151 s**. A supported owned
logging restart and one normal browser Retry then reached the useful task. The
original cause remains **unresolved**, not a fixed catalogue defect or proven crash.
The successful retry took **868.170 s wall time**, including **637.923 s** between
nine approval requests and resolutions; recorded model-result durations totalled
**228.701 s**, and tool-result durations **0.755 s**. Approval/supervisor waiting is
not model latency; these spans are not a general performance benchmark.

After useful work, a supported idle stop/start retained the account, named
conversation and exact two-file diff in a new runtime incarnation. One ordinary
authenticated browser continuation completed in **16.139 s**, recalling the change
and checks with zero tools, zero approvals and no source changes. That is live
retained-work resume, not replay or a repeat test. The model's statement that no
failed/blocked command or restart was visible is scoped to its retained task view;
it does not erase the original model failure or the two externally owned restarts.

Replay before and after that recovery returned exit 0, with chain integrity through
**63/63** and **69/69** records respectively, but **zero model turns verified** in
both: `ambiguous_inference` at sequence 4 bounds execution verification at the
original failed request. Neither chain integrity nor a zero CLI exit makes
whole-history replay green, and the recovery turn was not independently verified
by replay. The owner then used the advertised guest-local `account.logout`, confirmed
account absence, and stopped the idle runtime through authenticated `ouro stop`
with observed process absence. Rollback removed only the introduced profile while
the global userns restriction remained `1`; this final cleanup did not rerun the
stock/product denial probes. The guest's actual exit 0 was recorded at
**16:02:55 UTC**, before its deadline. The SSH tunnel's terminal exit 255 after guest
shutdown is recorded separately, not described as a successful transport command.

Linux x86-64 still needs the ordinary authenticated useful-task/approval/recovery
and browser journey. The ARM task advances that evidence but does not supply an
exact-current-source binary installation or complete deterministic replay. Helper
presence is not component execution, and web 401 is not authenticated-browser
acceptance. macOS Intel still needs build/install and ordinary journey evidence;
its locally prepared workflow is not a run. Wider distribution/version ranges are
not implied, and the four-target preview objective remains open.

Current source also includes the standalone fixture SDK-path correction and audit
fixture recovery quiescence. A controlled orphan demonstrated one interference path
and the isolated fixture passed; the original unrecorded extra session remains
unattributed. Relevant selected/composed automated results are retained, not a new
uninterrupted full-suite run or whole-program acceptance.

The disk cleanup deliberately removed stopped guest disks/images, generated caches,
owned stopped containers and Linux intermediate tarballs. Small source/manifests,
failure and success receipts, and one representative binary per tested platform
remain locally; historical hashes do not mean deleted artifacts remain available.
No binary download channel is proposed. The [feedback routes](#feedback) remain
ordinary issues and private vulnerability reporting; the latter was confirmed
enabled on the canonical public repository on 2026-09-12. No report was submitted.

## Obtain and build

Use the canonical repository's source at the exact revision identified by the
maintainer's candidate notes. Until such a revision is announced, this is a
contributor build recipe, not a reproducible released candidate. Start with a
fresh checkout; retain your existing work and old build outputs elsewhere.

Prerequisites:

- Elixir 1.20, Erlang/OTP 29, Rust 1.95, `make`, Git and a native C/C++ toolchain.
- macOS: Xcode command-line tools. Linux: compiler/linker and the system development
  libraries required by OTP/native dependencies. The project's Ubuntu build recipe
  uses `build-essential`, `pkg-config`, `libssl-dev` and `libsctp1`; that is not a
  universal distribution package list.
- Network access for dependency bootstrap. Use the checked-in Mix and Cargo locks;
  do not update dependencies as part of reproducing a candidate.
- Linux shell containment needs **usable** bubblewrap mount/network namespaces,
  not merely an installed `bwrap` command. Before a long build or first use, run the
  [quick Linux preflight](LINUX_BUBBLEWRAP.md#1-check-before-building-or-starting-a-runtime).
  That guide covers the demonstrated Ubuntu policy cause and opt-in administrator
  setup/verification/rollback, not an automatic policy change. Do not turn off
  machine-wide security to make a preview check green. macOS uses Seatbelt
  (`sandbox-exec`). If the backend cannot enforce a requested posture, stop and
  report the refusal; do not silently select full access.

From the checkout root:

```sh
mix deps.get
make ouro
./tui/target/release/ouro --help
```

Install Hex/Rebar through the normal Mix prompts if requested. `make ouro` builds
the WASM helper, assembles the production runtime and embeds the tarball into
`tui/target/release/ouro`. Node is not required for production web assets; Node and
Playwright are browser-test dependencies. Multiple release tarballs are refused
rather than selecting an older version; use a fresh build checkout, not an
indiscriminate cleanup of existing work.

Run the resulting binary by absolute path from the repository you want to work
on, or copy it into a private directory already on your `PATH`. Do not copy a
binary built for another OS/architecture. Same architecture is necessary, not a
promise of compatibility with every OS or system-library version.

## Configure model access and start

Native is the only runtime provider; no vendor CLI is required.

1. Open `ouro` from a small repository you own. Check the selected workspace and
   file permissions before submitting a task; `/options` exposes advanced setup.
2. Submit a bounded task. If prompted, connect ChatGPT through the displayed
   sign-in flow; the pending task starts after sign-in. Account entitlement,
   provider availability and model access are external prerequisites, not bundled
   with Ouroboros. Choose a model available to your account; do not assume an old
   documented model name is still offered.
3. Alternatively, before starting a **new** runtime, select
   `OUROBOROS_NATIVE_MODEL=openai:<available-model>` with `OPENAI_API_KEY`,
   `anthropic:<available-model>` with `ANTHROPIC_API_KEY`, or
   `xai:<available-model>` with `XAI_API_KEY`. Anthropic/xAI keys can also be saved
   through the local web setup. Identity-linked Anthropic keys may additionally
   require `ANTHROPIC_WORKSPACE_ID`. These implemented alternatives require their
   own setup smoke before being advertised as qualified preview lanes.

Use your normal private credential mechanism. Never put keys, login codes, tokens
or browser bootstrap URLs in prompts, source files, screenshots, shell transcripts
or issue reports. Changing an environment variable does not reconfigure an
already-running daemon. A new isolated data directory does not inherit its saved
ChatGPT sign-in; authenticate it through the supported UI rather than copying
private auth files.

For the browser front door, run `ouro web` with the same environment/data directory.
It serves locally by default. Both `ouro web` and `ouro web --print` print a
credential-bearing URL; keep terminal output private. `--print` skips opening the
browser. Remote web exposure/TLS and fleet setup are separate operator work, not
part of first use.

## One useful first journey

Use a non-sensitive repository with a clean baseline and existing tests. Do not
plant a broken test merely to demonstrate a repair. Example prompt:

> Read this project's setup instructions and the commands they describe. Identify
> one concrete discrepancy that affects a new contributor, correct only that
> discrepancy, and run the smallest existing relevant check. Do not install global
> software, publish, change Git refs or access credentials. If no real discrepancy
> exists, report that rather than inventing work. Finish with the exact diff,
> checks and unresolved limitations.

Keep approvals interactive. Read a command before approving it, and deny an
unneeded action rather than giving blanket approval. Missing auth, an unavailable
backend, a failed command or an operator denial is not success: the transcript
and final report must say what did and did not run. A refusal alone is not evidence
that another action was contained. In headless `ouro run`, approval requests are
denied by default because no human can answer; avoid `--approve-all` for first use.

After the task:

- Inspect the actual diff and check results yourself. Use `/export` to retain a
  local report; review/redact it before sharing. Exports can contain repository
  text, prompts and local paths.
- Keep the session idle rather than closing/deleting it. Leave and reopen the
  client using `ouro --continue` from the same workspace, or use
  `ouro run --resume SESSION-ID "Summarize the previous result; do not edit files"`.
  Resuming is a **new model turn**, not a free replay. Check the named session
  rather than assuming the most recent one is the intended one.
- `ouro replay SESSION-ID` renders retained history; `ouro replay SESSION-ID --verify`
  checks the recorded execution. Replay does not rerun live tools or inference.
  A gap, boundary or divergence is not a verified pass. See [REPLAY.md](REPLAY.md)
  for the bounded contract.
- For a controlled restart check, use only an explicitly owned standalone test
  runtime with no active work, record its data directory and stop/start it through
  `ouro stop` / `ouro daemon` in that same environment. Never stop another user's
  runtime or infer isolation from a second directory when BEAM peers are connected.
  Reopen the retained session and inspect the diff for unwanted repeated effects.

For disposable first-use testing, use fresh `HOME`, `XDG_CONFIG_HOME`,
`XDG_DATA_HOME`, `XDG_CACHE_HOME` and an absolute `OUROBOROS_DATA_DIR`, with
`OUROBOROS_DIST=none` and no fleet profile. Start from a clean environment without
inherited cluster, Erlang or release flags; do not copy your ordinary runtime's
state. Keep that exact environment for every command, including cleanup. The
launcher may adopt a runtime in the selected data directory and headless runs may
leave it running. A connected BEAM node is **not** isolated.

## Known limitations and failure guidance

### Prioritized first-use follow-ups

The ARM journey exposed these issues in the **older installed artifact**, not yet
confirmed against current source. They are retained for bounded current-source
triage, not silently dismissed or treated as established current defects:

1. **Reviewable edit approvals:** the pending edit card and Technical details showed
   cwd/tool name, not the patch. Approval required extracting the exact tool-call
   patch from the trajectory first. Persisted paths are not a rendered edit diff.
2. **Actionable model errors:** the original generic 26 ms failure lost its useful
   cause; initialized catalogue checks and a successful retry do not diagnose it.
   Any diagnostic improvement must preserve credential/provider-output privacy.
3. **Status availability:** safe status reported credential present `false` / source
   unavailable during successful authenticated model use. Unknown/unavailable must
   not be interpreted as confirmed absence or a reason to copy credentials.
4. **Workspace default:** the browser initially selected the extracted release cache;
   the supervisor explicitly selected the source project before submitting work.
5. **Model discovery:** Astra search returned no rows, while Custom accepted the exact
   model and real work succeeded. Catalogue coverage and resolver support differ.

These follow-ups do not authorize new probes, paid retries, unrestricted fallback
or work around a blocked review scope. Recovery summaries are model views of retained
context, not independent evidence of every external restart or prior failure.

### Existing boundaries

- This is not a hardened multi-tenant service. OS shell sandboxing is not a VM;
  worktrees share Git objects/refs and are not a security boundary. Full access
  means unrestricted host authority. Linux has documented nested `.git`/`.ouroboros`
  limitations. Read [Architecture: safety boundaries](ARCHITECTURE.md#safety-boundaries).
- Connected fleet peers share full Erlang authority. Roles and placement checks do
  not contain a hostile connected node. Start local; [FLEET.md](FLEET.md) is the
  optional manual trust-domain setup.
- Crash recovery is not exactly-once external effects. Inspect an ambiguous or
  lost outcome before retrying a command. A transport timeout is not proof that
  nothing happened. For APIs with caller-owned request IDs, reconcile the same
  ID and identical request using the documented contract, not a duplicate start.
- Long sessions are bounded. `steering_capacity` and
  `compaction_operation_capacity` are operational refusals, not provider-policy
  refusals. Do not erase operation history to free capacity. Preserve the report
  and use a supported handoff to a new session; handoff can itself take long
  enough for a caller timeout, requiring outcome reconciliation. Compaction is
  model-authored and lossy, not unlimited memory.
- During the self-development experiment, four independent review scopes remain
  provider-policy blocked: P0 AR2/AR4, P1, P4 core and P2 review06. No retry,
  rerouting or substitute clearance was obtained. Functional tests do not clear
  these reviews or establish whole-program independent acceptance. Historical
  wording “permanently” denotes that experiment's retained disposition, not a
  prediction about every future provider policy or release outcome.
- No protected installed-runtime acceptance, exhaustive maintenance fault/reboot
  qualification, matched improvement benchmark or automatic promotion is claimed.
  Humans retain signing, merging and promotion. Local integrity receipts are not
  independent execution witnesses.

## First-use failure and credential status

The browser's failed-turn cells distinguish reported authentication rejection, access
refusal, request/model/context problems, quota/rate limits, service/transport failures,
and unknown causes. Technical details retain bounded category, HTTP status, known
provider code, stream phase and reported retryability; raw exception/response text is
omitted. Unknown codes are marked `redacted`, not rewritten as a diagnosis. A retry
suggestion is an operator choice, not an automatic retry or evidence that previous work
had no effects. This does not diagnose the historical 26 ms failure above.

ChatGPT connection cards distinguish local credential material present, absent, invalid
store, and unavailable observation. Material present is **not** verified validity,
provider acceptance or model entitlement. `account.read` adds `credentialState` and
credential reports add `credential_state` (`present`, `absent`, `invalid`, `unavailable`).
Legacy report `present` remains a boolean material/readiness hint; consumers needing
absence truth must inspect the enum. Session safe status uses `present: null` for an
invalid/unavailable observation, rather than claiming `false`. Older payloads without
the enum have not reported that observation. Other provider-key rows retain their
existing contracts; this increment classifies the managed Codex OAuth store.

Status inspection does not refresh credentials or contact providers. The local OAuth
observation accepts regular files up to 64 KiB; malformed/oversized stores are invalid,
and failed reads/nonregular sources are unavailable. Restore a valid store before
signing in if parsing failed; sign-in is not a repair path for corrupt JSON. No store
path, token, decoder text or contents are included in the new status fields. Existing
sign-in, request-time refresh and logout writers are unchanged. Browser account-read
failure clears stale certainty and keeps following a pending login across recovery.

## Candidate exit record (maintainers)

Before announcing a public preview, retain and review:

1. An attributable source revision/version and exact selected paths, including
   integrated contributions; a few checkpoint commits cannot stand in for a larger
   dirty tested tree. Exclude credentials, runtime state, logs, caches, private
   experiments and unattributed old artifacts. Inspect the actual source bundle
   and embedded tar contents for private data before sharing either.
2. For **every claimed target**, exact OS/architecture/toolchain, revision and
   dependency locks, a fresh build log, binary and embedded-tarball digests,
   helper presence, system-library compatibility, install/start and clean shutdown.
   Container/emulated evidence must be labeled, not called native-host acceptance.
3. Terminal and local-browser first use, one supported provider's actual sign-in
   or key setup, useful native read/edit/check work, an honest ordinary failure or
   denial, retained work after resume/replay and a controlled owned-runtime restart.
   Record model/runtime/source identities, result, duration and human interventions.
4. Relevant automated checks on the candidate; explicit skipped/unavailable checks
   and unresolved reviews. A historical source campaign is not a candidate install
   test. Keep native subagent/worktree evidence and any real two-machine example
   distinct from the first local task; do not drop those core features or overstate
   their target coverage.
5. Public notes listing qualified targets, chosen provider route, version/revision,
   known limitations and feedback path. Only then follow the human maintainer
   release procedure in [CONTRIBUTING.md](../CONTRIBUTING.md#releases-maintainers).
   Publishing/tagging/pushing is a separate human action, not performed by this guide.

## Feedback

For ordinary bugs, open an issue in the canonical repository with revision/version,
OS/architecture, toolchain versions for build failures, model lane (no credentials),
workspace/approval/sandbox posture, minimal reproduction, expected versus actual
result, exit code and sanitized short error excerpt. State whether the run used a
fresh checkout, existing daemon, container or emulator, and what you retried.
Do not upload whole data directories, journals, logs or auth-bearing screenshots.
There is no automatic telemetry or upload step in this guide.

For suspected vulnerabilities, **do not open a public issue**: follow the private
reporting path in [SECURITY.md](../SECURITY.md).
