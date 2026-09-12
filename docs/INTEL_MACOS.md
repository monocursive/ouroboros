# Opt-in Intel macOS candidate build/smoke

This is a **prepared workflow, not recorded Intel qualification**. No Intel Mac
was available for the local preview campaign. `.github/workflows/intel-macos.yml`
offers one opt-in, uncredentialed hosted-VM route: manual dispatch, or a push only
to the dedicated `validation/intel-macos` branch. No PR/general push trigger or
change to existing Linux CI. A future successful run is evidence
for that exact source, artifact and VM, not a physical end-user desktop promise.

## What the future run does

- Uses the explicit standard `macos-15-intel` label and checks Darwin, x86_64,
  runner X64 and `machdep.cpu.vendor=GenuineIntel`. No Rosetta or paid-runner fallback.
- Manual dispatch requires a lowercase full 40-character `source_sha` equal to the
  selected workflow ref's resolved commit. A dedicated-branch push uses its exact
  event commit. Checkout uses that same SHA without persisted
  Git credentials. **Only dispatch reviewed source**: dependency/build scripts
  execute with the runner user's authority. This is not an untrusted-PR sandbox.
- Uses the existing `actions/checkout@v7`, `erlef/setup-beam@v1` conventions and
  Elixir1.20/OTP29/Rust1.95 ranges from Linux CI. These are not immutable action
  SHAs or patch-version locks; actual resolved compiler/OS versions are reported.
  The checked-in Mix/Cargo locks are retained; a tracked diff against HEAD after
  build fails, including staged changes.
- Runs `mix local.hex --force`, `mix local.rebar --force`, `mix deps.get`, then
  the existing native-host **`make ouro`** recipe, once. No persistent dependency
  or build cache is restored/saved. No SDK examples, full suite or model work.
- Copies the resulting embedded client into a fresh private directory, starts
  it with a runtime-only system PATH and fresh HOME/XDG/data/cache, distribution
  off and no model/CI credentials inherited. It records binary/tar/helper hashes,
  client version, Mach-O x86_64 checks and `otool -L` for client/helper/ERTS.
- Queries `ouro wasm doctor --json` for packaged helper presence, then runs the
  extracted helper's `doctor` and requires an usable engine and Intel target.
  **Neither is a component execution or signing/admission test.**
- Uses `ouro web --print` privately and requires unauthenticated HTTP401. It does
  not authenticate a browser, launch a browser engine, sign in or submit a task.
- Stops through the real `ouro stop` (authenticated shutdown and observed process
  exit), then runs the packaged release's `eval` in a different fresh data
  directory. The small `intel-macos-shell.exs` invokes actual compiled
  `Tools.Bash` under Seatbelt: read succeeds, read-only write refuses, workspace
  write succeeds, outside/.git/.ouroboros/hook-manifest/runtime-data writes refuse
  with unchanged synthetic contents. It checks actual BEAM Intel/OTP/JIT identity.
  These are no-model shell-path controls, not the permission/approval/model loop.

## Bounds, cleanup and retained output

One job, no matrix; 100-minute outer deadline, bounded setup steps and 80-minute
build/smoke step (build command capped at60 minutes). Cargo uses two jobs with
incremental output off. Commands check a **2GiB free-space reserve** before/during
execution and a16MiB combined-output cap per command, sampled every100ms; these
are refusal thresholds, not hard disk quotas. Cold toolchain/build fit remains
**unmeasured**. If unavailable or too large, fail and report it; no global cleanup,
cache restoration, alternate paid runner or automatic rerun is prescribed.

Runtime state is a new mode0700 `RUNNER_TEMP/ouro-intel-smoke` directory, never an
operator's existing data. The harness has a `finally` cleanup and a separate
`always()` workflow cleanup step. Stops use only the owned client/data directory,
never PID-name sweeps. Completed/timed-out command groups are torn down even if
their leader exited; only groups the harness itself spawned are signalled. A stale
publication cleanup is not accepted as the mandatory authenticated stop; that
phase requires the real client's shutdown-accepted and observed-exit messages.
An attempted startup without a publication is **cleanup unconfirmed**,
not a fabricated clean stop. Hard workflow cancellation/runner loss can prevent
cleanup: disposal of the dedicated hosted VM is the final resource backstop, not
an observed graceful shutdown. Do not mark such a run green.

Actions logs get selected identity/check/error-phase JSON, not raw daemon output,
tokens or bootstrap URLs. Private bounded command logs remain only under the
temporary directory until VM disposal; no artifact/cache upload action is used.
No binaries, runtime state, auth files or reports are published automatically.
On failure, the phase/status is evidence; do not infer later checks ran. Private
logs are deliberately not a durable remote diagnostic artifact—if more detail is
needed, arrange a separately reviewed, redacted diagnostic change rather than
upload the whole directory. No project or provider secrets are required.

## Run once before merge, only after separate authorization

For the first pre-merge validation, the narrow push trigger avoids needing to put
this workflow on the default branch or merge the whole candidate just to test it.
After explicit authorization to publish the reviewed candidate, an operator can
create/push the **exact** dedicated branch `validation/intel-macos` at that commit.
Use a new branch; if the remote name already exists, reconcile it rather than force
or overwrite it. Push only reviewed content including this workflow and helpers.
Each subsequent push to that exact branch would run again, so do not use it as a
general development branch. No branch creation, push or run occurs in preparation.

From a checkout containing the authorized reviewed commit, the single remote action
is the following, after checking the destination branch is absent:

```sh
git push origin FULL_REVIEWED_COMMIT_SHA:refs/heads/validation/intel-macos
```

That is a future operator action, **not current permission to push**. A normal push
of `codex/self-improvements` does not trigger this route. No PR, merge, tag, default-
branch workflow bootstrap, new secret or runner setting is necessary for the narrow
validation-branch trigger. This avoids requiring promotion to obtain build evidence.

For later manual runs, GitHub requires a `workflow_dispatch` workflow to exist on
the repository's **default branch** and the dispatcher to have write access.
Only after separate normal authorization has made that true, select
**Intel macOS candidate smoke** in Actions, choose the reviewed
branch/tag, and enter its exact resolved commit as `source_sha`; run once. Or,
after independently checking those values:

```sh
gh workflow run intel-macos.yml --ref REVIEWED_BRANCH_OR_TAG -f source_sha=FULL_REVIEWED_COMMIT_SHA
```

The input must match the dispatched ref's SHA; it cannot select arbitrary other
source or inject a shell command. A moving ref mismatch refuses rather than
building the wrong revision. Check the recorded runner/commit/artifact identities
and every phase outcome. Do not dispatch this workflow against unreviewed source.

## Availability and qualification limits

Read on2026-09-12: [GitHub hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
lists `macos-15-intel` (also `macos-26-intel`) as standard Intel VMs with4CPU,
14GB RAM and14GB SSD, and says standard public-repository use is free/unlimited.
That is time-qualified provider documentation, not account availability, capacity,
cost authorization or proof this build fits. [setup-beam](https://github.com/erlef/setup-beam)
lists macOS15 x86_64 with OTP25–29; the exact resolved build still needs execution.
[Manual dispatch requirements](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
are separate from permission to prepare this local change. The dedicated-branch
push trigger intentionally provides the pre-merge alternative.

Even a green smoke leaves ordinary Intel provider sign-in, useful model-backed
read/edit/check, actual approval behavior, retained resume/replay/restart and
authenticated browser/terminal first-use journeys **missing**. It does not clear
P0 AR2/AR4, P1, P4 core or P2 review06, nor prove broader sandbox/security claims.
The [four-target preview objective](PREVIEW.md#platform-and-delivery-contract)
remains open. Read [architecture limits](ARCHITECTURE.md#safety-boundaries) before
relying on containment. The Linux first-use owner and its source copy are separate.

## Lightweight local checks for this preparation

```sh
python3 scripts/test-intel-macos-smoke.py
git diff --check
```

The tests cover only the new orchestration helpers with harmless local processes
and cleanup doubles. They never invoke `make ouro`, a real runtime, Seatbelt or a
hosted runner. Workflow YAML and embedded shell syntax also need static review;
passing them is not Intel platform execution.
