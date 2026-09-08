# Self-improvement v1: implementation plan

Status: **plan**, 2026-09-08. Implements [self-improvement.md](self-improvement.md) (the
proposal) against `dev` at `160ca08`. Every file and line cited below was read at that ref.
This document is the contract the implementing agents work to, the review protocol each slice
runs under, and the record of where the plan departs from the proposal and why.

The proposal's claim (§0) stands unchanged. What changes is mechanism, in the ten places
where the source disagreed with the proposal's reading of it.

## 0. Where the source disagrees with the proposal

| # | Proposal says | Source says | This plan does |
|---|---|---|---|
| 1 | S2 replays the candidate policy against `:permission` and `:approval` ledger entries "that carry a request". | A `:permission` entry holds `%{tool, mode, provider, fingerprint}` where the fingerprint is a sha256 over command + paths + domains ([`permissions.ex:558`](../../lib/ouroboros/control/permissions.ex)). An `:approval` subject holds paths, hosts and a command *digest* ([`effect_ledger.ex:96-120`](../../lib/ouroboros/agent/effect_ledger.ex)). The session journal writes the approval *question* as a digest too ([`loop.ex:1809-1813`](../../lib/ouroboros/provider/native/loop.ex)). Nothing durable holds the request a policy would be shown. | S2 adds a **decision corpus**: `Ouroboros.Control.PolicyEvidence`, written at the one seam where the full request and the human's answer meet (`Control.Permissions.record/2`, `actor: :human`), holding the exact bytes `PolicyEngine.document/1` would hand a component. Node-local, bounded, never exported over the gateway. Replay reads it. |
| 2 | The native loop's `record/5` passes the request to the engine. | It passes `decision, scope, actor, rule_ref, reason, session_id, provider` and no request ([`loop.ex:2386-2398`](../../lib/ouroboros/provider/native/loop.ex)); `answered_request/1` therefore finds none. The interactive seam does pass one ([`approvals.ex:351-359`](../../lib/ouroboros/interactive/task/approvals.ex)). | S2 makes the loop pass `request: permission_request(state, classified)` at the four human-answer sites (1840, 1854, 2179, 2183). |
| 3 | The `self` posture sets `forge_signer` to `Signer.Local`. | `forge_signer` is lane B's signer. A lane-W sign goes through `Ouroboros.Upgrade.Signing.Service`: an explicit service, then the configured `:signing_node`, then **a service running on this node** ([`deploy.ex:384-407`](../../lib/ouroboros/wasm/deploy.ex)). The service loads its key from `OUROBOROS_SIGNER_KEY_PATH` / `OUROBOROS_SIGNER_ID` ([`service.ex:828-847`](../../lib/ouroboros/upgrade/signing/service.ex)). | The one-machine posture runs the local service with a dev key; the fleet posture names a `:signer` node. S4 verifies under which condition `application.ex:139` starts the service on a `:core` node and adds the posture arm if there is none. |
| 4 | Every corpus run has a `[budget] max_cost_usd`. | No such setting exists; `ouro run` has no cost flag ([`cli.rs:1240-1320`](../../tui/src/cli.rs)). The result object does carry `usage.cost_usd` when `llm_db` prices the model ([`cost.ex:47`](../../lib/ouroboros/provider/native/cost.ex)). | The runner enforces `--spend` **between tasks** and bounds each task by `--timeout`; a model `Native.Cost` cannot price is refused before the first task. One task can overshoot the cap by at most its own cost. Stated in the doc. |
| 5 | `author` is taken from the principal the permission engine receives. | The tool context the loop hands a tool carries `scope, provider_options, session_dir, audit, reads, subagents, desktop_evaluated_app` and no session identity ([`loop.ex:1085-1103`](../../lib/ouroboros/provider/native/loop.ex)). The loop already derives `"session:" <> id` in `principal/1` (line 3195). | S1 adds one key, `principal: principal(state)`, to that context map. The tool reads it and nothing else. |
| 6 | `Forge(<name>)` matches with `context.forge` set to the name. | `Capability(<name>)` is honest because the name is resolved against the live register before the engine is asked ([`tools.ex:596-603`](../../lib/ouroboros/provider/native/tools.ex)). A forge has no register entry yet. | The name is the tool's `name` parameter, charset-checked (`Wasm.Artifact.name?/1`, exact bytes, no trim) and put in `context.forge`; it is made honest downstream because the tool passes `name:` to `Wasm.Forge.forge/2` and `preview/2`, which refuse a manifest whose package name differs ([`forge.ex:601,845-848`](../../lib/ouroboros/wasm/forge.ex)). `Tool(forge)` is deny-and-ask only, like `Tool(capability)`. |
| 7 | The `forge` tool is added to the static list. | `capability` appears only when the node has a live rollout; the desktop tools only under a feature flag ([`tools.ex:170-215`](../../lib/ouroboros/provider/native/tools.ex)). A name the model is taught and cannot use costs calls. | `forge` is shown and resolvable only when `config :ouroboros, :native_forge_tool` is `true`. Default `false`. The `self` posture sets it. Default behaviour, `bench-local` included, is unchanged. |
| 8 | Candidates are "commits since June … 256 exist; 79 are `fix`". | The history starts 2026-08-12. 281 commits touch `lib/` and a `test/**/*_test.exs`; 81 are fixes; 114 are Elixir-only with ≤ 300 non-test lines changed. | The extractor ranks by non-test diff size and prefers fixes; the corpus is 20–30 tasks from that set. |
| 9 | Replay is fleet-wide through `ledger.list`. | `ledger.list` carries fingerprints (row 1). | v1 replays the node-local corpus. A `--fleet` replay is listed as not in v1. |
| 10 | `evaluate_with/3` runs "against a named artifact rather than the live one". | The engine stands one instance per sha under `policy-<sha>` and re-verifies the manifest before loading a byte ([`policy_engine.ex:341-420`](../../lib/ouroboros/wasm/policy_engine.ex)). | The dry path verifies the same way, instantiates under `policy-dry-<sha>`, records nothing, and is refused for anything that is not a verified `:policy` manifest in this node's store. |

Two smaller ones. The ledger's `tool_call` result carries `status, duration_ms, output_bytes`
only, so "forge and deploy settle it with the artifact id and sha" is done the way
`Effects.Runner` does it: a `:forge` / `:deploy` ledger entry under the session principal,
`record_started` before the effect and settled after, with the tool-call id as its cause. And
the corpus runs headless under `--approve-all`, so an ask is counted (`approvals_requested`)
and never blocks; S2's "approvals per task drop" is measured on that count.

## 1. Order, waves, and what each proves

| Wave | Slice | Agent | Files it owns | Proves |
|---|---|---|---|---|
| 1 | S0 measure | one implementer | `bench/self/**`, `docs/BENCHMARKS.md` §5, `Makefile` (`bench-self`), `docs/SELF.md` §S0 | There is a number, and a $0 way to prove the grader. |
| 1 | S1 forge tool | one implementer | `lib/ouroboros/provider/native/tools/forge.ex`, `tools.ex`, `loop.ex:1085-1103` (one key), `control/permissions/{pattern,matcher,rules}.ex`, `config/config.exs` (one key), `.agents/skills/forge/**`, tests, `docs/SELF.md` §S1, one cross-reference paragraph in `docs/WASM.md` §7.7 | A session can change the runtime it runs in, through every fence that exists. |
| 1 | S2a promotion runtime | one implementer | `lib/ouroboros/control/policy_evidence.ex`, `control/policy_promotion.ex`, `control/permissions.ex` (`record/2`), `wasm/policy_engine.ex`, `agent/effect_ledger.ex` (one kind), `loop.ex` human-answer sites, `config/config.exs` (storage keys), tests, `docs/SELF.md` §S2 | A self-change can loosen, on evidence, reversibly. |
| 1 | S3 outer loop | one implementer | `bench/self/improve.sh`, `bench/self/improve-selftest.sh`, `docs/self/briefs/**`, `docs/SELF.md` §S3 | Ouroboros can run its own review protocol. |
| 2 | S2b verbs + CLI | S2a's agent, continued | `gateway/methods/contract.ex`, `gateway/methods.ex`, goldens, `docs/PROTOCOL.md`, `tui/src/policy_cli.rs`, `tui/src/cli.rs`, `tui/src/main.rs` | A human runs `ouro policy replay` and `ouro policy promote` with the number in front of them. |
| 2 | S4 posture + ship | one implementer | `config/runtime.exs` (posture), `lib/ouroboros/self/**`, `Makefile` (`self-export`), `priv/self/`, `docs/SELF.md` §3 and §S4 | The next version carries what this one learned. |

S3 runs in wave 1 rather than after S0 because its only interface to S0 is the runner's command
line, fixed in §S0 below. The proposal's order S0 → S3 → S1 → S2 → S4 is the order the
*claims* land; the code lands in two waves because the file sets are disjoint.

Each slice: implementer → my gates and a read of the full diff → a separate adversarial
reviewer with a stated threat model, PROVED/PLAUSIBLE labels and a mutation table → fix wave
back to the implementer with its context intact → I re-run every former mutation survivor →
cherry-pick onto the integration branch `self-integrate` → the combined gate.

## 2. Ground rules for every agent

1. **Base.** `dev` at `160ca08`. Your worktree is at `.claude/worktrees/<slice>` on branch
   `self-<slice>`; verify with `git rev-parse HEAD` and `git merge-base --is-ancestor 160ca08 HEAD`
   before touching anything. Every command starts with `cd <absolute worktree path>`.
2. **Commit on your branch, never push, never touch another slice's files.** Write the commit
   message to your scratch directory early (`commit-msg.txt`) so an interrupted run can be
   committed by hand. One commit per slice is ideal; two is fine.
3. **Ownership is by file.** The table in §1 is exhaustive. A change you need outside your files
   is a message to the integrator, not an edit.
4. **Tests.** Any test that reads or writes global application environment lives in an
   `async: false` module. `mix test` output contains NUL bytes: `mix test … > log 2>&1;
   grep -a 'Result:' log`. This repository's formatter prints `Result: N passed` /
   `Failed: N tests`. Never run the full suite in your worktree; run the files you touched plus
   the suites named in your brief. Kill only your own PIDs, never `pkill cargo` or `pkill beam`.
5. **Worktrees find helpers only through `priv/wasm/` and `priv/sandbox/`** (both seeded) or
   `OUROBOROS_WASM_HELPER`. Do not add a cwd walk. A cargo path dependency is code execution:
   nothing derived from a cwd may reach a `Cargo.toml`.
6. **Docs claim only what a test proves.** Each slice writes its section of `docs/SELF.md`
   under the marker already there (`<!-- S<n> -->`). Decisions are numbered `S-D<n>` in that
   file. `docs/WASM.md` gets one cross-reference paragraph per slice at the end of the named
   section and nothing else; its decision and slice numbering is not touched.
7. **The honesty invariant.** Your final report lists what is proved by a test, what was run
   live once, and what is unverified. A mid-run notification is not a report.
8. **Scratch.** Your own directory under the session scratchpad, named in your brief. Nothing
   under `/tmp` directly.
9. **Exploits and mutations.** The reviewer keeps exploit scripts in its scratch directory; the
   fix wave adopts them as regression tests.

## 3. The `self` posture (corrected)

`OUROBOROS_POSTURE=self`, read in `config/runtime.exs`, is the one switch. Never the default.
It refuses to boot with any of its inputs missing rather than falling back.

| Setting | Value under `self` | Source of the requirement |
|---|---|---|
| `OUROBOROS_SIGNER_KEY_PATH`, `OUROBOROS_SIGNER_ID` | required on one machine; the local `Signing.Service` signs with them | `deploy.ex:384-407`, `service.ex:828-847` |
| `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` | must list the id and public key above (and the exporting installation's, S4) | `runtime.exs:301-340` |
| `OUROBOROS_SIGNING_NODE` | set instead of the two above on a fleet; then the `:signer` node signs and this node forges | D29, C14 |
| `signing_require_wasm_eval` | `true` (default) | `service.ex:951-953` |
| `wasm_forge_placement` | `:local` (default) | `forge.ex:437-457` |
| `native_forge_tool` | `true` | S1 |
| `permissions_engine` | `Ouroboros.Wasm.PolicyEngine` | `config.exs:352` |
| `wasm_policy`, `policy_allowable_tools` | the promotion record first, config as fallback | S2 |
| `OUROBOROS_NATIVE_MODEL` | required | `model.ex:108` |
| `self_ship` | `true`: boot deploys `priv/self/` bundles whose name is not live | S4 |

Everything else stays: permissions deny or ask, the native shell sandboxed, the helper sealed,
the effect ledger on.

## 4. Slices

### S0. The measure: `bench/self`

**Files.** `bench/self/README.md`, `bench/self/extract.exs`, `bench/self/run.sh`,
`bench/self/run.exs`, `bench/self/selftest.sh`, `bench/self/tasks/<id>/task.json`,
`bench/self/lib/` (shared shell), `Makefile` target `bench-self`, `docs/BENCHMARKS.md` new §5,
`docs/SELF.md` §S0.

**Extraction** (`extract.exs`, an `elixir` script like `bench/local/run.exs`, stdlib only).

- Candidates: commits reachable from `dev` that touch `lib/` and add or modify at least one
  `test/**/*_test.exs`, exclude anything under `tui/`, `assets/`, `.github/`, `scripts/`,
  merge commits, and commits whose non-test diff exceeds `--max-diff-lines` (default 300).
  Rank: `fix` prefix first, then smaller non-test diff first. Take `--max-tasks` (default 30).
- Verification, per candidate, in a detached worktree at the parent with `deps/` and `_build/`
  cloned from the repository (`cp -Rc` on macOS, `cp -R` elsewhere): `mix compile` then the
  commit's test files (taken from the commit) must **fail** at the parent and **pass** at the
  commit, each under a wall clock; compile plus test at the parent over `--task-ceiling-secs`
  (default 600) drops the task. Every drop is reported with its reason.
- A task is `bench/self/tasks/<nn>-<slug>/task.json`:
  `{id, base_sha, commit_sha, subject, instruction, hidden_tests: [paths], timeout_secs,
  measured: {compile_ms, test_ms, diff_lines}}`. Hidden test **content** is read from git at run
  time (`git show <commit_sha>:<path>`), so the corpus stays a list of pins and the number is
  reproducible as long as `dev`'s history is. `instruction` is the subject, the body with any
  diff or `Co-Authored-By` trailer removed, and an "Acceptance" list of the hidden tests' test
  titles (the `test "…"` strings), never their bodies. The report states the instruction
  length distribution.
- `--verify <task-dir>` re-checks an existing task without re-extracting.

**Runner** (`run.sh` → `run.exs`). Mirrors `bench/local/run.exs`: one `ouro --dev daemon` on
a scratch data dir (mode 0700), `ouro run --provider native --stream-json` per task, the
newest client binary. Differences, each stated in the README:

- **Real model, real credentials.** The environment is passed through; `XDG_CONFIG_HOME` is
  kept (the packaged default model authenticates through it). Only `OUROBOROS_DATA_DIR` is
  scratch. `--model <spec>` overrides `OUROBOROS_NATIVE_MODEL`.
- **`--spend <usd>` is required.** Before the first task, `mix run --no-start` asks
  `Ouroboros.Provider.Native.Cost` whether the model is priced; an unpriced model is a refusal.
  The running total of `usage.cost_usd` is checked before each task; reaching the cap stops the
  run and the report says which tasks did not run. A task is bounded by `--timeout` (default
  the task's `timeout_secs`).
- **Per task:** a detached worktree at `base_sha` under the scratch dir, `deps/` and `_build/`
  cloned in, `mix compile` run once by the runner (setup time, reported separately), then
  `ouro run` with `--workspace <worktree> --approval-mode prompt --approve-all --timeout`.
  `--no-approve-all` runs the unattended posture instead.
- **Grade,** in order: (1) the run finished `completed` inside its timeout; (2) the agent
  modified no pre-existing file under `test/` (`git status --porcelain -- test/` shows no `M`
  or `D`; new files are allowed and left in place); (3) the hidden test files are written from
  `commit_sha` over the worktree and `mix test <hidden paths>` passes under a wall clock. The
  reason a task failed is one of `timeout`, `not_completed`, `modified_tests`, `tests_failed`,
  `setup_failed`.
- **`--oracle`.** The scripted model from `bench/local/model/` answers every task with the
  commit's own non-test diff, applied through `apply_patch`, then stops. It must grade 100%
  and spend $0. This is the proof that the grader, the worktree, the hidden tests and the
  budget arithmetic work, and it needs no key. `selftest.sh` runs it over two tasks and is the
  gate I run.
- **Output.** `result.json`: `{run: {model, ouro_sha, ouro_bin, started_at, spend_cap, spent,
  tasks, ran, passed, pass_rate, wall_ms}, tasks: [{id, grade, reason, cost_usd, tokens,
  tool_calls, approvals_requested, approvals_answered, files_changed, wall_ms, status}]}`,
  kept under `--out` (default `bench/self/results/<timestamp>/`, gitignored) with every
  trajectory beside it; a table on stdout in `bench/local`'s style.

**Docs.** `docs/BENCHMARKS.md` gains §5 "The self corpus", above the §4 placeholder's meaning
and without touching it: what is measured (Ouroboros on Ouroboros), the oracle result with the
date and the corpus size, the exact command for a paid run, and a stated noise expectation
(two runs, same model, the pass rates differ by at most the number the doc then records — to
be filled by the first paid pair, not guessed). `docs/SELF.md` §S0 records the extraction
policy and every dropped candidate class.

**Acceptance (this wave, $0).** `bench/self/selftest.sh` green: extraction of two named
commits verifies, the oracle run grades 2/2, the spend guard refuses a run without `--spend`
and stops one at the cap (simulated by an oracle task with an injected `cost_usd`). Mutations
that must go red: skip the hidden-test restore (an agent that deletes a test must not pass);
skip the `modified_tests` check; let the spend total ignore a task.

**Human step, after the merge.** One paid run twice with the same model, the two numbers into
§5 with the spend. That is the acceptance in the proposal and it needs a key this environment
does not have.

**Not in this slice.** Terminal-Bench. Rust tasks. Any change under `lib/`.

### S1. Head to tail: the `forge` tool

**Files.** `lib/ouroboros/provider/native/tools/forge.ex` (new),
`lib/ouroboros/provider/native/tools.ex`, `lib/ouroboros/provider/native/loop.ex` (the
context map at 1085-1103 gains `principal: principal(state)`; the `execute_timeout/3` table at
1201-1220 gains a `"forge"` clause), `lib/ouroboros/control/permissions/pattern.ex`,
`matcher.ex`, `rules.ex`, `config/config.exs` (`native_forge_tool: false`),
`.agents/skills/forge/SKILL.md` plus the template files it references,
`test/provider/native/forge_tool_test.exs`, `test/control/permissions_test.exs` (patterns),
`test/wasm/forge_tool_acceptance_test.exs`, `docs/SELF.md` §S1, one paragraph at the end of
`docs/WASM.md` §7.7.

**The tool.** `Ouroboros.Provider.Native.Tools.Forge`, a `Jido.Action` like
`Tools.Capability` with a hand-written `model_schema/0`. Operations:

- `preview {name, path}` → `Wasm.Forge.preview(%{dir: resolved}, name: name, build?: true)`.
  `path` is resolved through `Ouroboros.Provider.Native.Paths.resolve/2` with the session's
  scope, the same containment `read` uses; a path outside the workspace is refused before the
  forge sees it. The refusal vocabulary is `Wasm.Forge`'s, rendered by class.
- `forge {name, path, eval, start_config}` → `Wasm.Forge.forge(%{dir: resolved}, author:
  context.principal, name: name, eval: eval, start_config: start_config, timeout_ms: …)`.
  `eval` is a JSON object in the shape `Ouroboros.Runtime.Capabilities` reads from a lane-W
  `manifest.json` (`Evaluation.validate/1` after the same atomisation); a project directory
  carrying a `manifest.json` supplies `eval`, `start.config` and `name` when the parameters are
  absent, so one proposal format serves the operator's `capabilities.admit` and this tool.
  `author` is `context.principal` and is never a parameter; a context without one is a
  refusal, not `"native"`.
- `deploy {artifact_id}` → the bundle is resolved from this node's forged ring exactly as
  `Effects.DeployWasmCapability` resolves it, and additionally the manifest's `author` must
  equal `context.principal`: a session deploys what it forged. Then
  `Wasm.Forge.deploy(artifact, [node()])`. The result renders the rollout state and the
  register entry's `eval_report`, bounded.
- `status` → this session's bundles in the ring and their register state.

Every operation is `:execute` in `Tools.classify/3`, so plan mode refuses it and the loop's
approval path handles it. `context(forge)` puts `%{forge: name}` in the request context only
when `name` is `Wasm.Artifact.name?/1` — exact bytes, no trim (the F1 rule in
`Tools.Capability.resolve/1`). The tool passes that same string as `name:` to the forge, which
refuses a manifest naming anything else. The spec and the lookup exist only while
`config :ouroboros, :native_forge_tool` is `true`; `Ouroboros.Audit.tool_supported?/1` is
left as is, so required audit refuses the tool by omission.

**Ledger.** Before `forge` runs, `EffectLedger.record_started` writes a `:forge` entry under the
session principal with attempt `%{module: "wasm/" <> name}`, the tool-call id as `cause`, and
the permission entry id in `authority`; it is settled with `artifact_id, module, epoch, signer,
source_sha256, nodes` — the fields `Effects.Runner` already writes. `deploy` does the same
with `:deploy`. A ledger that cannot record refuses the operation before it starts. Bytes
never enter the ledger.

**Timeout.** `Forge.max_timeout_ms/0` = `Wasm.Forge.build_timeout/1` plus signing and deploy
slack; `execute_timeout/3` uses it for `"forge"` as it does for `"capability"`.

**Permission language.** `Forge(<name>)` and `Forge(*)` in `Pattern` (kind `:forge`, the
capability charset), matched in `Matcher` on `context.forge` exactly as `Capability(…)` is
matched on `context.capability`; `Tool(forge)` joins `Tool(capability)` as
`:deny_or_ask_only`. `suggest/1` offers `Forge(<name>)` for an ask carrying the context, so
"don't ask again" persists it at workspace scope through the existing modal.

**Protected write.** `Rules.protected_write?/1` refuses any path whose final segment is
`ouroboros.toml`, case-insensitively (the file `Hooks` reads at `hooks.ex:285`), with the
worktree-delivery exemption unchanged. `protected_paths/0` lists it.

**Skill.** `.agents/skills/forge/SKILL.md`: the shape of a capability project (the counter
example's `Cargo.toml` and `src/lib.rs`, the `Cargo.lock` pin rule, the `manifest.json` with an
eval spec), the world contract, the four operations in order, what the fences refuse and how
the refusal reads. No SDK path is derived from a cwd: the skill says the `ouroboros-guest`
dependency is by path to this checkout's `tui/wasm/guest` and that the lock must be the SDK's.

**Tests.** Unit (`forge_tool_test.exs`, scripted model, no cargo): the tool is absent and
`:unknown_tool` when the switch is off; present when on; classification is `:execute` with
`context.forge` set only for a valid name and for the exact string; a call with a mismatched
manifest name is refused by the forge with `name_mismatch`; `author` cannot be supplied as a
parameter; plan mode refuses; an out-of-workspace `path` is refused before `Wasm.Forge` is
called (assert with a fake forge module named through a test seam); the ledger holds the
`:forge` entry before the effect and settled after; a ledger that refuses stops the forge.
Patterns (`permissions_test.exs`): parse, match, `Tool(forge)` deny-or-ask-only, `suggest`.
Rules: `ouroboros.toml` refused at every depth and case. Acceptance
(`forge_tool_acceptance_test.exs`, `ForgeFixture.tag()`): a scripted session writes the
counter project with the ordinary tools, previews, forges, deploys, and calls it through the
`capability` tool in the next turn; the ledger shows the `Forge(counter)` decision, the
`:forge` and `:deploy` entries with the artifact id and sha, and the register entry with its
eval report.

**Mutations that must go red.** Remove the permission classification; let a parameter reach
`author`; set the signing service to refuse and expect the typed refusal; strip the eval spec
and expect the signer's refusal; deploy an artifact another principal forged; write
`ouroboros.toml` through `write` and `apply_patch`.

**Not in this slice.** The BEAM lane. Hooks. Forwarding to a `:builder` node (the placement
answer is rendered in `preview`, not acted on). A `Forge(*)` default rule anywhere.

### S2. Earned widening: policy promotion by replay

Two parts. S2a is the runtime and its tests; S2b is the gateway verbs and the client.

**S2a files.** `lib/ouroboros/control/policy_evidence.ex` (new),
`lib/ouroboros/control/policy_promotion.ex` (new), `lib/ouroboros/control/permissions.ex`
(`record/2` writes evidence for human answers), `lib/ouroboros/wasm/policy_engine.ex`,
`lib/ouroboros/agent/effect_ledger.ex` (one new ledger-only kind, checkpoint version bumped
the way R1 did), `lib/ouroboros/provider/native/loop.ex` (the four human-answer `record`
calls pass `request:`), `config/config.exs` (`policy_promotion_storage`,
`policy_evidence_root` for tests), `lib/ouroboros/application.ex` (the promotion server in
the tree beside `Control.Grants`), tests, `docs/SELF.md` §S2, one paragraph at the end of
`docs/WASM.md` §8.2.

**The corpus** (`Control.PolicyEvidence`). Append-only NDJSON at
`<data_dir>/policy/evidence.ndjson`, mode 0600, one record per **human** answer:
`{at, node, session_id, tool, mode, fingerprint, decision, scope, permission_entry_id,
document}` where `document` is exactly `PolicyEngine.document/1`'s output for the request
(redacted by the engine's own redaction) and `fingerprint` is the digest
`Control.Permissions` already computes. Bounded: 10 000 records or 64 MiB, oldest dropped by
a rewrite, the journal's discipline. A write failure is logged and never refuses the answer
that caused it: the evidence is a corpus, not an authority. Nothing here is served over the
gateway. Under `:read` the gateway may report the **count** per tool and nothing else.

**The record** (`Control.PolicyPromotion`). A GenServer on `Control.Grants`' checkpoint
discipline (write, fsync, then acknowledge; a failed checkpoint is not applied), storage from
`config :ouroboros, :policy_promotion_storage` (ETS in dev and test, `DurableFile` in prod).
State: `%{policy_name, component_sha256, tools: %{tool => %{promoted_at, actor, evidence}},
demotions: [%{tool, at, reason, fingerprint}]}`. API: `promote(name, tool, evidence, actor)`,
`demote(name, tool, reason)`, `status/0`, `allowable_tools(name)`, `policy_name/0`. One policy
name per record; promoting a tool for a different name than the record holds is refused until
the record is cleared (`clear/1`, actor required). Every write is a `:policy_promotion` ledger
entry with attempt `%{policy_name, tool, action, component_sha256}` and result
`%{decisions, contradictions, report_sha256}`.

**The engine.** `PolicyEngine.configured_policy/0` answers the config, then the record;
`allowable_tools/0` becomes `allowable_tools(name)`: the config list plus the record's tools
**for that name only**, minus tools with a demotion newer than their promotion. `settle/6`
honours an `allow` through it. `evaluate_with(name_or_sha, document, opts)`: verifies the
manifest as `provenance/3` does, stands an instance under `policy-dry-<sha>`, asks once,
returns `{:ok, verdict, rule}` or a named refusal, records nothing. `replay(name, opts)`: over
the corpus (optionally `since:`), per tool: `decisions`, `agreements`, `contradictions` (the
component answered `allow` where the human answered `deny`), `would_resolve` (`allow` where
the human answered `approve`), `asks`; contradictions carry the fingerprint and the session id,
never the document; the report carries `policy_name`, `component_sha256`, `corpus_size`,
`replayed_at`, and its own `report_sha256` over the canonical JSON of everything else.
`promote(name, tool, evidence_report)`: refuses unless the report names this sha, then
**re-runs the replay** and refuses unless `decisions >= 50` and `contradictions == 0` now;
records both the report's `report_sha256` and the re-run's numbers. `record/2` gains the
canary: a human `deny` for a tool the record holds is dry-evaluated through the promoted
policy; an `allow` there demotes the tool, writes the ledger entry, and logs a warning
naming the session. The deny itself is recorded exactly as before.

**S2b.** Gateway verbs `policy.status` (`:read`), `policy.replay`, `policy.promote`,
`policy.demote` (`:operate`), each with a closed params contract, golden fixtures
(`make golden`), `docs/PROTOCOL.md` (`make protocol-docs`), and the Rust decode test the
golden set requires. `ouro policy status|replay <name> [--since] [--json]|promote <name>
--tool <t> --evidence <report.json>|demote <name> --tool <t> --reason`. `replay` writes the
report file the operator hands to `promote`.

**Tests.** `test/control/policy_evidence_test.exs`: record shape, bound, rewrite, no write on
a rule or classifier answer, write failure does not refuse. `test/control/policy_promotion_test.exs`:
checkpoint before acknowledge, refusal on storage fault, one name per record, demotion
newer than promotion, ledger entries. `test/wasm/policy_promotion_test.exs` (LiveFixture
tag, the real `no-network-shell` example signed and deployed through the real rollout as
`policy_acp_test.exs` does): `evaluate_with` answers `deny` for a `curl` and `ask` otherwise,
records nothing, and the live instance is untouched; a synthetic corpus of 60 human answers
replays with the expected counts; a corpus with one contradiction fails `promote`; after a
promotion the engine honours an `allow` for that tool and only that tool; a human deny that
the policy would allow demotes within the same `record/2` call.
`test/provider/native/loop_ledger_test.exs` gains: a scripted session whose human answer
leaves one evidence record whose `document` equals `PolicyEngine.document/1` of the request
the loop evaluated. S2b: contract tests as every other verb has.

**Mutations that must go red.** Remove the contradiction check in `promote`; remove the
re-run; let `allowable_tools/1` answer for a different policy name; drop the demotion-newer
check; write evidence for a `:rule` answer; let `evaluate_with` record.

**Not in this slice.** A classifier. A model in the promotion path. Promotion without a human
actor. Fleet-wide replay. A session-visible notice on demotion beyond the log and the ledger
(listed as S-D open).

### S3. The outer loop: Ouroboros works on Ouroboros

**Files.** `bench/self/improve.sh`, `bench/self/improve-selftest.sh`,
`docs/self/briefs/implementer.md`, `docs/self/briefs/reviewer.md`,
`docs/self/briefs/fix-wave.md`, `docs/SELF.md` §S3.

**`improve.sh <task.md> [--model <spec>] [--spend <usd>] [--no-bench] [--no-pr] [--dry-run]
[--ouro <path>]`.** POSIX `sh`, like `run.sh`. Steps, each printed with its exit code:

1. A worktree from `dev` at `.claude/worktrees/improve-<slug>` on branch `self/improve-<slug>`;
   `deps/` and `_build/` cloned in; `priv/wasm` and `priv/sandbox` copied.
2. Implementer: `ouro run "<implementer brief + task>" --provider native --workspace <wt>
   --approve-all --stream-json --timeout <s>`; the session id is read from the result object.
3. Gate 1: `mix format --check-formatted`, `mix test` on the test files the diff touches, then
   `make test` and `mix dialyzer` (both stated as the slow gate; `--quick` skips the second
   pair for iteration and says so in the PR body).
4. Reviewer: a second `ouro run` in the same worktree with the reviewer brief, the diff
   (`git diff dev...HEAD`), and the instruction to write `REVIEW.md` with PROVED/PLAUSIBLE
   findings and a mutation table.
5. Fix wave: `ouro run --resume <implementer session id> "<fix-wave brief + REVIEW.md>"`.
6. Gate 2, as gate 1. Then `bench/self/run.sh --spend <usd>` only when the diff touches
   `lib/ouroboros/provider/native/**` and `--spend` was given; otherwise the body says the
   corpus was not run and why.
7. The protected-namespace flag: any hunk under `lib/ouroboros/control/`, `upgrade/` or
   `storage/` lists that hunk under "Human review required" in the PR body regardless of the
   review's verdict.
8. Commit with the task title and `Co-Authored-By: Ouroboros native session <id>`; push;
   `gh pr create --base dev --body-file`. `--no-pr` stops after writing the body to the
   worktree. A human merges.

**Briefs.** Distilled from the operating lessons in the babysitting protocol (the reviewer is
told: state a threat model, prove findings with a running exploit, label PROVED vs PLAUSIBLE,
mutation-test every enforcement point and report survivors, read the code above the seam and
not only the spec, treat the implementer's green report as a claim). The implementer brief
carries the repository's test discipline (rule 4 above) and the commit-message shape.

**Test.** `improve-selftest.sh` runs the whole script with `--ouro <shim>` where the shim
applies a fixed patch and prints a result object, `--no-pr`, `--no-bench`, `--quick`: the
worktree exists, both gates ran, `REVIEW.md` exists, the body names the review and the
protected-namespace hunk of the shim's patch. `--dry-run` prints every command and runs none.

**Human step.** The first real run, with a key and a spend; then the PR. Then three.

**Not in this slice.** Auto-merge. Any change to merge rules. The orchestration-plan encoding.

### S4. Ship what it forged, and the posture

**Files.** `config/runtime.exs` (the `OUROBOROS_POSTURE=self` arm), `lib/ouroboros/self/boot.ex`
(new), `lib/mix/tasks/ouroboros.self.export.ex` (new), `Makefile` (`self-export`),
`priv/self/README.md`, tests, `docs/SELF.md` §3 and §S4.

**Posture.** §3 above, refusing to boot on a missing input. Verify how `application.ex:139`
starts `Signing.Service` and make the one-machine posture start it with the dev key on a
`:core` node if it does not already; document that the key lives beside the application and
that this is the dev loop `signer.ex:98` describes, never custody.

**Export.** `mix ouroboros.self.export` reads the promotion record and, for its policy, writes
`priv/self/<name>.ouro-wasm` from the node's store (the same bundle bytes `wasm.download`
serves), `priv/self/promotions.json` (the record, with the replay numbers), and
`priv/self/signers.txt` (the signer id and public key the bundle was signed under). The outer
loop's PR commits them.

**Boot.** `Ouroboros.Self.Boot`, beside `Wasm.Boot` in the supervision order: under the
posture, for each bundle in `priv/self` whose name is not `:live` in this node's register,
`Wasm.Deploy.deploy` it through the ordinary trust policy — a fresh install trusts the bundle
only because its operator listed the exporting key in `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`,
which `signers.txt` tells them — then apply `promotions.json` when the record is empty, with
actor `"shipped:<export sha>"`. Idempotent; a bundle that does not verify is skipped by name.

**Tests.** A fresh data dir under the posture with a fixture export boots live and promoted;
a second boot changes nothing; a bundle signed by an untrusted key is skipped and named; the
export refuses when the record is empty.

**Human step.** The approval-count reproduction on the corpus (paid).

## 5. Review protocol per slice

The reviewer's brief names the threat model for that slice:

- **S0:** a model that games the grade (edits tests, adds a passing test file, times out
  gracefully, spends past the cap); a runner that grades the wrong tree or the wrong binary.
- **S1:** a model that forges under another name, deploys another session's bundle, reaches
  a path outside the workspace, writes `ouroboros.toml`, or gets `author` from a parameter;
  a forge that runs without a ledger entry; the tool visible when the switch is off.
- **S2:** a record that widens for the wrong policy name, survives a demotion, or promotes on
  a report about other bytes; evidence written for non-human answers or read over the
  gateway; a dry evaluation that records or disturbs the live instance; a replay whose
  numbers depend on order.
- **S3:** a script that grades the wrong worktree, skips a gate silently, or opens a PR
  without the protected-namespace section.
- **S4:** a boot that deploys an unverified bundle or applies promotions over an existing
  record.

The reviewer proves findings with running exploits (PROVED) or states them (PLAUSIBLE),
deletes each enforcement point in turn and expects a red test (a survivor is a finding), and
leaves its scripts in its scratch directory. The fix wave goes back to the implementer with
that directory's path. I re-run every former survivor before the slice is cherry-picked.

## 6. Integration and the gates I run

Branch `self-integrate` from `dev`. Per slice, after its review: cherry-pick, `mix compile
--warnings-as-errors`, the slice's suites. After the wave: the full `mix test` detached,
`mix dialyzer`, `cargo +1.95 clippy --all-targets -- -D warnings` (both feature sets),
`cargo test` for the crates touched, `make bench-local`, `bench/self/selftest.sh`,
`bench/self/improve-selftest.sh`, golden and protocol-docs drift. Then a PR from `self` to
`dev`.

## 7. What stays with a human after the code lands

1. A model key and a spend. Two paid corpus runs; the numbers into `BENCHMARKS.md` §5.
2. `ouro wasm keygen`, the three signer variables, `OUROBOROS_POSTURE=self`.
3. The first `improve.sh` run and its PR. Then three.
4. A forged policy that resolves the `mix test` and `cargo test` asks, its replay over at
   least fifty decisions, `ouro policy promote` with the report in hand.
5. `make self-export`, committed by the outer loop's PR.

None of these is code. Each is a gate the model cannot pass for itself, which is the claim.
