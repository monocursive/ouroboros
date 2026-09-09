# Self-improvement, v1

Status: **proposal**, 2026-09-08. Written against `dev` at `160ca08`; every file cited
below was read at that ref. This document proposes work. Nothing in it is implemented.

## 0. The claim this plan builds toward

Ouroboros self-improves when a session running inside it produces a change to its own
behaviour that

1. the model authored,
2. passed gates the model cannot pass for itself,
3. measured better than before on one fixed benchmark, and
4. is running afterwards without a human editing code.

Humans stay at exactly the gates the model cannot pass: signing, merging, and promotion.
Everything else the runtime does on its own. The plan is four slices and one posture. It
adds one tool, one durable record, one benchmark, and one script. It refuses everything
else (§6).

## 1. Why nothing self-improves today

These are source facts, not opinions.

| Fact | Where |
|---|---|
| The native loop's tool list is static and has no forge in it. The `capability` tool can `list` and `call`, not build. | [`tools.ex:78`](../../lib/ouroboros/provider/native/tools.ex), [`capability.ex:110`](../../lib/ouroboros/provider/native/tools/capability.ex) |
| The forge is reachable only from mesh agents driven by typed signals, whose principal is `context.agent.id`, and from planner forge steps. Neither has a coding loop. | [`effects.ex:222,360`](../../lib/ouroboros/agent/effects.ex), [`runner.ex:128`](../../lib/ouroboros/agent/effects/runner.ex) |
| The three switches that gate forging are off by default and nothing outside tests can turn the grants one on: `Grants.grant/3` has no caller in `lib/`. | [`config.exs:92,157`](../../config/config.exs), [`grants.ex:137`](../../lib/ouroboros/control/grants.ex) |
| A policy component's `allow` is honoured only for tools in `:policy_allowable_tools`, which is empty, and only the policy named by `:wasm_policy`, which is `nil`, is consulted. Both are static config. "A policy component narrows until an operator widens it." | [`policy_engine.ex:7-33,254,334`](../../lib/ouroboros/wasm/policy_engine.ex), [`config.exs:353-354`](../../config/config.exs) |
| Hooks from an untrusted workspace can only narrow; trust is a workspace-level config list. Champion/challenger is deferred in lane W. | [`hooks.ex:128,869`](../../lib/ouroboros/provider/native/hooks.ex), [`rollout.ex:124`](../../lib/ouroboros/wasm/rollout.ex) |
| There is no benchmark number, and no corpus that runs a real model. | [`BENCHMARKS.md`](../BENCHMARKS.md) |
| The surfaces that decide coding ability, the loop, prompts, tools, context strategy, are unpatchable by design and are not in any forge lane. Their only route is the repository. | [`ARCHITECTURE.md:438-444`](../ARCHITECTURE.md), [`WASM.md` §9](../WASM.md) |

So the machinery for eating the tail exists, the model is not connected to it, and the
one direction that would let a self-change compound, loosening, is closed rather than
evidence-gated.

## 2. Two loops, one measure, one rule

**The outer loop, at source level.** A native session changes the Ouroboros repository, a
second native session reviews it adversarially, CI runs, a human merges, a release ships.
This loop can change anything, including the loop itself. It is where coding ability
improves, and it needs no new runtime code.

**The inner loop, at runtime.** A native session forges a lane-W component, a capability or
a policy, which is signed, evaluated, deployed, and later promoted on evidence. This loop
changes judgment and adds contained capabilities without a release. It needs one tool and
one record.

**One measure.** `make bench-self` runs a real model against tasks drawn from this
repository's own history and reports pass rate and cost. Both loops report their delta
against it. A change with no delta is not an improvement, it is a change.

**One rule.** The model never signs, merges, approves, or promotes its own change.
Loosening happens only on evidence that is itself recorded: a replay report against human
decisions, or a benchmark delta. The rule is what lets the sandbox stay exactly as strict
as it is while the direction of change is restored.

## 3. The `self` posture

A named configuration, never the default. It is the posture this project's own development
runs in.

| Setting | Value in `self` | Why |
|---|---|---|
| `forge_signer` | `{Signer.Local, private_key: …}` on one machine; `Signer.Remote` to a `:signer` node on a fleet | The signer's policy is the gate the model cannot pass: namespace, world, imports, and a required eval spec. [`signer.ex:98`](../../lib/ouroboros/upgrade/forge/signer.ex) says plainly that a local key is a dev-loop choice and not custody. |
| `signing_require_wasm_eval` | `true` (already the default) | A forged component with no evaluation spec is refused before a signature exists. |
| `wasm_forge_placement` | `:local` | The forge already runs under the builder sandbox with a read fence. Forwarding to a `:builder` node is a later switch, not a v1 need. |
| `:wasm_policy`, `:policy_allowable_tools` | read from the durable promotion record (S2), config as fallback | The two settings that make "earned" possible. |
| `OUROBOROS_NATIVE_MODEL` | a frontier model | The loop needs a brain worth measuring. |
| `[budget] max_cost_usd` | set, per task | Every corpus run and every improve run has a spend cap or does not start. |

Everything else stays as it is: permissions deny or ask, the native shell sandboxed, the
helper sealed, the effect ledger on. The posture turns the loop on; it does not turn a
fence off.

## 4. Slices

Each slice runs under the per-slice protocol already in use on this repository: one
implementer, a separate adversarial reviewer with a stated threat model who proves findings
and mutation-tests the enforcement points, a fix wave, and the integrator re-running the
former survivors before the commit.

### S0. The measure: `bench/self`

**What.** A corpus of twenty to thirty tasks extracted from this repository's git history,
run by a real model through the existing run client, graded by the hidden tests the
original commit added.

**How.**

- Extraction, `bench/self/extract.exs`: candidates are commits since June that touch
  `lib/` and add or modify `test/**/*_test.exs` (256 exist; 79 are `fix` commits). A
  candidate becomes a task only if its test files fail at the parent and pass at the commit,
  checked at extraction. A task is `{base_sha, instruction, hidden_tests, timeout}` where
  the instruction is the commit subject and body with the diff removed. Tasks that need more
  than ten minutes of compile plus test at the parent are dropped.
- Runner, `bench/self/run.sh`: mirrors [`bench/local/run.sh`](../../bench/local/run.sh)
  exactly, one daemon on a scratch data dir, `ouro run --provider native --stream-json`
  per task, except that the model is real, each task gets a worktree at `base_sha` with
  `deps/` and `_build/` copied from a warm cache, and the grade is: hidden tests pass, the
  agent modified no test file, and the run finished inside its budget. The
  [`Report`](../../tui/src/run.rs) object already carries status, usage, and
  `files_changed`.
- Output: a `result.json` with pass rate, cost, turns, approvals, and wall time per task,
  kept as an artifact, and the headline appended to [`BENCHMARKS.md`](../BENCHMARKS.md)
  §4 by hand with the date, the model, and the spend.
- Guard: the runner refuses to start without `--spend <usd>`, and stops when it is reached.

**Acceptance.** The corpus runs twice with the same model and the two pass rates differ by
no more than the noise the doc then states. The number is in `BENCHMARKS.md`.

**Not in this slice.** Terminal-Bench. Run it once later, on Linux with docker and a key,
as the external anchor; it answers a different question and the doc already says so.

### S1. Head to tail: the `forge` tool

**What.** A native tool that lets a session build, sign, and deploy a lane-W component,
through the fences that already exist, under a permission rule an operator can write.

**How.**

- `Ouroboros.Provider.Native.Tools.Forge`, added to the list at
  [`tools.ex:78`](../../lib/ouroboros/provider/native/tools.ex). Operations:
  `preview` → [`Wasm.Forge.preview/2`](../../lib/ouroboros/wasm/forge.ex) (the dry build,
  so the model sees a refusal before spending a signature); `forge` →
  `Wasm.Forge.forge/2`; `deploy` → `Wasm.Forge.deploy/3` to `[node()]`; `status`. The
  project files are read from a directory inside the workspace the model wrote with its
  ordinary tools, through the workspace containment `read` uses, and handed to the forge
  as the `files` map [`ForgeWasmCapability`](../../lib/ouroboros/agent/effects.ex) already
  hands it. C9's allow-list, the lock pin, and the builder sandbox apply unchanged.
- `author` in the signed manifest is `"session:" <> session_id`, taken from the same
  server-owned principal the permission engine already receives
  ([`permissions.ex:104-112`](../../lib/ouroboros/control/permissions.ex)). It is never a
  parameter.
- Permission: every operation is classified `:execute` in
  [`tools.ex:472`](../../lib/ouroboros/provider/native/tools.ex) with `context.forge` set
  to the name, and two new patterns, `Forge(<name>)` and `Forge(*)`, are added beside
  `Capability(…)` in [`pattern.ex:24`](../../lib/ouroboros/control/permissions/pattern.ex)
  and [`matcher.ex:38`](../../lib/ouroboros/control/permissions/matcher.ex). An
  unconfigured node asks the human once per name; "don't ask again for `Forge(*)`"
  persists at workspace scope through the existing modal answer. Plan mode refuses it,
  because it is an execute.
- Ledger: the call is a `tool_call` entry; forge and deploy settle it with the artifact id,
  the component sha, and the rollout's eval report. The bytes never enter the ledger, as
  `Wasm.Forge` already insists.
- After `deploy`, the component is `wasm/<name>` in the rollout register, and the next turn
  reaches it through the existing `capability` tool under `Capability(<name>)`.
- Scaffold: a checked-in skill under `.agents/skills/forge/` carries the guest SDK template
  and the world contract, so the model has the shape without a new tool operation and
  without the runtime resolving an SDK path from a cwd (the hole lesson 29 closed).

**Acceptance.** Live and on record: from the prompt "write a capability that checks
commit message format against CONTRIBUTING", the session writes the project, previews,
forges, deploys, and calls it in the following turn. The ledger shows the `Forge(<name>)`
decision, the `tool_call` with the artifact id, and the rollout entry with its eval report.
Mutations that must go red: remove the permission check; let a parameter reach `author`;
set the signer to `Deny` and expect the typed refusal; strip the eval spec and expect the
signer's refusal.

**Stated limit.** The eval spec inside the signature is written by the model, so it proves
the component answers what its author claimed, not that it is useful. Usefulness is
measured by S0 and, for policy, by S2.

**Not in this slice.** The BEAM lane (ambient authority once admitted; it stays on the
mesh-agent effect surface). Hooks (workspace-declared, trusted by workspace; the model
stays out of `ouroboros.toml`). Today that file is **not** a protected write: the list at
[`rules.ex:47`](../../lib/ouroboros/control/permissions/rules.ex) holds only `.git` and
`.ouroboros`. S1 adds `ouroboros.toml` to it, because a model that can write the file that
declares hooks can declare its own, and a human edits it the way a human edits
`.ouroboros/`.
Forwarding to a `:builder` node.

### S2. Earned widening: policy promotion by replay

**What.** The one place the direction of change is restored. A forged policy component
can come to resolve `ask` decisions for a tool, but only after a replay against recorded
human decisions shows it never contradicts them, and only by a human running one command
with that report in front of them.

**How.**

- A durable, ledgered record, `Ouroboros.Control.PolicyPromotion`, under `Control.` so the
  fast patch lane cannot replace it, holding `{policy_name, allowable_tools, evidence_sha,
  promoted_at, actor}` on the same checkpoint discipline as `Control.Grants`.
  [`PolicyEngine.allowable_tools/0`](../../lib/ouroboros/wasm/policy_engine.ex) and
  `live_policy/2` read it first and fall back to config.
- `PolicyEngine.evaluate_with/3`: the existing consult path run dry against a named
  artifact rather than the live one, recording nothing, with the same request projection.
- `ouro policy replay <name> [--since]` (operate scope): pulls the `:permission` and
  approval entries that carry a request and a human answer from
  [`EffectLedger.list/2`](../../lib/ouroboros/agent/effect_ledger.ex), fleet-wide through
  `ledger.list`, runs the candidate on each, and reports per tool: decisions, agreements,
  contradictions (the component allowed what a human denied), asks it would have resolved.
- `ouro policy promote <name> --tool <t> --evidence <report>`: refuses unless the report
  names this policy's sha, covers at least fifty human decisions for that tool, and shows
  zero contradictions. Writes the record. The actor is the human who ran it.
- Canary: honoured allows are already ledgered
  ([`policy_engine.ex:72`](../../lib/ouroboros/wasm/policy_engine.ex)). One addition: a
  human `deny` on a request the policy allowed writes a demotion record for that tool and
  says so in the session. Rollback of the component itself is the existing
  `wasm.rollback`.

**Acceptance.** A forged policy that resolves the `mix test` and `cargo test` asks in this
repository replays with zero contradictions over at least fifty decisions; after
promotion, approvals per corpus task drop and the pass rate does not; an injected
contradiction demotes the tool within one turn. Mutation: remove the contradiction check
and the promotion of a bad policy must fail the test.

**Not in this slice.** A classifier as the default. A model in the promotion path.
Promotion without a human actor: v1 keeps the human at `promote` with the number in front
of them. A v2 may let a scheduled job promote on the same evidence; this document does not.

### S3. The outer loop: Ouroboros works on Ouroboros

**What.** The review protocol this repository already runs by hand, run by Ouroboros
sessions, producing pull requests with the corpus delta in the body.

**How.**

- `bench/self/improve.sh <task.md>`: a worktree from `dev`; the implementer is
  `ouro run --provider native` with the task and the implementer brief; the reviewer is a
  second `ouro run` in the same worktree with the adversarial brief (threat model, PROVED
  versus PLAUSIBLE, a mutation table); the fix wave is `ouro run --continue` on the
  implementer's session with the reviewer's findings; the gate is `make test`, dialyzer,
  and protocol docs; `make bench-self` runs when the change touches
  `lib/ouroboros/provider/native/**`; the script opens the PR with the review and the
  delta in the body. A human merges.
- The two briefs are checked in under `docs/self/briefs/`, distilled from the operating
  lessons this repository has accumulated, so the reviewer is told the same things a
  babysitter would tell it.
- A change under `lib/ouroboros/control/`, `upgrade/`, or `storage/` flags the PR for
  human review of that hunk regardless of the review's verdict: the namespaces the verifier
  protects at runtime stay protected at the source level too.
- v1 is a script. Encoding it as a durable orchestration plan
  ([`plan.ex`](../../lib/ouroboros/orchestration/plan.ex), `:coding` steps through a team)
  is v2, after the script has produced three merged PRs and the shape is known.

**Acceptance.** One merged PR authored inside Ouroboros, review included, with the corpus
delta in the body. Then three.

**Not in this slice.** Auto-merge. Any change to the merge rules of this repository.

### S4. Ship what it forged

**What.** Promoted policy components and their promotion records are exported into
`priv/self/` and committed by the outer loop's PR; the `self` posture deploys them at boot
when absent. The next release carries what the runtime learned, which is the tail reaching
the mouth.

**How.** A Makefile target over the existing `wasm.download` and bundle path, and a boot
task beside the WASM boot recovery that deploys a bundle whose name is not yet live.

**Acceptance.** A fresh install in the `self` posture boots with the promoted policy live
and reproduces the S2 approval count on the corpus.

## 5. Order, size, and what each proves

| Order | Slice | Size | What is true afterwards |
|---|---|---|---|
| 1 | S0 measure | M | There is a number. |
| 2 | S3 outer loop, first PR | S script, then the PR is the work | Ouroboros has changed Ouroboros, measured. |
| 3 | S1 forge tool | M | A session can change the runtime it runs in. |
| 4 | S2 promotion | L | A self-change can loosen, on evidence, reversibly. |
| 5 | S4 ship | S | The next version contains what this one learned. |

S3 runs before S1 because it needs no runtime change and produces the first honest
instance of the claim in §0. S1 and S2 are the runtime half. S4 closes the loop between
them.

## 6. What this plan refuses, and the precondition for each

| Refused in v1 | Would need first |
|---|---|
| Lane T, tools as components | S1 in use, and a measured case where a forged capability could not do what a tool was needed for |
| Lane A, agent brains as components | Nothing; the loop's value is its host-side integration surface, as WASM.md §9.2 argues |
| BEAM-lane forge from the native loop | A custody story that is not a key in the application |
| Hooks forged by the model | A trust model for hooks that is per component rather than per workspace |
| Auto-merge | Three merged S3 PRs and a written merge rule |
| Promotion without a human actor | S2 running for a month with zero demotions |
| A replicated ledger | A second machine that owns sessions in production |

## 7. Risks, stated

- The corpus is small and drawn from one repository's history. It measures Ouroboros on
  Ouroboros, which is the claim, not general ability, which is Terminal-Bench's.
- A local signer key lives with the application. On one machine that is the dev loop the
  signer module documents; on a fleet it is the `:signer` node or nothing.
- A corpus run costs real money and real time; the spend cap and the ten-minute task
  ceiling are load-bearing, not polish.
- Every task compiles this repository. The warm `deps/` and `_build/` copy is what keeps a
  task under ten minutes, and the extraction step drops tasks that cannot meet it.
- The eval spec in a forged component is the model's own claim about itself. The plan says
  so in S1 and measures elsewhere.
