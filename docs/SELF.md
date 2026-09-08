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

## 3. Slices

### S0. The measure: `bench/self`

<!-- S0 -->

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
and a tool is promoted only where it contradicted none of them.

**The corpus.** `Ouroboros.Control.PolicyEvidence` writes one NDJSON row per human answer at
`<data_dir>/policy/evidence.ndjson` (directory `0700`, file `0600`), at
`Control.Permissions.record/2` — the one seam where the full request and a human's answer are
both in scope. The row holds `{at, node, session_id, tool, mode, fingerprint, decision, scope,
permission_entry_id, document}`, where `document` is **exactly**
`Wasm.PolicyEngine.document/1`'s output for the request and `fingerprint` is the digest
`Control.Permissions.fingerprint/1` writes into the `:permission` ledger entry beside it. It was
needed because nothing durable held the request a policy would be shown: a `:permission` entry
holds a digest of the command line, and so does the session journal's approval record. Nothing
is written for `actor: :rule` (that measures the rules) or `actor: :classifier` (that is the
component grading itself). Bounded at 10 000 rows or 64 MiB, oldest dropped by one rewrite to
90% of the bound. A write failure is logged once per reason per boot and never refuses the
answer that caused it.

**The record.** `Ouroboros.Control.PolicyPromotion` is a GenServer on `Control.Grants`'
checkpoint discipline — write, fsync, then acknowledge; a failed checkpoint is not applied and
not reported as promoted — with storage from `config :ouroboros, :policy_promotion_storage` (ETS
in dev and test). It holds one policy name at one component sha and, under them, the tools
promoted and the demotions since. Promoting under a different name, or under the same name at
different bytes, is refused until `clear/1`. The order of a promotion and a demotion is the
record's own sequence number rather than a timestamp.

**The engine.** `PolicyEngine.evaluate_with/3` verifies provenance exactly as the live path does
(the manifest the register row names, against this node's trust policy, held to the row's sha
and required to declare `:policy`), stands the component under `wasm/policy/dry/<sha>`, asks
once, and records nothing. `replay/2` counts `decisions`, `agreements`, `contradictions`
(`allow` where the human denied), `would_resolve` (`allow` where the human approved), `stricter`
(`deny` where the human approved), `asks` and `unreadable` per tool, carries contradiction rows
holding a fingerprint, a session id and a timestamp and never a document, and seals the whole
thing with a `report_sha256`. `promote/5` refuses a report that does not name this policy's sha
or does not hash to its own digest, **re-runs the replay**, and refuses unless the re-run shows
`decisions >= 50` and `contradictions == 0` for that tool. `record/2` gained the canary: a human
`deny` for a promoted tool that the promoted bytes would have allowed demotes that tool inside
the same call and logs a warning naming the tool, the session and the sha.

**What a promotion cannot do.** It cannot survive a re-deploy: `settle/6` honours an earned
`allow` only when the record's name *and* sha match the row about to answer. It cannot be
transferred: `allowable_tools/1` is name-scoped. It cannot happen without a named human actor,
without a ledger entry, or without a durable checkpoint.

Proved in `test/control/policy_evidence_test.exs`, `test/control/policy_promotion_test.exs`,
`test/wasm/policy_promotion_test.exs` (the real `no-network-shell`, signed and deployed through
the real rollout, for the dry path and the replay's arithmetic; a scripted verdict for what
happens to an `allow`, because that component never says one), and appends to
`test/effect_ledger_test.exs` and `test/provider/native/loop_ledger_test.exs`.

Not in this slice: a classifier, a model anywhere in the promotion path, promotion without a
human actor, fleet-wide replay, and the gateway verbs and `ouro policy` CLI (S2b).

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

## 4. Decisions

Numbered `S-D<n>`; each slice appends its own under its marker and never renumbers another's.

<!-- S0-decisions -->

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

**S-D20. The corpus is written at `Control.Permissions.record/2`, for human answers only, and
nowhere else.** Every seam that asks a human — the native loop, the interactive plane's external
approvals, the interactive shell, the ACP seam — records the answer through that one function,
so writing there is what makes the corpus complete without four call sites agreeing to be
correct. The native loop passed no request at all before this (plan §0 row 2); its four
human-answer sites now pass `request: permission_request(state, classified)` and the other
eleven `record/6` call sites are unchanged. A row is written even when the ledger refused the
entry, with `permission_entry_id` left `nil` rather than naming an entry that does not exist.

**S-D21. `replayed_at` is outside `report_sha256`.** The plan says the digest covers "everything
else"; taken literally that includes the timestamp, and two replays of one corpus would then
produce two digests, which is the opposite of what `promote/5` asks the digest. The digest
covers everything except itself and `replayed_at`, contradiction rows are sorted, and both
determinism and order-independence are tests.

**S-D22. One policy, one sha, per record — and the sha is checked again at the moment of the
`allow`.** A promotion is a measurement of one component's judgement against decisions humans
made. A re-deploy under the same name is different bytes that have measured nothing, so
`honoured_allow_tools/2` requires the register row's sha to equal the record's before it adds a
single earned tool. Without it, widening a policy would be a one-time cost that every later
version of it inherits.

**S-D23. A dry evaluation stands its own instance and records nothing.** `wasm/policy/dry/<sha>`
rather than the live `wasm/policy/<sha>`: a replay of ten thousand requests must not be able to
touch the state of the component deciding this node's live permissions. It writes no
`:permission` entry and no evidence row, because a ledger full of decisions nobody made is worse
than no ledger. A verdict outside the grammar is an *error* on this path rather than the `ask`
the live path reads it as — a replay counting malformed answers as good behaviour would promote
on them.

**S-D24. One human contradiction demotes.** Not a vote and not a ratio: the threshold a
promotion cleared was *zero* contradictions over fifty decisions, so a single one is the
evidence for that promotion being false, and re-earning it is a replay away. The canary is
bounded, total, and cannot change the answer it runs beside.

**S-D25. The ledger sits on opposite sides of a widening and a narrowing.** A promotion writes
its `:policy_promotion` entry *before* it checkpoints, and a ledger that refuses refuses the
promotion. A demotion and a `clear` write theirs *after*, and a ledger that refuses is logged
rather than obeyed. This is `Control.Permissions`' own rule for an unrecordable answer: an allow
nobody can account for has not been granted, but refusing without an audit entry is still
refusing. The plan's blanket "a ledger that refuses refuses the write" would have made a broken
audit trail into a permission surface nobody could narrow.

**S-D26. A promotion says a component may be listened to, not that it is useful.** The
thresholds are `decisions >= 50` and `contradictions == 0`, so a component that answers `ask` to
everything is promotable and resolves nothing. `would_resolve` is the number that says whether a
promotion is worth making, and it is in the report for an operator to read; adding it as a third
gate would be inventing a threshold the plan did not set.

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

## 5. Open

<!-- open -->
