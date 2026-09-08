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
`Ouroboros.Control.Permissions.suggest/1` offers `Forge(<name>)` for an ask that carries one.
The corpus is in `test/control/permissions_test.exs`.

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

### S3. The outer loop

<!-- S3 -->

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

**S-D13. Only the operations that pass the name on put it in the request context.** A
`deploy` names an artifact id and a `status` names nothing, so both carry no `forge` key and
match no `Forge(…)` rule at all — they can be denied or asked and never allowed by one. The
narrow reading, deliberately: an allow on `Forge(vet)` is a sentence about building `vet`,
and reading it as permission to deploy whatever some id resolves to would be a second
sentence nobody said. The alternative — resolving the id against the ring at classification
time — would have let an unverified file on disk name itself into a permission decision.

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

**S-D17. `authority` is a class; `cause` is the link.** A tool is handed `scope`, `audit` and
`principal` and no permission decision, so these entries say `%{decision: :granted, reason:
:native_tool_call}` — an honest statement that the loop admitted the call — and never a rule
id this module did not see. The chain to the decision is two hops and each is written by
whatever knew the fact: this entry's `cause.signal_id` is the `:tool_call` ledger entry for
the call, whose `attempt.permission_entry_id` names the `:permission` entry. When this node's
audit stream is off the cause carries its type and no id, rather than inventing one.

**S-D18. One proposal format, one validator.** A project directory's `manifest.json` — the
same file `Ouroboros.Runtime.Capabilities` reads for an operator's `capabilities.admit` —
supplies the description, the evaluation spec and `start.config`, and the `eval` and
`start_config` parameters override it. Both go through `Runtime.Capabilities`' own functions
(`wasm_manifest/1`, `wasm_eval/1`, `wasm_start_config/1`, extracted for this), so the
operator's file and the model's parameter cannot come to disagree about what an evaluation
spec is. The `name` is always the parameter, and a manifest naming something else is refused
before the forge.

**S-D19. `ouroboros.toml` is a protected write.** `Rules.protected_write?/1` refuses any path
whose final component is `ouroboros.toml`, case-folded for `.git`'s reason, at every depth —
the workspace hook manifest `Ouroboros.Provider.Native.Hooks` reads to decide which programs
run around a tool call. It joins the list for the reason the list exists: the engine's rules
and the ledger were already fenced, and this file was reachable through an ordinary `write`
in an ordinary workspace, which is where a self-improving session lives. Final component
rather than segment, so a directory by that name is not it. The worktree-delivery exemption
is unchanged.


<!-- S2-decisions -->

<!-- S3-decisions -->

<!-- S4-decisions -->

## 5. Open

<!-- open -->
