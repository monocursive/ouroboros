# Ouroboros architecture

The current shared mechanisms, storage migration, and restart matrix are documented in
[runtime simplification](SIMPLIFICATION.md).

## Definition of done

This tree is what [the core reduction](proposals/core.md) left standing in September
2026, and it is complete when all of the following are executable and tested. Each item
describes a plane that exists; the first nine are local implementation claims backed by
deterministic tests, and none of them implies the external claims in the tenth.

1. An interactive session outlives its caller, emits durable ordered events, is replayed
   without gaps, survives its coordinator crashing, and resolves to explicit
   completed/failed/cancelled/lost state. Its history can be rewound, forked and handed
   off, and every effect it causes is in a ledger that is checkpointed before the effect
   starts and settled after it.
2. A native session spawns subagents on other nodes of the cluster over Erlang
   distribution. Placement is a cluster fact (`Cluster.Facts`, operator tags); each child
   holds its own git worktree lease, and the lease — never a PID — is the unit of
   ownership. A mesh agent is supervised locally and addressed from another node through
   a typed signal.
3. Nodes form a cluster without anyone connecting them by hand, boot a role-shaped tree
   (`:core` full, `:builder` formation plus the helper pool, `:signer` formation plus the
   signing service), refuse to place work on a node that cannot run it, relocate forge
   builds onto a least-privileged builder, and ship as one embedded release whose node
   identity, cookie, and distribution transport are explicit and fail closed on the
   distributed path — told nothing at all, the release boots a standalone single-machine
   posture instead, with distribution off and no cookie in existence.
4. The model's shell runs under an OS sandbox — macOS `sandbox-exec` or Linux
   bubblewrap — whose label is honest or is refused: a `workspace_write` session on a
   node with no backend does not run `bash` unsandboxed, protected paths and this node's
   credentials are fenced by the backend rather than by a rule, and `:unrestricted` is
   the operator asking for no sandbox by name.
5. An agent-authored Cargo project can be validated without being built, compiled to a
   WebAssembly component under that sandbox with no network, signed through a seam the
   forge cannot satisfy itself, stamped with a durably allocated epoch, deployed behind a
   per-node health probe, held to a declarative evaluation spec carried inside its own
   signature, and — when the probe or that spec fails — rolled back to absence on every
   node, or quarantined when the evidence is ambiguous. A component's authority is its
   import list, enforced by the helper's linker on the loading node.
6. The signing authority runs on a `:signer` node rather than inside the application it
   authorizes: the key is read at boot from a file that node mounts, an independent
   policy recomputes the whole submitted manifest from the bytes and refuses a world its
   kind does not require, and every decision — issued and refused — is durably journaled
   before any signature is returned.
7. Two deny-by-default authorities decide what may happen, both node-local and durable:
   permission rules for what the model may do to this machine, grants for what an agent
   may do to the cluster. Every rule-made decision, every human answer, and every forge
   and deploy is recorded in the effect ledger whether it ran or was refused.
8. Under the `self` posture a session forges a component this runtime then runs; what a
   policy component may resolve is promoted on replayed evidence and can be withdrawn;
   and the outer loop produces a change a human signs, merges and promotes, measured on
   one fixed benchmark. Built and selftested ([SELF.md](SELF.md)); the first unattended
   run is an operator's decision, not a claim here.
9. A data directory written by the tree before the reduction — `dev` at `3bc8887` —
   boots on this one: every surviving checkpoint decodes, or is quarantined by name and
   reported, and `make boot-gate` proves it twenty times.
10. The documentation distinguishes those proofs from partition tolerance, billing, a VM
    boundary around the shell or the build, signing custody *outside the distribution
    trust domain*, evaluation beyond a declared spec, any release-installation or
    self-update lane, any claim that grants or permission rules sandbox loaded code, and
    any claim that node roles, placement checks, or signer isolation constrain a node
    that has already completed the distribution handshake.

## Planes and ownership

### Cluster plane

`Ouroboros.Cluster` owns two things nothing else may decide: which tree this node boots,
and how it finds the others.

Role (`:core`, `:builder`, `:signer`) is resolved once, at application start, before any
child is supervised — an unrecognized role raises rather than booting the privileged
tree. `:core` starts the full runtime. `:builder` starts formation and
`Ouroboros.Wasm.Supervisor` — the helper pool a forwarded lane-W forge needs in order to
read imports (W22) — and nothing that holds durable work: no stores and no sessions.
`:signer` starts the durable-directory owner when a data directory is configured, then
one process: `Upgrade.Signing.Service`, which holds the key, applies the signing policy,
and journals every decision, then formation. That process leads the role-specific
`rest_for_one` chain on a signer, so the node is not askable before its key is loaded,
and it refuses to boot — key missing, malformed, unidentified, or journal unusable —
rather than starting into a state where denial and misconfiguration look identical.

Formation is libcluster, off by default, selected by `OUROBOROS_CLUSTER_STRATEGY`. On a
core node it sits in the final `one_for_one` surface subtree: it connects and observes,
and nothing rebuilds state from it. A discovery strategy's crash restarts neither the
durable owners above it nor unrelated helpers beside it.

Invariant: role is a placement fact, not an authority boundary. Every check that reads a
remote role also requires the target to be connected and running this runtime, and the
answer is only ever an observation about a cooperative cluster — see "Safety
boundaries".

### Mesh

`Ouroboros.Mesh` owns logical IDs and placement. Each member is a real
`Jido.AgentServer` under `Ouroboros.Jido` supervision. A local directory monitors the
PID and joins it to `{:ouroboros_agent, logical_id}` in a named `:pg` scope.

Typed Jido signals are the protocol. Cross-node calls work because Erlang PIDs and
monitors are distribution-native. `:erpc` is used when an operation must execute inside
a selected node's ownership boundary.

Invariant: a PID is an observation, not durable identity. Callers retain logical IDs or
session references, never persist PIDs.

`Ouroboros.Mesh.ReceiveMessage` is the action every mesh agent routes
`ouroboros.agent.message` to. It bounds the inbox by count and by bytes, so a
remote-reachable send cannot grow an agent's state without limit, and it is what makes
`last_message` the field the rest of this runtime reads.

> The coordination stack that used to sit here — teams, a durable orchestration DAG, and
> an objective-level control loop with a planner and evaluator — was deleted in September
> 2026. See [the core reduction](proposals/core.md) §3 D3 for why: native subagents run
> cross-node through `Interactive.Task`, `Workspace.Worktree` and `Cluster.Facts`, and
> never used any of it.

### Session execution plane

> The nine wrapped vendor CLIs that used to sit beside the native loop — and the ACP
> client, the per-provider capability matrix, and the transport-specific approval bridge
> that existed for them — were deleted in September 2026. See
> [the core reduction](proposals/core.md) §3 D2. `:native` is the only provider;
> `Ouroboros.Interactive.State.new/2` refuses any other name before a workspace lease is
> taken, and a session record that names one still loads and lists.

`Jido.Harness` remains the session and run machinery: normalized events, cancellation, and
short-lived retained journals. The native session is registered as a `jido_harness`
provider and `Interactive.Task` still speaks `Jido.Harness.Session`; unwinding that is
[§7](proposals/core.md#7-what-comes-after), not this reduction.

`Ouroboros.InteractiveSession` owns domain truth:

- the workspace, owner node, and normalized request policy;
- the Harness session ID and provider resume ID;
- a durable exclusive Harness cursor and a separate Ouroboros event sequence;
- bounded redacted replay, per-turn outcomes, and explicit loss state; and
- node-aware info/replay/subscribe/await/close routing.

One `Ouroboros.Interactive.Task` GenServer serializes transitions for a session. It
persists cursor plus projected events in one checkpoint and only then broadcasts them.
`subscribe/2` registers and snapshots the backlog in that same process, eliminating the
replay-then-subscribe race.

When workspace roots are configured, that same coordinator owns a symlink-resolved
lease before it inspects or starts Harness. Read-only work shares a root; write work
is exclusive against overlapping roots. The private release capability is never
checkpointed. A coordinator crash releases via monitoring, then recovery reacquires
before reattachment. Durable nonterminal owners become fail-closed recovery
reservations across manager or downstream-registry restart; only the exact registered
coordinator can claim one. This authority is node-local.

The coordinator scans live Harness metadata before starting a missing session. That
closes the crash window between a start and saving the returned id, where an
unconditional retry could otherwise launch duplicate billable work.

#### Worktrees

`worktree: true` provisions a `git worktree` before the lease is taken,
and the lease is taken on the worktree rather than on the repository. `Ouroboros.Workspace.Worktree`
runs `git` as an argv list — never a shell string, and the exact list is asserted through
an injectable runner — canonicalises the created path through `Ouroboros.Workspace.Path`,
and hands *that* to the existing admission machinery, so every containment check the
runtime already performs now describes the worktree. A workspace that is not a git
repository is refused; a subdirectory of one gets the same subdirectory inside the
worktree. The session records the result as `worktree: %{path, root, branch, base_commit,
repository}` on its durable state, and the provider is told nothing beyond `cwd`.

Provisioning is idempotent, because admission runs again after every restart: a record
that already holds a worktree is returned unchanged rather than stranding the directory
its session was working in. Cleanup runs only when the session is *terminal* —
`terminate/2` fires on a supervisor restart too — and removes the directory only when
`git status --porcelain` inside it is empty, untracked files included. A worktree holding
uncommitted work is left where it is and named in the terminal event. A marker file under
the worktree root makes the set recoverable: `Worktree.reconcile/1` runs from
`Ouroboros.Application.start/2`, removes clean strays, and reports dirty ones without
touching them.

#### The native provider

`Ouroboros.Provider.Native` *is* the tool loop. It registers through
`:jido_harness, :providers` as the only provider, declares one session transport whose
adapter is a supervised GenServer in this VM, and emits normalized events into the
journals, the gateway stream and the cells.

Because the loop is here, three things are possible that are structurally impossible for a
CLI driven from outside: a tool call can be blocked on a human approval before it runs, a
steered message can be delivered between two tool calls of a running turn, and an
interrupt can stop the turn after the current tool rather than by killing a process. It
is therefore where hooks, permission rules, compaction, file checkpoints, and MCP
attach natively — all of which have landed.

- `Ouroboros.Provider.Native.Loop` drives one turn. It runs in a task so the session
  process stays answerable, emits through a function, and takes control on its mailbox.
  Models are reached through `Ouroboros.Provider.Native.Model`, a single-callback
  behaviour whose ReqLLM implementation opens every provider ReqLLM ships. `jido_ai` is
  used only for `ToolAdapter`, which turns a `Jido.Action` schema into the model's JSON
  Schema. The tool schemas are built once per turn and held in the loop's state: a tool
  list that could change between two calls of one turn is a changed cached prefix.
- `Ouroboros.Provider.Native.Tools` is the fifteen-tool set and the classification the
  permission engine is asked about — the tool, its mode (`:read`/`:write`/`:execute`/
  `:network`), the paths it touches, the subset it would *change*, the domains it would
  reach, and the command when there is one. Every path goes through
  `Ouroboros.Provider.Native.Paths`, which builds on `Ouroboros.Workspace.Path` and adds
  the case a tool loop needs: a file that does not exist yet, resolved through the deepest
  ancestor that does, so a write through a symlinked parent is judged by where that parent
  really points. `Ouroboros.Provider.Native.Exec` is the shared bounded process-group
  runner: argv with no shell for `grep` and Git, `/bin/sh -c` with separated stderr for
  hooks and `[checks]`, and the same group deadline beneath the native `bash` tool.
- `Ouroboros.Provider.Native.Session` is the transport. It writes the conversation to
  `Ouroboros.Provider.Native.Checkpoint` — content-addressed, `0600`, atomic — *before*
  the terminal turn event reaches the owner, the same checkpoint-before-broadcast rule
  the interactive coordinator follows. That file is what makes `provider_session_id`
  resumable for the one provider that is itself holding the transcript.
- `Ouroboros.Provider.Native.Permissions` is a thin bridge to `Ouroboros.Control.Permissions`,
  reached by `Code.ensure_loaded?/1`. With no engine present every gated tool answers
  `{:ask, :no_engine}` and reaches a human; a missing rule engine never becomes a silent
  allow.
- `Ouroboros.Provider.Native.Context` owns the half of a request that is supposed to
  stay still. It lays a request out as system prompt → tool definitions in a fixed order
  → conversation, and digests the first two into `prefix_fingerprint/1`. The session
  builds the prefix once and rebuilds it on exactly two events — an explicit `configure`,
  and a compaction — which are the two prompt-cache invalidators this runtime can cause.
  The fingerprint is asserted stable across turns in `test/provider/native/context_test.exs`,
  which is what stops a well-meaning "put the date in the system prompt" from becoming a
  bill rather than a failing test.
  - `Context.Instructions` discovers `AGENTS.md` from the workspace up, with `CLAUDE.md`
    as the per-level fallback, a user scope, `@relative` imports four hops deep, and
    `.agents/rules/*.md` held back behind `paths:` globs until a matching file is
    touched. It executes nothing it finds and refuses, by path, a file that would forge a
    reserved runtime delimiter. Total budget 40,000 characters, farthest dropped first,
    with the drop stated in the prompt.
  - `Context.Window` resolves the model's context window from `llm_db`, then node
    configuration, then **not at all**. `context_used`/`context_window` ride on every
    `usage` event; an unknown window omits the key rather than supplying a denominator
    nobody measured.
  - `Context.Compaction` elides older tool results before it summarises anything, and
    summarises into a fixed Goal / Constraints / Progress / Decisions / Next steps,
    keeping `keep_recent_tokens` of the tail verbatim. `Context.Archive` retains the
    pre-compaction messages content-addressed under the session directory and the
    `compaction` event names them, which is the reviewable-history half of R5's open row
    16. Two compactions inside three turns halts with a named `status` event.
  - `Context.Handoff` builds the packet a *new* session starts from — summary, touched
    files with their hashes as of now, open plan, operator instruction — which is Amp's
    answer to summary-on-summary rather than a third compaction.

##### Hooks, and where they sit in the order

`Ouroboros.Provider.Native.Hooks` reads `ouroboros.toml` in the workspace and
`~/.config/ouroboros/hooks.toml` for the user, and speaks the JSON contract Claude Code,
Codex, Gemini and Factory converged on. Project hooks and `[checks]` require the canonical
workspace root in `config :ouroboros, :trusted_workspaces`, because a repository that
ships hooks is a repository that runs commands on every machine that clones it. Trust is
held outside workspace contents; neither a native file tool nor an unsandboxed shell can
make the repository authorize itself.

An entry declares **exactly one** of `command` and `component`; both, or neither, is an error
line and no hook. `command` is a shell command line and is what workspace trust gates. When
this node has an OS sandbox backend, a command hook runs inside it — PreToolUse/PostToolUse
as `:read_only` (scratch `$TMPDIR` writes only); `[checks]` and the other lifecycle events
as `:workspace_write` (workspace writable, `.git` and `.ouroboros` fenced as `bash` is).
Without a backend the hook is logged and ignored rather than run with ambient filesystem
and network.

`component` names a WebAssembly component — a path, resolved relative to the workspace root
and confined to it — and is admitted from an untrusted workspace, because its authority is
the world's single `log` import and a verdict this runtime then narrows. A component entry may
also carry `config`, the JSON string handed to the component's `init` verbatim, bounded at
16 KiB; a `[checks]` entry takes both keys in table form,
`lint = { component = "./hooks/lint.wasm", config = '{"strict":true}' }`. Every key, every
bound, and the payload each event carries are in [the author guide](WASM_GUIDE.md).

`PreToolUse` hooks run **after** the permission engine and only when it did not deny. A
hook therefore cannot allow what a rule denied — not by convention but by construction,
because on a denial no hook is invoked at all. It may deny what a rule allowed, may
resolve a rule's `ask`, and its `ask` outranks `approval_mode` so `auto_approve` cannot
swallow it. `updatedInput` is re-evaluated by the engine before the rewritten call runs.
A hook that times out, crashes, prints nonsense, or cannot be sandboxed is logged and
ignored; only `deny` stops anything.

##### Checkpoints, and what rewind will not claim

The conversation checkpoint gained a file checkpoint beside it. Before every `write`,
`edit` and `apply_patch` the loop snapshots the file's prior
bytes into `blobs/<sha256>` under the session directory, and records a per-turn manifest
of `{path, before, after}` plus the message count at that turn's end. Content addressing
keeps it affordable; a per-session byte budget (256 MiB) bounds it, and turns dropped to
stay inside the budget are *recorded as dropped* rather than forgotten, so a rewind that
reaches into one reports those files by name.

`Session.rewind/3` restores files, truncates the conversation, or both, and answers with
`restored` and `unrestorable`. The second list is the design: Claude Code's rewind
silently under-delivered, and anything a `bash` command changed is beyond a runtime that
does not inspect the programs it runs. That is said before the operator commits, by turn,
with the command fingerprints.

`Ouroboros.Provider.Native.Sandbox` gives the native `bash` tool the same posture the
system prompt reports, both derived from `Sandbox.decision/2`. With macOS
`sandbox-exec` or Linux `bwrap`, `:workspace_write` makes the workspace and declared
roots writable while keeping `.git`, `.ouroboros`, runtime data and user configuration
read-only; `:read_only` permits a shell with writes confined to per-call scratch. The
network is denied by default in both modes. Without a backend, `:read_only` and
`:workspace_write` both refuse `bash` rather than running it unsandboxed —
`OUROBOROS_ALLOW_UNSANDBOXED_BASH=1` restores the old `workspace_write` posture;
`:unrestricted` is explicitly unsandboxed. An approved filesystem escalation re-runs
that one command under `:workspace_write_escalated`: the same writable roots, protected
data/config, `.ouroboros` fence, and network policy, with only the `.git` segment
fence lifted. `web_fetch` reaches the network and is bounded by the permission engine's
`WebFetch(domain:)` rules *and* by an address gate that refuses loopback, link-local,
private, and metadata destinations; Mint then connects to an admitted address tuple
(TLS SNI, certificate checks, and the HTTP `Host` header still use the original hostname),
so a rebind between lookup and connect cannot retarget the socket. It also refuses to follow
a redirect off the host that was evaluated. A later same-host redirect looks up and pins
again; a hop that rebinds to a non-public address is refused. The README states the same
limits where an operator will read them.

The `capability` tool reaches a deployed WebAssembly capability — the `:live` lane-W
rollouts that name this node, and nothing else on the mesh. It is gated by `Capability(<name>)`
rules, ledgered with the component's sha256, and everything a component says back to the
model is bounded and labelled untrusted. docs/WASM.md §7.7 and D17 are the whole story,
including what labelling does and does not buy.

Harness run ownership is node-local. A disconnected remote owner is unavailable; a
run becomes lost only when its confirmed owner reports `:not_found`.

`Ouroboros.InteractiveSession` applies the same ownership model to Harness sessions.
It checkpoints session configuration, logical turn intents, Harness turn IDs,
redacted events, terminal results, and an exclusive cursor. A coordinator restart
reattaches to the same live Harness session; a full Harness/BEAM restart cannot
reconstruct the session process and resolves to `:lost`.

### Evolution plane

The BEAM hot-patch lane was removed by docs/proposals/core.md §4 A1. A forged BEAM ran
with the whole VM's ambient authority, and the lane structurally could not introduce a
module without that being true, which is the opposite of what containment is for. What
replaced it is lane W: a forged capability is a WebAssembly component whose authority is
its import list, signed and content-addressed, deployed and rolled back without a
rebuild. docs/WASM.md is that lane's document; what follows here is the half of the old
lane that outlived it.

`Ouroboros.Wasm.Forge` owns the path from an agent-authored Cargo project to a signed
manifest, and `Ouroboros.Wasm.Rollout` owns the path from that manifest to a live,
health-gated capability. The stages, each with its own named refusal:

1. Contract C9 is checked before anything is compiled: `Cargo.toml`, `Cargo.lock`,
   `src/**.rs` and an optional `README.md` and `manifest.json`, at most 32 files and a
   mebibyte, no `build.rs`, no symlink followed, and the lock pinned byte-for-byte to
   the guest SDK's. Nothing is evaluated, so a rejected project has built nothing.
2. The cargo build runs under `Ouroboros.Provider.Native.Sandbox` — the same OS sandbox
   the native agent's shell runs in — with no network, writes confined to a scratch
   directory and the registry cache, and a wall-clock ceiling. A build script and a proc
   macro are arbitrary code at build time by construction, so "somewhere that cannot
   reach the cluster" has to mean an OS boundary and not merely a separate process.
3. `Upgrade.Epoch.next/2` reads the highest epoch every target's rollout register has
   admitted, allocates above the maximum, and persists the allocation durably *before*
   returning it, so a crash between allocation and use burns a number rather than
   reissuing one. An unreadable node is a refusal, not a zero. `:global.trans/4`
   serializes allocations in a connected cluster; it is not partition-safe, and the
   defence that does not depend on coordination is the target register's own
   monotonicity check.
4. The signature comes from `Upgrade.Signing.Service` — an explicit service, a configured
   `:signer`-role peer, or a service running on this node — and never from a key the
   forge holds. That seam is the next section.

`Ouroboros.Upgrade.Rollout.Registry` is the durable record of what a rollout intended and
what became of it: five states, and the difference between `:rolled_back` and
`:quarantined` is the whole point. A `:deploying` checkpoint is durable before a byte is
staged anywhere; a node that proved compensation earns `:rolled_back`; anything ambiguous
is `:quarantined`, which has no automatic exit. The register also holds the epoch gate,
decided inside the same serialized message that writes the entry, because a caller
reading the watermark and then checkpointing would be a read-then-write across two
messages.

> The OTP release-installation lane that used to sit beside this one — `Release.Metadata`,
> `RelupBuilder`, `Release.Artifact` and the `Release.Runtime` journal — was deleted in
> September 2026. See [the core reduction](proposals/core.md) §3 D4: it existed to install
> release archives onto other machines, and nothing installs onto other machines any more.

### Signing plane

`Upgrade.Signing.Service` is the other side of that seam, and it runs where the forge
does not: on a `:signer`-role node whose supervision tree contains this process and
cluster formation. Three properties make it independent rather than merely remote.

**The key is outside the requesting application.** It is read at `init/1` from the file
named by `OUROBOROS_SIGNER_KEY_PATH` (32 raw bytes or their base64), derived into an
Ed25519 keypair, and held in process state wrapped in a struct whose `Inspect`
implementation redacts it — so a crash report, a logged state, or an interpolated
exception cannot print it. `public_info/0` publishes the public half and renders the
exact `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry a core node needs; there is no accessor
for the private half anywhere. A one-machine posture runs this same service beside the
node that asks it, which is a dev loop and not custody.

**The policy sees the whole manifest and the bytes.** `Signing.Policy.Default`
recomputes every claim that can be recomputed — the component's sha256 and size, from
the bytes submitted beside the manifest — and refuses a world its `kind` does not
require, with no configuration that widens that. It requires `metadata.author`, and by
default (`:signing_require_wasm_eval`) a `Rollout.Evaluation` spec it can validate,
because nothing in this runtime compiles a component or runs its tests before the
signature, and the signed eval spec *is* the test story. What it deliberately does *not*
check is anything only a target node
knows: epoch ordering beyond a plausibility distance, and what the linker will actually
accept — the boundary there is the helper's own linker, which defines exactly the
world's imports and fails instantiation on anything else. Every failure is
`{:refused, reason}`; nothing raises across the boundary, because an exception reaching
the caller through `:erpc` would be indistinguishable from transport ambiguity.

**Every decision is journaled before it is answered.** `Signing.Journal` is a bounded
record of issuances *and* refusals — artifact id, epoch, the component it would have
loaded, requester, decision, reason, findings — checkpointed through
`:signing_journal_storage` (`Storage.DurableFile` in production) before the reply is
sent. A journal that will not accept the entry is a refusal to sign. The one asymmetry
is deliberate: the journal may record an issuance whose reply was lost, never a
signature that was returned without a record.

`Ouroboros.Wasm.Deploy` is the client. It resolves the target from `:signing_node` or a
service running on this node, sends the manifest and the component bytes plus an
advisory payload over a bounded `:erpc`, and converts every transport outcome into a
typed error. The advisory payload is cross-checked and discarded: the signature is
always over bytes the service derives itself, so a disagreement means version skew and
stops the deployment rather than producing a signature over bytes the requester did not
expect.

Admission control sits in front of all of it: a per-requester sliding-window rate limit
and a maximum submitted size, and a separate `admit/4` round trip that charges the
limiter *before* the signing node spends a compile on a component it may refuse. The
requester is self-reported and journaled as a claim, so the limit bounds accidents and
retry storms rather than adversaries — see "Safety boundaries" for what a connected node
can do regardless.

`Wasm.Rollout.deploy/3` checkpoints `:deploying` in the durable `Rollout.Registry`
before any node is staged, probes with `{Rollout.Probe, :ready?, [spec]}`, and
classifies failure from each node's own evidence. The probe starts the wrapper module as
a throwaway mesh agent, sends one synthetic signal, checks the answer, and stops it — and
converts every exception, exit, and throw into a health *result*, because an uncaught
error would reach the driver as transport ambiguity and quarantine a node the probe
merely failed to satisfy. Only a rollout whose every node proved compensation is recorded
`:rolled_back`; anything ambiguous is `:quarantined`, which has no automatic exit.

### Evaluation gates

The probe answers "is it alive". `Rollout.Evaluation` answers "did it do what it was
forged to do", which is the difference between a system that modifies itself and one
that improves. A spec is a bounded map of probes — a portable input and a data
expectation (`:any_reply`, `{:equals, v}`, `{:contains, s}`, `{:state_matches, k, v}`) —
plus `budget_ms`, an optional `max_latency_ms` gate, and `required`. It is data because
it lives in `metadata.forge.eval` *inside* the signed manifest: the criteria travel with
the bytes they judge, a rewritten spec invalidates the signature, and a future external
signer can require their presence. A closure could satisfy none of that.

The gate runs between commit and promote, while every node still holds its rollback
material. `Evaluation.run/3` starts one throwaway mesh agent per node and drives the
probes through it in order, so state expectations mean something; it enforces the
artifact's own budget, and — like the probe, and for the same reason — it converts every
exception, exit, and throw into a probe *result* rather than letting one escape into
`:erpc` and become transport ambiguity. `Rollout` then promotes if every node satisfied
its spec, rolls back if any node did not, and quarantines if any node's answer was
ambiguous — attempting compensation either way, but never recording an unevaluated
rollout as cleanly withdrawn. The registry entry carries a bounded `eval_report`: counts,
timings, and the first few failures per node, with an oversized or unportable report
replaced by a marker rather than truncated into something that reads like evidence. That
field is why the registry checkpoint is version 3; an older checkpoint is widened on
read (absent fields become `nil`) and anything newer is still refused.

Champion/challenger comparison is deferred, and deliberately: it needs a rule for what
"the version this displaces" means when identity is a digest rather than a name, and half
of one would be worse than none. Until then a new component is a new rollout and the
register's own supersede rule retires the entry it displaces.

Quarantine is a refusal, not a warning: it has no automatic exit, and clearing it means
inspecting the nodes themselves and deciding, as an operator, what the cluster is
actually running.

### The effect ledger

`Ouroboros.Agent.EffectLedger` is the durable record of what this runtime attempted and
what came of it. An admitted attempt is checkpointed *before* it starts and settled
after, so a restart can tell an unfinished acknowledged attempt from one that was never
requested. `Ouroboros.Provider.Native.Tools.Forge` and the permission engine are its
writers today; `ledger.list` and `ledger.export` are its readers.

`Ouroboros.Control.Grants` is the deny-by-default authority over what an agent may do to
the cluster. It is asked about a concrete attempt — this module, these nodes — and no
entry, an attempt outside the allow-list, a malformed call, and an unreachable authority
are all refusals. Grants are checkpointed before they are acknowledged, and a revocation
whose write fails leaves the grant standing rather than forgetting something it could not
durably forget.

> The typed-signal effect runner that used to sit between an agent and these two —
> `Ouroboros.Agent.Effects` and its six Jido actions — was deleted in September 2026.
> See [the core reduction](proposals/core.md) §3 D3.

### Permission plane

`Ouroboros.Control.Permissions` is the second deny-by-default authority, and it answers a
different question from grants: not what an *agent* may do to the cluster, but what the
model may do to this machine. It is consulted at the pre-tool seam the native loop owns —
`Ouroboros.Provider.Native.Permissions.evaluate/1` — before any `approval_requested` event
is emitted, and at the interactive plane's external approvals and operator shell.

A rule is `{pattern, decision, scope}`. The pattern language is `Bash(<prefix> *)` with a
word boundary, path globs for `Read`/`Edit`/`Write` canonicalised through
`Workspace.Path`, `WebFetch(domain:…)`, `mcp__<server>__<tool>`, and `Tool(<name>)`;
`Bash(command:…)` is refused, and `Tool(<name>:<param>=<value>)` may deny or ask but never
allow. A compound command splits per sub-command with wrappers stripped and redirect
targets evaluated as writes, and an `allow` must cover every part while a `deny` needs
only one — the asymmetry that keeps a chained command from smuggling a part past an allow.

Four scopes, `:node` (operator configuration) above `:user` above `:workspace` above
`:session`, resolved as: any `deny`, then any `ask`, then `allow`, with scope breaking
ties only inside one rank. Workspace rules are keyed by canonical root and stored in the
node's data directory rather than in the repository, so a clone cannot ship rules that
grant it permissions on the machine that clones it. Protected writes — `.git`,
`.ouroboros`, the data directory, `~/.config/ouroboros` — are decided before any rule is
read and no rule reaches them.

Storage follows `Control.Grants`: node-local, checkpoint before acknowledgement, bounded,
with `status/0`. The bound refuses a new rule rather than evicting an old one. An
unreachable store answers `{:ask, :authority_unavailable}` for anything a stored rule
could have allowed, while protected paths and configured denies still refuse, because
those need only configuration and the request. Every rule-made allow and deny, and every
human answer through `respond_approval`, is written to `Agent.EffectLedger` as a
`:permission` effect — tool, mode, provider, decision, scope, actor, rule id, and a digest
of the command line and paths, never their text. An `allow` whose ledger entry cannot be
written is downgraded to `ask`.

The engine sits under the same `Ouroboros.Control.` prefix as grants, and for the same
reason: the only lane that deploys agent-authored code is lane W, whose components run
inside a world whose imports do not reach the BEAM, so nothing an agent forges can
replace the module deciding what code may do.

### Durable checkpoints

Every store above that survives a restart keeps its state in
`Ouroboros.Storage.DurableFile` checkpoints, and every one of them is read with
`:erlang.binary_to_term(binary, [:safe])`. `[:safe]` refuses to *create* an atom. That is
an input-validation fence — a checkpoint is bytes on a disk another principal can write —
and it is also a durable-format contract: a build that stops spelling an atom has changed
the format of every checkpoint that holds it, and a file an older build wrote then fails
to decode as a whole term. The reduction deleted planes whose atoms sat in every one of
these stores. Three mechanisms keep the older directory readable, one per kind of name,
and they are disjoint:

- **`Ouroboros.Storage.RetiredAtoms`** covers a name *no module of this build spells any
  more*: the deleted planes' pattern kinds, subject keys, provider names, transports,
  statuses and module names — 197 names, each with the store that may still hold it.
  `DurableFile` compiles the list into itself, so the module that decodes is the module
  that interns them, and the reader that used to understand a value treats it as one
  that matches nothing: a retired pattern kind matches nothing, a retired provider loads
  as history a session can show and cannot run, a retired ledger key is a key nothing
  reads. Never as a reason to crash.
- **Quarantine** (`DurableFile.get_checkpoint_or_quarantine/2`) covers a name *no build
  can spell*: the node a record was written by (`:"ouroboros@host"`) and a capability
  module minted at runtime under `Ouroboros.Capability.`. Grants and the effect ledger
  read through it. An undecodable file moves aside as `<hash>.quarantined-<unix>.term`
  with every byte intact, one error line names the key, the old path and the new one,
  and the store starts from no checkpoint.
- **The preload** (`DurableFile.ensure_build_loaded/0`) covers a name *this build spells
  in a module that has not loaded yet*. Under interactive code loading the atom table at
  the first decode is a function of boot order — the integration fixture measured between
  36 and 117 `Ouroboros.*` modules loaded at the effect ledger's first read, run to run,
  and lost the ledger on a loaded machine. Before the first `[:safe]` decode in a VM the
  adapter loads every module of this build and of its dependencies, once.

Two blast radii. `Interactive.Store` is built on `Storage.Records` — one checkpoint per
session plus an index — so a name it cannot intern costs one session, dropped from the
index with a log line, and the node boots; quieter than a crash, and not better than one.
Every other store is one file: grants, permissions, policy promotion, the effect ledger,
the rollout register, the signing journal, the epoch watermark and the cluster's
session-owner record. There a miss would cost the file and, for a supervised child, the
boot — which is why the two stores that can hold a runtime-minted name quarantine rather
than stop, and why the rest are covered by the list and the preload. The register, the
journal and the WASM store write every atom through `Upgrade.Wire` as a tagged binary and
need none of this.

What an operator sees after upgrading a node whose grants named a capability forged at
runtime is one `[error]` line at boot —

```
checkpoint {:ouroboros, :agent_grants, 1} at <data dir>/grants/checkpoints/<hash>.term
could not be decoded (:invalid_term); quarantining it at
<data dir>/grants/checkpoints/<hash>.quarantined-<unix>.term and starting from no checkpoint
```

— a file by that name beside the store, and no grants at all: every principal is denied
every effect until someone grants again. That is deny-by-default reached from the
direction that narrows, and it is a fact the operator has to be told, not a silent
recovery. The effect ledger's version of the same event starts a new history at sequence
1 beside the old bytes; `ledger.export`'s chain is computed over the history the node
holds and claims nothing about the one it does not. Every *other* unreadable checkpoint —
an I/O error, a content-integrity failure, a missing directory — still stops the store,
because an authority that could not tell a broken disk from a build that moved on would
be inventing an empty allow-list out of a hardware fault.

The proof is `make boot-gate`: a data directory written by `dev` at `3bc8887`, holding
every durable shape the reduction retired, booted on this tree ten times in each
code-loading mode with every count compared against the record in
[`test/support/integration_fixture/README.md`](../test/support/integration_fixture/README.md).

## Failure model

| Failure | Current behavior | Required next behavior |
| --- | --- | --- |
| Starting caller exits | Harness session and its coordinator continue | Done |
| Interactive coordinator crashes | Reattaches to live Harness session and turn IDs | Done |
| Harness/BEAM/host restarts | Task checkpoint remains; missing local run becomes `:lost` | Explicit resume/retry policy |
| Remote owner disconnects | Returns `owner_unavailable`; does not corrupt state | Retry/backoff and operator view |
| Network partition during placement | `:global` cannot guarantee one owner | Consensus lease/admission service |
| Store write fails | Cursor is not advanced and events are not broadcast | Backpressure/health alarms |
| Workspace/registry owner restarts | Nonterminal durable roots remain reserved until the registered owner reclaims them | Cross-node consensus authority |
| A checkpoint holds an atom this build cannot intern | A retired name is interned by `Storage.RetiredAtoms`; a name this build spells but has not loaded is preloaded; a name no build can spell quarantines the file (grants, the ledger) or the record (a session) by name, and the node boots — see "Durable checkpoints" | Operator re-grant; nothing self-heals |
| Forged capability fails its health probe | Every committed node is rolled back, the module is absent again, and the registry records `:rolled_back` | Done |
| Forged capability fails its signed evaluation spec | Rolled back before promotion, while the rollback material still exists, with the failing report recorded | Done |
| Evaluation is unreachable, slow, or answers a shape this build cannot read | Compensation is attempted and the registry records `:quarantined`, never `:rolled_back` | Operator reconciliation tooling |
| Challenger capability regresses the probe set against the live champion | Rolled back with both reports; the champion keeps running | Cost models, canary cohorts, statistical significance |
| Evaluation criteria are rewritten after signing | The manifest signature fails on every loading node | Done |
| Capability rollout outcome is ambiguous anywhere | Registry records `:quarantined` and never `:rolled_back` | Operator reconciliation tooling |
| Forge crashes between allocating an epoch and using it | The number is durably spent and never reissued | Done |
| The cargo build hangs | One wall-clock ceiling covers the build; the sandboxed process group is killed | Done |
| The forge compiles hostile source | The build runs under the OS sandbox with no network and writes confined to a scratch directory; it still shares the build host's kernel and user | Container/VM boundary with resource and network limits (proposals/core.md §7) |
| Grant checkpoint write fails | A pre-rename failure is a definite refusal; a post-rename durability failure is `commit_outcome_unknown` and restarts the authority for reconciliation | Operator reconciliation tooling |
| Effect authority is unreachable | Every attempt is refused; there is no path that fails open | Replicated policy authority |

## Safety boundaries

- Development and test permit an unsigned local component deploy
  (`upgrade_trust_policy: [allow_unsigned: true]`). Production never does, and the
  `self` posture closes it in every environment. Trusted keys arrive through
  `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`; boot fails on a malformed entry and an unset
  variable trusts nobody.
- A forged capability's authority is its component's import list, enforced by the
  helper's linker on the loading node: it defines exactly the world's imports and fails
  instantiation on anything undeclared. The declared list in a manifest is provenance and
  review surface, not the enforcement mechanism.
- Forge project validation (contract C9) is a file allow-list and a lock pin, not a
  reading of the code. What makes a build safe is where it runs: under the OS sandbox,
  with no network and writes confined to a scratch directory.
- The forge holds no signing key and constructs no signature. Without a configured
  `:signing_node` or a service on this node it cannot sign at all, and a service running
  beside the node that asks it is a dev loop rather than custody. `Signing.Service` on a
  `:signer` node moves the key onto a host the requesting application does not run on,
  applies an independent policy to the full manifest and the bytes before a signature
  exists, and journals every decision durably before answering. That is a narrower blast
  radius, not custody: the signer node is a connected cluster member, so any node that
  completes the distribution handshake can call the same service the forge calls. What
  such a node gets is a policy decision — the world rule has no bypass for any caller,
  and the per-requester rate limit is keyed on a self-reported claim. Custody outside the
  distribution trust domain remains external.
- Agent effect grants gate the forge and deploy path — the one a session's `forge` tool
  and the operator's gateway travel through — and are deny-by-default, durable, and
  checked against the concrete attempt. They are not a sandbox and not a capability
  system. Any code running in this VM can call `Ouroboros.Wasm.Forge.forge/2`,
  `Ouroboros.Mesh.start_agent/2`, or `Ouroboros.Control.Grants.grant/4` directly without
  passing the tool at all, because it retains full ambient VM authority. The hard
  boundaries remain the component's import list, the signer's policy, and manifest
  signing whose production default refuses.
- No tool and no gateway verb grants — `grants.list` is read-only, and `Grants.grant/4`
  has no caller in `lib/` — so an agent cannot widen its own authority through any
  surface it can reach. That is a property of the surface, not of the VM, which is why
  signing approval belongs outside this application.
- The authority is node-local: one `Grants` process per node over that node's own
  checkpoint. An agent granted an effect on one node is not granted it on another, and
  nothing replicates or reconciles the two.
- Permission rules decide what the in-process Native loop may execute. They are not an OS
  sandbox. Prefix matching is defeated by construction by command
  substitution, `eval`, variable expansion, aliases, and `sh -c`: nothing is expanded, and
  a rule matches the literal command line the provider reported. This is why the posture
  is an allowlist plus protected paths rather than a denylist, and why argument-
  constraining patterns are accepted but returned marked `fragile` rather than silently
  trusted. There is no classifier; a classifier-backed `auto` mode is later work on top
  of the same engine and never a replacement for rules.
- The permission store is node-local and bounded like every other authority here. A
  machine's rules do not replicate, and the bound refuses a new rule rather than evicting
  an existing one — evicting a `deny` to admit an `allow` would be a storage limit that
  widens authority. A pre-commit rule-write failure leaves the previous state standing;
  post-rename ambiguity restarts the authority instead of continuing with divergent memory.
- A session never claims a posture it cannot enforce. `sandbox_mode` is rendered by the
  OS backend or refused by name, and `approval_mode` is applied by the loop that owns
  the tool call. Read-only is explicit (`sandbox_mode: :read_only`).
- The OS sandbox is a boundary and not a container: same kernel, same user. On Linux it
  is mounts and a network namespace with no seccomp filter, and a `.git` or
  `.ouroboros` created after the command starts, below the top level of a writable root,
  is not denied there (Seatbelt denies both cases by regex; the `LD_PRELOAD` filter that
  used to deny it on Linux went with proposals/core.md §4 A2). Untrusted work needs a
  separate container/VM boundary with resource and network limits, which is §7 of that
  plan.
- A worktree (`worktree: true`) is *containment scoping*, not isolation. It narrows what
  the runtime's own path checks and the native agent's tools consider in-bounds — the
  lease and every containment test are taken on the canonicalised worktree path, so a
  session cannot reach the repository it branched from through a relative path or a
  symlink. It does nothing about a `bash` command, which still runs with the operator's
  privileges and can write anywhere on the machine; and it shares the repository's object
  store, so a `git` command inside the worktree can still write refs the repository sees.
  The container/VM boundary above is what isolation would be, and it is not this.
- Worktree cleanup is fail-closed toward *keeping* data. Removal happens only when
  `git status --porcelain` inside the worktree is empty, an unreadable status counts as
  dirty, and there is no code path in `Ouroboros.Workspace.Worktree` that deletes an
  uncommitted change — including the boot-time `reconcile/1`, which reports dirty strays
  rather than tidying them. The failure this chooses is a leftover directory the operator
  has to remove, over work the runtime removed for them.
- Instruction files (`AGENTS.md`, `CLAUDE.md`, `.agents/rules/*.md`) are repository
  content and are treated as untrusted text, never as configuration with effects. Nothing
  in them is executed — no command substitution, no argument interpolation, no
  front-matter key naming a program — the only front-matter key read at all is `paths:`,
  imports cannot leave the importing file's own tree or name an absolute path, and text
  carrying a reserved runtime delimiter fails the session by path rather than being
  escaped. What a repository gets from these files is words in a prompt.
- Compaction is bounded and reviewable, not lossless. The pre-compaction messages are
  retained content-addressed under the session's directory and named in the `compaction`
  event, but the archive is bounded by the same message count the checkpoint uses, and a
  conversation longer than that bound loses its oldest messages from the archive with
  `truncated: true` stated rather than implied. The summary itself is a model's work and
  can be wrong; the archive is what makes that recoverable — so the archive decides the
  outcome: a transcript that cannot be written refuses the compaction and leaves the
  whole conversation standing, rather than folding it and logging the loss.
- Inline environment maps are rejected rather than persisted. Event payloads and
  result tails are redacted before checkpointing. Objectives and provider-specific
  options are durable domain data and must not contain secrets.
- Distribution must use authenticated, encrypted transport outside a trusted local
  network; Erlang cookies alone are not an adequate internet-facing boundary. The
  release renders `-proto_dist inet_tls` and an `ssl_dist_optfile` when it is built with
  `OUROBOROS_DIST_TLS=1`, and a node that forms a cluster over cleartext distribution
  refuses to boot unless `OUROBOROS_ALLOW_INSECURE_DIST=1` says so.
- Cookie and TLS are transport authentication, not authorization. They decide who may
  complete the handshake and nothing about what follows: every connected node holds full
  `:erpc` authority over every other, including loading code, reading application
  environment, and killing processes. `Ouroboros.Cluster`'s role checks — placement onto
  `:core` nodes, forge builds onto `:builder` nodes — are misconfiguration detection
  above that fact: a check a cooperating node honours, in exactly the sense that the
  signer's policy is a check a cooperating requester submits to. A hostile connected node
  never calls those functions at all.
- Node role narrows blast radius rather than containing a compromise. A `:builder` node
  boots cluster formation and the WASM helper pool, and nothing that holds sessions,
  journals or grants; a `:signer` node adds the signing
  service (and `RuntimeOwner` when a data directory is configured). Both remain fully
  authorized members of the cluster. Containment requires the build and signing hosts
  outside the cluster's trust domain, reached through something narrower than Erlang
  distribution.
- The data directory is deployment-owned infrastructure. `Storage.DurableFile`'s
  write-sync-rename discipline and the content-addressed WASM store do not defend against
  another OS principal that can replace files in that directory.

## Roadmap to a competitive coding system

### Milestone 1: reliable single-task execution

- deterministic contract tests for the native provider;
- scripted-model tests for the loop's process ownership, cancellation, and timeout
  behavior;
- append-oriented event storage instead of rewriting the changed record's retained history;
- ~~worktree provisioning and durable cleanup~~ (done: `Ouroboros.Workspace.Worktree`,
  above), explicit network policy, and the OS-level isolation a worktree does not give;
- budgets, retries, idempotency keys, telemetry, and operator diagnostics.

Stop condition: repeated crash/reattach/timeout/cancel tests show no duplicate run,
lost acknowledged event, leaked OS process, or ambiguous terminal state.

### Milestone 2: withdrawn

This milestone was a durable team DAG with a planner and evaluator above it. It was
built, and it was deleted in September 2026 — see [the core reduction](proposals/core.md)
§3 D3. What survives of the claim is the one shape that earns it: a native session
spawning subagents across machines, each holding its own worktree lease.

Consensus-backed ownership leases for partition behavior remain unbuilt, and remain the
honest limit on every ownership statement in this document.

### Milestone 3: safe self-improvement

Implemented:

- sandboxed builds of candidate source changes (`Wasm.Forge`: contract C9's file
  allow-list and lock pin, then a cargo build under `Provider.Native.Sandbox` with no
  network, writes confined to a scratch directory, and a wall-clock ceiling);
- a signing seam the forge cannot satisfy for itself, with the manifest re-verified
  against trusted keys on every loading node;
- a signing *service* on the other side of that seam (`Upgrade.Signing.Service`, on a
  `:signer` node for a fleet): the key read at boot from a file that node mounts and
  never leaves its process, an independent policy that recomputes the digest and the size
  from the submitted bytes and structurally refuses a world the `kind` does not require,
  a requirement (on by default) that the manifest declare a valid evaluation spec, a
  per-requester rate limit charged before a compile is spent, and a durable journal of
  every decision that must be acknowledged before a signature is returned. A signer node
  with no readable key refuses to boot;
- durable, crash-safe epoch allocation above every target node's register
  (`Upgrade.Epoch`);
- a durable deployment-level cluster journal (`Rollout.Registry`), checkpointed before
  any mutation, which never records ambiguity as a rollback and which decides the epoch
  gate in the same serialized message that writes the entry;
- health-gated rollout with real rollback proof (`Wasm.Rollout` + `Rollout.Probe`): a
  forged capability starts as a mesh agent and answers a signal on every target, or the
  whole rollout is compensated and the capability is absent again everywhere;
- declarative, signed evaluation gates before a rollout settles (`Rollout.Evaluation`):
  a probe set that lives inside the signed manifest, is run on every target, and decides
  live, rollback, or — on any ambiguous answer — quarantine;
- a durable deny-by-default authority over all of the above (`Control.Grants`), checked
  against the concrete attempt, identifying the actor from server-side state rather than
  from the request, bounding what it admits and recording each admission. The path that
  reaches it is a session's tool (`Provider.Native.Tools.Forge`) and the operator's
  gateway, not a typed signal; the effect runner that used to sit in front of both was
  deleted in September 2026. `Agent.EffectLedger` checkpoints a content-minimized intent
  and exact grant snapshot before execution, durably settles outcomes and refusals,
  exposes bounded cursor queries, and recovers unfinished work as ambiguous without
  retaining prompts, message bodies, source, provider output, or BEAM binaries;
- least-privileged builder and signer nodes (`Ouroboros.Cluster`): one release, one
  runtime, three roles. A `:builder` node boots cluster formation and the WASM helper
  pool, and nothing that holds sessions or stores; a
  `:signer` node adds the signing service (and `RuntimeOwner` when a data directory is
  configured). `:wasm_forge_placement` relocates a forge onto a builder without changing
  anything about the build. A component is one artifact for every node, forever, so a
  builder need not be runtime-identical to its targets — which is exactly the property
  the removed BEAM lane could not have;
- formation itself (libcluster: static epmd, gossip, DNS polling), off by default, plus
  a release whose distribution posture is explicit: long names, a refused blank
  node/cookie, optional TLS distribution baked into `vm.args`, and a boot that fails
  closed when a clustering node ends up on cleartext distribution.

Still external:

- **authority that is not node-local.** `Control.Grants` is one process per node over
  that node's own checkpoint, and `Agent.EffectLedger` is another node-local aggregate.
  There is no replicated policy/audit service or per-principal rate or cost budget. The
  effect ledger is durable in production and survives the acting agent, but it is
  bounded and checkpoint-based rather than an append-only external ledger.

- **signing custody outside the distribution trust domain.** The service now exists and
  is real: the key lives on a `:signer` node, in one process, read from a file that node
  mounts, and an independent policy decides on the full manifest before any signature is
  produced. An agent on a core node cannot read that key, and cannot obtain a signature
  for a component in a world this build does not implement at any price, because no code
  path on the signer produces one. What remains external is the rest of custody. A signer
  node is still a
  connected cluster member: a node that completes the distribution handshake can call
  the signing service directly, and can also do everything else `:erpc` allows on that
  host. Role isolation and TLS distribution narrow that surface; they do not close it.
  The per-requester rate limit is keyed on a self-reported claim. And there is no human
  in the loop — the policy is mechanical, so "independent" here means independent of the
  patchable application, not independent of the cluster. An HSM, a review queue, or a
  signing host reached over something narrower than Erlang distribution are all still
  outside this codebase.
- **a VM boundary around the build and the shell.** The cargo build runs under the OS
  sandbox with no network, which is a real boundary and not a container: same kernel,
  same user. A `:builder` node moves the host off the production path, which is worth
  doing and is not containment — the builder remains inside the distribution trust
  domain. docs/proposals/core.md §7 names the VM backend that would close this.
- **partition behavior.** Formation connects nodes; it does not fence them. There is no
  quorum, no partition policy, and no reconciliation for a node that returns with stale
  state. Role and placement checks are observations about a *connected* cluster.
- **evaluation beyond the declared spec.** The gate that exists runs criteria somebody
  wrote and signed, on a throwaway instance, on each target, once. It decides promotion
  automatically, which is real. What it is not is a measurement of production behaviour:
  there is no cost model, no canary cohort on real traffic, no repetition, and no
  champion/challenger comparison at all. A manifest that
  declares no spec is refused a signature outright by default
  (`:signing_require_wasm_eval`); what does not exist is any judgement about whether a
  declared spec is a *good* spec.
- **any release-installation lane.** A forged component *does* survive a restart — the
  store is content-addressed on disk and `Wasm.Boot` restarts what the register says is
  live — but a change to the runtime itself still needs a release, and a release is
  `make ouro` on the machine that will run it: the OTP release-installation lane and the
  self-updater were deleted by proposals/core.md §3 D4, and nothing installs onto another
  machine.

Stop condition: the agent can propose a change, but cannot authorize its own patch;
every rollout has a reproducible artifact, independent approval, canary evidence,
rollback proof, and a reboot-persistent release.

### Milestone 4: product differentiation

The BEAM advantage is not “another prompt loop.” It is long-lived, inspectable,
fault-contained sessions: live process topology, typed event provenance, supervision,
node placement, resumable sessions, and controlled behavior evolution. Compared with a
conventional single-process coding CLI, Ouroboros can keep several sessions and their
subagents alive, route them across connected nodes, recover each from its own durable
checkpoint, and evolve behavior through a separately gated component lane.
The product surface should expose those properties
directly through a terminal UI and API rather than hiding them behind one opaque chat
transcript.

That architecture creates promising future capabilities:

- live topology and fault-domain views instead of one transcript;
- long-running specialist subagents that retain independent cursors and provenance;
- canary or cohort rollout of a behavior patch with health gates and retained rollback;
- evaluator-driven repair loops whose execution identity survives coordinator churn;
- subagents placed by the facts and tags a machine advertises; and
- build/sign/loader services an agent cannot self-approve. The least-privileged *roles*
  exist, forge builds already relocate onto a builder node, and the signing authority is
  a real service on a signer node with its own key and its own policy; what remains is
  moving those hosts outside the distribution trust domain, so that reaching them is a
  narrow request rather than full `:erpc` authority in both directions.

## Primary references

- [Jido documentation](https://jido.run/docs/getting-started/elixir-developers)
- [Distributed Erlang](https://www.erlang.org/doc/system/distributed.html)
- [`erlang:binary_to_term/2` and the `safe` option](https://www.erlang.org/doc/apps/erts/erlang.html#binary_to_term/2)
- [The WebAssembly component model](https://component-model.bytecodealliance.org/)
