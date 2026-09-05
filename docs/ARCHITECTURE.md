# Ouroboros architecture

## Definition of done for this slice

This slice is complete when all of the following are executable and tested:

1. A logical Jido worker can be supervised locally and addressed from another BEAM
   node through a typed signal.
2. A provider-neutral coding request can outlive its caller, emit durable ordered
   events, be replayed without gaps, survive its Ouroboros coordinator crashing, and
   resolve to explicit completed/failed/cancelled/lost state.
3. A compatible BEAM module can be loaded with an explicit state migration and rolled
   back in place, while policy-protected control modules reject self-patching.
4. A durable DAG and opt-in planner/evaluator can dispatch through a supervised team,
   revise within a fixed budget, and preserve cancellation intent across restart.
5. A complete OTP upgrade archive can be inspected and its `:release_handler`
   lifecycle can be gated and journaled through an injected deterministic adapter.
6. Agent-authored source for a new capability module can be validated without being
   evaluated, compiled and tested in an isolated non-distributed build peer, signed
   through a seam the forge cannot satisfy itself, stamped with a durably allocated
   epoch, deployed behind a per-node health probe, held to a declarative evaluation spec
   carried inside its own signature, and — when the probe or that spec fails — rolled
   back to absence on every node, or quarantined when the evidence is ambiguous.
7. An agent driven only by typed signals can do all of that itself — start and stop mesh
   agents, message them, delegate through a team, forge a capability and deploy it —
   with every attempt authorized against a durable deny-by-default grant for the
   concrete target, identified from server-side agent state rather than the signal,
   bounded so no effect blocks the agent, and recorded whether it ran or was refused.
8. Nodes form a cluster without anyone connecting them by hand, boot a role-shaped tree
   (`:core` full, `:builder` formation-only, `:signer` formation plus the signing
   service), refuse to place work on a node that cannot run it, relocate forge builds
   onto a least-privileged builder, and ship as one release whose node identity, cookie,
   and distribution transport are explicit and fail closed on the distributed path —
   told nothing at all, the release boots a standalone single-machine posture instead,
   with distribution off and no cookie in existence.
9. The signing authority runs on a `:signer` node rather than inside the application it
   authorizes: the key is read at boot from a file that node mounts, an independent
   policy recomputes the whole submitted artifact and refuses anything outside
   `Ouroboros.Capability.`, and every decision — issued and refused — is durably
   journaled before any signature is returned.
10. The documentation distinguishes those proofs from partition tolerance, full-host
    provider durability, billing, real repository effects, OS-level sandboxing of
    generated code, signing custody *outside the distribution trust domain*, evaluation
    beyond a declared spec, a real packaged-release install/reboot rehearsal, any claim
    that effect grants sandbox loaded code, and any claim that node roles, placement
    checks, or signer isolation constrain a node that has already completed the
    distribution handshake.

The first nine are local implementation claims backed by deterministic tests. None
imply the external claims in item ten.

## Planes and ownership

### Cluster plane

`Ouroboros.Cluster` owns two things nothing else may decide: which tree this node boots,
and how it finds the others.

Role (`:core`, `:builder`, `:signer`) is resolved once, at application start, before any
child is supervised — an unrecognized role raises rather than booting the privileged
tree. `:core` starts the full runtime. `:builder` starts formation and
`Ouroboros.Wasm.Supervisor` — the helper pool a forwarded lane-W forge needs in order to
read imports (W22) — and nothing that holds durable work: no teams, stores, sessions,
schedulers, or control plane. A BEAM forge build is still `:peer.start/1` plus a call.
`:signer` starts the durable-directory owner when a data directory is configured, then
one process: `Upgrade.Signing.Service`, which holds the key, applies the signing policy,
and journals every decision, then formation. That process leads the role-specific
`rest_for_one` chain on a signer, so the node is not askable before its key is loaded,
and it refuses to boot — key missing, malformed, unidentified, or journal unusable —
rather than starting into a state where denial and misconfiguration look identical.

Formation is libcluster, off by default, selected by `OUROBOROS_CLUSTER_STRATEGY`. It
sits at the *tail* of the application's `rest_for_one` chain on purpose: it connects and
observes, and nothing downstream rebuilds state from it, so a discovery strategy's crash
must not restart the durable owners above it.

Invariant: role is a placement fact, not an authority boundary. Every check that reads a
remote role also requires the target to be connected and running this runtime, and the
answer is only ever an observation about a cooperative cluster — see "Safety
boundaries".

### Team plane

`Ouroboros.Mesh` owns logical IDs and placement. Each member is a real
`Jido.AgentServer` under `Ouroboros.Jido` supervision. A local directory monitors the
PID and joins it to `{:ouroboros_agent, logical_id}` in a named `:pg` scope.

Typed Jido signals are the team protocol. Cross-node calls work because Erlang PIDs
and monitors are distribution-native. `:erpc` is used when an operation must execute
inside a selected node's ownership boundary.

Invariant: a PID is an observation, not durable identity. Callers retain logical IDs
or coding task references, never persist PIDs.

`Ouroboros.Team.Server` owns one inspectable Jido coordinator, local Jido children,
explicit remote Mesh members, and delivery of persisted coding results. Remote worker
relationships are marked `:mesh_remote` because Jido 2.3.3's child-adoption liveness
check is local-only. One worker has at most one active delegation. Team state remains
in a serializable `Team.Snapshot` checkpoint containing logical IDs, nodes, task
references, cursors, and results—but never runtime PIDs. A crashed server rebuilds or
adopts agent projections, atomically resubscribes each in-flight coding task, and
retries terminal delivery. Public delegation IDs are scoped to their team; an internal
SHA-256 identity over team and delegation names the CodingSession, while a private
random origin digest proves the task was created by that delegation before adoption or
cancellation. Coordinator startup is a serialized claim in the Jido agent, and every
adoption, signal, and cleanup path rechecks the exact module/team/coordinator owner.
The coordinator is monitored. Deliberate closure moves through a durable `:closing`
state that retries cancellation and terminal delivery before cleanup.

Above teams, `Ouroboros.Orchestration.Scheduler` owns a durable dependency graph.
It persists claims before invoking an executor, caps cluster-local concurrency,
unlocks fan-out/fan-in, and propagates failure and cancellation. An execution token
identifies one attempt: it survives the *owner* process dying so a waiter can reattach,
and a scheduler restart *clears* it so a stale owner cannot complete the new attempt.
`TeamExecutor` therefore names the team delegation from `{plan_id, step_id}`, not from
the token — a second offer of the same step reattaches to the same coding task instead
of launching a duplicate provider run. This closes the local checkpoint/start retry
window while the same Harness journal is queryable; it is not provider-side exactly-once
billing across a full VM or host loss.

A plan is heterogeneous. Each step declares a kind — `:coding`, or `:forge` for one
compile-and-deploy of a capability module — and the scheduler resolves one executor per
kind. Per-kind input schemas are enforced in `Plan`, so a forge step carries a
capability-namespaced module name, a contained relative source path, and an optional
`test_path` for candidate ExUnit tests. It cannot choose a workspace, a node, or a
signer. Omitting tests does not bypass the signing policy's passing-test requirement.
`submit/2` refuses a plan naming a kind
this scheduler cannot execute before the plan is persisted; a scheduler with no
executors is manual mode and accepts any kind because the caller drives every step.
Snapshots written before kinds existed load as `:coding`, and a kind this build does not
know is refused rather than coerced.

`Ouroboros.Orchestration.ForgeExecutor` runs forge steps through `Upgrade.Forge` and
`Upgrade.Rollout`, reading source and tests under one shared-read workspace lease.
Both paths use the same containment and regular-file checks; tests run inside the
isolated build peer and must pass before signing and deployment. Forging is not
naturally idempotent, so the durable rollout registry is the reattachment anchor: a
module already `:live` with the same source digest on the same nodes completes the step
without a second build or epoch, and a `:deploying` record — ambiguity — fails the
attempt with a retryable error rather than deploying twice. The check is not atomic with
the build that follows it; what makes a lost race explicit rather than silent is
underneath, in monotonic epochs and a node's refusal to introduce a module it already
has.

`Ouroboros.Control.Server` owns the objective-level loop. It checkpoints deterministic
planning/evaluation request IDs, the candidate plan, revision history, and cancellation
intent. Provider callbacks run outside the server so one slow inference does not block
inspection or cancellation of other runs. Generated plans may contain only execution
objectives and graph dependencies; trusted runtime configuration supplies worker,
provider, workspace, sandbox, and approval policy. Jido.AI is the production adapter,
but is opt-in and disabled at application startup by default. Cancellation remains
pending until the scheduler has durable per-step callback evidence; that evidence says
whether no execution existed, a request was accepted, or provider termination remains
unconfirmed. It never equates request acceptance with an observed provider exit.

A terminal evaluator may additionally return a versioned `Control.EvidenceContract`.
The contract maps acceptance-criterion IDs and claim IDs to typed evidence references,
classifies claims as observed/inferred/assumed, and preserves unknown, ambiguous, and
unverified outcomes rather than coercing them to success. Control checkpoints contain
only transport-safe IDs, enums, timestamps, and SHA-256 digests—not command output,
model prose, file content, or credentials. Decisive criterion and claim statuses require
at least one evidence reference; unknown statuses may honestly carry none. Older
evaluators remain valid and complete runs with `evidence_contract: nil`.

`:control_allow_forge_steps` (default false) widens what a plan may express by exactly
one shape: a step of kind `forge` whose input is a capability module name and a
workspace-relative source path. The coding-step schema is unchanged by the flag, both
planner branches refuse unrecognized keys, and the server re-validates the accepted plan
against the same per-kind rules `Plan` applies. Enabling it grants no deployment
authority: the forged artifact is still signed by whatever `:forge_signer` names —
`Signer.Deny` in production unless an operator changed it — and still verified against
each target node's trusted signers, and a scheduler with no forge executor refuses the
plan outright.

### Coding execution plane

`Jido.Harness` owns provider processes, provider-specific argv/protocol mapping,
normalized events, cancellation, and short-lived retained journals. Ouroboros does
not wrap those CLIs in a second tool loop.

`Ouroboros.CodingSession` owns domain truth:

- the objective, workspace, provider, owner node, and normalized request policy;
- the Harness run ID and provider resume ID;
- a durable exclusive Harness cursor and a separate Ouroboros event sequence;
- bounded redacted replay, terminal result, and explicit loss state; and
- node-aware info/replay/subscribe/await/cancel routing.

One `Ouroboros.Coding.Task` GenServer serializes transitions for a task. It explicitly
polls `Jido.Harness.Run.replay/2`, persists cursor plus projected events in one
checkpoint, and only then broadcasts them. `subscribe/2` registers and snapshots the
backlog in that same process, eliminating the replay-then-subscribe race.

When workspace roots are configured, that same coordinator owns a symlink-resolved
lease before it inspects or starts Harness. Read-only work shares a root; write work
is exclusive against overlapping roots. The private release capability is never
checkpointed. A coordinator crash releases via monitoring, then recovery reacquires
before reattachment. Durable nonterminal owners become fail-closed recovery
reservations across manager or downstream-registry restart; only the exact registered
coordinator can claim one. This authority is node-local.

The coordinator scans live Harness metadata before starting a missing run. That
closes the crash window between `Run.start/2` and saving the returned run ID, where an
unconditional retry could otherwise launch duplicate billable work.

#### Worktrees

`worktree: true` on either plane provisions a `git worktree` before the lease is taken,
and the lease is taken on the worktree rather than on the repository. `Ouroboros.Workspace.Worktree`
runs `git` as an argv list — never a shell string, and the exact list is asserted through
an injectable runner — canonicalises the created path through `Ouroboros.Workspace.Path`,
and hands *that* to the existing admission machinery, so every containment check the
runtime already performs now describes the worktree. A workspace that is not a git
repository is refused; a subdirectory of one gets the same subdirectory inside the
worktree. Both planes record the result as `worktree: %{path, root, branch, base_commit,
repository}` on their durable state, and the provider is told nothing beyond `cwd`.

Provisioning is idempotent, because admission runs again after every restart: a record
that already holds a worktree is returned unchanged rather than stranding the directory
its session was working in. Cleanup runs only when the session or task is *terminal* —
`terminate/2` fires on a supervisor restart too — and removes the directory only when
`git status --porcelain` inside it is empty, untracked files included. A worktree holding
uncommitted work is left where it is and named in the terminal event. A marker file under
the worktree root makes the set recoverable: `Worktree.reconcile/1` runs from
`Ouroboros.Application.start/2`, removes clean strays, and reports dirty ones without
touching them.

#### The native provider

`Ouroboros.Provider.Native` is the one exception to "Ouroboros does not wrap those CLIs
in a second tool loop": it *is* the loop. It registers through `:jido_harness, :providers`
beside the three adapters this runtime already overrides, declares one session transport
whose adapter is a supervised GenServer in this VM, and emits the same normalized events
into the same journals, gateway stream, and cells as every vendor provider. Nothing about
a vendor session changes because it exists.

Because the loop is here, three things are possible that are structurally impossible for
a managed transport: a tool call can be blocked on a human approval before it runs, a
steered message can be delivered between two tool calls of a running turn, and an
interrupt can stop the turn after the current tool rather than by killing a process. It
is therefore where LSP, hooks, permission rules, compaction, file checkpoints, and MCP
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
`edit`, `apply_patch` and language-server rename the loop snapshots the file's prior
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

##### Code intelligence at the write path

`Ouroboros.Provider.Native.CodeIntel` is the loop's whole relationship with the LSP pool:
a baseline before a write, a bounded report after one, and `rename`. The policy is R4's —
edited files only, new against the baseline, version-gated, five seconds, errors always
and warnings only when there are at most three, capped at twenty, and the literal line
`Edit applied.` first so the model does not read a finding as a failed edit. A server that
did not answer says `(no LSP data for this file)`; a language with no registered server
says nothing. Nothing in this path can fail a write, because the write has already
happened when any of it runs. `[checks]` — a project-declared typecheck or lint — runs at
the end of a turn that changed a file and injects the tail of what failed for the next
model step, which is the universal fallback for languages with no good server.

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
model is bounded and labelled untrusted; `agents.message` is the same reach for a script,
at gateway `:operate` scope. docs/WASM.md §7.7 and D17 are the whole story, including what
labelling does and does not buy.

Harness run ownership is node-local. A disconnected remote owner is unavailable; a
run becomes lost only when its confirmed owner reports `:not_found`.

`Ouroboros.InteractiveSession` applies the same ownership model to Harness sessions.
It checkpoints session configuration, logical turn intents, Harness turn IDs,
redacted events, terminal results, and an exclusive cursor. Multi-turn follow-ups,
native steering, approval responses, and interruption remain provider-capability
gated. A coordinator restart reattaches to the same live Harness session; a full
Harness/BEAM restart cannot reconstruct the provider process and resolves to `:lost`.

### Evolution plane

`Ouroboros.Upgrade.NodeExecutor` is a policy-protected node-local authority. It accepts
signed, content-addressed bundles of already compiled BEAMs and their exact
preimages. Compilation and tests belong in an isolated build peer, never inside the
production loader.

Fast-lane transaction:

1. Verify runtime, signature, exact base hashes, policy, epoch, and module features.
2. Ask the code server to prepare the complete batch.
3. Suspend only declared stateful processes.
4. Atomically finish loading the batch.
5. Invoke explicit `code_change/3` migrations and resume.
6. Run health checks through the cluster coordinator.
7. Promote with soft purge, or downgrade state and restore preimages.

Never brutal-purge. If retired code remains on a process stack, quarantine the node
and retain rollback material. Retention is literal: when a commit fails at or after the
point where code became visible and compensation cannot finish, the terminal journal
record keeps the artifact and its migration targets rather than clearing the only
durable copy of the preimages.

Each module in an artifact carries a disposition. `:replace` is the transaction above.
`:introduce` loads a module that has never existed in this VM: no preimage is captured,
step 7 inverts to an unload (`:code.delete/1` then soft purge), and the identity the
node then expects for that module is `:non_existing` — a checked expectation, so a name
that reappears fails closed like a wrong hash would. Introduced modules cannot be
declared stateful, because a module nothing is running has no state to migrate, and the
retained rollback material for one is only its name: there are no preimage bytes to
keep when the way back is an unload. Unloading is not exempt from the no-brutal-purge
rule, so a process still executing introduced code yields
`{:introduced_code_in_use, module}` and quarantine. A single artifact may mix both
dispositions and commits or rolls back as one transition.

An introduction is additionally required to be absent — unloaded, unreachable on the
code path, and not already expected by the journal — and to be named under
`Ouroboros.Capability.`, the namespace `Ouroboros.Mesh` reserves for agents forged at
runtime. Neither rule makes introducing a module safer than replacing one. Any accepted
BEAM has full ambient VM authority however it arrived; the namespace gate only prevents
a new module from silently occupying an existing name.

Policy protects the modules that make these guarantees enforceable, not just the loader:
`Ouroboros.Upgrade.*`, `Ouroboros.Storage.*` (a patched journal writer makes every
write a silent no-op), `Ouroboros.Release.*` (the durable lane's authorizer),
`Ouroboros.Control.*` (which decides what gets patched), `Ouroboros.Gateway.*` (an
auth check that can be hot-patched is no auth at all), `Ouroboros.Agent.Effects*` and
`Ouroboros.Orchestration.*` (the forge and deploy entry points), `Ouroboros.Mesh` and
`Ouroboros.Mesh.*` (where deployed capabilities start), `Ouroboros.Runtime.Capabilities`,
`Ouroboros.Provider.Native` and `Ouroboros.Provider.Native.*` (path containment,
SafeWrite, and the OS sandbox), `Ouroboros.Workspace` and `Ouroboros.Workspace.*`
(the admission lease the file tools sit on), plus the application root and its
registry owner. On-load functions are detected by preparing the batch, because
`-on_load` lives in the Code chunk and never appears among a module's attributes; the
preimage is probed too, since rollback loads it with `:code.load_binary/3`.

The coordinator performs parallel prepare/commit, compensating abort/rollback,
optional health checks, promotion, and status across explicit connected nodes. It is
best-effort rather than atomic: ambiguous transport outcomes are quarantined. A
single executor preparation is reserved at a time, commit revalidates policy/base and
epoch, stateful declarations require migrations, and epoch monotonicity survives
rollback and executor restart.

This is not a security boundary against malicious loaded code. Any accepted BEAM has
ambient VM authority and can call the code server or mutate processes. NIF loading is
detected as a static import of `:erlang.load_nif/2` only; a runtime-resolved call is
not detected, and the import check is a policy gate rather than a proof. Independent
signing/authorization belongs outside the patchable application, preferably on a
separate least-privileged loader node.

The node executor durably journals write-ahead operations, monotonic epoch, retained
rollback receipts, expected loaded hashes, and quarantine. The journal key is not
versioned, so a checkpoint this build cannot interpret is read and quarantined with its
evidence preserved instead of disappearing behind a `:not_found` while the node's code is
already patched. Opaque OTP prepared-code
terms are intentionally not persisted and become `lost_on_restart`. A reservation whose
prepare reply was lost can be released by artifact id, so an ambiguous prepare does not
wedge the node; status reports the reservation's artifact, epoch, and prepare time.
Restart verifies loaded module identities and migration-process liveness; mismatches
fail closed. For an interrupted commit, the verified artifact and migration targets in
the write-ahead record let restart resume matching live callback processes before
retaining the incomplete operation in quarantine. Post-mutation journal failures trigger
immediate compensation where possible and otherwise leave an explicit
reconciliation-required quarantine.

Above the coordinator, `Ouroboros.Upgrade.Forge` owns the path from agent-authored
source to a signed artifact, and `Ouroboros.Upgrade.Rollout` owns the path from that
artifact to a live, health-gated capability. Both live under `Ouroboros.Upgrade.*` and
are therefore inside the protected set: what the forge produces can never patch the
forge.

Forge stages, each with its own named refusal:

1. `Forge.Source.validate/1` is parse-only. It checks the `Ouroboros.Capability.` name,
   parses source and tests with `Code.string_to_quoted/1`, requires exactly one
   top-level module matching the declared one, and walks both ASTs for `@on_load`,
   protocol definitions, `Code.*`, `:code.*`, `File.*`, `:file.*`, `System.cmd/shell`,
   `Port`, `:os.cmd`, `Node.*`, `:erpc`, `:rpc`, `Application.put_env`,
   `:persistent_term`, `:ets.give_away`, `:erlang.load_nif`, and node-explicit spawns.
   Nothing is evaluated, so a rejected source has defined nothing.
2. `Forge.BuildPeer` compiles and runs the candidate's own tests inside an OTP `:peer`
   started with `connection: :standard_io` and `-start_epmd false`. That peer is not
   distributed, so generated code has no distribution with which to reach the cluster.
   One deadline covers boot, compile, and tests; the peer is stopped in an `after` block
   on every path. `Forge.Sandbox` runs inside it and returns only plain serializable
   terms.
3. `Upgrade.Epoch.next/2` reads `last_epoch` from every target, allocates above the
   maximum, and persists the allocation durably *before* returning it, so a crash
   between allocation and use burns a number rather than reissuing one. An unreadable
   node is a refusal, not a zero. `:global.trans/4` serializes allocations in a
   connected cluster; it is not partition-safe, and the defence that does not depend on
   coordination is the target's own epoch monotonicity check.
4. `Forge.Signer` is the seam the agent cannot supply for itself. The forge never holds
   a key; it asks the configured module and the default refuses everything. The
   behaviour has two callbacks: `sign/2` takes the canonical payload, and the optional
   `sign_artifact/2` takes the whole artifact. The forge prefers the second whenever a
   signer exports it, because a payload is a hash of a manifest and a signer holding
   only the hash cannot check the manifest against the bytes it describes.
   `Forge.Signer.Remote` implements it; `Deny` and `Local` do not and are unchanged.

### Signing plane

`Upgrade.Signing.Service` is the other side of that seam, and it runs where the forge
does not: on a `:signer`-role node whose supervision tree contains this process and
cluster formation. Three properties make it independent rather than merely remote.

**The key is outside the patchable application.** It is read at `init/1` from the file
named by `OUROBOROS_SIGNER_KEY_PATH` (32 raw bytes or their base64), derived into an
Ed25519 keypair, and held in process state wrapped in a struct whose `Inspect`
implementation redacts it — so a crash report, a logged state, or an interpolated
exception cannot print it. `public_info/0` publishes the public half and renders the
exact `OUROBOROS_UPGRADE_TRUSTED_SIGNERS` entry a core node needs; there is no accessor
for the private half anywhere. `Forge.Signer.Local`, still shipped for dev loops, reads
its key from the configuration of the application it authorizes, which is precisely the
arrangement this replaces.

**The policy sees the whole artifact.** `Signing.Policy.Default` recomputes every
manifest claim from the BEAM bytes submitted — module name, sha256, md5, `vsn`, the
`:code.prepare_loading/1` on-load probe, static `:erlang.load_nif/2` imports, protocol
markers — for the new binary and, on a `:replace`, its pre-image. It requires every
module to be under `Ouroboros.Capability.`, with no configuration that widens that; it
requires `metadata.forge` to carry a `source_sha256` and a test report with no failures
and at least one pass; and under `:signing_require_eval` it requires a
`Rollout.Evaluation` spec it can validate. What it deliberately does *not* check is
anything only a target VM knows: epoch ordering (a signer has no view of any cluster's
watermark), pre-image currency, and module absence. Those stay with the executor and
survive the signature entirely. Every failure is `{:refused, reason}`; nothing raises
across the boundary, because an exception reaching the caller through `:erpc` would be
indistinguishable from transport ambiguity.

**Every decision is journaled before it is answered.** `Signing.Journal` is a bounded
record of issuances *and* refusals — artifact id, epoch, modules and dispositions,
requester, decision, reason, findings — checkpointed through
`:signing_journal_storage` (`Storage.DurableFile` in production) before the reply is
sent. A journal that will not accept the entry is a refusal to sign. The one asymmetry
is deliberate: the journal may record an issuance whose reply was lost, never a
signature that was returned without a record.

`Forge.Signer.Remote` is the client. It resolves the target from `:node` or
`:signing_node`, requires `Cluster.ensure_role(node, :signer)` before submitting, sends
the artifact plus an advisory payload over a bounded `:erpc`, and converts every
transport outcome into a typed error. The advisory payload is cross-checked and
discarded: the signature is always over bytes the service derives itself, so a
disagreement means version skew and stops the deployment rather than producing a
signature over bytes the requester did not expect.

Admission control sits in front of all of it: a per-requester sliding-window rate limit
and a maximum submitted artifact size. The requester is self-reported and journaled as a
claim, so the limit bounds accidents and retry storms rather than adversaries — see
"Safety boundaries" for what a connected node can do regardless.

`Rollout.deploy/4` checkpoints `:deploying` in the durable `Rollout.Registry` before any
node is mutated, deploys with `health_check: {Rollout.Probe, :ready?, [module]}`,
promotes on success, and classifies failure from the deployment's own recovery evidence.
The probe starts the introduced module as a throwaway mesh agent, sends one synthetic
signal, checks the answer, and stops it — and converts every exception, exit, and throw
into a health *result*, because an uncaught error would reach the coordinator as
transport ambiguity and quarantine a node the probe merely failed to satisfy. Only a
deployment whose every node proved compensation is recorded `:rolled_back`; anything
ambiguous is `:quarantined`, which has no automatic exit.

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
field is why the registry checkpoint is version 2; a version-1 checkpoint is widened on
read (absent report becomes `nil`) and anything else is still refused.

`compare: true` extends this to capability *upgrades*. A `:replace` beam for a live
module is admitted through this path and no other: the same spec runs against the current
version on every target first, and the challenger is promoted only if it passes at least
as many probes within `:capability_eval_regression_budget` of the champion's total time.
Both reports are recorded. This measures the declared probe set, twice, on a shared VM —
not production behaviour, not cost, and not with enough samples for the timing half to
mean much.

The isolation here is process-level and policy-level, never OS-level. The build peer
shares the host's user, filesystem, and network; the deny list is defeated by any macro,
`apply/3`, or runtime-built module name; and a forged capability that reaches a node runs
with the same ambient authority as every other module on it.

Quarantine is a refusal, not a warning: prepare, commit, rollback, and promote are all
gated on it, so a node whose loaded code provably disagrees with its journal cannot be
mutated further or have its preimages discarded by a promote.
`reconcile_quarantine/1` is the only exit and replays the same startup checks against
current state, journaling the transition when everything matches and returning
diagnostics when it does not. The operations log is bounded, except for pending
write-ahead records and records still carrying rollback material.

### Agent effect plane

`Ouroboros.Agent.Effects` is the layer at which an agent acts rather than projects. Six
Jido actions — start agent, stop agent, send message, delegate, forge, deploy — are
routed from typed signals on `Ouroboros.Agent.Worker` and call the same public APIs an
operator would. Everything else the agent does remains a pure state projection.

Each effect run is the same four steps, owned by `Ouroboros.Agent.Effects.Runner`:

1. The principal is `context.agent.id`, read from the agent struct the agent server
   owns. Jido drops `:agent`, `:state`, `:signal`, and `:agent_server_pid` from any
   caller-supplied action context, so the identity cannot be supplied by the sender. The
   signal's `from` is recorded as `claimed_from` and authorizes nothing.
2. `Ouroboros.Control.Grants.granted?/3` is asked about the concrete attempt — this
   module, this team, these nodes. It is deny-by-default: no entry, an attempt outside
   the allow-list, an attempt that does not name what the allow-list reads, a malformed
   call, and an unreachable authority are all refusals. Grants are checkpointed before
   they are acknowledged, and a revocation whose write fails leaves the grant standing
   rather than forgetting something it could not durably forget.
3. The work runs in a supervised task bounded by `:ouroboros, :effect_timeout`, never on
   the agent's own process. A forge boots a build peer, compiles, and runs a
   capability's tests; that is far longer than an agent server should block and longer
   than Jido's own action deadline.
4. The outcome settles back as `Ouroboros.Signals.EffectSettled`. Delivering it as a
   call is what orders it: a call arriving while the requesting call is still in flight
   queues behind it, so the in-flight registration written by the request's return value
   is always applied before the outcome that settles it. Refusals never start a runner
   and are cast instead, because a nested call would queue behind the very call it is
   inside.

Grants live under `Ouroboros.Control.` deliberately. That prefix is in the verifier's
protected set, so the fast lane refuses an artifact that would replace or introduce the
authority gating it: a capability an agent forged cannot patch the thing that decided it
could forge.

`state.forged` is what a `:deploy` resolves, and it is written only by settling an
in-flight effect this agent minted. A deploy therefore cannot ship bytes that arrived
any other way — and even then the artifact is re-verified and its signature re-checked
on every loading node.

The durable lane is separate. `Release.Metadata` builds and validates `.rel`, `.appup`,
and `relup` terms; `RelupBuilder` invokes `:systools.make_relup` without writing;
`Release.Artifact` validates a completed archive offline. `Release.Runtime` then gates
`unpack_release`, `check_install_release`, `install_release`, and `make_permanent`
behind ephemeral external authorization and a durable write-ahead journal. The default
authorizer denies mutation. Unpack publishes the exact verified bytes under a synced,
content-addressed name and gives OTP a same-inode alias matching the archive's validated
top-level `.rel`; operating-system ownership of that directory is part of the trust
boundary. Release and fast-patch journals sync both checkpoint file and parent directory
before acknowledging success. Tests use real tar archives and a deterministic adapter;
they do not execute a live embedded-release upgrade or reboot. Only that externally
rehearsed lane can prove restart persistence or an ERTS change.

### Code intelligence

`Ouroboros.CodeIntel` owns language servers on behalf of the node, never on behalf of a
session. One pool per host, keyed by `{workspace root, server id}`: sessions acquire a
ref-counted handle, the pool monitors the owner, and a session that crashes releases its
claim without anyone calling `release`. Two sessions editing one repository share one
server, one document stream, and one diagnostics cache. Servers must run where the files
are, so a fleet has one pool per host and a session on machine B uses machine B's pool;
every status entry names its `node()` for that reason.

The subtree is the last child of the `:core` tree, downstream of cluster formation, of
every plane, of the Codex account boundary, and of the gateway. It owns no durable state
and nothing rebuilds from it, so under `rest_for_one` its crash restarts nothing, and a
crash upstream restarts only a pool that rebuilds itself on the next request; the gateway
stays the only child a stranger can reach. It is unconditional because it is lazy: no
language server exists until a caller asks for one. It still carries a generous restart
intensity, because language-server failures are states inside the pool, never crashes
of it.

**Lifecycle.** A server is spawned on the first `acquire`, through the same
`priv/provider-exec` wrapper every provider CLI crosses, so it runs as the user with
umask 022 and cwd at the project root, with no interpolated command string. `initialize`
carries `clientInfo` and only the capabilities the pool consumes, bounded at 45 s because
ElixirLS, jdtls and Metals compile or index on first launch; ordinary requests are
bounded at 10 s. Idle servers stop after 600 s with no owner. A death is restarted with
doubling backoff up to `max_restarts`; the death past that marks the key `:broken` for an
hour, and every call against it then answers `{:error, :broken}` rather than respawning
something that has already failed. `shutdown`/`exit` get a bounded grace and then
`SIGKILL`, because closing a port closes pipes without reaping a child.

**Roots and discovery.** The project root is the nearest directory holding one of the
language's marker files, walking up from the file and stopping at — and including — the
workspace root, canonicalised and contained by `Ouroboros.Workspace.Path`. A file outside
every admitted root is refused before any directory is read, and a file with no marker
above it gets no server at all rather than one rooted at the workspace, because that
fallback is how monorepo false-positive diagnostics happen. Discovery reads the project's
own binary directories and then the user's `PATH`, and stops: **nothing is ever
installed**. An absent server answers `{:error, {:server_unavailable, id, hint}}` and the
hint text is the whole of this runtime's involvement.

**Budgets.** Per server, a soft RSS limit: exceeding it stops and restarts the server
once, and a second breach marks the key broken. Per host, a budget: while the measured
total is at or above it, nothing new is spawned — a healthy server is never killed to
make room, because the caller that would lose it did nothing wrong. RSS is read
off-process on a timer through an injectable reader; a reading that cannot be taken is
`:unknown`, and unknown is never treated as a breach.

**Documents and freshness.** `touch/3` takes a path and an action, never content: the
pool reads the file itself in the same message that assigns the next version, so two
writers cannot interleave into a state where the server holds older text under a newer
version. `diagnostics/2` answers only when the cached version equals the document's
current version, and `{:pending, version}` otherwise after waiting up to 5 s — a push
that arrived before the last edit describes text that no longer exists. A push carrying
an older version than one already cached is dropped, so the cache cannot roll backwards;
a server that reports no version has its push attributed to the current one and labelled
`:inferred`, because a weaker guarantee that says so is worth more than a strong-sounding
one that is not true. Pushes are deduped, debounced 150 ms, and capped per document.
Documents survive a server restart by being re-opened from disk, tracked by a per-key
generation.

**Ephemeral by design.** The pool checkpoints nothing and is not meant to. On restart
every server is gone, every document is closed, and the next acquire spawns fresh; the
only durable truth is the files on disk.

Diagnostics are fed back after native writes under a bounded edited-file policy, and the
model has one `code_intel` tool for diagnostics, nine navigation operations, rename
preview, and rename apply. The gateway exposes the same pool for clients, including
status. What remains absent is an installer — an unavailable server produces an install
hint and nothing is installed — plus formatting and a tree-sitter fallback for languages
without a server. Language-server stderr is inherited by the runtime process rather than
captured per server.
### Permission plane

`Ouroboros.Control.Permissions` is the second deny-by-default authority, and it answers a
different question from grants: not what an *agent* may do to the cluster, but what a
*provider* may do to this machine. It is consulted at the only two pre-tool seams this
runtime has — `Dialect.ACP.approval_request/2` and `Dialect.Codex.approval_request/2` —
before any `approval_requested` event is emitted.

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

The engine's namespace rides the same `Ouroboros.Control.` prefix as grants, so the fast
patch lane refuses an artifact that would replace the module deciding what code may do.

## Failure model

| Failure | Current behavior | Required next behavior |
| --- | --- | --- |
| Starting caller exits | Harness run and coding coordinator continue | Done |
| Coding coordinator crashes | Supervisor restarts it; durable cursor reattaches | Done |
| Interactive coordinator crashes | Reattaches to live Harness session and turn IDs | Done |
| Harness/BEAM/host restarts | Task checkpoint remains; missing local run becomes `:lost` | Explicit resume/retry policy |
| Remote owner disconnects | Returns `owner_unavailable`; does not corrupt state | Retry/backoff and operator view |
| Network partition during placement | `:global` cannot guarantee one owner | Consensus lease/admission service |
| Store write fails | Cursor is not advanced and events are not broadcast | Backpressure/health alarms |
| Workspace/registry owner restarts | Nonterminal durable roots remain reserved until the registered owner reclaims them | Cross-node consensus authority |
| Fast patch migration fails | Reverse migrated state and restore preimages, or quarantine while keeping the artifact and preimages journaled | Done; release persistence remains separate |
| Fast patch resume fails after loading | Compensate first; quarantine with retained rollback material only if compensation fails | Done |
| Fast patch prepare reply is lost | Reservation is released by artifact id; no code was loaded | Done |
| Introduced module is still running on rollback | `{:introduced_code_in_use, module}` and quarantine; never a brutal purge | Done |
| Introduced module reappears after rollback | Restart reconciliation fails closed against the expected `:non_existing` identity | Done |
| Forged capability fails its health probe | Every committed node is rolled back, the module is absent again, and the registry records `:rolled_back` | Done |
| Forged capability fails its signed evaluation spec | Rolled back before promotion, while the rollback material still exists, with the failing report recorded | Done |
| Evaluation is unreachable, slow, or answers a shape this build cannot read | Compensation is attempted and the registry records `:quarantined`, never `:rolled_back` | Operator reconciliation tooling |
| Challenger capability regresses the probe set against the live champion | Rolled back with both reports; the champion keeps running | Cost models, canary cohorts, statistical significance |
| Evaluation criteria are rewritten after signing | The manifest signature fails on every loading node | Done |
| Capability rollout outcome is ambiguous anywhere | Registry records `:quarantined` and never `:rolled_back` | Operator reconciliation tooling |
| Forge crashes between allocating an epoch and using it | The number is durably spent and never reissued | Done |
| Build peer boot, compile, or tests hang | One deadline covers all three; the callback is killed and the peer stopped | Done |
| Build peer compiles hostile source | The peer cannot reach the cluster; it can still reach the build host | Container/VM boundary with resource and network limits |
| Ungranted agent requests an effect | Refused as `{:effect_denied, effect, reason}` and recorded; the agent stays alive and nothing reaches the world | Done |
| Effect signal claims another agent's identity | The principal comes from server-side agent state; the claim is recorded as `claimed_from` and buys nothing | Done |
| Effect outruns its deadline | The work is killed at `:effect_timeout` and settles as a failure; the agent's process was never blocked | Done |
| Grant checkpoint write fails | A pre-rename failure is a definite refusal; a post-rename durability failure is `commit_outcome_unknown` and restarts the authority for reconciliation | Operator reconciliation tooling |
| Effect authority is unreachable | Every attempt is refused; there is no path that fails open | Replicated policy authority |
| Language server is absent from PATH | `{:server_unavailable, id, hint}` with the install command; nothing is installed | `ouro lsp install` (E1 follow-on) |
| Language server crashes | Restarted with backoff up to `max_restarts`, then the key is `:broken` for an hour and every call answers `{:error, :broken}` | Done |
| Language server exceeds its memory limit | Stopped and restarted once; a second breach marks the key broken | Done |
| Host language-server memory budget is exhausted | New spawns are refused; running servers are never killed to make room | Per-workspace budgets |
| Language server is slow or never answers | Every request has its own deadline and answers `{:error, :timeout}`; the server stays usable | Done |
| Diagnostics describe a version that is no longer current | Never served; `{:pending, version}` after a bounded wait, and an older push never overwrites a newer cache entry | Done |
| Language server reports diagnostics with no version | Attributed to the current version and labelled `:inferred` so the weaker guarantee is visible | Done |
| Code-intelligence pool crashes | Nothing else restarts; servers and documents are gone and the next acquire spawns fresh | Done; ephemeral by design |
| Team process crashes | Snapshot recovery adopts agents/tasks and resumes delivery | Done on one owner node |
| Scheduler or executor owner crashes | Same token is offered again for idempotent reattachment | Done on one owner node |
| Control process crashes | Durable request/plan/cancel intent is reconciled; stable IDs reused | Provider billing can still duplicate after response-before-checkpoint loss |
| Node restarts after fast patch | Original release boots | Build and rehearse the implemented OTP release lane |
| Release mutation result is ambiguous | Journal enters quarantine; no false success | Operator reconciliation and deployment rehearsal |

## Safety boundaries

- Development/test permits unsigned local patch tests. Production never does. Trusted
  keys arrive through `OUROBOROS_UPGRADE_TRUSTED_SIGNERS`; boot fails on a malformed
  entry and an unset variable trusts nobody.
- Upgrade policy rejects the upgrade, storage, release, control, gateway, effect,
  orchestration, mesh, native-provider, and workspace namespaces, the application root
  and its registry owner, on-load code, consolidated protocols, and sticky modules. It
  rejects statically imported `:erlang.load_nif/2`, which a runtime-resolved call
  evades. Loaded code remains VM-privileged.
- Newly introduced modules must be absent and named under `Ouroboros.Capability.`. Both
  rules are policy about names, not a sandbox: an introduced module is exactly as
  privileged as a replacement, and the gate only stops a new module from taking a name
  that already means something.
- Forge source validation is parse-only hygiene against accidents, not a sandbox. Macro
  expansion, `apply/3`, and runtime-built module names all defeat it by construction. The
  build peer is isolated from the cluster, not from the build host.
- The forge holds no signing key and constructs no signature. `:forge_signer` defaults to
  a module that refuses, and a signer whose key lives in this application's configuration
  (`Signer.Local`) lets the agent approve its own code. `Signing.Service` on a `:signer`
  node moves the key onto a host the patchable application does not run on, applies an
  independent policy to the full artifact before a signature exists, and journals every
  decision durably before answering. That is a narrower blast radius, not custody: the
  signer node is a connected cluster member, so any node that completes the distribution
  handshake can call the same service the forge calls. What such a node gets is a policy
  decision — the `Ouroboros.Capability.` namespace rule has no bypass for any caller,
  and the per-requester rate limit is keyed on a self-reported claim. Custody outside the
  distribution trust domain remains external.
- Agent effect grants gate the *action layer* — the typed signals a well-behaved agent
  flow travels through — and are deny-by-default, durable, and checked against the
  concrete attempt. They are not a sandbox and not a capability system. Any loaded BEAM
  can call `Ouroboros.Mesh.start_agent/2`, `Ouroboros.Upgrade.Forge.forge/2`, or
  `Ouroboros.Control.Grants.grant/3` directly without passing an effect action at all,
  because it retains full ambient VM authority. The hard boundaries remain the verifier's
  namespace policy, artifact signing whose production default refuses, and the isolated
  build peer.
- No effect exists for granting, so an agent cannot widen its own authority through this
  surface. That is a property of the surface, not of the VM, which is why the authority
  itself is fast-patch-protected and why signing approval belongs outside this
  application.
- The authority is node-local: one `Grants` process per node over that node's own
  checkpoint. An agent granted an effect on one node is not granted it on another, and
  nothing replicates or reconciles the two.
- Permission rules decide what the in-process Native loop and remaining ACP permission
  seam may execute. They are not an OS sandbox and do not reach a vendor transport that
  runs a tool without asking. Prefix matching is defeated by construction by command
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
- Coding requests default to workspace write and prompt approval where the provider can
  enforce it; a provider that cannot is refused at creation rather than silently
  downgraded, and the downgrade has to be typed out (`sandbox_mode: :default`).
  Read-only is explicit (`sandbox_mode: :read_only`). Interactive sessions instead omit
  an unenforceable default and run under the provider's own behavior.
- Provider flags do not replace an OS sandbox. Untrusted coding work needs a separate
  worktree/container/VM boundary with resource and network limits.
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
  above that fact, in exactly the same sense as the `Ouroboros.Capability.` namespace
  policy. A hostile connected node never calls those functions at all.
- Node role narrows blast radius rather than containing a compromise. A `:builder` node
  boots cluster formation and the WASM helper pool, and nothing that holds teams,
  sessions, journals, grants, or a control plane; a `:signer` node adds the signing
  service (and `RuntimeOwner` when a data directory is configured). Both remain fully
  authorized members of the cluster. Containment requires the build and signing hosts
  outside the cluster's trust domain, reached through something narrower than Erlang
  distribution.
- The OTP releases directory is deployment-owned infrastructure. Content addressing,
  exclusive links, and fsync do not defend against another OS principal that can replace
  files in that directory.

## Roadmap to a competitive coding system

### Milestone 1: reliable single-task execution

- deterministic provider-contract tests;
- real CLI fixture tests for argv, JSONL, process ownership, cancellation, and
  timeout behavior;
- append-oriented durable event store instead of rewriting an aggregate task map;
- ~~worktree provisioning and durable cleanup~~ (done: `Ouroboros.Workspace.Worktree`,
  above), explicit network policy, and the OS-level isolation a worktree does not give;
- budgets, retries, idempotency keys, telemetry, and operator diagnostics.

Stop condition: repeated crash/reattach/timeout/cancel tests show no duplicate run,
lost acknowledged event, leaked OS process, or ambiguous terminal state.

### Milestone 2: durable teams

- planner/evaluator policy above coordinator, workers, and correlated delivery
  (implemented as an explicit opt-in control plane);
- durable team DAG, dependencies, fan-out/fan-in, cancellation propagation, and
  result provenance (implemented with stable execution/delegation identities);
- capability-aware scheduling across nodes (bounded local scheduling is implemented);
- consensus-backed ownership leases for partition behavior.

Stop condition: multi-node fault injection proves deterministic ownership and replay
through worker, coordinator, and network failures.

### Milestone 3: safe self-improvement

Implemented:

- isolated build peers that compile and test candidate source changes
  (`Forge.BuildPeer` + `Forge.Sandbox`: a non-distributed `:peer` with a bounded overall
  deadline, always stopped, returning only serializable terms);
- a signing seam the forge cannot satisfy for itself (`Forge.Signer`, defaulting to
  `Deny`), with the artifact re-verified against trusted keys on every loading node;
- a signing *service* on the other side of that seam (`Upgrade.Signing.Service` on a
  `:signer` node, reached by `Forge.Signer.Remote`): the key read at boot from a file
  that node mounts and never leaves its process, an independent policy that recomputes
  the whole submitted artifact and structurally refuses anything outside
  `Ouroboros.Capability.`, an optional requirement that the artifact declare a valid
  evaluation spec, a per-requester rate limit, and a durable journal of every decision
  that must be acknowledged before a signature is returned. A signer node with no
  readable key refuses to boot;
- durable, crash-safe epoch allocation above every target node's journal
  (`Upgrade.Epoch`);
- a durable deployment-level cluster journal above the durable node executors
  (`Rollout.Registry`), checkpointed before any mutation, which never records ambiguity
  as a rollback;
- health-gated rollout with real rollback proof (`Rollout` + `Rollout.Probe`): a forged
  capability starts as a mesh agent and answers a signal on every target, or the whole
  deployment is compensated and the module is absent again everywhere;
- declarative, signed evaluation gates between commit and promotion
  (`Rollout.Evaluation`): a probe set that lives inside the signed manifest, is run on
  every target while rollback material still exists, and decides promote, rollback, or —
  on any ambiguous answer — quarantine; plus champion/challenger comparison for
  capability upgrades, holding a replacement to the pass count and total time of the
  version it displaces;
- an agent-reachable effect surface for all of the above (`Agent.Effects`), gated by a
  durable deny-by-default authority (`Control.Grants`) that is checked against the
  concrete attempt, identifies the actor from server-side state rather than the signal,
  bounds every effect, and records each one. `Agent.EffectLedger` checkpoints a
  content-minimized intent and exact grant snapshot before execution, durably settles
  outcomes and refusals, exposes bounded cursor queries, and recovers unfinished work as
  ambiguous without retaining prompts, message bodies, source, provider output, or BEAM
  binaries. An agent driven only by signals can forge a capability, deploy it, start it,
  and message it — and can be refused at any of those steps without dying;
- least-privileged builder and signer nodes (`Ouroboros.Cluster`): one release, one
  runtime, three roles. A `:builder` node boots cluster formation and the WASM helper
  pool, and nothing that holds teams, sessions, stores, scheduler, or control plane; a
  `:signer` node adds the signing service (and `RuntimeOwner` when a data directory is
  configured). `:forge_builder_node` relocates the build peer onto a builder without
  changing anything about the build. The builder must be runtime-identical to its targets,
  because the verifier checks the artifact's OTP/Elixir/architecture triple on every
  loading node; that constraint is *why* a builder is a role of the same release rather
  than a separate service;
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
  mounts, and an independent policy decides on the full artifact before any signature is
  produced. An agent that patches a core node cannot read that key, and cannot obtain a
  signature for a control-plane module at any price, because no code path on the signer
  produces one. What remains external is the rest of custody. A signer node is still a
  connected cluster member: a node that completes the distribution handshake can call
  the signing service directly, and can also do everything else `:erpc` allows on that
  host. Role isolation and TLS distribution narrow that surface; they do not close it.
  The per-requester rate limit is keyed on a self-reported claim. And there is no human
  in the loop — the policy is mechanical, so "independent" here means independent of the
  patchable application, not independent of the cluster. An HSM, a review queue, or a
  signing host reached over something narrower than Erlang distribution are all still
  outside this codebase.
- **real OS sandboxing.** The build peer is isolated from the *cluster*, not from the
  *host*: same user, same filesystem, same network. A `:builder` node moves that host
  off the production path, which is worth doing and is not containment — the builder
  remains inside the distribution trust domain. Compiling untrusted source safely needs
  a container or VM boundary with resource and network limits. The source deny list is
  hygiene against accidents and is defeated by any macro expansion, `apply/3`, or
  runtime-constructed module name.
- **partition behavior.** Formation connects nodes; it does not fence them. There is no
  quorum, no partition policy, and no reconciliation for a node that returns with stale
  state. Role and placement checks are observations about a *connected* cluster.
- **evaluation beyond the declared spec.** The gate that exists runs criteria somebody
  wrote and signed, on a throwaway instance, on each target, once. It decides promotion
  automatically and compares a challenger to its champion, which is real. What it is not
  is a measurement of production behaviour: there is no cost model, no canary cohort on
  real traffic, no repetition, and wall-clock over a handful of probes carries little
  signal, which is why the regression budget is deliberately loose. An artifact that
  declares no spec is still promoted on liveness alone — unless the signer was
  configured with `:signing_require_eval`, which refuses to sign one at all. That switch
  exists and defaults to off; what does not exist is any judgement about whether a
  declared spec is a *good* spec.
- **package assembly and reboot rehearsal** around the implemented `.appup`/`.relup`
  metadata/inspection lane. A forged capability lives in the running VM only; a restart
  boots the original release without it.

Stop condition: the agent can propose a change, but cannot authorize its own patch;
every rollout has a reproducible artifact, independent approval, canary evidence,
rollback proof, and a reboot-persistent release.

### Milestone 4: product differentiation

The BEAM advantage is not “another prompt loop.” It is long-lived, inspectable,
fault-contained teams: live process topology, typed event provenance, supervision,
node placement, resumable multi-provider sessions, and controlled behavior evolution.
Compared with a conventional single-process coding CLI, Ouroboros can keep several
logical workers and workflows alive, route them across connected nodes, recover each
plane from its own durable checkpoint, and evolve behavior through separately gated
fast-patch and release lanes. The product surface should expose those properties
directly through a terminal UI and API rather than hiding them behind one opaque chat
transcript.

That architecture creates promising future capabilities:

- live topology and fault-domain views instead of one transcript;
- long-running specialist teams that retain independent cursors and provenance;
- canary or cohort rollout of a behavior patch with health gates and retained rollback;
- evaluator-driven repair loops whose execution identity survives coordinator churn;
- heterogeneous provider workers selected by capability or policy; and
- build/sign/loader services an agent cannot self-approve. The least-privileged *roles*
  exist, forge builds already relocate onto a builder node, and the signing authority is
  a real service on a signer node with its own key and its own policy; what remains is
  moving those hosts outside the distribution trust domain, so that reaching them is a
  narrow request rather than full `:erpc` authority in both directions.

## Primary references

- [Jido documentation](https://jido.run/docs/getting-started/elixir-developers)
- [Erlang code loading](https://www.erlang.org/doc/apps/kernel/code.html)
- [Elixir `GenServer.code_change/3`](https://hexdocs.pm/elixir/GenServer.html#c:code_change/3)
- [OTP release handling](https://www.erlang.org/doc/system/release_handling.html)
- [SASL `release_handler`](https://www.erlang.org/doc/apps/sasl/release_handler.html)
- [Mix release hot-upgrade limitation](https://hexdocs.pm/mix/Mix.Tasks.Release.html#module-hot-code-upgrades)
