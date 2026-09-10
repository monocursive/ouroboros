# Proposal: fleet-aware subagents

**Status:** slices A–E implemented on `codex/fleet-aware-subagents`;
[final acceptance completed 2026-09-07](fleet-aware-subagents-validation.md)
**Written against:** `ffded0b` (dev, 2026-09-05); every citation below was read at that ref
**Scope:** the native provider's `agent` tool, the cluster posture seam, workspace
provisioning, and the two clients that draw subagent rows

---

## 1. Summary

The story this serves: an operator works on a React Native app in a session on a Linux
laptop. A Mac on the same fleet runs an Ouroboros daemon and has Xcode. The agent on the
laptop should know the Mac is there, know it can build iOS, ship the current state of the
repository to it, run the build as a child there, and get the result back — while the
operator keeps typing on the laptop and never touches the Mac.

At `ffded0b` the primitive exists and the story does not. A native session can already
place a child on another machine with `machine:` and `workspace:` (G3), fenced by the
target's own rules and sandbox, with approvals relayed back to the parent's human. What is
missing is everything around that primitive:

1. **Awareness.** The model is never told which machines are connected, what OS and CPU
   they run, or what they can do. It learns a machine name only by guessing one wrong.
2. **Provisioning.** Nothing moves code. The repository must already sit at an absolute
   path on the target, and the operator's uncommitted work stays on the laptop.
3. **Bounds sized for chat.** One turn, 300 s by default and 900 s at most, a 16 KiB
   summary, no way to bring a file back, and a background child that cannot ask.
4. **Provider coverage.** Only the native provider has `agent`; a Claude Code or Codex
   session running under Ouroboros cannot spawn a remote child.

This document decides how each gap closes, in five slices that keep every invariant the
current design is built on: absolute paths never cross nodes, tags never confer authority,
the parent's working tree is never modified, nothing deletes uncommitted work, every call
is bounded, and every new posture key is rolling-safe.

---

## 2. What exists today

**Placement.** `Ouroboros.Provider.Native.Tools.Agent` accepts `machine:` and
`workspace:` (`agent.ex:128-141`); a remote child is documented at `agent.ex:41-62`:
posture travels, filesystem authority does not, approvals relay back. `chosen_machine/1`
resolves the name against `[node() | Node.list()]` (`agent.ex:458-486`); the refusal on a
miss is the only place the model ever sees machine names (`agent.ex:556-575`).
`Subagent.spawn/1` sends `start_and_launch/1` to the target by `:erpc`, idempotent by
`task_id`, with an explicit ambiguous-outcome reconcile (`subagent.ex:174-256`).

**Facts.** `Cluster.local_fleet_posture/0` answers `node, role, running, machine,
runtime, wasm, workspace` (`cluster.ex:1438-1447`). `valid_fleet_posture?/2` checks five
keys and lets every other key ride along, which is the rolling-upgrade rule
(`cluster.ex:1516-1526`). `runtime_identity/0` carries `otp_release`, `elixir_version`,
`ouroboros_version`, `fleet_protocol_revision`, and `system_architecture`
(`cluster.ex:1816-1830`) — the CPU and OS are in that last string, but nothing reads them
out. The directory in `Cluster.Monitor` copies `runtime`, `wasm`, and `workspace` from
each probe and keeps `state: :local | :connected | :offline` with timestamps
(`cluster.ex:179-194`, `280-345`, `new_machine/2`). `Cluster.resolve_machine/1` accepts
a node string or the friendly machine name (`cluster.ex:1409-1421`).

**Prompt.** `Prompt.base/1` has sections Tools, Workspace, posture, plan, Rules,
Ouroboros sources, Style (`prompt.ex:69-135`) and no fleet section. At `ffded0b` it also
had a computer-use section; that plane was removed with desktop automation
(`docs/proposals/core.md` §4 A4). The prompt is
built when the session opens and again on compaction (`session.ex:1492-1520`), so
whatever it says about the fleet is a snapshot.

**Tools.** `Tools.specs/3` assembles the schema list and hides `agent`/`agent_result`
past the depth cap (`tools.ex:122-155`); `agent` is classified `:execute`
(`tools.ex:520`).

**Bounds.** `bash` caps `timeout_ms` at 600 s (`bash.ex:86`), and so does
`Exec` (`exec.ex:21`). A child defaults to 300 s and is capped at 900 s, settable per
node with `provider_options["subagent_deadline_ms"]` (`agent.ex:163-167`, `815-823`).
Progress is capped at 64 events per child (`subagent.ex:137`) and carries turns, tool
calls, files changed, and node — no elapsed time, no last activity
(`subagent.ex:694-705`). `agent_result` waits at most 60 s (`agent_result.ex:12-16`).
A background child "has no way to reach a human" (`subagent.ex:41-43`), so `agent`
refuses to spawn one whose tools could ask.

**Worktrees.** `Worktree.create/3` takes a path inside a repository, resolves the
toplevel and HEAD, and adds a detached worktree under `<data_dir>/worktrees/<hash>/<id>`
through argv lists on `Exec` (`worktree.ex:86-121`); the root is admissible only when it
sits inside `workspace_allowed_roots` (`worktree.ex:316-360`), which the runtime config
appends whenever any root is granted (`config/runtime.exs:227-240`). Cleanup never
deletes an uncommitted change.

**Stated non-claims.** FLEET.md: "No provisioning: nothing clones, fetches, or creates
worktrees"; tags, logical workspace maps, and workspace provisioning are on the deferred
list. research/agent-ux-2026/AGENT_EXPERIENCE.md G3: "Still: one turn per child, no steering into one."

**Tests that already hold these seams.** `test/provider/native/subagent_test.exs`,
`test/provider/native/subagent_remote_test.exs` (boots a real peer VM and proves
node-scoped decisions through `:erpc` on the peer), `test/cluster_test.exs`,
`test/workspace_worktree_test.exs`, and the cross-language goldens
`test/support/gateway_golden/event_provider_event_subagent.json` and
`event_approval_requested_subagent.json` with their Rust decode tests.

---

## 3. Decisions

**D1 — Live truth is a tool; the prompt carries a labelled snapshot.** Machines come and
go while a session is open. The `## Fleet` section lists what was connected when the
prompt was built and says so; the `fleet` tool answers the live directory. A model that
places work reads the tool first, and the prompt tells it to.

**D2 — Facts ride the existing posture seam, and every new key is optional.**
`local_fleet_posture/0` gains one `facts` map. `valid_fleet_posture?/2` keeps its five
keys; a peer on the previous release answers without `facts`, is a valid machine with
unknown facts, and every consumer reads `facts` with `Map.get/2`. No
`fleet_protocol_revision` bump: nothing here changes placement, routing, or ownership
semantics. A provisioning `:erpc` to a peer without the new modules fails `undef` and is
refused by name ("that machine runs a release without provisioning"), and a test proves
the sentence.

**D3 — Tags are the operator's claim; toolchains are detected by presence only.** Tags
live in the fleet profile, edited by `ouro fleet tag`, validated on read. Toolchain facts
come from `System.find_executable/1` over a fixed list and never from running a binary —
a probe must not execute anything. Both are advisory: FLEET.md's role doctrine applies
verbatim, placement checks are misconfiguration detection and never an authority boundary.

**D4 — A tag can select a machine; the concrete node is what persists.** `machine:
"tag:xcode"` resolves at admission against connected machines advertising the tag: one
match is the target, several are refused by name, none is refused with the tags that do
exist. This is FLEET.md's D5 exactly; nothing durable stores a tag.

**D5 — Provisioning is a snapshot commit shipped as a git bundle over distribution.**
The parent node builds a commit of its working tree without touching its index or HEAD,
bundles it against what the target already has, and streams the bundle in bounded chunks
over `:erpc` into a per-repository bare mirror on the target. The child's workspace is a
detached worktree of that mirror. No shell reaches the remote, no external remote is
required, no parent path crosses the wire — the target resolves its own paths — and a
bundle carries objects and refs only, never config or hooks.

**D6 — The parent's working tree is never modified; results come back as a ref.** At
settle the target snapshots the child's worktree, bundles it against the provisioned
commit, and ships it back; the parent fetches it into
`refs/ouroboros/subagents/<task_id>`. Files the child chose to deliver come back under
the parent's data directory, bounded. The rule "never delete uncommitted work" extends
to "never delete work that was not first shipped and acknowledged".

**D7 — Long children get a per-call deadline under a node ceiling, coalesced progress
with last activity, and a way to ask from the background.** Defaults do not change;
ceilings become operator-configurable so a build node can be sized for builds. The
session process, already the background subscriber, surfaces a background child's
approval between turns instead of denying it.

**D8 — Vendor providers get the same three verbs through `ouro mcp-serve`, last.** The
loop's spawn path is extracted into one module the gateway can call, so `agent`,
`agent_result`, and `fleet` mean the same thing from Claude Code as from the native loop.

**D9 — Ignored files do not travel, and the prompt says so.** `node_modules`, `Pods`,
build output, and every other ignored path stay where they are. Installing dependencies
on the target is the child's job; the first build in a fresh worktree is a cold build.
Provisioning hooks that would run install commands are deferred (§11).

---

## 4. Slice A — facts, the `fleet` tool, the prompt section, tag selectors

**Runtime.**

- `Cluster.local_fleet_posture/0` gains `facts: %{os, arch, hostname, tags, toolchains,
  provisionable}`. `os` from `:os.type/0` (`{:unix, :darwin}` → `"macos"`,
  `{:unix, :linux}` → `"linux"`, else the atom as a string); `arch` is the first segment
  of `system_architecture`; `hostname` from `:inet.gethostname/0`; `tags` from the fleet
  profile through the same size-bounded, `lstat`ed read `fleet_name/0` uses, validated
  against `^[a-z0-9][a-z0-9._:-]{0,63}$` and at most 32 — an invalid file yields
  `tags: []` plus `tags_error: <reason>` rather than a silent drop; `toolchains` is the
  subset of a fixed list present on `PATH`: `xcodebuild xcrun swift docker podman node
  npm pnpm yarn bun cargo rustc go java gradle adb flutter python3 uv mix elixir git
  make`; `provisionable` is `git on PATH ∧ data directory ∧ Worktree.admissible?/0`.
- `Cluster.Monitor` copies `facts` from each probe the way it copies `wasm` and
  `workspace` (`nil` until probed). `fleet.status` therefore carries facts with no new
  gateway method.
- `Cluster.resolve_machine/1` and `Agent.resolve_machine/2` accept `tag:<name>` (D4).
  Refusals list connected machines *with their tags*, so a miss teaches the model the
  vocabulary.
- New tool `fleet` (`lib/ouroboros/provider/native/tools/fleet.ex`), mode `:read`, no
  approval, one op. Shown only when `Node.alive?/0` — `Tools.specs/3` takes a
  `distributed:` option beside `subagent_depth:` — because a tool that always answers
  "not in a fleet" is noise on a single machine. Output: one line per machine — name,
  node, state (`local`, `connected`, or `offline since <time>`), os/arch, tags,
  toolchains, `provisionable`, role, and whether its runtime is compatible with this
  one — then a two-line footer on how to place work. Bounded at 64 machines.
- `Prompt.base/1` takes `fleet:` (a list of machine summaries, or `nil`) and renders
  `## Fleet` only when given: the snapshot, labelled "as of when this session opened —
  call `fleet` for the live list"; the contract of `agent` with `machine:` plus either
  `workspace:` (a path that exists there) or `sync: true` (slice B); tag selectors; and
  D9's sentence about ignored files. `Session.context_options/1` supplies it from
  `Cluster.fleet_status/0`, bounded, `nil` on any error — a slow directory never blocks
  a session from opening.

**Client (Rust).** `ouro fleet tag add|remove|list [--machine NAME]` edits `tags` in the
profile (`tui/src/fleet.rs`); the runtime re-reads the profile at probe time, so the
change appears on the next probe. `ouro fleet status` and `/machines` decode the optional
`facts` and render os/arch and tags; `fleet doctor` names an invalid tag.

**Tests.** `cluster_test.exs`: facts shape; a posture without `facts` is still valid; tag
validation on a planted profile; tag resolution one/many/none. `subagent_remote_test.exs`:
`machine: "tag:<peer-tag>"` lands on the peer, whose facts carry the peer's hostname.
Agent tool tests for the new refusal wording. Prompt test: section present only when
distributed, carries the label. `fleet` tool test against a scripted directory. Rust:
profile tag round trip and rendering; the `fleet.status` golden if one exists gains the
optional block.

**Live check.** On the two-node dev cluster: `ouro fleet tag add xcode` on the peer;
from a native session on the other node `fleet` shows it within one probe interval, and
`agent(machine: "tag:xcode", workspace: <peer path>)` runs there.

**Size.** M.

---

## 5. Slice B — outbound provisioning (`sync: true`)

**Runtime.**

- `Ouroboros.Workspace.Snapshot` (new). `commit(repo_root, task_id)` builds a commit of
  the working tree without touching the index or HEAD: copy `.git/index` to a private
  temp file, run `git add -A` with `GIT_INDEX_FILE` pointing at it (respects
  `.gitignore`; `[provision] exclude = [...]` in the workspace's `ouroboros.toml` becomes
  `:(exclude)` pathspecs), `git write-tree`, `git commit-tree <tree> -p HEAD`, and pin
  the result at `refs/ouroboros/snapshots/<task_id>` so gc cannot drop it in flight. Every
  call is an argv list on `Exec.run/3` with the 120 s cap `Worktree` uses (the runner
  must accept an `env:` option for `GIT_INDEX_FILE`; add it if it does not). Returns the
  commit, HEAD, the untracked paths it included (capped at 200, reported to the model so
  an un-ignored secret file is visible), and a byte estimate. An unborn HEAD is refused:
  commit something first.
- `Ouroboros.Workspace.Mirrors` (new, one GenServer per node). Bare repositories under
  `<data_dir>/mirrors/<repo_id>` where `repo_id = sha256(sorted root commits)` from
  `git rev-list --max-parents=0` — stable across clones, so two laptops with the same
  repository share one mirror on a target. One import per mirror at a time. API, every
  call bounded: `heads/1` (what the mirror already has, from `refs/ouroboros/incoming/*`),
  `begin_import/3`, `put_chunk/3`, `finish_import/2` (size and sha256 checked, then
  `git bundle verify`, then `git fetch <bundle> <commit>:refs/ouroboros/incoming/<task_id>`),
  and `worktree/3`, which calls a new `Worktree.create_detached/4` — the same marker file
  as today with `provisioned: true`, `repo_id`, and `source_node`, the same
  canonicalisation and lease. Temp files from an interrupted import are reconciled at
  boot like stray worktrees. At most 64 mirrors per node.
- `Ouroboros.Workspace.Provision` (new) orchestrates from the parent node, which owns the
  source: snapshot → target `heads/1` → `git bundle create <tmp> <commit> ^<basis…>`
  (basis is what the target has and this repository also has; an empty basis means a
  full bundle) → size check against `provision_max_bytes` → 1 MiB chunks over `:erpc`,
  30 s each, under a `provision_deadline_ms` of 600 s → `finish_import` → `worktree`.
  Returns root, commit, repo id, bytes, chunks, and basis. The bundle over the cap is
  refused with the alternative named: push to a remote both machines reach and use
  `workspace:`.
- `agent` gains `sync: true`. Rules: requires `machine:`; `workspace:` with `sync: true`
  is refused in this slice with the reason (in-place sync into a checkout a person may be
  using is deferred, §11); a provisioned root is a worktree, so `worktree: true` is
  implied; the parent must be inside a git repository. The missing-workspace refusal
  gains "or pass `sync: true` to provision this repository there".
- `Subagent.spawn/1` gains a provision phase before `start_and_launch/1`; the spec
  carries `provision: %{repo_id, commit, task_id}` and the target resolves the worktree
  path itself, so `request_attrs.cwd` for a provisioned child is set on the target. The
  `spawned` payload gains `provisioned`, `commit`, and `bytes`.
- The child's instructions are prefixed: "This is a snapshot of `<basename>` at
  `<commit>` from machine `<name>`, taken `<time>`. Ignored files did not travel; install
  dependencies with the project's own commands before building. Commit your changes;
  uncommitted work is returned too."

**Tests.** `workspace_snapshot_test.exs`: exact argv lists through the injectable runner;
the real index and HEAD are byte-identical before and after; untracked files included,
ignored ones not, excludes honoured; the pin ref exists. `workspace_mirrors_test.exs`:
digest mismatch refused, a corrupt bundle refused, imports serialised, boot reconcile of
temp files. `subagent_remote_test.exs`: a parent repository with an uncommitted edit → the
child on the peer reads that edit from a path under the peer's data directory, proven by
`:erpc` on the peer; a second spawn transfers fewer bytes than the first (incremental);
a bundle over the cap is refused with the sentence; a peer without `Mirrors` is refused
by name. Golden fixture for the extended `spawned` payload and its Rust decode test.

**Live check.** Mac ↔ Linux VPS, the topology already proven on 2026-08-28: a repository
with an uncommitted change; the child on the other machine prints the changed file; the
second run is incremental; `ls <data_dir>/mirrors` on the target shows one mirror.

**Size.** L.

---

## 6. Slice C — the return path and deliveries

**Runtime.**

- At settle on the target, before the worktree is retired: `Snapshot.commit/2` of the
  child's worktree when HEAD moved or the tree is dirty → bundle
  `<child> ^<provisioned commit>` → chunked `:erpc` to `Ouroboros.Workspace.Returns` on
  the parent node (same verification as an import) → `git fetch <bundle>
  <commit>:refs/ouroboros/subagents/<task_id>` into the parent's repository, serialised
  per repository, working tree and index untouched.
- The summary and the `settled` payload gain `returned_ref`, `returned_commit`,
  `returned_files` (name-status against the provisioned commit, capped at `@max_files`),
  and `return_error` when the return failed — in which case the worktree is kept on the
  target and its path is named. The parent's tool result tells the model how to look:
  `git diff HEAD...<ref>`, `git cherry-pick <commit>`.
- Deliveries: files the child writes under `<worktree>/.ouroboros/deliver/` (excluded
  from the snapshot) are tarred by argv, capped at `deliver_max_bytes` (32 MiB), shipped
  in the same return, and stored under `<parent data_dir>/deliveries/<task_id>/`; the
  summary lists paths and sizes. A build log, a test report, a simulator screenshot fit;
  an `.ipa` usually does not, and the cap says so.
- Retirement: a provisioned worktree is removed only after a successful return, through
  a new `Worktree.remove/2` option that verifies the tree equals the returned snapshot
  before deleting. The snapshot pin under `refs/ouroboros/snapshots/` is dropped on the
  parent after settle; `refs/ouroboros/subagents/*` are retained and documented.

**Client.** The settled row in the TUI and web transcript shows "changes returned as
`<ref>`" and the deliveries.

**Tests.** `subagent_remote_test.exs`: the child edits a file → the parent has the ref
with the edit and `git status --porcelain` on the parent is identical before and after;
a dirty child returns its uncommitted work; a failed return keeps the worktree and names
the path; deliveries over the cap are refused with the sentence. `workspace_returns_test`:
digest verification and per-repository serialisation. Golden fixture and Rust decode for
the new settled fields.

**Live check.** Same pair as slice B: the child modifies a file on the VPS; on the Mac
`git show refs/ouroboros/subagents/<id>` shows it and the working tree is untouched.

**Size.** M.

---

## 7. Slice D — long-running children

**Runtime.**

- `agent` gains `deadline_ms:` per call, clamped to a node ceiling
  `subagent_max_deadline_ms` (default 900 s — today's cap — absolute maximum 4 h);
  `subagent_deadline_ms` remains the default. `bash` `timeout_ms` is clamped to a node
  ceiling `bash_max_timeout_ms` (default 600 s, absolute 4 h), passed to `Exec.run/3` as
  an explicit `max_timeout_ms` — hooks, checks, and `grep` keep their 600 s.
- Progress: the 64-event cap becomes time-coalescing — at most one event per 5 s, a
  hard cap of 2000 per child, and always one at the start of a `bash` call — so an hour
  of `xcodebuild` is visible as one live row rather than silence after the 64th tool
  call. The payload gains `elapsed_ms`, `deadline_ms`, `last_tool`, and `last_activity`
  (at most 160 bytes: the command's first line or a path, content-minimised the way the
  ledger already minimises). `agent_result` with `wait_ms: 0` returns those facts for a
  running child.
- Background children that can ask: the session process is already the background
  subscriber. It forwards `{:approval, child_request_id, payload}` to the client as an
  `approval_requested` with the existing `subagent` block — between turns, not only
  during one — and routes the answer back through `Subagent.respond/3`. The `agent`
  refusal of a background child whose tools could ask is lifted for interactive sessions
  and kept for one-shot `ouro run`, where nobody can answer. The moduledoc sentence at
  `subagent.ex:41-43` changes accordingly. This is the piece that lets a `prompt`-mode
  session run a forty-minute build child in the background and still approve its
  `pod install`.
- The tool description states that a foreground child is bounded by the loop's tool
  timeout and that long children must be `background: true`.

**Client.** The folded subagent row shows elapsed time and last activity and refreshes
on every progress event; the `⇄ node` badge is unchanged.

**Tests.** `subagent_test.exs`: a scripted model emitting 500 tool calls produces a
bounded number of progress events with the last one carrying the last activity; a
per-call deadline above the ceiling is clamped; a background child's approval reaches a
fake client subscriber and the answer lands as an effect; a one-shot run still refuses.
`bash` tests: ceiling honoured, default unchanged. Golden fixtures and Rust decode for the
new progress fields.

**Live check.** A child running `sleep 700 && echo ok` with `deadline_ms: 900000` on a
node whose `bash_max_timeout_ms` is 1800 s completes; the row shows elapsed time
throughout.

**Size.** M for bounds and progress, L with background approvals.

---

## 8. Slice E — vendor providers

- Extract the loop's spawn path (`loop.ex:2203-2260`, `Agent.plan/2`, `Subagent.spawn/1`)
  into `Ouroboros.Provider.Native.Subagents`, used by the loop and by three new gateway
  methods — `subagent.spawn`, `subagent.result`, `subagent.stop` — scoped to the calling
  session's id, principal, and posture, with the same refusals in the same words. Facts
  come through `fleet.status`, which slice A already extends.
- `ouro mcp-serve` (`tui/src/mcp_serve.rs`) serves `agent`, `agent_result`, and `fleet`
  beside `approve`, so a Claude Code or Codex session under Ouroboros
  can place a native child on another machine. Approvals from that child reach the
  vendor session's channel through the `approval_requested` path the bridge already uses.

**Tests.** Gateway method tests and goldens; `mcp_serve` Rust tests; live: a Claude Code
session under Ouroboros spawns a native child on the peer and reads its returned ref.

**Size.** M.

---

## 9. Order, parallelism, and the review protocol

Slices A and D touch disjoint code apart from two functions in `agent.ex` and can run
in parallel; B then C are sequential (they share `Subagent` and `Worktree`); E is last
because it exposes what A–D proved. Suggested waves: **A ∥ D**, then **B**, then **C**,
then **E**.

Every slice follows the protocol the last three waves settled on:

- a worktree agent whose brief begins with the base sha to verify and reset to, seeded
  from freshly built helpers rather than the main checkout's `priv/`;
- a `file:line` brief listing the seams above and the invariants in §3 as things the
  reviewer will check, not as suggestions;
- an adversarial review of the branch diff, then a mutation replay of the slice's gate on
  a *committed* fix;
- the full `mix test` and `cargo test --no-fail-fast` on the integrated branch, never
  only the union of slice gates, with one or two integration-fix commits budgeted;
- a bounded live check on real machines for B, C, and D — the Mac ↔ VPS pair for
  provisioning and return, the dev cluster for the rest;
- docs in the same PR: the G3 row and the capability table in research/agent-ux-2026/AGENT_EXPERIENCE.md, the
  deferred list and the "What has been proven" paragraph in FLEET.md, PROTOCOL.md
  fixtures, and the TUI.md/WEB.md rows for the new cells. A claim goes into a document
  only after the test or live run that backs it exists.

---

## 10. Security posture and honest limits

- **One cluster is one trust domain**, unchanged. A joined machine can execute code on
  every other; tags and facts are self-reported and never an authority boundary. What a
  child may do is decided by the *target's* permission rules, engine, hooks, and sandbox.
- **What travels is objects and refs.** A bundle carries no config and no hooks;
  `git fetch` from a bundle runs no hooks, and a worktree of a bare mirror the runtime
  created has none to run. Untracked, non-ignored files travel: the tool result lists
  them so an un-ignored `.env` is visible, and `[provision] exclude` exists for exactly
  that file.
- **Ignored files do not travel.** Caches are per machine; the first build in a fresh
  worktree is cold. A target that already holds a checkout with installed dependencies
  is not used by this proposal (§11).
- **Bounds.** Bundle bytes, chunk size, chunk and total deadlines, deliveries, mirror
  count, worktree count per mirror, progress rate and total, the untracked-path list,
  and every ceiling in §7 are named constants or node options with stated defaults.
- **The parent repository gains refs under `refs/ouroboros/` and nothing else.** Its
  working tree and index are never modified.
- **A target that disconnects mid-child.** The child is stopped by the subscriber
  monitor as today; its worktree stays on the target and the return cannot run, so the
  summary says `return_error` with the path. Boot reconcile lists it; retrieving it is an
  operator action (§11).
- **Still one turn per child, no steering, no migration**; a network partition still
  produces independent views. None of this is partition-safe consensus.

---

## 11. Deferred, and why

- **In-place sync into an existing checkout on the target** (`workspace:` + `sync:
  true`): it mutates a tree a person may be using, and reusing its installed
  dependencies is the only reason to want it. Revisit with a clean-tree precondition and
  an explicit consent sentence.
- **Provisioning hooks** (`[provision] after = ["npm ci", "pod install"]`): running
  operator-declared commands on the target before the child starts is a permission
  question, not a plumbing one; it belongs with the permission plane's rule language.
- **Artifacts beyond the delivery cap**, and retrieval of a stranded worktree by
  `ouro`: a transfer command with resumable chunks.
- **Steering a running child**, follow-up turns, and toolchain *versions* (which require
  executing binaries at probe time).
- **Tags as a selector for `ouro new --machine` and the Machines menu**, once the native
  path has proven the vocabulary.
- **Automatic tag inference** beyond the fixed toolchain list.

---

## 12. The story, after A–D

```
> fleet
studio      connected  macos/aarch64  tags: xcode ios-sim   toolchains: xcodebuild xcrun node cargo git   provisionable
laptop      local      linux/x86_64   tags: —               toolchains: node cargo docker git             provisionable

> agent(machine: "tag:xcode", sync: true, background: true, deadline_ms: 2700000,
        prompt: "Install dependencies with the project's own commands, run the iOS
                 build for the simulator, fix what fails, and put the full build log
                 under .ouroboros/deliver/build.log.")
task-… spawned on studio: provisioned 4.2 MiB (incremental), commit ab12cd, worktree
<studio data_dir>/worktrees/…

> agent_result(task_id: "task-…", wait_ms: 0)
running · 9m14s of 45m · last: bash "xcodebuild -workspace ios/App.xcworkspace …"

> agent_result(task_id: "task-…")
completed · 3 turns · 11 tool calls · 2 files changed
changes returned as refs/ouroboros/subagents/task-… (ios/Podfile.lock, ios/App/Info.plist)
deliveries: build.log (2.1 MiB) under <laptop data_dir>/deliveries/task-…/
```
