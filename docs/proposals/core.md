# Core: the reduction, September 2026

Status: **landed on `core`, 2026-09-10.** The plan from §0 on is as decided on 2026-09-09,
written against `dev` at `3bc8887`, with every count in it measured on that tree; this
status section is the record of what happened to it. The four product decisions in §3 are
the user's. The four assumed cuts in §4 follow from the thesis in §1 and were each one
slice.

## Status

### What landed, in which commits

Integration branch `core`, cut from `dev` at `3bc8887`; every slice was cherry-picked onto
it after its gates and an adversarial review, and every review produced a fix wave that
went with it.

| Slice | What went | Integrated as |
|---|---|---|
| C5 (§4 A3, A4) and C3 (§4 A1) | `code_intel/`, `desktop/`, the computer-use crate and helper, `tui/src/desktop_cli.rs`; `upgrade/{forge/,beam,node_executor,coordinator,artifact,module_name,verifier,rollout}.ex`, `scripts/forge-linux-test.sh`; the `code_intel.*`, `computer_use.*`, `runtime.lsp.status` and `upgrade.*` methods | `974c3977` |
| the preload fix | `Storage.DurableFile.ensure_build_loaded/0` (see below) | `6d497ed4` |
| C1 (§3 D3) | `team/`, `coding/`, `orchestration/`, `control/{server,run,planner,evaluator,evidence_contract,jido_ai,store}.ex`, `agent/{effects,coordinator,worker}.ex`, `signals.ex`'s plane structs, 28 gateway methods | `d91b3d96` |
| C6 (§3 D4) | `release/`, `web/live/machines_live.ex`, `tui/src/{fleet_add.rs,fleet/}`, the machines overlay, `scripts/{fleet-e2e.sh,install.sh,test-install.sh,dist-linux.sh,homebrew-formula.sh,check-release-workflow.*}`, `.github/workflows/release.yml`, the `dist*`/`fleet-e2e` targets, `dist/`; then (C6b) `Cluster.Revocations`, `ouro update`, `dist/release.pub`, `fleet.revoke` | `5e79771d` |
| C4 (§4 A2) | `sandbox/helper.ex`, `tui/sandbox/`, `c_src/fs_filter.c`, `priv/sandbox/`, the `LD_PRELOAD` half of `bwrap.ex`, `protects_files?/1`, `hides_files?/1`, `read_fence`, `OUROBOROS_SELF_UNFENCED_KEY` | `c9729f79`, `c06f2b01` |
| C2 (§3 D2) | the nine adapters, `process_driver.ex`, `removed_codex.ex`, `grok_auth.ex`, the ACP client under `provider/session/`, `Control.Permissions.Seam`, `interactive.request_approval`, `grok.account.*`, `interactive.start`'s `provider` and `interactive.configure`'s `mode`, `--provider`, `[defaults] provider` | `55ea4180` |
| C7 | nothing: this status, the configuration surface, README, ARCHITECTURE, SIMPLIFICATION, the link sweep, and the integration record under `scripts/fixture/` and `test/support/integration_fixture/` | the commits after `55ea4180` |

### What the reviews found that changed the plan

- **Atoms in durable files.** The C5 review found that deleting the last line spelling an
  atom is a durable-format change: `Storage.DurableFile` decodes with
  `binary_to_term(bytes, [:safe])`, which refuses to create an atom, so an upgraded node
  whose permission store held a `ComputerUse(…)` rule did not boot. The rule became part of
  every slice's brief, and `Ouroboros.Storage.RetiredAtoms` — one list, 197 names, one doc
  sentence each — is consumed at compile time by the adapter that decodes. The C1 review
  found the same sweep had to be transitive (the effect ledger stores an error term's whole
  atom skeleton) and that the blast radius differs by store: a `Storage.Records` store loses
  one record, a whole-file store loses the boot.
- **Quarantine.** The C3 review found the grants half of a hazard the slice had called
  inherited: a `:forge` grant naming a capability module minted at runtime loaded on `dev`
  only because the deleted node executor interned the name first, and no list can hold a
  runtime-minted name. `DurableFile.get_checkpoint_or_quarantine/2` moves such a file aside
  by name and the store starts empty; grants and the effect ledger read through it.
- **The preload.** The integration fixture found that under interactive code loading the
  atom table at the first decode is a function of boot order — 36 to 117 modules loaded at
  the ledger's first read, run to run — so `dev` lost its own effect ledger on a loaded
  machine. `DurableFile.ensure_build_loaded/0` loads the build once before the first
  `[:safe]` decode. The three mechanisms are disjoint; ARCHITECTURE.md's "Durable
  checkpoints" is the contract.
- **The floor of D4.** The C6 review found that "sets the cluster environment by hand" was
  unachievable as delivered: with a profile the launcher scrubs every `OUROBOROS_*` variable
  an operator exports, and nothing left could sign a second machine's certificate. C6c added
  `ouro fleet create --from`, `ouro fleet members add|remove`, `create --regenerate` and
  `sessions restore`, each a local file operation and none an enrollment; FLEET.md's recipe
  was run end to end. C6b had already deleted `Cluster.Revocations` (no producer),
  `ouro update` (no publisher) and `fleet.revoke`, none of which D4 named.
- **A1's list was wrong in both directions.** `upgrade/rollout.ex`, listed as staying, is
  the BEAM lane's deploy driver and went; `:forge_module`, listed as going, is lane W's
  injection seam and stayed.
- **D2's edges.** `grok_auth.ex` went (no native lane reaches xAI through it);
  `Control.Permissions.Seam` went with the ACP client that was its only caller; the approval
  *relay* stayed, because native subagents carry a child's approval to its parent through
  it. `Jido.Harness.Registry` merges the configured providers over nine bundled ones, so the
  refusal lives in `Interactive.State.new/2`, before a lease. The C2 review found five verbs
  failing a session record that names a removed provider and a permanent unowned
  reservation on its workspace; such a record is now history that loads, lists, closes and
  deletes, and reserves nothing.
- **A2's edges.** The C4 review found a live Linux test asserting the deleted `.git`
  semantic, two non-total questions, and a backend-less node that had started signing;
  `Sandbox.label/1` and the three questions are total, a node with no backend starts no
  signing service, and the Linux loss — a `.git` or `.ouroboros` created after the command
  starts, below the top level of a writable root — is stated in the code and the docs.
- **Integration.** Two `mode` functions the union of removals emptied were deleted; the
  Permission-plane section C1 had swallowed from ARCHITECTURE.md was restored; 19 dead
  `dialyzer.ignore-warnings` entries were removed, and the trap that file's by-line pinning
  sets is recorded in CONTRIBUTING.md.

### Measured, on the integrated tree, the way §0 measured

| | `dev` at `3bc8887` | `core` after C7 |
|---|---|---|
| `lib/`, Elixir (`.ex`) | 151,765 | 111,597 |
| `test/`, Elixir (`.exs`) | 123,312 | 97,504 |
| `tui/src/`, Rust (`.rs`) | 116,766 | 98,708 |
| application-environment keys read in `lib/` | 105 | 73 |
| keys set in `config/config.exs` | 68 | 47 |
| `OUROBOROS_*` variables read in `config/runtime.exs` | 53 | 41 |
| gateway methods in `Gateway.Methods.Contract` | 126 | 83 |
| names in `Ouroboros.Storage.RetiredAtoms` | 0 | 197 |

Every key still set in `config/*.exs` has a reader in `lib/`; none needed deleting at C7.
`Ouroboros.Runtime.Exposure` reads one key, `:signing_node`, and it exists.

The integration gate is `make boot-gate`: the fixture data directory `dev` wrote at
`3bc8887` (`test/support/integration_fixture/`), booted against this tree ten times plain
and ten times with every module preloaded, every count compared against the record.

## 0. Why

Between 2026-08-12 and 2026-09-09 the runtime grew from about 25k lines of Elixir to
152k, plus 117k lines of Rust in the terminal client, 123k lines of Elixir tests, and
105 distinct application-environment keys. Most of that growth is not wrong. It is
*duplicated*: three sandbox backends and a C shim, two forge lanes and three upgrade
mechanisms, three coordination layers above sessions, ten providers, three front doors,
a fleet product on top of a cluster. Each layer was justified when it was built. Together
they hide the thing that is different about Ouroboros behind the things every agent has.

This plan cuts to the core and states the core so future work is judged against it.

## 1. The thesis

Ouroboros is different from Claude Code, Codex, Cursor and OpenCode in exactly four ways.
Everything kept serves one of them. Nothing else is kept because it exists.

1. **Sessions are durable BEAM state.** A session survives its coordinator crashing, the
   node restarting, and the machine changing. Its history is replayable, rewindable, and
   its effects are recorded in a ledger that is an authority boundary, not telemetry.
2. **Subagents run across machines on Erlang distribution.** Placement is a cluster fact.
   A worktree lease, not a PID, is the unit of ownership.
3. **Containment is authority.** The model's shell runs under an OS sandbox whose label
   is honest or refused. Third-party and forged code runs as WebAssembly components whose
   authority is their import list, signed and content-addressed, deployed and rolled back
   without a rebuild.
4. **The runtime improves itself under human gates.** A session forges components and
   policy; promotion happens on recorded evidence; humans sign, merge, and promote; one
   benchmark says whether a change was an improvement.

The terminal client, the web client, the permission grammar, hooks, skills, MCP, and
web fetch are table stakes borrowed from the field. They stay because a coding agent
without them is not usable, not because they are the point.

## 2. What stays

| Plane | Lines | Serves |
|---|---|---|
| `provider/native/` loop, tools, context, model, mcp, hooks, skills, subagents | ~24k | the agent itself; thesis 2 and 4 |
| `interactive/`, `interactive_session.ex`, `session/`, `storage/`, `workspace/`, `audit/`, `agent/effect_ledger.ex` | ~15k | thesis 1 |
| `cluster.ex`, `cluster/`, `mesh/`, `mesh.ex`, node roles | ~3.5k | thesis 2 |
| `provider/native/sandbox.ex`, `sandbox/sandbox_exec.ex`, `sandbox/bwrap.ex` | ~2.6k | thesis 3 |
| `wasm/`, `wasm.ex`, `tui/wasm/` helper, `upgrade/signing/`, `upgrade/rollout/`, `upgrade/epoch.ex`, `upgrade/wire.ex` | ~22k | thesis 3 and 4 |
| `control/permissions*`, `control/grants.ex`, `control/policy_promotion.ex`, `control/policy_evidence.ex` | ~4.6k | thesis 3 and 4 |
| `self/`, `bench/self`, `bench/local`, `priv/self` | ~1.4k | thesis 4 |
| `runtime/` exposure, manifesto, capabilities (wasm half) | ~1k | thesis 4 |
| `gateway/` (reduced), `web/` (reduced), `tui/` (reduced) | | the front doors, both kept |

The remaining dependencies: `jido`, `jido_ai`, `jido_harness`, `req_llm`, `req`, `mint`,
`exqlite`, `toml`, `libcluster`, `phoenix*`, `bandit`, `earmark`, `erlexec`. The native
session is still registered as a `jido_harness` provider and `Interactive.Task` still
speaks `Jido.Harness.Session`; unwinding that is a later refactor, not part of this
reduction.

## 3. The four decided cuts

Decided by the user on 2026-09-09.

**D1. Both front doors stay.** No TUI or web cut in this pass. Both shrink as the planes
they render disappear.

**D2. Native is the only provider.** The wrapped vendor CLIs go: `claude_adapter.ex`,
`grok_adapter.ex`, `kimi_adapter.ex`, `opencode_adapter.ex`, `removed_codex.ex`,
`process_driver.ex`, the whole ACP client in `provider/session/`, and the
`config :jido_harness, :providers` overrides. `provider.ex`'s per-provider capability
matrix collapses to the native answer. `event_presentation.ex` keeps the semantic record
contract and loses provider-alias interpretation. The model backends the native loop
uses stay: `openai_auth.ex`, `anthropic_key.ex`, `xai_key.ex`, and `grok_auth.ex` only
if the native model catalog still reaches xAI through it.

**D3. The coordination stack above sessions goes.** `team/`, `team.ex`, `coding/`,
`coding_session.ex`, `orchestration/`, `control.ex`, and in `control/`: `server.ex`,
`run.ex`, `planner.ex`, `evaluator.ex`, `evidence_contract.ex`, `jido_ai.ex`, `store.ex`.
In `agent/`: `effects.ex`, `effects/`, `coordinator.ex`, `worker.ex`. The effect ledger
stays. Native subagents already run cross-node through `Interactive.Task`,
`Workspace.Worktree` and `Cluster.Facts` and use none of the above. Gateway namespaces
`agents.*`, `coding.*`, `control.*`, `plans.*`, `teams.*` and `interactive.delegate` /
`interactive.delegations` go with them, as do their TUI and web renderings.

**D4. The cluster stays; the fleet product goes.** `cluster.ex`, `cluster/`, roles,
formation, placement and `fleet.status` / `fleet.doctor` / `fleet.tags` stay. What goes
is enrollment and distribution: `tui/src/fleet.rs`, `fleet_add.rs`, `fleet/`, the
machines overlay, the `vps` / `studio` / `tailscale` / `invite` / `join` / `add` /
`create` / `service` subcommands, `web/live/machines_live.ex`, `scripts/fleet-e2e.sh`,
`scripts/dist-linux.sh`, `scripts/install.sh`, `scripts/homebrew-formula.sh`,
`scripts/check-release-workflow.*`, `.github/workflows/release.yml`, the `dist*` and
`fleet-e2e` make targets, the `dist-check` CI job, and the OTP release-installation
lane in `release/` with its `Release.Runtime` child. `make ouro` keeps embedding the
release tarball; an operator copies that binary to each machine and sets the cluster
environment by hand. FLEET.md is rewritten as the cluster document; DISTRIBUTION.md and
MULTI_MACHINE_UX.md are deleted.

## 4. The four assumed cuts

Each follows from §1. Each is its own slice.

**A1. The BEAM forge lane goes; lane W is the forge.** Lane W exists because the BEAM
hot-patch lane structurally cannot introduce a module, and a forged BEAM module runs with
the whole VM's authority, which is the opposite of thesis 3. Delete `upgrade/forge/`,
`upgrade/beam.ex`, `upgrade/node_executor.ex`, `upgrade/coordinator.ex`,
`upgrade/artifact.ex`, `upgrade/module_name.ex`, and `upgrade/verifier.ex` after moving
`verify_payload_signature/4` into `upgrade/signing/`. `wasm/deploy.ex`'s
`@rollout_plane` drops `NodeExecutor`; `wasm/rollout.ex` drops its `Upgrade.Beam` alias;
`runtime/capabilities.ex` and `tools/forge.ex` keep only their lane-W halves; the
`capabilities.admit` gateway method admits wasm proposals only; `upgrade.*` gateway
methods fold into `wasm.status`. `Rollout.Registry`, `Rollout.Probe`,
`Rollout.Evaluation`, `Epoch`, `Wire` and all of `signing/` stay because lane W stands
on them. The capability-namespace rule stays as a signing-policy rule.

**A2. One Linux backend, no shim.** Claude Code and Codex each run one Linux backend,
bubblewrap plus seccomp, and Codex demoted Landlock to a legacy fallback. Neither tries
to deny creating a `.git` that did not exist when the command started; that semantic is
ours alone and is what the LD_PRELOAD shim exists for. Delete `sandbox/helper.ex`,
`tui/sandbox/`, `c_src/fs_filter.c`, `lib/mix/tasks/compile.ouroboros_fs_filter.ex`,
`priv/sandbox/`, `scripts/sandbox-linux-test.sh`, the `sandbox*` make targets, and the
`LD_PRELOAD` / `OUROBOROS_FS_DENY` half of `bwrap.ex`. With two backends that both
express every policy, the capability matrix in `sandbox.ex` collapses:
`protects_files?/1`, `hides_files?/1`, `read_fence` detection, and
`OUROBOROS_SELF_UNFENCED_KEY` go, and `Hooks.trusted?/2` and
`Application.self_signing_children/0` stop asking. The forge's builder read fence stays
on both backends. The named follow-on is §7.

**A3. Code intelligence goes.** `code_intel/`, `code_intel.ex`,
`provider/native/code_intel.ex`, `tools/code_intel.ex`, the `code_intel.*` gateway
methods, and the LSP pool. Diagnostics on edit is a feature the field does without;
it is a language-server pool with a restart budget inside a runtime whose point is
elsewhere.

**A4. Desktop automation goes.** `provider/native/desktop.ex`, `desktop/`,
`tools/desktop_act.ex`, `tools/desktop_state.ex`, `tui/computer-use/`,
`tui/src/desktop_cli.rs`, the `computer_use.*` gateway methods, `priv/computer-use/`,
the `computer-use*` make targets, COMPUTER_USE.md and DESKTOP.md.

## 5. What each slice must leave behind

Every slice: `mix compile --warnings-as-errors`, `mix format --check-formatted`, the full
`mix test`, `mix dialyzer`, `cargo fmt --check`, `cargo clippy -D warnings` and
`cargo test` for both feature sets, `make golden` and `make protocol-docs` with zero
drift, `make bench-local` at 17/17, `make improve-selftest`, and the bench-self selftest.
A slice that cannot get a gate green on its own says so in its report instead of
skipping it.

Rules that apply to every slice:

- **Delete, do not deprecate.** No compatibility shims, no `@deprecated`, no feature
  flags that keep a dead path selectable. A config key whose only reader is deleted is
  deleted from `config/*.exs` and from `Ouroboros.Runtime.Exposure`.
- **No new features.** A slice that finds a bug fixes it only if the fix is required to
  keep a gate green, and names it in the report.
- **The golden corpus and PROTOCOL.md follow the contract.** Removed gateway methods are
  removed from `Gateway.Methods.Contract`, the golden fixtures, PROTOCOL.md and the TUI's
  client in the same slice.
- **Docs are code.** A slice that deletes a plane deletes or rewrites every document
  that describes it in the same slice. ARCHITECTURE.md's definition-of-done list and the
  README's feature list are rewritten by C7 against the tree as it is then.
- **Tests go with the code.** A test that only exists to exercise a deleted module is
  deleted, not skipped. A test that covers a kept module through a deleted seam is
  rewritten against a kept seam.
- **`docs/experiments/` is another session's untracked work.** Never add it.

## 6. Slices and order

| Slice | Cuts | Mostly touches | Wave |
|---|---|---|---|
| C1 | D3 coordination stack | `team/ coding/ orchestration/ control/ agent/ gateway/ interactive/ workspace/ web/live/deck_live.ex tui/src/model.rs tui/src/ui/app/` | 1 |
| C3 | A1 BEAM forge | `upgrade/ wasm/deploy.ex wasm/rollout.ex wasm/verifier.ex runtime/capabilities.ex tools/forge.ex gateway/` | 1 |
| C5 | A3 code intel, A4 desktop | `code_intel/ provider/native/desktop* tools/ gateway/ tui/computer-use tui/src/desktop_cli.rs Makefile` | 1 |
| C6 | D4 fleet product, release lane | `release/ tui/src/fleet* tui/src/ui/app/machines.rs web/live/machines_live.ex scripts/ .github/ Makefile docs/FLEET.md` | 1 |
| C2 | D2 native only | `provider/*.ex provider/session/ provider.ex event_presentation.ex interactive/task.ex config/config.exs` | 2 |
| C4 | A2 sandbox | `provider/native/sandbox* tui/sandbox c_src/ hooks.ex application.ex self/posture.ex Makefile .github/` | 2 |
| C7 | docs, config, README, ARCHITECTURE, SIMPLIFICATION, memory | `docs/ README.md config/` | 3 |

Wave 1 slices touch mostly disjoint directories and run in parallel worktrees. Where two
of them meet, in `application.ex`, `ouroboros.ex`, `gateway/methods.ex`,
`gateway/methods/contract.ex`, `tui/src/model.rs` and `tui/src/cli.rs`, the meeting is a
deletion on both sides and is resolved at integration. Wave 2 runs after wave 1 lands
because C2 rewrites `interactive/task.ex` and `provider.ex`, which C1 also edits, and C4
rewrites `sandbox.ex`, which C3 also reads. C7 runs last against the integrated tree.

Integration branch `core`, cut from `dev` at `3bc8887`. Slice branches `core-c<n>` in
`.claude/worktrees/c<n>`. Each slice is cherry-picked onto `core` after its gates and an
adversarial review; the reviewer's brief names the seams the slice claims to have closed
and asks for the one it missed. `core` reaches `dev` as one pull request.

## 7. What comes after

Not part of this reduction. Named so the reduction does not accidentally close the
door on them.

- **The VM backend for the shell.** WASM.md §10 stands: one isolated execution
  environment per session behind `Sandbox.wrap`, tied to the worktree lease, no guest
  NIC, egress through a host proxy that consults the permission engine with the existing
  domain rules, denials surfacing as `EROFS` / `ENETUNREACH`. Apple's Containerization
  on macOS 26, Firecracker or Cloud Hypervisor on a Linux host with `/dev/kvm`, and
  Lima with `nestedVirtualization: true` for local parity on an M3 or newer. This is
  the slice that makes the credential read fence structural and removes the last reason
  the shell and the signing seed share a disk.
- **Second-tier trims inside kept planes**, each a product decision: the precompiled
  artifact fast path and its upload/download slots in `wasm/`, audit bundles and
  archives, `tui/src/acp_serve.rs` and `mcp_serve.rs`, the interactive fork and
  handoff verbs, the web deck.
- **Unwinding `jido_harness`** from the native session.
- **Merging the interactive and coding persistence schemas** became moot when C1 landed;
  SIMPLIFICATION.md records that the interactive store is the only `Storage.Records`
  store.
- **A seccomp filter for the bubblewrap backend.** Claude Code and Codex both add one;
  after A2 this runtime has neither a seccomp belt nor a syscall bound on Linux, because
  the deleted helper carried the only one. Named by C4 so the reduction is not read as
  having decided against it.
- **What a same-node boot of an old directory does.** `make boot-gate` boots the fixture
  under a node name of its own, so recovery adopts none of its sessions and the counts are
  the files'. Booted as the node that wrote it, the recovery sweep resumes every native
  session it finds — starting fresh provider sessions, appending events, failing the one
  whose recorded harness session is gone — before the operator has asked for anything.
  Whether an upgraded node should resume sessions it cannot continue, or hold them as it
  now holds a removed-provider record, is a product decision this reduction did not take.

## 8. What this does not claim

The reduced tree measured at C7 is 111,597 lines of Elixir under `lib/`, 97,504 under
`test/`, and 98,708 of Rust under `tui/src/` — the plan said about 100k and 90k. That is
one order of magnitude, not two, and it is the honest floor for four theses that each need
a durable store, a supervision tree, a client, and a proof. A second reduction, if one is
wanted, starts from §7's list and from a benchmark number, not from this document.
