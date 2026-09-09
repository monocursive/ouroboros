# Core: the reduction, September 2026

Status: **plan, decided 2026-09-09.** Written against `dev` at `3bc8887`. Every count below
was measured on that tree; every seam named was read. The four product decisions in §3 are
the user's. The four assumed cuts in §4 follow from the thesis in §1 and are each one
slice, so any of them can be vetoed without touching the others.

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
- **Merging the interactive and coding persistence schemas** is moot once C1 lands;
  the record in SIMPLIFICATION.md is updated by C7.

## 8. What this does not claim

The reduced tree is still about 100k lines of Elixir and 90k of Rust. That is one order
of magnitude, not two, and it is the honest floor for four theses that each need a
durable store, a supervision tree, a client, and a proof. A second reduction, if one is
wanted, starts from §7's list and from a benchmark number, not from this document.
