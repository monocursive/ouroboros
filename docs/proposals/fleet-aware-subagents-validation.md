# Fleet-aware subagents: implementation evidence

Work branch: `codex/fleet-aware-subagents`, based on `ffded0b` (`dev`).
The specification is [fleet-aware-subagents.md](fleet-aware-subagents.md).

This is a working acceptance record, not a release claim. The feature is incomplete
until all five slices and the integrated Mac/Ubuntu checks below pass.

## Current evidence

- Snapshot and mirror transfer: 49 focused snapshot/mirror/worktree tests passed.
  Real Git repositories prove staged index and HEAD preservation, untracked capture,
  ignored/configured exclusions, worktree-of-worktree capture, incremental bundles,
  digest/corrupt-bundle/size refusals, import serialization and interrupted-file cleanup.
- Native `agent(sync: true)`: a real peer VM reads the parent's uncommitted and
  untracked files from a peer-owned worktree. This plus the existing worktree gate:
  39 tests passed. Assertions about the target run through `:erpc` on the peer.
- A fresh worktree root under a canonicalized macOS temporary directory is admitted
  correctly; an unreturned provisioned worktree is retained even when Git reports it
  clean, including during boot reconciliation.
- Disposable Ubuntu 26.04 VPS prepared with OTP 29.0.5, Elixir 1.20.2, Rust 1.95.0,
  Hex, rebar3, Git and bubblewrap. A bubblewrap isolation smoke check passed. No
  physical fleet round trip is claimed yet.

## Required before completion

- [ ] A: discovery, live tag edits, prompt/tool facts, tag selection, both CLI modes.
- [ ] B: outbound provisioning reviewed, mutation-tested, integrated and live-verified.
- [ ] C: returned refs, bounded deliveries, acknowledged cleanup and failed-return retention.
- [ ] D: deadlines, progress, background approvals and live 700-second command.
- [ ] E: shared native/vendor spawn/result/stop semantics, scoped gateway and MCP tools.
- [ ] Adversarial review and committed mutation replay for every slice.
- [ ] Full integrated Elixir and Rust default/embed suites, format, Clippy, protocol goldens.
- [ ] Mac/Ubuntu setup, first/incremental transfers, returned dirty edits and deliveries.
- [ ] Rendered TUI/web rows and setup journey checked for clarity and actionable failures.
- [ ] FLEET, AGENT_EXPERIENCE, PROTOCOL, TUI and WEB documentation reconciled to evidence.

All local and remote test state must stay isolated from the developer's existing fleet.
