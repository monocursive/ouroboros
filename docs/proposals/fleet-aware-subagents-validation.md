# Fleet-aware subagents: implementation evidence

Work branch: `codex/fleet-aware-subagents`, based on `ffded0b` (`dev`).
The specification is [fleet-aware-subagents.md](fleet-aware-subagents.md).
This is an implementation acceptance record, not a release claim.

## Implemented and checked

- **A, fleet awareness:** optional facts, advisory tags, live inventory and labelled
  prompt snapshot. Real peer tag changes are observed after the connection is healthy;
  strict tag validation and ambiguity refusals are covered. The committed gate passed
  202 Elixir tests and 106 Rust fleet tests. Disabling healthy-fact refresh and weakening
  the tag end anchor each made its regression fail; restored gates passed.
- **B, provisioning:** a private-index snapshot preserves HEAD and index bytes, includes
  eligible dirty/untracked files, excludes ignored/configured paths, and transfers an
  incremental verified bundle into a target-owned mirror/worktree. Internal Git ignores
  hooks, global/system config and inherited config overrides. Removing forced exclusion
  from the private index made the partially staged exclusion regression fail; restored
  committed code passed.
- **C, returned work:** bounded imports, deliveries and idempotent acknowledgment;
  one returned commit contains the child's complete committed and dirty delta. An actual
  cherry-pick checks tree equality. Work is retained on failed/ambiguous return or changed
  cleanup state. Removing the provisioned-base parent made the cherry-pick regression
  fail. Foreground timeout/interrupt hands unfinished returns to the session; removing
  that handoff failed both real-peer regressions.
- **D, long children:** configurable per-call deadlines and node ceilings, coalesced
  activity, interactive approvals between turns, and one-shot refusal. A nil one-shot
  request regression and a subsecond node ceiling defect were fixed. Reintroducing the
  nil request access made the loop regression fail; restored code passed.
- **E, vendor bridge:** shared native dispatch, current owner posture, session-owned
  registry/sidecar, permissions/hooks/ledger and approval relay. Claude MCP attachment
  covers every interactive posture; the removed Codex CLI transport stays removed.
  Rust MCP initially passed 26 tests; the combined host gate passed 173. Mutating live
  posture refresh, hook execution, or MCP argument validation made the respective
  regression fail. Two later integration findings were fixed: stopping during return
  keeps collection available, and unanswered approvals no longer mask a foreground
  child's deadline or interruption. Both committed mutations failed their two
  regressions; the restored bridge/remote/subagent seam gate passed 57 tests.

## Physical Mac / Ubuntu evidence, 2026-09-07

The disposable Ubuntu 26.04 VPS has OTP 29.0.5, Elixir 1.20.2, Rust 1.95.0, Git and
bubblewrap. Mac and VPS connect directly over Tailscale with TLS distribution; readiness
passes after restarting the VPS service. Test fleet state is isolated from the user's
existing Mac daemon. Linux retains its user-namespace AppArmor restriction; a profile
admits only the exact sandbox executable paths used by the tests.

- **Outbound and return round trip:** first bundle 180885 bytes, second 540 bytes,
  one mirror. Actual native reads see the Mac's dirty/untracked files; ignored and
  configured exclusions are absent. A real child write succeeds under `workspace_write`.
  Both runs return committed and dirty changes plus a report, leave the parent HEAD,
  index and working status identical, pass a single cherry-pick tree comparison, release
  snapshot pins, remove acknowledged worker checkouts, and repeat acknowledgments safely.
  Model responses were scripted; a committed edit and artifact were seeded by bounded
  peer RPC while the child paused. Updated modules were loaded into packaged daemons.
  Evidence: `/tmp/ouro-fleet-bc-result.json` and the matching control/module scripts.
- **700-second background child:** real `sleep 700 && echo ok` completed in 700085 ms,
  returned `ok\n` with `is_error: false`, and collected as completed. Parent idle after
  20 ms and throughout all 140 progress observations. Requested bash timeout 800000 ms,
  node maximum 1800000 ms and child deadline 900000 ms. The actual process had no effective
  capabilities, `NoNewPrivs=1`, seccomp filtering, a read-only root and writable workspace.
  Model responses were scripted; command, timing, containment and lifecycle were real.
  Evidence: `/tmp/ouro-long-child-700-evidence/`.

## Client and integrated checks

- Initial complete Rust default run: **1658 passed**, no failures or ignored tests.
- Browser/protocol focused gate after display changes: **219 passed**.
- Actual web components rendered at desktop and phone widths. This caught long activity
  overflow and hidden return outcomes in folded rows. Wrapping now keeps page content at
  viewport width, folded rows name returned changes/delivery counts or incomplete returns,
  and expand buttons expose `aria-expanded`. Retained work is labelled without assuming
  it is uncommitted. Render fixtures: `/tmp/ouro-fleet-visual/`.
- Initial full Elixir run is under diagnosis; stale protocol docs were regenerated and
  their gate now passes. Sandbox-helper failures and data-directory test isolation are
  being checked before a fresh full integrated run.

## Remaining acceptance

- [ ] Run the real Claude parent / remote child check.
- [ ] Full final Elixir and Rust default/embed suites, format, Clippy and script checks.
- [ ] Final packaged builds and direct Mac/VPS readiness with the final source.
- [ ] Finish rendered TUI verification and reconcile this record to final evidence.

No push, merge, publication or production release is claimed.
