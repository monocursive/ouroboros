# Fleet-aware subagents: implementation evidence

Work branch: `codex/fleet-aware-subagents`, based on `ffded0b` (`dev`).
The specification is [fleet-aware-subagents.md](fleet-aware-subagents.md).
Acceptance completed on 2026-09-07. This is an implementation acceptance record,
not a release claim.

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

- **MCP bridge round trip:** the actual Rust stdio bridge connected over authenticated
  gateway TCP to a live session, listed the fleet, spawned a physical VPS child, collected
  its result, and inspected its returned Git ref. The child model was scripted and the
  parent was an MCP driver, not Claude. Evidence: `/tmp/ouro-fleet-mcp-wire-result.json`.
- **Native AI on the packaged VPS:** after the operator completed OpenAI device sign-in,
  `openai_codex:gpt-5.6-sol` through ReqLLM actually called native write and read tools and
  verified `VPS_NATIVE_AI_READY` in its test workspace. This used the packaged runtime
  at `31b3047`, without a scripted model or hotloaded modules. The test session was closed.
  Evidence: VPS `/tmp/ouro-final-vps-native-smoke.log`.
- **Real Claude parent and real native child:** after Mac reauthentication, Claude Code
  called the actual MCP `agent` and `agent_result` tools to delegate to the VPS's
  `openai_codex:gpt-5.6-sol` child, collect its returned commit, and inspect it with
  `git show`. The child actually read dirty and untracked inputs and returned
  `PHYSICAL_CLAUDE_REAL_NATIVE_RETURN_OK`. Ignored/configured exclusions stayed absent;
  parent HEAD, index and working files stayed unchanged. Both machines ran final packaged
  source `8706591`, with no scripted models, hotloaded modules or model configuration
  overrides. Test sessions were closed. Credentials were authorized separately on each
  machine and were not copied between them.
  Evidence: `/tmp/ouro-fleet-real-claude-result.json` and
  `/tmp/ouro-fleet-real-claude.log`.

Final `make ouro` builds at `8706591` succeeded on both hosts. The installed VPS service
is enabled, authenticated and ready after restart, with its native execution boundary
confirming the installed toolchains. The two final packaged daemons report two connected
machines over verified TLS; `fleet doctor` succeeds on both. The Mac acceptance profile
is isolated under `/tmp` and manually started, so managed recovery is intentionally not
installed there. Its explicitly pinned test ports overlap the ephemeral range; normal
product defaults are unchanged. This does not claim an upgrade of the user's default Mac
daemon. Evidence: `/tmp/ouro-fleet-final-mac-package.log`,
`/tmp/ouro-fleet-final-mac-posture.log` and `/tmp/ouro-final-linux-evidence/summary.json`.

## Client and integrated checks

- Final full Elixir suites at runtime/test tree `31b3047`: **4083 passed / 9 skipped on
  Mac**, **4065 passed / 27 skipped on Ubuntu**, zero failures or invalid tests. Linux
  required the real WASM helper and complete offline forge dependency cache. Mac ran
  with eight test cases at once and without competing build jobs. Logs:
  `/tmp/ouro-fleet-final-31b3047/mix.log` and VPS
  `/tmp/ouro-final-d6adc509-gate.log` (`d6adc509` has the identical tree).

- Complete Rust suites at `31b3047`: **1659 default / 1668 embed passed**, no failures or
  ignored tests. Strict Clippy then caught the enlarged child payload inflating every
  transcript enum value. The two-line layout fix at `8706591` boxes that payload; its
  **260 affected UI/corpus/transcript tests**, both strict all-target Clippy configurations
  and formatting passed. Script lifecycle checks and Elixir formatting also passed.
- Browser/protocol focused gate after display changes: **219 passed**.
- Actual web components rendered at desktop and phone widths. This caught long activity
  overflow and hidden return outcomes in folded rows. Wrapping now keeps page content at
  viewport width, folded rows name returned changes/delivery counts or incomplete returns,
  and expand buttons expose `aria-expanded`. Retained work is labelled without assuming
  it is uncommitted. Render fixtures: `/tmp/ouro-fleet-visual/`.
- Actual terminal App rendering covers running, returned and retained children at 40,
  80 and 120 columns. Explicit wrapping fixes clipped headings, activity and return refs.
  The UI, presentation corpus and transcript-cell gate passed **260 tests**. Rendered
  SVG/PNG/text fixtures: `/tmp/ouro-fleet-rendered/`.
- Fleet replay records its opening snapshot and tool availability, preserving them even
  when distribution is stopped before verification. The integrated replay/context/loop
  gate passed **85 tests**. Removing the recorded snapshot or rebuilding recorded tools
  from live distribution each failed the committed regression; restored gates passed.
- Integration fixed protocol documentation drift and fixtures that assumed no fleet or
  isolated data directory, plus Linux sandbox error wording. WASM helpers now enter their
  admitted scratch both before launch and after Linux mounts it. A real kernel regression
  checks relative-write/absolute-read agreement; removing backend cwd failed on Linux,
  restoring it passed. The earlier Mac startup timeouts did not recur in the full quiet
  run.
- Live tools continue to refresh between turns while replay keeps recorded schemas. A
  real MCP server becoming ready after session opening reaches the next model request.
  Removing the live/replay distinction failed that regression; restored MCP/replay gate
  passed **13 tests**.

## Acceptance

- [x] Run the real Claude parent / remote child check.
- [x] Full final Elixir suites on Mac and Ubuntu.
- [x] Full Rust default/embed suites, affected tests after the layout fix, format, Clippy
  and script checks.
- [x] Final packaged builds and direct Mac/VPS connectivity with the final source;
  managed VPS readiness and isolated manual Mac posture verified.
- [x] Finish rendered TUI verification.
- [x] Reconcile this record to final integrated evidence.

No push, merge, publication or production release is claimed.
