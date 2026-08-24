# Ouroboros Agent Experience: the 2026 bar, the map, and the plan

Status: research and plan written 2026-08-22 on branch `review-fixes`, with a dated status
section (§0a) recording what the implementation waves delivered. Below §0a nothing is
implemented unless it links to code that exists today; every scorecard
claim about the field cites a report in [research/agent-ux-2026/](research/agent-ux-2026/)
and every claim about this codebase was re-read in the source. Companion to
[ARCHITECTURE.md](ARCHITECTURE.md), [TUI.md](TUI.md), and [FLEET.md](FLEET.md).

## 0. Summary

**The bar.** By mid-2026 the top five developer coding agents by use are Claude Code
(39% of professionals), GitHub Copilot (21%), Codex (16%), Cursor (12%), and OpenCode
(7%). They converged on a shared interaction grammar — Shift+Tab permission modes, a
plan mode that sets execution autonomy on approval, Esc/Esc-Esc, a visible message queue,
`@`/`!`/`/` prefixes, `--continue` and forks, a context meter with compaction,
git-independent rewind, allow/ask/deny rules behind an OS sandbox, `AGENTS.md` and
hooks, mid-session model and effort switching, headless JSON streams, and inspectable
subagents — and on a shared rendering discipline: synchronized output, collapsed tool
rows with `Ctrl+O`, head/tail truncation with provenance, word-level diffs, a footer with
model/mode/context/cost, and notifications. The same model scores three points higher on
Terminal-Bench 2.1 inside Claude Code than inside the reference harness: the harness is
the product. And four scorecard rows have no leader at all — persistence across reboot
and machine change, lossless context, vendor-neutral cross-machine coordination, and a
durable per-effect audit ledger — which is the thesis this runtime was built on.

**The map.** Against a 25-row scorecard, `ouro` on this branch scores 23/75. The
table-stakes rows average 1.0; the open-slot rows average 1.5, two of them already at 2.
Three structural facts dominate: Ouroboros runs no tool loop, so it cannot add
diagnostics, veto a command, or offer a tool to any provider; the managed transports
(including Claude) have no approvals channel, so a Claude session at the plane default
`approval_mode: :prompt` has its tools **silently denied**; and `steer` is unsupported on
every provider but `pi`. A second class of gap is cheap: the structured turn envelope,
`model`/`reasoning_effort`/`system_prompt` at start, per-turn effort, `teams.delegate`,
the approval payload's diff and options, and nineteen of the twenty-nine event kinds are
all implemented server-side and unreachable or dropped in the client.

**The plan.** Twelve moves in five phases (§4.4, §8): fix what is silently wrong; render
every event; give the footer a brain; adopt the 2026 grammar; make approvals real on every
provider (a Claude bridge via `--permission-prompt-tool` and an Ouroboros MCP server);
survive restarts by resuming provider sessions; build `Ouroboros.Provider.Native` — an
Elixir tool loop on `Jido.AI` and ReqLLM's thirty providers — as the only honest home for
LSP, MCP, hooks, rules, compaction, checkpoints, worktrees, and the self-improvement
vision; run an LSP pool as a runtime service; make teams conversational and the fleet
view triage by need; make the effect ledger the feature; ship `ouro run --json` and
`ouro acp`; and distribute signed releases with channels. Projected scorecard: 34 after
Phase 1, 46 after Phase 2, 56 after Phase 3, 61–65 after Phase 4 — with 3s on the rows
nobody holds.

## 0a. Status as of 2026-08-23

Everything below §1 is the plan as written on 2026-08-22 and is left as the baseline it
was. This section records what the implementation waves of 2026-08-22/23 delivered on
`review-fixes`, slice by slice, with the evidence. Gates at the time of writing: the
full Elixir suite at **1854 passed, 0 failed**; the Rust suites at **0 failed** across
every target in both feature sets (≈3,000 test runs across the default and `embed` sets;
one epmd-binding test in `tui/src/fleet.rs` is load-flaky when a stray `epmd -daemon` is
running and passes in isolation every time); the local eval corpus at **17 / 17** through
the merged client. Every slice was built by a
babysat Opus agent in an isolated worktree, diff-verified against its own final report,
and merged with the CI-identical gates run on the merged tree; integration defects that
only the merged tree could reveal are listed under each track.

**Live-verified on the merged tree:** a real Claude Code 2.1.238 session started at
`approval_mode: :prompt` through `ouro run --provider claude` emitted `approval_requested`
(external, `kind: permissions`, the `Write` call with its cwd), the headless runner
answered it, `approval_resolved` followed, `hello.txt` contained `hi`, and the result
object reported `completed` with usage and `approvals: {requested: 1, answered: 1}` —
the silent denial §3.1 row 6 described is over for Claude at both `:prompt` and
`:default`. Also live-verified: `ouro run --resume` printing only the new turn's events;
Codex app-server `thread/resume` refusing a thread with no rollout (fail-closed to
`:lost`); the LSP pool's freshness gate against Apple clangd 21; `[` dumping a transcript
into tmux 3.7's native scrollback.

**Live-verified on 2026-08-23, on a default install (no `OUROBOROS_WORKSPACE_ROOTS`):**
the whole vendor diagnostics chain. A real Claude Code 2.1.238 session started through
`ouro run --provider claude` read the `PostToolUse` hook the adapter composed into
`--settings`, ran `ouro hook post-tool-use` after its `Edit`, which reached the gateway's
`code_intel.touch` (`gateway operate code_intel.touch` in the runtime log), which admitted
the session's own workspace, spawned clangd, and handed the model — which quoted it
verbatim in its answer — `Edit applied. Found 1 new diagnostic issue in …/main.c: error
5:11 [undeclared_var_use] Use of undeclared identifier 'undefined_thing'`. The same run
exposed that `ouro run` reported `files_changed: []` for that edit, fixed the same day
(see §I/H1 below).

### Fix-first (§6)

| # | Status |
|---|---|
| X1 | landed — `unsupported_approval_mode` typed refusal for `:prompt` on transports without an approvals channel (claude/gemini/grok/zai/codex-exec); lifted for Claude by the bridge below |
| X2 | landed — `options.capabilities` declares `steer`; chrome offers it only where truthy (`pi`, and since C3 the Codex app server) |
| X3 | landed — docs name `Ctrl-O` |
| X4 | landed — `[terminal] mouse`, one-time selection hint |
| X5 | landed — DEC 2026 bracket around every frame, cursor escapes inside |
| X6 | landed — `_excerpt`/`_bytes` leaf caps (128 KiB leaf, 512 KiB event, 4 MiB detail) + `interactive/coding.event_detail` |
| X7 | landed — Codex app-server `multimodal: :native`, `localImage` input items (schema from `codex app-server generate-json-schema`, 0.147.0) |
| X8 | landed — ACP diff content blocks → `file_change` with Myers unified diffs; commands/modes as `provider_event` kinds (`:status` is not a Harness type) |
| X9 | landed — `resume_or_lose/2` at all three `:not_found` sites; `State.request/1` now carries `provider_session_id`; `sequence_offset` keeps sequences monotonic |
| X10 | landed — turn-end dividers with elapsed time, queue badge |
| X11 | landed — the modal shows kind, command+cwd, the diff, provider options, reason, and a fifth "don't ask again for `<rule>`" answer |
| X12 | landed — plan cell + `Ctrl+T` panel |

### Tracks (§7)

| Slice | Status | Note |
|---|---|---|
| A0 | landed | `app.rs` → ten modules, no behaviour change |
| A1 | landed | sync output, `ctrl+x [` scrollback dump, `ctrl+x v` editor view, mouse honesty, `/raw` (copy mode) |
| A2 | landed | exhaustive `PresentationEvent` match — a new kind is a compile error; three-state thinking |
| A3 | landed | per-dialect summarisers, exploration groups, head/tail 6+6 with `… +N lines · ctrl+o` |
| A4 | landed | `ui/diff.rs`: gutters, word emphasis, counts from the parse, diffstat, `/diff` review overlay |
| A5 | landed | plan cell + `Ctrl+T` |
| A6 | landed | `pulldown-cmark` 0.13, Goose's hold-out rule for streaming tails, memo per (text, width, budget); no OSC 8 (ratatui has no cell attribute) |
| A7 | landed | ranked footer cells, `[statusline] command` (JSON stdin, 300 ms), `[notifications]`, OSC 0 title |
| A8 | landed | approval modal v2, snack bar (`ctrl+x a`) |
| A9 | landed | details as a tree over `Event::raw` with `event_detail` fetch, `/export [--json]`, `/copy raw` |
| A10 | landed | six palettes + `auto` (OSC 11) + `NO_COLOR`; screen-reader mode with Claude Code's label taxonomy and OSC 133; 392 colour sites routed through tokens |
| A11 | partial | protocol detection once at startup (kitty by handshake, sixel by DA1 attribute 4, iTerm2 by the documented terminal names; one bounded probe window shared with the OSC 11 theme probe; `OURO_NO_IMAGES`), bounded placement maths (≤ 40 rows, aspect kept), PNG/JPEG/GIF/WebP headers read over a bounded prefix with no decoder dependency, the inside-workspace path rule re-checked after canonicalisation, a one-row labelled image cell for the attachments this client sent (screen-reader and export arms by path only), `ctrl+x i` opens the newest image; kitty and iTerm2 encoders byte-tested. **The pixel blit itself is not wired** — placement after the transcript's scroll slice could not be verified without a real terminal, and a misplaced graphics escape corrupts the whole transcript rather than degrading to text; sixel is detected, not encoded; image *tool outputs* are not projected (the runtime's `input_accepted` carries no attachments) |
| A12 | landed | 5,000-entry gate: 2.6 ms debug / 0.6–1.3 ms release; found `Watch::entries` O(ledger) and the markdown memo thrashing |
| B0 | landed | capabilities + usage in `State.public/1`; tri-state chrome (only an explicit `false` hides) |
| B1 | landed | `interactive.configure` with `applies: :now | :next_turn` (`:now` only for `pi`); ACP refused by declaration (agent-invented mode ids) |
| B2 | landed (runtime + wire) | native read-only posture refused at the permission layer with a refusal that names planning, a `## Plan mode` prompt block, a held-turn plan-exit approval carrying `auto_edit`/`prompt`/`keep_planning` + a same-turn follow-up, durable across a resume; Claude `--permission-mode plan` (start-time only), Codex refused as `pending`, everything else refused by declaration. On the wire: `plan` on `interactive.start` and `interactive.configure` (its own path around the four-key Harness configure — native applies now, Claude refuses a mid-life change as `at_start_only`), a plan-exit answer may carry `provider_options: {choice, follow_up}`, and the record follows a plan exit so `interactive.info` stays true — proven end to end through the gateway with the scripted model. Client: a plan-exit modal in its own words (the payload's option rows, the plan or the prose, a follow-up composer, `ctrl+o` to lift the ceilings, numbered text for a screen reader), `/plan` with the `at_start_only` refusal rendered as the runtime's sentence, a `PLANNING` badge fed from `interactive.info`, the `configured` event, and the `plan_exit` event, `ouro new --plan`, and `ouro run --plan` which answers the question `keep_planning` headlessly (never granting `auto_edit` unattended) and carries the plan in the result — **live-verified** with the scripted model |
| B3 | landed | visible local+durable queue, `↑` retract, `Alt+Enter` steer where declared, Esc keeps the queue |
| B4 | landed | `@` chips → the object envelope; image paste into `<workspace>/.ouroboros/images` (self-ignoring); `/effort`; `/model` |
| B5 | landed | `Esc Esc` backtrack (fork where served, else edit-and-resend), `[keys] backtrack` |
| B6 | landed | `rename` + auto-title, `fork` via each transport's own verb (`fork` capability), picker/rail columns |
| B7 | landed | `workspace.exec` with `:operator_shell` ledger entry before run, envelope carries the last three; client `!cmd` states node, workspace, and approval posture before Enter, renders the reply as a block, dedupes the runtime's `operator_shell` cell by `command_digest`, and offers the engine's `suggested_rule` on refusal (`ctrl+x r` → `permissions.add`); `/btw` not done |
| B8 | landed | `keymap.rs`: 40 actions, `[keys]` grammar, every surface reads the map, `/keys` |
| B9 | landed | grouped `?`, first-run tips, `? new here` |
| C1 | landed | `Control.Permissions`: Claude Code's Bash semantics, four scopes, deny→ask→allow, protected paths, durable rules, every decision in the ledger, `permissions.{list,add,remove}` |
| C2 | landed | `ouro mcp-serve` + `--permission-prompt-tool` + `interactive.request_approval`; `ClaudeAdapter` bridges `:prompt` and `:default`; **live-verified** |
| C3 | landed (runtime) | `turn/steer` through `steer/3` (the adapter export, the JSONL request tracking, and the dialect return type all had to exist first — the runtime path did not); `acceptWithExecpolicyAmendment` offered only when Codex proposes one, answered by the same `scope: "session"` that writes the C1 rule; `item/permissions/requestApproval` now answered in its schema shape (it was being answered with a field the schema cannot read, and `seam.ex` read a `grantRoot` the schema does not have, so escalations reached the engine with zero paths); `thread/compact/start` and `model/list` as dialect halves with no runtime caller yet (a `compact` capability and a per-provider `models/1` seam are the pending runtime work); ten schema files pinned from codex-cli 0.147.0 and every frame asserted against them; live-verified frame-exact against `codex app-server --stdio`, not through a paid turn |
| C4 | landed (services + mode) | `Session.Service` serves an ACP agent's `fs/read_text_file`, `fs/write_text_file`, and the five `terminal/*` verbs through the runtime — paths canonicalised and contained like an admitted workspace, a write judged by `Permissions` as an edit or a create and emitting a real unified diff, a terminal judged as the shell execution it is (`Bash(…)` rules) and wrapped by the same `Native.Sandbox` the native shell gets (refused under `read_only` with no backend rather than run unwrapped), nothing blocking the transport process; the capabilities are declared only now that the handlers exist; `interactive.configure {mode}` carries the *agent's own* mode id, validated against the `availableModes` it published (approval/sandbox modes on ACP stay refused by declaration, as B1 decided). The Codex halves — `thread/compact/start` behind `interactive.compact` with a derived `compact` capability and a per-provider `models` seam — were in progress when the agent was stopped by the account's weekly usage limit; that work sits uncommitted in its worktree and is not on the branch |
| C5 | landed | `Ouroboros.Provider.Native.Sandbox`: `bash` runs inside macOS `sandbox-exec` (a Seatbelt profile after Codex's, roots as `-D` parameters never spliced into policy) or Linux `bwrap` (argv pinned byte for byte, untested here); `read_only` runs with writes only in a per-call scratch `$TMPDIR` and no external network (it used to be refused outright), `workspace_write` adds the workspace and `add_dirs` with `.git`/`.ouroboros`, the data dir and `~/.config/ouroboros` read-only — a `git commit` is deliberately outside it; loopback remains available on macOS for local build IPC while external access stays denied; policy denials are recognised from the backend's own text and answered with an escalation that tells the model to `ask_user`; `tool_call` events and the owner-projected session carry `sandbox: "sandbox-exec"\|"bwrap"\|"none"`; live escape tests on this Mac (home write, `.git` write, a real commit, local IPC, and an externally denied connection). No seccomp, no domain allowlist; hooks and `[checks]` still run unsandboxed; external network is on or off per node |
| C6 | pending | classifier |
| D1 | landed | `Ouroboros.Provider.Native` on ReqLLM (not `Jido.AI.Agent` — its runtime executes tools itself); approvals at the tool boundary; native steer; checkpoint before the terminal event; **no live model run yet** |
| D2 | landed | grep/glob/ls/`web_fetch`/`ask_user`/V4A `apply_patch`/skills/`todo` |
| D3 | landed | AGENTS.md hierarchy with lazy `paths:` rules, cache-stable prefix + fingerprint, meter → `usage.context_window`, compaction that refuses rather than lose its archive, handoff; client `/compact [focus]` (report as a block, then a re-measured meter), `/handoff <prompt>` (opens the child), `/context` (a scrollable page whose first line is `source`), all gated on `hello.methods` **and** `capabilities.transport == "native"`; the footer `%` is now `context_used / context_window`, not cumulative spend |
| D4 | landed | `Ouroboros.Provider.Native.Mcp`: a bounded stdio MCP client (one 15 s handshake budget including paginated `tools/list`, 60 s calls, 100 KB results with a visible truncation marker, restart cap then `broken`, idle stop, killed with the session that claimed it); tools appear as `mcp__<server>__<tool>` through one seam in the registry and go through `Permissions` like any other tool; servers by name from node config, `~/.config/ouroboros/mcp.json`, and a trust-gated `<workspace>/.ouroboros/mcp.json`; `mcp.list` on the wire; a real `mcp__fake__echo` round trip proven in events. Client: `/mcp` overlay (servers, states, tool counts, refusals with reasons, env *counts*) and `ouro mcp list|add|remove` writing the Claude-compatible `mcp.json` at user or workspace scope with private modes, refusing to clobber a different definition, never echoing env values, warning that a `url` entry will be refused by the runtime — live-verified, including the workspace-trust gate. stdio only — `url` servers are refused by name (`unsupported_transport`); no OAuth, no `resources/*`/`prompts/*`; the runtime reads the user file from `$HOME` while the client honours `XDG_CONFIG_HOME` (the client says so when they disagree) |
| D5 | landed | hooks (all ten events wired; `SessionStart`/`SessionEnd`/`PreCompact` dispatched by the session rather than the loop, bounded at 10 s each; `PreCompact` `exit 2` refuses a compaction the way `PreToolUse` refuses a tool) |
| D6 | landed | content-addressed pre-write snapshots, `rewind`/`rewind_points` (+ `interactive.rewind` on the wire); client `/rewind` as a menu with per-row warnings then a three-way `what` chooser, `Esc Esc` offers `r` where checkpoints exist; the facade now admits turn-id strings, not only ordinals |
| D7 | landed | `Workspace.Worktree`, `worktree: true` on both planes and on the wire. Until 2026-08-23 no session could write inside a worktree on a node with a data directory — worktrees live under `<data_dir>/worktrees` and the protected-path rule denied the whole data directory; neither D7 test wrote through a session's tools. The rule now exempts the worktree root (its `.git`/`.ouroboros` stay protected) and both OS-sandbox backends re-allow a writable root nested in a protected one |
| D8 | landed | Terminal-Bench adapter (`bench/terminal-bench/`, needs Linux + docker + a key for a number) and the local corpus (`make bench-local`: 17 scripted-model tasks through a real daemon and the real `ouro run`, 17 / 17); the corpus caught a stale-binary resolver bug and a `files_changed` double count |
| E1 | landed | per-node LSP pool, versioned sync, freshness-gated diagnostics, nine ops; placed after the gateway |
| E2 | landed | diagnostics after edit in the native loop; for bridged Claude sessions a `PostToolUse` hook (`ouro hook post-tool-use`, three fixed output shapes, exit 0 on every path) composed into `--settings` — **live-verified**; Codex has no hook (its app-server transport has no config plumbing — recorded as a gap, not guessed) |
| E3 | landed | `code_intel` tool (eleven ops, rename gated); `runtime.lsp.status`, `code_intel.{request,diagnostics,touch}` on the wire (node-routed, typed refusals, `pending` never reads as clean); `mcp-serve` serves `code_intel`/`diagnostics`/`touch` to Claude beside `approve`; `Diagnostics.signature/1` gives one definition of "the same diagnostic"; admission = configured roots **plus the workspace of every session the node holds** (a default install had none before 2026-08-23) |
| E4 | pending | `@symbol`, jump-to-definition |
| E5 | pending | structural index |
| F1 | landed | resume after restart |
| F2 | landed | `ouro --continue` and `ouro run --continue`: one fleet-fanned `interactive.list`, the newest non-terminal session whose workspace is this directory (by `updated_at`, ties by `created_at` then id), on any machine; no match refuses and creates nothing (`ouro run` exits 64) unless `--or-new`, which says so; `--continue` with `--resume` or with start options refused by name; a gateway that cannot answer the list is a failure, never an empty answer — **live-verified** (same session id on resume, a fresh turn subscribed from the session's cursor, nothing created on a miss). Workspace comparison is lexical across machines |
| F3 | landed | usage accounting, `runtime.models` from `llm_db` |
| F4 | landed | titles, list filters |
| F5 | landed | `/export`; compaction archives |
| G1 | landed | `interactive.delegate/delegations`; client `/delegate` with a caller-owned id, `delegation` events as transcript cells, child rows nested under the parent in the rail, `Ctrl+T` lists delegations beside the plan (Enter/Esc navigation lives in `/delegations`, a cursor surface) |
| G2 | landed | fleet triage: needs-input / working / done from declared state across every node, counts in the footer, node labels on rail cards and picker rows, offline owners keep their group with a `last_known` mark; `Space` peek and `r` reply on the session picker (the rail has no row cursor); `ouro agents [--json]` starts no runtime — **live-verified** against a scratch daemon |
| G3 | landed (runtime) | the native `agent` tool spawns a child native session inside the same interactive session — isolated context, the parent's tools intersected with an allowlist, never more permissive than the parent (plan, sandbox, approval mode), optional worktree (refused with the reason when the node cannot lease one), `background: true` with a companion `agent_result` to collect — with bounds: depth 2, at most 4 running children (a fifth is refused, not queued), 12 turns by default, a 300 s deadline, a 16 KiB summary; `provider_event kind: "subagent"` at spawn/progress/settled; a child's approvals reach the parent's channel; its usage folds into the parent's totals under the child's own turn id; its calls are ledgered with the parent named; stopped when the parent session closes. Live round trip through the interactive plane. It also found the D7 defect (no session could write inside a worktree on a node with a data directory), fixed the same day. Client rendering of the `subagent` events is pending; one turn per child, no steering into one |
| G4 | pending | visible agent-to-agent messaging |
| G5 | pending | orchestration UI |
| H1 | landed | `ouro run --json|--stream-json`, result object, exit codes; **live-verified**. `files_changed` counts every `file_change` plus the target of a well-known write tool once its result was not an error — Claude's harness adapter emits no `file_change`, so a Claude edit used to finish as `[]` |
| H2 | landed | `ouro acp`: ouroboros as an Agent Client Protocol agent on stdio (schema v1.21.0): `initialize` claims only what is true (`loadSession: false` — retention is bounded and ACP wants the whole conversation; no image/audio prompts — the runtime takes attachment *paths*; no MCP over the wire — `interactive.start` has no `mcp_config`), `session/new` → `interactive.start` with modes derived from the same gates `interactive.configure` applies (plan only where settable any time), `session/prompt` streamed as `agent_message_chunk`/`agent_thought_chunk`/`tool_call`/`tool_call_update` (with file-change content and locations)/`plan`/`current_mode_update`, `session/request_permission` from `approval_requested` with the runtime's own option rows passed through (plan-exit `optionId` → `provider_options.choice`), `session/cancel` → interrupt, `session/set_mode` → configure, resync from `run.rs`'s discipline, bounded everything, EOF interrupts and says so; 34 tests; **live-driven** by hand against a scratch daemon including an approval round trip (which found a placeholder `toolCallId` and fixed it). Not served: `session/load`, `usage_update` (no honest context size), ACP `diff` blocks (only a unified patch is retained); approval↔tool-call correlation is positional; a Zed `agent_servers` snippet documented |
| H3 | landed | `mix ouroboros.protocol.docs` generates `docs/PROTOCOL.md` (18 bands, 81 methods with scope, ceiling, a parameter table, the pinned fixture, and the errors it can answer) from `Methods.table/0`, a new declared `@params` contract, and the golden fixtures; an 11-test drift suite includes an AST check that `@params` equals what the validators enforce and a check that TUI.md §2.4 catalogues every method (it found the two rewind verbs missing; closed the same day); `make protocol-docs`; no thin clients yet |
| H4 | pending | HTTP/SSE |
| I1 | landed | `tool_call` entries for the native agent, checkpointed before the tool runs (a ledger that cannot record stops the tool) and settled with `completed\|failed\|refused\|timed_out`, content-minimised subjects (paths, a command digest, hosts, the MCP server and tool); `approval` entries for every human answer on every provider, written before the answer is forwarded, with `actor` (`human`, or `headless` — `ouro run` now names itself), `scope`, `rule_id`; `ledger_ref` `{node, id}` on `tool_call` and `approval_resolved` events; fair retention across kinds so a flood of tool calls cannot evict the only forge. Landing it exposed that the Claude bridge had been calling `Permissions.record/2` with the wrong shape since C2 — no bridged decision had ever reached the ledger; fixed the same day with a test against the real engine |
| I2 | landed | `/cost`, `/usage`, `[budget] max_cost_usd` |
| I3 | landed | `ledger.{list,get,export}` (`fleet: true` fans out over bounded `:erpc`, merges by `{node, sequence}`, names the nodes that did not answer); `ledger.export` is JSONL with `hash(n) = sha256(hash(n-1) ‖ line(n))` over a canonical encoding — client-verifiable, not tamper-evident storage; `ouro ledger [--fleet] [--since N] [--json]` |
| J1–J3 | landed (unexercised in CI) | `release.yml` signs `SHA256SUMS` with a minisign-compatible Ed25519 key from a CI secret and verifies its own signature before publishing; `dist/release.pub` is committed **unprovisioned** on purpose (a key nobody can sign with is worse than no key) and every reader treats that as "no key"; `ouro update [--check] [--from] [--allow-downgrade]` verifies the signature (both minisign forms, the global signature over the trusted comment too), then the digest, then replaces the binary atomically (write beside, fsync, rename), refusing with a documented exit code for each failure — **a build without a release key refuses even `--check`**; no HTTP crate (`curl`/`wget` with bounds and proxy discipline); `scripts/install.sh` (sha256 always, minisign when present and says so when absent, `~/.local/bin`, no sudo); Homebrew template + filler; `docs/DISTRIBUTION.md`; 54 structural checks on the workflow. Nothing has run in CI; the minisign verifier is cross-checked against an independent test signer, not yet against `minisign` itself; no key rotation story; no Windows; no channels |

### Scorecard now

Same rubric as §3.1; the 2026-08-22 column is the baseline, the 2026-08-23 column is
what a user of `ouro` on `review-fixes` gets today.

| # | Capability | 08-22 | 08-23 |
|---|---|---|---|
| 1 | Edit reliability & self-verification | 1 | 2 (native: read-before-edit, modified-since-read, diagnostics after edit, `[checks]`) |
| 2 | Benchmark standing | 0 | 0 (adapter in flight; no number) |
| 3 | Token efficiency & cost | 0 | 2 (usage + cost everywhere; cache-stable prefix; soft budget) |
| 4 | Responsiveness | 1 | 1 (managed transports still re-exec per turn) |
| 5 | Steering mid-turn | 1 | 2 (visible queue; native steer; vendor steer where declared — `pi` and, since C3, the Codex app server; Claude has no steer channel) |
| 6 | Plan / approval flow | 0 | 3 (approvals real on Claude/Codex/ACP/native with rules and "don't ask again"; native plan mode with a plan-exit question on the wire, Claude started planning; the three-choice modal is still the generic approval modal) |
| 7 | Input ergonomics | 1 | 2 (chips, image paste, `/effort`, `/model`, rebindable keys; no vim) |
| 8 | TUI rendering correctness | 1 | 2 (sync output, escape hatches, themes, a11y) |
| 9 | Work visibility | 1 | 3 (every kind rendered, plan panel, diff review, details tree, delegation rows, context page, operator-shell cells) |
| 10 | Permission model | 1 | 2 (rule engine with scopes, ledgered decisions, mid-session configure) |
| 11 | Sandboxing / isolation | 1 | 3 (worktrees on both planes; native `bash` under `sandbox-exec` on macOS with `.git` and the runtime's own config read-only and network off by default; `bwrap` argv pinned but unverified; no seccomp, no domain allowlist; hooks and checks unsandboxed) |
| 12 | MCP & tool ecosystem | 0 | 2 (native agent consumes stdio MCP servers by name with bounds and permissions; Ouroboros also *serves* MCP to Claude; hooks and skills landed; no HTTP/OAuth, no `ouro mcp add`) |
| 13 | LSP / semantic navigation | 0 | 3 (pool, native tool, the wire, MCP tools and a post-edit hook for Claude — live-verified end to end; no `@symbol` input or structural index yet) |
| 14 | Git-native flow | 0 | 1 (worktrees) |
| 15 | Persistence & resume | 2 | 3 (resume across BEAM/host restart for every resumable transport, from any fleet gateway; `ouro --continue` finds this directory's newest session on any machine) |
| 16 | Context management | 0 | 2 (meter for all, native compaction with a retained archive, handoff) |
| 17 | Memory & instructions | 0 | 2 (AGENTS.md hierarchy, skills; no cross-machine sync) |
| 18 | In-session parallelism | 1 | 3 (native subagents with bounds, summaries, and background collection; delegation on the wire and in the rail; the client does not draw `subagent` events yet) |
| 19 | Background handoff + remote attach | 2 | 2 |
| 20 | Cross-machine / fleet coordination | 2 | 3 (fleet ledger queries; triage across nodes in the rail, the picker, and `ouro agents`) |
| 21 | Programmability | 1 | 3 (hooks, skills, `ouro run --json`, MCP server, generated protocol reference, and `ouro acp` so editors drive it as an agent) |
| 22 | Install / update / auth | 1 | 2 (a signed self-update and an installer exist and refuse correctly, but no release has been cut with them and no key is provisioned; auth unchanged) |
| 23 | Provider freedom & pricing transparency | 2 | 3 (ten providers incl. native on thirty model vendors; cost shown) |
| 24 | Audit & governance | 2 | 3 (permission and operator-shell effects ledgered; fleet-wide queries and a verifiable export chain; native tool calls as ledger entries still pending) |
| 25 | Vendor honesty & stability | 1 | 1 |
| | **Total / 75** | **23** | **55** |

### Honest limits added this wave

- The native agent has never been run against a real model in this environment (no key;
  the `:live_native` test is defined and skipped). `Model.ReqLLM`'s chunk normalisation is
  the highest-risk untested code on the branch.
- `claude` sessions at `:auto_edit`/`:auto_approve` are unchanged — they never asked and
  still do not. Gemini, Grok, and Z.ai are still refused at `:prompt` (no bridge).
- The Claude bridge re-performs the pinned adapter's private argv assembly; if the pinned
  Harness changes how Claude is started, the bridged path must follow.
- A delegation is a coding task with a parent, not a sub-conversation (G3/G4 pending).
- `workspace.exec` is one command, one process; a detached grandchild outlives its timeout.
- The LSP pool inherits language-server stderr; ElixirLS/Expert cold starts are unmeasured
  against the 45 s initialize ceiling.
- Worktrees scope containment; `bash` still runs with the operator's privileges and the
  worktree shares the repository's object store.
- Test peers in `cluster_test.exs` never receive this repo's provider overrides.
- Code-intelligence admission follows sessions: a node admits its configured roots plus
  the workspace of every interactive session it holds, nothing else. Until 2026-08-23 a
  default install (no configured roots) had no code intelligence at all, and every
  code-intel test configured roots, so the suites never saw it — the local corpus, which
  runs a daemon with no roots, is where such defaults get caught now.
- The ledger export chain is computed over the answer and stored nowhere: it catches a
  copy altered after export, not a node that rewrote its own checkpoint first. The ledger
  is not replicated; `--fleet` asks every owner.
- `files_changed` in `ouro run` infers a write from a fixed list of tool names and a
  non-error result; a vendor tool named differently, or a write done through `Bash`, is
  not counted. New-only diagnostics over-report in two documented directions (a file the
  pool never held; an error whose range moved).
- Codex sessions get no post-edit hook; bridged Claude sessions at `auto_edit` /
  `auto_approve` get neither the MCP tools nor the hook.
- A native `tool_call` ledger entry names the Harness session id while an `approval`
  names the Ouroboros one (`interactive.info`'s `harness_session_id` bridges them); a
  `tool_call`'s `ledger_ref` carries no `sequence` because the row is broadcast before the
  write that admits it; `:timed_out` is inferred from elapsed time, not reported by the
  tool; a tool call now costs two ledger checkpoints on top of its permission writes.
- Codex steer is asserted at the dialect, not through a full Harness worker session; the
  amendment and permissions replies are schema- and fake-server-verified, never answered
  by a real Codex approval. The execpolicy amendment and the C1 rule are computed
  independently and agree by construction in the tested cases, not by derivation.
- `Interactive.State.account_usage/3` keeps the *maximum* of same-turn `usage` events,
  not the sum, so a native turn with several model calls under-reports; G3 folds a
  child's spend under the child's own turn id to sidestep it, but the parent's own
  multi-call turns are still under-counted. The `agent` tool is `:execute`, so under
  `prompt` a child that writes costs two approvals. Approval payloads carry no tool
  `call_id`, so `ouro acp` correlates a permission request with the call in flight
  positionally — right for today's sequential loop, not for parallel tool calls.
- C4's Codex halves (`thread/compact/start` behind `interactive.compact`, a
  per-provider models seam) were interrupted by the account's weekly usage limit; the
  ACP services and the `mode` key landed, the Codex work sits uncommitted in the agent's
  worktree and is not on the branch. The client draws neither `subagent` events nor the
  `ledger_ref` on tool rows yet.
- The MCP client speaks stdio only and validates no arguments (the server owns its
  schema); a `url` server is refused by name, never silently dropped. MCP tool names are
  absent from the cached system-prompt tool list (the loop rebuilds the specs before every
  model call, so the model still receives them), and a hallucinated `mcp__*` name reaches
  the permission engine before the in-band refusal names the real servers.
- Client halves of B7/G1/G2 were verified against the scripted `App` harness and the
  corpus, plus `ouro agents`/`ouro ledger` against a live scratch daemon — not the
  interactive screens against a live socket. The delegations panel and the `/context`
  meter are read on demand (`Ctrl+T`, `/compact`), not on a cadence; `Space`/`r` triage
  keys are on the session picker, not the rail; the `--worktree` refusal path (a workspace
  that is not a git repository) is rendered through the ordinary error path and was not
  exercised live.


## 1. Method and sources

This document was produced on 2026-08-22 from eight parallel investigations, then
re-verified by hand before anything here was allowed to drive a decision.

Five external research lenses, each by a web-researching agent with a mandate to cite a
primary source for every non-obvious claim and to tag anything it could not confirm as
*unverified* (the reports keep those tags; this document does not launder them):

| Report | Lens | Where |
|---|---|---|
| R1 | Interaction model: compose, modes, turn control, sessions, multi-agent, onboarding | [research/agent-ux-2026/R1-interaction-model.md](research/agent-ux-2026/R1-interaction-model.md) |
| R2 | Display and rendering: transcript, tool cells, diffs, footer, widgets, performance | [R2-display-rendering.md](research/agent-ux-2026/R2-display-rendering.md) |
| R3 | Tool surface, permissions, extensibility, embedding protocols | [R3-tools-permissions-extensibility.md](research/agent-ux-2026/R3-tools-permissions-extensibility.md) |
| R4 | LSP and code intelligence | [R4-lsp-code-intelligence.md](research/agent-ux-2026/R4-lsp-code-intelligence.md) |
| R5 | The 2026 landscape, complaints, demand signals, and a 25-row scorecard | [R5-landscape-and-scorecard.md](research/agent-ux-2026/R5-landscape-and-scorecard.md) |

Three read-only codebase maps over this branch (`review-fixes`, 665 Elixir + 501 Rust tests):

| Report | Scope | Where |
|---|---|---|
| M1 | Provider event → gateway stream → TUI cell: every kind, every limit | [M1-display-pipeline-map.md](research/agent-ux-2026/M1-display-pipeline-map.md) |
| M2 | Keys, slash commands, composer, gateway methods, what the TUI never calls | [M2-interaction-map.md](research/agent-ux-2026/M2-interaction-map.md) |
| M3 | Harness adapters, dialects, ownership line, extension seams | [M3-provider-tool-layer-map.md](research/agent-ux-2026/M3-provider-tool-layer-map.md) |

Every codebase claim that a decision below rests on was re-read in the source by the
author of this document, not taken from a report. The verified set: the `Ignore` arm that
drops 19 of 29 event kinds ([model/transcript.rs:163](../tui/src/model/transcript.rs));
the one-line tool result ([transcript_cells.rs:880](../tui/src/ui/transcript_cells.rs));
`DIFF_LINES = 12` and the other render caps ([transcript_cells.rs:26-34](../tui/src/ui/transcript_cells.rs));
the subject-only approval modal ([view.rs:395-411](../tui/src/ui/view.rs)); the 29 Harness
event types ([event.ex:15-46](../deps/jido_harness/lib/jido_harness/event.ex)); the absence
of any bell, OSC 9/777 notification, or tab-title write (only OSC 52 exists,
[mod.rs:300](../tui/src/ui/mod.rs)); the structured turn envelope
([methods.ex:1433-1447](../lib/ouroboros/gateway/methods.ex)) and `@start_options`
([methods.ex:261-275](../lib/ouroboros/gateway/methods.ex)); zero TUI call sites for
`teams.delegate`/`teams.add_worker`; `steer/3` returning `{:error, :unsupported}` in both
dialects ([acp.ex:107](../lib/ouroboros/provider/session/dialect/acp.ex),
[codex.ex:101](../lib/ouroboros/provider/session/dialect/codex.ex)) with only `pi`
declaring `steer: :native` ([pi.ex:142](../deps/jido_harness/lib/jido_harness/adapters/pi.ex));
`mcp_config` in `@rejected_inline_options` ([task_state.ex:28](../lib/ouroboros/coding/task_state.ex));
managed transports declaring no `approvals` capability
([transport_spec.ex:56-83](../deps/jido_harness/lib/jido_harness/session/transport_spec.ex));
the Claude adapter's argv carrying `--permission-mode` but never `--permission-prompt-tool`
([claude.ex:87-108,161-163](../deps/jido_harness/lib/jido_harness/adapters/claude.ex));
the per-turn prompt seam `expose_turn_request/2` ([task.ex:811-817](../lib/ouroboros/interactive/task.ex));
the ACP catch-all that turns `diff` into an opaque `provider_event`
([acp.ex:190-200](../lib/ouroboros/provider/session/dialect/acp.ex)); the Codex app-server
capabilities omitting `multimodal` ([codex.ex:25-36](../lib/ouroboros/provider/session/dialect/codex.ex));
`:settings` absent from `@durable_provider_options`; no DEC-2026 synchronized-output
bracket anywhere in `tui/src`; `provider_session_id` durable in `Interactive.State`
([state.ex:30,87,365](../lib/ouroboros/interactive/state.ex)) while recovery still calls
`lose/2` on `:not_found` ([task.ex:384](../lib/ouroboros/interactive/task.ex)).

One docs/code drift was found on the way and is listed under §6: [TUI.md](TUI.md) says
`Ctrl-E` toggles event details; the code binds `Ctrl-O`
([app.rs:5929](../tui/src/ui/app/)) and `Ctrl-E` opens `$EDITOR`.

Caveats carried over from the reports: the Stack Overflow 2026 survey has not published
results (articles citing it recycle 2025 data); Codex TUI key tables and Antigravity
shortcut names come from third-party guides; a handful of vendor benchmark numbers are
marketing, not leaderboard entries. All are tagged in the reports.

---

## 2. The 2026 bar

### 2.1 Who is top five, and on what axis

Three independent lenses agree on the tier (R5 §1):

| Lens | Ranking |
|---|---|
| JetBrains Developer Ecosystem 2026, 15k professional developers, May–Jul 2026 | Claude Code 39% (31% as primary) · Copilot 21% · Codex 16% · Cursor 12% · JetBrains AI 9% · OpenCode 7% · Antigravity 6% |
| Pragmatic Engineer practitioner survey, Jan–Feb 2026 | Claude Code #1 (46% "love"), Copilot, Cursor, Codex rising; Gemini CLI / OpenCode / Antigravity ~10% each |
| Terminal-Bench 2.1 (harness + model, official board) | Claude Code + Fable 5 83.8% · Codex + GPT-5.5 83.1% · Terminus 2 + Fable 5 80.4% · Cursor CLI + Grok 4.5 79.3% |

So the consensus top five is **Claude Code, Codex, Cursor, Copilot, OpenCode**, with
Antigravity (Gemini CLI's closed-source successor) sixth and Amp, Pi, Droid, Devin as
contenders. Seats are earned on one of three axes — harness quality on a frontier model
(Claude Code, Codex), installed base and procurement (Copilot, Cursor), or open-source and
model-agnostic freedom (OpenCode, Pi) — with a non-embarrassing showing on the other two.

Two numbers frame everything that follows. The same model, Fable 5, scores 83.8% inside
Claude Code and 80.4% inside the reference Terminus 2 harness: **the harness is worth about
three points**, which is also the entire gap between first and fourth place. And OpenCode
is the most-starred coding agent on GitHub (200k) while holding 7% adoption: **freedom is
rewarded, but not as much as a superior loop.**

### 2.2 Table stakes

A top-five agent in 2026 cannot lack these. Each is present in at least four of the six
most-used tools; the reports give the per-product evidence.

**Interaction (R1 §4a)**
1. Shift+Tab cycles permission modes with a visible status-bar label (`⏸ plan mode on`, `⏵⏵ accept edits on`).
2. A read-only plan mode whose approval prompt chooses the execution autonomy ("Yes, and use auto mode" / "Yes, manually approve edits" / "keep planning"); Shift+Tab always exits it.
3. Esc interrupts without destroying work; Esc Esc backtracks (rewind menu or edit-previous-message).
4. Messages queue while the agent works, the queue is visible, and it can be pulled back into the editor.
5. `@` fuzzy file/dir mention, `!` shell passthrough, `/` command menu with fuzzy matching.
6. Multiline (Shift+Enter / Ctrl+J), Ctrl+G to `$EDITOR`, Ctrl+V image paste; vim mode is near-universal.
7. `--continue` plus a searchable session picker with human names and auto-titles.
8. Fork / branch a conversation.
9. The context triad: auto-compaction, `/compact [focus]`, and a `/context` or `/status` meter.
10. Git-independent file checkpoints and rewind.
11. Graduated permissions — allow/ask/deny rules, "allow for this session", sandboxed command tiers — rather than binary YOLO.
12. `AGENTS.md` (with `CLAUDE.md`/`GEMINI.md` fallback) and lifecycle hooks.
13. Model and reasoning-effort switching mid-session with an on-screen indicator.
14. Non-interactive `-p`/`exec` with streaming JSON and resumable session ids, plus an SDK or protocol.
15. Visible, inspectable subagents: a panel or child-session navigation where a worker's transcript can be opened, messaged, and stopped.

**Display (R2 §10a)**
16. No visible flicker: DEC-2026 synchronized output around every frame, plus either cell diffing (Codex/ratatui, Bubble Tea v2, OpenTUI, pi-tui) or virtualization (Claude Code fullscreen, Warp).
17. A predictable scrollback story: either native scrollback preserved (Codex, Kiro, Pi) or an explicit escape hatch (Claude Code `Ctrl+O` → `[` dumps the transcript to native scrollback, `v` opens it in `$EDITOR`; Codex `/raw`). Alt-screen without search/copy parity generated the loudest 2026 complaints.
18. Collapsed-by-default tool rows with one consistent expand key (`Ctrl+O` is the de-facto standard), plus a transcript view that shows everything.
19. Head/tail truncation of long tool output with a visible "+N lines" marker and a pointer to where the rest lives; huge outputs spill to disk with a preview.
20. Unified diffs in-terminal with line-level colour and word-level emphasis, per-file +N/−M, and a post-turn diffstat.
21. A persistent footer carrying model, permission mode, context %, and an interrupt hint — configurable, ideally scriptable (Claude Code `statusLine` JSON, Codex `tui.status_line`).
22. Terminal-title and bell/OSC 9 notifications gated on unfocused state, with tmux passthrough documented.
23. Light/dark auto-detection, an ANSI-safe theme, `NO_COLOR`, a plain-text/screen-reader mode.
24. Approval prompts that show the exact command or diff, offer a scoped "don't ask again", and take a reason with "No".

**Tools, permissions, extensibility (R3; R5 rows 10–12, 21)**
25. Read/edit/write/bash/grep/glob plus web fetch and an agent/subagent tool; edits expressed as anchored replacements with read-before-write guards.
26. MCP client (stdio + HTTP, OAuth) with lazy tool loading; hooks on tool-use and lifecycle; skills/commands; an SDK.
27. OS-level sandboxing or worktree isolation behind the permission model, not instead of it.

**Code intelligence (R4 synthesis a)**
28. Post-edit diagnostics, bounded: edited-file scope, new-only against a pre-edit baseline, ≤5 s wait, explicit "edit applied" wording, silent fallback — or, at minimum, a project-declared typecheck/lint hook.
29. One navigation tool with the now-standard nine operations (definition, references, hover, document/workspace symbols, implementation, call hierarchy ×3).

### 2.3 What the leaders do that the rest do not

From R1 §4b, R2 §10b, R5 §3 — the differentiators, with who sets the bar:

- **True mid-turn steering at the next tool boundary**, distinct from queueing (Pi Enter vs Alt+Enter; Amp; Codex Enter vs Tab; Cursor since Aug 2026). Claude Code still queues within the turn and carries two open steering issues.
- **Classifier-mediated autonomy as the default.** Anthropic's 1,053-tester study: humans caught 13.6% of dangerous commands, the classifier 89%; auto mode became the Pro/Max/Team default on 2026-08-14. Codex `--approve-for-me`; Goose smart-approve.
- **Tree-structured history with branch summaries** (Pi `/tree`), versus linear transcript + fork.
- **A fleet view that triages by "needs input"** with peek-and-reply (`claude agents`, `codex agents` + `codex queue`, Cursor Agents Window).
- **Side-channel questions that do not pollute context** (`/btw`, Kiro `/tangent`).
- **Hunk-level review with refine-in-place** (Zed, Warp, Cursor `Ctrl+R`).
- **One-keystroke handoff to another executor** (`&` in Cursor and Copilot; Claude Code `/bg`; Amp orbs).
- **Durable, shareable thread URLs with search filters** (Amp; OpenCode `/share`).
- **Effort as a first-class dial separate from model.**
- **Ambient awareness**: session recap on return after three minutes away, PR badge in the footer, prompt suggestions off the warm cache.
- **Rendering**: Codex's scroll-region history insertion and grouped "Explored" cells; Claude Code's scriptable status line, mouse semantics, per-turn `/diff`, screen-reader renderer; Warp's diffs that expand during approval and collapse after apply; Kiro's snack-bar permission prompt that never scrolls away.
- **Verification over generation** (R5 §3.2): agents that show evidence — tests run, claims cross-checked, unverified items flagged — are what practitioners now say separates great from good.

### 2.4 The open slots

R5's scorecard (§6 there; reproduced with Ouroboros scores in §3 below) has four rows
where **no product scores 3 today**:

| Row | Capability | Best today | Why the slot is open |
|---|---|---|---|
| 15 | Persistence & resume across terminal close, sleep, crash, reboot, and machine change | Claude Code agent view (a per-user daemon that survives sleep but "stops if the machine shuts down", parks idle sessions after ~1 h); Omnara (Postgres-committed state) | Every leader's story is a per-machine supervisor, a vendor VM that expires, or a relay that needs the local process alive. Anthropic's own Remote Control doc says: use tmux. |
| 16 | Lossless context management (reviewable pre-compaction history, tunable, never loses plan state) | Nobody; Claude Code #17428/#27242 open; OpenCode `/compact` that grows context (#17557) | Compaction is opaque everywhere. |
| 20 | Cross-machine / fleet coordination without a vendor relay | Claude Code cross-session messaging only through Anthropic's relay, plain text, off when telemetry is off; Warp Oz and Omnara self-host at 2 | Codex's two most-upvoted issues ever are "Remote Development" (875) and "Remote Control" (542); "headless remote Linux hosts for Codex mobile without the desktop app online" is still open. |
| 24 | A local, tamper-evident effect ledger that survives retention cleanup and machine moves | Enterprise audit logs and OTel export at 2 | EU AI Act logging obligations bit on 2026-08-02; a fresh Claude Code bug reads "No audit trail for retention cleanup". Nobody ships a per-effect ledger. |

plus a defensible 23/25 (provider freedom and policy stability) after a year in which
every subscription vendor had a quota scandal, Anthropic locked subscription OAuth to
first-party tools (Apr 4) and reinstated third parties only via separate credit pools
(May 13), Google shut consumer Gemini CLI down with a 30-day cliff, and SpaceX bought
Cursor. Developers answered by rewarding open, model-agnostic tools.

**That cluster is the thesis this codebase was built on** — long-lived sessions owned by a
daemon rather than a terminal, an Erlang cluster across the operator's own machines,
checkpoint-before-broadcast durability, and a grants/effect ledger. The market has now
named those as the unfilled rows. The plan's job is to make them *visible* as product
while closing the table-stakes gap fast enough that nobody has to forgive the basics to
get there.

### 2.5 Mistakes with receipts

The reports' "avoid" lists, compressed to the ones that bear on this plan:

- Changing the screen model by default without telling the user (Claude Code v2.1.89 regression; Gemini reverting `useAlternateBuffer`), and capturing the mouse silently (#72681). Print the "hold Shift/Option to select" hint; ship the escape hatch on day one.
- Blurring queue and steer, or changing their semantics under users (Codex #13595/#17285); disabling Esc when queued state exists (Claude Code #16905).
- Rewind that silently under-delivers (#18516). Say what is and is not restorable *before* the user commits.
- Appending diagnostics without an explicit "edit applied" line — agents read them as failed edits and loop (OpenCode #9102); stale pre-edit diagnostics (Claude Code v2.1.107 fix); thousands of diagnostics stalling the UI (v2.1.216).
- Prompt fatigue that drives YOLO: 98.9% of analysed Claude Code configurations had zero deny rules; an `rm -rf … ~/` incident. Graduated tiers and a classifier, and an explicit warning on session-wide approvals.
- Undiscoverable power features (OpenCode's fork keybind defaulting to `none`; users not finding `/compact` for months).
- Breaking the harness under users; silent removals; quota surprises in the compose loop. Stability of semantics is itself a feature — the exact philosophy behind Pi's 95k stars.
- Performance cliffs in long threads: measure at 5,000 messages (Amp publishes CPU/memory numbers; OpenCode's lag reports show the alternative).

---

## 3. Where Ouroboros stands

### 3.1 Scorecard

R5's rubric: 0 absent · 1 basic/partial · 2 competitive with the top tier · 3 sets the
bar. Scores below are for what a user of `ouro` gets today on this branch, with the
evidence. "Inherited" means the capability exists only because the vendor CLI underneath
has it and Ouroboros neither adds to nor surfaces it.

| # | Capability | Score | Evidence |
|---|---|---|---|
| 1 | Edit reliability & self-verification | 1 (inherited) | Ouroboros runs no tool loop; every tool executes inside the vendor CLI child ([M3 §1.3](research/agent-ux-2026/M3-provider-tool-layer-map.md)). Nothing in `lib/` verifies an edit, runs a test, or feeds a diagnostic back. |
| 2 | Benchmark standing | 0 | Not submitted; as a harness-of-harnesses it would score whatever the vendor scores. |
| 3 | Token efficiency & cost | 0 | `:usage` events (with `input_tokens`, `output_tokens`, `total_tokens`, and for Claude `cost_usd`/`duration_ms`/`num_turns`, [claude_stream.ex:61-71,122-128](../deps/jido_harness/lib/jido_harness/adapters/cli_mapper/claude_stream.ex)) reach the client and hit the `Ignore` arm. No cost or context figure is shown anywhere. |
| 4 | Responsiveness | 1 | Streaming deltas work end to end. But every managed-transport turn (claude, gemini, amp, grok, zai, codex-exec) is a fresh process: `process: :per_turn` ([transport_spec.ex:62](../deps/jido_harness/lib/jido_harness/session/transport_spec.ex)), `claude --print --resume <id>` each time — a CLI cold start per turn. The coordinator polls Harness at 25 ms ([task.ex:16](../lib/ouroboros/interactive/task.ex)). ACP and Codex app-server sessions are persistent. |
| 5 | Steering mid-turn | 1 | Esc/Ctrl-C → `interactive.interrupt` works. `follow_up` is a durable server-side queue, but the client refuses a second Enter while one call is unacknowledged and shows no queue ([app.rs:6145-6154](../tui/src/ui/app/)). `steer` is `{:error, :unsupported}` for every provider except `pi` — the durable-steer work on this branch is live for one provider. |
| 6 | Plan / approval flow | 0 | No plan mode. The approval modal renders a one-line subject and four fixed answers; it never shows a diff, cwd, or the provider's own option labels ([view.rs:395-411](../tui/src/ui/view.rs)). Approvals exist only on Codex app-server and ACP (`approvals: :native`); managed transports declare none, and the Claude adapter never passes `--permission-prompt-tool` — so a Claude session under the plane default `approval_mode: :prompt` has its permission-needing tools **silently denied** by `claude --print`, and a working Claude session requires `auto_edit` or `auto_approve`. There is no human in the loop for the most-used provider. |
| 7 | Input ergonomics | 1 | The composer is genuinely good: grapheme-accurate readline, 100-entry history, `/` and `@` completion over a 4,000-file index, bracketed paste, `$EDITOR`, OSC 52 copy ([editor.rs](../tui/src/ui/editor.rs)). But `@path` is text substitution — the structured `{prompt, attachments[≤32], reasoning_effort}` envelope the gateway accepts ([methods.ex:1433-1447](../lib/ouroboros/gateway/methods.ex)) is never sent ([app.rs:6191-6194](../tui/src/ui/app/)); no image paste; no `!`; no vim; no session/agent mentions; 28 compile-time slash commands, all navigation. |
| 8 | TUI rendering correctness | 1 | ratatui alt-screen, 80 ms tick, no synchronized-output bracket, mouse captured for wheel only (native selection dead, no hint), no scrollback escape hatch, no images ([mod.rs:209-227,451-459](../tui/src/ui/mod.rs)). Hand-rolled unicode-width wrapping and a measured viewport are solid. |
| 9 | Work visibility | 1 | Tool rows correlate call/result by `call_id`; file and diff cells exist. But `thinking_delta`, `plan_updated`, `turn_completed`, `usage`, `queue_changed`, `provider_event` are all dropped ([model/transcript.rs:163](../tui/src/model/transcript.rs)); a tool result shows **one** wrapped line; a diff shows 12 raw lines; Ctrl-O is a flat `key=value` dump, not a tree; Agents/Teams tabs are read-only JSON explorers. |
| 10 | Permission model | 1 | `approval_mode` ∈ default/prompt/auto_edit/auto_approve and `sandbox_mode` ∈ default/read_only/workspace_write/unrestricted, **at start only** ([methods.ex:239-251](../lib/ouroboros/gateway/methods.ex)); a read-only session cannot be promoted, a new one is started ([app.rs:5513-5520](../tui/src/ui/app/)). No allow/deny rules, no classifier, no per-tool scope. `Control.Grants` gate six mesh effects, never a vendor tool call ([grants.ex:68-78](../lib/ouroboros/control/grants.ex)). |
| 11 | Sandboxing / isolation | 1 | Vendor sandboxes are selected by argv (Codex `sandboxPolicy`, Claude `--settings` sandbox block). Ouroboros-owned isolation is real but narrow: symlink-safe workspace admission with exclusive/shared-read leases ([workspace.ex:71-78](../lib/ouroboros/workspace.ex)), umask 077 on the runtime / 022 on provider children. No worktrees ("intentionally outside this component", [workspace.ex:10-13](../lib/ouroboros/workspace.ex)); no OS sandbox of its own. |
| 12 | MCP & tool ecosystem | 0 | `mcp_config` is refused at Ouroboros's own API on both planes ([task_state.ex:28,198-199](../lib/ouroboros/coding/task_state.ex)) although claude/zai/amp (`--mcp-config`) and ACP (`mcpServers` on `session/new`, [acp.ex:72](../lib/ouroboros/provider/session/dialect/acp.ex)) could carry it. No MCP client, no hooks, no plugins, no skills reachable (`AgentProfile.skills` exists but `agent_profile` is not a start option). |
| 13 | LSP / semantic navigation | 0 | Zero language-server code in `lib/` or `tui/`. |
| 14 | Git-native flow | 0 | No git awareness anywhere; Codex is started with `skip_git_repo_check: true` precisely because nothing guarantees a repo ([provider.ex:54](../lib/ouroboros/provider.ex)). |
| 15 | Persistence & resume | 2 | Sessions are caller-independent by construction; a closed terminal loses nothing; `interactive.subscribe` with a cursor gets an atomic backlog; `Interactive.Recovery` re-registers coordinators 1 s after a crash; sessions live on an owner node and are routed over distribution from any fleet gateway. What stops this being a 3: the Harness subprocess dies with the BEAM/host and recovery then marks the session `:lost` ([task.ex:384](../lib/ouroboros/interactive/task.ex)) even though `provider_session_id` is durable and every transport can resume (`claude --resume`, Codex `thread/resume`, ACP `session/load`); no fork; no `ouro --continue`. |
| 16 | Context management | 0 | Nothing summarises, measures, or compacts; vendor compaction is invisible. |
| 17 | Memory & instructions | 0 | No `CLAUDE.md`/`AGENTS.md` handling (the vendor CLIs read their own); `Ouroboros.AgentProfile` + `Prompt.Assembler` are a real, delimiter-safe, digest-traced prompt policy ([agent_profile.ex](../lib/ouroboros/agent_profile.ex), [assembler.ex](../lib/ouroboros/prompt/assembler.ex)) reachable only from `Team.Server`. |
| 18 | In-session parallelism | 1 | Teams, delegation, the orchestration DAG, and the control planner are durable, recoverable, and tested — and `teams.delegate`/`add_worker`/`cancel`/`close` have **zero** TUI call sites; the Plans tab's `s`/`c` are the only operate actions outside sessions. A conversation cannot spawn a worker. |
| 19 | Background handoff + remote attach | 2 | `--machine` places a session on a fleet node; any fleet gateway lists, routes, replays, and follows it; a detached daemon survives the client. No phone/web surface; no handoff of a *running* conversation to another executor. |
| 20 | Cross-machine / fleet coordination | 2 | One Erlang cluster over a tailnet with a signed membership roster, `fleet.status`/`fleet.doctor`, remote sessions, and a Machines menu ([FLEET.md](FLEET.md)). Vendor-neutral, no relay. Missing for 3: agent-to-agent messaging the user can see and address, and owner-loss migration of a live provider process. |
| 21 | Programmability | 1 | The gateway is a real, golden-fixture-tested JSON-RPC API with 53 methods and streaming — but there is no hooks system, no plugin or skill loader, no SDK, no ACP server mode, no HTTP/SSE, and `--print` emits prose only ([main.rs:447-575](../tui/src/main.rs)). |
| 22 | Install / update / auth polish | 1 | One binary with the release embedded, a boot screen, XDG config, a managed ChatGPT sign-in flow for Codex in-app. But the binary is valid only on the machine that built it, there is no signed download, no release channel, no auto-update, and Claude/Gemini auth is whatever the vendor CLI has on disk. |
| 23 | Provider freedom & pricing transparency | 2 | Nine providers through one normalised API, bring-your-own everything, zero markup. No cost display (row 3). |
| 24 | Audit & governance | 2 | A content-minimised effect ledger that checkpoints authority and intent before an action runs and records restarted work as ambiguous; deny-by-default grants; a signing decision journal; per-session event journals with redaction. Node-local; covers six mesh effects, not tool calls. |
| 25 | Vendor honesty & stability | 1 | The docs' honesty invariant is exemplary and every limit is written down. But there is no public release, changelog, or versioned docs yet ([README "Current limits"](../README.md)). |

Totals: **23 / 75**. Table-stakes rows (1–3, 5, 8–12, 15, 18–19, 21–22) average 1.0;
the four open-slot rows (15, 16, 20, 24) average 1.5 with two of them already at 2 —
the inverse of every incumbent, which is exactly the shape of an opportunity.

### 3.2 Server-ready, client-unreachable

A distinct class of gap, and the cheapest to close: capabilities the runtime already
implements, tests, and exposes on the wire that the client never calls.

| Capability | Server | Client |
|---|---|---|
| Structured turn input `{prompt, attachments[≤32], reasoning_effort}` with workspace-canonicalised attachments | [methods.ex:1419-1448](../lib/ouroboros/gateway/methods.ex), [task.ex:859-895](../lib/ouroboros/interactive/task.ex) | always a bare string ([app.rs:6191-6194](../tui/src/ui/app/)) |
| `model`, `system_prompt`, `max_turns`, `event_limit`, `reasoning_effort`, `runtime_exposure` at start | `@start_options` ([methods.ex:261-275](../lib/ouroboros/gateway/methods.ex)) | `StartRequest` sends `id, provider, workspace, approval_mode, sandbox_mode, machine` ([model.rs:1344+](../tui/src/model.rs)) |
| Per-turn `reasoning_effort` | structured envelope | never |
| `teams.add_worker`, `teams.delegate`, `teams.cancel`, `teams.close`, `agents.stop` | [methods.ex:215-221](../lib/ouroboros/gateway/methods.ex) | zero call sites |
| `approval_requested.options` (ACP) and `kind ∈ sandbox_escalation \| file_change \| permissions` (Codex) | [acp.ex:376-381](../deps/jido_harness/lib/jido_harness/session/transports/acp.ex), [codex.ex:347-366](../lib/ouroboros/provider/session/dialect/codex.ex) | modal shows subject only |
| `thinking_delta`, `plan_updated`, `usage`, `turn_*`, `queue_changed`, `run_started.model/tools` | journaled, replayed, streamed | `Ignore` |
| `Event::raw` full tree + a working `TreeView` | — | Ctrl-O renders a flat `key=value` line per event ([sessions.rs:1088-1112](../tui/src/ui/sessions.rs)) |
| `runtime.providers` `normalized_options`/`normalized_values`/`session_transports` | Wire-encoded | the `n` dialog cannot grey out choices a provider cannot take ([TUI.md §6](TUI.md)) |
| Session timeouts `turn_runtime_timeout_ms`, `turn_idle_timeout_ms`, `session_idle_timeout_ms`, `approval_timeout_ms` | [state.ex:8-14](../lib/ouroboros/interactive/state.ex) | not in `@start_options` |

### 3.3 Structural facts that constrain every choice below

- **F1 — Ouroboros runs no tool loop.** Both planes hand a request to Harness and poll it; all tools execute inside the vendor CLI ([M3 §1.1](research/agent-ux-2026/M3-provider-tool-layer-map.md)). `Jido.AI` is used only for control-plane planning ([jido_ai.ex:35,51](../lib/ouroboros/control/jido_ai.ex)). Ouroboros cannot today append a diagnostic to an edit result, veto a tool call, or offer its own tool, because it is never in the loop where those happen.
- **F2 — Managed transports have no approvals channel.** `claude`, `gemini`, `amp`, `grok`, `zai`, and `codex exec` sessions run one process per turn with `interrupt: :process` and no `approvals` capability ([transport_spec.ex:56-83](../deps/jido_harness/lib/jido_harness/session/transport_spec.ex)). A pre-tool hook is structurally impossible there; only Codex app-server and ACP ask before acting.
- **F3 — The only universal injection seam is prompt text.** `expose_turn_request/2` ([task.ex:811-817](../lib/ouroboros/interactive/task.ex)) already wraps every turn in a delimiter-checked `<ouroboros-runtime>` envelope whose captured bytes are durable and replay-exact. Anything that must reach every provider (diagnostics, instructions, context) rides there or in a `follow_up` turn.
- **F4 — Three transports can carry MCP server definitions today** (claude/zai `--mcp-config`, amp `--mcp-config`, ACP `mcpServers`); Codex can only via `-c` pairs baked into the managed launcher ([provider.ex:458-470](../lib/ouroboros/provider.ex)); Gemini can only filter names. The block is Ouroboros's own refusal ([task_state.ex:28](../lib/ouroboros/coding/task_state.ex)), put there for a good reason — inline server commands in a durable checkpoint are an execution vector — that needs a durable-safety story, not deletion.
- **F5 — No event bus for tool calls.** `Ouroboros.Signals` is nine mesh-agent signal types. Provider events reach consumers by `Session.replay` polling and `send/2` fan-out ([task.ex:1308-1310](../lib/ouroboros/interactive/task.ex)). A hook system has two in-band attachment points: the adapter `Stream.map` wrapper already used by `CodexAdapter.run/2` (post-hoc) and the dialect `approval_request/2` (the one pre-tool point).
- **F6 — Redaction is the ceiling on display.** The durable event has no `raw`; payloads pass `Jido.Harness.Redaction` before checkpoint. A transcript can never show more than the redacted payload — which is fine, but it means "show the full tool result" is bounded by what the adapter put in `payload`, and the ACP payload is the raw ACP update, never normalised.
- **F7 — The wire has no byte cap on payloads**, only depth/node caps ([wire.ex:49-52](../lib/ouroboros/gateway/wire.ex)); a multi-megabyte diff crosses the socket whole on every replay, to be cut to 128 KiB client-side.
- **F8 — Cross-machine is real and vendor-neutral, and the runtime owns the session.** This is the asset. Every plan item that adds state must keep the invariants that make it true: checkpoint before broadcast, derived identities that embed `node()`, bounded calls, fail-closed auth, the unpatchable namespaces.

---

## 4. Strategy

### 4.1 What not to do

- **Do not clone Claude Code's surface feature by feature.** Its velocity is the
  complaint (R1 §2, Pi's founding critique); its seat is held by a first-party model
  relationship Ouroboros cannot have. Match the *grammar* developers now expect (§2.2),
  not the feature count.
- **Do not compete on subscription access.** Anthropic closed subscription OAuth to
  third parties on 2026-04-04; Ouroboros reaches Claude only by running the first-party
  `claude` binary, which is what it does today. Treat that as a policy risk to state, not
  a moat to build on (§10).
- **Do not build an IDE.** Terminal-first with IDE-for-review is the standard workflow
  (R5 §3.7). The way into editors is ACP, where Zed, JetBrains, and Devin Desktop now host
  any agent.
- **Do not let the architecture stay invisible.** Rows 15, 19, 20, 24 are the only rows
  where Ouroboros already beats the field's average, and a user of `ouro` cannot see any
  of them from the transcript.

### 4.2 The thesis

Ouroboros becomes **the self-hosted control plane for coding agents**: sessions owned by
a daemon rather than a terminal, living across the operator's own machines, replayable
from any of them, with every effect in a ledger — *and* a terminal experience that is as
good as Codex CLI and Claude Code at the everyday loop of prompt → tool calls → diffs →
approval → done. Both halves are required. The first without the second is a curiosity;
the second without the first is a weaker Claude Code.

Top five, concretely, means: every table-stakes row at ≥ 2; a 3 on rows 15, 20, and 24
(the open slots the architecture was built for); a credible Terminal-Bench 2.1 submission
with the native agent; and a release a stranger can install with one command on the three
desktop platforms. §9 projects the scorecard per phase.

### 4.3 The structural decision: Ouroboros must own a loop

Facts F1, F2, and F5 together mean that, as a harness-of-harnesses only, Ouroboros can
never exceed 1 on rows 1, 6, 10, 12, 13, or 16 for the managed providers — which today
includes Claude, the provider 39% of professionals use. Nothing Ouroboros does can make
`claude --print` ask a human before a tool runs, append a diagnostic to an edit, veto a
command, or compact a context it does not hold.

Everything needed to own a loop already exists in the dependency tree: `Jido.AI.Agent`
gives a tool-calling loop with streaming, checkpoints, quota, and skills
([agent.ex:23-68](../deps/jido_ai/lib/jido_ai/agent.ex)); `ReqLLM` ships providers for
`anthropic`, `openai`, `openai_codex`, `google`, `google_vertex`, `amazon_bedrock`,
`azure`, `xai`, `zai`, `github_copilot`, `openrouter`, `ollama`, `vllm`, `groq`,
`mistral`, `deepseek`, `moonshot_ai` and more ([deps/req_llm/lib/req_llm/providers](../deps/req_llm/lib/req_llm/providers));
`Jido.Harness.Adapter` requires only `spec/0`, `run/2`, `status/1`, and a session
adapter only a pid handle ([M3 §4](research/agent-ux-2026/M3-provider-tool-layer-map.md)),
so a native loop registers like any other provider and emits the same 29 normalised
event kinds into the same journals, the same gateway stream, the same TUI cells.

So: **ship `Ouroboros.Provider.Native` as a tenth provider.** It is where LSP, MCP,
hooks, permission rules, compaction, file checkpoints, worktrees, and the effect ledger
attach *natively*, because it is the only place Ouroboros is in the loop. It is also the
only honest route to the self-improvement vision in [ARCHITECTURE.md](ARCHITECTURE.md):
a runtime-authored agent needs tools that are Elixir actions it can forge, grant, and
audit. The vendor CLIs stay — they are how a user brings a subscription — and each is
raised to its own ceiling (§7 Track C). Nothing in the native track is allowed to make a
vendor session worse.

### 4.4 The twelve moves

Each maps to a track in §7; the order is the order of §8.

1. **Fix what is silently wrong** (§6): Claude sessions that deny tools without saying so, a steer key that does nothing on eight of nine providers, a doc that names the wrong key.
2. **Render all 29 events.** Thinking, plan, usage, turn markers, grouped exploration cells, real tool-result excerpts, real diffs, markdown.
3. **Give the footer a brain.** Model, mode, context %, cost, elapsed; scriptable like Claude Code's `statusLine`; tab title and bell.
4. **Adopt the 2026 grammar.** Shift+Tab modes, plan mode, Esc/Esc-Esc, a visible queue, `@` attachments that are structured, `!`, `/model`, `/effort`, `--continue`, `/fork`, rebindable keys.
5. **Make approvals real everywhere.** One server-side permission engine with allow/ask/deny rules and session scope; a modal that shows the diff; the Claude bridge via `--permission-prompt-tool`.
6. **Survive everything.** Resume provider sessions across BEAM and host restarts; `ouro --continue` from any machine in the fleet.
7. **Build the native agent.** The loop, its tools, its MCP client, hooks, checkpoints, compaction — with approvals and the ledger at every tool call.
8. **Code intelligence as a runtime service.** An LSP pool per node, diagnostics after edits (native: in the tool result; vendors: via the Ouroboros MCP server and Claude hooks), one `code_intel` tool.
9. **Make teams conversational.** `/delegate`, child rows under the parent session, an agent panel, a fleet view that triages by needs-input.
10. **Make the ledger the feature.** Every tool call of the native agent and every approval of a vendor session in the ledger; `ouro ledger` and a transcript badge; export.
11. **Headless and hosted.** `ouro run --json`, `ouro acp` so editors host Ouroboros sessions, an SDK-grade protocol doc.
12. **Distribute.** Signed builds for the desktop triples, `ouro update` with channels, `ouro doctor`, device-code sign-in for SSH boxes, and a public changelog.

---

## 5. Decisions

**D1 — The native agent is a provider, not a replacement.** `Ouroboros.Provider.Native`
registers through `:jido_harness, :providers` like `codex`/`kimi`/`opencode` already do
([config.exs:127-133](../config/config.exs)), declares the full normalised option set,
and emits standard events. Vendor providers keep working unchanged; the `n` dialog lists
`native` beside them. A user who only ever uses Claude through Ouroboros must notice
nothing but improvements.

**D2 — No `Ignore` arm.** Every one of the 29 Harness event kinds gets either a cell or
a deliberate, documented hide in `PresentationEvent::from_event`
([model/transcript.rs:93-164](../tui/src/model/transcript.rs)). Hidden kinds remain in
Ctrl-O, which becomes a tree view over `Event::raw`, not a `key=value` line.

**D3 — Keep the alternate screen; add every escape hatch the field learned to need.**
Changing the screen model is the single most-punished rendering decision of 2026 (R2
§10d). `ouro` stays a virtualised alt-screen app and adds: DEC-2026 synchronized output
around every frame; `[` to write the transcript into native scrollback with tool output
expanded; `v` to open it in `$EDITOR`; `/raw` (no gutters, no app wrapping) for copying;
a one-time "hold Shift/Option to select natively" hint when the mouse is captured; and a
`mouse = false` setting. Images render via Kitty/iTerm2 protocols where the terminal
reports them and degrade to a placeholder elsewhere (Pi's rule).

**D4 — Adopt the de-facto keys and make all of them rebindable.** `Ctrl+O` show-more
(already bound; the doc is wrong, not the code), `Ctrl+T` tasks/plan panel, Shift+Tab
mode cycle, `Esc` interrupt, `Esc Esc` backtrack, `Ctrl+G` editor (already), `Ctrl+V`
image paste, `?` help. A `keybindings.toml` beside `config.toml` overrides any chord,
including double-Esc — the unrebindable double-Esc is Claude Code issue #43717.

**D5 — One permission engine, server-side, consulted before any human.**
`Ouroboros.Control.Permissions` evaluates allow/ask/deny rules (tool, command prefix,
path glob, session scope) against every `approval_requested` it can intercept — Codex
app-server, ACP, the native agent, and Claude via the prompt-tool bridge — and records
the verdict in the ledger. Only `ask` reaches the modal. Mode changes mid-session are a
gateway verb, `interactive.configure {approval_mode | sandbox_mode | model |
reasoning_effort}`, applied through the transport's `dynamic_configuration` where it is
`:native`/`:managed` and otherwise from the next turn, with the footer stating which. A
classifier-backed `auto` mode is a later slice on top of the same engine, never a
replacement for rules.

**D6 — MCP by reference, never inline.** The refusal of inline `mcp_config` in a durable
checkpoint ([task_state.ex:28](../lib/ouroboros/coding/task_state.ex)) is correct: a
server command in a checkpoint is an execution vector that survives the operator who
typed it. The durable form is a *name* resolved against node configuration
(`config :ouroboros, :mcp_servers` and `~/.config/ouroboros/mcp.toml`), validated at
start, and rendered to each transport's native shape (`--mcp-config`, `mcpServers`,
Codex `-c mcp_servers.*` in the managed launcher). Ouroboros also *serves* MCP: an
in-release stdio server (`ouro mcp-serve`) exposing runtime tools — `approve` (D5),
`diagnostics`, `code_intel`, `ledger`, `fleet` — to any vendor CLI that accepts a
server. The native agent uses the same catalogue directly.

**D7 — The LSP pool belongs to the runtime, never to a session.** One pool per node
keyed by `(workspace root, server)`, spawned lazily on first touch, ref-counted across
sessions, idle-stopped at 600 s, restart-capped then marked broken for the session's
lifetime, memory-budgeted per host, and co-located with the files (a session on machine
B uses machine B's pool). Diagnostics feedback follows the shipped consensus in R4: edited
files only, new-only against a pre-edit baseline, version-gated, ≤ 5 s wait, ≤ 20 items
then "+N more", an explicit "edit applied" line, silent "no LSP data" fallback, and a
project-declared CLI typecheck/lint hook as the universal alternative (OpenCode's 2026
position). A language-server failure never fails a write.

**D8 — A session survives the runtime.** `provider_session_id` is durable; every
transport can resume (`claude --resume`, `codex thread/resume`, ACP `session/load`).
Recovery tries resume before `lose/2` ([task.ex:384](../lib/ouroboros/interactive/task.ex));
`:lost` is reserved for a resume that the provider refuses. `ouro --continue` and
`ouro resume <id>` work from any fleet gateway because the session's owner node is
already in the record.

**D9 — Context is measured for every provider and managed for the native one.** A
context meter needs only `usage` events plus the model's window from `llm_db`; that ships
for all providers. Compaction — structured summary (Goal / Constraints / Progress /
Decisions / Next) with the pre-compaction transcript retained and reviewable — is native
only, because only there does Ouroboros hold the context. Vendors' own compaction is
surfaced as an event when they report it, never imitated.

**D10 — Checkpoints are Ouroboros's, and their limits are stated up front.** The native
agent snapshots a file's content before every write into a content-addressed store under
the session's data directory; `/rewind` offers "conversation", "files", "both", and
"summarise from here", and says before acting which files it cannot restore. For vendor
sessions the same store is fed from `file_change` events where the transport reports
content (Codex `turn/diff`, ACP `diff` once mapped) and is otherwise absent — shown as
"no file checkpoints for this provider", not implied.

**D11 — Teams become conversational, and the fleet view triages by need.** `/delegate
<objective>` and `@<worker>` in the composer call `teams.delegate`; a delegation renders
as a child row under the parent session with its own transcript, stoppable and
messageable; `Ctrl+T` shows the parent's task list including delegations. The Sessions
rail gains a "needs input / working / done" grouping across every fleet node, with
peek-and-reply. Handoff to another machine is `ouro new --machine` for a *new* task; a
running provider process is never migrated (a stated limit, as in FLEET.md).

**D12 — Headless output is the normalised event stream, and the agent is hostable.**
`ouro run "<prompt>" --json` prints one JSON object per normalised event (the same
shapes as the gateway's `interactive.event`), exits with a documented code, and prints
the session id for resume. `ouro acp` speaks the Agent Client Protocol as an *agent* over
stdio so Zed, JetBrains, and Devin Desktop can host an Ouroboros session; the gateway
stays the single authority underneath.

**D13 — Ship real releases.** CI builds signed tarballs per desktop triple
(`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`), publishes a manifest with digests, and `ouro update`
follows a `stable` or `latest` channel with the same release-cache verification that
already exists for the embedded release. `ouro doctor` subsumes `fleet.doctor`. Auth
stays delegated to vendor CLIs plus Ouroboros's own device-code flows where a vendor
exposes one (Codex already; others as they appear). The native agent takes API keys and
any ReqLLM provider.

**D14 — Honesty stays load-bearing.** Every capability matrix the TUI draws comes from
the runtime's own declaration (`runtime.providers`, `interactive.info`), never from a
client table; a key that cannot work on the open session is not advertised in the footer.
Policy risks (Anthropic's third-party posture, vendor sunsets) are written in the README,
not discovered by users.

---

## 6. Fix first

Defects found during mapping. Each is small, each is wrong today, and several make the
product look worse than it is.

| # | Defect | Where | Fix |
|---|---|---|---|
| X1 | A Claude session at the plane default `approval_mode: :prompt` has permission-needing tools silently denied by `claude --print`; nothing tells the user. | [claude.ex:161-163](../deps/jido_harness/lib/jido_harness/adapters/claude.ex), plane defaults [provider.ex:46](../lib/ouroboros/provider.ex) | Until the bridge (Track C2) lands: on managed transports, `interactive.start` with `:prompt` answers with a typed refusal naming the provider and the two modes that work, exactly like `unsupported_safety_options` does on the coding plane; the `n` dialog greys the choice using the capability data it already receives. |
| X2 | `s`/`/steer` are offered on every session; `steer/3` is `{:error, :unsupported}` on every provider but `pi`. | [acp.ex:107](../lib/ouroboros/provider/session/dialect/acp.ex), [codex.ex:101](../lib/ouroboros/provider/session/dialect/codex.ex), palette [app.rs:1812](../tui/src/ui/app/) | Advertise `steer` from `interactive.info.transport.capabilities`; the composer's Steer verb is shown only where it is true; where it is false, Enter-while-busy becomes a visible queued follow-up (Track B3). |
| X3 | TUI.md documents `Ctrl-E` for event details; the code binds `Ctrl-O` and `Ctrl-E` opens `$EDITOR`. | [TUI.md §3.4](TUI.md), [app.rs:5929](../tui/src/ui/app/) | Fix the doc; `?` already is the authority. |
| X4 | Mouse capture disables native text selection and consumes only the wheel; no hint, no opt-out. | [mod.rs:213,451-459](../tui/src/ui/mod.rs) | One-time hint line; `[terminal] mouse = false` in config.toml; `/raw` later (Track A9). |
| X5 | No synchronized-output bracket; every frame can tear in tmux/VS Code. | [mod.rs](../tui/src/ui/mod.rs) draw loop | Wrap `terminal.draw` in crossterm `BeginSynchronizedUpdate`/`EndSynchronizedUpdate`, cursor hide/show inside the bracket (the Codex cursor-flicker lesson). |
| X6 | Outbound event payloads have no byte cap; a multi-MB `file_change` crosses the socket on every replay and subscribe. | [wire.ex:49-52](../lib/ouroboros/gateway/wire.ex), [conn.ex:813-828](../lib/ouroboros/gateway/conn.ex) | Server-side excerpting of string leaves above a per-field cap with a `_truncated: {bytes}` marker, plus `interactive.event_detail {id, sequence}` to fetch one full event on demand. |
| X7 | Interactive Codex refuses every turn that carries an attachment: the app-server dialect omits `multimodal`, so `turn_options: :adapter` inherits `:attachments` and the validator rejects. | [codex.ex:25-36](../lib/ouroboros/provider/session/dialect/codex.ex), [request_validator.ex:77-78](../deps/jido_harness/lib/jido_harness/session/request_validator.ex) | Declare `multimodal: :native`; build image/file input blocks in `turn_params/2`. |
| X8 | ACP `diff`, `available_commands_update`, and `current_mode_update` fall into the opaque catch-all, so an OpenCode/Kimi edit never becomes a `file_change` and their slash commands and modes are invisible. | [acp.ex:190-200](../lib/ouroboros/provider/session/dialect/acp.ex) | Map `diff → :file_change` (`{"changes" => [...]}` shape), commands and mode into `session_ready`/`status` payloads the TUI can show. |
| X9 | Recovery marks a session `:lost` the moment Harness does not know it, although the provider session is resumable. | [task.ex:384](../lib/ouroboros/interactive/task.ex) | D8: start a new Harness session with `provider_session_id` first; `lose/2` only on a refused resume. |
| X10 | `turn_completed`, `run_completed`, `session_idle`, `queue_changed` are dropped, so a finished turn has no terminator and a queued follow-up no indicator. | [model/transcript.rs:163](../tui/src/model/transcript.rs) | Turn-end divider with elapsed time; queue badge above the composer. Cheap, and it removes the "did it finish?" ambiguity. |
| X11 | The approval modal never shows the diff or the provider's own options, though both are in the payload. | [view.rs:395-411](../tui/src/ui/view.rs), [transcript.rs:86-116](../tui/src/ui/transcript.rs) | Render `kind`, `command`+`cwd`, the `file_change` diff (Warp-style expanded while pending), and the provider's option labels; keep the four-way answer as the keyboard path. |
| X12 | `plan_updated` (Codex `update_plan`, ACP `plan`) is journaled and dropped. | [model/transcript.rs:163](../tui/src/model/transcript.rs) | A plan cell and the `Ctrl+T` panel (Track A5). |

---

## 7. Tracks and slices

Conventions, inherited from [TUI.md §5](TUI.md) and [FLEET.md §14](FLEET.md): every slice
is one PR, green before the next, independently revertible, with its acceptance stated
as something a test or a live run can show. Sizes are working days for one babysat
agent on a disjoint file set: **S** ≤ 2, **M** 3–5, **L** 6–10, **XL** > 10 (split
before starting). "Client" means `tui/src`; "runtime" means `lib/`. Where a slice
changes the gateway, it adds the method to `@table`, regenerates the golden fixtures
(`mix ouroboros.gateway.golden`), and gates the client on `hello.methods`, as today.

Two prerequisites that every track shares:

- **A0 — Split `app.rs`.** 9,416 lines in one file is where parallel agents collide.
  Split by responsibility (`input/`, `overlays/`, `session/`, `home/`, `fleet/`) with no
  behaviour change, pinned by the existing 501 tests. **S–M.** First.
- **B0 — Capability-driven chrome.** The footer, palette, composer verbs, and the `n`
  dialog read `interactive.info.transport.capabilities` and `runtime.providers`
  (`normalized_values`, `session_transports`) and never a client-side table (D14). Adds
  `capabilities` to `State.public/1` ([state.ex:194-236](../lib/ouroboros/interactive/state.ex)).
  Makes X1/X2 structural instead of special-cased. **S.**

### Track A — Transcript and display (client)

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **A1 Sync output + escape hatches** | DEC-2026 bracket around every `terminal.draw`, cursor hide/show inside it; `[` leaves the alternate screen, prints the expanded transcript into native scrollback, re-enters; `v` opens the transcript in `$EDITOR` (reuse [mod.rs:679-701](../tui/src/ui/mod.rs)); `/raw` toggle drops gutters and app wrapping; one-time selection hint; `[terminal] mouse = false`. | A pty test asserts `?2026h … ?2026l` around each frame; `[` output equals `/export`; `/raw` copies a paragraph as one logical line. | M |
| **A2 Render all 29 kinds (D2)** | Thinking cell with Crush's three states (10 lines → tail 200 → full); turn-end divider with elapsed time; `run_started.model/tools` into the session header; idle/closed/ended markers; `queue_changed` badge; `provider_event` as a dim one-line kind; `usage` accumulated into the session model. Delete the `Ignore` arm. | One projection test per kind from the golden fixtures; no kind maps to `Ignore`. | M |
| **A3 Tool cells v2** | Per-tool summarisers keyed on name and on ACP `kind` (`read\|edit\|delete\|move\|search\|execute\|think\|fetch`); grouped exploration cell ("Explored 7 files" collapsing consecutive read/search/list, flips from "Exploring…"); in-place expand with `Ctrl+O` on the focused cell (three states); head/tail truncation with "+N lines · ctrl+o" provenance; live timers; `command_output_delta` streamed as a tail window. | Fixture-driven snapshot tests per tool kind; a 10 k-line bash output renders in < 16 ms. | L |
| **A4 Diffs v2** | Per-file grouping, hunk headers, line numbers, word-level emphasis, +N/−M per file, a post-turn diffstat cell, wrap not truncate, expandable; `/diff` overlay listing files changed by turn with Enter → full diff in a pager; syntax colour inside diffs via [code.rs](../tui/src/ui/code.rs); Warp's rule — expanded while an approval is pending, collapsed to the header after apply. | Snapshot tests for unified/multi-file/rename/binary; `/diff` for a three-turn fixture session. | L |
| **A5 Plan / tasks panel** | `plan_updated` cell; `Ctrl+T` panel with `◌ ● ✓` glyphs that stays visible while idle (Codex #18920); delegations join it in G1. | Fixture test; panel survives idle redraws. | S–M |
| **A6 Markdown** | `pulldown-cmark`: headings, nested lists, tables wrapped to width (CJK-safe), blockquotes, bold/italic, links as OSC 8 where supported, inline code everywhere (not first-pair-only); streaming-safe by buffering open constructs (Goose's `MarkdownBuffer`). | Snapshot tests incl. a table at width 60 and a list at depth 4; a mid-stream unterminated fence never renders as garbage. | M |
| **A7 Footer with a brain** | Model · permission mode · sandbox · context % · cost · "Working 4m 07s" · queue count · background count; `statusLine` command in `config.toml` fed debounced JSON (Claude Code's shape); tab title via OSC 0/2 with a spinner/state glyph; bell / OSC 9 on approval-needed and turn-complete when unfocused (focus tracking via `?1004h`). Runtime: `runtime.models` exposing window and pricing from `llm_db`. | Footer snapshot at 80/112/160 columns; notification fires only when unfocused. | M |
| **A8 Approval modal v2** | X11: kind, command + cwd, the diff expanded, provider option labels, reason; "allow always" with a scope picker that writes a C1 rule ("commands starting with `cargo`"); a snack-bar variant above the composer so a pending approval never scrolls away (Kiro). | Fixture approvals for command / file_change / sandbox_escalation / ACP options. | M |
| **A9 Details, export, copy** | `Ctrl+O` details as a `TreeView` over `Event::raw`; `interactive.event_detail` drill-in (X6); `/export` to Markdown and JSON; copy raw Markdown of the last message. | Round-trip test: export → import renders the same cells. | S–M |
| **A10 Themes and accessibility** | Light/dark auto via OSC 11; an ANSI-safe theme; `NO_COLOR`; screen-reader mode (labelled lines, no boxes, static spinner, bell on attention); reduced motion. | Every cell has a plain-text rendering; contrast check on both themes. | M |
| **A11 Images** | Attachments and tool-returned images inline via Kitty/iTerm2 graphics where the terminal reports them; placeholders elsewhere (Pi's iTerm2 alt-screen rule). | Manual on Ghostty/Kitty/iTerm2/Terminal.app; placeholder test. | M |
| **A12 Performance gate** | A 5,000-message synthetic session benchmark; cell cache keyed by (width, content hash); ≤ 16 ms frame at 5 k entries; bounded memory. | Benchmark in CI with a threshold. | M |

### Track B — Interaction grammar (client + runtime)

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **B1 Modes + `interactive.configure`** | Shift+Tab cycles `prompt → auto_edit → plan → auto_approve` (the last gated by a confirm), label in the footer; runtime verb `interactive.configure {approval_mode \| sandbox_mode \| model \| reasoning_effort}` applied via the transport's `dynamic_configuration` (app-server: per-turn params already rebuilt in `turn_params/2`; ACP: `session/set_mode`; managed: next turn's argv; pi: native) and durable in `State`; the footer says "from next turn" when that is the truth. | Per-transport tests; a mode change mid-turn is reflected in the next `turn_started`. | M |
| **B2 Plan mode** | Read-only posture (`sandbox_mode: read_only` + a plan instruction block via the `expose_turn_request` envelope for vendors; tool allowlist for native); exit through an approval "Yes, auto-accept edits / Yes, manual approvals / keep planning" that calls `configure` and queues the follow-up; the plan is captured as `plan_updated` (native) or the final message. | A vendor session in plan mode makes no `file_change`; exit path test. | M |
| **B3 Queue and steer** | Visible queue (server `queue_changed` + local pending); Enter while busy = a queued follow-up row; steer offered only where the transport says so (pi today; Codex app-server after C3); Up pulls a queued draft back; Esc interrupts and keeps the queue (Claude Code #16905). | Queue/steer semantics pinned by tests that name the key and the transport. | M |
| **B4 Structured input** | `@path` → `attachments[]` (server-canonicalised, [task.ex:859-895](../lib/ouroboros/interactive/task.ex)); `Ctrl+V` image paste (clipboard via `osascript`/`xclip`/`wl-paste` → a file under the session's data dir → attachment); per-turn `/effort`; `/model` via B1. Requires X7. | Wire test shows the object form; an image reaches Codex app-server as an input block. | M |
| **B5 Esc semantics** | Esc always interrupts; Esc Esc opens a backtrack menu: "fork from this message" where the transport can (Codex `thread/fork` from any message; Claude `--fork-session` at the tail; native anywhere), else "edit and resend as a new turn" — named honestly per transport. | Menu entries come from capabilities; fork test on app-server. | M |
| **B6 Sessions** | `ouro --continue`, `ouro resume <id\|name>` from any fleet gateway; `/rename`, auto-title from the first prompt (native: a cheap model; others: first line); picker with search and filters (workspace, machine, status, needs-input); `/fork`. Runtime: `interactive.rename`, `interactive.fork`, `title` in `State`. | Resume from a second machine's gateway; picker search test. | L |
| **B7 `!cmd` and `/btw`** | `!cmd` runs in the session workspace on the owner node through a new operate-scope `workspace.exec` that is ledger-recorded and capability-gated to sessions already at `auto_approve` or to an explicit rule; output becomes a transcript note the agent can see next turn. `/btw` asks a side question in a throwaway native turn without touching the session. | `!` refused on a `prompt`-mode session until a rule allows it; ledger entry present. | M |
| **B8 Keybindings and vim** | `keybindings.toml` overriding every chord including double-Esc; `?` generated from the map; vim mode for the composer (NORMAL/INSERT, motions, text objects) as a later slice. | Rebinding test; help equals the map. | S (keys) + M (vim) |
| **B9 Discoverability** | Context-grouped `?`; first-run tips; `/hotkeys`; a "new here?" line in the footer until three prompts are sent. | Snapshot. | S |

### Track C — Approvals, permissions, vendor ceilings (runtime)

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **C1 `Ouroboros.Control.Permissions`** | Rule language: tool, command prefix with word-boundary `*`, compound splitting with per-sub-command evaluation, wrapper stripping, redirect targets as writes, path globs, domains; scopes node > user > workspace-external > session with deny → ask → allow; "allow always" writes rules *outside* the repo (Kiro); every decision in the ledger (I1); applied in `approval_request/2` for ACP and app-server, and in the native loop. Gateway `permissions.{list,add,remove}`. Protected namespace like `Control.Grants`. | Claude Code's documented rule cases as a test corpus; `Bash(ls *)` vs `lsof`; compound `&&` split. | L |
| **C2 Claude bridge** | `Ouroboros.Provider.ClaudeAdapter` overriding the pinned adapter (as codex/kimi/opencode already do): `--permission-prompt-tool mcp__ouroboros__approve` with an `--mcp-config` naming `ouro mcp-serve` — a stdio MCP server in the existing binary that forwards `approve` to the gateway as an `approval_requested` and returns the C1/human decision; the same server carries `diagnostics`/`code_intel` later (E2/E3). Also `--settings` hooks for `PostToolUse`. Plane default `:prompt` becomes real for Claude. | Live: a Claude session at `:prompt` opens the modal for a write; deny works; ledger entry. | L |
| **C3 Codex ceiling** | `turn/steer` → `steer/3`; `acceptWithExecpolicyAmendment` → a C1 rule; `acceptForSession`; `item/permissions/requestApproval`; `thread/fork`, `thread/compact/start`, `model/list`; X7 multimodal input. | Dialect tests per method; steer capability advertised. | M |
| **C4 ACP ceiling** | X8 mappings; `session/set_mode` (B1); `allow_always` → C1; opt-in `fs/read_text_file`, `fs/write_text_file`, `terminal/*` served by Ouroboros so ACP agents' file I/O and terminals pass through the runtime (checkpoints, diagnostics, ledger for OpenCode/Kimi). | `session_acp_test` extended; an OpenCode edit becomes `file_change` + a checkpoint. | L |
| **C5 OS sandbox for the native agent** | macOS `sandbox-exec` profile and Linux bubblewrap + seccomp for the Bash tool, workspace + declared roots writable, `.git`/own config read-only; a domain-allowlisting proxy later. Until then the footer says "no OS sandbox" for native sessions. | Escapes from the sandbox are tests; violated constraint surfaced with an escalation suggestion (Cursor). | XL — split: filesystem first, network second |
| **C6 Classifier `auto`** | A cheap ReqLLM model reviews `ask` decisions against stated boundaries; paired with rules and protected paths, never alone; measured on a corpus before default-on. | Catch-rate report published in docs. | L (Phase 4) |

### Track D — The native agent (runtime)

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **D1 `Ouroboros.Provider.Native`** | Harness run adapter + session adapter on `Jido.AI.Agent`; model spec through ReqLLM; streaming mapped to the 29 kinds (cost from `llm_db`); approvals through C1; native steer at the next tool boundary; interrupt; follow-up; `provider_session_id` = native session id; resume from `Jido.AI` checkpoints; same journals, gateway, cells. Registered in `:jido_harness, :providers`. | The existing interactive test suite passes against `native` with a deterministic model stub; a real run edits a file end to end. | XL — split: loop → events → approvals → resume |
| **D2 Tool set v1** | `read` (offset/limit, images), `write`, `edit` (exact match, read-before-edit, modified-since-read, whitespace-tolerant ladder with "similar lines" on failure), `apply_patch` (V4A), `bash` (timeout, background, head/tail 30 KB + spill-to-file with preview), `grep` (rg), `glob`, `ls`, `web_fetch` (bounded), `ask_user`, `plan`/`todo` (emits `plan_updated`), `skill` (Agent Skills in `.agents/skills/`), `agent` (G3). Each a `Jido.Action` with a schema; a `doom_loop` guard. | Per-tool tests incl. CRLF/format-on-save false positives; output caps. | XL — split by tool group |
| **D3 Context engineering** | System prompt ≲ 2 k tokens; `AGENTS.md`/`CLAUDE.md` hierarchy with lazy nested files; cache-stable prefix with deferred tool schemas; compaction per D9 with the pre-compaction transcript retained; `/compact [focus]`; `/handoff` into a fresh session with a curated prompt and file list (Amp). | Cache-hit rate measured in tests; compaction never loses the plan. | L |
| **D4 MCP client** | stdio + streamable HTTP; OAuth/DCR later; deferred tool loading (names first, schemas on demand); resources and prompts; per-server timeouts, 25 k-token output cap; servers by name (D6) from node config and `~/.config/ouroboros/mcp.toml`; `ouro mcp add\|list\|login`; the same catalogue rendered to vendor transports. | A stdio server's tool appears in native and in a Claude session; inline `mcp_config` still refused. | L |
| **D5 Hooks** | Events: `SessionStart/End`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `Stop`, `SubagentStart/Stop`, `PreCompact`, `Notification`, `FileChanged`; Claude-compatible JSON contract (`permissionDecision`, `updatedInput`, `additionalContext`, exit 2 blocks); command hooks in the workspace with a timeout; repo-supplied hooks gated on workspace trust; configured in `ouroboros.toml` (project) and the user scope. | Hook corpus ported from Claude Code's docs; a `PreToolUse` deny blocks the tool. | M–L |
| **D6 Checkpoints and rewind** | Content-addressed pre-write snapshots per session under the data dir; `/rewind` (conversation / files / both / summarise from here); says which files it cannot restore before acting. Vendor sessions fed from `file_change` where content exists (Codex `turn/diff`, ACP after C4). | Rewind restores byte-exact; a bash-made change is reported as unrestorable. | M |
| **D7 Worktrees** | `--worktree` / `isolation: worktree`: `git worktree add` under the data dir without shell interpolation, lease acquired on the worktree path ([workspace.ex:71-78](../lib/ouroboros/workspace.ex)), cleanup as a recoverable operation; vendors get the same (`cwd`). | Two sessions on one repo edit in parallel without a lease conflict. | M |
| **D8 Quality gate** | A Terminal-Bench 2.1 harness adapter for `native`; a local eval corpus; numbers published in docs whatever they are. | An official board submission. | L |

### Track E — Code intelligence (runtime, small client)

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **E1 `Ouroboros.CodeIntel.LspPool`** | Per-node supervisor keyed by (workspace root, server); registry with root finders for typescript-language-server, pyright, gopls, rust-analyzer, clangd, jdtls, elixir-ls/Expert, ruby-lsp, sourcekit-lsp; user toolchain first, no silent installs (`ouro lsp install <server>`); lazy spawn, ref-count, idle 600 s, restart cap then broken, memory watchdog with a per-host budget; versioned document sync; diagnostics cache; `runtime.lsp.status`. | Pool tests with a fake server; memory breach restarts once then marks broken. | XL — split: pool → registry → sync |
| **E2 Diagnostics feedback** | Native: appended to edit/write results under the R4 policy (edited file, new-only, version-gated, ≤ 5 s, ≤ 20 then "+N more", "Edit applied." first, "no LSP data" on timeout). Vendors: Claude and Codex via `PostToolUse` hooks → `ouro mcp-serve` → pool → `additionalContext`; ACP via served `fs/write` (C4); universal fallback: `[checks]` in `ouroboros.toml` (typecheck/lint commands) run on `file_change` and injected through the envelope next turn, never blocking. Client: per-file diagnostic badges from `diagnostics.changed` events. | OpenCode #9102 regression test (no loop on warnings); stale-diagnostic test. | L |
| **E3 `code_intel` tool** | Nine operations + `diagnostics` + `rename` (preview → apply, approval-gated), addressed by `file:line:character`; exposed natively and as an MCP tool for vendors; tree-sitter outline fallback via an `ouro outline` subcommand (tree-sitter crates in the binary). | SWE-Master-style turn-count check on an internal corpus. | L |
| **E4 Code-aware UI** | `@symbol` and `@diagnostics` mentions; `o` on a file cell opens `$EDITOR` at the line; diagnostics list overlay. | Snapshot + manual. | M |
| **E5 Structural index** | tree-sitter call graph + BM25 (+ optional embeddings) exposed as `codebase_search`/`codebase_graph` for multi-file tasks (R4: +7.9 pp resolve at lower $/solve). | Ablation on the internal corpus. | XL (Phase 4, optional) |

### Track F — Sessions, persistence, context

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **F1 Resume after restart (D8, X9)** | Recovery starts a Harness session with `provider_session_id` (`--resume`, `thread/resume`, `session/load`) and replays before ever calling `lose/2`. | Kill the BEAM mid-session, restart, continue the conversation on Codex app-server and on a fake adapter. | M |
| **F2 `--continue` / `resume`** | Last session for this workspace on any machine; fleet-aware resolution. | Test across two nodes. | S |
| **F3 Usage accounting** | Tokens in/out/cache and cost accumulated in `State`; `runtime.models` (window, pricing) from `llm_db`; in `interactive.info`/`list`. | Totals equal the sum of `usage` events. | M |
| **F4 Titles and search** | Part of B6; `interactive.list` filters. | — | with B6 |
| **F5 Export and archives** | `/export`; pre-compaction archives retained for native under the retention sweep. | — | S |

### Track G — Multi-agent UX

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **G1 Conversational delegation** | `/delegate <objective>` and `@<worker>` → `teams.delegate` on a per-workspace default team created lazily (ids embed `node()`); child rows under the parent in the rail; a delegation cell in the parent transcript with live status; `Ctrl+T` lists delegations. | Delegation from the composer shows up as a child and completes. | L |
| **G2 Agent panel and fleet triage** | Rail grouped by needs-input / working / done across every fleet node; peek (last message) and reply from the panel; counts in the footer; `ouro agents`. | Two machines, one waiting on approval: it is first in the list. | M |
| **G3 Native subagent tool** | The native `agent` tool spawns a child native session (isolated context, optional worktree, tool allowlist, background), summarised back; depth cap; appears as a child row. | Parallel explore subagents finish and summarise. | L |
| **G4 Visible agent-to-agent messaging** | Mesh `send_message` effects as transcript notes linked to the ledger; `@session` mention to message another live session; inbound messages can never approve. | Test that an inbound message cannot satisfy an approval. | M |
| **G5 Orchestration UI** | Plans tab as a live graph with per-step transcripts and cost; `/plan-run` from the composer → `control.submit`. | Snapshot + a DAG fixture. | M |

### Track H — Headless, protocol, hosting

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **H1 `ouro run`** | `ouro run "<prompt>" [--json\|--stream-json] [--resume id] [--machine] [--bare]`: NDJSON of normalised events, a final `result` (cost, files, session id), exit codes 0/1/2/3/64. | Golden NDJSON fixture; CI example in README. | M |
| **H2 `ouro acp`** | ACP *agent* over stdio backed by the gateway: sessions, tool calls with `kind`, `diff` blocks, `session/request_permission` from C1 `ask`, `session/set_mode` (B1), plan, usage, `session/load` replay from journals. | Zed and JetBrains host an Ouroboros session; ACP conformance run. | L |
| **H3 Protocol docs** | `docs/PROTOCOL.md` generated from `@table` and the golden fixtures; optional thin TS/Python clients. | Doc test that every method appears. | M |
| **H4 HTTP/SSE bridge** | `ouro serve --http` for web clients and an OpenCode-style SDK shape. | — | M (Phase 4) |

### Track I — Trust, ledger, observability

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **I1 Ledger for tool calls and approvals** | New effect kinds in `EffectLedger` — `tool_call` (tool, path/command fingerprint, session, node) recorded checkpoint-before-run for native, and `approval` (decision, rule id, actor) for every provider; `ledger.{list,get}` gateway methods; `ouro ledger`; "ledger #N" on tool rows; JSONL export with a hash chain. Content-minimised as today. | Kill the runtime mid-tool: the entry is `:ambiguous`, never missing. | L |
| **I2 Cost surfaces** | `/cost`, `/usage`, per-session totals in the picker; budgets (`max_budget_usd` native; Claude's own flag via C2). | Budget stop test. | M |
| **I3 Fleet-wide ledger queries** | `ledger.list` fans out across connected nodes with bounded `erpc`; the "survives machine moves" claim is made true by querying every owner, and the docs say so — a replicated append-only ledger stays deferred. | Two-node query test. | M |

### Track J — Distribution and onboarding

| Slice | Scope | Acceptance | Size |
|---|---|---|---|
| **J1 Release pipeline** | CI matrix for the four desktop triples; signed tarballs (minisign or cosign) and a digest manifest; `ouro version --check`. | A tagged build installs on a clean VM per triple. | L |
| **J2 `ouro update` / `ouro doctor`** | Channels `stable`/`latest` with the existing release-cache verification; `doctor` subsumes `fleet.doctor` and checks terminal capabilities, providers, LSP servers, data-dir permissions. | Update from N−1 on each triple. | M |
| **J3 Install** | `curl … \| sh`, a Homebrew tap; README quickstart in five lines. | Fresh-machine timing: first useful result < 3 minutes. | S–M |
| **J4 Auth** | `ouro login <provider>` runs the vendor's login in a pty and verifies status; native keys in a 0600 file, never argv; Codex device-code already. | Manual per provider. | M |
| **J5 Changelog and versioned docs** | `CHANGELOG.md` naming regressions and the version they regressed in; docs annotated "as of". | — | S |

---

## 8. Sequencing

Five phases. Each phase's exit criterion is a scorecard movement (§9), not a feature
count. Within a phase, slices on disjoint file sets run in parallel under babysat
agents with worktree isolation; after every multi-branch merge, `mix compile --force`
before trusting a test run (a lesson this repo has already paid for twice).

**Phase 0 — Fix first (1–2 weeks).** A0, B0, X1–X12. Nothing new is advertised; several
things stop being silently wrong. Exit: no key is offered on a session that cannot honour
it; a Claude session at `:prompt` is refused with the two modes that work, not denied
tool by tool.

**Phase 1 — Table stakes on the client (6–8 weeks).** A1–A7, A9, B1, B3, B4, B6, B9, C3,
F1–F3, H1, I2. Mostly Rust; runtime additions are `interactive.configure`,
`interactive.rename/fork`, `runtime.models`, `interactive.event_detail`, usage in `State`,
resume-on-recovery. Exit: rows 5, 7, 8, 9, 15 at ≥ 2; a Codex app-server session feels
like Codex CLI.

**Phase 2 — Approvals real, native agent alive (8–10 weeks).** C1, C2, C4, D1–D3, D5,
D6, A8, B2, B5, G1, G2, I1. Exit: rows 1, 6, 10, 12 at ≥ 2; a Claude session asks before
it writes; `native` passes the interactive suite and edits real files with diagnostics-free
but ledger-recorded tools.

**Phase 3 — Code intelligence, teams, hosting (8 weeks).** E1–E4, D4, D7, G3, G4, H2, H3,
A10–A12, B7, B8. Exit: rows 13, 18, 21 at ≥ 2; an Ouroboros session hosted in Zed; a
Terminal-Bench 2.1 submission (D8) — whatever the number, published.

**Phase 4 — Own the open slots, ship (6–8 weeks).** I3, C5, C6, E5 (optional), G5, H4,
J1–J5, F5. Exit: 3 on rows 15, 20, 24; a signed public release with a changelog.

Dependencies that order the work: A0 before every client slice; B0 before X1/X2 and A7;
C1 before A8, C2, C4 rules, D1 approvals, I1; X7 before B4 images on Codex; D1 before
D2–D7, E2 (native path), G3; E1 before E2–E4; C2 before E2 (Claude path); B1 before B2
and H2 modes; F3 before A7's context meter; I1 before I3.

Rough total: ~115–150 agent-days of implementation across ~60 slices, 30–34 calendar
weeks with three to four agents in parallel, plus verification. The honest caveat: D1/D2,
E1, and C5 are XL and will find problems the map did not; the phase exits, not the week
counts, are the commitments.

---

## 9. Scorecard projection

Scores per row after each phase, against the rubric in §3.1. "3" claims are only made
where the rubric's bar is specifically met.

| # | Capability | Now | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|---|
| 1 | Edit reliability & self-verification | 1 | 1 | 2 | 2 | 2 |
| 2 | Benchmark standing | 0 | 0 | 0 | 1–2 | 2 |
| 3 | Token efficiency & cost | 0 | 2 | 2 | 2 | 2 |
| 4 | Responsiveness | 1 | 1 | 2 | 2 | 2 |
| 5 | Steering mid-turn | 1 | 2 | 2 | 2 | 3 |
| 6 | Plan / approval flow | 0 | 1 | 2 | 2 | 2 |
| 7 | Input ergonomics | 1 | 2 | 2 | 2 | 2 |
| 8 | TUI rendering correctness | 1 | 2 | 2 | 2 | 2 |
| 9 | Work visibility | 1 | 2 | 2 | 3 | 3 |
| 10 | Permission model | 1 | 1 | 2 | 2 | 2–3 |
| 11 | Sandboxing / isolation | 1 | 1 | 1 | 2 | 2 |
| 12 | MCP & tool ecosystem | 0 | 0 | 1 | 2 | 2 |
| 13 | LSP / semantic navigation | 0 | 0 | 0 | 2 | 2 |
| 14 | Git-native flow | 0 | 0 | 1 | 2 | 2 |
| 15 | Persistence & resume | 2 | 2 | 2 | 3 | 3 |
| 16 | Context management | 0 | 1 | 2 | 2 | 2 |
| 17 | Memory & instructions | 0 | 0 | 2 | 2 | 2 |
| 18 | In-session parallelism | 1 | 1 | 2 | 2 | 2 |
| 19 | Background handoff + remote attach | 2 | 2 | 2 | 2 | 2 |
| 20 | Cross-machine / fleet coordination | 2 | 2 | 2 | 3 | 3 |
| 21 | Programmability | 1 | 1 | 2 | 3 | 3 |
| 22 | Install / update / auth | 1 | 1 | 1 | 1 | 2–3 |
| 23 | Provider freedom & pricing transparency | 2 | 3 | 3 | 3 | 3 |
| 24 | Audit & governance | 2 | 2 | 3 | 3 | 3 |
| 25 | Vendor honesty & stability | 1 | 1 | 1 | 1 | 2–3 |
| | **Total / 75** | **23** | **34** | **46** | **56** | **61–65** |

Why row 5 can reach 3 at P4: native steer at the tool boundary on every machine, with
`/goal`-style long-lived objectives already modelled by the control plane. Why 9 and 21
reach 3 at P3: a fleet-wide agent panel with per-worker transcripts and cost, and a
gateway + ACP + hooks + MCP surface other UIs can host. Why 22 and 25 wait for P4: those
rows are about shipping, and nothing ships before the release pipeline exists.

---

## 10. Risks and honest limits

- **Anthropic's third-party posture.** Subscription OAuth has been first-party-only
  since 2026-04-04; programmatic use by third-party harnesses moved to separate metered
  "Agent SDK" credit pools on 2026-05-13 (R5 §5). Ouroboros drives the first-party
  `claude` binary, which is exactly the surface the policy governs. Whether a harness
  running `claude --print` under a user's subscription is permitted is a question for the
  policy text at the time, not for this document; the plan assumes the API-key and
  credit-pool paths and treats subscription access as a bonus that may be withdrawn.
  The native agent is the hedge, and it speaks every ReqLLM provider.
- **A new harness starts below Claude Code.** The three-point harness gap on
  Terminal-Bench is earned by mechanics this plan copies from published sources (R3 §8c);
  the first submission will still be behind. The commitment in D8 is to publish the
  number. Vendor providers remain first-class so nobody is forced onto `native`.
- **No OS sandbox until C5.** Until then the native agent is Amp/Pi-class on
  containment: rules + protected paths + worktrees + ledger, and a footer that says so.
  Shipping without a sandbox is the documented alternative, not a secret.
- **LSP servers are a liability as much as an asset.** OpenCode turned theirs off by
  default over memory and staleness; Anthropic tells users to disable plugins under
  pressure (R4 §1). Hence: no silent installs, per-host memory budgets, the CLI-check
  fallback, and diagnostics that never block a write.
- **`jido_harness` is a Git pin.** Adapter changes mean overriding modules in
  `:jido_harness, :providers` (done three times already) or contributing upstream.
  Prefer upstream for anything the vendor CLI's argv changes; keep overrides thin.
- **ERTS does not cross-compile.** J1 builds on a hosted runner per OS; "four targets"
  stays a statement about ERTS until four builds have actually run.
- **Ids must embed `node()`** in every cluster-visible namespace — the bug class found
  three times in this repo. G1's default team ids and E1's pool keys are the new places it
  can recur.
- **The client is one 9.4k-line file.** A0 is not optional; three agents in `app.rs` is
  a merge-conflict generator.
- **Scope.** ~60 slices. The phase exits are the commitments; the week counts are
  estimates by someone who has not yet run the XL slices.
- **What stays true throughout:** every capability the TUI draws comes from the runtime's
  declaration; no key is advertised that cannot work on the open session; no claim in the
  docs outruns a test.

---

## 11. Deferred

Chosen, not forgotten: a web dashboard and phone surface beyond what ACP clients and H4
provide; voice; a classifier as the *default* mode (C6 stays opt-in until measured); a
replicated, append-only ledger (I3 queries every owner instead); an OS sandbox on
Windows, and Windows generally; the structural index (E5) unless the internal corpus shows
the multi-file gain; cross-cluster federation; live migration of a running provider
process off a lost owner; nested agent teams; vim mode beyond the composer; inline images
in the alternate screen on terminals that smear them; a vector store of any kind.
