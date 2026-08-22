# M2 — Interaction Model Map (`ouro` TUI ⇄ Ouroboros gateway)

Repo `/Users/monocursive/code/ouroboros`, branch `review-fixes`. All citations are `file:line`.
Scope: what a user can actually *drive* today, and through which gateway call.

---

## 1. Session lifecycle from the user's seat

### 1.1 Entry points

`ouro` with no subcommand attaches (or spawns) and lands on the **coding home** —
`App::open_home` (`tui/src/ui/app.rs:5319`) selects `Tab::Sessions`, fires
`account.read`, `interactive.list`, `coding.list`, and leaves a typeable composer while
those are in flight. There is no provider picker and no modal in the way (app.rs:5313-5318 doc).

`ouro new` (`tui/src/cli.rs:53-89`) takes `--provider --workspace --approval-mode
--sandbox-mode --message/-m --machine --print`. Flags → `config.resolve_start`
(`tui/src/config.rs:420`) → `interactive.start`. `--print` prints the session id and exits
(`tui/src/main.rs:447-449`, `561-575`).

`ouro attach [--addr --token-file --print]` (`cli.rs:92-107`); `--print` renders one status
page (`tui/src/main.rs:1722-1725`, `tui/src/status.rs:14-50`). Also `daemon`, `stop`,
`fleet …`, `version` (`cli.rs:88-137`).

The boot screen (`tui/src/ui/boot.rs:67-146` `BootEvent`, `:148 StepState`, `:467 draw`) is
a live phase list with the child's stdout tailed under it; `Progress::Plain` (`boot.rs:264-320`)
is used for `--print`/pipes.

### 1.2 Global keys — `App::key` (`app.rs:4806`)

| Key | Effect | Line |
|---|---|---|
| `Ctrl+P` | command palette overlay (toggle) | 4822 |
| `Ctrl+Q` | quit dialog | 4831 |
| `Ctrl+X` | leader chord, 25-tick window (`LEADER_TICKS` app.rs:64) | 4836 |
| `Ctrl+G` | external editor | 4841 |
| `Ctrl+O` | toggle event details | 4849 |
| `Ctrl+C` | clear draft → interrupt turn → (2nd press) quit | 4854, impl 6256 |
| `Ctrl+D` | quit dialog when prompt empty | 4859 |
| `PageUp/Dn`, `Shift/Ctrl+↑↓` | transcript scroll (beats composer history) | 5046-5066 |
| `?` (empty prompt) | help overlay | 4879 |
| `,` (empty prompt) | settings overlay | 4884 |
| `s` / `c` on Plans tab | `control.submit` / `control.cancel` | 4892, 4896 |
| `1`–`7`, `Tab`/`BackTab` | tab switch | 4916-4924 |
| `i` / `s` / `a` / `n` / `x` | compose / steer / approval / new / close (non-composer focus) | 4936-4940 |

Leader chords — `LEADER_KEYS` (`app.rs:2039-2052`), dispatch `leader_key` (`app.rs:4946`):
`n` new home, `N` new-session dialog, `l` session picker, `e`/`g` `$EDITOR`, `y` copy last,
`s` steer, `a` approval, `w` writable session, `x` end/remove, `o`/`d` details, `q` quit, `?` help, `,` settings.

### 1.3 Slash commands

Catalog for completion: `tui/src/ui/editor.rs:18-51` (28 entries). Dispatch:
`activate_slash_command` (`app.rs:6207-6251`). Map: `/new /switch|/sessions /details /copy
/interrupt /steer /editor /close /options /write /connect /runtime /agents /teams /plans
/upgrades /capabilities /logs /machines|/fleet /settings /help|/hotkeys /quit /clear`, plus
argument forms `/preview NAME` and `/admit NAME` (`app.rs:6210-6219`, `slash_arg` at 9298).
Slash commands are *local navigation only* — none of them sends a prompt; `/clear` just
drops the draft (app.rs:6246). There are **no user-defined commands**.

### 1.4 The composer

`Composer` (`app.rs:438-466`) = `ComposerVerb` (`app.rs:413-435`: `Message | FollowUp | Steer`)
+ `Editor` + draft generation + reconciliation owner. Opened by `compose()` (`app.rs:5797`).

`Editor` (`tui/src/ui/editor.rs:102-111`, keys at `:193-368`):
- **Multiline**: `Ctrl+J` always inserts newline; `Shift/Alt+Enter` only where the kitty
  protocol reports the modifier (editor.rs:205-213); bare `Enter` = submit (editor.rs:214).
- **Readline motions**: `Ctrl+A/E/B/F/H/D/U/K/W/Y`, `Alt+B/F/D`, word-wise `Ctrl/Alt+←→`,
  grapheme-cluster-accurate (editor.rs:225-330, `line_start`/cluster notes at :345).
- **History**: bare `↑/↓` walk 100 entries (`HISTORY_LIMIT` editor.rs:15, `history_previous`
  at :333); per-`(plane,id)` history and unsent drafts are persisted across composer
  close/reopen (`remember_composer_history` app.rs:5885-5911).
- **Completion**: `/` prefix at line start → command list; `@` prefix → workspace file list
  (`refresh_completion` editor.rs ~:600). Tab/BackTab/↑↓/`Ctrl+P/N` navigate; Tab applies and
  appends a space for files. Catalog is a plain BFS of the workspace capped at 4 000 files
  skipping `.git node_modules target deps _build` (`index_workspace` editor.rs:792-838),
  pushed as `Msg::WorkspaceFiles` (app.rs:2913-2918). **`@path` is only text substitution** —
  it is never turned into a structured attachment.
- **Paste**: bracketed paste routed by `App::paste` (`app.rs:5713`); overlays get a
  single-line-flattened variant (`overlay_paste` app.rs:5749). No image paste path exists.

### 1.5 Send / queue / steer / interrupt — the one-in-flight rule

`compose()` demotes `Message` → `FollowUp` whenever the latest snapshot's status is not
`idle` (`app.rs:5806-5817` + comment: a second immediate `send_message` is `:busy`).
After the first accepted submission the verb is pinned to `FollowUp` (`app.rs:6172-6174`).

`submit_composer` (`app.rs:6032`):
1. Refuses on owner conflict (`refuse_owner_conflict` app.rs:2891).
2. Drains any queued outcome-unknown reconciliation first, replaying the **same
   `turn_id`** (app.rs:6039-6143).
3. **One-in-flight per session**: `same_session_mutation_in_flight` (app.rs:5989) blocks a
   second Enter and leaves the draft untouched with a notice (app.rs:6145-6154). There is no
   client-side outbound queue — the second message is simply refused until the first is
   acknowledged. Ordering is protected by `submission_sequence`
   (`earlier_session_mutation_in_flight` app.rs:6005).
4. `turn_id` = fresh ULID-ish id for message/follow-up, **`None` for steer** (no durable
   ledger behind a steer, app.rs:6157-6163).
5. Params: `{"id","input","turn_id"}` + `node` routing (`routed_session_params` app.rs:2867).
   `input` is always a **bare string** — the structured envelope is never used.

Interrupt: `Esc`/`Ctrl+C` → `interrupt_turn` (`app.rs:6316`) → `interactive.interrupt {id}`
with no `turn_id` (defaults to the active turn, app.rs:6342). Coding plane has no interrupt;
it says so and points at `Ctrl+X x` (app.rs:6329-6337). `Esc` with an empty prompt on an idle
session leaves the session (`escape_from_prompt` app.rs:9112).

### 1.6 Approvals

Event `approval_requested` opens the modal, or `a`/`Ctrl+X a` reopens it (`reopen_approval`
app.rs:6361, `open_approval` app.rs:4742, `open_approval_with` app.rs:4754). Overlay variant
`Overlay::Approval { plane, id, request_id, subject, choice, reason }` (`app.rs:2011-2020`).
Four answers exactly — `APPROVAL_CHOICES` (`app.rs:2057-2062`): approve/once, approve/session,
deny/once, deny/session. Keys: `j/k/↑↓` choose, `r` opens the optional reason prompt
(`PromptKind::ApprovalReason` app.rs:860-867, handler app.rs:8628-8641), `Enter` submits,
`Esc` dismisses. `submit_approval` (`app.rs:8910`) marks the request answered locally then
issues `plane.method("respond_approval")` with
`model::respond_approval_params_with_reason(...)` — so the TUI **does** use the structured
`{decision, scope, reason}` object.

### 1.7 Session picker, new-session dialog, settings, quit

- **Picker** `Overlay::SessionPicker` (app.rs:2000-2002), keys `session_picker_key`
  (`app.rs:8815`): `j/k/↑↓`, `Enter` opens, `x` close/remove. Merged interactive+coding list.
  No search box, no rename, no fuzzy filter.
- **New-session dialog** `NewSession` (app.rs:1007-1038); fields `NewField`
  (app.rs:982-991): Plane, Machine, Provider, [Objective — coding only], Workspace,
  ApprovalMode, SandboxMode, Start. Approval cycler has 5 rows (`APPROVAL_ROWS` app.rs:872;
  index 0 = *omit the parameter*, app.rs:874-884). Sandbox likewise (`SANDBOX_ROWS` app.rs:873).
  Keys at app.rs:7804-7860; submit at `submit_new_session` (app.rs:7863).
- **Settings** `SettingsField` (app.rs:1216-1223): Machines, Provider, Workspace,
  ApprovalMode, SandboxMode, Save — writes `config.toml` only (app.rs:1236-1242 doc,
  keys app.rs:6726-6756).
- **Quit** `open_quit` (app.rs:8503): spawned → detach / shutdown (`runtime.shutdown` when
  served, else SIGTERM→SIGKILL, `Quit` enum app.rs:140-149); attached → disconnect only.
- **Close session** `open_close_confirm_for` (app.rs:8314): last-known row → `interactive.delete`
  (hide locally); terminal status → `*.delete`; live → close / kill options.
- **External editor**: `request_external_editor` (app.rs:9144) → driver suspends the screen and
  runs `$VISUAL`/`$EDITOR` (`tui/src/ui/mod.rs:679-701`, `run_external_editor` ~:770) →
  `Msg::ExternalEditor` replaces the draft (`apply_external_editor` app.rs:9151).
- **Copy last**: `copy_last_agent` (app.rs:9129) → `transcript_cells::last_agent_message` →
  OSC 52 + `pbcopy` on macOS (`tui/src/ui/mod.rs:294-315`).

### 1.8 Streaming / resync

`open_session_on` (app.rs ~:8420) creates a `Watch`, sets the cursor, and calls
`resync(plane,id,true)` → `interactive.subscribe {id,cursor}`; repairs use
`interactive.replay {id,cursor,limit:500}` (`resync` app.rs:4393-4453, `REPLAY_LIMIT` app.rs:75,
`MAX_RESYNC_ROUNDS` app.rs:80). Cursors are shared with the reconnect hook via `Cursors`
(app.rs:2085-2130) so a fresh handshake resubscribes from where each watch left off.
Notifications arrive as `interactive.event` / `coding.event` (app.rs:4110-4112).

---

## 2. Gateway methods (`lib/ouroboros/gateway/methods.ex`)

`@table` (`methods.ex:152-231`) is name → `%{scope, timeout, outcome}`; `permits?/2`
(`:328`) gates `:read` listeners; `names/0` (`:313`) is what `hello` advertises and what the
TUI feature-gates on (`Hello::serves` `tui/src/proto.rs:267`, `operates` `:271`).

**Read scope**: `hello`, `runtime.status`, `runtime.providers`, `fleet.status`, `fleet.doctor`,
`account.read`, `agents.list`, `agents.state`, `interactive.{list,info,replay,subscribe,unsubscribe}`,
`coding.{list,info,replay,subscribe,unsubscribe}`, `teams.{list,state}`, `plans.{list,get}`,
`control.{list,get}`, `upgrade.{status,rollouts,history}`, `signing.decisions`, `grants.list`.

**Operate scope**: `fleet.forget_session_owner`, `interactive.start`, `account.login.start`,
`account.login.cancel`, `account.logout`, `interactive.{send_message,follow_up,steer,
respond_approval,interrupt,close,kill,delete}`, `coding.{start,cancel,delete}`,
`teams.{add_worker,delegate,cancel,close}`, `control.{submit,cancel}`, `agents.stop`,
`capabilities.{list,preview,admit}`, `runtime.shutdown`.

`outcome: :unknown` on `interactive.start`, `coding.start`, `interactive.send_message`,
`interactive.follow_up` (methods.ex:189, 196-205, 212) — a gateway ceiling can fire *after*
durable dispatch, which is the whole reason the client carries caller-minted ids.

### 2.1 `@start_options` (`methods.ex:261-275`) → `InteractiveSession.start_for_gateway_on`

`id, provider, workspace, model, system_prompt, max_turns, event_limit, approval_mode,
sandbox_mode, reasoning_effort, runtime_exposure, machine, node`.
Enums: `@approval_modes` `default|prompt|auto_edit|auto_approve` (`:239-244`);
`@sandbox_modes` `default|read_only|workspace_write|unrestricted` (`:246-251`);
`@reasoning_efforts` `low|medium|high` (`:253`). Deliberately absent: `env`, `mcp_config`,
`provider_options` (`:256-260` comment).
**The TUI sends only `id, provider, workspace, approval_mode, sandbox_mode, machine`**
(`StartRequest::params`, `tui/src/model.rs:1344+`). `model`, `system_prompt`, `max_turns`,
`event_limit`, `reasoning_effort`, `runtime_exposure` are server-side-only today.

### 2.2 Turn envelope (`fetch_turn_input` methods.ex:1419-1448)

`params.input` may be a nonempty string **or** an object
`{prompt, attachments[≤32 strings], reasoning_effort}` (`structured_turn_input` :1433-1447).
Attachments are canonicalized against the session workspace before dispatch
(`authorize_turn_attachments` `lib/ouroboros/interactive/task.ex:859-866`). Codex's adapter
declares `:attachments` in `normalized_options`
(`deps/jido_harness/lib/jido_harness/adapters/codex.ex:36-45`).
**The TUI never sends the object form** (`app.rs:6191-6194`) — so per-turn attachments and
per-turn reasoning-effort switching exist server-side and are unreachable from the client.

`with_turn` (methods.ex:1141-1150) accepts `id, input, turn_id, node` and dispatches to
`InteractiveSession.send_message/3` or `follow_up/3`; the same `turn_id` returns the same turn
rather than starting a new one (`dispatch_turn` `interactive/task.ex:651-691`, `:turn_id_conflict`
on a different fingerprint, `:turn_dispatch_ambiguous` while `:dispatching`).

`interactive.steer` (methods.ex:605-620) takes `id, input, node` — **no `turn_id`**.
`interactive.interrupt` (`:635-647`) takes `id, turn_id?, node`, defaulting to `:active`.
`interactive.respond_approval` (`:622-633`) takes `id, request_id, response, node`;
`approval_response` (`:1308-1339`) accepts `"approve"`/`"deny"` or
`{decision, scope: once|session, reason}`.
Replay/subscribe: `with_replay` (`:1343-1349`) `id, cursor, limit, node`;
`subscription_params` (`:343-350`) `id, cursor, node` — subscribe registers `self()` (the conn)
and monitors it (`gateway/conn.ex:43-63`, `:144-148`).

### 2.3 Team / control / capability params

`teams.add_worker` `team_id, worker_id, role?, node?` (`@worker_options` :278; invoke :691).
`teams.delegate` `team_id, worker_id, objective, id?, coding_node?, workspace?, provider?`
(`@delegation_options` :280-285; invoke :703). `teams.cancel {team_id, delegation_id}` (:717),
`teams.close {team_id}` (:729). `control.submit {objective, id?, max_revisions?}` (:739),
`control.cancel {id}` (:751). `capabilities.{list,preview,admit}` take `workspace[,path[,session_id]]`
(:759-791).

---

## 3. Provider-facing session controls

`Ouroboros.InteractiveSession` (`lib/ouroboros/interactive_session.ex`) exposes
`start/start_on/start_for_gateway[_on]` (:25-113), `info` (:116), `list` (:119),
`subscribe/unsubscribe` (:126,:133), `replay` (:136), `send_message` (:143), `follow_up` (:148),
`await` (:153), `steer` (:194), `respond_approval` (:201), `interrupt(session, turn_id \\ :active)`
(:208-216), `close` (:219), `kill` (:222), `delete` (:231).

`Ouroboros.Interactive.Task` implements them (`handle_call` clauses at
`interactive/task.ex:145-216`). Steering is an injection into a live provider call and the text
is not recorded by Harness, so the task remembers up to 32 pending steers to re-attach the
prompt to the `input_accepted{kind:"steer"}` event (`task.ex:24`, `:435-473`).

**Safety options**: `Ouroboros.Provider.safety_options/3` (`lib/ouroboros/provider.ex:1222-1249`)
folds `@plane_defaults [approval_mode: :prompt, sandbox_mode: :workspace_write]`
(`provider.ex:46`) against the adapter's declared options. On the **interactive** plane an
unsupported-but-unstated option is silently dropped; on the **coding** plane it is refused,
naming *every* unsupported option at once (`:1234-1241`). `@unset_values [nil, [], %{}, :default]`
(`:88`) short-circuit as supported. Capability resolution is per-transport
(`normalized_options/2` `:1287-1300`).

**Status / `:lost`**: `Interactive.State` statuses include `:lost`
(`lib/ouroboros/interactive/state.ex:51`, terminal set at `:99`). `interactive_session.ex:49`
treats `:failed | :lost` as a start that did not survive. `Interactive.Task` marks a session
`:lost` when its durable record cannot be revived (`task.ex:1236`).
`Interactive.Recovery` (`lib/ouroboros/interactive/recovery.ex:44-60`) re-registers recoverable
sessions once per second after a restart — **so resume-after-restart is automatic and
server-side, with no user-facing "continue" verb**.

**What a session exposes publicly**: `State.public/1` (`state.ex:194-236`) projects
`approval_mode, sandbox_mode, model, reasoning_effort, transport, has_system_prompt,
has_provider_options, provider_execution` plus a per-turn map. Adapter capabilities include
`thinking?`, `usage?`, `resume?`, `native_cancel?`
(`adapters/claude.ex:25-32`, `adapters/codex.ex:25-33`).
There is **no plan mode** anywhere — `:plan` in `lib/ouroboros/control/*` is the *orchestration
planner*, not an agent plan/accept-edits mode.

---

## 4. Memory / context

- **No `CLAUDE.md` / `AGENTS.md` handling at all.** No file in `lib/` or `tui/src/` reads
  either name, and neither file exists in the repo.
- **Agent profiles**: `Ouroboros.AgentProfile` (`lib/ouroboros/agent_profile.ex:1-45`) is a
  versioned, provider-neutral prompt policy (id, base_prompt, instructions, skills, tools) with
  reserved-delimiter refusal (`:33-42`).
  `Ouroboros.Prompt.Assembler` (`lib/ouroboros/prompt/assembler.ex:1-38`) renders it into
  `<ouroboros-agent-profile>` / `<ouroboros-session-instructions>` / `<ouroboros-runtime>`
  blocks and emits a content-free digest trace (`Prompt.Trace` `lib/ouroboros/prompt/trace.ex:61-95`).
  Tools are advertised only when the request's explicit `allowed_tools` names them
  (assembler.ex:29-32).
  **`agent_profile` is not in `@start_options`** — only `Team.Server` sets it
  (`lib/ouroboros/team/server.ex:1799`, `:1833-1875`). It cannot be selected from the TUI or the
  gateway session verbs, and `state.ex:280-284` refuses a durable session that carries one.
- **No compaction / summarization / context-window accounting** anywhere in `lib/`.
- **Usage**: `usage` is a first-class event type produced by the Codex and ACP dialects
  (`lib/ouroboros/provider/session/dialect/codex.ex:166-174`,
  `dialect/acp.ex:197`) and parsed by the client (`tui/src/model.rs:260`, `:295`) — but
  `PresentationEvent::from_event` maps it to `Ignore` (`tui/src/model/transcript.rs:161`).
  Same for `plan_updated` and `queue_changed`. **Token usage is never shown**; it is only
  visible in the raw-event tree behind `Ctrl+O`.

---

## 5. Non-interactive / headless

- `ouro new --print` (`main.rs:447-575`): starts, prints the session id, optionally sends `-m`
  once with turn id `ouro-first:<session>`, retries exactly once on an outcome-unknown reply
  under the same id (`main.rs:485-527`), prints a "runtime still running (pid …)" line, exits.
  **No event stream, no transcript, no JSON.**
- `ouro attach --print` (`main.rs:1722-1725`): one human-readable status page
  (`tui/src/status.rs:14-50` `render_hello`/`render_status`). Not JSON.
- Mix tasks: exactly one — `mix ouroboros.gateway.golden`
  (`lib/mix/tasks/ouroboros.gateway.golden.ex`), a fixture generator, not an agent surface.
- **SDK-like use**: the gateway is a newline-delimited JSON-RPC socket over loopback with a
  0600 token file (`gateway/conn.ex:10-13`, `listener.ex`), so scripting it is possible, but no
  client library, no `--json`, and no documented headless streaming mode ships.

---

## 6. Onboarding / auth

- Boot screen as in §1.1. First run marks `onboarding.welcomed` on the first submitted prompt
  (`mark_welcomed` app.rs:5371, `config.rs:137-144`).
- Config is `$XDG_CONFIG_HOME/ouroboros/config.toml` (`tui/src/config.rs:68`, `:160-176`) with
  `[defaults] provider/workspace/approval_mode/sandbox_mode` (`:96-125`) and `[onboarding]`.
  `resolve_start` (`config.rs:420`) is the single flag-vs-config precedence point; a missing
  provider is a hard refusal with a message that prints the file path (`Missing::message` :401).
- **Provider probing**: `runtime.providers` (`methods.ex:428`, impl `:907-925`) fans out
  `probe_provider` with a 5 s ceiling (`@provider_probe_timeout` :102). Registry builtins:
  amp, claude, codex, gemini, kimi, opencode, grok, pi, zai
  (`deps/jido_harness/lib/jido_harness/registry.ex:5-16`). Un-probed entries are still selectable
  (app.rs:1000-1006 doc).
- **Account dialog** is Codex/ChatGPT-only. `AccountDialog`/`AccountFlow`
  (app.rs:1968-1995), `open_account` (app.rs:5658-5700) issues `account.login.start {flow:
  "browser"|"device_code"}`; browser when this client spawned the runtime, device code otherwise.
  Keys `account_key` (app.rs:8861-8905): `o` re-opens the URL, `l` logs out, `Esc` cancels via
  `account.login.cancel`. Server side is `Ouroboros.Provider.CodexAppServer`
  (`lib/ouroboros/provider/codex_app_server.ex:68-107`, completion notification at `:419-427`);
  `methods.ex:454-486` just forwards to `account_adapter()`.
- **Claude / Gemini / others have no auth flow here.** Their adapters report status from env
  vars only (`adapters/claude.ex:79-86` reads `ANTHROPIC_AUTH_TOKEN`/`ANTHROPIC_API_KEY`/
  `CLAUDE_CODE_API_KEY`; `adapters/codex.ex:69-75` for OpenAI). Authentication is entirely
  delegated to the provider CLI's own on-disk state — the TUI's home refuses to submit only for
  `codex` when unusable (`submit_home` app.rs:5420-5424).

---

## 7. Multi-agent UX as exposed today

Tabs: Dashboard, Sessions, Agents, Teams, Plans/Control, Upgrade, Logs (`Tab` app.rs:83-91).

- **Agents / Teams tabs are read-only JSON tree explorers.** `Explorer` (app.rs:372-411);
  `explorer_activate` (app.rs:5219-5241) only expands/collapses nodes. The tabs poll
  `agents.list`, `teams.list`, `teams.state` (app.rs:3078-3140).
- **`teams.delegate`, `teams.add_worker`, `teams.cancel`, `teams.close`, `agents.stop` have
  zero call sites in the TUI** (verified by grep over `tui/src/ui/app.rs`). They are gateway
  methods with no UI.
- **Plans/Control is the only tab with operate actions**: `s` → `control.submit` behind an
  objective prompt (`open_control_submit` app.rs:6668, `PromptKind::ControlObjective` app.rs:857,
  submit at app.rs:8994-9002); `c` → `control.cancel` behind a confirm (app.rs:6681-6705).
  `plans.list` / `plans.get` / `control.list` / `control.get` are polled read-only
  (app.rs:3086, 3145, 3087, 3151).
- **Delegated / sub-task progress is not surfaced** in the session transcript. A delegation
  becomes a coding task on the coding plane; the Sessions rail merges both planes
  (`SessionsTab::merged`, `sessions.rs:92-293` rail), but there is no parent/child grouping.
- **Coding plane takes no input at all** — `compose()` refuses it (app.rs:5811-5820) and the
  composer draws "This coding task takes no further input" (`sessions.rs:1275-1281`).
- **No worktree support anywhere** (no `git worktree` reference in `lib/` or `tui/src/`).
  Isolation is per-`workspace` path plus `sandbox_mode` only.
- **Background tasks**: `--machine` places a session on a fleet node (`@start_options` `machine`,
  `MachineChoice` app.rs:1782-1801), and coding tasks run headless, but nothing runs *detached
  behind the current conversation* the way Amp/Claude Code sub-agents do.

---

## 8. GAP LIST vs. Claude Code / Codex CLI / OpenCode / Amp

| Gap | What exists to build on | What is absent |
|---|---|---|
| **Plan mode** | `plan_updated` event type is parsed (`tui/src/model.rs:259`) | Mapped to `Ignore` (`model/transcript.rs:161`); no plan panel, no plan/accept toggle, no `plan` value in `@approval_modes` (`methods.ex:239-244`). `:plan` in `control/` is the orchestration planner, unrelated. |
| **Permission modes (auto / accept-edits / ask)** | Four `approval_mode` values + four `sandbox_mode` values, settable at start (`methods.ex:239-251`), cycler UI (`app.rs:874-933`), shown in composer chrome (`sessions.rs:1219-1226`) | **Start-time only** — `start_writable_session` (app.rs:5513-5520) says a running read-only session cannot be promoted, and starts a *new* session instead. No mid-session `Shift+Tab` mode cycle, no per-tool allowlist. |
| **Message queueing** | Durable `follow_up` queue exists server-side; verb auto-demotes (app.rs:5806-5817) | Client refuses a second Enter while one call is unacknowledged (app.rs:6145-6154). No visible outbound queue, no reorder/cancel of queued messages, and `queue_changed` events are ignored (`transcript.rs:161`). |
| **Rewind / checkpoint / undo** | Durable per-turn ledger with stable ids and fingerprints (`state.ex:177-192`, `task.ex:661-679`); event cursors (`app.rs:4393-4453`) | No verb to truncate/branch a session, no file snapshot, no `/rewind`, no `Esc Esc`. |
| **Resume / `--continue`** | `Interactive.Recovery` auto-revives sessions after restart (`recovery.ex:44-60`); picker lists everything (`app.rs:8815`); adapters declare `resume?: true` | No `ouro --continue` / `--resume <id>` flag (`cli.rs:39-137`), no "resume last session" affordance; the user must open the picker. |
| **Session naming / search** | `objective` field on the coding plane (`methods.ex:669`, `NewField::Objective` app.rs:989) | Interactive sessions have no title/name field, no rename verb, no search or filter in the picker; ids are shown compacted (`sessions.rs:294-320`). |
| **Model / effort switching** | `model` and `reasoning_effort` are in `@start_options` (`methods.ex:266,271`), projected in `State.public/1` (`state.ex:200-203`), and `reasoning_effort` is accepted **per-turn** in the structured envelope (`methods.ex:1434-1446`) | Neither is in `StartRequest` (`tui/src/model.rs:1344+`), neither is a `NewField` (app.rs:982-991) or `SettingsField` (app.rs:1216-1223), and no `/model` or `/effort` command exists (`editor.rs:18-51`). |
| **`@file` structured attachments** | `@` completion over a 4 000-file index (`editor.rs:792`); `attachments[≤32]` accepted and workspace-canonicalized (`methods.ex:1433-1447`, `task.ex:859-866`); Codex declares `:attachments` (`adapters/codex.ex:44`) | The TUI substitutes plain text and always sends `input` as a string (`app.rs:6191-6194`). The whole attachment path is dead from the client. |
| **Image paste** | Bracketed paste plumbing (`app.rs:5713`), Codex transport declares `%{multimodal: :managed}` (`adapters/codex.ex:35`) | No image decode, no clipboard-image read, no `image/*` attachment kind. |
| **Vim mode** | Full emacs/readline keymap (`editor.rs:225-330`); `j/k/h/l` navigation outside the composer (app.rs:4928-4933) | No modal editing, no `~/.ourorc` keymap, no keybinding customization at all. |
| **Hooks** | — | Nothing. No pre/post-tool hook, no session lifecycle script, no `settings.json` equivalent (`config.rs:83-152` has only defaults + onboarding). |
| **Custom commands / skills** | Fixed 28-entry slash catalog (`editor.rs:18-51`); `AgentProfile` already models `skills` and `tools` (`agent_profile.ex:29`) | Slash list is a compile-time array; profiles are unreachable from the gateway (`@start_options` has no `agent_profile`, `methods.ex:261-275`) and refused in durable session options (`state.ex:280-284`). |
| **Headless JSON streaming** | JSON-RPC gateway with `replay`/`subscribe` cursors (`methods.ex:341-380`); golden fixtures task | `--print` emits prose only (`main.rs:447-575`, `status.rs:14-50`). No `--output-format json`, no stream-json, no exit-code contract for agents. |
| **Notifications** | Notice line with three severities (`Notice`/`NoticeKind` app.rs:2065-2083) | No terminal bell, no OSC 9/777, no desktop notification, no idle/approval-waiting alert. Only OSC 52 clipboard writes exist (`ui/mod.rs:294-315`). |
| **Context/usage surfacing** | `usage` events from Codex + ACP dialects (`dialect/codex.ex:166-174`, `dialect/acp.ex:197`); `Usage` variant parsed (`model.rs:260`) | Ignored by the projection (`transcript.rs:161`); no token counter, no context-window bar, no cost. |
| **Compaction** | — | Absent entirely; nothing in `lib/` summarizes or truncates a conversation. |
| **Diff review UX** | `file_change` → `FileUpdate` with diff/insertions/deletions (`model/transcript.rs:147`, `:74-92`), rendered by `project_file` (`transcript_cells.rs:499`) | Read-only rendering; no per-hunk accept/reject, no `git`-aware review, no revert. |
| **Sub-agent / team UX** | `teams.delegate` / `teams.add_worker` / `teams.cancel` / `teams.close` all served (`methods.ex:215-221`) | Zero TUI call sites; Teams tab is a JSON tree. No spawn-subagent affordance, no per-worker transcript. |
| **Worktrees** | `workspace` per session, `add_dirs` in adapters | No git worktree creation/teardown, no branch isolation. |
