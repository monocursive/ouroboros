# M1 — Ouroboros display pipeline map (verified 2026-08-22)

## 1. Normalized event taxonomy (Jido.Harness)

The canonical envelope is `Jido.Harness.Event` (`deps/jido_harness/lib/jido_harness/event.ex`). 29 types at `event.ex:15-46`: run lifecycle (`:run_started/:run_completed/:run_failed/:run_cancelled`), session lifecycle (`:session_started/:session_ready/:session_idle/:session_closed/:session_failed/:session_cancelled`), turn/queue (`:input_accepted`, `:turn_queued`, `:turn_started`, `:turn_completed`, `:turn_failed`, `:turn_interrupted`, `:queue_changed`), output (`:output_text_delta`, `:output_text_final`, `:thinking_delta`, `:command_output_delta`, `:tool_call`, `:tool_result`, `:file_change`, `:plan_updated`, `:usage`), interaction (`:approval_requested`, `:approval_resolved`), escape hatch `:provider_event`.

Envelope fields (`event.ex:56-69`): `type, run_id, session_id, provider, provider_session_id, turn_id, request_id, sequence, timestamp, payload (string-keyed map), raw`. `raw` is in-memory only, never journalled.

Payload shapes:
- tool_call — Claude stream: `%{"name","input","call_id"}` (`adapters/cli_mapper/claude_stream.ex:88-98`). Codex CLI: `%{"name" => "exec_command", "input" => %{"cmd","cwd"}, "call_id"}` (`cli_mapper/codex.ex:78-90`); MCP calls `%{"name" => item["tool"], "input" => arguments}` (`codex.ex:105-118`). ACP: payload IS the raw ACP `update` map (`session/transports/acp.ex:329`) — keys `toolCallId/title/kind/status/content/locations/rawInput`, never normalized further.
- tool_result — Claude: `%{"output" => block["content"], "call_id", "is_error"}` (`claude_stream.ex:100-113`). Codex: `%{"name","output" => aggregated_output,"call_id","is_error"}` (`codex.ex:91-101`). ACP: raw `tool_call_update` map (`acp.ex:330`).
- file_change — two shapes: `%{"diff" => …}` for `turn.diff.updated` (`codex.ex:51`; dialect `lib/ouroboros/provider/session/dialect/codex.ex:150`) and `%{"changes" => […], "status" => …}` item-level (`codex.ex:127-137`; dialect `codex.ex:289`). Generic JSON adapter passes the raw record (`adapters/json_mapper.ex:54`).
- thinking_delta — `%{"text" => …}` (`claude_stream.ex:85`, dialect `codex.ex:284-286`).
- usage — provider usage map with `total_tokens` derived (`claude_stream.ex:116-123`, `codex.ex:145-149`, dialect `codex.ex:166-174`).
- approval_requested — `%{"tool_call" => …, "options" => […]}` for ACP (`acp.ex:376-381`); Codex dialect builds `%{"tool_call" => %{"name","command","cwd"}, "reason", "kind"}` (`dialect/codex.ex:347-366`), kinds `sandbox_escalation | file_change | permissions`.
- plan_updated — `%{"explanation", "plan" => […]}` (`codex.ex:56-64`).

Durability + redaction: `Ouroboros.Interactive.Event.from_harness/2` (`lib/ouroboros/interactive/event.ex:30-47`) and `Ouroboros.Coding.Event.from_harness/3` (`lib/ouroboros/coding/event.ex:27-40`) call `HarnessEventProjection.durable_fields/1` (`lib/ouroboros/harness_event_projection.ex:43-47`), then `Jido.Harness.Redaction.redact/1`. Durable struct has NO `raw` field — only `type` + redacted `payload` + identity survive. Redaction (`redaction.ex:5-6,24-35`): keys matching `authorization|credential|password|secret|token|api_key` → `[REDACTED]`, Bearer rewrite, env-derived secrets ≥4 bytes substring-replaced. Codex adapter derives secret set from effective env (`lib/ouroboros/provider/codex_adapter.ex:44-77`).

Ouroboros normalization: Codex `item.started` of a `command_execution` is rewritten from `:provider_event` into `:tool_call` with a stable `call_id` (`harness_event_projection.ex:27-38,58-66`).

Retention: `event_limit: 10_000` (`lib/ouroboros/interactive/state.ex:33`, `lib/ouroboros/coding/task_state.ex:110`, max 100_000 `state.ex:344`). Overflow drops oldest, raises `event_floor` (`interactive/task.ex:1360-1372`; `coding/task.ex:534-546`). Replay below floor → `{:cursor_pruned, floor}` (`interactive/task.ex:1421-1424`). Harness replay poll `@replay_limit 100` every `@poll_interval 25`ms (`interactive/task.ex:16-17`). User prompt text re-injected into `:input_accepted` under `"text"` (`interactive/task.ex:388-431`).

## 2. Gateway streaming

Notifications `interactive.event` / `coding.event` params `%{"id","event"}` (`lib/ouroboros/gateway/conn.ex:286-296,813-828`). Control frames `stream.ended` (`conn.ex:774-786`), `stream.lagged` `%{"id","plane","dropped","last_sequence"}` (`conn.ex:838-865`).

`Ouroboros.Gateway.Wire.to_json/1` (`gateway/wire.ex:57-61`): structs → fields + `"_struct"`, atoms lose `Elixir.`, pids/refs/functions → `%{"_opaque" => inspect}`, non-UTF8 → `%{"_b64"}`, deeper than 32 levels or >50_000 nodes → `%{"_truncated" => true}` (`wire.ex:49-52`). NO per-field byte truncation — a 10 MB diff payload is framed whole. Inbound frame cap `@default_max_frame 1_048_576` (`gateway/config.ex:102`; `conn.ex:378-379,396-399`); outbound unbounded.

Backpressure: `@default_queue_limit 1_000` outbound frames (`config.ex:103`); above it event notifications dropped and counted per session (`conn.ex:813-836`); responses/stream-control never dropped (`conn.ex:74-80`). One `stream.lagged` per session once queue drains below `queue_limit/2` (`conn.ex:846-878`). `@max_in_flight 8`, `@max_pending 64`, `@max_subscriptions 64` (`conn.ex:106-118`). Replay ceiling 500, default 100 (`gateway/methods.ex:110-111,1522-1528`).

## 3. TUI model and transcript projection

`Event::decode` (`tui/src/model.rs:363-377`) keeps full wire JSON in `Event::raw`; `decode_batch` drops undecodable (`model.rs:384-401`). `EventType` mirrors 29 kinds + `Other(String)` (`model.rs:203-234`).

`PresentationEvent::from_event` (`tui/src/model/transcript.rs:93-164`) handles exactly: InputAccepted (98), OutputTextDelta|Final (99), ToolCall (110), ToolResult (127), CommandOutputDelta (144), FileChange (147), ApprovalRequested (148), ApprovalResolved (152), Run/Session/TurnFailed (157), Run/SessionCancelled|TurnInterrupted (160). EVERYTHING ELSE → `Ignore` (`transcript.rs:163`) — incl. ThinkingDelta, Usage, PlanUpdated, TurnQueued, QueueChanged, TurnStarted/Completed, RunStarted/Completed, SessionReady/Idle/Closed, ProviderEvent.

Key tolerance: tool name from `name|tool_name|toolName|tool|title|kind` (`transcript.rs:114-117`), input `input|arguments|parameters|rawInput|raw_input` (120-123), output `output|result|content|rawOutput|raw_output` (137-140). Diff parsing counts +/- and pulls path from `diff --git a/… b/…` or `+++ b/` (`transcript.rs:317-360`).

Projection ceilings (`transcript.rs:13-18`): TEXT 64 KiB, VALUE 64 KiB, VALUE_NODES 2_048, DEPTH 32, DIFF 128 KiB, FILE_CHANGES 256 (synthetic "… additional files" row `transcript.rs:274-280`).

`tui/src/ui/transcript.rs::Watch`: `WINDOW = 5_000` (`:41`), overflow raises client floor (`:494-512`). `MAX_NOTES = 64` (`:45`). `entries()` (`:404-472`) interleaves Floor/Gap/Note/Event/Ended. Cursor = contiguous high-water mark (`:517-527`). Scroll/follow/viewport on `Watch` (`:245-281`).

Chat pane keeps last 128 entries (`tui/src/ui/sessions.rs:27,1046-1069`) with divider "{omitted} earlier chat entries omitted here — Ctrl-O shows all retained events".

`transcript_cells::project` (`transcript_cells.rs:114-266`) → Cells: `Message{You|Agent}`, `Tool`, `CommandOutput`, `File`, `Diff`, `Status`, `ChatNote`, `Divider`. Delta collapsing `project_agent_text` (`325-359`): consecutive deltas same turn → `PendingOutput` bounded `AGENT_OUTPUT_BYTES = 128 KiB`; final replaces draft. Tool rows correlated by `call_id`, mutated in place on result (`375-439`); approvals likewise, "Approval needed" Status cell rewritten to Approved/Denied (`453-497`).

HIDDEN VIEW IS Ctrl-O (not Ctrl-E as TUI.md says): `Ctrl+O` toggles `show_event_details` (`app.rs:4845-4851`, toggle at `app.rs:5929`; leader `x o`/`x d` `app.rs:4965`); `Ctrl+E`/`Ctrl+G` opens `$EDITOR` (`app.rs:4959`). Details view = flat list `{seq:>6}  {kind}  {summary}` (`sessions.rs:1088-1112`), `summary()` prefers `payload["text"]` else `key=value` pairs (`model.rs:403-418`). NOT a JSON tree — `TreeView` only in explorer/upgrade (`ui/explorer.rs:230,303`).

## 4. Rendering, per cell

- User message (`transcript_cells.rs:539-593`): boxed `┌─ ▌ YOU ─┐`, amber, ≤ `MESSAGE_LINES = 256` rows, then "… full message in event details".
- Agent message (`596-688`): header `◆ AGENT / RESPONSE` cyan; `code::split_fences` (`ui/code.rs:35-69`) splits prose/fences. Prose: `wrap_limited` + `style_inline_code` — colours ONLY the first backtick pair per wrapped row (`771-792`). Code blocks framed with language label (`render_code_block` `690-753`). NO other markdown — headings/lists/tables/quotes/bold/links literal.
- Syntax highlighting (`ui/code.rs`): 21 languages (`code.rs:141-164`), aliases (`194-227`). Hand-written tokenizer, not a parser (`code.rs:1-12`): comments, triple quotes, keywords, numbers, call names, capitalized types, atoms, `$vars`, `key:` (`266-300`). ANSI palette colours (`243-263`). No line numbers.
- Tool cell (`794-904`): head `{spinner|✓|✗} {display_name}  {input}  [running|failed]`. `display_tool_name` maps `exec_command|run_command|bash|shell` → `command`, else `_`→space (`1188-1193`). `tool_input` (`1104-1124`): `cmd|command` for command-ish, else first of `path|file|query|pattern|url`, else bounded JSON ≤ `TOOL_INPUT_BYTES = 8 KiB`, flattened, `tree::truncate` (`ui/tree.rs:400-423`). Width ≥ 24: boxed; OUTPUT SHOWS EXACTLY ONE WRAPPED LINE (`wrap_limited(&output, content_width, 2)` at `880`) + "… full result in event details". `TOOL_OUTPUT_LINES = 3` only on narrow fallback (`843-855`).
- Command output (`920-933`): `COMMAND_OUTPUT_LINES = 4`, indented, muted.
- File cell (`935-952`): `  {A|D|R|M} File  {path}` coloured (`1195-1207`). No stats.
- Diff cell (`954-1010`): heading `  Diff  {path}  +{a} -{d}` (+ "in excerpt" when cut), then 12 raw unified lines (`DIFF_LINES = 12`) coloured +/-/@@, truncated not wrapped, then "… full diff in event details". No line numbers, no per-file grouping, no intra-line diff, no side-by-side.
- Status cell (`1020-1044`): bold label + `STATUS_DETAIL_LINES = 32`.
- Dividers (`1229-1244`).
- Streaming cursor `▌` blinking `tick % 8 < 5` (`660-687`); tick 80 ms (`app.rs:53`).
- Spinner: 10 braille frames, verbs Working/Thinking/Planning every 38 ticks ≈ 3 s (`ui/theme.rs:88-114`).
- Wrapping/scrolling: hand-rolled `wrap_limited` via unicode-width (`transcript_cells.rs:1330-1420`); renderer reports line count via `Watch::measured` (`ui/transcript.rs:262-281`, `sessions.rs:782-826`). Keys PageUp/Down ±10, Ctrl/Shift+Up/Down ±3, wheel ±3 (`app.rs:5049-5076`, `ui/mod.rs:451-459`).
- Header (3 rows at width ≥ 52 & height ≥ 12): title / `● FOLLOWING|SCROLLED|RESTORING|ENDED` / `^O EVENTS`, then `{plane} · {provider} · {short id}` (`sessions.rs:836-928`).
- Footer (`ui/view.rs:255-346`): notice (`NOTICE_TICKS = 63` ≈ 5 s, `app.rs:62`) else `● LIVE  OWN RUNTIME|ATTACHED · {scope} · {address}` + shortcuts at width ≥ 112. NO model, tokens, context usage, cost, elapsed. `SessionInfo` (`model.rs:454-471`) = plane/id/status/provider/node/workspace/timestamps/objective.
- Right rail (`sessions.rs:334-528`, width ≥ 112 & height ≥ 34): SIGIL/CONTEXT CHANNEL, ACTIVE CONTEXT, EXECUTION TRACE, BOUNDARIES.
- Composer (`sessions.rs:1341-1435,1506-1554`): 2–6 rows, title `PROVIDER · REQUESTED APPROVAL · FILES`, footer names Ctrl+J or Shift+Enter (`sessions.rs:1431-1443`). Completions: `/` (28 at `ui/editor.rs:18`) and `@` paths, 3 rows + "+N more" (`sessions.rs:1446`); index cap `WORKSPACE_FILE_LIMIT = 4_000` (`editor.rs:16`); history 100 (`editor.rs:15`).

## 5. Approval modal

`Overlay::Approval` → generic `chooser` (`ui/view.rs:395-411` → `1807-1863`). Title `approval requested — {id}`; detail: `request {request_id}`, subject, `r — attach a reason`. Subject from `ApprovalRequest::subject()` (`ui/transcript.rs:86-97`): `{command} — {reason}`; command from `/tool_call/command`, `/tool/command`, `command` (`transcript.rs:99-116`) else compact JSON. Options fixed 4-way (`app.rs:2057-2062`). NEVER shows a diff, cwd, or provider option labels (harness carries `payload["options"]`, `acp.ex:376-381`).

## 6. Terminal integration

Alternate screen yes (`ui/mod.rs:209`, restore `287-292`). Bracketed paste yes (`211`). Mouse capture yes but only wheel consumed (`213`; `451-459`) — native text selection disabled. Kitty keyboard protocol probed (`217-227`), `ENHANCED_KEYBOARD` gates Shift+Enter advertisement (`mod.rs:172-177`). Clipboard OSC-52 + pbcopy (`mod.rs:296-315`). NO images (no sixel/kitty/iTerm). NO bell, NO OSC-9/777 desktop notification, NO OSC-0/2 tab title. No inline (non-alt-screen) mode; `ouro attach --print` one-shot status (`ui/mod.rs:193-196`, `cli.rs:86`).

## 7. Explicit limits

`event.ex` 29 types (15-46). `buffer.ex:12` 1 MiB harness buffer. `interactive/state.ex:33` / `coding/task_state.ex:110` event_limit 10_000, max 100_000 (`state.ex:344`). `interactive/task.ex:16-24` poll 25 ms, replay 100, max_pending_steers 32. `gateway/wire.ex:49-50` depth 32 / 50_000 nodes. `gateway/config.ex:102-103` max_frame 1 MiB, queue_limit 1_000. `gateway/conn.ex:106-118` in-flight 8, pending 64, subscriptions 64. `gateway/methods.ex:110-111` replay 500/100. `tui/transport.rs:54,58,68-70` max line 8 MiB, outbound 1 MiB, notification capacity 1024. `tui/ui/app.rs:53,75,80` tick 80 ms, replay 500, resync rounds 40. `tui/model/transcript.rs:13-18` 64 KiB text/value, 2048 nodes, depth 32, 128 KiB diff, 256 files. `tui/ui/transcript.rs:41,45` window 5_000, notes 64. `tui/ui/sessions.rs:27,1446-1449` chat 128, completion rows 3, composer 2–6+3. `tui/ui/transcript_cells.rs:26-34` tool output 3, command output 4, diff 12, message 256, status 32, agent 128 KiB, command 64 KiB, tool value 32 KiB, tool input 8 KiB. `tui/ui/editor.rs:15-16` history 100, files 4_000. `tui/ui/boot.rs:62` failure tail 200.

## 8. Gap list (verified)

1. Reasoning captured/durable but never displayed — `thinking_delta` → Ignore (`model/transcript.rs:163`).
2. No token/context/cost display — `:usage` ignored; no field in `SessionInfo`; footer carries none.
3. No model identity — only provider; harness carries `model` in Claude `run_started` (`claude_stream.ex:14-19`), discarded.
4. Tool results show one line (`transcript_cells.rs:880`); no in-place expand; Ctrl-O is a flat dump.
5. `plan_updated` dropped — no todo/plan panel.
6. Diffs 12 raw lines, truncated, no line numbers/grouping/intra-line.
7. Markdown essentially unrendered.
8. Approval modal shows no diff and no provider option labels.
9. No turn-completion markers (`turn_completed`, `run_completed`, `session_idle` ignored).
10. No timestamps/per-turn duration.
11. Mouse capture disables native selection; only copy-last-message.
12. No bell/desktop notification/tab title on approval or completion.
13. Ctrl-O details is a flat key=value dump though `Event::raw` holds the tree and `TreeView` exists.
14. `provider_event` invisible in chat.
15. Wire applies no payload byte cap; multi-MB diffs cross socket whole, cut client-side to 128 KiB/12 rows. Server-side excerpting would live in `gateway/conn.ex:813-828`.
