# REPLAY — deterministic re-execution for the native provider

Status: **BUILT** (2026-08-30; spec written same day against `deploy` @ `5d9bbda`,
implemented as slices R1–R4 plus the seam-wiring follow-up). The spec body below is kept
as designed; §11 records every as-built deviation and what the live acceptance walk
proved. File:line references in the body are to the pre-implementation tree.

## 0. Vocabulary, and the governing property

The property this document exists to deliver: **a native session is a deterministic
function of its inputs and its recorded effect results.** All nondeterminism — the model,
the tools, the clock, the human — flows through effects; once each effect's result is
recorded, re-running the session against the record must reproduce it exactly.

Two words, used precisely throughout:

- **Replay** — re-running against the record. Replaying an inference returns the
  recorded output. Replay executes nothing, spends nothing, and writes no ledger
  entries. Its output is a verdict and a transcript.
- **Fork** — replaying to a decision point and then *substituting*: a different model, a
  different answer, a live continuation. Re-calling the model is always a fork, never a
  replay, and the tooling must call it that.

Why this feature outranks the alternatives is recorded in the project history: it is the
missing pillar of the mediated-effects kernel (envelope, capability table, policy, WAL,
gate, supervision all exist in some shape; determinism/replay does not), it closes the
oldest open loop (Forge eval tests hand-assemble challengers; fork-at-a-decision-point
turns every recorded real session into an eval corpus), and it is structurally
native-only — nobody can deterministically replay `claude --print` — which makes it the
honest argument for the native provider as flagship.

## 1. What the tree already holds, and why none of it is the substrate

Four stores exist. Each was examined as a candidate replay substrate; each fails for a
reason worth recording, because the failures shape the design.

**The effect ledger** (`lib/ouroboros/agent/effect_ledger.ex`) is the authority record:
checkpoint-before-execution, refusals-as-terminal-entries, `:ambiguous` recovery at boot,
a `:tool_call` entry per native tool run and an `:approval` per human answer (I1). It is
disqualified as a replay substrate **by design, and correctly**: it is content-minimized
("Message bodies … provider output … are never accepted", moduledoc), it serializes and
fsyncs the *entire* retained list on every write (`checkpoint_state/1` :871), it retains
1,000 entries with max-min-fair-by-kind eviction from the *middle* of the sequence space
(`retain_terminal/2` :761-781), and settlement *mutates* an entry and re-sequences it
(`apply_settlement/4` :553-562). The last two also make a **stored** hash chain
structurally unsound here — a verifier could not distinguish eviction from tampering, and
every settle would invalidate successors' hashes. The codebase already made the right
call once: `ledger.export`'s chain is computed at answer time over the result set
(`Encode.chain/1`, `lib/ouroboros/gateway/methods/encode.ex:152-165`), "self-verifying,
which is a different and much smaller claim than tamper-proof storage". That stays as-is.

**The conversation checkpoint** (`lib/ouroboros/provider/native/checkpoint.ex`) is the
model-context cache: one `conversation.json` per session, **rewritten whole after every
turn**, trimmed to the newest `event_limit` (default 400) messages with an `offset`
recording what was dropped. Disqualified three ways: rewind truncates and re-appends, so
absolute message indices are **reused** over a session's lifetime (`session.ex:1141`);
compaction elision **replaces tool-result content in place** with a byte-count marker
(`context/compaction.ex` `elide/1`) and the pre-elision bytes survive in no durable
artifact; and neither the system prompt, the per-turn model spec, usage, thinking, nor
mid-session `configure` changes are in it at all.

**The harness event stream** carries most of what a client renders, and the existing
`interactive.replay` verb (gap-repair windowed fetch — that name is **taken**,
`tui/src/model.rs:85`) serves it. Disqualified as the *authoritative* substrate:
events are redacted at the emit boundary (`loop.ex:2740-2749`), thinking text is emitted
but the store's retention/durability posture was not designed as a replay contract, and
nothing in it carries provenance (prompt digests, model versions) or a tamper-evidence
chain. It remains the *render* source it already is.

**The turn manifest + blob store** (`<session dir>/manifest.json`, `blobs/<sha256>`) is
the rewind substrate: per-turn `{path, before, after}` file snapshots, content-addressed,
256 MiB budget, oldest turns dropped **as a recorded state** ("the record keeps the paths
and loses the digests"). Not a conversation record at all — but its two disciplines
(content addressing; dropped-is-a-recorded-state) are exactly the ones the journal below
adopts, and its blob store is reused directly (D5).

## 2. Design at a glance

Three additions, one extension, one badge:

1. **A per-session append-only turn journal** — the replay substrate and the tamper-
   evident record. New file beside the conversation. (§3)
2. **`:inference` as an effect-ledger kind** — every model call gets an authority entry
   with provenance, hard-gated like tool calls, settled with a journal pointer. (§4)
3. **Verified replay** — re-run `Loop.run_turn` with the model, tools, and control
   channel substituted by the record; assert byte-identical projection. (§5)
4. **Fork grows `to_turn` and `model`** — `interactive.fork` ships today
   (`methods.ex:328`, `seed_fork/4` at `native/session.ex:1094-1110`); the missing halves
   compose two mechanisms that already exist. (§6)
5. **A `replay` session capability** — the badge, derived beside `:fork`/`:compact`
   (`provider.ex:71`), explicit `false` for every vendor provider. (§7)

The sketch's line lands literally: the journal is the source of truth for what a session
*was*; `conversation.json` is a cache of it for the model's benefit.

## 3. The turn journal

### 3.1 File and framing (D1)

`<session dir>/journal.ndjson` — one JSON object per line, append-only, mode `0600`,
beside `conversation.json` / `manifest.json` / `blobs/`. NDJSON rather than a rewritten
document because append-only is what makes the chain (D3) and the crash story (D7)
sound; the conversation file's whole-rewrite discipline is right for *its* job and wrong
for this one.

Owner: `Ouroboros.Provider.Native.Journal` (new module). Writers: the loop process
during a turn; the session process between turns (open, configure, compaction, rewind,
close). Turns are sequential per session and session-side records are written only while
no turn is running, so there is exactly one writer at a time **by construction** — the
same argument `session.ex:36-42` already makes for the checkpoint. Appends use
`[:append, :binary, :raw]` with `:file.sync` per record (one delta-sized fsync per
record; for comparison, every tool call already costs two whole-ledger fsyncs).

**A journal write failure never refuses the effect.** The *ledger* is the authority gate
(loop.ex:47-55: "a ledger that cannot record the call refuses it" — unchanged); the
journal is the record. On append failure the session emits a `provider_event` of kind
`journal_degraded` once per turn, and the next successful append writes a `gap` record
naming what was lost. A session whose journal has gaps reports its capability as
degraded (§7) and verified replay refuses across the gap by name.

### 3.2 Record vocabulary (D2)

Every record: `{"seq": n, "at": iso8601, "turn_id": …, "kind": …, "prev": …, "hash": …,
…kind fields}`. `seq` is per-session, contiguous from 1. `at` is the wall instant that
was *already observed* by the live run (recorded, never re-read on replay — D9). Kinds:

| kind | fields | written when |
|---|---|---|
| `session_opened` | `provider_session_id`, `resumed?`, `forked_from_provider_session_id?`, `journal_version` | session init |
| `turn_started` | `turn_id`, `model_spec`, `reasoning_effort`, `approval_mode`, `sandbox_mode`, `max_iterations`, `prefix_fingerprint`, `system_sha256` | top of `Loop.run_turn` |
| `prompt` | the user message as appended (text + attachment pointers `{sha256, media_type, size}`) | after `UserPromptSubmit` hook fold (loop.ex:234-236) — i.e. the bytes that actually entered the conversation |
| `model_call` | `iteration`, `request_sha256`, `system_sha256`, `message_count`, `tools_sha256`, `ledger_effect_id` | before `Model.stream` (loop.ex:340) |
| `model_result` | `iteration`, `chunks` (the retained chunk list, in order: `text` deltas, `thinking` deltas, `tool_call`s, `reasoning_details`, `provider_metadata`, `usage`, `finish`), `duration_ms` | stream consumed |
| `tool_result` | `call_id`, `tool`, `ledger_ref`, `content` (the final `%{role: :tool}` message content — post hook-append, post LSP-append, i.e. exactly what entered `state.messages` at loop.ex:940-959), `is_error`, `duration_ms`, `output_bytes` | per tool, in dispatch order |
| `injected` | `origin` (`rule` \| `steer` \| `stop_hook` \| `checks` \| `session_start`), `content`, `after_call_id?` | any non-prompt user message appended mid-turn or at settle |
| `approval` | `request_id`, `call_id`, `question_sha256`, `decision`, `scope`, `actor`, `rule_id?`, `permission_entry_id?` | on answer/timeout/interrupt — the decision metadata; the resulting tool message is its own `tool_result`/`injected` record |
| `configure` | `key`, `value` | each applied `configure_one` (session.ex:996-1060) |
| `compaction` | `trigger` (`auto`\|`manual`\|`denied`), `summariser` (inline `model_call`+`model_result` pair for the `compact_N` call, session.ex:1637-1650), `elided` (`[{call_id, bytes}]`), `archive_id`, `pre_digest`, `post_digest` | `apply_compaction` |
| `rewind` | `to_turn`, `message_count` | conversation rewind |
| `turn_settled` | `turn_id`, `status` (`complete`\|`interrupted`\|`failed {reason}`), `message_count`, `conversation_digest` (the digest `Checkpoint.write` just computed — the journal↔checkpoint cross-link) | after `persist/1` in `settle/1` (loop.ex:2580-2589) |
| `gap` | `reason`, `dropped_kinds?` | first append after a write failure |
| `truncated` | `dropped_through_seq`, `prior_head` | budget enforcement (D5) |

Three deliberate consequences of this vocabulary, each answering a verified gap:

- **Thinking is retained.** Today `{:thinking, delta}` is emitted as an event and
  discarded (loop.ex:390-392). The journal is the first durable home for it.
- **Elision stops destroying evidence.** The journal's `tool_result` captured the
  content at dispatch time; compaction's in-place marker rewrite
  (`context/compaction.ex`) no longer erases the only copy. Replay renders what the
  model actually saw; `conversation.json` keeps its markers.
- **Timeout-shaped messages are recorded, not re-derived.** Every wall-clock-dependent
  message body the inventory found (tool timeout text, approval deadline text, subagent
  deadline text — loop.ex:1386-1400, 1463-1471, 2043-2050) is just content inside a
  recorded `tool_result`/`injected` record. Replay never re-races a timer.

### 3.3 The chain (D3)

`hash = sha256(prev || canonical_json(record minus prev/hash))`, `prev` of the first
record = 64 ASCII zeros — the same seed and canonical-JSON discipline as
`Encode.chain/1` (`encode.ex:15,152-165`), so one verification idiom serves both. The
chain is **stored** here because this file, unlike the ledger, is append-only and never
mutates or mid-evicts — the two properties whose absence makes a stored chain wrong
there. `Journal.verify/1` walks the file and answers
`{:ok, %{records, head, verified_through}}` or `{:error, {:chain_broken, seq}}`.

### 3.4 Budget (D4, D5)

The journal has its own byte budget (`:native_journal_budget_bytes`, default 64 MiB).
Past it, the **oldest whole turns** are dropped by rewriting the file once with a
`truncated` record at the head carrying `dropped_through_seq` and `prior_head` — the
chain restarts from the truncation record, and a verifier sees an explicit, signed-shape
statement of what is missing rather than a hole. This is the manifest's
dropped-is-a-recorded-state discipline (`checkpoint.ex:778-788`) applied to the journal.
Replay of a truncated session renders the surviving suffix and refuses the prefix by
name.

**Large payloads go to the blob store** (D5): any single record field over 256 KiB
(system prompts can reach ~1.6 MB via instruction files — `context/instructions.ex`
bounds) is stored as `{"blob": "<sha256>", "bytes": n}` in the existing
content-addressed `<session dir>/blobs/` store via `put_blob/2`, sharing its budget and
its honesty contract. Identical system prompts across turns dedup to one blob for free.
A dropped blob renders as a named marker on replay — degraded, stated, never silent.
Most records need none of this: tool results are already truncated upstream by the tools
themselves (`bash` inline 30 KiB, `read` 64 KiB — `tools/bash.ex:84-86`,
`tools/read.ex:32`).

### 3.5 Subagents

A child session journals **independently** under its own session dir (it is a full
session — `subagent.ex:548-573`). The parent's journal records the `agent` tool result
it actually received (which durably contains the child `task_id` — loop.ex:1924), and
the ledger link (`authority.constraints.subagent_parent`/`subagent_task_id`) already
crosses the two. Verified replay of a parent treats the `agent` tool result as a
recorded result like any other — the child is not re-run; it is verifiable separately.

## 4. Inference in the effect ledger

### 4.1 The kind (D6)

`:inference` joins `@ledger_only_effects` (`effect_ledger.ex:146`). The three-site rule,
named here because missing either map **crashes the ledger GenServer inside
`handle_call` via `Map.fetch!`** (`:611`, `:690`) and takes the core tree with it
(rest_for_one, `application.ex:131-135`):

- `@attempt_fields[:inference]` = `[:session_id, :turn_id, :iteration, :model,
  :provider, :prompt_sha256, :node]`. `prompt_sha256` is digested over the **ReqLLM
  context** — the wire request after `build_context/1`'s lossy projection
  (`req_llm.ex:126-145`) — not over `state.messages`, and it therefore covers the
  iteration-mutated system suffix (loop.ex:346-373) and the final-round empty tool list
  (loop.ex:375-379). Unvalidated string, the `operator_shell.command_digest` precedent.
- `@result_fields[:inference]` = `[:status, :duration_ms, :output_bytes, :journal_seq,
  :input_tokens, :output_tokens]`. `journal_seq` points at the `model_result` record —
  a pointer, preserving content-minimization exactly as the moduledoc demands.
- a `refine_result/3` clause and an inference status vocabulary
  (`:completed | :failed | :capacity_timeout | :stream_failed`), mirroring
  `@tool_call_statuses` discipline.

Correlation key across runs is `(session_id, turn_id, iteration)` in `attempt` — entry
ids embed nanosecond time by design (loop.ex:2277-2289) and must not be expected to
reproduce.

### 4.2 Call sites and gating

Three model-call sites, all gated: `call_model/2` (loop.ex:328-344), the compaction
summariser (session.ex:1637-1650, `turn_id` `"compact_N"` — already deterministic), and
`handoff_summary/1` (session.ex:1737-1750). Discipline is symmetric with tools:
`record_started` **before** `Model.stream`, and a ledger that cannot record the call
refuses it — the turn fails by name (`{:inference_unrecordable, reason}`) rather than
running a model call nobody can account for. `settle` after the stream is consumed,
best-effort like tool settles (loop.ex:2446). `authority` is the no-grant shape the
Permissions engine already writes (`%{decision:, reason:}` — `permissions.ex:501`
precedent). `cause.signal_type` is `"native.inference"` / `"native.subagent.inference"`
/ `"native.compaction.inference"`.

**Replay writes no ledger entries, ever.** Verified replay executes nothing; there is no
effect to account for. (This also sidesteps `same_attempt?/3` dedup against the original
run's entries — a hazard the exploration named explicitly.)

### 4.3 Version bump and surfaces

`@checkpoint_version` 1→2 with the `rollout/registry.ex:388-414` migration idiom:
`@upgradable_versions [1]`, struct-widening `struct(Entry, Map.from_struct(entry))`,
newer-refused. `@store_key` stays `{:ouroboros, :agent_effect_ledger, 1}` — bumping it
would hide old evidence behind an empty boot (`node_executor.ex:1201-1205` argues the
general case). Downstream, mechanically: the `ledger.list` effect enum
(`methods.ex:2572`), `mix ouroboros.gateway.golden` + `mix ouroboros.protocol.docs`
regeneration (both drift-locked by tests), and the retention arithmetic note — a fifth
kind present shifts the max-min quota to 1000/5; acceptable, because the ledger is the
authority record and the *journal* is the replay substrate.

## 5. Verified replay

### 5.1 The seams (D7)

Verified replay re-runs the real `Loop.run_turn` — the actual shipped decision code, not
a simulation — with every nondeterminism source substituted by the record:

- **Model**: `Ouroboros.Provider.Native.Replay.Model` implements the `Model` behaviour
  (`model.ex:76-84`) and streams the recorded `chunks` of the matching `model_result`.
  The seam is already clean: `Model.stream/3` is a pure dispatch on a module
  (`model.ex:99`), and the loop takes `state.model_module`.
- **Tools**: the `Loop` struct gains a `tool_source` field (default `:live`). In replay
  it returns the recorded `tool_result` content for `(call_id)` instead of dispatching —
  admission, hooks, sandbox, LSP, MCP, desktop are never invoked, because their outputs
  are already baked into the recorded content (the inventory's items 2.39–2.46 all land
  inside recorded messages). The ledger gate is bypassed with the same field (replay
  accounts for nothing because it executes nothing).
- **Control**: steers, interrupts, and approval answers are fed from the journal's
  `injected`/`approval` records at their recorded positions (`after_call_id`), replacing
  the mailbox races (`drain_control/1`, loop.ex:2490-2497) with the order that actually
  happened.
- **Hooks**: `state.hooks` is pre-set to the empty config, defeating the per-turn disk
  reload (`loop.ex:227` reloads only when `nil` — verified).
- **Compaction**: replayed as recorded (`compaction` record), never re-decided — the
  trigger arithmetic depends on provider-reported usage and the live `llm_db` window
  (session.ex:1379-1413, `window.ex:217-239`) and must not be re-derived.
- **Clock**: every emitted event re-carries the recorded `at` (D9). The projection reads
  no clock (`transcript_cells.rs:863-866`), so recorded instants are sufficient for
  byte-identity — including duration text like "turn complete · 1m 30s", which is
  computed from two payload instants.

### 5.2 The verdict

The engine (`Ouroboros.Provider.Native.Replay`) re-runs the recorded turns in order and
compares, per turn: the assembled message list against `turn_settled.conversation_digest`
(via the same canonical encoding `Checkpoint.digest/1` uses), and the emitted event
payloads against the record. Divergence is a named refusal —
`{:replay_diverged, %{seq:, turn_id:, field:, expected_sha256:, got_sha256:}}` — never a
best-effort continuation. A diverging replay means the code changed its derivation or
the record is inconsistent; both are findings, and the refusal says which record.

Above the engine verdict sits the projection assertion, reusing the corpus machinery:
the Elixir side projects both event streams through `Ouroboros.Web.Transcript.project/1`
and asserts equality; the Rust side does the same through `export::transcript`
(`tui/src/ui/export.rs:57` — "The same watch at the same width is the same bytes"),
constructible fully offline via `Watch::new` + `Watch::absorb`
(`transcript.rs:908,1095`).

### 5.3 Honest boundaries

- An `:ambiguous` inference entry (crash between started and settled) is a **hard replay
  boundary**: the journal shows how far the record reached; replay renders the settled
  prefix and refuses past it by name. The turn itself was already lost from
  `conversation.json` (previous-turn checkpoint semantics, session.ex crash story) — the
  journal may hold *more* than the conversation, and says so.
- A `gap` or `truncated` record bounds verification the same way.
- Sessions recorded before the journal existed have no journal: capability `false`,
  refusal `:no_journal`. No retrofit.

## 6. Fork: `to_turn` and `model`

`interactive.fork` ships (gateway `methods.ex:328,859-865,1646`; chain through
`fork_plan` → `Provider.session_fork_options` → `fork_start_options`
(`task.ex:2072-2095`) → native `seed_fork/4` (`session.ex:1094-1110`) which copies the
parent's message list into the child's own `conversation.json`; TUI `/fork` + backtrack
menu; caller-minted `fork_id` with outcome-unknown adoption). Two closed-envelope params
are added:

- **`to_turn`** — the `:turn_target` type `interactive.rewind` already validates
  (`fetch_rewind_target/2`, `methods.ex:2793-2799`), resolved by
  `Checkpoint.message_count_at/2` (`checkpoint.ex:550-562`, which already refuses a turn
  id from another session). `seed_fork` gains a truncation: copy, `Enum.take(messages,
  count)`, write. Both halves exist today; nothing composes them — this slice is the
  composition. Refusals mirror `Session.boundary/2`'s vocabulary: a `to_turn` below the
  child-visible floor (trim or summarising compaction moved it —
  `rewind_floor`/`offset` coordinates, checkpoint.ex:17-21) is
  `{:turn_boundary_dropped, to_turn}`, not a silent tail fork.
- **`model`** — optional string, threaded as an explicit override argument into
  `fork_start_options/4`, which today inherits `session.options` wholesale (verified: no
  seam). Applied as the child's `model` start option; the child's first `turn_started`
  journal record names it, which is what makes a fork-for-eval self-describing.

Standing limits, restated rather than solved here: a fork of a live session holding an
exclusive workspace lease is refused by the lease (`task.ex:1521-1523`); `worktree` is
not in fork's envelope (D7 of AGENT_EXPERIENCE remains deferred); vendor forks branch at
the tail only (Claude `--fork-session` semantics — `session.rs:1061-1067`), so `to_turn`
on a vendor session is refused as `{:unforkable_at_turn, provider}`.

Fork + journal compose into the eval loop: fork at the decision point, run the
challenger model live, and the two journals are directly comparable records — the corpus
`Rollout.Evaluation` never had.

## 7. Wire, CLI, badge

### 7.1 Gateway (D8)

Two verbs. Names avoid the verified collision (`interactive.replay` is the gap-repair
fetch, built by `Plane::method("replay")` — `model.rs:85`):

- **`interactive.journal`** — `:read`. Closed envelope `{id, node?, since_seq?,
  limit?}`; answers a window of journal records plus `{head, verified_through, records,
  truncated_through?}`. Read scope by the stated dividing line ("starts nothing" —
  `methods.ex:210-212` et al.): it reads one file. Windowing mirrors
  `interactive.replay`'s cursor discipline.
- **`interactive.replay_verify`** — `:operate`. `{id, node?}` → `{verified, turns,
  records, head, divergence: null | {…}}`. Operate because it starts a process — the
  `computer_use.status`/`probe` split is the exact precedent (`methods.ex:285-286`),
  even though it spends no tokens. Own timeout ceiling (long sessions re-derive many
  turns).

Both get `@params` entries, `@fixture_owners` placement, golden fixtures, and PROTOCOL
regeneration — all drift-locked by existing tests (`protocol_docs_test.exs:359-474`).

### 7.2 CLI

- **`ouro replay <session>`** — attaches read-scope (`remote_endpoint` precedent,
  `main.rs:2621-2673`), prints a provenance header from `interactive.journal` (records,
  chain head, verified-through, model calls with digests, truncation/gap notices), then
  the deterministic offline transcript: page events via the existing gap-repair verb,
  `Event::decode → Watch::absorb → export::transcript`. Two invocations at the same
  width are byte-identical. `--verify` additionally calls `interactive.replay_verify`
  and prints the verdict or the named divergence. `--json` emits `events_ndjson` +
  journal records for machine diffing.
- **`ouro fork <session> [--at <turn>] [--model <spec>]`** — client-minted `fork_id`
  before the call (`new_client_session_id` discipline, `main.rs:1992,427-429`),
  `interactive.fork` with the new params, prints the child id; outcome-unknown adoption
  identical to `ouro new`.

Both verbs follow the three-edit CLI pattern (`cli.rs` enum + `main.rs` arm + a
`replay_cli.rs` renderer taking `&Client` + `Write` sinks, the `ledger_cli.rs` shape).

### 7.3 Badge (D10)

`:replay` joins `@derived_capability_keys` (`provider.ex:71`, beside `:fork`/`:compact`)
— **explicit `false` for every non-native provider**, because the Rust client's
`Capability::offered()` treats absent as offered (`model.rs:610-612`); absence would lie.
Value for native: `true`, or `"degraded"` when the session's journal has gaps
(three-state, decoded like the existing capability enum). Surfaces: TUI rail badge via
the `worktree_badge` pattern (`sessions.rs:958-964`) and the conversation header; web
focused-pane vital beside Provider (`deck_live.ex:1783`). The web *rail row* badge is
deferred — `Rail.Row` carries no capabilities field (verified gap) and growing it is not
worth this slice; the parity map records the divergence.

## 8. Honest limits (v1, stated up front)

1. **Native sessions only.** Vendor sessions run their tool loops in vendor processes;
   nothing here can record or replay them. The badge says so per session.
2. **Verified replay proves derivation, not the world.** It proves the shipped loop
   re-derives the recorded conversation and events from the recorded effects — the
   determinism property. It does not prove the tools *would* return the same results
   today; that is what fork is for.
3. **Sessions predating the journal are not replayable.** No retrofit from
   `conversation.json` — it lacks too much (this document, §1).
4. **Blob-evicted content degrades to named markers** (screenshots, oversized prompts) —
   the existing staged-image contract (`req_llm.ex:499-509`) extended, never silent.
5. **Journal truncation bounds replay** — recorded, chained, refused by name.
6. **The journal is node-local**, like everything beside it. A session that lived on a
   dead machine replays only where its session dir is. Fleet-wide journal query rides
   the existing `:erpc` fan-out pattern if wanted later.
7. **Subagent verification is per-session**, linked, not transitive.

## 9. Acceptance

The slice is done when all of these hold live (not only in tests), on a real native
session that used tools, an approval, a steer, and one compaction:

1. **Recorded**: `journal.ndjson` chain verifies end-to-end; `ledger.list effect=inference`
   shows settled entries whose `journal_seq` pointers resolve; the `turn_settled`
   digests match `conversation.json`'s digest history.
2. **Rendered**: `ouro replay <id>` twice → byte-identical output; and equal to the live
   TUI's `export::transcript` of the same session at the same width.
3. **Verified**: `ouro replay --verify` → verified; flip one byte mid-journal →
   `{:chain_broken, seq}`; remove one record → `{:replay_diverged, …}` naming the seq.
4. **Crash-honest**: `kill -9` the runtime mid-turn; boot reconciles the inference entry
   to `:ambiguous`; `--verify` reports the intact prefix and the unsettled turn by name.
5. **Forked**: `ouro fork <id> --at <turn_2> --model <other>` → child seeded with the
   truncated prefix, `forked_from` set, first live turn on the substituted model, its
   journal's `turn_started` naming it; parent untouched.
6. **Elision-proof**: after compaction, `ouro replay` renders the pre-elision tool
   results while `conversation.json` holds markers.

## 10. Slices

Wave 1 (serial — one agent owns the loop/session/ledger seams):

- **R1 — journal + inference ledger + read verb** (Elixir). New
  `provider/native/journal.ex`; integration in `loop.ex` (model_call/model_result/
  tool_result/injected/approval records, `tool_source` + control-feed + hook-preset
  seams *defined but defaulting to live*), `session.ex` (session records, compaction,
  summariser + handoff gating), `effect_ledger.ex` (`:inference`, v2 migration),
  `methods.ex` (`interactive.journal`), golden + PROTOCOL regen. Gates: full Elixir
  suite (multiple seeds), golden byte-stable, `make protocol-docs` diff-clean.

Wave 2 (parallel, disjoint):

- **R2 — verify engine** (Elixir). `provider/native/replay/` (Model impl, engine,
  divergence vocabulary), `interactive.replay_verify`, corpus-grade projection-equality
  tests. Consumes R1's seams; does not edit `loop.ex`.
- **R3 — fork extensions** (Elixir). `to_turn` + `model` through `methods.ex` params /
  `task.ex` `fork_start_options` / native `seed_fork` truncation; refusal vocabulary;
  tests including the cross-session turn-id refusal.
- **R4 — client** (Rust only). `ouro replay` + `ouro fork` verbs, offline render,
  provenance header, `replay` capability decode + TUI badge; tests incl. the two
  fixture-accounting suites.

Integration (me): merge order R1 → (R2,R3,R4), `mix compile --force` before the first
post-merge run, full gates both toolchains, then the §9 live walk, then a docs honesty
pass recording any gap between this spec and what shipped.

## 11. As built (2026-08-30)

All four slices plus a seam-wiring follow-up are on `deploy`. Final gates: 2876 Elixir
tests / 40 cargo targets, both fully green, golden and PROTOCOL.md regenerated and
byte-stable, clippy/fmt clean.

### Spec corrections found during implementation (the spec above was wrong)

- **§3.2 `compaction.elided`** is `elided_count` (a count) — the compaction fold returns
  no per-call identity, and the pre-elision bytes live in the journal's own
  `tool_result` records anyway, which is the property §3.2 actually wanted.
- **§3.2 `injected.after_call_id`** does not exist — the journal is a total order and
  `seq` already fixes position.
- **§3.2 summariser inlining**: the compaction summariser's `model_call`/`model_result`
  pair are top-level records under `turn_id "compact_N"`, pointed at by the compaction
  record's `summariser_turn_id`, so the verify engine feeds every model call uniformly.
- **§7.1 `divergence: null | {…}`**: the reply is one object with a `kind`
  discriminator — `"diverged"` (field, expected/got digests) or `"boundary"` (reason,
  seq) — so a record honestly bounding verification is not dressed up as a mismatch.

### As-built decisions worth knowing

- **Gap intent survives the writer**: a failed append stages a sidecar
  (`journal.ndjson.gap`) so the `gap` record lands even when the loop process died.
- **`interactive.journal` routes through the native transport** (the `rewind_points`
  precedent); the verify engine reads the file directly, so a dead-transport session
  still verifies. A file-only read path for the *verb* is future work.
- **The ledger's `:inference` correlation key** is `(session_id, turn_id, iteration)`;
  `journal_seq` in the settled result points at the `model_result` record.
- **Verified-replay boundaries, by name**: `unsettled_turn` (crash mid-turn),
  `unstarted_turn` (a summariser/compaction group), `compaction` (the fold cannot be
  re-derived — the record carries digests, not the post-fold list), `forked` (a child's
  seeded prefix derives from the parent's journal, which the child's cannot rebuild;
  cross-journal verification via the recorded parent linkage is future work),
  `unreproducible_injection` (rules/hook text the record cannot re-derive), and
  attachment-bearing prompts. Approvals are inert under replay — recorded tools never
  ask.
- **Event-payload equality** is asserted by the parity tests (live stream vs replayed
  stream through both projections), not recomputed inside the engine; the engine
  compares prefix digests, request digests, and the per-turn conversation digest.
- **Timestamp granularity**: events re-emit the `at` of the record they derive from,
  which for delta events is coarser than the live instants. Closing it needs a per-event
  `at` in the record — a recording change, deliberately not made in v1.
- **Capability `replay`** is `true`/`false` only (the three-state `"degraded"` needs a
  per-session journal scan at list time — deferred); vendors get explicit `false`. The
  badge draws only on explicit `true`. Multimodal tool results replay with an exact
  *message* but a diverging `tool_result` *event* (live splits artifacts out) — surfaces
  as a named divergence, reconstruction deferred.

### What the live acceptance walk proved (§9, real daemon, real ollama models)

1. **Recorded** ✓ — chain 16/16 on a session with a structured tool call, two human
   approvals, and a mid-turn steer; settled `:inference` entries carrying model, turn,
   iteration, tokens, and resolving `journal_seq` pointers.
2. **Rendered** ✓ — `ouro replay` twice, byte-identical, provenance header + transcript.
3. **Verified** ✓ — the real tool+steer turn verified; one flipped byte →
   `chain_broken` at seq 8; one removed (re-chained) record → `DIVERGED
   request_sha256 at seq 9` with the expected/got pair.
4. **Crash-honest** ✓ — `kill -9` mid-stream: boot reconciled the inference entry to
   `:ambiguous` (`runtime_restarted_before_settlement`), the journal survived intact
   (per-record fsync), verify bounded at `unsettled_turn at seq 2`.
5. **Forked** ✓ — `ouro fork --at 1 --model …`: child seeded with the truncated prefix,
   `forked_from` set, substituted model named in the child's own `turn_started`; parent
   untouched. (Found live and fixed: the CLI sent ordinals as strings; the runtime
   types them as integers.)
6. **Elision-proof** ◐ — proven at the suite level (journal `tool_result` records carry
   pre-elision content); the live session was too small to trigger a real fold, and
   manual compaction was honestly a no-op below thresholds.

Small-model note for future walks: qwen2.5-coder:1.5b emits tool calls as *text JSON*
even when handed a tools array (confirmed against ollama directly) — use llama3.2:3b or
larger for a tool-calling live session.
