# Ouroboros Web on the wire — the transport migration spec

Status: **specification only. Nothing here is built, and this document does not claim the
work should start now.** Written 2026-08-30 against the `deploy` branch at `5d9bbda`;
every `file:line` claim was checked in that tree. Facts about code carry citations,
proposals carry decision numbers (W1–W13), and anything unverified says so in §9.

The question this document answers is narrow and deliberately not the big one. It is
**not** "should the runtime become a daemon that clients talk to over a socket." It is:
*what would it cost to put the web surface on the wire protocol, and what does paying that
cost buy that keeps the daemon question answerable later?* The daemon question is a
strategy decision that wants evidence; this is the slice that would produce some.

`docs/WEB.md` is the record of the decision that built the surface a week ago. This
document supersedes three parts of it and leaves the rest standing — §0.1 says exactly
which, so that nobody has to diff two specs to find out.

## 0. What this is, in five sentences

The web surface reaches the runtime by calling the gateway's method table in-process
(`lib/ouroboros/web/call.ex:73-87`) and receives events as raw BEAM messages sent to the
LiveView's own pid (`lib/ouroboros/web/live/deck_live.ex:394-398`), which is why it is fast,
why it has no backpressure, and why it is not a client of anything. The wire protocol next
to it — line-framed JSON-RPC over loopback TCP (`lib/ouroboros/gateway/listener.ex:145-146`)
— has the bounded outbound queue and the `stream.lagged` protocol the in-process path
lacks (`lib/ouroboros/gateway/conn.ex:849-913`), and a browser cannot speak it because the
gateway has no HTTP or WebSocket transport; that was filed as roadmap item **H4** and is
still `pending` (`docs/AGENT_EXPERIENCE.md:162`, `:863`). The option-preserving move is to
grow that transport and let the existing LiveView become a client of it, which retires
`Web.Call` and the pid subscription while keeping Phoenix, `Phoenix.LiveViewTest`, and the
transcript parity lock — the three things the GPUI deletion was paid for. The alternative
that deletes Phoenix and puts a JS client in the browser retires more code but re-incurs
the exact cost the GPUI removal just bought out: a surface with no headless test story, in
a third toolchain, in a repository that already carries 403 lines of untested JavaScript
it has flagged as an open risk (`docs/WEB.md:673-690`). The transport itself is worth
building under every option including doing nothing else, so §3 specs it as a standalone
slice.

### 0.1 What this supersedes in `docs/WEB.md`

| `WEB.md` | Status after this document |
|---|---|
| **D2, "One authorization surface"** (§2, `WEB.md:131-158`) | **Mechanism superseded, principle kept.** The rule "the web consults the gateway's table and never a plane" survives verbatim. What changes under W1 is that the consultation becomes a request over a socket instead of a function call, and `Ouroboros.Web.Call` — the module that exists to write that call once — is deleted rather than refactored. |
| **D9, §8 "Streaming, resync, and backpressure"** (`WEB.md:435-473`) | **Superseded under W1.** Its central sentence — "In-process removes the lag protocol but not the algorithm" (`WEB.md:453`) — becomes false: the lag protocol comes back, because the `Conn`'s queue is what the browser would be behind. The resync *algorithm* is unchanged and `Ouroboros.Web.Watch` is untouched. |
| **§11's open risk, "Mailbox growth on wedged views"** (`WEB.md:658-667`) | **Closed by construction under W1**, and only there. Under W3 (status quo) it stays open and C0 is the minimum honest answer to it. |
| **§1's "In-process data is uncapped"** (`WEB.md:63-67`) | **Still true today, and ceases to describe the web under W1.** This is the largest behavioural change in the migration and §6.3 is about nothing else. |
| Everything else — D1, D3, D4, D5, D6, D7, D8, D10–D14, §4's parity map, §10's removal record | **Stands unchanged.** |

## 1. Verified ground

### 1.1 The coupling today

- **Every operator verb is an in-process function call.** `Ouroboros.Web.Call.call/4` runs
  `Methods.fetch/1`, `Methods.permits?/2`, then `Methods.invoke/2` inside a supervised
  task awaited with the table's own timeout (`call.ex:73-87`, `:105-117`). It is the same
  three functions the `Conn` uses (`conn.ex:530-533`, `:936-939`), which is exactly what
  the module was designed to be (`call.ex:11-21`). 180 lines.
- **The feature gate is a direct table read, not a handshake.** `Call.available?/2`
  (`call.ex:98-103`) answers "does this build serve this method at this scope" — and its
  own docstring names the reason it exists: it is "the same question `hello` answers for a
  terminal client, asked directly because there is no handshake between a LiveView and the
  table it reads" (`call.ex:93-95`).
- **The LiveView subscribes as a process.** `DeckLive` calls
  `Methods.subscribe(plane, ref, cursor)` from its own process (`deck_live.ex:600-604`)
  because "Both planes register `self()` and monitor it" (`deck_live.ex:10-17`). Events
  arrive as raw messages, `{:ouroboros_interactive_event, id, %Event{}}` and its coding
  twin (`deck_live.ex:394-398`).
- **The plane sends to subscriber pids unconditionally.** After the durable checkpoint
  succeeds, `persist/3` fans every event out to every registered subscriber with a bare
  `send/2` — no queue check, no counter, no cap (`lib/ouroboros/interactive/task.ex:2268-2273`).
- **A terminal session answers the backlog and declines the registration.**
  `handle_call({:subscribe, …})` returns the backlog either way but only calls
  `put_subscriber/2` when the session is not terminal (`interactive/task.ex:143-156`,
  the branch at `:147-149`). This is why `DeckLive` checks terminality immediately after
  the backlog arrives (`deck_live.ex:637-642`).
- **Stream death is learned by monitoring the coordinator.** `Methods.coordinator/2` plus
  `Process.monitor/1` (`deck_live.ex:647-654`); the `:DOWN` routes into the one repair
  (`deck_live.ex:406-408`).
- **There is one repair and it is the TUI's, minus one round.** `subscribe(cursor)` where
  the cursor is the contiguous high-water mark `Ouroboros.Web.Watch` maintains
  (`deck_live.ex:564-633`, `lib/ouroboros/web/watch.ex:9-44`). The TUI's replay loop is
  absent because in-process `subscription_events/2` returns every retained event above the
  cursor in one call (`deck_live.ex:30-38`).
- **Drawing is coalesced at 80 ms; absorbing is not** (`deck_live.ex:113-114`, `:676-693`).
- **Auth today is a one-shot token→cookie exchange.** `GET /auth?token=…` compares
  `:crypto.hash_equals/2` over SHA-256 digests and mints a renewed, signed, `HttpOnly`,
  `SameSite=Lax` session cookie, then 302s to `/` (`lib/ouroboros/web/auth.ex:105-122`,
  `:70-77`). Every failure renders one identical page (`auth.ex:135-141`). The LiveView
  socket is refused at the *handshake* on that cookie, not at the mount, because
  `plug :socket_dispatch` runs before `Plug.Session`
  (`lib/ouroboros/web/live_socket.ex:1-42`).
- **Exposure has the gateway's refusal, implemented in both layers.** A non-loopback
  `OUROBOROS_WEB_BIND` refuses the boot without `OUROBOROS_WEB_ALLOW_REMOTE=1`
  (`lib/ouroboros/web/config.ex:17-19`, `:241-257`), and `config/runtime.exs` re-checks it
  (`web/config.ex:24`). `check_origin` is never `false`
  (`lib/ouroboros/web/endpoint.ex:32`, `:158`, `:256-257`).

### 1.2 The wire today

- **One transport, and it is TCP.** `:gen_tcp.listen/2` with `packet: :line` and
  `packet_size: config.max_frame` (`listener.ex:142-146`, `:162`). Nothing else binds.
- **`hello` is the only thing that grants anything** (`conn.ex:8`). Every frame before it
  is refused and closes the connection (`conn.ex:519-527`); `hello` authenticates on a
  token digest (`conn.ex:622-633`), pins `@protocol 1` (`conn.ex:105`, `:635-640`), and
  answers `server`, `node`, `role`, `protocol`, `scope`, and `methods` from
  `Methods.names/0` (`conn.ex:649-658`).
- **Scope is the listener's, fixed at boot** (`conn.ex:532`, refusal text at `:540-541`).
- **Bounded everything.** `@max_in_flight 8`, `@max_pending 64`, `@max_subscriptions 64`
  (`conn.ex:106`, `:112`, `:122`); `queue_limit` default 1,000 outbound frames and
  `max_frame` default 1 MiB (`lib/ouroboros/gateway/config.ex:140-141`); the connection
  cap is `@max_connections 64` enforced as a `DynamicSupervisor` `max_children`
  (`lib/ouroboros/gateway.ex:54-56`, `:78-79`), refused at `listener.ex:372-373`.
- **The lag protocol.** Over `queue_limit`, an event is dropped and counted rather than
  queued (`conn.ex:849-850`, `:860-874`); once the queue drains below half, one
  `stream.lagged` per lagged session carries `dropped` and `last_sequence`
  (`conn.ex:876-913`). `stream.ended` is the other stream terminator (`conn.ex:808`).
  The Rust client decodes both (`tui/src/model.rs:1566`, `:1579`).
- **Six methods are connection-answered**, not dispatched: `hello`, the four
  subscribe/unsubscribe verbs, and `runtime.shutdown` (`conn.ex:143-149`).
- **The `subscribe` backlog is not count-capped on the wire.** `open_subscription/5`
  answers with whatever `Methods.subscribe/3` returned (`conn.ex:705-711`) — the same call
  the LiveView makes. The `@replay_limit 500` bound belongs to `*.replay`
  (`lib/ouroboros/gateway/methods.ex:142`, `:635`), not to `subscribe`.
- **H4 is the roadmap trace.** `| H4 | pending | HTTP/SSE |`
  (`docs/AGENT_EXPERIENCE.md:162`); scoped as "**H4 HTTP/SSE bridge** — `ouro serve --http`
  for web clients and an OpenCode-style SDK shape", size M, Phase 4, and with its
  Acceptance column left as `—` (`AGENT_EXPERIENCE.md:863`); scheduled in Phase 4
  (`:912`); and §11 Deferred names "a web dashboard and phone surface beyond what ACP
  clients and H4 provide" (`:1010`). So the transport has a roadmap slot, no acceptance
  criteria, and no owner.
- **The WebSocket dependencies are already resolved.** `websock` 0.5.3 and
  `websock_adapter` 0.6.0 are in the lockfile, pulled by `bandit` 1.12.5 and `phoenix`
  1.8.13 (`mix.lock:3`, `:34`, `:52-53`). A WebSocket transport adds **no new dependency**
  whether or not Phoenix stays.

### 1.3 The byte-cap asymmetry — the one that decides §6.3

- **The caps live in exactly one place and apply to exactly two structs.**
  `Gateway.Wire.walk/3` byte-caps the `payload` of `%InteractiveEvent{}` and
  `%CodingEvent{}` and nothing else, and its own comment says why this is the one place:
  the cap must cover "a live notification, a `replay` result, or a `subscribe` backlog"
  alike (`lib/ouroboros/gateway/wire.ex:169-175`, `:237-242`).
- **The numbers.** `event_leaf_bytes` 128 KiB per string leaf, `event_payload_bytes`
  512 KiB per event across all its leaves, `detail_leaf_bytes` 4 MiB for
  `*.event_detail`'s override (`config.ex:56-60`, `:142-144`). The per-event budget is
  restored between events; the *node* budget is not — `@max_nodes 50_000` is per encode
  (`wire.ex:93`, `:234-236`).
- **Only leaves over 512 bytes can ever become markers.** `@keep_whole 512` and the
  `size <= max(cap, @keep_whole)` arm mean a short string survives even after the payload
  budget is fully spent (`wire.ex:97-100`, `:255-256`, `leaf_cap/1` at `:272`).
- **Four marker shapes exist**: `%{"_excerpt" => prefix, "_bytes" => size}` for an
  over-cap UTF-8 string, `%{"_b64" => …, "_bytes" => …}` for an over-cap binary
  (`wire.ex:257-264`), `%{"_opaque" => …}` for a pid/port/ref/function (`wire.ex:156-159`),
  and `@truncated` past depth 32 or once the node budget is exhausted
  (`wire.ex:92`, `:144-145`).
- **The web already speaks that vocabulary — in four places out of many.**
  `Ouroboros.Web.Presentation.wire_marker/1` renders all four as short labels and cites
  the Rust original it was ported from (`lib/ouroboros/web/presentation.ex:1588-1622`);
  `leaf_text/1` is the string-or-marker reader (`presentation.ex:1624-1627`). It is
  reached from `presentation.ex:1130` (plan-step content), `:1192`, `:1292-1302` (shell
  `output_excerpt`, with a comment naming the gateway's substitution), and from
  `lib/ouroboros/web/transcript/tools.ex:307`, `:436`, `:476`, `:532`. **Every other leaf
  read in the projection is a plain-string read** — for instance the text of
  `output_text_delta` / `output_text_final` (`presentation.ex:778-783`).
- **And the in-process path deliberately produces none of them.**
  `Presentation.payload_of/1` runs `wire_shape/1` (`presentation.ex:936-941`), which is
  documented as "the atom-flattening `Ouroboros.Gateway.Wire` does on the way out, applied
  in-process … and nothing else the wire does — **no byte caps, no `_opaque` minting, no
  struct tagging**" (`presentation.ex:943-950`, implementation `:952-961`).

That pairing is the whole of §6.3: the marker-reading code is present, correct, and today
almost entirely unreachable on the web path.

### 1.4 The projection implementations and the parity lock

**It is two implementations of a two-stage pipeline, not four projections.** The framing
matters, because "four implementations" makes retirement sound like it removes three
things when it removes at most two:

| Stage | Rust | Elixir |
|---|---|---|
| Presentation | `PresentationEvent::from_event` — `tui/src/model/transcript.rs:361` | `Ouroboros.Web.Presentation.from_event/1` — `lib/ouroboros/web/presentation.ex:771` |
| Projection | `project()` — `tui/src/ui/transcript_cells.rs:846` | `Ouroboros.Web.Transcript.project/1` — `lib/ouroboros/web/transcript.ex:272` |

Sizes: `transcript_cells.rs` 7,052 lines, `model/transcript.rs` 2,031;
`presentation.ex` 2,230, `transcript.ex` 1,356. The whole `lib/ouroboros/web/` tree is
14,836 lines across 31 files.

**The corpus is 69 fixtures, not 67** — verified by hand: `test/support/gateway_golden/`
holds 69 `.json` files, 46 of them `event_*` (the transcript corpus) and 23 protocol
fixtures. The Elixir lister is `fixtures/0` at
`lib/mix/tasks/ouroboros.gateway.golden.ex:120`, returning
`protocol_fixtures() ++ transcript_fixtures()` (`:124` and `:603`, built from
`transcript_corpus` at `:186`). The Rust accounting test is
**`tui/src/model.rs:3894`**, `every_golden_fixture_is_accounted_for` — an inline
`#[cfg(test)]` function, *not* a file under `tui/tests/`; it spells all 69 names in a
literal `vec![]` (`:3915-3985`).

**The parity lock, both halves.** `test/ouroboros/web/corpus_parity_test.exs` (1,025
lines, 48 tests in 12 `describe` blocks) and `tui/tests/presentation_corpus.rs` (1,315
lines, 47 tests). Each runs the same fixture bytes through its own two stages and asserts
the same string literals; the Elixir side states the direction of the contract explicitly
— "The Rust literals are the contract and this side conforms"
(`corpus_parity_test.exs:17-18`). Both carry a corpus-completeness test that hardcodes the
same 46 transcript names and globs the directory to prove nothing was added silently
(`corpus_parity_test.exs:932-988`; `presentation_corpus.rs:1231-1295`). The Elixir side
has one test the Rust side cannot have: `wire_shape` as the identity over an
already-encoded payload, iterating all 69 fixtures (`corpus_parity_test.exs:1009-1010`) —
which is the in-process/wire equivalence §6.3 depends on, asserted today.

**The resync algorithm has four copies, not three**, and one of them is already in Elixir:

- `tui/src/ui/transcript.rs:1095` `absorb`, with `has_gap` at `:1087` and `cursor` at
  `:1057` — state only; the drive loop is a fifth file,
  `tui/src/ui/app/streaming.rs:306-336` (the `resyncing` guard, `MAX_RESYNC_ROUNDS`, and
  the subscribe-vs-replay branch).
- `tui/src/run.rs:1266` `absorb`, paired with `offer` at `:1142`.
- `tui/src/acp_serve.rs:1419` `absorb`, paired with `offer` at `:1278` — whose doc comment
  is byte-identical to `run.rs:1141`.
- **`lib/ouroboros/web/watch.ex`** (295 lines), whose moduledoc opens "Port of
  `tui/src/ui/transcript.rs:1-31`" (`watch.ex:5`) and reproduces the same reasoning;
  `has_gap?/1` at `:124`.

That they are one algorithm is confirmed by shared constants: `REPLAY_LIMIT: u64 = 500`
(`run.rs:76`, `acp_serve.rs:100`), `MAX_RESYNC_ROUNDS: u32 = 40` (`run.rs:80`,
`acp_serve.rs:103`), `MAX_PENDING: usize = 10_000` (`run.rs:106`, `acp_serve.rs:106`).
`WEB.md:93-95` calls the repetition "the established pattern, not a smell" — which was a
statement about three copies and is now a statement about four.

**A live citation drift found while verifying this section**, worth fixing whatever else
happens: `lib/ouroboros/web/transcript.ex:5` cites `tui/src/ui/transcript_cells.rs:841` as
the `project()` it ports. `project` is at `:846`; line 841 is
`turn_id: Option<String>`, a field of `struct PendingThinking`. `transcript.ex:6` likewise
cites `ui/transcript.rs:1237` for `Watch::entries`, which is at `:1239`. Both verified by
hand. In a codebase whose cross-language seam is held together by citations, a citation
that has drifted onto an unrelated struct field is the failure mode to care about.

**Dependencies** (`mix.exs`): `{:phoenix, "~> 1.8"}` `:138`,
`{:phoenix_live_view, "~> 1.2"}` `:139`, `{:phoenix_html, "~> 4.3"}` `:140`,
`{:bandit, "~> 1.12"}` `:143`, `{:earmark, "~> 1.4"}` `:149`, and
`{:lazy_html, ">= 0.1.0", only: :test}` `:162`. Five runtime, one test-only. No `:plug`,
`:jason`, `:websock_adapter`, `:esbuild`, or `:tailwind` is declared directly.
`priv/static/web/app.js` is 403 lines; `app.css` is 2,244; the two Phoenix bundles beside
them are copied from `deps/`, not built (`@web_assets`, `mix.exs:47-51`).

## 2. The options

### W1 — Option A: LiveView stays and speaks the wire

The gateway grows a WebSocket transport (§3). `Ouroboros.Web.Call` is deleted; every
operator verb becomes a JSON-RPC request over a loopback WebSocket. The pid subscription
is deleted; events arrive as notification frames the client process forwards to the
LiveView. Phoenix, LiveView, `Phoenix.LiveViewTest`, `Web.Presentation`, `Web.Transcript`,
`Web.Watch`, and the parity corpus all stay exactly as they are.

**What it retires** (each line is a deletion, not a rewrite):

| Retired | Citation | Replaced by |
|---|---|---|
| `lib/ouroboros/web/call.ex`, whole module, 180 lines | `call.ex:1-180` | a request over the wire, answered by `Conn`'s existing dispatch (`conn.ex:529-557`) |
| `Call.available?/2`, the feature gate | `call.ex:98-103` | the `methods` list `hello` already returns (`conn.ex:656`) — the substitution `call.ex:93-95` itself names |
| the raw-message `handle_info` clauses | `deck_live.ex:394-398` | `interactive.event` / `coding.event` notification frames |
| `Presentation.wire_shape/1` and its call site | `presentation.ex:936-961` | the wire, which does the flattening for real |
| the coordinator monitor | `deck_live.ex:644-661` | `stream.ended` (`conn.ex:808`) |
| the in-process/wire divergence as a category | — | one encoder, one shape, one set of caps |

**What it costs.** A new transport in the gateway and a new wire client in Elixir — the
first Elixir client of a protocol Elixir has only ever served. A localhost WebSocket hop
per operator verb, on top of LiveView's own browser round trip; unmeasured (§9). The byte
caps start applying to the browser, which is §6.3 and is the largest single piece of work
in the migration. And the surface gains a failure mode it does not have today: the
transport can be down while the runtime is up.

**What it buys.** The backpressure gap closes by construction — the browser sits behind
the `Conn`'s bounded queue and gets `stream.lagged` like every other client
(`conn.ex:849-913`), and `WEB.md`'s one unclosed risk (`WEB.md:658-667`) stops being a
risk rather than staying a promise. The web becomes a *client*, which is the only thing
that makes the daemon question answerable by measurement. And it does all of that without
touching the week-old LiveView decision: the headless test story is `Phoenix.LiveViewTest`
before and after.

### W2 — Option B: a browser-side client

A JS/TS SPA served statically by the daemon, speaking JSON-RPC over the same WebSocket.
Phoenix, `phoenix_live_view`, `phoenix_html`, and Earmark leave `mix.exs`. The Elixir
presentation and projection are deleted and rewritten in TypeScript. `bandit` **stays** —
something has to serve the static files and terminate the WebSocket (`mix.lock:3`).

**What it retires.** Everything Option A retires, plus `presentation.ex` (2,230 lines),
`transcript.ex` (1,356), `watch.ex` (295) — the Elixir copy of the resync algorithm —
`transcript/`, `live/`, `layouts.ex`, `markdown.ex`, `router.ex`, `live_socket.ex`,
`status_live.ex`, `error_html.ex`, the Elixir half of the parity lock
(`corpus_parity_test.exs`, 1,025 lines, 48 tests), and four of the five runtime web deps
(`mix.exs:138-140`, `:149`; `bandit` at `:143` stays). Call it roughly 9,000 of the web
tree's 14,836 lines. `config.ex`, `publication.ex`, `auth.ex`, and `artifact_controller.ex`
survive in reshaped form.

**What it does not retire, contrary to the framing.** The projection does not go away; it
moves — Rust keeps `transcript_cells.rs:846` and `model/transcript.rs:361`, and TypeScript
gains a port of both, so the count of implementations is unchanged at two. The 69-fixture
corpus does not retire either: it has to be re-pointed at a TypeScript projection, which
means a JavaScript test runner in CI, which is a **third toolchain** in a repository that
today builds with `cargo` and `mix` and nothing else. And the resync algorithm's copy count
goes from four to four — `watch.ex` dies, a TypeScript watch is born.

**The cost that decides it.** The GPUI desktop was deleted seven days ago, and the first
reason given was that it had **no headless test story** — "Nothing here has been verified
by eye" (`WEB.md:26-36`, quoting `docs/DESKTOP.md:189-192`) — while
"`Phoenix.LiveViewTest` is fully headless, which changes the economics of every future
surface slice" (`WEB.md:35-36`). Option B's honest answer to "what is the headless test
story now" would have to be a real one: a Node/Bun test runner for the TS projection
against the corpus, plus a headless browser (Playwright) in CI for the surface itself,
plus the CI time and flake budget both carry. That is a defensible answer — it is what
most teams do — but it is **new** infrastructure, and this repository has already declined
to add a JavaScript toolchain once, on purpose (`WEB.md:258-260`), and is already paying
for that: `app.js` is ~380 lines, "the suite executes none of it", and W8 recorded that it
"did neither" of the two honest options rather than choosing one (`WEB.md:673-690`).
Option B multiplies that untested surface by roughly an order of magnitude and asks the
same team to build the harness it declined to build when the file was fifty lines.
(`priv/static/web/app.js` is 403 lines today; `WEB.md:673` rounds it to ~380.)

There is a genuine case for B — a browser client over a documented protocol is what an
external SDK consumer would use, and it is the shape H4 gestures at
(`AGENT_EXPERIENCE.md:863`, "an OpenCode-style SDK shape"). It is not a case that should be
made seven days after the opposite decision, on a surface whose acceptance checklist has
not yet been walked once end to end (`WEB.md:601-608`).

### W3 — Option C: status quo, with the in-process gaps fixed

Keep `Web.Call` and the pid subscription. Close the backpressure gap the way `WEB.md:456-464`
specifies: a bounded subscription window, deltas coalesced (both already built), plus the
one thing that was specified and never built — a `Process.info(:message_queue_len)`
self-check that kills a wedged view and lets the remount resync it.

**What it retires.** Nothing. It is a bug fix with a decision number.

**What it costs.** Very little: `Watch` already holds `@window 2_000` and raises the floor
on trim (`watch.ex:61-62`, `:184-196`), so the missing piece is the self-check and a load
test that proves the mailbox can actually grow.

**What it does not buy.** Nothing moves toward the daemon question. The web stays the one
surface that is not a client, the in-process shape stays divergent from the wire shape,
and `Presentation`'s marker vocabulary stays mostly dead code.

### W4 — Recommendation

**Option A, with the transport (§3) built first and separately, and C0 taken now
regardless of whether A is ever started.**

The reasoning, in the order it matters:

1. **A does not relitigate the LiveView decision; it is orthogonal to it.** Everything
   `WEB.md:20-36` argued for — headless tests, browser reachability, one shared
   authorization decision, the whole client-connection defect class collapsing into
   refresh semantics — is untouched by which side of a socket the LiveView sits on. That
   is the strongest thing about A and the reason it is bounded: the decision it changes is
   *transport*, and the decision it preserves is *surface*.
2. **A closes the one risk the last wave admitted it left open.** `WEB.md:660-667` is
   unusually plain about this: "This is the one risk in this list that a slice was supposed
   to close and did not." Under A the fix is not a new mechanism — it is the mechanism the
   `Conn` has had all along (`conn.ex:849-913`).
3. **B pays a bill that was just settled.** See W2. The objection is not that a browser
   client is wrong; it is that seven days is not long enough to have learned anything that
   would justify reversing, and the thing that would justify it — an external consumer of
   the protocol — does not exist yet and would be served by §3 alone.
4. **C is not an alternative to A; it is insurance while A is unbuilt.** If the answer to
   "should we start this now" is no, C's self-check is still the honest response to a risk
   this project has already written down twice. It is a handful of lines and it should not
   wait on a strategy decision.
5. **The sequencing is what makes A reversible.** §3 is valuable standing alone; §4's T1
   and T2 produce a working second transport and a working client with the web untouched.
   If the migration is then judged not worth it, nothing has to be undone — the transport
   is H4, delivered.

**What would change this recommendation.** A measured latency cost that makes the browser
feel worse (§9). A decision to ship an external SDK, which makes B's toolchain cost
something the project was going to pay anyway. Or a decision that the daemon question is
settled as "no" — in which case C is the whole answer and §3 is optional.

## 3. The transport (W5–W13)

Specified to be built and judged on its own. Nothing in this section presumes the web
migrates; a terminal client, an ACP bridge, an external SDK, or nothing at all may be its
only consumer.

### W5 — Where it lives: beside the listener, not inside Phoenix

A new `Ouroboros.Gateway.Ws` child in the gateway's own supervision tree
(`lib/ouroboros/gateway.ex:76-79`), running its own `Bandit` instance on its own port,
whose Plug serves exactly one path and upgrades it to a WebSocket via `websock_adapter`.
Both are already resolved dependencies (`mix.lock:3`, `:52-53`), so this adds nothing to
`mix.exs`.

The rejected alternative is a `/rpc` path on the existing Phoenix endpoint
(`lib/ouroboros/web/endpoint.ex:95`), which is fewer moving parts and one less bound port.
It is rejected for one reason: it would make the wire transport depend on Phoenix, and the
entire point of this document is to keep W1 and W2 both reachable. A transport that dies
with `phoenix_live_view` prejudges the question it exists to keep open.

The connection process is `Ouroboros.Gateway.Conn` **unchanged in role**: it already owns
framing, the handshake, dispatch, subscriptions, and the outbound queue, and none of that
is TCP-specific except the socket calls. W5's implementation shape is a socket-transport
seam behind `Conn` — not a second `Conn`. A second connection implementation is the thing
this slice must not produce, because the lag protocol, the caps, and the audit line would
then exist twice.

### W6 — Framing

One JSON-RPC object per WebSocket **text** frame. WebSocket frames the message, so the
trailing newline `Wire.frame!/1` appends (`wire.ex:142`) is not used on this transport;
`Wire.to_json/2` is, unchanged, because it is where the caps live.

`max_frame` (`config.ex:140`, default 1 MiB, `OUROBOROS_GATEWAY_MAX_FRAME`) becomes the
WebSocket maximum frame size, inbound. Same constant, same variable, same refusal text
(`conn.ex:427`). Binary frames are refused; a client that sends one is closed with the
same discipline as an oversized frame.

### W7 — Authentication: one credential path per connection

Two credentials already exist and each is right for a different caller. The rule is that a
connection has exactly one of them, decided at the handshake.

- **Browser: the session cookie, checked at the upgrade.** This is `LiveSocket.connect/3`'s
  discipline applied to a second socket (`live_socket.ex:32-38`), and its reasoning
  transfers exactly: a token cannot stop a stranger from *holding* a socket, and a
  handshake refusal can. The cookie is the one `Web.Auth` mints (`auth.ex:105-122`) and is
  read with the same `Auth.session_key/0` so the two cannot disagree (`auth.ex:79-86`).
  The token→cookie exchange is unchanged and remains the only place the token appears in a
  URL (`auth.ex:5-12`).
- **Everything else: `hello` with the gateway token**, byte for byte as the TCP transport
  does it (`conn.ex:581-633`).
- **The invariant:** a connection authenticated at the handshake **refuses** a `hello`
  carrying a `token` (`invalid_params`, naming the reason); a connection not authenticated
  at the handshake **requires** one and refuses every other frame until it arrives
  (`conn.ex:519-527`). One credential per connection, decided once, never merged.

Rejected: a short-lived signed exchange ticket minted by an authenticated HTTP route and
presented in `hello`. It is more machinery for the same guarantee and it puts a bearer
credential back somewhere a URL can carry it — the precise thing `auth.ex:5-12` exists to
prevent. Keep it named as the fallback for a future caller that cannot send a cookie
(a cross-origin embed, a native client that will not hold the gateway token).

### W8 — Origin checking is not optional here

A cookie-authenticated WebSocket is a CSRF target, and `SameSite=Lax` does not reliably
cover WebSocket upgrades. So the upgrade **must** check the `Origin` header against the
same computed allowlist the Phoenix endpoint uses — `check_origin` is never `false`
(`endpoint.ex:32`, `:256-257`), computed from the bound address and port, overridable by
`OUROBOROS_WEB_ORIGIN` for proxied setups (`WEB.md:185-186`).

Token-authenticated connections carry no ambient credential and are not subject to it; a
missing `Origin` is therefore accepted **only** on the token path and refused on the
cookie path. Stating it this way rather than "check Origin" is deliberate: the rule has to
be a property of which credential is in play, or a non-browser client with no `Origin`
header becomes unable to connect.

### W9 — Scope

One scope per transport instance, fixed at boot, exactly as the listener has it
(`conn.ex:532`). `OUROBOROS_GATEWAY_WS_SCOPE`, defaulting to the TCP listener's scope. No
per-connection and no per-session narrowing, which is `WEB.md`'s D3 unchanged.

**Open, and it is a real config-surface question** (§9): if the web later migrates,
`OUROBOROS_WEB_SCOPE` and `OUROBOROS_GATEWAY_WS_SCOPE` describe the same thing for the
same caller, and the two must converge rather than silently disagree. The dangerous
combination is the one the explicit branch already produces — `OUROBOROS_WEB_SCOPE`
defaulting to `read` while `OUROBOROS_GATEWAY_SCOPE` is `operate`
(`WEB.md:224-233`) — because a browser that reached `operate` through a WS transport whose
scope came from the gateway would silently gain authority its own configuration denied it.
Whichever way it resolves, it resolves **before** W1, not during it.

### W10 — `hello` and the methods gate carry over unchanged

`hello_result/1` already answers everything a browser needs to gate its controls:
`server`, `node`, `role`, `protocol`, `scope`, `methods` (`conn.ex:649-658`). Under W1
this is what replaces `Call.available?/2` (`call.ex:98-103`) — and the replacement is not
a new mechanism but the one that module's own docstring says it is standing in for
(`call.ex:93-95`). `@protocol 1` and the mismatch refusal are unchanged
(`conn.ex:105`, `:610-618`).

### W11 — Lag, caps, and subscription bounds map over without modification

Everything in this list is a property of the `Conn`'s state, not of TCP, and carries over
by leaving it alone:

- `queue_limit` and the drop-and-count path (`conn.ex:849-850`, `:860-874`);
  `stream.lagged` at the low-water mark (`conn.ex:876-913`); `stream.ended`
  (`conn.ex:808`). Both are already decoded by a client in this repository
  (`tui/src/model.rs:1566`, `:1579`).
- `@max_subscriptions 64`, `@max_in_flight 8`, `@max_pending 64`, `@response_headroom`
  (`conn.ex:106`, `:112`, `:117`, `:122`), and the cross-owner duplicate refusal
  (`conn.ex:684-694`).
- `@max_connections 64` as `max_children` (`gateway.ex:54-56`, `:78-79`) — but see §9: a
  browser holds a socket per tab, and 64 is sized for terminals.
- The byte caps, because they live in `Wire` and `Wire` is what encodes every frame
  (`wire.ex:169-175`).

The one genuinely new thing is the WebSocket close code vocabulary. Spec it minimally:
`1008` (policy violation) for an origin or credential refusal, `1009` for an oversized
frame, `1000` for a deliberate close, and the existing JSON-RPC error object for
everything the protocol already has a code for. A close code must never be the *only*
carrier of a refusal that has a protocol error code.

### W12 — Resync and the high-water contract

`Ouroboros.Web.Watch` is untouched and the algorithm is unchanged: the cursor is the
contiguous high-water mark, one repair function, floors render as dividers and never
discard (`watch.ex:9-44`, `:184-196`; `deck_live.ex:564-633`).

Two facts make this survive the transport, and one makes it need a new rule:

- **The replay loop stays absent.** `subscribe` answers the plane's whole backlog on the
  wire as well (`conn.ex:705-711`); `@replay_limit 500` binds `*.replay`, not `subscribe`
  (`methods.ex:142`, `:635`). So `deck_live.ex:30-38`'s reasoning holds, and
  `Watch.has_gap?/1` stays the question to ask if that changes.
- **`stream.lagged` becomes a fourth repair trigger**, and it routes into the same one
  function: a lag means events were dropped, so the answer is `subscribe(cursor)` — the
  cursor being the contiguous high-water mark is exactly what makes that correct without a
  special case. Note what this does *not* import: `MAX_RESYNC_ROUNDS` and `REPLAY_LIMIT`
  (`tui/src/run.rs:76`, `:80`) belong to the Rust clients' replay loop, and the web has no
  loop to bound because `subscribe` is not count-capped. `Ouroboros.Web.Watch` stays the
  fourth copy of this algorithm (§1.4) and W1 does not make it a fifth.
- **New rule — a `_truncated` event is present, not missing.** A large backlog shares one
  50,000-node encode budget (`wire.ex:93`, `:144`, `:234-236`), so the tail of a big
  backlog can arrive as `@truncated` markers. Such an event has a real sequence and must
  advance the high-water mark; what is missing is content, not history. It must render as
  a visible note (the vocabulary exists — `presentation.ex:1614-1615`) and must **not**
  raise a floor and must **not** look like an ordinary event. Getting this backwards in
  either direction is a correctness bug: raising a floor would draw a divider where no
  history was lost, and rendering it plainly would show an operator an empty turn.

### W13 — Reachability posture

Identical to the surfaces beside it, and implemented in both layers like both of them:
loopback default; a non-loopback bind refuses the boot without
`OUROBOROS_GATEWAY_WS_ALLOW_REMOTE=1`, once in `config/runtime.exs` standing on `System`
alone and once in the config module (`web/config.ex:17-19`, `:241-257` is the pattern to
copy, and it is itself a copy of the gateway's). No TLS in v1; the documented remote
posture is `tailscale serve` or an operator's reverse proxy, and the refusal text says so
(`web/config.ex:249-251`).

Publication: extend `gateway.json` with the WebSocket port rather than minting a second
file. A client that already reads the publication to find the gateway should not need to
learn a second discovery mechanism, and `web.json`'s missing `birth` field is a known gap
this document should not duplicate (`WEB.md:246-250`).

### What the transport deliberately does not do

No SSE. H4 names "HTTP/SSE" (`AGENT_EXPERIENCE.md:162`, `:863`), and SSE is the wrong
shape for this protocol: it is one-directional, so requests would need a second channel,
and the `Conn` would then own two half-connections whose lifecycles could disagree. If an
SSE bridge is ever wanted for a consumer that cannot hold a socket, it is a separate
adapter over this transport, not an alternative to it.

No TLS, no compression, no per-session scope, no multi-tenancy, no protocol version
beyond `@protocol 1`, and no SDK.

## 4. Slices

PR-sized, each green before the next. **T1–T3 are worth having under every option in §2,
including doing nothing else.** T4–T6 are the migration and only exist under W1.

- **C0 — the backpressure self-check.** Independent of everything else and takeable now.
  A `Process.info(:message_queue_len)` guard on the LiveView that kills the view over a
  threshold and lets the remount resync it, plus the load recipe that demonstrates a
  mailbox can actually grow. *Acceptance:* a test that drives a subscribed view faster
  than it flushes, observes the queue length cross the threshold, and asserts the view
  died and the remounted one rendered the same transcript from `subscribe(cursor)`.
  Closes `WEB.md:658-667`.

- **T1 — the WebSocket transport.** W5–W13, web untouched. *Acceptance:* every golden
  fixture, requested over WebSocket, produces the byte-identical frame the TCP transport
  produces for the same request; `hello` refusals (bad token, wrong protocol, token on a
  cookie-authenticated connection, missing token on an unauthenticated one) each assert
  their own error code; an origin refusal on the cookie path and its absence on the token
  path; an oversized frame closed with `1009`; a forced queue overflow producing exactly
  one `stream.lagged` with the right `dropped` and `last_sequence`; the boot-posture tests
  the gateway and the web endpoint both already have, mirrored for the new bind.

- **T2 — an Elixir wire client.** `Ouroboros.Wire.Client`: a GenServer that connects,
  says `hello`, correlates requests to responses, forwards notifications to an owner pid,
  surfaces `stream.lagged` and `stream.ended` as messages, and reconnects with the
  existing publication as its discovery. Used by nothing yet. *Acceptance:* the client
  drives the whole golden corpus against a live T1 endpoint in the same VM and asserts the
  decoded results equal what `Methods.invoke/2` answers in-process — which is the
  strongest available statement that the transport changed nothing.

- **T3 — the cap-awareness pass.** Route every leaf read in `Web.Presentation` and
  `Web.Transcript` through `leaf_text/1`; add over-cap fixtures to the golden corpus (one
  `_excerpt`, one `_b64`, one `_opaque`, one `_truncated`, and one event that exhausts the
  512 KiB per-event budget across two leaves); assert the rendered words on both sides.
  **Valuable under status quo**: it is currently near-dead code on the web path (§1.3) and
  the fixtures are the only thing that would keep it correct. Note the mechanical cost of
  each new fixture, which is the intended coupling and not an obstacle: the name lands in
  `transcript_corpus` (`ouroboros.gateway.golden.ex:186`), in the Rust literal `vec![]`
  (`tui/src/model.rs:3915-3985`), and in both corpus-completeness lists
  (`corpus_parity_test.exs:933-978`, `presentation_corpus.rs:1233-1278`) — four places, by
  design, so a fixture cannot be added on one side only. *Acceptance:* a 200 KiB assistant
  message renders as an excerpt label rather than as nothing, on both sides, from one
  fixture; and the `wire_shape` identity test (`corpus_parity_test.exs:1009`) still passes
  over the grown corpus, which is what proves the in-process and wire shapes have not
  diverged further.

- **T4 — `DeckLive` reads through the client.** `Web.Call.call/4` call sites become
  `Wire.Client.request/3`; the pid subscription becomes client notifications; the
  coordinator monitor becomes `stream.ended`; `Call.available?/2` becomes the `methods`
  set from `hello`. *Acceptance:* the existing LiveViewTest suite passes with no
  assertion rewritten — only the fixture that stands up the runtime changes. If a test
  assertion has to change, that is a behaviour change the slice must name and justify.

- **T5 — the other views.** `MachinesLive`, `NewSessionLive`, `StatusLive`, and the
  artifact controller (which calls `computer_use.artifact` in-process today,
  `WEB.md:305`). *Acceptance:* per-view LiveViewTest suites unchanged; the artifact
  controller's sha-addressed caching behaviour asserted unchanged, since the payload now
  arrives base64 through the wire rather than as a binary.

- **T6 — removals** (§5).

**Order.** C0 anywhere. T1 → T2 → T4 → T5 → T6. T3 is independent of T1 and T2 and can
land first; it should, because it is the slice most likely to find something.

## 5. Removal checklist

Nothing on this list is removed before the slice that replaces it is green, and each line
names its replacement so a reviewer can check that the replacement exists.

**Under W1 (Option A), at T6:**

- [ ] `lib/ouroboros/web/call.ex` — whole module. Replaced by: `Wire.Client` requests.
- [ ] `Ouroboros.Web.TaskSupervisor`'s use by `Call` (`call.ex:106-107`) — check whether
      anything else uses it before deleting the supervisor itself.
- [ ] `Presentation.wire_shape/1`, `wire_key/1`, `atom_to_string/1` and the `payload_of/1`
      call (`presentation.ex:936-971`) — replaced by the wire. **Verify first**: if any
      test constructs an event by hand and relies on `wire_shape`, it needs a fixture
      instead, not a keepalive.
- [ ] `deck_live.ex:394-398`, the raw-message clauses.
- [ ] `deck_live.ex:644-661`, the coordinator monitor and demonitor.
- [ ] The `alias Ouroboros.Gateway.Methods` in `deck_live.ex:99` and every direct
      `Methods.*` call in `lib/ouroboros/web/` — **this is the checkable invariant**: after
      T6, `grep -rn "Gateway.Methods" lib/ouroboros/web/` returns nothing, which is the
      one-line proof that the web is a client.
- [ ] `docs/WEB.md` D2 and §8 get as-built notes pointing here, in the style that document
      already uses (`WEB.md:9-13`) — **not** edits that make them agree with the code.

**Under W2 (Option B), additionally** — recorded for completeness, not recommended:

- [ ] `phoenix`, `phoenix_live_view`, `phoenix_html`, `earmark` from `mix.exs`; `bandit`
      stays and becomes a direct dependency.
- [ ] `lib/ouroboros/web/{presentation,transcript,markdown,watch,layouts,router,live_socket,status_live,error_html}.ex`
      and `lib/ouroboros/web/{live,transcript}/`.
- [ ] `test/ouroboros/web/corpus_parity_test.exs` — and its replacement in the new
      toolchain must land **before** it is deleted, exactly as `WEB.md:419-420` required of
      `surface_contract.rs`. The lock transfers; it never lapses.
- [ ] `WEB.md` §0's headless-test argument gets an explicit answer, in `WEB.md`, naming the
      harness and where it runs in CI.

## 6. Risks

### 6.1 The uncapped mailbox — the motivation, still unmeasured

`persist/3` sends to every subscriber pid with no queue check (`interactive/task.ex:2268-2273`),
and no test in this tree drives a view hard enough to observe the mailbox grow
(`WEB.md:660-667`). This is the strongest argument for W1 and it rests on a mechanism that
is real by construction and unquantified in practice. **It should not be used to justify
the migration without C0's load recipe first producing a number.** If the number turns out
to be "a wedged view holds 40 messages and recovers", the argument for A gets weaker and
the argument for C gets stronger, and this document would rather find that out than be
right by assumption.

### 6.2 The resync high-water contract

See W12. The specific hazard: an event that arrives `_truncated` because a large backlog
exhausted the per-encode node budget (`wire.ex:93`, `:234-236`) is *present*, and treating
it as *missing* would raise a floor and draw a divider over history that was never lost.
The corpus must carry a fixture for it (T3) or the rule is unenforced.

### 6.3 The event byte-cap asymmetry — the biggest behavioural change

Today the web gets uncapped payloads: `wire_shape/1` is documented as doing the wire's
atom flattening and explicitly "nothing else the wire does — no byte caps, no `_opaque`
minting, no struct tagging" (`presentation.ex:943-950`). On the wire, four marker shapes
start arriving (§1.3).

**What breaks visually, precisely.** `Presentation.wire_marker/1` already renders all four
correctly (`presentation.ex:1588-1622`), but only four call sites in the projection route
through `leaf_text/1` (`presentation.ex:1130`, `:1192`, `:1292-1302`;
`transcript/tools.ex:307`, `:436`, `:476`, `:532`). Everywhere else a leaf is read as a
plain string — for example the text of `output_text_delta` / `output_text_final`
(`presentation.ex:778-783`). A capped leaf arriving at one of those sites is a map where a
string was expected, so it reads as `nil`: **the content vanishes instead of degrading to
an excerpt.** An assistant message or tool result over 128 KiB would render as an empty
cell, not as "… (N bytes; full event via /details)".

**The bound on the blast radius, and it is a real one.** `@keep_whole 512` means a leaf of
512 bytes or fewer is never replaced, even after the per-event budget is spent
(`wire.ex:97-100`, `:255-256`). So only leaves over 512 bytes can break, which excludes
almost every field in the projection except message text, tool output, diffs, and plan
bodies — which is to say, exactly the fields an operator most wants to read.

**Second-order effect worth stating:** the per-event budget is shared across an event's
leaves and spent in walk order (`wire.ex:237-242`, `leaf_cap/1` at `:272`), so a large
first leaf can cause a *modest* second leaf in the same event to be excerpted. The failure
is not confined to giant payloads and cannot be reasoned about one field at a time. T3's
two-leaf budget-exhaustion fixture exists for this.

**The remedy is mechanical and testable**, which is why T3 is a slice rather than a
caveat: route every read through `leaf_text/1`, pin it with corpus fixtures, assert the
rendered words on both sides.

### 6.4 Latency

A localhost WebSocket hop per operator verb, on top of the browser round trip LiveView
already pays and `WEB.md:655-657` already accepts. Unmeasured (§9). The mitigation if it
bites is the ordinary one — the LiveView keeps issuing one request per operator action and
nothing becomes chattier — but "the mitigation is that we did not make it worse" is not a
measurement.

### 6.5 Connection budget

`@max_connections 64` (`gateway.ex:54-56`) was sized for terminals: "A terminal client
opens one connection." A browser holds one per tab, and a reconnect storm holds more
briefly. 64 is probably still plenty for an operator surface, but the constant's stated
reasoning no longer covers the caller, and W1 should either raise it with a new sentence
or write down why it does not need to.

### 6.6 A new failure mode

Today the web cannot be up while its access to the runtime is down — they are the same
process tree. After W1 they are not, and the connection pill acquires a third state. This
is a small UI risk and a real support-story change: "the browser says disconnected" and
"the daemon is down" stop being the same sentence.

## 7. What this buys for the daemon question — and what it does not commit to

**Buys.** A second transport for the protocol, and — more importantly — a *second client*
of it written in the language the server is written in. Today the protocol's only real
client is Rust, which means every claim about "the protocol is enough to build a surface
on" is a claim about one implementation by one author in one language. T2 plus T4 would
make the web an existence proof, and the corpus would keep it honest. It delivers H4's
substance (`AGENT_EXPERIENCE.md:863`) at H4's stated size, with the acceptance criteria
that row has never had. And it turns "should the runtime be a daemon" from an argument
into a measurement: after T4 the browser's latency, its behaviour under lag, and its
behaviour under caps are all observable facts rather than predictions.

**Does not commit to.** Deleting LiveView, or ever writing a browser client (W2 stays
available and stays unrecommended). Multi-tenancy or per-user scope — W9 keeps one scope
per transport and `WEB.md`'s D3 unchanged. TLS, which stays `tailscale serve`'s job
(`WEB.md:198-200`). A public or stable API: `@protocol 1` is unchanged and this document
adds no version negotiation, no deprecation policy, and no SDK. Running the runtime on a
different machine from the browser in any *supported* sense — the loopback default and
its both-layer refusal (W13) are the same posture the gateway and the web already ship,
and nothing here relaxes them. And it does not commit to the migration itself: T1–T3 stand
alone, and if T4 is never written, what exists is a transport, a client, and a projection
that reads capped payloads correctly — all three of which are improvements on their own
terms.

## 8. Open questions

- **W9's scope convergence.** If the web migrates, `OUROBOROS_WEB_SCOPE` and
  `OUROBOROS_GATEWAY_WS_SCOPE` describe the same authority for the same caller, and the
  shipped explicit-branch default has them disagreeing (`WEB.md:224-233`). Resolve before
  W1, not during.
- **Whether `Web.Call`'s audit line survives the move.** It exists to make one request
  reproducible against either surface with the same 16 hex characters
  (`call.ex:172-179`, matching `conn.ex:574-579`). After W1 the `Conn` writes the line,
  but with `peer` instead of the web session id — so the web session becomes untraceable
  in the audit log unless `hello`'s `client` field (`conn.ex:642-647`) carries it. That is
  a one-line answer and it should be a deliberate one.
- **Whether the transport gets its own port or shares the listener's.** W5 says its own;
  a single port speaking both line-framed JSON-RPC and HTTP-upgrade is possible and is
  probably not worth the sniffing.
- **`WEB.md`'s own open list** (`WEB.md:691-695`) is unchanged by this document: the
  effect-ledger question for operate calls, and server-side fleet-add.

## 9. Honest gaps in this document

- **Two premises this document was handed turned out to be wrong, and §1.4 corrects them
  rather than repeating them.** The corpus is **69** fixtures, not 67 (46 transcript + 23
  protocol, counted by hand). And "four transcript-projection implementations" is two
  implementations of a two-stage pipeline; what genuinely has four copies is the *resync*
  algorithm, and the fourth is `lib/ouroboros/web/watch.ex`, which is in Elixir and which
  Option A keeps and Option B replaces rather than removes. Any argument that leaned on
  either number should be re-run.
- **Nothing here is measured.** The mailbox risk (§6.1), the latency cost (§6.4), and the
  size of a realistic backlog relative to the 50,000-node budget (§6.2) are all reasoned
  from code, not observed. C0 and T1 both carry the load recipes that would change that.
- **The outbound frame size is unchecked.** `packet_size: config.max_frame`
  (`listener.ex:145-146`) governs *inbound* framing; this document did not verify whether
  anything bounds an outbound response frame, and a very large `subscribe` backlog is the
  case where it would matter. It is a pre-existing property of the TCP transport, not
  something W6 introduces, but W6 should not inherit it silently.
- **`Ouroboros.Web.Transcript`'s 1,356 lines were not read for this document** — only its
  entry point (`transcript.ex:272`) and its role. §6.3's inventory of plain-string leaf
  reads is complete for `presentation.ex` and `transcript/tools.ex`; if `transcript.ex`
  itself reads leaves, T3 is larger than described. Establishing that is a `grep` and it
  should be the first thing T3 does.
- **Two stale cross-language citations were found in passing** (§1.4):
  `transcript.ex:5` → `transcript_cells.rs:841` should be `:846`, and `transcript.ex:6` →
  `ui/transcript.rs:1237` should be `:1239`. They are unrelated to this migration and
  should be fixed independently of it — but they are evidence that citation drift is a real
  maintenance cost here, which is worth weighing when counting what each option leaves
  behind to keep in sync.
- **Unchanged and still open from `WEB.md`:** the removal checklist has not been walked
  end to end (`WEB.md:601-608`); `web.json` carries no `birth` (`WEB.md:246-250`); and
  `app.js` remains unexecuted by any test (`WEB.md:673-690`) — which W1 leaves exactly as
  it is and W2 would make substantially worse.
