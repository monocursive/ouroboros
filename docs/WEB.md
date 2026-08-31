# Ouroboros Web — the LiveView operator surface

Status: **W0–W8 landed; W9 (the GPUI removal) is the only slice outstanding.** Written
2026-08-29 as a specification against the `deploy` branch working tree (84987ab plus
uncommitted fleet WIP); every `file:line` claim below was verified against that tree, facts
about code carry citations, decisions carry numbers (D1–D14), and anything uncertain says
so.

The spec text is kept as written. Where the build diverged from it — and it did, in eight
places worth knowing about — the divergence is recorded as an **As built** note beside the
paragraph it corrects, rather than by editing the paragraph into agreement with the code.
A spec that has been quietly rewritten to match what shipped cannot tell you what was
learned. The as-built notes are in §9 (per slice) and in D10 and D14 (per decision).

The decision this document specifies: retire the GPUI desktop client (`ouro-desktop`) and
replace it with **Ouroboros.Web**, a Phoenix LiveView surface served by the daemon itself.
The Ratatui client (`ouro`) stays, unchanged in role: the flagship surface, the CLI, and
the thing that boots and supervises the runtime.

## 0. Why, in five sentences

The GPUI layer is 7,564 lines of rendering skin over a shared reducer that already owns
every protocol decision (`tui/src/desktop.rs:1-6`); the skin is what gets deleted, not the
model. Its recurring costs are structural: exact-pinned pre-1.0 frameworks
(`gpui =0.2.2` / `gpui-component =0.5.1`, pinned because "a floating compatible range can
compile two different framework APIs into one binary", `tui/Cargo.toml:24-33`), a
workaround-grade component bug already absorbed into our state model
(`tui/src/desktop.rs:517-532`), and **no headless test story** — "Nothing here has been
verified by eye" (`docs/DESKTOP.md:189-192`); every visual claim needs a human or
computer-use driving a live window. A browser surface is strictly better at the two things
the desktop uniquely provided — real pixels (computer-use screenshots) and a graphical
composer — and adds what gpui structurally never could: access from the Linux laptop, the
VPS, a phone over the tailnet, and multiple simultaneous viewers. The daemon is Elixir;
in-process the whole client-connection defect class (stale-token reconnect loops, chip
task_d2fd4c2d) collapses into browser-refresh semantics. `Phoenix.LiveViewTest` is fully
headless, which changes the economics of every future surface slice.

**Non-goals:** replacing the TUI; a native shell (a Tauri/PWA wrapper over the same pages
is a later option if dock presence is ever missed); TLS termination (v1 defers to
`tailscale serve` or a reverse proxy); exposing the web surface beyond what the gateway's
own exposure discipline allows.

## 1. Verified ground

Facts the design stands on, each checked in the tree:

- **The in-process dispatch seam already exists.** `Methods.invoke(method, params)` takes
  no connection state (`lib/ouroboros/gateway/methods.ex:1131-1135`); the scope gate is
  two public functions (`Methods.fetch/1`, `Methods.permits?/2` —
  `methods.ex:996-998`); the `Conn` calls `invoke/2` inside a supervised task with the
  table's per-method timeout (`lib/ouroboros/gateway/conn.ex:936-955`). The test suite
  already calls `Methods.invoke/2` directly (`test/team_test.exs:1078`).
- **Six methods are connection-answered, not dispatched**: `hello`, the four
  subscribe/unsubscribe verbs, and `runtime.shutdown` (`conn.ex:143-149`,
  `lib/mix/tasks/ouroboros.protocol.docs.ex:64-71`).
- **Subscriptions register the calling process.** "Both planes register `self()` and
  monitor it" (`methods.ex:1069-1084`); events arrive as
  `{:ouroboros_interactive_event, id, %Event{}}` /
  `{:ouroboros_coding_event, id, %Event{}}` sent only after the durable checkpoint
  (`lib/ouroboros/interactive/task.ex:2149-2154`). A terminal session answers the backlog
  but silently declines registration (`interactive/task.ex:142-155`). There is no
  per-session subscriber cap.
- **In-process data is uncapped.** The 128 KiB / 512 KiB / 4 MiB leaf caps live entirely in
  `Gateway.Wire.to_json/2`, reached only from the `Conn`'s frame builders
  (`conn.ex:192-219`, `wire.ex:120-133`). Subscribers and `invoke/2` callers get raw
  structs. The one exception: `*.event_detail` returns a pre-capped JSON tree
  (`lib/ouroboros/gateway/methods/encode.ex:191-198`).
- **Supervision tail.** `:rest_for_one`; the gateway sits at the end because "its crash
  must restart nothing, and it must be the first thing to stop … It is also the only child
  here that a stranger can reach" (`lib/ouroboros/application.ex:205-210`); tail order is
  `Cluster, OpenAIAuth, gateway_children(), CodeIntel.Supervisor, Desktop.Supervisor,
  Mcp.Supervisor` (`application.ex:235-242`). Absent gateway config means no child at all
  (`application.ex:273-279`).
- **Config split.** `config/runtime.exs` lines 3–418 are prod-only; everything below runs
  in every environment "because the gateway is how a laptop attaches to a runtime it
  started with `mix run --no-halt`" (`runtime.exs:420-424`). The defaulted single-machine
  posture (prod, no `OUROBOROS_GATEWAY`, no node, no cluster) auto-enables an
  operate-scope loopback gateway with `token_generate: true` (`runtime.exs:396-411`).
- **Exposure discipline, implemented twice on purpose**: non-loopback bind refuses the
  boot unless `OUROBOROS_GATEWAY_ALLOW_REMOTE=1` — once in the config provider standing on
  `System` alone (`runtime.exs:511-546`), once in the application layer
  (`lib/ouroboros/gateway/config.ex:307-320`). Token: file mode exactly 0600, ≥32 bytes,
  fail-closed; `token_generate` is the single exception and never overwrites
  (`config.ex:337-363, 500-531`).
- **The web stack is greenfield.** No phoenix/plug/bandit/cowboy/websock anywhere in
  `mix.lock`; `jason` 1.4.5 is transitive; the app's primary JSON is Elixir 1.20's
  built-in `JSON`. `phoenix_pubsub` is an optional dep of `jido_signal`, so it slots in
  without conflict. `priv/` holds two native executables and zero static files; the
  release's `:assemble` step copies `priv/` as-is.
- **No client render is reusable from the BEAM.** An Elixir renderer reimplements the
  presentation stage (`tui/src/model/transcript.rs`, 29 event kinds + the
  `provider_event.kind` sub-dispatch, deliberately no ignore arm) and the projection stage
  (`tui/src/ui/transcript_cells.rs:841 project()`). The resync algorithm is already
  reimplemented three times in the Rust tree alone (`ui/transcript.rs`, `run.rs:1266`,
  `acp_serve.rs:1419`) — a fourth, in Elixir, is the established pattern, not a smell.
- **The golden-fixture seam is the parity mechanism but is transcript-poor.** 20 fixtures
  in `test/support/gateway_golden/` pin the envelope, errors, excerpt markers, and lag
  shapes — but carry no `tool_call`/`tool_result`, `thinking_delta`,
  `approval_requested`, `plan_updated`, `usage`, or any `provider_event` payload. The
  Rust side names every fixture on purpose (`tui/src/model.rs:3424`,
  "a fixture added upstream must be decoded here on purpose").
- **Machine-add is client-side Rust over SSH.** The whole pipeline — probe, binary copy,
  invitation, `ouro fleet enroll`, Tailscale guided setup — lives in
  `tui/src/fleet_add.rs` behind the typed `AddEvent` stream (`fleet_add.rs:1116-1148`);
  the gateway's only fleet verbs are `fleet.status`, `fleet.doctor`,
  `fleet.forget_session_owner` (`methods.ex:212-213,292`). There is no Elixir enrolment
  path.
- **Two corrections to prior internal notes**: `fleet.sessions` does not exist
  (fleet-wide lists are `interactive.list`/`coding.list` fanning out over `:erpc`,
  `lib/ouroboros/gateway/methods/present.ex:55-113`), and `OUROBOROS_DIST_TAILNET` is
  spec-only in `docs/FLEET.md` — not implemented. This document mirrors the *pattern* of
  the implemented refusals, not that flag.

## 2. Architecture

### D1 — Namespace, placement, protection

New modules live under `Ouroboros.Web.*`. The supervisor `Ouroboros.Web` is appended as
the **final** child of the `:core` tail, after `Mcp.Supervisor`: under `:rest_for_one` its
crash then restarts nothing, and it is the second child a stranger can reach, so it sits
downstream of everything — the same argument the gateway and the LSP pool already carry
(`application.ex:199-234`). Gating copies `gateway_children/0` exactly: a
`web_children/0` returning `[Ouroboros.Web]` iff `Ouroboros.Web.Config.enabled?()`;
absent configuration means no endpoint at all, so tests, `:builder`, and `:signer` never
acquire one.

`"Elixir.Ouroboros.Web."` joins `@protected_prefixes` in
`lib/ouroboros/upgrade/verifier.ex:53-64` in the same commit that creates the namespace.
An operator surface must not be hot-patchable by the thing it operates.

### D2 — One authorization surface

The web layer calls **only** the gateway's public seam, never the planes:

```elixir
with {:ok, entry} <- Methods.fetch(method),
     true <- Methods.permits?(scope, entry) do
  Task.Supervisor.async_nolink(Ouroboros.Web.TaskSupervisor,
    fn -> Methods.invoke(method, params) end)
  # awaited with entry.timeout; timeout renders the same
  # "outcome: unknown" honesty the Conn does (conn.ex:951, 973-979)
end
```

No refactor of `Conn` is needed or wanted: `fetch/1`, `permits?/2`, `invoke/2` are already
public. A small `Ouroboros.Web.Call` module owns this gate so it is written once. The
`Conn`'s audit line for operate calls (`conn.ex:564-579`, params-digest, never the
payload) is reproduced: same log shape, `peer` replaced by the authenticated web session
id.

The six connection-answered methods map as:

| Conn method | Web treatment |
|---|---|
| `hello` | not spoken; the LiveView reads `Methods.names/0` directly — the same list `hello` serves, and still the only feature gate (a page shows a verb's control iff the method exists) |
| `*.subscribe` / `*.unsubscribe` | the LiveView process registers itself (§8) — the exact mechanism `Conn` uses |
| `runtime.shutdown` | **not offered in v1.** A browser tab is the wrong place for it; `ouro` keeps it |

### D3 — Scope

The endpoint carries one scope, `read` or `operate`, fixed at boot from config — the
gateway's model exactly (`config.ex:96`; "Scope is a property of the listener, fixed at
boot"). No per-user or per-session narrowing in v1; there is one operator credential per
data directory and the web surface inherits its authority. The defaulted single-machine
posture gets `operate`, mirroring the auto-gateway branch.

### D4 — Authentication

- **Credential: the gateway token, shared by default.** `Ouroboros.Web.Config` takes
  `token_file`, defaulting to `Path.join(data_dir, "gateway.token")` — the same file, the
  same 0600/≥32-byte/fail-closed validation (`config.ex:392-479` is reused, not copied),
  the same `token_generate` posture in the defaulted branch. One operator credential per
  data dir; a deployment that wants separate credentials sets a different path. Revisit if
  the surfaces ever need independent rotation.
- **Bootstrap: token → cookie.** `GET /auth?token=…` compares constant-time against the
  resolved token (the `conn.ex:622-633` pattern), sets a signed, `HttpOnly`, `SameSite=Lax`
  session cookie, and 302-redirects to `/` so the token never survives in the address bar
  or history beyond the exchange. `Referrer-Policy: no-referrer` on every page. Every
  other route requires the cookie; failures render one unauthenticated page naming
  `ouro web` — no probe surface.
- **Cookie secret:** `web.secret` in the data dir, 32 random bytes, generate-if-absent
  with the token file's exact write discipline (0600 temp → chmod → write → rename, never
  overwrite). Sessions survive daemon restarts.
- **CSRF:** Phoenix defaults stay on. **WebSocket origin:** `check_origin` is computed
  from the bound address and port (never `false`); an explicit
  `OUROBOROS_WEB_ORIGIN` overrides it for proxied/tailnet-served setups.

### D5 — Exposure

Mirrors the gateway refusal, implemented in both places like the original:

- Default bind `127.0.0.1`. A non-loopback `OUROBOROS_WEB_BIND` **refuses the boot**
  unless `OUROBOROS_WEB_ALLOW_REMOTE=1` is typed out on the host — once in
  `config/runtime.exs` (below line 420, standing on `System` alone), once in
  `Ouroboros.Web.Config` (the `config.ex:307-320` pattern). The refusal text names the
  risk in the same register: the session cookie and everything after it cross the wire in
  the clear.
- v1 ships no TLS. The documented remote posture is `tailscale serve` (TLS + tailnet
  identity in front of the loopback bind) or an operator's own reverse proxy. The refusal
  message says exactly that.
- **Port: sticky.** Default port 0, but the endpoint publishes `web.json`
  (`{"port", "protocol", "node", "pid", "scope"}` + optional `"token_file"` — the
  `gateway.json` shape and write discipline, `listener.ex:249-309`) and on the next boot
  tries the last-published port first, falling back to 0 if taken (precedent: the pinned
  rebind loop in the fleet WIP, `listener.ex:151-192`). Stable-enough origins keep
  cookies and bookmarks working across restarts; operators who want a fixed port set
  `OUROBOROS_WEB_PORT`.
- **Enablement:** wherever the gateway is on, the web is on unless refused —
  the defaulted release branch (`runtime.exs:396-411`) grows the web block, and the Rust
  spawner's `spawn_env` (`tui/src/runtime.rs:1645-1704`) adds `OUROBOROS_WEB=1` beside
  `OUROBOROS_GATEWAY=1`. `OUROBOROS_WEB=0` opts out. Same risk class, same posture:
  loopback + token.

### D14 — `ouro web`

One small Rust addition: `ouro web` reads `web.json` (spawning/adopting the runtime
through the existing spawn-lock machinery exactly as `ouro attach` does), prints
`http://127.0.0.1:<port>/auth?token=…`, and opens it in the system browser. `make web`
wraps it in dev. The desktop's HTTPS-only `open_url` guard does not apply — this URL is
constructed locally from the publication, not received from a stream.

**As built** (`tui/src/web_cli.rs`), with five notes where the paragraph above was
imprecise or silent:

- **Scope is stated by the client, not inherited.** D5 says `spawn_env` adds
  `OUROBOROS_WEB=1`; that alone is not enough. Setting `OUROBOROS_GATEWAY` is what forces
  `config/runtime.exs` down its *explicit* branch, and that branch defaults
  `OUROBOROS_WEB_SCOPE` to `read` — mirroring `OUROBOROS_GATEWAY_SCOPE`'s own explicit
  default, deliberately. A daemon `ouro` spawned is the operator's own, so `spawn_env`
  sends `OUROBOROS_WEB_SCOPE=operate` beside `OUROBOROS_GATEWAY_SCOPE=operate`; otherwise
  the browser would refuse every approve the terminal beside it is allowed to make. The
  scope variable is read only *inside* the `OUROBOROS_WEB == "1"` gate, so it is inert on
  its own and does not become a second way to turn the surface on.
- The runtime is resolved by `local_runtime` — the *bare* `ouro` command's adopt-or-start
  under the spawn lock. `ouro attach` was the wrong citation: it deliberately starts
  nothing. A runtime `ouro web` spawned is detached before the URL is printed, for
  `ouro daemon`'s reason: this command exits, and the browser it just opened must not go
  with it.
- `--print` writes the URL and opens nothing, for a script, a remote shell, or a machine
  with no browser. Boot progress goes to stderr rather than stdout so that stays true.
- `web.json` is polled for up to 10 s after the runtime is up. `Ouroboros.Web` is the last
  child of the supervision tree, so the endpoint binds after the gateway publishes, and
  the window where a fresh spawn has one publication and not the other is real. The
  timeout names `OUROBOROS_WEB=0` as the likeliest cause; a `web.json` left behind by a
  dead pid gets its own sentence, because that is a different situation.
- **Known gap:** `web.json` carries no `birth`, so staleness here is PID liveness alone —
  weaker than `gateway.json`'s incarnation check, and a recycled PID would read as live.
  It is survivable only because nothing reached through this record signals a process or
  authorizes anything: it produces a link a browser either loads or does not. Adding
  `birth` to `Ouroboros.Web.Publication.document/3` closes it.

## 3. Dependencies and assets (D6)

Added to `mix.exs`: `phoenix`, `phoenix_live_view`, `bandit`, `phoenix_html` (current
stable lines at implementation time; `phoenix_pubsub` arrives transitively and is already
optional-compatible via `jido_signal`). Nothing else is required at runtime.

**No esbuild, no Tailwind, no production asset pipeline.** The release copies `priv/`
verbatim. Node is a development/CI dependency only, used by Playwright to execute browser
acceptance journeys:

- JS: the prebuilt bundles that ship inside the deps
  (`deps/phoenix/priv/static/phoenix.min.js`,
  `deps/phoenix_live_view/priv/static/phoenix_live_view.min.js`) are copied into
  `priv/static/web/` by a mix alias that runs in `make release-tarball` and in dev
  compile. The hand-written `app.js` wires the LiveSocket and browser hooks; Playwright
  loads it exactly as the release serves it.
- CSS: hand-authored. `tui/src/desktop_design.rs` is already a token system (paired
  dark/light palettes, layer order, semantic tones — `docs/DESKTOP.md:211-227`); it ports
  to CSS custom properties nearly one-to-one, and the design rules it encodes (semantic
  tones never the action accent, hairline separation, scarce primary actions) carry over
  as written.
- Markdown: **Earmark** (pure Elixir). MDEx renders faster but is a Rust NIF, which would
  entangle the two dist triples for zero user-visible gain at these payload sizes.
- Diff parsing: written fresh in Elixir to the client contract — additions/deletions
  **counted from hunk bodies, never taken from the provider's claim**
  (`tui/src/ui/diff.rs:14`).

Release impact: these deps add single-digit MB to the 18 MB tarball and nothing to the
Rust build graph. `mix release`'s `:assemble` picks up `priv/static/web/` with no new
mechanism.

**As built**, two corrections to the paragraph above:

- **`app.js` is ~380 lines, not ~50**, and the hooks are not the ones listed. There is no
  clipboard hook and no notification-permission *hook*: what exists is `ScrollPin` (the
  terminal client's `follow` flag, in a browser), `Composer` (Enter-to-send and autosize,
  bound at the element because a round trip per keystroke to decide whether a key was a
  newline would make typing feel like the network), and three things that are not hooks at
  all — a delegated click listener for the two chrome toggles, a `phx:needs-you` listener,
  and the pre-paint theme read (which lives in `<head>`, not in this file). It is still one
  hand-written file with no module graph, and still small enough to read in one sitting.
- **Markdown is Earmark plus an allowlist renderer**, not Earmark alone. See W3's as-built
  note in §9 for what `escape: true` does not cover and how that was established.

## 4. Parity map

**The parity target is the GPUI desktop surface, not the seven-tab TUI.** The TUI remains
the full-surface client; the web starts where the desktop stopped and can grow later.
Inventory source: `docs/DESKTOP.md` and the verified feature map of `tui/src/desktop.rs`.

| Desktop feature (today) | Web treatment |
|---|---|
| Session rail: triage-ordered rows, presence, context menu, rename/delete dialogs with gating ("Finish session to delete") | LiveView list over `interactive.list` + `coding.list` polled at the TUI's ~3 s cadence while mounted; triage/sort/nesting rules ported from `tui/src/ui/app/session.rs:380` (`triaged()`); delete gating recomputed server-side by the same rule (`terminal? or last_known`, and only if the verb exists) |
| Transcript: markdown messages, thinking, tool cells with collapse, diffs, plan, subagent rows, dividers, streaming spinner | the Elixir projection (§5) rendered as LiveView streams; tool-output collapse keeps the desktop's 12-line/head-7/tail-4 budget |
| Computer-use screenshots (`gpui::img`) | `<img src="/artifact/<plane>/<id>/<sha>">` served by an authenticated controller that calls `Methods.invoke("computer_use.artifact", …)` — same surface, same node routing; sha-addressed so browser caching is safe |
| Composer: quick-start, three placeholder states, send/stop, queue | same reducer semantics, one Elixir implementation: quick-start issues `interactive.start` + first message; turn envelope stays "plain string unless structured" (`tui/src/model.rs:2823-2868`) |
| Auto-approve dropdown + approval-card switch | client-side-of-the-server: the LiveView answers `approve, once, actor: "automation"` per request, never `plan_exit`/`question`/computer-use (`ui/transcript.rs:441-449`), idempotent against replay — the TUI's exact carve-outs, asserted by shared fixtures (§6) |
| Approval card: kinds, choices, provider options, suggested rule, subagent attribution, diff excerpt | one card, optional sections, rendered from the same payload contract (`ui/transcript.rs:309-482`); respond params keep the closed envelope incl. the vendor-option decision table (`ui/transcript.rs:284`) and the plan-choice fallback mapping (`model.rs:2673`) |
| Sandbox picker, thinking picker — "absent, not defaulted, when the runtime said nothing" | identical rule; `interactive.configure {sandbox_mode}` / `{reasoning_effort}`; label follows the session row after re-list, exactly as `docs/DESKTOP.md:63-69` states it |
| New-session form: provider/model pickers with search, workspace + Browse…, sandbox, effort | `runtime.providers` / `runtime.models` (fetched on form open, never on cadence — `mod.rs:107`); a `<select>`/combobox has none of the gpui-component filtered-cache pathology, so the authoritative-choice workaround dies with gpui; **Browse… becomes `workspace.browse`** (§7) — the native picker browsed the *client's* filesystem, which was only ever correct when client and daemon shared a machine |
| ChatGPT account card | `account.read` / `account.login.*`; the sign-in URL is a plain link; "tokens never cross the gateway" holds — they never leave `OpenAIAuth` |
| Machines panel: fleet name, member presence chips, add-machine form with two-step Tailscale consent, stepper, AuthUrl card | **read-only in v1**: `fleet.status` + `fleet.doctor` + presence derived from `runtime.status.connected_nodes` under the desktop's exact rules (unknown-not-offline before first status, self-is-connected — `tui/src/desktop/machines.rs:107`); the fleet profile is read server-side from the same `<data_dir>/fleet/profile.json` the daemon already validates (`cluster.ex:716-748`). **Add-machine is deferred** (D10 below) with an honest empty state naming `ouro fleet add` — the desktop's own no-fleet posture |
| Window title, connection pill, notices | page title, a connection indicator driven by LiveView socket state, one notice slot with the same "Info is deliberately dropped" rule |
| Keyboard: Enter/Shift-Enter, ⌘., ⌘N | same bindings via LiveView key events (browser-permitting; ⌘N may need to become a different chord — browsers own it) |

**D10 — deferred, stated plainly:**

- **Add-machine from the browser.** The pipeline is Rust driving `ssh`/`scp` from the
  operator's machine (`fleet_add.rs:1`). Moving it server-side changes its trust shape:
  the daemon would hold the SSH authority and the Tailscale auth URL relay. That is a real
  design (a `fleet.add` verb streaming typed events — the `AddEvent` contract is already
  renderer-agnostic), but it is its own spec, not a port. v1 web renders membership and
  points at `ouro fleet add` / the TUI stepper.
- **`runtime.shutdown`, ledger/upgrade/teams/plans/control tabs, `workspace.exec`, /raw
  and /export, statusline.** TUI-only today or TUI-appropriate; none existed on the
  desktop. `[statusline]` in particular must never be ported naively — it runs a shell
  command on the client's machine, which server-side would mean shell execution on the
  daemon host (`tui/src/config.rs:295`).
- **Web-side prefs.** Form defaults (`[defaults]` provider/model/workspace) get a
  server-side home in the data dir (`web.prefs.json`, atomic 0600 writes), because
  `config.toml` belongs to the terminal client's machine. Per-browser conveniences
  (collapsed sections, theme) live in `localStorage`. Notifications API, reduced-motion,
  and keybinding remapping are later slices.

  **As built** (W8 — `lib/ouroboros/web/prefs.ex`), with three corrections:

  - **Five keys, not three.** `sandbox_mode` and `reasoning_effort` are stored beside
    provider/model/workspace. They are choices a person makes the same way and about the
    same work, and leaving them out would have made the file a partial memory of a form
    somebody had just filled in.
  - **A stored default is sendable**, and this is the one semantic here worth arguing
    about. `docs/DESKTOP.md`'s new-session paragraph reads "What the file supplies is where
    the control *starts*; an explicit pick is what gets sent, and an untouched panel with
    **no stored default** states no posture at all" — and the desktop implements exactly
    what that last clause forces: `self.new_sandbox.or(configured_sandbox)`, under the
    comment "the operator's pick, else the stored default, else nothing"
    (`tui/src/desktop.rs:2264-2269`). The web matches it. "Absent, not defaulted" keeps its
    meaning: what never reaches the plane is what the operator has never chosen, this time
    or last. A file that was drawn but not sent would show one posture and request another.
  - **Notifications are not a later slice; they landed in W8.** A topbar bell, off by
    default, that asks the browser for permission on enable and posts one notification per
    session *entering* the needs-you group while the tab is hidden. Reduced-motion was
    already honoured by the streaming pulse (`@media (prefers-reduced-motion: reduce)` in
    `app.css`, since W3). Keybinding remapping is still a later slice.

  The theme did stay in `localStorage` as specified, with one thing this paragraph did not
  anticipate: it has to be applied **before first paint**, or a viewer who chose light sees
  a dark frame on every navigation. That is a small inline `<script>` in `<head>` — the
  only inline script this surface serves (`Ouroboros.Web.Layouts.theme_script/0`).

**The three genuine losses, accepted:** native app presence (dock, ⌘-tab, native
notifications); a UI while the daemon is down (`ouro` remains the bootstrapper and the
place boot problems render); OS-native file dialogs (replaced by `workspace.browse`,
which is *more* correct for remote daemons).

## 5. The Elixir presentation and projection (D7)

The largest engineering piece, and the one place drift with the TUI is possible. Two
modules, both pure:

- `Ouroboros.Web.Presentation` — port of `PresentationEvent::from_event`
  (`tui/src/model/transcript.rs:361`): the 29-kind dispatch, the `provider_event.kind`
  sub-dispatch (`transcript.rs:533-546`: exactly three arms — `operator_shell`,
  `compaction`, `subagent`; a `plan_exit` provider_event deliberately falls through to
  the generic provider-note, as the W1 corpus pins), **no ignore arm** — an unrecognized
  kind becomes a visible provider note, exactly as the Rust module header demands
  (`transcript.rs:7`). Display ceilings
  applied here, not at render, with the same numbers (64 KiB text/value, 2,048 nodes,
  depth 32, 128 KiB diff, 256 file changes, 64 plan steps — `transcript.rs:22`). Input is
  the in-process `%Ouroboros.Interactive.Event{}` / coding struct — uncapped, so these
  ceilings are load-bearing, not decorative.
- `Ouroboros.Web.Transcript` — port of `project()`
  (`tui/src/ui/transcript_cells.rs:841`): delta accumulation into one message cell per
  turn, thinking 3-state, tool call/result correlation by `call_id`, exploration folding,
  approval-resolution rewriting the earlier status cell by `request_id`, subagent folding
  by `task_id`, diffstat at turn boundaries, floor/gap/ended entries. Clock-free and
  filesystem-free by the same contract (`transcript_cells.rs:3`, `:849`).
- The two vendor tables port as data, verbatim: `shape_of`/`summarise`
  (~80 tool names → verb/subject/outcome, `transcript_cells.rs:3773, 3860` — "nothing is
  inferred from the tool's name alone") and `ProviderOption::decision`
  (`ui/transcript.rs:284`).
- `pending_approvals` is rebuilt from the whole ordered ledger on every absorb, never
  folded incrementally — the replay-vs-live ordering hazard is the same in-process
  (`ui/transcript.rs:1331-1337`).

Markdown (Earmark) and diff painting are renderer-local, exactly as they are for ratatui
and were for gpui; diff *parsing* (per-file hunks, counted ±) is in the projection.

## 6. The parity harness (D8)

`tui/tests/surface_contract.rs` exists because two suites that never look at each other
let a payload ship on only one surface. Its job transfers to the cross-language mechanism
that already keeps the two toolchains honest — the golden fixtures ("The protocol has two
implementations that are compiled by different toolchains and cannot call each other's
tests. These files are the seam.", `lib/mix/tasks/ouroboros.gateway.golden.ex:11`).

- **Extend the corpus** with transcript payloads: one fixture per `EventType` and per
  `provider_event.kind`, plus the approval kinds (`plan_exit`, `question`,
  `sandbox_escalation`, subagent-attributed, suggested-rule-bearing), `usage`,
  `queue_changed`, and a computer-use artifact event. Generated by the same static,
  clock-free task from real `%Event{}` structs; the Elixir drift tests extend
  mechanically (`Golden.fixtures/0` is a plain list).
- **Rust side:** `every_golden_fixture_is_accounted_for` grows in lockstep (the intended
  coupling), and a new test feeds each transcript fixture through
  `PresentationEvent` + `project()` and snapshots the words (verb, subject, outcome, cell
  kind, tone).
- **Elixir side:** the same structs through `Web.Presentation` + `Web.Transcript`, the
  same words asserted. One corpus, both renderers locked to it.
- This lands **before** the transcript LiveView is written (slice order, §9) and before
  `surface_contract.rs` is deleted — the lock transfers, it never lapses.

## 7. One new server capability: `workspace.browse` (D11)

The only new gateway method this spec introduces, so the web never touches the filesystem
outside the surface. `operate` scope (it exists to start sessions), closed envelope:
`{path?}` → `{path, parent, entries: [{name, dir}]}`; directories only; bounded (500
entries, name-sorted, dotfiles excluded by default); rooted at `$HOME` plus
`:workspace_allowed_roots`; symlinks not followed out of the roots; refusals typed. Added
to `@table` with golden fixture + `mix ouroboros.protocol.docs` + the Rust
fixture-accounting update, like every method before it. The TUI's start form may adopt it
later; nothing requires it to.

## 8. Streaming, resync, and backpressure (D9)

A transcript LiveView subscribes the way a `Conn` does:

1. `ref = Ouroboros.Interactive.Ref.new(id, owner_node)`;
   `Methods.subscribe(:interactive, ref, cursor)` **from the LiveView process** — backlog
   returned, registration monitored by the plane, cross-node transparent via the existing
   `:erpc` routing (`interactive_session.ex:881-893`).
2. Check terminality immediately (`Methods.session/2`) — a terminal session declined
   registration; render the backlog and the ended divider.
3. Monitor the coordinator (`Methods.coordinator/2` + `Process.monitor/1`); its `:DOWN`
   is `stream.ended`.
4. Live events in `handle_info`; unsubscribe is automatic on LiveView death (the plane's
   monitor).

**The resync algorithm is the TUI's, verbatim** (`tui/src/ui/transcript.rs:1-31`): the
cursor is the contiguous high-water mark, not the newest sequence; every repair — remount,
coordinator `:DOWN`, `{:error, {:cursor_pruned, floor}}` — is `subscribe(cursor)` through
one function; a first backlog entry above `cursor + 1` proves a silent prune and raises
the floor; floors render as dividers, never discard held events. In-process removes the
lag protocol but not the algorithm.

**Backpressure is the honest new risk.** The plane sends to subscriber pids
unconditionally (`interactive/task.ex:2149`) — the `Conn`'s `queue_limit`/`stream.lagged`
machinery was the protection, and in-process subscribers don't have it. Mitigations, in
order: LiveView renders O(delta) via streams with a bounded window (the TUI's
`WINDOW = 5_000` is the ceiling; the web keeps less and raises its floor on trim, the
`trim()`/divider rule); text deltas coalesce per render frame; and a LiveView that dies
under load is cleaned up by the plane's monitor and recovers on remount via
`subscribe(cursor)` — crash-and-resync **is** the lag path. If profiling ever shows
mailbox growth on a wedged view, the remedy is a `Process.info(:message_queue_len)`
self-check that kills the view, not a new protocol.

Session lists, status, providers, models: polled with the TUI's cadences and its
visibility rule ("Only the visible tab" — `ui/app/mod.rs:2310`), which for LiveView means
"only mounted views poll, each for what it shows." Models are fetched where a picker will
read them, never on a cadence (`mod.rs:107,249`).

Multi-viewer honesty: two browsers answering one approval resolve by `request_id` — the
second answer is refused upstream and rendered as the refusal, the reducer rule the
clients already follow (`desktop_respond_approval`'s recheck). No web-side lock.

## 9. Slices

PR-sized, each green before the next; W1–W2 are deliberately before any transcript UI.

- **W0 — endpoint skeleton.** ✅ **Landed.** Deps; `Ouroboros.Web` supervisor +
  `web_children()` tail slot; `Web.Config` (bind/port/token/secret with both-layer
  refusals); `/auth` cookie bootstrap; `web.json` sticky-port publication; verifier prefix;
  one page rendering `runtime.status` through `Web.Call`. `ouro web` + `spawn_env`
  `OUROBOROS_WEB=1` + `make web`. Gates: LiveViewTest for auth/refusals; boot-posture tests
  mirroring the gateway's.

  **As built**, three notes:

  - **The socket is refused at the handshake, not only at the mount.** D4 says every route
    requires the cookie; the socket is not a route. `use Phoenix.Endpoint` injects
    `plug :socket_dispatch` as the **first** plug in the pipeline, so `/live` is answered
    before `Plug.Session` has run and long before `Web.Auth` could see it — and moving the
    `socket` declaration down the endpoint changes nothing, because the declaration
    registers a path and the dispatch position is fixed. The `on_mount` hook alone would
    have kept the data in; it would not have kept a stranger from *holding* a socket, which
    is the distinction `Gateway.Listener` already draws when it caps connections rather
    than trusting the token to do it. So `Ouroboros.Web.LiveSocket.connect/3` checks the
    session on the cookie the browser sends with the upgrade.
  - **Scope had to be stated by the client.** D5 says `spawn_env` adds `OUROBOROS_WEB=1`;
    that alone would have served every `ouro`-spawned daemon a `read`-scope browser beside
    an `operate` terminal. The full reasoning is in D14's as-built notes.
  - **`web.json` carries no `birth`**, so staleness is PID liveness alone — weaker than
    `gateway.json`'s incarnation check. Survivable because nothing reached through this
    record signals a process or authorizes anything; see D14, "Known gap".
- **W1 — golden transcript corpus.** ✅ **Landed.** Fixtures + Elixir drift tests + Rust
  accounting + Rust presentation/projection snapshot tests. No web code.
- **W2 — `Web.Presentation` + `Web.Transcript`** ✅ **Landed**, against the corpus; parity
  words asserted on both sides. No web UI yet.
- **W3 — sessions + read-only transcript.** ✅ **Landed.** Rail (triage port),
  subscribe/resync, streams rendering, markdown, diffs, images via the artifact controller.

  **As built**, three notes:

  - **There is no resync *loop*.** §8 says the algorithm is the TUI's "verbatim"; it is the
    TUI's minus one round. The terminal client loops — replay, and if it progressed and a
    gap remains, replay again — because the gateway's `*.replay` verb answers at most
    `REPLAY_LIMIT` events per frame. In-process there is no such limit:
    `subscription_events/2` returns **every** retained event above the cursor in one call
    (`interactive/task.ex:2301`, bounded only by the session's own `event_limit`), so one
    subscribe closes the whole gap and a second round could only ever answer nothing.
    Everything else is unchanged: contiguous high-water cursor, one repair function, floors
    that render as dividers and never discard. `Watch.has_gap?/1` is kept as the question to
    ask if that stops being true.
  - **`NEEDS YOU` deliberately diverges from the TUI's triage.** §4 says the rules are
    "ported from `tui/src/ui/app/session.rs:380`", and they are, with one door closed:
    an **idle** interactive session settles here, where `SessionInfo::triage`
    (`tui/src/model.rs:249-254`) routes it to `NeedsInput` on the argument that a
    conversation waiting for its next prompt is a human's turn. On a rail a person scans
    for work that argument does not survive contact — every conversation anyone has
    finished reading is idle, so the group meant to hold "a machine is blocked on you right
    now" fills with sessions nobody owes anything, and a first live pass found exactly
    that. Intentional, and stated in `Ouroboros.Web.Live.Rail`'s own docs so the two
    surfaces can be reconciled deliberately rather than by accident.
  - **Markdown is Earmark *plus* an allowlist renderer**, not §3's "Earmark" alone.
    `escape: true` covers less than its name suggests, and this was measured rather than
    assumed: inline raw HTML is escaped, **block-level** raw HTML is parsed into a real AST
    node the option does not touch, and `[click](javascript:alert(1))` is Markdown's own
    link syntax whose `href` Earmark passes straight through. An agent message is untrusted
    input reaching a browser that holds a cookie for a surface that can start agents, so
    the AST is rendered against an allowlist of elements and per-element attributes and
    anything else is dropped.
- **W4 — composer.** ✅ **Landed.** Quick-start, send/follow-up/steer with the queue rules,
  turn envelope, interrupt, connection pill.
- **W5 — approvals.** ✅ **Landed.** Card with all optional sections, provider options,
  plan-exit, auto-approve with the question/computer-use carve-outs, suggested-rule row
  (`permissions.add`).
- **W6 — new-session form.** ✅ **Landed.** Pickers from providers/models,
  `workspace.browse` (method first, then the UI), sandbox + effort, ChatGPT account card.
- **W7 — machines (read-only)** ✅ **Landed**, + fleet status/doctor rendering +
  deferred-add empty state.

  **As built:** `fleet.status` named no fleet. The saved profile has always carried a
  `name` — `ouro fleet` writes it as a required field — but `Cluster`'s roster decoder kept
  the roster, the revision and the tombstones and dropped it, so the page headed itself
  with this machine's node: one member standing in for the whole. W7 shipped with the gap
  documented rather than papered over; **W8 retained the name** (`Cluster.fleet_name/0`,
  `fleet_status.fleet_name`, `nil` for a runtime in no named fleet).
- **W8 — polish to the removal checklist.** ✅ **Landed.** Notifications, theme, prefs file,
  docs (this as-built pass, README, the `DESKTOP.md` freeze note).

  **As built**, four notes:

  - **The link defect was not a missing rule.** A live pass found the machines page's back
    link in the browser's blue-then-purple, and the cause was structural: a W7 merge left
    `.ouro-new-refusal-detail` without its closing brace and the Machines section's comment
    without its opening `/*`, and CSS error recovery answered by swallowing **every rule
    from that point to the end of the file**. The whole Machines stylesheet was dead. 584
    tests passed over it, because every one of them asserted on markup. Both halves are
    fixed, the global `a` discipline was added as specified, and
    `Ouroboros.Web.StylesheetTest` now asserts that the file's braces balance and its
    comments close — the cheapest assertion in the slice and the one that matters most.
  - **The light theme had never been rendered by anything.** It shipped in W0 behind
    `[data-theme="light"]` with no way to reach it. The same test mechanises the audit:
    every colour in the file is a token, every colour token declared for dark is declared
    for light with a different value, the layers stack monotonically in both, light `--ink`
    clears 4.5:1 on all five layers and the semantic tones clear 3:1 on a card. One
    assumption the audit killed: light is **not** an inversion of dark's layer order. Both
    palettes go lighter forwards — the page recedes to a grey rather than to near-black,
    and in both themes a card is the brightest thing on it.
  - **The bell pushes an edge and decides nothing.** Three of the four rules between a
    session needing somebody and a banner appearing — the bell being on, permission being
    granted, nobody looking at the tab — are facts about a browser and live in `app.js`.
    What is pushed is which sessions have just *entered* the needs-you group. What was
    already waiting when the page opened is recorded rather than announced, and a request
    auto-approve answered never rings. Keys are the `request_id` for the open session and
    `<plane>:<id>` for every other row, because `interactive.list` carries no request id.
  - **The theme needed server help after all.** D10 files the theme under "per-browser
    conveniences in `localStorage`", which is true and insufficient: read after the page
    paints, it flashes. See D10's as-built note.
- **W9 — gpui removal** (§10), only after the checklist below is checked live. **Not
  started.** Nothing in this slice or its predecessors removed anything from the desktop;
  `docs/DESKTOP.md` carries the feature-freeze note that §10 calls for and is otherwise
  intact, because it is the inventory §4's parity map was built from.

**Removal checklist** (all verified in a real browser against a live daemon, plus one
tailnet-proxied session): quick-start → real session → reply renders; approval answered
each way incl. sandbox escalation + auto-approve carve-outs; resync survives daemon
restart mid-stream; screenshot renders; rename/delete gating; machines presence flips on
member up/down; two concurrent browsers; `read`-scope endpoint refuses every operate
control it hides.

**Status of the checklist: not yet walked end to end.** It is the gate on W9 and it is
still open. What W8 can say about it is narrower and worth separating from it: a live pass
was made over the pages, and the two defects it found — the swallowed Machines stylesheet
and the unstyled links it caused — are fixed. That is not the same as the list above, none
of whose lines has been signed off in a real browser against a live daemon. The suite is
headless by design (§0: "`Phoenix.LiveViewTest` is fully headless, which changes the
economics of every future surface slice"), which is exactly why this checklist is a
separate, human gate and not something a green suite is allowed to stand in for.

Two more items belong on it, added by W8 because they are the parts of it no test in this
tree executes: **the theme survives a reload without flashing**, and **a needs-you
notification arrives while the tab is hidden and focuses it when clicked**. Both are
`app.js`, and nothing in this repository runs JavaScript.

## 10. GPUI removal (D13)

**Executed at W9.** Everything below is done as written; `docs/DESKTOP.md` is now a
tombstone. Two things went beyond this plan, both because the seam's last caller left with
the desktop: `App::configure_reasoning_effort` (the native picker's session-default write;
the TUI's per-turn `/think` is untouched) and the whole client-side `runtime.models`
pipeline — `fetch_models`, `Tag::Models`, `App::models` — which had no TUI reader at all.
`ModelsCatalog` and its decode tests stay in `model.rs` beside `decode_artifact`, on the
same reasoning: they pin a wire shape the runtime still serves. The lockfile lost 593
packages and gained nothing; no surviving crate moved versions.

- **Delete:** `tui/src/desktop.rs`, `tui/src/desktop/machines.rs`,
  `tui/src/desktop_design.rs`, `tui/src/desktop_main.rs`; the `[[bin]] ouro-desktop` and
  `desktop` feature + its four deps (`cocoa`, `gpui`, `gpui-component`,
  `gpui-component-assets`); `tui/macos/Info.plist`; `scripts/bundle-macos-desktop.sh`;
  make targets `gui`, `gui-stop`, `desktop-dev`, `desktop-app` and the `dev.sh` gui
  functions; the CI `desktop` job (`ci.yml:123-149`). The release workflow never shipped
  the `.app`, so `release.yml` is untouched.
- **Reducer seams that collapse:** `desktop_restored_draft` + the `desktop:` flag on
  `PendingFirstMessage`/`issue_quick_start`; `desktop_machines_open`;
  `App::desktop_artifacts` + `request_desktop_artifacts` (the web fetches artifacts
  in-process; the TUI renders placeholders and keeps the `model.rs` artifact
  decode + tests); the `desktop_*` control methods whose only callers were gpui.
- **Deleted only after W2:** the `desktop_cell` projection + `DesktopCell*` types and
  `tui/tests/surface_contract.rs` — their lock transfers to the golden corpus, so corpus
  first, deletion second.
- **Kept:** `tui/src/desktop_cli.rs` (`ouro desktop doctor` is computer-use tooling,
  ungated — `tui/src/lib.rs:17`); `fleet_add.rs` and the TUI Machines stepper;
  `sorted_fields`/`sorted_json` and the `BTreeMap` availability field — the gpui
  `preserve_order` motivation dies, the determinism argument stands; the comments get
  rewritten to say so.
- **Docs:** `DESKTOP.md` replaced by a tombstone pointing here; README's client matrix
  updated; `AGENT_EXPERIENCE.md` client rows re-scored.

## 11. Risks and open questions

- **Projection drift** is the standing risk; the corpus (§6) is the control. The corpus
  is only as good as its coverage — every new event kind or approval field must land as a
  fixture in the same PR, which the named-fixture coupling enforces on the Rust side and
  the drift test on the Elixir side.
- **Latency over tailnet**: LiveView round-trips per interaction; typing stays local but
  every send/click crosses the wire. Fine on a tailnet RTT; unusable over bad links is
  accepted (the TUI over SSH is the fallback, as ever).
- **Mailbox growth on wedged views** (§8) — mitigation stated; measure in W3 with the
  streaming-test load recipe before inventing anything.

  **As built: still unmeasured, and therefore still open.** W3 built the mitigations —
  O(delta) stream rendering inside a bounded window with floors on trim, deltas coalesced
  to one projection per 80 ms flush, and crash-and-resync as the lag path — but no test in
  this tree drives a view hard enough to observe a mailbox growing, and there is no
  `Process.info(:message_queue_len)` self-check anywhere. §8's instruction not to invent
  anything before measuring still stands; nobody has measured. This is the one risk in this
  list that a slice was supposed to close and did not.
- **Two operate surfaces**: gateway + web double the credentialed perimeter. Same
  credential, same postures, but the security-review pass in W0 should walk the Phoenix
  endpoint with the same eyes that reviewed the listener (frame limits → body limits,
  upload handling off by default, no code-reload endpoints in prod).
- **Browser regression coverage has a CI gate.** `test/browser/operator-flow.spec.js`
  drives the password recovery form, progressive session setup, desktop and mobile
  session layouts, empty-send protection, native modal behavior, and contextual document
  titles in Chromium. `playwright.config.js` starts the real Phoenix endpoint against an
  isolated data directory; `.github/workflows/ci.yml` installs Chromium and runs the
  suite. This closes the earlier W8 gap where `app.js` had only been exercised once under
  a throwaway fake DOM. It does not replace the BEAM-side LiveView tests; the browser gate
  covers browser-owned behavior while those tests continue to cover server transitions.
- **Open**: whether `Web.Call` should also write to the effect ledger the way operate
  calls via the gateway are audited today (v1: same log line, no ledger change); whether
  the defaulted posture should eventually serve the web on the tailnet automatically once
  a `tailscale serve` handshake exists (out of scope here); server-side fleet-add (its
  own spec, if wanted).
