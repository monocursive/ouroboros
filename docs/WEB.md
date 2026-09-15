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

> **Superseded in part, September 2026.** The provider picker this document specifies —
> in the new-session form, in `/settings`, and in `web.prefs.json`'s `[defaults]` — is
> gone, and so is the SpaceXAI subscription card and the `grok.account.*` calls behind it:
> `:native` is the only provider and `interactive.start` no longer takes a `provider`
> parameter. See [the core reduction](proposals/core.md) §3 D2. The ChatGPT device-code
> card stays, because the native `openai_codex:` model lane needs it, and so do the
> Anthropic and xAI API-key cards. The paragraphs below are left as the dated spec they
> are, per this document's own **As built** convention; §6's "provider aliases now have a
> runtime owner" is now "there are no provider aliases", and the semantic-record contract
> it describes is unchanged.

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
verified by eye" (the removed `docs/DESKTOP.md`); every visual claim needs a human or
a person driving a live window. A browser surface is strictly better at the thing
the desktop uniquely provided — a graphical composer — and adds what gpui structurally
never could: access from the Linux laptop, the
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
  already calls `Methods.invoke/2` directly.
- **Four methods are connection-answered, not dispatched**: `hello`, the two
  subscribe/unsubscribe verbs, and `runtime.shutdown` (`conn.ex:143-149`,
  `lib/mix/tasks/ouroboros.protocol.docs.ex:64-71`).
- **Subscriptions register the calling process.** "The plane registers `self()` and
  monitors it" (`methods.ex:1069-1084`); events arrive as
  `{:ouroboros_interactive_event, id, %Event{}}` sent only after the durable checkpoint
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
  `Cluster, OpenAIAuth, gateway_children(), Wasm.RuntimeSupervisor, Mcp.Supervisor`. Absent gateway config means no child at all
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
- **There is no machine-add anywhere.** Enrolment was deleted with the rest of the fleet
  product (`docs/proposals/core.md` §3). The gateway's fleet verbs are `fleet.status`,
  `fleet.doctor`, `fleet.tags` and `fleet.forget_session_owner`, all of which read or
  label an existing cluster; `docs/FLEET.md` is what an operator follows to add a second
  machine by hand.
- **Two corrections to prior internal notes**: `fleet.sessions` does not exist
  (the fleet-wide list is `interactive.list` fanning out over `:erpc`,
  `lib/ouroboros/gateway/methods/present.ex:55-113`), and `OUROBOROS_DIST_TAILNET` was
  spec-only in an earlier `docs/FLEET.md` and was never implemented; the rewritten
  cluster document no longer names it. This document mirrors the *pattern* of the
  implemented refusals, not that flag.

## 2. Architecture

### D1 — Namespace, placement, protection

New modules live under `Ouroboros.Web.*`. The supervisor `Ouroboros.Web` is appended as
the **final** child of the `:core` tail, after `Mcp.Supervisor`: under `:rest_for_one` its
crash then restarts nothing, and it is the second child a stranger can reach, so it sits
downstream of everything — the same argument the gateway already carries
(`application.ex:199-234`). Gating copies `gateway_children/0` exactly: a
`web_children/0` returning `[Ouroboros.Web]` iff `Ouroboros.Web.Config.enabled?()`;
absent configuration means no endpoint at all, so tests, `:builder`, and `:signer` never
acquire one.

`"Elixir.Ouroboros.Web."` joined `@protected_prefixes` in
`lib/ouroboros/upgrade/verifier.ex` in the commit that created the namespace. That list
and the verifier holding it went with the BEAM hot-patch lane in
[the core reduction](proposals/core.md) §4 A1, and nothing replaced them, because no lane
is left to gate: lane W is the only rollout, and a lane-W capability "introduces no BEAM
module and no atom" ([`capability.ex:5`](../lib/ouroboros/wasm/capability.ex)) — its
identity is the sha256 of its bytes, the signer takes a lowercase component name, one of
two kinds and the one world that kind requires
([`artifact.ex:140`](../lib/ouroboros/wasm/artifact.ex),
[`policy.ex:328`](../lib/ouroboros/upgrade/signing/policy.ex)), and the one module a
deploy may start is the shipped wrapper ([`mesh.ex:46`](../lib/ouroboros/mesh.ex)).
Nothing under `lib/` calls `:code.load_binary/3`, `Module.create/3`,
`Code.compile_string/2` or `Code.eval_string/2`. The sentence stands — an operator surface
must not be hot-patchable by the thing it operates — and is true by absence rather than by
a gate. Honest limit: the two-node rollout test proves a deploy *adds* no capability
module on any peer
([`rollout_two_node_test.exs:164`](../test/wasm/rollout_two_node_test.exs)); that it
cannot *replace* one under `Ouroboros.Web.` rests on that grep, and no test pins it.

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

**As built, first-use project context (September 2026):** `ouro web` captures the
invocation's current directory before starting or adopting a daemon and adds it as an
independently encoded `workspace` parameter to the token exchange. After successful GET
authentication, `/auth` redirects to the fixed local `/new?workspace=…` route without the
token; POST authentication and GET without project context retain `/`. This is a form
seed, not an arbitrary redirect or a daemon-global preference change. It selects the
invoking computer's project even when an existing daemon has another cwd. Saved local
model/thinking choices survive; saved remote-machine model choices do not carry over.
Explicit form edits then win. Without a handoff, saved choices remain available; without
a saved project, the browser requires an explicit absolute project path. Invalid supplied
context clears the project rather than falling back to saved state or an extracted release
directory. Significant spaces remain path bytes; existence and workspace admission are
checked at start.

The model picker includes the configured model before the snapshot cap and keeps the
current/saved exact ID accessible during search. A model absent from the snapshot has
unknown metadata and unverified access, not invented pricing or an unsupported verdict.
Custom accepts an exact `provider:model` ID; the selected ID and thinking level are sent
without model substitution. This is request selection, not proof of vendor entitlement.

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
- **Closed:** `web.json` now carries `birth` when `RuntimeOwner` has one, so staleness
  here is the same incarnation check as `gateway.json`. A recycled PID cannot make a
  dead endpoint look live. A file that omits the field is a legacy publication: liveness
  for those is still PID-only, and `ouro web` documents that rather than silently
  upgrading it. Adding `birth` to `Ouroboros.Web.Publication.document/2` closed the gap.

  **As built:** `document/2` claims `RuntimeOwner` the way the gateway listener
  does and writes `birth` when the claim has one. A registered owner that cannot answer
  refuses the boot rather than publishing a pid this VM invented. `ouro web` uses the
  same incarnation check as `gateway.json` when the field is present, and PID-only
  liveness only for a legacy file that omitted it.

## 3. Dependencies and assets (D6)

Added to `mix.exs`: `phoenix`, `phoenix_live_view`, `bandit`, `phoenix_html` (current
stable lines at implementation time; `phoenix_pubsub` arrives transitively through
Phoenix). Nothing else is required at runtime.

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
  dark/light palettes, layer order, semantic tones — the removed `docs/DESKTOP.md`); it ports
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

**The parity target was the GPUI desktop surface, not the seven-tab TUI**, and W1–W3 moved
it: `docs/design-qa/ui-review-2026-09-15.md` §4 counted the dashes against the terminal
client, and the slices closed the ones the gateway already served. The table below is that
matrix as it now stands. "Served" is the method `Ouroboros.Web.Call.available?/2` asks
about, which is the same question `hello` answers for a socket client; a row with no method
is a client-side or presentation fact and says so.

| Capability | TUI | Web | Served |
|---|---|---|---|
| New session, switch, close | `ctrl+x n`/`N`/`l`, `/new`, palette | `/new`, the rail, the row menu, palette **Session** | `interactive.start`, `interactive.close` |
| Rename session | `ctrl+r`, `/rename` | row menu, palette | `interactive.rename` |
| Delete a finished session | `ctrl+x k`, `/close` | row menu, palette (only once the session has ended) | `interactive.delete` |
| Interrupt | `esc` | the composer's button, `esc` **inside the composer**, palette | `interactive.interrupt` |
| Queue follow-up | `Enter` while busy | the same `Enter`; the button says "Queue" while a turn runs | `interactive.follow_up` |
| Steer | `alt+enter`, `/steer` | the composer's second submit button, palette | `interactive.steer` |
| Effort | `/effort` (next turn only) | the thinking picker, and a per-turn "next turn only" | `interactive.configure` |
| Sandbox | `/sandbox` | the file-access picker — drawn **only** where the session reported a posture | `interactive.configure` |
| Model change mid-session | `ctrl+x m`, `/model` | the composer's "Change" row, palette | `interactive.configure` |
| Plan mode | `/plan` | the composer's toggle, palette | `interactive.configure` |
| Auto-approve | `ctrl+x A`, `/auto-approve` | the toggle in the composer's status row | client-side; answers with `interactive.respond_approval` |
| Approvals, suggested rule | the modal's fifth answer | the card's "Remember" | `interactive.respond_approval` + `permissions.add` |
| Backtrack | `esc esc`, `ctrl+x g`, `/backtrack` | a dialog over the held `input_accepted` turns, palette | `interactive.send_message` (resend) / `interactive.fork` |
| Fork | `/fork` | the backtrack dialog's second verb, and its own palette row | `interactive.fork` |
| Rewind | `/rewind` | two screens, warning first, palette | `interactive.rewind_points`, `interactive.rewind` |
| Compact | `ctrl+x c`, `/compact [focus]` | a one-question dialog, then the report, then a fresh context read | `interactive.compact` |
| Handoff | `/handoff <prompt>` | a one-question dialog; opens the child and says whether it was `ready` | `interactive.handoff` |
| Context | `/context` | a panel whose first line is `source`; the vitals meter reads the same answer | `interactive.context` |
| Event ledger | `/details`, `ctrl+x d` | a panel, one row per held event, expandable to the wire object | `interactive.event_detail` (for an excerpted leaf) |
| Export transcript | `/export [--json] [path]`, `ctrl+x [`, `ctrl+x v` | a **download route**, text or NDJSON — see below | `interactive.replay` |
| Copy last message | `ctrl+x y`, `/copy raw` | a copy button on every settled agent message, and two palette rows (rendered text, source Markdown) | none — the browser's clipboard |
| Operator shell `!cmd` | yes | yes, claimed by the composer, with the refusal and its `suggested_rule` kept on the composer | `workspace.exec` (+ `permissions.add`) |
| MCP servers | `/mcp` | a panel: the node's servers and the entries its loader refused, read fresh on open | `mcp.list` |
| Cost / usage | `/cost` overlay, the footer | the vitals column and the per-turn cells | `interactive.info` |
| Changed files (`/diff`), raw copy mode (`/raw`) | two overlays | inline diffs only | n/a — presentation, see D10 |
| Verbose expand-all, plan panel | `ctrl+o`, `ctrl+t` | per-cell disclosure; the plan is an inline cell | n/a |
| Image paste, file picker, drop | yes; clipboard and `/attach` | yes; composer and first message | `attachment.*` and model image support |
| `@` file completion | yes | — | workspace index |
| Budget warning | the footer's `WARN` past `[budget] max_cost_usd` | — | client-side, and `[budget]` is the terminal client's file |
| Capabilities preview / admit | palette + `/capabilities`, `/preview`, `/admit` | — | `capabilities.list`, `.preview`, `.admit` (served, unexposed) |
| Dashboard / nodes | the Dashboard tab | `/status`, linked from the top bar on every page | `runtime.status` |
| Logs | the Logs tab | — | **nothing**: the gateway's method table has no log-reading verb at all |
| Upgrades | the Upgrade tab | — | `wasm.*`, `signing.decisions` (served, no design) |
| Audit search, evidence streams, bundle export | — | `/audit` | `audit.*` |
| Workspace browser | the `f5` location dialog | "Browse…" on `/new` | `workspace.browse` |
| Notifications | the terminal bell, `[notifications]` | the top bar's bell, on every page | none — the browser's Notifications API |
| Theme | `/theme`, `ctrl+x t` — six palettes | the top bar's toggle — two | n/a |
| Help / key map | `?`, `/keys` | `?` opens the shortcut sheet; palette **Client** | n/a |
| Settings | four sections (`F1`–`F4`) | four sections | `runtime.status`, `runtime.providers`, `credentials.*` |

**Logs and upgrades are absent for two different reasons, and only one of them is a
decision.** No method on the wire reads logs: the terminal client's Logs tab shows the
output of the runtime **it spawned**, which a browser attached over a socket has no
equivalent of, and `docs/TUI.md` §6 already defers streaming them. Upgrades are the other
kind of absence — `wasm.deploy`, `.upload`, `.sign`, `.rollback`, `.status`, `.list` and
`signing.decisions` are all served at operate scope, and there is simply no design for what
a browser should show for a signing decision. That one is deferred, not impossible, and it
is on the parity plan's own deferred list.

**The export is a route, and it says how much of the session is in it.**
`GET /s/:plane/:id/export?format=text|ndjson` ([`router.ex:56`](../lib/ouroboros/web/router.ex),
[`transcript_export_controller.ex`](../lib/ouroboros/web/transcript_export_controller.ex)) —
a controller rather than a LiveView, like the audit bundle, because it answers bytes, and
inside the authenticated scope so the cookie that opened the deck is the only thing that
opens it. It does **not** read the deck's held window, which is a fact about one browser
tab: it calls `interactive.replay` itself and builds a `Watch` out of the answer, so the
file and the page get the same floor inference, the same dividers and the same projection.
One reading, two renderings.

The bound is stated rather than left in the code. `interactive.replay` answers at most
`Contract.replay_limit/0` (500) events per call, so the controller pages from an exclusive
cursor until a page comes back short and stops at **40 pages either way** — twenty thousand
events. Both forms carry an `x-ouroboros-export-extent` response header naming what is in
the file: the count, the sequence range, whether anything was dropped below the floor, and
whether the page's own ceiling cut it. The text form carries the count and the sequence
range in its own header band, and its **last line** is the only place that file claims
anything about completeness: `complete: no history was dropped from this session`, or
`incomplete:` and the sequence the runtime no longer retains through — plus a line naming
the twenty-thousand-event ceiling where it was hit, and a count of events this build could
not decode, which are counted rather than shown. The NDJSON form adds nothing
and reshapes nothing — a leaf the gateway excerpted travels as `{"_excerpt": …, "_bytes": n}`,
because that is what a client was sent, and rewriting it as the prefix alone would produce
a file that looked whole and was not. `interactive.replay` is a read-scope method, so a
read-scope endpoint exports exactly as an operate one does. There is **no file on the
daemon's disk**: the TUI's `/export` writes one `0600` under the data directory, and the web's
equivalent is a download to the reader's own machine.

### The command palette and the one catalogue

[`Ouroboros.Web.Commands`](../lib/ouroboros/web/commands.ex) is every verb this surface can
run, as one list — thirty-five rows in the five groups the parity plan fixes (Session, Turn,
Conversation, Runtime, Client), in that order and sorted by nothing else. The palette, the
shortcut sheet and (at S1) a shared `priv/ui/commands.json` read it rather than each keeping
a list of their own: a verb added to the web is added here or it exists nowhere a reader can
find it.

**Every row is gated twice, and a row that fails either is not drawn.** The gate is a
one-argument function of the deck's assigns, and both halves are load-bearing: does this
build serve the method *at this scope* (`Call.available?/2` — a read-scope endpoint lists no
mutating verb), and does the session's own state allow it (an interrupt with no turn
running, a delete of a session that has not ended, a steer into a transport that declared it
cannot be steered). That is the honesty invariant in its narrowest form: the palette is a
list of things that will happen, not a menu of things that might be refused. `available/1`
draws it and `run_command/2` asks the same question again before doing anything
([`deck_live.ex:1081`](../lib/ouroboros/web/live/deck_live.ex)), so a row that went stale
while the modal was open cannot be run by pressing Enter on it, and a hand-made
`palette-run` is refused by the same line. A gate that raises answers "not offered" rather
than taking the page down.

The filtering is the server's too. `Commands.search/2` matches the label, the slash
spelling, the shortcut and the group's own heading — so typing `turn` narrows to the Turn
group, exactly as the terminal palette does — and it filters without reordering, so a row's
flat position and its position on screen are the same number and `↑`/`↓` move one visible
row. Nothing about which verbs exist is sent to the browser to be narrowed there: a
client-side filter would need the whole ungated catalogue in the DOM, and a row the runtime
cannot serve would then be one broken selector away from being drawn.

### Keyboard

The document-level keys — `⌘K`, `?`, `n`, `[`/`]` and the composer's `Esc` — are
[`app.js`](../priv/static/web/app.js)'s `Keys` hook, on an element inside the LiveView
because a listener outside a hook has nothing to `pushEvent` to. That element is rendered
by the deck and nowhere else, so **these are the deck's keys**: `/settings`, `/new`,
`/status` and `/audit` get the top bar and the bell, not the palette. The rest of the table
is noted where it belongs to something else — the palette's own `<dialog>`, the composer's
hook, or a listener older than either.

| Key | What it does |
|---|---|
| `⌘K` / `ctrl+K` | opens or closes the palette, from anywhere on the page **including inside the composer** — which is where a person is most likely to want it. Any *other* open `<dialog>` takes the key entirely, so ⌘K cannot put a palette over a question nobody has answered |
| `?` | the shortcut sheet — only when focus is not in an editable field, and not behind another dialog |
| `n` | a new session (the same gated `session.new` row the palette runs) |
| `[` / `]` | the previous or next session in the rail |
| `/` | focuses the rail's search box. Not the hook's — it is a separate document listener that predates it, and it does only the focus move, because that should never cost a round trip; LiveView owns the query and the filtering |
| `Esc` **in the composer** | interrupts a running turn, and only where a control on screen says one is running (`[data-ouro-interrupt]`). Everywhere else `Esc` keeps its existing meanings — a `<dialog>`'s native cancel, which the `Modal` hook turns into a close event |
| `↑` / `↓` | move the palette's selection. Bound with `phx-window-keydown` on two elements that exist **only while the palette is open**, which is what scopes a window binding to a modal; a bare `phx-keydown` would send a message for every character typed into the query box |
| `Enter` | runs the selected command — the palette's own form submit, not the hook — or sends the message being written, which is the `Composer` hook's |
| `shift`+`Enter` | a newline in the message being written (the `Composer` hook) |

**⌘N and ⌘. are deliberately not bound**, and the claim that they were is gone from this
document. They are the browser's and the operating system's, and a page that stole them
would be taking a window away from somebody to save them one keystroke. An IME's composing
keydowns are ignored, as they are for `Enter`.

### One top bar, on every page

[`Ouroboros.Web.Layouts.topbar/1`](../lib/ouroboros/web/layouts.ex) is rendered by all five
LiveViews. Until W1 it existed only on the deck, which is why the review found three header
treatments, no route to `/status` from anywhere, and a connection pill and a bell that a
person filling in `/new` or reading `/audit` could not see (§3.1). The spokes keep their
"← Sessions" breadcrumb *below* it rather than instead of it.

What it may say is bounded the same way everything else here is. The machine presence dots
and the day's token total are the deck's own measurements; every other page renders the bar
without them and therefore draws neither, because a presence readout on `/settings` would be
a claim about cluster connectivity made by a page that never asked. Absent, not defaulted,
applies to chrome too. `aria-current="page"` marks exactly one element per page — the
section link, not the wordmark as well — and a spoke is marked at its section, because that
is where the reader is.

### Names and refusals (D7's sixth ground rule)

[`Ouroboros.Web.Presentation`](../lib/ouroboros/web/presentation.ex) is the one place an
internal name becomes a word a reader was meant to see, and the TUI's `ui::presentation` is
its twin. `node_label/2` reads `nonode@nohost` (and `nil`, and `""`) as **"this computer"**,
and a real `release@host` as its **host** — the half before the `@` is the release name that
every machine in a fleet shares, so shortening `ouro@alpha` and `ouro@beta` both to "ouro"
would put the same word under two presence dots. Where `runtime.status`'s fleet roster names
a machine, *its* label wins. Something reported that this build cannot read is
`"not reported"` rather than "this computer": absent and unreadable are different facts.

`refusal/1` turns atoms, `{:error, reason}` pairs and the gateway's numeric codes into
sentences — `:audit_disabled` became `/audit`'s first line verbatim before W1 (§3.5), and
`-32004` is "That part of the runtime is not available here." A term it has no sentence for
is said **in words** rather than given a meaning nobody wrote down. It translates; it never
invents.

### The composer's status row and the per-session controls

The two standing risks the terminal client keeps permanently in its footer are on the
composer's bottom edge rather than one click behind "Session details", where the review found
them on every viewport (§3.2): the **auto-approve toggle**, which says on its own face that
it lasts only for this session while it is open and that questions and screen control still
ask, and the **file-access posture** — named only when it is `unrestricted`, because the
"Change" summary states it one line above and the vitals a third time, and three statements
of one fact in one band is noise. The rest of the vitals are a **real third grid column**
above 1100px — `.ouro-columns:has(> .ouro-vitals)`, which is what the moduledoc and seven
stranded CSS rules had always expected — and the `ouro-vitals-mobile` disclosure only below
it, where the column is hidden. Before W1 that disclosure was the only home the vitals had,
on every viewport, and the auto-approve toggle was inside it.

The pickers under the composer follow the same rule the TUI's do: **a sandbox picker is
offered only where the session reported a posture.** One defaulted to `workspace_write`
because nothing said otherwise would be this page telling an operator what a session is
allowed to do on no evidence. The sandbox and thinking pickers are marked-button groups
rather than `<select>`s on purpose — a `<select>` carries its own client-side value and
would show the operator's pick whether or not the transport accepted it, while a button
group has no state of its own, so the mark moves only when the runtime's next answer says it
moved. The model control is a searchable `<select>` because a 113-row catalogue is not a
button group, but the sentence saying which model this session is running is still drawn
from the session's own re-read.

### Capability gates: silence is not a refusal

Four keys of `info.options.capabilities` gate controls here — `steer`, `dynamic_model`,
`dynamic_configuration` and `fork` — and all four are read the way `Capability::offered`
reads them in the terminal client:

- **boolean `false` is the only refusal.** It is the one value the runtime sends on purpose
  to say a transport cannot do this, and it is the only one that takes a control off screen;
- **a string is a mechanism, not a verdict** — `"native"`, `"managed"` are declarations that
  it *can*;
- **absence, `nil`, and a shape this build cannot read are silence**, which keeps whatever
  the client did before the declaration existed. Hiding a working verb on a gateway's
  silence would be this surface inventing a ceiling it was never told about.

`dynamic_model` and `dynamic_configuration` are asked **separately**, because a transport can
serve one and refuse the other: a model-only transport keeps its model picker and loses the
plan, effort and sandbox controls. A fifth key, `transport`, is read differently and on
purpose — it is a *label* rather than a yes/no, so `native_transport?/1` compares it and
**silence stays offerable**. Four verbs are gated on it (compact, handoff, rewind and the
rewind's own points), because only a native session hands this runtime the conversation to
work on.

### What the desktop surface had, and how the web took it over

The original target, kept because it is where most of these surfaces came from and the
only record of the contracts they were ported under. Inventory source: the removed
`docs/DESKTOP.md` and the verified feature map of the GPUI client's `tui/src/desktop.rs`,
deleted at W9. Neither file is in the tree; this table is what was read out of them.

| Desktop feature (today) | Web treatment |
|---|---|
| Session rail: triage-ordered rows, presence, context menu, rename/delete dialogs with gating ("Finish session to delete") | LiveView list over `interactive.list` polled at the TUI's ~3 s cadence while mounted; triage/sort rules ported from `tui/src/ui/app/session.rs` (`triaged()`); delete gating recomputed server-side by the same rule (`terminal? or last_known`, and only if the verb exists) |
| Transcript: markdown messages, thinking, tool cells with collapse, diffs, plan, subagent rows, dividers, streaming spinner | the Elixir projection (§5) rendered as LiveView streams; tool-output collapse keeps the desktop's 12-line/head-7/tail-4 budget; folded child rows show elapsed time, last activity, returned refs, deliveries and retained-work errors |
| Composer: quick-start, three placeholder states, send/stop, queue | same reducer semantics, one Elixir implementation: quick-start issues `interactive.start` + first message; turn envelope stays "plain string unless structured" (`tui/src/model.rs:2823-2868`) |
| Auto-approve dropdown + approval-card switch | client-side-of-the-server: the LiveView answers `approve, once, actor: "automation"` per request, never `plan_exit`/`question` (`ui/transcript.rs:441-449`), idempotent against replay — the TUI's exact carve-outs, asserted by shared fixtures (§6) |
| Approval card: kinds, choices, provider options, suggested rule, subagent attribution, diff excerpt | one card, optional sections, rendered from the same payload contract (`ui/transcript.rs:309-482`); respond params keep the closed envelope incl. the vendor-option decision table (`ui/transcript.rs:284`) and the plan-choice fallback mapping (`model.rs:2673`) |
| Sandbox picker, thinking picker — "absent, not defaulted, when the runtime said nothing" | identical rule; `interactive.configure {sandbox_mode}` / `{reasoning_effort}`; label follows the session row after re-list, exactly as the removed `docs/DESKTOP.md` states it |
| New-session form: provider/model pickers with search, workspace + Browse…, sandbox, effort | `runtime.providers` / `runtime.models` (fetched on form open, never on cadence — `mod.rs:107`); a `<select>`/combobox has none of the gpui-component filtered-cache pathology, so the authoritative-choice workaround dies with gpui; **Browse… becomes `workspace.browse`** (§7) — the native picker browsed the *client's* filesystem, which was only ever correct when client and daemon shared a machine |
| ChatGPT / Grok account and API-key cards | ChatGPT uses `account.read` / `account.login.*`. Native `grok:` models read the local Grok OAuth sign-in and call the subscription endpoint directly; the card explains `grok login` and refreshes credential status through `runtime.providers`. Native `xai:` models use `credentials.xai.set` and API billing. Tokens never reach the page; Grok alone renews its rotating credentials. |
| Settings | `/settings` groups subscription and API connections first (including Grok local sign-in, provider marks, status/source, refresh and setup guidance), editable new-session defaults second, the detected provider/model catalogue third, and read-only boot/runtime facts last. Secret values never enter LiveView state; environment-owned configuration is shown as read-only rather than rendered as a control that cannot take effect. |
| Window title, connection pill, notices | page title, a connection indicator driven by LiveView socket state, one notice slot with the same "Info is deliberately dropped" rule |
| Keyboard: Enter/Shift-Enter, ⌘., ⌘N | Enter and Shift+Enter are the composer's, as they were. **⌘. and ⌘N were never built and are not going to be** — they are the operating system's and the browser's. What the web binds instead is above: ⌘K/ctrl+K, `?`, `n`, `[`/`]`, `/`, and Esc-in-the-composer |

**D10 — deferred, and three of these are now done:**

- ~~`workspace.exec`~~ (W3: `!cmd` in the composer), ~~the ledger~~ (W3: the event details
  panel) and ~~`/export`~~ (W3: the download route) have landed. What is left of the
  original list is **`runtime.shutdown`**, the **upgrade tab**, and **`/raw`** — the
  whole-transcript copy mode, which is a second renderer rather than a flag inside the
  first and has no browser equivalent worth the name, since a browser selection already
  yields logical lines.
- **`[statusline]` must never be ported**, and this is not a scheduling decision. It runs a
  shell command on the client's machine (`tui/src/config.rs:295`); server-side that would
  mean shell execution on the daemon host, configured from a browser. `!cmd` is the verb
  that runs a command in the workspace, it goes through `workspace.exec` and the permission
  engine, and it is refused by name where a rule says no — which is exactly what a
  statusline would have bypassed.
- **Web-side prefs.** Form defaults (`[defaults]` provider/model/workspace) get a
  server-side home in the data dir (`web.prefs.json`, atomic 0600 writes), because
  `config.toml` belongs to the terminal client's machine. Per-browser conveniences
  (collapsed sections, theme) live in `localStorage`.

  **As built** (W8 — `lib/ouroboros/web/prefs.ex`), with three corrections:

  - **Five keys, not three.** `sandbox_mode` and `reasoning_effort` are stored beside
    provider/model/workspace. They are choices a person makes the same way and about the
    same work, and leaving them out would have made the file a partial memory of a form
    somebody had just filled in.
  - **A stored default is sendable**, and this is the one semantic here worth arguing
    about. The removed `docs/DESKTOP.md`'s new-session paragraph read "What the file
    supplies is where the control *starts*; an explicit pick is what gets sent, and an
    untouched panel with **no stored default** states no posture at all" — and the GPUI
    client implemented exactly what that last clause forces:
    `self.new_sandbox.or(configured_sandbox)`, under the comment "the operator's pick,
    else the stored default, else nothing" (`tui/src/desktop.rs:2264-2269`, deleted at
    W9). The web matches it. "Absent, not defaulted" keeps its
    meaning: what never reaches the plane is what the operator has never chosen, this time
    or last. A file that was drawn but not sent would show one posture and request another.
  - **Notifications are not a later slice; they landed in W8** and reached every page in
    W1. A top bar bell, off by default and off is the only state it can be born in —
    asking for notification permission is a thing a person does on purpose, so enabling it
    is what asks the browser, and `app.js` re-checks the permission every time it would
    post rather than silently keeping a promise it cannot keep. It posts one notification
    per session **entering** the needs-you group while the tab is hidden. What was already
    waiting when the page opened is *recorded rather than announced*, so a page opened in a
    background tab does not post one banner per pending approval on arrival and a reconnect
    does not do it again; a refused or unreadable `interactive.list` rings nothing and
    leaves the announced set alone, because a page that cannot see the group must not claim
    it is empty. The arithmetic is
    [`Ouroboros.Web.NeedsYou`](../lib/ouroboros/web/needs_you.ex), and the four spokes get
    it as an `on_mount` hook that polls `interactive.list` once every three seconds — the
    deck's own cadence. The deck does **not** use the hook: it holds a live subscription and
    recomputes on every redraw, so its bell fires the moment a request arrives rather than
    up to three seconds later. What it shares is the arithmetic, so there is one definition
    of "has just entered the group" rather than two that can drift. Reduced-motion was
    already honoured by the streaming pulse. Keybinding remapping is still a later slice.

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
  applied here to tool and status details, with the same numbers (64 KiB text/value, 2,048 nodes,
  depth 32, 128 KiB diff, 256 file changes, 64 plan steps — `transcript.rs:22`). Input is
  the in-process `%Ouroboros.Interactive.Event{}` — uncapped, so these ceilings are
  load-bearing for those details. User and agent message text stays complete.
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

Provider aliases now have a runtime owner, `Ouroboros.EventPresentation`. Gateway events
carry an additive versioned semantic record for common transcript concepts. The terminal
reads that record directly, retaining an explicit legacy parser for older servers and
unsupported versions. The web uses the same runtime projection with its own cell layout.

`test/support/semantic_corpus.json` holds expected semantic records consumed by both
`test/ouroboros/web/corpus_parity_test.exs` and `tui/tests/presentation_corpus.rs`. The Rust
suite verifies these records without consulting provider fields again. Golden event
fixtures and platform-specific cell tests retain coverage of raw details, local grouping,
approval dialogs, and unknown-event fallbacks. See [runtime simplification](SIMPLIFICATION.md)
for the version and compatibility boundaries.

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
order: LiveView sends changed cells via streams; text deltas coalesce per render frame;
and a LiveView that dies under load is cleaned up by the plane's monitor and recovers on remount via
`subscribe(cursor)` — crash-and-resync **is** the lag path. If profiling ever shows
mailbox growth on a wedged view, the remedy is a `Process.info(:message_queue_len)`
self-check that kills the view, not a new protocol.

**As built:** DeckLive now self-checks mailbox depth against `Watch.window/0` (2,000)
on plane events and the 80 ms flush. A lagged view drops queued plane events, notes
`:client_dropped`, and resubscribes from the contiguous cursor — the same repair as
`:DOWN` — so the operator keeps the page. Crash-and-remount would also empty the
mailbox; resubscribe is preferred. `Watch.mailbox_lagged?/1` is the predicate. No new
wire protocol, no Wire byte caps.

The conversation projects the full retained ledger before paging complete display cells.
Streamed agent replies retain their full accumulated text, including beyond 128 KiB.
It initially draws the latest 50 cells; scrolling near the top or selecting **Load earlier
messages** prepends another 50. Already loaded cells stay visible as new output arrives,
and the browser anchors the cell being read when a page is prepended or a replay repairs
a gap. Cell identities, expansion keys and review links follow their originating events,
so inserted history cannot retarget them. Automatic loading and the button share one
in-flight request; the reading anchor is captured before stream deletions. A session change
resets the page and follows the newest output. The mounted view retains all delivered
events instead of imposing its former 2,000-event trim; events the runtime itself has
already pruned still appear as an explicit history-gap divider. Retention and projection
cost therefore grow with the mounted conversation, while older DOM content loads only
when requested. Closing the view releases its retained history.

Session lists, status, providers, models: polled with the TUI's cadences and its
visibility rule ("Only the visible tab" — `ui/app/mod.rs:1912`), which for LiveView means
"only mounted views poll, each for what it shows." Models are fetched where a picker will
read them, never on a cadence.

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
  - **`web.json` carries `birth`** when `RuntimeOwner` has one, so staleness is the
    same incarnation check as `gateway.json`. A legacy file that omitted the field
    stays PID-only; see D14.
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
  - **`NEEDS YOU` matches the TUI's triage.** An idle session settles on either plane;
    `SessionInfo::triage` (`tui/src/model.rs`) maps idle to `Triage::Done` for the same
    reason: the group meant to hold "a machine is blocked on you right now" must not fill
    with every conversation anyone has finished reading. Approvals and `awaiting_approval`
    still promote the row. Stated in `Ouroboros.Web.Live.Rail` so the two surfaces stay
    one rule.
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
  plan-exit, auto-approve with the question carve-outs, suggested-rule row
  (`permissions.add`).
- **W6 — new-session form.** ✅ **Landed.** Pickers from providers/models,
  `workspace.browse` (method first, then the UI), sandbox + effort, ChatGPT and Grok
  subscription cards, and private Anthropic/xAI API-key entry. The same contracts now
  have a dedicated `/settings` index: model connections first, everyday defaults second,
  catalogue visibility third, and restart-owned runtime/security facts last.
- **W7 — machines (read-only)** ✅ **Landed**, then **deleted** with the rest of the
  fleet product (`docs/proposals/core.md` §3). What survives is the deck's presence
  strip and `/new`'s machine picker, both from `fleet.status`.

  **As built:** `fleet.status` named no fleet. The saved profile has always carried a
  `name` — `ouro fleet` writes it as a required field — but `Cluster`'s roster decoder kept
  the roster, the revision and the tombstones and dropped it, so the page headed itself
  with this machine's node: one member standing in for the whole. W7 shipped with the gap
  documented rather than papered over; **W8 retained the name** (`Cluster.fleet_name/0`,
  `fleet_status.fleet_name`, `nil` for a runtime in no named fleet).
- **W8 — polish to the removal checklist.** ✅ **Landed.** Notifications, theme, prefs file,
  docs (this as-built pass, README, the `DESKTOP.md` freeze note; that file has since been
  deleted with the rest of the desktop-automation plane).

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
  the removed `docs/DESKTOP.md` carries the feature-freeze note that §10 calls for and is otherwise
  intact, because it is the inventory §4's parity map was built from.

**Removal checklist** (all verified in a real browser against a live daemon, plus one
tailnet-proxied session): quick-start → real session → reply renders; approval answered
each way incl. sandbox escalation + auto-approve carve-outs; resync survives daemon
restart mid-stream; rename/delete gating; machines presence flips on
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

**Executed at W9.** Everything below is done as written; the removed `docs/DESKTOP.md` is now a
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
- **Kept:** `tui/src/desktop_cli.rs` (`ouro desktop doctor`, since deleted with the
  computer-use plane); `fleet_add.rs` and the TUI Machines stepper;
  `sorted_fields`/`sorted_json` and the `BTreeMap` availability field — the gpui
  `preserve_order` motivation dies, the determinism argument stands; the comments get
  rewritten to say so.
- **Docs:** `DESKTOP.md` replaced by a tombstone pointing here, since deleted; README's client matrix
  updated; `research/agent-ux-2026/AGENT_EXPERIENCE.md` client rows re-scored.

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

  **As built: the self-check is in; the load recipe is still unmeasured.** DeckLive
  now asks `Watch.mailbox_lagged?/1` on live events and the coalesced flush, then
  resubscribes from the cursor after dropping the queued plane events (see §8). No test
  in this tree drives a view hard enough to observe a mailbox growing under a real
  stream; that measurement is still open. The missing guard is not.
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


## Image attachments

Paste a screenshot into the composer, drop image files, or use **Attach images**.
Images appear in order with preparation status, a thumbnail, preview, and removal.
Send a message with text, images, or both; attaching alone never invokes a model.
An unfinished or failed image blocks the entire submission until it is ready or
removed. Image-bearing messages use Send or Queue; mid-turn Steer and shell commands
cannot carry images. The same flow works for the initial message on `/new`.

Uploads go to the selected runtime before Send. PNG, JPEG, static WebP, and static
GIF are decoded by `ouro-media` inside the runtime's OS sandbox, oriented and
converted to PNG with metadata removed. Animated inputs are refused. Limits are
20 MiB per source and normalized image, 64 MiB per message, 32 total attachments,
16,384 pixels per dimension, and 40 million pixels per image. Images are never
written into the project directory. A runtime without the packaged normalizer or
read/network containment reports image uploads unavailable.

The browser retains upload IDs and metadata in tab session storage, while original
files stay in memory across LiveView conversation switches. Returning to a draft
resumes its unfinished uploads. The page retains at most 64 unfinished sources and
64 MiB across drafts; finish or remove images before adding beyond this limit.
Reload recovers ready uploads and completed preparation; an incomplete upload whose
source was lost must be selected again. Retry resumes interrupted transfers with the
same upload identity, while a terminal preparation failure starts a fresh attempt
from the retained source. Each successfully sent initial message rotates its image
draft so another new session cannot inherit the previous session's images. Unsent
ready images expire after 24 hours without a draft heartbeat. Accepted images live with the
conversation and appear after reload or in another authorized client. A pinned
first-message retry keeps its original text and images while account setup is repaired.

History thumbnails and previews use authenticated, non-cacheable requests; image
bytes never appear in gateway event notifications. Remote owners receive bounded
chunks through the existing authenticated gateway. The browser upload uses WebCrypto
and therefore requires HTTPS or a localhost browser connection. Clipboard image
availability depends on the browser and OS; the file picker is always the explicit
fallback when uploads are available.

For source development, build the native decoder with `make media` before starting
the runtime. `make dev` and release packaging include it. See
[the detailed design](proposals/chat-image-attachments.md) and the generated
[protocol reference](PROTOCOL.md) for storage, limits, and wire behavior.

Storage defaults reserve 256 MiB of unused uploads per identity, 1 GiB of runtime
staging, 2 GiB per conversation, and 10 GiB per runtime. Operators can set
`config :ouroboros, :attachment_quotas, client_bytes: ..., staging_bytes: ...,
session_bytes: ..., runtime_bytes: ...` before starting the runtime. Reservations
include bounded preparation overhead; accepted-image retention follows conversations.

Connections configured with small gateway frames advertise a smaller source-file
limit so an upload stays within 4,096 chunks. Clients use the negotiated chunk size;
the runtime also rejects excessive fragmentation. This bounds upload metadata as
well as the image bytes themselves.
