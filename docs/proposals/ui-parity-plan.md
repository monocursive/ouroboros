# UI parity plan — TUI and web

Source of findings: [docs/design-qa/ui-review-2026-09-15.md](../design-qa/ui-review-2026-09-15.md).
Every item below cites the finding it resolves. Branch: `ui-parity` off `dev` (`7bea32f5`);
one PR to `dev` at the end.

## Ground rules for every slice

1. **Own files only.** Each slice names the files and, where a file is shared, the region it
   owns. Add new `App` fields in `tui/src/ui/app/mod.rs` only under the comment marker
   `// ui-parity <slice>`; add new LiveView `handle_event` clauses in `deck_live.ex` only
   under `# ui-parity <slice>`. Anything outside the list is an integrator line and is named
   in the slice.
2. **Honesty invariant.** Nothing on screen claims what the runtime did not report. A verb
   that cannot work here is not drawn. Docs describe what the code does.
3. **Every behaviour change has a test that fails without it.** A reviewer will delete each
   new enforcement point and expect red.
4. **One commit per slice on its own branch**, message in the repo's style; do not touch
   generated files (`docs/PROTOCOL.md`, goldens) unless the slice says so.
5. **Rebindable means rebindable.** Any key added to the TUI is an `Action` in
   `keymap.rs`; nothing new is matched as a literal `KeyCode`.
6. **Presentation of internals.** Erlang node names, atoms, JSON-RPC codes, and wire words
   never reach a template or a pane title raw; they go through one label function per side.

## The five groups

Used by the TUI palette, the TUI `?` panel, the TUI which-key overlay, the web palette and
the web shortcut sheet, in this order:

| Group | Verbs |
|---|---|
| Session | new, options, switch, rename, end/remove, fork, handoff, writable |
| Turn | send/queue, steer, interrupt, retry, effort, model, plan, sandbox, auto-approve, approval |
| Conversation | backtrack, rewind, compact, context, details, changed files, raw, copy, copy source, export, scrollback, `$EDITOR` view, verbose, plan panel |
| Runtime | dashboard/nodes, logs, upgrades, MCP, capabilities, connect |
| Client | settings, theme, keys, help, quit |

## Target TUI key map (defaults)

| Action | Key | Change |
|---|---|---|
| `cancel` | `ctrl+c` | close overlay → clear draft → interrupt running turn → armed; **second press within 1 s opens the quit dialog from anywhere** |
| `quit` | `ctrl+q` | kept as alias; **claimed only when no overlay is open** |
| `quit_empty` | off | `ctrl+d` becomes delete-forward only |
| `interrupt` | `esc` | **dispatched through the keymap** |
| `editor` | off | `$EDITOR` on the draft is `leader.editor` (`ctrl+x e`) only; `ctrl+g` is free |
| `settings` | off | `leader.settings` (`ctrl+x ,`) and `/settings`; a message may start with `,` |
| `help` | `?` | on an empty draft; **no `!shift` guard** |
| `rename` | `ctrl+r` | new: prefills `/rename <current title>` |
| `suspend` | `ctrl+z` | new: leave the alternate screen, `SIGTSTP`, restore on `SIGCONT` |
| `transcript_top` / `transcript_bottom` | `home` / `end` | new: on an empty draft; with text they stay line start/end |
| `leader.export` | `ctrl+x x` | new (opencode); `/export` |
| `leader.end` | `ctrl+x k` | was `x` |
| `leader.compact` / `leader.model` / `leader.theme` / `leader.backtrack` | `c` / `m` / `t` / `g` | new (opencode); `m` prefills `/model `, `t` opens the theme picker |
| `leader.status` | `ctrl+x s` | new: Dashboard tab; `leader.steer` default **off** (`alt+enter`, `/steer` remain) |
| `leader.rail` | `ctrl+x b` | new: hide/show the session rail |
| `leader.dashboard` / `.sessions` / `.upgrade` / `.logs` | `ctrl+x 1`–`4` | new: tabs reachable with a session open |
| everything else | unchanged | `n N l w e y [ v i a A r d q ?` |

`[keys]` in `config.toml` still overrides all of it; a rebound key is what every surface shows.

---

## Phase 1 — four parallel slices

**Done.** T1 `7e10d452`, T2 `c0917e68`, W1 `e2020238`, W2 `07250025` (+ `6d2b9807`),
on the shared seed `984b8032`.

### T1 — TUI key layer (Rust)

Files: `tui/src/keymap.rs`, `tui/src/ui/app/keys.rs`, `tui/src/ui/app/home.rs`,
`tui/src/ui/app/session.rs` (all but lines 2306–2314), `tui/src/ui/editor.rs` (all but the
`COMMANDS` table at lines 24–76), `tui/src/ui/mod.rs` (terminal setup, suspend),
`tui/src/ui/app/overlays.rs` **only** `escape_from_prompt` / `leave_session`, `mod.rs` under
`// ui-parity T1`; tests `tui/tests/keymap.rs`, `input_grammar.rs`, `escape_hatches.rs`,
`onboarding.rs`, plus new files.

| # | Item | Resolves |
|---|---|---|
| T1.1 | **Enter accepts the highlighted completion** when a `/` or `@` menu is open; Tab still completes. **An unknown `/verb` is refused** with a notice naming the nearest verbs; the draft is kept; nothing is submitted — on home and in a session | review §2.3 |
| T1.2 | `ctrl+q` guarded by `overlay.is_none()`; `ctrl+c` state machine as in the key map table, with the footer showing `ctrl+c again to quit` while armed | §2.4 |
| T1.3 | `Action::Interrupt` dispatched through the keymap in both `keys.rs` and `editor.rs`; a rebound interrupt key interrupts and `esc` no longer does; `esc`'s other meanings stay on `esc` | §2.4 |
| T1.4 | `quit_empty` default `off`; `editor` default `off`; `settings` default `off`; `leader.settings` `,`; drop the `!shift` guard on help | §2.4 |
| T1.5 | New actions: `rename`, `suspend`, `transcript_top`, `transcript_bottom`, `leader.export`, `leader.compact`, `leader.model`, `leader.theme` (calls `open_theme_picker`, an integrator line until T2 lands — stub it as a notice), `leader.backtrack`, `leader.status`, `leader.rail` (flips `App.rail_hidden`), `leader.dashboard/.sessions/.upgrade/.logs`; `leader.end` → `k`; `leader.steer` → off; `/rename <title>` verb calling `interactive.rename` | §2.4, §5.3 |
| T1.6 | Non-Sessions-tab fallback: digits limited to `Tab::ALL.len()`; remove the dead `i`, `s`, `a`, `,`, `x`-without-session arms; keep `j/k/h/l/Enter/Esc/r/q/PageUp/PageDown` | §2.1 |
| T1.7 | `esc` with text on an idle session: the draft goes to prompt history and the editor is cleared, one notice says `up` brings it back | §2.1 |
| T1.8 | Docs: none in this slice (T3) | |

Acceptance: `cargo test` for the crate green; `cargo +1.95 clippy --all-targets -- -D warnings`
clean; a test per row above that fails when its enforcement is removed; `/keys` lists every
new action; `Action::ALL` count, `name()`, `default_spec()`, `describe()`, `group()` updated
together (the existing round-trip tests must still pass).

### T2 — TUI presentation and discovery (Rust)

Files: `tui/src/ui/view.rs`, `tui/src/ui/app/overlays.rs` (all but `escape_from_prompt` /
`leave_session`), `tui/src/ui/app/native.rs`, `tui/src/ui/app/settings.rs`,
`tui/src/ui/panels.rs`, `dashboard.rs`, `sessions.rs`, `explorer.rs`, `theme.rs`,
`statusline.rs`, `tui/src/ui/editor.rs` lines 24–76 only, `tui/src/ui/app/session.rs` lines
2306–2314 only, `mod.rs` under `// ui-parity T2`; tests `tui/tests/ui.rs`, `footer.rs`,
`themes.rs`, `approvals.rs`, `details.rs`, `fleet_triage.rs`, `accessibility.rs`, plus new.

| # | Item | Resolves |
|---|---|---|
| T2.1 | Palette: `Command::group()` returns one of the five groups; rows sorted by group then `ALL` order; each heading once; drop `Nodes`; labels truncated with `…` so the shortcut column never collides; Interrupt and Steer rows only while a turn is running; query matches label or shortcut, and a query equal to a group name filters to that group | §2.2 |
| T2.2 | `COMMANDS` table gains `/diff`, `/changes`, `/raw`, `/keymap`, `/usage`, `/rename` | §2.3 |
| T2.3 | `?` panel: headings are the five groups; key column sized to the longest key; every live action appears exactly once, including all leader verbs and the editor motions; the `1-7 / Tab` row replaced by `ctrl+x 1-4` | §2.5 |
| T2.4 | Header tab strip: the four tabs, current one highlighted, leader digit shown | §2.1 |
| T2.5 | Which-key overlay anchored above the footer on the right, never over the composer, verbs grouped under the five headings | §2.5 |
| T2.6 | Peek keeps the picker underneath, `Esc` returns to it, `Enter` opens the session; hints match | §2.1 |
| T2.7 | Approval modal hint names the movement keys; digits select for everyone | §2.5 |
| T2.8 | `ui::presentation::node_label(&str) -> String` (`nonode@nohost` → `this computer`, `name@host` → `name`), used by dashboard, picker rows, session cards, context rail, help footer, settings; pane titles carry `unavailable: <reason>` never `(-32004)` | §2.5 |
| T2.9 | `Overlay::Theme`: bare `/theme` and `leader.theme` open it; `↑↓` previews, `Enter` saves, `Esc` restores; nothing written before `Enter`; `/theme <name>` unchanged | §2.3 |
| T2.10 | Settings: provider display names from one table (`OpenAI`, `Anthropic`, `xAI`, `Alibaba`, `Alibaba (CN)`); new `F4 Client` section editing `[terminal] mouse`, `[accessibility]`, `[notifications]`, `[budget] max_cost_usd`, and pointing at `config.toml` for `[keys]`/`[statusline]` | §2.6 |
| T2.11 | Home `Folder:` line says where the path came from (`from config.toml` / `this directory`) and names `f5` | §2.5 |
| T2.12 | `rail_hidden` respected by the sessions layout | §5.3 |

Acceptance as T1, plus a `tests/ui.rs` render test per overlay change.

Integrator lines (not for T1 or T2): `Command::Settings.action()` → `Action::LeaderSettings`;
`Command::Theme.action()` → `Action::LeaderTheme`; `leader.theme` calls `open_theme_picker`.

### W1 — Web navigation, regressions, presentation (Elixir, CSS)

Files: `lib/ouroboros/web/layouts.ex`, `deck_live.ex` (render, `activity/1`, vitals,
empty state), `new_session_live.ex`, `settings_live.ex`, `status_live.ex`, `audit_live.ex`,
`priv/static/web/app.css` (existing rules), a new `lib/ouroboros/web/presentation.ex`;
tests under `test/ouroboros/web/`.

| # | Item | Resolves |
|---|---|---|
| W1.1 | One `<.topbar>` component in `layouts.ex` rendered on every LiveView: wordmark, Sessions, New session, Settings, Audit, Status, connection pill, bell, theme; breadcrumb below it on spokes | §3.1 |
| W1.2 | Fix `activity/1` (`deck_live.ex:2365`) to read the map; a test asserting a rail row shows the newest tool verb | §3.2 |
| W1.3 | Auto-approve toggle and file-access posture move to a status row inside the composer (where the TUI footer has them); vitals become a real third column at ≥1100px and the disclosure below; delete or use every `.ouro-columns > .ouro-vitals` rule; session id and a copy-id control added to vitals | §3.2 |
| W1.4 | `settings_live.ex` uses `NewSession.model_field/2` so a remembered model outside the catalogue is kept | §3.5 |
| W1.5 | `/status` titled "Runtime status", linked from the topbar; duplicated facts removed from Settings → Runtime & security or cross-linked | §3.1 |
| W1.6 | `Presentation.node_label/1`, `Presentation.refusal/1` (atoms and codes to sentences) used by status, settings, vitals, audit | §3.5 |
| W1.7 | Empty deck: the three empty groups collapse to one line; the eyebrow copy states what the page is | §3.1 |
| W1.8 | Type scale: one heading style per rank across pages (keep Garamond for the page title, sans for sections) | §3.1 |
| W1.9 | Breakpoints declared once each in `app.css` | §3.5 |

Acceptance: `mix test test/ouroboros/web` green; `mix format --check-formatted`; every
LiveView test for a page asserts the topbar is present.

### W2 — Web keyboard and command palette (Elixir, JS, CSS)

Files: new `lib/ouroboros/web/live/palette.ex`, new `lib/ouroboros/web/commands.ex`
(catalogue: id, label, group, gate, shortcut), `deck_live.ex` under `# ui-parity W2`,
`composer.ex`, `cells.ex` (copy button), `priv/static/web/app.js`, `app.css` appended under
`/* ui-parity W2 */`; tests under `test/ouroboros/web/live/`.

| # | Item | Resolves |
|---|---|---|
| W2.1 | `ctrl+k` / `⌘k` command palette listing the catalogue in the five groups, gated by `Call.available?/2` and session state; `Enter` runs; `Esc` closes; `?` opens a shortcut sheet; `n` new session and `[`/`]` previous/next rail row when focus is not editable; `Esc` in the composer interrupts a running turn; `<kbd>` hints on the composer and rail | §3.4 |
| W2.2 | Copy: a copy button on every agent message (rendered text and source Markdown) via a clipboard hook | §3.3 |
| W2.3 | Steer: `Steer` button while a turn runs where the session's `steer` capability is truthy → `interactive.steer` | §3.3 |
| W2.4 | Model change mid-session: model in the composer's "Change" row → `interactive.configure {model}` | §3.3 |
| W2.5 | Per-turn effort: the existing picker gains "next turn only" (structured input envelope as the TUI sends it) | §3.3 |
| W2.6 | Plan-mode toggle in the composer row → `interactive.configure {plan}` (same verb the TUI uses) | §4 |

Phase 3 adds the remaining verbs to the same palette.

---

## Phase 2 — review and integrate

**Done.** Integrated at `c0028f00`; review fixes W2 `b2c3e819` (+ `ea721127`), W1
`10f42ec7`, T2 `440c82cc`, T1 `0214969d`.

- One adversarial Opus reviewer per slice, in its own worktree, told to break it: reproduce
  every claim, mutation-test every new enforcement, run the TUI in tmux / the web in the
  fixture runtime. Findings PROVED or PLAUSIBLE.
- Fixes go back to the same implementer via message.
- Integrator cherry-picks in order T1 → T2 → W1 → W2, applies the integrator lines, runs the
  Rust crate tests, clippy 1.95, `mix test test/ouroboros/web`, then the full `mix test`
  detached.

## Phase 3 — three parallel slices on the integrated branch

### W3 — remaining web verbs
Event details (`interactive.event_detail` tree), transcript export (text / NDJSON download
route), backtrack + fork, rewind (two screens), compact, handoff, context overlay, `!cmd`
via `workspace.exec`, MCP list, logs page — each as a palette entry in its group.

**Done** — `24da22f9`, and `8587abf4` before it closed the four TUI gaps T3a could not call
finished. No logs page: the gateway's method table serves no log-reading verb, so there was
nothing to draw one from; `docs/WEB.md` §4 records that as unserved rather than deferred.

### S1 — shared command catalogue
`priv/ui/commands.json`: id, label, group, slash, tui_action, web_event, scope
(`both` / `tui` / `web`). `tui/src/ui/app/overlays.rs` and `lib/ouroboros/web/commands.ex`
read it at compile time; a Rust test and an ExUnit test assert each palette equals the
catalogue filtered by scope, and a drift test fails when either side adds a verb the file
does not name.

### T3 — docs
`docs/TUI.md` (§2.1 and §2.4 corrections, new key map, five groups), `docs/WEB.md`
(parity map rewritten from §4 of the review; drop ⌘./⌘N), `README.md` key hints.

**T3a done** — `docs/TUI.md`, `README.md`, the review's "Status" section and this file.

**T3b done** — `docs/WEB.md` §4 rewritten from the review's matrix as W3 left it (the
keyboard, the palette and its catalogue, the top bar, the presentation module, the
composer's status row, the capability gates, and the D10 list with three of its entries
struck), plus this file, the review's "Status" section again, and one README sentence.

S1 is in flight.

## Phase 4 — final review, gates, PR

Full detached `mix test`, `cargo test`, clippy 1.95, `mix dialyzer`; a live pass of both
surfaces against the fixture runtime; PR `ui-parity` → `dev`.

## Deferred, stated

- Self-hosting the three web fonts (OFL; ~1 MB of binaries) — separate change.
- TUI composer undo/redo and a multi-slot kill ring.
- A web upgrades page (`wasm.*` / signing) — no design yet.
