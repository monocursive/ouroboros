# Computer Use

Status: Phase 0–2 built (observe, act, helper-on-disk opt-in). See **§18** for
what is actually built vs still designed. This document is the contract a PR is
held to; it is not generated — edit it when the contract changes.

Related: [ARCHITECTURE.md](ARCHITECTURE.md) (native loop, permissions, MCP),
[DESKTOP.md](DESKTOP.md) (GPUI is presentation), [PROTOCOL.md](PROTOCOL.md)
(gateway; do not hand-edit),
[linux-computer-use.md](https://github.com/ilysenko/codex-desktop-linux/blob/main/docs/linux-computer-use.md)
(community Linux MCP backend),
[Codex Computer Use](https://developers.openai.com/codex/computer-use).

## 1. What this is

Computer Use lets the **native** provider see and operate graphical apps on the
**session-owner node** when files, shell, LSP, and MCP are not enough: reproduce
a GUI bug, click through a settings panel, read a value that only exists on
screen.

It is host-privileged I/O. It is not a coding tool, not an MCP server, and not
a GPUI feature. The BEAM remains authoritative for policy, ledger, tool
schemas, approvals, and replay. A Rust helper owns pixels, accessibility trees,
and injected input. The helper never decides allow or deny.

Default **off unless a helper is on disk**. `config(:enabled)` defaults true;
`OUROBOROS_COMPUTER_USE=0` and `enabled: false` still kill the tools. Absent from
the tool list when off. A flag that hid the tools but left the names callable
would be a different feature.

### 1.1 What it is not

| Out | Why |
|---|---|
| Vendor-provider Computer Use | Claude/Codex/Kimi CLIs run tools we cannot intercept. Only `:native` has a gate. |
| Locked use | macOS authorization plugin + display cover. Separate product, separate threat model. |
| Record & Replay / Chronicle / Skysight | Skill compiler and always-on screen memory. Phase 5 at the earliest. |
| Browser plugin / CDP | Codex treats `@Chrome` as a different plugin. A later dedicated browser MCP is the right web path. Computer Use may click a browser *as an app*. |
| Windows | No desktop client claim, no helper. |
| Linux in v1 | Checked desktop is macOS (`DESKTOP.md`). Linux is a later adapter behind the same helper protocol. |
| Automating Terminal, `ouro`, `ouro-desktop` | Would bypass the permission engine and the agent's own policy. Codex documents the same refusal. |
| Approving OS TCC / UAC / password sheets | The helper must not click security prompts. |
| Default-on, or silent allow | `Rules` already asks when nothing matches. Computer Use does not get a standing allow. |
| Auto-approve session covering clicks | Same carve-out as questions (`DesktopApproval.question`). A standing yes on `desktop_act` is a takeover. |

## 2. Decision log

Each row is a choice that later code must not quietly reverse. Alternatives
are the ones that looked reasonable and were rejected with a reason.

### D1. First-class native capability, not an MCP server

**Choice.** `desktop_state` / `desktop_act` are static native tools, listed by
`Ouroboros.Provider.Native.Tools.modules/0` when the feature is on. A node-local
helper is spawned like a language server, not registered in `:mcp_servers`.

**Rejected: vend `codex-computer-use-linux` as `mcp_servers.computer_use`.**

Evidence against:

- `Ouroboros.Provider.Native.Mcp.Result` **describes** image blocks
  (`[image, image/png, 41 kB]`) and never inlines them. The comment is load-bearing:
  "a 2 MB screenshot pasted into a conversation is how a session runs out of
  window in one call" **and** "bytes no model in this loop can look at." Computer
  Use *is* the screenshot. Wiring MCP without changing that module produces a
  feature that cannot see.
- `Tools.classify/3` maps every `mcp__*` name to `mode: :execute` because "this
  runtime cannot know what somebody else's server does." Screenshot vs click
  would share one mode. Observe would ask like a shell command.
- MCP is documented as "somebody else's program on the end of a pipe"
  (`config.exs`, `Mcp.Config`). A binary that injects `CGEvent`s is ours. Treating
  it as untrusted buys the wrong bounds (schema budget, result truncation,
  image stripping) and loses the right ones (app allowlist, TCC isolation,
  never-drive-ouro).
- The Linux crate exposes **18** tools. `Context` fingerprints the tool list.
  MCP tools already sit after the static prefix *because* they dirty the cache.
  Dumping 18 more into every Computer Use session is a prefix tax we measured
  MCP against and declined to pay for ordinary servers.
- Inline `mcp_config` is refused on durable checkpoints
  (`Coding.TaskState`). A host-input server definition does not belong in a
  session record anyway.
- Ouroboros desktop is macOS-first. The crate is a Linux compositor port
  (AT-SPI, xdg-desktop-portal, ydotool, GNOME extension, KWin, Hyprland, Niri,
  COSMIC, i3, X11). Importing it as the integration surface imports the wrong OS.

**Rejected: shell out to `screencapture` + `cliclick`.** No accessibility tree,
no coordinate scale, no doctor, no TCC-isolated helper, easy to click the
wrong window, no interrupt.

**Rejected: implement in GPUI.** `DESKTOP.md`: "The BEAM runtime remains
authoritative. Reconnect replay, cursor pruning, … and approval routing are
not reimplemented in the window layer." Clicks that live in the window die
when the window does and cannot be ledgered by the session owner.

**Keep from the Linux crate (contract, not code):**

- Layered readiness (`doctor`): screenshot, a11y, windowing, pointer, keyboard
  independently green.
- `get_app_state` as the turn primitive: bounded image + compact tree +
  coordinate metadata.
- Element index from the last snapshot, then semantic selector, then
  coordinates.
- Targeted keyboard refuses if focus cannot be verified; results warn when
  input did not land on an editable node.
- JPEG/quality before resize; default 1920px / 2 MiB.
- Mutating tools need host approval for submit/delete/send/purchase/overwrite.
- Compact readiness by default; `verbose` only when asked.

### D2. Two model tools, doctor is CLI

**Choice.** Model sees `desktop_state` and `desktop_act`. Operator sees
`ouro desktop doctor` and `computer_use.status`. No `desktop_setup` tool.

**Rejected: 18 tools matching the Linux MCP names.** Prefix cost, and
`setup_accessibility` / `setup_window_targeting` are Linux operator actions
that do not belong in a macOS turn.

**Rejected: one `desktop` tool with a free-form `action` string.** A free-form
action is `Bash(command:…)` by another name — a specifier this runtime cannot
enforce. The `action` field is a closed enum (see §5.2).

**Rejected: `doctor` as a model tool.** The model will call it every turn. The
Linux crate's own instructions say to begin every turn with `get_app_state` and
to call setup tools only when diagnostics report a specific failure. Doctor is
an operator surface; `desktop_state` already returns a compact readiness block.

### D3. No new permission *mode*

**Choice.** `desktop_state` classifies as `mode: :read`. `desktop_act` classifies
as `mode: :execute`. New *pattern kind* `ComputerUse(…)`. `Request.modes/0` stays
`[:read, :write, :execute, :network]`.

**Rejected: add `:observe` or `:desktop` to `Request.modes`.** That type is the
permission engine's closed world: `Request`, `Matcher`, `Rules`, plan-mode
(`Native.Permissions` refuses `:write` and `:execute` while planning), ACP
dialect, tests. A fifth mode is a compatibility break for a distinction the
pattern language already expresses.

Consequence, accepted: plan mode (`approval_mode: :plan`) allows `desktop_state`
(it is `:read`) and refuses `desktop_act` (it is `:execute`). That is the
correct split — a plan may look at the screen and must not click. Documented
here so nobody "fixes" it by making state `:execute`.

### D4. App identity in `context`, matched by `ComputerUse(app:…)`

**Choice.** `classify/3` puts `app` (bundle id or app id) and `desktop_action`
into the permission `context` map. Patterns:

```
ComputerUse(observe)
ComputerUse(act)
ComputerUse(app:<id>)
ComputerUse(app:*)
```

`ComputerUse(observe)` matches `desktop_state`. `ComputerUse(act)` matches
`desktop_act`. `ComputerUse(app:com.apple.Safari)` matches either tool when
`context.app` equals that id. Allow-quantifier is `:all` (already the engine
rule): an allow on `ComputerUse(app:X)` does not cover a call whose resolved
app is missing or different.

**Rejected: `Tool(desktop_act:app=Safari)`.** `Tool(name:param=value)` is
`:deny_or_ask_only` on purpose (`Pattern` docs): a parameter the provider
*reports* is not a parameter it will necessarily *act* on. App identity for
Computer Use is resolved by the helper from the live window, then stuffed into
`context` **before** `evaluate/1`. That is a fact this node measured, so a
dedicated kind may allow on it. Using `Tool(…:param=)` would forbid Always-allow.

**Rejected: persist allow-lists in a new `computer_use.toml`.** `remember/4`
already writes user/session/workspace rules. A second store is a second
authority. Always-allow *is* `remember(principal, "ComputerUse(app:…)", :allow, :user)`.

**Rejected: workspace-scoped Always-allow as the default remember target.**
Workspace rules live in the data directory (not the repo) — good — but "always
allow Safari in this repo" is the wrong default for a host app. Remember
defaults to `:user` for Computer Use. `:session` is offered. `:workspace` is
accepted if the operator picks it, not suggested.

### D5. Helper speaks a private JSON-RPC, not MCP

**Choice.** Newline-delimited JSON-RPC 2.0 over stdio, one in-flight request,
hard timeouts. Methods: `doctor`, `state`, `act`, `windows`. Elixir stages
images. The helper is as stateless as the OS allows.

**Rejected: helper is an MCP server the native client already speaks.** Same
objections as D1, plus: last-snapshot state in the helper would be
process-global and cross sessions. Last snapshot is **session-keyed in Elixir**
(`Native.Desktop`). The helper receives a fully resolved target on `act`.

**Rejected: Unix socket instead of stdio.** MCP and LSP children are stdio.
A third transport is a third supervisor. Revisit only if ScreenCaptureKit
forces a different process model.

### D6. TCC on the helper binary, not on GPUI

**Choice.** The helper is a distinct executable (`ouro-computer-use`). Screen
Recording and Accessibility are granted to that binary. The chat window does
not inherit the right to inject events.

**Rejected: implement capture inside `ouro-desktop`.** One TCC grant would
cover the entire UI. A compromised or confused renderer would inherit
keystroke injection.

### D7. Vision is a loop change, not an MCP exception

**Choice.** Tool results may carry `images: [%{path, media_type, sha256, size}]`.
`normalize_result/1` keeps them. `Loop.tool_result/3` appends a multimodal
tool message. `Model.ReqLLM` already knows `ContentPart.image/2` for user
attachments; tool results reuse that encoder. Gateway events name the artifact
by sha, never base64.

**Rejected: special-case MCP image passthrough for one server name.** That
punches a hole in a module whose job is not to trust a stranger's pipe. The
next "trusted" server would use it.

**Rejected: put screenshot bytes in `tool_result.output`.** Output is a string
capped at 100 KB (`Tools.@max_result_bytes`). A JPEG is not text.

**Rejected: write screenshots into the workspace so `images.rs` can show them.**
`images.rs` refuses paths outside the workspace *because* a transcript is a
stream of strings a provider wrote. A helper-written file in the workspace is
an agent-visible side effect and a protected-path fight (`.ouroboros` is
protected). Screenshots live under `session_dir/desktop/`, and clients fetch
them through `computer_use.artifact` (see §8).

### D8. macOS first, Linux as an adapter

**Choice.** v1 helper is macOS: ScreenCaptureKit + AXUIElement + CGEvent /
`AXPress`. Linux later implements the same four methods using the
`computer-use-linux` *modules* (`screenshot`, `atspi_tree`, `windowing`,
input backends), not its MCP `#[tool]` surface.

**Rejected: Linux first because the crate exists.** The crate solves compositor
fragmentation. Ouroboros's checked GUI is macOS. Building Linux first would
ship a feature the desktop client cannot present.

### D9. Feature flag hides tools; it does not deny them

**Choice.** `computer_use.enabled == false` (default) → `Tools.specs/3` omits
both names, `lookup/3` returns `:unknown_tool`. The model is not taught a
name it cannot use.

**Rejected: tools always listed, engine denies.** That spends prefix on a
disabled feature and trains the model to call a name that always fails.

### D10. Auto-approve does not invent a Computer Use allow

**Choice.** Client-side auto-approve (`approve, once, actor: automation`)
already skips questions. It must also skip Computer Use. `desktop_state`
classifies as `:read` but still asks in `:ask` mode: the *app allowlist* is
the product, not the tool mode.

Implementation: the native loop treats `classified.tool` in
`{"desktop_state", "desktop_act"}` as a question unless a stored
`ComputerUse(app:…)` allow already covers it. Headless `ouro run
--approve-all` uses the same carve-out. Auto-approve must not *invent* that
allow.

### D11. One helper per node, last state per session

**Choice.** Pool keyed like MCP's pool is *not* `{workspace, server}` — there
is one helper process on the node. `Native.Desktop.Pool` is a supervised
singleton. Last state is `%{session_dir => last_state}` in the BEAM. Session
death drops the snapshot. Helper crash drops nothing durable; the next
`state` rebuilds.

**Rejected: one helper per session.** TCC prompts would fire per session.
ScreenCaptureKit streams are expensive. Isolation we need is in Elixir
(snapshots, allowlist), not in a second helper pid.

### D12. Do not drive the agent, the terminal, or privacy sheets

**Choice.** Node-level deny rules, unoverridable by `remember/4` (node scope
is operator configuration; `remember` already refuses `:node`):

```
deny ComputerUse(app:com.ouroboros.desktop)
deny ComputerUse(app:com.ouroboros.tui)          # if bundled separately
deny ComputerUse(app:com.apple.Terminal)
deny ComputerUse(app:com.googlecode.iterm2)
deny ComputerUse(app:com.mitchellh.ghostty)
deny ComputerUse(app:net.kovidgoyal.kitty)
deny ComputerUse(app:com.apple.systempreferences)
deny ComputerUse(app:com.apple.loginwindow)
```

Plus a helper-side last line: if the resolved AX role is a password field,
secure text, or a system permission dialog, `act` returns an error without
injecting. Elixir cannot see the role until `state` returns; the helper must
refuse even if Elixir's denylist is incomplete.

**Rejected: "just document it in the system prompt."** Prompts are not
enforcement. Codex documents the same refusal *and* implements it.

## 3. Placement in the existing planes

```
operator
  TUI / ouro-desktop / ouro CLI
        │  gateway (loopback JSON-RPC)
        ▼
Ouroboros.Interactive.Task / Native.Session / Native.Loop
        │  Tools.lookup → classify → Native.Permissions.evaluate
        │  EffectLedger.record_started
        ▼
Ouroboros.Provider.Native.Tools.DesktopState | DesktopAct
        │
        ▼
Ouroboros.Provider.Native.Desktop          # pool + last_state + staging
        │  stdio JSON-RPC
        ▼
ouro-computer-use                          # Rust helper, TCC owner
        │
        ▼
ScreenCaptureKit / AXUIElement / CGEvent
```

Ownership:

| Concern | Owner |
|---|---|
| Feature flag, node denylist | `config :ouroboros, :computer_use` |
| Tool schemas, classify | `Native.Tools` + `Tools.DesktopState` / `DesktopAct` |
| Allow / deny / ask | `Control.Permissions` + `ComputerUse` patterns |
| Snapshot, image staging, helper IO | `Native.Desktop` |
| Pixels, AX, events | `ouro-computer-use` |
| Transcript, approval card, doctor UI | TUI / GPUI via existing desktop projection |
| Replay, sequence, reconnect | unchanged Interactive / Coding planes |

Vendor adapters (`claude_adapter`, etc.) do not grow Computer Use tools. A
bridged Claude session that needs a GUI uses whatever that CLI ships, outside
this engine.

## 4. Configuration

```elixir
# config/config.exs — defaults. runtime.exs may override from env.
config :ouroboros,
  computer_use: [
    enabled: true,                  # helper-on-disk is the opt-in; this key still kills
    act_enabled: true,              # false for observe-only
    helper_path: :bundled,          # :bundled | "/absolute/path"
    handshake_timeout_ms: 5_000,
    state_timeout_ms: 5_000,
    act_timeout_ms: 10_000,
    shutdown_grace_ms: 2_000,
    max_frame_bytes: 8 * 1024 * 1024,
    max_image_bytes: 2 * 1024 * 1024,
    max_image_width: 1920,
    max_image_height: 1920,
    max_nodes: 1_000,
    max_depth: 32,
    max_snapshots_per_session: 8,
    jpeg_quality: 80,
    denied_app_ids: [               # node deny, not remember-able
      "com.ouroboros.desktop",
      "com.apple.Terminal",
      "com.googlecode.iterm2",
      "com.mitchellh.ghostty",
      "net.kovidgoyal.kitty",
      "com.apple.systempreferences",
      "com.apple.loginwindow"
    ]
  ]
```

Same posture as `Mcp.Config`: a non-positive timeout or a raised byte cap
falls back to the shipped default. An operator typo must not widen a bound.

Env (optional, documented next to `OUROBOROS_*`):

- `OUROBOROS_COMPUTER_USE=0` kills Computer Use on this node even with a helper.
- `OUROBOROS_COMPUTER_USE=1` still requires the helper binary.
- `OUROBOROS_COMPUTER_USE_HELPER=/path` overrides the binary.

No workspace file can enable Computer Use. A repo that shipped
`.ouroboros/computer_use.json` would grant itself host input on every clone —
the same reason workspace hooks require `trusted_workspaces` and workspace
MCP requires trust.

## 5. Tool contract

### 5.1 When the tools appear

`Tools.specs/3` appends desktop modules **after** the static fifteen
and **before** MCP, only when all of:

1. `Native.Desktop.enabled?/0` (flag on, helper binary present).
   `desktop_act` additionally requires `Desktop.act_enabled?/0`.
2. `opts[:workspace]` is a binary (same gate MCP uses — no workspace, no
   host-local extras).
3. Session is not depth-capped in a way that hides them. Subagents **do** see
   the tools if the parent did: a child asked to "click the failing button"
   is a real use. They share the parent's allowlist (session-scoped rules
   apply to the same `session_id`? **No.** A subagent is a different
   interactive session. Decision: Computer Use rules remembered at `:session`
   apply only to the session that answered. `:user` Always-allow applies to
   children. Children still cannot drive denied apps.)

Prefix fingerprint: enabling Computer Use **is** a configure event. The
tools are absent or present for the life of the session. Toggling the flag
mid-session is a `configure` and is allowed to break the cache. Do not add
the tools after the first `desktop_state` "because doctor became green" —
that would change the prefix mid-conversation. Doctor redness is a
`desktop_state` result, not a schema change.

### 5.2 `desktop_state`

Jido action `Ouroboros.Provider.Native.Tools.DesktopState`.

```
name: desktop_state
mode: :read
description:
  Capture a size-bounded screenshot and a compact accessibility tree for one
  desktop app or window. Call this before desktop_act. Prefer read, bash, and
  MCP when the fact you need is in the workspace or a structured API.
  Do not use this to drive Terminal, ouro, or ouro-desktop.

schema:
  app            string   optional  bundle id, app name, or app id
  window_id      string   optional  helper-issued window id from a prior state
  title          string   optional  window title substring
  include_image  boolean  optional  default true. false → tree only
  max_width      integer  optional  default/cap from config
  max_height     integer  optional  default/cap from config
  format         enum     optional  jpeg (default) | png
  quality        integer  optional  1..95, jpeg only, default 80
```

`classify/3` for this tool:

- `mode: :read`
- `paths: []` (it does not read the workspace)
- `context.app` = resolved app id after the helper returns, **re-evaluated**
  if the first evaluate happened with only the caller's claimed `app`. See
  §6.3 for the two-phase gate.

Result `output` (text, always):

```
app: com.apple.calculator (Calculator)
window: "Calculator" id=w_12 focused=true bounds=100,120,240,320
image: 960x1280 jpeg q=80 scale=2.0 coord=1920x2560 sha=… (omitted if include_image=false)
readiness: screenshot=ok ax=ok input=unknown
focused_element: button "2" editable=false
nodes (12):
  [0] window "Calculator"
  [1] button "2" (click)
  [2] button "+" (click)
  …
offscreen: false
```

Result `images`: one staged JPEG/PNG or `[]`.

Hard errors (in-band, `is_error: true`): helper down, TCC missing, no display
session, target app not found, target is a denied app, timeout.

### 5.3 `desktop_act`

Jido action `Ouroboros.Provider.Native.Tools.DesktopAct`.

```
name: desktop_act
mode: :execute
description:
  Click, type, press a key, scroll, drag, or focus, against the latest
  desktop_state for this session. Prefer element_index from that state.
  Refused if the last state is missing, stale, or for a different app than
  the one this call resolves to. Never use this on Terminal, ouro, or
  ouro-desktop.

schema:
  action         enum     required  click | type | key | scroll | drag | focus
  element_index  integer  optional  index from the latest desktop_state
  x              integer  optional  screenshot-space pixels
  y              integer  optional
  text           string   optional  for type (literal, not a key combo)
  key            string   optional  for key. Grammar: Ctrl+L, Enter, Tab, …
  button         enum     optional  left (default) | right | middle
  direction      enum     optional  up | down | left | right (scroll)
  pages          number   optional  scroll amount, default 1
  from_x, from_y, to_x, to_y        drag endpoints, screenshot-space
  app, window_id, title             optional retarget; default = last state
```

Validation (tool, before the helper):

| action | required |
|---|---|
| `click` | `element_index` **or** (`x` and `y`) |
| `type` | `text` nonempty, max 4 KiB |
| `key` | `key` matching the grammar below |
| `scroll` | `direction`; target as click |
| `drag` | all four endpoints |
| `focus` | `app` or `window_id` or `title` or last state |

Key grammar (copy the Linux crate, case-insensitive, hyphens/spaces ignored):
combos join with `+`. Modifiers: `ctrl/control`, `alt/option`, `shift`,
`meta/super/cmd/command`. Named keys: `enter/return`, `escape/esc`, `tab`,
`backspace`, `delete/del`, `space`, `home`, `end`, `pageup`, `pagedown`,
arrows, `f1`–`f12`. Plus single US letters and digits. Anything else is
`is_error` at validation, not forwarded.

Staleness: last state older than **30s**, or a `desktop_state` from a
different session, or a `window_id` that the helper says is gone → refuse
with "call desktop_state again". Do not click coordinates from a vanished
window.

Result text: `ok=true/false`, backend, resolved app/window, landing notes
("focused role=textarea editable=true" or "warning: no editable element
holds focus — treat input as not landed"), offscreen warning.

No image on `desktop_act`. The next `desktop_state` is the observe step.
Auto-chaining a screenshot after every act would double spend and hide
whether the model actually looked.

### 5.4 System prompt addendum

Only when the tools are in `specs/3`. Lives in `Native.Prompt`, not a
per-turn injection (that would break the prefix fingerprint).

```
Computer Use is available as desktop_state and desktop_act. Prefer workspace
tools and MCP. Use desktop_state when the fact you need exists only in a
GUI. Call desktop_state before every desktop_act. Do not operate Terminal,
ouro, ouro-desktop, or system permission dialogs. If desktop_state reports
a denied app or missing OS permission, tell the operator — do not retry
around it.
```

Do **not** put the date, the frontmost app, or doctor output in the system
prompt. Those change every turn.

## 6. Permissions

### 6.1 Pattern language

Add `:computer_use` to `Pattern.kinds/0`. Parse:

```
ComputerUse(observe)
ComputerUse(act)
ComputerUse(app:<id>)
ComputerUse(app:*)
```

`<id>` is `[A-Za-z0-9._-]+`, max 128 chars. `app:*` is the explicit "any
app" form; a bare `ComputerUse` is a parse error (no permissive arm —
`Pattern.parse/1` already refuses unknown shapes).

`fragile?/1` is false for all four. There is no argument-prefix problem.

`Tool(desktop_state)` and `Tool(desktop_act)` continue to work: they match
by tool name. They are how an operator hides the feature without the new
kind. They are **not** the Always-allow form, because they do not name an
app.

### 6.2 Matcher

```
ComputerUse(observe)  → request.tool == "desktop_state"
ComputerUse(act)      → request.tool == "desktop_act"
ComputerUse(app:X)    → request.context[:app] == X
                        (or string key "app")
ComputerUse(app:*)    → request.context[:app] is a nonempty binary
```

`ComputerUse(app:*)` does **not** match a call whose app is missing. An
allow on `*` must not cover "we did not resolve an app."

Quantifier: unchanged. Allow requires every element; deny/ask any. A
request has one app, so this is a single-element list.

### 6.3 Two-phase gate for claimed vs resolved app

The model may pass `app: "Safari"`. The helper resolves
`com.apple.Safari`. Evaluating only the claim lets a stored allow for
Safari cover a call that actually focused Mail.

Sequence:

1. `classify/3` sets `context.app` to the caller's string if any, else
   the last state's resolved id, else `nil`.
2. `evaluate/1` as today. Denied apps at the node list refuse even on the
   claim if the claim canonicalises to a denied id (name map in
   `Native.Desktop.Apps`).
3. Helper runs (state or act).
4. If the resolved id ≠ the id evaluated, **evaluate again** with
   `context.app = resolved`. A second deny or ask wins. A second allow
   proceeds. The first allow is not enough.
5. Ledger the attempt against the **resolved** id.

If step 4 asks, the helper has already taken a screenshot (state) or must
**not** have acted. For `desktop_act`, resolution happens with a
**focus-only** preflight (`windows` + identify) before `act`. Never click
first and ask after.

### 6.4 Default and remember

No rule → `{:ask, :no_rule}` (existing). The card:

- title: `Calculator wants Computer Use`
- reason: observe vs act, in those words
- subject: resolved app name + bundle id
- thumbnail: last screenshot sha if we have one (state), else none
- choices: Once / This session / Always this app / Deny
- `suggested_rule`: `ComputerUse(app:com.apple.Calculator)`

Once → no `remember`. Session → `remember(..., :session)`. Always →
`remember(..., :user)`. Deny-once → no remember. Deny-always →
`remember(..., :deny, :user)`.

`suggested_rule/3` today takes `(tool, command, paths)`. Extend to accept
the classified map or add `suggested_rule/1` that understands Computer Use.
Do not stuff a bundle id into `paths`.

### 6.5 Plan mode and auto-approve

- Plan mode: `desktop_state` allowed (`:read`); `desktop_act` refused by
  `Native.Permissions` before the engine (`:execute`). Reason names
  planning, not sandbox.
- Auto-approve: does not answer `desktop_act`. May answer `desktop_state`
  only when a `ComputerUse(app:…)` allow already exists; the first observe
  of an unknown app still cards.

### 6.6 Sensitive-action ask (never remember)

Even with Always-allow, `desktop_act` asks when any of:

- AX role in `{AXSecureTextField, AXTextField}` with a password-ish title
- system permission / TCC / consent sheet (helper-detected)
- `action` is `type` and `text` matches a crude secret heuristic
  (contains `sk-`, `ghp_`, or is longer than 32 and entropy-high) — this
  is a seatbelt, not a detector. Prefer asking the operator to type
  secrets themselves.

These asks use `scope: :once` only. `remember` is not offered on the card
(`question: true` equivalent).

## 7. Helper protocol

Binary: `ouro-computer-use` (macOS). Bundled next to `ouro` in the desktop
app and the release. Spawned by `Native.Desktop.Pool` with no extra env
except a filtered block (no `OUROBOROS_GATEWAY_TOKEN`, no provider keys).

Transport: one JSON object per `\n` line, UTF-8, no embedded newlines, cap
`max_frame_bytes`. Same honesty as MCP codec: a non-JSON line is noise;
too many noise lines kill the child.

Handshake: client sends `{"jsonrpc":"2.0","id":1,"method":"doctor","params":{}}`.
A helper that cannot answer in `handshake_timeout_ms` is broken (MCP's
broken_ms posture: don't respawn a dying child in a tight loop).

### 7.1 `doctor`

Request: `{}`.

Response:

```json
{
  "platform": { "os": "macos", "arch": "arm64" },
  "permissions": {
    "screen_recording": { "ok": true, "detail": "granted" },
    "accessibility":    { "ok": false, "detail": "prompt-pending" }
  },
  "readiness": {
    "can_screenshot": true,
    "can_ax_tree": false,
    "can_list_windows": true,
    "can_focus_windows": true,
    "can_input": false,
    "recommended_next_step": "Grant Accessibility to ouro-computer-use in System Settings → Privacy & Security.",
    "blockers": ["accessibility"]
  }
}
```

No side effects. Does not prompt TCC on its own if a probe would. Listing
windows may be possible without Accessibility on macOS via
`CGWindowList`; say so honestly.

### 7.2 `windows`

Request: `{}`. Response: `{ "windows": [ { "id", "pid", "app_id", "name",
"title", "focused", "bounds": {x,y,w,h}, "layer" } ] }`.

`id` is a helper-minted opaque string, stable while the window exists,
not a raw `CGWindowID` leaked as a guessable integer if we can avoid it.
If we must use `CGWindowID`, document that it is recycled.

### 7.3 `state`

Request:

```json
{
  "target": { "app_id": "…", "window_id": "…", "title": "…", "pid": 1 },
  "include_image": true,
  "max_width": 1920,
  "max_height": 1920,
  "max_bytes": 2097152,
  "format": "jpeg",
  "quality": 80,
  "max_nodes": 1000,
  "max_depth": 32
}
```

Response:

```json
{
  "app": { "id": "com.apple.calculator", "name": "Calculator", "pid": 442 },
  "window": { "id": "w_12", "title": "Calculator", "focused": true,
              "bounds": { "x": 100, "y": 120, "w": 240, "h": 320 } },
  "image": {
    "path": "/var/folders/…/ouro-cu-XXXX/abc.jpg",
    "mime": "image/jpeg",
    "bytes": 81234,
    "width": 480, "height": 640,
    "coordinate_width": 960, "coordinate_height": 1280,
    "scale": 2.0,
    "sha256": "…"
  },
  "nodes": [
    { "index": 0, "role": "window", "name": "Calculator",
      "actions": [], "editable": false,
      "bounds": { "x": 0, "y": 0, "w": 240, "h": 320 },
      "states": ["focused"] }
  ],
  "focused_element": { "index": 1, "role": "button", "name": "2", "editable": false },
  "readiness": { "screenshot": "ok", "ax": "ok", "input": "ok" },
  "warnings": []
}
```

Image path is in `$TMPDIR` / `NSTemporaryDirectory`, mode `0600`, helper
does not delete it (Elixir stages then unlinks the temp). If
`include_image` is false, `image` is omitted.

Node bounds are in the **same coordinate space as `coordinate_*`**, so
`element_index` and `x,y` share a space. This is the Linux crate's most
important lesson.

Caps: Elixir clamps request numbers to config maxima before sending.

Denied app: helper may still capture if Elixir asked; Elixir must not
ask. Belt: helper also reads a `--deny-app` argv list.

### 7.4 `act`

Request:

```json
{
  "action": "click",
  "target": { "window_id": "w_12", "app_id": "com.apple.calculator" },
  "element": { "index": 1, "role": "button", "name": "2",
               "bounds": { "x": 40, "y": 80, "w": 32, "h": 32 } },
  "point": { "x": 56, "y": 96 },
  "text": null,
  "key": null,
  "button": "left",
  "require_focus": true
}
```

Elixir resolves `element_index` against `last_state` and sends the
**element snapshot** (role, name, bounds). The helper re-finds that node
in the live AX tree (same role+name+similar bounds). If it cannot, it
returns `ok: false, error: "element gone; call state again"` and does
not click the stale bounds.

`require_focus: true` (default for `type` and `key`): helper focuses the
window, verifies AX focused app == target, else refuses.

Password / permission-sheet detection happens here, before inject.

Response: `{ ok, focused_element, warnings, error }`.

### 7.5 Input lock and cancel

One act at a time (`tokio::sync::Mutex`, as the Linux crate). A gateway
interrupt (`Command-.` / session cancel) closes stdin or sends
`{"method":"cancel"}`. In-flight act aborts between events (a drag may
end mid-way; say so in the error). Do not leave a button held.

### 7.6 macOS implementation notes

- **Screenshot:** ScreenCaptureKit, prefer SCWindow for a targeted
  window, SCDisplay otherwise. JPEG via `image` crate or ImageIO.
- **Tree:** `AXUIElementCopyAttributeValue` walk, skip ignored, cap
  nodes/depth, prefer `AXRole`, `AXTitle`/`AXDescription`,
  `AXEnabled`, `AXValue` (not for secure fields), `AXActions`.
- **Act:** prefer `AXPress` / `AXConfirm` when the node lists them;
  otherwise CGEvent click at the element's screen point. Typing:
  `AXSetValue` on AXTextField when possible (paste-equivalent, layout
  safe); else CGEvent unicode. The Linux crate's "type_text via
  clipboard on KDE" is the same idea; on macOS AXSetValue is cleaner
  than polluting NSPasteboard. If AXSetValue is used, do **not** also
  clobber the user's clipboard.
- **Never** synthesise input to `ouro-desktop` or the helper's own
  process.

## 8. Loop, vision, compaction, protocol

### 8.1 Result shape

Extend `Tools.normalize_result/1` with:

```
images: [ %{path, media_type, sha256, size} ]
```

Absent or `[]` for every existing tool. `bound/1` still caps `output`
only. Images are not stuffed into `output`.

`DesktopState.run/2` stages via `Native.Desktop.stage_image/2`:

1. Read helper temp path.
2. Verify sha256 and magic bytes (jpeg/png only — reuse
   `Attachments.media_type/1`).
3. Refuse if `size > max_image_bytes`.
4. Write `session_dir/desktop/<sha>.<ext>` once, `0600`, same
   `write_once` as attachments.
5. Unlink helper temp.
6. Evict oldest files in that directory past
   `max_snapshots_per_session`.

### 8.2 Conversation message

Today:

```
%{role: :tool, tool_call_id, name, content: output, is_error}
```

When `images` nonempty:

```
%{
  role: :tool, tool_call_id, name, is_error,
  content: [
    %{type: :text, text: output},
    %{type: :image, path, media_type, sha256, size}
  ]
}
```

`ReqLLM` encoder: if `content` is a binary, keep current path; if a
list, map through existing `content_part/1`. A missing or mutated file
raises today for attachments; same for tool images — fail the model
call rather than send a silent text-only turn. The operator still has
the event.

Non-vision models: `Native.Model` (or the Desktop tool) checks a
`vision?/1` hint on the model spec. If false, omit image parts from the
**model** message but still emit the event and stage the file. The
operator sees the picture; the model gets the tree. Do not fail the
turn.

### 8.3 Compaction

`Context.Compaction.elide_old_tool_results/2` already replaces old tool
`content` with `[tool result elided: N bytes]`. Extend `elide/1`:

- If `content` is a list, drop every `:image` part and elide the text
  the same way. `N` includes image bytes.
- Images in the kept tail stay. Default `keep_recent_tokens` is 20k;
  two JPEGs plus recent text will usually sit in the tail. That is
  intended.
- Two `desktop_state` images in the tail is the working set. A third
  older one must elide.

Do not archive raw JPEGs into `Context.Archive` as conversation JSON.
Archive the text marker and the sha. The file in `session_dir/desktop/`
is the bytes; compaction does not delete it (session cleanup does).

### 8.4 Doom loop

`@doom_loop_repeats` already stops identical argument repeats.
`desktop_state` with identical args will hit this; good. A model that
re-states every act is working as designed and will not collide if
`element_index` / `x,y` change.

### 8.5 Gateway events

`tool_result` payload today: `name`, `call_id`, `output`, `is_error`.
Add optional:

```
"artifacts": [
  {
    "kind": "image",
    "sha256": "…",
    "media_type": "image/jpeg",
    "bytes": 81234,
    "width": 480,
    "height": 640
  }
]
```

No path on the wire. The path is a fact about this node.

New methods (add to `Gateway.Methods`, golden fixtures, then
`mix ouroboros.protocol.docs` — never hand-edit `PROTOCOL.md`):

| method | scope | timeout | does |
|---|---|---|---|
| `computer_use.status` | read | default | doctor + enabled + helper version + always-allowed apps (ids only). Node-routed like `mcp.list`. Starts nothing. |
| `computer_use.artifact` | read | default | `{sha256, session_id?}` → bytes as base64. Cap = `max_image_bytes`. 404 if unknown to this node. With `session_id`, only that existing native session's `desktop/` dir (never created). Without it, only the live helper pool's session dirs. |

Decision on artifact transfer: **base64 in the JSON result**, one image,
already size-capped. A second transport is not worth it for 2 MiB. The
client (TUI/GPUI) decodes into memory, never writes the workspace.

`hello.methods` gains both names. Older clients ignore them.

### 8.6 TUI / desktop presentation

- TUI: `images.rs` gains `session_desktop(session_dir, sha)` — a second
  containment rule, **not** a weakening of `inside_workspace/2`. Fetch
  via `computer_use.artifact` (preferred, works remotely) or local
  session_dir when attached to localhost. Max rows still 40.
  **As built (2026-08-26): the TUI shows a labelled placeholder, not inline
  pixels.** `ratatui-core`'s `Buffer::set_stringn` strips control characters,
  so a kitty/iTerm2 escape placed in a `Line`/`Paragraph` never reaches the
  terminal (verified against `buffer.rs:333/353`). The encoders exist and are
  unit-tested (`images::render`), but inline TUI pixels need a cursor-positioned
  raw-byte draw-loop pass over the backend — deferred, an operator-surface
  concern. GPUI is the surface that renders real pixels today.
- GPUI: add `DesktopCellKind::Image { sha, width, height, media_type }`.
  `desktop_cell/1` maps a tool_result with artifacts to a Tool cell plus
  an Image cell. Do not put pixels in `DesktopCell.body`.
- Approval card: optional `thumbnail_sha` on `DesktopApproval`. Renderer
  fetches the artifact. Absence is fine.

`/export` remains text: `![desktop_state 480x640](sha256:…)`.

## 9. Ledger

`tool_subject/1` grows desktop identities. `EffectLedger` subject
already has optional keys; add (sanitize like `mcp_server`):

```
app          # resolved bundle id
desktop_action  # state | click | type | key | scroll | drag | focus
window_id    # helper id, not a title
```

Never: pixels, AX names (they can contain the window's document
contents), screenshot bytes, typed `text`.

`settle_tool_effect` byte count: `output` bytes + sum of image sizes, so
a 1.8 MiB JPEG is visible on the entry.

## 10. CLI and operator UX

```
ouro desktop doctor          # pretty or --json, calls computer_use.status
ouro desktop doctor --probe  # operate: starts the helper, returns doctor
ouro desktop enable          # tells the operator to set the flag / env;
                             # does not flip production config itself
```

v1 does **not** ship `ouro desktop enable` as a config writer if we
don't already have a user-config mutation path. Print the exact env and
config snippet. A command that silently writes `runtime` config is a
new product.

Desktop settings (GPUI, later TUI `/computer-use`):

- Enabled (display of node flag; toggling is "restart with env" until a
  real config write exists)
- Always-allowed apps (from `permissions.list` filtered to
  `ComputerUse(app:…)`)
- Revoke ( `permissions.remove` )
- Last doctor blockers

No plugin store. No skill toggle. If we later ship a `computer-use`
skill under `~/.config/ouroboros/skills/`, it is ordinary skill
discovery (`Tools.Skill`) and grants nothing.

## 11. Fleet

`computer_use.status` is node-routed (`:erpc`, same as `mcp_call/2`). A
session whose owner node has no display (SSH builder, CI) reports
`readiness.can_screenshot=false` and `desktop_state` errors with that
sentence. Tools still appear if the flag is on — hiding them only on
the owner node would change the prefix after a migrate. The model is
told the node cannot see a screen.

Never proxy `act` to a different node than the session owner.

## 12. Threat model

| Threat | Mitigation |
|---|---|
| Model clicks the agent's own approve button | Node deny on ouro/ouro-desktop; helper refuses own pid; D12 |
| Model drives Terminal to escape the sandbox | Node deny on terminal bundle ids; helper deny list |
| Always-allow Safari, model focuses Mail | Two-phase gate (§6.3) |
| Stale coordinates click a different window | 30s snapshot TTL; helper re-finds AX node; refuse on miss |
| Screenshot exfiltrates another space / locked screen | ScreenCaptureKit of targeted window only when possible; doctor says if only full-display capture exists; no Locked use |
| MCP-shaped hole for images | D7: no MCP exception |
| Repo enables Computer Use | D4/§4: only node config / env |
| Auto-approve + Computer Use = unattended takeover | D10 |
| Helper crash-loop | broken_ms / handshake timeout, like MCP |
| Transcript names `/tmp/secret.png` and TUI opens it | Artifact fetch is sha-only from `session_dir/desktop/` |
| Typed password lands in ledger / events | `tool_call.input` today includes arguments. **Change:** for `desktop_act` with `action=type`, redact `text` on the emitted event and in any hook payload. The model already wrote it; the operator stream and hooks must not. Same for `key` sequences that look like paste. |
| PreToolUse hook rewrites `x,y` onto a denied app | Existing hook-rewrite re-evaluate path (`loop.ex` second `evaluate/1`) plus §6.3 |
| Subagent inherits Always-allow and runs wild | `:user` allows apply; `:session` do not. Subagent still cards on unknown apps. Denied apps still deny. |

Hooks: `PreToolUse` / `PostToolUse` run as today. Hook payload stays
content-minimised (`hook_base/1`). Do not put screenshot bytes or typed
text in the hook JSON. `desktop_act` `text` is redacted to
`{"text_bytes": N}`.

## 13. File layout

```
lib/ouroboros/provider/native/desktop.ex          # enabled?, status, probe, artifact
lib/ouroboros/provider/native/desktop/pool.ex     # supervised singleton helper
lib/ouroboros/provider/native/desktop/codec.ex    # JSON-RPC framing
lib/ouroboros/provider/native/tools/desktop_state.ex
lib/ouroboros/provider/native/tools/desktop_act.ex
lib/ouroboros/control/permissions/pattern.ex      # + ComputerUse
lib/ouroboros/control/permissions/matcher.ex      # + ComputerUse
lib/ouroboros/application.ex                      # Desktop.Pool child
tui/computer-use/                                  # ouro-computer-use bin
tui/src/desktop_cli.rs                             # ouro desktop doctor
config/config.exs                                 # :computer_use defaults
test/provider/native/desktop_test.exs
test/provider/native/desktop_pool_test.exs
test/control/permissions_test.exs                 # ComputerUse patterns
test/support/gateway_golden/
```

Do not add a Linux crate tree until Phase 4. Do not copy
`computer-use-linux/src/server.rs`.

Helper is compiled from the TUI/desktop Cargo workspace (already how
`ouro` / `ouro-desktop` ship) so one `make desktop-app` embeds it. Not
an Elixir NIF: crash isolation, TCC identity, and a killable process
group.

## 14. Tests (contract, not plumbing)

Permissions (`test/control/permissions_test.exs`):

- parse/reject the four `ComputerUse` forms and the bare `ComputerUse`
- `app:*` does not match missing app
- allow `ComputerUse(app:X)` does not match resolved Y
- node deny wins over user allow
- `Tool(desktop_act)` still matches
- `remember` cannot write `:node`

Tools / classify:

- `desktop_state` → `:read`, `desktop_act` → `:execute`
- tools absent when flag off (`lookup` → unknown)
- tools absent when no workspace in `specs/3`
- `desktop_act` validation table (missing action fields)
- type text redacted on the emitted tool_call fixture

Desktop pool (injectable runner, like Worktree):

- stages jpeg, rejects non-image magic, rejects oversize
- evicts past `max_snapshots_per_session`
- two-phase gate: claimed Safari, helper returns Mail → second evaluate
- stale snapshot (>30s) refuses act
- element gone → helper error surfaced in-band

Loop / model:

- tool result with images becomes a list content message
- compaction drops old images, keeps last-tail images
- prefix fingerprint unchanged across two `desktop_state` calls
- prefix fingerprint changes when the flag flips (configure)

Gateway golden:

- `computer_use.status` shape
- `computer_use.artifact` unknown sha → documented error
- `tool_result` with `artifacts` round-trips

Helper (Rust unit, no TCC in CI):

- key grammar
- coordinate scale arithmetic
- deny-app argv
- password-field refusal
- JSON codec bounds

Live macOS (manual / opt-in `make computer-use-smoke`): Calculator
`desktop_state` then click "2" by index. Not CI on Linux runners.

## 15. Phases and acceptance

### Phase 0 — contract

Pattern language, flag, tool modules that return
`"computer use is not enabled on this node"`, doctor CLI talking to a
helper stub. No pixels.

**Done when:** `permissions_test` covers `ComputerUse`; `specs/3` omits
tools by default; `ouro desktop doctor` prints the stub's JSON.

### Phase 1 — observe, macOS

Real helper: screenshot + windows + AX. `desktop_state` only.
Vision path through the loop. TUI/GPUI render via
`computer_use.artifact`.

**Done when:** on a Mac with TCC granted, a native session asked "what's
on screen in Calculator?" produces (1) a JPEG in the next model turn,
(2) an Image cell in the transcript, (3) a ledger row whose subject
names `com.apple.calculator` and no pixels. A model without vision still
gets the tree. Flag off: no tools, no helper spawn.

### Phase 2 — act, macOS

`desktop_act`, two-phase app gate, focus verification, landing notes,
redacted type text, interrupt cancels input, D10/D12.

**Done when:** click Calculator "2" by `element_index` from the last
state; a deliberately stale index refuses; Always-allow Safari does not
authorize a Mail focus; auto-approve does not click; Terminal is denied
with a named rule.

### Phase 3 — operator surfaces

Settings list, revoke, approval thumbnail, `suggested_rule`, doctor
copy that names the exact System Settings pane.

### Phase 4 — Linux adapter

Same four helper methods. Internals may be ported from
`computer-use-linux`. Model tools stay two. Doctor reports compositor
backends.

### Phase 5 — later, not implied

Browser MCP, Record & Replay → `skill`, Computer History, Locked use,
Windows, PiP overlay, `@App` composer sugar.

## 16. Open questions (do not block Phase 0–1)

1. **Artifact on remote attach.** `computer_use.artifact` is enough.
   Confirm desktop `--addr` remote path fetches 2 MiB comfortably. If
   not, a chunked method later; do not add it now.
2. **Menu bar / extra spaces / Stage Manager.** ScreenCaptureKit window
   filter may miss these. Doctor should say "window capture only" until
   proven.
3. **iOS Simulator.** Useful for app QA (Codex's pitch). Treat as an
   app (`com.apple.iphonesimulator`) if AX works; do not special-case
   in v1.
4. **Name map for `app: Safari`.** Need a small alias table
   (`Safari` → `com.apple.Safari`). Unknown names pass through to the
   helper's own resolver; failure is in-band.
5. **Whether `desktop_state` of a denied app should reveal that the app
   is running.** Yes: `is_error` naming the deny rule is enough. Do not
   return a screenshot.

## 17. Invariants

1. Flag default false. Off → no tools, no helper.
2. Helper never allow/denies policy. Elixir never injects events.
3. No MCP image passthrough. No fifth permission mode.
4. Two model tools. Doctor is not a tool.
5. Last snapshot is per session in the BEAM, not in the helper.
6. Act never runs against a snapshot the helper cannot re-find.
7. Screenshots live in `session_dir/desktop/`, fetched by sha.
8. Ledger and hooks never carry pixels or typed text.
9. Node denylist and helper denylist both refuse ouro and terminals.
10. Auto-approve never invents an app allow and never answers
    `desktop_act` without a stored `ComputerUse(app:…)` allow.
11. Prefix changes only on configure (flag) or compaction, not on
    doctor becoming green.
12. Plan mode can look and cannot click.
13. A Linux port implements `doctor|state|act|windows`, not 18 MCP
    tools.

## 18. Phase 0–2 — as built (2026-08-26)

Phase 0, Phase 1 (observe), and Phase 2 (act, macOS) are implemented.

**Proven / contract-tested:**

- Observe: ScreenCaptureKit + AX tree, staged JPEG, `computer_use.status` /
  `probe` / `artifact`, vision seam, supervised pool, `--approve-all` cannot
  invent a Computer Use allow.
- Act: `desktop_act` is advertised when Computer Use is enabled (`act_enabled`
  default true). Elixir resolves `element_index` against last state (30s
  stale window; a snapshot missing `:at` is stale), refuses a denied app and
  a last-state/app mismatch, and sends the element snapshot plus capture
  origin/scale to the helper. The helper rematches in global points (snapshot
  bounds inverted through origin+scale), prefers `AXPress` / `AXSetValue`,
  falls back to CGEvent only when AX was not attempted, requires focus for
  every action (and always raises on `focus`), refuses secure fields / self /
  ouro-desktop / permission sheets / `--deny-app` (baked floor, case-fold),
  and honors `cancel` between events.
- Two-phase: `Desktop.resolve_act/2` names the app the call would operate
  (last state, or a `focus` retarget). The loop re-evaluates when that id
  differs from the first classify. Always-allow Safari does not cover a
  Mail focus. A `window_id`/`title` observe without `app` is not covered by
  last state's grant; the helper ANDs `window_id` with `app_id`; untargeted
  capture is refused. Sensitive type/secure-field acts ask again (`:once` card).
- Interrupt: `Tools.execute` for `desktop_act` listens for
  `:native_interrupt`, sends helper `cancel`, and the loop flushes the
  interrupt so the turn stops.
- GPUI fetches `computer_use.artifact` by sha (optional native `session_id`)
  and overlays the bytes on Image cells. `enabled?/0` honours `config(:enabled)`.

**Still deferred:**

- TUI inline pixels (ratatui strips the codes).
- Live end-to-end "click Calculator 2" on this host is a manual
  `make computer-use` smoke, not CI.
- In-TUI `/computer-use` panel (Phase 3).
- Linux adapter (Phase 4).

