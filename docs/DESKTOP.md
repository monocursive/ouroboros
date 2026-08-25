# Native desktop client

`ouro-desktop` is the GPUI presentation of the same Rust client state machine used by the
Ratatui client. The BEAM runtime remains authoritative. Reconnect replay, cursor pruning,
session triage, turn mutation reconciliation, and approval routing are not reimplemented
in the window layer.

## Development

On macOS:

```sh
make desktop-dev
./tui/target/debug/Ouroboros.app/Contents/MacOS/ouro-desktop --dev
```

The bundle is written to `tui/target/debug/Ouroboros.app`. A private isolated data
directory can be supplied with `OUROBOROS_DATA_DIR`; create it with mode `0700` first.

The app starts or adopts the local runtime through the bundled `ouro` helper. This means
desktop startup uses the same spawn lock, stale-publication recovery, process-incarnation
checks, and token boundary as the terminal client. Set `OUROBOROS_CLI` only for an unusual
installation where the helper is not beside `ouro-desktop`.

To attach to a listener explicitly:

```sh
ouro-desktop --addr 127.0.0.1:7777 --token-file /absolute/path/gateway.token
```

The composer is multi-line. `Enter` sends and `Shift-Enter` inserts a new line;
`Command-Enter` remains an alternative send shortcut. `Command-.` interrupts the active
turn, `Command-N` toggles the new-session form, and `Command-Q` quits the client. Closing
the last window disconnects the client and leaves an adopted runtime running.

The composer footer carries the approvals-mode picker: "Ask first" (the default) or
"Auto-approve", which has this client answer every ordinary approval the open session
raises with `approve, once, actor: automation` — the same client-side mechanism as the
TUI's `/auto-approve` and `ouro run --approve-all`, so it works identically on every
transport and leaves a per-request ledger trail. Questions — the plan exit and
`ask_user`'s `kind: "question"` — are never auto-answered and keep their card. The
approval card offers "Auto-approve session" for the same switch on ordinary permissions,
since the composer is hidden while a card is showing. The mode does not override the OS
sandbox by itself: a denied command raises a `sandbox escalation` card, and because that
is a permission rather than a question, auto-approve answers it — so a `.git` write like
a commit goes through, one ledgered escalation per command. `.ouroboros`, the node's data
directory, and the user's ouroboros config never escalate. The mode is per session, this client
only, and not persisted; the trigger wears the warning tone while active because a
standing yes is a risk posture, not an action highlight.

Beside it sits the file-access picker: **Read only**, **Workspace write**, and **Full
access — no sandbox**, each with the consequence written under it. It sends
`interactive.configure {sandbox_mode}` — the same call the TUI's `/sandbox` makes, through
the same function — and the wire keeps the schema's word (`unrestricted`) while every label
says full access, because "unrestricted" names the parameter rather than what the agent is
being allowed to do. The trigger wears the warning variant while the session is on full
access, for the same reason the approvals trigger wears it: a risk posture, not an action
highlight. The control is **absent** where the runtime named no posture for the session —
a picker with a checked row is a claim about what the agent may touch, and the client does
not have one to make from silence.

The label follows the *session row*, not the request: it changes when the configure
succeeds and the re-list that success triggers brings the runtime's own answer back, so
what the trigger shows is always a posture the runtime confirmed. Whether a change applies
immediately or at the next turn is the runtime's answer too, and a native session applies
it now. A refusal — a transport that cannot be reconfigured, or a provider whose
`normalized_values` exclude the mode — appears as the window's inline error in the
runtime's own words.

The new-session panel carries the same three choices, defaulting from
`defaults.sandbox_mode` in your Ouroboros configuration. What the file supplies is where
the control *starts*; an explicit pick is what gets sent, and an untouched panel with no
stored default states no posture at all, leaving the plane to decide.

A command the sandbox stops arrives as an approval card with `kind: "sandbox escalation"`,
carrying the command, its working directory, the reason the sandbox gave, and the rule a
"don't ask again" would write. It is a permission rather than a question, so the
auto-approve mode answers it — full access and auto-approve are separate decisions and an
operator can hold both — while never writing the durable rule, which stays a person's
choice.

For `openai_codex:` models, the desktop shell reads only non-secret account readiness and
starts the runtime-owned ChatGPT OAuth flow. A local runtime uses browser PKCE; an explicit
remote attachment uses device code. Session start and send remain disabled until the
runtime reports that the selected subscription model is usable. Tokens never cross the
gateway into GPUI.

## Visual system

`tui/src/desktop_design.rs` is the native design-system boundary. It defines paired dark
and light palettes, the page/panel/card/inset layer order, semantic tones, GPUI Component
theme integration, and the shared panel, card, inset, status tag, field, empty-state,
keycap, icon-tile, and button constructors. Desktop views should use those tokens and
constructors instead of introducing raw colours or one-off radii. The application also
registers `gpui-component-assets`; component icons are real bundled assets rather than
text glyphs or placeholders.

The system combines the compact AI-workspace grammar of
[Beautiful UI](https://www.beautifului.dev/) with the native, quiet, precise desktop
guidance of [GPUI Component](https://longbridge.github.io/gpui-component/docs/design-guides):
neutral layers, hairline separation instead of nested cards, a small spacing and type
scale, medium controls by default, compact controls in dense rails, scarce primary
actions, and visible focus/loading/disabled/selected states. Ouroboros keeps approvals,
warnings, success, and failures on separate semantic tones so an action highlight never
implies an operational outcome. Routine acknowledgements stay in the transcript or
session status; alert surfaces are reserved for warnings and failures.

## Current platform and release boundary

The checked app bundle target is macOS. GPUI can support Linux, but an Ouroboros Linux
package, desktop entry, and live validation are separate deliverables and are not claimed
here. `make desktop-app` creates an ad-hoc-signed local app with an embedded BEAM release;
it is not Developer-ID signed or notarized.

The TUI remains built by default and remains the fallback client. GPUI dependencies are
behind the `desktop` Cargo feature, so ordinary server/TUI builds do not compile or link
the graphics stack.

GPUI 0.2.2 does not currently publish its rendered descendants into the macOS
accessibility hierarchy. The app has a native titled window and keyboard focus/shortcuts,
but screen-reader control parity is not claimed until the framework exposes a semantic
tree that Ouroboros can populate.
