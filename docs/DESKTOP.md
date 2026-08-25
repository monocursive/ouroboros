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
since the composer is hidden while a card is showing; it also does not override the OS
sandbox — a native session's protected paths (`.git`, `.ouroboros`, the data dir) stay
protected whatever the approval posture. The mode is per session, this client
only, and not persisted; the trigger wears the warning tone while active because a
standing yes is a risk posture, not an action highlight.

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
