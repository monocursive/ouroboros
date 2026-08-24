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

The composer is multi-line. `Command-Enter` sends, `Command-.` interrupts the active
turn, `Command-N` toggles the new-session form, and `Command-Q` quits the client. Closing
the last window disconnects the client and leaves an adopted runtime running.

For `openai_codex:` models, the desktop shell reads only non-secret account readiness and
starts the runtime-owned ChatGPT OAuth flow. A local runtime uses browser PKCE; an explicit
remote attachment uses device code. Session start and send remain disabled until the
runtime reports that the selected subscription model is usable. Tokens never cross the
gateway into GPUI.

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
