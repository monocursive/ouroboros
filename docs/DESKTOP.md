# Native desktop client (removed)

> **This client no longer exists.** `ouro-desktop`, the GPUI presentation of the Rust
> client state machine, was deleted in W9. This file is a tombstone: it says what was
> here, why it went, and where its documentation lives now. Nothing below describes code
> that ships.

## What it was

`ouro-desktop` was a native macOS window over the same Rust reducer the Ratatui client
drives. It rendered with [GPUI](https://www.gpui.rs/) and `gpui-component`, shipped as
`Ouroboros.app` from `scripts/bundle-macos-desktop.sh`, and started or adopted the local
runtime through the bundled `ouro` helper — so it shared the terminal client's spawn lock,
stale-publication recovery, process-incarnation checks, and token boundary. The BEAM
runtime was always authoritative: reconnect replay, cursor pruning, session triage, turn
mutation reconciliation, and approval routing were never reimplemented in the window
layer.

It reached the transcript, approvals, session triage, the new-session form, the sandbox
and thinking pickers, the account panel, and a Machines panel.

## Why it went

`docs/WEB.md` §0 makes the case in full. In short: a second presentation of the same
reducer cost a second renderer, a second visual system, a second set of platform
dependencies, and a macOS-only distribution — for a surface that could not be reached
from a phone, from another machine, or from a browser at all. `Ouroboros.Web`, a Phoenix
LiveView surface served by the daemon itself, replaces it, is served everywhere the
gateway is, and needs no client build.

The removal was planned as [`WEB.md` §10](WEB.md#10-gpui-removal-d13) and executed as W9.
That section lists exactly what was deleted, which reducer seams collapsed, and what was
deliberately kept.

## Where its documentation lives now

- **The web surface that replaces it:** [`docs/WEB.md`](WEB.md). §4 is the parity map,
  built from this document's inventory before it was emptied; §10 is the removal record.
- **The terminal client:** [`docs/TUI.md`](TUI.md), which is now the only client document.
- **The protocol both speak:** [`docs/PROTOCOL.md`](PROTOCOL.md).

The one rule from this file that is still load-bearing is the new-session panel's
defaulting behaviour: *what the config file supplies is where a control starts, never what
gets sent.* A stored default **is** sendable; only the absence of one leaves the field off
the request. `Ouroboros.Web.Prefs` and `Ouroboros.Web.Live.NewSession` implement it
deliberately, and `WEB.md` §4 restates it.

## What survived the removal

- **`ouro desktop doctor`** is unrelated to this client and is untouched. It reports
  Computer Use helper readiness — "desktop" there names the operator's screen, not a
  window this project draws. See [`docs/COMPUTER_USE.md`](COMPUTER_USE.md).
- **The Machines stepper** lives on in the TUI (`docs/TUI.md`).
- **The deterministic-ordering rules** — sorted JSON keys in `/export` and the payload
  tree, and the `BTreeMap` availability field — remain, on the determinism argument alone.
  They were introduced partly because the gpui dependency graph enabled `serde_json`'s
  `preserve_order`; that motivation is gone, and the rules are still correct, because
  cargo features are additive and any future dependency could do the same.
