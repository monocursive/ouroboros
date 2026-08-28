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
a commit goes through, one ledgered escalation per command. The re-run stays inside the
OS sandbox with only the `.git` fence lifted; it is not an unsandboxed shell.
`.ouroboros`, the node's data directory, and the user's ouroboros config never escalate. The mode is per session, this client
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

## Machines

The globe button in the session rail's header opens **Machines**: the fleet this runtime
belongs to, and the form that adds another machine to it. It sits beside **New** because
both are window-level actions rather than anything about the open session, and it draws as
a full-width panel in the workspace column — the same shape and the same slot as the
new-session form. Only one of the two is up at a time; each wants the whole column, and the
composer is hidden while either is showing.

The panel names the fleet, states which member is this machine and at what address, and
lists every member with its address, node, and a connected/offline chip. The chip wears the
semantic tones — success for connected, warning for offline, neutral for unknown — never the
action accent, because a machine being up is an operational outcome and not something to
click. A member is **connected** when the runtime names its node in `connected_nodes`, or
when it is this machine's own node: the local runtime does not list itself among its peers,
and drawing this machine as offline in its own window would be a false report. Before any
runtime status has arrived every peer is **unknown** rather than assumed offline, and the
list says so.

With no fleet profile in the data directory the panel shows an empty state that names
`ouro fleet create` and the terminal client's own Machines flow, rather than an Add button
that cannot work. The desktop reads the profile itself — `App::fleet_profile` is filled in
by the terminal launcher and not by the desktop driver — once per data directory and again
after an add settles.

### Adding a machine

The form takes a destination (`user@host`, required, the same thing you would type after
`ssh`) and optionally a machine name and a private address; both optional fields say in
their placeholder that the probe suggests them, so leaving them blank is the ordinary
answer rather than an omission. A destination containing whitespace or starting with `-` is
refused with a sentence, because it would reach `ssh` as something other than a machine.

**Set up Tailscale on the destination** is off by default. Switching it on reveals what it
will do — the two commands, quoted verbatim from the pipeline, that run as root over SSH on
the destination:

```sh
curl -fsSL https://tailscale.com/install.sh | sudo -n sh
sudo -n tailscale up
```

and a separate acknowledgement that must be ticked before the add can start. The toggle is
not the consent; it is what reveals what is being consented to. Turning it back off
withdraws the acknowledgement, so switching it on again asks afresh. Guided enrollment needs
passwordless sudo on the destination; without it nothing runs and nothing is changed there.

### The progress card

The add runs on its own thread through `fleet_add::spawn_add`. Its sink does nothing but
send each `AddEvent` into a channel, which the window drains on the tick it already has, so
the pipeline never touches GPUI state.

The card carries a six-step rail — probe, network, binary, copy, enroll, done — **driven
only by the typed events**. `AddEvent::Line` is free-form text that happens to be what the
CLI prints; reading a stage out of it would be the client inventing progress the pipeline
never claimed, so a line moves nothing but the log. Each typed event settles its own stage
and every stage before it (an install decision cannot exist without a probe) and lights the
next.

Today `spawn_add` emits only `Line` plus one terminal event. An add in flight therefore
shows an unlit rail with a line saying exactly that, and the log tail — bounded, and honest
about how many earlier lines it dropped — is the whole progress report. A `Line`-only run
that reaches `Done` still completes the rail, because `Done` is typed and genuinely implies
every step before it. When the pipeline gains the rest of its typed vocabulary the same card
lights up with no change to the window.

`Install(DistArtifact(path))` names the artifact by file and by full path.
`WaitingForAddress` renders as a countdown against its budget, and says so plainly once that
budget is spent instead of sitting at "0s left". `Done` shows a summary in the outcome's own
words, any remaining recipe, and refreshes the member list. `Failed` shows the error, the
residue lines naming what the failure left behind, and the sentence that matters most —
running the add again resumes it and reuses what already succeeded.

**Stop** calls `AddHandle::cancel`, which sets a flag the pipeline reads at its next
boundary. A blocking remote call already in flight finishes first, so the card says
"stopping" and states that, rather than claiming the add has ended before a terminal event
says it has.

### The Tailscale sign-in link

`AuthUrl` gets its own card inside the progress card: the instruction, the URL as readable
text, and a button that hands it to the system browser through `cx.open_url` — the same
affordance, and the same HTTPS-only guard, as the ChatGPT sign-in card. A link that is not
HTTPS is shown but never opened, and the card says why.

The link is a live, time-critical, one-time credential, and it is treated as the pipeline
treats it: held in memory only for as long as it is live, dropped as soon as the network
step settles or the add finishes, and written nowhere — not to a log, not to a file, not
into the invitation. Its in-memory holder redacts itself in `Debug` output so a panic or a
stray log line cannot leak it.

One caveat worth stating plainly: on today's bridge the pipeline also *prints* that URL as
an ordinary progress line, because the CLI's guided-enrollment path writes it to the
terminal. Those lines land in the card's in-memory log tail and are rendered verbatim —
the same text the terminal client shows. The tail is memory only and dies with the card,
but it is not redacted, so nothing should debug-print a whole card.

### Limits of this slice

- **Nothing here has been verified by eye.** A GPUI window cannot be screenshotted from the
  build that produced it, so every claim above about layout, spacing, and tone is a claim
  about the code that draws it, not about pixels that were looked at. The state machine
  underneath is covered by tests; the drawing is not.
- **The desktop and the TUI keep separate stepper state, deliberately.** The terminal
  client's Machines stepper and this card were built in parallel against the same
  `AddEvent` contract and share none of their state. That is a known unification candidate,
  not a design position: one projection with two renderers is what the transcript already
  does, and this should follow it once both halves have settled.
- The member list is a projection over the local roster and the runtime's peer list. It
  performs no reachability probe of its own, so "offline" means the runtime is not connected
  to that node, not that the machine is down.
- `cargo test --features desktop --lib` is currently not run by CI, which runs
  `--features desktop --test desktop`. The unit tests for this surface — and the
  pre-existing ones in `desktop.rs` and `desktop_design.rs` — need that step to be covered.

## Visual system

`tui/src/desktop/machines.rs` holds the Machines surface as state rather than pixels — the
fleet projection, the form's validation, and the card's event fold — with no GPUI in it, so
each rule above is a test rather than a screenshot. `tui/src/desktop.rs` renders it.

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
