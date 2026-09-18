# Fleet UX review — Devices in the web and the TUI

Date: 2026-09-18. Branch `dev` at `915eb6e7` (the day after PR #39 merged). Client
`ouro 0.1.9` as installed at `~/.local/bin/ouro`, plus a debug build of the same tree.

Method: a read of `lib/ouroboros/web/live/devices_live.ex`, `devices.ex`,
`tui/src/ui/app/devices.rs`, `tui/src/fleet_network.rs`, `tui/src/fleet_setup/` and
`docs/FLEET.md`; then live runs of every surface against a real second machine — a
Raspberry Pi 4 on the tailnet (`raspberrypi`, Debian 13 arm64, no `ouro`, password-only
SSH, a running `systemd --user`). Both UIs were driven against (a) a `--dev` runtime and
(b) the packaged 0.1.9 runtime, each on a fresh data directory. The CLI was run as the
control. Findings marked *(live)* were reproduced on screen; the rest come from the code.

---

## 1. Summary

The engine underneath is in good shape: `ouro fleet add monocursive@100.83.203.10
--machine raspberrypi --ask-password --dry-run` connected, authenticated with the
password, inspected the Pi, resolved the `aarch64-unknown-linux-gnu` 0.1.9 release and
printed a correct plan *(live)*. What sits on top of it is not yet something a person can
use to put Ouroboros on a second machine:

1. **Discovery fails inside every runtime on a Mac that has the Tailscale app.** The
   client lookup tries `/Applications/Tailscale.app/Contents/MacOS/Tailscale` before
   `$PATH`; from a daemon that program prints `The Tailscale GUI failed to start` and
   exits 0, which the adapter reads as "not JSON" and reports as *this build of
   Ouroboros may be older than the client*. The self row then has no address and the
   name `this device`, no peer is listed, and **Set up this device** fails on the
   placeholder name. This is the failed journal in the real data directory this morning
   (`b7bf725d78517635`, machine name `this device`). *(live, packaged 0.1.9 and debug)*
2. **"Deploy to an address" cannot succeed.** The manual form has no machine-name field,
   so the worker takes the address as the name and refuses it. *(live, 0.1.9)*
3. **Both setup forms pre-fill the machine name with a display name** ("Monocursive’s
   MacBook Pro", or "this device"), which is not a valid machine name. The TUI at least
   demotes it to a hint; the web submits it. *(live)*
4. **A setup that loses its runtime shows nothing.** After approving a local setup in
   the TUI, the runtime stops (by design) and the view keeps drawing "waiting for you to
   review the plan" over an empty body, forever, with no reconnect. The web has a
   reconnect path; the TUI has none. *(live)*
5. **A worker that dies before attaching leaves the operation "inspecting" with no
   error.** The worker's own log had the reason (a Unix socket path over 104 bytes); the
   broker logged `lost its worker: :normal` and the page said nothing. *(live)*
6. **The Advanced disclosure closes on every keystroke** — `<details>` is not bound to
   the `advanced?` assign, so each `phx-change` re-render collapses it. *(live)*
7. **There is no way to remove a device from either UI.** The engine has `leave`;
   the broker only accepts `setup` and `add`.
8. **Under `ouro --dev`, "Set up this device" builds a fleet the dev runtime can never
   start** and installs a LaunchAgent that exits 1 ("built without an embedded
   release"). Dev-only, but silent. *(live)*
9. **The presentation is written for the specification, not for a person.** The
   proposal's observed-state table is rendered verbatim as row text ("Discovered peer;
   Ouroboros installation unknown", "Current device without a fleet profile"); every
   screen opens with a boxed paragraph about where SSH runs; timestamps are raw ISO with
   microseconds; a legend table explains the vocabulary; the TUI spends six lines per
   device so five devices do not fit a 45-row terminal; a working home network of four
   devices is split into two sections with a search box and three filter buttons.

The rest of this document is the evidence (§2–§4) and the target design (§5), which
is what the `fleet-ux` branch implements.

---

## 2. What was run

| Surface | Runtime | Result |
|---|---|---|
| CLI `fleet devices` | shell | four peers listed, self row named and addressed |
| CLI `fleet add … --ask-password --dry-run` | shell → Pi | password accepted, plan correct |
| web `/devices` | `--dev` | discovery failed (finding 1); setup form pre-filled `this device` |
| web `/devices` | packaged 0.1.9 | discovery failed (finding 1); manual deploy failed (finding 2) |
| TUI `ctrl+x D` | `--dev` + `OUROBOROS_TAILSCALE` override | inventory correct; local setup ran to completion on disk, view went blank (finding 4) |
| TUI `ctrl+x D` | packaged 0.1.9 | discovery failed (finding 1) |
| LaunchAgent written by `--dev` setup | launchd | exit 1, finding 8 |

The `OUROBOROS_TAILSCALE=/opt/homebrew/bin/tailscale` override is the one thing that
made discovery work under a runtime, which is what isolates finding 1 to the lookup
order: `env -i` with any subset of the shell's variables reproduces the app-bundle
CLI's failure, so it needs the GUI login session's Mach bootstrap, not a variable.

---

## 3. Web — evidence

- `lib/ouroboros/web/live/devices_live.ex:661` — `"machine" => device["machine"] || device["name"]`
  seeds the form with the display name (finding 3). There is no machine field in
  `connect_step` (`:2269–2440`), so the manual path sends `target: {address}` only and
  the worker names the machine after the address (finding 2).
- `:2306` `<details class="ouro-devices-advanced">` has no `open` attribute; the
  `advanced` event at `:244` updates `advanced?` and nothing reads it (finding 6).
- `deployment_host/1` (`:1494`) draws a three-line boxed panel on the page and again
  inside the drawer; the row state at `:1616` is `Devices.state_words/1`, the
  proposal's table (finding 9). `presence/1` joins five facts with ` · ` including a raw
  `last_probe` ISO timestamp *(live: "Presence not reported by the network client ·
  connected to this runtime · compatible build · its runtime is running · last answered
  this runtime at 2026-09-18T12:50:48.319067Z")*.
- `finish_step` offers `/status`, `/settings#providers` and `/new` — the model link
  configures *this* runtime, not the new member's, which the hint under it admits.

## 4. TUI — evidence

- `tui/src/ui/app/devices.rs:3247` `row_lines` draws name + action, then `address`,
  `platform`, `network`, optional `runtime`, `ouroboros` — six lines per row.
- `:1848` `unwrap_or_else(|| "this device".into())` and `fleet_network.rs:1397` the
  same string for the self row when discovery gives no name (findings 1, 3).
- `operation_lines` (`:3767`) has no branch for a lost connection; `poll_devices` keeps
  polling a runtime that is gone, and the snapshot it last had is what is drawn
  (finding 4). The composer noticed ("Enter connects"); Devices did not.
- There is no manual-destination entry in the TUI at all (queued in the 2026-09-17
  checkpoint and still open).
- `finish_lines` (`:4212`) names three follow-ups that are not actions in this view.

---

## 5. Target design — one list, one action per row, plain words

The principle: **a row is a device, a device has one state and one thing you can do
about it.** Everything else is a detail behind the row. The two surfaces draw the same
rows, the same drawer steps and the same words; both take their words from one table
(`Ouroboros.Web.Live.Devices` and `DeviceState::label` today — kept, rewritten).

### 5.1 The page (web) / the view (TUI)

```
Devices                                                          ↻ Refresh

This Mac is not in a fleet yet.                          [ Set up this Mac ]
   — or, once set up —
Fleet of monocursives-macbook-pro · 2 of 3 machines connected

  This Mac    monocursives-macbook-pro   macOS   100.107.54.95   ● online   in the fleet          Open
  raspberrypi                            Linux   100.83.203.10   ● online   not set up            Add to fleet
  nostromo                               Linux   100.108.85.110  ○ offline, seen 3 days ago       —
  localhost                              iOS     100.112.142.139 ● online   can't run Ouroboros   —

Not listed?  Add a device by address
```

- One list. The self row first, labelled *This Mac* / *This machine* (from the host OS).
  Roster members next, then visible peers. No Fleet/Available split, no legend.
- Search and filter appear only past eight rows.
- Presence is a dot plus a word and a *relative* time ("seen 3 days ago"). Never an
  ISO timestamp on a row; the exact time goes in the details panel.
- The Ouroboros column is one of: `in the fleet`, `in the fleet · not connected`,
  `not set up`, `can't run Ouroboros`, `offline`, `setting up…`, `waiting for you`,
  `setup failed`, `set up just now`.
- The action column is one button or nothing: **Set up this Mac**, **Add to fleet**,
  **Open**, **Continue**, **Retry**, **Details**. A device that cannot be acted on shows
  no button; the reason is in its details.
- *Remove from fleet* lives in the member's details panel, not on the row.
- The "deploying from" fact is one quiet line under the title: `Actions run on
  monocursives-macbook-pro as monocursive.` It stays there when the browser is not on
  that machine, and inside every drawer as the caption under the heading.
- Discovery failure is one inline notice with the client's own words and the repair:
  *Tailscale did not answer from this runtime: "The Tailscale GUI failed to start".
  Devices already in the fleet are still listed.* Never a claim about build age.
- The blocker sentence for a standalone host is the status line itself ("This Mac is
  not in a fleet yet"), not a second paragraph.
- Rows keep `data-state` (web) and the `DeviceState` (TUI) so tests name them by code.

### 5.2 Add to fleet (kind `add`)

```
Add raspberrypi to your fleet
Runs on monocursives-macbook-pro as monocursive.

  Name in the fleet   [raspberrypi         ]   letters, digits, hyphens
  Address             100.83.203.10            (editable only when added by address)
  SSH user            [                    ]   the account on raspberrypi
  ▸ Advanced — port, SSH key, install path, data directory, start at login

  [ Connect ]   Reads the machine first. Nothing is installed until you approve a plan.
```

- Name pre-filled from `suggested_machine` (§5.5). Address read-only when it came from
  the list. Manual entry (*Add a device by address*) is the same form with the address
  editable and the name empty.
- **No authentication picker.** The default SSH identity is used; when the target asks
  for a password the worker raises the `password` challenge and the drawer asks for it.
  A specific key file or agent fingerprint is under Advanced. (Engine change §5.5.)
- Steps after Connect, each replacing the form body, the six-step strip underneath:
  1. *First time connecting to 100.83.203.10* — algorithm, SHA256, one sentence to
     check it on the device — **Trust and continue** / **Cancel**.
  2. *Password for monocursive@100.83.203.10* (attempt 1 of 3) — **Continue**.
  3. *Ready to deploy* — five lines: `Install ouro 0.1.9 (Linux arm64) to
     ~/.local/bin/ouro · Join the fleet as raspberrypi · Start at login as a user
     service · Update 1 roster (this Mac)` and the trust sentence in one line —
     **Deploy** / **Cancel**. The digest is shown in mono under it.
  4. Progress: `✓ Inspect · ✓ Install · ● Join fleet · ○ Start at login · ○ Connect ·
     ○ Ready`, the current step's detail under it, the worker log behind a disclosure.
  5. *raspberrypi is in your fleet* — **Open** (the machines panel) / **Done**. On
     failure: the cause in the worker's words, **Retry**, and what was left behind.
- Footer on every step: **Close** (`keeps running`) and **Cancel setup**.

### 5.3 Set up this Mac (kind `setup`)

Name (pre-filled slug, editable), address (pre-filled, read-only when discovery gave
one, editable otherwise), *Start at login* checkbox on. One sentence: *Ouroboros
restarts once during setup; this page reconnects by itself.* Button **Set up**. Then
review, progress, done — same as 5.2. In the TUI the restart is drawn as *Ouroboros is
restarting… reconnecting* and the view reloads the operation by id when the runtime
is back; it never draws the last snapshot as if it were current.

### 5.4 Remove from fleet (kind `leave`)

From a member's details panel: *Remove raspberrypi from the fleet*. Asks the SSH user
(and a password through the same challenge), reviews (*Stop Ouroboros on raspberrypi,
retire its credentials, take it out of every roster. Its sessions and data stay on
that machine.*), runs the engine's `leave`, reports. A member that cannot be reached
is told so with the CLI recipe for `fleet sessions forget` as the fallback.

### 5.5 Contract changes the surfaces rely on

| Where | Change |
|---|---|
| `ouro fleet devices --json` | client lookup order is `$PATH` then the known locations, as `docs/FLEET.md` already says; a client whose stdout is not a status document is skipped for the next candidate; the discovery `detail` carries that client's own first line. Every row gains `suggested_machine`: the roster name for a member, otherwise the display name lowercased with every run of non-alphanumerics folded to one hyphen, trimmed, at most 40 characters, or `null` when nothing valid remains. The self row's `name` falls back to the host name, never `this device`. |
| `fleet.deployment.prepare` | `kind: "leave"` with `target.machine` (a roster member), `ssh_user`, `port`, `identity`; exempt from no blocker except `no_ca_key` is *not* required (a leave needs no CA). Manual `add` requires `target.machine`. |
| `fleet.deployment.status` | when `source` is `journal` and the state is unfinished and no `done` frame exists, `worker_exit` `{code, last_lines}` from the worker's private log (scrubbed, at most three lines) so a surface can say *the worker stopped: …* and offer **Retry**. |
| `fleet.devices` `capabilities.reasons` | `dev_runtime` for `setup` when this runtime is a Mix dev runtime: *This is a development runtime; the packaged `ouro` is what sets a machine up.* |
| engine | with the default identity, an SSH password prompt raises the `password` challenge instead of failing the connection. |

### 5.6 What stays

Everything in `docs/FLEET.md` "Trust" and the secret-handling rules: no secret on a
command line or in a journal, one masked field per challenge, no `phx-change` on it,
the plan digest computed by the client, host keys always an explicit question, the
detached worker, per-tab challenge binding, take-over as an explicit answer. The
proposal's *observed states* are still the states; what changes is the words a person
reads and how many of them there are.
