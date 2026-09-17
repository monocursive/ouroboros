//! Slice 6, the terminal half: the Devices view and the deployment flow through it.
//!
//! A scripted gateway, in the shape `tui/tests/fleet_triage.rs` established: messages go
//! in, the outbound queue and the drawn frame come out, and the Elixir side is stood in
//! for by answers shaped like the ones `docs/TUI.md` §2.4 documents. What is *not* stood
//! in for is the device data — the rows below are built from the sanitized
//! `tailscale status --json` captures under `tests/fixtures/tailscale/`, so the names,
//! addresses, platforms and last-seen times this view renders are the ones a real client
//! reported, including the capture whose hostnames are hostile on purpose.
//!
//! ## The claim each group of tests makes
//!
//!   * **Inventory** — the two sections, the observed-state table, the search, the filter
//!     and a distinct empty state for each way discovery can fail.
//!   * **Deploy** — select and connect, all three challenge kinds, the reviewed plan and
//!     its digest, progress, and finishing or recovering.
//!   * **Authority** — read scope, a non-administrator, an absent capability, and one
//!     identity taking over another's setup.
//!   * **The secret** — a unique password is typed, submitted, and then looked for in the
//!     frame, in the App's own `Debug`, and in every request this client queued.

mod support;

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::proto::{ErrorCode, Hello, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Call, Command, DevicesTag, Msg, Overlay, Tag};

use support::{app, full_hello, read_hello, render, Screen};

/// ## Why every test in this file serialises
///
/// Screen-reader mode is a process-wide flag, for the reason `src/ui/access.rs` gives:
/// the renderers that need it are functions with no handle on any state. `cargo test`
/// runs a binary's tests on many threads, so a test that turned the flag on would change
/// what every other test in this file draws. Each one therefore takes [`MODE`] and
/// declares which mode it is in — `normal()` for almost all of them, `screen_reader()`
/// for the two that are about it — and puts the default back on the way out.
static MODE: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Held<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        ouro::ui::access::install(ouro::ui::access::Settings::default());
    }
}

fn holding(settings: ouro::ui::access::Settings) -> Held<'static> {
    let guard = MODE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    ouro::ui::access::install(settings);

    Held { _guard: guard }
}

fn normal() -> Held<'static> {
    holding(ouro::ui::access::Settings::default())
}

fn screen_reader() -> Held<'static> {
    holding(ouro::ui::access::Settings {
        screen_reader: true,
        reduced_motion: true,
    })
}

// ---------------------------------------------------------------------------------------
// driving
// ---------------------------------------------------------------------------------------

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn chord(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn typed(text: &str) -> Vec<Msg> {
    text.chars().map(|c| key(KeyCode::Char(c))).collect()
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn refuse(app: &mut App, tag: Tag, code: ErrorCode, data: Option<Value>) {
    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code,
            message: "refused".into(),
            data,
        })),
    });
}

/// How many characters the masked field is drawing.
///
/// The one property of the secret buffer a test can actually see from outside it: the
/// `Debug` is redacted by design, so an assertion about the `Debug` passes whether the
/// bytes are there or not.
fn bullets(app: &mut App) -> usize {
    screen(app)
        .rows
        .iter()
        .map(|row| row.matches('\u{2022}').count())
        .sum()
}

fn screen(app: &mut App) -> Screen {
    render(app, 150, 60)
}

/// Every request this client has queued since the last drain, as whole frames — which is
/// what a secret-placement assertion has to look at, not just the methods.
fn drained(app: &mut App) -> Vec<Call> {
    app.drain()
}

/// The frame's prose: the pane's borders dropped and its wrapping undone.
///
/// A sentence in this view is wrapped to the width of the pane, so `contains` on the raw
/// frame would be an assertion about the column the pane happens to break at rather than
/// about the words an operator reads. The tests that care about *layout* — the hostile
/// name capture, the cursor marker — read the rows instead.
fn flowed(drawn: &Screen) -> String {
    drawn
        .rows
        .iter()
        .map(|row| {
            row.replace(
                [
                    '\u{2502}', '\u{2500}', '\u{250c}', '\u{2510}', '\u{2514}', '\u{2518}',
                ],
                " ",
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The drawn frame as prose.
fn prose(app: &mut App) -> String {
    flowed(&screen(app))
}

/// Every primary action the observed-state table can put on a row.
const ACTIONS: [&str; 9] = [
    "Deploy Ouroboros",
    "View device",
    "Continue setup",
    // A failure and a cancellation are their own verbs on a row, not "in progress".
    "Setup failed",
    "Setup cancelled",
    // And a runtime that cannot deploy labels the row that way rather than offering it.
    "Deploy unavailable here",
    "Diagnose",
    "Set up this device",
    "Refresh or details",
];

/// The *inventory line* for a device: the one carrying both its name and an action.
///
/// Not `Screen::row`, which finds the first line containing the needle — and the first
/// line containing "studio" is the permanent header naming the deployment host.
fn device_row<'a>(drawn: &'a Screen, name: &str) -> &'a str {
    drawn
        .rows
        .iter()
        .find(|row| row.contains(name) && ACTIONS.iter().any(|action| row.contains(action)))
        .map(String::as_str)
        .unwrap_or_else(|| panic!("no device row for {name}\n{}", drawn.text()))
}

fn call_for<'a>(calls: &'a [Call], method: &str) -> &'a Call {
    calls
        .iter()
        .find(|call| call.method == method)
        .unwrap_or_else(|| {
            panic!(
                "no {method} call; queued: {:?}",
                calls.iter().map(|call| &call.method).collect::<Vec<_>>()
            )
        })
}

// ---------------------------------------------------------------------------------------
// the fixtures, as `fleet.devices` replies
// ---------------------------------------------------------------------------------------

/// One sanitized `tailscale status --json` capture, read from the checkout.
fn capture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tailscale")
        .join(format!("{name}.json"));

    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

    serde_json::from_slice(&bytes).expect("a JSON capture")
}

/// A peer's first IPv4, or `None` — the same fact `no_usable_ipv4` is about.
fn ipv4(peer: &Value) -> Option<String> {
    peer.get("TailscaleIPs")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find(|address| !address.contains(':'))
        .map(str::to_string)
}

/// The peers of a capture, as `fleet.devices` device rows.
///
/// The state each row gets is the one `fleet_network::device_rows` assigns for those
/// facts — that classification has its own tests beside the code it lives in, and is
/// reproduced here rather than imported because `classify` is private to that module.
/// What *this* file is testing is the view, so the rows are its input.
fn rows_from(name: &str) -> Vec<Value> {
    let capture = capture(name);
    let empty = serde_json::Map::new();
    let peers = capture
        .get("Peer")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut rows: Vec<Value> = peers
        .values()
        .map(|peer| {
            let os = peer.get("OS").and_then(Value::as_str).unwrap_or("");
            let online = peer.get("Online").and_then(Value::as_bool);
            let address = ipv4(peer);

            let state = if address.is_none() {
                "no_usable_ipv4"
            } else if !matches!(os, "linux" | "macOS" | "darwin") {
                "unsupported_platform"
            } else if online == Some(false) {
                "peer_offline"
            } else {
                "discovered_installation_unknown"
            };

            let last_seen = peer
                .get("LastSeen")
                .and_then(Value::as_str)
                .filter(|seen| !seen.starts_with("0001-"));

            json!({
                "name": peer.get("HostName"),
                "machine": Value::Null,
                "os": os,
                "address": address,
                "online": online,
                "last_seen": last_seen,
                "state": state,
                "action": "deploy Ouroboros",
                "name_conflicts_with_roster": Value::Null,
            })
        })
        .collect();

    rows.sort_by_key(|row| row["name"].as_str().unwrap_or("").to_string());
    rows
}

/// This machine's own row, in the roster.
fn self_row() -> Value {
    json!({
        "name": "studio",
        "machine": "studio",
        "os": "macos",
        "address": "100.64.12.21",
        "online": true,
        "last_seen": Value::Null,
        "state": "this_device",
        "action": "view device",
        "name_conflicts_with_roster": Value::Null,
    })
}

fn host(deploy: bool, reasons: &[&str]) -> Value {
    json!({
        "hostname": "studio",
        "user": "ada",
        "os": "darwin",
        "arch": "aarch64-apple-darwin",
        "issuer": true,
        "capabilities": { "deploy": deploy, "reasons": reasons },
    })
}

/// A whole `fleet.devices` reply: this host, what the capture saw, and the rows.
fn devices_reply(fixture: &str, code: &str, detail: Option<&str>, rows: Vec<Value>) -> Value {
    let peers = rows_from(fixture).len();

    json!({
        "host": host(true, &[]),
        "discovery": {
            "code": code,
            "reason": Value::Null,
            "detail": detail,
            "client": { "program": "tailscale", "version": "1.102.1" },
            "self": Value::Null,
            "visible_peers": peers,
        },
        "devices": rows,
        "fleet_protocol_revision": 5,
        "operations": [],
        "unknown": [],
    })
}

/// The common case: this machine plus four visible peers.
fn populated() -> Value {
    let mut rows = vec![self_row()];
    rows.extend(rows_from("running-with-peers"));
    devices_reply("running-with-peers", "ok", None, rows)
}

// ---------------------------------------------------------------------------------------
// opening
// ---------------------------------------------------------------------------------------

fn opened(hello: Hello) -> App {
    let mut app = app(hello);
    app.apply(Msg::Tick);
    let _startup = app.drain();
    app.open_devices();
    app
}

/// Opens the view and answers the inventory read it issues.
fn with_inventory(reply: Value) -> App {
    let mut app = opened(full_hello());
    let calls = drained(&mut app);
    let inventory = call_for(&calls, "fleet.devices");

    answer(&mut app, inventory.tag.clone(), reply);
    app
}

// ---------------------------------------------------------------------------------------
// navigation
// ---------------------------------------------------------------------------------------

/// The palette row, the rebindable action and the Settings link all reach one view.
#[test]
fn the_view_is_reachable_from_the_palette_the_keymap_and_the_settings_runtime_section() {
    let _mode = normal();
    // The palette: the row is offered, and choosing it opens the overlay.
    let mut client = app(full_hello());
    client.apply(Msg::Tick);
    let _startup = client.drain();

    assert!(
        client
            .palette_commands(&Default::default())
            .contains(&Command::Devices),
        "the Devices row is not in the palette"
    );

    client.apply(chord(KeyCode::Char('p')));
    for message in typed("Devices") {
        client.apply(message);
    }
    client.apply(key(KeyCode::Enter));
    assert!(
        matches!(client.overlay, Some(Overlay::Devices)),
        "the palette row did not open the view"
    );

    // The keymap: the leader, then the bound verb. Read through the map rather than
    // hardcoded, so a rebound key fails this loudly instead of silently.
    client.apply(key(KeyCode::Esc));
    let spec = client.keymap.label(ouro::keymap::Action::LeaderDevices);
    assert!(
        spec.ends_with('D'),
        "the default Devices chord moved; this test presses D: {spec}"
    );

    client.apply(chord(KeyCode::Char('x')));
    client.apply(key(KeyCode::Char('D')));
    assert!(
        matches!(client.overlay, Some(Overlay::Devices)),
        "the leader chord did not open the view"
    );

    // Settings: `d` in the Runtime section opens the same view.
    client.apply(key(KeyCode::Esc));
    client.apply(chord(KeyCode::Char('x')));
    client.apply(key(KeyCode::Char(',')));
    client.apply(key(KeyCode::F(3)));

    let drawn = screen(&mut client);
    assert!(
        drawn.contains("Devices"),
        "the Runtime section does not link Devices:\n{}",
        drawn.text()
    );

    client.apply(key(KeyCode::Char('d')));
    assert!(
        matches!(client.overlay, Some(Overlay::Devices)),
        "the Settings runtime link did not open the view"
    );
}

/// The Dashboard says the view exists, and says so with the key actually bound.
#[test]
fn the_dashboard_names_the_view_and_the_key_that_opens_it() {
    let _mode = normal();
    let mut client = app(full_hello());
    client.apply(Msg::Tick);
    // The machines panel lives on the Dashboard tab, which is not what a fresh client
    // opens on. `ctrl+x 1` is `leader.tab_dashboard`.
    client.apply(chord(KeyCode::Char('x')));
    client.apply(key(KeyCode::Char('1')));

    let hint = client
        .devices_hint()
        .expect("a hint on a runtime that serves it");
    assert!(hint.contains("devices"));
    assert!(
        hint.contains(&client.command_shortcut(Command::Devices)),
        "the hint does not print the bound key: {hint}"
    );

    let drawn = screen(&mut client);
    assert!(drawn.contains("devices"), "{}", drawn.text());

    // A runtime serving neither verb has no page worth advertising.
    let mut bare = app(support::hello(&["runtime.status"]));
    bare.apply(Msg::Tick);
    assert_eq!(bare.devices_hint(), None);
    assert!(!bare
        .palette_commands(&Default::default())
        .contains(&Command::Devices));
}

/// Opening reads the inventory; opening again closes, and never cancels anything.
#[test]
fn opening_reads_the_inventory_and_closing_cancels_nothing() {
    let _mode = normal();
    let mut app = opened(full_hello());
    let calls = drained(&mut app);

    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));

    answer(&mut app, Tag::Devices(DevicesTag::Inventory), populated());
    app.apply(key(KeyCode::Esc));

    assert!(app.overlay.is_none());
    let after = drained(&mut app);
    assert!(
        !after.iter().any(|call| call.method.contains("cancel")),
        "closing the view sent a cancel"
    );
}

// ---------------------------------------------------------------------------------------
// the inventory
// ---------------------------------------------------------------------------------------

/// The two sections, the fields of a row, and the permanent header.
#[test]
fn the_inventory_draws_two_sections_the_row_fields_and_the_deployment_host() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);
    let text = flowed(&screen);

    assert!(
        text.contains("Deploying from studio \u{b7} local user ada"),
        "the permanent header is missing:\n{text}"
    );
    assert!(text.contains("Fleet devices"), "{text}");
    assert!(text.contains("Available on this network"), "{text}");

    // One row, every field the proposal lists.
    assert!(text.contains("build-linux"), "{text}");
    assert!(text.contains("100.64.12.44"), "{text}");
    assert!(device_row(&screen, "build-linux").contains("Deploy Ouroboros"));
    assert!(
        text.contains("not inspected yet"),
        "the state, in words:\n{text}"
    );
    assert!(text.contains("online now"), "{text}");

    // An offline peer carries its observation time rather than a bare "offline".
    assert!(
        text.contains("offline, last seen 2026-09-17T07:50:00.1Z"),
        "{text}"
    );

    // The proposal's refusal to over-claim, on the page.
    assert!(
        text.contains("was contacted over SSH"),
        "the no-inspection sentence is missing:\n{text}"
    );
}

/// The observed-state table, as the capture's own peers land on it.
#[test]
fn every_observed_state_gets_the_proposals_words_and_action() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);

    // A visible, supported, online peer is never called uninstalled.
    assert!(device_row(&screen, "build-linux").contains("Deploy Ouroboros"));
    assert!(screen.contains("not inspected yet"));

    // iOS: a platform no release targets.
    assert!(screen.contains("no supported release for this platform"));
    assert!(device_row(&screen, "pocket-phone").contains("Refresh or details"));

    // No usable IPv4.
    assert!(screen.contains("no private IPv4 address the fleet can use"));

    // Offline, and explicitly not "powered off".
    assert!(screen.contains("offline, not inspected"));

    // This machine, in the roster.
    assert!(device_row(&screen, "studio").contains("View device"));
    assert!(screen.contains("this machine, set up"));
}

/// Each way discovery can fail says something different, and says what to do.
#[test]
fn every_discovery_failure_has_its_own_empty_state() {
    let _mode = normal();
    for (fixture, code, expected) in [
        (
            "no-state",
            "client_missing",
            "no Tailscale client is installed on this machine",
        ),
        (
            "needs-login",
            "signed_out",
            "the Tailscale client is installed and this machine is signed out",
        ),
        (
            "running-but-refused",
            "permission_denied",
            "the Tailscale client refused this account's request",
        ),
        (
            "stopped",
            "unavailable",
            "the Tailscale client could not report this machine's network",
        ),
        (
            "no-peers",
            "no_visible_peers",
            "the Tailscale client sees no other devices on this network",
        ),
    ] {
        let reply = devices_reply(
            fixture,
            code,
            Some("a sentence naming the repair"),
            vec![self_row()],
        );
        let mut app = with_inventory(reply);
        let text = prose(&mut app);

        assert!(
            text.contains(expected),
            "{code} did not say {expected:?}:\n{text}"
        );
        assert!(
            text.contains("a sentence naming the repair"),
            "{code} dropped the repair sentence:\n{text}"
        );
        // Known members are retained when discovery is unavailable.
        assert!(text.contains("studio"), "{code} lost the roster:\n{text}");
    }
}

/// A fleet with no members says so rather than drawing an empty heading.
#[test]
fn an_empty_fleet_says_how_to_start_one() {
    let _mode = normal();
    let reply = devices_reply("no-peers", "no_visible_peers", None, vec![]);
    let mut app = with_inventory(reply);

    assert!(prose(&mut app).contains("There is no fleet on this machine yet"));
}

/// Search narrows by name and by address; the filter narrows by section; `r` refetches.
#[test]
fn search_filter_and_refresh_narrow_and_reread_the_same_list() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    // `/` then text: only the matching row is drawn.
    app.apply(key(KeyCode::Char('/')));
    for message in typed("build") {
        app.apply(message);
    }
    app.apply(key(KeyCode::Enter));

    let text = prose(&mut app);
    assert!(text.contains("build-linux"), "{text}");
    assert!(
        !text.contains("pocket-phone"),
        "search did not narrow:\n{text}"
    );

    // Esc clears the query rather than closing the view.
    app.apply(key(KeyCode::Char('/')));
    app.apply(key(KeyCode::Esc));
    assert!(matches!(app.overlay, Some(Overlay::Devices)));
    assert!(screen(&mut app).contains("pocket-phone"));

    // `f` cycles all → fleet → available.
    app.apply(key(KeyCode::Char('f')));
    let text = prose(&mut app);
    assert!(text.contains("studio"), "{text}");
    assert!(
        !text.contains("build-linux"),
        "the fleet filter kept a peer:\n{text}"
    );

    app.apply(key(KeyCode::Char('f')));
    let text = prose(&mut app);
    assert!(text.contains("build-linux"), "{text}");

    // `r` asks again.
    app.apply(key(KeyCode::Char('r')));
    let calls = drained(&mut app);
    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));
}

/// A device that adopts a member's name is its own row with a note, never a merge.
#[test]
fn a_device_impersonating_a_member_is_listed_separately_with_a_note() {
    let _mode = normal();
    let mut rows = vec![json!({
        "name": "attic", "machine": "attic", "os": "linux",
        "address": "100.64.12.77", "online": Value::Null,
        "state": "fleet_member_not_visible", "action": "diagnose",
        "name_conflicts_with_roster": Value::Null,
    })];
    rows.extend(rows_from("roster-spoof"));
    rows[1]["name_conflicts_with_roster"] = json!("attic");

    let reply = devices_reply("roster-spoof", "ok", None, rows);
    let mut app = with_inventory(reply);
    let text = prose(&mut app);

    assert!(text.contains("It is not that machine."), "{text}");
    assert!(
        text.contains("in the fleet, not visible on this network"),
        "the real member lost its state:\n{text}"
    );
    assert!(
        text.contains("100.64.12.250"),
        "the impostor's own address is not shown:\n{text}"
    );
}

/// A hostname built to forge rows cannot forge one.
///
/// `hostile-names.json` is a capture whose peers are named with ANSI escapes, bidi
/// overrides, tabs and a four-line block shaped exactly like this view's own device row.
/// The CLI answers it by bounding every device string through `fleet_network::human`;
/// this asserts the view does the same, because a name that can draw a fake row can tell
/// an operator that a machine they do not control is already in their fleet.
#[test]
fn a_hostile_device_name_cannot_forge_a_row_or_move_the_cursor() {
    let _mode = normal();
    let reply = devices_reply("hostile-names", "ok", None, rows_from("hostile-names"));
    let mut app = with_inventory(reply);
    let rendered = screen(&mut app);
    let text = rendered.text();

    assert!(!text.contains('\u{1b}'), "an escape reached the frame");
    assert!(
        !text.contains('\u{202e}'),
        "a bidi override reached the frame"
    );
    assert!(!text.contains('\t'), "a tab reached the frame");

    // The forged row's giveaway: it claims a fleet membership for a peer.
    let forged = text
        .lines()
        .filter(|line| line.contains("in this machine's fleet"))
        .count();
    assert_eq!(
        forged, 0,
        "a device name forged a fleet-membership row:\n{text}"
    );
}

// ---------------------------------------------------------------------------------------
// the deploy flow
// ---------------------------------------------------------------------------------------

/// Moves the cursor onto a named row and presses Enter.
fn activate(app: &mut App, name: &str) {
    for _ in 0..40 {
        let drawn = screen(app);
        // The cursor marker, not the start of the line: the line starts with the pane's
        // own border, and in screen-reader mode the name is preceded by its number.
        let selected = device_row(&drawn, name).contains("> ");
        drop(drawn);

        if selected {
            app.apply(key(KeyCode::Enter));
            return;
        }

        app.apply(key(KeyCode::Char('j')));
    }
    panic!("never reached the {name} row");
}

/// Moves the connect form's cursor onto its submit row.
fn focus_inspect(app: &mut App) {
    for _ in 0..12 {
        let drawn = screen(app);
        // The two forms label their button differently — a local setup inspects nothing
        // over SSH — so the helper looks for whichever one this form is drawing.
        let focused = drawn.rows.iter().any(|row| {
            (row.contains("[ inspect this device ]") || row.contains("[ set this device up ]"))
                && row.contains("> ")
        });
        drop(drawn);

        if focused {
            return;
        }

        app.apply(key(KeyCode::Tab));
    }
    panic!("never reached the inspect row:\n{}", screen(app).text());
}

/// Step 1: the form, its required field, and the call it makes.
#[test]
fn selecting_a_device_asks_for_the_account_and_prepares_the_operation() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");

    let text = prose(&mut app);
    assert!(text.contains("Deploy Ouroboros to build-linux"), "{text}");
    assert!(text.contains("100.64.12.44"), "{text}");
    assert!(
        text.contains("Deploying from studio \u{b7} local user ada"),
        "the header is not on the connect screen:\n{text}"
    );
    assert!(text.contains("ssh username"), "{text}");
    assert!(text.contains("(required)"), "{text}");
    assert!(
        text.contains("Advanced"),
        "the advanced fields are unlabelled:\n{text}"
    );

    // Submitting with no username refuses, inline, without a call.
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    assert!(
        drained(&mut app).is_empty(),
        "an empty username still reached the runtime"
    );
    assert!(prose(&mut app).contains("An SSH username is required"));

    // With one, `prepare` goes out with the target, the account and no secret.
    for message in typed("deploy") {
        app.apply(message);
    }
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["target"]["address"], json!("100.64.12.44"));
    assert_eq!(prepare.params["ssh_user"], json!("deploy"));
    assert_eq!(prepare.params["port"], json!(22));
    assert!(
        prepare.params.get("secret").is_none(),
        "prepare carried a secret: {}",
        prepare.params
    );
}

/// An operation in flight, from `prepare` to a first snapshot.
fn deploying() -> App {
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    for message in typed("deploy") {
        app.apply(message);
    }
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");
    answer(
        &mut app,
        prepare.tag.clone(),
        json!({ "operation_id": "abcdef0123456789" }),
    );

    app
}

fn snapshot(state: &str, challenges: Value, extra: Value) -> Value {
    let mut reply = json!({
        "operation": "abcdef0123456789",
        "source": "worker",
        "attached": true,
        "state": state,
        "owner": "local-owner",
        "steps": [],
        "log": [],
        "challenges": challenges,
    });

    if let Some(object) = extra.as_object() {
        for (key, value) in object {
            reply[key] = value.clone();
        }
    }

    reply
}

/// One challenge, in the shape the real worker puts on the wire.
///
/// `fleet_setup::worker::challenge_event` nests what the metadata builders produced under
/// a `metadata` key, and the broker forwards that frame with `challenge`/`kind`/
/// `expires_at` written over the top. Every challenge fixture in this file goes through
/// here, so the shape these tests drive is the shape the worker sends — the first version
/// of this file spelled the metadata flat and passed against a shape nothing produces.
fn challenge(id: &str, kind: &str, metadata: Value) -> Value {
    json!({
        "operation": "abcdef0123456789",
        "challenge": id,
        "kind": kind,
        "expires_at": 4102444800u64,
        "metadata": metadata,
    })
}

fn status_tag() -> Tag {
    Tag::Devices(DevicesTag::Status {
        operation: "abcdef0123456789".into(),
    })
}

/// The unknown-host question: what it shows, and that trust is an explicit key.
#[test]
fn an_unknown_host_key_shows_its_fingerprint_and_is_trusted_only_on_purpose() {
    let _mode = normal();
    let mut app = deploying();

    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_host_trust",
            json!([challenge(
                "c-host",
                "host_trust",
                json!({ "address": "100.64.12.44",
                "port": 22,
                "algorithm": "ssh-ed25519",
                "sha256_fingerprint": "SHA256:0Yp1rL8mQe3xTgH2vKd9NcZaWbXuJiOpQrStUvWxYz0",
                "user": "deploy" })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        text.contains("This host has not been seen before"),
        "{text}"
    );
    assert!(
        text.contains("ssh-ed25519"),
        "the algorithm is missing:\n{text}"
    );
    assert!(
        text.contains("SHA256:0Yp1rL8mQe3xTgH2vKd9NcZaWbXuJiOpQrStUvWxYz0"),
        "the fingerprint is missing:\n{text}"
    );
    assert!(text.contains("100.64.12.44"), "{text}");
    assert!(text.contains("deploy"), "the account is missing:\n{text}");
    assert!(
        text.contains("Verify this fingerprint independently"),
        "the verify-independently line is missing:\n{text}"
    );
    assert!(text.contains("Trust this host and continue"), "{text}");

    // Enter is not an answer. Only `t` is.
    app.apply(key(KeyCode::Enter));
    assert!(
        drained(&mut app).is_empty(),
        "Enter accepted an unknown host key"
    );

    app.apply(key(KeyCode::Char('t')));
    let calls = drained(&mut app);
    let confirm = call_for(&calls, "fleet.deployment.confirm_host");

    assert_eq!(confirm.params["operation_id"], json!("abcdef0123456789"));
    assert_eq!(confirm.params["challenge"], json!("c-host"));
    assert_eq!(confirm.params["accept"], json!(true));
}

/// Declining sends a refusal rather than nothing, so the attempt fails cleanly.
#[test]
fn declining_an_unknown_host_refuses_it_explicitly() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_host_trust",
            json!([challenge(
                "c-host",
                "host_trust",
                json!({ "address": "100.64.12.44", "port": 22, "user": "deploy",
                     "algorithm": "ssh-ed25519", "sha256_fingerprint": "SHA256:aaa" })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    app.apply(key(KeyCode::Char('n')));
    let calls = drained(&mut app);

    assert_eq!(
        call_for(&calls, "fleet.deployment.confirm_host").params["accept"],
        json!(false)
    );
}

/// A changed key is never offered as a question; it blocks, in words.
#[test]
fn a_changed_host_key_blocks_rather_than_asking() {
    let _mode = normal();
    let mut app = deploying();

    app.apply(Msg::Answer {
        tag: status_tag(),
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "refused".into(),
            data: Some(json!({
                "reason": "worker_refused",
                "worker_reason": "host_key_changed",
            })),
        })),
    });

    let text = prose(&mut app);
    assert!(text.contains("host's key has changed"), "{text}");
    assert!(text.contains("never accepted here"), "{text}");
    assert!(
        !text.contains("Trust this host"),
        "a changed key was offered as a trust prompt:\n{text}"
    );
}

/// The password question, and the passphrase question, drawn from metadata only.
#[test]
fn both_secret_challenges_are_labelled_from_their_own_metadata() {
    let _mode = normal();
    // Password: the account, the target and the bounded attempt count.
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44",
                     "user": "deploy", "port": 22, "attempt": 2, "max_attempts": 3 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(text.contains("Password for this connection"), "{text}");
    assert!(text.contains("deploy"), "{text}");
    assert!(text.contains("100.64.12.44"), "{text}");
    assert!(
        text.contains("2 of 3"),
        "the attempt budget is missing:\n{text}"
    );
    assert!(text.contains("not kept for a reconnection"), "{text}");

    // Passphrase: a different question, labelled with the key rather than the account.
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pp",
                "passphrase",
                json!({ "key_label": "id_ed25519", "public_fingerprint": "SHA256:bbb" })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(text.contains("Passphrase for a private key"), "{text}");
    assert!(text.contains("id_ed25519"), "{text}");
    assert!(text.contains("SHA256:bbb"), "{text}");
    assert!(
        !text.contains("Password for this connection"),
        "a passphrase was labelled a password:\n{text}"
    );
}

/// The plan is shown whole, and approval carries exactly the digest reviewed.
#[test]
fn the_reviewed_plan_is_drawn_and_approved_by_its_own_digest() {
    let _mode = normal();
    let mut app = deploying();

    let plan = json!({
        "schema": 1,
        "operation": "abcdef0123456789",
        "kind": "add",
        "deployment_host": {
            "hostname": "studio", "user": "ada",
            "os": "darwin", "arch": "aarch64-apple-darwin", "issuer": true
        },
        "target": {
            "machine": "build-linux", "address": "100.64.12.44", "port": 22,
            "ssh_user": "deploy", "identity": "agent: id_ed25519",
            "install_path": "bin/ouro",
            "host_fingerprint": "SHA256:0Yp1rL8m"
        },
        "release": {
            "version": "0.1.8", "target": "x86_64-unknown-linux-gnu",
            "asset": "ouro-linux.tar.gz",
            "sha256": "9f2c1b7ae4d60358aa1f2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef",
            "official_origin": true
        },
        "service": "managed",
        "members": [
            { "machine": "studio", "host": "100.64.12.21",
              "reached_by": "local", "change": "add build-linux to the roster" }
        ],
        "grants": ["broad fleet trust between every member"]
    });

    // The digest the worker would send: sha256 over the canonical JSON of the document,
    // computed here with the same two public helpers `Plan::digest` uses. A hand-written
    // constant would be a test that only proves this client echoes whatever it is told.
    let digest = ouro::fleet_setup::sha256_hex(ouro::fleet_setup::canonical_json(&plan).as_bytes());

    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_review",
            json!([challenge(
                "c-review",
                "review",
                json!({ "plan_digest": digest, "plan": plan })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        text.contains("Review this plan before it is applied"),
        "{text}"
    );
    assert!(text.contains("build-linux"), "{text}");
    assert!(text.contains("deploy@100.64.12.44 port 22"), "{text}");
    assert!(
        text.contains("bin/ouro"),
        "the install path is missing:\n{text}"
    );
    assert!(text.contains("0.1.8"), "the release is missing:\n{text}");
    assert!(
        text.contains("broad fleet trust between every member"),
        "the grant is not stated:\n{text}"
    );
    assert!(text.contains(&digest), "the digest is not shown:\n{text}");
    assert!(
        !text.contains("does not match"),
        "an honest plan was reported as a mismatch:\n{text}"
    );

    app.apply(key(KeyCode::Char('a')));
    let calls = drained(&mut app);
    let start = call_for(&calls, "fleet.deployment.start");

    // What is approved is the digest this client computed over the plan it drew.
    assert_eq!(start.params["plan_digest"], json!(digest));
    assert_eq!(start.params["operation_id"], json!("abcdef0123456789"));

    let key = start.params["idempotency_key"]
        .as_str()
        .expect("an idempotency key");
    assert!(
        key.starts_with("abcdef0123456789-"),
        "the key is not derived from the operation: {key}"
    );
}

/// A plan this client cannot read is never approved by pressing a key next to it.
#[test]
fn an_unreadable_plan_is_refused_rather_than_approved_blind() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_review",
            json!([challenge(
                "c-review",
                "review",
                json!({ "plan_digest": "abc", "plan": { "not": "a plan" } })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(text.contains("could not read the plan"), "{text}");
    assert!(text.contains("Cancel the setup"), "{text}");
    assert!(
        !text.contains("Deploy Ouroboros \u{2014} applies exactly this plan"),
        "an unreadable plan still offered approval:\n{text}"
    );

    // And pressing the key that would approve one sends nothing at all.
    app.apply(key(KeyCode::Char('a')));
    let calls = drained(&mut app);
    assert!(
        !calls
            .iter()
            .any(|call| call.method == "fleet.deployment.start"),
        "a plan nobody could read was approved anyway: {:?}",
        calls.iter().map(|call| &call.method).collect::<Vec<_>>()
    );
}

/// Progress: every state has words, and per-step outcomes are drawn.
#[test]
fn progress_draws_each_state_in_words_with_its_step_outcomes() {
    let _mode = normal();
    for (state, expected) in [
        ("attaching", "connecting to the deployment worker"),
        ("inspecting", "inspecting the target"),
        ("deploying", "deploying"),
        ("restarting_host", "restarting this runtime"),
        ("checking_readiness", "checking readiness"),
    ] {
        let mut app = deploying();
        answer(
            &mut app,
            status_tag(),
            snapshot(
                state,
                json!([]),
                json!({
                    "steps": [
                        { "machine": "build-linux", "step": "inspect", "outcome": "ok" },
                        { "machine": "build-linux", "step": "install",
                          "outcome": "failed", "detail": "the archive did not verify" }
                    ]
                }),
            ),
        );
        let _polled = drained(&mut app);

        let text = prose(&mut app);
        assert!(text.contains(expected), "{state}:\n{text}");
        assert!(text.contains("inspect"), "{state} lost its steps:\n{text}");
        assert!(
            text.contains("the archive did not verify"),
            "{state} lost a step detail:\n{text}"
        );
        assert!(text.contains("a live worker"), "{state}:\n{text}");
    }
}

/// Finishing offers the three next steps, and does not claim to have taken them.
#[test]
fn a_completed_setup_offers_the_three_explicit_next_actions() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot("completed", json!([]), json!({})),
    );

    let text = prose(&mut app);
    assert!(text.contains("This device is set up"), "{text}");
    assert!(text.contains("Open device"), "{text}");
    assert!(text.contains("Configure model"), "{text}");
    assert!(text.contains("Run test task"), "{text}");
    assert!(
        text.contains("a first task is an explicit action"),
        "the page implied a task was run:\n{text}"
    );
}

/// A failure shows the steps that did run, the cause, the residue, and offers retry.
#[test]
fn a_failed_setup_shows_its_cause_and_residue_and_offers_a_retry() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "failed",
            json!([]),
            json!({
                "last_error": "the target refused the key",
                "residue": ["a partial archive at /home/deploy/.cache/ouro"],
                "steps": [{ "machine": "build-linux", "step": "inspect", "outcome": "ok" }]
            }),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(text.contains("This setup did not finish"), "{text}");
    assert!(text.contains("the target refused the key"), "{text}");
    assert!(text.contains("Left behind"), "{text}");
    assert!(
        text.contains("a partial archive at /home/deploy/.cache/ouro"),
        "{text}"
    );
    assert!(text.contains("Retry"), "{text}");
    assert!(
        text.contains("puts the plan up for review"),
        "the screen does not say what Retry does:\n{text}"
    );

    // Retry resumes this operation by its id. That is what makes it safe to offer after
    // a failure: a resume re-inspects and puts the plan up for review, so nothing is
    // applied that has not been read again — and it is never a second `start`.
    app.apply(key(KeyCode::Char('R')));
    let calls = drained(&mut app);

    assert!(
        !calls
            .iter()
            .any(|call| call.method == "fleet.deployment.start"),
        "retry resent an approval"
    );

    let resume = call_for(&calls, "fleet.deployment.resume");
    assert_eq!(resume.params, json!({ "operation_id": "abcdef0123456789" }));
    assert!(
        resume.params.get("takeover").is_none(),
        "retry took an operation over without asking"
    );
}

/// The proposal's step 5 on the row: a failure offers Retry and reads as a failure.
#[test]
fn a_failed_setup_offers_retry_on_its_row_and_a_cancelled_one_offers_a_fresh_deployment() {
    let _mode = normal();

    for (state, label, method) in [
        (
            "failed",
            "Setup failed \u{b7} Retry",
            Some("fleet.deployment.resume"),
        ),
        (
            "interrupted",
            "Continue setup",
            Some("fleet.deployment.resume"),
        ),
        // The broker's own terminal set is completed and cancelled: a resume of one
        // answers `operation_finished`, so the row offers a new operation instead of a
        // call that would be refused.
        ("cancelled", "Setup cancelled \u{b7} Deploy again", None),
    ] {
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "abcdef0123456789", "state": state, "kind": "add",
            "owner": "local-owner", "attached": false, "readable": true,
            "target": { "machine": "build-linux", "address": "100.64.12.44",
                        "ssh_user": "deploy", "port": 22 }
        }]);

        let mut app = with_inventory(reply);
        let _settled = drained(&mut app);

        let drawn = screen(&mut app);
        let row = device_row(&drawn, "build-linux").to_string();
        drop(drawn);

        assert!(row.contains(label), "{state}: {row:?}");
        assert!(
            !row.contains("Deploy Ouroboros"),
            "{state} lost its operation: {row:?}"
        );

        activate(&mut app, "build-linux");
        let calls = drained(&mut app);

        match method {
            Some(expected) => {
                assert_eq!(
                    call_for(&calls, expected).params,
                    json!({ "operation_id": "abcdef0123456789" }),
                    "{state}"
                );
            }
            None => {
                assert!(
                    !calls
                        .iter()
                        .any(|call| call.method.starts_with("fleet.deployment.")),
                    "{state} issued a call the broker would refuse: {:?}",
                    calls.iter().map(|call| &call.method).collect::<Vec<_>>()
                );
                // It opens the ordinary connect form: a new operation, reviewed from the
                // beginning.
                assert!(prose(&mut app).contains("ssh username"), "{state}");
            }
        }
    }

    // A completed operation says nothing at all; the row describes the device again.
    let mut reply = populated();
    reply["operations"] = json!([{
        "operation": "abcdef0123456789", "state": "completed", "kind": "add",
        "owner": "local-owner", "attached": false, "readable": true,
        "target": { "machine": "build-linux", "address": "100.64.12.44",
                    "ssh_user": "deploy", "port": 22 }
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);
    let drawn = screen(&mut app);

    assert!(device_row(&drawn, "build-linux").contains("Deploy Ouroboros"));
}

/// Cancel stops at a boundary and says what it does not claim.
#[test]
fn cancelling_stops_at_a_boundary_and_does_not_claim_to_undo() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot("deploying", json!([]), json!({})),
    );
    let _polled = drained(&mut app);

    app.apply(key(KeyCode::Char('c')));
    let calls = drained(&mut app);
    let cancel = call_for(&calls, "fleet.deployment.cancel");
    assert_eq!(cancel.params, json!({ "operation_id": "abcdef0123456789" }));

    answer(&mut app, cancel.tag.clone(), json!({}));
    answer(
        &mut app,
        status_tag(),
        snapshot("cancelled", json!([]), json!({ "residue": [] })),
    );

    let text = prose(&mut app);
    assert!(text.contains("This setup was cancelled"), "{text}");
    assert!(
        text.contains("a credential already delivered stays delivered"),
        "the page claimed an undo:\n{text}"
    );
}

/// Leaving does not cancel, and coming back is still following the same operation.
#[test]
fn leaving_keeps_the_operation_and_returning_is_still_following_it() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot("deploying", json!([]), json!({})),
    );
    let _polled = drained(&mut app);

    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none());
    assert!(
        !drained(&mut app)
            .iter()
            .any(|call| call.method.contains("cancel")),
        "leaving cancelled the operation"
    );

    // Reopening reads that operation by its id, which is what "reloads by operation id"
    // means for a client that never forgot it.
    app.open_devices();
    let calls = drained(&mut app);
    let status = call_for(&calls, "fleet.deployment.status");
    assert_eq!(status.params, json!({ "operation_id": "abcdef0123456789" }));

    let text = prose(&mut app);
    assert!(text.contains("operation abcdef0123456789"), "{text}");
    assert!(text.contains("deploying"), "{text}");

    // `b` goes back to the list without stopping anything.
    app.apply(key(KeyCode::Char('b')));
    let calls = drained(&mut app);
    assert!(
        !calls.iter().any(|call| call.method.contains("cancel")),
        "going back to the list cancelled the operation"
    );
}

/// A client that never saw the operation finds it on the row, and continues it by id.
///
/// This is acceptance 15's case: the page was closed, or this client was restarted, and
/// the only record is the one the deployment host holds.
#[test]
fn a_fresh_client_finds_the_open_setup_on_the_row_and_continues_it_by_id() {
    let _mode = normal();
    let mut reply = populated();
    reply["operations"] = json!([{
        "operation": "abcdef0123456789", "state": "deploying", "kind": "add",
        "owner": "local-owner", "attached": true, "readable": true,
        "updated_at": "2026-09-17T08:00:00Z",
        "target": { "machine": "build-linux", "address": "100.64.12.44",
                    "ssh_user": "deploy", "port": 22 }
    }]);

    let mut app = with_inventory(reply);
    let text = prose(&mut app);

    assert!(text.contains("a setup is open"), "{text}");
    assert!(text.contains("abcdef0123456789"), "{text}");
    assert!(
        text.contains("started by local-owner"),
        "the owner is not named:\n{text}"
    );
    assert!(
        text.contains("Continue setup"),
        "the row does not offer to continue:\n{text}"
    );

    // Pressing it reads that operation by id. A worker is attached, so nothing resumes.
    let _settled = drained(&mut app);
    activate(&mut app, "build-linux");

    let calls = drained(&mut app);
    let status = call_for(&calls, "fleet.deployment.status");
    assert_eq!(status.params, json!({ "operation_id": "abcdef0123456789" }));
    assert!(
        !calls.iter().any(|call| call.method.contains("resume")),
        "an attached operation was resumed"
    );
}

/// An operation whose worker is gone is resumed — and never with a silent takeover.
#[test]
fn an_operation_with_no_worker_is_resumed_without_asking_for_a_takeover() {
    let _mode = normal();
    let mut app = with_inventory({
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "abcdef0123456789", "state": "interrupted", "kind": "add",
            "owner": "local-owner", "attached": false, "readable": true,
            "target": { "machine": "build-linux", "address": "100.64.12.44",
                        "ssh_user": "deploy", "port": 22 }
        }]);
        reply
    });
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let calls = drained(&mut app);
    let resume = call_for(&calls, "fleet.deployment.resume");

    assert_eq!(resume.params, json!({ "operation_id": "abcdef0123456789" }));
    assert!(
        resume.params.get("takeover").is_none(),
        "a resume carried takeover without being asked: {}",
        resume.params
    );
}

// ---------------------------------------------------------------------------------------
// authority
// ---------------------------------------------------------------------------------------

/// Another identity's setup is never inherited quietly.
#[test]
fn taking_over_another_identitys_setup_is_an_explicit_answer_naming_its_owner() {
    let _mode = normal();
    let mut app = with_inventory({
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "abcdef0123456789", "state": "awaiting_auth", "kind": "add",
            "owner": "grace", "attached": false, "readable": true,
            "target": { "machine": "build-linux", "address": "100.64.12.44",
                        "ssh_user": "deploy", "port": 22 }
        }]);
        reply
    });
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let calls = drained(&mut app);
    let resume = call_for(&calls, "fleet.deployment.resume");
    assert!(resume.params.get("takeover").is_none());

    // The runtime says it is not ours.
    refuse(
        &mut app,
        resume.tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({ "reason": "operation_not_yours" })),
    );

    let text = prose(&mut app);
    assert!(text.contains("Take over this setup?"), "{text}");
    assert!(text.contains("grace"), "the owner is not named:\n{text}");
    assert!(
        text.contains("inheriting someone else's password prompt"),
        "the consequence is not stated:\n{text}"
    );
    assert!(text.contains("Take over this setup"), "{text}");
    assert!(text.contains("Leave it alone"), "{text}");

    // Nothing is sent while the question is open, not even a poll.
    app.apply(Msg::Tick);
    let idle = drained(&mut app);
    assert!(
        !idle
            .iter()
            .any(|call| call.method.starts_with("fleet.deployment")),
        "the view kept calling while the takeover question was open: {:?}",
        idle.iter().map(|call| &call.method).collect::<Vec<_>>()
    );

    // Only `t` sends it, and only then does `takeover` appear.
    app.apply(key(KeyCode::Char('t')));
    let calls = drained(&mut app);
    let takeover = call_for(&calls, "fleet.deployment.resume");

    assert_eq!(takeover.params["takeover"], json!(true));
    assert_eq!(takeover.params["operation_id"], json!("abcdef0123456789"));
}

/// Declining a takeover leaves the operation where it was.
#[test]
fn declining_a_takeover_sends_nothing_and_says_so() {
    let _mode = normal();
    let mut app = with_inventory({
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "abcdef0123456789", "state": "awaiting_auth",
            "owner": "grace", "attached": false, "readable": true,
            "target": { "machine": "build-linux", "address": "100.64.12.44",
                        "ssh_user": "deploy", "port": 22 }
        }]);
        reply
    });
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let calls = drained(&mut app);
    refuse(
        &mut app,
        call_for(&calls, "fleet.deployment.resume").tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({ "reason": "operation_not_yours" })),
    );

    app.apply(key(KeyCode::Char('n')));
    let calls = drained(&mut app);

    assert!(
        !calls.iter().any(|call| call.method.contains("resume")),
        "declining still resumed"
    );
    assert!(screen(&mut app).contains("still running under the identity"));
}

/// An unattributable operation is the same question, with the gap named.
#[test]
fn an_operation_with_no_recorded_owner_still_asks_before_taking_over() {
    let _mode = normal();
    let mut app = with_inventory({
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "abcdef0123456789", "state": "interrupted",
            "owner": Value::Null, "attached": false, "readable": true,
            "target": { "machine": "build-linux", "address": "100.64.12.44",
                        "ssh_user": "deploy", "port": 22 }
        }]);
        reply
    });
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let calls = drained(&mut app);
    refuse(
        &mut app,
        call_for(&calls, "fleet.deployment.resume").tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({ "reason": "operation_not_yours" })),
    );

    assert!(prose(&mut app).contains("an identity this runtime could not establish"));
}

/// A runtime that does not serve the inventory is a different fact from one that
/// refuses this identity, and both fall back to the membership subset.
#[test]
fn an_absent_capability_and_a_denied_permission_say_different_things() {
    let _mode = normal();
    // Absent: `fleet.devices` is not in `hello.methods` at all.
    let mut app = opened(support::hello(&["fleet.status", "runtime.status"]));
    let calls = drained(&mut app);

    assert!(
        !calls.iter().any(|call| call.method == "fleet.devices"),
        "a method this gateway does not serve was still called"
    );

    answer(
        &mut app,
        call_for(&calls, "fleet.status").tag.clone(),
        json!({
            "fleet_name": "studio's fleet",
            "machines": [
                { "machine": "studio", "state": "local" },
                { "machine": "build-linux", "state": "connected" }
            ]
        }),
    );

    let text = prose(&mut app);
    assert!(text.contains("does not serve fleet.devices"), "{text}");
    assert!(
        text.contains("studio's fleet"),
        "the subset is missing:\n{text}"
    );
    assert!(text.contains("build-linux"), "{text}");

    // Denied: served, and refused for this identity. `fleet.devices` is a read-scope
    // method, so the only thing a -32003 can mean here is the administrator rule.
    let mut app = opened(full_hello());
    let calls = drained(&mut app);
    refuse(
        &mut app,
        call_for(&calls, "fleet.devices").tag.clone(),
        ErrorCode::ScopeDenied,
        None,
    );

    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.status").tag.clone(),
        json!({ "fleet_name": "studio's fleet", "machines": [] }),
    );

    let text = prose(&mut app);
    assert!(
        text.contains("this identity is not an administrator"),
        "a denied permission read as an absent capability:\n{text}"
    );
    assert!(
        !text.contains("does not serve fleet.devices"),
        "a denied permission read as an absent capability:\n{text}"
    );
}

/// A read-scope listener sees the inventory and cannot start a deployment.
#[test]
fn a_read_scope_listener_shows_the_devices_and_refuses_to_deploy() {
    let _mode = normal();
    let mut app = opened(read_hello(&[
        "fleet.devices",
        "fleet.status",
        "fleet.deployment.prepare",
        "runtime.status",
    ]));
    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.devices").tag.clone(),
        populated(),
    );
    let _settled = drained(&mut app);

    assert!(screen(&mut app).contains("build-linux"));

    activate(&mut app, "build-linux");

    assert!(
        drained(&mut app).is_empty(),
        "a read-scope listener started a deployment"
    );
    assert!(prose(&mut app).contains("started at read scope"));
}

/// A runtime that cannot deploy explains why rather than offering an inert action.
#[test]
fn a_runtime_that_cannot_deploy_explains_the_blocker_instead_of_offering_deploy() {
    let _mode = normal();
    for (reason, expected) in [
        (
            "no_ca_key",
            "does not hold the fleet's certificate authority key",
        ),
        (
            "ouro_path_unknown",
            "cannot say where its own ouro executable is",
        ),
        ("no_data_dir", "serves no durable data directory"),
        ("cleartext_web_bind", "credential entry is refused"),
    ] {
        let mut reply = populated();
        reply["host"] = host(false, &[reason]);

        let mut app = with_inventory(reply);
        let _settled = drained(&mut app);

        let text = prose(&mut app);
        assert!(
            text.contains("Deploy is unavailable here"),
            "{reason}:\n{text}"
        );
        assert!(text.contains(expected), "{reason}:\n{text}");
        assert!(
            !text.contains(reason),
            "{reason} was printed as its own code:\n{text}"
        );

        activate(&mut app, "build-linux");
        assert!(
            drained(&mut app).is_empty(),
            "{reason} still let a deployment start"
        );
    }
}

/// "Set up this device" is the first local fleet: no account, no host key, same review.
#[test]
fn setting_up_this_machine_asks_for_no_ssh_and_prepares_a_setup_operation() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "os": "macos",
        "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    let drawn = screen(&mut app);
    assert!(device_row(&drawn, "studio").contains("Set up this device"));
    drop(drawn);

    activate(&mut app, "studio");

    // The form has a machine name and a service choice, and none of the SSH fields.
    let text = prose(&mut app);
    assert!(text.contains("Set up this device"), "{text}");
    assert!(text.contains("machine name"), "{text}");
    assert!(text.contains("startup service"), "{text}");
    assert!(
        !text.contains("ssh username"),
        "the local setup asked for an SSH account:\n{text}"
    );
    assert!(
        text.contains("without SSH to itself"),
        "the screen does not say why there is no account:\n{text}"
    );

    // And the required-username refusal does not fire on a form with no username.
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["kind"], json!("setup"));
    assert_eq!(prepare.params["machine"], json!("studio"));
    assert_eq!(prepare.params["address"], json!("100.64.12.21"));
    assert_eq!(prepare.params["service"], json!(true));
    assert!(
        prepare.params.get("ssh_user").is_none(),
        "a local setup carried an SSH account: {}",
        prepare.params
    );
    assert!(prepare.params.get("target").is_none(), "{}", prepare.params);
    assert!(
        prepare.params.get("identity").is_none(),
        "{}",
        prepare.params
    );
    assert!(
        !prose(&mut app).contains("An SSH username is required"),
        "the add-only refusal fired on a setup form"
    );
}

/// A first local setup restarts the runtime this client is attached to.
///
/// The worker is detached, so the deployment does not stop when the runtime does — but
/// this client's connection does. What the operator must not see is the operation
/// vanishing: it is an interruption, it reconnects, and it comes back by its own id.
#[test]
fn the_hosting_runtimes_restart_is_an_interruption_that_reloads_by_operation_id() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "os": "macos",
        "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);
    activate(&mut app, "studio");
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.deployment.prepare").tag.clone(),
        json!({ "operation_id": "abcdef0123456789" }),
    );

    // The runtime restarts itself as part of the plan.
    answer(
        &mut app,
        status_tag(),
        snapshot("restarting_host", json!([]), json!({})),
    );
    let _polled = drained(&mut app);
    assert!(prose(&mut app).contains("restarting this runtime"));

    // The connection goes. The operation is not cancelled by that, and nothing is sent.
    app.apply(Msg::Answer {
        tag: status_tag(),
        result: Err(ClientError::ConnectionClosed),
    });
    let during = drained(&mut app);
    assert!(
        !during.iter().any(|call| call.method.contains("cancel")),
        "losing the connection cancelled the setup"
    );

    // It comes back as a journal read — no worker attached — and by the same id. The
    // failed read backs off by the snapshot cadence, so the reconnect is a few ticks away
    // rather than the next one.
    for _ in 0..20 {
        app.apply(Msg::Tick);
    }
    let calls = drained(&mut app);
    let status = call_for(&calls, "fleet.deployment.status");
    assert_eq!(status.params, json!({ "operation_id": "abcdef0123456789" }));

    answer(
        &mut app,
        status_tag(),
        json!({
            "operation": "abcdef0123456789", "source": "journal", "attached": false,
            "state": "interrupted", "owner": "local-owner",
            "steps": [{ "machine": "studio", "step": "create", "outcome": "ok" }],
            "log": [], "challenges": [],
            "last_error": "the runtime this operation is running from restarted"
        }),
    );

    let text = prose(&mut app);
    assert!(text.contains("This setup was interrupted"), "{text}");
    assert!(
        text.contains("the journal; no worker is attached"),
        "the source of the answer is not stated:\n{text}"
    );
    assert!(
        text.contains("create"),
        "the steps that did run are gone:\n{text}"
    );
}

// ---------------------------------------------------------------------------------------
// the secret
// ---------------------------------------------------------------------------------------

/// The one string in this file that must never be found anywhere but the call that
/// consumes it. Unique, so a search for it cannot match anything incidental.
const SECRET: &str = "zx9Qv-unique-secret-Kp4w";

/// Typed, masked, sent once, and then gone from everywhere this client can be looked at.
#[test]
fn a_typed_secret_is_masked_sent_once_and_retained_nowhere() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44",
                     "user": "deploy", "port": 22, "attempt": 1, "max_attempts": 3 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    for message in typed(SECRET) {
        app.apply(message);
    }

    // While it is being typed it is bullets, and it is already not in the frame.
    let text = prose(&mut app);
    assert!(
        text.contains(&"\u{2022}".repeat(SECRET.chars().count())),
        "the field is not masked:\n{text}"
    );
    assert!(
        !text.contains(SECRET),
        "the secret was drawn while being typed:\n{text}"
    );
    assert!(
        !format!("{:?}", app.devices).contains(SECRET),
        "the secret is in the view's Debug while being typed"
    );

    app.apply(key(KeyCode::Enter));

    // It reached exactly one call, in the parameter that consumes it.
    let calls = drained(&mut app);
    let authenticate = call_for(&calls, "fleet.deployment.authenticate");

    assert_eq!(authenticate.params["secret"], json!(SECRET));
    assert_eq!(authenticate.params["challenge"], json!("c-pw"));
    assert_eq!(
        authenticate.params["operation_id"],
        json!("abcdef0123456789")
    );

    let carrying = calls
        .iter()
        .filter(|call| {
            serde_json::to_string(&call.params)
                .unwrap()
                .contains(SECRET)
        })
        .count();
    assert_eq!(carrying, 1, "the secret is in more than one request");

    // And it is not on the tag, which is cloned, hashed and Debug-printed.
    assert!(
        !format!("{:?}", authenticate.tag).contains(SECRET),
        "the secret is on the correlation tag: {:?}",
        authenticate.tag
    );

    // After the submit: not in the frame, not in the view's state, not in a notice.
    let text = prose(&mut app);
    assert!(!text.contains(SECRET), "the secret is still drawn:\n{text}");
    assert!(
        !format!("{:?}", app.devices).contains(SECRET),
        "the secret survived the submit in the view's Debug"
    );

    // A second Enter cannot resend it: the buffer is empty and the call is in flight.
    app.apply(key(KeyCode::Enter));
    let again = drained(&mut app);
    assert!(
        !again.iter().any(|call| serde_json::to_string(&call.params)
            .unwrap()
            .contains(SECRET)),
        "a second Enter resent the secret"
    );
}

/// Cancelling the question clears the buffer without sending anything.
#[test]
fn leaving_a_challenge_clears_what_was_typed_without_sending_it() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    for message in typed(SECRET) {
        app.apply(message);
    }
    app.apply(key(KeyCode::Esc));

    let calls = drained(&mut app);
    assert!(
        !calls.iter().any(|call| serde_json::to_string(&call.params)
            .unwrap()
            .contains(SECRET)),
        "Esc sent the secret"
    );
    assert!(
        !calls.iter().any(|call| call.method.contains("cancel")),
        "Esc cancelled the operation"
    );
    assert!(
        !format!("{:?}", app.devices).contains(SECRET),
        "Esc left the secret in the view's state"
    );
    assert!(app.overlay.is_none(), "Esc did not leave the view");
}

/// A consumed challenge takes its buffer with it, so a stale answer cannot be resent to
/// the next question.
#[test]
fn a_new_challenge_never_inherits_the_previous_ones_buffer() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-first",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    for message in typed(SECRET) {
        app.apply(message);
    }

    // The worker replaces the question before the operator pressed Enter — a retry after
    // a wrong password is exactly this.
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-second",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22,
                     "attempt": 2, "max_attempts": 3 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    // The Debug check alone is vacuous here: `SecretInput`'s `Debug` redacts, so it
    // reads the same whether the buffer was cleared or not. What is actually observable
    // is the field, which draws one bullet per character — and after the swap there are
    // none, because there is nothing left to draw.
    assert_eq!(
        bullets(&mut app),
        0,
        "the buffer survived its challenge being replaced"
    );
    assert!(!format!("{:?}", app.devices).contains(SECRET));

    app.apply(key(KeyCode::Enter));
    let calls = drained(&mut app);
    assert!(
        !calls.iter().any(|call| serde_json::to_string(&call.params)
            .unwrap()
            .contains(SECRET)),
        "the previous question's answer was sent to the new one"
    );
}

/// A refused answer is reported where the answer went, with the broker's own reason.
#[test]
fn a_refused_answer_is_explained_in_the_place_the_answer_went() {
    let _mode = normal();
    for (reason, expected) in [
        ("challenge_consumed", "already been answered once"),
        ("challenge_expired", "expired before it was answered"),
        ("challenge_not_bound", "asked of a different session"),
    ] {
        let mut app = deploying();
        answer(
            &mut app,
            status_tag(),
            snapshot(
                "awaiting_auth",
                json!([challenge(
                    "c-pw",
                    "password",
                    json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
                )]),
                json!({}),
            ),
        );
        let _polled = drained(&mut app);

        for message in typed(SECRET) {
            app.apply(message);
        }
        app.apply(key(KeyCode::Enter));

        let calls = drained(&mut app);
        refuse(
            &mut app,
            call_for(&calls, "fleet.deployment.authenticate")
                .tag
                .clone(),
            ErrorCode::UpstreamError,
            Some(json!({ "reason": reason })),
        );

        let text = prose(&mut app);
        assert!(text.contains(expected), "{reason}:\n{text}");
        assert!(
            !text.contains(SECRET),
            "{reason} echoed the secret:\n{text}"
        );
    }
}

/// A plan that changed between review and approval is refused in words, not applied.
#[test]
fn a_plan_that_changed_since_review_is_reported_rather_than_applied() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_review",
            json!([challenge(
                "c-review",
                "review",
                json!({ "plan_digest": "abc",
                     "plan": { "not": "a plan" } })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    // Approving an unreadable plan is already refused, so drive `start` through the
    // refusal path the runtime answers with.
    app.apply(Msg::Answer {
        tag: Tag::Devices(DevicesTag::Answer {
            operation: "abcdef0123456789".into(),
            label: "fleet.deployment.start",
        }),
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "refused".into(),
            data: Some(json!({
                "reason": "worker_refused",
                "worker_reason": "plan_changed"
            })),
        })),
    });

    assert!(prose(&mut app).contains("changed after it was reviewed"));
}

// ---------------------------------------------------------------------------------------
// screen-reader mode
// ---------------------------------------------------------------------------------------

/// A10, on this view: labelled lines, numbered menus, a digit that selects, and a bell
/// when the deployment stops for a person.
///
/// Serialised on the same mutex `tests/accessibility.rs` uses, and for the same reason:
/// screen-reader mode is a process-wide flag and `cargo test` runs these on many threads.
#[test]
fn screen_reader_mode_numbers_the_rows_drops_the_box_and_rings_for_a_question() {
    let _mode = screen_reader();

    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);
    let drawn = screen(&mut app);
    let text = drawn.text();

    // No box drawing at all: a rule character is a cell with no word in it.
    for glyph in ['\u{2502}', '\u{250c}', '\u{2510}', '\u{2514}', '\u{2518}'] {
        assert!(
            !text.contains(glyph),
            "{glyph:?} survived screen-reader mode:\n{text}"
        );
    }

    // The rows are numbered, and a digit picks one.
    assert!(
        drawn.rows.iter().any(|row| row.contains("1. studio")),
        "the rows are not numbered:\n{text}"
    );
    assert!(
        drawn.rows.iter().any(|row| row.contains("2. build-linux")),
        "the rows are not numbered:\n{text}"
    );
    drop(drawn);

    app.apply(key(KeyCode::Char('2')));
    let drawn = screen(&mut app);
    assert!(
        device_row(&drawn, "build-linux").contains("> 2. build-linux"),
        "a digit did not select its row:\n{}",
        drawn.text()
    );
    drop(drawn);

    // The middle dot this client writes is spoken, not punctuation nobody can hear.
    let hint = ouro::ui::app::devices_hint_line(&app);
    assert!(hint.contains('\u{b7}'), "the raw hint lost its separator");

    // A question rings the bell. `notify::permitted` returns true in this mode whether or
    // not the terminal has focus, and `channel` resolves `auto` to the bell.
    let mut app = deploying();
    let before = app.take_notifications().len();

    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );

    let signals = app.take_notifications();
    assert!(
        signals.len() > before,
        "the agent asked for a credential and nothing rang"
    );

    // And it rings once per question, not once per poll.
    let _polled = drained(&mut app);
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    assert!(
        app.take_notifications().is_empty(),
        "the same question rang twice"
    );

    // But a *second* question after a working stretch rings again. A wrong password is
    // exactly this shape — ask, work, ask — and a bell that went quiet after the first
    // attempt would leave someone listening waiting on a prompt nobody announced.
    let _polled = drained(&mut app);
    answer(
        &mut app,
        status_tag(),
        snapshot("deploying", json!([]), json!({})),
    );
    let _polled = drained(&mut app);
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-again",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22,
                     "attempt": 2, "max_attempts": 3 })
            )]),
            json!({}),
        ),
    );
    assert!(
        !app.take_notifications().is_empty(),
        "the second question did not ring"
    );
}

/// A challenge in screen-reader mode is a numbered menu too.
#[test]
fn a_host_trust_question_is_a_numbered_menu_in_screen_reader_mode() {
    let _mode = screen_reader();

    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_host_trust",
            json!([challenge(
                "c-host",
                "host_trust",
                json!({ "address": "100.64.12.44", "port": 22, "user": "deploy",
                     "algorithm": "ssh-ed25519", "sha256_fingerprint": "SHA256:aaa" })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(text.contains("1. t Trust this host and continue"), "{text}");
    assert!(text.contains("2. n Cancel"), "{text}");
}

// ---------------------------------------------------------------------------------------
// the properties the adversarial review's surviving mutations found nothing guarding
// ---------------------------------------------------------------------------------------

/// A second Enter while the first answer is in flight sends nothing — *because* of the
/// in-flight guard, not because the buffer happens to be empty.
///
/// The earlier version of this could not tell those apart: it pressed Enter on an empty
/// field and watched nothing happen. Here the field is refilled first, so the only thing
/// standing between the second Enter and a second `authenticate` is the guard.
#[test]
fn a_second_answer_is_refused_while_the_first_is_still_in_flight() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    for message in typed(SECRET) {
        app.apply(message);
    }
    app.apply(key(KeyCode::Enter));
    let first = drained(&mut app);
    assert_eq!(
        first
            .iter()
            .filter(|call| call.method == "fleet.deployment.authenticate")
            .count(),
        1
    );

    // Type a whole second secret and press Enter again, with the first still unanswered.
    for message in typed("a-second-secret-entirely") {
        app.apply(message);
    }
    assert_eq!(
        bullets(&mut app),
        0,
        "a challenge with an answer in flight is still taking keystrokes"
    );

    app.apply(key(KeyCode::Enter));
    let second = drained(&mut app);
    assert!(
        !second
            .iter()
            .any(|call| call.method == "fleet.deployment.authenticate"),
        "a second answer was sent while the first was in flight: {:?}",
        second.iter().map(|call| &call.method).collect::<Vec<_>>()
    );
}

/// An empty field sends nothing, and says so rather than sending an empty secret.
#[test]
fn an_empty_secret_is_refused_rather_than_sent() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    app.apply(key(KeyCode::Enter));
    let calls = drained(&mut app);

    assert!(
        !calls
            .iter()
            .any(|call| call.method == "fleet.deployment.authenticate"),
        "an empty secret was sent"
    );
    assert!(prose(&mut app).contains("Nothing was typed"));
}

/// Enter is not an answer to the takeover question. There is no default.
#[test]
fn enter_does_not_take_over_another_identitys_setup() {
    let _mode = normal();
    let mut app = asking_to_take_over();

    app.apply(key(KeyCode::Enter));
    let calls = drained(&mut app);

    assert!(
        !calls.iter().any(|call| call.method.contains("resume")),
        "Enter answered the takeover question: {:?}",
        calls.iter().map(|call| &call.method).collect::<Vec<_>>()
    );
    assert!(
        prose(&mut app).contains("Take over this setup?"),
        "Enter dismissed the question"
    );
}

/// Declining a takeover, and closing the view, both forget what was typed.
#[test]
fn leaving_by_either_door_forgets_the_typed_secret() {
    // Declining the takeover.
    let _mode = normal();
    let mut app = asking_to_take_over();
    app.apply(key(KeyCode::Char('n')));
    assert!(app.devices.operation.is_none());
    assert_eq!(bullets(&mut app), 0);

    // Closing the view on an open password question.
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([challenge(
                "c-pw",
                "password",
                json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
            )]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    for message in typed(SECRET) {
        app.apply(message);
    }
    assert_eq!(bullets(&mut app), SECRET.chars().count());

    app.close_devices();
    assert!(app.overlay.is_none());
    assert!(
        !format!("{:?}", app.devices).contains(SECRET),
        "closing the view kept the secret in its state"
    );

    // Reopening draws an empty field rather than the one that was typed into.
    app.open_devices();
    let _polled = drained(&mut app);
    assert_eq!(
        bullets(&mut app),
        0,
        "the field came back with what was typed into it before"
    );
}

/// An answer for another operation never lands on the one being followed.
#[test]
fn an_answer_for_another_operation_is_ignored() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot("deploying", json!([]), json!({})),
    );
    let _polled = drained(&mut app);
    assert!(prose(&mut app).contains("deploying"));

    // A snapshot for a long-gone operation, in a state that would be very visible.
    app.apply(Msg::Answer {
        tag: Tag::Devices(DevicesTag::Status {
            operation: "0000000000000000".into(),
        }),
        result: Ok(json!({
            "operation": "0000000000000000", "source": "worker", "attached": true,
            "state": "completed", "owner": "local-owner",
            "steps": [], "log": [], "challenges": []
        })),
    });

    let text = prose(&mut app);
    assert!(
        text.contains("deploying"),
        "another operation's snapshot overwrote this one:\n{text}"
    );
    assert!(!text.contains("This device is set up"), "{text}");
}

/// Two open questions are answered in the order the snapshot lists them.
#[test]
fn the_first_open_challenge_is_the_one_answered() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "awaiting_auth",
            json!([
                challenge(
                    "c-aaa",
                    "password",
                    json!({ "target": "100.64.12.44", "user": "deploy", "port": 22 })
                ),
                challenge(
                    "c-zzz",
                    "password",
                    json!({ "target": "100.64.12.44", "user": "other", "port": 22 })
                ),
            ]),
            json!({}),
        ),
    );
    let _polled = drained(&mut app);

    // The broker sorts its open challenges by id, so the first one listed is the one on
    // the screen — and the one a typed answer is addressed to.
    assert!(prose(&mut app).contains("deploy"));

    for message in typed(SECRET) {
        app.apply(message);
    }
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    assert_eq!(
        call_for(&calls, "fleet.deployment.authenticate").params["challenge"],
        json!("c-aaa")
    );
}

/// An operation another identity owns, with the takeover question on the screen.
fn asking_to_take_over() -> App {
    let mut reply = populated();
    reply["operations"] = json!([{
        "operation": "abcdef0123456789", "state": "awaiting_auth", "kind": "add",
        "owner": "grace", "attached": false, "readable": true,
        "target": { "machine": "build-linux", "address": "100.64.12.44",
                    "ssh_user": "deploy", "port": 22 }
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);
    activate(&mut app, "build-linux");

    let calls = drained(&mut app);
    refuse(
        &mut app,
        call_for(&calls, "fleet.deployment.resume").tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({ "reason": "operation_not_yours" })),
    );

    app
}

/// A blocked runtime does not open the form, not merely skip the call.
#[test]
fn a_blocked_runtime_opens_no_connect_form_at_all() {
    let _mode = normal();

    let mut reply = populated();
    reply["host"] = host(false, &["no_ca_key"]);
    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");

    let text = prose(&mut app);
    assert!(
        !text.contains("ssh username"),
        "a form opened on a runtime that cannot deploy:\n{text}"
    );
    assert!(text.contains("Fleet devices"), "the list was left:\n{text}");
    assert!(drained(&mut app).is_empty());

    // And at read scope, the same.
    let mut app = opened(read_hello(&[
        "fleet.devices",
        "fleet.status",
        "fleet.deployment.prepare",
        "runtime.status",
    ]));
    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.devices").tag.clone(),
        populated(),
    );
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let text = prose(&mut app);
    assert!(
        !text.contains("ssh username"),
        "a form opened at read scope:\n{text}"
    );
    assert!(drained(&mut app).is_empty());
}

/// Enter walks the connect form and never submits from a field.
#[test]
fn enter_moves_through_the_connect_form_and_submits_only_from_its_button() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    for message in typed("deploy") {
        app.apply(message);
    }

    // Enter from every field but the last moves on and sends nothing.
    for _ in 0..(ouro::ui::app::ConnectField::ALL.len() - 1) {
        app.apply(key(KeyCode::Enter));
        assert!(
            drained(&mut app).is_empty(),
            "Enter submitted the form from a field"
        );
    }

    // Now the cursor is on the button, and Enter is the submission.
    app.apply(key(KeyCode::Enter));
    let calls = drained(&mut app);
    assert_eq!(
        call_for(&calls, "fleet.deployment.prepare").params["ssh_user"],
        json!("deploy")
    );
}

/// A runtime that does not serve the verb behind an action does not offer the action.
///
/// The three gates are separate questions and this is the one with no other symptom: a
/// runtime holding the CA key, at operate scope, whose `hello.methods` simply does not
/// list `fleet.deployment.prepare` because its `ouro` predates the worker.
#[test]
fn a_runtime_that_does_not_serve_the_verb_says_so_rather_than_opening_a_form() {
    let _mode = normal();

    let mut app = opened(support::hello(&[
        "fleet.devices",
        "fleet.status",
        "runtime.status",
    ]));
    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.devices").tag.clone(),
        populated(),
    );
    let _settled = drained(&mut app);

    // The inventory is there — the gate is about the deployment verb, not the read.
    assert!(screen(&mut app).contains("build-linux"));

    activate(&mut app, "build-linux");

    let text = prose(&mut app);
    assert!(
        !text.contains("ssh username"),
        "a form opened for a verb this runtime does not serve:\n{text}"
    );
    assert!(
        text.contains("does not serve fleet.deployment.prepare"),
        "the missing method is not named:\n{text}"
    );
    assert!(drained(&mut app).is_empty());
}

/// A question with no id is not a question anybody can answer, so it is not drawn.
#[test]
fn a_challenge_with_no_id_is_never_drawn_as_a_prompt() {
    let _mode = normal();
    let mut app = deploying();

    // The worker's own `pending` list has this shape — id and kind and nothing else —
    // and a frame that lost its id in transit has it too. Either way there is nothing to
    // address an answer to.
    answer(
        &mut app,
        status_tag(),
        json!({
            "operation": "abcdef0123456789", "source": "worker", "attached": true,
            "state": "awaiting_auth", "owner": "local-owner",
            "steps": [], "log": [],
            "challenges": [{ "kind": "password",
                             "metadata": { "user": "deploy", "target": "100.64.12.44" } }]
        }),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        !text.contains("Password for this connection"),
        "a prompt was drawn for a question with no id:\n{text}"
    );
    assert_eq!(bullets(&mut app), 0);

    // And nothing typed at it goes anywhere.
    for message in typed(SECRET) {
        app.apply(message);
    }
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    assert!(
        !calls
            .iter()
            .any(|call| call.method == "fleet.deployment.authenticate"),
        "an answer was addressed to a challenge with no id"
    );
    assert!(
        !calls.iter().any(|call| serde_json::to_string(&call.params)
            .unwrap()
            .contains(SECRET)),
        "the secret left the client anyway"
    );
}

/// The live-run failure: a machine with no fleet could never set itself up.
///
/// `capabilities.deploy` is false with `no_ca_key` on exactly the machine "Set up this
/// device" exists for — it has no fleet, so it has no certificate authority — and gating
/// the setup path on it meant pressing Enter did nothing at all. Found by driving the
/// packaged client against a real runtime, which is the only place the two facts appear
/// together.
#[test]
fn a_machine_with_no_fleet_can_still_set_itself_up() {
    let _mode = normal();

    let mut reply = populated();
    reply["host"] = host(false, &["no_ca_key"]);
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "os": "macos",
        "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    // The page says what is true of *this* machine, not "go and open Devices somewhere
    // else": there is nowhere else, and the thing to do is on this screen.
    let text = prose(&mut app);
    assert!(
        text.contains("This machine is not set up yet"),
        "the standalone case still reads as a CA-key misconfiguration:\n{text}"
    );
    assert!(
        !text.contains("Open Devices on the machine that does"),
        "the page sent the operator to a machine that does not exist:\n{text}"
    );

    let drawn = screen(&mut app);
    assert!(device_row(&drawn, "studio").contains("Set up this device"));
    drop(drawn);

    // Enter opens the setup form rather than refusing.
    activate(&mut app, "studio");

    let text = prose(&mut app);
    assert!(
        text.contains("machine name"),
        "Enter on Set up this device did nothing:\n{text}"
    );
    assert!(!text.contains("ssh username"), "{text}");

    // And it submits `kind: "setup"`.
    focus_inspect(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["kind"], json!("setup"));
    assert_eq!(prepare.params["machine"], json!("studio"));
    assert_eq!(prepare.params["address"], json!("100.64.12.21"));
    assert!(
        prepare.params.get("ssh_user").is_none(),
        "{}",
        prepare.params
    );
}

/// Every other blocker still stops a first setup, because those are reasons this runtime
/// cannot run any deployment at all — including one against itself.
#[test]
fn a_first_setup_is_still_stopped_by_every_blocker_but_the_missing_ca_key() {
    let _mode = normal();

    for (reason, expected) in [
        ("cleartext_web_bind", "credential entry is refused"),
        (
            "ouro_path_unknown",
            "cannot say where its own ouro executable is",
        ),
        ("no_data_dir", "serves no durable data directory"),
    ] {
        let mut reply = populated();
        reply["host"] = host(false, &["no_ca_key", reason]);
        reply["devices"] = json!([{
            "name": "studio", "machine": Value::Null, "os": "macos",
            "address": "100.64.12.21", "online": true,
            "state": "this_device_without_profile", "action": "set up this device",
            "name_conflicts_with_roster": Value::Null,
        }]);

        let mut app = with_inventory(reply);
        let _settled = drained(&mut app);

        activate(&mut app, "studio");

        let text = prose(&mut app);
        assert!(
            !text.contains("machine name"),
            "{reason} let a setup form open:\n{text}"
        );
        assert!(text.contains(expected), "{reason}:\n{text}");
        assert!(drained(&mut app).is_empty(), "{reason} issued a call");
    }
}

/// No action is ever refused in silence.
///
/// The notice draws at the foot of the inventory, under the rows and the no-SSH
/// sentence, which on a real screen is below the fold — so a refusal that only went
/// there was a keypress that visibly did nothing. The hint line is the one row always on
/// the page, and every refusal says so there.
#[test]
fn a_refused_action_always_says_so_on_a_row_that_is_on_the_page() {
    let _mode = normal();

    // A row nothing can be done with.
    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "pocket-phone", "machine": Value::Null, "os": "iOS",
        "address": "100.64.12.31", "online": true,
        "state": "unsupported_platform", "action": "nothing to deploy",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    let before = ouro::ui::app::devices_hint_line(&app);
    activate(&mut app, "pocket-phone");
    let after = ouro::ui::app::devices_hint_line(&app);

    assert_ne!(before, after, "the hint line did not change on a refusal");
    assert!(
        after.contains("cannot be deployed to"),
        "the refusal is not on the hint line: {after:?}"
    );

    // And a blocked deployment says its blocker there too.
    let mut reply = populated();
    reply["host"] = host(false, &["cleartext_web_bind"]);
    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    let hint = ouro::ui::app::devices_hint_line(&app);

    assert!(
        hint.contains("credential entry is refused"),
        "the blocker is not on the hint line: {hint:?}"
    );

    // `r` puts the keys back.
    app.apply(key(KeyCode::Char('r')));
    assert!(ouro::ui::app::devices_hint_line(&app).contains("r refresh"));
}
