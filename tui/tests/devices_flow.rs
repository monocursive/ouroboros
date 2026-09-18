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

/// The secret buffer's character count, observed directly rather than through `Debug`.
fn secret_chars(app: &App) -> usize {
    app.devices
        .operation
        .as_ref()
        .map(|operation| operation.secret.len())
        .unwrap_or(0)
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

/// Every button §5.1's action column can put on a row, plus the dash a row with no
/// action carries instead of one.
const ACTIONS: [&str; 7] = [
    "Add to fleet",
    "Set up this Mac",
    "Set up this machine",
    "Open",
    "Continue",
    "Retry",
    "\u{2014}",
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
                // §5.5: the runtime folds the display name into a machine name, or
                // answers `null`. It is the only thing the name field is ever seeded
                // from, so the fixtures carry it exactly as the contract describes it.
                "suggested_machine": suggested(peer.get("HostName").and_then(Value::as_str)),
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

/// A display name folded to a machine name, as §5.5 specifies the runtime does it:
/// lowercased, every run of non-alphanumerics to one hyphen, trimmed, 40 characters,
/// `null` when nothing valid remains.
///
/// Reproduced here rather than imported because the folding runs on the deployment host;
/// what this file tests is that the view pre-fills from the answer and never from `name`.
fn suggested(name: Option<&str>) -> Value {
    let Some(name) = name else {
        return Value::Null;
    };

    let mut folded = String::new();
    for character in name.to_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            folded.push(character);
        } else if !folded.ends_with('-') {
            folded.push('-');
        }
    }

    let folded: String = folded.trim_matches('-').chars().take(40).collect();

    if folded.is_empty() || !folded.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Value::Null;
    }

    json!(folded)
}

/// This machine's own row, in the roster.
fn self_row() -> Value {
    json!({
        "name": "studio",
        "machine": "studio",
        "suggested_machine": "studio",
        "os": "macos",
        "address": "100.64.12.21",
        "online": true,
        "connected": true,
        "last_seen": Value::Null,
        "state": "this_device",
        "action": "view device",
        "name_conflicts_with_roster": Value::Null,
    })
}

/// A host block with the capabilities a test wants, for a reply built by hand.
fn host_with(deploy: bool, reasons: &[&str]) -> Value {
    host(deploy, reasons)
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
        "fleet_name": "studio",
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

/// One list, one line per device, the status line above it and the quiet line under it.
#[test]
fn the_inventory_draws_one_line_per_device_under_a_status_line() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);
    let text = flowed(&screen);

    // The fleet, and how much of it is here.
    assert!(
        text.contains("Fleet of studio \u{b7} 1 of 1 machine connected"),
        "the status line is missing:\n{text}"
    );
    // The one quiet line, not a boxed paragraph.
    assert!(
        text.contains("Actions run on studio as ada."),
        "the deployment-host line is missing:\n{text}"
    );
    // No sections, no legend.
    assert!(!text.contains("Fleet devices"), "{text}");
    assert!(!text.contains("Available on this network"), "{text}");

    // This machine first, under the noun its own OS gives it.
    let first = screen
        .rows
        .iter()
        .position(|row| row.contains("This Mac"))
        .expect("a self row");
    let peer = screen
        .rows
        .iter()
        .position(|row| row.contains("build-linux"))
        .expect("a peer row");
    assert!(first < peer, "the self row is not first:\n{text}");

    // One row, every column §5.1 lists.
    let row = device_row(&screen, "build-linux");
    assert!(row.contains("linux"), "the OS column: {row}");
    assert!(row.contains("100.64.12.44"), "the address column: {row}");
    assert!(
        row.contains("\u{25cf} online"),
        "the presence column: {row}"
    );
    assert!(row.contains("not set up"), "the Ouroboros column: {row}");
    assert!(row.contains("Add to fleet"), "the action column: {row}");

    // Six lines per device is what this replaced: every device fits on one row.
    for name in ["build-linux", "pocket-phone", "old-pi"] {
        assert_eq!(
            screen.rows.iter().filter(|row| row.contains(name)).count(),
            1,
            "{name} is drawn on more than one row:\n{text}"
        );
    }

    // A relative time on the row, never an ISO timestamp.
    assert!(
        !text.contains("2026-09-17T07:50:00.1Z"),
        "a raw timestamp reached a row:\n{text}"
    );
    assert!(text.contains("offline, seen"), "{text}");

    // And the exact time in the details panel, for the row under the cursor.
    assert!(
        text.contains("Not listed? a Add a device by address"),
        "{text}"
    );
}

/// The details panel under the list carries what the row does not.
#[test]
fn the_details_panel_carries_the_exact_time_and_the_runtime_facts() {
    let _mode = normal();
    let mut app = with_inventory(populated());

    // The self row is selected first.
    let text = prose(&mut app);
    assert!(text.contains("in the roster as studio"), "{text}");
    assert!(text.contains("presence online now"), "{text}");
    assert!(text.contains("runtime runtime connected"), "{text}");

    // Move onto the offline peer: the exact observation time is here, not on the row.
    activate_cursor(&mut app, "old-pi");
    let text = prose(&mut app);
    assert!(
        text.contains("offline, last seen 2026-09-17T07:50:00.1Z"),
        "the exact time is not in the details:\n{text}"
    );
    assert!(
        text.contains("Offline is not powered off"),
        "a row with no action does not say why:\n{text}"
    );
}

/// §5.1's Ouroboros column and action column, as the capture's own peers land on them.
#[test]
fn every_state_gets_one_word_and_one_action() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);

    // A visible, supported, online peer is offered admission, never called uninstalled.
    let build = device_row(&screen, "build-linux");
    assert!(build.contains("not set up"), "{build}");
    assert!(build.contains("Add to fleet"), "{build}");

    // iOS: a platform no release targets. No button, and a dash where one would be.
    let phone = device_row(&screen, "pocket-phone");
    assert!(phone.contains("can't run Ouroboros"), "{phone}");
    assert!(phone.contains('\u{2014}'), "{phone}");
    assert!(!phone.contains("Add to fleet"), "{phone}");

    // Offline, and explicitly not "powered off".
    let pi = device_row(&screen, "old-pi");
    assert!(pi.contains("offline"), "{pi}");

    // This machine, in the roster.
    let this = device_row(&screen, "This Mac");
    assert!(this.contains("in the fleet"), "{this}");
    assert!(this.contains("Open"), "{this}");
}

/// Each way discovery can fail is one line quoting the client's own words.
#[test]
fn a_discovery_failure_is_one_line_quoting_the_client() {
    let _mode = normal();
    for (fixture, code) in [
        ("no-state", "client_missing"),
        ("needs-login", "signed_out"),
        ("running-but-refused", "permission_denied"),
        ("stopped", "unavailable"),
    ] {
        let reply = devices_reply(
            fixture,
            code,
            Some("The Tailscale GUI failed to start"),
            vec![self_row()],
        );
        let mut app = with_inventory(reply);
        let text = prose(&mut app);

        assert!(
            text.contains("Tailscale did not answer from this runtime:"),
            "{code} did not name the client:\n{text}"
        );
        assert!(
            text.contains("The Tailscale GUI failed to start"),
            "{code} dropped the client's own words:\n{text}"
        );
        assert!(
            text.contains("Devices already in the fleet are still listed."),
            "{code} dropped the repair:\n{text}"
        );
        // Never a claim about build age: that was a guess, and a wrong one.
        assert!(
            !text.contains("older than the client"),
            "{code} still guesses at a version mismatch:\n{text}"
        );
        // Known members are retained when discovery is unavailable.
        assert!(text.contains("This Mac"), "{code} lost the roster:\n{text}");
    }

    // A client that answered is not a failure, so there is no notice at all.
    let mut app = with_inventory(populated());
    assert!(!prose(&mut app).contains("Tailscale did not answer"));
}

/// A machine with no fleet says so in the status line, not in a second paragraph.
#[test]
fn a_standalone_machine_says_so_in_its_status_line() {
    let _mode = normal();
    let mut reply = devices_reply("no-peers", "no_visible_peers", None, vec![]);
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "suggested_machine": "studio",
        "os": "macos", "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile",
        "name_conflicts_with_roster": Value::Null,
    }]);
    reply["host"] = host_with(false, &["no_ca_key"]);

    let mut app = with_inventory(reply);
    let text = prose(&mut app);

    assert!(text.contains("This Mac is not in a fleet yet"), "{text}");
    assert!(
        device_row(&screen(&mut app), "This Mac").contains("Set up this Mac"),
        "{text}"
    );
    // The blocker is the status line; it is not said twice.
    assert_eq!(
        text.matches("not in a fleet yet").count(),
        1,
        "the blocker sentence is drawn twice:\n{text}"
    );
}

/// Search and filter are offered only past eight rows.
#[test]
fn search_and_filter_appear_past_eight_rows_and_refresh_always_works() {
    let _mode = normal();

    // Five rows: no search, no filter, and the keys are not on the hint line.
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    let hint = ouro::ui::app::devices_hint_line(&app);
    assert!(!hint.contains("/ search"), "{hint}");
    assert!(!hint.contains("f filter"), "{hint}");
    assert!(hint.contains("a add by address"), "{hint}");
    assert!(hint.contains("x remove (members)"), "{hint}");

    app.apply(key(KeyCode::Char('/')));
    assert!(
        !prose(&mut app).contains("typing"),
        "a short list opened a search field"
    );

    // `r` asks again, whatever the length.
    app.apply(key(KeyCode::Char('r')));
    let calls = drained(&mut app);
    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));

    // Ten rows: the keys appear and narrow the one list.
    let mut rows = vec![self_row()];
    for index in 0..9 {
        rows.push(json!({
            "name": format!("peer-{index}"),
            "machine": Value::Null,
            "suggested_machine": format!("peer-{index}"),
            "os": "linux",
            "address": format!("100.64.9.{index}"),
            "online": true,
            "state": "discovered_installation_unknown",
            "name_conflicts_with_roster": Value::Null,
        }));
    }

    let mut long = with_inventory(devices_reply("running-with-peers", "ok", None, rows));
    let _settled = drained(&mut long);

    let hint = ouro::ui::app::devices_hint_line(&long);
    assert!(hint.contains("/ search"), "{hint}");
    assert!(hint.contains("f filter"), "{hint}");

    long.apply(key(KeyCode::Char('/')));
    for message in typed("peer-3") {
        long.apply(message);
    }
    long.apply(key(KeyCode::Enter));

    let text = prose(&mut long);
    assert!(text.contains("peer-3"), "{text}");
    assert!(!text.contains("peer-4"), "search did not narrow:\n{text}");

    // Esc clears the query rather than closing the view.
    long.apply(key(KeyCode::Char('/')));
    long.apply(key(KeyCode::Esc));
    assert!(matches!(long.overlay, Some(Overlay::Devices)));
    assert!(screen(&mut long).contains("peer-4"));

    // `f` cycles all → fleet → available.
    long.apply(key(KeyCode::Char('f')));
    let text = prose(&mut long);
    assert!(text.contains("This Mac"), "{text}");
    assert!(
        !text.contains("peer-4"),
        "the fleet filter kept a peer:\n{text}"
    );
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

    // Two rows, not one: the member and the device wearing its name.
    let drawn = screen(&mut app);
    for address in ["100.64.12.77", "100.64.12.250"] {
        assert!(
            drawn.rows.iter().any(|row| row.contains(address)),
            "{address} is not on the list:\n{}",
            drawn.text()
        );
    }
    drop(drawn);

    let text = prose(&mut app);
    assert!(
        text.contains("in the fleet \u{b7} not connected"),
        "the real member lost its state:\n{text}"
    );

    // The note is in the impostor's own details, under its own row.
    let mut found = false;
    for _ in 0..8 {
        if prose(&mut app).contains("It is not that machine.") {
            found = true;
            break;
        }
        app.apply(key(KeyCode::Char('j')));
    }
    assert!(
        found,
        "the impostor's row carries no note:\n{}",
        prose(&mut app)
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

/// Moves the cursor onto a named row, without pressing anything.
fn activate_cursor(app: &mut App, name: &str) {
    for _ in 0..40 {
        let drawn = screen(app);
        // The cursor marker, not the start of the line: the line starts with the pane's
        // own border, and in screen-reader mode the name is preceded by its number.
        let selected = device_row(&drawn, name).contains("> ");
        drop(drawn);

        if selected {
            return;
        }

        app.apply(key(KeyCode::Char('j')));
    }
    panic!("never reached the {name} row");
}

/// Moves the cursor onto a named row and presses Enter.
fn activate(app: &mut App, name: &str) {
    activate_cursor(app, name);
    app.apply(key(KeyCode::Enter));
}

/// Moves the cursor onto a named row and presses `x`.
fn remove(app: &mut App, name: &str) {
    activate_cursor(app, name);
    app.apply(key(KeyCode::Char('x')));
}

/// Moves the connect form's cursor onto its submit row.
fn focus_submit(app: &mut App) {
    for _ in 0..16 {
        let drawn = screen(app);
        // The three forms label their button differently, so the helper looks for
        // whichever one this form is drawing.
        let focused = drawn.rows.iter().any(|row| {
            (row.contains("[ Connect ]")
                || row.contains("[ Set up ]")
                || row.contains("[ Remove ]"))
                && row.contains("> ")
        });
        drop(drawn);

        if focused {
            return;
        }

        app.apply(key(KeyCode::Tab));
    }
    panic!("never reached the submit row:\n{}", screen(app).text());
}

/// Moves the form's cursor onto a named field and types into it.
fn fill(app: &mut App, label: &str, value: &str) {
    for _ in 0..16 {
        let drawn = screen(app);
        let focused = drawn
            .rows
            .iter()
            .any(|row| row.contains(label) && row.contains("> "));
        drop(drawn);

        if focused {
            for message in typed(value) {
                app.apply(message);
            }
            return;
        }

        app.apply(key(KeyCode::Tab));
    }
    panic!("never reached the {label} field:\n{}", screen(app).text());
}

/// Empties whatever text field has the cursor.
fn clear_field(app: &mut App) {
    for _ in 0..80 {
        app.apply(key(KeyCode::Backspace));
    }
}

/// Step 1: the form of §5.2, its required fields, and the call it makes.
#[test]
fn add_to_fleet_asks_for_a_name_and_an_account_and_prepares_the_operation() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");

    let text = prose(&mut app);
    assert!(text.contains("Add build-linux to your fleet"), "{text}");
    assert!(
        text.contains("Actions run on studio as ada."),
        "the deployment-host caption is not on the form:\n{text}"
    );
    assert!(text.contains("Name in the fleet"), "{text}");
    assert!(
        text.contains("letters, digits, hyphens"),
        "the name rule is missing:\n{text}"
    );
    // Pre-filled from `suggested_machine`, never from the display name.
    assert!(text.contains("build-linux"), "{text}");
    assert!(text.contains("SSH user"), "{text}");
    assert!(text.contains("(required)"), "{text}");
    assert!(
        text.contains("the account on build-linux"),
        "the account hint is missing:\n{text}"
    );
    // No authentication picker on the face of the form.
    assert!(
        !text.contains("authenticate with"),
        "an identity picker is still drawn:\n{text}"
    );
    assert!(
        text.contains("\u{25b8} Advanced \u{2014} port, SSH key"),
        "the Advanced disclosure is missing:\n{text}"
    );
    assert!(text.contains("[ Connect ]"), "{text}");

    // Submitting with no username refuses, inline, without a call.
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    assert!(
        drained(&mut app).is_empty(),
        "an empty username still reached the runtime"
    );
    assert!(prose(&mut app).contains("An SSH username is required"));

    // With one, `prepare` goes out with the target, the account and no secret.
    fill(&mut app, "SSH user", "deploy");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["target"]["address"], json!("100.64.12.44"));
    assert_eq!(prepare.params["target"]["machine"], json!("build-linux"));
    ouro::fleet::validate_machine(prepare.params["target"]["machine"].as_str().unwrap()).unwrap();
    assert_eq!(prepare.params["ssh_user"], json!("deploy"));
    assert_eq!(prepare.params["port"], json!(22));
    assert!(
        prepare.params.get("secret").is_none(),
        "prepare carried a secret: {}",
        prepare.params
    );
}

/// `a`: *Add a device by address* — the address is typed, and the name is required.
///
/// Finding 2: the manual form had no machine-name field at all, so the worker took the
/// address as the name and refused it. There was no way for that path to succeed.
#[test]
fn a_adds_a_device_by_address_with_the_address_typed_and_the_name_required() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    app.apply(key(KeyCode::Char('a')));

    let text = prose(&mut app);
    assert!(text.contains("Add a device by address"), "{text}");
    assert!(text.contains("Name in the fleet"), "{text}");
    assert!(text.contains("Address"), "{text}");
    assert!(text.contains("SSH user"), "{text}");
    assert!(
        !text.contains("from the list"),
        "a typed address was drawn as read-only:\n{text}"
    );

    // Nothing is pre-filled: there is no device to take a suggestion from.
    assert_eq!(
        app.devices
            .connect
            .as_ref()
            .map(|form| (form.machine.clone(), form.address.clone())),
        Some((String::new(), String::new()))
    );

    // An address and an account, and no name: refused on the name field, with no call.
    fill(&mut app, "Address", "100.83.203.10");
    fill(&mut app, "SSH user", "monocursive");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    assert!(
        drained(&mut app).is_empty(),
        "a nameless manual add reached the runtime"
    );
    assert!(
        prose(&mut app).contains("A name in the fleet is required"),
        "{}",
        prose(&mut app)
    );

    // A name that is not one is refused on the same field rather than sent.
    fill(&mut app, "Name in the fleet", "Not A Machine Name");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));
    assert!(drained(&mut app).is_empty(), "an invalid name was sent");

    fill(&mut app, "Name in the fleet", "");
    clear_field(&mut app);
    for message in typed("raspberrypi") {
        app.apply(message);
    }
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["kind"], json!("add"));
    assert_eq!(prepare.params["target"]["machine"], json!("raspberrypi"));
    assert_eq!(prepare.params["target"]["address"], json!("100.83.203.10"));
    assert_eq!(prepare.params["ssh_user"], json!("monocursive"));
    assert!(prepare.params.get("identity").is_none());
}

/// An operation in flight, from `prepare` to a first snapshot.
fn deploying() -> App {
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    activate(&mut app, "build-linux");
    fill(&mut app, "SSH user", "deploy");
    focus_submit(&mut app);
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
        text.contains("First time connecting to 100.64.12.44"),
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
    assert!(text.contains("Trust and continue"), "{text}");

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
        !text.contains("Trust and continue"),
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
    assert!(text.contains("Password for deploy@100.64.12.44"), "{text}");
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

    // §5.2 step 3: five plain lines, then the digest.
    let text = prose(&mut app);
    assert!(text.contains("Ready to deploy"), "{text}");
    assert!(
        text.contains("Install ouro 0.1.8 (x86_64-unknown-linux-gnu) to bin/ouro"),
        "the install line is missing:\n{text}"
    );
    assert!(
        text.contains("Join the fleet as build-linux."),
        "the join line is missing:\n{text}"
    );
    assert!(
        text.contains("Start at login as a user service"),
        "the startup line is missing:\n{text}"
    );
    assert!(
        text.contains("Update 1 roster (studio)."),
        "the roster line is missing:\n{text}"
    );
    assert!(
        text.contains("broad fleet trust between every member"),
        "the trust sentence is not stated:\n{text}"
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
        !text.contains("a  Deploy \u{2014} applies exactly this plan"),
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
                        { "machine": "build-linux", "step": "install_binary",
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

        // §5.2 step 4: the six-stage strip, with a mark per stage and the current
        // step's detail under it. `inspect` finished, `install` is where it stopped.
        assert!(
            text.contains("\u{2713} Inspect \u{b7} \u{d7} Install"),
            "{state} did not draw the stage strip:\n{text}"
        );
        for stage in ["Join fleet", "Start at login", "Connect", "Ready"] {
            assert!(
                text.contains(&format!("\u{25cb} {stage}")),
                "{state} lost the {stage} stage:\n{text}"
            );
        }
    }

    // A stage the worker is *on* is marked as the current one rather than as done.
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "deploying",
            json!([]),
            json!({
                "steps": [
                    { "machine": "build-linux", "step": "inspect", "outcome": "ok" },
                    { "machine": "build-linux", "step": "install_binary",
                      "outcome": "started", "detail": "downloading ouro 0.1.9" }
                ]
            }),
        ),
    );
    let _polled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        text.contains("\u{2713} Inspect \u{b7} \u{25cf} Install"),
        "the running stage is not marked as the current one:\n{text}"
    );
    assert!(
        text.contains("downloading ouro 0.1.9"),
        "the current step's detail is missing:\n{text}"
    );
}

/// Finishing names the machine and offers Open and Done, and nothing it did not do.
#[test]
fn a_completed_setup_names_the_machine_and_offers_open_and_done() {
    let _mode = normal();
    let mut app = deploying();
    answer(
        &mut app,
        status_tag(),
        snapshot("completed", json!([]), json!({})),
    );

    let text = prose(&mut app);
    assert!(text.contains("build-linux is in your fleet"), "{text}");
    assert!(text.contains("Open"), "{text}");
    assert!(text.contains("b Done"), "{text}");
    // The two follow-ups this view has no action for are gone: a model is configured
    // per machine and a first task is an explicit thing somebody does, and naming them
    // as steps of this screen was naming actions it does not have.
    assert!(!text.contains("Configure model"), "{text}");
    assert!(!text.contains("Run test task"), "{text}");
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

    for (state, word, label, method) in [
        (
            "failed",
            "setup failed",
            "Retry",
            Some("fleet.deployment.resume"),
        ),
        (
            "interrupted",
            "setting up\u{2026}",
            "Continue",
            Some("fleet.deployment.resume"),
        ),
        // The broker's own terminal set is completed and cancelled: a resume of one
        // answers `operation_finished`, so the row offers a new operation instead of a
        // call that would be refused.
        ("cancelled", "not set up", "Add to fleet", None),
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
            row.contains(word),
            "{state} did not read as itself: {row:?}"
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
                assert!(prose(&mut app).contains("SSH user"), "{state}");
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

    let row = device_row(&drawn, "build-linux");
    assert!(row.contains("set up just now"), "{row}");
    assert!(row.contains("Add to fleet"), "{row}");
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

    // The operation is on the row it is about, in that row's own Ouroboros column.
    let drawn = screen(&mut app);
    let row = device_row(&drawn, "build-linux").to_string();
    drop(drawn);
    assert!(row.contains("setting up\u{2026}"), "{row}");
    assert!(row.contains("Continue"), "{row}");

    // Its id and its owner are in that row's details, not in a banner over the list.
    activate_cursor(&mut app, "build-linux");
    let text = prose(&mut app);
    assert!(text.contains("abcdef0123456789"), "{text}");
    assert!(
        text.contains("started by local-owner"),
        "the owner is not named:\n{text}"
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
        assert!(text.contains(expected), "{reason}:\n{text}");
        assert!(
            !text.contains(reason),
            "{reason} was printed as its own code:\n{text}"
        );

        // The row carries no button at all rather than one the gate would refuse.
        let drawn = screen(&mut app);
        let row = device_row(&drawn, "build-linux").to_string();
        drop(drawn);
        assert!(!row.contains("Add to fleet"), "{reason}: {row}");
        assert!(row.contains('\u{2014}'), "{reason}: {row}");

        activate(&mut app, "build-linux");
        assert!(
            drained(&mut app).is_empty(),
            "{reason} still let a deployment start"
        );
    }
}

/// "Set up this Mac" is the first local fleet: no account, no host key, same review.
#[test]
fn setting_up_this_machine_asks_for_no_ssh_and_prepares_a_setup_operation() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "suggested_machine": "studio",
        "os": "macos", "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    let drawn = screen(&mut app);
    assert!(device_row(&drawn, "This Mac").contains("Set up this Mac"));
    drop(drawn);

    activate(&mut app, "This Mac");

    // The form has a machine name and a service choice, and none of the SSH fields.
    let text = prose(&mut app);
    assert!(text.contains("Set up this Mac"), "{text}");
    assert!(text.contains("Name in the fleet"), "{text}");
    assert!(text.contains("start at login"), "{text}");
    assert!(
        text.contains("this view reconnects by itself"),
        "the restart sentence is missing from the setup form:\n{text}"
    );
    assert!(
        !text.contains("SSH user"),
        "the local setup asked for an SSH account:\n{text}"
    );
    assert!(
        text.contains("without SSH to itself"),
        "the screen does not say why there is no account:\n{text}"
    );

    // And the required-username refusal does not fire on a form with no username.
    focus_submit(&mut app);
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

/// A first local setup restarts the runtime this client is attached to (finding 4).
///
/// The worker is detached, so the deployment does not stop when the runtime does — but
/// this client's connection does. Three things must be true across that gap, and none of
/// them were: the view must not draw the snapshot it had as though it were current, it
/// must not spin on a runtime that is gone, and when the client reconnects it must reload
/// *this* operation by its id and carry on from whatever the broker says.
///
/// The gap is driven the way the transport drives it: the in-flight read fails with
/// `ConnectionClosed`, which is what the socket closing produces, and the return is the
/// `Msg::Reconnected` the real reconnect hook sends after a fresh handshake
/// (`src/ui/mod.rs`'s `StreamHook::after_reconnect`).
#[test]
fn the_hosting_runtimes_restart_is_drawn_as_a_reconnect_and_reloads_by_operation_id() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "suggested_machine": "studio",
        "os": "macos", "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);
    activate(&mut app, "This Mac");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    answer(
        &mut app,
        call_for(&calls, "fleet.deployment.prepare").tag.clone(),
        json!({ "operation_id": "abcdef0123456789" }),
    );

    // The runtime restarts itself as part of the plan, and says so while it still can.
    answer(
        &mut app,
        status_tag(),
        snapshot(
            "restarting_host",
            json!([]),
            json!({ "kind": "setup",
                    "steps": [{ "machine": "studio", "step": "create", "outcome": "ok" }] }),
        ),
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

    // What is on the screen is what is true: the runtime is away, and this is waiting.
    let text = prose(&mut app);
    assert!(
        text.contains("Ouroboros is restarting\u{2026} reconnecting"),
        "the gap is not drawn:\n{text}"
    );
    assert!(
        text.contains("abcdef0123456789"),
        "the operation id was dropped across the gap:\n{text}"
    );
    // Never the last snapshot redrawn as though it were current.
    assert!(
        !text.contains("restarting this runtime"),
        "the stale snapshot is still drawn as the live state:\n{text}"
    );
    assert!(
        !text.contains("create"),
        "the stale steps are still drawn as the live ones:\n{text}"
    );
    assert!(
        ouro::ui::app::devices_hint_line(&app).contains("waiting for the runtime to come back"),
        "{}",
        ouro::ui::app::devices_hint_line(&app)
    );

    // And it does not spin: the failed read backs off by the snapshot cadence rather
    // than issuing a call on every tick at a runtime that is not there.
    for _ in 0..3 {
        app.apply(Msg::Tick);
    }
    assert!(
        drained(&mut app).is_empty(),
        "the view kept calling a runtime that is gone"
    );

    // The client reconnects. The operation is reloaded by its own id, and nothing else
    // about it is assumed: `fleet.deployment.status` is a read.
    app.apply(Msg::Reconnected(Box::new(full_hello())));
    let calls = drained(&mut app);
    let status = call_for(&calls, "fleet.deployment.status");
    assert_eq!(status.params, json!({ "operation_id": "abcdef0123456789" }));
    assert!(
        !calls
            .iter()
            .any(|call| call.method == "fleet.deployment.prepare"),
        "the reconnect started a second operation: {:?}",
        calls.iter().map(|call| &call.method).collect::<Vec<_>>()
    );

    // Until it answers, the screen still says what it is doing rather than pretending.
    let text = prose(&mut app);
    assert!(
        text.contains("Ouroboros is back\u{2026} reading this setup again"),
        "{text}"
    );

    // The worker carried on across the restart and is asking the next question. The view
    // picks the flow up there.
    answer(
        &mut app,
        status_tag(),
        json!({
            "operation": "abcdef0123456789", "source": "worker", "attached": true,
            "kind": "setup", "state": "checking_readiness", "owner": "local-owner",
            "steps": [
                { "machine": "studio", "step": "create", "outcome": "ok" },
                { "machine": "studio", "step": "connect", "outcome": "started" }
            ],
            "log": [], "challenges": []
        }),
    );

    let text = prose(&mut app);
    assert!(!text.contains("reconnecting"), "{text}");
    assert!(text.contains("checking readiness"), "{text}");
    assert!(
        text.contains("create"),
        "the steps that did run are gone:\n{text}"
    );
}

/// An interrupted operation still reads as one, from the journal, by the same id.
#[test]
fn an_interruption_is_reported_from_the_journal_with_the_steps_that_ran() {
    let _mode = normal();
    let mut app = deploying();

    app.apply(Msg::Answer {
        tag: status_tag(),
        result: Err(ClientError::ConnectionClosed),
    });
    app.apply(Msg::Reconnected(Box::new(full_hello())));
    let _reloaded = drained(&mut app);

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
        text.contains("create"),
        "the steps that did run are gone:\n{text}"
    );
    assert!(
        text.contains("R Retry"),
        "an interruption is not offered a retry:\n{text}"
    );
}

/// A worker that is gone with an unfinished journal says so, in its own last words.
///
/// The live failure: a worker died before attaching, the broker logged
/// `lost its worker: :normal`, and the page said nothing at all while the operation sat
/// reading "inspecting". The reason — a Unix socket path over 104 bytes — was in the
/// worker's private log, which §5.5 now hands to the surface as `worker_exit`.
#[test]
fn a_worker_that_stopped_says_so_in_its_own_words_and_offers_a_retry() {
    let _mode = normal();
    let mut app = deploying();

    answer(
        &mut app,
        status_tag(),
        json!({
            "operation": "abcdef0123456789", "source": "journal", "attached": false,
            "state": "inspecting", "owner": "local-owner",
            "steps": [], "log": [], "challenges": [],
            "worker_exit": {
                "code": 1,
                "last_lines": [
                    "bind: the socket path is 118 bytes and the limit is 104",
                    "the worker exited before it attached"
                ]
            }
        }),
    );

    let text = prose(&mut app);
    assert!(
        text.contains("The setup worker stopped:"),
        "the worker's exit is not reported:\n{text}"
    );
    assert!(
        text.contains("the socket path is 118 bytes and the limit is 104"),
        "the worker's own words were dropped:\n{text}"
    );
    // A worker that is gone is a finished operation, whatever the state field says.
    assert!(
        text.contains("R Retry"),
        "no retry was offered for a stopped worker:\n{text}"
    );
    assert!(
        !text.contains("inspecting the target"),
        "a dead worker still read as working:\n{text}"
    );

    // `R` resumes by id: a fresh inspection and a fresh review, never a second start.
    app.apply(key(KeyCode::Char('R')));
    let calls = drained(&mut app);
    assert_eq!(
        call_for(&calls, "fleet.deployment.resume").params,
        json!({ "operation_id": "abcdef0123456789" })
    );
}

/// A dev runtime can add a machine and cannot set this one up, and says which.
#[test]
fn a_development_runtime_is_blocked_from_setting_this_machine_up_only() {
    let _mode = normal();

    let mut reply = populated();
    reply["host"] = host(true, &["dev_runtime"]);
    reply["devices"] = json!([
        {
            "name": "studio", "machine": Value::Null, "suggested_machine": "studio",
            "os": "macos", "address": "100.64.12.21", "online": true,
            "state": "this_device_without_profile",
            "name_conflicts_with_roster": Value::Null
        },
        {
            "name": "build-linux", "machine": Value::Null,
            "suggested_machine": "build-linux", "os": "linux",
            "address": "100.64.12.44", "online": true,
            "state": "discovered_installation_unknown",
            "name_conflicts_with_roster": Value::Null
        }
    ]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        text.contains(
            "This is a development runtime; the packaged ouro is what sets a machine up."
        ),
        "the dev-runtime blocker is not in words:\n{text}"
    );
    assert!(
        !text.contains("dev_runtime"),
        "the code was printed as itself:\n{text}"
    );

    // Setting this machine up is refused; adding another one is not.
    let drawn = screen(&mut app);
    assert!(
        !device_row(&drawn, "This Mac").contains("Set up this Mac"),
        "{:?}",
        device_row(&drawn, "This Mac")
    );
    assert!(
        device_row(&drawn, "build-linux").contains("Add to fleet"),
        "{:?}",
        device_row(&drawn, "build-linux")
    );
    drop(drawn);

    activate(&mut app, "This Mac");
    assert!(drained(&mut app).is_empty(), "a dev runtime set itself up");
    assert!(app.devices.connect.is_none());

    activate(&mut app, "build-linux");
    assert!(
        app.devices.connect.is_some(),
        "a dev runtime was stopped from adding another machine:\n{}",
        prose(&mut app)
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
    assert_eq!(secret_chars(&app), 0, "Esc left the secret in the buffer");
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
    assert_eq!(secret_chars(&app), 0);

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
        drawn.rows.iter().any(|row| row.contains("1. This Mac")),
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
    assert!(text.contains("1. t Trust and continue"), "{text}");
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
    assert_eq!(secret_chars(&app), 0);

    // Closing the view on an open password question — through the Cancel chord, not
    // `close_devices()` directly. Ctrl+C used to drop the overlay without clearing the
    // buffer, so a half-typed password survived until the next open.
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
    assert_eq!(secret_chars(&app), SECRET.chars().count());

    app.apply(chord(KeyCode::Char('c')));
    assert!(app.overlay.is_none());
    assert_eq!(
        secret_chars(&app),
        0,
        "Ctrl+C left the typed secret in the buffer"
    );

    // Reopening draws an empty field rather than the one that was typed into.
    app.open_devices();
    let _polled = drained(&mut app);
    assert_eq!(
        bullets(&mut app),
        0,
        "the field came back with what was typed into it before"
    );
    assert_eq!(secret_chars(&app), 0);
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
        !text.contains("SSH user"),
        "a form opened on a runtime that cannot deploy:\n{text}"
    );
    assert!(
        text.contains("Fleet of studio"),
        "the list was left:\n{text}"
    );
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
        !text.contains("SSH user"),
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
    fill(&mut app, "SSH user", "deploy");

    // Enter from every row but the button moves on and sends nothing — including the
    // Advanced disclosure, where it opens the fields rather than reaching a machine.
    let rows = app
        .devices
        .connect
        .as_ref()
        .map(|form| form.rows().len())
        .expect("a form");

    for _ in 0..(rows * 2) {
        let on_button = app
            .devices
            .connect
            .as_ref()
            .is_some_and(|form| form.field == ouro::ui::app::ConnectField::Submit);

        if on_button {
            break;
        }

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
        !text.contains("SSH user"),
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
        "name": "studio", "machine": Value::Null, "suggested_machine": "studio",
        "os": "macos", "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    // The page says what is true of *this* machine, not "go and open Devices somewhere
    // else": there is nowhere else, and the thing to do is on this screen.
    let text = prose(&mut app);
    assert!(
        text.contains("This Mac is not in a fleet yet"),
        "the standalone case still reads as a CA-key misconfiguration:\n{text}"
    );
    assert!(
        !text.contains("Open Devices on the machine that does"),
        "the page sent the operator to a machine that does not exist:\n{text}"
    );

    let drawn = screen(&mut app);
    assert!(device_row(&drawn, "This Mac").contains("Set up this Mac"));
    drop(drawn);

    // Enter opens the setup form rather than refusing.
    activate(&mut app, "This Mac");

    let text = prose(&mut app);
    assert!(
        text.contains("Name in the fleet"),
        "Enter on Set up this device did nothing:\n{text}"
    );
    assert!(!text.contains("SSH user"), "{text}");

    // And it submits `kind: "setup"`.
    focus_submit(&mut app);
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

        activate(&mut app, "This Mac");

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

    // A row with no button is not a refusal: Enter does nothing, and the reason it has
    // nothing to do is already under the list, where somebody looking at the row is.
    let before = ouro::ui::app::devices_hint_line(&app);
    activate(&mut app, "pocket-phone");
    let after = ouro::ui::app::devices_hint_line(&app);

    assert_eq!(before, after, "an inert row wrote to the hint line");
    assert!(
        prose(&mut app).contains("No Ouroboros release targets this platform"),
        "the row with no action does not say why:\n{}",
        prose(&mut app)
    );

    // And a blocked add says its blocker there. `a` is the key that is always an
    // attempt to act, whatever the row under the cursor is, so it is the one that has
    // to answer rather than doing nothing visible.
    let mut reply = populated();
    reply["host"] = host(false, &["cleartext_web_bind"]);
    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    app.apply(key(KeyCode::Char('a')));
    let hint = ouro::ui::app::devices_hint_line(&app);

    assert!(
        hint.contains("credential entry is refused"),
        "the blocker is not on the hint line: {hint:?}"
    );

    // `r` puts the keys back.
    app.apply(key(KeyCode::Char('r')));
    assert!(ouro::ui::app::devices_hint_line(&app).contains("r refresh"));
}

/// A member this runtime is connected to says so, in its own state and its own line.
///
/// `ouro fleet devices` merges the roster with what the *network client* can see, which
/// is not the runtime's answer to "is that machine here, now" — so a member whose runtime
/// this one is connected to still read "in the fleet, not visible on this network"
/// whenever the client could not see it. The broker merges the cluster's facts onto
/// member rows and promotes the state; this is the row that draws it.
#[test]
fn a_connected_member_reads_as_connected_and_keeps_the_network_facts_separate() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([
        {
            "name": "build-linux", "machine": "build-linux", "os": "linux",
            "address": "100.64.12.44",
            // The network client cannot see it...
            "online": false, "last_seen": "2026-09-17T07:50:00.1Z",
            // ...and this runtime is talking to it.
            "state": "fleet_member_connected",
            "connected": true, "compatible": true, "runtime_running": true,
            "last_probe": "2026-09-17T08:10:00Z",
            "name_conflicts_with_roster": Value::Null
        },
        {
            "name": "old-pi", "machine": "old-pi", "os": "linux",
            "address": "100.64.12.10", "online": true, "last_seen": Value::Null,
            "state": "fleet_member",
            "connected": false, "compatible": Value::Null,
            "runtime_running": Value::Null, "last_probe": Value::Null,
            "name_conflicts_with_roster": Value::Null
        },
        {
            // A peer that has never been in a fleet: this runtime knows nothing about it,
            // and says nothing rather than reporting it as disconnected.
            "name": "vps", "machine": Value::Null, "os": "linux",
            "address": "100.64.12.99", "online": true, "last_seen": Value::Null,
            "state": "discovered_installation_unknown",
            "connected": Value::Null, "compatible": Value::Null,
            "runtime_running": Value::Null, "last_probe": Value::Null,
            "name_conflicts_with_roster": Value::Null
        }
    ]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    let drawn = screen(&mut app);
    let text = flowed(&drawn);

    // The state, in words, and the action a member gets.
    assert!(
        device_row(&drawn, "build-linux").contains("Open"),
        "{:?}",
        device_row(&drawn, "build-linux")
    );
    assert!(
        device_row(&drawn, "build-linux").contains("in the fleet"),
        "{:?}",
        device_row(&drawn, "build-linux")
    );
    drop(drawn);
    assert!(
        !text.contains("not visible on this network"),
        "a connected member still read as invisible:\n{text}"
    );

    // The runtime's facts, in that row's details, kept apart from the network's.
    activate_cursor(&mut app, "build-linux");
    let text = prose(&mut app);
    assert!(
        text.contains("runtime connected \u{b7} compatible build \u{b7} runtime running \u{b7} probed 2026-09-17T08:10:00Z"),
        "the live facts are not drawn:\n{text}"
    );

    // And the network's facts are still the network's: `online: false` is not overwritten
    // by the runtime being connected, because those are two different questions.
    assert!(
        text.contains("offline, last seen 2026-09-17T07:50:00.1Z"),
        "the network fact was replaced by the cluster's:\n{text}"
    );

    // A member this runtime is not connected to says that much and no more.
    activate_cursor(&mut app, "old-pi");
    let text = prose(&mut app);
    assert!(text.contains("runtime not connected"), "{text}");
    assert!(
        device_row(&screen(&mut app), "old-pi").contains("in the fleet \u{b7} not connected"),
        "{text}"
    );

    // A non-member carries no runtime line at all — null is "not known", not "absent".
    activate_cursor(&mut app, "vps");
    let text = prose(&mut app);
    assert!(
        !text.contains("runtime runtime") && !text.contains("runtime not connected"),
        "a device that has never been in a fleet was given cluster facts:\n{text}"
    );
}

/// A state string this build has never seen is a sentence, never a blank column.
#[test]
fn an_unreadable_state_is_named_rather_than_left_blank() {
    let _mode = normal();

    for (state, expected) in [
        ("quantum_entangled", "quantum_entangled"),
        ("", "reported no state"),
    ] {
        let mut reply = populated();
        reply["devices"] = json!([{
            "name": "mystery", "machine": Value::Null, "os": "linux",
            "address": "100.64.12.50", "online": true, "last_seen": Value::Null,
            "state": state, "name_conflicts_with_roster": Value::Null
        }]);

        let mut app = with_inventory(reply);
        let _settled = drained(&mut app);
        let text = prose(&mut app);

        assert!(text.contains(expected), "{state:?}:\n{text}");

        // The row is still a row, with its own fields drawn and no button invented.
        let drawn = screen(&mut app);
        assert!(device_row(&drawn, "mystery").contains('\u{2014}'));
        drop(drawn);
        assert!(text.contains("100.64.12.50"), "{state:?}:\n{text}");
        assert!(
            text.contains("which this client has no action for"),
            "{state:?} left the reason unsaid:\n{text}"
        );
    }
}

/// The server's own refusal speaks the same words the capability list does.
///
/// `deploy_blocked` carries `data.blockers` in exactly `capabilities.reasons`'
/// vocabulary, and it is the authority: a blocker can appear between the inventory being
/// read and the action being pressed, so the client-side gate passing means nothing by
/// the time the call lands. It goes to the hint line like every other refusal.
#[test]
fn a_server_side_deploy_blocked_reads_as_the_same_blocker_the_list_would_name() {
    let _mode = normal();

    for (code, expected) in [
        ("cleartext_web_bind", "credential entry is refused"),
        (
            "no_ca_key",
            "does not hold the fleet's certificate authority key",
        ),
        ("no_data_dir", "serves no durable data directory"),
    ] {
        // The inventory says this host *can* deploy, so the client-side gate lets the
        // call through and only the server refuses it.
        let mut app = with_inventory(populated());
        let _settled = drained(&mut app);

        activate(&mut app, "build-linux");
        fill(&mut app, "SSH user", "deploy");
        focus_submit(&mut app);
        app.apply(key(KeyCode::Enter));

        let calls = drained(&mut app);
        refuse(
            &mut app,
            call_for(&calls, "fleet.deployment.prepare").tag.clone(),
            ErrorCode::ScopeDenied,
            Some(json!({ "reason": "deploy_blocked", "blockers": [code] })),
        );

        let hint = ouro::ui::app::devices_hint_line(&app);
        assert!(hint.contains(expected), "{code}: {hint:?}");

        // The form is gone: this is not a field to correct, it is the host saying no.
        let text = prose(&mut app);
        assert!(!text.contains("SSH user"), "{code}:\n{text}");
        assert!(text.contains(expected), "{code}:\n{text}");
    }

    // A refusal naming a code this build predates is still a sentence, not an identifier.
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);
    activate(&mut app, "build-linux");
    fill(&mut app, "SSH user", "deploy");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    refuse(
        &mut app,
        call_for(&calls, "fleet.deployment.prepare").tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({ "reason": "deploy_blocked", "blockers": ["a_reason_from_the_future"] })),
    );

    let hint = ouro::ui::app::devices_hint_line(&app);
    assert!(hint.contains("a reason from the future"), "{hint:?}");
    assert!(!hint.contains("a_reason_from_the_future"), "{hint:?}");
}

#[test]
fn local_setup_can_resume_and_retry_without_a_ca() {
    let _mode = normal();
    let operation = "abcdef0123456789";
    let mut reply = populated();
    reply["host"] = host(false, &["no_ca_key"]);
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "os": "macos",
        "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile", "action": "set up this device"
    }]);
    reply["operations"] = json!([{
        "operation": operation, "state": "failed", "kind": "setup",
        "owner": "local-owner", "attached": false, "readable": true,
        "target": { "machine": "studio", "address": "100.64.12.21" }
    }]);
    let mut app = with_inventory(reply);
    drained(&mut app);
    activate(&mut app, "This Mac");
    let calls = drained(&mut app);
    let resume = call_for(&calls, "fleet.deployment.resume");
    assert_eq!(resume.params["operation_id"], operation);
    refuse(
        &mut app,
        resume.tag.clone(),
        ErrorCode::ScopeDenied,
        Some(json!({"reason":"operation_not_yours"})),
    );
    app.apply(key(KeyCode::Char('t')));
    let calls = drained(&mut app);
    let takeover = call_for(&calls, "fleet.deployment.resume");
    assert_eq!(takeover.params["takeover"], true);
    answer(
        &mut app,
        takeover.tag.clone(),
        json!({"operation_id":operation}),
    );
    answer(
        &mut app,
        Tag::Devices(DevicesTag::Status {
            operation: operation.into(),
        }),
        json!({"source":"journal", "kind":"setup", "state":"failed", "attached":false}),
    );
    drained(&mut app);
    app.apply(key(KeyCode::Char('R')));
    let calls = drained(&mut app);
    assert_eq!(
        call_for(&calls, "fleet.deployment.resume").params["operation_id"],
        operation
    );
}

/// The name field is seeded from `suggested_machine` and never from the display name.
///
/// Finding 3: both surfaces pre-filled it with a display name ("Monocursive\u{2019}s MacBook
/// Pro", or the `this device` a failed discovery invented), which is not a valid machine
/// name; the web submitted it. The runtime now answers with a name it folded itself, or
/// with `null`, and `null` leaves the field empty for somebody to fill in.
#[test]
fn the_name_field_comes_from_the_runtimes_suggestion_and_never_from_the_display_name() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([
        {
            "name": "Build Linux", "machine": Value::Null,
            "suggested_machine": "build-linux", "os": "linux",
            "address": "100.64.12.44", "online": true,
            "state": "discovered_installation_unknown", "action": "deploy Ouroboros",
            "name_conflicts_with_roster": Value::Null
        },
        {
            // The runtime could fold nothing valid out of this one.
            "name": "\u{2026}\u{2026}\u{2026}", "machine": Value::Null,
            "suggested_machine": Value::Null, "os": "linux",
            "address": "100.64.12.88", "online": true,
            "state": "discovered_installation_unknown", "action": "deploy Ouroboros",
            "name_conflicts_with_roster": "studio"
        }
    ]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    activate(&mut app, "Build Linux");
    assert_eq!(
        app.devices
            .connect
            .as_ref()
            .map(|form| form.machine.as_str()),
        Some("build-linux"),
        "the field was not seeded from suggested_machine"
    );
    let text = prose(&mut app);
    assert!(
        !text.contains("Name in the fleet Build Linux"),
        "the display name reached the name field:\n{text}"
    );
    app.apply(key(KeyCode::Esc));

    // `null` is an empty field, and submitting it is refused on that field.
    activate_cursor(&mut app, "100.64.12.88");
    app.apply(key(KeyCode::Enter));
    assert_eq!(
        app.devices
            .connect
            .as_ref()
            .map(|form| form.machine.as_str()),
        Some(""),
        "a name the runtime could not fold was invented here instead"
    );

    fill(&mut app, "SSH user", "deploy");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    assert!(
        drained(&mut app).is_empty(),
        "a nameless add reached the runtime"
    );
    assert!(
        prose(&mut app).contains("A name in the fleet is required"),
        "{}",
        prose(&mut app)
    );
}

/// Spaces in a pasted password survive; flattening used to trim them through a
/// non-zeroized String before the masked field saw them.
#[test]
fn a_pasted_password_keeps_its_leading_and_trailing_spaces() {
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

    const PADDED: &str = "  zx9Qv-padded-secret  ";
    app.apply(Msg::Paste(PADDED.into()));

    assert_eq!(secret_chars(&app), PADDED.chars().count());
    assert_eq!(bullets(&mut app), PADDED.chars().count());
    assert!(
        !prose(&mut app).contains(PADDED),
        "the pasted secret was drawn in the clear"
    );

    app.apply(key(KeyCode::Enter));
    let calls = drained(&mut app);
    let authenticate = call_for(&calls, "fleet.deployment.authenticate");
    assert_eq!(authenticate.params["secret"], json!(PADDED));
}

/// A member's facts are under the list, and Enter goes to where its sessions are.
#[test]
fn a_member_carries_its_facts_in_the_details_panel_and_opens_the_machines_panel() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "studio", "machine": "studio", "suggested_machine": "studio",
        "os": "macos", "address": "100.64.12.21", "online": true, "path": "direct",
        "state": "this_device", "action": "view device",
        "connected": true, "compatible": true, "runtime_running": true,
        "last_probe": "2026-09-17T08:10:00Z",
        "name_conflicts_with_roster": Value::Null
    }]);
    reply["operations"] = json!([{
        "operation": "op-old", "state": "completed", "kind": "setup",
        "owner": "ada", "attached": false, "readable": true,
        "created_at": "2026-09-16T08:00:00Z",
        "updated_at": "2026-09-16T09:00:00Z",
        "target": { "machine": "studio", "address": "100.64.12.21" }
    }]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    // No second screen to open: the facts are already under the row.
    let text = prose(&mut app);
    assert!(text.contains("in the roster as studio"), "{text}");
    assert!(text.contains("direct"), "{text}");
    assert!(text.contains("100.64.12.21"), "{text}");
    assert!(text.contains("runtime connected"), "{text}");
    assert!(text.contains("probed 2026-09-17T08:10:00Z"), "{text}");
    assert!(text.contains("op-old"), "{text}");
    assert!(text.contains("started by ada"), "{text}");
    assert!(!text.contains("SSH user"), "the list drew a form:\n{text}");

    // `r` still asks the runtime again.
    app.apply(key(KeyCode::Char('r')));
    let calls = drained(&mut app);
    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));

    // Enter on a member is **Open**: its sessions are the Dashboard's machines panel,
    // which is a place this view does not contain.
    activate(&mut app, "This Mac");
    assert!(app.overlay.is_none(), "Open left the view over the screen");
    assert!(
        prose(&mut app).contains("its machines and sessions are on this panel"),
        "{}",
        prose(&mut app)
    );
}

/// `x` on a member is `kind: "leave"`, by roster name, with its own account question.
#[test]
fn x_on_a_member_prepares_a_leave_for_its_roster_name() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([
        {
            "name": "studio", "machine": "studio", "suggested_machine": "studio",
            "os": "macos", "address": "100.64.12.21", "online": true,
            "state": "this_device", "connected": true,
            "name_conflicts_with_roster": Value::Null
        },
        {
            "name": "attic", "machine": "attic", "suggested_machine": "attic",
            "os": "linux", "address": "100.64.12.77", "online": false,
            "last_seen": "2026-09-17T07:50:00Z",
            "state": "fleet_member_not_visible", "action": "diagnose",
            "connected": false, "compatible": true, "runtime_running": false,
            "last_probe": Value::Null,
            "name_conflicts_with_roster": Value::Null
        }
    ]);

    let mut app = with_inventory(reply);
    let _settled = drained(&mut app);

    // The offer is in the member's own details, not on its row.
    activate_cursor(&mut app, "attic");
    let text = prose(&mut app);
    assert!(text.contains("x Remove attic from the fleet"), "{text}");
    assert!(text.contains("runtime not connected"), "{text}");

    app.apply(key(KeyCode::Char('x')));
    let text = prose(&mut app);
    assert!(text.contains("Remove attic from the fleet"), "{text}");
    assert!(
        text.contains("Its sessions and data stay on that machine"),
        "the departure does not say what it leaves behind:\n{text}"
    );
    assert!(text.contains("SSH user"), "{text}");
    assert!(text.contains("[ Remove ]"), "{text}");

    // The account is required, exactly as it is for an admission.
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));
    assert!(drained(&mut app).is_empty(), "a nameless leave was sent");
    assert!(prose(&mut app).contains("An SSH username is required"));

    fill(&mut app, "SSH user", "pi");
    focus_submit(&mut app);
    app.apply(key(KeyCode::Enter));

    let calls = drained(&mut app);
    let prepare = call_for(&calls, "fleet.deployment.prepare");

    assert_eq!(prepare.params["kind"], json!("leave"));
    assert_eq!(prepare.params["target"]["machine"], json!("attic"));
    assert_eq!(prepare.params["ssh_user"], json!("pi"));
    assert_eq!(prepare.params["port"], json!(22));
    assert!(
        prepare.params["target"]["address"].is_null(),
        "a leave named an address rather than a roster member: {}",
        prepare.params
    );
}

/// This machine does not leave its own fleet from here, and a device that is not a
/// member has nothing to leave.
#[test]
fn x_on_a_row_that_is_not_a_member_says_so_rather_than_opening_a_form() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    for (row, expected) in [
        ("This Mac", "nothing to remove it from"),
        ("build-linux", "nothing to remove it from"),
    ] {
        remove(&mut app, row);

        assert!(
            app.devices.connect.is_none(),
            "{row} opened a departure form"
        );
        assert!(drained(&mut app).is_empty(), "{row} sent a call");
        assert!(
            ouro::ui::app::devices_hint_line(&app).contains(expected),
            "{row}: {}",
            ouro::ui::app::devices_hint_line(&app)
        );
    }
}

/// Every reason, blocker and operation-state code the fixtures in this file put on the
/// wire has a sentence in the TUI catalogue.
#[test]
fn every_code_the_fixtures_emit_has_a_sentence() {
    use ouro::ui::app::devices::{
        blocker_known, blocker_sentence, operation_state, operation_state_known, reason_sentence,
    };

    // Refusal / blocker codes this file actually sends.
    for code in [
        "operation_not_yours",
        "host_key_changed",
        "plan_changed",
        "challenge_consumed",
        "challenge_expired",
        "challenge_not_bound",
        "deploy_blocked",
        "no_ca_key",
        "ouro_path_unknown",
        "no_data_dir",
        "cleartext_web_bind",
        "worker_refused",
        "a_reason_from_the_future",
    ] {
        let sentence = if blocker_known(code) {
            blocker_sentence(code)
        } else {
            reason_sentence(code)
        };
        assert!(!sentence.is_empty(), "{code} has no sentence");
        assert!(
            !sentence.contains(code),
            "{code} reached the screen as an identifier: {sentence}"
        );
    }

    for code in [
        "attaching",
        "inspecting",
        "awaiting_host_trust",
        "awaiting_auth",
        "awaiting_review",
        "deploying",
        "restarting_host",
        "checking_readiness",
        "completed",
        "interrupted",
        "failed",
        "cancelled",
    ] {
        assert!(operation_state_known(code), "{code} is not catalogued");
        let sentence = operation_state(code);
        assert!(
            !sentence.contains("does not know"),
            "{code} fell through: {sentence}"
        );
    }
}
