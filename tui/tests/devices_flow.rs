//! Slice K5, the terminal half: the Devices view as an inventory that runs no operation.
//!
//! A scripted gateway, in the shape `tui/tests/fleet_triage.rs` established: messages go
//! in, the outbound queue and the drawn frame come out, and the Elixir side is stood in
//! for by answers shaped like the ones the `fleet.devices` contract documents. What is
//! *not* stood in for is the device data — the rows below are built from the sanitized
//! `tailscale status --json` captures under `tests/fixtures/tailscale/`, so the names,
//! addresses, platforms and last-seen times this view renders are the ones a real client
//! reported, including the capture whose hostnames are hostile on purpose.
//!
//! ## The claim each group of tests makes
//!
//!   * **The list** — one row per device, §5.1's columns and words, the status line, the
//!     deploying-from line, a distinct empty state for each way discovery can fail, and
//!     the search and filter that appear only past eight rows.
//!   * **The command** — the one thing to do about each row, printed as the command that
//!     does it, filled from the runtime's own suggestion and never from a display name.
//!   * **The pane** — what Enter opens: the command in full, whose shell it belongs in,
//!     the exact times, and any operation the runtime is already running, read-only.
//!   * **Authority** — a read-scope listener, a non-administrator, an absent capability.
//!   * **Nothing is sent** — the two reads are the only calls this view can make.

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

/// The frame, drawn wide.
///
/// Two hundred columns rather than the eighty a person has, because the row budget is
/// 140 and a narrower pane folds every device onto two lines on purpose — which is its
/// own test, below. A wide frame is also what shows a whole command in the action
/// column, so an assertion about the command is about the command rather than about
/// where this build happened to cut it.
fn screen(app: &mut App) -> Screen {
    app.terminal_width = 200;
    render(app, 200, 60)
}

/// Every request this client has queued since the last drain.
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

/// The *inventory line* for a device: the one carrying both its name and the action
/// column, which is either a command or the dash a row with nothing to do carries.
///
/// Not `Screen::row`, which finds the first line containing the needle — and the first
/// line containing "studio" is the deploying-from line naming the host.
fn device_row<'a>(drawn: &'a Screen, name: &str) -> &'a str {
    drawn
        .rows
        .iter()
        .find(|row| row.contains(name) && (row.contains("ouro fleet") || row.contains('\u{2014}')))
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
                // The runtime folds the display name into a machine name, or answers
                // `null`. It is the only thing a printed `--machine` is ever filled from,
                // so the fixtures carry it exactly as the contract describes it.
                "suggested_machine": suggested(peer.get("HostName").and_then(Value::as_str)),
                "os": os,
                "address": address,
                "online": online,
                "last_seen": last_seen,
                "state": state,
                "name_conflicts_with_roster": Value::Null,
            })
        })
        .collect();

    rows.sort_by_key(|row| row["name"].as_str().unwrap_or("").to_string());
    rows
}

/// A display name folded to a machine name, as the contract specifies the runtime does
/// it: lowercased, every run of non-alphanumerics to one hyphen, trimmed, 40 characters,
/// `null` when nothing valid remains.
///
/// Reproduced here rather than imported because the folding runs on the deployment host;
/// what this file tests is that the command is filled from the answer and never from
/// `name`.
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

/// This machine's own row, in the fleet.
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
        "name_conflicts_with_roster": Value::Null,
    })
}

/// A host block with the capabilities a test wants.
///
/// No `issuer`: §1 withdrew the per-member PKI, so "which machine may admit" is not a
/// fact any document reports any more.
fn host(deploy: bool, reasons: &[&str]) -> Value {
    json!({
        "hostname": "studio",
        "user": "ada",
        "os": "darwin",
        "arch": "aarch64-apple-darwin",
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

/// Moves the cursor onto a named row, without pressing anything.
fn select(app: &mut App, name: &str) {
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

/// Moves the cursor onto a named row and opens its details pane.
fn open_details(app: &mut App, name: &str) {
    select(app, name);
    if !app.devices.details {
        app.apply(key(KeyCode::Enter));
    }
    assert!(app.devices.details, "Enter did not open the pane");
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

    // The keymap: the leader, then the bound verb. `ctrl+x D` stays (§10). Read through
    // the map rather than hardcoded, so a rebound key fails this loudly.
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
    // The page no longer deploys anything, and the Dashboard no longer says it does.
    assert!(
        !hint.contains("deploy"),
        "the hint still advertises a deployment: {hint}"
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

/// Opening reads the inventory; opening again closes, and nothing is sent either way.
#[test]
fn opening_reads_the_inventory_and_closing_sends_nothing() {
    let _mode = normal();
    let mut app = opened(full_hello());
    let calls = drained(&mut app);

    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.method.starts_with("fleet."))
            .count(),
        1,
        "opening the view issued more than the one read"
    );

    answer(&mut app, Tag::Devices(DevicesTag::Inventory), populated());
    app.apply(key(KeyCode::Esc));

    assert!(app.overlay.is_none());
    assert!(
        drained(&mut app).is_empty(),
        "closing the view sent something"
    );
}

// ---------------------------------------------------------------------------------------
// the list
// ---------------------------------------------------------------------------------------

/// On a narrow terminal each device folds onto two deliberate lines — name, address and
/// presence, then the Ouroboros word and the command under the name — rather than one
/// long line the pane wraps mid-word, and the hint says the same keys in fewer words.
#[test]
fn a_narrow_terminal_folds_each_device_onto_two_lines() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    // The real frame loop records the width before every draw; the harness does not.
    app.terminal_width = 80;
    let screen = render(&mut app, 80, 40);
    let text = flowed(&screen);

    let name_row = screen
        .rows
        .iter()
        .position(|row| row.contains("build-linux"))
        .expect("a row for build-linux");
    let first = &screen.rows[name_row];
    let second = &screen.rows[name_row + 1];
    assert!(
        first.contains("100.64.12.44"),
        "the address stays on the name line: {first}"
    );
    assert!(
        first.contains("\u{25cf} online"),
        "the presence stays on the name line: {first}"
    );
    assert!(
        !first.contains("ouro fleet") && !first.contains("not set up"),
        "the state and the command fold onto the second line: {first}"
    );
    assert!(
        second.contains("not set up") && second.contains("ouro fleet add"),
        "the second line carries the Ouroboros word and the command: {second}"
    );
    // A fold is not a wrap: "seen 3 days" and "ago" stay together.
    assert!(!text.contains("seen 3 days\nago"), "{text}");
    // The footer draws the hint's separators as commas.
    assert!(
        text.contains("Enter details, r refresh"),
        "the short hint: {text}"
    );
}

/// One list, one line per device, the status line above it and the quiet line under it.
#[test]
fn the_inventory_draws_one_line_per_device_under_a_status_line() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);
    let text = flowed(&screen);

    // The fleet, and how much of it is here.
    assert!(
        text.contains("studio \u{b7} 1 of 1 machine connected"),
        "the status line is missing:\n{text}"
    );
    // The one quiet line, not a boxed paragraph.
    assert!(
        text.contains("Actions run on studio as ada."),
        "the deploying-from line is missing:\n{text}"
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

    // One row, every column §5.1 lists, with the command in the action column.
    let row = device_row(&screen, "build-linux");
    assert!(row.contains("linux"), "the OS column: {row}");
    assert!(row.contains("100.64.12.44"), "the address column: {row}");
    assert!(
        row.contains("\u{25cf} online"),
        "the presence column: {row}"
    );
    assert!(row.contains("not set up"), "the Ouroboros column: {row}");
    assert!(
        row.contains("ouro fleet add USER@100.64.12.44 --machine build-linux"),
        "the action column: {row}"
    );

    // One row per device.
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

    // The recipe for a device the network client never listed, under the list.
    assert!(
        text.contains("Not listed? ouro fleet add USER@ADDRESS --machine NAME"),
        "{text}"
    );

    // And no pane until somebody asks for one.
    assert!(!app.devices.details);
    assert!(
        !text.contains("to run"),
        "the pane was open before Enter:\n{text}"
    );
}

/// §5.1's Ouroboros column, and the one command each state gets.
#[test]
fn every_state_gets_one_word_and_one_command() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let screen = screen(&mut app);

    // A visible, supported, online peer is told how to be added, never called uninstalled.
    let build = device_row(&screen, "build-linux");
    assert!(build.contains("not set up"), "{build}");
    assert!(
        build.contains("ouro fleet add USER@100.64.12.44 --machine build-linux"),
        "{build}"
    );

    // iOS: a platform no release targets. No command, and a dash where one would be.
    let phone = device_row(&screen, "pocket-phone");
    assert!(phone.contains("can't run Ouroboros"), "{phone}");
    assert!(phone.contains('\u{2014}'), "{phone}");
    assert!(!phone.contains("ouro fleet"), "{phone}");

    // Offline: nothing to reach, so nothing to run.
    let pi = device_row(&screen, "old-pi");
    assert!(pi.contains("offline"), "{pi}");
    assert!(!pi.contains("ouro fleet"), "{pi}");

    // This machine, in the fleet: the local leave, with no account and no address,
    // because there is no SSH to itself.
    let this = device_row(&screen, "This Mac");
    assert!(this.contains("in the fleet"), "{this}");
    assert!(this.contains("ouro fleet leave"), "{this}");
    assert!(
        !this.contains("--machine"),
        "this machine was told to reach itself over SSH: {this}"
    );
}

/// A member that is not this machine is told how to be taken out, by name and account.
#[test]
fn a_member_is_told_how_to_leave_by_name_with_the_account_left_to_the_operator() {
    let _mode = normal();
    let mut reply = populated();
    reply["devices"] = json!([
        self_row(),
        {
            "name": "raspberrypi", "machine": "pi", "suggested_machine": "pi",
            "os": "linux", "address": "100.64.12.60", "online": true,
            "connected": true, "state": "fleet_member",
            "name_conflicts_with_roster": Value::Null,
        }
    ]);

    let mut app = with_inventory(reply);
    let drawn = screen(&mut app);
    let row = device_row(&drawn, "raspberrypi");

    // The fleet name, not the display name; the account is the operator's to supply.
    assert!(
        row.contains("ouro fleet leave --machine pi --user USER"),
        "{row}"
    );
    assert!(
        !row.contains("--machine raspberrypi"),
        "the display name reached the command: {row}"
    );
}

/// A discovery failure is one inline notice in the client's own words.
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
        assert!(text.contains("This Mac"), "{code} lost the fleet:\n{text}");
    }

    // A client that answered is not a failure, so there is no notice at all.
    let mut app = with_inventory(populated());
    assert!(!prose(&mut app).contains("Tailscale did not answer"));
}

/// A machine with no fleet says so in the status line, and is told the one command.
#[test]
fn a_standalone_machine_says_so_in_its_status_line_and_is_told_how_to_start_one() {
    let _mode = normal();
    let mut reply = devices_reply("no-peers", "no_visible_peers", None, vec![]);
    reply["devices"] = json!([{
        "name": "studio", "machine": Value::Null, "suggested_machine": "operator-laptop",
        "os": "macos", "address": "100.64.12.21", "online": true,
        "state": "this_device_without_profile",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let text = prose(&mut app);

    assert!(text.contains("This Mac is not in a fleet yet"), "{text}");
    assert!(
        device_row(&screen(&mut app), "This Mac")
            .contains("ouro fleet setup --machine operator-laptop"),
        "{text}"
    );
    // The blocker is the status line; it is not said twice.
    assert_eq!(
        text.matches("not in a fleet yet").count(),
        1,
        "the blocker sentence is drawn twice:\n{text}"
    );
    // And nothing left over from the PKI that was withdrawn.
    assert!(
        !text.contains("certificate authority"),
        "a standalone machine was told about a CA key:\n{text}"
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
    assert!(hint.contains("Enter show details"), "{hint}");
    assert!(hint.contains("r refresh"), "{hint}");

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

/// The search field is the one thing left on this page that takes a paste.
#[test]
fn a_pasted_query_reaches_the_search_field_and_nothing_else_takes_text() {
    let _mode = normal();
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
    let mut app = with_inventory(devices_reply("running-with-peers", "ok", None, rows));
    let _settled = drained(&mut app);

    // Closed: the paste is refused and the client says so rather than swallowing it.
    app.apply(Msg::Paste("peer-3".into()));
    let text = prose(&mut app);
    assert!(
        text.contains("nothing here is taking text right now"),
        "{text}"
    );

    // Open: it goes into the query.
    app.apply(key(KeyCode::Char('/')));
    app.apply(Msg::Paste("peer-3".into()));
    let text = prose(&mut app);
    assert!(text.contains("peer-3"), "{text}");
    assert!(
        !text.contains("peer-4"),
        "the paste did not narrow:\n{text}"
    );
    assert!(drained(&mut app).is_empty(), "a paste sent something");
}

/// A device that adopts a member's name is its own row with a note, never a merge.
#[test]
fn a_device_impersonating_a_member_is_listed_separately_with_a_note() {
    let _mode = normal();
    let mut rows = vec![json!({
        "name": "attic", "machine": "attic", "suggested_machine": "attic", "os": "linux",
        "address": "100.64.12.77", "online": Value::Null,
        "state": "fleet_member_not_visible",
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

    // The note is in the impostor's own pane, under its own row.
    app.apply(key(KeyCode::Enter));
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
// the details pane
// ---------------------------------------------------------------------------------------

/// Enter opens the pane; it carries the command in full, whose shell it belongs in, and
/// the facts a row cannot hold. Esc closes it before it closes the view.
#[test]
fn enter_opens_a_pane_with_the_command_the_host_and_the_exact_time() {
    let _mode = normal();
    let mut app = with_inventory(populated());

    // The self row is selected first, and nothing is open.
    assert!(!prose(&mut app).contains("to run"));

    app.apply(key(KeyCode::Enter));
    let text = prose(&mut app);
    assert!(text.contains("to run ouro fleet leave"), "{text}");
    assert!(
        text.contains("Actions run on studio as ada."),
        "the pane does not say whose shell the command is for:\n{text}"
    );
    assert!(text.contains("in the fleet as studio"), "{text}");
    assert!(text.contains("presence online now"), "{text}");
    assert!(text.contains("runtime runtime connected"), "{text}");
    assert!(
        drained(&mut app).is_empty(),
        "opening the pane sent something"
    );

    // Move onto the offline peer: the exact observation time is here, not on the row,
    // and the reason there is no command is here too.
    select(&mut app, "old-pi");
    let text = prose(&mut app);
    assert!(
        text.contains("offline, last seen 2026-09-17T07:50:00.1Z"),
        "the exact time is not in the pane:\n{text}"
    );
    assert!(
        text.contains("Offline is not powered off"),
        "a row with no command does not say why:\n{text}"
    );
    assert!(text.contains("to run \u{2014}"), "{text}");

    // Esc closes the pane, and only then the view.
    app.apply(key(KeyCode::Esc));
    assert!(matches!(app.overlay, Some(Overlay::Devices)));
    assert!(!prose(&mut app).contains("to run"));
    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none());
}

/// An operation the runtime is running shows on the row and in the pane, and is
/// read-only: there is no key that answers it, continues it or cancels it.
#[test]
fn an_operation_in_progress_is_drawn_on_its_row_and_answered_by_nothing() {
    let _mode = normal();

    let underway = |state: &str, last_error: Value| {
        let mut reply = populated();
        reply["operations"] = json!([{
            "operation": "op-7", "kind": "add", "state": state,
            "running": state != "failed", "readable": true,
            "created_at": "2026-09-18T08:00:00Z",
            "updated_at": "2026-09-18T08:05:00Z",
            "target": { "machine": "build-linux", "address": "100.64.12.44" },
            "last_error": last_error,
        }]);
        reply
    };

    // Going: the Ouroboros column says so, and the action column has nothing to type.
    let mut app = with_inventory(underway("running", Value::Null));
    let drawn = screen(&mut app);
    let row = device_row(&drawn, "build-linux");
    assert!(row.contains("setting up\u{2026}"), "{row}");
    assert!(
        !row.contains("ouro fleet"),
        "a device being set up was still offered the command: {row}"
    );
    drop(drawn);

    open_details(&mut app, "build-linux");
    let text = prose(&mut app);
    assert!(text.contains("op-7"), "{text}");
    assert!(text.contains("running"), "{text}");
    assert!(text.contains("a worker is running it"), "{text}");

    // Waiting on somebody: still read-only, and the state says it is waiting. §6 has
    // five states and `waiting` is one of them; *what* it waits for is the live
    // challenge, which this client neither receives nor answers.
    let mut waiting = with_inventory(underway("waiting", Value::Null));
    open_details(&mut waiting, "build-linux");
    let text = prose(&mut waiting);
    assert!(text.contains("waiting for somebody"), "{text}");
    for code in [
        KeyCode::Char('t'),
        KeyCode::Char('n'),
        KeyCode::Char('c'),
        KeyCode::Char('y'),
        KeyCode::Enter,
    ] {
        waiting.apply(key(code));
        assert!(
            drained(&mut waiting).is_empty(),
            "{code:?} answered a challenge from the terminal"
        );
    }

    // Failed: the row says so, offers the command again, and the pane has the cause.
    let mut failed = with_inventory(underway(
        "failed",
        json!({ "reason": "worker_timeout", "detail": "no reply after 120s" }),
    ));
    let drawn = screen(&mut failed);
    let row = device_row(&drawn, "build-linux");
    assert!(row.contains("setup failed"), "{row}");
    assert!(
        row.contains("ouro fleet add USER@100.64.12.44 --machine build-linux"),
        "a stopped operation did not give the row its command back: {row}"
    );
    drop(drawn);

    open_details(&mut failed, "build-linux");
    let text = prose(&mut failed);
    assert!(text.contains("last error"), "{text}");
    assert!(text.contains("did not answer in time"), "{text}");
    assert!(text.contains("no reply after 120s"), "{text}");
}

/// The member facts are in the pane, the fleet's own words stay on the row, and `r` still
/// asks the runtime again.
#[test]
fn a_connected_member_reads_as_connected_and_keeps_the_network_facts_separate() {
    let _mode = normal();

    let mut reply = populated();
    reply["devices"] = json!([
        {
            "name": "build-linux", "machine": "build-linux",
            "suggested_machine": "build-linux", "os": "linux",
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
            "name": "old-pi", "machine": "old-pi", "suggested_machine": "old-pi",
            "os": "linux",
            "address": "100.64.12.10", "online": true, "last_seen": Value::Null,
            "state": "fleet_member",
            "connected": false, "compatible": Value::Null,
            "runtime_running": Value::Null, "last_probe": Value::Null,
            "name_conflicts_with_roster": Value::Null
        },
        {
            // A peer that has never been in a fleet: this runtime knows nothing about it,
            // and says nothing rather than reporting it as disconnected.
            "name": "vps", "machine": Value::Null, "suggested_machine": "vps",
            "os": "linux",
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
    let row = device_row(&drawn, "build-linux").to_string();
    assert!(row.contains("in the fleet"), "{row}");
    assert!(
        row.contains("ouro fleet leave --machine build-linux --user USER"),
        "{row}"
    );
    drop(drawn);
    let text = prose(&mut app);
    assert!(
        !text.contains("not visible on this network"),
        "a connected member still read as invisible:\n{text}"
    );

    // The runtime's facts, in that row's pane, kept apart from the network's.
    open_details(&mut app, "build-linux");
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
    select(&mut app, "old-pi");
    let text = prose(&mut app);
    assert!(text.contains("runtime not connected"), "{text}");
    assert!(
        device_row(&screen(&mut app), "old-pi").contains("in the fleet \u{b7} not connected"),
        "{text}"
    );

    // A non-member carries no runtime line at all — null is "not known", not "absent".
    select(&mut app, "vps");
    let text = prose(&mut app);
    assert!(
        !text.contains("runtime runtime") && !text.contains("runtime not connected"),
        "a device that has never been in a fleet was given cluster facts:\n{text}"
    );

    // `r` still asks the runtime again, and asks for nothing else.
    app.apply(key(KeyCode::Char('r')));
    let calls = drained(&mut app);
    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));
    assert_eq!(calls.len(), 1, "{:?}", calls);
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
            "name": "mystery", "machine": Value::Null, "suggested_machine": "mystery",
            "os": "linux",
            "address": "100.64.12.50", "online": true, "last_seen": Value::Null,
            "state": state, "name_conflicts_with_roster": Value::Null
        }]);

        let mut app = with_inventory(reply);
        let _settled = drained(&mut app);
        app.apply(key(KeyCode::Enter));
        let text = prose(&mut app);

        assert!(text.contains(expected), "{state:?}:\n{text}");

        // The row is still a row, with its own fields drawn and no command invented.
        let drawn = screen(&mut app);
        assert!(device_row(&drawn, "mystery").contains('\u{2014}'));
        drop(drawn);
        assert!(text.contains("100.64.12.50"), "{state:?}:\n{text}");
        assert!(
            text.contains("which this client has no command for"),
            "{state:?} left the reason unsaid:\n{text}"
        );
    }
}

/// Paging leaves the selection alone so a pane below the fold can be read, and no key
/// that pages acts on anything.
#[test]
fn paging_a_long_inventory_reaches_the_pane_without_acting() {
    let _mode = normal();
    let mut reply = populated();
    reply["devices"] = json!((0..30)
        .map(|index| json!({
            "name": format!("peer-{index:02}"),
            "machine": format!("peer-{index:02}"),
            "suggested_machine": format!("peer-{index:02}"),
            "address": format!("100.64.1.{}", index + 1),
            "os": "linux", "state": "fleet_member", "online": true,
            "connected": true,
            "last_probe": if index == 0 { "2026-09-17T08:10:00Z" } else { "other probe" }
        }))
        .collect::<Vec<_>>());

    let mut app = with_inventory(reply);
    app.terminal_width = 80;
    let _ = drained(&mut app);
    let initial = render(&mut app, 80, 24);
    assert!(initial.rows.iter().any(|row| row.contains("> peer-00")));
    assert!(!flowed(&initial).contains("probed 2026-09-17T08:10:00Z"));

    // Open the pane for the selected row, then page away from it.
    app.apply(key(KeyCode::Enter));
    let mut pages = String::new();
    for _ in 0..10 {
        app.apply(key(KeyCode::PageDown));
        pages.push_str(&flowed(&render(&mut app, 80, 24)));
        pages.push(' ');
    }
    assert!(pages.contains("runtime connected"), "{pages}");
    assert!(pages.contains("probed 2026-09-17T08:10:00Z"), "{pages}");
    assert_eq!(
        app.devices.cursor, 0,
        "paging changed the selected destination"
    );
    assert!(drained(&mut app).is_empty(), "paging acted on a device");

    // Ordinary cursor movement follows the destination below the fold, and the pane
    // follows the cursor.
    for _ in 0..25 {
        app.apply(key(KeyCode::Down));
    }
    let moved = render(&mut app, 80, 24);
    assert!(moved.rows.iter().any(|row| row.contains("> peer-25")));
    let text = flowed(&render(&mut app, 80, 24));
    assert!(
        text.contains("ouro fleet leave --machine peer-25 --user USER"),
        "{text}"
    );
    assert!(drained(&mut app).is_empty());
}

// ---------------------------------------------------------------------------------------
// authority
// ---------------------------------------------------------------------------------------

/// A runtime that does not serve the method, and one that refuses this identity, say
/// different things — and both fall back to the membership subset.
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

/// A read-scope listener sees the whole inventory, because it is a read — and there is
/// nothing on the page for its scope to refuse.
#[test]
fn a_read_scope_listener_sees_the_whole_list() {
    let _mode = normal();
    let mut app = opened(read_hello(&[
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

    assert!(screen(&mut app).contains("build-linux"));

    open_details(&mut app, "build-linux");
    let text = prose(&mut app);
    assert!(
        text.contains("ouro fleet add USER@100.64.12.44 --machine build-linux"),
        "a read-scope listener was not told what to run:\n{text}"
    );
    assert!(
        drained(&mut app).is_empty(),
        "a read-scope listener sent something"
    );
    // There is no "started at read scope" sentence left, because there is no verb it
    // could apply to.
    assert!(!text.contains("started at read scope"), "{text}");
}

/// Whatever this runtime says it cannot do is said once, above the list, and gates
/// nothing: the commands are for a shell, not for this client.
#[test]
fn a_runtime_that_cannot_deploy_says_so_once_and_still_prints_the_commands() {
    let _mode = normal();
    for (reason, expected) in [
        ("dev_runtime", "development runtime"),
        ("ouro_path_unknown", "where its own ouro executable is"),
        ("no_data_dir", "no durable data directory"),
        ("cleartext_web_bind", "non-loopback"),
    ] {
        let mut reply = populated();
        reply["host"] = host(false, &[reason]);

        let mut app = with_inventory(reply);
        let text = prose(&mut app);

        assert!(text.contains(expected), "{reason}:\n{text}");
        assert_eq!(
            text.matches(expected).count(),
            1,
            "{reason} is said more than once:\n{text}"
        );
        // The list is unchanged: this client is not the thing that would be blocked.
        assert!(
            device_row(&screen(&mut app), "build-linux").contains("ouro fleet add"),
            "{reason} took the command off a row:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// the contract
// ---------------------------------------------------------------------------------------

/// The `--machine` argument comes from the runtime's own suggestion, never from a
/// display name, and never from an unvalidated string.
#[test]
fn the_command_is_filled_from_the_runtimes_suggestion_only() {
    let _mode = normal();

    // The capture's own display names, and what the contract folds them to.
    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "Monocursive's MacBook Pro",
        "machine": Value::Null,
        "suggested_machine": "monocursive-s-macbook-pro",
        "os": "macOS", "address": "100.64.12.70", "online": true,
        "state": "discovered_installation_unknown",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let drawn = screen(&mut app);
    let row = device_row(&drawn, "Monocursive");
    assert!(
        row.contains("--machine monocursive-s-macbook-pro"),
        "the suggestion was not used: {row}"
    );
    assert!(
        !row.contains("--machine Monocursive's"),
        "a display name reached the command: {row}"
    );
    drop(drawn);

    // `null`: nothing valid remained, and the placeholder says so out loud.
    let mut reply = populated();
    reply["devices"] = json!([{
        "name": "\u{2603}\u{2603}\u{2603}",
        "machine": Value::Null,
        "suggested_machine": Value::Null,
        "os": "linux", "address": "100.64.12.71", "online": true,
        "state": "discovered_installation_unknown",
        "name_conflicts_with_roster": Value::Null,
    }]);

    let mut app = with_inventory(reply);
    let text = prose(&mut app);
    assert!(
        text.contains("ouro fleet add USER@100.64.12.71 --machine NAME"),
        "a name the runtime could not fold was invented:\n{text}"
    );
}

/// Every reason, blocker and operation-state code the fixtures in this file put on the
/// wire has a sentence in the TUI catalogue.
///
/// Against the published lists rather than against the `*_known` predicates, which are
/// `cfg(test)` in the lib: the view never asks whether a code is catalogued, because the
/// answer changes nothing it draws, and a helper that exists only so a test can ask is a
/// helper a test can own.
#[test]
fn every_code_the_fixtures_emit_has_a_sentence() {
    use ouro::ui::app::devices::{
        blocker_sentence, operation_state, reason_sentence, BLOCKER_CODES, OPERATION_STATES,
    };

    let blocker_known = |code: &str| BLOCKER_CODES.contains(&code);
    let operation_state_known = |code: &str| OPERATION_STATES.contains(&code);

    for code in [
        "host_key_changed",
        "version_mismatch",
        "worker_timeout",
        "worker_unavailable",
        "devices_busy",
        "journal_unreadable",
        "ouro_path_unknown",
        "no_data_dir",
        "cleartext_web_bind",
        "dev_runtime",
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

    // §6 and §8: an operation's state is one of five words, in the journal and on the
    // wire alike. The engine's finer phases never leave the process that runs it, so
    // this list is the whole vocabulary a row can carry.
    for code in ["running", "waiting", "completed", "failed", "cancelled"] {
        assert!(operation_state_known(code), "{code} is not catalogued");
        let sentence = operation_state(code);
        assert!(
            !sentence.contains("does not know"),
            "{code} fell through: {sentence}"
        );
    }

    // And the words that used to be states are not catalogued any more: a document
    // carrying one is a document from a build that predates the five, and it is named
    // rather than explained.
    for gone in [
        "spawning",
        "inspecting",
        "awaiting_host_trust",
        "awaiting_auth",
        "awaiting_review",
        "deploying",
        "restarting_host",
        "checking_readiness",
        "interrupted",
    ] {
        assert!(!operation_state_known(gone), "{gone} is still catalogued");
        assert!(
            operation_state(gone).contains("does not know"),
            "{gone} still has a sentence of its own"
        );
    }

    // The codes the deleted flow owned are gone with it, and a document that still sends
    // one is named rather than explained by a sentence this build no longer believes.
    for gone in ["no_ca_key", "operation_not_yours", "challenge_not_bound"] {
        assert!(!blocker_known(gone), "{gone} is still a blocker");
        let sentence = blocker_sentence(gone);
        assert!(
            sentence.contains(&gone.replace('_', " ")),
            "{gone} did not fall through to its own name: {sentence}"
        );
    }
}

/// Reconnecting reads the list again rather than redrawing what a runtime said before it
/// restarted.
#[test]
fn a_reconnect_reads_the_list_again() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    // Nothing is due yet: the inventory is read when the view opens and when `r` asks.
    for _ in 0..50 {
        app.apply(Msg::Tick);
    }
    assert!(drained(&mut app).is_empty());

    app.apply(Msg::Reconnected(Box::new(full_hello())));
    let calls = drained(&mut app);
    assert_eq!(call_for(&calls, "fleet.devices").params, json!({}));
    assert_eq!(
        calls
            .iter()
            .filter(|call| call.method.starts_with("fleet."))
            .count(),
        1,
        "a reconnect issued more than the one read: {calls:?}"
    );
}

// ---------------------------------------------------------------------------------------
// screen-reader mode
// ---------------------------------------------------------------------------------------

/// The rows are a numbered menu, the numbers select, and the box is gone.
#[test]
fn screen_reader_mode_numbers_the_rows_and_the_numbers_select() {
    let _mode = screen_reader();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    let text = prose(&mut app);
    assert!(
        text.contains("1. This Mac"),
        "the rows are not numbered:\n{text}"
    );
    assert!(!text.contains('\u{2502}'), "the box survived:\n{text}");

    // The number selects the row it numbers.
    app.apply(key(KeyCode::Char('2')));
    assert_eq!(app.devices.cursor, 1);

    // And Enter reads its command out, with the host the command is for.
    app.apply(key(KeyCode::Enter));
    let text = prose(&mut app);
    assert!(text.contains("to run ouro fleet"), "{text}");
    assert!(text.contains("Actions run on studio as ada."), "{text}");
    assert!(drained(&mut app).is_empty(), "a number sent something");
}

/// The keys the hint line names are the keys that work, in both modes.
#[test]
fn the_hint_line_names_the_keys_that_work() {
    let _mode = normal();
    let mut app = with_inventory(populated());
    let _settled = drained(&mut app);

    let hint = ouro::ui::app::devices_hint_line(&app);
    assert!(hint.contains("Enter show details"), "{hint}");
    assert!(hint.contains("Esc close"), "{hint}");
    // Nothing the view cannot do.
    for gone in ["add by address", "remove", "cancel", "take over", "retry"] {
        assert!(!hint.contains(gone), "the hint still offers {gone}: {hint}");
    }

    app.apply(key(KeyCode::Enter));
    let hint = ouro::ui::app::devices_hint_line(&app);
    assert!(hint.contains("Enter hide details"), "{hint}");
}
