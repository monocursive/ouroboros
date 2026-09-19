//! Adversarial review K5: what the Devices inventory still lets through.
//!
//! Not part of the slice. Each test here is a *finding*: it states the property the
//! view's own module documentation claims, and fails where the code does not hold it.
//! The leniency battery is the exception — it passes, and is kept as the proof that the
//! decoder survives the documents §3 of the review brief asks about.
//!
//! The harness is `w3b_exploits.rs`'s, reproduced rather than shared because a test
//! binary cannot import another test binary.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::proto::{ErrorCode, Hello, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Call, DeviceInventory, DeviceRow, Msg, Recipe, Tag};

use support::{app, full_hello, render, Screen};

static MODE: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct Held<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}
impl Drop for Held<'_> {
    fn drop(&mut self) {
        ouro::ui::access::install(ouro::ui::access::Settings::default());
    }
}
fn normal() -> Held<'static> {
    let guard = MODE.lock().unwrap_or_else(|p| p.into_inner());
    ouro::ui::access::install(ouro::ui::access::Settings::default());
    Held { _guard: guard }
}

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn screen(app: &mut App) -> Screen {
    app.terminal_width = 200;
    render(app, 200, 60)
}

fn drained(app: &mut App) -> Vec<Call> {
    app.drain()
}

fn call_for<'a>(calls: &'a [Call], method: &str) -> &'a Call {
    calls
        .iter()
        .find(|call| call.method == method)
        .unwrap_or_else(|| panic!("no {method} call"))
}

fn host(deploy: bool, reasons: &[&str]) -> Value {
    json!({
        "hostname": "studio", "user": "ada", "os": "darwin",
        "arch": "aarch64-apple-darwin",
        "capabilities": { "deploy": deploy, "reasons": reasons },
    })
}

fn row(name: &str, address: &str, state: &str) -> Value {
    json!({
        "name": name, "machine": Value::Null, "suggested_machine": name,
        "os": "linux", "address": address,
        "online": true, "last_seen": Value::Null, "state": state,
        "name_conflicts_with_roster": Value::Null,
    })
}

fn reply(rows: Vec<Value>, operations: Value, host: Value) -> Value {
    json!({
        "host": host,
        "discovery": { "code": "ok", "detail": Value::Null, "visible_peers": rows.len() },
        "devices": rows,
        "operations": operations,
        "unknown": [],
    })
}

fn opened(hello: Hello) -> App {
    let mut a = app(hello);
    a.apply(Msg::Tick);
    let _s = a.drain();
    a.open_devices();
    a
}

fn with_inventory(value: Value) -> App {
    let mut a = opened(full_hello());
    let calls = drained(&mut a);
    let tag = call_for(&calls, "fleet.devices").tag.clone();
    answer(&mut a, tag, value);
    a
}

/// Every span of every line the view draws — what a terminal is actually asked to print.
fn spans(app: &App) -> Vec<String> {
    ouro::ui::app::devices_lines(app)
        .iter()
        .flat_map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.to_string())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn joined_lines(app: &App) -> String {
    ouro::ui::app::devices_lines(app)
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The strings a terminal obeys, a person cannot see, or a reader cannot tell apart.
const HOSTILE: &str = "\u{1b}[2J\u{1b}[1;1H\u{9b}31m\u{202e}fleet admin\u{200b}\u{200d}\n\r\
                       \tstudio  macOS  100.64.0.1  \u{25cf} online  in the fleet  \u{2014}";

/// Every character class the funnel is documented to remove.
fn forbidden(text: &str) -> Option<char> {
    text.chars().find(|c| {
        c.is_control()
            || ('\u{80}'..='\u{9f}').contains(c)
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{00ad}')
    })
}

// =======================================================================
// K5-1  the gateway's `data.reason` never reaches the funnel
// =======================================================================
/// `devices.rs`'s module doc: "a gateway's refusal message ... reaches a `Line` through
/// `scrub`". `devices_refusal` sends `rpc.message` through `clean`, but the `data.reason`
/// branch beside it goes through `reason_sentence` — which, for a code this build does
/// not catalogue, interpolates the raw string into a sentence and draws it.
///
/// `w3b_exploits::x8` covers the `message` path with `data: None`, so this arm is the one
/// the suite never exercises.
#[test]
fn k5_1_a_refusal_reason_from_the_gateway_is_drawn_unscrubbed() {
    let _m = normal();
    let mut a = opened(full_hello());
    let calls = drained(&mut a);
    let tag = call_for(&calls, "fleet.devices").tag.clone();

    a.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            // Not a catalogued reason code, so `reason_sentence` falls through to the
            // arm that prints the runtime's own word.
            message: "refused".into(),
            data: Some(json!({ "reason": HOSTILE })),
        })),
    });

    for span in spans(&a) {
        assert!(
            forbidden(&span).is_none(),
            "a refusal reason reached a Line carrying {:?}: {span:?}",
            forbidden(&span).unwrap()
        );
    }

    // And the frame a terminal is handed, not only the Line behind it.
    //
    // Row by row rather than on `Screen::text()`: that helper joins the rows *with a
    // newline*, so the assertion as first written found the harness's own separator and
    // could not have passed for any frame taller than one row. The property is about the
    // cells the backend holds, and those are the rows.
    let drawn = screen(&mut a);
    for row in &drawn.rows {
        assert!(
            forbidden(row).is_none(),
            "a refusal reason reached the drawn frame carrying {:?}: {row:?}",
            forbidden(row).unwrap()
        );
    }
}

/// And it is unbounded: `clean` cuts a message to `MESSAGE_COLUMNS`, this arm cuts
/// nothing at all.
#[test]
fn k5_1b_a_refusal_reason_is_bounded_by_nothing() {
    let _m = normal();
    let mut a = opened(full_hello());
    let calls = drained(&mut a);
    let tag = call_for(&calls, "fleet.devices").tag.clone();

    a.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "refused".into(),
            data: Some(json!({ "reason": "z".repeat(10_000) })),
        })),
    });

    let longest = spans(&a)
        .into_iter()
        .map(|span| span.chars().count())
        .max()
        .unwrap_or(0);

    assert!(
        longest <= 400,
        "a 10 000-character refusal reason was drawn whole: {longest} characters in one span"
    );
}

// =======================================================================
// K5-2  the printed arguments are wider than the grammar `ouro` accepts
// =======================================================================
/// `machine_argument`'s own doc: "§5.2's rule, letters, digits and hyphens, beginning
/// with a letter or a digit, at most forty characters". `fleet::validate_machine` — the
/// code that runs when the printed line is pasted — is that rule *and* requires the last
/// character to be alphanumeric, and forbids `_`.
///
/// A value the view prints but `ouro` refuses is worse than the `NAME` placeholder: the
/// placeholder says "choose one", a rejected name says the command is broken.
#[test]
fn k5_2_every_printed_machine_is_a_name_ouro_would_accept() {
    let _m = normal();

    let mut refused = Vec::new();

    for suggested in ["under_score", "pi-", "a_b-c", "pi_", &"g".repeat(40)] {
        let row = DeviceRow {
            state: "fleet_member".into(),
            machine: Some(suggested.to_string()),
            ..Default::default()
        };

        let Recipe::Command(command) = row.recipe() else {
            continue;
        };
        let printed = command
            .split("--machine ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("a --machine argument");

        if printed == "NAME" {
            continue;
        }

        if let Err(error) = ouro::fleet::validate_machine(printed) {
            refused.push(format!("  `{command}`\n    -> {error}"));
        }
    }

    assert!(
        refused.is_empty(),
        "the view printed {} command line(s) `ouro` refuses:\n{}",
        refused.len(),
        refused.join("\n")
    );
}

/// The same for the address. `address_argument` allows `:` and the unit test beside it
/// pins `fd7a::1` as printable — but `ouro fleet add` refuses any host containing `:`
/// outright ("cannot be used by the current IPv4 fleet distribution"), and refuses a
/// public IPv4 as well.
#[test]
fn k5_2b_every_printed_address_is_a_host_ouro_would_accept() {
    let _m = normal();

    let mut refused = Vec::new();

    for address in [
        "fd7a::1",
        "8.8.8.8",
        "100.64.0.11",
        "pi.tailnet-example.ts.net",
    ] {
        let row = DeviceRow {
            state: "discovered_installation_unknown".into(),
            address: Some(address.to_string()),
            suggested_machine: Some("pi".into()),
            ..Default::default()
        };

        let Recipe::Command(command) = row.recipe() else {
            continue;
        };
        let printed = command
            .split("USER@")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .expect("an address argument");

        if printed == "ADDRESS" {
            continue;
        }

        if let Err(error) = ouro::fleet::canonical_host(printed) {
            refused.push(format!("  `{command}`\n    -> {error}"));
        }
    }

    assert!(
        refused.is_empty(),
        "the view printed {} command line(s) `ouro` refuses:\n{}",
        refused.len(),
        refused.join("\n")
    );
}

// =======================================================================
// K5-3  an operation is matched to a row by a truncated address
// =======================================================================
/// Both sides of `OperationTarget::is` are decoded through `text`, which cuts to
/// `FIELD_COLUMNS`. Two distinct hosts sharing a long prefix become one string on the
/// way in, so an operation against one is drawn on the other — which takes that row's
/// command away and puts `setting up…` on a device nothing is happening to.
#[test]
fn k5_3_two_long_addresses_are_one_row_after_the_bounding() {
    let _m = normal();

    // `FIELD_COLUMNS` is 72 and `human` keeps one column back for the cut marker, so the
    // first 71 columns are all that survives the decode. Two hosts that differ only
    // after that are one string by the time `OperationTarget::is` compares them.
    let prefix = "a".repeat(75);
    let mine = format!("{prefix}1.example.ts.net");
    let theirs = format!("{prefix}2.example.ts.net");

    let inventory = DeviceInventory::decode(&reply(
        vec![
            row("alpha", &mine, "discovered_installation_unknown"),
            row("bravo", &theirs, "discovered_installation_unknown"),
        ],
        json!([{
            "operation": "op-1", "kind": "add", "state": "deploying",
            "running": true, "readable": true,
            "target": { "address": theirs },
        }]),
        host(true, &[]),
    ));

    let alpha = &inventory.devices[0];

    assert_eq!(
        inventory.recipe(alpha),
        inventory.devices[0].recipe(),
        "an operation against {theirs} was drawn on the row for {mine}"
    );
}

// =======================================================================
// K5-6  a document with no devices still announces a fleet
// =======================================================================
/// `devices: null`, or a `fleet.devices` this client could not read a row out of, leaves
/// `standalone()` false and `members()` empty — and `status_line` then draws
/// "Fleet of this machine · 0 of 0 machines connected", in the colour reserved for a
/// healthy fleet. The runtime said nothing about a fleet; the line claims one.
#[test]
fn k5_6_a_document_with_no_devices_does_not_claim_a_fleet() {
    let _m = normal();

    for document in [
        json!({ "host": host(true, &[]), "devices": Value::Null }),
        json!({ "host": host(true, &[]), "devices": [] }),
        json!({}),
    ] {
        let inventory = DeviceInventory::decode(&document);
        let line = inventory.status_line();

        assert!(
            !line.contains("0 of 0 machine"),
            "a document with no rows drew `{line}`, which states a fleet the runtime \
             never reported"
        );
    }
}

// =======================================================================
// K5-7  the `unknown` list is bounded by nothing
// =======================================================================
/// Each key is cut to `FIELD_COLUMNS` on the way in; how many of them there are is not
/// bounded at all, and they are joined into one `Line`.
#[test]
fn k5_7_the_unknown_key_list_is_bounded() {
    let _m = normal();

    let keys: Vec<Value> = (0..5_000)
        .map(|i| json!(format!("key_{i}_{}", "z".repeat(80))))
        .collect();
    let mut a = with_inventory(json!({
        "host": host(true, &[]),
        "discovery": { "code": "ok", "visible_peers": 0 },
        "devices": [row("alpha", "100.64.0.1", "discovered_installation_unknown")],
        "operations": [],
        "unknown": keys,
    }));
    let _ = drained(&mut a);

    let longest = spans(&a)
        .into_iter()
        .map(|span| span.chars().count())
        .max()
        .unwrap_or(0);

    assert!(
        longest <= 400,
        "the unknown-key list was drawn whole: {longest} characters in one span"
    );
}

// =======================================================================
// K5-4  the leniency battery — nothing here may panic
// =======================================================================
/// §3 of the review brief, as documents. Each one is decoded, rendered, and its details
/// pane opened. A panic is the finding; this test passing is the proof there is none.
#[test]
fn k5_4_a_degenerate_document_never_panics() {
    let _m = normal();

    let documents = vec![
        json!(null),
        json!({}),
        json!({ "devices": Value::Null }),
        json!({ "devices": "not an array", "operations": 7, "host": 3, "discovery": [] }),
        json!({ "devices": [Value::Null, json!(5), json!("x"), json!([])] }),
        // A row with no state at all, and one with a state from the future.
        json!({ "devices": [{ "name": "a" }, { "name": "b", "state": "teleported" }] }),
        // `operations` without `running`, and `last_error` in each shape.
        json!({
            "devices": [row("alpha", "100.64.0.1", "discovered_installation_unknown")],
            "operations": [
                { "operation": "o1", "target": { "address": "100.64.0.1" } },
                { "operation": "o2", "target": { "address": "100.64.0.1" }, "last_error": 7 },
                { "operation": "o3", "target": { "address": "100.64.0.1" }, "last_error": [] },
                { "operation": "o4", "target": { "address": "100.64.0.1" },
                  "last_error": { "reason": 5, "detail": Value::Null } },
                { "operation": "o5", "target": { "address": "100.64.0.1" },
                  "last_error": "a bare string" },
            ],
        }),
        // No discovery, no host, an unknown blocker code, a hostile visible_peers.
        json!({
            "discovery": { "visible_peers": u64::MAX },
            "devices": [row("alpha", "100.64.0.1", "discovered_installation_unknown")],
        }),
        json!({
            "host": { "capabilities": { "reasons": ["quantum_decoherence", 5, Value::Null] } },
            "devices": [row("alpha", "100.64.0.1", "discovered_installation_unknown")],
        }),
        // A timestamp that is not one, at every boundary the parser slices on.
        json!({
            "devices": [{
                "name": "a", "state": "peer_offline", "online": false,
                "last_seen": "2020-01-01T00:00:0\u{e9}",
            }],
        }),
        json!({
            "devices": [{
                "name": "a", "state": "peer_offline", "online": false,
                "last_seen": "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            }],
        }),
    ];

    for document in documents {
        let mut a = with_inventory(document.clone());
        let _ = drained(&mut a);
        let _ = screen(&mut a);
        a.apply(key(KeyCode::Enter));
        let _ = screen(&mut a);
        a.apply(key(KeyCode::Char('j')));
        a.apply(key(KeyCode::Char('r')));
        let _ = screen(&mut a);
        let _ = ouro::ui::app::devices_hint_line(&a);
    }
}

// =======================================================================
// K5-5  every peer-written string, in one document
// =======================================================================
/// Each field §2 of the brief names, carrying the same hostile string, drawn on the row
/// and in the details pane. The property is one span, no obeyed characters, no forged
/// line.
#[test]
fn k5_5_every_peer_written_string_stays_inside_its_span() {
    let _m = normal();

    let document = json!({
        "host": {
            "hostname": HOSTILE, "user": HOSTILE, "os": HOSTILE, "arch": HOSTILE,
            "capabilities": { "deploy": true, "reasons": [HOSTILE] },
        },
        "fleet_name": HOSTILE,
        "discovery": { "code": "permission_denied", "detail": HOSTILE, "visible_peers": 3 },
        "devices": [{
            "name": HOSTILE,
            "machine": HOSTILE,
            "suggested_machine": HOSTILE,
            "os": HOSTILE,
            "address": HOSTILE,
            "online": false,
            "last_seen": HOSTILE,
            "path": HOSTILE,
            "last_probe": HOSTILE,
            "connected": false,
            "state": HOSTILE,
            "name_conflicts_with_roster": HOSTILE,
        }],
        "operations": [{
            "operation": HOSTILE,
            "kind": HOSTILE,
            "state": HOSTILE,
            "created_at": HOSTILE,
            "updated_at": HOSTILE,
            "running": true,
            "readable": true,
            "target": { "machine": HOSTILE, "address": HOSTILE },
            "last_error": { "reason": HOSTILE, "detail": HOSTILE },
        }],
        "unknown": [HOSTILE],
    });

    let mut a = with_inventory(document);
    let _ = drained(&mut a);
    a.apply(key(KeyCode::Enter));
    let _ = screen(&mut a);

    for span in spans(&a) {
        assert!(
            forbidden(&span).is_none(),
            "a peer string reached a Line carrying {:?}: {span:?}",
            forbidden(&span).unwrap()
        );
    }

    // And no row of this build's own was forged: the hostile string carries a whole
    // plausible device row, and it must never be a line of its own.
    let joined = joined_lines(&a);
    assert!(
        !joined
            .lines()
            .any(|line| line.trim_start().starts_with("studio  macOS")),
        "a peer forged a row of its own:\n{joined}"
    );
}

/// Ten thousand characters, East Asian width, combining marks and an emoji ZWJ sequence,
/// against the row's 140-column budget. Nothing may move a column boundary.
///
/// Measured on the spans rather than on the drawn frame: `TestBackend` writes a wide
/// grapheme into one cell and a *space* into its continuation cell, so the joined row
/// string over-counts a CJK name by one column per ideograph. The spans are what this
/// build composes, and the cells they become are the terminal's arithmetic, not this
/// client's.
///
/// This one passes. It is kept as the proof that §2 of the brief was actually run.
#[test]
fn k5_5b_a_wide_name_cannot_move_the_column_after_it() {
    use unicode_width::UnicodeWidthStr;

    let _m = normal();

    let names = [
        "x".repeat(10_000),
        "\u{5bb6}".repeat(400),
        format!("e{}", "\u{301}".repeat(2_000)),
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}".repeat(50),
    ];

    for name in names {
        let mut a = with_inventory(reply(
            vec![
                row(&name, "100.64.0.1", "discovered_installation_unknown"),
                row("sentinel", "100.64.0.2", "discovered_installation_unknown"),
            ],
            json!([]),
            host(true, &[]),
        ));
        let _ = drained(&mut a);
        let _ = screen(&mut a);

        // Every cell of a device row, as a width: the command is the last one and is
        // allowed to differ, everything before it is a boundary this build drew.
        let cells: Vec<Vec<usize>> = ouro::ui::app::devices_lines(&a)
            .iter()
            .filter(|line| {
                let joined: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                joined.contains("ouro fleet add") && !joined.contains("Not listed?")
            })
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
                    .collect()
            })
            .collect();

        assert_eq!(cells.len(), 2, "one of the two rows vanished");
        assert_eq!(
            cells[0][..cells[0].len() - 1],
            cells[1][..cells[1].len() - 1],
            "a {}-character name moved the columns after it: {cells:?}",
            name.chars().count()
        );
    }
}
