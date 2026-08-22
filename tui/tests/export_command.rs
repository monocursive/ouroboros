//! `/export` and `/copy raw`.
//!
//! The App is a pure state machine, so what a test can pin here is the bytes it hands the
//! driver, the filename it asks for, and the sentence it says about how much of the session
//! is in the file. Writing that file is [`ouro::ui::run`]'s, and it is the same
//! owner-readable, refuse-to-overwrite create the prompt draft already uses.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Tag};
use ouro::ui::export;

use support::{app, full_hello};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn notify(app: &mut App, sequence: u64, kind: &str, payload: serde_json::Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: "interactive.event".to_string(),
        params: json!({
            "id": SESSION,
            "event": {
                "_struct": "Ouroboros.Interactive.Event",
                "id": format!("evt-{sequence}"),
                "session_id": SESSION,
                "sequence": sequence,
                "type": kind,
                "timestamp": "2026-01-01T00:00:00.000000Z",
                "payload": payload
            }
        }),
    }));
}

fn slash(app: &mut App, line: &str) {
    for c in line.chars() {
        app.apply(key(KeyCode::Char(c)));
    }

    app.apply(key(KeyCode::Enter));
}

/// One open session holding three events, one of which the gateway excerpted.
fn conversing() -> App {
    let mut app = app(full_hello());

    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "claude_code",
            "workspace": "/tmp/w",
            "status": "running",
            "options": { "approval_mode": "auto_edit", "sandbox_mode": null },
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, SESSION.to_string());

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");
    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!([])),
    });

    notify(&mut app, 1, "input_accepted", json!({ "text": "hello" }));
    notify(
        &mut app,
        2,
        "output_text_final",
        json!({ "text": "**bold** and `code`" }),
    );
    notify(
        &mut app,
        3,
        "file_change",
        json!({
            "path": "src/lex.rs",
            "diff": { "_excerpt": "--- a/src/lex.rs", "_bytes": 900 }
        }),
    );

    app.terminal_width = 100;
    app
}

/// Byte for byte, the three events this session holds. One JSON object per line, keys in
/// `serde_json`'s `BTreeMap` order, no header and no trailing summary — the file is the
/// events and nothing else.
const NDJSON: &str = concat!(
    r#"{"_struct":"Ouroboros.Interactive.Event","id":"evt-1","payload":{"text":"hello"},"#,
    r#""sequence":1,"session_id":"session-0000000000000000000001","#,
    r#""timestamp":"2026-01-01T00:00:00.000000Z","type":"input_accepted"}"#,
    "\n",
    r#"{"_struct":"Ouroboros.Interactive.Event","id":"evt-2","#,
    r#""payload":{"text":"**bold** and `code`"},"sequence":2,"#,
    r#""session_id":"session-0000000000000000000001","#,
    r#""timestamp":"2026-01-01T00:00:00.000000Z","type":"output_text_final"}"#,
    "\n",
    r#"{"_struct":"Ouroboros.Interactive.Event","id":"evt-3","#,
    r#""payload":{"diff":{"_bytes":900,"_excerpt":"--- a/src/lex.rs"},"path":"src/lex.rs"},"#,
    r#""sequence":3,"session_id":"session-0000000000000000000001","#,
    r#""timestamp":"2026-01-01T00:00:00.000000Z","type":"file_change"}"#,
    "\n",
);

#[test]
fn export_json_is_the_events_one_object_per_line_byte_for_byte() {
    let app = conversing();
    let watch = app.sessions.open_watch().expect("a watch");

    assert_eq!(export::events_ndjson(watch), NDJSON);

    // Deterministic: the same watch is the same bytes, twice.
    assert_eq!(export::events_ndjson(watch), export::events_ndjson(watch));
}

#[test]
fn export_json_keeps_the_wire_excerpt_marker_rather_than_the_prefix_alone() {
    let app = conversing();
    let ndjson = export::events_ndjson(app.sessions.open_watch().expect("a watch"));

    assert!(
        ndjson.contains(r#""_bytes":900"#) && ndjson.contains(r#""_excerpt":"--- a/src/lex.rs""#),
        "an export that rewrote the marker as its prefix would look whole and not be:\n{ndjson}"
    );
}

#[test]
fn slash_export_hands_the_driver_the_same_text_the_escape_hatches_carry() {
    let mut app = conversing();
    let expected = export::transcript(app.sessions.open_watch().expect("a watch"), 100);

    slash(&mut app, "/export");

    let request = app.take_export().expect("/export asks the driver to write");

    assert_eq!(request.contents, expected);
    assert_eq!(request.path, None, "no path was named, so the driver picks");
    assert_eq!(
        request.filename,
        "ouro-interactive-session-0000000000000000000001.txt"
    );
    assert!(
        request.extent.contains("3 event(s), sequences 1–3"),
        "the notice says how much of the session is in the file: {}",
        request.extent
    );

    // Draining hands it over: a second frame must not write it again.
    assert!(app.take_export().is_none());
}

#[test]
fn slash_export_json_hands_over_the_ndjson_under_its_own_extension() {
    let mut app = conversing();

    slash(&mut app, "/export --json");

    let request = app.take_export().expect("/export --json");

    assert_eq!(request.contents, NDJSON);
    assert_eq!(
        request.filename,
        "ouro-interactive-session-0000000000000000000001.ndjson"
    );
    assert!(
        request.extent.contains("exported the events"),
        "{}",
        request.extent
    );
}

#[test]
fn a_named_path_is_used_as_given_and_two_of_them_are_refused() {
    let mut app = conversing();

    slash(&mut app, "/export --json /tmp/somewhere.ndjson");

    let request = app.take_export().expect("a named path");
    assert_eq!(request.path.as_deref(), Some("/tmp/somewhere.ndjson"));
    assert_eq!(request.contents, NDJSON);

    slash(&mut app, "/export one two");
    assert!(
        app.take_export().is_none(),
        "two paths is a mistake worth naming, not a file written somewhere"
    );
}

#[test]
fn exporting_without_an_open_session_writes_nothing() {
    let mut app = app(full_hello());

    // Through the palette, which is the other way to reach it and the one that works with
    // no composer on screen.
    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::Char('p'),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));
    for c in "Export the transcript".chars() {
        app.apply(key(KeyCode::Char(c)));
    }
    app.apply(key(KeyCode::Enter));

    assert!(
        app.take_export().is_none(),
        "an export of no session would be a file that said nothing happened"
    );
}

#[test]
fn copy_raw_copies_the_last_agent_message_as_the_provider_sent_it() {
    let mut app = conversing();

    slash(&mut app, "/copy raw");

    assert_eq!(
        app.take_copy().as_deref(),
        Some("**bold** and `code`"),
        "the source Markdown, not a rendering of it"
    );

    // And the plain verb still copies the last agent message.
    slash(&mut app, "/copy");
    assert_eq!(app.take_copy().as_deref(), Some("**bold** and `code`"));
}
