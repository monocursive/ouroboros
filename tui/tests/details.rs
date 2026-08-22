//! `/details` — the normalized event ledger, driven through the App the way a person does.
//!
//! The flat `{seq} {kind} {summary}` list is now one collapsible tree per event over the
//! whole wire object the client kept. These tests pin the three things that make it worth
//! the change: the envelope is reachable, an excerpted leaf can be completed through
//! `interactive.event_detail`, and a filter never hides a divider.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Tag};

use support::{full_hello, render};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

fn leader(app: &mut App, c: char) {
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(c)));
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn notify(app: &mut App, frame: serde_json::Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: frame["method"].as_str().expect("a method").to_string(),
        params: frame["params"].clone(),
    }));
}

fn event(sequence: u64, kind: &str, payload: serde_json::Value) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "interactive.event",
        "params": {
            "id": SESSION,
            "event": {
                "_struct": "Ouroboros.Interactive.Event",
                "id": format!("evt-{sequence}"),
                "session_id": SESSION,
                "sequence": sequence,
                "type": kind,
                "timestamp": "2026-01-01T00:00:00.000000Z",
                "turn_id": "turn-1",
                "payload": payload
            }
        }
    })
}

/// A session open on the ledger, with three events of different shapes in it.
fn ledger() -> App {
    let mut app = App::new(
        ouro::ui::app::Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        full_hello(),
        None,
    );

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
            "options": { "approval_mode": "prompt", "sandbox_mode": null },
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

    notify(
        &mut app,
        event(1, "input_accepted", json!({"text": "read the lexer"})),
    );
    notify(
        &mut app,
        event(
            2,
            "tool_call",
            json!({ "call_id": "c1", "name": "read", "input": { "path": "src/lex.rs" } }),
        ),
    );
    notify(
        &mut app,
        event(
            3,
            "file_change",
            json!({
                "path": "src/lex.rs",
                // `Gateway.Wire`'s byte-cap marker, as
                // `interactive_event_excerpt_notification.json` pins it.
                "diff": { "_excerpt": "--- a/src/lex.rs\n+++ b/src", "_bytes": 600 }
            }),
        ),
    );

    // ctrl+x d is the ledger.
    leader(&mut app, 'd');
    let _ = app.drain();

    app
}

#[test]
fn the_ledger_is_one_collapsed_row_per_event_until_a_row_is_opened() {
    let mut app = ledger();
    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("EVENT DETAILS"), "{}", screen.text());
    for kind in ["input_accepted", "tool_call", "file_change"] {
        assert!(
            screen.contains(kind),
            "{kind} is missing:\n{}",
            screen.text()
        );
    }
    assert!(
        !screen.contains("session_id"),
        "a collapsed event is one line, not its envelope:\n{}",
        screen.text()
    );

    // Down onto the tool call, then open it: the envelope the flat list never showed.
    app.apply(key(KeyCode::Char('j')));
    app.apply(key(KeyCode::Enter));

    let screen = render(&mut app, 120, 30);
    for label in ["session_id", "payload", "turn_id", "timestamp"] {
        assert!(
            screen.contains(label),
            "{label} is missing from the opened event:\n{}",
            screen.text()
        );
    }
    assert!(
        screen.contains("«Ouroboros.Interactive.Event»"),
        "the wire struct tag rides the event row, since the tree draws it on the root and \
         the root row is that one:\n{}",
        screen.text()
    );

    // And closed again.
    app.apply(key(KeyCode::Enter));
    let screen = render(&mut app, 120, 30);
    assert!(!screen.contains("session_id"), "{}", screen.text());
}

/// Moves the ledger cursor onto the node with this label, by pressing `j`.
fn seek(app: &mut App, label: &str) {
    for _ in 0..64 {
        let at = {
            let rows = app
                .details
                .rows(app.sessions.open_watch().expect("a watch"));
            matches!(
                rows.get(app.details.selected()),
                Some(ouro::ui::details::Row::Node { node, .. }) if node.label == label
            )
        };

        if at {
            return;
        }

        app.apply(key(KeyCode::Char('j')));
    }

    panic!("no {label} row within the ledger");
}

#[test]
fn an_excerpted_leaf_names_its_size_and_enter_fetches_the_event_whole() {
    let mut app = ledger();

    // The file_change is the last row; open it, then its payload.
    app.apply(key(KeyCode::Char('G')));
    app.apply(key(KeyCode::Enter));

    seek(&mut app, "payload");
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("(600 bytes) · enter fetches"),
        "an excerpted leaf names the whole size and what completes it:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("--- a/src/lex.rs"),
        "the prefix the gateway did send is shown:\n{}",
        screen.text()
    );

    seek(&mut app, "diff");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.event_detail")
        .expect("enter on an excerpt asks for the whole event");

    assert_eq!(call.params["id"], SESSION);
    assert_eq!(call.params["sequence"], 3);
    // `only_keys(params, ["id", "sequence", "node"])`. This session's owner is the node
    // this client is attached to, and a `node` naming the local machine would be a route
    // nobody needs — the same rule every other session verb follows.
    assert_eq!(call.params.as_object().expect("an object").len(), 2);
    assert!(call.params.get("node").is_none());
    assert!(matches!(call.tag, Tag::EventDetail { sequence: 3, .. }));

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!({
            "_struct": "Ouroboros.Interactive.Event",
            "id": "evt-3",
            "session_id": SESSION,
            "sequence": 3,
            "type": "file_change",
            "timestamp": "2026-01-01T00:00:00.000000Z",
            "turn_id": "turn-1",
            "payload": { "path": "src/lex.rs", "diff": "the whole six hundred bytes" }
        })),
    });

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("[whole]"),
        "the fetched event says it is no longer the capped copy:\n{}",
        screen.text()
    );
    assert!(
        screen.contains("the whole six hundred bytes"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.contains("enter fetches"),
        "the excerpt marker is gone once the leaf is whole:\n{}",
        screen.text()
    );
}

#[test]
fn the_filter_narrows_the_ledger_by_kind_and_esc_clears_it() {
    let mut app = ledger();

    app.apply(key(KeyCode::Char('/')));
    for character in "tool".chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("filter tool"), "{}", screen.text());
    assert!(screen.contains("tool_call"), "{}", screen.text());
    assert!(
        !screen.contains("input_accepted") && !screen.contains("file_change"),
        "{}",
        screen.text()
    );

    app.apply(key(KeyCode::Esc));
    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("input_accepted"), "{}", screen.text());
    assert!(screen.contains("file_change"), "{}", screen.text());

    // Nothing was sent to the runtime for any of it.
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.replay"));
}

#[test]
fn a_filter_that_matches_nothing_says_so_rather_than_drawing_an_empty_pane() {
    let mut app = ledger();

    app.apply(key(KeyCode::Char('/')));
    for character in "zzzz".chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("No retained event matches that filter"),
        "{}",
        screen.text()
    );
}

#[test]
fn the_ledger_gives_every_key_back_to_the_composer_once_the_draft_has_text() {
    let mut app = ledger();

    // `i` opens the composer and is not the ledger's key.
    app.apply(key(KeyCode::Char('i')));
    for character in "jkg/".chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("jkg/"),
        "a reader who started typing keeps every character:\n{}",
        screen.text()
    );
    assert!(!app.details.filtering);
}

#[test]
fn g_and_shift_g_jump_to_the_ends_of_the_ledger() {
    let mut app = ledger();

    app.apply(key(KeyCode::Char('G')));
    assert_eq!(app.details.selected(), 2);

    app.apply(key(KeyCode::Char('g')));
    assert_eq!(app.details.selected(), 0);
}
