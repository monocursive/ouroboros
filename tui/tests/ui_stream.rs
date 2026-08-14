//! The UI driven against a scripted gateway, over a real socket.
//!
//! These are the transitions no pure render test can pin, because they involve the
//! transport: a subscription that becomes a live tail, a connection that drops and takes
//! the subscription with it, a lag that is repaired by replaying from the contiguous
//! cursor, a cursor the runtime no longer retains, and a stream that ends. All five reach
//! the same reconciliation in `App`, which is the point of doing it this way rather than
//! by calling four different methods.

mod support;

use std::time::Duration;

use serde_json::json;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, NewField, Overlay};

use support::{config, listener, Harness, Peer};

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: KeyEventState::NONE,
    })
}

fn press(c: char) -> Msg {
    key(KeyCode::Char(c))
}

fn enter() -> Msg {
    key(KeyCode::Enter)
}

/// Moves the new-session form to a named row rather than counting keystrokes.
fn focus(app: &mut App, target: NewField) {
    for _ in 0..12 {
        let current = match &app.overlay {
            Some(Overlay::New(dialog)) => Some(dialog.field),
            _ => None,
        };

        if current == Some(target) {
            return;
        }

        app.apply(key(KeyCode::Down));
    }

    panic!("the form never reached {target:?}");
}

const SESSION: &str = "session-1";

const METHODS: &[&str] = &[
    "hello",
    "runtime.status",
    "runtime.providers",
    "interactive.list",
    "coding.list",
    "interactive.replay",
    "interactive.start",
    "interactive.send_message",
    "interactive.subscribe",
    "interactive.unsubscribe",
];

fn event(sequence: u64, text: &str) -> serde_json::Value {
    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "session_id": SESSION,
        "sequence": sequence,
        "type": "output_text_final",
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "payload": { "text": text }
    })
}

fn events(range: std::ops::RangeInclusive<u64>) -> serde_json::Value {
    serde_json::Value::Array(
        range
            .map(|sequence| event(sequence, &format!("line {sequence}")))
            .collect(),
    )
}

#[tokio::test]
async fn opening_a_session_subscribes_and_then_tails_it_live() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let subscribe = peer.request_for("interactive.subscribe").await;

        assert_eq!(subscribe["params"]["id"], SESSION);
        assert_eq!(
            subscribe["params"]["cursor"], 0,
            "a first open starts at the beginning of what the session retains"
        );

        peer.result(&subscribe["id"], events(1..=2)).await;

        // The live tail follows the backlog with no gap between them: the plane registers
        // the subscriber before answering, so the two cannot interleave.
        peer.notify(
            "interactive.event",
            json!({ "id": SESSION, "event": event(3, "live") }),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let mut harness = Harness::connect(config(address), None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 3)
                .unwrap_or(false)
        })
        .await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(watch.cursor(), 3);
    assert_eq!(watch.len(), 3);
    assert!(!watch.has_gap());

    let screen = harness.screen(110, 24);

    assert!(screen.contains("line 1"), "{}", screen.text());
    assert!(screen.contains("line 2"));
    assert!(screen.contains("live"));

    script.abort();
}

#[tokio::test]
async fn starting_a_session_subscribes_to_it_and_the_first_event_lands_in_the_transcript() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let providers = peer.request_for("runtime.providers").await;
        peer.result(
            &providers["id"],
            json!([{
                "provider": "ouroboros_test",
                "spec": {},
                "status": { "installed": true, "compatible": true, "authenticated": true },
                "error": null
            }]),
        )
        .await;

        let start = peer.request_for("interactive.start").await;

        // Exactly the allowlisted options, and no `id` — the plane mints that.
        assert_eq!(start["params"]["provider"], "ouroboros_test");
        assert_eq!(start["params"]["workspace"], "/srv/work");
        assert_eq!(
            start["params"].as_object().expect("an object").len(),
            2,
            "an option outside @start_options is -32602 naming it: {}",
            start["params"]
        );

        peer.result(
            &start["id"],
            json!({
                "_struct": "Ouroboros.Interactive.Ref",
                "id": SESSION,
                "node": "nonode@nohost"
            }),
        )
        .await;

        // The client watches what it just created, from the beginning of its history.
        let subscribe = peer.request_for("interactive.subscribe").await;

        assert_eq!(subscribe["params"]["id"], SESSION);
        assert_eq!(subscribe["params"]["cursor"], 0);

        peer.result(&subscribe["id"], json!([])).await;

        peer.notify(
            "interactive.event",
            json!({ "id": SESSION, "event": event(1, "session ready") }),
        )
        .await;

        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let mut harness = Harness::connect(config(address), None).await;
    harness.app.launch_dir = Some("/srv/work".into());

    // The whole flow from a keystroke: `2` to the Sessions tab, `n` for the form, then
    // straight to start with the defaults the form offered.
    harness.app.apply(press('2'));
    harness.app.apply(press('n'));
    harness.settle().await;

    focus(&mut harness.app, NewField::Start);
    harness.app.apply(enter());

    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 1)
                .unwrap_or(false)
        })
        .await;

    assert_eq!(
        harness.app.sessions.open,
        Some((Plane::Interactive, SESSION.into()))
    );

    let screen = harness.screen(110, 26);

    assert!(screen.contains("session ready"), "{}", screen.text());
    // The composer is open, so the first message is the next thing typed.
    assert!(screen.contains("Enter sends"), "{}", screen.text());

    script.abort();
}

#[tokio::test]
async fn a_reconnect_resubscribes_every_watched_session_at_its_cursor() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&server).await;
        first.hello(METHODS).await;

        let subscribe = first.request_for("interactive.subscribe").await;
        first.result(&subscribe["id"], events(1..=2)).await;

        // The socket dies with the subscription on it.
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(first);

        let mut second = Peer::accept(&server).await;
        second.hello(METHODS).await;

        let resubscribe = second.request_for("interactive.subscribe").await;

        assert_eq!(
            resubscribe["params"]["cursor"], 2,
            "the reconnect hook has to resume where the transcript stopped"
        );

        second.result(&resubscribe["id"], events(3..=4)).await;

        tokio::time::sleep(Duration::from_millis(600)).await;
    });

    let mut config = config(address);
    config.reconnect = true;
    config.backoff.initial = Duration::from_millis(20);
    config.backoff.max = Duration::from_millis(60);

    let mut harness = Harness::connect(config, None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 4)
                .unwrap_or(false)
        })
        .await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(watch.cursor(), 4, "the backlog reconciled without a hole");
    assert_eq!(watch.len(), 4);
    assert!(!watch.has_gap());

    let screen = harness.screen(110, 24);

    // The interruption is recorded rather than smoothed over.
    assert!(screen.contains("Connection restored"), "{}", screen.text());
    assert!(screen.contains("line 4"), "{}", screen.text());

    script.abort();
}

#[tokio::test]
async fn a_lag_replays_from_the_contiguous_cursor_and_fills_the_hole() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let subscribe = peer.request_for("interactive.subscribe").await;
        peer.result(&subscribe["id"], events(1..=2)).await;

        // Backpressure: the gateway discarded 3..6 and says so.
        peer.notify(
            "stream.lagged",
            json!({
                "id": SESSION,
                "plane": "interactive",
                "dropped": 4,
                "last_sequence": 6
            }),
        )
        .await;

        let replay = peer.request_for("interactive.replay").await;

        assert_eq!(
            replay["params"]["cursor"], 2,
            "the repair resumes at the contiguous prefix, not the newest event"
        );
        assert_eq!(replay["params"]["limit"], 500);

        // A live event past the hole, arriving while the replay is in flight.
        peer.notify(
            "interactive.event",
            json!({ "id": SESSION, "event": event(7, "after the hole") }),
        )
        .await;

        peer.result(&replay["id"], events(3..=6)).await;

        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let mut harness = Harness::connect(config(address), None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 7)
                .unwrap_or(false)
        })
        .await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(
        watch.cursor(),
        7,
        "reconciliation is exact, not approximate"
    );
    assert_eq!(watch.len(), 7);
    assert!(!watch.has_gap());
    assert_eq!(watch.dropped, 4);
    assert_eq!(
        watch.floor(),
        0,
        "nothing was pruned, so nothing is truncated"
    );

    let screen = harness.screen(110, 30);

    assert!(
        screen.contains("Some live updates were missed by the gateway"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.contains("events missing"),
        "the hole was filled, so it must stop being drawn:\n{}",
        screen.text()
    );

    script.abort();
}

#[tokio::test]
async fn a_pruned_cursor_restarts_from_the_floor_through_the_same_path() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let subscribe = peer.request_for("interactive.subscribe").await;

        // The exact shape `error_cursor_pruned.json` pins.
        peer.error(
            &subscribe["id"],
            -32006,
            "the session no longer retains events at or below that cursor; replay from 96",
            Some(json!({ "reason": "cursor_pruned", "floor": 96 })),
        )
        .await;

        let retry = peer.request_for("interactive.subscribe").await;

        assert_eq!(
            retry["params"]["cursor"], 96,
            "a pruned cursor restarts at the floor the gateway named"
        );

        peer.result(&retry["id"], events(97..=98)).await;

        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let mut harness = Harness::connect(config(address), None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 98)
                .unwrap_or(false)
        })
        .await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(watch.floor(), 96);
    assert_eq!(watch.cursor(), 98);
    assert!(!watch.has_gap());

    let screen = harness.screen(110, 24);

    assert!(
        screen.contains("Earlier conversation is no longer available"),
        "a transcript that lost history has to say so:\n{}",
        screen.text()
    );
    assert!(screen.contains("line 97"), "{}", screen.text());

    script.abort();
}

#[tokio::test]
async fn stream_ended_stops_the_client_expecting_more() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let subscribe = peer.request_for("interactive.subscribe").await;
        peer.result(&subscribe["id"], events(1..=1)).await;

        peer.notify(
            "stream.ended",
            json!({ "id": SESSION, "plane": "interactive", "status": "closed" }),
        )
        .await;

        // Session-list polling is independent of this stream. Serve those ordinary tab
        // refreshes, but fail if the client subscribes to or replays the ended stream.
        while let Some(request) = peer.request().await {
            match request["method"].as_str() {
                Some("interactive.list" | "coding.list") => {
                    peer.result(&request["id"], json!([])).await
                }
                _ => panic!("a finished stream must not be asked about again: {request}"),
            }
        }
    });

    let mut harness = Harness::connect(config(address), None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.ended.is_some())
                .unwrap_or(false)
        })
        .await;

    // Twenty seconds of ticks against a finished session.
    for _ in 0..80 {
        harness.app.apply(Msg::Tick);
    }

    harness.settle().await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(watch.ended.as_deref(), Some("closed"));
    assert!(!watch.resyncing);

    let screen = harness.screen(110, 24);
    assert!(
        screen.contains("Session ended (closed)"),
        "{}",
        screen.text()
    );

    // The list polls the tab is due for are fine; asking about the stream again is not.
    script.abort();
}

#[tokio::test]
async fn a_notification_this_client_could_not_take_is_repaired_like_a_lag() {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(METHODS).await;

        let subscribe = peer.request_for("interactive.subscribe").await;
        peer.result(&subscribe["id"], events(1..=2)).await;

        let replay = peer.request_for("interactive.replay").await;

        assert_eq!(replay["params"]["cursor"], 2);
        peer.result(&replay["id"], events(3..=5)).await;

        tokio::time::sleep(Duration::from_millis(400)).await;
    });

    let mut harness = Harness::connect(config(address), None).await;

    harness.app.open_session(Plane::Interactive, SESSION.into());
    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 2)
                .unwrap_or(false)
        })
        .await;

    // The transport's own counter moved: frames arrived and the notification channel
    // could not take them. Which session lost them is unknowable, so every watched one is
    // replayed — the same repair, from the same cursor.
    harness.app.apply(Msg::NotificationsDropped(3));

    harness
        .settle_until(|app| {
            app.sessions
                .open_watch()
                .map(|watch| watch.cursor() == 5)
                .unwrap_or(false)
        })
        .await;

    let watch = harness.app.sessions.open_watch().expect("an open watch");

    assert_eq!(watch.cursor(), 5);
    assert_eq!(watch.dropped, 3);

    // The interruption is old enough to have scrolled above the compact chat viewport;
    // the complete ledger must retain it exactly.
    harness.app.apply(Msg::Key(crossterm::event::KeyEvent::new(
        crossterm::event::KeyCode::Char('e'),
        crossterm::event::KeyModifiers::CONTROL,
    )));
    let screen = harness.screen(110, 24);

    assert!(
        screen.contains("this client could not take some event frames here"),
        "a drop on this side is as much a hole as a drop on the gateway's:\n{}",
        screen.text()
    );

    script.abort();
}
