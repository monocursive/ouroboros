//! The input grammar the 2026 leaders converged on: a visible queue and a separate steer
//! key (B3), structured `@` attachments and image paste (B4), Esc / Esc-Esc (B5), and the
//! discoverability that keeps all of it findable (B9).
//!
//! Every session payload here is shaped like `Interactive.State.public/1`, capability map
//! included, because the whole slice is capability-driven: a verb this client offers on a
//! transport that answers `{:error, :unsupported}` is the failure D14 names, and the tests
//! below name the key *and* the capability for exactly that reason.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::Plane;
use ouro::ui::app::{App, Call, ComposerVerb, Msg, Tag};

use support::{app, full_hello, render, Screen};

// ---------------------------------------------------------------------------------------
// scaffolding
// ---------------------------------------------------------------------------------------

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn modified(code: KeyCode, modifiers: KeyModifiers) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn type_text(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

/// Codex app-server: the one transport in the bundle that can both steer and take images.
fn steering_capabilities() -> Value {
    json!({
        "transport": "app_server",
        "process": "persistent",
        "multi_turn": "native",
        "follow_up": "native",
        "interrupt": "native",
        "approvals": "native",
        "steer": "native",
        "multimodal": "native",
        "dynamic_model": "native",
        "dynamic_configuration": "native"
    })
}

/// A managed transport — `claude`, `gemini`, `amp`, `grok`, `zai`. One process per turn,
/// no approvals channel, no steer, no images.
fn managed_capabilities() -> Value {
    json!({
        "transport": "managed",
        "process": "per_turn",
        "multi_turn": "managed",
        "follow_up": "managed",
        "interrupt": "process",
        "approvals": false,
        "steer": false,
        "multimodal": false,
        "dynamic_model": "managed",
        "dynamic_configuration": "managed"
    })
}

fn session(status: &str, capabilities: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-b3",
        "status": status,
        "provider": "codex",
        "workspace": "/Users/operator/code/ouroboros",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "options": {
            "approval_mode": "auto_edit",
            "sandbox_mode": "workspace_write",
            "model": "gpt-5-codex",
            "capabilities": capabilities,
        },
    })
}

fn event(sequence: u64, kind: &str, payload: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "payload": payload,
        "turn_id": "turn-1",
        "request_id": Value::Null,
        "provider": "codex"
    })
}

/// An App with one open interactive session, subscribed, holding `events`.
fn opened(status: &str, capabilities: Value, events: Vec<Value>) -> App {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([session(status, capabilities)]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, "session-b3".into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");
    answer(&mut app, subscribe.tag, json!(events));

    app.apply(Msg::Tick);
    app
}

/// Opens the composer and leaves it open, the way `i` does.
fn compose(app: &mut App) {
    if app.sessions.composer.is_none() {
        app.apply(key(KeyCode::Char('i')));
    }
    assert!(app.sessions.composer.is_some(), "`i` opens the composer");
}

/// Types `text` and presses Enter, returning whatever calls that produced.
fn send(app: &mut App, text: &str) -> Vec<Call> {
    compose(app);
    type_text(app, text);
    app.apply(key(KeyCode::Enter));
    app.drain()
}

fn turn_calls(calls: &[Call]) -> Vec<(String, Value)> {
    calls
        .iter()
        .filter(|call| {
            matches!(
                call.method.as_str(),
                "interactive.send_message" | "interactive.follow_up" | "interactive.steer"
            )
        })
        .map(|call| (call.method.clone(), call.params.clone()))
        .collect()
}

fn draft(app: &App) -> String {
    app.sessions
        .composer
        .as_ref()
        .map(|composer| composer.editor.text().to_string())
        .unwrap_or_default()
}

fn screen(app: &mut App) -> Screen {
    render(app, 180, 44)
}

// ---------------------------------------------------------------------------------------
// (a) B3 — the queue
// ---------------------------------------------------------------------------------------

/// The one-in-flight rule is still here; what changed is that it stopped being a refusal.
///
/// Before B3 a second Enter answered "the earlier request is still awaiting
/// acknowledgement; this draft remains unsent" and left the text in the editor. That
/// notice is gone: the draft is accepted, the editor is cleared, and the queue holds it.
#[test]
fn enter_while_a_send_is_unacknowledged_queues_the_draft_instead_of_refusing_it() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    let first = send(&mut app, "run the tests");
    assert_eq!(turn_calls(&first).len(), 1, "the first Enter is dispatched");

    // Nothing has answered it, so the one-in-flight rule is in force.
    let second = send(&mut app, "then update the docs");
    assert!(
        turn_calls(&second).is_empty(),
        "a second mutation must not go out while the first is unacknowledged"
    );

    assert_eq!(
        app.sessions
            .open_queued_drafts()
            .iter()
            .map(|queued| queued.input.as_str())
            .collect::<Vec<_>>(),
        vec!["then update the docs"]
    );
    assert_eq!(draft(&app), "", "the queued draft leaves the editor");
}

/// The queue is drawn above the composer, with the ordinal and a preview, and it says
/// which rows are the runtime's and which are only here.
#[test]
fn the_queue_panel_separates_what_is_durable_on_the_runtime_from_what_is_only_local() {
    let mut app = opened(
        "running",
        steering_capabilities(),
        vec![event(1, "queue_changed", json!({ "queued_turns": 2 }))],
    );

    send(&mut app, "run the tests");
    send(&mut app, "then update the docs");

    let screen = screen(&mut app);
    let text = screen.text();

    assert!(text.contains("QUEUE"), "{text}");
    assert!(
        screen.row("QUEUE").contains("2 durable"),
        "the runtime's own depth is stated: {}",
        screen.row("QUEUE")
    );
    assert!(
        screen.row("QUEUE").contains("1 here"),
        "and so is what this client is still holding: {}",
        screen.row("QUEUE")
    );
    assert!(
        screen.row("runtime").contains("the runtime is holding"),
        "the durable rows are a depth, never invented text: {}",
        screen.row("runtime")
    );
    assert!(
        screen.row("1. local").contains("then update the docs"),
        "a local row carries its ordinal and its text: {}",
        screen.row("1. local")
    );
}

/// Claude Code's rule: Up pulls the queue back into the editor.
#[test]
fn up_on_an_empty_draft_takes_the_newest_queued_draft_back() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    send(&mut app, "run the tests");
    send(&mut app, "then update the docs");
    send(&mut app, "and tag the release");

    assert_eq!(app.sessions.open_queued_drafts().len(), 2);

    compose(&mut app);
    app.apply(key(KeyCode::Up));

    assert_eq!(draft(&app), "and tag the release", "the newest comes back");
    assert_eq!(
        app.sessions
            .open_queued_drafts()
            .iter()
            .map(|queued| queued.input.as_str())
            .collect::<Vec<_>>(),
        vec!["then update the docs"]
    );

    // With the queue empty again, Up is prompt history exactly as it always was.
    app.apply(key(KeyCode::Up));
    app.apply(key(KeyCode::Up));
    assert_eq!(app.sessions.open_queued_drafts().len(), 1);
}

/// The queue drains itself: the acknowledgement that was blocking it is what releases it.
#[test]
fn a_queued_draft_is_dispatched_as_a_follow_up_when_the_acknowledgement_lands() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    let first = send(&mut app, "run the tests");
    let tag = first
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the first Enter is a send_message")
        .tag;

    send(&mut app, "then update the docs");
    assert_eq!(app.sessions.open_queued_drafts().len(), 1);

    answer(&mut app, tag, json!({ "status": "accepted" }));

    let released = turn_calls(&app.drain());
    assert_eq!(released.len(), 1, "the queue released exactly one draft");
    assert_eq!(released[0].0, "interactive.follow_up");
    assert_eq!(released[0].1["input"], "then update the docs");
    assert!(
        app.sessions.open_queued_drafts().is_empty(),
        "and stopped holding it"
    );
}

/// Claude Code #16905: Esc stopped working once queued messages existed. It must always
/// interrupt, and the queue must survive the interrupt.
#[test]
fn esc_interrupts_a_running_turn_and_keeps_the_queue() {
    let mut app = opened("running", steering_capabilities(), Vec::new());

    send(&mut app, "run the tests");
    send(&mut app, "then update the docs");
    assert_eq!(app.sessions.open_queued_drafts().len(), 1);

    compose(&mut app);
    app.apply(key(KeyCode::Esc));

    let interrupts = app
        .drain()
        .into_iter()
        .filter(|call| call.method == "interactive.interrupt")
        .count();
    assert_eq!(interrupts, 1, "esc interrupts even with a queue waiting");
    assert_eq!(
        app.sessions.open_queued_drafts().len(),
        1,
        "and the queue is still there afterwards"
    );
}

/// A local draft is bounded. Thirty-two is the gateway's own attachment ceiling reused as
/// a number that is obviously a bound.
#[test]
fn the_local_queue_is_bounded_and_says_so_rather_than_swallowing_the_draft() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    send(&mut app, "the dispatched one");

    for index in 0..ouro::ui::app::QUEUE_LIMIT {
        send(&mut app, &format!("queued {index}"));
    }

    assert_eq!(
        app.sessions.open_queued_drafts().len(),
        ouro::ui::app::QUEUE_LIMIT
    );

    send(&mut app, "one too many");
    assert_eq!(
        app.sessions.open_queued_drafts().len(),
        ouro::ui::app::QUEUE_LIMIT,
        "the queue does not grow past its bound"
    );
    assert_eq!(
        draft(&app),
        "one too many",
        "and the refused draft stays in the editor rather than vanishing"
    );
}

// ---------------------------------------------------------------------------------------
// (a) B3 — steer is a separate key, offered only where the transport declared it
// ---------------------------------------------------------------------------------------

/// X2/D14: `alt+enter` sends `interactive.steer` where `capabilities.steer` is truthy.
#[test]
fn alt_enter_sends_interactive_steer_where_the_capability_declares_it() {
    let mut app = opened("running", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "actually use the release profile");
    app.apply(modified(KeyCode::Enter, KeyModifiers::ALT));

    let calls = turn_calls(&app.drain());
    assert_eq!(calls.len(), 1, "alt+enter sent exactly one call");
    assert_eq!(calls[0].0, "interactive.steer");
    assert_eq!(calls[0].1["input"], "actually use the release profile");
    assert!(
        calls[0].1.get("turn_id").is_none(),
        "a steer has no durable request ledger, so it mints no idempotency key"
    );

    // The verb does not stick: the next bare Enter is still the queueing verb.
    assert_ne!(
        app.sessions.composer.as_ref().map(|composer| composer.verb),
        Some(ComposerVerb::Steer)
    );
}

/// Where the runtime declared `steer: false` there is no second verb, so the key keeps the
/// newline it inserted before this slice existed and nothing advertises a steer.
#[test]
fn alt_enter_stays_a_newline_where_the_transport_cannot_steer() {
    let mut app = opened("running", managed_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "first line");
    app.apply(modified(KeyCode::Enter, KeyModifiers::ALT));
    type_text(&mut app, "second line");

    assert_eq!(draft(&app), "first line\nsecond line");
    assert!(
        turn_calls(&app.drain()).is_empty(),
        "nothing was sent to a transport that cannot steer"
    );
}

/// The composer names the key on exactly the two conditions that make it work.
#[test]
fn the_composer_names_the_steer_key_only_where_the_capability_and_the_terminal_allow_it() {
    let mut app = opened("running", steering_capabilities(), Vec::new());
    compose(&mut app);

    app.keyboard_enhanced = false;
    assert!(
        !screen(&mut app).text().contains("alt+enter steers"),
        "a terminal that reports no modifier sends a bare Enter, so the key is not named"
    );

    app.keyboard_enhanced = true;
    assert!(
        screen(&mut app).text().contains("alt+enter steers"),
        "named where the transport can steer and the terminal can send the chord"
    );

    let mut managed = opened("running", managed_capabilities(), Vec::new());
    compose(&mut managed);
    managed.keyboard_enhanced = true;
    assert!(
        !screen(&mut managed).text().contains("alt+enter steers"),
        "never named on a transport whose steer capability is false"
    );
}

/// Enter on a busy session queues durably through `follow_up`, and the chrome says so
/// rather than calling it a send.
#[test]
fn the_composer_says_enter_queues_once_the_session_is_no_longer_idle() {
    let mut app = opened("running", steering_capabilities(), Vec::new());
    compose(&mut app);

    let text = screen(&mut app).text();
    assert!(text.contains("Enter queues"), "{text}");
}
