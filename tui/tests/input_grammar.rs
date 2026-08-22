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

use ouro::model::{Attachment, AttachmentKind, Plane};
use ouro::proto::{ErrorCode, Hello, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Call, ClipboardOutcome, ComposerVerb, Msg, Tag};

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
    opened_with(full_hello(), status, capabilities, events)
}

/// The same, on a gateway that also serves `extra` — for the verbs another slice is adding
/// to the runtime right now and which this client gates on `hello.methods`.
fn opened_serving(status: &str, capabilities: Value, extra: &[&str]) -> App {
    let mut hello = full_hello();
    for method in extra {
        hello.methods.push((*method).to_string());
    }

    opened_with(hello, status, capabilities, Vec::new())
}

fn opened_with(hello: Hello, status: &str, capabilities: Value, events: Vec<Value>) -> App {
    let mut app = app(hello);
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
            .map(|queued| queued.input.prompt())
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
            .map(|queued| queued.input.prompt())
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

// ---------------------------------------------------------------------------------------
// (b) B4 — structured input
// ---------------------------------------------------------------------------------------

/// Fills the workspace index so `@` completes against something.
fn with_files(app: &mut App, files: &[&str]) {
    app.apply(Msg::WorkspaceFiles(
        files.iter().map(|path| (*path).to_string()).collect(),
    ));
}

/// Completes `@<query>` with Tab.
fn mention(app: &mut App, query: &str) {
    compose(app);
    type_text(app, &format!("@{query}"));
    app.apply(key(KeyCode::Tab));
}

fn chips(app: &App) -> Vec<Attachment> {
    app.sessions
        .composer
        .as_ref()
        .map(|composer| composer.attachments.clone())
        .unwrap_or_default()
}

/// An `@path` is text *and* a structured attachment. Before B4 it was only text.
#[test]
fn an_at_mention_becomes_an_attachment_chip_as_well_as_text() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["src/ui/app/session.rs", "docs/TUI.md"]);

    mention(&mut app, "session.rs");

    assert_eq!(chips(&app).len(), 1, "one chip for one completed path");
    assert_eq!(chips(&app)[0].path, "src/ui/app/session.rs");
    assert!(
        draft(&app).contains("@src/ui/app/session.rs"),
        "the sentence the operator wrote still reads the way they wrote it: {}",
        draft(&app)
    );
    assert!(
        screen(&mut app).text().contains("@session.rs"),
        "the chip is drawn above the composer"
    );
}

/// The wire test: the gateway's object form, exactly as `structured_turn_input` accepts it.
#[test]
fn a_turn_with_an_attachment_is_sent_as_the_gateways_object_form() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["src/ui/app/session.rs"]);

    mention(&mut app, "session.rs");
    type_text(&mut app, "please read this");
    app.apply(key(KeyCode::Enter));

    let calls = turn_calls(&app.drain());
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "interactive.send_message");

    let input = &calls[0].1["input"];
    assert!(
        input.is_object(),
        "the object form, not a bare string: {input}"
    );
    assert_eq!(
        input["prompt"], "@src/ui/app/session.rs please read this",
        "{input}"
    );
    assert_eq!(input["attachments"], json!(["src/ui/app/session.rs"]));
    assert!(
        input.get("reasoning_effort").is_none(),
        "an absent effort is an absent key, never a null: {input}"
    );
}

/// And the other half of the same rule: a plain prompt is still a bare string, byte for
/// byte what this client sent before B4 existed.
#[test]
fn a_plain_prompt_is_still_a_bare_string_on_the_wire() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    let calls = turn_calls(&send(&mut app, "just words"));
    assert_eq!(calls[0].1["input"], json!("just words"));
}

/// `/effort` is per turn, and it puts `reasoning_effort` in the same object.
#[test]
fn effort_is_carried_on_the_next_turn_only() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/effort high");
    app.apply(key(KeyCode::Enter));
    assert!(
        turn_calls(&app.drain()).is_empty(),
        "a slash command is not a turn"
    );

    type_text(&mut app, "think hard about this");
    app.apply(key(KeyCode::Enter));

    let calls = turn_calls(&app.drain());
    assert_eq!(calls[0].1["input"]["prompt"], "think hard about this");
    assert_eq!(calls[0].1["input"]["reasoning_effort"], "high");

    assert!(
        app.sessions
            .composer
            .as_ref()
            .and_then(|composer| composer.reasoning_effort)
            .is_none(),
        "the dial is cleared after the send: it is per turn, not a mode"
    );
}

/// A value the gateway's enum does not contain is refused here rather than as a `-32602`.
#[test]
fn an_effort_the_gateway_does_not_take_is_refused_by_name() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/effort xhigh");
    app.apply(key(KeyCode::Enter));

    assert!(app
        .sessions
        .composer
        .as_ref()
        .and_then(|composer| composer.reasoning_effort)
        .is_none());
    let text = screen(&mut app).text();
    assert!(text.contains("low, medium, and high"), "{text}");
}

/// Backspace at the chip — on an empty draft the caret sits immediately after it.
#[test]
fn backspace_on_an_empty_draft_removes_the_newest_chip() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["a.rs", "b.rs"]);

    mention(&mut app, "a.rs");
    mention(&mut app, "b.rs");
    assert_eq!(chips(&app).len(), 2);

    // With text in the draft, Backspace is still Backspace.
    app.apply(key(KeyCode::Backspace));
    assert_eq!(chips(&app).len(), 2, "the draft was not empty");

    if let Some(composer) = app.sessions.composer.as_mut() {
        composer.editor.clear_text();
    }

    app.apply(key(KeyCode::Backspace));
    assert_eq!(
        chips(&app).len(),
        1,
        "the newest came off, the older stayed"
    );
    assert_eq!(chips(&app)[0].path, "a.rs");
}

/// D14: a transport whose `multimodal` is false gets the text substitution it always had,
/// and is told why there is no chip.
#[test]
fn a_transport_that_takes_no_attachments_keeps_the_text_and_says_so() {
    let mut app = opened("idle", managed_capabilities(), Vec::new());
    with_files(&mut app, &["src/main.rs"]);

    mention(&mut app, "main.rs");

    assert!(
        chips(&app).is_empty(),
        "no chip on a transport that declared multimodal: false"
    );
    assert!(draft(&app).contains("@src/main.rs"), "{}", draft(&app));

    let text = screen(&mut app).text();
    assert!(text.contains("takes no attachments"), "{text}");

    type_text(&mut app, "look at it");
    app.apply(key(KeyCode::Enter));
    let calls = turn_calls(&app.drain());
    assert!(
        calls[0].1["input"].is_string(),
        "and the wire stays a bare string: {}",
        calls[0].1["input"]
    );
}

/// The runtime canonicalises attachments against the session workspace and refuses an
/// outsider. That refusal belongs beside the chips that caused it.
#[test]
fn an_attachment_refused_by_the_runtime_is_rendered_on_the_composer() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["../outside.rs"]);

    mention(&mut app, "outside.rs");
    type_text(&mut app, "read it");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("a dispatched turn");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "attachment_outside_workspace: ../outside.rs".into(),
            data: None,
        })),
    });

    assert!(
        app.sessions
            .composer
            .as_ref()
            .and_then(|composer| composer.attachment_refusal.clone())
            .is_some_and(|refusal| refusal.contains("attachment_outside_workspace")),
        "the refusal is kept on the composer"
    );
    assert!(screen(&mut app)
        .text()
        .contains("attachment_outside_workspace"));
}

/// `Ctrl+V` asks the driver for the clipboard, naming the session's workspace — because an
/// attachment has to live inside it for `authorize_turn_attachments` to accept the turn.
#[test]
fn ctrl_v_asks_the_driver_to_read_the_clipboard_into_the_session_workspace() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);

    app.apply(modified(KeyCode::Char('v'), KeyModifiers::CONTROL));

    let request = app
        .take_clipboard_request()
        .expect("ctrl+v asks for a clipboard read");
    assert_eq!(request.workspace, "/Users/operator/code/ouroboros");
    assert!(!request.id.is_empty(), "the file is named by this client");
}

/// A written image becomes a chip; a clipboard holding text falls through to a paste.
#[test]
fn a_pasted_image_becomes_a_chip_and_text_falls_through_to_an_ordinary_paste() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);

    app.apply(Msg::Clipboard(ClipboardOutcome::Image(
        ".ouroboros/images/image-01ARZ3.png".into(),
    )));

    assert_eq!(chips(&app).len(), 1);
    assert_eq!(chips(&app)[0].path, ".ouroboros/images/image-01ARZ3.png");
    assert_eq!(chips(&app)[0].kind, AttachmentKind::Image);

    app.apply(Msg::Clipboard(ClipboardOutcome::Text(
        "pasted words".into(),
    )));
    assert_eq!(
        draft(&app),
        "pasted words",
        "a clipboard with no image is an ordinary paste"
    );
}

/// A machine with no clipboard tool is told once, not on every keystroke.
#[test]
fn a_machine_with_no_clipboard_tool_is_told_once() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);

    app.apply(Msg::Clipboard(ClipboardOutcome::NoTool));
    assert!(screen(&mut app).text().contains("no clipboard tool"));

    app.notice = None;
    app.apply(Msg::Clipboard(ClipboardOutcome::NoTool));
    assert!(!screen(&mut app).text().contains("no clipboard tool"));
}

/// D14 again: `Ctrl+V` on a transport that takes no images says so instead of writing a
/// file the runtime would refuse.
#[test]
fn ctrl_v_is_refused_by_transport_name_where_multimodal_is_false() {
    let mut app = opened("idle", managed_capabilities(), Vec::new());
    compose(&mut app);

    app.apply(modified(KeyCode::Char('v'), KeyModifiers::CONTROL));

    assert!(app.take_clipboard_request().is_none());
    let text = screen(&mut app).text();
    assert!(text.contains("managed takes no images"), "{text}");
}

/// `/model` is `interactive.configure`, gated on `hello.methods` like every other verb.
#[test]
fn model_answers_locally_when_the_gateway_does_not_serve_interactive_configure() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/model gpt-5-codex-high");
    app.apply(key(KeyCode::Enter));

    assert!(
        app.drain()
            .iter()
            .all(|call| call.method != "interactive.configure"),
        "nothing is sent to a gateway that does not serve it"
    );
    let text = screen(&mut app).text();
    assert!(
        text.contains("does not serve interactive.configure"),
        "the refusal names the method that is missing: {text}"
    );
}

/// And where it is served, the call goes out with the model the operator named.
#[test]
fn model_calls_interactive_configure_where_the_gateway_serves_it() {
    let mut app = opened_serving("idle", steering_capabilities(), &["interactive.configure"]);

    compose(&mut app);
    type_text(&mut app, "/model gpt-5-codex-high");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.configure")
        .expect("configure is issued");
    assert_eq!(call.params["id"], "session-b3");
    assert_eq!(call.params["model"], "gpt-5-codex-high");
}

/// A queued draft keeps its chips: a same-id replay that dropped them would present a
/// different fingerprint and come back `:turn_id_conflict`.
#[test]
fn a_queued_draft_carries_its_attachments_all_the_way_to_the_wire() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["src/lib.rs"]);

    let first = send(&mut app, "the first turn");
    let tag = first
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the first turn")
        .tag;

    mention(&mut app, "lib.rs");
    type_text(&mut app, "and this file");
    app.apply(key(KeyCode::Enter));

    assert_eq!(app.sessions.open_queued_drafts().len(), 1);
    assert_eq!(
        app.sessions.open_queued_drafts()[0].input.attachments.len(),
        1
    );

    answer(&mut app, tag, json!({ "status": "accepted" }));

    let released = turn_calls(&app.drain());
    assert_eq!(released[0].0, "interactive.follow_up");
    assert_eq!(released[0].1["input"]["attachments"], json!(["src/lib.rs"]));
}
