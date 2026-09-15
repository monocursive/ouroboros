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
use ouro::ui::app::{App, Call, ClipboardOutcome, ComposerVerb, Msg, Overlay, Tag};

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
        "provider": "native",
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
        "provider": "native"
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

/// The same, on a gateway that does NOT serve `missing` — an older runtime. The golden
/// `hello` now lists every verb this checkout serves, so "not served" has to be stated
/// rather than relied on.
fn opened_without(status: &str, capabilities: Value, events: Vec<Value>, missing: &[&str]) -> App {
    let mut hello = full_hello();
    hello
        .methods
        .retain(|method| !missing.contains(&method.as_str()));

    opened_with(hello, status, capabilities, events)
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
    type_text(&mut app, "/effort unbounded");
    app.apply(key(KeyCode::Enter));

    assert!(app
        .sessions
        .composer
        .as_ref()
        .and_then(|composer| composer.reasoning_effort)
        .is_none());
    let text = screen(&mut app).text();
    assert!(
        text.contains("none, low, medium, high, xhigh, and max"),
        "{text}"
    );
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
    let mut app = opened_without(
        "idle",
        steering_capabilities(),
        Vec::new(),
        &["interactive.configure"],
    );

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

// ---------------------------------------------------------------------------------------
// (c) B5 — Esc, Esc Esc, and going back
// ---------------------------------------------------------------------------------------

/// An `input_accepted` event, which is the durable record the backtrack menu reads.
fn user_turn(sequence: u64, text: &str) -> Value {
    event(sequence, "input_accepted", json!({ "text": text }))
}

fn overlay_is_backtrack(app: &App) -> bool {
    matches!(app.overlay, Some(Overlay::Backtrack { .. }))
}

fn backtrack_entries(app: &App) -> Vec<String> {
    match &app.overlay {
        Some(Overlay::Backtrack { entries, .. }) => entries
            .iter()
            .map(|(_sequence, text)| text.clone())
            .collect(),
        _other => Vec::new(),
    }
}

/// Two Escapes inside the window open the menu; the first still does its ordinary job.
#[test]
fn esc_esc_within_the_window_opens_the_backtrack_menu() {
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing"), user_turn(2, "second thing")],
    );

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));

    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);
    assert_eq!(
        backtrack_entries(&app),
        vec!["first thing".to_string(), "second thing".to_string()]
    );
}

/// Outside the window they are two Escapes, which is what an operator who paused meant.
#[test]
fn two_escapes_outside_the_window_are_two_escapes() {
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );

    compose(&mut app);
    app.apply(key(KeyCode::Esc));

    for _ in 0..(ouro::ui::app::BACKTRACK_TICKS + 1) {
        app.apply(Msg::Tick);
    }

    app.apply(key(KeyCode::Esc));
    assert!(!overlay_is_backtrack(&app), "{:?}", app.overlay);
}

/// Claude Code #43717: the chord must be rebindable, and it must be possible to turn off.
#[test]
fn the_backtrack_chord_is_rebindable_and_can_be_disabled() {
    let mut off = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );
    off.config.keys.backtrack = Some("off".into());
    off.reload_keymap();
    compose(&mut off);
    off.apply(key(KeyCode::Esc));
    off.apply(key(KeyCode::Esc));
    assert!(!overlay_is_backtrack(&off), "esc esc is off");

    let mut alt = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );
    alt.config.keys.backtrack = Some("alt+up".into());
    alt.reload_keymap();
    compose(&mut alt);
    alt.apply(key(KeyCode::Esc));
    alt.apply(key(KeyCode::Esc));
    assert!(!overlay_is_backtrack(&alt), "esc esc is not the chord now");

    alt.apply(modified(KeyCode::Up, KeyModifiers::ALT));
    assert!(overlay_is_backtrack(&alt), "alt+up is");
}

/// A chord this build cannot read is reported and treated as unset, never as "off".
#[test]
fn an_unreadable_backtrack_chord_falls_back_to_the_default() {
    let config: ouro::config::Config =
        toml::from_str("[keys]\nbacktrack = \"ctrl+shift+meta+z\"\n").expect("parseable");
    assert_eq!(
        config.keys.backtrack(),
        ouro::config::Backtrack::EscEsc,
        "an unreadable chord is unset, and unset is the default"
    );
}

/// Esc interrupts a running turn, and the second Esc of the chord does not stop it doing
/// so — Claude Code #16905 is exactly the interrupt being disabled by other state.
#[test]
fn the_first_esc_of_the_chord_still_interrupts() {
    let mut app = opened(
        "running",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );

    compose(&mut app);
    app.apply(key(KeyCode::Esc));

    let interrupts = app
        .drain()
        .into_iter()
        .filter(|call| call.method == "interactive.interrupt")
        .count();
    assert_eq!(interrupts, 1);

    app.apply(key(KeyCode::Esc));
    assert!(overlay_is_backtrack(&app), "and the chord still completed");
}

/// Where `interactive.fork` is not served, Enter is "edit and resend" and the menu says so.
#[test]
fn enter_edits_and_resends_where_the_gateway_cannot_fork() {
    let mut app = opened_without(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing"), user_turn(2, "second thing")],
        &["interactive.fork"],
    );

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));

    let text = screen(&mut app).text();
    assert!(
        text.contains("enter edits and resends as a new turn"),
        "{text}"
    );
    assert!(!text.contains("enter forks"), "{text}");

    app.apply(key(KeyCode::Up));
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none());
    assert_eq!(draft(&app), "first thing");
    assert!(
        app.drain()
            .iter()
            .all(|call| call.method != "interactive.fork"),
        "nothing was forked"
    );
}

/// Where it is served, Enter forks — and the menu never promises where the branch starts,
/// because `interactive.fork` takes a session and no message.
#[test]
fn enter_forks_where_the_gateway_serves_it_without_promising_where_the_branch_starts() {
    let mut app = opened_serving("idle", steering_capabilities(), &["interactive.fork"]);
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: "interactive.event".into(),
        params: json!({ "id": "session-b3", "event": user_turn(1, "first thing") }),
    }));

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));
    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);

    let text = screen(&mut app).text();
    assert!(text.contains("enter forks"), "{text}");
    assert!(
        text.contains("where the branch starts is the transport's decision"),
        "the menu never promises more than the runtime declares: {text}"
    );

    app.apply(key(KeyCode::Enter));

    let fork = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.fork")
        .expect("the fork is issued");
    assert_eq!(fork.params["id"], "session-b3");
}

/// D14: a transport the runtime declared cannot fork is not offered the verb, even on a
/// gateway that serves the method.
#[test]
fn a_transport_declared_unable_to_fork_is_not_offered_it() {
    let mut capabilities = steering_capabilities();
    capabilities["fork"] = json!(false);

    let mut app = opened_serving("idle", capabilities, &["interactive.fork"]);
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: "interactive.event".into(),
        params: json!({ "id": "session-b3", "event": user_turn(1, "first thing") }),
    }));

    assert!(!app.fork_offered());

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));

    let text = screen(&mut app).text();
    assert!(!text.contains("enter forks"), "{text}");
}

/// The menu lists at most ten, newest last, and never a steer.
#[test]
fn the_menu_lists_the_last_ten_user_turns_and_no_steer() {
    let mut events: Vec<Value> = (1..=14)
        .map(|index| user_turn(index, &format!("turn {index}")))
        .collect();
    events.push(event(
        15,
        "input_accepted",
        json!({ "text": "a steer", "kind": "steer" }),
    ));

    let mut app = opened("idle", steering_capabilities(), events);

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));

    let entries = backtrack_entries(&app);
    assert_eq!(entries.len(), 10);
    assert_eq!(entries.first().map(String::as_str), Some("turn 5"));
    assert_eq!(entries.last().map(String::as_str), Some("turn 14"));
    assert!(!entries.iter().any(|entry| entry == "a steer"));
}

/// `Esc` on an idle session with an empty prompt still leaves the session, and the second
/// `Esc` brings it back with the menu open rather than punishing the operator for being
/// idle when they pressed the chord.
#[test]
fn the_chord_survives_the_first_esc_leaving_the_session() {
    // The agent answered: a turn still waiting for its first words is a *busy* session,
    // and Escape interrupts one of those rather than leaving it.
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![
            user_turn(1, "first thing"),
            event(2, "output_text_final", json!({ "text": "done" })),
        ],
    );

    compose(&mut app);
    app.apply(key(KeyCode::Esc));
    assert!(
        app.sessions.open.is_none(),
        "the first esc left the session"
    );

    app.apply(key(KeyCode::Esc));
    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);
    assert_eq!(
        app.sessions.open,
        Some((Plane::Interactive, "session-b3".to_string()))
    );
}

// ---------------------------------------------------------------------------------------
// (d) B9 — discoverability
// ---------------------------------------------------------------------------------------

/// The `?` panel is grouped by the question someone is asking when they open it, and its
/// honest limits are pinned rather than scrolled off the bottom.
#[test]
fn the_help_panel_is_grouped_and_keeps_its_limits_in_view() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    app.sessions.composer = None;
    app.apply(key(KeyCode::Char('?')));

    // F1. An ordinary terminal. The panel is longer than any one screen, so the table is
    // what the headings are checked against and the *frame* is checked for the marker that
    // says the rest of it is reachable — which is the bug this size used to hide.
    let screen = render(&mut app, 100, 30);
    let text = screen.text();

    assert!(
        text.contains("more rows"),
        "a panel that does not fit must say so, or the rest of it is unreachable:\n{text}"
    );

    // The five groups of the `ui-parity` plan, which the palette, the which-key overlay
    // and the web's shortcut sheet all use as well. Every one of them is on the page,
    // because `Action::group` puts every action in one of them.
    let rows = ouro::ui::view::help_keys(&app);
    let headings: Vec<&str> = rows
        .iter()
        .map(|(group, _key, _description)| *group)
        .collect();

    for heading in ["Session", "Turn", "Conversation", "Runtime", "Client"] {
        assert!(headings.contains(&heading), "missing {heading}: {headings:?}");
    }

    // The first of them is drawn as a heading on the frame itself.
    assert!(text.contains("SESSION"), "{text}");

    assert!(text.contains("one gateway view of the fleet"), "{text}");
    assert!(text.contains("not a sandbox"), "{text}");

    // The keys this slice added are on it, in the group they belong to.
    let keys: Vec<&str> = rows
        .iter()
        .flat_map(|(_group, key, _description)| key.split(" / "))
        .collect();

    for chord in ["alt+enter", "esc esc", "ctrl+v"] {
        assert!(keys.contains(&chord), "{chord} is not on the ? panel");
    }
}

/// It scrolls rather than silently ending, and it says how much is left.
#[test]
fn the_help_panel_scrolls_and_says_there_is_more() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    app.sessions.composer = None;
    app.apply(key(KeyCode::Char('?')));

    // A short terminal cannot show the whole table.
    let short = render(&mut app, 120, 20);
    assert!(short.text().contains("more row"), "{}", short.text());
    // …and the limits are still there, because they are pinned outside the scroll.
    assert!(short.text().contains("not a sandbox"), "{}", short.text());

    app.apply(key(KeyCode::Char('j')));
    assert_eq!(app.help_scroll, 1);

    // Reopening starts at the top rather than where the last reader left it.
    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Char('?')));
    assert_eq!(app.help_scroll, 0);
}

/// The footer points at that page until three prompts have been sent, and the count
/// persists.
#[test]
fn the_footer_says_new_here_until_three_prompts_have_been_sent() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    assert!(app.onboarding());

    let footer = |app: &mut App| {
        render(app, 180, 44)
            .rows
            .last()
            .cloned()
            .unwrap_or_default()
    };

    let row = footer(&mut app);
    assert!(row.contains("? new here"), "{row}");

    for index in 0..3 {
        let calls = send(&mut app, &format!("prompt {index}"));
        let tag = calls
            .into_iter()
            .find(|call| {
                matches!(
                    call.method.as_str(),
                    "interactive.send_message" | "interactive.follow_up"
                )
            })
            .expect("a dispatched turn")
            .tag;
        answer(&mut app, tag, json!({ "status": "accepted" }));
    }

    assert_eq!(app.config.onboarding.prompts_sent, 3);
    assert!(!app.onboarding());
    assert!(!footer(&mut app).contains("? new here"));
    assert!(
        app.take_config_save().is_some(),
        "the counter is written to config.toml rather than lost with the process"
    );
}

/// Home teaches the immediate task and leaves advanced controls in discoverable help.
#[test]
fn the_coding_home_prioritises_composition_and_keeps_help_discoverable() {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": { "email": "operator@example.com" }, "requiresOpenaiAuth": true }),
    );
    app.config.defaults.model = Some("openai_codex:gpt-5.6-sol".into());

    let text = screen(&mut app).text();
    assert!(text.contains("Understand this project"), "{text}");
    assert!(text.contains("/help  A quick guide"), "{text}");
    assert!(!text.contains("esc interrupts the turn"), "{text}");

    app.config.onboarding.prompts_sent = 3;
    let text = screen(&mut app).text();
    assert!(text.contains("/options to change"), "{text}");
}

/// `/fork` is the same call the menu makes, without the menu, and it is gated the same
/// way.
#[test]
fn slash_fork_issues_the_call_directly_and_is_gated_the_same_way() {
    let mut refused = opened_without(
        "idle",
        steering_capabilities(),
        Vec::new(),
        &["interactive.fork"],
    );
    compose(&mut refused);
    type_text(&mut refused, "/fork");
    refused.apply(key(KeyCode::Enter));
    assert!(
        refused
            .drain()
            .iter()
            .all(|call| call.method != "interactive.fork"),
        "nothing is sent to a gateway that does not serve it"
    );
    assert!(screen(&mut refused)
        .text()
        .contains("does not serve interactive.fork"));

    let mut app = opened_serving("idle", steering_capabilities(), &["interactive.fork"]);
    compose(&mut app);
    type_text(&mut app, "/fork");
    app.apply(key(KeyCode::Enter));

    let fork = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.fork")
        .expect("the fork is issued");
    assert_eq!(fork.params["id"], "session-b3");
}

/// `/clear` clears the whole draft, chips and effort included: they are part of what
/// would have been sent.
#[test]
fn clear_takes_the_chips_and_the_effort_with_the_words() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["src/lib.rs"]);

    compose(&mut app);
    type_text(&mut app, "/effort high");
    app.apply(key(KeyCode::Enter));

    mention(&mut app, "lib.rs");
    assert_eq!(chips(&app).len(), 1);

    // A slash command is only a command at the start of a line, so the mention's text has
    // to go before `/clear` can be one.
    if let Some(composer) = app.sessions.composer.as_mut() {
        composer.editor.clear_text();
    }

    type_text(&mut app, "/clear");
    app.apply(key(KeyCode::Enter));

    assert!(chips(&app).is_empty(), "the chips went with the words");
    assert!(app
        .sessions
        .composer
        .as_ref()
        .and_then(|composer| composer.reasoning_effort)
        .is_none());
    assert_eq!(draft(&app), "");
}

// ---------------------------------------------------------------------------------------
// (e) ui-parity T1 — the key layer
// ---------------------------------------------------------------------------------------

/// A resolved keymap with `[keys]` applied, for the rebinding halves below.
fn rebound(app: &mut App, pairs: &[(&str, &str)]) {
    for (name, spec) in pairs {
        app.config
            .keys
            .bindings
            .insert((*name).to_string(), toml::Value::String((*spec).to_string()));
    }

    app.reload_keymap();
}

/// `ctrl+x` and then a verb.
fn leader(app: &mut App, verb: char) {
    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char(verb)));
}

fn interrupts(app: &mut App) -> usize {
    app.drain()
        .into_iter()
        .filter(|call| call.method == "interactive.interrupt")
        .count()
}

// ----- T1.1: Enter accepts the highlighted completion ------------------------------------

/// Enter on an open menu selects, as it does in opencode, Claude Code and Codex. It used
/// to submit, so `/ba` went to the model as a turn (R1 §2.3).
#[test]
fn enter_accepts_the_highlighted_completion_rather_than_sending_the_stub() {
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );

    compose(&mut app);
    type_text(&mut app, "/backtr");
    assert!(
        app.sessions
            .composer
            .as_ref()
            .is_some_and(|composer| composer.editor.completion().is_some()),
        "the menu is open"
    );

    app.apply(key(KeyCode::Enter));

    assert_eq!(
        draft(&app),
        "/backtrack",
        "Enter completed the verb instead of sending the stub"
    );
    assert!(app.overlay.is_none(), "and nothing ran yet: {:?}", app.overlay);
    assert!(
        turn_calls(&app.drain()).is_empty(),
        "the stub reached the model"
    );

    // A verb that takes no argument ends where it ends; the next Enter runs it.
    app.apply(key(KeyCode::Enter));
    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);
}

/// A verb that takes the rest of the line is left waiting for it, caret after a space.
#[test]
fn accepting_a_verb_that_takes_an_argument_leaves_the_space_it_needs() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/expo");
    app.apply(key(KeyCode::Enter));

    assert_eq!(draft(&app), "/export ");
}

/// Tab still completes, which is the key everybody already has in their fingers.
#[test]
fn tab_still_completes() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/backtr");
    app.apply(key(KeyCode::Tab));

    assert_eq!(draft(&app), "/backtrack");
}

/// A verb typed out in full is sent, not completed again. Without this a finished `/keys`
/// would be answered with `/hotkeys`, which sorts first in its own menu, and every verb
/// anyone ever typed whole would cost a second Enter.
#[test]
fn a_verb_typed_in_full_is_sent_rather_than_completed_into_a_different_one() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/keys");
    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Keys { .. })),
        "{:?}",
        app.overlay
    );
    assert_eq!(draft(&app), "");
}

/// The other half of T1.1, in a session: an unknown verb is refused by name, the draft is
/// kept, and nothing is sent. It used to go to the model as a turn.
#[test]
fn an_unknown_verb_in_a_session_is_refused_and_the_draft_is_kept() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/keyq");
    app.apply(key(KeyCode::Enter));

    assert!(
        turn_calls(&app.drain()).is_empty(),
        "an unknown verb was sent to the model"
    );
    assert_eq!(draft(&app), "/keyq", "the draft was thrown away");

    let notice = app.notice.as_ref().expect("a refusal");
    assert!(
        notice.text.contains("unknown command /keyq"),
        "{}",
        notice.text
    );
    assert!(notice.text.contains("/keys"), "{}", notice.text);
}

// ----- T1.2: the ctrl+c state machine ----------------------------------------------------

/// Four steps, in order, and the fourth one is reachable with a session open — which it
/// was not: `ctrl+c` used to issue an interrupt for a turn that was not running and reset
/// the arm every time, so this client had no exit key somebody arriving from opencode,
/// Claude Code or Codex would find (R1 §2.4).
#[test]
fn ctrl_c_clears_then_interrupts_then_arms_and_the_second_press_quits() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    // (2) a draft with text in it is cleared, and the arm is not set by clearing.
    compose(&mut app);
    type_text(&mut app, "never mind");
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(draft(&app), "");
    assert!(!app.quit_armed());

    // (4) the empty, idle screen arms instead of interrupting nothing.
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(interrupts(&mut app), 0, "there was no turn to interrupt");
    assert!(app.quit_armed(), "the footer has nothing to show");
    assert!(app.overlay.is_none());

    // and the second press inside the window quits, with a session open.
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        matches!(app.overlay, Some(Overlay::Quit { .. })),
        "{:?}",
        app.overlay
    );
    assert!(!app.quit_armed());
}

/// Step three still comes first while there is a turn: `ctrl+c` interrupts and does not
/// arm, so nobody quits by pressing it twice at a busy agent.
#[test]
fn ctrl_c_on_a_running_turn_interrupts_rather_than_arming() {
    let mut app = opened("running", steering_capabilities(), Vec::new());

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert_eq!(interrupts(&mut app), 1);
    assert!(!app.quit_armed());
    assert!(app.overlay.is_none(), "{:?}", app.overlay);
}

/// Step one: an overlay closes, and the arm is not what closed it.
#[test]
fn ctrl_c_closes_an_overlay_before_anything_else() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    assert!(matches!(app.overlay, Some(Overlay::Commands(_))));

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert!(app.overlay.is_none(), "{:?}", app.overlay);
    assert!(!app.quit_armed());
}

/// The arm is a window, not a latch: two presses a minute apart are two first presses.
#[test]
fn the_quit_arm_expires_with_its_window() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.quit_armed());

    for _ in 0..40 {
        app.apply(Msg::Tick);
    }

    assert!(!app.quit_armed(), "the window never closed");

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.overlay.is_none(), "{:?}", app.overlay);
    assert!(app.quit_armed(), "and the next press arms again");
}

// ----- T1.3: the interrupt follows its binding -------------------------------------------

/// `esc` interrupts because `[keys] interrupt` says `esc`, not because a match arm says
/// `KeyCode::Esc`.
#[test]
fn the_interrupt_is_whatever_the_map_says_it_is() {
    let mut app = opened("running", steering_capabilities(), Vec::new());
    rebound(&mut app, &[("interrupt", "ctrl+g")]);
    compose(&mut app);

    app.apply(modified(KeyCode::Char('g'), KeyModifiers::CONTROL));
    assert_eq!(
        interrupts(&mut app),
        1,
        "the rebound key did not reach the interrupt"
    );

    // And `esc` no longer does. It keeps its own meanings — here, leaving an idle-looking
    // composer — which is why this is checked after the key that does interrupt.
    app.apply(key(KeyCode::Esc));
    assert_eq!(
        interrupts(&mut app),
        0,
        "esc interrupted a turn it is no longer bound to"
    );
}

/// The other direction, with the default map: `esc` on a running turn interrupts.
#[test]
fn the_default_interrupt_key_still_interrupts() {
    let mut app = opened("running", steering_capabilities(), Vec::new());

    compose(&mut app);
    app.apply(key(KeyCode::Esc));

    assert_eq!(interrupts(&mut app), 1);
}

/// `esc`'s other meanings stay on `esc` when the interrupt moves away. The turn is
/// running and the draft has text, so before T1.3 this key interrupted; now it is the
/// draft's.
#[test]
fn escape_keeps_its_other_meanings_when_the_interrupt_is_rebound() {
    let mut app = opened("running", steering_capabilities(), Vec::new());
    rebound(&mut app, &[("interrupt", "ctrl+g")]);

    compose(&mut app);
    type_text(&mut app, "a draft to keep");
    app.apply(key(KeyCode::Esc));

    assert_eq!(interrupts(&mut app), 0);
    assert_eq!(draft(&app), "", "the draft was not cleared");

    // And it is recoverable, which is the whole reason it is allowed to be cleared.
    app.apply(key(KeyCode::Up));
    assert_eq!(draft(&app), "a draft to keep");
}

/// Mid-turn, `esc` still closes a completion menu before it interrupts anything. A turn
/// aborted because somebody wanted the `/` list to go away is neither keystroke's ask.
#[test]
fn escape_dismisses_a_completion_menu_before_it_interrupts() {
    let mut app = opened("running", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/backtr");
    app.apply(key(KeyCode::Esc));

    assert_eq!(interrupts(&mut app), 0, "the menu should have gone first");
    assert_eq!(draft(&app), "/backtr");
    assert!(app
        .sessions
        .composer
        .as_ref()
        .is_some_and(|composer| composer.editor.completion().is_none()));

    // The next one is the interrupt.
    app.apply(key(KeyCode::Esc));
    assert_eq!(interrupts(&mut app), 0, "there is still a draft to clear");
    app.apply(key(KeyCode::Esc));
    assert_eq!(interrupts(&mut app), 1);
}

// ----- T1.5: the new keys ----------------------------------------------------------------

/// `ctrl+r` prefills the verb and the title the session has now, so the key edits a name
/// rather than blanking one.
#[test]
fn ctrl_r_prefills_the_rename_verb_with_the_current_title() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    app.apply(modified(KeyCode::Char('r'), KeyModifiers::CONTROL));

    assert_eq!(draft(&app), "/rename ");

    // With a title the runtime has given it, the title is in the draft to be edited.
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-b3",
            "title": "the CRLF fixture",
            "status": "idle",
            "provider": "native",
            "workspace": "/Users/operator/code/ouroboros",
            "updated_at": "2026-01-01T00:00:00.000000Z",
            "options": { "capabilities": steering_capabilities() },
        }]),
    );

    app.apply(modified(KeyCode::Char('r'), KeyModifiers::CONTROL));
    assert_eq!(draft(&app), "/rename the CRLF fixture");
}

/// `/rename <title>` calls the gateway's own verb through the call path every other
/// session action uses.
#[test]
fn slash_rename_calls_interactive_rename() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "/rename the CRLF fixture");
    app.apply(key(KeyCode::Enter));

    let rename = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.rename")
        .expect("a rename call");

    assert_eq!(rename.params["id"], "session-b3");
    assert_eq!(rename.params["title"], "the CRLF fixture");
    assert_eq!(draft(&app), "", "the verb was accepted");
}

/// A gateway that does not serve the verb is said so, rather than called and refused.
#[test]
fn slash_rename_on_a_runtime_without_it_says_so_and_sends_nothing() {
    let mut app = opened_without(
        "idle",
        steering_capabilities(),
        Vec::new(),
        &["interactive.rename"],
    );

    compose(&mut app);
    type_text(&mut app, "/rename anything");
    app.apply(key(KeyCode::Enter));

    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.rename"));
    assert!(
        app.notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("interactive.rename")),
        "{:?}",
        app.notice
    );
}

/// `ctrl+z` asks the driver to hand the terminal back. The signal itself belongs to
/// [`ouro::ui::run`]; what a test can pin here is that the key reaches the request, once.
#[test]
fn ctrl_z_asks_the_driver_to_suspend() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    assert!(!app.take_suspend());

    app.apply(modified(KeyCode::Char('z'), KeyModifiers::CONTROL));

    assert!(app.take_suspend(), "ctrl+z asked for nothing");
    assert!(!app.take_suspend(), "and it asked twice");
}

/// `home` and `end` are the transcript's ends on an empty draft, and the editor's line
/// motions the moment there is text — which is what readline says they are.
#[test]
fn home_and_end_reach_the_transcript_only_while_the_draft_is_empty() {
    let mut app = opened(
        "idle",
        steering_capabilities(),
        (1..40)
            .map(|sequence| {
                event(
                    sequence,
                    "output_text_final",
                    json!({ "text": format!("line {sequence}") }),
                )
            })
            .collect(),
    );

    // A frame, because how far a transcript can scroll is what the last one measured.
    let _ = screen(&mut app);
    compose(&mut app);

    app.apply(key(KeyCode::Home));
    let watch = app.sessions.open_watch().expect("a watch");
    assert!(watch.scroll > 0, "home did not reach the first row");
    assert!(!watch.follow);

    app.apply(key(KeyCode::End));
    let watch = app.sessions.open_watch().expect("a watch");
    assert_eq!(watch.scroll, 0, "end did not come back");
    assert!(watch.follow);

    // With text in the draft they are the editor's again: the caret moves, the transcript
    // does not.
    type_text(&mut app, "half a sentence");
    app.apply(key(KeyCode::Home));
    assert_eq!(
        app.sessions
            .open_watch()
            .expect("a watch")
            .scroll,
        0,
        "home scrolled the transcript out from under an edit"
    );
    type_text(&mut app, "> ");
    assert_eq!(draft(&app), "> half a sentence");
}

/// The leader verbs this slice added, each running the code its `/` verb runs.
#[test]
fn the_new_leader_verbs_reach_the_same_code_their_slash_verbs_do() {
    // `ctrl+x g` is backtrack, which `/backtrack` opens.
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );
    leader(&mut app, 'g');
    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);

    // `ctrl+x m` prefills `/model `, which is what the palette's row does.
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    leader(&mut app, 'm');
    assert_eq!(draft(&app), "/model ");

    // `ctrl+x c` is the unfocused fold, which is bare `/compact` — and only a native
    // session holds a conversation of its own to fold.
    let mut native = steering_capabilities();
    native["transport"] = json!("native");
    let mut app = opened("idle", native, Vec::new());
    leader(&mut app, 'c');
    assert!(
        app.drain()
            .iter()
            .any(|call| call.method == "interactive.compact"),
        "ctrl+x c folded nothing"
    );

    // `ctrl+x x` is export, and `ctrl+x k` is what used to be on `x`.
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    leader(&mut app, 'x');
    assert!(
        app.take_export().is_some(),
        "ctrl+x x did not export; it is not end-session any more"
    );

    let mut app = opened("idle", steering_capabilities(), Vec::new());
    leader(&mut app, 'k');
    assert!(
        matches!(app.overlay, Some(Overlay::Confirm { .. })),
        "ctrl+x k is end or remove session: {:?}",
        app.overlay
    );

    // `ctrl+x s` is the dashboard, and the four digits are the four tabs.
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    leader(&mut app, 's');
    assert_eq!(app.tab, ouro::ui::app::Tab::Dashboard);

    for (digit, tab) in [
        ('1', ouro::ui::app::Tab::Dashboard),
        ('2', ouro::ui::app::Tab::Sessions),
        ('3', ouro::ui::app::Tab::Upgrade),
        ('4', ouro::ui::app::Tab::Logs),
    ] {
        let mut app = opened("idle", steering_capabilities(), Vec::new());
        leader(&mut app, digit);
        assert_eq!(app.tab, tab, "ctrl+x {digit}");
    }

    // `ctrl+x b` flips the rail, and `ctrl+x ,` is where settings went.
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    assert!(!app.rail_hidden);
    leader(&mut app, 'b');
    assert!(app.rail_hidden);
    leader(&mut app, 'b');
    assert!(!app.rail_hidden);

    leader(&mut app, ',');
    assert!(
        matches!(app.overlay, Some(Overlay::Settings(_))),
        "{:?}",
        app.overlay
    );
}

/// The two chords the realignment took away, gone from the keys as well as from the map:
/// a bare `,` is a comma a message may start with, and `ctrl+d` is delete-forward.
#[test]
fn the_keys_the_realignment_freed_are_free() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, ", then this");
    assert_eq!(draft(&app), ", then this");
    assert!(app.overlay.is_none(), "a comma opened settings");

    // `ctrl+d` on an empty prompt is no longer the quit dialog. With text it deletes
    // forward, which is its one remaining meaning.
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert_eq!(draft(&app), "");
    app.apply(modified(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert!(app.overlay.is_none(), "ctrl+d opened the quit dialog");

    type_text(&mut app, "xy");
    app.apply(key(KeyCode::Left));
    app.apply(key(KeyCode::Left));
    app.apply(modified(KeyCode::Char('d'), KeyModifiers::CONTROL));
    assert_eq!(draft(&app), "y");
}

// ----- T1.7: esc with text on an idle session --------------------------------------------

/// `docs/TUI.md` said this key kept the draft; the code dropped the keystroke and did
/// nothing at all (R1 §2.1). The draft goes where `up` finds it, and one line says so.
#[test]
fn escape_with_text_on_an_idle_session_banks_the_draft() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    compose(&mut app);
    type_text(&mut app, "half a thought");
    app.apply(key(KeyCode::Esc));

    assert_eq!(draft(&app), "");
    assert!(
        app.sessions.open.is_some(),
        "esc with text left the session as well as the draft"
    );

    let notice = app.notice.as_ref().expect("one line about the draft");
    assert!(
        notice.text.contains("draft cleared") && notice.text.contains("brings it back"),
        "{}",
        notice.text
    );

    app.apply(key(KeyCode::Up));
    assert_eq!(draft(&app), "half a thought");

    // And an empty draft still leaves the session, exactly as it did — after the `esc
    // esc` window the first one armed has closed, or this would be the backtrack chord.
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    for _ in 0..40 {
        app.apply(Msg::Tick);
    }
    app.apply(key(KeyCode::Esc));
    assert!(app.sessions.open.is_none(), "{:?}", app.overlay);
}

// ---------------------------------------------------------------------------------------
// (f) ui-parity T1 fix wave — the reviewer's probes, kept as regressions
// ---------------------------------------------------------------------------------------

/// H2. Enter completes only a verb the typed word continues into.
///
/// The menu matches descriptions as well as names, which is right for *offering* rows and
/// wrong for choosing one: `/new`'s description is "start a new coding session", so
/// `/session`, `/start`, `/s`, `/c` and `/e` all matched it — and `/new` is row 0, so
/// Enter answered every one of them with `/new`, which a second Enter then ran.
#[test]
fn enter_never_rewrites_a_word_into_a_verb_it_does_not_continue_into() {
    for typed in ["/session", "/start", "/s", "/c", "/e", "/a"] {
        let mut app = opened("idle", steering_capabilities(), Vec::new());
        compose(&mut app);
        type_text(&mut app, typed);
        app.apply(key(KeyCode::Enter));

        assert_ne!(draft(&app), "/new", "{typed:?} became /new");
        assert!(
            draft(&app).is_empty() || draft(&app).starts_with(typed),
            "{typed:?} became {:?}, which it does not continue into",
            draft(&app)
        );
    }
}

/// A lone sigil is not a word anybody started, and every row "matches" it.
#[test]
fn a_bare_slash_accepts_nothing_and_starts_nothing() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/");
    app.apply(key(KeyCode::Enter));

    assert_ne!(draft(&app), "/new", "a lone slash became a verb nobody typed");

    // Whatever it did, it did not start anything and did not open a dialog.
    app.apply(key(KeyCode::Enter));
    let methods: Vec<String> = app.drain().iter().map(|call| call.method.clone()).collect();
    assert!(
        !methods.iter().any(|method| method == "interactive.start"),
        "{methods:?}"
    );
}

/// The words it *does* continue into, including the two that share a stem.
#[test]
fn enter_completes_the_first_verb_in_table_order_that_the_word_continues_into() {
    for (typed, expected) in [("/ke", "/keys"), ("/st", "/steer"), ("/backtr", "/backtrack")] {
        let mut app = opened("idle", steering_capabilities(), Vec::new());
        compose(&mut app);
        type_text(&mut app, typed);
        app.apply(key(KeyCode::Enter));
        assert_eq!(draft(&app), expected, "{typed:?}");
    }
}

/// And a verb typed out in full is sent on the first Enter, not completed into a sibling.
#[test]
fn a_verb_typed_in_full_is_sent_on_the_first_enter() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/help");
    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Help)),
        "{:?}",
        app.overlay
    );
    assert_eq!(draft(&app), "");
}

// ----- M2: the slash grammar ------------------------------------------------------------

/// (a) An unknown verb-shaped word with more words after it is a sentence, and is sent.
#[test]
fn prose_that_begins_with_a_slash_word_is_sent_as_a_message() {
    for line in ["/tmp is full", "/usr is read-only on this box"] {
        let mut app = opened("idle", steering_capabilities(), Vec::new());
        compose(&mut app);
        type_text(&mut app, line);
        app.apply(key(KeyCode::Enter));

        let sent = turn_calls(&app.drain());
        assert_eq!(sent.len(), 1, "{line:?} was not sent: {:?}", app.notice);
        assert_eq!(sent[0].1["input"], line);
    }
}

/// (b) An unknown verb alone on one line is still refused — that is the `/ke` case — and
/// the notice says how to send it as text anyway.
#[test]
fn an_unknown_verb_alone_is_refused_and_the_notice_says_how_to_send_it() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/etc");
    app.apply(key(KeyCode::Enter));

    assert!(turn_calls(&app.drain()).is_empty());
    assert_eq!(draft(&app), "/etc");

    let notice = app.notice.as_ref().expect("a refusal").text.clone();
    assert!(notice.contains("unknown command /etc"), "{notice}");
    assert!(
        notice.contains("start the line with a space"),
        "the refusal is a dead end without this: {notice}"
    );
}

/// (c) …and that escape hatch works.
#[test]
fn a_leading_space_sends_a_verb_as_the_text_it_is() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, " /keys");
    app.apply(key(KeyCode::Enter));

    assert!(
        !matches!(app.overlay, Some(Overlay::Keys { .. })),
        "the space did not escape the grammar"
    );

    let sent = turn_calls(&app.drain());
    assert_eq!(sent.len(), 1, "{:?}", app.notice);
    assert_eq!(sent[0].1["input"], "/keys");
}

/// (d) A verb this client has, with an argument it cannot read, stays refused.
#[test]
fn a_known_verb_with_an_argument_it_cannot_take_is_refused_by_name() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/keys foo");
    app.apply(key(KeyCode::Enter));

    assert_eq!(
        app.notice.as_ref().map(|notice| notice.text.as_str()),
        Some("/keys did not take that argument")
    );
    assert!(turn_calls(&app.drain()).is_empty());
    assert_eq!(draft(&app), "/keys foo", "the draft was thrown away");
}

/// (e) A verb on line one with a paragraph under it was never a verb.
#[test]
fn a_verb_with_a_paragraph_under_it_is_a_paragraph() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/context");
    app.apply(modified(KeyCode::Char('j'), KeyModifiers::CONTROL));
    type_text(&mut app, "and explain what fills it");
    app.apply(key(KeyCode::Enter));

    let sent = turn_calls(&app.drain());
    assert_eq!(sent.len(), 1, "{:?}", app.notice);
    assert_eq!(sent[0].1["input"], "/context\nand explain what fills it");
}

/// (f4d) A draft whose first line is blank is a message, by the same rule as (c): leading
/// whitespace is leading whitespace, and a command has to be the first thing in the draft.
#[test]
fn a_draft_that_opens_with_a_blank_line_is_a_message() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    app.apply(modified(KeyCode::Char('j'), KeyModifiers::CONTROL));
    type_text(&mut app, "/keys");
    app.apply(key(KeyCode::Enter));

    assert!(
        !matches!(app.overlay, Some(Overlay::Keys { .. })),
        "a blank first line still ran the verb"
    );
    assert_eq!(turn_calls(&app.drain()).len(), 1);
}

// ----- H4: the prefills bank the draft they replace ---------------------------------------

/// `ctrl+r` and `ctrl+x m` used to eat an unsent draft with no way back: they cleared the
/// editor without banking it, so the `up` this client advertises brought back nothing.
#[test]
fn a_prefill_banks_the_draft_it_replaces() {
    for prefill in ['r', 'm'] {
        let mut app = opened("idle", steering_capabilities(), Vec::new());
        compose(&mut app);
        type_text(&mut app, "a long answer I have been writing for ten minutes");

        match prefill {
            'r' => app.apply(modified(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            _ => leader(&mut app, 'm'),
        }

        assert!(draft(&app).starts_with("/"), "{prefill}: {:?}", draft(&app));
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|notice| notice.text.contains("brings it back")),
            "{prefill}: {:?}",
            app.notice
        );

        app.apply(key(KeyCode::Up));
        assert_eq!(
            draft(&app),
            "a long answer I have been writing for ten minutes",
            "{prefill}: the draft is not in history"
        );
    }
}

/// An empty draft is not banked, so `up` still reaches whatever came before it.
#[test]
fn a_prefill_over_an_empty_draft_says_nothing() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    app.apply(modified(KeyCode::Char('r'), KeyModifiers::CONTROL));

    assert_eq!(draft(&app), "/rename ");
    assert!(
        app.notice.is_none() || !app.notice.as_ref().unwrap().text.contains("brings it back"),
        "{:?}",
        app.notice
    );
}

// ----- M4: the arm belongs to the screen it was made on -----------------------------------

/// Three presses used to quit when the middle one closed something. An arm is only good
/// for the screen it was made on.
#[test]
fn an_overlay_between_two_cancels_takes_the_arm_with_it() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.quit_armed());

    app.sessions.composer = None;
    app.apply(key(KeyCode::Char('?')));
    assert!(matches!(app.overlay, Some(Overlay::Help)), "{:?}", app.overlay);
    assert!(!app.quit_armed(), "an overlay opened over the arm");

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.overlay.is_none(), "that press closed the overlay");
    assert!(!app.quit_armed(), "and did not leave an arm behind");

    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(
        app.overlay.is_none(),
        "so the third press arms rather than quitting: {:?}",
        app.overlay
    );
    assert!(app.quit_armed());
}

/// The same for a tab change and for leaving the session.
#[test]
fn the_arm_does_not_survive_a_tab_change_or_a_session_change() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.quit_armed());
    leader(&mut app, '1');
    assert!(!app.quit_armed(), "the arm followed the operator to another tab");

    let mut app = opened("idle", steering_capabilities(), Vec::new());
    app.apply(modified(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.quit_armed());
    app.sessions.open = None;
    assert!(!app.quit_armed(), "the arm outlived the session it was made on");
}

// ----- L1: a path typed in full is still an attachment ------------------------------------

/// B4's promise is that an `@path` is both the sentence and the structured file. A path
/// somebody typed rather than Tab-completed used to be only the sentence.
#[test]
fn a_fully_typed_at_path_still_becomes_an_attachment() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    with_files(&mut app, &["src/main.rs"]);
    compose(&mut app);
    type_text(&mut app, "@src/main.rs");
    app.apply(key(KeyCode::Enter));

    let sent = turn_calls(&app.drain());
    assert_eq!(sent.len(), 1, "the path was not sent: {:?}", app.notice);
    assert_eq!(
        sent[0].1["input"]["attachments"][0], "src/main.rs",
        "sent without the structured attachment: {}",
        sent[0].1
    );
    assert_eq!(sent[0].1["input"]["prompt"], "@src/main.rs", "and without the words");
}

// ----- L2: an Esc that banked a draft is not half of a chord -------------------------------

/// Two Escapes, not three: the first banked the draft and therefore did its job, so it is
/// not also the arm of `Esc Esc`.
#[test]
fn two_escapes_leave_a_session_that_had_text_in_it() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "x");

    app.apply(key(KeyCode::Esc));
    assert_eq!(draft(&app), "", "the first banked the draft");
    assert!(app.sessions.open.is_some());

    app.apply(key(KeyCode::Esc));
    assert!(
        app.overlay.is_none(),
        "the second was eaten by the backtrack chord: {:?}",
        app.overlay
    );
    assert!(app.sessions.open.is_none(), "the second leaves the session");
}

/// And `Esc Esc` on an empty draft is still the chord it always was.
#[test]
fn esc_esc_on_an_empty_draft_is_still_the_chord() {
    let mut app = opened(
        "idle",
        steering_capabilities(),
        vec![user_turn(1, "first thing")],
    );
    compose(&mut app);

    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Esc));
    assert!(overlay_is_backtrack(&app), "{:?}", app.overlay);
}

// ----- M14: /rename's own gates -----------------------------------------------------------

/// An empty title is refused locally rather than sent for the gateway to refuse.
#[test]
fn slash_rename_with_no_title_is_refused_and_sends_nothing() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    compose(&mut app);
    type_text(&mut app, "/rename   ");
    app.apply(key(KeyCode::Enter));

    assert!(
        app.notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("name it")),
        "{:?}",
        app.notice
    );
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.rename"));
}

/// `ctrl+r` with no session says what it is for rather than talking about a next turn.
#[test]
fn ctrl_r_without_a_session_says_what_the_key_is_for() {
    let mut app = app(full_hello());
    app.apply(modified(KeyCode::Char('r'), KeyModifiers::CONTROL));

    assert!(
        app.notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("rename")),
        "{:?}",
        app.notice
    );
}

// ----- H3: the `?` panel's five headings ---------------------------------------------------

/// Each of the five groups is a heading, and each appears exactly **once**. The taxonomy
/// is only worth having if the panel is sorted by it; twelve headings over twenty-five
/// rows is a list with decoration rather than a grouped page.
#[test]
fn the_help_panel_draws_each_group_heading_exactly_once() {
    let mut app = opened("idle", steering_capabilities(), Vec::new());
    app.sessions.composer = None;
    app.apply(key(KeyCode::Char('?')));

    let text = render(&mut app, 180, 90).text();

    // The panel is a box drawn over the session behind it, so a heading shares its
    // terminal row with whatever is either side of the frame. A row *is* a heading when
    // one of the cells the frame divides it into is exactly that word.
    for heading in ["SESSION", "TURN", "CONVERSATION", "RUNTIME", "CLIENT"] {
        let seen = text
            .lines()
            .filter(|line| {
                line.split('\u{2502}')
                    .any(|cell| cell.trim() == heading)
            })
            .count();
        assert_eq!(seen, 1, "{heading} appears {seen} times:\n{text}");
    }
}
