//! `/sandbox`, the start surfaces that offer full access, and the words a person reads.
//!
//! The wire value is `unrestricted` — `Gateway.Methods` `@sandbox_modes` declares it, and
//! `interactive.configure` takes it on a running session. Everything an operator *reads*
//! says **full access** instead, because "unrestricted" names the parameter rather than
//! what the agent is being allowed to do.
//!
//! The honesty assertions are the point of the file:
//!
//! * the verb's three words reach the three wire values and nothing else — a posture verb
//!   that guessed which mode "sandbox" meant would eventually guess the widest one;
//! * bare `/sandbox` reports and never changes anything, because three values have no
//!   toggle;
//! * a session whose posture the runtime never named is drawn as unnamed, not as a
//!   default this client invented;
//! * the runtime's typed `unsupported_configuration` refusal is rendered as its own
//!   sentence rather than as a field of a JSON blob.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::{Plane, SandboxMode, StartRequest};
use ouro::proto::{ErrorCode, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Msg, Tag};

use support::{full_hello, render};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn session_row(options: Value) -> Value {
    json!([{
        "_struct": "Ouroboros.Interactive.State",
        "id": SESSION,
        "node": "ouroboros@golden",
        "provider": "native",
        "workspace": "/tmp/w",
        "status": "running",
        "options": options,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "updated_at": "2026-01-01T00:00:00.000000Z"
    }])
}

fn opened_with(hello: ouro::proto::Hello, options: Value) -> App {
    let mut app = App::new(
        ouro::ui::app::Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        hello,
        None,
    );

    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        session_row(options),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, SESSION.to_string());

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");

    answer(&mut app, call.tag, json!([]));
    app
}

fn opened() -> App {
    opened_with(full_hello(), json!({"sandbox_mode": "workspace_write"}))
}

fn compose(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
}

/// The one call the verb makes, and the tag that carries what was asked for.
fn sent(app: &mut App, method: &str) -> (Tag, Value) {
    let calls = app.drain();
    let call = calls
        .into_iter()
        .find(|call| call.method == method)
        .unwrap_or_else(|| panic!("a {method} call"));

    (call.tag, call.params)
}

// ------------------------------------------------------------------ the verb

/// Each word reaches its own wire value, and the params name the session and the mode and
/// nothing else.
#[test]
fn each_word_configures_its_own_sandbox_mode_and_nothing_else() {
    for (word, wire, want) in [
        ("full", "unrestricted", SandboxMode::Unrestricted),
        ("workspace", "workspace_write", SandboxMode::WorkspaceWrite),
        ("read-only", "read_only", SandboxMode::ReadOnly),
    ] {
        // Opened on a posture none of the three words names, so every case is a change.
        let mut app = opened_with(full_hello(), json!({"sandbox_mode": "default"}));
        compose(&mut app, &format!("/sandbox {word}"));

        let (tag, params) = sent(&mut app, "interactive.configure");

        assert_eq!(
            params,
            json!({"id": SESSION, "sandbox_mode": wire}),
            "/sandbox {word} names the session and the posture, and nothing else"
        );
        assert!(
            matches!(tag, Tag::SandboxMode { want: asked, .. } if asked == want),
            "the tag carries what was asked for, so the answer can say it"
        );
    }
}

/// The operator's word and the wire's word are deliberately different, and only one of
/// them is ever on screen.
#[test]
fn full_access_is_the_word_on_screen_and_unrestricted_is_the_word_on_the_wire() {
    let mut app = opened();
    compose(&mut app, "/sandbox full");

    let (_tag, params) = sent(&mut app, "interactive.configure");
    assert_eq!(params["sandbox_mode"], "unrestricted");

    let text = render(&mut app, 160, 40).text();
    assert!(
        text.contains("full access"),
        "the operator reads what they are agreeing to\n{text}"
    );
    assert!(
        !text.contains("unrestricted"),
        "and never the schema's word for the parameter\n{text}"
    );
}

/// Bare `/sandbox` reports. Three postures have no "the other one", and the widest of them
/// removes the OS sandbox, so a verb that guessed would eventually guess that.
#[test]
fn bare_sandbox_reports_the_posture_and_the_words_without_changing_anything() {
    let mut app = opened();
    compose(&mut app, "/sandbox");

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.configure"),
        "a report is not a round trip"
    );

    let text = render(&mut app, 200, 40).text();
    assert!(text.contains("can edit"), "the posture it is on\n{text}");
    assert!(
        text.contains("full, workspace, read-only"),
        "and the three words that move it\n{text}"
    );
}

/// A session whose row names no `sandbox_mode` is reported as naming none. Answering
/// "workspace write" here would be this client inventing a safety fact.
#[test]
fn a_session_with_no_stated_posture_is_reported_as_having_none() {
    let mut app = opened_with(full_hello(), json!({"approval_mode": "prompt"}));
    compose(&mut app, "/sandbox");

    let text = render(&mut app, 200, 40).text();
    assert!(
        text.contains("names no file-access mode"),
        "silence is reported as silence\n{text}"
    );
}

/// An argument that is none of the three is refused, and the refusal names all three.
#[test]
fn an_unreadable_argument_is_refused_naming_the_three_words() {
    let mut app = opened();
    compose(&mut app, "/sandbox yolo");

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.configure"),
        "an unreadable argument does not reach the wire"
    );

    let text = render(&mut app, 200, 40).text();
    assert!(
        text.contains("/sandbox takes full, workspace, read-only"),
        "{text}"
    );
    assert!(
        !text.contains("unrestricted"),
        "not even a refusal teaches the wire's word\n{text}"
    );
}

/// Asking for the posture the session is already on is answered here, not on the wire.
#[test]
fn the_posture_a_session_is_already_on_is_not_a_call() {
    let mut app = opened();
    compose(&mut app, "/sandbox workspace");

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.configure"),
        "a no-op posture change is not a round trip"
    );

    let text = render(&mut app, 160, 40).text();
    assert!(text.contains("already on can edit"), "{text}");
}

/// A gateway that does not serve `interactive.configure` is told apart from one that
/// refuses the change, and the local refusal names the way that does work.
#[test]
fn sandbox_is_refused_locally_where_the_gateway_does_not_serve_configure() {
    let mut hello = full_hello();
    hello
        .methods
        .retain(|method| method != "interactive.configure");

    let mut app = opened_with(hello, json!({}));
    compose(&mut app, "/sandbox full");

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.configure"),
        "an unserved method is not called"
    );

    let text = render(&mut app, 200, 44).text();
    assert!(text.contains("does not serve"), "{text}");
    assert!(
        text.contains("--sandbox-mode unrestricted"),
        "a flag is a wire word, so naming it is naming the parameter\n{text}"
    );
}

// ------------------------------------------------------------- the refusals

/// The runtime's typed `unsupported_configuration` is rendered as the sentence it is.
#[test]
fn a_transport_that_cannot_be_reconfigured_is_rendered_as_data() {
    let mut app = opened();
    compose(&mut app, "/sandbox full");

    let (tag, _params) = sent(&mut app, "interactive.configure");

    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "unsupported_configuration".into(),
            data: Some(json!({
                "provider": "claude",
                "transport": "stream_json_resume",
                "field": "sandbox_mode",
                "reason": "option_not_configurable",
                "message": "claude over the stream_json_resume transport cannot change \
                            sandbox_mode on an open session; start a new session instead."
            })),
        })),
    });

    let text = render(&mut app, 220, 44).text();
    assert!(
        text.contains("cannot change sandbox_mode on an open session"),
        "the runtime's own sentence is shown, not a JSON blob\n{text}"
    );
    assert!(
        text.contains("option_not_configurable"),
        "and the typed reason is named\n{text}"
    );
}

/// `value_not_accepted` carries an allowlist instead of a sentence, and the allowlist is
/// the whole answer: it says which postures this provider *would* take.
#[test]
fn a_provider_that_does_not_take_the_mode_names_the_ones_it_does() {
    let mut app = opened_with(full_hello(), json!({"sandbox_mode": "read_only"}));
    compose(&mut app, "/sandbox workspace");

    let (tag, _params) = sent(&mut app, "interactive.configure");

    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "unconfigurable_session".into(),
            data: Some(json!({
                "provider": "pi",
                "transport": "rpc",
                "field": "sandbox_mode",
                "reason": "value_not_accepted",
                "value": "workspace_write",
                "accepted_values": ["default", "read_only", "unrestricted"]
            })),
        })),
    });

    let text = render(&mut app, 220, 44).text();
    assert!(
        text.contains("takes only default, read_only, unrestricted"),
        "the provider's own allowlist is quoted\n{text}"
    );
}

/// A refusal about some other field is not paraphrased as a sandbox one.
#[test]
fn a_refusal_about_another_field_falls_back_to_the_generic_report() {
    let mut app = opened();
    compose(&mut app, "/sandbox full");

    let (tag, _params) = sent(&mut app, "interactive.configure");

    app.apply(Msg::Answer {
        tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "unconfigurable_session".into(),
            data: Some(json!({ "field": "model", "reason": "no_dynamic_model" })),
        })),
    });

    let text = render(&mut app, 220, 44).text();
    assert!(
        text.contains("file access"),
        "the generic report still names the verb that failed\n{text}"
    );
}

/// A success says the posture the runtime confirmed, and re-lists so every surface reading
/// `options.sandbox_mode` catches up with it.
#[test]
fn a_confirmed_change_says_so_and_re_lists() {
    let mut app = opened();
    compose(&mut app, "/sandbox full");

    let (tag, _params) = sent(&mut app, "interactive.configure");
    answer(&mut app, tag, json!({"id": SESSION, "applies": "now"}));

    assert!(
        app.drain()
            .iter()
            .any(|call| call.method == "interactive.list"),
        "the session row is the authority on the posture, so it is re-read"
    );

    let text = render(&mut app, 200, 40).text();
    assert!(text.contains("full access"), "{text}");
    assert!(text.contains("no OS sandbox"), "{text}");
}

// -------------------------------------------------------------- the surfaces

/// The footer's C5 cell names the posture in the operator's words, in the warn colour: the
/// runtime *stated* this session runs unconfined, so saying so is not a guess.
#[test]
fn the_footer_names_full_access_in_the_warn_colour() {
    let mut app = opened_with(
        full_hello(),
        json!({"sandbox_mode": "unrestricted", "capabilities": {"sandbox": "none"}}),
    );

    let screen = render(&mut app, 200, 40);
    let row = screen.row("no OS sandbox");

    assert!(row.contains("full access · no OS sandbox"), "{row}");
    assert_eq!(
        screen.colour_of("no OS sandbox", "full access"),
        ouro::ui::theme::warn(),
        "a risk posture is drawn as one\n{}",
        screen.text()
    );

    // The other postures keep the wire's own spelling: an operator matching the footer
    // against `--sandbox-mode` should still recognise them.
    let mut app = opened();
    assert!(render(&mut app, 200, 40).contains("workspace-write"));
}

/// The palette offers the verb, and teaches it by prefilling rather than picking a posture
/// on the operator's behalf.
#[test]
fn the_palette_teaches_the_verb_rather_than_choosing_a_posture() {
    let mut app = opened();
    app.apply(Msg::Key(KeyEvent::new(
        KeyCode::Char('p'),
        KeyModifiers::CONTROL,
    )));

    for character in "sandbox".chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    let screen = render(&mut app, 160, 40);
    assert!(
        screen.contains("Change file access (OS sandbox)"),
        "{}",
        screen.text()
    );
    assert!(
        screen.row("Change file access").contains("/sandbox"),
        "the row names the verb it teaches\n{}",
        screen.text()
    );

    app.apply(key(KeyCode::Enter));

    assert!(
        !app.drain()
            .iter()
            .any(|call| call.method == "interactive.configure"),
        "the palette row states no posture, so it sends nothing"
    );

    let screen = render(&mut app, 160, 40);
    assert!(
        screen.contains("/sandbox "),
        "the composer is prefilled with the verb\n{}",
        screen.text()
    );
}

/// The row is gated on the same two questions `/plan` asks.
#[test]
fn the_palette_row_needs_a_session_and_a_gateway_that_serves_configure() {
    let mut hello = full_hello();
    hello
        .methods
        .retain(|method| method != "interactive.configure");

    let mut app = opened_with(hello, json!({}));
    app.apply(Msg::Key(KeyEvent::new(
        KeyCode::Char('p'),
        KeyModifiers::CONTROL,
    )));

    assert!(
        !render(&mut app, 160, 40).contains("Change file access"),
        "a row that always refuses is not a row"
    );
}

/// `/sandbox` completes from the composer catalogue.
#[test]
fn the_verb_is_in_the_completion_catalogue() {
    let mut app = opened();
    for character in "/sand".chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    let screen = render(&mut app, 160, 40);
    assert!(screen.contains("/sandbox"), "{}", screen.text());
}

// --------------------------------------------------------------- start paths

/// The new-session dialog offers full access, states its consequence on the same line, and
/// draws it in the warn colour before Enter rather than after.
#[test]
fn the_new_session_dialog_offers_full_access_and_says_what_it_costs() {
    let mut app = App::new(
        ouro::ui::app::Mode::Spawned { pid: 4242 },
        "127.0.0.1:4560".into(),
        full_hello(),
        None,
    );

    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    // Printable shortcuts belong to the operator dashboard; home is a task composer.
    app.tab = ouro::ui::app::Tab::Dashboard;
    app.apply(key(KeyCode::Char('n')));

    let Some(ouro::ui::app::Overlay::New(dialog)) = app.overlay.as_mut() else {
        panic!("the new-session dialog is open");
    };
    dialog.field = ouro::ui::app::NewField::SandboxMode;
    dialog.sandbox = ouro::ui::app::sandbox_index(Some(SandboxMode::Unrestricted));

    let screen = render(&mut app, 160, 30);
    let row = screen.row("files");

    assert!(
        row.contains("full access — shell runs with no OS sandbox"),
        "the consequence is on the row, not behind it\n{}",
        screen.text()
    );
    assert_eq!(
        screen.colour_of("files", "full"),
        ouro::ui::theme::warn(),
        "{}",
        screen.text()
    );

    // Every schema value is reachable from the cycler, including this one.
    assert_eq!(
        ouro::ui::app::sandbox_at(dialog_sandbox(&mut app)),
        Some(SandboxMode::Unrestricted)
    );
}

fn dialog_sandbox(app: &mut App) -> usize {
    let Some(ouro::ui::app::Overlay::New(dialog)) = app.overlay.as_ref() else {
        panic!("the new-session dialog is open");
    };
    dialog.sandbox
}

/// `ouro new --sandbox-mode unrestricted` reaches the wire unmolested: the client parses
/// the schema's word, and sends the schema's word.
#[test]
fn the_start_request_carries_unrestricted_to_the_wire() {
    assert_eq!(
        SandboxMode::parse("unrestricted"),
        Some(SandboxMode::Unrestricted)
    );

    let mut request = StartRequest::new(Plane::Interactive);
    request.provider = "native".into();
    request.workspace = "/tmp/w".into();
    request.sandbox_mode = Some(SandboxMode::Unrestricted);

    let params = request.params().expect("a startable request");
    assert_eq!(params["sandbox_mode"], "unrestricted");
}
