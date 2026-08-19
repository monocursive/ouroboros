//! Contract tests for the transcript-first harness shell.
//!
//! The previous client opened a provider-picker onboarding modal. The product contract is
//! now the opposite: `ouro` lands on a coding composer, managed ChatGPT sign-in gates the
//! first-class Codex path, and distribution remains one searchable command palette away.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::proto::{ErrorCode, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{App, Mode, Msg, Overlay, Tab, Tag};

use support::{app, full_hello, render};

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        app.apply(key(KeyCode::Char(c)));
    }
}

fn answer(app: &mut App, tag: Tag, value: serde_json::Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn account(connected: bool) -> serde_json::Value {
    json!({
        "account": if connected {
            json!({ "type": "chatgpt", "email": "builder@example.com", "planType": "pro" })
        } else {
            serde_json::Value::Null
        },
        "requiresOpenaiAuth": true,
        "login": { "status": "idle", "loginId": null, "flow": null, "error": null }
    })
}

fn harness(connected: bool) -> App {
    let mut app = app(full_hello());
    app.launch_dir = Some("/work/ouroboros".into());
    app.open_home();
    answer(&mut app, Tag::Account, account(connected));
    let _ = app.drain();
    app
}

#[test]
fn ouro_opens_on_the_coding_harness_without_an_onboarding_modal() {
    let mut app = harness(false);
    let screen = render(&mut app, 120, 34);

    assert_eq!(app.tab, Tab::Sessions);
    assert!(app.sessions.open.is_none());
    assert!(app.overlay.is_none());
    assert!(screen.contains("New coding session"), "{}", screen.text());
    assert!(screen.contains("Connect ChatGPT to start coding"));
    assert!(screen.contains("Type / for commands"), "{}", screen.text());
    assert!(screen.contains("ctrl+p commands"));
    assert!(!screen.contains("Dashboard│"));
}

#[test]
fn an_existing_chatgpt_subscription_goes_straight_to_the_workspace_composer() {
    let mut app = harness(true);
    let screen = render(&mut app, 120, 34);

    assert!(screen.contains("ChatGPT Pro"), "{}", screen.text());
    assert!(screen.contains("Ready in this workspace"));
    assert!(screen.contains("Ask the agent to build, fix, explain, or review"));
    assert!(screen.contains("/work/ouroboros"));
    assert!(screen.contains("FILES can edit"), "{}", screen.text());
}

#[test]
fn a_configured_non_codex_provider_is_not_blocked_by_chatgpt_auth() {
    let mut app = harness(false);
    app.config.defaults.provider = Some("claude".into());
    app.config.defaults.workspace = Some("/srv/agent-work".into());

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Ready in this workspace"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("PROVIDER claude"), "{}", screen.text());
    assert!(screen.contains("Provider claude"), "{}", screen.text());
    assert!(
        !screen.contains("ChatGPT not connected") && !screen.contains("ChatGPT unavailable"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("requested /srv/agent-work"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("Requested workspace: /srv/agent-work"));

    type_text(&mut app, "review the current diff");
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    let start = calls
        .iter()
        .find(|call| call.method == "interactive.start")
        .expect("the configured provider starts directly");
    assert_eq!(start.params["provider"], "claude");
    assert_eq!(start.params["workspace"], "/srv/agent-work");
    assert!(calls
        .iter()
        .all(|call| call.method != "account.login.start"));
}

/// `account.read` is a round trip, and the composer is on screen with the caret in it from
/// the first frame. Gating the draft on *readiness* meant typing "quick fix" a moment too
/// early sent the `q` to the quit dialog.
#[test]
fn the_first_keystrokes_land_in_the_draft_while_the_account_answer_is_in_flight() {
    let mut app = app(full_hello());
    app.launch_dir = Some("/work/ouroboros".into());
    app.open_home();
    let _ = app.drain();

    // Nothing has answered `account.read` yet.
    assert!(!app.chatgpt_connected());

    type_text(&mut app, "quick fix for the parser");

    assert!(app.overlay.is_none(), "no dialog was asked for");
    assert_eq!(app.home_draft.text(), "quick fix for the parser");

    // And the draft survives the answer that says the home is not ready.
    answer(&mut app, Tag::Account, account(false));
    assert_eq!(app.home_draft.text(), "quick fix for the parser");

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("quick fix for the parser"),
        "{}",
        screen.text()
    );
}

/// Once the runtime has answered, an unauthenticated home is a surface whose printable keys
/// belong to the shell, and it says so on screen. That half is deliberate and stays.
#[test]
fn a_resolved_unauthenticated_home_still_gives_printable_keys_to_the_shell() {
    let mut app = harness(false);
    assert!(app.home_draft.is_empty());

    app.apply(key(KeyCode::Char('q')));

    assert!(app.home_draft.is_empty());
    assert!(matches!(app.overlay, Some(Overlay::Quit { .. })));
}

/// An install whose Codex credential is an API key on the runtime host reports no ChatGPT
/// identity and `requiresOpenaiAuth: false`. Reading only the identity left it looking at
/// "Connect ChatGPT" forever, with Enter pushing a login it neither needs nor can complete.
#[test]
fn an_api_key_codex_install_is_ready_without_a_chatgpt_sign_in() {
    let mut app = app(full_hello());
    app.launch_dir = Some("/work/ouroboros".into());
    app.open_home();
    answer(
        &mut app,
        Tag::Account,
        json!({
            "account": serde_json::Value::Null,
            "requiresOpenaiAuth": false,
            "login": { "status": "idle" }
        }),
    );
    let _ = app.drain();

    assert!(!app.chatgpt_connected(), "there is no subscription to name");
    assert!(app.codex_usable());
    assert!(app.home_ready());

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Ready in this workspace"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("Codex ready"), "{}", screen.text());
    assert!(
        !screen.contains("ChatGPT not connected"),
        "{}",
        screen.text()
    );

    type_text(&mut app, "rename the module");
    app.apply(key(KeyCode::Enter));

    let calls = app.drain();
    assert!(
        calls.iter().any(|call| call.method == "interactive.start"),
        "Enter starts work rather than a login it cannot complete"
    );
    assert!(calls
        .iter()
        .all(|call| call.method != "account.login.start"));
}

/// The three states of `requiresOpenaiAuth`, and the conservative reading of the third.
#[test]
fn an_absent_requires_openai_auth_is_treated_as_sign_in_required() {
    let ready = |value: serde_json::Value| {
        let mut app = app(full_hello());
        app.open_home();
        answer(&mut app, Tag::Account, value);
        let _ = app.drain();
        app.home_ready()
    };

    // Connected: ready whatever the flag says.
    assert!(ready(account(true)));

    // Stated as not required: ready with no identity at all.
    assert!(ready(json!({
        "account": serde_json::Value::Null,
        "requiresOpenaiAuth": false
    })));

    // Absent: not a statement. Offering a login nobody needed costs one keystroke; hiding
    // the only way in from someone who did need it costs them the client.
    assert!(!ready(json!({ "account": serde_json::Value::Null })));

    let mut app = app(full_hello());
    app.open_home();
    answer(&mut app, Tag::Account, json!({}));
    let _ = app.drain();
    app.apply(key(KeyCode::Enter));

    assert!(app
        .drain()
        .iter()
        .any(|call| call.method == "account.login.start"));
}

#[test]
fn slash_commands_are_available_before_codex_sign_in() {
    let mut app = harness(false);

    type_text(&mut app, "/help");
    app.apply(key(KeyCode::Enter));

    assert!(matches!(app.overlay, Some(Overlay::Help)));
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "account.login.start"));
}

#[test]
fn enter_starts_the_supported_browser_login_on_a_local_runtime() {
    let mut app = harness(false);
    app.apply(key(KeyCode::Enter));

    let login = app
        .drain()
        .into_iter()
        .find(|call| call.method == "account.login.start")
        .expect("a managed login call");

    assert_eq!(login.params, json!({ "flow": "browser" }));
    assert!(matches!(app.overlay, Some(Overlay::Account(_))));

    answer(
        &mut app,
        Tag::AccountLogin,
        json!({
            "type": "chatgpt",
            "loginId": "login-1",
            "authUrl": "https://chatgpt.com/auth/ouroboros"
        }),
    );

    assert_eq!(
        app.take_open_url().as_deref(),
        Some("https://chatgpt.com/auth/ouroboros")
    );
    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("waiting for ChatGPT"), "{}", screen.text());
}

#[test]
fn dismissing_login_before_its_id_arrives_cancels_it_when_the_answer_lands() {
    let mut app = harness(false);
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    app.apply(ctrl('p'));
    assert!(matches!(app.overlay, Some(Overlay::Account(_))));

    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none());

    answer(
        &mut app,
        Tag::AccountLogin,
        json!({
            "type": "chatgpt",
            "loginId": "late-login",
            "authUrl": "https://chatgpt.com/auth/ouroboros"
        }),
    );

    let cancel = app
        .drain()
        .into_iter()
        .find(|call| call.method == "account.login.cancel")
        .expect("the invisible login is cancelled");
    assert_eq!(cancel.params["login_id"], "late-login");
    assert!(app.take_open_url().is_none());
}

#[test]
fn an_attached_client_uses_the_device_code_flow_for_the_runtime_host() {
    let mut app = harness(false);
    app.mode = Mode::Attached;
    app.apply(key(KeyCode::Enter));

    let login = app
        .drain()
        .into_iter()
        .find(|call| call.method == "account.login.start")
        .expect("a managed login call");

    assert_eq!(login.params, json!({ "flow": "device_code" }));

    answer(
        &mut app,
        Tag::AccountLogin,
        json!({
            "type": "chatgptDeviceCode",
            "loginId": "device-1",
            "verificationUrl": "https://auth.openai.com/codex/device",
            "userCode": "ABCD-1234"
        }),
    );

    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("ABCD-1234"), "{}", screen.text());
    assert!(screen.contains("runtime host"));
}

/// The code is the one string a person has to carry to another device. It used to be drawn
/// after the URL, and on an 80-column terminal a long verification URL wrapped far enough to
/// push it out of a fixed-height popup.
#[test]
fn the_device_code_is_readable_on_an_eighty_column_terminal() {
    let mut app = harness(false);
    app.mode = Mode::Attached;
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    answer(
        &mut app,
        Tag::AccountLogin,
        json!({
            "type": "chatgptDeviceCode",
            "loginId": "device-1",
            "verificationUrl": "https://auth.openai.com/codex/device?flow=ouroboros&\
                                request=01JQ8Z2K5V7N3M9P4T6R8W0Y2A&redirect=cli",
            "userCode": "ABCD-1234"
        }),
    );

    let screen = render(&mut app, 80, 24);

    assert!(screen.contains("ABCD-1234"), "{}", screen.text());
    assert!(screen.contains("press o to open"), "{}", screen.text());
    // Cut to one row rather than wrapped over three.
    assert!(
        screen.contains("https://auth.openai.com"),
        "{}",
        screen.text()
    );
    assert!(screen.row("Open").contains('…'), "{}", screen.text());

    // And `o` asks the driver to open it again, for a browser that never came forward.
    app.apply(key(KeyCode::Char('o')));
    assert!(app
        .take_open_url()
        .is_some_and(|url| url.starts_with("https://auth.openai.com/codex/device")));
}

#[test]
fn typing_and_enter_start_codex_in_the_current_folder_then_send_the_first_message() {
    let mut app = harness(true);
    type_text(&mut app, "fix the flaky reconnect test");
    app.apply(key(KeyCode::Enter));

    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a session start");

    assert_eq!(start.params["provider"], "codex");
    assert_eq!(start.params["workspace"], "/work/ouroboros");

    answer(
        &mut app,
        Tag::Start {
            plane: Plane::Interactive,
        },
        json!({ "_struct": "Ouroboros.Interactive.Ref", "id": "session-1" }),
    );

    let calls = app.drain();
    let first = calls
        .iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the first message");
    assert_eq!(first.params["input"], "fix the flaky reconnect test");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("a stable first-message id")
        .to_string();
    assert!(calls
        .iter()
        .any(|call| call.method == "interactive.subscribe"));
    assert_eq!(
        app.sessions.open.as_ref().map(|(_plane, id)| id.as_str()),
        Some("session-1")
    );
    assert!(app.sessions.composer.is_some());

    app.apply(Msg::Answer {
        tag: first.tag.clone(),
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "provider refused the turn".into(),
            data: None,
        })),
    });

    let composer = app.sessions.composer.as_ref().expect("the restored draft");
    assert_eq!(composer.editor.text(), "fix the flaky reconnect test");

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("an idempotent retry");
    assert_eq!(retry.params["turn_id"], turn_id);
    assert_eq!(retry.params["input"], "fix the flaky reconnect test");
}

#[test]
fn ctrl_p_opens_a_searchable_palette_with_coding_and_distribution_groups() {
    let mut app = harness(true);
    app.apply(ctrl('p'));

    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("Coding"), "{}", screen.text());
    assert!(screen.contains("Runtime & distribution"));
    assert!(screen.contains("Agents"));
    assert!(screen.contains("Settings"));

    type_text(&mut app, "dist");
    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("Runtime & distribution"));
    assert!(screen.contains("New session"));

    app.apply(key(KeyCode::Enter));
    assert_eq!(app.tab, Tab::Dashboard);
    assert!(app.overlay.is_none());
}

#[test]
fn new_session_is_a_reset_to_the_harness_not_an_advanced_form() {
    let mut app = harness(true);
    app.open_session(Plane::Interactive, "old-session".into());
    let _ = app.drain();

    app.apply(ctrl('p'));
    app.apply(key(KeyCode::Enter));

    assert_eq!(app.tab, Tab::Sessions);
    assert!(app.sessions.open.is_none());
    assert!(app.sessions.composer.is_none());
}

#[test]
fn switch_session_stays_inside_the_palette_flow() {
    let mut app = harness(true);
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "recent-session",
            "provider": "codex",
            "status": "idle",
            "updated_at": "2026-08-14T10:00:00Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.apply(ctrl('p'));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    assert!(matches!(app.overlay, Some(Overlay::SessionPicker { .. })));

    app.apply(key(KeyCode::Enter));
    assert_eq!(
        app.sessions.open.as_ref().map(|(_plane, id)| id.as_str()),
        Some("recent-session")
    );
}

#[test]
fn secondary_operator_panels_return_to_coding_with_escape() {
    let mut app = harness(true);
    app.apply(ctrl('p'));
    type_text(&mut app, "agents");
    app.apply(key(KeyCode::Enter));
    assert_eq!(app.tab, Tab::Agents);

    app.apply(key(KeyCode::Esc));
    assert_eq!(app.tab, Tab::Sessions);
}

#[test]
fn account_completion_closes_the_gate_without_restarting_the_client() {
    let mut app = harness(false);
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    answer(&mut app, Tag::Account, account(true));

    assert!(app.chatgpt_connected());
    assert!(app.overlay.is_none());
    assert_eq!(app.config.defaults.provider.as_deref(), Some("codex"));
    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Ready in this workspace"),
        "{}",
        screen.text()
    );
}

#[test]
fn the_session_composer_remains_open_after_sending() {
    let mut app = harness(true);
    app.open_session(Plane::Interactive, "session-1".into());
    let _ = app.drain();
    type_text(&mut app, "run the focused test");
    app.apply(key(KeyCode::Enter));

    let send = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("a message call");
    assert_eq!(send.params["input"], "run the focused test");
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .map(|composer| composer.editor.text()),
        Some("")
    );
}
