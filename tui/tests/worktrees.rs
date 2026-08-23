//! D7 from the client's side: asking for a worktree, and saying which one a session got.
//!
//! Plus the five-line follow-up the accessibility slice left behind — `/theme` was
//! reachable only as a typed verb, and the palette is where a verb without a key is found.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::{Plane, StartRequest};
use ouro::ui::app::{App, Command, Msg, Overlay, Tag};

use support::{app, full_hello, render, Screen};

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

/// A session the runtime gave a worktree, as `interactive.list` reports one: `branch` is
/// `null` because the runtime runs `git worktree add --detach`.
fn session_with_worktree(retired: Option<&str>) -> Value {
    let mut worktree = json!({
        "path": "/data/worktrees/abc/session-w",
        "root": "/data/worktrees/abc/session-w",
        "branch": Value::Null,
        "base_commit": "9f2c1ab4de550711",
        "repository": "/Users/operator/code/ouroboros"
    });

    if let Some(retired) = retired {
        worktree["retired"] = json!(retired);
    }

    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-w",
        "status": "idle",
        "provider": "native",
        "node": "ouroboros@alpha",
        "workspace": "/data/worktrees/abc/session-w",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "worktree_requested": true,
        "worktree": worktree,
        "options": {"approval_mode": "auto_edit", "sandbox_mode": "workspace_write"}
    })
}

fn opened(rows: Value) -> App {
    let mut app = app(full_hello());

    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));

    answer(&mut app, Tag::Sessions(Plane::Interactive), rows);
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, "session-w".into());
    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening subscribes");
    answer(&mut app, subscribe.tag, json!([]));
    app.apply(Msg::Tick);

    app
}

fn screen(app: &mut App) -> Screen {
    render(app, 180, 48)
}

// ---------------------------------------------------------------------------------------
// asking for one
// ---------------------------------------------------------------------------------------

/// A strict boolean, and sent only when true: `interactive.start`'s `worktree` refuses
/// `"true"` and `1`, and an unasked-for `false` on every start would be this client
/// stating a default the plane already has.
#[test]
fn the_start_request_sends_worktree_only_when_it_was_asked_for() {
    let plain = StartRequest {
        provider: "native".into(),
        workspace: "/w".into(),
        ..StartRequest::new(Plane::Interactive)
    };
    let params = plain.params().expect("a valid start");
    assert!(
        params.get("worktree").is_none(),
        "an ordinary start says nothing about worktrees: {params}"
    );

    let isolated = StartRequest {
        worktree: true,
        ..plain
    };
    let params = isolated.params().expect("a valid start");
    assert_eq!(params["worktree"], Value::Bool(true));
}

#[test]
fn the_new_session_dialog_toggles_the_worktree_row() {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    // `ctrl+x N` is the dialog with every option on it.
    app.apply(modified(KeyCode::Char('x'), KeyModifiers::CONTROL));
    app.apply(key(KeyCode::Char('N')));

    assert!(matches!(app.overlay, Some(Overlay::New(_))));

    let text = screen(&mut app).text();
    assert!(text.contains("worktree"), "{text}");
    assert!(
        text.contains("the workspace itself, which takes an exclusive lease"),
        "the default says what it costs: {text}"
    );

    // Walk down to the row and flip it.
    for _ in 0..12 {
        if let Some(Overlay::New(dialog)) = app.overlay.as_ref() {
            if dialog.field == ouro::ui::app::NewField::Worktree {
                break;
            }
        }
        app.apply(key(KeyCode::Down));
    }

    app.apply(key(KeyCode::Right));

    let Some(Overlay::New(dialog)) = app.overlay.as_ref() else {
        panic!("the dialog is still open");
    };
    assert!(dialog.request.worktree);

    let text = screen(&mut app).text();
    assert!(
        text.contains("its own git worktree, so two sessions can share a repository"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------------------
// saying which one a session got
// ---------------------------------------------------------------------------------------

#[test]
fn a_session_in_a_worktree_wears_the_badge_in_the_header_and_the_rail() {
    let mut app = opened(json!([session_with_worktree(None)]));
    let text = screen(&mut app).text();

    // `git worktree add --detach` names no branch, so the badge falls back to the short
    // base commit rather than inventing one.
    assert!(text.contains("\u{2387} 9f2c1ab4"), "{text}");
    assert!(text.contains("WORKTREE"), "{text}");
}

/// A worktree the runtime removed — or kept because it still held uncommitted work — is
/// not somewhere this session is still editing, and the panel says so.
#[test]
fn a_retired_worktree_says_it_is_retired_instead_of_showing_a_live_branch() {
    let mut app = opened(json!([session_with_worktree(Some("kept"))]));
    let text = screen(&mut app).text();

    assert!(text.contains("9f2c1ab4 (kept)"), "{text}");
}

#[test]
fn a_session_without_a_worktree_draws_no_badge_at_all() {
    let mut app = opened(json!([{
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-w",
        "status": "idle",
        "provider": "native",
        "node": "ouroboros@alpha",
        "workspace": "/Users/operator/code/ouroboros",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "options": {"approval_mode": "auto_edit"}
    }]));

    let text = screen(&mut app).text();
    assert!(!text.contains('\u{2387}'), "{text}");
    assert!(
        !text.contains("WORKTREE"),
        "a row saying \"WORKTREE no\" would be narrating a default: {text}"
    );
}

// ---------------------------------------------------------------------------------------
// `/theme` in the palette
// ---------------------------------------------------------------------------------------

#[test]
fn the_theme_command_is_in_the_palette_and_cycles_from_there() {
    let mut app = opened(json!([session_with_worktree(None)]));

    app.apply(modified(KeyCode::Char('p'), KeyModifiers::CONTROL));
    type_text(&mut app, "theme");

    let palette = match &app.overlay {
        Some(Overlay::Commands(palette)) => palette,
        other => panic!("ctrl+p did not open the palette: {other:?}"),
    };

    assert_eq!(
        app.palette_commands(palette),
        vec![Command::Theme],
        "\"theme\" names exactly the theme row"
    );

    let before = app.config.theme.name();
    app.apply(key(KeyCode::Enter));

    assert!(app.overlay.is_none(), "the palette closes on the choice");
    assert_ne!(
        app.config.theme.name(),
        before,
        "the palette row cycles, exactly as the verb does"
    );
}
