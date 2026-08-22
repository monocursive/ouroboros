//! The two doors out of the alternate screen, and the line that says the mouse was taken.
//!
//! `ouro` owns the screen, which buys a stable transcript and costs `Cmd+F`, tmux copy
//! mode, and drag-to-select. The field's verdict on paying that price silently is
//! unambiguous — it produced the loudest rendering complaints of 2026 — so this file pins
//! the three things that make it honest: `ctrl+x [` hands the conversation back to the
//! terminal's own scrollback, `ctrl+x v` hands it to the operator's editor, and a captured
//! mouse says so once.
//!
//! Driven the way `tests/ui.rs` drives everything: messages in, state out. The *effects* of
//! these two — leaving the alternate screen, running `$EDITOR` — belong to
//! [`ouro::ui::run`] and are unit-tested beside it; what a test can pin here is that the
//! App asks for exactly the right bytes, and that asking for them changes nothing else.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, Command, Msg, Overlay, Tab};
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

fn leader(app: &mut App, c: char) {
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(c)));
}

fn answer(app: &mut App, tag: ouro::ui::app::Tag, value: serde_json::Value) {
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

/// A resolved App with one interactive session open, watched, and holding a conversation.
fn conversing() -> App {
    let mut app = app(full_hello());

    answer(
        &mut app,
        ouro::ui::app::Tag::Account,
        json!({
            "account": serde_json::Value::Null,
            "requiresOpenaiAuth": true,
            "login": { "status": "idle" }
        }),
    );

    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        ouro::ui::app::Tag::Sessions(Plane::Interactive),
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
    answer(
        &mut app,
        ouro::ui::app::Tag::Sessions(Plane::Coding),
        json!([]),
    );

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
        1,
        "input_accepted",
        json!({ "text": "why does the CRLF fixture fail" }),
    );
    notify(
        &mut app,
        2,
        "output_text_final",
        json!({ "text": "Because the lexer only looks for a bare newline." }),
    );
    notify(
        &mut app,
        3,
        "tool_call",
        json!({ "call_id": "c1", "name": "read", "input": { "path": "src/lex.rs" } }),
    );
    notify(
        &mut app,
        4,
        "tool_result",
        json!({
            "call_id": "c1",
            "output": { "text": "one\ntwo\nthree\nfour\nfive\nsix" },
            "is_error": false
        }),
    );

    app.terminal_width = 100;
    app
}

/// The export both hatches are supposed to be carrying.
fn expected(app: &App) -> String {
    let watch = app.sessions.open_watch().expect("an open watch");
    export::transcript(watch, 100)
}

#[test]
fn the_scrollback_dump_carries_the_whole_transcript_at_the_current_width() {
    let mut app = conversing();
    let expected = expected(&app);

    leader(&mut app, '[');

    let dumped = app
        .take_scrollback_dump()
        .expect("ctrl+x [ asks the driver for a dump");

    assert_eq!(dumped, expected);

    // Draining is what hands it over: a second frame must not print it again.
    assert!(app.take_scrollback_dump().is_none());

    // And what it carries is the *expanded* conversation, not the pane's three lines.
    for whole in ["one", "two", "three", "four", "five", "six"] {
        assert!(dumped.contains(whole), "the tool result was cut: {dumped}");
    }
    assert!(
        dumped.contains("why does the CRLF fixture fail"),
        "{dumped}"
    );
    assert!(
        dumped.contains("tool Read src/lex.rs → 6 lines · completed"),
        "{dumped}"
    );
    assert!(
        dumped.contains("c1"),
        "the correlation id survives the dump: {dumped}"
    );
}

#[test]
fn the_editor_view_carries_the_same_bytes_and_leaves_the_draft_alone() {
    let mut app = conversing();

    // Something in the composer that must survive being ignored.
    type_text(&mut app, "keep me");

    let before = app
        .sessions
        .composer
        .as_ref()
        .map(|composer| composer.editor.text().to_string());

    assert_eq!(before.as_deref(), Some("keep me"), "the draft did not land");

    leader(&mut app, 'v');

    let viewed = app
        .take_transcript_view()
        .expect("ctrl+x v asks the driver for a viewer");

    assert_eq!(viewed, expected(&app));
    assert!(app.take_transcript_view().is_none());

    // The composer's own `$EDITOR` path is a *different* request, and this one must not
    // have made it: `ctrl+x v` reads history, it does not edit a prompt.
    assert!(
        app.take_external_editor().is_none(),
        "the transcript viewer was confused with the composer's editor"
    );

    let after = app
        .sessions
        .composer
        .as_ref()
        .map(|composer| composer.editor.text().to_string());

    assert_eq!(after, before, "opening the transcript changed the draft");
}

#[test]
fn both_hatches_are_reachable_from_the_palette_as_well_as_the_leader() {
    for (query, command) in [
        ("scrollback", Command::DumpScrollback),
        ("open transcript", Command::ViewTranscript),
    ] {
        let mut app = conversing();

        app.apply(ctrl('p'));
        type_text(&mut app, query);

        let palette = match &app.overlay {
            Some(Overlay::Commands(palette)) => palette,
            other => panic!("ctrl+p did not open the palette: {other:?}"),
        };

        assert_eq!(
            app.palette_commands(palette),
            vec![command],
            "{query:?} does not name exactly {command:?} in the palette"
        );

        app.apply(key(KeyCode::Enter));

        let asked = app
            .take_scrollback_dump()
            .or_else(|| app.take_transcript_view());

        assert!(asked.is_some(), "{command:?} asked the driver for nothing");
        assert!(
            app.overlay.is_none(),
            "{command:?} left the palette open over the screen it was about to leave"
        );
    }
}

#[test]
fn a_hatch_without_a_session_says_so_rather_than_dumping_a_header() {
    for chord in ['[', 'v'] {
        let mut app = app(full_hello());
        app.tab = Tab::Sessions;

        leader(&mut app, chord);

        assert!(app.take_scrollback_dump().is_none());
        assert!(app.take_transcript_view().is_none());
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|notice| notice.text.contains("open a session")),
            "ctrl+x {chord} said nothing: {:?}",
            app.notice
        );
    }
}

#[test]
fn the_mouse_hint_is_shown_once_per_operator_and_then_written_down() {
    let mut app = app(full_hello());
    app.mouse_hint = Some("mouse captured for scrolling · hold Shift to select text".into());

    assert!(!app.config.onboarding.mouse_hint_shown);

    // The first frame, without waiting for the wheel event that proves the operator has
    // already run into the problem.
    app.apply(Msg::Tick);

    assert!(
        app.notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("hold Shift to select text")),
        "{:?}",
        app.notice
    );
    assert!(app.config.onboarding.mouse_hint_shown);

    // And written down, so the next launch does not say it again.
    let saved = app.take_config_save().expect("the answer is persisted");
    assert!(saved.onboarding.mouse_hint_shown);

    // Neither another frame nor the wheel brings it back.
    app.notice = None;
    app.apply(Msg::Tick);
    app.apply(Msg::Scroll(-3));

    assert!(app.notice.is_none(), "{:?}", app.notice);
    assert!(app.take_config_save().is_none(), "a second save was queued");
}

#[test]
fn writing_the_marker_down_does_not_talk_over_the_hint_it_is_about() {
    // The hint and the write that remembers it happen on the same frame, and the driver
    // persists before it draws. A "saved …" line there would spend the one notice row on
    // a file the operator never asked to have written, and the hint would be gone before
    // anyone read it.
    let dir = std::env::temp_dir().join(format!("ouro-hint-notice-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let mut app = app(full_hello());
    app.config_path = Some(dir.join("config.toml"));
    app.mouse_hint = Some("mouse captured for scrolling · hold Shift to select text".into());

    app.apply(Msg::Tick);
    ouro::ui::persist(&mut app);

    assert!(
        app.notice
            .as_ref()
            .is_some_and(|notice| notice.text.contains("hold Shift to select text")),
        "the save talked over the hint: {:?}",
        app.notice
    );

    // Written all the same — the point is the silence, not the skipping.
    let text = std::fs::read_to_string(dir.join("config.toml")).expect("a written config");
    assert!(text.contains("mouse_hint_shown = true"), "{text}");

    // A save the operator *did* ask for still says where it went; that is pinned beside
    // the settings overlay in `tests/preferences.rs`, which is where the ask lives.

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_terminal_whose_mouse_was_left_alone_is_told_nothing() {
    // `[terminal] mouse = false`: the driver sets no hint, because there is nothing true to
    // say — selection already works and the wheel already belongs to the terminal.
    let mut app = app(full_hello());
    app.mouse_hint = None;

    app.apply(Msg::Tick);
    app.apply(Msg::Scroll(-3));

    assert!(app.notice.is_none(), "{:?}", app.notice);
    assert!(!app.config.onboarding.mouse_hint_shown);
    assert!(app.take_config_save().is_none());
}

#[test]
fn an_operator_who_has_already_seen_the_hint_never_sees_it_again() {
    let mut app = app(full_hello());
    app.mouse_hint = Some("mouse captured for scrolling · hold Fn to select text".into());
    app.config.onboarding.mouse_hint_shown = true;

    app.apply(Msg::Tick);
    app.apply(Msg::Scroll(-3));

    assert!(app.notice.is_none(), "{:?}", app.notice);
    assert!(app.take_config_save().is_none());
}
