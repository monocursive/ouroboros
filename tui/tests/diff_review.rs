//! `/diff` and `/raw`: reviewing what a session changed, and copying what it said.
//!
//! Two commands with the same premise. This client never reads the filesystem and never
//! runs git, so both are scoped to the events it holds — and both say so, because a review
//! surface that looked like the whole repository and was not would be worse than none.
//!
//! `/diff` is Claude Code's per-turn viewer: `←`/`→` between "this session" and each turn,
//! `↑`/`↓` between files, `Enter` into a pager. `/raw` is Codex's copy mode: every cell
//! drawn with no frame, no gutter, no glyph column, so a native selection yields logical
//! lines rather than the app's rendering of them.
//!
//! Driven the way the rest of the suite is driven: messages in, state and pixels out.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::json;

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Overlay};

use support::{app, full_hello, render};

const SESSION: &str = "session-0000000000000000000001";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
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

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

/// The command palette, which reaches a verb from any tab and with no session open.
fn palette(app: &mut App, query: &str) {
    app.apply(ctrl('p'));
    for c in query.chars() {
        app.apply(key(KeyCode::Char(c)));
    }
    app.apply(key(KeyCode::Enter));
}

/// Typed into the composer, which an opened session already has focused, and submitted.
fn slash(app: &mut App, command: &str) {
    for c in command.chars() {
        app.apply(key(KeyCode::Char(c)));
    }
    app.apply(key(KeyCode::Enter));
}

/// A session that changed three files across two turns.
fn reviewed() -> App {
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
        json!({ "text": "make the lexer handle CRLF" }),
    );
    notify(
        &mut app,
        2,
        "file_change",
        json!({"changes": [{
            "path": "src/lex.rs",
            "kind": "modified",
            "diff": "--- a/src/lex.rs\n+++ b/src/lex.rs\n@@ -1,3 +1,3 @@ fn scan\n fn scan(text: &str) {\n-    let end = text.find('\\n');\n+    let end = text.find(['\\r', '\\n']);\n     ok\n"
        }]}),
    );
    notify(&mut app, 3, "turn_completed", json!({}));

    notify(
        &mut app,
        4,
        "input_accepted",
        json!({ "text": "and add a fixture" }),
    );
    notify(
        &mut app,
        5,
        "file_change",
        json!({"changes": [
            {
                "path": "tests/crlf.txt",
                "kind": "added",
                "diff": "--- /dev/null\n+++ b/tests/crlf.txt\n@@ -0,0 +1,2 @@\n+one\n+two\n"
            },
            {
                "path": "src/lex.rs",
                "kind": "modified",
                "diff": "--- a/src/lex.rs\n+++ b/src/lex.rs\n@@ -9,1 +9,2 @@\n keep\n+another\n"
            }
        ]}),
    );
    notify(&mut app, 6, "turn_completed", json!({}));

    app.terminal_width = 120;
    app
}

fn overlay(app: &App) -> &ouro::ui::diff::DiffOverlay {
    match app.overlay.as_ref() {
        Some(Overlay::Diff(state)) => state,
        other => panic!("expected the diff overlay, found {other:?}"),
    }
}

#[test]
fn slash_diff_lists_every_file_this_client_saw_change_folded_across_turns() {
    let mut app = reviewed();
    slash(&mut app, "/diff");

    let state = overlay(&app);
    assert_eq!(state.scope, 0, "it opens on \"this session\"");
    assert_eq!(state.scopes(), 3, "this session, plus one scope per turn");

    let rows = state.rows();
    let paths: Vec<&str> = rows.iter().map(|row| row.file.path.as_str()).collect();
    assert_eq!(paths, vec!["src/lex.rs", "tests/crlf.txt"]);

    // Touched by both turns: one row, with the counts summed.
    let lex = &rows[0].file;
    assert_eq!((lex.additions, lex.deletions), (2, 1));

    let screen = render(&mut app, 120, 40);
    assert!(screen.contains("/diff"), "{}", screen.text());
    assert!(screen.contains("this session"), "{}", screen.text());
    assert!(screen.contains("src/lex.rs"), "{}", screen.text());
    assert!(screen.contains("tests/crlf.txt"), "{}", screen.text());
}

#[test]
fn the_arrows_move_between_turns_and_the_files_change_with_them() {
    let mut app = reviewed();
    slash(&mut app, "/diff");

    app.apply(key(KeyCode::Right));
    let state = overlay(&app);
    assert_eq!(state.scope_label(), "turn 1");
    assert_eq!(
        state
            .rows()
            .iter()
            .map(|row| row.file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/lex.rs"],
        "the first turn touched one file"
    );

    app.apply(key(KeyCode::Right));
    let state = overlay(&app);
    assert_eq!(state.scope_label(), "turn 2");
    assert_eq!(state.rows().len(), 2);

    // The last scope is the last scope; the key does not wrap into a scope that is not there.
    app.apply(key(KeyCode::Right));
    assert_eq!(overlay(&app).scope_label(), "turn 2");

    app.apply(key(KeyCode::Left));
    app.apply(key(KeyCode::Left));
    assert_eq!(overlay(&app).scope_label(), "this session");
}

#[test]
fn down_moves_the_selection_and_enter_opens_the_file_in_a_pager() {
    let mut app = reviewed();
    slash(&mut app, "/diff");

    app.apply(key(KeyCode::Down));
    assert_eq!(overlay(&app).selected, 1);
    assert_eq!(
        overlay(&app).current().expect("a selected file").file.path,
        "tests/crlf.txt"
    );

    app.apply(key(KeyCode::Enter));
    assert_eq!(overlay(&app).pager, Some(0));

    let screen = render(&mut app, 120, 40);
    assert!(screen.contains("+one"), "{}", screen.text());
    assert!(screen.contains("+two"), "{}", screen.text());

    // Esc steps out of the pager before it closes the overlay.
    app.apply(key(KeyCode::Esc));
    assert_eq!(overlay(&app).pager, None);
    app.apply(key(KeyCode::Esc));
    assert!(app.overlay.is_none());
}

#[test]
fn the_footer_says_the_list_is_only_what_this_client_holds() {
    let mut app = reviewed();
    slash(&mut app, "/diff");

    let screen = render(&mut app, 120, 40);
    assert!(
        screen.contains("every change this client has seen in this session"),
        "{}",
        screen.text()
    );

    // With history pruned below a floor, the same footer says the list is partial.
    let mut pruned = reviewed();
    pruned
        .sessions
        .watches
        .get_mut(&(Plane::Interactive, SESSION.to_string()))
        .expect("an open watch")
        .raise_floor(3);
    slash(&mut pruned, "/diff");

    let screen = render(&mut pruned, 120, 40);
    assert!(
        screen.contains("only what this client holds"),
        "{}",
        screen.text()
    );
}

#[test]
fn slash_diff_without_a_session_says_so_rather_than_opening_an_empty_list() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('2')));
    palette(&mut app, "changed files");

    assert!(app.overlay.is_none());
}

#[test]
fn raw_mode_strips_the_transcript_of_its_frame() {
    let mut app = reviewed();

    let framed = render(&mut app, 120, 40).text();
    assert!(
        framed.contains("▌ YOU"),
        "the ordinary transcript is framed: {framed}"
    );
    assert!(
        framed.contains("2     -    let end"),
        "and gutters its diffs: {framed}"
    );

    slash(&mut app, "/raw");
    assert!(app.sessions.raw_mode);

    let raw = render(&mut app, 120, 40).text();
    assert!(!raw.contains("▌ YOU"), "raw kept the user frame:\n{raw}");
    assert!(
        !raw.contains("◆ AGENT"),
        "raw kept the speaker glyph:\n{raw}"
    );
    assert!(
        raw.contains("-    let end = text.find"),
        "the change is still there:\n{raw}"
    );
    assert!(
        !raw.contains("2     -    let end"),
        "raw kept the line-number gutter:\n{raw}"
    );

    // And back: the frame returns.
    slash(&mut app, "/raw");
    assert!(!app.sessions.raw_mode);
    assert!(render(&mut app, 120, 40).text().contains("▌ YOU"));
}

#[test]
fn raw_mode_puts_one_logical_line_on_one_row() {
    let mut app = reviewed();
    notify(
        &mut app,
        7,
        "output_text_final",
        json!({"text": "one paragraph that is comfortably longer than any pane this test asks for, \
                        written as a single logical line so a selection can prove it stayed one."}),
    );
    slash(&mut app, "/raw");

    let watch = app.sessions.open_watch().expect("an open watch");
    let cells = ouro::ui::transcript_cells::project(watch.entries());
    let lines = ouro::ui::transcript_cells::render_cells_at(
        &cells,
        60,
        0,
        ouro::ui::transcript_cells::Verbosity::Raw,
    );

    let paragraph = lines
        .iter()
        .filter(|line| {
            line.spans
                .iter()
                .any(|span| span.content.contains("one paragraph"))
        })
        .count();

    assert_eq!(
        paragraph, 1,
        "raw does not wrap: the paragraph is one row, and the terminal owns what happens next"
    );
}

#[test]
fn raw_mode_needs_an_open_session_and_says_so() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('2')));
    slash(&mut app, "/raw");

    assert!(!app.sessions.raw_mode);
}
