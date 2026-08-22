//! The footer with a brain (A7), the scriptable status line, notifications, and the
//! capability-driven chrome that only advertises what the open session can do (B0).
//!
//! Every session payload here is shaped like `Interactive.State.public/1` — `options`
//! carrying `approval_mode`, `sandbox_mode`, `model`, and the `capabilities` map the
//! runtime derives from the transport a session selected, plus the `usage` account it
//! folds from `:usage` and `:run_completed`. The point of the file is that nothing in the
//! footer comes from anywhere else.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{json, Value};

use ouro::config::{NotifyMode, NotifyWhen};
use ouro::model::{ApprovalMode, Capability, Plane, ProviderEntry, SandboxMode, SessionInfo};
use ouro::proto::Notification;
use ouro::ui::app::{App, ComposerVerb, Msg, Overlay, Tag};
use ouro::ui::notify::{self, Activity, Channel, Signal, Terminal};

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

fn answer(app: &mut App, tag: Tag, value: Value) {
    app.apply(Msg::Answer {
        tag,
        result: Ok(value),
    });
}

fn resolved() -> App {
    let mut app = app(full_hello());
    answer(
        &mut app,
        Tag::Account,
        json!({ "account": Value::Null, "requiresOpenaiAuth": true }),
    );
    app
}

/// The capability map for a Codex app-server session: everything native, and the one
/// transport in the bundle that can both steer and ask.
fn native_capabilities() -> Value {
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

/// A managed transport: one process per turn, no approvals channel, no steer. This is
/// what `claude`, `gemini`, `amp`, `grok`, and `zai` actually get.
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

fn session(status: &str, options: Value, usage: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": "session-a7",
        "status": status,
        "provider": "codex",
        "workspace": "/Users/operator/code/ouroboros",
        "updated_at": "2026-01-01T00:00:00.000000Z",
        "options": options,
        "usage": usage,
    })
}

fn options(capabilities: Value) -> Value {
    json!({
        "approval_mode": "auto_edit",
        "sandbox_mode": "workspace_write",
        "model": "gpt-5-codex",
        "capabilities": capabilities,
    })
}

fn usage() -> Value {
    json!({
        "input_tokens": 40_000,
        "output_tokens": 2_500,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
        "total_tokens": 42_500,
        "cost_usd": 0.42,
        "turns_with_usage": 3,
        "last": {}
    })
}

/// An App with one open interactive session, subscribed and holding `events`.
fn opened(status: &str, options: Value, usage: Value, events: Vec<Value>) -> App {
    let mut app = resolved();
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([session(status, options, usage)]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(Plane::Interactive, "session-a7".into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");

    answer(&mut app, subscribe.tag, json!(events));

    // Opening an interactive session opens its composer, and a composer owns every
    // printable key. Closed directly rather than with `Esc`, which on an idle session with
    // an empty draft leaves the *session* rather than the composer (M2 §1.5).
    app.sessions.composer = None;

    app.apply(Msg::Tick);
    app
}

fn event(sequence: u64, kind: &str, payload: Value, timestamp: &str) -> Value {
    // `request_id` is a top-level field of `Ouroboros.Interactive.Event`, and it is what
    // makes an `approval_requested` a *pending* approval rather than a transcript row.
    let request_id = payload.get("request_id").cloned().unwrap_or(Value::Null);

    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "type": kind,
        "timestamp": timestamp,
        "payload": payload,
        "turn_id": "turn-1",
        "request_id": request_id,
        "provider": "codex"
    })
}

/// A live stream frame, as `interactive.event` delivers it.
fn stream(kind: &str) -> Msg {
    Msg::Notification(Notification {
        method: "interactive.event".into(),
        params: json!({
            "id": "session-a7",
            "event": event(
                99,
                kind,
                json!({ "request_id": "req-live", "tool_call": { "command": "cargo test" } }),
                "2026-01-01T00:00:10.000000Z",
            )
        }),
    })
}

/// The footer is the last row of the frame.
fn footer(screen: &Screen) -> String {
    screen.rows.last().cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// (a) the footer
// ---------------------------------------------------------------------------------------

/// The whole row, cell by cell, so that a change to the layout is a change someone chose.
///
/// The two halves are compared separately: the gap between them is whatever
/// right-alignment leaves over at that width, which is arithmetic rather than a decision.
#[test]
fn the_footer_snapshot_at_three_widths() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());

    // B9. This operator has sent no prompts, so the row carries the "new here" pointer at
    // `?` — and it outranks the leader and quit hints, which are also on `?` and in the
    // palette. Three prompts in, the row is the one below.
    assert_eq!(
        columns(&footer(&render(&mut app, 160, 24))),
        (
            "● LIVE · OWN RUNTIME · operate · 127.0.0.1:4560 · gpt-5-codex · ⏵⏵ auto-edit · \
             workspace-write · 42.5k tokens · $0.42"
                .to_string(),
            "ctrl+p commands · ? new here".to_string()
        )
    );

    app.config.onboarding.prompts_sent = 3;

    assert_eq!(
        columns(&footer(&render(&mut app, 160, 24))),
        (
            "● LIVE · OWN RUNTIME · operate · 127.0.0.1:4560 · gpt-5-codex · ⏵⏵ auto-edit · \
             workspace-write · 42.5k tokens · $0.42"
                .to_string(),
            "ctrl+p commands · ctrl+x leader".to_string()
        )
    );

    // 112: the runtime identity yields first — it is on the Dashboard and in the header,
    // and the session's spend is not anywhere else.
    assert_eq!(
        columns(&footer(&render(&mut app, 112, 24))),
        (
            "● LIVE · gpt-5-codex · ⏵⏵ auto-edit · workspace-write · 42.5k tokens · $0.42"
                .to_string(),
            "ctrl+p commands".to_string()
        )
    );

    // 80: one column, and the spend goes before the mode does.
    assert_eq!(
        columns(&footer(&render(&mut app, 80, 24))),
        (
            "● LIVE · gpt-5-codex · ⏵⏵ auto-edit · workspace-write · ctrl+p commands".to_string(),
            String::new()
        )
    );
}

/// What the composer's `/` completion offers for `prefix`, on the open session.
fn slash_completions(app: &mut App, prefix: &str) -> Vec<String> {
    // The tick is what refreshes the catalog from the open session's capabilities.
    app.apply(Msg::Tick);
    app.apply(key(KeyCode::Char('i')));
    assert!(app.sessions.composer.is_some(), "`i` opens the composer");

    for character in prefix.chars() {
        app.apply(key(KeyCode::Char(character)));
    }

    let offered = app
        .sessions
        .composer
        .as_ref()
        .and_then(|composer| composer.editor.completion())
        .map(|menu| {
            menu.items
                .iter()
                .map(|item| item.value.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    app.sessions.composer = None;
    offered
}

/// A rendered footer split at the run of padding between its two halves.
fn columns(row: &str) -> (String, String) {
    let row = row.trim_end();

    match row.find("   ") {
        Some(index) => (
            row[..index].to_string(),
            row[index..].trim_start().to_string(),
        ),
        None => (row.to_string(), String::new()),
    }
}

#[test]
fn an_idle_session_states_its_model_mode_and_spend_at_every_width() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());

    for width in [160, 112] {
        let screen = render(&mut app, width, 24);
        let row = footer(&screen);

        assert!(row.contains("gpt-5-codex"), "{width}: {row}");
        assert!(
            row.contains("⏵⏵ auto-edit · workspace-write"),
            "{width}: {row}"
        );
        assert!(row.contains("42.5k tokens"), "{width}: {row}");
        assert!(row.contains("$0.42"), "{width}: {row}");
        // Idle: nothing is running, so nothing can be interrupted.
        assert!(!row.contains("interrupt"), "{width}: {row}");
        assert!(!row.contains("Working"), "{width}: {row}");
        assert!(row.contains("ctrl+p commands"), "{width}: {row}");
    }

    // 80 columns is below the two-column branch: the facts take the row and only the one
    // key that always leads somewhere stays with them.
    let screen = render(&mut app, 80, 24);
    let row = footer(&screen);
    assert!(row.contains("⏵⏵ auto-edit"), "{row}");
    assert!(row.contains("ctrl+p commands"), "{row}");
    assert!(!row.contains("interrupt"), "{row}");
    assert!(row.chars().count() <= 80, "{row}");
}

#[test]
fn a_working_session_carries_an_elapsed_timer_and_offers_esc_interrupt() {
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock")
        .as_secs()
        - 247;

    // 4m 07s ago, in the wire's own timestamp format.
    let timestamp = wire_timestamp(started);

    let mut app = opened(
        "running",
        options(native_capabilities()),
        usage(),
        vec![event(1, "turn_started", json!({}), &timestamp)],
    );

    for width in [160, 112] {
        let screen = render(&mut app, width, 24);
        let row = footer(&screen);

        assert!(row.contains("Working 4m 0"), "{width}: {row}");
        assert!(row.contains("esc interrupt"), "{width}: {row}");
    }

    let row = footer(&render(&mut app, 80, 24));
    assert!(row.contains("Working 4m 0"), "{row}");
}

#[test]
fn a_managed_session_never_advertises_a_key_it_cannot_honour() {
    let mut app = opened(
        "running",
        options(managed_capabilities()),
        usage(),
        Vec::new(),
    );

    // `interrupt: "process"` is truthy — killing the child *is* an interrupt — so the hint
    // stays. What must not appear is anything gated on the two capabilities this transport
    // answers `false` for.
    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("esc interrupt"), "{row}");

    app.apply(ctrl_x());
    let screen = render(&mut app, 160, 30);
    assert!(!screen.contains("steer"), "{}", screen.text());
    assert!(!screen.contains("approval"), "{}", screen.text());
}

#[test]
fn a_pending_approval_and_a_queue_are_counted_in_the_footer() {
    let mut app = opened(
        "awaiting_approval",
        options(native_capabilities()),
        usage(),
        vec![
            event(
                1,
                "queue_changed",
                json!({ "queued_turns": 3 }),
                "2026-01-01T00:00:01.000000Z",
            ),
            event(
                2,
                "approval_requested",
                json!({ "request_id": "req-1", "tool_call": { "command": "rm -rf /" } }),
                "2026-01-01T00:00:02.000000Z",
            ),
        ],
    );

    // The event opened the modal; the footer is behind it and still says what is pending.
    app.overlay = None;

    // The count outranks every other fact at every width: it is the one thing on the row
    // that is waiting on the person reading it.
    for width in [160, 112, 80] {
        let row = footer(&render(&mut app, width, 24));
        assert!(row.contains("1 approval"), "{width}: {row}");
    }

    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("3 queued"), "{row}");
    assert!(row.contains("esc interrupt"), "{row}");
}

#[test]
fn a_fact_the_runtime_did_not_report_is_absent_rather_than_guessed() {
    let mut app = opened(
        "idle",
        json!({ "capabilities": native_capabilities() }),
        Value::Null,
        Vec::new(),
    );

    let row = footer(&render(&mut app, 160, 24));

    // No model, no approval mode, no sandbox, no usage: nothing was reported, so nothing
    // is drawn. What must never appear is a default this client invented.
    assert!(!row.contains("prompt"), "{row}");
    assert!(!row.contains("auto-edit"), "{row}");
    assert!(!row.contains("tokens"), "{row}");
    assert!(!row.contains('$'), "{row}");
    assert!(row.contains("ctrl+p commands"), "{row}");
}

#[test]
fn the_model_falls_back_to_the_transcripts_run_started() {
    let mut app = opened(
        "idle",
        json!({
            "approval_mode": "prompt",
            "capabilities": native_capabilities(),
        }),
        Value::Null,
        vec![event(
            1,
            "run_started",
            json!({ "model": "claude-sonnet-4-6", "tools": [] }),
            "2026-01-01T00:00:01.000000Z",
        )],
    );

    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("claude-sonnet-4-6"), "{row}");
    assert!(row.contains("⏸ prompt"), "{row}");
}

#[test]
fn a_notice_still_owns_the_row_it_always_did() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());
    app.inform("something happened", ouro::ui::app::NoticeKind::Warn);

    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("something happened"), "{row}");
    assert!(!row.contains("gpt-5-codex"), "{row}");
}

#[test]
fn the_context_percentage_waits_for_a_window_the_runtime_has_not_reported_yet() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());
    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("42.5k tokens"), "{row}");
    assert!(!row.contains('%'), "{row}");

    // The hook: the moment a runtime reports one, the meter appears without a client-side
    // table of model windows.
    let mut with_window = usage();
    with_window["context_window"] = json!(200_000);
    let mut app = opened(
        "idle",
        options(native_capabilities()),
        with_window,
        Vec::new(),
    );

    let row = footer(&render(&mut app, 160, 24));
    assert!(row.contains("42.5k tokens · 21%"), "{row}");
}

// ---------------------------------------------------------------------------------------
// (b) the scriptable status line
// ---------------------------------------------------------------------------------------

#[test]
fn the_statusline_payload_carries_the_documented_shape() {
    let app = opened(
        "running",
        options(native_capabilities()),
        usage(),
        Vec::new(),
    );
    let payload = app.statusline_payload();

    assert_eq!(payload["session"]["id"], "session-a7");
    assert_eq!(payload["session"]["provider"], "codex");
    assert_eq!(payload["session"]["model"], "gpt-5-codex");
    assert_eq!(
        payload["session"]["workspace"],
        "/Users/operator/code/ouroboros"
    );
    assert_eq!(payload["session"]["machine"], Value::Null);
    assert_eq!(payload["session"]["status"], "running");
    assert_eq!(payload["modes"]["approval_mode"], "auto_edit");
    assert_eq!(payload["modes"]["sandbox_mode"], "workspace_write");
    assert_eq!(payload["usage"]["total_tokens"], 42_500);
    assert_eq!(payload["usage"]["input_tokens"], 40_000);
    assert_eq!(payload["cost_usd"], 0.42);
    assert_eq!(payload["elapsed_ms"], Value::Null);
    assert_eq!(payload["connection"]["state"], "live");

    // Fixed keys with nulls, not absent keys: a script reading `.session.model` gets a
    // null on a session that never reported one rather than two spellings of silence.
    for key in [
        "session",
        "modes",
        "usage",
        "cost_usd",
        "elapsed_ms",
        "connection",
    ] {
        assert!(payload.get(key).is_some(), "{key} missing from {payload}");
    }

    let empty = resolved();
    let payload = empty.statusline_payload();
    assert_eq!(payload["session"], Value::Null);
    assert_eq!(payload["modes"], Value::Null);
    assert_eq!(payload["usage"], Value::Null);
}

#[test]
fn the_statusline_is_off_until_configured_and_then_debounced() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());

    // Off unless configured.
    app.apply(Msg::Tick);
    assert!(app.take_statusline_request().is_none());

    app.config.statusline.command = Some("printf ok".into());

    // The first tick notices a change; the request waits for the debounce window.
    app.apply(Msg::Tick);
    assert!(
        app.take_statusline_request().is_none(),
        "300ms of debounce has not elapsed after one 80ms tick"
    );

    for _ in 0..4 {
        app.apply(Msg::Tick);
    }

    let (command, payload) = app
        .take_statusline_request()
        .expect("the settled facts dispatch");
    assert_eq!(command, "printf ok");
    assert_eq!(payload["session"]["id"], "session-a7");

    // One at a time: nothing else goes out while that invocation is outstanding.
    for _ in 0..10 {
        app.apply(Msg::Tick);
    }
    assert!(app.take_statusline_request().is_none());

    app.apply(Msg::StatusLine(Ok("main · 3 files".into())));
    assert_eq!(app.statusline().line(), Some("main · 3 files"));

    // Unchanged facts do not re-run it, however many ticks pass.
    for _ in 0..40 {
        app.apply(Msg::Tick);
    }
    assert!(
        app.take_statusline_request().is_none(),
        "an unchanged object must not re-run the command"
    );

    // A changed fact does, after the same window.
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([session("running", options(native_capabilities()), usage())]),
    );
    for _ in 0..5 {
        app.apply(Msg::Tick);
    }
    let (_command, payload) = app
        .take_statusline_request()
        .expect("a changed status re-runs it");
    assert_eq!(payload["session"]["status"], "running");
}

#[test]
fn a_running_turns_clock_does_not_re_run_the_command_every_tick() {
    let started = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock")
        .as_secs()
        - 10;

    let mut app = opened(
        "running",
        options(native_capabilities()),
        usage(),
        vec![event(
            1,
            "turn_started",
            json!({}),
            &wire_timestamp(started),
        )],
    );
    app.config.statusline.command = Some("cat".into());

    for _ in 0..6 {
        app.apply(Msg::Tick);
    }

    let (_command, payload) = app.take_statusline_request().expect("the first dispatch");
    assert!(
        payload["elapsed_ms"]
            .as_u64()
            .is_some_and(|ms| ms >= 10_000),
        "the elapsed time is still handed to the command: {payload}"
    );

    app.apply(Msg::StatusLine(Ok("row".into())));

    // The clock has moved on every one of these ticks, and it is deliberately not part of
    // the change key — otherwise the command would never settle and would fork a process
    // twelve times a second.
    for _ in 0..40 {
        app.apply(Msg::Tick);
    }
    assert!(app.take_statusline_request().is_none());
}

#[test]
fn the_statusline_row_is_drawn_above_the_footer_and_a_failure_is_reported_once() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());
    app.config.statusline.command = Some("printf ok".into());
    app.apply(Msg::StatusLine(Ok("\x1b[32m main \x1b[0m· 3 files".into())));

    let screen = render(&mut app, 160, 24);
    let rows = &screen.rows;
    let scripted = rows[rows.len() - 2].clone();

    assert!(scripted.contains("main"), "{}", screen.text());
    assert!(scripted.contains("3 files"), "{}", screen.text());
    assert!(
        !scripted.contains('\u{1b}') && !scripted.contains('['),
        "escapes must not reach the buffer: {scripted:?}"
    );
    assert!(footer(&screen).contains("gpt-5-codex"), "{}", screen.text());

    // A failure leaves the row absent and says so exactly once.
    app.apply(Msg::StatusLine(Err("exited with 3".into())));
    assert_eq!(app.statusline().line(), None);
    assert!(app
        .notice
        .as_ref()
        .is_some_and(|notice| notice.text.contains("statusline command failed")));

    app.notice = None;
    app.apply(Msg::StatusLine(Err("exited with 3".into())));
    assert!(app.notice.is_none(), "a broken command is reported once");
}

// ---------------------------------------------------------------------------------------
// (c) notifications
// ---------------------------------------------------------------------------------------

#[test]
fn the_notification_matrix_is_mode_times_when_times_focus() {
    let iterm = Terminal {
        program: Some("iTerm.app".into()),
        term: Some("xterm-256color".into()),
    };
    let plain = Terminal {
        program: Some("Apple_Terminal".into()),
        term: Some("xterm-256color".into()),
    };

    let cases: [(NotifyMode, NotifyWhen, bool, Option<Channel>); 8] = [
        (
            NotifyMode::Auto,
            NotifyWhen::Unfocused,
            false,
            Some(Channel::Osc9),
        ),
        (NotifyMode::Auto, NotifyWhen::Unfocused, true, None),
        (
            NotifyMode::Auto,
            NotifyWhen::Always,
            true,
            Some(Channel::Osc9),
        ),
        (
            NotifyMode::Bell,
            NotifyWhen::Unfocused,
            false,
            Some(Channel::Bell),
        ),
        (
            NotifyMode::Bell,
            NotifyWhen::Always,
            true,
            Some(Channel::Bell),
        ),
        (
            NotifyMode::Osc9,
            NotifyWhen::Always,
            true,
            Some(Channel::Osc9),
        ),
        (NotifyMode::Off, NotifyWhen::Always, false, None),
        (NotifyMode::Off, NotifyWhen::Unfocused, false, None),
    ];

    for (mode, when, focused, expected) in cases {
        let mut app = opened(
            "running",
            options(native_capabilities()),
            usage(),
            Vec::new(),
        );
        app.terminal = iterm.clone();
        app.config.notifications.mode = Some(mode.as_str().into());
        app.config.notifications.when = Some(when.as_str().into());
        app.apply(Msg::Focus(focused));
        app.apply(stream("approval_requested"));

        let fired = app.take_notifications();

        match expected {
            Some(channel) => {
                assert_eq!(
                    fired,
                    vec![(channel, Signal::NeedsInput)],
                    "{mode:?} × {when:?} × focused={focused}"
                );
            }
            None => assert!(
                fired.is_empty(),
                "{mode:?} × {when:?} × focused={focused} fired {fired:?}"
            ),
        }
    }

    // `auto` on a terminal that does not render OSC 9 falls back to the bell.
    let mut app = opened(
        "running",
        options(native_capabilities()),
        usage(),
        Vec::new(),
    );
    app.terminal = plain;
    app.apply(Msg::Focus(false));
    app.apply(stream("turn_completed"));
    assert_eq!(
        app.take_notifications(),
        vec![(Channel::Bell, Signal::TurnDone)]
    );
}

#[test]
fn nothing_but_an_approval_or_a_turn_terminator_rings() {
    for kind in [
        "output_text_delta",
        "tool_call",
        "usage",
        "session_ready",
        "queue_changed",
    ] {
        let mut app = opened(
            "running",
            options(native_capabilities()),
            usage(),
            Vec::new(),
        );
        app.apply(Msg::Focus(false));
        app.apply(stream(kind));

        assert!(
            app.take_notifications().is_empty(),
            "{kind} must not ring the terminal"
        );
    }

    for kind in ["turn_completed", "turn_failed", "turn_interrupted"] {
        let mut app = opened(
            "running",
            options(native_capabilities()),
            usage(),
            Vec::new(),
        );
        app.apply(Msg::Focus(false));
        app.apply(stream(kind));

        assert_eq!(
            app.take_notifications().len(),
            1,
            "{kind} is a turn reaching its end"
        );
    }
}

#[test]
fn a_keystroke_and_a_replayed_backlog_never_ring() {
    let mut app = resolved();
    app.terminal = Terminal {
        program: Some("iTerm.app".into()),
        term: None,
    };
    app.apply(Msg::Focus(false));

    for code in [
        KeyCode::Char('2'),
        KeyCode::Char('i'),
        KeyCode::Char('a'),
        KeyCode::Char('s'),
        KeyCode::Esc,
        KeyCode::Enter,
    ] {
        app.apply(key(code));
        assert!(
            app.take_notifications().is_empty(),
            "{code:?} rang the bell"
        );
    }

    // Opening a session replays its history through `interactive.subscribe`'s answer, not
    // through the live stream. Three days of approvals must not become three days of
    // bells.
    let mut app = opened(
        "idle",
        options(native_capabilities()),
        usage(),
        vec![
            event(
                1,
                "approval_requested",
                json!({ "request_id": "old-1" }),
                "2026-01-01T00:00:01.000000Z",
            ),
            event(
                2,
                "turn_completed",
                json!({}),
                "2026-01-01T00:00:02.000000Z",
            ),
        ],
    );
    app.apply(Msg::Focus(false));

    assert!(
        app.take_notifications().is_empty(),
        "a replayed backlog is history, not news"
    );
}

#[test]
fn the_window_title_follows_the_sessions_state() {
    let mut app = opened("idle", options(native_capabilities()), usage(), Vec::new());
    app.apply(Msg::Tick);

    assert_eq!(app.activity(), Activity::Idle);
    assert_eq!(
        app.take_title().as_deref(),
        Some("ouro · ◇ ouroboros"),
        "an idle session names the workspace basename"
    );

    // Unchanged state does not re-emit the escape sequence.
    app.apply(Msg::Tick);
    assert_eq!(app.take_title(), None);

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([session("running", options(native_capabilities()), usage())]),
    );
    app.apply(Msg::Tick);
    assert_eq!(app.activity(), Activity::Working);
    assert_eq!(app.take_title().as_deref(), Some("ouro · ✦ ouroboros"));

    app.apply(stream("approval_requested"));
    app.apply(Msg::Tick);
    assert_eq!(app.activity(), Activity::NeedsInput);
    assert_eq!(app.take_title().as_deref(), Some("ouro · ✋ ouroboros"));
}

#[test]
fn osc9_carries_a_body_and_the_bell_carries_nothing_that_could_escape() {
    // The bytes themselves, so a change to them is a deliberate change.
    assert_eq!(Signal::NeedsInput.text(), "ouro: waiting for your approval");
    assert_eq!(Signal::TurnDone.text(), "ouro: the turn finished");
    assert_eq!(
        notify::title(Activity::Working, Some("/srv/app")),
        "ouro · ✦ app"
    );
}

// ---------------------------------------------------------------------------------------
// (d) B0 — capability-driven chrome
// ---------------------------------------------------------------------------------------

#[test]
fn steer_is_offered_where_the_transport_declares_it_and_nowhere_else() {
    let mut native = opened(
        "running",
        options(native_capabilities()),
        usage(),
        Vec::new(),
    );
    assert!(native.steer_offered());

    // The four places the verb is advertised: `/` completion in the composer, the command
    // palette, the leader overlay, and the key itself.
    assert!(
        slash_completions(&mut native, "/steer")
            .iter()
            .any(|name| name == "/steer"),
        "the verb completes where the transport declares it"
    );

    native.apply(ctrl('p'));
    let screen = render(&mut native, 160, 30);
    assert!(
        screen.contains("Steer the running turn"),
        "{}",
        screen.text()
    );
    native.overlay = None;

    native.apply(ctrl_x());
    let screen = render(&mut native, 160, 30);
    assert!(screen.contains("steer"), "{}", screen.text());

    let mut managed = opened(
        "running",
        options(managed_capabilities()),
        usage(),
        Vec::new(),
    );
    assert!(!managed.steer_offered());

    assert!(
        !slash_completions(&mut managed, "/steer")
            .iter()
            .any(|name| name == "/steer"),
        "a transport that cannot steer must not complete `/steer`"
    );

    managed.apply(ctrl('p'));
    let screen = render(&mut managed, 160, 30);
    assert!(
        !screen.contains("Steer the running turn"),
        "{}",
        screen.text()
    );
    managed.overlay = None;

    // And the key itself refuses, naming the transport, rather than sending a call the
    // runtime answers `{:error, :unsupported}`.
    managed.apply(key(KeyCode::Char('s')));
    let notice = managed.notice.as_ref().expect("a refusal");
    assert!(notice.text.contains("cannot be steered"), "{}", notice.text);
    assert!(notice.text.contains("managed"), "{}", notice.text);
    assert!(
        managed.sessions.composer.is_none(),
        "the composer must not open in a verb the session cannot take"
    );
    assert!(
        !managed
            .drain()
            .iter()
            .any(|call| call.method.contains("steer")),
        "no steer call is made"
    );
}

#[test]
fn the_approval_key_says_why_a_managed_session_will_never_open_that_modal() {
    let mut managed = opened(
        "running",
        options(managed_capabilities()),
        usage(),
        Vec::new(),
    );
    assert!(!managed.approvals_offered());

    managed.apply(key(KeyCode::Char('a')));
    let notice = managed.notice.as_ref().expect("a refusal");
    assert!(
        notice.text.contains("no approvals channel"),
        "{}",
        notice.text
    );

    let mut native = opened(
        "running",
        options(native_capabilities()),
        usage(),
        Vec::new(),
    );
    assert!(native.approvals_offered());
    native.apply(key(KeyCode::Char('a')));
    assert!(native
        .notice
        .as_ref()
        .is_some_and(|notice| notice.text.contains("not waiting on an approval")));
}

#[test]
fn an_undeclared_capability_is_unknown_and_changes_nothing() {
    // An older gateway that answers no `capabilities` map at all. Nothing may be hidden
    // on its silence — that would be this client inventing a ceiling.
    let mut app = opened(
        "running",
        json!({ "approval_mode": "prompt", "model": "gpt-5-codex" }),
        usage(),
        Vec::new(),
    );

    assert!(app.steer_offered());
    assert!(app.approvals_offered());
    assert!(app.multimodal_offered());
    assert!(app.interrupt_offered());

    app.apply(ctrl('p'));
    let screen = render(&mut app, 160, 30);
    assert!(
        screen.contains("Steer the running turn"),
        "{}",
        screen.text()
    );
}

#[test]
fn the_new_session_dialog_greys_a_mode_the_provider_cannot_take() {
    let mut app = resolved();
    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Providers, providers());

    app.apply(key(KeyCode::Char('n')));

    // `claude`. Its spec normalizes `approval_mode`, so the schema would accept `prompt` —
    // and X1 is that its managed transport has no channel to ask through, so the runtime
    // refuses it. Its sandbox is argv and takes every value.
    let Some(Overlay::New(dialog)) = app.overlay.as_mut() else {
        panic!("the new-session dialog opens");
    };
    dialog.provider = 0;
    dialog.approval = 2; // prompt
    dialog.sandbox = 3; // workspace_write

    let screen = render(&mut app, 160, 30);
    assert!(
        screen.row("approval").contains("not offered by claude"),
        "{}",
        screen.text()
    );
    assert!(
        screen.row("approval").contains("no approvals channel"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.row("files").contains("not offered"),
        "claude's sandbox is argv and takes every value:\n{}",
        screen.text()
    );

    // `codex` app-server takes both.
    let Some(Overlay::New(dialog)) = app.overlay.as_mut() else {
        panic!("the dialog is still open");
    };
    dialog.provider = 1;

    let screen = render(&mut app, 160, 30);
    assert!(
        !screen.row("approval").contains("not offered"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.row("files").contains("not offered"),
        "{}",
        screen.text()
    );

    // `pi` constrains the values themselves: no `prompt`, no `workspace_write`.
    let Some(Overlay::New(dialog)) = app.overlay.as_mut() else {
        panic!("the dialog is still open");
    };
    dialog.provider = 2;

    let screen = render(&mut app, 160, 30);
    assert!(
        screen
            .row("approval")
            .contains("takes only default, auto_approve"),
        "{}",
        screen.text()
    );
    assert!(
        screen
            .row("files")
            .contains("takes only default, read_only, unrestricted"),
        "{}",
        screen.text()
    );

    // A value it does take is not greyed, and a refused one is still selectable — the
    // runtime is the authority on whether a start succeeds.
    let Some(Overlay::New(dialog)) = app.overlay.as_mut() else {
        panic!("the dialog is still open");
    };
    dialog.approval = 4; // auto_approve
    dialog.sandbox = 2; // read_only

    let screen = render(&mut app, 160, 30);
    assert!(
        !screen.row("approval").contains("not offered"),
        "{}",
        screen.text()
    );
    assert!(
        !screen.row("files").contains("not offered"),
        "{}",
        screen.text()
    );
}

/// `runtime.providers` as the gateway Wire-encodes it: the whole `AdapterSpec` beside the
/// probe, including `normalized_options`, `normalized_values`, and `session_transports`.
///
/// The three entries are the three shapes that exist in the bundle today, copied from the
/// adapters themselves — `claude` (managed, normalizes both modes, constrains neither, no
/// approvals channel), `codex` (app-server, everything), and `pi` (RPC, the only steer,
/// and the only spec that constrains the mode *values*).
fn providers() -> Value {
    json!([
        {
            "provider": "claude",
            "status": { "installed": true, "compatible": true, "authenticated": true },
            "spec": {
                "provider": "claude",
                "name": "Claude Code",
                "normalized_options": [
                    "model", "provider_session_id", "max_turns", "system_prompt",
                    "allowed_tools", "disallowed_tools", "add_dirs", "mcp_config",
                    "approval_mode", "sandbox_mode", "reasoning_effort"
                ],
                "normalized_values": {},
                "default_session_transport": "stream_json_resume",
                "session_transports": [{
                    "name": "stream_json_resume",
                    "adapter": "Jido.Harness.SessionAdapters.Managed",
                    "session_options": "adapter",
                    "configuration_options": ["model", "reasoning_effort", "approval_mode", "sandbox_mode"],
                    "capabilities": {
                        "transport": "stream_json_resume",
                        "process": "per_turn",
                        "multi_turn": "managed",
                        "follow_up": "managed",
                        "interrupt": "process",
                        "approvals": false,
                        "steer": false,
                        "multimodal": false,
                        "dynamic_model": "managed",
                        "dynamic_configuration": "managed"
                    }
                }]
            }
        },
        {
            "provider": "codex",
            "status": { "installed": true, "compatible": true, "authenticated": true },
            "spec": {
                "provider": "codex",
                "name": "Codex",
                "normalized_options": ["model", "approval_mode", "sandbox_mode", "reasoning_effort"],
                "normalized_values": {},
                "default_session_transport": "app_server",
                "session_transports": [{
                    "name": "app_server",
                    "adapter": "Ouroboros.Provider.Session.Dialect.Codex",
                    "session_options": "adapter",
                    "capabilities": {
                        "transport": "app_server",
                        "process": "persistent",
                        "multi_turn": "native",
                        "follow_up": "native",
                        "interrupt": "native",
                        "approvals": "native",
                        "steer": false,
                        "multimodal": "native",
                        "dynamic_model": "native",
                        "dynamic_configuration": "native"
                    }
                }]
            }
        },
        {
            "provider": "pi",
            "status": { "installed": true, "compatible": true, "authenticated": true },
            "spec": {
                "provider": "pi",
                "name": "Pi",
                "normalized_options": [
                    "model", "provider_session_id", "system_prompt", "allowed_tools",
                    "disallowed_tools", "approval_mode", "sandbox_mode", "attachments",
                    "reasoning_effort"
                ],
                "normalized_values": {
                    "approval_mode": ["default", "auto_approve"],
                    "sandbox_mode": ["default", "read_only", "unrestricted"]
                },
                "default_session_transport": "rpc",
                "session_transports": [{
                    "name": "rpc",
                    "adapter": "Jido.Harness.SessionAdapters.PiRPC",
                    "session_options": [
                        "model", "provider_session_id", "system_prompt", "allowed_tools",
                        "disallowed_tools", "approval_mode", "sandbox_mode",
                        "reasoning_effort", "env"
                    ],
                    "capabilities": {
                        "transport": "rpc",
                        "process": "persistent",
                        "multi_turn": "native",
                        "follow_up": "managed",
                        "interrupt": "native",
                        "approvals": false,
                        "steer": "native",
                        "multimodal": false,
                        "dynamic_model": "native",
                        "dynamic_configuration": "native"
                    }
                }]
            }
        }
    ])
}

#[test]
fn the_provider_spec_answers_which_modes_a_session_could_take() {
    let entries = ProviderEntry::decode_list(&providers());
    let (claude, codex, pi) = (&entries[0], &entries[1], &entries[2]);

    // X1: `prompt` promises a human is asked, and a managed transport has no channel.
    assert!(claude
        .approval_mode_refusal(ApprovalMode::Prompt)
        .is_some_and(|reason| reason.contains("no approvals channel")));
    // Everything else about claude is unconstrained.
    assert_eq!(claude.approval_mode_refusal(ApprovalMode::AutoEdit), None);
    assert_eq!(claude.approval_mode_refusal(ApprovalMode::Default), None);
    for mode in SandboxMode::ALL {
        assert_eq!(claude.sandbox_mode_refusal(mode), None, "{mode:?}");
    }

    for mode in ApprovalMode::ALL {
        assert_eq!(codex.approval_mode_refusal(mode), None, "{mode:?}");
    }
    for mode in SandboxMode::ALL {
        assert_eq!(codex.sandbox_mode_refusal(mode), None, "{mode:?}");
    }

    // Pi's spec constrains the values.
    assert!(pi
        .approval_mode_refusal(ApprovalMode::Prompt)
        .is_some_and(|reason| reason.contains("takes only default, auto_approve")));
    assert_eq!(pi.approval_mode_refusal(ApprovalMode::AutoApprove), None);
    assert!(pi
        .sandbox_mode_refusal(SandboxMode::WorkspaceWrite)
        .is_some());
    assert_eq!(pi.sandbox_mode_refusal(SandboxMode::ReadOnly), None);

    assert_eq!(
        codex.session_capabilities().approvals,
        Capability::Yes("native".into())
    );
    assert_eq!(claude.session_capabilities().steer, Capability::No);
    assert_eq!(
        pi.session_capabilities().steer,
        Capability::Yes("native".into())
    );

    // A spec this client cannot resolve greys nothing rather than guessing.
    let unknown = ProviderEntry::decode_list(&json!([{ "provider": "invented", "spec": {} }]));
    assert_eq!(unknown[0].approval_mode_refusal(ApprovalMode::Prompt), None);
    assert_eq!(unknown[0].sandbox_mode_refusal(SandboxMode::ReadOnly), None);
    assert!(!unknown[0].session_capabilities().declared);
}

// ---------------------------------------------------------------------------------------
// tolerant decoding
// ---------------------------------------------------------------------------------------

#[test]
fn capabilities_decode_tolerantly_and_absence_is_never_a_refusal() {
    // No `options` at all.
    let bare = decode(json!({ "id": "s", "status": "idle" }));
    assert!(!bare.capabilities.declared);
    assert_eq!(bare.capabilities.steer, Capability::Unknown);
    assert!(bare.capabilities.steer.offered());
    assert!(!bare.capabilities.steer.declared());
    assert_eq!(bare.usage, None);

    // A partial map, plus a key from a later runtime and a shape this build cannot read.
    let partial = decode(json!({
        "id": "s",
        "status": "idle",
        "options": { "capabilities": {
            "transport": "acp",
            "steer": false,
            "approvals": "native",
            "telepathy": "native",
            "multimodal": { "images": true }
        }}
    }));

    assert!(partial.capabilities.declared);
    assert_eq!(partial.capabilities.transport.as_deref(), Some("acp"));
    assert_eq!(partial.capabilities.steer, Capability::No);
    assert!(!partial.capabilities.steer.offered());
    assert_eq!(
        partial.capabilities.approvals,
        Capability::Yes("native".into())
    );
    // Absent from the map: unknown, so still offered.
    assert_eq!(partial.capabilities.interrupt, Capability::Unknown);
    assert!(partial.capabilities.interrupt.offered());
    // An unreadable shape is unknown too — never a silent `false`.
    assert_eq!(partial.capabilities.multimodal, Capability::Unknown);
    assert!(partial.capabilities.multimodal.offered());

    // A non-object where the map should be.
    let wrong = decode(json!({
        "id": "s", "status": "idle", "options": { "capabilities": "yes" }
    }));
    assert!(!wrong.capabilities.declared);
    assert!(wrong.capabilities.steer.offered());
}

#[test]
fn usage_decodes_tolerantly_and_an_unreported_counter_is_not_a_zero() {
    let partial = decode(json!({
        "id": "s",
        "status": "idle",
        "usage": { "total_tokens": 17, "cost_usd": Value::Null, "invented": true }
    }));

    let usage = partial.usage.expect("a usage map is a usage map");
    assert_eq!(usage.total_tokens, Some(17));
    assert_eq!(usage.cost_usd, None);
    assert_eq!(usage.input_tokens, None);
    assert_eq!(usage.context_window, None);

    // No map at all: a session that has spent nothing and one whose spend was never
    // reported are different facts.
    assert_eq!(decode(json!({ "id": "s", "status": "idle" })).usage, None);
    assert_eq!(
        decode(json!({ "id": "s", "status": "idle", "usage": 4 })).usage,
        None
    );
}

#[test]
fn the_options_projection_is_read_without_refusing_a_session_over_it() {
    let full = decode(json!({
        "id": "s",
        "status": "idle",
        "options": {
            "approval_mode": "auto_approve",
            "sandbox_mode": "unrestricted",
            "model": " gpt-5 ",
            "a_key_from_a_later_runtime": {"deeply": ["nested"]}
        }
    }));

    assert_eq!(full.approval_mode.as_deref(), Some("auto_approve"));
    assert_eq!(full.sandbox_mode.as_deref(), Some("unrestricted"));
    assert_eq!(full.model.as_deref(), Some("gpt-5"));

    // Blank is absent, not `""`.
    let blank = decode(json!({
        "id": "s", "status": "idle", "options": { "model": "   " }
    }));
    assert_eq!(blank.model, None);
}

fn decode(value: Value) -> SessionInfo {
    SessionInfo::decode(Plane::Interactive, &value).expect("an addressable session")
}

// ---------------------------------------------------------------------------------------

fn ctrl(c: char) -> Msg {
    Msg::Key(KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn ctrl_x() -> Msg {
    ctrl('x')
}

/// A unix timestamp in the format `Gateway.Wire` emits for a `DateTime`.
fn wire_timestamp(seconds: u64) -> String {
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);

    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000000Z",
        rest / 3_600,
        (rest / 60) % 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the inverse of the conversion the client uses.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };

    (year + i64::from(month <= 2), month, day)
}

/// A composer verb this file never sends, named so the import stays honest about what the
/// gating above is about.
#[allow(dead_code)]
const STEER: ComposerVerb = ComposerVerb::Steer;
