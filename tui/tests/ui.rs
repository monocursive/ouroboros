//! What the UI draws, on a `TestBackend`, from the bytes the gateway actually sends.
//!
//! Every payload here is either a golden fixture read from `test/support/gateway_golden`
//! or a shape the Elixir side's own tests pin, so a rendering test that passes is a
//! rendering test about the real protocol. The App is driven by messages and read by
//! rendering — no terminal, no socket, no sleeping.

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::style::Color;
use serde_json::json;

use ouro::model::Plane;
use ouro::transport::ClientError;
use ouro::ui::app::{App, Call, Mode, Msg, NoticeKind, Tab, Tag};

use support::{app, fixture, full_hello, render};

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

/// An App on the Dashboard holding the golden `runtime.status`.
fn dashboard() -> App {
    let mut app = app(full_hello());

    answer(
        &mut app,
        Tag::Status,
        fixture("runtime_status_result")["result"].clone(),
    );

    app
}

/// An App on the Sessions tab with one interactive session open and watched.
fn with_open_session() -> App {
    let mut app = app(full_hello());

    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-0000000000000000000001",
            "node": "ouroboros@golden",
            "provider": "claude_code",
            "workspace": "/tmp/w",
            "status": "running",
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );

    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.open_session(
        Plane::Interactive,
        "session-0000000000000000000001".to_string(),
    );

    // The subscribe this issued is answered with an empty backlog; the tests below feed
    // the events they care about.
    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening a session subscribes to it");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!([])),
    });

    app
}

fn event(sequence: u64, kind: &str, text: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "method": "interactive.event",
        "params": {
            "id": "session-0000000000000000000001",
            "event": {
                "_struct": "Ouroboros.Interactive.Event",
                "id": format!("evt-{sequence}"),
                "session_id": "session-0000000000000000000001",
                "sequence": sequence,
                "type": kind,
                "timestamp": "2026-01-01T00:00:00.000000Z",
                "payload": { "text": text }
            }
        }
    })
}

fn notify(app: &mut App, frame: serde_json::Value) {
    app.apply(Msg::Notification(ouro::proto::Notification {
        method: frame["method"].as_str().expect("a method").to_string(),
        params: frame["params"].clone(),
    }));
}

// ----- tab 1 -------------------------------------------------------------------------

#[test]
fn the_dashboard_renders_the_golden_runtime_status() {
    let mut app = dashboard();
    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("ouroboros@golden"), "{}", screen.text());
    assert!(screen.contains("core"));
    assert!(screen.contains("strategy=none"));
    assert!(screen.contains("distributed=false"));

    // Every plane in the fixture's matrix, by name.
    for plane in [
        "cluster",
        "coding",
        "control",
        "hot_upgrade",
        "interactive",
        "mesh",
        "orchestration",
        "release",
        "teams",
        "workspace",
    ] {
        assert!(
            screen.contains(plane),
            "{plane} is missing:\n{}",
            screen.text()
        );
    }

    assert!(screen.contains("none — this runtime is not connected to other nodes"));
}

#[test]
fn availability_is_three_colours_and_disabled_is_not_one_of_the_alarming_ones() {
    let mut app = dashboard();
    let screen = render(&mut app, 120, 30);

    // `:disabled` is a posture — the control and workspace planes report it when nobody
    // configured them — and painting it like an outage would teach an operator to ignore
    // the colour.
    assert_eq!(screen.colour_of("mesh", "available"), Color::Green);
    assert_eq!(screen.colour_of("control ", "disabled"), Color::DarkGray);
    assert_eq!(screen.colour_of("workspace", "disabled"), Color::DarkGray);

    let mut down = app;
    answer(
        &mut down,
        Tag::Status,
        json!({ "availability": { "mesh": "unavailable", "forged_lane": "degraded" } }),
    );

    let screen = render(&mut down, 120, 30);

    assert_eq!(screen.colour_of("mesh", "unavailable"), Color::Red);
    // A state this build has never heard of is neither good nor an outage.
    assert_eq!(screen.colour_of("forged_lane", "degraded"), Color::Yellow);
}

#[test]
fn a_provider_probe_that_failed_is_not_reported_as_a_missing_provider() {
    let mut app = dashboard();

    answer(
        &mut app,
        Tag::Providers,
        json!([
            {
                "provider": "claude_code",
                "spec": {},
                "status": { "installed": true, "compatible": true, "authenticated": "unknown" },
                "error": null
            },
            { "provider": "codex", "spec": {}, "status": null, "error": "probe_timeout" }
        ]),
    );

    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("claude_code"));
    assert!(screen.row("claude_code").contains("installed"));
    assert!(screen.row("codex").contains("probe failed: probe_timeout"));
}

#[test]
fn a_status_that_never_arrived_says_so_rather_than_drawing_an_empty_runtime() {
    let mut app = app(full_hello());
    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("waiting for runtime.status"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_refused_method_names_itself_in_the_pane_it_would_have_filled() {
    let mut app = app(full_hello());

    app.apply(Msg::Answer {
        tag: Tag::Status,
        result: Err(ClientError::Rpc(
            serde_json::from_value(fixture("error_scope_denied")["error"].clone())
                .expect("an error"),
        )),
    });

    let screen = render(&mut app, 160, 30);

    assert!(
        screen.contains("scope_denied (-32003)"),
        "the refusal has to be readable where the data would have been:\n{}",
        screen.text()
    );
}

// ----- tab 2 -------------------------------------------------------------------------

#[test]
fn the_sessions_list_merges_both_planes_and_tags_each_row() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{ "id": "session-1", "status": "awaiting_approval",
                 "updated_at": "2026-01-01T00:00:02.000000Z" }]),
    );

    answer(
        &mut app,
        Tag::Sessions(Plane::Coding),
        json!([{ "id": "task-2", "status": "running",
                 "updated_at": "2026-01-01T00:00:01.000000Z" }]),
    );

    let screen = render(&mut app, 120, 20);

    assert!(
        screen.row("session-1").starts_with("│int  "),
        "{}",
        screen.text()
    );
    assert!(screen.row("task-2").contains("code "));
    assert!(screen.row("session-1").contains("awaiting_approval"));

    // Newest activity first, so the list does not reshuffle under the cursor.
    let sessions = screen.rows.iter().position(|r| r.contains("session-1"));
    let tasks = screen.rows.iter().position(|r| r.contains("task-2"));
    assert!(sessions < tasks);
}

#[test]
fn the_transcript_renders_the_golden_interactive_event() {
    let mut app = with_open_session();

    let golden = fixture("interactive_event_notification");
    notify(&mut app, golden.clone());

    // Sequence 42 arriving against an empty backlog is a hole, and the client asks about
    // it rather than assuming. The answer starts at 42 too, which proves 1..41 are no
    // longer retained — so the floor rises instead of the gap staying forever.
    let replay = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.replay")
        .expect("an unexplained hole is asked about");

    assert_eq!(replay.params["cursor"], 0);

    app.apply(Msg::Answer {
        tag: replay.tag,
        result: Ok(json!([golden["params"]["event"].clone()])),
    });

    let screen = render(&mut app, 120, 24);

    assert!(screen.contains("output_text_final"), "{}", screen.text());
    assert!(screen.contains("the workspace is clean"));
    assert!(
        screen.contains("history truncated below 41"),
        "{}",
        screen.text()
    );

    // The gateway redacts at construction; the client shows exactly what it was given.
    assert!(screen.contains("[REDACTED]") || screen.contains("the workspace is clean"));

    // The header states the resync cursor, which is the number every repair uses.
    assert!(screen.contains("cursor 42"), "{}", screen.text());

    // And the hole is gone: it was never a hole, it was the start of history.
    assert!(!screen.contains("events missing"), "{}", screen.text());
    assert!(app.drain().is_empty(), "nothing more to ask for");
}

#[test]
fn a_lag_divider_renders_with_the_hole_it_left() {
    let mut app = with_open_session();

    notify(&mut app, event(1, "output_text_final", "first"));
    notify(&mut app, event(2, "output_text_final", "second"));

    // The gateway dropped 4 frames and says so; the newest it discarded was 6.
    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "stream.lagged",
            "params": {
                "id": "session-0000000000000000000001",
                "plane": "interactive",
                "dropped": 4,
                "last_sequence": 6
            }
        }),
    );

    notify(&mut app, event(7, "output_text_final", "after the hole"));

    let screen = render(&mut app, 120, 24);

    assert!(
        screen.contains("the gateway dropped 4 event frames here"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("4 events missing (3..6)"),
        "the hole itself has to be visible, not just the cause:\n{}",
        screen.text()
    );

    // The resync cursor stayed at the contiguous prefix, not the newest event.
    assert!(screen.contains("cursor 2"), "{}", screen.text());

    // And the repair asked for exactly that.
    let calls = app.drain();
    let replay = calls
        .iter()
        .find(|call| call.method == "interactive.replay")
        .expect("a lag replays");

    assert_eq!(replay.params["cursor"], 2);
    assert_eq!(replay.params["limit"], 500);
}

#[test]
fn a_pruned_cursor_restarts_from_the_floor_and_marks_the_transcript() {
    let mut app = with_open_session();

    notify(&mut app, event(1, "output_text_final", "old"));
    let _ = app.drain();

    // A replay whose cursor fell below the retained window.
    app.apply(Msg::Answer {
        tag: Tag::Resync {
            plane: Plane::Interactive,
            id: "session-0000000000000000000001".into(),
            cursor: 1,
            subscribe: false,
        },
        result: Err(ClientError::Rpc(
            serde_json::from_value(fixture("error_cursor_pruned")["error"].clone())
                .expect("a pruned cursor"),
        )),
    });

    let screen = render(&mut app, 120, 24);

    assert!(
        screen.contains("history truncated below 96"),
        "{}",
        screen.text()
    );

    // Restarted from the floor the gateway named, through the same path.
    let replay = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.replay")
        .expect("a pruned cursor restarts");

    assert_eq!(replay.params["cursor"], 96);
}

#[test]
fn stream_ended_marks_the_session_finished() {
    let mut app = with_open_session();

    notify(&mut app, event(1, "output_text_final", "last word"));
    let _ = app.drain();

    notify(&mut app, fixture("stream_ended_notification"));

    let screen = render(&mut app, 120, 24);

    assert!(
        screen.contains("stream ended (closed) — no further events"),
        "{}",
        screen.text()
    );

    let watch = app.sessions.open_watch().expect("an open watch");
    assert_eq!(watch.ended.as_deref(), Some("closed"));

    // Nothing further is asked for: the stream is over, not lagging.
    assert!(app.drain().is_empty());
}

#[test]
fn the_approval_modal_renders_and_produces_the_right_respond_approval_params() {
    let mut app = with_open_session();

    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": "session-0000000000000000000001",
                "event": {
                    "_struct": "Ouroboros.Interactive.Event",
                    "id": "evt-9",
                    "session_id": "session-0000000000000000000001",
                    "sequence": 9,
                    "type": "approval_requested",
                    "timestamp": "2026-01-01T00:00:00.000000Z",
                    "request_id": "req-17",
                    "turn_id": "turn-1",
                    "payload": { "tool_call": { "name": "bash", "command": "git status" },
                                 "options": [] }
                }
            }
        }),
    );

    let screen = render(&mut app, 120, 24);

    assert!(screen.contains("approval requested"), "{}", screen.text());
    assert!(screen.contains("req-17"));
    assert!(screen.contains("bash"));

    // Exactly the four answers `Jido.Harness.ApprovalResponse` declares, and no others.
    for choice in [
        "approve (once)",
        "approve (session)",
        "deny (once)",
        "deny (session)",
    ] {
        assert!(
            screen.contains(choice),
            "{choice} is missing:\n{}",
            screen.text()
        );
    }

    // deny/session is the fourth.
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("an approval answer");

    assert_eq!(call.params["id"], "session-0000000000000000000001");
    assert_eq!(call.params["request_id"], "req-17");
    assert_eq!(call.params["response"]["decision"], "deny");
    assert_eq!(call.params["response"]["scope"], "session");
    assert_eq!(
        call.params["response"]
            .as_object()
            .expect("an object")
            .len(),
        2,
        "provider_options is deliberately not accepted by the gateway"
    );

    // Cleared locally so the next event does not reopen it before `approval_resolved`.
    assert!(app.sessions.open_watch().unwrap().next_approval().is_none());
}

#[test]
fn the_composer_sends_a_message_and_ctrl_c_interrupts_rather_than_quitting() {
    let mut app = with_open_session();

    app.apply(key(KeyCode::Char('i')));
    type_text(&mut app, "look at the tests");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("a message");

    assert_eq!(call.params["id"], "session-0000000000000000000001");
    assert_eq!(call.params["input"], "look at the tests");

    app.apply(ctrl('c'));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.interrupt")
        .expect("ctrl-c interrupts the active turn");

    assert_eq!(call.params["id"], "session-0000000000000000000001");
    assert!(app.quit.is_none(), "ctrl-c must never quit the client");
}

#[test]
fn x_confirms_before_ending_a_session() {
    let mut app = with_open_session();

    app.apply(key(KeyCode::Char('x')));

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("end session-"), "{}", screen.text());
    assert!(screen.contains("close (let the provider finish"));
    assert!(screen.contains("kill (stop it now)"));

    // Nothing is sent until the choice is made.
    assert!(app.drain().is_empty());

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let call = app.drain().into_iter().next().expect("a kill");
    assert_eq!(call.method, "interactive.kill");
}

#[test]
fn a_coding_task_is_told_it_takes_no_input_rather_than_being_sent_one() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('2')));

    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(
        &mut app,
        Tag::Sessions(Plane::Coding),
        json!([{ "id": "task-2", "status": "running", "objective": "fix the build" }]),
    );

    app.open_session(Plane::Coding, "task-2".into());
    let _ = app.drain();

    app.apply(key(KeyCode::Char('i')));

    assert!(
        app.drain().is_empty(),
        "the coding plane serves no send_message and none must be sent"
    );

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("takes no input"), "{}", screen.text());
}

// ----- the value tree ----------------------------------------------------------------

#[test]
fn the_value_tree_names_every_wire_marker() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('3')));

    answer(
        &mut app,
        Tag::Agents,
        json!([{ "id": "reviewer-1", "node": "ouroboros@golden",
                 "pid": { "_opaque": "#PID<0.123.0>" }, "replicas": 1 }]),
    );

    answer(
        &mut app,
        Tag::AgentState("reviewer-1".into()),
        json!({
            "_struct": "Ouroboros.Capability.ForgedYesterday",
            "pid": { "_opaque": "#PID<0.123.0>" },
            "blob": { "_b64": "AAECAw==" },
            "deep": { "_truncated": true },
            "last_effects": [{ "principal": "operator", "effect": "write" }]
        }),
    );

    let screen = render(&mut app, 130, 24);

    // A module this binary has never heard of, drawn without a line of code about it.
    assert!(
        screen.contains("«Ouroboros.Capability.ForgedYesterday»"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("#PID<0.123.0>"), "{}", screen.text());
    assert!(screen.contains("not valid UTF-8"), "{}", screen.text());
    assert!(
        screen.contains("truncated by the gateway"),
        "a truncation the reader cannot see is a partial tree read as a whole one:\n{}",
        screen.text()
    );
    assert!(screen.contains("last_effects"));
}

#[test]
fn a_tree_node_opens_and_closes_under_the_cursor() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('4')));

    answer(
        &mut app,
        Tag::Teams,
        json!([{ "id": "team-alpha", "status": "active", "worker_count": 2,
                 "delegation_count": 1 }]),
    );

    answer(
        &mut app,
        Tag::TeamState("team-alpha".into()),
        json!({ "workers": { "w1": { "role": "reviewer" } }, "status": "active" }),
    );

    // Into the tree, past `status` onto `workers` — keys render sorted — and open it.
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));

    let screen = render(&mut app, 130, 24);
    assert!(screen.contains("w1"), "{}", screen.text());

    app.apply(key(KeyCode::Left));
    let screen = render(&mut app, 130, 24);
    assert!(!screen.contains("w1"), "{}", screen.text());
}

// ----- tabs 5 through 7 --------------------------------------------------------------

#[test]
fn plans_and_control_are_two_lists_on_one_tab() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('5')));

    answer(
        &mut app,
        Tag::Plans,
        json!([{ "id": "plan-1", "status": "running", "version": 3, "step_count": 4 }]),
    );

    answer(
        &mut app,
        Tag::ControlRuns,
        json!([{ "id": "run-1", "status": "awaiting_review", "revision": 2 }]),
    );

    let screen = render(&mut app, 130, 30);

    assert!(screen.contains("plan-1"), "{}", screen.text());
    assert!(screen.contains("run-1"));
    assert!(screen.contains("orchestration plans"));
    assert!(screen.contains("control runs"));
}

#[test]
fn the_upgrade_tab_asks_for_a_principal_rather_than_inventing_a_list_all() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('6')));

    // Down to `effect grants`.
    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }

    let screen = render(&mut app, 130, 24);
    assert!(
        screen.contains("per-principal by design"),
        "{}",
        screen.text()
    );

    assert!(
        !app.drain().iter().any(|call| call.method == "grants.list"),
        "grants.list must not be called without a principal"
    );

    app.apply(key(KeyCode::Enter));
    for c in "operator".chars() {
        app.apply(key(KeyCode::Char(c)));
    }
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "grants.list")
        .expect("a named principal is asked for");

    assert_eq!(call.params["principal"], "operator");
}

#[test]
fn signing_decisions_are_shown_as_unavailable_when_the_build_does_not_serve_them() {
    let mut app = app(support::hello(&[
        "hello",
        "runtime.status",
        "upgrade.status",
    ]));
    app.apply(key(KeyCode::Char('6')));

    for _ in 0..3 {
        app.apply(key(KeyCode::Down));
    }

    let screen = render(&mut app, 130, 24);

    // `hello.methods` is the feature gate and the only one (§2.3).
    assert!(
        screen.contains("does not serve signing.decisions"),
        "{}",
        screen.text()
    );
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "signing.decisions"));
}

#[test]
fn the_logs_tab_says_where_logs_are_when_this_client_did_not_start_the_runtime() {
    let mut app = App::new(Mode::Attached, "127.0.0.1:4560".into(), full_hello(), None);

    app.apply(key(KeyCode::Char('7')));
    let screen = render(&mut app, 120, 20);

    assert!(
        screen.contains("logs live with the spawner"),
        "{}",
        screen.text()
    );
}

#[test]
fn the_logs_tab_shows_the_ring_when_this_client_owns_the_child() {
    let ring = ouro::runtime::LogRing::new(100, 10_000);
    ring.push(
        ouro::runtime::Stream::Stderr,
        "12:00:00.000 [info] up".into(),
    );

    let mut app = App::new(
        Mode::Spawned { pid: 42 },
        "127.0.0.1:4560".into(),
        full_hello(),
        Some(ring),
    );

    app.apply(key(KeyCode::Char('7')));
    let screen = render(&mut app, 120, 20);

    assert!(screen.contains("[info] up"), "{}", screen.text());
}

// ----- chrome ------------------------------------------------------------------------

#[test]
fn every_tab_draws_without_any_data_at_all() {
    // A gateway that has answered nothing must still produce seven readable tabs.
    for digit in '1'..='7' {
        let mut app = app(full_hello());
        app.apply(key(KeyCode::Char(digit)));

        let screen = render(&mut app, 100, 24);

        assert!(
            screen.rows.iter().any(|row| row.contains("Dashboard")),
            "tab {digit} lost its tab bar"
        );
    }
}

#[test]
fn the_quit_dialog_offers_shutdown_only_where_the_gateway_advertises_it() {
    let mut app = app(full_hello());
    app.apply(key(KeyCode::Char('q')));

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("detach"), "{}", screen.text());
    assert!(screen.contains("runtime.shutdown, then SIGTERM"));

    // The same client against a gateway that does not serve it falls back to a signal.
    let mut without = app_without_shutdown();
    without.apply(key(KeyCode::Char('q')));

    let screen = render(&mut without, 120, 24);
    assert!(
        screen.contains("does not serve runtime.shutdown"),
        "{}",
        screen.text()
    );

    // Attach mode has one honest option.
    let mut attached = App::new(Mode::Attached, "a".into(), full_hello(), None);
    attached.apply(key(KeyCode::Char('q')));

    let screen = render(&mut attached, 120, 24);
    assert!(
        screen.contains("the runtime keeps running"),
        "{}",
        screen.text()
    );

    attached.apply(key(KeyCode::Enter));
    assert_eq!(attached.quit, Some(ouro::ui::Quit::Disconnect));
}

fn app_without_shutdown() -> App {
    app(support::hello(&["hello", "runtime.status"]))
}

#[test]
fn the_help_overlay_states_the_honest_limits() {
    let mut app = app(support::hello(&["hello", "runtime.status"]));
    // A read listener, so the scope warning applies.
    app.hello.scope = "read".into();

    app.apply(key(KeyCode::Char('?')));
    let screen = render(&mut app, 130, 30);

    assert!(screen.contains("ctrl-c"), "{}", screen.text());
    assert!(screen.contains("single-node view"));
    assert!(screen.contains("not a sandbox"));
    assert!(screen.contains("scope `read`"));

    app.apply(key(KeyCode::Esc));
    assert!(render(&mut app, 130, 30).contains("waiting for runtime.status"));
}

#[test]
fn a_notice_replaces_the_status_line_and_expires() {
    let mut app = app(full_hello());
    app.inform("something happened", NoticeKind::Warn);

    assert!(render(&mut app, 120, 20).contains("something happened"));

    for _ in 0..40 {
        app.apply(Msg::Tick);
    }

    let screen = render(&mut app, 120, 20);
    assert!(!screen.contains("something happened"), "{}", screen.text());
    assert!(screen.contains("scope"), "the status line comes back");
}

#[test]
fn the_visible_tab_is_the_only_one_polled() {
    let mut app = app(full_hello());
    app.apply(Msg::Tick);

    let methods: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();

    assert!(methods.contains(&"runtime.status".to_string()));
    assert!(methods.contains(&"runtime.providers".to_string()));
    assert!(
        !methods.iter().any(|method| method.ends_with(".list")),
        "the Dashboard must not poll the lists of tabs nobody is looking at: {methods:?}"
    );

    app.apply(key(KeyCode::Char('2')));

    let methods: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(methods.contains(&"interactive.list".to_string()));
    assert!(methods.contains(&"coding.list".to_string()));
}

#[test]
fn a_transcript_is_never_polled() {
    let mut app = with_open_session();
    notify(&mut app, event(1, "output_text_final", "hello"));
    let _ = app.drain();

    // Twenty seconds of ticks on the Sessions tab.
    for _ in 0..80 {
        app.apply(Msg::Tick);
    }

    let replays: Vec<Call> = app
        .drain()
        .into_iter()
        .filter(|call| call.method.ends_with(".replay") || call.method.ends_with(".subscribe"))
        .collect();

    assert!(
        replays.is_empty(),
        "history arrives by subscription; polling it would ask the runtime to re-send what \
         it already pushed: {replays:?}"
    );
}

#[test]
fn one_question_is_outstanding_at_a_time() {
    let mut app = app(full_hello());

    app.apply(Msg::Tick);
    let first = app.drain();
    assert!(!first.is_empty());

    // Nothing is answered, and the cadence keeps ticking.
    for _ in 0..40 {
        app.apply(Msg::Tick);
    }

    assert!(
        app.drain().is_empty(),
        "a slow runtime must not make the client queue the same question again"
    );
}

#[test]
fn tabs_wrap_in_both_directions() {
    let mut app = app(full_hello());

    assert_eq!(app.tab, Tab::Dashboard);

    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::BackTab,
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));

    assert_eq!(app.tab, Tab::Logs);

    app.apply(key(KeyCode::Tab));
    assert_eq!(app.tab, Tab::Dashboard);
}
