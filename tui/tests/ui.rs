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

use ouro::fleet::{Member, Profile};
use ouro::model::Plane;
use ouro::proto::{ErrorCode, RpcError};
use ouro::transport::ClientError;
use ouro::ui::app::{
    App, Call, ComposerVerb, FleetJob, MachineCandidate, Mode, Msg, NewField, NoticeKind, Overlay,
    Tab, Tag,
};
use ouro::ui::theme;

use support::{app, fixture, full_hello, render};

fn fleet_profile() -> Profile {
    Profile {
        schema: 1,
        fleet_id: "fleet-test-0123456789".into(),
        name: "Studio fleet".into(),
        machine: "studio".into(),
        host: "studio.test".into(),
        node: "ouro@studio.test".into(),
        role: "core".into(),
        members: vec![
            Member {
                machine: "studio".into(),
                host: "studio.test".into(),
                node: "ouro@studio.test".into(),
            },
            Member {
                machine: "mini".into(),
                host: "mini.test".into(),
                node: "ouro@mini.test".into(),
            },
            Member {
                machine: "workstation".into(),
                host: "workstation.test".into(),
                node: "ouro@workstation.test".into(),
            },
        ],
        roster_revision: 1,
        tombstones: Vec::new(),
        gateway_port: 47_123,
        epmd_port: 14_123,
        dist_port_min: 43_700,
        dist_port_max: 43_729,
    }
}

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

fn modified(code: KeyCode, modifiers: KeyModifiers) -> Msg {
    Msg::Key(KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    })
}

fn apply_leader(app: &mut App, c: char) {
    app.apply(ctrl('x'));
    app.apply(key(KeyCode::Char(c)));
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

/// An App whose `account.read` has already been answered — as "no ChatGPT subscription, and
/// this install wants one".
///
/// Every real client has that answer within the first frames, and until it arrives the home
/// composer owns the keyboard rather than letting a keystroke fall through to a global
/// binding. These tests are about the surfaces past the home, so they start from the
/// resolved state instead of the in-flight one.
fn shell(hello: ouro::proto::Hello) -> App {
    let mut app = app(hello);
    resolve_account(&mut app);
    app
}

fn resolve_account(app: &mut App) {
    answer(
        app,
        Tag::Account,
        json!({
            "account": serde_json::Value::Null,
            "requiresOpenaiAuth": true,
            "login": { "status": "idle" }
        }),
    );
}

/// An App on the Dashboard holding the golden `runtime.status`.
fn dashboard() -> App {
    let mut app = shell(full_hello());
    app.tab = Tab::Dashboard;

    answer(
        &mut app,
        Tag::Status,
        fixture("runtime_status_result")["result"].clone(),
    );

    app
}

/// An App on the Sessions tab with one interactive session open and watched.
fn with_open_session() -> App {
    let mut app = shell(full_hello());

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
            "options": {
                "approval_mode": "auto_edit",
                "sandbox_mode": null
            },
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

#[test]
fn coding_workspace_progressively_discloses_context_without_sacrificing_the_composer() {
    let mut app = with_open_session();
    notify(
        &mut app,
        event(1, "input_accepted", "inspect the runtime boundary"),
    );
    notify(
        &mut app,
        event(2, "output_text_final", "The boundary is contained."),
    );
    notify(
        &mut app,
        event_with(
            3,
            "tool_call",
            json!({"call_id": "check-1", "name": "exec_command", "input": {"cmd": "cargo test"}}),
        ),
    );
    notify(
        &mut app,
        event_with(
            4,
            "tool_result",
            json!({"call_id": "check-1", "output": "109 checks passed", "is_error": false}),
        ),
    );

    let wide = render(&mut app, 160, 40);
    if std::env::var_os("OUROBOROS_DUMP_VIEWPORTS").is_some() {
        eprintln!("\n--- wide 160x40 ---\n{}", wide.text());
    }
    for visible in [
        "SESSIONS / 01",
        "CONTEXT CHANNEL",
        "ACTIVE CONTEXT",
        "EXECUTION TRACE",
        "BOUNDARIES",
        "HERMETIC CORE",
        "YOU",
        "AGENT",
        "✓ command",
        "Ask a follow-up or request edits",
    ] {
        assert!(
            wide.contains(visible),
            "wide workspace lost {visible:?}:\n{}",
            wide.text()
        );
    }
    assert_eq!(wide.colour_of("▌ YOU", "YOU"), Color::Yellow);
    assert_eq!(wide.colour_of("◆ AGENT", "AGENT"), Color::Cyan);
    assert_eq!(wide.colour_of("✓ command", "✓"), Color::Green);

    let laptop = render(&mut app, 116, 58);
    if std::env::var_os("OUROBOROS_DUMP_VIEWPORTS").is_some() {
        eprintln!("\n--- laptop 116x58 ---\n{}", laptop.text());
    }
    for visible in [
        "SESSIONS / 01",
        "AGENT CHAT",
        "RUNTIME / CONTEXT",
        "ACTIVE CONTEXT",
        "EXECUTION TRACE",
        "BOUNDARIES",
        "INSERT",
    ] {
        assert!(
            laptop.contains(visible),
            "laptop workspace lost {visible:?}:\n{}",
            laptop.text()
        );
    }

    let standard = render(&mut app, 120, 30);
    if std::env::var_os("OUROBOROS_DUMP_VIEWPORTS").is_some() {
        eprintln!("\n--- standard 120x30 ---\n{}", standard.text());
    }
    assert!(standard.contains("SESSIONS / 01"), "{}", standard.text());
    assert!(standard.contains("YOU"), "{}", standard.text());
    assert!(
        standard.contains("Ask a follow-up or request edits"),
        "{}",
        standard.text()
    );
    assert!(
        !standard.contains("CONTEXT CHANNEL"),
        "the telemetry rail must yield before the reading pane:\n{}",
        standard.text()
    );

    let narrow = render(&mut app, 80, 24);
    if std::env::var_os("OUROBOROS_DUMP_VIEWPORTS").is_some() {
        eprintln!("\n--- narrow 80x24 ---\n{}", narrow.text());
    }
    assert!(narrow.contains("Agent chat"), "{}", narrow.text());
    assert!(narrow.contains("YOU"), "{}", narrow.text());
    assert!(narrow.contains("AGENT"), "{}", narrow.text());
    assert!(narrow.contains("PROVIDER"), "{}", narrow.text());
    assert!(!narrow.contains("SESSIONS /"), "{}", narrow.text());
    assert!(!narrow.contains("CONTEXT CHANNEL"), "{}", narrow.text());
}

#[test]
fn session_rail_caps_visual_noise_and_keeps_the_complete_picker_available() {
    let mut app = with_open_session();
    let sessions = (1..=8)
        .map(|number| {
            json!({
                "_struct": "Ouroboros.Interactive.State",
                "id": format!("session-000000000000000000000{number}"),
                "objective": format!("Task {number}"),
                "node": "ouroboros@golden",
                "provider": "codex",
                "workspace": "/tmp/w",
                "status": if number == 1 { "running" } else { "lost" },
                "options": {
                    "approval_mode": "auto_edit",
                    "sandbox_mode": "workspace_write"
                },
                "created_at": "2026-01-01T00:00:00.000000Z",
                "updated_at": "2026-01-01T00:00:00.000000Z"
            })
        })
        .collect::<Vec<_>>();
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        serde_json::Value::Array(sessions),
    );

    let screen = render(&mut app, 116, 58);
    for visible in [
        "Task 1",
        "Task 2",
        "Task 3",
        "Task 4",
        "+04 more · ctrl+x l",
    ] {
        assert!(screen.contains(visible), "{}", screen.text());
    }
    assert!(!screen.contains("Task 5"), "{}", screen.text());
    assert!(screen.contains("RUNTIME / CONTEXT"), "{}", screen.text());
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

fn event_with(sequence: u64, kind: &str, payload: serde_json::Value) -> serde_json::Value {
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
                "payload": payload
            }
        }
    })
}

/// Every visible transcript row that carries one of the numbered messages, with the screen
/// row it landed on. Two of these being equal is the whole claim of "the viewport did not
/// move under the reader".
fn message_rows(screen: &support::Screen) -> Vec<(usize, String)> {
    screen
        .rows
        .iter()
        .enumerate()
        .filter(|(_index, row)| row.contains("message-"))
        .map(|(index, row)| (index, row.trim_end().to_string()))
        .collect()
}

fn open_watch(app: &App) -> &ouro::ui::transcript::Watch {
    let key = app.sessions.open.clone().expect("an open session");
    app.sessions.watches.get(&key).expect("a watch")
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
    assert!(screen.contains("signer=deny"), "{}", screen.text());
    assert!(screen.contains("admit=no"), "{}", screen.text());
}

fn open_machines(app: &mut App) {
    app.apply(ctrl('p'));
    type_text(app, "machines");
    app.apply(key(KeyCode::Enter));
    assert!(matches!(app.overlay, Some(Overlay::Machines(_))));
}

#[test]
fn settings_makes_standalone_machine_setup_discoverable() {
    let mut app = dashboard();
    app.apply(key(KeyCode::Char(',')));

    let settings = render(&mut app, 120, 34);
    assert!(settings.contains("machines"), "{}", settings.text());
    assert!(
        settings.contains("standalone · open to create or join a fleet"),
        "{}",
        settings.text()
    );

    app.apply(key(KeyCode::Enter));
    let machines = render(&mut app, 120, 34);
    assert!(machines.contains("Standalone"), "{}", machines.text());
    assert!(machines.contains("Known 1 · Connected 1 · Offline 0"));
    assert!(
        machines.contains("Add a reachable machine"),
        "{}",
        machines.text()
    );
    assert!(
        machines.contains("I'll set it up myself"),
        "{}",
        machines.text()
    );
    assert!(machines.contains("Create a fleet"), "{}", machines.text());
    assert!(
        machines.contains("Join with an invitation"),
        "{}",
        machines.text()
    );
    assert!(
        machines.contains("Check the machines"),
        "{}",
        machines.text()
    );
    assert!(
        machines.contains("Diagnose a connection"),
        "{}",
        machines.text()
    );
    assert!(
        machines.contains("Enter runs the selected action"),
        "{}",
        machines.text()
    );
    assert!(machines.contains("ouro fleet add"), "{}", machines.text());
}

#[test]
fn a_healthy_three_machine_fleet_is_plain_and_secure() {
    let mut app = shell(full_hello());
    app.fleet_profile = Some(fleet_profile());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test", "ouro@workstation.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true, "cookie": "set", "proto_dist": "inet_tls" },
                "fleet": {
                    "summary": { "expected": 3, "connected": 3, "offline": 0 },
                    "machines": [
                        { "machine": "studio", "node": "ouro@studio.test", "role": "core", "state": "local" },
                        { "machine": "mini", "node": "ouro@mini.test", "role": "core", "state": "connected" },
                        { "machine": "workstation", "node": "ouro@workstation.test", "role": "core", "state": "connected" }
                    ]
                }
            }
        }),
    );
    open_machines(&mut app);

    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("Studio fleet"), "{}", screen.text());
    assert!(screen.contains("studio at studio.test"));
    assert!(screen.contains("Known 3 · Connected 3 · Offline 0"));
    assert!(screen.contains("encrypted and authenticated (TLS)"));
    assert!(screen.contains("All known machines are connected"));
    assert!(screen.contains("live provider work does not migrate"));
    assert!(screen.contains("after a full host"), "{}", screen.text());
    assert!(screen.contains("loss."));
}

#[test]
fn an_early_joiner_counts_later_machines_learned_from_beam() {
    let mut app = shell(full_hello());
    let mut early_profile = fleet_profile();
    early_profile.members.truncate(2);
    app.fleet_profile = Some(early_profile);
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test", "ouro@workstation.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": {
                    "summary": { "expected": 3, "connected": 3, "offline": 0 },
                    "machines": [
                        { "machine": "studio", "node": "ouro@studio.test", "role": "core", "state": "local" },
                        { "machine": "mini", "node": "ouro@mini.test", "role": "core", "state": "connected" },
                        { "machine": "workstation", "node": "ouro@workstation.test", "role": "core", "state": "connected" }
                    ]
                }
            }
        }),
    );
    open_machines(&mut app);

    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("Known 3 · Connected 3 · Offline 0"));
    assert!(!screen.contains("Known 2 · Connected 3"));
}

#[test]
fn newly_invited_profile_members_count_offline_before_the_live_runtime_learns_them() {
    let mut app = shell(full_hello());
    app.fleet_profile = Some(fleet_profile());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": [],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": {
                    "summary": { "expected": 1, "connected": 1, "offline": 0 },
                    "machines": [
                        { "machine": "studio", "node": "ouro@studio.test", "role": "core", "state": "local" }
                    ]
                }
            }
        }),
    );
    open_machines(&mut app);

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("Known 3 · Connected 1 · Offline 2"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("Offline: mini, workstation"),
        "{}",
        screen.text()
    );
}

#[test]
fn an_offline_machine_is_named_retried_and_then_recovers() {
    let mut app = shell(full_hello());
    app.fleet_profile = Some(fleet_profile());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": { "summary": { "expected": 3, "connected": 2, "offline": 1 } }
            }
        }),
    );
    open_machines(&mut app);

    let partial = render(&mut app, 120, 34);
    assert!(partial.contains("Known 3 · Connected 2 · Offline 1"));
    assert!(
        partial.contains("Offline: workstation"),
        "{}",
        partial.text()
    );
    assert!(partial.contains("running daemons keep retrying membership"));

    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test", "ouro@workstation.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": { "summary": { "expected": 3, "connected": 3, "offline": 0 } }
            }
        }),
    );
    let recovered = render(&mut app, 120, 34);
    assert!(recovered.contains("Known 3 · Connected 3 · Offline 0"));
    assert!(recovered.contains("retry membership after network interruptions"));
    assert!(!recovered.contains("Offline: workstation"));
}

#[test]
fn machines_calls_out_insecure_and_mismatched_runtime_states() {
    let mut insecure = shell(full_hello());
    answer(
        &mut insecure,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": false },
                "fleet": { "summary": { "expected": 2, "connected": 2, "offline": 0 } }
            }
        }),
    );
    open_machines(&mut insecure);
    let insecure_screen = render(&mut insecure, 120, 34);
    assert!(insecure_screen.contains("insecure: machine traffic is not using TLS"));

    let mut mismatch = shell(full_hello());
    mismatch.fleet_profile = Some(fleet_profile());
    answer(
        &mut mismatch,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": [],
            "cluster": {
                "distributed": false,
                "formation": { "strategy": "none" },
                "security": { "tls": false }
            }
        }),
    );
    open_machines(&mut mismatch);
    let mismatch_screen = render(&mut mismatch, 120, 34);
    assert!(mismatch_screen.contains("configuration mismatch"));
    assert!(mismatch_screen.contains("Known 3 · Connected 1 · Offline 2"));
}

#[test]
fn machines_create_join_and_service_open_runnable_forms() {
    let mut app = dashboard();
    open_machines(&mut app);
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    let create = render(&mut app, 120, 34);
    assert!(
        create.contains("Create a fleet on this Mac"),
        "{}",
        create.text()
    );
    assert!(create.contains("machine"), "{}", create.text());
    assert!(create.contains("host"), "{}", create.text());
    assert!(app.take_fleet_intent().is_none());
    assert!(app.quit.is_none());

    app.apply(key(KeyCode::Esc));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    let join = render(&mut app, 120, 34);
    assert!(join.contains("Join with an invitation"), "{}", join.text());
    assert!(join.contains("invitation"), "{}", join.text());
    assert!(join.contains("delete after join"), "{}", join.text());
    assert!(app.take_join_intent().is_none());
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
}

#[test]
fn machines_service_confirms_before_writing_a_unit() {
    let mut app = dashboard();
    app.fleet_profile = Some(fleet_profile());
    app.can_invite = true;
    open_machines(&mut app);

    for _ in 0..3 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));
    let service = render(&mut app, 120, 34);
    assert!(
        service.contains("Keep this machine running"),
        "{}",
        service.text()
    );
    assert!(
        service.contains("does not start the daemon"),
        "{}",
        service.text()
    );
    assert!(service.contains("activation command"), "{}", service.text());
    assert!(app.take_fleet_job().is_none());
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
}

#[test]
fn machines_copies_the_selected_command_without_running_it() {
    let mut app = dashboard();
    open_machines(&mut app);

    let overview = render(&mut app, 120, 34);
    assert!(overview.contains("y copy CLI"), "{}", overview.text());

    app.apply(key(KeyCode::Char('y')));
    assert_eq!(
        app.take_copy().as_deref(),
        Some("ouro fleet add user@host --machine NAME --host HOST")
    );
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Char('y')));
    assert_eq!(
        app.take_copy().as_deref(),
        Some("ouro fleet enroll INVITE.ouro --delete")
    );
    assert!(app.take_join_intent().is_none());
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
}

#[test]
fn machines_create_restarts_this_mac_as_the_owner() {
    let mut app = dashboard();
    app.mode = ouro::ui::app::Mode::Spawned { pid: 7 };
    open_machines(&mut app);

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    type_text(&mut app, "studio");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "studio.tailnet.ts.net");
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let intent = app.take_fleet_intent().expect("a create-only plan");
    assert!(intent.add.is_none());
    assert_eq!(intent.owner_machine, "studio");
    assert_eq!(intent.owner_host, "studio.tailnet.ts.net");
    assert_eq!(app.quit, Some(ouro::ui::Quit::ApplyFleetIntent));
}

#[test]
fn machines_status_and_doctor_run_from_the_menu() {
    let mut app = dashboard();
    app.data_dir = Some("/tmp/ouro-machines-test".into());
    open_machines(&mut app);

    for _ in 0..4 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));
    assert!(matches!(app.take_fleet_job(), Some(FleetJob::Status)));
    let report = render(&mut app, 120, 34);
    assert!(report.contains("Check the machines"), "{}", report.text());
    assert!(report.contains("Working"), "{}", report.text());

    app.apply(Msg::FleetJobFinished {
        log: vec!["Studio fleet".into(), "  machine      studio".into()],
        result: Ok(String::new()),
    });
    let done = render(&mut app, 120, 34);
    assert!(done.contains("Studio fleet"), "{}", done.text());
    assert!(done.contains("studio"), "{}", done.text());
}

#[test]
fn machines_add_flow_reviews_a_plan_then_requests_a_fleet_restart() {
    let mut app = dashboard();
    app.mode = ouro::ui::app::Mode::Spawned { pid: 7 };
    open_machines(&mut app);

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    let form = render(&mut app, 120, 34);
    assert!(
        form.contains("I'll set it up myself") || form.contains("machine"),
        "{}",
        form.text()
    );
    assert!(form.contains("host"), "{}", form.text());

    type_text(&mut app, "linux-laptop");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "linux-laptop.tailnet.ts.net");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "studio");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "studio.tailnet.ts.net");
    app.apply(key(KeyCode::Enter));

    let confirm = render(&mut app, 120, 34);
    assert!(confirm.contains("restart once"), "{}", confirm.text());
    assert!(
        confirm.contains("ouro fleet add --print-script --machine linux-laptop"),
        "{}",
        confirm.text()
    );
    assert!(confirm.contains("--init"), "{}", confirm.text());
    assert!(
        confirm.contains("--owner-host studio.tailnet.ts.net"),
        "{}",
        confirm.text()
    );

    app.apply(key(KeyCode::Enter));
    let intent = app.take_fleet_intent().expect("a saved add plan");
    assert_eq!(intent.add.as_ref().unwrap().machine, "linux-laptop");
    assert_eq!(intent.owner_host, "studio.tailnet.ts.net");
    assert_eq!(app.quit, Some(ouro::ui::Quit::ApplyFleetIntent));
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
}

#[test]
fn machines_add_picks_a_known_tailscale_host_and_prefills_this_mac() {
    let mut app = dashboard();
    open_machines(&mut app);
    app.apply(Msg::MachineCandidates {
        candidates: vec![
            MachineCandidate {
                label: "vps".into(),
                target: "vps.tailnet.ts.net".into(),
                host: Some("vps.tailnet.ts.net".into()),
                detail: "tailscale linux online".into(),
                tailscale: true,
            },
            MachineCandidate {
                label: "linux-laptop".into(),
                target: "linux-laptop.tailnet.ts.net".into(),
                host: Some("linux-laptop.tailnet.ts.net".into()),
                detail: "tailscale linux offline".into(),
                tailscale: true,
            },
        ],
        local_machine: Some("studio".into()),
        local_host: Some("studio.tailnet.ts.net".into()),
    });

    let menu = render(&mut app, 120, 34);
    assert!(menu.contains("Add vps"), "{}", menu.text());
    assert!(menu.contains("Add linux-laptop"), "{}", menu.text());
    assert!(
        menu.contains("linux-laptop.tailnet.ts.net"),
        "{}",
        menu.text()
    );

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    let form = render(&mut app, 120, 34);
    assert!(form.contains("linux-laptop"), "{}", form.text());
    assert!(
        form.contains("linux-laptop.tailnet.ts.net"),
        "{}",
        form.text()
    );
    assert!(form.contains("tailscale"), "{}", form.text());
    assert!(form.contains("studio.tailnet.ts.net"), "{}", form.text());
    assert!(
        form.contains("A Mac binary will not run on Linux"),
        "{}",
        form.text()
    );
}

#[test]
fn machines_add_on_a_live_owner_runs_without_restarting() {
    let mut app = dashboard();
    app.fleet_profile = Some(fleet_profile());
    app.can_invite = true;
    open_machines(&mut app);

    app.apply(key(KeyCode::Enter));
    type_text(&mut app, "op@vps");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "vps");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "vps.tailnet.ts.net");
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let job = app.take_fleet_job().expect("a live owner add");
    match job {
        FleetJob::Add {
            prepare,
            target,
            machine,
            ..
        } => {
            assert_eq!(target.as_deref(), Some("op@vps"));
            assert_eq!(machine, "vps");
            assert!(!prepare);
        }
        other => panic!("expected an add job, got {other:?}"),
    }
    assert!(app.quit.is_none());
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
}

#[test]
fn machines_add_refuses_an_attached_standalone_client() {
    let mut app = dashboard();
    app.mode = Mode::Attached;
    open_machines(&mut app);

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Enter));
    type_text(&mut app, "linux-laptop");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "linux-laptop.tailnet.ts.net");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "studio");
    app.apply(key(KeyCode::Tab));
    type_text(&mut app, "studio.tailnet.ts.net");
    app.apply(key(KeyCode::Enter));
    app.apply(key(KeyCode::Enter));

    let screen = render(&mut app, 120, 34);
    assert!(screen.contains("attached"), "{}", screen.text());
    assert!(app.quit.is_none());
    assert!(app.take_fleet_intent().is_none());
    assert!(app.take_fleet_job().is_none());
}

#[test]
fn machines_reopens_the_add_result_after_a_fleet_restart() {
    let mut app = dashboard();
    app.open_machines_on_start = true;
    app.resume_add_log = vec!["wrote a private invitation for laptop".into()];
    app.resume_add_recipe = Some("ouro fleet enroll laptop.ouro --delete".into());
    app.open_home();

    let screen = render(&mut app, 120, 34);
    assert!(
        screen.contains("wrote a private invitation for laptop"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("ouro fleet enroll laptop.ouro --delete"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("Provider sign-in is still on that machine"),
        "{}",
        screen.text()
    );
}

#[test]
fn machines_explains_signed_membership_updates_and_non_revocation() {
    let mut app = dashboard();
    app.fleet_profile = Some(fleet_profile());
    app.can_invite = true;
    open_machines(&mut app);

    for _ in 0..6 {
        app.apply(key(KeyCode::Down));
    }
    app.apply(key(KeyCode::Enter));

    let sync = render(&mut app, 120, 34);
    assert!(sync.contains("Export saved membership"), "{}", sync.text());
    assert!(sync.contains("roster"), "{}", sync.text());
    assert!(app.take_fleet_job().is_none());
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("fleet.")));
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
    assert_eq!(
        screen.colour_of("workspace      disabled", "disabled"),
        Color::DarkGray
    );

    let mut down = app;
    answer(
        &mut down,
        Tag::Status,
        json!({ "availability": { "mesh": "unavailable", "forged_lane": "degraded" } }),
    );

    let screen = render(&mut down, 120, 30);

    assert_eq!(screen.colour_of("mesh", "unavailable"), Color::Red);
    // A state this build has never heard of is neither good nor an outage.
    assert_eq!(
        screen.colour_of("forged_lane", "degraded"),
        Color::LightYellow
    );
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
    let mut app = shell(full_hello());
    app.tab = Tab::Dashboard;
    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("waiting for runtime.status"),
        "{}",
        screen.text()
    );
}

#[test]
fn a_refused_method_names_itself_in_the_pane_it_would_have_filled() {
    let mut app = shell(full_hello());
    app.tab = Tab::Dashboard;

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
fn the_coding_home_carries_the_terminal_logo() {
    let mut app = shell(full_hello());
    let screen = render(&mut app, 100, 24);

    assert!(screen.contains("▄█▄ ▄▄▄▄"), "{}", screen.text());
    assert!(screen.contains("▀▄▄▄▄▄▄▄▄▀"), "{}", screen.text());
}

#[test]
fn the_sessions_list_merges_both_planes_and_tags_each_row() {
    let mut app = shell(full_hello());
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

    app.overlay = Some(Overlay::SessionPicker { selected: None });
    let screen = render(&mut app, 120, 20);

    assert!(screen.row("session-1").contains("int"), "{}", screen.text());
    assert!(screen.row("task-2").contains("code "));
    assert!(screen.row("session-1").contains("awaiting_approval"));

    // Newest activity first, so the list does not reshuffle under the cursor.
    let sessions = screen.rows.iter().position(|r| r.contains("session-1"));
    let tasks = screen.rows.iter().position(|r| r.contains("task-2"));
    assert!(sessions < tasks);
}

#[test]
fn an_incomplete_fleet_list_keeps_last_known_session_rows() {
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('2')));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "remote-session",
            "node": "ouro@remote.test",
            "status": "running",
            "updated_at": "2026-01-01T00:00:02.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.apply(Msg::Answer {
        tag: Tag::Sessions(Plane::Interactive),
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::Unavailable,
            message: "session list is incomplete because owner ouro@remote.test did not answer"
                .into(),
            data: Some(json!({
                "reason": "owner_query_incomplete",
                "node": "ouro@remote.test"
            })),
        })),
    });
    assert!(app
        .sessions
        .interactive
        .error
        .as_deref()
        .is_some_and(|error| error.contains("session list is incomplete")));

    app.overlay = Some(Overlay::SessionPicker { selected: None });
    let screen = render(&mut app, 120, 20);
    assert!(screen.contains("remote-session"), "{}", screen.text());
}

#[test]
fn a_successful_local_only_list_retains_a_learned_offline_owners_last_known_row() {
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('2')));
    let remote_node = "ouro@late-member.test";

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "late-member-session",
            "node": remote_node,
            "status": "running",
            "updated_at": "2026-01-01T00:00:02.000000Z"
        }]),
    );

    // No local fleet profile names this node: it was learned transitively through the
    // runtime directory before going offline.
    assert!(app.fleet_profile.is_none());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": "ouroboros@golden", "machine": "local", "state": "local" },
                        { "node": remote_node, "machine": "late-member", "state": "offline" }
                    ]
                }
            }
        }),
    );

    // An older gateway may still return success after querying only the local owner. The
    // prior remote row remains because runtime.status explicitly proves that owner is
    // offline; absence from this array is not evidence that its durable session vanished.
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "local-session",
            "node": "ouroboros@golden",
            "status": "idle",
            "updated_at": "2026-01-01T00:00:03.000000Z"
        }]),
    );

    let rows = app
        .sessions
        .interactive
        .value
        .as_ref()
        .expect("the merged list");
    assert!(rows.iter().any(|row| {
        row.id == "late-member-session"
            && row.node.as_deref() == Some(remote_node)
            && row.last_known
    }));
    assert!(rows
        .iter()
        .any(|row| row.id == "local-session" && !row.last_known));

    app.overlay = Some(Overlay::SessionPicker { selected: None });
    let screen = render(&mut app, 130, 20);
    assert!(
        screen
            .row("late-member-session")
            .contains("last-known · owner offline"),
        "{}",
        screen.text()
    );
}

#[test]
fn escape_from_an_idle_empty_prompt_returns_home() {
    let mut app = with_open_session();
    assert!(app.sessions.open.is_some());
    assert!(app.sessions.composer.is_some());

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": "session-0000000000000000000001",
            "status": "idle",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );

    app.apply(key(KeyCode::Esc));

    assert!(app.sessions.open.is_none());
    assert!(app.sessions.composer.is_none());
    assert_eq!(app.tab, Tab::Sessions);
}

#[test]
fn a_list_poll_does_not_retarget_the_session_picker() {
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([
            {
                "id": "older",
                "status": "idle",
                "updated_at": "2026-01-01T00:00:01.000000Z"
            },
            {
                "id": "newer",
                "status": "idle",
                "updated_at": "2026-01-01T00:00:02.000000Z"
            }
        ]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    app.overlay = Some(Overlay::SessionPicker {
        selected: Some((Plane::Interactive, "older".into())),
    });

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([
            {
                "id": "older",
                "status": "idle",
                "updated_at": "2026-01-01T00:00:01.000000Z"
            },
            {
                "id": "newer",
                "status": "idle",
                "updated_at": "2026-01-01T00:00:03.000000Z"
            }
        ]),
    );

    match &app.overlay {
        Some(Overlay::SessionPicker { selected }) => {
            assert_eq!(
                selected.as_ref().map(|(_plane, id)| id.as_str()),
                Some("older")
            );
        }
        other => panic!("expected a session picker, got {other:?}"),
    }

    app.apply(key(KeyCode::Enter));
    assert_eq!(
        app.sessions.open.as_ref().map(|(_plane, id)| id.as_str()),
        Some("older")
    );
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

    assert!(screen.contains("Agent chat"), "{}", screen.text());
    assert!(screen.contains("Agent"), "{}", screen.text());
    assert!(screen.contains("the workspace is clean"));
    assert!(
        screen.contains("Earlier conversation is no longer available"),
        "{}",
        screen.text()
    );

    // The gateway redacts at construction; the client shows exactly what it was given.
    assert!(screen.contains("[REDACTED]") || screen.contains("the workspace is clean"));

    assert!(
        !screen.contains("output_text_final") && !screen.contains("cursor 42"),
        "protocol details stay out of the default chat:\n{}",
        screen.text()
    );

    // The complete event ledger remains one key away.
    app.apply(ctrl('o'));
    let details = render(&mut app, 120, 24);
    assert!(details.contains("EVENT DETAILS"), "{}", details.text());
    assert!(details.contains("output_text_final"), "{}", details.text());
    assert!(details.contains("cursor 42"), "{}", details.text());
    assert!(
        details.contains("history truncated below 41"),
        "{}",
        details.text()
    );

    // And the hole is gone: it was never a hole, it was the start of history.
    assert!(!screen.contains("events missing"), "{}", screen.text());
    assert!(app.drain().is_empty(), "nothing more to ask for");
}

#[test]
fn agent_chat_hides_system_events_and_keeps_both_sides_of_the_conversation() {
    let mut app = with_open_session();

    notify(
        &mut app,
        event(1, "session_started", "cwd=/Users/person/project"),
    );
    notify(&mut app, event(2, "input_accepted", "please fix the tests"));
    notify(
        &mut app,
        event(3, "provider_event", "internal provider diagnostic"),
    );
    notify(
        &mut app,
        event(4, "output_text_final", "The tests are fixed."),
    );
    notify(&mut app, event(5, "usage", "input_tokens=21088"));

    let chat = render(&mut app, 120, 26);
    assert!(chat.contains("YOU"), "{}", chat.text());
    assert!(chat.contains("please fix the tests"), "{}", chat.text());
    assert!(chat.contains("AGENT"), "{}", chat.text());
    assert!(chat.contains("The tests are fixed."), "{}", chat.text());

    for hidden in [
        "session_started",
        "provider_event",
        "internal provider diagnostic",
        "output_text_final",
        "usage",
        "input_tokens=21088",
    ] {
        assert!(
            !chat.contains(hidden),
            "{hidden:?} leaked into the default chat:\n{}",
            chat.text()
        );
    }

    // The details shortcut works even while the message composer owns printable keys.
    assert!(app.sessions.composer.is_some());
    app.apply(ctrl('o'));
    let details = render(&mut app, 120, 26);
    assert!(details.contains("session_started"), "{}", details.text());
    assert!(details.contains("provider_event"), "{}", details.text());
    assert!(details.contains("input_tokens=21088"), "{}", details.text());
}

#[test]
fn queueing_a_follow_up_shows_an_inline_typing_indicator_until_agent_text_arrives() {
    let mut app = with_open_session();

    type_text(&mut app, "please inspect this");
    app.apply(key(KeyCode::Enter));

    let send = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the composer queues the follow-up");

    let waiting = render(&mut app, 120, 30);
    assert!(waiting.contains("Agent"), "{}", waiting.text());
    assert!(
        waiting.contains(&format!("  {}  Working", theme::spinner(0))),
        "{}",
        waiting.text()
    );
    assert!(!waiting.contains("▄█▄ ▄▄▄▄"), "{}", waiting.text());
    assert!(
        !waiting.contains("waiting for agent reply"),
        "{}",
        waiting.text()
    );

    app.ticks = 2;
    let advanced = render(&mut app, 120, 30);
    assert!(
        advanced.contains(&format!("  {}  Working", theme::spinner(2))),
        "{}",
        advanced.text()
    );

    answer(&mut app, send.tag, json!({ "status": "running" }));
    notify(&mut app, event(1, "input_accepted", "please inspect this"));

    let accepted = render(&mut app, 120, 30);
    assert!(
        accepted.contains("please inspect this"),
        "{}",
        accepted.text()
    );
    assert!(
        accepted.contains(&format!("  {}  Working", theme::spinner(2))),
        "{}",
        accepted.text()
    );

    notify(&mut app, event(2, "output_text_delta", "I am checking"));

    let replying = render(&mut app, 120, 30);
    assert!(replying.contains("I am checking"), "{}", replying.text());
    assert!(!replying.contains("Working"), "{}", replying.text());
}

#[test]
fn an_unknown_follow_up_restores_and_retries_the_exact_draft_and_turn_id() {
    let mut app = with_open_session();
    let input = "queue this after the current work";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first queued request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("a logical turn id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamTimeout,
            message: "the runtime could not confirm the turn dispatch".into(),
            data: Some(json!({ "outcome": "unknown", "turn_id": turn_id })),
        })),
    });

    let composer = app.sessions.composer.as_ref().expect("the restored draft");
    assert_eq!(composer.editor.text(), input);
    assert_eq!(composer.verb, ComposerVerb::FollowUp);

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the same-id reconciliation");

    assert_eq!(retry.params["input"], input);
    assert_eq!(retry.params["turn_id"], turn_id);
}

#[test]
fn an_unknown_follow_up_keeps_a_newer_draft_while_reconciling_the_old_id_first() {
    let mut app = with_open_session();
    let first_input = "queue the first exact request";
    let newer_draft = "and then inspect the renderer";

    type_text(&mut app, first_input);
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first queued request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("the first logical id")
        .to_string();

    type_text(&mut app, newer_draft);
    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the newer draft remains active")
            .editor
            .text(),
        newer_draft
    );
    let notice = &app
        .notice
        .as_ref()
        .expect("the explicit reconciliation notice")
        .text;
    assert!(notice.contains(&turn_id), "{notice}");
    assert!(
        notice.contains("without overwriting the session draft"),
        "{notice}"
    );
    assert!(notice.contains("Enter reconciles it"), "{notice}");

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("1 outcome-unknown turn"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("Enter reconciles first"),
        "{}",
        screen.text()
    );

    // Enter reconciles A under the only safe id and does not consume or submit B.
    app.apply(key(KeyCode::Enter));
    let reconciliation = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the explicit same-id reconciliation");
    assert_eq!(reconciliation.params["input"], first_input);
    assert_eq!(reconciliation.params["turn_id"], turn_id);
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the newer draft still remains")
            .editor
            .text(),
        newer_draft
    );

    answer(
        &mut app,
        reconciliation.tag,
        json!({ "id": turn_id, "status": "running" }),
    );
    app.apply(key(KeyCode::Enter));
    let newer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the newer draft submits after reconciliation");
    assert_eq!(newer.params["input"], newer_draft);
    assert_ne!(newer.params["turn_id"], turn_id);
}

#[test]
fn an_identical_newer_draft_is_not_cleared_by_an_older_reconciliation() {
    let mut app = with_open_session();
    let repeated_input = "run the focused lifecycle test";

    type_text(&mut app, repeated_input);
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first submission");
    let first_id = first.params["turn_id"]
        .as_str()
        .expect("the first logical id")
        .to_string();

    // B is intentional new editor input even though its bytes equal A. Text equality is
    // not ownership: only the generation synthesized by retry restoration may be cleared.
    type_text(&mut app, repeated_input);
    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the independently typed B draft")
            .editor
            .text(),
        repeated_input
    );

    app.apply(key(KeyCode::Enter));
    let reconciliation = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the same-id reconciliation for A");
    assert_eq!(reconciliation.params["turn_id"], first_id);

    answer(
        &mut app,
        reconciliation.tag,
        json!({ "id": first_id, "status": "running" }),
    );
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("B survives A's accepted reconciliation")
            .editor
            .text(),
        repeated_input
    );

    app.apply(key(KeyCode::Enter));
    let second = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("B remains independently submittable");
    assert_eq!(second.params["input"], repeated_input);
    assert_ne!(second.params["turn_id"], first_id);
}

#[test]
fn same_session_follow_ups_are_issued_in_submission_order() {
    let mut app = with_open_session();

    type_text(&mut app, "first queued instruction");
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first queued instruction");
    let first_id = first.params["turn_id"]
        .as_str()
        .expect("the first turn id")
        .to_string();

    type_text(&mut app, "second queued instruction");
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.follow_up"),
        "the gateway must not receive B while A is unclassified"
    );
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("B remains visibly editable")
            .editor
            .text(),
        "second queued instruction"
    );

    answer(
        &mut app,
        first.tag,
        json!({ "id": first_id, "status": "running" }),
    );
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.follow_up"),
        "classification never submits a visible draft without another Enter"
    );
    app.apply(key(KeyCode::Enter));
    let second = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("B is issued after A is accepted and the operator confirms it");
    assert_eq!(second.params["input"], "second queued instruction");
    assert_ne!(second.params["turn_id"], first_id);
}

#[test]
fn an_unknown_first_submission_reconciles_before_a_visible_second_draft() {
    let mut app = with_open_session();

    type_text(&mut app, "first uncertain instruction");
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first instruction");
    let first_id = first.params["turn_id"]
        .as_str()
        .expect("the first turn id")
        .to_string();

    type_text(&mut app, "second locally queued instruction");
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.follow_up"),
        "B stays local while A is still in flight"
    );

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });
    app.apply(key(KeyCode::Enter));
    let first_retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("A reconciles before B can cross the gateway");
    assert_eq!(first_retry.params["input"], "first uncertain instruction");
    assert_eq!(first_retry.params["turn_id"], first_id);

    answer(
        &mut app,
        first_retry.tag,
        json!({ "id": first_id, "status": "running" }),
    );
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.follow_up"),
        "reconciliation leaves B visible rather than auto-submitting it"
    );
    app.apply(key(KeyCode::Enter));
    let second = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("B is sent only after A reconciles and Enter is pressed again");
    assert_eq!(second.params["input"], "second locally queued instruction");
    assert_ne!(second.params["turn_id"], first_id);
}

#[test]
fn an_unknown_reply_after_switching_sessions_is_reconciled_when_the_session_reopens() {
    let mut app = with_open_session();
    let session_id = "session-0000000000000000000001";
    let input = "preserve this turn across the session switch";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("the stable turn id")
        .to_string();

    app.open_session(Plane::Interactive, "another-session".into());
    let _ = app.drain();
    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    app.open_session(Plane::Interactive, session_id.into());
    let _ = app.drain();
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the reopened composer")
            .editor
            .text(),
        input
    );
    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("1 outcome-unknown turn"),
        "{}",
        screen.text()
    );

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the deferred reconciliation");
    assert_eq!(retry.params["id"], session_id);
    assert_eq!(retry.params["input"], input);
    assert_eq!(retry.params["turn_id"], turn_id);
}

#[test]
fn a_pending_reconciliation_survives_closing_and_reopening_the_composer() {
    let mut app = with_open_session();
    let session_id = "session-0000000000000000000001";
    let input = "keep this exact unresolved request";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("the stable turn id")
        .to_string();
    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    apply_leader(&mut app, 'n');
    assert!(app.sessions.open.is_none());
    assert!(app.sessions.composer.is_none());

    app.open_session(Plane::Interactive, session_id.into());
    let _ = app.drain();
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the rehydrated composer")
            .editor
            .text(),
        input
    );

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the same-id retry after reopening");
    assert_eq!(retry.params["input"], input);
    assert_eq!(retry.params["turn_id"], turn_id);
}

#[test]
fn a_transport_loss_after_follow_up_restores_the_same_draft_and_turn_id() {
    let mut app = with_open_session();
    let input = "do not duplicate this queued request";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the queued request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("a logical turn id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the restored transport-lost draft")
            .editor
            .text(),
        input
    );

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the same-id transport reconciliation");

    assert_eq!(retry.params["input"], input);
    assert_eq!(retry.params["turn_id"], turn_id);
}

#[test]
fn a_successful_rpc_read_of_a_failed_follow_up_restores_a_fresh_retry() {
    let mut app = with_open_session();
    let input = "retry this only as a new logical turn";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the queued request");
    let failed_id = first.params["turn_id"]
        .as_str()
        .expect("the failed logical id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Ok(json!({
            "id": failed_id,
            "status": "failed",
            "error": "provider_refused"
        })),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the failed turn draft")
            .editor
            .text(),
        input
    );
    let notice = &app.notice.as_ref().expect("the failed turn notice").text;
    assert!(notice.contains("is failed"), "{notice}");
    assert!(notice.contains("provider_refused"), "{notice}");

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("a deliberate fresh retry");

    assert_eq!(retry.params["input"], input);
    assert_ne!(retry.params["turn_id"], failed_id);
}

#[test]
fn a_legacy_unknown_follow_up_reply_still_preserves_the_same_turn_id() {
    let mut app = with_open_session();
    let input = "reconcile this legacy gateway reply";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the queued request");
    let turn_id = first.params["turn_id"]
        .as_str()
        .expect("a logical turn id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "the runtime refused the call".into(),
            data: Some(json!(["turn_dispatch_ambiguous", turn_id])),
        })),
    });

    app.apply(key(KeyCode::Enter));
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the legacy same-id reconciliation");

    assert_eq!(retry.params["input"], input);
    assert_eq!(retry.params["turn_id"], turn_id);
}

#[test]
fn a_busy_immediate_message_restores_the_draft_as_a_fresh_queued_follow_up() {
    let mut app = shell(full_hello());
    let session_id = "session-with-an-active-turn";
    let input = "implement now with the context you have";

    // With no list snapshot yet, this reproduces the old `ouro new -m` handoff: the
    // composer believes it owns the immediate-message slot while Harness is already busy.
    app.open_session(Plane::Interactive, session_id.into());
    let _ = app.drain();
    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let refused = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the stale immediate message");
    let failed_turn_id = refused.params["turn_id"]
        .as_str()
        .expect("a logical turn id")
        .to_string();

    app.apply(Msg::Answer {
        tag: refused.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "the session is already running a turn; queue this input with \
                      interactive.follow_up"
                .into(),
            data: Some(json!({
                "reason": "busy",
                "outcome": "not_dispatched",
                "retry_with": "interactive.follow_up",
                "error": ["turn_dispatch_failed", "busy"]
            })),
        })),
    });

    let composer = app.sessions.composer.as_ref().expect("the restored draft");
    assert_eq!(composer.editor.text(), input);
    assert_eq!(composer.verb, ComposerVerb::FollowUp);

    app.apply(key(KeyCode::Enter));
    let queued = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the actionable retry queues");

    assert_eq!(queued.params["input"], input);
    assert_ne!(queued.params["turn_id"], failed_turn_id);
}

#[test]
fn a_late_composer_failure_never_overwrites_the_next_draft() {
    let mut app = with_open_session();

    type_text(&mut app, "the submitted follow-up");
    app.apply(key(KeyCode::Enter));
    let submitted = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the submitted follow-up");

    type_text(&mut app, "a newer unsent thought");
    app.apply(Msg::Answer {
        tag: submitted.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "the follow-up was refused".into(),
            data: None,
        })),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the newer draft")
            .editor
            .text(),
        "a newer unsent thought"
    );
}

#[test]
fn an_empty_running_session_shows_a_working_indicator() {
    let mut app = with_open_session();
    let screen = render(&mut app, 120, 24);

    assert!(
        screen.contains(&format!("  {}  Working", theme::spinner(0))),
        "{}",
        screen.text()
    );
    assert!(!screen.contains("No messages yet."), "{}", screen.text());
}

/// A transcript is drawn bottom-anchored, so anything appended moves every row up by as
/// much. For a reader who has scrolled back into history that is the transcript sliding out
/// from under them — and the working indicator alone adds and removes a row on every turn.
#[test]
fn a_scrolled_back_transcript_holds_still_while_the_tail_grows() {
    let mut app = with_open_session();

    for sequence in 1..=40 {
        notify(
            &mut app,
            event(
                sequence,
                "output_text_final",
                &format!("message-{sequence:02}"),
            ),
        );
    }

    // The first frame is what tells the scroll keys how tall this content is.
    render(&mut app, 120, 24);
    for _ in 0..3 {
        app.apply(key(KeyCode::PageUp));
    }

    let before = render(&mut app, 120, 24);
    assert!(before.contains("SCROLLED"), "{}", before.text());
    let anchored = message_rows(&before);
    assert!(!anchored.is_empty(), "{}", before.text());

    // A queued follow-up appends the working indicator below the viewport.
    type_text(&mut app, "please inspect this");
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    assert!(app.waiting_for_open_agent_reply());
    let waiting = render(&mut app, 120, 24);
    assert_eq!(message_rows(&waiting), anchored, "{}", waiting.text());

    // And removes them again when the agent replies, in a turn the reader is not looking at.
    notify(&mut app, event(41, "output_text_delta", "on it"));
    assert!(!app.waiting_for_open_agent_reply());

    let replying = render(&mut app, 120, 24);
    assert_eq!(message_rows(&replying), anchored, "{}", replying.text());
}

/// The harder case: a cell already in the transcript is rewritten in place, so the rows do
/// not merely grow at the end — a running tool becomes a completed one with output under it.
#[test]
fn a_scrolled_back_transcript_holds_still_when_a_running_tool_completes() {
    let mut app = with_open_session();

    for sequence in 1..=40 {
        notify(
            &mut app,
            event(
                sequence,
                "output_text_final",
                &format!("message-{sequence:02}"),
            ),
        );
    }

    notify(
        &mut app,
        event_with(
            41,
            "tool_call",
            json!({"call_id": "call-1", "name": "bash", "input": {"command": "mix test"}}),
        ),
    );

    render(&mut app, 120, 24);
    for _ in 0..3 {
        app.apply(key(KeyCode::PageUp));
    }

    let before = render(&mut app, 120, 24);
    let anchored = message_rows(&before);
    assert!(!anchored.is_empty(), "{}", before.text());

    notify(
        &mut app,
        event_with(
            42,
            "tool_result",
            json!({
                "call_id": "call-1",
                "output": {"text": "3 tests, 0 failures\nfinished in 0.4s"},
                "is_error": false
            }),
        ),
    );

    let after = render(&mut app, 120, 24);
    assert_eq!(message_rows(&after), anchored, "{}", after.text());
}

/// The composer is always focused, so a wheel notch or Shift+Up used to walk prompt
/// history instead of the conversation. Those bindings have to reach the transcript
/// without touching the draft.
#[test]
fn the_wheel_and_shift_up_scroll_the_transcript_not_prompt_history() {
    let mut app = with_open_session();

    for sequence in 1..=40 {
        notify(
            &mut app,
            event(
                sequence,
                "output_text_final",
                &format!("message-{sequence:02}"),
            ),
        );
    }

    type_text(&mut app, "unfinished draft");
    render(&mut app, 120, 24);

    app.apply(modified(KeyCode::Up, KeyModifiers::SHIFT));
    let shifted = render(&mut app, 120, 24);
    assert!(shifted.contains("SCROLLED"), "{}", shifted.text());
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "unfinished draft"
    );

    app.apply(Msg::Scroll(-12));
    let wheeled = render(&mut app, 120, 24);
    assert!(wheeled.contains("SCROLLED"), "{}", wheeled.text());
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "unfinished draft"
    );

    app.apply(key(KeyCode::Up));
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "unfinished draft",
        "bare up still belongs to the prompt until there is history to recall"
    );
}

/// Scrolling back was unbounded, so holding PageUp on a transcript with nothing above the
/// viewport bought hundreds of keypresses that did nothing — and then hundreds more to get
/// back to the bottom.
#[test]
fn scrolling_back_stops_at_the_top_instead_of_counting_past_it() {
    let mut app = with_open_session();
    notify(&mut app, event(1, "output_text_final", "the only message"));

    render(&mut app, 120, 40);
    for _ in 0..50 {
        app.apply(key(KeyCode::PageUp));
    }

    let watch = open_watch(&app);
    assert_eq!(watch.scroll, 0);
    assert_eq!(watch.max_scroll(), 0);
    assert!(
        watch.follow,
        "there is nothing above the viewport to scroll back to"
    );

    let screen = render(&mut app, 120, 40);
    assert!(!screen.contains("SCROLLED"), "{}", screen.text());

    // And on a transcript that does have history, the offset stops at the top rather than
    // climbing: returning costs the pages that exist, not the keys that were pressed.
    let mut app = with_open_session();
    for sequence in 1..=40 {
        notify(
            &mut app,
            event(
                sequence,
                "output_text_final",
                &format!("message-{sequence:02}"),
            ),
        );
    }

    render(&mut app, 120, 24);
    for _ in 0..200 {
        app.apply(key(KeyCode::PageUp));
    }

    let top = open_watch(&app).max_scroll();
    assert!(top > 0);
    assert_eq!(open_watch(&app).scroll, top);

    for _ in 0..top.div_ceil(10) {
        app.apply(key(KeyCode::PageDown));
    }

    assert!(open_watch(&app).follow, "{}", open_watch(&app).scroll);
}

/// `Shift+Enter` is only distinguishable from `Enter` where the terminal speaks the kitty
/// keyboard protocol. Everywhere else — Terminal.app, iTerm2's default profile, tmux
/// without passthrough — advertising it tells someone that the key which sends their
/// half-written message inserts a newline.
#[test]
fn the_composer_advertises_shift_enter_only_where_the_terminal_reports_it() {
    let mut app = with_open_session();

    app.keyboard_enhanced = false;
    let plain = render(&mut app, 120, 30);
    assert!(
        plain.contains("Ctrl+J newline · Enter sends"),
        "{}",
        plain.text()
    );
    assert!(!plain.contains("Shift+Enter"), "{}", plain.text());

    app.keyboard_enhanced = true;
    let enhanced = render(&mut app, 120, 30);
    assert!(
        enhanced.contains("Shift+Enter/Ctrl+J newline · Enter sends"),
        "{}",
        enhanced.text()
    );

    // The same rule on the home composer, whose Enter starts rather than sends.
    let mut home = shell(full_hello());
    home.config.defaults.provider = Some("claude".into());

    let plain = render(&mut home, 120, 30);
    assert!(
        plain.contains("Ctrl+J newline · Enter starts"),
        "{}",
        plain.text()
    );
    assert!(!plain.contains("Shift+Enter"), "{}", plain.text());

    home.keyboard_enhanced = true;
    let enhanced = render(&mut home, 120, 30);
    assert!(
        enhanced.contains("Shift+Enter/Ctrl+J newline · Enter starts"),
        "{}",
        enhanced.text()
    );
}

#[test]
fn streamed_output_is_one_agent_message_when_the_final_text_arrives() {
    let mut app = with_open_session();

    notify(&mut app, event(1, "output_text_delta", "Hello "));
    notify(&mut app, event(2, "output_text_delta", "there"));
    notify(&mut app, event(3, "output_text_final", "Hello there"));

    let chat = render(&mut app, 120, 24);
    assert_eq!(
        chat.text().matches("Hello there").count(),
        1,
        "delta rows must collapse into the final message:\n{}",
        chat.text()
    );
    assert!(!chat.contains("output_text_delta"), "{}", chat.text());
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
        screen.contains("Some live updates were missed by the gateway"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("Restoring 4 missing updates"),
        "the hole itself has to be visible, not just the cause:\n{}",
        screen.text()
    );

    // The technical resync cursor stays out of chat and remains visible in details.
    assert!(!screen.contains("cursor 2"), "{}", screen.text());
    app.apply(ctrl('o'));
    let details = render(&mut app, 120, 24);
    assert!(details.contains("cursor 2"), "{}", details.text());

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
        screen.contains("Earlier conversation is no longer available"),
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

/// History is kept on the always-on composer, and survives switching away and back.
#[test]
fn composer_history_survives_leaving_and_reopening_the_session() {
    let mut app = with_open_session();

    type_text(&mut app, "run the focused test");
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    apply_leader(&mut app, 'n');
    assert!(app.sessions.open.is_none());
    assert!(app.sessions.composer.is_none());

    app.open_session(
        Plane::Interactive,
        "session-0000000000000000000001".to_string(),
    );
    let _ = app.drain();
    app.apply(key(KeyCode::Up));

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .map(|composer| composer.editor.text()),
        Some("run the focused test")
    );
}

#[test]
fn steering_sends_only_the_non_idempotent_envelope() {
    let mut app = with_open_session();

    apply_leader(&mut app, 's');
    type_text(&mut app, "stop and run the tests first");
    app.apply(key(KeyCode::Enter));

    let steer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.steer")
        .expect("a steer call");

    assert_eq!(steer.params["id"], "session-0000000000000000000001");
    assert_eq!(steer.params["input"], "stop and run the tests first");
    assert_eq!(
        steer.params.as_object().expect("an object").len(),
        2,
        "{}",
        steer.params
    );
    assert!(steer.params.get("turn_id").is_none(), "{}", steer.params);
}

#[test]
fn a_transport_loss_after_steer_restores_the_draft_as_unreconcilable() {
    let mut app = with_open_session();
    let input = "stop and inspect the failing test first";

    apply_leader(&mut app, 's');
    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let steer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.steer")
        .expect("the steer call");
    assert!(steer.params.get("turn_id").is_none(), "{}", steer.params);

    app.apply(Msg::Answer {
        tag: steer.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the exact steer draft")
            .editor
            .text(),
        input
    );
    assert!(
        app.drain().is_empty(),
        "a lost steer acknowledgement must not trigger an automatic replay"
    );

    let notice = &app
        .notice
        .as_ref()
        .expect("the unreconcilable warning")
        .text;
    assert!(
        notice.contains("delivery could not be confirmed"),
        "{notice}"
    );
    assert!(notice.contains("not idempotent"), "{notice}");
    assert!(
        notice.contains("before deliberately sending it again"),
        "{notice}"
    );
}

#[test]
fn a_lost_steer_acknowledgement_preserves_a_newer_draft_without_claiming_restoration() {
    let mut app = with_open_session();
    let steer_input = "stop and inspect the failing test first";
    let newer_draft = "then explain the renderer";

    apply_leader(&mut app, 's');
    type_text(&mut app, steer_input);
    app.apply(key(KeyCode::Enter));
    let steer = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.steer")
        .expect("the steer call");

    type_text(&mut app, newer_draft);
    app.apply(Msg::Answer {
        tag: steer.tag,
        result: Err(ClientError::ConnectionClosed),
    });

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("the newer draft remains active")
            .editor
            .text(),
        newer_draft
    );
    let notice = &app
        .notice
        .as_ref()
        .expect("the unreconcilable warning")
        .text;
    assert!(notice.contains("the newer draft was preserved"), "{notice}");
    assert!(notice.contains("composer history"), "{notice}");
    assert!(!notice.contains("exact draft was restored"), "{notice}");
}

/// Bracketed paste was dropped whenever an overlay was open. The workspace box of the `n`
/// dialog is the field most likely to receive a path off the clipboard, and it looked
/// broken in a way nothing on screen explained.
#[test]
fn a_paste_reaches_the_focused_field_of_an_overlay() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));
    focus(&mut app, NewField::Workspace);

    app.apply(Msg::Paste("/srv/pasted\n".into()));

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("/srv/pasted"), "{}", screen.text());

    // The palette takes one too, and re-derives its selection from the query.
    let mut app = shell(full_hello());
    app.apply(ctrl('p'));
    app.apply(Msg::Paste("settings".into()));

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("settings"), "{}", screen.text());
    assert!(screen.contains("Settings"), "{}", screen.text());

    // An overlay with no text field says so rather than swallowing it.
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('?')));
    app.apply(Msg::Paste("anything".into()));

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("nothing here is taking text"),
        "{}",
        screen.text()
    );
}

#[test]
fn stream_ended_marks_the_session_finished() {
    let mut app = with_open_session();

    notify(&mut app, event(1, "output_text_final", "last word"));
    let _ = app.drain();

    notify(&mut app, fixture("stream_ended_notification"));

    let screen = render(&mut app, 120, 24);

    assert!(
        screen.contains("Session ended (closed)"),
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

    assert!(matches!(
        call.tag,
        Tag::Approval {
            ref request_id,
            ..
        } if request_id == "req-17"
    ));

    // Hidden while this exact response is in flight, but retained until the runtime emits
    // `approval_resolved` so a refusal can make it retryable.
    assert!(app.sessions.open_watch().unwrap().next_approval().is_none());

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Err(ClientError::Rpc(ouro::proto::RpcError {
            code: ouro::proto::ErrorCode::InvalidParams,
            message: "approval was not accepted".into(),
            data: None,
        })),
    });
    assert_eq!(
        app.sessions
            .open_watch()
            .unwrap()
            .next_approval()
            .map(|request| request.request_id.as_str()),
        Some("req-17")
    );
}

#[test]
fn every_remote_session_verb_keeps_the_owner_node_from_the_reference() {
    let remote_id = "session-remote-1";
    let remote_node = "ouro@mini.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": remote_id,
            "node": remote_node,
            "provider": "codex",
            "status": "running",
            "updated_at": "2026-01-01T00:00:00Z"
        }]),
    );
    app.open_session(Plane::Interactive, remote_id.into());

    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("a remote subscribe");
    assert_eq!(subscribe.params["node"], remote_node);
    answer(&mut app, subscribe.tag, json!([]));

    type_text(&mut app, "run the remote checks");
    app.apply(key(KeyCode::Enter));
    let follow_up = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("a remote follow-up");
    assert_eq!(follow_up.params["node"], remote_node);
    answer(
        &mut app,
        follow_up.tag,
        json!({"id": follow_up.params["turn_id"], "status": "queued"}),
    );

    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": remote_id,
                "node": remote_node,
                "event": {
                    "id": "evt-remote-1",
                    "session_id": remote_id,
                    "sequence": 1,
                    "type": "approval_requested",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "request_id": "req-remote-1",
                    "payload": { "tool_call": { "name": "bash", "command": "mix test" } }
                }
            }
        }),
    );
    app.apply(key(KeyCode::Enter));
    let approval = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.respond_approval")
        .expect("a routed approval");
    assert_eq!(approval.params["node"], remote_node);

    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "stream.lagged",
            "params": {
                "id": remote_id,
                "node": remote_node,
                "plane": "interactive",
                "dropped": 1,
                "last_sequence": 2
            }
        }),
    );
    let replay = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.replay")
        .expect("a routed replay");
    assert_eq!(replay.params["node"], remote_node);

    app.apply(key(KeyCode::Esc));
    let interrupt = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.interrupt")
        .expect("a routed interrupt");
    assert_eq!(interrupt.params["node"], remote_node);

    apply_leader(&mut app, 'x');
    let Some(Overlay::Confirm { options, .. }) = app.overlay.as_ref() else {
        panic!("a close confirmation")
    };
    for (_label, call) in options
        .iter()
        .filter_map(|(label, call)| call.as_ref().map(|call| (label, call)))
    {
        assert_eq!(call.params["node"], remote_node);
    }
}

#[test]
fn duplicate_explicit_ids_on_two_owners_are_visible_and_never_routed() {
    let id = "explicit-duplicate";
    let first_owner = "ouro@mini.test";
    let second_owner = "ouro@workstation.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": id,
            "node": first_owner,
            "provider": "codex",
            "status": "running",
            "updated_at": "2026-01-01T00:00:00Z"
        }]),
    );
    app.open_session(Plane::Interactive, id.into());
    let initial = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("the unique owner can initially be watched");
    answer(&mut app, initial.tag, json!([]));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([
            {
                "id": id,
                "node": first_owner,
                "provider": "codex",
                "status": "running",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            {
                "id": id,
                "node": second_owner,
                "provider": "codex",
                "status": "running",
                "updated_at": "2026-01-01T00:00:01Z"
            }
        ]),
    );

    let notice = app.notice.as_ref().expect("the collision is announced");
    assert!(notice.text.contains(first_owner));
    assert!(notice.text.contains(second_owner));
    assert!(notice.text.contains("Explicit IDs must be fleet-unique"));
    assert!(notice.text.contains("generated IDs already are"));
    assert!(app
        .cursors
        .snapshot()
        .iter()
        .all(|(plane, watched, _cursor, _node)| { *plane != Plane::Interactive || watched != id }));

    // A fleet list is a partial observation: an unavailable owner's RPC can be omitted.
    // Once two owners have proved a collision, seeing only one later must never make the
    // ambiguous id routeable again.
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": id,
            "node": first_owner,
            "provider": "codex",
            "status": "running",
            "updated_at": "2026-01-01T00:00:02Z"
        }]),
    );

    apply_leader(&mut app, 'l');
    assert_eq!(
        app.sessions
            .merged()
            .iter()
            .filter(|session| session.id == id)
            .count(),
        1,
        "duplicate owners collapse into one visible conflict row"
    );
    let picker = render(&mut app, 140, 30);
    assert!(picker.contains("ID conflict"), "{}", picker.text());
    assert!(picker.contains(first_owner), "{}", picker.text());
    assert!(picker.contains(second_owner), "{}", picker.text());

    app.apply(key(KeyCode::Enter));
    assert!(app
        .drain()
        .iter()
        .all(|call| call.method != "interactive.subscribe"));

    type_text(&mut app, "do not send this to an arbitrary owner");
    app.apply(key(KeyCode::Enter));
    assert!(app
        .drain()
        .iter()
        .all(|call| !call.method.starts_with("interactive.")));
    assert!(app
        .notice
        .as_ref()
        .is_some_and(|notice| notice.text.contains("no request was sent")));
}

#[test]
fn cancelling_a_remote_coding_task_keeps_its_owner_node() {
    let remote_node = "ouro@workstation.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Coding),
        json!([{
            "id": "task-remote-1",
            "node": remote_node,
            "provider": "codex",
            "status": "running",
            "updated_at": "2026-01-01T00:00:00Z"
        }]),
    );
    app.open_session(Plane::Coding, "task-remote-1".into());
    let _ = app.drain();
    app.apply(key(KeyCode::Char('x')));
    app.apply(key(KeyCode::Enter));

    let cancel = app
        .drain()
        .into_iter()
        .find(|call| call.method == "coding.cancel")
        .expect("a remote task cancellation");
    assert_eq!(cancel.params["node"], remote_node);
}

#[test]
fn a_remote_machine_loss_retains_the_cursor_and_resubscribes_after_reconnect() {
    let remote_id = "session-recover-1";
    let remote_node = "ouro@mini.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": remote_id,
            "node": remote_node,
            "provider": "codex",
            "status": "running"
        }]),
    );
    app.open_session(Plane::Interactive, remote_id.into());
    let initial = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("the initial remote subscription");
    answer(&mut app, initial.tag, json!([]));

    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": remote_id,
                "node": remote_node,
                "event": {
                    "id": "evt-before-loss",
                    "session_id": remote_id,
                    "sequence": 1,
                    "type": "output_text_final",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "payload": { "text": "still running remotely" }
                }
            }
        }),
    );
    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "stream.ended",
            "params": {
                "id": remote_id,
                "node": remote_node,
                "plane": "interactive",
                "status": "unknown"
            }
        }),
    );

    assert!(
        app.sessions
            .open_watch()
            .expect("the retained watch")
            .ended
            .is_none(),
        "unknown means unreachable, not terminal"
    );
    assert!(app
        .cursors
        .snapshot()
        .iter()
        .any(|(plane, id, cursor, node)| {
            *plane == Plane::Interactive
                && id == remote_id
                && *cursor == 1
                && node.as_deref() == Some(remote_node)
        }));

    let status_call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "runtime.status")
        .expect("machine recovery checks fleet status");
    answer(
        &mut app,
        status_call.tag,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": remote_node, "machine": "mini", "role": "core", "state": "offline" }
                    ]
                }
            }
        }),
    );
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.subscribe"),
        "a known-offline owner is not hammered"
    );

    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [remote_node],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": remote_node, "machine": "mini", "role": "core", "state": "connected" }
                    ]
                }
            }
        }),
    );
    let retries = app
        .drain()
        .into_iter()
        .filter(|call| call.method == "interactive.subscribe")
        .collect::<Vec<_>>();
    assert_eq!(retries.len(), 1, "one status answer starts one subscribe");
    let retry = retries.into_iter().next().expect("the one retry");
    assert_eq!(retry.params["node"], remote_node);
    assert_eq!(retry.params["cursor"], 1);

    app.apply(Msg::Answer {
        tag: retry.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "owner still starting".into(),
            data: None,
        })),
    });
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [remote_node],
            "cluster": { "distributed": true }
        }),
    );
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.subscribe"),
        "the retry is backed off after a refusal"
    );

    app.ticks = 13;
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [remote_node],
            "cluster": { "distributed": true }
        }),
    );
    let retry = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("the bounded retry becomes due");
    answer(
        &mut app,
        retry.tag,
        json!([{
            "id": "evt-after-loss",
            "session_id": remote_id,
            "sequence": 2,
            "type": "output_text_final",
            "timestamp": "2026-01-01T00:00:01Z",
            "payload": { "text": "continued after reconnect" }
        }]),
    );

    let watch = app.sessions.open_watch().expect("the recovered watch");
    assert_eq!(watch.cursor(), 2);
    assert!(watch.ended.is_none());
    assert!(app.notice.as_ref().is_some_and(|notice| notice
        .text
        .contains("reconnected and resumed from cursor 2")));
}

#[test]
fn a_local_gateway_reconnect_waits_for_an_offline_remote_owner_then_resumes() {
    let remote_id = "session-owner-down-during-local-reconnect";
    let remote_node = "ouro@mini.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": remote_id,
            "node": remote_node,
            "provider": "codex",
            "status": "running"
        }]),
    );
    app.open_session(Plane::Interactive, remote_id.into());
    let initial = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("the initial remote subscription");
    answer(&mut app, initial.tag, json!([]));
    notify(
        &mut app,
        json!({
            "jsonrpc": "2.0",
            "method": "interactive.event",
            "params": {
                "id": remote_id,
                "node": remote_node,
                "event": {
                    "id": "evt-before-local-reconnect",
                    "session_id": remote_id,
                    "sequence": 1,
                    "type": "output_text_final",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "payload": { "text": "owned by mini" }
                }
            }
        }),
    );

    // The local gateway comes back first. Its reconnect hook tries every remembered
    // cursor, and this remote owner is still absent when that subscribe reaches it.
    app.apply(Msg::Reconnected(Box::new(full_hello())));
    app.apply(Msg::Answer {
        tag: Tag::Resync {
            plane: Plane::Interactive,
            id: remote_id.into(),
            cursor: 1,
            subscribe: true,
        },
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::Unavailable,
            message: "session owner is offline; Ouroboros is reconnecting".into(),
            data: Some(json!({
                "reason": "owner_unavailable",
                "node": remote_node,
                "outcome": "unknown"
            })),
        })),
    });

    assert!(app
        .cursors
        .snapshot()
        .iter()
        .any(|(plane, id, cursor, node)| {
            *plane == Plane::Interactive
                && id == remote_id
                && *cursor == 1
                && node.as_deref() == Some(remote_node)
        }));
    assert!(app
        .sessions
        .open_watch()
        .expect("the cursor-preserving watch")
        .ended
        .is_none());
    assert!(app
        .notice
        .as_ref()
        .is_some_and(|notice| notice.text.contains("machine is still unreachable")));

    let status = app
        .drain()
        .into_iter()
        .find(|call| call.method == "runtime.status")
        .expect("the failed hook subscribe starts machine-status recovery");
    answer(
        &mut app,
        status.tag,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": remote_node, "machine": "mini", "role": "core", "state": "offline" }
                    ]
                }
            }
        }),
    );
    assert!(app
        .drain()
        .into_iter()
        .all(|call| call.method != "interactive.subscribe"));

    app.ticks = 38;
    app.apply(Msg::Tick);
    let status = app
        .drain()
        .into_iter()
        .find(|call| call.method == "runtime.status")
        .expect("recovery keeps polling while the remote owner is offline");
    answer(
        &mut app,
        status.tag,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [remote_node],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": remote_node, "machine": "mini", "role": "core", "state": "connected" }
                    ]
                }
            }
        }),
    );
    let retries = app
        .drain()
        .into_iter()
        .filter(|call| call.method == "interactive.subscribe")
        .collect::<Vec<_>>();
    assert_eq!(retries.len(), 1, "the owner rejoin starts one subscribe");
    let retry = retries.into_iter().next().expect("the one owner retry");
    assert_eq!(retry.params["node"], remote_node);
    assert_eq!(retry.params["cursor"], 1);
    answer(
        &mut app,
        retry.tag,
        json!([{
            "id": "evt-after-owner-rejoin",
            "session_id": remote_id,
            "sequence": 2,
            "type": "output_text_final",
            "timestamp": "2026-01-01T00:00:01Z",
            "payload": { "text": "remote owner resumed" }
        }]),
    );

    let watch = app.sessions.open_watch().expect("the resumed remote watch");
    assert_eq!(watch.cursor(), 2);
    assert!(watch.ended.is_none());
    assert!(app.notice.as_ref().is_some_and(|notice| notice
        .text
        .contains("reconnected and resumed from cursor 2")));
}

#[test]
fn an_indeterminate_transport_failure_opening_a_remote_stream_enters_recovery() {
    let id = "session-remote-open-timeout";
    let owner = "ouro@mini.test";
    let mut app = shell(full_hello());
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": id,
            "node": owner,
            "provider": "codex",
            "status": "running"
        }]),
    );
    app.open_session(Plane::Interactive, id.into());
    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("opening the remembered remote stream subscribes");
    app.apply(Msg::Answer {
        tag: subscribe.tag,
        result: Err(ClientError::Timeout),
    });

    assert!(app
        .cursors
        .snapshot()
        .iter()
        .any(|(plane, watched, cursor, node)| {
            *plane == Plane::Interactive
                && watched == id
                && *cursor == 0
                && node.as_deref() == Some(owner)
        }));
    assert!(app
        .drain()
        .iter()
        .any(|call| call.method == "runtime.status"));
    assert!(app
        .notice
        .as_ref()
        .is_some_and(|notice| notice.text.contains("cursor is safe")));
}

#[test]
fn the_composer_queues_while_running_and_ctrl_c_interrupts_rather_than_quitting() {
    let mut app = with_open_session();

    type_text(&mut app, "look at the tests");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("a queued follow-up");

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
fn the_composer_edits_and_sends_a_multiline_bracketed_paste() {
    let mut app = with_open_session();

    app.apply(Msg::Paste("first\r\nthird".into()));
    app.apply(key(KeyCode::Up));
    app.apply(modified(KeyCode::Enter, KeyModifiers::SHIFT));
    type_text(&mut app, "second");

    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "first\nsecond\nthird"
    );

    app.apply(key(KeyCode::Enter));
    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("a multiline follow-up");

    assert_eq!(call.params["input"], "first\nsecond\nthird");
}

#[test]
fn the_open_composer_names_the_provider_and_serializes_later_requests() {
    let mut app = with_open_session();

    let screen = render(&mut app, 180, 30);
    assert!(screen.contains("claude_code"), "{}", screen.text());
    assert!(!screen.contains("PROVIDER Codex"), "{}", screen.text());
    assert!(screen.contains("workspace /tmp/w"), "{}", screen.text());
    assert!(screen.contains("APPROVAL auto_edit"), "{}", screen.text());
    assert!(
        screen.contains("FILES provider default"),
        "{}",
        screen.text()
    );
    assert!(
        screen.contains("/write to edit"),
        "a session that did not pin write access offers the switch: {}",
        screen.text()
    );

    type_text(&mut app, "first queued request");
    app.apply(key(KeyCode::Enter));
    let first = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the first follow-up");

    type_text(&mut app, "second queued request");
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.follow_up"),
        "the second input remains visible until the first RPC is classified"
    );
    answer(
        &mut app,
        first.tag,
        json!({"id": first.params["turn_id"], "status": "queued"}),
    );
    app.apply(key(KeyCode::Enter));

    let second = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.follow_up")
        .expect("the second follow-up after the first acknowledgement");
    assert_eq!(first.params["input"], "first queued request");
    assert_eq!(second.params["input"], "second queued request");
}

#[test]
fn an_open_session_never_borrows_client_workspace_or_provider_defaults() {
    let mut app = with_open_session();
    app.config.defaults.provider = Some("codex".into());
    app.config.defaults.workspace = Some("/wrong/client-default".into());
    app.launch_dir = Some("/wrong/local-cwd".into());

    // The transcript/watch can outlive a delayed or refreshed list snapshot. Until that
    // authoritative session row returns, the shell must name the fact as unknown.
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));

    let screen = render(&mut app, 160, 30);
    assert!(
        screen.contains("session workspace unknown"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("Provider unknown"), "{}", screen.text());
    assert!(
        !screen.contains("/wrong/client-default"),
        "{}",
        screen.text()
    );
    assert!(!screen.contains("/wrong/local-cwd"), "{}", screen.text());
    assert!(
        !screen.contains("ChatGPT not connected"),
        "{}",
        screen.text()
    );
}

#[test]
fn composer_history_restores_the_unsent_draft() {
    let mut app = with_open_session();

    type_text(&mut app, "previous request");
    app.apply(key(KeyCode::Enter));
    let _ = app.drain();

    type_text(&mut app, "unfinished draft");
    app.apply(key(KeyCode::Up));
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "previous request"
    );

    app.apply(key(KeyCode::Down));
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "unfinished draft"
    );
}

#[test]
fn slash_commands_and_workspace_mentions_complete_in_the_composer() {
    let mut app = with_open_session();
    app.apply(Msg::WorkspaceFiles(vec![
        "src/ui/app.rs".into(),
        "src/ui/view.rs".into(),
    ]));

    type_text(&mut app, "/sett");
    let commands = render(&mut app, 120, 30);
    assert!(commands.contains("/settings"), "{}", commands.text());
    assert!(commands.contains("command"), "{}", commands.text());

    app.apply(key(KeyCode::Tab));
    app.apply(key(KeyCode::Enter));
    assert!(
        matches!(app.overlay, Some(Overlay::Settings(_))),
        "a completed local command must not be sent to the provider"
    );
    assert!(
        app.drain().into_iter().all(|call| {
            call.method != "interactive.send_message" && call.method != "interactive.follow_up"
        }),
        "a slash command is a local action, not model input"
    );

    app.apply(key(KeyCode::Esc));
    type_text(&mut app, "inspect @ui/app");
    let files = render(&mut app, 120, 30);
    assert!(files.contains("@src/ui/app.rs"), "{}", files.text());
    assert!(files.contains("local workspace path"), "{}", files.text());

    app.apply(key(KeyCode::Tab));
    assert_eq!(
        app.sessions
            .composer
            .as_ref()
            .expect("composer")
            .editor
            .text(),
        "inspect @src/ui/app.rs "
    );
}

#[test]
fn preview_without_a_name_lists_workspace_proposals() {
    let mut app = with_open_session();
    let _ = app.drain();

    type_text(&mut app, "/preview");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "capabilities.list")
        .expect("a list");
    assert_eq!(call.params["workspace"], "/tmp/w");
}

#[test]
fn preview_names_a_contained_proposal_and_uses_the_forge_budget() {
    let mut app = with_open_session();
    let _ = app.drain();

    type_text(&mut app, "/preview Echo");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "capabilities.preview")
        .expect("a preview");
    assert_eq!(call.params["workspace"], "/tmp/w");
    assert_eq!(call.params["path"], ".ouroboros/capabilities/Echo");
    assert_eq!(call.timeout, Some(ouro::ui::app::START_TIMEOUT));
}

#[test]
fn admit_confirms_before_forging_and_records_the_open_session() {
    let mut app = with_open_session();
    let _ = app.drain();

    type_text(&mut app, "/admit Echo");
    app.apply(key(KeyCode::Enter));

    assert!(
        matches!(app.overlay, Some(Overlay::Confirm { .. })),
        "admit is operator-gated"
    );
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "capabilities.admit"),
        "confirming is what admits, not the slash itself"
    );

    app.apply(key(KeyCode::Up));
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "capabilities.admit")
        .expect("an admit");
    assert_eq!(call.params["workspace"], "/tmp/w");
    assert_eq!(call.params["path"], ".ouroboros/capabilities/Echo");
    assert_eq!(call.params["session_id"], "session-0000000000000000000001");
    assert_eq!(call.timeout, Some(ouro::ui::app::START_TIMEOUT));
}

#[test]
fn a_preview_answer_is_said_as_a_notice_not_as_user_text() {
    let mut app = with_open_session();
    let _ = app.drain();

    type_text(&mut app, "/preview Echo");
    app.apply(key(KeyCode::Enter));
    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "capabilities.preview")
        .expect("a preview");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!({
            "module": "Ouroboros.Capability.Echo",
            "loaded?": false,
            "test_report": { "total": 1, "failures": 0 }
        })),
    });

    let notice = app.notice.as_ref().expect("a preview notice");
    assert!(notice.text.contains("Ouroboros.Capability.Echo"));
    assert!(notice.text.contains("not loaded"));
    assert_eq!(notice.kind, NoticeKind::Info);
}

#[test]
fn x_confirms_before_ending_a_session() {
    let mut app = with_open_session();

    apply_leader(&mut app, 'x');

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
fn x_in_the_session_switcher_removes_a_terminal_session() {
    let mut app = with_open_session();
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([
            {
                "id": "session-0000000000000000000001",
                "status": "running",
                "updated_at": "2026-01-01T00:00:02.000000Z"
            },
            {
                "id": "session-dead",
                "status": "lost",
                "provider": "codex",
                "updated_at": "2026-01-01T00:00:01.000000Z"
            }
        ]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    apply_leader(&mut app, 'l');
    let _ = app.drain();
    let picker = render(&mut app, 80, 20);
    assert!(picker.contains("x end"), "{}", picker.text());

    app.apply(key(KeyCode::Down));
    app.apply(key(KeyCode::Char('x')));

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("remove session-dead"), "{}", screen.text());
    assert!(
        screen.contains("remove from this machine"),
        "{}",
        screen.text()
    );
    assert!(app.drain().is_empty(), "confirming is what deletes");

    app.apply(key(KeyCode::Enter));
    let call = app.drain().into_iter().next().expect("a delete");
    assert_eq!(call.method, "interactive.delete");
    assert_eq!(call.params["id"], "session-dead");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!("ok")),
    });

    assert!(app
        .sessions
        .merged()
        .iter()
        .all(|session| session.id != "session-dead"));
    assert_eq!(
        app.sessions.open.as_ref().map(|(_plane, id)| id.as_str()),
        Some("session-0000000000000000000001")
    );
    assert!(
        matches!(app.overlay, Some(Overlay::SessionPicker { .. })),
        "the switcher returns so several dead rows can be cleared"
    );
}

#[test]
fn x_on_a_lost_open_session_offers_remove_instead_of_kill() {
    let mut app = with_open_session();
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "session-0000000000000000000001",
            "status": "lost",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );

    apply_leader(&mut app, 'x');

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("remove session-"), "{}", screen.text());
    assert!(!screen.contains("kill (stop it now)"), "{}", screen.text());

    app.apply(key(KeyCode::Enter));
    let call = app.drain().into_iter().next().expect("a delete");
    assert_eq!(call.method, "interactive.delete");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!("ok")),
    });

    assert!(app.sessions.open.is_none());
    assert!(app.sessions.merged().is_empty());
}

#[test]
fn x_hides_a_last_known_offline_row_without_calling_the_runtime() {
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('2')));
    let remote_node = "ouro@late-member.test";

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "late-member-session",
            "node": remote_node,
            "status": "running",
            "updated_at": "2026-01-01T00:00:02.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouroboros@golden",
            "connected_nodes": [],
            "cluster": {
                "distributed": true,
                "fleet": {
                    "machines": [
                        { "node": "ouroboros@golden", "machine": "local", "state": "local" },
                        { "node": remote_node, "machine": "late-member", "state": "offline" }
                    ]
                }
            }
        }),
    );
    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "local-session",
            "node": "ouroboros@golden",
            "status": "idle",
            "updated_at": "2026-01-01T00:00:03.000000Z"
        }]),
    );

    let _ = app.drain();
    app.overlay = Some(Overlay::SessionPicker {
        selected: Some((Plane::Interactive, "late-member-session".into())),
    });
    app.apply(key(KeyCode::Char('x')));

    let screen = render(&mut app, 120, 24);
    assert!(
        screen.contains("hide late-member-session"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("hide here"), "{}", screen.text());

    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain().is_empty(),
        "an offline last-known row is hidden here; its owner cannot be reached"
    );
    assert!(app
        .sessions
        .merged()
        .iter()
        .all(|session| session.id != "late-member-session"));
    assert!(app
        .sessions
        .merged()
        .iter()
        .any(|session| session.id == "local-session"));

    answer(
        &mut app,
        Tag::Sessions(Plane::Interactive),
        json!([{
            "id": "local-session",
            "node": "ouroboros@golden",
            "status": "idle",
            "updated_at": "2026-01-01T00:00:04.000000Z"
        }]),
    );
    assert!(app
        .sessions
        .merged()
        .iter()
        .all(|session| session.id != "late-member-session"));
}

#[test]
fn a_coding_task_is_told_it_takes_no_input_rather_than_being_sent_one() {
    let mut app = shell(full_hello());
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

// ----- starting a session -------------------------------------------------------------

/// Which row of the new-session form has focus.
fn field(app: &App) -> Option<NewField> {
    match &app.overlay {
        Some(Overlay::New(dialog)) => Some(dialog.field),
        _ => None,
    }
}

/// Moves to a named row. Tests say which field they mean rather than counting keystrokes,
/// because the row list changes with the plane.
fn focus(app: &mut App, target: NewField) {
    for _ in 0..12 {
        if field(app) == Some(target) {
            return;
        }

        app.apply(key(KeyCode::Down));
    }

    panic!("the form never reached {target:?}");
}

/// The Sessions tab with both lists answered and a provider list the modal can draw.
fn ready_to_start() -> App {
    let mut app = shell(full_hello());
    app.launch_dir = Some("/home/operator/project".into());

    app.apply(key(KeyCode::Char('2')));
    answer(&mut app, Tag::Sessions(Plane::Interactive), json!([]));
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

    answer(
        &mut app,
        Tag::Providers,
        json!([
            {
                "provider": "claude_code",
                "spec": {},
                "status": { "installed": true, "compatible": true, "authenticated": true },
                "error": null
            },
            {
                "provider": "gemini",
                "spec": {},
                "status": { "installed": false, "compatible": false, "authenticated": "unknown" },
                "error": null
            }
        ]),
    );

    let _ = app.drain();
    app
}

#[test]
fn n_opens_a_form_whose_every_choice_is_visible() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 120, 30);

    assert!(screen.contains("new session"), "{}", screen.text());
    assert!(screen.contains("plane"));
    assert!(screen.contains("interactive — a conversation you send messages to"));
    assert!(screen.contains("provider"));
    assert!(screen.contains("workspace"));
    assert!(screen.contains("approval"));
    assert!(screen.contains("[ start ]"));

    // The launch directory is offered, not assumed: it is on screen and editable.
    assert!(
        screen.contains("/home/operator/project"),
        "{}",
        screen.text()
    );

    // Nothing is sent by opening a dialog.
    assert!(app.drain().is_empty());
}

#[test]
fn new_session_can_choose_a_connected_machine_by_friendly_name() {
    let mut app = ready_to_start();
    app.fleet_profile = Some(fleet_profile());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": {
                    "summary": { "expected": 3, "connected": 2, "offline": 1 },
                    "machines": [
                        { "machine": "studio", "node": "ouro@studio.test", "role": "core", "state": "local" },
                        { "machine": "mini", "node": "ouro@mini.test", "role": "core", "state": "connected" },
                        { "machine": "workstation", "node": "ouro@workstation.test", "role": "core", "state": "offline" }
                    ]
                }
            }
        }),
    );
    app.apply(key(KeyCode::Char('n')));
    focus(&mut app, NewField::Machine);
    app.apply(key(KeyCode::Right));

    let form = render(&mut app, 120, 30);
    assert!(
        form.contains("mini — connected (ouro@mini.test)"),
        "{}",
        form.text()
    );
    assert!(!form.contains("workstation — connected"));
    assert!(form.contains("Connected checks reachability, not provider readiness"));
    assert!(form.contains("fleet invites never copy credentials"));
    assert!(
        form.contains("claude_code — readiness unknown on destination"),
        "{}",
        form.text()
    );
    assert!(
        !form.contains("claude_code (1/2)"),
        "the local provider's green-ready label must not describe a remote machine: {}",
        form.text()
    );
    assert_eq!(
        form.colour_of("claude_code", "claude_code"),
        Color::LightYellow,
        "remote readiness is unknown even when the gateway has this provider"
    );

    focus(&mut app, NewField::Provider);
    app.apply(key(KeyCode::Right));
    let remote_missing_locally = render(&mut app, 120, 30);
    assert!(
        remote_missing_locally.contains("gemini — readiness unknown on destination"),
        "{}",
        remote_missing_locally.text()
    );
    assert!(
        !remote_missing_locally.contains("gemini — not installed"),
        "the gateway's missing executable is not evidence about the destination: {}",
        remote_missing_locally.text()
    );
    assert_eq!(
        remote_missing_locally.colour_of("gemini", "gemini"),
        Color::LightYellow,
        "remote readiness is unknown even when the gateway lacks this provider"
    );
    app.apply(key(KeyCode::Left));

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));
    assert!(
        app.drain().is_empty(),
        "an inferred local cwd is never sent remotely"
    );
    let form = render(&mut app, 120, 30);
    assert!(
        form.contains("choose an absolute workspace path on the destination machine"),
        "{}",
        form.text()
    );

    focus(&mut app, NewField::Workspace);
    type_text(&mut app, "/srv/project");

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));
    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a remote start");
    assert_eq!(start.params["machine"], "mini");
    assert_eq!(start.params["workspace"], "/srv/project");
    assert!(start.params.get("node").is_none());
}

#[test]
fn an_incompatible_connected_machine_is_not_offered_for_paid_work() {
    let mut app = ready_to_start();
    app.fleet_profile = Some(fleet_profile());
    answer(
        &mut app,
        Tag::Status,
        json!({
            "node": "ouro@studio.test",
            "connected_nodes": ["ouro@mini.test"],
            "cluster": {
                "distributed": true,
                "formation": { "strategy": "epmd" },
                "security": { "tls": true },
                "fleet": {
                    "summary": { "expected": 3, "connected": 2, "offline": 1 },
                    "machines": [
                        { "machine": "studio", "node": "ouro@studio.test", "role": "core", "state": "local", "compatibility": "compatible" },
                        { "machine": "mini", "node": "ouro@mini.test", "role": "core", "state": "connected", "compatibility": "incompatible" }
                    ]
                }
            }
        }),
    );

    app.apply(key(KeyCode::Char('n')));
    focus(&mut app, NewField::Machine);
    app.apply(key(KeyCode::Right));

    let form = render(&mut app, 120, 30);
    assert!(!form.contains("mini — connected"), "{}", form.text());
    assert!(form.contains("This machine"), "{}", form.text());
}

#[test]
fn the_provider_list_greys_an_uninstalled_provider_and_still_offers_it() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.row("claude_code").contains("(1/2)"),
        "{}",
        screen.text()
    );
    assert_eq!(screen.colour_of("claude_code", "claude_code"), Color::Green);

    // Right moves to the uninstalled one, which is drawn dim and says why.
    app.apply(key(KeyCode::Right));
    let screen = render(&mut app, 120, 30);

    assert!(
        screen.row("gemini").contains("not installed"),
        "{}",
        screen.text()
    );
    assert_eq!(screen.colour_of("gemini", "gemini"), Color::DarkGray);
    assert!(
        screen.contains("the runtime decides, not this probe"),
        "an installed-probe is a heuristic and the runtime is the authority:\n{}",
        screen.text()
    );

    // Selectable anyway: this client does not overrule the runtime on a probe.
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("an uninstalled provider is still the operator's to try");

    assert_eq!(call.params["provider"], "gemini");
}

#[test]
fn the_form_produces_exactly_the_options_the_gateway_allowlists() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    // provider stays claude_code; retype the workspace; pick `prompt`; start.
    focus(&mut app, NewField::Workspace);
    for _ in 0..40 {
        app.apply(key(KeyCode::Backspace));
    }
    type_text(&mut app, "/srv/work");

    focus(&mut app, NewField::ApprovalMode);
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("prompt — ask before every action"),
        "{}",
        screen.text()
    );

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    assert_eq!(call.params["provider"], "claude_code");
    assert_eq!(call.params["workspace"], "/srv/work");
    assert_eq!(call.params["approval_mode"], "prompt");
    assert_eq!(
        call.params.as_object().expect("an object").len(),
        4,
        "an option outside @start_options is -32602 naming it, so none is invented: {:?}",
        call.params
    );

    // The 120s gateway ceiling, not the transport's 20s default.
    assert_eq!(call.timeout, Some(ouro::ui::app::START_TIMEOUT));
}

#[test]
fn the_form_can_pin_workspace_write_or_read_only() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::SandboxMode);
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Right));
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 140, 30);
    assert!(
        screen.contains("can edit — can edit files in the workspace"),
        "{}",
        screen.text()
    );

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    assert_eq!(call.params["sandbox_mode"], "workspace_write");
}

#[test]
fn write_starts_a_session_that_can_edit_when_this_one_cannot() {
    let mut app = with_open_session();

    type_text(&mut app, "/write");
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a writable start");

    assert_eq!(call.params["sandbox_mode"], "workspace_write");
    assert_eq!(call.params["provider"], "claude_code");
    assert_eq!(call.params["workspace"], "/tmp/w");
}

#[test]
fn an_empty_workspace_is_omitted_rather_than_sent_blank() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::Workspace);
    for _ in 0..60 {
        app.apply(key(KeyCode::Backspace));
    }

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("none — the plane decides"),
        "{}",
        screen.text()
    );

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a start");

    let fields = call.params.as_object().expect("an object");

    assert!(
        !fields.contains_key("workspace"),
        "the gateway requires a nonempty string, so a blank box means no workspace: {fields:?}"
    );
    assert!(!fields.contains_key("approval_mode"));
    assert!(fields.contains_key("id"));
    assert_eq!(fields.len(), 2);
}

#[test]
fn the_coding_plane_adds_an_objective_row_and_requires_it() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::Plane);
    app.apply(key(KeyCode::Right));

    let screen = render(&mut app, 120, 30);

    assert!(
        screen.contains("coding — one objective, run to completion"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("objective"), "{}", screen.text());

    // Straight to start with no objective: refused here, on the form that produced it.
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    assert!(app.drain().is_empty(), "an invalid form sends nothing");

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("a coding task needs an objective"),
        "{}",
        screen.text()
    );

    // Fill it in and the start carries it.
    focus(&mut app, NewField::Objective);
    type_text(&mut app, "fix the build");
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "coding.start")
        .expect("a coding start");

    assert_eq!(call.params["objective"], "fix the build");
    assert_eq!(call.params["provider"], "claude_code");
}

#[test]
fn a_refused_start_stays_on_the_form_rather_than_flashing_past_in_a_notice() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app.drain().into_iter().next().expect("a start");

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("starting"),
        "a start in flight says so: {}",
        screen.text()
    );

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Err(ClientError::Rpc(
            serde_json::from_value(json!({
                "code": -32602,
                "message": "params.provider must name a provider this node serves: codex"
            }))
            .expect("an error"),
        )),
    });

    let screen = render(&mut app, 130, 30);

    assert!(
        screen.contains("new session"),
        "the form is still open: {}",
        screen.text()
    );
    assert!(
        screen.contains("must name a provider this node serves"),
        "{}",
        screen.text()
    );
    assert!(screen.contains("[ start ]"), "and it is submittable again");
    assert!(app.sessions.open.is_none());
}

#[test]
fn an_unknown_start_reconciles_the_same_id_before_any_new_start() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let first = app.drain().into_iter().next().expect("a start");
    let first_params = first.params.clone();
    let first_id = first.params["id"]
        .as_str()
        .expect("a stable id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::Timeout),
    });

    let screen = render(&mut app, 140, 30);
    assert!(screen.contains(&first_id), "{}", screen.text());
    assert!(screen.contains("already exist"), "{}", screen.text());
    assert!(screen.contains("reconcile"), "{}", screen.text());

    // The old request cannot be edited into a different request while retaining its id.
    app.apply(key(KeyCode::Char('x')));
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));
    let retry = app.drain().into_iter().next().expect("a reconciliation");
    assert_eq!(retry.params, first_params);

    app.apply(Msg::Answer {
        tag: retry.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::InvalidParams,
            message: "provider is not ready".into(),
            data: None,
        })),
    });

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));
    let replacement = app.drain().into_iter().next().expect("a fresh start");
    assert_ne!(replacement.params["id"], first_id);
}

#[test]
fn a_generic_runtime_start_failure_reconciles_instead_of_minting_a_duplicate() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));
    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let first = app.drain().into_iter().next().expect("a start");
    let first_params = first.params.clone();
    let first_id = first.params["id"]
        .as_str()
        .expect("a stable id")
        .to_string();

    app.apply(Msg::Answer {
        tag: first.tag,
        result: Err(ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "the provider failed after durable creation".into(),
            data: None,
        })),
    });

    let screen = render(&mut app, 140, 30);
    assert!(screen.contains(&first_id), "{}", screen.text());
    assert!(screen.contains("may already exist"), "{}", screen.text());

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));
    let retry = app.drain().into_iter().next().expect("a reconciliation");
    assert_eq!(retry.params, first_params);
}

#[test]
fn a_durable_failed_home_start_opens_the_session_without_dispatching_the_draft() {
    let mut app = shell(full_hello());
    app.config.defaults.provider = Some("claude_code".into());
    let input = "keep this prompt until the provider is repaired";

    type_text(&mut app, input);
    app.apply(key(KeyCode::Enter));

    let start = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.start")
        .expect("a home start");
    let id = start.params["id"]
        .as_str()
        .expect("the caller-owned id")
        .to_string();

    app.apply(Msg::Answer {
        tag: start.tag,
        result: Ok(json!({
            "id": id,
            "node": "ouroboros@golden",
            "outcome": "created",
            "ready": false,
            "error": ["session_start_failed", ["provider_not_ready", "login required"]]
        })),
    });

    assert_eq!(app.sessions.open, Some((Plane::Interactive, id.clone())));
    let composer = app.sessions.composer.as_ref().expect("the restored draft");
    assert_eq!(composer.editor.text(), input);
    assert_eq!(composer.verb, ComposerVerb::Message);

    let calls = app.drain();
    assert!(
        calls
            .iter()
            .any(|call| call.method == "interactive.subscribe"),
        "the durable failed session is still opened and watched"
    );
    assert!(
        calls
            .iter()
            .all(|call| call.method != "interactive.send_message"),
        "a readiness failure means the saved draft was definitely not dispatched: {calls:?}"
    );

    let notice = &app
        .notice
        .as_ref()
        .expect("the created-failure notice")
        .text;
    assert!(notice.contains(&id), "{notice}");
    assert!(notice.contains("did not become ready"), "{notice}");
    assert!(
        notice.contains("no first message was dispatched"),
        "{notice}"
    );
}

#[test]
fn a_refusal_carries_the_reason_the_gateway_put_in_its_data() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app.drain().into_iter().next().expect("a start");

    // The shape `{:error, {:invalid_workspace, path}}` Wire-encodes to. Most `-32006`
    // messages describe the shape of the failure and put the actionable part in `data`.
    app.apply(Msg::Answer {
        tag: call.tag,
        result: Err(ClientError::Rpc(
            serde_json::from_value(json!({
                "code": -32006,
                "message": "the runtime refused the call",
                "data": ["invalid_workspace", "/srv/nope"]
            }))
            .expect("an error"),
        )),
    });

    let screen = render(&mut app, 130, 30);

    assert!(
        screen.contains("invalid_workspace"),
        "a refusal whose reason is only in `data` is not a readable refusal:\n{}",
        screen.text()
    );
    assert!(screen.contains("/srv/nope"), "{}", screen.text());
}

#[test]
fn a_started_session_is_watched_focused_and_ready_to_be_written_to() {
    let mut app = ready_to_start();
    app.apply(key(KeyCode::Char('n')));

    focus(&mut app, NewField::Start);
    app.apply(key(KeyCode::Enter));

    let call = app.drain().into_iter().next().expect("a start");
    let id = call.params["id"]
        .as_str()
        .expect("the client-owned start id")
        .to_string();

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!({
            "_struct": "Ouroboros.Interactive.Ref",
            "id": id,
            "node": "ouroboros@golden"
        })),
    });

    assert!(app.overlay.is_none(), "the form closes on success");
    assert_eq!(app.sessions.open, Some((Plane::Interactive, id.clone())));

    // Subscribed at cursor 0, through the same resync path everything else uses.
    let subscribe = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.subscribe")
        .expect("a new session is watched immediately");

    assert_eq!(subscribe.params["id"], id);
    assert_eq!(subscribe.params["cursor"], 0);

    // The composer is open, so the next thing typed is the first message.
    let screen = render(&mut app, 120, 30);
    assert!(screen.contains(&id), "{}", screen.text());
    assert!(screen.contains("Enter sends"), "{}", screen.text());

    type_text(&mut app, "read the tests");
    app.apply(key(KeyCode::Enter));

    let message = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.send_message")
        .expect("the composer was ready");

    assert_eq!(message.params["id"], id);
    assert_eq!(message.params["input"], "read the tests");
}

#[test]
fn a_read_listener_is_told_why_it_cannot_start_a_session() {
    let mut app = shell(support::hello(&[
        "hello",
        "interactive.start",
        "interactive.list",
    ]));
    app.hello.scope = "read".into();
    app.apply(key(KeyCode::Char('2')));
    let _ = app.drain();

    app.apply(key(KeyCode::Char('n')));

    assert!(
        app.overlay.is_none(),
        "no form for a listener that would refuse it"
    );

    let screen = render(&mut app, 130, 30);
    assert!(screen.contains("scope `read`"), "{}", screen.text());

    // And a build that does not serve the verb at all says that instead.
    let mut older = app_without_start();
    older.apply(key(KeyCode::Char('2')));
    let _ = older.drain();
    older.apply(key(KeyCode::Char('n')));

    let screen = render(&mut older, 130, 30);
    assert!(
        screen.contains("does not serve interactive.start"),
        "{}",
        screen.text()
    );
}

fn app_without_start() -> App {
    shell(support::hello(&[
        "hello",
        "interactive.list",
        "coding.list",
    ]))
}

#[test]
fn opening_the_form_asks_for_the_providers_the_sessions_tab_never_polls() {
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('2')));

    let polled: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(
        !polled.contains(&"runtime.providers".to_string()),
        "the Sessions tab does not poll a list that shells out per provider"
    );

    app.apply(key(KeyCode::Char('n')));

    let asked: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(
        asked.contains(&"runtime.providers".to_string()),
        "but a form that lists providers has to have them: {asked:?}"
    );

    let screen = render(&mut app, 120, 30);
    assert!(
        screen.contains("asking the runtime which providers it serves"),
        "{}",
        screen.text()
    );
}

// ----- the value tree ----------------------------------------------------------------

#[test]
fn the_value_tree_names_every_wire_marker() {
    let mut app = shell(full_hello());
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
    let mut app = shell(full_hello());
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
    let mut app = shell(full_hello());
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
    let mut app = shell(full_hello());
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
    let mut app = shell(support::hello(&[
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
    resolve_account(&mut app);

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

    resolve_account(&mut app);
    app.apply(key(KeyCode::Char('7')));
    let screen = render(&mut app, 120, 20);

    assert!(screen.contains("[info] up"), "{}", screen.text());
}

// ----- chrome ------------------------------------------------------------------------

#[test]
fn every_tab_draws_without_any_data_at_all() {
    // A gateway that has answered nothing must still produce every secondary panel even
    // though the persistent tab bar has moved behind the command palette.
    for digit in '1'..='7' {
        let mut app = shell(full_hello());
        app.apply(key(KeyCode::Char(digit)));

        let screen = render(&mut app, 100, 24);

        assert!(
            screen.contains("OUROBOROS")
                && (screen.contains("Runtime & distribution")
                    || screen.contains("New coding session")),
            "surface {digit} lost its shell:\n{}",
            screen.text()
        );
    }
}

#[test]
fn the_quit_dialog_offers_shutdown_only_where_the_gateway_advertises_it() {
    let mut app = shell(full_hello());
    app.apply(key(KeyCode::Char('q')));

    let screen = render(&mut app, 120, 24);
    assert!(screen.contains("detach"), "{}", screen.text());
    assert!(screen.contains("runtime.shutdown, then SIGTERM"));

    let narrow = render(&mut app, 80, 24);
    assert!(narrow.contains("`ouro attach`"), "{}", narrow.text());
    assert!(
        narrow.contains("runtime.shutdown, then SIGTERM, then SIGKILL"),
        "a narrow terminal must still name the full shutdown consequence:\n{}",
        narrow.text()
    );

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
    resolve_account(&mut attached);
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
    shell(support::hello(&["hello", "runtime.status"]))
}

#[test]
fn the_help_overlay_states_the_honest_limits() {
    let mut app = shell(support::hello(&["hello", "runtime.status"]));
    // A read listener, so the scope warning applies.
    app.hello.scope = "read".into();

    app.apply(key(KeyCode::Char('?')));
    let screen = render(&mut app, 130, 30);

    assert!(screen.contains("ctrl+c"), "{}", screen.text());
    assert!(screen.contains("one gateway view of the fleet"));
    assert!(screen.contains("not a sandbox"));
    assert!(screen.contains("scope `read`"));

    app.apply(key(KeyCode::Esc));
    assert!(render(&mut app, 130, 30).contains("Connect ChatGPT to start coding"));
}

#[test]
fn an_open_session_keeps_the_composer_focused_like_an_agent_tui() {
    let mut app = with_open_session();

    assert!(app.sessions.composer.is_some());
    type_text(&mut app, "fix the flaky test");
    assert_eq!(
        app.sessions.composer.as_ref().unwrap().editor.text(),
        "fix the flaky test"
    );

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("ctrl+x leader"), "{}", screen.text());
    assert!(screen.contains("esc abort"), "{}", screen.text());
    assert!(!screen.contains("Press i to write"), "{}", screen.text());
}

#[test]
fn ctrl_x_opens_a_leader_overlay_and_n_starts_a_new_session() {
    let mut app = with_open_session();
    app.apply(ctrl('x'));

    let screen = render(&mut app, 120, 30);
    assert!(screen.contains("ctrl+x"), "{}", screen.text());
    assert!(screen.contains("new session"), "{}", screen.text());
    assert!(screen.contains("copy last message"), "{}", screen.text());

    app.apply(key(KeyCode::Char('n')));
    assert!(app.sessions.open.is_none());
    assert!(app.overlay.is_none());
}

#[test]
fn ctrl_x_y_copies_the_last_agent_message() {
    let mut app = with_open_session();
    notify(
        &mut app,
        event(1, "output_text_final", "the tests are green"),
    );

    apply_leader(&mut app, 'y');
    assert_eq!(app.take_copy().as_deref(), Some("the tests are green"));
}

#[test]
fn escape_interrupts_a_running_turn_without_closing_the_composer() {
    let mut app = with_open_session();
    assert!(app.sessions.composer.is_some());

    app.apply(key(KeyCode::Esc));

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "interactive.interrupt")
        .expect("esc interrupts the running turn");
    assert_eq!(call.params["id"], "session-0000000000000000000001");
    assert!(app.sessions.composer.is_some());
    assert!(app.sessions.open.is_some());
}

#[test]
fn ctrl_c_clears_the_prompt_before_it_interrupts() {
    let mut app = with_open_session();
    type_text(&mut app, "half written");

    app.apply(ctrl('c'));
    assert_eq!(app.sessions.composer.as_ref().unwrap().editor.text(), "");
    assert!(
        app.drain()
            .into_iter()
            .all(|call| call.method != "interactive.interrupt"),
        "clearing a draft must not abort the turn"
    );

    app.apply(ctrl('c'));
    assert!(app
        .drain()
        .into_iter()
        .any(|call| call.method == "interactive.interrupt"));
    assert!(app.quit.is_none());
}

#[test]
fn readline_kills_reach_the_open_composer() {
    let mut app = with_open_session();
    type_text(&mut app, "hello world");
    app.apply(ctrl('w'));
    assert_eq!(
        app.sessions.composer.as_ref().unwrap().editor.text(),
        "hello "
    );
    app.apply(ctrl('y'));
    assert_eq!(
        app.sessions.composer.as_ref().unwrap().editor.text(),
        "hello world"
    );
}

#[test]
fn a_notice_replaces_the_status_line_and_expires() {
    let mut app = shell(full_hello());
    app.inform("something happened", NoticeKind::Warn);

    assert!(render(&mut app, 120, 20).contains("something happened"));

    for _ in 0..80 {
        app.apply(Msg::Tick);
    }

    let screen = render(&mut app, 120, 20);
    assert!(!screen.contains("something happened"), "{}", screen.text());
    assert!(
        screen.contains("ctrl+p commands"),
        "the shell footer comes back"
    );
}

#[test]
fn attached_runtime_footer_preserves_the_complete_endpoint_at_standard_width() {
    for address in ["127.0.0.1:54272", "127.0.0.1:54274"] {
        let mut app = App::new(Mode::Attached, address.into(), full_hello(), None);
        resolve_account(&mut app);

        let screen = render(&mut app, 120, 30);
        let footer = screen.row("● LIVE");

        assert!(
            footer.contains(address),
            "the footer clipped {address:?}:\n{}",
            screen.text()
        );
        assert!(
            footer.contains("ctrl+p commands"),
            "making room for the endpoint must not discard the primary shortcut:\n{}",
            screen.text()
        );
    }
}

#[test]
fn the_visible_tab_is_the_only_one_polled() {
    let mut app = shell(full_hello());
    app.apply(Msg::Tick);

    let methods: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();

    assert!(methods.contains(&"interactive.list".to_string()));
    assert!(methods.contains(&"coding.list".to_string()));
    assert!(!methods.contains(&"runtime.status".to_string()));

    app.apply(key(KeyCode::Char('1')));

    let methods: Vec<String> = app.drain().into_iter().map(|call| call.method).collect();
    assert!(methods.contains(&"runtime.status".to_string()));
    assert!(methods.contains(&"runtime.providers".to_string()));
}

#[test]
fn a_transcript_is_never_polled() {
    let mut app = with_open_session();
    notify(&mut app, event(1, "output_text_final", "hello"));
    let _ = app.drain();

    // A long run of ticks on the Sessions tab.
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
    let mut app = shell(full_hello());

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
    let mut app = shell(full_hello());

    assert_eq!(app.tab, Tab::Sessions);

    app.apply(Msg::Key(KeyEvent {
        code: KeyCode::BackTab,
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::NONE,
    }));

    assert_eq!(app.tab, Tab::Dashboard);

    app.apply(key(KeyCode::Tab));
    assert_eq!(app.tab, Tab::Sessions);
}
