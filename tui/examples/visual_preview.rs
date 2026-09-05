//! Render the real TUI without a runtime or account. Usage:
//! cargo run --example visual_preview -- /tmp/ouro-preview
#[path = "../tests/support/mod.rs"]
mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ouro::model::Plane;
use ouro::ui::app::{Msg, Tag};
use ratatui::{backend::TestBackend, Terminal};
use serde_json::json;

fn main() {
    let directory = std::env::args().nth(1).expect("output directory");
    std::fs::create_dir_all(&directory).unwrap();
    for (name, width, height, connected) in [
        ("welcome", 120, 34, false),
        ("ready", 120, 34, true),
        ("compact", 80, 24, false),
        ("small", 60, 18, true),
        ("chat", 140, 40, true),
        ("sign-in", 80, 24, false),
        ("sign-in-small", 60, 18, false),
        ("expired", 80, 24, false),
        ("start-error", 80, 24, true),
    ] {
        let mut app = support::app(support::full_hello());
        app.launch_dir = Some("/work/ouroboros".into());
        app.open_home();
        app.apply(Msg::Answer {
            tag: Tag::Account,
            result: Ok(json!({
                "account": if connected { json!({"type":"chatgpt", "planType":"pro"}) } else { json!(null) },
                "requiresOpenaiAuth": true,
                "login": {"status":"idle"}
            })),
        });
        if name == "chat" {
            app.apply(Msg::Answer {
                tag: Tag::Sessions(Plane::Interactive),
                result: Ok(json!([{
                    "id":"preview-session", "provider":"native", "workspace":"/work/ouroboros",
                    "status":"idle", "objective":"Polish the first-run experience",
                    "options":{"model":"openai_codex:gpt-5.6-sol", "approval_mode":"ask", "sandbox_mode":"workspace_write"}
                }])),
            });
            app.open_session(Plane::Interactive, "preview-session".into());
            if let Some(call) = app
                .drain()
                .into_iter()
                .find(|call| call.method == "interactive.subscribe")
            {
                app.apply(Msg::Answer {
                    tag: call.tag,
                    result: Ok(json!([])),
                });
            }
            for (sequence, kind, payload) in [
                (
                    1,
                    "input_accepted",
                    json!({"text":"Make the first-run experience feel effortless."}),
                ),
                (
                    2,
                    "output_text_final",
                    json!({"text":"## A clearer place to start\n\nThe task composer is now the focus. Describe what you want to build, connect your account, and start working.\n\n- Your draft stays with you through sign-in.\n- File access stays visible before you begin.\n- Advanced setup is one command away."}),
                ),
                (
                    3,
                    "tool_call",
                    json!({"call_id":"check", "name":"exec_command", "input":{"cmd":"cargo test --test onboarding"}}),
                ),
                (
                    4,
                    "tool_result",
                    json!({"call_id":"check", "output":"30 passed; 0 failed", "is_error":false}),
                ),
            ] {
                app.apply(Msg::Notification(ouro::proto::Notification {
                    method: "interactive.event".into(),
                    params: json!({"id":"preview-session", "event":{
                        "id":format!("event-{sequence}"), "session_id":"preview-session", "sequence":sequence,
                        "type":kind, "timestamp":"2026-09-05T12:00:00.000000Z", "payload":payload
                    }}),
                }));
            }
        } else if matches!(name, "sign-in" | "sign-in-small" | "expired") {
            app.apply(Msg::Paste("Build a small command-line tool".into()));
            app.apply(Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
            app.apply(Msg::Answer {
                tag: Tag::AccountLogin,
                result: Ok(json!({"loginId":"preview-login", "authUrl":"https://auth.openai.com/codex/device", "userCode":"ABCD-EFGH"})),
            });
            if name == "expired" {
                app.apply(Msg::Answer {
                    tag: Tag::Account,
                    result: Ok(json!({"requiresOpenaiAuth":true, "login":{"status":"expired", "loginId":"preview-login", "error":"Your sign-in code expired. Get a new code to continue."}})),
                });
            }
        } else if name == "start-error" {
            app.apply(Msg::Paste("Build a small command-line tool".into()));
            app.apply(Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
            let start = app
                .drain()
                .into_iter()
                .find(|call| call.method == "interactive.start")
                .unwrap();
            app.apply(Msg::Answer {
                tag: start.tag,
                result: Err(ouro::transport::ClientError::Timeout),
            });
        }
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| ouro::ui::view::draw(frame, &mut app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let rows: Vec<Vec<_>> = (0..height).map(|y| (0..width).map(|x| {
            let cell = &buffer[(x, y)];
            json!({"text":cell.symbol(), "fg":format!("{:?}",cell.fg), "bg":format!("{:?}",cell.bg), "bold":cell.modifier.contains(ratatui::style::Modifier::BOLD), "reversed":cell.modifier.contains(ratatui::style::Modifier::REVERSED)})
        }).collect()).collect();
        std::fs::write(
            format!("{directory}/{name}.json"),
            serde_json::to_vec(&rows).unwrap(),
        )
        .unwrap();
    }
}
