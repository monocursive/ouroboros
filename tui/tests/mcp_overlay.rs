//! D4. `/mcp` — what the overlay reads, what it asks for, and what it refuses to draw.
//!
//! The fixture is `test/support/gateway_golden/mcp_list_result.json`, the same bytes the
//! Elixir side is pinned to, so a rendering that passes here is a rendering of an answer
//! this runtime actually sends.
//!
//! Two properties are the point:
//!
//! * **the three server states are told apart** — `ready` is running, `broken` carries the
//!   runtime's own reason, and `configured` was declared and never started, which is not a
//!   failure and must not read as one;
//! * **refusals are a section, not a footnote** — an entry the loader read and rejected is
//!   the only thing that distinguishes "my `mcp.json` was ignored" from "my `mcp.json` was
//!   read and found wanting".

mod support;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{json, Value};

use ouro::model::Plane;
use ouro::ui::app::{App, Msg, Tag};

use support::{fixture, full_hello, render};

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

/// A session open on a named node, in a named workspace — both of which `/mcp` sends.
fn opened(hello: ouro::proto::Hello) -> App {
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
        json!([{
            "_struct": "Ouroboros.Interactive.State",
            "id": SESSION,
            "node": "ouroboros@golden",
            "provider": "native",
            "workspace": "/srv/repo",
            "status": "running",
            "options": {"approval_mode": "prompt"},
            "created_at": "2026-01-01T00:00:00.000000Z",
            "updated_at": "2026-01-01T00:00:00.000000Z"
        }]),
    );
    answer(&mut app, Tag::Sessions(Plane::Coding), json!([]));

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

    app
}

fn compose(app: &mut App, text: &str) {
    for character in text.chars() {
        app.apply(key(KeyCode::Char(character)));
    }
    app.apply(key(KeyCode::Enter));
}

/// Opens `/mcp` and answers it with the golden fixture.
fn open_mcp(app: &mut App) -> Value {
    compose(app, "/mcp");

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "mcp.list")
        .expect("an mcp.list call");

    let params = call.params.clone();

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(fixture("mcp_list_result")["result"].clone()),
    });

    params
}

/// `/mcp` asks the node the *session* runs on, about the workspace it runs in.
///
/// A server runs where its session runs — `mcp.list` is a bounded `:erpc` for exactly that
/// reason — and without the workspace the answer would be only what is already running.
#[test]
fn mcp_asks_the_sessions_own_node_about_its_own_workspace() {
    let mut app = opened(full_hello());
    let params = open_mcp(&mut app);

    assert_eq!(
        params,
        json!({"node": "ouroboros@golden", "workspace": "/srv/repo"}),
    );
}

/// The three states, the reasons, and the refusal — at two widths.
#[test]
fn the_mcp_overlay_states_every_server_and_every_refusal() {
    for width in [80u16, 120] {
        let mut app = opened(full_hello());
        open_mcp(&mut app);

        let text = render(&mut app, width, 44).text();

        assert!(text.contains("mcp servers"), "{width}\n{text}");
        assert!(text.contains("ouroboros@golden"), "{width}\n{text}");

        // The three states, told apart.
        assert!(text.contains("fake"), "{width}\n{text}");
        assert!(text.contains("ready"), "{width}\n{text}");
        assert!(text.contains("flaky"), "{width}\n{text}");
        assert!(text.contains("broken"), "{width}\n{text}");
        assert!(text.contains("notes"), "{width}\n{text}");
        assert!(text.contains("configured"), "{width}\n{text}");

        // A broken server says why, in the runtime's own words.
        assert!(text.contains("restart_limit"), "{width}\n{text}");

        // The refusal section, with its typed reason.
        assert!(text.contains("REFUSED"), "{width}\n{text}");
        assert!(text.contains("remote"), "{width}\n{text}");
        assert!(text.contains("unsupported_transport"), "{width}\n{text}");

        // The environment is a count. There is no other form of it anywhere on screen.
        assert!(text.contains("env var"), "{width}\n{text}");
    }
}

/// The selected server shows the tool names a model would actually see.
#[test]
fn the_selected_server_shows_its_tool_names() {
    let mut app = opened(full_hello());
    open_mcp(&mut app);

    let text = render(&mut app, 120, 44).text();

    assert!(
        text.contains("mcp__fake__echo"),
        "the first row is selected and names its tools\n{text}"
    );
}

/// `r` re-reads: a server's state is exactly the thing that changes while it is on screen.
#[test]
fn r_re_reads_the_listing() {
    let mut app = opened(full_hello());
    open_mcp(&mut app);

    app.apply(key(KeyCode::Char('r')));

    assert!(
        app.drain().iter().any(|call| call.method == "mcp.list"),
        "r asks again rather than redrawing what it already had"
    );
}

/// A gateway that does not serve `mcp.list` is told so here, not by a refused round trip.
#[test]
fn mcp_is_refused_locally_where_the_gateway_does_not_serve_it() {
    let mut hello = full_hello();
    hello.methods.retain(|method| method != "mcp.list");

    let mut app = opened(hello);
    compose(&mut app, "/mcp");

    assert!(
        !app.drain().iter().any(|call| call.method == "mcp.list"),
        "an unserved method is not called"
    );

    let text = render(&mut app, 120, 44).text();
    assert!(text.contains("does not serve"), "{text}");
}

/// A node that runs no MCP says so as a posture, not as an error.
#[test]
fn a_node_with_mcp_off_says_so_rather_than_looking_broken() {
    let mut app = opened(full_hello());
    compose(&mut app, "/mcp");

    let call = app
        .drain()
        .into_iter()
        .find(|call| call.method == "mcp.list")
        .expect("an mcp.list call");

    app.apply(Msg::Answer {
        tag: call.tag,
        result: Ok(json!({
            "enabled": false,
            "node": "ouroboros@quiet",
            "servers": [],
            "refusals": [],
            "supervised": false,
            "transports": ["stdio"],
        })),
    });

    let text = render(&mut app, 120, 44).text();

    assert!(text.contains("MCP is off on this node"), "{text}");
    assert!(
        !text.to_lowercase().contains("error"),
        "a posture is not a failure\n{text}"
    );
}
