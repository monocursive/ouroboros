//! `--continue` against a scripted gateway (F2).
//!
//! The resolution *rule* is unit-tested in `ouro::continuation`; what is exercised here is
//! the half that needs a socket: which method is called, what a gateway that cannot answer
//! it produces, and — the property the whole slice turns on — that a `--continue` which
//! finds nothing makes exactly one call and mutates nothing.
//!
//! The rows are the shape `Interactive.State.public/1` answers, with two machines in the
//! fixture because "on any machine" is the claim `--continue` makes and a single-node
//! fixture would never test it.

mod support;

use std::time::Duration;

use serde_json::{json, Value};

use ouro::continuation::{self, Continued, Workspace};
use ouro::transport::{self, NoReconnectHook, ReconnectHook};

use support::{config, listener, Peer, PATIENCE};

use std::sync::Arc;

const WORKSPACE: &str = "/w/project";

fn hook() -> Arc<dyn ReconnectHook> {
    Arc::new(NoReconnectHook)
}

fn here() -> Workspace {
    Workspace::from_parts(WORKSPACE, None)
}

/// One `interactive.list` row.
fn row(id: &str, node: &str, workspace: &str, status: &str, updated: &str) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.State",
        "id": id,
        "node": node,
        "provider": "native",
        "status": status,
        "workspace": workspace,
        "title": null,
        "cursor": 12,
        "created_at": "2026-01-01T00:00:00.000000Z",
        "updated_at": updated,
        "options": {"approval_mode": "prompt", "sandbox_mode": "workspace_write"},
    })
}

/// The two-machine answer every test here starts from: the same workspace on two nodes,
/// one ended session on it, and one session belonging to a different directory.
fn fleet_rows() -> Value {
    json!([
        row(
            "on-alpha",
            "ouroboros@alpha",
            WORKSPACE,
            "idle",
            "2026-02-01T10:00:00.000000Z"
        ),
        row(
            "on-beta",
            "ouroboros@beta",
            WORKSPACE,
            "idle",
            "2026-02-01T12:00:00.000000Z"
        ),
        row(
            "ended-on-beta",
            "ouroboros@beta",
            WORKSPACE,
            "closed",
            "2026-02-01T23:59:00.000000Z"
        ),
        row(
            "another-project",
            "ouroboros@alpha",
            "/w/other",
            "idle",
            "2026-02-02T09:00:00.000000Z"
        ),
    ])
}

struct Asked {
    outcome: Result<Continued, String>,
    /// Every method the client called after the handshake, in order.
    methods: Vec<String>,
}

/// Resolves `--continue` against a gateway that serves `methods` and answers
/// `interactive.list` with `rows`, recording what was called.
async fn ask(serves: &'static [&'static str], rows: Option<Value>) -> Asked {
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&server).await;
        peer.hello(serves).await;

        let mut methods = Vec::new();

        while let Some(request) = peer.request().await {
            let method = request["method"].as_str().unwrap_or_default().to_string();
            methods.push(method.clone());

            match (method.as_str(), &rows) {
                ("interactive.list", Some(rows)) => {
                    peer.result(&request["id"], rows.clone()).await;
                }
                ("interactive.list", None) => {
                    peer.error(&request["id"], -32004, "the plane is unavailable", None)
                        .await;
                }
                _other => {
                    peer.error(&request["id"], -32601, "no such method", None)
                        .await;
                }
            }
        }

        methods
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        continuation::target(&connected.client, &connected.hello, &here()),
    )
    .await
    .expect("the resolution finished inside the test's patience");

    connected.client.stop().await;

    let methods = tokio::time::timeout(PATIENCE, script)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();

    Asked { outcome, methods }
}

#[tokio::test]
async fn the_newest_live_session_for_this_workspace_wins_across_two_machines() {
    let asked = ask(&["hello", "interactive.list"], Some(fleet_rows())).await;

    let Ok(Continued::Session(session)) = asked.outcome else {
        panic!("a workspace with two live sessions must resolve to one");
    };

    assert_eq!(session.id, "on-beta");
    assert_eq!(session.node.as_deref(), Some("ouroboros@beta"));
    assert_eq!(
        session.updated_at.as_deref(),
        Some("2026-02-01T12:00:00.000000Z")
    );

    let described = session.describe();
    assert!(described.contains("continuing on-beta"), "{described}");
    assert!(
        described.contains("ouroboros@beta"),
        "the machine is part of the claim: {described}"
    );

    assert_eq!(
        asked.methods,
        vec!["interactive.list"],
        "resolving a session is one read and nothing else"
    );
}

/// The property the flag turns on: nothing to continue must leave the fleet as it was.
#[tokio::test]
async fn nothing_to_continue_makes_one_read_and_starts_no_session() {
    let asked = ask(
        &["hello", "interactive.list", "interactive.start"],
        Some(json!([row(
            "another-project",
            "ouroboros@alpha",
            "/w/other",
            "idle",
            "2026-02-02T09:00:00.000000Z"
        )])),
    )
    .await;

    let Ok(Continued::Nothing(reason)) = asked.outcome else {
        panic!("a workspace with no sessions must resolve to nothing");
    };

    assert!(reason.contains(WORKSPACE), "{reason}");
    assert!(reason.contains("--or-new"), "{reason}");

    assert_eq!(
        asked.methods,
        vec!["interactive.list"],
        "a --continue that found nothing must not have started anything"
    );
    assert!(
        !asked
            .methods
            .iter()
            .any(|method| method == "interactive.start"),
        "interactive.start was called by a command that resolved to nothing"
    );
}

/// Terminal rows are skipped rather than opened and then rejected by `interactive.info`.
#[tokio::test]
async fn a_workspace_whose_only_sessions_have_ended_says_so_rather_than_opening_one() {
    let asked = ask(
        &["hello", "interactive.list", "interactive.start"],
        Some(json!([
            row(
                "ended",
                "ouroboros@alpha",
                WORKSPACE,
                "closed",
                "2026-02-02T09:00:00.000000Z"
            ),
            row(
                "cancelled",
                "ouroboros@beta",
                WORKSPACE,
                "cancelled",
                "2026-02-02T10:00:00.000000Z"
            ),
        ])),
    )
    .await;

    let Ok(Continued::Nothing(reason)) = asked.outcome else {
        panic!("two ended sessions are not something to continue");
    };

    assert!(reason.contains("have ended"), "{reason}");
    assert_eq!(asked.methods, vec!["interactive.list"]);
}

/// "We could not look" and "there was nothing there" are different answers, and only the
/// second one is allowed to become `--or-new`'s new session.
#[tokio::test]
async fn a_gateway_that_does_not_serve_the_list_is_a_failure_not_an_empty_answer() {
    let asked = ask(&["hello", "interactive.start"], Some(fleet_rows())).await;

    let Err(failure) = asked.outcome else {
        panic!("a gateway without interactive.list cannot answer --continue");
    };

    assert!(failure.contains("interactive.list"), "{failure}");
    assert!(failure.contains("--resume"), "{failure}");
    assert!(
        asked.methods.is_empty(),
        "a method the handshake did not advertise is never called: {:?}",
        asked.methods
    );
}

#[tokio::test]
async fn a_refused_list_is_a_failure_not_an_empty_answer() {
    let asked = ask(&["hello", "interactive.list"], None).await;

    let Err(failure) = asked.outcome else {
        panic!("a refused list is not evidence that there was nothing to continue");
    };

    assert!(
        failure.contains("interactive.list was refused"),
        "{failure}"
    );
    assert!(failure.contains(WORKSPACE), "{failure}");
}
