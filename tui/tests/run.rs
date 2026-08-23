//! `ouro run` driven against a scripted gateway.
//!
//! The driver is the whole slice: what lands on stdout, what never does, which verb a
//! resumed session gets, what a headless approval is answered with, and — the property
//! the honesty invariant turns on — that a turn whose end was never observed reports
//! `lost` rather than `completed`.
//!
//! The scripted peer is `support::Peer`, the same one the transport and UI tests use, so
//! these run over the real line protocol, the real correlation, and the real notification
//! channel. Only the Elixir side is stood in for, and the shapes it would have sent are
//! taken from the golden fixtures where one exists.

mod support;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use ouro::model::{Plane, StartRequest};
use ouro::proto::{ErrorCode, RpcError};
use ouro::run::{self, Options, Output, Plan, Report, Sinks, Status};
use ouro::transport::{self, NoReconnectHook, ReconnectHook};

use support::{config, listener, Peer, PATIENCE};

/// Everything `ouro run` feature-gates on, so a test that fails does so for its own
/// reason rather than for a missing method name.
const SERVES: &[&str] = &[
    "hello",
    "interactive.start",
    "interactive.info",
    "interactive.subscribe",
    "interactive.replay",
    "interactive.send_message",
    "interactive.follow_up",
    "interactive.respond_approval",
    "interactive.interrupt",
];

const SESSION: &str = "s-run-1";
const TURN: &str = "ouro-run:s-run-1";

fn hook() -> Arc<dyn ReconnectHook> {
    Arc::new(NoReconnectHook)
}

/// One event, in the envelope `interactive.event` frames — the golden fixture's shape,
/// with the fields a run reads.
fn event(sequence: u64, kind: &str, turn: Option<&str>, payload: Value) -> Value {
    let mut event = json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence:024}"),
        "session_id": SESSION,
        "sequence": sequence,
        "type": kind,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "provider": "codex",
        "payload": payload,
    });

    if let Some(turn) = turn {
        event["turn_id"] = Value::String(turn.to_string());
    }

    event
}

fn text_event(sequence: u64, kind: &str, text: &str) -> Value {
    event(sequence, kind, Some(TURN), json!({ "text": text }))
}

fn start_plan(prompt: &str) -> Plan {
    let request = StartRequest {
        id: SESSION.to_string(),
        plane: Plane::Interactive,
        provider: "codex".into(),
        machine: String::new(),
        workspace: "/w".into(),
        approval_mode: None,
        sandbox_mode: None,
        objective: String::new(),
        worktree: false,
    };

    let params = request.params().expect("a validated start request");

    Plan::Start {
        request,
        params,
        prompt: prompt.to_string(),
    }
}

fn options(output: Output) -> Options {
    Options {
        output,
        approve_all: false,
        timeout: Duration::from_secs(20),
        verbose: false,
    }
}

struct Ran {
    report: Result<Report, run::Refusal>,
    out: String,
    err: String,
}

impl Ran {
    fn report(&self) -> &Report {
        self.report
            .as_ref()
            .unwrap_or_else(|refusal| panic!("expected a report, got a refusal: {refusal}"))
    }

    fn refusal(&self) -> String {
        match &self.report {
            Ok(report) => panic!("expected a refusal, got {:?}", report.status),
            Err(refusal) => refusal.to_string(),
        }
    }

    /// stdout, as the lines a caller's `while read line` would see.
    fn lines(&self) -> Vec<&str> {
        self.out.lines().collect()
    }

    /// Every stdout line parsed as JSON, panicking with the offending line rather than
    /// with a serde message that does not say which one.
    fn objects(&self) -> Vec<Value> {
        self.lines()
            .into_iter()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line}"))
            })
            .collect()
    }
}

/// Runs the driver against a script, with stdout and stderr captured apart.
///
/// The script accepts the connection and answers the handshake, so it has to be running
/// before the client asks for one — hence the accept and the script body in the same
/// task, started before `connect`.
async fn run_against<F>(plan: Plan, options: Options, script: F) -> Ran
where
    F: FnOnce(Peer) -> tokio::task::JoinHandle<()> + Send + 'static,
{
    let (server, address) = listener().await;

    let script = tokio::spawn(async move {
        let peer = Peer::accept(&server).await;
        let _ = script(peer).await;
    });

    let connected = transport::connect(config(address), hook())
        .await
        .expect("a handshake");

    let mut notifications = connected.notifications;
    let mut out = Vec::new();
    let mut err = Vec::new();

    let report = {
        let mut sinks = Sinks {
            out: &mut out,
            err: &mut err,
        };

        tokio::time::timeout(
            Duration::from_secs(20),
            run::drive(
                &connected.client,
                &mut notifications,
                &connected.hello,
                plan,
                &options,
                &mut sinks,
            ),
        )
        .await
        .expect("the run finished inside the test's patience")
    };

    connected.client.stop().await;
    let _ = tokio::time::timeout(PATIENCE, script).await;

    Ran {
        report,
        out: String::from_utf8(out).expect("stdout is UTF-8"),
        err: String::from_utf8(err).expect("stderr is UTF-8"),
    }
}

/// The handshake plus the two calls every start does, answered as the gateway answers
/// them. Leaves the peer ready to notify events.
async fn accept_start(peer: &mut Peer, backlog: Value) {
    peer.hello(SERVES).await;

    let start = peer.request_for("interactive.start").await;
    assert_eq!(start["params"]["id"], SESSION);
    assert_eq!(start["params"]["provider"], "codex");
    peer.result(
        &start["id"],
        json!({ "id": SESSION, "outcome": "created", "ready": true }),
    )
    .await;

    let subscribe = peer.request_for("interactive.subscribe").await;
    assert_eq!(subscribe["params"]["cursor"], 0);
    peer.result(&subscribe["id"], backlog).await;

    let send = peer.request_for("interactive.send_message").await;
    assert_eq!(send["params"]["turn_id"], TURN);
    assert_eq!(send["params"]["input"], "do the thing");
    peer.result(&send["id"], json!({ "id": TURN, "status": "running" }))
        .await;
}

// ----- the two identifiers one turn has -------------------------------------------------

/// The caller mints the durable `turn_id`; the Harness mints the id its own events carry
/// and returns it as `harness_turn_id`. A live runtime showed what matching only on the
/// first one costs: this run's own `turn_completed` went past unrecognised and the command
/// reported a timeout on a turn that had finished.
#[tokio::test]
async fn events_keyed_by_the_harness_turn_id_still_settle_this_runs_turn() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                peer.hello(SERVES).await;

                let start = peer.request_for("interactive.start").await;
                peer.result(
                    &start["id"],
                    json!({ "id": SESSION, "outcome": "created", "ready": true }),
                )
                .await;

                let subscribe = peer.request_for("interactive.subscribe").await;
                peer.result(&subscribe["id"], json!([])).await;

                let send = peer.request_for("interactive.send_message").await;
                assert_eq!(send["params"]["turn_id"], TURN);
                peer.result(
                    &send["id"],
                    json!({
                        "id": TURN,
                        "status": "running",
                        "harness_turn_id": "turn_mO5v_f3_PnKJX6x0io71DQW1",
                    }),
                )
                .await;

                // Exactly what a real session emits: the provider's id, never the
                // caller's.
                for frame in [
                    event(
                        1,
                        "output_text_final",
                        Some("turn_mO5v_f3_PnKJX6x0io71DQW1"),
                        json!({ "text": "hello from ouro run" }),
                    ),
                    event(
                        2,
                        "turn_completed",
                        Some("turn_mO5v_f3_PnKJX6x0io71DQW1"),
                        json!({}),
                    ),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Completed);
    assert_eq!(report.exit().code(), 0);
    assert_eq!(report.text, "hello from ouro run");
    // The reported id stays the durable one: it is what a caller reconciles with.
    assert_eq!(report.turn_id, TURN);
}

/// The tolerance is a fallback, not the rule. Once the reply named a harness turn, another
/// turn's terminal event is somebody else's news.
#[tokio::test]
async fn a_known_harness_turn_makes_another_turns_completion_somebody_elses() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                peer.hello(SERVES).await;

                let start = peer.request_for("interactive.start").await;
                peer.result(
                    &start["id"],
                    json!({ "id": SESSION, "outcome": "created", "ready": true }),
                )
                .await;

                let subscribe = peer.request_for("interactive.subscribe").await;
                peer.result(&subscribe["id"], json!([])).await;

                let send = peer.request_for("interactive.send_message").await;
                peer.result(
                    &send["id"],
                    json!({ "id": TURN, "status": "running", "harness_turn_id": "h-ours" }),
                )
                .await;

                peer.notify(
                    "interactive.event",
                    json!({
                        "id": SESSION,
                        "event": event(1, "turn_completed", Some("h-theirs"), json!({})),
                    }),
                )
                .await;

                peer.notify(
                    "stream.ended",
                    json!({ "id": SESSION, "plane": "interactive", "status": "closed" }),
                )
                .await;
            })
        },
    )
    .await;

    assert_eq!(
        ran.report().status,
        Status::Lost,
        "another turn's completion is not this one's"
    );
}

// ----- output surfaces ----------------------------------------------------------------

#[tokio::test]
async fn stream_json_prints_the_wire_events_unchanged_and_then_the_result() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::StreamJson),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                for frame in [
                    text_event(1, "output_text_delta", "half "),
                    text_event(2, "output_text_final", "half a sentence"),
                    event(
                        3,
                        "usage",
                        Some(TURN),
                        json!({ "input_tokens": 11, "output_tokens": 4 }),
                    ),
                    event(
                        4,
                        "file_change",
                        Some(TURN),
                        json!({ "changes": [{ "path": "lib/a.ex" }] }),
                    ),
                    event(5, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Completed);
    assert_eq!(report.exit().code(), 0);

    let objects = ran.objects();
    assert_eq!(
        objects.len(),
        6,
        "five events then one result: {:#?}",
        objects
    );

    // Byte-for-byte the gateway's own object. Not a shape this client invented, and not a
    // subset of one: the golden fixture is the contract and this is it.
    assert_eq!(objects[0], text_event(1, "output_text_delta", "half "));
    assert_eq!(
        objects[4],
        event(5, "turn_completed", Some(TURN), json!({}))
    );
    assert_eq!(objects[0]["_struct"], "Ouroboros.Interactive.Event");

    let result = &objects[5];
    assert_eq!(result["type"], "result");
    assert_eq!(result["session_id"], SESSION);
    assert_eq!(result["turn_id"], TURN);
    assert_eq!(result["status"], "completed");
    assert_eq!(result["provider"], "codex");
    assert_eq!(result["usage"]["input_tokens"], 11);
    assert_eq!(result["usage"]["total_tokens"], 15);
    assert_eq!(result["files_changed"], json!(["lib/a.ex"]));
    assert_eq!(
        result["approvals"],
        json!({ "requested": 0, "answered": 0 })
    );
    assert!(result["duration_ms"].is_number());
    assert!(
        result.get("error").is_none(),
        "a completed run has nothing to explain: {result}"
    );
}

#[tokio::test]
async fn json_prints_the_result_object_and_nothing_before_it() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                for frame in [
                    text_event(1, "output_text_final", "done"),
                    event(2, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    assert_eq!(ran.report().status, Status::Completed);

    let objects = ran.objects();
    assert_eq!(objects.len(), 1, "only the result: {:#?}", objects);
    assert_eq!(objects[0]["type"], "result");
    assert_eq!(objects[0]["status"], "completed");
}

#[tokio::test]
async fn plain_output_is_the_agents_words_and_nothing_else() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Text),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                for frame in [
                    // Deltas collapse into the message; the final replaces the draft, exactly
                    // as the transcript projects them.
                    text_event(1, "output_text_delta", "par"),
                    text_event(2, "output_text_delta", "tial"),
                    text_event(3, "output_text_final", "the whole answer"),
                    event(4, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    assert_eq!(ran.report().status, Status::Completed);
    assert_eq!(ran.out, "the whole answer\n");
    assert!(
        !ran.out.contains('{'),
        "plain mode prints prose, not JSON: {}",
        ran.out
    );
}

#[tokio::test]
async fn plain_output_falls_back_to_the_collapsed_deltas_when_no_final_arrives() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Text),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                for frame in [
                    text_event(1, "output_text_delta", "only "),
                    text_event(2, "output_text_delta", "deltas"),
                    event(3, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    assert_eq!(ran.out, "only deltas\n");
}

// ----- approvals ------------------------------------------------------------------------

#[tokio::test]
async fn an_approval_is_denied_once_with_a_reason_that_says_why() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::StreamJson),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                let mut approval = event(
                    1,
                    "approval_requested",
                    Some(TURN),
                    json!({ "tool_call": { "name": "exec_command", "command": "rm -rf /" } }),
                );
                approval["request_id"] = Value::String("req-9".into());

                peer.notify(
                    "interactive.event",
                    json!({ "id": SESSION, "event": approval }),
                )
                .await;

                let answer = peer.request_for("interactive.respond_approval").await;
                assert_eq!(answer["params"]["id"], SESSION);
                assert_eq!(answer["params"]["request_id"], "req-9");
                assert_eq!(answer["params"]["response"]["decision"], "deny");
                assert_eq!(answer["params"]["response"]["scope"], "once");
                assert_eq!(
                    answer["params"]["response"]["reason"],
                    "ouro run: headless, no approver"
                );
                peer.result(&answer["id"], json!({})).await;

                for frame in [
                    event(
                        2,
                        "approval_resolved",
                        Some(TURN),
                        json!({ "decision": "deny" }),
                    ),
                    event(3, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.approvals_requested, 1);
    assert_eq!(report.approvals_answered, 1);

    let objects = ran.objects();
    // The request is on the stream like every other event: a caller reading the NDJSON
    // must be able to see what was asked and what this command did about it.
    assert_eq!(objects[0]["type"], "approval_requested");
    assert_eq!(
        objects.last().expect("a result")["approvals"],
        json!({ "requested": 1, "answered": 1 })
    );
    assert!(
        ran.err.contains("headless"),
        "the decision this command made for the operator is said out loud: {}",
        ran.err
    );
}

#[tokio::test]
async fn approve_all_answers_approve_once_instead() {
    let mut options = options(Output::Json);
    options.approve_all = true;

    let ran = run_against(start_plan("do the thing"), options, |mut peer| {
        tokio::spawn(async move {
            accept_start(&mut peer, json!([])).await;

            let mut approval = event(1, "approval_requested", Some(TURN), json!({}));
            approval["request_id"] = Value::String("req-1".into());

            peer.notify("interactive.event", json!({ "id": SESSION, "event": approval }))
                .await;

            let answer = peer.request_for("interactive.respond_approval").await;
            assert_eq!(answer["params"]["response"]["decision"], "approve");
            assert_eq!(answer["params"]["response"]["scope"], "once");
            assert!(
                answer["params"]["response"].get("reason").is_none(),
                "an approval nobody objected to needs no reason: {}",
                answer["params"]["response"]
            );
            peer.result(&answer["id"], json!({})).await;

            peer.notify(
                "interactive.event",
                json!({ "id": SESSION, "event": event(2, "turn_completed", Some(TURN), json!({})) }),
            )
            .await;
        })
    })
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Completed);
    assert_eq!(report.approvals_requested, 1);
    assert_eq!(report.approvals_answered, 1);
}

// ----- the endings ------------------------------------------------------------------------

#[tokio::test]
async fn a_turn_past_its_timeout_is_interrupted_and_reported_as_a_timeout() {
    let mut options = options(Output::Json);
    options.timeout = Duration::from_millis(150);

    let ran = run_against(start_plan("do the thing"), options, |mut peer| {
        tokio::spawn(async move {
            accept_start(&mut peer, json!([])).await;

            // Nothing else is ever sent: this is the turn that does not end.
            let interrupt = peer.request_for("interactive.interrupt").await;
            assert_eq!(interrupt["params"]["id"], SESSION);
            peer.result(&interrupt["id"], json!({})).await;

            peer.notify(
                "interactive.event",
                json!({
                    "id": SESSION,
                    "event": event(1, "turn_interrupted", Some(TURN), json!({})),
                }),
            )
            .await;
        })
    })
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Timeout);
    assert_eq!(report.exit().code(), 4);

    let result = ran.objects().pop().expect("a result");
    assert_eq!(result["status"], "timeout");
    assert!(
        result["error"]
            .as_str()
            .expect("a timeout says what it was")
            .contains("ceiling"),
        "{result}"
    );
}

#[tokio::test]
async fn a_connection_that_closes_before_the_turn_ends_is_lost_and_never_completed() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                peer.notify(
                    "interactive.event",
                    json!({
                        "id": SESSION,
                        "event": text_event(1, "output_text_delta", "half an ans"),
                    }),
                )
                .await;

                // The runtime goes away mid-turn. Whatever it is doing now, this process
                // cannot see it.
                drop(peer);
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Lost);
    assert_eq!(report.exit().code(), 3);
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("closed"),
        "{:?}",
        report.error
    );
}

#[tokio::test]
async fn a_session_that_ends_before_its_turn_does_is_lost() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                peer.notify(
                    "stream.ended",
                    json!({ "id": SESSION, "plane": "interactive", "status": "closed" }),
                )
                .await;
            })
        },
    )
    .await;

    assert_eq!(ran.report().status, Status::Lost);
    assert_eq!(ran.report().exit().code(), 3);
}

#[tokio::test]
async fn a_failed_turn_keeps_the_runtimes_own_sentence_and_exits_one() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                peer.notify(
                    "interactive.event",
                    json!({
                        "id": SESSION,
                        "event": event(
                            1,
                            "turn_failed",
                            Some(TURN),
                            json!({ "error": "the provider exited 1" }),
                        ),
                    }),
                )
                .await;
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Failed);
    assert_eq!(report.exit().code(), 1);
    assert_eq!(report.error.as_deref(), Some("the provider exited 1"));
}

/// The honesty invariant, as a test: a send this client could not reconcile is never
/// rounded up to a success, even though the RPC envelope for the retry came back fine.
#[tokio::test]
async fn a_send_whose_outcome_stayed_unknown_is_lost_rather_than_completed() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                peer.hello(SERVES).await;

                let start = peer.request_for("interactive.start").await;
                peer.result(
                    &start["id"],
                    json!({ "id": SESSION, "outcome": "created", "ready": true }),
                )
                .await;

                let subscribe = peer.request_for("interactive.subscribe").await;
                peer.result(&subscribe["id"], json!([])).await;

                // Both the send and its same-id retry answer with a durable turn that is
                // still dispatching: nothing here proves the prompt reached the provider.
                for _attempt in 0..2 {
                    let send = peer.request_for("interactive.send_message").await;
                    assert_eq!(send["params"]["turn_id"], TURN);
                    peer.result(&send["id"], json!({ "id": TURN, "status": "dispatching" }))
                        .await;
                }

                // And then the session says nothing more.
                peer.notify(
                    "stream.ended",
                    json!({ "id": SESSION, "plane": "interactive", "status": "unknown" }),
                )
                .await;
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Lost);
    assert_eq!(report.exit().code(), 3);
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("outcome remains unknown"),
        "{:?}",
        report.error
    );
}

/// When this command is itself the reason the run stopped, that is what the status says —
/// and the unreconciled send is still told, because it is the more actionable half.
#[tokio::test]
async fn a_timeout_over_an_unreconciled_send_stays_a_timeout_and_says_both() {
    let mut options = options(Output::Json);
    options.timeout = Duration::from_millis(150);

    let ran = run_against(start_plan("do the thing"), options, |mut peer| {
        tokio::spawn(async move {
            peer.hello(SERVES).await;

            let start = peer.request_for("interactive.start").await;
            peer.result(
                &start["id"],
                json!({ "id": SESSION, "outcome": "created", "ready": true }),
            )
            .await;

            let subscribe = peer.request_for("interactive.subscribe").await;
            peer.result(&subscribe["id"], json!([])).await;

            for _attempt in 0..2 {
                let send = peer.request_for("interactive.send_message").await;
                peer.result(&send["id"], json!({ "id": TURN, "status": "dispatching" }))
                    .await;
            }

            let interrupt = peer.request_for("interactive.interrupt").await;
            peer.result(&interrupt["id"], json!({})).await;
        })
    })
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Timeout);
    assert_eq!(report.exit().code(), 4);

    let error = report.error.as_deref().unwrap_or_default();
    assert!(error.contains("outcome remains unknown"), "{error}");
    assert!(error.contains("ceiling"), "{error}");
}

// ----- resync ----------------------------------------------------------------------------

#[tokio::test]
async fn a_lagged_stream_is_replayed_and_no_event_prints_twice() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::StreamJson),
        |mut peer| {
            tokio::spawn(async move {
                accept_start(&mut peer, json!([])).await;

                peer.notify(
                    "interactive.event",
                    json!({ "id": SESSION, "event": text_event(1, "output_text_delta", "one") }),
                )
                .await;

                // Frames 2 and 3 never arrive live.
                peer.notify(
                    "stream.lagged",
                    json!({
                        "id": SESSION,
                        "plane": "interactive",
                        "dropped": 2,
                        "last_sequence": 3,
                    }),
                )
                .await;

                let replay = peer.request_for("interactive.replay").await;
                assert_eq!(replay["params"]["cursor"], 1);
                assert_eq!(replay["params"]["limit"], 500);
                // The window overlaps what was already printed, exactly as the real one does.
                peer.result(
                    &replay["id"],
                    json!([
                        text_event(2, "output_text_delta", "two"),
                        text_event(3, "output_text_delta", "three"),
                    ]),
                )
                .await;

                for frame in [
                    // A frame the client already holds, re-sent live. It must not print again.
                    text_event(3, "output_text_delta", "three"),
                    text_event(4, "output_text_final", "onetwothreefour"),
                    event(5, "turn_completed", Some(TURN), json!({})),
                ] {
                    peer.notify(
                        "interactive.event",
                        json!({ "id": SESSION, "event": frame }),
                    )
                    .await;
                }
            })
        },
    )
    .await;

    assert_eq!(ran.report().status, Status::Completed);

    let objects = ran.objects();
    let sequences: Vec<u64> = objects
        .iter()
        .filter_map(|object| object["sequence"].as_u64())
        .collect();

    assert_eq!(
        sequences,
        vec![1, 2, 3, 4, 5],
        "every event once, in order: {:#?}",
        ran.lines()
    );
    assert_eq!(objects.len(), 6, "five events and one result");
    assert!(
        ran.err.contains("dropped 2 event frames"),
        "a gap the gateway admitted to is said out loud: {}",
        ran.err
    );
}

#[tokio::test]
async fn a_hole_no_lagged_frame_explained_is_replayed_too() {
    let ran = run_against(start_plan("do the thing"), options(Output::StreamJson), |mut peer| {
        tokio::spawn(async move {
            accept_start(&mut peer, json!([])).await;

            // 1 arrives, 2 is lost on this side, 3 arrives: a hole with nothing to
            // announce it.
            peer.notify(
                "interactive.event",
                json!({ "id": SESSION, "event": text_event(1, "output_text_delta", "one") }),
            )
            .await;
            peer.notify(
                "interactive.event",
                json!({ "id": SESSION, "event": text_event(3, "output_text_delta", "three") }),
            )
            .await;

            let replay = peer.request_for("interactive.replay").await;
            assert_eq!(replay["params"]["cursor"], 1);
            peer.result(
                &replay["id"],
                json!([text_event(2, "output_text_delta", "two")]),
            )
            .await;

            peer.notify(
                "interactive.event",
                json!({ "id": SESSION, "event": event(4, "turn_completed", Some(TURN), json!({})) }),
            )
            .await;
        })
    })
    .await;

    let sequences: Vec<u64> = ran
        .objects()
        .iter()
        .filter_map(|object| object["sequence"].as_u64())
        .collect();

    assert_eq!(sequences, vec![1, 2, 3, 4], "{:#?}", ran.lines());
}

// ----- resume ------------------------------------------------------------------------------

#[tokio::test]
async fn resume_subscribes_from_the_sessions_own_cursor_and_prints_only_the_new_turn() {
    let plan = Plan::Resume {
        session_id: SESSION.to_string(),
        prompt: "and again".to_string(),
    };

    let ran = run_against(plan, options(Output::StreamJson), |mut peer| {
        tokio::spawn(async move {
            peer.hello(SERVES).await;

            let info = peer.request_for("interactive.info").await;
            assert_eq!(info["params"]["id"], SESSION);
            peer.result(
                &info["id"],
                json!({
                    "_struct": "Ouroboros.Interactive.State",
                    "id": SESSION,
                    "status": "idle",
                    "provider": "codex",
                    // The plane's own contiguous high-water mark. Forty events of history
                    // this run has no business reprinting.
                    "cursor": 40,
                    "event_floor": 0,
                }),
            )
            .await;

            let subscribe = peer.request_for("interactive.subscribe").await;
            assert_eq!(
                subscribe["params"]["cursor"], 40,
                "a resumed run starts where the session already is"
            );
            peer.result(&subscribe["id"], json!([])).await;

            // Idle, so the plain verb rather than the queueing one.
            let send = peer.request_for("interactive.send_message").await;
            assert_eq!(send["params"]["input"], "and again");
            let turn = send["params"]["turn_id"]
                .as_str()
                .expect("a turn id")
                .to_string();
            peer.result(&send["id"], json!({ "id": turn, "status": "running" }))
                .await;

            for frame in [
                event(
                    41,
                    "output_text_final",
                    Some(&turn),
                    json!({ "text": "second answer" }),
                ),
                event(42, "turn_completed", Some(&turn), json!({})),
            ] {
                peer.notify(
                    "interactive.event",
                    json!({ "id": SESSION, "event": frame }),
                )
                .await;
            }
        })
    })
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Completed);
    assert_eq!(report.session_id, SESSION);
    assert_eq!(report.text, "second answer");

    let sequences: Vec<u64> = ran
        .objects()
        .iter()
        .filter_map(|object| object["sequence"].as_u64())
        .collect();

    assert_eq!(
        sequences,
        vec![41, 42],
        "only the new turn's events: {:#?}",
        ran.lines()
    );
}

#[tokio::test]
async fn a_busy_session_is_resumed_with_follow_up_rather_than_a_second_message() {
    let plan = Plan::Resume {
        session_id: SESSION.to_string(),
        prompt: "and again".to_string(),
    };

    let ran = run_against(plan, options(Output::Json), |mut peer| {
        tokio::spawn(async move {
            peer.hello(SERVES).await;

            let info = peer.request_for("interactive.info").await;
            peer.result(
                &info["id"],
                json!({ "id": SESSION, "status": "running", "provider": "codex", "cursor": 7 }),
            )
            .await;

            let subscribe = peer.request_for("interactive.subscribe").await;
            peer.result(&subscribe["id"], json!([])).await;

            // A second immediate `send_message` into a running session is `:busy`; this is
            // the verb that queues instead.
            let send = peer.request_for("interactive.follow_up").await;
            let turn = send["params"]["turn_id"].as_str().expect("a turn id").to_string();
            peer.result(&send["id"], json!({ "id": turn, "status": "queued" }))
                .await;

            peer.notify(
                "interactive.event",
                json!({ "id": SESSION, "event": event(8, "turn_completed", Some(&turn), json!({})) }),
            )
            .await;
        })
    })
    .await;

    assert_eq!(ran.report().status, Status::Completed);
}

#[tokio::test]
async fn a_terminal_session_is_refused_rather_than_sent_a_turn() {
    let plan = Plan::Resume {
        session_id: SESSION.to_string(),
        prompt: "and again".to_string(),
    };

    let ran = run_against(plan, options(Output::Json), |mut peer| {
        tokio::spawn(async move {
            peer.hello(SERVES).await;

            let info = peer.request_for("interactive.info").await;
            peer.result(
                &info["id"],
                json!({ "id": SESSION, "status": "closed", "cursor": 12 }),
            )
            .await;
        })
    })
    .await;

    let refusal = ran.refusal();
    assert!(
        refusal.contains("closed") && refusal.contains("no further turns"),
        "{refusal}"
    );
    assert!(ran.out.is_empty(), "a refusal starts nothing: {}", ran.out);
}

// ----- refusals ------------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_start_carries_the_runtimes_own_words() {
    let data = json!([
        "session_start_failed",
        {
            "__exception__": true,
            "provider": "codex",
            "message": "provider does not support normalized session option",
            "details": { "field": "sandbox_mode" }
        }
    ]);

    let refused = data.clone();
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        move |mut peer| {
            tokio::spawn(async move {
                peer.hello(SERVES).await;

                let start = peer.request_for("interactive.start").await;
                peer.error(
                    &start["id"],
                    -32006,
                    "the runtime refused the call",
                    Some(refused),
                )
                .await;
            })
        },
    )
    .await;

    // Exactly `model::refusal`'s rendering, which is what makes the one-sentence version
    // of a Wire-encoded exception reach a pipe rather than the raw JSON blob.
    let expected = ouro::model::refusal(&RpcError {
        code: ErrorCode::UpstreamError,
        message: "the runtime refused the call".into(),
        data: Some(data),
    });

    let refusal = ran.refusal();
    assert!(refusal.contains(&expected), "{refusal}\n---\n{expected}");
    assert!(
        refusal.contains("provider does not support normalized session option"),
        "{refusal}"
    );
    assert!(
        ran.out.is_empty(),
        "a refusal prints no result: {}",
        ran.out
    );
    assert_eq!(run::Exit::USAGE.code(), 64);
}

/// The exit code and the two surfaces, end to end through the real binary.
///
/// This is the one property no driver test can prove: that a refusal costs 64, that it
/// reaches both stderr and — because stdout is JSON here — stdout, and that it happens
/// *before* a runtime is started. A `ouro run` that spawned a daemon and then refused
/// would leave one behind on every misspelled flag.
#[test]
fn the_binary_refuses_a_prompt_with_no_provider_before_it_starts_a_runtime() {
    let home = std::env::temp_dir().join(format!("ouro-run-refusal-{}", std::process::id()));
    let data = home.join("data");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&data).expect("a scratch home");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(["run", "do the thing", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("share"))
        .env("OUROBOROS_DATA_DIR", &data)
        .output()
        .expect("the ouro binary runs");

    assert_eq!(
        output.status.code(),
        Some(64),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    let object: Value = serde_json::from_str(stdout.trim()).expect("one JSON object on stdout");
    assert_eq!(object["type"], "error");
    assert!(
        object["error"]
            .as_str()
            .expect("the refusal text")
            .contains("no provider was named"),
        "{object}"
    );
    assert!(stderr.contains("no provider was named"), "{stderr}");
    assert!(
        !data.join("gateway.json").exists(),
        "a refusal must not leave a runtime behind it"
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// The headless approval policy is documented where a person types the command.
#[test]
fn the_help_says_what_a_headless_approval_is_answered_with() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(["run", "--help"])
        .output()
        .expect("the ouro binary runs");

    let help = String::from_utf8(output.stdout).expect("help is UTF-8");

    assert!(help.contains("--approve-all"), "{help}");
    assert!(
        help.contains("deny") && help.contains("never waits"),
        "the default an unattended run applies has to be readable before it is relied on: \
         {help}"
    );
    assert!(
        help.contains("--stream-json") && help.contains("--resume"),
        "{help}"
    );
}

#[tokio::test]
async fn a_gateway_that_does_not_serve_the_verbs_is_refused_before_anything_starts() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                peer.hello(&["hello", "runtime.status"]).await;
            })
        },
    )
    .await;

    let refusal = ran.refusal();
    assert!(
        refusal.contains("interactive.start"),
        "the refusal names the verb it needed: {refusal}"
    );
}

#[tokio::test]
async fn a_session_created_but_never_ready_is_a_failure_with_its_reason() {
    let ran = run_against(
        start_plan("do the thing"),
        options(Output::Json),
        |mut peer| {
            tokio::spawn(async move {
                peer.hello(SERVES).await;

                let start = peer.request_for("interactive.start").await;
                peer.result(
                    &start["id"],
                    json!({
                        "id": SESSION,
                        "outcome": "created",
                        "ready": false,
                        "error": { "message": "the provider binary is not on PATH" },
                    }),
                )
                .await;
            })
        },
    )
    .await;

    let report = ran.report();
    assert_eq!(report.status, Status::Failed);
    assert_eq!(report.exit().code(), 1);
    assert!(
        report
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("the provider binary is not on PATH"),
        "{:?}",
        report.error
    );
    assert_eq!(ran.objects()[0]["status"], "failed");
}
