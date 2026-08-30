//! `ouro replay` and `ouro fork` against the scripted gateway.
//!
//! Three claims, and the first one is the feature:
//!
//! 1. **The render is stable.** Two runs of `ouro replay` over the same records produce
//!    the same bytes. A deterministic replay whose *rendering* was not deterministic would
//!    be undiffable, and diffing two runs is the whole reason the command exists.
//! 2. **The params are the flags and nothing else.** An absent `--at` is an absent
//!    `to_turn`, because `interactive.fork`'s envelope is closed and a client that always
//!    sent the key would break every plain fork against a runtime that has not grown it.
//! 3. **An old runtime is told about legibly.** `-32602` on a call carrying `to_turn` is
//!    rendered as "this runtime does not support `--at` yet", not as `invalid_params`.
//!
//! The badge is the other half of this slice and has its own file, `replay_badge.rs`.

mod support;

use serde_json::{json, Value};

use ouro::replay_cli::{
    self, ForkOptions, Options, EVENTS_METHOD, FORK_METHOD, JOURNAL_METHOD, VERIFY_METHOD,
};

use support::{config, listener, Peer};

// ---------------------------------------------------------------------------------------
// canned records
// ---------------------------------------------------------------------------------------

const SESSION: &str = "session-0000000000000000000001";

/// A journal window shaped like the golden fixture: a `turn_started` naming the model, the
/// `model_call` that does not, and the `turn_settled` that closes the chain.
fn journal_page() -> Value {
    json!({
        "count": 3,
        "head": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "head_seq": 3,
        "verified_through": 3,
        "truncated_through": Value::Null,
        "records": [
            {
                "seq": 1,
                "kind": "turn_started",
                "at": "2026-01-01T00:00:00.000000Z",
                "turn_id": "turn-1",
                "prev": "0000000000000000000000000000000000000000000000000000000000000000",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "model_spec": "anthropic:claude-sonnet-4",
                "system_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
            },
            {
                "seq": 2,
                "kind": "model_call",
                "at": "2026-01-01T00:00:01.000000Z",
                "turn_id": "turn-1",
                "iteration": 1,
                "prev": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "request_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                "message_count": 7,
                "ledger_effect_id": "inference-0001"
            },
            {
                "seq": 3,
                "kind": "turn_settled",
                "at": "2026-01-01T00:01:30.000000Z",
                "turn_id": "turn-1",
                "prev": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "status": "complete",
                "message_count": 7,
                "conversation_digest": "4444444444444444444444444444444444444444444444444444444444444444"
            }
        ]
    })
}

/// The page that ends the walk: a window with no records is the end of the journal.
fn journal_end() -> Value {
    json!({
        "count": 3,
        "head": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "head_seq": 3,
        "verified_through": 3,
        "truncated_through": Value::Null,
        "records": []
    })
}

fn event(sequence: u64, kind: &str, payload: Value) -> Value {
    json!({
        "_struct": "Ouroboros.Interactive.Event",
        "id": format!("evt-{sequence}"),
        "sequence": sequence,
        "session_id": SESSION,
        "timestamp": "2026-01-01T00:00:00.000000Z",
        "type": kind,
        "payload": payload
    })
}

fn event_page() -> Value {
    json!([
        event(1, "input_accepted", json!({ "text": "run the suite" })),
        event(
            2,
            "output_text_final",
            json!({ "text": "The suite passed: 412 tests, 0 failures." })
        ),
    ])
}

// ---------------------------------------------------------------------------------------
// the scripted gateway
// ---------------------------------------------------------------------------------------

/// What the peer answers, per verb, in order.
#[derive(Default)]
struct Script {
    journal: Vec<Value>,
    events: Vec<Value>,
    verify: Option<Value>,
}

impl Script {
    /// The ordinary session: one page of each, then the page that ends the walk.
    fn whole() -> Self {
        Self {
            journal: vec![journal_page(), journal_end()],
            events: vec![event_page(), json!([])],
            verify: None,
        }
    }

    /// Exactly how many calls the client will make against this script, which is what lets
    /// the peer stop rather than waiting on a socket the test still holds open.
    fn calls(&self) -> usize {
        self.journal.len() + self.events.len() + usize::from(self.verify.is_some())
    }
}

/// Runs `replay_cli::run` against a scripted peer. Returns the requests it made and the
/// two streams it wrote.
async fn drive(options: Options, script: Script) -> (Vec<Value>, String, String) {
    let (listen, address) = listener().await;
    let calls = script.calls();

    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[JOURNAL_METHOD, EVENTS_METHOD, VERIFY_METHOD])
            .await;

        let mut journal = script.journal.into_iter();
        let mut events = script.events.into_iter();
        let mut seen = Vec::new();

        for _ in 0..calls {
            let request = peer.request().await.expect("a call");
            let answer = match request["method"].as_str() {
                Some(JOURNAL_METHOD) => journal.next().unwrap_or_else(journal_end),
                Some(EVENTS_METHOD) => events.next().unwrap_or_else(|| json!([])),
                Some(VERIFY_METHOD) => script.verify.clone().unwrap_or_else(|| json!({})),
                other => panic!("unexpected call {other:?}"),
            };

            peer.result(&request["id"], answer).await;
            seen.push(request);
        }

        seen
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    replay_cli::run(&connected.client, &options, &mut out, &mut err)
        .await
        .expect("a replay");

    let seen = peer.await.expect("the script");

    (
        seen,
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

fn options() -> Options {
    Options {
        session: SESSION.to_string(),
        ..Options::default()
    }
}

// ---------------------------------------------------------------------------------------
// 1. the render is stable
// ---------------------------------------------------------------------------------------

/// The property the whole feature rests on: same records, same width, same bytes.
///
/// Two *separate* runs against two separate connections, not one render compared with
/// itself — the second form would pass for a renderer that read the clock once and cached
/// it, which is precisely the bug this is here to catch.
#[tokio::test]
async fn two_replays_of_the_same_records_are_byte_identical() {
    let (_first_calls, first, first_notes) = drive(options(), Script::whole()).await;
    let (_second_calls, second, second_notes) = drive(options(), Script::whole()).await;

    assert_eq!(first, second, "the same records rendered differently twice");
    assert_eq!(first_notes, second_notes);

    // And the render is not empty, so the equality above is a claim about something.
    assert!(first.contains("run the suite"), "{first}");
    assert!(first.contains("The suite passed"), "{first}");
}

/// A narrower width is a different render, which is what makes `--width` load-bearing
/// rather than decorative.
#[tokio::test]
async fn the_width_is_the_measure_the_transcript_wraps_at() {
    let (_calls, wide, _notes) = drive(options(), Script::whole()).await;
    let (_calls, narrow, _notes) = drive(
        Options {
            width: 40,
            ..options()
        },
        Script::whole(),
    )
    .await;

    assert_ne!(wide, narrow);
    // The provenance header is not wrapped: it is a fixed set of facts, and a header that
    // reflowed would make two runs at two widths incomparable for no reason.
    assert!(
        narrow.contains("chain head        cccccccccccc"),
        "{narrow}"
    );
}

// ---------------------------------------------------------------------------------------
// 2. the provenance header
// ---------------------------------------------------------------------------------------

/// Everything the header claims, and where each fact came from.
#[tokio::test]
async fn the_header_states_the_chain_and_one_row_per_model_call() {
    let (calls, out, notes) = drive(options(), Script::whole()).await;

    assert!(out.starts_with(&format!("replay {SESSION}\n")), "{out}");
    assert!(out.contains("records read      3"), "{out}");
    assert!(
        out.contains("chain head        cccccccccccc (seq 3)"),
        "{out}"
    );
    assert!(out.contains("verified through  3 of 3"), "{out}");

    // §3.2 puts `model_spec` on `turn_started` and not on the call, so the row resolves it
    // by turn rather than leaving a dash where the journal does know the answer.
    assert!(out.contains("model calls (1)"), "{out}");
    assert!(
        out.contains("anthropic:claude-sonnet-4"),
        "the model is resolved from the turn that started it: {out}"
    );
    assert!(
        out.contains("111111111111"),
        "the request digest prefix is the diffable fact: {out}"
    );

    // Nothing was dropped, so nothing claims it was.
    assert!(!out.contains("truncated"), "{out}");
    assert_eq!(notes, "", "a whole read has nothing to warn about");

    // The journal is walked with an exclusive cursor, and the second page proves the walk
    // terminates on an empty window rather than on a guess.
    let journal: Vec<&Value> = calls
        .iter()
        .filter(|call| call["method"] == JOURNAL_METHOD)
        .collect();
    assert_eq!(journal.len(), 2);
    assert_eq!(journal[0]["params"], json!({"id": SESSION, "limit": 500}));
    assert_eq!(
        journal[1]["params"],
        json!({"id": SESSION, "since_seq": 3, "limit": 500})
    );

    // The events come from the *existing* gap-repair verb, cursor-windowed. This slice
    // introduced no second event verb and this is where that stays true.
    let events: Vec<&Value> = calls
        .iter()
        .filter(|call| call["method"] == EVENTS_METHOD)
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["params"], json!({"id": SESSION, "limit": 500}));
    assert_eq!(
        events[1]["params"],
        json!({"id": SESSION, "cursor": 2, "limit": 500})
    );
}

/// A session with no journal is said to have none, rather than rendering a header of
/// dashes that reads like a verified empty chain.
#[tokio::test]
async fn a_session_without_a_journal_says_so_before_the_transcript() {
    let (_calls, out, _notes) = drive(
        options(),
        Script {
            journal: vec![json!({"records": []})],
            events: vec![event_page(), json!([])],
            verify: None,
        },
    )
    .await;

    assert!(out.contains("no journal"), "{out}");
    assert!(out.contains("Nothing below is verifiable"), "{out}");
    // The transcript is still rendered: the events exist even where the journal does not.
    assert!(out.contains("The suite passed"), "{out}");
}

/// Truncation and gaps are the records that bound a replay, and they are stated.
#[tokio::test]
async fn a_truncated_journal_names_what_cannot_be_replayed() {
    let mut page = journal_page();
    page["truncated_through"] = json!(9);
    page["verified_through"] = json!(2);
    page["records"]
        .as_array_mut()
        .expect("records")
        .push(json!({
            "seq": 4,
            "kind": "gap",
            "reason": "the journal could not be appended to"
        }));

    // The page that ends the walk restates the same chain facts, because it is the newest
    // answer and the newest answer is the one the header believes.
    let mut end = page.clone();
    end["records"] = json!([]);

    let (_calls, out, _notes) = drive(
        options(),
        Script {
            journal: vec![page, end],
            events: vec![json!([])],
            verify: None,
        },
    )
    .await;

    assert!(
        out.contains("everything at or below seq 9 was dropped"),
        "{out}"
    );
    assert!(
        out.contains("the chain above 2 is not verified"),
        "a bounded verification must not read as a whole one: {out}"
    );
    assert!(
        out.contains("gap at seq 4: the journal could not be appended to"),
        "{out}"
    );
}

// ---------------------------------------------------------------------------------------
// 3. --verify, against the shape the engine slice publishes
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn verify_renders_the_verdict_in_the_header() {
    let (calls, out, _notes) = drive(
        Options {
            verify: true,
            ..options()
        },
        Script {
            verify: Some(json!({
                "verified": true,
                "turns": 12,
                "records": 340,
                "head": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "divergence": Value::Null
            })),
            ..Script::whole()
        },
    )
    .await;

    assert!(out.contains("verify            verified"), "{out}");
    assert!(out.contains("12 turn(s), 340 record(s)"), "{out}");

    let verify = calls
        .iter()
        .find(|call| call["method"] == VERIFY_METHOD)
        .expect("--verify asks the engine");
    assert_eq!(verify["params"], json!({"id": SESSION}));
}

/// A divergence is a finding, so every field of it is printed rather than a boolean.
#[tokio::test]
async fn a_divergence_is_named_field_by_field() {
    let (_calls, out, _notes) = drive(
        Options {
            verify: true,
            ..options()
        },
        Script {
            verify: Some(json!({
                "verified": false,
                "turns": 3,
                "records": 40,
                "divergence": {
                    "seq": 17,
                    "turn_id": "turn-2",
                    "field": "conversation_digest",
                    "expected_sha256": "aaaaaaaaaaaaaaaa",
                    "got_sha256": "bbbbbbbbbbbbbbbb"
                }
            })),
            ..Script::whole()
        },
    )
    .await;

    assert!(out.contains("verify            DIVERGED"), "{out}");
    assert!(
        out.contains("divergence        conversation_digest at seq 17 of turn turn-2"),
        "{out}"
    );
    assert!(out.contains("expected          aaaaaaaaaaaa"), "{out}");
    assert!(out.contains("got               bbbbbbbbbbbb"), "{out}");
}

/// The engine verb ships in another slice. Until it does, `--verify` says that in a
/// sentence and still prints the transcript it was able to read.
#[tokio::test]
async fn a_runtime_without_the_verify_verb_says_so_and_still_renders() {
    let (listen, address) = listener().await;

    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[JOURNAL_METHOD, EVENTS_METHOD]).await;

        let mut journal = vec![journal_page(), journal_end()].into_iter();
        let mut events = vec![event_page(), json!([])].into_iter();

        for _ in 0..5 {
            let request = peer.request().await.expect("a call");

            match request["method"].as_str() {
                Some(JOURNAL_METHOD) => {
                    let answer = journal.next().unwrap_or_else(journal_end);
                    peer.result(&request["id"], answer).await;
                }
                Some(EVENTS_METHOD) => {
                    let answer = events.next().unwrap_or_else(|| json!([]));
                    peer.result(&request["id"], answer).await;
                }
                Some(VERIFY_METHOD) => {
                    peer.error(
                        &request["id"],
                        -32601,
                        "no such method: interactive.replay_verify",
                        None,
                    )
                    .await;
                }
                other => panic!("unexpected call {other:?}"),
            }
        }
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    replay_cli::run(
        &connected.client,
        &Options {
            verify: true,
            ..options()
        },
        &mut out,
        &mut err,
    )
    .await
    .expect("a replay whose verify was refused is still a replay");

    let out = String::from_utf8(out).expect("utf-8");

    assert!(
        out.contains(&format!("does not serve {VERIFY_METHOD} yet")),
        "{out}"
    );
    assert!(out.contains("The suite passed"), "{out}");

    peer.await.expect("the script");
}

// ---------------------------------------------------------------------------------------
// 4. --json
// ---------------------------------------------------------------------------------------

/// The machine stream: the journal's own records, then the session's own events, and the
/// header moved off stdout so a pipe reads a clean stream.
#[tokio::test]
async fn json_puts_the_records_on_stdout_and_the_header_on_stderr() {
    let (_calls, out, notes) = drive(
        Options {
            json: true,
            ..options()
        },
        Script::whole(),
    )
    .await;

    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 5, "three records and two events: {out}");

    // Unreshaped, and told apart by their own shapes rather than by an envelope this
    // client invented: a journal record has `seq`/`kind`, an event has `sequence`/`type`.
    let first: Value = serde_json::from_str(lines[0]).expect("a JSON object");
    assert_eq!(first["seq"], 1);
    assert_eq!(first["kind"], "turn_started");
    assert_eq!(first["model_spec"], "anthropic:claude-sonnet-4");

    let event: Value = serde_json::from_str(lines[3]).expect("a JSON object");
    assert_eq!(event["sequence"], 1);
    assert_eq!(event["type"], "input_accepted");
    assert_eq!(event["_struct"], "Ouroboros.Interactive.Event");

    // Nothing but records on stdout, and the provenance still reaches the operator.
    assert!(!out.contains("chain head"), "{out}");
    assert!(notes.contains("chain head        cccccccccccc"), "{notes}");
}

// ---------------------------------------------------------------------------------------
// 5. `ouro fork`: the params are the flags
// ---------------------------------------------------------------------------------------

fn fork_options() -> ForkOptions {
    ForkOptions {
        session: SESSION.to_string(),
        fork_id: "ouro-cli-deadbeef".to_string(),
        ..ForkOptions::default()
    }
}

/// A plain fork sends the two keys the shipped envelope has and no others. This is the
/// test that keeps `ouro fork` working against a runtime that has not taken R3 yet.
#[test]
fn an_unflagged_fork_sends_neither_new_param() {
    assert_eq!(
        fork_options().params(),
        json!({"id": SESSION, "fork_id": "ouro-cli-deadbeef"})
    );
}

#[test]
fn each_flag_becomes_the_param_it_names_and_only_when_given() {
    let at_only = ForkOptions {
        at: Some("turn-2".into()),
        ..fork_options()
    };
    assert_eq!(
        at_only.params(),
        json!({"id": SESSION, "fork_id": "ouro-cli-deadbeef", "to_turn": "turn-2"})
    );

    let model_only = ForkOptions {
        model: Some("anthropic:claude-opus-4".into()),
        ..fork_options()
    };
    assert_eq!(
        model_only.params(),
        json!({
            "id": SESSION,
            "fork_id": "ouro-cli-deadbeef",
            "model": "anthropic:claude-opus-4"
        })
    );

    let both = ForkOptions {
        node: Some("ouroboros@alpha".into()),
        at: Some("turn-2".into()),
        model: Some("anthropic:claude-opus-4".into()),
        ..fork_options()
    };
    assert_eq!(
        both.params(),
        json!({
            "id": SESSION,
            "fork_id": "ouro-cli-deadbeef",
            "node": "ouroboros@alpha",
            "to_turn": "turn-2",
            "model": "anthropic:claude-opus-4"
        })
    );

    // Whitespace is not a flag. An empty `--model ""` is the operator saying nothing, and
    // sending `model: ""` would be this client turning that into a refusal.
    let blank = ForkOptions {
        at: Some("   ".into()),
        model: Some(String::new()),
        ..fork_options()
    };
    assert_eq!(
        blank.params(),
        json!({"id": SESSION, "fork_id": "ouro-cli-deadbeef"})
    );
}

/// Drives `replay_cli::fork` against one scripted answer.
async fn drive_fork(
    options: ForkOptions,
    answer: Result<Value, (i64, &'static str)>,
) -> (Value, Result<String, String>) {
    let (listen, address) = listener().await;

    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[FORK_METHOD]).await;
        let request = peer.request_for(FORK_METHOD).await;

        match answer {
            Ok(result) => peer.result(&request["id"], result).await,
            Err((code, message)) => peer.error(&request["id"], code, message, None).await,
        }

        request
    });

    let connected = ouro::transport::connect(
        config(address),
        std::sync::Arc::new(ouro::transport::NoReconnectHook),
    )
    .await
    .expect("a handshake");

    let mut out = Vec::new();
    let mut err = Vec::new();

    let outcome = replay_cli::fork(&connected.client, &options, &mut out, &mut err).await;
    let request = peer.await.expect("the script");

    let rendered = match outcome {
        Ok(()) => Ok(String::from_utf8(out).expect("utf-8")),
        Err(error) => Err(format!("{error:#}")),
    };

    (request["params"].clone(), rendered)
}

#[tokio::test]
async fn a_fork_prints_the_child_and_its_ready_state() {
    let (params, rendered) = drive_fork(
        fork_options(),
        Ok(json!({
            "_struct": "Ouroboros.Interactive.Ref",
            "id": "ouro-cli-deadbeef",
            "node": "ouroboros@alpha",
            "ready": true,
            "error": Value::Null
        })),
    )
    .await;

    assert_eq!(params["fork_id"], "ouro-cli-deadbeef");

    let text = rendered.expect("a fork");
    assert!(text.contains("forked"), "{text}");
    assert!(text.contains("ouro-cli-deadbeef"), "{text}");
    assert!(text.contains("node    ouroboros@alpha"), "{text}");
    assert!(text.contains("ready   yes"), "{text}");
}

/// A durable child that did not become ready is addressable *and* broken, and both halves
/// are printed: an operator who is told only "not ready" has nothing to go and look at.
#[tokio::test]
async fn a_child_that_did_not_become_ready_names_the_error_too() {
    let (_params, rendered) = drive_fork(
        fork_options(),
        Ok(json!({
            "id": "ouro-cli-deadbeef",
            "node": "ouroboros@alpha",
            "ready": false,
            "error": {"reason": "the workspace lease is held"}
        })),
    )
    .await;

    let text = rendered.expect("a fork");
    assert!(text.contains("ready   no"), "{text}");
    assert!(text.contains("the workspace lease is held"), "{text}");
}

/// The identity contract, from the other side: a child this client did not name is a
/// refusal, because the same-id retry above could otherwise adopt something else.
#[tokio::test]
async fn a_child_with_a_different_id_is_refused_rather_than_reported() {
    let (_params, rendered) = drive_fork(
        fork_options(),
        Ok(json!({"id": "some-other-session", "ready": true})),
    )
    .await;

    let error = rendered.expect_err("a mismatched id is not a fork");
    assert!(error.contains("ouro-cli-deadbeef"), "{error}");
    assert!(error.contains("some-other-session"), "{error}");
}

// ---------------------------------------------------------------------------------------
// 6. the refusal an older runtime earns
// ---------------------------------------------------------------------------------------

/// `-32602` on a call that carried `to_turn` is a runtime whose fork envelope predates the
/// param. Saying `invalid_params` at an operator who just typed `--at` is the least useful
/// true sentence available.
#[tokio::test]
async fn an_old_runtime_refusing_to_turn_is_rendered_as_the_flag_it_refused() {
    let (_params, rendered) = drive_fork(
        ForkOptions {
            at: Some("turn-2".into()),
            ..fork_options()
        },
        Err((-32602, "unknown key: to_turn")),
    )
    .await;

    let error = rendered.expect_err("a refusal");
    assert!(
        error.contains("this runtime does not support --at yet"),
        "{error}"
    );
    // The runtime's own words survive beside the translation, so the operator can tell a
    // missing param from a malformed one.
    assert!(error.contains("unknown key: to_turn"), "{error}");
}

#[tokio::test]
async fn the_refusal_names_both_flags_when_both_were_sent() {
    let (_params, rendered) = drive_fork(
        ForkOptions {
            at: Some("turn-2".into()),
            model: Some("anthropic:claude-opus-4".into()),
            ..fork_options()
        },
        Err((-32602, "unknown key: to_turn")),
    )
    .await;

    let error = rendered.expect_err("a refusal");
    assert!(
        error.contains("this runtime does not support --at and --model yet"),
        "{error}"
    );
}

/// And a plain fork's `-32602` is *not* translated: nothing about the flags was wrong,
/// because none were sent, so inventing that explanation would send the operator looking
/// for a flag they never typed.
#[tokio::test]
async fn an_unflagged_fork_keeps_the_runtime_s_own_refusal() {
    let (_params, rendered) = drive_fork(fork_options(), Err((-32602, "unknown key: id"))).await;

    let error = rendered.expect_err("a refusal");
    assert!(!error.contains("does not support"), "{error}");
    assert!(error.contains("unknown key: id"), "{error}");
}
