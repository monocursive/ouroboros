//! `ouro acp` driven as the two things it actually is: an ACP agent on one side and a
//! gateway client on the other.
//!
//! The ACP half is exercised frame by frame through [`Agent::handle_line`] and
//! [`Agent::handle_notification`], so the JSON these tests assert on is the bytes an
//! editor would read. The gateway half runs against `support::Peer`, the same scripted
//! peer the transport, UI and `mcp-serve` tests use, so the handshake, the correlation and
//! the parameters are the real ones. Two tests drive the whole loop over a pair of duplex
//! streams, because stdin EOF and the frame ceiling are properties of the loop rather than
//! of the state machine.
//!
//! The property most of these are really about is the same one: what the editor is told
//! happened is what the runtime said happened — no update this bridge invented, and no
//! `stopReason` for a turn that did not stop.

mod support;

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use ouro::acp_serve::{
    completed_stop_reason, configured_mode, modes_for, prompt_input, tool_kind, Agent, Options,
    StopReason, MAX_LINE_BYTES, PROTOCOL_VERSION,
};
use ouro::proto::Notification;
use ouro::transport::{self, NoReconnectHook};

use support::{config, listener, Peer, PATIENCE};

/// Everything `Agent::unserved` checks, plus the two optional verbs the modes and the
/// queued-follow-up path need.
const METHODS: &[&str] = &[
    "interactive.start",
    "interactive.info",
    "interactive.subscribe",
    "interactive.replay",
    "interactive.send_message",
    "interactive.follow_up",
    "interactive.interrupt",
    "interactive.respond_approval",
    "interactive.configure",
];

/// A scripted gateway that answers by method name and records every request it was sent.
///
/// A reply carrying `__error` is answered as a typed JSON-RPC error instead of a result,
/// which is how the refusal tests reach `model::refusal`.
struct Harness {
    agent: Agent,
    requests: mpsc::UnboundedReceiver<Value>,
    script: tokio::task::JoinHandle<()>,
    /// The id `session/new` opened. Client-minted, so a fixture cannot know it in advance
    /// — which is the point: the start identity belongs to this client.
    session: String,
    #[allow(dead_code)]
    notifications: mpsc::Receiver<Notification>,
}

impl Harness {
    async fn start(replies: Vec<(&'static str, Value)>) -> Self {
        let (listen, address) = listener().await;
        let (sender, requests) = mpsc::unbounded_channel();

        let script = tokio::spawn(async move {
            let mut peer = Peer::accept(&listen).await;
            peer.hello(METHODS).await;
            let mut replies = replies;

            while let Some(request) = peer.request().await {
                let method = request["method"].as_str().unwrap_or_default().to_string();
                let _ = sender.send(request.clone());

                let mut reply = match replies.iter().position(|(name, _)| *name == method) {
                    Some(index) => replies.remove(index).1,
                    None => json!({}),
                };

                // The start identity contract, honoured: a runtime answers the id it was
                // asked for. The agent refuses to drive a session that answers another.
                if method == "interactive.start" && reply.get("__error").is_none() {
                    reply["id"] = request["params"]["id"].clone();
                }

                match reply.get("__error") {
                    Some(error) => {
                        peer.error(
                            &request["id"],
                            error["code"].as_i64().unwrap_or(-32006),
                            error["message"].as_str().unwrap_or_default(),
                            error.get("data").cloned(),
                        )
                        .await
                    }
                    None => peer.result(&request["id"], reply).await,
                }
            }
        });

        let connected = transport::connect(config(address), Arc::new(NoReconnectHook))
            .await
            .expect("a handshake");

        Self {
            agent: Agent::new(connected.client, connected.hello, options()),
            requests,
            script,
            session: String::new(),
            notifications: connected.notifications,
        }
    }

    /// One editor line in, the frames out.
    async fn line(&mut self, frame: Value) -> Vec<Value> {
        self.agent
            .handle_line(&serde_json::to_string(&frame).expect("encodable"))
            .await
    }

    /// One gateway event in, the frames out.
    async fn event(&mut self, sequence: u64, kind: &str, payload: Value) -> Vec<Value> {
        self.event_for(sequence, kind, payload, None, None).await
    }

    async fn event_for(
        &mut self,
        sequence: u64,
        kind: &str,
        payload: Value,
        turn_id: Option<&str>,
        request_id: Option<&str>,
    ) -> Vec<Value> {
        let mut event = json!({
            "id": format!("evt-{sequence}"),
            "sequence": sequence,
            "type": kind,
            "timestamp": "2026-08-23T00:00:00.000000Z",
            "payload": payload,
        });

        if let Some(turn_id) = turn_id {
            event["turn_id"] = json!(turn_id);
        }
        if let Some(request_id) = request_id {
            event["request_id"] = json!(request_id);
        }

        let params = json!({ "id": self.session, "event": event });
        self.notify("interactive.event", params).await
    }

    async fn notify(&mut self, method: &str, params: Value) -> Vec<Value> {
        self.agent
            .handle_notification(Notification {
                method: method.into(),
                params,
            })
            .await
    }

    /// The next request the gateway was sent for `method`, panicking with what it did get.
    fn sent(&mut self, method: &str) -> Value {
        let mut seen = Vec::new();

        while let Ok(request) = self.requests.try_recv() {
            if request["method"] == method {
                return request;
            }

            seen.push(request["method"].as_str().unwrap_or_default().to_string());
        }

        panic!("no {method} was sent; the gateway saw {seen:?}");
    }

    fn nothing_sent(&mut self, method: &str) {
        while let Ok(request) = self.requests.try_recv() {
            assert_ne!(
                request["method"], method,
                "{method} should not have been sent"
            );
        }
    }

    /// Handshake, open a session, and forget the frames those produced.
    async fn opened(&mut self) {
        self.line(initialize()).await;
        let opened = self.line(session_new()).await;

        self.session = opened[0]["result"]["sessionId"]
            .as_str()
            .unwrap_or_else(|| panic!("session/new did not open a session: {opened:#?}"))
            .to_string();

        while self.requests.try_recv().is_ok() {}
    }

    /// One `session/prompt` into the session this harness opened.
    async fn prompt(&mut self, id: u64, text: &str) -> Vec<Value> {
        let frame = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/prompt",
            "params": {
                "sessionId": self.session,
                "prompt": [{"type": "text", "text": text}]
            }
        });

        self.line(frame).await
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.script.abort();
    }
}

fn options() -> Options {
    Options {
        provider: "native".into(),
        workspace: None,
        approval_mode: Some("prompt".into()),
        sandbox_mode: None,
    }
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {
                "fs": {"readTextFile": true, "writeTextFile": true},
                "terminal": true
            },
            "clientInfo": {"name": "zed", "title": "Zed", "version": "1.0.0"}
        }
    })
}

fn session_new() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "session/new",
        "params": {"cwd": "/tmp/project", "mcpServers": []}
    })
}

/// `interactive.start`'s reference (whose `id` the script replaces with the one it was
/// asked for), `interactive.info`'s options, and the empty backlog a subscribe answers
/// with — the three calls one `session/new` makes.
fn open_replies() -> Vec<(&'static str, Value)> {
    vec![
        (
            "interactive.start",
            json!({"node": "ouroboros@host", "outcome": "created", "ready": true}),
        ),
        (
            "interactive.info",
            json!({
                "provider": "native",
                "status": "idle",
                "options": {
                    "approval_mode": "prompt",
                    "plan": false,
                    "capabilities": {
                        "transport": "native",
                        "approvals": "native",
                        "dynamic_configuration": "native",
                        "multimodal": false
                    }
                }
            }),
        ),
        ("interactive.subscribe", json!([])),
    ]
}

fn accepted() -> Value {
    json!({"accepted": true, "harness_turn_id": "harness-turn-1"})
}

fn with_send(extra: Vec<(&'static str, Value)>) -> Vec<(&'static str, Value)> {
    let mut replies = open_replies();
    replies.push(("interactive.send_message", accepted()));
    replies.extend(extra);
    replies
}

/// The one `session/update` in a batch, or a panic naming what was there instead.
fn only_update(frames: &[Value]) -> Value {
    let updates: Vec<&Value> = frames
        .iter()
        .filter(|frame| frame["method"] == "session/update")
        .collect();

    assert_eq!(
        updates.len(),
        1,
        "expected exactly one session/update, got {frames:#?}"
    );

    updates[0]["params"]["update"].clone()
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initialize_answers_the_v1_handshake_byte_for_byte() {
    let mut harness = Harness::start(Vec::new()).await;
    let frames = harness.line(initialize()).await;

    assert_eq!(frames.len(), 1);
    assert_eq!(
        frames[0],
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "agentCapabilities": {
                    "loadSession": false,
                    "promptCapabilities": {
                        "image": false,
                        "audio": false,
                        "embeddedContext": false
                    },
                    "mcpCapabilities": {"http": false, "sse": false}
                },
                "agentInfo": {
                    "name": "ouroboros",
                    "title": "Ouroboros",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "authMethods": []
            }
        })
    );
}

#[tokio::test]
async fn nothing_is_served_before_initialize() {
    let mut harness = Harness::start(open_replies()).await;
    let frames = harness.line(session_new()).await;

    assert_eq!(frames[0]["error"]["code"], -32600);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("initialize must be the first method"));

    harness.nothing_sent("interactive.start");
}

#[tokio::test]
async fn session_load_and_authenticate_are_refused_because_nothing_advertises_them() {
    let mut harness = Harness::start(Vec::new()).await;
    harness.line(initialize()).await;

    for (method, params) in [
        (
            "session/load",
            json!({"sessionId": "s1", "cwd": "/tmp", "mcpServers": []}),
        ),
        ("authenticate", json!({"methodId": "anything"})),
    ] {
        let frames = harness
            .line(json!({"jsonrpc": "2.0", "id": 9, "method": method, "params": params}))
            .await;

        assert_eq!(frames[0]["error"]["code"], -32601, "{method}");
    }
}

#[tokio::test]
async fn an_unknown_method_is_method_not_found_and_a_bad_frame_does_not_end_the_agent() {
    let mut harness = Harness::start(Vec::new()).await;
    harness.line(initialize()).await;

    let unknown = harness
        .line(json!({"jsonrpc": "2.0", "id": 3, "method": "session/teleport"}))
        .await;
    assert_eq!(unknown[0]["error"]["code"], -32601);

    let malformed = harness.agent.handle_line("{not json").await;
    assert_eq!(malformed[0]["error"]["code"], -32700);

    let headless = harness.agent.handle_line(r#"{"jsonrpc":"2.0"}"#).await;
    assert_eq!(headless[0]["error"]["code"], -32600);

    // Still serving: a refused frame is one frame, not the end of the connection.
    let after = harness.line(initialize()).await;
    assert_eq!(after[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
}

// ---------------------------------------------------------------------------
// session/new
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_new_starts_the_session_on_the_editors_cwd_and_advertises_its_modes() {
    let mut harness = Harness::start(open_replies()).await;
    harness.line(initialize()).await;

    let frames = harness.line(session_new()).await;
    let start = harness.sent("interactive.start");

    assert_eq!(start["params"]["provider"], "native");
    assert_eq!(start["params"]["workspace"], "/tmp/project");
    assert_eq!(start["params"]["approval_mode"], "prompt");
    assert!(
        start["params"]["id"]
            .as_str()
            .expect("a client-minted id")
            .starts_with("ouro-session-"),
        "the start id is this client's own durable key"
    );

    // Routed to the owner the start named, so a fleet session is not asked of this node.
    let subscribe = harness.sent("interactive.subscribe");
    assert_eq!(subscribe["params"]["node"], "ouroboros@host");
    assert_eq!(subscribe["params"]["cursor"], 0);

    let result = &frames[0]["result"];
    assert_eq!(result["sessionId"], start["params"]["id"]);
    assert_eq!(result["modes"]["currentModeId"], "prompt");

    let ids: Vec<&str> = result["modes"]["availableModes"]
        .as_array()
        .expect("modes")
        .iter()
        .map(|mode| mode["id"].as_str().expect("an id"))
        .collect();

    assert_eq!(
        ids,
        ["plan", "prompt", "auto_edit", "auto_approve", "default"]
    );
}

#[tokio::test]
async fn a_relative_cwd_is_refused_before_anything_is_started() {
    let mut harness = Harness::start(open_replies()).await;
    harness.line(initialize()).await;

    let frames = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/new",
            "params": {"cwd": "project", "mcpServers": []}
        }))
        .await;

    assert_eq!(frames[0]["error"]["code"], -32602);
    harness.nothing_sent("interactive.start");
}

#[tokio::test]
async fn a_gateway_missing_a_verb_refuses_session_new_rather_than_half_starting() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        // Everything except the send verb.
        peer.hello(&[
            "interactive.start",
            "interactive.info",
            "interactive.subscribe",
            "interactive.replay",
            "interactive.interrupt",
            "interactive.respond_approval",
        ])
        .await;

        while peer.request().await.is_some() {}
    });

    let connected = transport::connect(config(address), Arc::new(NoReconnectHook))
        .await
        .expect("a handshake");
    let mut agent = Agent::new(connected.client, connected.hello, options());

    assert_eq!(agent.unserved(), vec!["interactive.send_message"]);

    agent
        .handle_line(&serde_json::to_string(&initialize()).expect("encodable"))
        .await;
    let frames = agent
        .handle_line(&serde_json::to_string(&session_new()).expect("encodable"))
        .await;

    assert_eq!(frames[0]["error"]["code"], -32601);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("interactive.send_message"));

    script.abort();
}

// ---------------------------------------------------------------------------
// One turn, streamed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_prompt_streams_the_turn_and_resolves_with_end_turn() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;

    // The prompt itself is owed nothing yet: its answer is the turn's outcome.
    assert!(harness.prompt(2, "add a test").await.is_empty());

    let session = harness.session.clone();
    let sent = harness.sent("interactive.send_message");
    assert_eq!(sent["params"]["id"], session);
    assert_eq!(sent["params"]["input"], "add a test");
    assert!(sent["params"]["turn_id"]
        .as_str()
        .expect("a caller-minted turn id")
        .starts_with("ouro-acp-"));

    // Text deltas.
    assert_eq!(
        only_update(
            &harness
                .event(1, "output_text_delta", json!({"text": "Look"}))
                .await
        ),
        json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "Look"}})
    );
    assert_eq!(
        only_update(
            &harness
                .event(2, "output_text_delta", json!({"text": "ing"}))
                .await
        ),
        json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "ing"}})
    );

    // The final that follows deltas says nothing new; sending it again would double the
    // message the editor has already rendered.
    assert!(harness
        .event(3, "output_text_final", json!({"text": "Looking"}))
        .await
        .is_empty());

    assert_eq!(
        only_update(
            &harness
                .event(4, "thinking_delta", json!({"text": "hmm"}))
                .await
        ),
        json!({"sessionUpdate": "agent_thought_chunk", "content": {"type": "text", "text": "hmm"}})
    );

    // A tool call, its file edit, and its result.
    let call = only_update(
        &harness
            .event(
                5,
                "tool_call",
                json!({"call_id": "c1", "name": "edit", "input": {"path": "/tmp/project/a.rs"}}),
            )
            .await,
    );
    assert_eq!(call["sessionUpdate"], "tool_call");
    assert_eq!(call["toolCallId"], "c1");
    assert_eq!(call["kind"], "edit");
    assert_eq!(call["status"], "in_progress");
    assert_eq!(call["title"], "edit: /tmp/project/a.rs");
    assert_eq!(call["locations"], json!([{"path": "/tmp/project/a.rs"}]));

    let change = only_update(
        &harness
            .event(
                6,
                "file_change",
                json!({
                    "status": "completed",
                    "changes": [{
                        "path": "/tmp/project/a.rs",
                        "kind": "update",
                        "diff": "--- a/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n-old\n+new\n"
                    }]
                }),
            )
            .await,
    );
    assert_eq!(change["sessionUpdate"], "tool_call_update");
    assert_eq!(change["toolCallId"], "c1");
    assert_eq!(change["status"], "completed");
    assert_eq!(change["content"][0]["type"], "content");
    assert!(change["content"][0]["content"]["text"]
        .as_str()
        .expect("the patch")
        .contains("+new"));
    assert_eq!(change["locations"], json!([{"path": "/tmp/project/a.rs"}]));

    let result = only_update(
        &harness
            .event(
                7,
                "tool_result",
                json!({"call_id": "c1", "output": {"text": "applied"}, "is_error": false}),
            )
            .await,
    );
    assert_eq!(result["sessionUpdate"], "tool_call_update");
    assert_eq!(result["toolCallId"], "c1");
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["content"],
        json!([{"type": "content", "content": {"type": "text", "text": "applied"}}])
    );

    // A plan, with every field ACP declares required on an entry.
    let plan = only_update(
        &harness
            .event(
                8,
                "plan_updated",
                json!({"plan": [{"step": "write the test", "status": "in_progress"}]}),
            )
            .await,
    );
    assert_eq!(
        plan,
        json!({
            "sessionUpdate": "plan",
            "entries": [{
                "content": "write the test",
                "priority": "medium",
                "status": "in_progress"
            }]
        })
    );

    // The turn ends, and the prompt is finally answered.
    let ended = harness
        .event_for(
            9,
            "turn_completed",
            json!({"status": "completed"}),
            Some("harness-turn-1"),
            None,
        )
        .await;

    assert_eq!(
        ended,
        vec![json!({"jsonrpc": "2.0", "id": 2, "result": {"stopReason": "end_turn"}})]
    );
}

#[tokio::test]
async fn a_provider_that_only_finalises_still_reaches_the_editor() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;
    harness.prompt(2, "hello").await;

    assert_eq!(
        only_update(
            &harness
                .event(1, "output_text_final", json!({"text": "hi"}))
                .await
        ),
        json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "hi"}})
    );
}

#[tokio::test]
async fn an_untied_file_change_announces_its_own_tool_call_rather_than_vanishing() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;
    harness.prompt(2, "edit").await;

    let frames = harness
        .event(
            1,
            "file_change",
            json!({"changes": [{"path": "/tmp/project/b.rs", "kind": "add"}]}),
        )
        .await;

    assert_eq!(frames.len(), 2);
    let announced = &frames[0]["params"]["update"];
    assert_eq!(announced["sessionUpdate"], "tool_call");
    assert_eq!(announced["kind"], "edit");

    let updated = &frames[1]["params"]["update"];
    assert_eq!(updated["sessionUpdate"], "tool_call_update");
    assert_eq!(updated["toolCallId"], announced["toolCallId"]);
    assert_eq!(updated["locations"], json!([{"path": "/tmp/project/b.rs"}]));
}

#[tokio::test]
async fn a_failed_turn_is_an_error_and_never_a_stop_reason() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;
    harness.prompt(2, "break").await;

    let frames = harness
        .event_for(
            1,
            "turn_failed",
            json!({"error": "the model refused to stream"}),
            Some("harness-turn-1"),
            None,
        )
        .await;

    assert_eq!(frames[0]["id"], 2);
    assert_eq!(frames[0]["error"]["code"], -32603);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("the model refused to stream"));
    assert!(frames[0].get("result").is_none());
}

#[tokio::test]
async fn a_second_prompt_while_one_is_in_flight_is_refused() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;
    harness.prompt(2, "one").await;

    let frames = harness.prompt(3, "two").await;
    assert_eq!(frames[0]["error"]["code"], -32600);
}

#[tokio::test]
async fn a_content_block_the_handshake_said_would_not_be_read_is_refused() {
    let mut harness = Harness::start(open_replies()).await;
    harness.opened().await;

    let session = harness.session.clone();
    let frames = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/prompt",
            "params": {
                "sessionId": session,
                "prompt": [{"type": "image", "data": "aGk=", "mimeType": "image/png"}]
            }
        }))
        .await;

    assert_eq!(frames[0]["error"]["code"], -32602);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("promptCapabilities"));
    harness.nothing_sent("interactive.send_message");
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_approval_becomes_a_permission_request_and_the_editors_answer_reaches_the_runtime() {
    let mut harness =
        Harness::start(with_send(vec![("interactive.respond_approval", json!({}))])).await;

    harness.opened().await;
    harness.prompt(2, "run the tests").await;

    let session = harness.session.clone();

    // The call the question is about, announced first — exactly the order the runtime
    // emits them in.
    harness
        .event(
            1,
            "tool_call",
            json!({"call_id": "b1", "name": "bash", "input": {"command": "cargo test"}}),
        )
        .await;

    let frames = harness
        .event_for(
            2,
            "approval_requested",
            json!({
                "kind": "command",
                "tool_call": {"name": "bash", "command": "cargo test", "cwd": "/tmp/project"},
                "paths": [],
                "reason": "commands ask"
            }),
            Some("harness-turn-1"),
            Some("napp_1"),
        )
        .await;

    assert_eq!(frames.len(), 1);
    let request = frames[0].clone();
    assert_eq!(request["method"], "session/request_permission");
    assert_eq!(request["params"]["sessionId"], session);
    assert_eq!(request["params"]["toolCall"]["kind"], "execute");
    assert_eq!(request["params"]["toolCall"]["title"], "bash: cargo test");
    // The question attaches to the row the editor already drew, rather than inventing a
    // second one: the runtime's approval payload names a tool but not its call id, and the
    // call it is about is the one in flight.
    assert_eq!(request["params"]["toolCall"]["toolCallId"], "b1");

    let kinds: Vec<&str> = request["params"]["options"]
        .as_array()
        .expect("options")
        .iter()
        .map(|option| option["kind"].as_str().expect("a kind"))
        .collect();
    assert_eq!(
        kinds,
        ["allow_once", "allow_always", "reject_once", "reject_always"]
    );

    // The editor picks "allow for this session".
    let answered = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": {"outcome": {"outcome": "selected", "optionId": "allow_always"}}
        }))
        .await;
    assert!(answered.is_empty());

    let responded = harness.sent("interactive.respond_approval");
    assert_eq!(responded["params"]["id"], session);
    assert_eq!(responded["params"]["request_id"], "napp_1");
    assert_eq!(responded["params"]["response"]["decision"], "approve");
    assert_eq!(responded["params"]["response"]["scope"], "session");
}

#[tokio::test]
async fn an_editor_that_cancels_a_permission_request_is_a_denial() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push(("interactive.respond_approval", json!({})));
        replies
    })
    .await;

    harness.opened().await;

    let frames = harness
        .event_for(
            1,
            "approval_requested",
            json!({"kind": "command", "tool_call": {"name": "bash", "command": "rm -rf /"}}),
            None,
            Some("napp_2"),
        )
        .await;

    let id = frames[0]["id"].clone();
    harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"outcome": {"outcome": "cancelled"}}
        }))
        .await;

    let responded = harness.sent("interactive.respond_approval");
    assert_eq!(responded["params"]["response"]["decision"], "deny");
    assert_eq!(responded["params"]["response"]["scope"], "once");
}

#[tokio::test]
async fn a_plan_exit_carries_the_runtimes_own_options_and_answers_with_the_choice() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push(("interactive.respond_approval", json!({})));
        replies
    })
    .await;

    harness.opened().await;

    let frames = harness
        .event_for(
            1,
            "approval_requested",
            json!({
                "kind": "plan_exit",
                "header": "Plan ready",
                "question": "This session has been planning. Ready to build it?",
                "plan_source": "plan_tool",
                "options": [
                    {"optionId": "auto_edit", "name": "Yes, auto-accept edits", "kind": "allow_always"},
                    {"optionId": "prompt", "name": "Yes, manual approvals", "kind": "allow_once"},
                    {"optionId": "keep_planning", "name": "No, keep planning", "kind": "reject_once"}
                ]
            }),
            None,
            Some("plan_exit_abc"),
        )
        .await;

    // The runtime's own rows travel through unchanged: an editor shows the labels the
    // runtime wrote, not four generic ones this bridge invented.
    assert_eq!(
        frames[0]["params"]["options"],
        json!([
            {"optionId": "auto_edit", "name": "Yes, auto-accept edits", "kind": "allow_always"},
            {"optionId": "prompt", "name": "Yes, manual approvals", "kind": "allow_once"},
            {"optionId": "keep_planning", "name": "No, keep planning", "kind": "reject_once"}
        ])
    );

    let id = frames[0]["id"].clone();
    harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"outcome": {"outcome": "selected", "optionId": "auto_edit"}}
        }))
        .await;

    let responded = harness.sent("interactive.respond_approval");
    assert_eq!(responded["params"]["request_id"], "plan_exit_abc");
    assert_eq!(responded["params"]["response"]["decision"], "approve");
    assert_eq!(
        responded["params"]["response"]["provider_options"],
        json!({"choice": "auto_edit"})
    );

    // The mode really moved, and the runtime says so — which is where the editor's
    // `current_mode_update` comes from.
    let update = only_update(
        &harness
            .event(
                2,
                "provider_event",
                json!({
                    "kind": "plan_exit",
                    "choice": "auto_edit",
                    "approval_mode": "auto_edit",
                    "plan": false,
                    "applied": true
                }),
            )
            .await,
    );
    assert_eq!(
        update,
        json!({"sessionUpdate": "current_mode_update", "currentModeId": "auto_edit"})
    );
}

#[tokio::test]
async fn a_plan_exit_the_runtime_could_not_apply_announces_no_mode_change() {
    let mut harness = Harness::start(open_replies()).await;
    harness.opened().await;

    let frames = harness
        .event(
            1,
            "provider_event",
            json!({
                "kind": "plan_exit",
                "choice": "auto_edit",
                "approval_mode": "prompt",
                "plan": true,
                "applied": false
            }),
        )
        .await;

    assert!(frames.is_empty());
}

#[tokio::test]
async fn a_questions_string_options_become_answers_carried_as_the_reason() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push(("interactive.respond_approval", json!({})));
        replies
    })
    .await;

    harness.opened().await;

    let frames = harness
        .event_for(
            1,
            "approval_requested",
            json!({
                "kind": "question",
                "question": "Which database?",
                "header": "Choose one",
                "options": ["postgres", "sqlite"]
            }),
            None,
            Some("napp_q"),
        )
        .await;

    let options = frames[0]["params"]["options"]
        .as_array()
        .expect("options")
        .clone();
    assert_eq!(options[0]["name"], "postgres");
    assert_eq!(options[1]["name"], "sqlite");
    // A question with only answers would be one nobody can decline.
    assert_eq!(options[2]["kind"], "reject_once");

    let id = frames[0]["id"].clone();
    let chosen = options[1]["optionId"].clone();
    harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"outcome": {"outcome": "selected", "optionId": chosen}}
        }))
        .await;

    let responded = harness.sent("interactive.respond_approval");
    assert_eq!(responded["params"]["response"]["decision"], "approve");
    assert_eq!(responded["params"]["response"]["reason"], "sqlite");
}

// ---------------------------------------------------------------------------
// Cancel and modes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancel_interrupts_the_turn_and_the_prompt_answers_cancelled() {
    let mut harness = Harness::start(with_send(vec![("interactive.interrupt", json!({}))])).await;
    harness.opened().await;
    harness.prompt(2, "long job").await;

    let session = harness.session.clone();
    let answered = harness
        .line(json!({
            "jsonrpc": "2.0",
            "method": "session/cancel",
            "params": {"sessionId": session}
        }))
        .await;
    assert!(answered.is_empty(), "a notification is never answered");

    let interrupt = harness.sent("interactive.interrupt");
    assert_eq!(interrupt["params"]["id"], session);

    // Even a `turn_completed` that lands after the cancel is the cancellation the editor
    // is waiting on — and never a JSON-RPC error, which ACP forbids here.
    let frames = harness
        .event_for(
            1,
            "turn_completed",
            json!({"status": "completed"}),
            Some("harness-turn-1"),
            None,
        )
        .await;

    assert_eq!(
        frames,
        vec![json!({"jsonrpc": "2.0", "id": 2, "result": {"stopReason": "cancelled"}})]
    );
}

#[tokio::test]
async fn set_mode_configures_the_session_and_a_mode_never_advertised_is_refused() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push((
            "interactive.configure",
            json!({"options": {"approval_mode": "auto_edit"}, "applies": "next_turn"}),
        ));
        replies
    })
    .await;

    harness.opened().await;
    let session = harness.session.clone();

    let frames = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "session/set_mode",
            "params": {"sessionId": session, "modeId": "auto_edit"}
        }))
        .await;

    assert_eq!(frames[0], json!({"jsonrpc": "2.0", "id": 4, "result": {}}));

    let configured = harness.sent("interactive.configure");
    assert_eq!(configured["params"]["id"], session);
    assert_eq!(configured["params"]["approval_mode"], "auto_edit");
    // The session was not planning, so no `plan` key is sent: a key the transport would
    // refuse is not one to send on a hunch.
    assert!(configured["params"].get("plan").is_none());

    // A mode this session never advertised never reaches the runtime.
    let refused = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "session/set_mode",
            "params": {"sessionId": session, "modeId": "architect"}
        }))
        .await;

    assert_eq!(refused[0]["error"]["code"], -32602);
    assert!(refused[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("provider native"));
}

#[tokio::test]
async fn a_configure_the_runtime_refuses_is_relayed_rather_than_swallowed() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push((
            "interactive.configure",
            json!({"__error": {
                "code": -32006,
                "message": "the plane refused",
                "data": ["unconfigurable_session", {"reason": "no_dynamic_configuration"}]
            }}),
        ));
        replies
    })
    .await;

    harness.opened().await;
    let session = harness.session.clone();

    let frames = harness
        .line(json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "session/set_mode",
            "params": {"sessionId": session, "modeId": "auto_approve"}
        }))
        .await;

    assert_eq!(frames[0]["error"]["code"], -32603);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("no_dynamic_configuration"));
}

#[tokio::test]
async fn a_configured_status_event_becomes_a_current_mode_update() {
    let mut harness = Harness::start(open_replies()).await;
    harness.opened().await;

    let update = only_update(
        &harness
            .event(
                1,
                "status",
                json!({
                    "kind": "configured",
                    "applies": "next_turn",
                    "changed": {"approval_mode": "auto_approve"}
                }),
            )
            .await,
    );

    assert_eq!(
        update,
        json!({"sessionUpdate": "current_mode_update", "currentModeId": "auto_approve"})
    );
}

// ---------------------------------------------------------------------------
// Resync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_out_of_order_event_is_held_until_the_gap_under_it_is_replayed() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push((
            "interactive.replay",
            json!([
                {"id": "e1", "sequence": 1, "type": "output_text_delta",
                 "timestamp": "t", "payload": {"text": "one "}},
                {"id": "e2", "sequence": 2, "type": "output_text_delta",
                 "timestamp": "t", "payload": {"text": "two "}}
            ]),
        ));
        replies
    })
    .await;

    harness.opened().await;

    // Sequence 3 with nothing under it: nothing may be emitted before 1 and 2.
    let frames = harness
        .event(3, "output_text_delta", json!({"text": "three"}))
        .await;

    let texts: Vec<&str> = frames
        .iter()
        .map(|frame| {
            frame["params"]["update"]["content"]["text"]
                .as_str()
                .expect("text")
        })
        .collect();

    assert_eq!(texts, ["one ", "two ", "three"]);

    let replay = harness.sent("interactive.replay");
    assert_eq!(replay["params"]["cursor"], 0);
    assert_eq!(replay["params"]["limit"], 500);
}

#[tokio::test]
async fn a_lagged_stream_replays_from_the_contiguous_high_water_mark() {
    let mut harness = Harness::start({
        let mut replies = open_replies();
        replies.push((
            "interactive.replay",
            json!([{"id": "e1", "sequence": 1, "type": "output_text_delta",
                    "timestamp": "t", "payload": {"text": "recovered"}}]),
        ));
        replies
    })
    .await;

    harness.opened().await;
    let session = harness.session.clone();

    let frames = harness
        .notify(
            "stream.lagged",
            json!({"id": session, "plane": "interactive", "dropped": 12}),
        )
        .await;

    assert_eq!(
        only_update(&frames)["content"]["text"],
        Value::String("recovered".into())
    );
    assert_eq!(harness.sent("interactive.replay")["params"]["cursor"], 0);
}

#[tokio::test]
async fn a_stream_that_ends_before_the_turn_does_resolves_the_prompt_as_unobserved() {
    let mut harness = Harness::start(with_send(Vec::new())).await;
    harness.opened().await;
    harness.prompt(2, "work").await;

    let session = harness.session.clone();
    let frames = harness
        .notify(
            "stream.ended",
            json!({"id": session, "plane": "interactive", "status": "unknown"}),
        )
        .await;

    assert_eq!(frames[0]["id"], 2);
    assert_eq!(frames[0]["error"]["code"], -32603);
    assert!(frames[0]["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("was not observed"));
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// The editor's end of a duplex pair, plus the gateway script and the running loop.
struct Loop {
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    reader: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    methods: mpsc::UnboundedReceiver<String>,
    running: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Loop {
    /// A running `ouro acp` loop over a duplex pair, and a gateway script behind it.
    async fn start() -> Self {
        let (listen, address) = listener().await;
        let (sender, methods) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut peer = Peer::accept(&listen).await;
            peer.hello(METHODS).await;

            while let Some(request) = peer.request().await {
                let method = request["method"].as_str().unwrap_or_default().to_string();
                let _ = sender.send(method.clone());

                let reply = match method.as_str() {
                    "interactive.start" => json!({
                        "id": request["params"]["id"].clone(),
                        "outcome": "created",
                        "ready": true
                    }),
                    "interactive.info" => json!({"provider": "native", "status": "idle"}),
                    "interactive.subscribe" => json!([]),
                    "interactive.send_message" => accepted(),
                    _other => json!({}),
                };

                peer.result(&request["id"], reply).await;
            }
        });

        let connected = transport::connect(config(address), Arc::new(NoReconnectHook))
            .await
            .expect("a handshake");
        let agent = Agent::new(connected.client, connected.hello, options());

        let (editor_side, agent_side) = tokio::io::duplex(8 * 1024 * 1024);
        let (agent_read, agent_write) = tokio::io::split(agent_side);
        let (editor_read, editor_write) = tokio::io::split(editor_side);

        let running = tokio::spawn(ouro::acp_serve::run(
            agent,
            agent_read,
            agent_write,
            connected.notifications,
        ));

        Self {
            writer: editor_write,
            reader: BufReader::new(editor_read),
            methods,
            running,
        }
    }

    async fn send(&mut self, frame: Value) {
        let mut bytes = serde_json::to_vec(&frame).expect("encodable");
        bytes.push(b'\n');
        self.raw(&bytes).await;
    }

    async fn raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("a live agent");
        self.writer.flush().await.expect("a live agent");
    }

    async fn frame(&mut self) -> Value {
        let mut line = String::new();

        tokio::time::timeout(PATIENCE, self.reader.read_line(&mut line))
            .await
            .expect("a frame in time")
            .expect("a readable agent");

        serde_json::from_str(&line).unwrap_or_else(|error| panic!("{error}: {line:?}"))
    }

    /// stdin EOF, which is what closing an editor looks like to the agent. The read half
    /// stays open, because the agent's last words are still to come.
    async fn close_stdin(&mut self) {
        self.writer.shutdown().await.expect("a closable pipe");
    }

    /// Waits until the gateway has actually been sent `method`.
    async fn awaited(&mut self, method: &str) {
        let mut seen = Vec::new();

        while !seen.iter().any(|name| name == method) {
            let name = tokio::time::timeout(PATIENCE, self.methods.recv())
                .await
                .unwrap_or_else(|_elapsed| panic!("no {method} in time; saw {seen:?}"))
                .expect("a live script");
            seen.push(name);
        }
    }

    fn sent(&mut self) -> Vec<String> {
        let mut seen = Vec::new();

        while let Ok(method) = self.methods.try_recv() {
            seen.push(method);
        }

        seen
    }

    async fn ended(self) {
        tokio::time::timeout(Duration::from_secs(10), self.running)
            .await
            .expect("the loop ended")
            .expect("no panic")
            .expect("a clean end");
    }
}

#[tokio::test]
async fn stdin_eof_mid_turn_interrupts_and_says_so_before_it_exits() {
    let mut driver = Loop::start().await;

    driver.send(initialize()).await;
    assert_eq!(
        driver.frame().await["result"]["protocolVersion"],
        PROTOCOL_VERSION
    );

    driver.send(session_new()).await;
    let session = driver.frame().await["result"]["sessionId"]
        .as_str()
        .expect("a session id")
        .to_string();

    driver
        .send(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/prompt",
            "params": {"sessionId": session, "prompt": [{"type": "text", "text": "long job"}]}
        }))
        .await;

    // The turn really is in flight when stdin closes, rather than only having been typed.
    driver.awaited("interactive.send_message").await;
    driver.close_stdin().await;

    // The last word, then the cancellation — in that order, because an editor that has
    // seen the result may stop rendering updates for the turn.
    let notice = driver.frame().await;
    assert_eq!(notice["method"], "session/update");
    assert_eq!(notice["params"]["sessionId"], session);
    assert!(notice["params"]["update"]["content"]["text"]
        .as_str()
        .expect("a sentence")
        .contains("interrupted this turn"));

    let answer = driver.frame().await;
    assert_eq!(answer["id"], 2);
    assert_eq!(answer["result"]["stopReason"], "cancelled");

    driver.awaited("interactive.interrupt").await;
    driver.ended().await;
}

#[tokio::test]
async fn a_frame_above_the_ceiling_is_refused_and_the_loop_ends_rather_than_desynchronising() {
    let mut driver = Loop::start().await;

    driver.send(initialize()).await;
    assert_eq!(
        driver.frame().await["result"]["protocolVersion"],
        PROTOCOL_VERSION
    );

    // Well past the ceiling: the reader refuses once its buffer crosses it, so an
    // overshoot smaller than one read chunk could still arrive as a whole line.
    let oversized: Vec<u8> = std::iter::repeat_n(b'x', MAX_LINE_BYTES + 1024 * 1024).collect();
    driver.raw(&oversized).await;
    driver.raw(b"\n").await;

    let refusal = driver.frame().await;
    assert_eq!(refusal["error"]["code"], -32600);
    assert!(refusal["error"]["message"]
        .as_str()
        .expect("a message")
        .contains("ceiling"));

    // Nothing was started, so the shutdown has nothing to interrupt and the loop just ends.
    assert!(!driver.sent().iter().any(|m| m == "interactive.interrupt"));
    driver.ended().await;
}

// ---------------------------------------------------------------------------
// The pure mapping
// ---------------------------------------------------------------------------

#[test]
fn tool_kinds_come_from_the_name_and_never_from_a_guess() {
    for (name, kind) in [
        ("read", "read"),
        ("Write", "edit"),
        ("apply_patch", "edit"),
        ("bash", "execute"),
        ("grep", "search"),
        ("web_fetch", "fetch"),
        ("plan", "think"),
        ("mcp__acme__deploy", "other"),
    ] {
        assert_eq!(tool_kind(name, &json!({})), kind, "{name}");
    }

    // An ACP-transport session forwards the hosted agent's own kind, and it wins.
    assert_eq!(
        tool_kind("anything", &json!({"tool_kind": "switch_mode"})),
        "switch_mode"
    );
    // `kind` alone is not read as a tool kind: the gateway's own payloads put an approval
    // classification there, and reading it as ACP's taxonomy would mislabel a call.
    assert_eq!(
        tool_kind("anything", &json!({"kind": "permissions"})),
        "other"
    );
}

#[test]
fn stop_reasons_are_read_from_the_payload_and_default_to_end_turn() {
    for (payload, reason) in [
        (json!({"status": "completed"}), StopReason::EndTurn),
        (
            json!({"stop_reason": "max_turns"}),
            StopReason::MaxTurnRequests,
        ),
        (json!({"stopReason": "refusal"}), StopReason::Refusal),
        (json!({"reason": "max_tokens"}), StopReason::MaxTokens),
        (json!({"stopReason": "cancelled"}), StopReason::Cancelled),
    ] {
        assert_eq!(completed_stop_reason(&payload), reason, "{payload}");
    }
}

#[test]
fn a_prompt_is_text_and_workspace_paths_and_nothing_else() {
    assert_eq!(
        prompt_input(&[
            json!({"type": "text", "text": "one"}),
            json!({"type": "text", "text": "two"})
        ])
        .expect("two text blocks"),
        Value::String("one\n\ntwo".into())
    );

    assert_eq!(
        prompt_input(&[
            json!({"type": "text", "text": "look at"}),
            json!({"type": "resource_link", "name": "a.rs", "uri": "file:///tmp/my%20project/a.rs"})
        ])
        .expect("a link"),
        json!({"prompt": "look at", "attachments": ["/tmp/my project/a.rs"]})
    );

    for block in [
        json!({"type": "resource_link", "name": "x", "uri": "https://example.com/x"}),
        json!({"type": "audio", "data": "aGk=", "mimeType": "audio/wav"}),
        json!({"type": "resource", "resource": {"uri": "file:///x", "text": "x"}}),
    ] {
        assert!(
            prompt_input(std::slice::from_ref(&block)).is_err(),
            "{block}"
        );
    }

    assert!(prompt_input(&[]).is_err());
}

#[test]
fn modes_are_offered_only_where_the_runtime_would_not_refuse_them() {
    let full = json!({"dynamic_configuration": "native", "approvals": "native"});
    let ids: Vec<String> = modes_for("native", Some(&full), false)
        .into_iter()
        .map(|mode| mode.id)
        .collect();
    assert_eq!(
        ids,
        ["plan", "prompt", "auto_edit", "auto_approve", "default"]
    );

    // No approvals channel: `prompt` is the mode `interactive.start`/`configure` refuse
    // with `["unsupported_approval_mode", …]`, so it is not offered.
    let no_approvals = json!({"dynamic_configuration": "managed", "approvals": false});
    let ids: Vec<String> = modes_for("claude", Some(&no_approvals), false)
        .into_iter()
        .map(|mode| mode.id)
        .collect();
    assert_eq!(ids, ["auto_edit", "auto_approve", "default"]);

    // The ACP transport declares no dynamic configuration at all, so it gets no modes —
    // and `plan` is not offered for a provider whose plan mode is not settable mid-session.
    let acp = json!({"transport": "acp", "dynamic_configuration": false, "approvals": "native"});
    assert!(modes_for("opencode", Some(&acp), false).is_empty());

    // A session that *is* planning may always be offered the way out of it.
    let ids: Vec<String> = modes_for("opencode", Some(&acp), true)
        .into_iter()
        .map(|mode| mode.id)
        .collect();
    assert_eq!(ids, ["plan"]);

    // No capabilities read at all: nothing but the one mode a provider table proves.
    assert!(modes_for("native", None, false)
        .iter()
        .all(|mode| mode.id == "plan"));
}

#[test]
fn only_a_configured_status_event_names_a_mode() {
    assert_eq!(
        configured_mode(&json!({"kind": "configured", "changed": {"approval_mode": "prompt"}})),
        Some("prompt".to_string())
    );
    assert_eq!(
        configured_mode(&json!({"kind": "configured", "changed": {"plan": true}})),
        Some("plan".to_string())
    );
    assert_eq!(
        configured_mode(&json!({"kind": "configured", "changed": {"model": "gpt-5"}})),
        None
    );
    assert_eq!(configured_mode(&json!({"kind": "other"})), None);
}
