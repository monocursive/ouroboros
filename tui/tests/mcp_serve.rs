//! `ouro mcp-serve` driven as the two things it actually is: an MCP server on one side
//! and a gateway client on the other.
//!
//! The MCP half is exercised message by message through `Server::handle_line`, so the
//! frames these tests assert on are the bytes Claude Code would read. The gateway half
//! runs against `support::Peer`, the same scripted peer the transport and UI tests use, so
//! the handshake, the correlation, and the reconnect are the real ones.
//!
//! The property every test here is really about is the same one: an `allow` comes from a
//! runtime that said `allow`, and nothing else in this module can produce one.

mod support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::net::TcpListener;

use ouro::mcp_serve::{Bridge, Server, APPROVAL_METHOD, PROTOCOL_VERSION, TOOL_NAME};

use support::{listener, Peer, TOKEN};

const SESSION: &str = "s-mcp-1";

static TOKEN_FILES: AtomicU32 = AtomicU32::new(0);

/// The gateway refuses a token file that is not a private regular file at 0600, and
/// `read_token` refuses to read one — which is the posture this bridge inherits rather
/// than works around.
fn token_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ouro-mcp-serve-token-{}-{}",
        std::process::id(),
        TOKEN_FILES.fetch_add(1, Ordering::Relaxed)
    ));

    fs::write(&path, TOKEN).expect("a writable temp dir");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("a chmodable file");

    path
}

fn bridge(addr: SocketAddr, timeout: Duration) -> Bridge {
    Bridge {
        addr,
        token_file: token_file(),
        session_id: SESSION.to_string(),
        node: Some("ouroboros@host".to_string()),
        timeout,
    }
}

fn server(addr: SocketAddr, timeout: Duration) -> Server {
    Server::new(Ok(bridge(addr, timeout)))
}

fn call(tool_name: &str, input: Value) -> String {
    frame(json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": TOOL_NAME,
            "arguments": {"tool_name": tool_name, "input": input, "tool_use_id": "toolu_1"}
        }
    }))
}

fn frame(value: Value) -> String {
    serde_json::to_string(&value).expect("encodable")
}

fn decode(line: &str) -> Value {
    serde_json::from_str(line).expect("a JSON frame")
}

/// The behaviour object out of the text content block, which is where the contract puts
/// it: one text block whose body is the JSON `canUseTool` answer.
fn behavior(response: &Value) -> Value {
    let content = &response["result"]["content"][0];
    assert_eq!(content["type"], "text");

    serde_json::from_str(content["text"].as_str().expect("text")).expect("a JSON behaviour object")
}

/// Answers one `interactive.request_approval`, asserting the params on the way past.
async fn answer_one(peer: &mut Peer, answer: Value) -> Value {
    peer.hello(&[APPROVAL_METHOD]).await;
    let request = peer.request_for(APPROVAL_METHOD).await;
    peer.result(&request["id"], answer).await;

    request
}

#[tokio::test]
async fn the_handshake_and_the_tool_it_advertises() {
    let (listen, address) = listener().await;
    drop(listen);
    let mut server = server(address, Duration::from_millis(200));

    let initialize = decode(
        &server
            .handle_line(&frame(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "claude-code", "version": "2.1.0"}
                }
            })))
            .await
            .expect("a response to initialize"),
    );

    assert_eq!(initialize["jsonrpc"], "2.0");
    assert_eq!(initialize["id"], 1);
    // The client named a revision, so that is the one both sides speak.
    assert_eq!(initialize["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(initialize["result"]["serverInfo"]["name"], "ouroboros");
    assert!(initialize["result"]["capabilities"]["tools"].is_object());

    // A client that names none gets this build's own revision, from the current spec.
    let defaulted = decode(
        &server
            .handle_line(&frame(
                json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}),
            ))
            .await
            .expect("a response"),
    );

    assert_eq!(defaulted["result"]["protocolVersion"], PROTOCOL_VERSION);

    // A notification is acted on and never answered.
    assert!(server
        .handle_line(&frame(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        ))
        .await
        .is_none());

    let listed = decode(
        &server
            .handle_line(&frame(
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
            ))
            .await
            .expect("a response"),
    );

    let tools = listed["result"]["tools"].as_array().expect("a tool array");
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], TOOL_NAME);
    assert_eq!(tools[0]["inputSchema"]["type"], "object");
    assert_eq!(
        tools[0]["inputSchema"]["properties"]["tool_name"]["type"],
        "string"
    );
    assert_eq!(
        tools[0]["inputSchema"]["properties"]["input"]["type"],
        "object"
    );
    assert!(tools[0]["inputSchema"]["properties"]["tool_use_id"].is_object());

    let pong = decode(
        &server
            .handle_line(&frame(json!({"jsonrpc": "2.0", "id": 4, "method": "ping"})))
            .await
            .expect("a response"),
    );

    assert_eq!(pong["result"], json!({}));

    let unknown = decode(
        &server
            .handle_line(&frame(
                json!({"jsonrpc": "2.0", "id": 5, "method": "resources/list"}),
            ))
            .await
            .expect("a response"),
    );

    assert_eq!(unknown["error"]["code"], -32601);

    let garbage = decode(&server.handle_line("{not json").await.expect("a response"));
    assert_eq!(garbage["error"]["code"], -32700);
    assert_eq!(garbage["id"], Value::Null);
}

#[tokio::test]
async fn an_allow_is_the_runtime_saying_allow() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        let request = answer_one(
            &mut peer,
            json!({"decision": "allow", "request_id": "r-1", "source": "human", "reason": null}),
        )
        .await;

        // A second question rides the same connection: one handshake for the server's
        // lifetime is the point of holding the client.
        let second = peer.request_for(APPROVAL_METHOD).await;
        peer.result(
            &second["id"],
            json!({"decision": "allow", "request_id": "r-2", "source": "engine", "reason": "Read(**)"}),
        )
        .await;

        (request, second)
    });

    let mut server = server(address, Duration::from_secs(5));
    let input = json!({"file_path": "lib/a.ex", "content": "x"});

    let first = decode(
        &server
            .handle_line(&call("Write", input.clone()))
            .await
            .expect("a response"),
    );
    assert_eq!(first["result"]["isError"], false);
    assert_eq!(
        behavior(&first),
        json!({"behavior": "allow", "updatedInput": input})
    );

    let second = decode(
        &server
            .handle_line(&call("Read", json!({})))
            .await
            .expect("a response"),
    );
    assert_eq!(behavior(&second)["behavior"], "allow");

    let (request, _second) = script.await.expect("the script");

    // What the runtime was actually asked. `cwd` is the bridge's own contribution and is
    // the directory the tool would run in.
    assert_eq!(request["params"]["id"], SESSION);
    assert_eq!(request["params"]["node"], "ouroboros@host");
    assert_eq!(request["params"]["request"]["tool_name"], "Write");
    assert_eq!(request["params"]["request"]["input"], input);
    assert_eq!(request["params"]["request"]["tool_use_id"], "toolu_1");
    assert!(request["params"]["request"]["cwd"].is_string());
}

#[tokio::test]
async fn a_denial_carries_the_reason_back_to_the_agent() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        answer_one(
            &mut peer,
            json!({
                "decision": "deny",
                "request_id": "r-3",
                "source": "human",
                "reason": "not in this workspace"
            }),
        )
        .await
    });

    let mut server = server(address, Duration::from_secs(5));
    let response = decode(
        &server
            .handle_line(&call("Bash", json!({"command": "rm -rf ."})))
            .await
            .expect("a response"),
    );

    let behavior = behavior(&response);
    assert_eq!(behavior["behavior"], "deny");
    assert!(behavior["updatedInput"].is_null());

    let message = behavior["message"].as_str().expect("a message");
    assert!(message.contains("not in this workspace"), "{message}");
    assert!(message.contains("human"), "{message}");

    script.await.expect("the script");
}

#[tokio::test]
async fn a_decision_this_build_cannot_read_is_a_denial() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        answer_one(&mut peer, json!({"decision": "maybe later"})).await
    });

    let mut server = server(address, Duration::from_secs(5));
    let response = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );

    assert_eq!(behavior(&response)["behavior"], "deny");
    script.await.expect("the script");
}

#[tokio::test]
async fn a_runtime_that_never_answers_is_a_denial_naming_the_deadline() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[APPROVAL_METHOD]).await;
        let _asked = peer.request_for(APPROVAL_METHOD).await;
        // And then nothing, which is a person who walked away.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let mut server = server(address, Duration::from_millis(150));
    let response = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );

    let behavior = behavior(&response);
    assert_eq!(behavior["behavior"], "deny");
    assert!(
        behavior["message"]
            .as_str()
            .expect("a message")
            .contains("no decision within 150ms"),
        "{behavior}"
    );

    script.abort();
}

#[tokio::test]
async fn a_gateway_that_refuses_the_call_is_a_denial_that_says_so() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[APPROVAL_METHOD]).await;
        let asked = peer.request_for(APPROVAL_METHOD).await;
        peer.error(&asked["id"], -32007, "session not found", None)
            .await;
    });

    let mut server = server(address, Duration::from_secs(5));
    let response = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );

    let behavior = behavior(&response);
    assert_eq!(behavior["behavior"], "deny");
    assert!(
        behavior["message"]
            .as_str()
            .expect("a message")
            .contains("session not found"),
        "{behavior}"
    );

    script.await.expect("the script");
}

#[tokio::test]
async fn no_runtime_at_all_is_a_denial() {
    // Bind and release, so the address is one nothing is listening on.
    let listen = TcpListener::bind(("127.0.0.1", 0)).await.expect("a port");
    let address = listen.local_addr().expect("an address");
    drop(listen);

    let mut server = server(address, Duration::from_secs(5));
    let response = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );

    let behavior = behavior(&response);
    assert_eq!(behavior["behavior"], "deny");
    assert!(
        behavior["message"]
            .as_str()
            .expect("a message")
            .contains("Ouroboros could not ask"),
        "{behavior}"
    );
}

#[tokio::test]
async fn a_dropped_connection_is_reopened_exactly_once() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&listen).await;
        first.hello(&[APPROVAL_METHOD]).await;
        let asked = first.request_for(APPROVAL_METHOD).await;
        first
            .result(
                &asked["id"],
                json!({"decision": "allow", "request_id": "r-4"}),
            )
            .await;

        // The runtime went away between one question and the next.
        drop(first);

        let mut second = Peer::accept(&listen).await;
        second.hello(&[APPROVAL_METHOD]).await;
        let asked = second.request_for(APPROVAL_METHOD).await;
        second
            .result(
                &asked["id"],
                json!({"decision": "deny", "request_id": "r-5", "source": "timeout"}),
            )
            .await;
    });

    let mut server = server(address, Duration::from_secs(5));

    let first = decode(
        &server
            .handle_line(&call("Read", json!({})))
            .await
            .expect("a response"),
    );
    assert_eq!(behavior(&first)["behavior"], "allow");

    let second = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );
    assert_eq!(behavior(&second)["behavior"], "deny");

    script.await.expect("the script");
}

#[tokio::test]
async fn a_malformed_call_is_a_denial_rather_than_a_guess() {
    let (listen, address) = listener().await;
    drop(listen);
    let mut server = server(address, Duration::from_millis(200));

    let cases = [
        json!({"name": TOOL_NAME, "arguments": {}}),
        json!({"name": TOOL_NAME, "arguments": {"tool_name": "  "}}),
        json!({"name": TOOL_NAME, "arguments": {"tool_name": "Write", "input": "a string"}}),
        json!({"name": TOOL_NAME, "arguments": "not an object"}),
        json!({"name": TOOL_NAME}),
    ];

    for params in cases {
        let response = decode(
            &server
                .handle_line(&frame(json!({
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": params
                })))
                .await
                .expect("a response"),
        );

        assert_eq!(behavior(&response)["behavior"], "deny", "{response}");
    }

    // A tool this server does not serve is a misconfiguration, not a permission
    // decision, so it is a protocol error rather than a denial the model reads.
    let unknown = decode(
        &server
            .handle_line(&frame(json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "diagnostics", "arguments": {}}
            })))
            .await
            .expect("a response"),
    );

    assert_eq!(unknown["error"]["code"], -32602);
}

#[tokio::test]
async fn a_bridge_with_no_runtime_to_ask_denies_and_says_it_was_run_by_hand() {
    let mut server = Server::new(Err("OUROBOROS_GATEWAY_ADDR is not set".to_string()));

    let response = decode(
        &server
            .handle_line(&call("Write", json!({})))
            .await
            .expect("a response"),
    );
    let behavior = behavior(&response);

    assert_eq!(behavior["behavior"], "deny");
    let message = behavior["message"].as_str().expect("a message");
    assert!(message.contains("OUROBOROS_GATEWAY_ADDR"), "{message}");
    assert!(message.contains("not by hand"), "{message}");

    // The MCP surface still works, so a harness that spawned this by mistake gets a
    // legible refusal per call instead of a server that would not start.
    assert!(server
        .handle_line(&frame(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        ))
        .await
        .is_some());
}
