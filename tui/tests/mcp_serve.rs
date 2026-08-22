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

use ouro::mcp_serve::{
    Bridge, Server, APPROVAL_METHOD, CODE_INTEL_TOOL, DIAGNOSTICS_METHOD, DIAGNOSTICS_TOOL,
    INFO_METHOD, PROTOCOL_VERSION, REQUEST_METHOD, TOOL_NAME, TOUCH_METHOD, TOUCH_TOOL,
};

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
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("a name"))
        .collect();

    // One tool for the harness and three for the model. The permission prompt is first
    // because it is the one `--permission-prompt-tool` is pointed at by name.
    assert_eq!(
        names,
        vec![TOOL_NAME, CODE_INTEL_TOOL, DIAGNOSTICS_TOOL, TOUCH_TOOL]
    );
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
                "params": {"name": "rename_everything", "arguments": {}}
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

// ---------------------------------------------------------------------------
// The three code-intelligence tools (E3)
// ---------------------------------------------------------------------------

const WORKSPACE: &str = "/work/repo";

fn tool_call(name: &str, arguments: Value) -> String {
    frame(json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    }))
}

/// The text a model would read out of a tool result.
fn text(response: &Value) -> String {
    let content = &response["result"]["content"][0];
    assert_eq!(content["type"], "text", "{response}");

    content["text"].as_str().expect("text").to_string()
}

fn failed(response: &Value) -> bool {
    response["result"]["isError"] == json!(true)
}

/// A path only means something inside a workspace, and the session is what knows which.
async fn answer_info(peer: &mut Peer) -> Value {
    let request = peer.request_for(INFO_METHOD).await;
    peer.result(
        &request["id"],
        json!({"id": SESSION, "workspace": WORKSPACE, "status": "idle"}),
    )
    .await;

    request
}

async fn answer(peer: &mut Peer, method: &str, result: Value) -> Value {
    let request = peer.request_for(method).await;
    peer.result(&request["id"], result).await;

    request
}

fn diagnostic(signature: &str, severity: &str, line: u64, message: &str) -> Value {
    json!({
        "signature": signature,
        "severity": severity,
        "code": "E001",
        "source": "fake",
        "message": message,
        "tags": [],
        "range": {
            "start": {"line": line, "character": 4},
            "end": {"line": line, "character": 9}
        }
    })
}

#[tokio::test]
async fn code_intel_asks_in_the_session_workspace_and_renders_what_came_back() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, REQUEST_METHOD]).await;
        answer_info(&mut peer).await;

        answer(
            &mut peer,
            REQUEST_METHOD,
            json!({
                "status": "ok",
                "truncated": 2,
                "items": [
                    {
                        "path": "lib/a.ex",
                        "external": false,
                        "range": {"start": {"line": 11, "character": 4},
                                  "end": {"line": 11, "character": 9}}
                    },
                    {
                        "path": "deps/b/lib/b.ex",
                        "external": true,
                        "range": {"start": {"line": 0, "character": 0},
                                  "end": {"line": 0, "character": 3}}
                    }
                ]
            }),
        )
        .await
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(
                CODE_INTEL_TOOL,
                json!({"operation": "references", "path": "lib/a.ex", "line": 11, "character": 4}),
            ))
            .await
            .expect("a response"),
    );

    assert!(!failed(&response), "{response}");

    let rendered = text(&response);
    assert!(rendered.starts_with("2 references results:"), "{rendered}");
    // 0-based on the wire, 1-based where a person reads it.
    assert!(rendered.contains("  lib/a.ex:12:5"), "{rendered}");
    assert!(
        rendered.contains("deps/b/lib/b.ex:1:1 [outside the workspace]"),
        "{rendered}"
    );
    // The runtime's own cap is added to whatever this client left out.
    assert!(rendered.contains("+2 more"), "{rendered}");

    let asked = script.await.expect("the script");
    assert_eq!(asked["params"]["workspace"], WORKSPACE);
    assert_eq!(asked["params"]["operation"], "references");
    // A relative path is relative to the *workspace*, and this process is the one that
    // knows what that is; the runtime would expand it against wherever the daemon started.
    assert_eq!(asked["params"]["path"], "/work/repo/lib/a.ex");
    assert_eq!(asked["params"]["line"], 11);
    assert_eq!(asked["params"]["character"], 4);
    assert_eq!(asked["params"]["node"], "ouroboros@host");
}

#[tokio::test]
async fn the_diagnostics_tool_reports_only_what_the_edit_added() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD, DIAGNOSTICS_METHOD])
            .await;
        answer_info(&mut peer).await;

        let touched = answer(
            &mut peer,
            TOUCH_METHOD,
            json!({
                "version": 7,
                "baseline": {
                    "fresh?": true,
                    "version": 6,
                    "truncated": 0,
                    "signatures": ["old-one"],
                    "counts": {"error": 1}
                }
            }),
        )
        .await;

        answer(
            &mut peer,
            DIAGNOSTICS_METHOD,
            json!({
                "status": "ok",
                "version": 7,
                "truncated": 0,
                "items": [
                    diagnostic("old-one", "error", 3, "this was already broken"),
                    diagnostic("new-one", "error", 11, "undefined variable"),
                    diagnostic("new-two", "warning", 20, "unused")
                ]
            }),
        )
        .await;

        touched
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(DIAGNOSTICS_TOOL, json!({"path": "lib/a.ex"})))
            .await
            .expect("a response"),
    );

    let rendered = text(&response);
    assert!(
        rendered.starts_with("Found 2 new diagnostic issues in /work/repo/lib/a.ex:"),
        "{rendered}"
    );
    assert!(rendered.contains("undefined variable"), "{rendered}");
    assert!(rendered.contains("unused"), "{rendered}");
    // The pre-existing error is not this edit's doing and is not reported as if it were.
    assert!(!rendered.contains("already broken"), "{rendered}");

    let touched = script.await.expect("the script");
    assert_eq!(touched["params"]["workspace"], WORKSPACE);
    assert_eq!(touched["params"]["path"], "/work/repo/lib/a.ex");
    // The edit already happened, so the file is announced as changed rather than opened.
    assert_eq!(touched["params"]["action"], "changed");
}

#[tokio::test]
async fn a_server_that_has_not_answered_is_no_lsp_data_and_never_an_empty_list() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD, DIAGNOSTICS_METHOD])
            .await;
        answer_info(&mut peer).await;
        answer(&mut peer, TOUCH_METHOD, json!({"version": 2})).await;
        // The freshness gate: the cache describes text that no longer exists.
        answer(
            &mut peer,
            DIAGNOSTICS_METHOD,
            json!({"status": "pending", "version": 1}),
        )
        .await
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(DIAGNOSTICS_TOOL, json!({"path": "lib/a.ex"})))
            .await
            .expect("a response"),
    );

    assert!(!failed(&response), "{response}");
    assert_eq!(text(&response), "(no LSP data for /work/repo/lib/a.ex)");

    script.await.expect("the script");
}

#[tokio::test]
async fn the_touch_tool_announces_an_edit_made_somewhere_else() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD]).await;
        answer_info(&mut peer).await;
        answer(&mut peer, TOUCH_METHOD, json!({"version": 4})).await
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(
                TOUCH_TOOL,
                json!({"path": "lib/a.ex", "action": "open"}),
            ))
            .await
            .expect("a response"),
    );

    assert!(text(&response).contains("version 4"), "{response}");

    let asked = script.await.expect("the script");
    assert_eq!(asked["params"]["action"], "open");
}

#[tokio::test]
async fn the_workspace_is_read_once_and_then_held() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, REQUEST_METHOD]).await;
        answer_info(&mut peer).await;

        answer(
            &mut peer,
            REQUEST_METHOD,
            json!({"status": "ok", "truncated": 0, "items": []}),
        )
        .await;

        // A second `interactive.info` would show up here as the next frame; what arrives
        // instead is the second question, which is the assertion.
        let second = peer.request().await.expect("a second call");
        assert_eq!(second["method"], REQUEST_METHOD);
        peer.result(
            &second["id"],
            json!({"status": "ok", "truncated": 0, "items": []}),
        )
        .await;
    });

    let mut server = server(address, Duration::from_secs(5));

    for _call in 0..2 {
        let response = decode(
            &server
                .handle_line(&tool_call(
                    CODE_INTEL_TOOL,
                    json!({"operation": "definition", "path": "lib/a.ex"}),
                ))
                .await
                .expect("a response"),
        );

        assert_eq!(
            text(&response),
            "No definition results for /work/repo/lib/a.ex."
        );
    }

    script.await.expect("the script");
}

#[tokio::test]
async fn a_runtime_refusal_is_an_error_result_the_model_can_act_on() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, REQUEST_METHOD]).await;
        answer_info(&mut peer).await;

        let asked = peer.request_for(REQUEST_METHOD).await;
        peer.error(
            &asked["id"],
            -32004,
            "no language server is available for that file: install rust-analyzer",
            Some(json!({"reason": "server_unavailable"})),
        )
        .await;
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(
                CODE_INTEL_TOOL,
                json!({"operation": "references", "path": "src/main.rs"}),
            ))
            .await
            .expect("a response"),
    );

    assert!(failed(&response), "{response}");
    assert!(
        text(&response).contains("install rust-analyzer"),
        "{response}"
    );

    script.await.expect("the script");
}

#[tokio::test]
async fn a_malformed_code_intel_call_never_reaches_the_runtime() {
    // Nothing is listening, so any call that got as far as the gateway would fail with a
    // connection error rather than the argument message these assert on.
    let listen = TcpListener::bind(("127.0.0.1", 0)).await.expect("a port");
    let address = listen.local_addr().expect("an address");
    drop(listen);

    let mut server = server(address, Duration::from_millis(200));

    let cases = [
        (
            CODE_INTEL_TOOL,
            json!({"operation": "rename", "path": "lib/a.ex"}),
            "operation must be one of",
        ),
        (
            CODE_INTEL_TOOL,
            json!({"path": "lib/a.ex"}),
            "operation must be a non-empty string",
        ),
        (
            CODE_INTEL_TOOL,
            json!({"operation": "references"}),
            "path must be a non-empty string",
        ),
        (DIAGNOSTICS_TOOL, json!({"path": "  "}), "path must be"),
        (
            TOUCH_TOOL,
            json!({"path": "lib/a.ex", "action": "deleted"}),
            "action must be one of",
        ),
        (TOUCH_TOOL, json!("not an object"), "takes an object"),
    ];

    for (tool, arguments, expected) in cases {
        let response = decode(
            &server
                .handle_line(&tool_call(tool, arguments))
                .await
                .unwrap(),
        );

        assert!(failed(&response), "{response}");
        assert!(text(&response).contains(expected), "{response}");
    }
}

#[tokio::test]
async fn an_absolute_path_is_left_alone_and_a_relative_one_is_joined_to_the_workspace() {
    assert_eq!(
        ouro::mcp_serve::in_workspace(WORKSPACE, "lib/a.ex"),
        "/work/repo/lib/a.ex"
    );
    assert_eq!(
        ouro::mcp_serve::in_workspace(WORKSPACE, "/elsewhere/a.ex"),
        "/elsewhere/a.ex"
    );
}

#[tokio::test]
async fn on_demand_diagnostics_open_without_claiming_a_change() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[INFO_METHOD, TOUCH_METHOD, DIAGNOSTICS_METHOD])
            .await;
        answer_info(&mut peer).await;

        let touched = answer(&mut peer, TOUCH_METHOD, json!({"version": 1})).await;

        answer(
            &mut peer,
            DIAGNOSTICS_METHOD,
            json!({
                "status": "ok",
                "version": 1,
                "truncated": 0,
                "items": [diagnostic("here", "error", 3, "already broken")]
            }),
        )
        .await;

        touched
    });

    let mut server = server(address, Duration::from_secs(5));

    let response = decode(
        &server
            .handle_line(&tool_call(
                CODE_INTEL_TOOL,
                json!({"operation": "diagnostics", "path": "lib/a.ex"}),
            ))
            .await
            .expect("a response"),
    );

    // No baseline diff: the question was "what is wrong with this file", not "what did I
    // just break", so a pre-existing error is the answer rather than something to hide.
    let rendered = text(&response);
    assert!(
        rendered.starts_with("Found 1 diagnostic issue in /work/repo/lib/a.ex:"),
        "{rendered}"
    );
    assert!(rendered.contains("already broken"), "{rendered}");

    // `ensure_open`, not `open`: re-opening assigns a new version, and a server with
    // nothing new to say never publishes for it, so asking twice would answer "no LSP data"
    // the second time. Found by a live run against clangd.
    let touched = script.await.expect("the script");
    assert_eq!(touched["params"]["action"], "ensure_open");
}

#[tokio::test]
async fn code_intel_without_a_runtime_says_it_was_run_by_hand() {
    let mut server = Server::new(Err("OUROBOROS_SESSION_ID is not set".to_string()));

    let response = decode(
        &server
            .handle_line(&tool_call(
                CODE_INTEL_TOOL,
                json!({"operation": "references", "path": "lib/a.ex"}),
            ))
            .await
            .expect("a response"),
    );

    assert!(failed(&response), "{response}");
    assert!(text(&response).contains("not by hand"), "{response}");
}
