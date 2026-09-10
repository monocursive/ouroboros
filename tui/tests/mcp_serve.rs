//! `ouro mcp-serve` driven as the two things it actually is: an MCP server on one side
//! and a gateway client on the other.
//!
//! The MCP half is exercised message by message through `Server::handle_line`, so the
//! frames these tests assert on are the bytes an MCP client would read. The gateway half
//! runs against `support::Peer`, the same scripted peer the transport and UI tests use, so
//! the handshake, the correlation, and the reconnect are the real ones.
//!
//! The property every test here is really about is the same one: the session a tool call
//! acts on is the one in the bridge environment, and no argument can name another.

mod support;

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use ouro::mcp_serve::{
    Bridge, Server, AGENT_RESULT_TOOL, AGENT_TOOL, FLEET_METHOD, FLEET_TOOL, PROTOCOL_VERSION,
    SUBAGENT_RESULT_METHOD, SUBAGENT_SPAWN_METHOD, SUBAGENT_STOP_METHOD,
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

fn bridge(addr: SocketAddr) -> Bridge {
    Bridge {
        addr,
        token_file: token_file(),
        session_id: SESSION.to_string(),
        node: Some("ouroboros@host".to_string()),
    }
}

fn server(addr: SocketAddr) -> Server {
    Server::new(Ok(bridge(addr)))
}

fn frame(value: Value) -> String {
    serde_json::to_string(&value).expect("encodable")
}

fn decode(line: &str) -> Value {
    serde_json::from_str(line).expect("a JSON frame")
}

#[tokio::test]
async fn the_handshake_and_the_tools_it_advertises() {
    let (listen, address) = listener().await;
    drop(listen);
    let mut server = server(address);

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

    // Three tools, all of them the model's. There is no fourth for a harness to point a
    // permission prompt at: approvals are the runtime's own channel now.
    assert_eq!(names, vec![AGENT_TOOL, AGENT_RESULT_TOOL, FLEET_TOOL]);
    assert_eq!(tools[0]["name"], AGENT_TOOL);
    assert_eq!(tools[0]["inputSchema"]["type"], "object");
    assert_eq!(
        tools[0]["inputSchema"]["properties"]["prompt"]["type"],
        "string"
    );

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

// ---------------------------------------------------------------------------
// The tools the model may call
// ---------------------------------------------------------------------------

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

async fn answer(peer: &mut Peer, method: &str, result: Value) -> Value {
    let request = peer.request_for(method).await;
    peer.result(&request["id"], result).await;

    request
}

/// A gateway refusal reaches the model as a tool result it can act on — an `isError`
/// content block carrying the runtime's own sentence — rather than as an MCP error the
/// harness swallows.
#[tokio::test]
async fn a_runtime_refusal_is_an_error_result_the_model_can_act_on() {
    let (listen, address) = listener().await;

    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[FLEET_METHOD]).await;

        let asked = peer.request_for(FLEET_METHOD).await;
        peer.error(
            &asked["id"],
            -32004,
            "the cluster plane is not running on that node",
            Some(json!({"reason": "unavailable"})),
        )
        .await;
    });

    let mut server = server(address);

    let response = decode(
        &server
            .handle_line(&tool_call(FLEET_TOOL, json!({})))
            .await
            .expect("a response"),
    );

    assert!(failed(&response), "{response}");
    assert!(
        text(&response).contains("the cluster plane is not running"),
        "{response}"
    );

    script.await.expect("the script");
}

/// `ouro mcp-serve` is started by the runtime. Run by hand it has no session to ask, and
/// every model tool says so instead of failing obscurely.
#[tokio::test]
async fn a_model_tool_without_a_runtime_says_it_was_run_by_hand() {
    let mut server = Server::new(Err("OUROBOROS_SESSION_ID is not set".to_string()));

    let response = decode(
        &server
            .handle_line(&tool_call(FLEET_TOOL, json!({})))
            .await
            .expect("a response"),
    );

    assert!(failed(&response), "{response}");
    assert!(text(&response).contains("not by hand"), "{response}");
}

/// A tool this server does not serve is a misconfiguration, not something the model can
/// act on, so it is a protocol error rather than a result it would read and retry.
#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error_rather_than_a_result() {
    let mut server = Server::new(Err("must not connect".into()));

    let unknown = decode(
        &server
            .handle_line(&tool_call("rename_everything", json!({})))
            .await
            .expect("a response"),
    );

    assert_eq!(unknown["error"]["code"], -32602);
}

#[tokio::test]
async fn native_tool_schemas_match_argument_types_and_exclude_owner_authority() {
    let mut server = Server::new(Err("unused".into()));
    let listed = decode(
        &server
            .handle_line(&frame(json!({"jsonrpc":"2.0", "id":1,
        "method":"tools/list"})))
            .await
            .unwrap(),
    );
    let tools = listed["result"]["tools"].as_array().unwrap();
    let schema =
        |name: &str| &tools.iter().find(|tool| tool["name"] == name).unwrap()["inputSchema"];
    let agent = schema(AGENT_TOOL);
    assert_eq!(agent["required"], json!(["prompt"]));
    assert_eq!(agent["additionalProperties"], false);
    assert_eq!(agent["properties"].as_object().unwrap().len(), 10);
    for key in ["prompt", "description", "machine", "workspace"] {
        assert_eq!(agent["properties"][key]["type"], "string");
    }
    for key in ["worktree", "sync", "background"] {
        assert_eq!(agent["properties"][key]["type"], "boolean");
    }
    assert_eq!(agent["properties"]["tools"]["items"]["type"], "string");
    assert_eq!(agent["properties"]["deadline_ms"]["minimum"], 1);
    assert_eq!(agent["properties"]["max_turns"]["default"], 12);
    assert_eq!(
        schema(AGENT_RESULT_TOOL)["properties"]["stop"]["type"],
        "boolean"
    );
    assert_eq!(
        schema(AGENT_RESULT_TOOL)["properties"]["wait_ms"]["minimum"],
        0
    );
    assert_eq!(schema(FLEET_TOOL)["properties"], json!({}));
    for tool in [AGENT_TOOL, AGENT_RESULT_TOOL, FLEET_TOOL] {
        for field in [
            "id",
            "node",
            "request_id",
            "approval_mode",
            "sandbox_mode",
            "provider_options",
        ] {
            assert!(schema(tool)["properties"].get(field).is_none());
        }
    }
}

#[tokio::test]
async fn an_ambiguous_spawn_reconnect_reuses_one_session_bound_request() {
    let (listen, address) = listener().await;
    let input = json!({"prompt":"build the project", "machine":"tag:linux", "sync":true,
        "background":true, "deadline_ms":900000, "tools":["bash", "read"]});
    let expected_input = input.clone();
    let script = tokio::spawn(async move {
        let mut first = Peer::accept(&listen).await;
        first.hello(&[SUBAGENT_SPAWN_METHOD]).await;
        let accepted = first.request_for(SUBAGENT_SPAWN_METHOD).await;
        // The host accepted the spawn but its reply was lost. A reconnect must ask
        // for the same cached invocation, never produce a second child.
        drop(first);
        let mut second = Peer::accept(&listen).await;
        second.hello(&[SUBAGENT_SPAWN_METHOD]).await;
        let retry = answer(
            &mut second,
            SUBAGENT_SPAWN_METHOD,
            json!({"output":"task-1 started", "is_error":false}),
        )
        .await;
        assert_eq!(accepted["params"], retry["params"]);
        assert_eq!(retry["params"]["id"], SESSION);
        assert_eq!(retry["params"]["node"], "ouroboros@host");
        assert_eq!(retry["params"]["input"], expected_input);
        let id = retry["params"]["request_id"].as_str().unwrap();
        assert!(id.starts_with("mcp-") && id.len() <= 128);
        assert_eq!(retry["params"].as_object().unwrap().len(), 4);
    });
    let mut server = server(address);
    let reply = decode(
        &server
            .handle_line(&tool_call(AGENT_TOOL, input))
            .await
            .unwrap(),
    );
    assert!(!failed(&reply), "{reply}");
    assert_eq!(text(&reply), "task-1 started");
    script.await.unwrap();
}

#[tokio::test]
async fn result_and_stop_keep_the_bridge_owner_and_preserve_native_errors() {
    let (listen, address) = listener().await;
    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[SUBAGENT_RESULT_METHOD, SUBAGENT_STOP_METHOD])
            .await;
        let collected = answer(
            &mut peer,
            SUBAGENT_RESULT_METHOD,
            json!({"output":"unknown task", "is_error":true}),
        )
        .await;
        let stopped = answer(
            &mut peer,
            SUBAGENT_STOP_METHOD,
            json!({"output":"returning; still collectable", "is_error":false}),
        )
        .await;
        for call in [&collected, &stopped] {
            assert_eq!(call["params"]["id"], SESSION);
            assert_eq!(call["params"]["node"], "ouroboros@host");
        }
        assert_eq!(
            collected["params"]["input"],
            json!({"task_id":"task-1", "wait_ms":0})
        );
        assert_eq!(stopped["params"]["task_id"], "task-1");
        assert!(stopped["params"].get("input").is_none());
        assert_ne!(
            collected["params"]["request_id"], stopped["params"]["request_id"],
            "MCP ids may be reused for a later logical invocation"
        );
    });
    let mut server = server(address);
    let reply = decode(
        &server
            .handle_line(&tool_call(
                AGENT_RESULT_TOOL,
                json!({"task_id":"task-1", "wait_ms":0}),
            ))
            .await
            .unwrap(),
    );
    assert!(failed(&reply));
    assert_eq!(text(&reply), "unknown task");
    let reply = decode(
        &server
            .handle_line(&tool_call(
                AGENT_RESULT_TOOL,
                json!({"task_id":"task-1", "stop":true}),
            ))
            .await
            .unwrap(),
    );
    assert!(!failed(&reply));
    assert_eq!(text(&reply), "returning; still collectable");
    script.await.unwrap();
}

#[tokio::test]
async fn fleet_routes_to_the_bridge_owner_and_bounds_the_inventory() {
    let (listen, address) = listener().await;
    let script = tokio::spawn(async move {
        let mut peer = Peer::accept(&listen).await;
        peer.hello(&[FLEET_METHOD]).await;
        let request = answer(
            &mut peer,
            FLEET_METHOD,
            json!({"machines":vec![
            json!({"machine":"builder", "state":"online", "facts":{"tags":["linux"]}}); 65]}),
        )
        .await;
        assert_eq!(request["params"], json!({"node":"ouroboros@host"}));
    });
    let mut server = server(address);
    let reply = decode(
        &server
            .handle_line(&tool_call(FLEET_TOOL, json!({})))
            .await
            .unwrap(),
    );
    assert!(!failed(&reply), "{reply}");
    let inventory: Value = serde_json::from_str(&text(&reply)).unwrap();
    assert_eq!(inventory["machines"].as_array().unwrap().len(), 64);
    assert_eq!(inventory["omitted_machines"], 1);
    assert_eq!(inventory["machines"][0]["facts"]["tags"], json!(["linux"]));
    script.await.unwrap();
}

#[tokio::test]
async fn forged_native_owner_or_posture_arguments_are_rejected_before_connecting() {
    let (listen, address) = listener().await;
    let mut server = server(address);
    for tool in [AGENT_TOOL, AGENT_RESULT_TOOL, FLEET_TOOL] {
        for field in [
            "id",
            "node",
            "request_id",
            "approval_mode",
            "sandbox_mode",
            "provider_options",
        ] {
            let mut input = match tool {
                AGENT_TOOL => json!({"prompt":"x"}),
                AGENT_RESULT_TOOL => json!({"task_id":"task-1"}),
                _ => json!({}),
            };
            input[field] = json!("forged");
            let reply = tokio::time::timeout(
                Duration::from_secs(1),
                server.handle_line(&tool_call(tool, input)),
            )
            .await
            .expect("validation is local")
            .unwrap();
            let reply = decode(&reply);
            assert!(failed(&reply), "{reply}");
            assert!(
                text(&reply).contains(&format!("does not accept {field}")),
                "{reply}"
            );
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listen.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_native_arguments_are_refused_without_losing_mcp() {
    let mut server = Server::new(Err("must not connect".into()));
    for (tool, input) in [
        (AGENT_TOOL, json!({"prompt":"x", "deadline_ms":0})),
        (AGENT_TOOL, json!({"prompt":"x", "tools":[true]})),
        (AGENT_TOOL, json!({"prompt":"x", "background":"true"})),
        (AGENT_TOOL, json!({"prompt":3})),
        (AGENT_RESULT_TOOL, json!({"task_id":"x", "wait_ms":-1})),
        (AGENT_RESULT_TOOL, json!({"task_id":"x", "stop":1})),
    ] {
        let reply = decode(&server.handle_line(&tool_call(tool, input)).await.unwrap());
        assert!(failed(&reply));
        assert!(text(&reply).starts_with("invalid "), "{reply}");
    }
}
