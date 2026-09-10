//! `ouro mcp-serve`: this session's native children and fleet, over MCP on stdio.
//!
//! ## Why this exists
//!
//! An Ouroboros session can delegate work to native children and can read the fleet it
//! belongs to. This module lends those two abilities to an external MCP client — an
//! editor, another agent harness — so that a tool call made *there* is carried out by
//! *this* session, under this session's ownership and permissions.
//!
//! It is not run by hand. The runtime spawns it with the gateway address, the token
//! *file*, and the session id in the child's environment; the client speaks MCP over its
//! stdio, and `agent`, `agent_result` and `fleet` land here.
//!
//! ## The contract, pinned
//!
//! **MCP.** Revision `2026-07-28` (<https://modelcontextprotocol.io/specification>, whose
//! schema is `schema/2026-07-28/schema.ts`). The stdio binding is newline-delimited
//! JSON-RPC 2.0 on stdin/stdout — one message per line, no embedded newlines, and nothing
//! that is not a message may be written to stdout, which is why every log here goes to
//! stderr and only when `OUROBOROS_MCP_SERVE_VERBOSE=1`. `initialize` /
//! `notifications/initialized` are the handshake of the initialization-based revisions;
//! the requested `protocolVersion` is echoed back when the client named one, because a
//! server that insists on its own revision fails the negotiation the spec's
//! backward-compatibility rules exist to make work.
//!
//! ## Refuse by default, and say why
//!
//! Every failure — no runtime, a refused token, a gateway that answered an error, a
//! malformed call, a deadline — answers with `isError` and a message naming the cause.
//! Nothing here succeeds because something did not happen: a tool that fails silently is
//! one the model will call again with the same arguments.
//!
//! The connection is opened on first use and held for the server's lifetime; a transport
//! failure is retried exactly once against a fresh connection. A *timeout* is never
//! retried. Child calls carry one bridge-generated request id across that reconnect, so
//! the owning session can replay a result rather than spawn a second child. Session
//! identity and owner routing come only from the bridge environment; tool arguments
//! cannot select another owner.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::TryRngCore;
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::runtime;
use crate::transport::{self, Client, ClientError, NoReconnectHook, Secret, TransportConfig};

/// The MCP revision this server implements. Echoed only when the client did not name one.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The server name the client registers this bridge under. It is half of every
/// `mcp__<server>__<tool>` name, so it is a constant on both sides rather than a string
/// typed twice.
pub const SERVER_NAME: &str = "ouroboros";

/// The tools the *model* may call.
pub const AGENT_TOOL: &str = "agent";
pub const AGENT_RESULT_TOOL: &str = "agent_result";
pub const FLEET_TOOL: &str = "fleet";
pub const SUBAGENT_SPAWN_METHOD: &str = "subagent.spawn";
pub const SUBAGENT_RESULT_METHOD: &str = "subagent.result";
pub const SUBAGENT_STOP_METHOD: &str = "subagent.stop";
pub const FLEET_METHOD: &str = "fleet.status";
/// Above the gateway's own 15s ceiling on `fleet.status`, so a slow answer is reported by
/// the runtime that knows why rather than by a client stopwatch.
const FLEET_TIMEOUT: Duration = Duration::from_secs(20);
const SUBAGENT_SPAWN_TIMEOUT: Duration = Duration::from_secs(930);
const SUBAGENT_RESULT_TIMEOUT: Duration = Duration::from_secs(75);
const MAX_FLEET_OUTPUT_BYTES: usize = 64 * 1024;

pub const ADDR_ENV: &str = "OUROBOROS_GATEWAY_ADDR";
pub const TOKEN_FILE_ENV: &str = "OUROBOROS_GATEWAY_TOKEN_FILE";
pub const SESSION_ID_ENV: &str = "OUROBOROS_SESSION_ID";
pub const SESSION_NODE_ENV: &str = "OUROBOROS_SESSION_NODE";
pub const VERBOSE_ENV: &str = "OUROBOROS_MCP_SERVE_VERBOSE";

/// The most one MCP message may be. A tool call carries arguments, not a file, and a line
/// that never ends is a peer growing this process's memory on its say-so.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// What the environment said about the runtime to ask. Every field is validated once, at
/// start, so a misconfiguration is one legible denial per call rather than a panic.
#[derive(Debug, Clone)]
pub struct Bridge {
    pub addr: SocketAddr,
    pub token_file: PathBuf,
    pub session_id: String,
    pub node: Option<String>,
}

impl Bridge {
    /// Reads the bridge out of the environment the adapter set.
    pub fn from_env() -> Result<Self> {
        let addr = std::env::var(ADDR_ENV)
            .map_err(|_absent| anyhow!("{ADDR_ENV} is not set"))?
            .parse::<SocketAddr>()
            .map_err(|error| anyhow!("{ADDR_ENV} is not a host:port address: {error}"))?;

        let token_file = std::env::var(TOKEN_FILE_ENV)
            .map_err(|_absent| anyhow!("{TOKEN_FILE_ENV} is not set"))?;

        let session_id = std::env::var(SESSION_ID_ENV)
            .map_err(|_absent| anyhow!("{SESSION_ID_ENV} is not set"))?;

        if session_id.trim().is_empty() {
            return Err(anyhow!("{SESSION_ID_ENV} is empty"));
        }

        let node = std::env::var(SESSION_NODE_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            addr,
            token_file: PathBuf::from(token_file),
            session_id,
            node,
        })
    }
}

fn verbose() -> bool {
    std::env::var(VERBOSE_ENV).is_ok_and(|value| value == "1")
}

/// stderr, and only when asked. stdout is the transport and carries nothing else.
fn log(message: &str) {
    if verbose() {
        eprintln!("ouro mcp-serve: {message}");
    }
}

/// The gateway connection, opened lazily and reopened once after a transport failure.
#[derive(Default)]
struct Gateway {
    client: Option<Client>,
}

impl Gateway {
    async fn connect(bridge: &Bridge) -> Result<Client, String> {
        let token: Secret = runtime::read_token(&bridge.token_file)
            .map_err(|error| format!("the gateway token could not be read: {error:#}"))?;

        let mut config = TransportConfig::new(bridge.addr, token);
        // A dropped connection is this module's to notice, not the transport's to paper
        // over: a call in flight when the socket died has to become a refusal, and a
        // background reconnect would leave the caller waiting for its ceiling instead.
        config.reconnect = false;

        transport::connect(config, Arc::new(NoReconnectHook))
            .await
            .map(|connected| connected.client)
            .map_err(|error| format!("the runtime at {} did not answer: {error}", bridge.addr))
    }

    /// One call, with at most one reconnect and identical parameters. Timeouts are never
    /// retried; child calls carry a stable invocation id for host-side deduplication.
    async fn call(
        &mut self,
        bridge: &Bridge,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        for attempt in 0..2u8 {
            let client = match self.client.clone() {
                Some(client) => client,
                None => {
                    let client = Self::connect(bridge).await?;
                    self.client = Some(client.clone());
                    client
                }
            };

            match client
                .call_with_timeout(method, params.clone(), timeout)
                .await
            {
                Ok(value) => return Ok(value),

                // The runtime decided; there is nothing to retry and the message is the
                // one worth relaying.
                Err(ClientError::Rpc(error)) => {
                    return Err(format!(
                        "the runtime refused the call ({}: {})",
                        error.code, error.message
                    ))
                }

                // A call that ran out of time may have had an effect already. Asking
                // again would risk a second one, so this ends here.
                Err(ClientError::Timeout) => {
                    return Err(format!(
                        "no decision within {}ms",
                        timeout.as_millis().min(u128::from(u64::MAX))
                    ))
                }

                Err(error) => {
                    self.client = None;

                    if attempt == 1 {
                        return Err(format!("the runtime connection failed: {error}"));
                    }

                    log(&format!("reconnecting after {error}"));
                }
            }
        }

        Err("the runtime connection failed".to_string())
    }
}

/// The server, as a value a test can drive one line at a time.
pub struct Server {
    bridge: Result<Bridge, String>,
    gateway: Gateway,
}

impl Server {
    pub fn new(bridge: Result<Bridge, String>) -> Self {
        Self {
            bridge,
            gateway: Gateway::default(),
        }
    }

    /// Answers one inbound line. `None` where MCP says nothing is owed: a notification, a
    /// response (this server issues no requests), or a line that is not a message at all.
    pub async fn handle_line(&mut self, line: &str) -> Option<String> {
        let line = line.trim();

        if line.is_empty() {
            return None;
        }

        let message: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            // A parse error with no id to correlate is still owed an answer per JSON-RPC.
            Err(error) => {
                return Some(encode(error_frame(
                    Value::Null,
                    -32700,
                    &format!("invalid JSON: {error}"),
                )))
            }
        };

        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str);

        let (Some(method), Some(id)) = (method, id) else {
            // A notification (no id) is acted on and never answered; a response is not
            // ours to receive, because this server never asks.
            if let Some(method) = method {
                log(&format!("notification {method}"));
            }

            return None;
        };

        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let response = self.dispatch(method, params).await;

        Some(encode(match response {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => error_frame(id, code, &message),
        }))
    }

    async fn dispatch(&mut self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(initialize_result(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tool_descriptors()})),
            "tools/call" => self.tools_call(params).await,
            other => Err((-32601, format!("method not found: {other}"))),
        }
    }

    async fn tools_call(&mut self, params: Value) -> Result<Value, (i64, String)> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

        match name {
            AGENT_TOOL | AGENT_RESULT_TOOL => Ok(match self.subagent(name, arguments).await {
                Ok(result) => result,
                Err(reason) => text_result(Err(reason)),
            }),
            FLEET_TOOL => Ok(text_result(self.fleet(arguments).await)),
            other => Err((-32602, format!("unknown tool: {other}"))),
        }
    }

    async fn subagent(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let input = native_arguments(name, &arguments)?;
        let bridge = self.configured()?;
        // One identifier per invocation, minted before Gateway's reconnect loop. JSON-RPC
        // ids may be reused by a client after a reply, so they cannot key the runtime cache.
        let mut random = [0u8; 24];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|error| format!("could not identify this child request: {error}"))?;
        let request_id = format!(
            "mcp-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let stop = name == AGENT_RESULT_TOOL && input.get("stop") == Some(&Value::Bool(true));
        let method = if name == AGENT_TOOL {
            SUBAGENT_SPAWN_METHOD
        } else if stop {
            SUBAGENT_STOP_METHOD
        } else {
            SUBAGENT_RESULT_METHOD
        };
        let mut params = Map::new();
        params.insert("id".into(), json!(bridge.session_id));
        params.insert("request_id".into(), json!(request_id));
        if stop {
            params.insert("task_id".into(), input["task_id"].clone());
        } else {
            params.insert("input".into(), Value::Object(input.clone()));
        }
        self.route(&bridge, &mut params);
        let timeout = if name == AGENT_TOOL {
            SUBAGENT_SPAWN_TIMEOUT
        } else {
            SUBAGENT_RESULT_TIMEOUT
        };
        let result = self
            .gateway
            .call(&bridge, method, Value::Object(params), timeout)
            .await
            .map_err(|error| format!("{error} (child request {request_id})"))?;
        let output = result
            .get("output")
            .and_then(Value::as_str)
            .ok_or_else(|| "the runtime returned no child tool output".to_string())?;
        let is_error = result
            .get("is_error")
            .and_then(Value::as_bool)
            .ok_or_else(|| "the runtime returned no child tool outcome".to_string())?;
        Ok(json!({"content": [{"type": "text", "text": output}], "isError": is_error}))
    }

    async fn fleet(&mut self, arguments: Value) -> Result<String, String> {
        let arguments = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        native_arguments(FLEET_TOOL, &arguments)?;
        let bridge = self.configured()?;
        let mut params = Map::new();
        self.route(&bridge, &mut params);
        let mut result = self
            .gateway
            .call(&bridge, FLEET_METHOD, Value::Object(params), FLEET_TIMEOUT)
            .await?;
        let machines = result
            .get_mut("machines")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "the runtime returned no fleet machine list".to_string())?;
        let omitted = machines.len().saturating_sub(64);
        machines.truncate(64);
        if omitted > 0 {
            result["omitted_machines"] = json!(omitted);
        }
        let output = serde_json::to_string(&result).map_err(|error| error.to_string())?;
        if output.len() > MAX_FLEET_OUTPUT_BYTES {
            return Err("the fleet inventory exceeds this tool's 64 KiB output limit".into());
        }
        Ok(output)
    }

    fn route(&self, bridge: &Bridge, params: &mut Map<String, Value>) {
        if let Some(node) = &bridge.node {
            params.insert("node".into(), json!(node));
        }
    }

    fn configured(&self) -> Result<Bridge, String> {
        self.bridge.clone().map_err(|reason| {
            format!(
                "this session is not connected to an Ouroboros runtime ({reason}); \
                 `ouro mcp-serve` is started by the runtime, not by hand"
            )
        })
    }
}

/// What model-facing tools answer with. A refusal is `isError` and says what
/// went wrong in the same text block, because a tool that fails silently is one the model
/// will call again with the same arguments.
fn text_result(outcome: Result<String, String>) -> Value {
    match outcome {
        Ok(text) => json!({"content": [{"type": "text", "text": text}], "isError": false}),
        Err(message) => json!({"content": [{"type": "text", "text": message}], "isError": true}),
    }
}

// ---------------------------------------------------------------------------
// Argument reading
// ---------------------------------------------------------------------------

fn native_arguments<'a>(name: &str, value: &'a Value) -> Result<&'a Map<String, Value>, String> {
    let input = object(value, name)?;
    let allowed: &[&str] = match name {
        AGENT_TOOL => &[
            "prompt",
            "description",
            "tools",
            "worktree",
            "machine",
            "workspace",
            "sync",
            "background",
            "deadline_ms",
            "max_turns",
        ],
        AGENT_RESULT_TOOL => &["task_id", "wait_ms", "stop"],
        FLEET_TOOL => &[],
        _ => return Err("unknown native tool".into()),
    };
    for key in input.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{name} does not accept {key}"));
        }
    }
    for (key, value) in input {
        let valid = match key.as_str() {
            "prompt" | "description" | "machine" | "workspace" | "task_id" => value.is_string(),
            "tools" => value
                .as_array()
                .is_some_and(|tools| tools.iter().all(Value::is_string)),
            "worktree" | "sync" | "background" | "stop" => value.is_boolean(),
            "deadline_ms" | "max_turns" => value.as_u64().is_some_and(|n| n > 0),
            "wait_ms" => value.as_u64().is_some(),
            _ => false,
        };
        if !valid {
            return Err(format!("invalid {key} argument for {name}"));
        }
    }
    if name == AGENT_TOOL {
        string_argument(input, "prompt")?;
    }
    if name == AGENT_RESULT_TOOL {
        string_argument(input, "task_id")?;
    }
    Ok(input)
}

fn object<'a>(arguments: &'a Value, tool: &str) -> Result<&'a Map<String, Value>, String> {
    arguments
        .as_object()
        .ok_or_else(|| format!("the {tool} tool takes an object"))
}

fn string_argument(request: &Map<String, Value>, key: &str) -> Result<String, String> {
    optional_string(request, key).ok_or_else(|| format!("{key} must be a non-empty string"))
}

fn optional_string(request: &Map<String, Value>, key: &str) -> Option<String> {
    request
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// A missing or nonsensical position is zero rather than a refusal: `document_symbols` and
/// `workspace_symbols` need none, and a model that omits one for `definition` gets an
/// answer about the top of the file instead of an error it has to reason about.
fn tool_descriptors() -> Vec<Value> {
    vec![
        agent_descriptor(),
        agent_result_descriptor(),
        fleet_descriptor(),
    ]
}

fn agent_descriptor() -> Value {
    json!({
        "name": AGENT_TOOL, "title": "Delegate work to a native child",
        "description": "Start a child owned by this Ouroboros session. Put the full goal and constraints in prompt; the child has none of this conversation. Its tools and permissions are bounded by this session. Call fleet before choosing machine or tag:NAME. Use sync:true to send this repository including uncommitted work into an isolated remote worktree; dependencies are installed there and changes return as a Git ref. Use background:true for long work and collect with agent_result. Foreground waits are bounded by the loop tool timeout. Approvals reach this session's human, including between turns.",
        "inputSchema": {"type": "object", "properties": {
            "prompt": {"type": "string", "minLength": 1},
            "description": {"type": "string", "default": ""},
            "tools": {"type": "array", "items": {"type": "string"}, "default": []},
            "worktree": {"type": "boolean", "default": false},
            "machine": {"type": "string", "default": ""},
            "workspace": {"type": "string", "default": "", "description": "An absolute path on the target, required with machine unless sync:true. Cannot combine with sync:true."},
            "sync": {"type": "boolean", "default": false},
            "background": {"type": "boolean", "default": false},
            "deadline_ms": {"type": "integer", "minimum": 1, "description": "Bounded by the configured child deadline ceiling, at most four hours."},
            "max_turns": {"type": "integer", "minimum": 1, "default": 12, "description": "Maximum 30 model round-trips."}
        }, "required": ["prompt"], "additionalProperties": false}
    })
}

fn agent_result_descriptor() -> Value {
    json!({
        "name": AGENT_RESULT_TOOL, "title": "Collect or stop a native child",
        "description": "Collect the task_id returned by agent. A running child remains collectable and reports elapsed time and last activity. Set wait_ms:0 for an immediate snapshot, or stop:true to stop editing while preserving its work and any return in flight.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": {"type": "string", "minLength": 1},
            "wait_ms": {"type": "integer", "minimum": 0, "default": 30000, "description": "Clamped to 60000 milliseconds."},
            "stop": {"type": "boolean", "default": false}
        }, "required": ["task_id"], "additionalProperties": false}
    })
}

fn fleet_descriptor() -> Value {
    json!({
        "name": FLEET_TOOL, "title": "Read this session's fleet",
        "description": "List live fleet machines, connectivity, advisory tags and toolchains before choosing a machine for agent. These facts do not grant authority. The bridge reads the fleet of the session that started this agent.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
    })
}

fn initialize_result(params: &Value) -> Value {
    // Echo what the client asked for when it named a revision. The 2026-07-28 spec's
    // backward-compatibility rules exist precisely so that a server and a client of
    // different eras still talk; insisting on our own string here would fail the
    // negotiation instead.
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|version| !version.trim().is_empty())
        .unwrap_or(PROTOCOL_VERSION);

    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {
            "name": SERVER_NAME,
            "title": "Ouroboros session bridge",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Ouroboros lends this client the session that started it: `agent` \
                         delegates work to a native child owned by that session, \
                         `agent_result` collects or stops one, and `fleet` reads the \
                         machines that session can reach. Ownership comes from the \
                         session, never from these arguments."
    })
}

fn error_frame(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn encode(value: Value) -> String {
    serde_json::to_string(&value).unwrap_or_else(|_unencodable| {
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"unencodable"}}"#.to_string()
    })
}

/// Speaks MCP on this process's stdio until stdin ends.
pub async fn serve() -> Result<()> {
    let bridge = Bridge::from_env().map_err(|error| format!("{error:#}"));

    match &bridge {
        Ok(bridge) => log(&format!("session {} at {}", bridge.session_id, bridge.addr)),
        Err(reason) => log(&format!("unconfigured: {reason}")),
    }

    let stdin = BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();

    run(Server::new(bridge), stdin, stdout).await
}

/// The loop, over any pair of streams so a test can be the peer.
pub async fn run<R, W>(mut server: Server, reader: R, mut writer: W) -> Result<()>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = reader.lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) => return Err(anyhow!("reading MCP stdin: {error}")),
        };

        if line.len() > MAX_LINE_BYTES {
            let frame = encode(error_frame(
                Value::Null,
                -32600,
                &format!("message above the {MAX_LINE_BYTES}-byte ceiling"),
            ));

            write_line(&mut writer, &frame).await?;
            continue;
        }

        if let Some(frame) = server.handle_line(&line).await {
            write_line(&mut writer, &frame).await?;
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, frame: &str) -> Result<()> {
    // One message per line, and the frame itself can never contain a newline because
    // `serde_json` escapes them — which is exactly what the stdio binding requires.
    writer
        .write_all(frame.as_bytes())
        .await
        .map_err(|error| anyhow!("writing an MCP frame: {error}"))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|error| anyhow!("writing an MCP frame: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| anyhow!("flushing an MCP frame: {error}"))
}
