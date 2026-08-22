//! `ouro mcp-serve`: the permission prompt Claude Code has no other way to reach.
//!
//! ## Why this exists
//!
//! `claude --print` runs one process per turn and offers no approvals channel, so an
//! Ouroboros session at `approval_mode: :prompt` used to have its permission-needing
//! tools denied without a word. What Claude Code *does* offer headless is
//! `--permission-prompt-tool <mcp tool name>`: instead of prompting, it calls one MCP
//! tool and reads the decision out of the result. This module is that tool's server.
//!
//! It is not run by hand. `Ouroboros.Provider.ClaudeAdapter` composes an `--mcp-config`
//! naming this binary and this subcommand, with the gateway address, the token *file*,
//! and the session id in the child's environment; Claude Code spawns it, speaks MCP over
//! its stdio, and the `approve` call lands here.
//!
//! ## The two contracts, pinned
//!
//! **MCP.** Revision `2026-07-28` (<https://modelcontextprotocol.io/specification>, whose
//! schema is `schema/2026-07-28/schema.ts`). The stdio binding is newline-delimited
//! JSON-RPC 2.0 on stdin/stdout — one message per line, no embedded newlines, and nothing
//! that is not a message may be written to stdout, which is why every log here goes to
//! stderr and only when `OUROBOROS_MCP_SERVE_VERBOSE=1`. `initialize` /
//! `notifications/initialized` are the handshake of the initialization-based revisions
//! that Claude Code speaks; the requested `protocolVersion` is echoed back when the client
//! named one, because a server that insists on its own revision fails the negotiation the
//! spec's backward-compatibility rules exist to make work.
//!
//! **The permission prompt tool.** `--permission-prompt-tool` takes an MCP tool name
//! (<https://code.claude.com/docs/en/cli-reference>), and MCP tools are named
//! `mcp__<server>__<tool>` (<https://code.claude.com/docs/en/mcp>) — so this server,
//! registered as `ouroboros`, exposes `mcp__ouroboros__approve`. The call carries the
//! tool being asked about (`tool_name`), the arguments it would run with (`input`), and
//! the `tool_use_id` correlating it to the assistant's tool call. The answer is a JSON
//! object inside a text content block, and it is exactly the `canUseTool` result shape:
//! `{"behavior":"allow","updatedInput":{…}}` or `{"behavior":"deny","message":"…"}`
//! (<https://code.claude.com/docs/en/agent-sdk/user-input>, "Respond to tool requests").
//!
//! ## Deny by default, and say why
//!
//! Every failure — no runtime, a refused token, a gateway that answered an error, a
//! malformed call, a deadline — answers `deny` with a message naming the cause. There is
//! no path here that allows because something did not happen. The one place `allow` comes
//! from is a runtime that said so, which is a human or the permission engine on their
//! behalf.
//!
//! The connection is opened on first use and held for the server's lifetime; a transport
//! failure is retried exactly once against a fresh connection. A *timeout* is never
//! retried: a call that ran out of time may be sitting in front of a person, and asking
//! again would put a second question beside it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::runtime;
use crate::transport::{self, Client, ClientError, NoReconnectHook, Secret, TransportConfig};

/// The MCP revision this server implements. Echoed only when the client did not name one.
pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The server name in `--mcp-config`. It is half of the tool name Claude Code is told to
/// call, so it is a constant on both sides of the bridge rather than a string typed twice.
pub const SERVER_NAME: &str = "ouroboros";

/// The one tool. `mcp__ouroboros__approve` is what `--permission-prompt-tool` receives.
pub const TOOL_NAME: &str = "approve";

/// The gateway method the tool forwards to.
pub const APPROVAL_METHOD: &str = "interactive.request_approval";

pub const ADDR_ENV: &str = "OUROBOROS_GATEWAY_ADDR";
pub const TOKEN_FILE_ENV: &str = "OUROBOROS_GATEWAY_TOKEN_FILE";
pub const SESSION_ID_ENV: &str = "OUROBOROS_SESSION_ID";
pub const SESSION_NODE_ENV: &str = "OUROBOROS_SESSION_NODE";
pub const TIMEOUT_ENV: &str = "OUROBOROS_APPROVAL_TIMEOUT_MS";
pub const VERBOSE_ENV: &str = "OUROBOROS_MCP_SERVE_VERBOSE";

/// Ten minutes, the same order as a person walking back to their terminal. Held below the
/// gateway's own fifteen-minute ceiling on `interactive.request_approval` so that the
/// answer is the runtime's decision rather than a killed task.
pub const DEFAULT_APPROVAL_TIMEOUT_MS: u64 = 600_000;

/// The most one MCP message may be. A permission prompt carries a tool's arguments, not a
/// file, and a line that never ends is a peer growing this process's memory on its say-so.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// What the environment said about the runtime to ask. Every field is validated once, at
/// start, so a misconfiguration is one legible denial per call rather than a panic.
#[derive(Debug, Clone)]
pub struct Bridge {
    pub addr: SocketAddr,
    pub token_file: PathBuf,
    pub session_id: String,
    pub node: Option<String>,
    pub timeout: Duration,
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

        let timeout = match std::env::var(TIMEOUT_ENV) {
            Ok(value) => value
                .trim()
                .parse::<u64>()
                .map_err(|error| anyhow!("{TIMEOUT_ENV} is not a whole number of ms: {error}"))?,
            Err(_absent) => DEFAULT_APPROVAL_TIMEOUT_MS,
        };

        if timeout == 0 {
            return Err(anyhow!("{TIMEOUT_ENV} must be greater than zero"));
        }

        Ok(Self {
            addr,
            token_file: PathBuf::from(token_file),
            session_id,
            node,
            timeout: Duration::from_millis(timeout),
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
        // over: an approval in flight when the socket died has to become a denial, and a
        // background reconnect would leave the caller waiting for its ceiling instead.
        config.reconnect = false;

        transport::connect(config, Arc::new(NoReconnectHook))
            .await
            .map(|connected| connected.client)
            .map_err(|error| format!("the runtime at {} did not answer: {error}", bridge.addr))
    }

    /// One call, with exactly one reconnect. `retry` is false for anything whose outcome
    /// the runtime may still be deciding.
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
                        "the runtime refused the approval request ({}: {})",
                        error.code, error.message
                    ))
                }

                // A question that ran out of time may be in front of a person. Asking
                // again would put a second one beside it, so this ends here.
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
            "tools/list" => Ok(json!({"tools": [tool_descriptor()]})),
            "tools/call" => self.tools_call(params).await,
            other => Err((-32601, format!("method not found: {other}"))),
        }
    }

    async fn tools_call(&mut self, params: Value) -> Result<Value, (i64, String)> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");

        if name != TOOL_NAME {
            return Err((-32602, format!("unknown tool: {name}")));
        }

        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

        Ok(tool_result(self.approve(arguments).await))
    }

    /// The whole decision, as the behaviour object Claude Code reads.
    async fn approve(&mut self, arguments: Value) -> Value {
        let Some(request) = arguments.as_object() else {
            return deny("the approve tool takes an object with a tool_name");
        };

        let Some(tool_name) = request
            .get("tool_name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
        else {
            return deny("the approve tool call carried no tool_name");
        };

        let input = request.get("input").cloned().unwrap_or_else(|| json!({}));

        if !input.is_object() {
            return deny("the approve tool call carried an input that is not an object");
        }

        let bridge = match &self.bridge {
            Ok(bridge) => bridge.clone(),
            Err(reason) => {
                return deny(&format!(
                    "this approval bridge is not configured to reach a runtime ({reason}); \
                     `ouro mcp-serve` is started by the runtime, not by hand"
                ))
            }
        };

        let mut forwarded = Map::new();
        forwarded.insert("tool_name".into(), json!(tool_name));
        forwarded.insert("input".into(), input.clone());

        if let Some(tool_use_id) = request
            .get("tool_use_id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
        {
            forwarded.insert("tool_use_id".into(), json!(tool_use_id));
        }

        if let Some(cwd) = current_dir() {
            forwarded.insert("cwd".into(), json!(cwd));
        }

        let mut params = Map::new();
        params.insert("id".into(), json!(bridge.session_id));
        params.insert("request".into(), Value::Object(forwarded));

        if let Some(node) = &bridge.node {
            params.insert("node".into(), json!(node));
        }

        log(&format!("asking the runtime about {tool_name}"));

        match self
            .gateway
            .call(
                &bridge,
                APPROVAL_METHOD,
                Value::Object(params),
                bridge.timeout,
            )
            .await
        {
            Ok(answer) => decision(&answer, input),
            Err(reason) => deny(&format!("Ouroboros could not ask: {reason}")),
        }
    }
}

/// Maps the runtime's answer onto the permission-prompt tool's behaviour object. Anything
/// that is not an explicit `"allow"` is a denial, including a shape this build does not
/// recognise: a decision that cannot be read is not a decision to run the tool.
fn decision(answer: &Value, input: Value) -> Value {
    let decision = answer.get("decision").and_then(Value::as_str).unwrap_or("");
    let reason = answer
        .get("reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.trim().is_empty());
    let source = answer.get("source").and_then(Value::as_str);

    if decision == "allow" {
        return json!({"behavior": "allow", "updatedInput": input});
    }

    let mut message = match (decision, source) {
        ("deny", Some(source)) => format!("Ouroboros denied this ({source})"),
        ("deny", None) => "Ouroboros denied this".to_string(),
        (other, _) => {
            format!("Ouroboros answered {other:?}, which this bridge cannot read as a decision")
        }
    };

    if let Some(reason) = reason {
        message.push_str(": ");
        message.push_str(reason);
    }

    deny(&message)
}

fn deny(message: &str) -> Value {
    json!({"behavior": "deny", "message": message})
}

/// The behaviour object rides inside a text content block, JSON-encoded, which is the
/// shape the permission prompt tool's caller parses.
fn tool_result(behavior: Value) -> Value {
    let text = serde_json::to_string(&behavior).unwrap_or_else(|_unencodable| {
        r#"{"behavior":"deny","message":"Ouroboros could not encode its own decision"}"#.to_string()
    });

    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

fn tool_descriptor() -> Value {
    json!({
        "name": TOOL_NAME,
        "title": "Ask Ouroboros for permission",
        "description": "Ask the Ouroboros session that started this agent whether one \
                        tool call may run. Answers with the permission-prompt behaviour \
                        object: allow with the input to run, or deny with a reason. \
                        Ouroboros is the approver; this tool never decides on its own.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "The tool the agent wants to use."
                },
                "input": {
                    "type": "object",
                    "description": "The arguments that tool would run with.",
                    "additionalProperties": true
                },
                "tool_use_id": {
                    "type": "string",
                    "description": "The id of the tool call being asked about."
                }
            },
            "required": ["tool_name", "input"],
            "additionalProperties": true
        }
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
            "title": "Ouroboros approvals",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Ouroboros serves one tool: approve. It is the permission prompt \
                         for this session and is called by the agent harness, not by the \
                         model."
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

fn current_dir() -> Option<String> {
    std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
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
