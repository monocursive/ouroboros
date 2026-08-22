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

/// The permission prompt. `mcp__ouroboros__approve` is what `--permission-prompt-tool`
/// receives; it is called by the harness, never by the model.
pub const TOOL_NAME: &str = "approve";

/// The three tools the *model* may call: the runtime's language-server pool, offered to a
/// vendor agent that has no code intelligence of its own (E3).
pub const CODE_INTEL_TOOL: &str = "code_intel";
pub const DIAGNOSTICS_TOOL: &str = "diagnostics";
pub const TOUCH_TOOL: &str = "touch";

/// The gateway method the permission tool forwards to.
pub const APPROVAL_METHOD: &str = "interactive.request_approval";

/// The methods the three code-intelligence tools forward to, and the one they need first:
/// a tool call names a path, and only the session knows which workspace that path is in.
pub const INFO_METHOD: &str = "interactive.info";
pub const REQUEST_METHOD: &str = "code_intel.request";
pub const DIAGNOSTICS_METHOD: &str = "code_intel.diagnostics";
pub const TOUCH_METHOD: &str = "code_intel.touch";

/// The nine navigation operations, exactly as `Ouroboros.CodeIntel.operations/0` names
/// them. `diagnostics` is a tenth value of the same enum and is handled separately,
/// because it is the one operation that needs the document open first.
pub const NAVIGATION_OPERATIONS: [&str; 9] = [
    "definition",
    "references",
    "hover",
    "document_symbols",
    "workspace_symbols",
    "implementation",
    "prepare_call_hierarchy",
    "incoming_calls",
    "outgoing_calls",
];

/// Above the gateway's own 15s ceiling on the `code_intel.*` verbs, so a slow language
/// server is reported by the runtime that knows why rather than by a client stopwatch.
pub const CODE_INTEL_TIMEOUT: Duration = Duration::from_secs(20);

/// R4 §2's bounded wait: five seconds for a diagnostics push that matches the file's new
/// contents, then "no LSP data" and move on.
pub const DIAGNOSTICS_WAIT_MS: u64 = 5_000;

/// R4's noise bounds. Errors are always shown; warnings are capped because a file full of
/// style advice is how a useful signal gets ignored; the hard cap exists because thousands
/// of diagnostics in one file is a real shape (Claude Code v2.1.216).
pub const MAX_DIAGNOSTIC_LINES: usize = 20;
pub const MAX_WARNING_LINES: usize = 3;

/// Navigation answers are bounded by the runtime already (`max_results`, 200 by default);
/// this is the second bound, on what is worth putting in front of a model at once.
pub const MAX_NAVIGATION_LINES: usize = 50;

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
                        "the runtime refused the call ({}: {})",
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
    /// The session's workspace root, read once from `interactive.info` and held. A session
    /// cannot change the directory it was started in, so asking twice would be asking the
    /// runtime to repeat itself on every tool call.
    workspace: Option<String>,
}

impl Server {
    pub fn new(bridge: Result<Bridge, String>) -> Self {
        Self {
            bridge,
            gateway: Gateway::default(),
            workspace: None,
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
            TOOL_NAME => Ok(tool_result(self.approve(arguments).await)),
            CODE_INTEL_TOOL => Ok(text_result(self.code_intel(arguments).await)),
            DIAGNOSTICS_TOOL => Ok(text_result(self.diagnostics(arguments).await)),
            TOUCH_TOOL => Ok(text_result(self.touch(arguments).await)),
            other => Err((-32602, format!("unknown tool: {other}"))),
        }
    }

    // -----------------------------------------------------------------------
    // Code intelligence (E3)
    // -----------------------------------------------------------------------

    /// One of the nine navigation questions, or on-demand diagnostics for a file.
    async fn code_intel(&mut self, arguments: Value) -> Result<String, String> {
        let request = object(&arguments, CODE_INTEL_TOOL)?;
        let operation = string_argument(request, "operation")?;
        let path = string_argument(request, "path")?;

        // Argued before asked. A call this build cannot make is a message the model can act
        // on, and sending it to the runtime first would spend a round trip to learn what
        // the enum here already says.
        if operation != "diagnostics" && !NAVIGATION_OPERATIONS.contains(&operation.as_str()) {
            return Err(format!(
                "operation must be one of {}, diagnostics",
                NAVIGATION_OPERATIONS.join(", ")
            ));
        }

        let bridge = self.configured()?;
        let workspace = self.workspace(&bridge).await?;
        let path = in_workspace(&workspace, &path);

        if operation == "diagnostics" {
            // The pool never opens a document behind a caller's back, because opening one
            // is a decision about what a language server spends memory on. Asking "what is
            // broken in this file" is that decision, made out loud — and `ensure_open`
            // rather than `open`, because re-opening assigns a new version and a server
            // with nothing new to say never publishes for it, so the freshness gate would
            // answer "no LSP data" to every repeat of the same question.
            self.announce(&bridge, &workspace, &path, "ensure_open")
                .await?;
            let answer = self.read_diagnostics(&bridge, &workspace, &path).await?;

            return Ok(render_diagnostics(&path, &answer));
        }

        let mut params = Map::new();
        params.insert("workspace".into(), json!(workspace));
        params.insert("operation".into(), json!(operation));
        params.insert("path".into(), json!(path));
        params.insert("line".into(), json!(integer_argument(request, "line")));
        params.insert(
            "character".into(),
            json!(integer_argument(request, "character")),
        );

        if let Some(query) = optional_string(request, "query") {
            params.insert("query".into(), json!(query));
        }

        self.route(&bridge, &mut params);

        let answer = self
            .gateway
            .call(
                &bridge,
                REQUEST_METHOD,
                Value::Object(params),
                CODE_INTEL_TIMEOUT,
            )
            .await?;

        Ok(render_navigation(&operation, &path, &answer))
    }

    /// The post-edit read: announce the change, wait a bounded moment, report only what is
    /// new. The baseline comes back from the same call that announced the edit, so nothing
    /// can land between reading it and invalidating it.
    async fn diagnostics(&mut self, arguments: Value) -> Result<String, String> {
        let request = object(&arguments, DIAGNOSTICS_TOOL)?;
        let path = string_argument(request, "path")?;

        // Resolved before the answer is rendered as well as before it is asked for, so the
        // file named in the text is the file the runtime was actually asked about.
        let bridge = self.configured()?;
        let workspace = self.workspace(&bridge).await?;
        let path = in_workspace(&workspace, &path);

        match self.post_edit_diagnostics(&path).await? {
            PostEdit::NoData => Ok(format!("(no LSP data for {path})")),
            PostEdit::Fresh(items) if items.is_empty() => {
                Ok(format!("No new diagnostics in {path}."))
            }
            PostEdit::Fresh(items) => Ok(render_found(&path, &items, "new ")),
        }
    }

    /// The whole post-edit round trip, without any wording attached to it.
    ///
    /// Public because `ouro hook post-tool-use` performs exactly this sequence and must
    /// perform it the same way — but prints something else, because the hook's text is a
    /// contract with Claude Code while the tool's is a message to a model.
    pub async fn post_edit_diagnostics(&mut self, path: &str) -> Result<PostEdit, String> {
        let bridge = self.configured()?;
        let workspace = self.workspace(&bridge).await?;
        let path = &in_workspace(&workspace, path);

        let touched = self.announce(&bridge, &workspace, path, "changed").await?;
        let baseline = baseline_signatures(&touched);
        let answer = self.read_diagnostics(&bridge, &workspace, path).await?;

        if diagnostics_ready(&answer) {
            Ok(PostEdit::Fresh(new_diagnostics(&baseline, &answer)))
        } else {
            Ok(PostEdit::NoData)
        }
    }

    /// Announce an edit made outside the harness's own edit tools.
    async fn touch(&mut self, arguments: Value) -> Result<String, String> {
        let request = object(&arguments, TOUCH_TOOL)?;
        let path = string_argument(request, "path")?;
        let action = optional_string(request, "action").unwrap_or_else(|| "changed".to_string());

        if !["open", "ensure_open", "changed", "closed"].contains(&action.as_str()) {
            return Err("action must be one of open, ensure_open, changed, closed".to_string());
        }

        let bridge = self.configured()?;
        let workspace = self.workspace(&bridge).await?;
        let path = in_workspace(&workspace, &path);
        let touched = self.announce(&bridge, &workspace, &path, &action).await?;

        let version = touched
            .get("version")
            .and_then(Value::as_u64)
            .unwrap_or_default();

        Ok(format!(
            "The language server for {path} was told the file is {action} (version {version})."
        ))
    }

    /// `code_intel.touch`, which answers with the version it assigned and the picture that
    /// preceded it.
    async fn announce(
        &mut self,
        bridge: &Bridge,
        workspace: &str,
        path: &str,
        action: &str,
    ) -> Result<Value, String> {
        let mut params = Map::new();
        params.insert("workspace".into(), json!(workspace));
        params.insert("path".into(), json!(path));
        params.insert("action".into(), json!(action));
        self.route(bridge, &mut params);

        self.gateway
            .call(
                bridge,
                TOUCH_METHOD,
                Value::Object(params),
                CODE_INTEL_TIMEOUT,
            )
            .await
    }

    async fn read_diagnostics(
        &mut self,
        bridge: &Bridge,
        workspace: &str,
        path: &str,
    ) -> Result<Value, String> {
        let mut params = Map::new();
        params.insert("workspace".into(), json!(workspace));
        params.insert("path".into(), json!(path));
        params.insert("wait_ms".into(), json!(DIAGNOSTICS_WAIT_MS));
        self.route(bridge, &mut params);

        self.gateway
            .call(
                bridge,
                DIAGNOSTICS_METHOD,
                Value::Object(params),
                CODE_INTEL_TIMEOUT,
            )
            .await
    }

    /// The workspace the session was started in. A tool call names a path; the boundary
    /// that path is admitted against is the session's, not the tool's to choose.
    async fn workspace(&mut self, bridge: &Bridge) -> Result<String, String> {
        if let Some(workspace) = &self.workspace {
            return Ok(workspace.clone());
        }

        let mut params = Map::new();
        params.insert("id".into(), json!(bridge.session_id));
        self.route(bridge, &mut params);

        let info = self
            .gateway
            .call(
                bridge,
                INFO_METHOD,
                Value::Object(params),
                CODE_INTEL_TIMEOUT,
            )
            .await?;

        let workspace = info
            .get("workspace")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|workspace| !workspace.is_empty())
            .ok_or_else(|| "the runtime did not report a workspace for this session".to_string())?
            .to_string();

        self.workspace = Some(workspace.clone());
        Ok(workspace)
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

/// What the three model-facing tools answer with. A refusal is `isError` and says what
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
fn integer_argument(request: &Map<String, Value>, key: &str) -> u64 {
    request.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// A relative path is relative to the workspace, resolved here rather than on the runtime.
///
/// It has to be resolved by whoever knows what it is relative to, and that is this process:
/// the runtime would expand it against its own working directory, which is wherever the
/// daemon was started and has nothing to do with the session. A model writing `src/main.rs`
/// means the file in the workspace it was given, every time.
pub fn in_workspace(workspace: &str, path: &str) -> String {
    if std::path::Path::new(path).is_absolute() {
        return path.to_string();
    }

    std::path::Path::new(workspace)
        .join(path)
        .display()
        .to_string()
}

// ---------------------------------------------------------------------------
// The R4 §2 feedback policy, in one place
// ---------------------------------------------------------------------------

/// The signatures `code_intel.touch` reported for the file as it stood before the edit.
///
/// An absent or unreadable baseline is an empty one, which reports every current
/// diagnostic as new. That is the honest failure direction and it is a stated limit: the
/// first edit to a file the pool has never held over-reports its pre-existing errors once.
/// Hiding real errors to avoid that would be the worse trade.
pub fn baseline_signatures(touched: &Value) -> Vec<String> {
    touched
        .get("baseline")
        .and_then(|baseline| baseline.get("signatures"))
        .and_then(Value::as_array)
        .map(|signatures| {
            signatures
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the runtime answered with diagnostics that describe the file's current content.
///
/// `status: "pending"` is not a failure and not an empty list — it is "no LSP data yet",
/// and the two must never be rendered the same way.
pub fn diagnostics_ready(answer: &Value) -> bool {
    answer.get("status").and_then(Value::as_str) == Some("ok")
}

/// The new-only rule: current items the pre-edit baseline did not carry. Identity is the
/// runtime's `signature`, so there is exactly one definition of "the same diagnostic".
pub fn new_diagnostics(baseline: &[String], answer: &Value) -> Vec<Value> {
    items(answer)
        .into_iter()
        .filter(|item| match item.get("signature").and_then(Value::as_str) {
            Some(signature) => !baseline.iter().any(|seen| seen == signature),
            // A diagnostic with no signature cannot be matched against the baseline, and
            // showing it is the direction that cannot hide a real error.
            None => true,
        })
        .collect()
}

fn items(answer: &Value) -> Vec<Value> {
    answer
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// R4's noise bound, applied: every error, at most three warnings, at most twenty lines,
/// and one `+N more` covering everything the two caps left out.
pub fn diagnostic_lines(items: &[Value]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for item in items {
        match item.get("severity").and_then(Value::as_str) {
            Some("error") => errors.push(item),
            Some("warning") => warnings.push(item),
            _lower => {}
        }
    }

    let shown_warnings = warnings.len().min(MAX_WARNING_LINES);
    let mut selected: Vec<&Value> = errors;
    selected.extend(warnings.into_iter().take(shown_warnings));

    let kept = selected.len().min(MAX_DIAGNOSTIC_LINES);
    let omitted = items.len() - kept;

    let mut lines: Vec<String> = selected
        .into_iter()
        .take(kept)
        .map(diagnostic_line)
        .collect();

    if omitted > 0 {
        lines.push(format!("  +{omitted} more"));
    }

    lines
}

fn diagnostic_line(item: &Value) -> String {
    let severity = item
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("diagnostic");
    let message = item
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("");

    let mut line = format!("  {severity} {}", position_of(item));

    if let Some(code) = item.get("code").and_then(Value::as_str) {
        line.push_str(&format!(" [{code}]"));
    }

    line.push_str(&format!(" {message}"));
    line
}

/// `line:character`, converted to the 1-based numbers an editor shows. The protocol counts
/// from zero and the wire keeps it that way; a person reading a transcript does not.
fn position_of(item: &Value) -> String {
    let start = item
        .get("range")
        .or_else(|| item.get("item").and_then(|inner| inner.get("range")))
        .and_then(|range| range.get("start"));

    let line = start
        .and_then(|start| start.get("line"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let character = start
        .and_then(|start| start.get("character"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;

    format!("{line}:{character}")
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

/// What one post-edit read produced: either an answer that describes the file as it now
/// stands, or no answer at all inside the budget. The two are never the same thing, and a
/// caller that rendered them the same way would tell a model a file is clean when what
/// happened is that nobody looked.
#[derive(Debug, Clone)]
pub enum PostEdit {
    Fresh(Vec<Value>),
    NoData,
}

/// Everything the model reads about a set of diagnostics: the count, then the bounded
/// lines. `adjective` is `"new "` where the set was diffed against a baseline and empty
/// where it was not, so the sentence never claims a diff that did not happen.
pub fn render_found(path: &str, found: &[Value], adjective: &str) -> String {
    let count = found.len();
    let mut text = format!(
        "Found {count} {adjective}diagnostic issue{} in {path}:",
        plural(count)
    );

    for line in diagnostic_lines(found) {
        text.push('\n');
        text.push_str(&line);
    }

    text
}

/// One on-demand diagnostics answer: what the server says is wrong with the file now.
fn render_diagnostics(path: &str, answer: &Value) -> String {
    if !diagnostics_ready(answer) {
        return format!("(no LSP data for {path})");
    }

    let found = items(answer);

    if found.is_empty() {
        return format!("No diagnostics in {path}.");
    }

    render_found(path, &found, "")
}

/// One navigation answer. Each item is a place plus whatever the operation names it: a
/// symbol, a call, a hover string. An item this build has no shape for is printed as its
/// own JSON rather than dropped.
fn render_navigation(operation: &str, path: &str, answer: &Value) -> String {
    let items = items(answer);

    if items.is_empty() {
        return format!("No {operation} results for {path}.");
    }

    let truncated = answer
        .get("truncated")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    let count = items.len();
    let mut text = format!("{count} {operation} result{}:", plural(count));

    for item in items.iter().take(MAX_NAVIGATION_LINES) {
        text.push('\n');
        text.push_str(&navigation_line(item));
    }

    let omitted = count.saturating_sub(MAX_NAVIGATION_LINES) as u64 + truncated;

    if omitted > 0 {
        text.push_str(&format!("\n  +{omitted} more"));
    }

    text
}

fn navigation_line(item: &Value) -> String {
    // A call hierarchy answer wraps the place one level down, under `item`.
    let place = item.get("item").unwrap_or(item);

    let Some(path) = place.get("path").and_then(Value::as_str) else {
        // Hover has no path of its own: it is a string about the position you asked at.
        if let Some(value) = item.get("value").and_then(Value::as_str) {
            return format!("  {}", value.trim());
        }

        return format!(
            "  {}",
            serde_json::to_string(item).unwrap_or_else(|_unencodable| "?".to_string())
        );
    };

    let mut line = format!("  {path}:{}", position_of(place));

    if place.get("external").and_then(Value::as_bool) == Some(true) {
        line.push_str(" [outside the workspace]");
    }

    if let Some(name) = place.get("name").and_then(Value::as_str) {
        line.push(' ');
        line.push_str(name);
    }

    if let Some(kind) = place.get("kind").and_then(Value::as_str) {
        line.push_str(&format!(" ({kind})"));
    }

    if let Some(container) = place.get("container").and_then(Value::as_str) {
        line.push_str(&format!(" in {container}"));
    }

    if let Some(detail) = place.get("detail").and_then(Value::as_str) {
        line.push_str(&format!(" — {detail}"));
    }

    line
}

fn tool_descriptors() -> Vec<Value> {
    vec![
        tool_descriptor(),
        code_intel_descriptor(),
        diagnostics_descriptor(),
        touch_descriptor(),
    ]
}

/// The description is written for the model, and R4 §(d) is why it says when *not* to call
/// this: Serena's own numbers show a small edit costs 4.5× the payload through a code-intel
/// tool, and an independent benchmark found a simple find-a-rule task four times more
/// expensive through one. References, call hierarchies, and multi-file changes are where
/// the tool wins by an order of magnitude; a lookup in a file already in context is not.
fn code_intel_descriptor() -> Value {
    let mut operations: Vec<&str> = NAVIGATION_OPERATIONS.to_vec();
    operations.push("diagnostics");

    json!({
        "name": CODE_INTEL_TOOL,
        "title": "Ask this workspace's language server",
        "description": "Ask the language server Ouroboros already runs for this workspace \
                        about the symbol at a position. Reach for it when reading files \
                        would be unreliable or expensive: every reference to a symbol \
                        before renaming it, who calls a function, where an interface is \
                        implemented, and any change spanning several files. For a single \
                        lookup in a file you have already read, grep and reading are \
                        cheaper and just as correct. `diagnostics` reports what the server \
                        currently says is wrong with one file. Positions are 0-based, as \
                        the Language Server Protocol reports them; results are printed \
                        1-based. Paths may be absolute or relative to the workspace root. \
                        A missing language server is an ordinary answer, never a failure \
                        of your edit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": operations,
                    "description": "Which question to ask."
                },
                "path": {
                    "type": "string",
                    "description": "The file the position is in."
                },
                "line": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "0-based line. Omit for document_symbols, workspace_symbols and diagnostics."
                },
                "character": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "0-based character on that line."
                },
                "query": {
                    "type": "string",
                    "description": "The search string, for workspace_symbols."
                }
            },
            "required": ["operation", "path"],
            "additionalProperties": false
        }
    })
}

fn diagnostics_descriptor() -> Value {
    json!({
        "name": DIAGNOSTICS_TOOL,
        "title": "New diagnostics for a file you changed",
        "description": "Tell the language server one file changed, wait up to five seconds, \
                        and report only the diagnostics that were not there before. Use it \
                        after editing a file, or after changing one with a shell command or \
                        a code generator. It never blocks and never fails an edit: with no \
                        server for the file, or no answer in time, it says there is no LSP \
                        data and you should carry on.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file that changed."
                }
            },
            "required": ["path"],
            "additionalProperties": false
        }
    })
}

fn touch_descriptor() -> Value {
    json!({
        "name": TOUCH_TOOL,
        "title": "Announce a file change to the language server",
        "description": "Tell Ouroboros that a file changed on disk, so later diagnostics \
                        and navigation describe its new contents. Only needed for changes \
                        made outside your own edit tools — a shell command, a generator, a \
                        branch switch. Use the diagnostics tool instead when you want to \
                        know what the change broke.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The file that changed."
                },
                "action": {
                    "type": "string",
                    "enum": ["changed", "open", "ensure_open", "closed"],
                    "description": "Defaults to changed. Use ensure_open to make a file \
                                    readable without claiming it changed."
                }
            },
            "required": ["path"],
            "additionalProperties": false
        }
    })
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
