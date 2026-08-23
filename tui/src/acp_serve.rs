//! `ouro acp`: Ouroboros as an Agent Client Protocol agent on stdio.
//!
//! ## What this is
//!
//! ACP (<https://agentclientprotocol.com>, version 1) is the protocol Zed, JetBrains,
//! Neovim, Emacs and VS Code use to host a coding agent inside an editor: newline-framed
//! JSON-RPC 2.0 over the agent process's stdio, with the *editor* as the JSON-RPC client
//! and the agent as the server. This module is that server. Underneath it, nothing
//! changes: the editor's `session/new` is an `interactive.start` on the gateway, its
//! `session/prompt` is an `interactive.send_message`, and the session it drives is the
//! same durable session `ouro` and `ouro run` drive. The runtime stays the single
//! authority; this is a dialect, not a second brain.
//!
//! Ouroboros is already an ACP *client* — `Ouroboros.Provider.Session.Dialect.ACP` speaks
//! this protocol *to* Gemini CLI, OpenCode and Kimi. That module and this one are the two
//! ends of the same wire, and where they disagree the published schema wins; the
//! disagreements are named in the comments below rather than smoothed over.
//!
//! ## What it advertises, and why each claim is true
//!
//! `initialize` answers `protocolVersion: 1` and an `agentCapabilities` that claims as
//! little as this bridge can prove:
//!
//! * **`loadSession: false`.** ACP requires an agent that advertises it to replay *the
//!   entire* conversation as `session/update` notifications before answering. Ouroboros
//!   retains a bounded event window per session and answers `cursor_pruned` below it
//!   ([`crate::model::CursorPruned`]), so a replay of an older session would be a prefix
//!   the editor could not tell from the whole. Advertising the capability and then
//!   silently truncating history is the one thing worse than not having it.
//! * **`promptCapabilities.image`/`audio`/`embeddedContext: false`.** The gateway's
//!   `interactive.send_message` takes a string or a closed `{prompt, attachments,
//!   reasoning_effort}` object whose attachments are *paths inside the session's leased
//!   workspace* — it takes no inline bytes at all. A base64 image block could only be
//!   honoured by writing a file into the operator's workspace behind their back, so it is
//!   refused instead. `text` and `resource_link` need no capability flag and are both
//!   served: a `file://` resource link becomes an attachment path.
//! * **`mcpCapabilities`: neither `http` nor `sse`.** `interactive.start`'s option
//!   allowlist has no `mcp_config` key at all — it is *deliberately* absent
//!   (`Gateway.Methods` `@start_options`), because an inline server command inside a
//!   durable checkpoint is an execution vector. So a `session/new` carrying `mcpServers`
//!   is answered, the session is started, and the servers are reported as **not applied**
//!   in an `agent_message_chunk`. They are never dropped in silence.
//! * **`authMethods: []`.** Authentication is the vendor CLI's or the runtime's, settled
//!   before this process starts; there is nothing for the editor to log into.
//!
//! ## The editor's own services are acknowledged and unused
//!
//! An ACP client may offer `fs/read_text_file`, `fs/write_text_file` and `terminal/*` so
//! the agent can work through the editor's buffers. Ouroboros does its file and process
//! work in the runtime, behind its own workspace lease, sandbox and permission engine —
//! routing a tool through the editor would move it outside all three. So the capabilities
//! the editor declares are recorded (they are part of the handshake) and never called,
//! and the editor learns what changed on disk from `tool_call_update` content instead.
//! That is a stated limit, not an oversight.
//!
//! ## One connection, and the same resync discipline as `ouro run`
//!
//! There is exactly one gateway connection for the process's lifetime. Every session
//! subscribes from its own cursor, out-of-order events are held until the gap under them
//! is replayed (`interactive.replay`), and a `stream.lagged` frame replays from the
//! contiguous high-water mark. The loop is copied from [`crate::run`] rather than shared:
//! `run.rs` folds events into a result object and this folds them into notifications, and
//! a shared abstraction over both would be an abstraction over nothing.
//!
//! ## Bounded, and fail-closed
//!
//! Every editor frame is validated before it reaches the gateway; an unknown method is
//! `-32601`, a frame that is not a request is `-32600`, a line over the ceiling is
//! refused without being buffered. At most [`MAX_SESSIONS`] sessions, at most
//! [`MAX_PERMISSIONS`] outstanding permission questions, at most [`MAX_PENDING`]
//! out-of-order events per session. stdin EOF interrupts every in-flight turn, says so in
//! a last `agent_message_chunk`, resolves the outstanding prompts as `cancelled`, and
//! exits.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::model::{self, ApprovalDecision, ApprovalScope, Event, EventType};
use crate::proto::{ErrorCode, Hello, Notification};
use crate::transport::{Client, ClientError, LineReader};

/// The ACP revision this agent implements. A number, not a date string: ACP versions its
/// protocol as an integer and `1` is what `Dialect.ACP` sends as a client.
pub const PROTOCOL_VERSION: u64 = 1;

/// The most one editor frame may be. A prompt carries text and file references, not a
/// file; a line that never ends is a peer growing this process's memory on its say-so.
pub const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// `interactive.start` declares a 120s gateway ceiling because provider readiness is
/// `:infinity` upstream. The same number `ouro run` uses, for the same reason.
const START_TIMEOUT: Duration = Duration::from_secs(130);

/// The gateway refuses a replay limit above 500.
const REPLAY_LIMIT: u64 = 500;

/// How many replay rounds one gap may cost before this agent stops asking.
const MAX_RESYNC_ROUNDS: u32 = 40;

/// Ceiling on out-of-order events held per session while a gap is being replayed.
pub const MAX_PENDING: usize = 10_000;

/// How many sessions one editor may hold open through one `ouro acp`.
pub const MAX_SESSIONS: usize = 32;

/// Outstanding permission questions, matching the runtime's own per-session bound.
pub const MAX_PERMISSIONS: usize = 8;

/// Ceiling on one `agent_message_chunk`, matching the transcript's own draft bound.
const CHUNK_BYTES: usize = 128 * 1024;

/// Ceiling on the calls this agent makes while it is already ending.
const INTERRUPT_CEILING: Duration = Duration::from_secs(5);

/// Tool calls remembered per session, so a `tool_call_update` names an id the editor saw.
const MAX_TOOLS: usize = 512;

const VERBOSE_ENV: &str = "OUROBOROS_ACP_VERBOSE";

/// stderr, and only when asked. stdout is the protocol and carries nothing else.
fn log(message: &str) {
    if std::env::var(VERBOSE_ENV).is_ok_and(|value| value == "1") {
        eprintln!("ouro acp: {message}");
    }
}

// ---------------------------------------------------------------------------
// What the command line said
// ---------------------------------------------------------------------------

/// The start intent every `session/new` inherits. The editor supplies `cwd`; everything
/// else is the operator's, stated once when they registered this agent with their editor.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// A provider this runtime serves. Required: this bridge will not let an editor's
    /// default decide which vendor runs the operator's code.
    pub provider: String,
    /// Used only when the editor's `session/new` names no `cwd`.
    pub workspace: Option<String>,
    pub approval_mode: Option<String>,
    pub sandbox_mode: Option<String>,
}

/// What the editor said it can do for us. Recorded because it is part of the handshake,
/// and deliberately never acted on — see the module docs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EditorServices {
    pub read_text_file: bool,
    pub write_text_file: bool,
    pub terminal: bool,
}

impl EditorServices {
    fn decode(params: &Value) -> Self {
        let capabilities = params.get("clientCapabilities");
        let fs = capabilities.and_then(|value| value.get("fs"));

        Self {
            read_text_file: flag(fs, "readTextFile"),
            write_text_file: flag(fs, "writeTextFile"),
            terminal: capabilities
                .and_then(|value| value.get("terminal"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }

    fn any(&self) -> bool {
        self.read_text_file || self.write_text_file || self.terminal
    }
}

fn flag(value: Option<&Value>, key: &str) -> bool {
    value
        .and_then(|value| value.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

/// One row of `session/new`'s `modes.availableModes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mode {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// The mode vocabulary, derived from what `interactive.configure` would accept.
///
/// Four of the five ids are `Gateway.Methods` `@approval_modes` verbatim; the fifth is
/// `plan`, which is `interactive.configure`'s fifth field (`@configuration_options`) and
/// not an approval mode. Nothing here is advertised on a hunch:
///
/// * the approval modes are offered only where the session's own
///   `options.capabilities.dynamic_configuration` is truthy — the exact gate
///   `Ouroboros.Provider.session_configuration/3` applies before anything else;
/// * `prompt` is additionally gated on `capabilities.approvals`, because
///   `interactive.start`/`configure` answer `["unsupported_approval_mode", …]` where no
///   transport can carry a question to a person;
/// * `plan` is offered only for the one provider whose plan mode `Ouroboros.Provider.plan_mode/2`
///   reports as `settable: :any_time`. `claude` is `:at_start` (a mid-session change is
///   refused), `codex` is `:pending`, and every other provider is
///   `transport_cannot_plan` — so none of them are offered a mode they would refuse.
///
/// A refusal that happens anyway is relayed to the editor verbatim rather than swallowed.
pub fn modes_for(provider: &str, capabilities: Option<&Value>, planning: bool) -> Vec<Mode> {
    let configurable = capability(capabilities, "dynamic_configuration");
    let approvals = capability(capabilities, "approvals");
    let mut modes = Vec::new();

    // Plan is not an approval mode and does not travel on `dynamic_configuration`: it is
    // its own field with its own per-provider answer.
    if plan_settable(provider) || planning {
        modes.push(Mode {
            id: "plan".into(),
            name: "Plan".into(),
            description: "Read-only; produces a plan and asks before building it".into(),
        });
    }

    if configurable {
        if approvals {
            modes.push(Mode {
                id: "prompt".into(),
                name: "Ask first".into(),
                description: "Ask before every action".into(),
            });
        }

        modes.push(Mode {
            id: "auto_edit".into(),
            name: "Accept edits".into(),
            description: "Edit files without asking; ask for anything else".into(),
        });
        modes.push(Mode {
            id: "auto_approve".into(),
            name: "Accept all".into(),
            description: "Never ask".into(),
        });
        modes.push(Mode {
            id: "default".into(),
            name: "Provider default".into(),
            description: "Whatever the provider does on its own".into(),
        });
    }

    modes
}

/// Whether a mid-session `interactive.configure {plan: …}` is accepted for this provider.
///
/// Transcribed from `Ouroboros.Provider.plan_mode/2`'s own `plan_support/1` table, the
/// same way [`crate::model::ApprovalMode`] transcribes `@approval_modes`, because there is
/// no capability key that reports it. Wrong here is visible: the runtime refuses and the
/// refusal reaches the editor.
fn plan_settable(provider: &str) -> bool {
    provider == "native"
}

fn capability(capabilities: Option<&Value>, key: &str) -> bool {
    match capabilities.and_then(|value| value.get(key)) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
        Some(_other) => true,
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// The editor's in-flight `session/prompt`, waiting for a turn-terminal event.
#[derive(Debug, Clone)]
struct Prompt {
    /// The JSON-RPC id the answer must carry.
    id: Value,
    /// The caller-minted durable turn id — the gateway's reconciliation key.
    turn_id: String,
    /// The id the provider's own events carry, once the send named it.
    harness_turn: Option<String>,
    /// A `session/cancel` was asked for; whatever the stream says, this ends `cancelled`.
    cancelled: bool,
    /// The send could not be reconciled. Only a turn-terminal event clears it.
    unreconciled: Option<String>,
}

/// One open session: the ouroboros session, and everything the editor has been told.
#[derive(Debug)]
struct Session {
    id: String,
    node: Option<String>,
    provider: String,
    cursor: u64,
    pending: BTreeMap<u64, Event>,
    rounds: u32,
    prompt: Option<Prompt>,
    /// Tool call ids already announced, so an update names one the editor has seen.
    tools: VecDeque<String>,
    /// The most recently announced tool call, which an untied `file_change` attaches to.
    last_tool: Option<String>,
    /// Whether a delta has been streamed since the last final, so a provider that emits
    /// only a final message is not silently dropped and one that streams is not doubled.
    streamed: bool,
    /// A monotonic counter for the tool call ids this bridge has to invent.
    minted: u64,
    modes: Vec<Mode>,
    current_mode: Option<String>,
    planning: bool,
}

impl Session {
    fn routed(&self, params: Value) -> Value {
        let mut params = params;

        if let (Some(node), Some(fields)) = (self.node.as_deref(), params.as_object_mut()) {
            fields.insert("node".into(), Value::String(node.to_string()));
        }

        params
    }

    fn knows_tool(&self, id: &str) -> bool {
        self.tools.iter().any(|known| known == id)
    }

    fn remember_tool(&mut self, id: String) {
        if self.knows_tool(&id) {
            self.last_tool = Some(id);
            return;
        }

        if self.tools.len() >= MAX_TOOLS {
            self.tools.pop_front();
        }

        self.last_tool = Some(id.clone());
        self.tools.push_back(id);
    }

    fn mint_tool_id(&mut self) -> String {
        self.minted += 1;
        format!("ouro-{}-{}", self.id, self.minted)
    }
}

/// One permission question this agent asked the editor and has not been answered on.
#[derive(Debug, Clone)]
struct Permission {
    session_id: String,
    /// The id the runtime's `approval_requested` carried.
    request_id: String,
    /// What each `optionId` this agent offered means to `interactive.respond_approval`.
    answers: BTreeMap<String, Answer>,
}

/// What selecting one permission option turns into on the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// A plain decision, with the scope "don't ask again in this session" implies.
    Decision {
        decision: ApprovalDecision,
        scope: ApprovalScope,
    },
    /// A plan-exit answer, carried as `provider_options.choice` so the runtime applies
    /// exactly what was picked rather than inferring it from a decision.
    Choice(String),
    /// An `ask_user` answer: the option's own text, carried as `reason`, which is where
    /// `Ouroboros.Provider.Native.Tools.AskUser` reads it from.
    Reason(String),
}

// ---------------------------------------------------------------------------
// The agent
// ---------------------------------------------------------------------------

/// The ACP server, as a value a test can drive one frame at a time.
pub struct Agent {
    client: Client,
    hello: Hello,
    options: Options,
    services: Option<EditorServices>,
    sessions: BTreeMap<String, Session>,
    permissions: BTreeMap<String, Permission>,
    /// Ids for the requests this agent sends *to* the editor.
    outbound: u64,
}

/// One thing to write on stdout: a JSON-RPC frame, already encoded as a value.
pub type Frame = Value;

impl Agent {
    pub fn new(client: Client, hello: Hello, options: Options) -> Self {
        Self {
            client,
            hello,
            options,
            services: None,
            sessions: BTreeMap::new(),
            permissions: BTreeMap::new(),
            outbound: 0,
        }
    }

    /// The methods this bridge needs, checked once so a session/new does not discover it
    /// halfway. `interactive.configure` is not in the list: without it there are simply no
    /// modes to advertise.
    pub fn unserved(&self) -> Vec<&'static str> {
        [
            "interactive.start",
            "interactive.info",
            "interactive.subscribe",
            "interactive.replay",
            "interactive.send_message",
            "interactive.interrupt",
            "interactive.respond_approval",
        ]
        .into_iter()
        .filter(|method| !self.hello.serves(method))
        .collect()
    }

    // ----- inbound from the editor ---------------------------------------------------

    /// Answers one line from the editor. Frames to write, in order; empty where ACP says
    /// nothing is owed yet — a `session/prompt` is answered when its turn ends, not here.
    pub async fn handle_line(&mut self, line: &str) -> Vec<Frame> {
        let line = line.trim();

        if line.is_empty() {
            return Vec::new();
        }

        let message: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                return vec![error_frame(
                    Value::Null,
                    -32700,
                    &format!("invalid JSON: {error}"),
                )]
            }
        };

        // A response to something this agent asked. The only questions it asks are
        // permission requests.
        if message.get("method").is_none() {
            if let Some(id) = message.get("id") {
                return self.permission_answer(id.clone(), &message).await;
            }

            return vec![error_frame(
                Value::Null,
                -32600,
                "a frame with neither a method nor an id is not a JSON-RPC message",
            )];
        }

        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let id = message.get("id").cloned();

        // A notification: acted on, never answered.
        let Some(id) = id.filter(|id| !id.is_null()) else {
            return self.notification(&method, params).await;
        };

        match self.dispatch(&method, params, &id).await {
            Ok(None) => Vec::new(),
            Ok(Some(result)) => vec![result_frame(id, result)],
            Err(refusal) => vec![error_frame(id, refusal.code, &refusal.message)],
        }
    }

    async fn notification(&mut self, method: &str, params: Value) -> Vec<Frame> {
        match method {
            // The spec's own name for "stop what you are doing". A notification, so there
            // is nothing to answer: the in-flight `session/prompt` resolves `cancelled`.
            "session/cancel" => self.cancel(&params).await,
            other => {
                log(&format!("notification {other} ignored"));
                Vec::new()
            }
        }
    }

    async fn dispatch(
        &mut self,
        method: &str,
        params: Value,
        id: &Value,
    ) -> Result<Option<Value>, Refusal> {
        // `initialize` first, as the spec requires; everything else before it is refused
        // rather than answered from a handshake that has not happened.
        if method != "initialize" && self.services.is_none() {
            return Err(Refusal::new(
                -32600,
                "initialize must be the first method on an ACP connection",
            ));
        }

        match method {
            "initialize" => Ok(Some(self.initialize(&params))),
            "authenticate" => Err(Refusal::new(
                -32601,
                "this agent advertises no authentication methods; authentication is settled \
                 before `ouro acp` starts",
            )),
            "session/new" => self.session_new(params).await.map(Some),
            "session/prompt" => self.session_prompt(params, id).await,
            "session/set_mode" => self.session_set_mode(params).await.map(Some),
            "session/load" => Err(Refusal::new(
                -32601,
                "this agent does not advertise loadSession: Ouroboros retains a bounded \
                 event window per session, so it cannot promise to replay a whole \
                 conversation",
            )),
            other => Err(Refusal::new(-32601, &format!("method not found: {other}"))),
        }
    }

    // ----- initialize ----------------------------------------------------------------

    fn initialize(&mut self, params: &Value) -> Value {
        let services = EditorServices::decode(params);
        self.services = Some(services);

        if services.any() {
            log(
                "the editor offers fs/terminal services; they are acknowledged and unused — \
                 Ouroboros does its own file and process work inside the runtime",
            );
        }

        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "agentCapabilities": {
                "loadSession": false,
                "promptCapabilities": {
                    "image": false,
                    "audio": false,
                    "embeddedContext": false
                },
                "mcpCapabilities": {
                    "http": false,
                    "sse": false
                }
            },
            "agentInfo": {
                "name": "ouroboros",
                "title": "Ouroboros",
                "version": env!("CARGO_PKG_VERSION")
            },
            "authMethods": []
        })
    }

    // ----- session/new ---------------------------------------------------------------

    async fn session_new(&mut self, params: Value) -> Result<Value, Refusal> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Refusal::new(
                -32600,
                &format!("this agent holds {MAX_SESSIONS} sessions, which is its ceiling"),
            ));
        }

        let unserved = self.unserved();

        if !unserved.is_empty() {
            return Err(Refusal::new(
                -32601,
                &format!(
                    "this gateway does not serve {}; `ouro acp` needs every one of them",
                    unserved.join(", ")
                ),
            ));
        }

        if !self.hello.operates() {
            return Err(Refusal::new(
                -32601,
                &format!(
                    "this gateway is at scope `{}`; hosting a session mutates the runtime \
                     and needs OUROBOROS_GATEWAY_SCOPE=operate",
                    self.hello.scope
                ),
            ));
        }

        let provider = self.options.provider.trim();

        if provider.is_empty() {
            return Err(Refusal::new(
                -32600,
                "`ouro acp` was started without --provider, so there is no honest answer to \
                 which vendor should run this workspace's code",
            ));
        }

        let workspace = match params.get("cwd").and_then(Value::as_str) {
            Some(cwd) if !cwd.trim().is_empty() => cwd.trim().to_string(),
            _absent => match self.options.workspace.clone() {
                Some(workspace) => workspace,
                None => {
                    return Err(Refusal::new(
                        -32602,
                        "session/new needs an absolute `cwd`, and `ouro acp` was started \
                         without --workspace to fall back to",
                    ))
                }
            },
        };

        if !std::path::Path::new(&workspace).is_absolute() {
            return Err(Refusal::new(
                -32602,
                &format!("session/new's cwd must be absolute; got {workspace}"),
            ));
        }

        let session_id = model::new_session_id();
        let mut start = Map::new();
        start.insert("id".into(), json!(session_id));
        start.insert("provider".into(), json!(provider));
        start.insert("workspace".into(), json!(workspace));

        if let Some(mode) = self.options.approval_mode.as_deref() {
            start.insert("approval_mode".into(), json!(mode));
        }
        if let Some(mode) = self.options.sandbox_mode.as_deref() {
            start.insert("sandbox_mode".into(), json!(mode));
        }

        let started = self.start_call(Value::Object(start)).await?;

        let Some(started) = model::StartedRef::decode(&started) else {
            return Err(Refusal::new(
                -32603,
                &format!(
                    "the runtime answered client session {session_id} with a reference this \
                     build cannot read: {started}"
                ),
            ));
        };

        if started.id != session_id {
            return Err(Refusal::new(
                -32603,
                &format!(
                    "the runtime answered client session {session_id} with a different id \
                     {}; refusing to drive it because the start identity contract was \
                     violated",
                    started.id
                ),
            ));
        }

        if let Some(failure) = &started.start_failure {
            return Err(Refusal::new(
                -32603,
                &format!(
                    "created durable session {}, but it did not become ready: {failure}",
                    started.id
                ),
            ));
        }

        let mut session = Session {
            id: started.id.clone(),
            node: started.node.clone(),
            provider: provider.to_string(),
            cursor: 0,
            pending: BTreeMap::new(),
            rounds: 0,
            prompt: None,
            tools: VecDeque::new(),
            last_tool: None,
            streamed: false,
            minted: 0,
            modes: Vec::new(),
            current_mode: None,
            planning: false,
        };

        // What the session declares about itself decides which modes are honest to offer.
        // A read that fails costs the modes and nothing else: a session with no `modes` in
        // its `session/new` result is a session the editor will not offer a mode picker
        // for, which is exactly right when this bridge could not learn what it accepts.
        let info = self
            .client
            .call(
                "interactive.info",
                session.routed(json!({ "id": session.id })),
            )
            .await
            .ok();

        if let Some(info) = &info {
            let options = info.get("options");
            session.planning = options
                .and_then(|options| options.get("plan"))
                .and_then(Value::as_bool)
                == Some(true);
            session.modes = modes_for(
                provider,
                options.and_then(|options| options.get("capabilities")),
                session.planning,
            );
            session.current_mode = Some(current_mode(options, session.planning));
        }

        self.subscribe(&mut session, 0).await?;

        let mut result = Map::new();
        result.insert("sessionId".into(), json!(session.id));

        if !session.modes.is_empty() {
            let current = session
                .current_mode
                .clone()
                .unwrap_or_else(|| "default".to_string());

            // A current mode this agent did not advertise would be a picker with no
            // selected row. Where the session is in a mode it will not offer, the honest
            // answer is the mode list without a claim about which one is current — so the
            // list is dropped rather than the claim invented.
            if session.modes.iter().any(|mode| mode.id == current) {
                result.insert(
                    "modes".into(),
                    json!({
                        "currentModeId": current,
                        "availableModes": session
                            .modes
                            .iter()
                            .map(|mode| json!({
                                "id": mode.id,
                                "name": mode.name,
                                "description": mode.description,
                            }))
                            .collect::<Vec<_>>(),
                    }),
                );
            } else {
                session.modes.clear();
            }
        }

        let id = session.id.clone();
        let servers = mcp_server_names(&params);
        self.sessions.insert(id.clone(), session);

        // Said out loud, in the transcript the operator is reading, rather than dropped.
        if !servers.is_empty() {
            log(&format!("{} MCP servers were not applied", servers.len()));
        }

        Ok(Value::Object(result))
    }

    /// The start, with the exact same-id retry `ouro run` and `ouro new` perform.
    ///
    /// A transport failure or an upstream timeout may have happened *after* the gateway
    /// durably created the session, so the only safe recovery is replaying the identical
    /// request: it can adopt the same session or report a conflict, never bill a second.
    /// Copied from [`crate::run`] rather than shared, because that module is another
    /// agent's to change.
    async fn start_call(&self, params: Value) -> Result<Value, Refusal> {
        let first = self
            .client
            .call_with_timeout("interactive.start", params.clone(), START_TIMEOUT)
            .await;

        let first_error = match first {
            Ok(started) => return Ok(started),
            Err(error) => error,
        };

        if !model::start_outcome_unknown(&first_error) {
            return Err(Refusal::new(
                -32603,
                &format!("interactive.start was refused: {}", rendered(&first_error)),
            ));
        }

        match self
            .client
            .call_with_timeout("interactive.start", params, START_TIMEOUT)
            .await
        {
            Ok(started) => Ok(started),
            Err(retry) => Err(Refusal::new(
                -32603,
                &format!(
                    "the interactive.start outcome is unknown and the exact same-id retry \
                     did not settle it. Run `ouro` and inspect the sessions this runtime \
                     holds before asking for another. first attempt: {}; retry: {}",
                    rendered(&first_error),
                    rendered(&retry)
                ),
            )),
        }
    }

    async fn subscribe(&mut self, session: &mut Session, cursor: u64) -> Result<(), Refusal> {
        session.cursor = cursor;
        let params = session.routed(json!({ "id": session.id, "cursor": cursor }));

        match self.client.call("interactive.subscribe", params).await {
            Ok(_backlog) => Ok(()),
            Err(ClientError::Rpc(rpc)) => {
                if let Some(pruned) = model::CursorPruned::from_error_data(rpc.data.as_ref()) {
                    session.cursor = pruned.floor;
                    let params =
                        session.routed(json!({ "id": session.id, "cursor": pruned.floor }));

                    return self
                        .client
                        .call("interactive.subscribe", params)
                        .await
                        .map(|_backlog| ())
                        .map_err(|error| {
                            Refusal::new(
                                -32603,
                                &format!(
                                    "subscribing to {} was refused: {}",
                                    session.id,
                                    rendered(&error)
                                ),
                            )
                        });
                }

                Err(Refusal::new(
                    -32603,
                    &format!(
                        "subscribing to {} was refused: {}",
                        session.id,
                        model::refusal(&rpc)
                    ),
                ))
            }
            Err(error) => Err(Refusal::new(
                -32603,
                &format!("subscribing to {} failed: {}", session.id, rendered(&error)),
            )),
        }
    }

    // ----- session/prompt ------------------------------------------------------------

    async fn session_prompt(
        &mut self,
        params: Value,
        id: &Value,
    ) -> Result<Option<Value>, Refusal> {
        let session_id = session_id_of(&params)?;

        if !self.sessions.contains_key(&session_id) {
            return Err(Refusal::new(
                -32602,
                &format!("this agent holds no session {session_id}"),
            ));
        }

        if self
            .sessions
            .get(&session_id)
            .and_then(|session| session.prompt.as_ref())
            .is_some()
        {
            return Err(Refusal::new(
                -32600,
                &format!(
                    "session {session_id} already has a prompt in flight; ACP takes one \
                     turn at a time"
                ),
            ));
        }

        let blocks = params
            .get("prompt")
            .and_then(Value::as_array)
            .ok_or_else(|| Refusal::new(-32602, "session/prompt needs a `prompt` array"))?;

        let input = prompt_input(blocks)?;
        let turn_id = new_turn_id();

        let session = self
            .sessions
            .get_mut(&session_id)
            .expect("the session checked above");
        session.streamed = false;
        session.prompt = Some(Prompt {
            id: id.clone(),
            turn_id: turn_id.clone(),
            harness_turn: None,
            cancelled: false,
            unreconciled: None,
        });

        let params = session.routed(json!({
            "id": session_id,
            "input": input,
            "turn_id": turn_id,
        }));

        match self.send(&session_id, params).await {
            Ok(()) => Ok(None),
            Err(refusal) => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.prompt = None;
                }

                Err(refusal)
            }
        }
    }

    /// `interactive.send_message`, falling back to the queued verb where the session is
    /// busy, with the one safe reconciliation for an indeterminate outcome.
    async fn send(&mut self, session_id: &str, params: Value) -> Result<(), Refusal> {
        let mut method = "interactive.send_message";
        let mut attempt = self.client.call(method, params.clone()).await;

        // The one-in-flight rule is the runtime's, not this bridge's: a session busy with
        // a turn somebody else started queues rather than refuses, and `follow_up` is the
        // verb that says so.
        if is_busy(&attempt) && self.hello.serves("interactive.follow_up") {
            method = "interactive.follow_up";
            attempt = self.client.call(method, params.clone()).await;
        }

        let failure = match &attempt {
            Ok(value) => turn_failure(value),
            Err(error) => Some(SendFailure {
                rendered: rendered(error),
                outcome_unknown: send_outcome_unknown(error),
            }),
        };

        let Some(failure) = failure else {
            if let (Ok(value), Some(session)) = (&attempt, self.sessions.get_mut(session_id)) {
                adopt_harness_turn(session, value);
            }

            return Ok(());
        };

        if !failure.outcome_unknown {
            return Err(Refusal::new(
                -32603,
                &format!("the prompt was not accepted: {}", failure.rendered),
            ));
        }

        let retry = self.client.call(method, params).await;
        let retry_failure = match &retry {
            Ok(value) => turn_failure(value),
            Err(error) => Some(SendFailure {
                rendered: rendered(error),
                outcome_unknown: send_outcome_unknown(error),
            }),
        };

        match retry_failure {
            None => {
                if let (Ok(value), Some(session)) = (&retry, self.sessions.get_mut(session_id)) {
                    adopt_harness_turn(session, value);
                }

                Ok(())
            }
            Some(retry) if retry.outcome_unknown => {
                // Not an error: this agent is subscribed, so the stream may still resolve
                // the turn. What it may not do is disappear — an unresolved prompt is
                // reported as such when the session or the process ends.
                if let Some(session) = self.sessions.get_mut(session_id) {
                    if let Some(prompt) = session.prompt.as_mut() {
                        prompt.unreconciled = Some(format!(
                            "the prompt's outcome remains unknown after retrying turn {}; \
                             first attempt: {}; retry: {}",
                            prompt.turn_id, failure.rendered, retry.rendered
                        ));
                    }
                }

                Ok(())
            }
            Some(retry) => Err(Refusal::new(
                -32603,
                &format!("the prompt was not accepted: {}", retry.rendered),
            )),
        }
    }

    // ----- session/cancel ------------------------------------------------------------

    async fn cancel(&mut self, params: &Value) -> Vec<Frame> {
        let Some(session_id) = params.get("sessionId").and_then(Value::as_str) else {
            return Vec::new();
        };

        let Some(session) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };

        // Recorded before the call so a turn that ends while the interrupt is in flight is
        // still reported as the cancellation the editor asked for.
        if let Some(prompt) = session.prompt.as_mut() {
            prompt.cancelled = true;
        }

        let params = session.routed(json!({ "id": session.id }));
        let _ = self
            .client
            .call_with_timeout("interactive.interrupt", params, INTERRUPT_CEILING)
            .await;

        Vec::new()
    }

    // ----- session/set_mode ----------------------------------------------------------

    async fn session_set_mode(&mut self, params: Value) -> Result<Value, Refusal> {
        let session_id = session_id_of(&params)?;
        let mode = params
            .get("modeId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|mode| !mode.is_empty())
            .ok_or_else(|| Refusal::new(-32602, "session/set_mode needs a `modeId`"))?
            .to_string();

        let Some(session) = self.sessions.get(&session_id) else {
            return Err(Refusal::new(
                -32602,
                &format!("this agent holds no session {session_id}"),
            ));
        };

        if !session.modes.iter().any(|known| known.id == mode) {
            return Err(Refusal::new(
                -32602,
                &format!(
                    "{mode} is not a mode this session offers; session/new advertised {} for \
                     provider {}",
                    if session.modes.is_empty() {
                        "none".to_string()
                    } else {
                        session
                            .modes
                            .iter()
                            .map(|mode| mode.id.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    session.provider
                ),
            ));
        }

        if !self.hello.serves("interactive.configure") {
            return Err(Refusal::new(
                -32601,
                "this gateway does not serve interactive.configure",
            ));
        }

        let mut changes = Map::new();
        changes.insert("id".into(), json!(session_id));

        if mode == "plan" {
            changes.insert("plan".into(), Value::Bool(true));
        } else {
            changes.insert("approval_mode".into(), json!(mode));

            // Leaving plan mode is part of choosing an approval mode, and the two travel
            // in one call so the session is never briefly planning under a mode that says
            // otherwise. Sent only where this session was planning: a `plan: false` on a
            // provider that cannot plan is a key the runtime would refuse.
            if session.planning {
                changes.insert("plan".into(), Value::Bool(false));
            }
        }

        let params = session.routed(Value::Object(changes));

        match self.client.call("interactive.configure", params).await {
            Ok(_answer) => {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.planning = mode == "plan";
                    session.current_mode = Some(mode);
                }

                // The spec's result is an empty object; the `current_mode_update` the
                // editor renders comes from the runtime's own `configured` event, so a
                // change this call could not carry is never announced as one that landed.
                Ok(json!({}))
            }
            Err(ClientError::Rpc(rpc)) => Err(Refusal::new(-32603, &model::refusal(&rpc))),
            Err(error) => Err(Refusal::new(-32603, &rendered(&error))),
        }
    }

    // ----- permission answers --------------------------------------------------------

    /// The editor's answer to a `session/request_permission` this agent sent.
    async fn permission_answer(&mut self, id: Value, message: &Value) -> Vec<Frame> {
        let key = id_key(&id);

        let Some(permission) = self.permissions.remove(&key) else {
            log(&format!("an answer for unknown request {key} was ignored"));
            return Vec::new();
        };

        // An error response to a permission request is the editor saying it could not ask.
        // Fail closed: that is a denial, and the reason travels with it.
        let outcome = message
            .get("result")
            .and_then(|result| result.get("outcome"));

        let answer = match outcome {
            Some(outcome) if outcome.get("outcome").and_then(Value::as_str) == Some("selected") => {
                outcome
                    .get("optionId")
                    .and_then(Value::as_str)
                    .and_then(|chosen| permission.answers.get(chosen).cloned())
                    .unwrap_or(Answer::Decision {
                        decision: ApprovalDecision::Deny,
                        scope: ApprovalScope::Once,
                    })
            }
            _cancelled_or_error => Answer::Decision {
                decision: ApprovalDecision::Deny,
                scope: ApprovalScope::Once,
            },
        };

        let params = match self.sessions.get(&permission.session_id) {
            Some(session) => session.routed(respond_params(
                &permission.session_id,
                &permission.request_id,
                &answer,
            )),
            None => respond_params(&permission.session_id, &permission.request_id, &answer),
        };

        if let Err(error) = self
            .client
            .call("interactive.respond_approval", params)
            .await
        {
            log(&format!(
                "answering an approval failed: {}",
                rendered(&error)
            ));
        }

        Vec::new()
    }

    // ----- inbound from the gateway --------------------------------------------------

    /// Turns one gateway notification into the `session/update` frames it implies.
    pub async fn handle_notification(&mut self, notification: Notification) -> Vec<Frame> {
        match notification.method.as_str() {
            "interactive.event" => {
                let Some(session_id) = notification
                    .params
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                else {
                    return Vec::new();
                };

                if !self.sessions.contains_key(&session_id) {
                    return Vec::new();
                }

                let Some(event) = notification.params.get("event") else {
                    return Vec::new();
                };

                match Event::decode(event) {
                    Ok(event) => self.offer(&session_id, event).await,
                    Err(error) => {
                        log(&format!("an undecodable event was skipped: {error}"));
                        Vec::new()
                    }
                }
            }
            "stream.lagged" => {
                let Ok(lagged) = serde_json::from_value::<model::Lagged>(notification.params)
                else {
                    return Vec::new();
                };

                if !self.sessions.contains_key(&lagged.id) {
                    return Vec::new();
                }

                log(&format!(
                    "the gateway dropped {} frames for {}; replaying",
                    lagged.dropped, lagged.id
                ));

                self.replay(&lagged.id).await
            }
            "stream.ended" => {
                let Ok(ended) = serde_json::from_value::<model::Ended>(notification.params) else {
                    return Vec::new();
                };

                self.stream_ended(&ended)
            }
            other => {
                log(&format!("notification {other} ignored"));
                Vec::new()
            }
        }
    }

    /// Takes one event, emits everything that has become contiguous, and repairs a gap.
    async fn offer(&mut self, session_id: &str, event: Event) -> Vec<Frame> {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };

        if event.sequence <= session.cursor {
            // Already delivered. Replay windows overlap the live stream by design.
            return Vec::new();
        }

        if session.pending.len() >= MAX_PENDING {
            log("more out-of-order events than this agent will hold");
            return Vec::new();
        }

        session.pending.insert(event.sequence, event);
        let mut frames = self.drain(session_id);

        let gap = self
            .sessions
            .get(session_id)
            .map(|session| !session.pending.is_empty())
            .unwrap_or(false);

        if gap {
            frames.extend(self.replay(session_id).await);
        }

        frames
    }

    /// Emits every held event that now sits directly on the cursor.
    fn drain(&mut self, session_id: &str) -> Vec<Frame> {
        let mut frames = Vec::new();

        loop {
            let Some(session) = self.sessions.get_mut(session_id) else {
                return frames;
            };

            let Some((&sequence, _)) = session.pending.iter().next() else {
                return frames;
            };

            if sequence != session.cursor + 1 {
                return frames;
            }

            let event = session.pending.remove(&sequence).expect("the peeked entry");
            session.cursor = sequence;

            frames.extend(self.fold(session_id, &event));
        }
    }

    /// `interactive.replay` from the cursor, exactly as `ouro run` repairs a hole.
    async fn replay(&mut self, session_id: &str) -> Vec<Frame> {
        let mut frames = Vec::new();

        loop {
            let Some(session) = self.sessions.get_mut(session_id) else {
                return frames;
            };

            session.rounds += 1;

            if session.rounds > MAX_RESYNC_ROUNDS {
                log("this session produces history faster than `ouro acp` can replay it");
                return frames;
            }

            let asked_from = session.cursor;
            let params = session.routed(json!({
                "id": session_id,
                "cursor": asked_from,
                "limit": REPLAY_LIMIT,
            }));

            let answer = match self.client.call("interactive.replay", params).await {
                Ok(answer) => answer,
                Err(ClientError::Rpc(rpc)) => {
                    match model::CursorPruned::from_error_data(rpc.data.as_ref()) {
                        Some(pruned) if pruned.floor > asked_from => {
                            if let Some(session) = self.sessions.get_mut(session_id) {
                                session.cursor = pruned.floor;
                            }

                            frames.extend(self.drain(session_id));
                            continue;
                        }
                        _other => {
                            log(&format!(
                                "replaying {session_id} failed: {}",
                                model::refusal(&rpc)
                            ));
                            return frames;
                        }
                    }
                }
                Err(error) => {
                    log(&format!(
                        "replaying {session_id} failed: {}",
                        rendered(&error)
                    ));
                    return frames;
                }
            };

            let count = self.absorb(session_id, &answer, asked_from);
            frames.extend(self.drain(session_id));

            let Some(session) = self.sessions.get_mut(session_id) else {
                return frames;
            };

            if session.pending.is_empty() {
                // The budget is per interruption, not per session.
                session.rounds = 0;
                return frames;
            }

            if count == 0 || session.cursor == asked_from {
                log(&format!(
                    "{session_id} still has a gap above {}",
                    session.cursor
                ));
                return frames;
            }
        }
    }

    /// Absorbs a replay answer. Returns how many events it carried.
    fn absorb(&mut self, session_id: &str, value: &Value, asked_from: u64) -> usize {
        let (events, refused) = Event::decode_batch(value);

        if refused > 0 {
            log(&format!(
                "{refused} undecodable replayed events were skipped"
            ));
        }

        let Some(session) = self.sessions.get_mut(session_id) else {
            return 0;
        };

        // Both verbs answer "the retained events after this cursor, in order", so a first
        // entry above `asked_from + 1` proves the ones between are gone.
        if let Some(first) = events.first().map(|event| event.sequence) {
            if first > asked_from + 1 && session.cursor < first - 1 {
                log(&format!(
                    "{session_id}: events {}..{} are no longer retained",
                    asked_from + 1,
                    first - 1
                ));
                session.cursor = first - 1;
            }
        }

        let count = events.len();

        for event in events {
            if event.sequence <= session.cursor || session.pending.len() >= MAX_PENDING {
                continue;
            }

            session.pending.insert(event.sequence, event);
        }

        count
    }

    fn stream_ended(&mut self, ended: &model::Ended) -> Vec<Frame> {
        let Some(session) = self.sessions.get_mut(&ended.id) else {
            return Vec::new();
        };

        let Some(prompt) = session.prompt.take() else {
            return Vec::new();
        };

        // A turn-terminal event would have resolved the prompt before this frame arrived,
        // so whatever the session's own end was, this turn's end was not observed.
        vec![error_frame(
            prompt.id,
            -32603,
            &format!(
                "the event stream for {} ended ({}) before turn {} did; its outcome was not \
                 observed",
                ended.id,
                if ended.status.is_empty() {
                    "no status"
                } else {
                    &ended.status
                },
                prompt.turn_id
            ),
        )]
    }

    // ----- the mapping ---------------------------------------------------------------

    /// One normalised event, as the ACP frames it implies.
    ///
    /// This is the whole event → `session/update` table, in one function, so the mapping
    /// can be read in one place rather than inferred from six.
    fn fold(&mut self, session_id: &str, event: &Event) -> Vec<Frame> {
        let mut frames = Vec::new();

        match &event.kind {
            EventType::OutputTextDelta => {
                if let Some(text) = payload_text(&event.payload, &["text"]) {
                    if let Some(session) = self.sessions.get_mut(session_id) {
                        session.streamed = true;
                    }

                    frames.push(update(
                        session_id,
                        json!({
                            "sessionUpdate": "agent_message_chunk",
                            "content": {"type": "text", "text": text},
                        }),
                    ));
                }
            }
            EventType::OutputTextFinal => {
                // The deltas already carried it where there were any. A provider that
                // emits only a final — several managed transports do — would otherwise
                // have its whole answer dropped.
                let streamed = self
                    .sessions
                    .get(session_id)
                    .map(|session| session.streamed)
                    .unwrap_or(false);

                if let Some(session) = self.sessions.get_mut(session_id) {
                    session.streamed = false;
                }

                if !streamed {
                    if let Some(text) = payload_text(&event.payload, &["text"]) {
                        frames.push(update(
                            session_id,
                            json!({
                                "sessionUpdate": "agent_message_chunk",
                                "content": {"type": "text", "text": text},
                            }),
                        ));
                    }
                }
            }
            EventType::ThinkingDelta => {
                if let Some(text) = payload_text(&event.payload, &["text", "thinking", "reasoning"])
                {
                    frames.push(update(
                        session_id,
                        json!({
                            "sessionUpdate": "agent_thought_chunk",
                            "content": {"type": "text", "text": text},
                        }),
                    ));
                }
            }
            EventType::ToolCall => {
                let id = tool_call_id(&event.payload)
                    .unwrap_or_else(|| self.mint_tool_id(session_id, event.sequence));

                if let Some(session) = self.sessions.get_mut(session_id) {
                    session.remember_tool(id.clone());
                }

                frames.push(update(session_id, tool_call_update(&id, &event.payload)));
            }
            EventType::ToolResult => {
                let id = tool_call_id(&event.payload);

                match id.filter(|id| {
                    self.sessions
                        .get(session_id)
                        .map(|session| session.knows_tool(id))
                        .unwrap_or(false)
                }) {
                    Some(id) => {
                        frames.push(update(session_id, tool_result_update(&id, &event.payload)));
                    }
                    // A result for a call this bridge never announced. Announcing the call
                    // and completing it in one breath is the honest rendering: the tool
                    // ran, and the editor is told what it produced.
                    None => {
                        let id = tool_call_id(&event.payload)
                            .unwrap_or_else(|| self.mint_tool_id(session_id, event.sequence));

                        if let Some(session) = self.sessions.get_mut(session_id) {
                            session.remember_tool(id.clone());
                        }

                        frames.push(update(session_id, tool_call_update(&id, &event.payload)));
                        frames.push(update(session_id, tool_result_update(&id, &event.payload)));
                    }
                }
            }
            EventType::FileChange => {
                let (id, announce) = match self
                    .sessions
                    .get(session_id)
                    .and_then(|session| session.last_tool.clone())
                {
                    Some(id) => (id, false),
                    None => (self.mint_tool_id(session_id, event.sequence), true),
                };

                if announce {
                    if let Some(session) = self.sessions.get_mut(session_id) {
                        session.remember_tool(id.clone());
                    }

                    frames.push(update(
                        session_id,
                        json!({
                            "sessionUpdate": "tool_call",
                            "toolCallId": id,
                            "title": "Edit files",
                            "kind": "edit",
                            "status": "in_progress",
                        }),
                    ));
                }

                frames.push(update(session_id, file_change_update(&id, &event.payload)));
            }
            EventType::PlanUpdated => {
                frames.push(update(session_id, plan_update(&event.payload)));
            }
            EventType::ApprovalRequested => {
                frames.extend(self.request_permission(session_id, event));
            }
            EventType::ProviderEvent => {
                frames.extend(provider_event(session_id, &event.payload));
            }
            // `interactive.configure`'s own event. `Jido.Harness.Event` has no `:status`
            // type, so the runtime's `Event.from_runtime(:status, …)` arrives here as the
            // tolerant arm rather than as a named one.
            EventType::Other(name) if name == "status" => {
                if let Some(mode) = configured_mode(&event.payload) {
                    if let Some(session) = self.sessions.get_mut(session_id) {
                        session.current_mode = Some(mode.clone());
                        session.planning = mode == "plan";
                    }

                    frames.push(update(
                        session_id,
                        json!({"sessionUpdate": "current_mode_update", "currentModeId": mode}),
                    ));
                }
            }
            EventType::TurnCompleted => {
                frames.extend(self.settle(session_id, event, completed_stop_reason(&event.payload)))
            }
            EventType::TurnInterrupted => {
                frames.extend(self.settle(session_id, event, StopReason::Cancelled))
            }
            EventType::TurnFailed => frames.extend(self.fail(
                session_id,
                event,
                &format!("the turn failed: {}", event_detail(&event.payload)),
            )),
            EventType::SessionFailed => frames.extend(self.fail(
                session_id,
                event,
                &format!("the session failed: {}", event_detail(&event.payload)),
            )),
            EventType::SessionCancelled => {
                frames.extend(self.settle(session_id, event, StopReason::Cancelled))
            }
            EventType::SessionClosed => frames.extend(self.fail(
                session_id,
                event,
                "the session closed before the turn ended; its outcome was not observed",
            )),
            _other => {}
        }

        frames
    }

    fn mint_tool_id(&mut self, session_id: &str, sequence: u64) -> String {
        match self.sessions.get_mut(session_id) {
            Some(session) => session.mint_tool_id(),
            None => format!("ouro-{session_id}-{sequence}"),
        }
    }

    /// Resolves the in-flight prompt, if this event belongs to its turn.
    fn settle(&mut self, session_id: &str, event: &Event, reason: StopReason) -> Vec<Frame> {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Vec::new();
        };

        let Some(prompt) = session.prompt.as_ref() else {
            return Vec::new();
        };

        if !ours(prompt, event) {
            return Vec::new();
        }

        // An end this editor asked for keeps its own name: a `turn_completed` that lands
        // after a `session/cancel` is still the cancellation the editor is waiting on.
        let reason = if prompt.cancelled {
            StopReason::Cancelled
        } else {
            reason
        };

        let prompt = session.prompt.take().expect("the prompt checked above");
        session.streamed = false;

        // An unreconciled send that a terminal event resolved is reconciled. One that a
        // terminal event did *not* resolve never reaches here.
        vec![result_frame(
            prompt.id,
            json!({ "stopReason": reason.as_str() }),
        )]
    }

    /// Resolves the in-flight prompt as an error: a turn that failed did not stop for a
    /// reason ACP has a name for, and reporting `end_turn` there would be a lie.
    ///
    /// The one exception is a turn the editor cancelled. ACP is explicit that a cancelled
    /// prompt is answered `stopReason: "cancelled"` and **not** with a JSON-RPC error, so
    /// a failure that follows a `session/cancel` still resolves as the cancellation the
    /// editor is waiting for.
    fn fail(&mut self, session_id: &str, event: &Event, message: &str) -> Vec<Frame> {
        let cancelled = {
            let Some(session) = self.sessions.get(session_id) else {
                return Vec::new();
            };

            let Some(prompt) = session.prompt.as_ref() else {
                return Vec::new();
            };

            if !ours(prompt, event) {
                return Vec::new();
            }

            prompt.cancelled
        };

        if cancelled {
            return self.settle(session_id, event, StopReason::Cancelled);
        }

        let session = self
            .sessions
            .get_mut(session_id)
            .expect("the session checked above");
        let prompt = session.prompt.take().expect("the prompt checked above");
        session.streamed = false;

        let message = match &prompt.unreconciled {
            Some(unreconciled) => format!("{message}; {unreconciled}"),
            None => message.to_string(),
        };

        vec![error_frame(prompt.id, -32603, &message)]
    }

    /// One `approval_requested`, as the `session/request_permission` it becomes.
    fn request_permission(&mut self, session_id: &str, event: &Event) -> Vec<Frame> {
        let Some(request_id) = event.request_id.clone().filter(|id| !id.is_empty()) else {
            log("an approval request carried no request id and cannot be answered");
            return Vec::new();
        };

        if self.permissions.len() >= MAX_PERMISSIONS {
            log("more outstanding permission questions than this agent will hold");
            return Vec::new();
        }

        let (options, answers) = permission_options(&event.payload);

        // Which tool call this is about. The runtime raises the question *between* the
        // `tool_call` event and the tool running, and its payload's `tool_call` object
        // carries a name and a command but no call id — so the session's most recent call
        // is the one being asked about, and naming it is what makes the editor attach the
        // question to the row it already drew instead of inventing a second one. A
        // question or a plan exit has no tool call at all, and gets a minted id.
        let last_tool = self
            .sessions
            .get(session_id)
            .and_then(|session| session.last_tool.clone());
        let call_id = permission_call_id(&event.payload)
            .or(last_tool)
            .unwrap_or_else(|| self.mint_tool_id(session_id, event.sequence));

        self.outbound += 1;
        let id = json!(format!("ouro-permission-{}", self.outbound));

        self.permissions.insert(
            id_key(&id),
            Permission {
                session_id: session_id.to_string(),
                request_id,
                answers,
            },
        );

        vec![json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/request_permission",
            "params": {
                "sessionId": session_id,
                "toolCall": permission_tool_call(&event.payload, &call_id),
                "options": options,
            }
        })]
    }

    // ----- shutdown ------------------------------------------------------------------

    /// stdin closed. Interrupt every in-flight turn, say so, and resolve the prompts.
    ///
    /// The order matters: the sentence goes out as an `agent_message_chunk` *before* the
    /// prompt resolves, because an editor that has already seen its result may stop
    /// rendering updates for that turn.
    pub async fn shutdown(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        let busy: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_id, session)| session.prompt.is_some())
            .map(|(id, _session)| id.clone())
            .collect();

        for session_id in busy {
            let Some(session) = self.sessions.get(&session_id) else {
                continue;
            };

            let params = session.routed(json!({ "id": session_id }));
            let interrupted = self
                .client
                .call_with_timeout("interactive.interrupt", params, INTERRUPT_CEILING)
                .await;

            let sentence = match interrupted {
                Ok(_value) => format!(
                    "`ouro acp` lost its editor connection and interrupted this turn. The \
                     session ({session_id}) is still in the runtime; `ouro` attaches to it."
                ),
                Err(error) => format!(
                    "`ouro acp` lost its editor connection. Interrupting this turn failed \
                     ({}), so it may still be running; `ouro` attaches to session \
                     {session_id}.",
                    rendered(&error)
                ),
            };

            frames.push(update(
                &session_id,
                json!({
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": sentence},
                }),
            ));

            if let Some(prompt) = self
                .sessions
                .get_mut(&session_id)
                .and_then(|session| session.prompt.take())
            {
                frames.push(result_frame(
                    prompt.id,
                    json!({ "stopReason": StopReason::Cancelled.as_str() }),
                ));
            }
        }

        frames
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers — pure, so the table above is testable without a socket
// ---------------------------------------------------------------------------

/// The `stopReason` values ACP defines. There is no `failed`: a turn that failed is a
/// JSON-RPC error on the prompt, not a stop reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    MaxTurnRequests,
    Refusal,
    Cancelled,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndTurn => "end_turn",
            Self::MaxTokens => "max_tokens",
            Self::MaxTurnRequests => "max_turn_requests",
            Self::Refusal => "refusal",
            Self::Cancelled => "cancelled",
        }
    }
}

/// What a `turn_completed` payload says about *why* it completed.
///
/// Native emits `{"status": "completed", …}` and carries no stop reason; the ACP dialect
/// forwards the agent's own `stopReason`; the Codex dialect and the CLI mappers use
/// `reason`. Read all three, default to `end_turn`, and never invent a limit the provider
/// did not report.
pub fn completed_stop_reason(payload: &Value) -> StopReason {
    let named = ["stop_reason", "stopReason", "reason", "finish_reason"]
        .into_iter()
        .find_map(|key| payload.get(key).and_then(Value::as_str))
        .unwrap_or("");

    match named {
        "max_turns" | "max_turn_requests" | "max_iterations" => StopReason::MaxTurnRequests,
        "max_tokens" | "length" | "max_output_tokens" => StopReason::MaxTokens,
        "refusal" | "refused" | "content_filter" => StopReason::Refusal,
        "cancelled" | "canceled" | "interrupted" | "aborted" => StopReason::Cancelled,
        _end => StopReason::EndTurn,
    }
}

/// Whether an event belongs to the turn this prompt sent.
///
/// Both identifiers count: the caller-minted id the gateway keys the durable turn on, and
/// the `harness_turn_id` the provider's own events carry. An event with no `turn_id` is
/// accepted — several session-level events carry none — and so is one this bridge cannot
/// place *because the send named no harness turn*: a session takes one turn at a time.
fn ours(prompt: &Prompt, event: &Event) -> bool {
    let Some(turn) = event.turn_id.as_deref() else {
        return true;
    };

    match prompt.harness_turn.as_deref() {
        Some(harness) => turn == harness || turn == prompt.turn_id,
        None => true,
    }
}

fn adopt_harness_turn(session: &mut Session, reply: &Value) {
    let Some(harness) = reply
        .get("harness_turn_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return;
    };

    if let Some(prompt) = session.prompt.as_mut() {
        prompt.harness_turn = Some(harness.to_string());
    }
}

/// The `session/update` envelope.
fn update(session_id: &str, body: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {"sessionId": session_id, "update": body}
    })
}

/// One `tool_call` update, with ACP's own `kind` taxonomy.
fn tool_call_update(id: &str, payload: &Value) -> Value {
    let name = text(payload, &["name", "tool_name", "toolName", "tool"])
        .unwrap_or_else(|| "tool".to_string());

    let mut body = Map::new();
    body.insert("sessionUpdate".into(), json!("tool_call"));
    body.insert("toolCallId".into(), json!(id));
    body.insert("title".into(), json!(tool_title(&name, payload)));
    body.insert("kind".into(), json!(tool_kind(&name, payload)));
    body.insert("status".into(), json!("in_progress"));

    if let Some(input) = first_value(payload, &["input", "arguments", "parameters", "rawInput"]) {
        body.insert("rawInput".into(), input.clone());
    }

    let locations = tool_locations(payload);

    if !locations.is_empty() {
        body.insert("locations".into(), Value::Array(locations));
    }

    Value::Object(body)
}

/// One `tool_call_update` carrying a result.
fn tool_result_update(id: &str, payload: &Value) -> Value {
    let failed = payload
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || matches!(
            text(payload, &["status"]).as_deref(),
            Some("failed") | Some("error") | Some("refused") | Some("timed_out")
        );

    let mut body = Map::new();
    body.insert("sessionUpdate".into(), json!("tool_call_update"));
    body.insert("toolCallId".into(), json!(id));
    body.insert(
        "status".into(),
        json!(if failed { "failed" } else { "completed" }),
    );

    if let Some(output) = first_value(payload, &["output", "result", "content", "rawOutput"]) {
        body.insert("rawOutput".into(), output.clone());

        if let Some(text) = leaf_text(output) {
            body.insert(
                "content".into(),
                json!([{"type": "content", "content": {"type": "text", "text": text}}]),
            );
        }
    }

    Value::Object(body)
}

/// A `file_change`, as content on the tool call that produced it.
///
/// ACP's `diff` content block wants `oldText` and `newText`; the gateway's `file_change`
/// carries a *unified diff* and no file bodies (`Dialect.ACP` computes the patch from the
/// agent's own `oldText`/`newText` on the way in and keeps only the patch). Reconstructing
/// two whole buffers from a patch is not possible, so the patch is delivered as a fenced
/// text content block — which is what it is — and the paths ride in `locations`. A `diff`
/// block is emitted only where the payload really carries both texts.
fn file_change_update(id: &str, payload: &Value) -> Value {
    let mut content = Vec::new();
    let mut locations = Vec::new();

    let changes = payload
        .get("changes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    for change in &changes {
        if let Some(path) = text(change, &["path", "file", "file_path"]) {
            locations.push(json!({ "path": path }));
        }

        match (
            text(change, &["path", "file", "file_path"]),
            change.get("oldText").and_then(Value::as_str),
            change.get("newText").and_then(Value::as_str),
        ) {
            (Some(path), Some(old), Some(new)) => content.push(json!({
                "type": "diff",
                "path": path,
                "oldText": old,
                "newText": new,
            })),
            _patch_only => {
                if let Some(diff) = change.get("diff").and_then(Value::as_str) {
                    content.push(fenced_diff(diff));
                }
            }
        }
    }

    // The whole-turn shape: one patch for everything the turn changed.
    if let Some(diff) = payload.get("diff").and_then(Value::as_str) {
        content.push(fenced_diff(diff));
    }

    let mut body = Map::new();
    body.insert("sessionUpdate".into(), json!("tool_call_update"));
    body.insert("toolCallId".into(), json!(id));
    body.insert(
        "status".into(),
        json!(match text(payload, &["status"]).as_deref() {
            Some("failed") | Some("error") => "failed",
            Some("pending") | Some("in_progress") => "in_progress",
            _settled => "completed",
        }),
    );

    if !content.is_empty() {
        body.insert("content".into(), Value::Array(content));
    }

    if !locations.is_empty() {
        body.insert("locations".into(), Value::Array(locations));
    }

    Value::Object(body)
}

fn fenced_diff(diff: &str) -> Value {
    json!({
        "type": "content",
        "content": {
            "type": "text",
            "text": format!("```diff\n{}\n```", bounded(diff.trim_end()))
        }
    })
}

/// The `plan` update. Both plan shapes this runtime delivers, read the way the transcript
/// reads them: Codex sends `{"plan": [{"step", "status"}]}`, ACP forwards its own
/// `{"entries": [{"content", "priority", "status"}]}`.
fn plan_update(payload: &Value) -> Value {
    let entries = first_value(payload, &["plan", "entries", "steps", "todos", "tasks"])
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let entries: Vec<Value> = entries
        .iter()
        .filter_map(|entry| {
            let content = match entry {
                Value::String(text) => Some(text.trim().to_string()).filter(|t| !t.is_empty()),
                _object => text(
                    entry,
                    &["step", "content", "text", "title", "description", "name"],
                ),
            }?;

            Some(json!({
                "content": bounded(&content),
                "priority": plan_priority(entry),
                "status": plan_status(entry),
            }))
        })
        .collect();

    json!({"sessionUpdate": "plan", "entries": entries})
}

fn plan_priority(entry: &Value) -> &'static str {
    match text(entry, &["priority"]).as_deref() {
        Some("high") => "high",
        Some("low") => "low",
        _medium => "medium",
    }
}

fn plan_status(entry: &Value) -> &'static str {
    match text(entry, &["status", "state"]).as_deref() {
        Some("in_progress") | Some("running") | Some("active") | Some("started") => "in_progress",
        Some("completed") | Some("complete") | Some("done") | Some("finished") => "completed",
        _pending => "pending",
    }
}

/// The two `provider_event` kinds that have an ACP update, and nothing else.
fn provider_event(session_id: &str, payload: &Value) -> Vec<Value> {
    match text(payload, &["kind"]).as_deref() {
        // The ACP dialect's normalisation of another agent's `current_mode_update`.
        Some("mode") => text(payload, &["mode"])
            .map(|mode| {
                vec![update(
                    session_id,
                    json!({"sessionUpdate": "current_mode_update", "currentModeId": mode}),
                )]
            })
            .unwrap_or_default(),
        // A plan exit the native session applied: the mode really moved, and the payload
        // says whether it did (`applied`) rather than leaving it to be assumed.
        Some("plan_exit") => {
            if payload.get("applied").and_then(Value::as_bool) != Some(true) {
                return Vec::new();
            }

            let mode = if payload.get("plan").and_then(Value::as_bool) == Some(true) {
                Some("plan".to_string())
            } else {
                text(payload, &["approval_mode"])
            };

            mode.map(|mode| {
                vec![update(
                    session_id,
                    json!({"sessionUpdate": "current_mode_update", "currentModeId": mode}),
                )]
            })
            .unwrap_or_default()
        }
        Some("available_commands") => {
            let commands: Vec<Value> = payload
                .get("commands")
                .and_then(Value::as_array)
                .map(|commands| {
                    commands
                        .iter()
                        .filter_map(|command| {
                            let name = text(command, &["name"])?;

                            Some(json!({
                                "name": name,
                                "description": text(command, &["description"]).unwrap_or_default(),
                            }))
                        })
                        .collect()
                })
                .unwrap_or_default();

            vec![update(
                session_id,
                json!({
                    "sessionUpdate": "available_commands_update",
                    "availableCommands": commands,
                }),
            )]
        }
        _other => Vec::new(),
    }
}

/// The mode a `status` event with `kind: "configured"` moved the session into.
pub fn configured_mode(payload: &Value) -> Option<String> {
    if text(payload, &["kind"]).as_deref() != Some("configured") {
        return None;
    }

    let changed = payload.get("changed")?;

    if changed.get("plan").and_then(Value::as_bool) == Some(true) {
        return Some("plan".to_string());
    }

    text(changed, &["approval_mode"])
}

/// ACP's tool `kind` taxonomy, from the tool's own name.
///
/// The v1 enum is `read|edit|delete|move|search|execute|think|fetch|other`. A name this
/// build does not recognise is `other`, never a guess: an editor renders the icon and the
/// grouping from this field, and a `bash` call shown as a read is a lie about what ran.
pub fn tool_kind(name: &str, payload: &Value) -> &'static str {
    // The ACP dialect forwards another agent's own `kind` untouched; where it is present
    // and already one of the nine, it is authoritative.
    if let Some(kind) = text(payload, &["tool_kind", "toolKind"]) {
        if let Some(known) = known_kind(&kind) {
            return known;
        }
    }

    let lowered = name.trim().to_ascii_lowercase();

    if let Some(known) = known_kind(&lowered) {
        return known;
    }

    match lowered.as_str() {
        "read" | "read_file" | "view" | "cat" | "notebookread" | "ls" | "list" | "list_dir" => {
            "read"
        }
        "edit"
        | "write"
        | "multiedit"
        | "notebookedit"
        | "apply_patch"
        | "patch"
        | "write_file"
        | "edit_file"
        | "create_file"
        | "replace"
        | "str_replace_editor"
        | "str_replace_based_edit_tool" => "edit",
        "bash" | "shell" | "run" | "exec" | "run_command" | "terminal" => "execute",
        "grep" | "glob" | "search" | "codebase_search" | "workspace_symbols" => "search",
        "web_fetch" | "webfetch" | "fetch" | "web_search" | "websearch" | "url" => "fetch",
        "plan" | "think" | "todowrite" => "think",
        "rm" | "delete" | "remove" => "delete",
        "mv" | "move" | "rename" => "move",
        _unknown => "other",
    }
}

fn known_kind(value: &str) -> Option<&'static str> {
    match value {
        "read" => Some("read"),
        "edit" => Some("edit"),
        "delete" => Some("delete"),
        "move" => Some("move"),
        "search" => Some("search"),
        "execute" => Some("execute"),
        "think" => Some("think"),
        "fetch" => Some("fetch"),
        // The tenth value. The tool-calls prose page lists nine and omits it; the
        // published JSON Schema (`schema-v1.21.0`) has it and the session-modes page uses
        // it in an example, so the schema is what this reads.
        "switch_mode" => Some("switch_mode"),
        "other" => Some("other"),
        _unknown => None,
    }
}

/// The one line the editor puts on the tool row: the tool, and the thing it names.
fn tool_title(name: &str, payload: &Value) -> String {
    let input = first_value(payload, &["input", "arguments", "parameters", "rawInput"]);

    let subject = input.and_then(|input| {
        text(
            input,
            &[
                "path",
                "file_path",
                "file",
                "command",
                "cmd",
                "pattern",
                "query",
                "url",
            ],
        )
    });

    match subject {
        Some(subject) => bounded_to(&format!("{name}: {subject}"), 200),
        None => bounded_to(name, 200),
    }
}

/// Every file path a tool call names, as ACP `locations`.
fn tool_locations(payload: &Value) -> Vec<Value> {
    let Some(input) = first_value(payload, &["input", "arguments", "parameters", "rawInput"])
    else {
        return Vec::new();
    };

    let mut locations = Vec::new();

    for key in ["path", "file_path", "file", "notebook_path"] {
        if let Some(path) = text(input, &[key]) {
            locations.push(json!({ "path": path }));
        }
    }

    // The native permission engine's own list, where a call carries several.
    if let Some(paths) = input.get("paths").and_then(Value::as_array) {
        for path in paths.iter().filter_map(Value::as_str) {
            locations.push(json!({ "path": path }));
        }
    }

    locations.dedup_by(|a, b| a == b);
    locations
}

/// The `toolCall` an editor renders above the permission options.
///
/// A `ToolCallUpdate` rather than a `ToolCall`, which is what the schema asks for here:
/// only `toolCallId` is required, and the rest is what makes the question readable.
fn permission_tool_call(payload: &Value, call_id: &str) -> Value {
    let call = payload.get("tool_call").unwrap_or(payload);
    let name = text(call, &["name", "tool_name", "tool"])
        .or_else(|| text(payload, &["header"]))
        .unwrap_or_else(|| "this action".to_string());

    let mut object = Map::new();
    object.insert("toolCallId".into(), json!(call_id));
    object.insert("title".into(), json!(permission_title(payload, &name)));
    object.insert("kind".into(), json!(tool_kind(&name, payload)));
    object.insert("status".into(), json!("pending"));

    let locations: Vec<Value> = payload
        .get("paths")
        .and_then(Value::as_array)
        .map(|paths| {
            paths
                .iter()
                .filter_map(Value::as_str)
                .map(|path| json!({ "path": path }))
                .collect()
        })
        .unwrap_or_default();

    if !locations.is_empty() {
        object.insert("locations".into(), Value::Array(locations));
    }

    Value::Object(object)
}

/// The call id the approval payload named, where it named one. Today's runtime does not —
/// `Ouroboros.Provider.Native.Loop`'s `tool_call` object is `{name, command, cwd}` and the
/// Codex dialect's is its own shape — so this is the arm that keeps working the day one
/// starts to.
fn permission_call_id(payload: &Value) -> Option<String> {
    text(
        payload.get("tool_call").unwrap_or(payload),
        &["call_id", "tool_call_id", "toolCallId", "id"],
    )
}

/// The sentence the person reads. A plan exit and a question carry their own; a tool call
/// gets the command or the paths it would touch, because "may bash run?" is not a question
/// anybody can answer.
fn permission_title(payload: &Value, name: &str) -> String {
    if let Some(question) = text(payload, &["question"]) {
        return bounded_to(&question, 400);
    }

    let call = payload.get("tool_call").unwrap_or(payload);

    if let Some(command) = text(call, &["command"]) {
        return bounded_to(&format!("{name}: {command}"), 400);
    }

    let paths: Vec<String> = payload
        .get("paths")
        .and_then(Value::as_array)
        .map(|paths| {
            paths
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    if !paths.is_empty() {
        return bounded_to(&format!("{name}: {}", paths.join(", ")), 400);
    }

    bounded_to(name, 400)
}

/// The permission rows, and what selecting each one means on the gateway.
///
/// Three shapes reach here and all three are served:
///
/// * **the runtime's own ACP-shaped options** — a plan exit's three answers
///   (`Ouroboros.Provider.Native.Session` `@plan_exit_options`) and, on an ACP-transport
///   session, the hosted agent's own rows. Both are `{optionId, name, kind}` already, so
///   they pass through and the `optionId` goes back as `provider_options.choice`, which is
///   where `plan_exit_choice/1` looks first;
/// * **a question's string options** (`Tools.AskUser`), which become rows whose answer is
///   the option's own text carried as `reason` — the field `AskUser.answer_text/1` reads
///   once `provider_options` has been narrowed to `{choice, follow_up}` by the gateway;
/// * **no options at all**, which is every ordinary tool approval: the standard
///   allow-once / allow-always / reject-once / reject-always rows.
fn permission_options(payload: &Value) -> (Vec<Value>, BTreeMap<String, Answer>) {
    let mut rows = Vec::new();
    let mut answers = BTreeMap::new();
    let kind = text(payload, &["kind"]).unwrap_or_default();
    let supplied = payload.get("options").and_then(Value::as_array);

    if let Some(supplied) = supplied {
        for option in supplied {
            match option {
                Value::Object(_) => {
                    let Some(id) = text(option, &["optionId", "option_id", "id"]) else {
                        continue;
                    };
                    let name = text(option, &["name", "label"]).unwrap_or_else(|| id.clone());
                    let row_kind = permission_kind(option);

                    rows.push(json!({"optionId": id, "name": name, "kind": row_kind}));

                    // A plan exit is answered by naming the choice; anything else the
                    // runtime supplied is answered by the decision its kind implies, which
                    // is exactly how `Dialect.ACP` picks the option to send onward.
                    answers.insert(
                        id.clone(),
                        if kind == "plan_exit" {
                            Answer::Choice(id)
                        } else {
                            decision_for(row_kind)
                        },
                    );
                }
                Value::String(text) if !text.trim().is_empty() => {
                    let id = format!("answer-{}", rows.len() + 1);

                    rows.push(json!({
                        "optionId": id,
                        "name": bounded_to(text.trim(), 200),
                        "kind": "allow_once",
                    }));
                    answers.insert(id, Answer::Reason(text.trim().to_string()));
                }
                _other => {}
            }
        }
    }

    if rows.is_empty() {
        for (id, name, row_kind) in [
            ("allow_once", "Allow once", "allow_once"),
            ("allow_always", "Allow for this session", "allow_always"),
            ("reject_once", "Reject", "reject_once"),
            ("reject_always", "Reject for this session", "reject_always"),
        ] {
            rows.push(json!({"optionId": id, "name": name, "kind": row_kind}));
            answers.insert(id.to_string(), decision_for(row_kind));
        }
    } else if kind == "question" {
        // A question with only answers is a question nobody can decline.
        rows.push(json!({
            "optionId": "reject_once",
            "name": "Decline to answer",
            "kind": "reject_once",
        }));
        answers.insert("reject_once".to_string(), decision_for("reject_once"));
    }

    (rows, answers)
}

/// One supplied option's `kind`, narrowed to the four ACP defines.
fn permission_kind(option: &Value) -> &'static str {
    match text(option, &["kind"]).as_deref() {
        Some("allow_always") => "allow_always",
        Some("reject_always") => "reject_always",
        Some("reject_once") | Some("reject") | Some("deny") => "reject_once",
        _allow => "allow_once",
    }
}

fn decision_for(kind: &str) -> Answer {
    match kind {
        "allow_always" => Answer::Decision {
            decision: ApprovalDecision::Approve,
            scope: ApprovalScope::Session,
        },
        "reject_once" => Answer::Decision {
            decision: ApprovalDecision::Deny,
            scope: ApprovalScope::Once,
        },
        "reject_always" => Answer::Decision {
            decision: ApprovalDecision::Deny,
            scope: ApprovalScope::Session,
        },
        _allow_once => Answer::Decision {
            decision: ApprovalDecision::Approve,
            scope: ApprovalScope::Once,
        },
    }
}

/// `interactive.respond_approval`'s params for one answer.
fn respond_params(session_id: &str, request_id: &str, answer: &Answer) -> Value {
    match answer {
        Answer::Decision { decision, scope } => {
            model::respond_approval_params(session_id, request_id, *decision, *scope)
        }
        Answer::Reason(reason) => model::respond_approval_params_with_reason(
            session_id,
            request_id,
            ApprovalDecision::Approve,
            ApprovalScope::Once,
            Some(reason),
        ),
        Answer::Choice(choice) => {
            // `keep_planning` is a refusal to leave plan mode, and the runtime reads the
            // decision as well as the choice; sending `approve` there would put a session
            // to work on an answer that said not to.
            let decision = if choice == "keep_planning" {
                ApprovalDecision::Deny
            } else {
                ApprovalDecision::Approve
            };

            let mut params = model::respond_approval_params(
                session_id,
                request_id,
                decision,
                ApprovalScope::Once,
            );
            params["response"]["provider_options"] = json!({ "choice": choice });
            params
        }
    }
}

/// `interactive.send_message`'s `input`, from the editor's content blocks.
///
/// Text is joined; a `file://` resource link becomes an attachment path, which the session
/// canonicalises against its own leased workspace and refuses if it escapes. Everything
/// else is refused here rather than dropped: this agent advertised `image`, `audio` and
/// `embeddedContext` as false, so a block of one of those kinds is the editor sending
/// something the handshake said would not be read.
pub fn prompt_input(blocks: &[Value]) -> Result<Value, Refusal> {
    let mut text = String::new();
    let mut attachments: Vec<String> = Vec::new();

    for block in blocks {
        match block.get("type").and_then(Value::as_str).unwrap_or("") {
            "text" => {
                let Some(chunk) = block.get("text").and_then(Value::as_str) else {
                    return Err(Refusal::new(-32602, "a text content block carried no text"));
                };

                if !text.is_empty() {
                    text.push_str("\n\n");
                }

                text.push_str(chunk);
            }
            "resource_link" => {
                let Some(uri) = block.get("uri").and_then(Value::as_str) else {
                    return Err(Refusal::new(
                        -32602,
                        "a resource_link content block carried no uri",
                    ));
                };

                let Some(path) = file_path(uri) else {
                    return Err(Refusal::new(
                        -32602,
                        &format!(
                            "this agent can only attach files: {uri} is not a file:// URI, and \
                             Ouroboros attaches paths inside the session's workspace rather \
                             than fetching URLs"
                        ),
                    ));
                };

                attachments.push(path);
            }
            other => {
                return Err(Refusal::new(
                    -32602,
                    &format!(
                        "this agent's promptCapabilities do not include `{other}` content; \
                         Ouroboros's runtime takes text and workspace file paths only"
                    ),
                ))
            }
        }
    }

    if text.trim().is_empty() && attachments.is_empty() {
        return Err(Refusal::new(
            -32602,
            "session/prompt carried nothing to send",
        ));
    }

    if attachments.is_empty() {
        // The legacy string form, which is what every other client sends for a plain
        // prompt; the object form exists for the attachments.
        return Ok(Value::String(text));
    }

    Ok(json!({"prompt": text, "attachments": attachments}))
}

/// A `file://` URI's path, percent-decoded. `None` for every other scheme.
fn file_path(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("file://")?;
    // `file:///abs` (empty authority) and `file:/abs` are both seen; a non-empty authority
    // names another host and is not a path this runtime can admit.
    let rest = match rest.strip_prefix('/') {
        Some(path) => format!("/{path}"),
        None if rest.is_empty() => return None,
        None => return None,
    };

    Some(percent_decode(&rest))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();

            if let Some(byte) = hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(byte);
                index += 3;
                continue;
            }
        }

        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// The names in a `session/new`'s `mcpServers`, for the sentence that says they were not
/// applied. Never the commands: this bridge does not forward them anywhere.
fn mcp_server_names(params: &Value) -> Vec<String> {
    params
        .get("mcpServers")
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| text(server, &["name"]))
                .collect()
        })
        .unwrap_or_default()
}

/// The mode a fresh session is in, as `interactive.info` reports it.
///
/// `options.approval_mode` is `null` where the plane omitted an unenforceable default and
/// the provider's own behaviour governs — which is exactly what the `default` mode means,
/// so that is what it maps to rather than an absent claim.
fn current_mode(options: Option<&Value>, planning: bool) -> String {
    if planning {
        return "plan".to_string();
    }

    options
        .and_then(|options| text(options, &["approval_mode"]))
        .unwrap_or_else(|| "default".to_string())
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

/// A refusal this agent answers a request with.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub code: i64,
    pub message: String,
}

impl Refusal {
    pub fn new(code: i64, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
        }
    }
}

struct SendFailure {
    rendered: String,
    outcome_unknown: bool,
}

fn turn_failure(value: &Value) -> Option<SendFailure> {
    match model::turn_reply(value) {
        model::TurnReply::Accepted => None,
        model::TurnReply::OutcomeUnknown => Some(SendFailure {
            rendered: model::turn_reply_diagnostic(value),
            outcome_unknown: true,
        }),
        model::TurnReply::Rejected => Some(SendFailure {
            rendered: model::turn_reply_diagnostic(value),
            outcome_unknown: false,
        }),
    }
}

fn is_busy(attempt: &Result<Value, ClientError>) -> bool {
    match attempt {
        Ok(value) => model::turn_reply_busy(value),
        Err(ClientError::Rpc(rpc)) => model::turn_busy(rpc.data.as_ref()),
        Err(_other) => false,
    }
}

fn send_outcome_unknown(error: &ClientError) -> bool {
    match error {
        ClientError::Rpc(rpc) => {
            rpc.code == ErrorCode::UpstreamTimeout || model::outcome_unknown(rpc.data.as_ref())
        }
        _transport => true,
    }
}

fn rendered(error: &ClientError) -> String {
    match error {
        ClientError::Rpc(rpc) => model::refusal(rpc),
        other => other.to_string(),
    }
}

fn session_id_of(params: &Value) -> Result<String, Refusal> {
    params
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| Refusal::new(-32602, "this method needs a `sessionId`"))
}

fn id_key(id: &Value) -> String {
    match id {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn result_frame(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_frame(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string)
    })
}

fn first_value<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| value.get(*key).filter(|value| !value.is_null()))
}

fn payload_text(payload: &Value, keys: &[&str]) -> Option<String> {
    let text = keys
        .iter()
        .find_map(|key| payload.get(*key).and_then(Value::as_str))?;

    (!text.is_empty()).then(|| bounded(text))
}

/// A leaf string out of a tool result, whatever shape the provider put it in.
fn leaf_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => (!text.trim().is_empty()).then(|| bounded(text)),
        Value::Object(_) => text(value, &["text", "output", "content", "stdout"])
            .map(|text| bounded(&text))
            .or_else(|| Some(bounded(&model::compact(value)))),
        Value::Array(items) if !items.is_empty() => Some(bounded(&model::compact(value))),
        _empty => None,
    }
}

/// The sentence behind a failure event, or an honest placeholder.
fn event_detail(payload: &Value) -> String {
    for key in ["error", "reason", "message", "detail", "text"] {
        if let Some(value) = payload.get(key).filter(|value| !value.is_null()) {
            let rendered = model::compact(value);

            if !rendered.trim().is_empty() {
                return rendered;
            }
        }
    }

    match payload {
        Value::Object(fields) if fields.is_empty() => "the runtime gave no detail".to_string(),
        Value::Null => "the runtime gave no detail".to_string(),
        other => model::compact(other),
    }
}

fn tool_call_id(payload: &Value) -> Option<String> {
    text(payload, &["call_id", "tool_call_id", "toolCallId", "id"])
}

fn bounded(text: &str) -> String {
    bounded_to(text, CHUNK_BYTES)
}

/// A UTF-8-safe truncation with a marker, so a bound is visible rather than silent.
fn bounded_to(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }

    let mut end = limit;

    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}… (truncated by ouro acp)", &text[..end])
}

/// A caller-owned turn id, tagged with the surface that minted it so a ledger reader can
/// tell an editor's turn from one somebody typed into the TUI.
fn new_turn_id() -> String {
    use rand::TryRngCore;

    let mut bytes = [0_u8; 16];

    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_ok() {
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        return format!("ouro-acp-{encoded}");
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = TURN_ID_FALLBACK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!("ouro-acp-{}-{timestamp:x}-{sequence:x}", std::process::id())
}

static TURN_ID_FALLBACK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

/// Speaks ACP on this process's stdio until stdin ends.
pub async fn serve(
    client: Client,
    hello: Hello,
    notifications: mpsc::Receiver<Notification>,
    options: Options,
) -> Result<()> {
    let agent = Agent::new(client, hello, options);
    let unserved = agent.unserved();

    if !unserved.is_empty() {
        // Said on stderr and then served anyway: the editor's `initialize` still gets a
        // truthful handshake, and `session/new` is where the refusal belongs, because that
        // is the frame the editor can show a person.
        eprintln!(
            "ouro acp: this gateway does not serve {}; session/new will refuse",
            unserved.join(", ")
        );
    }

    run(
        agent,
        tokio::io::stdin(),
        tokio::io::stdout(),
        notifications,
    )
    .await
}

/// The loop, over any pair of streams so a test can be the editor.
///
/// Both arms are cancel-safe: [`LineReader::next_line`] mutates only after its inner read
/// returns, and an `mpsc::Receiver` loses nothing to a cancelled `recv`. `biased` puts the
/// gateway first so a turn's events reach the editor ahead of the next thing it typed.
pub async fn run<R, W>(
    mut agent: Agent,
    reader: R,
    mut writer: W,
    mut notifications: mpsc::Receiver<Notification>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = LineReader::new(reader, MAX_LINE_BYTES);

    loop {
        let frames = tokio::select! {
            biased;

            notification = notifications.recv() => {
                match notification {
                    Some(notification) => agent.handle_notification(notification).await,
                    None => {
                        // The runtime connection is gone. Every session this agent holds is
                        // now unobservable, so it says so and ends rather than sitting on a
                        // stream that is never coming back.
                        let frames = agent.shutdown().await;
                        write_all(&mut writer, &frames).await?;
                        return Err(anyhow!("the connection to the runtime closed"));
                    }
                }
            }

            line = lines.next_line() => {
                match line {
                    Ok(Some(line)) => match std::str::from_utf8(&line) {
                        Ok(line) => agent.handle_line(line).await,
                        Err(error) => vec![error_frame(
                            Value::Null,
                            -32700,
                            &format!("a frame that is not UTF-8 is not JSON: {error}"),
                        )],
                    },
                    Ok(None) => {
                        let frames = agent.shutdown().await;
                        write_all(&mut writer, &frames).await?;
                        return Ok(());
                    }
                    Err(ClientError::FrameTooLarge { limit }) => {
                        // The reader is poisoned by design — a frame it could not bound is
                        // a stream it can no longer find the start of — so this is said and
                        // then the loop ends.
                        let frame = error_frame(
                            Value::Null,
                            -32600,
                            &format!("a frame above the {limit}-byte ceiling"),
                        );
                        write_all(&mut writer, &[frame]).await?;
                        let frames = agent.shutdown().await;
                        write_all(&mut writer, &frames).await?;
                        return Ok(());
                    }
                    Err(error) => return Err(anyhow!("reading the editor's stdin: {error}")),
                }
            }
        };

        write_all(&mut writer, &frames).await?;
    }
}

async fn write_all<W: AsyncWrite + Unpin>(writer: &mut W, frames: &[Frame]) -> Result<()> {
    for frame in frames {
        write_line(writer, frame).await?;
    }

    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Value) -> Result<()> {
    // One message per line, and the frame itself can never contain a newline because
    // `serde_json` escapes them — which is exactly what the stdio binding requires.
    let mut bytes =
        serde_json::to_vec(frame).map_err(|error| anyhow!("encoding an ACP frame: {error}"))?;
    bytes.push(b'\n');

    writer
        .write_all(&bytes)
        .await
        .map_err(|error| anyhow!("writing an ACP frame: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| anyhow!("flushing an ACP frame: {error}"))
}
