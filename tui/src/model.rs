//! The shapes this client names, and the rule for everything it does not.
//!
//! ## Tolerance is the point, not a concession
//!
//! The runtime on the other end rewrites its own modules. A client that refused a payload
//! carrying a field it had never seen would go blind on the first forged
//! `Ouroboros.Capability.*` module, which is the one thing this system exists to do. So
//! every struct here ignores unknown fields, every enum has an `Other(String)` arm, and
//! anything without a type falls through to [`serde_json::Value`] and the generic tree
//! widget. The types are a *convenience for layout* — knowing that a session has a status
//! worth colouring — not a schema the wire has to satisfy.
//!
//! ## The fixtures are the contract, and they win
//!
//! `test/support/gateway_golden/*.json` is regenerated from the Elixir side by
//! `mix ouroboros.gateway.golden` and re-derived through the live `Conn` envelope by
//! `golden_test.exs`. The tests at the bottom of this module decode all thirteen. When a
//! fixture and a type here disagree, the fixture is right: it came from the build that
//! produced the bytes.
//!
//! ## Three shapes worth stating because the source misleads
//!
//! * `availability` is **tri-state**. `:disabled` is a posture — the control plane and the
//!   workspace plane report it when they were never configured — and rendering it as
//!   "down" would report a choice as a fault ([ouroboros.ex] `availability/0`).
//! * `status.cluster` has no `mode` key on success. `Ouroboros.Cluster.status/0` returns
//!   `{node, role, distributed, connected_nodes, roles, formation, security}`; the
//!   `%{mode: :unavailable}` beside it in `Ouroboros.status/0` is the *fallback*. Both
//!   shapes decode here, and the tree widget renders whatever else arrives.
//! * `interactive.list`/`info` return `Ouroboros.Interactive.State` structs, so their maps
//!   carry `"_struct"`. The tag is kept rather than discarded: it is how a value tree
//!   labels a node it has no other name for.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{Deserializer, Error as _};
use serde::Deserialize;
use serde_json::Value;

/// Which plane an id belongs to. The two have separate id spaces, so a session is only
/// addressable as a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Plane {
    Interactive,
    Coding,
}

impl Plane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Coding => "coding",
        }
    }

    /// The short tag a session list shows beside an id.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Interactive => "int",
            Self::Coding => "code",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "interactive" => Some(Self::Interactive),
            "coding" => Some(Self::Coding),
            _ => None,
        }
    }

    /// The method name for one of this plane's verbs: `interactive.replay`, and so on.
    pub fn method(self, verb: &str) -> String {
        format!("{}.{verb}", self.as_str())
    }
}

impl fmt::Display for Plane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A plane's liveness as `Ouroboros.status/0` reports it — three states, not two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
    /// Never configured. Not a fault, and must not be coloured like one.
    Disabled,
    Other(String),
}

impl Availability {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Disabled => "disabled",
            Self::Other(name) => name,
        }
    }
}

impl<'de> Deserialize<'de> for Availability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match String::deserialize(deserializer)?.as_str() {
            "available" => Self::Available,
            "unavailable" => Self::Unavailable,
            "disabled" => Self::Disabled,
            other => Self::Other(other.to_string()),
        })
    }
}

/// The union of both planes' status atoms. They overlap but are not equal — a coding task
/// completes, an interactive session closes — and one enum with an `Other` arm costs less
/// than two that a caller has to switch between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStatus {
    Starting,
    Idle,
    Running,
    AwaitingApproval,
    Closing,
    Closed,
    Completed,
    Failed,
    Cancelled,
    Lost,
    Other(String),
}

impl SessionStatus {
    pub fn parse(name: &str) -> Self {
        match name {
            "starting" => Self::Starting,
            "idle" => Self::Idle,
            "running" => Self::Running,
            "awaiting_approval" => Self::AwaitingApproval,
            "closing" => Self::Closing,
            "closed" => Self::Closed,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "lost" => Self::Lost,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Starting => "starting",
            Self::Idle => "idle",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Lost => "lost",
            Self::Other(name) => name,
        }
    }

    /// Whether the plane will produce no further events. An unrecognized status is *not*
    /// terminal: a client that guessed wrong here would stop rendering a live session.
    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Closed | Self::Completed | Self::Failed | Self::Cancelled | Self::Lost
        )
    }

    pub fn busy(&self) -> bool {
        matches!(self, Self::Running | Self::Starting | Self::Closing)
    }
}

impl<'de> Deserialize<'de> for SessionStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

/// `Jido.Harness.Event`'s canonical types, plus the arm that keeps a newer harness
/// legible. The transcript colours by this; nothing branches on it for correctness except
/// the two approval arms, which the modal needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventType {
    RunStarted,
    RunCompleted,
    RunFailed,
    RunCancelled,
    SessionStarted,
    SessionReady,
    SessionIdle,
    SessionClosed,
    SessionFailed,
    SessionCancelled,
    InputAccepted,
    TurnQueued,
    TurnStarted,
    OutputTextDelta,
    OutputTextFinal,
    ThinkingDelta,
    CommandOutputDelta,
    ToolCall,
    ToolResult,
    FileChange,
    PlanUpdated,
    Usage,
    TurnCompleted,
    TurnFailed,
    TurnInterrupted,
    ApprovalRequested,
    ApprovalResolved,
    QueueChanged,
    ProviderEvent,
    Other(String),
}

impl EventType {
    pub fn parse(name: &str) -> Self {
        match name {
            "run_started" => Self::RunStarted,
            "run_completed" => Self::RunCompleted,
            "run_failed" => Self::RunFailed,
            "run_cancelled" => Self::RunCancelled,
            "session_started" => Self::SessionStarted,
            "session_ready" => Self::SessionReady,
            "session_idle" => Self::SessionIdle,
            "session_closed" => Self::SessionClosed,
            "session_failed" => Self::SessionFailed,
            "session_cancelled" => Self::SessionCancelled,
            "input_accepted" => Self::InputAccepted,
            "turn_queued" => Self::TurnQueued,
            "turn_started" => Self::TurnStarted,
            "output_text_delta" => Self::OutputTextDelta,
            "output_text_final" => Self::OutputTextFinal,
            "thinking_delta" => Self::ThinkingDelta,
            "command_output_delta" => Self::CommandOutputDelta,
            "tool_call" => Self::ToolCall,
            "tool_result" => Self::ToolResult,
            "file_change" => Self::FileChange,
            "plan_updated" => Self::PlanUpdated,
            "usage" => Self::Usage,
            "turn_completed" => Self::TurnCompleted,
            "turn_failed" => Self::TurnFailed,
            "turn_interrupted" => Self::TurnInterrupted,
            "approval_requested" => Self::ApprovalRequested,
            "approval_resolved" => Self::ApprovalResolved,
            "queue_changed" => Self::QueueChanged,
            "provider_event" => Self::ProviderEvent,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::RunStarted => "run_started",
            Self::RunCompleted => "run_completed",
            Self::RunFailed => "run_failed",
            Self::RunCancelled => "run_cancelled",
            Self::SessionStarted => "session_started",
            Self::SessionReady => "session_ready",
            Self::SessionIdle => "session_idle",
            Self::SessionClosed => "session_closed",
            Self::SessionFailed => "session_failed",
            Self::SessionCancelled => "session_cancelled",
            Self::InputAccepted => "input_accepted",
            Self::TurnQueued => "turn_queued",
            Self::TurnStarted => "turn_started",
            Self::OutputTextDelta => "output_text_delta",
            Self::OutputTextFinal => "output_text_final",
            Self::ThinkingDelta => "thinking_delta",
            Self::CommandOutputDelta => "command_output_delta",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::FileChange => "file_change",
            Self::PlanUpdated => "plan_updated",
            Self::Usage => "usage",
            Self::TurnCompleted => "turn_completed",
            Self::TurnFailed => "turn_failed",
            Self::TurnInterrupted => "turn_interrupted",
            Self::ApprovalRequested => "approval_requested",
            Self::ApprovalResolved => "approval_resolved",
            Self::QueueChanged => "queue_changed",
            Self::ProviderEvent => "provider_event",
            Self::Other(name) => name,
        }
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::parse(&String::deserialize(deserializer)?))
    }
}

/// One event from either plane.
///
/// The two structs differ in three fields — the interactive one keys on `session_id` and
/// carries `turn_id`/`request_id`, the coding one keys on `task_id` and carries
/// `harness_sequence` — and are otherwise the same envelope. One type with the union of
/// the optional fields decodes both, and the `raw` copy is what the tree widget draws when
/// a reader wants everything rather than the summary line.
#[derive(Debug, Clone)]
pub struct Event {
    pub id: String,
    pub sequence: u64,
    pub kind: EventType,
    pub timestamp: String,
    pub payload: Value,
    pub turn_id: Option<String>,
    pub request_id: Option<String>,
    pub provider: Option<String>,
    pub struct_tag: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Deserialize)]
struct RawEvent {
    #[serde(default)]
    id: String,
    #[serde(default)]
    sequence: u64,
    #[serde(rename = "type", default = "unknown_event_type")]
    kind: EventType,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    turn_id: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(rename = "_struct", default)]
    struct_tag: Option<String>,
}

fn unknown_event_type() -> EventType {
    EventType::Other("unknown".into())
}

impl Event {
    /// Decodes one event, keeping the original tree beside the summary.
    pub fn decode(value: &Value) -> Result<Self, serde_json::Error> {
        let raw: RawEvent = serde_json::from_value(value.clone())?;

        Ok(Self {
            id: raw.id,
            sequence: raw.sequence,
            kind: raw.kind,
            timestamp: raw.timestamp,
            payload: raw.payload,
            turn_id: raw.turn_id,
            request_id: raw.request_id,
            provider: raw.provider,
            struct_tag: raw.struct_tag,
            raw: value.clone(),
        })
    }

    /// A batch, dropping the entries that do not decode rather than the batch.
    ///
    /// A replay answer is a contiguous window of history; refusing all of it because one
    /// event grew a field this build cannot read would hide the other four hundred.
    pub fn decode_batch(value: &Value) -> (Vec<Self>, usize) {
        let Some(items) = value.as_array() else {
            return (Vec::new(), 0);
        };

        let mut events = Vec::with_capacity(items.len());
        let mut refused = 0;

        for item in items {
            match Self::decode(item) {
                Ok(event) => events.push(event),
                Err(_undecodable) => refused += 1,
            }
        }

        (events, refused)
    }

    /// The one line a transcript shows before the payload.
    pub fn summary(&self) -> String {
        if let Some(text) = self.payload.get("text").and_then(Value::as_str) {
            return text.to_string();
        }

        match &self.payload {
            Value::Object(fields) if fields.is_empty() => String::new(),
            Value::Object(fields) => fields
                .iter()
                .map(|(key, value)| format!("{key}={}", compact(value)))
                .collect::<Vec<_>>()
                .join(" "),
            Value::Null => String::new(),
            other => compact(other),
        }
    }
}

/// A scalar as it appears inline; anything structured keeps its JSON shape rather than
/// being flattened into a guess.
pub fn compact(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "null".into(),
        Value::Object(fields) if fields.len() == 1 => {
            if let Some(Value::String(inspected)) = fields.get("_opaque") {
                return inspected.clone();
            }

            if fields.contains_key("_truncated") {
                return "<truncated>".into();
            }

            if let Some(Value::String(encoded)) = fields.get("_b64") {
                return format!("<{} base64 bytes>", encoded.len());
            }

            value.to_string()
        }
        other => other.to_string(),
    }
}

/// One entry of `interactive.list`/`coding.list`, and of `info`.
///
/// `interactive.list` answers `Interactive.State.public/1` structs and `coding.list`
/// answers `Coding.TaskState.public/1` structs; the fields below are the ones both carry
/// under the same names. Everything else — turns, options, the retained event window —
/// stays in `raw` for the tree widget, because a session's own shape is exactly what a
/// forged plane is free to change.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub plane: Plane,
    pub id: String,
    pub status: SessionStatus,
    pub provider: Option<String>,
    pub node: Option<String>,
    pub workspace: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub objective: Option<String>,
    pub struct_tag: Option<String>,
    pub raw: Value,
}

#[derive(Debug, Deserialize)]
struct RawSession {
    #[serde(default)]
    id: String,
    #[serde(default = "unknown_status")]
    status: SessionStatus,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    workspace: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    /// Coding tasks only.
    #[serde(default)]
    objective: Option<String>,
    #[serde(rename = "_struct", default)]
    struct_tag: Option<String>,
}

fn unknown_status() -> SessionStatus {
    SessionStatus::Other("unknown".into())
}

impl SessionInfo {
    pub fn decode(plane: Plane, value: &Value) -> Result<Self, serde_json::Error> {
        let raw: RawSession = serde_json::from_value(value.clone())?;

        if raw.id.is_empty() {
            return Err(serde_json::Error::custom(
                "a session without an id cannot be addressed",
            ));
        }

        Ok(Self {
            plane,
            id: raw.id,
            status: raw.status,
            provider: raw.provider,
            node: raw.node,
            workspace: raw.workspace,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            objective: raw.objective,
            struct_tag: raw.struct_tag,
            raw: value.clone(),
        })
    }

    pub fn decode_list(plane: Plane, value: &Value) -> Vec<Self> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| Self::decode(plane, item).ok())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// `runtime.status`, as far as a Dashboard needs to lay it out.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuntimeStatus {
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub connected_nodes: Vec<String>,
    /// Either `Cluster.status/0`'s seven keys or the `%{mode: :unavailable}` fallback, so
    /// it stays a tree rather than a type.
    #[serde(default)]
    pub cluster: Value,
    /// Sorted by construction: `serde_json::Map` is a `BTreeMap` unless `preserve_order`
    /// is on, and a `BTreeMap` here says so rather than relying on it.
    #[serde(default)]
    pub availability: BTreeMap<String, Availability>,
    #[serde(default)]
    pub agents: Vec<Value>,
    #[serde(default)]
    pub coding_tasks: Vec<Value>,
    #[serde(default)]
    pub interactive_sessions: Vec<Value>,
    #[serde(default)]
    pub teams: Vec<Value>,
    #[serde(default)]
    pub orchestration_plans: Vec<Value>,
    #[serde(default)]
    pub control: ControlStatus,
    #[serde(default)]
    pub upgrade: Value,
    #[serde(default)]
    pub release: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ControlStatus {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub runs: Vec<Value>,
}

impl RuntimeStatus {
    pub fn decode(value: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }

    /// What `mode` a sub-map reports, for the two that have one.
    pub fn mode(&self, section: &str) -> Option<&str> {
        let value = match section {
            "upgrade" => &self.upgrade,
            "release" => &self.release,
            _ => return None,
        };

        value.get("mode").and_then(Value::as_str)
    }

    /// The cluster line, assembled from whichever of the two shapes arrived.
    pub fn cluster_summary(&self) -> String {
        if self.cluster.is_null() {
            return "-".into();
        }

        let mut parts = Vec::new();

        if let Some(strategy) = self
            .cluster
            .get("formation")
            .and_then(|formation| formation.get("strategy"))
        {
            parts.push(format!("strategy={}", compact(strategy)));
        }

        if let Some(distributed) = self.cluster.get("distributed") {
            parts.push(format!("distributed={}", compact(distributed)));
        }

        if let Some(mode) = self.cluster.get("mode") {
            parts.push(format!("mode={}", compact(mode)));
        }

        if parts.is_empty() {
            return compact(&self.cluster);
        }

        parts.join("  ")
    }
}

/// One entry of `runtime.providers`: the adapter spec, the probe, and why the probe
/// failed when it did.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderEntry {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub spec: Value,
    /// `null` when the probe failed or timed out — which is a different fact from "this
    /// provider is not installed", and is rendered as one.
    #[serde(default)]
    pub status: Option<ProviderProbe>,
    #[serde(default)]
    pub error: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProviderProbe {
    #[serde(default)]
    pub installed: bool,
    #[serde(default)]
    pub compatible: bool,
    /// `true`, `false`, or the string `"unknown"` — the harness declares all three.
    #[serde(default)]
    pub authenticated: Value,
    #[serde(default)]
    pub smoke_ready: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub executable: Option<String>,
}

impl ProviderEntry {
    pub fn decode_list(value: &Value) -> Vec<Self> {
        value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value(item.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether this provider could plausibly serve a session right now.
    pub fn ready(&self) -> bool {
        self.status
            .as_ref()
            .map(|probe| probe.installed && probe.compatible)
            .unwrap_or(false)
    }
}

/// `stream.lagged`: the gateway dropped event frames for this session and says how many.
#[derive(Debug, Clone, Deserialize)]
pub struct Lagged {
    pub id: String,
    #[serde(default)]
    pub plane: Option<String>,
    #[serde(default)]
    pub dropped: u64,
    /// The sequence of the newest frame discarded — how far ahead the session had run.
    #[serde(default)]
    pub last_sequence: u64,
}

/// `stream.ended`: no further events will arrive for this session.
#[derive(Debug, Clone, Deserialize)]
pub struct Ended {
    pub id: String,
    #[serde(default)]
    pub plane: Option<String>,
    /// `"unknown"` when the coordinator died rather than the session finishing.
    #[serde(default)]
    pub status: String,
}

impl Lagged {
    pub fn plane(&self) -> Option<Plane> {
        self.plane.as_deref().and_then(Plane::parse)
    }
}

impl Ended {
    pub fn plane(&self) -> Option<Plane> {
        self.plane.as_deref().and_then(Plane::parse)
    }
}

/// The one error payload a client branches on rather than displays: `-32006` with
/// `reason: "cursor_pruned"`. Everything else in an error's `data` is meant to be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPruned {
    pub floor: u64,
}

impl CursorPruned {
    /// Matches on the discriminator, not on the code alone: `-32006` is the generic
    /// upstream-error code and most of them carry a Wire-encoded reason instead.
    pub fn from_error_data(data: Option<&Value>) -> Option<Self> {
        let data = data?;

        if data.get("reason").and_then(Value::as_str) != Some("cursor_pruned") {
            return None;
        }

        Some(Self {
            floor: data.get("floor").and_then(Value::as_u64).unwrap_or(0),
        })
    }
}

/// Whether a `-32005` admits that the runtime may still be working on the request.
pub fn outcome_unknown(data: Option<&Value>) -> bool {
    data.and_then(|data| data.get("outcome"))
        .and_then(Value::as_str)
        == Some("unknown")
}

/// The three values `interactive.respond_approval` accepts for a decision and a scope,
/// spelled out here because they are `Jido.Harness.ApprovalResponse`'s and nothing else's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalScope {
    Once,
    Session,
}

impl ApprovalDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

impl ApprovalScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
        }
    }
}

/// The exact `params` for one approval answer.
///
/// Built here rather than at the call site so the allowlist the gateway enforces —
/// `decision` in `approve|deny`, `scope` in `once|session`, and nothing else, because
/// `provider_options` is deliberately not accepted — is stated once, in a type, instead of
/// being spelled into a `json!` literal that a later edit could widen.
pub fn respond_approval_params(
    session_id: &str,
    request_id: &str,
    decision: ApprovalDecision,
    scope: ApprovalScope,
) -> Value {
    serde_json::json!({
        "id": session_id,
        "request_id": request_id,
        "response": { "decision": decision.as_str(), "scope": scope.as_str() },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ErrorCode, Hello, Incoming, Notification, RpcError};

    /// Every fixture is read from the checkout rather than embedded, so a regeneration on
    /// the Elixir side is picked up by the next `cargo test` without a copy step.
    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../test/support/gateway_golden")
            .join(format!("{name}.json"));

        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));

        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{} is not JSON: {error}", path.display()))
    }

    /// A fixture decoded the way the transport decodes a line, so the tests exercise the
    /// frame layer rather than reaching past it.
    fn frame(name: &str) -> Incoming {
        let bytes = serde_json::to_vec(&fixture(name)).expect("re-encodable");
        Incoming::decode(&bytes).expect("a decodable frame")
    }

    fn result(name: &str) -> Value {
        match frame(name) {
            Incoming::Response { outcome, .. } => (*outcome).expect("a result"),
            other => panic!("{name} is not a result frame: {other:?}"),
        }
    }

    fn error(name: &str) -> RpcError {
        match frame(name) {
            Incoming::Response { outcome, .. } => (*outcome).expect_err("an error"),
            other => panic!("{name} is not an error frame: {other:?}"),
        }
    }

    fn notification(name: &str) -> Notification {
        match frame(name) {
            Incoming::Notification(notification) => notification,
            other => panic!("{name} is not a notification: {other:?}"),
        }
    }

    #[test]
    fn hello_result_decodes_into_the_feature_gate() {
        let hello: Hello = serde_json::from_value(result("hello_result")).expect("a handshake");

        assert_eq!(hello.protocol, 1);
        assert_eq!(hello.scope, "operate");
        assert_eq!(hello.node, "ouroboros@golden");
        assert_eq!(hello.role, "core");
        assert!(hello.operates());
        assert!(hello.serves("interactive.respond_approval"));
        assert!(hello.serves("runtime.shutdown"));
        assert!(!hello.serves("mesh.send_message"));
    }

    #[test]
    fn runtime_status_decodes_with_a_tri_state_availability_matrix() {
        let status = RuntimeStatus::decode(&result("runtime_status_result")).expect("a status");

        assert_eq!(status.node, "ouroboros@golden");
        assert_eq!(status.role, "core");
        assert!(status.connected_nodes.is_empty());

        assert_eq!(
            status.availability.get("mesh"),
            Some(&Availability::Available)
        );
        assert_eq!(
            status.availability.get("control"),
            Some(&Availability::Disabled)
        );
        assert_eq!(
            status.availability.get("workspace"),
            Some(&Availability::Disabled)
        );
        assert_eq!(status.availability.len(), 10);

        assert_eq!(status.mode("upgrade"), Some("ready"));
        assert_eq!(status.mode("release"), Some("ready"));
        assert!(!status.control.enabled);
        assert_eq!(status.cluster_summary(), "strategy=none  distributed=false");
    }

    #[test]
    fn runtime_status_keeps_the_opaque_marker_a_pid_became() {
        let status = RuntimeStatus::decode(&result("runtime_status_result")).expect("a status");
        let agent = &status.agents[0];

        assert_eq!(agent["id"], "reviewer-1");
        assert_eq!(agent["pid"]["_opaque"], "#PID<0.123.0>");
        assert_eq!(compact(&agent["pid"]), "#PID<0.123.0>");
    }

    #[test]
    fn runtime_status_session_summaries_decode_as_sessions() {
        let status = RuntimeStatus::decode(&result("runtime_status_result")).expect("a status");

        let sessions = status
            .interactive_sessions
            .iter()
            .filter_map(|value| SessionInfo::decode(Plane::Interactive, value).ok())
            .collect::<Vec<_>>();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "session-0000000000000000000001");
        assert_eq!(sessions[0].status, SessionStatus::Idle);
        assert_eq!(sessions[0].provider.as_deref(), Some("claude_code"));

        let tasks = status
            .coding_tasks
            .iter()
            .filter_map(|value| SessionInfo::decode(Plane::Coding, value).ok())
            .collect::<Vec<_>>();

        assert_eq!(tasks[0].status, SessionStatus::Running);
        assert!(tasks[0].status.busy());
        assert!(!tasks[0].status.terminal());
    }

    #[test]
    fn an_interactive_event_notification_decodes_and_keeps_its_struct_tag() {
        let notification = notification("interactive_event_notification");

        assert_eq!(notification.method, "interactive.event");
        assert_eq!(notification.params["id"], "session-0000000000000000000001");

        let event = Event::decode(&notification.params["event"]).expect("an event");

        assert_eq!(event.sequence, 42);
        assert_eq!(event.kind, EventType::OutputTextFinal);
        assert_eq!(
            event.struct_tag.as_deref(),
            Some("Ouroboros.Interactive.Event")
        );
        assert_eq!(
            event.turn_id.as_deref(),
            Some("turn-0000000000000000000001")
        );
        assert_eq!(event.request_id, None);
        assert_eq!(event.summary(), "the workspace is clean");
        assert_eq!(event.payload["token"], "[REDACTED]");
    }

    #[test]
    fn a_coding_event_notification_decodes_through_the_same_type() {
        let notification = notification("coding_event_notification");

        assert_eq!(notification.method, "coding.event");
        assert_eq!(notification.params["id"], "task-0000000000000000000000002");

        let event = Event::decode(&notification.params["event"]).expect("an event");

        assert_eq!(event.sequence, 17);
        assert_eq!(event.kind, EventType::RunCompleted);
        assert_eq!(event.struct_tag.as_deref(), Some("Ouroboros.Coding.Event"));
        // The coding struct keys on `task_id` and carries no turn; both are absent rather
        // than defaulted to something that looks like an answer.
        assert_eq!(event.turn_id, None);
        assert_eq!(event.raw["task_id"], "task-0000000000000000000000002");
        assert_eq!(event.summary(), "objective satisfied");
    }

    #[test]
    fn stream_lagged_carries_the_plane_and_the_resync_facts() {
        let lagged: Lagged =
            serde_json::from_value(notification("stream_lagged_notification").params)
                .expect("a lag notification");

        assert_eq!(lagged.id, "session-0000000000000000000001");
        assert_eq!(lagged.plane(), Some(Plane::Interactive));
        assert_eq!(lagged.dropped, 128);
        assert_eq!(lagged.last_sequence, 512);
    }

    #[test]
    fn stream_ended_carries_a_terminal_status() {
        let ended: Ended = serde_json::from_value(notification("stream_ended_notification").params)
            .expect("an end notification");

        assert_eq!(ended.id, "session-0000000000000000000001");
        assert_eq!(ended.plane(), Some(Plane::Interactive));
        assert_eq!(ended.status, "closed");
        assert!(SessionStatus::parse(&ended.status).terminal());
    }

    #[test]
    fn the_cursor_pruned_error_is_matched_on_its_reason_and_yields_a_floor() {
        let error = error("error_cursor_pruned");

        assert_eq!(error.code, ErrorCode::UpstreamError);

        let pruned = CursorPruned::from_error_data(error.data.as_ref()).expect("a pruned cursor");

        assert_eq!(pruned.floor, 96);

        // The same code without the discriminator is an error to display, not to branch on.
        let generic = serde_json::json!({ "kind": "some_upstream_reason" });
        assert_eq!(CursorPruned::from_error_data(Some(&generic)), None);
    }

    #[test]
    fn an_upstream_timeout_can_admit_it_does_not_know() {
        let error = error("error_upstream_timeout_unknown");

        assert_eq!(error.code, ErrorCode::UpstreamTimeout);
        assert!(outcome_unknown(error.data.as_ref()));
        assert!(!outcome_unknown(None));
    }

    #[test]
    fn the_refusal_fixtures_decode_with_their_codes() {
        for (name, code) in [
            ("error_unauthenticated", ErrorCode::Unauthenticated),
            ("error_protocol_mismatch", ErrorCode::ProtocolMismatch),
            ("error_scope_denied", ErrorCode::ScopeDenied),
            ("error_not_found", ErrorCode::NotFound),
            ("error_invalid_request", ErrorCode::InvalidRequest),
        ] {
            let error = error(name);

            assert_eq!(error.code, code, "{name}");
            assert!(!error.message.is_empty(), "{name} must say why");
        }

        assert_eq!(error("error_protocol_mismatch").server_protocol(), Some(1));
        assert!(error("error_unauthenticated").code.is_handshake_refusal());
        assert!(!error("error_scope_denied").code.is_handshake_refusal());
    }

    #[test]
    fn every_golden_fixture_is_accounted_for() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../test/support/gateway_golden");

        let mut found: Vec<String> = std::fs::read_dir(&dir)
            .expect("the golden fixtures")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                name.strip_suffix(".json").map(str::to_string)
            })
            .collect();

        found.sort();

        // Named rather than counted: a fixture added upstream must be decoded here on
        // purpose, and this is where a client learns it exists.
        assert_eq!(
            found,
            vec![
                "coding_event_notification",
                "error_cursor_pruned",
                "error_invalid_request",
                "error_not_found",
                "error_protocol_mismatch",
                "error_scope_denied",
                "error_unauthenticated",
                "error_upstream_timeout_unknown",
                "hello_result",
                "interactive_event_notification",
                "runtime_status_result",
                "stream_ended_notification",
                "stream_lagged_notification",
            ]
        );
    }

    #[test]
    fn an_unknown_enum_value_survives_rather_than_failing_the_decode() {
        let event = Event::decode(&serde_json::json!({
            "id": "e",
            "sequence": 1,
            "type": "capability_forged",
            "timestamp": "2026-01-01T00:00:00Z",
            "payload": { "module": "Ouroboros.Capability.Novel" },
            "a_field_from_a_newer_runtime": true
        }))
        .expect("a tolerant decode");

        assert_eq!(event.kind, EventType::Other("capability_forged".into()));
        assert_eq!(event.kind.as_str(), "capability_forged");

        let availability: BTreeMap<String, Availability> =
            serde_json::from_value(serde_json::json!({ "forged_lane": "degraded" }))
                .expect("a tolerant matrix");

        assert_eq!(
            availability.get("forged_lane"),
            Some(&Availability::Other("degraded".into()))
        );

        assert_eq!(
            SessionStatus::parse("hibernating"),
            SessionStatus::Other("hibernating".into())
        );
        assert!(
            !SessionStatus::parse("hibernating").terminal(),
            "a status this build does not know is not one it may declare finished"
        );
    }

    #[test]
    fn a_batch_keeps_what_it_can_read_and_counts_what_it_cannot() {
        let (events, refused) = Event::decode_batch(&serde_json::json!([
            { "id": "a", "sequence": 1, "type": "usage", "timestamp": "t", "payload": {} },
            { "id": "b", "sequence": "not a number", "type": "usage" },
            { "id": "c", "sequence": 3, "type": "usage", "timestamp": "t", "payload": {} },
        ]));

        assert_eq!(events.len(), 2);
        assert_eq!(refused, 1);
        assert_eq!(events[1].sequence, 3);
    }

    #[test]
    fn an_approval_answer_carries_only_what_the_plane_accepts() {
        let params = respond_approval_params(
            "session-1",
            "req-9",
            ApprovalDecision::Deny,
            ApprovalScope::Session,
        );

        assert_eq!(params["id"], "session-1");
        assert_eq!(params["request_id"], "req-9");
        assert_eq!(params["response"]["decision"], "deny");
        assert_eq!(params["response"]["scope"], "session");
        assert_eq!(
            params["response"].as_object().expect("an object").len(),
            2,
            "provider_options is deliberately not accepted by the gateway"
        );
    }

    #[test]
    fn provider_entries_separate_a_failed_probe_from_a_missing_provider() {
        let providers = ProviderEntry::decode_list(&serde_json::json!([
            {
                "provider": "claude_code",
                "spec": { "provider": "claude_code" },
                "status": {
                    "installed": true, "compatible": true, "authenticated": "unknown",
                    "smoke_ready": false, "version": "1.2.3", "executable": "/usr/bin/claude"
                },
                "error": null
            },
            { "provider": "codex", "spec": {}, "status": null, "error": "probe_timeout" }
        ]));

        assert_eq!(providers.len(), 2);
        assert!(providers[0].ready());
        assert_eq!(
            providers[0].status.as_ref().unwrap().version.as_deref(),
            Some("1.2.3")
        );
        assert!(!providers[1].ready());
        assert!(
            providers[1].status.is_none(),
            "a failed probe is not a false negative"
        );
        assert_eq!(providers[1].error, "probe_timeout");
    }

    #[test]
    fn a_plane_round_trips_through_its_wire_name() {
        for plane in [Plane::Interactive, Plane::Coding] {
            assert_eq!(Plane::parse(plane.as_str()), Some(plane));
        }

        assert_eq!(Plane::parse("teams"), None);
        assert_eq!(Plane::Coding.method("replay"), "coding.replay");
    }
}
