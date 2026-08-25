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
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRngCore;
use serde::de::{Deserializer, Error as _};
use serde::Deserialize;
use serde_json::Value;

use crate::proto::{ErrorCode, RpcError};
use crate::transport::ClientError;

static SESSION_ID_FALLBACK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub mod native;
pub mod transcript;

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

/// G2. Which of the three questions a fleet row answers: does it need me, is it working,
/// or is it done.
///
/// The order is the order they are drawn in, and it is the whole point of the grouping —
/// what needs a human is what a person opening `ouro` is looking for, and it must not be
/// below eleven finished sessions from yesterday.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Triage {
    NeedsInput,
    Working,
    Done,
}

impl Triage {
    pub const ALL: [Self; 3] = [Self::NeedsInput, Self::Working, Self::Done];

    pub fn label(self) -> &'static str {
        match self {
            Self::NeedsInput => "NEEDS INPUT",
            Self::Working => "WORKING",
            Self::Done => "DONE",
        }
    }

    /// The one-word form `ouro agents --json` and the footer use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeedsInput => "needs_input",
            Self::Working => "working",
            Self::Done => "done",
        }
    }
}

impl SessionInfo {
    /// Which group this row belongs to, from *declared* state and nothing else.
    ///
    /// The three inputs are the plane's own `status`, the pending approvals this client
    /// is holding for the session, and whether the runtime says the session is waiting on
    /// a human. Never a guess: a row whose owner is offline keeps whichever group its
    /// last complete observation put it in, because "we cannot see it right now" is not
    /// the same claim as "it needs you" — and a client that promoted every unreachable
    /// session to the top would make the top of the list meaningless.
    pub fn triage(&self, pending_approvals: usize) -> Triage {
        if pending_approvals > 0 || self.status == SessionStatus::AwaitingApproval {
            return Triage::NeedsInput;
        }

        if self.status.terminal() {
            return Triage::Done;
        }

        if self.status.busy() {
            return Triage::Working;
        }

        // `idle` on the interactive plane is a conversation waiting for its next prompt —
        // a human's turn, which is exactly what this grouping is for. On the coding plane
        // there is nobody to prompt it, so an idle task is simply between turns.
        match (self.plane, &self.status) {
            (Plane::Interactive, SessionStatus::Idle) => Triage::NeedsInput,
            _otherwise => Triage::Working,
        }
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
            Value::Object(fields) => sorted_fields(fields)
                .into_iter()
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

            sorted_json(value).to_string()
        }
        other => sorted_json(other).to_string(),
    }
}

/// A map's entries in sorted key order, whatever order the map itself iterates in.
///
/// `serde_json::Map` is only a `BTreeMap` until something turns on `preserve_order` — and
/// the desktop build's gpui dependency tree does, for the whole crate graph, features
/// being additive. A rendering that followed the map's own order would therefore say
/// different things in `ouro` and `ouro-desktop`. Every user-facing walk of a payload map
/// sorts instead, so the same payload reads the same in both binaries.
pub fn sorted_fields(fields: &serde_json::Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<_> = fields.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    entries
}

/// The same value rebuilt with every object's keys in sorted order, ready to serialise.
///
/// [`sorted_fields`] settles what a *walk* says; this settles what a *serialisation*
/// says. `Value`'s `Display` and `to_string_pretty` write keys in whatever order the
/// `Map` holds, so a JSON blob shown to a person or written to an export would otherwise
/// differ between the two binaries. Key order is not part of what a JSON object says, so
/// sorting it is a canonical form, not a reshaping.
pub fn sorted_json(value: &Value) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            sorted_fields(fields)
                .into_iter()
                .map(|(key, value)| (key.clone(), sorted_json(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sorted_json).collect()),
        scalar => scalar.clone(),
    }
}

/// What one entry of `options.capabilities` said.
///
/// Three states rather than a `bool`, and the third one is the point. The runtime derives
/// this map from the transport a session actually selected; a gateway that predates the
/// declaration sends no map at all, and a map a later runtime extends carries keys this
/// build has never heard of. Neither of those is the runtime saying "no", so neither
/// becomes [`Capability::No`] — and only [`Capability::No`] is allowed to take a key off
/// the screen (D14: the client never asserts a limit the runtime did not declare).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Capability {
    /// No claim was made. Chrome that depends on it stays as it was.
    #[default]
    Unknown,
    /// Declared `false`. The transport cannot do this at all, and nothing offers it.
    No,
    /// Declared as a mechanism — `native`, `managed`, `process`, or a word a later
    /// runtime invents. Carried verbatim rather than collapsed to `true`, because
    /// "managed" and "native" are different promises about *when* a control takes effect.
    Yes(String),
}

impl Capability {
    fn decode(value: Option<&Value>) -> Self {
        match value {
            None | Some(Value::Null) => Self::Unknown,
            Some(Value::Bool(false)) => Self::No,
            Some(Value::Bool(true)) => Self::Yes("true".to_string()),
            Some(Value::String(mechanism)) if mechanism.trim().is_empty() => Self::Unknown,
            Some(Value::String(mechanism)) => Self::Yes(mechanism.clone()),
            // A shape this build cannot read is not a refusal. Treated as unknown so a
            // later runtime that answers a capability with an object does not silently
            // delete a working key from this client's chrome.
            Some(_other) => Self::Unknown,
        }
    }

    /// Whether chrome that depends on this capability is offered.
    ///
    /// Everything but an explicit `false`. An unknown capability keeps whatever the
    /// client did before the declaration existed, because hiding a control the runtime
    /// never spoke about would be this client inventing a ceiling.
    pub fn offered(&self) -> bool {
        !matches!(self, Self::No)
    }

    /// Whether the runtime positively declared it. The footer uses this for the facts it
    /// only states when it knows them.
    pub fn declared(&self) -> bool {
        matches!(self, Self::Yes(_))
    }

    /// The mechanism the runtime named, if it named one.
    pub fn mechanism(&self) -> Option<&str> {
        match self {
            Self::Yes(mechanism) => Some(mechanism.as_str()),
            _ => None,
        }
    }
}

/// `options.capabilities` from `Interactive.State.public/1`.
///
/// Derived server-side from the provider spec and the transport the session selected, so
/// it is answered for a session listed after a restart as well as for a live one. Every
/// field defaults to [`Capability::Unknown`], which is what an older gateway's silence
/// means.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// The transport's own name (`app_server`, `acp`, `managed`, …). A label, not a
    /// yes/no, so it is kept as the string the runtime used.
    pub transport: Option<String>,
    pub process: Capability,
    pub multi_turn: Capability,
    pub follow_up: Capability,
    pub interrupt: Capability,
    pub approvals: Capability,
    pub steer: Capability,
    pub multimodal: Capability,
    /// Whether this transport can branch a session (Codex `thread/fork`, Claude
    /// `--fork-session`). A key the runtime has not spoken about is *unknown*, not "no",
    /// so the backtrack menu offers the fork wherever `interactive.fork` is served and the
    /// runtime has not said the transport cannot.
    pub fork: Capability,
    pub dynamic_model: Capability,
    pub dynamic_configuration: Capability,
    /// C5. Which OS sandbox the runtime actually put this session's process in —
    /// `sandbox-exec` on macOS, `bwrap` on Linux, or the literal `"none"` where the
    /// platform offered neither and the session runs unconfined.
    ///
    /// Held as a mechanism rather than a yes/no because the three answers are three
    /// different things to say, and because `"none"` is a *positive* claim: it is the
    /// runtime reporting that nothing is between the agent and the filesystem, which is
    /// worth a line of chrome. Silence stays [`Capability::Unknown`] and draws nothing —
    /// a client that rendered "no OS sandbox" from an absent key would be inventing the
    /// most alarming of the three answers out of an older gateway's silence.
    pub sandbox: Capability,
    /// Whether a map was present at all. `false` means an older gateway, and is the
    /// difference between "this session cannot steer" and "nobody said".
    pub declared: bool,
}

impl Capabilities {
    /// Reads `options.capabilities`. Unknown keys are ignored; an absent or non-object
    /// value is "unknown", never "false".
    pub fn decode(value: Option<&Value>) -> Self {
        let Some(map) = value.and_then(Value::as_object) else {
            return Self::default();
        };

        let at = |key: &str| Capability::decode(map.get(key));

        Self {
            transport: map
                .get("transport")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
            process: at("process"),
            multi_turn: at("multi_turn"),
            follow_up: at("follow_up"),
            interrupt: at("interrupt"),
            approvals: at("approvals"),
            steer: at("steer"),
            multimodal: at("multimodal"),
            fork: at("fork"),
            dynamic_model: at("dynamic_model"),
            dynamic_configuration: at("dynamic_configuration"),
            sandbox: at("sandbox"),
            declared: true,
        }
    }
}

impl Capabilities {
    /// How the chrome names the OS sandbox, or `None` where the runtime did not say.
    ///
    /// Three answers and a silence, and the silence renders nothing: `sandbox_mode` is
    /// the policy a session was *started* with, and this is the mechanism that enforces
    /// it. A client that turned "nobody said" into either "confined" or "unconfined"
    /// would be asserting the one fact an operator most needs to be true.
    pub fn os_sandbox(&self) -> Option<&str> {
        match self.sandbox.mechanism()?.trim() {
            "" => None,
            // The runtime's own word for "the platform offered nothing and the process
            // runs unconfined". Said in a sentence rather than as a mechanism name,
            // because `sandbox: workspace_write · none` reads like a mechanism called
            // "none" rather than like the absence of one.
            "none" => Some("no OS sandbox"),
            mechanism => Some(mechanism),
        }
    }
}

/// What the provider said this session has spent, as `Interactive.State` folded it.
///
/// Every field is optional because a partial map is the ordinary case: the runtime keeps
/// a counter at `0` when no `:usage` event carried it, and leaves `cost_usd` `nil` rather
/// than turning "not reported" into a zero that reads as "free". A field this build
/// cannot read stays `None` and is not drawn.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_creation_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
    pub turns_with_usage: Option<u64>,
    /// The model's context window, for the footer's `%` meter.
    ///
    /// `interactive.info` carries it where a provider named one — a `usage` event's own
    /// `context_window`, or a native session's own count (D9). A `list` row does not: the
    /// runtime reduces a row's `usage` to tokens and cost, so the meter lights up on the
    /// open session and stays dark in the rail, which is the honest asymmetry.
    pub context_window: Option<u64>,
    /// How much of that window the *last request* filled, as the provider counted it.
    ///
    /// This is the numerator the meter needs, and it is not `total_tokens`: a session's
    /// cumulative spend crosses its own window many times over, so a percentage built
    /// from it would climb past 100% on a conversation that was never close to full.
    pub context_used: Option<u64>,
}

impl SessionUsage {
    /// Reads the session's `usage` map. `None` when there is no map: a session that has
    /// spent nothing and a session whose spend was never reported are different facts.
    pub fn decode(value: Option<&Value>) -> Option<Self> {
        let map = value.and_then(Value::as_object)?;

        let count = |key: &str| map.get(key).and_then(Value::as_u64);

        Some(Self {
            input_tokens: count("input_tokens"),
            output_tokens: count("output_tokens"),
            cache_read_tokens: count("cache_read_tokens"),
            cache_creation_tokens: count("cache_creation_tokens"),
            total_tokens: count("total_tokens"),
            cost_usd: map.get("cost_usd").and_then(Value::as_f64),
            turns_with_usage: count("turns_with_usage"),
            context_window: count("context_window"),
            context_used: count("context_used"),
        })
    }

    /// How full the window is, where both halves were reported.
    ///
    /// `None` rather than a guess: a provider that named no window gets no percentage,
    /// and one that named a window but has not spent a turn yet gets none either — a
    /// meter reading 0% on a session with a loaded prefix would be a measurement nobody
    /// made.
    pub fn context_share(&self) -> Option<u64> {
        let window = self.context_window.filter(|window| *window > 0)?;
        let used = self.context_used.filter(|used| *used > 0)?;

        Some((used.saturating_mul(100) / window).min(999))
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
    /// A human or runtime-generated title for interactive sessions. Coding tasks keep
    /// using their objective; older gateways omit this field entirely.
    pub title: Option<String>,
    pub status: SessionStatus,
    pub provider: Option<String>,
    pub node: Option<String>,
    pub workspace: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub objective: Option<String>,
    pub struct_tag: Option<String>,
    /// `options.model`, as the session was started. `None` where the start did not name
    /// one — the provider then chose, and the transcript's `run_started` is the only
    /// place that choice is reported.
    pub model: Option<String>,
    /// `options.approval_mode` / `options.sandbox_mode`, verbatim. `None` means the start
    /// omitted them and the plane's own default applies, which is a fact this client does
    /// not have.
    pub approval_mode: Option<String>,
    pub sandbox_mode: Option<String>,
    /// B2. `options.plan` — whether this session is planning: read-only, holding its
    /// terminal event at the end of a planning turn to ask whether to build the plan.
    ///
    /// A plain `bool` rather than an `Option<bool>` on purpose, and it is the one option
    /// here that is: an older gateway omits the key, and "this runtime never told me it was
    /// planning" and "this session is not planning" are the same fact for a client that
    /// must decide whether to draw a `PLANNING` badge. The badge claims the session *is*
    /// planning, so silence must not raise it.
    pub plan: bool,
    /// What the transport this session selected can actually do (B0/D14).
    pub capabilities: Capabilities,
    /// What the provider reported spending, folded by the runtime.
    pub usage: Option<SessionUsage>,
    /// G1. The coding task ids this conversation delegated — ids only, which is what the
    /// row carries. Empty where it delegated nothing *and* where the gateway predates the
    /// key: both are "this client knows of no children", and the rail nests nothing
    /// either way rather than drawing an empty branch.
    pub children: Vec<String>,
    /// G1, the other half. Coding rows only: the conversation that delegated this task.
    pub parent: Option<native::Parent>,
    /// D7. The `git worktree` this session was given, where it asked for one.
    pub worktree: Option<native::Worktree>,
    /// D7. Whether the start asked for a worktree. Kept beside `worktree` because a
    /// request the runtime could not honour is a different fact from never asking.
    pub worktree_requested: bool,
    /// D9. The session this one's opening packet was written from. Held apart from
    /// `forked_from` because the two are different claims: a fork carries the parent's
    /// conversation, a handoff carries a packet *about* it.
    pub handed_off_from: Option<String>,
    /// This row came from the previous complete list because runtime.status explicitly
    /// reports its owner offline. It is retained for addressability, not presented as a
    /// fresh observation.
    pub last_known: bool,
    pub raw: Value,
}

#[derive(Debug, Deserialize)]
struct RawSession {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: Option<String>,
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

        // Read out of the raw tree rather than through `RawSession`: `options` is a
        // projection whose keys the runtime is free to extend, and a strict struct here
        // would be the one place this client refuses a session because a later build
        // described it more fully.
        let options = value.get("options");
        let option = |key: &str| {
            options
                .and_then(|options| options.get(key))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        };

        Ok(Self {
            plane,
            id: raw.id,
            title: raw
                .title
                .map(|title| title.trim().to_string())
                .filter(|title| !title.is_empty()),
            status: raw.status,
            provider: raw.provider,
            node: raw.node,
            workspace: raw.workspace,
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            objective: raw.objective,
            struct_tag: raw.struct_tag,
            model: option("model"),
            approval_mode: option("approval_mode"),
            sandbox_mode: option("sandbox_mode"),
            plan: options
                .and_then(|options| options.get("plan"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            capabilities: Capabilities::decode(
                options.and_then(|options| options.get("capabilities")),
            ),
            usage: SessionUsage::decode(value.get("usage")),
            // Read tolerantly out of the raw tree for the same reason `options` is: these
            // five keys arrived with D7/D9/G1, an older gateway sends none of them, and a
            // strict field here would be the one place this client refuses a session
            // because its runtime is a build behind.
            children: value
                .get("children")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(native::MAX_ROWS)
                        .filter_map(Value::as_str)
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            parent: native::Parent::decode(value.get("parent")),
            worktree: native::Worktree::decode(value.get("worktree")),
            worktree_requested: value
                .get("worktree_requested")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            handed_off_from: value
                .get("handed_off_from")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string),
            last_known: false,
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
    /// Sorted by construction: `serde_json::Map` is only a `BTreeMap` until
    /// `preserve_order` is on — and the desktop build's gpui tree turns it on — so a
    /// `BTreeMap` here says sorted rather than relying on it.
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
    /// Signer posture and live capability count. Absent on older gateways.
    #[serde(default)]
    pub forge: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ControlStatus {
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

    /// Signer posture and how many capabilities are live, from whatever `status.forge` sent.
    pub fn forge_summary(&self) -> String {
        if self.forge.is_null() {
            return "-".into();
        }

        let signer = self
            .forge
            .get("signer")
            .map(compact)
            .unwrap_or_else(|| "-".into());
        let live = self
            .forge
            .get("live_count")
            .map(compact)
            .unwrap_or_else(|| "-".into());
        let admit = match self.forge.get("admit_possible?").and_then(Value::as_bool) {
            Some(true) => "admit=yes",
            Some(false) => "admit=no",
            None => "admit=?",
        };

        format!("signer={signer} live={live} {admit}")
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

    /// What the interactive transport this provider's sessions will select can do.
    ///
    /// The same map `Interactive.State.public/1` projects, read here from the spec so the
    /// `n` dialog can say what a session *would* be able to do before one exists.
    pub fn session_capabilities(&self) -> Capabilities {
        Capabilities::decode(
            self.selected_transport()
                .and_then(|transport| transport.get("capabilities")),
        )
    }

    /// Why `mode` cannot be the approval mode of a session on this provider, or `None`
    /// when it can be — or when the spec does not say, which is not the same thing.
    ///
    /// Mirrors `Ouroboros.Provider.safety_options/3`: an option the selected transport
    /// does not normalize takes only `default`; an option it normalizes with an
    /// allowlist takes only what the allowlist names. X1 is the extra clause — `prompt`
    /// promises a human is asked, and a transport with `approvals: false` has no channel
    /// to ask through, so the runtime refuses it even though the schema accepts it.
    pub fn approval_mode_refusal(&self, mode: ApprovalMode) -> Option<String> {
        if mode == ApprovalMode::Default {
            return None;
        }

        if let Some(refusal) = self.normalized_refusal("approval_mode", mode.as_str()) {
            return Some(refusal);
        }

        if mode == ApprovalMode::Prompt && self.session_capabilities().approvals == Capability::No {
            return Some("no approvals channel".to_string());
        }

        None
    }

    /// The same rule for `sandbox_mode`. No X1 clause: a sandbox is argv, not a channel.
    pub fn sandbox_mode_refusal(&self, mode: SandboxMode) -> Option<String> {
        if mode == SandboxMode::Default {
            return None;
        }

        self.normalized_refusal("sandbox_mode", mode.as_str())
    }

    fn normalized_refusal(&self, field: &str, value: &str) -> Option<String> {
        let declared = self.declared_session_options()?;

        if !declared.iter().any(|option| option == field) {
            return Some(format!("its transport takes no {field}"));
        }

        let allowed = self
            .spec
            .get("normalized_values")
            .and_then(|values| values.get(field))
            .and_then(Value::as_array)?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        if allowed.is_empty() || allowed.contains(&value) {
            return None;
        }

        Some(format!("takes only {}", allowed.join(", ")))
    }

    /// The option names the transport a session will select validates against, mirroring
    /// `Ouroboros.Provider.normalized_options/2`. `None` when the spec does not resolve —
    /// an unregistered provider or a transport no adapter declares is the harness's to
    /// name, and greying a row on a guess would be worse than greying none.
    fn declared_session_options(&self) -> Option<Vec<String>> {
        let adapter_options = || {
            Some(
                self.spec
                    .get("normalized_options")?
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            )
        };

        match self.selected_transport() {
            Some(transport) => match transport.get("session_options") {
                // `:adapter` — the transport inherits the adapter's own list.
                Some(Value::String(marker)) if marker == "adapter" => adapter_options(),
                Some(Value::Array(options)) => Some(
                    options
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect(),
                ),
                _unreadable => None,
            },
            // The manager synthesizes a managed transport for an adapter that declares
            // none, and that synthetic transport inherits the adapter's list.
            None if self.selected_transport_name().as_deref() == Some("managed") => {
                adapter_options()
            }
            None => None,
        }
    }

    fn selected_transport_name(&self) -> Option<String> {
        self.spec
            .get("default_session_transport")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                self.spec
                    .get("session_transports")?
                    .as_array()?
                    .first()?
                    .get("name")?
                    .as_str()
                    .map(str::to_string)
            })
    }

    fn selected_transport(&self) -> Option<&Value> {
        let selected = self.selected_transport_name()?;

        self.spec
            .get("session_transports")?
            .as_array()?
            .iter()
            .find(|transport| transport.get("name").and_then(Value::as_str) == Some(&selected))
    }
}

/// Non-secret account metadata exposed by the runtime's direct OAuth boundary.
///
/// Tokens stay in the runtime's private credential file. This shape is only enough for
/// the shell to report ChatGPT subscription readiness and managed-login progress.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountState {
    #[serde(default)]
    pub account: Option<AccountIdentity>,
    /// Whether the selected ChatGPT-subscription model still needs OAuth. `Option`
    /// distinguishes an absent claim from an explicit ready/not-ready answer.
    #[serde(default)]
    pub requires_openai_auth: Option<bool>,
    #[serde(default)]
    pub login: AccountLoginState,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountIdentity {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub plan_type: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLoginState {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub login_id: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl AccountState {
    pub fn decode(value: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }

    /// Whether a managed ChatGPT subscription is connected. What the account panel reports,
    /// and what the sign-in flow is trying to achieve.
    pub fn connected(&self) -> bool {
        self.account
            .as_ref()
            .map(|account| account.kind == "chatgpt")
            .unwrap_or(false)
    }

    /// Whether an OAuth-backed `openai_codex:` model can run now.
    ///
    /// Official `openai:` API-key models do not consult this account surface; the home
    /// readiness gate checks the configured model prefix before calling this.
    pub fn usable(&self) -> bool {
        self.connected() || self.requires_openai_auth == Some(false)
    }

    pub fn plan_label(&self) -> Option<String> {
        self.account.as_ref().and_then(|account| {
            account
                .plan_type
                .as_deref()
                .filter(|plan| !plan.is_empty())
                .map(|plan| {
                    let mut chars = plan.chars();
                    match chars.next() {
                        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                        None => String::new(),
                    }
                })
        })
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

/// A gateway refusal, rendered for a person.
///
/// This is the one place a refusal becomes text, and every surface that shows one goes
/// through it: the `n` dialog, the quick-start screen, the notice line, and `ouro new`'s
/// stderr. What it produces is one or two lines — the sentence to read, and, when the
/// payload carried keys that sentence did not use, those keys underneath it.
///
/// ## Why the `data` needs this at all
///
/// Most `-32006` messages describe the *shape* of the failure — "the runtime refused the
/// call" — and leave the actionable half Wire-encoded in `data`. A `Jido.Harness.Error`
/// raised inside `interactive.start` arrives as `["session_start_failed", {…}]`, and
/// rendering that as JSON put a line like
///
/// ```text
/// ["session_start_failed",{"__exception__":true,"category":"validation","cause":null,
///  "details":{"field":"sandbox_mode"},"message":"provider does not support normalized
///  session option","provider":"amp","run_id":null}]
/// ```
///
/// in front of an operator whose actual problem was one short sentence.
pub fn refusal(rpc: &RpcError) -> String {
    let Some(data) = rpc.data.as_ref().filter(|data| !data.is_null()) else {
        return rpc.to_string();
    };

    // An unrecognised payload keeps the compact JSON it always had. Guessing at a shape
    // this build has never seen is how a prettifier starts asserting things the runtime
    // did not say.
    let rendered = humanise_unknown_outcome(data)
        .or_else(|| humanise(data))
        .unwrap_or_else(|| compact(data));

    format!("{rpc} — {rendered}")
}

/// `Wire` marks every Elixir exception it encodes. It is a fact about the *encoding* —
/// true on all of them — rather than about this failure, so it is the one key
/// [`humanise`] drops without showing it anywhere. Everything else survives.
const EXCEPTION_MARKER: &str = "__exception__";

/// Past this many fields, `details` stops being a phrase and goes back to being JSON.
const MAX_DETAIL_FIELDS: usize = 6;

/// An indeterminate mutation is a state to reconcile, not a refusal to retry under a new
/// id. The gateway carries that distinction as an object so clients can branch on it;
/// this renderer says the same thing to the person and keeps every diagnostic field it
/// did not use on the following line.
fn humanise_unknown_outcome(data: &Value) -> Option<String> {
    let payload = data.as_object()?;

    if payload.get("outcome").and_then(Value::as_str) != Some("unknown") {
        return None;
    }

    let mut used = vec!["outcome"];
    let mut line = String::from("outcome unknown");

    if let Some(turn_id) = payload.get("turn_id") {
        used.push("turn_id");
        line.push_str(" (turn ");
        line.push_str(&compact(turn_id));
        line.push(')');
    }

    let rest: Vec<String> = sorted_fields(payload)
        .into_iter()
        .filter(|(key, _value)| !used.contains(&key.as_str()))
        .map(|(key, value)| format!("{key}={}", compact(value)))
        .collect();

    if rest.is_empty() {
        Some(line)
    } else {
        Some(format!("{line}\nalso: {}", rest.join(", ")))
    }
}

/// One line for a `{tag, exception}` payload, plus whatever that line did not use.
///
/// The recognised shape is exactly `[tag, map]` — the Wire encoding of an `{:error,
/// {:some_tag, %SomeException{}}}` tuple, which is what both planes raise. Nothing else is
/// touched.
///
/// The line reads `provider: message (details)`, and each of the three is skipped when the
/// payload does not carry it. The **tag is only shown when there is no message**: a human
/// sentence written by the runtime says everything `session_start_failed` says and more,
/// and the surrounding text already establishes that a start was refused.
///
/// Every remaining key is appended on a second line rather than dropped. A payload this
/// build renders *less* completely than JSON would be worse than the JSON.
fn humanise(data: &Value) -> Option<String> {
    let items = data.as_array()?;

    let [tag, payload] = items.as_slice() else {
        return None;
    };

    let tag = tag.as_str()?;
    let payload = payload.as_object()?;

    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };

    let message = text("message");
    let provider = text("provider");

    // A key is "used" only where it really appeared in the line. A `provider: null` is not
    // a provider this rendered, so it belongs in the remainder like anything else.
    let mut used = vec![EXCEPTION_MARKER];
    let mut line = String::new();

    if let Some(provider) = provider {
        used.push("provider");
        line.push_str(provider);
        line.push_str(": ");
    }

    match message {
        Some(message) => {
            used.push("message");
            line.push_str(message);
        }
        None => line.push_str(tag),
    }

    if let Some(rendered) = payload.get("details").and_then(flatten) {
        used.push("details");
        line.push_str(" (");
        line.push_str(&rendered);
        line.push(')');
    }

    let rest: Vec<String> = sorted_fields(payload)
        .into_iter()
        .filter(|(key, _value)| !used.contains(&key.as_str()))
        .map(|(key, value)| format!("{key}={}", compact(value)))
        .collect();

    if rest.is_empty() {
        return Some(line);
    }

    Some(format!("{line}\nalso: {}", rest.join(", ")))
}

/// A small map of scalars as `key: value, key: value`, or `None` for anything else.
///
/// Deliberately shallow and deliberately small. A nested or sprawling `details` goes back
/// to the compact JSON through the remainder, because a flattener that invented a path
/// syntax for it would be this client making up a notation the runtime never used — and
/// because the point of the line is that it fits on one.
///
/// Nothing here knows what any particular key *means*. `{"field": "sandbox_mode"}` and a
/// `details` naming an override to try both come out as themselves, which is what lets a
/// refusal shape nobody has written yet arrive readable.
fn flatten(details: &Value) -> Option<String> {
    let fields = details.as_object()?;

    if fields.is_empty() || fields.len() > MAX_DETAIL_FIELDS {
        return None;
    }

    let mut parts = Vec::with_capacity(fields.len());

    for (key, value) in sorted_fields(fields) {
        match value {
            Value::String(text) => parts.push(format!("{key}: {text}")),
            Value::Number(number) => parts.push(format!("{key}: {number}")),
            Value::Bool(flag) => parts.push(format!("{key}: {flag}")),
            // A null or a nested value is not a phrase. The whole map goes to the
            // remainder rather than half of it here.
            _ => return None,
        }
    }

    Some(parts.join(", "))
}

/// Whether an error admits that the runtime may still be working on the request.
///
/// Current gateways carry the explicit object discriminator. The tuple clauses retain
/// the same safety with a runtime from before that discriminator was added: those exact
/// interactive errors already meant dispatch may have crossed the boundary, even though
/// they were incorrectly labelled as a refusal.
pub fn outcome_unknown(data: Option<&Value>) -> bool {
    let Some(data) = data else {
        return false;
    };

    if data.get("outcome").and_then(Value::as_str) == Some("unknown") {
        return true;
    }

    let Some(items) = data.as_array() else {
        return false;
    };

    match items.as_slice() {
        [Value::String(tag), Value::String(marker), Value::String(turn_id)]
            if tag == "turn_dispatch_checkpoint_failed"
                && marker == "dispatch_may_have_started"
                && !turn_id.trim().is_empty() =>
        {
            true
        }
        [Value::String(tag), Value::String(turn_id)]
            if tag == "turn_dispatch_ambiguous" && !turn_id.trim().is_empty() =>
        {
            true
        }
        [Value::String(tag), Value::String(turn_id), Value::String(marker)]
            if tag == "turn_dispatch_ambiguous"
                && marker == "checkpoint_failed"
                && !turn_id.trim().is_empty() =>
        {
            true
        }
        _ => false,
    }
}

/// Whether a failed `*.start` reply may have crossed the durable creation boundary.
///
/// A caller-owned session id makes reconciliation cheap, so this deliberately errs on
/// the side of retaining that id. Only protocol/schema/auth/placement decisions are
/// provably pre-dispatch. Generic upstream failures and newer error codes are not
/// permission to mint a second potentially billable session.
pub fn start_outcome_unknown(error: &ClientError) -> bool {
    match error {
        ClientError::Rpc(rpc) => {
            if rpc.data.as_ref().and_then(|data| data.get("outcome"))
                == Some(&Value::String("not_dispatched".into()))
            {
                return false;
            }

            if rpc.code == ErrorCode::UpstreamTimeout || outcome_unknown(rpc.data.as_ref()) {
                return true;
            }

            !matches!(
                rpc.code,
                ErrorCode::ParseError
                    | ErrorCode::InvalidRequest
                    | ErrorCode::MethodNotFound
                    | ErrorCode::InvalidParams
                    | ErrorCode::Unauthenticated
                    | ErrorCode::ProtocolMismatch
                    | ErrorCode::ScopeDenied
                    | ErrorCode::NotFound
            )
        }
        // A transport can disappear after the gateway accepted the mutation but before
        // its answer reached the client. An undecodable success has the same property.
        _transport => true,
    }
}

/// Whether an immediate interactive message was definitely not dispatched because the
/// session already had an active turn.
///
/// Current gateways name the state and the safe queueing verb in an object. The exact
/// legacy tuple remains recognizable so a newer TUI attached to an older runtime can
/// still restore the draft and offer the queue rather than losing the user's input.
pub fn turn_busy(data: Option<&Value>) -> bool {
    let Some(data) = data else {
        return false;
    };

    if data.get("reason").and_then(Value::as_str) == Some("busy") {
        return true;
    }

    matches!(
        data.as_array().map(Vec::as_slice),
        Some([Value::String(tag), Value::String(reason)])
            if tag == "turn_dispatch_failed" && reason == "busy"
    )
}

/// What a successful `interactive.send_message` / `follow_up` RPC proves.
///
/// A same-id call is also a read of the durable turn. Most statuses prove that Harness
/// accepted it, but `dispatching` / `ambiguous` still require reconciliation and a
/// terminal failure must not be presented as a fresh acceptance merely because the RPC
/// envelope itself succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnReply {
    Accepted,
    OutcomeUnknown,
    Rejected,
}

pub fn turn_reply(value: &Value) -> TurnReply {
    match value.get("status").and_then(Value::as_str) {
        Some("dispatching" | "ambiguous") => TurnReply::OutcomeUnknown,
        Some("failed" | "interrupted" | "cancelled") => TurnReply::Rejected,
        // Missing and newer statuses retain the protocol's tolerant behavior. A runtime
        // that wants a client to branch must use one of the durable statuses above.
        _ => TurnReply::Accepted,
    }
}

/// A readable diagnostic for a durable turn returned inside a successful RPC envelope.
pub fn turn_reply_diagnostic(value: &Value) -> String {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty());

    let mut text = match id {
        Some(id) => format!("turn {id} is {status}"),
        None => format!("turn status is {status}"),
    };

    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        text.push_str(" — error=");
        text.push_str(&compact(error));
    }

    text
}

/// Whether a durable failed-turn read names the immediate-message `:busy` refusal.
pub fn turn_reply_busy(value: &Value) -> bool {
    value.get("error").is_some_and(|error| {
        error.as_str() == Some("busy")
            || error.get("reason").and_then(Value::as_str) == Some("busy")
            || turn_busy(Some(error))
    })
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

/// The four values `interactive.start` and `coding.start` accept for `approval_mode`.
///
/// `Jido.Harness.RunRequest`'s enum, transcribed from `Gateway.Methods` `@approval_modes`
/// rather than inferred. The gateway matches a client's string against those literal terms
/// and answers `-32602` **naming the parameter** for anything else — an option that was
/// silently dropped would run the session under a policy nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    Default,
    Prompt,
    AutoEdit,
    AutoApprove,
}

impl ApprovalMode {
    pub const ALL: [ApprovalMode; 4] = [
        ApprovalMode::Default,
        ApprovalMode::Prompt,
        ApprovalMode::AutoEdit,
        ApprovalMode::AutoApprove,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Prompt => "prompt",
            Self::AutoEdit => "auto_edit",
            Self::AutoApprove => "auto_approve",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == name)
    }

    /// What choosing it means, in the terms an operator is deciding in.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Default => "whatever the provider does on its own",
            Self::Prompt => "ask before every action",
            Self::AutoEdit => "edit files without asking; ask for anything else",
            Self::AutoApprove => "never ask",
        }
    }
}

/// The four values `interactive.start` and `coding.start` accept for `sandbox_mode`.
///
/// Transcribed from `Gateway.Methods` `@sandbox_modes`. Sending anything else is `-32602`
/// naming the parameter. The TUI default is to omit this field so the plane can apply
/// workspace write where the provider allows it, and omit it where the provider cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    Default,
    ReadOnly,
    WorkspaceWrite,
    Unrestricted,
}

impl SandboxMode {
    pub const ALL: [SandboxMode; 4] = [
        SandboxMode::Default,
        SandboxMode::ReadOnly,
        SandboxMode::WorkspaceWrite,
        SandboxMode::Unrestricted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ReadOnly => "read_only",
            Self::WorkspaceWrite => "workspace_write",
            Self::Unrestricted => "unrestricted",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == name)
    }

    /// Short caption for the composer chrome, in the terms an operator is deciding in.
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "provider default",
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "can edit",
            Self::Unrestricted => "unrestricted",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Default => "whatever the provider does on its own",
            Self::ReadOnly => "cannot create or edit files",
            Self::WorkspaceWrite => "can edit files in the workspace",
            Self::Unrestricted => "no filesystem sandbox",
        }
    }

    pub fn writable(self) -> bool {
        matches!(self, Self::WorkspaceWrite | Self::Unrestricted)
    }
}

/// Why a start was refused before it was sent.
///
/// Local refusals are typed rather than free text because two of them are this client
/// being *stricter* than the gateway, and a reader has to be able to tell which side said
/// no. The gateway's own refusals arrive as `-32602` and are shown verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// A client-owned id is the retry boundary for a start whose reply is lost. Starting
    /// without one makes a timeout indistinguishable from permission to bill a second
    /// provider session.
    NoId,
    /// The gateway would accept a start with no provider and let the node's default
    /// decide. This client will not: a terminal that silently picked a provider would be
    /// choosing which vendor runs the operator's code.
    NoProvider,
    /// `coding.start` takes `objective` as a required nonempty string.
    NoObjective,
    /// `objective` is not in the interactive allowlist, so sending it would be `-32602`.
    ObjectiveOnInteractive,
    /// A remote runtime must never inherit the packaged release's working directory.
    NoRemoteWorkspace,
    /// Relative paths are relative to the destination runtime, not this terminal.
    RemoteWorkspaceNotAbsolute(String),
    UnknownApprovalMode(String),
    UnknownSandboxMode(String),
}

impl StartError {
    pub fn message(&self) -> String {
        match self {
            Self::NoId => {
                "the client did not assign this start a retry-safe session id".to_string()
            }
            Self::NoProvider => "choose a provider: this client will not let the node pick \
                                 which vendor runs your code"
                .to_string(),
            Self::NoObjective => {
                "a coding task needs an objective; it runs that one thing to completion".to_string()
            }
            Self::ObjectiveOnInteractive => {
                "an interactive session takes no objective — it takes messages".to_string()
            }
            Self::NoRemoteWorkspace => "choose an absolute workspace path on the destination \
                                        machine; remote sessions never guess from this terminal"
                .to_string(),
            Self::RemoteWorkspaceNotAbsolute(path) => format!(
                "remote workspace {path:?} must be an absolute path on the destination machine"
            ),
            Self::UnknownApprovalMode(name) => format!(
                "approval_mode must be one of {}; the gateway refuses {name:?} by name",
                ApprovalMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::UnknownSandboxMode(name) => format!(
                "sandbox_mode must be one of {}; the gateway refuses {name:?} by name",
                SandboxMode::ALL
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// One request to start a session, and the only place its parameters are built.
///
/// The gateway's allowlist for both start verbs is `id`, `provider`, `workspace`, `model`,
/// `system_prompt`, `max_turns`, `event_limit`, `approval_mode`, `sandbox_mode`,
/// `reasoning_effort`, `runtime_exposure`, `machine` (`Gateway.Methods` `@start_options`), and an
/// option outside it is `-32602` naming it rather than being ignored. This type emits a
/// strict subset of that — the ones a terminal can honestly ask a person for — and
/// **omits** every optional field it has no answer for rather than sending a placeholder: the
/// gateway requires a *nonempty* string for `workspace`, so an empty box means "no
/// workspace", not `""`. Runtime exposure is default-on upstream, so this dialog does
/// not send `runtime_exposure`.
///
/// `id` is always client-owned. It is retained across an indeterminate reply so retrying
/// reconciles the same logical start instead of creating and billing another session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRequest {
    pub id: String,
    pub plane: Plane,
    pub provider: String,
    pub model: Option<String>,
    /// A friendly fleet machine name. Blank means this machine, which is the safe and
    /// backwards-compatible default.
    pub machine: String,
    pub workspace: String,
    pub approval_mode: Option<ApprovalMode>,
    pub sandbox_mode: Option<SandboxMode>,
    /// Required on the coding plane, refused on the interactive one.
    pub objective: String,
    /// D7. Run in a `git worktree` under the runtime's data directory instead of the
    /// workspace itself, so two sessions on one repository do not fight over its lease.
    ///
    /// Sent only when true. The gateway's `worktree` option is a strict boolean — `"true"`
    /// or `1` is `-32602` — and an unasked-for `false` on every start would be this client
    /// stating a default the plane already has.
    pub worktree: bool,
    /// B2. Start the session planning: read-only, and holding its terminal event at the
    /// end of a planning turn to ask whether to build the plan.
    ///
    /// Sent only when true, for the same reason `worktree` is. It is the one way to reach
    /// plan mode on a transport that carries the posture on every launch — Claude refuses
    /// a mid-life change as `at_start_only` — so `--plan` is not merely a shortcut for
    /// `/plan on` after the fact.
    pub plan: bool,
}

impl StartRequest {
    pub fn new(plane: Plane) -> Self {
        Self {
            id: new_session_id(),
            plane,
            provider: String::new(),
            model: None,
            machine: String::new(),
            workspace: String::new(),
            approval_mode: None,
            sandbox_mode: None,
            objective: String::new(),
            worktree: false,
            plan: false,
        }
    }

    pub fn method(&self) -> String {
        self.plane.method("start")
    }

    /// The exact `params` object, or the reason it was not built.
    pub fn params(&self) -> Result<Value, StartError> {
        let id = self.id.trim();

        if id.is_empty() {
            return Err(StartError::NoId);
        }

        let provider = self.provider.trim();

        if provider.is_empty() {
            return Err(StartError::NoProvider);
        }

        let mut params = serde_json::Map::new();
        params.insert("id".into(), Value::String(id.to_string()));
        params.insert("provider".into(), Value::String(provider.to_string()));

        if let Some(model) = self
            .model
            .as_deref()
            .map(str::trim)
            .filter(|model| !model.is_empty())
        {
            params.insert("model".into(), Value::String(model.to_string()));
        }

        let machine = self.machine.trim();

        if !machine.is_empty() {
            params.insert("machine".into(), Value::String(machine.to_string()));
        }

        let objective = self.objective.trim();

        match self.plane {
            Plane::Coding if objective.is_empty() => return Err(StartError::NoObjective),
            Plane::Coding => {
                params.insert("objective".into(), Value::String(objective.to_string()));
            }
            Plane::Interactive if !objective.is_empty() => {
                return Err(StartError::ObjectiveOnInteractive)
            }
            Plane::Interactive => {}
        }

        let workspace = self.workspace.trim();

        if !machine.is_empty() && workspace.is_empty() {
            return Err(StartError::NoRemoteWorkspace);
        }

        if !machine.is_empty() && !Path::new(workspace).is_absolute() {
            return Err(StartError::RemoteWorkspaceNotAbsolute(
                workspace.to_string(),
            ));
        }

        if !workspace.is_empty() {
            params.insert("workspace".into(), Value::String(workspace.to_string()));
        }

        if let Some(mode) = self.approval_mode {
            params.insert(
                "approval_mode".into(),
                Value::String(mode.as_str().to_string()),
            );
        }

        if let Some(mode) = self.sandbox_mode {
            params.insert(
                "sandbox_mode".into(),
                Value::String(mode.as_str().to_string()),
            );
        }

        if self.worktree {
            params.insert("worktree".into(), Value::Bool(true));
        }

        if self.plan {
            params.insert("plan".into(), Value::Bool(true));
        }

        Ok(Value::Object(params))
    }
}

/// A durable identity minted before a start mutation crosses the socket.
///
/// OS randomness is the normal path. The process/time/sequence fallback keeps the UI
/// usable if the platform entropy source is temporarily unavailable without reusing an
/// id inside this process.
pub fn new_session_id() -> String {
    let mut bytes = [0_u8; 16];

    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_ok() {
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        return format!("ouro-session-{encoded}");
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = SESSION_ID_FALLBACK_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    format!(
        "ouro-session-{}-{timestamp:x}-{sequence:x}",
        std::process::id()
    )
}

/// What a start answers: `Ouroboros.Interactive.Ref` / `Ouroboros.Coding.TaskRef`,
/// Wire-encoded — `{id, node}` plus the struct tag — or the same stable identity with a
/// typed post-checkpoint readiness failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedRef {
    pub id: String,
    pub node: Option<String>,
    /// Present only when the runtime durably created this exact request but could not
    /// make its provider/workspace coordinator ready. The reference remains addressable.
    pub start_failure: Option<String>,
}

impl StartedRef {
    pub fn decode(value: &Value) -> Option<Self> {
        // A bare string is accepted too: the id is the only field this client needs, and
        // a future gateway that answered one should not break session creation.
        if let Some(id) = value.as_str() {
            return Some(Self {
                id: id.to_string(),
                node: None,
                start_failure: None,
            });
        }

        let id = value.get("id")?.as_str()?;

        if id.is_empty() {
            return None;
        }

        let created_but_not_ready = value.get("outcome").and_then(Value::as_str) == Some("created")
            && value.get("ready").and_then(Value::as_bool) == Some(false);
        let start_failure = created_but_not_ready.then(|| {
            value
                .get("error")
                .map(|error| humanise(error).unwrap_or_else(|| compact(error)))
                .unwrap_or_else(|| "the durable session did not become ready".to_string())
        });

        Some(Self {
            id: id.to_string(),
            node: value
                .get("node")
                .and_then(Value::as_str)
                .map(str::to_string),
            start_failure,
        })
    }
}

/// The exact `params` for one approval answer without a reason.
///
/// Built here rather than at the call site so the allowlist the gateway enforces —
/// `decision` in `approve|deny`, `scope` in `once|session`, plus the one `provider_options`
/// shape [`respond_approval_params_with_plan`] adds — is stated once, in a type, instead of
/// being spelled into a `json!` literal that a later edit could widen.
pub fn respond_approval_params(
    session_id: &str,
    request_id: &str,
    decision: ApprovalDecision,
    scope: ApprovalScope,
) -> Value {
    respond_approval_params_with_reason(session_id, request_id, decision, scope, None)
}

/// The auto-approve mode's one answer, stated once: `approve`, scope `once`, and an
/// `actor` that says a robot pressed the button.
///
/// Scope stays `once` because the mode itself is the session-wide fact — every later
/// request is answered as it arrives — while a `session` scope would additionally write a
/// durable engine rule for this subject that outlives the toggle. `actor: automation`
/// keeps the runtime's approval ledger honest the same way `ouro run` marks its headless
/// answers, and is why this is not a call site of [`respond_approval_params`] plus a
/// mutation: the extra key is part of the answer's meaning, not a decoration.
pub fn respond_approval_params_as_automation(session_id: &str, request_id: &str) -> Value {
    let mut params = respond_approval_params(
        session_id,
        request_id,
        ApprovalDecision::Approve,
        ApprovalScope::Once,
    );
    params["response"]["actor"] = Value::String("automation".to_string());
    params
}

/// The same answer with the operator's optional `reason`.
///
/// The gateway's closed envelope accepts `{decision, scope?, reason?}`; an absent reason
/// omits the key entirely rather than sending a null, so a gateway that never heard of
/// reasons sees byte-identical params to [`respond_approval_params`].
pub fn respond_approval_params_with_reason(
    session_id: &str,
    request_id: &str,
    decision: ApprovalDecision,
    scope: ApprovalScope,
    reason: Option<&str>,
) -> Value {
    let mut response = serde_json::json!({
        "decision": decision.as_str(),
        "scope": scope.as_str(),
    });
    if let Some(reason) = reason {
        response["reason"] = Value::String(reason.to_string());
    }
    serde_json::json!({
        "id": session_id,
        "request_id": request_id,
        "response": response,
    })
}

/// B2. The three answers a `plan_exit` approval admits, in the order the modal lists them.
///
/// These are `optionId`s, not labels: `Provider.Native.Session`'s `@plan_exit_options`
/// spells them `auto_edit` / `prompt` / `keep_planning`, and the gateway matches the
/// `provider_options["choice"]` a client sends against exactly those three literals
/// (`Gateway.Methods` `@plan_exit_choices`). The *names* a person reads come from the
/// payload's own `options` rows and are never derived from this enum — a modal that
/// invented its own wording for a vendor's option would be describing a button that does
/// something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanChoice {
    /// Leave plan mode into `auto_edit`: edits inside the workspace apply without asking.
    AutoEdit,
    /// Leave plan mode into `prompt`: every write and command is put to the operator.
    Prompt,
    /// Stay planning. Nothing is reconfigured, which is what makes the label true.
    KeepPlanning,
}

impl PlanChoice {
    /// The `optionId`s this build knows, in the payload's own order.
    pub const ALL: [Self; 3] = [Self::AutoEdit, Self::Prompt, Self::KeepPlanning];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AutoEdit => "auto_edit",
            Self::Prompt => "prompt",
            Self::KeepPlanning => "keep_planning",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "auto_edit" => Some(Self::AutoEdit),
            "prompt" => Some(Self::Prompt),
            "keep_planning" => Some(Self::KeepPlanning),
            _unknown => None,
        }
    }

    /// The four-way answer this choice degrades to on a gateway that refuses
    /// `provider_options`.
    ///
    /// Not a guess: `Provider.Native.Session.plan_exit_choice/1` falls back to exactly this
    /// mapping when no explicit `choice` reached it — a deny is `keep_planning`, an
    /// approve-for-the-session is `auto_edit`, and an approve-once is `prompt`. So the
    /// fallback answer settles the session the same way the explicit one does; what is lost
    /// is the follow-up prompt, which is why the client says so once rather than silently
    /// dropping it.
    pub fn decision(self) -> (ApprovalDecision, ApprovalScope) {
        match self {
            Self::AutoEdit => (ApprovalDecision::Approve, ApprovalScope::Session),
            Self::Prompt => (ApprovalDecision::Approve, ApprovalScope::Once),
            Self::KeepPlanning => (ApprovalDecision::Deny, ApprovalScope::Once),
        }
    }
}

/// At most this many bytes of follow-up prompt, because that is the gateway's own ceiling
/// (`Gateway.Methods` `@max_follow_up_bytes`). Clipped here so an over-long draft is
/// bounded by the composer that produced it rather than refused by a round trip.
pub const MAX_PLAN_FOLLOW_UP_BYTES: usize = 32 * 1024;

/// B2. One plan-exit answer: the explicit `choice`, and the prompt to run once the session
/// has left plan mode.
///
/// `provider_options` is admitted by the gateway in exactly one shape — `{choice?,
/// follow_up?}` — and anything else under that key is refused outright, so this builds that
/// shape and nothing else. `decision`/`scope` are still sent and still mean what they mean:
/// a runtime that reads the explicit choice and one that falls back to the four-way answer
/// settle the same way.
pub fn respond_approval_params_with_plan(
    session_id: &str,
    request_id: &str,
    choice: PlanChoice,
    follow_up: Option<&str>,
) -> Value {
    let (decision, scope) = choice.decision();
    let mut params = respond_approval_params(session_id, request_id, decision, scope);

    let mut options = serde_json::Map::new();
    options.insert("choice".into(), Value::String(choice.as_str().to_string()));

    // A blank follow-up is *absent*, not an empty string: the runtime trims and drops a
    // blank one anyway, and omitting the key keeps these params byte-identical to an answer
    // from a client that never offered a composer.
    if let Some(text) = follow_up.map(str::trim).filter(|text| !text.is_empty()) {
        options.insert(
            "follow_up".into(),
            Value::String(clip_utf8(text, MAX_PLAN_FOLLOW_UP_BYTES)),
        );
    }

    params["response"]["provider_options"] = Value::Object(options);
    params
}

/// One follow-up draft, bounded to what the gateway will accept.
///
/// Applied where the operator's text is *stored* as well as where it is sent, so the
/// modal shows the bytes that will actually cross the wire rather than a draft it will
/// silently shorten later.
pub fn clip_plan_follow_up(text: &str) -> String {
    clip_utf8(text.trim(), MAX_PLAN_FOLLOW_UP_BYTES)
}

/// Truncates on a character boundary, so a clipped follow-up is still UTF-8.
fn clip_utf8(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }

    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    text[..end].to_string()
}

/// One `@`-mention, carried to the gateway as a path rather than as substituted text.
///
/// **The path is never resolved here.** `interactive.send_message`/`follow_up`
/// canonicalise every attachment against the *session's* workspace and refuse an outsider
/// (`interactive/task.ex`, `authorize_turn_attachments`) — and that workspace may be on
/// another machine entirely, where this client cannot stat anything. What is sent is what
/// the operator picked; what comes back when it is outside the workspace is a refusal this
/// client renders on the composer that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Attachment {
    pub path: String,
    pub kind: AttachmentKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachmentKind {
    /// Completed from the workspace index with `@`.
    Path,
    /// Written by this client from the clipboard, under the session workspace.
    Image,
}

impl Attachment {
    pub fn path(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: AttachmentKind::Path,
        }
    }

    pub fn image(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: AttachmentKind::Image,
        }
    }

    /// What the chip says: the tail of the path, because a chip row has no width for a
    /// repository-root prefix that is the same on every chip.
    pub fn label(&self) -> &str {
        self.path
            .rsplit_once('/')
            .map(|(_head, tail)| tail)
            .unwrap_or(&self.path)
    }
}

/// Per-turn reasoning effort, exactly the three values `@reasoning_efforts` declares in
/// `gateway/methods.ex`. A fourth would be a `-32602` naming the parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effort {
    Low,
    Medium,
    High,
}

impl Effort {
    pub const ALL: [Effort; 3] = [Self::Low, Self::Medium, Self::High];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|effort| effort.as_str() == name)
    }
}

/// What goes in `params.input` of a turn.
///
/// The gateway takes **either** a nonempty string **or** the object
/// `{prompt, attachments[≤32], reasoning_effort}` (`structured_turn_input`,
/// `gateway/methods.ex`). Both are sent, and which one is a fact about the turn rather
/// than a client preference: a plain prompt stays a plain string so the bytes on the wire
/// for the overwhelmingly common turn are exactly what they were before B4, and the object
/// appears only where there is something in it a string could not carry.
///
/// This is also the unit a reconciliation replays. A same-id retry that dropped the
/// attachments would change the turn's fingerprint and come back `:turn_id_conflict`, so
/// the whole envelope travels with the tag rather than the prompt alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TurnInput {
    pub prompt: String,
    pub attachments: Vec<Attachment>,
    pub reasoning_effort: Option<Effort>,
}

impl TurnInput {
    /// The gateway's own ceiling, restated so the composer can refuse the 33rd chip with a
    /// sentence instead of letting the runtime refuse the whole turn.
    pub const ATTACHMENT_LIMIT: usize = 32;

    pub fn plain(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            attachments: Vec::new(),
            reasoning_effort: None,
        }
    }

    /// The text half — what goes back into the editor when a turn is restored.
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// Whether this turn needs the object form at all.
    pub fn structured(&self) -> bool {
        !self.attachments.is_empty() || self.reasoning_effort.is_some()
    }

    /// `params.input`, in whichever of the two shapes this turn actually needs.
    pub fn to_value(&self) -> Value {
        if !self.structured() {
            return Value::String(self.prompt.clone());
        }

        let mut input = serde_json::Map::new();
        input.insert("prompt".into(), Value::String(self.prompt.clone()));

        if !self.attachments.is_empty() {
            input.insert(
                "attachments".into(),
                Value::Array(
                    self.attachments
                        .iter()
                        .map(|attachment| Value::String(attachment.path.clone()))
                        .collect(),
                ),
            );
        }

        if let Some(effort) = self.reasoning_effort {
            input.insert(
                "reasoning_effort".into(),
                Value::String(effort.as_str().to_string()),
            );
        }

        Value::Object(input)
    }
}

/// Whether a refusal is the runtime rejecting an *attachment* rather than the turn.
///
/// The runtime answers `{:attachment_outside_workspace, path}`,
/// `{:invalid_attachment, path, reason}`, and `{:invalid_attachment_workspace, reason}`
/// (`interactive/task.ex`); all three reach the wire as text naming the attachment. Matched
/// on that rather than on a code, because the code is the generic refusal code every other
/// turn failure also carries.
pub fn attachment_refusal(diagnostic: &str) -> bool {
    diagnostic.to_ascii_lowercase().contains("attachment")
}

/// The exact `params` for the durable half of a "don't ask again" answer.
///
/// `scope` is `"workspace"` and never `"user"`: the modal names one workspace before the
/// answer is chosen, and a client that widened that to the whole account because it had
/// nowhere else to put the rule would be writing authority nobody read. `decision` is
/// `"allow"` because this is only ever reached from an approve answer — the deny side of
/// "don't ask again" is `permissions.add` with `deny`, which belongs to a rules editor and
/// not to a modal about one command.
///
/// `pattern` is the runtime's own `suggested_rule` from the `approval_requested` payload.
/// This client does not have the rule language and does not invent one:
/// `Control.Permissions.Pattern` validates it, and an unvalidatable pattern comes back as
/// `-32602` naming itself rather than as a rule that matches nothing.
pub fn permission_add_params(pattern: &str, workspace: &str) -> Value {
    serde_json::json!({
        "scope": "workspace",
        "pattern": pattern,
        "decision": "allow",
        "workspace": workspace,
    })
}

/// D4. What `mcp.list` answers, for one node.
///
/// Decoded tolerantly out of the raw tree for the reason [`SessionInfo`] is: this is a
/// status projection whose keys the runtime is free to extend, and a strict struct would be
/// the one place this client refuses to show an operator their MCP servers because the
/// runtime described them more fully than it used to.
///
/// **`refusals` is the load-bearing half.** An entry the loader read and rejected is the
/// only thing that distinguishes "my `mcp.json` was ignored" from "my `mcp.json` was read
/// and found wanting", so it is a first-class list here and a first-class section in every
/// rendering, never folded into an error count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpList {
    /// Whether this node runs MCP for the native agent at all. `false` is a posture, not a
    /// failure: the servers list is then empty because nothing was started, not because
    /// nothing was configured.
    pub enabled: bool,
    /// Whether the pool supervises the servers it started.
    pub supervised: bool,
    pub node: Option<String>,
    /// The MCP protocol version this build speaks.
    pub protocol_version: Option<String>,
    /// The transports this build implements — `["stdio"]` today, which is exactly why a
    /// `url` entry is refused rather than attempted.
    pub transports: Vec<String>,
    pub servers: Vec<McpServer>,
    pub refusals: Vec<McpRefusal>,
}

/// One MCP server, as the node holds it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpServer {
    pub name: String,
    /// `configured` (declared, never started), `starting`, `ready`, or `broken`. Kept as
    /// the runtime's own string: an unknown fifth state renders as itself rather than being
    /// folded into one of the four this build happens to know.
    pub state: Option<String>,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    /// `node`, `user`, or `workspace` — which of the three files declared it.
    pub scope: Option<String>,
    /// The file it was read from, where there was one. Absent for node-scope servers,
    /// which come from the runtime's own configuration and not from a file.
    pub source: Option<String>,
    pub workspace: Option<String>,
    pub transport: Option<String>,
    /// How many tools it advertises, and their `mcp__server__tool` names.
    pub tools: u64,
    pub tool_names: Vec<String>,
    /// **How many environment variables it carries — never their names, never their
    /// values.** The runtime does not put them on the wire and this client has nowhere to
    /// get them from; the count is the whole fact.
    pub env_count: u64,
    pub restarts: u64,
    pub claims: u64,
    pub uptime_ms: Option<u64>,
    pub idle_ms: Option<u64>,
    /// Why it is broken, in the runtime's words. Present only in the `broken` state.
    pub broken_reason: Option<String>,
    pub broken_until_ms: Option<u64>,
}

impl McpServer {
    pub fn broken(&self) -> bool {
        self.state.as_deref() == Some("broken")
    }
}

/// One entry the loader read and refused, with the typed reason it refused it for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpRefusal {
    /// The name the entry gave itself, where it gave a usable one.
    pub name: Option<String>,
    /// `unsupported_transport`, `invalid_name`, `missing_command`, `untrusted_workspace`,
    /// … — kept verbatim, because an unknown reason is still a reason worth showing.
    pub reason: Option<String>,
    /// The runtime's own sentence about this refusal.
    pub detail: Option<String>,
    pub scope: Option<String>,
    pub workspace: Option<String>,
}

/// At most this many rows out of one answer, matching [`native::MAX_ROWS`].
const MAX_MCP_ROWS: usize = native::MAX_ROWS;

impl McpList {
    pub fn decode(value: &Value) -> Self {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|found| !found.is_empty())
                .map(str::to_string)
        };

        Self {
            enabled: value
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            supervised: value
                .get("supervised")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            node: text("node"),
            protocol_version: text("protocol_version"),
            transports: strings(value.get("transports")),
            servers: value
                .get("servers")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_MCP_ROWS)
                        .filter_map(McpServer::decode)
                        .collect()
                })
                .unwrap_or_default(),
            refusals: value
                .get("refusals")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_MCP_ROWS)
                        .map(McpRefusal::decode)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// How many of the listed servers are broken — the one count worth leading with.
    pub fn broken(&self) -> usize {
        self.servers.iter().filter(|server| server.broken()).count()
    }
}

impl McpServer {
    /// `None` for a row with no usable name: a server this client cannot name is a row it
    /// cannot honestly address, and dropping it is better than showing a blank one.
    fn decode(value: &Value) -> Option<Self> {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|found| !found.is_empty())
                .map(str::to_string)
        };
        let number = |key: &str| value.get(key).and_then(Value::as_u64);

        Some(Self {
            name: text("name")?,
            state: text("state"),
            command: text("command"),
            args: strings(value.get("args")),
            cwd: text("cwd"),
            scope: text("scope"),
            source: text("source"),
            workspace: text("workspace"),
            transport: text("transport"),
            tools: number("tools").unwrap_or(0),
            tool_names: strings(value.get("tool_names")),
            env_count: number("env_count").unwrap_or(0),
            restarts: number("restarts").unwrap_or(0),
            claims: number("claims").unwrap_or(0),
            uptime_ms: number("uptime_ms"),
            idle_ms: number("idle_ms"),
            broken_reason: text("broken_reason"),
            broken_until_ms: number("broken_until_ms"),
        })
    }
}

impl McpRefusal {
    fn decode(value: &Value) -> Self {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|found| !found.is_empty())
                .map(str::to_string)
        };

        Self {
            name: text("name"),
            reason: text("reason"),
            detail: text("detail"),
            scope: text("scope"),
            workspace: text("workspace"),
        }
    }
}

/// A bounded list of nonempty strings out of a JSON array, or an empty one.
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(MAX_MCP_ROWS)
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|found| !found.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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
        assert!(hello.serves("interactive.delete"));
        assert!(hello.serves("coding.delete"));
        assert!(hello.serves("interactive.respond_approval"));
        assert!(hello.serves("runtime.shutdown"));
        assert!(hello.serves("capabilities.preview"));
        assert!(hello.serves("capabilities.admit"));
        assert!(hello.serves("capabilities.list"));
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
        assert_eq!(
            status.availability.get("effect_ledger"),
            Some(&Availability::Available)
        );

        assert_eq!(status.mode("upgrade"), Some("ready"));
        assert_eq!(status.mode("release"), Some("ready"));
        assert!(status.control.runs.is_empty());
        assert_eq!(status.cluster_summary(), "strategy=none  distributed=false");
        assert_eq!(status.forge_summary(), "signer=deny live=0 admit=no");
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
                "code_intel_diagnostics_result",
                "coding_event_detail_result",
                "coding_event_notification",
                "error_cursor_pruned",
                "error_invalid_request",
                "error_not_found",
                "error_protocol_mismatch",
                "error_scope_denied",
                "error_unauthenticated",
                "error_upstream_timeout_unknown",
                "hello_result",
                "interactive_event_detail_result",
                "interactive_event_excerpt_notification",
                "interactive_event_notification",
                "ledger_export_result",
                "ledger_list_result",
                "mcp_list_result",
                "runtime_status_result",
                "stream_ended_notification",
                "stream_lagged_notification",
            ]
        );
    }

    /// D4's `mcp.list`: what a client reads to draw a node's MCP servers — the state
    /// discriminator, the prefixed tool names, a refusal's typed reason, and the one fact
    /// about a server's environment that is allowed on the wire (a count, never a value).
    #[test]
    fn the_mcp_list_fixture_carries_what_a_client_reads() {
        let list = &fixture("mcp_list_result")["result"];

        assert_eq!(list["enabled"], true);
        assert_eq!(list["protocol_version"], "2026-07-28");

        let server = &list["servers"][0];
        assert_eq!(server["state"], "ready");
        assert_eq!(server["transport"], "stdio");
        assert_eq!(server["tool_names"][0], "mcp__fake__echo");
        assert!(server["env_count"].is_u64(), "{server}");
        assert!(
            server.get("env").is_none(),
            "an environment value never reaches the wire"
        );

        let refusal = &list["refusals"][0];
        assert_eq!(refusal["reason"], "unsupported_transport");
        assert_eq!(refusal["name"], "remote");
    }

    /// D4. The same fixture through the typed decode, which is what `/mcp` and
    /// `ouro mcp list` actually render from.
    ///
    /// The three server states in the fixture are the three a person has to be able to
    /// tell apart — `ready` is running, `broken` has a reason, and `configured` was
    /// declared and never started — and a decode that folded any pair together would make
    /// the overlay claim a server is working when it is not.
    #[test]
    fn the_mcp_list_fixture_decodes_into_the_typed_model() {
        let list = McpList::decode(&fixture("mcp_list_result")["result"]);

        assert!(list.enabled);
        assert!(list.supervised);
        assert_eq!(list.node.as_deref(), Some("ouroboros@golden"));
        assert_eq!(list.protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(list.transports, vec!["stdio".to_string()]);
        assert_eq!(list.servers.len(), 3);
        assert_eq!(list.broken(), 1);

        let ready = &list.servers[0];
        assert_eq!(ready.name, "fake");
        assert_eq!(ready.state.as_deref(), Some("ready"));
        assert_eq!(ready.transport.as_deref(), Some("stdio"));
        assert_eq!(ready.scope.as_deref(), Some("node"));
        assert_eq!(ready.tools, 2);
        assert_eq!(
            ready.tool_names,
            vec!["mcp__fake__echo".to_string(), "mcp__fake__add".to_string()]
        );
        // The count, and only the count. There is no field on this type that could hold a
        // name or a value, which is the point.
        assert_eq!(ready.env_count, 1);
        assert!(!ready.broken());
        assert_eq!(ready.broken_reason, None);

        let broken = &list.servers[1];
        assert!(broken.broken());
        assert_eq!(broken.restarts, 4);
        assert_eq!(
            broken.broken_reason.as_deref(),
            Some("{:restart_limit, {:server_exited, 1}}"),
            "a broken server says why, in the runtime's own words"
        );
        assert_eq!(
            broken.source.as_deref(),
            Some("/home/operator/.config/ouroboros/mcp.json")
        );

        // Declared and never started: no uptime, no tools, and that is not a failure.
        let configured = &list.servers[2];
        assert_eq!(configured.state.as_deref(), Some("configured"));
        assert_eq!(configured.uptime_ms, None);
        assert_eq!(configured.tools, 0);
        assert_eq!(configured.scope.as_deref(), Some("workspace"));

        assert_eq!(list.refusals.len(), 1);
        let refused = &list.refusals[0];
        assert_eq!(refused.name.as_deref(), Some("remote"));
        assert_eq!(refused.reason.as_deref(), Some("unsupported_transport"));
        assert!(
            refused
                .detail
                .as_deref()
                .is_some_and(|text| !text.is_empty()),
            "a refusal carries the sentence that explains it"
        );
    }

    /// An answer from a gateway that never heard of MCP decodes to "nothing here", not to
    /// a panic and not to a fabricated server.
    #[test]
    fn an_empty_mcp_answer_decodes_to_a_disabled_list() {
        let empty = McpList::decode(&serde_json::json!({}));

        assert!(!empty.enabled);
        assert!(empty.servers.is_empty());
        assert!(empty.refusals.is_empty());
        assert_eq!(empty.broken(), 0);

        // A server row with no name cannot be addressed, so it is dropped rather than
        // rendered blank.
        let nameless = McpList::decode(&serde_json::json!({
            "enabled": true,
            "servers": [{"state": "ready"}, {"name": "real", "state": "ready"}],
        }));

        assert_eq!(nameless.servers.len(), 1);
        assert_eq!(nameless.servers[0].name, "real");
    }

    /// The three fixtures this slice added, decoded for the fields a client branches on.
    /// Named here rather than only listed above, because "accounted for" has to mean
    /// something was read out of the bytes.
    #[test]
    fn the_code_intelligence_and_ledger_fixtures_carry_what_a_client_reads() {
        let diagnostics = &fixture("code_intel_diagnostics_result")["result"];

        // The discriminator first: `pending` is a different answer from an empty list.
        assert_eq!(diagnostics["status"], "ok");
        assert_eq!(diagnostics["counts"]["error"], 1);

        let item = &diagnostics["items"][0];
        assert_eq!(item["severity"], "error");
        // 0-based, as the protocol reports them.
        assert_eq!(item["range"]["start"]["line"], 11);
        // The identity that makes the new-only rule possible outside the runtime.
        assert_eq!(
            item["signature"].as_str().expect("a signature").len(),
            16,
            "{item}"
        );

        let list = &fixture("ledger_list_result")["result"];
        assert_eq!(list["entries"][0]["origin_node"], "ouroboros@golden");
        assert_eq!(list["entries"][0]["effect"], "permission");
        // A machine that did not answer is a row, never a shorter list.
        assert_eq!(list["nodes"][1]["status"], "unavailable");

        let export = &fixture("ledger_export_result")["result"];
        assert_eq!(export["algorithm"], "sha256");
        assert_eq!(export["seed"].as_str().expect("a seed").len(), 64);

        let line = &export["lines"][0];
        assert_eq!(line["previous"], export["seed"]);
        assert_eq!(line["hash"], export["head"]);
        // The hashed text is a decodable record, and it is the record it names.
        let decoded: Value =
            serde_json::from_str(line["line"].as_str().expect("a line")).expect("a JSON object");
        assert_eq!(decoded["id"], line["id"]);
    }

    #[test]
    fn an_event_detail_result_decodes_as_one_bare_event_on_both_planes() {
        for name in [
            "interactive_event_detail_result",
            "coding_event_detail_result",
        ] {
            let frame = fixture(name);
            let event = Event::decode(&frame["result"]).expect("a bare event object");
            assert_eq!(
                Some(event.sequence),
                frame["result"]["sequence"].as_u64(),
                "{name} keeps its sequence"
            );
            assert!(
                event.payload.get("diff").is_some(),
                "{name} keeps its payload whole"
            );
        }
    }

    #[test]
    fn an_excerpted_notification_keeps_the_wire_marker_as_data() {
        // The gateway excerpts long payload strings into `{"_excerpt", "_bytes"}` maps
        // (docs/TUI.md §2.7). The client must decode them as values it can render, never
        // fail the event; rendering the marker is the transcript's job.
        let frame = fixture("interactive_event_excerpt_notification");
        let event = Event::decode(&frame["params"]["event"]).expect("an excerpted event decodes");
        assert_eq!(event.payload["diff"]["_bytes"], 600);
        assert_eq!(event.payload["note"]["_bytes"], 601);
        assert_eq!(event.payload["tail"]["_excerpt"], "");
        assert_eq!(event.payload["path"], "lib/ouroboros/gateway/wire.ex");
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
            "an ordinary answer names no provider_options at all"
        );
    }

    /// B2. The exact params for each of the three plan-exit choices.
    ///
    /// Byte-exact rather than field-spotted: `decision`/`scope` are what an older gateway
    /// settles on and `provider_options.choice` is what a current one reads, and the two
    /// have to agree or the same button means two different things depending on which
    /// runtime answered.
    #[test]
    fn each_plan_choice_sends_the_answer_the_runtime_folds_it_back_to() {
        let expected = [
            (PlanChoice::AutoEdit, "approve", "session", "auto_edit"),
            (PlanChoice::Prompt, "approve", "once", "prompt"),
            (PlanChoice::KeepPlanning, "deny", "once", "keep_planning"),
        ];

        for (choice, decision, scope, id) in expected {
            let params =
                respond_approval_params_with_plan("session-1", "plan_exit_x", choice, None);

            assert_eq!(
                params,
                serde_json::json!({
                    "id": "session-1",
                    "request_id": "plan_exit_x",
                    "response": {
                        "decision": decision,
                        "scope": scope,
                        "provider_options": {"choice": id},
                    },
                }),
                "{id}"
            );
        }
    }

    /// A follow-up rides along under the one key the gateway admits, and a blank one is
    /// absent rather than an empty string.
    #[test]
    fn a_plan_follow_up_is_carried_verbatim_and_a_blank_one_is_omitted() {
        let carried = respond_approval_params_with_plan(
            "session-1",
            "plan_exit_x",
            PlanChoice::Prompt,
            Some("  start with the parser  "),
        );

        assert_eq!(
            carried["response"]["provider_options"],
            serde_json::json!({"choice": "prompt", "follow_up": "start with the parser"}),
        );

        for blank in ["", "   ", "\n\t "] {
            let params = respond_approval_params_with_plan(
                "session-1",
                "plan_exit_x",
                PlanChoice::Prompt,
                Some(blank),
            );

            assert_eq!(
                params["response"]["provider_options"],
                serde_json::json!({"choice": "prompt"}),
                "a blank follow-up is not a follow-up ({blank:?})"
            );
        }
    }

    /// The gateway refuses a follow-up over 32 KiB outright, so the client clips rather
    /// than losing the whole answer — and clips on a character boundary, because a
    /// truncated multi-byte character is not a string the gateway would accept either.
    #[test]
    fn an_over_long_plan_follow_up_is_clipped_on_a_character_boundary() {
        // A 3-byte character repeated past the ceiling: a naive byte truncation lands
        // mid-character on exactly this input.
        let long = "→".repeat(MAX_PLAN_FOLLOW_UP_BYTES);
        let params = respond_approval_params_with_plan(
            "session-1",
            "plan_exit_x",
            PlanChoice::AutoEdit,
            Some(&long),
        );

        let sent = params["response"]["provider_options"]["follow_up"]
            .as_str()
            .expect("a follow-up");

        assert!(sent.len() <= MAX_PLAN_FOLLOW_UP_BYTES, "{}", sent.len());
        assert!(
            sent.chars().all(|found| found == '→'),
            "no partial character survives the clip"
        );
    }

    /// Every choice this build offers is one the gateway's own enum admits, spelled the
    /// same way.
    #[test]
    fn the_plan_choices_round_trip_through_their_wire_names() {
        for choice in PlanChoice::ALL {
            assert_eq!(PlanChoice::parse(choice.as_str()), Some(choice));
        }

        assert_eq!(PlanChoice::parse("allow_always"), None);
        assert_eq!(PlanChoice::parse(""), None);
    }

    #[test]
    fn an_approval_reason_is_carried_verbatim_and_omitted_when_absent() {
        let reasoned = respond_approval_params_with_reason(
            "session-1",
            "req-9",
            ApprovalDecision::Approve,
            ApprovalScope::Once,
            Some("matches the documented migration"),
        );

        assert_eq!(reasoned["response"]["decision"], "approve");
        assert_eq!(reasoned["response"]["scope"], "once");
        assert_eq!(
            reasoned["response"]["reason"],
            "matches the documented migration"
        );

        let bare = respond_approval_params_with_reason(
            "session-1",
            "req-9",
            ApprovalDecision::Approve,
            ApprovalScope::Once,
            None,
        );

        assert!(
            bare["response"]
                .as_object()
                .expect("an object")
                .get("reason")
                .is_none(),
            "an absent reason omits the key instead of sending null"
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
    fn a_start_sends_only_options_the_gateway_allowlists() {
        let mut request = StartRequest::new(Plane::Interactive);
        request.provider = "claude_code".into();
        request.workspace = "/work".into();
        request.approval_mode = Some(ApprovalMode::Prompt);

        let params = request.params().expect("a valid start");
        let fields = params.as_object().expect("an object");

        assert_eq!(fields["id"], request.id);
        assert_eq!(fields["provider"], "claude_code");
        assert_eq!(fields["workspace"], "/work");
        assert_eq!(fields["approval_mode"], "prompt");
        assert_eq!(
            fields.len(),
            4,
            "an option outside @start_options is -32602 naming it, so none is invented: \
             {fields:?}"
        );

        request.sandbox_mode = Some(SandboxMode::ReadOnly);
        let fields = request
            .params()
            .expect("still valid")
            .as_object()
            .expect("an object")
            .clone();
        assert_eq!(fields["sandbox_mode"], "read_only");
        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn an_unanswered_field_is_omitted_rather_than_sent_empty() {
        let mut request = StartRequest::new(Plane::Interactive);
        request.provider = "codex".into();

        let params = request.params().expect("a valid start");
        let fields = params.as_object().expect("an object");

        // `option_value(_, :string, _)` requires a nonempty binary, so `""` would be a
        // parameter error rather than "no workspace".
        assert!(!fields.contains_key("workspace"));
        assert!(!fields.contains_key("approval_mode"));
        assert!(!fields.contains_key("sandbox_mode"));
        assert!(!fields.contains_key("objective"));
        assert_eq!(fields["id"], request.id);
        assert_eq!(fields.len(), 2);

        // Whitespace is not an answer either.
        request.workspace = "   ".into();
        assert!(!request
            .params()
            .expect("still valid")
            .as_object()
            .unwrap()
            .contains_key("workspace"));
    }

    #[test]
    fn the_two_planes_disagree_about_objective_and_both_are_enforced_here() {
        let mut coding = StartRequest::new(Plane::Coding);
        coding.provider = "codex".into();

        assert_eq!(coding.params(), Err(StartError::NoObjective));

        coding.objective = "fix the build".into();
        let params = coding.params().expect("a valid coding start");
        assert_eq!(params["objective"], "fix the build");
        assert_eq!(coding.method(), "coding.start");

        // `objective` is not in the interactive allowlist, so sending it would be -32602.
        let mut interactive = StartRequest::new(Plane::Interactive);
        interactive.provider = "codex".into();
        interactive.objective = "fix the build".into();

        assert_eq!(
            interactive.params(),
            Err(StartError::ObjectiveOnInteractive)
        );
        assert_eq!(interactive.method(), "interactive.start");
    }

    #[test]
    fn a_start_without_a_provider_is_refused_here_rather_than_guessed() {
        let request = StartRequest::new(Plane::Interactive);

        assert_eq!(request.params(), Err(StartError::NoProvider));
        assert!(StartError::NoProvider.message().contains("which vendor"));
    }

    #[test]
    fn every_start_has_a_client_owned_retry_identity() {
        let request = StartRequest::new(Plane::Interactive);

        assert!(request.id.starts_with("ouro-session-"));

        let mut invalid = request;
        invalid.id.clear();
        invalid.provider = "codex".into();
        assert_eq!(invalid.params(), Err(StartError::NoId));
    }

    #[test]
    fn a_remote_start_requires_an_absolute_destination_workspace() {
        let mut request = StartRequest::new(Plane::Interactive);
        request.provider = "codex".into();
        request.machine = "mini".into();

        assert_eq!(request.params(), Err(StartError::NoRemoteWorkspace));

        request.workspace = "project".into();
        assert_eq!(
            request.params(),
            Err(StartError::RemoteWorkspaceNotAbsolute("project".into()))
        );

        request.workspace = "/srv/project".into();
        let params = request.params().expect("an explicit remote workspace");
        assert_eq!(params["machine"], "mini");
        assert_eq!(params["workspace"], "/srv/project");
    }

    #[test]
    fn the_approval_modes_are_the_ones_the_schema_declares() {
        // Exactly `Gateway.Methods` @approval_modes. A fifth would be -32602.
        assert_eq!(
            ApprovalMode::ALL.map(ApprovalMode::as_str),
            ["default", "prompt", "auto_edit", "auto_approve"]
        );

        for mode in ApprovalMode::ALL {
            assert_eq!(ApprovalMode::parse(mode.as_str()), Some(mode));
            assert!(!mode.describe().is_empty());
        }

        assert_eq!(ApprovalMode::parse("yolo"), None);
        assert!(StartError::UnknownApprovalMode("yolo".into())
            .message()
            .contains("auto_approve"));
    }

    #[test]
    fn the_sandbox_modes_are_the_ones_the_schema_declares() {
        assert_eq!(
            SandboxMode::ALL.map(SandboxMode::as_str),
            ["default", "read_only", "workspace_write", "unrestricted"]
        );

        for mode in SandboxMode::ALL {
            assert_eq!(SandboxMode::parse(mode.as_str()), Some(mode));
            assert!(!mode.describe().is_empty());
            assert!(!mode.label().is_empty());
        }

        assert_eq!(SandboxMode::parse("yolo"), None);
        assert!(StartError::UnknownSandboxMode("yolo".into())
            .message()
            .contains("workspace_write"));
    }

    #[test]
    fn a_started_session_is_read_out_of_the_wire_encoded_ref() {
        let started = StartedRef::decode(&serde_json::json!({
            "_struct": "Ouroboros.Interactive.Ref",
            "id": "session-0000000000000000000001",
            "node": "ouroboros@golden"
        }))
        .expect("a ref");

        assert_eq!(started.id, "session-0000000000000000000001");
        assert_eq!(started.node.as_deref(), Some("ouroboros@golden"));
        assert_eq!(started.start_failure, None);

        let created = StartedRef::decode(&serde_json::json!({
            "id": "session-failed-after-checkpoint",
            "node": "ouroboros@golden",
            "outcome": "created",
            "ready": false,
            "error": ["session_start_failed", ["workspace_admission_failed", "busy"]]
        }))
        .expect("a durable failed start reference");

        assert_eq!(created.id, "session-failed-after-checkpoint");
        assert_eq!(created.node.as_deref(), Some("ouroboros@golden"));
        assert!(
            created
                .start_failure
                .as_deref()
                .is_some_and(|failure| failure.contains("session_start_failed")
                    && failure.contains("workspace_admission_failed")),
            "{:?}",
            created.start_failure
        );

        assert_eq!(
            StartedRef::decode(&serde_json::json!("bare-id")).map(|r| r.id),
            Some("bare-id".to_string())
        );

        assert_eq!(StartedRef::decode(&serde_json::json!({})), None);
        assert_eq!(StartedRef::decode(&serde_json::json!({ "id": "" })), None);
    }

    fn upstream(data: Value) -> RpcError {
        RpcError {
            code: ErrorCode::UpstreamError,
            message: "the runtime refused the call".into(),
            data: Some(data),
        }
    }

    /// The payload an operator was actually shown as raw JSON: a `Jido.Harness.Error`
    /// raised inside `interactive.start`, Wire-encoded.
    fn session_start_failed() -> Value {
        serde_json::json!([
            "session_start_failed",
            {
                "__exception__": true,
                "category": "validation",
                "cause": null,
                "details": { "field": "sandbox_mode" },
                "message": "provider does not support normalized session option",
                "provider": "amp",
                "run_id": null
            }
        ])
    }

    #[test]
    fn a_wire_encoded_exception_reads_as_a_sentence_rather_than_as_json() {
        let rendered = refusal(&upstream(session_start_failed()));
        let mut lines = rendered.lines();

        assert_eq!(
            lines.next(),
            Some(
                "upstream_error (-32006): the runtime refused the call — amp: provider does \
                 not support normalized session option (field: sandbox_mode)"
            ),
            "{rendered}"
        );

        // The tag is gone from the sentence: `session_start_failed` says nothing the
        // message does not, and the surrounding text already said a start was refused.
        assert!(
            !lines.clone().collect::<String>().is_empty(),
            "the keys the sentence did not use are still on screen: {rendered}"
        );
    }

    #[test]
    fn an_indeterminate_turn_dispatch_keeps_its_id_and_diagnostic() {
        let rpc = RpcError {
            code: ErrorCode::UpstreamTimeout,
            message: "the runtime could not confirm the turn dispatch".into(),
            data: Some(serde_json::json!({
                "outcome": "unknown",
                "turn_id": "ouro-first:session-1",
                "error": [
                    "turn_dispatch_checkpoint_failed",
                    "dispatch_may_have_started",
                    "ouro-first:session-1"
                ]
            })),
        };

        let rendered = refusal(&rpc);
        let mut lines = rendered.lines();

        assert_eq!(
            lines.next(),
            Some(
                "upstream_timeout (-32005): the runtime could not confirm the turn dispatch — \
                 outcome unknown (turn ouro-first:session-1)"
            ),
            "{rendered}"
        );

        let diagnostic = lines.next().expect("the Wire diagnostic remains visible");
        assert!(
            diagnostic.contains("turn_dispatch_checkpoint_failed"),
            "{diagnostic}"
        );
        assert!(outcome_unknown(rpc.data.as_ref()));

        // A new client attached to an older runtime still must not turn this exact legacy
        // Wire tuple into permission to mint a second logical turn.
        let legacy = serde_json::json!([
            "turn_dispatch_checkpoint_failed",
            "dispatch_may_have_started",
            "ouro-first:session-1"
        ]);
        assert!(outcome_unknown(Some(&legacy)));
        assert!(outcome_unknown(Some(&serde_json::json!([
            "turn_dispatch_ambiguous",
            "ouro-first:session-1"
        ]))));
        assert!(outcome_unknown(Some(&serde_json::json!([
            "turn_dispatch_ambiguous",
            "ouro-first:session-1",
            "checkpoint_failed"
        ]))));
        assert!(!outcome_unknown(Some(&serde_json::json!([
            "turn_dispatch_failed",
            "provider_refused"
        ]))));
        assert!(!outcome_unknown(Some(&serde_json::json!([
            "turn_dispatch_ambiguous"
        ]))));
    }

    #[test]
    fn a_busy_turn_is_distinct_from_an_unknown_dispatch() {
        let current = serde_json::json!({
            "reason": "busy",
            "outcome": "not_dispatched",
            "retry_with": "interactive.follow_up",
            "error": ["turn_dispatch_failed", "busy"]
        });
        let legacy = serde_json::json!(["turn_dispatch_failed", "busy"]);

        assert!(turn_busy(Some(&current)));
        assert!(turn_busy(Some(&legacy)));
        assert!(!outcome_unknown(Some(&current)));
        assert!(!turn_busy(Some(&serde_json::json!([
            "turn_dispatch_failed",
            "closed"
        ]))));
    }

    #[test]
    fn successful_turn_envelopes_do_not_turn_terminal_failure_into_acceptance() {
        let running = serde_json::json!({ "id": "t-1", "status": "running" });
        let completed = serde_json::json!({ "id": "t-1", "status": "completed" });
        let dispatching = serde_json::json!({ "id": "t-1", "status": "dispatching" });
        let ambiguous = serde_json::json!({ "id": "t-1", "status": "ambiguous" });
        let failed = serde_json::json!({
            "id": "t-1",
            "status": "failed",
            "error": "busy"
        });
        let interrupted = serde_json::json!({ "id": "t-1", "status": "interrupted" });

        assert_eq!(turn_reply(&running), TurnReply::Accepted);
        assert_eq!(turn_reply(&completed), TurnReply::Accepted);
        assert_eq!(turn_reply(&dispatching), TurnReply::OutcomeUnknown);
        assert_eq!(turn_reply(&ambiguous), TurnReply::OutcomeUnknown);
        assert_eq!(turn_reply(&failed), TurnReply::Rejected);
        assert_eq!(turn_reply(&interrupted), TurnReply::Rejected);
        assert!(turn_reply_busy(&failed));
        assert_eq!(
            turn_reply_diagnostic(&failed),
            "turn t-1 is failed — error=busy"
        );
    }

    #[test]
    fn nothing_the_sentence_did_not_use_is_lost() {
        let rendered = refusal(&upstream(session_start_failed()));
        let rest = rendered.lines().nth(1).expect("a remainder line");

        // Everything the line above did not carry, and nothing it did.
        assert!(rest.starts_with("also: "), "{rest}");
        assert!(rest.contains("category=validation"), "{rest}");
        assert!(rest.contains("cause=null"), "{rest}");
        assert!(rest.contains("run_id=null"), "{rest}");

        assert!(
            !rest.contains("sandbox_mode") && !rest.contains("amp"),
            "the remainder is the remainder, not a second copy: {rest}"
        );

        // `__exception__` is the only key that goes nowhere: `Wire` sets it on every
        // exception it encodes, so it is a fact about the envelope rather than this
        // failure.
        assert!(!rest.contains("__exception__"), "{rest}");
    }

    #[test]
    fn a_payload_with_no_message_falls_back_to_its_tag() {
        let rendered = refusal(&upstream(serde_json::json!([
            "invalid_workspace",
            { "__exception__": true, "provider": "codex", "details": { "path": "/srv/nope" } }
        ])));

        assert_eq!(
            rendered,
            "upstream_error (-32006): the runtime refused the call — codex: \
             invalid_workspace (path: /srv/nope)"
        );
    }

    #[test]
    fn each_half_of_the_sentence_is_optional() {
        // No provider: the message stands on its own.
        let rendered = refusal(&upstream(serde_json::json!([
            "start_failed",
            { "message": "the workspace does not exist" }
        ])));

        assert_eq!(
            rendered,
            "upstream_error (-32006): the runtime refused the call — the workspace does not \
             exist"
        );

        // No details, and a provider that is present but null — which is not a provider,
        // so it belongs in the remainder rather than in the line.
        let rendered = refusal(&upstream(serde_json::json!([
            "start_failed",
            { "message": "no", "provider": null }
        ])));

        assert_eq!(
            rendered,
            "upstream_error (-32006): the runtime refused the call — no\nalso: provider=null"
        );
    }

    /// The coding plane's fail-closed refusals are the same shape with different keys, and
    /// nothing here knows what any particular key means.
    #[test]
    fn a_details_map_nobody_has_written_yet_renders_as_itself() {
        let rendered = refusal(&upstream(serde_json::json!([
            "coding_start_refused",
            {
                "__exception__": true,
                "message": "this provider will not accept a stated sandbox mode",
                "provider": "opencode",
                "details": {
                    "field": "sandbox_mode",
                    "override": "omit it and let the plane decide",
                    "attempted": "danger-full-access"
                }
            }
        ])));

        assert_eq!(
            rendered,
            "upstream_error (-32006): the runtime refused the call — opencode: this provider \
             will not accept a stated sandbox mode (attempted: danger-full-access, field: \
             sandbox_mode, override: omit it and let the plane decide)"
        );
    }

    #[test]
    fn an_unrecognised_payload_keeps_the_json_it_always_had() {
        // Not a two-element array.
        for data in [
            serde_json::json!({ "reason": "cursor_pruned", "floor": 96 }),
            serde_json::json!(["one"]),
            serde_json::json!(["one", "two", "three"]),
            // The second element is not a map, which is the older `{:error, {tag, term}}`
            // encoding this client has always shown as JSON.
            serde_json::json!(["invalid_workspace", "/srv/nope"]),
            serde_json::json!("a bare string"),
            serde_json::json!([{ "message": "the tag is not a string" }, {}]),
        ] {
            let rendered = refusal(&upstream(data.clone()));

            assert_eq!(
                rendered,
                format!(
                    "upstream_error (-32006): the runtime refused the call — {}",
                    compact(&data)
                ),
                "guessing at an unknown shape is how a prettifier starts asserting things"
            );
        }
    }

    #[test]
    fn a_details_map_too_big_or_too_deep_goes_to_the_remainder_whole() {
        // Nested: not a phrase, and not silently half-rendered either.
        let rendered = refusal(&upstream(serde_json::json!([
            "start_failed",
            { "message": "no", "details": { "nested": { "a": 1 } } }
        ])));

        assert_eq!(
            rendered,
            "upstream_error (-32006): the runtime refused the call — no\n\
             also: details={\"nested\":{\"a\":1}}"
        );

        // Seven fields is past the point where a parenthesis is easier to read than JSON.
        let wide = serde_json::json!([
            "start_failed",
            { "message": "no", "details": { "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7 } }
        ]);

        assert!(
            refusal(&upstream(wide)).contains("also: details={"),
            "a sprawling details map is JSON, not a sentence"
        );
    }

    #[test]
    fn a_refusal_with_no_data_is_just_the_error() {
        let plain = RpcError {
            code: ErrorCode::ScopeDenied,
            message: "this listener runs at scope read".into(),
            data: None,
        };

        assert_eq!(
            refusal(&plain),
            "scope_denied (-32003): this listener runs at scope read"
        );

        // An explicit null carries nothing either.
        let null = RpcError {
            data: Some(Value::Null),
            ..plain.clone()
        };

        assert_eq!(refusal(&null), refusal(&plain));
    }

    /// The fixture the golden set already carries, through the new renderer.
    #[test]
    fn the_golden_refusal_fixtures_still_render() {
        for name in [
            "error_scope_denied",
            "error_not_found",
            "error_invalid_request",
            "error_cursor_pruned",
        ] {
            let rendered = refusal(&error(name));

            assert!(!rendered.is_empty(), "{name}");
            assert!(
                rendered.starts_with(&error(name).code.to_string()),
                "the code stays in front, because that is what a report is grepped for: \
                 {name} -> {rendered}"
            );
        }
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
