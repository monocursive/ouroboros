//! A tolerant, presentation-only reading of normalized Harness events.
//!
//! The durable event and its raw payload remain the source of truth. These types name only
//! the fields a transcript can lay out usefully; missing or newer shapes fall back to the
//! complete event-details view instead of becoming client-side state or policy.
//!
//! ## Every kind is presented, and a hide is a decision with a reason
//!
//! There is deliberately no catch-all "ignore" arm. Each of the twenty-nine normalized
//! event types names a [`PresentationEvent`], and the one arm that draws nothing —
//! [`PresentationEvent::Hidden`] — carries the reason it drew nothing. A kind the client
//! did not recognise becomes [`PresentationEvent::ProviderNote`] rather than disappearing:
//! a transcript that silently omits events is a transcript that cannot be trusted about
//! the events it does show.

use serde_json::{Map, Value};

use super::{compact, Event, EventType};

// These ceilings apply only to the derived transcript projection. `Event::payload` and
// `Event::raw` remain complete for event details, replay, and any future presentation.
const PRESENTATION_TEXT_BYTES: usize = 64 * 1024;
const PRESENTATION_VALUE_BYTES: usize = 64 * 1024;
const PRESENTATION_VALUE_NODES: usize = 2_048;
const PRESENTATION_VALUE_DEPTH: usize = 32;
const PRESENTATION_DIFF_BYTES: usize = 128 * 1024;
const PRESENTATION_FILE_CHANGES: usize = 256;
/// Plan payloads are model-authored task lists, not data structures: a provider that emits
/// a thousand steps is reporting a runaway, and the panel says so rather than drawing it.
const PRESENTATION_PLAN_STEPS: usize = 64;
/// How many tool names a `run_started` header fact keeps. The complete list stays on the
/// event.
const PRESENTATION_RUN_TOOLS: usize = 128;
const TEXT_TRUNCATION: &str =
    "\n… transcript excerpt truncated; full value is available in event details";
const DIFF_TRUNCATION: &str = "\n… diff truncated; full diff is available in event details";

#[derive(Debug, Clone, PartialEq)]
pub enum PresentationEvent {
    UserMessage(String),
    /// A steer. The text is optional because a checkpointed event from before the runtime
    /// carried it, and every recovered turn, arrives without one.
    UserSteer(Option<String>),
    /// An accepted input whose words this ledger does not hold. Named rather than dropped:
    /// a chat that silently omits a turn the operator remembers typing is a chat that
    /// cannot be trusted about the turns it does show.
    UnrecordedInput,
    AgentText {
        turn_id: Option<String>,
        text: String,
        final_text: bool,
    },
    /// Reasoning the provider chose to publish. Accumulated per turn by the cell
    /// projection; never treated as the agent's answer.
    Thinking {
        turn_id: Option<String>,
        text: String,
    },
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    CommandOutput(String),
    FileUpdate(FileUpdate),
    Plan(PlanUpdate),
    Usage(UsageReport),
    /// A provider run began. Claude reports the model and the tool catalogue here; nothing
    /// else in the stream ever names the model.
    RunStarted(RunStart),
    TurnStarted {
        turn_id: Option<String>,
        /// Milliseconds since the epoch, from `Event::timestamp`, when it parses.
        at: Option<i64>,
    },
    TurnEnded {
        turn_id: Option<String>,
        at: Option<i64>,
        outcome: TurnOutcome,
        detail: String,
    },
    /// How many turns the runtime is holding behind the running one.
    QueueChanged {
        queued: usize,
    },
    /// A lifecycle fact with no payload worth a cell of its own.
    Lifecycle {
        marker: Lifecycle,
        detail: String,
    },
    ApprovalRequested {
        request_id: Option<String>,
        detail: String,
    },
    ApprovalResolved {
        request_id: Option<String>,
        decision: Option<String>,
        detail: String,
    },
    Failure(String),
    Interrupted(String),
    /// Something the provider said that this client does not model. Named by its own kind
    /// so it is one dim line rather than an invisible event.
    ProviderNote {
        kind: String,
        detail: String,
    },
    /// Drawn as nothing, on purpose, for the stated reason.
    Hidden(Hidden),
}

/// Why a presentation drew nothing. Every value here is a payload that carried no content,
/// never a *kind* this client declines to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hidden {
    /// An output delta or final with no text: transports emit these as keep-alives.
    EmptyText,
    /// A reasoning delta with no text.
    EmptyThinking,
    /// A command-output delta with no bytes.
    EmptyCommandOutput,
}

impl Hidden {
    pub fn reason(self) -> &'static str {
        match self {
            Self::EmptyText => "an output event carrying no text",
            Self::EmptyThinking => "a reasoning delta carrying no text",
            Self::EmptyCommandOutput => "a command-output delta carrying no bytes",
        }
    }
}

/// Lifecycle facts that belong in the reading path as one dim line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    RunCompleted,
    SessionStarted,
    SessionReady,
    SessionIdle,
    SessionClosed,
    TurnQueued,
}

impl Lifecycle {
    pub fn label(self) -> &'static str {
        match self {
            Self::RunCompleted => "run finished",
            Self::SessionStarted => "session started",
            Self::SessionReady => "session ready",
            Self::SessionIdle => "session idle",
            Self::SessionClosed => "session closed",
            Self::TurnQueued => "turn queued",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnOutcome {
    Completed,
    Failed,
    Interrupted,
}

impl TurnOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Completed => "turn complete",
            Self::Failed => "turn failed",
            Self::Interrupted => "turn interrupted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunStart {
    pub model: Option<String>,
    pub cwd: Option<String>,
    /// Tool names the provider declared for the run, bounded.
    pub tools: Vec<String>,
    /// How many tools the provider actually declared, which may exceed `tools.len()`.
    pub tool_count: usize,
}

/// One `usage` report exactly as the provider phrased it. Absent fields stay absent: a
/// zero this client invented would be indistinguishable from a zero a provider measured.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct UsageReport {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

impl UsageReport {
    pub fn is_empty(&self) -> bool {
        self.input_tokens.is_none()
            && self.output_tokens.is_none()
            && self.cached_tokens.is_none()
            && self.total_tokens.is_none()
            && self.cost_usd.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanUpdate {
    pub explanation: Option<String>,
    pub steps: Vec<PlanStep>,
    /// How many steps the provider sent, which may exceed `steps.len()`.
    pub step_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub text: String,
    pub status: PlanStatus,
    pub priority: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStatus {
    Pending,
    InProgress,
    Done,
    /// A word this client does not recognise, kept verbatim. Guessing that an unknown
    /// status meant "done" is how a panel reports finished work that never happened.
    Other(String),
}

impl PlanStatus {
    pub fn parse(status: Option<&str>) -> Self {
        let Some(status) = status.map(str::trim).filter(|status| !status.is_empty()) else {
            return Self::Pending;
        };

        match status.to_ascii_lowercase().as_str() {
            "pending" | "todo" | "not_started" | "notstarted" | "queued" | "planned" => {
                Self::Pending
            }
            "in_progress" | "inprogress" | "in-progress" | "running" | "active" | "started" => {
                Self::InProgress
            }
            "completed" | "complete" | "done" | "finished" | "succeeded" => Self::Done,
            _ => Self::Other(status.to_string()),
        }
    }

    /// Warp's plan glyphs: `◌` pending, `●` in progress, `✓` done.
    pub fn glyph(&self) -> &'static str {
        match self {
            Self::Pending => "◌",
            Self::InProgress => "●",
            Self::Done => "✓",
            Self::Other(_) => "?",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in progress",
            Self::Done => "done",
            Self::Other(status) => status,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub call_id: Option<String>,
    pub name: String,
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolResult {
    pub call_id: Option<String>,
    pub name: Option<String>,
    pub output: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileUpdate {
    pub status: Option<String>,
    pub changes: Vec<FileChange>,
    pub diff: Option<Diff>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileChange {
    pub path: Option<String>,
    pub kind: Option<String>,
    pub diff: Option<Diff>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub text: String,
    pub path: Option<String>,
    pub additions: usize,
    pub deletions: usize,
    /// Counts describe only the bounded projection when this is true.
    pub truncated: bool,
}

impl PresentationEvent {
    /// Every normalized kind, with no catch-all. Adding a type to [`EventType`] without a
    /// presentation is a compile error rather than a silent drop.
    pub fn from_event(event: &Event) -> Self {
        match event.kind {
            EventType::InputAccepted => input_accepted(&event.payload),
            EventType::OutputTextDelta | EventType::OutputTextFinal => {
                let Some(text) = raw_text(&event.payload, &["text"]) else {
                    return Self::Hidden(Hidden::EmptyText);
                };

                Self::AgentText {
                    turn_id: bounded_optional(event.turn_id.as_deref()),
                    text,
                    final_text: event.kind == EventType::OutputTextFinal,
                }
            }
            EventType::ThinkingDelta => {
                let Some(text) = raw_text(&event.payload, &["text", "thinking", "reasoning"])
                else {
                    return Self::Hidden(Hidden::EmptyThinking);
                };

                Self::Thinking {
                    turn_id: bounded_optional(event.turn_id.as_deref()),
                    text,
                }
            }
            EventType::ToolCall => Self::ToolCall(ToolCall {
                call_id: text(
                    &event.payload,
                    &["call_id", "tool_call_id", "toolCallId", "id"],
                ),
                name: text(
                    &event.payload,
                    &["name", "tool_name", "toolName", "tool", "title", "kind"],
                )
                .unwrap_or_else(|| "tool".to_string()),
                input: first_value(
                    &event.payload,
                    &["input", "arguments", "parameters", "rawInput", "raw_input"],
                )
                .map(bounded_value)
                .unwrap_or_else(empty_object),
            }),
            EventType::ToolResult => Self::ToolResult(ToolResult {
                call_id: text(
                    &event.payload,
                    &["call_id", "tool_call_id", "toolCallId", "id"],
                ),
                name: text(
                    &event.payload,
                    &["name", "tool_name", "toolName", "tool", "title", "kind"],
                ),
                output: first_value(
                    &event.payload,
                    &["output", "result", "content", "rawOutput", "raw_output"],
                )
                .map(bounded_value)
                .unwrap_or(Value::Null),
                is_error: error_result(&event.payload),
            }),
            EventType::CommandOutputDelta => raw_text(&event.payload, &["text", "output"])
                .map(Self::CommandOutput)
                .unwrap_or(Self::Hidden(Hidden::EmptyCommandOutput)),
            EventType::FileChange => Self::FileUpdate(file_update(&event.payload)),
            EventType::PlanUpdated => Self::Plan(plan_update(&event.payload)),
            EventType::Usage => Self::Usage(usage_report(&event.payload)),
            EventType::RunStarted => Self::RunStarted(run_start(&event.payload)),
            EventType::TurnStarted => Self::TurnStarted {
                turn_id: bounded_optional(event.turn_id.as_deref()),
                at: epoch_millis(&event.timestamp),
            },
            EventType::TurnCompleted | EventType::TurnFailed | EventType::TurnInterrupted => {
                Self::TurnEnded {
                    turn_id: bounded_optional(event.turn_id.as_deref()),
                    at: epoch_millis(&event.timestamp),
                    outcome: match event.kind {
                        EventType::TurnFailed => TurnOutcome::Failed,
                        EventType::TurnInterrupted => TurnOutcome::Interrupted,
                        _ => TurnOutcome::Completed,
                    },
                    detail: optional_detail(&event.payload).unwrap_or_default(),
                }
            }
            EventType::QueueChanged => Self::QueueChanged {
                queued: count(
                    &event.payload,
                    &["queued_turns", "queued", "length", "count"],
                ),
            },
            EventType::TurnQueued => Self::Lifecycle {
                marker: Lifecycle::TurnQueued,
                detail: optional_detail(&event.payload).unwrap_or_default(),
            },
            EventType::RunCompleted
            | EventType::SessionStarted
            | EventType::SessionReady
            | EventType::SessionIdle
            | EventType::SessionClosed => Self::Lifecycle {
                marker: match event.kind {
                    EventType::RunCompleted => Lifecycle::RunCompleted,
                    EventType::SessionStarted => Lifecycle::SessionStarted,
                    EventType::SessionReady => Lifecycle::SessionReady,
                    EventType::SessionIdle => Lifecycle::SessionIdle,
                    _ => Lifecycle::SessionClosed,
                },
                detail: lifecycle_detail(&event.payload),
            },
            EventType::ProviderEvent => provider_note(&event.payload),
            // A kind this build does not know. It is still an event the runtime recorded,
            // so it reads as one dim line naming itself rather than as nothing at all.
            EventType::Other(ref kind) => Self::ProviderNote {
                kind: bounded_copy(kind, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION),
                detail: optional_detail(&event.payload).unwrap_or_default(),
            },
            EventType::ApprovalRequested => Self::ApprovalRequested {
                request_id: bounded_optional(event.request_id.as_deref()),
                detail: subject(&event.payload),
            },
            EventType::ApprovalResolved => Self::ApprovalResolved {
                request_id: bounded_optional(event.request_id.as_deref()),
                decision: text(&event.payload, &["decision"]),
                detail: approval_resolution(&event.payload),
            },
            EventType::RunFailed | EventType::SessionFailed => {
                Self::Failure(detail(&event.payload))
            }
            EventType::RunCancelled | EventType::SessionCancelled => {
                Self::Interrupted(detail(&event.payload))
            }
        }
    }
}

/// What one accepted input was, given that the ledger does not always carry its words.
///
/// The text is missing for every event checkpointed before the runtime recorded it and for
/// every recovered turn, and those events are not going away. Mapping them to `Ignore`
/// deleted real turns from the chat — including every steer, which is the one kind of turn
/// an operator is most likely to be looking for afterwards.
fn input_accepted(payload: &Value) -> PresentationEvent {
    let words = raw_text(payload, &["text"]).filter(|words| !words.trim().is_empty());
    let steered = text(payload, &["kind"])
        .map(|kind| kind == "steer")
        .unwrap_or(false);

    match (steered, words) {
        (true, words) => PresentationEvent::UserSteer(words),
        (false, Some(words)) => PresentationEvent::UserMessage(words),
        (false, None) => PresentationEvent::UnrecordedInput,
    }
}

/// The provider kind an escape-hatch event is reporting, so it is never invisible.
///
/// ACP wraps every update it does not map in `{"kind": "acp_update", "update": …}`; the
/// update's own `sessionUpdate` type is the informative half and is lifted out here.
fn provider_note(payload: &Value) -> PresentationEvent {
    let kind = text(payload, &["kind", "type", "item_type", "event", "name"]);
    let nested = payload
        .get("update")
        .and_then(|update| text(update, &["sessionUpdate", "session_update", "type"]));

    // Empty when the provider named no kind at all: the cell says "provider event" once,
    // and inventing a second copy of that phrase to sit in this field would only make it
    // say it twice.
    let kind = match (kind, nested) {
        (Some(kind), Some(nested)) => format!("{kind} · {nested}"),
        (Some(kind), None) => kind,
        (None, Some(nested)) => nested,
        (None, None) => String::new(),
    };

    PresentationEvent::ProviderNote {
        kind: bounded_copy(&kind, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION),
        detail: optional_detail(payload).unwrap_or_default(),
    }
}

fn run_start(payload: &Value) -> RunStart {
    let declared = payload.get("tools").and_then(Value::as_array);
    let tool_count = declared.map(Vec::len).unwrap_or(0);
    let tools = declared
        .map(|tools| {
            tools
                .iter()
                .take(PRESENTATION_RUN_TOOLS)
                .filter_map(|tool| match tool {
                    Value::String(name) => nonempty(name),
                    other => text(other, &["name", "tool", "title"]),
                })
                .collect()
        })
        .unwrap_or_default();

    RunStart {
        model: text(payload, &["model", "model_id", "modelId"]),
        cwd: text(payload, &["cwd", "workspace", "working_directory"]),
        tools,
        tool_count,
    }
}

fn usage_report(payload: &Value) -> UsageReport {
    UsageReport {
        input_tokens: number(payload, &["input_tokens", "inputTokens", "prompt_tokens"]),
        output_tokens: number(
            payload,
            &["output_tokens", "outputTokens", "completion_tokens"],
        ),
        cached_tokens: number(
            payload,
            &[
                "cache_read_input_tokens",
                "cached_input_tokens",
                "cachedInputTokens",
                "cache_read_tokens",
            ],
        ),
        total_tokens: number(payload, &["total_tokens", "totalTokens"]),
        cost_usd: first_value(payload, &["cost_usd", "total_cost_usd", "costUsd"])
            .and_then(Value::as_f64),
    }
}

/// Both plan shapes this runtime can deliver, read tolerantly.
///
/// Codex sends `{"explanation", "plan": [{"step", "status"}]}`
/// (`Ouroboros.Provider.Session.Dialect.Codex`); ACP forwards its `plan` session update
/// verbatim, whose entries are `{"content", "priority", "status"}`.
fn plan_update(payload: &Value) -> PlanUpdate {
    let entries = first_value(payload, &["plan", "entries", "steps", "todos", "tasks"])
        .and_then(Value::as_array);
    let step_count = entries.map(Vec::len).unwrap_or(0);
    let steps = entries
        .map(|entries| {
            entries
                .iter()
                .take(PRESENTATION_PLAN_STEPS)
                .filter_map(plan_step)
                .collect()
        })
        .unwrap_or_default();

    PlanUpdate {
        explanation: text(payload, &["explanation", "summary", "description"]),
        steps,
        step_count,
    }
}

fn plan_step(value: &Value) -> Option<PlanStep> {
    match value {
        Value::String(text) => nonempty(text).map(|text| PlanStep {
            text,
            status: PlanStatus::Pending,
            priority: None,
        }),
        Value::Object(_) => {
            let body = text(
                value,
                &["step", "content", "text", "title", "description", "name"],
            )
            .or_else(|| leaf_text(value.get("content")?));

            body.map(|text| PlanStep {
                text,
                status: PlanStatus::parse(
                    trimmed_string_value(value, &["status", "state"])
                        .map(str::to_string)
                        .as_deref(),
                ),
                priority: text_field(value, &["priority"]),
            })
        }
        _ => None,
    }
}

fn text_field(value: &Value, keys: &[&str]) -> Option<String> {
    text(value, keys)
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

fn nonempty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| bounded_copy(text, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION))
}

fn number(value: &Value, keys: &[&str]) -> Option<u64> {
    first_value(value, keys).and_then(|value| match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_f64()
                .filter(|value| *value >= 0.0)
                .map(|value| value as u64)
        }),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    })
}

fn count(value: &Value, keys: &[&str]) -> usize {
    number(value, keys)
        .map(|count| count.min(usize::MAX as u64) as usize)
        .or_else(|| {
            first_value(value, keys)
                .and_then(Value::as_array)
                .map(Vec::len)
        })
        .unwrap_or(0)
}

/// A lifecycle line's detail, preferring the words a provider chose over its bookkeeping.
fn lifecycle_detail(payload: &Value) -> String {
    optional_detail(payload)
        .or_else(|| {
            let transport = text(payload, &["transport"])?;
            Some(match text(payload, &["maturity"]) {
                Some(maturity) => format!("{transport} · {maturity}"),
                None => transport,
            })
        })
        .unwrap_or_default()
}

/// Human-facing words from a payload, or nothing. Unlike [`detail`] this never falls back
/// to compact JSON: a lifecycle marker with `{}` behind it must read as a marker.
fn optional_detail(payload: &Value) -> Option<String> {
    text(
        payload,
        &["error", "reason", "message", "text", "status", "detail"],
    )
}

/// Milliseconds since the Unix epoch, for an ISO-8601 instant.
///
/// The runtime stamps every event with `DateTime.to_iso8601/1`, which is always UTC with a
/// `Z` suffix; the offset forms are accepted anyway because a timestamp this client cannot
/// read must degrade to "no elapsed time shown", never to a wrong one.
pub fn epoch_millis(timestamp: &str) -> Option<i64> {
    let timestamp = timestamp.trim();
    let (date, rest) = timestamp.split_once(['T', 't', ' '])?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Split the zone off before the clock: `+05:30` and `-08:00` both contain digits and
    // colons that would otherwise read as another field.
    let (clock, offset_minutes) = match rest.char_indices().find(|(at, character)| {
        matches!(character, 'Z' | 'z') || (*at > 0 && matches!(character, '+' | '-'))
    }) {
        Some((at, 'Z' | 'z')) => (&rest[..at], 0),
        Some((at, _)) => (&rest[..at], zone_minutes(&rest[at..])?),
        None => (rest, 0),
    };

    let mut clock = clock.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let seconds = clock.next().unwrap_or("0");
    let (second, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
    let second: i64 = second.parse().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    let millis: i64 = {
        let digits: String = fraction
            .chars()
            .filter(char::is_ascii_digit)
            .take(3)
            .collect();
        let scale = 10i64.pow(3u32.saturating_sub(digits.len() as u32));
        digits.parse::<i64>().unwrap_or(0) * scale
    };

    let days = days_from_civil(year, month, day);
    Some(
        ((days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60) * 1_000)
            + millis,
    )
}

fn zone_minutes(offset: &str) -> Option<i64> {
    let sign = match offset.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let body = &offset[1..];
    let (hours, minutes) = match body.split_once(':') {
        Some((hours, minutes)) => (hours, minutes),
        None if body.len() == 4 => body.split_at(2),
        None => (body, "0"),
    };

    Some(sign * (hours.parse::<i64>().ok()? * 60 + minutes.parse::<i64>().ok()?))
}

/// Howard Hinnant's `days_from_civil`, the standard branch-free proleptic Gregorian
/// conversion. Written out rather than pulled in: one date arithmetic function is not worth
/// a dependency in a client that has no other use for a calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;

    era * 146_097 + day_of_era - 719_468
}

/// The label a gateway wire marker renders as, if this value is one.
///
/// `Ouroboros.Gateway.Wire` replaces leaves it cannot or will not encode with small tagged
/// objects. Rendering those as raw JSON in a transcript is how `{"_opaque":"#PID<0.1.0>"}`
/// ends up looking like tool output; each one gets a short label instead, and the excerpt
/// marker keeps its prefix so the words the provider wrote are still readable.
pub fn wire_marker(value: &Value) -> Option<String> {
    let Value::Object(fields) = value else {
        return None;
    };

    if let Some(prefix) = fields.get("_excerpt").and_then(Value::as_str) {
        let bytes = fields
            .get("_bytes")
            .and_then(Value::as_u64)
            .map(|bytes| format!("{bytes} bytes"))
            .unwrap_or_else(|| "full value".to_string());

        return Some(format!("{prefix}… ({bytes}; full event via /details)"));
    }

    if let Some(opaque) = fields.get("_opaque").and_then(Value::as_str) {
        return Some(format!("[not encodable: {opaque}]"));
    }

    if fields.contains_key("_b64") {
        return Some("[binary value; full event via /details]".to_string());
    }

    if fields
        .get("_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && fields.len() == 1
    {
        return Some("[truncated; full event via /details]".to_string());
    }

    None
}

/// One leaf as text: a plain string, or the label of a wire marker standing in for one.
pub fn leaf_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => nonempty(text),
        other => wire_marker(other),
    }
}

fn first_value<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| value.get(*key))
}

fn string_value<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    first_value(value, keys).and_then(Value::as_str)
}

fn trimmed_string_value<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    string_value(value, keys)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    trimmed_string_value(value, keys)
        .map(|text| bounded_copy(text, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION))
        .or_else(|| first_value(value, keys).and_then(wire_marker))
}

fn raw_text(value: &Value, keys: &[&str]) -> Option<String> {
    string_value(value, keys)
        .filter(|text| !text.is_empty())
        .map(|text| bounded_copy(text, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION))
        .or_else(|| first_value(value, keys).and_then(wire_marker))
}

fn bounded_optional(text: Option<&str>) -> Option<String> {
    text.map(|text| bounded_copy(text, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION))
}

fn error_result(payload: &Value) -> bool {
    payload
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            text(payload, &["status"])
                .map(|status| matches!(status.as_str(), "error" | "failed" | "declined"))
                .unwrap_or(false)
        })
}

fn detail(payload: &Value) -> String {
    text(payload, &["error", "reason", "message", "text"])
        .unwrap_or_else(|| bounded_compact(payload))
}

fn subject(payload: &Value) -> String {
    first_value(payload, &["tool_call", "tool", "command", "text"])
        .map(bounded_compact)
        .filter(|subject| !subject.is_empty() && subject != "null")
        .unwrap_or_else(|| bounded_compact(payload))
}

fn approval_resolution(payload: &Value) -> String {
    let mut parts = Vec::new();

    if let Some(decision) = text(payload, &["decision"]) {
        parts.push(decision);
    }
    if let Some(scope) = text(payload, &["scope"]) {
        parts.push(scope);
    }
    if let Some(reason) = text(payload, &["reason", "message"]) {
        parts.push(reason);
    }

    if parts.is_empty() {
        bounded_compact(payload)
    } else {
        bounded_copy(&parts.join(" · "), PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION)
    }
}

fn file_update(payload: &Value) -> FileUpdate {
    let status = text(payload, &["status"]);
    let changes = payload
        .get("changes")
        .and_then(Value::as_array)
        .map(|changes| {
            let mut projected: Vec<_> = changes
                .iter()
                .filter_map(file_change)
                .take(PRESENTATION_FILE_CHANGES + 1)
                .collect();

            if projected.len() > PRESENTATION_FILE_CHANGES {
                projected.truncate(PRESENTATION_FILE_CHANGES);
                projected.push(FileChange {
                    path: Some("… additional files in event details".into()),
                    kind: None,
                    diff: None,
                });
            }

            projected
        })
        .unwrap_or_else(|| {
            file_change(payload)
                .filter(|change| change.path.is_some() || change.kind.is_some())
                .into_iter()
                .collect()
        });
    let diff = diff_field(payload);

    FileUpdate {
        status,
        changes,
        diff,
    }
}

/// A diff leaf, whether the gateway sent the patch or an excerpt of it.
///
/// An excerpted patch is still a patch worth colouring, but its `+`/`-` counts describe
/// only the prefix — so it is marked truncated, which is what makes the cell say
/// "in excerpt" beside the numbers instead of asserting a diffstat it cannot know.
fn diff_field(payload: &Value) -> Option<Diff> {
    let value = first_value(payload, &["diff", "patch", "delta"])?;

    match value {
        Value::String(text) => {
            let text = text.trim();
            (!text.is_empty()).then(|| Diff::parse(text))
        }
        other => {
            let excerpt = wire_marker(other)?;
            let mut diff = Diff::parse(&excerpt);
            diff.truncated = true;
            Some(diff)
        }
    }
}

fn file_change(value: &Value) -> Option<FileChange> {
    match value {
        Value::String(path) if !path.trim().is_empty() => Some(FileChange {
            path: Some(bounded_copy(
                path.trim(),
                PRESENTATION_TEXT_BYTES,
                TEXT_TRUNCATION,
            )),
            kind: None,
            diff: None,
        }),
        Value::Object(_) => {
            let path = text(value, &["path", "file", "name", "file_path"]);
            let kind = text(value, &["kind", "action", "change_type", "type", "status"]);
            let diff = diff_field(value);

            (path.is_some() || kind.is_some() || diff.is_some()).then_some(FileChange {
                path,
                kind,
                diff,
            })
        }
        _ => None,
    }
}

impl Diff {
    pub fn parse(text: &str) -> Self {
        // Bound the owned presentation copy before scanning it. Re-projecting a transcript on
        // every draw must not repeatedly walk a multi-megabyte raw patch; the complete patch is
        // still present on the source Event and in event details.
        let truncated = text.len() > PRESENTATION_DIFF_BYTES;
        let text = bounded_copy(text, PRESENTATION_DIFF_BYTES, DIFF_TRUNCATION);
        let mut path = None;
        let mut additions = 0;
        let mut deletions = 0;

        for line in text.lines() {
            if let Some((_before, after)) = line
                .strip_prefix("diff --git a/")
                .and_then(|line| line.split_once(" b/"))
            {
                path.get_or_insert_with(|| {
                    bounded_copy(after, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION)
                });
            } else if let Some(after) = line.strip_prefix("+++ b/") {
                path.get_or_insert_with(|| {
                    bounded_copy(after, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION)
                });
            }

            if line.starts_with('+') && !line.starts_with("+++") {
                additions += 1;
            } else if line.starts_with('-') && !line.starts_with("---") {
                deletions += 1;
            }
        }

        Self {
            text,
            path,
            additions,
            deletions,
            truncated,
        }
    }
}

fn bounded_compact(value: &Value) -> String {
    let value = bounded_value(value);
    bounded_copy(&compact(&value), PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION)
}

fn bounded_copy(text: &str, limit: usize, marker: &str) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }

    if limit == 0 {
        return String::new();
    }

    let marker = if marker.len() <= limit {
        marker
    } else if "…".len() <= limit {
        "…"
    } else {
        ""
    };
    let mut end = limit.saturating_sub(marker.len()).min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut bounded = String::with_capacity(end + marker.len());
    bounded.push_str(&text[..end]);
    bounded.push_str(marker);
    bounded
}

fn bounded_value(value: &Value) -> Value {
    let mut budget = ValueBudget {
        bytes: PRESENTATION_VALUE_BYTES,
        nodes: PRESENTATION_VALUE_NODES,
    };

    clone_value(value, &mut budget, 0).unwrap_or_else(truncated_value)
}

#[derive(Debug)]
struct ValueBudget {
    bytes: usize,
    nodes: usize,
}

impl ValueBudget {
    fn take_node(&mut self) -> bool {
        if self.nodes == 0 {
            false
        } else {
            self.nodes -= 1;
            true
        }
    }

    fn take_key(&mut self, key: &str) -> bool {
        if key.len() > self.bytes {
            false
        } else {
            self.bytes -= key.len();
            true
        }
    }

    fn take_string(&mut self, text: &str) -> String {
        if text.len() <= self.bytes {
            self.bytes -= text.len();
            return text.to_owned();
        }

        let available = std::mem::take(&mut self.bytes);
        bounded_copy(text, available, TEXT_TRUNCATION)
    }

    fn exhausted(&self) -> bool {
        self.bytes == 0 || self.nodes == 0
    }
}

fn clone_value(value: &Value, budget: &mut ValueBudget, depth: usize) -> Option<Value> {
    if depth >= PRESENTATION_VALUE_DEPTH || !budget.take_node() {
        return None;
    }

    Some(match value {
        Value::Null => Value::Null,
        Value::Bool(value) => Value::Bool(*value),
        Value::Number(value) => Value::Number(value.clone()),
        Value::String(value) => Value::String(budget.take_string(value)),
        Value::Array(values) => {
            let mut projected = Vec::with_capacity(values.len().min(PRESENTATION_VALUE_NODES));
            for value in values {
                if budget.exhausted() {
                    projected.push(truncated_value());
                    break;
                }

                match clone_value(value, budget, depth + 1) {
                    Some(value) => projected.push(value),
                    None => {
                        projected.push(truncated_value());
                        break;
                    }
                }
            }
            Value::Array(projected)
        }
        Value::Object(values) => {
            let mut projected = Map::new();

            // Keep the fields transcript renderers understand even when a provider also
            // includes a large amount of opaque metadata before them.
            for key in [
                "text", "content", "cmd", "command", "path", "file", "query", "pattern", "url",
                "error", "message", "reason",
            ] {
                let Some(value) = values.get(key) else {
                    continue;
                };
                if !clone_field(&mut projected, key, value, budget, depth) {
                    insert_truncation(&mut projected);
                    return Some(Value::Object(projected));
                }
            }

            for (key, value) in values {
                if projected.contains_key(key) {
                    continue;
                }
                if !clone_field(&mut projected, key, value, budget, depth) {
                    insert_truncation(&mut projected);
                    break;
                }
            }
            Value::Object(projected)
        }
    })
}

fn clone_field(
    projected: &mut Map<String, Value>,
    key: &str,
    value: &Value,
    budget: &mut ValueBudget,
    depth: usize,
) -> bool {
    if budget.exhausted() || !budget.take_key(key) {
        return false;
    }

    let Some(value) = clone_value(value, budget, depth + 1) else {
        return false;
    };
    projected.insert(key.to_owned(), value);
    true
}

fn truncated_value() -> Value {
    let mut marker = Map::new();
    marker.insert("_truncated".into(), Value::Bool(true));
    Value::Object(marker)
}

fn insert_truncation(projected: &mut Map<String, Value>) {
    if !projected.contains_key("_truncated") {
        projected.insert("_truncated".into(), Value::Bool(true));
    } else {
        projected.insert("_transcript_truncated".into(), Value::Bool(true));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn event(kind: &str, payload: Value) -> Event {
        Event::decode(&json!({
            "id": "evt-1",
            "sequence": 1,
            "type": kind,
            "timestamp": "2026-08-14T00:00:00Z",
            "turn_id": "turn-1",
            "payload": payload
        }))
        .expect("an event")
    }

    #[test]
    fn parses_the_normalized_tool_contract_without_provider_fields() {
        let call = event(
            "tool_call",
            json!({
                "call_id": "call-7",
                "name": "read",
                "input": {"path": "lib/ouroboros.ex"}
            }),
        );
        let result = event(
            "tool_result",
            json!({
                "call_id": "call-7",
                "output": {"text": "defmodule Ouroboros"},
                "is_error": false
            }),
        );

        assert_eq!(
            PresentationEvent::from_event(&call),
            PresentationEvent::ToolCall(ToolCall {
                call_id: Some("call-7".into()),
                name: "read".into(),
                input: json!({"path": "lib/ouroboros.ex"}),
            })
        );
        assert_eq!(
            PresentationEvent::from_event(&result),
            PresentationEvent::ToolResult(ToolResult {
                call_id: Some("call-7".into()),
                name: None,
                output: json!({"text": "defmodule Ouroboros"}),
                is_error: false,
            })
        );
    }

    #[test]
    fn tolerates_acp_camel_case_tool_updates_without_leaking_protocol_into_the_renderer() {
        let call = event(
            "tool_call",
            json!({
                "sessionUpdate": "tool_call",
                "toolCallId": "tool-7",
                "title": "Read workspace file",
                "rawInput": {"path": "README.md"}
            }),
        );
        let result = event(
            "tool_result",
            json!({
                "sessionUpdate": "tool_call_update",
                "toolCallId": "tool-7",
                "status": "completed",
                "rawOutput": {"text": "project docs"}
            }),
        );

        assert_eq!(
            PresentationEvent::from_event(&call),
            PresentationEvent::ToolCall(ToolCall {
                call_id: Some("tool-7".into()),
                name: "Read workspace file".into(),
                input: json!({"path": "README.md"}),
            })
        );
        assert_eq!(
            PresentationEvent::from_event(&result),
            PresentationEvent::ToolResult(ToolResult {
                call_id: Some("tool-7".into()),
                name: None,
                output: json!({"text": "project docs"}),
                is_error: false,
            })
        );
    }

    #[test]
    fn parses_file_lists_and_diff_metadata_without_treating_them_as_authority() {
        let event = event(
            "file_change",
            json!({
                "status": "completed",
                "changes": [
                    {"path": "lib/a.ex", "kind": "modified"},
                    {"path": "test/a_test.exs", "kind": "added"}
                ],
                "diff": "diff --git a/lib/a.ex b/lib/a.ex\n--- a/lib/a.ex\n+++ b/lib/a.ex\n@@ -1 +1,2 @@\n-old\n+new\n+line"
            }),
        );

        let PresentationEvent::FileUpdate(update) = PresentationEvent::from_event(&event) else {
            panic!("expected a file update")
        };

        assert_eq!(update.changes.len(), 2);
        assert_eq!(update.changes[0].path.as_deref(), Some("lib/a.ex"));
        let diff = update.diff.expect("a diff");
        assert_eq!(diff.path.as_deref(), Some("lib/a.ex"));
        assert_eq!((diff.additions, diff.deletions), (2, 1));
    }

    /// Checkpointed events written before the runtime carried the text, and every recovered
    /// turn, arrive without one. Dropping them deleted real turns from the chat.
    #[test]
    fn an_accepted_input_without_text_is_named_rather_than_dropped() {
        assert_eq!(
            PresentationEvent::from_event(&event("input_accepted", json!({"kind": "message"}))),
            PresentationEvent::UnrecordedInput
        );

        // No `kind` either — an older event that says only that something was accepted.
        assert_eq!(
            PresentationEvent::from_event(&event("input_accepted", json!({}))),
            PresentationEvent::UnrecordedInput
        );

        assert_eq!(
            PresentationEvent::from_event(&event("input_accepted", json!({"kind": "steer"}))),
            PresentationEvent::UserSteer(None)
        );
    }

    #[test]
    fn a_steer_carries_its_text_once_the_runtime_sends_one() {
        assert_eq!(
            PresentationEvent::from_event(&event(
                "input_accepted",
                json!({"kind": "steer", "text": "stop and run the tests first"})
            )),
            PresentationEvent::UserSteer(Some("stop and run the tests first".into()))
        );

        // An ordinary message is still an ordinary message.
        assert_eq!(
            PresentationEvent::from_event(&event(
                "input_accepted",
                json!({"kind": "message", "text": "fix the flaky test"})
            )),
            PresentationEvent::UserMessage("fix the flaky test".into())
        );
    }

    /// Was `unknown_payload_shapes_remain_ignorable_presentation_data`, which pinned the
    /// `Ignore` arm this projection no longer has. A payload nobody modelled is still an
    /// event the runtime recorded, so it reads as one dim line naming itself.
    #[test]
    fn unknown_payload_shapes_are_named_rather_than_dropped() {
        let event = event("provider_event", json!({"future": {"shape": true}}));
        assert_eq!(
            PresentationEvent::from_event(&event),
            PresentationEvent::ProviderNote {
                kind: String::new(),
                detail: String::new(),
            }
        );
        assert_eq!(event.raw["payload"]["future"]["shape"], true);
    }

    #[test]
    fn bounds_multi_megabyte_tool_values_without_touching_the_source_event() {
        let source = "界".repeat(1024 * 1024);
        let source_bytes = source.len();
        assert!(source_bytes > 2 * 1024 * 1024);
        let event = event("tool_result", json!({"output": {"text": source}}));

        let PresentationEvent::ToolResult(result) = PresentationEvent::from_event(&event) else {
            panic!("expected a tool result")
        };
        let projected = result.output["text"].as_str().expect("projected text");

        assert!(projected.len() <= PRESENTATION_VALUE_BYTES);
        assert!(projected.contains("transcript excerpt truncated"));
        assert_eq!(
            event.payload["output"]["text"]
                .as_str()
                .expect("source payload")
                .len(),
            source_bytes
        );
        assert_eq!(
            event.raw["payload"]["output"]["text"]
                .as_str()
                .expect("raw event")
                .len(),
            source_bytes
        );
    }

    #[test]
    fn bounds_a_multi_megabyte_diff_before_copying_or_counting_it() {
        let patch = format!(
            "diff --git a/huge.txt b/huge.txt\n--- a/huge.txt\n+++ b/huge.txt\n@@ -1 +1 @@\n-old\n+{}",
            "x".repeat(3 * 1024 * 1024)
        );
        let source_bytes = patch.len();
        let event = event("file_change", json!({"diff": patch}));

        let PresentationEvent::FileUpdate(update) = PresentationEvent::from_event(&event) else {
            panic!("expected a file update")
        };
        let diff = update.diff.expect("projected diff");

        assert!(diff.text.len() <= PRESENTATION_DIFF_BYTES);
        assert!(diff.text.contains("diff truncated"));
        assert!(diff.truncated);
        assert_eq!(diff.path.as_deref(), Some("huge.txt"));
        assert_eq!((diff.additions, diff.deletions), (1, 1));
        assert_eq!(
            event.payload["diff"].as_str().expect("source patch").len(),
            source_bytes
        );
        assert_eq!(
            event.raw["payload"]["diff"]
                .as_str()
                .expect("raw patch")
                .len(),
            source_bytes
        );
    }

    #[test]
    fn caps_large_file_lists_in_the_presentation_projection() {
        let changes: Vec<_> = (0..(PRESENTATION_FILE_CHANGES + 100))
            .map(|index| json!({"path": format!("file-{index}.txt"), "kind": "modified"}))
            .collect();
        let event = event("file_change", json!({"changes": changes}));

        let PresentationEvent::FileUpdate(update) = PresentationEvent::from_event(&event) else {
            panic!("expected a file update")
        };

        assert_eq!(update.changes.len(), PRESENTATION_FILE_CHANGES + 1);
        assert_eq!(
            update
                .changes
                .last()
                .and_then(|change| change.path.as_deref()),
            Some("… additional files in event details")
        );
        assert_eq!(
            event.payload["changes"]
                .as_array()
                .expect("complete source list")
                .len(),
            PRESENTATION_FILE_CHANGES + 100
        );
    }

    #[test]
    fn approval_events_keep_the_correlation_and_resolution() {
        let requested = Event::decode(&json!({
            "id": "evt-1",
            "sequence": 1,
            "type": "approval_requested",
            "timestamp": "2026-08-14T00:00:00Z",
            "request_id": "req-1",
            "payload": {"tool_call": {"name": "bash", "command": "git status"}}
        }))
        .expect("a request");
        let resolved = Event::decode(&json!({
            "id": "evt-2",
            "sequence": 2,
            "type": "approval_resolved",
            "timestamp": "2026-08-14T00:00:01Z",
            "request_id": "req-1",
            "payload": {"decision": "approve", "scope": "once"}
        }))
        .expect("a resolution");

        assert!(matches!(
            PresentationEvent::from_event(&requested),
            PresentationEvent::ApprovalRequested {
                request_id: Some(request_id),
                detail
            } if request_id == "req-1" && detail.contains("git status")
        ));
        assert_eq!(
            PresentationEvent::from_event(&resolved),
            PresentationEvent::ApprovalResolved {
                request_id: Some("req-1".into()),
                decision: Some("approve".into()),
                detail: "approve · once".into(),
            }
        );
    }

    /// One representative payload per normalized kind, asserting that it presents. The list
    /// is the twenty-nine `EventType` variants plus the `Other` arm; a kind added to the
    /// model without a presentation fails here and in the compiler.
    #[test]
    fn every_normalized_kind_has_a_presentation_and_none_is_dropped() {
        let cases: Vec<(&str, Value)> = vec![
            (
                "run_started",
                json!({"model": "sonnet-5", "tools": ["read"]}),
            ),
            ("run_completed", json!({"num_turns": 3})),
            ("run_failed", json!({"error": "the provider exited"})),
            ("run_cancelled", json!({"reason": "cancelled"})),
            ("session_started", json!({})),
            ("session_ready", json!({"transport": "acp"})),
            ("session_idle", json!({})),
            ("session_closed", json!({"reason": "closed"})),
            ("session_failed", json!({"error": "transport died"})),
            ("session_cancelled", json!({"reason": "cancelled"})),
            ("input_accepted", json!({"kind": "message", "text": "hi"})),
            ("turn_queued", json!({})),
            ("turn_started", json!({})),
            ("output_text_delta", json!({"text": "part"})),
            ("output_text_final", json!({"text": "answer"})),
            ("thinking_delta", json!({"text": "considering"})),
            ("command_output_delta", json!({"text": "building"})),
            ("tool_call", json!({"call_id": "c1", "name": "read"})),
            ("tool_result", json!({"call_id": "c1", "output": "ok"})),
            ("file_change", json!({"changes": [{"path": "a.ex"}]})),
            (
                "plan_updated",
                json!({"plan": [{"step": "write the test", "status": "pending"}]}),
            ),
            ("usage", json!({"input_tokens": 10, "output_tokens": 5})),
            ("turn_completed", json!({})),
            ("turn_failed", json!({"error": "boom"})),
            ("turn_interrupted", json!({"reason": "esc"})),
            ("approval_requested", json!({"command": "git status"})),
            ("approval_resolved", json!({"decision": "approve"})),
            ("queue_changed", json!({"queued_turns": 2})),
            ("provider_event", json!({"kind": "acp_update"})),
            ("a_kind_from_a_newer_harness", json!({"text": "something"})),
        ];

        assert_eq!(cases.len(), 30, "29 normalized kinds plus the unknown arm");

        for (kind, payload) in cases {
            let projected = PresentationEvent::from_event(&event(kind, payload));

            assert!(
                !matches!(projected, PresentationEvent::Hidden(_)),
                "{kind} maps to a silent drop: {projected:?}"
            );
        }
    }

    /// The only hides are payloads that carried nothing, and each says which.
    #[test]
    fn an_empty_payload_hides_with_a_stated_reason_rather_than_by_default() {
        for (kind, hidden) in [
            ("output_text_final", Hidden::EmptyText),
            ("thinking_delta", Hidden::EmptyThinking),
            ("command_output_delta", Hidden::EmptyCommandOutput),
        ] {
            assert_eq!(
                PresentationEvent::from_event(&event(kind, json!({"text": ""}))),
                PresentationEvent::Hidden(hidden),
                "{kind}"
            );
            assert!(!hidden.reason().is_empty());
        }
    }

    #[test]
    fn a_turn_boundary_carries_the_timestamp_the_divider_measures_elapsed_time_from() {
        let started = Event::decode(&json!({
            "id": "evt-1",
            "sequence": 1,
            "type": "turn_started",
            "timestamp": "2026-08-14T00:00:00.000000Z",
            "turn_id": "turn-1",
            "payload": {}
        }))
        .expect("a turn start");
        let completed = Event::decode(&json!({
            "id": "evt-2",
            "sequence": 2,
            "type": "turn_completed",
            "timestamp": "2026-08-14T00:04:07.500000Z",
            "turn_id": "turn-1",
            "payload": {}
        }))
        .expect("a turn end");

        let PresentationEvent::TurnStarted {
            at: Some(start), ..
        } = PresentationEvent::from_event(&started)
        else {
            panic!("expected a turn start with an instant")
        };
        let PresentationEvent::TurnEnded {
            at: Some(end),
            outcome,
            ..
        } = PresentationEvent::from_event(&completed)
        else {
            panic!("expected a turn end with an instant")
        };

        assert_eq!(outcome, TurnOutcome::Completed);
        assert_eq!(end - start, 247_500);
    }

    #[test]
    fn iso_timestamps_parse_and_an_unreadable_one_yields_no_elapsed_time() {
        assert_eq!(epoch_millis("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(epoch_millis("1970-01-01T00:00:00.250Z"), Some(250));
        assert_eq!(
            epoch_millis("2026-01-01T00:00:00.000000Z"),
            Some(1_767_225_600_000)
        );
        // A leap day, and a non-UTC offset that names the same instant as its UTC form.
        assert_eq!(
            epoch_millis("2024-02-29T12:00:00Z"),
            Some(1_709_208_000_000)
        );
        assert_eq!(
            epoch_millis("2026-01-01T05:30:00+05:30"),
            epoch_millis("2026-01-01T00:00:00Z")
        );
        assert_eq!(epoch_millis(""), None);
        assert_eq!(epoch_millis("not a timestamp"), None);
        assert_eq!(epoch_millis("2026-13-01T00:00:00Z"), None);
    }

    /// Codex sends `{"explanation", "plan": [{"step", "status"}]}`; ACP forwards its `plan`
    /// session update, whose entries are `{"content", "priority", "status"}`. Both are the
    /// same plan to a reader, so both project to the same steps.
    #[test]
    fn both_plan_dialects_project_to_the_same_steps() {
        let codex = event(
            "plan_updated",
            json!({
                "explanation": "three steps",
                "plan": [
                    {"step": "read the failing test", "status": "completed"},
                    {"step": "fix the projection", "status": "in_progress"},
                    {"step": "run the suite", "status": "pending"}
                ]
            }),
        );
        let acp = event(
            "plan_updated",
            json!({
                "sessionUpdate": "plan",
                "entries": [
                    {"content": "read the failing test", "priority": "high", "status": "completed"},
                    {"content": "fix the projection", "priority": "high", "status": "in_progress"},
                    {"content": "run the suite", "priority": "medium", "status": "pending"}
                ]
            }),
        );

        for (dialect, source) in [("codex", codex), ("acp", acp)] {
            let PresentationEvent::Plan(plan) = PresentationEvent::from_event(&source) else {
                panic!("{dialect}: expected a plan")
            };

            assert_eq!(plan.step_count, 3, "{dialect}");
            assert_eq!(
                plan.steps
                    .iter()
                    .map(|step| step.text.as_str())
                    .collect::<Vec<_>>(),
                [
                    "read the failing test",
                    "fix the projection",
                    "run the suite"
                ],
                "{dialect}"
            );
            assert_eq!(
                plan.steps
                    .iter()
                    .map(|step| step.status.glyph())
                    .collect::<Vec<_>>(),
                ["\u{2713}", "\u{25cf}", "\u{25cc}"],
                "{dialect}"
            );
        }
    }

    /// A status nobody modelled keeps the provider's own word. Reading "awaiting_review" as
    /// "done" would report finished work that never happened.
    #[test]
    fn an_unknown_plan_status_is_kept_verbatim_rather_than_guessed() {
        let plan = event(
            "plan_updated",
            json!({"plan": [{"step": "verify", "status": "awaiting_review"}]}),
        );

        let PresentationEvent::Plan(plan) = PresentationEvent::from_event(&plan) else {
            panic!("expected a plan")
        };

        assert_eq!(
            plan.steps[0].status,
            PlanStatus::Other("awaiting_review".into())
        );
        assert_eq!(plan.steps[0].status.glyph(), "?");
    }

    #[test]
    fn a_plan_longer_than_the_projection_ceiling_says_how_many_it_left_out() {
        let steps: Vec<_> = (0..(PRESENTATION_PLAN_STEPS + 10))
            .map(|index| json!({"step": format!("step {index}"), "status": "pending"}))
            .collect();
        let plan = event("plan_updated", json!({"plan": steps}));

        let PresentationEvent::Plan(plan) = PresentationEvent::from_event(&plan) else {
            panic!("expected a plan")
        };

        assert_eq!(plan.steps.len(), PRESENTATION_PLAN_STEPS);
        assert_eq!(plan.step_count, PRESENTATION_PLAN_STEPS + 10);
    }

    #[test]
    fn usage_reports_only_the_numbers_the_provider_sent() {
        let PresentationEvent::Usage(usage) = PresentationEvent::from_event(&event(
            "usage",
            json!({"input_tokens": 21088, "output_tokens": 512, "total_tokens": 21600}),
        )) else {
            panic!("expected usage")
        };

        assert_eq!(usage.input_tokens, Some(21_088));
        assert_eq!(usage.output_tokens, Some(512));
        assert_eq!(usage.total_tokens, Some(21_600));
        assert_eq!(
            usage.cached_tokens, None,
            "an unreported field stays absent"
        );
        assert_eq!(usage.cost_usd, None);
    }

    #[test]
    fn run_started_carries_the_model_and_tool_count_the_header_states() {
        let PresentationEvent::RunStarted(run) = PresentationEvent::from_event(&event(
            "run_started",
            json!({
                "cwd": "/srv/project",
                "model": "claude-sonnet-5",
                "tools": ["Read", "Edit", "Bash"]
            }),
        )) else {
            panic!("expected a run start")
        };

        assert_eq!(run.model.as_deref(), Some("claude-sonnet-5"));
        assert_eq!(run.tool_count, 3);
        assert_eq!(run.tools, ["Read", "Edit", "Bash"]);
        assert_eq!(run.cwd.as_deref(), Some("/srv/project"));
    }

    /// An ACP escape-hatch event names the update type it wrapped, so "something happened
    /// and this build does not model it" is still a line a reader can act on.
    #[test]
    fn a_provider_event_names_its_own_kind() {
        assert_eq!(
            PresentationEvent::from_event(&event(
                "provider_event",
                json!({"kind": "acp_update", "update": {"sessionUpdate": "current_mode_update"}})
            )),
            PresentationEvent::ProviderNote {
                kind: "acp_update \u{b7} current_mode_update".into(),
                detail: String::new(),
            }
        );
    }

    /// `Ouroboros.Gateway.Wire` replaces leaves it excerpts, cannot encode, or cut off with
    /// small tagged objects. None of them may reach a transcript as JSON.
    #[test]
    fn wire_markers_render_as_labels_and_an_excerpt_keeps_its_prefix() {
        assert_eq!(
            wire_marker(&json!({"_excerpt": "the first bytes", "_bytes": 4096})).as_deref(),
            Some("the first bytes\u{2026} (4096 bytes; full event via /details)")
        );
        assert_eq!(
            wire_marker(&json!({"_excerpt": "no size given"})).as_deref(),
            Some("no size given\u{2026} (full value; full event via /details)")
        );
        assert_eq!(
            wire_marker(&json!({"_opaque": "#PID<0.101.0>"})).as_deref(),
            Some("[not encodable: #PID<0.101.0>]")
        );
        assert_eq!(
            wire_marker(&json!({"_b64": "3q2+7w=="})).as_deref(),
            Some("[binary value; full event via /details]")
        );
        assert_eq!(
            wire_marker(&json!({"_truncated": true})).as_deref(),
            Some("[truncated; full event via /details]")
        );
        assert_eq!(wire_marker(&json!({"text": "ordinary"})), None);
        assert_eq!(wire_marker(&json!("ordinary")), None);
    }

    #[test]
    fn an_excerpted_text_leaf_reads_as_its_prefix_and_an_excerpted_diff_is_marked() {
        let message = PresentationEvent::from_event(&event(
            "output_text_final",
            json!({"text": {"_excerpt": "The tests are", "_bytes": 90_000}}),
        ));

        assert!(
            matches!(message, PresentationEvent::AgentText { ref text, .. }
                if text == "The tests are\u{2026} (90000 bytes; full event via /details)"),
            "{message:?}"
        );

        let PresentationEvent::FileUpdate(update) = PresentationEvent::from_event(&event(
            "file_change",
            json!({"diff": {"_excerpt": "--- a/lib/a.ex\n+++ b/lib/a.ex\n+new", "_bytes": 2_000_000}}),
        )) else {
            panic!("expected a file update")
        };
        let diff = update.diff.expect("an excerpted diff is still a diff");

        assert!(diff.text.contains("2000000 bytes"), "{}", diff.text);
        assert!(
            diff.truncated,
            "counts taken from an excerpt must be labelled as an excerpt"
        );
        assert_eq!(diff.path.as_deref(), Some("lib/a.ex"));
    }
}
