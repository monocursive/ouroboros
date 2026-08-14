//! A tolerant, presentation-only reading of normalized Harness events.
//!
//! The durable event and its raw payload remain the source of truth. These types name only
//! the fields a transcript can lay out usefully; missing or newer shapes fall back to the
//! complete event-details view instead of becoming client-side state or policy.

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
const TEXT_TRUNCATION: &str =
    "\n… transcript excerpt truncated; full value is available in event details";
const DIFF_TRUNCATION: &str = "\n… diff truncated; full diff is available in event details";

#[derive(Debug, Clone, PartialEq)]
pub enum PresentationEvent {
    UserMessage(String),
    AgentText {
        turn_id: Option<String>,
        text: String,
        final_text: bool,
    },
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    CommandOutput(String),
    FileUpdate(FileUpdate),
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
    Ignore,
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
    pub fn from_event(event: &Event) -> Self {
        match event.kind {
            EventType::InputAccepted => raw_text(&event.payload, &["text"])
                .filter(|text| !text.trim().is_empty())
                .map(Self::UserMessage)
                .unwrap_or(Self::Ignore),
            EventType::OutputTextDelta | EventType::OutputTextFinal => {
                let Some(text) = raw_text(&event.payload, &["text"]) else {
                    return Self::Ignore;
                };

                Self::AgentText {
                    turn_id: bounded_optional(event.turn_id.as_deref()),
                    text,
                    final_text: event.kind == EventType::OutputTextFinal,
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
                .unwrap_or(Self::Ignore),
            EventType::FileChange => Self::FileUpdate(file_update(&event.payload)),
            EventType::ApprovalRequested => Self::ApprovalRequested {
                request_id: bounded_optional(event.request_id.as_deref()),
                detail: subject(&event.payload),
            },
            EventType::ApprovalResolved => Self::ApprovalResolved {
                request_id: bounded_optional(event.request_id.as_deref()),
                decision: text(&event.payload, &["decision"]),
                detail: approval_resolution(&event.payload),
            },
            EventType::RunFailed | EventType::SessionFailed | EventType::TurnFailed => {
                Self::Failure(detail(&event.payload))
            }
            EventType::RunCancelled | EventType::SessionCancelled | EventType::TurnInterrupted => {
                Self::Interrupted(detail(&event.payload))
            }
            _ => Self::Ignore,
        }
    }
}

fn empty_object() -> Value {
    Value::Object(Default::default())
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
}

fn raw_text(value: &Value, keys: &[&str]) -> Option<String> {
    string_value(value, keys)
        .filter(|text| !text.is_empty())
        .map(|text| bounded_copy(text, PRESENTATION_TEXT_BYTES, TEXT_TRUNCATION))
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
    let diff = trimmed_string_value(payload, &["diff", "patch", "delta"]).map(Diff::parse);

    FileUpdate {
        status,
        changes,
        diff,
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
            let diff = trimmed_string_value(value, &["diff", "patch", "delta"]).map(Diff::parse);

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

    #[test]
    fn unknown_payload_shapes_remain_ignorable_presentation_data() {
        let event = event("provider_event", json!({"future": {"shape": true}}));
        assert_eq!(
            PresentationEvent::from_event(&event),
            PresentationEvent::Ignore
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
}
