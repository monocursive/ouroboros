//! Runtime-authored semantic records. No provider aliases belong in this decoder.
use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "kind", content = "data")]
enum Semantic {
    AgentText {
        turn_id: Option<String>,
        text: String,
        final_text: bool,
    },
    Thinking {
        turn_id: Option<String>,
        text: String,
    },
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    UsageReport(UsageReport),
    ApprovalRequested {
        request_id: Option<String>,
        detail: String,
    },
    ApprovalResolved {
        request_id: Option<String>,
        decision: Option<String>,
        detail: String,
    },
    TurnStarted {
        turn_id: Option<String>,
        at: Option<i64>,
    },
    TurnEnded {
        turn_id: Option<String>,
        at: Option<i64>,
        outcome: TurnOutcome,
        detail: String,
    },
    UserMessage {
        text: String,
    },
    UserSteer {
        text: Option<String>,
    },
    CommandOutput {
        text: String,
    },
    Failure {
        detail: String,
    },
    Interrupted {
        detail: String,
    },
    Hidden {
        reason: Hidden,
    },
}

pub(super) fn decode(event: &Event) -> Option<PresentationEvent> {
    let value = event.raw.get("semantic")?;
    if value.get("version")?.as_u64()? != 1 {
        return None;
    }
    // Invalid or newer records retain the visible legacy/unknown-event fallback.
    let semantic: Semantic = serde_json::from_value(value.clone()).ok()?;
    Some(match semantic {
        Semantic::AgentText {
            turn_id,
            text,
            final_text,
        } => PresentationEvent::AgentText {
            turn_id,
            text,
            final_text,
        },
        Semantic::Thinking { turn_id, text } => PresentationEvent::Thinking { turn_id, text },
        Semantic::ToolCall(call) => PresentationEvent::ToolCall(call),
        Semantic::ToolResult(result) => PresentationEvent::ToolResult(result),
        Semantic::UsageReport(usage) => PresentationEvent::Usage(usage),
        Semantic::ApprovalRequested { request_id, detail } => {
            PresentationEvent::ApprovalRequested { request_id, detail }
        }
        Semantic::ApprovalResolved {
            request_id,
            decision,
            detail,
        } => PresentationEvent::ApprovalResolved {
            request_id,
            decision,
            detail,
        },
        Semantic::TurnStarted { turn_id, at } => PresentationEvent::TurnStarted { turn_id, at },
        Semantic::TurnEnded {
            turn_id,
            at,
            outcome,
            detail,
        } => PresentationEvent::TurnEnded {
            turn_id,
            at,
            outcome,
            detail,
        },
        Semantic::UserMessage { text } => PresentationEvent::UserMessage(text),
        Semantic::UserSteer { text } => PresentationEvent::UserSteer(text),
        Semantic::CommandOutput { text } => PresentationEvent::CommandOutput(text),
        Semantic::Failure { detail } => PresentationEvent::Failure(detail),
        Semantic::Interrupted { detail } => PresentationEvent::Interrupted(detail),
        Semantic::Hidden { reason } => PresentationEvent::Hidden(reason),
    })
}
