//! Semantic controls and immutable projections for non-terminal clients.
//!
//! The TUI and native desktop have different input and layout primitives, but they must
//! not have different meanings for "send", "approve", session triage, or transcript
//! replay. These methods are the narrow bridge: native widgets express an operator's
//! intent here, and render cloned presentation data from the same reducer the TUI drives.

use super::*;
use crate::model::transcript::PlanStatus;
use crate::ui::transcript_cells::{self, Cell, Speaker, ThinkingState, Tone, ToolState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopTone {
    Neutral,
    Muted,
    Accent,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopCellKind {
    Message,
    Thinking,
    Plan,
    Tool,
    File,
    Diff,
    Runtime,
    Status,
    Divider,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopCell {
    pub kind: DesktopCellKind,
    pub label: String,
    pub body: String,
    pub tone: DesktopTone,
    pub streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSession {
    pub plane: Plane,
    pub id: String,
    pub status: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub triage: Triage,
    pub depth: usize,
    pub selected: bool,
    pub pending_approvals: usize,
    pub last_known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopApprovalChoice {
    pub label: String,
    pub decision: Option<ApprovalDecision>,
    pub scope: Option<ApprovalScope>,
    pub plan: Option<PlanChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopApproval {
    pub plane: Plane,
    pub session_id: String,
    pub request_id: String,
    pub subject: String,
    pub kind: Option<String>,
    pub title: Option<String>,
    pub reason: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub locations: Vec<String>,
    pub suggested_rule: Option<String>,
    pub diff: Option<DesktopApprovalDiff>,
    pub edits: Vec<String>,
    pub choices: Vec<DesktopApprovalChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopApprovalDiff {
    pub label: String,
    pub text: String,
}

impl App {
    /// Rows for a native rail, preserving the TUI's attention-first ordering and nesting.
    pub fn desktop_sessions(&self) -> Vec<DesktopSession> {
        self.sessions
            .triaged()
            .into_iter()
            .map(|row| {
                let key = (row.session.plane, row.session.id.clone());
                DesktopSession {
                    plane: row.session.plane,
                    id: row.session.id.clone(),
                    status: row.session.status.as_str().to_string(),
                    provider: row.session.provider.clone(),
                    model: row.session.model.clone(),
                    workspace: row.session.workspace.clone(),
                    triage: row.group,
                    depth: row.depth,
                    selected: self.sessions.open.as_ref() == Some(&key),
                    pending_approvals: self
                        .sessions
                        .watches
                        .get(&key)
                        .map(|watch| watch.pending_approvals.len())
                        .unwrap_or(0),
                    last_known: row.session.last_known,
                }
            })
            .collect()
    }

    /// A bounded conversation projection for a native transcript.
    pub fn desktop_transcript(&self) -> Vec<DesktopCell> {
        let Some(watch) = self.sessions.open_watch() else {
            return Vec::new();
        };

        transcript_cells::project(
            watch
                .recent_entries(transcript_cells::CHAT_ENTRY_WINDOW)
                .entries,
        )
        .into_iter()
        .map(desktop_cell)
        .collect()
    }

    /// The oldest unanswered approval for the open session.
    pub fn desktop_approval(&self) -> Option<DesktopApproval> {
        let (plane, id) = self.sessions.open.as_ref()?;
        let request = self.sessions.open_watch()?.next_approval()?;
        let detail = request.detail();

        let choices = if let Some(plan) = detail.plan.as_ref() {
            plan.choices
                .iter()
                .map(|choice| DesktopApprovalChoice {
                    label: choice.name.clone(),
                    decision: None,
                    scope: None,
                    plan: Some(choice.choice),
                })
                .collect()
        } else if !detail.options.is_empty() {
            detail
                .options
                .iter()
                .map(|choice| {
                    let mapped = choice.decision();
                    DesktopApprovalChoice {
                        label: choice.name.clone(),
                        decision: mapped.map(|answer| answer.0),
                        scope: mapped.map(|answer| answer.1),
                        plan: None,
                    }
                })
                .collect()
        } else {
            [
                ("Allow once", ApprovalDecision::Approve, ApprovalScope::Once),
                (
                    "Allow for session",
                    ApprovalDecision::Approve,
                    ApprovalScope::Session,
                ),
                ("Deny once", ApprovalDecision::Deny, ApprovalScope::Once),
                (
                    "Deny for session",
                    ApprovalDecision::Deny,
                    ApprovalScope::Session,
                ),
            ]
            .into_iter()
            .map(|(label, decision, scope)| DesktopApprovalChoice {
                label: label.to_string(),
                decision: Some(decision),
                scope: Some(scope),
                plan: None,
            })
            .collect()
        };

        Some(DesktopApproval {
            plane: *plane,
            session_id: id.clone(),
            request_id: request.request_id.clone(),
            subject: request.subject(),
            kind: detail.kind,
            title: detail.title,
            reason: detail.reason,
            command: detail.command,
            cwd: detail.cwd,
            locations: detail.locations,
            suggested_rule: detail.suggested_rule,
            diff: detail.diff.map(|diff| DesktopApprovalDiff {
                label: format!(
                    "{}+{} −{}{}",
                    diff.path
                        .as_deref()
                        .map(|path| format!("{path} · "))
                        .unwrap_or_default(),
                    diff.additions,
                    diff.deletions,
                    if detail.diff_excerpted || diff.truncated {
                        " · excerpt"
                    } else {
                        ""
                    }
                ),
                text: desktop_excerpt(&diff.text, 16 * 1024),
            }),
            edits: detail
                .edits
                .into_iter()
                .map(|edit| {
                    format!(
                        "{} · {} · {} → {} bytes",
                        edit.path, edit.kind, edit.old_bytes, edit.new_bytes
                    )
                })
                .collect(),
            choices,
        })
    }

    /// Sends exactly one native composer draft through the TUI's reconciliation path.
    pub fn desktop_submit_message(&mut self, text: &str) -> Result<(), String> {
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Err("write a message before sending".to_string());
        }
        let Some((plane, id)) = self.sessions.open.clone() else {
            return Err("open an interactive session before sending".to_string());
        };
        if plane != Plane::Interactive {
            return Err(format!(
                "{id} is a coding task and does not accept follow-up messages"
            ));
        }

        self.compose(ComposerVerb::Message);
        let Some(composer) = self.sessions.composer.as_mut() else {
            return Err(self
                .notice
                .as_ref()
                .map(|notice| notice.text.clone())
                .unwrap_or_else(|| "this session cannot accept a message".to_string()));
        };
        let restored = composer.editor.text();
        if !restored.trim().is_empty() && restored != text {
            return Err(
                "this session has a restored terminal draft; submit or clear it in the TUI before replacing it from desktop"
                    .to_string(),
            );
        }
        composer.editor.clear_text();
        composer.editor.paste(text, &self.completion_catalog);
        composer.user_changed_draft();
        self.submit_composer();
        Ok(())
    }

    /// Starts an interactive session with choices visible in the native form.
    pub fn desktop_start_session(
        &mut self,
        provider: String,
        model: Option<String>,
        workspace: String,
    ) -> Result<String, String> {
        if !self.hello.serves("interactive.start") {
            return Err("this gateway does not serve interactive.start".to_string());
        }
        if !self.hello.operates() {
            return Err(format!(
                "starting a session needs operate scope; this listener is {}",
                self.hello.scope
            ));
        }

        let request = StartRequest {
            id: new_session_id(),
            plane: Plane::Interactive,
            provider: provider.trim().to_string(),
            model: model.filter(|value| !value.trim().is_empty()),
            machine: String::new(),
            workspace: workspace.trim().to_string(),
            approval_mode: self.config.defaults.approval_mode(),
            sandbox_mode: self.config.defaults.sandbox_mode(),
            objective: String::new(),
            worktree: false,
            plan: false,
        };
        let params = request.params().map_err(|refusal| refusal.message())?;
        let id = request.id.clone();

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                    id: id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
        Ok(id)
    }

    /// Answers the current approval. The request id is rechecked to prevent a stale
    /// button from answering a newer prompt that appeared under it.
    pub fn desktop_respond_approval(
        &mut self,
        request_id: &str,
        decision: ApprovalDecision,
        scope: ApprovalScope,
    ) -> Result<(), String> {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return Err("no session is open".to_string());
        };
        let Some(request) = self.sessions.open_watch().and_then(Watch::next_approval) else {
            return Err("this session is not waiting on approval".to_string());
        };
        if request.request_id != request_id {
            return Err(
                "the approval changed; review the new request before answering".to_string(),
            );
        }

        let marked = self
            .sessions
            .watches
            .get_mut(&(plane, id.clone()))
            .is_some_and(|watch| watch.mark_approval_response(request_id));
        if !marked {
            return Err("this approval is already being answered".to_string());
        }

        let params = self.routed_session_params(
            plane,
            &id,
            model::respond_approval_params(&id, request_id, decision, scope),
        );
        self.issue(Call::new(
            Tag::Approval {
                plane,
                id: id.clone(),
                request_id: request_id.to_string(),
            },
            plane.method("respond_approval"),
            params,
        ));
        Ok(())
    }

    pub fn desktop_respond_plan(
        &mut self,
        request_id: &str,
        choice: PlanChoice,
    ) -> Result<(), String> {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return Err("no session is open".to_string());
        };
        let Some(request) = self.sessions.open_watch().and_then(Watch::next_approval) else {
            return Err("this session is not waiting on a plan decision".to_string());
        };
        if request.request_id != request_id {
            return Err("the plan decision changed; review it before answering".to_string());
        }

        self.submit_plan_exit(plane, id, request_id.to_string(), choice, None);
        Ok(())
    }

    /// Interrupts the active turn using the same capability and routing checks as Ctrl-C.
    pub fn desktop_interrupt(&mut self) {
        self.interrupt_turn();
    }
}

fn desktop_excerpt(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n… {} more bytes omitted; inspect event details in the TUI for the full value",
        &text[..end],
        text.len() - end
    )
}

fn desktop_cell(cell: Cell) -> DesktopCell {
    match cell {
        Cell::Message {
            speaker,
            text,
            streaming,
        } => DesktopCell {
            kind: DesktopCellKind::Message,
            label: match speaker {
                Speaker::You => "You",
                Speaker::Agent => "Agent",
            }
            .to_string(),
            body: text,
            tone: match speaker {
                Speaker::You => DesktopTone::Accent,
                Speaker::Agent => DesktopTone::Neutral,
            },
            streaming,
        },
        Cell::Thinking { text, lines, state } => DesktopCell {
            kind: DesktopCellKind::Thinking,
            label: format!(
                "Thinking · {lines} line{}",
                if lines == 1 { "" } else { "s" }
            ),
            body: match state {
                ThinkingState::Collapsed => String::new(),
                ThinkingState::Tail | ThinkingState::Full => text,
            },
            tone: DesktopTone::Muted,
            streaming: state == ThinkingState::Tail,
        },
        Cell::Plan(plan) => DesktopCell {
            kind: DesktopCellKind::Plan,
            label: format!("Plan · {} steps", plan.step_count),
            body: plan
                .steps
                .into_iter()
                .map(|step| {
                    let mark = match step.status {
                        PlanStatus::Done => "✓",
                        PlanStatus::InProgress => "→",
                        PlanStatus::Pending => "○",
                        PlanStatus::Other(_) => "·",
                    };
                    format!("{mark} {}", step.text.replace('\n', " "))
                })
                .collect::<Vec<_>>()
                .join("\n"),
            tone: DesktopTone::Neutral,
            streaming: false,
        },
        Cell::Usage(usage) => DesktopCell {
            kind: DesktopCellKind::Status,
            label: "Usage".to_string(),
            body: format!(
                "{} tokens{}",
                usage.total_tokens.unwrap_or(0),
                usage
                    .cost_usd
                    .map(|cost| format!(" · ${cost:.4}"))
                    .unwrap_or_default()
            ),
            tone: DesktopTone::Muted,
            streaming: false,
        },
        Cell::Tool(tool) => {
            let summary = transcript_cells::summarise(&tool).line();
            DesktopCell {
                kind: DesktopCellKind::Tool,
                label: summary,
                body: tool.output.as_ref().map(model::compact).unwrap_or_default(),
                tone: match tool.state {
                    ToolState::Running => DesktopTone::Accent,
                    ToolState::Completed => DesktopTone::Muted,
                    ToolState::Failed => DesktopTone::Error,
                },
                streaming: tool.state == ToolState::Running,
            }
        }
        Cell::Exploration(group) => DesktopCell {
            kind: DesktopCellKind::Tool,
            label: if group.done {
                format!("Explored {} items", group.total())
            } else {
                format!("Exploring {} items…", group.total())
            },
            body: group
                .calls
                .iter()
                .map(|call| transcript_cells::summarise(call).line())
                .collect::<Vec<_>>()
                .join("\n"),
            tone: DesktopTone::Muted,
            streaming: !group.done,
        },
        Cell::CommandOutput(body) => DesktopCell {
            kind: DesktopCellKind::Tool,
            label: "Command output".to_string(),
            body,
            tone: DesktopTone::Muted,
            streaming: true,
        },
        Cell::File(file) => DesktopCell {
            kind: DesktopCellKind::File,
            label: file.kind.unwrap_or_else(|| "File".to_string()),
            body: file.path.unwrap_or_else(|| "Path not reported".to_string()),
            tone: DesktopTone::Muted,
            streaming: false,
        },
        Cell::Image(image) => DesktopCell {
            kind: DesktopCellKind::File,
            label: "Image".to_string(),
            body: image.label(),
            tone: DesktopTone::Muted,
            streaming: false,
        },
        Cell::Diff(diff) => DesktopCell {
            kind: DesktopCellKind::Diff,
            label: format!(
                "{} · +{} −{}{}",
                diff.diff.path.as_deref().unwrap_or("Diff"),
                diff.parsed.additions(),
                diff.parsed.deletions(),
                if diff.pending_approval {
                    " · awaiting approval"
                } else {
                    ""
                }
            ),
            body: diff.diff.text,
            tone: if diff.pending_approval {
                DesktopTone::Warning
            } else {
                DesktopTone::Muted
            },
            streaming: false,
        },
        Cell::DiffStat {
            files,
            additions,
            deletions,
            in_excerpt,
        } => DesktopCell {
            kind: DesktopCellKind::Diff,
            label: "Changes".to_string(),
            body: format!(
                "{files} files · +{additions} −{deletions}{}",
                if in_excerpt { " · excerpt" } else { "" }
            ),
            tone: DesktopTone::Muted,
            streaming: false,
        },
        Cell::Status {
            label,
            detail,
            tone,
        } => DesktopCell {
            kind: DesktopCellKind::Status,
            label,
            body: detail,
            tone: desktop_tone(tone),
            streaming: false,
        },
        Cell::ChatNote { text } => DesktopCell {
            kind: DesktopCellKind::Status,
            label: "Note".to_string(),
            body: text,
            tone: DesktopTone::Muted,
            streaming: false,
        },
        Cell::Runtime(block) => DesktopCell {
            kind: DesktopCellKind::Runtime,
            label: block.label,
            body: [block.detail, block.body.join("\n")]
                .into_iter()
                .filter(|part| !part.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
            tone: desktop_tone(block.tone),
            streaming: false,
        },
        Cell::Divider { text, tone, .. } => DesktopCell {
            kind: DesktopCellKind::Divider,
            label: text,
            body: String::new(),
            tone: desktop_tone(tone),
            streaming: false,
        },
    }
}

fn desktop_tone(tone: Tone) -> DesktopTone {
    match tone {
        Tone::Muted => DesktopTone::Muted,
        Tone::Success => DesktopTone::Success,
        Tone::Warning => DesktopTone::Warning,
        Tone::Error => DesktopTone::Error,
    }
}
