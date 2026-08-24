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
    Activity,
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
    /// Stable identity for renderer-local affordances such as expanding one tool result.
    /// This is presentation state only; the durable transcript remains authoritative.
    pub key: Option<String>,
    pub kind: DesktopCellKind,
    pub label: String,
    pub body: String,
    pub tone: DesktopTone,
    pub streaming: bool,
    /// Passive bookkeeping shown from the agent reply's hover affordance instead of as
    /// standalone conversation rows.
    pub metadata: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSession {
    pub plane: Plane,
    pub id: String,
    pub title: Option<String>,
    pub status: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub workspace: Option<String>,
    pub triage: Triage,
    pub depth: usize,
    pub selected: bool,
    pub pending_approvals: usize,
    pub last_known: bool,
    pub terminal: bool,
    pub can_rename: bool,
    pub can_delete: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopAccount {
    pub resolved: bool,
    pub connected: bool,
    pub usable: bool,
    pub pending: bool,
    pub identity: Option<String>,
    pub url: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

impl App {
    /// Non-secret ChatGPT readiness and managed-login state for a native shell.
    pub fn desktop_account(&self) -> DesktopAccount {
        let state = self.account.value.as_ref();
        let dialog = match self.overlay.as_ref() {
            Some(Overlay::Account(dialog)) => Some(dialog.as_ref()),
            _ => None,
        };
        let identity = state.and_then(|state| {
            state.account.as_ref().map(|account| {
                account
                    .email
                    .clone()
                    .or_else(|| state.plan_label())
                    .unwrap_or_else(|| "ChatGPT subscription".to_string())
            })
        });

        DesktopAccount {
            resolved: state.is_some() || self.account.error.is_some(),
            connected: state.is_some_and(AccountState::connected),
            usable: state.is_some_and(AccountState::usable),
            pending: dialog.is_some_and(|dialog| dialog.pending)
                || state.is_some_and(|state| state.login.status == "pending"),
            identity,
            url: dialog.and_then(|dialog| dialog.url.clone()),
            code: dialog.and_then(|dialog| dialog.code.clone()),
            error: dialog
                .and_then(|dialog| dialog.error.clone())
                .or_else(|| state.and_then(|state| state.login.error.clone()))
                .or_else(|| self.account.error.clone()),
        }
    }

    /// Starts the runtime-owned OAuth flow. Local clients can receive the loopback browser
    /// callback; an explicitly attached client uses device code on the runtime host.
    pub fn desktop_start_chatgpt_login(&mut self, local_runtime: bool) -> Result<(), String> {
        if self.chatgpt_connected() {
            return Ok(());
        }
        if !self.hello.serves("account.login.start") {
            return Err(
                "this gateway does not expose managed ChatGPT sign-in; update the runtime"
                    .to_string(),
            );
        }
        if !self.hello.operates() {
            return Err(format!(
                "ChatGPT sign-in changes the runtime host, and this listener runs at scope `{}`",
                self.hello.scope
            ));
        }
        if self.desktop_account().pending {
            return Err("ChatGPT sign-in is already waiting for completion".to_string());
        }

        let flow = if local_runtime {
            AccountFlow::Browser
        } else {
            AccountFlow::DeviceCode
        };
        self.overlay = Some(Overlay::Account(Box::new(AccountDialog::new(flow))));
        self.issue(Call::new(
            Tag::AccountLogin,
            "account.login.start",
            json!({
                "flow": match flow {
                    AccountFlow::Browser => "browser",
                    AccountFlow::DeviceCode => "device_code",
                }
            }),
        ));
        Ok(())
    }

    /// Cancels a managed login without leaving an invisible request on the runtime host.
    pub fn desktop_cancel_chatgpt_login(&mut self) {
        let login_id = match self.overlay.as_ref() {
            Some(Overlay::Account(dialog)) if dialog.pending => dialog.login_id.clone(),
            _ => None,
        };
        self.overlay = None;
        if let Some(login_id) = login_id {
            self.issue(Call::new(
                Tag::AccountCancel,
                "account.login.cancel",
                json!({ "login_id": login_id }),
            ));
        }
    }

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
                    title: row.session.title.clone(),
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
                    terminal: row.session.status.terminal(),
                    can_rename: row.session.plane == Plane::Interactive
                        && !row.session.last_known
                        && self.hello.operates()
                        && self.hello.serves("interactive.rename"),
                    can_delete: self.hello.operates()
                        && (row.session.last_known
                            || (row.session.status.terminal()
                                && self.hello.serves(&row.session.plane.method("delete")))),
                }
            })
            .collect()
    }

    /// A bounded conversation projection for a native transcript.
    pub fn desktop_transcript(&self) -> Vec<DesktopCell> {
        let Some(watch) = self.sessions.open_watch() else {
            return Vec::new();
        };

        let projected = transcript_cells::project(
            watch
                .recent_entries(transcript_cells::CHAT_ENTRY_WINDOW)
                .entries,
        )
        .into_iter()
        .map(desktop_cell)
        .collect::<Vec<_>>();
        let mut cells = attach_passive_metadata(projected);

        // The durable transcript cannot describe the RPC-to-first-token gap by itself.
        // Keep that honest local state in the conversation flow so a native client never
        // looks idle immediately after accepting a message.
        if self.waiting_for_open_agent_reply() {
            cells.push(DesktopCell {
                key: None,
                kind: DesktopCellKind::Activity,
                label: "Agent is working".to_string(),
                body: String::new(),
                tone: DesktopTone::Accent,
                streaming: true,
                metadata: Vec::new(),
            });
        }

        cells
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
        let requires_chatgpt = self.sessions.open_info().is_some_and(|session| {
            session.provider.as_deref() == Some("native")
                && session
                    .model
                    .as_deref()
                    .is_some_and(|model| model.starts_with("openai_codex:"))
        });
        if requires_chatgpt && !self.codex_usable() {
            return Err("connect ChatGPT before sending to this session".to_string());
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

        let provider = provider.trim().to_string();
        let model = model
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if provider == "native"
            && model
                .as_deref()
                .is_some_and(|model| model.starts_with("openai_codex:"))
            && !self.codex_usable()
        {
            return Err("connect ChatGPT before starting this model".to_string());
        }

        let request = StartRequest {
            id: new_session_id(),
            plane: Plane::Interactive,
            provider,
            model,
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

    /// Renames one interactive session through the runtime-owned durable title field.
    pub fn desktop_rename_session(
        &mut self,
        plane: Plane,
        id: &str,
        title: &str,
    ) -> Result<(), String> {
        if plane != Plane::Interactive {
            return Err("coding tasks use their objective as their name".to_string());
        }
        if !self.hello.serves("interactive.rename") {
            return Err("this gateway does not serve interactive.rename".to_string());
        }
        if !self.hello.operates() {
            return Err(format!(
                "renaming a session needs operate scope; this listener is {}",
                self.hello.scope
            ));
        }

        let Some(session) = self.sessions.get(plane, id) else {
            return Err(format!("{id} is no longer in the session list"));
        };
        if session.last_known {
            return Err(
                "the session owner is offline, so its durable title cannot be changed".to_string(),
            );
        }

        let title = title.trim();
        if title.is_empty() {
            return Err("enter a session name".to_string());
        }
        if title.chars().count() > 120 {
            return Err("a session name can be at most 120 characters".to_string());
        }
        if title.chars().any(char::is_control) {
            return Err("a session name cannot contain control characters".to_string());
        }

        let params = self.routed_session_params(plane, id, json!({ "id": id, "title": title }));
        self.issue(Call::new(
            Tag::Action {
                label: "rename",
                plane,
                id: id.to_string(),
            },
            "interactive.rename",
            params,
        ));
        Ok(())
    }

    /// Deletes terminal durable state, or hides a last-known row whose owner is offline.
    pub fn desktop_delete_session(&mut self, plane: Plane, id: &str) -> Result<(), String> {
        if !self.hello.operates() {
            return Err(format!(
                "deleting a session needs operate scope; this listener is {}",
                self.hello.scope
            ));
        }

        let Some(session) = self.sessions.get(plane, id) else {
            return Err(format!("{id} is no longer in the session list"));
        };
        let last_known = session.last_known;
        let terminal = session.status.terminal();
        if !terminal && !last_known {
            return Err("finish or stop this session before deleting it".to_string());
        }

        if last_known {
            self.session_removed(plane, id);
            return Ok(());
        }

        let method = plane.method("delete");
        if !self.hello.serves(&method) {
            return Err(format!("this gateway does not serve {method}"));
        }
        let params = self.routed_session_params(plane, id, json!({ "id": id }));
        self.issue(Call::new(
            Tag::Action {
                label: "remove",
                plane,
                id: id.to_string(),
            },
            method,
            params,
        ));
        Ok(())
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
            key: None,
            kind: DesktopCellKind::Message,
            label: match speaker {
                Speaker::You => "You",
                Speaker::Agent => "Agent",
            }
            .to_string(),
            body: text,
            tone: match speaker {
                Speaker::You => DesktopTone::Neutral,
                Speaker::Agent => DesktopTone::Accent,
            },
            streaming,
            metadata: Vec::new(),
        },
        Cell::Thinking { text, lines, state } => DesktopCell {
            key: None,
            kind: DesktopCellKind::Thinking,
            label: format!(
                "Thinking · {lines} line{}",
                if lines == 1 { "" } else { "s" }
            ),
            // GPUI has room to keep reasoning/status context inspectable. Its muted visual
            // treatment, rather than removing its body, makes it secondary to the answer.
            body: text,
            tone: DesktopTone::Muted,
            streaming: state == ThinkingState::Tail,
            metadata: Vec::new(),
        },
        Cell::Plan(plan) => DesktopCell {
            key: None,
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
            metadata: Vec::new(),
        },
        Cell::Usage(usage) => DesktopCell {
            key: None,
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
            metadata: Vec::new(),
        },
        Cell::Tool(tool) => {
            let summary = transcript_cells::summarise(&tool).line();
            DesktopCell {
                key: tool.call_id.as_ref().map(|id| format!("tool:{id}")),
                kind: DesktopCellKind::Tool,
                label: summary,
                body: tool.output.as_ref().map(model::compact).unwrap_or_default(),
                tone: match tool.state {
                    ToolState::Running => DesktopTone::Muted,
                    ToolState::Completed => DesktopTone::Muted,
                    ToolState::Failed => DesktopTone::Error,
                },
                streaming: tool.state == ToolState::Running,
                metadata: Vec::new(),
            }
        }
        Cell::Exploration(group) => DesktopCell {
            key: group
                .calls
                .first()
                .and_then(|call| call.call_id.as_ref())
                .map(|id| format!("exploration:{id}")),
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
            metadata: Vec::new(),
        },
        Cell::CommandOutput(body) => DesktopCell {
            key: None,
            kind: DesktopCellKind::Tool,
            label: "Command output".to_string(),
            body,
            tone: DesktopTone::Muted,
            streaming: true,
            metadata: Vec::new(),
        },
        Cell::File(file) => DesktopCell {
            key: None,
            kind: DesktopCellKind::File,
            label: file.kind.unwrap_or_else(|| "File".to_string()),
            body: file.path.unwrap_or_else(|| "Path not reported".to_string()),
            tone: DesktopTone::Muted,
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::Image(image) => DesktopCell {
            key: None,
            kind: DesktopCellKind::File,
            label: "Image".to_string(),
            body: image.label(),
            tone: DesktopTone::Muted,
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::Diff(diff) => DesktopCell {
            key: None,
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
            metadata: Vec::new(),
        },
        Cell::DiffStat {
            files,
            additions,
            deletions,
            in_excerpt,
        } => DesktopCell {
            key: None,
            kind: DesktopCellKind::Diff,
            label: "Changes".to_string(),
            body: format!(
                "{files} files · +{additions} −{deletions}{}",
                if in_excerpt { " · excerpt" } else { "" }
            ),
            tone: DesktopTone::Muted,
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::Status {
            label,
            detail,
            tone,
        } => DesktopCell {
            key: None,
            kind: DesktopCellKind::Status,
            label,
            body: detail,
            tone: desktop_tone(tone),
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::ChatNote { text } => DesktopCell {
            key: None,
            kind: DesktopCellKind::Status,
            label: "Note".to_string(),
            body: text,
            tone: DesktopTone::Muted,
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::Runtime(block) => DesktopCell {
            key: None,
            kind: DesktopCellKind::Runtime,
            label: block.label,
            body: [block.detail, block.body.join("\n")]
                .into_iter()
                .filter(|part| !part.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
            tone: desktop_tone(block.tone),
            streaming: false,
            metadata: Vec::new(),
        },
        Cell::Divider { text, tone, .. } => DesktopCell {
            key: None,
            kind: DesktopCellKind::Divider,
            label: text,
            body: String::new(),
            tone: desktop_tone(tone),
            streaming: false,
            metadata: Vec::new(),
        },
    }
}

fn attach_passive_metadata(cells: Vec<DesktopCell>) -> Vec<DesktopCell> {
    let mut visible: Vec<DesktopCell> = Vec::with_capacity(cells.len());
    let mut agent_message: Option<usize> = None;
    let mut pending = Vec::new();

    for mut cell in cells {
        let user_message =
            cell.kind == DesktopCellKind::Message && cell.label.eq_ignore_ascii_case("you");
        let agent_reply = cell.kind == DesktopCellKind::Message && !user_message;
        let passive = matches!(
            cell.kind,
            DesktopCellKind::Status | DesktopCellKind::Divider
        ) && matches!(cell.tone, DesktopTone::Neutral | DesktopTone::Muted);

        if passive {
            let metadata = desktop_metadata_line(&cell);
            if let Some(index) = agent_message {
                visible[index].metadata.push(metadata);
            } else {
                pending.push(metadata);
            }
            continue;
        }

        if user_message {
            // Session-start bookkeeping belongs to the session, not to the user's first
            // prompt or the answer that eventually follows it.
            pending.clear();
            agent_message = None;
        } else if agent_reply {
            cell.metadata.append(&mut pending);
            visible.push(cell);
            agent_message = Some(visible.len() - 1);
            continue;
        }

        visible.push(cell);
    }

    visible
}

fn desktop_metadata_line(cell: &DesktopCell) -> String {
    let detail = cell.body.trim();
    if detail.is_empty() {
        cell.label.clone()
    } else {
        format!("{} · {}", cell.label, detail.replace('\n', " · "))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::transcript_cells::ToolCell;
    use serde_json::json;

    #[test]
    fn desktop_tool_rows_keep_their_call_identity_for_local_expansion_state() {
        let cell = desktop_cell(Cell::Tool(ToolCell {
            call_id: Some("call-42".to_string()),
            name: "bash".to_string(),
            kind: Some("execute".to_string()),
            input: json!({"command": "printf hello"}),
            output: Some(json!("hello")),
            state: ToolState::Completed,
            started_at: Some(10),
            settled_at: Some(20),
        }));

        assert_eq!(cell.key.as_deref(), Some("tool:call-42"));
        assert_eq!(cell.kind, DesktopCellKind::Tool);
    }
}
