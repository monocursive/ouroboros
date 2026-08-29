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

// No longer `Copy`: the [`Self::Image`] variant carries the artifact's identity, so the kind
// is matched by reference rather than copied out. Every existing use is an `==` or a
// non-binding `matches!`/`match`, so the borrow is all any of them needed anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopCellKind {
    Message,
    Activity,
    Thinking,
    Plan,
    Tool,
    File,
    Diff,
    Runtime,
    /// A child agent this session spawned. Its own kind rather than [`Self::Runtime`] so
    /// the desktop can give it the agent icon: a reader should be able to see that a row
    /// is another agent's work without reading it.
    Subagent,
    Status,
    Divider,
    /// A11. A desktop screenshot artifact (§8.6). Its own kind so the GPUI desktop draws the
    /// picture with `gpui::img` rather than a file row, and so the pixels stay off
    /// [`DesktopCell::body`]: the identity and the drawable travel here, on the kind, never as
    /// text in a body. `bytes` is the decoded drawable once a surface fetched it by sha,
    /// `None` until then — a placeholder-with-real-dimensions in the meantime. `Arc` so a
    /// cloned cell is a refcount, not a copy of a screenshot.
    Image {
        sha: Option<String>,
        width: Option<u32>,
        height: Option<u32>,
        media_type: Option<String>,
        bytes: Option<std::sync::Arc<Vec<u8>>>,
    },
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
    /// A question for a person — the plan exit or `ask_user` — rather than a
    /// permission. Auto-approve never answers these, so the card must not offer it.
    pub question: bool,
    pub title: Option<String>,
    pub reason: Option<String>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub locations: Vec<String>,
    pub suggested_rule: Option<String>,
    pub diff: Option<DesktopApprovalDiff>,
    pub edits: Vec<String>,
    pub choices: Vec<DesktopApprovalChoice>,
    /// `asked by subagent <description> (<task_id>)`, plus ` on <node>` where the child
    /// runs on a machine that is not the session's own — absent for every approval the
    /// session asked for itself.
    pub subagent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopApprovalDiff {
    pub label: String,
    pub text: String,
}

/// What a quick start would do, read from the same functions that would do it.
///
/// The window shows this beside the composer so the shortest path to a session is not also
/// the least legible one: the provider, model, and workspace here are the values
/// [`App::desktop_quick_start`] will send, not a second description of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopQuickStart {
    pub provider: String,
    pub model: String,
    /// The stored default workspace, or the directory this client was launched in. Empty
    /// where neither exists, in which case the runtime resolves the session's own.
    pub workspace: String,
    /// Whether this gateway would take a start at all: it serves `interactive.start` and
    /// this listener runs at operate scope.
    ///
    /// Not a promise that the next start succeeds. A ChatGPT-gated default model is refused
    /// at submit time, where the account card that fixes it is already on screen — a
    /// composer greyed out for that reason would hide the one thing worth acting on.
    pub ready: bool,
    /// Whether the composer has to wait: a start is in flight, or a first message is still
    /// waiting for the session it belongs to.
    ///
    /// False once a start's outcome is *unknown*, because that is a state the operator can
    /// act on — resubmitting the same prompt reconciles that same session id, and a box
    /// disabled at that moment would hide the only move available.
    pub pending: bool,
}

/// The model- and provider-specific reasoning control for one open desktop session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopReasoning {
    /// The session value last confirmed by the runtime. `None` is drawn as `Default`, not
    /// guessed as `High`; the high default belongs to the new-session form.
    pub current: Option<Effort>,
    pub choices: Vec<Effort>,
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
                        .map(Watch::unanswered_approvals)
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
        .map(|cell| desktop_cell(self.with_desktop_artifact_bytes(cell)))
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

    /// Hands fetched artifact bytes onto the image cell before the desktop maps it, so
    /// GPUI draws from the projection rather than a second cache at render time.
    fn with_desktop_artifact_bytes(&self, mut cell: Cell) -> Cell {
        if let Cell::Image(image) = &mut cell {
            if image.bytes.is_none() {
                if let Some(sha) = image.sha.as_ref() {
                    image.bytes = self.desktop_artifacts.get(sha).cloned();
                }
            }
        }
        cell
    }

    pub fn desktop_approval(&self) -> Option<DesktopApproval> {
        let (plane, id) = self.sessions.open.as_ref()?;
        let request = self.sessions.open_watch()?.next_approval()?;
        let detail = request.detail();
        let subagent = detail.subagent.as_ref().map(|subagent| {
            subagent.line(
                self.sessions
                    .session(*plane, id)
                    .and_then(|session| session.node.as_deref()),
            )
        });

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
        // An `ask_user` option's answer rides `reason`, and `desktop_respond_approval`
        // carries a decision and a scope and nothing else. A row labelled "staging-db" that
        // sent a bare approve would reach the agent as "the operator acknowledged the
        // question without giving an answer" — a button lying about what it sends, which is
        // worse than not offering it. Until the window can carry the words, a question keeps
        // the four standard answers.
        } else if !detail.options.is_empty()
            && detail.options.iter().all(|option| option.answer.is_none())
        {
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
            question: request.question(),
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
            subagent,
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

    /// What the no-session composer will start, before it is asked to start it.
    pub fn desktop_quick_start_context(&self) -> DesktopQuickStart {
        DesktopQuickStart {
            provider: self.home_provider().to_string(),
            model: self.home_model().to_string(),
            workspace: self.default_workspace(),
            ready: self.hello.serves("interactive.start") && self.hello.operates(),
            // The same two conditions `desktop_quick_start` refuses on, so a live Start
            // button and an accepted start are the same answer.
            pending: self.home_pending
                || self
                    .first_message
                    .as_ref()
                    .is_some_and(|pending| !pending.start_outcome_unknown),
        }
    }

    /// Starts an interactive session with the stored defaults and sends `text` as its
    /// first message.
    ///
    /// The window's composer with no session open. Everything about the request — provider,
    /// model, workspace, the approval and sandbox defaults, the first-message bookkeeping,
    /// and the same-id replay after an outcome-unknown refusal — comes from the same
    /// function the terminal home submits through, so the two clients cannot mean different
    /// things by "quick start".
    ///
    /// A leading `/` is sent as text rather than run. Slash commands are a terminal grammar
    /// with a completion catalog and overlays behind them; a window that silently swallowed
    /// a line instead of sending it would be claiming a command surface it does not draw.
    ///
    /// Returning `Err` leaves the prompt with the caller: the window keeps what was typed.
    pub fn desktop_quick_start(&mut self, text: &str) -> Result<(), String> {
        if !self.hello.serves("interactive.start") {
            return Err("this gateway does not serve interactive.start".to_string());
        }
        if !self.hello.operates() {
            return Err(format!(
                "starting a session mutates the runtime, and this listener runs at scope `{}`",
                self.hello.scope
            ));
        }

        let prompt = text.trim().to_string();
        if prompt.is_empty() {
            return Err("type what you want the agent to do".to_string());
        }

        // Only the OAuth-backed direct model needs ChatGPT sign-in, and the account card
        // that grants it is on the same screen as this refusal.
        if self.home_requires_chatgpt() && !self.codex_usable() {
            return Err(format!(
                "connect ChatGPT before starting a session on {}",
                self.home_model()
            ));
        }

        if self.home_pending {
            return Err("a session start is already in flight".to_string());
        }
        if let Some(pending) = self.first_message.as_ref() {
            if !pending.start_outcome_unknown {
                return Err(
                    "a first message is already waiting for its session to start".to_string(),
                );
            }
            // The previous start's outcome is unknown, so its id is still the only safe
            // thing to send. Editing the prompt would mint a new id and risk a duplicate
            // session; resubmitting it unchanged replays the same one.
            if pending.input != prompt {
                return Err(format!(
                    "start {} may already exist; send that same prompt again to reconcile its \
                     session id before changing it",
                    pending.start.id
                ));
            }
        }

        let provider = self.home_provider().to_string();
        self.issue_quick_start(provider, prompt, true)
    }

    /// Takes back a quick-start prompt whose start the runtime refused.
    ///
    /// The reducer restores a refused first message into terminal state — the home draft or
    /// the session composer — that a native window never renders. This hands the same text
    /// to the window instead, once, so a failed start costs an error and not the typing.
    pub fn desktop_take_restored_draft(&mut self) -> Option<String> {
        self.desktop_restored_draft.take()
    }

    /// Fills the two lists the native new-session form picks from.
    ///
    /// One seam rather than two calls at the window, because the form needs both at once
    /// and neither is a session action. Each fetch is a no-op while its answer is
    /// outstanding or already held, so calling this every time the form opens costs
    /// nothing; a gateway that serves neither verb leaves both lists empty and the form
    /// degrades to the text fields it had before.
    pub fn desktop_fetch_pickers(&mut self) {
        self.fetch_providers();
        self.fetch_models();
    }

    /// The desktop's Machines panel opened or closed. While it is open, the shared tick
    /// polls `runtime.status` at the same cadence the TUI's machines overlay uses, so
    /// member presence chips stay live; opening also asks immediately rather than
    /// waiting out the cadence. Closing merely stops the extra polling.
    pub fn desktop_machines_open(&mut self, open: bool) {
        self.desktop_machines_open = open;
        if open {
            self.issue_if_due(
                super::Tag::Status,
                "runtime.status",
                serde_json::json!({}),
                super::STATUS_TICKS,
            );
        }
    }

    /// Reasoning levels both the selected model and provider transport declare usable.
    /// A missing catalogue/provider row returns none rather than a generic three-row list:
    /// the caller asked for what is available for this model, and silence is not proof.
    pub fn desktop_reasoning_choices_for(
        &self,
        provider: &str,
        model: Option<&str>,
    ) -> Vec<Effort> {
        let provider = provider.trim();
        let Some(catalogue) = self.models.value.as_ref() else {
            return Vec::new();
        };
        let Some(catalogue_row) = catalogue.provider(provider) else {
            return Vec::new();
        };
        let Some(model) = model
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .or(catalogue_row.default.as_deref())
        else {
            return Vec::new();
        };
        let Some(model) = catalogue_row.models.iter().find(|entry| entry.id == model) else {
            return Vec::new();
        };
        let Some(provider_row) = self
            .providers
            .value
            .as_ref()
            .and_then(|rows| rows.iter().find(|entry| entry.provider == provider))
        else {
            return Vec::new();
        };

        desktop_reasoning_choices(model, provider_row)
    }

    /// The reasoning select shown in the active session's composer bar.
    pub fn desktop_reasoning(&self) -> Option<DesktopReasoning> {
        let session = self.sessions.open_info()?;
        if session.plane != Plane::Interactive
            || session.capabilities.dynamic_configuration == Capability::No
        {
            return None;
        }

        let provider = session.provider.as_deref()?;
        let model = session
            .model
            .as_deref()
            .or_else(|| self.sessions.open_watch().and_then(Watch::model));
        let choices = self.desktop_reasoning_choices_for(provider, model);
        (!choices.is_empty()).then_some(DesktopReasoning {
            current: session.reasoning_effort,
            choices,
        })
    }

    /// Starts an interactive session with choices visible in the native form.
    ///
    /// `sandbox_mode` is the form's own answer, and `None` means the operator did not
    /// state one — only then does the stored default apply. An explicit choice wins over
    /// the config file for the same reason the TUI's dialog works that way: what a file
    /// supplies is where a control *starts*, never what gets sent.
    pub fn desktop_start_session(
        &mut self,
        provider: String,
        model: Option<String>,
        workspace: String,
        sandbox_mode: Option<SandboxMode>,
        reasoning_effort: Option<Effort>,
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
            sandbox_mode: sandbox_mode.or_else(|| self.config.defaults.sandbox_mode()),
            reasoning_effort,
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

    /// Whether the open session is in this client's auto-approve mode. `None` when no
    /// session is open, which is also "there is nothing to toggle".
    pub fn desktop_auto_approve(&self) -> Option<bool> {
        self.sessions
            .open
            .as_ref()
            .map(|key| self.sessions.auto_approve.contains(key))
    }

    /// Switches the open session's client-side auto-approve mode, through the same path
    /// as `/auto-approve`: turning it on answers the whole backlog immediately (the card
    /// the window is showing included), plan-exit questions keep asking either way.
    pub fn desktop_set_auto_approve(&mut self, on: bool) -> Result<(), String> {
        if self.sessions.open.is_none() {
            return Err("no session is open".to_string());
        }

        self.set_auto_approve(Some(on));
        Ok(())
    }

    /// The open session's file-access posture, for the composer footer's picker.
    ///
    /// `None` means "the runtime has not said", and the native control is *omitted* rather
    /// than defaulted: a picker showing `Workspace write` for a session whose posture
    /// nobody stated would be this client inventing a safety fact, and the checked row
    /// would make the invention look confirmed.
    pub fn desktop_sandbox_mode(&self) -> Option<SandboxMode> {
        self.open_sandbox_mode()
    }

    /// The three postures the picker offers, in the order it draws them.
    pub fn desktop_sandbox_choices() -> [SandboxMode; 3] {
        SandboxMode::CHANGEABLE
    }

    /// Moves the open session's file access, through the same call `/sandbox` sends.
    ///
    /// Returns as soon as the request is *issued*; the picker's label does not move until
    /// the runtime's answer re-lists the session, so what it shows is always a posture the
    /// runtime confirmed. Local refusals — no session, wrong plane, a gateway that does
    /// not serve `interactive.configure`, or the mode it is already on — come back here as
    /// the window's inline error rather than as a notice the desktop never draws. Their
    /// severity is dropped rather than translated: the window has one error slot, and a
    /// refused change is a refused change in it.
    pub fn desktop_set_sandbox_mode(&mut self, mode: SandboxMode) -> Result<(), String> {
        self.configure_sandbox(mode)
            .map_err(|(_kind, refusal)| refusal)
    }

    /// Changes the open session's default effort for future turns. As with file access,
    /// the label stays on the runtime-confirmed value until the configure answer re-lists
    /// the session.
    pub fn desktop_set_reasoning_effort(&mut self, effort: Effort) -> Result<(), String> {
        self.configure_reasoning_effort(effort)
            .map_err(|(_kind, refusal)| refusal)
    }
}

fn desktop_reasoning_choices(
    model: &crate::model::ModelEntry,
    provider: &ProviderEntry,
) -> Vec<Effort> {
    model
        .efforts()
        .into_iter()
        .filter(|effort| provider.reasoning_effort_refusal(*effort).is_none())
        .collect()
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
        // A11. A desktop screenshot artifact becomes an Image cell the GPUI desktop draws
        // with `gpui::img`; a composer attachment, which carries no sha and no fetched bytes,
        // stays a File placeholder because there is nothing here to hand a real renderer.
        // Either way the label — never the pixels — is the body, so a text surface still has
        // a sentence and the picture surface has the drawable off to the side (§8.6).
        Cell::Image(image) if image.sha.is_some() => DesktopCell {
            key: image.sha.as_ref().map(|sha| format!("image:{sha}")),
            kind: DesktopCellKind::Image {
                sha: image.sha.clone(),
                width: image.pixels.map(|(width, _height)| width),
                height: image.pixels.map(|(_width, height)| height),
                media_type: image.media_type.clone(),
                bytes: image.bytes.clone(),
            },
            label: "Screenshot".to_string(),
            body: image.label(),
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
        // Keyed by task so the desktop's list keeps one child's row identified across the
        // rewrites its progress reports cause, rather than treating each render as a new
        // row and losing whatever the reader had expanded.
        Cell::Subagent(subagent) => DesktopCell {
            key: subagent
                .task_id
                .as_ref()
                .map(|task| format!("subagent:{task}")),
            kind: DesktopCellKind::Subagent,
            label: subagent.headline(),
            body: [subagent.detail(), subagent.rows().join("\n")]
                .into_iter()
                .filter(|part| !part.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n"),
            tone: desktop_tone(subagent.tone()),
            // A child that has not settled is still working, and the desktop's live
            // treatment is the only thing on that row that says so.
            streaming: !subagent.settled,
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
    use crate::ui::transcript_cells::{ImageCell, SubagentCell, ToolCell};
    use serde_json::json;

    #[test]
    fn desktop_reasoning_rows_intersect_model_and_transport_capabilities() {
        let catalogue = ModelsCatalog::decode(&json!({
            "providers": [{
                "provider": "native",
                "models": [{
                    "id": "openai_codex:gpt-test",
                    "reasoning_efforts": ["low", "medium", "high", "future"]
                }]
            }]
        }))
        .expect("a model catalogue");
        let providers = ProviderEntry::decode_list(&json!([{
            "provider": "native",
            "spec": {
                "provider": "native",
                "default_session_transport": "managed",
                "normalized_options": ["model", "reasoning_effort"],
                "normalized_values": {"reasoning_effort": ["low", "high"]}
            }
        }]));
        let model = &catalogue.provider("native").unwrap().models[0];

        assert_eq!(
            desktop_reasoning_choices(model, &providers[0]),
            vec![Effort::Low, Effort::High]
        );

        let no_effort = ProviderEntry::decode_list(&json!([{
            "provider": "native",
            "spec": {
                "provider": "native",
                "default_session_transport": "managed",
                "normalized_options": ["model"]
            }
        }]));
        assert!(desktop_reasoning_choices(model, &no_effort[0]).is_empty());
    }

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

    /// Parity is not two renderers that happen to agree. It is one projection with two
    /// renderers over it, and this is the seam where the desktop reads it — so what the
    /// desktop shows for a child agent is asserted against the same [`Cell`] the pane draws.
    #[test]
    fn a_running_child_agent_reaches_the_desktop_keyed_and_live() {
        let cell = desktop_cell(Cell::Subagent(SubagentCell {
            task_id: Some("task-a".to_string()),
            description: Some("audit the parser".to_string()),
            provider_session_id: Some("sess-child".to_string()),
            node: Some("ouro-2@fleet".to_string()),
            remote: true,
            worktree: true,
            background: true,
            depth: Some(2),
            turns: Some(4),
            tool_calls: Some(11),
            files: Some(2),
            ..SubagentCell::default()
        }));

        assert_eq!(cell.kind, DesktopCellKind::Subagent);
        assert_eq!(
            cell.key.as_deref(),
            Some("subagent:task-a"),
            "the row keeps its identity across the rewrites progress causes"
        );
        assert_eq!(
            cell.label,
            "Subagent audit the parser · ⇄ ouro-2@fleet · ⎇ worktree · background · depth 2"
        );
        assert!(
            cell.body.contains("4 turns · 11 tool calls · 2 files"),
            "{cell:#?}"
        );
        assert!(
            cell.body.contains("session sess-child"),
            "the desktop leads to the child's own transcript too: {cell:#?}"
        );
        assert!(cell.streaming, "a child that has not settled is working");
        assert_eq!(cell.tone, DesktopTone::Muted);
    }

    /// A11. The seam the GPUI desktop reads for a screenshot: a desktop artifact is an Image
    /// cell carrying the identity and (once fetched) the drawable, and its label — never the
    /// pixels — is the body. A composer attachment, which has neither sha nor bytes, stays a
    /// File placeholder.
    #[test]
    fn a_desktop_artifact_reaches_the_desktop_as_an_image_cell_with_its_bytes_off_the_body() {
        let sha = "a".repeat(64);
        let bytes = std::sync::Arc::new(vec![1u8, 2, 3, 4]);

        let cell = desktop_cell(Cell::Image(ImageCell {
            named: format!("desktop capture · {}", &sha[..12]),
            pixels: Some((480, 640)),
            format: Some("jpeg".to_string()),
            note: None,
            sha: Some(sha.clone()),
            media_type: Some("image/jpeg".to_string()),
            bytes: Some(bytes.clone()),
        }));

        assert_eq!(
            cell.kind,
            DesktopCellKind::Image {
                sha: Some(sha.clone()),
                width: Some(480),
                height: Some(640),
                media_type: Some("image/jpeg".to_string()),
                bytes: Some(bytes),
            }
        );
        assert_eq!(cell.key.as_deref(), Some(format!("image:{sha}").as_str()));
        // The body is the label, a sentence — the pixels are on the kind, not in the text.
        assert!(cell.body.contains("480×640 jpeg"), "{cell:#?}");
        assert!(
            !cell.body.contains('\u{1b}'),
            "no escapes leak into the body"
        );

        // A composer attachment (no sha, no fetched bytes) has nothing to hand a renderer.
        let attachment = desktop_cell(Cell::Image(ImageCell {
            named: ".ouroboros/images/shot.png".to_string(),
            pixels: Some((32, 32)),
            format: Some("png".to_string()),
            note: None,
            sha: None,
            media_type: None,
            bytes: None,
        }));
        assert_eq!(attachment.kind, DesktopCellKind::File);
    }

    /// A settled child stops being live, and its verdict becomes the row's tone.
    #[test]
    fn a_settled_child_agent_stops_streaming_and_takes_its_verdicts_tone() {
        let settled = |status: &str| {
            desktop_cell(Cell::Subagent(SubagentCell {
                task_id: Some("task-a".to_string()),
                description: Some("audit the parser".to_string()),
                status: Some(status.to_string()),
                settled: true,
                turns: Some(9),
                tool_calls: Some(31),
                files: Some(4),
                input_tokens: Some(18_400),
                output_tokens: Some(2_100),
                ..SubagentCell::default()
            }))
        };

        let completed = settled("completed");
        assert!(!completed.streaming);
        assert_eq!(completed.tone, DesktopTone::Success);
        assert!(
            completed.body.contains(
                "completed · 9 turns · 31 tool calls · 4 files · 18400 in / 2100 out tokens"
            ),
            "{completed:#?}"
        );

        assert_eq!(settled("failed").tone, DesktopTone::Error);
        assert_eq!(settled("timed_out").tone, DesktopTone::Error);
        // Neither a success nor a failure, and the desktop does not pick one.
        assert_eq!(settled("stopped").tone, DesktopTone::Muted);
    }
}
