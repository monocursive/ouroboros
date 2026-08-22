use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptKind {
    HistoryModule,
    GrantsPrincipal,
    PreviewCapability,
    AdmitCapability,
    ControlObjective,
    /// Editing the optional reason for an approval already on screen. Carries the
    /// chooser state and the pre-edit reason so submitting or abandoning the prompt
    /// returns to the same chooser instead of dropping the answer.
    ApprovalReason {
        plane: Plane,
        id: String,
        request_id: String,
        choice: usize,
        reason: Option<String>,
    },
}

/// How many rows an approval-mode cycler has: the four the schema declares, plus the
/// "say nothing" row that is not one of them.
pub const APPROVAL_ROWS: usize = ApprovalMode::ALL.len() + 1;
pub const SANDBOX_ROWS: usize = SandboxMode::ALL.len() + 1;

/// The mode a cycler row means. Index 0 is "leave it to the plane", which is an *absent*
/// parameter rather than `"default"` — the gateway's `default` is itself a value the
/// schema declares, and sending it is a different statement from sending nothing.
///
/// Shared by the new-session dialog and the settings overlay so the two cannot disagree
/// about what row zero means.
pub fn approval_at(index: usize) -> Option<ApprovalMode> {
    index
        .checked_sub(1)
        .and_then(|index| ApprovalMode::ALL.get(index).copied())
}

/// The inverse: where a stored mode sits in the cycler. An unknown mode lands on "unset",
/// which is the only honest place for a value this build cannot name.
pub fn approval_index(mode: Option<ApprovalMode>) -> usize {
    match mode {
        None => 0,
        Some(mode) => ApprovalMode::ALL
            .iter()
            .position(|candidate| *candidate == mode)
            .map(|index| index + 1)
            .unwrap_or(0),
    }
}

/// What a cycler row reads as.
pub fn approval_label(index: usize) -> String {
    match approval_at(index) {
        None => "unset — the plane's own default".to_string(),
        Some(mode) => format!("{} — {}", mode.as_str(), mode.describe()),
    }
}

pub fn sandbox_at(index: usize) -> Option<SandboxMode> {
    index
        .checked_sub(1)
        .and_then(|index| SandboxMode::ALL.get(index).copied())
}

pub fn sandbox_index(mode: Option<SandboxMode>) -> usize {
    match mode {
        None => 0,
        Some(mode) => SandboxMode::ALL
            .iter()
            .position(|candidate| *candidate == mode)
            .map(|index| index + 1)
            .unwrap_or(0),
    }
}

pub fn sandbox_label(index: usize) -> String {
    match sandbox_at(index) {
        None => "unset — can edit when the provider allows it".to_string(),
        Some(mode) => format!("{} — {}", mode.label(), mode.describe()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    NewSession,
    NewSessionOptions,
    WriteAccess,
    SwitchSession,
    SessionDetails,
    CopyLast,
    CopyRawLast,
    Export,
    DumpScrollback,
    ViewTranscript,
    Interrupt,
    Steer,
    ExternalEditor,
    CloseSession,
    ConnectChatGpt,
    Runtime,
    Agents,
    Teams,
    Nodes,
    Plans,
    Upgrades,
    ListCapabilities,
    PreviewCapability,
    AdmitCapability,
    Logs,
    Machines,
    Settings,
    Help,
}

impl Command {
    pub const ALL: [Self; 28] = [
        Self::NewSession,
        Self::SwitchSession,
        Self::SessionDetails,
        Self::CopyLast,
        Self::CopyRawLast,
        Self::Export,
        Self::DumpScrollback,
        Self::ViewTranscript,
        Self::Interrupt,
        Self::Steer,
        Self::ExternalEditor,
        Self::CloseSession,
        Self::NewSessionOptions,
        Self::WriteAccess,
        Self::ConnectChatGpt,
        Self::Runtime,
        Self::Agents,
        Self::Teams,
        Self::Nodes,
        Self::Plans,
        Self::Upgrades,
        Self::Logs,
        Self::Machines,
        Self::Settings,
        Self::Help,
        Self::ListCapabilities,
        Self::PreviewCapability,
        Self::AdmitCapability,
    ];

    pub fn group(self) -> &'static str {
        match self {
            Self::NewSession
            | Self::NewSessionOptions
            | Self::WriteAccess
            | Self::SwitchSession
            | Self::SessionDetails
            | Self::CopyLast
            | Self::CopyRawLast
            | Self::Export
            | Self::DumpScrollback
            | Self::ViewTranscript
            | Self::Interrupt
            | Self::Steer
            | Self::ExternalEditor
            | Self::CloseSession
            | Self::ConnectChatGpt
            | Self::Help => "Coding",
            _ => "Runtime & distribution",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NewSession => "New session",
            Self::NewSessionOptions => "New session options",
            Self::WriteAccess => "Start a session that can edit files",
            Self::SwitchSession => "Switch session",
            Self::SessionDetails => "Toggle event details",
            Self::CopyLast => "Copy last agent message",
            Self::CopyRawLast => "Copy last agent message as source Markdown",
            Self::Export => "Export the transcript to a file",
            Self::DumpScrollback => "Print transcript into terminal scrollback",
            Self::ViewTranscript => "Open transcript in $EDITOR",
            Self::Interrupt => "Interrupt the running turn",
            Self::Steer => "Steer the running turn",
            Self::ExternalEditor => "Edit prompt in $EDITOR",
            Self::CloseSession => "End or remove session",
            Self::ConnectChatGpt => "Connect ChatGPT",
            Self::Runtime => "Runtime & distribution",
            Self::Agents => "Agents",
            Self::Teams => "Teams",
            Self::Nodes => "Nodes",
            Self::Plans => "Plans & control",
            Self::Upgrades => "Upgrades",
            Self::ListCapabilities => "List capability proposals",
            Self::PreviewCapability => "Preview a capability",
            Self::AdmitCapability => "Admit a capability",
            Self::Logs => "Logs",
            Self::Machines => "Machines",
            Self::Settings => "Settings",
            Self::Help => "Keyboard shortcuts",
        }
    }

    pub fn shortcut(self) -> &'static str {
        match self {
            Self::NewSession => "ctrl+x n",
            Self::NewSessionOptions => "ctrl+x N",
            Self::WriteAccess => "/write",
            Self::SwitchSession => "ctrl+x l",
            Self::SessionDetails => "ctrl+x d",
            Self::CopyLast => "ctrl+x y",
            Self::CopyRawLast => "/copy raw",
            Self::Export => "/export",
            Self::DumpScrollback => "ctrl+x [",
            Self::ViewTranscript => "ctrl+x v",
            Self::Interrupt => "esc",
            Self::Steer => "ctrl+x s",
            Self::ExternalEditor => "ctrl+g",
            Self::CloseSession => "ctrl+x x",
            Self::ConnectChatGpt => "/connect",
            Self::Runtime => "/runtime",
            Self::Agents => "/agents",
            Self::Teams => "/teams",
            Self::Nodes => "/runtime",
            Self::Plans => "/plans",
            Self::Upgrades => "/upgrades",
            Self::ListCapabilities => "/capabilities",
            Self::PreviewCapability => "/preview",
            Self::AdmitCapability => "/admit",
            Self::Logs => "/logs",
            Self::Machines => "/machines",
            Self::Settings => "/settings",
            Self::Help => "?",
        }
    }

    fn matches(self, query: &str) -> bool {
        let query = query.trim().to_ascii_lowercase();
        query.is_empty()
            || self.label().to_ascii_lowercase().contains(&query)
            || self.group().to_ascii_lowercase().contains(&query)
            || self.shortcut().contains(&query)
    }
}

#[derive(Debug, Default)]
pub struct CommandPalette {
    pub query: String,
    pub selected: usize,
}

impl CommandPalette {
    /// Every command whose label, group, or shortcut matches the query — before the
    /// capability filter. [`App::palette_commands`] is what a caller draws or activates;
    /// this is the half that does not need to know which session is open.
    pub fn matching(&self, offered: &[Command]) -> Vec<Command> {
        offered
            .iter()
            .copied()
            .filter(|command| command.matches(&self.query))
            .collect()
    }
}

impl App {
    /// The palette's rows for the session that is actually open.
    ///
    /// B0/D14: a command that cannot work here is not listed. `Steer` is the live case —
    /// `steer/3` is `{:error, :unsupported}` on every transport but `pi`'s — and the
    /// approval entry goes the same way on a transport with no approvals channel.
    pub fn palette_commands(&self, palette: &CommandPalette) -> Vec<Command> {
        let offered = Command::ALL
            .iter()
            .copied()
            .filter(|command| match command {
                Command::Steer => self.steer_offered(),
                Command::Interrupt => self.open_capabilities().interrupt.offered(),
                _always => true,
            })
            .collect::<Vec<_>>();

        palette.matching(&offered)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountFlow {
    Browser,
    DeviceCode,
}

#[derive(Debug)]
pub struct AccountDialog {
    pub pending: bool,
    pub flow: AccountFlow,
    pub login_id: Option<String>,
    pub url: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

impl AccountDialog {
    pub(super) fn new(flow: AccountFlow) -> Self {
        Self {
            pending: true,
            flow,
            login_id: None,
            url: None,
            code: None,
            error: None,
        }
    }
}

#[derive(Debug)]
pub enum Overlay {
    Commands(CommandPalette),
    Account(Box<AccountDialog>),
    SessionPicker {
        selected: Option<(Plane, String)>,
    },
    Help,
    /// This client's own preferences, beside the facts the runtime reports.
    Settings(Box<Settings>),
    /// A guided fleet setup surface. Add-another-machine can run after an explicit
    /// confirm; the remaining rows still copy exact commands.
    Machines(Box<Machines>),
    Quit {
        options: Vec<(String, Quit)>,
        choice: usize,
    },
    /// Opened by an `approval_requested` event, or by `a` while one is outstanding.
    Approval {
        plane: Plane,
        id: String,
        request_id: String,
        subject: String,
        choice: usize,
        reason: Option<String>,
        /// Everything the `approval_requested` payload carries, read once when the modal
        /// opened rather than re-derived on every frame.
        detail: Box<ApprovalDetail>,
        /// The fifth answer, present only when the payload suggested a rule *and* this
        /// gateway serves `permissions.add` *and* the session names a workspace to scope
        /// it to. Absent rather than broken: an offer this client could not honour would
        /// be worse than no offer.
        rule: Option<ApprovalRule>,
        /// Why the fifth answer is missing although the payload suggested a rule. Shown,
        /// because "this runtime cannot remember that" and "nothing was suggested" are
        /// different facts.
        rule_absent: Option<&'static str>,
        /// `ctrl+o` inside the modal: draw the diff at its full retained length instead of
        /// the pane-height budget.
        expanded: bool,
    },
    Confirm {
        title: String,
        detail: String,
        /// `None` dismisses without acting.
        options: Vec<(String, Option<Call>)>,
        choice: usize,
    },
    Prompt {
        kind: PromptKind,
        label: String,
        buffer: String,
    },
    New(Box<NewSession>),
}

/// The four answers `interactive.respond_approval` accepts, in the order the modal lists
/// them. Exactly `Jido.Harness.ApprovalResponse`'s two enums crossed; nothing else is
/// offered because nothing else is accepted.
pub const APPROVAL_CHOICES: [(ApprovalDecision, ApprovalScope); 4] = [
    (ApprovalDecision::Approve, ApprovalScope::Once),
    (ApprovalDecision::Approve, ApprovalScope::Session),
    (ApprovalDecision::Deny, ApprovalScope::Once),
    (ApprovalDecision::Deny, ApprovalScope::Session),
];

/// The index of the durable "don't ask again" answer, which is the fifth row when there is
/// one. It is not in [`APPROVAL_CHOICES`] because it is not one call: `respond_approval`
/// has no `scope: "always"` — the pinned `ApprovalResponse` schema admits only `once` and
/// `session` — so the durable form is a session-scoped approval *plus* a `permissions.add`
/// rule, and the modal says exactly that before it is chosen.
pub const APPROVAL_REMEMBER: usize = APPROVAL_CHOICES.len();

/// A session id reduced to something safe to put in a filename.
///
/// Ids are generated here and are already `[a-z0-9-]`, but an operator may supply their
/// own with `interactive.start {id}` and this builds a *path* out of it. Anything outside
/// the allowlist becomes `-`, so no id can walk out of the directory the export was meant
/// for, and the result is bounded so no id can produce a name the filesystem refuses.
fn file_stem(id: &str) -> String {
    let stem: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();

    if stem.is_empty() {
        "session".to_string()
    } else {
        stem
    }
}

/// The rule the fifth answer would write, named in full before it is written.
///
/// `pattern` is the runtime's own `suggested_rule` — this client never invents one, which
/// is the point of computing it server-side in `Control.Permissions.Seam`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRule {
    pub pattern: String,
    pub workspace: String,
}

impl App {
    /// `control.submit` from the Plans tab. The objective is the only field the plane
    /// lets a model-invisible caller choose; revision policy stays runtime configuration.
    pub(super) fn open_control_submit(&mut self) {
        if !self.hello.serves("control.submit") {
            return;
        }
        self.overlay = Some(Overlay::Prompt {
            kind: PromptKind::ControlObjective,
            label: "objective for the control run".into(),
            buffer: String::new(),
        });
    }

    /// `control.cancel` for the selected run, behind the same confirmation every
    /// destructive session verb uses.
    pub(super) fn open_control_cancel(&mut self) {
        if !self.hello.serves("control.cancel") {
            return;
        }
        let Some(row) = self.control.current() else {
            return;
        };
        let status = row.status.as_deref().unwrap_or_default();
        if matches!(status, "completed" | "failed" | "cancelled") {
            self.inform(
                format!("run {} is already {status}", row.id),
                NoticeKind::Info,
            );
            return;
        }
        let id = row.id.clone();
        let call = Call::new(
            Tag::ControlCancel(id.clone()),
            "control.cancel",
            json!({ "id": id }),
        );
        self.overlay = Some(Overlay::Confirm {
            title: format!("cancel control run {id}?"),
            detail: "the run stops durably; steps already dispatched may still finish".to_string(),
            options: vec![
                ("cancel it".to_string(), Some(call)),
                ("leave it running".to_string(), None),
            ],
            choice: 0,
        });
    }

    // ----- overlays ------------------------------------------------------------------

    pub(super) fn open_quit(&mut self) {
        let options = match self.mode {
            Mode::Spawned { pid } => vec![
                (
                    format!("detach — leave the runtime running (pid {pid})"),
                    Quit::Detach,
                ),
                (
                    if self.shutdown_served() {
                        "shut down — runtime.shutdown, then SIGTERM, then SIGKILL".to_string()
                    } else {
                        // `hello.methods` is the feature gate and the only one (§2.3).
                        "shut down — this gateway does not serve runtime.shutdown, so SIGTERM"
                            .to_string()
                    },
                    Quit::Shutdown,
                ),
            ],
            Mode::Attached => vec![(
                "disconnect — the runtime keeps running".to_string(),
                Quit::Disconnect,
            )],
        };

        self.overlay = Some(Overlay::Quit { options, choice: 0 });
    }

    pub fn shutdown_served(&self) -> bool {
        self.hello.serves("runtime.shutdown") && self.hello.operates()
    }

    pub(super) fn overlay_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};

        if matches!(self.overlay, Some(Overlay::Commands(_))) {
            self.command_palette_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::Account(_))) {
            self.account_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::SessionPicker { .. })) {
            self.session_picker_key(key);
            return;
        }

        // A form has its own key discipline — every printable character belongs to a text
        // field — so it is dispatched before the choosers below can claim `j` and `k`.
        if matches!(self.overlay, Some(Overlay::New(_))) {
            self.new_session_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::Settings(_))) {
            self.settings_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::Machines(_))) {
            self.machines_key(key);
            return;
        }

        let Some(overlay) = self.overlay.as_mut() else {
            return;
        };

        match overlay {
            Overlay::Help => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter) {
                    self.overlay = None;
                }
            }
            Overlay::Quit { options, choice } => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.overlay = None,
                KeyCode::Char('j') | KeyCode::Down => {
                    *choice = (*choice + 1).min(options.len().saturating_sub(1))
                }
                KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                KeyCode::Enter => {
                    self.quit = options.get(*choice).map(|(_label, quit)| *quit);
                    self.overlay = None;
                }
                _ => {}
            },
            Overlay::Confirm {
                options, choice, ..
            } => match key.code {
                KeyCode::Esc => {
                    self.overlay = None;
                    self.resume_picker_if_requested();
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    *choice = (*choice + 1).min(options.len().saturating_sub(1))
                }
                KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                KeyCode::Enter => {
                    let call = options.get(*choice).and_then(|(_label, call)| call.clone());
                    self.overlay = None;

                    if let Some(call) = call {
                        self.submit_confirm(call);
                    } else {
                        self.resume_picker_if_requested();
                    }
                }
                _ => {}
            },
            Overlay::Approval {
                plane,
                id,
                request_id,
                choice,
                reason,
                rule,
                expanded,
                ..
            } => {
                let rows = APPROVAL_CHOICES.len() + usize::from(rule.is_some());

                match key.code {
                    KeyCode::Esc => self.overlay = None,
                    KeyCode::Char('j') | KeyCode::Down => *choice = (*choice + 1).min(rows - 1),
                    KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                    // Claude Code's `Ctrl+O`, inside the modal: the diff at full retained
                    // length instead of the rows the popup could spare for it.
                    KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        *expanded = !*expanded;
                    }
                    // Claude Code offers the comment field on `Tab` from the answer row;
                    // this client has always offered it on `r`. Both, because `r` is what
                    // the modal's own hint says and `Tab` is what a reader arrives with.
                    KeyCode::Char('r') | KeyCode::Tab => {
                        let kind = PromptKind::ApprovalReason {
                            plane: *plane,
                            id: id.clone(),
                            request_id: request_id.clone(),
                            choice: *choice,
                            reason: reason.clone(),
                        };
                        let buffer = reason.clone().unwrap_or_default();
                        self.overlay = Some(Overlay::Prompt {
                            kind,
                            label: "approval reason — enter attaches it, an empty line keeps none"
                                .to_string(),
                            buffer,
                        });
                    }
                    KeyCode::Enter => self.submit_approval(),
                    _ => {}
                }
            }
            Overlay::Prompt { buffer, .. } => match key.code {
                KeyCode::Esc => self.resume_approval_choice(),
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => buffer.push(c),
                KeyCode::Enter => self.submit_prompt(),
                _ => {}
            },
            // All three are dispatched above, before this match could claim their
            // printable keys.
            Overlay::Commands(_)
            | Overlay::Account(_)
            | Overlay::SessionPicker { .. }
            | Overlay::New(_)
            | Overlay::Settings(_)
            | Overlay::Machines(_) => {}
        }
    }

    fn command_palette_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        if matches!(key.code, KeyCode::Esc) || (ctrl && matches!(key.code, KeyCode::Char('p'))) {
            self.overlay = None;
            return;
        }

        let selected_command = match self.overlay.as_ref() {
            Some(Overlay::Commands(palette)) if matches!(key.code, KeyCode::Enter) => self
                .palette_commands(palette)
                .get(palette.selected)
                .copied(),
            _ => None,
        };

        if let Some(command) = selected_command {
            self.activate_command(command);
            return;
        }

        let rows = match self.overlay.as_ref() {
            Some(Overlay::Commands(palette)) => self.palette_commands(palette).len(),
            _ => return,
        };

        let Some(Overlay::Commands(palette)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Down => {
                palette.selected = (palette.selected + 1).min(rows.saturating_sub(1));
            }
            KeyCode::Up => palette.selected = palette.selected.saturating_sub(1),
            KeyCode::Backspace => {
                palette.query.pop();
                // The visible list is already filtered to what matches, so the first row
                // is the first match.
                palette.selected = 0;
            }
            KeyCode::Char(c) if !ctrl => {
                palette.query.push(c);
                palette.selected = 0;
            }
            _ => {}
        }
    }

    pub(super) fn activate_command(&mut self, command: Command) {
        match command {
            Command::NewSession => self.new_home(),
            Command::NewSessionOptions => {
                self.overlay = None;
                self.open_new_session();
            }
            Command::WriteAccess => {
                self.overlay = None;
                self.start_writable_session();
            }
            Command::SwitchSession => {
                let selected = self
                    .sessions
                    .open
                    .clone()
                    .or_else(|| self.sessions.picker_key(0));
                self.overlay = Some(Overlay::SessionPicker { selected });
                self.sessions.interactive.invalidate();
                self.sessions.coding.invalidate();
                self.poll();
            }
            Command::SessionDetails => {
                self.overlay = None;
                self.toggle_session_details();
            }
            Command::CopyRawLast => {
                self.overlay = None;
                self.copy_last_agent_source();
            }
            Command::Export => {
                self.overlay = None;
                self.export_transcript("");
            }
            Command::CopyLast => {
                self.overlay = None;
                self.copy_last_agent();
            }
            Command::DumpScrollback => self.dump_to_scrollback(),
            Command::ViewTranscript => self.view_transcript(),
            Command::Interrupt => {
                self.overlay = None;
                self.interrupt_turn();
            }
            Command::Steer => {
                self.overlay = None;
                self.compose(ComposerVerb::Steer);
            }
            Command::ExternalEditor => {
                self.overlay = None;
                self.request_external_editor();
            }
            Command::CloseSession => {
                self.open_close_confirm();
            }
            Command::ConnectChatGpt => {
                self.overlay = None;
                self.open_account();
            }
            Command::Runtime | Command::Nodes => {
                self.overlay = None;
                self.select_tab(Tab::Dashboard);
            }
            Command::Agents => {
                self.overlay = None;
                self.select_tab(Tab::Agents);
            }
            Command::Teams => {
                self.overlay = None;
                self.select_tab(Tab::Teams);
            }
            Command::Plans => {
                self.overlay = None;
                self.select_tab(Tab::Plans);
            }
            Command::Upgrades => {
                self.overlay = None;
                self.select_tab(Tab::Upgrade);
            }
            Command::ListCapabilities => {
                self.overlay = None;
                self.list_capabilities();
            }
            Command::PreviewCapability => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::PreviewCapability,
                    label: "proposal name (empty lists them)".into(),
                    buffer: String::new(),
                });
            }
            Command::AdmitCapability => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::AdmitCapability,
                    label: "proposal name to admit".into(),
                    buffer: String::new(),
                });
            }
            Command::Logs => {
                self.overlay = None;
                self.select_tab(Tab::Logs);
            }
            Command::Machines => {
                self.overlay = None;
                self.open_machines();
            }
            Command::Settings => {
                self.overlay = None;
                self.open_settings();
            }
            Command::Help => {
                self.overlay = Some(Overlay::Help);
            }
        }
    }

    fn session_picker_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        if matches!(key.code, KeyCode::Esc) {
            self.overlay = None;
            return;
        }

        let Some(Overlay::SessionPicker { selected }) = self.overlay.as_ref() else {
            return;
        };

        let selected = selected.clone();
        let index = self.sessions.picker_index(selected.as_ref());
        let last = self.sessions.merged().len().saturating_sub(1);

        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(key) = self.sessions.picker_key((index + 1).min(last)) {
                    self.overlay = Some(Overlay::SessionPicker {
                        selected: Some(key),
                    });
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(key) = self.sessions.picker_key(index.saturating_sub(1)) {
                    self.overlay = Some(Overlay::SessionPicker {
                        selected: Some(key),
                    });
                }
            }
            KeyCode::Enter => {
                let session = selected.or_else(|| self.sessions.picker_key(index));
                self.overlay = None;
                if let Some((plane, id)) = session {
                    self.open_session(plane, id);
                }
            }
            KeyCode::Char('x') => {
                if let Some((plane, id)) = selected.or_else(|| self.sessions.picker_key(index)) {
                    self.open_close_confirm_for(plane, id, true);
                }
            }
            _ => {}
        }
    }

    fn account_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let connected = self.chatgpt_connected();

        match key.code {
            KeyCode::Esc => {
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
            KeyCode::Enter if connected => self.overlay = None,
            // The URL is opened once when it arrives, and a browser that was not running,
            // or a window that swallowed it, leaves nothing on screen to act on. This is
            // the affordance the dialog advertises beside the link.
            KeyCode::Char('o') if !connected => {
                let url = match self.overlay.as_ref() {
                    Some(Overlay::Account(dialog)) => dialog.url.clone(),
                    _ => None,
                };

                match url {
                    Some(url) => self.open_url_pending = Some(url),
                    None => self.inform(
                        "there is no sign-in page yet; the runtime is still preparing one",
                        NoticeKind::Info,
                    ),
                }
            }
            KeyCode::Char('l') if connected && self.hello.serves("account.logout") => {
                self.overlay = None;
                self.issue(Call::new(Tag::AccountLogout, "account.logout", json!({})));
            }
            _ => {}
        }
    }

    fn submit_approval(&mut self) {
        let Some(Overlay::Approval {
            plane,
            id,
            request_id,
            choice,
            reason,
            rule,
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        // The fifth row answers `approve` for the rest of the session and then writes the
        // durable rule. The other four are exactly themselves.
        let remembering = choice == APPROVAL_REMEMBER;
        let rule = remembering.then_some(rule).flatten();
        let (decision, scope) = if remembering {
            (ApprovalDecision::Approve, ApprovalScope::Session)
        } else {
            APPROVAL_CHOICES[choice.min(APPROVAL_CHOICES.len() - 1)]
        };

        let marked = self
            .sessions
            .watches
            .get_mut(&(plane, id.clone()))
            .is_some_and(|watch| watch.mark_approval_response(&request_id));

        if !marked {
            return;
        }

        let params = self.routed_session_params(
            plane,
            &id,
            model::respond_approval_params_with_reason(
                &id,
                &request_id,
                decision,
                scope,
                reason.as_deref(),
            ),
        );
        self.issue(Call::new(
            Tag::Approval {
                plane,
                id: id.clone(),
                request_id: request_id.clone(),
            },
            plane.method("respond_approval"),
            params,
        ));

        // Second, and only second: the provider is waiting on the answer above, and a rule
        // written before it was sent would be a rule that outlived a refused approval.
        if let Some(rule) = rule {
            self.issue(Call::new(
                Tag::PermissionRule {
                    pattern: rule.pattern.clone(),
                },
                "permissions.add",
                model::permission_add_params(&rule.pattern, &rule.workspace),
            ));
        }
    }

    fn submit_prompt(&mut self) {
        let Some(Overlay::Prompt { kind, buffer, .. }) = self.overlay.take() else {
            return;
        };

        let value = buffer.trim().to_string();

        match kind {
            PromptKind::PreviewCapability => {
                self.preview_capability(&value);
                return;
            }
            PromptKind::AdmitCapability => {
                self.confirm_admit_capability(&value);
                return;
            }
            PromptKind::ControlObjective if value.trim().is_empty() => {
                return;
            }
            PromptKind::HistoryModule | PromptKind::GrantsPrincipal if value.is_empty() => {
                return;
            }
            PromptKind::ApprovalReason {
                plane,
                id,
                request_id,
                choice,
                reason,
            } => {
                let attached = if value.is_empty() { None } else { Some(value) };
                self.open_approval_with(plane, id, request_id, choice, attached.or(reason));
                return;
            }
            PromptKind::ControlObjective => {
                let objective = value.trim().to_string();
                self.issue(Call::new(
                    Tag::ControlSubmit,
                    "control.submit",
                    json!({ "objective": objective }),
                ));
                self.control.rows.invalidate();
                self.inform("control run submitted", NoticeKind::Info);
            }
            PromptKind::HistoryModule => {
                self.upgrade.history_module = Some(value);
                self.upgrade.history = Loadable::default();
                self.upgrade.tree.reset();
            }
            PromptKind::GrantsPrincipal => {
                self.upgrade.grants_principal = Some(value);
                self.upgrade.grants = Loadable::default();
                self.upgrade.tree.reset();
            }
        }

        self.poll_upgrade_section();
    }

    /// Return to an approval chooser after its reason prompt: the same pending request
    /// is peeked afresh from the watch, with the operator's choice and reason intact.
    fn resume_approval_choice(&mut self) {
        match self.overlay.take() {
            Some(Overlay::Prompt {
                kind:
                    PromptKind::ApprovalReason {
                        plane,
                        id,
                        request_id,
                        choice,
                        reason,
                    },
                ..
            }) => self.open_approval_with(plane, id, request_id, choice, reason),
            _ => self.overlay = None,
        }
    }

    pub(super) fn expire_chords(&mut self) {
        if self.leader_until.is_some_and(|until| self.ticks >= until) {
            self.leader_until = None;
        }

        if self.ctrl_c_until.is_some_and(|until| self.ticks >= until) {
            self.ctrl_c_until = None;
        }
    }

    pub(super) fn focused_prompt_empty(&self) -> bool {
        match self.focused_editor() {
            Some(editor) => editor.is_empty(),
            None => true,
        }
    }

    fn focused_editor(&self) -> Option<&Editor> {
        if self.overlay.is_some() {
            return None;
        }

        if self.tab != Tab::Sessions {
            return None;
        }

        if let Some(composer) = self.sessions.composer.as_ref() {
            return Some(&composer.editor);
        }

        if self.sessions.open.is_none() {
            return Some(&self.home_draft);
        }

        None
    }

    pub(super) fn focused_editor_mut(&mut self) -> Option<&mut Editor> {
        if self.overlay.is_some() {
            return None;
        }

        if self.tab != Tab::Sessions {
            return None;
        }

        if self.sessions.composer.is_some() {
            return self
                .sessions
                .composer
                .as_mut()
                .map(|composer| &mut composer.editor);
        }

        if self.sessions.open.is_none() {
            return Some(&mut self.home_draft);
        }

        None
    }

    fn session_busy(&self) -> bool {
        if self.waiting_for_open_agent_reply() {
            return true;
        }

        self.sessions.open_info().is_some_and(|session| {
            matches!(
                session.status.as_str(),
                "running" | "starting" | "awaiting_approval"
            )
        })
    }

    pub(super) fn escape_from_prompt(&mut self) {
        if self.session_busy() {
            self.interrupt_turn();
            return;
        }

        if self.focused_prompt_empty() {
            self.leave_session();
        }
    }

    fn leave_session(&mut self) {
        self.remember_composer_history();
        self.sessions.composer = None;
        self.sessions.open = None;
    }

    pub(super) fn copy_last_agent(&mut self) {
        let Some(watch) = self.sessions.open_watch() else {
            self.inform("open a session before copying a message", NoticeKind::Info);
            return;
        };

        match transcript_cells::last_agent_message(watch.entries()) {
            Some(text) => {
                self.copy_pending = Some(text);
                self.inform("copied the last agent message", NoticeKind::Info);
            }
            None => self.inform("no agent message to copy yet", NoticeKind::Info),
        }
    }

    /// `/copy raw`: the last agent message exactly as the provider wrote it.
    ///
    /// Honest limit, stated because it will stop being true: nothing in this build renders
    /// Markdown, so the bytes this copies and the bytes `ctrl+x y` copies are the same
    /// bytes today. The two verbs are separate because the *questions* are separate — "give
    /// me what I am reading" and "give me what the model sent" — and the second one has to
    /// keep answering the source once a renderer stands between them.
    pub(super) fn copy_last_agent_source(&mut self) {
        let Some(watch) = self.sessions.open_watch() else {
            self.inform("open a session before copying a message", NoticeKind::Info);
            return;
        };

        match transcript_cells::last_agent_message(watch.entries()) {
            Some(text) => {
                let bytes = text.len();
                self.copy_pending = Some(text);
                self.inform(
                    format!("copied the last agent message's source, {bytes} bytes as sent"),
                    NoticeKind::Info,
                );
            }
            None => self.inform("no agent message to copy yet", NoticeKind::Info),
        }
    }

    /// `/export [--json] [path]`.
    ///
    /// The text form is [`crate::ui::export::transcript`] — the same projection the pane
    /// draws, with the render-time caps and the gutters removed — and `--json` is
    /// [`crate::ui::export::events_ndjson`], the events themselves. Both are bounded by
    /// what this client still holds, and both say so: the text export's last line names the
    /// floor, and the notice that names the path says it for either.
    pub(super) fn export_transcript(&mut self, argument: &str) {
        let mut json = false;
        let mut path: Option<String> = None;

        for word in argument.split_whitespace() {
            match word {
                "--json" | "-j" => json = true,
                "--text" => json = false,
                _path if path.is_none() => path = Some(word.to_string()),
                _extra => {
                    self.inform(
                        "usage: /export [--json] [path] — one path, and it is the last word",
                        NoticeKind::Error,
                    );
                    return;
                }
            }
        }

        // Zero before the first frame, and a width of zero would wrap every word onto its
        // own line. Eighty is what a terminal that has not said otherwise is.
        let width = match self.terminal_width {
            0 => 80,
            width => usize::from(width),
        };

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "open a session before exporting its transcript",
                NoticeKind::Info,
            );
            return;
        };

        let Some(watch) = self.sessions.open_watch() else {
            self.inform(
                "open a session before exporting its transcript",
                NoticeKind::Info,
            );
            return;
        };

        let contents = if json {
            crate::ui::export::events_ndjson(watch)
        } else {
            crate::ui::export::transcript(watch, width)
        };
        let extent = crate::ui::export::extent(watch);
        let extension = if json { "ndjson" } else { "txt" };

        self.overlay = None;
        self.export_pending = Some(ExportRequest {
            path,
            filename: format!("ouro-{}-{}.{extension}", plane.as_str(), file_stem(&id)),
            contents,
            extent: format!(
                "exported {} of {id}",
                if json { "the events" } else { "the transcript" }
            ) + &format!(" ({extent})"),
        });
    }

    pub(super) fn request_external_editor(&mut self) {
        let text = self
            .focused_editor()
            .map(|editor| editor.text().to_string())
            .unwrap_or_default();
        self.external_editor_pending = Some(text);
    }

    pub(super) fn apply_external_editor(&mut self, text: String) {
        if self.tab != Tab::Sessions {
            self.select_tab(Tab::Sessions);
        }

        if self.sessions.open.is_some() {
            self.compose(ComposerVerb::Message);
        }

        let catalog = self.completion_catalog.clone();
        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.editor.clear_text();
            composer.editor.paste(&text, &catalog);
            composer.user_changed_draft();
            self.remember_composer_history();
            return;
        }

        if let Some(editor) = self.focused_editor_mut() {
            editor.clear_text();
            editor.paste(&text, &catalog);
            return;
        }

        self.home_draft.clear_text();
        self.home_draft.paste(&text, &catalog);
    }
}
