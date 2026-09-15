use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptKind {
    GrantsPrincipal,
    PreviewCapability,
    AdmitCapability,
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
    /// B2. Editing the optional follow-up prompt on a plan-exit modal already on screen —
    /// "what to do first" once the session has left plan mode. The same shape
    /// [`PromptKind::ApprovalReason`] has, and for the same reason: abandoning the prompt
    /// must return to the chooser with the answer intact rather than dropping a question
    /// the provider is still blocked on.
    PlanFollowUp {
        plane: Plane,
        id: String,
        request_id: String,
        choice: usize,
        follow_up: Option<String>,
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

/// T2.1. The five groups every discovery surface sorts by, in the order they are drawn.
///
/// One list, used by the palette, the `?` panel and the which-key overlay, because the
/// review's finding was not that the palette's groups were wrong — it was that each
/// surface had invented its own. A verb learned in one place is looked for under the same
/// heading in the next, and the order is the order a session is lived: what this
/// conversation *is*, what the turn in front of you is doing, the conversation as a
/// document, the runtime around it, and this client.
///
/// Ordinal order is drawing order — [`Group::ALL`] and the `derive`d `Ord` are the same
/// sequence — so a sort by group cannot disagree with the headings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Session,
    Turn,
    Conversation,
    Runtime,
    Client,
}

impl Group {
    pub const ALL: [Group; 5] = [
        Group::Session,
        Group::Turn,
        Group::Conversation,
        Group::Runtime,
        Group::Client,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "Session",
            Self::Turn => "Turn",
            Self::Conversation => "Conversation",
            Self::Runtime => "Runtime",
            Self::Client => "Client",
        }
    }

    /// The group a query names outright, so `runtime` in the palette is a filter and not a
    /// substring match. Case-insensitive, because a heading is drawn capitalised and typed
    /// however the operator types it.
    pub fn parse(query: &str) -> Option<Self> {
        let query = query.trim();

        Self::ALL
            .into_iter()
            .find(|group| group.as_str().eq_ignore_ascii_case(query))
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
    Upgrades,
    ListCapabilities,
    PreviewCapability,
    AdmitCapability,
    Logs,
    Settings,
    Help,
    /// Claude Code's `/diff`: the files this session changed, by turn.
    ShowDiff,
    /// Codex's `/raw`: cells with no frame, gutter, or app wrapping, so a native
    /// selection copies logical lines.
    RawMode,
    /// B5: the backtrack menu, for anyone who never learns the chord.
    Backtrack,
    /// B5: `interactive.fork`, where it is served.
    Fork,
    /// B4: `/model` and `/effort`, taught by prefilling the composer with the verb.
    Model,
    Effort,
    /// B8: the effective keymap, and where each binding came from.
    Keys,
    /// I2: what this session has spent.
    Cost,
    /// D9: fold the conversation now. `/compact <focus>` takes an argument; the palette
    /// row is the unfocused fold.
    Compact,
    /// D9: a fresh session seeded with a packet about this one.
    Handoff,
    /// D9: what this session can honestly say about its own context window.
    Context,
    /// D6: the turns this session can go back to.
    Rewind,
    /// A10: cycle the palette. The one command that was reachable only as a verb.
    Theme,
    /// B2: toggle plan mode on the open session. `/plan on|off` names the posture it
    /// wants; the bare verb toggles whatever the session is in now.
    Plan,
    /// Auto-approve for the open session: this client answers yes to every ordinary
    /// approval the session raises until it is turned off. Client-side — the runtime's
    /// `approval_mode` is untouched, and plan-exit questions still ask.
    AutoApprove,
    /// The open session's OS file-access posture: `/sandbox full|workspace|read-only`,
    /// carried by `interactive.configure {sandbox_mode}`. Unlike auto-approve this moves
    /// the *runtime's* posture rather than a client mode, so it is gated on the method.
    Sandbox,
    /// D4: the MCP servers this session's node runs, and the entries it refused.
    Mcp,
}

impl Command {
    pub const ALL: [Self; 40] = [
        Self::NewSession,
        Self::SwitchSession,
        Self::SessionDetails,
        Self::ShowDiff,
        Self::RawMode,
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
        Self::Upgrades,
        Self::Logs,
        Self::Settings,
        Self::Help,
        Self::ListCapabilities,
        Self::PreviewCapability,
        Self::AdmitCapability,
        Self::Backtrack,
        Self::Fork,
        Self::Model,
        Self::Effort,
        Self::Cost,
        Self::Keys,
        Self::Compact,
        Self::Handoff,
        Self::Context,
        Self::Rewind,
        Self::Theme,
        Self::Plan,
        Self::AutoApprove,
        Self::Sandbox,
        Self::Mcp,
    ];

    /// T2.1. The five groups of the parity plan, and nothing else.
    ///
    /// Two groups of thirty-five and six were a split that told a reader nothing: a
    /// palette whose first heading covers everything from "new session" to "change the
    /// model" has one heading. These five are the question each verb answers — what is
    /// this conversation, what is this turn doing, what is the conversation *as a
    /// document*, what is the runtime around it, and what is this client — and they are
    /// the same five the `?` panel, the which-key overlay and the web palette use, so a
    /// verb learned on one surface is found in the same place on the next.
    pub fn group(self) -> Group {
        match self {
            Self::NewSession
            | Self::NewSessionOptions
            | Self::WriteAccess
            | Self::SwitchSession
            | Self::CloseSession
            | Self::Fork
            | Self::Handoff => Group::Session,

            Self::Interrupt
            | Self::Steer
            | Self::Effort
            | Self::Model
            | Self::Plan
            | Self::Sandbox
            | Self::AutoApprove
            | Self::ExternalEditor => Group::Turn,

            Self::SessionDetails
            | Self::CopyLast
            | Self::CopyRawLast
            | Self::Export
            | Self::DumpScrollback
            | Self::ViewTranscript
            | Self::ShowDiff
            | Self::RawMode
            | Self::Backtrack
            | Self::Rewind
            | Self::Compact
            | Self::Context
            | Self::Cost => Group::Conversation,

            Self::ConnectChatGpt
            | Self::Runtime
            | Self::Upgrades
            | Self::ListCapabilities
            | Self::PreviewCapability
            | Self::AdmitCapability
            | Self::Logs
            | Self::Mcp => Group::Runtime,

            Self::Settings | Self::Theme | Self::Keys | Self::Help => Group::Client,
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
            Self::Upgrades => "Upgrades",
            Self::ListCapabilities => "List capability proposals",
            Self::PreviewCapability => "Preview a capability",
            Self::AdmitCapability => "Admit a capability",
            Self::Logs => "Logs",
            Self::Settings => "Settings",
            Self::Help => "Keyboard shortcuts",
            Self::ShowDiff => "Show changed files",
            Self::RawMode => "Toggle raw copy mode",
            Self::Backtrack => "Go back to an earlier message",
            Self::Fork => "Fork this session",
            Self::Model => "Change the model",
            Self::Effort => "Reasoning effort for the next turn",
            Self::Keys => "Show the effective key map",
            Self::Cost => "Show tokens and cost for this session",
            Self::Compact => "Compact this conversation now",
            Self::Handoff => "Hand this session's work to a fresh one",
            Self::Context => "Show what fills the context window",
            Self::Rewind => "Rewind to an earlier turn",
            Self::Theme => "Change the colour theme",
            Self::Plan => "Plan without editing anything",
            Self::AutoApprove => "Auto-approve everything this session asks",
            Self::Sandbox => "Change file access (OS sandbox)",
            Self::Mcp => "Show this node's MCP servers",
        }
    }

    /// The chord or verb this command answers to, as a *literal*.
    ///
    /// Only for the commands whose spelling is a slash verb rather than a key. Anything
    /// with a key goes through [`Command::action`] and the resolved keymap instead, so a
    /// rebound chord is what the palette shows (D14, B8) — see [`App::command_shortcut`].
    fn slash(self) -> &'static str {
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
            Self::Upgrades => "/upgrades",
            Self::ListCapabilities => "/capabilities",
            Self::PreviewCapability => "/preview",
            Self::AdmitCapability => "/admit",
            Self::Logs => "/logs",
            Self::Settings => "/settings",
            Self::Help => "?",
            Self::ShowDiff => "/diff",
            Self::RawMode => "/raw",
            Self::Backtrack => "esc esc",
            Self::Fork => "/fork",
            Self::Model => "/model",
            Self::Effort => "/effort",
            Self::Keys => "/keys",
            Self::Cost => "/cost",
            Self::Compact => "/compact",
            Self::Handoff => "/handoff",
            Self::Context => "/context",
            Self::Rewind => "/rewind",
            Self::Theme => "/theme",
            Self::Plan => "/plan",
            Self::AutoApprove => "/auto-approve",
            Self::Sandbox => "/sandbox",
            Self::Mcp => "/mcp",
        }
    }

    /// The keymap action this command is also reachable by, where there is one.
    ///
    /// The single place the palette's shortcut column and the keymap agree: adding a key
    /// to a command means naming its action here, and the column follows.
    pub fn action(self) -> Option<Action> {
        Some(match self {
            Self::NewSession => Action::LeaderNew,
            Self::NewSessionOptions => Action::LeaderNewOptions,
            Self::SwitchSession => Action::LeaderSessions,
            Self::SessionDetails => Action::LeaderDetails,
            Self::CopyLast => Action::LeaderCopy,
            Self::DumpScrollback => Action::LeaderScrollback,
            Self::ViewTranscript => Action::LeaderEditorView,
            Self::Interrupt => Action::Interrupt,
            Self::Steer => Action::LeaderSteer,
            Self::ExternalEditor => Action::Editor,
            Self::CloseSession => Action::LeaderEnd,
            Self::Settings => Action::LeaderSettings,
            Self::Theme => Action::LeaderTheme,
            Self::Help => Action::Help,
            Self::Backtrack => Action::Backtrack,
            Self::AutoApprove => Action::LeaderAutoApprove,
            _slash_only => return None,
        })
    }

    /// T2.1. Whether this row answers the query: its label, or the chord it is reached by.
    ///
    /// The group name is *not* matched as a substring. It used to be, and the effect was
    /// that typing `co` — two letters of `copy`, `compact`, `context` — returned all
    /// thirty-five rows of the group called "Coding", because every one of them contained
    /// those letters in a column the operator was not typing about. A query that is a
    /// group name *exactly* is handled one level up, in [`CommandPalette::matching`],
    /// where it filters to that group instead of matching rows.
    fn matches(self, query: &str, shortcut: &str) -> bool {
        let query = query.trim().to_ascii_lowercase();
        query.is_empty()
            || self.label().to_ascii_lowercase().contains(&query)
            || shortcut.to_ascii_lowercase().contains(&query)
    }
}

#[derive(Debug, Default)]
pub struct CommandPalette {
    pub query: String,
    pub selected: usize,
}

impl CommandPalette {
    /// Every command that answers the query, in the order the palette draws them — before
    /// the capability filter. [`App::palette_commands`] is what a caller draws or
    /// activates; this is the half that does not need to know which session is open.
    ///
    /// T2.1. Sorted by group, then by [`Command::ALL`] order within it. The rows used to
    /// come out in `ALL` order with a heading printed on every change of group, and `ALL`
    /// crossed between the two groups six times — so a palette that fitted twenty rows
    /// printed each heading three times and put "Settings" a page away from "Theme". A
    /// stable sort is the whole fix: every heading appears exactly once, and the order
    /// inside a group is still the deliberate one the table is written in.
    pub fn matching(&self, offered: &[Command], keymap: &Keymap) -> Vec<Command> {
        // A query that *is* a group name selects the group. It is the one query where a
        // substring match on the group would be right and every other one where it would
        // be wrong, so it is answered here and nowhere else.
        let group = Group::parse(&self.query);

        let mut rows = offered
            .iter()
            .copied()
            .filter(|command| match group {
                Some(group) => command.group() == group,
                None => command.matches(&self.query, &shortcut_of(*command, keymap)),
            })
            .collect::<Vec<_>>();

        rows.sort_by_key(|command| command.group());
        rows
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
                // T2.1. Two gates, not one. The transport capability says whether this
                // verb *can ever* work here; `session_busy` says whether there is a turn
                // for it to act on. Both rows used to be offered on an idle or ended
                // session, where pressing them does nothing at all — which is the same
                // "advertising a verb that will be refused" failure D14 names, arrived at
                // from the other direction.
                Command::Steer => self.steer_offered() && self.session_busy(),
                Command::Interrupt => {
                    self.open_capabilities().interrupt.offered() && self.session_busy()
                }
                Command::Fork => self.fork_offered(),
                Command::Model => self.hello.serves("interactive.configure"),
                // B2/D4. Same rule: a control the runtime cannot serve is not offered.
                // `/plan` additionally needs a session to be about — the posture belongs
                // to one conversation, not to the client.
                Command::Plan => {
                    self.sessions.open.is_some() && self.hello.serves("interactive.configure")
                }
                // Client-side, so no `hello.methods` gate — but like `/plan` it needs a
                // session to be about.
                Command::AutoApprove => self.sessions.open.is_some(),
                // The runtime's own posture, so the same two questions `/plan` asks: is
                // there a session, and does this gateway serve the verb that moves one.
                Command::Sandbox => {
                    self.sessions.open.is_some() && self.hello.serves("interactive.configure")
                }
                Command::Mcp => self.hello.serves("mcp.list"),
                // D9/D6. Native only, and the gate is the same two questions the verb
                // itself asks: a row that always refuses is a row that should not be
                // drawn.
                Command::Compact | Command::Handoff | Command::Rewind => {
                    self.context_verbs_offered()
                }
                // Answers for every transport, with different amounts of truth.
                Command::Context => self.context_overlay_offered(),
                _always => true,
            })
            .collect::<Vec<_>>();

        palette.matching(&offered, &self.keymap)
    }

    /// What the palette prints in a command's shortcut column.
    ///
    /// The keymap first, always: a command with a key shows the key the operator would
    /// actually press, including one they rebound and including `off` — which reads as
    /// "this has no key any more", not as a chord that does nothing. A command with no
    /// key shows its slash verb, which is the only spelling it has.
    pub fn command_shortcut(&self, command: Command) -> String {
        shortcut_of(command, &self.keymap)
    }
}

/// [`App::command_shortcut`] for a caller holding a map and no App — the palette's own
/// filter runs before the rows are drawn.
fn shortcut_of(command: Command, keymap: &Keymap) -> String {
    match command.action() {
        Some(action) => keymap.label(action),
        None => command.slash().to_string(),
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
    Location(Location),
    Commands(CommandPalette),
    Account(Box<AccountDialog>),
    SessionPicker {
        selected: Option<(Plane, String)>,
    },
    Help,
    /// B8. `/keys`: the effective keymap, with the entries that came from `config.toml`
    /// marked and the lines of it this build could not act on named.
    Keys {
        scroll: usize,
    },
    /// I2. `/cost` and `/usage`: what the runtime says this session has spent, beside what
    /// the transcript this client is holding folds to.
    Cost {
        scroll: usize,
    },
    /// This client's own preferences, beside the facts the runtime reports.
    Settings(Box<Settings>),
    /// T2.9. `/theme` with no argument, and `leader.theme`: the palettes this build has,
    /// previewed on the screen already showing the conversation.
    ///
    /// The preview really is the switch — there is nothing useful to preview a palette in
    /// but the transcript — but a preview that *wrote* it was the problem: bare `/theme`
    /// cycled one step and saved `config.toml` on the spot, so looking at the next palette
    /// and looking at the next palette **and keeping it** were the same keystroke. This
    /// separates them: moving previews, `Enter` writes, `Esc` puts back what was drawing
    /// before the overlay opened and writes nothing at all.
    Theme {
        choice: usize,
        /// What was drawing when this opened, so `Esc` can restore it exactly. Held rather
        /// than re-read on close: the config is what `Enter` edits, and restoring from it
        /// would restore whatever the last preview had already made of it.
        previous: super::super::theme::ThemeName,
    },
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
        /// gateway serves `permissions.add`. Workspace-scoped rules also need the session
        /// to name a workspace; Computer Use remember is user-scoped and does not.
        rule: Option<ApprovalRule>,
        /// Why the fifth answer is missing although the payload suggested a rule. Shown,
        /// because "this runtime cannot remember that" and "nothing was suggested" are
        /// different facts.
        rule_absent: Option<&'static str>,
        /// `ctrl+o` inside the modal: draw the diff at its full retained length instead of
        /// the pane-height budget.
        expanded: bool,
        /// B2, plan exits only: what to do first once the session has left plan mode.
        ///
        /// Optional by construction — the runtime treats a blank one as absent and emits
        /// the held terminal event instead of starting a turn — so an operator who just
        /// wants out of plan mode presses `Enter` and is done.
        follow_up: Option<String>,
    },
    /// D4. The MCP servers one node runs for the native agent, and the entries its loader
    /// refused. Read fresh every time it opens: a server's state is exactly the thing that
    /// changes while nobody is looking.
    Mcp {
        node: Option<String>,
        list: Box<crate::model::McpList>,
        choice: usize,
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
    /// Claude Code's `/diff`, scoped to what this client holds. Built when it opens.
    Diff(Box<super::super::diff::DiffOverlay>),
    /// B5. The last ten user turns of the open session, and the two things that can be
    /// done with one. Opened by `Esc Esc` (rebindable), `/backtrack`, or the palette.
    Backtrack {
        plane: Plane,
        id: String,
        /// `(sequence, text)`, oldest first, from `input_accepted`.
        entries: Vec<(u64, String)>,
        choice: usize,
        /// Whether `interactive.fork` is served *and* the transport has not been declared
        /// unable to fork. Both halves, because the method gate and the capability gate
        /// are different questions and this menu must not offer a verb that fails either.
        fork_offered: bool,
        /// D6. Whether `/rewind` is offered here as well as the two above. A rewind is a
        /// third answer to "go back", and it belongs in the menu that asks the question —
        /// but only where this session's transport is the one that keeps checkpoints.
        rewind_offered: bool,
    },
    /// D9. `/context`: what this session can honestly say about its own context window.
    Context {
        context: Box<crate::model::native::SessionContext>,
        scroll: usize,
    },
    /// D6. `/rewind`: the turns this session can go back to, what each of them cannot put
    /// back, and the three-way choice of what to restore.
    ///
    /// `confirming` is the second screen rather than a second overlay: the warning a turn
    /// carries has to be read *before* the choice is committed, and a menu that acted on
    /// the first Enter would be the silently-under-delivering rewind D10 exists to not be.
    Rewind {
        plane: Plane,
        id: String,
        points: Vec<crate::model::native::RewindPoint>,
        choice: usize,
        what: usize,
        confirming: bool,
    },
    /// G2. The last thing one session's agent said, without leaving the list.
    ///
    /// Read out of the transcript this client already holds — never a fresh call — so a
    /// row whose events were never subscribed says so rather than showing an empty box.
    Peek {
        plane: Plane,
        id: String,
        title: String,
        text: Option<String>,
        /// T2.6. Whether the session picker is underneath, so leaving goes back to it.
        ///
        /// `Space` is advertised as looking *without leaving the list* — the whole reason
        /// a triage key is cheap — and an overlay that replaced the list made the cheap
        /// key cost the place in it.
        ///
        /// No separate copy of the picker's selection, because there is only one answer
        /// it could hold: the picker peeks the row under its own cursor, so this overlay's
        /// `plane` and `id` *are* that selection. Carrying a second copy would be a second
        /// thing that could disagree with it.
        from_picker: bool,
    },
}

/// The four answers `interactive.respond_approval` accepts, in the order the modal lists
/// them. Exactly `Jido.Harness.ApprovalResponse`'s two enums crossed; nothing else is
/// offered because nothing else is accepted.
/// How far `PageDown` moves inside the `/diff` pager. A fixed page rather than the drawn
/// height because the overlay's key handler runs outside the frame that knows it.
pub const DIFF_PAGE: usize = 16;

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
/// is the point of computing it server-side in the runtime's permission engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRule {
    pub pattern: String,
    pub workspace: String,
}

impl App {
    // ----- overlays ------------------------------------------------------------------

    /// `?`, always from the top of the table.
    pub(super) fn open_help(&mut self) {
        self.help_scroll = 0;
        self.overlay = Some(Overlay::Help);
    }

    /// `/keys`, the map itself. Toggles, like the palette: pressing the verb twice is how
    /// an operator checks a chord and gets back to what they were doing.
    pub fn open_keymap(&mut self) {
        self.overlay = match &self.overlay {
            Some(Overlay::Keys { .. }) => None,
            _other => Some(Overlay::Keys { scroll: 0 }),
        };
    }

    /// `/cost` and `/usage`, which are one overlay because they are one question.
    pub fn open_cost(&mut self) {
        self.overlay = match &self.overlay {
            Some(Overlay::Cost { .. }) => None,
            _other => Some(Overlay::Cost { scroll: 0 }),
        };
    }

    pub(super) fn open_quit(&mut self) {
        if matches!(self.overlay, Some(Overlay::Account(_))) {
            self.cancel_account();
        }
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
        if matches!(self.overlay, Some(Overlay::Location(_))) {
            self.location_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::New(_))) {
            self.new_session_key(key);
            return;
        }

        if matches!(self.overlay, Some(Overlay::Settings(_))) {
            self.settings_key(key);
            return;
        }

        let Some(overlay) = self.overlay.as_mut() else {
            return;
        };

        match overlay {
            Overlay::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter => self.overlay = None,
                // The table is grouped and it grows; the panel scrolls rather than
                // silently ending, and the limits at its foot are pinned outside this.
                KeyCode::Char('j') | KeyCode::Down => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(10),
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
                _ => {}
            },
            // Two read-only pages with the same discipline as `?`: scroll, or leave.
            Overlay::Keys { scroll } | Overlay::Cost { scroll } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.overlay = None,
                KeyCode::Char('j') | KeyCode::Down => *scroll = scroll.saturating_add(1),
                KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::PageDown => *scroll = scroll.saturating_add(10),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                _ => {}
            },
            // The overlay owns its own cursor discipline, in the module that knows what a
            // page of a diff is.
            Overlay::Diff(diff) => {
                if !diff.key(key.code, DIFF_PAGE) {
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
                // A10: a numbered menu is only a numbered menu if the number selects.
                // Screen-reader mode only, because `1` through `9` are ordinary characters
                // everywhere else and taking them would be a keybinding nobody asked for.
                KeyCode::Char(digit)
                    if super::super::access::screen_reader()
                        && super::super::access::row_for_digit(digit)
                            .is_some_and(|row| row < options.len()) =>
                {
                    *choice = super::super::access::row_for_digit(digit).expect("a digit row");
                }
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
                detail,
                follow_up,
                ..
            } => {
                // B2. A plan exit's rows are the payload's own three options; every other
                // approval's are the four fixed answers plus the durable fifth.
                let planning = detail.plan.is_some();
                let rows = match detail.plan.as_ref() {
                    Some(plan) => plan.choices.len(),
                    None => APPROVAL_CHOICES.len() + usize::from(rule.is_some()),
                };
                let last = rows.saturating_sub(1);

                match key.code {
                    KeyCode::Esc => self.overlay = None,
                    KeyCode::Char('j') | KeyCode::Down => *choice = (*choice + 1).min(last),
                    KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                    // A10, as above: the number on the row is the key that picks it.
                    //
                    // T2.7. For everyone, not only under screen-reader mode. The general
                    // rule — that `1` through `9` are ordinary characters and taking them
                    // would be a keybinding nobody asked for — is about surfaces where
                    // something is being *typed*. Nothing is being typed here: this modal
                    // draws a numbered list of at most five answers and has no text field
                    // until `r` or `Tab` opens one. A number that does not select on a
                    // numbered menu is a number printed for decoration.
                    KeyCode::Char(digit)
                        if super::super::access::row_for_digit(digit)
                            .is_some_and(|row| row < rows) =>
                    {
                        *choice = super::super::access::row_for_digit(digit).expect("a digit row");
                    }
                    // Claude Code's `Ctrl+O`, inside the modal: the diff at full retained
                    // length instead of the rows the popup could spare for it.
                    KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        *expanded = !*expanded;
                    }
                    // Claude Code offers the comment field on `Tab` from the answer row;
                    // this client has always offered it on `r`. Both, because `r` is what
                    // the modal's own hint says and `Tab` is what a reader arrives with.
                    // B2. On a plan exit the same two keys open the follow-up composer
                    // instead of the reason field: `respond_approval` carries a plan exit's
                    // `reason` only as a fallback way of naming the choice, so offering it
                    // here would be offering a second, weaker way to say what the selected
                    // row already says.
                    KeyCode::Char('r') | KeyCode::Tab if planning => {
                        let kind = PromptKind::PlanFollowUp {
                            plane: *plane,
                            id: id.clone(),
                            request_id: request_id.clone(),
                            choice: *choice,
                            follow_up: follow_up.clone(),
                        };
                        let buffer = follow_up.clone().unwrap_or_default();
                        self.overlay = Some(Overlay::Prompt {
                            kind,
                            label: "what to do first — enter attaches it, an empty line keeps none"
                                .to_string(),
                            buffer,
                        });
                    }
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
            // B5. Two verbs, and the menu says which one Enter is before it is pressed:
            // an "Enter forks" that quietly edited instead would be exactly the rewind
            // that silently under-delivers (Claude Code #18516).
            Overlay::Backtrack {
                entries,
                choice,
                fork_offered,
                rewind_offered,
                ..
            } => {
                let last = entries.len().saturating_sub(1);
                let forkable = *fork_offered;
                let rewindable = *rewind_offered;

                match key.code {
                    KeyCode::Esc => self.overlay = None,
                    KeyCode::Char('j') | KeyCode::Down => *choice = (*choice + 1).min(last),
                    KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                    KeyCode::Char('e') => self.backtrack_edit(),
                    KeyCode::Char('f') if forkable => self.backtrack_fork(),
                    // D6. The third answer to "go back", where this session's transport
                    // is the one that keeps checkpoints. It leaves the menu and opens the
                    // rewind's own, because a rewind states what it cannot restore before
                    // it is chosen and there is no room for that here.
                    KeyCode::Char('r') if rewindable => {
                        self.overlay = None;
                        self.open_rewind();
                    }
                    KeyCode::Enter if forkable => self.backtrack_fork(),
                    KeyCode::Enter => self.backtrack_edit(),
                    _ => {}
                }
            }
            // T2.9. Moving previews; `Enter` keeps; `Esc` puts back. Nothing reaches
            // `config.toml` until `Enter`, which is the whole point of the overlay.
            Overlay::Theme { choice, previous } => {
                let previous = *previous;
                let last = super::super::theme::ThemeName::ALL.len() - 1;

                let moved = match key.code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        *choice = (*choice + 1).min(last);
                        true
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        *choice = choice.saturating_sub(1);
                        true
                    }
                    _elsewhere => false,
                };

                if moved {
                    let name = super::super::theme::ThemeName::ALL[*choice];
                    // The process-wide install only: this is a look, not a decision.
                    super::super::switch_theme(name);
                    return;
                }

                match key.code {
                    KeyCode::Enter => {
                        let name = super::super::theme::ThemeName::ALL[*choice];
                        self.overlay = None;
                        // The App's own, which is the one that records and announces it.
                        self.switch_theme(name);
                    }
                    KeyCode::Esc | KeyCode::Char('q') => {
                        self.overlay = None;
                        super::super::switch_theme(previous);
                    }
                    _ => {}
                }
            }
            // D9. A read-only page, with the same discipline as `?`.
            Overlay::Context { scroll, .. } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.overlay = None,
                KeyCode::Char('j') | KeyCode::Down => *scroll = scroll.saturating_add(1),
                KeyCode::Char('k') | KeyCode::Up => *scroll = scroll.saturating_sub(1),
                KeyCode::PageDown => *scroll = scroll.saturating_add(10),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                _ => {}
            },
            // D6. Two screens: the turns, then what to restore. `Esc` steps back one
            // screen rather than closing outright, because the second screen is where the
            // warning is and stepping out of it by accident should not cost the menu.
            Overlay::Rewind {
                points,
                choice,
                what,
                confirming,
                ..
            } => {
                let last = points.len().saturating_sub(1);

                if *confirming {
                    match key.code {
                        KeyCode::Esc => *confirming = false,
                        KeyCode::Char('j') | KeyCode::Down => {
                            *what = (*what + 1).min(super::native::REWIND_WHAT.len() - 1)
                        }
                        KeyCode::Char('k') | KeyCode::Up => *what = what.saturating_sub(1),
                        KeyCode::Enter => self.rewind_confirm(),
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => self.overlay = None,
                        KeyCode::Char('j') | KeyCode::Down => *choice = (*choice + 1).min(last),
                        KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                        KeyCode::Enter => *confirming = true,
                        _ => {}
                    }
                }
            }
            // G2. One key in, one key out. `r` goes on from the peek to the reply, so a
            // triage pass is Space to look and r to answer without a detour.
            //
            // T2.6. Four keys, and each of them does what the hint says. `Enter` *opens*,
            // which is what the hint has always claimed and what the picker's own Enter
            // does; `Space` and `q` put the peek away the way it was opened; `Esc` steps
            // back to the list rather than out of it, because a triage pass that lost its
            // place every time it looked at a row is a pass nobody finishes.
            Overlay::Peek {
                plane,
                id,
                from_picker,
                ..
            } => {
                let (plane, id, from_picker) = (*plane, id.clone(), *from_picker);

                match key.code {
                    KeyCode::Esc | KeyCode::Char('q' | ' ') => {
                        self.restore_picker(from_picker.then(|| (plane, id.clone())))
                    }
                    KeyCode::Enter => {
                        self.overlay = None;
                        self.open_session(plane, id);
                    }
                    KeyCode::Char('r') => {
                        self.overlay = None;
                        self.reply_to_session(plane, id);
                    }
                    _ => {}
                }
            }
            // D4. A reading overlay: there is no `mcp.add` on the wire, by design, so
            // there is nothing here to press Enter on. `r` re-reads, because a server's
            // state is exactly the thing that changes while it is on screen.
            Overlay::Mcp { list, choice, .. } => {
                let last = (list.servers.len() + list.refusals.len()).saturating_sub(1);

                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.overlay = None,
                    KeyCode::Char('j') | KeyCode::Down => *choice = (*choice + 1).min(last),
                    KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                    KeyCode::Char('r') => self.open_mcp(),
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
            | Overlay::Location(_)
            | Overlay::Account(_)
            | Overlay::SessionPicker { .. }
            | Overlay::New(_)
            | Overlay::Settings(_) => {}
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
            Command::Backtrack => {
                self.overlay = None;
                self.open_backtrack(None);
            }
            Command::Fork => {
                self.overlay = None;
                self.fork_open_session();
            }
            // The palette teaches the verb rather than replacing it: both take an argument
            // the operator has to type anyway, and a second surface for choosing a model
            // would be a second place for it to disagree with the runtime.
            Command::Model => {
                self.overlay = None;
                self.prefill_composer("/model ");
            }
            Command::Effort => {
                self.overlay = None;
                self.prefill_composer("/effort ");
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
            Command::Runtime => {
                self.overlay = None;
                self.select_tab(Tab::Dashboard);
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
            Command::Settings => {
                self.overlay = None;
                self.open_settings();
            }
            Command::Help => {
                self.open_help();
            }
            Command::Keys => {
                self.overlay = None;
                self.open_keymap();
            }
            Command::Cost => {
                self.overlay = None;
                self.open_cost();
            }
            Command::Compact => {
                self.overlay = None;
                self.compact_session(None);
            }
            // Both take words, so the palette teaches the verb by prefilling the composer
            // rather than acting on an argument the operator has not typed yet — the same
            // thing `/model` and `/effort` do.
            Command::Handoff => {
                self.overlay = None;
                self.prefill_composer("/handoff ");
            }
            Command::Context => {
                self.overlay = None;
                self.open_context();
            }
            Command::Rewind => {
                self.overlay = None;
                self.open_rewind();
            }
            // T2.9. The list, not a step through it. A palette is a thing you look at and
            // keep or put back, and the palette row was the one place the verb was reached
            // by people who do not know the names.
            Command::Theme => {
                self.overlay = None;
                self.open_theme_picker();
            }
            // B2. The palette row toggles, because the palette has nowhere to type
            // `on`/`off`; the slash verb takes both.
            Command::Plan => {
                self.overlay = None;
                self.configure_plan(None);
            }
            Command::AutoApprove => {
                self.overlay = None;
                self.set_auto_approve(None);
            }
            // Three postures have no toggle, so the palette teaches the verb by
            // prefilling it — the same thing `/model` does with an argument the operator
            // has to state rather than have guessed for them. The widest of the three
            // takes the OS sandbox away; a palette row that picked for them could pick it.
            Command::Sandbox => {
                self.overlay = None;
                self.prefill_composer("/sandbox ");
            }
            Command::Mcp => {
                self.overlay = None;
                self.open_mcp();
            }
            Command::ShowDiff => {
                self.overlay = None;
                let Some(watch) = self.sessions.open_watch() else {
                    self.inform(
                        "open a session before reviewing what it changed",
                        NoticeKind::Info,
                    );
                    return;
                };
                // Built once, when it opens. The projection is the transcript's, so this
                // list cannot disagree with the conversation about which turn changed what.
                let cells = super::super::transcript_cells::project(watch.entries());
                let pruned = watch.floor();
                self.overlay = Some(Overlay::Diff(Box::new(
                    super::super::diff::DiffOverlay::new(&cells, pruned),
                )));
            }
            Command::RawMode => {
                self.overlay = None;
                self.toggle_raw_transcript();
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
            // G2. Peek and reply, on the surface that has a cursor. `Space` shows the
            // last thing the agent said without leaving the list — the question triage
            // exists to answer is "does this one need me", and opening a transcript to
            // find out costs the place in the list. `r` is the answer to "yes".
            KeyCode::Char(' ') => {
                if let Some((plane, id)) = selected.or_else(|| self.sessions.picker_key(index)) {
                    self.peek_session(plane, id);
                }
            }
            KeyCode::Char('r') => {
                let session = selected.or_else(|| self.sessions.picker_key(index));
                self.overlay = None;

                if let Some((plane, id)) = session {
                    self.reply_to_session(plane, id);
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
            KeyCode::Esc => self.cancel_account(),
            KeyCode::Char('r')
                if !connected
                    && matches!(&self.overlay, Some(Overlay::Account(dialog)) if !dialog.pending) =>
            {
                let intent = self.home_login_start.take();
                self.open_account();
                if matches!(self.overlay, Some(Overlay::Account(_))) {
                    self.home_login_start = intent;
                }
            }
            KeyCode::Enter if connected => self.cancel_account(),
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

    /// B2. Sends one plan-exit answer, with the explicit choice where this gateway takes
    /// one and without it where a previous call proved it does not.
    ///
    /// The latch matters because the refusal is not distinguishable after the fact: an
    /// older gateway collapses every `structured_approval/1` failure into one `-32602` with
    /// a generic sentence, so "this build does not know `provider_options`" and "that
    /// answer was malformed" arrive identically. Retrying once per session and remembering
    /// the outcome is the only way to tell them apart without asking a person to.
    pub(super) fn submit_plan_exit(
        &mut self,
        plane: Plane,
        id: String,
        request_id: String,
        choice: PlanChoice,
        follow_up: Option<String>,
    ) {
        let marked = self
            .sessions
            .watches
            .get_mut(&(plane, id.clone()))
            .is_some_and(|watch| watch.mark_approval_response(&request_id));

        if !marked {
            return;
        }

        let follow_up = follow_up.filter(|text| !text.trim().is_empty());
        let explicit = !self.plan_options_refused;

        let answer = if explicit {
            model::respond_approval_params_with_plan(&id, &request_id, choice, follow_up.as_deref())
        } else {
            let (decision, scope) = choice.decision();
            model::respond_approval_params(&id, &request_id, decision, scope)
        };

        let params = self.routed_session_params(plane, &id, answer);

        // A call sent *without* the explicit choice is an ordinary approval as far as the
        // answer handler is concerned: there is nothing left to fall back to.
        let tag = if explicit {
            Tag::PlanExit {
                plane,
                id: id.clone(),
                request_id: request_id.clone(),
                choice,
                had_follow_up: follow_up.is_some(),
            }
        } else {
            Tag::Approval {
                plane,
                id: id.clone(),
                request_id: request_id.clone(),
            }
        };

        self.issue(Call::new(tag, plane.method("respond_approval"), params));
    }

    fn submit_approval(&mut self) {
        let Some(Overlay::Approval {
            plane,
            id,
            request_id,
            choice,
            reason,
            rule,
            detail,
            follow_up,
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        // B2. A plan exit answers on its own path: three rows, an explicit `choice`, and a
        // follow-up prompt the four-way answer has nowhere to put.
        if let Some(plan) = detail.plan.as_ref() {
            let Some(option) = plan.choices.get(choice).or_else(|| plan.choices.first()) else {
                return;
            };

            self.submit_plan_exit(plane, id, request_id, option.choice, follow_up);
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
            PromptKind::GrantsPrincipal if value.is_empty() => {
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
                self.open_approval_with(plane, id, request_id, choice, attached.or(reason), None);
                return;
            }
            PromptKind::PlanFollowUp {
                plane,
                id,
                request_id,
                choice,
                follow_up,
            } => {
                // A cleared prompt clears the follow-up: "I changed my mind about running
                // something first" has to be expressible, and the only way to say it is an
                // empty line replacing the old text rather than falling back to it.
                let attached = if value.is_empty() {
                    None
                } else {
                    Some(model::clip_plan_follow_up(&value))
                };
                let _ = follow_up;
                self.open_approval_with(plane, id, request_id, choice, None, attached);
                return;
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
            }) => self.open_approval_with(plane, id, request_id, choice, reason, None),
            Some(Overlay::Prompt {
                kind:
                    PromptKind::PlanFollowUp {
                        plane,
                        id,
                        request_id,
                        choice,
                        follow_up,
                    },
                ..
            }) => self.open_approval_with(plane, id, request_id, choice, None, follow_up),
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

    /// One predicate with `App::turn_running`, which the interrupt key and the `ctrl+c`
    /// state machine read; the palette gates on the same fact.
    fn session_busy(&self) -> bool {
        self.turn_running()
    }

    /// `Esc` in the composer, after the interrupt has had its chance at the key.
    ///
    /// Interrupting is no longer decided here. `App::interrupt_key` claims the key bound
    /// to `Action::Interrupt` while a turn is running, so this runs only when there is
    /// nothing to interrupt — or when the operator moved the interrupt somewhere else,
    /// in which case `Esc` genuinely no longer interrupts and must not pretend to.
    ///
    /// The two meanings that are left are the two `Esc` has always had on an idle
    /// session, and the first of them used to do nothing at all: `docs/TUI.md` said a
    /// draft was kept and the code dropped the keystroke (R1 §2.1). The draft goes where
    /// `up` finds it rather than into a modal nobody asked for.
    pub(super) fn escape_from_prompt(&mut self) {
        if self.focused_prompt_empty() {
            self.leave_session();
            return;
        }

        let remembered = self
            .sessions
            .composer
            .as_mut()
            .and_then(|composer| {
                let remembered = composer.editor.accept_submission();
                composer.user_changed_draft();
                remembered
            })
            .is_some();

        if !remembered {
            return;
        }

        self.remember_composer_history();

        let mut note = format!(
            "draft cleared; {} brings it back",
            self.keymap.label(Action::QueueRetract)
        );

        // This key only gets here mid-turn when the interrupt lives somewhere else, and
        // whoever pressed it out of habit is owed the key that is one.
        if self.session_busy() && self.bound(Action::Interrupt) {
            note.push_str(&format!(
                " · {} interrupts the turn",
                self.keymap.label(Action::Interrupt)
            ));
        }

        self.inform(note, NoticeKind::Info);
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
