//! The whole UI as a state machine, with no I/O in it.
//!
//! ## Why this type does not hold a `Client`
//!
//! A TUI that awaits an RPC inside its event loop stops drawing for as long as the
//! runtime takes to answer, and this runtime has methods with a 120s ceiling. So the App
//! never calls: it *emits* [`Call`]s into a queue, the driver spawns a task per call, and
//! the answer comes back as [`Msg::Answer`]. Every panel keeps its last good value and a
//! `pending` flag, so a refresh in flight renders as the previous data with a spinner
//! rather than as a blank pane.
//!
//! The same shape is what makes the UI testable without a socket: a test applies messages
//! and reads the queue, which is how the approval modal's parameters and the resync
//! arithmetic are pinned below and in `tests/ui.rs`.
//!
//! ## The refresh cadence, and the one method that is not on it
//!
//! Cheap list methods for the *visible* tab are polled every few seconds. Transcript data
//! is never polled — that is what a subscription is for, and replaying on a timer would
//! be asking the runtime to re-send history it already pushed. `runtime.providers` is the
//! one list on a slow cadence: each provider probe shells out to check an installed
//! executable ([methods.ex] `@provider_probe_timeout`), so polling it beside
//! `runtime.status` would fork a process per provider every three seconds.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::TryRngCore;
use serde_json::{json, Value};

use crate::config::{Config, Defaults, ONBOARDING_PROMPTS};
use crate::fleet::Profile as FleetProfile;
use crate::fleet_add::{AddKind, AddPlan, Intent as FleetIntent, JoinIntent};
use crate::keymap::{Action, Keymap};
use crate::model::{
    self, new_session_id, AccountState, ApprovalDecision, ApprovalMode, ApprovalScope, Attachment,
    Capabilities, CursorPruned, Effort, Event, EventType, Plane, ProviderEntry, RuntimeStatus,
    SandboxMode, SessionInfo, StartRequest, StartedRef, TurnInput,
};
use crate::proto::{ErrorCode, Hello, Notification, RpcError};
use crate::runtime::LogRing;
use crate::transport::ClientError;

use super::details::DetailsView;
use super::editor::{CompletionCatalog, Editor, EditorAction};
use super::notify::{self, Terminal as TerminalIdentity};
use super::transcript::{ApprovalDetail, Note, Watch};
use super::transcript_cells;
use super::tree::{TreeState, TreeView};

mod answers;
mod details;
mod footer;
mod home;
mod keys;
mod machines;
pub mod native;
mod overlays;
mod session;
mod settings;
mod start;
mod streaming;

/// Internal state types shared between the modules above. Re-exported here so each
/// module's `use super::*` reaches them without naming a sibling.
use session::{
    ComposerRestoreDisposition, PendingComposerReconciliation, PendingFirstMessage,
    PendingReconciliationKind, SavedComposerDraft, SessionRecovery,
};

pub use footer::{SessionFacts, TranscriptFacts};
pub use machines::{
    AddField, AddMachine, AddMethod, AddStep, FleetJob, FormField, FormKind, MachineAction,
    MachineCandidate, MachineChoice, MachineForm, MachineReport, MachineSecurity, MachineSummary,
    Machines, MenuItem,
};
pub use overlays::{
    approval_at, approval_index, approval_label, sandbox_at, sandbox_index, sandbox_label,
    AccountDialog, AccountFlow, ApprovalRule, Command, CommandPalette, Overlay, PromptKind,
    APPROVAL_CHOICES, APPROVAL_REMEMBER, APPROVAL_ROWS, SANDBOX_ROWS,
};
pub use session::{Composer, ComposerVerb, QueuedDraft, SessionsTab, QUEUE_LIMIT};
pub use settings::{Settings, SettingsField};
pub use start::{provider_choices, NewField, NewSession, ProviderChoice};

/// The driver's tick. Pi and OpenCode animate the working spinner at ~80ms; poll
/// cadences below are counted in these frames so wall-clock meaning stays put.
pub const TICK: Duration = Duration::from_millis(80);

/// [`TICK`] in milliseconds, for the chord windows that are specified in wall-clock time.
pub const TICK_MS: u64 = 80;

const STATUS_TICKS: u64 = 38; // ~3s
const LIST_TICKS: u64 = 38; // ~3s
const UPGRADE_TICKS: u64 = 63; // ~5s
const DETAIL_TICKS: u64 = 125; // ~10s: `Mesh.state/1` is a whole agent's state tree
const PROVIDER_TICKS: u64 = 750; // ~60s: each entry probes an executable
const ACCOUNT_TICKS: u64 = 375; // ~30s; ~1s while a managed login is pending
const ACCOUNT_LOGIN_TICKS: u64 = 13;
const NOTICE_TICKS: u64 = 63;
/// OpenCode waits two seconds after the leader key; this is the same window in ticks.
const LEADER_TICKS: u64 = 25;

/// How long the first Escape of an `Esc Esc` stays armed, in milliseconds.
///
/// Long enough to be a chord and short enough that an Escape pressed twice a second apart
/// is two Escapes. Named in milliseconds because that is what the doc states and what an
/// operator would measure; [`BACKTRACK_TICKS`] is the same number in this client's clock.
pub const BACKTRACK_WINDOW_MS: u64 = 400;

/// [`BACKTRACK_WINDOW_MS`] in ticks, rounded up so the window is never *shorter* than
/// advertised.
pub const BACKTRACK_TICKS: u64 = BACKTRACK_WINDOW_MS.div_ceil(TICK_MS);
/// Pi's double Ctrl+C quit: the second press has to arrive inside this window.
const CTRL_C_QUIT_TICKS: u64 = 13;
static TURN_ID_FALLBACK_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// `interactive.start` and `coding.start` declare a 120s gateway ceiling, because provider
/// readiness is `:infinity` upstream. This leaves room for the answer rather than racing
/// it, and it is the one call the transport's 20s default cannot serve.
pub const START_TIMEOUT: Duration = Duration::from_secs(130);

/// The gateway refuses a replay limit above 500.
const REPLAY_LIMIT: u64 = 500;

/// How many replay rounds one interruption may cost before the client stops asking. Past
/// this the transcript keeps its visible gap, which is the honest end state: continuing
/// would be a loop against a session whose history is moving faster than it can be read.
const MAX_RESYNC_ROUNDS: u32 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Dashboard,
    Sessions,
    Agents,
    Teams,
    Plans,
    Upgrade,
    Logs,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Dashboard,
        Tab::Sessions,
        Tab::Agents,
        Tab::Teams,
        Tab::Plans,
        Tab::Upgrade,
        Tab::Logs,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Sessions => "Sessions",
            Self::Agents => "Agents",
            Self::Teams => "Teams",
            Self::Plans => "Plans/Control",
            Self::Upgrade => "Upgrade",
            Self::Logs => "Logs",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }
}

/// Whether this client started the runtime it is attached to. It decides what the quit
/// dialog may offer and whether the Logs tab has anything to show.
#[derive(Debug, Clone)]
pub enum Mode {
    Spawned { pid: i32 },
    Attached,
}

#[derive(Debug, Clone)]
pub enum Connection {
    Live,
    /// The transport is retrying underneath; this is what the UI knows about it.
    Lost {
        reason: String,
    },
}

/// What the driver does after the loop returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quit {
    /// Leave the runtime running.
    Detach,
    /// `runtime.shutdown` when the gateway serves it, then SIGTERM, then SIGKILL.
    Shutdown,
    /// Attach mode: close the socket and nothing else.
    Disconnect,
    /// Stop this standalone runtime, create a fleet from the saved intent, then come back.
    ApplyFleetIntent,
}

/// One request the driver should make. `Clone` because a confirmation dialog holds the
/// call it will emit if the answer is yes.
#[derive(Debug, Clone, PartialEq)]
pub struct Call {
    pub tag: Tag,
    pub method: String,
    pub params: Value,
    /// `None` uses the transport's default ceiling.
    pub timeout: Option<Duration>,
}

impl Call {
    pub fn new(tag: Tag, method: impl Into<String>, params: Value) -> Self {
        Self {
            tag,
            method: method.into(),
            params,
            timeout: None,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// What an answer is an answer to. Also the in-flight key: one outstanding request per
/// tag, so a slow runtime cannot make the UI queue a second copy of the same question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tag {
    Account,
    AccountLogin,
    AccountCancel,
    AccountLogout,
    Status,
    Providers,
    Sessions(Plane),
    Agents,
    AgentState(String),
    Teams,
    TeamState(String),
    Plans,
    Plan(String),
    ControlRuns,
    ControlRun(String),
    UpgradeStatus,
    Rollouts,
    History(String),
    Signing,
    Grants(String),
    /// `control.submit`. The answer carries the id of a run that did not exist before.
    ControlSubmit,
    /// `control.cancel {id}`.
    ControlCancel(String),
    /// The single resync path: `subscribe` after a reconnect or a first open, `replay`
    /// after a lag or a pruned cursor.
    ///
    /// `cursor` is the exclusive cursor the request carried. It is on the tag rather than
    /// re-read from the watch when the answer lands, because live events can advance the
    /// watch while the request is in flight, and the answer has to be interpreted against
    /// the question that was asked.
    Resync {
        plane: Plane,
        id: String,
        cursor: u64,
        subscribe: bool,
    },
    /// An operate verb. The label is what a failure names in the notice line.
    Action {
        label: &'static str,
        plane: Plane,
        id: String,
    },
    /// A composer mutation retains the exact draft and, for dispatched turns, its logical
    /// id until the answer. Steer has no durable request id; retaining a pretend one would
    /// make a lost acknowledgement look safely replayable when it is not.
    ///
    /// `input` is the whole turn envelope rather than the prompt alone (B4): a same-id
    /// reconciliation that replayed the prompt without its attachments would present a
    /// different fingerprint and come back `:turn_id_conflict`.
    ComposerAction {
        label: &'static str,
        verb: ComposerVerb,
        plane: Plane,
        id: String,
        turn_id: Option<String>,
        input: TurnInput,
        reconciling: bool,
        submission_sequence: u64,
    },
    /// `interactive.event_detail` / `coding.event_detail` for one excerpted event, asked
    /// for by the `/details` ledger. The sequence is on the tag because the answer is a
    /// bare event and two drill-ins can be outstanding at once.
    EventDetail {
        plane: Plane,
        id: String,
        sequence: u64,
    },
    /// `permissions.add` for the rule the approval modal's fifth answer names.
    ///
    /// Separate from [`Tag::Action`] because it is not a session verb: it fails or succeeds
    /// on its own, after the approval it accompanies has already been answered, and the
    /// notice has to be able to say which of the two happened.
    PermissionRule {
        pattern: String,
    },
    /// One approval response, keyed by the runtime request id so parallel prompts cannot
    /// collapse into one in-flight action.
    Approval {
        plane: Plane,
        id: String,
        request_id: String,
    },
    /// `interactive.start` / `coding.start`. Separate from [`Tag::Action`] because the
    /// answer carries the id of a session that did not exist when the request was made.
    Start {
        plane: Plane,
        id: String,
    },
    /// The first message of a session this client just started.
    FirstMessage {
        plane: Plane,
        id: String,
        turn_id: String,
        input: String,
        submission_sequence: u64,
    },
    /// D9. `interactive.compact`. Its own tag rather than an [`Tag::Action`] because the
    /// answer is a *report* to draw, not an acknowledgement to acknowledge.
    Compact {
        plane: Plane,
        id: String,
    },
    /// D9. `interactive.handoff`. Carries the caller-owned child id so a ceiling that
    /// fires after the child exists still names something this client can open.
    Handoff {
        plane: Plane,
        id: String,
        child: String,
    },
    /// D9. `interactive.context`. `show` separates the operator asking to *see* it from
    /// the refresh a compaction triggers, which only needs the meter.
    Context {
        plane: Plane,
        id: String,
        show: bool,
    },
    /// D6. `interactive.rewind_points` — the menu, before anything is chosen.
    RewindPoints {
        plane: Plane,
        id: String,
    },
    /// D6. `interactive.rewind`. `label` and `what` travel with the request because the
    /// answer names neither, and a note that could not say what was undone would be a
    /// worse record than none.
    Rewind {
        plane: Plane,
        id: String,
        label: String,
        what: &'static str,
    },
    /// B7. `workspace.exec`. The command line is on the tag because the runtime never
    /// records it — the ledger holds a digest and deliberately not the words — so this is
    /// the only place it can be echoed back.
    Shell {
        plane: Plane,
        id: String,
        command: String,
    },
    /// G1. `interactive.delegate`.
    Delegate {
        plane: Plane,
        id: String,
    },
    /// G1. `interactive.delegations`, for the overlay or for the `Ctrl+T` panel.
    Delegations {
        plane: Plane,
        id: String,
        show: bool,
    },
}

/// B7. A `workspace.exec` the runtime would not run, as the composer states it.
///
/// Everything here came from the runtime's own refusal. `offer` is present only where all
/// three conditions this client can check hold — the engine suggested a rule, this gateway
/// serves `permissions.add`, and the session names a workspace to scope it to — because a
/// one-key offer that could not be honoured would be worse than no offer at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellRefusalState {
    pub reason: Option<String>,
    pub message: Option<String>,
    pub denied_by: Option<String>,
    pub approval_mode: Option<String>,
    pub suggested_rule: Option<String>,
    /// `(pattern, workspace)` for the rule the one-key answer would write.
    pub offer: Option<(String, String)>,
}

/// One `/export` the driver has to write.
///
/// The App stays a pure state machine: it renders the bytes, names the file it wants, and
/// says what the file will contain. Resolving a default directory and touching the disk is
/// the driver's, because both read an environment this type does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    /// The path the operator named, or `None` for the default under the data directory.
    pub path: Option<String>,
    /// The filename the default resolves to, inside whichever directory the driver picks.
    pub filename: String,
    pub contents: String,
    /// What the notice says before the path: how much of the session is in the file, and
    /// whether anything was dropped before it.
    pub extent: String,
}

#[derive(Debug)]
pub enum Msg {
    Key(crossterm::event::KeyEvent),
    /// Bracketed paste is a single edit, including any embedded newlines.
    Paste(String),
    /// A local, bounded index produced by the I/O driver for `@` completion.
    WorkspaceFiles(Vec<String>),
    Tick,
    Notification(Notification),
    Answer {
        tag: Tag,
        result: Result<Value, ClientError>,
    },
    /// The transport completed a fresh handshake after a lost connection.
    Reconnected(Box<Hello>),
    /// The supervised child exited on its own.
    DaemonExited(String),
    /// The transport's cumulative count of notifications it could not hand over.
    NotificationsDropped(u64),
    /// The terminal was resized; nothing to do but redraw.
    Redraw,
    /// The mouse wheel or a trackpad notch, in transcript rows. Negative is older.
    Scroll(isize),
    /// Text the I/O driver read back from `$VISUAL`/`$EDITOR`.
    ExternalEditor(String),
    /// Tailscale peers and SSH config hosts, gathered by the driver when Machines opens.
    MachineCandidates {
        candidates: Vec<MachineCandidate>,
        local_machine: Option<String>,
        local_host: Option<String>,
    },
    /// Result of a confirmed `fleet add` / prepare job the driver ran.
    FleetJobFinished {
        log: Vec<String>,
        result: Result<String, String>,
    },
    /// The driver declined a second machine discovery scan; one is still running.
    MachineScanPending,
    /// The terminal reported focus in or out (CSI ?1004h). `true` is focused.
    ///
    /// Assumed focused until told otherwise: a terminal that never sends this is one
    /// whose user is, as far as anything here can tell, looking at it.
    Focus(bool),
    /// What a `[statusline] command` printed, or why it did not.
    StatusLine(Result<String, String>),
    /// What the driver found on the clipboard after a `Ctrl+V` (B4).
    Clipboard(ClipboardOutcome),
}

/// A `Ctrl+V` the driver should service.
///
/// The App does no I/O, and this is I/O twice over: it shells out to whichever clipboard
/// tool the machine has, and it writes a file. Both happen on the driver's blocking pool,
/// exactly as `$EDITOR` and `pbcopy` already do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardRequest {
    /// The **session's** workspace, as the runtime reported it. An attachment has to live
    /// inside it or `authorize_turn_attachments` refuses the turn, so this is where the
    /// image goes — and a fleet session's workspace is a path on another machine, which
    /// the driver discovers by failing to find the directory and says so.
    pub workspace: String,
    /// The id the file is named after, minted here so the state machine stays the thing
    /// that decides names.
    pub id: String,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardOutcome {
    /// A PNG was written; the path is relative to the session workspace.
    Image(String),
    /// No image. This is the ordinary text paste, performed unchanged.
    Text(String),
    /// Tools exist and the clipboard held nothing either of them could read.
    Empty,
    /// This machine has no clipboard tool at all. Said once.
    NoTool,
    /// A tool ran and something went wrong, named.
    Failed(String),
}

/// A panel's value, its freshness, and whether a refresh is in flight.
#[derive(Debug, Clone)]
pub struct Loadable<T> {
    pub value: Option<T>,
    pub error: Option<String>,
    pub pending: bool,
    /// The tick at which a poll may next be issued.
    pub next_tick: u64,
}

impl<T> Default for Loadable<T> {
    fn default() -> Self {
        Self {
            value: None,
            error: None,
            pending: false,
            next_tick: 0,
        }
    }
}

impl<T> Loadable<T> {
    fn due(&self, ticks: u64) -> bool {
        !self.pending && ticks >= self.next_tick
    }

    fn started(&mut self) {
        self.pending = true;
    }

    fn resolved(&mut self, ticks: u64, cadence: u64) {
        self.pending = false;
        self.next_tick = ticks + cadence;
    }

    pub fn ok(&mut self, value: T, ticks: u64, cadence: u64) {
        self.value = Some(value);
        self.error = None;
        self.resolved(ticks, cadence);
    }

    pub fn failed(&mut self, error: String, ticks: u64, cadence: u64) {
        self.error = Some(error);
        self.resolved(ticks, cadence);
    }

    /// Forces the next poll, for `r`.
    pub fn invalidate(&mut self) {
        self.next_tick = 0;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Pane {
    #[default]
    List,
    Detail,
}

/// One row of a list pane, projected out of whatever the method answered.
#[derive(Debug, Clone)]
pub struct Row {
    pub id: String,
    pub label: String,
    pub status: Option<String>,
    pub raw: Value,
}

/// A list on the left and a value tree on the right — tabs 3 through 6, which differ only
/// in which method fills the list and which fills the tree.
#[derive(Debug)]
pub struct Explorer {
    pub rows: Loadable<Vec<Row>>,
    pub selected: usize,
    pub detail: Loadable<Value>,
    pub tree: TreeState,
    pub focus: Pane,
    /// The id whose detail `detail` currently holds, so a selection change is detectable.
    pub detail_of: Option<String>,
}

impl Default for Explorer {
    fn default() -> Self {
        Self {
            rows: Loadable::default(),
            selected: 0,
            detail: Loadable::default(),
            tree: TreeState::opened(),
            focus: Pane::List,
            detail_of: None,
        }
    }
}

impl Explorer {
    pub fn current(&self) -> Option<&Row> {
        self.rows.value.as_ref()?.get(self.selected)
    }

    fn move_by(&mut self, delta: isize) {
        let len = self.rows.value.as_ref().map(Vec::len).unwrap_or(0);

        if len == 0 {
            self.selected = 0;
            return;
        }

        self.selected = (self.selected as isize + delta).clamp(0, len as isize - 1) as usize;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeSection {
    Status,
    Rollouts,
    History,
    Signing,
    Grants,
}

impl UpgradeSection {
    pub const ALL: [UpgradeSection; 5] = [
        UpgradeSection::Status,
        UpgradeSection::Rollouts,
        UpgradeSection::History,
        UpgradeSection::Signing,
        UpgradeSection::Grants,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Status => "node executor",
            Self::Rollouts => "rollouts",
            Self::History => "module history",
            Self::Signing => "signing decisions",
            Self::Grants => "effect grants",
        }
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::Status => "upgrade.status",
            Self::Rollouts => "upgrade.rollouts",
            Self::History => "upgrade.history",
            Self::Signing => "signing.decisions",
            Self::Grants => "grants.list",
        }
    }
}

#[derive(Debug)]
pub struct UpgradeTab {
    pub section: usize,
    pub status: Loadable<Value>,
    pub rollouts: Loadable<Value>,
    pub history: Loadable<Value>,
    pub history_module: Option<String>,
    pub signing: Loadable<Value>,
    pub grants: Loadable<Value>,
    pub grants_principal: Option<String>,
    pub tree: TreeState,
    pub focus: Pane,
}

impl Default for UpgradeTab {
    fn default() -> Self {
        Self {
            section: 0,
            status: Loadable::default(),
            rollouts: Loadable::default(),
            history: Loadable::default(),
            history_module: None,
            signing: Loadable::default(),
            grants: Loadable::default(),
            grants_principal: None,
            // Open, like every other detail pane: a tree whose root is closed shows one
            // line where the answer is.
            tree: TreeState::opened(),
            focus: Pane::default(),
        }
    }
}

impl UpgradeTab {
    pub fn current(&self) -> UpgradeSection {
        UpgradeSection::ALL[self.section.min(UpgradeSection::ALL.len() - 1)]
    }

    pub fn panel(&self, section: UpgradeSection) -> &Loadable<Value> {
        match section {
            UpgradeSection::Status => &self.status,
            UpgradeSection::Rollouts => &self.rollouts,
            UpgradeSection::History => &self.history,
            UpgradeSection::Signing => &self.signing,
            UpgradeSection::Grants => &self.grants,
        }
    }

    fn panel_mut(&mut self, section: UpgradeSection) -> &mut Loadable<Value> {
        match section {
            UpgradeSection::Status => &mut self.status,
            UpgradeSection::Rollouts => &mut self.rollouts,
            UpgradeSection::History => &mut self.history,
            UpgradeSection::Signing => &mut self.signing,
            UpgradeSection::Grants => &mut self.grants,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    Warn,
    Error,
}

#[derive(Debug)]
pub struct Notice {
    pub text: String,
    pub kind: NoticeKind,
    pub until: u64,
}

/// The last seen sequence per watched session, shared with the reconnect hook.
///
/// The hook runs inside the transport's task, after a handshake this App did not witness,
/// and it has to know where each subscription left off. A mutex around a small map is the
/// whole coupling: the App writes cursors, the hook reads them, and the answers come back
/// as ordinary [`Msg::Answer`]s so there is still one resync code path.
#[derive(Debug, Clone, Default)]
pub struct Cursors {
    inner: Arc<Mutex<BTreeMap<(Plane, String), CursorRegistration>>>,
}

#[derive(Debug, Clone, Default)]
struct CursorRegistration {
    cursor: u64,
    node: Option<String>,
}

impl Cursors {
    pub fn set(&self, plane: Plane, id: &str, cursor: u64, node: Option<&str>) {
        if let Ok(mut cursors) = self.inner.lock() {
            cursors.insert(
                (plane, id.to_string()),
                CursorRegistration {
                    cursor,
                    node: node.map(str::to_string),
                },
            );
        }
    }

    pub fn forget(&self, plane: Plane, id: &str) {
        if let Ok(mut cursors) = self.inner.lock() {
            cursors.remove(&(plane, id.to_string()));
        }
    }

    pub fn snapshot(&self) -> Vec<(Plane, String, u64, Option<String>)> {
        self.inner
            .lock()
            .map(|cursors| {
                cursors
                    .iter()
                    .map(|((plane, id), registration)| {
                        (
                            *plane,
                            id.clone(),
                            registration.cursor,
                            registration.node.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub struct App {
    pub mode: Mode,
    pub address: String,
    pub hello: Hello,
    pub connection: Connection,
    pub tab: Tab,
    pub ticks: u64,
    pub account: Loadable<AccountState>,
    pub status: Loadable<RuntimeStatus>,
    pub providers: Loadable<Vec<ProviderEntry>>,
    pub sessions: SessionsTab,
    pub agents: Explorer,
    pub teams: Explorer,
    pub plans: Explorer,
    pub control: Explorer,
    /// Which of the two lists tab 5 is driving.
    pub plans_on_control: bool,
    pub upgrade: UpgradeTab,
    pub logs: Option<LogRing>,
    pub log_scroll: usize,
    pub overlay: Option<Overlay>,
    pub notice: Option<Notice>,
    pub quit: Option<Quit>,
    pub cursors: Cursors,
    /// Where `ouro` was launched from, offered as the new-session workspace.
    ///
    /// A default rather than a decision: it is prefilled, visible, and editable, because
    /// the directory a terminal happens to be sitting in is a good guess and a bad
    /// assumption. The runtime resolves it, not this process — an `ouro` attached over an
    /// SSH tunnel is naming a path on the *runtime's* filesystem.
    pub launch_dir: Option<String>,
    /// This client's preferences, as the file said them plus whatever the settings overlay
    /// has changed since. Never a runtime fact, and labelled as such wherever it is drawn.
    pub config: Config,
    /// Every chord this client binds, resolved once from [`config`](Self::config) (B8).
    ///
    /// Resolved rather than consulted per keystroke because the answer is a fact about a
    /// file that is read once, and because the surfaces that *draw* a key — the `?` panel,
    /// the footer, the which-key overlay, the palette — must all be reading the same map
    /// as the handler that acts on it (D14). A caller that changes `config.keys` calls
    /// [`App::reload_keymap`]; nothing else in this type may go behind it.
    pub keymap: Keymap,
    /// Where [`config`](Self::config) is read from and written to. `None` only when there
    /// is nowhere to keep preferences at all, which the settings overlay says out loud.
    pub config_path: Option<PathBuf>,
    /// The data directory this client told the runtime to use, when it started one.
    ///
    /// `None` in attach mode on purpose: a client that did not spawn this runtime does not
    /// know where that runtime keeps its files, and a local path printed under a remote
    /// node would be a guess wearing a fact's clothes.
    pub data_dir: Option<String>,
    /// Non-secret membership metadata loaded by the launcher from this runtime's data
    /// directory. The App remains a pure state machine: it never reads the profile itself.
    pub fleet_profile: Option<FleetProfile>,
    /// Whether this data directory holds the fleet CA key. Loaded by the launcher; the
    /// App never stats the key file.
    pub can_invite: bool,
    /// Ask the driver to list Tailscale/SSH hosts. Set when Machines opens.
    scan_machines_pending: bool,
    /// Whether the "this is not the palette you asked for" sentence has been said. Once
    /// per run rather than once per operator: the reason it is true is the terminal this
    /// run was started in, and that can differ from the last one.
    theme_hint_shown: bool,
    /// Restart-as-fleet plan. The driver writes it, then this process shuts down.
    fleet_intent_pending: Option<FleetIntent>,
    /// Restart-and-join plan. The driver writes the invitation path, then shuts down.
    join_intent_pending: Option<JoinIntent>,
    /// Confirmed add/prepare for a live fleet owner. The driver runs it.
    fleet_job_pending: Option<FleetJob>,
    /// Open Machines after a fleet-intent restart so the operator sees what happened.
    pub open_machines_on_start: bool,
    /// Progress from that restart's add, shown on the Add Done step.
    pub resume_add_log: Vec<String>,
    /// Enroll recipe from that restart's add, if the destination still needs a command.
    pub resume_add_recipe: Option<String>,
    /// Whether this terminal reports `Shift+Enter` as something other than `Enter`. Set by
    /// the driver once it has asked; see [`super::keyboard_enhanced`]. The composer footers
    /// advertise the binding only where it exists, because in every other terminal that
    /// keystroke sends the message.
    pub keyboard_enhanced: bool,
    /// The first-class harness composer before a session exists.
    pub home_draft: Editor,
    pub home_pending: bool,
    pub home_error: Option<String>,
    completion_catalog: CompletionCatalog,
    outbound: VecDeque<Call>,
    in_flight: HashSet<Tag>,
    dropped_seen: u64,
    /// Set when the App has changed [`config`](Self::config) and wants it on disk. Drained
    /// by the driver, exactly like [`Call`]s are, because this type does no I/O.
    save_pending: bool,
    /// Whether the write [`save_pending`](Self::save_pending) asks for is a marker rather
    /// than an answer, and so should be made without a word about it.
    ///
    /// A settings save is the operator's own action and naming the file is the receipt for
    /// it. An onboarding marker is not: it is written *because* something else is being
    /// said, and there is one notice row.
    save_quiet: bool,
    /// The coding home's first prompt, held between `*.start` being issued and its answer
    /// arriving. There is nothing to send it to until the session exists.
    first_message: Option<PendingFirstMessage>,
    /// A start launched from an existing composer (currently `/write`) has no modal to
    /// retain its retry boundary. Keep it here until success or a definite refusal.
    pending_background_start: Option<StartRequest>,
    /// A URL the I/O driver should open in the operator's browser. Kept out of notices so
    /// a managed login URL is never copied into logs by accident.
    open_url_pending: Option<String>,
    /// Tick at which a pending Ctrl+X leader chord expires.
    pub leader_until: Option<u64>,
    /// How far the `?` panel is scrolled. Reset when it opens: a help panel that
    /// remembered where the last reader left it would open on the middle of a table.
    pub help_scroll: usize,
    /// The armed first half of an `Esc Esc`, and the session it was pressed in.
    ///
    /// The session travels with the arm because the first Escape may have *left* it: on an
    /// idle session with an empty prompt that is what Escape has always done, and a
    /// double-Escape that then had nothing to show would be a chord that punished you for
    /// being idle.
    pub(super) backtrack_arm: Option<(u64, (Plane, String))>,
    /// D9. What `interactive.context` last answered, and for which session.
    ///
    /// Keyed by identity rather than stored on the session row because a row's `usage` is
    /// reduced by the runtime to tokens and cost — the window is not in it — so the meter
    /// has nowhere else to read a measured `context_used / context_window` from. Dropped
    /// on nothing: a stale reading for a session that is no longer open is simply not
    /// matched, and the footer falls back to stating tokens without a percentage.
    pub(super) context: Option<(Plane, String, Box<crate::model::native::SessionContext>)>,
    /// G1. What `interactive.delegations` last answered, and for which session.
    pub(super) delegations: Option<(Plane, String, Vec<crate::model::native::DelegationRow>)>,
    /// G1. Whether a `/delegate` is in flight, for the composer's chip.
    pub(super) delegating: bool,
    /// B7. The last refused operator command, kept on the composer so the reason and the
    /// one key that fixes it are on screen together.
    pub(super) shell_refusal: Option<ShellRefusalState>,
    /// Tick at which a second Ctrl+C will open the quit dialog.
    ctrl_c_until: Option<u64>,
    /// Last agent message the I/O driver should copy to the clipboard.
    /// The `/details` ledger's expansion, cursor, filter, and drill-in answers.
    pub details: DetailsView,
    export_pending: Option<ExportRequest>,
    copy_pending: Option<String>,
    /// Current prompt text the I/O driver should open in `$VISUAL`/`$EDITOR`.
    external_editor_pending: Option<String>,
    /// The transcript the I/O driver should print into the terminal's native scrollback.
    scrollback_dump_pending: Option<String>,
    /// The transcript the I/O driver should open in `$VISUAL`/`$EDITOR`, read-only.
    transcript_view_pending: Option<String>,
    /// What to tell this operator about the mouse this client captured, or `None` when it
    /// captured nothing. Set by the driver once the terminal is taken over, because whether
    /// the capture actually happened is a fact about the terminal and not about this state
    /// machine — see [`super::mouse_hint`].
    pub mouse_hint: Option<String>,
    /// Columns the last frame was laid out against. Written by the driver on every draw;
    /// the export wraps to it, because the terminal it is about to be printed into is the
    /// same one that just drew the frame. Zero until the first frame.
    pub terminal_width: u16,
    /// Monotonic issue order for composer mutations. Outcome-unknown answers may arrive
    /// out of order; reconciliation is sorted by this sequence, never by error arrival.
    next_composer_submission_sequence: u64,
    /// After ending a session chosen from the switcher, put the switcher back so several
    /// dead rows can be cleared without reopening it each time.
    resume_session_picker: bool,
    /// Whether this terminal has focus, as it reports through CSI ?1004h.
    ///
    /// `true` until a `FocusLost` says otherwise, and it stays `true` forever in a
    /// terminal that does not implement focus reporting. That is the safe default for the
    /// thing it gates: with `when = "unfocused"` an unreporting terminal gets no bells at
    /// all, which is quieter than the alternative of ringing at every turn.
    pub focused: bool,
    /// What this terminal says it is, for resolving `[notifications] mode = "auto"`. Set
    /// by the driver from the environment; a test sets it directly.
    pub terminal: TerminalIdentity,
    /// The title this client last asked the driver to write, so an unchanged title is not
    /// re-emitted eighty times a second.
    title_shown: Option<String>,
    title_pending: Option<String>,
    /// Notifications the driver should emit. A `Vec` rather than an `Option` because two
    /// sessions can want attention in the same frame; bounded by [`NOTIFY_BURST`] so a
    /// storm of events cannot become a storm of bells.
    notify_pending: Vec<notify::Signal>,
    statusline: StatusLine,
    /// A `Ctrl+V` the driver should service (B4).
    clipboard_pending: Option<ClipboardRequest>,
    /// Whether "this machine has no clipboard tool" has been said. Once per run: the
    /// thing it explains does not change between keystrokes.
    clipboard_tool_reported: bool,
    /// Sessions whose reported cost has already crossed `[budget] max_cost_usd` (I2).
    ///
    /// A set rather than a flag: two open sessions crossing the same limit are two facts,
    /// and the warning belongs to the session, not to the run.
    budget_warned: HashSet<String>,
}

/// How many notifications one frame may emit. A session that produced fifty terminal
/// turns in one batch is one thing worth noticing, not fifty.
const NOTIFY_BURST: usize = 2;

/// Claude Code debounces its status line by 300 ms; this is that window rounded up to a
/// whole number of the 80 ms tick, so the arithmetic stays integral and testable.
const STATUSLINE_DEBOUNCE_TICKS: u64 = 4;

/// The scriptable status line's state machine.
///
/// Its whole job is to run the command as rarely as it can get away with: only when the
/// object it would be fed differs from the one it was last fed, only after that object
/// has stopped changing for the debounce window, and never twice at once.
#[derive(Debug, Default)]
pub struct StatusLine {
    /// The payload the running (or last finished) invocation was given.
    dispatched: Option<Value>,
    /// A payload that differs from `dispatched`, and the tick it was first seen at.
    settling: Option<(Value, u64)>,
    /// Whether an invocation is outstanding. One at a time: a command slower than the
    /// debounce window must not stack.
    running: bool,
    /// The first line of the last successful run. `None` means there is no row.
    line: Option<String>,
    /// Whether a failure has already been reported. Once, then silence — a status line
    /// that re-announced a broken command every frame would own the notice line.
    reported: bool,
}

impl StatusLine {
    /// What to draw above the footer, if anything.
    pub fn line(&self) -> Option<&str> {
        self.line.as_deref().filter(|line| !line.trim().is_empty())
    }
}

impl App {
    pub fn new(mode: Mode, address: String, hello: Hello, logs: Option<LogRing>) -> Self {
        Self {
            mode,
            address,
            hello,
            connection: Connection::Live,
            tab: Tab::Sessions,
            ticks: 0,
            account: Loadable::default(),
            status: Loadable::default(),
            providers: Loadable::default(),
            sessions: SessionsTab::default(),
            agents: Explorer::default(),
            teams: Explorer::default(),
            plans: Explorer::default(),
            control: Explorer::default(),
            plans_on_control: false,
            upgrade: UpgradeTab::default(),
            logs,
            log_scroll: 0,
            overlay: None,
            notice: None,
            quit: None,
            cursors: Cursors::default(),
            launch_dir: None,
            config: Config::default(),
            keymap: Keymap::builtin(),
            config_path: None,
            data_dir: None,
            fleet_profile: None,
            can_invite: false,
            scan_machines_pending: false,
            theme_hint_shown: false,
            fleet_intent_pending: None,
            join_intent_pending: None,
            fleet_job_pending: None,
            open_machines_on_start: false,
            resume_add_log: Vec::new(),
            resume_add_recipe: None,
            keyboard_enhanced: false,
            home_draft: Editor::default(),
            home_pending: false,
            home_error: None,
            completion_catalog: CompletionCatalog::default(),
            outbound: VecDeque::new(),
            in_flight: HashSet::new(),
            dropped_seen: 0,
            save_pending: false,
            save_quiet: false,
            first_message: None,
            pending_background_start: None,
            open_url_pending: None,
            leader_until: None,
            help_scroll: 0,
            backtrack_arm: None,
            context: None,
            delegations: None,
            delegating: false,
            shell_refusal: None,
            ctrl_c_until: None,
            details: DetailsView::default(),
            export_pending: None,
            copy_pending: None,
            external_editor_pending: None,
            scrollback_dump_pending: None,
            transcript_view_pending: None,
            mouse_hint: None,
            terminal_width: 0,
            next_composer_submission_sequence: 0,
            resume_session_picker: false,
            focused: true,
            terminal: TerminalIdentity::default(),
            title_shown: None,
            title_pending: None,
            notify_pending: Vec::new(),
            statusline: StatusLine::default(),
            clipboard_pending: None,
            clipboard_tool_reported: false,
            budget_warned: HashSet::new(),
        }
    }

    /// Re-resolves [`keymap`](Self::keymap) from the current `[keys]` table.
    ///
    /// Called by the launcher once the preference file has been read, and by any test that
    /// sets `config.keys` directly. The keymap's own problems are *not* drained here: they
    /// belong to the map, `/keys` lists them, and the launcher says them once at startup.
    pub fn reload_keymap(&mut self) {
        self.keymap = Keymap::resolve(&self.config.keys.overrides());
    }

    /// Whether `action` still has a key on it, for the surfaces that must not advertise a
    /// chord an operator turned off.
    pub fn bound(&self, action: Action) -> bool {
        !self.keymap.spec(action).is_off()
    }

    /// The row the `[statusline] command` produced, for the renderer.
    pub fn statusline(&self) -> &StatusLine {
        &self.statusline
    }

    /// The title the driver should write, when it differs from the one already written.
    pub fn take_title(&mut self) -> Option<String> {
        self.title_pending.take()
    }

    /// Forgets what was written, so the next tick emits the title again.
    ///
    /// For the one thing that takes the terminal away and gives it back: leaving
    /// `$EDITOR` restores the screen through the same path that empties the title on
    /// exit, and without this the tab would stay blank until the session's activity
    /// happened to change.
    pub fn forget_title(&mut self) {
        self.title_shown = None;
    }

    /// Notifications the driver should emit, and the channel to emit them through.
    ///
    /// The channel is resolved here rather than in the driver so that `mode = "auto"`
    /// stays a pure function of state a test can set.
    pub fn take_notifications(&mut self) -> Vec<(notify::Channel, notify::Signal)> {
        let signals = std::mem::take(&mut self.notify_pending);

        let Some(channel) = notify::channel(self.config.notifications.mode(), &self.terminal)
        else {
            return Vec::new();
        };

        signals
            .into_iter()
            .map(|signal| (channel, signal))
            .collect()
    }

    /// The status-line command the driver should run, and the object to feed it.
    ///
    /// `None` until the facts have stopped changing for the debounce window, and never
    /// while an invocation is outstanding.
    pub fn take_statusline_request(&mut self) -> Option<(String, Value)> {
        let command = self.config.statusline.command()?.to_string();

        if self.statusline.running {
            return None;
        }

        let (_key, since) = self.statusline.settling.as_ref()?;

        if self.ticks.saturating_sub(*since) < STATUSLINE_DEBOUNCE_TICKS {
            return None;
        }

        let (key, _since) = self.statusline.settling.take()?;
        self.statusline.running = true;
        self.statusline.dispatched = Some(key);

        // Built fresh rather than replayed from the key, so the elapsed time the command
        // is handed is the one at dispatch and not the one that started the debounce.
        Some((command, self.statusline_payload()))
    }

    /// Notices a change worth re-running the status-line command for.
    ///
    /// The comparison deliberately drops `elapsed_ms`: it changes every tick while a turn
    /// runs, and a status line that re-ran twelve times a second would never settle and
    /// would fork a process for each attempt. Claude Code's own contract is the same one —
    /// the command runs on discrete events, not on a clock.
    fn statusline_key(&self, facts: Option<&SessionFacts>) -> Value {
        let mut payload = self.statusline_payload_of(facts);

        if let Some(map) = payload.as_object_mut() {
            map.remove("elapsed_ms");
        }

        payload
    }

    /// The window title and the status-line debounce, once per tick.
    ///
    /// On the tick rather than on every message: both read the open session's transcript,
    /// and a burst of a hundred streamed deltas must cost one pass, not a hundred.
    /// I2. Says once, per session, that the reported cost has passed `[budget]
    /// max_cost_usd`.
    ///
    /// Once because the condition does not un-happen: a limit crossed at $5.01 is still
    /// crossed at $5.02, and a notice on every tick would own the one row a refusal has to
    /// fit on. Per session because two sessions crossing the same limit are two facts.
    ///
    /// The wording is deliberate. This client **warns**; it does not stop, cannot stop, and
    /// says so — the runtime's own budgets are a later slice, and a client that implied it
    /// had halted anything would be claiming an authority it does not have.
    fn warn_over_budget(&mut self, facts: Option<&SessionFacts>) {
        let Some(limit) = self.config.budget.max_cost_usd() else {
            return;
        };

        let Some(facts) = facts else {
            return;
        };

        let Some(spent) = facts.usage.as_ref().and_then(|usage| usage.cost_usd) else {
            return;
        };

        if spent < limit || !self.budget_warned.insert(facts.id.clone()) {
            return;
        }

        self.inform(
            format!(
                "{} has reported {} of the {} in [budget] max_cost_usd \u{b7} this client \
                 warns and does not stop anything",
                facts.id,
                super::view::money(spent),
                super::view::money(limit)
            ),
            NoticeKind::Warn,
        );
    }

    fn refresh_chrome(&mut self) {
        self.refresh_offered_commands();

        // Read once. Gathering them walks the retained event window, and the title, the
        // debounce key, and the payload all want the same answer.
        let facts = self.session_facts();
        self.warn_over_budget(facts.as_ref());
        let title = notify::title(
            self.activity_of(facts.as_ref()),
            self.title_workspace_of(facts.as_ref()).as_deref(),
        );

        if self.title_shown.as_deref() != Some(title.as_str()) {
            self.title_shown = Some(title.clone());
            self.title_pending = Some(title);
        }

        if self.config.statusline.command().is_none() {
            self.statusline = StatusLine::default();
            return;
        }

        if self.statusline.running {
            return;
        }

        let key = self.statusline_key(facts.as_ref());

        if self.statusline.dispatched.as_ref() == Some(&key) {
            self.statusline.settling = None;
            return;
        }

        match &self.statusline.settling {
            // Still the same candidate: leave the clock where it started.
            Some((settling, _since)) if *settling == key => {}
            _changed => self.statusline.settling = Some((key, self.ticks)),
        }
    }

    /// Counts one sent prompt, until the onboarding threshold (B9).
    ///
    /// Written quietly: the marker is a side effect of something else being done, and the
    /// notice row belongs to whatever the operator actually asked for.
    pub(super) fn count_prompt(&mut self) {
        if self.config.onboarding.prompts_sent >= ONBOARDING_PROMPTS {
            return;
        }

        self.config.onboarding.prompts_sent += 1;
        self.save_pending = true;
        self.save_quiet = true;
    }

    /// `/theme`: the next palette in the cycle, live, and remembered.
    ///
    /// The preview *is* the switch. There is nothing useful to preview a palette in but the
    /// screen already showing the conversation, and a modal that painted swatches would be
    /// showing the operator six rectangles instead of their own transcript. Cycling back
    /// round is one more `/theme`, and what is written to the file is whatever they stopped
    /// on — so the preview is undoable by the same key that made it.
    pub(super) fn cycle_theme(&mut self) {
        self.switch_theme(self.config.theme.name().next());
    }

    /// `/theme <name>`.
    pub(super) fn choose_theme(&mut self, name: &str) {
        let Some(theme) = super::theme::ThemeName::parse(name) else {
            self.inform(
                format!(
                    "no theme called {name:?}; this build has {}",
                    super::theme::ThemeName::ALL
                        .iter()
                        .map(|theme| theme.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                NoticeKind::Error,
            );
            return;
        };

        self.switch_theme(theme);
    }

    fn switch_theme(&mut self, name: super::theme::ThemeName) {
        super::switch_theme(name);

        self.config.theme.name = Some(name.as_str().to_string());
        self.save_pending = true;

        // What is *drawing*, not what was asked for. Under `NO_COLOR` those are two
        // different answers and the operator is owed both — a client that said "theme:
        // light" while drawing in grey would be the silent swap this project refuses.
        let drawing = super::theme::current().name;
        let note = match drawing == name.as_str() {
            true => format!("theme: {}", name.as_str()),
            false => format!(
                "theme: {} was saved, but {drawing} is what is drawing — {}",
                name.as_str(),
                super::theme_note()
                    .unwrap_or_else(|| "this terminal is not being asked".to_string())
            ),
        };

        self.inform(note, NoticeKind::Info);
    }

    /// Says once, on the first tick, that the palette drawing is not the one that was
    /// asked for.
    ///
    /// The same shape as [`Self::hint_mouse_capture`] and for the same reason: the fact is
    /// knowable only after a screen exists, and it is exactly the fact whose absence would
    /// leave someone editing `config.toml` in a loop.
    pub(super) fn hint_theme_resolution(&mut self) {
        if self.theme_hint_shown {
            return;
        }

        self.theme_hint_shown = true;

        if let Some(note) = super::theme_note() {
            self.inform(note, NoticeKind::Info);
        }
    }

    /// Whether this operator is still new enough to be pointed at the keys.
    pub fn onboarding(&self) -> bool {
        self.config.onboarding.prompts_sent < ONBOARDING_PROMPTS
    }

    /// Keeps the `/` completion list to the verbs the open session can honour.
    ///
    /// The palette, the leader overlay, and the footer are gated where they are drawn;
    /// this is the fourth place a verb is advertised, and a completion menu offering
    /// `/steer` on a transport that answers `{:error, :unsupported}` is the same failure
    /// D14 names.
    fn refresh_offered_commands(&mut self) {
        let mut hidden = Vec::new();

        if !self.steer_offered() {
            hidden.push("/steer");
        }

        if !self.open_capabilities().interrupt.offered() {
            hidden.push("/interrupt");
        }

        // B4/B1. `/model` is `interactive.configure`, and `hello.methods` is the feature
        // gate for every verb. A gateway that does not serve it cannot change a running
        // session's model, so the completion does not offer to.
        if !self.hello.serves("interactive.configure") {
            hidden.push("/model");
        }

        // B5. Forking needs the method *and* a transport the runtime has not declared
        // unable to branch; the backtrack menu itself is always reachable, because "edit
        // and resend" works everywhere.
        if !self.fork_offered() {
            hidden.push("/fork");
        }

        // D9/D6. Three verbs only a native session can honour: this runtime has to be the
        // one holding the conversation to fold it, hand it over, or put it back.
        if !self.context_verbs_offered() {
            hidden.push("/compact");
            hidden.push("/handoff");
            hidden.push("/rewind");
        }

        // D9. `interactive.context` answers for every transport, so its only gate is the
        // method — a vendor session gets the subset its own `usage` events reported.
        if !self.context_overlay_offered() {
            hidden.push("/context");
        }

        // G1. Two halves of the same slice, gated separately because a gateway can serve
        // one and not the other.
        if !self.delegation_offered() {
            hidden.push("/delegate");
        }

        if !(self.sessions.open.is_some() && self.hello.serves("interactive.delegations")) {
            hidden.push("/delegations");
        }

        self.completion_catalog.hide_commands(hidden);
    }

    /// Arms a notification, if this session's state and the operator's settings allow one.
    fn notify(&mut self, signal: notify::Signal) {
        if !notify::permitted(self.config.notifications.when(), self.focused) {
            return;
        }

        if notify::channel(self.config.notifications.mode(), &self.terminal).is_none() {
            return;
        }

        if self.notify_pending.len() >= NOTIFY_BURST {
            return;
        }

        self.notify_pending.push(signal);
    }

    /// What a live stream frame is worth interrupting someone for, and which session it
    /// was about.
    ///
    /// Live frames only — this is read from [`Msg::Notification`], never from a replay
    /// answer, so opening a session with history rings nothing.
    fn live_signal(notification: &Notification) -> Option<(Plane, String, notify::Signal)> {
        let plane = match notification.method.as_str() {
            "interactive.event" => Plane::Interactive,
            "coding.event" => Plane::Coding,
            _not_an_event => return None,
        };

        let id = notification.params.get("id").and_then(Value::as_str)?;
        let kind = notification
            .params
            .pointer("/event/type")
            .and_then(Value::as_str)?;

        let signal = match EventType::parse(kind) {
            EventType::ApprovalRequested => notify::Signal::NeedsInput,
            EventType::TurnCompleted | EventType::TurnFailed | EventType::TurnInterrupted => {
                notify::Signal::TurnDone
            }
            _uninteresting => return None,
        };

        Some((plane, id.to_string(), signal))
    }

    pub fn take_open_url(&mut self) -> Option<String> {
        self.open_url_pending.take()
    }

    pub fn take_copy(&mut self) -> Option<String> {
        self.copy_pending.take()
    }

    /// The clipboard read the driver should perform, if the composer asked for one.
    pub fn take_clipboard_request(&mut self) -> Option<ClipboardRequest> {
        self.clipboard_pending.take()
    }

    pub fn take_export(&mut self) -> Option<ExportRequest> {
        self.export_pending.take()
    }

    pub fn take_external_editor(&mut self) -> Option<String> {
        self.external_editor_pending.take()
    }

    pub fn take_scrollback_dump(&mut self) -> Option<String> {
        self.scrollback_dump_pending.take()
    }

    pub fn take_transcript_view(&mut self) -> Option<String> {
        self.transcript_view_pending.take()
    }

    /// The open session as plain text, at the measure the transcript is being read at.
    ///
    /// `None` — with the sentence already shown — when there is nothing open: both escape
    /// hatches are about *this* conversation, and a dump of no conversation would leave the
    /// operator looking at their own shell wondering what happened.
    fn transcript_export(&mut self) -> Option<String> {
        // Zero before the first frame, and a width of zero would wrap every word onto its
        // own line. Eighty is what a terminal that has not said otherwise is.
        let width = match self.terminal_width {
            0 => 80,
            width => usize::from(width),
        };

        let Some(watch) = self.sessions.open_watch() else {
            self.inform(
                "open a session before exporting its transcript",
                NoticeKind::Info,
            );
            return None;
        };

        Some(super::export::transcript(watch, width))
    }

    /// Claude Code's `[`: the whole conversation, handed back to the terminal that owns the
    /// scrollback, so `Cmd+F` and drag-to-copy work on it again.
    pub(super) fn dump_to_scrollback(&mut self) {
        self.overlay = None;
        self.scrollback_dump_pending = self.transcript_export();
    }

    /// Claude Code's `v`: the same text, in the operator's own editor, where searching and
    /// saving a piece of it are the editor's problem rather than this client's.
    pub(super) fn view_transcript(&mut self) {
        self.overlay = None;
        self.transcript_view_pending = self.transcript_export();
    }

    /// Says once, and only where it is true, that this client took the mouse.
    ///
    /// Once per operator rather than once per session (`onboarding.mouse_hint_shown`): the
    /// thing it explains does not change between runs, and a line that reappears every
    /// launch is a line nobody reads. Silent capture is the complaint this answers —
    /// Claude Code #72681 — so it is shown on the first frame rather than waiting for the
    /// wheel event that proves the operator already found the problem.
    pub(super) fn hint_mouse_capture(&mut self) {
        if self.config.onboarding.mouse_hint_shown {
            return;
        }

        let Some(hint) = self.mouse_hint.clone() else {
            return;
        };

        self.config.onboarding.mouse_hint_shown = true;
        self.save_pending = true;
        // The marker is written on the same frame the hint is said, and the driver
        // persists before it draws. Announcing that write would spend the one notice row
        // on a file the operator never asked for and take the hint with it.
        self.save_quiet = true;
        self.inform(hint, NoticeKind::Info);
    }

    pub fn take_scan_machines(&mut self) -> bool {
        std::mem::take(&mut self.scan_machines_pending)
    }

    pub fn take_fleet_intent(&mut self) -> Option<FleetIntent> {
        self.fleet_intent_pending.take()
    }

    pub fn take_join_intent(&mut self) -> Option<JoinIntent> {
        self.join_intent_pending.take()
    }

    pub fn fleet_plan_write_failed(&mut self, error: impl Into<String>) {
        self.quit = None;
        let error = error.into();
        self.inform(error.clone(), NoticeKind::Error);
        if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
            if let Some(add) = machines.add.as_mut() {
                add.pending = false;
                add.step = AddStep::Confirm;
                add.error = Some(error.clone());
            }
            if let Some(form) = machines.form.as_mut() {
                form.pending = false;
                form.step = AddStep::Confirm;
                form.error = Some(error);
            }
        }
    }

    pub fn take_fleet_job(&mut self) -> Option<FleetJob> {
        self.fleet_job_pending.take()
    }

    pub fn leader_pending(&self) -> bool {
        self.leader_until.is_some()
    }

    pub fn chatgpt_connected(&self) -> bool {
        self.account
            .value
            .as_ref()
            .map(AccountState::connected)
            .unwrap_or(false)
    }

    /// Whether Codex can be started without asking anyone to sign in: a connected ChatGPT
    /// subscription, or an install the runtime says needs no OpenAI auth at all.
    pub fn codex_usable(&self) -> bool {
        self.account
            .value
            .as_ref()
            .map(AccountState::usable)
            .unwrap_or(false)
    }

    /// Whether the coding home can start its configured provider now. Codex keeps its
    /// first-class managed sign-in gate; every other explicit provider owns its own auth
    /// and must not be blocked by an unrelated OpenAI account state.
    pub fn home_ready(&self) -> bool {
        self.home_provider() != "codex" || self.codex_usable()
    }

    pub fn home_provider(&self) -> &str {
        self.config.defaults.provider.as_deref().unwrap_or("codex")
    }

    /// Whether `account.read` has come back at all — with a state, or with a refusal.
    ///
    /// Not the same question as [`home_ready`](Self::home_ready): until this is true the
    /// client does not yet know whether the home is ready, and it must not act as though
    /// the answer were "no".
    fn account_resolved(&self) -> bool {
        self.account.value.is_some() || self.account.error.is_some()
    }

    /// Whether the visible home composer owns this key, or the global bindings do.
    ///
    /// The composer is on screen from the first frame and the caret is in it, so the first
    /// thing typed has to land in the draft. Gating that on *readiness* meant the account
    /// round trip decided where a keystroke went: type "quick fix" a moment too early and
    /// the `q` opened the quit dialog. The gate is resolution instead — once the runtime
    /// has answered, an unauthenticated home genuinely is a surface whose printable keys
    /// belong to the shell, and it says so on screen.
    fn home_owns_key(&self, code: crossterm::event::KeyCode) -> bool {
        use crossterm::event::KeyCode;

        self.home_ready()
            || !self.home_draft.text().is_empty()
            || !self.account_resolved()
            || matches!(
                code,
                KeyCode::Char('/') | KeyCode::Enter | KeyCode::Backspace | KeyCode::Esc
            )
    }

    pub fn home_workspace(&self) -> String {
        self.default_workspace()
    }

    /// What the home composer should say about file access, and whether that is writable.
    ///
    /// Unset follows the plane: workspace write where the provider allows it. A stored
    /// `read_only` is the opt-in for launching a session that cannot edit.
    pub fn home_sandbox(&self) -> (&'static str, bool) {
        match self.config.defaults.sandbox_mode() {
            Some(mode) => (mode.label(), mode.writable()),
            None => (SandboxMode::WorkspaceWrite.label(), true),
        }
    }

    /// The open session's sandbox caption, if a session is open.
    pub fn open_sandbox(&self) -> Option<(String, bool)> {
        let value = self.sessions.open_info().and_then(|session| {
            session
                .raw
                .get("options")
                .and_then(|options| options.get("sandbox_mode"))
        })?;

        match value {
            serde_json::Value::Null => Some(("provider default".to_string(), false)),
            serde_json::Value::String(name) if !name.trim().is_empty() => {
                let mode = SandboxMode::parse(name);
                Some((
                    mode.map(SandboxMode::label)
                        .unwrap_or(name.as_str())
                        .to_string(),
                    mode.is_some_and(SandboxMode::writable),
                ))
            }
            other => Some((crate::model::compact(other), false)),
        }
    }

    /// The config this App wants written, once. Drained by the driver, which owns the
    /// filesystem; see [`super::persist`].
    pub fn take_config_save(&mut self) -> Option<Config> {
        if !std::mem::take(&mut self.save_pending) {
            return None;
        }

        Some(self.config.clone())
    }

    /// Whether the write [`take_config_save`](Self::take_config_save) just handed over is
    /// worth a line on the notice row.
    ///
    /// Drained, because the answer belongs to that one write: a quiet marker must not
    /// silence the settings save after it. A *failed* write is announced either way — a
    /// file this client could not write is worth saying however it came to be written.
    pub fn take_config_save_announcement(&mut self) -> bool {
        !std::mem::take(&mut self.save_quiet)
    }

    /// Everything the driver should send, in order. Draining is the only way a request
    /// leaves this type.
    pub fn drain(&mut self) -> Vec<Call> {
        self.outbound.drain(..).collect()
    }

    /// Whether anything is queued, for a driver that wants to know without taking it.
    pub fn has_outbound(&self) -> bool {
        !self.outbound.is_empty()
    }

    /// Whether any question is still outstanding. The panels show this per-pane as a
    /// spinner; a caller that has to wait for the whole tab to be answered — which in
    /// practice means a test — asks here.
    pub fn busy(&self) -> bool {
        !self.in_flight.is_empty()
    }

    /// Whether the open transcript is waiting for its first user-visible agent text.
    ///
    /// The local marker covers the narrow RPC-to-first-event gap. After that, the ordered
    /// durable event ledger is authoritative. A lost connection or an unresolved replay
    /// gap suppresses the animation rather than implying progress this client cannot see.
    pub fn waiting_for_open_agent_reply(&self) -> bool {
        if !matches!(self.connection, Connection::Live) {
            return false;
        }

        let Some(key) = self.sessions.open.as_ref() else {
            return false;
        };
        let Some(watch) = self.sessions.watches.get(key) else {
            return false;
        };

        if watch.ended.is_some() {
            return false;
        }

        if self.sessions.pending_replies.contains(key) {
            return true;
        }

        !watch.resyncing && !watch.has_gap() && watch.waiting_for_reply()
    }

    /// Outcome-unknown turns which Enter must reconcile before submitting the open draft.
    pub fn open_pending_reconciliation_count(&self) -> usize {
        self.sessions
            .open
            .as_ref()
            .and_then(|key| self.sessions.pending_reconciliations.get(key))
            .map_or(0, VecDeque::len)
    }

    pub fn spawned(&self) -> bool {
        matches!(self.mode, Mode::Spawned { .. })
    }

    /// A successful fleet list can still be partial when an older gateway only queries
    /// currently connected owners. Keep a prior row only when the latest runtime.status
    /// explicitly names that exact owner node as offline. This includes members learned
    /// transitively over BEAM and absent from this machine's original invitation profile.
    fn retain_offline_session_rows(
        &mut self,
        plane: Plane,
        mut fresh: Vec<SessionInfo>,
    ) -> Vec<SessionInfo> {
        for session in &fresh {
            self.sessions.hidden.remove(&(plane, session.id.clone()));
        }

        let offline_nodes: HashSet<&str> = self
            .status
            .value
            .as_ref()
            .and_then(|status| status.cluster.get("fleet"))
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|machine| machine.get("state").and_then(Value::as_str) == Some("offline"))
            .filter_map(|machine| machine.get("node").and_then(Value::as_str))
            .collect();

        if offline_nodes.is_empty() {
            return fresh;
        }

        let observed: HashSet<(String, String)> = fresh
            .iter()
            .filter_map(|session| {
                session
                    .node
                    .as_ref()
                    .map(|node| (session.id.clone(), node.clone()))
            })
            .collect();
        let previous = match plane {
            Plane::Interactive => self.sessions.interactive.value.as_ref(),
            Plane::Coding => self.sessions.coding.value.as_ref(),
        };

        if let Some(previous) = previous {
            fresh.extend(previous.iter().filter_map(|session| {
                let node = session.node.as_deref()?;
                if self.sessions.hidden.contains(&(plane, session.id.clone()))
                    || !offline_nodes.contains(node)
                    || observed.contains(&(session.id.clone(), node.to_string()))
                {
                    return None;
                }

                let mut retained = session.clone();
                retained.last_known = true;
                Some(retained)
            }));
        }

        fresh
    }

    /// Adds the owner only when this reference is remote. An omitted node retains the
    /// original local protocol; a remembered node makes every subsequent verb route to
    /// the same owner that returned the reference.
    fn routed_session_params(&self, plane: Plane, id: &str, mut params: Value) -> Value {
        if let (Some(node), Some(fields)) =
            (self.session_route_node(plane, id), params.as_object_mut())
        {
            fields.insert("node".into(), Value::String(node.to_string()));
        }
        params
    }

    fn session_route_node(&self, plane: Plane, id: &str) -> Option<&str> {
        let owner = self.sessions.owner_node(plane, id)?;
        let local = self
            .status
            .value
            .as_ref()
            .map(|status| status.node.as_str())
            .filter(|node| !node.is_empty())
            .unwrap_or(self.hello.node.as_str());
        (owner != local).then_some(owner)
    }

    /// V1 stream notifications do not carry an owner node. Until that wire contract is
    /// versioned, two explicit IDs on different machines cannot be distinguished safely.
    /// Every outbound session path calls this before it can choose or omit a route.
    fn refuse_owner_conflict(&mut self, plane: Plane, id: &str) -> bool {
        let Some(owners) = self
            .sessions
            .owner_conflict(plane, id)
            .map(|owners| owners.join(" and "))
        else {
            return false;
        };

        self.inform(
            format!(
                "session ID {id} belongs to {owners}; no request was sent. Explicit IDs must be fleet-unique (generated IDs already are); stop or restart one duplicate with a unique ID, then reconnect this TUI"
            ),
            NoticeKind::Error,
        );
        true
    }

    pub fn apply(&mut self, message: Msg) {
        match message {
            Msg::Key(key) => self.key(key),
            Msg::Paste(text) => self.paste(&text),
            Msg::WorkspaceFiles(files) => {
                self.completion_catalog.set_files(files);
                self.home_draft.update_completions(&self.completion_catalog);
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.editor.update_completions(&self.completion_catalog);
                }
            }
            Msg::Tick => {
                self.ticks += 1;
                self.expire_notice();
                self.expire_chords();
                self.hint_mouse_capture();
                self.hint_theme_resolution();
                self.poll();
                self.refresh_chrome();
                // B3. A draft queued behind a request that failed, was refused, or simply
                // took a while is still a draft the operator pressed Enter on.
                self.flush_queued_drafts();
            }
            Msg::Redraw => {}
            Msg::Scroll(delta) => {
                // The first wheel event is the second chance: whoever reaches for the mouse
                // is exactly the person the hint is for, and a notice that had already
                // expired unread would leave them none the wiser.
                self.hint_mouse_capture();
                self.scroll_view(delta);
            }
            Msg::Notification(notification) => {
                let candidate = Self::live_signal(&notification);
                self.notification(notification);

                // Armed after the dispatch, so a frame for a session this client is no
                // longer subscribed to — the one frame that can cross an unsubscribe —
                // does not ring for a conversation nobody is following.
                if let Some((plane, id, signal)) = candidate {
                    if self.sessions.watches.contains_key(&(plane, id)) {
                        self.notify(signal);
                    }
                }
            }
            Msg::Focus(focused) => self.focused = focused,
            Msg::StatusLine(result) => {
                self.statusline.running = false;

                match result {
                    Ok(line) => {
                        self.statusline.line = Some(line).filter(|line| !line.trim().is_empty())
                    }
                    Err(error) => {
                        self.statusline.line = None;

                        // Once. A command that is broken is broken on every tick, and a
                        // notice line that said so every tick would be the status line's
                        // failure taking over the row it failed to fill.
                        if !self.statusline.reported {
                            self.statusline.reported = true;
                            self.inform(
                                format!("the statusline command failed: {error}"),
                                NoticeKind::Warn,
                            );
                        }
                    }
                }
            }
            Msg::Clipboard(outcome) => self.clipboard_read(outcome),
            Msg::Answer { tag, result } => {
                self.answer(tag, result);
                // The acknowledgement that was blocking the queue may have just landed.
                self.flush_queued_drafts();
            }
            Msg::Reconnected(hello) => {
                self.connection = Connection::Live;
                self.hello = *hello;
                self.note_all_watches(Note::Reconnected);
                self.inform(
                    "the connection was re-established; resubscribing",
                    NoticeKind::Warn,
                );
            }
            Msg::DaemonExited(reason) => {
                self.connection = Connection::Lost {
                    reason: format!("the runtime exited: {reason}"),
                };
                self.inform(
                    format!("the runtime this client started exited: {reason}"),
                    NoticeKind::Error,
                );
            }
            Msg::NotificationsDropped(total) => self.client_dropped(total),
            Msg::ExternalEditor(text) => self.apply_external_editor(text),
            Msg::MachineScanPending => {
                self.inform("machine discovery is already running", NoticeKind::Info);
            }
            Msg::MachineCandidates {
                candidates,
                local_machine,
                local_host,
            } => {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    machines.candidates = candidates;
                    machines.local_machine = local_machine.clone();
                    machines.local_host = local_host.clone();
                    if let Some(add) = machines.add.as_mut() {
                        if add.owner_machine.is_empty() {
                            if let Some(name) = local_machine {
                                add.owner_machine = name;
                            }
                        }
                        if add.owner_host.is_empty() {
                            if let Some(host) = local_host {
                                add.owner_host = host;
                            }
                        }
                    }
                }
            }
            Msg::FleetJobFinished { log, result } => {
                if let Some(Overlay::Machines(machines)) = self.overlay.as_mut() {
                    if let Some(add) = machines.add.as_mut() {
                        add.pending = false;
                        add.log = log.clone();
                        match result.clone() {
                            Ok(recipe) => {
                                add.step = AddStep::Done;
                                add.recipe = (!recipe.is_empty()).then_some(recipe);
                                add.error = None;
                            }
                            Err(error) => {
                                add.step = AddStep::Confirm;
                                add.error = Some(error);
                            }
                        }
                    } else if let Some(form) = machines.form.as_mut() {
                        form.pending = false;
                        form.log = log.clone();
                        match result.clone() {
                            Ok(recipe) => {
                                form.step = AddStep::Done;
                                form.recipe = (!recipe.is_empty()).then_some(recipe);
                                form.error = None;
                            }
                            Err(error) => {
                                form.step = AddStep::Confirm;
                                form.error = Some(error);
                            }
                        }
                    } else if let Some(report) = machines.report.as_mut() {
                        report.pending = false;
                        match result {
                            Ok(recipe) => {
                                let mut body = log.join("\n");
                                if !recipe.is_empty() {
                                    if !body.is_empty() {
                                        body.push_str("\n\n");
                                    }
                                    body.push_str(&recipe);
                                }
                                report.body = body;
                                report.copy = (!recipe.is_empty()).then_some(recipe);
                            }
                            Err(error) => {
                                report.body = error;
                            }
                        }
                    }
                }
            }
        }
    }

    // ----- refresh -------------------------------------------------------------------

    /// Issues the polls the visible tab is due for. Only the visible tab: a Dashboard
    /// nobody is looking at is not a reason to keep a runtime answering.
    fn poll(&mut self) {
        // Account identity belongs to the shell, not a secondary operator panel. Keep it
        // fresh on every surface, with a tighter cadence while a browser/device login is
        // waiting for Codex's completion notification.
        let account_cadence = if self
            .account
            .value
            .as_ref()
            .map(|account| account.login.status == "pending")
            .unwrap_or(false)
            || matches!(self.overlay, Some(Overlay::Account(_)))
        {
            ACCOUNT_LOGIN_TICKS
        } else {
            ACCOUNT_TICKS
        };

        self.issue_if_due(Tag::Account, "account.read", json!({}), account_cadence);

        match self.tab {
            Tab::Dashboard => {
                self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
                self.issue_if_due(
                    Tag::Providers,
                    "runtime.providers",
                    json!({}),
                    PROVIDER_TICKS,
                );
            }
            Tab::Sessions => {
                self.issue_if_due(
                    Tag::Sessions(Plane::Interactive),
                    "interactive.list",
                    json!({}),
                    LIST_TICKS,
                );
                self.issue_if_due(
                    Tag::Sessions(Plane::Coding),
                    "coding.list",
                    json!({}),
                    LIST_TICKS,
                );
            }
            Tab::Agents => {
                self.issue_if_due(Tag::Agents, "agents.list", json!({}), LIST_TICKS);
                self.poll_detail(Tab::Agents);
            }
            Tab::Teams => {
                self.issue_if_due(Tag::Teams, "teams.list", json!({}), LIST_TICKS);
                self.poll_detail(Tab::Teams);
            }
            Tab::Plans => {
                self.issue_if_due(Tag::Plans, "plans.list", json!({}), LIST_TICKS);
                self.issue_if_due(Tag::ControlRuns, "control.list", json!({}), LIST_TICKS);
                self.poll_detail(Tab::Plans);
            }
            Tab::Upgrade => {
                self.issue_if_due(
                    Tag::UpgradeStatus,
                    "upgrade.status",
                    json!({}),
                    UPGRADE_TICKS,
                );
                self.issue_if_due(Tag::Rollouts, "upgrade.rollouts", json!({}), UPGRADE_TICKS);
                self.poll_upgrade_section();
            }
            // The ring is local. There is nothing to ask anyone for.
            Tab::Logs => {}
        }

        // A remote session that lost only its stream keeps recovering even while the
        // operator stays on the conversation. Machine status is the cheap, bounded signal
        // that its owner has returned; it avoids hammering a known-offline node with
        // subscribe calls.
        if !self.sessions.recovering.is_empty()
            || matches!(self.overlay, Some(Overlay::Machines(_)))
        {
            self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
        }
    }

    fn poll_detail(&mut self, tab: Tab) {
        let requests: Vec<(Tag, &'static str, String)> = match tab {
            Tab::Agents => self
                .agents
                .current()
                .map(|row| {
                    (
                        Tag::AgentState(row.id.clone()),
                        "agents.state",
                        row.id.clone(),
                    )
                })
                .into_iter()
                .collect(),
            Tab::Teams => self
                .teams
                .current()
                .map(|row| {
                    (
                        Tag::TeamState(row.id.clone()),
                        "teams.state",
                        row.id.clone(),
                    )
                })
                .into_iter()
                .collect(),
            Tab::Plans => {
                let mut out = Vec::new();

                if let Some(row) = self.plans.current() {
                    out.push((Tag::Plan(row.id.clone()), "plans.get", row.id.clone()));
                }

                if let Some(row) = self.control.current() {
                    out.push((
                        Tag::ControlRun(row.id.clone()),
                        "control.get",
                        row.id.clone(),
                    ));
                }

                out
            }
            _ => Vec::new(),
        };

        let mut due = Vec::new();

        for (tag, method, id) in requests {
            let ticks = self.ticks;

            let explorer = match &tag {
                Tag::AgentState(_) => &mut self.agents,
                Tag::TeamState(_) => &mut self.teams,
                Tag::Plan(_) => &mut self.plans,
                Tag::ControlRun(_) => &mut self.control,
                _ => continue,
            };

            // A selection that moved is fetched immediately; the same selection is
            // refreshed on the slow cadence, because a state tree is not a cheap list.
            if explorer.detail_of.as_deref() != Some(id.as_str()) {
                explorer.detail.invalidate();
                explorer.tree.reset();
                explorer.detail_of = Some(id.clone());
            }

            if explorer.detail.due(ticks) {
                explorer.detail.started();
                due.push(Call::new(tag, method, json!({ "id": id })));
            }
        }

        for call in due {
            self.issue(call);
        }
    }

    fn poll_upgrade_section(&mut self) {
        let section = self.upgrade.current();

        let (tag, method, params) = match section {
            // Already polled unconditionally above.
            UpgradeSection::Status | UpgradeSection::Rollouts => return,
            UpgradeSection::History => {
                let Some(module) = self.upgrade.history_module.clone() else {
                    return;
                };

                (
                    Tag::History(module.clone()),
                    "upgrade.history",
                    json!({ "module": module }),
                )
            }
            UpgradeSection::Signing => (Tag::Signing, "signing.decisions", json!({})),
            UpgradeSection::Grants => {
                let Some(principal) = self.upgrade.grants_principal.clone() else {
                    return;
                };

                (
                    Tag::Grants(principal.clone()),
                    "grants.list",
                    json!({ "principal": principal }),
                )
            }
        };

        if !self.upgrade.panel(section).due(self.ticks) {
            return;
        }

        self.upgrade.panel_mut(section).started();
        self.issue(Call::new(tag, method, params));
    }

    fn issue_if_due(&mut self, tag: Tag, method: &str, params: Value, _cadence: u64) {
        let due = match &tag {
            Tag::Account => self.account.due(self.ticks),
            Tag::Status => self.status.due(self.ticks),
            Tag::Providers => self.providers.due(self.ticks),
            Tag::Sessions(Plane::Interactive) => self.sessions.interactive.due(self.ticks),
            Tag::Sessions(Plane::Coding) => self.sessions.coding.due(self.ticks),
            Tag::Agents => self.agents.rows.due(self.ticks),
            Tag::Teams => self.teams.rows.due(self.ticks),
            Tag::Plans => self.plans.rows.due(self.ticks),
            Tag::ControlRuns => self.control.rows.due(self.ticks),
            Tag::UpgradeStatus => self.upgrade.status.due(self.ticks),
            Tag::Rollouts => self.upgrade.rollouts.due(self.ticks),
            _ => true,
        };

        if !due {
            return;
        }

        match &tag {
            Tag::Account => self.account.started(),
            Tag::Status => self.status.started(),
            Tag::Providers => self.providers.started(),
            Tag::Sessions(Plane::Interactive) => self.sessions.interactive.started(),
            Tag::Sessions(Plane::Coding) => self.sessions.coding.started(),
            Tag::Agents => self.agents.rows.started(),
            Tag::Teams => self.teams.rows.started(),
            Tag::Plans => self.plans.rows.started(),
            Tag::ControlRuns => self.control.rows.started(),
            Tag::UpgradeStatus => self.upgrade.status.started(),
            Tag::Rollouts => self.upgrade.rollouts.started(),
            _ => {}
        }

        self.issue(Call::new(tag, method, params));
    }

    /// Queues a call unless the same question is already outstanding.
    ///
    /// `hello.methods` is the feature gate and the only one (§2.3), so a verb this build
    /// does not serve is answered here rather than sent and refused. The answer is a real
    /// `-32601` so the pane that wanted it says which method is missing, in the place the
    /// data would have been — a client that discovered the gap by trying could not tell an
    /// older gateway from a broken one.
    fn issue(&mut self, call: Call) {
        if !self.hello.serves(&call.method) {
            let message = format!("this gateway does not serve {}", call.method);

            self.answer(
                call.tag,
                Err(ClientError::Rpc(RpcError {
                    code: ErrorCode::MethodNotFound,
                    message,
                    data: None,
                })),
            );

            return;
        }

        if !self.in_flight.insert(call.tag.clone()) {
            return;
        }

        self.outbound.push_back(call);
    }

    /// Forces every panel of the visible tab to refetch.
    fn refresh(&mut self) {
        match self.tab {
            Tab::Dashboard => {
                self.status.invalidate();
                self.providers.invalidate();
            }
            Tab::Sessions => {
                self.sessions.interactive.invalidate();
                self.sessions.coding.invalidate();
            }
            Tab::Agents => {
                self.agents.rows.invalidate();
                self.agents.detail.invalidate();
            }
            Tab::Teams => {
                self.teams.rows.invalidate();
                self.teams.detail.invalidate();
            }
            Tab::Plans => {
                self.plans.rows.invalidate();
                self.plans.detail.invalidate();
                self.control.rows.invalidate();
                self.control.detail.invalidate();
            }
            Tab::Upgrade => {
                self.upgrade.status.invalidate();
                self.upgrade.rollouts.invalidate();
                let section = self.upgrade.current();
                self.upgrade.panel_mut(section).invalidate();
            }
            Tab::Logs => {}
        }

        self.poll();
    }

    // ----- notices -------------------------------------------------------------------

    pub fn inform(&mut self, text: impl Into<String>, kind: NoticeKind) {
        self.notice = Some(Notice {
            text: text.into(),
            kind,
            until: self.ticks + NOTICE_TICKS,
        });
    }

    fn expire_notice(&mut self) {
        if let Some(notice) = &self.notice {
            if self.ticks >= notice.until {
                self.notice = None;
            }
        }
    }
}

/// Appends to a field that may not exist, answering whether there was one.
fn push_into(field: Option<&mut String>, text: &str) -> bool {
    match field {
        Some(field) => {
            field.push_str(text);
            true
        }
        None => false,
    }
}

/// A caller-owned turn id is the retry and concurrency boundary at the gateway. Prefer
/// OS randomness; the timestamp/process/sequence fallback keeps the composer usable on a
/// platform whose entropy source is temporarily unavailable without reusing an id inside
/// this process.
fn new_turn_id() -> String {
    let mut bytes = [0_u8; 16];

    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_ok() {
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        return format!("ouro-{encoded}");
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let sequence = TURN_ID_FALLBACK_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    format!("ouro-{}-{timestamp:x}-{sequence:x}", std::process::id())
}

fn value_usize(value: Option<&Value>) -> Option<usize> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}
