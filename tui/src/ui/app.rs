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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::config::{Config, Defaults};
use crate::model::{
    self, ApprovalDecision, ApprovalMode, ApprovalScope, CursorPruned, Event, EventType, Plane,
    ProviderEntry, RuntimeStatus, SessionInfo, StartRequest, StartedRef,
};
use crate::proto::{ErrorCode, Hello, Notification, RpcError};
use crate::runtime::LogRing;
use crate::transport::ClientError;

use super::transcript::{Note, Watch};
use super::tree::TreeState;

/// The driver's tick. Everything measured in ticks below is measured in these.
pub const TICK: Duration = Duration::from_millis(250);

const STATUS_TICKS: u64 = 12; // 3s
const LIST_TICKS: u64 = 12; // 3s
const UPGRADE_TICKS: u64 = 20; // 5s
const DETAIL_TICKS: u64 = 40; // 10s: `Mesh.state/1` is a whole agent's state tree
const PROVIDER_TICKS: u64 = 240; // 60s: each entry probes an executable
const NOTICE_TICKS: u64 = 20;

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
    /// `interactive.start` / `coding.start`. Separate from [`Tag::Action`] because the
    /// answer carries the id of a session that did not exist when the request was made.
    Start {
        plane: Plane,
    },
    /// The first message of a session this client just started.
    FirstMessage {
        plane: Plane,
        id: String,
    },
}

#[derive(Debug)]
pub enum Msg {
    Key(crossterm::event::KeyEvent),
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
pub enum ComposerVerb {
    Message,
    Steer,
}

impl ComposerVerb {
    pub fn title(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Steer => "steer",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Message => "send_message",
            Self::Steer => "steer",
        }
    }
}

#[derive(Debug)]
pub struct Composer {
    pub verb: ComposerVerb,
    pub buffer: String,
}

#[derive(Debug, Default)]
pub struct SessionsTab {
    pub interactive: Loadable<Vec<SessionInfo>>,
    pub coding: Loadable<Vec<SessionInfo>>,
    pub selected: usize,
    pub open: Option<(Plane, String)>,
    pub watches: HashMap<(Plane, String), Watch>,
    pub composer: Option<Composer>,
    pub focus: Pane,
    /// Per-session resync rounds since the last interruption, bounded.
    rounds: HashMap<(Plane, String), u32>,
}

impl SessionsTab {
    /// Both planes' sessions in one list, ordered so the list does not reshuffle under the
    /// cursor between polls: newest activity first, ties broken by plane then id.
    pub fn merged(&self) -> Vec<&SessionInfo> {
        let mut rows: Vec<&SessionInfo> = self
            .interactive
            .value
            .iter()
            .flatten()
            .chain(self.coding.value.iter().flatten())
            .collect();

        rows.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.plane.cmp(&right.plane))
                .then_with(|| left.id.cmp(&right.id))
        });

        rows
    }

    pub fn current(&self) -> Option<&SessionInfo> {
        self.merged().get(self.selected).copied()
    }

    pub fn open_watch(&self) -> Option<&Watch> {
        self.watches.get(self.open.as_ref()?)
    }

    fn open_watch_mut(&mut self) -> Option<&mut Watch> {
        let key = self.open.clone()?;
        self.watches.get_mut(&key)
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
pub enum PromptKind {
    HistoryModule,
    GrantsPrincipal,
}

/// How many rows an approval-mode cycler has: the four the schema declares, plus the
/// "say nothing" row that is not one of them.
pub const APPROVAL_ROWS: usize = ApprovalMode::ALL.len() + 1;

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

/// One row of a provider picker that has to be able to show a stored default the runtime
/// does not report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderChoice {
    /// No default: every session states its own provider, as it always did.
    Unset,
    /// A provider this runtime reports, and whether its probe found an executable.
    Probed { name: String, ready: bool },
    /// The config file names it and this runtime's provider list does not.
    Unserved { name: String },
}

impl ProviderChoice {
    /// The name to store, or `None` for the "unset" row.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Unset => None,
            Self::Probed { name, .. } | Self::Unserved { name } => Some(name),
        }
    }
}

/// The rows the settings provider picker offers.
///
/// "unset" first, then whatever `runtime.providers` reported, then the stored default when
/// this runtime does not report it. That last row is why this is a function rather than an
/// index into the probe list: a config written on another machine — or before a provider
/// was removed — names something the probe will not list, and a picker that silently
/// dropped it would show an operator a default they no longer have.
pub fn provider_choices(providers: &[ProviderEntry], stored: Option<&str>) -> Vec<ProviderChoice> {
    let mut choices = vec![ProviderChoice::Unset];

    choices.extend(providers.iter().map(|entry| ProviderChoice::Probed {
        name: entry.provider.clone(),
        ready: entry.ready(),
    }));

    if let Some(stored) = stored.map(str::trim).filter(|stored| !stored.is_empty()) {
        if !providers.iter().any(|entry| entry.provider == stored) {
            choices.push(ProviderChoice::Unserved {
                name: stored.to_string(),
            });
        }
    }

    choices
}

/// One row of the new-session dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewField {
    Plane,
    Provider,
    Workspace,
    ApprovalMode,
    /// Only reachable on the coding plane, where the objective is required.
    Objective,
    Start,
}

/// The dialog that turns "start a session" into a set of stated choices.
///
/// Every field is on screen at once, and every one of them stays editable. What the config
/// file supplies is where the *cursor starts*, never what gets sent: a prefilled provider
/// is one the operator chose once, explicitly, in a file they can read, which is a
/// different thing from a node's default deciding for them. With no config the dialog is
/// exactly what it was — provider on row one, nothing preselected but the first entry.
///
/// The provider list comes from `runtime.providers` — the same answer the Dashboard shows
/// — and an entry whose probe found no executable is drawn dim but is **still
/// selectable**: "installed" means a file exists, the runtime is the authority on whether
/// a session can start, and refusing on a heuristic would be this client overruling it.
#[derive(Debug)]
pub struct NewSession {
    pub field: NewField,
    pub request: StartRequest,
    /// Index into the provider list, kept rather than the name so the cursor survives a
    /// providers refresh that reordered nothing.
    pub provider: usize,
    pub approval: usize,
    /// True while `*.start` is in flight — it declares a 120s ceiling, so this is a dialog
    /// that legitimately waits.
    pub pending: bool,
    /// Why the last attempt did not start a session. Shown here rather than in the notice
    /// line: the operator is still looking at the form that produced it.
    pub error: Option<String>,
    /// The provider the config file names, until the probe list arrives and the cursor can
    /// be put on it.
    ///
    /// A name rather than an index because the list it indexes into is fetched
    /// asynchronously and may not exist when this dialog opens. Cleared the moment it is
    /// placed — or the moment the operator moves the cursor themselves, so a providers
    /// answer that lands late cannot move a choice they already made.
    wanted_provider: Option<String>,
}

impl NewSession {
    fn new(plane: Plane, workspace: String, defaults: &Defaults) -> Self {
        Self {
            field: NewField::Provider,
            request: StartRequest {
                workspace,
                ..StartRequest::new(plane)
            },
            provider: 0,
            approval: approval_index(defaults.approval_mode()),
            pending: false,
            error: None,
            wanted_provider: defaults.provider.clone(),
        }
    }

    /// Puts the cursor on the provider the config names, once the list is known.
    ///
    /// Answers the stored name back when this runtime does not serve it, so the caller can
    /// say so rather than leaving the cursor somewhere the operator did not choose. Idle
    /// on every later call — a default is applied once, and the cursor is the operator's
    /// afterwards.
    fn place_provider(&mut self, providers: &[ProviderEntry]) -> Option<String> {
        let wanted = self.wanted_provider.clone()?;

        if providers.is_empty() {
            return None;
        }

        self.wanted_provider = None;

        match providers.iter().position(|entry| entry.provider == wanted) {
            Some(index) => {
                self.provider = index;
                None
            }
            None => Some(wanted),
        }
    }

    /// The rows this plane has. `objective` exists only where the gateway accepts it.
    pub fn fields(&self) -> Vec<NewField> {
        let mut fields = vec![NewField::Plane, NewField::Provider];

        if self.request.plane == Plane::Coding {
            fields.push(NewField::Objective);
        }

        fields.extend([NewField::Workspace, NewField::ApprovalMode, NewField::Start]);
        fields
    }

    pub fn approval_mode(&self) -> Option<ApprovalMode> {
        approval_at(self.approval)
    }

    /// The approval row's label, including the "say nothing" option at index 0.
    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    /// The request as the fields currently read.
    pub fn resolved(&self, providers: &[ProviderEntry]) -> StartRequest {
        let mut request = self.request.clone();

        request.provider = providers
            .get(self.provider)
            .map(|entry| entry.provider.clone())
            .unwrap_or_default();

        request.approval_mode = self.approval_mode();
        request
    }

    fn move_field(&mut self, delta: isize) {
        let fields = self.fields();

        let index = fields
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as isize;

        let next = (index + delta).rem_euclid(fields.len() as isize) as usize;
        self.field = fields[next];
    }

    fn cycle(&mut self, delta: isize, providers: usize) {
        match self.field {
            NewField::Plane => {
                self.request.plane = match self.request.plane {
                    Plane::Interactive => Plane::Coding,
                    Plane::Coding => Plane::Interactive,
                };

                // The objective row appears and disappears with the plane; the cursor
                // must not be left pointing at a row that no longer exists.
                if !self.fields().contains(&self.field) {
                    self.field = NewField::Provider;
                }
            }
            NewField::Provider if providers > 0 => {
                // The operator is choosing now, so a providers answer still in flight must
                // not move the cursor out from under them afterwards.
                self.wanted_provider = None;
                self.provider =
                    (self.provider as isize + delta).rem_euclid(providers as isize) as usize;
            }
            NewField::ApprovalMode => {
                self.approval =
                    (self.approval as isize + delta).rem_euclid(APPROVAL_ROWS as isize) as usize;
            }
            _ => {}
        }
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            NewField::Workspace => Some(&mut self.request.workspace),
            NewField::Objective => Some(&mut self.request.objective),
            _ => None,
        }
    }
}

/// Which half of the quick-start screen the keyboard belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuickZone {
    Picker,
    Prompt,
}

impl QuickZone {
    fn other(self) -> Self {
        match self {
            Self::Picker => Self::Prompt,
            Self::Prompt => Self::Picker,
        }
    }
}

/// The screen that turns "I want an agent to do a thing" into a running session in one
/// keystroke.
///
/// It exists because the shortest honest path is *pick a model, say what you want, go* —
/// not a page of facts to acknowledge before any of that can start. Everything on it that
/// is not the picker or the prompt is **stated**, never asked: the workspace and the
/// approval mode are shown with where they came from, and changing either is what the `n`
/// dialog and `,` are for.
///
/// It is not a wizard. There is exactly one screen, Enter does the whole path, and Esc
/// leaves for the Dashboard with nothing started.
#[derive(Debug)]
pub struct QuickStart {
    pub zone: QuickZone,
    /// Index into `runtime.providers`, which is the same list the Dashboard and the `n`
    /// dialog draw.
    pub provider: usize,
    pub prompt: String,
    /// True while `interactive.start` is in flight. It declares a 120s ceiling, so this is
    /// a screen that legitimately waits.
    pub pending: bool,
    /// Why the last attempt did not start a session, shown on the screen that produced it
    /// rather than in a notice line that expires.
    pub error: Option<String>,
    /// Whether this is the operator's first run, which is the only time the screen also
    /// says where this client keeps its files.
    pub first_run: bool,
    /// Whether the cursor has been put where the defaults say. False until the provider
    /// list arrives; true forever after, including once the operator moves it themselves.
    placed: bool,
    wanted_provider: Option<String>,
}

impl QuickStart {
    /// Puts the cursor on the provider to start from, once the list is known.
    ///
    /// The stored default when this runtime reports it; otherwise the first entry whose
    /// probe found an executable, because a quick start that opened on one the runtime
    /// cannot run would be one keystroke from a refusal. When nothing is ready it lands on
    /// the first row anyway — the list stays the operator's to pick from, and the runtime
    /// is the authority on whether a start works.
    ///
    /// Answers the stored name back when this runtime does not serve it, so the caller can
    /// say so.
    fn place_provider(&mut self, providers: &[ProviderEntry]) -> Option<String> {
        if self.placed || providers.is_empty() {
            return None;
        }

        self.placed = true;
        let first_ready = providers
            .iter()
            .position(|entry| entry.ready())
            .unwrap_or(0);

        let Some(wanted) = self.wanted_provider.take() else {
            self.provider = first_ready;
            return None;
        };

        match providers.iter().position(|entry| entry.provider == wanted) {
            Some(index) => {
                self.provider = index;
                None
            }
            None => {
                self.provider = first_ready;
                Some(wanted)
            }
        }
    }

    fn move_provider(&mut self, delta: isize, providers: usize) {
        if providers == 0 {
            return;
        }

        // Choosing now, so a providers answer still in flight must not move the cursor out
        // from under the operator afterwards.
        self.placed = true;
        self.wanted_provider = None;
        self.provider = (self.provider as isize + delta).rem_euclid(providers as isize) as usize;
    }
}

/// One editable row of the settings overlay. The facts above them are not rows: they are
/// what the runtime reported, and nothing here can change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Provider,
    Workspace,
    ApprovalMode,
    QuickStart,
    Save,
}

impl SettingsField {
    pub const ALL: [SettingsField; 5] = [
        SettingsField::Provider,
        SettingsField::Workspace,
        SettingsField::ApprovalMode,
        SettingsField::QuickStart,
        SettingsField::Save,
    ];
}

/// The `,` overlay: what the runtime says, and what this client remembers.
///
/// The two halves are labelled separately and never mixed. Above the rows are facts read
/// off the handshake and this process's own paths; the rows themselves are the config
/// file's, and saving is the only thing that writes one. A settings screen that showed a
/// stored provider beside a node name as if both came from the same place would be this
/// client claiming the runtime confirmed a preference it has never been told about.
#[derive(Debug)]
pub struct Settings {
    pub field: SettingsField,
    /// Index into [`provider_choices`], where 0 is "unset".
    pub provider: usize,
    pub workspace: String,
    pub approval: usize,
    /// Whether the quick-start screen opens on its own when this node has nothing live.
    pub quick_start: bool,
    /// The stored provider, until the probe list arrives and the cursor can be put on it.
    wanted_provider: Option<String>,
    /// Whether anything has been typed or cycled, so closing can say what it discards.
    pub edited: bool,
}

impl Settings {
    fn place_provider(&mut self, choices: &[ProviderChoice]) {
        let Some(wanted) = self.wanted_provider.clone() else {
            return;
        };

        // One row is always present, so a list of one is a list that has not arrived.
        if choices.len() < 2 {
            return;
        }

        self.wanted_provider = None;

        // `provider_choices` appends an unserved stored default rather than dropping it,
        // so a stored name always has a row here — which is what makes this a `position`
        // that cannot silently land on "unset".
        if let Some(index) = choices
            .iter()
            .position(|choice| choice.name() == Some(wanted.as_str()))
        {
            self.provider = index;
        }
    }

    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            SettingsField::Workspace => Some(&mut self.workspace),
            _ => None,
        }
    }

    fn move_field(&mut self, delta: isize) {
        let index = SettingsField::ALL
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as isize;

        let next = (index + delta).rem_euclid(SettingsField::ALL.len() as isize) as usize;
        self.field = SettingsField::ALL[next];
    }

    fn cycle(&mut self, delta: isize, providers: usize) {
        match self.field {
            SettingsField::Provider if providers > 0 => {
                self.wanted_provider = None;
                self.edited = true;
                self.provider =
                    (self.provider as isize + delta).rem_euclid(providers as isize) as usize;
            }
            SettingsField::ApprovalMode => {
                self.edited = true;
                self.approval =
                    (self.approval as isize + delta).rem_euclid(APPROVAL_ROWS as isize) as usize;
            }
            SettingsField::QuickStart => {
                self.edited = true;
                self.quick_start = !self.quick_start;
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
pub enum Overlay {
    Help,
    /// Pick a model, say what you want, press Enter.
    QuickStart(Box<QuickStart>),
    /// This client's own preferences, beside the facts the runtime reports.
    Settings(Box<Settings>),
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

/// Whether the quick-start screen opens, and the whole of the rule.
///
/// A first run opens it whatever else is true: there is nothing to go back to, and the
/// screen *is* how this client introduces itself. Afterwards it stops being a greeting and
/// becomes the "type and go" path, so it opens only when this node has nothing live to
/// return to — and only while the operator leaves it on. Both halves matter: a screen that
/// appeared over a running session would be interrupting work to offer to start some.
pub fn should_quick_start(first_run: bool, enabled: bool, live_sessions: usize) -> bool {
    first_run || (enabled && live_sessions == 0)
}

/// How far the quick-start decision has got. It is made at most once per process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuickIntent {
    /// Nobody has asked. `ouro new` leaves it here: that invocation already knows what it
    /// wants, and a screen offering to start a session over the one it just started would
    /// be absurd.
    Unasked,
    /// Wanted, waiting on the session lists to say whether there is anything live.
    Waiting,
    /// Decided, whichever way it went. Never asked again in this session.
    Settled,
}

/// The last seen sequence per watched session, shared with the reconnect hook.
///
/// The hook runs inside the transport's task, after a handshake this App did not witness,
/// and it has to know where each subscription left off. A mutex around a small map is the
/// whole coupling: the App writes cursors, the hook reads them, and the answers come back
/// as ordinary [`Msg::Answer`]s so there is still one resync code path.
#[derive(Debug, Clone, Default)]
pub struct Cursors {
    inner: Arc<Mutex<BTreeMap<(Plane, String), u64>>>,
}

impl Cursors {
    pub fn set(&self, plane: Plane, id: &str, cursor: u64) {
        if let Ok(mut cursors) = self.inner.lock() {
            cursors.insert((plane, id.to_string()), cursor);
        }
    }

    pub fn forget(&self, plane: Plane, id: &str) {
        if let Ok(mut cursors) = self.inner.lock() {
            cursors.remove(&(plane, id.to_string()));
        }
    }

    pub fn snapshot(&self) -> Vec<(Plane, String, u64)> {
        self.inner
            .lock()
            .map(|cursors| {
                cursors
                    .iter()
                    .map(|((plane, id), cursor)| (*plane, id.clone(), *cursor))
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
    /// Where [`config`](Self::config) is read from and written to. `None` only when there
    /// is nowhere to keep preferences at all, which the settings overlay says out loud.
    pub config_path: Option<PathBuf>,
    /// The data directory this client told the runtime to use, when it started one.
    ///
    /// `None` in attach mode on purpose: a client that did not spawn this runtime does not
    /// know where that runtime keeps its files, and a local path printed under a remote
    /// node would be a guess wearing a fact's clothes.
    pub data_dir: Option<String>,
    outbound: VecDeque<Call>,
    in_flight: HashSet<Tag>,
    dropped_seen: u64,
    /// Set when the App has changed [`config`](Self::config) and wants it on disk. Drained
    /// by the driver, exactly like [`Call`]s are, because this type does no I/O.
    save_pending: bool,
    quick_intent: QuickIntent,
    /// The quick-start screen's prompt, held between `*.start` being issued and its answer
    /// arriving. There is nothing to send it to until the session exists.
    first_message: Option<String>,
}

impl App {
    pub fn new(mode: Mode, address: String, hello: Hello, logs: Option<LogRing>) -> Self {
        Self {
            mode,
            address,
            hello,
            connection: Connection::Live,
            tab: Tab::Dashboard,
            ticks: 0,
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
            config_path: None,
            data_dir: None,
            outbound: VecDeque::new(),
            in_flight: HashSet::new(),
            dropped_seen: 0,
            save_pending: false,
            quick_intent: QuickIntent::Unasked,
            first_message: None,
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

    pub fn spawned(&self) -> bool {
        matches!(self.mode, Mode::Spawned { .. })
    }

    pub fn apply(&mut self, message: Msg) {
        match message {
            Msg::Key(key) => self.key(key),
            Msg::Tick => {
                self.ticks += 1;
                self.expire_notice();
                self.poll();
            }
            Msg::Redraw => {}
            Msg::Notification(notification) => self.notification(notification),
            Msg::Answer { tag, result } => self.answer(tag, result),
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
        }
    }

    // ----- refresh -------------------------------------------------------------------

    /// Issues the polls the visible tab is due for. Only the visible tab: a Dashboard
    /// nobody is looking at is not a reason to keep a runtime answering.
    fn poll(&mut self) {
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

    // ----- answers -------------------------------------------------------------------

    fn answer(&mut self, tag: Tag, result: Result<Value, ClientError>) {
        self.in_flight.remove(&tag);

        if let Err(error) = &result {
            if matches!(
                error,
                ClientError::ConnectionClosed | ClientError::Stopped(_)
            ) {
                self.connection = Connection::Lost {
                    reason: error.to_string(),
                };
            }
        }

        let ticks = self.ticks;

        match tag {
            Tag::Status => match result {
                Ok(value) => match RuntimeStatus::decode(&value) {
                    Ok(status) => self.status.ok(status, ticks, STATUS_TICKS),
                    Err(error) => self.status.failed(
                        format!("runtime.status did not decode: {error}"),
                        ticks,
                        STATUS_TICKS,
                    ),
                },
                Err(error) => self.status.failed(error.to_string(), ticks, STATUS_TICKS),
            },
            Tag::Providers => match result {
                Ok(value) => {
                    let providers = ProviderEntry::decode_list(&value);
                    self.providers.ok(providers, ticks, PROVIDER_TICKS);
                    // A dialog opened before the list arrived has a default it could not
                    // point at yet. This is the moment it can.
                    self.place_default_provider();
                }
                Err(error) => self
                    .providers
                    .failed(error.to_string(), ticks, PROVIDER_TICKS),
            },
            Tag::Sessions(plane) => {
                let panel = match plane {
                    Plane::Interactive => &mut self.sessions.interactive,
                    Plane::Coding => &mut self.sessions.coding,
                };

                match result {
                    Ok(value) => {
                        panel.ok(SessionInfo::decode_list(plane, &value), ticks, LIST_TICKS)
                    }
                    Err(error) => panel.failed(error.to_string(), ticks, LIST_TICKS),
                }

                // Whether this node has live work is the other half of the quick-start
                // question, and this is the only place it becomes knowable.
                self.settle_quick_start();
            }
            Tag::Agents => Self::fill_rows(&mut self.agents, result, ticks, project_agent),
            Tag::Teams => Self::fill_rows(&mut self.teams, result, ticks, project_team),
            Tag::Plans => Self::fill_rows(&mut self.plans, result, ticks, project_plan),
            Tag::ControlRuns => Self::fill_rows(&mut self.control, result, ticks, project_run),
            Tag::AgentState(_) => Self::fill_detail(&mut self.agents, result, ticks),
            Tag::TeamState(_) => Self::fill_detail(&mut self.teams, result, ticks),
            Tag::Plan(_) => Self::fill_detail(&mut self.plans, result, ticks),
            Tag::ControlRun(_) => Self::fill_detail(&mut self.control, result, ticks),
            Tag::UpgradeStatus => {
                Self::fill_value(&mut self.upgrade.status, result, ticks, UPGRADE_TICKS)
            }
            Tag::Rollouts => {
                Self::fill_value(&mut self.upgrade.rollouts, result, ticks, UPGRADE_TICKS)
            }
            Tag::History(_) => {
                Self::fill_value(&mut self.upgrade.history, result, ticks, UPGRADE_TICKS)
            }
            Tag::Signing => {
                Self::fill_value(&mut self.upgrade.signing, result, ticks, UPGRADE_TICKS)
            }
            Tag::Grants(_) => {
                Self::fill_value(&mut self.upgrade.grants, result, ticks, UPGRADE_TICKS)
            }
            Tag::Resync {
                plane,
                id,
                cursor,
                subscribe,
            } => self.resync_answered(plane, id, cursor, subscribe, result),
            Tag::Action { label, plane, id } => match result {
                Ok(_value) => self.inform(format!("{label} accepted for {id}"), NoticeKind::Info),
                Err(error) => self.action_failed(label, plane, &id, error),
            },
            Tag::Start { plane } => match result {
                Ok(value) => match StartedRef::decode(&value) {
                    Some(started) => self.started(plane, started),
                    // The session exists; this client just cannot address it. Saying so is
                    // the only honest answer — retrying would start a second one.
                    None => self.start_failed(ClientError::BadJson(format!(
                        "the runtime started a session but answered a reference this build \
                         cannot read: {value}"
                    ))),
                },
                Err(error) => self.start_failed(error),
            },
            Tag::FirstMessage { plane, id } => match result {
                Ok(_value) => {}
                Err(error) => self.action_failed("send_message", plane, &id, error),
            },
        }
    }

    fn fill_rows(
        explorer: &mut Explorer,
        result: Result<Value, ClientError>,
        ticks: u64,
        project: fn(&Value) -> Option<Row>,
    ) {
        match result {
            Ok(value) => {
                let rows: Vec<Row> = value
                    .as_array()
                    .map(|items| items.iter().filter_map(project).collect())
                    .unwrap_or_default();

                if explorer.selected >= rows.len() {
                    explorer.selected = rows.len().saturating_sub(1);
                }

                explorer.rows.ok(rows, ticks, LIST_TICKS);
            }
            Err(error) => explorer.rows.failed(error.to_string(), ticks, LIST_TICKS),
        }
    }

    fn fill_detail(explorer: &mut Explorer, result: Result<Value, ClientError>, ticks: u64) {
        match result {
            Ok(value) => explorer.detail.ok(value, ticks, DETAIL_TICKS),
            Err(error) => explorer
                .detail
                .failed(error.to_string(), ticks, DETAIL_TICKS),
        }
    }

    fn fill_value(
        panel: &mut Loadable<Value>,
        result: Result<Value, ClientError>,
        ticks: u64,
        cadence: u64,
    ) {
        match result {
            Ok(value) => panel.ok(value, ticks, cadence),
            Err(error) => panel.failed(error.to_string(), ticks, cadence),
        }
    }

    /// A refused operate verb, said in the terms the gateway used.
    fn action_failed(&mut self, label: &str, _plane: Plane, id: &str, error: ClientError) {
        let text = match &error {
            ClientError::Rpc(rpc) if rpc.code == ErrorCode::ScopeDenied => format!(
                "{label} was refused: this listener runs at scope `{}` and {label} mutates the \
                 runtime",
                self.hello.scope
            ),
            ClientError::Rpc(rpc)
                if rpc.code == ErrorCode::UpstreamTimeout
                    && model::outcome_unknown(rpc.data.as_ref()) =>
            {
                format!(
                    "{label} on {id}: the gateway stopped waiting, the runtime did not stop \
                     working — read the session to see which it was"
                )
            }
            ClientError::Rpc(rpc) => format!("{label} on {id}: {}", refusal(rpc)),
            other => format!("{label} on {id} failed: {other}"),
        };

        self.inform(text, NoticeKind::Error);
    }

    // ----- streaming -----------------------------------------------------------------

    fn notification(&mut self, notification: Notification) {
        match notification.method.as_str() {
            "interactive.event" => self.event(Plane::Interactive, &notification.params),
            "coding.event" => self.event(Plane::Coding, &notification.params),
            "stream.lagged" => self.lagged(&notification.params),
            "stream.ended" => self.ended(&notification.params),
            // A notification a newer gateway invented. Counted in the notice line rather
            // than dropped in silence, because it is evidence of a version skew.
            other => self.inform(
                format!("the gateway sent a notification this build does not know: {other}"),
                NoticeKind::Warn,
            ),
        }
    }

    fn event(&mut self, plane: Plane, params: &Value) {
        let Some(id) = params.get("id").and_then(Value::as_str) else {
            return;
        };

        let key = (plane, id.to_string());

        let Some(watch) = self.sessions.watches.get_mut(&key) else {
            // An event for a session this client stopped watching. The gateway drops the
            // registration on unsubscribe, so this is the one frame that can cross it.
            return;
        };

        let Some(event) = params.get("event") else {
            return;
        };

        match Event::decode(event) {
            Ok(event) => {
                let approval = matches!(event.kind, EventType::ApprovalRequested);
                watch.absorb(vec![event]);

                let cursor = watch.cursor();
                let gap = watch.has_gap();

                self.cursors.set(plane, id, cursor);

                // A hole in the live stream that no `stream.lagged` explained: this side
                // lost frames, and the repair is the same one.
                if gap {
                    self.resync(plane, id.to_string(), false);
                }

                if approval {
                    self.open_approval(plane, id.to_string());
                }
            }
            Err(_undecodable) => watch.undecodable += 1,
        }
    }

    fn lagged(&mut self, params: &Value) {
        let Ok(lagged) = serde_json::from_value::<model::Lagged>(params.clone()) else {
            return;
        };

        let Some((plane, key)) = self.locate(lagged.plane(), &lagged.id) else {
            return;
        };

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.dropped += lagged.dropped;
            watch.note(
                Note::Lagged {
                    dropped: lagged.dropped,
                },
                lagged.last_sequence,
            );
        }

        self.sessions.rounds.remove(&key);
        self.inform(
            format!(
                "the gateway dropped {} event frames for {}; replaying from {}",
                lagged.dropped,
                lagged.id,
                self.sessions
                    .watches
                    .get(&key)
                    .map(Watch::cursor)
                    .unwrap_or(0)
            ),
            NoticeKind::Warn,
        );

        self.resync(plane, lagged.id, false);
    }

    fn ended(&mut self, params: &Value) {
        let Ok(ended) = serde_json::from_value::<model::Ended>(params.clone()) else {
            return;
        };

        let Some((plane, key)) = self.locate(ended.plane(), &ended.id) else {
            return;
        };

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.end(ended.status.clone());
        }

        self.cursors.forget(plane, &ended.id);
    }

    /// A notification the transport could not hand over is indistinguishable from a lag,
    /// except that this side lost it. Every watched session is resynced, because the
    /// counter does not say which one the frame belonged to.
    fn client_dropped(&mut self, total: u64) {
        if total <= self.dropped_seen {
            return;
        }

        let lost = total - self.dropped_seen;
        self.dropped_seen = total;

        self.note_all_watches(Note::ClientDropped);

        for watch in self.sessions.watches.values_mut() {
            watch.dropped += lost;
        }

        self.inform(
            format!(
                "this client could not take {lost} event frames; replaying every watched session"
            ),
            NoticeKind::Warn,
        );

        let keys: Vec<(Plane, String)> = self.sessions.watches.keys().cloned().collect();

        for (plane, id) in keys {
            self.sessions.rounds.remove(&(plane, id.clone()));
            self.resync(plane, id, false);
        }
    }

    fn note_all_watches(&mut self, note: Note) {
        for watch in self.sessions.watches.values_mut() {
            let at = watch.newest();
            watch.note(note.clone(), at);
        }
    }

    /// The one repair. `subscribe` is true when the registration is gone (a first open, or
    /// a reconnect) and false when only frames were lost.
    fn resync(&mut self, plane: Plane, id: String, subscribe: bool) {
        let key = (plane, id.clone());

        let Some(watch) = self.sessions.watches.get_mut(&key) else {
            return;
        };

        if watch.ended.is_some() && !subscribe {
            return;
        }

        if watch.resyncing {
            // A second interruption while the first repair is in flight. The answer on
            // its way was asked from a cursor that predates this one, so it cannot repair
            // it — the request is remembered rather than dropped.
            watch.resync_again = true;
            return;
        }

        let rounds = self.sessions.rounds.entry(key.clone()).or_insert(0);
        *rounds += 1;

        if *rounds > MAX_RESYNC_ROUNDS {
            self.inform(
                format!(
                    "{id} is producing history faster than this client can replay it; the \
                     transcript keeps its gap rather than looping"
                ),
                NoticeKind::Error,
            );

            return;
        }

        watch.resyncing = true;
        let cursor = watch.cursor();

        let (verb, params) = if subscribe {
            ("subscribe", json!({ "id": id, "cursor": cursor }))
        } else {
            (
                "replay",
                json!({ "id": id, "cursor": cursor, "limit": REPLAY_LIMIT }),
            )
        };

        self.issue(Call::new(
            Tag::Resync {
                plane,
                id: id.clone(),
                cursor,
                subscribe,
            },
            plane.method(verb),
            params,
        ));
    }

    fn resync_answered(
        &mut self,
        plane: Plane,
        id: String,
        asked_from: u64,
        subscribe: bool,
        result: Result<Value, ClientError>,
    ) {
        let key = (plane, id.clone());

        let Some(watch) = self.sessions.watches.get_mut(&key) else {
            return;
        };

        watch.resyncing = false;

        match result {
            Ok(value) => {
                let (events, refused) = Event::decode_batch(&value);
                let batch = events.len() as u64;
                let approvals = events
                    .iter()
                    .any(|event| matches!(event.kind, EventType::ApprovalRequested));

                // Both verbs answer "the retained events after this cursor, in order". A
                // first entry above `cursor + 1` therefore *proves* the ones between are
                // no longer retained — a prune the gateway had no reason to raise, since
                // the cursor itself was still inside the window. Raising the floor here
                // is what stops the transcript showing a hole that will never fill.
                if let Some(first) = events.first().map(|event| event.sequence) {
                    if first > asked_from + 1 {
                        watch.raise_floor(first - 1);
                    }
                }

                watch.undecodable += refused;
                let before = watch.cursor();
                watch.absorb(events);

                let cursor = watch.cursor();
                let progressed = cursor > before;
                let more = batch >= REPLAY_LIMIT || watch.has_gap();
                let again = std::mem::take(&mut watch.resync_again);

                self.cursors.set(plane, &id, cursor);

                // Another round while it is buying something, or because an interruption
                // arrived while this one was in flight. A replay that answered nothing new
                // and had no second cause leaves the gap visible instead of asking again
                // forever.
                if (progressed && more) || again {
                    self.resync(plane, id.clone(), false);
                } else {
                    self.sessions.rounds.remove(&key);
                }

                if approvals {
                    self.open_approval(plane, id);
                }
            }
            Err(ClientError::Rpc(rpc)) => {
                match CursorPruned::from_error_data(rpc.data.as_ref()) {
                    Some(pruned) => {
                        watch.raise_floor(pruned.floor);
                        watch.resync_again = false;
                        let cursor = watch.cursor();
                        self.cursors.set(plane, &id, cursor);

                        self.inform(
                            format!(
                                "{id}: the runtime no longer retains history below {}; the \
                                 transcript starts there",
                                pruned.floor
                            ),
                            NoticeKind::Warn,
                        );

                        // Restart from the floor through the same path, which is why the
                        // prune arm is three lines rather than a second implementation.
                        self.resync(plane, id, subscribe);
                    }
                    None => {
                        watch.resync_again = false;
                        self.sessions.rounds.remove(&key);
                        self.inform(format!("replaying {id} failed: {rpc}"), NoticeKind::Error);
                    }
                }
            }
            Err(other) => {
                watch.resync_again = false;
                self.sessions.rounds.remove(&key);
                self.inform(format!("replaying {id} failed: {other}"), NoticeKind::Error);
            }
        }
    }

    /// Which watched session a stream notification is about. The plane is on the wire, but
    /// an id this client is watching on exactly one plane is answerable without it.
    fn locate(&self, plane: Option<Plane>, id: &str) -> Option<(Plane, (Plane, String))> {
        if let Some(plane) = plane {
            let key = (plane, id.to_string());

            if self.sessions.watches.contains_key(&key) {
                return Some((plane, key));
            }
        }

        self.sessions
            .watches
            .keys()
            .find(|(_plane, watched)| watched == id)
            .map(|key| (key.0, key.clone()))
    }

    /// Opens (or re-opens) a session: one watch, one subscribe, and the cursor registered
    /// where the reconnect hook can find it.
    pub fn open_session(&mut self, plane: Plane, id: String) {
        let key = (plane, id.clone());

        self.sessions
            .watches
            .entry(key.clone())
            .or_insert_with(|| Watch::new(plane, id.clone()));

        self.sessions.open = Some(key.clone());
        self.sessions.focus = Pane::Detail;

        // Opening a session is a request to look at it, and an approval modal raised by
        // one that opened behind another tab would have nothing legible underneath it.
        self.tab = Tab::Sessions;

        let cursor = self
            .sessions
            .watches
            .get(&key)
            .map(Watch::cursor)
            .unwrap_or(0);

        self.cursors.set(plane, &id, cursor);
        self.resync(plane, id, true);
    }

    fn open_approval(&mut self, plane: Plane, id: String) {
        // An approval modal must not steal the terminal from a dialog already open.
        if self.overlay.is_some() {
            return;
        }

        let Some(watch) = self.sessions.watches.get(&(plane, id.clone())) else {
            return;
        };

        let Some(request) = watch.next_approval() else {
            return;
        };

        self.overlay = Some(Overlay::Approval {
            plane,
            id,
            request_id: request.request_id.clone(),
            subject: request.subject(),
            choice: 0,
        });
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

    // ----- keys ----------------------------------------------------------------------

    fn key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

        // A key that is only a release is not a press. Terminals with the kitty protocol
        // send both, and acting on each would double every keystroke.
        if key.kind == KeyEventKind::Release {
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        // Never the TUI. §3.4 is explicit: ctrl-c interrupts the active turn, and `q` is
        // the only thing that quits.
        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.interrupt();
            return;
        }

        if self.overlay.is_some() {
            self.overlay_key(key);
            return;
        }

        if self.sessions.composer.is_some() && self.tab == Tab::Sessions {
            self.composer_key(key);
            return;
        }

        match key.code {
            KeyCode::Char(digit @ '1'..='7') => {
                let index = digit as usize - '1' as usize;
                self.select_tab(Tab::ALL[index]);
            }
            KeyCode::Tab => self.select_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]),
            KeyCode::BackTab => {
                let index = (self.tab.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.select_tab(Tab::ALL[index]);
            }
            KeyCode::Char('q') => self.open_quit(),
            KeyCode::Char('?') => self.overlay = Some(Overlay::Help),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('j') | KeyCode::Down => self.move_by(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_by(-1),
            KeyCode::PageDown => self.move_by(10),
            KeyCode::PageUp => self.move_by(-10),
            KeyCode::Char('h') | KeyCode::Left => self.left(),
            KeyCode::Char('l') | KeyCode::Right => self.right(),
            KeyCode::Enter => self.activate(),
            KeyCode::Esc => self.escape(),
            KeyCode::Char('i') => self.compose(ComposerVerb::Message),
            KeyCode::Char('s') => self.compose(ComposerVerb::Steer),
            KeyCode::Char('a') => self.reopen_approval(),
            KeyCode::Char('n') => self.open_new_session(),
            KeyCode::Char('x') => self.open_close_confirm(),
            // `,` is free in every other dispatch here, and it is the punctuation a
            // terminal reader already expects to mean "preferences".
            KeyCode::Char(',') => self.open_settings(),
            _ => {}
        }
    }

    fn select_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.poll();
    }

    fn move_by(&mut self, delta: isize) {
        match self.tab {
            Tab::Dashboard => {}
            Tab::Sessions => match self.sessions.focus {
                Pane::List => {
                    let len = self.sessions.merged().len();

                    if len == 0 {
                        self.sessions.selected = 0;
                    } else {
                        self.sessions.selected = (self.sessions.selected as isize + delta)
                            .clamp(0, len as isize - 1)
                            as usize;
                    }
                }
                Pane::Detail => {
                    if let Some(watch) = self.sessions.open_watch_mut() {
                        // Scrolling away from the bottom stops the transcript from
                        // jumping under a reader every time an event arrives.
                        if delta < 0 {
                            watch.follow = false;
                            watch.scroll = watch.scroll.saturating_add(delta.unsigned_abs());
                        } else {
                            watch.scroll = watch.scroll.saturating_sub(delta as usize);

                            if watch.scroll == 0 {
                                watch.follow = true;
                            }
                        }
                    }
                }
            },
            Tab::Agents => Self::explorer_move(&mut self.agents, delta),
            Tab::Teams => Self::explorer_move(&mut self.teams, delta),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                Self::explorer_move(explorer, delta);
            }
            Tab::Upgrade => match self.upgrade.focus {
                Pane::List => {
                    let len = UpgradeSection::ALL.len() as isize;
                    self.upgrade.section =
                        (self.upgrade.section as isize + delta).clamp(0, len - 1) as usize;
                    self.upgrade.tree.reset();
                    self.poll_upgrade_section();
                }
                Pane::Detail => {
                    let rows = self.upgrade_rows();
                    self.upgrade.tree.move_by(delta, rows);
                }
            },
            Tab::Logs => {
                if delta < 0 {
                    self.log_scroll = self.log_scroll.saturating_add(delta.unsigned_abs());
                } else {
                    self.log_scroll = self.log_scroll.saturating_sub(delta as usize);
                }
            }
        }
    }

    fn explorer_move(explorer: &mut Explorer, delta: isize) {
        match explorer.focus {
            Pane::List => explorer.move_by(delta),
            Pane::Detail => {
                let rows = explorer
                    .detail
                    .value
                    .as_ref()
                    .map(|value| super::tree::TreeView::new("state", value).rows(&explorer.tree))
                    .map(|rows| rows.len())
                    .unwrap_or(0);

                explorer.tree.move_by(delta, rows);
            }
        }
    }

    fn upgrade_rows(&self) -> usize {
        let section = self.upgrade.current();

        self.upgrade
            .panel(section)
            .value
            .as_ref()
            .map(|value| {
                super::tree::TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .len()
            })
            .unwrap_or(0)
    }

    fn left(&mut self) {
        match self.tab {
            Tab::Sessions => self.sessions.focus = Pane::List,
            Tab::Agents => Self::explorer_left(&mut self.agents),
            Tab::Teams => Self::explorer_left(&mut self.teams),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                if explorer.focus == Pane::List {
                    self.plans_on_control = false;
                } else {
                    Self::explorer_left(explorer);
                }
            }
            Tab::Upgrade if self.upgrade.focus == Pane::Detail => self.collapse_upgrade_or_leave(),
            _ => {}
        }
    }

    fn explorer_left(explorer: &mut Explorer) {
        if explorer.focus == Pane::List {
            return;
        }

        let Some(value) = explorer.detail.value.as_ref() else {
            explorer.focus = Pane::List;
            return;
        };

        let view = super::tree::TreeView::new("state", value);
        let rows = view.rows(&explorer.tree);

        match rows.get(explorer.tree.selected()) {
            Some(row) if row.expanded => explorer.tree.collapse(&row.path),
            // Collapsed already: left is how you get back to the list.
            _ => explorer.focus = Pane::List,
        }
    }

    fn collapse_upgrade_or_leave(&mut self) {
        let section = self.upgrade.current();
        let selected = self.upgrade.tree.selected();

        let path = self
            .upgrade
            .panel(section)
            .value
            .as_ref()
            .and_then(|value| {
                super::tree::TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .get(selected)
                    .filter(|row| row.expanded)
                    .map(|row| row.path.clone())
            });

        match path {
            Some(path) => self.upgrade.tree.collapse(&path),
            None => self.upgrade.focus = Pane::List,
        }
    }

    fn right(&mut self) {
        match self.tab {
            Tab::Sessions => {
                if self.sessions.open.is_some() {
                    self.sessions.focus = Pane::Detail;
                }
            }
            Tab::Agents => self.agents.focus = Pane::Detail,
            Tab::Teams => self.teams.focus = Pane::Detail,
            Tab::Plans => {
                let on_control = self.plans_on_control;
                let explorer = if on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                if explorer.focus == Pane::Detail && !on_control {
                    self.plans_on_control = true;
                } else {
                    explorer.focus = Pane::Detail;
                }
            }
            Tab::Upgrade => self.upgrade.focus = Pane::Detail,
            _ => {}
        }
    }

    fn activate(&mut self) {
        match self.tab {
            Tab::Sessions => match self.sessions.focus {
                Pane::List => {
                    if let Some(session) = self.sessions.current() {
                        let (plane, id) = (session.plane, session.id.clone());
                        self.open_session(plane, id);
                    }
                }
                Pane::Detail => self.compose(ComposerVerb::Message),
            },
            Tab::Agents => Self::explorer_activate(&mut self.agents),
            Tab::Teams => Self::explorer_activate(&mut self.teams),
            Tab::Plans => {
                let explorer = if self.plans_on_control {
                    &mut self.control
                } else {
                    &mut self.plans
                };

                Self::explorer_activate(explorer);
            }
            Tab::Upgrade => match self.upgrade.focus {
                Pane::List => self.activate_upgrade_section(),
                Pane::Detail => self.toggle_upgrade_row(),
            },
            _ => {}
        }
    }

    fn explorer_activate(explorer: &mut Explorer) {
        if explorer.focus == Pane::List {
            explorer.focus = Pane::Detail;
            return;
        }

        let Some(value) = explorer.detail.value.as_ref() else {
            return;
        };

        let view = super::tree::TreeView::new("state", value);
        let rows = view.rows(&explorer.tree);

        if let Some(row) = rows.get(explorer.tree.selected()) {
            if row.expandable {
                explorer.tree.toggle(&row.path);
            }
        }
    }

    fn activate_upgrade_section(&mut self) {
        match self.upgrade.current() {
            UpgradeSection::History => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::HistoryModule,
                    label: "module (e.g. Ouroboros.Capability.Example)".into(),
                    buffer: self.upgrade.history_module.clone().unwrap_or_default(),
                })
            }
            UpgradeSection::Grants => {
                self.overlay = Some(Overlay::Prompt {
                    kind: PromptKind::GrantsPrincipal,
                    // `Control.Grants.list/1` is per-principal by design; there is no
                    // list-all upstream and the gateway did not add one.
                    label: "principal".into(),
                    buffer: self.upgrade.grants_principal.clone().unwrap_or_default(),
                })
            }
            _ => self.upgrade.focus = Pane::Detail,
        }
    }

    fn toggle_upgrade_row(&mut self) {
        let section = self.upgrade.current();
        let selected = self.upgrade.tree.selected();

        let path = self
            .upgrade
            .panel(section)
            .value
            .as_ref()
            .and_then(|value| {
                super::tree::TreeView::new(section.title(), value)
                    .rows(&self.upgrade.tree)
                    .get(selected)
                    .filter(|row| row.expandable)
                    .map(|row| row.path.clone())
            });

        if let Some(path) = path {
            self.upgrade.tree.toggle(&path);
        }
    }

    fn escape(&mut self) {
        if self.tab == Tab::Sessions {
            if self.sessions.composer.is_some() {
                self.sessions.composer = None;
                return;
            }

            if self.sessions.focus == Pane::Detail {
                self.sessions.focus = Pane::List;
                return;
            }

            self.sessions.open = None;
        }
    }

    // ----- session verbs -------------------------------------------------------------

    /// Opens the composer, refusing where the plane has no such verb rather than sending
    /// a call that would come back `-32601`.
    fn compose(&mut self, verb: ComposerVerb) {
        if self.tab != Tab::Sessions {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "open a session with Enter before writing to it",
                NoticeKind::Info,
            );
            return;
        };

        if plane == Plane::Coding {
            self.inform(
                format!(
                    "{id} is a coding task: it runs one objective to completion and takes no \
                     input. `x` cancels it"
                ),
                NoticeKind::Info,
            );
            return;
        }

        let method = plane.method(verb.method());

        if !self.hello.serves(&method) {
            self.inform(
                format!("this gateway does not serve {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        self.sessions.focus = Pane::Detail;
        self.sessions.composer = Some(Composer {
            verb,
            buffer: String::new(),
        });
    }

    fn composer_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => self.sessions.composer = None,
            KeyCode::Enter => self.submit_composer(),
            KeyCode::Backspace => {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.buffer.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.buffer.push(c);
                }
            }
            _ => {}
        }
    }

    fn submit_composer(&mut self) {
        let Some(composer) = self.sessions.composer.take() else {
            return;
        };

        let input = composer.buffer.trim().to_string();

        if input.is_empty() {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        let (label, method) = match composer.verb {
            ComposerVerb::Message => ("send_message", plane.method("send_message")),
            ComposerVerb::Steer => ("steer", plane.method("steer")),
        };

        self.issue(Call::new(
            Tag::Action {
                label,
                plane,
                id: id.clone(),
            },
            method,
            json!({ "id": id, "input": input }),
        ));
    }

    /// Ctrl-C: the active turn, never this process.
    fn interrupt(&mut self) {
        if self.overlay.is_some() {
            // Leaving the quick-start screen is leaving it, however the key was pressed:
            // ctrl-c takes the same exit Esc does, so the marker is written and the
            // Dashboard is what appears, rather than a bare overlay dismissal that would
            // leave the screen able to come back.
            if matches!(self.overlay, Some(Overlay::QuickStart(_))) {
                self.leave_quick_start();
            } else {
                self.overlay = None;
            }

            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "ctrl-c interrupts a running turn; `q` opens the quit dialog",
                NoticeKind::Info,
            );
            return;
        };

        let (label, method) = match plane {
            Plane::Interactive => ("interrupt", "interactive.interrupt".to_string()),
            // The coding plane has no interrupt; cancelling is what it offers, and it is
            // destructive enough to go through the confirmation instead.
            Plane::Coding => {
                self.inform(
                    format!("{id} is a coding task; `x` cancels it"),
                    NoticeKind::Info,
                );
                return;
            }
        };

        // `interactive.interrupt` defaults to the active turn, which is the only thing a
        // terminal's ctrl-c can mean.
        self.issue(Call::new(
            Tag::Action {
                label,
                plane,
                id: id.clone(),
            },
            method,
            json!({ "id": id }),
        ));

        self.inform(
            format!("interrupting the active turn of {id}"),
            NoticeKind::Info,
        );
    }

    fn reopen_approval(&mut self) {
        if self.tab != Tab::Sessions {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        let has_pending = self
            .sessions
            .watches
            .get(&(plane, id.clone()))
            .and_then(Watch::next_approval)
            .is_some();

        if has_pending {
            self.open_approval(plane, id);
        } else {
            self.inform(
                format!("{id} is not waiting on an approval"),
                NoticeKind::Info,
            );
        }
    }

    /// `n`: the dialog that starts a session.
    ///
    /// Only on the Sessions tab, because that is where the result appears, and only when
    /// the gateway serves the verb — `hello.methods` is the feature gate (§2.3), and a
    /// read listener advertises the operate verbs it will refuse, so scope is checked too.
    fn open_new_session(&mut self) {
        if self.tab != Tab::Sessions || self.overlay.is_some() {
            return;
        }

        if !self.hello.serves("interactive.start") {
            self.inform(
                "this gateway does not serve interactive.start",
                NoticeKind::Warn,
            );
            return;
        }

        if !self.hello.operates() {
            self.inform(
                format!(
                    "starting a session mutates the runtime, and this listener runs at scope \
                     `{}`",
                    self.hello.scope
                ),
                NoticeKind::Warn,
            );
            return;
        }

        // The dialog is about to list providers, and the Sessions tab never polls them.
        self.fetch_providers();

        self.overlay = Some(Overlay::New(Box::new(NewSession::new(
            Plane::Interactive,
            self.default_workspace(),
            &self.config.defaults,
        ))));

        // The list may already be here, in which case the cursor can be placed now rather
        // than on the next answer.
        self.place_default_provider();
    }

    /// The workspace the `n` dialog and the settings overlay start from.
    ///
    /// A stored default first — it is the one the operator wrote down — then the directory
    /// this client was launched in, which is a good guess and a bad assumption. Both are
    /// prefilled and editable; neither is sent unless it is still there when start is
    /// pressed.
    fn default_workspace(&self) -> String {
        self.config
            .defaults
            .workspace
            .clone()
            .or_else(|| self.launch_dir.clone())
            .unwrap_or_default()
    }

    /// Points whichever picker is open at the provider the config names.
    ///
    /// Called both when a dialog opens and when a providers answer lands, because the two
    /// can happen in either order and the cursor has to end up in the same place either
    /// way.
    fn place_default_provider(&mut self) {
        let providers = self.providers.value.clone().unwrap_or_default();
        let stored = self.config.defaults.provider.clone();

        let unserved = match self.overlay.as_mut() {
            Some(Overlay::New(dialog)) => dialog.place_provider(&providers),
            Some(Overlay::QuickStart(quick)) => quick.place_provider(&providers),
            Some(Overlay::Settings(settings)) => {
                let choices = provider_choices(&providers, stored.as_deref());
                settings.place_provider(&choices);
                None
            }
            _ => None,
        };

        if let Some(name) = unserved {
            // Said rather than silently ignored: a default that does not exist here is the
            // operator's to know about, and the list on screen is what this runtime does
            // serve.
            self.inform(
                format!(
                    "the default provider {name:?} is not one this runtime reports; the list \
                     here is what it does serve"
                ),
                NoticeKind::Warn,
            );
        }
    }

    /// Asks for the provider list if this connection has not got one yet.
    fn fetch_providers(&mut self) {
        if self.providers.value.is_some() || self.providers.pending {
            return;
        }

        self.providers.started();
        self.issue(Call::new(Tag::Providers, "runtime.providers", json!({})));
    }

    /// Probes again, whatever the list already says.
    ///
    /// The quick-start screen's `r`, and the whole of the "install the CLI in another
    /// terminal, then come back" story: a probe is a fact about a moment, and the moment
    /// this client asked is not the moment the operator finished installing.
    fn refetch_providers(&mut self) {
        if self.providers.pending {
            return;
        }

        self.providers.started();
        self.issue(Call::new(Tag::Providers, "runtime.providers", json!({})));
    }

    // ----- quick start ----------------------------------------------------------------

    /// Offers the quick-start screen, if this is an invocation that should get one.
    ///
    /// Called once by the driver, before the first frame, and only where a session was not
    /// already asked for — `ouro new` states what it wants on the command line, and a
    /// screen offering to start one over the session it just started would be absurd.
    ///
    /// A first run opens it now rather than waiting on anything: there is nothing to
    /// return to by definition. Every other run has to know whether this node has live
    /// work, which only the two session lists can say, so they are asked for here — the
    /// Dashboard never polls them.
    pub fn offer_quick_start(&mut self) {
        if self.quick_intent != QuickIntent::Unasked {
            return;
        }

        if !self.config.onboarding.welcomed {
            self.quick_intent = QuickIntent::Settled;
            self.open_quick_start(true);
            return;
        }

        if !self.config.onboarding.quick_start {
            self.quick_intent = QuickIntent::Settled;
            return;
        }

        self.quick_intent = QuickIntent::Waiting;
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

    /// Decides the steady-state case, once both lists have answered.
    ///
    /// Both, not either: a node with no interactive sessions may still be running a coding
    /// task, and "nothing is happening here" is not something one list can say on its own.
    /// A list that was *refused* is not a list that said none, so a refusal settles the
    /// question shut rather than opening a screen on a guess.
    fn settle_quick_start(&mut self) {
        if self.quick_intent != QuickIntent::Waiting {
            return;
        }

        let refused =
            self.sessions.interactive.error.is_some() || self.sessions.coding.error.is_some();

        let (Some(interactive), Some(coding)) = (
            self.sessions.interactive.value.as_ref(),
            self.sessions.coding.value.as_ref(),
        ) else {
            if refused {
                self.quick_intent = QuickIntent::Settled;
            }

            return;
        };

        // A closed session is not work to return to. `SessionStatus::terminal` is
        // deliberately false for a status this build does not recognise, so an unknown one
        // counts as live — the safe direction, because it keeps a screen off a node that
        // may be busy.
        let live = interactive
            .iter()
            .chain(coding.iter())
            .filter(|session| !session.status.terminal())
            .count();

        self.quick_intent = QuickIntent::Settled;

        if should_quick_start(false, self.config.onboarding.quick_start, live) {
            self.open_quick_start(false);
        }
    }

    fn open_quick_start(&mut self, first_run: bool) {
        if self.overlay.is_some() {
            return;
        }

        // The picker is the provider list, and no tab has necessarily asked for it yet.
        self.fetch_providers();

        self.overlay = Some(Overlay::QuickStart(Box::new(QuickStart {
            // The prompt, so the first thing a person can do is the thing they came to do.
            zone: QuickZone::Prompt,
            provider: 0,
            prompt: String::new(),
            pending: false,
            error: None,
            first_run,
            placed: false,
            wanted_provider: self.config.defaults.provider.clone(),
        })));

        self.place_default_provider();
    }

    /// Esc, or the ctrl-c that leaves any overlay: to the Dashboard, with nothing started.
    ///
    /// The marker is written on the way out because reaching the screen is what it records.
    /// Nothing else is stored — a provider the cursor happened to be on is not a choice the
    /// operator made, and only Enter is.
    fn leave_quick_start(&mut self) {
        self.overlay = None;
        self.tab = Tab::Dashboard;
        self.mark_welcomed();
        self.poll();
    }

    fn mark_welcomed(&mut self) {
        if !self.config.onboarding.welcomed {
            self.config.onboarding.welcomed = true;
            self.save_pending = true;
        }
    }

    /// The keyboard, split between the two zones.
    ///
    /// The rule is that **letters belong to the prompt**, because typing what you want is
    /// the point of the screen and a picker that swallowed a `j` would be a text box that
    /// silently is not one. So: the arrows always move the picker, `ctrl-n`/`ctrl-p` always
    /// move it too — for hands that are already in the prompt — `Tab` swaps which zone has
    /// focus, and `j`/`k` move it only where the picker itself has focus. `r` re-probes
    /// from the picker zone and `ctrl-r` from either. All of it is on the footer.
    fn quick_start_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};

        let providers = self
            .providers
            .value
            .as_ref()
            .map(Vec::len)
            .unwrap_or_default();

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        let Some(Overlay::QuickStart(quick)) = self.overlay.as_ref() else {
            return;
        };

        let (zone, pending) = (quick.zone, quick.pending);

        // A start in flight takes no edits: the parameters that produced the request are
        // the ones its answer is about. Esc still leaves.
        if pending {
            if matches!(key.code, KeyCode::Esc) {
                self.leave_quick_start();
            }

            return;
        }

        if matches!(key.code, KeyCode::Char('r')) && (ctrl || zone == QuickZone::Picker) {
            self.refetch_providers();
            return;
        }

        match key.code {
            KeyCode::Esc => return self.leave_quick_start(),
            KeyCode::Enter => return self.submit_quick_start(),
            _ => {}
        }

        let Some(Overlay::QuickStart(quick)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Tab | KeyCode::BackTab => quick.zone = quick.zone.other(),
            KeyCode::Up => quick.move_provider(-1, providers),
            KeyCode::Down => quick.move_provider(1, providers),
            KeyCode::Char('n') if ctrl => quick.move_provider(1, providers),
            KeyCode::Char('p') if ctrl => quick.move_provider(-1, providers),
            KeyCode::Backspace if zone == QuickZone::Prompt => {
                quick.prompt.pop();
            }
            KeyCode::Char(c) if !ctrl => match zone {
                QuickZone::Prompt => quick.prompt.push(c),
                // On a list, the printable keys worth having are the ones the arrows
                // already do; typing into it would look like a search box that does not
                // search.
                QuickZone::Picker => match c {
                    'j' => quick.move_provider(1, providers),
                    'k' => quick.move_provider(-1, providers),
                    _ => {}
                },
            },
            _ => {}
        }
    }

    /// Enter: the whole efficient path, in the order `ouro new -m` already uses.
    ///
    /// Records the provider as the stored default — pressing Enter on it *is* the operator
    /// stating it — starts an interactive session through the same [`StartRequest`] the `n`
    /// dialog builds, and leaves the typed prompt where [`App::started`] will send it as
    /// soon as there is a session to send it to. An empty prompt is a complete answer: the
    /// session starts and the composer opens.
    fn submit_quick_start(&mut self) {
        let providers = self.providers.value.clone().unwrap_or_default();
        let nothing_to_start = self.no_provider_refusal();
        let workspace = self.default_workspace();
        let approval_mode = self.config.defaults.approval_mode();

        let (request, prompt) = {
            let Some(Overlay::QuickStart(quick)) = self.overlay.as_mut() else {
                return;
            };

            let Some(entry) = providers.get(quick.provider) else {
                quick.error = Some(nothing_to_start);
                return;
            };

            (
                StartRequest {
                    plane: Plane::Interactive,
                    provider: entry.provider.clone(),
                    workspace,
                    approval_mode,
                    objective: String::new(),
                },
                quick.prompt.trim().to_string(),
            )
        };

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                // This client's own refusal, shown on the screen that produced it.
                if let Some(Overlay::QuickStart(quick)) = self.overlay.as_mut() {
                    quick.error = Some(refusal.message());
                }

                return;
            }
        };

        if let Some(Overlay::QuickStart(quick)) = self.overlay.as_mut() {
            quick.error = None;
            quick.pending = true;
        }

        self.first_message = (!prompt.is_empty()).then_some(prompt);
        self.config.defaults.provider = Some(request.provider.clone());
        self.mark_welcomed();
        self.save_pending = true;

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    /// Why there is nothing to start, in the terms the probe reported.
    ///
    /// Names what the runtime looked for rather than telling an operator to "install a
    /// provider": the probe already knows which executables it could not find, and that is
    /// the actionable half. No key-entry surface is offered because the provider CLIs own
    /// their own auth — this client has nowhere to put a secret that would help.
    fn no_provider_refusal(&self) -> String {
        if let Some(error) = &self.providers.error {
            return format!("runtime.providers was refused: {error}");
        }

        let Some(providers) = &self.providers.value else {
            return "still asking the runtime which providers it serves".to_string();
        };

        if providers.is_empty() {
            return "this runtime serves no coding providers, so there is nothing to start"
                .to_string();
        }

        let probed: Vec<&str> = providers
            .iter()
            .filter_map(|entry| entry.status.as_ref()?.executable.as_deref())
            .collect();

        if probed.is_empty() {
            return "no provider on this list can be started; the runtime reported no \
                    executable for any of them"
                .to_string();
        }

        format!(
            "no provider is ready. The runtime looked for {} on its own PATH; install one \
             and press r to probe again",
            probed.join(", ")
        )
    }

    /// `,`: this client's preferences, from any tab.
    ///
    /// No scope check and no `hello.methods` gate, unlike `n`: writing a file this process
    /// owns is not a verb the gateway serves, and a `read` listener is no reason to stop
    /// someone recording which provider they prefer.
    fn open_settings(&mut self) {
        if self.overlay.is_some() {
            return;
        }

        // The picker lists what the runtime reports, and most tabs never ask for it.
        self.fetch_providers();

        self.overlay = Some(Overlay::Settings(Box::new(Settings {
            field: SettingsField::Provider,
            provider: 0,
            workspace: self.default_workspace(),
            approval: approval_index(self.config.defaults.approval_mode()),
            quick_start: self.config.onboarding.quick_start,
            wanted_provider: self.config.defaults.provider.clone(),
            edited: false,
        })));

        self.place_default_provider();
    }

    fn settings_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let choices = provider_choices(
            self.providers.value.as_deref().unwrap_or_default(),
            self.config.defaults.provider.as_deref(),
        );

        let Some(Overlay::Settings(settings)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Down => settings.move_field(1),
            KeyCode::BackTab | KeyCode::Up => settings.move_field(-1),
            KeyCode::Left => settings.cycle(-1, choices.len()),
            KeyCode::Right => settings.cycle(1, choices.len()),
            KeyCode::Backspace => {
                if let Some(text) = settings.text_mut() {
                    text.pop();
                    settings.edited = true;
                }
            }
            KeyCode::Enter => {
                if settings.field == SettingsField::Save {
                    self.save_settings();
                } else {
                    // Enter never saves from a field row, for the same reason it never
                    // starts a session from one: finishing a sentence in a text box is not
                    // a decision to write a file.
                    settings.move_field(1);
                }
            }
            KeyCode::Char(c) => {
                if let Some(text) = settings.text_mut() {
                    text.push(c);
                    settings.edited = true;
                }
            }
            _ => {}
        }
    }

    /// Takes the rows as they read and asks the driver to write them.
    ///
    /// The file is rewritten whole from [`Config`], so what lands on disk is exactly what
    /// the overlay showed — no merge with a file that may have changed underneath, which
    /// would be this client guessing which of two answers the operator meant.
    fn save_settings(&mut self) {
        let choices = provider_choices(
            self.providers.value.as_deref().unwrap_or_default(),
            self.config.defaults.provider.as_deref(),
        );

        let Some(Overlay::Settings(settings)) = self.overlay.take() else {
            return;
        };

        self.config.defaults.provider = choices
            .get(settings.provider)
            .and_then(ProviderChoice::name)
            .map(str::to_string);

        // A blank box is "no default", not `""`: the same statement an empty workspace
        // makes in the start dialog.
        let workspace = settings.workspace.trim();
        self.config.defaults.workspace = (!workspace.is_empty()).then(|| workspace.to_string());

        self.config.defaults.approval_mode =
            approval_at(settings.approval).map(|mode| mode.as_str().to_string());

        self.config.onboarding.quick_start = settings.quick_start;

        self.save_pending = true;
    }

    fn new_session_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let providers = self
            .providers
            .value
            .as_ref()
            .map(Vec::len)
            .unwrap_or_default();

        let Some(Overlay::New(dialog)) = self.overlay.as_mut() else {
            return;
        };

        // A dialog whose start is in flight takes no edits: the parameters that produced
        // the request are the ones its answer is about.
        if dialog.pending {
            if matches!(key.code, KeyCode::Esc) {
                self.overlay = None;
            }

            return;
        }

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Down => dialog.move_field(1),
            KeyCode::BackTab | KeyCode::Up => dialog.move_field(-1),
            KeyCode::Left => dialog.cycle(-1, providers),
            KeyCode::Right => dialog.cycle(1, providers),
            KeyCode::Backspace => {
                if let Some(text) = dialog.text_mut() {
                    text.pop();
                }
            }
            KeyCode::Enter => {
                if dialog.field == NewField::Start {
                    self.submit_new_session();
                } else {
                    // Enter never starts from a field row. A dialog that could be
                    // submitted by finishing a sentence in the workspace box would start
                    // sessions nobody asked for.
                    dialog.move_field(1);
                }
            }
            // On a picker row this is deliberately nothing: the printable keys that would
            // mean something are the ones the arrows already do, and typing into a list
            // would look like a search box that does not search.
            KeyCode::Char(c) => {
                if let Some(text) = dialog.text_mut() {
                    text.push(c)
                }
            }
            _ => {}
        }
    }

    fn submit_new_session(&mut self) {
        let providers = self.providers.value.clone().unwrap_or_default();

        let Some(Overlay::New(dialog)) = self.overlay.as_mut() else {
            return;
        };

        let request = dialog.resolved(&providers);

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                // This client's own refusal, shown on the form that produced it.
                dialog.error = Some(refusal.message());
                return;
            }
        };

        dialog.error = None;
        dialog.pending = true;

        let plane = request.plane;

        // `interactive.start` and `coding.start` declare a 120s gateway ceiling: provider
        // readiness is legitimately unbounded upstream and this is the one call that
        // waits for it.
        self.issue(
            Call::new(Tag::Start { plane }, request.method(), params).with_timeout(START_TIMEOUT),
        );
    }

    /// A session this client just created: watch it, focus it, and open the composer so
    /// the next thing typed is the first message.
    fn started(&mut self, plane: Plane, started: StartedRef) {
        self.overlay = None;

        // The lists are polled, and waiting up to three seconds for the row to appear
        // under a session the operator is already looking at reads as a bug.
        self.sessions.interactive.invalidate();
        self.sessions.coding.invalidate();

        self.open_session(plane, started.id.clone());

        if plane == Plane::Interactive {
            self.sessions.composer = Some(Composer {
                verb: ComposerVerb::Message,
                buffer: String::new(),
            });
        }

        // The quick-start screen's prompt. Sent here rather than beside the start, because
        // until this answer arrived there was no session to send it to — the same order
        // `ouro new -m` uses, and for the same reason: `*.start` waits for provider
        // readiness before it answers, so the session is ready to take this.
        if let Some(input) = self.first_message.take() {
            let method = plane.method("send_message");

            if self.hello.serves(&method) {
                self.issue(Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: started.id.clone(),
                    },
                    method,
                    json!({ "id": started.id, "input": input }),
                ));
            } else {
                // The session exists and the message does not. Saying which is the only
                // honest answer; the composer below is where it can be retyped.
                self.inform(
                    format!(
                        "{} started, but this gateway does not serve {method}",
                        started.id
                    ),
                    NoticeKind::Warn,
                );

                return;
            }
        }

        self.inform(
            format!("started {} on the {plane} plane", started.id),
            NoticeKind::Info,
        );
    }

    fn start_failed(&mut self, error: ClientError) {
        let message = match &error {
            ClientError::Rpc(rpc) => refusal(rpc),
            other => other.to_string(),
        };

        // A prompt whose session never existed has nowhere to go, and must not be sent to
        // the next session this client starts.
        self.first_message = None;

        match self.overlay.as_mut() {
            // The form is still on screen, so the refusal belongs on it rather than in a
            // notice line that expires in five seconds.
            Some(Overlay::New(dialog)) => {
                dialog.pending = false;
                dialog.error = Some(message);
            }
            Some(Overlay::QuickStart(quick)) => {
                quick.pending = false;
                quick.error = Some(message);
            }
            _ => self.inform(
                format!("starting a session failed: {message}"),
                NoticeKind::Error,
            ),
        }
    }

    fn open_close_confirm(&mut self) {
        if self.tab != Tab::Sessions {
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        let options = match plane {
            Plane::Interactive => vec![
                (
                    "close (let the provider finish and shut down)".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "close",
                            plane,
                            id: id.clone(),
                        },
                        "interactive.close",
                        json!({ "id": id }),
                    )),
                ),
                (
                    "kill (stop it now)".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "kill",
                            plane,
                            id: id.clone(),
                        },
                        "interactive.kill",
                        json!({ "id": id }),
                    )),
                ),
                ("cancel".to_string(), None),
            ],
            Plane::Coding => vec![
                (
                    "cancel the task".to_string(),
                    Some(Call::new(
                        Tag::Action {
                            label: "cancel",
                            plane,
                            id: id.clone(),
                        },
                        "coding.cancel",
                        json!({ "id": id }),
                    )),
                ),
                ("leave it running".to_string(), None),
            ],
        };

        self.overlay = Some(Overlay::Confirm {
            title: format!("end {id}?"),
            detail: "this ends work the runtime is doing; it is not undone by reattaching"
                .to_string(),
            options,
            // The least destructive answer is under the cursor: an operator who reflexively
            // presses Enter on a dialog they did not expect must not kill a session.
            choice: 0,
        });
    }

    // ----- overlays ------------------------------------------------------------------

    fn open_quit(&mut self) {
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

    fn overlay_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

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

        if matches!(self.overlay, Some(Overlay::QuickStart(_))) {
            self.quick_start_key(key);
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
                KeyCode::Esc => self.overlay = None,
                KeyCode::Char('j') | KeyCode::Down => {
                    *choice = (*choice + 1).min(options.len().saturating_sub(1))
                }
                KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                KeyCode::Enter => {
                    let call = options.get(*choice).and_then(|(_label, call)| call.clone());
                    self.overlay = None;

                    if let Some(call) = call {
                        self.issue(call);
                    }
                }
                _ => {}
            },
            Overlay::Approval { choice, .. } => match key.code {
                KeyCode::Esc => self.overlay = None,
                KeyCode::Char('j') | KeyCode::Down => {
                    *choice = (*choice + 1).min(APPROVAL_CHOICES.len() - 1)
                }
                KeyCode::Char('k') | KeyCode::Up => *choice = choice.saturating_sub(1),
                KeyCode::Enter => self.submit_approval(),
                _ => {}
            },
            Overlay::Prompt { buffer, .. } => match key.code {
                KeyCode::Esc => self.overlay = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) => buffer.push(c),
                KeyCode::Enter => self.submit_prompt(),
                _ => {}
            },
            // All three are dispatched above, before this match could claim their
            // printable keys.
            Overlay::New(_) | Overlay::Settings(_) | Overlay::QuickStart(_) => {}
        }
    }

    fn submit_approval(&mut self) {
        let Some(Overlay::Approval {
            plane,
            id,
            request_id,
            choice,
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        let (decision, scope) = APPROVAL_CHOICES[choice.min(APPROVAL_CHOICES.len() - 1)];

        self.issue(Call::new(
            Tag::Action {
                label: "respond_approval",
                plane,
                id: id.clone(),
            },
            plane.method("respond_approval"),
            model::respond_approval_params(&id, &request_id, decision, scope),
        ));

        // Cleared locally as well: the plane will emit `approval_resolved`, and until it
        // does the modal must not reopen on the next event.
        if let Some(watch) = self.sessions.watches.get_mut(&(plane, id)) {
            watch.resolve_approval(&request_id);
        }
    }

    fn submit_prompt(&mut self) {
        let Some(Overlay::Prompt { kind, buffer, .. }) = self.overlay.take() else {
            return;
        };

        let value = buffer.trim().to_string();

        if value.is_empty() {
            return;
        }

        match kind {
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
}

/// A gateway refusal with the reason it carried.
///
/// Most `-32006` messages are a sentence about the *shape* of the failure and the actual
/// upstream reason is Wire-encoded into `data` — `{:error, {:invalid_workspace, path}}`
/// becomes `["invalid_workspace", "/path"]` there. Dropping it leaves "the runtime refused
/// the call", which tells an operator nothing they can act on. The two `data` payloads a
/// client *branches* on are handled where they are branched on; this is for the rest,
/// which §2.3 says are meant to be read.
fn refusal(rpc: &RpcError) -> String {
    match &rpc.data {
        Some(data) if !data.is_null() => format!("{rpc} — {}", model::compact(data)),
        _ => rpc.to_string(),
    }
}

fn project_agent(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  {}",
            value.get("node").map(model::compact).unwrap_or_default()
        ),
        status: value
            .get("replicas")
            .map(|replicas| format!("{} replicas", model::compact(replicas))),
        id,
        raw: value.clone(),
    })
}

fn project_team(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  {} workers  {} delegations",
            value
                .get("worker_count")
                .map(model::compact)
                .unwrap_or_default(),
            value
                .get("delegation_count")
                .map(model::compact)
                .unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}

fn project_plan(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  v{}",
            value.get("version").map(model::compact).unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}

fn project_run(value: &Value) -> Option<Row> {
    let id = value.get("id").map(model::compact)?;

    Some(Row {
        label: format!(
            "{id}  rev {}",
            value
                .get("revision")
                .map(model::compact)
                .unwrap_or_default()
        ),
        status: value.get("status").map(model::compact),
        id,
        raw: value.clone(),
    })
}
