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

use crate::config::{Config, Defaults};
use crate::fleet::Profile as FleetProfile;
use crate::model::{
    self, new_session_id, AccountState, ApprovalDecision, ApprovalMode, ApprovalScope,
    CursorPruned, Event, EventType, Plane, ProviderEntry, RuntimeStatus, SandboxMode, SessionInfo,
    StartRequest, StartedRef,
};
use crate::proto::{ErrorCode, Hello, Notification, RpcError};
use crate::runtime::LogRing;
use crate::transport::ClientError;

use super::editor::{CompletionCatalog, Editor, EditorAction};
use super::transcript::{Note, Watch};
use super::transcript_cells;
use super::tree::TreeState;

/// The driver's tick. Pi and OpenCode animate the working spinner at ~80ms; poll
/// cadences below are counted in these frames so wall-clock meaning stays put.
pub const TICK: Duration = Duration::from_millis(80);

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
    ComposerAction {
        label: &'static str,
        verb: ComposerVerb,
        plane: Plane,
        id: String,
        turn_id: Option<String>,
        input: String,
        reconciling: bool,
        submission_sequence: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComposerVerb {
    Message,
    FollowUp,
    Steer,
}

impl ComposerVerb {
    pub fn title(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::FollowUp => "follow-up",
            Self::Steer => "steer",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::Message => "send_message",
            Self::FollowUp => "follow_up",
            Self::Steer => "steer",
        }
    }
}

#[derive(Debug)]
pub struct Composer {
    pub verb: ComposerVerb,
    pub editor: Editor,
    draft_generation: u64,
    reconciliation_owner: Option<ReconciliationDraftOwner>,
}

impl Composer {
    fn user_changed_draft(&mut self) {
        self.draft_generation = self.draft_generation.saturating_add(1);
        self.reconciliation_owner = None;
    }

    fn restore_reconciliation(&mut self, input: &str, turn_id: &str, catalog: &CompletionCatalog) {
        self.editor.clear_text();
        self.editor.paste(input, catalog);
        self.draft_generation = self.draft_generation.saturating_add(1);
        self.reconciliation_owner = Some(ReconciliationDraftOwner {
            turn_id: turn_id.to_string(),
            generation: self.draft_generation,
        });
    }

    fn owns_reconciliation(&self, turn_id: &str) -> bool {
        self.reconciliation_owner.as_ref().is_some_and(|owner| {
            owner.turn_id == turn_id && owner.generation == self.draft_generation
        })
    }
}

#[derive(Debug, Clone)]
struct ReconciliationDraftOwner {
    turn_id: String,
    generation: u64,
}

#[derive(Debug, Clone)]
struct SavedComposerDraft {
    input: String,
    generation: u64,
    reconciliation_owner: Option<ReconciliationDraftOwner>,
}

#[derive(Debug, Clone)]
struct PendingComposerReconciliation {
    kind: PendingReconciliationKind,
    input: String,
    turn_id: String,
    submission_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComposerRestoreDisposition {
    Restored,
    SavedForReopen,
    ReconciliationQueued,
    NewerDraftPreserved,
}

impl ComposerRestoreDisposition {
    fn reconciliation_deferred(self) -> bool {
        self == Self::ReconciliationQueued
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReconciliationKind {
    FirstMessage,
    Composer(ComposerVerb),
}

#[derive(Debug)]
struct PendingFirstMessage {
    input: String,
    turn_id: String,
    start: StartRequest,
    start_outcome_unknown: bool,
}

#[derive(Debug, Clone, Copy)]
struct SessionRecovery {
    attempts: u32,
    next_tick: u64,
}

#[derive(Debug, Default)]
pub struct SessionsTab {
    pub interactive: Loadable<Vec<SessionInfo>>,
    pub coding: Loadable<Vec<SessionInfo>>,
    pub open: Option<(Plane, String)>,
    pub watches: HashMap<(Plane, String), Watch>,
    pub composer: Option<Composer>,
    /// Owning node for remote references. First-party session ids carry 128 bits of
    /// client/runtime entropy and are therefore fleet-unique; the node is routing data,
    /// not folded into the user-facing id or map key.
    owner_nodes: HashMap<(Plane, String), String>,
    /// Explicit IDs can be supplied by API clients. The v1 stream envelope carries only
    /// plane + id, so the same value on two owners is deliberately unrouteable instead of
    /// silently choosing whichever fleet-list row happened to arrive last.
    owner_conflicts: HashMap<(Plane, String), Vec<String>>,
    /// Remote streams whose owner disappeared without a terminal session status. Their
    /// cursors stay registered while fleet status watches for the owner to return.
    recovering: HashMap<(Plane, String), SessionRecovery>,
    /// The complete normalized event ledger is an operator detail, not the default chat.
    /// It remains one key away and is never discarded from the watch.
    pub show_event_details: bool,
    /// Per-session resync rounds since the last interruption, bounded.
    rounds: HashMap<(Plane, String), u32>,
    /// Requests accepted by this client that have not produced their first lifecycle
    /// event yet. The Watch takes over as soon as input/turn/run state reaches the stream.
    pending_replies: HashSet<(Plane, String)>,
    /// What has been submitted to each session, so the Up arrow recalls it after the
    /// composer has been closed and reopened. The composer itself is rebuilt on every `i`,
    /// and a recall that forgot everything typed before the last Esc is one nobody relies
    /// on twice.
    composer_history: HashMap<(Plane, String), Vec<String>>,
    /// The unsent text in each composer. Unlike submission history this must survive a
    /// session switch verbatim, especially while an older turn awaits reconciliation.
    composer_drafts: HashMap<(Plane, String), SavedComposerDraft>,
    /// Stable-id mutations that remain outcome-unknown, keyed by their session rather than
    /// the ephemeral open composer. This survives Esc and session switching; Enter always
    /// reconciles the oldest before it can submit a newer draft.
    pending_reconciliations: HashMap<(Plane, String), VecDeque<PendingComposerReconciliation>>,
    /// Rows the operator hid or deleted in this client. Last-known reconstruction must
    /// not bring them back; a later list that actually observes the id clears the hide.
    hidden: HashSet<(Plane, String)>,
}

impl SessionsTab {
    fn remember_owner(&mut self, plane: Plane, id: &str, node: Option<&str>) {
        if self.owner_conflicts.contains_key(&(plane, id.to_string())) {
            return;
        }

        if let Some(node) = node.map(str::trim).filter(|node| !node.is_empty()) {
            self.owner_nodes
                .insert((plane, id.to_string()), node.to_string());
        }
    }

    pub fn owner_node(&self, plane: Plane, id: &str) -> Option<&str> {
        if self.owner_conflicts.contains_key(&(plane, id.to_string())) {
            return None;
        }

        self.owner_nodes
            .get(&(plane, id.to_string()))
            .map(String::as_str)
            .or_else(|| {
                let sessions = match plane {
                    Plane::Interactive => self.interactive.value.as_ref()?,
                    Plane::Coding => self.coding.value.as_ref()?,
                };
                sessions
                    .iter()
                    .find(|session| session.id == id)
                    .and_then(|session| session.node.as_deref())
            })
    }

    /// Reconciles one fleet-wide list without ever choosing between duplicate explicit
    /// IDs. Conflicts are sticky for this client lifetime because a later fleet list may
    /// be partial while one owner is offline; absence is not proof that its id vanished.
    /// Returns newly observed/expanded conflicts for one visible notice.
    fn remember_list_owners(
        &mut self,
        plane: Plane,
        sessions: &[SessionInfo],
    ) -> Vec<(String, Vec<String>)> {
        let mut owners = BTreeMap::<String, BTreeSet<String>>::new();
        for session in sessions {
            owners.entry(session.id.clone()).or_default().insert(
                session
                    .node
                    .as_deref()
                    .map(str::trim)
                    .filter(|node| !node.is_empty())
                    .unwrap_or("owner not reported")
                    .to_string(),
            );
        }

        let mut newly_conflicted = Vec::new();
        for (id, owners) in owners {
            let key = (plane, id.clone());
            let mut owners = owners;
            if let Some(previous) = self.owner_conflicts.get(&key) {
                owners.extend(previous.iter().cloned());
            }
            let nodes = owners.into_iter().collect::<Vec<_>>();
            if nodes.len() > 1 {
                self.owner_nodes.remove(&key);
                let changed = self.owner_conflicts.get(&key) != Some(&nodes);
                self.owner_conflicts.insert(key.clone(), nodes.clone());
                if changed {
                    newly_conflicted.push((id, nodes));
                }
            } else if !self.owner_conflicts.contains_key(&key) && !self.watches.contains_key(&key) {
                if let Some(node) = nodes
                    .first()
                    .filter(|node| node.as_str() != "owner not reported")
                {
                    self.owner_nodes.insert(key, node.clone());
                }
            }
        }

        newly_conflicted
    }

    pub fn owner_conflict(&self, plane: Plane, id: &str) -> Option<&[String]> {
        self.owner_conflicts
            .get(&(plane, id.to_string()))
            .map(Vec::as_slice)
    }

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

        // One row represents one addressable v1 stream. A duplicate explicit ID is still
        // visible, but as a single conflict row whose owners are named by the renderer.
        let mut seen = HashSet::new();
        rows.retain(|session| seen.insert((session.plane, session.id.clone())));

        rows
    }

    pub fn picker_index(&self, selected: Option<&(Plane, String)>) -> usize {
        selected
            .and_then(|(plane, id)| {
                self.merged()
                    .iter()
                    .position(|session| session.plane == *plane && session.id == *id)
            })
            .unwrap_or(0)
    }

    pub fn picker_key(&self, index: usize) -> Option<(Plane, String)> {
        self.merged()
            .get(index)
            .map(|session| (session.plane, session.id.clone()))
    }

    pub fn get(&self, plane: Plane, id: &str) -> Option<&SessionInfo> {
        let sessions = match plane {
            Plane::Interactive => self.interactive.value.as_ref()?,
            Plane::Coding => self.coding.value.as_ref()?,
        };

        sessions
            .iter()
            .find(|session| session.plane == plane && session.id == id)
    }

    fn drop_row(&mut self, plane: Plane, id: &str) {
        self.hidden.insert((plane, id.to_string()));
        let sessions = match plane {
            Plane::Interactive => &mut self.interactive.value,
            Plane::Coding => &mut self.coding.value,
        };

        if let Some(sessions) = sessions {
            sessions.retain(|session| session.id != id);
        }
    }

    pub fn open_watch(&self) -> Option<&Watch> {
        self.watches.get(self.open.as_ref()?)
    }

    /// The list snapshot for the session whose transcript is open, when the latest poll
    /// has observed it. The watch stays authoritative for events; this is presentation and
    /// interaction context such as provider and whether a new turn must be queued.
    pub fn open_info(&self) -> Option<&SessionInfo> {
        let (plane, id) = self.open.as_ref()?;
        let sessions = match plane {
            Plane::Interactive => self.interactive.value.as_ref()?,
            Plane::Coding => self.coding.value.as_ref()?,
        };

        sessions
            .iter()
            .find(|session| session.plane == *plane && session.id == *id)
    }

    fn open_watch_mut(&mut self) -> Option<&mut Watch> {
        let key = self.open.clone()?;
        self.watches.get_mut(&key)
    }

    fn mark_reply_pending(&mut self, plane: Plane, id: &str) {
        self.pending_replies.insert((plane, id.to_string()));
    }

    fn clear_reply_pending(&mut self, plane: Plane, id: &str) {
        self.pending_replies.remove(&(plane, id.to_string()));
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
    PreviewCapability,
    AdmitCapability,
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
    Machine,
    Provider,
    Workspace,
    ApprovalMode,
    SandboxMode,
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
    /// Index into [`App::machine_choices`]. Zero is always this machine.
    pub machine: usize,
    pub approval: usize,
    pub sandbox: usize,
    /// True while `*.start` is in flight — it declares a 120s ceiling, so this is a dialog
    /// that legitimately waits.
    pub pending: bool,
    /// Why the last attempt did not start a session. Shown here rather than in the notice
    /// line: the operator is still looking at the form that produced it.
    pub error: Option<String>,
    /// The exact request whose reply may have been lost. While present, Enter replays
    /// these immutable params and edits are held back so the id remains meaningful.
    pending_request: Option<StartRequest>,
    pub reconciling: bool,
    /// The caller's cwd is a useful local hint and an unsafe remote default. Keep it only
    /// so cycling back to this machine can restore it before the operator edits the field.
    inferred_local_workspace: Option<String>,
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
    fn new(
        plane: Plane,
        workspace: String,
        workspace_is_inferred: bool,
        defaults: &Defaults,
    ) -> Self {
        let inferred_local_workspace = workspace_is_inferred.then(|| workspace.clone());
        Self {
            field: NewField::Provider,
            request: StartRequest {
                workspace,
                ..StartRequest::new(plane)
            },
            provider: 0,
            machine: 0,
            approval: approval_index(defaults.approval_mode()),
            sandbox: sandbox_index(defaults.sandbox_mode()),
            pending: false,
            error: None,
            pending_request: None,
            reconciling: false,
            inferred_local_workspace,
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
        let mut fields = vec![NewField::Plane, NewField::Machine, NewField::Provider];

        if self.request.plane == Plane::Coding {
            fields.push(NewField::Objective);
        }

        fields.extend([
            NewField::Workspace,
            NewField::ApprovalMode,
            NewField::SandboxMode,
            NewField::Start,
        ]);
        fields
    }

    pub fn approval_mode(&self) -> Option<ApprovalMode> {
        approval_at(self.approval)
    }

    /// The approval row's label, including the "say nothing" option at index 0.
    pub fn approval_label(&self) -> String {
        approval_label(self.approval)
    }

    pub fn sandbox_mode(&self) -> Option<SandboxMode> {
        sandbox_at(self.sandbox)
    }

    pub fn sandbox_label(&self) -> String {
        sandbox_label(self.sandbox)
    }

    /// The request as the fields currently read.
    pub fn resolved(&self, providers: &[ProviderEntry]) -> StartRequest {
        let mut request = self.request.clone();

        request.provider = providers
            .get(self.provider)
            .map(|entry| entry.provider.clone())
            .unwrap_or_default();

        request.approval_mode = self.approval_mode();
        request.sandbox_mode = self.sandbox_mode();
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

    fn cycle(&mut self, delta: isize, providers: usize, machines: &[MachineChoice]) {
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
            NewField::Machine if !machines.is_empty() => {
                self.machine =
                    (self.machine as isize + delta).rem_euclid(machines.len() as isize) as usize;
                self.request.machine = machines
                    .get(self.machine)
                    .and_then(MachineChoice::wire_name)
                    .unwrap_or_default()
                    .to_string();

                if let Some(local_workspace) = self.inferred_local_workspace.as_ref() {
                    if self.request.machine.is_empty() {
                        self.request.workspace = local_workspace.clone();
                    } else {
                        self.request.workspace.clear();
                    }
                }
            }
            NewField::ApprovalMode => {
                self.approval =
                    (self.approval as isize + delta).rem_euclid(APPROVAL_ROWS as isize) as usize;
            }
            NewField::SandboxMode => {
                self.sandbox =
                    (self.sandbox as isize + delta).rem_euclid(SANDBOX_ROWS as isize) as usize;
            }
            _ => {}
        }
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            NewField::Workspace => {
                self.inferred_local_workspace = None;
                Some(&mut self.request.workspace)
            }
            NewField::Objective => Some(&mut self.request.objective),
            _ => None,
        }
    }
}

/// One editable row of the settings overlay. The facts above them are not rows: they are
/// what the runtime reported, and nothing here can change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    Machines,
    Provider,
    Workspace,
    ApprovalMode,
    SandboxMode,
    Save,
}

impl SettingsField {
    pub const ALL: [SettingsField; 6] = [
        SettingsField::Machines,
        SettingsField::Provider,
        SettingsField::Workspace,
        SettingsField::ApprovalMode,
        SettingsField::SandboxMode,
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
    pub sandbox: usize,
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

    pub fn sandbox_label(&self) -> String {
        sandbox_label(self.sandbox)
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
            SettingsField::SandboxMode => {
                self.edited = true;
                self.sandbox =
                    (self.sandbox as isize + delta).rem_euclid(SANDBOX_ROWS as isize) as usize;
            }
            _ => {}
        }
    }
}

/// One safe, local action in the Machines guide. The TUI explains and can copy these
/// commands but deliberately does not execute them: creating an invite writes private
/// membership material and joining changes how a daemon starts, so both stay explicit
/// terminal actions whose exact command can be reviewed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineAction {
    Create,
    Join,
    Invite,
    Service,
    Status,
    Doctor,
    Sync,
}

impl MachineAction {
    pub const ALL: [Self; 7] = [
        Self::Create,
        Self::Join,
        Self::Invite,
        Self::Service,
        Self::Status,
        Self::Doctor,
        Self::Sync,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Create => "Create a fleet",
            Self::Join => "Join this fleet",
            Self::Invite => "Add another machine",
            Self::Service => "Keep this machine running",
            Self::Status => "Check the machines",
            Self::Doctor => "Diagnose a connection",
            Self::Sync => "Update saved membership",
        }
    }

    pub fn command(self) -> &'static str {
        match self {
            Self::Create => "ouro fleet create",
            Self::Join => "ouro fleet join INVITE.ouro",
            Self::Invite => "ouro fleet invite --machine NAME --host HOST --out INVITE.ouro",
            Self::Service => "ouro fleet service install",
            Self::Status => "ouro fleet status",
            Self::Doctor => "ouro fleet doctor",
            Self::Sync => "ouro fleet sync export --out fleet.ouro-roster",
        }
    }
}

/// Keyboard state for the newcomer-facing Machines guide.
#[derive(Debug, Default)]
pub struct Machines {
    pub selected: usize,
    /// Enter opens the focused action's longer explanation. Escape first returns to the
    /// overview, then closes the guide, so exploring never loses the fleet summary.
    pub guide: Option<MachineAction>,
}

impl Machines {
    pub fn selected(&self) -> MachineAction {
        MachineAction::ALL[self.selected.min(MachineAction::ALL.len() - 1)]
    }
}

/// The small, intentionally non-secret view model shared by Settings, the Dashboard and
/// the Machines guide. It combines the local profile (what this machine expects) with the
/// runtime status (what is connected now), and leaves unknown facts unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineSummary {
    pub mode: String,
    pub fleet: Option<String>,
    pub machine: String,
    pub host: Option<String>,
    pub expected: Option<usize>,
    pub connected: usize,
    pub offline: Option<usize>,
    pub offline_names: Vec<String>,
    pub security: MachineSecurity,
    pub recovery: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineSecurity {
    Standalone,
    Secure,
    Insecure,
    Mismatch,
    Unknown,
}

impl MachineSecurity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Standalone => "not needed while standalone",
            Self::Secure => "encrypted and authenticated (TLS)",
            Self::Insecure => "insecure: machine traffic is not using TLS",
            Self::Mismatch => "configuration mismatch: fleet profile loaded, runtime is standalone",
            Self::Unknown => "security not reported yet",
        }
    }
}

/// One destination in the new-session form. Local is represented by an omitted wire
/// parameter, so an older standalone runtime behaves exactly as before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineChoice {
    Local { label: String },
    Connected { machine: String, node: String },
}

impl MachineChoice {
    pub fn label(&self) -> String {
        match self {
            Self::Local { label } => format!("This machine — {label}"),
            Self::Connected { machine, node } => format!("{machine} — connected ({node})"),
        }
    }

    pub fn wire_name(&self) -> Option<&str> {
        match self {
            Self::Local { .. } => None,
            Self::Connected { machine, .. } => Some(machine),
        }
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
    pub const ALL: [Self; 24] = [
        Self::NewSession,
        Self::SwitchSession,
        Self::SessionDetails,
        Self::CopyLast,
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
            Self::SessionDetails => "ctrl+o",
            Self::CopyLast => "ctrl+x y",
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
    pub fn visible(&self) -> Vec<Command> {
        Command::ALL.to_vec()
    }

    fn first_match(&self) -> usize {
        Command::ALL
            .iter()
            .position(|command| command.matches(&self.query))
            .unwrap_or(0)
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
    fn new(flow: AccountFlow) -> Self {
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
    /// A guided, read-only fleet setup surface. Commands are shown exactly and are never
    /// run from a keypress in this overlay.
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

/// Chords after `Ctrl+X`. Drawn by the which-key overlay while the leader is pending.
pub const LEADER_KEYS: &[(&str, &str)] = &[
    ("n", "new session"),
    ("N", "session options"),
    ("l", "switch session"),
    ("e", "external editor"),
    ("y", "copy last message"),
    ("s", "steer"),
    ("a", "approval"),
    ("w", "writable session"),
    ("x", "end or remove session"),
    ("o", "event details"),
    ("q", "quit"),
    ("?", "keyboard help"),
];

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
    /// Tick at which a second Ctrl+C will open the quit dialog.
    ctrl_c_until: Option<u64>,
    /// Last agent message the I/O driver should copy to the clipboard.
    copy_pending: Option<String>,
    /// Current prompt text the I/O driver should open in `$VISUAL`/`$EDITOR`.
    external_editor_pending: Option<String>,
    /// Monotonic issue order for composer mutations. Outcome-unknown answers may arrive
    /// out of order; reconciliation is sorted by this sequence, never by error arrival.
    next_composer_submission_sequence: u64,
    /// After ending a session chosen from the switcher, put the switcher back so several
    /// dead rows can be cleared without reopening it each time.
    resume_session_picker: bool,
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
            config_path: None,
            data_dir: None,
            fleet_profile: None,
            keyboard_enhanced: false,
            home_draft: Editor::default(),
            home_pending: false,
            home_error: None,
            completion_catalog: CompletionCatalog::default(),
            outbound: VecDeque::new(),
            in_flight: HashSet::new(),
            dropped_seen: 0,
            save_pending: false,
            first_message: None,
            pending_background_start: None,
            open_url_pending: None,
            leader_until: None,
            ctrl_c_until: None,
            copy_pending: None,
            external_editor_pending: None,
            next_composer_submission_sequence: 0,
            resume_session_picker: false,
        }
    }

    pub fn take_open_url(&mut self) -> Option<String> {
        self.open_url_pending.take()
    }

    pub fn take_copy(&mut self) -> Option<String> {
        self.copy_pending.take()
    }

    pub fn take_external_editor(&mut self) -> Option<String> {
        self.external_editor_pending.take()
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

    /// The fleet state a person needs, without the distribution vocabulary used by the
    /// runtime protocol. Local membership says what should be present; live status says
    /// what is present now. Neither source contains a cookie, key, or certificate.
    pub fn machine_summary(&self) -> MachineSummary {
        let status = self.status.value.as_ref();
        let cluster = status.map(|status| &status.cluster);
        let runtime_fleet = cluster.and_then(|cluster| cluster.get("fleet"));
        let runtime_summary = runtime_fleet.and_then(|fleet| fleet.get("summary"));
        let runtime_machines = runtime_fleet
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array);
        let connected_nodes: HashSet<&str> = status
            .map(|status| status.connected_nodes.iter().map(String::as_str).collect())
            .unwrap_or_default();

        let strategy = cluster
            .and_then(|cluster| cluster.get("formation"))
            .and_then(|formation| formation.get("strategy"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        let distributed = cluster
            .and_then(|cluster| cluster.get("distributed"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let tls = cluster
            .and_then(|cluster| cluster.get("security"))
            .and_then(|security| security.get("tls"))
            .and_then(Value::as_bool);

        let fleet_mode = self.fleet_profile.is_some()
            || runtime_fleet.is_some()
            || distributed
            || strategy != "none";

        if !fleet_mode {
            return MachineSummary {
                mode: "Standalone".into(),
                fleet: None,
                machine: friendly_machine(
                    status
                        .map(|status| status.node.as_str())
                        .unwrap_or(&self.hello.node),
                ),
                host: None,
                expected: Some(1),
                connected: 1,
                offline: Some(0),
                offline_names: Vec::new(),
                security: MachineSecurity::Standalone,
                recovery:
                    "This machine runs on its own. Create a fleet when another machine is ready."
                        .into(),
            };
        }

        let (fleet, machine, host, profile_expected, profile_connected, offline_names) = match self
            .fleet_profile
            .as_ref()
        {
            Some(profile) => {
                let mut members: BTreeMap<String, String> = profile
                    .members
                    .iter()
                    .map(|member| (member.node.clone(), member.machine.clone()))
                    .collect();
                members
                    .entry(profile.node.clone())
                    .or_insert_with(|| profile.machine.clone());

                // Invitations are intentionally independent: an early joiner does
                // not have to receive a rewritten secret bundle every time the owner
                // later invites another machine. Merge the runtime's last-known
                // directory so that a machine already observed over BEAM is still
                // counted and named here. Otherwise the UI can claim the impossible
                // “expected 2, connected 3”.
                if let Some(runtime_machines) = runtime_machines {
                    for runtime_machine in runtime_machines {
                        let Some(node) = runtime_machine.get("node").and_then(Value::as_str) else {
                            continue;
                        };
                        let machine = runtime_machine
                            .get("machine")
                            .and_then(Value::as_str)
                            .unwrap_or(node);
                        members
                            .entry(node.to_string())
                            .or_insert_with(|| machine.to_string());
                    }
                }

                let mut offline_names = members
                    .iter()
                    .filter(|(node, _machine)| {
                        node.as_str() != profile.node && !connected_nodes.contains(node.as_str())
                    })
                    .map(|(_node, machine)| machine.clone())
                    .collect::<Vec<_>>();
                if let Some(runtime_machines) = runtime_machines {
                    offline_names.extend(runtime_machines.iter().filter_map(|machine| {
                        (machine.get("state").and_then(Value::as_str) == Some("offline"))
                            .then(|| {
                                machine
                                    .get("machine")
                                    .and_then(Value::as_str)
                                    .or_else(|| machine.get("node").and_then(Value::as_str))
                                    .map(str::to_string)
                            })
                            .flatten()
                    }));
                }
                offline_names.sort();
                offline_names.dedup();
                let expected = members.len().max(1);
                let connected = expected.saturating_sub(offline_names.len());

                (
                    Some(profile.name.clone()),
                    profile.machine.clone(),
                    Some(profile.host.clone()),
                    Some(expected),
                    Some(connected),
                    offline_names,
                )
            }
            None => {
                let node = status
                    .map(|status| status.node.as_str())
                    .unwrap_or(&self.hello.node);
                let offline_names = runtime_fleet
                    .and_then(|fleet| fleet.get("machines"))
                    .and_then(Value::as_array)
                    .map(|machines| {
                        machines
                            .iter()
                            .filter(|machine| {
                                machine.get("state").and_then(Value::as_str) == Some("offline")
                            })
                            .filter_map(|machine| {
                                machine
                                    .get("machine")
                                    .and_then(Value::as_str)
                                    .or_else(|| machine.get("node").and_then(Value::as_str))
                            })
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                (
                    runtime_fleet
                        .and_then(|fleet| fleet.get("fleet_id"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    friendly_machine(node),
                    node.split_once('@').map(|(_name, host)| host.to_string()),
                    value_usize(runtime_summary.and_then(|summary| summary.get("expected"))),
                    value_usize(runtime_summary.and_then(|summary| summary.get("connected"))),
                    offline_names,
                )
            }
        };

        let connected = value_usize(runtime_summary.and_then(|summary| summary.get("connected")))
            .or(profile_connected)
            .unwrap_or_else(|| connected_nodes.len() + 1);
        let expected = profile_expected
            .into_iter()
            .chain(value_usize(
                runtime_summary.and_then(|summary| summary.get("expected")),
            ))
            .max()
            .map(|expected| expected.max(connected));
        let offline = value_usize(runtime_summary.and_then(|summary| summary.get("offline")))
            .into_iter()
            .chain(expected.map(|expected| expected.saturating_sub(connected)))
            .chain(std::iter::once(offline_names.len()))
            .max();

        let security = match (self.fleet_profile.is_some(), distributed, tls) {
            (true, false, Some(_)) => MachineSecurity::Mismatch,
            (_, true, Some(true)) => MachineSecurity::Secure,
            (_, true, Some(false)) => MachineSecurity::Insecure,
            (true, false, None) if status.is_some() => MachineSecurity::Mismatch,
            _ => MachineSecurity::Unknown,
        };

        let recovery = match offline {
            Some(0) => {
                "All known machines are connected. Running daemons retry membership after network interruptions."
                    .into()
            }
            Some(offline) => format!(
                "{offline} machine{} offline; running daemons keep retrying membership.",
                if offline == 1 { " is" } else { "s are" }
            ),
            None => {
                "Running daemons retry membership; expected membership is not known here."
                    .into()
            }
        };

        MachineSummary {
            mode: "Fleet".into(),
            fleet,
            machine,
            host,
            expected,
            connected,
            offline,
            offline_names,
            security,
            recovery,
        }
    }

    /// Destinations that can safely be offered for a new session right now. Expected but
    /// offline members are visible in Machines, not selectable here: a start form should
    /// never invite a request that the runtime already knows it cannot route.
    pub fn machine_choices(&self) -> Vec<MachineChoice> {
        let summary = self.machine_summary();
        let mut choices = vec![MachineChoice::Local {
            label: summary.machine,
        }];
        let Some(status) = self.status.value.as_ref() else {
            return choices;
        };

        let connected: HashSet<&str> = status.connected_nodes.iter().map(String::as_str).collect();
        let local_node = self
            .fleet_profile
            .as_ref()
            .map(|profile| profile.node.as_str())
            .unwrap_or(status.node.as_str());
        let mut remotes = BTreeMap::<String, String>::new();
        let mut incompatible_nodes = HashSet::<String>::new();

        if let Some(machines) = status
            .cluster
            .get("fleet")
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array)
        {
            for machine in machines {
                let state = machine.get("state").and_then(Value::as_str);
                let role = machine.get("role").and_then(Value::as_str);
                let Some(node) = machine.get("node").and_then(Value::as_str) else {
                    continue;
                };
                if machine.get("compatibility").and_then(Value::as_str) == Some("incompatible") {
                    incompatible_nodes.insert(node.to_string());
                    continue;
                }
                if state != Some("connected") || role.is_some_and(|role| role != "core") {
                    continue;
                }

                let Some(name) = machine.get("machine").and_then(Value::as_str) else {
                    continue;
                };
                if node != local_node {
                    remotes.insert(name.to_string(), node.to_string());
                }
            }
        }

        // A profile remains useful against an older runtime that does not yet embed the
        // fleet directory. Connectivity is still a live fact from runtime.status.
        if let Some(profile) = self.fleet_profile.as_ref() {
            for member in &profile.members {
                if member.node != profile.node
                    && connected.contains(member.node.as_str())
                    && !incompatible_nodes.contains(&member.node)
                {
                    remotes
                        .entry(member.machine.clone())
                        .or_insert_with(|| member.node.clone());
                }
            }
        }

        choices.extend(
            remotes
                .into_iter()
                .map(|(machine, node)| MachineChoice::Connected { machine, node }),
        );
        choices
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
                self.poll();
            }
            Msg::Redraw => {}
            Msg::Scroll(delta) => self.scroll_view(delta),
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
            Msg::ExternalEditor(text) => self.apply_external_editor(text),
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
            Tag::Account => match result {
                Ok(value) => match AccountState::decode(&value) {
                    Ok(account) => {
                        let connected = account.connected();
                        let cadence = if account.login.status == "pending" {
                            ACCOUNT_LOGIN_TICKS
                        } else {
                            ACCOUNT_TICKS
                        };

                        self.account.ok(account, ticks, cadence);

                        if connected {
                            if self.config.defaults.provider.is_none() {
                                self.config.defaults.provider = Some("codex".to_string());
                                self.save_pending = true;
                            }

                            if matches!(self.overlay, Some(Overlay::Account(_))) {
                                self.overlay = None;
                                self.inform(
                                    "ChatGPT is connected. Type a request to start coding.",
                                    NoticeKind::Info,
                                );
                            }
                        } else if let Some(Overlay::Account(dialog)) = self.overlay.as_mut() {
                            if let Some(account) = self.account.value.as_ref() {
                                dialog.login_id = account.login.login_id.clone();
                                if account.login.status == "failed" {
                                    dialog.pending = false;
                                    dialog.error = account.login.error.clone().or_else(|| {
                                        Some("ChatGPT sign-in did not complete".to_string())
                                    });
                                }
                            }
                        }
                    }
                    Err(error) => self.account.failed(
                        format!("account.read did not decode: {error}"),
                        ticks,
                        ACCOUNT_TICKS,
                    ),
                },
                Err(error) => self.account.failed(error.to_string(), ticks, ACCOUNT_TICKS),
            },
            Tag::AccountLogin => self.account_login_answered(result),
            Tag::AccountCancel => {
                self.account.invalidate();
                self.poll();

                if let Err(error) = result {
                    self.inform(
                        format!("cancelling ChatGPT sign-in failed: {error}"),
                        NoticeKind::Error,
                    );
                }
            }
            Tag::AccountLogout => {
                self.account.invalidate();
                self.poll();

                match result {
                    Ok(_) => self.inform("ChatGPT was disconnected", NoticeKind::Info),
                    Err(error) => self.inform(
                        format!("disconnecting ChatGPT failed: {error}"),
                        NoticeKind::Error,
                    ),
                }
            }
            Tag::Status => match result {
                Ok(value) => match RuntimeStatus::decode(&value) {
                    Ok(status) => {
                        self.status.ok(status, ticks, STATUS_TICKS);
                        self.recover_remote_sessions();
                    }
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
            Tag::Sessions(plane) => match result {
                Ok(value) => {
                    let sessions = self.retain_offline_session_rows(
                        plane,
                        SessionInfo::decode_list(plane, &value),
                    );
                    let conflicts = self.sessions.remember_list_owners(plane, &sessions);
                    for (id, owners) in conflicts {
                        self.cursors.forget(plane, &id);
                        self.inform(
                            format!(
                                "session ID {id} is reported by {}; Ouroboros will not open or route it. Explicit IDs must be fleet-unique (generated IDs already are); stop or restart one duplicate with a unique ID, then reconnect this TUI",
                                owners.join(" and ")
                            ),
                            NoticeKind::Error,
                        );
                    }
                    let panel = match plane {
                        Plane::Interactive => &mut self.sessions.interactive,
                        Plane::Coding => &mut self.sessions.coding,
                    };
                    panel.ok(sessions, ticks, LIST_TICKS)
                }
                Err(error) => {
                    let panel = match plane {
                        Plane::Interactive => &mut self.sessions.interactive,
                        Plane::Coding => &mut self.sessions.coding,
                    };
                    panel.failed(error.to_string(), ticks, LIST_TICKS)
                }
            },
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
            Tag::ComposerAction {
                label,
                verb,
                plane,
                id,
                turn_id,
                input,
                reconciling,
                submission_sequence,
            } => match result {
                Ok(value) => match model::turn_reply(&value) {
                    model::TurnReply::Accepted => {
                        if reconciling {
                            if let Some(turn_id) = turn_id.as_deref() {
                                self.accept_reconciled_composer_draft(plane, &id, turn_id);
                            }
                            self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                        }
                        self.inform(format!("{label} accepted for {id}"), NoticeKind::Info);
                    }
                    model::TurnReply::OutcomeUnknown => {
                        // Current runtimes return these states as typed RPC errors. Keep
                        // this branch for a same-id read from an older runtime: it is still
                        // not proof that the turn was accepted.
                        let retry_turn_id = if verb == ComposerVerb::Steer {
                            None
                        } else {
                            turn_id
                        };
                        let reconciliation_id = retry_turn_id.clone();
                        let disposition = self.restore_composer_submission(
                            plane,
                            &id,
                            input,
                            retry_turn_id,
                            verb,
                            submission_sequence,
                        );
                        if verb == ComposerVerb::Steer {
                            self.steer_delivery_unconfirmed(&id, disposition);
                        } else if disposition.reconciliation_deferred() {
                            self.inform(
                                format!(
                                    "{label} on {id}: {}; saved outcome-unknown turn {} without \
                                     overwriting the session draft. Open {id}; Enter reconciles \
                                     it before newer input",
                                    model::turn_reply_diagnostic(&value),
                                    reconciliation_id.as_deref().unwrap_or("unknown")
                                ),
                                NoticeKind::Error,
                            );
                        } else {
                            self.inform(
                                format!(
                                    "{label} on {id}: {}; the exact draft and turn id were \
                                     restored",
                                    model::turn_reply_diagnostic(&value)
                                ),
                                NoticeKind::Error,
                            );
                        }
                    }
                    model::TurnReply::Rejected => {
                        if reconciling {
                            self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                            if let Some(turn_id) = turn_id.as_deref() {
                                self.release_reconciliation_draft(plane, &id, turn_id);
                            }
                        }
                        if matches!(verb, ComposerVerb::Message | ComposerVerb::FollowUp) {
                            self.sessions.clear_reply_pending(plane, &id);
                        }

                        let retry_verb =
                            if verb == ComposerVerb::Message && model::turn_reply_busy(&value) {
                                ComposerVerb::FollowUp
                            } else {
                                verb
                            };

                        // This id is durably terminal. Preserve the exact input but mint a
                        // fresh logical turn if the operator deliberately retries it.
                        self.restore_composer_submission(
                            plane,
                            &id,
                            input,
                            None,
                            retry_verb,
                            submission_sequence,
                        );
                        self.inform(
                            format!("{label} on {id}: {}", model::turn_reply_diagnostic(&value)),
                            NoticeKind::Error,
                        );
                    }
                },
                Err(error) => {
                    let outcome_unknown = Self::reply_outcome_unknown(&error);
                    let busy = matches!(
                        &error,
                        ClientError::Rpc(rpc) if model::turn_busy(rpc.data.as_ref())
                    );

                    if reconciling && !outcome_unknown {
                        self.settle_pending_reconciliation(plane, &id, turn_id.as_deref());
                        if let Some(turn_id) = turn_id.as_deref() {
                            self.release_reconciliation_draft(plane, &id, turn_id);
                        }
                    }

                    if matches!(label, "send_message" | "follow_up") && !outcome_unknown {
                        self.sessions.clear_reply_pending(plane, &id);
                    }

                    // Only dispatched turns have a caller-owned reconciliation id. A
                    // definite refusal mints a fresh one; steer has no idempotency at all.
                    let retry_turn_id = if outcome_unknown && verb != ComposerVerb::Steer {
                        turn_id
                    } else {
                        None
                    };
                    let retry_verb = if busy && verb == ComposerVerb::Message {
                        ComposerVerb::FollowUp
                    } else {
                        verb
                    };

                    let reconciliation_id = retry_turn_id.clone();
                    let disposition = self.restore_composer_submission(
                        plane,
                        &id,
                        input,
                        retry_turn_id,
                        retry_verb,
                        submission_sequence,
                    );
                    if outcome_unknown && verb == ComposerVerb::Steer {
                        self.steer_delivery_unconfirmed(&id, disposition);
                    } else if disposition.reconciliation_deferred() {
                        let diagnostic = match &error {
                            ClientError::Rpc(rpc) => model::refusal(rpc),
                            other => other.to_string(),
                        };
                        self.inform(
                            format!(
                                "{label} on {id}: {diagnostic}; saved outcome-unknown turn {} \
                                 without overwriting the session draft. Open {id}; Enter \
                                 reconciles it before newer input",
                                reconciliation_id.as_deref().unwrap_or("unknown")
                            ),
                            NoticeKind::Error,
                        );
                    } else {
                        self.action_failed(label, plane, &id, error);
                    }
                }
            },
            Tag::Action {
                label, plane, id, ..
            } => match result {
                Ok(value) if matches!(label, "preview" | "admit" | "list capabilities") => {
                    self.capability_answered(label, &id, value)
                }
                Ok(_) if label == "remove" => self.session_removed(plane, &id),
                Err(error) if label == "remove" && error.code() == Some(ErrorCode::NotFound) => {
                    self.session_removed(plane, &id)
                }
                Ok(_value) => {
                    self.inform(format!("{label} accepted for {id}"), NoticeKind::Info);
                    self.refresh_session_lists();
                    self.resume_picker_if_requested();
                }
                Err(error) => {
                    if matches!(label, "send_message" | "follow_up")
                        && !Self::reply_outcome_unknown(&error)
                    {
                        self.sessions.clear_reply_pending(plane, &id);
                    }
                    self.action_failed(label, plane, &id, error);
                    self.resume_picker_if_requested();
                }
            },
            Tag::Approval {
                plane,
                id,
                request_id,
            } => match result {
                Ok(_value) => self.inform(
                    format!("approval response accepted for {id}"),
                    NoticeKind::Info,
                ),
                Err(error) => {
                    if let Some(watch) = self.sessions.watches.get_mut(&(plane, id.clone())) {
                        watch.retry_approval_response(&request_id);
                    }
                    self.action_failed("respond_approval", plane, &id, error);
                }
            },
            Tag::Start { plane, id } => match result {
                Ok(value) => match StartedRef::decode(&value) {
                    Some(started) if started.id == id => {
                        if self
                            .pending_background_start
                            .as_ref()
                            .is_some_and(|request| request.id == id)
                        {
                            self.pending_background_start = None;
                        }
                        self.started(plane, started);
                    }
                    Some(started) => self.start_failed(
                        plane,
                        &id,
                        ClientError::BadJson(format!(
                            "the runtime answered start id {} for retry id {id}; both identities \
                             must be inspected before another start",
                            started.id
                        )),
                    ),
                    // The session exists; this client just cannot address it. Saying so is
                    // the only honest answer. The same id makes reconciliation safe.
                    None => self.start_failed(
                        plane,
                        &id,
                        ClientError::BadJson(format!(
                            "the runtime started a session but answered a reference this build \
                         cannot read: {value}"
                        )),
                    ),
                },
                Err(error) => self.start_failed(plane, &id, error),
            },
            Tag::FirstMessage {
                plane,
                id,
                turn_id,
                input,
                submission_sequence,
            } => match result {
                Ok(value) => match model::turn_reply(&value) {
                    model::TurnReply::Accepted => {
                        self.accept_first_message(plane, &id, &turn_id);
                    }
                    model::TurnReply::OutcomeUnknown => {
                        self.restore_first_message(plane, &id, input, turn_id, submission_sequence);
                        self.inform(
                            format!(
                                "send_message on {id}: {}; the exact draft and turn id were \
                                 restored",
                                model::turn_reply_diagnostic(&value)
                            ),
                            NoticeKind::Error,
                        );
                    }
                    model::TurnReply::Rejected => {
                        self.settle_pending_reconciliation(plane, &id, Some(&turn_id));
                        self.sessions.clear_reply_pending(plane, &id);
                        let verb = if model::turn_reply_busy(&value) {
                            ComposerVerb::FollowUp
                        } else {
                            ComposerVerb::Message
                        };
                        self.restore_refused_first_message(plane, &id, input, verb);
                        self.inform(
                            format!(
                                "send_message on {id}: {}",
                                model::turn_reply_diagnostic(&value)
                            ),
                            NoticeKind::Error,
                        );
                    }
                },
                Err(error) => {
                    let outcome_unknown = Self::reply_outcome_unknown(&error);
                    let busy = matches!(
                        &error,
                        ClientError::Rpc(rpc) if model::turn_busy(rpc.data.as_ref())
                    );

                    if !outcome_unknown {
                        self.settle_pending_reconciliation(plane, &id, Some(&turn_id));
                        self.sessions.clear_reply_pending(plane, &id);
                    }

                    if outcome_unknown {
                        self.restore_first_message(plane, &id, input, turn_id, submission_sequence);
                    } else {
                        // This logical id is durably failed. Replaying it would return the
                        // existing failed turn as an idempotent read and falsely clear the
                        // draft. Keep the text but mint a replacement on Enter; `:busy`
                        // also changes the retry to Harness's safe queueing verb.
                        let verb = if busy {
                            ComposerVerb::FollowUp
                        } else {
                            ComposerVerb::Message
                        };
                        self.restore_refused_first_message(plane, &id, input, verb);
                    }

                    self.action_failed("send_message", plane, &id, error);
                }
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

    fn account_login_answered(&mut self, result: Result<Value, ClientError>) {
        if !matches!(self.overlay, Some(Overlay::Account(_))) {
            // The operator dismissed the modal before Codex returned its login id. Once
            // that id exists, cancel it rather than leaving an invisible managed login
            // alive on the runtime host.
            if let Ok(value) = result {
                if let Some(login_id) = value.get("loginId").and_then(Value::as_str) {
                    self.issue(Call::new(
                        Tag::AccountCancel,
                        "account.login.cancel",
                        json!({ "login_id": login_id }),
                    ));
                }
            }
            return;
        }

        let Some(Overlay::Account(dialog)) = self.overlay.as_mut() else {
            return;
        };

        match result {
            Ok(value) => {
                dialog.pending = true;
                dialog.login_id = value
                    .get("loginId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.url = value
                    .get("authUrl")
                    .or_else(|| value.get("verificationUrl"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.code = value
                    .get("userCode")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                dialog.error = None;

                if let Some(url) = dialog.url.as_deref() {
                    if url.starts_with("https://") {
                        self.open_url_pending = Some(url.to_string());
                    }
                }

                self.account.invalidate();
                self.poll();
            }
            Err(error) => {
                dialog.pending = false;
                dialog.error = Some(error.to_string());
            }
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
            ClientError::Rpc(rpc) => format!("{label} on {id}: {}", model::refusal(rpc)),
            other => format!("{label} on {id} failed: {other}"),
        };

        self.inform(text, NoticeKind::Error);
    }

    fn steer_delivery_unconfirmed(&mut self, id: &str, disposition: ComposerRestoreDisposition) {
        let preservation = match disposition {
            ComposerRestoreDisposition::Restored => {
                "the exact draft was restored for inspection".to_string()
            }
            ComposerRestoreDisposition::SavedForReopen => {
                "the exact draft was saved for inspection when this composer is reopened"
                    .to_string()
            }
            ComposerRestoreDisposition::NewerDraftPreserved => {
                "the newer draft was preserved; the prior steer remains available in composer history"
                    .to_string()
            }
            ComposerRestoreDisposition::ReconciliationQueued => {
                unreachable!("steer has no durable reconciliation id")
            }
        };
        self.inform(
            format!(
                "steer on {id}: delivery could not be confirmed; {preservation}. Steer is not \
                 idempotent — check the transcript and provider state before deliberately \
                 sending it again"
            ),
            NoticeKind::Error,
        );
    }

    fn accept_reconciled_composer_draft(&mut self, plane: Plane, id: &str, turn_id: &str) {
        let key = (plane, id.to_string());
        let cleared = if self.sessions.open.as_ref() == Some(&key) {
            self.sessions.composer.as_mut().is_some_and(|composer| {
                if composer.owns_reconciliation(turn_id) {
                    composer.editor.accept_submission();
                    composer.user_changed_draft();
                    true
                } else {
                    false
                }
            })
        } else {
            self.sessions
                .composer_drafts
                .get(&key)
                .and_then(|draft| draft.reconciliation_owner.as_ref())
                .is_some_and(|owner| {
                    owner.turn_id == turn_id
                        && self
                            .sessions
                            .composer_drafts
                            .get(&key)
                            .is_some_and(|draft| owner.generation == draft.generation)
                })
        };

        if cleared {
            self.sessions.composer_drafts.remove(&key);
            if self.sessions.open.as_ref() == Some(&key) {
                self.remember_composer_history();
            }
        }
    }

    fn release_reconciliation_draft(&mut self, plane: Plane, id: &str, turn_id: &str) {
        let key = (plane, id.to_string());
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.owns_reconciliation(turn_id) {
                    composer.reconciliation_owner = None;
                }
            }
            self.remember_composer_history();
            return;
        }

        if let Some(draft) = self.sessions.composer_drafts.get_mut(&key) {
            let owned = draft.reconciliation_owner.as_ref().is_some_and(|owner| {
                owner.turn_id == turn_id && owner.generation == draft.generation
            });
            if owned {
                draft.reconciliation_owner = None;
            }
        }
    }

    fn settle_pending_reconciliation(&mut self, plane: Plane, id: &str, turn_id: Option<&str>) {
        let Some(turn_id) = turn_id else {
            return;
        };
        let key = (plane, id.to_string());
        if let Some(pending) = self.sessions.pending_reconciliations.get_mut(&key) {
            pending.retain(|entry| entry.turn_id != turn_id);
            if pending.is_empty() {
                self.sessions.pending_reconciliations.remove(&key);
            }
        }
    }

    fn reply_outcome_unknown(error: &ClientError) -> bool {
        match error {
            ClientError::Rpc(rpc) => {
                rpc.code == ErrorCode::UpstreamTimeout || model::outcome_unknown(rpc.data.as_ref())
            }
            // The transport can disappear after the gateway received the mutation but
            // before its answer reached this client. As in the CLI first-message path,
            // no local transport error is permission to mint a second logical turn.
            _transport => true,
        }
    }

    fn event_acknowledges_reply_request(event: &Event) -> bool {
        matches!(
            event.kind,
            EventType::RunStarted
                | EventType::RunCompleted
                | EventType::RunFailed
                | EventType::RunCancelled
                | EventType::InputAccepted
                | EventType::TurnQueued
                | EventType::TurnStarted
                | EventType::OutputTextDelta
                | EventType::OutputTextFinal
                | EventType::TurnCompleted
                | EventType::TurnFailed
                | EventType::TurnInterrupted
                | EventType::ApprovalRequested
        )
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

        if self.sessions.owner_conflict(plane, id).is_some() {
            self.cursors.forget(plane, id);
            return;
        }

        let key = (plane, id.to_string());
        let owner = self.session_route_node(plane, id).map(str::to_string);

        if !self.sessions.watches.contains_key(&key) {
            // An event for a session this client stopped watching. The gateway drops the
            // registration on unsubscribe, so this is the one frame that can cross it.
            return;
        }

        let Some(event) = params.get("event") else {
            return;
        };

        match Event::decode(event) {
            Ok(event) => {
                let approval = matches!(event.kind, EventType::ApprovalRequested);
                let acknowledges_reply = Self::event_acknowledges_reply_request(&event);
                let Some(watch) = self.sessions.watches.get_mut(&key) else {
                    return;
                };
                watch.absorb(vec![event]);

                let cursor = watch.cursor();
                let gap = watch.has_gap();

                if acknowledges_reply {
                    self.sessions.clear_reply_pending(plane, id);
                }

                self.cursors.set(plane, id, cursor, owner.as_deref());

                // A hole in the live stream that no `stream.lagged` explained: this side
                // lost frames, and the repair is the same one.
                if gap {
                    self.resync(plane, id.to_string(), false);
                }

                if approval {
                    self.open_approval(plane, id.to_string());
                }
            }
            Err(_undecodable) => {
                if let Some(watch) = self.sessions.watches.get_mut(&key) {
                    watch.undecodable += 1;
                }
            }
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

        self.sessions
            .remember_owner(plane, &ended.id, params.get("node").and_then(Value::as_str));

        // `unknown` means the coordinator disappeared, not that the provider session
        // reached a terminal state. A remote BEAM node may keep running and return after
        // the network heals, so retain the cursor and wait for fleet status to report its
        // owner connected before resubscribing.
        if ended.status == "unknown" && self.session_route_node(plane, &ended.id).is_some() {
            self.wait_for_remote_owner(plane, &ended.id);
            self.inform(
                format!(
                    "{} became unreachable; its cursor is safe and Ouroboros will resubscribe when the machine reconnects",
                    ended.id
                ),
                NoticeKind::Warn,
            );
            return;
        }

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.end(ended.status.clone());
        }

        self.sessions.recovering.remove(&key);
        self.sessions.clear_reply_pending(plane, &ended.id);

        self.cursors.forget(plane, &ended.id);
    }

    /// Retains a remote stream exactly where it stopped and waits for live fleet status
    /// before trying to subscribe again. This is shared by `stream.ended status=unknown`
    /// and by the reconnect hook: after the local gateway reconnects, the hook can be the
    /// first caller to discover that this particular owner is still offline.
    fn wait_for_remote_owner(&mut self, plane: Plane, id: &str) {
        let key = (plane, id.to_string());

        if let Some(watch) = self.sessions.watches.get_mut(&key) {
            watch.ended = None;
            watch.resyncing = false;
            watch.resync_again = false;
        }

        self.sessions.rounds.remove(&key);
        self.sessions
            .recovering
            .entry(key)
            .or_insert(SessionRecovery {
                attempts: 0,
                next_tick: self.ticks,
            });
        self.sessions.clear_reply_pending(plane, id);
        self.status.invalidate();
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
    }

    /// Whether a failed remote subscribe says only that the owner cannot be reached yet.
    /// Typed RPC data is preferred; transport loss is necessarily outcome-unknown. Bad
    /// frames and a stopped client are deterministic local failures and must not create a
    /// background retry loop.
    fn resync_waits_for_remote_owner(error: &ClientError) -> bool {
        match error {
            ClientError::Rpc(rpc) => {
                rpc.data
                    .as_ref()
                    .and_then(|data| data.get("reason"))
                    .and_then(Value::as_str)
                    == Some("owner_unavailable")
            }
            ClientError::ConnectionClosed | ClientError::Timeout | ClientError::Io(_) => true,
            ClientError::FrameTooLarge { .. }
            | ClientError::BadJson(_)
            | ClientError::Stopped(_) => false,
        }
    }

    fn recover_remote_sessions(&mut self) {
        let Some(status) = self.status.value.as_ref() else {
            return;
        };
        let connected_nodes: HashSet<&str> =
            status.connected_nodes.iter().map(String::as_str).collect();
        let fleet_machines = status
            .cluster
            .get("fleet")
            .and_then(|fleet| fleet.get("machines"))
            .and_then(Value::as_array);

        let due = self
            .sessions
            .recovering
            .iter()
            .filter_map(|(key @ (plane, id), recovery)| {
                if self.ticks < recovery.next_tick {
                    return None;
                }
                let owner = self.session_route_node(*plane, id)?;
                let connected = connected_nodes.contains(owner)
                    || fleet_machines.is_some_and(|machines| {
                        machines.iter().any(|machine| {
                            machine.get("node").and_then(Value::as_str) == Some(owner)
                                && matches!(
                                    machine.get("state").and_then(Value::as_str),
                                    Some("connected" | "local")
                                )
                        })
                    });
                connected.then(|| key.clone())
            })
            .collect::<Vec<_>>();

        for (plane, id) in due {
            let Some(recovery) = self.sessions.recovering.get_mut(&(plane, id.clone())) else {
                continue;
            };
            recovery.attempts = recovery.attempts.saturating_add(1);
            let shift = recovery.attempts.saturating_sub(1).min(5);
            let delay = 13_u64.checked_shl(shift).unwrap_or(375).min(375);
            recovery.next_tick = self.ticks.saturating_add(delay);
            self.sessions.rounds.remove(&(plane, id.clone()));
            self.resync(plane, id, true);
        }
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
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

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
        let params = self.routed_session_params(plane, &id, params);

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
        if self.sessions.owner_conflict(plane, &id).is_some() {
            if let Some(watch) = self.sessions.watches.get_mut(&key) {
                watch.resyncing = false;
                watch.resync_again = false;
            }
            self.cursors.forget(plane, &id);
            return;
        }

        let owner = self.session_route_node(plane, &id).map(str::to_string);
        let recovering = subscribe && self.sessions.recovering.contains_key(&key);

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
                let acknowledges_reply = events.iter().any(Self::event_acknowledges_reply_request);

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

                if recovering {
                    watch.ended = None;
                    watch.note(Note::Reconnected, cursor);
                }

                if acknowledges_reply {
                    self.sessions.clear_reply_pending(plane, &id);
                }

                self.cursors.set(plane, &id, cursor, owner.as_deref());

                if recovering {
                    self.sessions.recovering.remove(&key);
                    self.inform(
                        format!("{id} reconnected and resumed from cursor {cursor}"),
                        NoticeKind::Info,
                    );
                }

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
            Err(error)
                if subscribe && owner.is_some() && Self::resync_waits_for_remote_owner(&error) =>
            {
                watch.resync_again = false;
                self.wait_for_remote_owner(plane, &id);
                self.inform(
                    format!(
                        "{id}'s machine is still unreachable; its cursor is safe and Ouroboros will retry after it reconnects ({error})"
                    ),
                    NoticeKind::Warn,
                );
            }
            Err(ClientError::Rpc(rpc)) => {
                match CursorPruned::from_error_data(rpc.data.as_ref()) {
                    Some(pruned) => {
                        watch.raise_floor(pruned.floor);
                        watch.resync_again = false;
                        let cursor = watch.cursor();
                        self.cursors.set(plane, &id, cursor, owner.as_deref());

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
        let owner = self.sessions.owner_node(plane, &id).map(str::to_string);
        self.open_session_on(plane, id, owner);
    }

    /// Opens a returned fleet reference before the next list poll has had a chance to
    /// report it. Callers that only have a local id use [`open_session`](Self::open_session).
    pub fn open_session_on(&mut self, plane: Plane, id: String, node: Option<String>) {
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        self.sessions.remember_owner(plane, &id, node.as_deref());
        let key = (plane, id.clone());
        let switching = self.sessions.open.as_ref() != Some(&key);

        if switching {
            self.remember_composer_history();
            self.sessions.composer = None;
        }

        self.sessions
            .watches
            .entry(key.clone())
            .or_insert_with(|| Watch::new(plane, id.clone()));

        self.sessions.open = Some(key.clone());
        self.tab = Tab::Sessions;

        if plane == Plane::Interactive {
            if self.sessions.composer.is_none() {
                self.compose(ComposerVerb::Message);
            }
        } else {
            self.sessions.composer = None;
        }

        let cursor = self
            .sessions
            .watches
            .get(&key)
            .map(Watch::cursor)
            .unwrap_or(0);

        let owner = self.session_route_node(plane, &id);
        self.cursors.set(plane, &id, cursor, owner);
        self.resync(plane, id, true);
    }

    /// Reissues an indeterminate initial message under its original logical turn id.
    ///
    /// This is the `ouro new -m` handoff after its pre-UI call lost a trustworthy answer.
    /// The runtime either accepts this as the first arrival when the original request
    /// never reached it, reports a turn whose dispatch is now known, or keeps a
    /// checkpointed uncertain dispatch outcome-unknown. It never redispatches that
    /// uncertain intent. [`Tag::FirstMessage`] keeps the draft and same id only while the
    /// outcome stays unknown; a definite refusal restores the draft with a fresh id.
    pub fn retry_first_message(&mut self, id: String, input: String, turn_id: String) {
        let plane = Plane::Interactive;
        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let method = plane.method("send_message");
        if !self.hello.serves(&method) {
            self.restore_refused_first_message(plane, &id, input, ComposerVerb::Message);
            self.inform(
                format!("{id} is open, but this gateway no longer serves {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        let submission_sequence = self.next_composer_submission_sequence();
        self.restore_first_message(
            plane,
            &id,
            input.clone(),
            turn_id.clone(),
            submission_sequence,
        );

        self.sessions.mark_reply_pending(plane, &id);
        let params = self.routed_session_params(
            plane,
            &id,
            json!({ "id": id, "input": input, "turn_id": turn_id }),
        );
        self.issue(Call::new(
            Tag::FirstMessage {
                plane,
                id: id.clone(),
                turn_id: turn_id.clone(),
                input: input.clone(),
                submission_sequence,
            },
            method,
            params,
        ));
    }

    /// Opens a known-created but failed `ouro new` handoff without dispatching its CLI
    /// message. Unlike reconciliation, the gateway has already proved the start outcome:
    /// the session exists and readiness failed before this draft was sent.
    pub fn restore_created_start_failure(
        &mut self,
        plane: Plane,
        id: &str,
        input: Option<String>,
        notice: String,
    ) {
        if let Some(input) = input {
            self.restore_refused_first_message(plane, id, input, ComposerVerb::Message);
        }
        self.inform(notice, NoticeKind::Error);
    }

    /// Marks the successful pre-UI `ouro new -m` turn so the next typed request queues
    /// behind it instead of attempting a second immediate Harness message.
    pub fn continue_after_first_message(&mut self, id: &str) {
        if self.sessions.open.as_ref() != Some(&(Plane::Interactive, id.to_string())) {
            return;
        }

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.verb = ComposerVerb::FollowUp;
        }
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
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        if self.leader_until.is_some() {
            self.leader_key(key);
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('p')) {
            if matches!(self.overlay, Some(Overlay::Commands(_))) {
                self.overlay = None;
            } else if self.overlay.is_none() {
                self.overlay = Some(Overlay::Commands(CommandPalette::default()));
            }
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('q')) {
            self.open_quit();
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('x')) && self.overlay.is_none() {
            self.leader_until = Some(self.ticks + LEADER_TICKS);
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('g')) && self.overlay.is_none() {
            self.request_external_editor();
            return;
        }

        // Event details must remain reachable while the composer owns printable keys.
        // Ctrl+O is the Pi/OpenCode muscle memory for expanding tool output; Ctrl+E is
        // readline end-of-line once it reaches the editor.
        if ctrl && matches!(key.code, KeyCode::Char('o')) && self.overlay.is_none() {
            self.toggle_session_details();
            return;
        }

        if ctrl && matches!(key.code, KeyCode::Char('c')) {
            self.ctrl_c();
            return;
        }

        if ctrl
            && matches!(key.code, KeyCode::Char('d'))
            && self.overlay.is_none()
            && self.focused_prompt_empty()
        {
            self.open_quit();
            return;
        }

        if self.overlay.is_some() {
            self.overlay_key(key);
            return;
        }

        // The composer is always focused, so these have to be claimed before Up/Down
        // become prompt history. The wheel is handled as Msg::Scroll, not as keys.
        if self.transcript_scroll_key(key) {
            return;
        }

        if matches!(key.code, KeyCode::Char('?')) && !shift && self.focused_prompt_empty() {
            self.overlay = Some(Overlay::Help);
            return;
        }

        if self.sessions.composer.is_some() && self.tab == Tab::Sessions {
            self.composer_key(key);
            return;
        }

        if self.tab == Tab::Sessions && self.sessions.open.is_none() && self.home_owns_key(key.code)
        {
            self.home_key(key);
            return;
        }

        match key.code {
            KeyCode::Char(digit @ '1'..='7') if !ctrl => {
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
            KeyCode::Char(',') => self.open_settings(),
            _ => {}
        }
    }

    fn leader_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};

        self.leader_until = None;

        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        match key.code {
            KeyCode::Esc => {}
            KeyCode::Char('n') if shift => self.open_new_session(),
            KeyCode::Char('N') => self.open_new_session(),
            KeyCode::Char('n') => self.new_home(),
            KeyCode::Char('l') => self.activate_command(Command::SwitchSession),
            KeyCode::Char('e') | KeyCode::Char('g') => self.request_external_editor(),
            KeyCode::Char('y') => self.copy_last_agent(),
            KeyCode::Char('s') => self.compose(ComposerVerb::Steer),
            KeyCode::Char('a') => self.reopen_approval(),
            KeyCode::Char('w') => self.start_writable_session(),
            KeyCode::Char('x') => self.open_close_confirm(),
            KeyCode::Char('o') | KeyCode::Char('d') => self.toggle_session_details(),
            KeyCode::Char('q') => self.open_quit(),
            KeyCode::Char('?') => self.overlay = Some(Overlay::Help),
            KeyCode::Char(',') => self.open_settings(),
            _ => self.inform(
                "ctrl+x n new · w write · l sessions · e editor · y copy · s steer · x end · q quit",
                NoticeKind::Info,
            ),
        }
    }

    fn select_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.poll();
    }

    fn move_by(&mut self, delta: isize) {
        match self.tab {
            Tab::Dashboard => {}
            Tab::Sessions => {
                if let Some(watch) = self.sessions.open_watch_mut() {
                    // Scrolling away from the bottom stops the transcript from jumping
                    // under a reader every time an event arrives; `Watch::measured`
                    // holds the rows still on the frames that follow.
                    if delta < 0 {
                        // Clamped against what the last frame drew. Left unbounded, a
                        // held PageUp on a short transcript buys hundreds of keypresses
                        // that do nothing, and then hundreds more to get back.
                        let wanted = watch
                            .scroll
                            .saturating_add(delta.unsigned_abs())
                            .min(watch.max_scroll());

                        if wanted > 0 {
                            watch.follow = false;
                            watch.scroll = wanted;
                        }
                    } else {
                        watch.scroll = watch.scroll.saturating_sub(delta as usize);

                        if watch.scroll == 0 {
                            watch.follow = true;
                        }
                    }
                }
            }
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

    /// Transcript motion that must win over the always-on composer.
    ///
    /// Bare Up/Down stay prompt history, matching Pi and OpenCode. The wheel, PageUp, and
    /// Shift/Ctrl+Up are how you read the conversation without leaving the draft.
    fn transcript_scroll_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};

        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            return false;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);

        match key.code {
            KeyCode::PageUp => self.scroll_view(-10),
            KeyCode::PageDown => self.scroll_view(10),
            KeyCode::Up if ctrl || shift => self.scroll_view(-3),
            KeyCode::Down if ctrl || shift => self.scroll_view(3),
            _ => return false,
        }

        true
    }

    fn scroll_view(&mut self, delta: isize) {
        if self.overlay.is_some() {
            return;
        }

        self.move_by(delta);
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
            Tab::Sessions => {}
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
            Tab::Sessions => {}

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
            Tab::Sessions => {
                if self.sessions.open.is_some() {
                    self.compose(ComposerVerb::Message);
                }
            }
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
        if self.tab != Tab::Sessions {
            self.select_tab(Tab::Sessions);
            return;
        }

        if self.tab == Tab::Sessions {
            if self.sessions.composer.is_some() {
                self.remember_composer_history();
                self.sessions.composer = None;
                return;
            }

            self.sessions.open = None;
        }
    }

    // ----- harness home --------------------------------------------------------------

    /// Lands this client on the coding home and asks for what that home needs.
    ///
    /// Called once by the driver, before the first frame, and only where a session was not
    /// already asked for — `ouro new` states what it wants on the command line and opens
    /// what it started.
    ///
    /// There is no modal to dismiss and no provider picker between `ouro` and the composer.
    /// Account state, recent sessions, and the current workspace all arrive behind the
    /// first frame, so the composer is typeable while they are still in flight.
    pub fn open_home(&mut self) {
        self.tab = Tab::Sessions;
        self.issue_if_due(Tag::Account, "account.read", json!({}), ACCOUNT_TICKS);
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

    /// Records that this operator has reached the coding home once.
    ///
    /// A marker rather than a timestamp: the only question it answers is "has this person
    /// seen this client introduce itself", and a date would invite a client to decide the
    /// answer expires.
    fn mark_welcomed(&mut self) {
        if !self.config.onboarding.welcomed {
            self.config.onboarding.welcomed = true;
            self.save_pending = true;
        }
    }

    fn home_key(&mut self, key: crossterm::event::KeyEvent) {
        if self.home_pending {
            return;
        }

        if self
            .first_message
            .as_ref()
            .is_some_and(|pending| pending.start_outcome_unknown)
        {
            if key.code == crossterm::event::KeyCode::Enter {
                self.submit_home();
            } else {
                self.home_error = Some(
                    "this start may already exist; press Enter to reconcile its same session id \
                     before changing the prompt"
                        .to_string(),
                );
            }
            return;
        }

        match self.home_draft.handle_key(key, &self.completion_catalog) {
            EditorAction::Submit => self.submit_home(),
            EditorAction::Cancel => {
                self.home_draft.clear_text();
                self.home_error = None;
            }
            EditorAction::None => {
                self.home_error = None;
            }
            EditorAction::Scroll(_) => {}
        }
    }

    fn submit_home(&mut self) {
        let provider = self.home_provider().to_string();
        let prompt = self.home_draft.submission();

        // Navigation and account commands remain usable before Codex authentication. The
        // draft is accepted only when the command itself was handled, so ordinary work text
        // survives the login overlay and can be submitted unchanged afterwards.
        if prompt
            .as_deref()
            .is_some_and(|prompt| self.activate_slash_command(prompt))
        {
            self.home_draft.accept_submission();
            return;
        }

        // An API-key install needs no sign-in, and pushing one at it would be offering a
        // flow that cannot succeed and is not needed.
        if provider == "codex" && !self.codex_usable() {
            self.open_account();
            return;
        }

        let Some(prompt) = prompt else {
            self.home_error = Some("Type what you want the agent to do.".to_string());
            return;
        };

        if !self.hello.serves("interactive.start") {
            self.home_error = Some("this gateway does not serve interactive.start".to_string());
            return;
        }

        if !self.hello.operates() {
            self.home_error = Some(format!(
                "starting a session mutates the runtime, and this listener runs at scope `{}`",
                self.hello.scope
            ));
            return;
        }

        let request = self
            .first_message
            .as_ref()
            .filter(|pending| pending.start_outcome_unknown && pending.input == prompt)
            .map(|pending| pending.start.clone())
            .unwrap_or_else(|| StartRequest {
                id: new_session_id(),
                plane: Plane::Interactive,
                provider: provider.clone(),
                machine: String::new(),
                workspace: self.default_workspace(),
                approval_mode: self.config.defaults.approval_mode(),
                sandbox_mode: self.config.defaults.sandbox_mode(),
                objective: String::new(),
            });

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                self.home_error = Some(refusal.message());
                return;
            }
        };

        self.home_pending = true;
        self.home_error = None;
        match self.first_message.as_mut() {
            Some(pending)
                if pending.start_outcome_unknown
                    && pending.input == prompt
                    && pending.start.id == request.id =>
            {
                pending.start_outcome_unknown = false;
            }
            _ => {
                self.first_message = Some(PendingFirstMessage {
                    input: prompt,
                    turn_id: new_turn_id(),
                    start: request.clone(),
                    start_outcome_unknown: false,
                });
            }
        }
        self.config.defaults.provider = Some(provider);
        self.mark_welcomed();
        self.save_pending = true;

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    /// Starts a new interactive session that can edit the workspace.
    ///
    /// Sandbox is a start-time option: a running read-only session cannot be promoted.
    /// This is the switch the composer chrome offers.
    fn start_writable_session(&mut self) {
        if let Some(request) = self.pending_background_start.clone() {
            let Ok(params) = request.params() else {
                self.pending_background_start = None;
                self.inform(
                    "the saved writable-session reconciliation was invalid; no request was sent",
                    NoticeKind::Error,
                );
                return;
            };
            self.inform(
                format!(
                    "reconciling the same writable session id {}; no duplicate will be started",
                    request.id
                ),
                NoticeKind::Warn,
            );
            self.issue(
                Call::new(
                    Tag::Start {
                        plane: request.plane,
                        id: request.id.clone(),
                    },
                    request.method(),
                    params,
                )
                .with_timeout(START_TIMEOUT),
            );
            return;
        }

        if self.open_sandbox().is_some_and(|(_, writable)| writable) {
            self.inform(
                "this session can already edit files in the workspace",
                NoticeKind::Info,
            );
            return;
        }

        if self.sessions.open.is_none()
            && self
                .config
                .defaults
                .sandbox_mode()
                .map_or(true, SandboxMode::writable)
        {
            self.inform(
                "new sessions can already edit files; --sandbox-mode read_only or settings \
                 starts a read-only one",
                NoticeKind::Info,
            );
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
                    "starting a session mutates the runtime, and this listener runs at scope `{}`",
                    self.hello.scope
                ),
                NoticeKind::Warn,
            );
            return;
        }

        let provider = self
            .sessions
            .open_info()
            .and_then(|session| session.provider.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.home_provider().to_string());

        if provider.is_empty() {
            self.inform(
                "choose a provider before starting a writable session",
                NoticeKind::Warn,
            );
            return;
        }

        let workspace = self
            .sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| self.default_workspace());

        let request = StartRequest {
            id: new_session_id(),
            plane: Plane::Interactive,
            provider,
            machine: String::new(),
            workspace,
            approval_mode: self.config.defaults.approval_mode(),
            sandbox_mode: Some(SandboxMode::WorkspaceWrite),
            objective: String::new(),
        };

        let params = match request.params() {
            Ok(params) => params,
            Err(refusal) => {
                self.inform(refusal.message(), NoticeKind::Warn);
                return;
            }
        };

        self.inform(
            "starting a session that can edit files in the workspace",
            NoticeKind::Info,
        );

        self.pending_background_start = Some(request.clone());

        self.issue(
            Call::new(
                Tag::Start {
                    plane: Plane::Interactive,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    fn open_account(&mut self) {
        if self.chatgpt_connected() {
            let flow = if self.spawned() {
                AccountFlow::Browser
            } else {
                AccountFlow::DeviceCode
            };

            self.overlay = Some(Overlay::Account(Box::new(AccountDialog {
                pending: false,
                flow,
                login_id: None,
                url: None,
                code: None,
                error: None,
            })));
            return;
        }

        if !self.hello.serves("account.login.start") {
            self.home_error = Some(
                "this gateway does not expose managed ChatGPT sign-in; update the runtime"
                    .to_string(),
            );
            return;
        }

        if !self.hello.operates() {
            self.home_error = Some(format!(
                "ChatGPT sign-in changes the runtime host, and this listener runs at scope `{}`",
                self.hello.scope
            ));
            return;
        }

        let flow = if self.spawned() {
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
    }

    fn new_home(&mut self) {
        self.overlay = None;
        self.tab = Tab::Sessions;
        self.remember_composer_history();
        self.sessions.open = None;
        self.sessions.composer = None;
        self.home_draft.clear_text();
        self.home_error = None;
        self.poll();
    }

    fn paste(&mut self, text: &str) {
        if self.overlay.is_some() {
            self.overlay_paste(text);
            return;
        }

        if self.tab == Tab::Sessions {
            if let Some(composer) = self.sessions.composer.as_mut() {
                let before = composer.editor.text().to_string();
                composer.editor.paste(text, &self.completion_catalog);
                if composer.editor.text() != before {
                    composer.user_changed_draft();
                }
                return;
            }

            if self.sessions.open.is_none()
                && self.home_ready()
                && !self.home_pending
                && !self
                    .first_message
                    .as_ref()
                    .is_some_and(|pending| pending.start_outcome_unknown)
            {
                self.home_draft.paste(text, &self.completion_catalog);
                self.home_error = None;
            }
        }
    }

    /// A bracketed paste while an overlay owns the keyboard.
    ///
    /// Dropped silently before this, which made the workspace box of the `n` dialog and the
    /// settings overlay — the two fields most likely to receive a path off the clipboard —
    /// look broken in a way nothing on screen explained. Every overlay with a text field
    /// takes it; the rest say so rather than swallowing it.
    fn overlay_paste(&mut self, text: &str) {
        // These are one-line fields. A multi-line clipboard becomes one line rather than
        // being refused, because the alternative is a field that silently holds a newline
        // it cannot draw.
        let flattened = text
            .split(['\n', '\r'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");

        if flattened.is_empty() {
            return;
        }

        let taken = match self.overlay.as_mut() {
            // A dialog whose start is in flight takes no edits, for the same reason it
            // takes no keys: the parameters that produced the request are the ones its
            // answer is about.
            Some(Overlay::New(dialog)) if !dialog.pending => {
                push_into(dialog.text_mut(), &flattened)
            }
            Some(Overlay::Settings(settings)) => {
                let taken = push_into(settings.text_mut(), &flattened);
                settings.edited |= taken;
                taken
            }
            Some(Overlay::Commands(palette)) => {
                palette.query.push_str(&flattened);
                // The selection is derived from the query, exactly as for a typed character.
                palette.selected = palette.first_match();
                true
            }
            Some(Overlay::Prompt { buffer, .. }) => push_into(Some(buffer), &flattened),
            _ => false,
        };

        // Said rather than swallowed: a paste that vanished with nothing on screen to
        // explain it reads as the terminal being broken.
        if !taken {
            self.inform("nothing here is taking text right now", NoticeKind::Info);
        }
    }

    // ----- session verbs -------------------------------------------------------------

    /// Opens the composer, refusing where the plane has no such verb rather than sending
    /// a call that would come back `-32601`.
    fn compose(&mut self, requested_verb: ComposerVerb) {
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

        // Harness deliberately separates an immediate message from the durable follow-up
        // queue. Sending another immediate message to a running session is `:busy`, so `i`
        // means "queue the next request" unless the latest session snapshot is idle.
        let verb = if requested_verb == ComposerVerb::Message
            && self
                .sessions
                .open_info()
                .is_some_and(|session| session.status.as_str() != "idle")
        {
            ComposerVerb::FollowUp
        } else {
            requested_verb
        };

        let method = plane.method(verb.method());

        if !self.hello.serves(&method) {
            self.inform(
                format!("this gateway does not serve {method}"),
                NoticeKind::Warn,
            );
            return;
        }

        if let Some(composer) = self.sessions.composer.as_mut() {
            composer.verb = verb;
            return;
        }

        let key = (plane, id);
        let mut editor = Editor::default();
        editor.restore_history(
            self.sessions
                .composer_history
                .get(&key)
                .cloned()
                .unwrap_or_default(),
        );
        let saved = self.sessions.composer_drafts.get(&key).cloned();
        let (draft_generation, reconciliation_owner) = if let Some(saved) = saved {
            editor.paste(&saved.input, &self.completion_catalog);
            (saved.generation, saved.reconciliation_owner)
        } else if let Some(pending) = self
            .sessions
            .pending_reconciliations
            .get(&key)
            .and_then(|pending| pending.front())
        {
            editor.paste(&pending.input, &self.completion_catalog);
            (
                1,
                Some(ReconciliationDraftOwner {
                    turn_id: pending.turn_id.clone(),
                    generation: 1,
                }),
            )
        } else {
            (0, None)
        };

        self.sessions.composer = Some(Composer {
            verb,
            editor,
            draft_generation,
            reconciliation_owner,
        });
    }

    /// Copies the open composer's history and exact unsent draft where the next composer
    /// over the same session will find them.
    fn remember_composer_history(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };
        let Some(composer) = self.sessions.composer.as_ref() else {
            return;
        };

        let key = (plane, id);
        let history = composer.editor.history().to_vec();
        let draft = composer.editor.text().to_string();
        let generation = composer.draft_generation;
        let reconciliation_owner = composer.reconciliation_owner.clone();

        self.sessions.composer_history.insert(key.clone(), history);
        if draft.is_empty() {
            self.sessions.composer_drafts.remove(&key);
        } else {
            self.sessions.composer_drafts.insert(
                key,
                SavedComposerDraft {
                    input: draft,
                    generation,
                    reconciliation_owner,
                },
            );
        }
    }

    fn toggle_session_details(&mut self) {
        if self.tab != Tab::Sessions || self.sessions.open.is_none() {
            self.inform(
                "open a session before viewing its event details",
                NoticeKind::Info,
            );
            return;
        }

        self.sessions.show_event_details = !self.sessions.show_event_details;

        if let Some(watch) = self.sessions.open_watch_mut() {
            // Chat and event rows wrap differently. Returning to the newest content avoids
            // carrying a line-based scroll offset into a view where it means something else.
            watch.follow = true;
            watch.scroll = 0;
        }
    }

    fn composer_key(&mut self, key: crossterm::event::KeyEvent) {
        if self.first_message_in_flight() {
            return;
        }

        let action = self
            .sessions
            .composer
            .as_mut()
            .map(|composer| {
                let before = composer.editor.text().to_string();
                let action = composer.editor.handle_key(key, &self.completion_catalog);
                if composer.editor.text() != before {
                    composer.user_changed_draft();
                }
                action
            })
            .unwrap_or(EditorAction::None);

        match action {
            EditorAction::Submit => self.submit_composer(),
            EditorAction::Cancel => self.escape_from_prompt(),
            EditorAction::Scroll(delta) => self.move_by(delta * 10),
            EditorAction::None => {}
        }
    }

    fn first_message_in_flight(&self) -> bool {
        let Some((plane, id)) = self.sessions.open.as_ref() else {
            return false;
        };

        self.in_flight.iter().any(|tag| {
            matches!(
                tag,
                Tag::FirstMessage {
                    plane: pending_plane,
                    id: pending_id,
                    ..
                } if pending_plane == plane && pending_id == id
            )
        })
    }

    fn next_composer_submission_sequence(&mut self) -> u64 {
        self.next_composer_submission_sequence =
            self.next_composer_submission_sequence.saturating_add(1);
        self.next_composer_submission_sequence
    }

    fn same_session_mutation_in_flight(&self, plane: Plane, id: &str) -> bool {
        self.in_flight.iter().any(|tag| match tag {
            Tag::FirstMessage {
                plane: pending_plane,
                id: pending_id,
                ..
            }
            | Tag::ComposerAction {
                plane: pending_plane,
                id: pending_id,
                ..
            } => *pending_plane == plane && pending_id == id,
            _ => false,
        })
    }

    fn earlier_session_mutation_in_flight(
        &self,
        plane: Plane,
        id: &str,
        submission_sequence: u64,
    ) -> bool {
        self.in_flight.iter().any(|tag| match tag {
            Tag::FirstMessage {
                plane: pending_plane,
                id: pending_id,
                submission_sequence: pending_sequence,
                ..
            }
            | Tag::ComposerAction {
                plane: pending_plane,
                id: pending_id,
                submission_sequence: pending_sequence,
                ..
            } => {
                *pending_plane == plane
                    && pending_id == id
                    && *pending_sequence <= submission_sequence
            }
            _ => false,
        })
    }

    fn submit_composer(&mut self) {
        let open_key = self.sessions.open.clone();
        if open_key
            .as_ref()
            .is_some_and(|(plane, id)| self.refuse_owner_conflict(*plane, id))
        {
            return;
        }

        let pending = open_key.as_ref().and_then(|key| {
            self.sessions
                .pending_reconciliations
                .get(key)
                .and_then(|pending| pending.front())
                .cloned()
        });

        if let Some(pending) = pending {
            let Some((plane, id)) = self.sessions.open.clone() else {
                return;
            };

            if self.earlier_session_mutation_in_flight(plane, &id, pending.submission_sequence) {
                self.inform(
                    format!(
                        "still reconciling outcome-unknown turn {}; the draft remains unsent",
                        pending.turn_id
                    ),
                    NoticeKind::Info,
                );
                return;
            }

            self.sessions.mark_reply_pending(plane, &id);
            self.inform(
                format!(
                    "reconciling outcome-unknown turn {}; the newer draft remains in the editor",
                    pending.turn_id
                ),
                NoticeKind::Info,
            );

            let params = json!({
                "id": id,
                "input": pending.input,
                "turn_id": pending.turn_id
            });
            let params = self.routed_session_params(plane, &id, params);
            let call = match pending.kind {
                PendingReconciliationKind::FirstMessage => Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: id.clone(),
                        turn_id: pending.turn_id,
                        input: pending.input,
                        submission_sequence: pending.submission_sequence,
                    },
                    plane.method("send_message"),
                    params,
                ),
                PendingReconciliationKind::Composer(verb) => {
                    let (label, method) = match verb {
                        ComposerVerb::Message => ("send_message", plane.method("send_message")),
                        ComposerVerb::FollowUp => ("follow_up", plane.method("follow_up")),
                        ComposerVerb::Steer => {
                            unreachable!("steer has no same-id reconciliation")
                        }
                    };
                    Call::new(
                        Tag::ComposerAction {
                            label,
                            verb,
                            plane,
                            id: id.clone(),
                            turn_id: Some(pending.turn_id),
                            input: pending.input,
                            reconciling: true,
                            submission_sequence: pending.submission_sequence,
                        },
                        method,
                        params,
                    )
                }
            };
            self.issue(call);
            return;
        }

        let Some(composer) = self.sessions.composer.as_mut() else {
            return;
        };

        let Some(input) = composer.editor.submission() else {
            return;
        };
        let verb = composer.verb;

        if self.activate_slash_command(&input) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.accept_submission();
                composer.user_changed_draft();
            }
            self.remember_composer_history();
            return;
        }

        let Some((plane, id)) = self.sessions.open.clone() else {
            return;
        };

        // JSON-RPC requests are handled by independent gateway tasks. Keep the next input
        // visible and untouched until the prior same-session mutation is classified, so
        // scheduler order can never replace the order in which the operator pressed Enter.
        if self.same_session_mutation_in_flight(plane, &id) {
            self.inform(
                format!(
                    "the earlier request for {id} is still awaiting acknowledgement; this draft remains unsent"
                ),
                NoticeKind::Info,
            );
            return;
        }

        let Some(composer) = self.sessions.composer.as_mut() else {
            return;
        };
        let turn_id = if verb == ComposerVerb::Steer {
            // A steer is an injection into an already-running provider call. There is no
            // durable request ledger behind it, so do not manufacture an idempotency key.
            None
        } else {
            Some(new_turn_id())
        };
        composer.editor.accept_submission();
        composer.user_changed_draft();

        // After the first immediate message, every later acknowledged submission uses
        // Harness's durable queueing verb. An Enter while this acknowledgement is still
        // outstanding was returned above with the next draft visibly untouched.
        if composer.verb == ComposerVerb::Message {
            composer.verb = ComposerVerb::FollowUp;
        }

        self.remember_composer_history();
        let submission_sequence = self.next_composer_submission_sequence();
        let (label, method) = match verb {
            ComposerVerb::Message => ("send_message", plane.method("send_message")),
            ComposerVerb::FollowUp => ("follow_up", plane.method("follow_up")),
            ComposerVerb::Steer => ("steer", plane.method("steer")),
        };

        if matches!(verb, ComposerVerb::Message | ComposerVerb::FollowUp) {
            self.sessions.mark_reply_pending(plane, &id);
        }

        let tag = Tag::ComposerAction {
            label,
            verb,
            plane,
            id: id.clone(),
            turn_id: turn_id.clone(),
            input: input.clone(),
            reconciling: false,
            submission_sequence,
        };

        let params = match turn_id {
            Some(turn_id) => json!({ "id": id, "input": input, "turn_id": turn_id }),
            None => json!({ "id": id, "input": input }),
        };
        let params = self.routed_session_params(plane, &id, params);

        self.issue(Call::new(tag, method, params));
    }

    fn activate_slash_command(&mut self, input: &str) -> bool {
        let trimmed = input.trim();

        if let Some(name) = slash_arg(trimmed, "/preview") {
            self.preview_capability(name);
            return true;
        }

        if let Some(name) = slash_arg(trimmed, "/admit") {
            self.confirm_admit_capability(name);
            return true;
        }

        let command = match trimmed {
            "/new" => Some(Command::NewSession),
            "/switch" | "/sessions" => Some(Command::SwitchSession),
            "/details" => Some(Command::SessionDetails),
            "/copy" => Some(Command::CopyLast),
            "/interrupt" => Some(Command::Interrupt),
            "/steer" => Some(Command::Steer),
            "/editor" => Some(Command::ExternalEditor),
            "/close" => Some(Command::CloseSession),
            "/options" => Some(Command::NewSessionOptions),
            "/write" => Some(Command::WriteAccess),
            "/connect" => Some(Command::ConnectChatGpt),
            "/runtime" => Some(Command::Runtime),
            "/agents" => Some(Command::Agents),
            "/teams" => Some(Command::Teams),
            "/plans" => Some(Command::Plans),
            "/upgrades" => Some(Command::Upgrades),
            "/capabilities" => Some(Command::ListCapabilities),
            "/logs" => Some(Command::Logs),
            "/machines" | "/fleet" => Some(Command::Machines),
            "/settings" => Some(Command::Settings),
            "/help" | "/hotkeys" => Some(Command::Help),
            "/quit" => {
                self.open_quit();
                return true;
            }
            "/clear" => return true,
            _ => return false,
        };

        self.activate_command(command.expect("matched slash command"));
        true
    }

    /// Ctrl-C: clear the prompt if it has text; otherwise interrupt a running turn;
    /// a second press on an idle surface opens the quit dialog. Never a single-press quit.
    fn ctrl_c(&mut self) {
        if self.overlay.is_some() {
            self.interrupt();
            return;
        }

        if !self.focused_prompt_empty() {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.editor.clear_text();
                composer.user_changed_draft();
                self.remember_composer_history();
            } else if let Some(editor) = self.focused_editor_mut() {
                editor.clear_text();
            }
            self.ctrl_c_until = None;
            return;
        }

        if self.sessions.open.is_some() {
            self.interrupt_turn();
            self.ctrl_c_until = None;
            return;
        }

        if self.ctrl_c_until.is_some_and(|until| self.ticks < until) {
            self.ctrl_c_until = None;
            self.open_quit();
            return;
        }

        self.ctrl_c_until = Some(self.ticks + CTRL_C_QUIT_TICKS);
        self.inform(
            "press ctrl+c again to quit · esc aborts a running turn · ctrl+q opens the quit dialog",
            NoticeKind::Info,
        );
    }

    /// Ctrl-C / Esc: the active turn, never this process.
    fn interrupt(&mut self) {
        if self.overlay.is_some() {
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

            return;
        }

        self.interrupt_turn();
    }

    fn interrupt_turn(&mut self) {
        let Some((plane, id)) = self.sessions.open.clone() else {
            self.inform(
                "esc or ctrl+c interrupts a running turn; ctrl+q opens the quit dialog",
                NoticeKind::Info,
            );
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let (label, method) = match plane {
            Plane::Interactive => ("interrupt", "interactive.interrupt".to_string()),
            // The coding plane has no interrupt; cancelling is what it offers, and it is
            // destructive enough to go through the confirmation instead.
            Plane::Coding => {
                self.inform(
                    format!("{id} is a coding task; ctrl+x x cancels it"),
                    NoticeKind::Info,
                );
                return;
            }
        };

        // `interactive.interrupt` defaults to the active turn, which is the only thing a
        // terminal's ctrl-c can mean.
        let params = self.routed_session_params(plane, &id, json!({ "id": id }));
        self.issue(Call::new(
            Tag::Action {
                label,
                plane,
                id: id.clone(),
            },
            method,
            params,
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
        if self.overlay.is_some() {
            return;
        }

        self.select_tab(Tab::Sessions);

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

        let workspace_is_inferred = self.config.defaults.workspace.is_none()
            && self
                .launch_dir
                .as_ref()
                .is_some_and(|path| !path.is_empty());
        self.overlay = Some(Overlay::New(Box::new(NewSession::new(
            Plane::Interactive,
            self.default_workspace(),
            workspace_is_inferred,
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

    fn capability_workspace(&self) -> Option<String> {
        self.sessions
            .open_info()
            .and_then(|session| session.workspace.clone())
            .filter(|workspace| !workspace.is_empty())
            .or_else(|| {
                let workspace = self.default_workspace();
                (!workspace.is_empty()).then_some(workspace)
            })
    }

    fn capability_target(&self) -> (Plane, String) {
        self.sessions
            .open
            .clone()
            .unwrap_or((Plane::Interactive, "capabilities".into()))
    }

    fn list_capabilities(&mut self) {
        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before listing capabilities",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, id) = self.capability_target();
        self.issue(Call::new(
            Tag::Action {
                label: "list capabilities",
                plane,
                id,
            },
            "capabilities.list",
            json!({ "workspace": workspace }),
        ));
    }

    fn preview_capability(&mut self, name: &str) {
        if name.trim().is_empty() {
            self.list_capabilities();
            return;
        }

        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before previewing a capability",
                NoticeKind::Warn,
            );
            return;
        };

        let Some(path) = capability_proposal_path(name) else {
            self.inform(
                "a capability path must stay inside the workspace",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, _) = self.capability_target();
        self.issue(
            Call::new(
                Tag::Action {
                    label: "preview",
                    plane,
                    id: path.clone(),
                },
                "capabilities.preview",
                json!({ "workspace": workspace, "path": path }),
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    fn confirm_admit_capability(&mut self, name: &str) {
        if name.trim().is_empty() {
            self.inform("name a proposal: /admit Echo", NoticeKind::Warn);
            return;
        }

        let Some(workspace) = self.capability_workspace() else {
            self.inform(
                "open a session or set a default workspace before admitting a capability",
                NoticeKind::Warn,
            );
            return;
        };

        let Some(path) = capability_proposal_path(name) else {
            self.inform(
                "a capability path must stay inside the workspace",
                NoticeKind::Warn,
            );
            return;
        };

        let (plane, session_id) = self.capability_target();
        let mut params = json!({ "workspace": workspace, "path": path });
        if session_id != "capabilities" {
            params["session_id"] = json!(session_id);
        }

        self.overlay = Some(Overlay::Confirm {
            title: format!("admit {path}?"),
            detail: "this forges, signs, and rolls out the proposal; the selected model cannot \
                     undo it"
                .to_string(),
            options: vec![
                (
                    "admit (forge, sign, roll out)".to_string(),
                    Some(
                        Call::new(
                            Tag::Action {
                                label: "admit",
                                plane,
                                id: path,
                            },
                            "capabilities.admit",
                            params,
                        )
                        .with_timeout(START_TIMEOUT),
                    ),
                ),
                ("cancel".to_string(), None),
            ],
            choice: 1,
        });
    }

    fn capability_answered(&mut self, label: &str, id: &str, value: Value) {
        let text = match label {
            "list capabilities" => format_capability_list(&value),
            "preview" => format_capability_preview(id, &value),
            "admit" => format_capability_admit(id, &value),
            _ => format!("{label} accepted for {id}"),
        };

        self.inform(text, NoticeKind::Info);
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
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);

        self.overlay = Some(Overlay::Settings(Box::new(Settings {
            field: SettingsField::Machines,
            provider: 0,
            workspace: self.default_workspace(),
            approval: approval_index(self.config.defaults.approval_mode()),
            sandbox: sandbox_index(self.config.defaults.sandbox_mode()),
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
                match settings.field {
                    SettingsField::Machines => self.open_machines(),
                    SettingsField::Save => self.save_settings(),
                    _ => {
                        // Enter never saves from a field row, for the same reason it never
                        // starts a session from one: finishing a sentence in a text box is not
                        // a decision to write a file.
                        settings.move_field(1);
                    }
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

    fn open_machines(&mut self) {
        self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
        self.overlay = Some(Overlay::Machines(Box::default()));
    }

    fn machines_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let Some(Overlay::Machines(machines)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc if machines.guide.is_some() => machines.guide = None,
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Char('j') | KeyCode::Down => {
                machines.guide = None;
                machines.selected =
                    (machines.selected + 1).min(MachineAction::ALL.len().saturating_sub(1));
            }
            KeyCode::BackTab | KeyCode::Char('k') | KeyCode::Up => {
                machines.guide = None;
                machines.selected = machines.selected.saturating_sub(1);
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                machines.guide = Some(machines.selected())
            }
            KeyCode::Left | KeyCode::Char('h') => machines.guide = None,
            KeyCode::Char('y') => {
                let command = machines.selected().command().to_string();
                self.copy_pending = Some(command.clone());
                self.inform(
                    format!("copied `{command}`; review any placeholders before running it"),
                    NoticeKind::Info,
                );
            }
            KeyCode::Char('r') => {
                self.status.invalidate();
                self.issue_if_due(Tag::Status, "runtime.status", json!({}), STATUS_TICKS);
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

        self.config.defaults.sandbox_mode =
            sandbox_at(settings.sandbox).map(|mode| mode.as_str().to_string());

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
        let machines = self.machine_choices();

        let Some(Overlay::New(dialog)) = self.overlay.as_mut() else {
            return;
        };

        // A dialog whose start is in flight takes no edits: the parameters that produced
        // the request are the ones its answer is about.
        if dialog.pending {
            if matches!(key.code, KeyCode::Esc) {
                dialog.error = Some(
                    "start is still in flight; wait for its answer before closing this form"
                        .to_string(),
                );
            }

            return;
        }

        if dialog.reconciling {
            match key.code {
                KeyCode::Tab | KeyCode::Down => dialog.move_field(1),
                KeyCode::BackTab | KeyCode::Up => dialog.move_field(-1),
                KeyCode::Enter if dialog.field == NewField::Start => self.submit_new_session(),
                _ => {
                    dialog.error = Some(format!(
                        "session {} may already exist; choose Start and press Enter to reconcile \
                         that same id before editing or closing",
                        dialog.request.id
                    ));
                }
            }
            return;
        }

        match key.code {
            KeyCode::Esc => self.overlay = None,
            KeyCode::Tab | KeyCode::Down => dialog.move_field(1),
            KeyCode::BackTab | KeyCode::Up => dialog.move_field(-1),
            KeyCode::Left => dialog.cycle(-1, providers, &machines),
            KeyCode::Right => dialog.cycle(1, providers, &machines),
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

        let request = dialog
            .pending_request
            .clone()
            .unwrap_or_else(|| dialog.resolved(&providers));

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
        dialog.pending_request = Some(request.clone());

        let plane = request.plane;

        // `interactive.start` and `coding.start` declare a 120s gateway ceiling: provider
        // readiness is legitimately unbounded upstream and this is the one call that
        // waits for it.
        self.issue(
            Call::new(
                Tag::Start {
                    plane,
                    id: request.id.clone(),
                },
                request.method(),
                params,
            )
            .with_timeout(START_TIMEOUT),
        );
    }

    /// A session this client just created: watch it, focus it, and open the composer so
    /// the next thing typed is the first message.
    fn started(&mut self, plane: Plane, started: StartedRef) {
        if self.refuse_owner_conflict(plane, &started.id) {
            return;
        }

        let start_failure = started.start_failure.clone();

        self.overlay = None;
        self.home_pending = false;
        self.home_error = None;
        self.home_draft.accept_submission();

        // The lists are polled, and waiting up to three seconds for the row to appear
        // under a session the operator is already looking at reads as a bug.
        self.sessions.interactive.invalidate();
        self.sessions.coding.invalidate();

        self.open_session_on(plane, started.id.clone(), started.node.clone());

        // This exact request exists and is addressable, but its coordinator recorded a
        // readiness failure. Open that durable record and keep any home prompt as a fresh,
        // definitely-not-dispatched draft. Treating the typed result as an ordinary ready
        // reference would immediately send into a terminal session; treating it as an
        // error would trap the caller in same-id reconciliation despite a known outcome.
        if let Some(failure) = start_failure {
            if let Some(first_message) = self.first_message.take() {
                self.restore_refused_first_message(
                    plane,
                    &started.id,
                    first_message.input,
                    ComposerVerb::Message,
                );
            }

            self.inform(
                format!(
                    "created {} on the {plane} plane, but it did not become ready: {failure}. \
                     The durable session is open; no first message was dispatched.",
                    started.id
                ),
                NoticeKind::Error,
            );
            return;
        }

        // The quick-start screen's prompt. Sent here rather than beside the start, because
        // until this answer arrived there was no session to send it to — the same order
        // `ouro new -m` uses, and for the same reason: `*.start` waits for provider
        // readiness before it answers, so the session is ready to take this.
        if let Some(first_message) = self.first_message.take() {
            let method = plane.method("send_message");

            if self.hello.serves(&method) {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.restore_reconciliation(
                        &first_message.input,
                        &first_message.turn_id,
                        &self.completion_catalog,
                    );
                }
                self.remember_composer_history();
                let submission_sequence = self.next_composer_submission_sequence();
                self.sessions.mark_reply_pending(plane, &started.id);
                let params = self.routed_session_params(
                    plane,
                    &started.id,
                    json!({
                        "id": started.id,
                        "input": first_message.input,
                        "turn_id": first_message.turn_id
                    }),
                );
                self.issue(Call::new(
                    Tag::FirstMessage {
                        plane,
                        id: started.id.clone(),
                        turn_id: first_message.turn_id.clone(),
                        input: first_message.input.clone(),
                        submission_sequence,
                    },
                    method,
                    params,
                ));
            } else {
                if let Some(composer) = self.sessions.composer.as_mut() {
                    composer.editor.clear_text();
                    composer
                        .editor
                        .paste(&first_message.input, &self.completion_catalog);
                    composer.user_changed_draft();
                }
                self.remember_composer_history();
                // The session exists and the message does not. Saying which is the only
                // honest answer; the composer below is where it can be retyped.
                self.inform(
                    format!(
                        "{} started, but this gateway does not serve {method}",
                        started.id
                    ),
                    NoticeKind::Warn,
                );

                self.restore_refused_first_message(
                    plane,
                    &started.id,
                    first_message.input,
                    ComposerVerb::Message,
                );

                return;
            }
        }

        self.inform(
            format!("started {} on the {plane} plane", started.id),
            NoticeKind::Info,
        );
    }

    fn accept_first_message(&mut self, plane: Plane, id: &str, turn_id: &str) {
        self.accept_reconciled_composer_draft(plane, id, turn_id);
        self.settle_pending_reconciliation(plane, id, Some(turn_id));

        if self.sessions.open.as_ref() == Some(&(plane, id.to_string())) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                composer.verb = ComposerVerb::FollowUp;
            }
        }
    }

    fn restore_first_message(
        &mut self,
        plane: Plane,
        id: &str,
        input: String,
        turn_id: String,
        submission_sequence: u64,
    ) {
        if plane != Plane::Interactive {
            return;
        }

        let key = (plane, id.to_string());
        let pending = self
            .sessions
            .pending_reconciliations
            .entry(key.clone())
            .or_default();
        if !pending.iter().any(|pending| pending.turn_id == turn_id) {
            pending.push_back(PendingComposerReconciliation {
                kind: PendingReconciliationKind::FirstMessage,
                input: input.clone(),
                turn_id: turn_id.clone(),
                submission_sequence,
            });
            pending
                .make_contiguous()
                .sort_by_key(|pending| pending.submission_sequence);
        }

        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.editor.is_empty() {
                    composer.restore_reconciliation(&input, &turn_id, &self.completion_catalog);
                    composer.verb = ComposerVerb::Message;
                }
            }
            self.remember_composer_history();
        }
    }

    fn restore_refused_first_message(
        &mut self,
        plane: Plane,
        id: &str,
        input: String,
        verb: ComposerVerb,
    ) {
        if plane != Plane::Interactive {
            return;
        }

        let key = (plane, id.to_string());
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                let owned_retry = composer.reconciliation_owner.take().is_some();
                let restored = composer.editor.is_empty();
                if restored {
                    composer.editor.paste(&input, &self.completion_catalog);
                    composer.user_changed_draft();
                }
                if restored || owned_retry {
                    composer.verb = verb;
                }
            }
            self.remember_composer_history();
        } else {
            match self.sessions.composer_drafts.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(SavedComposerDraft {
                        input,
                        generation: 1,
                        reconciliation_owner: None,
                    });
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().reconciliation_owner = None;
                }
            }
        }
    }

    fn restore_composer_submission(
        &mut self,
        plane: Plane,
        id: &str,
        input: String,
        retry_turn_id: Option<String>,
        verb: ComposerVerb,
        submission_sequence: u64,
    ) -> ComposerRestoreDisposition {
        if plane != Plane::Interactive {
            return ComposerRestoreDisposition::NewerDraftPreserved;
        }

        let key = (plane, id.to_string());
        let has_reconciliation = retry_turn_id.is_some();
        let reconciliation_turn_id = retry_turn_id.clone();

        if let Some(turn_id) = retry_turn_id {
            let pending = self
                .sessions
                .pending_reconciliations
                .entry(key.clone())
                .or_default();
            if !pending.iter().any(|pending| pending.turn_id == turn_id) {
                pending.push_back(PendingComposerReconciliation {
                    kind: PendingReconciliationKind::Composer(verb),
                    input: input.clone(),
                    turn_id: turn_id.clone(),
                    submission_sequence,
                });
                pending
                    .make_contiguous()
                    .sort_by_key(|pending| pending.submission_sequence);
            }
        }

        // A reply can arrive after the operator began typing the next thought. Keep that
        // newer draft intact. The stable-id queue above lives on the session, so switching
        // away before this answer or closing/reopening the composer cannot discard it.
        if self.sessions.open.as_ref() == Some(&key) {
            if let Some(composer) = self.sessions.composer.as_mut() {
                if composer.editor.is_empty() {
                    if let Some(turn_id) = reconciliation_turn_id.as_deref() {
                        composer.restore_reconciliation(&input, turn_id, &self.completion_catalog);
                    } else {
                        composer.editor.paste(&input, &self.completion_catalog);
                        composer.user_changed_draft();
                    }
                    composer.verb = verb;
                    self.remember_composer_history();
                    return ComposerRestoreDisposition::Restored;
                }

                self.remember_composer_history();
                return if has_reconciliation {
                    ComposerRestoreDisposition::ReconciliationQueued
                } else {
                    ComposerRestoreDisposition::NewerDraftPreserved
                };
            }
        }

        // A known refusal has no reconciliation id, but its exact text is still useful on
        // return to this session. Never replace a newer draft saved during the switch.
        if !has_reconciliation {
            return match self.sessions.composer_drafts.entry(key) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(SavedComposerDraft {
                        input,
                        generation: 1,
                        reconciliation_owner: None,
                    });
                    ComposerRestoreDisposition::SavedForReopen
                }
                std::collections::hash_map::Entry::Occupied(_) => {
                    ComposerRestoreDisposition::NewerDraftPreserved
                }
            };
        }

        ComposerRestoreDisposition::ReconciliationQueued
    }

    fn start_failed(&mut self, plane: Plane, id: &str, error: ClientError) {
        let message = match &error {
            ClientError::Rpc(rpc) => model::refusal(rpc),
            other => other.to_string(),
        };
        let outcome_unknown = model::start_outcome_unknown(&error);

        if let Some(Overlay::New(dialog)) = self.overlay.as_mut() {
            if dialog
                .pending_request
                .as_ref()
                .is_some_and(|request| request.id == id && request.plane == plane)
            {
                dialog.pending = false;
                if outcome_unknown {
                    dialog.reconciling = true;
                    dialog.error = Some(format!(
                        "{message}. Session {id} may already exist; choose Start and press Enter \
                         to reconcile this exact id. Editing and closing stay locked until then."
                    ));
                } else {
                    dialog.reconciling = false;
                    dialog.pending_request = None;
                    dialog.request.id = new_session_id();
                    dialog.error = Some(message);
                }
                return;
            }
        }

        if self
            .first_message
            .as_ref()
            .is_some_and(|pending| pending.start.id == id && pending.start.plane == plane)
        {
            self.home_pending = false;
            if outcome_unknown {
                if let Some(pending) = self.first_message.as_mut() {
                    pending.start_outcome_unknown = true;
                }
                self.home_error = Some(format!(
                    "{message}. Session {id} may already exist; press Enter to reconcile the \
                     same id before changing this prompt."
                ));
            } else {
                // A definite refusal means this id cannot become a session. Keep the
                // visible draft, but the next submission mints a fresh start identity.
                self.first_message = None;
                self.home_error = Some(message);
            }
            return;
        }

        if self
            .pending_background_start
            .as_ref()
            .is_some_and(|request| request.id == id && request.plane == plane)
        {
            if outcome_unknown {
                self.inform(
                    format!(
                        "{message}. Writable session {id} may already exist; run /write again to \
                         reconcile the same id."
                    ),
                    NoticeKind::Error,
                );
            } else {
                self.pending_background_start = None;
                self.inform(
                    format!("starting writable session {id} was refused: {message}"),
                    NoticeKind::Error,
                );
            }
            return;
        }

        if self.tab == Tab::Sessions && self.sessions.open.is_none() {
            self.home_pending = false;
            self.home_error = Some(format!("start {id}: {message}"));
        } else {
            self.inform(
                format!("starting session {id} failed: {message}"),
                NoticeKind::Error,
            );
        }
    }

    fn open_close_confirm(&mut self) {
        let from_picker = matches!(self.overlay, Some(Overlay::SessionPicker { .. }));
        let Some((plane, id)) = self.session_action_target() else {
            if !self.sessions.merged().is_empty() {
                self.activate_command(Command::SwitchSession);
                self.inform(
                    "choose a session, then press x to end or remove it",
                    NoticeKind::Info,
                );
            }
            return;
        };
        self.open_close_confirm_for(plane, id, from_picker);
    }

    fn session_action_target(&self) -> Option<(Plane, String)> {
        match &self.overlay {
            Some(Overlay::SessionPicker { selected }) => selected
                .clone()
                .or_else(|| self.sessions.picker_key(self.sessions.picker_index(None))),
            _ => self.sessions.open.clone(),
        }
    }

    fn open_close_confirm_for(&mut self, plane: Plane, id: String, from_picker: bool) {
        if self.tab != Tab::Sessions && !from_picker {
            return;
        }

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        self.resume_session_picker = from_picker;
        let session = self.sessions.get(plane, &id);

        if session.is_some_and(|session| session.last_known) {
            self.overlay = Some(Overlay::Confirm {
                title: format!("hide {id}?"),
                detail: "its owner is offline, so this only hides the last-known row in this client; the durable record stays on that machine"
                    .to_string(),
                options: vec![
                    (
                        "hide here".to_string(),
                        Some(Call::new(
                            Tag::Action {
                                label: "hide",
                                plane,
                                id: id.clone(),
                            },
                            "interactive.delete",
                            json!({ "id": id }),
                        )),
                    ),
                    ("keep it".to_string(), None),
                ],
                choice: 0,
            });
            return;
        }

        if session.is_some_and(|session| session.status.terminal()) {
            let routed = self.routed_session_params(plane, &id, json!({ "id": id }));
            let method = plane.method("delete");
            self.overlay = Some(Overlay::Confirm {
                title: format!("remove {id}?"),
                detail:
                    "this deletes the durable record on its owner; it is not undone by reattaching"
                        .to_string(),
                options: vec![
                    (
                        "remove from this machine".to_string(),
                        Some(Call::new(
                            Tag::Action {
                                label: "remove",
                                plane,
                                id: id.clone(),
                            },
                            method,
                            routed,
                        )),
                    ),
                    ("keep it".to_string(), None),
                ],
                choice: 0,
            });
            return;
        }

        let routed = self.routed_session_params(plane, &id, json!({ "id": id }));

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
                        routed.clone(),
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
                        routed.clone(),
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
                        routed,
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

    fn submit_confirm(&mut self, call: Call) {
        if let Tag::Action {
            label: "hide",
            plane,
            id,
        } = &call.tag
        {
            let plane = *plane;
            let id = id.clone();
            self.session_removed(plane, &id);
            return;
        }

        self.issue(call);
    }

    fn session_removed(&mut self, plane: Plane, id: &str) {
        self.drop_local_session(plane, id);
        self.inform(format!("{id} removed from this client"), NoticeKind::Info);
        self.resume_picker_if_requested();
    }

    fn drop_local_session(&mut self, plane: Plane, id: &str) {
        let key = (plane, id.to_string());
        self.cursors.forget(plane, id);
        self.sessions.watches.remove(&key);
        self.sessions.rounds.remove(&key);
        self.sessions.clear_reply_pending(plane, id);
        self.sessions.composer_history.remove(&key);
        self.sessions.composer_drafts.remove(&key);
        self.sessions.pending_reconciliations.remove(&key);
        self.sessions.recovering.remove(&key);
        self.sessions.drop_row(plane, id);

        if self.sessions.open.as_ref() == Some(&key) {
            self.sessions.open = None;
            self.sessions.composer = None;
        }
    }

    fn refresh_session_lists(&mut self) {
        self.sessions.interactive.invalidate();
        self.sessions.coding.invalidate();
        self.poll();
    }

    fn resume_picker_if_requested(&mut self) {
        if !self.resume_session_picker {
            return;
        }

        self.resume_session_picker = false;
        if self.sessions.merged().is_empty() {
            return;
        }

        let selected = self
            .sessions
            .open
            .clone()
            .or_else(|| self.sessions.picker_key(0));
        self.overlay = Some(Overlay::SessionPicker { selected });
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
            Some(Overlay::Commands(palette)) if matches!(key.code, KeyCode::Enter) => {
                palette.visible().get(palette.selected).copied()
            }
            _ => None,
        };

        if let Some(command) = selected_command {
            self.activate_command(command);
            return;
        }

        let Some(Overlay::Commands(palette)) = self.overlay.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Down => {
                let len = palette.visible().len();
                palette.selected = (palette.selected + 1).min(len.saturating_sub(1));
            }
            KeyCode::Up => palette.selected = palette.selected.saturating_sub(1),
            KeyCode::Backspace => {
                palette.query.pop();
                palette.selected = palette.first_match();
            }
            KeyCode::Char(c) if !ctrl => {
                palette.query.push(c);
                palette.selected = palette.first_match();
            }
            _ => {}
        }
    }

    fn activate_command(&mut self, command: Command) {
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
            Command::CopyLast => {
                self.overlay = None;
                self.copy_last_agent();
            }
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
            ..
        }) = self.overlay.take()
        else {
            return;
        };

        if self.refuse_owner_conflict(plane, &id) {
            return;
        }

        let (decision, scope) = APPROVAL_CHOICES[choice.min(APPROVAL_CHOICES.len() - 1)];

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
            model::respond_approval_params(&id, &request_id, decision, scope),
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
            PromptKind::HistoryModule | PromptKind::GrantsPrincipal if value.is_empty() => {
                return;
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

    fn expire_chords(&mut self) {
        if self.leader_until.is_some_and(|until| self.ticks >= until) {
            self.leader_until = None;
        }

        if self.ctrl_c_until.is_some_and(|until| self.ticks >= until) {
            self.ctrl_c_until = None;
        }
    }

    fn focused_prompt_empty(&self) -> bool {
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

    fn focused_editor_mut(&mut self) -> Option<&mut Editor> {
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

    fn escape_from_prompt(&mut self) {
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

    fn copy_last_agent(&mut self) {
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

    fn request_external_editor(&mut self) {
        let text = self
            .focused_editor()
            .map(|editor| editor.text().to_string())
            .unwrap_or_default();
        self.external_editor_pending = Some(text);
    }

    fn apply_external_editor(&mut self, text: String) {
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

fn friendly_machine(node: &str) -> String {
    node.split_once('@')
        .map(|(name, _host)| name)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("this machine")
        .to_string()
}

fn value_usize(value: Option<&Value>) -> Option<usize> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn slash_arg<'a>(input: &'a str, command: &str) -> Option<&'a str> {
    if input == command {
        Some("")
    } else {
        input
            .strip_prefix(command)
            .and_then(|rest| rest.strip_prefix(' '))
            .map(str::trim)
    }
}

fn capability_proposal_path(name: &str) -> Option<String> {
    let trimmed = name.trim().trim_start_matches('/').replace('\\', "/");

    if trimmed.is_empty() {
        return None;
    }

    if trimmed
        .split('/')
        .any(|part| part.is_empty() || part == "..")
    {
        return None;
    }

    if trimmed.contains('/') {
        Some(trimmed)
    } else {
        Some(format!(".ouroboros/capabilities/{trimmed}"))
    }
}

fn format_capability_list(value: &Value) -> String {
    let Some(items) = value.as_array() else {
        return "listed capability proposals".into();
    };

    if items.is_empty() {
        return "no capability proposals under .ouroboros/capabilities".into();
    }

    let names: Vec<String> = items
        .iter()
        .filter_map(|item| {
            item.get("path")
                .and_then(Value::as_str)
                .map(|path| path.rsplit('/').next().unwrap_or(path).to_string())
                .or_else(|| {
                    item.get("module")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
        })
        .collect();

    format!(
        "{} proposal{}: {}",
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names.join(", ")
    )
}

fn format_capability_preview(id: &str, value: &Value) -> String {
    let module = value.get("module").and_then(Value::as_str).unwrap_or(id);
    let loaded = value
        .get("loaded?")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let report = value.get("test_report");
    let total = report
        .and_then(|report| report.get("total"))
        .and_then(Value::as_u64);
    let failures = report
        .and_then(|report| report.get("failures"))
        .and_then(Value::as_u64);
    let tests = match (total, failures) {
        (Some(total), Some(failures)) => {
            format!("tests {}/{total}", total.saturating_sub(failures))
        }
        _ => "tests unknown".into(),
    };
    let load = if loaded {
        "loaded on this node"
    } else {
        "not loaded"
    };

    format!("preview {module}: {tests}, {load}")
}

fn format_capability_admit(id: &str, value: &Value) -> String {
    let module = value.get("module").and_then(Value::as_str).unwrap_or(id);
    let epoch = value
        .get("epoch")
        .map(model::compact)
        .unwrap_or_else(|| "-".into());
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let started = match value.get("started") {
        None | Some(Value::Null) => None,
        Some(started) => {
            if let Some(error) = started.get("error") {
                Some(format!("start failed: {}", model::compact(error)))
            } else if let Some(agent) = started.get("id").and_then(Value::as_str) {
                Some(format!("started {agent}"))
            } else {
                Some(model::compact(started))
            }
        }
    };

    match started {
        Some(started) => format!("admitted {module} epoch={epoch} {state}; {started}"),
        None => format!("admitted {module} epoch={epoch} {state}"),
    }
}
