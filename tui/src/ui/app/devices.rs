//! The Devices view: the machines this runtime can see, and the deployment of Ouroboros
//! onto one of them.
//!
//! This is the terminal half of the proposal's "Devices UI and deployment experience".
//! The web page built beside it draws the same inventory, the same fields, the same
//! confirmations, the same challenge kinds and the same progress states; what differs is
//! that this one is a keyboard and eighty columns.
//!
//! ## Nothing here does any work
//!
//! Discovery, SSH, artifact verification and roster writes happen on the *deployment
//! host* — the machine hosting the runtime this client is attached to, which for a
//! connected TUI is no more this laptop than it is a browser's. So this module contacts
//! nothing, forks nothing and reads no file: it issues the eight gateway methods listed
//! in `docs/TUI.md` §2.4 and draws what comes back. The permanent header says whose
//! machine that is, on every screen, because a credential typed into the wrong host's
//! prompt is the failure the header exists to prevent.
//!
//! ## Where the secret is, and is not
//!
//! Exactly one field in this file holds a typed secret: [`SecretInput`], whose buffer is
//! a [`Zeroizing<String>`] from the moment it exists, whose `Debug` prints a character
//! count and no characters, and which is cleared on submit, on cancel, on leaving the
//! challenge and on closing the view. It is never drawn — the field renders one bullet
//! per character — never put on a [`Tag`], never in a notice, and never in a log line.
//! What leaves this module is a single `fleet.deployment.authenticate` call whose
//! parameters the gateway is documented to keep out of its audit digest.
//!
//! ## The broker is the authority, not this view
//!
//! After `prepare` answers an operation id, every screen after it is a rendering of one
//! `fleet.deployment.status` snapshot: the state names the stage, the open challenges
//! name the question, and the steps name what happened. This client holds no parallel
//! idea of where the deployment has got to, which is what makes closing the view (or
//! losing the connection, or restarting this client) cost nothing but the screen.

use std::fmt;

use zeroize::Zeroizing;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::fleet_network::{human, DeviceState, DiscoveryCode, FIELD_COLUMNS, MESSAGE_COLUMNS};

use super::super::access;
use super::super::theme;
use super::*;

/// How often the live operation's snapshot is re-read while the view is open. The
/// progress screen is the one place in this client where a second matters to a person
/// watching, and the method is a cheap read of state the broker already holds.
const SNAPSHOT_TICKS: u64 = 13; // ~1s

/// The inventory is not on a cadence at all: `fleet.devices` shells out to the network
/// client under a ten-second ceiling, and polling that every few seconds would fork a
/// process at a peer's expense for a list that changes when an operator changes it. It
/// is read when the view opens and when `r` asks.
///
/// A quarter of `u64::MAX` rather than all of it: [`Loadable::resolved`] adds this to the
/// current tick, and the honest "never" would be the one value that overflows there.
const INVENTORY_HOLD: u64 = u64::MAX / 4;

// ------------------------------------------------------------------------ the secret

/// The masked input buffer, and the only place in this client a typed secret lives.
///
/// Three properties, each of which a test pins: the bytes are zeroized when they are
/// dropped or cleared ([`Zeroizing`]), `Debug` never prints them, and the renderer is
/// given a bullet count rather than the string.
#[derive(Default)]
pub struct SecretInput {
    buffer: Zeroizing<String>,
}

impl fmt::Debug for SecretInput {
    /// A count, never the characters. `#[derive(Debug)]` on the struct that holds this
    /// would otherwise print a password into whatever a panic handler writes.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SecretInput({} characters, redacted)",
            self.len()
        )
    }
}

impl SecretInput {
    pub fn len(&self) -> usize {
        self.buffer.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn push(&mut self, character: char) {
        self.buffer.push(character);
    }

    pub fn pop(&mut self) {
        self.buffer.pop();
    }

    /// Overwrites the bytes and empties the buffer.
    ///
    /// `String::clear` sets the length to zero and leaves the capacity holding what was
    /// typed, so this zeroizes first. Called on submit, on cancel, on leaving the
    /// challenge and on closing the view.
    pub fn clear(&mut self) {
        use zeroize::Zeroize;

        self.buffer.zeroize();
        self.buffer.clear();
    }

    /// Takes the secret out for its one use, leaving the buffer zeroized.
    ///
    /// The returned value is still a [`Zeroizing`], so the caller's copy is wiped when
    /// the call that carries it goes out of scope.
    fn take(&mut self) -> Zeroizing<String> {
        let taken = Zeroizing::new(self.buffer.to_string());
        self.clear();
        taken
    }

    /// What the field draws: one bullet per character, and nothing that is in the buffer.
    pub fn masked(&self) -> String {
        "\u{2022}".repeat(self.len())
    }
}

// ------------------------------------------------------------------ decoded inventory

/// The deployment host, from `fleet.devices`'s `host`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentHost {
    pub hostname: String,
    pub user: String,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub issuer: bool,
    pub deploy: bool,
    pub reasons: Vec<String>,
}

impl DeploymentHost {
    fn decode(value: &Value) -> Self {
        let capabilities = value.get("capabilities");

        Self {
            hostname: text(value.get("hostname")).unwrap_or_else(|| "this machine".into()),
            user: text(value.get("user")).unwrap_or_else(|| "unknown".into()),
            os: text(value.get("os")),
            arch: text(value.get("arch")),
            issuer: value
                .get("issuer")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            deploy: capabilities
                .and_then(|capabilities| capabilities.get("deploy"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            reasons: capabilities
                .and_then(|capabilities| capabilities.get("reasons"))
                .and_then(Value::as_array)
                .map(|reasons| {
                    reasons
                        .iter()
                        .filter_map(|reason| text(Some(reason)))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// The permanent header the proposal requires on every screen of the flow, filled
    /// from the actual host and account rather than an example.
    pub fn header(&self) -> String {
        format!(
            "Deploying from {} \u{b7} local user {}",
            self.hostname, self.user
        )
    }

    /// The first reason Deploy is unavailable, in words.
    ///
    /// The codes are the broker's and stay in the data; these are the sentences. An
    /// unrecognised code is named rather than swallowed, because a runtime that grew a
    /// new blocker must not read as no blocker at all.
    pub fn blocker(&self) -> Option<String> {
        self.reasons.first().map(|reason| match reason.as_str() {
            "no_ca_key" => "This machine does not hold the fleet's certificate authority \
                            key, so it can describe the fleet but cannot admit a member. \
                            Open Devices on the machine that does."
                .to_string(),
            "ouro_path_unknown" => "This runtime cannot say where its own ouro executable \
                                    is, so it has nothing to hand a deployment worker."
                .to_string(),
            "no_data_dir" => "This runtime serves no durable data directory, so a \
                              deployment would have nowhere to keep its journal."
                .to_string(),
            "cleartext_web_bind" => "This runtime publishes its web endpoint on a \
                                     non-loopback address with no TLS, so credential \
                                     entry is refused on this deployment host."
                .to_string(),
            other => format!("This runtime reports the blocker {other}."),
        })
    }
}

/// What the network client could see, from `fleet.devices`'s `discovery`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub code: String,
    pub detail: Option<String>,
    pub visible_peers: usize,
}

impl Discovery {
    fn decode(value: &Value) -> Self {
        Self {
            code: text(value.get("code")).unwrap_or_else(|| "unavailable".into()),
            detail: sentence(value.get("detail")),
            visible_peers: value
                .get("visible_peers")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
        }
    }

    /// The distinct empty states the proposal's Inventory section requires, in the words
    /// `ouro fleet devices` already prints for them.
    ///
    /// Not retyped: [`headline_for`] builds the same [`crate::fleet_network::Inventory`]
    /// the CLI builds and asks it, so the two surfaces cannot drift apart.
    pub fn headline(&self) -> String {
        headline_for(&self.code, self.visible_peers)
    }

    /// Whether the client answered with a peer list at all.
    pub fn answered(&self) -> bool {
        matches!(self.code.as_str(), "ok" | "no_visible_peers")
    }
}

/// One row of the inventory, from `fleet.devices`'s `devices`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRow {
    pub name: String,
    pub machine: Option<String>,
    pub os: Option<String>,
    pub address: Option<String>,
    pub online: Option<bool>,
    pub last_seen: Option<String>,
    /// The snake_case state code. The words are [`DeviceRow::state_label`].
    pub state: String,
    pub name_conflict: Option<String>,
}

impl DeviceRow {
    fn decode(value: &Value) -> Self {
        Self {
            name: text(value.get("name")).unwrap_or_else(|| "unnamed device".into()),
            machine: text(value.get("machine")),
            os: text(value.get("os")),
            address: text(value.get("address")),
            online: value.get("online").and_then(Value::as_bool),
            last_seen: text(value.get("last_seen")),
            state: text(value.get("state")).unwrap_or_default(),
            name_conflict: text(value.get("name_conflicts_with_roster")),
        }
    }

    /// The state this build understands, or `None` for a code a newer `ouro` grew.
    pub fn parsed_state(&self) -> Option<DeviceState> {
        parse_state(&self.state)
    }

    /// The state a person reads. A code this build does not know is shown as itself
    /// rather than as a guess: the row is still a device, and inventing words for a
    /// state nothing here can reason about would be the honesty failure, not the gap.
    pub fn state_label(&self) -> String {
        match self.parsed_state() {
            Some(state) => state.label().to_string(),
            None => format!("{} (a state this client does not know)", self.state),
        }
    }

    /// Whether this row belongs under "Fleet devices" rather than "Available on this
    /// network". The same split `render_devices` makes for the CLI.
    pub fn in_fleet(&self) -> bool {
        self.machine.is_some() || self.parsed_state() == Some(DeviceState::ThisDeviceWithoutProfile)
    }

    /// Network presence with its observation time, in the CLI's words.
    pub fn presence(&self) -> String {
        match (self.online, self.last_seen.as_deref()) {
            (Some(true), _connected) => "online now".into(),
            (Some(false), Some(seen)) => format!("offline, last seen {seen}"),
            (Some(false), None) => "offline".into(),
            (None, Some(seen)) => format!("unknown, last seen {seen}"),
            (None, None) => "unknown".into(),
        }
    }

    /// The proposal's observed-state table: what an operator can do with this row.
    pub fn primary(&self) -> Primary {
        match self.parsed_state() {
            Some(DeviceState::DiscoveredInstallationUnknown) => Primary::Deploy,
            Some(DeviceState::ThisDevice) | Some(DeviceState::FleetMember) => Primary::View,
            Some(DeviceState::FleetMemberNotVisible) => Primary::Diagnose,
            Some(DeviceState::ThisDeviceWithoutProfile) => Primary::SetUpThisDevice,
            Some(DeviceState::PeerOffline)
            | Some(DeviceState::UnsupportedPlatform)
            | Some(DeviceState::NoUsableIpv4) => Primary::Blocked,
            None => Primary::Blocked,
        }
    }
}

/// The primary action of a row, as the proposal's table names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primary {
    Deploy,
    View,
    Continue,
    Diagnose,
    SetUpThisDevice,
    Blocked,
}

impl Primary {
    pub fn label(self) -> &'static str {
        match self {
            Self::Deploy => "Deploy Ouroboros",
            Self::View => "View device",
            Self::Continue => "Continue setup",
            Self::Diagnose => "Diagnose",
            Self::SetUpThisDevice => "Set up this device",
            Self::Blocked => "Refresh or details",
        }
    }
}

/// One deployment operation this data directory holds a journal for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationSummary {
    pub operation: String,
    pub state: Option<String>,
    pub kind: Option<String>,
    pub updated_at: Option<String>,
    /// The identity that started it (seam S5), or `None` on a journal this runtime
    /// cannot attribute. Shown, because continuing somebody else's setup inherits their
    /// credential prompts and must never happen quietly.
    pub owner: Option<String>,
    pub attached: bool,
    pub readable: bool,
}

impl OperationSummary {
    fn decode(value: &Value) -> Self {
        Self {
            operation: text(value.get("operation")).unwrap_or_default(),
            state: text(value.get("state")),
            kind: text(value.get("kind")),
            updated_at: text(value.get("updated_at")),
            owner: text(value.get("owner")),
            attached: value
                .get("attached")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            readable: value
                .get("readable")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }
    }

    /// Whether this operation can still be continued. A journal nobody can read is
    /// *not* finished — it is unknown — and it is offered for continuation so the
    /// operator hears about it rather than having it quietly filtered away.
    pub fn open(&self) -> bool {
        !matches!(self.state.as_deref(), Some("completed") | Some("cancelled"))
    }
}

/// The whole `fleet.devices` reply, decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    pub host: DeploymentHost,
    pub discovery: Discovery,
    pub devices: Vec<DeviceRow>,
    pub operations: Vec<OperationSummary>,
    /// Top-level keys this build did not read, named rather than passed through.
    pub unknown: Vec<String>,
}

impl Inventory {
    pub fn decode(value: &Value) -> Self {
        Self {
            host: value
                .get("host")
                .map(DeploymentHost::decode)
                .unwrap_or_default(),
            discovery: value
                .get("discovery")
                .map(Discovery::decode)
                .unwrap_or_default(),
            devices: array(value.get("devices"))
                .iter()
                .map(DeviceRow::decode)
                .collect(),
            operations: array(value.get("operations"))
                .iter()
                .map(OperationSummary::decode)
                .collect(),
            unknown: array(value.get("unknown"))
                .iter()
                .filter_map(|key| text(Some(key)))
                .collect(),
        }
    }

    /// The open operation for a device, matched by the machine name the journal records.
    ///
    /// `None` for every row when no operation is open, which is the common case: a row
    /// only says "Continue setup" when there is something to continue.
    pub fn open_operation(&self) -> Option<&OperationSummary> {
        self.operations
            .iter()
            .find(|operation| operation.open() && !operation.operation.is_empty())
    }
}

/// The membership subset a non-administrator or a read-scope listener sees instead,
/// from `fleet.status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FleetSubset {
    pub fleet_name: Option<String>,
    pub machines: Vec<(String, String)>,
}

impl FleetSubset {
    pub fn decode(value: &Value) -> Self {
        Self {
            fleet_name: text(value.get("fleet_name")),
            machines: array(value.get("machines"))
                .iter()
                .map(|machine| {
                    (
                        text(machine.get("machine")).unwrap_or_else(|| "unnamed".into()),
                        text(machine.get("state")).unwrap_or_else(|| "unknown".into()),
                    )
                })
                .collect(),
        }
    }
}

// ------------------------------------------------------------------ decoded snapshot

/// One step of a deployment, from a `step` event or the journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Step {
    pub machine: Option<String>,
    pub step: String,
    pub outcome: String,
    pub detail: Option<String>,
}

impl Step {
    fn decode(value: &Value) -> Self {
        Self {
            machine: text(value.get("machine")),
            step: text(value.get("step")).unwrap_or_else(|| "step".into()),
            outcome: text(value.get("outcome")).unwrap_or_else(|| "unknown".into()),
            detail: sentence(value.get("detail")),
        }
    }
}

/// One open challenge, with the secret-free metadata the worker issued it with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Challenge {
    pub id: String,
    pub kind: String,
    pub metadata: Value,
}

impl Challenge {
    fn decode(value: &Value) -> Self {
        Self {
            id: text(value.get("challenge")).unwrap_or_default(),
            kind: text(value.get("kind")).unwrap_or_default(),
            metadata: value.clone(),
        }
    }

    /// One metadata field, bounded.
    ///
    /// The spec's rule for these: normalize the labels rather than rendering an
    /// arbitrary remote prompt as trusted UI. The *shape* is normalized by this client
    /// drawing its own headings and its own field names; what is left is the value, and
    /// the value goes through [`human`] like every other remote string.
    fn field(&self, key: &str) -> Option<String> {
        self.metadata.get(key).and_then(|value| match value {
            Value::String(_) => text(Some(value)),
            Value::Number(number) => Some(number.to_string()),
            _other => None,
        })
    }
}

/// The sanitized snapshot of one operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// `worker` when one is attached, `journal` when none is. The operator's whole
    /// question after an interruption, so it is drawn rather than inferred.
    pub source: String,
    pub attached: bool,
    pub state: String,
    /// The identity that started this operation, when the worker reports one.
    pub owner: Option<String>,
    pub steps: Vec<Step>,
    pub log: Vec<String>,
    pub last_error: Option<String>,
    pub residue: Vec<String>,
    pub challenges: Vec<Challenge>,
}

impl Snapshot {
    pub fn decode(value: &Value) -> Self {
        Self {
            source: text(value.get("source")).unwrap_or_else(|| "journal".into()),
            attached: value
                .get("attached")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            state: text(value.get("state")).unwrap_or_default(),
            owner: text(value.get("owner")),
            steps: array(value.get("steps")).iter().map(Step::decode).collect(),
            log: array(value.get("log"))
                .iter()
                .filter_map(|line| sentence(line.get("line")).or_else(|| sentence(Some(line))))
                .collect(),
            last_error: sentence(value.get("last_error"))
                .or_else(|| sentence(value.get("last_error").and_then(|e| e.get("detail")))),
            residue: array(value.get("residue"))
                .iter()
                .filter_map(|item| sentence(Some(item)))
                .collect(),
            challenges: array(value.get("challenges"))
                .iter()
                .map(Challenge::decode)
                .collect(),
        }
    }

    /// The open challenge this screen is about, if any. The worker asks one question at
    /// a time; when it somehow asks two, the first by id is answered first — which is
    /// the order the broker sorts them in.
    pub fn challenge(&self) -> Option<&Challenge> {
        self.challenges.first()
    }

    /// The state a person reads. The codes stay in the data.
    pub fn state_label(&self) -> String {
        match self.state.as_str() {
            "attaching" => "connecting to the deployment worker".into(),
            "inspecting" => "inspecting the target".into(),
            "awaiting_host_trust" => "waiting for you to verify the host key".into(),
            "awaiting_auth" => "waiting for your credential".into(),
            "awaiting_review" => "waiting for you to review the plan".into(),
            "deploying" => "deploying".into(),
            "restarting_host" => "restarting this runtime".into(),
            "checking_readiness" => "checking readiness".into(),
            "completed" => "completed".into(),
            "interrupted" => "interrupted".into(),
            "failed" => "failed".into(),
            "cancelled" => "cancelled".into(),
            "" => "state not reported".into(),
            other => format!("{other} (a state this client does not know)"),
        }
    }

    pub fn waiting(&self) -> bool {
        matches!(
            self.state.as_str(),
            "awaiting_host_trust" | "awaiting_auth" | "awaiting_review"
        ) || self.challenge().is_some()
    }

    pub fn terminal(&self) -> bool {
        matches!(
            self.state.as_str(),
            "completed" | "failed" | "cancelled" | "interrupted"
        )
    }

    pub fn succeeded(&self) -> bool {
        self.state == "completed"
    }
}

// ------------------------------------------------------------------------ view state

/// Which rows the list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Filter {
    #[default]
    All,
    Fleet,
    Available,
}

impl Filter {
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Fleet => "fleet",
            Self::Available => "available",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::All => Self::Fleet,
            Self::Fleet => Self::Available,
            Self::Available => Self::All,
        }
    }
}

/// Why the inventory is not on the screen.
///
/// Two facts the proposal insists are different: a runtime that does not serve the
/// method at all, and one that serves it and would not answer this identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `hello.methods` does not list `fleet.devices`.
    CapabilityAbsent,
    /// The method is served and answered `-32003`. `fleet.devices` is a *read*-scope
    /// method, so a read-scope listener passes the scope gate: a refusal here can only
    /// be the identity rule, which demands an administrator for this one read.
    NotAdministrator,
    /// The listener was started at read scope and the verb mutates.
    ReadScope,
    /// Anything else the gateway said, kept as it said it.
    Other(String),
}

impl Refusal {
    /// The one sentence the proposal requires: why inventory or deployment is
    /// unavailable, distinguishing an absent capability from a denied permission.
    pub fn sentence(&self) -> String {
        match self {
            Self::CapabilityAbsent => "This runtime does not serve fleet.devices, so it \
                                       has no device inventory to show. The machines \
                                       below are its fleet membership, from fleet.status."
                .into(),
            Self::NotAdministrator => "Reading every machine on this network is an \
                                       administrator's read, and this identity is not an \
                                       administrator. The machines below are its fleet \
                                       membership, from fleet.status."
                .into(),
            Self::ReadScope => "This listener was started at read scope, so it can show \
                                what is here and cannot start a deployment."
                .into(),
            Self::Other(message) => format!("The runtime refused the inventory: {message}"),
        }
    }
}

/// Which field of the connect form has the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectField {
    User,
    Port,
    Identity,
    IdentityRef,
    InstallPath,
    DataDir,
    Service,
    Inspect,
}

impl ConnectField {
    pub const ALL: [Self; 8] = [
        Self::User,
        Self::Port,
        Self::Identity,
        Self::IdentityRef,
        Self::InstallPath,
        Self::DataDir,
        Self::Service,
        Self::Inspect,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::User => "ssh username",
            Self::Port => "port",
            Self::Identity => "authenticate with",
            Self::IdentityRef => "identity",
            Self::InstallPath => "install path",
            Self::DataDir => "data dir",
            Self::Service => "startup service",
            Self::Inspect => "[ inspect this device ]",
        }
    }

    /// The four fields the proposal calls advanced. Drawn under a heading that says so,
    /// because a form whose required field is fourth is a form people fill out wrong.
    pub fn advanced(self) -> bool {
        matches!(
            self,
            Self::Port | Self::IdentityRef | Self::InstallPath | Self::DataDir
        )
    }
}

/// How the operator wants to authenticate. A reference, never key material.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IdentityKind {
    /// Let the worker offer what this deployment host has.
    #[default]
    Offered,
    Agent,
    Key,
    Password,
}

impl IdentityKind {
    const ALL: [Self; 4] = [Self::Offered, Self::Agent, Self::Key, Self::Password];

    pub fn label(self) -> &'static str {
        match self {
            Self::Offered => "whatever this host has",
            Self::Agent => "an SSH agent identity",
            Self::Key => "a private key on this host",
            Self::Password => "the target account's password",
        }
    }

    fn wire(self) -> Option<&'static str> {
        match self {
            Self::Offered => None,
            Self::Agent => Some("agent"),
            Self::Key => Some("key"),
            Self::Password => Some("password"),
        }
    }

    /// What the `identity` field means for this choice, or `None` where it means
    /// nothing. A password has no reference: the secret is answered to its challenge.
    fn reference_hint(self) -> Option<&'static str> {
        match self {
            Self::Offered => None,
            Self::Agent => Some("the agent identity's label or public fingerprint"),
            Self::Key => Some("a path to a private key on the deployment host"),
            Self::Password => None,
        }
    }

    fn cycle(self, by: i32) -> Self {
        let index = Self::ALL.iter().position(|kind| *kind == self).unwrap_or(0) as i32;
        let next = (index + by).rem_euclid(Self::ALL.len() as i32) as usize;
        Self::ALL[next]
    }
}

/// Step 1 of the flow: select and connect.
#[derive(Debug, Clone)]
pub struct ConnectForm {
    /// The row this is about, for the header and for `target`.
    pub device: String,
    pub address: Option<String>,
    pub field: ConnectField,
    pub user: String,
    pub port: String,
    pub identity: IdentityKind,
    pub identity_ref: String,
    pub install_path: String,
    pub data_dir: String,
    pub service: bool,
    /// The inline, actionable error for the field that is wrong.
    pub error: Option<String>,
}

impl ConnectForm {
    fn new(row: &DeviceRow) -> Self {
        Self {
            device: row.name.clone(),
            address: row.address.clone(),
            field: ConnectField::User,
            user: String::new(),
            port: "22".into(),
            identity: IdentityKind::default(),
            identity_ref: String::new(),
            install_path: String::new(),
            data_dir: String::new(),
            service: true,
            error: None,
        }
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            ConnectField::User => Some(&mut self.user),
            ConnectField::Port => Some(&mut self.port),
            ConnectField::IdentityRef => Some(&mut self.identity_ref),
            ConnectField::InstallPath => Some(&mut self.install_path),
            ConnectField::DataDir => Some(&mut self.data_dir),
            _not_text => None,
        }
    }

    pub fn value(&self, field: ConnectField) -> String {
        match field {
            ConnectField::User => self.user.clone(),
            ConnectField::Port => self.port.clone(),
            ConnectField::Identity => self.identity.label().to_string(),
            ConnectField::IdentityRef => self.identity_ref.clone(),
            ConnectField::InstallPath => self.install_path.clone(),
            ConnectField::DataDir => self.data_dir.clone(),
            ConnectField::Service => {
                if self.service {
                    "propose a user service".into()
                } else {
                    "manual start".into()
                }
            }
            ConnectField::Inspect => String::new(),
        }
    }

    fn move_field(&mut self, by: i32) {
        let index = ConnectField::ALL
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as i32;
        let next = (index + by).rem_euclid(ConnectField::ALL.len() as i32) as usize;
        self.field = ConnectField::ALL[next];
    }

    /// The `fleet.deployment.prepare` parameters, or the inline error that stops them.
    ///
    /// The username is required and is never inferred from the network client's owner:
    /// the Tailscale account that owns a device says nothing about which local account
    /// an operator may log into.
    fn params(&self) -> Result<Value, (ConnectField, String)> {
        let user = self.user.trim();
        if user.is_empty() {
            return Err((
                ConnectField::User,
                "An SSH username is required. It is the account on the target, and it is \
                 never guessed from the network client's owner."
                    .into(),
            ));
        }

        let port: u16 = match self.port.trim() {
            "" => 22,
            digits => digits.parse().map_err(|_error| {
                (
                    ConnectField::Port,
                    "The port must be a number from 1 to 65535.".to_string(),
                )
            })?,
        };

        if port == 0 {
            return Err((
                ConnectField::Port,
                "The port must be a number from 1 to 65535.".into(),
            ));
        }

        let Some(address) = self.address.as_deref().filter(|a| !a.is_empty()) else {
            return Err((
                ConnectField::Inspect,
                "This device reported no private address, so there is nothing to connect \
                 to. Refresh, or use the manual fleet commands."
                    .into(),
            ));
        };

        let mut params = json!({
            "target": { "address": address },
            "ssh_user": user,
            "port": port,
            "service": self.service,
        });

        if let Some(kind) = self.identity.wire() {
            let mut identity = json!({ "kind": kind });
            let reference = self.identity_ref.trim();

            if !reference.is_empty() && self.identity.reference_hint().is_some() {
                identity["ref"] = json!(reference);
            }

            params["identity"] = identity;
        }

        for (key, value) in [
            ("install_path", self.install_path.trim()),
            ("data_dir", self.data_dir.trim()),
        ] {
            if !value.is_empty() {
                params[key] = json!(value);
            }
        }

        Ok(params)
    }
}

/// The question asked before one identity inherits another's deployment.
///
/// A resume attaches a new worker connection under the *resuming* identity, so every
/// challenge the worker issues afterwards binds to them: taking over an operation is
/// taking over its credential prompts. The runtime refuses it with `operation_not_yours`
/// unless `takeover: true` is set, and this client only ever sets it from an explicit
/// answer to this question — there is no code path that sends it otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Takeover {
    /// The identity the journal records, or `None` when this runtime could not
    /// establish one — which is a reason for more care, not less.
    pub owner: Option<String>,
    /// Which verb was refused, so the sentence can say what was being attempted.
    pub refused: &'static str,
}

impl Takeover {
    pub fn owner_label(&self) -> String {
        match self.owner.as_deref() {
            Some(owner) => owner.to_string(),
            None => "an identity this runtime could not establish".into(),
        }
    }
}

/// An operation this view is following.
#[derive(Debug)]
pub struct Operation {
    pub id: String,
    /// The row's name, for the header. The plan carries the machine name the worker
    /// resolved; this is what the operator pressed Deploy on.
    pub device: String,
    pub snapshot: Loadable<Snapshot>,
    /// The masked buffer, live only while a password or passphrase challenge is open.
    pub secret: SecretInput,
    /// Which challenge the buffer belongs to, so a buffer typed for one question is
    /// never submitted to the next.
    pub answering: Option<String>,
    /// The state the bell has already rung for, so it rings once per question.
    pub rung_for: Option<String>,
    /// Set while `start`, `authenticate`, `confirm_host` or `cancel` is in flight, so a
    /// second Enter cannot submit the same answer twice.
    pub submitting: bool,
    /// Set when the runtime answered `operation_not_yours`. While this is set the view
    /// shows the takeover question and nothing else can be answered.
    pub takeover: Option<Takeover>,
    /// What a refusal said, in the place the answer would have gone.
    pub error: Option<String>,
}

impl Operation {
    fn new(id: String, device: String) -> Self {
        Self {
            id,
            device,
            snapshot: Loadable::default(),
            secret: SecretInput::default(),
            answering: None,
            rung_for: None,
            submitting: false,
            takeover: None,
            error: None,
        }
    }

    /// The idempotency key for approving this operation's plan.
    ///
    /// Derived rather than random, from the operation and the digest that was reviewed:
    /// a lost answer retried under the same key replays the recorded one, and a plan
    /// that changed produces a different key for a different intention. A fresh random
    /// key per attempt would turn a timeout into `operation_in_progress`, which is the
    /// failure the key exists to prevent.
    fn idempotency_key(&self, digest: &str) -> String {
        format!("{}-{}", self.id, &digest[..digest.len().min(16)])
    }
}

/// The Devices view's whole state.
///
/// Held on the [`App`] rather than inside the overlay so that closing the view and
/// opening it again is free, and so that "leaving never cancels" is structural rather
/// than remembered: there is nothing in here whose drop stops an operation.
#[derive(Debug, Default)]
pub struct DevicesState {
    pub inventory: Loadable<Inventory>,
    pub fallback: Loadable<FleetSubset>,
    pub refusal: Option<Refusal>,
    pub filter: Filter,
    pub query: String,
    /// Whether `/` has opened the search field for typing.
    pub searching: bool,
    pub cursor: usize,
    /// How far the page is scrolled. The list follows its cursor; the longer screens —
    /// a plan under review, a deployment's steps — are paged explicitly.
    pub scroll: usize,
    pub connect: Option<Box<ConnectForm>>,
    pub operation: Option<Box<Operation>>,
    /// A sentence about the last thing that happened, shown in the view rather than in
    /// the global notice line so it is where the operator is looking.
    pub notice: Option<String>,
}

impl DevicesState {
    /// The rows the filter and the query leave, in the order they are drawn.
    pub fn visible<'a>(&self, inventory: &'a Inventory) -> Vec<&'a DeviceRow> {
        let query = self.query.trim().to_ascii_lowercase();

        inventory
            .devices
            .iter()
            .filter(|row| match self.filter {
                Filter::All => true,
                Filter::Fleet => row.in_fleet(),
                Filter::Available => !row.in_fleet(),
            })
            .filter(|row| {
                query.is_empty()
                    || row.name.to_ascii_lowercase().contains(&query)
                    || row
                        .address
                        .as_deref()
                        .is_some_and(|address| address.to_ascii_lowercase().contains(&query))
            })
            .collect()
    }

    /// Everything the operator typed, gone. Called on close and before a fresh open.
    fn forget_secret(&mut self) {
        if let Some(operation) = self.operation.as_mut() {
            operation.secret.clear();
            operation.answering = None;
        }
    }
}

// ----------------------------------------------------------------------- the App side

impl App {
    /// `/devices`, the palette row, the rebindable action, and the Settings link.
    ///
    /// Toggles like the other pages: pressing the verb twice is how an operator checks
    /// something and gets back to what they were doing. Closing clears the typed secret
    /// and cancels nothing.
    pub fn open_devices(&mut self) {
        if matches!(self.overlay, Some(Overlay::Devices)) {
            self.close_devices();
            return;
        }

        self.devices.notice = None;
        // Re-read on every open: the whole point of an inventory is that it is what is
        // there now, and a cached list of machines is a list of machines that were. An
        // operation this view was following is re-read for the same reason — coming back
        // to a deployment is asking what it is doing *now*, not what it was doing when
        // the screen was last closed.
        self.devices.inventory.invalidate();
        self.devices.fallback.invalidate();

        if let Some(operation) = self.devices.operation.as_mut() {
            operation.snapshot.invalidate();
        }

        self.overlay = Some(Overlay::Devices);
        self.poll_devices();
    }

    /// Leaving the view. Never cancels the operation; only forgets what was typed.
    pub fn close_devices(&mut self) {
        self.devices.forget_secret();
        self.overlay = None;
    }

    /// Whether the Devices row is offered at all.
    ///
    /// The method gate only. A runtime that serves `fleet.devices` and refuses this
    /// identity still has a Devices view worth opening — it is where the sentence
    /// explaining the refusal is written.
    pub fn devices_offered(&self) -> bool {
        self.hello.serves("fleet.devices") || self.hello.serves("fleet.status")
    }

    /// The Dashboard's one line about this view, or `None` where there is nothing to say.
    pub fn devices_hint(&self) -> Option<String> {
        if !self.devices_offered() {
            return None;
        }

        Some(format!(
            "devices   {} \u{b7} deploy Ouroboros to another machine",
            self.command_shortcut(Command::Devices)
        ))
    }

    pub(super) fn poll_devices(&mut self) {
        if !matches!(self.overlay, Some(Overlay::Devices)) {
            return;
        }

        let ticks = self.ticks;

        if self.hello.serves("fleet.devices") {
            if self.devices.inventory.due(ticks) {
                self.devices.inventory.started();
                self.issue(Call::new(
                    Tag::Devices(DevicesTag::Inventory),
                    "fleet.devices",
                    json!({}),
                ));
            }
        } else {
            self.devices.refusal = Some(Refusal::CapabilityAbsent);
            self.poll_devices_fallback();
        }

        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.snapshot.due(ticks) {
            operation.snapshot.started();
            let id = operation.id.clone();

            self.issue(Call::new(
                Tag::Devices(DevicesTag::Status {
                    operation: id.clone(),
                }),
                "fleet.deployment.status",
                json!({ "operation_id": id }),
            ));
        }
    }

    fn poll_devices_fallback(&mut self) {
        if !self.hello.serves("fleet.status") {
            return;
        }

        if self.devices.fallback.due(self.ticks) {
            self.devices.fallback.started();
            self.issue(Call::new(
                Tag::Devices(DevicesTag::FleetStatus),
                "fleet.status",
                json!({}),
            ));
        }
    }

    // ----- answers ---------------------------------------------------------------

    pub(super) fn devices_answer(&mut self, tag: DevicesTag, result: Result<Value, ClientError>) {
        let ticks = self.ticks;

        match tag {
            DevicesTag::Inventory => match result {
                Ok(value) => {
                    self.devices.refusal = None;
                    let inventory = Inventory::decode(&value);
                    self.devices.cursor = self
                        .devices
                        .cursor
                        .min(self.devices.visible(&inventory).len().saturating_sub(1));
                    self.devices.inventory.ok(inventory, ticks, INVENTORY_HOLD);
                }
                Err(error) => {
                    self.devices.refusal =
                        Some(devices_refusal(&error, "fleet.devices", &self.hello));
                    self.devices
                        .inventory
                        .failed(error.to_string(), ticks, INVENTORY_HOLD);
                    self.poll_devices_fallback();
                }
            },
            DevicesTag::FleetStatus => match result {
                Ok(value) => {
                    self.devices
                        .fallback
                        .ok(FleetSubset::decode(&value), ticks, INVENTORY_HOLD)
                }
                Err(error) => {
                    self.devices
                        .fallback
                        .failed(error.to_string(), ticks, INVENTORY_HOLD)
                }
            },
            DevicesTag::Prepare => match result {
                Ok(value) => match text(value.get("operation_id")) {
                    Some(id) => {
                        let device = self
                            .devices
                            .connect
                            .as_ref()
                            .map(|form| form.device.clone())
                            .unwrap_or_else(|| "this device".into());

                        self.devices.connect = None;
                        self.devices.operation = Some(Box::new(Operation::new(id, device)));
                        self.devices.notice = None;
                        self.devices.scroll = 0;
                        self.poll_devices();
                    }
                    None => {
                        self.devices_form_error(
                            "The runtime accepted the request and answered no operation id, \
                             so there is nothing to follow.",
                        );
                    }
                },
                Err(error) => {
                    let sentence =
                        devices_error_sentence(&error, "fleet.deployment.prepare", &self.hello);
                    self.devices_form_error(&sentence);
                }
            },
            DevicesTag::Status { operation } => {
                if !self.devices_is_current(&operation) {
                    return;
                }

                match result {
                    Ok(value) => {
                        let snapshot = Snapshot::decode(&value);
                        let waiting = snapshot.waiting();
                        let state = snapshot.state.clone();

                        if let Some(current) = self.devices.operation.as_mut() {
                            // A challenge that is gone takes the buffer typed for it with
                            // it: an answer consumed, expired or superseded must never be
                            // resubmitted to the next question.
                            let open = snapshot.challenge().map(|challenge| challenge.id.clone());
                            if current.answering.is_some() && current.answering != open {
                                current.secret.clear();
                                current.answering = None;
                            }

                            current.snapshot.ok(snapshot, ticks, SNAPSHOT_TICKS);
                        }

                        if waiting {
                            self.devices_ring_for(&state);
                        } else if let Some(current) = self.devices.operation.as_mut() {
                            // Forget what was rung for, so a *second* question in the same
                            // state — a retried password after a working stretch — rings
                            // again rather than being mistaken for the first one.
                            current.rung_for = None;
                        }
                    }
                    Err(error) => {
                        // A foreign owner is not a broken read: it is the takeover
                        // question, asked before anything attaches under this identity.
                        if refusal_reason(&error).as_deref() == Some("operation_not_yours") {
                            self.devices_ask_takeover("fleet.deployment.status");
                            return;
                        }

                        let sentence =
                            devices_error_sentence(&error, "fleet.deployment.status", &self.hello);

                        if let Some(current) = self.devices.operation.as_mut() {
                            current.snapshot.failed(sentence, ticks, SNAPSHOT_TICKS);
                        }
                    }
                }
            }
            DevicesTag::Answer { operation, label } => {
                if !self.devices_is_current(&operation) {
                    return;
                }

                let sentence = match result {
                    Ok(_accepted) => None,
                    Err(error) => Some(devices_error_sentence(&error, label, &self.hello)),
                };

                if let Some(current) = self.devices.operation.as_mut() {
                    current.submitting = false;
                    current.error = sentence;
                    // Whatever happened, read the operation again rather than believing
                    // this client's idea of what the answer did.
                    current.snapshot.invalidate();
                }

                self.poll_devices();
            }
            DevicesTag::Resume { operation } => match result {
                Ok(_resumed) => {
                    self.devices.notice = None;
                    if let Some(current) = self.devices.operation.as_mut() {
                        current.submitting = false;
                        current.takeover = None;
                        current.snapshot.invalidate();
                    }
                    self.poll_devices();
                }
                Err(error) => {
                    if !self.devices_is_current(&operation) {
                        return;
                    }

                    if let Some(current) = self.devices.operation.as_mut() {
                        current.submitting = false;
                    }

                    // The one refusal that is a question rather than an error. A resume
                    // is never retried with `takeover: true` on this client's own
                    // initiative: the operator answers, by name, or nothing happens.
                    if refusal_reason(&error).as_deref() == Some("operation_not_yours") {
                        self.devices_ask_takeover("fleet.deployment.resume");
                        return;
                    }

                    let sentence =
                        devices_error_sentence(&error, "fleet.deployment.resume", &self.hello);

                    if let Some(current) = self.devices.operation.as_mut() {
                        current.error = Some(sentence.clone());
                    }

                    self.devices.notice = Some(sentence);
                }
            },
        }
    }

    /// Put the takeover question on the screen, naming the owner the journal records.
    fn devices_ask_takeover(&mut self, refused: &'static str) {
        let Some(id) = self
            .devices
            .operation
            .as_ref()
            .map(|operation| operation.id.clone())
        else {
            return;
        };

        // The owner from whichever source has it: the snapshot when it was readable, the
        // inventory's operation list otherwise. Never invented.
        let owner = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref())
            .and_then(|snapshot| snapshot.owner.clone())
            .or_else(|| {
                self.devices
                    .inventory
                    .value
                    .as_ref()
                    .and_then(|inventory| {
                        inventory
                            .operations
                            .iter()
                            .find(|summary| summary.operation == id)
                    })
                    .and_then(|summary| summary.owner.clone())
            });

        if let Some(operation) = self.devices.operation.as_mut() {
            operation.secret.clear();
            operation.answering = None;
            operation.error = None;
            operation.takeover = Some(Takeover { owner, refused });
            // Stop asking: every poll would re-refuse until the question is answered.
            operation.snapshot.failed(
                "this operation belongs to another identity".into(),
                self.ticks,
                INVENTORY_HOLD,
            );
        }
    }

    /// The only place `takeover: true` is ever sent, and only from an explicit answer.
    fn devices_take_over(&mut self) {
        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        operation.submitting = true;
        operation.error = None;
        let id = operation.id.clone();

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Resume {
                operation: id.clone(),
            }),
            "fleet.deployment.resume",
            json!({ "operation_id": id, "takeover": true }),
        ));
    }

    fn devices_is_current(&self, operation: &str) -> bool {
        self.devices
            .operation
            .as_ref()
            .is_some_and(|current| current.id == operation)
    }

    fn devices_form_error(&mut self, sentence: &str) {
        if let Some(form) = self.devices.connect.as_mut() {
            form.error = Some(sentence.to_string());
        } else {
            self.devices.notice = Some(sentence.to_string());
        }
    }

    /// One bell per question. The mode decides the channel: in screen-reader mode
    /// [`notify::channel`] resolves `auto` to the bell and rings whether or not this
    /// terminal has focus, which is the whole point of the signal for someone listening.
    fn devices_ring_for(&mut self, state: &str) {
        let already = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.rung_for.clone());

        if already.as_deref() == Some(state) {
            return;
        }

        if let Some(operation) = self.devices.operation.as_mut() {
            operation.rung_for = Some(state.to_string());
        }

        self.notify(notify::Signal::NeedsInput);
    }

    // ----- keys ------------------------------------------------------------------

    pub(super) fn devices_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        if self.devices.operation.is_some() {
            self.devices_operation_key(key);
            return;
        }

        if self.devices.connect.is_some() {
            self.devices_connect_key(key);
            return;
        }

        // The search field owns every printable character while it is open, so `r` and
        // `f` cannot be typed into a query and swallowed as verbs.
        if self.devices.searching {
            match key.code {
                KeyCode::Esc => {
                    self.devices.searching = false;
                    self.devices.query.clear();
                    self.devices.cursor = 0;
                }
                KeyCode::Enter => self.devices.searching = false,
                KeyCode::Backspace => {
                    self.devices.query.pop();
                    self.devices.cursor = 0;
                }
                KeyCode::Char(character) => {
                    self.devices.query.push(character);
                    self.devices.cursor = 0;
                }
                _other => {}
            }
            return;
        }

        let rows = self
            .devices
            .inventory
            .value
            .as_ref()
            .map(|inventory| self.devices.visible(inventory).len())
            .unwrap_or(0);

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.close_devices(),
            KeyCode::Char('r') => {
                self.devices.inventory.invalidate();
                self.devices.fallback.invalidate();
                self.devices.notice = None;
                self.poll_devices();
            }
            KeyCode::Char('/') => {
                self.devices.searching = true;
                self.devices.query.clear();
            }
            KeyCode::Char('f') => {
                self.devices.filter = self.devices.filter.next();
                self.devices.cursor = 0;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.devices.cursor = (self.devices.cursor + 1).min(rows.saturating_sub(1))
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.devices.cursor = self.devices.cursor.saturating_sub(1)
            }
            KeyCode::PageDown => self.devices.scroll = self.devices.scroll.saturating_add(10),
            KeyCode::PageUp => self.devices.scroll = self.devices.scroll.saturating_sub(10),
            // A10: a numbered menu is only a numbered menu if the number selects.
            KeyCode::Char(digit)
                if access::screen_reader()
                    && access::row_for_digit(digit).is_some_and(|row| row < rows) =>
            {
                self.devices.cursor = access::row_for_digit(digit).expect("a digit row");
            }
            KeyCode::Enter => self.devices_activate_row(),
            _other => {}
        }
    }

    /// The primary action of the row under the cursor.
    fn devices_activate_row(&mut self) {
        let Some(inventory) = self.devices.inventory.value.as_ref() else {
            return;
        };

        let rows = self.devices.visible(inventory);
        let Some(row) = rows.get(self.devices.cursor).map(|row| (*row).clone()) else {
            return;
        };

        // An operation already open is what "Continue setup" continues, whichever row
        // the cursor is on: the journal knows the operation, and this view follows it.
        if let Some(open) = inventory.open_operation().cloned() {
            self.devices_continue(&open, &row.name);
            return;
        }

        match row.primary() {
            Primary::Deploy => self.devices_begin_deploy(&row),
            Primary::SetUpThisDevice => {
                self.devices.notice = Some(
                    "Setting up this machine happens on this machine, without SSH to \
                     itself. This runtime's deployment methods take a target and an SSH \
                     account, so run `ouro fleet setup` here first; then this view can \
                     add the others."
                        .into(),
                );
            }
            Primary::View | Primary::Diagnose => {
                self.devices.notice = Some(format!(
                    "{} \u{b7} {} \u{b7} {}. Nothing here has been contacted over SSH; \
                     `ouro fleet doctor` is the bounded remote check.",
                    row.name,
                    row.state_label(),
                    row.presence()
                ));
            }
            Primary::Blocked => {
                self.devices.notice = Some(format!(
                    "{} cannot be deployed to: {}. Press r to look again.",
                    row.name,
                    row.state_label()
                ));
            }
            Primary::Continue => {}
        }
    }

    fn devices_begin_deploy(&mut self, row: &DeviceRow) {
        let host = self
            .devices
            .inventory
            .value
            .as_ref()
            .map(|inventory| inventory.host.clone())
            .unwrap_or_default();

        if !host.deploy {
            self.devices.notice = Some(
                host.blocker()
                    .unwrap_or_else(|| "This runtime cannot deploy from here.".into()),
            );
            return;
        }

        if !self.hello.serves("fleet.deployment.prepare") {
            self.devices.notice = Some(
                "This runtime does not serve fleet.deployment.prepare, so there is no \
                 deployment worker behind a Deploy action here."
                    .into(),
            );
            return;
        }

        if self.hello.scope == "read" {
            self.devices.notice = Some(Refusal::ReadScope.sentence());
            return;
        }

        self.devices.notice = None;
        self.devices.scroll = 0;
        self.devices.connect = Some(Box::new(ConnectForm::new(row)));
    }

    fn devices_continue(&mut self, open: &OperationSummary, device: &str) {
        let mut operation = Operation::new(open.operation.clone(), device.to_string());

        // A journal with no worker behind it needs one before it can be answered. The
        // broker refuses a resume that would be a second worker, so asking is safe.
        if !open.attached && self.hello.serves("fleet.deployment.resume") {
            operation.submitting = true;
            let id = operation.id.clone();
            self.devices.operation = Some(Box::new(operation));

            self.issue(Call::new(
                Tag::Devices(DevicesTag::Resume {
                    operation: id.clone(),
                }),
                "fleet.deployment.resume",
                json!({ "operation_id": id }),
            ));

            return;
        }

        self.devices.operation = Some(Box::new(operation));
        self.poll_devices();
    }

    fn devices_connect_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let Some(form) = self.devices.connect.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                self.devices.connect = None;
                return;
            }
            KeyCode::Tab | KeyCode::Down => form.move_field(1),
            KeyCode::BackTab | KeyCode::Up => form.move_field(-1),
            KeyCode::Left | KeyCode::Right => {
                let by = if key.code == KeyCode::Left { -1 } else { 1 };

                match form.field {
                    ConnectField::Identity => form.identity = form.identity.cycle(by),
                    ConnectField::Service => form.service = !form.service,
                    _not_a_choice => {}
                }
            }
            KeyCode::Backspace => {
                if let Some(text) = form.text_mut() {
                    text.pop();
                }
            }
            KeyCode::Enter => {
                if form.field == ConnectField::Inspect {
                    self.devices_prepare();
                } else {
                    // Enter in a field moves, and never submits: finishing a sentence in
                    // a text box is not a decision to reach out to another machine.
                    form.move_field(1);
                }
                return;
            }
            KeyCode::Char(character) => {
                if let Some(text) = form.text_mut() {
                    text.push(character);
                }
            }
            _other => {}
        }

        if let Some(form) = self.devices.connect.as_mut() {
            form.error = None;
        }
    }

    fn devices_prepare(&mut self) {
        let Some(form) = self.devices.connect.as_mut() else {
            return;
        };

        match form.params() {
            Ok(params) => {
                form.error = None;
                self.issue(Call::new(
                    Tag::Devices(DevicesTag::Prepare),
                    "fleet.deployment.prepare",
                    params,
                ));
            }
            Err((field, sentence)) => {
                form.field = field;
                form.error = Some(sentence);
            }
        }
    }

    fn devices_operation_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        // The takeover question owns the screen while it is open: nothing else can be
        // answered on an operation this identity has not taken over.
        if self
            .devices
            .operation
            .as_ref()
            .is_some_and(|operation| operation.takeover.is_some())
        {
            match key.code {
                KeyCode::Char('t') => self.devices_take_over(),
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.devices.forget_secret();
                    self.devices.operation = None;
                    self.devices.notice = Some(
                        "That setup was left alone. It is still running under the identity \
                         that started it."
                            .into(),
                    );
                    self.devices.inventory.invalidate();
                    self.poll_devices();
                }
                _other => {}
            }
            return;
        }

        let challenge = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref())
            .and_then(Snapshot::challenge)
            .cloned();

        match challenge.as_ref().map(|challenge| challenge.kind.as_str()) {
            Some("password") | Some("passphrase") => {
                self.devices_secret_key(key, challenge.as_ref().expect("a challenge"));
                return;
            }
            Some("host_trust") => {
                self.devices_host_trust_key(key, challenge.as_ref().expect("a challenge"));
                return;
            }
            Some("review") => {
                self.devices_review_key(key, challenge.as_ref().expect("a challenge"));
                return;
            }
            _no_open_question => {}
        }

        let terminal = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref())
            .is_some_and(Snapshot::terminal);

        match key.code {
            // Leaving is leaving. The operation keeps running on the deployment host and
            // the row says so when this comes back.
            KeyCode::Esc => self.close_devices(),
            KeyCode::PageDown | KeyCode::Down => {
                self.devices.scroll = self.devices.scroll.saturating_add(10)
            }
            KeyCode::PageUp | KeyCode::Up => {
                self.devices.scroll = self.devices.scroll.saturating_sub(10)
            }
            KeyCode::Char('b') => {
                self.devices.forget_secret();
                self.devices.operation = None;
                self.devices.inventory.invalidate();
                self.poll_devices();
            }
            KeyCode::Char('c') if !terminal => self.devices_cancel(),
            KeyCode::Char('R') if terminal => self.devices_retry(),
            _other => {}
        }
    }

    fn devices_secret_key(&mut self, key: crossterm::event::KeyEvent, challenge: &Challenge) {
        use crossterm::event::KeyCode;

        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.answering.as_deref() != Some(challenge.id.as_str()) {
            operation.secret.clear();
            operation.answering = Some(challenge.id.clone());
        }

        match key.code {
            // Cancelling the question clears what was typed before it clears the screen.
            KeyCode::Esc => {
                operation.secret.clear();
                operation.answering = None;
                self.close_devices();
            }
            KeyCode::Backspace => operation.secret.pop(),
            KeyCode::Char(character) => operation.secret.push(character),
            KeyCode::Enter => self.devices_submit_secret(challenge),
            _other => {}
        }
    }

    /// The one call in this client that carries a typed secret.
    ///
    /// The buffer is emptied and zeroized before the call is queued, so the App holds no
    /// copy from the moment this returns; what the call carries is a `Zeroizing` string
    /// whose bytes are wiped when the parameter object is built.
    fn devices_submit_secret(&mut self, challenge: &Challenge) {
        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        if operation.secret.is_empty() {
            operation.error = Some("Nothing was typed, so nothing was sent.".into());
            return;
        }

        let secret = operation.secret.take();
        operation.answering = None;
        operation.submitting = true;
        operation.error = None;

        let id = operation.id.clone();
        let params = json!({
            "operation_id": id,
            "challenge": challenge.id,
            "secret": secret.as_str(),
        });

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Answer {
                operation: id,
                label: "fleet.deployment.authenticate",
            }),
            "fleet.deployment.authenticate",
            params,
        ));
    }

    fn devices_host_trust_key(&mut self, key: crossterm::event::KeyEvent, challenge: &Challenge) {
        use crossterm::event::KeyCode;

        match key.code {
            // Trust is typed in full. There is no default answer and no Enter that
            // accepts: a host key is confirmed by an operator who read the fingerprint.
            KeyCode::Char('t') => self.devices_confirm_host(challenge, true),
            KeyCode::Char('n') | KeyCode::Esc => self.devices_confirm_host(challenge, false),
            _other => {}
        }
    }

    fn devices_confirm_host(&mut self, challenge: &Challenge, accept: bool) {
        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        operation.submitting = true;
        operation.error = None;
        let id = operation.id.clone();

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Answer {
                operation: id.clone(),
                label: "fleet.deployment.confirm_host",
            }),
            "fleet.deployment.confirm_host",
            json!({
                "operation_id": id,
                "challenge": challenge.id,
                "accept": accept,
            }),
        ));
    }

    fn devices_review_key(&mut self, key: crossterm::event::KeyEvent, challenge: &Challenge) {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Char('a') => self.devices_approve(challenge),
            KeyCode::Char('c') => self.devices_cancel(),
            KeyCode::Esc => self.close_devices(),
            // The plan is the longest screen in the flow and it is the one that must be
            // read before it is answered, so it pages.
            KeyCode::PageDown | KeyCode::Down => {
                self.devices.scroll = self.devices.scroll.saturating_add(10)
            }
            KeyCode::PageUp | KeyCode::Up => {
                self.devices.scroll = self.devices.scroll.saturating_sub(10)
            }
            _other => {}
        }
    }

    /// Approve exactly the plan that was reviewed.
    ///
    /// The digest travels from the challenge's own metadata, never from anything this
    /// client recomputed: the worker refuses a digest that is not the plan it holds, and
    /// a plan that changed between review and approval comes back `plan_changed` rather
    /// than as a deployment nobody read.
    fn devices_approve(&mut self, challenge: &Challenge) {
        let Some(digest) = challenge.field("plan_digest") else {
            if let Some(operation) = self.devices.operation.as_mut() {
                operation.error = Some(
                    "The review question carries no plan digest, so there is no reviewed \
                     plan to approve."
                        .into(),
                );
            }
            return;
        };

        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        operation.submitting = true;
        operation.error = None;

        let id = operation.id.clone();
        let key = operation.idempotency_key(&digest);

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Answer {
                operation: id.clone(),
                label: "fleet.deployment.start",
            }),
            "fleet.deployment.start",
            json!({
                "operation_id": id,
                "plan_digest": digest,
                "idempotency_key": key,
            }),
        ));
    }

    fn devices_cancel(&mut self) {
        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        operation.secret.clear();
        operation.answering = None;
        operation.submitting = true;
        operation.error = None;
        let id = operation.id.clone();

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Answer {
                operation: id.clone(),
                label: "fleet.deployment.cancel",
            }),
            "fleet.deployment.cancel",
            json!({ "operation_id": id }),
        ));
    }

    /// Retry a failed operation: back to the list, and read it again.
    ///
    /// Not a second `start` under a new key. A failed deployment is resumed or begun
    /// again from a fresh review, and which of the two it is belongs to the journal.
    fn devices_retry(&mut self) {
        self.devices.forget_secret();
        self.devices.operation = None;
        self.devices.inventory.invalidate();
        self.devices.notice =
            Some("Reading the inventory again; a setup that can be continued says so.".into());
        self.poll_devices();
    }
}

// --------------------------------------------------------------------------- rendering

/// Every row of the view, so a test can read it without a terminal.
pub fn devices_lines(app: &App) -> Vec<Line<'static>> {
    let state = &app.devices;
    let mut lines = Vec::new();

    // The permanent header, on every screen of the flow. For a connected TUI the
    // deployment host is the runtime's machine, which may be nothing like this laptop.
    lines.push(Line::from(Span::styled(header_of(app), theme::heading())));
    lines.push(Line::from(Span::styled(
        format!("attached to {}", app.address),
        Style::default().fg(theme::muted()),
    )));
    lines.push(Line::from(""));

    if let Some(operation) = state.operation.as_ref() {
        operation_lines(app, operation, &mut lines);
        return lines;
    }

    if let Some(form) = state.connect.as_deref() {
        connect_lines(app, form, &mut lines);
        return lines;
    }

    inventory_lines(app, &mut lines);
    lines
}

fn header_of(app: &App) -> String {
    app.devices
        .inventory
        .value
        .as_ref()
        .map(|inventory| inventory.host.header())
        .unwrap_or_else(|| "Deploying from the attached runtime's machine".into())
}

fn inventory_lines(app: &App, lines: &mut Vec<Line<'static>>) {
    let state = &app.devices;

    if let Some(refusal) = state.refusal.as_ref() {
        lines.push(Line::from(Span::styled(
            access::speakable(&refusal.sentence()),
            Style::default().fg(theme::warn()),
        )));
        lines.push(Line::from(""));
        fallback_lines(app, lines);
        return;
    }

    let Some(inventory) = state.inventory.value.as_ref() else {
        lines.push(Line::from(Span::styled(
            match state.inventory.error.as_ref() {
                Some(error) => format!("the inventory could not be read: {error}"),
                None => "reading this machine's inventory".to_string(),
            },
            Style::default().fg(theme::muted()),
        )));
        return;
    };

    lines.push(Line::from(vec![
        Span::styled("filter ", theme::label()),
        Span::styled(state.filter.label().to_string(), Style::default()),
        Span::styled("   search ", theme::label()),
        Span::styled(
            if state.query.is_empty() {
                "(none)".to_string()
            } else {
                state.query.clone()
            },
            Style::default(),
        ),
        Span::styled(
            if state.searching { "  typing" } else { "" }.to_string(),
            Style::default().fg(theme::accent()),
        ),
    ]));

    if !inventory.host.deploy {
        if let Some(blocker) = inventory.host.blocker() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                access::speakable(&format!("Deploy is unavailable here. {blocker}")),
                Style::default().fg(theme::warn()),
            )));
        }
    }

    if let Some(open) = inventory.open_operation() {
        lines.push(Line::from(Span::styled(
            format!(
                "a setup is open: {} \u{b7} {} \u{b7} {} \u{b7} started by {}",
                open.operation,
                open.state.as_deref().unwrap_or("state not recorded"),
                if open.attached {
                    "a worker is attached"
                } else {
                    "no worker is attached"
                },
                open.owner
                    .as_deref()
                    .unwrap_or("an identity this runtime could not establish"),
            ),
            Style::default().fg(theme::accent()),
        )));
    }

    let rows = state.visible(inventory);
    let continuing = inventory.open_operation().is_some();

    for (heading, wanted) in [
        ("Fleet devices", true),
        ("Available on this network", false),
    ] {
        let section: Vec<_> = rows.iter().filter(|row| row.in_fleet() == wanted).collect();

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            if wanted {
                heading.to_string()
            } else {
                format!("{heading} \u{2014} {}", inventory.discovery.headline())
            },
            theme::heading(),
        )));

        if section.is_empty() {
            lines.push(Line::from(Span::styled(
                empty_sentence(app, wanted),
                Style::default().fg(theme::muted()),
            )));
            continue;
        }

        for row in section {
            let index = rows
                .iter()
                .position(|candidate| std::ptr::eq(*candidate, *row))
                .unwrap_or(0);
            row_lines(app, row, index, continuing, lines);
        }
    }

    if !inventory.unknown.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "this runtime also reported {}, which this client does not read",
                inventory.unknown.join(", ")
            ),
            Style::default().fg(theme::muted()),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Nothing above was contacted over SSH and no device was inspected; an \
         installation state is only established by a preflight.",
        Style::default().fg(theme::muted()),
    )));

    if let Some(notice) = state.notice.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            access::speakable(notice),
            Style::default().fg(theme::accent()),
        )));
    }
}

/// The distinct empty states the proposal requires, each naming its own repair.
fn empty_sentence(app: &App, fleet_section: bool) -> String {
    if fleet_section {
        return "There is no fleet on this machine yet; `ouro fleet create` starts one."
            .to_string();
    }

    let state = &app.devices;
    let Some(inventory) = state.inventory.value.as_ref() else {
        return "nothing to show".to_string();
    };

    if !state.query.is_empty() || state.filter == Filter::Fleet {
        return "no device here matches the filter and search in force".to_string();
    }

    match inventory.discovery.detail.as_deref() {
        Some(detail) => format!("{} \u{2014} {detail}", inventory.discovery.headline()),
        None => inventory.discovery.headline(),
    }
}

fn row_lines(
    app: &App,
    row: &DeviceRow,
    index: usize,
    continuing: bool,
    lines: &mut Vec<Line<'static>>,
) {
    let selected = app.devices.cursor == index;
    let primary = if continuing {
        Primary::Continue
    } else {
        row.primary()
    };

    let marker = if selected { "> " } else { "  " };
    let name = access::numbered(index, &row.name);

    lines.push(Line::from(vec![
        Span::styled(
            format!("{marker}{name}"),
            if selected {
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            },
        ),
        Span::styled(
            format!("   {}", primary.label()),
            Style::default().fg(theme::action_colour()),
        ),
    ]));

    for (label, value) in [
        ("address", row.address.clone().unwrap_or_else(unknown)),
        ("platform", row.os.clone().unwrap_or_else(unknown)),
        ("network", row.presence()),
        ("ouroboros", row.state_label()),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("      {label:<12}"), theme::label()),
            Span::styled(value, Style::default()),
        ]));
    }

    // Never merged into the row it collides with. A device that adopts a member's name
    // is either a mistake worth fixing or an attempt to be mistaken for it, and listing
    // it as an ordinary peer says neither.
    if let Some(machine) = row.name_conflict.as_ref() {
        lines.push(Line::from(Span::styled(
            format!(
                "      [note] this device calls itself {machine}, which is the name of a \
                 machine in this fleet at a different address. It is not that machine."
            ),
            Style::default().fg(theme::warn()),
        )));
    }
}

fn fallback_lines(app: &App, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled("Fleet devices", theme::heading())));

    let Some(subset) = app.devices.fallback.value.as_ref() else {
        lines.push(Line::from(Span::styled(
            match app.devices.fallback.error.as_ref() {
                Some(error) => format!("fleet.status could not be read either: {error}"),
                None => "reading this machine's fleet membership".to_string(),
            },
            Style::default().fg(theme::muted()),
        )));
        return;
    };

    if let Some(name) = subset.fleet_name.as_ref() {
        lines.push(Line::from(vec![
            Span::styled("fleet       ", theme::label()),
            Span::styled(name.clone(), Style::default()),
        ]));
    }

    if subset.machines.is_empty() {
        lines.push(Line::from(Span::styled(
            "this runtime reports no fleet members",
            Style::default().fg(theme::muted()),
        )));
        return;
    }

    for (index, (machine, state)) in subset.machines.iter().enumerate() {
        lines.push(Line::from(Span::styled(
            access::numbered(index, &format!("{machine} \u{b7} {state}")),
            Style::default(),
        )));
    }
}

fn connect_lines(app: &App, form: &ConnectForm, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(
        format!(
            "Deploy Ouroboros to {} \u{b7} {}",
            form.device,
            form.address.clone().unwrap_or_else(unknown)
        ),
        theme::heading(),
    )));
    lines.push(Line::from(""));

    let mut advanced_drawn = false;

    for (index, field) in ConnectField::ALL.into_iter().enumerate() {
        if field.advanced() && !advanced_drawn {
            advanced_drawn = true;
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Advanced", theme::label())));
        }

        let selected = form.field == field;
        let marker = if selected { "> " } else { "  " };

        if field == ConnectField::Inspect {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("{marker}{}", access::numbered(index, field.label())),
                if selected {
                    Style::default()
                        .fg(theme::accent())
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )));
            continue;
        }

        let value = form.value(field);
        let shown = if value.is_empty() {
            match field {
                ConnectField::User => "(required)".to_string(),
                ConnectField::IdentityRef => form
                    .identity
                    .reference_hint()
                    .map(|hint| format!("({hint})"))
                    .unwrap_or_else(|| "(not used by this method)".into()),
                _optional => "(the target's default)".to_string(),
            }
        } else {
            value
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker}{:<18}", field.label()),
                if selected {
                    theme::label().add_modifier(Modifier::BOLD)
                } else {
                    theme::label()
                },
            ),
            Span::styled(
                shown,
                if selected {
                    Style::default().fg(theme::accent())
                } else {
                    Style::default()
                },
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "The username is the account on the target. It is never taken from the network \
         client's owner, and no password is typed on this screen: a credential is only \
         ever answered to its own question.",
        Style::default().fg(theme::muted()),
    )));

    if let Some(error) = form.error.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }

    let _ = app;
}

fn operation_lines(app: &App, operation: &Operation, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(
        format!(
            "Setting up {} \u{b7} operation {}",
            operation.device, operation.id
        ),
        theme::heading(),
    )));

    if let Some(takeover) = operation.takeover.as_ref() {
        takeover_lines(operation, takeover, lines);
        return;
    }

    let Some(snapshot) = operation.snapshot.value.as_ref() else {
        lines.push(Line::from(Span::styled(
            match operation.snapshot.error.as_ref() {
                Some(error) => format!("this operation could not be read: {error}"),
                None => "reading this operation".to_string(),
            },
            Style::default().fg(theme::muted()),
        )));
        return;
    };

    lines.push(Line::from(vec![
        Span::styled("state       ", theme::label()),
        Span::styled(
            snapshot.state_label(),
            Style::default().fg(if snapshot.succeeded() {
                theme::good()
            } else if snapshot.terminal() {
                theme::bad()
            } else {
                theme::accent()
            }),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("reported by ", theme::label()),
        Span::styled(
            match snapshot.source.as_str() {
                "worker" => "a live worker".to_string(),
                "journal" => "the journal; no worker is attached".to_string(),
                other => other.to_string(),
            },
            Style::default(),
        ),
    ]));

    if let Some(owner) = snapshot.owner.as_ref() {
        lines.push(Line::from(vec![
            Span::styled("started by  ", theme::label()),
            Span::styled(owner.clone(), Style::default()),
        ]));
    }

    steps_lines(snapshot, lines);

    match snapshot.challenge() {
        Some(challenge) if challenge.kind == "host_trust" => host_trust_lines(challenge, lines),
        Some(challenge) if challenge.kind == "review" => review_lines(challenge, lines),
        Some(challenge) if challenge.kind == "password" || challenge.kind == "passphrase" => {
            secret_lines(operation, challenge, lines)
        }
        Some(challenge) => lines.push(Line::from(Span::styled(
            format!(
                "This operation is asking a {} question, which this client does not know \
                 how to answer.",
                challenge.kind
            ),
            Style::default().fg(theme::warn()),
        ))),
        None if snapshot.terminal() => finish_lines(app, snapshot, lines),
        None => {}
    }

    if let Some(error) = operation.error.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }

    let _ = app;
}

/// "Take over this setup?" — never a silent retry.
fn takeover_lines(operation: &Operation, takeover: &Takeover, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Take over this setup?",
        theme::heading(),
    )));
    lines.push(Line::from(vec![
        Span::styled("  started by    ", theme::label()),
        Span::styled(takeover.owner_label(), Style::default()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  operation     ", theme::label()),
        Span::styled(operation.id.clone(), Style::default()),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  refused       ", theme::label()),
        Span::styled(takeover.refused.to_string(), Style::default()),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        access::speakable(
            "This setup belongs to another identity. Taking it over attaches a worker \
             under yours, so every credential this deployment asks for from now on is \
             asked of you \u{2014} you would be inheriting someone else's password prompt. \
             The runtime records who took what from whom.",
        ),
        Style::default().fg(theme::warn()),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        access::numbered(0, "t  Take over this setup"),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "n  Leave it alone"),
        Style::default().fg(theme::action_colour()),
    )));

    if let Some(error) = operation.error.as_ref() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }
}

fn steps_lines(snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    if snapshot.steps.is_empty() {
        return;
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("Steps", theme::label())));

    for step in &snapshot.steps {
        let colour = match step.outcome.as_str() {
            "ok" => theme::good(),
            "failed" => theme::bad(),
            _running => theme::muted(),
        };

        let machine = step
            .machine
            .as_deref()
            .map(|machine| format!("{machine} "))
            .unwrap_or_default();

        lines.push(Line::from(vec![
            Span::styled(format!("  {machine}{:<22}", step.step), Style::default()),
            Span::styled(step.outcome.clone(), Style::default().fg(colour)),
            Span::styled(
                step.detail
                    .as_deref()
                    .map(|detail| format!("  {detail}"))
                    .unwrap_or_default(),
                Style::default().fg(theme::muted()),
            ),
        ]));
    }
}

/// The unknown-host question: algorithm, SHA256 fingerprint, and the address, port and
/// account it belongs to, with an explicit trust or cancel and the line that says to
/// check the fingerprint somewhere that is not this screen.
fn host_trust_lines(challenge: &Challenge, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "This host has not been seen before",
        theme::heading(),
    )));

    for (label, key) in [
        ("address", "address"),
        ("port", "port"),
        ("account", "user"),
        ("algorithm", "algorithm"),
        ("fingerprint", "sha256_fingerprint"),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!("  {label:<14}"), theme::label()),
            Span::styled(
                challenge.field(key).unwrap_or_else(unknown),
                Style::default(),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Verify this fingerprint independently \u{2014} on the device itself, or from \
         however it was provisioned \u{2014} before trusting it. Discovery is not host-key \
         authentication, and a key that matches nothing you can check is a key you cannot \
         trust.",
        Style::default().fg(theme::warn()),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        access::numbered(0, "t  Trust this host and continue"),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "n  Cancel"),
        Style::default().fg(theme::action_colour()),
    )));
}

fn secret_lines(operation: &Operation, challenge: &Challenge, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));

    let (heading, subject) = if challenge.kind == "passphrase" {
        (
            "Passphrase for a private key",
            vec![
                ("key", challenge.field("key_label")),
                ("fingerprint", challenge.field("public_fingerprint")),
            ],
        )
    } else {
        (
            "Password for this connection",
            vec![
                ("account", challenge.field("user")),
                ("target", challenge.field("target")),
                ("port", challenge.field("port")),
                (
                    "attempt",
                    match (challenge.field("attempt"), challenge.field("max_attempts")) {
                        (Some(attempt), Some(max)) => Some(format!("{attempt} of {max}")),
                        (Some(attempt), None) => Some(attempt),
                        _unstated => None,
                    },
                ),
            ],
        )
    };

    lines.push(Line::from(Span::styled(heading, theme::heading())));

    for (label, value) in subject {
        if let Some(value) = value {
            lines.push(Line::from(vec![
                Span::styled(format!("  {label:<14}"), theme::label()),
                Span::styled(value, Style::default()),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  secret        ", theme::label()),
        // One bullet per character. The buffer itself never reaches a `Line`.
        Span::styled(operation.secret.masked(), Style::default()),
        Span::styled(
            if operation.submitting {
                "  sending"
            } else {
                ""
            }
            .to_string(),
            Style::default().fg(theme::accent()),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Typed here and sent once, to this question only. It is not stored, not echoed, \
         not written to a log, and not kept for a reconnection. Enter sends it; Esc \
         clears it and leaves the setup running.",
        Style::default().fg(theme::muted()),
    )));
}

fn review_lines(challenge: &Challenge, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Review this plan before it is applied",
        theme::heading(),
    )));

    // The plan is rendered by the same code the CLI and the dry run print, from the
    // document the worker put in the challenge: two surfaces reading one plan cannot
    // describe it differently.
    match challenge
        .metadata
        .get("plan")
        .cloned()
        .map(serde_json::from_value::<crate::fleet_setup::plan::Plan>)
    {
        Some(Ok(plan)) => {
            for line in plan.render().lines() {
                lines.push(Line::from(Span::styled(line.to_string(), Style::default())));
            }
        }
        _unreadable => {
            lines.push(Line::from(Span::styled(
                "This client could not read the plan this operation is holding, so there \
                 is nothing here to review. Cancel the setup rather than approving a plan \
                 nobody has read.",
                Style::default().fg(theme::bad()),
            )));
            return;
        }
    }

    lines.push(Line::from(vec![
        Span::styled("  digest        ", theme::label()),
        Span::styled(
            challenge.field("plan_digest").unwrap_or_else(unknown),
            Style::default(),
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        access::numbered(0, "a  Deploy Ouroboros \u{2014} applies exactly this plan"),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "c  Cancel setup"),
        Style::default().fg(theme::action_colour()),
    )));
}

fn finish_lines(app: &App, snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));

    if snapshot.succeeded() {
        lines.push(Line::from(Span::styled(
            "This device is set up",
            theme::heading(),
        )));
        // The key this client would actually press, from the resolved map: a rebound
        // chord is the one printed, and `off` reads as "this has no key any more".
        lines.push(Line::from(Span::styled(
            access::numbered(
                0,
                &format!(
                    "Open device \u{2014} {}, the Dashboard's machines panel",
                    app.keymap.label(Action::LeaderTabDashboard)
                ),
            ),
            Style::default().fg(theme::action_colour()),
        )));
        lines.push(Line::from(Span::styled(
            access::numbered(
                1,
                "Configure model \u{2014} /model on a session on that machine",
            ),
            Style::default().fg(theme::action_colour()),
        )));
        lines.push(Line::from(Span::styled(
            access::numbered(
                2,
                "Run test task \u{2014} start a session there and send it one",
            ),
            Style::default().fg(theme::action_colour()),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "A model is configured per machine and a first task is an explicit action; \
             neither happened as part of this setup.",
            Style::default().fg(theme::muted()),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            match snapshot.state.as_str() {
                "cancelled" => "This setup was cancelled",
                "interrupted" => "This setup was interrupted",
                _failed => "This setup did not finish",
            },
            theme::heading(),
        )));

        if let Some(error) = snapshot.last_error.as_ref() {
            lines.push(Line::from(Span::styled(
                access::speakable(error),
                Style::default().fg(theme::bad()),
            )));
        }

        if snapshot.residue.is_empty() {
            lines.push(Line::from(Span::styled(
                "The worker reported no residue. That is what it recorded, not a promise \
                 that nothing reached the target: a credential already delivered stays \
                 delivered.",
                Style::default().fg(theme::muted()),
            )));
        } else {
            lines.push(Line::from(Span::styled("Left behind", theme::label())));
            for item in &snapshot.residue {
                lines.push(Line::from(Span::styled(
                    format!("  {item}"),
                    Style::default().fg(theme::warn()),
                )));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "R  Retry or continue setup      b  back to the device list",
        Style::default().fg(theme::action_colour()),
    )));
}

/// The footer hint, which is different on every screen because the keys are.
pub fn devices_hint_line(app: &App) -> String {
    let state = &app.devices;

    if let Some(operation) = state.operation.as_ref() {
        if operation.takeover.is_some() {
            return "t take over this setup \u{b7} n leave it alone".into();
        }

        let kind = operation
            .snapshot
            .value
            .as_ref()
            .and_then(Snapshot::challenge)
            .map(|challenge| challenge.kind.clone());

        return match kind.as_deref() {
            Some("password") | Some("passphrase") => {
                "type the secret \u{b7} Enter sends it \u{b7} Esc clears it and leaves".into()
            }
            Some("host_trust") => "t trust this host \u{b7} n cancel".into(),
            Some("review") => "a apply this plan \u{b7} c cancel setup \u{b7} Esc leave".into(),
            _following => {
                "c cancel setup \u{b7} R retry \u{b7} b device list \u{b7} Esc leave (nothing is cancelled)"
                    .into()
            }
        };
    }

    if state.connect.is_some() {
        return "Tab/\u{2191}\u{2193} move \u{b7} \u{2190}\u{2192} change \u{b7} Enter on inspect connects \u{b7} Esc back"
            .into();
    }

    if state.searching {
        return "type to search by name or address \u{b7} Enter keeps it \u{b7} Esc clears it"
            .into();
    }

    "\u{2191}\u{2193} select \u{b7} Enter acts \u{b7} r refresh \u{b7} / search \u{b7} f filter \u{b7} Esc close"
        .into()
}

// ------------------------------------------------------------------------- small parts

/// A string field, bounded and stripped of everything a terminal would obey.
///
/// Every value in a `fleet.devices` reply and in a challenge's metadata is text some
/// *other* machine chose: a device's hostname, a worker's prompt label, a remote path.
/// `tui/tests/fixtures/tailscale/hostile-names.json` is a peer list whose names carry
/// ANSI escapes, bidi overrides and a forged four-line device row, and the CLI's own row
/// renderer already answers it with [`human`]. This is the same answer, so a name that
/// cannot forge a row in `ouro fleet devices` cannot forge one here either.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| human(raw, FIELD_COLUMNS))
        .filter(|text| !text.is_empty())
}

/// A sentence rather than a field: longer, and bounded the same way.
fn sentence(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| human(raw, MESSAGE_COLUMNS))
        .filter(|text| !text.is_empty())
}

fn array(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn unknown() -> String {
    "unknown".to_string()
}

/// The snake_case state code, back to the enum that carries its words.
///
/// The codes are `DeviceState`'s serde spellings; `a_state_code_maps_to_the_words_the_cli_prints`
/// below pins this against the serializer, so a variant renamed there is a failing test
/// here rather than a row that silently reads "a state this client does not know".
fn parse_state(code: &str) -> Option<DeviceState> {
    Some(match code {
        "this_device" => DeviceState::ThisDevice,
        "this_device_without_profile" => DeviceState::ThisDeviceWithoutProfile,
        "fleet_member" => DeviceState::FleetMember,
        "fleet_member_not_visible" => DeviceState::FleetMemberNotVisible,
        "discovered_installation_unknown" => DeviceState::DiscoveredInstallationUnknown,
        "peer_offline" => DeviceState::PeerOffline,
        "unsupported_platform" => DeviceState::UnsupportedPlatform,
        "no_usable_ipv4" => DeviceState::NoUsableIpv4,
        _unknown => return None,
    })
}

/// The discovery headline, asked of the type that owns the words.
///
/// Built rather than retyped: `Inventory::headline` is what `ouro fleet devices` prints,
/// and a second copy of those six sentences in this file would be six sentences to keep
/// in step with a file nobody editing them would think to open.
fn headline_for(code: &str, visible_peers: usize) -> String {
    let inventory = crate::fleet_network::Inventory {
        code: match code {
            "client_missing" => DiscoveryCode::ClientMissing,
            "signed_out" => DiscoveryCode::SignedOut,
            "permission_denied" => DiscoveryCode::PermissionDenied,
            "no_visible_peers" => DiscoveryCode::NoVisiblePeers,
            "ok" => DiscoveryCode::Ok,
            _unavailable => DiscoveryCode::Unavailable,
        },
        peers: vec![crate::fleet_network::Device::default(); visible_peers],
        ..crate::fleet_network::Inventory::default()
    };

    inventory.headline()
}

/// Why the inventory is not here, from what the gateway answered.
///
/// `fleet.devices` is a **read**-scope method, so a listener started at read scope
/// passes the scope gate: a `-32003` on this method is the identity rule, which demands
/// an administrator for this one read. That is the distinction the proposal asks both
/// surfaces to draw, and it is derivable rather than guessed.
fn devices_refusal(error: &ClientError, method: &str, hello: &Hello) -> Refusal {
    match error {
        ClientError::Rpc(rpc) => match rpc.code {
            ErrorCode::MethodNotFound => Refusal::CapabilityAbsent,
            ErrorCode::ScopeDenied if method_mutates(method) && hello.scope == "read" => {
                Refusal::ReadScope
            }
            ErrorCode::ScopeDenied => Refusal::NotAdministrator,
            _other => Refusal::Other(rpc.message.clone()),
        },
        other => Refusal::Other(other.to_string()),
    }
}

fn method_mutates(method: &str) -> bool {
    method.starts_with("fleet.deployment.") && method != "fleet.deployment.status"
}

/// The stable reason code a refusal carries.
///
/// `worker_refused` is the broker saying "the machine being deployed to said no", and
/// the fact an operator can act on is inside `worker_reason` — `plan_changed`,
/// `host_key_changed` — so that is what this answers with when it is there.
fn refusal_reason(error: &ClientError) -> Option<String> {
    let ClientError::Rpc(rpc) = error else {
        return None;
    };

    let data = rpc.data.as_ref()?;
    let reason = data.get("reason").and_then(Value::as_str)?;

    if reason == "worker_refused" {
        if let Some(inner) = data.get("worker_reason").and_then(Value::as_str) {
            return Some(inner.to_string());
        }
    }

    Some(reason.to_string())
}

/// One sentence for a refused verb, in the place the answer would have gone.
fn devices_error_sentence(error: &ClientError, method: &str, hello: &Hello) -> String {
    match error {
        ClientError::Rpc(rpc) => {
            let reason = refusal_reason(error);

            match reason.as_deref() {
                Some(reason) => format!("{method} was refused: {}", reason_sentence(reason)),
                None => match rpc.code {
                    ErrorCode::MethodNotFound => {
                        format!("This runtime does not serve {method}.")
                    }
                    ErrorCode::ScopeDenied => devices_refusal(error, method, hello).sentence(),
                    ErrorCode::UpstreamTimeout => format!(
                        "{method} outlived the gateway's ceiling, so its outcome is \
                         unknown here. The deployment host did not stop working; press r \
                         to read what it actually did."
                    ),
                    _other => format!("{method} was refused: {}", rpc.message),
                },
            }
        }
        other => format!("{method} could not be sent: {other}"),
    }
}

/// The broker's stable reason codes, as sentences. An unrecognised code is printed as
/// itself: a runtime that grew a refusal this build predates must still be legible.
fn reason_sentence(reason: &str) -> String {
    match reason {
        "plan_changed" => "the plan changed after it was reviewed, so it was not applied. \
                           Read the new one and approve that."
            .into(),
        "operation_in_progress" => {
            "this operation is already running under a different approval.".into()
        }
        "start_in_flight" => "an approval for this operation is still in flight.".into(),
        "challenge_not_bound" => "this question was asked of a different session, so this \
                                  one cannot answer it."
            .into(),
        "challenge_consumed" => "this question has already been answered once. A challenge \
                                 is consumed when it is sent, so this is not a second guess."
            .into(),
        "challenge_expired" => "this question expired before it was answered.".into(),
        "challenge_kind_mismatch" => "this answer is the wrong shape for the question.".into(),
        "host_key_changed" => "this host's key has changed. That blocks the deployment and \
                               needs a separate, verified repair; it is never accepted here."
            .into(),
        "already_attached" => "a worker is already attached to this operation.".into(),
        "operation_finished" => "this operation has already finished.".into(),
        "operation_state_unknown" => "this operation's record cannot be read, so resuming \
                                      it would be starting a second worker against a \
                                      machine whose state nobody knows."
            .into(),
        "operation_not_yours" => "this operation belongs to another identity, and taking \
                                  it over is a decision to make out loud."
            .into(),
        "no_worker" => "no worker is attached to this operation; read its status, then \
                        continue it."
            .into(),
        "worker_attaching" => "this operation's worker is still being connected to.".into(),
        "worker_unavailable" | "worker_unreachable" => {
            "the deployment worker is no longer reachable from this runtime.".into()
        }
        "worker_timeout" => "the deployment worker did not answer in time.".into(),
        "no_review_pending" => "this operation has no plan waiting for approval.".into(),
        "session_unbound" => "this connection carries no client session, and a deployment \
                              question is answered by the session it was issued to."
            .into(),
        "unknown_operation" => "this runtime has no operation with that id.".into(),
        "devices_busy" => "this runtime is already running as many device inventories as \
                           it allows. Try again in a moment."
            .into(),
        "no_data_dir" => "this runtime serves no durable data directory, so it holds no \
                          deployments."
            .into(),
        "ouro_path_unknown" => "this runtime does not know where its own ouro executable \
                                is, so it cannot run a deployment."
            .into(),
        "journal_unreadable" => "this operation's record on the deployment host could not \
                                 be read."
            .into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_at(scope: &str) -> Hello {
        serde_json::from_value(json!({
            "server": "0.1.0",
            "node": "ouroboros@golden",
            "role": "core",
            "protocol": 1,
            "scope": scope,
            "methods": ["fleet.devices"],
        }))
        .expect("a handshake")
    }

    fn refused(reason: &str, extra: Value) -> ClientError {
        let mut data = json!({ "reason": reason });
        if let Some(object) = extra.as_object() {
            for (key, value) in object {
                data[key] = value.clone();
            }
        }

        ClientError::Rpc(RpcError {
            code: ErrorCode::UpstreamError,
            message: "refused".into(),
            data: Some(data),
        })
    }

    /// Every `DeviceState` the CLI can print is a state this view has words for.
    ///
    /// The fence, both ways: the codes come from the serializer rather than from a list
    /// here, so a variant renamed in `fleet_network` fails this rather than quietly
    /// reaching an operator as "a state this client does not know".
    #[test]
    fn a_state_code_maps_to_the_words_the_cli_prints() {
        for state in [
            DeviceState::ThisDevice,
            DeviceState::ThisDeviceWithoutProfile,
            DeviceState::FleetMember,
            DeviceState::FleetMemberNotVisible,
            DeviceState::DiscoveredInstallationUnknown,
            DeviceState::PeerOffline,
            DeviceState::UnsupportedPlatform,
            DeviceState::NoUsableIpv4,
        ] {
            let code = serde_json::to_value(state)
                .expect("a serializable state")
                .as_str()
                .expect("a string code")
                .to_string();

            assert_eq!(
                parse_state(&code),
                Some(state),
                "{code} does not map back to the state that printed it"
            );

            let row = DeviceRow {
                state: code.clone(),
                ..DeviceRow::default()
            };

            assert_eq!(row.state_label(), state.label());
        }
    }

    /// A code this build has never seen is named, not guessed at.
    #[test]
    fn an_unknown_state_code_is_named_rather_than_invented() {
        let row = DeviceRow {
            state: "quantum_entangled".into(),
            ..DeviceRow::default()
        };

        assert_eq!(row.parsed_state(), None);
        assert!(row.state_label().contains("quantum_entangled"));
        assert_eq!(row.primary(), Primary::Blocked);
    }

    /// The six discovery outcomes read exactly as `ouro fleet devices` prints them.
    #[test]
    fn every_discovery_code_keeps_the_cli_wording() {
        for (code, state) in [
            ("client_missing", DiscoveryCode::ClientMissing),
            ("signed_out", DiscoveryCode::SignedOut),
            ("permission_denied", DiscoveryCode::PermissionDenied),
            ("unavailable", DiscoveryCode::Unavailable),
            ("no_visible_peers", DiscoveryCode::NoVisiblePeers),
        ] {
            let expected = crate::fleet_network::Inventory {
                code: state,
                ..Default::default()
            }
            .headline();

            assert_eq!(headline_for(code, 0), expected, "{code} drifted");
        }

        // `ok` counts, so it is checked with peers in hand.
        let expected = crate::fleet_network::Inventory {
            code: DiscoveryCode::Ok,
            peers: vec![crate::fleet_network::Device::default(); 3],
            ..Default::default()
        }
        .headline();

        assert_eq!(headline_for("ok", 3), expected);
    }

    /// The header the proposal requires, from the host the runtime named.
    #[test]
    fn the_header_names_the_deployment_host_and_its_account() {
        let host = DeploymentHost::decode(&json!({
            "hostname": "studio",
            "user": "ada",
            "os": "darwin",
            "arch": "aarch64-apple-darwin",
            "issuer": true,
            "capabilities": { "deploy": true, "reasons": [] }
        }));

        assert_eq!(host.header(), "Deploying from studio \u{b7} local user ada");
        assert!(host.deploy);
        assert_eq!(host.blocker(), None);
    }

    /// Every blocker the broker can name is a sentence, and an unknown one is still one.
    #[test]
    fn each_deploy_blocker_is_explained_in_words() {
        for reason in [
            "no_ca_key",
            "ouro_path_unknown",
            "no_data_dir",
            "cleartext_web_bind",
        ] {
            let host = DeploymentHost::decode(&json!({
                "hostname": "vps", "user": "root",
                "capabilities": { "deploy": false, "reasons": [reason] }
            }));

            let blocker = host.blocker().expect("a sentence");
            assert!(
                !blocker.contains(reason),
                "{reason} was printed as its code"
            );
            assert!(blocker.ends_with('.'), "{reason} is not a sentence");
        }

        let host = DeploymentHost::decode(&json!({
            "capabilities": { "deploy": false, "reasons": ["a_reason_from_the_future"] }
        }));

        assert!(host
            .blocker()
            .expect("a sentence")
            .contains("a_reason_from_the_future"));
    }

    /// The masked buffer never prints what was typed, however it is formatted.
    #[test]
    fn the_secret_buffer_redacts_itself_in_debug_and_on_screen() {
        let mut secret = SecretInput::default();
        for character in "hunter2-unique".chars() {
            secret.push(character);
        }

        let debug = format!("{secret:?}");
        assert!(
            !debug.contains("hunter2"),
            "Debug printed the secret: {debug}"
        );
        assert!(debug.contains("14 characters"));
        assert!(debug.contains("redacted"));

        assert_eq!(secret.masked(), "\u{2022}".repeat(14));
        assert!(!secret.masked().contains('h'));

        secret.clear();
        assert!(secret.is_empty());
        assert_eq!(secret.masked(), "");
    }

    /// Taking the secret leaves the buffer empty: the one use is the only use.
    #[test]
    fn taking_the_secret_empties_the_buffer() {
        let mut secret = SecretInput::default();
        for character in "one-shot".chars() {
            secret.push(character);
        }

        let taken = secret.take();
        assert_eq!(taken.as_str(), "one-shot");
        assert!(secret.is_empty());
        assert!(!format!("{secret:?}").contains("one-shot"));
    }

    /// A required username is a refusal with a field to go to, not a call.
    #[test]
    fn the_connect_form_refuses_an_empty_username() {
        let form = ConnectForm::new(&DeviceRow {
            name: "vps".into(),
            address: Some("100.64.0.9".into()),
            ..DeviceRow::default()
        });

        let (field, sentence) = form.params().expect_err("an empty username is refused");
        assert_eq!(field, ConnectField::User);
        assert!(sentence.contains("never guessed"));
    }

    /// The parameters carry a reference and never key material, and no secret at all.
    #[test]
    fn the_connect_form_sends_a_reference_and_no_secret() {
        let mut form = ConnectForm::new(&DeviceRow {
            name: "vps".into(),
            address: Some("100.64.0.9".into()),
            ..DeviceRow::default()
        });

        form.user = "deploy".into();
        form.port = "2222".into();
        form.identity = IdentityKind::Key;
        form.identity_ref = "~/.ssh/id_ed25519".into();
        form.data_dir = "/srv/ouro".into();
        form.service = false;

        let params = form.params().expect("a valid form");

        assert_eq!(params["target"]["address"], json!("100.64.0.9"));
        assert_eq!(params["ssh_user"], json!("deploy"));
        assert_eq!(params["port"], json!(2222));
        assert_eq!(params["identity"]["kind"], json!("key"));
        assert_eq!(params["identity"]["ref"], json!("~/.ssh/id_ed25519"));
        assert_eq!(params["data_dir"], json!("/srv/ouro"));
        assert_eq!(params["service"], json!(false));
        assert!(params.get("secret").is_none());
        assert!(params.get("password").is_none());
        assert!(params["install_path"].is_null());
    }

    /// A port that is not a port names the field it is in.
    #[test]
    fn the_connect_form_refuses_a_port_that_is_not_one() {
        let mut form = ConnectForm::new(&DeviceRow {
            address: Some("100.64.0.9".into()),
            ..DeviceRow::default()
        });
        form.user = "deploy".into();
        form.port = "http".into();

        let (field, _sentence) = form.params().expect_err("a bad port is refused");
        assert_eq!(field, ConnectField::Port);
    }

    /// Omitting the identity lets the worker offer what the host has, rather than
    /// sending a kind nobody chose.
    #[test]
    fn an_unchosen_identity_is_omitted_rather_than_guessed() {
        let mut form = ConnectForm::new(&DeviceRow {
            address: Some("100.64.0.9".into()),
            ..DeviceRow::default()
        });
        form.user = "deploy".into();

        let params = form.params().expect("a valid form");
        assert!(params.get("identity").is_none());
        assert_eq!(params["port"], json!(22));
    }

    /// The approval key is a function of the operation and the digest reviewed, so a
    /// retry replays and a different plan is a different intention.
    #[test]
    fn the_idempotency_key_is_stable_for_one_reviewed_plan() {
        let operation = Operation::new("abcdef0123456789".into(), "vps".into());
        let digest = "0123456789abcdef0123456789abcdef";

        assert_eq!(
            operation.idempotency_key(digest),
            operation.idempotency_key(digest)
        );
        assert_ne!(
            operation.idempotency_key(digest),
            operation.idempotency_key("ffffffffffffffff0000")
        );
        assert!(operation
            .idempotency_key(digest)
            .starts_with("abcdef0123456789-"));
    }

    /// The states the worker can be in, each with words and the right disposition.
    #[test]
    fn every_operation_state_has_words_and_a_disposition() {
        for (code, waiting, terminal) in [
            ("inspecting", false, false),
            ("awaiting_host_trust", true, false),
            ("awaiting_auth", true, false),
            ("awaiting_review", true, false),
            ("deploying", false, false),
            ("restarting_host", false, false),
            ("checking_readiness", false, false),
            ("completed", false, true),
            ("interrupted", false, true),
            ("failed", false, true),
            ("cancelled", false, true),
        ] {
            let snapshot = Snapshot {
                state: code.into(),
                ..Snapshot::default()
            };

            assert!(
                !snapshot.state_label().contains("does not know"),
                "{code} has no words"
            );
            assert_eq!(snapshot.waiting(), waiting, "{code} waiting");
            assert_eq!(snapshot.terminal(), terminal, "{code} terminal");
        }

        let unknown = Snapshot {
            state: "warp_drive".into(),
            ..Snapshot::default()
        };
        assert!(unknown.state_label().contains("warp_drive"));
    }

    /// An open challenge makes the operation "waiting" whatever the state field says:
    /// a question on the screen is a question whether or not the state caught up.
    #[test]
    fn an_open_challenge_is_waiting_even_when_the_state_lags() {
        let snapshot = Snapshot::decode(&json!({
            "state": "inspecting",
            "challenges": [{ "challenge": "c1", "kind": "password", "user": "deploy" }]
        }));

        assert!(snapshot.waiting());
        assert_eq!(snapshot.challenge().expect("a challenge").kind, "password");
    }

    /// A refusal on a read method is the identity rule; on a mutation at read scope it
    /// is the scope. Two different sentences for two different facts.
    #[test]
    fn a_refusal_distinguishes_an_absent_capability_from_a_denied_permission() {
        let absent = ClientError::Rpc(RpcError {
            code: ErrorCode::MethodNotFound,
            message: "this build does not serve fleet.devices".into(),
            data: None,
        });
        let denied = ClientError::Rpc(RpcError {
            code: ErrorCode::ScopeDenied,
            message: "refused".into(),
            data: None,
        });

        let operate = hello_at("operate");
        let read = hello_at("read");

        assert_eq!(
            devices_refusal(&absent, "fleet.devices", &operate),
            Refusal::CapabilityAbsent
        );
        assert_eq!(
            devices_refusal(&denied, "fleet.devices", &operate),
            Refusal::NotAdministrator
        );
        assert_eq!(
            devices_refusal(&denied, "fleet.devices", &read),
            Refusal::NotAdministrator,
            "fleet.devices is a read method, so read scope is not the reason"
        );
        assert_eq!(
            devices_refusal(&denied, "fleet.deployment.prepare", &read),
            Refusal::ReadScope
        );

        assert!(Refusal::CapabilityAbsent
            .sentence()
            .contains("does not serve"));
        assert!(Refusal::NotAdministrator
            .sentence()
            .contains("administrator"));
    }

    /// Every stable reason code the broker documents reads as a sentence.
    #[test]
    fn each_broker_reason_reads_as_a_sentence() {
        for reason in [
            "plan_changed",
            "operation_in_progress",
            "start_in_flight",
            "challenge_not_bound",
            "challenge_consumed",
            "challenge_expired",
            "challenge_kind_mismatch",
            "host_key_changed",
            "already_attached",
            "operation_finished",
            "operation_state_unknown",
            "operation_not_yours",
            "no_worker",
            "worker_attaching",
            "worker_unavailable",
            "worker_timeout",
            "no_review_pending",
            "session_unbound",
            "unknown_operation",
            "devices_busy",
            "no_data_dir",
            "ouro_path_unknown",
            "journal_unreadable",
        ] {
            let sentence = reason_sentence(reason);
            assert!(!sentence.contains(reason), "{reason} printed as its code");
            assert!(sentence.len() > 20, "{reason} has no explanation");
        }

        assert_eq!(reason_sentence("from_the_future"), "from_the_future");
    }

    /// The worker's own refusal is what an operator can act on, so it wins over the
    /// broker's `worker_refused` wrapper.
    #[test]
    fn a_worker_refusal_surfaces_the_workers_own_reason() {
        let wrapped = refused("worker_refused", json!({ "worker_reason": "plan_changed" }));
        assert_eq!(refusal_reason(&wrapped).as_deref(), Some("plan_changed"));

        let sentence =
            devices_error_sentence(&wrapped, "fleet.deployment.start", &hello_at("operate"));
        assert!(
            sentence.contains("changed after it was reviewed"),
            "{sentence}"
        );

        // With no inner reason the wrapper is still legible.
        let bare = refused("worker_refused", json!({}));
        assert_eq!(refusal_reason(&bare).as_deref(), Some("worker_refused"));

        assert_eq!(refusal_reason(&ClientError::ConnectionClosed), None);
    }

    /// A changed host key is never an answerable question: it blocks, and the sentence
    /// says a separate verified repair is what fixes it.
    #[test]
    fn a_changed_host_key_reads_as_a_block_not_a_prompt() {
        let sentence = reason_sentence("host_key_changed");

        assert!(sentence.contains("blocks"));
        assert!(sentence.contains("never accepted here"));
    }

    /// The takeover question names the owner, and names the gap when there is none.
    #[test]
    fn the_takeover_question_names_the_owner_or_says_it_cannot() {
        let named = Takeover {
            owner: Some("ada".into()),
            refused: "fleet.deployment.resume",
        };
        assert_eq!(named.owner_label(), "ada");

        let unattributable = Takeover {
            owner: None,
            refused: "fleet.deployment.status",
        };
        assert!(unattributable.owner_label().contains("could not establish"));
    }

    /// `attaching` is a state like the others: words, not waiting, not terminal.
    #[test]
    fn attaching_is_a_state_with_words_of_its_own() {
        let snapshot = Snapshot {
            state: "attaching".into(),
            ..Snapshot::default()
        };

        assert_eq!(
            snapshot.state_label(),
            "connecting to the deployment worker"
        );
        assert!(!snapshot.waiting());
        assert!(!snapshot.terminal());
    }

    /// The owner travels from both places that can carry it.
    #[test]
    fn the_owner_is_read_from_the_snapshot_and_from_the_operation_list() {
        let snapshot = Snapshot::decode(&json!({ "state": "deploying", "owner": "ada" }));
        assert_eq!(snapshot.owner.as_deref(), Some("ada"));

        let summary = OperationSummary::decode(&json!({
            "operation": "abc123", "state": "deploying", "owner": "grace"
        }));
        assert_eq!(summary.owner.as_deref(), Some("grace"));

        // A journal this runtime cannot attribute says so by absence, not by a guess.
        let unattributable = OperationSummary::decode(&json!({
            "operation": "abc123", "state": "deploying", "owner": Value::Null
        }));
        assert_eq!(unattributable.owner, None);
    }

    /// The filter and the search are two independent narrowings of one list.
    #[test]
    fn the_filter_and_the_search_narrow_the_same_list() {
        let inventory = Inventory::decode(&json!({
            "devices": [
                { "name": "studio", "machine": "studio", "state": "this_device",
                  "address": "100.64.0.1" },
                { "name": "vps", "state": "discovered_installation_unknown",
                  "address": "100.64.0.9" },
                { "name": "pi", "state": "peer_offline", "address": "100.64.0.4" }
            ]
        }));

        let mut state = DevicesState::default();
        assert_eq!(state.visible(&inventory).len(), 3);

        state.filter = Filter::Fleet;
        assert_eq!(
            state
                .visible(&inventory)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["studio"]
        );

        state.filter = Filter::Available;
        assert_eq!(state.visible(&inventory).len(), 2);

        // Address search, not only name search.
        state.query = "100.64.0.9".into();
        assert_eq!(
            state
                .visible(&inventory)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["vps"]
        );

        state.filter = Filter::All;
        state.query = "STUD".into();
        assert_eq!(
            state
                .visible(&inventory)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["studio"],
            "search is case-insensitive"
        );
    }

    /// The proposal's observed-state table, row for row.
    #[test]
    fn the_observed_state_table_is_the_proposals() {
        for (code, primary) in [
            ("discovered_installation_unknown", Primary::Deploy),
            ("fleet_member", Primary::View),
            ("this_device", Primary::View),
            ("fleet_member_not_visible", Primary::Diagnose),
            ("this_device_without_profile", Primary::SetUpThisDevice),
            ("peer_offline", Primary::Blocked),
            ("unsupported_platform", Primary::Blocked),
            ("no_usable_ipv4", Primary::Blocked),
        ] {
            let row = DeviceRow {
                state: code.into(),
                ..DeviceRow::default()
            };

            assert_eq!(row.primary(), primary, "{code}");
        }
    }

    /// A roster name conflict is a note on the row, never a merge into it.
    #[test]
    fn a_name_conflict_stays_a_note_on_its_own_row() {
        let inventory = Inventory::decode(&json!({
            "devices": [
                { "name": "studio", "machine": "studio", "state": "this_device" },
                { "name": "studio", "state": "discovered_installation_unknown",
                  "address": "100.64.0.77", "name_conflicts_with_roster": "studio" }
            ]
        }));

        assert_eq!(inventory.devices.len(), 2, "the two rows were merged");
        assert!(inventory.devices[0].in_fleet());
        assert!(!inventory.devices[1].in_fleet());
        assert_eq!(
            inventory.devices[1].name_conflict.as_deref(),
            Some("studio")
        );
    }

    /// An operation that finished is not offered for continuation.
    #[test]
    fn only_an_unfinished_operation_can_be_continued() {
        for (state, open) in [
            ("completed", false),
            ("cancelled", false),
            ("failed", true),
            ("interrupted", true),
            ("deploying", true),
        ] {
            let summary = OperationSummary::decode(&json!({
                "operation": "abc123", "state": state, "attached": false
            }));

            assert_eq!(summary.open(), open, "{state}");
        }

        // A journal nobody can read is unknown, not finished.
        let unreadable = OperationSummary::decode(&json!({
            "operation": "abc123", "readable": false, "reason": "journal_unreadable"
        }));
        assert!(unreadable.open());
        assert!(!unreadable.readable);
    }
}
