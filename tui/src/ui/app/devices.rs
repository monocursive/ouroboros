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
//! Three of those are pinned by tests: the `Debug`, the bullets, and that the buffer is
//! empty after a submit, a cancel or a challenge being replaced. **The zeroizing itself
//! is not.** An in-process test cannot observe that freed heap bytes were overwritten —
//! reading them back is undefined behaviour, and a test that appeared to do it would be
//! testing the allocator. What [`Zeroizing`] buys is that the overwrite happens on drop;
//! what it does not buy, and what this module does not claim, is that no copy of those
//! bytes exists anywhere else. `serde_json` copies the string into the request object,
//! and the spec says as much: minimize and zeroize native buffers where possible, and do
//! not promise perfect erasure.
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

use crate::fleet_network::{human, DeviceState, FIELD_COLUMNS, MESSAGE_COLUMNS};
use crate::fleet_setup::{canonical_json, sha256_hex};

use super::super::access;
use super::super::theme;
use super::*;

use super::devices_catalogue as catalogue;
pub use catalogue::{
    blocker_known, blocker_sentence, operation_state, operation_state_known, reason_known,
    reason_sentence, BLOCKER_CODES, OPERATION_STATES, REASON_CODES,
};

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

    /// The one quiet line the target design puts under the title, and again as the
    /// caption inside every form: whose machine actually does the work, and as whom.
    ///
    /// It replaced a boxed three-line panel that said the same thing twice. The fact is
    /// the same one the panel existed for — a credential typed into the wrong host's
    /// prompt — and it stays on every screen of the flow.
    pub fn actions_line(&self) -> String {
        format!("Actions run on {} as {}.", self.hostname, self.user)
    }

    /// What this machine is called on its own row: the host OS gives the noun.
    ///
    /// `darwin` is what `fleet.devices`'s `host.os` reports for a Mac. Anything else —
    /// Linux, or an OS this build has never heard of — is "This machine", which is true
    /// of every one of them and claims nothing about which.
    pub fn self_label(&self) -> &'static str {
        match self.os.as_deref() {
            Some("darwin") | Some("macos") => "This Mac",
            _other => "This machine",
        }
    }

    /// The reasons a *local first setup* is blocked.
    ///
    /// Every blocker a deployment has except one: `no_ca_key`. A machine with no fleet
    /// certificate authority is exactly the machine "Set up this Mac" exists for, so
    /// gating first setup on holding a CA key means the action can never work on the one
    /// kind of machine that needs it — which is what a live run found it doing. Read
    /// scope, a non-administrator, an absent method, a cleartext web bind, an unknown
    /// `ouro` path and a missing data directory all still block it: those are reasons
    /// this runtime cannot run *any* deployment, including one against itself.
    ///
    /// `dev_runtime` is the other way round: it blocks *only* setup. A Mix dev runtime
    /// can drive a deployment onto another machine perfectly well; what it cannot do is
    /// be the thing that gets installed here.
    pub fn setup_reasons(&self) -> Vec<String> {
        self.reasons
            .iter()
            .filter(|reason| reason.as_str() != "no_ca_key")
            .cloned()
            .collect()
    }

    /// The reasons an *admission* is blocked: every blocker except the dev-runtime one,
    /// which is about installing this runtime rather than about reaching another machine.
    pub fn add_reasons(&self) -> Vec<String> {
        self.reasons
            .iter()
            .filter(|reason| reason.as_str() != "dev_runtime")
            .cloned()
            .collect()
    }

    /// The first reason a local first setup is unavailable, in words.
    ///
    /// Its own list, not [`DeploymentHost::blocker`]'s: the two filter opposite codes,
    /// and routing this through that one made `dev_runtime` — the one blocker that is
    /// *only* about setting this machine up — the one blocker setup never mentioned.
    pub fn setup_blocker(&self) -> Option<String> {
        self.setup_reasons()
            .first()
            .map(|reason| blocker_sentence(reason))
    }

    /// The first reason Add to fleet is unavailable, in words.
    ///
    /// The codes are the broker's and stay in the data; these are the sentences. An
    /// unrecognised code is named rather than swallowed, because a runtime that grew a
    /// new blocker must not read as no blocker at all.
    pub fn blocker(&self) -> Option<String> {
        self.add_reasons()
            .first()
            .map(|reason| blocker_sentence(reason))
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
    /// Count-based rather than by constructing a [`crate::fleet_network::Inventory`]:
    /// that type's `headline` counts `peers.len()`, and feeding it a hostile
    /// `visible_peers` used to mean allocating that many `Device`s. The wording is
    /// pinned against the CLI in `every_discovery_code_keeps_the_cli_wording`.
    pub fn headline(&self) -> String {
        headline_for(&self.code, self.visible_peers)
    }

    /// Whether the client answered with a peer list at all.
    pub fn answered(&self) -> bool {
        matches!(self.code.as_str(), "ok" | "no_visible_peers")
    }

    /// The one-line notice a failed discovery gets, quoting the client's own words.
    ///
    /// `None` when discovery worked. The `detail` is the network client's first line,
    /// carried through by the contract in §5.5 precisely so this sentence can quote it
    /// rather than guess — the old wording claimed *this build of Ouroboros may be older
    /// than the client*, which was a guess, and a wrong one.
    pub fn notice(&self) -> Option<String> {
        if self.answered() {
            return None;
        }

        let repair = "Devices already in the fleet are still listed.";

        Some(match self.detail.as_deref() {
            Some(detail) => format!(
                "Tailscale did not answer from this runtime: \u{201c}{detail}\u{201d}. {repair}"
            ),
            None => format!("{}. {repair}", self.headline()),
        })
    }
}

/// One row of the inventory, from `fleet.devices`'s `devices`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRow {
    pub name: String,
    pub machine: Option<String>,
    /// The name this device would take in the roster, chosen by the runtime: the roster
    /// name for a member, otherwise the display name folded to a valid machine name, or
    /// `null` when nothing valid remains.
    ///
    /// The *only* source the name field is ever pre-filled from. `name` is a display
    /// name — "Monocursive's MacBook Pro", or the `this device` a failed discovery used
    /// to invent — and neither is a machine name, which is what put an invalid name into
    /// the form on both surfaces (finding 3).
    pub suggested_machine: Option<String>,
    pub os: Option<String>,
    pub address: Option<String>,
    pub online: Option<bool>,
    pub last_seen: Option<String>,
    /// The snake_case state code. The words are [`DeviceRow::state_label`].
    pub state: String,
    /// Whether *this runtime* is connected to that member's runtime. A different
    /// question from `online`, which is what the network client can see, and the two
    /// disagreeing is a real and useful thing to show rather than a contradiction to
    /// resolve. `None` for every row that is not a member: discovery sees devices that
    /// have never been in a fleet, and this runtime knows nothing about those.
    pub connected: Option<bool>,
    pub compatible: Option<bool>,
    pub runtime_running: Option<bool>,
    /// When the runtime last had an answer from that member.
    pub last_probe: Option<String>,
    /// The network client's path observation (`direct` / `relayed` / `unknown`), when it
    /// reported one. Kept as the string the runtime sent: this view does not re-derive it.
    pub path: Option<String>,
    pub name_conflict: Option<String>,
}

impl DeviceRow {
    fn decode(value: &Value) -> Self {
        Self {
            name: text(value.get("name")).unwrap_or_else(|| "unnamed device".into()),
            machine: text(value.get("machine")),
            suggested_machine: text(value.get("suggested_machine")),
            os: text(value.get("os")),
            address: text(value.get("address")),
            online: value.get("online").and_then(Value::as_bool),
            last_seen: text(value.get("last_seen")),
            state: text(value.get("state")).unwrap_or_default(),
            connected: value.get("connected").and_then(Value::as_bool),
            compatible: value.get("compatible").and_then(Value::as_bool),
            runtime_running: value.get("runtime_running").and_then(Value::as_bool),
            last_probe: text(value.get("last_probe")),
            path: text(value.get("path")),
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
        if let Some(state) = self.parsed_state() {
            return state.label().to_string();
        }

        match self.state.as_str() {
            // The broker's own promotion: a member whose runtime this one is connected to
            // says so in its own state rather than being left on discovery's word, which
            // called it "not visible on this network" whenever the network client could
            // not see it. `DeviceState` has no variant for this — it is a fact about the
            // cluster, and that enum is about the network — so the words live here, in the
            // same house style as the ones it does own.
            "fleet_member_connected" => "connected now".into(),
            // Never a blank row. A state this client has no words for is still a device,
            // and a row whose Ouroboros column is empty says nothing at all — including
            // nothing about the fact that something is there this build cannot read.
            "" => "this runtime reported no state for this device".into(),
            other => format!("{other} (a state this client does not know)"),
        }
    }

    /// The live facts, as a line — or `None` when this runtime knows none of them.
    ///
    /// Separate from [`DeviceRow::presence`] on purpose. That line is the *network's*
    /// answer, from `online` and `last_seen`; this one is the *runtime's*, from the
    /// cluster. A machine reachable over BEAM but invisible to the network client is a
    /// different problem from one that is neither, and one line carrying both would make
    /// those two look like the same row.
    pub fn runtime_facts(&self) -> Option<String> {
        let mut facts = Vec::new();

        if let Some(connected) = self.connected {
            facts.push(if connected {
                "runtime connected".to_string()
            } else {
                "runtime not connected".to_string()
            });
        }

        if let Some(compatible) = self.compatible {
            facts.push(if compatible {
                "compatible build".to_string()
            } else {
                "incompatible build".to_string()
            });
        }

        if let Some(running) = self.runtime_running {
            facts.push(if running {
                "runtime running".to_string()
            } else {
                "runtime stopped".to_string()
            });
        }

        if let Some(probe) = self.last_probe.as_deref() {
            facts.push(format!("probed {probe}"));
        }

        (!facts.is_empty()).then(|| facts.join(" \u{b7} "))
    }

    /// Whether this row belongs under "Fleet devices" rather than "Available on this
    /// network". The same split `render_devices` makes for the CLI.
    pub fn in_fleet(&self) -> bool {
        self.machine.is_some()
            || self.parsed_state() == Some(DeviceState::ThisDeviceWithoutProfile)
            || self.state == "fleet_member_connected"
    }

    /// Network presence with its observation time, in the CLI's words. The details
    /// panel's line: the *exact* time, never abbreviated.
    pub fn presence(&self) -> String {
        match (self.online, self.last_seen.as_deref()) {
            (Some(true), _connected) => "online now".into(),
            (Some(false), Some(seen)) => format!("offline, last seen {seen}"),
            (Some(false), None) => "offline".into(),
            (None, Some(seen)) => format!("unknown, last seen {seen}"),
            (None, None) => "unknown".into(),
        }
    }

    /// Presence as the *row* carries it: a dot, a word, and a relative time.
    ///
    /// Never an ISO timestamp — a row that reads `2026-09-18T12:50:48.319067Z` is a row
    /// nobody can scan. The exact time is one line down, in the details panel.
    pub fn presence_short(&self) -> String {
        match (self.online, self.last_seen.as_deref()) {
            (Some(true), _connected) => "\u{25cf} online".into(),
            (Some(false), Some(seen)) => match relative_time(seen) {
                Some(ago) => format!("\u{25cb} offline, seen {ago}"),
                None => "\u{25cb} offline".into(),
            },
            (Some(false), None) => "\u{25cb} offline".into(),
            (None, Some(seen)) => match relative_time(seen) {
                Some(ago) => format!("\u{25cb} last seen {ago}"),
                None => "\u{25cb} presence unknown".into(),
            },
            (None, None) => "\u{25cb} presence unknown".into(),
        }
    }

    /// The Ouroboros column: one of the nine phrases §5.1 lists, or — for a state code
    /// this build has never seen — that code, named as one.
    ///
    /// The operation phrases (`setting up…`, `waiting for you`, `setup failed`, `set up
    /// just now`) are not derivable from the device's state at all; they come from the
    /// operation on its row, so [`Inventory::ouroboros_word`] is what the list calls.
    pub fn ouroboros_word(&self) -> String {
        match self.parsed_state() {
            Some(DeviceState::ThisDevice) | Some(DeviceState::FleetMember) => {
                match self.connected {
                    Some(false) => "in the fleet \u{b7} not connected".into(),
                    _connected_or_unknown => "in the fleet".into(),
                }
            }
            Some(DeviceState::FleetMemberNotVisible) => "in the fleet \u{b7} not connected".into(),
            Some(DeviceState::ThisDeviceWithoutProfile)
            | Some(DeviceState::DiscoveredInstallationUnknown) => "not set up".into(),
            Some(DeviceState::PeerOffline) => "offline".into(),
            Some(DeviceState::UnsupportedPlatform) | Some(DeviceState::NoUsableIpv4) => {
                "can't run Ouroboros".into()
            }
            // The broker's own promotion: a member whose runtime this one is connected to.
            None if self.state == "fleet_member_connected" => "in the fleet".into(),
            // Never a blank column, and never invented words. A state this build cannot
            // reason about is still a device, and saying so is the honest column.
            None => self.state_label(),
        }
    }

    /// The reason there is no action on this row, for the details panel. `None` when
    /// there is one.
    pub fn no_action_reason(&self) -> Option<String> {
        match self.parsed_state() {
            Some(DeviceState::PeerOffline) => Some(
                "The network client reports this device offline, so there is nothing to \
                 reach. Offline is not powered off."
                    .into(),
            ),
            Some(DeviceState::UnsupportedPlatform) => Some(
                "No Ouroboros release targets this platform, so there is nothing to \
                 install on it."
                    .into(),
            ),
            Some(DeviceState::NoUsableIpv4) => Some(
                "This device reports no private IPv4 address the fleet could use, so \
                 there is no address to connect to."
                    .into(),
            ),
            None if self.state != "fleet_member_connected" => Some(format!(
                "This runtime reports the state {}, which this client has no action for.",
                self.state_label()
            )),
            _actionable => None,
        }
    }

    /// The one thing an operator can do with this row, before any open operation on it
    /// is taken into account. [`Inventory::primary`] is what the list calls.
    pub fn primary(&self) -> Primary {
        match self.parsed_state() {
            Some(DeviceState::DiscoveredInstallationUnknown) => Primary::Add,
            Some(DeviceState::ThisDevice)
            | Some(DeviceState::FleetMember)
            | Some(DeviceState::FleetMemberNotVisible) => Primary::Open,
            Some(DeviceState::ThisDeviceWithoutProfile) => Primary::SetUp,
            Some(DeviceState::PeerOffline)
            | Some(DeviceState::UnsupportedPlatform)
            | Some(DeviceState::NoUsableIpv4) => Primary::None,
            // A member this runtime is talking to is a member: the same action as any
            // other, and never the "nothing to do here" an unrecognised code would get.
            None if self.state == "fleet_member_connected" => Primary::Open,
            None => Primary::None,
        }
    }

    /// Whether `x` offers to take this device out of the fleet: only a roster member,
    /// and never this machine, which leaves its own fleet by other means.
    pub fn removable(&self) -> bool {
        self.machine.is_some()
            && !matches!(
                self.parsed_state(),
                Some(DeviceState::ThisDevice) | Some(DeviceState::ThisDeviceWithoutProfile)
            )
    }
}

/// The one thing a row offers, as §5.1's action column names it. `None` draws nothing —
/// a device that cannot be acted on shows no button, and the reason is in its details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Primary {
    /// This machine, with no fleet yet.
    SetUp,
    /// A device on the network that is not in the fleet.
    Add,
    /// A member: the Dashboard's machines panel is where its sessions are.
    Open,
    /// An operation that is running or waiting on a person.
    Continue,
    /// An operation that failed.
    Retry,
    None,
}

impl Primary {
    /// The button's words. `self_label` is the host's own noun, because "Set up this
    /// Mac" on a Linux box is a sentence about a machine that is not there.
    pub fn label(self, self_label: &str) -> String {
        match self {
            Self::SetUp => format!("Set up {}", lowercase_first(self_label)),
            Self::Add => "Add to fleet".into(),
            Self::Open => "Open".into(),
            Self::Continue => "Continue".into(),
            Self::Retry => "Retry".into(),
            Self::None => "\u{2014}".into(),
        }
    }
}

/// "This Mac" as it reads mid-sentence.
fn lowercase_first(label: &str) -> String {
    let mut characters = label.chars();

    match characters.next() {
        Some(first) => format!("{}{}", first.to_lowercase(), characters.as_str()),
        None => String::new(),
    }
}

/// One deployment operation this data directory holds a journal for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationSummary {
    pub operation: String,
    pub state: Option<String>,
    pub kind: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// The identity that started it (seam S5), or `None` on a journal this runtime
    /// cannot attribute. Shown, because continuing somebody else's setup inherits their
    /// credential prompts and must never happen quietly.
    pub owner: Option<String>,
    /// Which device the operation is about. `None` on a journal too old or too broken to
    /// say — and an operation whose target is unknown is never silently attached to a row.
    pub target: Option<OperationTarget>,
    pub attached: bool,
    pub readable: bool,
}

/// What a row offers for an operation that has not finished cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resumption {
    /// Still going, or waiting on a person: pick it up where it is.
    Continue,
    /// It failed. Resuming re-inspects and re-reviews, so this is a retry rather than a
    /// second attempt at applying a plan nobody looked at again.
    Retry,
    /// It was cancelled, which the broker will not resume. A fresh operation, reviewed
    /// from the beginning.
    DeployAgain,
    /// Finished. The row goes back to describing the device.
    None,
}

/// Enough of an operation's target to put it on the row it belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationTarget {
    pub machine: Option<String>,
    pub address: Option<String>,
    pub ssh_user: Option<String>,
    pub port: Option<u64>,
}

impl OperationTarget {
    fn decode(value: &Value) -> Option<Self> {
        let target = value.as_object()?;
        let decoded = Self {
            machine: text(target.get("machine").map(|v| v as &Value)),
            address: text(target.get("address").map(|v| v as &Value)),
            ssh_user: text(target.get("ssh_user").map(|v| v as &Value)),
            port: target.get("port").and_then(Value::as_u64),
        };

        // A target naming neither a machine nor an address identifies no row.
        (decoded.machine.is_some() || decoded.address.is_some()).then_some(decoded)
    }

    /// Whether this target is the device in `row`.
    ///
    /// The address first, because that is what the worker actually talks to and what a
    /// roster name can be made to collide with; the machine name only when both sides
    /// have one.
    pub fn is(&self, row: &DeviceRow) -> bool {
        if let (Some(mine), Some(theirs)) = (self.address.as_deref(), row.address.as_deref()) {
            if mine == theirs {
                return true;
            }
        }

        match (self.machine.as_deref(), row.machine.as_deref()) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _unnamed => false,
        }
    }

    /// The device this operation is about, for a header.
    pub fn label(&self) -> String {
        self.machine
            .clone()
            .or_else(|| self.address.clone())
            .unwrap_or_else(|| "a device this runtime could not name".into())
    }
}

impl OperationSummary {
    fn decode(value: &Value) -> Self {
        Self {
            operation: text(value.get("operation")).unwrap_or_default(),
            state: text(value.get("state")),
            kind: text(value.get("kind")),
            created_at: text(value.get("created_at")),
            updated_at: text(value.get("updated_at")),
            owner: text(value.get("owner")),
            target: value.get("target").and_then(OperationTarget::decode),
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
    /// What an operator can do about this operation from its device's row.
    ///
    /// The three answers are different verbs on purpose. The spec's step 5 asks a failure
    /// to show its completed steps, its cause, and **Retry** — and a retry here is a
    /// resume, which re-inspects and re-reviews, so a stale failure cannot apply anything
    /// nobody has read. A cancelled operation is not resumable at all (the broker's own
    /// terminal set is `completed` and `cancelled`, answering `operation_finished`), so
    /// its verb is a fresh deployment rather than a call that would be refused.
    pub fn resumption(&self) -> Resumption {
        match self.state.as_deref() {
            Some("completed") => Resumption::None,
            Some("cancelled") => Resumption::DeployAgain,
            Some("failed") => Resumption::Retry,
            _still_going => Resumption::Continue,
        }
    }

    /// Whether this operation is still something the row should say anything about.
    pub fn open(&self) -> bool {
        self.resumption() != Resumption::None
    }
}

/// The reviewed plan, as *this view* reads it.
///
/// Deliberately not `fleet_setup::plan::Plan`. That type is the local one: its
/// `Deserialize` accepts whatever a plan document says and its `render` is written for a
/// plan this machine built, so it byte-slices `release.sha256` (`plan.rs`, the `install`
/// line) and prints every field raw. A plan arriving over the wire is a document a
/// *worker on another machine* wrote — and in the failure the broker is built around, one
/// this runtime is meant to be suspicious of. Handing it to a renderer written for local
/// data is how a multibyte `sha256` panics the client and how a `machine` with newlines
/// forges an aligned row saying the grants are routine.
///
/// So the document is decoded here, into fields that are already scrubbed and bounded,
/// with the digests held to hex. What cannot be decoded is refused rather than drawn.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanView {
    pub kind: String,
    pub host_name: String,
    pub host_user: String,
    pub host_issuer: bool,
    pub machine: String,
    pub address: String,
    pub port: Option<u64>,
    pub ssh_user: Option<String>,
    pub identity: Option<String>,
    pub install_path: Option<String>,
    pub data_dir: Option<String>,
    pub host_fingerprint: Option<String>,
    pub node: Option<String>,
    pub release: Option<PlanRelease>,
    pub service: Option<String>,
    pub members: Vec<PlanMember>,
    pub restart: Option<String>,
    pub grants: Vec<String>,
    /// The sha256 of the canonical JSON of the document that produced this view — this
    /// client's own arithmetic, never the challenge's claim about it.
    pub digest: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanRelease {
    pub version: String,
    pub target: String,
    /// Held to 64 lowercase hex: a checksum is not free text, and the one place this is
    /// abbreviated for the screen is safe to cut only because of that.
    pub sha256: String,
    pub official_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanMember {
    pub machine: String,
    pub host: String,
    pub reached_by: String,
    pub change: String,
}

/// A sha256 as this client will accept one: exactly 64 lowercase hex characters.
///
/// Anything else is not a digest. Returning `None` rather than a lenient normalisation is
/// the point — a "digest" this client cannot recognise is a plan it must not approve, and
/// a string it must not slice.
pub fn hex_digest(raw: &str) -> Option<String> {
    let trimmed = raw.trim();

    (trimmed.len() == 64
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| trimmed.to_string())
}

impl PlanView {
    /// Decodes one plan document, or `None` when it is not one this client can read.
    pub fn decode(document: &Value) -> Option<Self> {
        let target = document.get("target")?;
        let host = document.get("deployment_host")?;

        // The digest is computed from the document as it arrived, before any of it is
        // scrubbed for the screen: the worker's arithmetic is over the bytes it sent.
        let digest = hex_digest(&sha256_hex(canonical_json(document).as_bytes()))?;

        let release = match document.get("release") {
            None | Some(Value::Null) => None,
            Some(release) => Some(PlanRelease {
                version: text(release.get("version")).unwrap_or_else(unknown),
                target: text(release.get("target")).unwrap_or_else(unknown),
                // A release whose checksum is not a checksum is not a release this client
                // will draw an `install` line for.
                sha256: release
                    .get("sha256")
                    .and_then(Value::as_str)
                    .and_then(hex_digest)?,
                official_origin: release
                    .get("official_origin")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }),
        };

        Some(Self {
            kind: text(document.get("kind")).unwrap_or_else(|| "add".into()),
            host_name: text(host.get("hostname")).unwrap_or_else(unknown),
            host_user: text(host.get("user")).unwrap_or_else(unknown),
            host_issuer: host.get("issuer").and_then(Value::as_bool).unwrap_or(false),
            machine: text(target.get("machine")).unwrap_or_else(unknown),
            address: text(target.get("address")).unwrap_or_else(unknown),
            port: target.get("port").and_then(Value::as_u64),
            ssh_user: text(target.get("ssh_user")),
            identity: text(target.get("identity")),
            install_path: text(target.get("install_path")),
            data_dir: text(target.get("data_dir")),
            host_fingerprint: text(target.get("host_fingerprint")),
            node: text(target.get("node")),
            release,
            service: text(document.get("service")),
            members: array(document.get("members"))
                .iter()
                .map(|member| PlanMember {
                    machine: text(member.get("machine")).unwrap_or_else(unknown),
                    host: text(member.get("host")).unwrap_or_else(unknown),
                    reached_by: text(member.get("reached_by")).unwrap_or_else(unknown),
                    change: sentence(member.get("change")).unwrap_or_else(unknown),
                })
                .collect(),
            restart: sentence(document.get("restart")),
            grants: array(document.get("grants"))
                .iter()
                .filter_map(|grant| sentence(Some(grant)))
                .collect(),
            digest,
        })
    }

    /// The caption under the heading: the same quiet line the rest of the flow carries,
    /// with the authority note that only a plan can state.
    pub fn header(&self) -> String {
        let authority = match (self.kind.as_str(), self.host_issuer) {
            (_, true) => "",
            ("setup", false) => " This machine will hold the fleet's CA key.",
            (_, false) => " This machine does not hold the fleet's CA key.",
        };

        format!(
            "Runs on {} as {}.{authority}",
            self.host_name, self.host_user
        )
    }

    /// §5.2 step 3: the five plain lines an operator reads before approving.
    ///
    /// Sentences rather than a field table. The table was every decoded field, one per
    /// row, which is a specification; these are the four things that will happen to two
    /// machines and the one sentence about trust.
    pub fn review_lines(&self) -> Vec<String> {
        if self.kind == "leave" {
            return vec![
                format!(
                    "Stop Ouroboros on {} and disable its start at login.",
                    self.machine
                ),
                format!("Retire {}'s credentials.", self.machine),
                self.roster_sentence(),
                "Its sessions and data stay on that machine.".to_string(),
                self.trust_sentence(),
            ];
        }

        let install = match self.release.as_ref() {
            // Safe to cut at sixteen because `decode` refused anything that is not 64
            // lowercase hex: the characters are one byte each.
            Some(release) => format!(
                "Install ouro {} ({}) to {} \u{b7} sha256 {}{}",
                release.version,
                release.target,
                self.install_path.as_deref().unwrap_or("the default path"),
                &release.sha256[..16],
                if release.official_origin {
                    ""
                } else {
                    " \u{b7} not the official release"
                }
            ),
            None => format!("{} already has ouro; nothing is installed.", self.machine),
        };

        let join = match self.kind.as_str() {
            "setup" => format!("Start a fleet on this machine as {}.", self.machine),
            _add => format!("Join the fleet as {}.", self.machine),
        };

        let start = match self.service.as_deref() {
            Some("managed") => {
                "Start at login as a user service, not a pre-login daemon.".to_string()
            }
            Some("manual") => "Start manually; no service is installed.".to_string(),
            Some(other) => format!("Start: {other}."),
            None => "The plan does not say how it starts.".to_string(),
        };

        vec![
            install,
            join,
            start,
            self.roster_sentence(),
            self.trust_sentence(),
        ]
    }

    fn roster_sentence(&self) -> String {
        match self.members.len() {
            0 => "No other machine's roster changes.".into(),
            count => format!(
                "Update {count} roster{} ({}).",
                if count == 1 { "" } else { "s" },
                self.members
                    .iter()
                    .map(|member| member.machine.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// The trust sentence, in one line. What a plan grants is the one thing on this
    /// screen that is not reversible by deleting a file, so it is never left out.
    fn trust_sentence(&self) -> String {
        let key = match self.host_fingerprint.as_deref() {
            Some(fingerprint) => format!(" Host key {fingerprint}."),
            None => String::new(),
        };

        match self.grants.len() {
            0 => format!("No new trust between machines is granted.{key}"),
            _granted => format!("Grants: {}.{key}", self.grants.join("; ")),
        }
    }
}

/// The whole `fleet.devices` reply, decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    pub host: DeploymentHost,
    pub discovery: Discovery,
    pub devices: Vec<DeviceRow>,
    pub operations: Vec<OperationSummary>,
    /// The fleet's own name, when the runtime states one. The status line falls back to
    /// the self row's roster name rather than inventing one.
    pub fleet_name: Option<String>,
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
            fleet_name: text(value.get("fleet_name"))
                .or_else(|| text(value.get("fleet").and_then(|fleet| fleet.get("name")))),
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

    /// The open operation for one device, or `None`.
    ///
    /// Matched through `operations[].target`, which is why that field exists. Before it,
    /// this answered "is *any* operation open" and every row in the list offered to
    /// continue it — so pressing Continue on `alpha` attached the view to a deployment
    /// against `bravo`, and the password prompt that followed appeared under a header
    /// naming the wrong machine.
    pub fn open_operation_for(&self, row: &DeviceRow) -> Option<&OperationSummary> {
        self.operations.iter().find(|operation| {
            operation.open()
                && !operation.operation.is_empty()
                && operation
                    .target
                    .as_ref()
                    .is_some_and(|target| target.is(row))
        })
    }

    /// Whether this machine has no fleet profile at all.
    ///
    /// The self row says so — it is the one row whose state is about this machine rather
    /// than about a peer — and it changes what "Deploy is unavailable" means. On a
    /// machine with no fleet, `no_ca_key` is not a misconfiguration to go and fix
    /// somewhere else; it is the ordinary state of a machine that has not been set up,
    /// and the thing to do about it is on this screen.
    pub fn standalone(&self) -> bool {
        self.devices
            .iter()
            .any(|row| row.parsed_state() == Some(DeviceState::ThisDeviceWithoutProfile))
    }

    /// Whether this row is the machine the runtime is on.
    pub fn is_self(&self, row: &DeviceRow) -> bool {
        let _ = self;
        matches!(
            row.parsed_state(),
            Some(DeviceState::ThisDevice) | Some(DeviceState::ThisDeviceWithoutProfile)
        )
    }

    /// The rows in the order §5.1 draws them: this machine first, then roster members,
    /// then everything discovery found. One list, no sections, no legend.
    pub fn ordered(&self) -> Vec<&DeviceRow> {
        let mut rows: Vec<&DeviceRow> = self.devices.iter().collect();

        rows.sort_by_key(|row| {
            if self.is_self(row) {
                0
            } else if row.in_fleet() {
                1
            } else {
                2
            }
        });

        rows
    }

    /// What this row is called on screen. The self row takes the host's own noun so the
    /// first line of the list is about the reader's machine rather than about a hostname
    /// that may be a display name, an address, or nothing at all.
    pub fn row_label(&self, row: &DeviceRow) -> String {
        if self.is_self(row) {
            return self.host.self_label().to_string();
        }

        scrub(&row.name, NAME_COLUMNS)
    }

    /// The Ouroboros column, with any operation on this row folded in.
    ///
    /// The operation's *kind* is half of what the column says. A completed removal read
    /// "set up just now" under an **Add to fleet** button, which is a row describing the
    /// opposite of what just happened — the live run that found this was a real
    /// `Remove from fleet` against a Raspberry Pi, and the row announced a setup.
    pub fn ouroboros_word(&self, row: &DeviceRow) -> String {
        let Some(operation) = latest_operation_for(self, row) else {
            return row.ouroboros_word();
        };

        let leaving = operation.kind.as_deref() == Some("leave");

        match operation.state.as_deref() {
            Some("failed") if leaving => "removal failed".into(),
            Some("failed") => "setup failed".into(),
            Some("completed") if leaving => "removed just now".into(),
            Some("completed") => "set up just now".into(),
            Some("awaiting_host_trust") | Some("awaiting_auth") | Some("awaiting_review") => {
                "waiting for you".into()
            }
            Some("cancelled") | None => row.ouroboros_word(),
            Some(_running) if leaving => "removing\u{2026}".into(),
            Some(_running) => "setting up\u{2026}".into(),
        }
    }

    /// The button on this row, with any operation on it folded in and the host's own
    /// blockers applied: an action a gate would refuse is never drawn as an action.
    pub fn primary(&self, row: &DeviceRow) -> Primary {
        if let Some(open) = self.open_operation_for(row) {
            return match open.resumption() {
                Resumption::Continue => Primary::Continue,
                Resumption::Retry => Primary::Retry,
                // The broker will not resume a cancelled operation, so what is offered is
                // a fresh one — which is the row's ordinary action.
                Resumption::DeployAgain | Resumption::None => row.primary(),
            };
        }

        let primary = row.primary();

        match primary {
            Primary::Add if !self.host.add_reasons().is_empty() => Primary::None,
            Primary::SetUp if !self.host.setup_reasons().is_empty() => Primary::None,
            other => other,
        }
    }

    /// The roster members, which is what "N of M connected" counts.
    pub fn members(&self) -> Vec<&DeviceRow> {
        self.devices
            .iter()
            .filter(|row| row.machine.is_some())
            .collect()
    }

    /// The line above the list: either this machine has no fleet, or the fleet's name
    /// and how much of it is here.
    ///
    /// This *is* the blocker sentence for a standalone host — §5.1 is explicit that it
    /// is the status line rather than a second paragraph underneath one.
    pub fn status_line(&self) -> String {
        if self.standalone() {
            return format!("{} is not in a fleet yet", self.host.self_label());
        }

        let members = self.members();
        let total = members.len();
        let connected = members
            .iter()
            .filter(|row| {
                row.connected == Some(true)
                    || row.state == "fleet_member_connected"
                    || row.parsed_state() == Some(DeviceState::ThisDevice)
            })
            .count();

        // A fleet's name already reads as one ("studio's fleet"), so it is printed as it
        // is; "Fleet of studio's fleet" was what the first draft said. Only a fleet with
        // no name is described by the machine that holds it.
        let name = self
            .fleet_name
            .clone()
            .map(|name| scrub(&name, 40))
            .unwrap_or_else(|| {
                let machine = self
                    .devices
                    .iter()
                    .find(|row| self.is_self(row))
                    .and_then(|row| row.machine.clone())
                    .unwrap_or_else(|| "this machine".into());
                format!("Fleet of {}", scrub(&machine, NAME_COLUMNS))
            });

        format!(
            "{name} \u{b7} {connected} of {total} machine{} connected",
            if total == 1 { "" } else { "s" }
        )
    }

    /// Why deployment is unavailable, in the words that are true of *this* machine.
    pub fn deploy_blocker(&self) -> Option<String> {
        if self.host.deploy {
            return None;
        }

        if self.standalone() && self.host.reasons.iter().any(|r| r == "no_ca_key") {
            // Every other blocker still gets its own sentence; this is only about the
            // one that a first setup answers.
            return Some(match self.host.setup_blocker() {
                Some(other) => other,
                None => format!(
                    "{} is not in a fleet yet \u{2014} set it up from the first row.",
                    self.host.self_label()
                ),
            });
        }

        self.host.blocker()
    }

    /// Every open operation, for the line above the list that says one is running.
    pub fn open_operations(&self) -> Vec<&OperationSummary> {
        self.operations
            .iter()
            .filter(|operation| operation.open() && !operation.operation.is_empty())
            .collect()
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
    /// The whole challenge object, as the broker's snapshot carries it.
    pub frame: Value,
}

impl Challenge {
    /// One open challenge, or `None` for a frame this client cannot answer.
    ///
    /// A challenge with no id is dropped here rather than drawn. The id is the whole of
    /// how an answer is addressed: a question with none is one the worker cannot be told
    /// about, and putting a masked field on the screen for it would be asking somebody to
    /// type a password into a prompt whose answer goes nowhere.
    fn decode(value: &Value) -> Option<Self> {
        let id = text(value.get("challenge"))?;
        let kind = text(value.get("kind"))?;

        Some(Self {
            id,
            kind,
            frame: value.clone(),
        })
    }

    /// One metadata field, from where the broker actually leaves it.
    ///
    /// Seam S4 describes a challenge's kind-specific fields as fields *of the challenge*:
    /// a `password` carries `{target, user, port, attempt, max_attempts}`. The worker
    /// sends them one level down, under `metadata`, and the broker's
    /// `challenge_metadata/1` **lifts** them back to the top before a client ever sees
    /// them — so `challenge["plan_digest"]` is where the seam says it is, and that is the
    /// read that runs in production.
    ///
    /// The nested form is kept as a fallback because it is what the worker puts on its
    /// own socket, and a broker that stopped lifting would otherwise empty every prompt
    /// on this screen in silence. Reading both cannot be wrong for either.
    fn meta(&self) -> Option<&Value> {
        self.frame.get("metadata").filter(|value| value.is_object())
    }

    fn lookup(&self, key: &str) -> Option<&Value> {
        self.frame
            .get(key)
            .or_else(|| self.meta().and_then(|meta| meta.get(key)))
    }

    fn field(&self, key: &str) -> Option<String> {
        self.lookup(key).and_then(|value| match value {
            Value::String(_) => text(Some(value)),
            Value::Number(number) => Some(number.to_string()),
            _other => None,
        })
    }

    /// The plan this challenge carries, decoded and bounded by this view.
    pub fn plan(&self) -> Option<PlanView> {
        PlanView::decode(self.lookup("plan")?)
    }

    /// The digest the challenge *claims*, held to hex.
    ///
    /// Never approved on its own: [`review_lines`] draws it only to name the mismatch, and
    /// what `start` carries is the digest this client computed over the plan it drew.
    pub fn claimed_digest(&self) -> Option<String> {
        self.lookup("plan_digest")
            .and_then(Value::as_str)
            .and_then(hex_digest)
    }
}

/// The sanitized snapshot of one operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub kind: Option<String>,
    /// `worker` when one is attached, `journal` when none is. The operator's whole
    /// question after an interruption, so it is drawn rather than inferred.
    pub source: String,
    pub attached: bool,
    pub state: String,
    /// The worker's own refusal code from its `done` frame, when it named one.
    ///
    /// Kept beside [`Self::last_error`] rather than folded into it: the sentence is for
    /// the operator and the code is what this view is allowed to *reason* about. A
    /// failure the engine gave a stable reason is a refusal it understood; one with no
    /// reason at all is a plain error, which for a removal is what an unreachable
    /// machine looks like.
    pub reason: Option<String>,
    /// The identity that started this operation, when the worker reports one.
    pub owner: Option<String>,
    pub steps: Vec<Step>,
    pub log: Vec<String>,
    pub last_error: Option<String>,
    pub residue: Vec<String>,
    /// The worker's own one-line summary of a finished operation, from its `done` frame.
    pub summary: Option<String>,
    /// What the worker says to do next — the field the proposal requires the final
    /// display to name, written by the side that knows what actually happened.
    pub next: Option<String>,
    pub challenges: Vec<Challenge>,
    /// The worker's own last words, when the broker found it gone with an unfinished
    /// journal and no `done` frame (§5.5).
    ///
    /// The live failure this answers: a worker that died before attaching left the
    /// operation reading "inspecting" with nothing said, while the reason — a Unix socket
    /// path over 104 bytes — sat in the worker's private log. Present means *the worker
    /// stopped*, which is a finished operation whatever the state says.
    pub worker_exit: Option<WorkerExit>,
}

/// A worker that is gone, and the last of what it wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerExit {
    pub code: Option<i64>,
    /// At most three lines, scrubbed on the way in, as the broker sends them.
    pub last_lines: Vec<String>,
}

impl WorkerExit {
    fn decode(value: &Value) -> Option<Self> {
        let object = value.as_object()?;

        Some(Self {
            code: object.get("code").and_then(Value::as_i64),
            last_lines: array(object.get("last_lines").map(|v| v as &Value))
                .iter()
                .filter_map(|line| sentence(Some(line)))
                .take(3)
                .collect(),
        })
    }

    /// The sentence the operation screen draws.
    pub fn sentence(&self) -> String {
        if self.last_lines.is_empty() {
            return "The setup worker stopped, and wrote nothing this runtime could read."
                .to_string();
        }

        format!(
            "The setup worker stopped: {}",
            self.last_lines.join(" \u{b7} ")
        )
    }
}

impl Snapshot {
    pub fn decode(value: &Value) -> Self {
        let done = value.get("done").filter(|done| done.is_object());

        Self {
            source: text(value.get("source")).unwrap_or_else(|| "journal".into()),
            kind: text(value.get("kind")),
            attached: value
                .get("attached")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            state: text(value.get("state")).unwrap_or_default(),
            reason: text(done.and_then(|done| done.get("reason")))
                .or_else(|| text(value.get("reason"))),
            owner: text(value.get("owner")),
            steps: array(value.get("steps")).iter().map(Step::decode).collect(),
            log: array(value.get("log"))
                .iter()
                .filter_map(|line| sentence(line.get("line")).or_else(|| sentence(Some(line))))
                .collect(),
            // Two sources, because there are two: a journal read carries `last_error` and
            // `residue` at the top level (they are `Journal`'s own fields), and a live
            // worker carries them inside the `done` frame the broker stored whole —
            // `{ok, state, summary, next, residue, unknown}` on success and
            // `{ok: false, reason, detail}` on a failure. Reading only the journal's
            // spelling meant a running worker's residue and cause were never drawn.
            last_error: sentence(value.get("last_error"))
                .or_else(|| sentence(done.and_then(|done| done.get("detail"))))
                .or_else(|| {
                    done.and_then(|done| done.get("reason"))
                        .and_then(Value::as_str)
                        .map(reason_sentence)
                }),
            residue: match array(value.get("residue")) {
                empty if empty.is_empty() => array(done.and_then(|done| done.get("residue"))),
                journal => journal,
            }
            .iter()
            .filter_map(|item| sentence(Some(item)))
            .collect(),
            summary: sentence(done.and_then(|done| done.get("summary"))),
            next: sentence(done.and_then(|done| done.get("next"))),
            challenges: array(value.get("challenges"))
                .iter()
                .filter_map(Challenge::decode)
                .collect(),
            worker_exit: value.get("worker_exit").and_then(WorkerExit::decode),
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
        operation_state(&self.state)
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
        ) || self.worker_exit.is_some()
    }

    pub fn succeeded(&self) -> bool {
        self.state == "completed"
    }

    /// The stage strip §5.2 draws, as (name, marker) pairs.
    ///
    /// Not the worker's steps one for one: those are engine verbs (`member_preflight`,
    /// `install_binary`, `issue`) and there are more of them than a person wants to read.
    /// Each stage collects the steps that belong to it, so a stage is done when its steps
    /// are, current when one of them is running, and pending otherwise.
    ///
    /// `kind` is passed in rather than read from the snapshot alone: `fleet.deployment.
    /// status` carries no `kind` field, so a removal watched through the broker arrives
    /// here indistinguishable from an add — which is how a live `leave` drew the add
    /// flow's six stages and filed its roster removal under *Join fleet*. The view knows
    /// the kind from the operation it opened, and hands it over.
    pub fn stages(&self, kind: Option<&str>) -> Vec<(&'static str, Marker)> {
        let kind = self.kind.as_deref().or(kind);
        let plan: &[(&'static str, &[&str])] = match kind {
            // The engine's own `run_leave`/`stop_and_retire` steps, in the order it
            // records them: `inspect`, `stop_runtime`, `disable_service`,
            // `verify_disconnected`, `leave`, then `member_preflight`/`roster` for every
            // roster this removal edits.
            Some("leave") => &[
                ("Inspect", &["inspect"]),
                ("Stop", &["stop_runtime"]),
                ("Disable startup", &["disable_service"]),
                ("Leave", &["verify_disconnected", "leave"]),
                ("Update rosters", &["member_preflight", "roster"]),
            ],
            _add_or_setup => &[
                ("Inspect", &["inspect", "member_preflight", "prepare"]),
                ("Install", &["install_binary", "materials"]),
                ("Join fleet", &["create", "issue", "install", "roster"]),
                ("Start at login", &["service"]),
                ("Connect", &["connect"]),
                ("Ready", &["test_task", "readiness", "diagnostics"]),
            ],
        };

        let mut stages = Vec::new();
        let mut reached = false;

        for (name, steps) in plan {
            let mine: Vec<&Step> = self
                .steps
                .iter()
                .filter(|step| steps.contains(&step.step.as_str()))
                .collect();

            let marker = if mine.iter().any(|step| step.outcome == "failed") {
                reached = true;
                Marker::Failed
            } else if mine
                .iter()
                .any(|step| matches!(step.outcome.as_str(), "started" | "running"))
            {
                reached = true;
                Marker::Current
            } else if !mine.is_empty() {
                Marker::Done
            } else if !reached && self.succeeded() {
                // A stage the worker never reported a step for, on an operation that
                // completed. It is not pending — the operation is over — and it is not
                // done either: the live add that prompted this ended at `connect` with
                // no readiness step at all, and the strip ticked *Ready* as though
                // something had checked it. What actually happened is that nothing did.
                Marker::NotChecked
            } else {
                Marker::Pending
            };

            stages.push((*name, marker));
        }

        // Nothing has been stepped yet and the worker is still working: the first stage
        // is the one it is on, rather than six circles that say nothing is happening.
        if !self.terminal()
            && stages
                .iter()
                .all(|(_name, marker)| *marker == Marker::Pending)
        {
            if let Some(first) = stages.first_mut() {
                first.1 = Marker::Current;
            }
        }

        stages
    }

    /// The detail of whichever step is running, for the line under the strip.
    pub fn current_detail(&self) -> Option<String> {
        self.steps
            .iter()
            .rev()
            .find(|step| matches!(step.outcome.as_str(), "started" | "running" | "failed"))
            .and_then(|step| {
                step.detail
                    .clone()
                    .map(|detail| format!("{} \u{2014} {detail}", step.step))
                    .or_else(|| Some(step.step.clone()))
            })
    }
}

/// A stage's mark in the progress strip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Done,
    Current,
    Pending,
    Failed,
    /// Finished without this stage ever being reported. Not a tick: nobody looked.
    NotChecked,
}

impl Marker {
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Done => "\u{2713}",
            Self::Current => "\u{25cf}",
            Self::Pending => "\u{25cb}",
            Self::Failed => "\u{00d7}",
            Self::NotChecked => "\u{2013}",
        }
    }

    /// What a screen reader is given instead of a glyph nobody announces usefully.
    pub fn word(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Current => "now",
            Self::Pending => "to do",
            Self::Failed => "failed",
            Self::NotChecked => "not checked",
        }
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

/// Which of the four forms this is.
///
/// One type rather than four, because everything after the fields is identical: the same
/// `prepare`, the same challenges, the same review, the same progress. What differs is
/// which rows are drawn, which are required, and what the button says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    /// A device the list found: the address came with it and is read-only.
    Add,
    /// *Add a device by address*: the same form with the address editable and the name
    /// empty. The name is required here too — the live failure was a worker taking the
    /// address as the machine name and refusing it (finding 2).
    AddByAddress,
    /// This machine's first fleet.
    Setup,
    /// Taking a member out of the fleet.
    Leave,
}

impl FormKind {
    fn adds(self) -> bool {
        matches!(self, Self::Add | Self::AddByAddress)
    }
}

/// Which field of the connect form has the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectField {
    /// The device's roster name.
    Machine,
    Address,
    User,
    Port,
    /// A private key on the deployment host, under Advanced.
    KeyPath,
    /// An agent identity's fingerprint or label, under Advanced.
    AgentId,
    InstallPath,
    DataDir,
    Service,
    /// The disclosure row itself. Enter on it opens or closes the fields underneath —
    /// a row of the form, so it is reachable by Tab and by its number, and so nothing
    /// re-renders it shut behind an operator's typing (the web's finding 6).
    Advanced,
    Submit,
}

impl ConnectField {
    /// What an admission asks for first: a name, where it is, and whose account.
    ///
    /// There is **no authentication picker**. The default identity is used, and when the
    /// target asks for a password the worker raises the `password` challenge and the
    /// operation screen asks for it — which is what the engine change in §5.5 makes true.
    /// A specific key or agent identity is an Advanced field, not a first decision.
    pub const ADD: [Self; 3] = [Self::Machine, Self::Address, Self::User];

    /// §5.2's Advanced list, in its order.
    pub const ADD_ADVANCED: [Self; 6] = [
        Self::Port,
        Self::KeyPath,
        Self::InstallPath,
        Self::DataDir,
        Self::AgentId,
        Self::Service,
    ];

    /// What a first *local* setup draws: no account, no port, no identity, no install
    /// path on another machine. This device is not reached over SSH, so none of the
    /// fields that describe an SSH connection have anything to describe — and *start at
    /// login* is the one choice it does have, so it is on the face of the form.
    pub const SETUP: [Self; 3] = [Self::Machine, Self::Address, Self::Service];

    /// What a departure asks for: the account on the member.
    pub const LEAVE: [Self; 1] = [Self::User];

    /// How to reach the member, when the defaults are not it.
    pub const LEAVE_ADVANCED: [Self; 3] = [Self::Port, Self::KeyPath, Self::AgentId];

    pub fn label(self) -> &'static str {
        match self {
            Self::Machine => "Name in the fleet",
            Self::Address => "Address",
            Self::User => "SSH user",
            Self::Port => "port",
            Self::KeyPath => "SSH key",
            Self::AgentId => "agent fingerprint",
            Self::InstallPath => "install path",
            Self::DataDir => "data directory",
            Self::Service => "start at login",
            Self::Advanced => "Advanced",
            Self::Submit => "submit",
        }
    }

    /// Whether digits typed into this field are content rather than a menu choice.
    ///
    /// A10 numbers every row of this form in screen-reader mode and the numbers have to
    /// select — but an address, a port and a machine name can all be digits, and a form
    /// where `2` jumps to another field instead of typing `2` cannot express
    /// `100.83.203.10` or port 22.
    pub fn takes_digits(self) -> bool {
        matches!(self, Self::Port | Self::Address | Self::Machine)
    }
}

/// Step 1 of the flow: the form, whichever of the four it is.
#[derive(Debug, Clone)]
pub struct ConnectForm {
    pub kind: FormKind,
    /// The row this is about, for the heading.
    pub device: String,
    pub field: ConnectField,
    pub user: String,
    /// The device's roster name.
    pub machine: String,
    pub address: String,
    /// Whether the address came from the list, in which case it is not editable.
    pub address_fixed: bool,
    pub port: String,
    pub key_path: String,
    pub agent_id: String,
    pub install_path: String,
    pub data_dir: String,
    pub service: bool,
    /// Whether the Advanced disclosure is open. It stays open once opened — the web's
    /// finding 6 was a `<details>` that closed on every keystroke, and a terminal form
    /// that re-collapsed on each character would be the same bug in another house.
    pub advanced_open: bool,
    /// The inline, actionable error for the field that is wrong.
    pub error: Option<String>,
}

impl ConnectForm {
    /// The form for admitting a device the list found.
    fn add(inventory: &Inventory, row: &DeviceRow) -> Self {
        Self {
            kind: FormKind::Add,
            device: inventory.row_label(row),
            // Never `name`: that is a display name. §5.5's `suggested_machine` is the
            // only thing this field is ever seeded from, and `null` leaves it empty.
            machine: row.suggested_machine.clone().unwrap_or_default(),
            address: row.address.clone().unwrap_or_default(),
            address_fixed: row.address.is_some(),
            field: ConnectField::Machine,
            ..Self::blank(FormKind::Add)
        }
    }

    /// *Add a device by address*: the same form, nothing pre-filled, address editable.
    fn manual() -> Self {
        Self {
            device: "a device at an address you type".into(),
            field: ConnectField::Machine,
            ..Self::blank(FormKind::AddByAddress)
        }
    }

    /// Step 1 for *this* machine: a name, an address, and whether to start at login.
    fn setup(inventory: &Inventory, row: &DeviceRow) -> Self {
        Self {
            kind: FormKind::Setup,
            device: inventory.host.self_label().to_string(),
            machine: row.suggested_machine.clone().unwrap_or_default(),
            address: row.address.clone().unwrap_or_default(),
            address_fixed: row.address.is_some(),
            field: ConnectField::Machine,
            ..Self::blank(FormKind::Setup)
        }
    }

    /// Taking a member out of the fleet.
    fn leave(inventory: &Inventory, row: &DeviceRow) -> Self {
        Self {
            kind: FormKind::Leave,
            device: inventory.row_label(row),
            machine: row.machine.clone().unwrap_or_default(),
            address: row.address.clone().unwrap_or_default(),
            address_fixed: true,
            field: ConnectField::User,
            ..Self::blank(FormKind::Leave)
        }
    }

    fn blank(kind: FormKind) -> Self {
        Self {
            kind,
            device: String::new(),
            field: ConnectField::Machine,
            user: String::new(),
            machine: String::new(),
            address: String::new(),
            address_fixed: false,
            port: "22".into(),
            key_path: String::new(),
            agent_id: String::new(),
            install_path: String::new(),
            data_dir: String::new(),
            service: true,
            advanced_open: false,
            error: None,
        }
    }

    /// The heading this form draws.
    pub fn heading(&self) -> String {
        match self.kind {
            FormKind::Add => format!("Add {} to your fleet", self.device),
            FormKind::AddByAddress => "Add a device by address".into(),
            FormKind::Setup => format!("Set up {}", lowercase_first(&self.device)),
            FormKind::Leave => format!("Remove {} from the fleet", self.device),
        }
    }

    /// The button's words.
    pub fn submit_label(&self) -> &'static str {
        match self.kind {
            FormKind::Add | FormKind::AddByAddress => "[ Connect ]",
            FormKind::Setup => "[ Set up ]",
            FormKind::Leave => "[ Remove ]",
        }
    }

    /// The sentence under the button.
    pub fn submit_hint(&self) -> &'static str {
        match self.kind {
            FormKind::Add | FormKind::AddByAddress => {
                "Reads the machine first. Nothing is installed until you approve a plan."
            }
            FormKind::Setup => {
                "Ouroboros restarts once during setup; this view reconnects by itself."
            }
            FormKind::Leave => {
                "Reads the machine first. Nothing is changed until you approve a plan."
            }
        }
    }

    /// The fields on the face of this form.
    pub fn fields(&self) -> &'static [ConnectField] {
        match self.kind {
            FormKind::Add | FormKind::AddByAddress => &ConnectField::ADD,
            FormKind::Setup => &ConnectField::SETUP,
            FormKind::Leave => &ConnectField::LEAVE,
        }
    }

    /// The fields behind the Advanced disclosure, which is not drawn when there are none.
    pub fn advanced_fields(&self) -> &'static [ConnectField] {
        match self.kind {
            FormKind::Add | FormKind::AddByAddress => &ConnectField::ADD_ADVANCED,
            FormKind::Setup => &[],
            FormKind::Leave => &ConnectField::LEAVE_ADVANCED,
        }
    }

    /// The rows the cursor walks, in the order they are drawn: the plain fields, the
    /// disclosure, whatever it is showing, then the button.
    pub fn rows(&self) -> Vec<ConnectField> {
        let mut rows: Vec<ConnectField> = self
            .fields()
            .iter()
            .copied()
            .filter(|field| self.editable(*field))
            .collect();

        if !self.advanced_fields().is_empty() {
            rows.push(ConnectField::Advanced);

            if self.advanced_open {
                rows.extend(self.advanced_fields().iter().copied());
            }
        }

        rows.push(ConnectField::Submit);
        rows
    }

    /// Whether a field can be typed into at all. A read-only address is drawn, and the
    /// cursor does not stop on it.
    pub fn editable(&self, field: ConnectField) -> bool {
        match field {
            ConnectField::Address => !self.address_fixed,
            _other => true,
        }
    }

    fn text_mut(&mut self) -> Option<&mut String> {
        match self.field {
            ConnectField::User => Some(&mut self.user),
            ConnectField::Machine => Some(&mut self.machine),
            ConnectField::Address => (!self.address_fixed).then_some(&mut self.address),
            ConnectField::Port => Some(&mut self.port),
            ConnectField::KeyPath => Some(&mut self.key_path),
            ConnectField::AgentId => Some(&mut self.agent_id),
            ConnectField::InstallPath => Some(&mut self.install_path),
            ConnectField::DataDir => Some(&mut self.data_dir),
            _not_text => None,
        }
    }

    pub fn value(&self, field: ConnectField) -> String {
        match field {
            ConnectField::User => self.user.clone(),
            ConnectField::Machine => self.machine.clone(),
            ConnectField::Address => self.address.clone(),
            ConnectField::Port => self.port.clone(),
            ConnectField::KeyPath => self.key_path.clone(),
            ConnectField::AgentId => self.agent_id.clone(),
            ConnectField::InstallPath => self.install_path.clone(),
            ConnectField::DataDir => self.data_dir.clone(),
            ConnectField::Service => {
                if self.service {
                    "on".into()
                } else {
                    "off".into()
                }
            }
            ConnectField::Advanced | ConnectField::Submit => String::new(),
        }
    }

    /// The note beside a field: what it is for, in the target design's words.
    pub fn hint(&self, field: ConnectField) -> Option<String> {
        match field {
            ConnectField::Machine => Some("letters, digits, hyphens".into()),
            ConnectField::User if self.kind.adds() || self.kind == FormKind::Leave => {
                Some(format!("the account on {}", self.device))
            }
            ConnectField::Address if self.address_fixed => Some("from the list".into()),
            ConnectField::Service => {
                Some("starts at login as a user service, not a pre-login daemon".into())
            }
            _plain => None,
        }
    }

    fn move_field(&mut self, by: i32) {
        let rows = self.rows();
        let index = rows
            .iter()
            .position(|field| *field == self.field)
            .unwrap_or(0) as i32;
        let next = (index + by).rem_euclid(rows.len() as i32) as usize;
        self.field = rows[next];
    }

    /// The `fleet.deployment.prepare` parameters, or the inline error that stops them.
    ///
    /// For `add` and `leave` the username is required and is never inferred from the
    /// network client's owner: the Tailscale account that owns a device says nothing
    /// about which local account an operator may log into. For `setup` there is no
    /// account at all — this machine is not reached over SSH — so that refusal must not
    /// fire on a form that has no username field to fill in.
    fn params(&self) -> Result<Value, (ConnectField, String)> {
        match self.kind {
            FormKind::Setup => self.setup_params(),
            FormKind::Leave => self.leave_params(),
            FormKind::Add | FormKind::AddByAddress => self.add_params(),
        }
    }

    /// The account on the target, required for everything that reaches one over SSH.
    fn ssh_user(&self) -> Result<&str, (ConnectField, String)> {
        let user = self.user.trim();

        if user.is_empty() {
            return Err((
                ConnectField::User,
                "An SSH username is required. It is the account on the target, and it is \
                 never guessed from the network client's owner."
                    .into(),
            ));
        }

        Ok(user)
    }

    fn ssh_port(&self) -> Result<u16, (ConnectField, String)> {
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

        Ok(port)
    }

    /// The `identity` object, or `None` for the default the engine now falls back from.
    ///
    /// Two named fields rather than a picker and a free-text reference: an operator who
    /// types a path means a key and one who types a fingerprint means an agent, and
    /// deciding which from the shape of the string would be this client guessing at the
    /// one input where a wrong guess spends a server's retry budget.
    fn identity(&self) -> Result<Option<Value>, (ConnectField, String)> {
        let key = self.key_path.trim();
        let agent = self.agent_id.trim();

        match (key.is_empty(), agent.is_empty()) {
            (true, true) => Ok(None),
            (false, false) => Err((
                ConnectField::KeyPath,
                "Name one identity, not two: either a key file on this deployment host \
                 or an agent fingerprint. Clear the one you did not mean."
                    .into(),
            )),
            (false, true) => Ok(Some(json!({ "kind": "key", "ref": key }))),
            (true, false) => Ok(Some(json!({ "kind": "agent", "ref": agent }))),
        }
    }

    fn add_params(&self) -> Result<Value, (ConnectField, String)> {
        // The machine name is required on both add paths. It used to be absent from the
        // manual one altogether, which is how the address became the machine name and
        // the worker refused it.
        if self.machine.trim().is_empty() {
            return Err((
                ConnectField::Machine,
                "A name in the fleet is required. It is how this device is addressed \
                 from every other machine, and an address is not one."
                    .into(),
            ));
        }

        if let Err(error) = crate::fleet_setup::engine::normalize_machine(&self.machine) {
            return Err((ConnectField::Machine, error.to_string()));
        }

        let user = self.ssh_user()?;
        let port = self.ssh_port()?;

        let address = self.address.trim();
        if address.is_empty() {
            return Err((
                ConnectField::Address,
                match self.kind {
                    FormKind::AddByAddress => "Type the address to connect to.".to_string(),
                    _from_the_list => "This device reported no private address, so there \
                                       is nothing to connect to. Refresh, or add it by \
                                       address."
                        .to_string(),
                },
            ));
        }

        let mut params = json!({
            "kind": "add",
            "target": { "address": address, "machine": self.machine.trim() },
            "ssh_user": user,
            "port": port,
            "service": self.service,
        });

        if let Some(identity) = self.identity()? {
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

    /// `kind: "setup"` — no target, no account, no identity.
    fn setup_params(&self) -> Result<Value, (ConnectField, String)> {
        let mut params = json!({ "kind": "setup", "service": self.service });

        let machine = self.machine.trim();
        if !machine.is_empty() {
            if let Err(error) = crate::fleet_setup::engine::normalize_machine(machine) {
                return Err((ConnectField::Machine, error.to_string()));
            }

            params["machine"] = json!(machine);
        }

        // The worker refuses `unresolved_address` rather than guessing, and the inventory
        // is where this machine's own overlay address comes from, so it is passed when
        // there is one and left out when there is not.
        let address = self.address.trim();
        if !address.is_empty() {
            params["address"] = json!(address);
        }

        Ok(params)
    }

    /// `kind: "leave"` — a roster member, by name, and the account to reach it as.
    fn leave_params(&self) -> Result<Value, (ConnectField, String)> {
        let machine = self.machine.trim();

        if machine.is_empty() {
            return Err((
                ConnectField::User,
                "This device has no roster name, so there is no member to remove.".into(),
            ));
        }

        let user = self.ssh_user()?;
        let port = self.ssh_port()?;

        let mut params = json!({
            "kind": "leave",
            "target": { "machine": machine },
            "ssh_user": user,
            "port": port,
        });

        if let Some(identity) = self.identity()? {
            params["identity"] = identity;
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
    pub kind: Option<String>,
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
    /// Whether the snapshot in hand describes a moment that has passed.
    ///
    /// Set the instant the connection to the deployment host goes — which a local setup
    /// makes happen on purpose — and cleared only by a fresh `fleet.deployment.status`.
    /// Between those two the view says what it is doing instead of redrawing the last
    /// thing it knew as though it were still true (finding 4).
    pub stale: bool,
    /// What a refusal said, in the place the answer would have gone.
    pub error: Option<String>,
}

impl Operation {
    fn new(id: String, device: String) -> Self {
        Self {
            id,
            kind: None,
            device,
            snapshot: Loadable::default(),
            secret: SecretInput::default(),
            answering: None,
            rung_for: None,
            submitting: false,
            takeover: None,
            stale: false,
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
        // `digest` is a [`hex_digest`], so it is 64 ASCII bytes and this cut is on a
        // character boundary by construction. It used to be `digest.len().min(16)` on
        // whatever string the challenge carried, which panicked the whole client the
        // first time a worker sent a multibyte one.
        let short: String = digest.chars().take(16).collect();

        format!("{}-{short}", self.id)
    }
}
/// How many rows the list draws before it offers to narrow itself.
///
/// §5.1: search and filter appear only past eight rows. A working home network of four
/// devices split into two sections with a search box and three filter buttons is the
/// presentation finding 9 is about; four rows do not need to be searched.
pub const NARROWING_ROWS: usize = 8;

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
    /// The last refused action, drawn in the hint line — the one row that is always on
    /// the page whatever the list is doing.
    pub refusal_line: Option<String>,
}

impl DevicesState {
    /// The rows the filter and the query leave, in the order §5.1 draws them.
    pub fn visible<'a>(&self, inventory: &'a Inventory) -> Vec<&'a DeviceRow> {
        let query = self.query.trim().to_ascii_lowercase();
        let narrowing = self.narrowing(inventory);

        inventory
            .ordered()
            .into_iter()
            .filter(|row| {
                !narrowing
                    || match self.filter {
                        Filter::All => true,
                        Filter::Fleet => row.in_fleet(),
                        Filter::Available => !row.in_fleet(),
                    }
            })
            .filter(|row| {
                !narrowing
                    || query.is_empty()
                    || row.name.to_ascii_lowercase().contains(&query)
                    || row
                        .address
                        .as_deref()
                        .is_some_and(|address| address.to_ascii_lowercase().contains(&query))
            })
            .collect()
    }

    /// Whether this list is long enough to be worth narrowing. Below the threshold `/`
    /// and `f` do nothing and are not offered, so the keys on the hint line are the keys
    /// that work.
    pub fn narrowing(&self, inventory: &Inventory) -> bool {
        inventory.devices.len() > NARROWING_ROWS
    }

    /// The row under the cursor, for the details panel and for Enter.
    pub fn selected<'a>(&self, inventory: &'a Inventory) -> Option<&'a DeviceRow> {
        self.visible(inventory).get(self.cursor).copied()
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
        self.devices.refusal_line = None;
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

    /// Drop whatever is over the screen. If that was Devices, the typed secret goes with
    /// it — every path that clears `overlay` has to come through here, because Ctrl+C
    /// used to set `overlay = None` without touching the buffer.
    pub(super) fn close_overlay(&mut self) {
        if matches!(self.overlay, Some(Overlay::Devices)) {
            self.devices.forget_secret();
        }
        let _dropped = self.overlay.take();
    }

    /// Leaving the view. Never cancels the operation; only forgets what was typed.
    pub fn close_devices(&mut self) {
        self.close_overlay();
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
            // Belt: any teardown path that dropped the overlay without
            // [`App::close_overlay`] still cannot leave a typed secret sitting in
            // `DevicesState` for the next open.
            self.devices.forget_secret();
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

    /// The runtime this client is attached to is back.
    ///
    /// Finding 4's other half. A local setup stops the runtime by design, and the
    /// operation outlives it — the worker is detached, and the journal is on the
    /// deployment host. So what the reconnect owes an operator is the operation read
    /// again *by its own id*, not the snapshot from before the restart and not a fresh
    /// deployment. Nothing is sent that could apply anything: `fleet.deployment.status`
    /// is a read, and whatever it answers is what the screen then shows — including a
    /// challenge that is waiting, which is where the flow picks up.
    pub(super) fn devices_reconnected(&mut self) {
        self.devices.inventory.invalidate();
        self.devices.fallback.invalidate();

        if let Some(operation) = self.devices.operation.as_mut() {
            // Still stale until the reload lands: the last snapshot is from a runtime
            // that has since restarted, and drawing it as current is the bug.
            operation.stale = true;
            operation.submitting = false;
            operation.snapshot.invalidate();
        }

        self.poll_devices();
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
        match tag {
            DevicesTag::Inventory => self.devices_answer_inventory(result),
            DevicesTag::FleetStatus => self.devices_answer_fleet_status(result),
            DevicesTag::Prepare => self.devices_answer_prepare(result),
            DevicesTag::Status { operation } => self.devices_answer_status(operation, result),
            DevicesTag::Answer { operation, label } => {
                self.devices_answer_challenge(operation, label, result)
            }
            DevicesTag::Resume { operation } => self.devices_answer_resume(operation, result),
        }
    }

    fn devices_answer_inventory(&mut self, result: Result<Value, ClientError>) {
        let ticks = self.ticks;

        match result {
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
                self.devices.refusal = Some(devices_refusal(&error, "fleet.devices", &self.hello));
                self.devices
                    .inventory
                    .failed(clean(&error.to_string()), ticks, INVENTORY_HOLD);
                self.poll_devices_fallback();
            }
        }
    }

    fn devices_answer_fleet_status(&mut self, result: Result<Value, ClientError>) {
        let ticks = self.ticks;

        match result {
            Ok(value) => {
                self.devices
                    .fallback
                    .ok(FleetSubset::decode(&value), ticks, INVENTORY_HOLD)
            }
            Err(error) => {
                self.devices
                    .fallback
                    .failed(clean(&error.to_string()), ticks, INVENTORY_HOLD)
            }
        }
    }

    fn devices_answer_prepare(&mut self, result: Result<Value, ClientError>) {
        match result {
            Ok(value) => match text(value.get("operation_id")) {
                Some(id) => {
                    // The operation's own target, never a placeholder. "this device" was
                    // the string finding 3 found on screen and in a journal, standing in
                    // for a machine the runtime could have named perfectly well.
                    let device = self
                        .devices
                        .connect
                        .as_ref()
                        .map(|form| match form.machine.trim() {
                            "" => form.device.clone(),
                            machine => machine.to_string(),
                        })
                        .unwrap_or_else(|| {
                            self.devices
                                .inventory
                                .value
                                .as_ref()
                                .map(|inventory| inventory.host.self_label().to_string())
                                .unwrap_or_else(|| "this machine".into())
                        });

                    let mut operation = Operation::new(id, device);
                    operation.kind = self.devices.connect.as_ref().map(|form| {
                        match form.kind {
                            FormKind::Setup => "setup",
                            FormKind::Leave => "leave",
                            FormKind::Add | FormKind::AddByAddress => "add",
                        }
                        .into()
                    });
                    self.devices.connect = None;
                    self.devices.operation = Some(Box::new(operation));
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

                // A host that has become unable to deploy is not a bad form field: it
                // is the same refusal the list draws, and it goes where every other
                // refusal goes.
                if refusal_reason(&error).as_deref() == Some("deploy_blocked") {
                    self.devices.connect = None;
                    self.devices_refuse(sentence);
                } else {
                    self.devices_form_error(&sentence);
                }
            }
        }
    }

    fn devices_answer_status(&mut self, operation: String, result: Result<Value, ClientError>) {
        if !self.devices_is_current(&operation) {
            return;
        }

        let ticks = self.ticks;

        match result {
            Ok(value) => {
                let snapshot = Snapshot::decode(&value);
                let waiting = snapshot.waiting();
                let state = snapshot.state.clone();

                if let Some(current) = self.devices.operation.as_mut() {
                    if snapshot.kind.is_some() {
                        current.kind = snapshot.kind.clone();
                    }
                    // A challenge that is gone takes the buffer typed for it with
                    // it: an answer consumed, expired or superseded must never be
                    // resubmitted to the next question.
                    let open = snapshot.challenge().map(|challenge| challenge.id.clone());
                    if current.answering.is_some() && current.answering != open {
                        current.secret.clear();
                        current.answering = None;
                    }

                    // A fresh read is what makes the snapshot current again.
                    current.stale = false;
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

                // The connection is gone, not the operation. Whatever snapshot is in
                // hand describes a moment that has passed, so it is marked as such and
                // the screen says what it is waiting for.
                let lost = matches!(
                    error,
                    ClientError::ConnectionClosed | ClientError::Stopped(_) | ClientError::Io(_)
                );

                let sentence =
                    devices_error_sentence(&error, "fleet.deployment.status", &self.hello);

                if let Some(current) = self.devices.operation.as_mut() {
                    current.stale = current.stale || lost;
                    current.snapshot.failed(sentence, ticks, SNAPSHOT_TICKS);
                }
            }
        }
    }

    fn devices_answer_challenge(
        &mut self,
        operation: String,
        label: &'static str,
        result: Result<Value, ClientError>,
    ) {
        if !self.devices_is_current(&operation) {
            return;
        }

        let blocked = result
            .as_ref()
            .err()
            .is_some_and(|error| refusal_reason(error).as_deref() == Some("deploy_blocked"));

        let sentence = match result {
            Ok(_accepted) => None,
            Err(error) => Some(devices_error_sentence(&error, label, &self.hello)),
        };

        if let Some(sentence) = sentence.as_ref().filter(|_| blocked) {
            self.devices_refuse(sentence.clone());
        }

        if let Some(current) = self.devices.operation.as_mut() {
            current.submitting = false;
            current.error = sentence;
            // Whatever happened, read the operation again rather than believing
            // this client's idea of what the answer did.
            current.snapshot.invalidate();
        }

        self.poll_devices();
    }

    fn devices_answer_resume(&mut self, operation: String, result: Result<Value, ClientError>) {
        match result {
            Ok(_resumed) => {
                // The same guard the error arm has. Without it, a success for an
                // operation this view walked away from ten minutes ago cleared the
                // takeover question standing on the screen for a *different* one —
                // and the question disappearing looks exactly like it being answered.
                if !self.devices_is_current(&operation) {
                    return;
                }

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

                self.devices_refuse(sentence);
            }
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
        // The same three gates every other mutating verb passes, checked here rather than
        // at the key, so there is no path to the send that skips them.
        if self.devices_takeover_refused() {
            return;
        }

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

    /// Leaving another identity's setup alone: nothing is sent, and the buffer is gone.
    fn devices_decline_takeover(&mut self) {
        self.devices.forget_secret();
        self.devices.operation = None;
        self.devices.notice = Some(
            "That setup was left alone. It is still running under the identity that \
             started it."
                .into(),
        );
        self.devices.inventory.invalidate();
        self.poll_devices();
    }

    /// The takeover question's gate, applied before the answer rather than after it.
    fn devices_takeover_refused(&mut self) -> bool {
        let Some(refusal) =
            self.devices_deploy_refusal("fleet.deployment.resume", self.devices_local_setup())
        else {
            return false;
        };

        if let Some(operation) = self.devices.operation.as_mut() {
            operation.error = Some(refusal);
        }

        true
    }

    fn devices_is_current(&self, operation: &str) -> bool {
        self.devices
            .operation
            .as_ref()
            .is_some_and(|current| current.id == operation)
    }

    /// A refused action, said where the operator is looking.
    ///
    /// The notice alone was not enough: it draws at the *foot* of the inventory, below
    /// the device rows and the no-SSH sentence, and on a real screen with the cursor near
    /// the top that is off the page. A live run pressed Enter on "Set up this device" and
    /// saw nothing happen at all — no form, no sentence, no change. Whatever else a
    /// refusal does, it says so on the one row that is always drawn.
    fn devices_refuse(&mut self, sentence: String) {
        self.devices.refusal_line = Some(sentence.clone());
        self.devices.notice = Some(sentence);
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
        // `a` cannot be typed into a query and swallowed as verbs.
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

        let inventory = self.devices.inventory.value.as_ref();
        let rows = inventory
            .map(|inventory| self.devices.visible(inventory).len())
            .unwrap_or(0);
        // Below the threshold there is no search and no filter: the keys are not drawn,
        // and pressing them does nothing rather than silently narrowing a list of four.
        let narrowing = inventory.is_some_and(|inventory| self.devices.narrowing(inventory));

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.close_devices(),
            KeyCode::Char('r') => {
                self.devices.inventory.invalidate();
                self.devices.fallback.invalidate();
                self.devices.notice = None;
                self.devices.refusal_line = None;
                self.poll_devices();
            }
            KeyCode::Char('/') if narrowing => {
                self.devices.searching = true;
                self.devices.query.clear();
            }
            KeyCode::Char('f') if narrowing => {
                self.devices.filter = self.devices.filter.next();
                self.devices.cursor = 0;
            }
            KeyCode::Char('a') => self.devices_begin_manual(),
            KeyCode::Char('x') => self.devices_begin_leave(),
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

        let Some(row) = self.devices.selected(inventory).cloned() else {
            return;
        };

        // Only the row this operation is actually about acts on it, and which verb it is
        // depends on how the operation ended.
        if let Some(open) = inventory.open_operation_for(&row).cloned() {
            match open.resumption() {
                // A resume re-inspects and re-reviews, which is what makes offering it
                // after a failure safe: nothing is applied that has not been read again.
                Resumption::Continue | Resumption::Retry => {
                    self.devices_continue(&open);
                    return;
                }
                // The broker refuses to resume a cancelled operation, so the row falls
                // through to its ordinary action, which begins a fresh one.
                Resumption::DeployAgain | Resumption::None => {}
            }
        }

        match inventory.primary(&row) {
            Primary::Add => self.devices_begin_add(&row),
            Primary::SetUp => self.devices_begin_setup(&row),
            Primary::Open => self.devices_open_machine(&row),
            // A row with no button is a row Enter does nothing to. Its reason is already
            // on the screen, in the details panel under the list — saying it again in the
            // hint line would be this view telling somebody what they are looking at.
            Primary::None => {}
            // These two come from an operation on the row, and that branch is taken above.
            Primary::Continue | Primary::Retry => {}
        }
    }

    /// **Open**: a member's sessions are the Dashboard's machines panel, not this view.
    fn devices_open_machine(&mut self, row: &DeviceRow) {
        let label = self
            .devices
            .inventory
            .value
            .as_ref()
            .map(|inventory| inventory.row_label(row))
            .unwrap_or_else(|| scrub(&row.name, NAME_COLUMNS));

        self.close_devices();
        self.tab = Tab::Dashboard;
        self.inform(
            format!("{label} is in the fleet; its machines and sessions are on this panel.",),
            NoticeKind::Info,
        );
    }

    fn devices_local_setup(&self) -> bool {
        self.devices
            .operation
            .as_ref()
            .is_some_and(|operation| operation.kind.as_deref() == Some("setup"))
    }

    /// The three gates every mutating deployment verb passes, in words.
    ///
    /// One function rather than three checks at each call site: `prepare` had them and the
    /// continue path did not, so an operation in the journal was a way around all three —
    /// a read-scope listener issued `resume`, and a runtime holding no CA key attached a
    /// worker it had already said it could not run.
    fn devices_deploy_refusal(&self, method: &str, setup: bool) -> Option<String> {
        let inventory = self.devices.inventory.value.as_ref();
        let host = inventory
            .map(|inventory| inventory.host.clone())
            .unwrap_or_default();

        // First setup answers to a shorter list: see `DeploymentHost::setup_reasons`.
        let blocker = if setup {
            host.setup_blocker()
        } else if host.deploy {
            None
        } else {
            Some(
                inventory
                    .and_then(Inventory::deploy_blocker)
                    .unwrap_or_else(|| "This runtime cannot deploy from here.".into()),
            )
        };

        if let Some(blocker) = blocker {
            return Some(blocker);
        }

        if !self.hello.serves(method) {
            return Some(format!(
                "This runtime does not serve {method}, so there is no deployment worker \
                 behind that action here."
            ));
        }

        if self.hello.scope == "read" {
            return Some(Refusal::ReadScope.sentence());
        }

        None
    }
    fn devices_begin_add(&mut self, row: &DeviceRow) {
        if let Some(refusal) = self.devices_deploy_refusal("fleet.deployment.prepare", false) {
            self.devices_refuse(refusal);
            return;
        }

        let Some(inventory) = self.devices.inventory.value.as_ref() else {
            return;
        };

        let form = ConnectForm::add(inventory, row);
        self.devices_open_form(form);
    }

    /// `a`: *Add a device by address*, the same form with nothing pre-filled.
    ///
    /// The name is required here exactly as it is on the list path. Without a name field
    /// the worker took the address as the machine name and refused it, which is finding
    /// 2: a manual destination that could not succeed.
    fn devices_begin_manual(&mut self) {
        if let Some(refusal) = self.devices_deploy_refusal("fleet.deployment.prepare", false) {
            self.devices_refuse(refusal);
            return;
        }

        self.devices_open_form(ConnectForm::manual());
    }

    /// `x` on a member: take it out of the fleet.
    fn devices_begin_leave(&mut self) {
        let Some(inventory) = self.devices.inventory.value.as_ref() else {
            return;
        };

        let Some(row) = self.devices.selected(inventory).cloned() else {
            return;
        };

        if !row.removable() {
            self.devices_refuse(format!(
                "{} is not a member of this fleet, so there is nothing to remove it from.",
                inventory.row_label(&row)
            ));
            return;
        }

        if let Some(refusal) = self.devices_deploy_refusal("fleet.deployment.prepare", false) {
            self.devices_refuse(refusal);
            return;
        }

        let Some(inventory) = self.devices.inventory.value.as_ref() else {
            return;
        };

        let form = ConnectForm::leave(inventory, &row);
        self.devices_open_form(form);
    }

    /// "Set up this Mac": the first local fleet, which takes no target and no account.
    ///
    /// The same review and progress flow as an admission — it is the same worker and the
    /// same plan — with the SSH fields gone, because this machine does not reach itself
    /// over SSH. The spec is explicit about that, and the method now says so too.
    fn devices_begin_setup(&mut self, row: &DeviceRow) {
        if let Some(refusal) = self.devices_deploy_refusal("fleet.deployment.prepare", true) {
            self.devices_refuse(refusal);
            return;
        }

        let Some(inventory) = self.devices.inventory.value.as_ref() else {
            return;
        };

        let form = ConnectForm::setup(inventory, row);
        self.devices_open_form(form);
    }

    fn devices_open_form(&mut self, form: ConnectForm) {
        self.devices.notice = None;
        self.devices.refusal_line = None;
        self.devices.scroll = 0;
        self.devices.connect = Some(Box::new(form));
    }

    fn devices_continue(&mut self, open: &OperationSummary) {
        // The header names the machine the *operation* is about, from its own target —
        // never the row that was pressed. Those were the same thing only by accident, and
        // when they were not, a password prompt appeared under another machine's name.
        let device = open
            .target
            .as_ref()
            .map(OperationTarget::label)
            .unwrap_or_else(|| "a device this runtime could not name".into());

        let mut operation = Operation::new(open.operation.clone(), device);
        operation.kind = open.kind.clone();

        // A journal with no worker behind it needs one before it can be answered, and a
        // resume is a mutation like any other: the same three gates. A failed operation
        // always takes this path — its worker is gone by definition — which is how
        // "Retry" becomes a fresh inspection and a fresh review rather than a second go
        // at a plan nobody re-read.
        if !open.attached {
            if let Some(refusal) = self.devices_deploy_refusal(
                "fleet.deployment.resume",
                open.kind.as_deref() == Some("setup"),
            ) {
                self.devices.notice = Some(refusal);
                return;
            }

            operation.submitting = true;
            let id = operation.id.clone();
            self.devices.operation = Some(Box::new(operation));
            self.devices.scroll = 0;

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
        self.devices.scroll = 0;
        self.poll_devices();
    }

    fn devices_connect_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        let Some(form) = self.devices.connect.as_mut() else {
            return;
        };

        // A10: the rows of this form are numbered in screen-reader mode, so the numbers
        // select — except on a field where a digit is the value somebody is typing.
        // Selecting the submit row is pressing it: it is a button, not a field.
        let digit = (access::screen_reader() && !form.field.takes_digits())
            .then(|| access::row_for_digit(as_char(key.code)))
            .flatten()
            .and_then(|row| form.rows().get(row).copied());

        if let Some(field) = digit {
            form.field = field;
            form.error = None;

            match field {
                ConnectField::Submit => self.devices_prepare(),
                ConnectField::Advanced => self.devices_toggle_advanced(),
                _a_field => {}
            }

            return;
        }

        match key.code {
            KeyCode::Esc => {
                self.devices.connect = None;
                return;
            }
            KeyCode::Tab | KeyCode::Down => form.move_field(1),
            KeyCode::BackTab | KeyCode::Up => form.move_field(-1),
            KeyCode::Left | KeyCode::Right => match form.field {
                ConnectField::Service => form.service = !form.service,
                ConnectField::Advanced => {
                    let open = key.code == KeyCode::Right;
                    if form.advanced_open != open {
                        self.devices_toggle_advanced();
                    }
                    return;
                }
                _not_a_choice => {}
            },
            KeyCode::Backspace => {
                if let Some(text) = form.text_mut() {
                    text.pop();
                }
            }
            KeyCode::Enter => {
                match form.field {
                    ConnectField::Submit => self.devices_prepare(),
                    ConnectField::Advanced => self.devices_toggle_advanced(),
                    // Enter in a field moves, and never submits: finishing a sentence in
                    // a text box is not a decision to reach out to another machine.
                    _a_field => form.move_field(1),
                }
                return;
            }
            KeyCode::Char(character) => match form.text_mut() {
                Some(text) => text.push(character),
                // A row that takes no text still has one key worth having on it.
                None if character == ' ' => match form.field {
                    ConnectField::Service => form.service = !form.service,
                    ConnectField::Advanced => {
                        self.devices_toggle_advanced();
                        return;
                    }
                    _nothing_to_toggle => {}
                },
                None => {}
            },
            _other => {}
        }

        if let Some(form) = self.devices.connect.as_mut() {
            form.error = None;
        }
    }

    /// Open or close the Advanced disclosure, keeping the cursor on a row that is drawn.
    fn devices_toggle_advanced(&mut self) {
        let Some(form) = self.devices.connect.as_mut() else {
            return;
        };

        form.advanced_open = !form.advanced_open;
        form.error = None;

        // The cursor goes where the eye does: into the fields that just appeared, or on
        // to the button when they have just gone. Leaving it on the disclosure is how
        // Enter stops walking the form and starts flipping one row back and forth.
        form.field = match (form.advanced_open, form.advanced_fields().first()) {
            (true, Some(first)) => *first,
            _closed_or_empty => ConnectField::Submit,
        };
    }

    /// Whether a password or passphrase challenge currently owns the keyboard.
    pub(super) fn devices_secret_open(&self) -> bool {
        self.devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref())
            .and_then(Snapshot::challenge)
            .is_some_and(|challenge| matches!(challenge.kind.as_str(), "password" | "passphrase"))
    }

    /// A bracketed paste, into whichever field this view has open.
    ///
    /// Returns whether anything took it, which is what decides the "nothing here is
    /// taking text" notice. The secret buffer is preferred when a secret challenge is the
    /// screen: that is the only field drawn at the time.
    pub(super) fn devices_paste(&mut self, flattened: &str) -> bool {
        let challenge = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref())
            .and_then(Snapshot::challenge)
            .cloned();

        if let Some(challenge) = challenge {
            if matches!(challenge.kind.as_str(), "password" | "passphrase") {
                let Some(operation) = self.devices.operation.as_mut() else {
                    return false;
                };

                if operation.submitting {
                    return false;
                }

                // The same buffer discipline a typed character gets: a paste for one
                // question never lands in the next one's field.
                if operation.answering.as_deref() != Some(challenge.id.as_str()) {
                    operation.secret.clear();
                    operation.answering = Some(challenge.id.clone());
                }

                for character in flattened.chars() {
                    operation.secret.push(character);
                }

                return true;
            }

            return false;
        }

        match self.devices.connect.as_mut() {
            Some(form) => match form.text_mut() {
                Some(text) => {
                    text.push_str(flattened);
                    true
                }
                None => false,
            },
            None => false,
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
            let digit = access::screen_reader()
                .then(|| access::row_for_digit(as_char(key.code)))
                .flatten();

            match key.code {
                // A10: a numbered menu answers to its numbers, in the mode that draws them.
                _ if digit == Some(0) || matches!(key.code, KeyCode::Char('t')) => {
                    self.devices_take_over()
                }
                _ if digit == Some(1) => self.devices_decline_takeover(),
                KeyCode::Char('n') | KeyCode::Esc => self.devices_decline_takeover(),
                // Enter is not an answer to this question. There is no default: the whole
                // point of the prompt is that taking somebody else's setup is a decision
                // somebody made on purpose.
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

        // A question whose answer is already on its way takes no more keystrokes. The
        // guard used to be on the *submit* alone, so a second secret could be typed into
        // a field whose answer was in flight — bytes with nowhere to go, in a buffer
        // whose whole purpose is to hold as little as possible for as short a time as
        // possible. Esc still works: leaving is always available.
        if operation.submitting && !matches!(key.code, KeyCode::Esc) {
            return;
        }

        // The same belt-and-braces as the submit guard above, and untestable for the same
        // reason: the snapshot arm already clears the buffer the moment the open
        // challenge id changes, so by the time a keystroke arrives the rebinding has
        // nothing left to clear. Kept because it is what makes this function correct on
        // its own terms rather than by relying on its caller having run first.
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

        // Redundant with the guard in `devices_secret_key` and the one in
        // `devices_paste`, which between them stop the buffer being filled at all while
        // an answer is in flight — so no input reaches here with both `submitting` and a
        // non-empty buffer, and no test can distinguish this line being present from it
        // being absent (the review's mutation of it survives, and that is why). It stays
        // because it is the last line before the send: a path added later that fills the
        // buffer some other way should meet a closed door here rather than a second
        // `authenticate` for one question.
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

        let digit = access::screen_reader()
            .then(|| access::row_for_digit(as_char(key.code)))
            .flatten();

        match key.code {
            // Trust is typed in full. There is no default answer and no Enter that
            // accepts: a host key is confirmed by an operator who read the fingerprint.
            // A10: in the mode that numbers the two answers, the numbers answer.
            _ if digit == Some(0) => self.devices_confirm_host(challenge, true),
            KeyCode::Char('t') => self.devices_confirm_host(challenge, true),
            _ if digit == Some(1) => self.devices_confirm_host(challenge, false),
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

        // The mismatch screen draws one answer, `c`, and numbers it first; the ordinary
        // screen draws `a` then `c`. The digit means the row it is next to on the screen
        // the operator is actually reading.
        let approvable = challenge.plan().is_some_and(|plan| {
            challenge.claimed_digest().as_deref() == Some(plan.digest.as_str())
        });
        let digit = access::screen_reader()
            .then(|| access::row_for_digit(as_char(key.code)))
            .flatten();

        match key.code {
            _ if digit == Some(0) && approvable => self.devices_approve(challenge),
            _ if digit == Some(0) => self.devices_cancel(),
            _ if digit == Some(1) && approvable => self.devices_cancel(),
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
        // What is approved is the digest of the plan that was *drawn*, computed here.
        // Taking the challenge's claim would approve a number with no established
        // relationship to anything on the screen: swap the plan under a challenge that
        // keeps its digest and the operator reviews one deployment and authorises
        // another, with nothing to notice.
        let Some(plan) = challenge.plan() else {
            if let Some(operation) = self.devices.operation.as_mut() {
                operation.error = Some(
                    "This client could not read the plan this operation is holding, so \
                     there is nothing here it can approve."
                        .into(),
                );
            }
            return;
        };

        if challenge.claimed_digest().as_deref() != Some(plan.digest.as_str()) {
            if let Some(operation) = self.devices.operation.as_mut() {
                operation.error = Some(
                    "The plan on this screen is not the plan the runtime is asking you to \
                     approve: the two digests disagree. Nothing was sent. Cancel the setup \
                     and start it again."
                        .into(),
                );
            }
            return;
        }

        let Some(operation) = self.devices.operation.as_mut() else {
            return;
        };

        if operation.submitting {
            return;
        }

        operation.submitting = true;
        operation.error = None;

        let id = operation.id.clone();
        let key = operation.idempotency_key(&plan.digest);

        self.issue(Call::new(
            Tag::Devices(DevicesTag::Answer {
                operation: id.clone(),
                label: "fleet.deployment.start",
            }),
            "fleet.deployment.start",
            json!({
                "operation_id": id,
                "plan_digest": plan.digest,
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
        let snapshot = self
            .devices
            .operation
            .as_ref()
            .and_then(|operation| operation.snapshot.value.as_ref());

        let state = snapshot
            .map(|snapshot| snapshot.state.clone())
            .unwrap_or_default();

        // A worker that is gone is a stopped operation whatever its last written state
        // says: the live failure left one reading `inspecting` forever, with the reason
        // in a log nobody on this screen could see. It is resumed like any other.
        let stopped = snapshot.is_some_and(|snapshot| snapshot.worker_exit.is_some());

        // A failure is resumed by its own id: the worker inspects again and puts the plan
        // up for review again, so pressing this cannot apply anything unreviewed. Only a
        // *cancelled* or *completed* operation goes back to the list, because the broker
        // will not resume either.
        if state == "failed" || (stopped && !matches!(state.as_str(), "cancelled" | "completed")) {
            if let Some(refusal) =
                self.devices_deploy_refusal("fleet.deployment.resume", self.devices_local_setup())
            {
                if let Some(operation) = self.devices.operation.as_mut() {
                    operation.error = Some(refusal);
                }
                return;
            }

            let Some(operation) = self.devices.operation.as_mut() else {
                return;
            };

            if operation.submitting {
                return;
            }

            operation.submitting = true;
            operation.error = None;
            operation.takeover = None;
            let id = operation.id.clone();
            self.devices.scroll = 0;

            self.issue(Call::new(
                Tag::Devices(DevicesTag::Resume {
                    operation: id.clone(),
                }),
                "fleet.deployment.resume",
                json!({ "operation_id": id }),
            ));

            return;
        }

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

/// The one quiet line that says whose machine does the work, and as whom.
///
/// On every screen of the flow, because a credential typed into the wrong host's prompt
/// is the failure it exists to prevent — but *one line*, under the title, rather than the
/// boxed paragraph that opened every screen before it.
fn actions_line(app: &App) -> String {
    app.devices
        .inventory
        .value
        .as_ref()
        .map(|inventory| inventory.host.actions_line())
        .unwrap_or_else(|| "Actions run on the machine hosting this runtime.".into())
}

fn caption(app: &App, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(
        actions_line(app),
        Style::default().fg(theme::muted()),
    )));
}

fn blank(lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
}

fn inventory_lines(app: &App, lines: &mut Vec<Line<'static>>) {
    let state = &app.devices;

    lines.push(Line::from(Span::styled("Devices", theme::heading())));

    if let Some(refusal) = state.refusal.as_ref() {
        lines.push(Line::from(Span::styled(
            access::speakable(&refusal.sentence()),
            Style::default().fg(theme::warn()),
        )));
        blank(lines);
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

    // The status line *is* the blocker sentence for a standalone host: §5.1 is explicit
    // that "This Mac is not in a fleet yet" replaces a second paragraph saying so.
    lines.push(Line::from(Span::styled(
        inventory.status_line(),
        Style::default().fg(if inventory.standalone() {
            theme::accent()
        } else {
            theme::good()
        }),
    )));
    caption(app, lines);

    // One inline notice with the client's own words, never a claim about build age.
    if let Some(notice) = inventory.discovery.notice() {
        lines.push(Line::from(Span::styled(
            access::speakable(&scrub(&notice, MESSAGE_COLUMNS)),
            Style::default().fg(theme::warn()),
        )));
    }

    // Everything that stops an action, said once, above the list rather than on each row.
    // On a machine with no fleet the status line already says it is not in one, so what
    // is left to say here is whatever *else* stops a first setup.
    let blocker = if inventory.standalone() {
        inventory.host.setup_blocker()
    } else {
        inventory.deploy_blocker()
    };

    if let Some(blocker) = blocker {
        lines.push(Line::from(Span::styled(
            access::speakable(&scrub(&blocker, MESSAGE_COLUMNS)),
            Style::default().fg(theme::warn()),
        )));
    }

    if state.narrowing(inventory) {
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
    }

    blank(lines);

    let rows = state.visible(inventory);

    if rows.is_empty() {
        lines.push(Line::from(Span::styled(
            empty_sentence(app),
            Style::default().fg(theme::muted()),
        )));
    }

    for (index, row) in rows.iter().enumerate() {
        row_line(app, inventory, row, index, lines);
    }

    // The details of the selected row, under the list, where the facts that used to need
    // five more lines per device now live once.
    if let Some(row) = state.selected(inventory) {
        blank(lines);
        details_lines(inventory, row, lines);
    }

    blank(lines);
    lines.push(Line::from(Span::styled(
        access::speakable("Not listed?  a  Add a device by address"),
        Style::default().fg(theme::action_colour()),
    )));

    if !inventory.unknown.is_empty() {
        lines.push(Line::from(Span::styled(
            format!(
                "this runtime also reported {}, which this client does not read",
                inventory.unknown.join(", ")
            ),
            Style::default().fg(theme::muted()),
        )));
    }

    if let Some(notice) = state.notice.as_ref() {
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::speakable(notice),
            Style::default().fg(theme::accent()),
        )));
    }
}

/// What an empty list says. The distinct discovery failures keep their own sentences.
fn empty_sentence(app: &App) -> String {
    let state = &app.devices;
    let Some(inventory) = state.inventory.value.as_ref() else {
        return "nothing to show".to_string();
    };

    if state.narrowing(inventory) && (!state.query.is_empty() || state.filter != Filter::All) {
        return "no device here matches the filter and search in force".to_string();
    }

    match inventory.discovery.detail.as_deref() {
        Some(detail) => format!("{} \u{2014} {detail}", inventory.discovery.headline()),
        None => inventory.discovery.headline(),
    }
}

/// How many columns a device's own name may occupy.
///
/// Narrow on purpose, and followed by explicit column boundaries. A name is the one field
/// on the row that an attacker chooses outright, and a wide one runs into the column
/// beside it: `hostile-names.json` carries a name whose text is a forged device row, and
/// the answer is that the name column *ends*, visibly, well before anything this client
/// wrote. What follows is always this build's words.
const NAME_COLUMNS: usize = 18;

/// How many columns a device's other fields may occupy. Also a device's choice.
const ROW_FIELD_COLUMNS: usize = 44;

/// How many columns a line this build composed may occupy.
///
/// Wider, because the words are this client's: a remote string inside one has already
/// been bounded on the way in, and holding the whole sentence to a hostile name's budget
/// only truncates the part that says what is going on.
const OWN_WORDS_COLUMNS: usize = 96;

/// "macOS", "linux", "iOS": five is the widest the network client reports.
const OS_COLUMNS: usize = 5;
const ADDRESS_COLUMNS: usize = 16;
/// "○ offline, seen 3 days ago" is twenty-six columns; "● online" is the other shape.
const PRESENCE_COLUMNS: usize = 28;
const STATE_COLUMNS: usize = 30;

/// One cell of the list, bounded to its width and padded out to it.
///
/// Every column goes through here, including the ones this build composed. The column
/// boundary has to be a fact about the row rather than an alignment the longest value
/// happens to respect: a presence string that overran its cell used to push the Ouroboros
/// column along, and a name that can move a column is a name that can forge a row.
fn column(value: &str, columns: usize) -> String {
    format!("{:<width$}", scrub(value, columns), width = columns + 2)
}

/// The columns a full-width row needs: marker, name, OS, address, presence, state and
/// the widest action label. Below this the row is drawn on two lines on purpose, because
/// a Paragraph wrapping one long line puts "seen 3 days" on one row and "ago" on the
/// next, in the wrong column.
const FULL_ROW_COLUMNS: usize = 2
    + NAME_COLUMNS
    + 4
    + OS_COLUMNS
    + 2
    + ADDRESS_COLUMNS
    + 2
    + PRESENCE_COLUMNS
    + 2
    + STATE_COLUMNS
    + 2
    + 15;

/// The columns the Devices overlay has for a line: 92 % of the frame inside a border,
/// which is how `view::devices` sizes it. Zero before the first frame reads as wide, so a
/// test that never drew a frame sees the one-line row.
fn overlay_columns(app: &App) -> usize {
    match app.terminal_width {
        0 => usize::MAX,
        width => (usize::from(width) * 92 / 100).saturating_sub(2),
    }
}

/// Whether the list has to fold each row onto two lines to fit.
pub fn narrow_rows(app: &App) -> bool {
    overlay_columns(app) < FULL_ROW_COLUMNS
}

/// One device, one line: name, OS, address, presence, Ouroboros, and the one thing you
/// can do about it. On a narrow terminal, two lines: the name, address and presence on
/// the first (which carries the cursor marker), the Ouroboros word and the action on the
/// second, indented under the name.
fn row_line(
    app: &App,
    inventory: &Inventory,
    row: &DeviceRow,
    index: usize,
    lines: &mut Vec<Line<'static>>,
) {
    let selected = app.devices.cursor == index;
    let marker = if selected { "> " } else { "  " };
    let name = access::numbered(index, &inventory.row_label(row));
    let primary = inventory.primary(row);
    let narrow = narrow_rows(app);

    let name_span = Span::styled(
        // Four spare columns rather than two: screen-reader mode puts "10. " in front
        // of the name, and a number that pushed the OS column along would undo the
        // boundary the narrow name column exists to draw.
        format!("{marker}{name:<width$}", width = NAME_COLUMNS + 4),
        if selected {
            Style::default()
                .fg(theme::accent())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        },
    );
    let os_span = Span::styled(
        column(row.os.as_deref().unwrap_or("?"), OS_COLUMNS),
        Style::default().fg(theme::muted()),
    );
    let address_span = Span::styled(
        column(
            row.address.as_deref().unwrap_or("no address"),
            ADDRESS_COLUMNS,
        ),
        Style::default(),
    );
    let presence_span = Span::styled(
        column(&row.presence_short(), PRESENCE_COLUMNS),
        Style::default().fg(if row.online == Some(true) {
            theme::good()
        } else {
            theme::muted()
        }),
    );
    let state_span = Span::styled(
        column(&inventory.ouroboros_word(row), STATE_COLUMNS),
        Style::default(),
    );
    let action_span = Span::styled(
        primary.label(inventory.host.self_label()),
        Style::default().fg(if primary == Primary::None {
            theme::muted()
        } else {
            theme::action_colour()
        }),
    );

    if narrow {
        // The last cell of a line is not padded: the pane wraps a trailing run of
        // spaces onto a blank row of its own, which read as a third line per device.
        let presence_end = Span::styled(
            scrub(&row.presence_short(), PRESENCE_COLUMNS),
            presence_span.style,
        );
        lines.push(Line::from(vec![name_span, address_span, presence_end]));
        lines.push(Line::from(vec![
            Span::raw("      "),
            state_span,
            action_span,
        ]));
        return;
    }

    lines.push(Line::from(vec![
        name_span,
        os_span,
        address_span,
        presence_span,
        state_span,
        action_span,
    ]));
}

/// The three or four lines under the list: everything about the selected row that does
/// not belong on it.
fn details_lines(inventory: &Inventory, row: &DeviceRow, lines: &mut Vec<Line<'static>>) {
    let mut where_it_is = vec![scrub(
        row.address.as_deref().unwrap_or("no address"),
        ROW_FIELD_COLUMNS,
    )];

    if let Some(path) = row.path.as_deref() {
        where_it_is.push(scrub(path, ROW_FIELD_COLUMNS));
    }
    if let Some(machine) = row.machine.as_deref() {
        where_it_is.push(format!("in the roster as {}", scrub(machine, NAME_COLUMNS)));
    }

    detail_field(lines, "address", where_it_is.join(" \u{b7} "));
    // The *exact* time lives here. The row carries a relative one; this is the fact.
    detail_field(lines, "presence", row.presence());

    if let Some(facts) = row.runtime_facts() {
        detail_field(lines, "runtime", scrub(&facts, OWN_WORDS_COLUMNS));
    }

    if let Some(summary) = latest_operation_for(inventory, row) {
        let mut parts = vec![scrub(&summary.operation, OWN_WORDS_COLUMNS)];

        parts.push(
            summary
                .state
                .as_deref()
                .map(operation_state)
                .unwrap_or_else(|| "state not recorded".into()),
        );

        if let Some(owner) = summary.owner.as_deref() {
            parts.push(format!("started by {}", scrub(owner, ROW_FIELD_COLUMNS)));
        }
        if let Some(updated) = summary.updated_at.as_deref() {
            parts.push(scrub(updated, ROW_FIELD_COLUMNS));
        }

        detail_field(lines, "last setup", parts.join(" \u{b7} "));
    }

    // Why there is no button, said once, where somebody who pressed Enter will look.
    //
    // This row's own reason only. A blocker that belongs to the *host* is true of every
    // row at once, so it is the line above the list; repeating it here would be the same
    // fact twice on one screen, which is what finding 9 is about.
    if let Some(reason) = row.no_action_reason() {
        lines.push(Line::from(Span::styled(
            format!("  {}", access::speakable(&scrub(&reason, MESSAGE_COLUMNS))),
            Style::default().fg(theme::muted()),
        )));
    }

    // Never merged into the row it collides with. A device that adopts a member's name is
    // either a mistake worth fixing or an attempt to be mistaken for it, and listing it
    // as an ordinary peer says neither.
    if let Some(machine) = row.name_conflict.as_ref() {
        lines.push(Line::from(Span::styled(
            format!(
                "  this device calls itself {}, which is the name of a machine in this \
                 fleet at a different address. It is not that machine.",
                scrub(machine, NAME_COLUMNS)
            ),
            Style::default().fg(theme::warn()),
        )));
    }

    if row.removable() {
        lines.push(Line::from(Span::styled(
            format!(
                "  x  Remove {} from the fleet",
                scrub(row.machine.as_deref().unwrap_or_default(), NAME_COLUMNS)
            ),
            Style::default().fg(theme::action_colour()),
        )));
    }
}

fn detail_field(lines: &mut Vec<Line<'static>>, label: &str, value: String) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {label:<12}"), theme::label()),
        Span::styled(value, Style::default()),
    ]));
}

fn latest_operation_for<'a>(
    inventory: &'a Inventory,
    row: &DeviceRow,
) -> Option<&'a OperationSummary> {
    inventory
        .operations
        .iter()
        .filter(|operation| {
            !operation.operation.is_empty()
                && operation
                    .target
                    .as_ref()
                    .is_some_and(|target| target.is(row))
        })
        .max_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.created_at.cmp(&right.created_at))
                .then_with(|| left.operation.cmp(&right.operation))
        })
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

// ------------------------------------------------------------------------- the forms

fn connect_lines(app: &App, form: &ConnectForm, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(form.heading(), theme::heading())));
    caption(app, lines);
    blank(lines);

    if form.kind == FormKind::Setup {
        lines.push(Line::from(Span::styled(
            "This is the first fleet on this machine. It configures itself, without SSH \
             to itself, so there is no account and no host key to verify here. The plan \
             is reviewed exactly like any other.",
            Style::default().fg(theme::muted()),
        )));
        blank(lines);
    }

    if form.kind == FormKind::Leave {
        lines.push(Line::from(Span::styled(
            format!(
                "Stops Ouroboros on {}, retires its credentials and takes it out of every \
                 roster. Its sessions and data stay on that machine.",
                form.device
            ),
            Style::default().fg(theme::muted()),
        )));
        blank(lines);
    }

    for (index, field) in form.rows().iter().copied().enumerate() {
        let selected = form.field == field;
        let marker = if selected { "> " } else { "  " };

        let style = |selected: bool| {
            if selected {
                Style::default()
                    .fg(theme::accent())
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            }
        };

        match field {
            ConnectField::Advanced => {
                blank(lines);
                lines.push(Line::from(Span::styled(
                    format!(
                        "{marker}{}",
                        access::numbered(
                            index,
                            &format!(
                                "{} Advanced \u{2014} {}",
                                if form.advanced_open {
                                    "\u{25be}"
                                } else {
                                    "\u{25b8}"
                                },
                                form.advanced_fields()
                                    .iter()
                                    .map(|field| field.label())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        )
                    ),
                    style(selected),
                )));
                continue;
            }
            ConnectField::Submit => {
                blank(lines);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{marker}{}", access::numbered(index, form.submit_label())),
                        style(selected),
                    ),
                    Span::styled(
                        format!("   {}", form.submit_hint()),
                        Style::default().fg(theme::muted()),
                    ),
                ]));
                continue;
            }
            _a_field => {}
        }

        let value = form.value(field);
        let shown = if value.is_empty() {
            match field {
                ConnectField::User => "(required)".to_string(),
                ConnectField::Machine => "(required)".to_string(),
                ConnectField::Address => "(required)".to_string(),
                _optional => "(the target's default)".to_string(),
            }
        } else {
            value
        };

        let mut spans = vec![
            Span::styled(
                format!(
                    "{marker}{}",
                    access::numbered(index, &format!("{:<20}", field.label()))
                ),
                if selected {
                    theme::label().add_modifier(Modifier::BOLD)
                } else {
                    theme::label()
                },
            ),
            Span::styled(
                scrub(&shown, ROW_FIELD_COLUMNS),
                if selected {
                    Style::default().fg(theme::accent())
                } else {
                    Style::default()
                },
            ),
        ];

        if let Some(hint) = form.hint(field) {
            spans.push(Span::styled(
                format!("   {}", scrub(&hint, OWN_WORDS_COLUMNS)),
                Style::default().fg(theme::muted()),
            ));
        }

        lines.push(Line::from(spans));
    }

    // A read-only address is still a fact about where this is going, so it is drawn even
    // though the cursor does not stop on it.
    if !form.address.is_empty() && form.address_fixed && form.kind == FormKind::Leave {
        detail_field(lines, "address", scrub(&form.address, ROW_FIELD_COLUMNS));
    }

    blank(lines);
    lines.push(Line::from(Span::styled(
        match form.kind {
            FormKind::Setup => {
                "No password is typed on this screen. If this setup needs one, it is asked \
                 for as its own question."
            }
            _over_ssh => {
                "The default SSH identity is used. No password is typed on this screen: if \
                 the target asks for one, it is asked for as its own question."
            }
        },
        Style::default().fg(theme::muted()),
    )));

    if let Some(error) = form.error.as_ref() {
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }
}

// --------------------------------------------------------------------- the operation

/// The heading an operation draws, from its own kind and target.
fn operation_heading(operation: &Operation) -> String {
    let verb = match operation.kind.as_deref() {
        Some("setup") => "Setting up",
        Some("leave") => "Removing",
        _add => "Adding",
    };

    format!(
        "{verb} {} \u{b7} operation {}",
        operation.device, operation.id
    )
}

fn operation_lines(app: &App, operation: &Operation, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(Span::styled(
        operation_heading(operation),
        theme::heading(),
    )));
    caption(app, lines);

    if let Some(takeover) = operation.takeover.as_ref() {
        takeover_lines(operation, takeover, lines);
        return;
    }

    // Finding 4. The runtime this client is attached to is gone — a local setup stops it
    // by design — so whatever snapshot is in hand describes a moment that has passed.
    // Drawing it as if it were current is the failure; so is spinning on it forever.
    let live = matches!(app.connection, Connection::Live);

    if !live || operation.stale {
        blank(lines);
        lines.push(Line::from(Span::styled(
            if live {
                "Ouroboros is back\u{2026} reading this setup again"
            } else {
                "Ouroboros is restarting\u{2026} reconnecting"
            },
            Style::default().fg(theme::accent()),
        )));
        lines.push(Line::from(Span::styled(
            format!(
                "The setup keeps running on the deployment host; its worker is detached \
                 from this connection. This view reads operation {} again by its id and \
                 carries on from whatever it says.",
                operation.id
            ),
            Style::default().fg(theme::muted()),
        )));

        if let Some(error) = operation.error.as_ref() {
            blank(lines);
            lines.push(Line::from(Span::styled(
                access::speakable(error),
                Style::default().fg(theme::bad()),
            )));
        }

        return;
    }

    let Some(snapshot) = operation.snapshot.value.as_ref() else {
        blank(lines);
        lines.push(Line::from(Span::styled(
            match operation.snapshot.error.as_ref() {
                Some(error) => format!("this operation could not be read: {error}"),
                None => "reading this operation".to_string(),
            },
            Style::default().fg(theme::muted()),
        )));
        return;
    };

    match snapshot.challenge() {
        Some(challenge) if challenge.kind == "host_trust" => host_trust_lines(challenge, lines),
        Some(challenge) if challenge.kind == "review" => review_lines(challenge, lines),
        Some(challenge) if challenge.kind == "password" || challenge.kind == "passphrase" => {
            secret_lines(operation, challenge, lines)
        }
        Some(challenge) => {
            blank(lines);
            lines.push(Line::from(Span::styled(
                format!(
                    "This operation is asking a {} question, which this client does not \
                     know how to answer.",
                    challenge.kind
                ),
                Style::default().fg(theme::warn()),
            )));
        }
        None if snapshot.terminal() => finish_lines(app, operation, snapshot, lines),
        None => progress_lines(operation.kind.as_deref(), snapshot, lines),
    }

    if let Some(error) = operation.error.as_ref() {
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }
}

/// "Take over this setup?" — never a silent retry.
fn takeover_lines(operation: &Operation, takeover: &Takeover, lines: &mut Vec<Line<'static>>) {
    blank(lines);
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
    blank(lines);
    lines.push(Line::from(Span::styled(
        access::speakable(
            "This setup belongs to another identity. Taking it over attaches a worker \
             under yours, so every credential this deployment asks for from now on is \
             asked of you \u{2014} you would be inheriting someone else's password prompt. \
             The runtime records who took what from whom.",
        ),
        Style::default().fg(theme::warn()),
    )));
    blank(lines);
    lines.push(Line::from(Span::styled(
        access::numbered(0, "t  Take over this setup"),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "n  Leave it alone"),
        Style::default().fg(theme::action_colour()),
    )));

    if let Some(error) = operation.error.as_ref() {
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }
}

/// §5.2 step 4: the strip, the current step's detail, and the worker's own steps.
fn progress_lines(kind: Option<&str>, snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    blank(lines);
    stage_strip(kind, snapshot, lines);
    state_line(snapshot, lines);

    if let Some(detail) = snapshot.current_detail() {
        lines.push(Line::from(Span::styled(
            format!("  {}", scrub(&detail, OWN_WORDS_COLUMNS)),
            Style::default().fg(theme::muted()),
        )));
    }

    lines.push(Line::from(vec![
        Span::styled("  reported by ", theme::label()),
        Span::styled(source_words(snapshot), Style::default().fg(theme::muted())),
    ]));

    steps_lines(snapshot, lines);
}

fn source_words(snapshot: &Snapshot) -> String {
    match snapshot.source.as_str() {
        "worker" => "a live worker".to_string(),
        "journal" => "the journal; no worker is attached".to_string(),
        other => format!("something this client does not recognise ({other})"),
    }
}

fn stage_strip(kind: Option<&str>, snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    let stages = snapshot.stages(kind);
    let mut spans = vec![Span::styled("  ", Style::default())];

    for (index, (name, marker)) in stages.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                " \u{b7} ",
                Style::default().fg(theme::muted()),
            ));
        }

        let colour = match marker {
            Marker::Done => theme::good(),
            Marker::Current => theme::accent(),
            Marker::Failed => theme::bad(),
            Marker::Pending | Marker::NotChecked => theme::muted(),
        };

        // A glyph is not what a screen reader announces, so in that mode the mark is the
        // word it stands for. "Not checked" is written out in both modes: a dash nobody
        // has a key for is exactly as silent as the tick it replaces.
        let mark = if access::screen_reader() {
            format!("{name} {}", marker.word())
        } else if *marker == Marker::NotChecked {
            format!("{} {name} ({})", marker.glyph(), marker.word())
        } else {
            format!("{} {name}", marker.glyph())
        };

        spans.push(Span::styled(mark, Style::default().fg(colour)));
    }

    lines.push(Line::from(spans));
}

/// The broker's own state, in words. Only where it is the live answer: a worker that has
/// stopped leaves a state field describing the step it was on, and drawing that under a
/// failure would be the screen saying it is still inspecting something.
fn state_line(snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(vec![
        Span::styled("  state       ", theme::label()),
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
}

fn steps_lines(snapshot: &Snapshot, lines: &mut Vec<Line<'static>>) {
    if snapshot.steps.is_empty() {
        return;
    }

    blank(lines);
    lines.push(Line::from(Span::styled("Steps", theme::label())));

    for step in &snapshot.steps {
        // The five the engine actually writes: `ok`, `failed`, `skipped`, `started` and
        // `running`. `skipped` is not a failure — a step that was not needed is a step
        // that was not needed — and it used to be painted the same grey as "in progress".
        let colour = match step.outcome.as_str() {
            "ok" => theme::good(),
            "failed" => theme::bad(),
            "skipped" => theme::muted(),
            "started" | "running" => theme::accent(),
            _unknown => theme::muted(),
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
    blank(lines);
    lines.push(Line::from(Span::styled(
        format!(
            "First time connecting to {}",
            challenge.field("address").unwrap_or_else(unknown)
        ),
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

    blank(lines);
    lines.push(Line::from(Span::styled(
        "Verify this fingerprint independently \u{2014} on the device itself, or from \
         however it was provisioned \u{2014} before trusting it. Discovery is not host-key \
         authentication, and a key that matches nothing you can check is a key you cannot \
         trust.",
        Style::default().fg(theme::warn()),
    )));
    blank(lines);
    lines.push(Line::from(Span::styled(
        access::numbered(0, "t  Trust and continue"),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "n  Cancel"),
        Style::default().fg(theme::action_colour()),
    )));
}

fn secret_lines(operation: &Operation, challenge: &Challenge, lines: &mut Vec<Line<'static>>) {
    blank(lines);

    let (heading, subject) = if challenge.kind == "passphrase" {
        (
            "Passphrase for a private key".to_string(),
            vec![
                ("key", challenge.field("key_label")),
                ("fingerprint", challenge.field("public_fingerprint")),
            ],
        )
    } else {
        (
            match (challenge.field("user"), challenge.field("target")) {
                (Some(user), Some(target)) => format!("Password for {user}@{target}"),
                (Some(user), None) => format!("Password for {user}"),
                _unstated => "Password for this connection".to_string(),
            },
            vec![
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

    blank(lines);
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
    blank(lines);
    lines.push(Line::from(Span::styled(
        "Typed here and sent once, to this question only. It is not stored, not echoed, \
         not written to a log, and not kept for a reconnection. Enter sends it; Esc \
         clears it and leaves the setup running.",
        Style::default().fg(theme::muted()),
    )));
}

/// §5.2 step 3: five plain lines, the digest, and two answers.
///
/// Every line is built here, from a decoded field, rather than by splitting a rendered
/// block on newlines: a `machine` carrying its own newlines and column padding is how a
/// plan forges an aligned row saying the grants are routine, and a plan that can add rows
/// to its own review is a plan nobody has read.
fn review_lines(challenge: &Challenge, lines: &mut Vec<Line<'static>>) {
    blank(lines);

    // The plan is read before the heading is written, because the heading is one of the
    // things the plan says. "Ready to deploy" over a removal, answered by `a Deploy`, is
    // this screen describing the opposite of what approving it does — which is what a
    // live "Remove from fleet" against a Raspberry Pi was asked to confirm.
    let plan = challenge.plan();
    let (heading, approve) = review_words(plan.as_ref().map(|plan| plan.kind.as_str()));

    lines.push(Line::from(Span::styled(heading, theme::heading())));

    let Some(plan) = plan else {
        lines.push(Line::from(Span::styled(
            "This client could not read the plan this operation is holding, so there is \
             nothing here to review. Cancel the setup rather than approving a plan nobody \
             has read.",
            Style::default().fg(theme::bad()),
        )));
        return;
    };

    lines.push(Line::from(Span::styled(
        plan.header(),
        Style::default().fg(theme::muted()),
    )));
    blank(lines);

    for sentence in plan.review_lines() {
        lines.push(Line::from(Span::styled(
            format!("  {}", access::speakable(&sentence)),
            Style::default(),
        )));
    }

    blank(lines);
    lines.push(Line::from(vec![
        Span::styled("  digest        ", theme::label()),
        Span::styled(plan.digest.clone(), Style::default().fg(theme::muted())),
    ]));

    // The digest this client computed over the document it drew, against the one the
    // challenge claims. They are the same number in every honest case; when they are not,
    // one of them describes a plan that is not on this screen, and neither is approved.
    let claimed = challenge.claimed_digest();

    if claimed.as_deref() != Some(plan.digest.as_str()) {
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::speakable(&format!(
                "This plan's digest does not match the one the runtime is asking you to \
                 approve ({}). The plan on this screen is not the plan that would be \
                 applied, so it cannot be approved from here. Cancel the setup and start \
                 it again.",
                claimed
                    .as_deref()
                    .unwrap_or("which it did not state as a digest")
            )),
            Style::default().fg(theme::bad()),
        )));
        blank(lines);
        lines.push(Line::from(Span::styled(
            access::numbered(0, "c  Cancel"),
            Style::default().fg(theme::action_colour()),
        )));
        return;
    }

    blank(lines);
    lines.push(Line::from(Span::styled(
        access::numbered(
            0,
            &format!("a  {approve} \u{2014} applies exactly this plan"),
        ),
        Style::default().fg(theme::action_colour()),
    )));
    lines.push(Line::from(Span::styled(
        access::numbered(1, "c  Cancel"),
        Style::default().fg(theme::action_colour()),
    )));
}

/// The review screen's heading and the word on its `a` key, from the plan's own kind.
///
/// One place, because the heading, the button and the footer hint are three renderings of
/// the same fact and a surface where two of them agree is worse than one where none do.
/// An unreadable plan keeps the neutral words: this client will not name a verb it could
/// not read the document for.
fn review_words(kind: Option<&str>) -> (&'static str, &'static str) {
    match kind {
        Some("leave") => ("Ready to remove", "Remove"),
        Some("setup") => ("Ready to set up", "Set up"),
        _add_or_unreadable => ("Ready to deploy", "Deploy"),
    }
}

fn finish_lines(
    app: &App,
    operation: &Operation,
    snapshot: &Snapshot,
    lines: &mut Vec<Line<'static>>,
) {
    blank(lines);

    // The operation's own target, which is what the form was filled in for — not the
    // first machine a step happens to name, which on an `add` is the roster being
    // updated rather than the machine being added.
    let machine = scrub(&operation.device, NAME_COLUMNS);

    // `fleet.deployment.status` carries no `kind`, so the operation the view opened is
    // what knows whether this was a removal. Reading the snapshot alone is how a
    // finished `leave` congratulated the operator on a machine it had just taken out.
    let kind = snapshot.kind.as_deref().or(operation.kind.as_deref());
    let leaving = kind == Some("leave");

    if snapshot.succeeded() {
        lines.push(Line::from(Span::styled(
            if leaving {
                format!("{machine} is out of your fleet")
            } else {
                format!("{machine} is in your fleet")
            },
            theme::heading(),
        )));

        // The worker's own words about what to do next, when it wrote any. It ran the
        // deployment; this client did not.
        if let Some(summary) = snapshot.summary.as_ref() {
            lines.push(Line::from(Span::styled(
                access::speakable(summary),
                Style::default().fg(theme::muted()),
            )));
        }
        if let Some(next) = snapshot.next.as_ref() {
            lines.push(Line::from(Span::styled(
                access::speakable(next),
                Style::default().fg(theme::muted()),
            )));
        }

        // What ran, and — the live add that prompted this — what never did. A completed
        // operation whose steps stop at `connect` reported no readiness at all, and a
        // ticked *Ready* was this screen inventing a check nobody made. The strip is
        // drawn only when there are steps to draw: a snapshot with none says nothing
        // about stages either way.
        if !snapshot.steps.is_empty() {
            blank(lines);
            stage_strip(kind, snapshot, lines);
        }

        blank(lines);

        // A removal has nowhere to open: the machine it named is not in the fleet any
        // more, so the machines panel is not where it is. One key, back to the list.
        if leaving {
            lines.push(Line::from(Span::styled(
                "b  back to the device list",
                Style::default().fg(theme::action_colour()),
            )));

            return;
        }

        // The key this client would actually press, from the resolved map: a rebound
        // chord is the one printed, and `off` reads as "this has no key any more".
        lines.push(Line::from(Span::styled(
            access::numbered(
                0,
                &format!(
                    "Open \u{2014} {}, the Dashboard's machines panel",
                    app.keymap.label(Action::LeaderTabDashboard)
                ),
            ),
            Style::default().fg(theme::action_colour()),
        )));
        lines.push(Line::from(Span::styled(
            access::numbered(1, "b  Done \u{2014} back to the device list"),
            Style::default().fg(theme::action_colour()),
        )));

        return;
    }

    lines.push(Line::from(Span::styled(
        match (leaving, snapshot.state.as_str()) {
            (true, "cancelled") => "This removal was cancelled",
            (true, "interrupted") => "This removal was interrupted",
            (true, _failed) => "This removal did not finish",
            (false, "cancelled") => "This setup was cancelled",
            (false, "interrupted") => "This setup was interrupted",
            (false, _failed) => "This setup did not finish",
        },
        theme::heading(),
    )));

    // A worker that is gone with an unfinished journal said nothing at all before this
    // existed: the operation sat reading "inspecting" while the reason was in a log
    // nobody on this screen could see.
    if let Some(exit) = snapshot.worker_exit.as_ref() {
        lines.push(Line::from(Span::styled(
            access::speakable(&scrub(&exit.sentence(), MESSAGE_COLUMNS)),
            Style::default().fg(theme::bad()),
        )));
    }

    if let Some(error) = snapshot.last_error.as_ref() {
        lines.push(Line::from(Span::styled(
            access::speakable(error),
            Style::default().fg(theme::bad()),
        )));
    }

    // The one place this view names the CLI fallback, and only where it is the answer:
    // a removal that never reached the machine it was about. §5.4 asks for the recipe
    // there; showing it any earlier is a screen telling an operator a machine is gone
    // while the operation that would prove it is still running.
    if unreached_removal(leaving, snapshot, &operation.device) {
        lines.push(Line::from(Span::styled(
            access::speakable(&format!(
                "{machine} did not answer, so nothing on it was changed. To take it out \
                 of this fleet's roster anyway, run `ouro fleet sessions forget --machine \
                 {machine} --accept-state-loss` on this machine, and on every other \
                 machine in the fleet.",
            )),
            Style::default().fg(theme::warn()),
        )));
    }

    stage_strip(kind, snapshot, lines);

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

    steps_lines(snapshot, lines);

    blank(lines);
    lines.push(Line::from(Span::styled(
        match (snapshot.state.as_str(), snapshot.worker_exit.is_some()) {
            ("failed" | "interrupted", _) | (_, true) => {
                "R  Retry \u{2014} inspects again and puts the plan up for review      \
                 b  back to the device list"
            }
            _finished => "b  back to the device list",
        },
        Style::default().fg(theme::action_colour()),
    )));
}

/// Whether this failed removal never reached the machine it was about.
///
/// Two pieces of evidence, both from the snapshot, because the broker sends no "could not
/// connect" code of its own. The engine's first recorded step on a `leave` is `inspect`,
/// and it is written only after SSH connected, the preflight ran and the helper session
/// opened — so a removal with no step at all against its target never got that far.
/// A refusal the engine *named* (a changed plan, a busy runtime, a declined review) is a
/// failure it understood and is excluded: those reached the machine, or never needed to.
fn unreached_removal(leaving: bool, snapshot: &Snapshot, device: &str) -> bool {
    leaving
        && snapshot.state == "failed"
        && snapshot.reason.as_deref().unwrap_or("failed") == "failed"
        && !snapshot
            .steps
            .iter()
            .any(|step| step.machine.as_deref() == Some(device))
}

/// The footer hint, which is different on every screen because the keys are.
pub fn devices_hint_line(app: &App) -> String {
    let state = &app.devices;

    // A refused action wins the row. The keys are discoverable again the moment anything
    // else happens; a refusal nobody saw is the failure this exists to prevent.
    if let Some(refusal) = state.refusal_line.as_ref() {
        return refusal.clone();
    }

    if let Some(operation) = state.operation.as_ref() {
        if operation.takeover.is_some() {
            return "t take over this setup \u{b7} n leave it alone".into();
        }

        if !matches!(app.connection, Connection::Live) || operation.stale {
            return "waiting for the runtime to come back \u{b7} Esc leave (nothing is cancelled)"
                .into();
        }

        let open = operation
            .snapshot
            .value
            .as_ref()
            .and_then(Snapshot::challenge);
        let kind = open.map(|challenge| challenge.kind.clone());

        return match kind.as_deref() {
            Some("password") | Some("passphrase") => {
                "type the secret \u{b7} Enter sends it \u{b7} Esc clears it and leaves".into()
            }
            Some("host_trust") => "t trust and continue \u{b7} n cancel".into(),
            // The same word as the key on the screen above it, from the same place.
            Some("review") => {
                let (_heading, approve) = review_words(
                    open.and_then(Challenge::plan)
                        .map(|plan| plan.kind)
                        .as_deref()
                        .or(operation.kind.as_deref()),
                );

                format!(
                    "a {} \u{b7} c cancel \u{b7} Esc leave",
                    approve.to_lowercase()
                )
            }
            _following => {
                "c cancel setup \u{b7} R retry \u{b7} b device list \u{b7} Esc leave (nothing is cancelled)"
                    .into()
            }
        };
    }

    if state.connect.is_some() {
        return "Tab/\u{2191}\u{2193} move \u{b7} \u{2190}\u{2192} change \u{b7} Enter on the button submits \u{b7} Esc back"
            .into();
    }

    if state.searching {
        return "type to search by name or address \u{b7} Enter keeps it \u{b7} Esc clears it"
            .into();
    }

    let narrowing = state
        .inventory
        .value
        .as_ref()
        .is_some_and(|inventory| state.narrowing(inventory));

    // The keys on this row are the keys that work. `/` and `f` exist only past eight
    // rows, so on a list of four they are not offered.
    // The same keys in fewer words on a narrow terminal, where the long form is cut off
    // mid-word by the footer row and the last keys are the ones that vanish.
    let mut hint = if narrow_rows(app) {
        "\u{2191}\u{2193} Enter act \u{b7} a add \u{b7} x remove \u{b7} r refresh".to_string()
    } else {
        "\u{2191}\u{2193} select \u{b7} Enter act \u{b7} a add by address \u{b7} x remove (members) \u{b7} r refresh"
            .to_string()
    };

    if narrowing {
        hint.push_str(if narrow_rows(app) {
            " \u{b7} / f"
        } else {
            " \u{b7} / search \u{b7} f filter"
        });
    }

    hint.push_str(" \u{b7} Esc close");
    hint
}

// ------------------------------------------------------------------------- small parts

/// Everything a terminal would obey, and everything a person cannot see.
///
/// [`human`] already drops control characters, the C1 block and the bidi overrides, which
/// is what stops an escape sequence from repainting the screen. It keeps the *invisible*
/// characters — a zero-width space, a joiner, a soft hyphen — and those are how one device
/// name is made to look like another's (`bui\u{200b}ld-linux` reads as `build-linux` and is
/// a different string). Default-ignorable code points are removed before the bounding, so
/// what reaches a `Line` is what a person can actually see.
fn ignorable(character: char) -> bool {
    crate::fleet_network::ignorable(character)
}

/// One remote string, made safe to draw and bounded to `columns`.
///
/// **Every** string this view draws that some other machine chose goes through here: a
/// device's hostname and address, a worker's step and prompt labels, a plan's fields, a
/// gateway's refusal message. `tui/tests/fixtures/tailscale/hostile-names.json` is a peer
/// list whose names carry ANSI escapes, bidi overrides and a forged four-line device row,
/// and the CLI's own row renderer answers it with [`human`]; this adds the invisible
/// characters that bounding alone leaves behind.
pub fn scrub(raw: &str, columns: usize) -> String {
    let visible: String = raw.chars().filter(|c| !ignorable(*c)).collect();

    human(&visible, columns)
}

/// A string field of a reply, scrubbed and bounded.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| scrub(raw, FIELD_COLUMNS))
        .filter(|text| !text.is_empty())
}

/// A sentence rather than a field: longer, and scrubbed the same way.
fn sentence(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| scrub(raw, MESSAGE_COLUMNS))
        .filter(|text| !text.is_empty())
}

/// A sentence this client did not write, from a gateway message or an error.
///
/// The same scrubbing, for the strings that arrive as `String` rather than as JSON: an
/// `RpcError`'s `message` is chosen by whatever answered the call, and a refusal drawn
/// straight from one is a refusal that can repaint the screen.
fn clean(raw: &str) -> String {
    scrub(raw, MESSAGE_COLUMNS)
}

fn array(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

fn unknown() -> String {
    "unknown".to_string()
}

/// One RFC 3339 timestamp as seconds since the epoch, or `None` when it is not one.
///
/// Written out rather than pulled in: this client has no date crate and one field on one
/// row is not a reason to acquire one. What it accepts is exactly what the runtime sends
/// — `YYYY-MM-DDTHH:MM:SS`, optional fractional seconds, and `Z` or `±HH:MM` — and
/// anything else is `None` rather than a number derived from a guess.
fn epoch_seconds(raw: &str) -> Option<i64> {
    let text = raw.trim();
    let bytes = text.as_bytes();

    if bytes.len() < 19 || (bytes[10] != b'T' && bytes[10] != b' ') {
        return None;
    }

    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();

    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }

    // Howard Hinnant's days-from-civil: the shift puts the leap day at the end of the
    // 400-year era, which is what makes the arithmetic branch-free and correct for every
    // year this will ever be handed.
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    let mut seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;

    // The offset, when there is one. A missing one is read as UTC, which is what every
    // timestamp this runtime writes actually is.
    let rest = &text[19..];
    let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());

    if let Some(sign) = rest.chars().next() {
        if sign == '+' || sign == '-' {
            let offset_hours = rest.get(1..3)?.parse::<i64>().ok()?;
            let offset_minutes = rest
                .get(4..6)
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or(0);
            let offset = offset_hours * 3_600 + offset_minutes * 60;

            seconds += if sign == '+' { -offset } else { offset };
        }
    }

    Some(seconds)
}

/// How long ago a timestamp was, in the words a row carries.
///
/// `None` when the timestamp cannot be read or is in the future: a row that says "seen
/// 3 days ago" about a clock that is ahead of this one would be inventing a past.
fn relative_time(raw: &str) -> Option<String> {
    let then = epoch_seconds(raw)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;

    let elapsed = now - then;

    if elapsed < -60 {
        return None;
    }

    let plural =
        |count: i64, unit: &str| format!("{count} {unit}{} ago", if count == 1 { "" } else { "s" });

    Some(match elapsed {
        // A clock a minute either side of this one is "now", not "1 minute ago".
        ..=59 => "just now".to_string(),
        // Up to an hour and a half in minutes, up to two days in hours, then in days.
        60..=5_399 => plural(elapsed / 60, "minute"),
        5_400..=172_799 => plural(elapsed / 3_600, "hour"),
        _days => plural(elapsed / 86_400, "day"),
    })
}

/// The character a key event carries, or `\0` for a key that is not one.
fn as_char(code: crossterm::event::KeyCode) -> char {
    match code {
        crossterm::event::KeyCode::Char(character) => character,
        _not_a_character => '\0',
    }
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
/// Built rather than retyped: the sentences are `Inventory::headline`'s, but that
/// method counts `peers.len()` and the only way to feed it a count used to be
/// allocating that many [`crate::fleet_network::Device`]s. A hostile `visible_peers`
/// u64 would OOM this client drawing a sentence. The count-based sibling below is
/// the same match with the number already in hand.
fn headline_for(code: &str, visible_peers: usize) -> String {
    headline_for_count(code, visible_peers)
}

fn headline_for_count(code: &str, visible_peers: usize) -> String {
    match code {
        "client_missing" => "no Tailscale client is installed on this machine".into(),
        "signed_out" => "the Tailscale client is installed and this machine is signed out".into(),
        "permission_denied" => "the Tailscale client refused this account's request".into(),
        "no_visible_peers" => "the Tailscale client sees no other devices on this network".into(),
        "ok" => format!(
            "the Tailscale client sees {} device{} on this network",
            visible_peers,
            if visible_peers == 1 { "" } else { "s" }
        ),
        _unavailable => "the Tailscale client could not report this machine's network".into(),
    }
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
            _other => Refusal::Other(clean(&rpc.message)),
        },
        other => Refusal::Other(clean(&other.to_string())),
    }
}

/// Whether a -32003 on this method can be the listener's *scope* rather than the
/// identity rule. Only the operate verbs; `fleet.deployment.status` is a read.
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
                // The server checked the same list this client draws from, and it is the
                // authority: a blocker can appear between the inventory being read and
                // the action being pressed.
                Some("deploy_blocked") => refusal_blockers(error).unwrap_or_else(|| {
                    "This host cannot deploy right now; press r to read why.".into()
                }),
                Some(reason) => format!("{method} was refused: {}", reason_sentence(reason)),
                None => match rpc.code {
                    ErrorCode::MethodNotFound => {
                        format!("This runtime does not serve {method}.")
                    }
                    // Not the inventory's explanation. A -32003 arriving *during* a
                    // deployment is this identity's authority being refused now — a read
                    // scope it always had, or a revocation that has just happened — and
                    // the operator's question is what happens to the operation, not why
                    // the device list is unavailable.
                    ErrorCode::ScopeDenied if method_mutates(method) => format!(
                        "This runtime refused {method}: this listener or this identity is \
                         not permitted to act on a deployment. The operation itself is \
                         untouched and keeps whatever state it had; its next step waits \
                         until somebody who is permitted answers."
                    ),
                    ErrorCode::ScopeDenied => devices_refusal(error, method, hello).sentence(),
                    ErrorCode::UpstreamTimeout => format!(
                        "{method} outlived the gateway's ceiling, so its outcome is \
                         unknown here. The deployment host did not stop working; press r \
                         to read what it actually did."
                    ),
                    _other => format!("{method} was refused: {}", clean(&rpc.message)),
                },
            }
        }
        other => format!("{method} could not be sent: {}", clean(&other.to_string())),
    }
}

/// The blockers a `deploy_blocked` refusal names, in words.
fn refusal_blockers(error: &ClientError) -> Option<String> {
    let ClientError::Rpc(rpc) = error else {
        return None;
    };

    let blockers = rpc.data.as_ref()?.get("blockers")?.as_array()?;
    let first = blockers.iter().find_map(Value::as_str)?;

    Some(blocker_sentence(first))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_network::DiscoveryCode;

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

    /// Every `DeviceState` lands on one of the nine phrases \u{a7}5.1 lists.
    ///
    /// The sibling of the pin above, for the words that moved. `DeviceState::label` is
    /// still where the *CLI's* wording lives and is still pinned against the serializer;
    /// what a row in this view reads is [`DeviceRow::ouroboros_word`], a shorter
    /// vocabulary shared with the web page. The fence is the same both ways: a variant
    /// added to `fleet_network` fails this rather than reaching an operator through a
    /// fallback arm that names a code.
    #[test]
    fn every_state_lands_on_one_of_the_columns_nine_phrases() {
        const COLUMN: [&str; 9] = [
            "in the fleet",
            "in the fleet \u{b7} not connected",
            "not set up",
            "can't run Ouroboros",
            "offline",
            "setting up\u{2026}",
            "waiting for you",
            "setup failed",
            "set up just now",
        ];

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

            let row = DeviceRow {
                state: code.clone(),
                ..DeviceRow::default()
            };

            assert!(
                COLUMN.contains(&row.ouroboros_word().as_str()),
                "{code} reads as {:?}, which is not one of the column's phrases",
                row.ouroboros_word()
            );
        }

        // And the four an *operation* puts there, from the row it is about.
        let inventory = Inventory::decode(&json!({
            "devices": [{ "name": "vps", "address": "100.64.0.9",
                          "state": "discovered_installation_unknown" }],
        }));
        let row = inventory.devices.first().expect("a row").clone();

        for (state, expected) in [
            ("deploying", "setting up\u{2026}"),
            ("awaiting_review", "waiting for you"),
            ("failed", "setup failed"),
            ("completed", "set up just now"),
        ] {
            let with_operation = Inventory {
                operations: vec![OperationSummary::decode(&json!({
                    "operation": "op-1", "state": state,
                    "target": { "machine": "vps", "address": "100.64.0.9" }
                }))],
                ..inventory.clone()
            };

            assert_eq!(with_operation.ouroboros_word(&row), expected, "{state}");
            assert!(COLUMN.contains(&expected));
        }
    }

    /// The fence against the worker: every field this view draws is a field the real
    /// metadata builders write, read out of the shape the real worker puts them in.
    ///
    /// `fleet_setup::challenge` is in this crate, so nothing here is a fake: the three
    /// builders are called, wrapped the way `worker::challenge_event` wraps them, and
    /// decoded by the same code the gateway's answers go through. The first version of
    /// this view read the metadata *flat* and every test passed, because the tests and
    /// the view agreed with each other and neither agreed with the worker.
    #[test]
    fn a_challenge_is_decoded_out_of_the_shape_the_real_worker_sends() {
        use crate::fleet_setup::challenge::{
            host_trust_metadata, passphrase_metadata, password_metadata,
        };

        // What a client is actually handed: `challenge_metadata/1` merges the worker's
        // nested object up into the challenge, and `challenge_view/1` writes the id, the
        // kind and the expiry over the top.
        fn wire(id: &str, kind: &str, metadata: Value) -> Value {
            let mut frame = json!({
                "operation": "abcdef0123456789",
                "challenge": id,
                "kind": kind,
                "expires_at": 4_102_444_800u64,
            });

            for (key, value) in metadata.as_object().expect("an object") {
                frame[key] = value.clone();
            }

            frame
        }

        // And the worker's own spelling, straight off its socket, which the fallback
        // reads so a broker that stopped lifting does not empty every prompt silently.
        fn nested(id: &str, kind: &str, metadata: Value) -> Value {
            json!({
                "operation": "abcdef0123456789",
                "challenge": id,
                "kind": kind,
                "expires_at": 4_102_444_800u64,
                "metadata": metadata,
            })
        }

        let password = Challenge::decode(&wire(
            "c-pw",
            "password",
            password_metadata("100.64.12.44", "deploy", 22, 2, 3),
        ))
        .expect("a decodable password challenge");

        assert_eq!(password.field("target").as_deref(), Some("100.64.12.44"));
        assert_eq!(password.field("user").as_deref(), Some("deploy"));
        assert_eq!(password.field("port").as_deref(), Some("22"));
        assert_eq!(password.field("attempt").as_deref(), Some("2"));
        assert_eq!(password.field("max_attempts").as_deref(), Some("3"));

        let passphrase = Challenge::decode(&wire(
            "c-pp",
            "passphrase",
            passphrase_metadata("id_ed25519", "SHA256:bbb"),
        ))
        .expect("a decodable passphrase challenge");

        assert_eq!(passphrase.field("key_label").as_deref(), Some("id_ed25519"));
        assert_eq!(
            passphrase.field("public_fingerprint").as_deref(),
            Some("SHA256:bbb")
        );

        let trust = Challenge::decode(&wire(
            "c-host",
            "host_trust",
            host_trust_metadata("100.64.12.44", 22, "ssh-ed25519", "SHA256:abc", "deploy"),
        ))
        .expect("a decodable host_trust challenge");

        for (key, value) in [
            ("address", "100.64.12.44"),
            ("port", "22"),
            ("algorithm", "ssh-ed25519"),
            ("sha256_fingerprint", "SHA256:abc"),
            ("user", "deploy"),
        ] {
            assert_eq!(trust.field(key).as_deref(), Some(value), "{key} drifted");
        }

        // The worker's own nested spelling reads too, through the fallback.
        let unlifted = Challenge::decode(&nested(
            "c-pw",
            "password",
            password_metadata("100.64.12.44", "deploy", 22, 1, 3),
        ))
        .expect("a decodable unlifted challenge");

        assert_eq!(unlifted.field("user").as_deref(), Some("deploy"));
        assert_eq!(unlifted.field("target").as_deref(), Some("100.64.12.44"));
    }

    /// The review challenge's plan, and the digest computed over it, are the worker's.
    #[test]
    fn a_review_challenge_yields_the_plan_and_the_digest_the_worker_would_send() {
        let document = json!({
            "schema": 1,
            "operation": "abcdef0123456789",
            "kind": "add",
            "deployment_host": { "hostname": "studio", "user": "ada",
                                 "os": "darwin", "arch": "aarch64", "issuer": true },
            "target": { "machine": "vps", "address": "100.64.0.9", "port": 22,
                        "ssh_user": "deploy", "identity": "default",
                        "install_path": "bin/ouro" },
            "service": "managed",
            "members": [],
            "grants": ["broad fleet trust between every member"]
        });

        // `engine.rs` issues the review challenge with exactly these two keys, and the
        // broker lifts them to the top of the challenge.
        let wire = json!({
            "challenge": "c-review",
            "kind": "review",
            "plan": document,
            "plan_digest": sha256_hex(canonical_json(&document).as_bytes()),
        });

        let challenge = Challenge::decode(&wire).expect("a decodable review challenge");
        let plan = challenge.plan().expect("a decodable plan");

        assert_eq!(plan.machine, "vps");
        assert_eq!(plan.address, "100.64.0.9");
        assert_eq!(plan.ssh_user.as_deref(), Some("deploy"));
        assert_eq!(plan.grants, vec!["broad fleet trust between every member"]);
        assert_eq!(
            challenge.claimed_digest(),
            Some(plan.digest.clone()),
            "the digest this client computes is not the one the worker sends"
        );
    }

    /// Every step name the engine actually writes has words and a colour path here.
    #[test]
    fn every_step_the_engine_writes_is_decodable() {
        for name in [
            "inspect",
            "install_binary",
            "prepare",
            "issue",
            "install",
            "roster",
            "member_preflight",
            "service",
            "disable_service",
            "connect",
            "stop_runtime",
            "create",
            "verify_disconnected",
            "leave",
            "test_task",
        ] {
            for outcome in ["started", "running", "ok", "skipped", "failed"] {
                let step = Step::decode(&json!({
                    "machine": "vps", "step": name, "outcome": outcome,
                    "detail": Value::Null
                }));

                assert_eq!(step.step, name);
                assert_eq!(step.outcome, outcome);
                assert_eq!(step.machine.as_deref(), Some("vps"));
            }
        }
    }

    /// A live worker's residue and cause live inside `done`; a journal's live at the top.
    #[test]
    fn residue_and_cause_are_read_from_both_places_they_are_written() {
        // The worker's `done_frame`, as `worker.rs` builds it.
        let worker = Snapshot::decode(&json!({
            "source": "worker", "attached": true, "state": "failed",
            "done": {
                "ok": false, "state": "failed",
                "reason": "host_key_changed",
                "detail": "the key on 100.64.0.9 is not the one this fleet trusts"
            }
        }));

        assert!(worker
            .last_error
            .as_deref()
            .expect("a cause")
            .contains("100.64.0.9"));

        let finished = Snapshot::decode(&json!({
            "source": "worker", "attached": true, "state": "completed",
            "done": { "ok": true, "state": "completed",
                      "summary": "vps joined the fleet",
                      "next": "run a test task on vps",
                      "residue": ["a partial archive at /tmp/ouro"] }
        }));

        assert_eq!(finished.summary.as_deref(), Some("vps joined the fleet"));
        assert_eq!(finished.next.as_deref(), Some("run a test task on vps"));
        assert_eq!(finished.residue, vec!["a partial archive at /tmp/ouro"]);

        // The journal's own spelling, which is what a read with no worker answers.
        let journal = Snapshot::decode(&json!({
            "source": "journal", "attached": false, "state": "interrupted",
            "last_error": "the connection dropped",
            "residue": ["a half-written roster on studio"]
        }));

        assert_eq!(
            journal.last_error.as_deref(),
            Some("the connection dropped")
        );
        assert_eq!(journal.residue, vec!["a half-written roster on studio"]);
    }

    /// The removal's stages are the engine's own leave steps, and every one of them
    /// lands somewhere.
    ///
    /// The list on the right is `fleet_setup::engine`'s `run_leave` and
    /// `stop_and_retire` read off in order: a step the engine records and this table
    /// does not name is a stage strip that stalls while the worker is working.
    #[test]
    fn a_removals_stages_account_for_every_step_its_engine_records() {
        let engine_steps = [
            "inspect",
            "stop_runtime",
            "disable_service",
            "verify_disconnected",
            "leave",
            "member_preflight",
            "roster",
        ];

        for step in engine_steps {
            let snapshot = Snapshot::decode(&json!({
                "source": "worker", "attached": true, "state": "deploying",
                "steps": [{ "machine": "attic", "step": step, "outcome": "started" }]
            }));

            let stages = snapshot.stages(Some("leave"));

            assert_eq!(
                stages
                    .iter()
                    .map(|(name, _marker)| *name)
                    .collect::<Vec<_>>(),
                vec![
                    "Inspect",
                    "Stop",
                    "Disable startup",
                    "Leave",
                    "Update rosters"
                ],
                "{step}"
            );
            assert_eq!(
                stages
                    .iter()
                    .filter(|(_name, marker)| *marker == Marker::Current)
                    .count(),
                1,
                "`{step}` is not the current step of any removal stage"
            );
        }

        // The kind travels with the operation, because `fleet.deployment.status` does
        // not carry one: a snapshot read on its own is an `add` as far as the wire is
        // concerned, and a removal drawn that way is the live defect this pins.
        let removal = Snapshot::decode(&json!({
            "source": "worker", "attached": true, "state": "deploying",
            "steps": [{ "machine": "studio", "step": "roster", "outcome": "started" }]
        }));

        assert_eq!(removal.stages(Some("leave"))[4].0, "Update rosters");
        assert_eq!(removal.stages(None)[2].0, "Join fleet");
    }

    /// A finished operation does not tick a stage nothing reported.
    #[test]
    fn a_stage_no_step_ever_named_is_not_checked_rather_than_done() {
        let completed = Snapshot::decode(&json!({
            "source": "worker", "attached": true, "state": "completed",
            "steps": [
                { "machine": "vps", "step": "inspect", "outcome": "ok" },
                { "machine": "vps", "step": "install_binary", "outcome": "ok" },
                { "machine": "vps", "step": "issue", "outcome": "ok" },
                { "machine": "vps", "step": "service", "outcome": "ok" },
                { "machine": "vps", "step": "connect", "outcome": "ok" }
            ]
        }));

        let stages = completed.stages(None);

        assert_eq!(stages.last().expect("a last stage").0, "Ready");
        assert_eq!(stages.last().expect("a last stage").1, Marker::NotChecked);
        assert_eq!(Marker::NotChecked.word(), "not checked");
        // Everything the worker did report is still done: this is about the silence,
        // not about doubting the steps that exist.
        for (name, marker) in stages.iter().take(5) {
            assert_eq!(*marker, Marker::Done, "{name}");
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
        assert!(row.ouroboros_word().contains("quantum_entangled"));
        assert_eq!(row.primary(), Primary::None);
        assert!(row
            .no_action_reason()
            .expect("a reason")
            .contains("quantum_entangled"));
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
        assert_eq!(headline_for_count("ok", 3), expected);
        // A hostile `visible_peers` used to allocate that many `Device`s. The count-based
        // sibling must still produce the sentence without that allocation.
        let huge = headline_for("ok", 1_000_000);
        assert!(huge.contains("1000000"), "{huge}");
    }

    /// The name field is seeded from `suggested_machine` and from nothing else.
    ///
    /// `name` is a display name — "Monocursive\u{2019}s MacBook Pro", or the `this device`
    /// a failed discovery invented — and neither is a machine name. Both surfaces used to
    /// seed the field from it, and the web submitted it (finding 3).
    #[test]
    fn the_name_field_is_prefilled_from_the_runtimes_suggestion_only() {
        let inventory = Inventory::decode(&json!({
            "host": { "hostname": "studio", "user": "ada", "os": "darwin",
                      "capabilities": { "deploy": true, "reasons": [] } },
            "devices": [],
        }));

        let suggested = DeviceRow {
            name: "Monocursive\u{2019}s MacBook Pro".into(),
            suggested_machine: Some("monocursives-macbook-pro".into()),
            address: Some("100.64.12.44".into()),
            state: "discovered_installation_unknown".into(),
            ..DeviceRow::default()
        };

        let form = ConnectForm::add(&inventory, &suggested);
        assert_eq!(form.machine, "monocursives-macbook-pro");
        assert!(form.address_fixed, "an address from the list is read-only");

        // No suggestion is an empty field, never the display name.
        let unnamed = DeviceRow {
            name: "Monocursive\u{2019}s MacBook Pro".into(),
            suggested_machine: None,
            ..DeviceRow::default()
        };

        assert_eq!(ConnectForm::add(&inventory, &unnamed).machine, "");
        assert!(ConnectForm::add(&inventory, &unnamed)
            .params()
            .is_err_and(|(field, _why)| field == ConnectField::Machine));
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

        assert_eq!(host.actions_line(), "Actions run on studio as ada.");
        assert_eq!(host.self_label(), "This Mac");
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

        // The code's own words, with the underscores gone: quotable by an operator, and
        // not a snake_case identifier on a screen somebody is asked to act on.
        let unknown = host.blocker().expect("a sentence");
        assert!(unknown.contains("a reason from the future"), "{unknown}");
        assert!(!unknown.contains("a_reason_from_the_future"), "{unknown}");
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

    /// An inventory with one discovered peer and one member, for the form tests.
    fn form_inventory() -> Inventory {
        Inventory::decode(&json!({
            "host": { "hostname": "studio", "user": "ada", "os": "darwin",
                      "capabilities": { "deploy": true, "reasons": [] } },
            "fleet_name": "studio",
            "devices": [
                { "name": "studio", "machine": "studio", "os": "macos",
                  "address": "100.64.12.21", "online": true, "connected": true,
                  "state": "this_device", "suggested_machine": "studio" },
                { "name": "vps", "machine": Value::Null, "os": "linux",
                  "address": "100.64.0.9", "online": true,
                  "state": "discovered_installation_unknown", "suggested_machine": "vps" },
                { "name": "attic", "machine": "attic", "os": "linux",
                  "address": "100.64.0.77", "online": false, "connected": false,
                  "state": "fleet_member_not_visible", "suggested_machine": "attic" },
            ],
        }))
    }

    fn peer(inventory: &Inventory, name: &str) -> DeviceRow {
        inventory
            .devices
            .iter()
            .find(|row| row.name == name)
            .expect("a row")
            .clone()
    }

    /// A required username is a refusal with a field to go to, not a call.
    #[test]
    fn the_connect_form_refuses_an_empty_username() {
        let inventory = form_inventory();
        let form = ConnectForm::add(&inventory, &peer(&inventory, "vps"));

        let (field, sentence) = form.params().expect_err("an empty username is refused");
        assert_eq!(field, ConnectField::User);
        assert!(sentence.contains("never guessed"));
    }

    /// The parameters carry a reference and never key material, and no secret at all.
    #[test]
    fn the_connect_form_sends_a_reference_and_no_secret() {
        let inventory = form_inventory();
        let mut form = ConnectForm::add(&inventory, &peer(&inventory, "vps"));

        form.user = "deploy".into();
        form.port = "2222".into();
        form.key_path = "~/.ssh/id_ed25519".into();
        form.data_dir = "/srv/ouro".into();
        form.service = false;

        let params = form.params().expect("a valid form");

        assert_eq!(params["kind"], json!("add"));
        assert_eq!(params["target"]["address"], json!("100.64.0.9"));
        assert_eq!(params["target"]["machine"], json!("vps"));
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

    /// Two identities named at once is a question, not a guess at which was meant.
    #[test]
    fn naming_a_key_and_an_agent_at_once_is_refused() {
        let inventory = form_inventory();
        let mut form = ConnectForm::add(&inventory, &peer(&inventory, "vps"));

        form.user = "deploy".into();
        form.key_path = "~/.ssh/id_ed25519".into();
        form.agent_id = "SHA256:aaaa".into();

        let (field, sentence) = form.params().expect_err("two identities are refused");
        assert_eq!(field, ConnectField::KeyPath);
        assert!(sentence.contains("one identity"), "{sentence}");

        // One of them alone is an agent reference, sent as one.
        form.key_path.clear();
        let params = form.params().expect("a valid form");
        assert_eq!(params["identity"]["kind"], json!("agent"));
        assert_eq!(params["identity"]["ref"], json!("SHA256:aaaa"));
    }

    /// A port that is not a port names the field it is in.
    #[test]
    fn the_connect_form_refuses_a_port_that_is_not_one() {
        let inventory = form_inventory();
        let mut form = ConnectForm::add(&inventory, &peer(&inventory, "vps"));
        form.user = "deploy".into();
        form.port = "http".into();

        let (field, _sentence) = form.params().expect_err("a bad port is refused");
        assert_eq!(field, ConnectField::Port);
    }

    /// There is no identity picker, and no identity is sent unless one was named.
    #[test]
    fn an_unchosen_identity_is_omitted_rather_than_guessed() {
        let inventory = form_inventory();
        let mut form = ConnectForm::add(&inventory, &peer(&inventory, "vps"));
        form.user = "deploy".into();

        let params = form.params().expect("a valid form");
        assert!(params.get("identity").is_none());
        assert_eq!(params["port"], json!(22));

        // And the form draws no picker row at all: the default identity is used, and a
        // password comes back as its own challenge.
        assert!(!form
            .rows()
            .iter()
            .any(|field| matches!(field, ConnectField::KeyPath | ConnectField::AgentId)));
    }

    /// Adding by address is the same form with the address editable and nothing seeded.
    #[test]
    fn a_manual_add_needs_both_a_name_and_an_address() {
        let mut form = ConnectForm::manual();

        assert_eq!(form.kind, FormKind::AddByAddress);
        assert!(!form.address_fixed, "the typed address must be editable");
        assert!(form.rows().contains(&ConnectField::Address));

        // No name: refused on the name field, before anything reaches the runtime. The
        // worker used to be handed the address as the machine name and refuse it.
        form.address = "100.83.203.10".into();
        form.user = "monocursive".into();
        let (field, sentence) = form.params().expect_err("a nameless add is refused");
        assert_eq!(field, ConnectField::Machine);
        assert!(sentence.contains("an address is not one"), "{sentence}");

        form.machine = "raspberrypi".into();
        let params = form.params().expect("a named manual add");
        assert_eq!(params["kind"], json!("add"));
        assert_eq!(params["target"]["machine"], json!("raspberrypi"));
        assert_eq!(params["target"]["address"], json!("100.83.203.10"));
    }

    /// `x` on a member sends `kind: "leave"` with the roster name, never the address.
    #[test]
    fn removing_a_member_sends_a_leave_for_its_roster_name() {
        let inventory = form_inventory();
        let attic = peer(&inventory, "attic");

        assert!(attic.removable());
        assert!(
            !peer(&inventory, "studio").removable(),
            "this machine does not leave its own fleet from here"
        );
        assert!(
            !peer(&inventory, "vps").removable(),
            "a device that is not a member has nothing to leave"
        );

        let mut form = ConnectForm::leave(&inventory, &attic);
        assert_eq!(form.kind, FormKind::Leave);

        let (field, _why) = form.params().expect_err("a leave needs an account");
        assert_eq!(field, ConnectField::User);

        form.user = "pi".into();
        form.port = "2200".into();
        let params = form.params().expect("a valid leave");

        assert_eq!(params["kind"], json!("leave"));
        assert_eq!(params["target"]["machine"], json!("attic"));
        assert!(params["target"]["address"].is_null());
        assert_eq!(params["ssh_user"], json!("pi"));
        assert_eq!(params["port"], json!(2200));
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
        for reason in catalogue::REASON_CODES {
            let sentence = reason_sentence(reason);
            assert!(!sentence.contains(reason), "{reason} printed as its code");
            assert!(sentence.len() > 20, "{reason} has no explanation");
        }

        let unknown = reason_sentence("from_the_future");
        assert!(unknown.contains("from the future"), "{unknown}");
        assert!(
            !unknown.contains("from_the_future"),
            "an unrecognised code reached the screen as an identifier: {unknown}"
        );
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

    /// Search and filter exist only past eight rows, and then narrow one list.
    ///
    /// A working home network of four devices split into two sections with a search box
    /// and three filter buttons is the presentation finding 9 is about, so below the
    /// threshold the keys are not offered and do nothing.
    #[test]
    fn the_filter_and_the_search_appear_past_eight_rows_and_narrow_one_list() {
        let short = Inventory::decode(&json!({
            "devices": [
                { "name": "studio", "machine": "studio", "state": "this_device",
                  "address": "100.64.0.1" },
                { "name": "vps", "state": "discovered_installation_unknown",
                  "address": "100.64.0.9" },
            ]
        }));

        let mut state = DevicesState::default();
        assert!(!state.narrowing(&short));

        state.filter = Filter::Fleet;
        state.query = "nothing-matches-this".into();
        assert_eq!(
            state.visible(&short).len(),
            2,
            "a short list is never narrowed"
        );

        let mut devices = vec![json!({
            "name": "studio", "machine": "studio", "state": "this_device",
            "address": "100.64.0.1"
        })];
        for index in 0..8 {
            devices.push(json!({
                "name": format!("peer-{index}"),
                "state": "discovered_installation_unknown",
                "address": format!("100.64.1.{index}"),
            }));
        }
        devices.push(json!({
            "name": "pi", "state": "peer_offline", "address": "100.64.0.4"
        }));

        let long = Inventory::decode(&json!({ "devices": devices }));
        let mut state = DevicesState::default();

        assert!(state.narrowing(&long));
        assert_eq!(state.visible(&long).len(), 10);

        // This machine first, then members, then the peers discovery found.
        assert_eq!(state.visible(&long)[0].name, "studio");

        state.filter = Filter::Fleet;
        assert_eq!(
            state
                .visible(&long)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["studio"]
        );

        state.filter = Filter::Available;
        assert_eq!(state.visible(&long).len(), 9);

        // Address search, not only name search.
        state.query = "100.64.1.3".into();
        assert_eq!(
            state
                .visible(&long)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["peer-3"]
        );

        state.filter = Filter::All;
        state.query = "STUD".into();
        assert_eq!(
            state
                .visible(&long)
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            vec!["studio"],
            "search is case-insensitive"
        );
    }

    /// §5.1's action column: one button per state, or nothing and a reason.
    #[test]
    fn every_state_gets_one_action_and_one_ouroboros_word() {
        for (code, primary, word) in [
            (
                "discovered_installation_unknown",
                Primary::Add,
                "not set up",
            ),
            ("fleet_member", Primary::Open, "in the fleet"),
            ("this_device", Primary::Open, "in the fleet"),
            (
                "fleet_member_not_visible",
                Primary::Open,
                "in the fleet \u{b7} not connected",
            ),
            ("this_device_without_profile", Primary::SetUp, "not set up"),
            ("peer_offline", Primary::None, "offline"),
            ("unsupported_platform", Primary::None, "can't run Ouroboros"),
            ("no_usable_ipv4", Primary::None, "can't run Ouroboros"),
        ] {
            let row = DeviceRow {
                state: code.into(),
                ..DeviceRow::default()
            };

            assert_eq!(row.primary(), primary, "{code}");
            assert_eq!(row.ouroboros_word(), word, "{code}");

            // A row with no button says why, in its details, and never in silence.
            assert_eq!(
                row.no_action_reason().is_some(),
                primary == Primary::None,
                "{code}"
            );
        }

        // A member this runtime is not connected to says so rather than reading as gone.
        let disconnected = DeviceRow {
            state: "fleet_member".into(),
            connected: Some(false),
            ..DeviceRow::default()
        };
        assert_eq!(
            disconnected.ouroboros_word(),
            "in the fleet \u{b7} not connected"
        );
    }

    /// The nouns the host OS gives this machine's own row.
    #[test]
    fn the_self_row_takes_its_noun_from_the_host_os() {
        let mac = DeploymentHost::decode(&json!({ "hostname": "studio", "os": "darwin" }));
        let other = DeploymentHost::decode(&json!({ "hostname": "vps", "os": "linux" }));
        let unstated = DeploymentHost::decode(&json!({ "hostname": "vps" }));

        assert_eq!(mac.self_label(), "This Mac");
        assert_eq!(other.self_label(), "This machine");
        assert_eq!(unstated.self_label(), "This machine");

        assert_eq!(Primary::SetUp.label(mac.self_label()), "Set up this Mac");
        assert_eq!(
            Primary::SetUp.label(other.self_label()),
            "Set up this machine"
        );
    }

    /// This machine, before it has a fleet, belongs under "Fleet devices".
    ///
    /// It has no roster name — there is no roster — so the `machine.is_some()` half of
    /// the split says "available on this network", which is the one row where that is
    /// exactly wrong: a device is not deployed to over SSH by itself.
    #[test]
    fn this_machine_without_a_profile_is_filed_under_the_fleet() {
        let bare = DeviceRow {
            name: "studio".into(),
            machine: None,
            state: "this_device_without_profile".into(),
            ..DeviceRow::default()
        };

        assert!(bare.in_fleet(), "this machine was filed under the peers");
        assert_eq!(bare.primary(), Primary::SetUp);

        let peer = DeviceRow {
            name: "vps".into(),
            machine: None,
            state: "discovered_installation_unknown".into(),
            ..DeviceRow::default()
        };

        assert!(!peer.in_fleet());
    }

    /// An operation is placed by its target, and one that names no device places nowhere.
    #[test]
    fn an_operation_is_matched_to_its_row_by_target() {
        let inventory = Inventory::decode(&json!({
            "devices": [
                { "name": "alpha", "state": "discovered_installation_unknown",
                  "address": "100.64.0.11" },
                { "name": "bravo", "state": "discovered_installation_unknown",
                  "address": "100.64.0.22" }
            ],
            "operations": [{
                "operation": "op1", "state": "awaiting_auth", "attached": true,
                "owner": "ada",
                "target": { "machine": "bravo", "address": "100.64.0.22" }
            }]
        }));

        let alpha = &inventory.devices[0];
        let bravo = &inventory.devices[1];

        assert!(inventory.open_operation_for(alpha).is_none());
        assert_eq!(
            inventory
                .open_operation_for(bravo)
                .map(|operation| operation.operation.as_str()),
            Some("op1")
        );

        // A journal too old to say what it targets is listed, and attached to no row.
        let untargeted = Inventory::decode(&json!({
            "devices": [{ "name": "alpha", "state": "discovered_installation_unknown",
                          "address": "100.64.0.11" }],
            "operations": [{ "operation": "op2", "state": "awaiting_auth",
                             "attached": true, "target": Value::Null }]
        }));

        assert!(untargeted
            .open_operation_for(&untargeted.devices[0])
            .is_none());
        assert_eq!(untargeted.open_operations().len(), 1);
    }

    /// A digest is 64 lowercase hex characters, and nothing else is one.
    #[test]
    fn only_sixty_four_lowercase_hex_characters_are_a_digest() {
        let good = "9f2c1b7ae4d60358aa1f2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef";
        assert_eq!(hex_digest(good).as_deref(), Some(good));
        assert_eq!(hex_digest(&format!("  {good}  ")).as_deref(), Some(good));

        for bad in [
            "",
            "9f2c",
            "9F2C1B7AE4D60358AA1F2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF",
            "9f2c1b7ae4d60358aa1f2c3d4e5f60718293a4b5c6d7e8f90123456789abcdeg",
            // The one that panicked the client: multibyte, and shorter in characters
            // than it is in bytes.
            "\u{65e5}\u{672c}\u{8a9e}\u{3067}\u{3059}",
        ] {
            assert_eq!(hex_digest(bad), None, "{bad:?} was accepted as a digest");
        }

        // A plan whose release checksum is not one is not decodable at all.
        let plan = json!({
            "deployment_host": { "hostname": "studio", "user": "ada" },
            "target": { "machine": "vps", "address": "100.64.0.9" },
            "release": { "version": "0.1.8", "target": "linux",
                         "sha256": "\u{30a2}\u{30fc}\u{30c6}", "official_origin": true }
        });

        assert_eq!(PlanView::decode(&plan), None);
    }

    /// Invisible characters are removed before a name is bounded.
    #[test]
    fn a_zero_width_character_never_reaches_the_screen() {
        for hidden in ['\u{200b}', '\u{200d}', '\u{00ad}', '\u{feff}', '\u{2060}'] {
            let name = format!("bui{hidden}ld-linux");
            let drawn = scrub(&name, 28);

            assert!(
                !drawn.contains(hidden),
                "{hidden:?} survived into a drawn name"
            );
            assert_eq!(drawn, "build-linux");
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

    /// Each way an operation can end has its own verb, and the broker would accept it.
    #[test]
    fn only_an_unfinished_operation_can_be_continued() {
        for (state, resumption) in [
            ("completed", Resumption::None),
            // Not resumable: the broker's terminal set is `completed` and `cancelled`,
            // so offering a resume here would be offering `operation_finished`.
            ("cancelled", Resumption::DeployAgain),
            // Resumable, and a resume re-inspects and re-reviews — which is what makes
            // Retry after a failure safe rather than a second go at an unread plan.
            ("failed", Resumption::Retry),
            ("interrupted", Resumption::Continue),
            ("deploying", Resumption::Continue),
            ("awaiting_auth", Resumption::Continue),
        ] {
            let summary = OperationSummary::decode(&json!({
                "operation": "abc123", "state": state, "attached": false
            }));

            assert_eq!(summary.resumption(), resumption, "{state}");
            assert_eq!(summary.open(), resumption != Resumption::None, "{state}");
        }

        // A journal nobody can read is unknown, not finished.
        let unreadable = OperationSummary::decode(&json!({
            "operation": "abc123", "readable": false, "reason": "journal_unreadable"
        }));
        assert!(unreadable.open());
        assert!(!unreadable.readable);
    }
}
