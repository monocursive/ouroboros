//! The Devices view: the machines this runtime can see, as an inventory.
//!
//! This is the terminal half of "Fleet, simplified" §10. The web page beside it draws the
//! same rows, the same status line and the same words; what differs is that this one is a
//! keyboard and eighty columns — and that this one **runs nothing**.
//!
//! ## It runs nothing
//!
//! The view issues two reads, `fleet.devices` and `fleet.status`, and draws what comes
//! back. There is no form, no challenge, no plan, no progress and no takeover, because
//! there is no operation to start: the one thing to do about a row is printed *as the
//! command that does it*, to be run on the deployment host. That is the whole of the
//! simplification — a terminal client that cannot ask for a password cannot ask for it
//! under the wrong machine's name, and an inventory that starts nothing cannot start the
//! wrong thing.
//!
//! An operation the runtime is already running for a row still shows on that row, from
//! `fleet.devices`'s own `operations` list: `setting up…` while it is going, `setup
//! failed` when it stopped, and its last error in the details pane. Read-only, all of it.
//!
//! ## Every remote string goes through one funnel
//!
//! A device's name, its address, a fleet's name, a gateway's refusal message *and its
//! reason code* are all chosen by something that is not this client. Each one reaches a
//! [`Line`] through [`scrub`], which is [`human`] and nothing else: it drops what a
//! terminal would obey (control characters, the C1 block, bidi overrides), drops what a
//! person cannot see (zero-width spaces, joiners, soft hyphens — the characters that make
//! one device name look like another's), collapses whitespace, and cuts the result to the
//! column it is drawn in. The columns then *end*, visibly, well before anything this
//! build composed: `tui/tests/fixtures/tailscale/hostile-names.json` is a peer list whose
//! names are ANSI escapes and a forged four-line device row, and the answer to it is that
//! a name cannot reach past its own cell.
//!
//! Two kinds of string are deliberately outside the funnel, and neither is ever drawn.
//! [`identity`] keeps an address and a fleet name whole, because scrubbing and bounding
//! destroy the thing an identity comparison needs. And a `--machine` or an address that
//! is about to be printed *inside a command line* is not scrubbed but **validated**, by
//! `crate::fleet`'s own rules: see [`machine_argument`].

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::fleet_network::{human, DeviceState, FIELD_COLUMNS, MESSAGE_COLUMNS};

use super::super::access;
use super::super::theme;
use super::*;

use super::devices_catalogue as catalogue;
pub use catalogue::{
    blocker_sentence, operation_state, reason_sentence, BLOCKER_CODES, OPERATION_STATES,
    REASON_CODES,
};

/// The drift predicates, for the suites that walk a fixture's codes against the
/// catalogue. Not part of what the view does — see the note above them.
#[cfg(test)]
pub use catalogue::{blocker_known, operation_state_known, reason_known};

/// The inventory is not on a cadence at all: `fleet.devices` shells out to the network
/// client under a ten-second ceiling, and polling that every few seconds would fork a
/// process at a peer's expense for a list that changes when an operator changes it. It
/// is read when the view opens and when `r` asks.
///
/// A quarter of `u64::MAX` rather than all of it: [`Loadable::resolved`] adds this to the
/// current tick, and the honest "never" would be the one value that overflows there.
const INVENTORY_HOLD: u64 = u64::MAX / 4;

// ------------------------------------------------------------------ decoded inventory

/// The deployment host, from `fleet.devices`'s `host`.
///
/// `issuer` is gone with the per-member PKI (§1): one fleet is one shared bundle, every
/// member holds the CA key, and "which machine may admit" is no longer a question a row
/// can answer. A document that still carries the key is simply not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentHost {
    pub hostname: String,
    pub user: String,
    pub os: Option<String>,
    pub reasons: Vec<String>,
}

impl DeploymentHost {
    /// `arch` and `capabilities.deploy` are in the document and are not read here.
    ///
    /// The architecture belonged to the release line of a plan this view no longer draws,
    /// and `deploy` is the boolean summary of `reasons` — which this view prints in full,
    /// because it gates nothing and a summary of a list it is already showing would be
    /// the same fact twice.
    fn decode(value: &Value) -> Self {
        let capabilities = value.get("capabilities");

        Self {
            hostname: text(value.get("hostname")).unwrap_or_else(|| "this machine".into()),
            user: text(value.get("user")).unwrap_or_else(|| "unknown".into()),
            os: text(value.get("os")),
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

    /// The one quiet line the target design puts under the title, and again beside every
    /// command in the details pane: whose machine the commands are for, and as whom.
    ///
    /// It matters more here than it did when this view ran the deployment itself. A
    /// recipe is a line somebody is about to type into a shell, and the shell it belongs
    /// in is the deployment host's — which, for a client attached over a tunnel, is not
    /// the laptop the terminal is on.
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

    /// The first thing this runtime says it cannot do, in words, or `None`.
    ///
    /// These no longer gate anything in this view — there is nothing here to gate — but
    /// they are facts the runtime reported about itself, and one of them changes what a
    /// recipe means: on a Mix dev runtime the `ouro` on `$PATH` is not the thing that
    /// would be set up. The codes stay in the data; these are the sentences.
    pub fn blocker(&self) -> Option<String> {
        self.reasons.first().map(|reason| blocker_sentence(reason))
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

    /// The distinct empty states the inventory needs, in the words `ouro fleet devices`
    /// already prints for them.
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
    /// carried through by the contract precisely so this sentence can quote it rather
    /// than guess — the old wording claimed *this build of Ouroboros may be older than
    /// the client*, which was a guess, and a wrong one.
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
    /// The name this device would take in the fleet, chosen by the runtime: the member
    /// name for a member, otherwise the display name folded to a valid machine name, or
    /// `null` when nothing valid remains.
    ///
    /// The *only* source a recipe's `--machine` is ever filled from. `name` is a display
    /// name — "Monocursive's MacBook Pro" — and that is not a machine name, which is what
    /// put an invalid one into the old form on both surfaces.
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
    /// `address` and `machine` as the runtime sent them, for identity only.
    ///
    /// Never drawn: the two above are the drawable ones, and they are cut at
    /// `FIELD_COLUMNS` on the way in. That cut is right for a cell and wrong for an
    /// answer to "is this operation about this device" — two hosts that differ only
    /// after column 71 are one string once it has been made, and [`OperationTarget::is`]
    /// would then draw one device's setup on the other. So the comparison uses these,
    /// and the screen uses those.
    pub address_key: Option<String>,
    pub machine_key: Option<String>,
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
            address_key: identity(value.get("address")),
            machine_key: identity(value.get("machine")),
        }
    }

    /// This row's address for comparison, whole.
    ///
    /// Falls back to the drawable field for a row built by hand rather than decoded —
    /// a test's row, which has no key because it never had a document. A decoded row
    /// always has the key whenever it has the field, so the fallback is never what a
    /// real comparison uses.
    pub fn address_identity(&self) -> Option<&str> {
        self.address_key.as_deref().or(self.address.as_deref())
    }

    /// This row's fleet name for comparison, whole. Never its display name.
    pub fn machine_identity(&self) -> Option<&str> {
        self.machine_key.as_deref().or(self.machine.as_deref())
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
            // The runtime's own promotion: a member whose runtime this one is connected
            // to says so in its own state rather than being left on discovery's word,
            // which called it "not visible on this network" whenever the network client
            // could not see it. `DeviceState` has no variant for this — it is a fact
            // about the cluster, and that enum is about the network — so the words live
            // here, in the same house style as the ones it does own.
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

    /// Whether this row is a machine of this fleet rather than a device on the network.
    /// The same split `render_devices` makes for the CLI, and what the list sorts by.
    pub fn in_fleet(&self) -> bool {
        self.machine.is_some()
            || self.parsed_state() == Some(DeviceState::ThisDeviceWithoutProfile)
            || self.state == "fleet_member_connected"
    }

    /// Network presence with its observation time, in the CLI's words. The details
    /// pane's line: the *exact* time, never abbreviated.
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
    /// nobody can scan. The exact time is in the details pane.
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

    /// The Ouroboros column: one of the phrases §5.1 lists, or — for a state code this
    /// build has never seen — that code, named as one.
    ///
    /// The operation phrases (`setting up…`, `setup failed`, `set up just now`) are not
    /// derivable from the device's state at all; they come from the operation on its row,
    /// so [`Inventory::ouroboros_word`] is what the list calls.
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
            // The runtime's own promotion: a member whose runtime this one is talking to.
            None if self.state == "fleet_member_connected" => "in the fleet".into(),
            // Never a blank column, and never invented words. A state this build cannot
            // reason about is still a device, and saying so is the honest column.
            None => self.state_label(),
        }
    }

    /// The reason there is no command on this row, for the details pane. `None` when
    /// there is one.
    pub fn no_recipe_reason(&self) -> Option<String> {
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
                "This runtime reports the state {}, which this client has no command for.",
                self.state_label()
            )),
            _actionable => None,
        }
    }

    /// The one thing to do about this device, as the command that does it — before any
    /// operation already running on it is taken into account. [`Inventory::recipe`] is
    /// what the list calls.
    pub fn recipe(&self) -> Recipe {
        match self.parsed_state() {
            Some(DeviceState::ThisDeviceWithoutProfile) => Recipe::setup(self.machine_argument()),
            Some(DeviceState::DiscoveredInstallationUnknown) => {
                Recipe::add(self.address_argument(), self.machine_argument())
            }
            // This machine leaves its own fleet where it is; there is no account to reach
            // it by, because there is no SSH to itself.
            Some(DeviceState::ThisDevice) => Recipe::leave_here(),
            Some(DeviceState::FleetMember) | Some(DeviceState::FleetMemberNotVisible) => {
                Recipe::leave(self.machine_argument())
            }
            Some(DeviceState::PeerOffline)
            | Some(DeviceState::UnsupportedPlatform)
            | Some(DeviceState::NoUsableIpv4) => Recipe::None,
            // A member this runtime is talking to is a member: the same command as any
            // other, and never the "nothing to do here" an unrecognised code would get.
            None if self.state == "fleet_member_connected" => {
                Recipe::leave(self.machine_argument())
            }
            None => Recipe::None,
        }
    }

    /// What `--machine` gets: the runtime's own suggestion, or the placeholder.
    ///
    /// Never `name`. A display name is not a machine name, and a recipe that printed one
    /// would be a command line that fails when it is pasted. And never an unvalidated
    /// one: see [`machine_argument`].
    fn machine_argument(&self) -> String {
        self.machine
            .as_deref()
            .and_then(machine_argument)
            .or_else(|| self.suggested_machine.as_deref().and_then(machine_argument))
            .unwrap_or_else(|| Recipe::MACHINE_PLACEHOLDER.to_string())
    }

    fn address_argument(&self) -> String {
        self.address
            .as_deref()
            .and_then(address_argument)
            .unwrap_or_else(|| Recipe::ADDRESS_PLACEHOLDER.to_string())
    }
}

/// The one thing to do about a row, as the command that does it.
///
/// A command rather than a button, because this view runs nothing (§10). What it cannot
/// know it prints as a placeholder in capitals rather than as a guess: `USER@` is
/// literal, because `fleet.devices` reports a device, not an account on it, and a
/// plausible-looking account name in a command line somebody is about to run is exactly
/// the kind of invention a deployment must not make on their behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipe {
    /// The command line, ready to run on the deployment host.
    Command(String),
    /// Nothing to do about this device from here. The reason is in its details.
    None,
}

impl Recipe {
    /// Stood in for what this runtime could not name. Capitals, so that a command that
    /// still has one in it cannot be run by accident.
    pub const MACHINE_PLACEHOLDER: &'static str = "NAME";
    pub const ADDRESS_PLACEHOLDER: &'static str = "ADDRESS";
    /// The account on the target. Never guessed: a device is not an account.
    pub const USER_PLACEHOLDER: &'static str = "USER";

    fn setup(machine: String) -> Self {
        Self::Command(format!("ouro fleet setup --machine {machine}"))
    }

    fn add(address: String, machine: String) -> Self {
        Self::Command(format!(
            "ouro fleet add {}@{address} --machine {machine}",
            Self::USER_PLACEHOLDER
        ))
    }

    fn leave(machine: String) -> Self {
        Self::Command(format!(
            "ouro fleet leave --machine {machine} --user {}",
            Self::USER_PLACEHOLDER
        ))
    }

    /// This machine, taking itself out of its fleet. No account, no address: §5's bare
    /// `ouro fleet leave` is the local form.
    fn leave_here() -> Self {
        Self::Command("ouro fleet leave".into())
    }

    /// Adding a device the network client never listed. The line under the list, and the
    /// only recipe that belongs to no row.
    pub fn manual() -> String {
        format!(
            "ouro fleet add {}@{} --machine {}",
            Self::USER_PLACEHOLDER,
            Self::ADDRESS_PLACEHOLDER,
            Self::MACHINE_PLACEHOLDER
        )
    }

    /// What the action column draws: the command, or the dash a row with nothing to do
    /// carries instead of one.
    pub fn words(&self) -> String {
        match self {
            Self::Command(command) => command.clone(),
            Self::None => "\u{2014}".into(),
        }
    }

    pub fn command(&self) -> Option<&str> {
        match self {
            Self::Command(command) => Some(command),
            Self::None => None,
        }
    }
}

/// One deployment operation this runtime holds a journal for.
///
/// `owner` and `attached` are gone with the broker's ownership model (§9): a challenge is
/// answered by whoever is an administrator on this runtime, so there is no identity to
/// attribute a journal to and no per-tab binding to report. What replaced them is
/// `running` — whether a worker process is alive for it — which is the only thing this
/// view needs to tell "being done now" from "was done".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationSummary {
    pub operation: String,
    pub state: Option<String>,
    pub kind: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// Which device the operation is about. `None` on a journal too old or too broken to
    /// say — and an operation whose target is unknown is never silently attached to a row.
    pub target: Option<OperationTarget>,
    /// Whether a worker is alive for it on the deployment host.
    pub running: bool,
    pub readable: bool,
    /// The journal's `last_error`, in words, when it recorded one.
    pub last_error: Option<String>,
}

/// Enough of an operation's target to put it on the row it belongs to.
///
/// **Both fields are identity, not text.** They are the strings the runtime sent, kept
/// whole, and nothing draws them: what a person reads about an operation comes from the
/// row it was matched to and from [`OperationSummary`]'s own bounded fields. Bounding
/// these would be the bug — [`text`] cuts a field at `FIELD_COLUMNS`, so two hosts that
/// differ only after column 71 are one string by the time they are compared, and an
/// operation against one would take the other row's command away and put `setting up…`
/// on a device nothing is happening to.
///
/// [`IDENTITY_LIMIT`] is the one bound, and it is about not holding a megabyte per row
/// rather than about what a person sees; `crate::fleet`'s own host rule stops well short
/// of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationTarget {
    pub machine: Option<String>,
    pub address: Option<String>,
}

impl OperationTarget {
    fn decode(value: &Value) -> Option<Self> {
        let target = value.as_object()?;
        let decoded = Self {
            machine: identity(target.get("machine").map(|v| v as &Value)),
            address: identity(target.get("address").map(|v| v as &Value)),
        };

        // A target naming neither a machine nor an address identifies no row.
        (decoded.machine.is_some() || decoded.address.is_some()).then_some(decoded)
    }

    /// Whether this target is the device in `row`.
    ///
    /// The address first, because that is what the worker actually talks to and what a
    /// machine name can be made to collide with; the machine name only when both sides
    /// have one — and **never** a display name. `row.name` is what the device calls
    /// itself, and matching an operation on it would let any peer on the network put
    /// `setting up…` on a member's row by renaming itself.
    pub fn is(&self, row: &DeviceRow) -> bool {
        if let (Some(mine), Some(theirs)) = (self.address.as_deref(), row.address_identity()) {
            if mine == theirs {
                return true;
            }
        }

        match (self.machine.as_deref(), row.machine_identity()) {
            (Some(mine), Some(theirs)) => mine == theirs,
            _unnamed => false,
        }
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
            target: value.get("target").and_then(OperationTarget::decode),
            running: value
                .get("running")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            readable: value
                .get("readable")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            last_error: last_error(value.get("last_error")),
        }
    }

    /// Whether this operation is still going, or waiting on somebody.
    ///
    /// Only the four states that have *stopped* say no. A state this build has never seen
    /// is still going, for the same reason [`Inventory::ouroboros_word`] already calls it
    /// `setting up…`: of the two ways to be wrong about a code from the future, printing
    /// "run this" next to a machine something may be halfway through installing on is the
    /// worse one. A journal with no state at all is not an operation in progress — it is
    /// a record nobody could read, and the details pane says so.
    pub fn underway(&self) -> bool {
        match self.state.as_deref() {
            None => false,
            Some("completed") | Some("failed") | Some("cancelled") | Some("interrupted") => false,
            Some(_going) => true,
        }
    }

    /// The state in words, from the one catalogue both surfaces read.
    pub fn state_label(&self) -> String {
        match self.state.as_deref() {
            Some(state) => operation_state(state),
            None if !self.readable => "this operation's record could not be read".into(),
            None => "state not recorded".into(),
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
    /// the self row's machine name rather than inventing one.
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

    /// Whether this machine has no fleet profile at all. The self row says so — it is the
    /// one row whose state is about this machine rather than about a peer.
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

    /// The rows in the order §5.1 draws them: this machine first, then the fleet's
    /// machines, then everything discovery found. One list, no sections, no legend.
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
    /// opposite of what just happened — the live run that found this was a real removal
    /// against a Raspberry Pi, and the row announced a setup.
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
            Some("cancelled") | Some("interrupted") | None => row.ouroboros_word(),
            Some(_running) if leaving => "removing\u{2026}".into(),
            Some(_running) => "setting up\u{2026}".into(),
        }
    }

    /// The command on this row, with any operation already running on it folded in.
    ///
    /// A device the runtime is mid-operation on has nothing for a person to type: the
    /// command that would start it has been run. What it has instead is a state, which
    /// the Ouroboros column is already saying, and a last error, which the details pane
    /// carries. An operation that has *stopped* — failed, cancelled, interrupted —
    /// leaves the row its ordinary command, because running it again is the repair.
    pub fn recipe(&self, row: &DeviceRow) -> Recipe {
        match latest_operation_for(self, row) {
            Some(operation) if operation.underway() => Recipe::None,
            _nothing_running => row.recipe(),
        }
    }

    /// The fleet's machines, which is what "N of M connected" counts.
    pub fn members(&self) -> Vec<&DeviceRow> {
        self.devices
            .iter()
            .filter(|row| row.machine.is_some())
            .collect()
    }

    /// Whether the status line is describing a fleet at all.
    ///
    /// False for a document with no rows, and for one whose rows name no machine of this
    /// fleet. The renderer colours the line neutrally then: the green is the "your fleet
    /// is here, and this much of it is connected" colour, and a green line saying nothing
    /// is reassurance attached to nothing.
    pub fn describes_a_fleet(&self) -> bool {
        !self.members().is_empty()
    }

    /// The line above the list: either this machine has no fleet, or the fleet's name
    /// and how much of it is here — or, when the runtime reported neither, that.
    ///
    /// This *is* the blocker sentence for a standalone host — §5.1 is explicit that it
    /// is the status line rather than a second paragraph underneath one.
    ///
    /// The arithmetic is drawn only when there is something to count. `devices: null`, a
    /// `[]`, a `{}` and a document this client could read no row out of all used to reach
    /// it and print *Fleet of this machine · 0 of 0 machines connected*, in the colour of
    /// a healthy fleet — a sentence about a fleet the runtime never mentioned, assembled
    /// entirely out of this client's own fallbacks.
    pub fn status_line(&self) -> String {
        if self.standalone() {
            return format!("{} is not in a fleet yet", self.host.self_label());
        }

        if self.devices.is_empty() {
            return "This runtime reported no devices.".into();
        }

        let members = self.members();
        let total = members.len();

        if total == 0 {
            return match self.fleet_name.as_deref() {
                Some(name) => format!(
                    "{} \u{b7} this runtime listed none of its machines",
                    scrub(name, 40)
                ),
                None => "This runtime reported no fleet.".into(),
            };
        }

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
/// Two facts that are different: a runtime that does not serve the method at all, and one
/// that serves it and would not answer this identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `hello.methods` does not list `fleet.devices`.
    CapabilityAbsent,
    /// The method is served and answered `-32003`. `fleet.devices` is a *read*-scope
    /// method, so a read-scope listener passes the scope gate: a refusal here can only
    /// be the identity rule, which demands an administrator for this one read.
    NotAdministrator,
    /// Anything else the gateway said, kept as it said it.
    Other(String),
}

impl Refusal {
    /// The one sentence this view owes: why the inventory is unavailable, distinguishing
    /// an absent capability from a denied permission.
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
            Self::Other(message) => format!("The runtime refused the inventory: {message}"),
        }
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
/// opening it again is free. There is nothing in here whose drop stops anything, because
/// there is nothing here that started anything.
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
    /// How far the page is scrolled. The list follows its cursor; `PageUp`/`PageDown`
    /// page it explicitly.
    pub scroll: usize,
    /// Manual paging leaves selection alone, so the details of a row that has scrolled
    /// off can be read.
    pub inventory_paging: bool,
    /// Whether Enter has opened the details pane for the row under the cursor.
    pub details: bool,
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

    /// The row under the cursor, for the details pane.
    pub fn selected<'a>(&self, inventory: &'a Inventory) -> Option<&'a DeviceRow> {
        self.visible(inventory).get(self.cursor).copied()
    }
}

// ----------------------------------------------------------------------- the App side

impl App {
    /// `/devices`, the palette row, the rebindable action, and the Settings link.
    ///
    /// Toggles like the other pages: pressing the verb twice is how an operator checks
    /// something and gets back to what they were doing.
    pub fn open_devices(&mut self) {
        if matches!(self.overlay, Some(Overlay::Devices)) {
            self.close_devices();
            return;
        }

        self.devices.inventory_paging = false;
        self.devices.details = false;
        // Re-read on every open: the whole point of an inventory is that it is what is
        // there now, and a cached list of machines is a list of machines that were.
        self.devices.inventory.invalidate();
        self.devices.fallback.invalidate();

        self.overlay = Some(Overlay::Devices);
        self.poll_devices();
    }

    /// Drop whatever is over the screen.
    pub(super) fn close_overlay(&mut self) {
        let _dropped = self.overlay.take();
    }

    /// Leaving the view. It holds nothing that has to be undone.
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
            "devices   {} \u{b7} the machines this runtime can see",
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
    }

    /// The runtime this client is attached to is back: read the list again.
    pub(super) fn devices_reconnected(&mut self) {
        self.devices.inventory.invalidate();
        self.devices.fallback.invalidate();
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
                self.devices.refusal = Some(devices_refusal(&error));
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

    // ----- keys ------------------------------------------------------------------

    pub(super) fn devices_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;

        if !matches!(key.code, KeyCode::PageDown | KeyCode::PageUp) {
            self.devices.inventory_paging = false;
        }

        // The search field owns every printable character while it is open, so `r` cannot
        // be typed into a query and swallowed as a verb.
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
            // One door at a time: the details pane closes before the view does, because
            // Esc on an open pane meaning "close the whole page" is how a reader loses
            // the list they were halfway down.
            KeyCode::Esc if self.devices.details => self.devices.details = false,
            KeyCode::Esc | KeyCode::Char('q') => self.close_devices(),
            KeyCode::Char('r') => {
                self.devices.inventory.invalidate();
                self.devices.fallback.invalidate();
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
            KeyCode::Char('j') | KeyCode::Down => {
                self.devices.cursor = (self.devices.cursor + 1).min(rows.saturating_sub(1))
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.devices.cursor = self.devices.cursor.saturating_sub(1)
            }
            KeyCode::PageDown => {
                self.devices.inventory_paging = true;
                self.devices.scroll = self.devices.scroll.saturating_add(10);
            }
            KeyCode::PageUp => {
                self.devices.inventory_paging = true;
                self.devices.scroll = self.devices.scroll.saturating_sub(10);
            }
            // A10: a numbered menu is only a numbered menu if the number selects.
            KeyCode::Char(digit)
                if access::screen_reader()
                    && access::row_for_digit(digit).is_some_and(|row| row < rows) =>
            {
                self.devices.cursor = access::row_for_digit(digit).expect("a digit row");
            }
            // The one thing Enter does here: open the pane that says what this device is
            // and what to run about it. Nothing on this page starts anything.
            KeyCode::Enter => self.devices.details = !self.devices.details,
            _other => {}
        }
    }

    /// A bracketed paste while this view owns the keyboard.
    ///
    /// The search field is the only thing here that takes text — there is no form and no
    /// secret — and a paste anywhere else is refused so the driver can say so rather than
    /// swallow it.
    pub(super) fn devices_paste(&mut self, flattened: &str) -> bool {
        if !self.devices.searching {
            return false;
        }

        self.devices.query.push_str(flattened);
        self.devices.cursor = 0;
        true
    }
}

// -------------------------------------------------------------------------- the view

pub fn devices_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    inventory_lines(app, &mut lines);
    lines
}

/// The one quiet line that says whose machine the commands are for, and as whom.
fn actions_line(app: &App) -> String {
    app.devices
        .inventory
        .value
        .as_ref()
        .map(|inventory| inventory.host.actions_line())
        .unwrap_or_else(|| "Actions run on the machine hosting this runtime.".into())
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
            // The one line that is an invitation rather than a report.
            theme::accent()
        } else if inventory.describes_a_fleet() {
            theme::good()
        } else {
            // Nothing to be reassured about: the runtime named no machine of a fleet.
            theme::muted()
        }),
    )));

    // The deploying-from line: one line under the title, on every screen this view has.
    lines.push(Line::from(Span::styled(
        actions_line(app),
        Style::default().fg(theme::muted()),
    )));

    // One inline notice with the client's own words, never a claim about build age.
    if let Some(notice) = inventory.discovery.notice() {
        lines.push(Line::from(Span::styled(
            access::speakable(&scrub(&notice, MESSAGE_COLUMNS)),
            Style::default().fg(theme::warn()),
        )));
    }

    // Whatever this runtime says it cannot do, said once, above the list rather than on
    // each row. On a machine with no fleet the status line has already said it is not in
    // one, so what is left here is whatever *else* it reported.
    if let Some(blocker) = inventory.host.blocker() {
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

    // The details of the selected row, under the list, when Enter has asked for them.
    if state.details {
        if let Some(row) = state.selected(inventory) {
            blank(lines);
            details_lines(app, inventory, row, lines);
        }
    }

    blank(lines);
    lines.push(Line::from(vec![
        Span::styled("Not listed?  ", Style::default().fg(theme::muted())),
        Span::styled(
            Recipe::manual(),
            Style::default().fg(theme::action_colour()),
        ),
    ]));

    if !inventory.unknown.is_empty() {
        lines.push(Line::from(Span::styled(
            access::speakable(&unknown_keys_line(&inventory.unknown)),
            Style::default().fg(theme::muted()),
        )));
    }
}

/// How many of the keys this build did not read are named before the line gives up and
/// counts the rest.
///
/// A list is bounded by how long it is as well as by how wide each entry is. Each key
/// arrives through [`text`] and is at most `FIELD_COLUMNS` wide, and five thousand of
/// them were still joined into one 370 000-character `Line` — a paste of the whole
/// document into the pane, in the colour of an aside.
const UNKNOWN_KEYS_NAMED: usize = 4;

/// How wide a named key may be here.
///
/// Narrower than `FIELD_COLUMNS`, which is what it arrived bounded to. Four keys at full
/// width leave no room in a `MESSAGE_COLUMNS` sentence for the number at the end — and
/// the number is the part that matters, because it is the one thing a reader cannot work
/// out from what is shown. A key is an identifier; thirty-two columns name it.
const UNKNOWN_KEY_COLUMNS: usize = 32;

/// The keys this client does not read, named while they fit and counted after that.
fn unknown_keys_line(keys: &[String]) -> String {
    let named = keys
        .iter()
        .take(UNKNOWN_KEYS_NAMED)
        .map(|key| scrub(key, UNKNOWN_KEY_COLUMNS))
        .collect::<Vec<_>>()
        .join(", ");

    let sentence = match keys.len().saturating_sub(UNKNOWN_KEYS_NAMED) {
        0 => format!("this runtime also reported {named}, which this client does not read"),
        more => format!(
            "this runtime also reported {named} and {more} other key{}, which this client \
             does not read",
            if more == 1 { "" } else { "s" }
        ),
    };

    // Named keys are bounded one by one; the sentence they are in is bounded as a whole,
    // like every other sentence this view composes out of somebody else's words.
    scrub(&sentence, MESSAGE_COLUMNS)
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
const NAME_COLUMNS: usize = 17;

/// How many columns a device's other fields may occupy. Also a device's choice.
const ROW_FIELD_COLUMNS: usize = 44;

/// How many columns a line this build composed may occupy.
///
/// Wider, because the words are this client's: a remote string inside one has already
/// been bounded on the way in, and holding the whole sentence to a hostile name's budget
/// only truncates the part that says what is going on.
const OWN_WORDS_COLUMNS: usize = 96;

/// "macOS", "linux", "iOS": five is the widest the network client reports, plus the
/// column the truncation marker takes when a longer one arrives.
const OS_COLUMNS: usize = 6;
const ADDRESS_COLUMNS: usize = 16;
/// "○ offline, seen 3 days ago" is twenty-six columns; "● online" is the other shape.
/// Two over, because [`human`] keeps one column back for the cut marker and a cell that
/// fits its longest value exactly is a cell that truncates it.
const PRESENCE_COLUMNS: usize = 28;
/// "in the fleet · not connected" is twenty-eight, the longest of §5.1's words, and the
/// same one-column allowance applies.
const STATE_COLUMNS: usize = 30;

/// The command column's floor: what the row gives a command on a terminal only just wide
/// enough for one-line rows at all. The whole command is always in the details pane, so
/// this is where a long one is cut rather than where it is lost.
const COMMAND_COLUMNS: usize = 29;

/// The command column's ceiling. A recipe is composed here out of fields that were each
/// bounded on the way in, so this is a layout bound rather than a safety one — but it is
/// still a bound, because the cell is the last one on the row and an unbounded width on
/// a terminal that reports a silly one is a padding loop nobody asked for.
const COMMAND_LIMIT: usize = 72;

/// What the details pane gives a command, which is all of it.
///
/// The longest one this client can compose is
/// `ouro fleet add USER@<host> --machine <name>`, and the two arguments are bounded by
/// the validators that accept them: `crate::fleet`'s host rule allows 253 characters and
/// its machine rule 40, so the line is at most 324. Wider than that, so the pane is the
/// one place a recipe is never cut — which is what makes cutting it on the row safe.
const COMMAND_PANE_COLUMNS: usize = 340;

/// Pads a value out to `columns` *display* columns.
///
/// Not `{:<width$}`, which counts `char`s. A name of ten CJK ideographs is ten characters
/// and twenty columns, so padding it by character count pushed every cell after it eight
/// columns to the right — the column boundary moving because of what a device called
/// itself, which is the one thing these cells exist to prevent. [`human`] already bounds
/// by display width on the way in; this closes the other half.
fn pad(value: &str, columns: usize) -> String {
    use unicode_width::UnicodeWidthStr;

    let width = UnicodeWidthStr::width(value);

    format!("{value}{}", " ".repeat(columns.saturating_sub(width)))
}

/// One cell of the list, bounded to its width and padded out to it.
///
/// Every column goes through here, including the ones this build composed. The column
/// boundary has to be a fact about the row rather than an alignment the longest value
/// happens to respect: a presence string that overran its cell used to push the Ouroboros
/// column along, and a name that can move a column is a name that can forge a row.
fn column(value: &str, columns: usize) -> String {
    pad(&scrub(value, columns), columns + 2)
}

/// The columns a full-width row needs: marker, name, OS, address, presence, the Ouroboros
/// word and the command. Below this the row is drawn on two lines on purpose, because a
/// Paragraph wrapping one long line puts "seen 3 days" on one row and "ago" on the next,
/// in the wrong column.
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
    + COMMAND_COLUMNS;

/// Everything on a row before the command, which is what the command's own width is
/// whatever is left of.
const ROW_COLUMNS_BEFORE_COMMAND: usize = FULL_ROW_COLUMNS - COMMAND_COLUMNS;

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

/// How much of the command a row can show. Whatever the terminal has left after the
/// fixed columns, between the floor and the ceiling — the full command on a wide
/// terminal, its head and a visible cut on a narrow one, and the whole of it in the
/// details pane either way.
fn command_columns(app: &App) -> usize {
    overlay_columns(app)
        .saturating_sub(ROW_COLUMNS_BEFORE_COMMAND)
        .clamp(COMMAND_COLUMNS, COMMAND_LIMIT)
}

/// One device, one line: name, OS, address, presence, Ouroboros, and the command for the
/// one thing to do about it. On a narrow terminal, two lines: the name, address and
/// presence on the first (which carries the cursor marker), the Ouroboros word and the
/// command on the second, indented under the name.
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
    let recipe = inventory.recipe(row);
    let narrow = narrow_rows(app);

    let name_span = Span::styled(
        // Four spare columns rather than two: screen-reader mode puts "10. " in front
        // of the name, and a number that pushed the OS column along would undo the
        // boundary the narrow name column exists to draw.
        format!("{marker}{}", pad(&name, NAME_COLUMNS + 4)),
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
    // The last cell of a line is never padded: the pane wraps a trailing run of spaces
    // onto a blank row of its own, which reads as another line per device.
    let command_span = Span::styled(
        scrub(&recipe.words(), command_columns(app)),
        Style::default().fg(if recipe == Recipe::None {
            theme::muted()
        } else {
            theme::action_colour()
        }),
    );

    if narrow {
        let presence_end = Span::styled(
            scrub(&row.presence_short(), PRESENCE_COLUMNS),
            presence_span.style,
        );
        lines.push(Line::from(vec![name_span, address_span, presence_end]));
        lines.push(Line::from(vec![
            Span::raw("      "),
            state_span,
            command_span,
        ]));
        return;
    }

    lines.push(Line::from(vec![
        name_span,
        os_span,
        address_span,
        presence_span,
        state_span,
        command_span,
    ]));
}

/// The pane under the list: the command in full, the facts that do not fit on a row, and
/// whatever the runtime is already doing about this device.
///
/// Read-only, all of it. Nothing on this page is a control.
fn details_lines(
    app: &App,
    inventory: &Inventory,
    row: &DeviceRow,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(Line::from(Span::styled(
        access::speakable(&inventory.row_label(row)),
        theme::heading(),
    )));

    // The command, whole, and whose shell it belongs in. A recipe without that second
    // fact is a line somebody types into the wrong machine's terminal.
    match inventory.recipe(row).command() {
        Some(command) => {
            detail_field(
                lines,
                "to run",
                scrub(command, COMMAND_PANE_COLUMNS),
                Style::default().fg(theme::action_colour()),
            );
            detail_field(
                lines,
                "",
                scrub(&inventory.host.actions_line(), OWN_WORDS_COLUMNS),
                Style::default().fg(theme::muted()),
            );
        }
        None => detail_field(
            lines,
            "to run",
            "\u{2014}".into(),
            Style::default().fg(theme::muted()),
        ),
    }

    let mut where_it_is = vec![scrub(
        row.address.as_deref().unwrap_or("no address"),
        ROW_FIELD_COLUMNS,
    )];

    if let Some(path) = row.path.as_deref() {
        where_it_is.push(scrub(path, ROW_FIELD_COLUMNS));
    }
    if let Some(machine) = row.machine.as_deref() {
        where_it_is.push(format!("in the fleet as {}", scrub(machine, NAME_COLUMNS)));
    }

    detail_field(
        lines,
        "address",
        where_it_is.join(" \u{b7} "),
        Style::default(),
    );
    // The *exact* time lives here. The row carries a relative one; this is the fact.
    detail_field(lines, "presence", row.presence(), Style::default());
    detail_field(
        lines,
        "ouroboros",
        scrub(&inventory.ouroboros_word(row), OWN_WORDS_COLUMNS),
        Style::default(),
    );

    if let Some(facts) = row.runtime_facts() {
        detail_field(
            lines,
            "runtime",
            scrub(&facts, OWN_WORDS_COLUMNS),
            Style::default(),
        );
    }

    if let Some(summary) = latest_operation_for(inventory, row) {
        let mut parts = vec![scrub(&summary.operation, OWN_WORDS_COLUMNS)];

        parts.push(summary.state_label());

        if summary.running {
            parts.push("a worker is running it".into());
        }
        if let Some(updated) = summary.updated_at.as_deref() {
            parts.push(scrub(updated, ROW_FIELD_COLUMNS));
        }

        detail_field(lines, "operation", parts.join(" \u{b7} "), Style::default());

        // The worker's own last words, where somebody asking why it says "setup failed"
        // will look. Never a control: this view answers nothing.
        if let Some(error) = summary.last_error.as_deref() {
            detail_field(
                lines,
                "last error",
                scrub(error, OWN_WORDS_COLUMNS),
                Style::default().fg(theme::warn()),
            );
        }
    }

    // Why there is no command, said once, where somebody who opened this pane will look.
    //
    // This row's own reason only. A blocker that belongs to the *host* is true of every
    // row at once, so it is the line above the list; repeating it here would be the same
    // fact twice on one screen.
    if let Some(reason) = row.no_recipe_reason() {
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

    let _ = app;
}

fn detail_field(lines: &mut Vec<Line<'static>>, label: &str, value: String, style: Style) {
    lines.push(Line::from(vec![
        Span::styled(format!("  {label:<12}"), theme::label()),
        Span::styled(value, style),
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

/// The one row that is always on the page: the keys that work, here, now.
pub fn devices_hint_line(app: &App) -> String {
    let state = &app.devices;

    if state.searching {
        return "type to search by name or address \u{b7} Enter keeps it \u{b7} Esc clears it"
            .into();
    }

    if state.inventory_paging {
        return "PgUp/PgDn scroll \u{b7} Enter details \u{b7} Esc close".into();
    }

    let narrowing = state
        .inventory
        .value
        .as_ref()
        .is_some_and(|inventory| state.narrowing(inventory));

    // The same keys in fewer words on a narrow terminal, where the long form is cut off
    // mid-word by the footer row and the last keys are the ones that vanish.
    let mut hint = if narrow_rows(app) {
        format!(
            "\u{2191}\u{2193} Enter {} \u{b7} r refresh",
            if state.details { "hide" } else { "details" }
        )
    } else {
        format!(
            "\u{2191}\u{2193} select \u{b7} Enter {} \u{b7} r refresh",
            if state.details {
                "hide details"
            } else {
                "show details"
            }
        )
    };

    // The keys on this row are the keys that work. `/` and `f` exist only past eight
    // rows, so on a list of four they are not offered.
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

/// One remote string, made safe to draw and bounded to `columns`.
///
/// **Every** string this view draws that some other machine chose goes through here: a
/// device's hostname and address, a fleet's name, an operation's recorded error, a
/// gateway's refusal message and its reason code.
///
/// It is [`human`] and nothing else. That function drops what a terminal would obey
/// (C0 and C1 controls, ESC, the newlines and tabs that would let one field draw several
/// rows), drops what a person cannot see (default-ignorable code points — a zero-width
/// space, a joiner, a soft hyphen, which are how `bui\u{200b}ld-linux` is made to read as
/// `build-linux`), collapses the whitespace around what it removed, and cuts the result
/// to `columns` of *display* width with a visible marker. This wrapper used to pre-filter
/// the ignorables itself and claim in its own documentation that bounding alone left them
/// behind; it does not, and `human`'s first statement is that filter.
/// `tui/tests/fixtures/tailscale/hostile-names.json` is the peer list all of this is for.
pub fn scrub(raw: &str, columns: usize) -> String {
    human(raw, columns)
}

/// A string field of a reply, scrubbed and bounded.
fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| scrub(raw, FIELD_COLUMNS))
        .filter(|text| !text.is_empty())
}

/// How much of a string kept for comparison is kept.
///
/// Not a presentation bound — nothing built with [`identity`] is drawn. It is here so a
/// document cannot make this client hold a megabyte per row, and it is far above
/// anything the grammar on the other side allows: `crate::fleet`'s host rule stops at
/// 253 characters and its machine rule at 40.
const IDENTITY_LIMIT: usize = 512;

/// A string field kept for comparison rather than for the screen.
///
/// Deliberately **not** [`text`]. Scrubbing and bounding are what make a string safe to
/// draw, and both of them destroy identity: `human` collapses whitespace, drops
/// invisible characters and cuts at `FIELD_COLUMNS`, so two values that differ only in
/// what it removed become one. That is the right trade for a cell and the wrong one for
/// the question "is this operation about this device".
fn identity(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|raw| !raw.is_empty())
        .map(|raw| raw.chars().take(IDENTITY_LIMIT).collect())
}

/// A sentence rather than a field: longer, and scrubbed the same way.
fn sentence(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(|raw| scrub(raw, MESSAGE_COLUMNS))
        .filter(|text| !text.is_empty())
}

/// An operation's `last_error`, out of whichever shape the journal carries it in.
///
/// Lenient on purpose (§9 rewrote the journal): a bare string, or the schema-2 object of
/// a snake_case `reason` and a `detail`. Anything else is no error rather than a guess,
/// and a `reason` this build predates still reads as a sentence because the catalogue's
/// fallback names it in its own words.
fn last_error(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(_)) => sentence(value),
        Some(object @ Value::Object(_)) => {
            let reason = text(object.get("reason"));
            let detail = sentence(object.get("detail"));

            match (reason, detail) {
                (Some(reason), Some(detail)) => {
                    Some(format!("{} \u{2014} {detail}", reason_sentence(&reason)))
                }
                (Some(reason), None) => Some(reason_sentence(&reason)),
                (None, detail) => detail,
            }
        }
        _absent => None,
    }
}

/// A machine name as an argument of a printed command, or `None` for anything that is
/// not one.
///
/// The one place where scrubbing is not enough. Everywhere else a remote string is drawn
/// *as* a remote string, inside its own cell, and the worst it can do is look like
/// something; here it is drawn inside a command line a person is being invited to run,
/// and a space in it is a second argument. [`scrub`] answers an escape sequence by
/// deleting the escape byte — which turns `pi\u{1b}[2K\u{1b}[1G--machine pwned` into
/// `pi [2K [1G--machine pwned`, a perfectly runnable second `--machine`. A newline
/// collapses to a space and does the same with a whole second command.
///
/// So the argument is *validated*, not repaired — and validated by the code that will
/// read the line when it is pasted, [`crate::fleet::validate_machine`], rather than by a
/// copy of its rule. A copy drifted the moment it was written: this one allowed `_` and a
/// trailing hyphen, which `ouro` refuses, so the view printed command lines that fail.
/// A value the parser would reject is worse than the placeholder, because the placeholder
/// says "choose one" and a rejected name says the command is broken.
fn machine_argument(raw: &str) -> Option<String> {
    let name = raw.trim();

    crate::fleet::validate_machine(name)
        .ok()
        .map(|()| name.to_string())
}

/// An address as an argument of a printed command, or `None`.
///
/// The same rule for the same reason, from the same place:
/// [`crate::fleet::canonical_host`] is what `ouro fleet add` puts in a certificate, and
/// what it refuses — an IPv6 literal, anything carrying `:`, a public IPv4, an all-numeric
/// top label, an `@`. The copy this replaced allowed `:` outright, so the view printed
/// `USER@fd7a::1` under a device `ouro` will not add.
///
/// Canonical rather than as-reported: a DNS name is case-insensitive and may carry the
/// root dot, and the spelling that goes in the command should be the spelling the parser
/// will settle on rather than a third one.
fn address_argument(raw: &str) -> Option<String> {
    crate::fleet::canonical_host(raw.trim()).ok()
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

/// The stable reason code a refusal carries, when it carries one.
///
/// Through [`text`], like every other string that arrives from the wire. A reason is
/// supposed to be a snake_case identifier out of one small catalogue, but "supposed to"
/// is what the gateway sends rather than what this client can rely on, and the one arm
/// that prints an uncatalogued one prints it as itself.
fn refusal_reason(error: &ClientError) -> Option<String> {
    let ClientError::Rpc(rpc) = error else {
        return None;
    };

    text(rpc.data.as_ref()?.get("reason"))
}

/// Why the inventory is not here, from what the gateway answered.
///
/// `fleet.devices` is a **read**-scope method, so a listener started at read scope
/// passes the scope gate: a `-32003` on it is the identity rule, which demands an
/// administrator for this one read. That is the distinction both surfaces draw, and it is
/// derivable rather than guessed.
fn devices_refusal(error: &ClientError) -> Refusal {
    match error {
        ClientError::Rpc(rpc) => match rpc.code {
            ErrorCode::MethodNotFound => Refusal::CapabilityAbsent,
            ErrorCode::ScopeDenied => Refusal::NotAdministrator,
            ErrorCode::UpstreamTimeout => Refusal::Other(
                "the inventory outlived the gateway's ceiling. The network client did not \
                 stop working; press r to ask again."
                    .into(),
            ),
            // Both arms go through [`clean`]. The `message` one always did; the `reason`
            // one did not, and an uncatalogued code is interpolated into a sentence by
            // [`reason_sentence`], so a gateway that answered `reason: "<ESC>[2J…"` drew
            // it. A reason is a remote string like any other, and there is exactly one
            // way a remote string reaches a `Line`.
            _other => Refusal::Other(clean(&match refusal_reason(error) {
                Some(reason) => reason_sentence(&reason),
                None => rpc.message.clone(),
            })),
        },
        other => Refusal::Other(clean(&other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_network::DiscoveryCode;

    fn row(state: &str) -> DeviceRow {
        DeviceRow {
            state: state.into(),
            ..Default::default()
        }
    }

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
                .expect("a serialisable state")
                .as_str()
                .expect("a string code")
                .to_string();

            assert_eq!(
                parse_state(&code),
                Some(state),
                "{code} does not round-trip through the view's own table"
            );

            let row = DeviceRow {
                state: code.clone(),
                ..Default::default()
            };
            assert_eq!(
                row.state_label(),
                state.label(),
                "{code} does not print the CLI's words"
            );
        }
    }

    /// Every state this client knows lands on one of §5.1's Ouroboros phrases, and an
    /// unknown one on a sentence naming itself.
    #[test]
    fn every_state_lands_on_one_of_the_columns_words() {
        const WORDS: [&str; 5] = [
            "in the fleet",
            "in the fleet \u{b7} not connected",
            "not set up",
            "can't run Ouroboros",
            "offline",
        ];

        for code in [
            "this_device",
            "this_device_without_profile",
            "fleet_member",
            "fleet_member_not_visible",
            "fleet_member_connected",
            "discovered_installation_unknown",
            "peer_offline",
            "unsupported_platform",
            "no_usable_ipv4",
        ] {
            let word = row(code).ouroboros_word();
            assert!(
                WORDS.contains(&word.as_str()),
                "{code} drew {word}, which is not one of the column's words"
            );
        }

        let unknown = row("quantum_entangled").ouroboros_word();
        assert!(
            unknown.contains("quantum_entangled") && unknown.contains("does not know"),
            "an unknown state must name itself: {unknown}"
        );
    }

    /// The recipe is the command, and what the runtime could not name is a placeholder in
    /// capitals rather than a plausible guess.
    #[test]
    fn each_row_prints_the_one_command_for_it() {
        let standalone = DeviceRow {
            state: "this_device_without_profile".into(),
            suggested_machine: Some("operator-laptop".into()),
            ..Default::default()
        };
        assert_eq!(
            standalone.recipe(),
            Recipe::Command("ouro fleet setup --machine operator-laptop".into())
        );

        let peer = DeviceRow {
            state: "discovered_installation_unknown".into(),
            address: Some("100.64.12.44".into()),
            suggested_machine: Some("build-linux".into()),
            ..Default::default()
        };
        assert_eq!(
            peer.recipe(),
            Recipe::Command("ouro fleet add USER@100.64.12.44 --machine build-linux".into()),
            "the account is unknown, so USER@ is literal"
        );

        let member = DeviceRow {
            state: "fleet_member".into(),
            machine: Some("pi".into()),
            ..Default::default()
        };
        assert_eq!(
            member.recipe(),
            Recipe::Command("ouro fleet leave --machine pi --user USER".into())
        );

        // This machine leaves where it is: no account, no address.
        let here = DeviceRow {
            state: "this_device".into(),
            machine: Some("studio".into()),
            ..Default::default()
        };
        assert_eq!(here.recipe(), Recipe::Command("ouro fleet leave".into()));

        for code in ["peer_offline", "unsupported_platform", "no_usable_ipv4"] {
            assert_eq!(
                row(code).recipe(),
                Recipe::None,
                "{code} must offer no command"
            );
            assert!(
                row(code).no_recipe_reason().is_some(),
                "{code} must say why"
            );
        }

        // Nothing the runtime could not name is invented.
        let nameless = DeviceRow {
            state: "discovered_installation_unknown".into(),
            name: "Monocursive's MacBook Pro".into(),
            ..Default::default()
        };
        assert_eq!(
            nameless.recipe(),
            Recipe::Command("ouro fleet add USER@ADDRESS --machine NAME".into()),
            "a display name is never a machine name"
        );
    }

    /// An argument of a printed command is validated, not repaired — by the parser's own
    /// rule, so a line this view prints is a line `ouro` accepts.
    #[test]
    fn an_argument_that_is_not_one_becomes_the_placeholder() {
        for good in ["pi", "build-linux", "studio2", "a", &"g".repeat(40)] {
            assert_eq!(machine_argument(good).as_deref(), Some(good), "{good}");
            // The property, not the copy of the rule: whatever this prints, `ouro` takes.
            assert!(crate::fleet::validate_machine(good).is_ok(), "{good}");
        }

        for bad in [
            "",
            " ",
            "-leading-hyphen",
            // `ouro` requires the *last* character to be alphanumeric too, and forbids
            // `_` outright. A copy of the rule allowed both, and printed lines that fail.
            "trailing-",
            "under_score",
            "a_b-c",
            "two words",
            // The raw escape, and what `scrub` would have left of it: both are a second
            // argument, and neither is a name.
            "pi\u{1b}[2K\u{1b}[1G--machine pwned",
            "pi [2K [1G--machine pwned",
            "pi ouro fleet add USER@evil.example --machine pwned",
            "pi;rm -rf ~",
            "pi$(id)",
            "pi\u{a0}--machine pwned",
            "pi\u{200b}x",
            &"g".repeat(41),
        ] {
            assert_eq!(machine_argument(bad), None, "{bad:?} was printed as a name");
        }

        for good in ["100.64.0.11", "10.0.0.2", "pi.tailnet-example.ts.net"] {
            assert_eq!(address_argument(good).as_deref(), Some(good), "{good}");
            assert!(crate::fleet::canonical_host(good).is_ok(), "{good}");
        }

        // Canonical, so the printed spelling is the one the parser settles on.
        assert_eq!(
            address_argument("PI.Tailnet-Example.TS.NET.").as_deref(),
            Some("pi.tailnet-example.ts.net")
        );

        for bad in [
            "",
            // `ouro fleet add` refuses these outright, so printing them would be a
            // command line that fails when it is pasted.
            "fd7a::1",
            "8.8.8.8",
            "100.64.0.11 --machine pwned",
            // The recipe writes the `@` itself; a second one moves the account.
            "evil@100.64.0.11",
            "100.64.0.11;curl evil",
            "100.64.0.11\u{1b}[1G",
            &"1".repeat(255),
        ] {
            assert_eq!(
                address_argument(bad),
                None,
                "{bad:?} was printed as an address"
            );
        }

        // And the row falls back rather than printing either of them.
        let hostile = DeviceRow {
            state: "discovered_installation_unknown".into(),
            address: Some("100.64.0.11 --machine pwned".into()),
            suggested_machine: Some("pi ouro fleet add USER@evil --machine pwned".into()),
            ..Default::default()
        };
        assert_eq!(
            hostile.recipe(),
            Recipe::Command("ouro fleet add USER@ADDRESS --machine NAME".into())
        );
    }

    /// A device the runtime is mid-operation on has nothing for a person to type; one it
    /// has stopped working on gets its command back.
    #[test]
    fn an_operation_underway_takes_the_command_off_the_row() {
        let peer = DeviceRow {
            state: "discovered_installation_unknown".into(),
            address: Some("100.64.12.44".into()),
            suggested_machine: Some("build-linux".into()),
            ..Default::default()
        };

        let with_state = |state: &str| Inventory {
            devices: vec![peer.clone()],
            operations: vec![OperationSummary {
                operation: "op-1".into(),
                state: Some(state.into()),
                kind: Some("add".into()),
                target: Some(OperationTarget {
                    address: Some("100.64.12.44".into()),
                    ..Default::default()
                }),
                readable: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        for going in ["inspecting", "deploying", "awaiting_review"] {
            let inventory = with_state(going);
            assert_eq!(
                inventory.recipe(&peer),
                Recipe::None,
                "{going} still offered a command"
            );
            assert_eq!(inventory.ouroboros_word(&peer), "setting up\u{2026}");
        }

        let failed = with_state("failed");
        assert_eq!(failed.ouroboros_word(&peer), "setup failed");
        assert!(
            matches!(failed.recipe(&peer), Recipe::Command(_)),
            "a stopped operation leaves the row its command"
        );

        // A state from the future is still going, so the row offers nothing to type —
        // and the column that already reads `setting up…` is not contradicted by it.
        let unknown = with_state("teleporting");
        assert_eq!(unknown.recipe(&peer), Recipe::None);
        assert_eq!(unknown.ouroboros_word(&peer), "setting up\u{2026}");

        // A journal nobody could read is not an operation in progress.
        let unreadable = Inventory {
            devices: vec![peer.clone()],
            operations: vec![OperationSummary {
                operation: "op-9".into(),
                target: Some(OperationTarget {
                    address: Some("100.64.12.44".into()),
                    ..Default::default()
                }),
                readable: false,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(matches!(unreadable.recipe(&peer), Recipe::Command(_)));
        assert!(unreadable.operations[0]
            .state_label()
            .contains("could not be read"));
    }

    /// A removal reads as a removal on the row it is about.
    #[test]
    fn a_removal_is_not_announced_as_a_setup() {
        let member = DeviceRow {
            state: "fleet_member".into(),
            machine: Some("pi".into()),
            ..Default::default()
        };

        let inventory = |state: &str| Inventory {
            devices: vec![member.clone()],
            operations: vec![OperationSummary {
                operation: "op-2".into(),
                state: Some(state.into()),
                kind: Some("leave".into()),
                target: Some(OperationTarget {
                    machine: Some("pi".into()),
                    ..Default::default()
                }),
                readable: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            inventory("deploying").ouroboros_word(&member),
            "removing\u{2026}"
        );
        assert_eq!(
            inventory("failed").ouroboros_word(&member),
            "removal failed"
        );
        assert_eq!(
            inventory("completed").ouroboros_word(&member),
            "removed just now"
        );
    }

    /// An operation is matched to its row by target, never by "is anything running".
    #[test]
    fn an_operation_is_matched_to_its_row_by_target() {
        let alpha = DeviceRow {
            state: "discovered_installation_unknown".into(),
            name: "alpha".into(),
            address: Some("100.64.0.1".into()),
            suggested_machine: Some("alpha".into()),
            ..Default::default()
        };
        let bravo = DeviceRow {
            address: Some("100.64.0.2".into()),
            name: "bravo".into(),
            suggested_machine: Some("bravo".into()),
            ..alpha.clone()
        };

        let inventory = Inventory {
            devices: vec![alpha.clone(), bravo.clone()],
            operations: vec![OperationSummary {
                operation: "op-3".into(),
                state: Some("deploying".into()),
                kind: Some("add".into()),
                target: Some(OperationTarget {
                    address: Some("100.64.0.2".into()),
                    ..Default::default()
                }),
                readable: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        assert!(matches!(inventory.recipe(&alpha), Recipe::Command(_)));
        assert_eq!(inventory.recipe(&bravo), Recipe::None);
        assert_eq!(inventory.ouroboros_word(&alpha), "not set up");

        // A target naming neither a machine nor an address belongs to no row at all.
        assert_eq!(OperationTarget::decode(&json!({"port": 22})), None);

        // **Never by display name.** `name` is what a device calls itself, so matching on
        // it would let any peer on this network put `setting up…` on a member's row, and
        // take that row's command away, by renaming itself.
        let member = DeviceRow {
            state: "fleet_member".into(),
            name: "raspberrypi".into(),
            machine: Some("pi".into()),
            ..Default::default()
        };
        let by_hostname = OperationTarget {
            machine: Some("raspberrypi".into()),
            address: None,
        };
        assert!(
            !by_hostname.is(&member),
            "an operation was matched to a member by its display name"
        );
        assert!(OperationTarget {
            machine: Some("pi".into()),
            address: None,
        }
        .is(&member));
    }

    /// Identity is the string the runtime sent, not the string the screen gets.
    ///
    /// `text` cuts a field at `FIELD_COLUMNS` and `human` keeps one column back for the
    /// marker, so two hosts differing only after column 71 are one string once bounded.
    /// An operation against one was then drawn on the other: `setting up…` on a device
    /// nothing was happening to, and no command on the row that needed one.
    #[test]
    fn two_hosts_that_differ_past_the_column_budget_are_two_rows() {
        let prefix = "a".repeat(75);
        let mine = format!("{prefix}1.example.ts.net");
        let theirs = format!("{prefix}2.example.ts.net");

        let row = |address: &str| {
            DeviceRow::decode(&json!({
                "name": "peer", "state": "discovered_installation_unknown",
                "address": address, "online": true,
            }))
        };

        let (alpha, bravo) = (row(&mine), row(&theirs));

        // The drawn field is one string for both; the identity is not.
        assert_eq!(alpha.address, bravo.address, "the cut is what it was");
        assert_ne!(alpha.address_identity(), bravo.address_identity());

        let target = OperationTarget::decode(&json!({ "address": theirs }))
            .expect("a target with an address");

        assert!(target.is(&bravo), "the operation lost its own row");
        assert!(
            !target.is(&alpha),
            "an operation against {theirs} was matched to {mine}"
        );

        // Nothing kept for identity is ever drawn, and it is still bounded — against a
        // document holding a megabyte per row rather than against a screen.
        assert_eq!(
            identity(Some(&json!("z".repeat(4_000))))
                .expect("an identity")
                .chars()
                .count(),
            IDENTITY_LIMIT
        );
        assert_eq!(identity(Some(&json!(""))), None);
        assert_eq!(identity(Some(&json!(7))), None);

        // A row built by hand rather than decoded has no key, and falls back to the
        // field it does have rather than matching nothing.
        let handmade = DeviceRow {
            address: Some("100.64.0.1".into()),
            machine: Some("pi".into()),
            ..Default::default()
        };
        assert_eq!(handmade.address_identity(), Some("100.64.0.1"));
        assert_eq!(handmade.machine_identity(), Some("pi"));
    }

    /// The journal's `last_error` is read out of either shape, and an unreadable one is
    /// no error rather than a guess.
    #[test]
    fn a_last_error_is_decoded_from_either_shape_and_never_invented() {
        assert_eq!(
            last_error(Some(&json!("the worker stopped"))).as_deref(),
            Some("the worker stopped")
        );

        let structured = last_error(Some(&json!({
            "reason": "host_key_changed",
            "detail": "ssh said the key is different"
        })))
        .expect("a sentence");
        assert!(
            structured.contains("host's key has changed"),
            "the reason is a sentence: {structured}"
        );
        assert!(
            structured.contains("ssh said the key is different"),
            "the detail is kept: {structured}"
        );

        // A reason this build predates still reads, in its own words.
        let future = last_error(Some(&json!({"reason": "from_the_future"}))).expect("a sentence");
        assert!(future.contains("from the future"), "{future}");

        assert_eq!(last_error(None), None);
        assert_eq!(last_error(Some(&Value::Null)), None);
        assert_eq!(last_error(Some(&json!(7))), None);
    }

    /// The document is decoded leniently: rows and operations without the schema-1 keys
    /// are read, and `issuer`, `owner` and `attached` are simply not looked at.
    #[test]
    fn a_document_without_the_withdrawn_keys_still_decodes() {
        let inventory = Inventory::decode(&json!({
            "host": {
                "hostname": "studio",
                "user": "ada",
                "os": "darwin",
                "capabilities": { "deploy": true, "reasons": [] }
            },
            "fleet_name": "studio",
            "discovery": { "code": "ok", "visible_peers": 1 },
            "devices": [{
                "name": "pi", "machine": "pi", "os": "linux",
                "address": "100.64.0.2", "online": true, "state": "fleet_member"
            }],
            "operations": [{
                "operation": "op-4", "kind": "add", "state": "deploying",
                "target": { "address": "100.64.0.2" }, "running": true
            }],
            "unknown": ["fleet_protocol_revision"]
        }));

        assert_eq!(inventory.host.hostname, "studio");
        assert_eq!(inventory.devices.len(), 1);
        assert!(inventory.operations[0].running);
        assert!(inventory.operations[0].underway());
        assert_eq!(
            inventory.unknown,
            vec!["fleet_protocol_revision".to_string()]
        );

        // And a document that still carries the withdrawn keys is read without them.
        let legacy = Inventory::decode(&json!({
            "host": { "hostname": "studio", "user": "ada", "issuer": true },
            "devices": [],
            "operations": [{
                "operation": "op-5", "owner": "ada", "attached": true,
                "target": { "machine": "pi" }
            }],
        }));
        assert_eq!(legacy.operations[0].operation, "op-5");
        assert!(
            !legacy.operations[0].running,
            "no `running` key is not running"
        );
        assert!(!legacy.operations[0].underway(), "no state is not underway");
    }

    #[test]
    fn every_discovery_code_keeps_the_cli_wording() {
        for code in [
            DiscoveryCode::Ok,
            DiscoveryCode::NoVisiblePeers,
            DiscoveryCode::ClientMissing,
            DiscoveryCode::SignedOut,
            DiscoveryCode::PermissionDenied,
            DiscoveryCode::Unavailable,
        ] {
            let name = serde_json::to_value(code)
                .expect("a serialisable code")
                .as_str()
                .expect("a string")
                .to_string();

            let discovery = Discovery {
                code: name.clone(),
                detail: None,
                visible_peers: 3,
            };

            assert!(
                !discovery.headline().is_empty(),
                "{name} has no headline of its own"
            );

            // Only a failure gets a notice, and the notice always carries the repair.
            match discovery.answered() {
                true => assert_eq!(discovery.notice(), None, "{name} drew a failure notice"),
                false => {
                    let notice = discovery.notice().expect("a notice");
                    assert!(
                        notice.contains("Devices already in the fleet are still listed."),
                        "{name} dropped the repair: {notice}"
                    );
                    assert!(
                        !notice.contains("older than the client"),
                        "{name} still guesses at a version mismatch"
                    );
                }
            }
        }
    }

    #[test]
    fn the_status_line_says_either_no_fleet_or_how_much_of_one_is_here() {
        let standalone = Inventory {
            host: DeploymentHost {
                os: Some("darwin".into()),
                ..Default::default()
            },
            devices: vec![row("this_device_without_profile")],
            ..Default::default()
        };
        assert_eq!(standalone.status_line(), "This Mac is not in a fleet yet");
        assert!(standalone.standalone());

        let fleet = Inventory {
            fleet_name: Some("studio".into()),
            devices: vec![
                DeviceRow {
                    state: "this_device".into(),
                    machine: Some("studio".into()),
                    ..Default::default()
                },
                DeviceRow {
                    state: "fleet_member".into(),
                    machine: Some("pi".into()),
                    connected: Some(false),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            fleet.status_line(),
            "studio \u{b7} 1 of 2 machines connected"
        );
        assert!(fleet.describes_a_fleet());
    }

    /// A document that names no machine of a fleet does not announce one.
    ///
    /// `0 of 0 machines connected`, in the colour reserved for a healthy fleet, was a
    /// sentence assembled entirely out of this client's own fallbacks: the runtime had
    /// said nothing about a fleet at all.
    #[test]
    fn a_document_with_no_machines_states_that_rather_than_a_fleet() {
        for devices in [Vec::new(), vec![row("discovered_installation_unknown")]] {
            let empty = devices.is_empty();
            let inventory = Inventory {
                devices,
                ..Default::default()
            };

            let line = inventory.status_line();
            assert!(
                !line.contains("0 of 0 machine"),
                "a document with no machines drew `{line}`"
            );
            assert!(
                !inventory.describes_a_fleet(),
                "`{line}` would be drawn in the healthy colour"
            );
            assert_eq!(
                line,
                if empty {
                    "This runtime reported no devices."
                } else {
                    "This runtime reported no fleet."
                },
                "{line}"
            );
        }

        // A named fleet whose machines this runtime did not list says which of the two
        // facts it has.
        let named = Inventory {
            fleet_name: Some("studio".into()),
            devices: vec![row("discovered_installation_unknown")],
            ..Default::default()
        };
        assert_eq!(
            named.status_line(),
            "studio \u{b7} this runtime listed none of its machines"
        );
        assert!(!named.describes_a_fleet());
    }

    #[test]
    fn the_self_row_takes_its_noun_from_the_host_os() {
        for (os, label) in [
            (Some("darwin"), "This Mac"),
            (Some("macos"), "This Mac"),
            (Some("linux"), "This machine"),
            (None, "This machine"),
        ] {
            let host = DeploymentHost {
                os: os.map(str::to_string),
                ..Default::default()
            };
            assert_eq!(host.self_label(), label);
        }
    }

    #[test]
    fn the_deploying_from_line_names_the_host_and_its_account() {
        let host = DeploymentHost {
            hostname: "studio".into(),
            user: "ada".into(),
            ..Default::default()
        };
        assert_eq!(host.actions_line(), "Actions run on studio as ada.");
    }

    #[test]
    fn each_blocker_is_explained_in_words() {
        for code in BLOCKER_CODES {
            let sentence = blocker_sentence(code);
            assert!(blocker_known(code), "{code} is not catalogued");
            assert!(
                !sentence.contains(code),
                "{code} printed as its identifier: {sentence}"
            );
        }

        let host = DeploymentHost {
            reasons: vec!["dev_runtime".into()],
            ..Default::default()
        };
        assert!(host
            .blocker()
            .is_some_and(|sentence| sentence.contains("development runtime")));
        assert_eq!(DeploymentHost::default().blocker(), None);
    }

    #[test]
    fn every_operation_state_has_words() {
        for code in OPERATION_STATES {
            assert!(operation_state_known(code), "{code} is not catalogued");
            let sentence = operation_state(code);
            assert!(
                !sentence.contains("does not know"),
                "{code} fell through: {sentence}"
            );
        }

        assert!(operation_state("from_the_future").contains("does not know"));
    }

    #[test]
    fn each_refusal_reason_reads_as_a_sentence() {
        for reason in REASON_CODES {
            assert!(reason_known(reason), "{reason} is not catalogued");
            let sentence = reason_sentence(reason);
            assert!(
                !sentence.contains(reason),
                "{reason} printed as its identifier: {sentence}"
            );
        }

        let unknown = reason_sentence("from_the_future");
        assert!(unknown.contains("from the future"), "{unknown}");
    }

    fn refused(code: ErrorCode, reason: Option<&str>) -> ClientError {
        ClientError::Rpc(RpcError {
            code,
            message: "refused".into(),
            data: reason.map(|reason| json!({ "reason": reason })),
        })
    }

    #[test]
    fn a_refusal_distinguishes_an_absent_capability_from_a_denied_permission() {
        assert_eq!(
            devices_refusal(&refused(ErrorCode::MethodNotFound, None)),
            Refusal::CapabilityAbsent
        );
        assert_eq!(
            devices_refusal(&refused(ErrorCode::ScopeDenied, None)),
            Refusal::NotAdministrator
        );

        let sentences = [
            Refusal::CapabilityAbsent.sentence(),
            Refusal::NotAdministrator.sentence(),
        ];
        assert_ne!(sentences[0], sentences[1]);
        for sentence in sentences {
            assert!(sentence.contains("fleet.status"), "{sentence}");
        }

        // A reason code the runtime names is drawn in its own words, not as a code.
        let busy = devices_refusal(&refused(ErrorCode::InvalidParams, Some("devices_busy")));
        match busy {
            Refusal::Other(sentence) => {
                assert!(
                    sentence.contains("as many device inventories"),
                    "{sentence}"
                );
                assert!(!sentence.contains("devices_busy"), "{sentence}");
            }
            other => panic!("expected a sentence, got {other:?}"),
        }
    }

    /// A zero-width character never reaches the screen, so one name cannot wear another's.
    #[test]
    fn a_zero_width_character_never_reaches_the_screen() {
        let drawn = scrub("bui\u{200b}ld-linux", NAME_COLUMNS);
        assert_eq!(drawn, "build-linux");
        assert!(!drawn.contains('\u{200b}'));

        // And an escape, a bidi override and a tab are gone with it.
        let hostile = scrub("\u{1b}[2J\u{202e}evil\tname", ROW_FIELD_COLUMNS);
        assert!(!hostile.contains('\u{1b}'));
        assert!(!hostile.contains('\u{202e}'));
        assert!(!hostile.contains('\t'));
    }

    /// The row's cells end where this build says they end, whatever a device calls itself.
    #[test]
    fn a_column_is_a_fact_about_the_row_not_an_alignment() {
        use unicode_width::UnicodeWidthStr;

        let wide = column(&"x".repeat(200), NAME_COLUMNS);
        assert_eq!(
            UnicodeWidthStr::width(wide.as_str()),
            NAME_COLUMNS + 2,
            "a long value moved its own column: {wide}"
        );
        assert!(wide.contains('\u{2026}'), "the cut is invisible: {wide}");

        // Every shape a name can take ends at the same column: narrow, wide, combining,
        // and the emoji sequence a terminal draws as one glyph.
        for name in [
            "pi",
            "\u{5bb6}".repeat(20).as_str(),
            "e\u{301}\u{302}looong",
            "emoji-\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
            "",
        ] {
            let cell = column(name, NAME_COLUMNS);
            assert_eq!(
                UnicodeWidthStr::width(cell.as_str()),
                NAME_COLUMNS + 2,
                "{name:?} moved the column after it: {cell:?}"
            );
        }
    }

    /// The row budget is 140 columns, and the pane is where a command is never cut.
    #[test]
    fn the_row_budget_is_one_hundred_and_forty_and_the_pane_cuts_nothing() {
        assert_eq!(FULL_ROW_COLUMNS, 140);
        assert_eq!(ROW_COLUMNS_BEFORE_COMMAND + COMMAND_COLUMNS, 140);

        // The longest recipe this client can compose, from arguments at their own bounds.
        let longest = DeviceRow {
            state: "discovered_installation_unknown".into(),
            address: Some("a".repeat(64)),
            suggested_machine: Some("m".repeat(40)),
            ..Default::default()
        };
        let command = longest.recipe().command().expect("a command").to_string();

        assert!(
            command.chars().count() > COMMAND_LIMIT,
            "the row's ceiling is above the longest command, which would make the pane \
             pointless: {} columns",
            command.chars().count()
        );
        assert_eq!(
            scrub(&command, COMMAND_PANE_COLUMNS),
            command,
            "the pane cut a command this client composed"
        );
    }

    #[test]
    fn the_filter_and_the_search_appear_past_eight_rows_and_narrow_one_list() {
        let mut inventory = Inventory::default();
        for index in 0..4 {
            inventory.devices.push(DeviceRow {
                name: format!("peer-{index}"),
                state: "discovered_installation_unknown".into(),
                ..Default::default()
            });
        }

        let mut state = DevicesState {
            filter: Filter::Fleet,
            query: "peer-1".into(),
            ..Default::default()
        };

        assert!(!state.narrowing(&inventory));
        assert_eq!(
            state.visible(&inventory).len(),
            4,
            "a short list must ignore a filter and a query it never offered"
        );

        for index in 4..12 {
            inventory.devices.push(DeviceRow {
                name: format!("peer-{index}"),
                state: "discovered_installation_unknown".into(),
                ..Default::default()
            });
        }

        assert!(state.narrowing(&inventory));
        state.filter = Filter::All;
        assert_eq!(
            state.visible(&inventory).len(),
            3,
            "peer-1, peer-10 and peer-11 all contain the query"
        );

        state.query.clear();
        state.filter = Filter::Fleet;
        assert!(state.visible(&inventory).is_empty());
        assert_eq!(Filter::All.next(), Filter::Fleet);
        assert_eq!(Filter::Fleet.next(), Filter::Available);
        assert_eq!(Filter::Available.next(), Filter::All);
    }

    /// The self row is first, ahead of a machine of the fleet as well as a peer.
    ///
    /// Both halves, because §5.1's order is *self, then the fleet's machines, then what
    /// discovery found* and the sort key has to separate all three. Pinning it only
    /// against peers left "self before a member" free: `in_fleet()` is true of the self
    /// row too, so a key that answered 1 for both would pass and put this machine
    /// wherever the input happened to have it.
    #[test]
    fn the_self_row_is_first_ahead_of_a_member_and_a_peer() {
        let member = DeviceRow {
            state: "fleet_member".into(),
            machine: Some("pi".into()),
            ..Default::default()
        };

        // Both shapes of self row: this machine before it has a fleet, and after.
        for this_machine in [
            DeviceRow {
                state: "this_device_without_profile".into(),
                ..Default::default()
            },
            DeviceRow {
                state: "this_device".into(),
                machine: Some("studio".into()),
                ..Default::default()
            },
        ] {
            let state = this_machine.state.clone();
            let inventory = Inventory {
                devices: vec![
                    row("discovered_installation_unknown"),
                    member.clone(),
                    this_machine,
                ],
                ..Default::default()
            };

            let ordered = inventory.ordered();
            assert_eq!(ordered[0].state, state, "the self row is not first");
            assert_eq!(ordered[1].state, "fleet_member", "the member is not second");
            assert_eq!(
                ordered[2].state, "discovered_installation_unknown",
                "the peer is not last"
            );
            assert!(inventory.is_self(ordered[0]));
            assert!(ordered[0].in_fleet(), "the self row sorted with the peers");
        }
    }

    /// A relative time on the row, the exact one in the pane.
    #[test]
    fn presence_is_relative_on_the_row_and_exact_in_the_details() {
        let seen = DeviceRow {
            online: Some(false),
            last_seen: Some("2020-01-01T00:00:00Z".into()),
            ..Default::default()
        };

        assert!(seen.presence_short().contains("seen"));
        assert!(!seen.presence_short().contains("2020-01-01"));
        assert_eq!(seen.presence(), "offline, last seen 2020-01-01T00:00:00Z");

        // A clock ahead of this one is not turned into an invented past.
        assert_eq!(relative_time("2999-01-01T00:00:00Z"), None);
        assert_eq!(relative_time("not a timestamp"), None);
        assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), Some(0));
    }

    /// `last_seen` goes through the funnel like every other field.
    ///
    /// It is the field most easily mistaken for a number: it is a timestamp, and a
    /// timestamp is not something a device writes freely — except that it is, because it
    /// arrives as a string and this client draws it verbatim in the details pane when it
    /// cannot parse it as a time.
    #[test]
    fn a_hostile_last_seen_is_scrubbed_like_any_other_field() {
        let row = DeviceRow::decode(&json!({
            "name": "peer",
            "state": "peer_offline",
            "online": false,
            "last_seen": "\u{1b}[2J\u{202e}2020-01-01T00:00:00Z\n\n  studio  in the fleet",
        }));

        for drawn in [row.presence(), row.presence_short()] {
            assert!(!drawn.contains('\u{1b}'), "{drawn:?}");
            assert!(!drawn.contains('\u{202e}'), "{drawn:?}");
            assert!(!drawn.contains('\n'), "{drawn:?}");
            assert!(
                drawn.chars().count() <= FIELD_COLUMNS + 32,
                "the field is unbounded: {drawn:?}"
            );
        }
    }

    /// The `unknown` list is bounded by how long it is, not only by how wide each key is.
    #[test]
    fn the_unknown_key_list_names_a_few_and_counts_the_rest() {
        let one = unknown_keys_line(&["fleet_protocol_revision".to_string()]);
        assert!(one.contains("fleet_protocol_revision"), "{one}");
        assert!(!one.contains("other key"), "{one}");

        let five: Vec<String> = (0..5).map(|index| format!("key_{index}")).collect();
        let line = unknown_keys_line(&five);
        assert!(line.contains("key_0") && line.contains("key_3"), "{line}");
        assert!(!line.contains("key_4"), "{line}");
        assert!(line.contains("and 1 other key,"), "{line}");

        // Five thousand of them, each as wide as a key can be, were one 370 000-character
        // span. The count is what survives the cut, because it is the one thing a reader
        // cannot work out from what is shown.
        let many: Vec<String> = (0..5_000)
            .map(|index| format!("key_{index}_{}", "z".repeat(80)))
            .collect();
        let line = unknown_keys_line(&many);
        assert!(line.chars().count() <= MESSAGE_COLUMNS, "{}", line.len());
        assert!(line.contains("4996 other keys"), "{line}");
        assert!(line.contains("key_0_zzz"), "{line}");
    }
}
