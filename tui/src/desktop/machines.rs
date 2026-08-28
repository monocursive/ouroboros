//! The desktop Machines surface, as state rather than pixels.
//!
//! Three values live here and nothing else: the read-only projection of fleet membership
//! ([`FleetView`]), the Add Machine form's validation ([`AddForm`]), and the card that a
//! running deploy drives ([`AddCard`]). [`super`] renders them; GPUI never appears in this
//! file, which is what lets every rule below be a test rather than a screenshot.
//!
//! Two facts shape the whole design.
//!
//! **The stage rail is driven only by typed events.** [`AddEvent::Line`] is free-form text
//! that happens to be what the CLI prints; reading a stage out of it would be this client
//! inventing progress the pipeline never claimed. Today `spawn_add` emits only `Line` plus
//! one terminal event, so an in-flight card shows an unlit rail and says so
//! ([`AddCard::only_lines_so_far`]). When the pipeline gains the rest of its typed
//! vocabulary the same card lights up with no change here.
//!
//! **The Tailscale sign-in URL is never persisted.** It reaches [`AddCard::auth`] in
//! memory, is dropped as soon as the network step settles or the add ends, and nothing here
//! writes to disk. [`AuthPrompt`]'s `Debug` redacts it, so a panic or a stray log line
//! cannot leak a live credential.
//!
//! One honest caveat: on today's bridge the pipeline also *prints* that URL as an ordinary
//! [`AddEvent::Line`], because the CLI's own guided-enrollment path writes it to the
//! terminal. Those lines land in [`AddCard`]'s in-memory tail like every other line and are
//! rendered verbatim, which is exactly what the terminal client does with the same text.
//! The tail is memory only, it is dropped with the card, and — unlike [`AuthPrompt`] — it
//! is not redacted in `Debug`, so nothing should debug-print a whole [`AddCard`].

use std::collections::VecDeque;
use std::path::Path;

use crate::fleet::{Member, Profile};
use crate::fleet_add::{AddEvent, AddOptions, AddParams, InstallDecision, NetworkPlan, Outcome};
use crate::model::RuntimeStatus;

/// How many recent pipeline lines the card keeps. The add log the outcome carries is the
/// complete record; this is the tail an operator watches while it runs.
pub const RECENT_LINES: usize = 200;

// -----------------------------------------------------------------------------------
// Fleet membership, projected.
//
// `App` never reads the fleet profile itself and the desktop path never fills
// `App::fleet_profile` in, so this is the desktop's own projection over `fleet::load` and
// the runtime status the reducer already holds. It performs no I/O of its own beyond that
// one load, and decides nothing the two sources do not already say.
// -----------------------------------------------------------------------------------

/// Whether a member is answering right now, or whether that is simply unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// This machine, or a node the runtime lists among its connected peers.
    Connected,
    /// A member of the roster that the runtime is not connected to.
    Offline,
    /// No runtime status has arrived yet, so neither answer is available.
    Unknown,
}

impl Presence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Offline => "offline",
            Self::Unknown => "unknown",
        }
    }
}

/// One row of the member list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRow {
    pub machine: String,
    pub host: String,
    pub node: String,
    pub presence: Presence,
    /// The machine this window is running on, drawn as itself rather than as a peer.
    pub is_this_machine: bool,
}

/// The fleet as the Machines surface shows it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FleetView {
    pub fleet: String,
    pub this_machine: String,
    pub this_host: String,
    pub members: Vec<MemberRow>,
}

impl FleetView {
    pub fn connected(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.presence == Presence::Connected)
            .count()
    }

    pub fn offline(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.presence == Presence::Offline)
            .count()
    }
}

/// Fuse the local roster with the runtime's live peer list.
///
/// The profile says who is expected; `connected_nodes` says who is answering. A member is
/// connected when the runtime names its node or when it *is* this node — the local runtime
/// does not list itself among its peers, and drawing this machine as offline in its own
/// window would be a false report. With no status yet, every peer is [`Presence::Unknown`]
/// rather than guessed offline.
pub fn fleet_view(profile: &Profile, status: Option<&RuntimeStatus>) -> FleetView {
    let members = profile
        .members
        .iter()
        .map(|member| member_row(member, profile, status))
        .collect();
    FleetView {
        fleet: profile.name.clone(),
        this_machine: profile.machine.clone(),
        this_host: profile.host.clone(),
        members,
    }
}

fn member_row(member: &Member, profile: &Profile, status: Option<&RuntimeStatus>) -> MemberRow {
    let is_this_machine = member.node == profile.node;
    let presence = match status {
        _ if is_this_machine => Presence::Connected,
        Some(status)
            if status
                .connected_nodes
                .iter()
                .any(|node| node == &member.node) =>
        {
            Presence::Connected
        }
        Some(_) => Presence::Offline,
        None => Presence::Unknown,
    };
    MemberRow {
        machine: member.machine.clone(),
        host: member.host.clone(),
        node: member.node.clone(),
        presence,
        is_this_machine,
    }
}

/// Load the fleet profile for a data directory the runtime named.
///
/// `Ok(None)` is a standalone machine — an honest answer, not a failure. An error is a
/// profile that exists and cannot be read, which the surface reports rather than hides.
pub fn load_profile(data_dir: Option<&str>) -> Result<Option<Profile>, String> {
    let Some(data_dir) = data_dir else {
        return Ok(None);
    };
    crate::fleet::load(Path::new(data_dir)).map_err(|error| format!("{error:#}"))
}

/// What the surface shows when there is no fleet to show. Named here rather than in the
/// render so the empty state is a fact with a test, not a string in a layout.
pub const NO_FLEET_TITLE: &str = "This machine runs on its own";
pub const NO_FLEET_BODY: &str = "There is no fleet profile in this data directory yet, so \
there is no roster to show and nothing to add a machine to. Create one with `ouro fleet \
create`, or open Machines in the terminal client (`ouro` → Machines) to be walked through \
it. This window will show the roster once a profile exists.";

// -----------------------------------------------------------------------------------
// The Add Machine form.
// -----------------------------------------------------------------------------------

/// The exact command guided enrollment runs as root on the destination, quoted verbatim
/// from `fleet_add`'s `TAILSCALE_INSTALL` so the consent text cannot drift away from what
/// actually executes. `curl` stays unprivileged; only the shell interpreting the script is
/// elevated.
pub const TAILSCALE_INSTALL_COMMAND: &str = crate::fleet_add::TAILSCALE_INSTALL;

/// The second command, from `fleet_add`'s `TAILSCALE_UP_SCRIPT`. It is started detached so
/// the sign-in link can be read out of its output while it blocks on the operator.
pub const TAILSCALE_UP_COMMAND: &str = crate::fleet_add::TAILSCALE_UP_COMMAND;

/// The sentences shown beside the two commands above. Guided enrollment is the one thing
/// this form does that changes a machine the operator is not sitting at, so what it does
/// is stated before it can be started, not after.
pub const TAILSCALE_CONSENT: &[&str] = &[
    "Only with this on, and only when the destination has no private address already, \
     Ouroboros runs these two commands as root over SSH on the destination:",
    "It needs passwordless sudo there. Without it nothing runs and nothing is changed. \
     The first command downloads and executes the Tailscale vendor's own installer; the \
     second signs that machine in to your tailnet and prints a one-time link you approve \
     here.",
];

pub const TAILSCALE_CONSENT_ACK: &str =
    "I authorise running those two commands as root on the destination";

/// Why a form cannot be started yet. Each variant carries the sentence the surface shows;
/// a refusal an operator cannot act on is not a refusal, it is a disabled button.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormRefusal {
    NotAnOwner,
    NoTarget,
    TargetHasWhitespace,
    TargetLooksLikeFlag,
    NoConsent,
}

impl FormRefusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::NotAnOwner => {
                "This machine joined the fleet from an invitation, so it holds no signing key \
                 and cannot invite others. Run the add on the machine that created the fleet."
            }
            Self::NoTarget => {
                "Name the destination first, as user@host — the same thing you would type \
                 after `ssh`."
            }
            Self::TargetHasWhitespace => {
                "The destination goes to `ssh` as one argument, so it cannot contain spaces."
            }
            Self::TargetLooksLikeFlag => {
                "A destination starting with `-` would be read by `ssh` as an option rather \
                 than a machine."
            }
            Self::NoConsent => {
                "Guided Tailscale enrollment runs commands as root on the destination. \
                 Confirm that below, or turn the toggle off."
            }
        }
    }
}

/// What the operator typed, before it is known to be startable.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddForm {
    pub target: String,
    pub machine: String,
    pub host: String,
    pub setup_tailscale: bool,
    /// The explicit acknowledgement the consent text asks for. Cleared whenever the toggle
    /// goes off, so turning it back on asks again rather than remembering a yes given to a
    /// panel that was not on screen.
    pub consented: bool,
    /// True when this machine joined the fleet rather than creating it. Adding a machine
    /// means issuing an invitation, and only the owner holds the key that signs one, so this
    /// is refused before anything is asked of a destination. Named for the blocking
    /// condition so the default — an ordinary owner — is the one that is not blocked.
    pub joined_without_signing_key: bool,
}

/// A validated add, ready to become [`AddParams`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddRequest {
    pub target: String,
    pub machine: Option<String>,
    pub host: Option<String>,
    pub setup_tailscale: bool,
}

impl AddForm {
    /// Turning guided enrollment off withdraws the consent that went with it.
    pub fn set_setup_tailscale(&mut self, on: bool) {
        self.setup_tailscale = on;
        if !on {
            self.consented = false;
        }
    }

    /// What the form will send, or the first reason it cannot be sent.
    ///
    /// The optional fields become `None` when blank, which is what makes the placeholder
    /// honest: an empty machine name is the probe's suggestion being accepted, not an empty
    /// name being chosen.
    pub fn validate(&self) -> Result<AddRequest, FormRefusal> {
        // First, because nothing typed into this form can make it startable.
        if self.joined_without_signing_key {
            return Err(FormRefusal::NotAnOwner);
        }
        let target = self.target.trim();
        if target.is_empty() {
            return Err(FormRefusal::NoTarget);
        }
        if target.chars().any(char::is_whitespace) {
            return Err(FormRefusal::TargetHasWhitespace);
        }
        if target.starts_with('-') {
            return Err(FormRefusal::TargetLooksLikeFlag);
        }
        if self.setup_tailscale && !self.consented {
            return Err(FormRefusal::NoConsent);
        }
        Ok(AddRequest {
            target: target.to_string(),
            machine: optional(&self.machine),
            host: optional(&self.host),
            setup_tailscale: self.setup_tailscale,
        })
    }
}

fn optional(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

impl AddRequest {
    /// Everything `spawn_add` needs, with the data directory and this machine's own host
    /// supplied by the caller because only the window knows them.
    pub fn params(&self, data_dir: &Path, owner_host: Option<String>) -> AddParams {
        AddParams {
            data_dir: data_dir.to_path_buf(),
            target: self.target.clone(),
            machine: self.machine.clone(),
            host: self.host.clone(),
            via: Default::default(),
            binary: None,
            owner_host,
            options: AddOptions {
                setup_tailscale: self.setup_tailscale,
                ..AddOptions::default()
            },
        }
    }
}

// -----------------------------------------------------------------------------------
// The progress card.
// -----------------------------------------------------------------------------------

/// The pipeline's steps, in the order the add performs them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Probe,
    Network,
    Binary,
    Copy,
    Enroll,
    Finish,
}

/// The rail, top to bottom. Index in this array is the stage's order.
pub const STAGES: [Stage; 6] = [
    Stage::Probe,
    Stage::Network,
    Stage::Binary,
    Stage::Copy,
    Stage::Enroll,
    Stage::Finish,
];

const LAST_STAGE: usize = STAGES.len() - 1;

impl Stage {
    pub fn index(self) -> usize {
        match self {
            Self::Probe => 0,
            Self::Network => 1,
            Self::Binary => 2,
            Self::Copy => 3,
            Self::Enroll => 4,
            Self::Finish => 5,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Probe => "Probe",
            Self::Network => "Network",
            Self::Binary => "Binary",
            Self::Copy => "Copy",
            Self::Enroll => "Enroll",
            Self::Finish => "Done",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Probe => "Ask the destination what it is",
            Self::Network => "Decide how the fleet reaches it",
            Self::Binary => "Decide which ouro runs there",
            Self::Copy => "Send the binary and the invitation",
            Self::Enroll => "Run ouro fleet enroll there",
            Self::Finish => "The machine is in the fleet",
        }
    }
}

/// How far a stage has got.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageState {
    /// Not reported yet. Says nothing about whether it has happened.
    Pending,
    Active,
    Done,
    Failed,
}

/// Where the add as a whole stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Running,
    /// Cancel has been asked for, and the pipeline has not stopped yet.
    Cancelling,
    Succeeded,
    Failed,
}

impl Phase {
    pub fn settled(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}

/// A live Tailscale sign-in link.
///
/// Held only for as long as the add is running, and deliberately not `Debug`-printable:
/// it is a one-time credential, and the pipeline's own rule is that it reaches the operator
/// and nowhere else — not a log, not an invitation, not a file.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthPrompt {
    url: String,
}

impl AuthPrompt {
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether the window may hand this to the system browser. A sign-in link that is not
    /// HTTPS is shown as text and never opened, the same rule the ChatGPT sign-in card
    /// already applies.
    pub fn openable(&self) -> bool {
        self.url.starts_with("https://")
    }
}

impl std::fmt::Debug for AuthPrompt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthPrompt")
            .field("url", &"<redacted sign-in link>")
            .finish()
    }
}

pub const AUTH_INSTRUCTION: &str =
    "Open this link and approve the machine. It is a one-time Tailscale sign-in, it expires, \
     and Ouroboros never writes it down.";

/// How long the destination still has to receive a tailnet address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Countdown {
    pub elapsed_s: u64,
    pub budget_s: u64,
}

impl Countdown {
    pub fn remaining_s(self) -> u64 {
        self.budget_s.saturating_sub(self.elapsed_s)
    }

    pub fn expired(self) -> bool {
        self.remaining_s() == 0
    }
}

/// What the failure left behind, and what to do about it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub error: String,
    pub residue: Vec<String>,
}

/// The sentence every failure ends with. The pipeline is resumable by construction —
/// rerunning skips what already succeeded — and an operator who does not know that will
/// go looking for a cleanup step that does not exist.
pub const RESUME_NOTE: &str =
    "Run the add again to resume; it reuses what already succeeded and starts nothing twice.";

/// What `cancel` can and cannot promise. `AddHandle::cancel` sets a flag the pipeline reads
/// at its next boundary, so a blocking remote call already in flight runs to completion.
pub const CANCEL_NOTE: &str =
    "Stopping takes effect at the next step. A call already in flight on the destination \
     finishes first, so this can take a moment.";

/// What the rail says while the pipeline reports only log lines.
pub const LINE_ONLY_NOTE: &str =
    "This runtime reports the add as log lines only, so the steps below stay unlit until it \
     reports them. The lines are the whole progress report; nothing here is inferred from \
     their text.";

/// One deploy, as the card shows it.
#[derive(Clone, Debug)]
pub struct AddCard {
    pub target: String,
    phase: Phase,
    /// Highest stage index reported complete.
    completed_through: Option<usize>,
    /// Stage currently in flight, if the stream has said which.
    active: Option<usize>,
    /// Where a failure landed. `None` when the add failed before naming any stage.
    failed_at: Option<usize>,
    /// How many events carried a stage. Zero means every stage claim would be an inference.
    stage_marks: usize,
    lines: VecDeque<String>,
    /// Total lines seen, so a trimmed tail can say how much it is not showing.
    lines_seen: usize,
    probe: Option<String>,
    network: Option<String>,
    install: Option<String>,
    copying: Option<&'static str>,
    auth: Option<AuthPrompt>,
    countdown: Option<Countdown>,
    outcome: Option<Outcome>,
    failure: Option<Failure>,
}

impl AddCard {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            phase: Phase::Running,
            completed_through: None,
            active: None,
            failed_at: None,
            stage_marks: 0,
            lines: VecDeque::new(),
            lines_seen: 0,
            probe: None,
            network: None,
            install: None,
            copying: None,
            auth: None,
            countdown: None,
            outcome: None,
            failure: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn probe(&self) -> Option<&str> {
        self.probe.as_deref()
    }

    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    pub fn install(&self) -> Option<&str> {
        self.install.as_deref()
    }

    pub fn copying(&self) -> Option<&'static str> {
        self.copying
    }

    pub fn auth(&self) -> Option<&AuthPrompt> {
        self.auth.as_ref()
    }

    pub fn countdown(&self) -> Option<Countdown> {
        self.countdown
    }

    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    pub fn failure(&self) -> Option<&Failure> {
        self.failure.as_ref()
    }

    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(String::as_str)
    }

    /// How many lines the tail has dropped, so the card can say so instead of pretending
    /// the add started where the visible text starts.
    pub fn lines_omitted(&self) -> usize {
        self.lines_seen.saturating_sub(self.lines.len())
    }

    /// Whether the stream has said anything about stages yet. True while a `Line`-only
    /// pipeline is running: the rail stays unlit and the card says why.
    pub fn only_lines_so_far(&self) -> bool {
        self.stage_marks == 0
    }

    /// Cancel was asked for. The pipeline stops at its next boundary, so the card says
    /// "stopping" rather than "stopped" until a terminal event actually arrives.
    pub fn request_cancel(&mut self) {
        if self.phase == Phase::Running {
            self.phase = Phase::Cancelling;
        }
    }

    pub fn cancel_requested(&self) -> bool {
        self.phase == Phase::Cancelling
    }

    /// Whether the card is still worth a Cancel button.
    pub fn can_cancel(&self) -> bool {
        self.phase == Phase::Running
    }

    pub fn stage_state(&self, stage: Stage) -> StageState {
        let index = stage.index();
        if self.failed_at == Some(index) {
            return StageState::Failed;
        }
        if self
            .completed_through
            .is_some_and(|through| index <= through)
        {
            return StageState::Done;
        }
        if self.active == Some(index) && !self.phase.settled() {
            return StageState::Active;
        }
        StageState::Pending
    }

    /// Fold one pipeline event into the card.
    ///
    /// `Line` moves nothing but the log. Every other arm carries its own stage, which is
    /// the entire reason the rail can be trusted: the pipeline says where it is, and this
    /// never guesses. Anything arriving after a terminal event is dropped — the contract
    /// promises exactly one, and a card that kept moving afterwards would be describing a
    /// run that had already finished.
    pub fn observe(&mut self, event: AddEvent) {
        if self.phase.settled() {
            return;
        }
        match event {
            AddEvent::Line(text) => self.push_line(text),
            AddEvent::Probed {
                triple,
                home,
                tailscale,
                hostname,
                has_ouro,
            } => {
                self.complete(Stage::Probe);
                let mut detail = format!("{triple} · home {home}");
                if let Some(hostname) = hostname {
                    detail.push_str(&format!(" · {hostname}"));
                }
                if let Some(address) = tailscale {
                    detail.push_str(&format!(" · tailnet {address}"));
                }
                if has_ouro {
                    detail.push_str(" · ouro present");
                }
                self.probe = Some(detail);
            }
            AddEvent::Network(plan) => {
                self.complete(Stage::Network);
                // The sign-in link's moment is over once the network plan is settled.
                self.auth = None;
                self.countdown = None;
                self.network = Some(match plan {
                    NetworkPlan::HostProvided(host) => format!("reaching it at {host}, as given"),
                    NetworkPlan::TailscaleExisting(host) => {
                        format!("it already answers on {host}")
                    }
                    NetworkPlan::GuidedSetup => {
                        "guided Tailscale enrollment, with your consent".to_string()
                    }
                });
            }
            AddEvent::AuthUrl(url) => {
                self.activate(Stage::Network);
                self.auth = Some(AuthPrompt { url });
            }
            AddEvent::WaitingForAddress {
                elapsed_s,
                budget_s,
            } => {
                self.activate(Stage::Network);
                self.countdown = Some(Countdown {
                    elapsed_s,
                    budget_s,
                });
            }
            AddEvent::Install(decision) => {
                self.complete(Stage::Binary);
                self.install = Some(match decision {
                    InstallDecision::RemoteExisting(version) => {
                        format!("it already runs a matching ouro ({version})")
                    }
                    InstallDecision::SelfCopy => {
                        "this machine's own ouro, copied across".to_string()
                    }
                    InstallDecision::DistArtifact(path) => {
                        let name = path
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.display().to_string());
                        format!("{name} — {}", path.display())
                    }
                    InstallDecision::RecipeOnly => {
                        "nothing installable from here; the invitation carries a recipe".to_string()
                    }
                });
            }
            AddEvent::Copying { what } => {
                self.activate(Stage::Copy);
                self.copying = Some(what);
            }
            AddEvent::Enrolling => {
                self.activate(Stage::Enroll);
                self.copying = None;
            }
            AddEvent::Done(outcome) => {
                self.complete(Stage::Finish);
                self.active = None;
                self.phase = Phase::Succeeded;
                self.auth = None;
                self.countdown = None;
                self.copying = None;
                self.outcome = Some(outcome);
            }
            AddEvent::Failed { error, residue } => {
                self.failed_at = self.active;
                self.phase = Phase::Failed;
                self.auth = None;
                self.countdown = None;
                self.copying = None;
                self.failure = Some(Failure { error, residue });
            }
        }
    }

    fn push_line(&mut self, text: String) {
        self.lines_seen += 1;
        self.lines.push_back(text);
        while self.lines.len() > RECENT_LINES {
            self.lines.pop_front();
        }
    }

    /// The pipeline reported this stage decided. Everything before it is decided too — an
    /// install decision could not exist without a probe — and the next stage is where the
    /// run now is.
    fn complete(&mut self, stage: Stage) {
        let index = stage.index();
        self.stage_marks += 1;
        self.completed_through = Some(match self.completed_through {
            Some(through) => through.max(index),
            None => index,
        });
        self.active = (index < LAST_STAGE).then_some(index + 1);
    }

    /// The pipeline reported work happening *in* this stage. That settles every earlier
    /// stage without claiming this one is finished.
    fn activate(&mut self, stage: Stage) {
        let index = stage.index();
        self.stage_marks += 1;
        if index > 0 {
            self.completed_through = Some(match self.completed_through {
                Some(through) => through.max(index - 1),
                None => index - 1,
            });
        }
        self.active = Some(match self.active {
            Some(active) => active.max(index),
            None => index,
        });
    }
}

/// The one-line summary a finished add earns, from the outcome's own words.
pub fn success_summary(outcome: &Outcome) -> String {
    use crate::fleet_add::OutcomeKind;
    match outcome.kind {
        OutcomeKind::Enrolled => format!(
            "{} joined the fleet at {} and is running.",
            outcome.machine, outcome.host
        ),
        OutcomeKind::InviteDelivered => format!(
            "The invitation for {} is waiting on {}. This machine cannot install the right \
             binary there, so the recipe below is what remains.",
            outcome.machine, outcome.host
        ),
        OutcomeKind::Prepared => format!(
            "The invitation for {} is prepared on this machine. SSH did not reach it, so the \
             recipe below is what to run on the other machine.",
            outcome.machine
        ),
        OutcomeKind::Created => format!("{} is now a fleet owner.", outcome.machine),
        OutcomeKind::Joined => format!("{} joined from an invitation.", outcome.machine),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_add::{OutcomeKind, Recipe};
    use std::path::PathBuf;

    fn profile() -> Profile {
        Profile {
            schema: 1,
            fleet_id: "fleet-1".into(),
            name: "orbit".into(),
            machine: "studio".into(),
            host: "studio.tailnet.ts.net".into(),
            node: "ouro@studio.tailnet.ts.net".into(),
            role: "owner".into(),
            members: vec![
                Member {
                    machine: "studio".into(),
                    host: "studio.tailnet.ts.net".into(),
                    node: "ouro@studio.tailnet.ts.net".into(),
                },
                Member {
                    machine: "vps".into(),
                    host: "100.64.0.8".into(),
                    node: "ouro@100.64.0.8".into(),
                },
                Member {
                    machine: "attic".into(),
                    host: "100.64.0.9".into(),
                    node: "ouro@100.64.0.9".into(),
                },
            ],
            roster_revision: 3,
            tombstones: Vec::new(),
            gateway_port: 7777,
            epmd_port: 4369,
            dist_port_min: 43700,
            dist_port_max: 43729,
        }
    }

    fn status(connected: &[&str]) -> RuntimeStatus {
        RuntimeStatus {
            node: "ouro@studio.tailnet.ts.net".into(),
            connected_nodes: connected.iter().map(|node| node.to_string()).collect(),
            ..RuntimeStatus::default()
        }
    }

    fn outcome(kind: OutcomeKind) -> Outcome {
        Outcome {
            machine: "vps".into(),
            host: "100.64.0.8".into(),
            kind,
            log: vec!["probing op@vps over ssh".into()],
            recipe: None,
        }
    }

    // --- the fleet projection ---------------------------------------------------------

    /// The runtime does not list itself among its peers, so the row for this machine has to
    /// come from the profile's own node rather than from the connected set.
    #[test]
    fn this_machine_is_connected_in_its_own_window_and_peers_come_from_the_runtime() {
        let profile = profile();
        let view = fleet_view(&profile, Some(&status(&["ouro@100.64.0.8"])));

        assert_eq!(view.fleet, "orbit");
        assert_eq!(view.this_machine, "studio");
        assert_eq!(view.members.len(), 3);

        let studio = &view.members[0];
        assert!(studio.is_this_machine);
        assert_eq!(studio.presence, Presence::Connected);

        let vps = &view.members[1];
        assert!(!vps.is_this_machine);
        assert_eq!(vps.presence, Presence::Connected);
        assert_eq!(vps.host, "100.64.0.8");
        assert_eq!(vps.node, "ouro@100.64.0.8");

        assert_eq!(view.members[2].presence, Presence::Offline);
        assert_eq!(view.connected(), 2);
        assert_eq!(view.offline(), 1);
    }

    /// Before any status arrives the client knows the roster but not who is answering.
    /// Drawing those peers as offline would be a report it has not earned.
    #[test]
    fn a_roster_without_runtime_status_leaves_every_peer_unknown() {
        let profile = profile();
        let view = fleet_view(&profile, None);

        assert_eq!(view.members[0].presence, Presence::Connected);
        assert_eq!(view.members[1].presence, Presence::Unknown);
        assert_eq!(view.members[2].presence, Presence::Unknown);
        assert_eq!(view.offline(), 0);
    }

    /// A data directory the runtime never named cannot be read, and that is not an error.
    #[test]
    fn a_missing_data_directory_is_standalone_rather_than_a_failure() {
        assert_eq!(load_profile(None), Ok(None));
    }

    /// The empty state has to name a way forward. A surface that says "no fleet" and stops
    /// is a dead end wearing a button.
    #[test]
    fn the_empty_state_names_the_command_that_creates_a_fleet() {
        assert!(NO_FLEET_BODY.contains("ouro fleet create"));
        assert!(NO_FLEET_BODY.contains("Machines"));
    }

    // --- form validation --------------------------------------------------------------

    #[test]
    fn an_empty_target_refuses_to_start() {
        let form = AddForm::default();
        assert_eq!(form.validate(), Err(FormRefusal::NoTarget));

        let form = AddForm {
            target: "   ".into(),
            ..AddForm::default()
        };
        assert_eq!(form.validate(), Err(FormRefusal::NoTarget));
    }

    /// The target becomes one argv entry for `ssh` and `scp`. Whitespace or a leading dash
    /// would be read as something other than a machine, so both are refused here with a
    /// sentence rather than discovered as a transport error later.
    #[test]
    fn a_target_that_ssh_would_misread_is_refused_with_a_reason() {
        let spaced = AddForm {
            target: "op@vps extra".into(),
            ..AddForm::default()
        };
        assert_eq!(spaced.validate(), Err(FormRefusal::TargetHasWhitespace));

        let flag = AddForm {
            target: "-oProxyCommand=x".into(),
            ..AddForm::default()
        };
        assert_eq!(flag.validate(), Err(FormRefusal::TargetLooksLikeFlag));

        for refusal in [
            FormRefusal::NotAnOwner,
            FormRefusal::NoTarget,
            FormRefusal::TargetHasWhitespace,
            FormRefusal::TargetLooksLikeFlag,
            FormRefusal::NoConsent,
        ] {
            assert!(!refusal.message().is_empty());
        }
    }

    /// Adding a machine means issuing an invitation, and only the owner holds the key that
    /// signs one. A machine that joined is refused here rather than after it has asked a
    /// destination to do something on its behalf.
    #[test]
    fn a_machine_that_joined_the_fleet_cannot_add_others() {
        let form = AddForm {
            target: "op@vps".into(),
            joined_without_signing_key: true,
            ..AddForm::default()
        };
        assert_eq!(form.validate(), Err(FormRefusal::NotAnOwner));
        assert!(FormRefusal::NotAnOwner
            .message()
            .contains("created the fleet"));

        // The ordinary owner is the default, and is not blocked.
        assert!(AddForm {
            target: "op@vps".into(),
            ..AddForm::default()
        }
        .validate()
        .is_ok());
    }

    /// The toggle alone is not consent. It reveals what runs as root; the acknowledgement
    /// is what authorises it, and until it is given the form cannot launch.
    #[test]
    fn guided_enrollment_cannot_launch_without_the_acknowledgement() {
        let mut form = AddForm {
            target: "op@vps".into(),
            ..AddForm::default()
        };
        assert!(form.validate().is_ok(), "the plain add is startable");

        form.set_setup_tailscale(true);
        assert_eq!(form.validate(), Err(FormRefusal::NoConsent));

        form.consented = true;
        let request = form.validate().expect("consent unblocks the start");
        assert!(request.setup_tailscale);
    }

    /// Withdrawing the toggle withdraws the yes that went with it, so switching it back on
    /// asks again instead of remembering an answer given to a panel that was not on screen.
    #[test]
    fn turning_the_toggle_off_withdraws_the_consent() {
        let mut form = AddForm {
            target: "op@vps".into(),
            setup_tailscale: true,
            consented: true,
            ..AddForm::default()
        };
        assert!(form.validate().is_ok());

        form.set_setup_tailscale(false);
        assert!(!form.consented);

        form.set_setup_tailscale(true);
        assert_eq!(form.validate(), Err(FormRefusal::NoConsent));
    }

    /// The consent text is only consent if it says what actually runs. These are the exact
    /// strings `fleet_add` executes; if the pipeline changes one, this fails.
    #[test]
    fn the_consent_text_quotes_the_commands_that_actually_run_as_root() {
        assert_eq!(
            TAILSCALE_INSTALL_COMMAND,
            "curl -fsSL https://tailscale.com/install.sh | sudo -n sh"
        );
        assert!(TAILSCALE_UP_COMMAND.contains("tailscale up"));
        assert!(TAILSCALE_UP_COMMAND.contains("sudo"));
        assert!(TAILSCALE_CONSENT
            .iter()
            .any(|line| line.contains("passwordless sudo")));
        assert!(TAILSCALE_CONSENT_ACK.contains("as root"));
    }

    /// Blank optional fields are the probe's suggestion being accepted, not empty values
    /// being chosen — the pipeline must see `None` so it derives them itself.
    #[test]
    fn blank_optional_fields_reach_the_pipeline_as_unset() {
        let form = AddForm {
            target: "  op@vps  ".into(),
            machine: "   ".into(),
            host: String::new(),
            ..AddForm::default()
        };
        let request = form.validate().unwrap();
        assert_eq!(request.target, "op@vps");
        assert_eq!(request.machine, None);
        assert_eq!(request.host, None);

        let params = request.params(Path::new("/data"), Some("studio".into()));
        assert_eq!(params.target, "op@vps");
        assert_eq!(params.machine, None);
        assert_eq!(params.data_dir, PathBuf::from("/data"));
        assert_eq!(params.owner_host.as_deref(), Some("studio"));
        assert!(!params.options.setup_tailscale);
    }

    // --- the card, on the full typed vocabulary ---------------------------------------

    /// The rail walks the pipeline's own report. Each event settles its stage and lights
    /// the next; nothing is read out of the log lines that arrive alongside.
    #[test]
    fn a_typed_sequence_walks_the_rail_from_probe_to_done() {
        let mut card = AddCard::new("op@vps");
        assert!(card.only_lines_so_far());
        assert_eq!(card.stage_state(Stage::Probe), StageState::Pending);

        card.observe(AddEvent::Probed {
            triple: "x86_64-unknown-linux-gnu".into(),
            home: "/home/op".into(),
            tailscale: None,
            hostname: Some("vps".into()),
            has_ouro: false,
        });
        assert!(!card.only_lines_so_far());
        assert_eq!(card.stage_state(Stage::Probe), StageState::Done);
        assert_eq!(card.stage_state(Stage::Network), StageState::Active);
        assert!(card.probe().unwrap().contains("x86_64-unknown-linux-gnu"));

        card.observe(AddEvent::Network(NetworkPlan::TailscaleExisting(
            "100.64.0.8".into(),
        )));
        assert_eq!(card.stage_state(Stage::Network), StageState::Done);
        assert_eq!(card.stage_state(Stage::Binary), StageState::Active);
        assert!(card.network().unwrap().contains("100.64.0.8"));

        card.observe(AddEvent::Install(InstallDecision::DistArtifact(
            PathBuf::from("/dist/ouro-x86_64-unknown-linux-gnu"),
        )));
        assert_eq!(card.stage_state(Stage::Binary), StageState::Done);
        assert_eq!(card.stage_state(Stage::Copy), StageState::Active);

        card.observe(AddEvent::Copying { what: "binary" });
        assert_eq!(card.copying(), Some("binary"));
        assert_eq!(card.stage_state(Stage::Copy), StageState::Active);

        card.observe(AddEvent::Enrolling);
        assert_eq!(card.stage_state(Stage::Copy), StageState::Done);
        assert_eq!(card.stage_state(Stage::Enroll), StageState::Active);
        assert_eq!(card.copying(), None);

        card.observe(AddEvent::Done(outcome(OutcomeKind::Enrolled)));
        assert_eq!(card.phase(), Phase::Succeeded);
        for stage in STAGES {
            assert_eq!(
                card.stage_state(stage),
                StageState::Done,
                "{stage:?} after a successful add"
            );
        }
        assert!(success_summary(card.outcome().unwrap()).contains("joined the fleet"));
    }

    /// A cross-platform artifact is a file the operator can check for themselves, so the
    /// card names it rather than saying "a binary".
    #[test]
    fn a_dist_artifact_is_named_by_file_and_by_path() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Install(InstallDecision::DistArtifact(
            PathBuf::from("/dist/ouro-aarch64-unknown-linux-gnu"),
        )));
        let install = card.install().unwrap();
        assert!(install.starts_with("ouro-aarch64-unknown-linux-gnu"));
        assert!(install.contains("/dist/ouro-aarch64-unknown-linux-gnu"));
    }

    /// The sign-in link is the one moment the operator must act on, and the one value the
    /// pipeline refuses to write down. It is offered as a button only over HTTPS, and it
    /// leaves the card the moment the network step settles.
    #[test]
    fn the_sign_in_link_is_offered_while_it_is_live_and_dropped_when_it_is_not() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::AuthUrl(
            "https://login.tailscale.com/a/deadbeef".into(),
        ));

        let auth = card.auth().expect("the link is held while it is live");
        assert_eq!(auth.url(), "https://login.tailscale.com/a/deadbeef");
        assert!(auth.openable());
        assert_eq!(card.stage_state(Stage::Probe), StageState::Done);
        assert_eq!(card.stage_state(Stage::Network), StageState::Active);

        // A live credential must not be reachable through a debug print.
        let printed = format!("{:?}", card.auth());
        assert!(!printed.contains("deadbeef"), "{printed}");
        assert!(printed.contains("redacted"), "{printed}");

        card.observe(AddEvent::Network(NetworkPlan::GuidedSetup));
        assert!(card.auth().is_none(), "the link's moment is over");
    }

    /// A sign-in link that is not HTTPS is shown as text and never handed to the browser —
    /// the same rule the ChatGPT sign-in card already applies.
    #[test]
    fn a_non_https_sign_in_link_is_shown_but_never_opened() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::AuthUrl("http://login.example/a/1".into()));
        let auth = card.auth().unwrap();
        assert_eq!(auth.url(), "http://login.example/a/1");
        assert!(!auth.openable());
    }

    #[test]
    fn waiting_for_an_address_counts_down_against_its_budget() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::WaitingForAddress {
            elapsed_s: 45,
            budget_s: 300,
        });
        assert_eq!(card.countdown().unwrap().remaining_s(), 255);
        assert!(!card.countdown().unwrap().expired());

        card.observe(AddEvent::WaitingForAddress {
            elapsed_s: 400,
            budget_s: 300,
        });
        assert!(card.countdown().unwrap().expired());
    }

    // --- the card, on today's Line-only bridge ----------------------------------------

    /// `spawn_add` currently emits log lines and one terminal event. The card renders the
    /// lines, keeps every stage unlit, and says why — because reading a stage out of that
    /// text would be this window inventing progress the pipeline never reported.
    #[test]
    fn a_line_only_stream_shows_its_lines_and_claims_no_stage() {
        let mut card = AddCard::new("op@vps");
        for line in [
            "probing op@vps over ssh",
            "remote is x86_64-unknown-linux-gnu (home /home/op)",
            "copying the binary",
            "enrolling op@vps",
        ] {
            card.observe(AddEvent::Line(line.into()));
        }

        assert!(card.only_lines_so_far());
        for stage in STAGES {
            assert_eq!(
                card.stage_state(stage),
                StageState::Pending,
                "{stage:?} was inferred from log text"
            );
        }
        assert_eq!(card.lines().count(), 4);
        assert_eq!(card.lines().next(), Some("probing op@vps over ssh"));
        assert_eq!(card.phase(), Phase::Running);
        assert!(LINE_ONLY_NOTE.contains("unlit"));
    }

    /// The terminal event is typed even on the bridge, so a `Line`-only run that succeeds
    /// still earns its rail: `Done` cannot happen without every step before it.
    #[test]
    fn a_line_only_stream_that_succeeds_still_completes_the_rail() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Line("probing op@vps over ssh".into()));
        card.observe(AddEvent::Done(outcome(OutcomeKind::InviteDelivered)));

        assert_eq!(card.phase(), Phase::Succeeded);
        assert!(!card.only_lines_so_far());
        for stage in STAGES {
            assert_eq!(card.stage_state(stage), StageState::Done);
        }
        assert!(success_summary(card.outcome().unwrap()).contains("invitation"));
    }

    /// The tail is bounded, and says how much it dropped rather than pretending the add
    /// began where the visible text begins.
    #[test]
    fn the_line_tail_is_bounded_and_admits_what_it_dropped() {
        let mut card = AddCard::new("op@vps");
        for index in 0..(RECENT_LINES + 25) {
            card.observe(AddEvent::Line(format!("step {index}")));
        }

        assert_eq!(card.lines().count(), RECENT_LINES);
        assert_eq!(card.lines_omitted(), 25);
        assert_eq!(card.lines().next(), Some("step 25"));
        assert_eq!(
            card.lines().last(),
            Some(format!("step {}", RECENT_LINES + 24).as_str())
        );
    }

    // --- failure and cancel -----------------------------------------------------------

    /// A failure fails the stage it was in, keeps the stages that really did finish, and
    /// carries the residue plus the sentence that says rerunning is the fix.
    #[test]
    fn a_failure_marks_its_own_stage_and_keeps_the_residue() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Probed {
            triple: "x86_64-unknown-linux-gnu".into(),
            home: "/home/op".into(),
            tailscale: None,
            hostname: None,
            has_ouro: false,
        });
        card.observe(AddEvent::Network(NetworkPlan::HostProvided(
            "100.64.0.8".into(),
        )));
        card.observe(AddEvent::Failed {
            error: "scp op@vps failed (exit 1): permission denied".into(),
            residue: vec![
                "a pending invitation for vps is on this machine".into(),
                "vps was not enrolled".into(),
            ],
        });

        assert_eq!(card.phase(), Phase::Failed);
        assert_eq!(card.stage_state(Stage::Probe), StageState::Done);
        assert_eq!(card.stage_state(Stage::Network), StageState::Done);
        assert_eq!(card.stage_state(Stage::Binary), StageState::Failed);
        assert_eq!(card.stage_state(Stage::Copy), StageState::Pending);

        let failure = card.failure().unwrap();
        assert!(failure.error.contains("permission denied"));
        assert_eq!(failure.residue.len(), 2);
        assert!(RESUME_NOTE.contains("Run the add again"));
        assert!(RESUME_NOTE.contains("reuses what already succeeded"));
    }

    /// A failure before any typed stage leaves the rail unlit rather than blaming a step
    /// the pipeline never said it reached.
    #[test]
    fn a_failure_with_no_typed_stage_blames_no_stage() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Line("probing op@vps over ssh".into()));
        card.observe(AddEvent::Failed {
            error: "ssh op@vps failed (exit 255): host unreachable".into(),
            residue: Vec::new(),
        });

        assert_eq!(card.phase(), Phase::Failed);
        for stage in STAGES {
            assert_eq!(card.stage_state(stage), StageState::Pending);
        }
        assert!(card.failure().unwrap().residue.is_empty());
    }

    /// Cancel is a request, not a stop: the flag is read at the next pipeline boundary, so
    /// the card says "stopping" until a terminal event actually arrives.
    #[test]
    fn cancel_is_a_request_that_only_a_terminal_event_settles() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Copying { what: "binary" });
        assert!(card.can_cancel());

        card.request_cancel();
        assert_eq!(card.phase(), Phase::Cancelling);
        assert!(card.cancel_requested());
        assert!(!card.can_cancel(), "one cancel button, pressed once");
        assert!(!card.phase().settled(), "nothing has stopped yet");
        assert!(CANCEL_NOTE.contains("in flight"));

        // The pipeline keeps reporting until it reaches its boundary.
        card.observe(AddEvent::Line("copying the binary".into()));
        assert_eq!(card.phase(), Phase::Cancelling);

        card.observe(AddEvent::Failed {
            error: "the add was cancelled".into(),
            residue: vec!["nothing was enrolled".into()],
        });
        assert_eq!(card.phase(), Phase::Failed);
    }

    /// The contract promises exactly one terminal event, delivered last. A card that kept
    /// moving after it would be describing a run that had already finished.
    #[test]
    fn events_after_a_terminal_event_are_dropped() {
        let mut card = AddCard::new("op@vps");
        card.observe(AddEvent::Done(outcome(OutcomeKind::Enrolled)));
        card.observe(AddEvent::Line("a late line".into()));
        card.observe(AddEvent::Failed {
            error: "a late failure".into(),
            residue: Vec::new(),
        });

        assert_eq!(card.phase(), Phase::Succeeded);
        assert_eq!(card.lines().count(), 0);
        assert!(card.failure().is_none());
    }

    /// A prepared outcome carries a recipe, and the summary has to say the add is not over
    /// rather than reading as a success that needs nothing.
    #[test]
    fn a_prepared_outcome_says_what_is_still_left_to_do() {
        let mut outcome = outcome(OutcomeKind::Prepared);
        outcome.recipe = Some(Recipe {
            machine: "vps".into(),
            invite_path: PathBuf::from("/data/fleet/pending/vps.json"),
            lines: vec!["copy the invitation to vps".into()],
        });
        let summary = success_summary(&outcome);
        assert!(summary.contains("recipe"));
        assert!(summary.contains("vps"));
    }
}
