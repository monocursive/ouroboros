//! The steps, in order, for the three orchestrations.
//!
//! One code path serves the CLI and the detached worker; what differs is the
//! [`Conversation`] a question goes to. Every externally visible step is bracketed by a
//! journal write, and every step that has already succeeded is skipped on a resume — so
//! an operation interrupted at any durable boundary continues from that boundary rather
//! than reissuing credentials or installing twice.
//!
//! The order in `add` is `docs/proposals/fleet-kiss.md` §6, and the order matters:
//!
//! 1. inspect the *effective* SSH config, before connecting;
//! 2. verify the host key, before authenticating;
//! 3. authenticate and run the fixed preflight;
//! 4. install a missing `ouro`, from the exact own-version release;
//! 5. `hello`, and refuse a version that is not ours;
//! 6. `inspect` — is a fleet already there, is a runtime running;
//! 7. review;
//! 8. `install` with this fleet's bundle, then `service`, then `start`;
//! 9. watch the target's own `status` until it reports the fleet connected;
//! 10. append the new member to *this* machine's list, and nowhere else (§1).

use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::fleet;
use crate::update::release;

use super::askpass::{Bridge, PromptContext};
use super::challenge::{host_trust_metadata, Answer, ChallengeKind};
use super::gateway::{self, Gateway};
use super::helper;
use super::journal::{
    Handle as JournalHandle, IntendedPaths, Journal, SelectedRelease, StepRecord, TargetIdentity,
};
use super::plan::{
    admission_grant, removal_note, DeploymentHost, Plan, PlanMember, PlanRelease, PlanTarget,
    ServicePlan,
};
use super::service::{ServiceAction, ServiceActions};
use super::ssh::{self, Destination, ResolvedIdentity, Runner};
use super::trust::{self, Trust};
use super::{
    refuse, sanitize_remote_text, ChallengeRequest, Conversation, Event, OperationKind,
    OperationRequest, OperationState, Phase,
};

/// How long the engine waits for a new member to appear connected.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(60);
/// How long it waits for a removed member to disappear.
pub const DISCONNECT_DEADLINE: Duration = Duration::from_secs(60);
/// Dry-run scratch directories, keyed by process and operation so every step of one
/// `--dry-run` shares a unique 0700 directory without parking it under the data dir.
fn dry_run_scratch() -> &'static Mutex<HashMap<String, PathBuf>> {
    static PATHS: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A short exclusive 0700 directory under `TMPDIR`. The name is kept tiny so an
/// OpenSSH mux socket created inside it stays inside `sockaddr_un` after the
/// destination hash OpenSSH appends to `ControlPath`.
fn exclusive_temp_dir(prefix: &str) -> Result<PathBuf> {
    for _ in 0..8 {
        let path = std::env::temp_dir().join(format!("{prefix}{}", super::random_hex(4)?));
        match std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(false)
            .create(&path)
        {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).context(format!("creating {}", path.display()));
            }
        }
    }
    refuse(
        "invalid_request",
        format!("could not create a private {prefix} directory"),
    )
}

/// Hosts this process has already scanned and found trusted, keyed by the store
/// they were recorded in. OpenSSH 9.8+ `PerSourcePenalties` bans a client that
/// `ssh-keyscan`s the same address too often (the scan's RSA/ECDSA probes never
/// authenticate); a second connect to a host we already accepted must not scan again.
/// A changed key still fails at `ssh` itself (`StrictHostKeyChecking=yes`).
type TrustedHost = (String, String, u16);
type TrustedHostCache = HashMap<TrustedHost, String>;

fn trusted_hosts() -> &'static Mutex<TrustedHostCache> {
    static HOSTS: OnceLock<Mutex<TrustedHostCache>> = OnceLock::new();
    HOSTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What the operation ended up doing.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub operation: String,
    /// One of §6's five words. `--json` prints it and the CLI's exit status is read off
    /// it: anything but `completed` is an incomplete operation.
    pub state: OperationState,
    /// Whether this was a `--dry-run`, which resolved a plan and changed nothing.
    ///
    /// A dry run's state is `completed`, because inspecting and printing is the whole of
    /// what it undertook to do — the same answer `--frames` has always given. This is
    /// what a display branches on instead: the plan it resolved was never reviewed, so
    /// it is printed here rather than at a review prompt that never happened.
    pub dry_run: bool,
    pub plan: Option<Plan>,
    /// One line for a person.
    pub summary: String,
    /// The next thing to do, which the proposal requires the final display to name.
    pub next: String,
    pub steps: Vec<StepRecord>,
    pub residue: Vec<String>,
    /// Facts the operation could not establish. Never guessed at.
    pub unknown: Vec<String>,
}

impl Outcome {
    pub fn to_value(&self) -> Value {
        json!({
            "operation": self.operation,
            "state": self.state.as_str(),
            "summary": self.summary,
            "next": self.next,
            "plan": self.plan.as_ref().map(Plan::to_value),
            "steps": self.steps,
            "residue": self.residue,
            "unknown": self.unknown,
        })
    }

    pub fn complete(&self) -> bool {
        self.state == OperationState::Completed
    }
}

/// Everything the engine needs to run one operation.
pub struct Engine {
    pub data_dir: PathBuf,
    pub token_file: PathBuf,
    pub request: OperationRequest,
    pub conversation: Arc<dyn Conversation>,
    pub gateway: Arc<dyn Gateway>,
    pub services: Arc<dyn ServiceActions>,
    pub programs: ssh::Programs,
    pub trust_tools: trust::Tools,
    /// The operator's own `known_hosts`, honoured but never written.
    pub user_known_hosts: Option<PathBuf>,
    pub origin: release::Origin,
    /// This binary's version, which is the release a missing-binary install selects.
    pub version: String,
}

impl Engine {
    /// Run the operation the request names, journalling into a handle of its own.
    ///
    /// A dry run is answered *before* a journal is opened: opening one would create the
    /// file that `--dry-run` promises not to write. The issuer-wide lock is taken later,
    /// at the first mutating step, so inspection and challenges do not block other
    /// deployments on this host.
    pub fn run(&self) -> Result<Outcome> {
        self.validate_request()?;
        if self.request.dry_run {
            return self.dry_run();
        }
        let journal = JournalHandle::new(Journal::open(
            &self.data_dir,
            &self.request.operation,
            self.request.kind,
        )?);
        self.run_locked(&journal)
    }

    /// The same, against a journal a caller already opened.
    pub fn run_with(&self, journal: &JournalHandle) -> Result<Outcome> {
        self.validate_request()?;
        if self.request.dry_run {
            return self.dry_run();
        }
        journal.reload(&self.data_dir, &self.request.operation, self.request.kind)?;
        self.run_locked(journal)
    }

    fn validate_request(&self) -> Result<()> {
        super::validate_operation_id(&self.request.operation)
    }

    fn run_locked(&self, journal: &JournalHandle) -> Result<Outcome> {
        if journal.state() == OperationState::Completed {
            return Ok(self.completed_outcome(journal));
        }
        // This operation's own lock, before anything writes to its journal and before
        // any question is asked or any connection made.
        //
        // It used to be taken at the first mutating step, so that "inspection and
        // challenges do not block other deployments on this host" — which was the right
        // rule for the issuer-wide lock §8 deleted, and the wrong one for a per-operation
        // lock. Two *different* operations have two different lock files and never meet.
        // The only thing this one excludes is a second process running the same
        // operation id, and that has to be excluded from the first journal write, not
        // from the first mutation: a second process that got as far as resolving a plan
        // would have cleared the first one's error, connected over SSH, and asked
        // somebody a question, all against an operation it was never going to be allowed
        // to run.
        let _lock = self.lock_operation(journal)?;
        // The startup choice, at operation start, so a resume — and the broker
        // rebuilding a resume's argv — reads it rather than inferring it from a step
        // that may not have happened. `leave` has no such flag and records none.
        if matches!(self.request.kind, OperationKind::Add | OperationKind::Setup) {
            journal.set_service(self.request.service)?;
        }
        journal.clear_error()?;
        let result = match self.request.kind {
            OperationKind::Add => self.run_add(journal),
            OperationKind::Setup => self.run_setup(journal),
            OperationKind::Leave => self.run_leave(journal),
        };
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                let reason = super::reason_of(&error).unwrap_or("failed");
                let phase = if reason == "cancelled" {
                    Phase::Cancelled
                } else {
                    Phase::Failed
                };
                // Before the failure is written, because the failure is what makes
                // residue residue: everything delivered up to here stays where it was
                // put, and §6 requires an operation that stops to name it rather than
                // claim a clean undo. Cancellation comes through here too.
                self.note_residue(journal)?;
                journal.fail(phase.state(), reason, format!("{error:#}"))?;
                self.notify_phase(phase);
                Err(error)
            }
        }
    }

    /// Name what this operation has already delivered and is not going to take back.
    ///
    /// Read off the steps recorded `ok`, never guessed: §6 says residue is "what an
    /// interrupted or cancelled operation left behind that it could not clean up.
    /// Named, never guessed at." A `join` that landed is credentials on a machine; a
    /// `remember` that landed is a member on this roster; a `remove` that landed on a
    /// `leave` whose `forget` has not is the mirror of it. Every one of these is a
    /// thing an operator has to know about before they decide what to do next, and
    /// `residue` was `[]` on every surface — `--json`, `fleet.deployment.status`, the
    /// cancel path — because nothing in this build ever called `note_residue`.
    fn note_residue(&self, journal: &JournalHandle) -> Result<()> {
        let record = journal.record();
        let Some(machine) = record
            .target
            .as_ref()
            .map(|target| target.machine.clone())
            .filter(|machine| !machine.is_empty())
        else {
            // No target resolved yet, so nothing was sent anywhere. An operation that
            // stopped before it knew who it was about has left nothing behind.
            return Ok(());
        };
        let install_path = record
            .paths
            .install_path
            .clone()
            .unwrap_or_else(|| "its install path".to_string());

        if record.completed(&machine, "install") && !record.completed(&machine, "join") {
            journal.note_residue(format!(
                "the matching `ouro` release is installed on {machine} at {install_path}, and it holds no fleet credentials"
            ))?;
        }
        if record.completed(&machine, "join") {
            journal.note_residue(format!(
                "{machine} holds this fleet's credentials: `ouro fleet leave --machine {machine} --user <account>` is what takes them back"
            ))?;
        }
        if record.completed(&machine, "service") {
            journal.note_residue(format!(
                "{machine} has this fleet's startup service installed"
            ))?;
        }
        if record.completed(&machine, "remember") {
            journal.note_residue(format!("{machine} is on this machine's member list"))?;
        }
        if record.completed(&machine, "create") {
            journal.note_residue(
                "this machine holds the fleet this operation created; `ouro fleet leave` retires it"
                    .to_string(),
            )?;
        }
        // The `leave` mirror: the far half is done and the near half is not, so this
        // roster still names a machine whose credentials are already gone.
        if record.completed(&machine, "remove") && !record.completed(&machine, "forget") {
            journal.note_residue(format!(
                "{machine}'s credentials were removed and it is still on this machine's member list"
            ))?;
        }
        Ok(())
    }

    fn transfer_progress<'a>(
        &'a self,
        machine: &'a str,
        phase: &'static str,
        total: Option<usize>,
    ) -> impl FnMut(usize) + 'a {
        let began = Instant::now();
        let mut last = None;
        move |bytes| {
            if last.is_some_and(|at: Instant| at.elapsed() < Duration::from_secs(1)) {
                return;
            }
            last = Some(Instant::now());
            let amount = match total {
                Some(total) => format!(
                    "{:.1} / {:.1} MB ({}%)",
                    bytes as f64 / 1_000_000.0,
                    total as f64 / 1_000_000.0,
                    bytes.saturating_mul(100) / total.max(1)
                ),
                None => format!("{:.1} MB received", bytes as f64 / 1_000_000.0),
            };
            self.step_event(
                machine,
                "install",
                "attempted",
                Some(format!(
                    "{phase}: {amount} · {}s elapsed",
                    began.elapsed().as_secs()
                )),
            );
        }
    }

    fn completed_outcome(&self, journal: &JournalHandle) -> Outcome {
        Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
            dry_run: false,
            plan: None,
            summary: format!(
                "operation {} already completed on this machine",
                self.request.operation
            ),
            next: "Nothing to do; this operation is recorded as complete.".to_string(),
            steps: journal.record().steps,
            residue: journal.record().residue,
            unknown: Vec::new(),
        }
    }

    // ---------------------------------------------------------------- shared plumbing

    /// Tell whoever is listening where this operation is. The phase is the engine's own
    /// grain; what reaches a wire is [`Phase::state`], one of §6's five words.
    fn notify_phase(&self, phase: Phase) {
        self.conversation.notify(Event::State(phase));
    }

    /// Enter a phase: say so, and write the state it maps to into the journal.
    ///
    /// The two used to be written out at every transition, which is how the journal came
    /// to hold a vocabulary of its own that nothing downstream could read.
    fn enter(&self, journal: &JournalHandle, phase: Phase) -> Result<()> {
        self.notify_phase(phase);
        journal.set_state(phase.state())
    }

    fn note(&self, text: impl Into<String>) {
        self.conversation.notify(Event::Log(text.into()));
    }

    fn step_event(&self, machine: &str, step: &str, outcome: &str, detail: Option<String>) {
        self.conversation.notify(Event::Step {
            machine: machine.to_string(),
            step: step.to_string(),
            outcome: outcome.to_string(),
            detail,
        });
    }

    fn check_cancelled(&self) -> Result<()> {
        if self.conversation.cancelled() {
            return refuse(
                "cancelled",
                "the operation was cancelled at a step boundary; anything already delivered is named in the journal",
            );
        }
        Ok(())
    }

    /// The operation's private workspace.
    ///
    /// A dry run gets one outside the data directory entirely. `--dry-run` says it
    /// changes nothing, and creating `<data dir>/deploy/` — the namespace a real
    /// operation journals into — is a change: on a machine that has never deployed, an
    /// inspection would leave that directory behind.
    fn scratch(&self) -> Result<PathBuf> {
        if self.request.dry_run {
            return self.prepare_dry_run_scratch();
        }
        super::ensure_deploy_dir(&self.data_dir)?;
        let path = super::scratch_dir(&self.data_dir, &self.request.operation);
        super::ensure_private_subdir(&path)?;
        Ok(path)
    }

    /// A short exclusive directory for the SSH mux socket.
    ///
    /// OpenSSH binds `ControlPath` plus a destination hash (`s.<16>`). Operation
    /// scratch under a nested `TMPDIR` is already most of `sockaddr_un`; handing
    /// that path to `prepare_control_socket` produces a socket OpenSSH then refuses.
    /// A fresh home per connection, because a resumed run must not inherit a
    /// ControlMaster whose socket `Drop` could not unlink (the hashed name).
    fn control_scratch(&self) -> Result<PathBuf> {
        exclusive_temp_dir("oc")
    }

    /// Unique, mode 0700, and refused rather than adopted if that path already exists.
    fn prepare_dry_run_scratch(&self) -> Result<PathBuf> {
        let key = format!("{}:{}", std::process::id(), self.request.operation);
        {
            let paths = dry_run_scratch()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(path) = paths.get(&key) {
                return Ok(path.clone());
            }
        }
        let path = exclusive_temp_dir("od")?;
        dry_run_scratch()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, path.clone());
        Ok(path)
    }

    fn forget_dry_run_scratch(&self) {
        let key = format!("{}:{}", std::process::id(), self.request.operation);
        let path = dry_run_scratch()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        if let Some(path) = path {
            let _ = std::fs::remove_dir_all(path);
        }
    }

    /// The private host key stores this operation trusts against, in the order OpenSSH
    /// reads them; the first is the one an acceptance is written to.
    ///
    /// A dry run *reads* the durable store — a host this machine already trusts is not
    /// asked about again — and writes to an ephemeral one inside the operation's
    /// scratch, so `--dry-run` leaves nothing behind, not even a trust decision.
    fn known_hosts(&self, scratch: &std::path::Path) -> Vec<PathBuf> {
        let durable = super::known_hosts_path(&self.data_dir);
        if self.request.dry_run {
            vec![scratch.join("known_hosts.dry-run"), durable]
        } else {
            vec![durable]
        }
    }

    fn destination(&self, address: &str, user: Option<&str>) -> Result<Destination> {
        let address: std::net::Ipv4Addr = address.parse().map_err(|_| {
            super::SetupError {
                reason: "unresolved_address",
                detail: format!(
                    "`{address}` is not a private-network IPv4 address. Fleet setup connects to the selected overlay address itself; resolve the device first with `ouro fleet devices`"
                ),
            }
        })?;
        let Some(user) = user.map(str::trim).filter(|user| !user.is_empty()) else {
            return refuse(
                "ssh_user_required",
                "this operation needs the target's SSH account name. The Tailscale owner is not the target account, so it is never inferred",
            );
        };
        Ok(Destination {
            // Canonical dotted-quad, which is also what the profile's host must be.
            address: address.to_string(),
            port: self.request.ssh_port.unwrap_or(22),
            user: user.to_string(),
        })
    }

    /// §8: the only lock left is this operation's own, so two processes cannot run it.
    fn lock_operation(&self, journal: &JournalHandle) -> Result<super::lock::Lock> {
        super::lock::Lock::acquire_operation(
            &self.data_dir,
            &self.request.operation,
            journal.state().as_str(),
            Some(self.request.machine.as_str()),
        )
    }

    /// Current Tailscale node key for `address`: discovery first, then the request.
    fn current_peer_identity(&self, address: &str) -> (Option<String>, Option<String>) {
        let discovered = discover_peer_keys(address);
        if discovered.0.is_some() || discovered.1.is_some() {
            return discovered;
        }
        (self.request.peer_id.clone(), self.request.stable_id.clone())
    }

    /// Node key recorded for this machine/address, from the current journal or a
    /// previous admission of the same target.
    fn recorded_peer_id(
        &self,
        journal: &JournalHandle,
        machine: &str,
        address: &str,
    ) -> Option<String> {
        if let Some(peer_id) = journal
            .record()
            .target
            .as_ref()
            .filter(|target| target.machine == machine)
            .and_then(|target| target.peer_id.clone())
        {
            return Some(peer_id);
        }
        Journal::list(&self.data_dir)
            .ok()?
            .into_iter()
            .filter_map(|operation| Journal::read(&self.data_dir, &operation).ok().flatten())
            .filter(|record| {
                record.operation != self.request.operation
                    && record.kind == OperationKind::Add
                    && record
                        .target
                        .as_ref()
                        .is_some_and(|target| target.machine == machine)
                    && record
                        .target
                        .as_ref()
                        .and_then(|target| target.address.as_deref())
                        == Some(address)
            })
            .max_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then(left.updated_at.cmp(&right.updated_at))
            })
            .and_then(|record| record.target.and_then(|target| target.peer_id))
    }

    fn bind_peer_identity(
        &self,
        journal: &JournalHandle,
        machine: &str,
        address: &str,
    ) -> Result<(Option<String>, Option<String>)> {
        let (peer_id, stable_id) = self.current_peer_identity(address);
        if let Some(recorded) = self.recorded_peer_id(journal, machine, address) {
            match &peer_id {
                Some(current) if current != &recorded => {
                    return refuse(
                        "peer_identity_changed",
                        format!(
                            "{machine} at {address} presents a different Tailscale node key than the one recorded for it. A device re-registration needs explicit repair rather than a silent rewrite"
                        ),
                    );
                }
                Some(_) => {}
                None => {
                    if !journal.record().attempted(machine, "peer_identity") {
                        journal.skip_step(
                            machine,
                            "peer_identity",
                            "no Tailscale node key is visible for this address; the recorded identity was not re-checked",
                        )?;
                    }
                }
            }
        } else if peer_id.is_none() {
            if !journal.record().attempted(machine, "peer_identity") {
                journal.skip_step(
                    machine,
                    "peer_identity",
                    "no Tailscale node key is visible for this address; identity is not pinned",
                )?;
            }
        } else if !journal.record().completed(machine, "peer_identity") {
            journal.finish_step(
                machine,
                "peer_identity",
                "ok",
                Some("recorded the Tailscale node key for this address".into()),
                None,
            )?;
        }
        Ok((peer_id, stable_id))
    }

    fn remember_identity(&self, mut target: TargetIdentity) -> TargetIdentity {
        target.identity = Some(self.request.identity.clone());
        target
    }

    /// The same, for one existing member, honouring its own access overrides.
    fn connect(&self, destination: Destination) -> Result<Connection> {
        self.connect_with_identity(destination, &self.request.identity)
    }

    fn connect_with_identity(
        &self,
        destination: Destination,
        choice: &super::IdentityChoice,
    ) -> Result<Connection> {
        let scratch = self.scratch()?;
        let identity = ssh::resolve_identity(&self.programs, choice, &scratch)?;
        let known_hosts = self.known_hosts(&scratch);
        let control = ssh::prepare_control_socket(&self.control_scratch()?)?;

        // Built without a bridge first: `ssh -G` does not authenticate, and arming the
        // askpass socket before the routing check would allow a prompt for a destination
        // this operation is about to refuse. The probe also omits the mux socket so
        // `ControlMaster=no` is what `-G` reports.
        let probe = Runner {
            programs: self.programs.clone(),
            destination: destination.clone(),
            identity: identity.clone(),
            known_hosts: known_hosts.clone(),
            user_known_hosts: self.user_known_hosts.clone(),
            connect_timeout: ssh::CONNECT_TIMEOUT,
            command_timeout: ssh::COMMAND_TIMEOUT,
            bridge: None,
            control: None,
            cancelled: None,
            challenge_window: None,
        };
        probe.inspect_effective_config()?;

        let fingerprint = self.ensure_host_trust(&destination, &known_hosts, &scratch)?;

        let bridge = Arc::new(Bridge::start(
            &self.programs.askpass,
            PromptContext {
                target: destination.address.clone(),
                user: destination.user.clone(),
                port: destination.port,
                key_label: identity_label(&identity),
                key_fingerprint: identity_fingerprint(&identity),
            },
            Arc::clone(&self.conversation),
        )?);

        let cancelled = {
            let conversation = Arc::clone(&self.conversation);
            Some(Arc::new(move || conversation.cancelled()) as Arc<dyn Fn() -> bool + Send + Sync>)
        };
        let runner = Runner {
            programs: self.programs.clone(),
            destination,
            identity,
            known_hosts,
            user_known_hosts: self.user_known_hosts.clone(),
            connect_timeout: ssh::CONNECT_TIMEOUT,
            command_timeout: ssh::COMMAND_TIMEOUT,
            bridge: Some(Arc::clone(&bridge)),
            control: Some(control),
            cancelled,
            challenge_window: None,
        };
        self.notify_phase(Phase::AwaitingAuth);
        runner.check_access()?;
        Ok(Connection {
            runner: Arc::new(runner),
            _bridge: bridge,
            host_fingerprint: fingerprint,
        })
    }

    /// Ask about an unknown host key, once, explicitly.
    fn ensure_host_trust(
        &self,
        destination: &Destination,
        known_hosts: &[PathBuf],
        scratch: &std::path::Path,
    ) -> Result<String> {
        let store = known_hosts
            .first()
            .ok_or_else(|| super::SetupError {
                reason: "invalid_request",
                detail: "this operation has nowhere to record a host key".into(),
            })?
            .clone();
        let mut stores = known_hosts.to_vec();
        if let Some(user_file) = &self.user_known_hosts {
            stores.push(user_file.clone());
        }
        let cache_key = (
            store.display().to_string(),
            destination.address.clone(),
            destination.port,
        );
        if let Some(fingerprint) = trusted_hosts()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cache_key)
            .cloned()
        {
            return Ok(fingerprint);
        }
        match trust::examine(
            &self.trust_tools,
            &stores,
            &destination.address,
            destination.port,
            scratch,
        )? {
            Trust::Known { fingerprint, .. } => {
                trusted_hosts()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(cache_key, fingerprint.clone());
                Ok(fingerprint)
            }
            Trust::Revoked {
                algorithm,
                fingerprint,
            } => refuse(
                "host_key_revoked",
                format!(
                    "{} presents a {algorithm} host key this deployment host has revoked ({fingerprint}). A revocation is the strongest statement a known_hosts file makes; nothing was sent",
                    destination.address
                ),
            ),
            Trust::Changed { presented, .. } => refuse(
                "host_key_changed",
                format!(
                    "{} presents a host key this deployment host does not trust ({}). A changed host key blocks setup: verify the machine's identity out of band and repair the trust record deliberately. Nothing was sent",
                    destination.address,
                    presented
                        .iter()
                        .map(|key| format!("{} {}", key.algorithm, key.fingerprint))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            Trust::Unknown { keys } => {
                let key = keys.first().expect("a scan with no keys is refused earlier");
                self.notify_phase(Phase::AwaitingHostTrust);
                let answer = self.conversation.ask(ChallengeRequest {
                    kind: ChallengeKind::HostTrust,
                    metadata: host_trust_metadata(
                        &destination.address,
                        destination.port,
                        &key.algorithm,
                        &key.fingerprint,
                        &destination.user,
                    ),
                })?;
                match answer {
                    Answer::Trust(true) => {
                        trust::accept(&store, key)?;
                        trusted_hosts()
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(cache_key, key.fingerprint.clone());
                        self.note(if self.request.dry_run {
                            format!(
                                "trusting {} {} for this run only; a dry run records nothing",
                                destination.address, key.fingerprint
                            )
                        } else {
                            format!(
                                "recorded trust for {} {}",
                                destination.address, key.fingerprint
                            )
                        });
                        Ok(key.fingerprint.clone())
                    }
                    _ => refuse(
                        "host_trust_declined",
                        format!(
                            "{}'s host key was not accepted, so nothing was sent to it",
                            destination.address
                        ),
                    ),
                }
            }
        }
    }

    /// Ask the operator to approve a plan.
    ///
    /// §6 deleted the plan digest. What binds a resumed operation to what was approved is
    /// the journal: the plan lines are written there when the review is accepted, and an
    /// operation that already has them is not asked again.
    fn review(&self, journal: &JournalHandle, plan: &Plan) -> Result<()> {
        if journal.record().reviewed() {
            return Ok(());
        }
        self.notify_phase(Phase::AwaitingReview);
        if self.request.assume_yes {
            // `--yes` accepts a *resolved* plan. It has already failed to bypass host
            // trust (that challenge is raised before this point and is answered by the
            // conversation, which refuses it non-interactively) and it cannot make a
            // busy runtime idle.
            self.note("--yes: accepting the resolved plan without a review prompt");
            return journal.set_plan(plan.lines());
        }
        let answer = self.conversation.ask(ChallengeRequest {
            kind: ChallengeKind::Review,
            metadata: json!({ "plan": plan.to_value(), "lines": plan.lines() }),
        })?;
        match answer {
            Answer::Approval(true) => journal.set_plan(plan.lines()),
            _ => refuse("review_declined", "the plan was not approved"),
        }
    }

    fn local_profile(&self) -> Result<Option<fleet::Profile>> {
        fleet::load(&self.data_dir)
    }

    // ---------------------------------------------------------------- dry run

    /// Inspect and print; write nothing.
    ///
    /// No journal, no fleet state, no installation, and not even a durable host-trust
    /// record: an unknown host is still an explicit challenge (the proposal requires
    /// that even during a dry run) but the acceptance goes to a file inside the
    /// operation's scratch that is removed with it.
    fn dry_run(&self) -> Result<Outcome> {
        let plan = match self.request.kind {
            OperationKind::Add => self.plan_add()?.0,
            OperationKind::Setup => self.plan_setup()?,
            OperationKind::Leave => self.plan_leave(None)?.0,
        };
        self.forget_dry_run_scratch();
        Ok(Outcome {
            operation: self.request.operation.clone(),
            // §6's five have no word for "resolved a plan and stopped there", and the
            // engine's old `awaiting_review` was never one of them: `--frames` already
            // reported a dry run `completed`, and `--json` said a word nothing
            // downstream knew. A dry run *completed* what it undertook — it inspected
            // and printed — and `dry_run` is what tells a display the plan was never
            // reviewed.
            state: OperationState::Completed,
            dry_run: true,
            summary: format!(
                "dry run: nothing was changed on this machine or on {}",
                plan.target.machine
            ),
            next: "Run the same command without --dry-run to apply this plan.".to_string(),
            plan: Some(plan),
            steps: Vec::new(),
            residue: Vec::new(),
            unknown: Vec::new(),
        })
    }

    // ---------------------------------------------------------------- add

    /// Inspect the target and every member, and produce the plan.
    ///
    /// Returns the plan and the facts the deploy steps need, so that a dry run and a
    /// real run agree by construction rather than by two code paths staying in step.
    fn plan_add(&self) -> Result<(Plan, Prepared)> {
        self.notify_phase(Phase::Inspecting);
        let machine = normalize_machine(&self.request.machine)?;
        let profile = self.local_profile()?.ok_or_else(|| super::SetupError {
            reason: "no_fleet",
            detail: "this machine is standalone, so it cannot admit another. Run `ouro fleet setup` here first".into(),
        })?;
        if !fleet::fleet_dir(&self.data_dir)
            .join(fleet::CA_KEY_FILE)
            .try_exists()?
        {
            return refuse(
                "no_ca_key",
                "this machine holds the fleet certificate but not its key, so it cannot admit a machine. Run this on the machine that created the fleet",
            );
        }

        let address = self
            .request
            .address
            .clone()
            .ok_or_else(|| super::SetupError {
                reason: "unresolved_address",
                detail: "this operation has no resolved target address".into(),
            })?;
        let destination = self.destination(&address, self.request.ssh_user.as_deref())?;
        let connection = self.connect(destination)?;

        let preflight = super::bootstrap::preflight(&connection.runner)?;
        let executable = self.remote_executable(&preflight)?;

        // Whether a release has to be fetched at all is a plan fact, so the artifact is
        // resolved (name and checksum, not bytes) before the review.
        let release_plan = if self.remote_executable_present(&connection, &executable) {
            None
        } else if self.install_path_is_absolute() {
            // An absolute path names an installation this workflow did not create. It
            // may be used, and it is never written to: replacing or creating an
            // installation outside the account's own home is a manual step.
            return refuse(
                "unsupported_install_path",
                format!(
                    "{executable} does not exist on {machine}, and this workflow installs only into the target account's own home directory. Install Ouroboros there yourself, or leave --install-path unset to install {}",
                    super::bootstrap::DEFAULT_INSTALL_PATH
                ),
            );
        } else {
            let target = preflight.target_triple()?;
            let asset = release::asset_name(&self.version, &target);
            let cancelled = AtomicBool::new(false);
            let manifest = release::checksums(&self.origin, &self.version, &cancelled)?;
            let sha256 = release::checksum_for(&manifest, &asset)
                .map_err(|error| super::refusing("release_unavailable", error))?;
            Some(PlanRelease {
                version: self.version.clone(),
                target,
                asset,
                sha256,
                official_origin: self.origin.is_official(),
            })
        };

        let plan = Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Add,
            summary: String::new(),
            deployment_host: DeploymentHost::here(&self.data_dir),
            target: PlanTarget {
                machine: machine.clone(),
                address: connection.runner.destination.address.clone(),
                port: connection.runner.destination.port,
                ssh_user: connection.runner.destination.user.clone(),
                identity: connection.runner.identity.describe(),
                install_path: executable.clone(),
                data_dir: self.request.remote_data_dir.clone(),
                host_fingerprint: Some(connection.host_fingerprint.clone()),
                node: Some(format!(
                    "ouro-{machine}@{}",
                    connection.runner.destination.address
                )),
            },
            release: release_plan.clone(),
            service: if self.request.service {
                ServicePlan::Managed
            } else {
                ServicePlan::Manual
            },
            fleet: Some(profile.name.clone()),
            members: Vec::new(),
            restart: None,
            grants: vec![admission_grant()],
            build: Some(
                serde_json::to_value(crate::fleet_protocol::build_metadata())
                    .unwrap_or(Value::Null),
            ),
        };

        let mut plan = plan;
        plan.refresh_summary();

        Ok((
            plan,
            Prepared {
                machine,
                profile,
                connection,
                executable,
                release: release_plan,
            },
        ))
    }

    fn install_path_is_absolute(&self) -> bool {
        self.request
            .install_path
            .as_deref()
            .is_some_and(|path| path.starts_with('/'))
    }

    /// Where `ouro` is, or will be, on the target.
    ///
    /// A relative path is the normal case and is validated against the same `case`
    /// patterns the remote bootstrap script uses. An absolute path names an existing
    /// installation the operator chose; it is used and never written to.
    fn remote_executable(&self, preflight: &super::bootstrap::Preflight) -> Result<String> {
        self.remote_executable_for(&self.request.machine, preflight)
    }

    /// The same, for a named machine, preferring what this machine wrote down when it
    /// admitted that one.
    ///
    /// A member was installed at a path this operator chose, and that path is in the
    /// journal of the operation that admitted it. Falling straight through to
    /// `$HOME/.local/bin/ouro` meant a later `leave` ran whatever `ouro` the login
    /// shell's PATH happened to find — which on a machine deployed to a custom path is a
    /// different, older installation that does not speak this protocol at all.
    fn remote_executable_for(
        &self,
        machine: &str,
        preflight: &super::bootstrap::Preflight,
    ) -> Result<String> {
        // An explicit request always wins: it is what the operator just typed.
        if let Some(requested) = self
            .request
            .install_path
            .clone()
            .filter(|_| fleet::same_name(machine, self.request.machine.trim()))
        {
            if requested.starts_with('/') {
                return Ok(requested);
            }
            super::bootstrap::validate_install_path(&requested)?;
            return Ok(preflight.install_path(&requested));
        }
        if let Some(recorded) = self.recorded_executable(machine) {
            return Ok(recorded);
        }
        Ok(preflight.install_path(super::bootstrap::DEFAULT_INSTALL_PATH))
    }

    /// The `OUROBOROS_DATA_DIR` a named machine's `ouro` was deployed against.
    ///
    /// An explicit request wins, and otherwise this comes from the journal of the
    /// operation that admitted the machine — the same place `remote_executable_for`
    /// reads the install path from, and for the same reason. A `leave` written by the
    /// UI's broker names a roster member, an account and an identity; it has no way to
    /// know that this machine was admitted with a non-default data directory, and
    /// falling through to the far side's default would open a helper against a data
    /// directory with no fleet in it and report the member as already standalone.
    fn remote_data_dir_for(&self, machine: &str) -> Option<String> {
        self.request
            .remote_data_dir
            .clone()
            .or_else(|| self.recorded_data_dir(machine))
    }

    /// The `OUROBOROS_DATA_DIR` this machine's own journals record for `machine`.
    fn recorded_data_dir(&self, machine: &str) -> Option<String> {
        let mut found = None;
        for operation in Journal::list(&self.data_dir).ok()? {
            let Ok(Some(record)) = Journal::read(&self.data_dir, &operation) else {
                continue;
            };
            if record.kind != OperationKind::Add
                || record.state != OperationState::Completed
                || record.target.as_ref().map(|target| target.machine.as_str()) != Some(machine)
            {
                continue;
            }
            if let Some(path) = record.paths.data_dir.clone() {
                found = Some(path);
            }
        }
        found
    }

    /// Where this machine's own journals say `ouro` was installed on `machine`.
    ///
    /// Only an operation that *completed* counts: a half-finished admission's intended
    /// path is an intention, not an installation.
    fn recorded_executable(&self, machine: &str) -> Option<String> {
        let mut found = None;
        for operation in Journal::list(&self.data_dir).ok()? {
            let Ok(Some(record)) = Journal::read(&self.data_dir, &operation) else {
                continue;
            };
            if record.kind != OperationKind::Add
                || record.state != OperationState::Completed
                || record.target.as_ref().map(|target| target.machine.as_str()) != Some(machine)
            {
                continue;
            }
            if let Some(path) = record.paths.install_path.clone() {
                // Journals are listed in id order, so a later admission of the same name
                // — a machine removed and added again — wins.
                found = Some(path);
            }
        }
        found
    }

    /// Whether a usable `ouro` is already at the selected path. A non-default install
    /// path is not reported by the fixed preflight, so it is tested directly.
    fn remote_executable_present(&self, connection: &Connection, executable: &str) -> bool {
        let command = format!("test -x {}", ssh::shell_quote(executable));
        connection
            .runner
            .run(&command, None)
            .map(|completed| completed.success())
            .unwrap_or(false)
    }

    fn run_add(&self, journal: &JournalHandle) -> Result<Outcome> {
        let (mut plan, prepared) = self.plan_add()?;
        let before = journal.record();
        // A resumed `add` whose binary this operation already installed plans no install
        // — the binary is there — so the release it was approved with is restored from
        // the journal and re-verified by checksum rather than silently forgotten.
        if before.attempted(&prepared.machine, "install") && plan.release.is_none() {
            if let Some(release) = &before.release {
                let command = format!("if command -v sha256sum >/dev/null 2>&1; then sha256sum < {}; else shasum -a 256 < {}; fi", ssh::shell_quote(&prepared.executable), ssh::shell_quote(&prepared.executable));
                let checked = prepared.connection.runner.run(&command, None)?;
                if !checked.success()
                    || String::from_utf8_lossy(&checked.stdout)
                        .split_whitespace()
                        .next()
                        != Some(release.sha256.as_str())
                {
                    return refuse(
                        "plan_changed",
                        "the installed binary no longer matches this operation's approved release",
                    );
                }
                journal.finish_step(
                    &prepared.machine,
                    "install",
                    "ok",
                    Some("verified the previously installed release checksum".into()),
                    None,
                )?;
            }
        }
        plan.refresh_summary();

        let machine = prepared.machine.clone();
        let target_host = plan.target.address.clone();

        let (peer_id, stable_id) = self.bind_peer_identity(journal, &machine, &target_host)?;
        journal.set_target(self.remember_identity(TargetIdentity {
            machine: machine.clone(),
            address: Some(target_host.clone()),
            port: Some(plan.target.port),
            ssh_user: Some(plan.target.ssh_user.clone()),
            node: plan.target.node.clone(),
            host_fingerprint: plan.target.host_fingerprint.clone(),
            peer_id,
            stable_id,
            ..TargetIdentity::default()
        }))?;
        journal.set_paths(IntendedPaths {
            install_path: Some(prepared.executable.clone()),
            data_dir: self.request.remote_data_dir.clone(),
        })?;
        if let Some(release) = &prepared.release {
            journal.set_release(SelectedRelease {
                version: release.version.clone(),
                asset: release.asset.clone(),
                sha256: release.sha256.clone(),
            })?;
        }

        // The operation's own lock is already held, from `run_locked`.
        self.enter(journal, Phase::Deploying)?;
        let mut unknown = Vec::new();

        // ---- install a missing ouro
        if let Some(release) = &prepared.release {
            if !journal.record().completed(&machine, "install") {
                self.check_cancelled()?;
                journal.begin_step(&machine, "install")?;
                self.step_event(&machine, "install", "attempted", None);
                let cancelled = AtomicBool::new(false);
                let mut download = self.transfer_progress(&machine, "Downloading", None);
                let bytes = release::fetch_verified_with_progress(
                    &self.origin,
                    &release.version,
                    &release.asset,
                    &release.sha256,
                    &cancelled,
                    &mut |received| {
                        cancelled.store(
                            self.conversation.cancelled(),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        download(received);
                    },
                )?;
                self.check_cancelled()?;
                let install_relative = self
                    .request
                    .install_path
                    .clone()
                    .filter(|path| !path.starts_with('/'))
                    .unwrap_or_else(|| super::bootstrap::DEFAULT_INSTALL_PATH.to_string());
                let mut upload = self.transfer_progress(&machine, "Uploading", Some(bytes.len()));
                let installed = super::bootstrap::install_with_progress(
                    &prepared.connection.runner,
                    &release.asset,
                    &bytes,
                    &release.sha256,
                    &install_relative,
                    &mut upload,
                )?;
                journal.finish_step(
                    &machine,
                    "install",
                    "ok",
                    Some(format!("ouro {} at {}", release.version, installed.path)),
                    Some(format!("sha256:{}", installed.sha256)),
                )?;
                self.step_event(&machine, "install", "ok", Some(installed.path));
            }
        } else if !journal.record().completed(&machine, "install") {
            journal.skip_step(&machine, "install", "the target already has ouro")?;
        }

        // ---- inspect the target through its own helper
        let mut session = helper::Session::open(
            &prepared.connection.runner,
            &prepared.executable,
            self.request.remote_data_dir.as_deref(),
        )?;
        let hello = session.ask("hello", json!({}))?;
        self.verify_build_contract(&hello, &machine)?;
        let inspection = session.ask("inspect", json!({}))?;
        let mut already_joined = false;
        if let Some(existing) = inspection.get("fleet").and_then(Value::as_object) {
            let existing_fleet = existing
                .get("fleet_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if existing_fleet == prepared.profile.fleet_id {
                if existing.get("machine").and_then(Value::as_str) != Some(machine.as_str())
                    || existing.get("host").and_then(Value::as_str) != Some(target_host.as_str())
                {
                    return refuse("identity_mismatch", "the installed target identity does not match the reviewed machine and host");
                }
                already_joined = true;
            } else {
                return refuse(
                    "fleet_present",
                    format!(
                        "{machine} already belongs to another fleet ({}). Run `ouro fleet leave` there first; this workflow never replaces an existing installation's identity",
                        sanitize_remote_text(existing_fleet, 40)
                    ),
                );
            }
        }
        if !already_joined && inspection.get("runtime_running") != Some(&Value::Bool(false)) {
            return refuse("runtime_running", format!("{machine}'s runtime must be stopped before it joins. Run `ouro stop --require-idle` for its data directory, then retry; no credentials were sent"));
        }
        journal.finish_step(
            &machine,
            "inspect",
            "ok",
            Some(format!(
                "{} {}",
                hello
                    .get("os")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown os"),
                hello
                    .get("arch")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown arch")
            )),
            None,
        )?;
        self.step_event(&machine, "inspect", "ok", None);

        // ---- the review, then the bundle
        self.review(journal, &plan)?;
        journal.set_state(Phase::Deploying.state())?;

        if already_joined {
            if !journal.record().completed(&machine, "join") {
                journal.skip_step(
                    &machine,
                    "join",
                    "the target already holds this fleet's credentials",
                )?;
            }
        } else if !journal.record().completed(&machine, "join") {
            self.check_cancelled()?;
            journal.begin_step(&machine, "join")?;
            // The bundle is read here and nowhere else, and it lives only as long as
            // this frame: §2's `Bundle` zeroizes its cookie and CA key on drop.
            let bundle = fleet::bundle(&self.data_dir)?;
            let mut install = json!({
                "bundle": serde_json::to_value(&bundle)?,
                "machine": machine,
                "host": target_host,
            });
            let ports = self.request.ports();
            if ports != fleet::Ports::DEFAULT {
                install["ports"] = json!({ "gateway": ports.gateway, "dist": ports.dist });
            }
            drop(bundle);
            let joined = session.ask("install", install)?;
            journal.finish_step(
                &machine,
                "join",
                "ok",
                Some(format!(
                    "joined as {}",
                    joined
                        .get("node")
                        .and_then(Value::as_str)
                        .map(|node| sanitize_remote_text(node, 80))
                        .unwrap_or_else(|| machine.clone())
                )),
                None,
            )?;
            self.step_event(&machine, "join", "ok", None);
        }

        // ---- startup
        let startup = self.arrange_startup(journal, &machine, &mut session)?;
        match startup {
            Startup::Manual => unknown.push(format!(
                "{machine}'s connection, because manual startup was chosen and its runtime has not been started from here"
            )),
            Startup::Unsupported => unknown.push(format!(
                "{machine}'s connection: it has no supported user supervisor, so it must be started there by hand"
            )),
            Startup::NotStarted => unknown.push(format!(
                "{machine}'s connection: its startup service was installed and would not start. Its fleet credentials are in place; start it there and run `ouro fleet doctor`"
            )),
            Startup::Started => {}
        }

        // ---- the local roster edit, then connectivity
        //
        // §1: the roster is not replicated. The operator's own list gains the machine,
        // and nothing is written anywhere else.
        if !journal.record().completed(&machine, "remember") {
            journal.begin_step(&machine, "remember")?;
            let dist_port = self
                .request
                .ports()
                .dist
                .unwrap_or(prepared.profile.dist_port);
            let added = fleet::add_member(&self.data_dir, &machine, &target_host, dist_port, None)?;
            journal.finish_step(
                &machine,
                "remember",
                "ok",
                Some(format!("{} is on this machine's list", added.node)),
                None,
            )?;
            self.step_event(&machine, "remember", "ok", None);
        }

        self.enter(journal, Phase::CheckingReadiness)?;
        let connected = if startup == Startup::Started {
            self.await_connection(journal, &machine, &mut session)?
        } else {
            journal.skip_step(&machine, "connect", "the runtime was not started from here")?;
            false
        };
        self.record_readiness(journal, &machine, &mut unknown)?;

        session.close();

        // The operation is complete when every step it *intended* to take succeeded. A
        // runtime the operator chose to start themselves has not failed to connect; it
        // has not been started. A `start` this operation intended and that failed is
        // incomplete, even though the credentials it already delivered stay put.
        //
        // Incomplete is `failed` — §6 has five states and none of them is `interrupted`
        // — and the *reason* is what distinguishes the two ways to arrive here. Both
        // journals stay put and both resume with `--operation ID`: the steps say what
        // has already happened, and `join:ok` is not repeated.
        let unfinished = match startup {
            _ if connected => None,
            Startup::Manual | Startup::Unsupported => None,
            Startup::NotStarted => Some((
                "start_failed",
                format!(
                    "{machine} joined and its startup service would not start it. Its fleet credentials are in place; the `start` step records what the service manager said"
                ),
            )),
            Startup::Started => Some((
                "not_connected",
                format!(
                    "{machine} joined and was started, and it did not report a connected fleet within {} seconds",
                    CONNECT_DEADLINE.as_secs()
                ),
            )),
        };
        let state = match &unfinished {
            None => {
                self.enter(journal, Phase::Completed)?;
                OperationState::Completed
            }
            Some((reason, detail)) => {
                // Written with `fail` rather than `set_state`, because what a resumed or
                // inspected journal needs is not the word `failed` — it is which of the
                // two things went wrong, in `last_error.reason`, beside steps that
                // already say `join:ok` and `start:failed`.
                //
                // This is the one failure that does not travel through `run_locked`'s
                // error arm — it is an `Ok` outcome that is not `completed` — so the
                // residue is named here as well.
                self.note_residue(journal)?;
                journal.fail(Phase::Failed.state(), reason, detail.clone())?;
                self.notify_phase(Phase::Failed);
                OperationState::Failed
            }
        };
        let _ =
            std::fs::remove_dir_all(super::scratch_dir(&self.data_dir, &self.request.operation));

        Ok(Outcome {
            operation: self.request.operation.clone(),
            state,
            dry_run: false,
            summary: if connected {
                format!("{machine} joined the fleet and is connected")
            } else {
                format!("{machine} joined; its connection is not observed yet")
            },
            next: if connected {
                format!("Connected; configure a model on {machine}")
            } else if startup == Startup::NotStarted {
                format!(
                    "Joined, and {machine}'s startup service would not start. Its credentials are in place: start it there, then `ouro fleet doctor --peer {target_host}`"
                )
            } else if startup == Startup::Started {
                format!(
                    "Joined. Check {machine} with `ouro fleet doctor --peer {target_host}` once its runtime is up"
                )
            } else {
                format!("Joined. Start the runtime on {machine} with `ouro daemon` there, then `ouro fleet doctor`")
            },
            plan: Some(plan),
            steps: journal.record().steps,
            residue: journal.record().residue,
            unknown,
        })
    }

    /// Refuse an installation whose build contract is not this one's.
    ///
    /// `Cluster.runtime_compatible?/2` compares the tuple exactly, so anything other
    /// than an exact match is a manual upgrade instruction rather than something this
    /// workflow silently replaces.
    fn verify_build_contract(
        &self,
        hello: &serde_json::Map<String, Value>,
        machine: &str,
    ) -> Result<()> {
        let local = crate::fleet_protocol::build_metadata();
        let Some(remote) = hello
            .get("version")
            .and_then(Value::as_str)
            .map(|text| sanitize_remote_text(text, 64))
        else {
            return refuse(
                "incompatible_installation",
                format!(
                    "{machine} did not report its Ouroboros version, so its compatibility with this fleet cannot be established. Upgrade it to a current official release and run this again"
                ),
            );
        };
        if remote == local.ouroboros_version {
            return Ok(());
        }
        // §6: "a different version is `version_mismatch`, naming both, with the upgrade
        // recipe; nothing is replaced".
        refuse(
            "version_mismatch",
            format!(
                "{machine} runs Ouroboros {remote} and this machine runs {}. A fleet is one version (§12), and this workflow never replaces an existing installation: run `ouro update` on {machine}, or install the matching official release there, then run this command again",
                local.ouroboros_version
            ),
        )
    }

    /// §6's `service` and `start`, which are two steps because §6 names two.
    ///
    /// They were one step once, and that hid the thing an operator most needs to see:
    /// a machine whose unit was installed and whose runtime would not come up. Worse, a
    /// `start` that failed propagated out of this function and failed the whole
    /// operation *before* the member was appended to this machine's list — so the
    /// credentials were on the target, the target was not on the roster, and the
    /// journal never named `start` at all. A start that fails is now a failed `start`
    /// step: the credentials stay, the member is remembered, `connect` is not attempted,
    /// and the operation ends incomplete with the reason on the step.
    fn arrange_startup(
        &self,
        journal: &JournalHandle,
        machine: &str,
        session: &mut helper::Session,
    ) -> Result<Startup> {
        if !self.request.service {
            if !journal.record().completed(machine, "service") {
                journal.skip_step(
                    machine,
                    "service",
                    "manual startup was chosen with --no-service",
                )?;
            }
            if !journal.record().completed(machine, "start") {
                journal.skip_step(
                    machine,
                    "start",
                    "manual startup was chosen with --no-service",
                )?;
            }
            return Ok(Startup::Manual);
        }
        if !journal.record().completed(machine, "service") {
            journal.begin_step(machine, "service")?;
            let installed = self.services.remote(session, ServiceAction::Install)?;
            if !installed.supported {
                journal.finish_step(
                    machine,
                    "service",
                    "skipped",
                    Some(format!(
                        "no supported user supervisor: {}. Start it manually",
                        installed.detail
                    )),
                    None,
                )?;
                self.step_event(machine, "service", "skipped", Some(installed.detail));
                journal.skip_step(
                    machine,
                    "start",
                    "there is no user supervisor on that machine to start it with",
                )?;
                return Ok(Startup::Unsupported);
            }
            journal.finish_step(
                machine,
                "service",
                "ok",
                Some(installed.detail.clone()),
                None,
            )?;
            self.step_event(machine, "service", "ok", Some(installed.detail));
        }
        if journal.record().completed(machine, "start") {
            return Ok(Startup::Started);
        }
        journal.begin_step(machine, "start")?;
        match self.services.remote(session, ServiceAction::Start) {
            Ok(started) => {
                journal.finish_step(machine, "start", "ok", Some(started.detail.clone()), None)?;
                self.step_event(machine, "start", "ok", Some(started.detail));
                Ok(Startup::Started)
            }
            // The bundle is already installed at this point. Losing the operation here
            // would leave the credentials on a machine this roster never names.
            Err(error) => {
                let detail = super::sanitize_remote_text(&format!("{error:#}"), 300);
                journal.finish_step(machine, "start", "failed", Some(detail.clone()), None)?;
                self.step_event(machine, "start", "failed", Some(detail));
                Ok(Startup::NotStarted)
            }
        }
    }

    /// Poll the *target's* own `status` until it reports the fleet connected (§6).
    ///
    /// Asking the machine that just joined is the honest question: the operator's runtime
    /// may not even be running, and distribution is transitive, so what matters is that
    /// the new member dialled somebody.
    fn await_connection(
        &self,
        journal: &JournalHandle,
        machine: &str,
        session: &mut helper::Session,
    ) -> Result<bool> {
        journal.begin_step(machine, "connect")?;
        let deadline = Instant::now() + CONNECT_DEADLINE;
        loop {
            match session.ask("status", json!({})) {
                Ok(status) => {
                    let connected = status
                        .get("connected_to")
                        .and_then(Value::as_array)
                        .is_some_and(|nodes| !nodes.is_empty());
                    if connected {
                        journal.finish_step(
                            machine,
                            "connect",
                            "ok",
                            Some(format!("{machine} reports the fleet connected")),
                            None,
                        )?;
                        self.step_event(machine, "connect", "ok", None);
                        return Ok(true);
                    }
                }
                Err(error) => {
                    journal.finish_step(
                        machine,
                        "connect",
                        "skipped",
                        Some(format!("{machine} could not be asked: {error:#}")),
                        None,
                    )?;
                    return Ok(false);
                }
            }
            if Instant::now() >= deadline {
                journal.finish_step(
                    machine,
                    "connect",
                    "failed",
                    Some(format!(
                        "{machine} did not report a connected fleet within {} seconds",
                        CONNECT_DEADLINE.as_secs()
                    )),
                    None,
                )?;
                self.step_event(machine, "connect", "failed", None);
                return Ok(false);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// Readiness is reported separately from connectivity, and unknown where it is
    /// unknown.
    ///
    /// The owner-local readiness methods (`runtime.providers`, `runtime.models`,
    /// `attachment.limits`) take no owner selector today, so the local gateway's answers
    /// describe *this* machine and not the new member. Reporting them as the member's
    /// would be a false claim, so the honest answer is `unknown` plus the configuration
    /// step the proposal's recovery table names.
    fn record_readiness(
        &self,
        journal: &JournalHandle,
        machine: &str,
        unknown: &mut Vec<String>,
    ) -> Result<()> {
        journal.finish_step(
            machine,
            "readiness",
            "skipped",
            Some(
                "provider, model and workspace prerequisites on the new member are unknown from here: the owner-local readiness methods answer for the runtime they are asked, and none of them takes an owner selector"
                    .into(),
            ),
            None,
        )?;
        unknown.push(format!(
            "{machine}'s provider, model and workspace prerequisites — configure a model on {machine}"
        ));
        Ok(())
    }

    fn plan_setup(&self) -> Result<Plan> {
        self.notify_phase(Phase::Inspecting);
        let machine = normalize_machine(&self.request.machine)?;
        let address = self
            .request
            .address
            .clone()
            .ok_or_else(|| super::SetupError {
                reason: "unresolved_address",
                detail: "this machine's own private address was not resolved. `ouro fleet devices` shows what the network client reports".into(),
            })?;
        let parsed: std::net::Ipv4Addr = address.parse().map_err(|_| super::SetupError {
            reason: "unresolved_address",
            detail: format!("`{address}` is not this machine's private IPv4 address"),
        })?;
        let restart = if self.gateway.running() {
            Some(
                "this machine's runtime must be idle and will be stopped and started again"
                    .to_string(),
            )
        } else {
            None
        };
        let mut plan = Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Setup,
            summary: String::new(),
            deployment_host: DeploymentHost::here(&self.data_dir),
            target: PlanTarget {
                machine: machine.clone(),
                address: parsed.to_string(),
                port: 0,
                ssh_user: String::new(),
                identity: "none: this machine configures itself without SSH".into(),
                install_path: String::new(),
                data_dir: Some(self.data_dir.display().to_string()),
                host_fingerprint: None,
                node: Some(format!("ouro-{machine}@{parsed}")),
            },
            release: None,
            service: if self.request.service {
                ServicePlan::Managed
            } else {
                ServicePlan::Manual
            },
            fleet: None,
            members: vec![PlanMember {
                machine: machine.clone(),
                host: parsed.to_string(),
                reached_by: "local".into(),
                change: "create this fleet".into(),
                ssh: None,
            }],
            restart,
            grants: vec![admission_grant()],
            build: Some(
                serde_json::to_value(crate::fleet_protocol::build_metadata())
                    .unwrap_or(Value::Null),
            ),
        };
        plan.refresh_summary();
        Ok(plan)
    }

    fn run_setup(&self, journal: &JournalHandle) -> Result<Outcome> {
        let machine = normalize_machine(&self.request.machine)?;
        // Calling setup on a configured machine is an inspection.
        let existing = self.local_profile()?;
        if let Some(profile) = existing
            .as_ref()
            .filter(|_| !journal.record().attempted(&machine, "create"))
        {
            journal.set_state(OperationState::Completed)?;
            return Ok(Outcome {
                operation: self.request.operation.clone(),
                state: OperationState::Completed,
                dry_run: false,
                plan: None,
                summary: format!(
                    "this machine is already {} in fleet {}; nothing was changed",
                    profile.machine, profile.name
                ),
                next: format!(
                    "Run `ouro fleet status` to see it, or `ouro fleet add` to bring another machine in. Its address is {}",
                    profile.host
                ),
                steps: journal.record().steps,
                residue: Vec::new(),
                unknown: Vec::new(),
            });
        }

        let plan = self.plan_setup()?;
        if journal.record().reviewed() {
            if let Some(profile) = &existing {
                if profile.machine != machine || profile.host != plan.target.address {
                    return refuse(
                        "identity_mismatch",
                        "the local fleet differs from the identity this setup created",
                    );
                }
                journal.finish_step(
                    &machine,
                    "create",
                    "ok",
                    Some("verified this operation's local fleet identity".into()),
                    None,
                )?;
            }
        }
        journal.set_target(TargetIdentity {
            machine: machine.clone(),
            address: Some(plan.target.address.clone()),
            node: plan.target.node.clone(),
            identity: Some(self.request.identity.clone()),
            ..TargetIdentity::default()
        })?;
        self.review(journal, &plan)?;

        // The operation's own lock is already held, from `run_locked`.
        self.enter(journal, Phase::Deploying)?;

        // The authorized local transition. The runtime that is running now is the one
        // serving whoever asked for this, so it is stopped only if it is idle.
        if !journal.record().completed(&machine, "stop_runtime") {
            journal.begin_step(&machine, "stop_runtime")?;
            self.enter(journal, Phase::RestartingHost)?;
            let stopped = gateway::stop_require_idle(&self.data_dir, &self.token_file)?;
            let outcome = match stopped {
                gateway::StopOutcome::NotRunning => "skipped",
                _ => "ok",
            };
            journal.finish_step(
                &machine,
                "stop_runtime",
                outcome,
                Some(match stopped {
                    gateway::StopOutcome::NotRunning => {
                        "no runtime was running here, so there was nothing to stop".to_string()
                    }
                    gateway::StopOutcome::RemovedStale { pid } => {
                        format!("removed a stale publication for pid {pid}")
                    }
                    gateway::StopOutcome::Stopped { pid } => {
                        format!("the idle runtime (pid {pid}) stopped")
                    }
                }),
                None,
            )?;
            self.step_event(&machine, "stop_runtime", outcome, None);
        }

        journal.set_state(Phase::Deploying.state())?;
        if !journal.record().completed(&machine, "create") {
            journal.begin_step(&machine, "create")?;
            let profile = fleet::create(
                &self.data_dir,
                None,
                &machine,
                &plan.target.address,
                self.request.ports(),
            )?;
            journal.finish_step(
                &machine,
                "create",
                "ok",
                Some(format!("{} at {}", profile.node, profile.host)),
                None,
            )?;
            self.step_event(&machine, "create", "ok", None);
        }

        let mut unknown = Vec::new();
        let started = if journal.record().completed(&machine, "service") {
            true
        } else if self.request.service {
            journal.begin_step(&machine, "service")?;
            let installed = self.services.local(ServiceAction::Install)?;
            if installed.supported {
                journal.finish_step(
                    &machine,
                    "service",
                    "ok",
                    Some(installed.detail.clone()),
                    None,
                )?;
                true
            } else {
                journal.finish_step(
                    &machine,
                    "service",
                    "skipped",
                    Some(format!(
                        "no supported user supervisor here: {}",
                        installed.detail
                    )),
                    None,
                )?;
                unknown.push("automatic startup is unavailable on this machine".into());
                false
            }
        } else {
            journal.skip_step(
                &machine,
                "service",
                "manual startup was chosen with --no-service",
            )?;
            false
        };

        // §6's `setup` ends at `start` and `ready`: the service manager is what starts
        // the runtime, and the readiness probe is the gateway publishing a port.
        if started && !journal.record().completed(&machine, "start") {
            journal.begin_step(&machine, "start")?;
            let outcome = match self.services.local(ServiceAction::Start) {
                Ok(started) if started.supported => {
                    journal.finish_step(
                        &machine,
                        "start",
                        "ok",
                        Some(started.detail.clone()),
                        None,
                    )?;
                    true
                }
                Ok(started) => {
                    journal.finish_step(
                        &machine,
                        "start",
                        "skipped",
                        Some(started.detail.clone()),
                        None,
                    )?;
                    false
                }
                Err(error) => {
                    journal.finish_step(
                        &machine,
                        "start",
                        "failed",
                        Some(format!("{error:#}")),
                        None,
                    )?;
                    false
                }
            };
            if outcome {
                journal.begin_step(&machine, "ready")?;
                let deadline = Instant::now() + CONNECT_DEADLINE;
                let mut ready = false;
                while Instant::now() < deadline {
                    if self.gateway.running() {
                        ready = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                journal.finish_step(
                    &machine,
                    "ready",
                    if ready { "ok" } else { "failed" },
                    Some(if ready {
                        "this machine's runtime published its gateway".to_string()
                    } else {
                        format!(
                            "this machine's runtime did not publish a gateway within {} seconds",
                            CONNECT_DEADLINE.as_secs()
                        )
                    }),
                    None,
                )?;
                if !ready {
                    unknown.push("whether this machine's runtime finished starting".into());
                }
            }
        } else if !journal.record().completed(&machine, "start") {
            journal.skip_step(&machine, "start", "manual startup was chosen")?;
            journal.skip_step(&machine, "ready", "the runtime was not started from here")?;
        }

        self.enter(journal, Phase::Completed)?;
        Ok(Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
            dry_run: false,
            summary: format!("this machine is now {machine} at {}", plan.target.address),
            next: if started {
                "Verify it with `ouro fleet doctor`, then add another machine with `ouro fleet add <user>@<address> --machine <name>`".to_string()
            } else {
                "Start this machine with `ouro daemon`, verify it with `ouro fleet doctor`, then add another machine with `ouro fleet add`".to_string()
            },
            plan: Some(plan),
            steps: journal.record().steps,
            residue: journal.record().residue,
            unknown,
        })
    }

    // ---------------------------------------------------------------- leave

    fn plan_leave(&self, journal: Option<&JournalHandle>) -> Result<(Plan, fleet::Profile)> {
        self.notify_phase(Phase::Inspecting);
        let machine = normalize_machine(&self.request.machine)?;
        let profile = self.local_profile()?.ok_or_else(|| super::SetupError {
            reason: "no_fleet",
            detail: "this machine is standalone; there is no member to remove".into(),
        })?;
        if fleet::same_name(&machine, &profile.machine) {
            return refuse(
                "identity_mismatch",
                "`ouro fleet leave --machine` takes another machine's name. To retire this one, stop its runtime and run `ouro fleet leave`",
            );
        }
        // Refused *before* the plan is shown. Discovering it in `deploying` cost an
        // operator a review they had already approved, and recorded a failed operation.
        if self
            .request
            .ssh_user
            .as_deref()
            .map(str::trim)
            .filter(|user| !user.is_empty())
            .is_none()
        {
            return refuse(
                "ssh_user_required",
                format!(
                    "removing {machine} from here connects to it over SSH, and that needs its account name: `ouro fleet leave --machine {machine} --user <account>`"
                ),
            );
        }
        let Some(member) = profile
            .members
            .iter()
            .find(|member| crate::fleet::same_name(&member.machine, &machine))
            .cloned()
            .or_else(|| {
                // A resumed `leave` whose local removal already happened still has to be
                // able to describe the machine it removed.
                let record = journal?.record();
                let target = record.target.clone()?;
                if !fleet::same_name(&target.machine, &machine) {
                    return None;
                }
                Some(fleet::Member {
                    machine: target.machine,
                    host: target.address?,
                    node: target.node?,
                    dist_port: profile.dist_port,
                })
            })
        else {
            return refuse(
                "machine_unknown",
                format!("this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"),
            );
        };

        // The roster's spelling is the identity recorded in steps, access records and
        // runtime status. Keep it after matching the operator's case-insensitive input.
        let machine = member.machine.clone();
        // The one machine this operation contacts. §1 withdrew the replicated roster, so
        // there is nobody else to tell.
        let members = vec![PlanMember {
            machine: machine.clone(),
            host: member.host.clone(),
            reached_by: "ssh".into(),
            change: "stop, retire credentials, leave".into(),
            ssh: Some(format!(
                "{}@{} port {}",
                self.request.ssh_user.clone().unwrap_or_default(),
                member.host,
                self.request.ssh_port.unwrap_or(22)
            )),
        }];

        let plan = Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Leave,
            summary: String::new(),
            deployment_host: DeploymentHost::here(&self.data_dir),
            target: PlanTarget {
                machine: machine.clone(),
                address: member.host.clone(),
                port: self.request.ssh_port.unwrap_or(22),
                ssh_user: self.request.ssh_user.clone().unwrap_or_default(),
                identity: "resolved when the member is contacted".into(),
                install_path: String::new(),
                data_dir: self.remote_data_dir_for(&machine),
                host_fingerprint: None,
                node: Some(member.node.clone()),
            },
            release: None,
            service: ServicePlan::Manual,
            fleet: Some(profile.name.clone()),
            members,
            restart: Some(format!(
                "{machine}'s runtime is stopped through its own idle-gated shutdown before its credentials are removed"
            )),
            grants: vec![removal_note(&machine)],
            build: None,
        };
        let mut plan = plan;
        plan.refresh_summary();
        Ok((plan, profile))
    }

    fn run_leave(&self, journal: &JournalHandle) -> Result<Outcome> {
        let (plan, _profile) = self.plan_leave(Some(journal))?;
        let machine = plan.target.machine.clone();
        let (peer_id, stable_id) =
            self.bind_peer_identity(journal, &machine, &plan.target.address)?;
        journal.set_target(self.remember_identity(TargetIdentity {
            machine: machine.clone(),
            address: Some(plan.target.address.clone()),
            port: Some(plan.target.port),
            ssh_user: self.request.ssh_user.clone(),
            node: plan.target.node.clone(),
            host_fingerprint: plan.target.host_fingerprint.clone(),
            peer_id,
            stable_id,
            ..TargetIdentity::default()
        }))?;
        self.review(journal, &plan)?;

        // The operation's own lock is already held, from `run_locked`.
        self.enter(journal, Phase::Deploying)?;

        let mut residue = None;
        if !journal.record().completed(&machine, "remove") {
            let destination =
                self.destination(&plan.target.address, self.request.ssh_user.as_deref())?;
            let connection = self.connect(destination)?;
            let preflight = super::bootstrap::preflight(&connection.runner)?;
            let executable = self.remote_executable_for(&machine, &preflight)?;
            let mut session = helper::Session::open(
                &connection.runner,
                &executable,
                self.remote_data_dir_for(&machine).as_deref(),
            )?;
            let result = self.stop_and_retire(journal, &machine, &mut session);
            session.close();
            match result {
                Ok(()) => {}
                Err(error) => {
                    // §6's `leave` is `stop`, `remove`, `forget`. A machine that cannot
                    // be stopped keeps its credentials and stays on this roster: a
                    // removal that only edited the local list would leave a machine in
                    // the fleet that this operator believes is out of it.
                    return Err(error);
                }
            }
        } else {
            residue = Some(format!(
                "{machine}'s credentials were already removed by this operation"
            ));
        }
        if let Some(note) = residue {
            // A `log` frame *and* the journal. The frame is seen by whoever is attached
            // at this instant; the journal is what an operator reads afterwards, and
            // this is the resumed `leave` whose far half is done — if `forget` then
            // fails, this roster names a machine whose credentials are already gone,
            // and that sentence is the only record of it.
            journal.note_residue(note.clone())?;
            self.note(note);
        }

        // ---- the local half: forget it here, and nowhere else (§1)
        if !journal.record().completed(&machine, "forget") {
            journal.begin_step(&machine, "forget")?;
            let detail = match fleet::remove_member(&self.data_dir, &machine) {
                Ok(removed) => format!("{} is off this machine's list", removed.node),
                // Idempotent on a resume: a machine that is already off the list is the
                // state this step exists to reach.
                Err(error) => format!("nothing to remove here: {error:#}"),
            };
            journal.finish_step(&machine, "forget", "ok", Some(detail), None)?;
            self.step_event(&machine, "forget", "ok", None);
        }

        self.enter(journal, Phase::Completed)?;
        let _ =
            std::fs::remove_dir_all(super::scratch_dir(&self.data_dir, &self.request.operation));
        Ok(Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
            dry_run: false,
            summary: format!("{machine} left the fleet; its work and session history stay on it"),
            next: removal_note(&machine),
            plan: Some(plan),
            steps: journal.record().steps,
            residue: journal.record().residue,
            unknown: Vec::new(),
        })
    }

    /// §6's `stop` and `remove`, in one helper round trip each.
    ///
    /// The helper's `leave` op is idle-gated on the far side: it asks that machine's own
    /// runtime to stop only if it is idle, takes its startup service away, and deletes
    /// its fleet directory. Nothing here signals a PID and nothing here deletes a file
    /// on the target directly.
    fn stop_and_retire(
        &self,
        journal: &JournalHandle,
        machine: &str,
        session: &mut helper::Session,
    ) -> Result<()> {
        if !journal.record().completed(machine, "stop") {
            journal.begin_step(machine, "stop")?;
            let inspection = session.ask("inspect", json!({}))?;
            let running = inspection
                .get("runtime_running")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            journal.finish_step(
                machine,
                "stop",
                "ok",
                Some(if running {
                    format!("{machine}'s runtime is running and will be stopped through its own idle gate")
                } else {
                    format!("{machine}'s runtime is already stopped")
                }),
                None,
            )?;
            self.step_event(machine, "stop", "ok", None);
        }

        journal.begin_step(machine, "remove")?;
        let left = session.ask("leave", json!({}))?;
        let removed = left
            .get("removed")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|text| sanitize_remote_text(text, 80))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "credentials removed".into());
        journal.finish_step(machine, "remove", "ok", Some(removed), None)?;
        self.step_event(machine, "remove", "ok", None);
        Ok(())
    }
}

/// What this operation did about the target's startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Startup {
    /// `--no-service`: the operator starts it themselves.
    Manual,
    /// No supported user supervisor there. A result, not a failure.
    Unsupported,
    /// This operation installed and started a managed service.
    Started,
    /// The unit was installed and the manager would not start it. The credentials are
    /// on the target and this operation is incomplete.
    NotStarted,
}

/// An authenticated channel to one machine, with the bridge that serves its prompts.
#[derive(Clone)]
struct Connection {
    runner: Arc<Runner>,
    /// Held for the connection's lifetime: dropping it removes the askpass socket.
    _bridge: Arc<Bridge>,
    host_fingerprint: String,
}

/// One current member, its roster revision, and an open helper session to it.
struct Prepared {
    machine: String,
    profile: fleet::Profile,
    connection: Connection,
    executable: String,
    release: Option<PlanRelease>,
}

/// Current Tailscale node key and stable id for an overlay address, if this
/// machine's network client can name one. A missing client or a private-network
/// address that is not in the inventory is `None`, and the engine then skips the
/// pin rather than refusing.
fn discover_peer_keys(address: &str) -> (Option<String>, Option<String>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return (None, None);
    };
    let inventory = runtime.block_on(crate::fleet_network::inventory());
    for device in inventory.self_device.iter().chain(inventory.peers.iter()) {
        if device.ipv4.map(|ip| ip.to_string()).as_deref() == Some(address) {
            return (device.node_key.clone(), device.stable_id.clone());
        }
    }
    (None, None)
}

fn identity_label(identity: &ResolvedIdentity) -> Option<String> {
    match identity {
        ResolvedIdentity::Agent { label, .. } | ResolvedIdentity::Key { label, .. } => {
            Some(label.clone())
        }
        _ => None,
    }
}

fn identity_fingerprint(identity: &ResolvedIdentity) -> Option<String> {
    match identity {
        ResolvedIdentity::Agent { fingerprint, .. } => Some(fingerprint.clone()),
        ResolvedIdentity::Key { fingerprint, .. } => fingerprint.clone(),
        _ => None,
    }
}

/// Machine names are lower-case in the admission path, and a name that only differs by
/// case would otherwise become a second identity for the same machine.
pub fn normalize_machine(machine: &str) -> Result<String> {
    let trimmed = machine.trim();
    if trimmed.is_empty() {
        return refuse("invalid_request", "a machine needs a short name");
    }
    let lowered = trimmed.to_ascii_lowercase();
    // The refusal quotes the name back, and a name is not always the local operator's
    // typing: `fleet.deployment.start` takes one over the gateway from whoever is an
    // administrator on this runtime, and the refusal is printed on somebody's terminal.
    // `fleet::validate_machine`'s message repeats the name verbatim, so a name carrying
    // ANSI escapes used to rewrite the terminal it was refused on. It is sanitized the
    // same way any other text this process did not author is.
    fleet::validate_machine(&lowered).map_err(|_| super::SetupError {
        reason: "invalid_request",
        detail: format!(
            "machine name `{}` must be 1–40 letters, numbers, or hyphens, starting and ending with a letter or number (example: studio-mini)",
            super::sanitize_remote_text(&lowered, 60)
        ),
    })?;
    Ok(lowered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine name is lower-cased before it becomes an identity, so `Buildbox` and
    /// `buildbox` cannot become two members.
    #[test]
    fn machine_names_are_normalized_to_one_identity() {
        assert_eq!(normalize_machine("BuildBox").expect("a name"), "buildbox");
        assert_eq!(normalize_machine("  studio ").expect("a name"), "studio");
        assert!(normalize_machine("").is_err());
        assert!(normalize_machine("has spaces").is_err());
    }
}
