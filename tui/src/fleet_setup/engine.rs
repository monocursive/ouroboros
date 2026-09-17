//! The steps, in order, for the three orchestrations.
//!
//! One code path serves the CLI and the detached worker; what differs is the
//! [`Conversation`] a question goes to. Every externally visible step is bracketed by a
//! journal write, and every step that has already succeeded is skipped on a resume — so
//! an operation interrupted at any durable boundary continues from that boundary rather
//! than reissuing credentials or installing twice.
//!
//! The order in `add` is the proposal's, and the order matters:
//!
//! 1. inspect the *effective* SSH config, before connecting;
//! 2. verify the host key, before authenticating;
//! 3. authenticate and inspect the target;
//! 4. install a missing `ouro`, from the exact own-version release;
//! 5. read every current member's fleet identity and roster — and stop here if one is
//!    unreachable or has an unresolved operation, because credentials must not leave the
//!    issuer while the roster cannot be completed;
//! 6. prepare the target's key, issue its certificate, install its profile;
//! 7. update every member's roster;
//! 8. hand startup to the service seam;
//! 9. observe connectivity, then report readiness separately from connectivity.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::{json, Value};

use crate::fleet;
use crate::update::release;

use super::askpass::{Bridge, PromptContext};
use super::challenge::{host_trust_metadata, Answer, ChallengeKind};
use super::gateway::{self, Gateway};
use super::helper;
use super::journal::{
    Handle as JournalHandle, IntendedPaths, Journal, RosterMember, RosterSnapshot, SelectedRelease,
    StepRecord, TargetIdentity,
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
    OperationRequest, OperationState,
};

/// How long the engine waits for a new member to appear connected.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(60);
/// How long it waits for a removed member to disappear.
pub const DISCONNECT_DEADLINE: Duration = Duration::from_secs(60);
/// A roster edit that lost a lock race is retried this many times before it is reported.
const ROSTER_RETRIES: u32 = 3;

/// What the operation ended up doing.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub operation: String,
    pub state: OperationState,
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
            "plan_digest": self.plan.as_ref().map(Plan::digest),
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
    /// The authenticated subject this operation belongs to, when it is known before the
    /// operation starts. The CLI knows it — the local account. The worker does not: its
    /// owner is the first client that attaches, so it passes `None` and records it then.
    pub owner: Option<String>,
}

impl Engine {
    /// Run the operation the request names, journalling into a handle of its own.
    ///
    /// A dry run is answered *before* a journal is opened: opening one would create the
    /// file that `--dry-run` promises not to write.
    pub fn run(&self) -> Result<Outcome> {
        super::validate_operation_id(&self.request.operation)?;
        if self.request.dry_run {
            return self.dry_run();
        }
        let journal = JournalHandle::new(Journal::open(
            &self.data_dir,
            &self.request.operation,
            self.request.kind,
        )?);
        self.run_with(&journal)
    }

    /// The same, against a journal somebody else is also writing — the worker's socket
    /// thread records the operation's owner there while the engine records its steps.
    pub fn run_with(&self, journal: &JournalHandle) -> Result<Outcome> {
        super::validate_operation_id(&self.request.operation)?;
        if self.request.dry_run {
            return self.dry_run();
        }
        if let Some(owner) = &self.owner {
            journal.claim(owner)?;
        }
        if journal.state() == OperationState::Completed {
            return Ok(self.completed_outcome(journal));
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
                let state = if reason == "cancelled" {
                    OperationState::Cancelled
                } else {
                    OperationState::Failed
                };
                journal.fail(state, format!("{error:#}"))?;
                self.notify_state(state);
                Err(error)
            }
        }
    }

    fn completed_outcome(&self, journal: &JournalHandle) -> Outcome {
        Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
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

    fn notify_state(&self, state: OperationState) {
        self.conversation.notify(Event::State(state));
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

    fn scratch(&self) -> Result<PathBuf> {
        let path = super::scratch_dir(&self.data_dir, &self.request.operation);
        super::ensure_deploy_dir(&self.data_dir)?;
        super::ensure_private_subdir(&path)?;
        Ok(path)
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

    /// The same, for one existing member, honouring its own access overrides.
    fn member_destination(&self, host: &str, access: &super::MemberAccess) -> Result<Destination> {
        let mut destination = self.destination(
            host,
            access
                .ssh_user
                .as_deref()
                .or(self.request.ssh_user.as_deref()),
        )?;
        if let Some(port) = access.ssh_port {
            destination.port = port;
        }
        Ok(destination)
    }

    /// Everything between "we have an address" and "we have an authenticated channel":
    /// the effective-config check, host trust, and the first authentication.
    fn connect(&self, destination: Destination) -> Result<Connection> {
        let scratch = self.scratch()?;
        let identity = ssh::resolve_identity(&self.programs, &self.request.identity, &scratch)?;
        let known_hosts = self.known_hosts(&scratch);

        // Built without a bridge first: `ssh -G` does not authenticate, and arming the
        // askpass socket before the routing check would allow a prompt for a destination
        // this operation is about to refuse.
        let probe = Runner {
            programs: self.programs.clone(),
            destination: destination.clone(),
            identity: identity.clone(),
            known_hosts: known_hosts.clone(),
            user_known_hosts: self.user_known_hosts.clone(),
            connect_timeout: ssh::CONNECT_TIMEOUT,
            command_timeout: ssh::COMMAND_TIMEOUT,
            bridge: None,
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

        let runner = Runner {
            programs: self.programs.clone(),
            destination,
            identity,
            known_hosts,
            user_known_hosts: self.user_known_hosts.clone(),
            connect_timeout: ssh::CONNECT_TIMEOUT,
            command_timeout: ssh::COMMAND_TIMEOUT,
            bridge: Some(Arc::clone(&bridge)),
        };
        self.notify_state(OperationState::AwaitingAuth);
        runner.check_access()?;
        Ok(Connection {
            runner,
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
        match trust::examine(
            &self.trust_tools,
            &stores,
            &destination.address,
            destination.port,
            scratch,
        )? {
            Trust::Known { fingerprint, .. } => Ok(fingerprint),
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
                self.notify_state(OperationState::AwaitingHostTrust);
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
                        self.note(format!(
                            "recorded trust for {} {}",
                            destination.address, key.fingerprint
                        ));
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

    /// Ask the operator to approve a plan, and bind the approval to its digest.
    fn review(&self, plan: &Plan) -> Result<()> {
        self.notify_state(OperationState::AwaitingReview);
        if self.request.assume_yes {
            // `--yes` accepts a *resolved* plan. It has already failed to bypass host
            // trust (that challenge is raised before this point and is answered by the
            // conversation, which refuses it non-interactively) and it cannot make a
            // busy runtime idle.
            self.note("--yes: accepting the resolved plan without a review prompt");
            return Ok(());
        }
        let digest = plan.digest();
        let answer = self.conversation.ask(ChallengeRequest {
            kind: ChallengeKind::Review,
            metadata: json!({ "plan": plan.to_value(), "plan_digest": digest }),
        })?;
        match answer {
            Answer::Approval { plan_digest } if super::constant_time_eq(&plan_digest, &digest) => {
                Ok(())
            }
            Answer::Approval { .. } => refuse(
                "plan_changed",
                "the approval names a different plan than the one this operation resolved; review the current plan again",
            ),
            _ => refuse("review_declined", "the plan was not approved"),
        }
    }

    /// The plan digest a resumed operation has to still match (seam S6).
    fn bind_plan(&self, journal: &JournalHandle, plan: &Plan) -> Result<()> {
        let digest = plan.digest();
        if let Some(recorded) = journal.record().plan_digest.clone() {
            if !super::constant_time_eq(&recorded, &digest) {
                return refuse(
                    "plan_changed",
                    "the facts behind this operation changed since it was approved — the target, the roster or the selected release is not what was reviewed. Review the new plan rather than continuing the old one",
                );
            }
            return Ok(());
        }
        self.review(plan)?;
        journal.set_plan_digest(&digest)
    }

    fn local_profile(&self) -> Result<Option<fleet::Profile>> {
        fleet::load(&self.data_dir)
    }

    fn roster_snapshot(&self, profile: &fleet::Profile) -> RosterSnapshot {
        RosterSnapshot {
            fleet_id: Some(profile.fleet_id.clone()),
            roster_revision: profile.roster_revision,
            members: profile
                .members
                .iter()
                .map(|member| RosterMember {
                    machine: member.machine.clone(),
                    host: member.host.clone(),
                })
                .collect(),
        }
    }

    /// The source roster must still be the one the plan was computed against.
    ///
    /// The proposal: "A changed source roster or conflicting operation requires
    /// reconciliation, never overwriting later edits."
    fn ensure_roster_unchanged(
        &self,
        journal: &JournalHandle,
        profile: &fleet::Profile,
    ) -> Result<()> {
        let Some(recorded) = &journal.record().roster else {
            return Ok(());
        };
        let current = self.roster_snapshot(profile);
        if recorded.fleet_id != current.fleet_id {
            return refuse(
                "fleet_changed",
                "this machine's fleet identity changed since the operation started; nothing was applied",
            );
        }
        if recorded.roster_revision != current.roster_revision
            || recorded.members != current.members
        {
            return refuse(
                "roster_changed",
                format!(
                    "this machine's roster moved from revision {} to {} since the plan was reviewed. Re-run the operation so the change is reconciled rather than overwritten",
                    recorded.roster_revision, current.roster_revision
                ),
            );
        }
        Ok(())
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
            OperationKind::Leave => self.plan_leave()?.0,
        };
        let _ =
            std::fs::remove_dir_all(super::scratch_dir(&self.data_dir, &self.request.operation));
        Ok(Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::AwaitingReview,
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
        self.notify_state(OperationState::Inspecting);
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

        let members: Vec<PlanMember> = profile
            .members
            .iter()
            .map(|member| PlanMember {
                machine: member.machine.clone(),
                host: member.host.clone(),
                reached_by: if member.machine == profile.machine {
                    "local".to_string()
                } else {
                    "ssh".to_string()
                },
                change: format!("add {machine}"),
            })
            .collect();

        let plan = Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Add,
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
            members,
            restart: None,
            grants: vec![admission_grant()],
            build: Some(
                serde_json::to_value(crate::fleet_protocol::build_metadata())
                    .unwrap_or(Value::Null),
            ),
        };

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
        let requested = self
            .request
            .install_path
            .clone()
            .unwrap_or_else(|| super::bootstrap::DEFAULT_INSTALL_PATH.to_string());
        if requested.starts_with('/') {
            return Ok(requested);
        }
        super::bootstrap::validate_install_path(&requested)?;
        Ok(preflight.install_path(&requested))
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
        let (plan, prepared) = self.plan_add()?;
        let machine = prepared.machine.clone();
        let target_host = plan.target.address.clone();

        journal.set_target(TargetIdentity {
            machine: machine.clone(),
            peer_id: None,
            hostname: None,
            address: Some(target_host.clone()),
            port: Some(plan.target.port),
            ssh_user: Some(plan.target.ssh_user.clone()),
            os: None,
            arch: None,
            node: plan.target.node.clone(),
            host_fingerprint: plan.target.host_fingerprint.clone(),
        })?;
        journal.set_paths(IntendedPaths {
            install_path: Some(prepared.executable.clone()),
            data_dir: self.request.remote_data_dir.clone(),
        })?;
        if journal.record().roster.is_none() {
            journal.set_roster(self.roster_snapshot(&prepared.profile))?;
        }
        if let Some(release) = &prepared.release {
            journal.set_release(SelectedRelease {
                version: release.version.clone(),
                target: release.target.clone(),
                asset: release.asset.clone(),
                sha256: release.sha256.clone(),
            })?;
        }
        self.bind_plan(journal, &plan)?;
        self.ensure_roster_unchanged(journal, &prepared.profile)?;

        self.notify_state(OperationState::Deploying);
        journal.set_state(OperationState::Deploying)?;
        let mut unknown = Vec::new();

        // ---- install a missing ouro
        if let Some(release) = &prepared.release {
            if !journal.record().completed(&machine, "install_binary") {
                self.check_cancelled()?;
                journal.begin_step(&machine, "install_binary")?;
                self.step_event(&machine, "install_binary", "started", None);
                let cancelled = AtomicBool::new(false);
                let bytes = release::fetch_verified(
                    &self.origin,
                    &release.version,
                    &release.asset,
                    &release.sha256,
                    &cancelled,
                )?;
                let install_relative = self
                    .request
                    .install_path
                    .clone()
                    .filter(|path| !path.starts_with('/'))
                    .unwrap_or_else(|| super::bootstrap::DEFAULT_INSTALL_PATH.to_string());
                let installed = super::bootstrap::install(
                    &prepared.connection.runner,
                    &release.asset,
                    &bytes,
                    &release.sha256,
                    &install_relative,
                )?;
                journal.finish_step(
                    &machine,
                    "install_binary",
                    "ok",
                    Some(format!("ouro {} at {}", release.version, installed.path)),
                    Some(format!("sha256:{}", installed.sha256)),
                )?;
                self.step_event(&machine, "install_binary", "ok", Some(installed.path));
            }
        } else {
            journal.skip_step(&machine, "install_binary", "the target already has ouro")?;
        }

        // ---- inspect the target through its own helper
        let mut session = helper::Session::open(
            &prepared.connection.runner,
            &prepared.executable,
            self.request.remote_data_dir.as_deref(),
        )?;
        let inspection = session.ask("inspect", json!({}))?;
        self.verify_build_contract(&inspection, &machine)?;
        let mut target_admitted = false;
        if let Some(existing) = inspection.get("fleet").and_then(Value::as_object) {
            let existing_fleet = existing
                .get("fleet_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if existing_fleet == prepared.profile.fleet_id {
                target_admitted = true;
            } else {
                return refuse(
                    "fleet_exists",
                    format!(
                        "{machine} already belongs to another fleet ({}). Run `ouro fleet leave` there first; this workflow never replaces an existing installation's identity",
                        sanitize_remote_text(existing_fleet, 40)
                    ),
                );
            }
        }
        journal.finish_step(
            &machine,
            "inspect",
            "ok",
            Some(format!(
                "{} {}",
                inspection
                    .get("os")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown os"),
                inspection
                    .get("arch")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown arch")
            )),
            None,
        )?;
        self.step_event(&machine, "inspect", "ok", None);

        // ---- read every current member before any credential is issued
        let mut member_sessions = self.preflight_members(journal, &prepared.profile)?;

        // ---- prepare, issue, install
        // Membership is the operator's *name*, and nothing else. Matching on the host as
        // well would call a machine a member because another member happens to share an
        // address, which is exactly what happens when two data directories are set up on
        // one host; `issue_member_certificate` refuses a genuine node collision on its
        // own.
        let already_member = prepared
            .profile
            .members
            .iter()
            .any(|member| member.machine == machine);
        if target_admitted {
            for step in ["prepare", "issue", "install"] {
                if !journal.record().completed(&machine, step) {
                    journal.skip_step(
                        &machine,
                        step,
                        "the target already holds this fleet's credentials",
                    )?;
                }
            }
        } else if already_member {
            return refuse(
                "identity_mismatch",
                format!(
                    "this machine's roster already names {machine}, but {machine} holds no fleet identity. One of the two is stale: `ouro fleet members remove {machine}` here, or `ouro fleet status` there, before admitting it again"
                ),
            );
        } else if journal.record().completed(&machine, "issue") {
            // The certificate left this machine and the target does not have it. The
            // materials cannot be reissued — replaying an admission is exactly what the
            // issuer refuses — and they were never written down, because they carry the
            // fleet cookie. Say so precisely instead of failing on a replay refusal.
            return refuse(
                "credentials_unrecoverable",
                format!(
                    "operation {} issued credentials for {machine} and they did not reach it. They cannot be reissued under this operation. Check {machine}: if it has a fleet directory, finish the operation there; otherwise run `ouro fleet members remove {machine}` here and admit it again as a new operation",
                    self.request.operation
                ),
            );
        } else if !journal.record().completed(&machine, "install") {
            self.check_cancelled()?;
            journal.begin_step(&machine, "prepare")?;
            let request_fields = session.ask(
                "prepare",
                json!({
                    "operation": self.request.operation,
                    "machine": machine,
                    "host": target_host,
                }),
            )?;
            let admission: fleet::AdmissionRequest =
                serde_json::from_value(Value::Object(request_fields.clone())).map_err(|error| {
                    super::SetupError {
                        reason: "helper_protocol",
                        detail: format!(
                            "the target's prepare reply is not an admission request: {error}"
                        ),
                    }
                })?;
            journal.finish_step(
                &machine,
                "prepare",
                "ok",
                Some(admission.node.clone()),
                Some(admission.key_fingerprint.clone()),
            )?;
            self.step_event(&machine, "prepare", "ok", None);

            // The last safe place to stop. From here to the end of `install` the
            // operation finishes what it started: a certificate that has been issued and
            // not delivered cannot be reissued, so cancelling in that window would cost
            // the target its identity rather than save it. The proposal's wording is
            // "finish or reconcile the in-flight durable step".
            if self.conversation.cancelled() {
                journal.note_residue(format!(
                    "{machine} holds a prepared key for operation {}; resuming this operation uses it, and `ouro fleet doctor` there names it until then",
                    self.request.operation
                ))?;
                return refuse(
                    "cancelled",
                    format!(
                        "the operation stopped before any credential was issued. {machine} holds a prepared key for it and is otherwise unchanged"
                    ),
                );
            }

            journal.begin_step(&machine, "issue")?;
            let materials = fleet::issue_member_certificate(&self.data_dir, &admission)?;
            journal.finish_step(
                &machine,
                "issue",
                "ok",
                Some(format!("issued for {}", admission.node)),
                Some(admission.key_fingerprint.clone()),
            )?;
            self.step_event(&machine, "issue", "ok", None);

            journal.begin_step(&machine, "install")?;
            let mut install = json!({
                "operation": self.request.operation,
                "materials": serde_json::to_value(&materials)?,
            });
            let ports = self.request.ports();
            if ports != fleet::Ports::DEFAULT {
                install["ports"] = json!({
                    "gateway": ports.gateway,
                    "dist": ports.dist,
                    "epmd": ports.epmd,
                });
            }
            let installed = session.ask("install", install)?;
            // The admission slice reports a post-rename bookkeeping failure as a warning
            // beside a successful install: the target *is* admitted at that point, and
            // calling it a failure would send an operator to undo something that
            // happened.
            let warnings: Vec<String> = installed
                .get("warnings")
                .and_then(Value::as_array)
                .map(|warnings| {
                    warnings
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|text| sanitize_remote_text(text, 200))
                        .collect()
                })
                .unwrap_or_default();
            for warning in &warnings {
                journal.note_residue(format!("{machine}: {warning}"))?;
            }
            let warning = warnings.first().cloned();
            journal.finish_step(
                &machine,
                "install",
                "ok",
                Some(match &warning {
                    Some(warning) => format!("admitted, with a warning: {warning}"),
                    None => "admitted".to_string(),
                }),
                None,
            )?;
            self.step_event(&machine, "install", "ok", warning);
        }

        // ---- roster on every member
        self.apply_roster_everywhere(
            journal,
            &prepared.profile,
            &mut member_sessions,
            fleet::RosterChange::Add {
                machine: machine.clone(),
                host: target_host.clone(),
                node: None,
            },
        )?;

        // ---- startup
        let startup = self.arrange_startup(journal, &machine, &mut session)?;
        match startup {
            Startup::Manual => unknown.push(format!(
                "{machine}'s connection, because manual startup was chosen and its runtime has not been started from here"
            )),
            Startup::Unsupported => unknown.push(format!(
                "{machine}'s connection: it has no supported user supervisor, so it must be started there by hand"
            )),
            Startup::Started => {}
        }

        // ---- connectivity, then readiness
        self.notify_state(OperationState::CheckingReadiness);
        journal.set_state(OperationState::CheckingReadiness)?;
        let connected = if startup == Startup::Started {
            self.await_connection(journal, &machine)?
        } else {
            journal.skip_step(&machine, "connect", "the runtime was not started from here")?;
            false
        };
        let doctor = self.remote_doctor(
            journal,
            &machine,
            &prepared.connection.runner,
            &prepared.executable,
        )?;
        if doctor.is_none() {
            unknown.push(format!("{machine}'s own diagnostics could not be read"));
        }
        self.record_readiness(journal, &machine, &mut unknown)?;
        if self.request.run_test_task {
            self.run_test_task(journal, &machine)?;
        } else {
            journal.skip_step(&machine, "test_task", "not requested")?;
        }

        session.close();
        for session in member_sessions.drain(..) {
            session.session.close();
        }

        // Admission is complete when every step this operation *intended* to take
        // succeeded. A runtime the operator chose to start themselves has not failed to
        // connect; it has not been started. Only a startup this operation performed can
        // leave the operation unfinished.
        let state = if connected || startup != Startup::Started {
            OperationState::Completed
        } else {
            OperationState::Interrupted
        };
        journal.set_state(state)?;
        self.notify_state(state);
        let _ =
            std::fs::remove_dir_all(super::scratch_dir(&self.data_dir, &self.request.operation));

        Ok(Outcome {
            operation: self.request.operation.clone(),
            state,
            summary: if connected {
                format!("{machine} joined the fleet and is connected")
            } else {
                format!("{machine} was admitted; its connection is not observed yet")
            },
            next: if connected {
                format!("Connected; configure a model on {machine}")
            } else if startup == Startup::Started {
                format!(
                    "Admitted. Check {machine} with `ouro fleet doctor --peer {target_host}` once its runtime is up"
                )
            } else {
                format!("Admitted. Start the runtime on {machine} with `ouro daemon` there, then `ouro fleet doctor`")
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
        inspection: &serde_json::Map<String, Value>,
        machine: &str,
    ) -> Result<()> {
        let local = crate::fleet_protocol::build_metadata();
        let Some(remote) = inspection.get("build").filter(|build| !build.is_null()) else {
            return refuse(
                "incompatible_installation",
                format!(
                    "{machine} did not report a build contract, so its compatibility with this fleet cannot be established. Upgrade it to a current official release and run this again"
                ),
            );
        };
        let field = |name: &str| -> Option<String> {
            remote
                .get(name)
                .and_then(Value::as_str)
                .map(|text| sanitize_remote_text(text, 64))
        };
        let revision = remote
            .get("fleet_protocol_revision")
            .and_then(Value::as_u64);
        let mismatches = [
            (
                "fleet protocol revision",
                revision.map(|value| value.to_string()),
                Some(local.fleet_protocol_revision.to_string()),
            ),
            (
                "Ouroboros version",
                field("ouroboros_version"),
                Some(local.ouroboros_version.clone()),
            ),
            (
                "OTP release",
                field("otp_release"),
                local.otp_release.clone(),
            ),
        ];
        let differing: Vec<String> = mismatches
            .iter()
            .filter(|(_, remote, local)| remote != local)
            .map(|(label, remote, local)| {
                format!(
                    "{label} {} here and {} there",
                    local.clone().unwrap_or_else(|| "unknown".into()),
                    remote.clone().unwrap_or_else(|| "unknown".into())
                )
            })
            .collect();
        if differing.is_empty() {
            return Ok(());
        }
        refuse(
            "incompatible_installation",
            format!(
                "{machine}'s Ouroboros is not compatible with this fleet: {}. This workflow never replaces an existing installation — install the matching official release there yourself (`ouro update` on that machine, or download the same release), then run this command again",
                differing.join("; ")
            ),
        )
    }

    /// Read every current member's fleet identity and roster revision, and refuse to go
    /// further if one cannot be reached or has an unresolved operation.
    fn preflight_members(
        &self,
        journal: &JournalHandle,
        profile: &fleet::Profile,
    ) -> Result<Vec<MemberSession>> {
        let mut sessions = Vec::new();
        for member in &profile.members {
            if member.machine == profile.machine {
                continue;
            }
            self.check_cancelled()?;
            journal.begin_step(&member.machine, "member_preflight")?;
            let access = self
                .request
                .members
                .get(&member.machine)
                .cloned()
                .unwrap_or_default();
            let destination = self.member_destination(&member.host, &access)?;
            let connection = self.connect(destination).map_err(|error| {
                super::SetupError {
                    reason: "member_unreachable",
                    detail: format!(
                        "{} could not be reached, and a new member's credentials must not be issued while an existing member cannot be told about it: {error:#}",
                        member.machine
                    ),
                }
            })?;
            let preflight = super::bootstrap::preflight(&connection.runner)?;
            let executable = match access.install_path.as_deref() {
                Some(path) if path.starts_with('/') => path.to_string(),
                Some(path) => {
                    super::bootstrap::validate_install_path(path)?;
                    preflight.install_path(path)
                }
                None => self.remote_executable(&preflight)?,
            };
            let mut session =
                helper::Session::open(&connection.runner, &executable, access.data_dir.as_deref())
                    .map_err(|error| super::SetupError {
                        reason: "member_unreachable",
                        detail: format!(
                            "{}'s setup helper did not start: {error:#}",
                            member.machine
                        ),
                    })?;
            let inspection = session.ask("inspect", json!({}))?;
            let pending = inspection
                .get("pending_operations")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0);
            if pending > 0 {
                return refuse(
                    "member_operation_unresolved",
                    format!(
                        "{} has an unresolved admission operation. Finish or clear it there before admitting another machine; a half-finished admission plus a new one is how a roster diverges",
                        member.machine
                    ),
                );
            }
            let Some(fleet) = inspection.get("fleet").and_then(Value::as_object) else {
                return refuse(
                    "member_unreachable",
                    format!(
                        "{} is no longer configured as a fleet member",
                        member.machine
                    ),
                );
            };
            if fleet.get("fleet_id").and_then(Value::as_str) != Some(profile.fleet_id.as_str()) {
                return refuse(
                    "member_unreachable",
                    format!(
                        "{} belongs to a different fleet than this one",
                        member.machine
                    ),
                );
            }
            let revision = fleet
                .get("roster_revision")
                .and_then(Value::as_u64)
                .ok_or_else(|| super::SetupError {
                    reason: "helper_protocol",
                    detail: format!("{} reported no roster revision", member.machine),
                })?;
            journal.finish_step(
                &member.machine,
                "member_preflight",
                "ok",
                Some(format!("roster revision {revision}")),
                None,
            )?;
            self.step_event(&member.machine, "member_preflight", "ok", None);
            sessions.push(MemberSession {
                machine: member.machine.clone(),
                revision,
                session,
                _connection: connection,
            });
        }
        Ok(sessions)
    }

    /// Apply one roster change on the local member and on every remote member.
    fn apply_roster_everywhere(
        &self,
        journal: &JournalHandle,
        profile: &fleet::Profile,
        members: &mut [MemberSession],
        change: fleet::RosterChange,
    ) -> Result<()> {
        let step = "roster";
        if !journal.record().completed(&profile.machine, step) {
            self.check_cancelled()?;
            journal.begin_step(&profile.machine, step)?;
            let current = self.local_profile()?.ok_or_else(|| super::SetupError {
                reason: "no_fleet",
                detail: "this machine's fleet profile disappeared mid-operation".into(),
            })?;
            // A receipt belongs to one machine identity, and on the issuer this
            // operation's receipt already belongs to the machine being admitted. The
            // issuer's own roster edit is therefore recorded under a derived id; the
            // journal is what ties the two halves of the operation together.
            let outcome = fleet::apply_roster_change(
                &self.data_dir,
                &self.local_roster_operation(),
                current.roster_revision,
                &change,
            )?;
            journal.finish_step(
                &profile.machine,
                step,
                "ok",
                Some(format!("revision {}", outcome.roster_revision)),
                None,
            )?;
            self.step_event(&profile.machine, step, "ok", None);
        }

        for member in members.iter_mut() {
            if journal.record().completed(&member.machine, step) {
                continue;
            }
            self.check_cancelled()?;
            journal.begin_step(&member.machine, step)?;
            let mut revision = member.revision;
            let mut attempt = 0;
            loop {
                attempt += 1;
                let result = member.session.ask(
                    "roster",
                    json!({
                        "operation": self.request.operation,
                        "expected_revision": revision,
                        "change": serde_json::to_value(&change)?,
                    }),
                );
                match result {
                    Ok(fields) => {
                        let now = fields
                            .get("roster_revision")
                            .and_then(Value::as_u64)
                            .unwrap_or(revision);
                        journal.finish_step(
                            &member.machine,
                            step,
                            "ok",
                            Some(format!("revision {now}")),
                            None,
                        )?;
                        self.step_event(&member.machine, step, "ok", None);
                        member.revision = now;
                        break;
                    }
                    // A lock held by a concurrent roster edit on that machine is a
                    // retry; a stale revision is a re-read; an invalid change is neither.
                    Err(error)
                        if attempt <= ROSTER_RETRIES
                            && super::reason_of(&error) == Some("lock_unavailable") =>
                    {
                        std::thread::sleep(Duration::from_millis(250 * u64::from(attempt)));
                        continue;
                    }
                    Err(error) if super::reason_of(&error) == Some("roster_conflict") => {
                        // The member's roster moved. Re-read it once and try again with
                        // the revision it actually holds; a second conflict is reported
                        // rather than retried into a lost update.
                        if attempt > 2 {
                            return Err(error);
                        }
                        let inspection = member.session.ask("inspect", json!({}))?;
                        let Some(now) = inspection
                            .get("fleet")
                            .and_then(|fleet| fleet.get("roster_revision"))
                            .and_then(Value::as_u64)
                        else {
                            return Err(error);
                        };
                        revision = now;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    /// The operation id the issuer's own roster edit is receipted under. See
    /// [`Self::apply_roster_everywhere`].
    fn local_roster_operation(&self) -> String {
        format!("{}-roster", self.request.operation)
    }

    /// Install (or explicitly skip) the target's startup service, through seam S9.
    fn arrange_startup(
        &self,
        journal: &JournalHandle,
        machine: &str,
        session: &mut helper::Session,
    ) -> Result<Startup> {
        if !self.request.service {
            journal.skip_step(
                machine,
                "service",
                "manual startup was chosen with --no-service",
            )?;
            return Ok(Startup::Manual);
        }
        if journal.record().completed(machine, "service") {
            return Ok(Startup::Started);
        }
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
            return Ok(Startup::Unsupported);
        }
        let started = self.services.remote(session, ServiceAction::Start)?;
        journal.finish_step(
            machine,
            "service",
            "ok",
            Some(format!("{}; {}", installed.detail, started.detail)),
            None,
        )?;
        self.step_event(machine, "service", "ok", Some(started.detail));
        Ok(Startup::Started)
    }

    /// Poll the local gateway's `fleet.status` until the member appears connected.
    fn await_connection(&self, journal: &JournalHandle, machine: &str) -> Result<bool> {
        journal.begin_step(machine, "connect")?;
        let deadline = Instant::now() + CONNECT_DEADLINE;
        loop {
            match self.gateway.call("fleet.status", json!({})) {
                Ok(Some(status)) if member_connected(&status, machine) => {
                    journal.finish_step(
                        machine,
                        "connect",
                        "ok",
                        Some("the local runtime sees it connected".into()),
                        None,
                    )?;
                    self.step_event(machine, "connect", "ok", None);
                    return Ok(true);
                }
                Ok(_) => {}
                Err(error) => {
                    journal.finish_step(
                        machine,
                        "connect",
                        "skipped",
                        Some(format!(
                            "this machine's runtime could not be asked: {error:#}"
                        )),
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
                        "this machine's runtime did not see {machine} connect within {} seconds",
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

    /// The target's own diagnostics, which say things the issuer cannot observe.
    fn remote_doctor(
        &self,
        journal: &JournalHandle,
        machine: &str,
        runner: &Runner,
        executable: &str,
    ) -> Result<Option<Value>> {
        let command = match self.request.remote_data_dir.as_deref() {
            Some(data_dir) => format!(
                "exec /usr/bin/env OUROBOROS_DATA_DIR={} {} fleet doctor --json",
                ssh::shell_quote(data_dir),
                ssh::shell_quote(executable)
            ),
            None => format!("exec {} fleet doctor --json", ssh::shell_quote(executable)),
        };
        let completed = runner.run(&command, None)?;
        let parsed: Option<Value> = serde_json::from_slice(&completed.stdout).ok();
        match &parsed {
            Some(_) => {
                journal.finish_step(
                    machine,
                    "diagnostics",
                    if completed.success() { "ok" } else { "failed" },
                    Some(if completed.success() {
                        "the target's own doctor reports no setup problems".into()
                    } else {
                        "the target's own doctor found setup problems".to_string()
                    }),
                    None,
                )?;
            }
            None => {
                journal.finish_step(
                    machine,
                    "diagnostics",
                    "skipped",
                    Some(format!(
                        "the target's diagnostics could not be read: {}",
                        completed.stderr_text()
                    )),
                    None,
                )?;
            }
        }
        Ok(parsed)
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

    /// The explicit first-task check, only when asked for.
    fn run_test_task(&self, journal: &JournalHandle, machine: &str) -> Result<()> {
        journal.begin_step(machine, "test_task")?;
        // A *planning* session, deliberately: it reads and reasons and edits nothing, and
        // it is the smallest real thing that exercises the new member's model access
        // through the normal path. The proposal's rule is that a real model call happens
        // only when the operator asks, which is what `--run-test-task` is.
        match self.gateway.call(
            "interactive.start",
            json!({ "machine": machine, "plan": true }),
        ) {
            Ok(Some(started)) => {
                let id = started
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| sanitize_remote_text(id, 64))
                    .unwrap_or_else(|| "unnamed".into());
                journal.finish_step(
                    machine,
                    "test_task",
                    "ok",
                    Some(format!(
                        "started planning session {id} on {machine}; open it with `ouro attach`"
                    )),
                    None,
                )?;
                self.step_event(machine, "test_task", "ok", Some(id));
            }
            Ok(None) => {
                journal.finish_step(
                    machine,
                    "test_task",
                    "skipped",
                    Some("this machine's runtime is not running, so no task was started".into()),
                    None,
                )?;
            }
            Err(error) => {
                journal.finish_step(
                    machine,
                    "test_task",
                    "failed",
                    Some(format!("the task could not be started: {error:#}")),
                    None,
                )?;
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- setup

    fn plan_setup(&self) -> Result<Plan> {
        self.notify_state(OperationState::Inspecting);
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
        Ok(Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Setup,
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
            members: vec![PlanMember {
                machine: machine.clone(),
                host: parsed.to_string(),
                reached_by: "local".into(),
                change: "create this fleet".into(),
            }],
            restart,
            grants: vec![admission_grant()],
            build: Some(
                serde_json::to_value(crate::fleet_protocol::build_metadata())
                    .unwrap_or(Value::Null),
            ),
        })
    }

    fn run_setup(&self, journal: &JournalHandle) -> Result<Outcome> {
        let machine = normalize_machine(&self.request.machine)?;
        // Calling setup on a configured machine is an inspection.
        if let Some(profile) = self.local_profile()? {
            journal.set_state(OperationState::Completed)?;
            return Ok(Outcome {
                operation: self.request.operation.clone(),
                state: OperationState::Completed,
                plan: None,
                summary: format!(
                    "this machine is already {} in fleet {}; nothing was changed",
                    profile.machine, profile.name
                ),
                next: format!(
                    "Run `ouro fleet status` to see it, `ouro fleet add` to admit another machine, or `ouro fleet create --regenerate` to repair generated policy files. Its address is {}",
                    profile.host
                ),
                steps: journal.record().steps,
                residue: Vec::new(),
                unknown: Vec::new(),
            });
        }

        let plan = self.plan_setup()?;
        journal.set_target(TargetIdentity {
            machine: machine.clone(),
            address: Some(plan.target.address.clone()),
            node: plan.target.node.clone(),
            ..TargetIdentity::default()
        })?;
        self.bind_plan(journal, &plan)?;

        self.notify_state(OperationState::Deploying);
        journal.set_state(OperationState::Deploying)?;

        // The authorized local transition. The runtime that is running now is the one
        // serving whoever asked for this, so it is stopped only if it is idle.
        if !journal.record().completed(&machine, "stop_runtime") {
            journal.begin_step(&machine, "stop_runtime")?;
            self.notify_state(OperationState::RestartingHost);
            journal.set_state(OperationState::RestartingHost)?;
            let stopped = gateway::stop_require_idle(&self.data_dir, &self.token_file)?;
            journal.finish_step(
                &machine,
                "stop_runtime",
                "ok",
                Some(match stopped {
                    gateway::StopOutcome::NotRunning => "no runtime was running".to_string(),
                    gateway::StopOutcome::RemovedStale { pid } => {
                        format!("removed a stale publication for pid {pid}")
                    }
                    gateway::StopOutcome::Stopped { pid } => {
                        format!("the idle runtime (pid {pid}) stopped")
                    }
                }),
                None,
            )?;
            self.step_event(&machine, "stop_runtime", "ok", None);
        }

        journal.set_state(OperationState::Deploying)?;
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
        let started = if self.request.service {
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

        journal.set_state(OperationState::Completed)?;
        self.notify_state(OperationState::Completed);
        Ok(Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
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

    fn plan_leave(&self) -> Result<(Plan, fleet::Profile)> {
        self.notify_state(OperationState::Inspecting);
        let machine = normalize_machine(&self.request.machine)?;
        let profile = self.local_profile()?.ok_or_else(|| super::SetupError {
            reason: "no_fleet",
            detail: "this machine is standalone; there is no member to remove".into(),
        })?;
        if machine == profile.machine {
            return refuse(
                "identity_mismatch",
                "`ouro fleet leave --machine` takes another machine's name. To retire this one, stop its runtime and run `ouro fleet leave`",
            );
        }
        let Some(member) = profile
            .members
            .iter()
            .find(|member| member.machine == machine)
            .cloned()
        else {
            return refuse(
                "machine_unknown",
                format!("this machine's roster has no member named {machine}; `ouro fleet status` prints the names it knows"),
            );
        };

        let members: Vec<PlanMember> = profile
            .members
            .iter()
            .filter(|entry| entry.machine != machine)
            .map(|entry| PlanMember {
                machine: entry.machine.clone(),
                host: entry.host.clone(),
                reached_by: if entry.machine == profile.machine {
                    "local".into()
                } else {
                    "ssh".into()
                },
                change: format!("remove {machine}"),
            })
            .collect();

        let plan = Plan {
            schema: super::SCHEMA,
            operation: self.request.operation.clone(),
            kind: OperationKind::Leave,
            deployment_host: DeploymentHost::here(&self.data_dir),
            target: PlanTarget {
                machine: machine.clone(),
                address: member.host.clone(),
                port: self.request.ssh_port.unwrap_or(22),
                ssh_user: self.request.ssh_user.clone().unwrap_or_default(),
                identity: "resolved when the member is contacted".into(),
                install_path: String::new(),
                data_dir: self.request.remote_data_dir.clone(),
                host_fingerprint: None,
                node: Some(member.node.clone()),
            },
            release: None,
            service: ServicePlan::Manual,
            members,
            restart: Some(format!(
                "{machine}'s runtime is stopped through its own idle-gated shutdown before its credentials are removed"
            )),
            grants: vec![removal_note(&machine)],
            build: None,
        };
        Ok((plan, profile))
    }

    fn run_leave(&self, journal: &JournalHandle) -> Result<Outcome> {
        let (plan, profile) = self.plan_leave()?;
        let machine = plan.target.machine.clone();
        journal.set_target(TargetIdentity {
            machine: machine.clone(),
            address: Some(plan.target.address.clone()),
            port: Some(plan.target.port),
            ssh_user: self.request.ssh_user.clone(),
            node: plan.target.node.clone(),
            ..TargetIdentity::default()
        })?;
        if journal.record().roster.is_none() {
            journal.set_roster(self.roster_snapshot(&profile))?;
        }
        self.bind_plan(journal, &plan)?;
        self.ensure_roster_unchanged(journal, &profile)?;

        self.notify_state(OperationState::Deploying);
        journal.set_state(OperationState::Deploying)?;

        let destination =
            self.destination(&plan.target.address, self.request.ssh_user.as_deref())?;
        let connection = self.connect(destination)?;
        let preflight = super::bootstrap::preflight(&connection.runner)?;
        let executable = self.remote_executable(&preflight)?;
        let mut session = helper::Session::open(
            &connection.runner,
            &executable,
            self.request.remote_data_dir.as_deref(),
        )?;

        // ---- what this machine will lose sight of
        let inspection = session.ask("inspect", json!({}))?;
        let running = inspection
            .get("runtime_running")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let sessions_note = self.session_ownership(&machine);
        journal.finish_step(
            &machine,
            "inspect",
            "ok",
            Some(format!(
                "runtime {}; {sessions_note}",
                if running { "running" } else { "stopped" }
            )),
            None,
        )?;
        self.step_event(&machine, "inspect", "ok", Some(sessions_note.clone()));

        // ---- stop it from coming back, then stop it
        if !journal.record().completed(&machine, "disable_service") {
            journal.begin_step(&machine, "disable_service")?;
            let disabled = self.services.remote(&mut session, ServiceAction::Disable)?;
            journal.finish_step(
                &machine,
                "disable_service",
                if disabled.supported { "ok" } else { "skipped" },
                Some(disabled.detail.clone()),
                None,
            )?;
            self.step_event(&machine, "disable_service", "ok", Some(disabled.detail));
        }

        if !journal.record().completed(&machine, "stop_runtime") {
            journal.begin_step(&machine, "stop_runtime")?;
            if running {
                let command = match self.request.remote_data_dir.as_deref() {
                    Some(data_dir) => format!(
                        "exec /usr/bin/env OUROBOROS_DATA_DIR={} {} stop --require-idle",
                        ssh::shell_quote(data_dir),
                        ssh::shell_quote(&executable)
                    ),
                    None => format!("exec {} stop --require-idle", ssh::shell_quote(&executable)),
                };
                let completed = connection.runner.run(&command, None)?;
                if !completed.success() {
                    // `ouro stop --require-idle` documents these two: 10 is a runtime
                    // with work in flight, 11 is a runtime that could not say. Unknown
                    // activity never authorizes a removal either.
                    let (reason, detail): (&'static str, String) = match completed.code {
                        Some(10) => (
                            "runtime_busy",
                            format!("{machine} is working, so it was not stopped and nothing was removed. Let the work finish and run this again"),
                        ),
                        Some(11) => (
                            "activity_unknown",
                            format!("{machine} could not say whether it is idle, and unknown activity does not authorize a removal. Stop it yourself when you know it is safe, then run this again"),
                        ),
                        _ => (
                            "runtime_busy",
                            format!(
                                "{machine}'s runtime did not stop: {}. Cooperative removal never stops a runtime that is working",
                                completed.stderr_text()
                            ),
                        ),
                    };
                    return refuse(reason, detail);
                }
                journal.finish_step(
                    &machine,
                    "stop_runtime",
                    "ok",
                    Some("stopped through its own idle-gated shutdown".into()),
                    None,
                )?;
            } else {
                journal.skip_step(&machine, "stop_runtime", "its runtime was not running")?;
            }
            self.step_event(&machine, "stop_runtime", "ok", None);
        }

        // ---- verify it is gone from this machine's view
        let disconnected = self.await_disconnection(journal, &machine)?;

        // ---- retire its credentials there
        if !journal.record().completed(&machine, "leave") {
            journal.begin_step(&machine, "leave")?;
            let left = session.ask(
                "leave",
                json!({ "operation": self.request.operation, "machine": machine }),
            )?;
            journal.finish_step(
                &machine,
                "leave",
                "ok",
                Some(
                    left.get("removed")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "credentials removed".into()),
                ),
                None,
            )?;
            self.step_event(&machine, "leave", "ok", None);
        }

        // ---- and take it out of every remaining roster
        let mut members = self.preflight_members_for_removal(journal, &profile, &machine)?;
        self.apply_roster_everywhere(
            journal,
            &profile,
            &mut members,
            fleet::RosterChange::Remove {
                machine: machine.clone(),
            },
        )?;

        session.close();
        for member in members.drain(..) {
            member.session.close();
        }

        journal.set_state(OperationState::Completed)?;
        self.notify_state(OperationState::Completed);
        let _ =
            std::fs::remove_dir_all(super::scratch_dir(&self.data_dir, &self.request.operation));
        let mut unknown = Vec::new();
        if !disconnected {
            unknown.push(format!(
                "whether {machine} is fully disconnected from this runtime's view"
            ));
        }
        Ok(Outcome {
            operation: self.request.operation.clone(),
            state: OperationState::Completed,
            summary: format!("{machine} left the fleet; its work and session history stay on it"),
            next: removal_note(&machine),
            plan: Some(plan),
            steps: journal.record().steps,
            residue: journal.record().residue,
            unknown,
        })
    }

    /// The remaining members, for a removal. Unreachable members are named rather than
    /// skipped: a roster that still dials a machine that has left is exactly the residue
    /// the proposal requires to be reported.
    fn preflight_members_for_removal(
        &self,
        journal: &JournalHandle,
        profile: &fleet::Profile,
        leaving: &str,
    ) -> Result<Vec<MemberSession>> {
        let remaining = fleet::Profile {
            members: profile
                .members
                .iter()
                .filter(|member| member.machine != leaving)
                .cloned()
                .collect(),
            ..profile.clone()
        };
        self.preflight_members(journal, &remaining)
    }

    fn await_disconnection(&self, journal: &JournalHandle, machine: &str) -> Result<bool> {
        journal.begin_step(machine, "verify_disconnected")?;
        let deadline = Instant::now() + DISCONNECT_DEADLINE;
        loop {
            match self.gateway.call("fleet.status", json!({})) {
                Ok(Some(status)) if !member_connected(&status, machine) => {
                    journal.finish_step(
                        machine,
                        "verify_disconnected",
                        "ok",
                        Some("this machine's runtime no longer sees it connected".into()),
                        None,
                    )?;
                    return Ok(true);
                }
                Ok(None) => {
                    journal.finish_step(
                        machine,
                        "verify_disconnected",
                        "skipped",
                        Some("this machine's runtime is not running, so there is nothing connected to it".into()),
                        None,
                    )?;
                    return Ok(true);
                }
                Ok(_) => {}
                Err(error) => {
                    journal.finish_step(
                        machine,
                        "verify_disconnected",
                        "skipped",
                        Some(format!(
                            "this machine's runtime could not be asked: {error:#}"
                        )),
                        None,
                    )?;
                    return Ok(false);
                }
            }
            if Instant::now() >= deadline {
                journal.finish_step(
                    machine,
                    "verify_disconnected",
                    "failed",
                    Some(format!(
                        "{machine} still appears connected after {} seconds",
                        DISCONNECT_DEADLINE.as_secs()
                    )),
                    None,
                )?;
                return Ok(false);
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// What this machine can say about sessions the leaving member owns.
    fn session_ownership(&self, machine: &str) -> String {
        match self.gateway.call("fleet.status", json!({})) {
            Ok(Some(status)) => match member_sessions(&status, machine) {
                Some(count) => format!("it owns {count} session(s) this runtime knows about"),
                None => "this runtime does not report its session count".to_string(),
            },
            Ok(None) => {
                "this machine's runtime is not running, so its session count is unknown".to_string()
            }
            Err(_) => {
                "this machine's runtime did not answer, so its session count is unknown".to_string()
            }
        }
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
}

/// An authenticated channel to one machine, with the bridge that serves its prompts.
struct Connection {
    runner: Runner,
    /// Held for the connection's lifetime: dropping it removes the askpass socket.
    _bridge: Arc<Bridge>,
    host_fingerprint: String,
}

/// One current member, its roster revision, and an open helper session to it.
struct MemberSession {
    machine: String,
    revision: u64,
    session: helper::Session,
    _connection: Connection,
}

/// What `plan_add` established, carried into the deploy steps.
struct Prepared {
    machine: String,
    profile: fleet::Profile,
    connection: Connection,
    executable: String,
    release: Option<PlanRelease>,
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
    fleet::validate_machine(&lowered).map_err(|error| super::refusing("invalid_request", error))?;
    Ok(lowered)
}

/// Whether `fleet.status` reports this machine as connected.
///
/// Matched by the roster *name*, which is the identity the operator gave it; a peer's
/// self-reported hostname is display information and is never treated as a member
/// identity anywhere in this engine.
fn member_connected(status: &Value, machine: &str) -> bool {
    machine_entry(status, machine).is_some_and(|entry| {
        entry
            .get("connected")
            .and_then(Value::as_bool)
            .or_else(|| {
                entry
                    .get("state")
                    .and_then(Value::as_str)
                    .map(|state| state == "connected" || state == "up")
            })
            .unwrap_or(false)
    })
}

fn member_sessions(status: &Value, machine: &str) -> Option<u64> {
    machine_entry(status, machine)?
        .get("sessions")
        .and_then(Value::as_u64)
}

fn machine_entry<'a>(status: &'a Value, machine: &str) -> Option<&'a Value> {
    for key in ["machines", "members", "nodes"] {
        if let Some(entries) = status.get(key).and_then(Value::as_array) {
            if let Some(entry) = entries.iter().find(|entry| {
                entry.get("machine").and_then(Value::as_str) == Some(machine)
                    || entry.get("name").and_then(Value::as_str) == Some(machine)
            }) {
                return Some(entry);
            }
        }
    }
    None
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

    /// Membership is decided by the roster name the operator gave, never by a hostname a
    /// peer reports about itself.
    #[test]
    fn connection_is_read_from_the_roster_name_and_not_from_a_peer_hostname() {
        let status = json!({
            "machines": [
                {"machine": "studio", "connected": true, "sessions": 2},
                {"machine": "buildbox", "connected": false, "sessions": 0}
            ]
        });
        assert!(member_connected(&status, "studio"));
        assert!(!member_connected(&status, "buildbox"));
        assert!(!member_connected(&status, "absent"));
        assert_eq!(member_sessions(&status, "studio"), Some(2));
        assert_eq!(member_sessions(&status, "absent"), None);

        let stateful = json!({"members": [{"name": "vps", "state": "connected"}]});
        assert!(member_connected(&stateful, "vps"));
        assert_eq!(
            member_sessions(&stateful, "vps"),
            None,
            "an absent session count is unknown, not zero"
        );
    }
}
