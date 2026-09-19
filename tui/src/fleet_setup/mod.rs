//! The deployment engine: one operation, one journal, one set of typed questions.
//!
//! `ouro fleet setup`, `ouro fleet add` and `ouro fleet leave --machine` are three
//! shapes of the same thing — a bounded sequence of externally visible steps against a
//! machine an operator selected, each written down before and after it happens, each
//! able to stop and ask a question that only a person can answer. The terminal front end
//! and the `--frames` front end the runtime's broker runs as a port program are the same
//! code; what differs between them is only where a question goes and how progress is
//! reported.
//!
//! The module boundary is deliberate:
//!
//! - [`ssh`] owns every `ssh` invocation and the normalized option set that makes one
//!   safe to run. Nothing else in the tree builds an ssh command line.
//! - [`trust`] owns host-key verification: the private store, `ssh-keyscan`, and the
//!   decision that a changed key blocks.
//! - [`askpass`] is the only path a password or passphrase travels, from the attached
//!   operator to the `ssh` process that asked for it.
//! - [`journal`] is the durable authority for what has already happened (seam S5). It
//!   never contains a secret.
//! - [`plan`] turns an inspected target into the concrete plan an operator approves.
//! - [`engine`] sequences the steps; [`frames`] answers them as NDJSON on this
//!   process's own stdio (§8), and [`terminal`] answers them from a tty.
//!
//! ## What may never appear here
//!
//! The proposal's "Secret handling and authorization" section is the single list, and
//! this module defers to it: no password, passphrase, cookie or private key may reach a
//! command line, an environment variable, the journal, a log line or an error string.
//! The one frame that may carry a secret is a `respond` on stdin, and neither side logs
//! it. [`crate::fleet_setup::askpass`] is the only place a secret is held at all,
//! in a `Zeroizing<String>` that lives for one authentication attempt.

pub mod askpass;
pub mod bootstrap;
pub mod challenge;
pub mod cli;
pub mod engine;
pub mod frames;
pub mod gateway;
pub mod helper;
pub mod journal;
pub(crate) mod lock;
pub mod plan;
pub mod service;
pub mod ssh;
pub mod terminal;
pub mod trust;

use std::fmt::Write as _;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// `<data dir>/deploy/`: the operation namespace (seams S2, S3, S5).
///
/// **Deviation from the seams' spelling, forced by the code.** They say
/// `<data dir>/fleet/deploy/`. That cannot work: `<data dir>/fleet/` is *created by an
/// atomic rename* of a private staging directory (`fleet::create`), which is what makes
/// a half-written identity impossible — and a rename onto an existing directory fails.
/// A deployment journal has to exist before the fleet does, because `ouro fleet setup`
/// journals the operation that is about to create one so an interrupted first setup can
/// be resumed. Everything else about the seams is unchanged, including every file name
/// inside this directory; only the parent moved up one level.
pub const DEPLOY_DIR: &str = "deploy";

/// The private per-deployment-host known-hosts store (seam S7).
pub const KNOWN_HOSTS_FILE: &str = "known_hosts";

/// Seam S3: one frame per line, never more than this many bytes — **including the
/// newline that ends it**.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The most a frame's JSON body may be, which is one byte less: the line is the body
/// plus its newline, and the line is what the cap is about. An emitter that writes a
/// body of exactly [`MAX_FRAME_BYTES`] has written a line of one more than the limit,
/// and the reader on the other side is entitled to hang up on it.
pub const MAX_FRAME_BODY_BYTES: usize = MAX_FRAME_BYTES - 1;

/// How much free text one frame field carries: a log line, a step's detail, a summary.
///
/// Far below the frame cap on purpose. Nothing this protocol says needs two thousand
/// characters, and a field that *could* grow to a megabyte is a field that turns a
/// remote's output, or a long error chain, into a frame nobody can read and a line the
/// peer may refuse. The cap on the whole body stays as the backstop it is.
pub const MAX_FRAME_TEXT: usize = 2_000;

/// A challenge nobody answers expires rather than holding the issuer's locks.
pub const CHALLENGE_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Seam S4, and the proposal's "at most three, respecting stricter server limits".
pub const MAX_PASSWORD_ATTEMPTS: u32 = 3;

/// The journal schema this build writes and reads (§6).
pub const SCHEMA: u8 = 2;

// ------------------------------------------------------------------ refusals

/// A refusal with a stable machine-readable reason, mirroring
/// [`crate::fleet::Refusal`] so one orchestrator can branch on `reason` wherever it
/// came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupError {
    pub reason: &'static str,
    pub detail: String,
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for SetupError {}

/// The stable reason behind an error, when one was declared. Falls back to the fleet
/// library's reason so a helper refusal keeps its code on the way out.
pub fn reason_of(error: &anyhow::Error) -> Option<&'static str> {
    if let Some(declared) = error.downcast_ref::<SetupError>() {
        return Some(declared.reason);
    }
    crate::fleet::refusal(error).map(|declared| declared.reason)
}

pub fn refuse<T>(reason: &'static str, detail: impl Into<String>) -> Result<T> {
    Err(SetupError {
        reason,
        detail: detail.into(),
    }
    .into())
}

/// Give an existing error a stable reason without losing what it said.
pub fn refusing(reason: &'static str, error: anyhow::Error) -> anyhow::Error {
    SetupError {
        reason,
        detail: format!("{error:#}"),
    }
    .into()
}

// ------------------------------------------------------------------ states

/// The operation states the proposal names, in the order an operation passes through
/// them. Serialized into the journal and reported to an attached client.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    #[default]
    Inspecting,
    AwaitingHostTrust,
    AwaitingAuth,
    AwaitingReview,
    Deploying,
    RestartingHost,
    CheckingReadiness,
    Completed,
    Interrupted,
    Failed,
    Cancelled,
}

impl OperationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inspecting => "inspecting",
            Self::AwaitingHostTrust => "awaiting_host_trust",
            Self::AwaitingAuth => "awaiting_auth",
            Self::AwaitingReview => "awaiting_review",
            Self::Deploying => "deploying",
            Self::RestartingHost => "restarting_host",
            Self::CheckingReadiness => "checking_readiness",
            Self::Completed => "completed",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the operation has stopped for good. A terminal state is never resumed.
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Interrupted
        )
    }

    /// Whether this state means the operation is waiting for a person.
    pub fn waiting(self) -> bool {
        matches!(
            self,
            Self::AwaitingHostTrust | Self::AwaitingAuth | Self::AwaitingReview
        )
    }
}

/// Which of the three orchestrations an operation is.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Setup,
    Add,
    Leave,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Add => "add",
            Self::Leave => "leave",
        }
    }
}

// ------------------------------------------------------------------ the request

/// How the operator wants to authenticate to the target.
///
/// `ref` is a *reference*, never a secret: an agent identity's public fingerprint, or a
/// path to a private key this host already holds. `Password` names no value at all —
/// the password arrives through [`askpass`] in answer to a challenge.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityChoice {
    /// Whatever the deployment host's own ssh configuration selects.
    #[default]
    Default,
    /// One identity held by a running agent, selected by its public fingerprint.
    Agent { fingerprint: String },
    /// A private key file on the deployment host.
    Key { path: PathBuf },
    /// The target account's password, for this operation only.
    Password,
}

/// What an operation was asked to do.
///
/// §6: **the request for an operation is argv.** Nothing on it is a secret — an address,
/// an account, a port, a path, a key path or an agent fingerprint — and a password never
/// is, because it arrives through [`askpass`] in answer to a challenge. The private
/// `deploy/<id>.request.json` the detached worker needed is gone with the worker.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub schema: u8,
    pub operation: String,
    pub kind: OperationKind,
    /// The friendly machine name this operation is about.
    pub machine: String,
    /// The target's overlay IPv4, as text. `None` for a `setup` that has to detect it.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub ssh_user: Option<String>,
    #[serde(default)]
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub identity: IdentityChoice,
    /// Tailscale `PublicKey` for the selected address, when discovery named one.
    #[serde(default)]
    pub peer_id: Option<String>,
    /// Tailscale `ID`, recorded beside [`Self::peer_id`].
    #[serde(default)]
    pub stable_id: Option<String>,
    /// Where `ouro` lives on the target, relative to its `$HOME` unless absolute.
    #[serde(default)]
    pub install_path: Option<String>,
    /// The target's `OUROBOROS_DATA_DIR`, when the operator named one.
    #[serde(default)]
    pub remote_data_dir: Option<String>,
    /// Propose a managed user service rather than manual startup.
    #[serde(default = "yes")]
    pub service: bool,
    /// Inspect and print; write nothing anywhere.
    #[serde(default)]
    pub dry_run: bool,
    /// Accept a resolved plan without a review prompt. Never accepts an unknown or
    /// changed host key, and never a busy runtime.
    #[serde(default)]
    pub assume_yes: bool,
    /// Test-only port policy for the target's profile. `None` is the production policy.
    #[serde(default)]
    pub ports: Option<PortPolicy>,
}

fn yes() -> bool {
    true
}

/// How an identity choice is named in a refusal. Never the secret, and never a path
/// this process did not already have on its own argv.
fn describe_identity(identity: &IdentityChoice) -> String {
    match identity {
        IdentityChoice::Default => "this host's default SSH identities".to_string(),
        IdentityChoice::Agent { fingerprint } => {
            format!("agent identity {}", sanitize_remote_text(fingerprint, 80))
        }
        IdentityChoice::Key { path } => format!("key {}", path.display()),
        IdentityChoice::Password => "the target account's password".to_string(),
    }
}

/// The two ports [`crate::fleet::Ports`] carries, in a form that survives JSON.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortPolicy {
    #[serde(default)]
    pub gateway: Option<u16>,
    #[serde(default)]
    pub dist: Option<u16>,
}

impl From<PortPolicy> for crate::fleet::Ports {
    fn from(policy: PortPolicy) -> Self {
        Self {
            gateway: policy.gateway,
            dist: policy.dist,
        }
    }
}

impl OperationRequest {
    pub fn new(
        operation: impl Into<String>,
        kind: OperationKind,
        machine: impl Into<String>,
    ) -> Self {
        Self {
            schema: SCHEMA,
            operation: operation.into(),
            kind,
            machine: machine.into(),
            address: None,
            ssh_user: None,
            ssh_port: None,
            identity: IdentityChoice::Default,
            peer_id: None,
            stable_id: None,
            install_path: None,
            remote_data_dir: None,
            service: true,
            dry_run: false,
            assume_yes: false,
            ports: None,
        }
    }

    pub fn ports(&self) -> crate::fleet::Ports {
        self.ports
            .map(Into::into)
            .unwrap_or(crate::fleet::Ports::DEFAULT)
    }

    /// Fill in what argv left out from an existing journal, for `--operation ID`.
    ///
    /// §6's resume is "a step recorded `ok` is not repeated", and the journal already
    /// holds that. What it also holds is who the target was, which identity was used and
    /// whether a managed service was asked for — so an operator resuming an operation
    /// does not have to retype any of it, and the broker can rebuild a resume's argv
    /// from the document rather than guessing. Argv that *contradicts* the journal is a
    /// refusal: a resumed operation is the same operation, or it is a new one.
    ///
    /// Two reasons, because they are two different mistakes. `plan_changed` is a
    /// different deployment wearing this id — another address, account or port.
    /// `resume_mismatch` is this deployment, resumed with a different *how*: another
    /// key, another agent identity, a password where a key was used, or a startup
    /// choice the first run did not make. Neither is silently applied.
    pub fn hydrate(&mut self, record: &journal::Record) -> Result<()> {
        let default_target = journal::TargetIdentity::default();
        let target = record.target.as_ref().unwrap_or(&default_target);
        let paths = &record.paths;
        fn agree<T: PartialEq + std::fmt::Debug>(
            field: &'static str,
            mine: &mut Option<T>,
            recorded: Option<T>,
        ) -> Result<()> {
            match (mine.as_ref(), recorded) {
                (Some(mine), Some(recorded)) if *mine != recorded => refuse(
                    "plan_changed",
                    format!("this operation was recorded against a different {field}; start a new operation to deploy different intent"),
                ),
                (None, recorded) => {
                    *mine = recorded;
                    Ok(())
                }
                _ => Ok(()),
            }
        }

        if !target.machine.is_empty() && !self.machine.is_empty() && target.machine != self.machine
        {
            return refuse(
                "plan_changed",
                format!(
                    "operation {} is recorded against machine {}, not {}",
                    self.operation, target.machine, self.machine
                ),
            );
        }
        if self.machine.is_empty() {
            self.machine = target.machine.clone();
        }
        agree("address", &mut self.address, target.address.clone())?;
        agree("account", &mut self.ssh_user, target.ssh_user.clone())?;
        agree("port", &mut self.ssh_port, target.port)?;
        if self.install_path.is_none() {
            self.install_path = paths.install_path.clone();
        }
        if self.remote_data_dir.is_none() {
            self.remote_data_dir = paths.data_dir.clone();
        }
        // `IdentityChoice::Default` is what argv that named no `--key`, `--agent` or
        // `--ask-password` produces, so it is exactly the "argv left this out" case: the
        // journal's choice applies. Anything else was typed, and a typed choice that
        // disagrees with the recorded one is refused rather than quietly switched — a
        // resume that authenticated differently from the run it is resuming is a
        // different act, whatever it goes on to do.
        match (&self.identity, target.identity.clone()) {
            (IdentityChoice::Default, Some(recorded)) => self.identity = recorded,
            (mine, Some(recorded)) if *mine != recorded => {
                return refuse(
                    "resume_mismatch",
                    format!(
                        "operation {} was started with {}, and this resume names {}. Resume it the way it was started, or start a new operation",
                        self.operation,
                        describe_identity(&recorded),
                        describe_identity(mine),
                    ),
                )
            }
            _ => {}
        }

        // The same rule for the startup choice. `--no-service` is the only way to state
        // one, so `service == true` is "argv said nothing" and the journal applies;
        // `service == false` was typed, and a journal that says otherwise is refused.
        match record.service {
            Some(recorded) if self.service && !recorded => self.service = recorded,
            Some(recorded) if self.service != recorded => {
                return refuse(
                    "resume_mismatch",
                    format!(
                        "operation {} was started with a managed startup service, and this resume names `--no-service`. Resume it the way it was started, or start a new operation",
                        self.operation
                    ),
                )
            }
            _ => {}
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ the conversation

/// A question the engine needs answered, before it has an id or an expiry.
///
/// The engine builds the *kind* and the secret-free *metadata*; whoever is listening
/// decides what a challenge id, a lifetime and a session binding mean for them. That
/// split is what lets the CLI and the worker run the same engine: a terminal renders
/// this and reads a line, and a worker issues it into
/// [`challenge::Registry`](crate::fleet_setup::challenge::Registry) and waits for a
/// bound, single-use `respond` frame.
pub struct ChallengeRequest {
    pub kind: challenge::ChallengeKind,
    pub metadata: Value,
}

/// Progress, for whoever is watching. Never carries a secret.
#[derive(Clone, Debug)]
pub enum Event {
    State(OperationState),
    Step {
        machine: String,
        step: String,
        outcome: String,
        detail: Option<String>,
    },
    Log(String),
}

/// The engine's one channel to a person.
///
/// `Send + Sync` because the askpass bridge asks from its own accept thread while the
/// engine thread is blocked inside `ssh`.
///
/// A password or passphrase asked with [`Self::ask_from`] is tagged with that
/// `issuer` — one armed `ssh` child — and [`Self::withdraw`] unblocks it. Issuer `0`
/// is the engine thread (host trust, review) and is never withdrawn, so a lost
/// connection cannot cancel a plan the operator is mid-reading.
pub trait Conversation: Send + Sync {
    fn ask(&self, request: ChallengeRequest) -> Result<challenge::Answer>;
    /// Ask on behalf of one armed `ssh` child. The default delegates to [`Self::ask`],
    /// which is enough for a conversation that answers immediately (scripted tests,
    /// `--yes` reviews). A conversation that blocks — the worker's registry, a
    /// terminal secret read — overrides this so [`Self::withdraw`] can unblock it.
    fn ask_from(&self, _issuer: u64, request: ChallengeRequest) -> Result<challenge::Answer> {
        self.ask(request)
    }
    /// Withdraw every still-pending challenge this issuer asked. The default is a
    /// no-op: conversations that do not block have nothing to wake. First reason
    /// wins; issuer `0` is ignored.
    fn withdraw(&self, _issuer: u64, _reason: &'static str) {}
    fn notify(&self, event: Event);
    /// Whether the operator has asked the operation to stop. Checked at step
    /// boundaries, so cancellation lands somewhere durable rather than mid-write.
    fn cancelled(&self) -> bool {
        false
    }
}

// ------------------------------------------------------------------ paths

pub fn deploy_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(DEPLOY_DIR)
}

pub fn journal_path(data_dir: &Path, operation: &str) -> PathBuf {
    deploy_dir(data_dir).join(format!("{operation}.json"))
}

pub fn log_path(data_dir: &Path, operation: &str) -> PathBuf {
    deploy_dir(data_dir).join(format!("{operation}.log"))
}

/// The operation's own private scratch: the askpass socket, a selected agent identity's
/// public key, a staged release artifact. Removed when the operation ends.
pub fn scratch_dir(data_dir: &Path, operation: &str) -> PathBuf {
    deploy_dir(data_dir).join(format!("{operation}.d"))
}

pub fn known_hosts_path(data_dir: &Path) -> PathBuf {
    deploy_dir(data_dir).join(KNOWN_HOSTS_FILE)
}

/// Create `<data dir>/deploy/` at 0700 when it is missing, and refuse it when it is not
/// private.
///
/// A deployment host without a fleet yet still needs somewhere durable to journal the
/// `setup` that is about to create one, so this deliberately does not require a profile
/// — and deliberately does not touch `<data dir>/fleet/`, which `fleet::create` commits
/// by renaming a staging directory into place.
pub fn ensure_deploy_dir(data_dir: &Path) -> Result<PathBuf> {
    crate::runtime::ensure_private_data_dir(data_dir)?;
    let deploy = deploy_dir(data_dir);
    ensure_private_subdir(&deploy)?;
    Ok(deploy)
}

/// [`ensure_private_subdir`], for the hardening suite: what protects the bridge's own
/// directory is that a foreign or loose one is refused rather than adopted, and that is
/// worth a test of its own.
#[doc(hidden)]
pub fn ensure_private_subdir_for_tests(path: &Path) -> Result<()> {
    ensure_private_subdir(path)
}

pub(crate) fn ensure_private_subdir(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let uid = unsafe { libc::geteuid() };
            if !metadata.file_type().is_dir() {
                bail!("{} must be a directory", path.display());
            }
            if std::os::unix::fs::MetadataExt::uid(&metadata) != uid {
                bail!("{} must be owned by uid {uid}; it is not", path.display());
            }
            if std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o077 != 0 {
                bail!("{} must be a private directory (mode 0700)", path.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match DirBuilder::new().mode(0o700).recursive(false).create(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Created by a racing caller: re-check owner and mode rather than
                    // adopting a directory we did not just make.
                    ensure_private_subdir(path)
                }
                Err(error) => Err(error)
                    .with_context(|| format!("creating private directory {}", path.display())),
            }
        }
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

// ------------------------------------------------------------------ small shared helpers

/// An operation id names files in a shared directory, so it is checked before it is
/// used as one. Identical rules to [`crate::fleet`]'s, because the two halves of an
/// operation have to agree on what its id is.
pub fn validate_operation_id(operation: &str) -> Result<()> {
    let shaped = (8..=64).contains(&operation.len())
        && operation
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !operation.starts_with('-')
        && !operation.ends_with('-')
        && !operation.contains("--");
    if !shaped {
        return refuse(
            "invalid_request",
            format!(
                "`{operation}` is not an operation id: 8 to 64 characters of lowercase letters, digits and single hyphens, not starting or ending with one"
            ),
        );
    }
    Ok(())
}

/// A fresh operation id: `op-` and twelve hex characters, which fits the shape above.
pub fn new_operation_id() -> Result<String> {
    Ok(format!("op-{}", random_hex(6)?))
}

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0_u8; bytes];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|error| anyhow!("cannot read OS randomness: {error}"))?;
    let mut encoded = String::with_capacity(bytes * 2);
    for byte in random {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    Ok(encoded)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut text = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

/// Constant-time equality for a value compared against attacker-supplied input.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

pub fn utc_timestamp() -> Result<String> {
    utc_timestamp_at(SystemTime::now())
}

pub fn utc_timestamp_at(at: SystemTime) -> Result<String> {
    let seconds: libc::time_t = at
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_secs()
        .try_into()
        .context("the current time does not fit the platform clock")?;
    // SAFETY: both pointers name initialized storage for the duration of the call;
    // `gmtime_r` writes only the supplied `tm` and keeps no shared static result.
    let mut calendar: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut calendar) }.is_null() {
        bail!("the operating system could not convert the current UTC time");
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        calendar.tm_year + 1900,
        calendar.tm_mon + 1,
        calendar.tm_mday,
        calendar.tm_hour,
        calendar.tm_min,
        calendar.tm_sec
    ))
}

/// Private, atomic, 0600. The journal is rewritten before and after every step, so this
/// is the one write primitive the module uses for durable state.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("deploy-file");
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        random_hex(6)?
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .with_context(|| format!("creating {}", temporary.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("writing {}", path.display()));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("publishing {}", path.display()));
    }
    Ok(())
}

/// The canonical JSON a digest is taken over: object keys sorted, no whitespace.
///
/// Seam S6 binds an approval to `sha256(canonical(plan))`, so two encoders that disagree
/// about key order would turn an unchanged plan into `plan_changed`. Serde's map
/// ordering already follows struct field order, but a plan travels through `serde_json`
/// on the broker's side too; sorting here makes the digest a property of the *values*.
pub fn canonical_json(value: &Value) -> String {
    let mut text = String::new();
    write_canonical(value, &mut text);
    text
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(fields) => {
            let mut sorted: Vec<(&String, &Value)> = fields.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(right.0));
            out.push('{');
            for (index, (key, field)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(field, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// Text that came from somewhere this process does not control — a remote helper's
/// `detail`, an `ssh` stderr line, a network client's ping output — on its way to a
/// person, a log or a durable file.
///
/// Three rules, all of them from the proposal's treatment of remote output as data:
/// control characters cannot reposition a terminal cursor or forge a line, the whole
/// thing is capped so one runaway process cannot own the screen, and a URL is redacted
/// because a remote must never be able to put a link in front of an operator who is in
/// the middle of authenticating to it.
pub fn sanitize_remote_text(text: &str, limit: usize) -> String {
    let mut cleaned = String::with_capacity(text.len().min(limit + 8));
    for word in text.split_whitespace() {
        if !cleaned.is_empty() {
            cleaned.push(' ');
        }
        if looks_like_url(word) {
            cleaned.push_str("<redacted url>");
        } else {
            cleaned.extend(word.chars().filter(|character| !character.is_control()));
        }
    }
    if cleaned.chars().count() <= limit {
        return cleaned;
    }
    let mut short: String = cleaned.chars().take(limit).collect();
    short.push('…');
    short
}

fn looks_like_url(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    [
        "http://", "https://", "ftp://", "ws://", "wss://", "file://",
    ]
    .iter()
    .any(|scheme| lowered.contains(scheme))
}

/// Merge `fields` into a reply envelope. Shared by the worker and the helper client so
/// one frame shape exists in this module.
pub fn envelope(id: &Value, ok: bool, fields: Value) -> Value {
    let mut reply = Map::new();
    reply.insert("v".to_string(), Value::from(1));
    reply.insert("id".to_string(), id.clone());
    reply.insert("ok".to_string(), Value::Bool(ok));
    if let Value::Object(fields) = fields {
        for (key, value) in fields {
            reply.insert(key, value);
        }
    }
    Value::Object(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An operation id names files in a shared directory, so nothing that could be a
    /// path survives the check.
    #[test]
    fn an_operation_id_cannot_name_a_path() {
        assert!(validate_operation_id("op-0123456789ab").is_ok());
        for hostile in [
            "../../etc/passwd",
            "op/../../x",
            "OP-0123456789AB",
            "short",
            "op--0123456789",
            "-op-0123456789",
            &"o".repeat(65),
        ] {
            assert!(
                validate_operation_id(hostile).is_err(),
                "{hostile} must be refused"
            );
        }
        let generated = new_operation_id().expect("an id");
        assert!(validate_operation_id(&generated).is_ok(), "{generated}");
    }

    /// Remote text is data on its way to a terminal, a log and a durable file.
    #[test]
    fn remote_text_loses_control_characters_urls_and_length() {
        assert_eq!(
            sanitize_remote_text("hello\u{1b}[2Jworld", 40),
            "hello[2Jworld"
        );
        assert_eq!(
            sanitize_remote_text("go to https://evil.example now", 60),
            "go to <redacted url> now"
        );
        let long = sanitize_remote_text(&"x".repeat(100), 10);
        assert_eq!(long.chars().count(), 11, "ten characters plus the marker");
        assert!(long.ends_with('…'));
    }

    /// A journal record shaped like one an interrupted `add` leaves behind.
    fn resumable(service: Option<bool>, identity: Option<IdentityChoice>) -> journal::Record {
        journal::Record {
            schema: SCHEMA,
            operation: "op-0123456789ab".into(),
            kind: OperationKind::Add,
            state: OperationState::Interrupted,
            created_at: "2026-09-19T00:00:00Z".into(),
            updated_at: "2026-09-19T00:00:00Z".into(),
            target: Some(journal::TargetIdentity {
                machine: "buildbox".into(),
                address: Some("100.64.0.2".into()),
                ssh_user: Some("me".into()),
                port: Some(2222),
                identity,
                ..journal::TargetIdentity::default()
            }),
            service,
            release: None,
            paths: journal::IntendedPaths {
                install_path: Some("/home/me/.local/bin/ouro".into()),
                data_dir: None,
            },
            plan: Vec::new(),
            steps: Vec::new(),
            residue: Vec::new(),
            last_error: None,
        }
    }

    /// §6: a resumed operation is the same operation, or it is a new one.
    #[test]
    fn hydrating_a_request_fills_gaps_and_refuses_contradictions() {
        let record = resumable(None, None);

        let mut request = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        request.hydrate(&record).expect("a clean resume");
        assert_eq!(request.address.as_deref(), Some("100.64.0.2"));
        assert_eq!(request.ssh_user.as_deref(), Some("me"));
        assert_eq!(request.ssh_port, Some(2222));
        assert_eq!(
            request.install_path.as_deref(),
            Some("/home/me/.local/bin/ouro")
        );

        let mut moved = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        moved.address = Some("100.64.0.9".into());
        let error = moved.hydrate(&record).expect_err("a moved target");
        assert_eq!(reason_of(&error), Some("plan_changed"));

        let mut renamed = OperationRequest::new("op-0123456789ab", OperationKind::Add, "vps");
        let error = renamed.hydrate(&record).expect_err("another machine");
        assert_eq!(reason_of(&error), Some("plan_changed"));
    }

    /// The *how* of a resume: the identity it authenticated with, and the startup
    /// choice it was started with. Omitted on argv, the journal's applies; stated and
    /// different, it is `resume_mismatch` rather than a silent switch.
    #[test]
    fn a_resume_keeps_the_identity_and_startup_choice_it_was_started_with() {
        let key = IdentityChoice::Key {
            path: PathBuf::from("/home/me/.ssh/rig"),
        };
        let record = resumable(Some(false), Some(key.clone()));

        // Argv that names neither takes both from the journal.
        let mut quiet = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        assert!(quiet.service, "argv that omits --no-service means `true`");
        quiet.hydrate(&record).expect("a clean resume");
        assert_eq!(quiet.identity, key);
        assert!(!quiet.service, "the journal's choice applies");

        // Argv that names the same things agrees.
        let mut same = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        same.identity = key.clone();
        same.service = false;
        same.hydrate(&record).expect("an agreeing resume");
        assert_eq!(same.identity, key);

        // A different identity is refused, and the refusal names neither secret nor
        // anything this process did not already have on its own argv.
        let mut switched = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        switched.identity = IdentityChoice::Password;
        let error = switched.hydrate(&record).expect_err("a switched identity");
        assert_eq!(reason_of(&error), Some("resume_mismatch"));
        assert!(format!("{error:#}").contains("password"), "{error:#}");

        // And a startup choice the first run did not make.
        let managed = resumable(Some(true), Some(key.clone()));
        let mut manual = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        manual.service = false;
        let error = manual.hydrate(&managed).expect_err("a switched startup");
        assert_eq!(reason_of(&error), Some("resume_mismatch"));

        // A journal from a build that predates the field decides nothing.
        let older = resumable(None, Some(key.clone()));
        let mut manual = OperationRequest::new("op-0123456789ab", OperationKind::Add, "buildbox");
        manual.service = false;
        manual.hydrate(&older).expect("an older journal");
        assert!(
            !manual.service,
            "argv still decides when the journal did not"
        );
    }

    /// §6 deleted the plan digest, but the canonical encoder is still how two sides
    /// agree about a document's values rather than its key order.
    #[test]
    fn canonical_json_sorts_keys_and_keeps_arrays_in_order() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": [3, 2]})),
            r#"{"a":[3,2],"b":1}"#
        );
    }

    /// A refusal carries a stable reason through `anyhow`.
    #[test]
    fn a_refusal_keeps_its_reason() {
        let error = refuse::<()>("invalid_request", "nope").expect_err("a refusal");
        assert_eq!(reason_of(&error), Some("invalid_request"));
        let wrapped = refusing("plan_changed", anyhow!("something moved"));
        assert_eq!(reason_of(&wrapped), Some("plan_changed"));
        assert!(format!("{wrapped:#}").contains("something moved"));
        // And a fleet-library refusal keeps its own.
        let fleet = crate::fleet::refusal(&anyhow::Error::new(crate::fleet::Refusal {
            reason: "fleet_present",
            detail: "already there".into(),
        }))
        .map(|declared| declared.reason);
        assert_eq!(fleet, Some("fleet_present"));
    }
}
