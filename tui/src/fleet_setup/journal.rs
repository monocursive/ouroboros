//! The operation journal: the durable authority for what has already happened.
//!
//! `<data dir>/deploy/<id>.json`, mode 0600, schema 2 (§6), rewritten atomically
//! *before* and *after* every externally visible step. Before, so a process that dies
//! mid-step leaves behind the statement "this was attempted"; after, so a resume knows
//! not to repeat it. Joining is not a distributed transaction: once a bundle has been
//! delivered, no deletion can prove it was not copied, so the journal's job is to say
//! exactly what was done rather than to promise a rollback.
//!
//! Nothing here is a secret. The release carries a version and a sha256 — never bytes.
//! The plan is the lines an operator read. The last error is a stable reason plus the
//! sanitized `detail` of a refusal, not a `Debug` dump of an error chain that might have
//! quoted a prompt.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    ensure_deploy_dir, journal_path, utc_timestamp, utc_timestamp_at, write_private_atomic,
    IdentityChoice, OperationKind, OperationState, SCHEMA,
};

/// Who the operation is against, as far as it has been established.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetIdentity {
    pub machine: String,
    /// Tailscale `PublicKey` (`nodekey:…`) for this address, when discovery could
    /// name one. `None` for a manual private-network address that has no node key.
    #[serde(default)]
    pub peer_id: Option<String>,
    /// Tailscale `ID`, recorded beside [`Self::peer_id`] when discovery named it.
    #[serde(default)]
    pub stable_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ssh_user: Option<String>,
    /// How this operation authenticated to the target. Folded here from the request
    /// so `completed`/`cancelled` operations can drop the request file.
    #[serde(default)]
    pub identity: Option<IdentityChoice>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    /// The node name the target will answer to, once one is known.
    #[serde(default)]
    pub node: Option<String>,
    /// The SHA256 fingerprint of the host key this operation trusted.
    #[serde(default)]
    pub host_fingerprint: Option<String>,
}

/// The exact artifact a missing-binary install selected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedRelease {
    pub version: String,
    pub asset: String,
    pub sha256: String,
}

/// Why the operation stopped, for something that branches on it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LastError {
    pub reason: String,
    pub detail: String,
}

/// Where the operation intends to put things on the target.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntendedPaths {
    #[serde(default)]
    pub install_path: Option<String>,
    #[serde(default)]
    pub data_dir: Option<String>,
}

/// One externally visible step.
///
/// §6's shape is `{"step","state","at","detail"}`. `machine` is additive and stays
/// because every surface that renders a step says which machine it was about, and an
/// operation now touches exactly one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepRecord {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub machine: String,
    pub step: String,
    /// `attempted`, `ok`, `skipped` or `failed`.
    #[serde(rename = "state")]
    pub outcome: String,
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// The whole durable record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u8,
    pub operation: String,
    pub kind: OperationKind,
    pub state: OperationState,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub target: Option<TargetIdentity>,
    /// The `--no-service` choice, written at operation start beside the target's
    /// identity: `true` is a managed user service, `false` is manual startup.
    ///
    /// It lives here rather than being inferred from a `service` step, because a
    /// resume has to know what was chosen *before* it reaches that step — and because
    /// the broker rebuilds a resume's argv from this document and must not have to
    /// guess. `None` on a `leave`, which has no such flag, and on a journal written by
    /// a build that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<bool>,
    #[serde(default)]
    pub release: Option<SelectedRelease>,
    #[serde(default)]
    pub paths: IntendedPaths,
    /// The plan lines an operator reviewed, in order. §6 replaced the plan document and
    /// its digest with the text a person actually read.
    #[serde(default)]
    pub plan: Vec<String>,
    #[serde(default)]
    pub steps: Vec<StepRecord>,
    /// What an interrupted or cancelled operation left behind that it could not clean
    /// up. Named, never guessed at.
    #[serde(default)]
    pub residue: Vec<String>,
    #[serde(default)]
    pub last_error: Option<LastError>,
}

impl Record {
    /// Whether this machine already completed a step, by name. The resume predicate.
    pub fn completed(&self, machine: &str, step: &str) -> bool {
        self.steps
            .iter()
            .any(|entry| entry.machine == machine && entry.step == step && entry.outcome == "ok")
    }

    /// Whether a step was attempted and never finished — the boundary a crash lands on.
    pub fn attempted(&self, machine: &str, step: &str) -> bool {
        self.steps
            .iter()
            .any(|entry| entry.machine == machine && entry.step == step)
    }

    /// Whether this operation has already been reviewed and approved.
    pub fn reviewed(&self) -> bool {
        !self.plan.is_empty()
    }

    pub fn last_step(&self) -> Option<&StepRecord> {
        self.steps.last()
    }
}

/// A journal open for writing, with the record it holds.
pub struct Journal {
    path: PathBuf,
    record: Record,
}

impl Journal {
    /// Open the operation's journal, creating it when this is the first sight of it.
    ///
    /// A journal whose `kind` disagrees with the one asked for is a different operation
    /// wearing the same id, which is refused rather than adopted.
    pub fn open(data_dir: &Path, operation: &str, kind: OperationKind) -> Result<Self> {
        super::validate_operation_id(operation)?;
        ensure_deploy_dir(data_dir)?;
        let path = journal_path(data_dir, operation);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let record: Record = serde_json::from_str(&text).with_context(|| {
                    format!("decoding the operation journal {}", path.display())
                })?;
                if record.kind != kind {
                    return super::refuse(
                        "operation_in_progress",
                        format!(
                            "operation {operation} is already a `{}` on this machine, not a `{}`",
                            record.kind.as_str(),
                            kind.as_str()
                        ),
                    );
                }
                Ok(Self { path, record })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let now = utc_timestamp()?;
                let record = Record {
                    schema: SCHEMA,
                    operation: operation.to_string(),
                    kind,
                    state: OperationState::Inspecting,
                    created_at: now.clone(),
                    updated_at: now,
                    target: None,
                    service: None,
                    release: None,
                    paths: IntendedPaths::default(),
                    plan: Vec::new(),
                    steps: Vec::new(),
                    residue: Vec::new(),
                    last_error: None,
                };
                let mut journal = Self { path, record };
                journal.flush()?;
                Ok(journal)
            }
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Read a journal without opening it for writing. The broker uses this, and only
    /// when no worker is alive (seam S5).
    pub fn read(data_dir: &Path, operation: &str) -> Result<Option<Record>> {
        super::validate_operation_id(operation)?;
        let path = journal_path(data_dir, operation);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(serde_json::from_str(&text).with_context(|| {
                format!("decoding the operation journal {}", path.display())
            })?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Every operation this data directory has a journal for, newest id last.
    pub fn list(data_dir: &Path) -> Result<Vec<String>> {
        let dir = super::deploy_dir(data_dir);
        let mut operations = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(operations),
            Err(error) => return Err(error).with_context(|| format!("reading {}", dir.display())),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(operation) = name.strip_suffix(".json") else {
                continue;
            };
            if super::validate_operation_id(operation).is_ok() {
                operations.push(operation.to_string());
            }
        }
        operations.sort();
        Ok(operations)
    }

    /// Drop durable files for `completed`/`cancelled` operations that are both older
    /// than `older_than` and outside the newest `keep_newest`. Failed, interrupted and
    /// in-flight work is left alone, as is anything whose `worker.lock` is currently held.
    pub fn prune_terminal(
        data_dir: &Path,
        keep_newest: usize,
        older_than: std::time::Duration,
    ) -> Result<usize> {
        let cutoff = match std::time::SystemTime::now().checked_sub(older_than) {
            Some(at) => utc_timestamp_at(at)?,
            None => return Ok(0),
        };
        let mut candidates = Vec::new();
        for operation in Self::list(data_dir)? {
            if super::lock::Lock::held(data_dir, &format!("{operation}.lock")) {
                continue;
            }
            let Some(record) = Self::read(data_dir, &operation)? else {
                continue;
            };
            if !matches!(
                record.state,
                OperationState::Completed | OperationState::Cancelled
            ) {
                continue;
            }
            candidates.push((record.updated_at, record.created_at, operation));
        }
        candidates.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then(right.1.cmp(&left.1))
                .then(right.2.cmp(&left.2))
        });
        let mut removed = 0;
        for (updated_at, _, operation) in candidates.into_iter().skip(keep_newest) {
            if updated_at >= cutoff {
                continue;
            }
            remove_operation_files(data_dir, &operation)?;
            removed += 1;
        }
        Ok(removed)
    }

    pub fn record(&self) -> &Record {
        &self.record
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn state(&self) -> OperationState {
        self.record.state
    }

    /// Move to a state and persist it. Called before the work of that state begins.
    pub fn set_state(&mut self, state: OperationState) -> Result<()> {
        self.record.state = state;
        self.flush()
    }

    pub fn set_target(&mut self, target: TargetIdentity) -> Result<()> {
        self.record.target = Some(target);
        self.flush()
    }

    /// Record the startup choice this operation was started with. Idempotent: a resume
    /// that agrees writes the same value, and one that disagrees was refused before it
    /// reached here.
    pub fn set_service(&mut self, service: bool) -> Result<()> {
        if self.record.service == Some(service) {
            return Ok(());
        }
        self.record.service = Some(service);
        self.flush()
    }

    pub fn set_release(&mut self, release: SelectedRelease) -> Result<()> {
        self.record.release = Some(release);
        self.flush()
    }

    pub fn set_paths(&mut self, paths: IntendedPaths) -> Result<()> {
        self.record.paths = paths;
        self.flush()
    }

    /// Record the plan lines an operator approved.
    pub fn set_plan(&mut self, lines: Vec<String>) -> Result<()> {
        self.record.plan = lines;
        self.flush()
    }

    /// Write the "about to happen" half of a step.
    pub fn begin_step(&mut self, machine: &str, step: &str) -> Result<()> {
        self.finish_step(machine, step, "attempted", None, None)
    }

    /// Write the outcome half.
    ///
    /// One machine's one step appears once, carrying its latest outcome. A resumed
    /// operation that re-verifies an idempotent step (`prepare` re-reads the key it
    /// already staged) must not leave a journal that reads as if the step happened
    /// twice — the journal is what an operator and a broker use to decide what is still
    /// outstanding.
    pub fn finish_step(
        &mut self,
        machine: &str,
        step: &str,
        outcome: &str,
        detail: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<()> {
        self.record
            .steps
            .retain(|entry| !(entry.machine == machine && entry.step == step));
        self.push(machine, step, outcome, detail, fingerprint)
    }

    /// A step this operation deliberately did not perform, and why.
    pub fn skip_step(
        &mut self,
        machine: &str,
        step: &str,
        detail: impl Into<String>,
    ) -> Result<()> {
        self.finish_step(machine, step, "skipped", Some(detail.into()), None)
    }

    fn push(
        &mut self,
        machine: &str,
        step: &str,
        outcome: &str,
        detail: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<()> {
        self.record.steps.push(StepRecord {
            machine: machine.to_string(),
            step: step.to_string(),
            outcome: outcome.to_string(),
            at: utc_timestamp()?,
            detail: detail.map(|text| bounded(&text)),
            fingerprint,
        });
        self.flush()
    }

    /// Name something the operation left behind. The proposal requires cancellation to
    /// report residue rather than claim a clean undo.
    pub fn note_residue(&mut self, note: impl Into<String>) -> Result<()> {
        let note = bounded(&note.into());
        if !self.record.residue.contains(&note) {
            self.record.residue.push(note);
        }
        self.flush()
    }

    /// The sanitized reason the operation stopped. Never a `Debug` rendering.
    pub fn fail(
        &mut self,
        state: OperationState,
        reason: &str,
        detail: impl Into<String>,
    ) -> Result<()> {
        let detail = bounded(&detail.into());
        for step in &mut self.record.steps {
            if step.outcome == "attempted" {
                step.outcome = "failed".into();
                step.detail = Some(detail.clone());
            }
        }
        self.record.last_error = Some(LastError {
            reason: reason.to_string(),
            detail,
        });
        self.record.state = state;
        self.flush()
    }

    pub fn clear_error(&mut self) -> Result<()> {
        if self.record.last_error.is_some() {
            self.record.last_error = None;
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.record.updated_at = utc_timestamp()?;
        let bytes =
            serde_json::to_vec_pretty(&self.record).context("encoding the operation journal")?;
        write_private_atomic(&self.path, &bytes)
    }
}

/// A journal two threads write.
///
/// The engine thread writes steps; the worker's socket thread writes the operation's
/// owner and any takeover. One mutex rather than two readers of one file: a
/// read-modify-write from a second process would lose whichever update landed first.
#[derive(Clone)]
pub struct Handle(std::sync::Arc<std::sync::Mutex<Journal>>);

impl Handle {
    pub fn new(journal: Journal) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(journal)))
    }

    fn with<T>(&self, act: impl FnOnce(&mut Journal) -> T) -> T {
        let mut journal = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        act(&mut journal)
    }

    pub fn reload(&self, data_dir: &Path, operation: &str, kind: OperationKind) -> Result<()> {
        self.with(|journal| {
            *journal = Journal::open(data_dir, operation, kind)?;
            Ok(())
        })
    }

    /// A snapshot. Owned on purpose: a caller holding a borrow across a step would hold
    /// the lock across an SSH round trip.
    pub fn record(&self) -> Record {
        self.with(|journal| journal.record().clone())
    }

    pub fn state(&self) -> OperationState {
        self.with(|journal| journal.state())
    }

    pub fn set_state(&self, state: OperationState) -> Result<()> {
        self.with(|journal| journal.set_state(state))
    }

    pub fn set_target(&self, target: TargetIdentity) -> Result<()> {
        self.with(|journal| journal.set_target(target))
    }

    pub fn set_service(&self, service: bool) -> Result<()> {
        self.with(|journal| journal.set_service(service))
    }

    pub fn set_release(&self, release: SelectedRelease) -> Result<()> {
        self.with(|journal| journal.set_release(release))
    }

    pub fn set_paths(&self, paths: IntendedPaths) -> Result<()> {
        self.with(|journal| journal.set_paths(paths))
    }

    pub fn set_plan(&self, lines: Vec<String>) -> Result<()> {
        self.with(|journal| journal.set_plan(lines))
    }

    pub fn begin_step(&self, machine: &str, step: &str) -> Result<()> {
        self.with(|journal| journal.begin_step(machine, step))
    }

    pub fn finish_step(
        &self,
        machine: &str,
        step: &str,
        outcome: &str,
        detail: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<()> {
        self.with(|journal| journal.finish_step(machine, step, outcome, detail, fingerprint))
    }

    pub fn skip_step(&self, machine: &str, step: &str, detail: impl Into<String>) -> Result<()> {
        let detail = detail.into();
        self.with(|journal| journal.skip_step(machine, step, detail))
    }

    pub fn note_residue(&self, note: impl Into<String>) -> Result<()> {
        let note = note.into();
        self.with(|journal| journal.note_residue(note))
    }

    pub fn fail(
        &self,
        state: OperationState,
        reason: &'static str,
        detail: impl Into<String>,
    ) -> Result<()> {
        let detail = detail.into();
        self.with(|journal| journal.fail(state, reason, detail))
    }

    pub fn clear_error(&self) -> Result<()> {
        self.with(|journal| journal.clear_error())
    }
}

fn remove_operation_files(data_dir: &Path, operation: &str) -> Result<()> {
    for path in [
        super::journal_path(data_dir, operation),
        super::log_path(data_dir, operation),
        super::deploy_dir(data_dir).join(format!("{operation}.lock")),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("removing {}", path.display()))
            }
        }
    }
    let scratch = super::scratch_dir(data_dir, operation);
    match std::fs::remove_dir_all(&scratch) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("removing {}", scratch.display())),
    }
    Ok(())
}

/// Free text out of a subprocess or an error chain, on its way into a durable file.
///
/// The same sanitizer the human path uses: a journal is read by people and by a broker,
/// and neither wants a megabyte of remote stderr, a cursor escape, or a link a remote
/// machine chose.
fn bounded(text: &str) -> String {
    const LIMIT: usize = 400;
    super::sanitize_remote_text(text, LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQUENCE: AtomicU32 = AtomicU32::new(0);

    fn scratch(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ouro-journal-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("a private scratch directory");
        path
    }

    /// The before/after pair is the whole recovery contract: a crash between them
    /// leaves `started`, and the resume sees it.
    #[test]
    fn a_step_is_durable_before_it_happens_and_after_it_happens() {
        let data = scratch("steps");
        let mut journal =
            Journal::open(&data, "op-0000000000a1", OperationKind::Add).expect("a new journal");

        journal.begin_step("buildbox", "install").expect("begin");
        let mid = Journal::read(&data, "op-0000000000a1")
            .expect("a readable journal")
            .expect("a present journal");
        assert!(mid.attempted("buildbox", "install"));
        assert!(
            !mid.completed("buildbox", "install"),
            "a started step is not a completed step"
        );

        journal
            .finish_step("buildbox", "install", "ok", Some("installed".into()), None)
            .expect("finish");
        // A step re-verified on a resume still appears once, with its latest outcome.
        journal
            .finish_step("buildbox", "install", "ok", Some("verified".into()), None)
            .expect("a repeated verification");
        let after = Journal::read(&data, "op-0000000000a1")
            .expect("a readable journal")
            .expect("a present journal");
        assert!(after.completed("buildbox", "install"));
        assert_eq!(
            after
                .steps
                .iter()
                .filter(|entry| entry.step == "install")
                .count(),
            1,
            "the outcome replaces the attempt rather than stacking beside it"
        );
    }

    /// Private and atomic: the file is 0600 and a reader never sees a partial document.
    #[test]
    fn the_journal_is_private_and_reopens_where_it_left_off() {
        let data = scratch("private");
        {
            let mut journal =
                Journal::open(&data, "op-0000000000b2", OperationKind::Setup).expect("a journal");
            journal
                .set_state(OperationState::Deploying)
                .expect("a state");
            journal.note_residue("a staged file").expect("residue");
        }
        let path = journal_path(&data, "op-0000000000b2");
        let mode = std::fs::metadata(&path)
            .expect("a journal file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a journal is readable only by its owner");

        let reopened =
            Journal::open(&data, "op-0000000000b2", OperationKind::Setup).expect("a journal");
        assert_eq!(reopened.state(), OperationState::Deploying);
        assert_eq!(reopened.record().residue, vec!["a staged file".to_string()]);

        let wrong_kind = match Journal::open(&data, "op-0000000000b2", OperationKind::Add) {
            Ok(_) => panic!("one id is one operation"),
            Err(error) => error,
        };
        assert_eq!(
            super::super::reason_of(&wrong_kind),
            Some("operation_in_progress")
        );
    }

    /// The journal is a secret-free document by construction: there is no field for a
    /// cookie or a key, and free text that arrives from elsewhere is bounded and
    /// stripped of control characters before it is written.
    #[test]
    fn free_text_entering_the_journal_is_bounded_and_stripped() {
        let data = scratch("bounded");
        let mut journal =
            Journal::open(&data, "op-0000000000c3", OperationKind::Leave).expect("a journal");
        journal
            .fail(
                OperationState::Failed,
                "runtime_busy",
                format!("line one\nline two\r\n{}", "x".repeat(1000)),
            )
            .expect("a failure");

        let text = std::fs::read_to_string(journal_path(&data, "op-0000000000c3")).expect("a file");
        let record: Record = serde_json::from_str(&text).expect("a decodable journal");
        let error = record.last_error.expect("a recorded error");
        // §6: `last_error` is a stable reason plus a bounded, sanitized detail.
        assert_eq!(error.reason, "runtime_busy");
        assert!(
            !error.detail.contains('\n'),
            "no raw newlines reach the journal"
        );
        assert!(
            error.detail.chars().count() <= 401,
            "{}",
            error.detail.chars().count()
        );
        assert!(error.detail.starts_with("line one line two"));
    }

    /// Listing returns every operation this data directory has a journal for.
    #[test]
    fn listing_returns_every_operation() {
        let data = scratch("list");
        for id in ["op-0000000000d4", "op-0000000000e5"] {
            Journal::open(&data, id, OperationKind::Add).expect("a journal");
        }
        assert_eq!(
            Journal::list(&data).expect("a listing"),
            vec!["op-0000000000d4".to_string(), "op-0000000000e5".to_string()]
        );
    }

    /// Completed and cancelled journals outside the newest-N window and older than the
    /// cutoff are removed; failed and interrupted work is not.
    #[test]
    fn prune_keeps_the_newest_completed_and_never_touches_failed_or_interrupted() {
        let data = scratch("prune");
        for index in 0..55u32 {
            let id = format!("op-00000000{index:04x}");
            let mut journal = Journal::open(&data, &id, OperationKind::Add).expect("a journal");
            journal
                .set_state(OperationState::Completed)
                .expect("completed");
            let path = journal_path(&data, &id);
            let mut record: Record =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("a journal file"))
                    .expect("a record");
            record.updated_at = format!("2020-01-01T00:{:02}:{:02}Z", index / 60, index % 60);
            super::super::write_private_atomic(
                &path,
                &serde_json::to_vec_pretty(&record).expect("bytes"),
            )
            .expect("rewritten");
        }
        let mut failed =
            Journal::open(&data, "op-00000000fail", OperationKind::Add).expect("failed");
        failed
            .fail(OperationState::Failed, "failed", "still resumable")
            .expect("failed");
        let mut interrupted =
            Journal::open(&data, "op-00000000intr", OperationKind::Add).expect("interrupted");
        interrupted
            .fail(OperationState::Interrupted, "failed", "still resumable")
            .expect("interrupted");

        let removed =
            Journal::prune_terminal(&data, 50, std::time::Duration::from_secs(30 * 86400))
                .expect("prune");
        assert_eq!(removed, 5, "55 completed minus the newest 50");
        let remaining = Journal::list(&data).expect("a listing");
        assert_eq!(remaining.len(), 52, "{remaining:?}");
        assert!(remaining.iter().any(|id| id == "op-00000000fail"));
        assert!(remaining.iter().any(|id| id == "op-00000000intr"));
        assert!(journal_path(&data, "op-00000000fail").exists());
        assert!(journal_path(&data, "op-00000000intr").exists());
    }

    /// A live worker keeps its journal even when the operation is already completed.
    #[test]
    fn prune_does_not_remove_an_operation_whose_worker_lock_is_held() {
        let data = scratch("held");
        let mut journal =
            Journal::open(&data, "op-00000000hold", OperationKind::Add).expect("a journal");
        journal
            .set_state(OperationState::Completed)
            .expect("completed");
        let path = journal_path(&data, "op-00000000hold");
        let mut record: Record =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("a journal file"))
                .expect("a record");
        record.updated_at = "2020-01-01T00:00:00Z".into();
        super::super::write_private_atomic(
            &path,
            &serde_json::to_vec_pretty(&record).expect("bytes"),
        )
        .expect("rewritten");
        let _worker = super::super::lock::Lock::acquire(&data, "op-00000000hold.lock")
            .expect("a held worker lock");
        assert_eq!(
            Journal::prune_terminal(&data, 0, std::time::Duration::from_secs(30 * 86400))
                .expect("prune"),
            0
        );
        assert!(path.exists());
    }
}
