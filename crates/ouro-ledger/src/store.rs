//! The sole writer. The canonical stream is authoritative; run.json is a projection.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::OnceLock,
    time::SystemTime,
};

use ouro_records::{
    canonical::{sha256_prefixed, to_jcs},
    records,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::protocol::{
    AppendReceipt, Chain, LedgerError, MAX_FRAME_BYTES, MAX_VERIFY_LIMIT, Peer, ReadPage,
    ReadRequest, Result, RunRecord, StoreStatus, VerifyPage, VerifyReport,
};

use crate::discovery::valid_name;
use crate::manifest::{self, STREAM};
use crate::schemas;

mod bundle_replay;
mod capture_pruning;
pub(crate) use bundle_replay::{Replayed, replay as replay_bundle};
mod catalog;
#[cfg(test)]
mod intent_tail_tests;
#[cfg(test)]
mod lifecycle_tests;
mod operator;
mod pending_recovery;
mod pruning;
mod retention;
mod tail;
mod transcript;
mod verification;
pub(crate) use verification::{VerifyPlan, verify_page};

const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
/// Canonical history one verify page re-reads, so one request's reply stays
/// prompt; the re-read itself never runs on the writer thread.
const VERIFY_PAGE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Replay {
    digest: String,
    receipt: AppendReceipt,
}

#[cfg_attr(test, derive(Clone))]
struct Anchor {
    bytes: u64,
    digest: String,
    state: &'static str,
    labels_digest: String,
}

/// How a stream stopped being trustworthy, decided where the failure is
/// detected rather than recovered later from its message text. Variants are
/// ordered by severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PoisonKind {
    /// This writer's own interruption or uncertain persistence: the validated
    /// prefix stands, and what follows it is missing or unacknowledged.
    Incomplete,
    /// Bytes or store metadata contradict anything this writer could have
    /// produced: an integrity violation.
    Corrupt,
    /// The durable segment manifest does not corroborate the canonical bytes,
    /// so even the validated prefix has no durable anchor.
    Unanchored,
}

impl PoisonKind {
    pub(crate) fn stream_status(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Corrupt | Self::Unanchored => "corrupt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Poison {
    pub(crate) kind: PoisonKind,
    pub(crate) detail: String,
}

impl Poison {
    fn new(kind: PoisonKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// The most severe finding decides: an integrity violation is never reported
/// as a merely incomplete stream.
pub(crate) fn poison_status(poisoned: &[Poison]) -> Option<&'static str> {
    poisoned
        .iter()
        .map(|p| p.kind)
        .max()
        .map(PoisonKind::stream_status)
}

fn poison_details(poisoned: &[Poison]) -> Vec<String> {
    poisoned.iter().map(|p| p.detail.clone()).collect()
}

#[cfg_attr(test, derive(Clone))]
struct Stream {
    run: RunRecord,
    accepted_bytes: u64,
    replay: BTreeMap<String, Replay>,
    source_heads: BTreeMap<String, u64>,
    source_gaps: Vec<Value>,
    last_source: Option<Value>,
    first_loss: Option<Value>,
    receipt_phase: Option<String>,
    poisoned: Vec<Poison>,
    segments: Vec<manifest::Segment>,
    active_segment: usize,
    segment_bytes: u64,
    segment_hash: Sha256,
    replay_hash: Sha256,
    anchors: BTreeMap<u64, Anchor>,
    last_activity_at: Option<String>,
    retention_time_valid: bool,
    pruned: Option<pruning::Retained>,
}

pub struct Store {
    pub(crate) retention: ouro_records::retention::LedgerRetention,
    root: PathBuf,
    lock: File,
    streams: BTreeMap<String, Stream>,
    preparations: BTreeMap<String, (String, String)>,
    recovery_ambiguous: bool,
    readers: crate::reader::Readers,
    index: Option<crate::projection::Projection>,
    index_error: Option<String>,
    index_pending: BTreeMap<String, RunRecord>,
    /// Pending journals whose background reconciliation failed, as last seen.
    /// They are retried only once the journal changes.
    #[cfg(target_os = "linux")]
    pending_failures: BTreeMap<String, Option<pending_recovery::JournalSeen>>,
    segment_limit: u64,
    verify_page_bytes: u64,
    /// Advances whenever a GC may remove or rewrite run files, so a verifier
    /// reading off the writer thread can tell a GC race from damage.
    gc_generation: u64,
    #[cfg(test)]
    fault: Option<Fault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    BeforeWrite,
    RotationCreated,
    RotationSynced,
    PartialWrite,
    EventSync,
    Projection,
    Manifest,
    DirectorySync,
    GcIntentWrite,
    GcIntentSync,
    GcBeforeUnlink,
    GcAfterUnlink,
    GcDirectorySync,
    GcCompletion,
    GcCompletionSync,
    GcProjection,
}

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| LedgerError("directory has no parent".into()))?;
        if !parent.exists() {
            private_directory(parent)?;
        }
        // Created owner-only, so it is never wider than 0700 under any umask;
        // the explicit mode then also corrects a narrower umask.
        fs::DirBuilder::new().mode(0o700).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        File::open(parent)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != crate::os::euid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(LedgerError(format!(
            "{} must be an owned private directory (0700)",
            path.display()
        )));
    }
    Ok(())
}

fn private_file(path: &Path, create: bool, append: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .append(append)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != crate::os::euid()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(LedgerError(format!(
            "unsafe private file {}",
            path.display()
        )));
    }
    Ok(file)
}

/// The exact projection bytes: canonical JSON and one LF, never published
/// unless it satisfies the frozen run schema.
fn projection_bytes(run: &RunRecord) -> Result<Vec<u8>> {
    let value = serde_json::to_value(run)?;
    validate_frozen("run", &value)?;
    let mut bytes = canonical(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Whether `path` is a private file holding exactly `expected`, synchronized
/// now. Any doubt answers false, so the caller republishes it.
fn synced_unchanged(path: &Path, expected: &[u8]) -> bool {
    use std::io::Read as _;
    let Ok(file) = private_file(path, false, false) else {
        return false;
    };
    let mut bytes = Vec::new();
    (&file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .is_ok()
        && bytes == expected
        && file.sync_all().is_ok()
}

fn loaded<'a>(streams: &'a mut BTreeMap<String, Stream>, run_id: &str) -> &'a mut Stream {
    streams
        .get_mut(run_id)
        .expect("a looked-up run id names a loaded stream")
}

fn check_run_id(id: &str) -> Result<()> {
    if !id.starts_with("run_")
        || id.len() != 36
        || !id[4..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(LedgerError("invalid run id".into()));
    }
    Ok(())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    to_jcs(value).map_err(|error| LedgerError(error.to_string()))
}

fn digest(value: &Value) -> Result<String> {
    Ok(sha256_prefixed(&canonical(value)?))
}

fn validate_frozen(name: &str, value: &Value) -> Result<()> {
    static VALIDATORS: OnceLock<BTreeMap<&'static str, jsonschema::Validator>> = OnceLock::new();
    let validators = VALIDATORS.get_or_init(|| {
        let schemas = [
            (
                "event",
                include_str!("../../../docs/specs/jail-v1/event.schema.json"),
            ),
            (
                "jail-event",
                include_str!("../../../docs/specs/jail-v1/jail-event.schema.json"),
            ),
            (
                "jail-receipt",
                include_str!("../../../docs/specs/jail-v1/jail-receipt.schema.json"),
            ),
            (
                "request",
                include_str!("../../../docs/specs/ledger-v1/request.schema.json"),
            ),
            (
                "source",
                include_str!("../../../docs/specs/ledger-v1/source.schema.json"),
            ),
            (
                "record",
                include_str!("../../../docs/specs/ledger-v1/record.schema.json"),
            ),
            (
                "run",
                include_str!("../../../docs/specs/ledger-v1/run.schema.json"),
            ),
        ]
        .map(|(name, source)| {
            (
                name,
                serde_json::from_str::<Value>(source).expect("checked-in frozen schema"),
            )
        });
        let resources = schemas.iter().map(|(_, schema)| {
            (
                schema["$id"].as_str().expect("frozen schema id").to_owned(),
                jsonschema::Resource::from_contents(schema.clone()),
            )
        });
        let registry: &'static jsonschema::Registry = Box::leak(Box::new(
            jsonschema::Registry::new()
                .extend(resources)
                .expect("frozen schema registry")
                .prepare()
                .expect("prepared frozen registry"),
        ));
        schemas
            .into_iter()
            .map(|(name, schema)| {
                (
                    name,
                    jsonschema::options()
                        .with_registry(registry)
                        .should_validate_formats(true)
                        .build(&schema)
                        .expect("frozen schema validator"),
                )
            })
            .collect()
    });
    if validators[name].is_valid(value) {
        Ok(())
    } else {
        Err(LedgerError(format!("record violates frozen {name} schema")))
    }
}

fn validate_receipt(receipt: &Value) -> Result<()> {
    validate_frozen("jail-receipt", receipt)?;
    if !records::semantic::receipt(receipt).is_empty() {
        return Err(LedgerError("record violates jail receipt semantics".into()));
    }
    Ok(())
}

pub(crate) fn validate_source(event: &Value, attempt_id: &str) -> Result<records::Event> {
    validate_frozen("jail-event", event)?;
    let typed: records::Event = serde_json::from_value(event.clone())?;
    if typed.attempt_id != attempt_id || !records::semantic::event(event).is_empty() {
        return Err(LedgerError(
            "source attempt or semantic contract mismatch".into(),
        ));
    }
    Ok(typed)
}

/// The frozen request schema states the whole plan, and the run projection
/// embeds it by reference: any hand-written copy that drifted from it could
/// acknowledge a preparation whose projection then refuses at every start.
pub(crate) fn validate_payload(payload: &Value) -> Result<()> {
    validate_frozen("request", payload).map_err(|_| {
        LedgerError("prepare only accepts the versioned digest-only request plan".into())
    })?;
    // JSON Schema's integer also admits 1.0; the limit is a byte count.
    if !payload["capture"]["limit_bytes"].is_u64() {
        return Err(LedgerError(
            "capture limit must be a whole number of bytes".into(),
        ));
    }
    Ok(())
}

fn initial_run(run_id: &str, request_id: &str, attempt_id: &str, payload: Value) -> RunRecord {
    RunRecord {
        schema: schemas::RUN.into(),
        run_id: run_id.into(),
        request_id: request_id.into(),
        attempt_id: attempt_id.into(),
        payload,
        state: "prepared".into(),
        child_protection: "unprotected".into(),
        owner: None,
        outcome: None,
        coverage: json!({"status":"unobserved"}),
        settlement: "pending".into(),
        receipts: vec![],
        capture: json!({"stdout":{"state":"not_captured"},"stderr":{"state":"not_captured"},"argv":{"state":"not_captured"}}),
        chain: Chain {
            head_seq: 0,
            head_digest: None,
        },
        holds: vec![],
        history: None,
        capture_history: None,
    }
}

impl Drop for Store {
    /// A child forked elsewhere in this process holds every inherited
    /// descriptor until it execs; unlocking the shared open file releases
    /// the writer lock for it too, so a successor never sees a phantom writer.
    fn drop(&mut self) {
        // SAFETY: flock takes the still-open descriptor and flags by value.
        unsafe {
            libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Store {
    pub fn open(data: &Path) -> Result<Self> {
        Self::open_with_recovery_sync(data, File::sync_all)
    }

    fn open_with_recovery_sync(
        data: &Path,
        recovery_sync: impl Fn(&File) -> std::io::Result<()>,
    ) -> Result<Self> {
        private_directory(data)?;
        let root = data.join("ledger");
        private_directory(&root)?;
        let lock = private_file(&root.join("writer.lock"), true, false)?;
        // SAFETY: flock takes the open descriptor and flags by value.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(LedgerError(
                    "another ledger writer holds the process-lifetime lock".into(),
                ));
            }
            return Err(LedgerError(format!(
                "cannot take the ledger writer lock: {error}"
            )));
        }
        let mut store = Self {
            retention: Default::default(),
            root,
            lock,
            streams: BTreeMap::new(),
            preparations: BTreeMap::new(),
            recovery_ambiguous: false,
            readers: crate::reader::Readers::default(),
            index: None,
            index_error: None,
            index_pending: BTreeMap::new(),
            #[cfg(target_os = "linux")]
            pending_failures: BTreeMap::new(),
            segment_limit: SEGMENT_BYTES,
            verify_page_bytes: VERIFY_PAGE_BYTES,
            gc_generation: 0,
            #[cfg(test)]
            fault: None,
        };
        for entry in fs::read_dir(&store.root)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| LedgerError("non-UTF-8 store entry".into()))?;
            if !name.starts_with("run_") {
                continue;
            }
            check_run_id(&name)?;
            private_directory(&entry.path())?;
            let mut stream = if let Some(retained) = pruning::read(&store.root.join(&name), &name)?
            {
                store.restore_pruned(&name, retained)?
            } else {
                store.load_stream_with_sync(&name, &recovery_sync)?.0
            };
            if stream.poisoned.is_empty() && stream.pruned.is_none() {
                store.recover_captures(&name, &mut stream)?;
            }
            if !stream.poisoned.is_empty() {
                store.recovery_ambiguous = true;
            }
            let payload_digest = digest(&stream.run.payload)?;
            let request_id = stream.run.request_id.clone();
            if !request_id.is_empty()
                && store
                    .preparations
                    .insert(request_id, (payload_digest, name.clone()))
                    .is_some()
            {
                return Err(LedgerError(
                    "duplicate prepare request identity in durable streams".into(),
                ));
            }
            if stream.poisoned.is_empty() {
                // Every verified segment was synchronized before publishing
                // recovered receipts, including a complete unacknowledged tail.
                // Unchanged files are only synchronized again: an earlier
                // writer may have crashed between their rename and its
                // directory sync, but rewriting them would cost every run
                // several writes and syncs at every start.
                let directory = store.root.join(&name);
                let mut published = false;
                if !synced_unchanged(&directory.join("run.json"), &projection_bytes(&stream.run)?) {
                    store.write_projection(&stream.run)?;
                    published = true;
                }
                if stream.pruned.is_none() {
                    let manifest = stream.manifest();
                    if !synced_unchanged(
                        &directory.join(manifest::NAME),
                        &manifest::encode(&manifest)?,
                    ) {
                        manifest::write(&directory, &manifest)?;
                        published = true;
                    }
                }
                if !published {
                    File::open(&directory)?.sync_all()?;
                }
            }
            store.streams.insert(name, stream);
        }
        match crate::projection::Projection::open(&store.root).and_then(|mut index| {
            index.rebuild(&store.runs())?;
            Ok(index)
        }) {
            Ok(index) => store.index = Some(index),
            Err(error) => store.index_error = Some(error.to_string()),
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare(&mut self, request_id: &str, payload: &Value, peer: &Peer) -> Result<RunRecord> {
        if !valid_name(request_id) {
            return Err(LedgerError("prepare needs a bounded request id".into()));
        }
        validate_payload(payload)?;
        let payload_digest = digest(payload)?;
        if let Some((expected, run_id)) = self.preparations.get(request_id) {
            if expected != &payload_digest {
                return Err(LedgerError(
                    "request id already maps to a different prepare payload".into(),
                ));
            }
            if !self.stream(run_id)?.poisoned.is_empty() {
                return Err(LedgerError(
                    "ambiguous preparation cannot acknowledge before recovery".into(),
                ));
            }
            return self.show(run_id);
        }
        if self.recovery_ambiguous {
            return Err(LedgerError(
                "ambiguous recovery blocks new preparation; inspect verify".into(),
            ));
        }
        let run_id = format!("run_{}", Uuid::new_v4().simple());
        let attempt_id = format!("att_{}", Uuid::new_v4());
        let directory = self.root.join(&run_id);
        private_directory(&directory)?;
        private_directory(&directory.join("receipts"))?;
        private_directory(&directory.join("artifacts"))?;
        let run = initial_run(&run_id, request_id, &attempt_id, payload.clone());
        self.streams.insert(
            run_id.clone(),
            Stream {
                run,
                ..Stream::empty(&run_id)
            },
        );
        self.preparations
            .insert(request_id.into(), (payload_digest, run_id.clone()));
        let record = json!({"kind":"prepared","body":{"request_id":request_id,"payload":payload},"request_id":format!("prepare:{request_id}")});
        if let Err(error) = self.append(&run_id, record, "operator", peer, None) {
            self.recovery_ambiguous = true;
            return Err(error);
        }
        self.show(&run_id)
    }

    pub fn claim_owner(&mut self, run_id: &str, peer: &Peer) -> Result<()> {
        let stream = self.stream(run_id)?;
        if !stream.poisoned.is_empty() {
            return Err(LedgerError("poisoned stream refuses ownership".into()));
        }
        if let Some(owner) = &stream.run.owner {
            if owner != peer {
                return Err(LedgerError("attempt already has an owner; dead owners require reconciliation and are never restarted".into()));
            }
            return Ok(());
        }
        if stream.pruned.is_some() {
            return Err(LedgerError(
                "pruned run cannot acquire a new launch owner".into(),
            ));
        }
        self.append(
            run_id,
            json!({"kind":"owner_claimed","body":{"owner":peer},"request_id":"owner:claim"}),
            "owner",
            peer,
            None,
        )?;
        Ok(())
    }

    // Mirrors the explicit authenticated protocol fields at this boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn append_owner(
        &mut self,
        run_id: &str,
        request_id: &str,
        kind: &str,
        effect_id: Option<&str>,
        body: &Value,
        peer: &Peer,
        token_id: &str,
    ) -> Result<AppendReceipt> {
        if !valid_name(request_id)
            || effect_id.is_some_and(|id| !valid_name(id))
            || !body.is_object()
            || !["admitted", "denied", "settled", "note", "outcome_unknown"].contains(&kind)
        {
            return Err(LedgerError("invalid owner intent".into()));
        }
        if self.stream(run_id)?.run.owner.as_ref() != Some(peer) {
            return Err(LedgerError(
                "owner identity does not match the durable claim".into(),
            ));
        }
        self.append(
            run_id,
            json!({"kind":kind,"body":body,"request_id":request_id,"effect_id":effect_id}),
            "owner",
            peer,
            Some(token_id),
        )
    }

    pub fn append_source(
        &mut self,
        run_id: &str,
        event: &Value,
        peer: &Peer,
        token_id: &str,
    ) -> Result<AppendReceipt> {
        self.append_source_as(run_id, event, peer, Some(token_id), "producer")
    }

    fn append_source_as(
        &mut self,
        run_id: &str,
        event: &Value,
        peer: &Peer,
        token_id: Option<&str>,
        role: &str,
    ) -> Result<AppendReceipt> {
        let run = &self.stream(run_id)?.run;
        let minimized = crate::redaction::minimize(event, &run.payload, &run.attempt_id)?;
        let event = &minimized;
        let event_typed = validate_source(&crate::redaction::envelope(event), &run.attempt_id)?;
        if event_typed.schema != records::SCHEMA_EVENT
            || event_typed.attempt_id != self.stream(run_id)?.run.attempt_id
            || event_typed.source_seq == 0
        {
            return Err(LedgerError(
                "source event schema, attempt or sequence is invalid".into(),
            ));
        }
        let source = event.get("source").and_then(Value::as_str).unwrap_or("");
        let allowed = match source {
            "wrapper" => ["note", "jail.receipt"].contains(&event_typed.operation.as_str()),
            "audit" => [
                "proc.exec",
                "proc.exit",
                "fs.create",
                "fs.write",
                "fs.rename",
                "fs.unlink",
                "fs.deny",
                "net.connect",
            ]
            .contains(&event_typed.operation.as_str()),
            "proxy" => {
                event_typed.operation == "net.connect"
                    && event_typed.stage == records::EventStage::Result
                    && event_typed.decision.is_some()
            }
            _ => false,
        };
        if !allowed || !records::semantic::event(event).is_empty() {
            return Err(LedgerError(
                "source event violates the jail producer contract".into(),
            ));
        }
        let request_id = format!("source:{source}:{}", event_typed.source_seq);
        let receipt = self.append(
            run_id,
            json!({"kind":"source","body":event,"request_id":request_id}),
            role,
            peer,
            token_id,
        )?;
        let stream = self.stream(run_id)?;
        if stream.run.payload["evidence"] == "strict" && !stream.source_gaps.is_empty() {
            // The actual evidence is durable, but strict execution gets no success
            // acknowledgement, including on retries after a lost failure reply.
            return Err(LedgerError(
                "strict producer transport loss was durably recorded; stop admission and execution"
                    .into(),
            ));
        }
        Ok(receipt)
    }

    /// The loaded stream of a run id this writer has already looked up.
    fn stream_mut(&mut self, run_id: &str) -> &mut Stream {
        loaded(&mut self.streams, run_id)
    }

    /// Record why a loaded stream can no longer be trusted.
    fn poison(&mut self, run_id: &str, kind: PoisonKind, detail: impl Into<String>) {
        self.stream_mut(run_id)
            .poisoned
            .push(Poison::new(kind, detail));
    }

    fn stream(&self, run_id: &str) -> Result<&Stream> {
        check_run_id(run_id)?;
        self.streams
            .get(run_id)
            .ok_or_else(|| LedgerError("unknown run".into()))
    }

    fn append(
        &mut self,
        run_id: &str,
        mut record: Value,
        role: &str,
        peer: &Peer,
        token_id: Option<&str>,
    ) -> Result<AppendReceipt> {
        let stream = self.stream(run_id)?;
        let key = record["request_id"]
            .as_str()
            .ok_or_else(|| LedgerError("missing request identity".into()))?
            .to_owned();
        let payload_digest = digest(&record)?;
        if let Some(replay) = stream.replay.get(&key) {
            if replay.digest != payload_digest {
                return Err(LedgerError(
                    "request id conflicts with its immutable payload".into(),
                ));
            }
            if !stream.poisoned.is_empty() {
                return Err(LedgerError(
                    "stream durability is ambiguous; replay cannot acknowledge before recovery"
                        .into(),
                ));
            }
            return Ok(replay.receipt.clone());
        }
        if !stream.poisoned.is_empty() {
            return Err(LedgerError(
                "stream is poisoned; no dependent dispatch or sequence reuse".into(),
            ));
        }
        if stream.pruned.is_some() {
            return Err(LedgerError(
                "run history was pruned; new mutations are refused".into(),
            ));
        }
        if stream
            .run
            .capture_history
            .as_ref()
            .is_some_and(|h| h.state == "pruning")
        {
            return Err(LedgerError(
                "capture pruning is incomplete; retry GC or restart before mutations".into(),
            ));
        }
        // Exactly the checks recovery repeats: anything acknowledged here must
        // also be accepted from the canonical stream at the next start.
        validate_recovery(stream, &record, role)?;
        validate_transition(stream, &record)?;
        validate_intent(stream, &record)?;
        let seq = stream
            .run
            .chain
            .head_seq
            .checked_add(1)
            .ok_or_else(|| LedgerError("sequence exhausted".into()))?;
        record["schema"] = json!(schemas::RECORD);
        record["run_id"] = json!(run_id);
        record["attempt_id"] = json!(stream.run.attempt_id);
        record["seq"] = json!(seq);
        record["prev"] = json!(stream.run.chain.head_digest);
        record["received_at"] = json!(records::rfc3339_utc(SystemTime::now()));
        record["provenance"] = json!({"role":role,"peer_uid":peer.uid,"peer_pid":peer.pid,"peer_birth":peer.birth,"token_id":token_id});
        if record["kind"] == "source" {
            let source = record["body"]
                .as_object()
                .expect("validated source object")
                .clone();
            let object = record.as_object_mut().expect("record object");
            object.remove("body");
            // Preserve the validated source envelope and any explicit ledger redaction marker.
            object.extend(source);
        }
        validate_frozen("record", &record)?;
        let bytes = canonical(&record)?;
        if bytes.len() + 1 > MAX_FRAME_BYTES {
            return Err(LedgerError(
                "canonical event exceeds bounded frame limit".into(),
            ));
        }
        let receipt = AppendReceipt {
            seq,
            digest: sha256_prefixed(&bytes),
        };
        let result = self.persist(run_id, &bytes, &record, &receipt, &payload_digest);
        if let Err(error) = result {
            self.poison(
                run_id,
                PoisonKind::Incomplete,
                format!("uncertain persistence: {error}"),
            );
            return Err(error);
        }
        Ok(receipt)
    }

    fn persist(
        &mut self,
        run_id: &str,
        bytes: &[u8],
        record: &Value,
        receipt: &AppendReceipt,
        payload_digest: &str,
    ) -> Result<()> {
        #[cfg(test)]
        let _fault_scope = crate::faults::scope(record["kind"].as_str().unwrap_or(""));
        let directory = self.root.join(run_id);
        let stream = loaded(&mut self.streams, run_id);
        let rotate = stream.segment_bytes > 0
            && stream.segment_bytes.saturating_add(bytes.len() as u64 + 1) > self.segment_limit;
        let mut file = if rotate {
            if stream.active_segment == manifest::MAX_SEGMENTS {
                return Err(LedgerError(
                    "segment count limit reached; no history was removed".into(),
                ));
            }
            let next = stream.active_segment + 1;
            // Exclusive creation never appends over an unexpected successor.
            let file = OpenOptions::new()
                .read(true)
                .append(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join(manifest::name(next)))?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::RotationCreated)) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            file.sync_all()?;
            File::open(&directory)?.sync_all()?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::RotationSynced)) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
            stream.begin_segment(next);
            file
        } else {
            private_file(
                &directory.join(manifest::name(stream.active_segment)),
                stream.active_segment == 1 && stream.segment_bytes == 0,
                true,
            )?
        };
        if file.metadata()?.len() != stream.segment_bytes {
            return Err(LedgerError(
                "active segment length changed before append".into(),
            ));
        }
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::BeforeWrite)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::PartialWrite)) {
            file.write_all(&bytes[..bytes.len() / 2])?;
            file.sync_all()?;
            return Err(std::io::Error::from_raw_os_error(libc::EINTR).into());
        }
        #[cfg(test)]
        {
            crate::faults::hit("event.before_write")?;
            if crate::faults::active("event.partial_write") {
                file.write_all(&bytes[..bytes.len() / 2])?;
                file.sync_all()?;
                crate::faults::hit("event.partial_write")?;
            }
        }
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        #[cfg(test)]
        crate::faults::hit("event.before_sync")?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::EventSync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        file.sync_all()?;
        #[cfg(test)]
        crate::faults::hit("event.after_sync")?;
        let stream = loaded(&mut self.streams, run_id);
        apply_record(
            stream,
            &original_payload(record),
            receipt.clone(),
            payload_digest.into(),
        )?;
        stream.accepted_bytes += (bytes.len() + 1) as u64;
        stream.hash_record(bytes, record, receipt, payload_digest)?;
        let run = stream.run.clone();
        let manifest = stream.manifest();
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::Projection)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        self.write_projection(&run)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::Manifest)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        crate::manifest::write(&self.root.join(run_id), &manifest)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::DirectorySync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        #[cfg(test)]
        crate::faults::hit("append.before_directory_sync")?;
        File::open(self.root.join(run_id))?.sync_all()?;
        #[cfg(test)]
        crate::faults::hit("append.after_directory_sync")?;
        if self.index.is_some() {
            self.index_pending.insert(run_id.into(), run);
        }
        Ok(())
    }

    fn write_projection(&self, run: &RunRecord) -> Result<()> {
        let bytes = projection_bytes(run)?;
        let dir = self.root.join(&run.run_id);
        let temp = dir.join(format!(".run-{}.tmp", Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        let result = (|| -> Result<()> {
            #[cfg(test)]
            crate::faults::hit("projection.before_write")?;
            file.write_all(&bytes)?;
            #[cfg(test)]
            crate::faults::hit("projection.before_sync")?;
            file.sync_all()?;
            #[cfg(test)]
            crate::faults::hit("projection.before_rename")?;
            fs::rename(&temp, dir.join("run.json"))?;
            Ok(())
        })();
        if result.is_err() {
            // An unpublished temporary projection has no authority; never leak it.
            let _ = fs::remove_file(&temp);
        }
        result?;
        #[cfg(test)]
        crate::faults::hit("projection.before_directory_sync")?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn show(&self, run_id: &str) -> Result<RunRecord> {
        let stream = self.stream(run_id)?;
        let mut run = stream.run.clone();
        if !stream.poisoned.is_empty() {
            run.state = "outcome_unknown".into();
            run.settlement = "pending".into();
            run.outcome = Some(
                json!({"kind":"unknown","unknown":true,"unknown_reason":"stream persistence or recovery is ambiguous"}),
            );
            run.coverage = json!({"status":"degraded","gaps":poison_details(&stream.poisoned)});
        }
        Ok(run)
    }

    pub fn runs(&self) -> Vec<RunRecord> {
        self.streams
            .keys()
            .filter_map(|id| self.show(id).ok())
            .collect()
    }

    pub fn index_status(&self) -> Value {
        json!({"state":if self.index.is_some() {"ready"} else {"unavailable"},
            "authoritative":false,"rebuild":"writer_restart","pending_runs":self.index_pending.len(),"error":self.index_error})
    }

    /// Dispatch has already handed the durable response to the connection handler.
    /// Index failures cannot change that acknowledgement or canonical stream.
    pub fn flush_index(&mut self) {
        let pending = std::mem::take(&mut self.index_pending);
        if let Some(index) = &mut self.index {
            for run in pending.values() {
                if let Err(error) = index.upsert(run) {
                    self.index_error = Some(error.to_string());
                    self.index = None;
                    break;
                }
            }
        }
    }

    pub fn read(&mut self, request: &ReadRequest) -> Result<ReadPage> {
        check_run_id(&request.run_id)?;
        let stream = self
            .streams
            .get(&request.run_id)
            .ok_or_else(|| LedgerError("unknown run".into()))?;
        if stream.pruned.is_some() {
            return Err(LedgerError(
                "run history was pruned; canonical query and export are unavailable".into(),
            ));
        }
        self.readers.read(
            &self.root.join(&request.run_id).join(STREAM),
            request,
            &stream.run,
            &stream.poisoned,
            stream.accepted_bytes,
            (
                |key: &str| stream.replay.get(key).map(|r| r.receipt.clone()),
                |seq, digest: &str, bytes, page: Option<&ReadPage>| {
                    if seq == 0 {
                        // A clean empty snapshot never restores: streams open
                        // at durable preparation and empty or broken streams
                        // stay poisoned, so seq 0 corroborates only genuine
                        // canonical emptiness.
                        return bytes == 0
                            && digest.is_empty()
                            && stream.run.chain.head_seq == 0
                            && stream.accepted_bytes == 0
                            && stream.poisoned.is_empty();
                    }
                    !stream
                        .poisoned
                        .iter()
                        .any(|problem| problem.kind == PoisonKind::Unanchored)
                        && stream.anchors.get(&seq).is_some_and(|anchor| {
                            anchor.bytes == bytes
                                && anchor.digest == digest
                                && page.is_none_or(|page| {
                                    (page.state == anchor.state
                                        || (!page.local_consistency
                                            && page.state == "outcome_unknown"))
                                        && crate::reader::snapshot_labels_digest(
                                            &page.child_protection,
                                            &page.coverage,
                                        )
                                        .is_ok_and(|digest| digest == anchor.labels_digest)
                                })
                        })
                },
            ),
        )
    }

    pub fn settle_orphans(
        &mut self,
        peer: &Peer,
        alive: impl Fn(&Peer) -> bool,
    ) -> Result<Vec<RunRecord>> {
        let orphans: Vec<_> = self
            .streams
            .iter()
            .filter_map(|(id, stream)| {
                if ["settled", "denied", "outcome_unknown"].contains(&stream.run.state.as_str())
                    || !stream.poisoned.is_empty()
                {
                    return None;
                }
                stream
                    .run
                    .owner
                    .as_ref()
                    .filter(|owner| !alive(owner))
                    .map(|_| id.clone())
            })
            .collect();
        let mut reconciled = Vec::new();
        for id in orphans {
            if self.pending_exists(&id) {
                // Corrupt or incomplete local evidence must never imply
                // settlement; its refusal is recorded with the unknown outcome.
                let result = self.reconcile(&id, peer, &alive);
                if !["prepared", "admitted"].contains(&self.stream(&id)?.run.state.as_str()) {
                    reconciled.push(self.show(&id)?);
                    continue;
                }
                match result {
                    Ok(_) => {}
                    Err(pending_recovery::PendingFailure::Refused(refusal, _)) => {
                        self.record_invalid_pending(&id, peer, refusal)?;
                        reconciled.push(self.show(&id)?);
                        continue;
                    }
                    // Not the journal's doing: nothing is recorded for this
                    // run, and a later settlement can retry it.
                    Err(pending_recovery::PendingFailure::Other(problem)) => {
                        return Err(LedgerError(format!(
                            "{id}: pending evidence could not be reconciled now: {problem}"
                        )));
                    }
                }
            }
            let owner = self.stream(&id)?.run.owner.clone();
            self.append(&id, json!({"kind":"outcome_unknown","request_id":"reconcile:owner-dead","body":{"owner":owner,"outcome":{"kind":"unknown","unknown":true,"unknown_reason":"owner birth identity is no longer live; tree termination and unrecorded effects are not inferred"},"coverage":{"status":"degraded","gaps":[{"reason":"owner_lost"}]}}}), "operator", peer, None)?;
            reconciled.push(self.show(&id)?);
        }
        Ok(reconciled)
    }

    /// The accepted in-memory state only: nothing is re-read from disk, so a
    /// readiness probe never competes with live owners for the writer thread.
    pub fn status(&self) -> StoreStatus {
        let mut status = StoreStatus {
            scope: "writer_accepted_state".into(),
            runs: self.streams.len() as u32,
            ambiguous_runs: 0,
            incomplete_deletions: 0,
            preparation_blocked: self.recovery_ambiguous,
        };
        for stream in self.streams.values() {
            status.ambiguous_runs += u32::from(!stream.poisoned.is_empty());
            status.incomplete_deletions += u32::from(
                [&stream.run.history, &stream.run.capture_history]
                    .into_iter()
                    .flatten()
                    .any(|history| history.state == "pruning"),
            );
        }
        status
    }

    fn load_stream_with_sync(
        &self,
        run_id: &str,
        sync: &impl Fn(&File) -> std::io::Result<()>,
    ) -> Result<(Stream, u64)> {
        let directory = self.root.join(run_id);
        let layout = Layout::read(&directory, run_id);
        let loaded = load_stream(&directory, run_id, layout, sync, &mut || true)?;
        Ok((loaded.stream, loaded.events))
    }
}

/// One run's canonical layout as it stood at one moment. A re-read never goes
/// past it, so it is consistent with whatever the writer appends later.
struct Layout {
    manifest: std::result::Result<Option<manifest::Manifest>, String>,
    names: std::result::Result<Vec<String>, String>,
    /// The last segment's length at that moment: appends only ever grow the
    /// last segment, and a rotation seals it at or beyond this length.
    last_bytes: Option<u64>,
}

impl Layout {
    fn read(directory: &Path, run_id: &str) -> Self {
        let manifest = crate::manifest::read(directory, run_id).map_err(|error| error.to_string());
        let names = manifest::names(directory).map_err(|error| error.to_string());
        let last_bytes = names
            .as_ref()
            .ok()
            .and_then(|names| names.last())
            .and_then(|name| fs::symlink_metadata(directory.join(name)).ok())
            .map(|metadata| metadata.len());
        Self {
            manifest,
            names,
            last_bytes,
        }
    }
}

struct Loaded {
    stream: Stream,
    events: u64,
    /// The canonical bytes re-read before `proceed` stopped the load, if it did.
    stopped: Option<u64>,
}

/// Re-read and re-validate one run's canonical history within `layout`.
/// `proceed` is asked before every frame; once it answers false the load
/// stops and says how far it got, never what it did not read.
fn load_stream(
    directory: &Path,
    run_id: &str,
    layout: Layout,
    sync: &impl Fn(&File) -> std::io::Result<()>,
    proceed: &mut impl FnMut() -> bool,
) -> Result<Loaded> {
    let mut stream = Stream::empty(run_id);
    let manifest = match layout.manifest {
        Ok(manifest) => manifest,
        Err(error) => {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                format!("invalid segment manifest: {error}"),
            ));
            None
        }
    };
    let names = match layout.names {
        Ok(names) => names,
        Err(error) => {
            stream.poisoned.push(Poison::new(
                PoisonKind::Corrupt,
                format!("invalid segment layout: {error}"),
            ));
            return Ok(Loaded {
                stream,
                events: 0,
                stopped: None,
            });
        }
    };
    let count = names.len();
    if manifest
        .as_ref()
        .is_none_or(|m| count < m.segments.len() || count > m.segments.len() + 1)
        && !(manifest.is_none() && count == 1)
    {
        stream.poisoned.push(Poison::new(
            PoisonKind::Unanchored,
            "segment manifest does not authorize this segment layout",
        ));
    }
    let mut events = 0;
    let mut stopped = None;
    'segments: for (index, name) in names.iter().enumerate() {
        stream.begin_segment(index + 1);
        let anchor = manifest.as_ref().and_then(|m| m.segments.get(index));
        let mut anchored = anchor.is_none();
        let file = match private_file(&directory.join(name), false, false) {
            Ok(file) => file,
            Err(error) => {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Corrupt,
                    format!("missing or unsafe canonical segment: {error}"),
                ));
                break;
            }
        };
        // Once a successor exists, its predecessor is sealed at the
        // durable anchor. A tail there could not come from this writer.
        if index + 1 < count
            && anchor.is_none_or(|a| file.metadata().is_ok_and(|m| m.len() != a.bytes))
        {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                "sealed segment length differs from its manifest anchor",
            ));
            break;
        }
        let limit = match layout.last_bytes {
            Some(bytes) if index + 1 == count => bytes,
            _ => u64::MAX,
        };
        use std::io::Read as _;
        let mut reader = BufReader::new((&file).take(limit));
        loop {
            if !proceed() {
                stopped = Some(stream.accepted_bytes);
                break 'segments;
            }
            let mut bytes = Vec::new();
            // read_until alone is unbounded; the limited reader also catches a missing newline.
            let length = reader
                .by_ref()
                .take((MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut bytes)?;
            if length == 0 {
                break;
            }
            // This writer never emits an oversized frame; only a crash
            // between its write and newline leaves an unterminated tail.
            if length > MAX_FRAME_BYTES {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Corrupt,
                    "oversized canonical frame; bytes retained",
                ));
                break;
            }
            if bytes.last() != Some(&b'\n') {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Incomplete,
                    "interrupted canonical frame; bytes retained",
                ));
                break;
            }
            bytes.pop();
            // Every refusal of a complete frame is an integrity violation:
            // this writer validates the same rules before it appends.
            if let Err(error) = stream.accept_canonical(run_id, &bytes) {
                stream
                    .poisoned
                    .push(Poison::new(PoisonKind::Corrupt, error.to_string()));
                break;
            }
            events += 1;
            if let Some(anchor) = anchor
                && events == anchor.last_seq
            {
                anchored = true;
                let m = manifest.as_ref().expect("anchored manifest");
                if stream.segments.last() != Some(anchor)
                    || stream.run.attempt_id != m.attempt_id
                    || (index + 1 == m.segments.len()
                        && stream.manifest().replay_digest != m.replay_digest)
                {
                    stream.poisoned.push(Poison::new(
                        PoisonKind::Unanchored,
                        "segment manifest committed prefix mismatch",
                    ));
                    break;
                }
            }
        }
        // The manifest is written only after its records are synchronized,
        // so bytes missing below an anchor are lost acknowledged history.
        if !anchored {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                "canonical stream truncated before its segment manifest anchor",
            ));
        }
        // Only one empty unlisted successor of a fully anchored stream can be
        // an interrupted rotation, and only a lone unlisted first segment an
        // interrupted preparation. Never manufacture a missing committed file.
        if stream.segment_bytes == 0 && (index == 0 || anchor.is_some() || index + 1 != count) {
            let kind = if index == 0 && anchor.is_none() && count == 1 {
                PoisonKind::Incomplete
            } else {
                PoisonKind::Corrupt
            };
            stream
                .poisoned
                .push(Poison::new(kind, "empty canonical segment"));
        }
        if !stream.poisoned.is_empty() {
            break;
        }
        // Sync the exact descriptor just verified, not a reopened path. A
        // failure aborts startup before any repaired metadata is published.
        sync(&file)?;
    }
    if stream.poisoned.is_empty() && stopped.is_none() {
        capture_pruning::apply(directory, &mut stream)?;
    }
    Ok(Loaded {
        stream,
        events,
        stopped,
    })
}

impl Stream {
    fn empty(run_id: &str) -> Self {
        Self {
            run: initial_run(run_id, "", "", json!({})),
            accepted_bytes: 0,
            replay: BTreeMap::new(),
            source_heads: BTreeMap::new(),
            source_gaps: vec![],
            last_source: None,
            first_loss: None,
            receipt_phase: None,
            poisoned: vec![],
            segments: vec![],
            active_segment: 1,
            segment_bytes: 0,
            segment_hash: Sha256::new(),
            replay_hash: Sha256::new(),
            anchors: BTreeMap::new(),
            last_activity_at: None,
            retention_time_valid: true,
            pruned: None,
        }
    }

    /// Shared by store recovery and read-only portable bundle verification.
    fn accept_canonical(&mut self, run_id: &str, bytes: &[u8]) -> Result<()> {
        let decoded: Value = serde_json::from_slice(bytes)
            .map_err(|error| LedgerError(format!("invalid canonical JSON: {error}")))?;
        if !canonical(&decoded).is_ok_and(|encoded| encoded == bytes) {
            return Err(LedgerError(
                "noncanonical or unsupported stream bytes".into(),
            ));
        }
        validate_frozen("record", &decoded).map_err(|_| {
            LedgerError("canonical ledger record violates its versioned schema".into())
        })?;
        let expected_seq = self.run.chain.head_seq + 1;
        let expected_schema = if decoded["kind"] == "source" {
            records::SCHEMA_EVENT
        } else {
            schemas::RECORD
        };
        if decoded["schema"] != expected_schema
            || decoded["run_id"] != run_id
            || decoded["seq"].as_u64() != Some(expected_seq)
            || decoded["prev"] != json!(self.run.chain.head_digest)
        {
            return Err(LedgerError(
                "canonical identity, sequence or hash-chain link mismatch".into(),
            ));
        }
        if expected_seq == 1 {
            if decoded["kind"] != "prepared" {
                return Err(LedgerError(
                    "stream does not start at durable preparation".into(),
                ));
            }
            self.run = initial_run(
                run_id,
                decoded["body"]["request_id"].as_str().unwrap_or(""),
                decoded["attempt_id"].as_str().unwrap_or(""),
                decoded["body"]["payload"].clone(),
            );
            validate_payload(&self.run.payload)?;
        }
        if decoded["attempt_id"] != self.run.attempt_id {
            return Err(LedgerError("mixed attempt identity".into()));
        }
        let payload = original_payload(&decoded);
        if decoded["kind"] == "source" {
            crate::redaction::validate_stored(
                &payload["body"],
                &self.run.payload,
                &self.run.attempt_id,
            )
            .map_err(|_| {
                LedgerError("canonical producer violates the frozen source contract".into())
            })?;
        }
        if let Some(receipt) = decoded["body"].get("receipt") {
            validate_receipt(receipt).map_err(|_| {
                LedgerError("canonical receipt violates the frozen receipt contract".into())
            })?;
        }
        let payload_digest = digest(&payload)?;
        let receipt = AppendReceipt {
            seq: expected_seq,
            digest: sha256_prefixed(bytes),
        };
        validate_recovery(
            self,
            &payload,
            decoded["provenance"]["role"].as_str().unwrap_or(""),
        )?;
        validate_transition(self, &payload)?;
        validate_intent(self, &payload)?;
        apply_record(self, &payload, receipt.clone(), payload_digest.clone())?;
        self.accepted_bytes += bytes.len() as u64 + 1;
        self.hash_record(bytes, &decoded, &receipt, &payload_digest)
    }

    fn begin_segment(&mut self, number: usize) {
        self.active_segment = number;
        self.segment_bytes = 0;
        self.segment_hash = Sha256::new();
    }

    fn hash_record(
        &mut self,
        bytes: &[u8],
        record: &Value,
        receipt: &AppendReceipt,
        payload_digest: &str,
    ) -> Result<()> {
        // Retention uses writer receipt time, never producer time or file mtime.
        // A clock regression cannot shorten the observed retention interval.
        match record["received_at"]
            .as_str()
            .filter(|time| crate::reader::utc_second(time))
        {
            Some(time) => {
                if self
                    .last_activity_at
                    .as_deref()
                    .is_none_or(|last| time > last)
                {
                    self.last_activity_at = Some(time.into());
                }
            }
            None => self.retention_time_valid = false,
        }
        self.segment_hash.update(bytes);
        self.segment_hash.update(b"\n");
        self.segment_bytes += bytes.len() as u64 + 1;
        let first_seq = self
            .segments
            .get(self.active_segment - 1)
            .map_or(receipt.seq, |s| s.first_seq);
        let segment = manifest::Segment {
            name: manifest::name(self.active_segment),
            first_seq,
            last_seq: receipt.seq,
            bytes: self.segment_bytes,
            digest: format!("sha256:{:x}", self.segment_hash.clone().finalize()),
            head_digest: receipt.digest.clone(),
        };
        if self.segments.len() < self.active_segment {
            self.segments.push(segment);
        } else {
            self.segments[self.active_segment - 1] = segment;
        }
        let identity = canonical(&json!({"request_id":record["request_id"],
            "effect_id":record.get("effect_id"),"payload_digest":payload_digest,
            "seq":receipt.seq,"digest":receipt.digest}))?;
        self.replay_hash
            .update((identity.len() as u64).to_le_bytes());
        self.replay_hash.update(identity);
        let state = match self.run.state.as_str() {
            "prepared" => "prepared",
            "admitted" => "admitted",
            "denied" => "denied",
            "settled" => "settled",
            "outcome_unknown" => "outcome_unknown",
            _ => return Err(LedgerError("unsupported canonical run state".into())),
        };
        let labels_digest = crate::reader::snapshot_labels_digest(
            &self.run.child_protection,
            &crate::reader::coverage_summary(&self.run.coverage),
        )?;
        self.anchors.insert(
            receipt.seq,
            Anchor {
                bytes: self.accepted_bytes,
                digest: receipt.digest.clone(),
                state,
                labels_digest,
            },
        );
        Ok(())
    }

    fn manifest(&self) -> crate::manifest::Manifest {
        let hash = |h: &Sha256| -> String { format!("sha256:{:x}", h.clone().finalize()) };
        crate::manifest::Manifest {
            schema: schemas::SEGMENTS.into(),
            run_id: self.run.run_id.clone(),
            attempt_id: self.run.attempt_id.clone(),
            segments: self.segments.clone(),
            replay_digest: hash(&self.replay_hash),
        }
    }
}

fn original_payload(record: &Value) -> Value {
    if record["kind"] == "source" {
        let mut source = record.clone();
        let object = source.as_object_mut().expect("canonical source object");
        for key in [
            "run_id",
            "seq",
            "prev",
            "received_at",
            "provenance",
            "kind",
            "request_id",
        ] {
            object.remove(key);
        }
        return json!({"kind":"source","request_id":record["request_id"],"body":source});
    }
    let mut value = record.clone();
    let object = value.as_object_mut().expect("canonical record object");
    for key in [
        "schema",
        "run_id",
        "attempt_id",
        "seq",
        "prev",
        "received_at",
        "provenance",
    ] {
        object.remove(key);
    }
    value
}

/// Identity the writer assigns. No intent body may supply it, so a body can
/// never be read as the record's own provenance.
const RESERVED_BODY_KEYS: [&str; 9] = [
    "actor",
    "role",
    "provenance",
    "run_id",
    "attempt_id",
    "seq",
    "prev",
    "received_at",
    "token_id",
];

fn check_reserved(body: &Value, what: &str) -> Result<()> {
    match RESERVED_BODY_KEYS
        .iter()
        .find(|key| body.get(**key).is_some())
    {
        Some(key) => Err(LedgerError(format!(
            "{what} body cannot supply reserved identity {key}"
        ))),
        None => Ok(()),
    }
}

fn validate_intent(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["kind"].as_str().unwrap_or("");
    if !["admitted", "denied", "settled", "note", "outcome_unknown"].contains(&kind) {
        return Ok(());
    }
    let body = &record["body"];
    check_reserved(body, "intent")?;
    if kind == "note"
        && ["receipt", "coverage", "outcome", "capture"]
            .iter()
            .any(|field| body.get(field).is_some())
    {
        return Err(LedgerError(
            "notes cannot replace receipt or state projections".into(),
        ));
    }
    let run = &stream.run;
    if let Some(receipt) = body.get("receipt") {
        validate_receipt(receipt)?;
        if receipt["attempt_id"] != run.attempt_id {
            return Err(LedgerError("receipt belongs to a different attempt".into()));
        }
        if let Some(claimed) = body.get("receipt_digest")
            && claimed
                != &json!(
                    records::semantic::receipt_digest(receipt).map_err(|_| LedgerError(
                        "receipt has unsupported canonical values".into()
                    ))?
                )
        {
            return Err(LedgerError(
                "intent receipt digest does not match the embedded receipt".into(),
            ));
        }
        if body
            .get("outcome")
            .is_some_and(|outcome| outcome != &receipt["outcome"])
            || body
                .get("coverage")
                .is_some_and(|coverage| coverage != &receipt["coverage"])
        {
            return Err(LedgerError(
                "intent outcome or coverage does not match its receipt".into(),
            ));
        }
        if kind == "denied" && receipt["phase"] != "refused" {
            return Err(LedgerError("denial requires a refused receipt".into()));
        }
    }
    if kind == "admitted" || kind == "settled" {
        let receipt = &body["receipt"];
        let valid_phase = if kind == "admitted" {
            receipt["phase"] == "prepared"
        } else {
            receipt["phase"] == "settled" || known_exec_failure(receipt)
        };
        if receipt["schema"] != records::SCHEMA_RECEIPT
            || !valid_phase
            || receipt["attempt_id"] != run.attempt_id
            || receipt["argv_digest"] != run.payload["argv_digest"]
            || receipt["policy"]["digest"] != run.payload["policy_digest"]
            || receipt["policy"]["requirements"] != run.payload["requirements"]
        {
            return Err(LedgerError(
                "intent receipt does not match prepared policy, argv, requirements and attempt"
                    .into(),
            ));
        }
        if run.payload["profile"] == "none" && receipt["child_protection"] != "unprotected" {
            return Err(LedgerError(
                "none cannot claim enforced child protection".into(),
            ));
        }
        if run.payload["evidence"] == "strict" && !stream.source_gaps.is_empty() {
            return Err(LedgerError(
                "strict source loss blocks admission and settlement".into(),
            ));
        }
    }
    if kind == "settled" || (kind == "denied" && body.get("receipt").is_some()) {
        let mut correlation = Vec::with_capacity(2);
        if let Some(loss) = &stream.first_loss {
            correlation.push(loss.clone());
        }
        if let Some(last) = &stream.last_source {
            correlation.push(last.clone());
        }
        if !records::semantic::trace_ends_with(&correlation, &body["receipt"]).is_empty() {
            return Err(LedgerError(
                "terminal trace and receipt do not corroborate".into(),
            ));
        }
    }
    Ok(())
}

// A jail refusal after durable admission can describe a proved failed exec,
// rather than a policy denial. The failed target never became an executing
// child, and the entire attempt boundary must still be verified empty.
fn known_exec_failure(receipt: &Value) -> bool {
    receipt["phase"] == "refused"
        && receipt["outcome"]["kind"] == "exec_error"
        && receipt["exec_observed"] == false
        && receipt["lifetime"]["tree_empty"] == true
        && receipt["lifetime"]["integrity"] == "verified"
        && receipt["lifetime"]["verification_scope"] == "attempt_tree"
}

fn validate_transition(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["kind"].as_str().unwrap_or("");
    if kind == "prepared" && stream.run.chain.head_seq != 0 {
        return Err(LedgerError("duplicate preparation".into()));
    }
    if let Some(effect_id) = record["effect_id"].as_str() {
        let effect_key = operator::effect_key(record, effect_id);
        if let Some(previous) = stream.replay.get(&effect_key) {
            if previous.digest != digest(record)? {
                return Err(LedgerError(
                    "effect id conflicts with its immutable payload".into(),
                ));
            }
            return Err(LedgerError(
                "effect id already belongs to another request id".into(),
            ));
        }
    }
    match kind {
        "evidence_gap" => {
            let body = &record["body"];
            if stream.run.state != "admitted"
                || stream.run.payload["evidence"] != "best-effort"
                || body["reason"] != "writer_outage"
                || body["episode"].as_u64().is_none_or(|n| n == 0)
                || body["owner"] != serde_json::to_value(&stream.run.owner)?
                || body.as_object().is_none_or(|o| o.len() != 3)
            {
                return Err(LedgerError("invalid best-effort outage marker".into()));
            }
        }
        "operator_intent" => operator::validate(stream, record)?,
        "admitted" | "denied" if stream.run.state != "prepared" => {
            return Err(LedgerError(
                "admission or refusal is only valid from prepared".into(),
            ));
        }
        "settled" if stream.run.state != "admitted" => {
            return Err(LedgerError("settlement requires durable admission".into()));
        }
        "owner_claimed" if stream.run.owner.is_some() => {
            return Err(LedgerError("owner identity is immutable".into()));
        }
        "outcome_unknown" if ["settled", "denied"].contains(&stream.run.state.as_str()) => {
            return Err(LedgerError(
                "a recorded terminal outcome is immutable".into(),
            ));
        }
        "source" => {
            if ["settled", "denied", "outcome_unknown"].contains(&stream.run.state.as_str()) {
                return Err(LedgerError(
                    "terminal run cannot ingest new observations".into(),
                ));
            }
            let source = record["body"]["source"]
                .as_str()
                .ok_or_else(|| LedgerError("source name missing".into()))?;
            let seq = record["body"]["source_seq"]
                .as_u64()
                .ok_or_else(|| LedgerError("source seq missing".into()))?;
            if seq <= stream.source_heads.get(source).copied().unwrap_or(0) {
                return Err(LedgerError(
                    "producer source sequence reused or reordered".into(),
                ));
            }
            if record["body"]["operation"] == "jail.receipt" {
                let phase = record["body"]["fields"]["phase"]
                    .as_str()
                    .ok_or_else(|| LedgerError("receipt note phase missing".into()))?;
                if stream.receipt_phase.as_deref().is_some_and(|previous| {
                    previous != phase
                        && !matches!(
                            (previous, phase),
                            ("prepared", "enforced" | "settled" | "refused")
                                | ("enforced", "settled")
                        )
                }) {
                    return Err(LedgerError(
                        "receipt note lifecycle order is invalid".into(),
                    ));
                }
            }
        }
        "hold" | "release" => {
            if record["body"] != json!({}) || record.get("effect_id").is_some() {
                return Err(LedgerError(
                    "retention intents require an empty body and no effect id".into(),
                ));
            }
        }
        "prepared" | "owner_claimed" | "admitted" | "denied" | "settled" | "note"
        | "outcome_unknown" => {}
        _ => return Err(LedgerError("unknown durable record kind".into())),
    }
    Ok(())
}

fn apply_record(
    stream: &mut Stream,
    record: &Value,
    receipt: AppendReceipt,
    payload_digest: String,
) -> Result<()> {
    let request_id = record["request_id"]
        .as_str()
        .ok_or_else(|| LedgerError("record has no request identity".into()))?;
    if stream.replay.contains_key(request_id) {
        return Err(LedgerError(
            "duplicate request id in canonical stream".into(),
        ));
    }
    let replay = Replay {
        digest: payload_digest,
        receipt: receipt.clone(),
    };
    stream.replay.insert(request_id.into(), replay.clone());
    if let Some(effect_id) = record["effect_id"].as_str() {
        stream
            .replay
            .insert(operator::effect_key(record, effect_id), replay);
    }
    stream.run.chain = Chain {
        head_seq: receipt.seq,
        head_digest: Some(receipt.digest),
    };
    match record["kind"].as_str().unwrap_or("") {
        "evidence_gap" => stream.source_gaps.push(record["body"].clone()),
        "hold" => stream.run.holds = vec!["operator".into()],
        "release" => stream.run.holds.clear(),
        "owner_claimed" => {
            stream.run.owner = Some(serde_json::from_value(record["body"]["owner"].clone())?)
        }
        "admitted" => stream.run.state = "admitted".into(),
        "denied" => {
            stream.run.state = "denied".into();
            stream.run.settlement = "recorded".into();
        }
        "settled" => {
            stream.run.state = "settled".into();
            stream.run.settlement = "recorded".into();
        }
        "outcome_unknown" => {
            stream.run.state = "outcome_unknown".into();
            stream.run.settlement = "recorded".into();
        }
        "source" => {
            let source = record["body"]["source"].as_str().unwrap_or("");
            let seq = record["body"]["source_seq"].as_u64().unwrap_or(0);
            let previous = stream.source_heads.insert(source.into(), seq).unwrap_or(0);
            if seq != previous + 1 {
                stream.source_gaps.push(json!({"source":source,"from_source_seq":previous+1,"to_source_seq":seq-1,"at_source_seq":seq,"reason":"source sequence gap"}));
            }
            if record["body"]["fields"]["kind"] == "trace_transport_loss"
                && stream.first_loss.is_none()
            {
                stream.first_loss = Some(record["body"].clone());
                let fields = &record["body"]["fields"];
                stream.source_gaps.push(json!({"source":fields["source"],"at_source_seq":seq,"reason":"trace_transport_loss","start_ns":fields["start_ns"],"end_ns":fields["end_ns"],"classes":fields["classes"]}));
            }
            if record["body"]["operation"] == "jail.receipt" {
                stream.receipt_phase = record["body"]["fields"]["phase"]
                    .as_str()
                    .map(str::to_owned);
            }
            stream.last_source = Some(record["body"].clone());
        }
        _ => {}
    }
    // Source outcomes describe individual operations, not the terminal run.
    // Only authenticated owner/reconciliation intents update projections.
    let kind = record["kind"].as_str().unwrap_or("");
    if matches!(kind, "admitted" | "denied" | "settled" | "outcome_unknown") {
        let body = &record["body"];
        if let Some(receipt) = body.get("receipt") {
            stream.run.receipts.push(receipt.clone());
            if let Some(protection) = receipt.get("child_protection").and_then(Value::as_str)
                && (protection == "enforced" || protection == "unprotected")
            {
                stream.run.child_protection = protection.into();
            }
            if matches!(kind, "denied" | "settled") {
                stream.run.outcome = receipt.get("outcome").cloned();
            }
        }
        if kind == "outcome_unknown" {
            stream.run.outcome = Some(unknown_outcome(body.get("outcome")));
        } else if let Some(outcome) = body.get("outcome") {
            stream.run.outcome = Some(outcome.clone());
        }
        if let Some(coverage) = body.get("coverage") {
            stream.run.coverage = coverage.clone();
        }
        if let Some(capture) = body.get("capture") {
            stream.run.capture = capture.clone();
        }
    }
    // none remains unprotected regardless of an owner's requested display label.
    if stream.run.payload["profile"] == "none" {
        stream.run.child_protection = "unprotected".into();
    }
    if !stream.source_gaps.is_empty() {
        if !stream.run.coverage.is_object() {
            stream.run.coverage = json!({"source_coverage":stream.run.coverage});
        }
        stream.run.coverage["ledger"] = json!({"status":"degraded","gaps":stream.source_gaps});
    }
    Ok(())
}

const UNRESOLVED: &str = "owner or reconciliation reported an unresolved run outcome";

/// The projection of an unresolved run (run projection rule 2). A child
/// outcome the owner did observe stays beside the unknown; an owner's or
/// reconciler's own unknown is not a child outcome, so its reason becomes
/// the run's.
fn unknown_outcome(reported: Option<&Value>) -> Value {
    match reported {
        Some(child) if child["kind"] != "unknown" => json!({"kind":"unknown","unknown":true,
            "unknown_reason":UNRESOLVED,"observed_child_outcome":child}),
        reported => json!({"kind":"unknown","unknown":true,"unknown_reason":reported
            .and_then(|outcome| outcome["unknown_reason"].as_str())
            .unwrap_or(UNRESOLVED)}),
    }
}

fn validate_recovery(stream: &Stream, record: &Value, role: &str) -> Result<()> {
    if role == "recovery"
        && (stream.run.payload["evidence"] != "best-effort"
            || stream.run.state != "admitted"
            || stream.run.owner.is_none()
            || !["source", "evidence_gap", "settled", "outcome_unknown"]
                .contains(&record["kind"].as_str().unwrap_or("")))
    {
        return Err(LedgerError(
            "recovery requires an already admitted best-effort run".into(),
        ));
    }
    if record["kind"] == "evidence_gap" && role != "recovery" {
        return Err(LedgerError(
            "outage markers require recovery provenance".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    mod redaction;

    /// The call failed with the refusal named by `expected`, not with some
    /// unrelated error that merely makes it fail.
    #[track_caller]
    pub(super) fn assert_refused<T>(result: Result<T>, expected: &str) {
        match result {
            Ok(_) => panic!("expected a refusal containing {expected:?}, but the call succeeded"),
            Err(error) => assert!(
                error.0.contains(expected),
                "expected a refusal containing {expected:?}, got {:?}",
                error.0
            ),
        }
    }

    pub(super) fn peer() -> Peer {
        Peer {
            uid: crate::os::euid(),
            pid: std::process::id(),
            birth: "fixture-birth".into(),
            boot_id: "fixture-boot".into(),
        }
    }
    pub(super) fn payload() -> Value {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        json!({"schema":"ouro.ledger.request/1","profile":"tool","argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],"jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},"capture":{"streams":[],"limit_bytes":1_048_576},"evidence":"strict"})
    }

    #[test]
    fn detached_request_lifetime_is_validated_and_cannot_rebind_a_request() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let mut plan = payload();
        plan["owner_lifetime"] = "systemd_user_service".into();
        let run = store.prepare("detached", &plan, &peer()).unwrap();
        assert_refused(
            store.prepare("detached", &payload(), &peer()),
            "request id already maps to a different prepare payload",
        );
        drop(store);
        let mut store = Store::open(temp.path()).unwrap();
        assert_eq!(
            store.prepare("detached", &plan, &peer()).unwrap().run_id,
            run.run_id
        );
        plan["io"]["mode"] = "foreground".into();
        assert_refused(
            store.prepare("foreground", &plan, &peer()),
            "prepare only accepts the versioned digest-only request plan",
        );
        plan["io"]["mode"] = "batch".into();
        plan["owner_lifetime"] = "unchecked_double_fork".into();
        assert_refused(
            store.prepare("unproved", &plan, &peer()),
            "prepare only accepts the versioned digest-only request plan",
        );
    }
    fn prepared(run: &RunRecord) -> Value {
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        receipt
    }

    #[test]
    fn pending_recovery_keeps_the_journal_through_canonical_persistence_failures() {
        use crate::pending::Journal;
        for fault in [
            Fault::BeforeWrite,
            Fault::PartialWrite,
            Fault::EventSync,
            Fault::Projection,
            Fault::Manifest,
            Fault::DirectorySync,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            let mut store = Store::open(&data).unwrap();
            let mut plan = payload();
            plan["evidence"] = "best-effort".into();
            let run = store.prepare("pending-fault", &plan, &peer()).unwrap();
            store.claim_owner(&run.run_id, &peer()).unwrap();
            store
                .append_owner(
                    &run.run_id,
                    "admission",
                    "admitted",
                    None,
                    &json!({"receipt":prepared(&run)}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap();
            let run = store.show(&run.run_id).unwrap();
            let dir = store.root.join(&run.run_id);
            let journal = Journal::open(&dir).unwrap();
            journal.create(&run, &peer()).unwrap();
            let mut pending = journal.read(&run).unwrap();
            pending
                .push(
                    serde_json::to_value(records::Event::lifecycle_note(
                        &run.attempt_id,
                        1,
                        SystemTime::now(),
                        1,
                        "pending_test",
                    ))
                    .unwrap(),
                )
                .unwrap();
            journal.save(&pending).unwrap();
            let before = fs::read(dir.join("owner-pending.json")).unwrap();
            drop(journal);
            store.fault = Some(fault);
            assert!(
                store
                    .reconcile_pending(&run.run_id, &peer(), &|_| true)
                    .is_err()
            );
            assert_eq!(fs::read(dir.join("owner-pending.json")).unwrap(), before);
            drop(store);
            let mut store = Store::open(&data).unwrap();
            let result = store.reconcile_pending(&run.run_id, &peer(), &|_| true);
            if matches!(fault, Fault::PartialWrite) {
                assert_refused(
                    result,
                    "ambiguous canonical history refuses pending recovery",
                );
                assert!(!store.verify(None).unwrap()[0].local_consistency);
            } else {
                let recovered = result.unwrap();
                assert_eq!(recovered.chain.head_seq, run.chain.head_seq + 2);
                assert_eq!(
                    store
                        .reconcile_pending(&run.run_id, &peer(), &|_| true)
                        .unwrap()
                        .chain,
                    recovered.chain
                );
                assert!(store.verify(None).unwrap()[0].local_consistency);
            }
        }
    }
    #[test]
    fn orphan_settlement_records_why_pending_evidence_was_refused() {
        use crate::pending::{Journal, STATE};
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["evidence"] = "best-effort".into();
        let run = store.prepare("pending-refused", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store
            .append_owner(
                &run.run_id,
                "admission",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let run = store.show(&run.run_id).unwrap();
        let directory = store.root.join(&run.run_id);
        Journal::open(&directory)
            .unwrap()
            .create(&run, &peer())
            .unwrap();
        // Decoding this journal fails with an error that quotes its value.
        fs::write(
            directory.join(STATE),
            b"{\"state\":\"journal-value-7f3a\",\"digest\":\"x\"}",
        )
        .unwrap();
        let refusal = store
            .reconcile_pending(&run.run_id, &peer(), &|_| false)
            .unwrap_err();
        assert!(refusal.0.contains("journal-value-7f3a"), "{refusal}");
        let settled = store.settle_orphans(&peer(), |_| false).unwrap();
        assert_eq!(settled[0].state, "outcome_unknown");
        assert_eq!(
            settled[0].outcome.as_ref().unwrap()["unknown_reason"],
            "pending evidence could not be reconciled"
        );
        let stream = fs::read(directory.join(STREAM)).unwrap();
        let last: Value = serde_json::from_slice(
            stream[..stream.len() - 1]
                .rsplit(|b| *b == b'\n')
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(last["request_id"], "reconcile:pending-invalid");
        // History keeps the refusal's class, never its text.
        assert_eq!(
            last["body"],
            json!({"reason":"invalid_pending_evidence","refusal":"journal_unreadable",
                "outcome":{"kind":"unknown","unknown":true,
                    "unknown_reason":"pending evidence could not be reconciled"},
                "coverage":{"status":"degraded","gaps":[{"reason":"invalid_pending_evidence"}]}})
        );
        assert!(!String::from_utf8_lossy(&stream).contains("journal-value-7f3a"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreconcilable_pending_evidence_is_recorded_once_and_retried_only_after_a_change() {
        use crate::pending::{Journal, STATE};
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["evidence"] = "best-effort".into();
        let run = store.prepare("pending-invalid", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store
            .append_owner(
                &run.run_id,
                "admission",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let run = store.show(&run.run_id).unwrap();
        let journal = store.root.join(&run.run_id).join(STATE);
        Journal::open(&store.root.join(&run.run_id))
            .unwrap()
            .create(&run, &peer())
            .unwrap();
        fs::write(&journal, b"{\"damaged\":true}").unwrap();
        // The fixture owner's birth identity is not this process's: it is dead.
        store.recover_pending_orphans(&peer());
        let recorded = store.show(&run.run_id).unwrap();
        assert_eq!(recorded.state, "outcome_unknown");
        assert_eq!(
            recorded.outcome.unwrap()["unknown_reason"],
            "pending evidence could not be reconciled"
        );
        assert!(journal.exists(), "the refused journal stays for inspection");
        // Reconciliation opens (and recreates) the journal's lock file, so its
        // absence shows an unchanged journal was not retried.
        let lock = store.root.join(&run.run_id).join("owner-pending.lock");
        fs::remove_file(&lock).unwrap();
        store.recover_pending_orphans(&peer());
        assert!(!lock.exists(), "an unchanged failed journal was retried");
        fs::write(&journal, b"{\"damaged\":\"again\"}").unwrap();
        store.recover_pending_orphans(&peer());
        assert!(lock.exists(), "a changed journal must be retried");
        assert_eq!(
            store.show(&run.run_id).unwrap().chain,
            recorded.chain,
            "a terminal run gains no second unknown outcome"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reconciliation_the_journal_did_not_refuse_is_neither_recorded_nor_cached() {
        use crate::pending::Journal;
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["evidence"] = "best-effort".into();
        let run = store.prepare("pending-busy", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store
            .append_owner(
                &run.run_id,
                "admission",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let run = store.show(&run.run_id).unwrap();
        let journal = Journal::open(&store.root.join(&run.run_id)).unwrap();
        journal.create(&run, &peer()).unwrap();
        // While another holder keeps the journal locked, nothing is decided.
        store.recover_pending_orphans(&peer());
        assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
        drop(journal);
        // The unchanged journal is tried again and reconciled.
        store.recover_pending_orphans(&peer());
        let reconciled = store.show(&run.run_id).unwrap();
        assert_eq!(reconciled.state, "outcome_unknown");
        assert_eq!(
            reconciled.outcome.unwrap()["unknown_reason"],
            "pending owner has no durable local exit record"
        );
    }

    fn create() -> (tempfile::TempDir, Store, RunRecord) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("test-prepare", &payload(), &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        (temp, store, run)
    }

    #[test]
    fn retention_holds_replay_without_reapplying_an_old_intent_after_release() {
        let (temp, mut store, run) = create();
        store.segment_limit = 1;
        let original = fs::read(store.root.join(&run.run_id).join(STREAM)).unwrap();
        let held = store.hold(&run.run_id, "hold-1", &peer()).unwrap();
        assert_eq!(store.show(&run.run_id).unwrap().holds, ["operator"]);
        assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
        assert_refused(
            store.release(&run.run_id, "hold-1", &peer()),
            "request id conflicts with its immutable payload",
        );
        let released = store.release(&run.run_id, "release-1", &peer()).unwrap();
        assert_eq!(released.seq, held.seq + 1);
        assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
        assert!(store.show(&run.run_id).unwrap().holds.is_empty());
        assert_refused(
            store.append_owner(
                &run.run_id,
                "forged",
                "hold",
                None,
                &json!({}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "invalid owner intent",
        );
        let path = store.root.join(&run.run_id).join(manifest::name(2));
        let record: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(record["provenance"]["role"], "operator");
        assert!(record["provenance"]["token_id"].is_null());
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(store.hold(&run.run_id, "hold-1", &peer()).unwrap(), held);
        assert_eq!(
            store.release(&run.run_id, "release-1", &peer()).unwrap(),
            released
        );
        assert!(store.show(&run.run_id).unwrap().holds.is_empty());
        store.hold(&run.run_id, "hold-2", &peer()).unwrap();
        assert_eq!(
            store.release(&run.run_id, "release-1", &peer()).unwrap(),
            released
        );
        assert_eq!(store.show(&run.run_id).unwrap().holds, ["operator"]);
        assert_eq!(
            fs::read(store.root.join(&run.run_id).join(STREAM)).unwrap(),
            original
        );
        assert!(store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        assert_eq!(
            Store::open(&temp.path().join("data"))
                .unwrap()
                .show(&run.run_id)
                .unwrap()
                .holds,
            ["operator"]
        );
    }

    #[test]
    fn retention_faults_preserve_history_and_recover_one_original_receipt() {
        for release in [false, true] {
            for fault in [
                Fault::BeforeWrite,
                Fault::RotationCreated,
                Fault::RotationSynced,
                Fault::PartialWrite,
                Fault::EventSync,
                Fault::Projection,
                Fault::Manifest,
                Fault::DirectorySync,
            ] {
                let (temp, mut store, run) = create();
                if release {
                    store.hold(&run.run_id, "first-hold", &peer()).unwrap();
                }
                store.segment_limit = 1;
                let before = store.show(&run.run_id).unwrap().chain.head_seq;
                store.fault = Some(fault);
                let apply = |store: &mut Store| {
                    if release {
                        store.release(&run.run_id, "retry", &peer())
                    } else {
                        store.hold(&run.run_id, "retry", &peer())
                    }
                };
                assert!(apply(&mut store).is_err());
                store.fault = None;
                assert!(
                    apply(&mut store).is_err(),
                    "uncertain writes cannot acknowledge before restart"
                );
                let directory = store.root.join(&run.run_id);
                let history = manifest::names(&directory)
                    .unwrap()
                    .into_iter()
                    .map(|name| {
                        let bytes = fs::read(directory.join(&name)).unwrap();
                        (name, bytes)
                    })
                    .collect::<Vec<_>>();
                drop(store);
                let mut store = Store::open(&temp.path().join("data")).unwrap();
                for (name, bytes) in &history {
                    assert_eq!(&fs::read(directory.join(name)).unwrap(), bytes);
                }
                if matches!(fault, Fault::PartialWrite) {
                    assert_refused(
                        apply(&mut store),
                        "stream is poisoned; no dependent dispatch or sequence reuse",
                    );
                    assert!(!store.verify(None).unwrap()[0].local_consistency);
                } else {
                    let receipt = apply(&mut store).unwrap();
                    assert_eq!(receipt.seq, before + 1);
                    assert_eq!(apply(&mut store).unwrap(), receipt);
                    assert_eq!(store.show(&run.run_id).unwrap().holds.is_empty(), release);
                    assert!(store.verify(None).unwrap()[0].local_consistency);
                }
            }
        }
    }

    #[test]
    fn retention_preview_keeps_active_unknown_held_recent_and_damaged_runs() {
        use std::time::Duration;
        let (_temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "denial",
                "denied",
                None,
                &json!({"outcome":{"kind":"refused"}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let now = SystemTime::now();
        let future = now + Duration::from_secs(90 * 86_400);
        let plan = store.gc_plan_at(90, None, 100, now).unwrap();
        assert!(
            plan.runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "retention_window")
        );
        assert!(
            store
                .gc_plan_at(90, None, 100, now - Duration::from_secs(10))
                .unwrap()
                .runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "clock_before_activity")
        );
        assert!(store.gc_plan_at(90, None, 100, future).unwrap().runs[0].candidate);
        store.hold(&run.run_id, "keep", &peer()).unwrap();
        assert!(
            store.gc_plan_at(90, None, 100, future).unwrap().runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "operator_hold")
        );
        store.release(&run.run_id, "unhold", &peer()).unwrap();
        let active = store.prepare("active", &payload(), &peer()).unwrap();
        let unknown = store.prepare("unknown", &payload(), &peer()).unwrap();
        store.claim_owner(&unknown.run_id, &peer()).unwrap();
        store
            .append_owner(
                &unknown.run_id,
                "unknown",
                "outcome_unknown",
                None,
                &json!({}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let plan = store.gc_plan_at(90, None, 100, future).unwrap();
        assert!(
            plan.runs
                .iter()
                .find(|r| r.run_id == active.run_id)
                .unwrap()
                .keep_reasons
                .iter()
                .any(|r| r == "active_run")
        );
        assert!(
            plan.runs
                .iter()
                .find(|r| r.run_id == unknown.run_id)
                .unwrap()
                .keep_reasons
                .iter()
                .any(|r| r == "outcome_unknown")
        );
        let first = store.gc_plan_at(90, None, 1, future).unwrap();
        let second = store
            .gc_plan_at(90, first.next_after.as_deref(), 100, future)
            .unwrap();
        assert_eq!(second.runs.len(), 2);
        assert!(second.runs.iter().all(|r| r.run_id > first.runs[0].run_id));
        assert!(second.next_after.is_none());
        assert_refused(
            store.gc_plan(0, None, 1),
            "retention requires 1..36500 days",
        );
        assert_refused(
            store.gc_plan(u32::MAX, None, 1),
            "retention requires 1..36500 days",
        );
        assert_refused(
            store.gc_plan(90, None, 101),
            "GC preview requires 1..36500 retention days and 1..100 runs per page",
        );
        assert_refused(store.gc_plan(90, Some("../escape"), 1), "invalid run id");
        assert!(serde_json::to_vec(&plan).unwrap().len() < MAX_FRAME_BYTES);
        let path = store.root.join(&run.run_id).join(STREAM);
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(b"partial").unwrap();
        let plan = store.gc_plan_at(90, None, 100, future).unwrap();
        assert!(
            plan.runs
                .iter()
                .find(|r| r.run_id == run.run_id)
                .unwrap()
                .keep_reasons
                .iter()
                .any(|r| r == "canonical_layout_changed")
        );
    }

    #[test]
    fn retention_preview_pins_durable_readers_without_expiring_or_repairing_files() {
        use std::time::Duration;
        let (temp, mut store, run) = create();
        store
            .read(&read_request(&run, crate::protocol::ReadSelector::All))
            .unwrap();
        let directory = store.root.join("readers");
        let checkpoint = fs::read_dir(&directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let bytes = fs::read(&checkpoint).unwrap();
        drop(store);
        let store = Store::open(&temp.path().join("data")).unwrap();
        let now = SystemTime::now();
        let plan = store.gc_plan_at(90, None, 100, now).unwrap();
        assert!(
            plan.runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "reader_snapshot")
        );
        let later = store
            .gc_plan_at(90, None, 100, now + Duration::from_secs(601))
            .unwrap();
        assert!(
            !later.runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "reader_snapshot")
        );
        assert_eq!(fs::read(&checkpoint).unwrap(), bytes);
        fs::write(&checkpoint, b"corrupt").unwrap();
        assert!(
            store.gc_plan_at(90, None, 100, now).unwrap().runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "reader_checkpoint_unknown")
        );
        assert_eq!(fs::read(&checkpoint).unwrap(), b"corrupt");
        fs::remove_file(&checkpoint).unwrap();
        std::os::unix::fs::symlink("../writer.lock", &checkpoint).unwrap();
        assert!(
            store.gc_plan_at(90, None, 100, now).unwrap().runs[0]
                .keep_reasons
                .iter()
                .any(|r| r == "reader_checkpoint_unknown")
        );
    }
    fn note(store: &mut Store, run: &RunRecord, key: &str, body: Value) -> Result<AppendReceipt> {
        store.append_owner(
            &run.run_id,
            key,
            "note",
            None,
            &body,
            &peer(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
    }

    pub(super) fn gc_fixture() -> (tempfile::TempDir, Store, RunRecord) {
        gc_fixture_captures(&[("stdout", b"private-capture")])
    }

    pub(super) fn gc_fixture_captures(
        captures: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, Store, RunRecord) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        plan["capture"]["streams"] =
            json!(captures.iter().map(|(name, _)| *name).collect::<Vec<_>>());
        let run = store.prepare("gc-prepare", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        store.segment_limit = 1;
        source_fixture(&mut store, &run, "exec", 1, None);
        store
            .append_owner(
                &run.run_id,
                "gc-note",
                "note",
                Some("effect-1"),
                &json!({"note":"private-note-body"}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let mut metadata =
            json!({"stdout":{"state":"not_captured"},"stderr":{"state":"not_captured"}});
        for (name, contents) in captures {
            let path = format!("artifacts/{name}.bin");
            let mut file =
                private_file(&store.root.join(&run.run_id).join(&path), true, false).unwrap();
            file.write_all(contents).unwrap();
            file.sync_all().unwrap();
            metadata[name] = json!({"state":"captured","stored_bytes":contents.len(),"path":path});
        }
        store
            .append_owner(
                &run.run_id,
                "gc-denial",
                "denied",
                None,
                &json!({"outcome":{"kind":"refused"},"capture":metadata}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        (temp, store, run)
    }

    pub(super) fn gc_future() -> SystemTime {
        SystemTime::now() + std::time::Duration::from_secs(2 * 86_400)
    }

    fn capture_policy() -> ouro_records::retention::RetentionPolicy {
        ouro_records::retention::RetentionPolicy {
            retain_days: 90,
            capture_retain_days: 1,
        }
    }

    #[test]
    fn capture_expiry_preserves_canonical_bytes_queries_replays_and_later_history_gc() {
        let (temp, mut store, run) = gc_fixture();
        let directory = store.root.join(&run.run_id);
        let snapshots: Vec<_> = manifest::names(&directory)
            .unwrap()
            .into_iter()
            .map(|n| (n.clone(), fs::read(directory.join(n)).unwrap()))
            .collect();
        let before = store.show(&run.run_id).unwrap();
        let plan = store
            .gc_plan_policy_at(capture_policy(), None, 100, gc_future())
            .unwrap();
        assert!(!plan.runs[0].candidate);
        assert!(plan.runs[0].captures_candidate);
        let result = store
            .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
            .unwrap();
        assert!(result.failed.is_empty(), "{:?}", result.failed);
        assert!(result.pruned.is_empty());
        assert_eq!(result.captures_pruned[0].removed_bytes, 15);
        assert!(!directory.join("artifacts/stdout.bin").exists());
        let after = store.show(&run.run_id).unwrap();
        assert_eq!(after.chain, before.chain);
        assert!(after.history.is_none());
        assert_eq!(after.capture_history.as_ref().unwrap().state, "pruned");
        assert_eq!(after.capture["stdout"]["pruned_bytes"], 15);
        assert_eq!(after.child_protection, "unprotected");
        assert!(store.verify(None).unwrap()[0].local_consistency);
        for (name, bytes) in &snapshots {
            assert_eq!(fs::read(directory.join(name)).unwrap(), *bytes);
        }
        let held = store
            .hold(&run.run_id, "after-capture-expiry", &peer())
            .unwrap();
        drop(store);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            store
                .hold(&run.run_id, "after-capture-expiry", &peer())
                .unwrap(),
            held
        );
        assert_eq!(
            store.show(&run.run_id).unwrap().capture["stdout"]["state"],
            "pruned"
        );
        assert!(store.verify(None).unwrap()[0].local_consistency);
        store
            .release(&run.run_id, "release-after-expiry", &peer())
            .unwrap();
        let whole = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert!(whole.failed.is_empty(), "{:?}", whole.failed);
        assert_eq!(whole.pruned.len(), 1);
        drop(store);
        let store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            store.show(&run.run_id).unwrap().capture["stdout"]["pruned_bytes"],
            15
        );
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn capture_expiry_recovers_each_deletion_boundary_and_never_removes_history() {
        for fault in [
            Fault::GcIntentWrite,
            Fault::GcIntentSync,
            Fault::GcBeforeUnlink,
            Fault::GcAfterUnlink,
            Fault::GcDirectorySync,
            Fault::GcCompletion,
            Fault::GcCompletionSync,
            Fault::GcProjection,
        ] {
            let (temp, mut store, run) =
                gc_fixture_captures(&[("stdout", b"private-capture"), ("stderr", b"second")]);
            let directory = store.root.join(&run.run_id);
            let names = manifest::names(&directory).unwrap();
            let original: Vec<_> = names
                .iter()
                .map(|n| fs::read(directory.join(n)).unwrap())
                .collect();
            store.fault = Some(fault);
            let result = store
                .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                .unwrap();
            assert_eq!(result.failed.len(), 1);
            if matches!(
                fault,
                Fault::GcIntentWrite | Fault::GcIntentSync | Fault::GcBeforeUnlink
            ) {
                assert_eq!(
                    fs::read(directory.join("artifacts/stdout.bin")).unwrap(),
                    b"private-capture"
                );
            }
            if matches!(fault, Fault::GcIntentSync | Fault::GcBeforeUnlink) {
                assert_refused(
                    store.hold(&run.run_id, "during-expiry", &peer()),
                    "capture pruning is incomplete; retry GC or restart before mutations",
                );
                let _ = store.verify(None); // A verifier cannot delete the pending capture.
                assert!(directory.join("artifacts/stdout.bin").exists());
            }
            drop(store);
            let mut store = Store::open(&temp.path().join("data")).unwrap();
            let retry = store
                .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                .unwrap();
            assert!(retry.failed.is_empty(), "{:?}", retry.failed);
            assert!(!directory.join("artifacts/stdout.bin").exists());
            assert!(!directory.join("artifacts/stderr.bin").exists());
            assert!(store.verify(None).unwrap()[0].local_consistency);
            for (name, bytes) in names.iter().zip(original) {
                assert_eq!(fs::read(directory.join(name)).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn capture_expiry_refuses_changed_reappearing_or_unanchored_files() {
        for mode in [
            "changed",
            "symlink",
            "hardlink",
            "anchor",
            "reappeared",
            "canonical",
            "chain",
            "segment",
        ] {
            let (temp, mut store, run) = gc_fixture();
            let directory = store.root.join(&run.run_id);
            store.fault = Some(Fault::GcBeforeUnlink);
            assert_eq!(
                store
                    .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                    .unwrap()
                    .failed
                    .len(),
                1
            );
            store.fault = None;
            let path = directory.join("artifacts/stdout.bin");
            match mode {
                "changed" => fs::write(&path, b"changed-capture").unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink("../events-0001.ndjson", &path).unwrap();
                }
                "hardlink" => {
                    fs::remove_file(&path).unwrap();
                    fs::hard_link(directory.join(STREAM), &path).unwrap();
                }
                "anchor" => fs::write(directory.join("captures-gc.json"), b"corrupt").unwrap(),
                "chain" | "segment" => {
                    let path = directory.join("captures-gc.json");
                    let mut anchor: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    if mode == "chain" {
                        anchor["retained"]["chain"]["head_digest"] =
                            json!(format!("sha256:{}", "a".repeat(64)));
                    } else {
                        anchor["retained"]["files"][0]["path"] = json!(STREAM);
                    }
                    anchor["digest"] = json!(digest(&anchor["retained"]).unwrap());
                    let mut bytes = canonical(&anchor).unwrap();
                    bytes.push(b'\n');
                    fs::write(path, bytes).unwrap();
                }
                "canonical" => fs::write(directory.join(STREAM), b"corrupt\n").unwrap(),
                "reappeared" => {
                    store
                        .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
                        .unwrap();
                    private_file(&path, true, false)
                        .unwrap()
                        .write_all(b"private-capture")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(store);
            let opened = Store::open(&temp.path().join("data"));
            if matches!(mode, "canonical" | "hardlink") {
                assert!(!opened.unwrap().verify(None).unwrap()[0].local_consistency);
            } else {
                assert!(opened.is_err(), "{mode}");
            }
            assert!(fs::symlink_metadata(path).is_ok());
        }
    }

    #[test]
    fn capture_expiry_removes_empty_selected_files_without_claiming_removed_bytes() {
        let (_temp, mut store, run) = gc_fixture_captures(&[("stdout", b"")]);
        let result = store
            .gc_policy_at(capture_policy(), None, 100, &peer(), gc_future())
            .unwrap();
        assert!(result.failed.is_empty());
        assert_eq!(result.captures_pruned[0].removed_files, 1);
        assert_eq!(result.captures_pruned[0].removed_bytes, 0);
        assert!(
            !store
                .root
                .join(&run.run_id)
                .join("artifacts/stdout.bin")
                .exists()
        );
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn capture_expiry_keeps_holds_unknown_outcomes_active_runs_and_reader_pins() {
        for reason in [
            "operator_hold",
            "outcome_unknown",
            "active_run",
            "reader_snapshot",
        ] {
            let (_temp, mut store, run) = gc_fixture();
            match reason {
                "operator_hold" => {
                    store.hold(&run.run_id, "keep-captures", &peer()).unwrap();
                }
                "outcome_unknown" => {
                    store.streams.get_mut(&run.run_id).unwrap().run.state = "outcome_unknown".into()
                }
                "active_run" => {
                    store.streams.get_mut(&run.run_id).unwrap().run.state = "admitted".into()
                }
                "reader_snapshot" => {
                    let request = ReadRequest {
                        run_id: run.run_id.clone(),
                        filter: crate::protocol::ReadFilter {
                            selector: crate::protocol::ReadSelector::All,
                            stage: None,
                            since: None,
                            until: None,
                        },
                        limit: 1,
                        cursor: None,
                    };
                    store.read(&request).unwrap();
                }
                _ => unreachable!(),
            }
            // Reader expiry must not be simulated by moving the wall clock ahead.
            let plan = store
                .gc_plan_policy_at(
                    capture_policy(),
                    None,
                    100,
                    if reason == "reader_snapshot" {
                        SystemTime::now()
                    } else {
                        gc_future()
                    },
                )
                .unwrap();
            assert!(!plan.runs[0].captures_candidate);
            assert!(
                plan.runs[0]
                    .captures_keep_reasons
                    .iter()
                    .any(|s| s == reason)
            );
            assert!(
                store
                    .root
                    .join(&run.run_id)
                    .join("artifacts/stdout.bin")
                    .exists()
            );
        }
    }

    #[test]
    fn gc_prunes_segments_and_captures_but_preserves_replays_effects_and_none_labels() {
        let (temp, mut store, run) = gc_fixture();
        let original = store.show(&run.run_id).unwrap();
        let replay = store.stream(&run.run_id).unwrap().replay.clone();
        let directory = store.root.join(&run.run_id);
        let manifest = fs::read(directory.join("segments.json")).unwrap();
        let result = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert!(result.failed.is_empty(), "{:?}", result.failed);
        assert_eq!(result.pruned.len(), 1);
        assert!(result.pruned[0].removed_files >= 4);
        assert!(!directory.join(STREAM).exists());
        assert!(!directory.join("artifacts/stdout.bin").exists());
        assert_eq!(fs::read(directory.join("segments.json")).unwrap(), manifest);
        let anchor = fs::read_to_string(directory.join("gc.json")).unwrap();
        assert!(!anchor.contains("private-note-body") && !anchor.contains("private-capture"));
        let projected = store.show(&run.run_id).unwrap();
        assert_eq!(projected.chain, original.chain);
        assert_eq!(projected.state, "denied");
        assert_eq!(projected.child_protection, "unprotected");
        assert_eq!(projected.history.as_ref().unwrap().state, "pruned");
        assert_eq!(projected.capture["stdout"]["state"], "pruned");
        assert_eq!(projected.capture["stdout"]["stored_bytes"], 0);
        assert_eq!(projected.capture["stdout"]["pruned_bytes"], 15);
        assert!(
            store
                .read(&read_request(&run, crate::protocol::ReadSelector::All))
                .unwrap_err()
                .0
                .contains("pruned")
        );
        assert_refused(
            store.hold(&run.run_id, "too-late", &peer()),
            "run history was pruned; new mutations are refused",
        );
        store.flush_index();
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            recovered
                .prepare("gc-prepare", &run.payload, &peer())
                .unwrap()
                .run_id,
            run.run_id
        );
        let mut conflicting = run.payload.clone();
        conflicting["argv_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
        assert_refused(
            recovered.prepare("gc-prepare", &conflicting, &peer()),
            "request id already maps to a different prepare payload",
        );
        recovered.claim_owner(&run.run_id, &peer()).unwrap();
        let note = recovered
            .append_owner(
                &run.run_id,
                "gc-note",
                "note",
                Some("effect-1"),
                &json!({"note":"private-note-body"}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(note, replay["gc-note"].receipt);
        assert_refused(
            recovered.append_owner(
                &run.run_id,
                "new-key",
                "note",
                Some("effect-1"),
                &json!({"note":"private-note-body"}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "run history was pruned; new mutations are refused",
        );
        assert_refused(
            recovered.append_owner(
                &run.run_id,
                "gc-note",
                "note",
                Some("effect-1"),
                &json!({"note":"changed"}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "request id conflicts with its immutable payload",
        );
        source_fixture(&mut recovered, &run, "exec", 1, None);
        assert_eq!(recovered.stream(&run.run_id).unwrap().replay, replay);
        let verified = recovered.verify(Some(&run.run_id)).unwrap();
        assert!(verified[0].local_consistency, "{:?}", verified[0]);
        assert_eq!(verified[0].events, 0);
        assert_eq!(verified[0].history.as_ref().unwrap().state, "pruned");
        assert_eq!(verified[0].child_protection, "unprotected");
        let again = recovered.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert_eq!(
            serde_json::to_value(&again.pruned).unwrap(),
            serde_json::to_value(&result.pruned).unwrap()
        );
        assert_eq!(
            fs::read_to_string(directory.join("gc.json")).unwrap(),
            anchor
        );
    }

    #[test]
    fn gc_recovers_every_deletion_boundary_without_losing_replay_or_chain_anchors() {
        for fault in [
            Fault::GcIntentWrite,
            Fault::GcIntentSync,
            Fault::GcBeforeUnlink,
            Fault::GcAfterUnlink,
            Fault::GcDirectorySync,
            Fault::GcCompletion,
            Fault::GcCompletionSync,
            Fault::GcProjection,
        ] {
            let (temp, mut store, run) = gc_fixture();
            let replay = store.stream(&run.run_id).unwrap().replay.clone();
            let directory = store.root.join(&run.run_id);
            let manifest = fs::read(directory.join("segments.json")).unwrap();
            store.fault = Some(fault);
            let failed = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
            assert_eq!(failed.failed.len(), 1);
            assert!(failed.pruned.is_empty());
            if matches!(fault, Fault::GcIntentWrite) {
                assert!(!directory.join("gc.json").exists());
                assert!(directory.join(STREAM).exists());
            } else {
                assert!(directory.join("gc.json").exists());
                assert_refused(
                    store.read(&read_request(&run, crate::protocol::ReadSelector::All)),
                    "run history was pruned; canonical query and export are unavailable",
                );
                assert_refused(
                    store.hold(&run.run_id, "after-decision", &peer()),
                    "run history was pruned; new mutations are refused",
                );
            }
            drop(store);
            let mut recovered = Store::open(&temp.path().join("data")).unwrap();
            let retried = recovered.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
            assert!(retried.failed.is_empty(), "{:?}", retried.failed);
            assert_eq!(retried.pruned.len(), 1);
            assert_eq!(fs::read(directory.join("segments.json")).unwrap(), manifest);
            assert_eq!(recovered.stream(&run.run_id).unwrap().replay, replay);
            assert!(!directory.join(STREAM).exists());
            assert!(!directory.join("artifacts/stdout.bin").exists());
            assert!(recovered.verify(None).unwrap()[0].local_consistency);
        }
    }

    #[test]
    fn gc_revalidates_bytes_and_refuses_changed_files_or_symlinked_capture_directories() {
        for mode in ["canonical", "capture", "symlink", "anchor"] {
            let (temp, mut store, run) = gc_fixture();
            let directory = store.root.join(&run.run_id);
            let outside = temp.path().join("outside");
            private_directory(&outside).unwrap();
            fs::write(outside.join("stdout.bin"), b"must be kept").unwrap();
            if mode != "canonical" {
                store.fault = Some(Fault::GcBeforeUnlink);
                assert_eq!(
                    store
                        .gc_at(1, None, 100, &peer(), gc_future())
                        .unwrap()
                        .failed
                        .len(),
                    1
                );
                store.fault = None;
            }
            match mode {
                "canonical" => {
                    let path = directory.join(manifest::name(3));
                    let bytes = fs::read_to_string(&path).unwrap();
                    assert!(bytes.contains("private-note-body"));
                    fs::write(
                        path,
                        bytes.replace("private-note-body", "changed-note-body"),
                    )
                    .unwrap();
                }
                "capture" => {
                    fs::write(directory.join("artifacts/stdout.bin"), b"changed-capture").unwrap();
                }
                "symlink" => {
                    fs::rename(
                        directory.join("artifacts"),
                        directory.join("preserved-artifacts"),
                    )
                    .unwrap();
                    std::os::unix::fs::symlink(&outside, directory.join("artifacts")).unwrap();
                }
                "anchor" => {
                    fs::write(directory.join("gc.json"), b"broken\n").unwrap();
                }
                _ => unreachable!(),
            }
            let first = fs::read(directory.join(STREAM)).unwrap();
            let failed = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
            assert_eq!(failed.failed.len(), 1, "{mode}");
            assert_eq!(fs::read(directory.join(STREAM)).unwrap(), first);
            assert_eq!(
                fs::read(outside.join("stdout.bin")).unwrap(),
                b"must be kept"
            );
            if matches!(mode, "canonical" | "hardlink") {
                assert!(!directory.join("gc.json").exists());
            } else {
                drop(store);
                assert!(Store::open(&temp.path().join("data")).is_err());
            }
        }
    }

    #[test]
    fn gc_keeps_held_unknown_recent_and_live_reader_runs_and_refuses_active_launches() {
        let (_temp, mut store, run) = gc_fixture();
        assert!(store.gc(1, None, 100, &peer()).unwrap().pruned.is_empty());
        store.hold(&run.run_id, "hold", &peer()).unwrap();
        assert!(
            store
                .gc_at(1, None, 100, &peer(), gc_future())
                .unwrap()
                .pruned
                .is_empty()
        );
        store.release(&run.run_id, "release", &peer()).unwrap();
        let active = store.prepare("active", &payload(), &peer()).unwrap();
        store.claim_owner(&active.run_id, &peer()).unwrap();
        assert!(
            store
                .gc_at(1, None, 100, &peer(), gc_future())
                .unwrap_err()
                .0
                .contains("quiescent")
        );
        store.settle_orphans(&peer(), |_| false).unwrap();
        store
            .read(&read_request(&run, crate::protocol::ReadSelector::All))
            .unwrap();
        // Model a reader begun at the injected collection clock, after the run aged.
        let now = gc_future();
        let entry = fs::read_dir(store.root.join("readers"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut envelope: Value = serde_json::from_slice(&fs::read(&entry).unwrap()).unwrap();
        envelope["checkpoint"]["created"] =
            json!(now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
        envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
        fs::write(&entry, canonical(&envelope).unwrap()).unwrap();
        let result = store.gc_at(1, None, 100, &peer(), now).unwrap();
        assert!(result.pruned.is_empty());
        assert!(result.kept.iter().any(
            |r| r.run_id == run.run_id && r.keep_reasons.iter().any(|r| r == "reader_snapshot")
        ));
        assert!(
            result.kept.iter().any(|r| r.run_id == active.run_id
                && r.keep_reasons.iter().any(|r| r == "outcome_unknown"))
        );
        let result = store
            .gc_at(
                1,
                None,
                100,
                &peer(),
                now + std::time::Duration::from_secs(601),
            )
            .unwrap();
        assert_eq!(result.pruned.len(), 1);
        assert_eq!(result.pruned[0].run_id, run.run_id);
        assert_eq!(store.show(&active.run_id).unwrap().state, "outcome_unknown");
    }

    #[test]
    fn gc_never_removes_files_reappearing_after_completion() {
        let (temp, mut store, run) = gc_fixture();
        let directory = store.root.join(&run.run_id);
        assert_eq!(
            store
                .gc_at(1, None, 100, &peer(), gc_future())
                .unwrap()
                .pruned
                .len(),
            1
        );
        private_file(&directory.join(STREAM), true, false)
            .unwrap()
            .write_all(b"restored history")
            .unwrap();
        assert!(!store.verify(None).unwrap()[0].local_consistency);
        let retry = store.gc_at(1, None, 100, &peer(), gc_future()).unwrap();
        assert_eq!(retry.failed.len(), 1);
        assert_eq!(
            fs::read(directory.join(STREAM)).unwrap(),
            b"restored history"
        );
        drop(store);
        assert_refused(
            Store::open(&temp.path().join("data")),
            "GC inventory file identity or content changed; bytes preserved",
        );
        assert_eq!(
            fs::read(directory.join(STREAM)).unwrap(),
            b"restored history"
        );
    }

    fn read_request(run: &RunRecord, selector: crate::protocol::ReadSelector) -> ReadRequest {
        ReadRequest {
            run_id: run.run_id.clone(),
            filter: crate::protocol::ReadFilter {
                selector,
                stage: None,
                since: None,
                until: None,
            },
            cursor: None,
            limit: 100,
        }
    }

    fn read_all(store: &mut Store, mut request: ReadRequest) -> (Vec<ReadPage>, String) {
        let mut pages = vec![];
        let mut bytes = String::new();
        for _ in 0..1000 {
            let page = store.read(&request).unwrap();
            bytes.push_str(&page.ndjson);
            request.cursor = page.next_cursor.clone();
            let done = page.done;
            pages.push(page);
            if done {
                return (pages, bytes);
            }
        }
        panic!("reader did not finish its bounded snapshot");
    }

    fn source_fixture(
        store: &mut Store,
        run: &RunRecord,
        fixture: &str,
        seq: u64,
        path: Option<&str>,
    ) {
        let fixtures = [
            (
                "exec",
                include_str!("../../../docs/specs/jail-v1/examples/event-exec.json"),
            ),
            (
                "exit",
                include_str!("../../../docs/specs/jail-v1/examples/event-exit.json"),
            ),
            (
                "path",
                include_str!("../../../docs/specs/jail-v1/examples/event-open.json"),
            ),
            (
                "deny",
                include_str!("../../../docs/specs/jail-v1/examples/event-deny.json"),
            ),
            (
                "host",
                include_str!("../../../docs/specs/jail-v1/examples/event-connect.json"),
            ),
            (
                "proxy",
                include_str!("../../../docs/specs/jail-v1/examples/event-proxy-deny.json"),
            ),
        ];
        let mut event: Value = serde_json::from_str(
            fixtures
                .iter()
                .find(|(name, _)| *name == fixture)
                .unwrap()
                .1,
        )
        .unwrap();
        event["attempt_id"] = json!(run.attempt_id);
        event["source_seq"] = json!(seq);
        if let Some(path) = path {
            event["fields"]["path"]["value"] = json!(path);
        }
        store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
    }

    #[test]
    fn reader_snapshot_export_is_exact_bounded_and_retries_the_identical_prior_page() {
        let (temp, mut store, run) = create();
        for n in 0..80 {
            note(&mut store, &run, &format!("note:{n}"), json!({"index":n})).unwrap();
        }
        let path = temp
            .path()
            .join("data/ledger")
            .join(&run.run_id)
            .join(STREAM);
        let original = fs::read_to_string(&path).unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let first = store.read(&request).unwrap();
        assert!(!first.done);
        assert!(first.scanned_through_seq <= crate::protocol::READ_SCAN_FRAMES as u64);
        let snapshot = first.snapshot.clone();
        note(&mut store, &run, "after-snapshot", json!({"later":true})).unwrap();
        request.cursor = first.next_cursor.clone();
        let second = store.read(&request).unwrap();
        assert_eq!(second, store.read(&request).unwrap());
        assert_eq!(second.snapshot, snapshot);
        request.cursor = second.next_cursor.clone();
        let (pages, remaining) = read_all(&mut store, request);
        assert_eq!(
            format!("{}{}{}", first.ndjson, second.ndjson, remaining),
            original
        );
        assert!(pages.iter().all(|p| p.ndjson.len() <= crate::protocol::READ_CHUNK_BYTES && p.local_consistency));
        assert_eq!(
            store.show(&run.run_id).unwrap().chain.head_seq,
            snapshot.head_seq + 1
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap().lines().count() as u64,
            snapshot.head_seq + 1
        );
    }

    #[test]
    fn reader_filters_original_source_operations_stage_and_writer_time() {
        let (_temp, mut store, run) = create();
        for (fixture, seq) in [
            ("exec", 1),
            ("exit", 2),
            ("path", 3),
            ("deny", 4),
            ("host", 5),
            ("proxy", 1),
        ] {
            source_fixture(&mut store, &run, fixture, seq, None);
        }
        for (selector, count) in [
            (crate::protocol::ReadSelector::Execs, 2),
            (crate::protocol::ReadSelector::Paths, 2),
            (crate::protocol::ReadSelector::Hosts, 2),
            (crate::protocol::ReadSelector::Denials, 2),
        ] {
            let (pages, _) = read_all(&mut store, read_request(&run, selector));
            let events: Vec<_> = pages.iter().flat_map(|p| &p.records).collect();
            assert_eq!(events.len(), count);
            assert!(events.iter().all(|e| e["schema"] == records::SCHEMA_EVENT
                && e["stage"] == "result"
                && e["provenance"]["role"] == "producer"));
        }
        let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
        request.filter.stage = Some(crate::protocol::ReadStage::Attempt);
        let (pages, _) = read_all(&mut store, request);
        assert!(pages.iter().all(|p| p.records.is_empty()));
        let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
        request.filter.since = Some("2099-01-01T00:00:00Z".into());
        assert!(
            read_all(&mut store, request)
                .0
                .iter()
                .all(|p| p.records.is_empty())
        );
        let mut request = read_request(&run, crate::protocol::ReadSelector::Execs);
        request.filter.until = Some("2000-01-01T00:00:00Z".into());
        assert!(
            read_all(&mut store, request)
                .0
                .iter()
                .all(|p| p.records.is_empty())
        );
    }

    #[test]
    fn reader_large_utf8_records_are_fully_verified_before_chunks_and_query_block_replays() {
        let (temp, mut store, run) = create();
        source_fixture(&mut store, &run, "path", 1, Some("small"));
        source_fixture(&mut store, &run, "path", 2, Some(&"€\\\"".repeat(80_000)));
        let original = fs::read_to_string(
            temp.path()
                .join("data/ledger")
                .join(&run.run_id)
                .join(STREAM),
        )
        .unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::Paths);
        let mut blocked = None;
        for _ in 0..100 {
            let page = store.read(&request).unwrap();
            if page.oversized_record.is_some() {
                assert_eq!(page, store.read(&request).unwrap());
                blocked = Some(page);
                break;
            }
            assert!(!page.done);
            request.cursor = page.next_cursor;
        }
        let blocked = blocked.unwrap();
        assert_eq!(blocked.oversized_record.unwrap().seq, 4);
        let (pages, export) = read_all(
            &mut store,
            read_request(&run, crate::protocol::ReadSelector::All),
        );
        assert_eq!(export, original);
        assert!(pages.iter().any(|p| p.ndjson.is_empty() && !p.done));
        for page in pages {
            assert!(page.ndjson.len() <= crate::protocol::READ_CHUNK_BYTES);
            let response = crate::protocol::Response::Ok {
                value: serde_json::to_value(&page).unwrap(),
            };
            assert!(serde_json::to_vec(&response).unwrap().len() < MAX_FRAME_BYTES);
            let mut frame = vec![];
            crate::daemon::write_frame(&mut frame, &response).unwrap();
        }
    }

    #[test]
    fn reader_refuses_filtered_corruption_and_reports_extra_tails_without_mutation() {
        let (temp, mut store, run) = create();
        note(&mut store, &run, "irrelevant", json!({"value":"original"})).unwrap();
        source_fixture(&mut store, &run, "exec", 1, None);
        let path = temp
            .path()
            .join("data/ledger")
            .join(&run.run_id)
            .join(STREAM);
        let original = fs::read_to_string(&path).unwrap();
        let altered = original.replace("original", "modified");
        fs::write(&path, &altered).unwrap();
        let (pages, _) = read_all(
            &mut store,
            read_request(&run, crate::protocol::ReadSelector::Execs),
        );
        assert!(pages.iter().all(|p| p.records.is_empty()));
        assert_eq!(pages.last().unwrap().stream_status, "corrupt");
        assert!(!pages.last().unwrap().local_consistency);
        assert_eq!(fs::read_to_string(&path).unwrap(), altered);
        fs::write(&path, format!("{original}{{\"torn\":")).unwrap();
        let (pages, bytes) = read_all(
            &mut store,
            read_request(&run, crate::protocol::ReadSelector::All),
        );
        assert_eq!(bytes, original);
        assert!(
            pages
                .iter()
                .all(|p| !p.local_consistency && p.stream_status == "incomplete")
        );
        assert!(fs::read_to_string(&path).unwrap().ends_with("{\"torn\":"));
    }

    #[test]
    fn reader_new_page_refuses_truncation_of_a_previously_verified_cached_large_frame() {
        let (temp, mut store, run) = create();
        source_fixture(&mut store, &run, "path", 1, Some(&"€".repeat(230_000)));
        let path = temp
            .path()
            .join("data/ledger")
            .join(&run.run_id)
            .join(STREAM);
        let length = fs::metadata(&path).unwrap().len();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let mut exercised = false;
        for _ in 0..100 {
            let page = store.read(&request).unwrap();
            if page.scanned_through_seq == 3 && !page.done && !page.ndjson.is_empty() {
                assert!(request.cursor.is_some());
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(length - 1)
                    .unwrap();
                // A lost reply may retry the exact historical page, but a new
                // continuation cannot publish the rest of its cached frame.
                assert_eq!(store.read(&request).unwrap(), page);
                request.cursor = page.next_cursor;
                let next = store.read(&request).unwrap();
                assert!(next.done && !next.local_consistency);
                assert_eq!(next.stream_status, "corrupt");
                assert!(next.ndjson.is_empty());
                assert!(next.problems.iter().any(|p| p.contains("truncated")));
                assert_eq!(fs::metadata(&path).unwrap().len(), length - 1);
                exercised = true;
                break;
            }
            assert!(!page.done);
            request.cursor = page.next_cursor;
        }
        assert!(exercised);
    }

    #[test]
    fn reader_cursor_cannot_change_scope_and_survives_restart() {
        let (temp, mut store, run) = create();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let request = read_request(&run, crate::protocol::ReadSelector::All);
        let page = store.read(&request).unwrap();
        let mut resumed = request.clone();
        resumed.cursor = page.next_cursor;
        let mut wrong = resumed.clone();
        wrong.filter.selector = crate::protocol::ReadSelector::Execs;
        assert!(store.read(&wrong).unwrap_err().0.contains("mismatch"));
        wrong = resumed.clone();
        wrong.limit += 1;
        assert!(store.read(&wrong).unwrap_err().0.contains("mismatch"));
        wrong = resumed.clone();
        wrong.cursor.as_mut().unwrap().replace_range(63..64, "z");
        assert_refused(store.read(&wrong), "invalid reader cursor");
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert!(recovered.read(&resumed).unwrap().local_consistency);
        for _ in 0..40 {
            assert!(
                read_all(
                    &mut recovered,
                    read_request(&run, crate::protocol::ReadSelector::Execs)
                )
                .0
                .last()
                .unwrap()
                .done
            );
        }
    }

    #[test]
    fn durable_reader_refuses_rechecksummed_forged_snapshot_labels() {
        for field in ["state", "child_protection", "coverage", "zero_head"] {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("data");
            let mut store = Store::open(&data).unwrap();
            let mut plan = payload();
            plan["profile"] = json!("none");
            let run = store.prepare("none-reader", &plan, &peer()).unwrap();
            store.claim_owner(&run.run_id, &peer()).unwrap();
            for n in 0..40 {
                note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
            }
            let mut request = read_request(&run, crate::protocol::ReadSelector::All);
            let first = store.read(&request).unwrap();
            assert_eq!(first.state, "prepared");
            assert_eq!(first.child_protection, "unprotected");
            request.cursor = first.next_cursor;
            let cursor = request.cursor.as_ref().unwrap();
            let checkpoint_path = store
                .root
                .join("readers")
                .join(format!("{}.json", &cursor[..32]));
            let canonical_path = store.root.join(&run.run_id).join(STREAM);
            let original = fs::read(&canonical_path).unwrap();
            drop(store);

            let mut envelope: Value =
                serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
            let template = &mut envelope["checkpoint"]["template"];
            match field {
                "state" => {
                    template["state"] = json!("settled");
                    template["stream_status"] = json!("complete");
                }
                "child_protection" => template["child_protection"] = json!("enforced"),
                "coverage" => template["coverage"]["status"] = json!("active"),
                "zero_head" => {
                    template["snapshot"] = json!({"head_seq":0,"head_digest":null});
                    template["state"] = json!("settled");
                    template["child_protection"] = json!("enforced");
                    template["stream_status"] = json!("complete");
                    envelope["checkpoint"]["accepted_bytes"] = json!(0);
                    envelope["checkpoint"]["position"] = json!({
                        "offset":0,"frame_start":0,"pending_bytes":0,
                        "ready_emitted":null,"next_seq":1,"previous_digest":null,"verified":0
                    });
                }
                _ => unreachable!(),
            }
            envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&checkpoint_path)
                .unwrap();
            file.write_all(&canonical(&envelope).unwrap()).unwrap();
            file.sync_all().unwrap();
            drop(file);

            let mut recovered = Store::open(&data).unwrap();
            let error = recovered.read(&request).unwrap_err();
            assert!(error.0.contains("snapshot"), "forged {field}: {}", error.0);
            assert!(recovered.verify(None).unwrap()[0].local_consistency);
            let canonical_run = recovered.show(&run.run_id).unwrap();
            assert_eq!(canonical_run.state, "prepared");
            assert_eq!(canonical_run.child_protection, "unprotected");
            assert_eq!(fs::read(&canonical_path).unwrap(), original);
        }
    }

    #[test]
    fn durable_reader_preserves_snapshot_labels_after_a_later_state_change() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        let run = store.prepare("none-reader", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let original = fs::read_to_string(store.root.join(&run.run_id).join(STREAM)).unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor.clone();
        assert!(request.cursor.is_some());
        store
            .append_owner(
                &run.run_id,
                "later-state",
                "outcome_unknown",
                None,
                &json!({"coverage":{"status":"degraded"}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        drop(store);

        let mut recovered = Store::open(&data).unwrap();
        assert_eq!(
            recovered.show(&run.run_id).unwrap().state,
            "outcome_unknown"
        );
        let second = recovered.read(&request).unwrap();
        assert_eq!(recovered.read(&request).unwrap(), second);
        let mut pages = vec![second.clone()];
        let mut exported = format!("{}{}", first.ndjson, second.ndjson);
        if !second.done {
            request.cursor = second.next_cursor;
            let (remaining, bytes) = read_all(&mut recovered, request);
            pages.extend(remaining);
            exported.push_str(&bytes);
        }
        for page in &pages {
            assert!(page.local_consistency);
            assert_eq!(page.snapshot, first.snapshot);
            assert_eq!(page.state, "prepared");
            assert_eq!(page.child_protection, "unprotected");
            assert_eq!(page.coverage, first.coverage);
        }
        assert!(pages.last().unwrap().done);
        assert_eq!(exported, original);
    }

    #[test]
    fn durable_reader_sync_failure_refuses_retries_until_recovery_barrier_succeeds() {
        let (_temp, mut store, run) = create();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let canonical_path = store.root.join(&run.run_id).join(STREAM);
        let original = fs::read_to_string(&canonical_path).unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor.clone();
        let cursor = request.cursor.as_ref().unwrap();
        let checkpoint_path = store
            .root
            .join("readers")
            .join(format!("{}.json", &cursor[..32]));
        let initial_checkpoint = fs::read(&checkpoint_path).unwrap();

        store.readers.fail_directory_sync = true;
        assert!(store.read(&request).is_err());
        let failed_checkpoint = fs::read(&checkpoint_path).unwrap();
        assert_ne!(failed_checkpoint, initial_checkpoint);
        let envelope: Value = serde_json::from_slice(&failed_checkpoint).unwrap();
        assert_eq!(envelope["checkpoint"]["prior"]["token"], cursor[32..]);
        assert!(store.read(&request).is_err());
        assert_eq!(fs::read(&checkpoint_path).unwrap(), failed_checkpoint);
        assert_eq!(fs::read_to_string(&canonical_path).unwrap(), original);

        store.readers.fail_directory_sync = false;
        let second = store.read(&request).unwrap();
        assert_eq!(
            json!(digest(&serde_json::to_value(&second).unwrap()).unwrap()),
            envelope["checkpoint"]["prior"]["response_digest"]
        );
        assert_eq!(store.read(&request).unwrap(), second);
        assert_eq!(fs::read(&checkpoint_path).unwrap(), failed_checkpoint);
        let mut exported = format!("{}{}", first.ndjson, second.ndjson);
        if !second.done {
            request.cursor = second.next_cursor;
            let (_, remaining) = read_all(&mut store, request);
            exported.push_str(&remaining);
        }
        assert_eq!(exported, original);
        assert_eq!(fs::read_to_string(&canonical_path).unwrap(), original);
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn a_checkpoint_rewritten_in_place_is_validated_again() {
        let (_temp, mut store, run) = create();
        for n in 0..40 {
            note(&mut store, &run, &format!("n{n}"), json!({"v":n})).unwrap();
        }
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        request.limit = 1;
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor.clone();
        let second = store.read(&request).unwrap();
        let cursor = second.next_cursor.clone().unwrap();
        let path = store
            .root
            .join("readers")
            .join(format!("{}.json", &cursor[..32]));
        let mut bytes = fs::read(&path).unwrap();
        let digest = bytes.windows(7).position(|w| w == b"sha256:").unwrap();
        bytes[digest + 7] = if bytes[digest + 7] == b'0' {
            b'1'
        } else {
            b'0'
        };
        fs::write(&path, &bytes).unwrap();
        request.cursor = Some(cursor);
        assert_refused(
            store.read(&request),
            "reader checkpoint is corrupt or unavailable; start a new snapshot",
        );
    }

    #[test]
    fn corrupt_reader_checkpoint_is_isolated_bounded_and_expires() {
        let (_temp, mut store, run) = create();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let canonical_path = store.root.join(&run.run_id).join(STREAM);
        let original = fs::read(&canonical_path).unwrap();
        let fresh = read_request(&run, crate::protocol::ReadSelector::All);
        let initial = store.read(&fresh).unwrap();
        assert!(!initial.done);
        let mut corrupt_request = fresh.clone();
        corrupt_request.cursor = initial.next_cursor;
        let cursor = corrupt_request.cursor.as_ref().unwrap();
        let directory = store.root.join("readers");
        let checkpoint_path = directory.join(format!("{}.json", &cursor[..32]));
        let mut envelope: Value =
            serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
        envelope["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
        let altered = canonical(&envelope).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&checkpoint_path)
            .unwrap();
        file.write_all(&altered).unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_refused(
            store.read(&corrupt_request),
            "reader checkpoint is corrupt or unavailable; start a new snapshot",
        );
        for _ in 0..31 {
            let unrelated = store.read(&fresh).unwrap();
            assert!(!unrelated.done);
            assert!(unrelated.local_consistency);
            assert_eq!(unrelated.snapshot, initial.snapshot);
        }
        assert_eq!(fs::read(&checkpoint_path).unwrap(), altered);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 32);
        assert!(store.read(&fresh).unwrap_err().0.contains("session limit"));
        assert_refused(
            store.read(&corrupt_request),
            "reader checkpoint is corrupt or unavailable; start a new snapshot",
        );

        File::open(&checkpoint_path)
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(SystemTime::now() - std::time::Duration::from_secs(601)),
            )
            .unwrap();
        let after_expiry = store.read(&fresh).unwrap();
        assert!(after_expiry.local_consistency);
        assert_eq!(after_expiry.snapshot, initial.snapshot);
        assert!(!checkpoint_path.exists());
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 32);
        assert_refused(
            store.read(&corrupt_request),
            "reader cursor expired or is unknown; start a new snapshot, do not append it to an old export",
        );
        assert_eq!(fs::read(&canonical_path).unwrap(), original);
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn durable_reader_refuses_a_rechecksummed_empty_snapshot_template() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        let run = store.prepare("none-reader", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        for n in 0..40 {
            note(&mut store, &run, &format!("n:{n}"), json!({"n":n})).unwrap();
        }
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor;
        let cursor = request.cursor.as_ref().unwrap();
        let checkpoint_path = store
            .root
            .join("readers")
            .join(format!("{}.json", &cursor[..32]));
        let canonical_path = store.root.join(&run.run_id).join(STREAM);
        let original = fs::read(&canonical_path).unwrap();
        drop(store);

        // A clean empty snapshot cannot exist: every restorable stream opens
        // at durable preparation, so the zero-record claim must corroborate
        // the canonical accepted state instead of passing vacuously.
        let mut envelope: Value =
            serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
        envelope["checkpoint"]["template"]["snapshot"] = json!({"head_seq":0,"head_digest":null});
        envelope["checkpoint"]["template"]["state"] = json!("settled");
        envelope["checkpoint"]["template"]["stream_status"] = json!("complete");
        envelope["checkpoint"]["template"]["child_protection"] = json!("enforced");
        envelope["checkpoint"]["accepted_bytes"] = json!(0);
        envelope["checkpoint"]["position"] = json!({
            "offset":0,"frame_start":0,"pending_bytes":0,"ready_emitted":null,
            "next_seq":1,"previous_digest":null,"verified":0});
        envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&checkpoint_path)
            .unwrap();
        file.write_all(&canonical(&envelope).unwrap()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut recovered = Store::open(&data).unwrap();
        let error = recovered.read(&request).unwrap_err();
        assert!(error.0.contains("corrupt"), "forged empty: {error}");
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
        let canonical_run = recovered.show(&run.run_id).unwrap();
        assert_eq!(canonical_run.state, "prepared");
        assert_eq!(canonical_run.child_protection, "unprotected");
        assert_eq!(canonical_run.chain.head_seq, first.snapshot.head_seq);
        assert_eq!(fs::read(&canonical_path).unwrap(), original);
    }

    #[test]
    fn lifetime_lock_refuses_a_second_writer() {
        let (temp, _store, _) = create();
        assert!(
            matches!(Store::open(&temp.path().join("data")), Err(error) if error.0.contains("writer"))
        );
    }

    #[test]
    fn a_closed_writer_releases_its_lock_even_while_a_copy_of_its_descriptor_lives() {
        let (temp, store, _) = create();
        // A child forked by another thread holds a copy until it execs.
        // SAFETY: dup takes the open descriptor by value; the copy is owned below.
        let copy = unsafe { libc::dup(store.lock.as_raw_fd()) };
        assert!(copy >= 0);
        // SAFETY: dup returned a new descriptor owned only here.
        let copy = unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(copy) };
        drop(store);
        Store::open(&temp.path().join("data")).unwrap();
        drop(copy);
    }

    #[test]
    fn full_length_request_id_prepares_replays_and_recovers_without_ambiguous_state() {
        let temp = tempfile::tempdir().unwrap();
        let request_id = "x".repeat(128);
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare(&request_id, &payload(), &peer()).unwrap();
        assert_eq!(run.request_id, request_id);
        assert_eq!(
            run.run_id,
            store
                .prepare(&request_id, &payload(), &peer())
                .unwrap()
                .run_id
        );
        assert!(store.verify(None).unwrap()[0].local_consistency);
        assert!(!store.recovery_ambiguous);
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            run.run_id,
            recovered
                .prepare(&request_id, &payload(), &peer())
                .unwrap()
                .run_id
        );
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
        assert!(!recovered.recovery_ambiguous);
    }

    #[test]
    fn lost_replies_replay_same_run_and_exact_receipt_after_recovery() {
        let (temp, mut store, run) = create();
        let first = note(
            &mut store,
            &run,
            "stable",
            json!({"meaning":"persisted but reply lost"}),
        )
        .unwrap();
        assert_eq!(
            first,
            note(
                &mut store,
                &run,
                "stable",
                json!({"meaning":"persisted but reply lost"})
            )
            .unwrap()
        );
        assert_refused(
            note(&mut store, &run, "stable", json!({"meaning":"changed"})),
            "request id conflicts with its immutable payload",
        );
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            recovered
                .prepare("test-prepare", &payload(), &peer())
                .unwrap()
                .run_id,
            run.run_id
        );
        assert_eq!(
            first,
            note(
                &mut recovered,
                &run,
                "stable",
                json!({"meaning":"persisted but reply lost"})
            )
            .unwrap()
        );
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn different_payload_cannot_rebind_prepare_or_effect_identity() {
        let (_temp, mut store, run) = create();
        assert_refused(
            store.prepare("test-prepare", &json!({"different":true}), &peer()),
            "prepare only accepts the versioned digest-only request plan",
        );
        store
            .append_owner(
                &run.run_id,
                "effect-first",
                "note",
                Some("effect-1"),
                &json!({"v":1}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_refused(
            store.append_owner(
                &run.run_id,
                "effect-second",
                "note",
                Some("effect-1"),
                &json!({"v":2}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "effect id conflicts with its immutable payload",
        );
    }

    #[test]
    fn interrupted_write_is_retained_poisoned_and_never_truncated_on_recovery() {
        let (temp, mut store, run) = create();
        let stream_path = store.root.join(&run.run_id).join(STREAM);
        let before = fs::read(&stream_path).unwrap();
        store.fault = Some(Fault::PartialWrite);
        assert!(note(&mut store, &run, "partial", json!({"v":"half record"})).is_err());
        let broken = fs::read(&stream_path).unwrap();
        assert!(broken.len() > before.len());
        store.fault = None;
        assert_refused(
            note(&mut store, &run, "retry", json!({})),
            "stream is poisoned; no dependent dispatch or sequence reuse",
        );
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(fs::read(&stream_path).unwrap(), broken);
        assert!(!recovered.verify(None).unwrap()[0].local_consistency);
        assert_eq!(
            recovered.show(&run.run_id).unwrap().state,
            "outcome_unknown"
        );
        assert_refused(
            recovered.prepare("different", &payload(), &peer()),
            "ambiguous recovery blocks new preparation; inspect verify",
        );
        assert_refused(
            note(&mut recovered, &run, "partial", json!({"v":"half record"})),
            "stream is poisoned; no dependent dispatch or sequence reuse",
        );
    }

    /// Rewrite the canonical records and drop the segment manifest, so only the
    /// edited records' own rules can refuse them on the next start.
    fn rewrite_without_manifest(
        store: &Store,
        run: &RunRecord,
        edit: impl FnOnce(&mut Vec<Value>),
    ) {
        let directory = store.root.join(&run.run_id);
        let mut records: Vec<Value> = fs::read(directory.join(STREAM))
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        edit(&mut records);
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend(canonical(&record).unwrap());
            bytes.push(b'\n');
        }
        fs::write(directory.join(STREAM), bytes).unwrap();
        fs::remove_file(directory.join(manifest::NAME)).unwrap();
    }

    #[test]
    fn the_most_severe_poison_decides_a_stream_status() {
        let poison = |kinds: &[PoisonKind]| -> Vec<Poison> {
            kinds.iter().map(|kind| Poison::new(*kind, "x")).collect()
        };
        assert_eq!(poison_status(&[]), None);
        for kinds in [
            [PoisonKind::Incomplete, PoisonKind::Corrupt],
            [PoisonKind::Corrupt, PoisonKind::Incomplete],
            [PoisonKind::Incomplete, PoisonKind::Unanchored],
        ] {
            assert_eq!(poison_status(&poison(&kinds)), Some("corrupt"), "{kinds:?}");
        }
        assert_eq!(
            poison_status(&poison(&[PoisonKind::Incomplete])),
            Some("incomplete")
        );
    }

    #[test]
    fn integrity_violations_read_as_corrupt_and_interruptions_as_incomplete() {
        let mixed_attempt = |records: &mut Vec<Value>| {
            records.last_mut().unwrap()["attempt_id"] =
                json!("att_00000000-0000-4000-8000-000000000000");
        };
        let duplicate_request = |records: &mut Vec<Value>| {
            let mut copy = records.last().unwrap().clone();
            copy["seq"] = json!(copy["seq"].as_u64().unwrap() + 1);
            copy["prev"] = json!(sha256_prefixed(
                &canonical(records.last().unwrap()).unwrap()
            ));
            records.push(copy);
        };
        let corrupt = |problem: &str, edit: &dyn Fn(&mut Vec<Value>)| {
            let (temp, mut store, run) = create();
            note(&mut store, &run, "first", json!({"v":1})).unwrap();
            rewrite_without_manifest(&store, &run, edit);
            drop(store);
            let mut store = Store::open(&temp.path().join("data")).unwrap();
            assert_eq!(store.verify(None).unwrap()[0].problems, [problem]);
            let page = store
                .read(&read_request(&run, crate::protocol::ReadSelector::All))
                .unwrap();
            assert!(!page.local_consistency, "{problem}");
            assert_eq!(page.stream_status, "corrupt", "{problem}");
        };
        corrupt("mixed attempt identity", &mixed_attempt);
        corrupt(
            "duplicate request id in canonical stream",
            &duplicate_request,
        );
        let (temp, mut store, run) = create();
        note(&mut store, &run, "first", json!({"v":1})).unwrap();
        let path = store.root.join(&run.run_id).join(STREAM);
        drop(store);
        let mut torn = fs::read(&path).unwrap();
        torn.extend_from_slice(b"{\"torn\":");
        fs::write(&path, torn).unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            store.verify(None).unwrap()[0].problems,
            ["interrupted canonical frame; bytes retained"]
        );
        let page = store
            .read(&read_request(&run, crate::protocol::ReadSelector::All))
            .unwrap();
        assert!(!page.local_consistency);
        assert_eq!(page.stream_status, "incomplete");
    }

    #[test]
    fn append_refuses_every_intent_that_recovery_would_refuse() {
        let (temp, mut store, run) = create();
        for (forged, refusal) in [
            (
                json!({"kind":"note","request_id":"note","body":{"receipt":prepared(&run)}}),
                "notes cannot replace receipt or state projections",
            ),
            (
                json!({"kind":"outcome_unknown","request_id":"unknown","body":{"token_id":"x"}}),
                "intent body cannot supply reserved identity token_id",
            ),
        ] {
            let refused = store
                .append(&run.run_id, forged, "owner", &peer(), None)
                .unwrap_err();
            assert!(refused.to_string().contains(refusal), "{refused}");
        }
        drop(store);
        let store = Store::open(&temp.path().join("data")).unwrap();
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn verification_pages_are_bounded_by_runs_and_bytes_and_status_reads_no_history() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut ids: Vec<_> = (0..3)
            .map(|n| {
                store
                    .prepare(&format!("verify-{n}"), &payload(), &peer())
                    .unwrap()
                    .run_id
            })
            .collect();
        ids.sort();
        for limit in [0, MAX_VERIFY_LIMIT + 1] {
            assert_refused(
                store.verify_page(None, None, limit),
                "verify limit must be between 1 and 100",
            );
        }
        let first = store.verify_page(None, None, 2).unwrap();
        assert_eq!(first.reports.len(), 2);
        assert!(!first.done);
        assert_eq!(first.next_after.as_deref(), Some(ids[1].as_str()));
        let last = store
            .verify_page(None, first.next_after.as_deref(), 2)
            .unwrap();
        assert_eq!(last.reports[0].run_id, ids[2]);
        assert!(last.done && last.next_after.is_none());
        // A page re-reads at most its byte budget, but never fewer than one run.
        store.verify_page_bytes = 1;
        let one = store.verify_page(None, None, MAX_VERIFY_LIMIT).unwrap();
        assert_eq!(one.reports.len(), 1);
        assert_eq!(one.next_after.as_deref(), Some(ids[0].as_str()));
        assert_eq!(store.verify(None).unwrap().len(), 3);
        // Reports carry the bounded coverage summary, not raw gap payloads.
        assert_eq!(
            one.reports[0].coverage,
            crate::reader::coverage_summary(&json!({"status":"unobserved"}))
        );
        assert!(store.status().ready());
        assert_eq!(store.status().runs, 3);
        // Status reflects accepted state; damage on disk waits for verify.
        fs::write(store.root.join(&ids[0]).join(STREAM), b"damaged\n").unwrap();
        assert!(store.status().ready());
        assert!(!store.verify_page(Some(&ids[0]), None, 1).unwrap().reports[0].local_consistency);
        store.fault = Some(Fault::BeforeWrite);
        assert!(store.hold(&ids[1], "lost", &peer()).is_err());
        let status = store.status();
        assert_eq!(status.ambiguous_runs, 1);
        assert!(!status.ready());
    }

    #[test]
    fn every_persistence_failure_stops_acknowledgements_until_recovery() {
        for fault in [
            Fault::BeforeWrite,
            Fault::EventSync,
            Fault::Projection,
            Fault::Manifest,
            Fault::DirectorySync,
        ] {
            let (temp, mut store, run) = create();
            store.fault = Some(fault);
            assert!(note(&mut store, &run, "uncertain", json!({"v":1})).is_err());
            store.fault = None;
            assert_refused(
                note(&mut store, &run, "new", json!({"v":2})),
                "stream is poisoned; no dependent dispatch or sequence reuse",
            );
            assert!(!store.verify(None).unwrap()[0].local_consistency);
            drop(store);
            let mut recovered = Store::open(&temp.path().join("data")).unwrap();
            let acknowledgement = note(&mut recovered, &run, "uncertain", json!({"v":1})).unwrap();
            assert!(acknowledgement.seq > 2);
            assert!(recovered.verify(None).unwrap()[0].local_consistency);
        }
    }

    #[test]
    fn recovery_sync_failure_cannot_publish_or_acknowledge_an_unflushed_tail() {
        let (temp, mut store, run) = create();
        let directory = store.root.join(&run.run_id);
        let stream_path = directory.join(STREAM);
        let manifest_path = directory.join("segments.json");
        let projection_path = directory.join("run.json");
        let old_manifest = fs::read(&manifest_path).unwrap();
        let old_projection = fs::read(&projection_path).unwrap();
        store.fault = Some(Fault::EventSync);
        let body = json!({"v":"written without successful sync"});
        assert!(note(&mut store, &run, "unflushed", body.clone()).is_err());
        let unflushed = fs::read(&stream_path).unwrap();
        let last_frame = unflushed
            .split(|byte| *byte == b'\n')
            .rfind(|frame| !frame.is_empty())
            .unwrap();
        let record: Value = serde_json::from_slice(last_frame).unwrap();
        let original_receipt = AppendReceipt {
            seq: record["seq"].as_u64().unwrap(),
            digest: sha256_prefixed(last_frame),
        };
        drop(store);

        let syncs = std::cell::Cell::new(0);
        let data = temp.path().join("data");
        let failed = Store::open_with_recovery_sync(&data, |_| {
            syncs.set(syncs.get() + 1);
            assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
            assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        });
        assert!(failed.is_err());
        assert_eq!(syncs.get(), 1);
        assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
        assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
        assert_eq!(fs::read(&stream_path).unwrap(), unflushed);

        let mut recovered = Store::open_with_recovery_sync(&data, |file| {
            syncs.set(syncs.get() + 1);
            assert_eq!(fs::read(&manifest_path).unwrap(), old_manifest);
            assert_eq!(fs::read(&projection_path).unwrap(), old_projection);
            file.sync_all()
        })
        .unwrap();
        assert_eq!(syncs.get(), 2);
        assert_eq!(
            note(&mut recovered, &run, "unflushed", body).unwrap(),
            original_receipt
        );
        assert_eq!(fs::read(&stream_path).unwrap(), unflushed);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn index_failure_after_acknowledgement_does_not_poison_or_reexecute() {
        let (temp, mut store, run) = create();
        let external = temp.path().join("outside-index");
        fs::write(&external, b"must stay unchanged").unwrap();
        let index = store.root.join("index.sqlite");
        fs::remove_file(&index).unwrap();
        std::os::unix::fs::symlink(&external, &index).unwrap();
        let receipt = note(&mut store, &run, "durable-without-index", json!({"v":1})).unwrap();
        store.flush_index();
        assert_eq!(store.index_status()["state"], "unavailable");
        assert_eq!(fs::read(external).unwrap(), b"must stay unchanged");
        assert!(store.verify(None).unwrap()[0].local_consistency);
        assert_eq!(
            note(&mut store, &run, "durable-without-index", json!({"v":1})).unwrap(),
            receipt
        );
    }

    #[test]
    fn admission_cannot_change_reserved_policy_or_argv() {
        let (_temp, mut store, run) = create();
        let mut receipt = prepared(&run);
        receipt["argv_digest"] = json!("sha256:bad");
        assert_refused(
            store.append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":receipt}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "record violates frozen jail-receipt schema",
        );
        // Well-formed receipts for another argv or policy reach the binding check.
        let other = json!(format!("sha256:{}", "e".repeat(64)));
        for path in ["/argv_digest", "/policy/digest"] {
            let mut receipt = prepared(&run);
            *receipt.pointer_mut(path).unwrap() = other.clone();
            assert_refused(
                store.append_owner(
                    &run.run_id,
                    "admit",
                    "admitted",
                    None,
                    &json!({"receipt":receipt}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                "intent receipt does not match prepared policy, argv, requirements and attempt",
            );
        }
        let first = store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            first,
            store
                .append_owner(
                    &run.run_id,
                    "admit",
                    "admitted",
                    None,
                    &json!({"receipt":prepared(&run)}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .unwrap()
        );
        assert_refused(
            store.append_owner(
                &run.run_id,
                "admit-again",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "admission or refusal is only valid from prepared",
        );
    }

    #[test]
    fn source_replay_and_gap_are_preserved_when_projection_is_updated() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["evidence"] = json!("best-effort");
        let run = store.prepare("gap-test", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        let event = serde_json::to_value(records::Event::lifecycle_note(
            &run.attempt_id,
            2,
            SystemTime::now(),
            1,
            "test",
        ))
        .unwrap();
        let first = store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            first,
            store
                .append_source(
                    &run.run_id,
                    &event,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .unwrap()
        );
        let mut changed = event.clone();
        changed["fields"]["message"] = json!("conflicting source sequence");
        assert_refused(
            store.append_source(
                &run.run_id,
                &changed,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "request id conflicts with its immutable payload",
        );
        store
            .append_owner(
                &run.run_id,
                "coverage",
                "outcome_unknown",
                None,
                &json!({"coverage":{"exec":"active"}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            store.show(&run.run_id).unwrap().coverage["ledger"]["status"],
            "degraded"
        );
    }

    #[test]
    fn owner_death_records_unknown_without_restart_or_tree_claim() {
        let (_temp, mut store, run) = create();
        let records = store.settle_orphans(&peer(), |_| false).unwrap();
        assert_eq!(records[0].state, "outcome_unknown");
        let outcome = records[0].outcome.as_ref().unwrap();
        assert_eq!(outcome["unknown"], true);
        // The reconciler's own unknown is the run's reason, not a child outcome.
        assert!(outcome.get("observed_child_outcome").is_none(), "{outcome}");
        assert_eq!(
            outcome["unknown_reason"],
            "owner birth identity is no longer live; tree termination and unrecorded effects are not inferred"
        );
        let mut stranger = peer();
        stranger.birth = "new-process-birth".into();
        assert_refused(
            store.claim_owner(&run.run_id, &stranger),
            "attempt already has an owner; dead owners require reconciliation and are never restarted",
        );
    }

    #[test]
    fn none_cannot_claim_enforced_protection_on_admission_or_in_its_projection() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        let mut store = Store::open(&data).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        let run = store.prepare("none", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        let receipt = prepared(&run);
        assert_eq!(receipt["child_protection"], "enforced");
        let refused = store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":receipt}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("none cannot claim enforced child protection"),
            "{refused}"
        );
        // An unresolved outcome may still carry the jail's receipt; its label
        // never upgrades a none run's projection.
        store
            .append_owner(
                &run.run_id,
                "unknown",
                "outcome_unknown",
                None,
                &json!({"receipt":receipt}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            store.show(&run.run_id).unwrap().child_protection,
            "unprotected"
        );
        assert_eq!(
            store.verify(None).unwrap()[0].child_protection,
            "unprotected"
        );
        drop(store);
        let store = Store::open(&data).unwrap();
        assert_eq!(
            store.show(&run.run_id).unwrap().child_protection,
            "unprotected"
        );
    }

    #[test]
    fn recovery_poisons_an_enforced_admission_of_a_none_run() {
        let (temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        // Re-chain the history as a none preparation: only recovery's own
        // intent check can refuse the enforced admission that follows it.
        rewrite_without_manifest(&store, &run, |records| {
            records[0]["body"]["payload"]["profile"] = json!("none");
            for index in 1..records.len() {
                let prev = sha256_prefixed(&canonical(&records[index - 1]).unwrap());
                records[index]["prev"] = json!(prev);
            }
        });
        drop(store);
        let store = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            store.verify(None).unwrap()[0].problems,
            ["none cannot claim enforced child protection"]
        );
        assert_eq!(store.show(&run.run_id).unwrap().state, "outcome_unknown");
    }

    #[test]
    fn unsafe_store_paths_and_oversized_events_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(temp.path(), temp.path().join("link")).unwrap();
        assert!(Store::open(&temp.path().join("link")).is_err());
        let (_temp, mut store, run) = create();
        assert_refused(
            note(
                &mut store,
                &run,
                "large",
                json!({"body":"x".repeat(MAX_FRAME_BYTES)}),
            ),
            "canonical event exceeds bounded frame limit",
        );
        assert_refused(store.show("../../escape"), "invalid run id");
    }

    #[test]
    fn flattened_source_is_the_original_frozen_envelope_plus_writer_fields() {
        let (_temp, mut store, run) = create();
        let source = serde_json::to_value(records::Event::lifecycle_note(
            &run.attempt_id,
            1,
            SystemTime::now(),
            1,
            "prepared",
        ))
        .unwrap();
        store
            .append_source(
                &run.run_id,
                &source,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let bytes = fs::read(store.root.join(&run.run_id).join(STREAM)).unwrap();
        let mut canonical: Value = serde_json::from_slice(
            bytes
                .split(|byte| *byte == b'\n')
                .rfind(|line| !line.is_empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(canonical["schema"], records::SCHEMA_EVENT);
        assert!(canonical.get("body").is_none());
        for field in [
            "run_id",
            "seq",
            "prev",
            "received_at",
            "provenance",
            "kind",
            "request_id",
        ] {
            canonical.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(canonical, source);
        assert!(store.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn strict_transport_gap_and_private_metadata_refuse_without_an_ack() {
        let (_temp, mut store, run) = create();
        let source = serde_json::to_value(records::Event::lifecycle_note(
            &run.attempt_id,
            2,
            SystemTime::now(),
            1,
            "prepared",
        ))
        .unwrap();
        assert_refused(
            store.append_source(
                &run.run_id,
                &source,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "strict producer transport loss was durably recorded; stop admission and execution",
        );
        let mut source = source;
        source["source_seq"] = json!(1);
        source["fields"]["raw_environment"] = json!("seed-secret-must-not-leak");
        let error = store
            .append_source(
                &run.run_id,
                &source,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap_err();
        assert!(!error.0.contains("seed-secret"));
        let mut plan = payload();
        plan["argv"] = json!(["seed-secret-must-not-leak"]);
        let error = store.prepare("raw-metadata", &plan, &peer()).unwrap_err();
        assert!(!error.0.contains("seed-secret"));
        assert_eq!(store.show(&run.run_id).unwrap().chain.head_seq, 3);
        assert_eq!(
            store.show(&run.run_id).unwrap().coverage["ledger"]["status"],
            "degraded"
        );
        assert_refused(
            store.append_source(
                &run.run_id,
                &source,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "record violates frozen jail-event schema",
        );
    }

    #[test]
    fn settlement_requires_matching_final_receipt_and_trace_and_closes_observations() {
        let (_temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-tool.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        let body =
            json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]});
        assert_refused(
            store.append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "terminal trace and receipt do not corroborate",
        );
        let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
        let event = serde_json::to_value(records::Event::receipt_note(
            &run.attempt_id,
            1,
            SystemTime::now(),
            1,
            records::Phase::Settled,
            &receipt_digest,
        ))
        .unwrap();
        store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let settled = store
            .append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            settled,
            store
                .append_owner(
                    &run.run_id,
                    "settle",
                    "settled",
                    None,
                    &body,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .unwrap()
        );
        assert_eq!(store.show(&run.run_id).unwrap().state, "settled");
        let event = serde_json::to_value(records::Event::lifecycle_note(
            &run.attempt_id,
            2,
            SystemTime::now(),
            2,
            "after_settlement",
        ))
        .unwrap();
        assert_refused(
            store.append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "terminal run cannot ingest new observations",
        );
    }

    #[test]
    fn refused_receipt_requires_the_same_attempt_and_final_source_note() {
        let (_temp, mut store, run) = create();
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        let body =
            json!({"receipt":receipt,"outcome":receipt["outcome"],"coverage":receipt["coverage"]});
        assert_refused(
            store.append_owner(
                &run.run_id,
                "denied",
                "denied",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "terminal trace and receipt do not corroborate",
        );
        let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
        let event = serde_json::to_value(records::Event::receipt_note(
            &run.attempt_id,
            1,
            SystemTime::now(),
            1,
            records::Phase::Refused,
            &receipt_digest,
        ))
        .unwrap();
        store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        store
            .append_owner(
                &run.run_id,
                "denied",
                "denied",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(store.show(&run.run_id).unwrap().state, "denied");
    }

    #[test]
    fn source_exec_outcomes_do_not_become_the_run_outcome_on_ingress_or_recovery() {
        let (temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let mut event: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/event-exec.json"
        ))
        .unwrap();
        event["attempt_id"] = json!(run.attempt_id);
        event["source_seq"] = json!(1);
        store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
        assert_eq!(store.show(&run.run_id).unwrap().outcome, None);
        let stored = fs::read_to_string(
            temp.path()
                .join("data/ledger")
                .join(&run.run_id)
                .join("events-0001.ndjson"),
        )
        .unwrap();
        let source: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
        assert_eq!(source["outcome"], event["outcome"]);
        drop(store);
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(recovered.show(&run.run_id).unwrap().outcome, None);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn admitted_exec_failure_settles_only_with_a_correlated_verified_empty_attempt() {
        let (temp, mut store, run) = create();
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        receipt["outcome"]["cause"] = json!("ENOENT");
        let body = json!({"receipt":receipt,"coverage":receipt["coverage"]});
        // A known exec error cannot retroactively stand in for admission.
        assert_refused(
            store.append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "settlement requires durable admission",
        );
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        for kind in ["denied", "settled"] {
            assert!(
                store
                    .append_owner(
                        &run.run_id,
                        "settle",
                        kind,
                        None,
                        &body,
                        &peer(),
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .is_err()
            );
        }
        let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
        let event = serde_json::to_value(records::Event::receipt_note(
            &run.attempt_id,
            1,
            SystemTime::now(),
            1,
            records::Phase::Refused,
            &receipt_digest,
        ))
        .unwrap();
        store
            .append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let ack = store
            .append_owner(
                &run.run_id,
                "settle",
                "settled",
                None,
                &body,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        assert_eq!(
            store
                .append_owner(
                    &run.run_id,
                    "settle",
                    "settled",
                    None,
                    &body,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .unwrap(),
            ack
        );
        let record = store.show(&run.run_id).unwrap();
        assert_eq!(record.state, "settled");
        assert_eq!(record.outcome.unwrap()["cause"], "ENOENT");
        assert_eq!(record.receipts.last().unwrap()["phase"], "refused");
        assert!(store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        let record = recovered.show(&run.run_id).unwrap();
        assert_eq!(record.state, "settled");
        assert_eq!(record.outcome.unwrap()["kind"], "exec_error");
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn admitted_refusal_cannot_settle_with_unproved_tree_policy_mismatch_or_source_loss() {
        for variant in [
            "refused",
            "unverified",
            "registered",
            "policy",
            "source_gap",
        ] {
            let (_temp, mut store, run) = create();
            store
                .append_owner(
                    &run.run_id,
                    "admit",
                    "admitted",
                    None,
                    &json!({"receipt":prepared(&run)}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap();
            let mut receipt: Value = serde_json::from_str(include_str!(
                "../../../docs/specs/jail-v1/examples/receipt-exec-refused.json"
            ))
            .unwrap();
            receipt["attempt_id"] = json!(run.attempt_id);
            match variant {
                "refused" => receipt["outcome"]["kind"] = json!("refused"),
                "unverified" => {
                    receipt["lifetime"]["tree_empty"] = Value::Null;
                    receipt["lifetime"]["verified_at"] = Value::Null;
                    receipt["lifetime"]["integrity"] = json!("lost");
                }
                "registered" => {
                    receipt["lifetime"]["verification_scope"] = json!("registered_boundary");
                }
                "policy" => {
                    receipt["policy"]["digest"] = json!(format!("sha256:{}", "e".repeat(64)))
                }
                _ => {}
            }
            let receipt_digest = records::semantic::receipt_digest(&receipt).unwrap();
            let event = serde_json::to_value(records::Event::receipt_note(
                &run.attempt_id,
                if variant == "source_gap" { 2 } else { 1 },
                SystemTime::now(),
                1,
                records::Phase::Refused,
                &receipt_digest,
            ))
            .unwrap();
            let appended = store.append_source(
                &run.run_id,
                &event,
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            );
            assert_eq!(appended.is_err(), variant == "source_gap");
            let head = store.show(&run.run_id).unwrap().chain.head_seq;
            assert!(
                store
                    .append_owner(
                        &run.run_id,
                        "settle",
                        "settled",
                        None,
                        &json!({"receipt":receipt}),
                        &peer(),
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    )
                    .is_err(),
                "accepted {variant}"
            );
            assert_eq!(store.show(&run.run_id).unwrap().state, "admitted");
            assert_eq!(store.show(&run.run_id).unwrap().chain.head_seq, head);
        }
    }

    #[test]
    fn unresolved_run_keeps_a_proven_child_exit_separate_from_unknown_outcome() {
        let (_temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "unknown",
                "outcome_unknown",
                None,
                &json!({"outcome":{"kind":"exited","code":0}}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let record = store.show(&run.run_id).unwrap();
        let outcome = record.outcome.unwrap();
        assert_eq!(record.state, "outcome_unknown");
        assert_eq!(outcome["unknown"], true);
        assert_eq!(outcome["kind"], "unknown");
        assert_eq!(outcome["observed_child_outcome"]["code"], 0);
        assert_eq!(
            outcome["unknown_reason"],
            "owner or reconciliation reported an unresolved run outcome"
        );
    }

    #[test]
    fn recovery_rechecks_admission_bindings_even_with_a_recomputed_local_chain() {
        let (temp, mut store, run) = create();
        store
            .append_owner(
                &run.run_id,
                "admit",
                "admitted",
                None,
                &json!({"receipt":prepared(&run)}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        let path = store.root.join(&run.run_id).join(STREAM);
        let bytes = fs::read(&path).unwrap();
        let mut records: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        records.last_mut().unwrap()["body"]["receipt"]["policy"]["digest"] =
            json!(format!("sha256:{}", "e".repeat(64)));
        let mut rewritten = Vec::new();
        for record in records {
            rewritten.extend(canonical(&record).unwrap());
            rewritten.push(b'\n');
        }
        fs::write(&path, &rewritten).unwrap();
        assert!(!store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), rewritten);
        assert_eq!(
            recovered.show(&run.run_id).unwrap().state,
            "outcome_unknown"
        );
        assert!(!recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn verification_detects_projection_drift_and_recovery_rebuilds_it() {
        let (temp, store, run) = create();
        let projection = store.root.join(&run.run_id).join("run.json");
        fs::write(&projection, b"{}\n").unwrap();
        assert!(!store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }
    #[test]
    fn recovery_keeps_unchanged_projections_and_manifests_in_place() {
        let (temp, store, run) = create();
        let directory = store.root.join(&run.run_id);
        let inode = |name: &str| fs::metadata(directory.join(name)).unwrap().ino();
        let before = (inode("run.json"), inode(manifest::NAME));
        drop(store);
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!((inode("run.json"), inode(manifest::NAME)), before);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
        drop(recovered);
        fs::write(directory.join("run.json"), b"{}\n").unwrap();
        let recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_ne!(
            inode("run.json"),
            before.0,
            "a changed projection is republished"
        );
        assert_eq!(inode(manifest::NAME), before.1);
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn a_failed_projection_write_leaves_no_temporary_file() {
        let (temp, mut store, run) = create();
        crate::faults::arm(crate::faults::Plan {
            kind: "note".into(),
            point: "projection.before_rename".into(),
            action: "error".into(),
            marker: temp.path().join("marker"),
        });
        let refused = note(&mut store, &run, "unpublished", json!({"v":1}));
        crate::faults::disarm();
        assert!(refused.is_err());
        let leftovers: Vec<_> = fs::read_dir(store.root.join(&run.run_id))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    fn segment_bytes(directory: &Path) -> Vec<u8> {
        manifest::names(directory)
            .unwrap()
            .iter()
            .flat_map(|name| fs::read(directory.join(name)).unwrap())
            .collect()
    }

    #[test]
    fn rotation_preserves_exact_export_global_chain_and_original_replay_after_restart() {
        let (temp, mut store, run) = create();
        store.segment_limit = 2048;
        let directory = store.root.join(&run.run_id);
        let initial = fs::read(directory.join(STREAM)).unwrap();
        let mut receipts = Vec::new();
        for i in 0..12 {
            let body = json!({"index":i,"padding":"€".repeat(300)});
            receipts.push(note(&mut store, &run, &format!("rotated-{i}"), body).unwrap());
        }
        let names = manifest::names(&directory).unwrap();
        assert!(names.len() > 3);
        assert_eq!(fs::read(directory.join(STREAM)).unwrap(), initial);
        let canonical = segment_bytes(&directory);
        let mut previous = None;
        for (i, frame) in canonical
            .split(|b| *b == b'\n')
            .filter(|f| !f.is_empty())
            .enumerate()
        {
            let record: Value = serde_json::from_slice(frame).unwrap();
            assert_eq!(record["seq"], i + 1);
            assert_eq!(record["prev"], json!(previous));
            previous = Some(sha256_prefixed(frame));
        }
        let anchored = fs::read(directory.join(manifest::NAME)).unwrap();
        assert!(store.verify(None).unwrap()[0].local_consistency);
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        for (i, receipt) in receipts.iter().enumerate() {
            assert_eq!(
                *receipt,
                note(
                    &mut recovered,
                    &run,
                    &format!("rotated-{i}"),
                    json!({"index":i,"padding":"€".repeat(300)})
                )
                .unwrap()
            );
        }
        let (pages, exported) = read_all(
            &mut recovered,
            read_request(&run, crate::protocol::ReadSelector::All),
        );
        assert_eq!(exported.as_bytes(), canonical);
        assert!(pages.iter().all(|page| page.local_consistency));
        assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), anchored);
        assert_eq!(segment_bytes(&directory), canonical);
        // Request/effect identities are global, not scoped to a file.
        assert_refused(
            note(&mut recovered, &run, "rotated-0", json!({"changed":true})),
            "request id conflicts with its immutable payload",
        );
    }

    #[test]
    fn rotation_failure_boundaries_never_duplicate_or_truncate_history() {
        for fault in [
            Fault::RotationCreated,
            Fault::RotationSynced,
            Fault::BeforeWrite,
            Fault::PartialWrite,
            Fault::EventSync,
            Fault::Projection,
            Fault::Manifest,
            Fault::DirectorySync,
        ] {
            let (temp, mut store, run) = create();
            store.segment_limit = 1;
            let directory = store.root.join(&run.run_id);
            let first = fs::read(directory.join(STREAM)).unwrap();
            store.fault = Some(fault);
            assert!(note(&mut store, &run, "rotation-fault", json!({"v":1})).is_err());
            store.fault = None;
            assert_refused(
                note(&mut store, &run, "different", json!({})),
                "stream is poisoned; no dependent dispatch or sequence reuse",
            );
            let second = directory.join(manifest::name(2));
            let before = fs::read(&second).unwrap();
            let original_receipt = before.strip_suffix(b"\n").map(|frame| {
                let record: Value = serde_json::from_slice(frame).unwrap();
                AppendReceipt {
                    seq: record["seq"].as_u64().unwrap(),
                    digest: sha256_prefixed(frame),
                }
            });
            drop(store);
            let mut recovered = Store::open(&temp.path().join("data")).unwrap();
            assert_eq!(fs::read(directory.join(STREAM)).unwrap(), first);
            assert_eq!(fs::read(&second).unwrap(), before);
            if matches!(fault, Fault::PartialWrite) {
                assert!(!recovered.verify(None).unwrap()[0].local_consistency);
                assert_refused(
                    note(&mut recovered, &run, "rotation-fault", json!({"v":1})),
                    "stream is poisoned; no dependent dispatch or sequence reuse",
                );
                assert_refused(
                    recovered.prepare("new", &payload(), &peer()),
                    "ambiguous recovery blocks new preparation; inspect verify",
                );
                continue;
            }
            let receipt = note(&mut recovered, &run, "rotation-fault", json!({"v":1})).unwrap();
            if let Some(original) = original_receipt {
                assert_eq!(receipt, original);
            }
            assert_eq!(
                receipt,
                note(&mut recovered, &run, "rotation-fault", json!({"v":1})).unwrap()
            );
            assert_eq!(receipt.seq, 3);
            assert_eq!(
                fs::read(&second)
                    .unwrap()
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count(),
                1
            );
            assert!(recovered.verify(None).unwrap()[0].local_consistency);
        }
    }

    #[test]
    fn rotation_recovery_syncs_each_segment_before_publishing_promoted_metadata() {
        let (temp, mut store, run) = create();
        store.segment_limit = 1;
        let directory = store.root.join(&run.run_id);
        note(&mut store, &run, "sealed", json!({})).unwrap();
        let old = fs::read(directory.join(manifest::NAME)).unwrap();
        store.fault = Some(Fault::EventSync);
        assert!(note(&mut store, &run, "tail", json!({})).is_err());
        let before = segment_bytes(&directory);
        drop(store);
        for failing_segment in 1..=3 {
            let seen = std::cell::Cell::new(0);
            assert!(
                Store::open_with_recovery_sync(&temp.path().join("data"), |_| {
                    let n = seen.get() + 1;
                    seen.set(n);
                    assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), old);
                    if n == failing_segment {
                        Err(std::io::Error::from_raw_os_error(libc::EIO))
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            assert_eq!(seen.get(), failing_segment);
            assert_eq!(segment_bytes(&directory), before);
            assert_eq!(fs::read(directory.join(manifest::NAME)).unwrap(), old);
        }
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(
            note(&mut recovered, &run, "tail", json!({})).unwrap().seq,
            4
        );
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
    }

    #[test]
    fn rotated_streams_refuse_missing_changed_reordered_and_unanchored_segments() {
        for damage in [
            "missing-middle",
            "missing-last",
            "swap",
            "changed",
            "sealed-tail",
            "manifest-order",
            "no-manifest",
            "extra-empty",
            "symlink",
        ] {
            let (temp, mut store, run) = create();
            store.segment_limit = 1;
            let directory = store.root.join(&run.run_id);
            note(&mut store, &run, "one", json!({"v":"original"})).unwrap();
            note(&mut store, &run, "two", json!({"v":"original"})).unwrap();
            drop(store);
            let second = directory.join(manifest::name(2));
            let third = directory.join(manifest::name(3));
            match damage {
                "missing-middle" => fs::remove_file(&second).unwrap(),
                "missing-last" => fs::remove_file(&third).unwrap(),
                "swap" => {
                    let a = fs::read(&second).unwrap();
                    let b = fs::read(&third).unwrap();
                    fs::write(&second, b).unwrap();
                    fs::write(&third, a).unwrap();
                }
                "changed" => fs::write(
                    &second,
                    fs::read_to_string(&second)
                        .unwrap()
                        .replace("original", "modified"),
                )
                .unwrap(),
                "sealed-tail" => {
                    OpenOptions::new()
                        .append(true)
                        .open(&second)
                        .unwrap()
                        .write_all(b"\n")
                        .unwrap();
                }
                "manifest-order" => {
                    let path = directory.join(manifest::NAME);
                    let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    m["segments"].as_array_mut().unwrap().swap(0, 1);
                    let mut bytes = canonical(&m).unwrap();
                    bytes.push(b'\n');
                    fs::write(path, bytes).unwrap();
                }
                "no-manifest" => fs::remove_file(directory.join(manifest::NAME)).unwrap(),
                "extra-empty" => {
                    private_file(&directory.join(manifest::name(4)), true, false).unwrap();
                    private_file(&directory.join(manifest::name(5)), true, false).unwrap();
                }
                "symlink" => {
                    fs::remove_file(&second).unwrap();
                    std::os::unix::fs::symlink(&third, &second).unwrap();
                }
                _ => unreachable!(),
            }
            let before: Vec<_> = fs::read_dir(&directory)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("events-")
                })
                .map(|p| {
                    let bytes = fs::read(&p).unwrap();
                    (p, bytes)
                })
                .collect();
            let mut recovered = Store::open(&temp.path().join("data")).unwrap();
            assert!(
                !recovered.verify(None).unwrap()[0].local_consistency,
                "{damage}"
            );
            assert_eq!(
                recovered.show(&run.run_id).unwrap().state,
                "outcome_unknown",
                "{damage}"
            );
            assert!(
                note(&mut recovered, &run, "new", json!({})).is_err(),
                "{damage}"
            );
            assert!(
                recovered.prepare("new", &payload(), &peer()).is_err(),
                "{damage}"
            );
            for (path, bytes) in before {
                assert_eq!(fs::read(path).unwrap(), bytes, "{damage}");
            }
        }
    }

    #[test]
    fn reader_snapshot_and_lost_reply_survive_rotation_with_partial_utf8_export() {
        let (temp, mut store, run) = create();
        store.segment_limit = 16_384;
        let directory = store.root.join(&run.run_id);
        note(&mut store, &run, "large", json!({"v":"€".repeat(90_000)})).unwrap();
        note(&mut store, &run, "last", json!({"v":3})).unwrap();
        let expected = String::from_utf8(segment_bytes(&directory)).unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        request.limit = 1;
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor.clone();
        let retry_request = request.clone();
        let second = store.read(&request).unwrap();
        assert!(!second.done);
        note(&mut store, &run, "later", json!({"v":"x".repeat(20_000)})).unwrap();
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(recovered.read(&retry_request).unwrap(), second);
        request.cursor = second.next_cursor.clone();
        let (pages, rest) = read_all(&mut recovered, request);
        assert_eq!(format!("{}{}{rest}", first.ndjson, second.ndjson), expected);
        assert!(
            pages
                .iter()
                .all(|p| p.snapshot == first.snapshot && p.local_consistency)
        );
        assert!(recovered.show(&run.run_id).unwrap().chain.head_seq > first.snapshot.head_seq);
    }

    #[test]
    fn reader_cursor_refuses_replaced_later_segment_after_restart() {
        let (temp, mut store, run) = create();
        store.segment_limit = 1;
        note(
            &mut store,
            &run,
            "second-file",
            json!({"v":"x".repeat(100_000)}),
        )
        .unwrap();
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        request.limit = 1;
        request.cursor = store.read(&request).unwrap().next_cursor;
        let path = store.root.join(&run.run_id).join(manifest::name(2));
        let bytes = fs::read(&path).unwrap();
        drop(store);
        fs::rename(&path, path.with_extension("old")).unwrap();
        // Keep the old inode allocated but outside the canonical namespace.
        fs::rename(path.with_extension("old"), temp.path().join("old-segment")).unwrap();
        private_file(&path, true, false)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert!(recovered.verify(None).unwrap()[0].local_consistency);
        assert_refused(
            recovered.read(&request),
            "reader canonical snapshot is corrupt: identity or length changed",
        );
    }

    #[test]
    fn legacy_manifest_and_reader_checkpoint_migrate_before_rotation() {
        let (temp, mut store, run) = create();
        note(
            &mut store,
            &run,
            "legacy-large",
            json!({"v":"x".repeat(100_000)}),
        )
        .unwrap();
        let directory = store.root.join(&run.run_id);
        let mut request = read_request(&run, crate::protocol::ReadSelector::All);
        request.limit = 1;
        let first = store.read(&request).unwrap();
        request.cursor = first.next_cursor;
        let checkpoint = store
            .root
            .join("readers")
            .join(format!("{}.json", &request.cursor.as_ref().unwrap()[..32]));
        let mut envelope: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
        envelope["checkpoint"]["schema"] = json!("ouro.ledger.reader-checkpoint/1");
        envelope["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("segments_digest");
        envelope["digest"] = json!(digest(&envelope["checkpoint"]).unwrap());
        fs::write(&checkpoint, canonical(&envelope).unwrap()).unwrap();
        let path = directory.join(manifest::NAME);
        let mut m: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let segments = m.as_object_mut().unwrap().remove("segments").unwrap();
        m["segment"] = segments[0].clone();
        m["schema"] = json!("ouro.ledger.segments/1");
        let mut bytes = canonical(&m).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let original = fs::read(directory.join(STREAM)).unwrap();
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        recovered.segment_limit = 1;
        note(&mut recovered, &run, "rotate", json!({})).unwrap();
        let page = recovered.read(&request).unwrap();
        assert_eq!(page.snapshot.head_seq, 3);
        assert!(page.local_consistency);
        assert_eq!(fs::read(directory.join(STREAM)).unwrap(), original);
        let m: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(m["schema"], "ouro.ledger.segments/2");
        assert_eq!(m["segments"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn rotated_queries_preserve_source_filters_and_effect_identity() {
        use crate::protocol::ReadSelector;
        let (temp, mut store, run) = create();
        store.segment_limit = 1;
        let effect = store
            .append_owner(
                &run.run_id,
                "effect-request",
                "note",
                Some("effect-stable"),
                &json!({"v":1}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap();
        source_fixture(&mut store, &run, "exec", 1, None);
        source_fixture(&mut store, &run, "path", 2, Some("one"));
        source_fixture(&mut store, &run, "host", 3, None);
        source_fixture(&mut store, &run, "path", 4, Some("two"));
        let mut request = read_request(&run, ReadSelector::Paths);
        request.limit = 1;
        let first = store.read(&request).unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0]["fields"]["path"]["value"], "one");
        request.cursor = first.next_cursor;
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        let (pages, _) = read_all(&mut recovered, request);
        let records: Vec<_> = pages.iter().flat_map(|p| &p.records).collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["fields"]["path"]["value"], "two");
        assert_eq!(
            recovered
                .append_owner(
                    &run.run_id,
                    "effect-request",
                    "note",
                    Some("effect-stable"),
                    &json!({"v":1}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .unwrap(),
            effect
        );
        assert_refused(
            recovered.append_owner(
                &run.run_id,
                "new-request",
                "note",
                Some("effect-stable"),
                &json!({"v":1}),
                &peer(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            "effect id conflicts with its immutable payload",
        );
        for selector in [ReadSelector::Execs, ReadSelector::Hosts] {
            let (pages, _) = read_all(&mut recovered, read_request(&run, selector));
            assert_eq!(pages.iter().map(|p| p.records.len()).sum::<usize>(), 1);
            assert!(pages.iter().all(|p| p.local_consistency));
        }
    }
}
