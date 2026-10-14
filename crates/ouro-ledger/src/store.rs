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
use crate::faults::{self, Point, Replaced, Step};
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
        let _scope = faults::enter(|| faults::Scope::of_record(record["kind"].as_str()?));
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
            faults::hit(Point::RotationCreated)?;
            file.sync_all()?;
            File::open(&directory)?.sync_all()?;
            faults::hit(Point::RotationSynced)?;
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
        faults::hit(Point::EventBeforeWrite)?;
        faults::partial_write(Point::EventPartialWrite, &mut file, bytes)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        faults::hit(Point::EventBeforeSync)?;
        file.sync_all()?;
        faults::hit(Point::EventAfterSync)?;
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
        self.write_projection(&run)?;
        crate::manifest::write(&self.root.join(run_id), &manifest)?;
        faults::hit(Point::AppendBeforeDirectorySync)?;
        File::open(self.root.join(run_id))?.sync_all()?;
        faults::hit(Point::AppendAfterDirectorySync)?;
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
            faults::hit(Point::Replace(Replaced::Projection, Step::BeforeWrite))?;
            file.write_all(&bytes)?;
            faults::hit(Point::Replace(Replaced::Projection, Step::BeforeSync))?;
            file.sync_all()?;
            faults::hit(Point::Replace(Replaced::Projection, Step::BeforeRename))?;
            fs::rename(&temp, dir.join("run.json"))?;
            Ok(())
        })();
        if result.is_err() {
            // An unpublished temporary projection has no authority; never leak it.
            let _ = fs::remove_file(&temp);
        }
        result?;
        faults::hit(Point::Replace(
            Replaced::Projection,
            Step::BeforeDirectorySync,
        ))?;
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
mod tests;
