//! Bounded readers of the original canonical stream. Cursors confer no authority.
//!
//! Restart restoration reads at most one maximum-sized current frame before
//! replaying one ordinary bounded page. Checkpoint housekeeping reads at most
//! 32 private files of at most 32 KiB each; record payloads are never checkpointed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::protocol::{
    AppendReceipt, LedgerError, MAX_FRAME_BYTES, MAX_READ_LIMIT, OversizedRecord, READ_CHUNK_BYTES,
    READ_OUTPUT_BYTES, READ_SCAN_BYTES, READ_SCAN_FRAMES, ReadFilter, ReadPage, ReadRequest,
    ReadSelector, ReadStage, Result, RunRecord,
};

const MAX_SESSIONS: usize = 32;
const TTL: Duration = Duration::from_secs(600);
const MAX_CHECKPOINT_BYTES: u64 = 32_768;

#[derive(Default)]
pub(crate) struct Readers {
    sessions: BTreeMap<String, Session>,
    #[cfg(test)]
    pub(crate) fail_directory_sync: bool,
}

struct Ready {
    bytes: String,
    record: Value,
    digest: String,
    emitted: usize,
}

struct Session {
    created: u64,
    request: ReadRequest,
    file: crate::segments::Snapshot,
    device: u64,
    inode: u64,
    accepted_bytes: u64,
    offset: u64,
    pending: Vec<u8>,
    ready: Option<Ready>,
    next_seq: u64,
    previous_digest: Option<String>,
    verified: u64,
    template: ReadPage,
    current: String,
    prior: Option<(String, ReadPage)>,
    prior_position: Option<Position>,
}

/// Only replay positions and response digests are durable. Canonical record
/// payloads remain in their original stream, including partially exported ones.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Position {
    offset: u64,
    frame_start: u64,
    pending_bytes: usize,
    ready_emitted: Option<usize>,
    next_seq: u64,
    previous_digest: Option<String>,
    verified: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    token: String,
    before: Position,
    response_digest: String,
    next_cursor: Option<String>,
    done: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema: String,
    id: String,
    created: u64,
    request: ReadRequest,
    device: u64,
    inode: u64,
    accepted_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    segments_digest: Option<String>,
    template: ReadPage,
    position: Position,
    current: String,
    prior: Replay,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    digest: String,
    checkpoint: Checkpoint,
}

fn epoch_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LedgerError("reader clock predates Unix epoch".into()))?
        .as_secs())
}

fn token_valid(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn durable_digest(value: &impl Serialize) -> Result<String> {
    let bytes = to_jcs(&serde_json::to_value(value)?)
        .map_err(|_| LedgerError("reader checkpoint cannot be canonicalized".into()))?;
    Ok(sha256_prefixed(&bytes))
}

fn private_directory(path: &Path) -> Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(LedgerError("reader checkpoint directory is unsafe".into()));
    }
    Ok(directory)
}

fn checkpoint_directory(path: &Path) -> Result<PathBuf> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| LedgerError("reader canonical path has no ledger root".into()))?;
    let parent = private_directory(root)?;
    let directory = root.join("readers");
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    private_directory(&directory)?;
    // A previous mkdir may have survived a failed parent sync. Re-establish
    // its namespace durability before any checkpoint can be acknowledged.
    parent.sync_all()?;
    Ok(directory)
}

fn checkpoint_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_CHECKPOINT_BYTES
    {
        return Err(LedgerError(
            "reader checkpoint file is unsafe or oversized".into(),
        ));
    }
    Ok(file)
}

fn load_checkpoint(directory: &Path, id: &str) -> Result<(Checkpoint, File)> {
    let mut bytes = Vec::new();
    let mut file = checkpoint_file(&directory.join(format!("{id}.json")))?;
    (&mut file)
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(LedgerError("reader checkpoint exceeds bounded size".into()));
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)
        .map_err(|_| LedgerError("reader checkpoint is corrupt".into()))?;
    let checkpoint = envelope.checkpoint;
    if envelope.digest != durable_digest(&checkpoint)?
        || !matches!(
            checkpoint.schema.as_str(),
            "ouro.ledger.reader-checkpoint/1" | "ouro.ledger.reader-checkpoint/2"
        )
        || (checkpoint.schema == "ouro.ledger.reader-checkpoint/2"
            && checkpoint.segments_digest.is_none())
        || (checkpoint.schema == "ouro.ledger.reader-checkpoint/1"
            && checkpoint.segments_digest.is_some())
        || checkpoint.id != id
        || !token_valid(&checkpoint.current)
        || !token_valid(&checkpoint.prior.token)
        || checkpoint.request.cursor.is_some()
        || checkpoint.template.run_id != checkpoint.request.run_id
        || checkpoint.template.schema != "ouro.ledger.read/1"
        || !checkpoint.template.records.is_empty()
        || !checkpoint.template.ndjson.is_empty()
        || checkpoint.template.next_cursor.is_some()
        || checkpoint.template.scanned_through_seq != 0
        || checkpoint.template.done
        || checkpoint.template.oversized_record.is_some()
    {
        return Err(LedgerError(
            "reader checkpoint checksum or identity is corrupt".into(),
        ));
    }
    validate_request(&checkpoint.request)?;
    let terminal =
        ["settled", "denied", "outcome_unknown"].contains(&checkpoint.template.state.as_str());
    if checkpoint.template.coverage["selection_status"]
        != selection_status(&checkpoint.request.filter, &checkpoint.template.coverage)
        || (checkpoint.template.local_consistency
            && (checkpoint.template.stream_status != if terminal { "complete" } else { "active" }
                || !checkpoint.template.problems.is_empty()))
        || (!checkpoint.template.local_consistency
            && !["corrupt", "incomplete"].contains(&checkpoint.template.stream_status.as_str()))
    {
        return Err(LedgerError(
            "reader checkpoint labels are inconsistent".into(),
        ));
    }
    Ok((checkpoint, file))
}

#[derive(Default)]
struct Checkpoints {
    valid: Vec<Checkpoint>,
    invalid: BTreeSet<String>,
}

impl Checkpoints {
    fn len(&self) -> usize {
        self.valid.len() + self.invalid.len()
    }
}

/// Scan a bounded private directory, expiring both disk and in-memory sessions.
/// Interrupted atomic writes have no issued cursor and can be safely removed.
fn checkpoints(directory: &Path, now: u64) -> Result<Checkpoints> {
    private_directory(directory)?;
    let mut result = Checkpoints::default();
    for (count, entry) in fs::read_dir(directory)?.enumerate() {
        if count >= MAX_SESSIONS * 2 {
            return Err(LedgerError(
                "reader checkpoint directory exceeds bounded size".into(),
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| LedgerError("reader checkpoint filename is unsafe".into()))?;
        let (id, suffix) = name
            .rsplit_once('.')
            .ok_or_else(|| LedgerError("reader checkpoint filename is unsafe".into()))?;
        if !token_valid(id) || !["json", "tmp"].contains(&suffix) {
            return Err(LedgerError("reader checkpoint filename is unsafe".into()));
        }
        let file = checkpoint_file(&entry.path())?;
        if suffix == "tmp" {
            fs::remove_file(entry.path())?;
            private_directory(directory)?.sync_all()?;
            continue;
        }
        let checkpoint = load_checkpoint(directory, id)
            .ok()
            .map(|(checkpoint, _)| checkpoint)
            .filter(|checkpoint| checkpoint.created <= now);
        // Safe corrupt files remain bounded capacity occupants until their
        // filesystem timestamp expires; their cursors refuse independently.
        let created = checkpoint.as_ref().map_or_else(
            || {
                file.metadata()?
                    .modified()?
                    .duration_since(UNIX_EPOCH)
                    .map(|time| time.as_secs())
                    .map_err(|_| LedgerError("reader checkpoint timestamp is invalid".into()))
            },
            |checkpoint| Ok(checkpoint.created),
        )?;
        if now.saturating_sub(created) >= TTL.as_secs() {
            fs::remove_file(entry.path())?;
            private_directory(directory)?.sync_all()?;
        } else if let Some(checkpoint) = checkpoint {
            result.valid.push(checkpoint);
        } else {
            result.invalid.insert(id.to_owned());
        }
    }
    if result.len() > MAX_SESSIONS {
        return Err(LedgerError(
            "reader checkpoint session limit exceeded".into(),
        ));
    }
    Ok(result)
}

fn utc_second(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, c)| ![4, 7, 10, 13, 16, 19].contains(&i) && !c.is_ascii_digit())
    {
        return false;
    }
    let number = |from, to| value[from..to].parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day) = (number(0, 4), number(5, 7), number(8, 10));
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year > 0
        && day > 0
        && day <= days
        && number(11, 13) < 24
        && number(14, 16) < 60
        && number(17, 19) < 60
}

fn validate_request(request: &ReadRequest) -> Result<()> {
    if !(1..=MAX_READ_LIMIT).contains(&request.limit) {
        return Err(LedgerError("read limit must be between 1 and 1000".into()));
    }
    if request
        .filter
        .since
        .as_deref()
        .is_some_and(|v| !utc_second(v))
        || request
            .filter
            .until
            .as_deref()
            .is_some_and(|v| !utc_second(v))
        || matches!((&request.filter.since, &request.filter.until), (Some(a), Some(b)) if a >= b)
    {
        return Err(LedgerError(
            "reader times need a valid increasing whole-second UTC interval".into(),
        ));
    }
    if request.filter.selector == ReadSelector::All
        && (request.filter.stage.is_some()
            || request.filter.since.is_some()
            || request.filter.until.is_some())
    {
        return Err(LedgerError(
            "canonical export does not accept query filters".into(),
        ));
    }
    Ok(())
}

fn selected(filter: &ReadFilter, record: &Value) -> bool {
    if filter.selector == ReadSelector::All {
        return true;
    }
    let received = record["received_at"].as_str().unwrap_or("");
    if filter.since.as_deref().is_some_and(|v| received < v)
        || filter.until.as_deref().is_some_and(|v| received >= v)
    {
        return false;
    }
    let source = record["kind"] == "source";
    if let Some(stage) = filter.stage {
        let expected = match stage {
            ReadStage::Attempt => "attempt",
            ReadStage::Result => "result",
        };
        if !source || record["stage"] != expected {
            return false;
        }
    }
    let operation = record["operation"].as_str().unwrap_or("");
    match filter.selector {
        ReadSelector::All => true,
        ReadSelector::Execs => source && matches!(operation, "proc.exec" | "proc.exit"),
        ReadSelector::Paths => source && operation.starts_with("fs."),
        ReadSelector::Hosts => source && matches!(operation, "net.connect" | "net.dns"),
        ReadSelector::Denials => {
            (source && (record["decision"] == "deny" || operation == "fs.deny"))
                || record["kind"] == "denied"
        }
    }
}

/// Preserve status, supported sources and gap cardinality without cloning an
/// unbounded collection of gap payloads into every socket response.
pub(crate) fn coverage_summary(coverage: &Value) -> Value {
    let mut classes = serde_json::Map::new();
    for class in [
        "exec",
        "fs.write",
        "fs.deny",
        "net",
        "limits",
        "proxy.net",
        "ledger",
    ] {
        if let Some(entry) = coverage.get(class) {
            let status = entry["status"]
                .as_str()
                .filter(|s| s.len() <= 32)
                .unwrap_or("unobserved");
            let sources: Vec<_> = entry["sources"]
                .as_array()
                .into_iter()
                .flatten()
                .take(8)
                .filter_map(|v| v.as_str().filter(|s| s.len() <= 32))
                .collect();
            classes.insert(
                class.into(),
                json!({"status":status,"sources":sources,
                "observed_count":entry["observed_count"].as_u64(),
                "gap_count":entry["gaps"].as_array().map_or(0, Vec::len)}),
            );
        }
    }
    let status = coverage["status"]
        .as_str()
        .filter(|s| s.len() <= 32)
        .unwrap_or("by_class");
    json!({"scope":"snapshot_run","status":status,"classes":classes,
        "gap_count":coverage["gaps"].as_array().map_or(0, Vec::len)})
}

pub(crate) fn snapshot_labels_digest(child_protection: &str, coverage: &Value) -> Result<String> {
    let mut coverage = coverage.clone();
    if let Some(object) = coverage.as_object_mut() {
        object.remove("selection_status");
    }
    durable_digest(&json!({"child_protection":child_protection,"coverage":coverage}))
}

fn selection_status(filter: &ReadFilter, coverage: &Value) -> &'static str {
    let classes: &[&str] = match filter.selector {
        ReadSelector::All => &["exec", "fs.write", "fs.deny", "net", "limits", "proxy.net"],
        ReadSelector::Execs => &["exec"],
        ReadSelector::Paths => &["fs.write", "fs.deny"],
        ReadSelector::Hosts => &["net", "proxy.net"],
        ReadSelector::Denials => &["exec", "fs.write", "fs.deny", "net", "proxy.net"],
    };
    let classes_coverage = &coverage["classes"];
    let gaps = |entry: &Value| entry["gap_count"].as_u64().is_some_and(|count| count > 0);
    if coverage["status"] == "degraded"
        || gaps(coverage)
        || gaps(&classes_coverage["ledger"])
        || classes
            .iter()
            .any(|c| classes_coverage[*c]["status"] == "degraded" || gaps(&classes_coverage[*c]))
    {
        return "degraded";
    }
    if classes
        .iter()
        .any(|c| classes_coverage[*c]["status"] != "active")
    {
        "unobserved"
    } else {
        "active"
    }
}

impl Readers {
    pub(crate) fn read(
        &mut self,
        path: &Path,
        request: &ReadRequest,
        run: &RunRecord,
        poisoned: &[String],
        accepted_bytes: u64,
        proofs: (
            impl Fn(&str) -> Option<AppendReceipt>,
            impl Fn(u64, &str, u64, Option<&ReadPage>) -> bool,
        ),
    ) -> Result<ReadPage> {
        let (accepted, accepted_snapshot) = proofs;
        #[cfg(test)]
        let fail_directory_sync = self.fail_directory_sync;
        let sync_directory = |file: &File| {
            #[cfg(test)]
            if fail_directory_sync {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            file.sync_all()
        };
        validate_request(request)?;
        let now = epoch_seconds()?;
        let directory = checkpoint_directory(path)?;
        let mut durable = checkpoints(&directory, now)?;
        self.sessions
            .retain(|id, _| durable.valid.iter().any(|s| &s.id == id));
        let (id, token) = if let Some(cursor) = &request.cursor {
            if cursor.len() != 64
                || !cursor
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(LedgerError("invalid reader cursor".into()));
            }
            let id = cursor[..32].to_owned();
            if durable.invalid.contains(&id) {
                return Err(LedgerError(
                    "reader checkpoint is corrupt or unavailable; start a new snapshot".into(),
                ));
            }
            if !self.sessions.contains_key(&id)
                && let Some(index) = durable.valid.iter().position(|s| s.id == id)
            {
                durable.valid.swap_remove(index);
                let (checkpoint, file) = load_checkpoint(&directory, &id)?;
                if checkpoint.request.run_id != request.run_id
                    || checkpoint.request.filter != request.filter
                    || checkpoint.request.limit != request.limit
                {
                    return Err(LedgerError(
                        "reader cursor run, filter or limit mismatch".into(),
                    ));
                }
                // A visible rename is not proof of its directory sync. Flush
                // the validated descriptor and namespace before replaying it.
                file.sync_all()?;
                sync_directory(&private_directory(&directory)?)?;
                let session = Session::restore(
                    checkpoint,
                    path,
                    &cursor[32..],
                    &accepted,
                    &accepted_snapshot,
                )?;
                self.sessions.insert(id.clone(), session);
            }
            (id, cursor[32..].to_owned())
        } else {
            if durable.len() >= MAX_SESSIONS
                && let Some(oldest) = durable
                    .valid
                    .iter()
                    .filter(|s| s.prior.done)
                    .min_by_key(|s| s.created)
                    .map(|s| s.id.clone())
            {
                self.sessions.remove(&oldest);
                fs::remove_file(directory.join(format!("{oldest}.json")))?;
                private_directory(&directory)?.sync_all()?;
                durable.valid.retain(|s| s.id != oldest);
            }
            if durable.len() >= MAX_SESSIONS {
                return Err(LedgerError(
                    "reader session limit reached; wait for expiry".into(),
                ));
            }
            let file = crate::segments::Snapshot::open(path, accepted_bytes)?;
            let physical_bytes = file.physical_bytes();
            let (device, inode) = file.first_identity();
            let id = Uuid::new_v4().simple().to_string();
            let token = Uuid::new_v4().simple().to_string();
            let mut health = if poisoned.is_empty() {
                if ["settled", "denied", "outcome_unknown"].contains(&run.state.as_str()) {
                    "complete"
                } else {
                    "active"
                }
            } else if poisoned.iter().any(|p| {
                p.contains("invalid")
                    || p.contains("mismatch")
                    || p.contains("noncanonical")
                    || p.contains("violates")
            }) {
                "corrupt"
            } else {
                "incomplete"
            };
            let unexpected_tail = physical_bytes != accepted_bytes;
            if unexpected_tail {
                health = if physical_bytes < accepted_bytes {
                    "corrupt"
                } else {
                    "incomplete"
                };
            }
            let mut coverage = coverage_summary(&run.coverage);
            coverage["selection_status"] = json!(selection_status(&request.filter, &coverage));
            let template = ReadPage {
                schema: "ouro.ledger.read/1".into(),
                run_id: run.run_id.clone(),
                snapshot: run.chain.clone(),
                state: if poisoned.is_empty() {
                    run.state.clone()
                } else {
                    "outcome_unknown".into()
                },
                child_protection: run.child_protection.clone(),
                coverage,
                local_consistency: poisoned.is_empty() && !unexpected_tail,
                stream_status: health.into(),
                problems: if unexpected_tail {
                    vec!["canonical file length differs from its validated accepted prefix".into()]
                } else if poisoned.is_empty() {
                    vec![]
                } else {
                    vec!["stream recovery or durability is ambiguous; only the validated prefix is readable".into()]
                },
                records: vec![],
                ndjson: String::new(),
                next_cursor: None,
                scanned_through_seq: 0,
                done: false,
                oversized_record: None,
            };
            self.sessions.insert(
                id.clone(),
                Session {
                    created: now,
                    request: request.clone(),
                    file,
                    device,
                    inode,
                    accepted_bytes,
                    offset: 0,
                    pending: vec![],
                    ready: None,
                    next_seq: 1,
                    previous_digest: None,
                    verified: 0,
                    template,
                    current: token.clone(),
                    prior: None,
                    prior_position: None,
                },
            );
            (id, token)
        };
        let session = self.sessions.get_mut(&id).ok_or_else(|| LedgerError(
            "reader cursor expired or is unknown; start a new snapshot, do not append it to an old export".into()))?;
        if request.run_id != session.request.run_id
            || request.filter != session.request.filter
            || request.limit != session.request.limit
        {
            return Err(LedgerError(
                "reader cursor run, filter or limit mismatch".into(),
            ));
        }
        if let Some((prior, page)) = &session.prior
            && prior == &token
        {
            return Ok(page.clone());
        }
        if session.current != token {
            return Err(LedgerError(
                "reader cursor position is stale or forged".into(),
            ));
        }
        let mut page = session.template.clone();
        let before = session.position();
        session.page(&mut page, &accepted)?;
        page.scanned_through_seq = session.verified;
        if page.oversized_record.is_some() {
            page.next_cursor = Some(format!("{id}{token}"));
            session.prior = Some((token, page.clone()));
        } else {
            let next = Uuid::new_v4().simple().to_string();
            if !page.done {
                page.next_cursor = Some(format!("{id}{next}"));
            }
            session.prior = Some((token, page.clone()));
            session.current = next;
        }
        session.prior_position = Some(before);
        // Durable state precedes the socket response. A lost reply retries the
        // exact prior page after restart rather than silently skipping bytes.
        if let Err(error) = session.persist(&directory, &id, sync_directory) {
            self.sessions.remove(&id);
            return Err(error);
        }
        Ok(page)
    }
}

impl Session {
    fn position(&self) -> Position {
        Position {
            offset: self.offset,
            frame_start: self.offset
                - self
                    .ready
                    .as_ref()
                    .map_or(self.pending.len(), |r| r.bytes.len()) as u64,
            pending_bytes: self.pending.len(),
            ready_emitted: self.ready.as_ref().map(|r| r.emitted),
            next_seq: self.next_seq,
            previous_digest: self.previous_digest.clone(),
            verified: self.verified,
        }
    }

    fn persist(
        &self,
        directory: &Path,
        id: &str,
        sync_directory: impl Fn(&File) -> std::io::Result<()>,
    ) -> Result<()> {
        let (token, page) = self
            .prior
            .as_ref()
            .ok_or_else(|| LedgerError("reader checkpoint has no response".into()))?;
        let mut request = self.request.clone();
        request.cursor = None;
        let checkpoint = Checkpoint {
            schema: "ouro.ledger.reader-checkpoint/2".into(),
            id: id.into(),
            created: self.created,
            request,
            device: self.device,
            inode: self.inode,
            accepted_bytes: self.accepted_bytes,
            segments_digest: Some(self.file.identity()?),
            template: self.template.clone(),
            position: self.position(),
            current: self.current.clone(),
            prior: Replay {
                token: token.clone(),
                before: self.prior_position.clone().ok_or_else(|| {
                    LedgerError("reader checkpoint has no replay position".into())
                })?,
                response_digest: durable_digest(page)?,
                next_cursor: page.next_cursor.clone(),
                done: page.done,
            },
        };
        let envelope = Envelope {
            digest: durable_digest(&checkpoint)?,
            checkpoint,
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
            return Err(LedgerError("reader checkpoint exceeds bounded size".into()));
        }
        let parent = private_directory(directory)?;
        let temporary = directory.join(format!("{id}.tmp"));
        let final_path = directory.join(format!("{id}.json"));
        if fs::symlink_metadata(&final_path).is_ok() {
            checkpoint_file(&final_path)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &final_path)?;
            sync_directory(&parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn restore(
        checkpoint: Checkpoint,
        path: &Path,
        token: &str,
        accepted: impl Fn(&str) -> Option<AppendReceipt>,
        accepted_snapshot: impl Fn(u64, &str, u64, Option<&ReadPage>) -> bool,
    ) -> Result<Self> {
        let file = crate::segments::Snapshot::open(path, checkpoint.accepted_bytes)?;
        file.validate()?;
        if file.first_identity() != (checkpoint.device, checkpoint.inode)
            || match &checkpoint.segments_digest {
                Some(identity) => &file.identity()? != identity,
                None => !file.is_single_segment(),
            }
        {
            return Err(LedgerError(
                "reader canonical snapshot is corrupt: identity or length changed".into(),
            ));
        }
        let mut session = Self {
            created: checkpoint.created,
            request: checkpoint.request,
            file,
            device: checkpoint.device,
            inode: checkpoint.inode,
            accepted_bytes: checkpoint.accepted_bytes,
            offset: 0,
            pending: vec![],
            ready: None,
            next_seq: 1,
            previous_digest: None,
            verified: 0,
            template: checkpoint.template,
            current: checkpoint.current,
            prior: None,
            prior_position: Some(checkpoint.prior.before.clone()),
        };
        if token != checkpoint.prior.token && token != session.current {
            return Err(LedgerError(
                "reader cursor position is stale or forged".into(),
            ));
        }
        // Canonical recovery already validated the accepted prefix. Corroborate
        // its saved head and position, then reconstruct at most one bounded
        // frame before replaying the ordinary bounded page. No receipt can
        // grant append or capture access.
        if token != checkpoint.prior.token {
            // Advancing the saved current cursor does not need to replay the
            // previous response, which becomes stale after this request.
            session.restore_position(&checkpoint.position, &accepted, &accepted_snapshot)?;
            return Ok(session);
        }
        session.restore_position(&checkpoint.prior.before, &accepted, &accepted_snapshot)?;
        let mut page = session.template.clone();
        session.page(&mut page, &accepted)?;
        page.scanned_through_seq = session.verified;
        page.next_cursor = checkpoint.prior.next_cursor;
        if session.position() != checkpoint.position
            || page.done != checkpoint.prior.done
            || durable_digest(&page)? != checkpoint.prior.response_digest
            || page.next_cursor.as_ref().is_some_and(|cursor| {
                cursor != &format!("{}{}", checkpoint.id, session.current)
                    && !(page.oversized_record.is_some()
                        && cursor == &format!("{}{}", checkpoint.id, checkpoint.prior.token))
            })
        {
            return Err(LedgerError(
                "reader checkpoint replay did not corroborate".into(),
            ));
        }
        session.prior = Some((checkpoint.prior.token, page));
        Ok(session)
    }

    fn restore_position(
        &mut self,
        position: &Position,
        accepted: impl Fn(&str) -> Option<AppendReceipt>,
        accepted_snapshot: impl Fn(u64, &str, u64, Option<&ReadPage>) -> bool,
    ) -> Result<()> {
        let invalid =
            || LedgerError("reader checkpoint position or canonical snapshot is corrupt".into());
        let terminal = self
            .template
            .snapshot
            .head_seq
            .checked_add(1)
            .ok_or_else(invalid)?;
        if !(1..=terminal).contains(&position.next_seq)
            || position.offset > self.accepted_bytes
            || position.frame_start > position.offset
            || position.pending_bytes > MAX_FRAME_BYTES
            || position.verified != position.next_seq - u64::from(position.ready_emitted.is_none())
        {
            return Err(invalid());
        }
        // A snapshot head, including an empty one, is a claim about the
        // canonical accepted state: seq 0 must corroborate genuine canonical
        // emptiness instead of passing vacuously on forged metadata.
        let head_corroborates =
            |seq, digest: &Option<String>, bytes: u64, labels: Option<&ReadPage>| {
                if seq == 0 {
                    digest.is_none() && bytes == 0 && accepted_snapshot(0, "", 0, labels)
                } else {
                    digest
                        .as_deref()
                        .is_some_and(|digest| accepted_snapshot(seq, digest, bytes, labels))
                }
            };
        // A replay position simply has no predecessor record.
        let position_corroborates = |seq, digest: &Option<String>, bytes: u64| {
            if seq == 0 {
                digest.is_none() && bytes == 0
            } else {
                digest
                    .as_deref()
                    .is_some_and(|digest| accepted_snapshot(seq, digest, bytes, None))
            }
        };
        if !head_corroborates(
            self.template.snapshot.head_seq,
            &self.template.snapshot.head_digest,
            self.accepted_bytes,
            Some(&self.template),
        ) || !position_corroborates(
            position.next_seq - 1,
            &position.previous_digest,
            position.frame_start,
        ) {
            return Err(invalid());
        }
        let (mut pending, mut ready) = (Vec::new(), None);
        if position.ready_emitted.is_some() || position.pending_bytes > 0 {
            if position.next_seq == terminal {
                return Err(invalid());
            }
            let mut file = self.file.try_clone()?;
            file.seek(SeekFrom::Start(position.frame_start))?;
            let bound =
                (self.accepted_bytes - position.frame_start).min((MAX_FRAME_BYTES + 1) as u64);
            let mut input = BufReader::new(file.take(bound));
            let mut bytes = Vec::new();
            input.read_until(b'\n', &mut bytes)?;
            if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES || bytes.last() != Some(&b'\n') {
                return Err(invalid());
            }
            let end = position.frame_start + bytes.len() as u64;
            let digest = sha256_prefixed(&bytes[..bytes.len() - 1]);
            let record: Value =
                serde_json::from_slice(&bytes[..bytes.len() - 1]).map_err(|_| invalid())?;
            if record["request_id"]
                .as_str()
                .and_then(&accepted)
                .is_none_or(|receipt| receipt.seq != position.next_seq || receipt.digest != digest)
                || record["run_id"] != self.request.run_id
                || record["seq"].as_u64() != Some(position.next_seq)
                || record["prev"] != json!(position.previous_digest)
                || !accepted_snapshot(position.next_seq, &digest, end, None)
            {
                return Err(invalid());
            }
            if let Some(emitted) = position.ready_emitted {
                let bytes = String::from_utf8(bytes).map_err(|_| invalid())?;
                if position.offset != end
                    || position.pending_bytes != 0
                    || emitted >= bytes.len()
                    || !bytes.is_char_boundary(emitted)
                {
                    return Err(invalid());
                }
                ready = Some(Ready {
                    bytes,
                    record,
                    digest,
                    emitted,
                });
            } else {
                if !(position.frame_start..end).contains(&position.offset)
                    || position.offset - position.frame_start != position.pending_bytes as u64
                {
                    return Err(invalid());
                }
                pending.extend_from_slice(&bytes[..position.pending_bytes]);
            }
        } else if position.offset != position.frame_start {
            return Err(invalid());
        }
        if position.next_seq == terminal
            && (position.offset != self.accepted_bytes
                || position.pending_bytes != 0
                || position.ready_emitted.is_some()
                || position.previous_digest != self.template.snapshot.head_digest)
        {
            return Err(invalid());
        }
        self.offset = position.offset;
        self.pending = pending;
        self.ready = ready;
        self.next_seq = position.next_seq;
        self.previous_digest = position.previous_digest.clone();
        self.verified = position.verified;
        Ok(())
    }

    fn corrupt(&mut self, page: &mut ReadPage, reason: &str) {
        page.local_consistency = false;
        page.stream_status = "corrupt".into();
        page.problems.push(reason.into());
        page.done = true;
        self.template.local_consistency = false;
        self.template.stream_status = "corrupt".into();
    }

    fn advance(&mut self) {
        let ready = self.ready.take().expect("verified ready frame");
        self.previous_digest = Some(ready.digest);
        self.next_seq += 1;
    }

    fn page(
        &mut self,
        page: &mut ReadPage,
        accepted: impl Fn(&str) -> Option<AppendReceipt>,
    ) -> Result<()> {
        if let Err(error) = self.file.validate() {
            self.corrupt(page, &error.to_string());
            return Ok(());
        }
        let (mut scanned, mut frames, mut output) = (0, 0, 0);
        while frames < READ_SCAN_FRAMES && scanned < READ_SCAN_BYTES {
            if self.next_seq > self.template.snapshot.head_seq {
                if self.previous_digest != self.template.snapshot.head_digest {
                    self.corrupt(page, "snapshot head digest did not corroborate");
                } else {
                    page.done = true;
                }
                break;
            }
            if self.ready.is_none() {
                let mut buffer = [0; 8192];
                if self.file.seek(SeekFrom::Start(self.offset)).is_err() {
                    self.corrupt(page, "canonical stream position could not be read");
                    break;
                }
                let bound = buffer
                    .len()
                    .min(READ_SCAN_BYTES - scanned)
                    .min(MAX_FRAME_BYTES + 1 - self.pending.len());
                let count = match self.file.read(&mut buffer[..bound]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        self.corrupt(page, "canonical stream read failed");
                        break;
                    }
                };
                if count == 0 {
                    self.corrupt(page, "canonical snapshot is truncated or missing a frame");
                    break;
                }
                scanned += count;
                let consumed = buffer[..count]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(count, |i| i + 1);
                self.pending.extend_from_slice(&buffer[..consumed]);
                self.offset += consumed as u64;
                if self.pending.len() > MAX_FRAME_BYTES {
                    self.corrupt(page, "canonical frame exceeds bounded size");
                    break;
                }
                if self.pending.last() != Some(&b'\n') {
                    continue;
                }
                let bytes = std::mem::take(&mut self.pending);
                let record: Value = match serde_json::from_slice(&bytes[..bytes.len() - 1]) {
                    Ok(value) => value,
                    Err(_) => {
                        self.corrupt(page, "canonical frame is invalid JSON");
                        break;
                    }
                };
                let digest = sha256_prefixed(&bytes[..bytes.len() - 1]);
                let receipt = record["request_id"].as_str().and_then(&accepted);
                if receipt.is_none_or(|r| r.seq != self.next_seq || r.digest != digest)
                    || record["run_id"] != self.request.run_id
                    || record["seq"].as_u64() != Some(self.next_seq)
                    || record["prev"] != json!(self.previous_digest)
                {
                    self.corrupt(
                        page,
                        "canonical frame does not match the validated immutable record or chain",
                    );
                    break;
                }
                let bytes = String::from_utf8(bytes)
                    .map_err(|_| LedgerError("validated canonical UTF-8 unavailable".into()))?;
                self.verified = self.next_seq;
                self.ready = Some(Ready {
                    bytes,
                    record,
                    digest,
                    emitted: 0,
                });
                frames += 1;
            }
            let ready = self.ready.as_mut().expect("verified frame");
            if !selected(&self.request.filter, &ready.record) {
                self.advance();
                continue;
            }
            if self.request.filter.selector == ReadSelector::All {
                let mut end =
                    (ready.emitted + READ_CHUNK_BYTES - page.ndjson.len()).min(ready.bytes.len());
                while !ready.bytes.is_char_boundary(end) {
                    end -= 1;
                }
                page.ndjson.push_str(&ready.bytes[ready.emitted..end]);
                ready.emitted = end;
                if end == ready.bytes.len() {
                    self.advance();
                }
                if page.ndjson.len() >= READ_CHUNK_BYTES - 3 {
                    break;
                }
            } else {
                let bytes = ready.bytes.len() - 1;
                if bytes > READ_OUTPUT_BYTES {
                    page.oversized_record = Some(OversizedRecord {
                        seq: self.next_seq,
                        bytes,
                    });
                    page.problems.push(
                        "query record exceeds page bytes; canonical export retrieves it in chunks"
                            .into(),
                    );
                    break;
                }
                if output + bytes > READ_OUTPUT_BYTES {
                    break;
                }
                output += bytes;
                page.records.push(ready.record.clone());
                self.advance();
                if page.records.len() >= self.request.limit as usize {
                    break;
                }
            }
        }
        if self.next_seq > self.template.snapshot.head_seq
            && self.ready.is_none()
            && self.previous_digest == self.template.snapshot.head_digest
        {
            page.done = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_are_bounded_even_for_arbitrary_owner_coverage_and_keep_gaps_unknown() {
        let coverage = json!({"exec":{"status":"active","observed_count":{"private":"x".repeat(MAX_FRAME_BYTES)},
            "sources":["audit"],"gaps":[{"private":"x".repeat(MAX_FRAME_BYTES)}]},
            "net":{"status":"active","sources":["audit"],"gaps":[]},
            "proxy.net":{"status":"unsupported","sources":[],"gaps":[]}});
        let summary = coverage_summary(&coverage);
        assert!(serde_json::to_vec(&summary).unwrap().len() < 2048);
        assert_eq!(summary["classes"]["exec"]["observed_count"], Value::Null);
        assert_eq!(summary["classes"]["exec"]["gap_count"], 1);
        let mut filter = ReadFilter {
            selector: ReadSelector::Execs,
            stage: None,
            since: None,
            until: None,
        };
        assert_eq!(selection_status(&filter, &summary), "degraded");
        filter.selector = ReadSelector::Hosts;
        assert_eq!(selection_status(&filter, &summary), "unobserved");
    }

    #[test]
    fn time_filters_reject_invalid_dates_offsets_fractional_times_and_non_ascii() {
        assert!(utc_second("2024-02-29T23:59:59Z"));
        for value in [
            "2023-02-29T00:00:00Z",
            "2024-13-01T00:00:00Z",
            "2024-01-00T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00.1Z",
            "€24-01-01T00:00:00Z",
        ] {
            assert!(!utc_second(value), "accepted {value}");
        }
    }
}
