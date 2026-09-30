//! Bounded readers of the original canonical stream. Cursors confer no authority.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use ouro_records::canonical::sha256_prefixed;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::protocol::{
    AppendReceipt, LedgerError, MAX_FRAME_BYTES, MAX_READ_LIMIT, OversizedRecord, READ_CHUNK_BYTES,
    READ_OUTPUT_BYTES, READ_SCAN_BYTES, READ_SCAN_FRAMES, ReadFilter, ReadPage, ReadRequest,
    ReadSelector, ReadStage, Result, RunRecord,
};

const MAX_SESSIONS: usize = 32;
const TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(crate) struct Readers {
    sessions: BTreeMap<String, Session>,
}

struct Ready {
    bytes: String,
    record: Value,
    digest: String,
    emitted: usize,
}

struct Session {
    created: Instant,
    request: ReadRequest,
    path: PathBuf,
    file: File,
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
}

fn reader_file(path: &Path) -> Result<File> {
    for directory in path
        .parent()
        .into_iter()
        .chain(path.parent().and_then(Path::parent))
    {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(LedgerError("reader directory is unsafe".into()));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(LedgerError("reader canonical file is unsafe".into()));
    }
    Ok(file)
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
fn coverage_summary(coverage: &Value) -> Value {
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

fn selection_status(filter: &ReadFilter, coverage: &Value) -> &'static str {
    let classes: &[&str] = match filter.selector {
        ReadSelector::All => &["exec", "fs.write", "fs.deny", "net", "limits", "proxy.net"],
        ReadSelector::Execs => &["exec"],
        ReadSelector::Paths => &["fs.write", "fs.deny"],
        ReadSelector::Hosts => &["net", "proxy.net"],
        ReadSelector::Denials => &["exec", "fs.write", "fs.deny", "net", "proxy.net"],
    };
    let gaps = |entry: &Value| entry["gaps"].as_array().is_some_and(|g| !g.is_empty());
    if coverage["status"] == "degraded"
        || gaps(coverage)
        || gaps(&coverage["ledger"])
        || classes
            .iter()
            .any(|c| coverage[*c]["status"] == "degraded" || gaps(&coverage[*c]))
    {
        return "degraded";
    }
    if classes.iter().any(|c| coverage[*c]["status"] != "active") {
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
        accepted: impl Fn(&str) -> Option<AppendReceipt>,
    ) -> Result<ReadPage> {
        validate_request(request)?;
        self.sessions.retain(|_, s| s.created.elapsed() < TTL);
        let (id, token) = if let Some(cursor) = &request.cursor {
            if cursor.len() != 64
                || !cursor
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(LedgerError("invalid reader cursor".into()));
            }
            (cursor[..32].to_owned(), cursor[32..].to_owned())
        } else {
            if self.sessions.len() >= MAX_SESSIONS
                && let Some(oldest) = self
                    .sessions
                    .iter()
                    .filter(|(_, s)| s.prior.as_ref().is_some_and(|(_, p)| p.done))
                    .min_by_key(|(_, s)| s.created)
                    .map(|(id, _)| id.clone())
            {
                self.sessions.remove(&oldest);
            }
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(LedgerError(
                    "reader session limit reached; wait for expiry".into(),
                ));
            }
            let file = reader_file(path)?;
            let metadata = file.metadata()?;
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
            let unexpected_tail = metadata.len() != accepted_bytes;
            if unexpected_tail {
                health = if metadata.len() < accepted_bytes {
                    "corrupt"
                } else {
                    "incomplete"
                };
            }
            let mut coverage = coverage_summary(&run.coverage);
            coverage["selection_status"] = json!(selection_status(&request.filter, &run.coverage));
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
                    created: Instant::now(),
                    request: request.clone(),
                    path: path.into(),
                    file,
                    device: metadata.dev(),
                    inode: metadata.ino(),
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
                },
            );
            (id, token)
        };
        let session = self.sessions.get_mut(&id).ok_or_else(|| LedgerError(
            "reader cursor expired or daemon restarted; start a new snapshot, do not append it to an old export".into()))?;
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
        session.page(&mut page, accepted)?;
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
        Ok(page)
    }
}

impl Session {
    fn corrupt(&mut self, page: &mut ReadPage, reason: &'static str) {
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
        let current = match reader_file(&self.path) {
            Ok(file) => file.metadata()?,
            Err(_) => {
                self.corrupt(page, "canonical stream became missing or unsafe");
                return Ok(());
            }
        };
        if current.dev() != self.device || current.ino() != self.inode {
            self.corrupt(page, "canonical stream identity changed during snapshot");
            return Ok(());
        }
        if current.len() < self.accepted_bytes {
            self.corrupt(page, "canonical snapshot was truncated during reading");
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
        assert_eq!(selection_status(&filter, &coverage), "degraded");
        filter.selector = ReadSelector::Hosts;
        assert_eq!(selection_status(&filter, &coverage), "unobserved");
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
