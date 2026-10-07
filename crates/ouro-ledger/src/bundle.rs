//! Bounded portable evidence bundles, independently replayable without a writer.
use crate::{
    daemon::Client,
    protocol::{LedgerError, ReadFilter, ReadPage, ReadRequest, ReadSelector, Result, RunRecord},
    store,
};
use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::{Duration, Instant},
};

pub(crate) mod files;
mod signing;
pub const MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECORDS: u64 = 10_000;
const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub name: String,
    pub bytes: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub authenticity: String,
    pub capture_digest_basis: String,
    /// Historical canonical projection, not present-day source storage availability.
    pub run: RunRecord,
    pub files: Vec<Member>,
}

fn error(message: &str) -> LedgerError {
    LedgerError(message.into())
}
fn check_time(start: Instant) -> Result<()> {
    if start.elapsed() >= DEADLINE {
        Err(error("bundle exceeded its 300 second work budget"))
    } else {
        Ok(())
    }
}
fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes =
        to_jcs(&serde_json::to_value(value)?).map_err(|e| LedgerError(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(error("bundle JSON exceeds 4 MiB"));
    }
    Ok(bytes)
}
fn read_json(file: impl Read) -> Result<Value> {
    let mut bytes = Vec::new();
    file.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err(error("bundle JSON exceeds 4 MiB"));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if canonical_json(&value)? != bytes {
        return Err(error("bundle JSON is not canonical with one LF"));
    }
    Ok(value)
}
fn write_json(dir: &File, name: &str, value: &impl Serialize) -> Result<Member> {
    let bytes = canonical_json(value)?;
    let mut file = files::member(dir, name, true)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(Member {
        name: name.into(),
        bytes: bytes.len() as u64,
        digest: sha256_prefixed(&bytes),
    })
}

fn copy_hash(
    input: &mut File,
    output: &mut impl Write,
    name: &str,
    max: u64,
    start: Instant,
) -> Result<Member> {
    let before = input.metadata()?;
    if before.len() > max {
        return Err(error("bundle member exceeds its byte bound"));
    }
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 65_536];
    loop {
        check_time(start)?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > max {
            return Err(error("bundle member grew beyond its byte bound"));
        }
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    let after = input.metadata()?;
    if bytes != before.len() || bytes != after.len() || before.modified()? != after.modified()? {
        return Err(error("bundle member changed while being read"));
    }
    Ok(Member {
        name: name.into(),
        bytes,
        digest: format!("sha256:{:x}", hash.finalize()),
    })
}

// Hash precisely the bytes consumed by semantic replay, on the same descriptor.
struct CheckedReader {
    file: File,
    before: std::fs::Metadata,
    hash: Sha256,
    bytes: u64,
    max: u64,
    start: Instant,
}
impl CheckedReader {
    fn new(file: File, max: u64, start: Instant) -> Result<Self> {
        let before = file.metadata()?;
        if before.len() > max {
            return Err(error("bundle member exceeds its byte bound"));
        }
        Ok(Self {
            file,
            before,
            hash: Sha256::new(),
            bytes: 0,
            max,
            start,
        })
    }
    fn finish(self, name: &str) -> Result<Member> {
        let after = self.file.metadata()?;
        if self.bytes != self.before.len()
            || self.bytes != after.len()
            || self.before.modified()? != after.modified()?
        {
            return Err(error("bundle member changed during verification"));
        }
        Ok(Member {
            name: name.into(),
            bytes: self.bytes,
            digest: format!("sha256:{:x}", self.hash.finalize()),
        })
    }
}
impl Read for CheckedReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.start.elapsed() >= DEADLINE {
            return Err(std::io::Error::other("bundle exceeded its work budget"));
        }
        let n = self.file.read(bytes)?;
        self.bytes += n as u64;
        if self.bytes > self.max {
            return Err(std::io::Error::other("bundle exceeds byte bound"));
        }
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
}

fn capture_bytes(run: &RunRecord, name: &str) -> Result<u64> {
    if !["stdout", "stderr", "argv"].contains(&name)
        || !["settled", "denied", "outcome_unknown"].contains(&run.state.as_str())
        || !run.payload["capture"]["streams"]
            .as_array()
            .is_some_and(|streams| streams.contains(&json!(name)))
        || run.capture[name]["path"] != format!("artifacts/{name}.bin")
        || !matches!(
            run.capture[name]["state"].as_str(),
            Some("captured" | "incomplete")
        )
    {
        return Err(error("selected capture has no terminal recorded artifact"));
    }
    run.capture[name]["stored_bytes"]
        .as_u64()
        .filter(|n| *n <= MAX_CAPTURE_BYTES)
        .ok_or_else(|| error("selected capture has invalid recorded size"))
}

/// Uses the authenticated writer's reader pin, which blocks both history and
/// capture GC for 600 seconds. This operation has a shorter 300 second budget.
pub fn create(
    client: &mut Client,
    data: &Path,
    run_id: &str,
    output: &Path,
    captures: &[String],
) -> Result<Value> {
    create_with_reader(data, run_id, output, captures, |request| {
        client.read(request)
    })
}

/// Sign using an explicitly supplied private key; provisioning is separate.
pub fn create_signed(
    client: &mut Client,
    data: &Path,
    run_id: &str,
    output: &Path,
    captures: &[String],
    key: &Path,
) -> Result<Value> {
    let signer = signing::Signer::load(key)?;
    assemble(data, run_id, output, captures, Some(&signer), |request| {
        client.read(request)
    })
}

/// Create a new private key directory without touching a node store.
pub fn keygen(output: &Path) -> Result<Value> {
    signing::keygen(output)
}

pub(crate) fn create_with_reader(
    data: &Path,
    run_id: &str,
    output: &Path,
    captures: &[String],
    read: impl FnMut(&ReadRequest) -> Result<ReadPage>,
) -> Result<Value> {
    assemble(data, run_id, output, captures, None, read)
}

fn assemble(
    data: &Path,
    run_id: &str,
    output: &Path,
    captures: &[String],
    signer: Option<&signing::Signer>,
    mut read: impl FnMut(&ReadRequest) -> Result<ReadPage>,
) -> Result<Value> {
    let start = Instant::now();
    let selected: BTreeSet<_> = captures.iter().map(String::as_str).collect();
    if selected.len() != captures.len()
        || selected
            .iter()
            .any(|s| !["stdout", "stderr", "argv"].contains(s))
    {
        return Err(error("select stdout, stderr and/or argv once each"));
    }
    let stage = files::Staging::new(output)?;
    let mut events = files::member(&stage.dir, "events.ndjson", true)?;
    let mut request = ReadRequest {
        run_id: run_id.into(),
        filter: ReadFilter {
            selector: ReadSelector::All,
            stage: None,
            since: None,
            until: None,
        },
        cursor: None,
        limit: 100,
    };
    let mut snapshot: Option<ReadPage> = None;
    let mut bytes = 0;
    let mut pages = 0;
    loop {
        check_time(start)?;
        let page = read(&request)?;
        check_time(start)?;
        pages += 1;
        bytes += page.ndjson.len() as u64;
        if bytes > MAX_STREAM_BYTES || pages > 20_000 || page.snapshot.head_seq > MAX_RECORDS {
            return Err(error(
                "bundle snapshot exceeds its byte, record or page bound",
            ));
        }
        if page.run_id != run_id
            || !page.local_consistency
            || !page.problems.is_empty()
            || matches!(page.stream_status.as_str(), "incomplete" | "corrupt")
            || !page.records.is_empty()
            || page.oversized_record.is_some()
        {
            return Err(error("bundle requires a consistent canonical snapshot"));
        }
        if let Some(first) = &snapshot {
            if first.snapshot != page.snapshot
                || first.state != page.state
                || first.child_protection != page.child_protection
                || first.coverage != page.coverage
            {
                return Err(error("bundle snapshot changed during pagination"));
            }
        } else {
            let mut labels = page.clone();
            labels.ndjson.clear();
            snapshot = Some(labels);
        }
        events.write_all(page.ndjson.as_bytes())?;
        if page.done {
            break;
        }
        let next = page
            .next_cursor
            .ok_or_else(|| error("bundle page has no continuation"))?;
        if request.cursor.as_ref() == Some(&next) {
            return Err(error("bundle page made no progress"));
        }
        request.cursor = Some(next);
    }
    events.sync_all()?;
    events.seek(SeekFrom::Start(0))?;
    let run = store::replay_bundle(&mut events, run_id)?;
    let labels = snapshot.expect("at least one page");
    let mut coverage = crate::reader::coverage_summary(&run.coverage);
    coverage["selection_status"] =
        json!(crate::reader::selection_status(&request.filter, &coverage));
    if run.chain != labels.snapshot
        || run.state != labels.state
        || run.child_protection != labels.child_protection
        || coverage != labels.coverage
    {
        return Err(error("bundle replay differs from writer snapshot"));
    }
    events.seek(SeekFrom::Start(0))?;
    let mut members = vec![
        copy_hash(
            &mut events,
            &mut std::io::sink(),
            "events.ndjson",
            MAX_STREAM_BYTES,
            start,
        )?,
        write_json(&stage.dir, "receipts.json", &run.receipts)?,
    ];
    if !selected.is_empty() {
        let root = files::directory(data)?;
        files::private(&root)?;
        let ledger = files::child_dir(&root, "ledger")?;
        files::private(&ledger)?;
        let source = files::child_dir(&ledger, &run.run_id)?;
        files::private(&source)?;
        let artifacts = files::child_dir(&source, "artifacts")?;
        files::private(&artifacts)?;
        for name in selected {
            let expected = capture_bytes(&run, name)?;
            let leaf = format!("{name}.bin");
            let mut input = files::member(&artifacts, &leaf, false)?;
            files::private(&input)?;
            let mut output = files::member(&stage.dir, &leaf, true)?;
            let member = copy_hash(&mut input, &mut output, &leaf, MAX_CAPTURE_BYTES, start)?;
            if member.bytes != expected {
                return Err(error("capture differs from its recorded size"));
            }
            output.sync_all()?;
            members.push(member);
        }
    }
    let manifest = Manifest {
        schema: if signer.is_some() {
            "ouro.ledger.bundle/2"
        } else {
            "ouro.ledger.bundle/1"
        }
        .into(),
        authenticity: if signer.is_some() {
            "signed"
        } else {
            "unsigned"
        }
        .into(),
        capture_digest_basis: "bundle_time".into(),
        run,
        files: members,
    };
    write_json(&stage.dir, "bundle.json", &manifest)?;
    if let Some(signer) = signer {
        write_json(
            &stage.dir,
            "signature.json",
            &signer.sign(&canonical_json(&manifest)?),
        )?;
    }
    let public = signer.map(signing::Signer::public);
    let report = verify_directory(&stage.dir, start, public.as_ref())?;
    check_time(start)?;
    stage.publish()?;
    Ok(report)
}

/// Opens only bundle members; never opens a node store, writer, or vendor state.
pub fn verify(input: &Path) -> Result<Value> {
    verify_with_key(input, None)
}

/// A supplied key is mandatory trust: unsigned bundles and other signers refuse.
pub fn verify_with_key(input: &Path, trusted_key: Option<&Path>) -> Result<Value> {
    let key = trusted_key.map(signing::trusted_key).transpose()?;
    verify_directory(&files::directory(input)?, Instant::now(), key.as_ref())
}

fn verify_directory(
    dir: &File,
    start: Instant,
    trusted: Option<&signing::PublicKey>,
) -> Result<Value> {
    let value = read_json(files::member(dir, "bundle.json", false)?)?;
    let manifest: Manifest = serde_json::from_value(value.clone())?;
    let signed = manifest.schema == "ouro.ledger.bundle/2" && manifest.authenticity == "signed";
    if !(signed
        || (manifest.schema == "ouro.ledger.bundle/1" && manifest.authenticity == "unsigned"))
        || manifest.capture_digest_basis != "bundle_time"
        || !(2..=5).contains(&manifest.files.len())
    {
        return Err(error("unsupported bundle manifest"));
    }
    let mut expected = BTreeSet::from(["bundle.json".to_owned()]);
    let signature = if signed {
        expected.insert("signature.json".into());
        // The envelope itself is bounded independently of the 4 MiB manifest.
        let mut file = files::member(dir, "signature.json", false)?;
        if file.metadata()?.len() > 4096 {
            return Err(error("bundle signature exceeds 4 KiB"));
        }
        Some(signing::verify(
            read_json((&mut file).take(4097))?,
            &canonical_json(&value)?,
            trusted,
        )?)
    } else {
        if trusted.is_some() {
            return Err(error("trusted-key verification requires a signed bundle"));
        }
        None
    };
    let mut captures = vec![];
    let mut replayed = None;
    let mut receipts = None;
    for member in &manifest.files {
        let max = match member.name.as_str() {
            "events.ndjson" => MAX_STREAM_BYTES,
            "receipts.json" => MAX_JSON_BYTES,
            "stdout.bin" | "stderr.bin" | "argv.bin" => {
                let stream = member.name.trim_end_matches(".bin");
                if capture_bytes(&manifest.run, stream)? != member.bytes {
                    return Err(error("bundle capture differs from canonical size"));
                }
                captures.push(stream.to_owned());
                MAX_CAPTURE_BYTES
            }
            _ => return Err(error("unexpected bundle inventory member")),
        };
        if !expected.insert(member.name.clone()) || member.bytes > max {
            return Err(error("duplicate or oversized bundle member"));
        }
        let mut file = CheckedReader::new(files::member(dir, &member.name, false)?, max, start)?;
        match member.name.as_str() {
            "events.ndjson" => {
                replayed = Some(store::replay_bundle(&mut file, &manifest.run.run_id)?)
            }
            "receipts.json" => receipts = Some(read_json(&mut file)?),
            _ => {
                std::io::copy(&mut file, &mut std::io::sink())?;
            }
        }
        let observed = file.finish(&member.name)?;
        if observed != *member {
            return Err(error("bundle member size or digest mismatch"));
        }
    }
    if !expected.contains("events.ndjson")
        || !expected.contains("receipts.json")
        || files::names(dir)? != expected
    {
        return Err(error("bundle has missing or uninventoried members"));
    }
    let run = replayed.ok_or_else(|| error("bundle has no canonical records"))?;
    if serde_json::to_value(&run)? != value["run"] {
        return Err(error("bundle run labels differ from canonical replay"));
    }
    if receipts != Some(json!(run.receipts)) {
        return Err(error(
            "bundle receipts differ from embedded canonical receipts",
        ));
    }
    check_time(start)?;
    let mut report = json!({"schema":"ouro.ledger.bundle-verification/1", "run_id":run.run_id,
        "snapshot":run.chain, "state":run.state, "child_protection":run.child_protection,
        "coverage":run.coverage, "local_consistency":true, "authenticity":"unsigned",
        "external_custody":false, "capture_digest_basis":"bundle_time", "captures":captures,
        "manifest_digest":sha256_prefixed(&canonical_json(&value)?)});
    if let Some(signature) = signature {
        report["schema"] = json!("ouro.ledger.bundle-verification/2");
        report["authenticity"] = json!("signed");
        report["signature"] = signature;
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
