//! The sole writer. The canonical stream is authoritative; run.json is a projection.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
use uuid::Uuid;

use crate::protocol::{
    AppendReceipt, Chain, LedgerError, MAX_FRAME_BYTES, Peer, Result, RunRecord, VerifyReport,
};

const STREAM: &str = "events-0001.ndjson";

#[derive(Clone)]
struct Replay {
    digest: String,
    receipt: AppendReceipt,
}

struct Stream {
    run: RunRecord,
    replay: BTreeMap<String, Replay>,
    source_heads: BTreeMap<String, u64>,
    source_gaps: Vec<Value>,
    last_source: Option<Value>,
    first_loss: Option<Value>,
    receipt_phase: Option<String>,
    poisoned: Vec<String>,
}

pub struct Store {
    root: PathBuf,
    _lock: File,
    streams: BTreeMap<String, Stream>,
    preparations: BTreeMap<String, (String, String)>,
    recovery_ambiguous: bool,
    #[cfg(test)]
    fault: Option<Fault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    BeforeWrite,
    PartialWrite,
    EventSync,
    Projection,
    DirectorySync,
}

pub fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path
            .parent()
            .ok_or_else(|| LedgerError("directory has no parent".into()))?;
        if !parent.exists() {
            private_directory(parent)?;
        }
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        File::open(parent)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
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

fn valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
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

fn validate_source(event: &Value, attempt_id: &str) -> Result<records::Event> {
    validate_frozen("jail-event", event)?;
    let typed: records::Event = serde_json::from_value(event.clone())?;
    if typed.attempt_id != attempt_id || !records::semantic::event(event).is_empty() {
        return Err(LedgerError(
            "source attempt or semantic contract mismatch".into(),
        ));
    }
    Ok(typed)
}

fn is_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    })
}

fn validate_payload(payload: &Value) -> Result<()> {
    let keys = [
        "schema",
        "argv_digest",
        "policy_digest",
        "requirements",
        "profile",
        "jail_image_digest",
        "io",
        "capture",
        "evidence",
    ];
    let Some(object) = payload.as_object() else {
        return Err(LedgerError("prepare payload must be an object".into()));
    };
    if object.len() != keys.len()
        || object.keys().any(|key| !keys.contains(&key.as_str()))
        || payload["schema"] != "ouro.ledger.request/1"
        || !is_digest(&payload["argv_digest"])
        || !is_digest(&payload["policy_digest"])
        || !is_digest(&payload["jail_image_digest"])
        || !payload["profile"].as_str().is_some_and(valid_id)
        || !["strict", "best-effort"].contains(&payload["evidence"].as_str().unwrap_or(""))
    {
        return Err(LedgerError(
            "prepare only accepts the versioned digest-only request plan".into(),
        ));
    }
    let requirements = payload["requirements"]
        .as_array()
        .ok_or_else(|| LedgerError("requirements must be an array".into()))?;
    if requirements.len() > 64
        || requirements
            .iter()
            .any(|value| !value.as_str().is_some_and(valid_id))
    {
        return Err(LedgerError(
            "requirements are bounded named capabilities".into(),
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    if requirements
        .iter()
        .any(|value| !unique.insert(value.as_str().unwrap_or("")))
    {
        return Err(LedgerError("duplicate requirement".into()));
    }
    let io = payload["io"]
        .as_object()
        .ok_or_else(|| LedgerError("io must be an object".into()))?;
    if io.len() != 2
        || !["foreground", "batch"].contains(&payload["io"]["mode"].as_str().unwrap_or(""))
        || payload["io"]["pty"] != false
    {
        return Err(LedgerError("unsupported io plan".into()));
    }
    let capture = payload["capture"]
        .as_object()
        .ok_or_else(|| LedgerError("capture must be an object".into()))?;
    let streams = payload["capture"]["streams"]
        .as_array()
        .ok_or_else(|| LedgerError("capture streams must be an array".into()))?;
    let mut unique = std::collections::BTreeSet::new();
    if capture.len() != 2
        || payload["capture"]["limit_bytes"]
            .as_u64()
            .is_none_or(|limit| limit > 16 * 1_048_576)
        || streams.len() > 2
        || streams.iter().any(|stream| {
            ![Some("stdout"), Some("stderr")].contains(&stream.as_str())
                || !unique.insert(stream.as_str().unwrap_or(""))
        })
    {
        return Err(LedgerError(
            "capture only accepts unique stdout/stderr selections and at most 16 MiB per stream"
                .into(),
        ));
    }
    Ok(())
}

fn initial_run(run_id: &str, request_id: &str, attempt_id: &str, payload: Value) -> RunRecord {
    RunRecord {
        schema: "ouro.ledger.run/1".into(),
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
    }
}

impl Store {
    pub fn open(data: &Path) -> Result<Self> {
        private_directory(data)?;
        let root = data.join("ledger");
        private_directory(&root)?;
        let lock = private_file(&root.join("writer.lock"), true, false)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(LedgerError(
                "another ledger writer holds the process-lifetime lock".into(),
            ));
        }
        let mut store = Self {
            root,
            _lock: lock,
            streams: BTreeMap::new(),
            preparations: BTreeMap::new(),
            recovery_ambiguous: false,
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
            let (stream, _) = store.load_stream(&name)?;
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
                store.write_projection(&stream.run)?;
            }
            store.streams.insert(name, stream);
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare(&mut self, request_id: &str, payload: &Value, peer: &Peer) -> Result<RunRecord> {
        if !valid_id(request_id) {
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
                run: run.clone(),
                replay: BTreeMap::new(),
                source_heads: BTreeMap::new(),
                source_gaps: vec![],
                last_source: None,
                first_loss: None,
                receipt_phase: None,
                poisoned: vec![],
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
        if !valid_id(request_id)
            || effect_id.is_some_and(|id| !valid_id(id))
            || !body.is_object()
            || !["admitted", "denied", "settled", "note", "outcome_unknown"].contains(&kind)
        {
            return Err(LedgerError("invalid owner intent".into()));
        }
        for key in [
            "actor",
            "provenance",
            "run_id",
            "seq",
            "prev",
            "received_at",
        ] {
            if body.get(key).is_some() {
                return Err(LedgerError(format!(
                    "body cannot supply reserved identity {key}"
                )));
            }
        }
        if self.stream(run_id)?.run.owner.as_ref() != Some(peer) {
            return Err(LedgerError(
                "owner identity does not match the durable claim".into(),
            ));
        }
        validate_intent(self.stream(run_id)?, &json!({"kind":kind,"body":body}))?;
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
        let event_typed = validate_source(event, &self.stream(run_id)?.run.attempt_id)?;
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
            "producer",
            peer,
            Some(token_id),
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
        validate_transition(stream, &record)?;
        let seq = stream
            .run
            .chain
            .head_seq
            .checked_add(1)
            .ok_or_else(|| LedgerError("sequence exhausted".into()))?;
        record["schema"] = json!("ouro.ledger.event/1");
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
            // Preserve the complete frozen source envelope, including its schema.
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
            self.streams
                .get_mut(run_id)
                .expect("known stream")
                .poisoned
                .push(format!("uncertain persistence: {error}"));
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
        let path = self.root.join(run_id).join(STREAM);
        let mut file = private_file(&path, true, true)?;
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
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::EventSync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        file.sync_all()?;
        let stream = self.streams.get_mut(run_id).expect("known stream");
        apply_record(
            stream,
            &original_payload(record),
            receipt.clone(),
            payload_digest.into(),
        )?;
        let run = stream.run.clone();
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::Projection)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        self.write_projection(&run)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::DirectorySync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        File::open(self.root.join(run_id))?.sync_all()?;
        Ok(())
    }

    fn write_projection(&self, run: &RunRecord) -> Result<()> {
        validate_frozen("run", &serde_json::to_value(run)?)?;
        let dir = self.root.join(&run.run_id);
        let temp = dir.join(format!(".run-{}.tmp", Uuid::new_v4().simple()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(&canonical(&serde_json::to_value(run)?)?)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(temp, dir.join("run.json"))?;
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
            run.coverage = json!({"status":"degraded","gaps":stream.poisoned});
        }
        Ok(run)
    }

    pub fn runs(&self) -> Vec<RunRecord> {
        self.streams
            .keys()
            .filter_map(|id| self.show(id).ok())
            .collect()
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
            let owner = self.stream(&id)?.run.owner.clone();
            self.append(&id, json!({"kind":"outcome_unknown","request_id":"reconcile:owner-dead","body":{"owner":owner,"outcome":{"kind":"unknown","unknown":true,"unknown_reason":"owner birth identity is no longer live; tree termination and unrecorded effects are not inferred"},"coverage":{"status":"degraded","gaps":[{"reason":"owner_lost"}]}}}), "operator", peer, None)?;
            reconciled.push(self.show(&id)?);
        }
        Ok(reconciled)
    }

    pub fn verify(&self, run_id: Option<&str>) -> Result<Vec<VerifyReport>> {
        let ids: Vec<_> = match run_id {
            Some(id) => {
                self.stream(id)?;
                vec![id.to_owned()]
            }
            None => self.streams.keys().cloned().collect(),
        };
        ids.iter()
            .map(|id| {
                let (stream, events) = self.load_stream(id)?;
                let mut problems = stream.poisoned.clone();
                if stream.poisoned.is_empty() {
                    let projection = (|| -> Result<Value> {
                        use std::io::Read as _;
                        let file =
                            private_file(&self.root.join(id).join("run.json"), false, false)?;
                        let mut bytes = Vec::new();
                        file.take((4 * MAX_FRAME_BYTES + 1) as u64)
                            .read_to_end(&mut bytes)?;
                        if bytes.len() > 4 * MAX_FRAME_BYTES {
                            return Err(LedgerError(
                                "run projection exceeds its bounded read limit".into(),
                            ));
                        }
                        let value: Value = serde_json::from_slice(&bytes)?;
                        validate_frozen("run", &value)?;
                        Ok(value)
                    })();
                    if projection.is_err()
                        || projection.as_ref().is_ok_and(|value| {
                            serde_json::to_value(&stream.run)
                                .is_ok_and(|expected| expected != *value)
                        })
                    {
                        problems.push(
                            "run projection does not match verified canonical records".into(),
                        );
                    }
                }
                if let Some(active) = self.streams.get(id) {
                    problems.extend(active.poisoned.clone());
                }
                problems.sort();
                problems.dedup();
                Ok(VerifyReport {
                    run_id: id.clone(),
                    local_consistency: problems.is_empty(),
                    child_protection: stream.run.child_protection,
                    coverage: stream.run.coverage,
                    events,
                    problems,
                })
            })
            .collect()
    }

    fn load_stream(&self, run_id: &str) -> Result<(Stream, u64)> {
        let placeholder = initial_run(run_id, "", "", json!({}));
        let mut stream = Stream {
            run: placeholder,
            replay: BTreeMap::new(),
            source_heads: BTreeMap::new(),
            source_gaps: vec![],
            last_source: None,
            first_loss: None,
            receipt_phase: None,
            poisoned: vec![],
        };
        let file = match private_file(&self.root.join(run_id).join(STREAM), false, false) {
            Ok(file) => file,
            Err(error) => {
                stream
                    .poisoned
                    .push(format!("missing or unsafe canonical stream: {error}"));
                return Ok((stream, 0));
            }
        };
        let mut reader = BufReader::new(file);
        let mut events = 0;
        loop {
            let mut bytes = Vec::new();
            // read_until alone is unbounded; the limited reader also catches a missing newline.
            use std::io::Read as _;
            let length = reader
                .by_ref()
                .take((MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut bytes)?;
            if length == 0 {
                break;
            }
            if length > MAX_FRAME_BYTES || bytes.last() != Some(&b'\n') {
                stream
                    .poisoned
                    .push("oversized or interrupted canonical frame; bytes retained".into());
                break;
            }
            bytes.pop();
            let decoded = match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    stream
                        .poisoned
                        .push(format!("invalid canonical JSON: {error}"));
                    break;
                }
            };
            match canonical(&decoded) {
                Ok(encoded) if encoded == bytes => {}
                _ => {
                    stream
                        .poisoned
                        .push("noncanonical or unsupported stream bytes".into());
                    break;
                }
            }
            let expected_seq = events + 1;
            if validate_frozen("record", &decoded).is_err() {
                stream
                    .poisoned
                    .push("canonical ledger record violates its versioned schema".into());
                break;
            }
            let expected_schema = if decoded["kind"] == "source" {
                records::SCHEMA_EVENT
            } else {
                "ouro.ledger.event/1"
            };
            if decoded["schema"] != expected_schema
                || decoded["run_id"] != run_id
                || decoded["seq"].as_u64() != Some(expected_seq)
                || decoded["prev"] != json!(stream.run.chain.head_digest)
            {
                stream
                    .poisoned
                    .push("canonical identity, sequence or hash-chain link mismatch".into());
                break;
            }
            if events == 0 {
                if decoded["kind"] != "prepared" {
                    stream
                        .poisoned
                        .push("stream does not start at durable preparation".into());
                    break;
                }
                stream.run = initial_run(
                    run_id,
                    decoded["body"]["request_id"].as_str().unwrap_or(""),
                    decoded["attempt_id"].as_str().unwrap_or(""),
                    decoded["body"]["payload"].clone(),
                );
                if let Err(error) = validate_payload(&stream.run.payload) {
                    stream.poisoned.push(error.to_string());
                    break;
                }
            }
            if decoded["attempt_id"] != stream.run.attempt_id {
                stream.poisoned.push("mixed attempt identity".into());
                break;
            }
            if decoded["kind"] == "source"
                && validate_source(&original_payload(&decoded)["body"], &stream.run.attempt_id)
                    .is_err()
            {
                stream
                    .poisoned
                    .push("canonical producer violates the frozen source contract".into());
                break;
            }
            if let Some(receipt) = decoded["body"].get("receipt")
                && validate_receipt(receipt).is_err()
            {
                stream
                    .poisoned
                    .push("canonical receipt violates the frozen receipt contract".into());
                break;
            }
            let payload_digest = digest(&original_payload(&decoded))?;
            let receipt = AppendReceipt {
                seq: expected_seq,
                digest: sha256_prefixed(&bytes),
            };
            if let Err(error) = validate_transition(&stream, &original_payload(&decoded))
                .and_then(|_| validate_intent(&stream, &original_payload(&decoded)))
                .and_then(|_| {
                    apply_record(
                        &mut stream,
                        &original_payload(&decoded),
                        receipt,
                        payload_digest,
                    )
                })
            {
                stream.poisoned.push(error.to_string());
                break;
            }
            events += 1;
        }
        if events == 0 && stream.poisoned.is_empty() {
            stream.poisoned.push("empty canonical stream".into());
        }
        Ok((stream, events))
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

fn validate_intent(stream: &Stream, record: &Value) -> Result<()> {
    let kind = record["kind"].as_str().unwrap_or("");
    if !["admitted", "denied", "settled", "note", "outcome_unknown"].contains(&kind) {
        return Ok(());
    }
    let body = &record["body"];
    for key in [
        "actor",
        "provenance",
        "run_id",
        "seq",
        "prev",
        "received_at",
    ] {
        if body.get(key).is_some() {
            return Err(LedgerError(format!(
                "intent body cannot supply reserved identity {key}"
            )));
        }
    }
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
        let effect_key = format!("effect:{kind}:{effect_id}");
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
        stream.replay.insert(
            format!(
                "effect:{}:{effect_id}",
                record["kind"].as_str().unwrap_or("")
            ),
            replay,
        );
    }
    stream.run.chain = Chain {
        head_seq: receipt.seq,
        head_digest: Some(receipt.digest),
    };
    match record["kind"].as_str().unwrap_or("") {
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
            stream.run.outcome = Some(
                json!({"kind":"unknown","unknown":true,"unknown_reason":"owner reported an unresolved outcome"}),
            );
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
    if matches!(
        record["kind"].as_str(),
        Some("admitted" | "denied" | "settled" | "outcome_unknown")
    ) {
        if let Some(receipt) = record["body"].get("receipt") {
            stream.run.receipts.push(receipt.clone());
            if let Some(protection) = receipt.get("child_protection").and_then(Value::as_str)
                && (protection == "enforced" || protection == "unprotected")
            {
                stream.run.child_protection = protection.into();
            }
            if matches!(record["kind"].as_str(), Some("denied" | "settled")) {
                stream.run.outcome = receipt.get("outcome").cloned();
            }
        }
        for field in ["outcome", "coverage", "capture"] {
            if let Some(value) = record["body"].get(field) {
                match field {
                    "outcome" => stream.run.outcome = Some(value.clone()),
                    "coverage" => stream.run.coverage = value.clone(),
                    "capture" => stream.run.capture = value.clone(),
                    _ => {}
                }
            }
        }
    }
    // none remains unprotected regardless of an owner's requested display label.
    if stream
        .run
        .payload
        .get("jail_profile")
        .or_else(|| stream.run.payload.get("profile"))
        .and_then(Value::as_str)
        == Some("none")
    {
        stream.run.child_protection = "unprotected".into();
    }
    if !stream.source_gaps.is_empty() {
        if !stream.run.coverage.is_object() {
            stream.run.coverage = json!({"source_coverage":stream.run.coverage});
        }
        stream.run.coverage["ledger"] = json!({"status":"degraded","gaps":stream.source_gaps});
    }
    if record["kind"] == "outcome_unknown" {
        stream.run.outcome = Some(
            json!({"kind":"unknown","unknown":true,"unknown_reason":"owner or reconciliation reported an unresolved run outcome","observed_child_outcome":record["body"].get("outcome")}),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Peer {
        Peer {
            uid: unsafe { libc::geteuid() },
            pid: std::process::id(),
            birth: "fixture-birth".into(),
            boot_id: "fixture-boot".into(),
        }
    }
    fn payload() -> Value {
        let receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        json!({"schema":"ouro.ledger.request/1","profile":"tool","argv_digest":receipt["argv_digest"],"policy_digest":receipt["policy"]["digest"],"requirements":receipt["policy"]["requirements"],"jail_image_digest":receipt["argv_digest"],"io":{"mode":"batch","pty":false},"capture":{"streams":[],"limit_bytes":1_048_576},"evidence":"strict"})
    }
    fn prepared(run: &RunRecord) -> Value {
        let mut receipt: Value = serde_json::from_str(include_str!(
            "../../../docs/specs/jail-v1/examples/receipt-prepared.json"
        ))
        .unwrap();
        receipt["attempt_id"] = json!(run.attempt_id);
        receipt
    }
    fn create() -> (tempfile::TempDir, Store, RunRecord) {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let run = store.prepare("test-prepare", &payload(), &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        (temp, store, run)
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

    #[test]
    fn lifetime_lock_refuses_a_second_writer() {
        let (temp, _store, _) = create();
        assert!(
            matches!(Store::open(&temp.path().join("data")), Err(error) if error.0.contains("writer"))
        );
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
        assert!(note(&mut store, &run, "stable", json!({"meaning":"changed"})).is_err());
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
        assert!(
            store
                .prepare("test-prepare", &json!({"different":true}), &peer())
                .is_err()
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
        assert!(
            store
                .append_owner(
                    &run.run_id,
                    "effect-second",
                    "note",
                    Some("effect-1"),
                    &json!({"v":2}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(note(&mut store, &run, "retry", json!({})).is_err());
        drop(store);
        let mut recovered = Store::open(&temp.path().join("data")).unwrap();
        assert_eq!(fs::read(&stream_path).unwrap(), broken);
        assert!(!recovered.verify(None).unwrap()[0].local_consistency);
        assert_eq!(
            recovered.show(&run.run_id).unwrap().state,
            "outcome_unknown"
        );
        assert!(recovered.prepare("different", &payload(), &peer()).is_err());
        assert!(note(&mut recovered, &run, "partial", json!({"v":"half record"})).is_err());
    }

    #[test]
    fn every_persistence_failure_stops_acknowledgements_until_recovery() {
        for fault in [
            Fault::BeforeWrite,
            Fault::EventSync,
            Fault::Projection,
            Fault::DirectorySync,
        ] {
            let (temp, mut store, run) = create();
            store.fault = Some(fault);
            assert!(note(&mut store, &run, "uncertain", json!({"v":1})).is_err());
            store.fault = None;
            assert!(note(&mut store, &run, "new", json!({"v":2})).is_err());
            assert!(!store.verify(None).unwrap()[0].local_consistency);
            drop(store);
            let mut recovered = Store::open(&temp.path().join("data")).unwrap();
            let acknowledgement = note(&mut recovered, &run, "uncertain", json!({"v":1})).unwrap();
            assert!(acknowledgement.seq > 2);
            assert!(recovered.verify(None).unwrap()[0].local_consistency);
        }
    }

    #[test]
    fn admission_cannot_change_reserved_policy_or_argv() {
        let (_temp, mut store, run) = create();
        let mut receipt = prepared(&run);
        receipt["argv_digest"] = json!("sha256:bad");
        assert!(
            store
                .append_owner(
                    &run.run_id,
                    "admit",
                    "admitted",
                    None,
                    &json!({"receipt":receipt}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
        );
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
        assert!(
            store
                .append_owner(
                    &run.run_id,
                    "admit-again",
                    "admitted",
                    None,
                    &json!({"receipt":prepared(&run)}),
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(
            store
                .append_source(
                    &run.run_id,
                    &changed,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert_eq!(records[0].outcome.as_ref().unwrap()["unknown"], true);
        let mut stranger = peer();
        stranger.birth = "new-process-birth".into();
        assert!(store.claim_owner(&run.run_id, &stranger).is_err());
    }

    #[test]
    fn none_verify_retains_unprotected_even_if_receipt_claims_enforced() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("data")).unwrap();
        let mut plan = payload();
        plan["profile"] = json!("none");
        let run = store.prepare("none", &plan, &peer()).unwrap();
        store.claim_owner(&run.run_id, &peer()).unwrap();
        assert!(
            note(
                &mut store,
                &run,
                "cannot-upgrade",
                json!({"receipt":{"child_protection":"enforced"}})
            )
            .is_err()
        );
        assert_eq!(
            store.verify(None).unwrap()[0].child_protection,
            "unprotected"
        );
    }

    #[test]
    fn unsafe_store_paths_and_oversized_events_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(temp.path(), temp.path().join("link")).unwrap();
        assert!(Store::open(&temp.path().join("link")).is_err());
        let (_temp, mut store, run) = create();
        assert!(
            note(
                &mut store,
                &run,
                "large",
                json!({"body":"x".repeat(MAX_FRAME_BYTES)})
            )
            .is_err()
        );
        assert!(store.show("../../escape").is_err());
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
        assert!(
            store
                .append_source(
                    &run.run_id,
                    &source,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(
            store
                .append_source(
                    &run.run_id,
                    &source,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(
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
                .is_err()
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
            "after-settlement",
        ))
        .unwrap();
        assert!(
            store
                .append_source(
                    &run.run_id,
                    &event,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(
            store
                .append_owner(
                    &run.run_id,
                    "denied",
                    "denied",
                    None,
                    &body,
                    &peer(),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
                .is_err()
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
        assert!(
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
                .is_err()
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
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
}
