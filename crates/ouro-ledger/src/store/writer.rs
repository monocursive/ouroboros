//! The sole writer: it owns every loaded stream and appends to them.
use super::*;

pub(super) const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
/// Canonical history one verify page re-reads, so one request's reply stays
/// prompt; the re-read itself never runs on the writer thread.
pub(super) const VERIFY_PAGE_BYTES: u64 = 8 * 1024 * 1024;

pub struct Store {
    pub(crate) retention: ouro_records::retention::LedgerRetention,
    pub(super) root: PathBuf,
    pub(super) lock: File,
    pub(super) streams: BTreeMap<String, Stream>,
    pub(super) preparations: BTreeMap<String, (String, String)>,
    pub(super) recovery_ambiguous: bool,
    pub(super) readers: crate::reader::Readers,
    pub(super) index: Option<crate::projection::Projection>,
    pub(super) index_error: Option<String>,
    pub(super) index_pending: BTreeMap<String, RunRecord>,
    /// Pending journals whose background reconciliation failed, as last seen.
    /// They are retried only once the journal changes.
    #[cfg(target_os = "linux")]
    pub(super) pending_failures: BTreeMap<String, Option<pending_recovery::JournalSeen>>,
    pub(super) segment_limit: u64,
    pub(super) verify_page_bytes: u64,
    /// Advances whenever a GC may remove or rewrite run files, so a verifier
    /// reading off the writer thread can tell a GC race from damage.
    pub(super) gc_generation: u64,
}

/// A run directory, like every store member, is private (see `fsx`).
pub(super) const RUN_DIRECTORY: &str = "run directory is not an owned private directory";

/// The private store file at `path`, opened for reading and writing and as
/// `options` add.
pub(super) fn private_file(path: &Path, options: &mut OpenOptions) -> Result<File> {
    fsx::open_file(
        path,
        options.read(true).write(true),
        &format!("unsafe private file {}", path.display()),
    )
}

/// The exact projection bytes: canonical JSON and one LF, never published
/// unless it satisfies the frozen run schema.
pub(super) fn projection_bytes(run: &RunRecord) -> Result<Vec<u8>> {
    let value = serde_json::to_value(run)?;
    validate_frozen("run", &value)?;
    let mut bytes = canonical(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Durably replace the run's `run.json` in its pinned directory `dir`.
pub(super) fn publish_projection(dir: &File, run: &RunRecord) -> Result<()> {
    let bytes = projection_bytes(run)?;
    fsx::replace(
        dir,
        &fsx::temporary("run"),
        c"run.json",
        &bytes,
        Replaced::Projection,
    )
}

/// Whether `path` is a private file holding exactly `expected`, synchronized
/// now. Any doubt answers false, so the caller republishes it.
pub(super) fn synced_unchanged(path: &Path, expected: &[u8]) -> bool {
    use std::io::Read as _;
    let Ok(file) = private_file(path, &mut OpenOptions::new()) else {
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

pub(super) fn loaded<'a>(
    streams: &'a mut BTreeMap<String, Stream>,
    run_id: &str,
) -> &'a mut Stream {
    streams
        .get_mut(run_id)
        .expect("a looked-up run id names a loaded stream")
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

    pub(super) fn open_with_recovery_sync(
        data: &Path,
        recovery_sync: impl Fn(&File) -> std::io::Result<()>,
    ) -> Result<Self> {
        fsx::create_dir_all(data)?;
        let root = data.join("ledger");
        fsx::create_dir_all(&root)?;
        let lock = private_file(&root.join("writer.lock"), OpenOptions::new().create(true))?;
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
            let directory = fsx::create_dir_all(&entry.path())?;
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
                let path = entry.path();
                let mut published = false;
                if !synced_unchanged(&path.join("run.json"), &projection_bytes(&stream.run)?) {
                    publish_projection(&directory, &stream.run)?;
                    published = true;
                }
                if stream.pruned.is_none() {
                    let manifest = stream.manifest();
                    if !synced_unchanged(&path.join(manifest::NAME), &manifest::encode(&manifest)?)
                    {
                        manifest::write(&directory, &manifest)?;
                        published = true;
                    }
                }
                if !published {
                    directory.sync_all()?;
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
        fsx::create_dir_all(&directory)?;
        fsx::create_dir_all(&directory.join("receipts"))?;
        fsx::create_dir_all(&directory.join("artifacts"))?;
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

    pub(super) fn append_source_as(
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
    pub(super) fn stream_mut(&mut self, run_id: &str) -> &mut Stream {
        loaded(&mut self.streams, run_id)
    }

    /// Record why a loaded stream can no longer be trusted.
    pub(super) fn poison(&mut self, run_id: &str, kind: PoisonKind, detail: impl Into<String>) {
        self.stream_mut(run_id)
            .poisoned
            .push(Poison::new(kind, detail));
    }

    pub(super) fn stream(&self, run_id: &str) -> Result<&Stream> {
        check_run_id(run_id)?;
        self.streams
            .get(run_id)
            .ok_or_else(|| LedgerError("unknown run".into()))
    }

    pub(super) fn append(
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

    pub(super) fn persist(
        &mut self,
        run_id: &str,
        bytes: &[u8],
        record: &Value,
        receipt: &AppendReceipt,
        payload_digest: &str,
    ) -> Result<()> {
        let _scope = faults::enter(|| faults::Scope::of_record(record["kind"].as_str()?));
        let directory = self.root.join(run_id);
        let dir = fsx::open_dir(&directory, RUN_DIRECTORY)?;
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
            let file = private_file(
                &directory.join(manifest::name(next)),
                OpenOptions::new().append(true).create_new(true),
            )?;
            faults::hit(Point::RotationCreated)?;
            file.sync_all()?;
            dir.sync_all()?;
            faults::hit(Point::RotationSynced)?;
            stream.begin_segment(next);
            file
        } else {
            private_file(
                &directory.join(manifest::name(stream.active_segment)),
                OpenOptions::new()
                    .append(true)
                    .create(stream.active_segment == 1 && stream.segment_bytes == 0),
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
        publish_projection(&dir, &run)?;
        manifest::write(&dir, &manifest)?;
        faults::hit(Point::AppendBeforeDirectorySync)?;
        dir.sync_all()?;
        faults::hit(Point::AppendAfterDirectorySync)?;
        if self.index.is_some() {
            self.index_pending.insert(run_id.into(), run);
        }
        Ok(())
    }

    pub(super) fn write_projection(&self, run: &RunRecord) -> Result<()> {
        let dir = fsx::open_dir(&self.root.join(&run.run_id), RUN_DIRECTORY)?;
        publish_projection(&dir, run)
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

    pub(super) fn load_stream_with_sync(
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
