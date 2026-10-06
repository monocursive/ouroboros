//! Whole-run pruning. A synchronized retention anchor authorizes only an exact
//! inventory; recovery never guesses which missing files or replay ids existed.
use std::{ffi::CString, io::Read, os::fd::FromRawFd};

use serde::{Deserialize, Serialize};

use super::*;
use crate::protocol::{GcFailure, GcReceipt, GcResult, PrunedHistory};

const ANCHOR: &str = "gc.json";
const DONE: &str = "gc-done.json";
const MAX_ANCHOR: usize = 16 * 1024 * 1024;
const MAX_REPLAYS: usize = 65_536;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemovedFile {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) digest: String,
    pub(super) device: u64,
    pub(super) inode: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retained {
    schema: String,
    run: RunRecord,
    manifest: manifest::Manifest,
    replay: BTreeMap<String, Replay>,
    strict_source_loss: bool,
    last_activity_at: String,
    collected_at: String,
    cutoff: String,
    retain_days: u32,
    operator: Peer,
    files: Vec<RemovedFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    digest: String,
    retained: Retained,
}

pub(super) fn digest_valid(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(LedgerError("GC requires owned private directories".into()));
    }
    Ok(file)
}

pub(super) fn safe_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    safe_metadata(&file.metadata()?)?;
    Ok(file)
}

fn safe_metadata(m: &fs::Metadata) -> Result<()> {
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(LedgerError("GC refuses unsafe or linked files".into()));
    }
    Ok(())
}

pub(super) fn file_hash(file: &mut File, bytes: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut remaining = bytes;
    let mut buffer = [0u8; 65_536];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..limit])?;
        if n == 0 {
            return Err(LedgerError(
                "GC file was truncated during verification".into(),
            ));
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(LedgerError("GC file grew during verification".into()));
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Open relative to a pinned parent, never through a caller-supplied path.
pub(super) fn member(root: &Path, name: &str) -> Result<(File, CString, Option<File>)> {
    let (parent, leaf) = if let Some(leaf) = name.strip_prefix("artifacts/") {
        if !["stdout.bin", "stderr.bin"].contains(&leaf) {
            return Err(LedgerError("unsafe GC capture path".into()));
        }
        (root.join("artifacts"), leaf)
    } else {
        let number = name
            .strip_prefix("events-")
            .and_then(|s| s.strip_suffix(".ndjson"))
            .and_then(|s| s.parse::<usize>().ok());
        if !number
            .is_some_and(|i| (1..=manifest::MAX_SEGMENTS).contains(&i) && name == manifest::name(i))
        {
            return Err(LedgerError("unsafe GC segment path".into()));
        }
        (root.to_owned(), name)
    };
    directory(root)?;
    let parent = directory(&parent)?;
    let leaf = CString::new(leaf).map_err(|_| LedgerError("unsafe GC filename".into()))?;
    // SAFETY: parent and the NUL-terminated filename remain live for openat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok((parent, leaf, None));
        }
        return Err(error.into());
    }
    // SAFETY: openat returned one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    safe_metadata(&file.metadata()?)?;
    Ok((parent, leaf, Some(file)))
}

pub(super) fn check_member(root: &Path, entry: &RemovedFile) -> Result<(File, CString, bool)> {
    let (parent, leaf, file) = member(root, &entry.path)?;
    let Some(mut file) = file else {
        return Ok((parent, leaf, false));
    };
    let metadata = file.metadata()?;
    if metadata.dev() != entry.device
        || metadata.ino() != entry.inode
        || metadata.len() != entry.bytes
        || file_hash(&mut file, entry.bytes)? != entry.digest
    {
        return Err(LedgerError(
            "GC inventory file identity or content changed; bytes preserved".into(),
        ));
    }
    // Check the namespace again after hashing, before unlinking through the same parent.
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pointers reference a live name and writable stat buffer.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut current,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if i128::from(current.st_dev) != i128::from(metadata.dev())
        || i128::from(current.st_ino) != i128::from(metadata.ino())
    {
        return Err(LedgerError(
            "GC inventory path changed during verification".into(),
        ));
    }
    Ok((parent, leaf, true))
}

pub(super) fn read_json(path: &Path, max: usize) -> Result<Value> {
    let mut bytes = Vec::new();
    safe_file(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max || bytes.pop() != Some(b'\n') {
        return Err(LedgerError("oversized or interrupted GC metadata".into()));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if canonical(&value)? != bytes {
        return Err(LedgerError("noncanonical GC metadata".into()));
    }
    Ok(value)
}

pub(super) fn publish(root: &Path, name: &str, value: &Value, max: usize) -> Result<()> {
    let bytes = canonical(value)?;
    if bytes.len() + 1 > max {
        return Err(LedgerError(
            "GC retained metadata exceeds its bounded size; no files removed".into(),
        ));
    }
    // Never replace an existing authority or completion marker.
    if fs::symlink_metadata(root.join(name)).is_ok() {
        if read_json(&root.join(name), max)? != *value {
            return Err(LedgerError("existing GC metadata conflicts".into()));
        }
        safe_file(&root.join(name))?.sync_all()?;
        directory(root)?.sync_all()?;
        return Ok(());
    }
    let temp = root.join(format!(".gc-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        // The process-lifetime writer lock serializes publication. A temp file
        // never becomes authority until this atomic rename is visible.
        fs::rename(&temp, root.join(name))?;
        directory(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

impl Retained {
    fn digest(&self) -> Result<String> {
        digest(&serde_json::to_value(self)?)
    }
    fn history(&self, complete: bool) -> Result<PrunedHistory> {
        Ok(PrunedHistory {
            state: if complete { "pruned" } else { "pruning" }.into(),
            anchor_digest: self.digest()?,
            collected_at: self.collected_at.clone(),
        })
    }
    fn receipt(&self) -> Result<GcReceipt> {
        Ok(GcReceipt {
            run_id: self.run.run_id.clone(),
            chain: self.run.chain.clone(),
            history: self.history(true)?,
            removed_files: self.files.len() as u32,
            removed_bytes: self.files.iter().map(|f| f.bytes).sum(),
        })
    }
    fn projection(&self, complete: bool) -> Result<RunRecord> {
        let mut run = self.run.clone();
        run.history = Some(self.history(complete)?);
        for file in &self.files {
            if let Some(name) = file
                .path
                .strip_prefix("artifacts/")
                .and_then(|s| s.strip_suffix(".bin"))
            {
                run.capture[name]["state"] = json!(if complete { "pruned" } else { "pruning" });
                if complete {
                    run.capture[name]["stored_bytes"] = json!(0);
                    run.capture[name]["pruned_bytes"] = json!(file.bytes);
                }
            }
        }
        Ok(run)
    }
    fn completion(&self) -> Result<Value> {
        Ok(json!({"schema":"ouro.ledger.gc-complete/1","anchor_digest":self.digest()?}))
    }
    fn complete(&self, root: &Path) -> Result<bool> {
        match fs::symlink_metadata(root.join(DONE)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
            Ok(_) => {
                if read_json(&root.join(DONE), 1024)? != self.completion()? {
                    return Err(LedgerError(
                        "GC completion does not match its anchor".into(),
                    ));
                }
                Ok(true)
            }
        }
    }
    fn validate(&self, root: &Path, id: &str) -> Result<()> {
        validate_frozen("run", &serde_json::to_value(&self.run)?)?;
        if self.schema != "ouro.ledger.gc-anchor/1"
            || self.run.run_id != id
            || self.run.history.is_some()
            || !self.run.holds.is_empty()
            || !["settled", "denied"].contains(&self.run.state.as_str())
            || self.run.settlement != "recorded"
            || self.run.outcome.as_ref().is_none_or(|outcome| {
                !matches!(
                    outcome["kind"].as_str(),
                    Some("exited" | "signaled" | "exec_error" | "refused")
                ) || outcome["unknown"] == true
            })
            || !(1..=36_500).contains(&self.retain_days)
            || ![&self.last_activity_at, &self.cutoff, &self.collected_at]
                .into_iter()
                .all(|s| crate::reader::utc_second(s))
            || self.last_activity_at > self.cutoff
            || self.cutoff >= self.collected_at
            || self.manifest.run_id != id
            || self.manifest.attempt_id != self.run.attempt_id
            || manifest::read(root, id)?.as_ref() != Some(&self.manifest)
            || self.replay.is_empty()
            || self.replay.len() > MAX_REPLAYS
            || self.files.len() < self.manifest.segments.len()
            || self.files.len() > self.manifest.segments.len() + 2
        {
            return Err(LedgerError("invalid retained GC authority".into()));
        }
        let last = self
            .manifest
            .segments
            .last()
            .ok_or_else(|| LedgerError("GC anchor has no segments".into()))?;
        if self.run.chain.head_seq != last.last_seq
            || self.run.chain.head_digest.as_ref() != Some(&last.head_digest)
        {
            return Err(LedgerError(
                "GC chain anchor differs from terminal projection".into(),
            ));
        }
        for (i, file) in self.files.iter().enumerate() {
            if !digest_valid(&file.digest) || file.bytes > 1024 * 1024 * 1024 {
                return Err(LedgerError("invalid GC file anchor".into()));
            }
            if let Some(segment) = self.manifest.segments.get(i) {
                if file.path != segment.name
                    || file.bytes != segment.bytes
                    || file.digest != segment.digest
                {
                    return Err(LedgerError(
                        "GC segment inventory differs from chain anchors".into(),
                    ));
                }
            } else if !["artifacts/stdout.bin", "artifacts/stderr.bin"]
                .contains(&file.path.as_str())
                || file.bytes > 16 * 1024 * 1024
            {
                return Err(LedgerError("invalid GC capture inventory".into()));
            }
            if self.files[..i].iter().any(|prior| prior.path == file.path) {
                return Err(LedgerError("duplicate GC file inventory".into()));
            }
        }
        for (key, replay) in &self.replay {
            if key.is_empty()
                || key.len() > 256
                || !digest_valid(&replay.digest)
                || !digest_valid(&replay.receipt.digest)
                || replay.receipt.seq == 0
                || replay.receipt.seq > self.run.chain.head_seq
            {
                return Err(LedgerError("invalid retained replay identity".into()));
            }
        }
        let preparation = json!({"kind":"prepared","body":{"request_id":self.run.request_id,"payload":self.run.payload},"request_id":format!("prepare:{}",self.run.request_id)});
        if !self
            .replay
            .get(&format!("prepare:{}", self.run.request_id))
            .is_some_and(|r| {
                r.receipt.seq == 1 && digest(&preparation).is_ok_and(|d| d == r.digest)
            })
        {
            return Err(LedgerError(
                "GC anchor does not preserve preparation identity".into(),
            ));
        }
        Ok(())
    }

    fn check_remaining(&self, root: &Path, complete: bool) -> Result<()> {
        capture_pruning::check_pruned_history(root, &self.run)?;
        // Extra successors must not disappear into a successful pruning report.
        for entry in fs::read_dir(root)? {
            let name = entry?.file_name();
            if name.as_encoded_bytes().starts_with(b"events-")
                && !self
                    .files
                    .iter()
                    .any(|f| name == std::ffi::OsStr::new(&f.path))
            {
                return Err(LedgerError("unlisted canonical segment during GC".into()));
            }
        }
        for entry in &self.files {
            if check_member(root, entry)?.2 && complete {
                return Err(LedgerError(
                    "pruned file reappeared after GC completion".into(),
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn read(root: &Path, id: &str) -> Result<Option<Retained>> {
    directory(root)?;
    match fs::symlink_metadata(root.join(ANCHOR)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(root.join(DONE)).is_ok() {
                return Err(LedgerError(
                    "GC completion is missing its retained authority".into(),
                ));
            }
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let value = read_json(&root.join(ANCHOR), MAX_ANCHOR)?;
    let envelope: Envelope = serde_json::from_value(value.clone())?;
    if envelope.digest != envelope.retained.digest()? || serde_json::to_value(&envelope)? != value {
        return Err(LedgerError(
            "GC anchor checksum or encoding mismatch".into(),
        ));
    }
    envelope.retained.validate(root, id)?;
    Ok(Some(envelope.retained))
}

impl Store {
    pub fn gc(
        &mut self,
        retain_days: u32,
        after: Option<&str>,
        limit: u32,
        peer: &Peer,
    ) -> Result<GcResult> {
        self.gc_policy(Some(retain_days), None, after, limit, peer)
    }

    pub fn gc_policy(
        &mut self,
        history: Option<u32>,
        captures: Option<u32>,
        after: Option<&str>,
        limit: u32,
        peer: &Peer,
    ) -> Result<GcResult> {
        let policy = self
            .retention
            .resolve(history, captures)
            .map_err(|e| LedgerError(e.into()))?;
        self.gc_policy_at(policy, after, limit, peer, SystemTime::now())
    }

    #[cfg(test)]
    pub(super) fn gc_at(
        &mut self,
        retain_days: u32,
        after: Option<&str>,
        limit: u32,
        peer: &Peer,
        now: SystemTime,
    ) -> Result<GcResult> {
        let policy = self
            .retention
            .resolve(Some(retain_days), None)
            .map_err(|e| LedgerError(e.into()))?;
        self.gc_policy_at(policy, after, limit, peer, now)
    }

    pub(super) fn gc_policy_at(
        &mut self,
        policy: ouro_records::retention::RetentionPolicy,
        after: Option<&str>,
        limit: u32,
        peer: &Peer,
        now: SystemTime,
    ) -> Result<GcResult> {
        let retain_days = policy.retain_days;
        // Full verification and fsync must not stall a live launch's strict channel.
        if self.streams.values().any(|s| {
            s.run.owner.is_some() && ["prepared", "admitted"].contains(&s.run.state.as_str())
        }) {
            return Err(LedgerError(
                "GC requires a quiescent writer; finish or reconcile active launch owners first"
                    .into(),
            ));
        }
        let plan = self.gc_plan_policy_at(policy, after, limit, now)?;
        let mut result = GcResult {
            schema: "ouro.ledger.gc-result/1".into(),
            retain_days,
            capture_retain_days: policy.capture_retain_days,
            pruned: vec![],
            captures_pruned: vec![],
            kept: vec![],
            failed: vec![],
            next_after: plan.next_after,
        };
        for candidate in plan.runs {
            let id = &candidate.run_id;
            if self.stream(id)?.pruned.is_none()
                && ((candidate.captures_candidate && !candidate.candidate)
                    || self
                        .stream(id)?
                        .run
                        .capture_history
                        .as_ref()
                        .is_some_and(|h| h.state == "pruning"))
            {
                match self.prune_captures(
                    id,
                    policy.capture_retain_days,
                    &plan.evaluated_at,
                    &plan.capture_cutoff,
                    peer,
                ) {
                    Ok(receipt) => result.captures_pruned.push(receipt),
                    Err(e) => {
                        result.failed.push(GcFailure {
                            run_id: id.clone(),
                            message: e.to_string().chars().take(512).collect(),
                        });
                        continue;
                    }
                }
            }
            if !candidate.candidate && self.stream(id)?.pruned.is_none() {
                if result
                    .captures_pruned
                    .last()
                    .is_some_and(|r| r.run_id == *id)
                {
                    continue;
                }
                result.kept.push(candidate);
                continue;
            }
            let collected = (|| -> Result<GcReceipt> {
                let retained = if let Some(retained) = self.stream(id)?.pruned.clone() {
                    retained
                } else {
                    self.begin_pruning(id, retain_days, &plan.evaluated_at, &plan.cutoff, peer)?
                };
                self.finish_pruning(id, &retained)?;
                let stream = self.streams.get_mut(id).expect("known retained run");
                stream.run = retained.projection(true)?;
                let run = stream.run.clone();
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcProjection)) {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
                }
                self.write_projection(&run)?;
                if self.index.is_some() {
                    self.index_pending.insert(id.clone(), run);
                }
                retained.receipt()
            })();
            match collected {
                Ok(receipt) => result.pruned.push(receipt),
                Err(error) => result.failed.push(GcFailure {
                    run_id: id.clone(),
                    message: error.to_string().chars().take(512).collect(),
                }),
            }
        }
        Ok(result)
    }

    fn begin_pruning(
        &mut self,
        id: &str,
        retain_days: u32,
        now: &str,
        cutoff: &str,
        peer: &Peer,
    ) -> Result<Retained> {
        let root = self.root.join(id);
        if fs::symlink_metadata(root.join(ANCHOR)).is_ok() {
            return Err(LedgerError(
                "uncertain GC publication requires writer restart".into(),
            ));
        }
        if self.stream(id)?.replay.len() > MAX_REPLAYS {
            return Err(LedgerError(
                "GC replay inventory exceeds its bounded size; run retained".into(),
            ));
        }
        let verified = self.load_stream_with_sync(id, &File::sync_all)?.0;
        let live = self.stream(id)?;
        if !verified.poisoned.is_empty()
            || verified.manifest() != live.manifest()
            || serde_json::to_value(&verified.run)? != serde_json::to_value(&live.run)?
            || verified.replay != live.replay
            || !verified.run.holds.is_empty()
            || !verified.retention_time_valid
            || verified
                .last_activity_at
                .as_deref()
                .is_none_or(|t| t > cutoff)
        {
            return Err(LedgerError(
                "GC canonical verification differs from accepted writer state; nothing removed"
                    .into(),
            ));
        }
        let mut files = Vec::new();
        for segment in &verified.segments {
            let file = safe_file(&root.join(&segment.name))?;
            let m = file.metadata()?;
            if m.len() != segment.bytes {
                return Err(LedgerError("GC segment length changed".into()));
            }
            files.push(RemovedFile {
                path: segment.name.clone(),
                bytes: segment.bytes,
                digest: segment.digest.clone(),
                device: m.dev(),
                inode: m.ino(),
            });
        }
        files.extend(capture_pruning::inventory(&root, &verified.run)?);
        let retained = Retained {
            schema: "ouro.ledger.gc-anchor/1".into(),
            run: verified.run.clone(),
            manifest: verified.manifest(),
            replay: verified.replay.clone(),
            strict_source_loss: !verified.source_gaps.is_empty(),
            last_activity_at: verified
                .last_activity_at
                .clone()
                .expect("checked retention time"),
            collected_at: now.into(),
            cutoff: cutoff.into(),
            retain_days,
            operator: peer.clone(),
            files,
        };
        retained.validate(&root, id)?;
        retained.check_remaining(&root, false)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::GcIntentWrite)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        let value = serde_json::to_value(Envelope {
            digest: retained.digest()?,
            retained: retained.clone(),
        })?;
        if let Err(error) = publish(&root, ANCHOR, &value, MAX_ANCHOR) {
            self.streams
                .get_mut(id)
                .expect("known run")
                .poisoned
                .push("GC publication is uncertain; restart required".into());
            return Err(error);
        }
        let stream = self.streams.get_mut(id).expect("known run");
        stream.pruned = Some(retained.clone());
        stream.run = retained.projection(false)?;
        // Expired in-memory sessions must release descriptors as well as pins.
        self.readers.forget_run(id);
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::GcIntentSync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        Ok(retained)
    }

    fn finish_pruning(&self, id: &str, retained: &Retained) -> Result<()> {
        let root = self.root.join(id);
        let current =
            read(&root, id)?.ok_or_else(|| LedgerError("GC authority vanished".into()))?;
        if current.digest()? != retained.digest()? {
            return Err(LedgerError("GC authority changed".into()));
        }
        let complete = retained.complete(&root)?;
        retained.check_remaining(&root, complete)?;
        // A visible anchor after an interrupted rename is not a completed durability barrier.
        safe_file(&root.join(ANCHOR))?.sync_all()?;
        directory(&root)?.sync_all()?;
        if !complete {
            for entry in &retained.files {
                let (parent, name, exists) = check_member(&root, entry)?;
                if !exists {
                    continue;
                }
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcBeforeUnlink)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                // SAFETY: delete only this verified basename in its still-pinned parent directory.
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcAfterUnlink)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                parent.sync_all()?;
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcDirectorySync)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
            }
            // Sync both namespaces even if a preceding unlink survived a crash.
            directory(&root.join("artifacts"))?.sync_all()?;
            directory(&root)?.sync_all()?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::GcCompletion)) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
        }
        publish(&root, DONE, &retained.completion()?, 1024)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::GcCompletionSync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        Ok(())
    }

    pub(super) fn restore_pruned(&self, id: &str, retained: Retained) -> Result<Stream> {
        self.finish_pruning(id, &retained)?;
        let run = retained.projection(true)?;
        Ok(Stream {
            run,
            accepted_bytes: 0,
            replay: retained.replay.clone(),
            source_heads: BTreeMap::new(),
            source_gaps: if retained.strict_source_loss {
                vec![json!({"reason":"retained_source_loss"})]
            } else {
                vec![]
            },
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
            last_activity_at: Some(retained.last_activity_at.clone()),
            retention_time_valid: true,
            pruned: Some(retained),
        })
    }

    pub(super) fn verify_pruned(&self, id: &str) -> Result<VerifyReport> {
        let stream = self.stream(id)?;
        let retained = stream.pruned.as_ref().expect("retained run");
        let checked = (|| -> Result<()> {
            let root = self.root.join(id);
            let current =
                read(&root, id)?.ok_or_else(|| LedgerError("GC authority is missing".into()))?;
            if current.digest()? != retained.digest()? {
                return Err(LedgerError("GC authority changed".into()));
            }
            let complete = retained.complete(&root)?;
            retained.check_remaining(&root, complete)?;
            if !complete {
                return Err(LedgerError(
                    "GC deletion is incomplete; retry GC or restart the writer".into(),
                ));
            }
            if read_json(&root.join("run.json"), 4 * MAX_FRAME_BYTES)?
                != serde_json::to_value(&stream.run)?
            {
                return Err(LedgerError(
                    "pruned run projection differs from retained authority".into(),
                ));
            }
            Ok(())
        })();
        Ok(VerifyReport {
            run_id: id.into(),
            local_consistency: checked.is_ok(),
            child_protection: stream.run.child_protection.clone(),
            coverage: stream.run.coverage.clone(),
            events: 0,
            problems: checked
                .err()
                .map(|e| vec![e.to_string()])
                .unwrap_or_default(),
            history: stream.run.history.clone(),
        })
    }
}
