//! Capture-only expiry retains canonical events. An exact durable inventory
//! authorizes deletion, and the terminal chain anchors it to canonical history.
use super::pruning::{
    RemovedFile, check_member, directory, file_hash, member, publish, read_json, safe_file,
};
use super::*;
use crate::protocol::{CaptureGcReceipt, PrunedHistory};
use serde::{Deserialize, Serialize};

const ANCHOR: &str = "captures-gc.json";
const DONE: &str = "captures-gc-done.json";
const MAX_ANCHOR: usize = 65_536;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    schema: String,
    run_id: String,
    attempt_id: String,
    chain: Chain,
    capture: Value,
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
    fn capture(&self, complete: bool) -> Value {
        let mut value = self.capture.clone();
        for f in &self.files {
            let name = if f.path == "artifacts/stdout.bin" {
                "stdout"
            } else {
                "stderr"
            };
            value[name]["state"] = json!(if complete { "pruned" } else { "pruning" });
            if complete {
                value[name]["stored_bytes"] = json!(0);
                value[name]["pruned_bytes"] = json!(f.bytes);
            }
        }
        value
    }
    fn completion(&self) -> Result<Value> {
        Ok(json!({"schema":"ouro.ledger.capture-gc-complete/1","anchor_digest":self.digest()?}))
    }
    fn complete(&self, root: &Path) -> Result<bool> {
        match fs::symlink_metadata(root.join(DONE)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
            Ok(_) => {
                if read_json(&root.join(DONE), 1024)? == self.completion()? {
                    Ok(true)
                } else {
                    Err(LedgerError(
                        "capture GC completion differs from its authority".into(),
                    ))
                }
            }
        }
    }
    fn check_files(&self, root: &Path, complete: bool) -> Result<()> {
        for file in &self.files {
            if check_member(root, file)?.2 && complete {
                return Err(LedgerError(
                    "pruned capture reappeared after completion".into(),
                ));
            }
        }
        Ok(())
    }
    fn receipt(&self) -> Result<CaptureGcReceipt> {
        Ok(CaptureGcReceipt {
            run_id: self.run_id.clone(),
            chain: self.chain.clone(),
            capture_history: self.history(true)?,
            removed_files: self.files.len() as u32,
            removed_bytes: self.files.iter().map(|f| f.bytes).sum(),
        })
    }
}

fn read(root: &Path, id: &str) -> Result<Option<Retained>> {
    directory(root)?;
    match fs::symlink_metadata(root.join(ANCHOR)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(root.join(DONE)).is_ok() {
                return Err(LedgerError("capture GC completion has no authority".into()));
            }
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let value = read_json(&root.join(ANCHOR), MAX_ANCHOR)?;
    let envelope: Envelope = serde_json::from_value(value.clone())?;
    let r = &envelope.retained;
    if envelope.digest != r.digest()?
        || serde_json::to_value(&envelope)? != value
        || r.schema != "ouro.ledger.capture-gc-anchor/1"
        || r.run_id != id
        || r.chain.head_seq == 0
        || !r
            .chain
            .head_digest
            .as_deref()
            .is_some_and(pruning::digest_valid)
        || !(1..=36_500).contains(&r.retain_days)
        || r.files.is_empty()
        || r.files.len() > 2
        || ![&r.last_activity_at, &r.cutoff, &r.collected_at]
            .into_iter()
            .all(|s| crate::reader::utc_second(s))
        || r.last_activity_at > r.cutoff
        || r.cutoff >= r.collected_at
    {
        return Err(LedgerError("invalid capture GC authority".into()));
    }
    for (i, f) in r.files.iter().enumerate() {
        let name = match f.path.as_str() {
            "artifacts/stdout.bin" => "stdout",
            "artifacts/stderr.bin" => "stderr",
            _ => return Err(LedgerError("unsafe capture GC inventory".into())),
        };
        if f.bytes > 16 * 1024 * 1024
            || !pruning::digest_valid(&f.digest)
            || r.files[..i].iter().any(|other| other.path == f.path)
            || r.capture[name]["stored_bytes"].as_u64() != Some(f.bytes)
            || !matches!(
                r.capture[name]["state"].as_str(),
                Some("captured" | "incomplete")
            )
        {
            return Err(LedgerError(
                "capture GC inventory differs from recorded capture".into(),
            ));
        }
    }
    for name in ["stdout", "stderr"] {
        if matches!(
            r.capture[name]["state"].as_str(),
            Some("captured" | "incomplete")
        ) && !r
            .files
            .iter()
            .any(|f| f.path == format!("artifacts/{name}.bin"))
        {
            return Err(LedgerError(
                "capture GC inventory omits a recorded stream".into(),
            ));
        }
    }
    Ok(Some(envelope.retained))
}

/// A read-only projection overlay. `verify` must never resume deletion.
pub(super) fn apply(root: &Path, stream: &mut Stream) -> Result<()> {
    let Some(retained) = read(root, &stream.run.run_id)? else {
        return Ok(());
    };
    if retained.attempt_id != stream.run.attempt_id
        || retained.capture != stream.run.capture
        || !stream
            .anchors
            .get(&retained.chain.head_seq)
            .is_some_and(|a| {
                Some(&a.digest) == retained.chain.head_digest.as_ref()
                    && ["settled", "denied"].contains(&a.state)
            })
    {
        return Err(LedgerError(
            "capture GC authority does not match canonical terminal history".into(),
        ));
    }
    let complete = retained.complete(root)?;
    retained.check_files(root, complete)?;
    stream.run.capture = retained.capture(complete);
    stream.run.capture_history = Some(retained.history(complete)?);
    Ok(())
}

pub(super) fn check_pruned_history(root: &Path, run: &RunRecord) -> Result<()> {
    let retained = read(root, &run.run_id)?;
    match (retained, &run.capture_history) {
        (None, None) => Ok(()),
        (Some(r), Some(h))
            if r.attempt_id == run.attempt_id
                && *h == r.history(true)?
                && run.capture == r.capture(true)
                && r.complete(root)? =>
        {
            r.check_files(root, true)
        }
        _ => Err(LedgerError(
            "capture GC authority differs from retained history".into(),
        )),
    }
}

impl Store {
    pub(super) fn recover_captures(&self, id: &str, stream: &mut Stream) -> Result<()> {
        if let Some(r) = read(&self.root.join(id), id)? {
            self.finish_capture_pruning(id, &r)?;
            stream.run.capture = r.capture(true);
            stream.run.capture_history = Some(r.history(true)?);
        }
        Ok(())
    }

    pub(super) fn prune_captures(
        &mut self,
        id: &str,
        days: u32,
        now: &str,
        cutoff: &str,
        peer: &Peer,
    ) -> Result<CaptureGcReceipt> {
        let root = self.root.join(id);
        let retained = match read(&root, id)? {
            Some(r) => {
                if self
                    .stream(id)?
                    .run
                    .capture_history
                    .as_ref()
                    .is_none_or(|h| h.anchor_digest != r.digest().unwrap_or_default())
                {
                    return Err(LedgerError(
                        "uncertain capture GC publication requires writer restart".into(),
                    ));
                }
                r
            }
            None => {
                let verified = self.load_stream_with_sync(id, &File::sync_all)?.0;
                let live = self.stream(id)?;
                if !verified.poisoned.is_empty()
                    || verified.manifest() != live.manifest()
                    || serde_json::to_value(&verified.run)? != serde_json::to_value(&live.run)?
                    || verified.replay != live.replay
                    || !verified.run.holds.is_empty()
                    || verified.run.capture_history.is_some()
                    || !verified.retention_time_valid
                    || verified
                        .last_activity_at
                        .as_deref()
                        .is_none_or(|t| t > cutoff)
                {
                    return Err(LedgerError(
                        "capture GC canonical verification differs from accepted writer state"
                            .into(),
                    ));
                }
                let files = inventory(&root, &verified.run)?;
                if files.is_empty() {
                    return Err(LedgerError("no captures available for expiry".into()));
                }
                let r = Retained {
                    schema: "ouro.ledger.capture-gc-anchor/1".into(),
                    run_id: id.into(),
                    attempt_id: verified.run.attempt_id.clone(),
                    chain: verified.run.chain.clone(),
                    capture: verified.run.capture.clone(),
                    last_activity_at: verified.last_activity_at.clone().expect("checked time"),
                    collected_at: now.into(),
                    cutoff: cutoff.into(),
                    retain_days: days,
                    operator: peer.clone(),
                    files,
                };
                r.check_files(&root, false)?;
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcIntentWrite)) {
                    return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
                }
                let value = serde_json::to_value(Envelope {
                    digest: r.digest()?,
                    retained: r.clone(),
                })?;
                if let Err(e) = publish(&root, ANCHOR, &value, MAX_ANCHOR) {
                    self.streams
                        .get_mut(id)
                        .expect("known run")
                        .poisoned
                        .push("uncertain capture GC publication; restart required".into());
                    return Err(e);
                }
                let stream = self.streams.get_mut(id).expect("known run");
                stream.run.capture = r.capture(false);
                stream.run.capture_history = Some(r.history(false)?);
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcIntentSync)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                r
            }
        };
        self.finish_capture_pruning(id, &retained)?;
        let stream = self.streams.get_mut(id).expect("known run");
        stream.run.capture = retained.capture(true);
        stream.run.capture_history = Some(retained.history(true)?);
        let run = stream.run.clone();
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::GcProjection)) {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into());
        }
        self.write_projection(&run)?;
        if self.index.is_some() {
            self.index_pending.insert(id.into(), run);
        }
        retained.receipt()
    }

    fn finish_capture_pruning(&self, id: &str, r: &Retained) -> Result<()> {
        let root = self.root.join(id);
        let current =
            read(&root, id)?.ok_or_else(|| LedgerError("capture GC authority vanished".into()))?;
        if current.digest()? != r.digest()? {
            return Err(LedgerError("capture GC authority changed".into()));
        }
        let complete = r.complete(&root)?;
        r.check_files(&root, complete)?;
        safe_file(&root.join(ANCHOR))?.sync_all()?;
        directory(&root)?.sync_all()?;
        if !complete {
            for entry in &r.files {
                let (parent, name, exists) = check_member(&root, entry)?;
                if !exists {
                    continue;
                }
                #[cfg(test)]
                if matches!(self.fault, Some(Fault::GcBeforeUnlink)) {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
                }
                // SAFETY: only the verified basename in the pinned parent is removed.
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
            directory(&root.join("artifacts"))?.sync_all()?;
            directory(&root)?.sync_all()?;
            #[cfg(test)]
            if matches!(self.fault, Some(Fault::GcCompletion)) {
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
        }
        publish(&root, DONE, &r.completion()?, 1024)?;
        #[cfg(test)]
        if matches!(self.fault, Some(Fault::GcCompletionSync)) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        Ok(())
    }
}

/// Exact inventory of selected captures; also used by whole-run pruning.
pub(super) fn inventory(root: &Path, run: &RunRecord) -> Result<Vec<RemovedFile>> {
    directory(&root.join("artifacts"))?;
    let mut files = Vec::new();
    for name in ["stdout", "stderr"] {
        let path = format!("artifacts/{name}.bin");
        let (_, _, file) = member(root, &path)?;
        let expected = run.capture[name]["stored_bytes"].as_u64().unwrap_or(0);
        if let Some(mut file) = file {
            let m = file.metadata()?;
            if !run.payload["capture"]["streams"]
                .as_array()
                .is_some_and(|s| s.contains(&json!(name)))
                || m.len() > 16 * 1024 * 1024
                || m.len() != expected
                || run.capture[name]["stored_bytes"].as_u64().is_none()
                || !matches!(
                    run.capture[name]["state"].as_str(),
                    Some("captured" | "incomplete")
                )
            {
                return Err(LedgerError(
                    "GC capture does not match recorded selection and size".into(),
                ));
            }
            files.push(RemovedFile {
                path,
                bytes: m.len(),
                digest: file_hash(&mut file, m.len())?,
                device: m.dev(),
                inode: m.ino(),
            });
        } else if expected != 0
            || matches!(
                run.capture[name]["state"].as_str(),
                Some("captured" | "incomplete")
            )
        {
            return Err(LedgerError("GC recorded capture is missing".into()));
        }
    }
    Ok(files)
}
