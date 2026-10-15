//! Capture-only expiry retains canonical events. An exact durable inventory
//! authorizes deletion, and the terminal chain anchors it to canonical history.
use std::{os::unix::fs::MetadataExt as _, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    Store,
    gc::{self, Authority, RemovedFile, check_member, directory, file_hash, member},
    stream::{PoisonKind, Stream},
};
use crate::{
    faults::{self, Point},
    protocol::{
        CaptureGcReceipt, Chain, HistoryState, LedgerError, Peer, PrunedHistory, Result, RunRecord,
        RunState,
    },
    schemas,
};

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
impl Retained {
    fn history(&self, complete: bool) -> Result<PrunedHistory> {
        Ok(PrunedHistory {
            state: if complete {
                HistoryState::Pruned
            } else {
                HistoryState::Pruning
            },
            anchor_digest: self.digest()?,
            collected_at: self.collected_at.clone(),
        })
    }
    fn capture(&self, complete: bool) -> Value {
        let mut value = self.capture.clone();
        for f in &self.files {
            let name = f
                .path
                .strip_prefix("artifacts/")
                .and_then(|p| p.strip_suffix(".bin"))
                .expect("validated capture path");
            value[name]["state"] = json!(if complete { "pruned" } else { "pruning" });
            if complete {
                value[name]["stored_bytes"] = json!(0);
                value[name]["pruned_bytes"] = json!(f.bytes);
            }
        }
        value
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

impl Authority for Retained {
    const ANCHOR: &'static str = "captures-gc.json";
    const DONE: &'static str = "captures-gc-done.json";
    const MAX_ANCHOR: usize = 65_536;
    const COMPLETE_SCHEMA: &'static str = schemas::CAPTURE_GC_COMPLETE;
    const ORPHANED: &'static str = "capture GC completion has no authority";
    const CORRUPT: &'static str = "invalid capture GC authority";
    const VANISHED: &'static str = "capture GC authority vanished";
    const CHANGED: &'static str = "capture GC authority changed";
    const MISMATCH: &'static str = "capture GC completion differs from its authority";

    fn files(&self) -> &[RemovedFile] {
        &self.files
    }

    fn validate(&self, _root: &Path, id: &str) -> Result<()> {
        let r = self;
        if r.schema != schemas::CAPTURE_GC_ANCHOR
            || r.run_id != id
            || r.chain.head_seq == 0
            || !r
                .chain
                .head_digest
                .as_deref()
                .is_some_and(crate::protocol::sha256_digest)
            || !ukai_records::retention::RETAIN_DAYS.contains(&r.retain_days)
            || r.files.is_empty()
            || r.files.len() > 3
            || ![&r.last_activity_at, &r.cutoff, &r.collected_at]
                .into_iter()
                .all(|s| crate::reader::utc_second(s))
            || r.last_activity_at > r.cutoff
            || r.cutoff >= r.collected_at
        {
            return Err(LedgerError::refused("invalid capture GC authority"));
        }
        for (i, f) in r.files.iter().enumerate() {
            let name = match f.path.as_str() {
                "artifacts/stdout.bin" => "stdout",
                "artifacts/stderr.bin" => "stderr",
                "artifacts/argv.bin" => "argv",
                _ => return Err(LedgerError::refused("unsafe capture GC inventory")),
            };
            if f.bytes > crate::protocol::MAX_CAPTURE_BYTES
                || !crate::protocol::sha256_digest(&f.digest)
                || r.files[..i].iter().any(|other| other.path == f.path)
                || r.capture[name]["stored_bytes"].as_u64() != Some(f.bytes)
                || !matches!(
                    r.capture[name]["state"].as_str(),
                    Some("captured" | "incomplete")
                )
            {
                return Err(LedgerError::refused(
                    "capture GC inventory differs from recorded capture",
                ));
            }
        }
        for name in crate::protocol::CAPTURE_STREAMS {
            if matches!(
                r.capture[name]["state"].as_str(),
                Some("captured" | "incomplete")
            ) && !r
                .files
                .iter()
                .any(|f| f.path == format!("artifacts/{name}.bin"))
            {
                return Err(LedgerError::refused(
                    "capture GC inventory omits a recorded stream",
                ));
            }
        }
        Ok(())
    }

    fn check_remaining(&self, root: &Path, complete: bool) -> Result<()> {
        for file in &self.files {
            if check_member(root, file)?.2 && complete {
                return Err(LedgerError::refused(
                    "pruned capture reappeared after completion",
                ));
            }
        }
        Ok(())
    }
}

fn read(root: &Path, id: &str) -> Result<Option<Retained>> {
    gc::read(root, id)
}

/// A read-only projection overlay. `verify` must never resume deletion.
pub(super) fn apply(root: &Path, stream: &mut Stream) -> Result<()> {
    let Some(retained) = read(root, &stream.run().run_id)? else {
        return Ok(());
    };
    if retained.attempt_id != stream.run().attempt_id
        || retained.capture != stream.run().capture
        || !stream.anchor(retained.chain.head_seq).is_some_and(|a| {
            Some(&a.digest) == retained.chain.head_digest.as_ref()
                && matches!(a.state, RunState::Settled | RunState::Denied)
        })
    {
        return Err(LedgerError::refused(
            "capture GC authority does not match canonical terminal history",
        ));
    }
    let complete = retained.complete(root)?;
    retained.check_remaining(root, complete)?;
    stream.set_captures(retained.capture(complete), retained.history(complete)?);
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
            r.check_remaining(root, true)
        }
        _ => Err(LedgerError::refused(
            "capture GC authority differs from retained history",
        )),
    }
}

impl Store {
    pub(super) fn recover_captures(&self, id: &str, stream: &mut Stream) -> Result<()> {
        if let Some(r) = read(&self.run_dir(id), id)? {
            self.finish_capture_pruning(id, &r)?;
            stream.set_captures(r.capture(true), r.history(true)?);
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
        let root = self.run_dir(id);
        let retained = match read(&root, id)? {
            Some(r) => {
                if self
                    .stream(id)?
                    .run()
                    .capture_history
                    .as_ref()
                    .is_none_or(|h| h.anchor_digest != r.digest().unwrap_or_default())
                {
                    return Err(LedgerError::refused(
                        "uncertain capture GC publication requires writer restart",
                    ));
                }
                r
            }
            None => {
                const DIFFERS: &str =
                    "capture GC canonical verification differs from accepted writer state";
                let verified = self.verified_for_gc(id, cutoff, DIFFERS)?;
                if verified.run().capture_history.is_some() {
                    return Err(LedgerError::refused(DIFFERS));
                }
                let files = inventory(&root, verified.run())?;
                if files.is_empty() {
                    return Err(LedgerError::refused("no captures available for expiry"));
                }
                let r = Retained {
                    schema: schemas::CAPTURE_GC_ANCHOR.into(),
                    run_id: id.into(),
                    attempt_id: verified.run().attempt_id.clone(),
                    chain: verified.run().chain.clone(),
                    capture: verified.run().capture.clone(),
                    last_activity_at: verified.last_activity_at().expect("checked time").into(),
                    collected_at: now.into(),
                    cutoff: cutoff.into(),
                    retain_days: days,
                    operator: peer.clone(),
                    files,
                };
                // Every later read holds a published authority to `validate`,
                // and nothing removes one, so an authority it would refuse is
                // refused here, before it becomes durable.
                r.validate(&root, id)?;
                r.check_remaining(&root, false)?;
                faults::hit(Point::GcIntentWrite)?;
                if let Err(e) = gc::publish_anchor(&root, &r) {
                    self.poison(
                        id,
                        PoisonKind::Incomplete,
                        "uncertain capture GC publication; restart required",
                    );
                    return Err(e);
                }
                let stream = self.stream_mut(id);
                stream.set_captures(r.capture(false), r.history(false)?);
                faults::hit(Point::GcIntentSync)?;
                r
            }
        };
        self.finish_capture_pruning(id, &retained)?;
        self.stream_mut(id)
            .set_captures(retained.capture(true), retained.history(true)?);
        faults::hit(Point::GcProjection)?;
        self.write_projection(self.stream(id)?.run())?;
        self.queue_index(id);
        retained.receipt()
    }

    fn finish_capture_pruning(&self, id: &str, r: &Retained) -> Result<()> {
        gc::finish(&self.run_dir(id), id, r)
    }
}

/// Exact inventory of selected captures; also used by whole-run pruning.
pub(super) fn inventory(root: &Path, run: &RunRecord) -> Result<Vec<RemovedFile>> {
    directory(&root.join("artifacts"))?;
    let mut files = Vec::new();
    for name in crate::protocol::CAPTURE_STREAMS {
        let path = format!("artifacts/{name}.bin");
        let (_, _, file) = member(root, &path)?;
        let expected = run.capture[name]["stored_bytes"].as_u64().unwrap_or(0);
        if let Some(mut file) = file {
            let m = file.metadata()?;
            if !run.payload["capture"]["streams"]
                .as_array()
                .is_some_and(|s| s.contains(&json!(name)))
                || m.len() > crate::protocol::MAX_CAPTURE_BYTES
                || m.len() != expected
                || run.capture[name]["stored_bytes"].as_u64().is_none()
                || !matches!(
                    run.capture[name]["state"].as_str(),
                    Some("captured" | "incomplete")
                )
            {
                return Err(LedgerError::refused(
                    "GC capture does not match recorded selection and size",
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
            return Err(LedgerError::refused("GC recorded capture is missing"));
        }
    }
    Ok(files)
}
