//! Whole-run pruning. A synchronized retention anchor authorizes only an exact
//! inventory; recovery never guesses which missing files or replay ids existed.
use serde::{Deserialize, Serialize};

use super::gc::{self, Authority, RemovedFile, check_member, read_json, safe_file};
use super::*;
use crate::faults::{self, Point};
use crate::protocol::{GcFailure, GcReceipt, GcResult, PrunedHistory};

const MAX_REPLAYS: usize = 65_536;

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

impl Retained {
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
}

impl Authority for Retained {
    const ANCHOR: &'static str = "gc.json";
    const DONE: &'static str = "gc-done.json";
    const MAX_ANCHOR: usize = 16 * 1024 * 1024;
    const COMPLETE_SCHEMA: &'static str = schemas::GC_COMPLETE;
    const ORPHANED: &'static str = "GC completion is missing its retained authority";
    const CORRUPT: &'static str = "GC anchor checksum or encoding mismatch";
    const VANISHED: &'static str = "GC authority vanished";
    const CHANGED: &'static str = "GC authority changed";
    const MISMATCH: &'static str = "GC completion does not match its anchor";

    fn files(&self) -> &[RemovedFile] {
        &self.files
    }

    fn validate(&self, root: &Path, id: &str) -> Result<()> {
        validate_frozen("run", &serde_json::to_value(&self.run)?)?;
        if self.schema != schemas::GC_ANCHOR
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
            || !ouro_records::retention::RETAIN_DAYS.contains(&self.retain_days)
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
            || self.files.len() > self.manifest.segments.len() + 3
        {
            return Err(LedgerError::refused("invalid retained GC authority"));
        }
        let last = self
            .manifest
            .segments
            .last()
            .ok_or_else(|| LedgerError::refused("GC anchor has no segments"))?;
        if self.run.chain.head_seq != last.last_seq
            || self.run.chain.head_digest.as_ref() != Some(&last.head_digest)
        {
            return Err(LedgerError::refused(
                "GC chain anchor differs from terminal projection",
            ));
        }
        for (i, file) in self.files.iter().enumerate() {
            if !crate::protocol::sha256_digest(&file.digest) || file.bytes > 1024 * 1024 * 1024 {
                return Err(LedgerError::refused("invalid GC file anchor"));
            }
            if let Some(segment) = self.manifest.segments.get(i) {
                if file.path != segment.name
                    || file.bytes != segment.bytes
                    || file.digest != segment.digest
                {
                    return Err(LedgerError::refused(
                        "GC segment inventory differs from chain anchors",
                    ));
                }
            } else if ![
                "artifacts/stdout.bin",
                "artifacts/stderr.bin",
                "artifacts/argv.bin",
            ]
            .contains(&file.path.as_str())
                || file.bytes > crate::protocol::MAX_CAPTURE_BYTES
            {
                return Err(LedgerError::refused("invalid GC capture inventory"));
            }
            if self.files[..i].iter().any(|prior| prior.path == file.path) {
                return Err(LedgerError::refused("duplicate GC file inventory"));
            }
        }
        for (key, replay) in &self.replay {
            if key.is_empty()
                || key.len() > 256
                || !crate::protocol::sha256_digest(&replay.digest)
                || !crate::protocol::sha256_digest(&replay.receipt.digest)
                || replay.receipt.seq == 0
                || replay.receipt.seq > self.run.chain.head_seq
            {
                return Err(LedgerError::refused("invalid retained replay identity"));
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
            return Err(LedgerError::refused(
                "GC anchor does not preserve preparation identity",
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
                return Err(LedgerError::refused("unlisted canonical segment during GC"));
            }
        }
        for entry in &self.files {
            if check_member(root, entry)?.2 && complete {
                return Err(LedgerError::refused(
                    "pruned file reappeared after GC completion",
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn read(root: &Path, id: &str) -> Result<Option<Retained>> {
    gc::read(root, id)
}

impl Store {
    #[cfg(test)]
    pub(crate) fn gc(
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
            .map_err(LedgerError::refused)?;
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
            .map_err(LedgerError::refused)?;
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
        self.gc_begins();
        let retain_days = policy.retain_days;
        // Full verification and fsync must not stall a live launch's strict channel.
        if self.streams().values().any(|s| {
            s.run().owner.is_some() && ["prepared", "admitted"].contains(&s.run().state.as_str())
        }) {
            return Err(LedgerError::refused(
                "GC requires a quiescent writer; finish or reconcile active launch owners first",
            ));
        }
        let plan = self.gc_plan_policy_at(policy, after, limit, now)?;
        let mut result = GcResult {
            schema: schemas::GC_RESULT.into(),
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
            if self.stream(id)?.pruned().is_none()
                && ((candidate.captures_candidate && !candidate.candidate)
                    || self
                        .stream(id)?
                        .run()
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
            if !candidate.candidate && self.stream(id)?.pruned().is_none() {
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
                let retained = if let Some(retained) = self.stream(id)?.pruned() {
                    (**retained).clone()
                } else {
                    self.begin_pruning(id, retain_days, &plan.evaluated_at, &plan.cutoff, peer)?
                };
                self.finish_pruning(id, &retained)?;
                let run = retained.projection(true)?;
                self.stream_mut(id).finish_pruning(run.clone());
                faults::hit(Point::GcProjection)?;
                self.write_projection(&run)?;
                self.queue_index(run);
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
        let root = self.run_dir(id);
        if fs::symlink_metadata(root.join(Retained::ANCHOR)).is_ok() {
            return Err(LedgerError::refused(
                "uncertain GC publication requires writer restart",
            ));
        }
        if self.stream(id)?.replay().len() > MAX_REPLAYS {
            return Err(LedgerError::refused(
                "GC replay inventory exceeds its bounded size; run retained",
            ));
        }
        let verified = self.verified_for_gc(
            id,
            cutoff,
            "GC canonical verification differs from accepted writer state; nothing removed",
        )?;
        let mut files = Vec::new();
        for segment in verified.segments() {
            let file = safe_file(&root.join(&segment.name))?;
            let m = file.metadata()?;
            if m.len() != segment.bytes {
                return Err(LedgerError::refused("GC segment length changed"));
            }
            files.push(RemovedFile {
                path: segment.name.clone(),
                bytes: segment.bytes,
                digest: segment.digest.clone(),
                device: m.dev(),
                inode: m.ino(),
            });
        }
        files.extend(capture_pruning::inventory(&root, verified.run())?);
        let retained = Retained {
            schema: schemas::GC_ANCHOR.into(),
            run: verified.run().clone(),
            manifest: verified.manifest(),
            replay: verified.replay().clone(),
            strict_source_loss: !verified.source_gaps().is_empty(),
            last_activity_at: verified
                .last_activity_at()
                .expect("checked retention time")
                .into(),
            collected_at: now.into(),
            cutoff: cutoff.into(),
            retain_days,
            operator: peer.clone(),
            files,
        };
        retained.validate(&root, id)?;
        retained.check_remaining(&root, false)?;
        faults::hit(Point::GcIntentWrite)?;
        if let Err(error) = gc::publish_anchor(&root, &retained) {
            self.poison(
                id,
                PoisonKind::Incomplete,
                "GC publication is uncertain; restart required",
            );
            return Err(error);
        }
        let run = retained.projection(false)?;
        self.stream_mut(id).begin_pruning(retained.clone(), run);
        // Expired in-memory sessions must release descriptors as well as pins.
        self.readers_mut().forget_run(id);
        faults::hit(Point::GcIntentSync)?;
        Ok(retained)
    }

    fn finish_pruning(&self, id: &str, retained: &Retained) -> Result<()> {
        gc::finish(&self.run_dir(id), id, retained)
    }

    pub(super) fn restore_pruned(&self, id: &str, retained: Retained) -> Result<Stream> {
        self.finish_pruning(id, &retained)?;
        Ok(Stream::restored(
            retained.projection(true)?,
            retained.replay.clone(),
            retained.strict_source_loss,
            retained.last_activity_at.clone(),
            retained,
        ))
    }
}

/// A pruned run re-checked against the retained authority and projection
/// the writer held when it planned this verification.
pub(super) fn verify_pruned(
    root: &Path,
    id: &str,
    retained: &Retained,
    run: &RunRecord,
) -> VerifyReport {
    let checked = (|| -> Result<()> {
        let current =
            read(root, id)?.ok_or_else(|| LedgerError::refused("GC authority is missing"))?;
        if current.digest()? != retained.digest()? {
            return Err(LedgerError::refused("GC authority changed"));
        }
        let complete = retained.complete(root)?;
        retained.check_remaining(root, complete)?;
        if !complete {
            return Err(LedgerError::refused(
                "GC deletion is incomplete; retry GC or restart the writer",
            ));
        }
        if read_json(&root.join("run.json"), crate::projection::MAX_RUN_BYTES)?
            != serde_json::to_value(run)?
        {
            return Err(LedgerError::refused(
                "pruned run projection differs from retained authority",
            ));
        }
        Ok(())
    })();
    VerifyReport {
        run_id: id.into(),
        local_consistency: checked.is_ok(),
        child_protection: run.child_protection.clone(),
        coverage: crate::reader::coverage_summary(&run.coverage),
        events: 0,
        problems: checked
            .err()
            .map(|e| vec![e.to_string()])
            .unwrap_or_default(),
        history: run.history.clone(),
    }
}
