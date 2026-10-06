//! Durable operator holds and a bounded, non-destructive retention preview.
use std::{
    ops::Bound,
    time::{Duration, UNIX_EPOCH},
};

use super::*;
use crate::protocol::{GcCandidate, GcPlan};
use ouro_records::retention::RetentionPolicy;

impl Store {
    pub fn hold(&mut self, run_id: &str, request_id: &str, peer: &Peer) -> Result<AppendReceipt> {
        self.retention_intent(run_id, request_id, "hold", peer)
    }

    pub fn release(
        &mut self,
        run_id: &str,
        request_id: &str,
        peer: &Peer,
    ) -> Result<AppendReceipt> {
        self.retention_intent(run_id, request_id, "release", peer)
    }

    fn retention_intent(
        &mut self,
        run_id: &str,
        request_id: &str,
        kind: &str,
        peer: &Peer,
    ) -> Result<AppendReceipt> {
        if !valid_id(request_id) {
            return Err(LedgerError(
                "retention intent needs a bounded request id".into(),
            ));
        }
        self.append(
            run_id,
            json!({"kind":kind,"request_id":request_id,"body":{}}),
            "operator",
            peer,
            None,
        )
    }

    pub fn gc_plan(&self, retain_days: u32, after: Option<&str>, limit: u32) -> Result<GcPlan> {
        self.gc_plan_policy(Some(retain_days), None, after, limit)
    }

    pub fn gc_plan_policy(
        &self,
        history: Option<u32>,
        captures: Option<u32>,
        after: Option<&str>,
        limit: u32,
    ) -> Result<GcPlan> {
        let policy = self
            .retention
            .resolve(history, captures)
            .map_err(|e| LedgerError(e.into()))?;
        self.gc_plan_policy_at(policy, after, limit, SystemTime::now())
    }

    #[cfg(test)]
    pub(super) fn gc_plan_at(
        &self,
        retain_days: u32,
        after: Option<&str>,
        limit: u32,
        now: SystemTime,
    ) -> Result<GcPlan> {
        let policy = self
            .retention
            .resolve(Some(retain_days), None)
            .map_err(|e| LedgerError(e.into()))?;
        self.gc_plan_policy_at(policy, after, limit, now)
    }

    pub(super) fn gc_plan_policy_at(
        &self,
        policy: RetentionPolicy,
        after: Option<&str>,
        limit: u32,
        now: SystemTime,
    ) -> Result<GcPlan> {
        let RetentionPolicy {
            retain_days,
            capture_retain_days,
        } = policy;
        if capture_retain_days > retain_days
            || !(1..=36_500).contains(&capture_retain_days)
            || !(1..=36_500).contains(&retain_days)
            || !(1..=100).contains(&limit)
        {
            return Err(LedgerError(
                "GC preview requires 1..36500 retention days and 1..100 runs per page".into(),
            ));
        }
        if let Some(id) = after {
            check_run_id(id)?;
        }
        let epoch = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LedgerError("retention clock predates Unix epoch".into()))?
            .as_secs();
        let cutoff = now
            .checked_sub(Duration::from_secs(u64::from(retain_days) * 86_400))
            .ok_or_else(|| LedgerError("retention cutoff is outside the clock range".into()))?;
        let cutoff = records::rfc3339_utc(cutoff);
        let capture_cutoff = records::rfc3339_utc(
            now.checked_sub(Duration::from_secs(u64::from(capture_retain_days) * 86_400))
                .ok_or_else(|| LedgerError("capture cutoff outside clock range".into()))?,
        );
        let evaluated_at = records::rfc3339_utc(now);
        if !crate::reader::utc_second(&cutoff)
            || !crate::reader::utc_second(&capture_cutoff)
            || !crate::reader::utc_second(&evaluated_at)
        {
            return Err(LedgerError(
                "retention clock is outside the supported UTC range".into(),
            ));
        }
        let pins = self.readers.retention_pins(&self.root, epoch);
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut streams = self.streams.range::<str, _>((lower, Bound::Unbounded));
        let mut runs = Vec::new();
        for (id, stream) in streams.by_ref().take(limit as usize) {
            let mut reasons = Vec::new();
            if stream.pruned.is_some() {
                reasons.push("history_pruned");
            }
            if !stream.poisoned.is_empty() {
                reasons.push("poisoned_stream");
            }
            if stream.run.state == "outcome_unknown" {
                reasons.push("outcome_unknown");
            } else if !["settled", "denied"].contains(&stream.run.state.as_str()) {
                reasons.push("active_run");
            } else if stream.run.settlement != "recorded" {
                reasons.push("settlement_pending");
            } else if stream.run.outcome.as_ref().is_none_or(|outcome| {
                !matches!(
                    outcome["kind"].as_str(),
                    Some("exited" | "signaled" | "exec_error" | "refused")
                ) || outcome["unknown"] == true
            }) {
                reasons.push("outcome_unknown");
            }
            if !stream.run.holds.is_empty() {
                reasons.push("operator_hold");
            }
            match stream
                .last_activity_at
                .as_deref()
                .filter(|_| stream.retention_time_valid)
            {
                None => reasons.push("activity_time_unknown"),
                Some(time) if time > evaluated_at.as_str() => reasons.push("clock_before_activity"),
                Some(time) if time > cutoff.as_str() => reasons.push("retention_window"),
                Some(_) => {}
            }
            match &pins {
                Err(_) => reasons.push("reader_checkpoint_unknown"),
                Ok(pins) if pins.contains(id) => reasons.push("reader_snapshot"),
                Ok(_) => {}
            }
            // This is a metadata/layout check, not a rescan of unbounded history.
            // A candidate still requires canonical verification before deletion.
            if stream.pruned.is_none() && !self.retention_layout_matches(id, stream) {
                reasons.push("canonical_layout_changed");
            }
            let mut capture_reasons: Vec<_> = reasons
                .iter()
                .copied()
                .filter(|r| *r != "retention_window")
                .collect();
            if stream
                .last_activity_at
                .as_deref()
                .is_some_and(|t| t > capture_cutoff.as_str())
            {
                capture_reasons.push("retention_window");
            }
            if stream.run.capture_history.is_some() {
                capture_reasons.push("captures_pruned");
            } else if !["stdout", "stderr"].iter().any(|name| {
                matches!(
                    stream.run.capture[name]["state"].as_str(),
                    Some("captured" | "incomplete")
                )
            }) {
                capture_reasons.push("no_captures");
            }
            runs.push(GcCandidate {
                run_id: id.clone(),
                state: stream.run.state.clone(),
                child_protection: stream.run.child_protection.clone(),
                chain: stream.run.chain.clone(),
                last_activity_at: stream.last_activity_at.clone(),
                candidate: reasons.is_empty(),
                captures_candidate: capture_reasons.is_empty(),
                captures_keep_reasons: capture_reasons.into_iter().map(str::to_owned).collect(),
                keep_reasons: reasons.into_iter().map(str::to_owned).collect(),
            });
        }
        let next_after = if streams.next().is_some() {
            runs.last().map(|run| run.run_id.clone())
        } else {
            None
        };
        Ok(GcPlan {
            schema: "ouro.ledger.gc-plan/1".into(),
            dry_run: true,
            deletion_supported: true,
            verification_required: true,
            retain_days,
            capture_retain_days,
            capture_cutoff,
            evaluated_at,
            cutoff,
            runs,
            next_after,
        })
    }

    fn retention_layout_matches(&self, run_id: &str, stream: &Stream) -> bool {
        let directory = self.root.join(run_id);
        manifest::read(&directory, run_id)
            .is_ok_and(|manifest| manifest.as_ref() == Some(&stream.manifest()))
            && crate::segments::Snapshot::open(&directory.join(STREAM), stream.accepted_bytes)
                .is_ok_and(|snapshot| {
                    snapshot.physical_bytes() == stream.accepted_bytes
                        && snapshot.validate().is_ok()
                })
    }
}
