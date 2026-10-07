use super::*;
use crate::pending::{Completion, Journal};

impl Store {
    pub(super) fn pending_exists(&self, id: &str) -> bool {
        fs::symlink_metadata(self.root.join(id).join("owner-pending.json")).is_ok()
    }

    /// Reconcile evidence only. Neither this path nor orphan recovery can launch.
    pub fn reconcile_pending(
        &mut self,
        id: &str,
        peer: &Peer,
        alive: &impl Fn(&Peer) -> bool,
    ) -> Result<RunRecord> {
        if !self.stream(id)?.poisoned.is_empty() {
            return Err(LedgerError(
                "ambiguous canonical history refuses pending recovery".into(),
            ));
        }
        let run = self.show(id)?;
        if run.payload["evidence"] != "best-effort" {
            return Err(LedgerError(
                "strict runs cannot recover pending owner evidence".into(),
            ));
        }
        let owner = run
            .owner
            .as_ref()
            .ok_or_else(|| LedgerError("pending recovery requires a durable owner".into()))?;
        if peer != owner && alive(owner) {
            return Err(LedgerError(
                "only the live owner may reconcile its journal".into(),
            ));
        }
        if !self.pending_exists(id) {
            if ["settled", "denied", "outcome_unknown"].contains(&run.state.as_str()) {
                return Ok(run);
            }
            return Err(LedgerError(
                "nonterminal recovery requires its pending journal".into(),
            ));
        }
        let journal = Journal::open(&self.root.join(id))?;
        let mut state = journal.read(&run)?;
        if ["settled", "denied", "outcome_unknown"].contains(&run.state.as_str()) {
            journal.remove()?;
            return Ok(run);
        }
        if run.state != "admitted" {
            return Err(LedgerError(
                "pending evidence cannot supply admission".into(),
            ));
        }
        if let Some(completion) = &state.completion {
            validate_completion(&run, completion)?;
        }
        let events = state.pending();
        for event in &events {
            crate::redaction::validate_stored(event, &run.payload, &run.attempt_id)?;
        }
        if state.active || state.completion.is_some() {
            state.outage()?;
            let record = json!({"kind":"evidence_gap","request_id":format!("outage:{}",state.episode),"body":{"reason":"writer_outage","episode":state.episode,"owner":owner}});
            self.append(id, record, "recovery", peer, None)?;
        }
        for event in events {
            self.append_source_as(id, &event, peer, None, "recovery")?;
        }
        if let Some(completion) = &state.completion {
            let record = json!({"kind":completion.kind,"request_id":"settlement","effect_id":null,"body":completion.body});
            validate_intent(self.stream(id)?, &record)?;
            self.append(id, record, "recovery", peer, None)?;
            journal.remove()?;
        } else if !alive(owner) {
            self.append(id, json!({"kind":"outcome_unknown","request_id":"reconcile:pending-owner-dead","body":{"outcome":{"kind":"unknown","unknown":true,"unknown_reason":"pending owner has no durable local exit record"},"coverage":{"status":"degraded","gaps":[{"reason":"local_exit_missing"}]}}}), "recovery", peer, None)?;
            journal.remove()?;
        } else {
            state.clear();
            journal.save(&state)?;
        }
        self.show(id)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recover_pending_orphans(&mut self, peer: &Peer) {
        let ids: Vec<_> = self
            .streams
            .iter()
            .filter(|(id, s)| {
                s.run.payload["evidence"] == "best-effort"
                    && s.poisoned.is_empty()
                    && (self.pending_exists(id)
                        || ["prepared", "admitted"].contains(&s.run.state.as_str()))
                    && s.run
                        .owner
                        .as_ref()
                        .is_some_and(|owner| !crate::daemon::peer_alive(owner))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            if let Err(problem) = self.reconcile_pending(&id, peer, &crate::daemon::peer_alive) {
                // Retain the failed journal for inspection. A bad local file is
                // never sufficient evidence for a successful terminal outcome.
                if self
                    .stream(&id)
                    .is_ok_and(|s| ["prepared", "admitted"].contains(&s.run.state.as_str()))
                {
                    let _ = self.append(&id, json!({"kind":"outcome_unknown","request_id":"reconcile:pending-invalid","body":{"reason":"invalid_pending_evidence","outcome":{"kind":"unknown","unknown":true,"unknown_reason":"pending evidence could not be reconciled"},"coverage":{"status":"degraded","gaps":[{"reason":"invalid_pending_evidence"}]}}}), "operator", peer, None);
                    eprintln!("pending recovery for {id}: {problem}");
                }
            }
        }
    }
}

fn validate_completion(run: &RunRecord, completion: &Completion) -> Result<()> {
    let receipt = &completion.body["receipt"];
    validate_receipt(receipt)?;
    let control = &completion.control;
    let typed: records::Receipt = serde_json::from_value(receipt.clone())?;
    if control.seq == 0
        || control.outcome != typed.outcome
        || control.error != typed.outcome.error
        || control.schema != records::SCHEMA_CONTROL
        || control.attempt_id != run.attempt_id
        || control.receipt_phase != typed.phase
        || control.receipt_digest
            != records::semantic::receipt_digest(receipt).map_err(|e| LedgerError(e.to_string()))?
        || !match control.kind {
            records::ControlKind::Settled => typed.phase == records::Phase::Settled,
            records::ControlKind::Refused => typed.phase == records::Phase::Refused,
            records::ControlKind::Unsettled => completion.kind == "outcome_unknown",
            _ => false,
        }
        || (completion.kind == "settled"
            && !(typed.phase == records::Phase::Settled && typed.lifetime.tree_empty == Some(true)
                || known_exec_failure(receipt)))
    {
        return Err(LedgerError(
            "pending exit record lacks corroborating terminal control".into(),
        ));
    }
    Ok(())
}
