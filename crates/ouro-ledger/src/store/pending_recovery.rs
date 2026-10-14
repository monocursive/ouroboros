use super::*;
use crate::pending::{Completion, Journal, STATE};

/// A pending journal's identity and change times, as last seen.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct JournalSeen {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

/// Why a dead owner's pending evidence was refused. Canonical history keeps
/// only this class, never the refusal's text, which can quote journal values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingRefusal {
    /// A nonterminal run whose owner died has no pending journal.
    JournalMissing,
    /// The journal cannot be opened safely or decoded.
    JournalUnreadable,
    /// Pending evidence cannot supply the admission the run never recorded.
    NotAdmitted,
    /// The recorded exit lacks corroborating terminal control.
    ExitUncorroborated,
    /// The journal's evidence violates the source contract or canonical history.
    EvidenceRefused,
}

impl PendingRefusal {
    fn class(self) -> &'static str {
        match self {
            Self::JournalMissing => "journal_missing",
            Self::JournalUnreadable => "journal_unreadable",
            Self::NotAdmitted => "not_admitted",
            Self::ExitUncorroborated => "exit_uncorroborated",
            Self::EvidenceRefused => "evidence_refused",
        }
    }
}

/// A failed reconciliation. Only a refusal the journal caused is final for an
/// unchanged journal; anything else (a held lock, store I/O, an owner that is
/// still alive) may not happen again.
pub(super) enum PendingFailure {
    Refused(PendingRefusal, LedgerError),
    Other(LedgerError),
}

impl PendingFailure {
    fn into_error(self) -> LedgerError {
        match self {
            Self::Refused(_, error) | Self::Other(error) => error,
        }
    }

    /// A journal that could not be opened or read is the journal's doing
    /// only when its content, identity, size or ownership is wrong. An
    /// operating-system failure (no descriptor or memory left, an
    /// interrupted call, a failed sync) says nothing about the journal and
    /// may not happen again.
    fn unreadable(error: LedgerError) -> Self {
        match error.kind() {
            crate::protocol::ErrorKind::Io(_) => Self::Other(error),
            _ => Self::Refused(PendingRefusal::JournalUnreadable, error),
        }
    }
}

impl Store {
    pub(super) fn pending_exists(&self, id: &str) -> bool {
        fs::symlink_metadata(self.run_dir(id).join(STATE)).is_ok()
    }

    #[cfg(target_os = "linux")]
    fn journal_seen(&self, id: &str) -> Option<JournalSeen> {
        let m = fs::symlink_metadata(self.run_dir(id).join(STATE)).ok()?;
        Some(JournalSeen {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        })
    }

    /// A dead owner's local evidence could not be reconciled. Record the
    /// unknown outcome with the refusal's class; the journal stays for
    /// inspection, and the refusal's text goes only to the operator's log.
    pub(super) fn record_invalid_pending(
        &mut self,
        id: &str,
        peer: &Peer,
        refusal: PendingRefusal,
    ) -> Result<AppendReceipt> {
        self.append(
            id,
            json!({"kind":"outcome_unknown","request_id":"reconcile:pending-invalid","body":{
                "reason":"invalid_pending_evidence","refusal":refusal.class(),
                "outcome":{"kind":"unknown","unknown":true,"unknown_reason":"pending evidence could not be reconciled"},
                "coverage":{"status":"degraded","gaps":[{"reason":"invalid_pending_evidence"}]}}}),
            "operator",
            peer,
            None,
        )
    }

    /// Reconcile evidence only. Neither this path nor orphan recovery can launch.
    pub fn reconcile_pending(
        &mut self,
        id: &str,
        peer: &Peer,
        alive: &impl Fn(&Peer) -> bool,
    ) -> Result<RunRecord> {
        self.reconcile(id, peer, alive)
            .map_err(PendingFailure::into_error)
    }

    pub(super) fn reconcile(
        &mut self,
        id: &str,
        peer: &Peer,
        alive: &impl Fn(&Peer) -> bool,
    ) -> std::result::Result<RunRecord, PendingFailure> {
        use PendingFailure::{Other, Refused};
        use PendingRefusal::*;
        let refused = |refusal| move |error| Refused(refusal, error);
        if self.stream(id).map_err(Other)?.is_poisoned() {
            return Err(Other(LedgerError::refused(
                "ambiguous canonical history refuses pending recovery",
            )));
        }
        let run = self.show(id).map_err(Other)?;
        if run.payload["evidence"] != "best-effort" {
            return Err(Other(LedgerError::refused(
                "strict runs cannot recover pending owner evidence",
            )));
        }
        let owner = run.owner.as_ref().ok_or_else(|| {
            Other(LedgerError::refused(
                "pending recovery requires a durable owner",
            ))
        })?;
        if peer != owner && alive(owner) {
            return Err(Other(LedgerError::refused(
                "only the live owner may reconcile its journal",
            )));
        }
        if !self.pending_exists(id) {
            if ["settled", "denied", "outcome_unknown"].contains(&run.state.as_str()) {
                return Ok(run);
            }
            return Err(Refused(
                JournalMissing,
                LedgerError::refused("nonterminal recovery requires its pending journal"),
            ));
        }
        let journal = Journal::try_open(&self.run_dir(id))
            .map_err(PendingFailure::unreadable)?
            .ok_or_else(|| {
                Other(LedgerError::refused(
                    "another process holds the pending journal's lock",
                ))
            })?;
        let mut state = journal.read(&run).map_err(PendingFailure::unreadable)?;
        if ["settled", "denied", "outcome_unknown"].contains(&run.state.as_str()) {
            journal.remove().map_err(Other)?;
            return Ok(run);
        }
        if run.state != "admitted" {
            return Err(Refused(
                NotAdmitted,
                LedgerError::refused("pending evidence cannot supply admission"),
            ));
        }
        if let Some(completion) = &state.completion {
            validate_completion(&run, completion).map_err(refused(ExitUncorroborated))?;
        }
        let events = state.pending();
        for event in &events {
            crate::redaction::validate_stored(event, &run.payload, &run.attempt_id)
                .map_err(refused(EvidenceRefused))?;
        }
        // History refuses journal evidence without poisoning the stream; a
        // persistence failure poisons it and is never the journal's fault.
        let appended = |store: &Self, result: Result<AppendReceipt>| {
            result.map(drop).map_err(|error| {
                if store.stream(id).is_ok_and(|s| !s.is_poisoned()) {
                    Refused(EvidenceRefused, error)
                } else {
                    Other(error)
                }
            })
        };
        if state.active || state.completion.is_some() {
            state.outage().map_err(refused(EvidenceRefused))?;
            let record = json!({"kind":"evidence_gap","request_id":format!("outage:{}",state.episode),"body":{"reason":"writer_outage","episode":state.episode,"owner":owner}});
            let result = self.append(id, record, "recovery", peer, None);
            appended(self, result)?;
        }
        for event in events {
            let result = self.append_source_as(id, &event, peer, None, "recovery");
            appended(self, result)?;
        }
        if let Some(completion) = &state.completion {
            let record = json!({"kind":completion.kind,"request_id":"settlement","effect_id":null,"body":completion.body});
            let result = self.append(id, record, "recovery", peer, None);
            appended(self, result)?;
            journal.remove().map_err(Other)?;
        } else if !alive(owner) {
            self.append(id, json!({"kind":"outcome_unknown","request_id":"reconcile:pending-owner-dead","body":{"outcome":{"kind":"unknown","unknown":true,"unknown_reason":"pending owner has no durable local exit record"},"coverage":{"status":"degraded","gaps":[{"reason":"local_exit_missing"}]}}}), "recovery", peer, None).map_err(Other)?;
            journal.remove().map_err(Other)?;
        } else {
            state.clear();
            journal.save(&state).map_err(Other)?;
        }
        self.show(id).map_err(Other)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recover_pending_orphans(&mut self, peer: &Peer) {
        let ids: Vec<_> = self
            .streams()
            .iter()
            .filter(|(id, s)| {
                s.run().payload["evidence"] == "best-effort"
                    && !s.is_poisoned()
                    && (self.pending_exists(id)
                        || ["prepared", "admitted"].contains(&s.run().state.as_str()))
                    && s.run()
                        .owner
                        .as_ref()
                        .is_some_and(|owner| !crate::daemon::peer_alive(owner))
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let seen = self.journal_seen(&id);
            if self.failed_journals().get(&id) == Some(&seen) {
                continue;
            }
            let (refusal, problem) = match self.reconcile(&id, peer, &crate::daemon::peer_alive) {
                Ok(_) => {
                    self.failed_journals().remove(&id);
                    continue;
                }
                Err(PendingFailure::Other(problem)) => {
                    // Not the journal's doing: the next attempt may succeed.
                    eprintln!(
                        "{}",
                        log_line(
                            format_args!("pending recovery for {id} will be retried"),
                            &problem
                        )
                    );
                    continue;
                }
                Err(PendingFailure::Refused(refusal, problem)) => (refusal, problem),
            };
            eprintln!(
                "{}",
                log_line(format_args!("pending recovery for {id}"), &problem)
            );
            // Retain the failed journal for inspection. A bad local file is
            // never sufficient evidence for a successful terminal outcome.
            if self
                .stream(&id)
                .is_ok_and(|s| ["prepared", "admitted"].contains(&s.run().state.as_str()))
                && let Err(error) = self.record_invalid_pending(&id, peer, refusal)
            {
                eprintln!(
                    "{}",
                    log_line(format_args!("recording unknown outcome for {id}"), &error)
                );
            }
            // Retrying an unchanged journal every second cannot succeed.
            self.failed_journals().insert(id, seen);
        }
    }
}

/// One line for the operator's log. A refusal can quote journal values
/// verbatim, so control characters are spelled out: a journal must neither
/// forge log lines nor drive the operator's terminal.
#[cfg(any(target_os = "linux", test))]
fn log_line(context: std::fmt::Arguments<'_>, problem: &LedgerError) -> String {
    format!("{context}: {}", records::escape_control(problem.message()))
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
            != records::semantic::receipt_digest(receipt)
                .map_err(|e| LedgerError::refused(e.to_string()))?
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
        return Err(LedgerError::refused(
            "pending exit record lacks corroborating terminal control",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
