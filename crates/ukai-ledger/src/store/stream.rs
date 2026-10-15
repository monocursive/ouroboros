//! One run's accepted canonical state: what the writer acknowledged, the
//! anchors that corroborate it, and how it stopped being trustworthy.
use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use ukai_records::{canonical::sha256_prefixed, records};

use self::rules::{
    apply_record, original_payload, validate_intent, validate_recovery, validate_transition,
};
use super::{
    canonical, digest,
    frozen::{validate_frozen, validate_payload, validate_receipt},
    pruning,
};
use crate::{
    manifest,
    protocol::{
        AppendReceipt, Chain, ChildProtection, LedgerError, PrunedHistory, Result, RunRecord,
        RunState, Settlement, StreamStatus,
    },
    schemas,
};

pub(super) mod load;
pub(super) mod rules;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Replay {
    pub(super) digest: String,
    pub(super) receipt: AppendReceipt,
}

#[cfg_attr(test, derive(Clone))]
pub(super) struct Anchor {
    pub(super) bytes: u64,
    pub(super) digest: String,
    pub(super) state: RunState,
    pub(super) labels_digest: String,
}

/// How a stream stopped being trustworthy, decided where the failure is
/// detected rather than recovered later from its message text. Variants are
/// ordered by severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PoisonKind {
    /// This writer's own interruption or uncertain persistence: the validated
    /// prefix stands, and what follows it is missing or unacknowledged.
    Incomplete,
    /// Bytes or store metadata contradict anything this writer could have
    /// produced: an integrity violation.
    Corrupt,
    /// The durable segment manifest does not corroborate the canonical bytes,
    /// so even the validated prefix has no durable anchor.
    Unanchored,
}

impl PoisonKind {
    pub(crate) fn stream_status(self) -> StreamStatus {
        match self {
            Self::Incomplete => StreamStatus::Incomplete,
            Self::Corrupt | Self::Unanchored => StreamStatus::Corrupt,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Poison {
    pub(crate) kind: PoisonKind,
    pub(crate) detail: String,
}

impl Poison {
    pub(super) fn new(kind: PoisonKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// The most severe finding decides: an integrity violation is never reported
/// as a merely incomplete stream.
pub(crate) fn poison_status(poisoned: &[Poison]) -> Option<StreamStatus> {
    poisoned
        .iter()
        .map(|p| p.kind)
        .max()
        .map(PoisonKind::stream_status)
}

pub(super) fn poison_details(poisoned: &[Poison]) -> Vec<String> {
    poisoned.iter().map(|p| p.detail.clone()).collect()
}

#[cfg_attr(test, derive(Clone))]
pub(super) struct Stream {
    run: RunRecord,
    accepted_bytes: u64,
    replay: BTreeMap<String, Replay>,
    source_heads: BTreeMap<String, u64>,
    source_gaps: Vec<Value>,
    last_source: Option<Value>,
    first_loss: Option<Value>,
    receipt_phase: Option<String>,
    poisoned: Vec<Poison>,
    segments: Vec<manifest::Segment>,
    active_segment: usize,
    segment_bytes: u64,
    segment_hash: Sha256,
    replay_hash: Sha256,
    anchors: BTreeMap<u64, Anchor>,
    last_activity_at: Option<String>,
    retention_time_valid: bool,
    /// Shared, so planning a verification of a pruned run does not copy
    /// its retained replay identities.
    pruned: Option<std::sync::Arc<pruning::Retained>>,
}

pub(super) fn initial_run(
    run_id: &str,
    request_id: &str,
    attempt_id: &str,
    payload: Value,
) -> RunRecord {
    RunRecord {
        schema: schemas::RUN.into(),
        run_id: run_id.into(),
        request_id: request_id.into(),
        attempt_id: attempt_id.into(),
        payload,
        state: RunState::Prepared,
        child_protection: ChildProtection::Unprotected,
        owner: None,
        outcome: None,
        coverage: json!({"status":"unobserved"}),
        settlement: Settlement::Pending,
        receipts: vec![],
        capture: json!({"stdout":{"state":"not_captured"},"stderr":{"state":"not_captured"},"argv":{"state":"not_captured"}}),
        chain: Chain {
            head_seq: 0,
            head_digest: None,
        },
        holds: vec![],
        history: None,
        capture_history: None,
    }
}

impl Stream {
    pub(super) fn empty(run_id: &str) -> Self {
        Self {
            run: initial_run(run_id, "", "", json!({})),
            accepted_bytes: 0,
            replay: BTreeMap::new(),
            source_heads: BTreeMap::new(),
            source_gaps: vec![],
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
            last_activity_at: None,
            retention_time_valid: true,
            pruned: None,
        }
    }

    /// The stream of a run whose preparation is being appended.
    pub(super) fn prepared(run: RunRecord) -> Self {
        Self::empty(&run.run_id).with_run(run)
    }

    fn with_run(mut self, run: RunRecord) -> Self {
        self.run = run;
        self
    }

    /// A pruned run as its retained authority keeps it: its terminal
    /// projection, replay identities, any strict source loss and its last
    /// activity; no canonical bytes remain to re-read.
    pub(super) fn restored(
        run: RunRecord,
        replay: BTreeMap<String, Replay>,
        strict_source_loss: bool,
        last_activity_at: String,
        retained: pruning::Retained,
    ) -> Self {
        let mut stream = Self::empty(&run.run_id).with_run(run);
        stream.replay = replay;
        if strict_source_loss {
            stream.source_gaps = vec![json!({"reason":"retained_source_loss"})];
        }
        stream.last_activity_at = Some(last_activity_at);
        stream.pruned = Some(std::sync::Arc::new(retained));
        stream
    }

    /// The run as this stream has accepted it.
    pub(super) fn run(&self) -> &RunRecord {
        &self.run
    }

    pub(super) fn into_run(self) -> RunRecord {
        self.run
    }

    /// Tests forge accepted state directly to reach states no record allows.
    #[cfg(test)]
    pub(super) fn run_mut(&mut self) -> &mut RunRecord {
        &mut self.run
    }

    /// The canonical bytes this stream has accepted.
    pub(super) fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    /// Every request and effect identity with its acknowledged receipt.
    pub(super) fn replay(&self) -> &BTreeMap<String, Replay> {
        &self.replay
    }

    /// Why this stream stopped being trustworthy, if it did.
    pub(super) fn poisoned(&self) -> &[Poison] {
        &self.poisoned
    }

    pub(super) fn is_poisoned(&self) -> bool {
        !self.poisoned.is_empty()
    }

    /// Record why this stream can no longer be trusted.
    pub(super) fn poison(&mut self, kind: PoisonKind, detail: impl Into<String>) {
        self.poisoned.push(Poison::new(kind, detail));
    }

    /// The retained authority of a pruned run.
    pub(super) fn pruned(&self) -> Option<&std::sync::Arc<pruning::Retained>> {
        self.pruned.as_ref()
    }

    /// The accepted head at `seq`, with what it corroborates.
    pub(super) fn anchor(&self, seq: u64) -> Option<&Anchor> {
        self.anchors.get(&seq)
    }

    /// The latest writer receipt time among accepted records.
    pub(super) fn last_activity_at(&self) -> Option<&str> {
        self.last_activity_at.as_deref()
    }

    /// Whether every accepted record carries a usable receipt time, so
    /// `last_activity_at` can decide retention.
    pub(super) fn retention_time_valid(&self) -> bool {
        self.retention_time_valid
    }

    pub(super) fn segments(&self) -> &[manifest::Segment] {
        &self.segments
    }

    /// Recorded producer transport loss and outage gaps.
    pub(super) fn source_gaps(&self) -> &[Value] {
        &self.source_gaps
    }

    /// The active segment's number and accepted length.
    pub(super) fn active_segment(&self) -> (usize, u64) {
        (self.active_segment, self.segment_bytes)
    }

    /// GC published this run's authority: until deletion completes the run
    /// projects `run`, and its history is never appended to again.
    pub(super) fn begin_pruning(&mut self, retained: pruning::Retained, run: RunRecord) {
        self.pruned = Some(std::sync::Arc::new(retained));
        self.run = run;
    }

    /// GC completed this run's deletion; it projects `run` from now on.
    pub(super) fn finish_pruning(&mut self, run: RunRecord) {
        self.run = run;
    }

    /// Capture expiry relabels the run's captures and records its history.
    pub(super) fn set_captures(&mut self, capture: Value, history: PrunedHistory) {
        self.run.capture = capture;
        self.run.capture_history = Some(history);
    }

    /// Refuse `payload` (an intent as appended) in `role` unless this
    /// stream's state allows it. Appends and recovery ask exactly this, so a
    /// record acknowledged now is accepted again at the next start.
    pub(super) fn check(&self, payload: &Value, role: &str) -> Result<()> {
        validate_recovery(self, payload, role)?;
        validate_transition(self, payload)?;
        validate_intent(self, payload)
    }

    /// Accept one checked canonical record: `bytes` are its frame without the
    /// newline, `record` the canonical record and `payload` the intent it
    /// carries.
    pub(super) fn accept(
        &mut self,
        bytes: &[u8],
        record: &Value,
        payload: &Value,
        receipt: AppendReceipt,
        payload_digest: String,
    ) -> Result<()> {
        apply_record(self, payload, receipt.clone(), payload_digest.clone())?;
        self.accepted_bytes += bytes.len() as u64 + 1;
        self.hash_record(bytes, record, &receipt, &payload_digest)
    }

    /// Shared by store recovery and read-only portable bundle verification.
    pub(super) fn accept_canonical(&mut self, run_id: &str, bytes: &[u8]) -> Result<()> {
        let decoded: Value = serde_json::from_slice(bytes).map_err(|error| {
            LedgerError::new(
                crate::protocol::ErrorKind::Decode,
                format!("invalid canonical JSON: {error}"),
            )
        })?;
        if !canonical(&decoded).is_ok_and(|encoded| encoded == bytes) {
            return Err(LedgerError::refused(
                "noncanonical or unsupported stream bytes",
            ));
        }
        validate_frozen("record", &decoded).map_err(|_| {
            LedgerError::refused("canonical ledger record violates its versioned schema")
        })?;
        let expected_seq = self.run.chain.head_seq + 1;
        let expected_schema = if decoded["kind"] == "source" {
            records::SCHEMA_EVENT
        } else {
            schemas::RECORD
        };
        if decoded["schema"] != expected_schema
            || decoded["run_id"] != run_id
            || decoded["seq"].as_u64() != Some(expected_seq)
            || decoded["prev"] != json!(self.run.chain.head_digest)
        {
            return Err(LedgerError::refused(
                "canonical identity, sequence or hash-chain link mismatch",
            ));
        }
        if expected_seq == 1 {
            if decoded["kind"] != "prepared" {
                return Err(LedgerError::refused(
                    "stream does not start at durable preparation",
                ));
            }
            self.run = initial_run(
                run_id,
                decoded["body"]["request_id"].as_str().unwrap_or(""),
                decoded["attempt_id"].as_str().unwrap_or(""),
                decoded["body"]["payload"].clone(),
            );
            validate_payload(&self.run.payload)?;
        }
        if decoded["attempt_id"] != self.run.attempt_id {
            return Err(LedgerError::refused("mixed attempt identity"));
        }
        let payload = original_payload(&decoded);
        if decoded["kind"] == "source" {
            crate::redaction::validate_stored(
                &payload["body"],
                &self.run.payload,
                &self.run.attempt_id,
            )
            .map_err(|_| {
                LedgerError::refused("canonical producer violates the frozen source contract")
            })?;
        }
        if let Some(receipt) = decoded["body"].get("receipt") {
            validate_receipt(receipt).map_err(|_| {
                LedgerError::refused("canonical receipt violates the frozen receipt contract")
            })?;
        }
        let payload_digest = digest(&payload)?;
        let receipt = AppendReceipt {
            seq: expected_seq,
            digest: sha256_prefixed(bytes),
        };
        self.check(
            &payload,
            decoded["provenance"]["role"].as_str().unwrap_or(""),
        )?;
        self.accept(bytes, &decoded, &payload, receipt, payload_digest)
    }

    pub(super) fn begin_segment(&mut self, number: usize) {
        self.active_segment = number;
        self.segment_bytes = 0;
        self.segment_hash = Sha256::new();
    }

    fn hash_record(
        &mut self,
        bytes: &[u8],
        record: &Value,
        receipt: &AppendReceipt,
        payload_digest: &str,
    ) -> Result<()> {
        // Retention uses writer receipt time, never producer time or file mtime.
        // A clock regression cannot shorten the observed retention interval.
        match record["received_at"]
            .as_str()
            .filter(|time| crate::reader::utc_second(time))
        {
            Some(time) => {
                if self
                    .last_activity_at
                    .as_deref()
                    .is_none_or(|last| time > last)
                {
                    self.last_activity_at = Some(time.into());
                }
            }
            None => self.retention_time_valid = false,
        }
        self.segment_hash.update(bytes);
        self.segment_hash.update(b"\n");
        self.segment_bytes += bytes.len() as u64 + 1;
        let first_seq = self
            .segments
            .get(self.active_segment - 1)
            .map_or(receipt.seq, |s| s.first_seq);
        let segment = manifest::Segment {
            name: manifest::name(self.active_segment),
            first_seq,
            last_seq: receipt.seq,
            bytes: self.segment_bytes,
            digest: format!("sha256:{:x}", self.segment_hash.clone().finalize()),
            head_digest: receipt.digest.clone(),
        };
        if self.segments.len() < self.active_segment {
            self.segments.push(segment);
        } else {
            self.segments[self.active_segment - 1] = segment;
        }
        let identity = canonical(&json!({"request_id":record["request_id"],
            "effect_id":record.get("effect_id"),"payload_digest":payload_digest,
            "seq":receipt.seq,"digest":receipt.digest}))?;
        self.replay_hash
            .update((identity.len() as u64).to_le_bytes());
        self.replay_hash.update(identity);
        let state = self.run.state;
        let labels_digest = crate::reader::snapshot_labels_digest(
            self.run.child_protection,
            &crate::reader::coverage_summary(&self.run.coverage),
        )?;
        self.anchors.insert(
            receipt.seq,
            Anchor {
                bytes: self.accepted_bytes,
                digest: receipt.digest.clone(),
                state,
                labels_digest,
            },
        );
        Ok(())
    }

    pub(super) fn manifest(&self) -> crate::manifest::Manifest {
        let hash = |h: &Sha256| -> String { format!("sha256:{:x}", h.clone().finalize()) };
        crate::manifest::Manifest {
            schema: schemas::SEGMENTS.into(),
            run_id: self.run.run_id.clone(),
            attempt_id: self.run.attempt_id.clone(),
            segments: self.segments.clone(),
            replay_digest: hash(&self.replay_hash),
        }
    }
}
