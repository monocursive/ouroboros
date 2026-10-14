//! One run's accepted canonical state: what the writer acknowledged, the
//! anchors that corroborate it, and how it stopped being trustworthy.
use super::*;

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
    pub(super) state: &'static str,
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
    pub(crate) fn stream_status(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Corrupt | Self::Unanchored => "corrupt",
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
pub(crate) fn poison_status(poisoned: &[Poison]) -> Option<&'static str> {
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
    pub(super) run: RunRecord,
    pub(super) accepted_bytes: u64,
    pub(super) replay: BTreeMap<String, Replay>,
    pub(super) source_heads: BTreeMap<String, u64>,
    pub(super) source_gaps: Vec<Value>,
    pub(super) last_source: Option<Value>,
    pub(super) first_loss: Option<Value>,
    pub(super) receipt_phase: Option<String>,
    pub(super) poisoned: Vec<Poison>,
    pub(super) segments: Vec<manifest::Segment>,
    pub(super) active_segment: usize,
    pub(super) segment_bytes: u64,
    pub(super) segment_hash: Sha256,
    pub(super) replay_hash: Sha256,
    pub(super) anchors: BTreeMap<u64, Anchor>,
    pub(super) last_activity_at: Option<String>,
    pub(super) retention_time_valid: bool,
    pub(super) pruned: Option<pruning::Retained>,
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

    /// Shared by store recovery and read-only portable bundle verification.
    pub(super) fn accept_canonical(&mut self, run_id: &str, bytes: &[u8]) -> Result<()> {
        let decoded: Value = serde_json::from_slice(bytes)
            .map_err(|error| LedgerError(format!("invalid canonical JSON: {error}")))?;
        if !canonical(&decoded).is_ok_and(|encoded| encoded == bytes) {
            return Err(LedgerError(
                "noncanonical or unsupported stream bytes".into(),
            ));
        }
        validate_frozen("record", &decoded).map_err(|_| {
            LedgerError("canonical ledger record violates its versioned schema".into())
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
            return Err(LedgerError(
                "canonical identity, sequence or hash-chain link mismatch".into(),
            ));
        }
        if expected_seq == 1 {
            if decoded["kind"] != "prepared" {
                return Err(LedgerError(
                    "stream does not start at durable preparation".into(),
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
            return Err(LedgerError("mixed attempt identity".into()));
        }
        let payload = original_payload(&decoded);
        if decoded["kind"] == "source" {
            crate::redaction::validate_stored(
                &payload["body"],
                &self.run.payload,
                &self.run.attempt_id,
            )
            .map_err(|_| {
                LedgerError("canonical producer violates the frozen source contract".into())
            })?;
        }
        if let Some(receipt) = decoded["body"].get("receipt") {
            validate_receipt(receipt).map_err(|_| {
                LedgerError("canonical receipt violates the frozen receipt contract".into())
            })?;
        }
        let payload_digest = digest(&payload)?;
        let receipt = AppendReceipt {
            seq: expected_seq,
            digest: sha256_prefixed(bytes),
        };
        validate_recovery(
            self,
            &payload,
            decoded["provenance"]["role"].as_str().unwrap_or(""),
        )?;
        validate_transition(self, &payload)?;
        validate_intent(self, &payload)?;
        apply_record(self, &payload, receipt.clone(), payload_digest.clone())?;
        self.accepted_bytes += bytes.len() as u64 + 1;
        self.hash_record(bytes, &decoded, &receipt, &payload_digest)
    }

    pub(super) fn begin_segment(&mut self, number: usize) {
        self.active_segment = number;
        self.segment_bytes = 0;
        self.segment_hash = Sha256::new();
    }

    pub(super) fn hash_record(
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
        let state = match self.run.state.as_str() {
            "prepared" => "prepared",
            "admitted" => "admitted",
            "denied" => "denied",
            "settled" => "settled",
            "outcome_unknown" => "outcome_unknown",
            _ => return Err(LedgerError("unsupported canonical run state".into())),
        };
        let labels_digest = crate::reader::snapshot_labels_digest(
            &self.run.child_protection,
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
