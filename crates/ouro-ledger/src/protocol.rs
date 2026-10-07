//! Bounded authenticated local protocol and the public ledger projections.

use std::{fmt, io};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const MAX_CONNECTIONS: usize = 32;

#[derive(Debug)]
pub struct LedgerError(pub String);

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LedgerError {}
impl From<io::Error> for LedgerError {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}
impl From<serde_json::Error> for LedgerError {
    fn from(error: serde_json::Error) -> Self {
        Self(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, LedgerError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppendReceipt {
    pub seq: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedOwner {
    pub attempt_id: String,
    pub owner_token: String,
    pub producer_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub uid: u32,
    pub pid: u32,
    pub birth: String,
    pub boot_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub head_seq: u64,
    pub head_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub schema: String,
    pub run_id: String,
    pub attempt_id: String,
    pub request_id: String,
    pub payload: Value,
    pub state: String,
    pub child_protection: String,
    pub owner: Option<Peer>,
    pub outcome: Option<Value>,
    pub coverage: Value,
    pub settlement: String,
    pub receipts: Vec<Value>,
    pub capture: Value,
    pub chain: Chain,
    /// Rebuilt from canonical operator hold/release records. Legacy runs have none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub holds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PrunedHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_history: Option<PrunedHistory>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrunedHistory {
    pub state: String,
    pub anchor_digest: String,
    pub collected_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcReceipt {
    pub run_id: String,
    pub chain: Chain,
    pub history: PrunedHistory,
    pub removed_files: u32,
    pub removed_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureGcReceipt {
    pub run_id: String,
    pub chain: Chain,
    pub capture_history: PrunedHistory,
    pub removed_files: u32,
    pub removed_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcFailure {
    pub run_id: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcResult {
    pub schema: String,
    pub retain_days: u32,
    pub capture_retain_days: u32,
    pub pruned: Vec<GcReceipt>,
    pub captures_pruned: Vec<CaptureGcReceipt>,
    pub kept: Vec<GcCandidate>,
    pub failed: Vec<GcFailure>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcCandidate {
    pub run_id: String,
    pub state: String,
    pub child_protection: String,
    pub chain: Chain,
    pub last_activity_at: Option<String>,
    pub candidate: bool,
    pub keep_reasons: Vec<String>,
    pub captures_candidate: bool,
    pub captures_keep_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcPlan {
    pub schema: String,
    pub dry_run: bool,
    pub deletion_supported: bool,
    pub verification_required: bool,
    pub retain_days: u32,
    pub capture_retain_days: u32,
    pub capture_cutoff: String,
    pub evaluated_at: String,
    pub cutoff: String,
    pub runs: Vec<GcCandidate>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReport {
    pub run_id: String,
    pub local_consistency: bool,
    pub child_protection: String,
    pub coverage: Value,
    pub events: u64,
    pub problems: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<PrunedHistory>,
}

pub const MAX_READ_LIMIT: u32 = 1000;
pub const READ_SCAN_BYTES: usize = 131_072;
pub const READ_SCAN_FRAMES: usize = 32;
pub const READ_OUTPUT_BYTES: usize = 131_072;
pub const READ_CHUNK_BYTES: usize = 65_536;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunFilter {
    /// Inclusive last accepted writer activity time.
    pub since: Option<String>,
    /// Exclusive last accepted writer activity time.
    pub until: Option<String>,
    pub launch: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Exact recorded outcome kind, or `pending` before any terminal outcome.
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRequest {
    pub filter: RunFilter,
    pub after: Option<String>,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RunSummary {
    pub run_id: String,
    pub attempt_id: String,
    pub request_id: String,
    pub last_activity_at: Option<String>,
    pub profile: String,
    pub launch: Option<String>,
    pub tags: Vec<String>,
    pub state: String,
    pub outcome: String,
    pub child_protection: String,
    pub coverage: Value,
    pub chain: Chain,
    pub evidence_status: String,
    pub history: Option<PrunedHistory>,
    pub capture_history: Option<PrunedHistory>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CatalogPage {
    pub schema: String,
    pub snapshot: String,
    pub runs: Vec<RunSummary>,
    pub matched_runs: u32,
    pub scanned_runs: u32,
    pub next_after: Option<String>,
    pub done: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub runs: RunFilter,
    pub filter: ReadFilter,
    pub after: Option<String>,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryPage {
    pub schema: String,
    pub catalog_snapshot: String,
    pub matched_runs: u32,
    pub run: Option<RunSummary>,
    pub page: Option<ReadPage>,
    pub problem: Option<String>,
    pub next_after: Option<String>,
    pub done: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadSelector {
    All,
    Execs,
    Paths,
    Hosts,
    Denials,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadStage {
    Attempt,
    Result,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReadFilter {
    pub selector: ReadSelector,
    pub stage: Option<ReadStage>,
    pub since: Option<String>,
    pub until: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub run_id: String,
    pub filter: ReadFilter,
    pub cursor: Option<String>,
    pub limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OversizedRecord {
    pub seq: u64,
    pub bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReadPage {
    pub schema: String,
    pub run_id: String,
    pub snapshot: Chain,
    pub state: String,
    pub child_protection: String,
    pub coverage: Value,
    pub local_consistency: bool,
    pub stream_status: String,
    pub problems: Vec<String>,
    pub records: Vec<Value>,
    /// Exact canonical NDJSON fragments; concatenate pages of one snapshot.
    pub ndjson: String,
    pub next_cursor: Option<String>,
    pub scanned_through_seq: u64,
    pub done: bool,
    pub oversized_record: Option<OversizedRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntent {
    pub run_id: String,
    pub request_id: String,
    pub kind: String,
    pub effect_id: Option<String>,
    pub body: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailRequest {
    pub run_id: String,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailPage {
    pub schema: String,
    pub run_id: String,
    pub head: Chain,
    pub state: String,
    pub child_protection: String,
    pub coverage: Value,
    pub local_consistency: bool,
    pub stream_status: String,
    /// Exact canonical fragments; concatenate pages, including partial records.
    pub ndjson: String,
    pub next_cursor: String,
    pub caught_up: bool,
    pub scanned_through_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Append {
        intent: OperatorIntent,
    },
    Tail {
        request: TailRequest,
    },
    Prepare {
        request_id: String,
        payload: Value,
    },
    ClaimOwner {
        run_id: String,
    },
    AppendOwner {
        run_id: String,
        request_id: String,
        kind: String,
        effect_id: Option<String>,
        body: Value,
        token: String,
    },
    AppendSource {
        run_id: String,
        event: Value,
        token: String,
    },
    Show {
        run_id: String,
    },
    ShowWithTranscript {
        run_id: String,
    },
    Runs,
    Catalog {
        request: CatalogRequest,
    },
    Discover {
        request: DiscoveryRequest,
    },
    Verify {
        run_id: Option<String>,
    },
    Read {
        request: ReadRequest,
    },
    Ping,
    SettleOrphans,
    ReconcilePending {
        run_id: String,
    },
    Hold {
        run_id: String,
        request_id: String,
    },
    Release {
        run_id: String,
        request_id: String,
    },
    Gc {
        dry_run: bool,
        retain_days: Option<u32>,
        capture_retain_days: Option<u32>,
        after: Option<String>,
        limit: u32,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ok { value: Value },
    Error { message: String },
}
