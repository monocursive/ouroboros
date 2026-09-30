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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
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
    Runs,
    Verify {
        run_id: Option<String>,
    },
    Ping,
    SettleOrphans,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ok { value: Value },
    Error { message: String },
}
