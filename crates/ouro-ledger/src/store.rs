//! The sole writer. The canonical stream is authoritative; run.json is a projection.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::SystemTime,
};

use ouro_records::{
    canonical::{sha256_prefixed, to_jcs},
    records,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::protocol::{
    AppendReceipt, Chain, LedgerError, MAX_FRAME_BYTES, Peer, ReadPage, ReadRequest, Result,
    RunRecord, StoreStatus,
};

use crate::discovery::valid_name;
use crate::faults::{self, Point, Replaced};
use crate::fsx;
use crate::manifest::{self, STREAM};
use crate::schemas;

mod bundle_replay;
mod capture_pruning;
pub(crate) use bundle_replay::{Replayed, replay as replay_bundle};
mod catalog;
mod frozen;
mod gc;
#[cfg(test)]
mod intent_tail_tests;
#[cfg(test)]
mod lifecycle_tests;
mod operator;
mod pending_recovery;
mod pruning;
mod retention;
mod stream;
mod tail;
mod transcript;
mod verification;
mod writer;
pub(crate) use frozen::{validate_payload, validate_source};
pub(crate) use stream::{Poison, PoisonKind, poison_status};
pub(crate) use verification::{VerifyPlan, verify_page};
pub use writer::Store;

use frozen::*;
use stream::{load::*, rules::*, *};
use writer::*;

fn check_run_id(id: &str) -> Result<()> {
    if !id.starts_with("run_")
        || id.len() != 36
        || !id[4..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(LedgerError::refused("invalid run id"));
    }
    Ok(())
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    to_jcs(value).map_err(|error| LedgerError::refused(error.to_string()))
}

fn digest(value: &Value) -> Result<String> {
    Ok(sha256_prefixed(&canonical(value)?))
}

#[cfg(test)]
mod tests;
