//! The ledger store: the sole writer, the canonical streams it owns, and the
//! features built on them. The canonical stream is authoritative; run.json is
//! a projection.
//!
//! - `writer`: [`Store`] and the append path;
//! - `stream`: one run's accepted state, its record rules and its re-read;
//! - `frozen`: validation against the frozen schemas;
//! - the features, each owning its own state and reaching the writer and
//!   streams only through their methods: `catalog`, `tail`, `transcript`,
//!   `operator`, `retention`, `pruning` and `capture_pruning` (over the
//!   shared GC protocol in `gc`), `verification`, `pending_recovery` and
//!   `bundle_replay`.

use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde_json::Value;

use crate::protocol::{LedgerError, Result};

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
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(crate) use frozen::validate_payload;
pub(crate) use frozen::validate_source;
pub(crate) use stream::{Poison, poison_status};
pub(crate) use verification::{VerifyPlan, verify_page};
pub use writer::Store;

fn check_run_id(id: &str) -> Result<()> {
    if !crate::protocol::run_id(id) {
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
