//! `gc`: reconcile what a dead supervisor left behind (jail-v1 §7, §9.3,
//! §14.2, §15 C03; J4 decisions S6, S7, S9).
//!
//! C03: "GC skips live/foreign/unidentified resources; boot/PID/cgroup reuse
//! does not target an unrelated process." The module is three parts:
//!
//! - [`gc_with`] walks `<data>/attempts` (and nothing else) under one entry
//!   bound per invocation (S7), identifies each attempt root without following
//!   a link out of it, takes the lease only of a claimed root, reads jail state
//!   and the last receipt, asks [`decide`] what may be done, does it through
//!   the [`Host`], records it in jail state (S6), removes the temporary files
//!   a crash left when the owner is dead, then runs the J3 resumption of the
//!   proxy directory and vendor state within what is left of the bound, which
//!   gc's own verification of the registered leaf also permits (J4 wave 2).
//! - [`decide`] is pure: [`Facts`] in, the next probe or a [`Decision`] out.
//!   Every "may gc touch this" rule lives there and is tested without a host.
//! - [`Host`] is the only place the host is asked or changed: the recorded
//!   owner's liveness, and the identity-checked probe, kill and removal of the
//!   execution cgroup (Linux: `platform::linux::reconcile`).
//!
//! What `gc` never does: signal a pid (the only kill is `cgroup.kill` of a
//! leaf pinned by the inode jail state registered), act on a leaf whose name
//! is not its attempt's (J4 wave 3, G2), touch a cgroup recorded in another
//! boot, act while the recorded owner is alive (a zombie leader with a live
//! thread is alive, P1 (c)), clean an attempt whose state or receipt it
//! cannot read, clean a foreign platform's attempt, take the lease of an
//! unclaimed root, or rewrite a receipt whose phase is not `refused` or
//! `settled` (S6: its own actions go to jail state and to its report; J4
//! wave 3, G1).
//!
//! J4 wave 3: a removal's intent is durable before its `rmdir` (G3); an
//! attempt with nothing left is recorded `gc_finished` and later passes spend
//! only its name on it (G4); a record gc repeats is kept once with a count
//! (G5); lost integrity keeps managed scratch in every boot (G6).

use std::collections::BTreeMap;
use std::time::Duration;

use crate::cleanup;
use crate::state;

mod decide;
mod host;
mod view;
mod walk;

pub use decide::{CgroupStep, Decision, Facts, Next, OwnerVerdict, Retention, ScratchStep, decide};
pub use host::{Host, HostIdentity, LeafProbe, LeafRecord, Liveness, OwnerRecord};
pub use view::{
    LeafSource, ReceiptView, RegisteredLeaf, StateView, VerifiedLeaf, parse_receipt, parse_state,
};
pub use walk::{FINISHED, gc, gc_with};

/// The test seam that shrinks the per-invocation entry bound (S9).
pub const SEAM_MAX_ENTRIES: &str = "OURO_JAIL_TEST_GC_MAX_ENTRIES";

/// The first component of an execution leaf's name.
pub const LEAF_PREFIX: &str = "ouro-";
/// The last component of an execution leaf's name.
pub const LEAF_SUFFIX: &str = ".leaf";

/// The name of the execution leaf of the attempt `attempt_id`:
/// `ouro-<attempt id>.leaf` (J4 wave 3, G2). The leaf carries its attempt
/// association (§9.3), so a registration naming any other leaf is not this
/// attempt's, and gc never acts on it.
#[must_use]
pub fn leaf_name_of(attempt_id: &str) -> String {
    format!("{LEAF_PREFIX}{attempt_id}{LEAF_SUFFIX}")
}

/// Largest `jail.json` or `policy.json` gc reads.
const RECORD_MAX: u64 = cleanup::RECEIPT_MAX;

/// What one invocation may do (§14.2, S7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Options {
    /// Entries one invocation visits: the names read from `attempts/`, the
    /// entries of every tree it removes and of every cgroup subtree.
    pub max_entries: usize,
    /// Directory descriptors a removal holds at once.
    pub max_depth: usize,
    /// How long a killed leaf may take to empty (§9.3's forced-stop
    /// verification budget).
    pub kill_budget: Duration,
}

impl Options {
    /// §14.2's initial bounds and §9.3's 5-second verification budget.
    pub const DEFAULT: Options = Options {
        max_entries: cleanup::DEFAULT_MAX_ENTRIES,
        max_depth: cleanup::DEFAULT_MAX_DEPTH,
        kill_budget: Duration::from_secs(5),
    };
}

/// The bound a [`SEAM_MAX_ENTRIES`] value asks for: shrink-only, so a value
/// that is not a plain decimal ([`state::plain_decimal`]) below `default`
/// changes nothing.
#[must_use]
pub fn seam_max_entries(value: &str, default: usize) -> usize {
    state::plain_decimal(value)
        .and_then(|max| usize::try_from(max).ok())
        .filter(|max| (1..default).contains(max))
        .unwrap_or(default)
}

/// What one `gc` invocation found and did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report {
    /// One entry per name read from `attempts/`, sorted by name.
    pub entries: Vec<Entry>,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// Attempts whose cleanup or state access failed or remains pending;
    /// non-empty means `gc` exits 1 after printing its report (§6.4).
    pub incomplete: Vec<String>,
    /// The per-invocation entry bound and its use (S7).
    pub budget: Budget,
    /// The `OURO_JAIL_TEST_*` seams set for this invocation, by name (S9).
    pub test_seams: BTreeMap<String, String>,
}

/// The per-invocation entry bound (S7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budget {
    /// The bound.
    pub max_entries: usize,
    /// Entries charged against it: the listing, removals and cgroup
    /// subtrees (a removal that stops is charged everything it was given).
    pub charged: usize,
    /// Whether the bound was reached.
    pub exhausted: bool,
    /// Whether every name in `attempts/` was read.
    pub listing_complete: bool,
}

/// One name `gc` read from `attempts/`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Entry {
    /// The name, which is an attempt id when it parses as one.
    pub attempt_id: String,
    /// What `gc` did, or `skipped`/`retained`.
    pub action: String,
    /// Why.
    pub reason: String,
    /// What became of the attempt's proxy directory (J3).
    pub proxy_dir: Option<String>,
    /// What `gc` established about the recorded supervisor, when it asked.
    pub owner: Option<String>,
    /// What became of the recorded execution cgroup.
    pub cgroup: Option<String>,
    /// What became of the managed scratch and placeholder directories.
    pub scratch: Option<String>,
    /// The actions this pass recorded in jail state (S6), in order.
    pub recorded: Vec<String>,
    /// The temporary files (`.<name>.tmp`) found in the attempt root when
    /// gc held its lease, sorted: what a crashed durable replacement left.
    pub leftover_temp_files: Vec<String>,
    /// What became of them: `removed <count>`, `would_remove`,
    /// `retained: <why>`, `pending: <why>` or `failed: <why>`; `None` when
    /// there were none.
    pub temp_files: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_seam_only_shrinks_the_bound() {
        assert_eq!(seam_max_entries("4", 100), 4);
        for ignored in ["0", "100", "1000", "-3", "x", "", " 4", "4 ", "+4", "04"] {
            assert_eq!(seam_max_entries(ignored, 100), 100, "{ignored:?}");
        }
    }
}
