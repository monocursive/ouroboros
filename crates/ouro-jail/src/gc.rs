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
//!   the [`Host`], records it in jail state (S6), then runs the J3 resumption
//!   of the proxy directory and vendor state exactly as before.
//! - [`decide`] is pure: [`Facts`] in, the next probe or a [`Decision`] out.
//!   Every "may gc touch this" rule lives there and is tested without a host.
//! - [`Host`] is the only place the host is asked or changed: the recorded
//!   owner's liveness, and the identity-checked probe, kill and removal of the
//!   execution cgroup (Linux: `platform::linux::reconcile`).
//!
//! What `gc` never does: signal a pid (the only kill is `cgroup.kill` of a
//! leaf pinned by the inode its receipt registered), touch a cgroup recorded
//! in another boot, act while the recorded owner is alive, clean an attempt
//! whose state or receipt it cannot read, clean a foreign platform's attempt,
//! take the lease of an unclaimed root, or rewrite the supervisor's receipt
//! (S6: its own actions go to jail state and to its report).

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde_json::Value;

use crate::cleanup;
use crate::cli::GcArgs;
use crate::records::{
    ErrorCode, ErrorStage, JailError, Os, Remediation, SCHEMA_RECEIPT, rfc3339_utc,
};
use crate::state::{self, AttemptDir, AttemptId};
use crate::supervisor::{Context, GcEntry, GcReport};

/// The test seam that shrinks the per-invocation entry bound (S9).
pub const SEAM_MAX_ENTRIES: &str = "OURO_JAIL_TEST_GC_MAX_ENTRIES";

/// Largest `jail-state.json` gc reads.
const STATE_MAX: u64 = 1024 * 1024;
/// Largest `jail.json` or `policy.json` gc reads.
const RECORD_MAX: u64 = 4 * 1024 * 1024;

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
/// that is not a positive number below `default` changes nothing.
#[must_use]
pub fn seam_max_entries(value: &str, default: usize) -> usize {
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|max| (1..default).contains(max))
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// The host seam
// ---------------------------------------------------------------------------

/// Who is running `gc`: the platform identity and the current boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HostIdentity {
    /// The OS this build runs on.
    pub os: Os,
    /// The architecture string the platform records in state.
    pub arch: String,
    /// The current boot, where the platform can name one.
    pub boot_id: Option<String>,
}

/// The supervisor birth identity jail state recorded (§7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnerRecord {
    /// The pid as recorded: a number, never an address by itself.
    pub pid: u32,
    /// The boot it was recorded in.
    pub boot_id: String,
    /// Its birth time, field 22 of `/proc/<pid>/stat`.
    pub start_time_ticks: u64,
}

/// What the host says about a recorded owner in this boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Liveness {
    /// The pid names the recorded process, and it has not exited.
    Alive,
    /// No process has the pid.
    Gone,
    /// The pid names a process born at another time: the pid was reused.
    Reused,
    /// The recorded process has exited and is not yet reaped.
    Exited,
    /// Liveness could not be read; the reason says why.
    Unknown(String),
}

/// An execution cgroup as its registration names it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LeafRecord {
    /// The leaf's path as created.
    pub path: std::path::PathBuf,
    /// Its device at creation.
    pub device: u64,
    /// Its inode at creation.
    pub inode: u64,
}

/// What the host found at a recorded leaf's path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafProbe {
    /// Nothing is there.
    Absent,
    /// A cgroup with another identity is there.
    Replaced,
    /// The registration or what is there cannot be verified; why.
    Unverifiable(String),
    /// The recorded cgroup itself, and whether any process is in it.
    Identified {
        /// `populated` from its `cgroup.events` (recursive).
        populated: bool,
    },
}

/// Every host question and every host change `gc` makes.
pub trait Host {
    /// The platform and the current boot.
    fn identity(&self) -> HostIdentity;
    /// Whether the recorded owner (of this boot) is alive.
    fn owner(&self, owner: &OwnerRecord) -> Liveness;
    /// What is at the recorded leaf's path.
    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe;
    /// Re-identifies the leaf, writes its `cgroup.kill` and waits at most
    /// `budget` for it to empty.
    ///
    /// # Errors
    /// Why the leaf was not identified, killed or seen empty.
    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), String>;
    /// Re-identifies the leaf, checks it is empty and removes it (and any
    /// empty child cgroups), spending at most `entries` directory entries.
    ///
    /// # Errors
    /// Why the leaf was not identified, not empty or not removed.
    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), String>;
}

/// The host `gc` runs on: the platform's identity, and on Linux the
/// identity-checked mechanisms of `platform::linux::reconcile`.
struct NativeHost {
    identity: HostIdentity,
}

impl NativeHost {
    fn new(ctx: &Context) -> NativeHost {
        let platform = ctx.platform.identity();
        NativeHost {
            identity: HostIdentity {
                os: platform.os,
                arch: platform.arch,
                boot_id: ctx.platform.owner_identity().map(|owner| owner.boot_id),
            },
        }
    }
}

#[cfg(not(target_os = "linux"))]
const NO_MECHANISM: &str = "this platform has no execution cgroup mechanism";

impl Host for NativeHost {
    fn identity(&self) -> HostIdentity {
        self.identity.clone()
    }

    fn owner(&self, owner: &OwnerRecord) -> Liveness {
        #[cfg(target_os = "linux")]
        {
            crate::platform::linux::reconcile::owner_liveness(owner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            Liveness::Unknown("this platform reads no process birth identity".to_owned())
        }
    }

    fn probe_leaf(&self, leaf: &LeafRecord) -> LeafProbe {
        #[cfg(target_os = "linux")]
        {
            crate::platform::linux::reconcile::probe_leaf(leaf)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = leaf;
            LeafProbe::Unverifiable(NO_MECHANISM.to_owned())
        }
    }

    fn terminate_leaf(&self, leaf: &LeafRecord, budget: Duration) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            crate::platform::linux::reconcile::terminate_leaf(leaf, budget)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (leaf, budget);
            Err(NO_MECHANISM.to_owned())
        }
    }

    fn remove_leaf(&self, leaf: &LeafRecord, entries: &mut usize) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            crate::platform::linux::reconcile::remove_leaf(leaf, entries)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (leaf, entries);
            Err(NO_MECHANISM.to_owned())
        }
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

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
    // J4-R: slice R adds the report of leftover `.tmp` files a crashed
    // durable replacement left in the attempt directory here (and in
    // `main.rs`'s `gc_json`).
}

impl From<Report> for GcReport {
    fn from(report: Report) -> GcReport {
        GcReport {
            entries: report
                .entries
                .into_iter()
                .map(|entry| GcEntry {
                    attempt_id: entry.attempt_id,
                    action: entry.action,
                    reason: entry.reason,
                    proxy_dir: entry.proxy_dir,
                })
                .collect(),
            dry_run: report.dry_run,
            incomplete: report.incomplete,
        }
    }
}

// ---------------------------------------------------------------------------
// What gc reads: jail state and the last receipt, as views
// ---------------------------------------------------------------------------

/// What `gc` needs from `jail-state.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateView {
    /// The claiming platform's OS.
    pub os: String,
    /// The claiming platform's architecture.
    pub arch: String,
    /// The supervisor's birth identity; `None` where the platform had none.
    pub owner: Option<OwnerRecord>,
    /// N7 (wave 2): the execution leaf registered in state before `mkdir`.
    /// Parsed when present, not yet written by the supervisor, and not yet
    /// read by [`recorded_leaf`].
    pub leaf: Option<LeafRecord>,
    /// Leaves an earlier pass removed (`gc_removed_cgroup`).
    pub gc_removed: Vec<LeafRecord>,
    /// Whether an earlier pass removed managed scratch (`gc_removed_scratch`).
    pub gc_removed_scratch: bool,
}

/// Where a receipt says the execution leaf is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LeafSource {
    /// No leaf is registered; why.
    NotRecorded(String),
    /// The registration.
    Recorded(LeafRecord),
    /// A registration that does not have the shape the supervisor writes.
    Malformed(String),
}

/// What `gc` needs from the last receipt, `jail.json`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReceiptView {
    /// The lifecycle phase.
    pub phase: String,
    /// `lifetime.tree_empty`: `Some(true)` only after a verified tree end.
    pub tree_empty: Option<bool>,
    /// `lifetime.integrity`.
    pub integrity: String,
    /// The boot the recorded process identity names, when it names one.
    pub boot_id: Option<String>,
    /// The execution leaf from `lifetime.native.details.execution_cgroup`.
    pub leaf: LeafSource,
}

fn leaf_from(value: &Value) -> Option<LeafRecord> {
    Some(LeafRecord {
        path: value.get("path")?.as_str()?.into(),
        device: value.get("device")?.as_u64()?,
        inode: value.get("inode")?.as_u64()?,
    })
}

fn leaf_json(leaf: &LeafRecord) -> Value {
    serde_json::json!({
        "path": leaf.path,
        "device": leaf.device,
        "inode": leaf.inode,
    })
}

/// Parses jail state for the attempt named `id`.
///
/// # Errors
/// Why the state is corrupt: not JSON, another schema, another attempt, or
/// a field without the shape the supervisor writes.
pub fn parse_state(bytes: &[u8], id: &str) -> Result<StateView, String> {
    let state: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if state.get("schema").and_then(Value::as_str) != Some("ouro.jail.state/1") {
        return Err("the schema is not ouro.jail.state/1".to_owned());
    }
    if state.get("attempt_id").and_then(Value::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let text = |key: &str| {
        state
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("`{key}` is missing"))
    };
    let owner = match state.get("owner") {
        None | Some(Value::Null) => None,
        Some(owner) => Some(
            (|| {
                Some(OwnerRecord {
                    pid: u32::try_from(owner.get("pid")?.as_u64()?).ok()?,
                    boot_id: owner.get("boot_id")?.as_str()?.to_owned(),
                    start_time_ticks: owner.get("start_time_ticks")?.as_u64()?,
                })
            })()
            .ok_or("`owner` is not a birth identity")?,
        ),
    };
    let leaf = match state.get("execution_cgroup") {
        None | Some(Value::Null) => None,
        Some(value) => Some(leaf_from(value).ok_or("`execution_cgroup` is malformed")?),
    };
    let mut gc_removed = Vec::new();
    let mut gc_removed_scratch = false;
    match state.get("gc_actions") {
        None | Some(Value::Null) => {}
        Some(Value::Array(actions)) => {
            for action in actions {
                match action.get("action").and_then(Value::as_str) {
                    Some("gc_removed_cgroup") => {
                        if let Some(leaf) = action.get("execution_cgroup").and_then(leaf_from) {
                            gc_removed.push(leaf);
                        }
                    }
                    Some("gc_removed_scratch") => gc_removed_scratch = true,
                    _ => {}
                }
            }
        }
        Some(_) => return Err("`gc_actions` is not a list".to_owned()),
    }
    Ok(StateView {
        os: text("os")?,
        arch: text("arch")?,
        owner,
        leaf,
        gc_removed,
        gc_removed_scratch,
    })
}

/// Parses the last receipt of the attempt named `id`.
///
/// # Errors
/// Why the receipt is corrupt: not JSON, another schema, another attempt, or
/// no lifecycle phase.
pub fn parse_receipt(bytes: &[u8], id: &str) -> Result<ReceiptView, String> {
    let receipt: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA_RECEIPT) {
        return Err(format!("the schema is not {SCHEMA_RECEIPT}"));
    }
    if receipt.get("attempt_id").and_then(Value::as_str) != Some(id) {
        return Err("it names another attempt".to_owned());
    }
    let phase = receipt
        .get("phase")
        .and_then(Value::as_str)
        .filter(|phase| ["prepared", "enforced", "settled", "refused"].contains(phase))
        .ok_or("it has no lifecycle phase")?
        .to_owned();
    let lifetime = receipt.get("lifetime").unwrap_or(&Value::Null);
    let native = lifetime.get("native").unwrap_or(&Value::Null);
    let leaf = if native.get("os").and_then(Value::as_str) == Some("linux") {
        match native
            .get("details")
            .and_then(|details| details.get("execution_cgroup"))
        {
            None | Some(Value::Null) => {
                LeafSource::NotRecorded("the receipt registers no execution cgroup".to_owned())
            }
            Some(value) if value.get("unavailable").is_some() => LeafSource::NotRecorded(
                "the run had no execution cgroup (its receipt says unavailable)".to_owned(),
            ),
            Some(value) => leaf_from(value).map_or_else(
                || {
                    LeafSource::Malformed(
                        "the registered execution cgroup has no path, device and inode".to_owned(),
                    )
                },
                LeafSource::Recorded,
            ),
        }
    } else {
        LeafSource::NotRecorded("the receipt records no Linux lifetime details".to_owned())
    };
    Ok(ReceiptView {
        phase,
        tree_empty: lifetime.get("tree_empty").and_then(Value::as_bool),
        integrity: lifetime
            .get("integrity")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        boot_id: receipt
            .pointer("/process/identity/value/boot_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        leaf,
    })
}

/// Where the execution leaf's identity is read from.
///
/// Wave 1 reads the last receipt's `lifetime.native.details.execution_cgroup`,
/// because jail state does not register the leaf yet (N7). When the
/// supervisor registers it in state before `mkdir`, switching the source is
/// this one expression: `state.leaf.clone().map_or_else(.., LeafSource::Recorded)`.
fn recorded_leaf(_state: &StateView, receipt: Option<&ReceiptView>) -> LeafSource {
    receipt.map_or_else(
        || LeafSource::NotRecorded("no receipt was written".to_owned()),
        |receipt| receipt.leaf.clone(),
    )
}

// ---------------------------------------------------------------------------
// The decision: pure
// ---------------------------------------------------------------------------

/// Everything `gc` knows about one leased attempt when it decides.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Facts {
    /// Who is asking.
    pub host: HostIdentity,
    /// Jail state, or why it is corrupt.
    pub state: Result<StateView, String>,
    /// The last receipt (`None`: none was written), or why it is corrupt.
    pub receipt: Result<Option<ReceiptView>, String>,
    /// The owner's liveness, once [`Next::ProbeOwner`] was answered.
    pub owner: Option<Liveness>,
    /// The leaf probe, once [`Next::ProbeLeaf`] was answered.
    pub leaf: Option<LeafProbe>,
}

/// What [`decide`] needs next.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Next {
    /// Ask the host about this owner, then decide again.
    ProbeOwner(OwnerRecord),
    /// Ask the host about this leaf, then decide again.
    ProbeLeaf(LeafRecord),
    /// Done.
    Decided(Decision),
}

/// Why an attempt is retained untouched.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Retention {
    /// The report's reason.
    pub reason: String,
    /// A state or receipt that could not be read: §6.4's failed state
    /// access, so `gc` exits 1.
    pub failed_access: bool,
}

/// What may be done with the execution cgroup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CgroupStep {
    /// Nothing to do and nothing worth reporting.
    Nothing,
    /// Nothing to do; the report says this.
    Report(String),
    /// A populated, positively identified orphan of this boot: kill it
    /// through `cgroup.kill`, verify it empty, remove it.
    Terminate(LeafRecord),
    /// An empty, positively identified leaf: remove it.
    Remove(LeafRecord),
}

/// What may be done with managed scratch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScratchStep {
    /// Not gc's to decide: the supervisor verified the tree and owns its
    /// cleanup (the J3 resumption finishes it), or gc already removed it.
    NotApplicable,
    /// Kept; why.
    Keep(String),
    /// The tree's end is already established; how.
    Now(String),
    /// Removable once the cgroup step verifies the leaf empty.
    AfterCgroup,
}

/// What [`decide`] allows for one attempt.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decision {
    /// `Some`: touch nothing (and do not resume J3 cleanup either).
    pub retain: Option<Retention>,
    /// What was established about the owner, for the report.
    pub owner: Option<String>,
    /// The execution cgroup.
    pub cgroup: CgroupStep,
    /// Managed scratch.
    pub scratch: ScratchStep,
}

fn retained(reason: String, failed_access: bool, owner: Option<String>) -> Next {
    Next::Decided(Decision {
        retain: Some(Retention {
            reason,
            failed_access,
        }),
        owner,
        cgroup: CgroupStep::Nothing,
        scratch: ScratchStep::NotApplicable,
    })
}

fn decided(owner: Option<String>, cgroup: CgroupStep, scratch: ScratchStep) -> Next {
    Next::Decided(Decision {
        retain: None,
        owner,
        cgroup,
        scratch,
    })
}

/// Decides what `gc` may do with one attempt whose lease it holds.
///
/// Rules, in order; the first that applies decides:
/// 1. Corrupt jail state or receipt: retain everything, failed state access.
/// 2. Another OS or architecture claimed it: retain everything.
/// 3. No owner identity, no current boot, or records that disagree about the
///    boot: the cgroup is unverifiable and kept; J3 cleanup may resume.
/// 4. Another boot: its processes cannot be alive, and no cgroup at the
///    recorded path is the original, so no cgroup is probed or touched; the
///    tree ended with that boot.
/// 5. This boot: ask whether the owner is alive. Alive: retain everything.
///    Unknown: the cgroup is kept. Dead: go on.
/// 6. No leaf recorded, a malformed one, or lost integrity: keep.
/// 7. A leaf an earlier pass removed: done; the tree's end was verified then.
/// 8. Ask the host about the leaf. Only the recorded cgroup itself is acted
///    on: populated and not verified empty by the supervisor, terminate and
///    remove; empty, remove. Absent, replaced or unverifiable: keep.
#[must_use]
pub fn decide(facts: &Facts) -> Next {
    let state = match &facts.state {
        Ok(state) => state,
        Err(reason) => {
            return retained(
                format!(
                    "corrupt jail-state.json ({reason}): quarantined by reporting; nothing is \
                     cleaned from a state gc cannot read"
                ),
                true,
                None,
            );
        }
    };
    if state.os != facts.host.os.as_str() || state.arch != facts.host.arch {
        return retained(
            format!(
                "foreign platform: the attempt was claimed on {}/{} and this is {}/{}; its \
                 resources are retained",
                state.os,
                state.arch,
                facts.host.os.as_str(),
                facts.host.arch
            ),
            false,
            None,
        );
    }
    let receipt = match &facts.receipt {
        Ok(receipt) => receipt.as_ref(),
        Err(reason) => {
            return retained(
                format!(
                    "corrupt jail.json ({reason}): quarantined by reporting; nothing is cleaned \
                     on a receipt gc cannot read"
                ),
                true,
                None,
            );
        }
    };
    // The supervisor verified the tree's end: it owns the cleanup (J3).
    let tree_verified = receipt.is_some_and(|receipt| receipt.tree_empty == Some(true));
    let source = recorded_leaf(state, receipt);
    let recorded = matches!(source, LeafSource::Recorded(_));
    // An unverified end keeps whatever scratch exists; a reason is reported.
    let keep_scratch = |reason: &str| {
        if tree_verified {
            ScratchStep::NotApplicable
        } else {
            ScratchStep::Keep(reason.to_owned())
        }
    };
    let keep_leaf = |reason: String| {
        if recorded {
            CgroupStep::Report(format!("retained: {reason}"))
        } else {
            CgroupStep::Nothing
        }
    };

    let Some(owner) = &state.owner else {
        return decided(
            Some("unknown: jail state records no owner birth identity".to_owned()),
            keep_leaf("the owner cannot be identified".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    };
    let Some(host_boot) = &facts.host.boot_id else {
        return decided(
            Some("unknown: this host's boot identity cannot be read".to_owned()),
            keep_leaf("the boot cannot be compared".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    };
    if let Some(receipt_boot) = receipt.and_then(|receipt| receipt.boot_id.as_ref())
        && *receipt_boot != owner.boot_id
    {
        return decided(
            Some("unknown: jail state and the receipt name different boots".to_owned()),
            keep_leaf("the records disagree about the boot, so no cgroup is identified".to_owned()),
            keep_scratch("the tree's end is not verified"),
        );
    }
    if owner.boot_id != *host_boot {
        // §14.2: "After host reboot, the old processes cannot be alive, but
        // any reused cgroup path must not be treated as the original
        // resource." Nothing is asked about the leaf or the owner's pid.
        let scratch = if tree_verified || state.gc_removed_scratch {
            ScratchStep::NotApplicable
        } else {
            ScratchStep::Now("the tree ended with the boot it ran in".to_owned())
        };
        return decided(
            Some("dead: recorded in another boot".to_owned()),
            keep_leaf(
                "recorded in another boot: a cgroup at that path now is not the original \
                 resource and is never touched"
                    .to_owned(),
            ),
            scratch,
        );
    }

    let Some(liveness) = &facts.owner else {
        return Next::ProbeOwner(owner.clone());
    };
    let owner_text = match liveness {
        Liveness::Alive => {
            return retained(
                format!(
                    "the recorded supervisor (pid {}, same boot and birth time) is alive though \
                     it holds no lease; it is the only killer while it lives, so nothing is \
                     touched",
                    owner.pid
                ),
                false,
                Some("alive".to_owned()),
            );
        }
        Liveness::Unknown(reason) => {
            return decided(
                Some(format!("unknown: {reason}")),
                keep_leaf(format!("the owner's liveness is unknown ({reason})")),
                keep_scratch("the tree's end is not verified"),
            );
        }
        Liveness::Gone => "dead: no process has its pid",
        Liveness::Reused => "dead: its pid was reused (another birth time)",
        Liveness::Exited => "dead: exited, not yet reaped",
    };
    let owner_text = Some(owner_text.to_owned());

    let leaf = match source {
        LeafSource::Recorded(leaf) => leaf,
        LeafSource::NotRecorded(reason) => {
            let cgroup = if tree_verified {
                CgroupStep::Nothing
            } else {
                CgroupStep::Report(format!("not_recorded: {reason}"))
            };
            return decided(
                owner_text,
                cgroup,
                keep_scratch("no registered leaf verifies the tree's end"),
            );
        }
        LeafSource::Malformed(reason) => {
            return decided(
                owner_text,
                CgroupStep::Report(format!("retained: {reason}")),
                keep_scratch("no registered leaf verifies the tree's end"),
            );
        }
    };
    if receipt.is_some_and(|receipt| receipt.integrity == "lost") {
        return decided(
            owner_text,
            CgroupStep::Report(
                "retained: the receipt records lost boundary integrity; the leaf is kept for \
                 explicit recovery"
                    .to_owned(),
            ),
            keep_scratch("boundary integrity was lost"),
        );
    }
    if state.gc_removed.contains(&leaf) {
        let scratch = if tree_verified || state.gc_removed_scratch {
            ScratchStep::NotApplicable
        } else {
            ScratchStep::Now("an earlier gc verified the leaf empty and removed it".to_owned())
        };
        return decided(
            owner_text,
            CgroupStep::Report("removed by gc earlier".to_owned()),
            scratch,
        );
    }
    let Some(probe) = &facts.leaf else {
        return Next::ProbeLeaf(leaf);
    };
    match probe {
        LeafProbe::Absent => decided(
            owner_text,
            if tree_verified {
                CgroupStep::Nothing
            } else {
                CgroupStep::Report(
                    "absent: the recorded leaf no longer exists, so the tree's end cannot be \
                     verified through it"
                        .to_owned(),
                )
            },
            keep_scratch("the recorded leaf is gone"),
        ),
        LeafProbe::Replaced => decided(
            owner_text,
            CgroupStep::Report(
                "retained: replaced; the path names another cgroup, which is never touched"
                    .to_owned(),
            ),
            keep_scratch("the recorded leaf was replaced"),
        ),
        LeafProbe::Unverifiable(reason) => decided(
            owner_text,
            CgroupStep::Report(format!("retained: {reason}")),
            keep_scratch("the recorded leaf cannot be verified"),
        ),
        LeafProbe::Identified { populated: true } if tree_verified => decided(
            owner_text,
            CgroupStep::Report(
                "retained: populated after the supervisor verified the tree's end, so what is in \
                 it is not this attempt's orphan"
                    .to_owned(),
            ),
            ScratchStep::NotApplicable,
        ),
        LeafProbe::Identified { populated: true } => decided(
            owner_text,
            CgroupStep::Terminate(leaf),
            ScratchStep::AfterCgroup,
        ),
        LeafProbe::Identified { populated: false } => decided(
            owner_text,
            CgroupStep::Remove(leaf),
            if tree_verified {
                ScratchStep::NotApplicable
            } else {
                ScratchStep::AfterCgroup
            },
        ),
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// The per-invocation entry bound (S7).
struct Meter {
    max: usize,
    charged: usize,
}

impl Meter {
    fn remaining(&self) -> usize {
        self.max - self.charged
    }

    fn charge(&mut self, entries: usize) {
        self.charged = self.charged.saturating_add(entries).min(self.max);
    }

    /// Charges a removal that was given `given` entries. `Removal` reports
    /// what it removed, not what it visited; a completed pass visits each
    /// entry at most twice (`cleanup`'s termination argument), so twice the
    /// removals bounds it, and a pass that stopped is charged all it was
    /// given.
    fn charge_removal(&mut self, removal: &cleanup::Removal, given: usize) {
        self.charge(if removal.complete {
            removal.removed.saturating_mul(2).min(given)
        } else {
            given
        });
    }
}

fn state_access(path: &Path, detail: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Reconciling,
        Remediation::InspectState,
        format!("{}: {detail}", path.display()),
    )
}

/// `gc` on this host: the native host, [`Options::DEFAULT`] and the S9 seam.
///
/// # Errors
/// As [`gc_with`].
pub fn gc(ctx: &Context, args: &GcArgs) -> Result<Report, JailError> {
    let mut options = Options::DEFAULT;
    let mut seams = BTreeMap::new();
    if let Some(value) = std::env::var_os(SEAM_MAX_ENTRIES) {
        let value = value.to_string_lossy().into_owned();
        options.max_entries = seam_max_entries(&value, options.max_entries);
        seams.insert(SEAM_MAX_ENTRIES.to_owned(), value);
    }
    let mut report = gc_with(ctx, args, &NativeHost::new(ctx), options)?;
    report.test_seams = seams;
    Ok(report)
}

/// Enumerates the registered state root and reconciles what it may (§14.2).
///
/// # Errors
/// [`ErrorCode::UnsafeStatePath`] when the state root or `attempts/` fails
/// its checks (a symlinked `attempts/` included), and
/// [`ErrorCode::StateWriteFailed`] when `attempts/` cannot be read.
pub fn gc_with(
    ctx: &Context,
    args: &GcArgs,
    host: &dyn Host,
    options: Options,
) -> Result<Report, JailError> {
    let mut report = Report {
        entries: Vec::new(),
        dry_run: args.dry_run,
        incomplete: Vec::new(),
        budget: Budget {
            max_entries: options.max_entries,
            charged: 0,
            exhausted: false,
            listing_complete: true,
        },
        test_seams: BTreeMap::new(),
    };
    let data_dir = state::data_dir(&ctx.env_settings, ctx.home.as_deref())?;
    // §14.2 enumerates "the registered state root". A root that fails the
    // §6.2 checks is not this operator's registered state, so `gc` says so
    // instead of printing a clean scan of a directory anyone can write.
    match std::fs::symlink_metadata(&data_dir) {
        Ok(_) => state::check_state_dir(&data_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => {
            return Err(JailError::new(
                ErrorCode::UnsafeStatePath,
                ErrorStage::Resolving,
                Remediation::InspectState,
                format!("{}: {error}", data_dir.display()),
            ));
        }
    }
    let attempts = data_dir.join("attempts");
    // The same check one level down: a symlinked or foreign `attempts/` is
    // not the registered state root's, and is never followed.
    match std::fs::symlink_metadata(&attempts) {
        Ok(_) => state::check_state_dir(&attempts)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(state_access(&attempts, error)),
    }
    let listing = std::fs::read_dir(&attempts).map_err(|error| state_access(&attempts, error))?;
    let mut meter = Meter {
        max: options.max_entries,
        charged: 0,
    };
    // S7: the listing counts against the bound, and stops at it.
    let mut names: Vec<OsString> = Vec::new();
    for entry in listing {
        if meter.remaining() == 0 {
            report.budget.listing_complete = false;
            break;
        }
        meter.charge(1);
        match entry {
            Ok(entry) => names.push(entry.file_name()),
            Err(error) => report.incomplete.push(format!("attempts/ (read: {error})")),
        }
    }
    names.sort();
    for name in names {
        let entry = visit(
            &data_dir,
            &attempts,
            &name,
            host,
            options,
            args.dry_run,
            &mut meter,
            &mut report.incomplete,
        );
        report.entries.push(entry);
    }
    if !report.budget.listing_complete {
        report.incomplete.push(format!(
            "attempts/ (the per-invocation bound of {} entries ended the listing; run gc again)",
            options.max_entries
        ));
    }
    report.incomplete.sort();
    report.budget.charged = meter.charged;
    report.budget.exhausted = meter.remaining() == 0;
    Ok(report)
}

/// One name read from `attempts/`.
#[allow(clippy::too_many_arguments)]
fn visit(
    data_dir: &Path,
    attempts: &Path,
    name: &std::ffi::OsStr,
    host: &dyn Host,
    options: Options,
    dry_run: bool,
    meter: &mut Meter,
    incomplete: &mut Vec<String>,
) -> Entry {
    let display = name.to_string_lossy().into_owned();
    let mut entry = Entry {
        attempt_id: display.clone(),
        ..Entry::default()
    };
    let mut finish = |action: &str, reason: String| {
        entry.action = action.to_owned();
        entry.reason = reason;
    };
    let Some(id) = name.to_str().and_then(|text| AttemptId::parse(text).ok()) else {
        finish(
            "skipped",
            "the directory name is not an attempt id".to_owned(),
        );
        return entry;
    };
    // Never follow a link out of the state root: the entry itself must be a
    // private directory this operator owns.
    let path = attempts.join(name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            finish("skipped", format!("the entry cannot be inspected: {error}"));
            return entry;
        }
    };
    if metadata.file_type().is_symlink() {
        finish(
            "skipped",
            "a symlink, which gc never follows out of the state root".to_owned(),
        );
        return entry;
    }
    if !metadata.is_dir() {
        finish("skipped", "not a directory".to_owned());
        return entry;
    }
    {
        use std::os::unix::fs::MetadataExt as _;
        if let Err(error) = state::check_ownership(
            &path,
            metadata.uid(),
            metadata.mode() & 0o7777,
            state::DIRECTORY_MODE,
        ) {
            finish(
                "retained",
                format!("not a private attempt root: {}", error.message),
            );
            return entry;
        }
    }
    let dir = AttemptDir::new(data_dir, &id);
    // J4-G: the claim race (§7). The supervisor creates `jail.lock`, locks
    // it, and only then claims `jail-state.json`. A root without the claim is
    // never locked here: between the supervisor's create and its lock, a
    // lock taken by gc would make it refuse `attempt_exists`. A claimed root
    // was locked before it was claimed, so its lease is held by a live
    // supervisor or by nobody.
    match std::fs::symlink_metadata(dir.state_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (action, reason) = unclaimed(&dir);
            finish(action, reason);
            return entry;
        }
        _ => {}
    }
    // J4-D3: probe the lease without creating `jail.lock`.
    let lease = match state::Lease::probe_existing(&dir.lock_path()) {
        Ok(state::LeaseProbe::Acquired(lease)) => lease,
        Ok(state::LeaseProbe::Absent) => {
            let reason = match state::check_fresh_attempt(&dir) {
                Ok(()) => "no jail.lock: no lease protects this attempt".to_owned(),
                Err(error) => error.message,
            };
            finish(
                "retained",
                format!(
                    "no jail.lock, so no lease protects this attempt and gc leaves it untouched: \
                     {reason}"
                ),
            );
            return entry;
        }
        Ok(state::LeaseProbe::Held) => {
            finish("retained", "a live supervisor holds the lease".to_owned());
            return entry;
        }
        Err(error) => {
            finish("skipped", error.message);
            return entry;
        }
    };

    let facts = Facts {
        host: host.identity(),
        state: read_view(&dir.state_path(), STATE_MAX, |bytes| {
            parse_state(bytes, &display)
        })
        .and_then(|state| state.ok_or_else(|| "the file vanished".to_owned())),
        receipt: read_view(&dir.receipt_path(), RECORD_MAX, |bytes| {
            parse_receipt(bytes, &display)
        }),
        owner: None,
        leaf: None,
    };
    let decision = settle(facts, host);
    entry.owner.clone_from(&decision.owner);
    if let Some(retention) = &decision.retain {
        if retention.failed_access {
            incomplete.push(format!("{display} (corrupt_state)"));
        }
        entry.action = "retained".to_owned();
        entry.reason.clone_from(&retention.reason);
        drop(lease);
        return entry;
    }

    let done = reconcile(&dir, &decision, host, options, dry_run, meter, &mut entry);
    if let Some(failure) = &done.failure {
        incomplete.push(format!("{display} ({failure})"));
    }
    // J3: the dead supervisor's proxy directory, then vendor state.
    let (action, reason) = proxy_then_resume(&dir, &display, dry_run, incomplete, &mut entry);
    let (action, reason) = combine(action, reason, &done);
    entry.action = action;
    entry.reason = reason;
    drop(lease);
    entry
}

/// Asks [`decide`] until it decides, answering its probes from the host.
fn settle(mut facts: Facts, host: &dyn Host) -> Decision {
    loop {
        match decide(&facts) {
            Next::ProbeOwner(owner) => facts.owner = Some(host.owner(&owner)),
            Next::ProbeLeaf(leaf) => facts.leaf = Some(host.probe_leaf(&leaf)),
            Next::Decided(decision) => return decision,
        }
    }
}

/// Reads a bounded record and parses it; `Ok(None)` when it does not exist.
fn read_view<T>(
    path: &Path,
    cap: u64,
    parse: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<Option<T>, String> {
    match state::read_capped(path, cap) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => parse(&bytes).map(Some),
        Err(error) => Err(error.to_string()),
    }
}

/// The report for a root nobody has claimed (§7, §14.2; N5).
fn unclaimed(dir: &AttemptDir) -> (&'static str, String) {
    match std::fs::symlink_metadata(dir.lock_path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            "retained",
            match state::check_fresh_attempt(dir) {
                Ok(()) => "no jail.lock and no jail-owned artifact: an unclaimed attempt root, \
                           which gc leaves untouched and claimable"
                    .to_owned(),
                Err(error) => format!(
                    "no jail.lock, so no lease protects this attempt and gc leaves it untouched: {}",
                    error.message
                ),
            },
        ),
        _ => (
            "retained",
            "jail.lock but no jail-state.json: an unclaimed root, which a live supervisor may \
             be claiming now or whose supervisor died before claiming it; gc takes no lease on \
             an unclaimed root and leaves it untouched"
                .to_owned(),
        ),
    }
}

/// What [`reconcile`] did, for the entry's summary.
#[derive(Default)]
struct Done {
    /// The most significant step, as an action word: `terminated_orphan`,
    /// `removed_cgroup`, `removed_scratch` or their `would_` forms.
    action: Option<&'static str>,
    /// What failed, when something did: the cleanup is incomplete (§6.4).
    failure: Option<String>,
}

/// Performs the cgroup and scratch steps of a decision and records them.
fn reconcile(
    dir: &AttemptDir,
    decision: &Decision,
    host: &dyn Host,
    options: Options,
    dry_run: bool,
    meter: &mut Meter,
    entry: &mut Entry,
) -> Done {
    let mut done = Done::default();
    // How the tree's end was verified by this pass, when it was.
    let mut verified: Option<&'static str> = None;
    match &decision.cgroup {
        CgroupStep::Nothing => {}
        CgroupStep::Report(text) => entry.cgroup = Some(text.clone()),
        CgroupStep::Terminate(leaf) if dry_run => {
            entry.cgroup = Some("would_terminate_orphan".to_owned());
            done.action = Some("would_terminate_orphan");
        }
        CgroupStep::Remove(_) if dry_run => {
            entry.cgroup = Some("would_remove".to_owned());
            done.action = Some("would_remove_cgroup");
        }
        CgroupStep::Terminate(leaf) => {
            match terminate(dir, leaf, host, options, meter, &mut entry.recorded) {
                Ok(()) => {
                    entry.cgroup = Some("terminated_orphan_and_removed".to_owned());
                    done.action = Some("terminated_orphan");
                    verified = Some("gc ended the orphan and verified its leaf empty");
                }
                Err(failure) => {
                    entry.cgroup = Some(format!("failed: {failure}"));
                    done.failure = Some(format!("cgroup: {failure}"));
                }
            }
        }
        CgroupStep::Remove(leaf) => match remove(dir, leaf, host, meter, &mut entry.recorded) {
            Ok(()) => {
                entry.cgroup = Some("removed".to_owned());
                done.action = Some("removed_cgroup");
                verified = Some("gc verified the leaf empty and removed it");
            }
            Err(failure) => {
                entry.cgroup = Some(format!("failed: {failure}"));
                done.failure = Some(format!("cgroup: {failure}"));
            }
        },
    }
    let basis: Option<String> = match &decision.scratch {
        ScratchStep::NotApplicable => None,
        ScratchStep::Keep(reason) => {
            if managed_scratch_present(dir).is_some_and(|present| !present.is_empty()) {
                entry.scratch = Some(format!("retained: {reason}"));
            }
            None
        }
        ScratchStep::Now(basis) => Some(basis.clone()),
        ScratchStep::AfterCgroup => {
            if dry_run && done.action.is_some() {
                Some("the cgroup step would verify the tree's end".to_owned())
            } else if let Some(basis) = verified {
                Some(basis.to_owned())
            } else {
                if managed_scratch_present(dir).is_some_and(|present| !present.is_empty()) {
                    entry.scratch = Some("retained: the tree's end was not verified".to_owned());
                }
                None
            }
        }
    };
    if let Some(basis) = basis {
        remove_scratch(dir, &basis, options, dry_run, meter, entry, &mut done);
    }
    done
}

fn record(
    dir: &AttemptDir,
    action: &str,
    detail: Value,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let mut item = serde_json::json!({
        "action": action,
        "at": rfc3339_utc(SystemTime::now()),
    });
    if let (Some(item), Value::Object(detail)) = (item.as_object_mut(), detail) {
        item.extend(detail);
    }
    state::update_attempt_state(dir, |state| {
        match state.get_mut("gc_actions").and_then(Value::as_array_mut) {
            Some(actions) => actions.push(item),
            None => state["gc_actions"] = Value::Array(vec![item]),
        }
    })
    .map_err(|error| format!("jail state could not record {action}: {}", error.message))?;
    recorded.push(action.to_owned());
    Ok(())
}

/// §14.2: "Record `gc_terminated_orphan` and verify emptiness before deleting
/// state." The intent is durable before the kill, so a crash after the kill
/// never loses the fact that gc killed; the result is recorded after the leaf
/// was seen empty, and only then is the leaf removed.
fn terminate(
    dir: &AttemptDir,
    leaf: &LeafRecord,
    host: &dyn Host,
    options: Options,
    meter: &mut Meter,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let cgroup = serde_json::json!({ "execution_cgroup": leaf_json(leaf) });
    record(dir, "gc_terminating_orphan", cgroup.clone(), recorded)
        .map_err(|error| format!("{error}; nothing was killed"))?;
    host.terminate_leaf(leaf, options.kill_budget)?;
    let mut verified = cgroup;
    verified["verified_empty"] = Value::Bool(true);
    record(dir, "gc_terminated_orphan", verified, recorded)?;
    remove(dir, leaf, host, meter, recorded)
}

fn remove(
    dir: &AttemptDir,
    leaf: &LeafRecord,
    host: &dyn Host,
    meter: &mut Meter,
    recorded: &mut Vec<String>,
) -> Result<(), String> {
    let mut left = meter.remaining();
    let given = left;
    let removed = host.remove_leaf(leaf, &mut left);
    meter.charge(given - left.min(given));
    removed?;
    record(
        dir,
        "gc_removed_cgroup",
        serde_json::json!({ "execution_cgroup": leaf_json(leaf) }),
        recorded,
    )
}

/// The managed directories present, or `None` when scratch is not managed
/// (an operator `--scratch` is never deleted) or the policy is unreadable.
fn managed_scratch_present(dir: &AttemptDir) -> Option<Vec<&'static str>> {
    let bytes = state::read_capped(&dir.policy_path(), RECORD_MAX).ok()??;
    let policy: Value = serde_json::from_slice(&bytes).ok()?;
    (policy.pointer("/snapshot/roots/scratch/kind") == Some(&Value::from("managed"))).then(|| {
        ["scratch", "placeholders"]
            .into_iter()
            .filter(|name| std::fs::symlink_metadata(dir.root().join(name)).is_ok())
            .collect()
    })
}

/// §14.2: "when tree death is unverified the scratch is retained and GC may
/// remove it later." Only managed scratch and placeholders, through the
/// anchored traversal, within what is left of the entry bound.
fn remove_scratch(
    dir: &AttemptDir,
    basis: &str,
    options: Options,
    dry_run: bool,
    meter: &mut Meter,
    entry: &mut Entry,
    done: &mut Done,
) {
    let Some(present) = managed_scratch_present(dir) else {
        return;
    };
    if present.is_empty() {
        return;
    }
    if dry_run {
        entry.scratch = Some("would_remove".to_owned());
        done.action.get_or_insert("would_remove_scratch");
        return;
    }
    for name in present {
        let given = meter.remaining();
        if given == 0 {
            let reason = "pending: the per-invocation entry bound is reached".to_owned();
            done.failure
                .get_or_insert_with(|| format!("scratch: {reason}"));
            entry.scratch = Some(reason);
            return;
        }
        let removal = cleanup::remove_managed_dir(
            dir,
            name,
            cleanup::Limits {
                max_entries: given,
                max_depth: options.max_depth,
            },
        );
        meter.charge_removal(&removal, given);
        if !removal.complete {
            let reason = format!(
                "pending: {}",
                removal.reason.as_deref().unwrap_or("the removal stopped")
            );
            done.failure
                .get_or_insert_with(|| format!("scratch: {reason}"));
            entry.scratch = Some(reason);
            return;
        }
    }
    match record(
        dir,
        "gc_removed_scratch",
        serde_json::json!({ "basis": basis }),
        &mut entry.recorded,
    ) {
        Ok(()) => {
            entry.scratch = Some("removed".to_owned());
            done.action.get_or_insert("removed_scratch");
        }
        Err(failure) => {
            entry.scratch = Some(format!("removed; {failure}"));
            done.failure.get_or_insert(failure);
        }
    }
}

// J3-agent begin: `gc` of a dead supervisor's proxy directory (§14.2), moved
// here from `supervisor.rs` with the rest of gc (J4 exception G1)
/// Runs [`state::gc_proxy_dir`], says in `proxy_dir` what became of the
/// directory (one whose read or removal failed is a cleanup that did not
/// complete, §6.4: `gc` exits 1; one whose identity cannot be proven is
/// retained and said so, §14.2), then resumes the vendor-state cleanup
/// exactly as before, and maps its result to the entry's action.
fn proxy_then_resume(
    dir: &AttemptDir,
    name: &str,
    dry_run: bool,
    incomplete: &mut Vec<String>,
    entry: &mut Entry,
) -> (String, String) {
    entry.proxy_dir = match state::gc_proxy_dir(dir, dry_run) {
        Ok(outcome) => {
            if let state::ProxyDirGc::Failed(reason) = &outcome {
                incomplete.push(format!("{name} (proxy directory: {reason})"));
            }
            outcome.describe()
        }
        Err(error) => {
            incomplete.push(format!("{name} ({})", error.code.as_str()));
            Some(format!("failed: {}", error.code.as_str()))
        }
    };
    // J3-agent end
    // J3-launch begin: §12, §14.2 — resume a pending vendor-state cleanup the
    // terminal receipt permits.
    match cleanup::resume(dir, dry_run) {
        Ok(cleanup::Resume::NothingPending) => (
            "retained".to_owned(),
            "no vendor-state cleanup is pending; receipts, policy and trace are retained"
                .to_owned(),
        ),
        Ok(cleanup::Resume::Completed) => (
            "removed_vendor_state".to_owned(),
            "the pending vendor-state cleanup completed and the receipt records it".to_owned(),
        ),
        Ok(cleanup::Resume::WouldRemove) => (
            "would_remove_vendor_state".to_owned(),
            "the terminal receipt permits the pending vendor-state cleanup".to_owned(),
        ),
        Ok(cleanup::Resume::Retained(reason)) => (
            "retained".to_owned(),
            format!("vendor-state cleanup is not permitted: {reason}"),
        ),
        Ok(cleanup::Resume::StillPending(reason)) => {
            incomplete.push(format!("{name} ({reason})"));
            (
                "pending".to_owned(),
                format!("vendor-state cleanup stopped again: {reason}"),
            )
        }
        Err(error) => {
            incomplete.push(format!("{name} ({})", error.code.as_str()));
            ("skipped".to_owned(), error.message)
        }
    }
    // J3-launch end
}

/// The entry's action and reason: a failed gc step makes it `pending`; a gc
/// step that did something names the action when the J3 resumption had
/// nothing to do (`retained`), and the resumption's own reason is kept.
fn combine(action: String, reason: String, done: &Done) -> (String, String) {
    if let Some(failure) = &done.failure {
        return ("pending".to_owned(), format!("{failure}; {reason}"));
    }
    match done.action {
        Some(step) if action == "retained" => (step.to_owned(), reason),
        _ => (action, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "boot-a";

    fn host() -> HostIdentity {
        HostIdentity {
            os: Os::Linux,
            arch: "x86_64".to_owned(),
            boot_id: Some(BOOT.to_owned()),
        }
    }

    fn leaf() -> LeafRecord {
        LeafRecord {
            path: "/sys/fs/cgroup/x/ouro-att_00000000-0000-4000-8000-000000000001.leaf".into(),
            device: 1,
            inode: 2,
        }
    }

    fn state() -> StateView {
        StateView {
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
            owner: Some(OwnerRecord {
                pid: 77,
                boot_id: BOOT.to_owned(),
                start_time_ticks: 5,
            }),
            leaf: None,
            gc_removed: Vec::new(),
            gc_removed_scratch: false,
        }
    }

    fn receipt(tree_empty: Option<bool>) -> ReceiptView {
        ReceiptView {
            phase: "enforced".to_owned(),
            tree_empty,
            integrity: "verified".to_owned(),
            boot_id: Some(BOOT.to_owned()),
            leaf: LeafSource::Recorded(leaf()),
        }
    }

    fn facts(state: StateView, receipt: ReceiptView) -> Facts {
        Facts {
            host: host(),
            state: Ok(state),
            receipt: Ok(Some(receipt)),
            owner: Some(Liveness::Gone),
            leaf: Some(LeafProbe::Identified { populated: true }),
        }
    }

    fn decision(next: Next) -> Decision {
        match next {
            Next::Decided(decision) => decision,
            other => panic!("not decided: {other:?}"),
        }
    }

    #[test]
    fn only_a_dead_owners_identified_populated_unverified_leaf_is_terminated() {
        let base = facts(state(), receipt(None));
        assert_eq!(
            decision(decide(&base)).cgroup,
            CgroupStep::Terminate(leaf())
        );
        // Each precondition, removed, leaves nothing to terminate.
        let mut alive = base.clone();
        alive.owner = Some(Liveness::Alive);
        assert!(decision(decide(&alive)).retain.is_some());
        let mut verified = base.clone();
        verified.receipt = Ok(Some(receipt(Some(true))));
        assert!(matches!(
            decision(decide(&verified)).cgroup,
            CgroupStep::Report(_)
        ));
        for probe in [
            LeafProbe::Absent,
            LeafProbe::Replaced,
            LeafProbe::Unverifiable("x".to_owned()),
        ] {
            let mut other = base.clone();
            other.leaf = Some(probe);
            assert!(matches!(
                decision(decide(&other)).cgroup,
                CgroupStep::Report(_)
            ));
        }
        let mut lost = base.clone();
        let mut lost_receipt = receipt(None);
        lost_receipt.integrity = "lost".to_owned();
        lost.receipt = Ok(Some(lost_receipt));
        assert!(matches!(
            decision(decide(&lost)).cgroup,
            CgroupStep::Report(_)
        ));
    }

    #[test]
    fn nothing_is_probed_before_it_is_needed() {
        let mut unprobed = facts(state(), receipt(None));
        unprobed.owner = None;
        unprobed.leaf = None;
        assert!(matches!(decide(&unprobed), Next::ProbeOwner(_)));
        unprobed.owner = Some(Liveness::Reused);
        assert_eq!(decide(&unprobed), Next::ProbeLeaf(leaf()));
        // Another boot: neither probe, whatever the answers would be.
        let mut other_boot = facts(state(), receipt(None));
        other_boot.owner = None;
        other_boot.leaf = None;
        other_boot.host.boot_id = Some("boot-b".to_owned());
        let decided = decision(decide(&other_boot));
        assert!(matches!(decided.cgroup, CgroupStep::Report(_)));
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
    }

    #[test]
    fn disagreeing_or_missing_identities_never_reach_the_leaf() {
        let mut disagree = facts(state(), receipt(None));
        disagree.receipt = Ok(Some(ReceiptView {
            boot_id: Some("boot-b".to_owned()),
            ..receipt(None)
        }));
        assert!(matches!(
            decision(decide(&disagree)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut no_boot = facts(state(), receipt(None));
        no_boot.host.boot_id = None;
        assert!(matches!(
            decision(decide(&no_boot)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut no_owner = facts(state(), receipt(None));
        no_owner.state = Ok(StateView {
            owner: None,
            ..state()
        });
        assert!(matches!(
            decision(decide(&no_owner)).cgroup,
            CgroupStep::Report(_)
        ));
        let mut unknown = facts(state(), receipt(None));
        unknown.owner = Some(Liveness::Unknown("x".to_owned()));
        assert!(matches!(
            decision(decide(&unknown)).cgroup,
            CgroupStep::Report(_)
        ));
    }

    #[test]
    fn a_leaf_gc_removed_is_never_probed_again() {
        let mut again = facts(
            StateView {
                gc_removed: vec![leaf()],
                ..state()
            },
            receipt(None),
        );
        again.leaf = None;
        let decided = decision(decide(&again));
        assert_eq!(
            decided.cgroup,
            CgroupStep::Report("removed by gc earlier".to_owned())
        );
        assert!(matches!(decided.scratch, ScratchStep::Now(_)));
    }

    #[test]
    fn state_and_receipt_views_refuse_what_the_supervisor_does_not_write() {
        let id = "att_00000000-0000-4000-8000-000000000001";
        let good = serde_json::json!({
            "schema": "ouro.jail.state/1", "attempt_id": id, "os": "linux", "arch": "x86_64",
            "owner": {"pid": 5, "boot_id": "b", "start_time_ticks": 9},
        });
        assert!(parse_state(&serde_json::to_vec(&good).unwrap(), id).is_ok());
        for (key, value) in [
            ("schema", serde_json::json!("ouro.jail.state/2")),
            ("attempt_id", serde_json::json!("att_other")),
            ("owner", serde_json::json!({"pid": "5"})),
            (
                "owner",
                serde_json::json!({"pid": -1, "boot_id": "b", "start_time_ticks": 9}),
            ),
            ("gc_actions", serde_json::json!({})),
            ("os", Value::Null),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                parse_state(&serde_json::to_vec(&bad).unwrap(), id).is_err(),
                "{key}"
            );
        }
        let receipt = serde_json::json!({
            "schema": SCHEMA_RECEIPT, "attempt_id": id, "phase": "enforced",
            "lifetime": {"native": {"os": "linux", "details": {"execution_cgroup":
                {"path": "/p", "device": 1, "inode": 2}}}},
        });
        let view = parse_receipt(&serde_json::to_vec(&receipt).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Recorded(_)));
        let mut malformed = receipt.clone();
        malformed["lifetime"]["native"]["details"]["execution_cgroup"]["inode"] =
            serde_json::json!("2");
        let view = parse_receipt(&serde_json::to_vec(&malformed).unwrap(), id).unwrap();
        assert!(matches!(view.leaf, LeafSource::Malformed(_)));
        let mut phaseless = receipt;
        phaseless["phase"] = serde_json::json!("running");
        assert!(parse_receipt(&serde_json::to_vec(&phaseless).unwrap(), id).is_err());
    }

    #[test]
    fn the_seam_only_shrinks_the_bound() {
        assert_eq!(seam_max_entries("4", 100), 4);
        for ignored in ["0", "100", "1000", "-3", "x", ""] {
            assert_eq!(seam_max_entries(ignored, 100), 100, "{ignored:?}");
        }
    }
}
