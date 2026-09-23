//! Vendor-state cleanup (jail-v1 §7, §8.1 step 9, §12, §14.2).
//!
//! "On pre-exec refusal or verified tree death, remove vendor state using
//! anchored directory traversal that does not follow symlinks or cross mount
//! boundaries. Delete a child-created link itself; never its external target.
//! Unmount any readonly credential views first. Keep `state_cleanup=pending`
//! until deletion and the relevant directory sync complete, then atomically
//! record `complete`. If no vendor state was created, use `not_needed`.
//! Attempts with unproved live trees retain state. Cleanup failure does not
//! rewrite a known child exit."
//!
//! How each sentence is met here:
//!
//! - Anchored: the traversal holds a descriptor for every directory on the
//!   current branch and touches entries only through `fstatat`, `openat`,
//!   `unlinkat` and `renameat` with a single validated component, never with a
//!   path. The vendor-state root is opened from the attempt directory with
//!   `O_NOFOLLOW` and must be the directory whose identity jail state
//!   registered.
//! - No symlink is followed: a symlink, a FIFO, a socket, a device and a hard
//!   link are all removed with `unlinkat` of the entry itself, which removes
//!   the name and never resolves it.
//! - No mount is crossed: an entry on another device, or (on Linux) one that
//!   `statx` reports as a mount root, stops the cleanup with `pending`; a
//!   directory whose mount status cannot be established is treated the same.
//! - Read-only credential views: a `bind_ro` view exists only inside the
//!   attempt's own mount namespace, which is gone once the tree is dead or the
//!   preparation was torn down, so on the host the view's mount point is an
//!   ordinary empty file. If a mount is ever found there, the mount rule above
//!   stops the cleanup instead of unmounting or descending: the source behind
//!   a view is never reachable through this code.
//! - Durable, resumable: the traversal is idempotent, the directory removal is
//!   followed by an `fsync` of the attempt directory, and only then is
//!   `complete` recorded (`jail-state.json` through the durable replacement).
//!   A crash at any point leaves `pending`, and [`resume`] (`gc`) finishes it.
//! - Bounded: one pass visits at most [`Limits::max_entries`] entries and holds
//!   at most [`Limits::max_depth`] directory descriptors. A deeper directory
//!   is renamed up to the vendor-state root and visited from there, so an
//!   arbitrarily deep tree needs no more descriptors, and a larger tree takes
//!   more passes. Reaching the entry bound leaves `pending` with a reason.
//!
//! Termination. Every visit of an entry is one of: an unlink, a hoist, or a
//! descent, and a descent is followed within `max_depth` visits by an unlink,
//! a hoist or the removal of an emptied directory. A hoisted directory lands
//! at depth two and is never hoisted again, so each entry is visited at most
//! twice; a pass that stops on its budget revisits at most `max_depth`
//! directories on its way back down in the next one. A tree of `N` entries
//! therefore finishes in at most `ceil(2 * N / (max_entries - max_depth))`
//! passes: one pass for any tree up to 49,936 entries with the defaults.
//!
//! What a same-UID child can build does not stop a pass: permissions it removes from its own directories are
//! restored (`chmod`, identity-checked) before an entry is read, unlinked from
//! or hoisted; it cannot create an entry owned by anyone else (that needs
//! `CAP_CHOWN` in the initial user namespace), an immutable or append-only
//! file (`CAP_LINUX_IMMUTABLE`), a device node (`CAP_MKNOD`), or a mount
//! that survives its own mount namespace. What can still stop one is outside
//! the child: an operator's or root's mount, attribute or ownership change,
//! and I/O errors of the filesystem itself. Each leaves `pending` with a
//! reason, and nothing is ever followed or crossed to get past it.

use std::io;
use std::path::Path;

use crate::records::{ErrorCode, ErrorStage, JailError, Phase, Receipt, Remediation, StateCleanup};
use crate::state::anchored::{Dir, Kind, Name, Stat};
use crate::state::{self, AttemptDir, VENDOR_STATE_NAME};

/// Entries one cleanup pass visits (the §9.1 scan bound, reused).
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;
/// Directory descriptors one cleanup pass holds (the §9.1 depth bound).
pub const DEFAULT_MAX_DEPTH: usize = 128;
/// Names read from a directory per `readdir` batch.
const BATCH: usize = 256;

/// The reason recorded when a pass reached its entry bound.
pub const REASON_BUDGET: &str = "cleanup_budget_exhausted";
/// The reason recorded when the tree's death was not verified.
pub const REASON_TREE_UNVERIFIED: &str = "tree_unverified";
/// The reason recorded when boundary integrity was lost.
pub const REASON_INTEGRITY_LOST: &str = "integrity_lost";
/// The reason recorded when a registered vendor-state directory has no
/// recorded identity, so nothing proves this attempt created it.
pub const REASON_IDENTITY_UNRECORDED: &str = "vendor_state_identity_unrecorded";

/// The cleanup status for an attempt that staged nothing.
#[must_use]
pub fn not_needed() -> StateCleanup {
    StateCleanup::NotNeeded
}

/// Whether this build can remove vendor state at all.
///
/// True since J3: [`remove_vendor_state`] performs the anchored removal and
/// records `complete` only after it and the directory sync succeeded.
#[must_use]
pub fn vendor_state_removal_implemented() -> bool {
    true
}

/// How much one pass may do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    /// Entries visited before the pass stops with `pending`.
    pub max_entries: usize,
    /// Directory descriptors held at once; deeper directories are hoisted.
    pub max_depth: usize,
}

impl Limits {
    /// The bounds the supervisor and `gc` use.
    pub const DEFAULT: Limits = Limits {
        max_entries: DEFAULT_MAX_ENTRIES,
        max_depth: DEFAULT_MAX_DEPTH,
    };
}

/// What one removal pass achieved.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Removal {
    /// True when the tree and its own entry are gone.
    pub complete: bool,
    /// The safe reason the pass stopped, when it did not complete.
    pub reason: Option<String>,
    /// Entries removed in this pass, the root included.
    pub removed: usize,
    /// The most directory descriptors the traversal held at once.
    pub peak_held: usize,
    // J4 W2-S begin: S7
    /// Entries this pass charged against its bound (`Limits::max_entries`):
    /// every name it read and looked at, which is what the bound counts.
    pub visited: usize,
    // J4 W2-S end
}

impl Removal {
    fn stopped(reason: impl Into<String>, removed: usize) -> Removal {
        Removal {
            complete: false,
            reason: Some(reason.into()),
            removed,
            peak_held: 0,
            visited: 0,
        }
    }
}

fn io_reason(what: &str, error: &io::Error) -> String {
    // io::Error from an anchored call carries no path, so this is safe to
    // record: the operation and the OS error, nothing the child named.
    format!("{what}: {error}")
}

/// One directory on the current branch of the traversal.
struct Frame {
    dir: Dir,
    /// Its name in the parent frame (or in the anchor for the root).
    name: Name,
    /// Its identity when it was entered.
    stat: Stat,
}

fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Whether an entry may be entered or removed without crossing a mount.
fn mount_refusal(stat: &Stat, device: u64) -> Option<&'static str> {
    if stat.dev != device {
        return Some("mount_crossing_refused");
    }
    if stat.mount_root == Some(true) {
        return Some("mount_crossing_refused");
    }
    if is_linux() && stat.kind == Kind::Directory && stat.mount_root.is_none() {
        // Linux can say whether a directory is a mount root. When it cannot
        // here, "unknown" is not "no": descending might cross a bind mount of
        // the same filesystem, which `st_dev` alone cannot see.
        return Some("mount_status_unknown");
    }
    None
}

/// Opens a directory entry, regaining access to one the child made
/// unsearchable, and makes it writable so its entries can be unlinked.
fn enter(parent: &Dir, name: &Name, stat: &Stat) -> io::Result<Dir> {
    let dir = match parent.open_dir_at(name, Some(stat)) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            parent.chmod_at(name, 0o700)?;
            parent.open_dir_at(name, Some(stat))?
        }
        Err(error) => return Err(error),
    };
    if dir.stat()?.mode & 0o700 != 0o700 {
        dir.chmod(0o700)?;
    }
    Ok(dir)
}

/// Gives the owner write and search permission on a directory entry before it
/// is renamed, and checks the entry is still the directory `stat` described.
///
/// Renaming a directory to another parent rewrites its `..` entry, which
/// needs write permission on the directory itself: a child that leaves a
/// `0500` directory at the hoisting depth would otherwise stop every pass
/// with `EACCES` (J3 review H1).
fn make_writable(parent: &Dir, name: &Name, stat: &Stat) -> io::Result<()> {
    if stat.mode & 0o700 == 0o700 {
        return Ok(());
    }
    parent.chmod_at(name, 0o700)?;
    let now = parent.stat_at(name)?;
    if now.identity() != stat.identity() || now.kind != Kind::Directory {
        return Err(io::Error::other(
            "the directory was replaced while its mode was changed",
        ));
    }
    Ok(())
}

/// Removes an emptied directory, but only while its name still is the
/// directory that was emptied: a different (empty) directory put there in the
/// meantime is not this traversal's to remove.
///
/// # Errors
/// The safe reason the removal stopped.
pub fn remove_emptied(parent: &Dir, name: &Name, expected: &Stat) -> Result<(), String> {
    match parent.stat_at(name) {
        Ok(now) if now.identity() == expected.identity() => {}
        Ok(_) => return Err("managed_directory_replaced".to_owned()),
        Err(error) => return Err(io_reason("inspect", &error)),
    }
    parent
        .rmdir_at(name)
        .map_err(|error| io_reason("remove directory", &error))
}

/// Why the root of a removal may not be touched, or `None`.
///
/// It must be a directory, be the registered one when an identity was
/// registered, be owned by this operator, and lie on the anchor's device
/// without being a mount root.
#[must_use]
pub fn root_refusal(
    root: &Stat,
    expected: Option<(u64, u64)>,
    anchor_device: u64,
    euid: u32,
) -> Option<&'static str> {
    if root.kind != Kind::Directory {
        return Some("managed_directory_replaced");
    }
    if expected.is_some_and(|identity| identity != root.identity()) {
        return Some("managed_directory_replaced");
    }
    if root.uid != euid {
        return Some("managed_directory_foreign_owner");
    }
    mount_refusal(root, anchor_device)
}

fn hoist_name(counter: &mut u64) -> io::Result<Name> {
    *counter += 1;
    Name::new(format!(".ouro-hoist-{}-{}", counter, uuid::Uuid::new_v4().simple()).as_bytes())
}

/// Removes `anchor/name` and everything beneath it (§12).
///
/// `expected` is the identity jail state registered for the root; a root that
/// is not that directory, is not a directory at all, is foreign-owned or is a
/// mount root is never touched. A root that does not exist is `complete`: an
/// absent directory has nothing left to delete, and this is what makes a
/// second pass after an interruption finish.
#[must_use]
pub fn remove_tree_at(
    anchor: &Dir,
    name: &Name,
    expected: Option<(u64, u64)>,
    limits: Limits,
) -> Removal {
    // J4 W2-S: S7 — what the pass charged against its bound, however it ends.
    let mut budget = limits.max_entries;
    let mut removal = remove_tree_within(anchor, name, expected, limits, &mut budget);
    removal.visited = limits.max_entries - budget;
    removal
}

/// [`remove_tree_at`], spending `budget`.
fn remove_tree_within(
    anchor: &Dir,
    name: &Name,
    expected: Option<(u64, u64)>,
    limits: Limits,
    budget: &mut usize,
) -> Removal {
    let root_stat = match anchor.stat_at(name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Removal {
                complete: true,
                reason: None,
                removed: 0,
                peak_held: 0,
                visited: 0,
            };
        }
        Err(error) => return Removal::stopped(io_reason("inspect", &error), 0),
    };
    let anchor_stat = match anchor.stat() {
        Ok(stat) => stat,
        Err(error) => return Removal::stopped(io_reason("inspect", &error), 0),
    };
    if let Some(reason) = root_refusal(
        &root_stat,
        expected,
        anchor_stat.dev,
        state::effective_uid(),
    ) {
        return Removal::stopped(reason, 0);
    }
    let device = root_stat.dev;
    let root = match enter(anchor, name, &root_stat) {
        Ok(dir) => dir,
        Err(error) => return Removal::stopped(io_reason("open", &error), 0),
    };
    // A bound of one would hoist a directory into the directory it is in.
    let max_depth = limits.max_depth.max(2);
    let mut removed = 0usize;
    let mut hoisted = 0u64;
    let mut stack: Vec<Frame> = vec![Frame {
        dir: root,
        name: name.clone(),
        stat: root_stat,
    }];
    let mut peak_held = 1usize;

    loop {
        let depth = stack.len();
        let Some(top) = stack.last() else { break };
        let names = match top.dir.names(BATCH) {
            Ok(names) => names,
            Err(error) => return Removal::stopped(io_reason("read directory", &error), removed),
        };
        if names.is_empty() {
            let Some(frame) = stack.pop() else { break };
            let parent = stack.last().map_or(anchor, |frame| &frame.dir);
            drop(frame.dir);
            if let Err(reason) = remove_emptied(parent, &frame.name, &frame.stat) {
                return Removal::stopped(reason, removed);
            }
            removed += 1;
            if stack.is_empty() {
                return Removal {
                    complete: true,
                    reason: None,
                    removed,
                    peak_held,
                    visited: 0,
                };
            }
            continue;
        }

        let mut descend: Option<Frame> = None;
        for entry in names {
            if *budget == 0 {
                return Removal::stopped(REASON_BUDGET, removed);
            }
            *budget -= 1;
            let stat = match top.dir.stat_at(&entry) {
                Ok(stat) => stat,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Removal::stopped(io_reason("inspect", &error), removed),
            };
            if let Some(reason) = mount_refusal(&stat, device) {
                return Removal::stopped(reason, removed);
            }
            if stat.kind != Kind::Directory {
                // A regular file, a symlink, a FIFO, a socket or a device:
                // the entry itself goes, and nothing it names is resolved.
                match top.dir.unlink_at(&entry) {
                    Ok(()) => removed += 1,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Removal::stopped(io_reason("remove entry", &error), removed);
                    }
                }
                continue;
            }
            if depth >= max_depth {
                // Too deep to hold another descriptor: move the subtree up to
                // the root, where it will be visited with a short stack.
                let fresh = match hoist_name(&mut hoisted) {
                    Ok(fresh) => fresh,
                    Err(error) => return Removal::stopped(io_reason("hoist", &error), removed),
                };
                if let Err(error) = make_writable(&top.dir, &entry, &stat)
                    .and_then(|()| top.dir.rename_at(&entry, &stack[0].dir, &fresh))
                {
                    return Removal::stopped(io_reason("hoist", &error), removed);
                }
                continue;
            }
            match enter(&top.dir, &entry, &stat) {
                Ok(dir) => {
                    descend = Some(Frame {
                        dir,
                        name: entry,
                        stat,
                    });
                    break;
                }
                Err(error) => return Removal::stopped(io_reason("open", &error), removed),
            }
        }
        if let Some(frame) = descend {
            stack.push(frame);
            peak_held = peak_held.max(stack.len());
        }
    }
    Removal {
        complete: false,
        reason: Some("traversal_ended_unexpectedly".to_owned()),
        removed,
        peak_held,
        visited: 0,
    }
}

/// The result of cleaning one attempt's vendor state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VendorCleanup {
    /// The status to record: `not_needed`, `pending` or `complete`.
    pub status: StateCleanup,
    /// The safe reason for `pending`.
    pub reason: Option<String>,
    /// J4-R: the failure to record the result in jail state, when there was
    /// one. The status is then `pending` whatever the removal did.
    pub record_error: Option<JailError>,
}

impl VendorCleanup {
    /// A `pending` result with a reason.
    #[must_use]
    pub fn pending(reason: impl Into<String>) -> VendorCleanup {
        VendorCleanup {
            status: StateCleanup::Pending,
            reason: Some(reason.into()),
            record_error: None,
        }
    }
}

/// Removes this attempt's registered vendor state and records the result.
///
/// The caller has already established that cleanup is permitted: a pre-exec
/// refusal before any boundary existed, a verified teardown, or verified tree
/// death (§12, §14.2). `complete` is recorded only after the directory entry
/// is gone and the attempt directory has been synced.
#[must_use]
pub fn remove_vendor_state(attempt_dir: &AttemptDir, limits: Limits) -> VendorCleanup {
    let registration = match state::vendor_registration(attempt_dir) {
        Ok(Some(registration)) => registration,
        Ok(None) => {
            return VendorCleanup {
                status: StateCleanup::NotNeeded,
                reason: None,
                record_error: None,
            };
        }
        Err(error) => {
            return VendorCleanup::pending(format!("state_unreadable: {}", error.code.as_str()));
        }
    };
    let result = remove_registered(attempt_dir, registration.identity, limits, &mut 0);
    let recorded = state::record_cleanup(attempt_dir, result.status, result.reason.as_deref());
    match recorded {
        Ok(()) => result,
        // A `complete` that jail state does not remember is not durable yet.
        Err(error) => VendorCleanup {
            record_error: Some(error.clone()),
            ..VendorCleanup::pending(format!("state_write_failed: {}", error.code.as_str()))
        },
    }
}

/// Removes the registered vendor-state directory; adds to `visited` the
/// entries the removal charged against `limits` (S7).
fn remove_registered(
    attempt_dir: &AttemptDir,
    identity: Option<(u64, u64)>,
    limits: Limits,
    visited: &mut usize,
) -> VendorCleanup {
    let attempt = match state::open_attempt_dir(attempt_dir) {
        Ok(dir) => dir,
        Err(error) => {
            return VendorCleanup::pending(format!("attempt_unopenable: {}", error.code.as_str()));
        }
    };
    let name = match Name::new(VENDOR_STATE_NAME.as_bytes()) {
        Ok(name) => name,
        Err(error) => return VendorCleanup::pending(io_reason("name", &error)),
    };
    // A registration without a recorded identity is never cleaned: whatever
    // stands at that name, nothing proves this attempt made it (J3 review H2).
    // An absent directory is still nothing to clean.
    let Some(identity) = identity else {
        return match attempt.stat_at(&name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => VendorCleanup {
                status: StateCleanup::Complete,
                reason: None,
                record_error: None,
            },
            _ => VendorCleanup::pending(REASON_IDENTITY_UNRECORDED),
        };
    };
    let removal = remove_tree_at(&attempt, &name, Some(identity), limits);
    *visited += removal.visited;
    if !removal.complete {
        return VendorCleanup {
            status: StateCleanup::Pending,
            reason: removal.reason,
            record_error: None,
        };
    }
    if let Err(error) = attempt.sync() {
        return VendorCleanup::pending(io_reason("sync", &error));
    }
    VendorCleanup {
        status: StateCleanup::Complete,
        reason: None,
        record_error: None,
    }
}

/// Removes one managed directory of the attempt (`scratch`, `placeholders`)
/// with the same anchored traversal, and syncs the attempt directory.
#[must_use]
pub fn remove_managed_dir(attempt_dir: &AttemptDir, name: &str, limits: Limits) -> Removal {
    let attempt = match state::open_attempt_dir(attempt_dir) {
        Ok(dir) => dir,
        Err(error) => {
            return Removal::stopped(format!("attempt_unopenable: {}", error.code.as_str()), 0);
        }
    };
    let entry = match Name::new(name.as_bytes()) {
        Ok(entry) => entry,
        Err(error) => return Removal::stopped(io_reason("name", &error), 0),
    };
    let removal = remove_tree_at(&attempt, &entry, None, limits);
    if removal.complete
        && let Err(error) = attempt.sync()
    {
        return Removal {
            visited: removal.visited,
            ..Removal::stopped(io_reason("sync", &error), removal.removed)
        };
    }
    removal
}

// J4 W2-S begin: permitted by gc's own verification
/// The reason recorded when no receipt proves anything and gc did not verify
/// the registered leaf either (a crash before any terminal receipt).
pub const REASON_NO_TERMINAL_RECEIPT: &str = "no_terminal_receipt";

/// Whether the records prove that vendor state may be deleted (§12, §14.2):
/// the receipt ([`permitted_by`]), or else `gc`'s own record that it verified
/// the registered execution leaf empty (`gc_terminated_orphan` after
/// `cgroup.kill`, or `gc_removed_cgroup`): the tree that could use the state
/// is then known dead, whatever the dead supervisor's last receipt says, and
/// even when it wrote none. Lost integrity still refuses.
///
/// # Errors
/// Returns the safe reason cleanup must wait.
pub fn permitted(receipt: Option<&Receipt>, gc_verified_leaf: bool) -> Result<(), &'static str> {
    match receipt.map(permitted_by) {
        Some(Ok(())) => Ok(()),
        Some(Err(REASON_INTEGRITY_LOST)) => Err(REASON_INTEGRITY_LOST),
        Some(Err(_)) | None if gc_verified_leaf => Ok(()),
        Some(Err(reason)) => Err(reason),
        None => Err(REASON_NO_TERMINAL_RECEIPT),
    }
}
// J4 W2-S end

/// Whether a receipt proves that vendor state may be deleted (§12, §14.2).
///
/// Permitted: a refusal before any boundary existed, a refusal after a
/// teardown that verified the tree empty, and a verified settlement. Not
/// permitted: lost integrity, an unverified tree, and any receipt that proves
/// neither (a crash before a terminal receipt). The reason names which.
///
/// # Errors
/// Returns the safe reason cleanup must wait.
pub fn permitted_by(receipt: &Receipt) -> Result<(), &'static str> {
    if receipt.lifetime.integrity == "lost" {
        return Err(REASON_INTEGRITY_LOST);
    }
    let verified_empty = receipt.lifetime.tree_empty == Some(true);
    match receipt.phase {
        Phase::Settled if verified_empty => Ok(()),
        Phase::Refused if verified_empty || receipt.lifetime.boundary == "pending" => Ok(()),
        _ => Err(REASON_TREE_UNVERIFIED),
    }
}

/// What `gc` did with one attempt's pending cleanup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Resume {
    /// No vendor state was ever registered, or its cleanup is recorded
    /// complete in both jail state and the receipt.
    NothingPending,
    /// Cleanup is not permitted yet; the reason says why.
    Retained(String),
    /// A dry run: cleanup is permitted and would run.
    WouldRemove,
    /// This pass completed the cleanup and recorded it: in jail state, and
    /// in the receipt only when the receipt itself permits the cleanup (a
    /// `refused` or `settled` receipt, [`permitted_by`]); J4 wave 3, G1.
    Completed {
        /// Whether the receipt was replaced with `state_cleanup = complete`.
        receipt_updated: bool,
    },
    /// This pass ran and stopped again; the reason says why.
    StillPending(String),
}

const RECEIPT_MAX: u64 = 4 * 1024 * 1024;

fn read_receipt(attempt_dir: &AttemptDir) -> Result<Option<Receipt>, JailError> {
    let path = attempt_dir.receipt_path();
    let failure = |detail: String| {
        JailError::new(
            ErrorCode::StateWriteFailed,
            ErrorStage::Reconciling,
            Remediation::InspectState,
            format!("{}: {detail}", path.display()),
        )
    };
    let Some(bytes) =
        state::read_capped(&path, RECEIPT_MAX).map_err(|error| failure(error.to_string()))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| failure(error.to_string()))
}

fn scratch_is_managed(attempt_dir: &AttemptDir) -> bool {
    let Ok(Some(bytes)) = state::read_capped(&attempt_dir.policy_path(), RECEIPT_MAX) else {
        return false;
    };
    let Ok(policy) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    policy["snapshot"]["roots"]["scratch"]["kind"] == "managed"
}

/// Resumes an interrupted vendor-state cleanup from jail state (§12, §14.2).
///
/// The caller holds the attempt's lease, so no live supervisor owns it. The
/// records must prove cleanup is permitted ([`permitted`]); the removal is
/// the same anchored, idempotent traversal the supervisor uses. On success a
/// receipt that itself permits the cleanup (refused or settled,
/// [`permitted_by`]) is replaced with `state_cleanup = complete` at the next
/// revision, then jail state records `complete`: a crash between the two is
/// found and finished by the next pass, because either record still saying
/// `pending` keeps the attempt pending. Permitted only by gc's own
/// verification (no receipt, or one whose phase is not refused or settled),
/// only jail state records it: gc never rewrites such a receipt (S6; J4 wave
/// 3, G1: `complete` in a `prepared` or `enforced` receipt is
/// schema-invalid).
///
/// For a settled attempt the supervisor's `complete` also covers managed
/// scratch and placeholder directories, so those are removed here too, with
/// the same traversal, and only when `policy.json` says scratch was managed.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state or the receipt
/// cannot be read or replaced.
pub fn resume(attempt_dir: &AttemptDir, dry_run: bool) -> Result<Resume, JailError> {
    resume_with(attempt_dir, dry_run, Limits::DEFAULT, false).map(|resumed| resumed.outcome)
}

// J4 W2-S begin: S7 and gc's verification
/// What [`resume_with`] did, and what it spent.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Resumed {
    /// The outcome.
    pub outcome: Resume,
    /// Entries the removals charged against the given bound (S7).
    pub visited: usize,
}

/// [`resume`] within `limits` (S7: gc passes what is left of its
/// per-invocation bound, and charges `visited` to it), and with gc's own
/// verification of the registered leaf (`gc_verified_leaf`, see
/// [`permitted`]).
///
/// # Errors
/// As [`resume`].
pub fn resume_with(
    attempt_dir: &AttemptDir,
    dry_run: bool,
    limits: Limits,
    gc_verified_leaf: bool,
) -> Result<Resumed, JailError> {
    let mut visited = 0usize;
    let outcome = resume_within(attempt_dir, dry_run, limits, gc_verified_leaf, &mut visited)?;
    Ok(Resumed { outcome, visited })
}

fn resume_within(
    attempt_dir: &AttemptDir,
    dry_run: bool,
    limits: Limits,
    gc_verified_leaf: bool,
    visited: &mut usize,
) -> Result<Resume, JailError> {
    let Some(registration) = state::vendor_registration(attempt_dir)? else {
        return Ok(Resume::NothingPending);
    };
    let mut receipt = read_receipt(attempt_dir)?;
    // J4 wave 3 (G1): only a receipt that itself permits the cleanup ever
    // records its completion; any other is the supervisor's and stays as it
    // was, so jail state alone says `complete`.
    let receipt_records = receipt
        .as_ref()
        .is_some_and(|receipt| permitted_by(receipt).is_ok());
    if registration.state_cleanup == StateCleanup::Complete
        && receipt.as_ref().is_none_or(|receipt| {
            !receipt_records || receipt.state_cleanup == StateCleanup::Complete
        })
    {
        return Ok(Resume::NothingPending);
    }
    if let Err(reason) = permitted(receipt.as_ref(), gc_verified_leaf) {
        return Ok(Resume::Retained(reason.to_owned()));
    }
    if dry_run {
        return Ok(Resume::WouldRemove);
    }
    let left = |visited: usize| Limits {
        max_entries: limits.max_entries.saturating_sub(visited),
        ..limits
    };
    let mut result = remove_registered(attempt_dir, registration.identity, limits, visited);
    if result.status == StateCleanup::Complete
        && receipt
            .as_ref()
            .is_some_and(|receipt| receipt.phase == Phase::Settled)
        && scratch_is_managed(attempt_dir)
    {
        for name in ["scratch", "placeholders"] {
            let removal = remove_managed_dir(attempt_dir, name, left(*visited));
            *visited += removal.visited;
            if !removal.complete {
                result = VendorCleanup {
                    status: StateCleanup::Pending,
                    reason: removal.reason,
                    record_error: None,
                };
                break;
            }
        }
    }
    // J4 W2-S end
    if result.status != StateCleanup::Complete {
        state::record_cleanup_at(
            state::Site::GcResume,
            attempt_dir,
            StateCleanup::Pending,
            result.reason.as_deref(),
        )?;
        return Ok(Resume::StillPending(
            result.reason.unwrap_or_else(|| "unknown".to_owned()),
        ));
    }
    if let Some(receipt) = receipt.as_mut().filter(|_| receipt_records)
        && receipt.state_cleanup != StateCleanup::Complete
    {
        receipt.state_cleanup = StateCleanup::Complete;
        receipt.cleanup_error = None;
        receipt.revision += 1;
        receipt.updated_at = crate::records::rfc3339_utc(std::time::SystemTime::now());
        let bytes = serde_json::to_vec_pretty(&*receipt).map_err(|error| {
            JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Reconciling,
                Remediation::InspectState,
                format!("the receipt could not be serialized: {error}"),
            )
        })?;
        state::replace_atomically_at(state::Site::GcResume, &attempt_dir.receipt_path(), &bytes)?;
    }
    state::record_cleanup_at(
        state::Site::GcResume,
        attempt_dir,
        StateCleanup::Complete,
        None,
    )?;
    Ok(Resume::Completed {
        receipt_updated: receipt_records,
    })
}

/// Whether `path` names nothing (used by tests and diagnostics only).
#[must_use]
pub fn absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 0700 temporary directory whatever the umask: a state root under a
    /// group-writable one is refused, rightly.
    fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("a temporary directory")
    }
    use std::os::unix::fs::PermissionsExt as _;

    fn anchor() -> (tempfile::TempDir, Dir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = Dir::open_trusted(&path).unwrap();
        (dir, anchor)
    }

    fn name(text: &str) -> Name {
        Name::new(text.as_bytes()).unwrap()
    }

    /// A chain of `depth` directories below `anchor/top`, each left with
    /// `mode` after a file is planted at the bottom: what a child can build.
    fn locked_chain(anchor: &Dir, top: &str, depth: usize, mode: u32) {
        let mut current = anchor.mkdir_at(&name(top), 0o700).unwrap();
        let mut chain = Vec::new();
        for _ in 0..depth {
            current = current.mkdir_at(&name("d"), 0o700).unwrap();
            chain.push(current.try_clone_fd().unwrap());
        }
        use std::io::Write as _;
        current
            .create_file_at(&name("stolen-copy"), 0o600)
            .unwrap()
            .write_all(b"fixture-credential-bytes")
            .unwrap();
        for fd in chain.iter().rev() {
            crate::state::anchored::fchmod(std::os::fd::AsFd::as_fd(fd), mode).unwrap();
        }
    }

    #[test]
    fn read_only_directories_at_beyond_and_below_the_hoist_depth_are_removed() {
        // J3 review H1: a child's 0500 chain at the hoisting depth stopped
        // every pass with EACCES, because renaming a directory rewrites its
        // `..` and needs write permission on it.
        for mode in [0o500, 0o100, 0o000, 0o300] {
            for depth in [1usize, 3, 4, 5, 12, 40] {
                let (root, anchor) = anchor();
                locked_chain(&anchor, "tree", depth, mode);
                let removal = remove_tree_at(
                    &anchor,
                    &name("tree"),
                    None,
                    Limits {
                        max_entries: 10_000,
                        max_depth: 4,
                    },
                );
                assert!(removal.complete, "mode {mode:o} depth {depth}: {removal:?}");
                assert!(removal.peak_held <= 4);
                assert!(absent(&root.path().canonicalize().unwrap().join("tree")));
            }
        }
    }

    #[test]
    fn the_reviewers_140_deep_read_only_trap_is_removed_in_one_default_pass() {
        let (root, anchor) = anchor();
        locked_chain(&anchor, "vs", 140, 0o500);
        let removal = remove_tree_at(&anchor, &name("vs"), None, Limits::DEFAULT);
        assert!(removal.complete, "{removal:?}");
        assert!(absent(&root.path().canonicalize().unwrap().join("vs")));
    }

    /// A deterministic generator, so a failing tree can be rebuilt.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % bound
        }
    }

    /// Builds a random tree a same-UID child could build under `base/tree`:
    /// files, symlinks out of the tree and to `/`, hard links to an outside
    /// file, and directories nested past the hoisting depth, each finally
    /// left with a random owner-permission combination. Returns the number of
    /// entries.
    fn random_tree(base: &std::path::Path, seed: u64, outside: &std::path::Path) -> usize {
        let mut rng = Lcg(seed);
        let top = base.join("tree");
        std::fs::create_dir(&top).unwrap();
        let mut dirs: Vec<(std::path::PathBuf, usize)> = vec![(top, 0)];
        let mut modes: Vec<(std::path::PathBuf, u32)> = Vec::new();
        for index in 0..400 {
            let pick = usize::try_from(rng.next(dirs.len() as u64)).unwrap();
            let (parent, depth) = dirs[pick].clone();
            let entry = parent.join(format!("e{index}"));
            match rng.next(5) {
                0 | 1 if depth < 20 => {
                    std::fs::create_dir(&entry).unwrap();
                    let mode = [0o000, 0o100, 0o300, 0o500, 0o555, 0o700]
                        [usize::try_from(rng.next(6)).unwrap()];
                    modes.push((entry.clone(), mode));
                    dirs.push((entry, depth + 1));
                }
                2 => std::fs::write(&entry, b"x").unwrap(),
                3 => {
                    let target = if rng.next(2) == 0 {
                        outside.to_path_buf()
                    } else {
                        std::path::PathBuf::from("/")
                    };
                    std::os::unix::fs::symlink(target, &entry).unwrap();
                }
                _ => std::fs::hard_link(outside.join("precious"), &entry).unwrap(),
            }
        }
        // Deepest first, so no chmod locks the way to a later one.
        for (path, mode) in modes.iter().rev() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(*mode)).unwrap();
        }
        400
    }

    #[test]
    fn any_tree_a_same_uid_child_builds_is_removed_within_the_pass_bound() {
        for seed in 1..=12u64 {
            let (root, anchor) = anchor();
            let base = root.path().canonicalize().unwrap();
            let outside = base.join("outside");
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("precious"), b"keep").unwrap();
            let entries = random_tree(&base, seed, &outside);
            let limits = Limits {
                max_entries: 64,
                max_depth: 4,
            };
            let bound = (2 * entries).div_ceil(limits.max_entries - limits.max_depth);
            let mut passes = 0usize;
            loop {
                passes += 1;
                let removal = remove_tree_at(&anchor, &name("tree"), None, limits);
                if removal.complete {
                    break;
                }
                assert_eq!(
                    removal.reason.as_deref(),
                    Some(REASON_BUDGET),
                    "seed {seed}: only the budget may stop a pass: {removal:?}"
                );
                assert!(
                    passes <= bound,
                    "seed {seed}: {passes} passes > bound {bound}"
                );
            }
            assert!(passes <= bound.max(1), "seed {seed}: {passes} > {bound}");
            assert!(absent(&base.join("tree")), "seed {seed}");
            assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"keep");
            assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
        }
    }

    #[test]
    fn an_emptied_directory_replaced_before_its_removal_is_kept() {
        // J3 review RM03: a real replacement (the directory renamed away and
        // a new empty one made at its name), not a symlink.
        let (root, anchor) = anchor();
        let base = root.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("d")).unwrap();
        let original = anchor.stat_at(&name("d")).unwrap();
        std::fs::rename(base.join("d"), base.join("moved")).unwrap();
        std::fs::create_dir(base.join("d")).unwrap();
        assert_eq!(
            remove_emptied(&anchor, &name("d"), &original).unwrap_err(),
            "managed_directory_replaced"
        );
        assert!(
            base.join("d").is_dir(),
            "the replacement is not ours to remove"
        );
        let moved = anchor.stat_at(&name("moved")).unwrap();
        assert!(remove_emptied(&anchor, &name("moved"), &moved).is_ok());
    }

    fn stat_with(kind: Kind, dev: u64, uid: u32, mount_root: Option<bool>) -> Stat {
        Stat {
            dev,
            ino: 7,
            kind,
            mode: 0o700,
            uid,
            gid: 0,
            nlink: 2,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mount_root,
        }
    }

    #[test]
    fn the_root_of_a_removal_must_be_ours_registered_and_on_the_anchor_device() {
        let good = stat_with(Kind::Directory, 1, 501, Some(false));
        assert_eq!(root_refusal(&good, Some((1, 7)), 1, 501), None);
        assert_eq!(root_refusal(&good, None, 1, 501), None);
        assert_eq!(
            root_refusal(&good, Some((1, 8)), 1, 501),
            Some("managed_directory_replaced")
        );
        assert_eq!(
            root_refusal(&stat_with(Kind::Symlink, 1, 501, Some(false)), None, 1, 501),
            Some("managed_directory_replaced")
        );
        assert_eq!(
            root_refusal(
                &stat_with(Kind::Directory, 1, 65_534, Some(false)),
                None,
                1,
                501
            ),
            Some("managed_directory_foreign_owner")
        );
        assert_eq!(
            root_refusal(
                &stat_with(Kind::Directory, 2, 501, Some(false)),
                None,
                1,
                501
            ),
            Some("mount_crossing_refused")
        );
        assert_eq!(
            root_refusal(
                &stat_with(Kind::Directory, 1, 501, Some(true)),
                None,
                1,
                501
            ),
            Some("mount_crossing_refused")
        );
    }

    fn registered_attempt(identity: Option<(u64, u64)>) -> (tempfile::TempDir, AttemptDir) {
        let dir = private_tempdir();
        let data = dir.path().canonicalize().unwrap().join("data");
        let id = crate::state::AttemptId::generate();
        let attempt = AttemptDir::new(&data, &id);
        attempt.create(&data).unwrap();
        let vendor = match identity {
            Some((dev, ino)) => serde_json::json!({
                "name": "vendor-state", "dev": dev.to_string(), "ino": ino.to_string(),
                "credentials": []
            }),
            None => serde_json::json!({
                "name": "vendor-state", "dev": null, "ino": null, "credentials": []
            }),
        };
        let state = serde_json::json!({
            "schema": "ouro.jail.state/1",
            "vendor_state": vendor,
            "state_cleanup": "pending",
        });
        crate::state::replace_atomically(
            &attempt.state_path(),
            &serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        (dir, attempt)
    }

    #[test]
    fn a_registration_without_a_recorded_identity_is_never_cleaned() {
        // J3 review H2: whatever stands at `vendor-state`, nothing proves this
        // attempt made it unless its identity was recorded.
        let (_dir, attempt) = registered_attempt(None);
        std::fs::create_dir(attempt.vendor_state_path()).unwrap();
        std::fs::write(attempt.vendor_state_path().join("precious"), b"keep").unwrap();
        let result = remove_vendor_state(&attempt, Limits::DEFAULT);
        assert_eq!(result.status, StateCleanup::Pending);
        assert_eq!(result.reason.as_deref(), Some(REASON_IDENTITY_UNRECORDED));
        assert!(attempt.vendor_state_path().join("precious").exists());

        let (_dir, attempt) = registered_attempt(None);
        let result = remove_vendor_state(&attempt, Limits::DEFAULT);
        assert_eq!(
            result.status,
            StateCleanup::Complete,
            "nothing there, nothing to clean"
        );
    }

    #[test]
    fn a_registered_identity_is_the_only_directory_removed() {
        let (_dir, attempt) = registered_attempt(Some((1, 1)));
        std::fs::create_dir(attempt.vendor_state_path()).unwrap();
        std::fs::write(attempt.vendor_state_path().join("precious"), b"keep").unwrap();
        let result = remove_vendor_state(&attempt, Limits::DEFAULT);
        assert_eq!(result.status, StateCleanup::Pending);
        assert_eq!(result.reason.as_deref(), Some("managed_directory_replaced"));
        assert!(attempt.vendor_state_path().join("precious").exists());
    }

    #[test]
    fn removal_is_implemented_and_the_empty_case_is_not_needed() {
        assert_eq!(not_needed(), StateCleanup::NotNeeded);
        assert!(vendor_state_removal_implemented());
    }

    #[test]
    fn links_are_removed_themselves_and_their_targets_survive() {
        let (root, anchor) = anchor();
        let base = root.path().canonicalize().unwrap();
        let outside = base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("precious"), b"keep").unwrap();
        let tree = base.join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("dir-link")).unwrap();
        std::os::unix::fs::symlink(outside.join("precious"), tree.join("file-link")).unwrap();
        std::fs::hard_link(outside.join("precious"), tree.join("hard-link")).unwrap();
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::os::unix::fs::symlink("/", tree.join("a/b/root-link")).unwrap();

        let removal = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(removal.complete, "{removal:?}");
        assert!(absent(&tree));
        assert_eq!(std::fs::read(outside.join("precious")).unwrap(), b"keep");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn an_unsearchable_directory_is_still_removed() {
        let (root, anchor) = anchor();
        let tree = root.path().canonicalize().unwrap().join("tree");
        std::fs::create_dir_all(tree.join("locked/inner")).unwrap();
        std::fs::write(tree.join("locked/inner/file"), b"x").unwrap();
        std::fs::set_permissions(
            tree.join("locked/inner"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::set_permissions(tree.join("locked"), std::fs::Permissions::from_mode(0o100))
            .unwrap();
        let removal = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(removal.complete, "{removal:?}");
        assert!(absent(&tree));
    }

    #[test]
    fn a_bounded_pass_stops_pending_and_a_second_pass_finishes() {
        let (root, anchor) = anchor();
        let tree = root.path().canonicalize().unwrap().join("tree");
        std::fs::create_dir(&tree).unwrap();
        for index in 0..10 {
            std::fs::write(tree.join(format!("f{index}")), b"").unwrap();
        }
        let first = remove_tree_at(
            &anchor,
            &name("tree"),
            None,
            Limits {
                max_entries: 4,
                max_depth: 8,
            },
        );
        assert!(!first.complete);
        assert_eq!(first.reason.as_deref(), Some(REASON_BUDGET));
        assert!(tree.exists(), "an interrupted pass leaves the rest");
        let second = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(second.complete, "{second:?}");
        assert!(absent(&tree));
        let third = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(third.complete, "an absent tree is complete");
    }

    #[test]
    fn a_tree_deeper_than_the_descriptor_bound_is_hoisted_and_removed() {
        let (root, anchor) = anchor();
        let tree = root.path().canonicalize().unwrap().join("tree");
        let mut deep = tree.clone();
        for _ in 0..40 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("leaf"), b"x").unwrap();
        let removal = remove_tree_at(
            &anchor,
            &name("tree"),
            None,
            Limits {
                max_entries: 10_000,
                max_depth: 4,
            },
        );
        assert!(removal.complete, "{removal:?}");
        assert!(removal.peak_held <= 4, "{removal:?}");
        assert!(absent(&tree));
    }

    /// Linux only: macOS builds deep chains in quadratic time, and its
    /// descriptor limit here is far above any depth worth building.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_tree_deeper_than_the_process_descriptor_limit_is_still_removed() {
        // Built through anchored handles, one level at a time, so the depth
        // is not bounded by PATH_MAX. One descriptor per level would need
        // 1100, above the reference host's soft limit of 1024; the hoisting
        // keeps the traversal at `max_depth` descriptors.
        let (root, anchor) = anchor();
        let mut current = anchor.mkdir_at(&name("tree"), 0o700).unwrap();
        for _ in 0..1100 {
            current = current.mkdir_at(&name("d"), 0o700).unwrap();
        }
        drop(current);
        let removal = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(removal.complete, "{removal:?}");
        assert_eq!(removal.removed, 1101);
        assert!(removal.peak_held <= DEFAULT_MAX_DEPTH, "{removal:?}");
        assert!(absent(&root.path().canonicalize().unwrap().join("tree")));
    }

    fn stat_of(kind: Kind, dev: u64, mount_root: Option<bool>) -> Stat {
        Stat {
            dev,
            ino: 7,
            kind,
            mode: 0o700,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 0,
            mtime: (0, 0),
            ctime: (0, 0),
            mount_root,
        }
    }

    #[test]
    fn no_mount_is_crossed_and_an_unknown_mount_status_is_not_no() {
        assert_eq!(
            mount_refusal(&stat_of(Kind::Directory, 2, Some(false)), 1),
            Some("mount_crossing_refused"),
            "another device"
        );
        assert_eq!(
            mount_refusal(&stat_of(Kind::Regular, 1, Some(true)), 1),
            Some("mount_crossing_refused"),
            "a bind mount of the same filesystem"
        );
        assert_eq!(
            mount_refusal(&stat_of(Kind::Directory, 1, Some(false)), 1),
            None
        );
        assert_eq!(mount_refusal(&stat_of(Kind::Regular, 1, None), 1), None);
        assert_eq!(
            mount_refusal(&stat_of(Kind::Directory, 1, None), 1),
            if cfg!(target_os = "linux") {
                Some("mount_status_unknown")
            } else {
                None
            }
        );
    }

    #[test]
    fn cleanup_waits_for_a_proof_that_no_tree_can_use_the_state() {
        let mut receipt = sample_receipt();
        receipt.phase = Phase::Settled;
        receipt.lifetime.tree_empty = Some(true);
        receipt.lifetime.integrity = "verified".into();
        assert_eq!(permitted_by(&receipt), Ok(()));
        receipt.lifetime.integrity = "lost".into();
        assert_eq!(permitted_by(&receipt), Err(REASON_INTEGRITY_LOST));
        receipt.lifetime.integrity = "verified".into();
        receipt.lifetime.tree_empty = None;
        assert_eq!(permitted_by(&receipt), Err(REASON_TREE_UNVERIFIED));
        receipt.phase = Phase::Refused;
        assert_eq!(permitted_by(&receipt), Err(REASON_TREE_UNVERIFIED));
        receipt.lifetime.boundary = "pending".into();
        assert_eq!(permitted_by(&receipt), Ok(()), "no boundary ever existed");
        receipt.phase = Phase::Enforced;
        assert_eq!(permitted_by(&receipt), Err(REASON_TREE_UNVERIFIED));
        receipt.phase = Phase::Prepared;
        assert_eq!(permitted_by(&receipt), Err(REASON_TREE_UNVERIFIED));
    }

    // J4 W2-S begin
    #[test]
    fn gcs_verification_of_the_leaf_is_proof_enough_except_after_lost_integrity() {
        let mut receipt = sample_receipt();
        receipt.phase = Phase::Enforced;
        receipt.lifetime.tree_empty = None;
        receipt.lifetime.integrity = "verified".into();
        assert_eq!(
            permitted(Some(&receipt), false),
            Err(REASON_TREE_UNVERIFIED)
        );
        assert_eq!(permitted(Some(&receipt), true), Ok(()));
        assert_eq!(permitted(None, false), Err(REASON_NO_TERMINAL_RECEIPT));
        assert_eq!(permitted(None, true), Ok(()));
        receipt.lifetime.integrity = "lost".into();
        assert_eq!(permitted(Some(&receipt), true), Err(REASON_INTEGRITY_LOST));
    }
    // J4 W2-S end

    fn sample_receipt() -> Receipt {
        use crate::observer::CoverageSummary;
        use crate::records::{
            Applied, AppliedNetwork, AttemptRecord, Containment, EvidenceMode, JailRecord,
            Lifetime, ObserveMode, Os, Outcome, PlatformRecord, PolicyRecord,
        };
        AttemptRecord {
            attempt_id: "att_00000000-0000-4000-8000-000000000001".into(),
            revision: 1,
            platform: PlatformRecord {
                os: Os::Linux,
                arch: "x86_64".into(),
                kernel: "test".into(),
            },
            jail: JailRecord {
                component: "ouro-jail".into(),
                version: "0".into(),
                backend: None,
                backend_version: None,
            },
            policy: PolicyRecord {
                name: "tool".into(),
                digest: format!("sha256:{}", "0".repeat(64)),
                observe: ObserveMode::On,
                evidence: EvidenceMode::Strict,
                requirements: Vec::new(),
                grants: Vec::new(),
            },
            containment: Containment::Enforced,
            exec_observed: true,
            argv_digest: None,
            applied: Applied {
                filesystem: None,
                network: AppliedNetwork {
                    mode: "none".into(),
                    mechanism: None,
                    allowed_hosts: Vec::new(),
                },
                syscalls: None,
                limits: Vec::new(),
                environment_names: Vec::new(),
                removed_environment_names: Vec::new(),
            },
            observer: CoverageSummary::unobserved().to_observer_record(),
            coverage: CoverageSummary::unobserved().to_coverage(),
            process: None,
            lifetime: Lifetime {
                boundary: "pid_namespace".into(),
                ..Lifetime::pending()
            },
            outcome: Outcome::pending(),
            state_cleanup: StateCleanup::Pending,
            cleanup_error: None,
            created_at: std::time::SystemTime::UNIX_EPOCH,
            updated_at: std::time::SystemTime::UNIX_EPOCH,
            errors: Vec::new(),
            credentials: Vec::new(),
        }
        .receipt(Phase::Enforced)
    }

    #[test]
    fn a_replaced_root_is_never_touched() {
        let (root, anchor) = anchor();
        let base = root.path().canonicalize().unwrap();
        std::fs::create_dir(base.join("tree")).unwrap();
        std::fs::write(base.join("tree/file"), b"x").unwrap();
        let removal = remove_tree_at(&anchor, &name("tree"), Some((1, 1)), Limits::DEFAULT);
        assert!(!removal.complete);
        assert_eq!(
            removal.reason.as_deref(),
            Some("managed_directory_replaced")
        );
        assert!(base.join("tree/file").exists());

        std::fs::remove_dir_all(base.join("tree")).unwrap();
        std::fs::create_dir(base.join("elsewhere")).unwrap();
        std::fs::write(base.join("elsewhere/file"), b"x").unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere"), base.join("tree")).unwrap();
        let removal = remove_tree_at(&anchor, &name("tree"), None, Limits::DEFAULT);
        assert!(
            !removal.complete,
            "a symlinked root is refused, not followed"
        );
        assert!(base.join("elsewhere/file").exists());
    }
}
