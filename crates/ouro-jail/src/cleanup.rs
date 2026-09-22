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
}

impl Removal {
    fn stopped(reason: impl Into<String>, removed: usize) -> Removal {
        Removal {
            complete: false,
            reason: Some(reason.into()),
            removed,
            peak_held: 0,
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
    let root_stat = match anchor.stat_at(name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Removal {
                complete: true,
                reason: None,
                removed: 0,
                peak_held: 0,
            };
        }
        Err(error) => return Removal::stopped(io_reason("inspect", &error), 0),
    };
    if root_stat.kind != Kind::Directory {
        return Removal::stopped("managed_directory_replaced", 0);
    }
    if expected.is_some_and(|identity| identity != root_stat.identity()) {
        return Removal::stopped("managed_directory_replaced", 0);
    }
    if root_stat.uid != state::effective_uid() {
        return Removal::stopped("managed_directory_foreign_owner", 0);
    }
    let anchor_stat = match anchor.stat() {
        Ok(stat) => stat,
        Err(error) => return Removal::stopped(io_reason("inspect", &error), 0),
    };
    if let Some(reason) = mount_refusal(&root_stat, anchor_stat.dev) {
        return Removal::stopped(reason, 0);
    }
    let device = root_stat.dev;
    let root = match enter(anchor, name, &root_stat) {
        Ok(dir) => dir,
        Err(error) => return Removal::stopped(io_reason("open", &error), 0),
    };
    // A bound of one would hoist a directory into the directory it is in.
    let max_depth = limits.max_depth.max(2);
    let mut budget = limits.max_entries;
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
            // The name must still be the directory that was emptied.
            match parent.stat_at(&frame.name) {
                Ok(now) if now.identity() == frame.stat.identity() => {}
                Ok(_) => return Removal::stopped("managed_directory_replaced", removed),
                Err(error) => return Removal::stopped(io_reason("inspect", &error), removed),
            }
            drop(frame.dir);
            if let Err(error) = parent.rmdir_at(&frame.name) {
                return Removal::stopped(io_reason("remove directory", &error), removed);
            }
            removed += 1;
            if stack.is_empty() {
                return Removal {
                    complete: true,
                    reason: None,
                    removed,
                    peak_held,
                };
            }
            continue;
        }

        let mut descend: Option<Frame> = None;
        for entry in names {
            if budget == 0 {
                return Removal::stopped(REASON_BUDGET, removed);
            }
            budget -= 1;
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
                if let Err(error) = top.dir.rename_at(&entry, &stack[0].dir, &fresh) {
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
    }
}

/// The result of cleaning one attempt's vendor state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VendorCleanup {
    /// The status to record: `not_needed`, `pending` or `complete`.
    pub status: StateCleanup,
    /// The safe reason for `pending`.
    pub reason: Option<String>,
}

impl VendorCleanup {
    /// A `pending` result with a reason.
    #[must_use]
    pub fn pending(reason: impl Into<String>) -> VendorCleanup {
        VendorCleanup {
            status: StateCleanup::Pending,
            reason: Some(reason.into()),
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
            };
        }
        Err(error) => {
            return VendorCleanup::pending(format!("state_unreadable: {}", error.code.as_str()));
        }
    };
    let result = remove_registered(attempt_dir, registration.identity, limits);
    let recorded = state::record_cleanup(attempt_dir, result.status, result.reason.as_deref());
    match recorded {
        Ok(()) => result,
        // A `complete` that jail state does not remember is not durable yet.
        Err(error) => {
            VendorCleanup::pending(format!("state_write_failed: {}", error.code.as_str()))
        }
    }
}

fn remove_registered(
    attempt_dir: &AttemptDir,
    identity: Option<(u64, u64)>,
    limits: Limits,
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
    let removal = remove_tree_at(&attempt, &name, identity, limits);
    if !removal.complete {
        return VendorCleanup {
            status: StateCleanup::Pending,
            reason: removal.reason,
        };
    }
    if let Err(error) = attempt.sync() {
        return VendorCleanup::pending(io_reason("sync", &error));
    }
    VendorCleanup {
        status: StateCleanup::Complete,
        reason: None,
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
        return Removal::stopped(io_reason("sync", &error), removal.removed);
    }
    removal
}

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
    /// This pass completed the cleanup and recorded it.
    Completed,
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
/// receipt must prove cleanup is permitted ([`permitted_by`]); the removal is
/// the same anchored, idempotent traversal the supervisor uses. On success the
/// receipt is replaced with `state_cleanup = complete` at the next revision,
/// then jail state records `complete`: a crash between the two is found and
/// finished by the next pass, because either record still saying `pending`
/// keeps the attempt pending.
///
/// For a settled attempt the supervisor's `complete` also covers managed
/// scratch and placeholder directories, so those are removed here too, with
/// the same traversal, and only when `policy.json` says scratch was managed.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state or the receipt
/// cannot be read or replaced.
pub fn resume(attempt_dir: &AttemptDir, dry_run: bool) -> Result<Resume, JailError> {
    let Some(registration) = state::vendor_registration(attempt_dir)? else {
        return Ok(Resume::NothingPending);
    };
    let Some(mut receipt) = read_receipt(attempt_dir)? else {
        return Ok(Resume::Retained("no_terminal_receipt".to_owned()));
    };
    if registration.state_cleanup == StateCleanup::Complete
        && receipt.state_cleanup == StateCleanup::Complete
    {
        return Ok(Resume::NothingPending);
    }
    if let Err(reason) = permitted_by(&receipt) {
        return Ok(Resume::Retained(reason.to_owned()));
    }
    if dry_run {
        return Ok(Resume::WouldRemove);
    }
    let mut result = remove_registered(attempt_dir, registration.identity, Limits::DEFAULT);
    if result.status == StateCleanup::Complete
        && receipt.phase == Phase::Settled
        && scratch_is_managed(attempt_dir)
    {
        for name in ["scratch", "placeholders"] {
            let removal = remove_managed_dir(attempt_dir, name, Limits::DEFAULT);
            if !removal.complete {
                result = VendorCleanup {
                    status: StateCleanup::Pending,
                    reason: removal.reason,
                };
                break;
            }
        }
    }
    if result.status != StateCleanup::Complete {
        state::record_cleanup(attempt_dir, StateCleanup::Pending, result.reason.as_deref())?;
        return Ok(Resume::StillPending(
            result.reason.unwrap_or_else(|| "unknown".to_owned()),
        ));
    }
    if receipt.state_cleanup != StateCleanup::Complete {
        receipt.state_cleanup = StateCleanup::Complete;
        receipt.cleanup_error = None;
        receipt.revision += 1;
        receipt.updated_at = crate::records::rfc3339_utc(std::time::SystemTime::now());
        let bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| {
            JailError::new(
                ErrorCode::InternalError,
                ErrorStage::Reconciling,
                Remediation::InspectState,
                format!("the receipt could not be serialized: {error}"),
            )
        })?;
        state::replace_atomically(&attempt_dir.receipt_path(), &bytes)?;
    }
    state::record_cleanup(attempt_dir, StateCleanup::Complete, None)?;
    Ok(Resume::Completed)
}

/// Whether `path` names nothing (used by tests and diagnostics only).
#[must_use]
pub fn absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
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
