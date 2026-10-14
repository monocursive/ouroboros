//! Attempt state: directories, ids, the durable replacement and the lease.
//!
//! Implements jail-v1 §6.2 (state paths and their safety rules) and §7 (attempt
//! id grammar, the attempt directory layout and durable persistence).
//!
//! A successful rename alone is not a durable acknowledgment (§7), so a
//! replacement is: create a new temporary file in the same directory, write,
//! `fsync` the file, rename, then `fsync` the parent directory. The temporary
//! file is only ever renamed by [`TempWrite::commit`] (or linked by
//! [`TempWrite::publish_new`] for the exclusive claim), so an abandoned write
//! leaves the previous file untouched. Every step goes through the persistence
//! seam of [`persist`], and every write names its site (R02).

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config::EnvSettings;
use crate::records::{ErrorCode, ErrorStage, JailError, Remediation};

/// Mode for every file this tool writes under the state root (§6.2).
pub const FILE_MODE: u32 = 0o600;
/// Mode for every directory this tool creates under the state root (§6.2).
pub const DIRECTORY_MODE: u32 = 0o700;

fn unsafe_path(path: &Path, message: impl Into<String>) -> JailError {
    JailError::new(
        ErrorCode::UnsafeStatePath,
        ErrorStage::Resolving,
        Remediation::HostSetup,
        format!("{}: {}", path.display(), message.into()),
    )
}

fn write_failed(path: &Path, error: &std::io::Error) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("{}: {error}", path.display()),
    )
}

/// Resolves the configuration directory (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when neither `OURO_CONFIG_DIR` nor a
/// home directory names a location.
pub fn config_dir(settings: &EnvSettings, home: Option<&Path>) -> Result<PathBuf, JailError> {
    if let Some(dir) = &settings.config_dir {
        return Ok(dir.clone());
    }
    let home = home.ok_or_else(|| {
        unsafe_path(
            Path::new("~/.config/ouro"),
            "no home directory and no OURO_CONFIG_DIR",
        )
    })?;
    let home = crate::config::absolute_dir(crate::config::HOME_VAR, home)?;
    Ok(home.join(".config").join("ouro"))
}

/// Resolves the runtime state directory (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when neither `OURO_DATA_DIR` nor a
/// home directory names a location.
pub fn data_dir(settings: &EnvSettings, home: Option<&Path>) -> Result<PathBuf, JailError> {
    if let Some(dir) = &settings.data_dir {
        return Ok(dir.clone());
    }
    let home = home.ok_or_else(|| {
        unsafe_path(
            Path::new("~/.local/share/ouro"),
            "no home directory and no OURO_DATA_DIR",
        )
    })?;
    let home = crate::config::absolute_dir(crate::config::HOME_VAR, home)?;
    Ok(home.join(".local").join("share").join("ouro"))
}

/// Security 2026-09-29 (audit 6 F1): the settled marker's name. A
/// `--profile none` child sees the whole host, so any trusted file
/// (`config.toml`, a launch profile, a `--profile FILE` policy) that existed
/// before the end of such a run could have been written by its child. The
/// marker's own ctime is that end; later runs refuse trusted files that do
/// not postdate it.
const UNCONTAINED_SETTLED: &str = "uncontained.epoch";
/// The live markers' names are `uncontained.<attempt id>.live`: one per
/// uncontained run, written before its target is released and removed only
/// once that run's settled marker is written. While one exists, a run is in
/// progress or ended without settling, and no trusted file can be dated.
const UNCONTAINED_LIVE_PREFIX: &str = "uncontained.";
const UNCONTAINED_LIVE_SUFFIX: &str = ".live";

/// The settled marker's path under a marker directory.
#[must_use]
pub fn uncontained_settled_path(dir: &Path) -> PathBuf {
    dir.join(UNCONTAINED_SETTLED)
}

fn uncontained_live_path(dir: &Path, attempt_id: &str) -> PathBuf {
    dir.join(format!(
        "{UNCONTAINED_LIVE_PREFIX}{attempt_id}{UNCONTAINED_LIVE_SUFFIX}"
    ))
}

/// What the markers say about uncontained runs on this host.
///
/// The markers live in the data directory *and* the configuration
/// directory (review of audit 6 F1): the two are chosen independently
/// (`OURO_DATA_DIR`, `OURO_CONFIG_DIR`), and a run that shares either with
/// an uncontained one sees its markers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UncontainedEpoch {
    /// The newest settled marker's ctime: when the last uncontained run's
    /// tree was gone.
    pub settled: Option<SystemTime>,
    /// Live markers: uncontained runs in progress, or ones that ended
    /// without settling (a supervisor killed outright, a settled marker the
    /// run could not write).
    pub live: Vec<PathBuf>,
}

/// A file's ctime — the one timestamp no unprivileged process can set — as
/// a `SystemTime`, or `None` when it is out of range.
#[must_use]
pub(crate) fn ctime_of(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    let nanos = u32::try_from(metadata.ctime_nsec()).ok()?;
    let secs = u64::try_from(metadata.ctime()).ok()?;
    std::time::UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

/// Reads the markers in `dirs`.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] — fail closed, since a guard that
/// cannot see the epoch must not treat every file as newer than it — when a
/// directory or a settled marker cannot be inspected, when a settled marker
/// is not a regular file (a child can put a directory there so the run's
/// own marker cannot be written, review of audit 6 F1), or when its ctime
/// cannot be read.
pub fn uncontained_epoch(dirs: &[&Path]) -> Result<UncontainedEpoch, JailError> {
    let mut epoch = UncontainedEpoch::default();
    for dir in dirs {
        let settled = uncontained_settled_path(dir);
        match std::fs::symlink_metadata(&settled) {
            Ok(metadata) if metadata.is_file() => {
                let changed = ctime_of(&metadata)
                    .ok_or_else(|| unsafe_path(&settled, "the marker's ctime is out of range"))?;
                epoch.settled = epoch.settled.max(Some(changed));
            }
            Ok(_) => {
                return Err(unsafe_path(
                    &settled,
                    "the uncontained-run marker is not a regular file, so the end of the last \
                     `--profile none` run cannot be dated; check the trusted configuration, \
                     then remove it",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(unsafe_path(
                    &settled,
                    format!("the uncontained-run marker cannot be inspected: {error}"),
                ));
            }
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(unsafe_path(
                    dir,
                    format!("the uncontained-run markers cannot be listed: {error}"),
                ));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                unsafe_path(
                    dir,
                    format!("the uncontained-run markers cannot be listed: {error}"),
                )
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(UNCONTAINED_LIVE_PREFIX) && name.ends_with(UNCONTAINED_LIVE_SUFFIX)
            {
                epoch.live.push(entry.path());
            }
        }
    }
    epoch.live.sort();
    Ok(epoch)
}

/// The guard of one uncontained run's markers.
///
/// [`UncontainedRun::arm`] writes a live marker into every marker
/// directory before the target is released, and refuses the run when it
/// cannot. Dropping the guard — after the run's tree is gone, so no live
/// descendant can order its own writes after the marker — writes the
/// settled marker durably (its directory synced), and only then removes the
/// live one and syncs the directory again, so no crash can leave the live
/// marker gone without the settled one. A failure to settle leaves the live
/// marker in place, which later runs read as "cannot date", so the failure
/// fails closed; it is also reported on stderr, because a `Drop` cannot
/// refuse the run. Every write goes through the persistence seam at
/// [`Site::UncontainedMarker`].
pub(crate) struct UncontainedRun {
    markers: Vec<(PathBuf, PathBuf)>,
}

impl UncontainedRun {
    /// Writes this run's live marker into each of `dirs`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when a marker cannot be
    /// written: an uncontained run whose end no later run could date must
    /// not start. Markers already written are removed again.
    pub(crate) fn arm(dirs: &[&Path], attempt_id: &str) -> Result<Self, JailError> {
        let mut run = UncontainedRun {
            markers: Vec::new(),
        };
        let contents = format!("live pid={} attempt={attempt_id}\n", std::process::id());
        for dir in dirs {
            let live = uncontained_live_path(dir, attempt_id);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(DIRECTORY_MODE)
                .create(dir)
                .map_err(|error| error.to_string())
                .and_then(|()| {
                    write_marker(&live, contents.as_bytes()).map_err(|error| error.message)
                })
                .map_err(|error| {
                    // Nothing was released yet: the markers already written
                    // have nothing to settle.
                    for (_, live) in run.markers.drain(..) {
                        let _ = std::fs::remove_file(live);
                    }
                    JailError::new(
                        ErrorCode::StateWriteFailed,
                        ErrorStage::Preparing,
                        Remediation::InspectState,
                        format!(
                            "{}: the uncontained-run marker could not be written ({error}); \
                             later runs use it to refuse trusted files an uncontained child \
                             could have written",
                            live.display()
                        ),
                    )
                })?;
            run.markers.push((dir.to_path_buf(), live));
        }
        Ok(run)
    }
}

impl Drop for UncontainedRun {
    fn drop(&mut self) {
        let contents = format!(
            "settled {}\n",
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        );
        for (dir, live) in &self.markers {
            if let Err(error) = settle(dir, contents.as_bytes()) {
                eprintln!(
                    "ouro-jail: warning: the uncontained-run marker {} could not be written \
                     ({error}); {} stays in place, so later runs refuse every trusted \
                     configuration file until it is checked and the marker removed",
                    uncontained_settled_path(dir).display(),
                    live.display()
                );
                continue;
            }
            if let Err(error) = remove_marker(dir, live) {
                eprintln!(
                    "ouro-jail: warning: the live uncontained-run marker {} could not be \
                     removed durably ({error}); while it stays, later runs refuse every \
                     trusted configuration file",
                    live.display()
                );
            }
        }
    }
}

/// Writes `dir`'s settled marker, first clearing what the uncontained child
/// could have put in its way: a non-file at the marker's path, or the
/// operator's own directory made unwritable. The child is gone by now, so
/// nothing re-creates the obstacle.
fn settle(dir: &Path, contents: &[u8]) -> Result<(), String> {
    let cleared = || -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(dir)?;
        if metadata.is_dir()
            && metadata.uid() == effective_uid()
            && metadata.mode() & 0o700 != 0o700
        {
            std::fs::set_permissions(
                dir,
                std::fs::Permissions::from_mode((metadata.mode() & 0o7777) | 0o700),
            )?;
        }
        let settled = uncontained_settled_path(dir);
        match std::fs::symlink_metadata(&settled) {
            Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&settled)?,
            Ok(metadata) if !metadata.is_file() => std::fs::remove_file(&settled)?,
            _ => {}
        }
        Ok(())
    };
    cleared().map_err(|error| error.to_string())?;
    write_marker(&uncontained_settled_path(dir), contents).map_err(|error| error.message)
}

/// Replaces the marker `target` durably through the persistence seam: an
/// exclusively created temporary beside it (never a planted name or link),
/// written and synced, renamed over it, then its directory synced; a failed
/// directory sync fails the write.
fn write_marker(target: &Path, contents: &[u8]) -> Result<(), JailError> {
    let io = current_io();
    TempWrite::create_at(Site::UncontainedMarker, target, contents, &*io)?.commit()
}

/// Removes the live marker `live` from `dir` and syncs `dir`, through the
/// persistence seam, so the removal is as durable as the settled marker
/// written before it.
fn remove_marker(dir: &Path, live: &Path) -> std::io::Result<()> {
    let io = current_io();
    match io.remove(Site::UncontainedMarker, live) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    io.sync_dir(Site::UncontainedMarker, dir)
}

/// An attempt identifier: `att_` plus a UUIDv4 with the RFC 9562 variant (§7).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct AttemptId(String);

impl AttemptId {
    /// Allocates a new cryptographically random identifier.
    #[must_use]
    pub fn generate() -> Self {
        AttemptId(format!("att_{}", uuid::Uuid::new_v4()))
    }

    /// Validates a caller-supplied identifier before any path is derived (§7).
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidConfig`], a usage error, when the grammar
    /// does not match. An id is never an arbitrary directory argument.
    pub fn parse(text: &str) -> Result<Self, JailError> {
        let usage = || {
            JailError::new(
                ErrorCode::InvalidConfig,
                ErrorStage::Resolving,
                Remediation::Configuration,
                "an attempt id must be `att_` followed by a lowercase UUIDv4 \
                 with the RFC 9562 variant"
                    .to_owned(),
            )
            .with_key_path("--attempt-id")
        };
        let uuid = text.strip_prefix("att_").ok_or_else(usage)?;
        let groups: Vec<&str> = uuid.split('-').collect();
        if groups.len() != 5 {
            return Err(usage());
        }
        let lengths = [8usize, 4, 4, 4, 12];
        for (group, length) in groups.iter().zip(lengths) {
            if group.len() != length
                || !group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(usage());
            }
        }
        if !groups[2].starts_with('4') {
            return Err(usage());
        }
        if !matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b') {
            return Err(usage());
        }
        Ok(AttemptId(text.to_owned()))
    }

    /// The identifier as it appears in records.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `jail.lock`'s name inside an attempt directory.
pub const LOCK_NAME: &str = "jail.lock";
/// `jail-state.json`'s name inside an attempt directory.
pub const STATE_NAME: &str = "jail-state.json";
/// `policy.json`'s name inside an attempt directory.
pub const POLICY_NAME: &str = "policy.json";
/// The receipt's name inside an attempt directory.
pub const RECEIPT_NAME: &str = "jail.json";
/// The default trace's name inside an attempt directory.
pub const TRACE_NAME: &str = "trace.ndjson";
/// Managed scratch's name inside an attempt directory.
pub const SCRATCH_NAME: &str = "scratch";
/// The placeholder holders' name inside an attempt directory.
pub const PLACEHOLDERS_NAME: &str = "placeholders";
/// The managed directories of an attempt: removed at settlement, or by `gc`
/// once the tree's end is proven, when the attempt's scratch is managed.
pub const MANAGED_DIRS: [&str; 2] = [SCRATCH_NAME, PLACEHOLDERS_NAME];

/// The attempt directory layout of §7.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AttemptDir {
    root: PathBuf,
}

impl AttemptDir {
    /// `<data>/attempts/<attempt-id>/`.
    #[must_use]
    pub fn new(data_dir: &Path, id: &AttemptId) -> Self {
        AttemptDir {
            root: data_dir.join("attempts").join(id.as_str()),
        }
    }

    // N7
    /// The layout of the attempt rooted at `root`, as a platform that was
    /// handed the attempt directory names it.
    #[must_use]
    pub fn from_root(root: PathBuf) -> Self {
        AttemptDir { root }
    }

    /// The attempt root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `jail.lock`: the exclusive live-supervisor lease.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_NAME)
    }

    /// `jail-state.json`: identity, lifecycle and owned resources.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.root.join(STATE_NAME)
    }

    /// `policy.json`: the immutable resolved policy envelope.
    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.root.join(POLICY_NAME)
    }

    /// `jail.json`: the latest receipt.
    #[must_use]
    pub fn receipt_path(&self) -> PathBuf {
        self.root.join(RECEIPT_NAME)
    }

    /// `trace.ndjson`: the default bounded standalone event sink.
    #[must_use]
    pub fn trace_path(&self) -> PathBuf {
        self.root.join(TRACE_NAME)
    }

    /// `vendor-state/`: created only when a launch profile requires it.
    #[must_use]
    pub fn vendor_state_path(&self) -> PathBuf {
        self.root.join(VENDOR_STATE_NAME)
    }

    /// `scratch/`: the default child-writable scratch directory.
    #[must_use]
    pub fn scratch_path(&self) -> PathBuf {
        self.root.join(SCRATCH_NAME)
    }

    /// `placeholders/`: the holders of workspace paths a run masks.
    #[must_use]
    pub fn placeholders_path(&self) -> PathBuf {
        self.root.join(PLACEHOLDERS_NAME)
    }

    /// Creates the attempt root, checking every ancestor this tool owns.
    ///
    /// # Errors
    /// Returns [`ErrorCode::UnsafeStatePath`] when the state root or the
    /// attempts directory fails its symlink, ownership or mode check, and
    /// [`ErrorCode::StateWriteFailed`] when a directory cannot be created.
    pub fn create(&self, data_dir: &Path) -> Result<(), JailError> {
        create_private_dir(data_dir)?;
        let attempts = data_dir.join("attempts");
        create_private_dir(&attempts)?;
        create_private_dir(&self.root)?;
        Ok(())
    }
}

/// Creates `path` with mode 0700 when absent, then checks it (§6.2).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when creation fails and
/// [`ErrorCode::UnsafeStatePath`] when the existing directory is a symlink, is
/// not owned by this user, or is group- or world-accessible.
pub fn create_private_dir(path: &Path) -> Result<(), JailError> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|error| write_failed(path, &error))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A missing parent: create the chain, then retry this level.
            if let Some(parent) = path.parent() {
                create_private_dir(parent)?;
            }
            std::fs::create_dir(path).map_err(|error| write_failed(path, &error))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|error| write_failed(path, &error))?;
        }
        Err(error) => return Err(write_failed(path, &error)),
    }
    check_state_dir(path)
}

/// This process's effective uid.
#[must_use]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` reads this process's effective uid. It takes no
    // argument, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether an object with this mode, owner and group can be written by an
/// account other than its owner. The sticky bit is the caller's concern.
///
/// World write always counts. Group write counts unless the group is the
/// owner's private group: stock Debian and Ubuntu give every account a group
/// of its own and a umask of 002, so an operator's own directories are
/// group-writable by nobody else. The jail accepts that, as Debian's OpenSSH
/// does, only when the group is the owner's primary group, lists no member
/// but the owner, and is no other account's primary group. An account the
/// system's user database does not enumerate cannot be seen, which is the
/// same limit OpenSSH accepts.
#[must_use]
pub fn writable_by_others(mode: u32, uid: u32, gid: u32) -> bool {
    if mode & 0o002 != 0 {
        return true;
    }
    if mode & 0o020 == 0 {
        return false;
    }
    !accounts::group_is_private_to(uid, gid)
}

pub mod accounts;

/// Checks that `path` is a private directory this operator owns (§6.2).
///
/// Rejects a symlinked state root, foreign ownership and a mode that lets
/// anyone else read or write it. Every ancestor is checked too: §6.2 rejects
/// "unsafe parent replacement", and a private directory under a symlinked or
/// world-writable parent is not private.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] on any of those conditions.
pub fn check_state_dir(path: &Path) -> Result<(), JailError> {
    // The ancestor walk runs on the resolved path. `/var`, `/tmp` and `/etc`
    // are symlinks on macOS, so refusing a symlinked ancestor outright would
    // refuse every ordinary state root there; what "unsafe parent replacement"
    // really means is an ancestor that someone else can write.
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    check_state_ancestors(&resolved)?;
    check_one_dir(path)
}

/// Checks every ancestor of an already-resolved `path` (§6.2).
///
/// An ancestor may legitimately be shared (`/`, `/home`, `/tmp`), so the rule
/// is about who can replace an entry in it, not about who owns it: a directory
/// writable by others without the sticky bit lets anyone swap the next
/// component for their own, which is the "unsafe parent replacement" §6.2
/// names. `/tmp` passes because it is sticky.
///
/// The caller resolves the path first, so this walks real directories.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when an ancestor is not a directory
/// or is writable by anyone other than its owner without the sticky bit (a
/// group-writable ancestor whose group is its owner's private group is not;
/// see [`writable_by_others`]).
pub fn check_state_ancestors(path: &Path) -> Result<(), JailError> {
    let mut ancestors: Vec<&Path> = path.ancestors().skip(1).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|error| unsafe_path(ancestor, format!("cannot be inspected: {error}")))?;
        if !metadata.is_dir() {
            return Err(unsafe_path(ancestor, "is not a directory"));
        }
        let mode = mode_of(&metadata);
        // `/tmp` is group- and world-writable but sticky, which is what makes
        // it safe against replacement of entries this operator owns.
        let (owner, group) = {
            use std::os::unix::fs::MetadataExt as _;
            (metadata.uid(), metadata.gid())
        };
        if writable_by_others(mode, owner, group) && mode & 0o1000 == 0 {
            return Err(unsafe_path(
                ancestor,
                format!(
                    "has mode {mode:04o}: an ancestor writable by others without the sticky bit \
                     permits parent replacement"
                ),
            ));
        }
    }
    Ok(())
}

fn check_one_dir(path: &Path) -> Result<(), JailError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| unsafe_path(path, format!("cannot be inspected: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_path(path, "a state directory may not be a symlink"));
    }
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "is not a directory"));
    }
    check_ownership(
        path,
        owner_of(&metadata),
        mode_of(&metadata),
        DIRECTORY_MODE,
    )
}

/// Checks that a state file is a private regular file this operator owns.
///
/// Used on descriptors this tool reopens rather than creates: `jail.lock` and a
/// pre-existing `trace.ndjson` are as much state as the receipt is.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when the file is a symlink, is not a
/// regular file, is foreign-owned or is readable by anyone else.
pub fn check_state_file(path: &Path) -> Result<(), JailError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(unsafe_path(path, format!("cannot be inspected: {error}"))),
    };
    if metadata.file_type().is_symlink() {
        return Err(unsafe_path(path, "a state file may not be a symlink"));
    }
    if !metadata.is_file() {
        return Err(unsafe_path(path, "is not a regular file"));
    }
    check_ownership(path, owner_of(&metadata), mode_of(&metadata), FILE_MODE)
}

fn owner_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.uid()
}

fn mode_of(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    metadata.mode() & 0o7777
}

/// The ownership and mode predicate of §6.2, over plain values.
///
/// Taking `uid` and `mode` rather than a `std::fs::Metadata` is what makes the
/// rule testable: a test cannot `chown` a file to another user, but it can ask
/// this function about one.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when `uid` is not this operator or
/// `mode` grants anything outside `expected`.
pub fn check_ownership(path: &Path, uid: u32, mode: u32, expected: u32) -> Result<(), JailError> {
    let effective = effective_uid();
    if uid != effective {
        return Err(unsafe_path(
            path,
            format!("is owned by uid {uid} rather than this operator ({effective})"),
        ));
    }
    let permissions = mode & 0o777;
    if permissions & !expected != 0 {
        return Err(unsafe_path(
            path,
            format!("has mode {permissions:04o}; {expected:04o} or stricter is required"),
        ));
    }
    Ok(())
}

/// Reads a file that must be a private regular file, with a size cap (§7, H3).
///
/// The project `ouro.toml` is child-controlled: it can be a fifo that never
/// ends, a symlink to `/dev/zero`, or larger than memory. This opens with
/// `O_NOFOLLOW | O_NONBLOCK`, checks with `fstat` that the descriptor really is
/// a regular file, and reads at most `cap` bytes.
///
/// `Ok(None)` means the file does not exist, which is the only condition that
/// is not an error: every other failure is the caller's to report.
///
/// # Errors
/// Returns `Err(io::Error)` for a symlink, a non-regular file, an oversized
/// file or any read failure.
pub fn read_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>, std::io::Error> {
    read_capped_checked(path, cap, |_| Ok(()))
}

/// [`read_capped`], with `check` judging the open descriptor's metadata
/// before a byte is read, so an identity rule cannot be raced by a swap of
/// the path.
///
/// # Errors
/// As [`read_capped`], and whatever `check` returns.
pub fn read_capped_checked(
    path: &Path,
    cap: u64,
    check: impl FnOnce(&std::fs::Metadata) -> std::io::Result<()>,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("is {} bytes; the maximum is {cap}", metadata.len()),
        ));
    }
    check(&metadata)?;
    // `O_NONBLOCK` keeps the open from hanging on a fifo; the size check above
    // bounds a regular file, and `take` bounds anything that grows under us.
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file.take(cap + 1), &mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("grew past the {cap} byte maximum while being read"),
        ));
    }
    Ok(Some(bytes))
}

// The persistence seam (§7, §13.2, §13.3; R02)
pub mod persist;

pub use persist::{
    ABORT_AT_SEAM, CrashPoint, Installed, PERSIST_BUDGET, Pending, PersistIo, Persister, Progress,
    RealIo, SharedIo, Site, Stalled, TEST_SEAM_PREFIX, crash_point, current_io, install,
    plain_decimal, test_seams, test_seams_in, with_persist_io,
};

/// Writes every byte through the seam, one `write` at a time: a short write
/// is resumed at its offset, and an error after it is the write's error.
fn write_fully(
    io: &dyn PersistIo,
    site: Site,
    file: &mut File,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        match io.write(site, file, &bytes[written..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "the write made no progress",
                ));
            }
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A pending durable replacement: written and synced, not yet renamed.
///
/// Dropping it without [`TempWrite::commit`] leaves the target file exactly as
/// it was, which is the "either the old or the new file" property of R02, and
/// removes the temporary file. A crash leaves the temporary file behind;
/// [`leftover_temp_files`] names what it left.
pub struct TempWrite<'a> {
    temp: PathBuf,
    target: PathBuf,
    site: Site,
    committed: bool,
    io: &'a dyn PersistIo,
}

impl std::fmt::Debug for TempWrite<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempWrite")
            .field("temp", &self.temp)
            .field("target", &self.target)
            .field("site", &self.site)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

/// What an exclusive publication found (§7's claim).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Published {
    /// The complete file now exists under the target name.
    Created,
    /// The target already existed; nothing was published.
    Exists,
}

impl<'a> TempWrite<'a> {
    /// Creates the temporary file for a replacement of `target` at `site`
    /// beside it, through `io`, writes `bytes` and syncs it.
    ///
    /// The temporary file is removed on any failure here, so a failed write
    /// never leaves a partial file behind except when the process dies.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be created,
    /// written or synced.
    pub fn create_at(
        site: Site,
        target: &Path,
        bytes: &[u8],
        io: &'a dyn PersistIo,
    ) -> Result<Self, JailError> {
        let directory = target.parent().ok_or_else(|| {
            write_failed(
                target,
                &std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory"),
            )
        })?;
        let name = target
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "state".to_owned());
        // A random UUIDv4: no two writers, in this process or another, race
        // on the same temporary name, and nobody can plant it in advance.
        let temp = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
        let mut file = io
            .create_new(site, &temp)
            .map_err(|error| write_failed(&temp, &error))?;
        let pending = TempWrite {
            temp,
            target: target.to_path_buf(),
            site,
            committed: false,
            io,
        };
        write_fully(io, site, &mut file, bytes)
            .map_err(|error| write_failed(&pending.temp, &error))?;
        crash_point(site, CrashPoint::TempWritten);
        io.sync_file(site, &file)
            .map_err(|error| write_failed(&pending.temp, &error))?;
        crash_point(site, CrashPoint::TempSynced);
        Ok(pending)
    }

    /// The temporary file's path, for tests that inspect the failure window.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    fn directory(&self) -> &Path {
        self.target
            .parent()
            .expect("create_at() already established a parent")
    }

    /// Renames the temporary file over the target and syncs the directory.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the rename or the directory
    /// sync fails; a rename that is not followed by a successful directory sync
    /// is reported rather than acknowledged.
    pub fn commit(mut self) -> Result<(), JailError> {
        self.io
            .rename(self.site, &self.temp, &self.target)
            .map_err(|error| write_failed(&self.target, &error))?;
        self.committed = true;
        crash_point(self.site, CrashPoint::Renamed);
        let directory = self.directory().to_path_buf();
        self.io
            .sync_dir(self.site, &directory)
            .map_err(|error| write_failed(&directory, &error))?;
        crash_point(self.site, CrashPoint::DirSynced);
        Ok(())
    }

    /// Publishes the complete file under the target name only if nothing is
    /// there yet (§7: "Claim it with exclusive creation"), then syncs the
    /// directory.
    ///
    /// A `link` is both exclusive and atomic: the name appears with every
    /// byte already written and synced, so no reader, and no crash, can ever
    /// see a partial claim. The temporary name is then only a second link to
    /// the same file and is removed; one a crash leaves is harmless.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the link fails for a
    /// reason other than an existing target, or the directory sync fails.
    pub fn publish_new(mut self) -> Result<Published, JailError> {
        match self.io.link(self.site, &self.temp, &self.target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(Published::Exists);
            }
            Err(error) => return Err(write_failed(&self.target, &error)),
        }
        self.committed = true;
        crash_point(self.site, CrashPoint::Renamed);
        let _ = self.io.remove(self.site, &self.temp);
        let directory = self.directory().to_path_buf();
        self.io
            .sync_dir(self.site, &directory)
            .map_err(|error| write_failed(&directory, &error))?;
        crash_point(self.site, CrashPoint::DirSynced);
        Ok(Published::Created)
    }
}

impl Drop for TempWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: the target is intact either way, and a leftover
            // temporary file is visible state rather than a silent overwrite.
            let _ = self.io.remove(self.site, &self.temp);
        }
    }
}

/// Replaces `target` durably (§7) through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically(target: &Path, bytes: &[u8]) -> Result<(), JailError> {
    replace_atomically_at(Site::Unnamed, target, bytes)
}

/// [`replace_atomically`] at a named site, through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically_at(site: Site, target: &Path, bytes: &[u8]) -> Result<(), JailError> {
    let io = current_io();
    TempWrite::create_at(site, target, bytes, &*io)?.commit()
}

/// Creates `target` with `bytes` only if it does not exist, never exposing a
/// partial file (§7's claim), through this thread's seam.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn create_exclusively_at(
    site: Site,
    target: &Path,
    bytes: &[u8],
) -> Result<Published, JailError> {
    let io = current_io();
    TempWrite::create_at(site, target, bytes, &*io)?.publish_new()
}

/// The temporary files a crash left beside this attempt's records: names of
/// the form `.<record>.<uuid>.tmp` directly in the attempt root. They never
/// replaced anything (the prior file is intact), and nothing reads them.
///
/// # Errors
/// Returns the listing failure.
pub fn leftover_temp_files(attempt_dir: &AttemptDir) -> std::io::Result<Vec<String>> {
    leftover_temp_files_within(attempt_dir, usize::MAX).map(|listing| listing.names)
}

// Gc's leftovers (S7: the listing is charged)
/// [`leftover_temp_files`] reading at most `max_entries` names of the
/// attempt root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TempListing {
    /// The names found, sorted.
    pub names: Vec<String>,
    /// Names read from the attempt root (what the listing costs).
    pub read: usize,
    /// Whether every name was read before the bound.
    pub complete: bool,
}

/// [`leftover_temp_files`] within a bound of `max_entries` names read.
///
/// # Errors
/// Returns the listing failure.
pub fn leftover_temp_files_within(
    attempt_dir: &AttemptDir,
    max_entries: usize,
) -> std::io::Result<TempListing> {
    let mut names = Vec::new();
    let mut read = 0usize;
    let mut complete = true;
    for entry in std::fs::read_dir(attempt_dir.root())? {
        if read == max_entries {
            complete = false;
            break;
        }
        read += 1;
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && name.ends_with(".tmp") {
            names.push(name);
        }
    }
    names.sort();
    Ok(TempListing {
        names,
        read,
        complete,
    })
}

/// The records a durable replacement writes directly in the attempt root.
pub const ROOT_RECORDS: [&str; 3] = [STATE_NAME, POLICY_NAME, RECEIPT_NAME];

/// Whether `name` is exactly what [`TempWrite`] names the temporary file of
/// one of [`ROOT_RECORDS`]: `.<record>.<uuid>.tmp`, the uuid hyphenated.
/// Only such a name is ever removed by `gc`; anything else is reported.
#[must_use]
pub fn is_record_temp_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((record, id)) = middle.rsplit_once('.') else {
        return false;
    };
    ROOT_RECORDS.contains(&record)
        && id.len() == 36
        && uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
}

/// An exclusive advisory lease on `jail.lock` (§7).
///
/// The lock is released explicitly on drop rather than relying on the close: a
/// forked child holds every inherited `flock` until it execs, so an implicit
/// release at close is not a release at the moment the supervisor expects.
#[derive(Debug)]
pub struct Lease {
    file: File,
    path: PathBuf,
}

impl Lease {
    /// Takes the lease without blocking.
    ///
    /// Returns `Ok(None)` when another live supervisor already holds it, which
    /// the caller reports as `attempt_exists` rather than spawning again.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the lock file cannot be
    /// created or the lock call fails for a reason other than contention.
    pub fn acquire(path: &Path) -> Result<Option<Lease>, JailError> {
        // A lock file left with a wider mode, or replaced by a symlink, is not
        // this operator's private state any more (§6.2).
        check_state_file(path)?;
        // Security 2026-09-27 (audit 4 B5): the open does not follow a
        // symlink and the descriptor's own metadata is re-checked, so a
        // same-uid racer that swaps the path between the check above and
        // this open cannot have the lease taken on a foreign inode or have
        // an attacker-chosen file created through a dangling link — the
        // same re-verify [`Lease::probe_existing`] below already does.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| write_failed(path, &error))?;
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(unsafe_path(path, "is not a regular file")),
            Err(error) => return Err(write_failed(path, &error)),
        }
        Self::lock(file, path)
    }

    // `gc` probes a lease without creating its file
    /// Takes the lease of an attempt that already has a `jail.lock`, without
    /// blocking and without ever creating one (§14.2: `gc` "takes nonblocking
    /// attempt locks").
    ///
    /// [`Lease::acquire`] creates the file, which is right for the supervisor
    /// claiming a root and wrong for `gc`: a created `jail.lock` is a
    /// jail-owned artifact, so [`check_fresh_attempt`] would refuse a reserved,
    /// never-claimed root forever, and a dry run would have written to disk.
    /// The file is opened read-only, no-follow and nonblocking, and must be a
    /// regular file; opening and locking it change nothing on disk.
    ///
    /// # Errors
    /// Returns [`ErrorCode::UnsafeStatePath`] when the lock file fails its
    /// checks, and [`ErrorCode::StateWriteFailed`] when it cannot be opened or
    /// the lock call fails for a reason other than contention.
    pub fn probe_existing(path: &Path) -> Result<LeaseProbe, JailError> {
        check_state_file(path)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LeaseProbe::Absent);
            }
            Err(error) => return Err(write_failed(path, &error)),
        };
        // Checked on the open descriptor, so a file swapped in after
        // `check_state_file` is refused rather than locked.
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(unsafe_path(path, "is not a regular file")),
            Err(error) => return Err(write_failed(path, &error)),
        }
        Ok(match Self::lock(file, path)? {
            Some(lease) => LeaseProbe::Acquired(lease),
            None => LeaseProbe::Held,
        })
    }

    fn lock(file: File, path: &Path) -> Result<Option<Lease>, JailError> {
        // SAFETY: `flock` takes a valid open descriptor, which `file` owns for
        // the whole call, and an operation constant. It touches no memory.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(Some(Lease {
                file,
                path: path.to_path_buf(),
            }));
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => Ok(None),
            _ => Err(write_failed(path, &error)),
        }
    }

    /// The lock file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// What [`Lease::probe_existing`] found.
#[derive(Debug)]
pub enum LeaseProbe {
    /// There is no `jail.lock`, so there is no lease to take: the supervisor
    /// creates it before it claims a root. Nothing was created.
    Absent,
    /// A live supervisor holds the lease.
    Held,
    /// The lease was free and the caller now holds it.
    Acquired(Lease),
}

impl Drop for Lease {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still owned by `self.file` at this point,
        // and `LOCK_UN` releases the lock this process took on it.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

// ---------------------------------------------------------------------------
// J3 launch: vendor state in jail state (§7, §8.1 step 2, §12)
// ---------------------------------------------------------------------------

pub mod anchored;
pub mod mount_alias;
pub mod mountinfo;
pub mod record;

pub use record::{
    CredentialEntry, Decimal, Field, GcAction, JailState, LeafEntry, Owner, ProxyDirEntry,
    SocketEntry, VendorStateEntry,
};

use crate::records::StateCleanup;

/// The vendor-state directory's name inside an attempt directory (§7).
pub const VENDOR_STATE_NAME: &str = "vendor-state";

/// The schema identifier of `jail-state.json` (§7).
pub const SCHEMA_STATE: &str = "ouro.jail.state/1";

/// Largest `jail-state.json` this tool reads back. It writes the file itself;
/// the bound is there so a replaced file cannot grow a read without limit.
pub const STATE_FILE_MAX: u64 = 1024 * 1024;

/// What jail state records about an attempt's vendor state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VendorRegistration {
    /// The directory's `(dev, ino)`, once it has been created.
    pub identity: Option<(u64, u64)>,
    /// Cleanup progress as last recorded.
    pub state_cleanup: StateCleanup,
    /// The safe reason recorded with a `pending` status, if any.
    pub reason: Option<String>,
}

/// One staged credential's private provenance, kept in jail state only.
///
/// §12: "Source identity/paths and credential contents stay in private
/// operational state, never the receipt." This is that private state: the
/// source object's identity and size, never its path (which `policy.json`
/// already holds) and never its bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateCredential {
    /// The logical id.
    pub id: String,
    /// `copy_rw` or `bind_ro`.
    pub mode: String,
    /// Source device.
    pub source_dev: u64,
    /// Source inode.
    pub source_ino: u64,
    /// Source size at staging.
    pub source_size: u64,
    /// The content digest as staging computed it (`sha256:…`), or the null
    /// staging recorded. Audit 2026-09-25-2, S6: the receipt publishes no
    /// verifier of secret bytes (it is the artifact meant to be shared, and
    /// a plain digest is an offline guessing oracle); the operator verifies
    /// against this private record instead.
    pub content_digest: Option<String>,
}

fn state_parse_failed(detail: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("the attempt state could not be read back: {detail}"),
    )
}

/// Reads `jail-state.json` back.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the file is missing,
/// unreadable, oversized, a symlink, not JSON or of another shape than the
/// one this tool writes.
pub fn read_attempt_state(attempt_dir: &AttemptDir) -> Result<JailState, JailError> {
    let path = attempt_dir.state_path();
    let bytes = read_capped(&path, STATE_FILE_MAX)
        .map_err(state_parse_failed)?
        .ok_or_else(|| state_parse_failed("the file is absent"))?;
    JailState::parse(&bytes).map_err(state_parse_failed)
}

/// Read-modify-write of `jail-state.json` through the durable replacement.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be read,
/// parsed or durably replaced, or names another schema.
pub fn update_attempt_state(
    site: Site,
    attempt_dir: &AttemptDir,
    change: impl FnOnce(&mut JailState),
) -> Result<(), JailError> {
    let mut state = read_attempt_state(attempt_dir)?;
    if state.schema.get().map(String::as_str) != Some(SCHEMA_STATE) {
        return Err(state_parse_failed(format!(
            "the schema is not {SCHEMA_STATE}"
        )));
    }
    change(&mut state);
    let bytes = state.to_bytes().map_err(state_parse_failed)?;
    replace_atomically_at(site, &attempt_dir.state_path(), &bytes)
}

/// What jail state says about vendor state, or `None` when none was ever
/// registered.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state cannot be read, and
/// when it names vendor state with a cleanup status it cannot parse.
pub fn vendor_registration(
    attempt_dir: &AttemptDir,
) -> Result<Option<VendorRegistration>, JailError> {
    let state = read_attempt_state(attempt_dir)?;
    let Some(vendor) = state.vendor_state.get() else {
        return Ok(None);
    };
    let state_cleanup = match state.state_cleanup.get() {
        Some(status @ (StateCleanup::Pending | StateCleanup::Complete)) => *status,
        // Registered vendor state is never `not_needed`; no status at all is
        // a state file this tool did not write.
        other => {
            return Err(state_parse_failed(format!(
                "vendor state is registered with cleanup status {other:?}"
            )));
        }
    };
    Ok(Some(VendorRegistration {
        identity: vendor.identity(),
        state_cleanup,
        reason: state.cleanup_reason.get().cloned(),
    }))
}

/// Opens this attempt's directory as the anchor for vendor-state work.
///
/// The attempt directory is operator state (§6.2): it must be a directory this
/// operator owns, mode 0700 or stricter, and not a symlink.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] when it is not.
pub fn open_attempt_dir(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    let root = attempt_dir.root();
    let dir = anchored::Dir::open_trusted(root)
        .map_err(|error| unsafe_path(root, format!("cannot be opened: {error}")))?;
    let stat = dir
        .stat()
        .map_err(|error| unsafe_path(root, format!("cannot be inspected: {error}")))?;
    check_ownership(root, stat.uid, stat.mode, DIRECTORY_MODE)?;
    Ok(dir)
}

/// A directory of the attempt that jail state registers before it is
/// created (§7: vendor state, §10: the proxy directory).
pub(crate) struct Registration {
    /// Its name in the attempt directory.
    pub name: &'static str,
    /// What it is, for the refusal when something is already there.
    pub what: &'static str,
    /// Writes the registration, its identity null, before `mkdirat`.
    pub register: fn(&mut JailState),
    /// Records the created directory's `(dev, ino)`.
    pub identify: fn(&mut JailState, (u64, u64)),
    /// Withdraws a registration whose directory this attempt did not make.
    pub withdraw: fn(&mut JailState),
}

/// Registers a directory in jail state, then creates it mode 0700, then
/// records its identity and syncs the attempt directory (§7).
///
/// The registration is durable before `mkdirat` runs, so a crash between
/// the two leaves a registered, absent directory, which cleanup treats as
/// removed, never an unregistered directory nobody will clean. The identity
/// is recorded before anything else can fail: nothing removes a registered
/// directory whose identity was not recorded. Something already there is
/// not this attempt's, and nothing created means nothing to clean: either
/// way the registration is withdrawn, so no later cleanup can remove what
/// this attempt did not make (J3 review H2). An entry this call may have
/// made (a failure after `mkdirat`) stays registered with no identity,
/// which cleanup retains rather than deletes. `between` runs once the
/// registration is durable and before the directory exists.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when a state write or the creation
/// fails, [`ErrorCode::UnsafeStatePath`] when the attempt directory fails
/// its checks or the name already exists.
pub(crate) fn create_registered_dir(
    attempt_dir: &AttemptDir,
    registration: &Registration,
    between: &mut dyn FnMut(&AttemptDir),
) -> Result<anchored::Dir, JailError> {
    let path = attempt_dir.root().join(registration.name);
    update_attempt_state(Site::LaunchState, attempt_dir, registration.register)?;
    between(attempt_dir);
    let attempt = open_attempt_dir(attempt_dir)?;
    let name = anchored::Name::new(registration.name.as_bytes())
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    let dir = match attempt.mkdir_at(&name, DIRECTORY_MODE) {
        Ok(dir) => dir,
        Err(error) => {
            let exists = error.kind() == std::io::ErrorKind::AlreadyExists;
            if exists || attempt.stat_at(&name).is_err() {
                update_attempt_state(Site::LaunchState, attempt_dir, registration.withdraw)?;
            }
            return Err(if exists {
                unsafe_path(
                    &path,
                    format!(
                        "already exists in a fresh attempt; it is not this attempt's {}",
                        registration.what
                    ),
                )
            } else {
                write_failed(&path, &error)
            });
        }
    };
    let identity = dir
        .stat()
        .map_err(|error| write_failed(&path, &error))?
        .identity();
    update_attempt_state(Site::LaunchState, attempt_dir, |state| {
        (registration.identify)(state, identity);
    })?;
    attempt
        .sync()
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    Ok(dir)
}

/// How vendor state is registered (§7, §12): "Register vendor state before
/// the first copy, create it mode 0700", its cleanup `pending` from then on.
const VENDOR_STATE_REGISTRATION: Registration = Registration {
    name: VENDOR_STATE_NAME,
    what: "vendor state",
    register: |state| {
        state.vendor_state = Field::Set(VendorStateEntry {
            name: Field::Set(VENDOR_STATE_NAME.to_owned()),
            registered_at: Field::Set(crate::records::rfc3339_utc(SystemTime::now())),
            dev: Field::Null,
            ino: Field::Null,
            credentials: Field::Set(Vec::new()),
            rest: serde_json::Map::new(),
        });
        state.state_cleanup = Field::Set(StateCleanup::Pending);
        state.cleanup_reason = Field::Null;
    },
    identify: |state, (dev, ino)| {
        let vendor = state.vendor_state.get_or_insert_default();
        vendor.dev = Field::Set(Decimal(dev));
        vendor.ino = Field::Set(Decimal(ino));
    },
    // Jail state no longer names it, so nothing will ever clean it.
    withdraw: |state| {
        state.vendor_state = Field::Null;
        state.vendor_state_withdrawn =
            Field::Set("the directory was not created by this attempt".to_owned());
        state.state_cleanup = Field::Set(StateCleanup::NotNeeded);
        state.cleanup_reason = Field::Null;
    },
};

/// Registers vendor state in jail state, then creates it
/// ([`create_registered_dir`]); cleanup refuses to delete anything but the
/// directory whose identity it records.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either state write or the
/// creation fails, and [`ErrorCode::UnsafeStatePath`] when the attempt
/// directory fails its checks or `vendor-state` already exists.
pub fn create_vendor_state(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    create_registered_dir(attempt_dir, &VENDOR_STATE_REGISTRATION, &mut |_| {})
}

pub mod proxy_dir;

pub use proxy_dir::{
    PROXY_DIR_NAME, PROXY_SOCKET_NAME, ProxyDirRemoval, ProxySocketIdentity, create_proxy_dir,
    create_proxy_dir_observed, gc_proxy_dir, record_proxy_socket, remove_proxy_dir,
};

/// The jail-owned names of an attempt directory (§7), which an existing
/// attempt root must not already hold before this supervisor claims it.
pub const JAIL_OWNED_NAMES: [&str; 9] = [
    LOCK_NAME,
    STATE_NAME,
    POLICY_NAME,
    RECEIPT_NAME,
    TRACE_NAME,
    VENDOR_STATE_NAME,
    SCRATCH_NAME,
    PLACEHOLDERS_NAME,
    PROXY_DIR_NAME,
];

/// Refuses an attempt root that already holds any jail-owned artifact (§7:
/// "An existing attempt root is acceptable only with validated
/// ownership/permissions and no previous jail state or jail-owned
/// artifacts").
///
/// Called before the lease is taken, so `jail.lock` is checked too: any
/// `jail.lock` present then was not created by this supervisor.
///
/// # Errors
/// Returns [`ErrorCode::AttemptExists`] naming the first artifact found.
pub fn check_fresh_attempt(attempt_dir: &AttemptDir) -> Result<(), JailError> {
    for name in JAIL_OWNED_NAMES {
        match std::fs::symlink_metadata(attempt_dir.root().join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(JailError::new(
                    ErrorCode::AttemptExists,
                    ErrorStage::Resolving,
                    Remediation::InspectState,
                    format!(
                        "the attempt directory already holds the jail-owned `{name}`; a prior \
                         attempt, live or dead, owns it"
                    ),
                ));
            }
            Err(error) => {
                return Err(unsafe_path(
                    &attempt_dir.root().join(name),
                    format!("cannot be inspected: {error}"),
                ));
            }
        }
    }
    Ok(())
}

/// Records the private provenance of staged credentials in jail state.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_staged_credentials(
    attempt_dir: &AttemptDir,
    staged: &[PrivateCredential],
) -> Result<(), JailError> {
    let rows: Vec<CredentialEntry> = staged
        .iter()
        .map(|row| CredentialEntry {
            id: row.id.clone(),
            mode: row.mode.clone(),
            source_dev: Decimal(row.source_dev),
            source_ino: Decimal(row.source_ino),
            source_size: Decimal(row.source_size),
            content_digest: Field::or_null(row.content_digest.clone()),
            rest: serde_json::Map::new(),
        })
        .collect();
    update_attempt_state(Site::LaunchState, attempt_dir, |state| {
        state.vendor_state.get_or_insert_default().credentials = Field::Set(rows);
    })
}

// N7
/// Registers the execution leaf in jail state (§7): `identity` `None` names
/// it before `mkdir` (P15), `Some((device, inode))` identifies it right
/// after, before anything is placed in it (P16). `gc` reads the leaf from
/// here, so a crash anywhere after the name is durable leaves a leaf `gc`
/// can find (§14.2).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when jail state cannot be read or
/// durably replaced, or the path is not UTF-8 (a cgroup path this build
/// makes always is).
pub fn register_execution_leaf(
    attempt_dir: &AttemptDir,
    path: &Path,
    identity: Option<(u64, u64)>,
) -> Result<(), JailError> {
    if path.to_str().is_none() {
        return Err(state_parse_failed(format!(
            "the execution leaf path {} is not UTF-8",
            path.display()
        )));
    }
    let site = if identity.is_some() {
        Site::ExecutionLeafIdentity
    } else {
        Site::ExecutionLeaf
    };
    update_attempt_state(site, attempt_dir, |state| {
        state.execution_cgroup = Field::Set(LeafEntry::new(path.to_path_buf(), identity));
    })
}

/// Records cleanup progress in jail state, atomically and durably.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_cleanup(
    attempt_dir: &AttemptDir,
    status: StateCleanup,
    reason: Option<&str>,
) -> Result<(), JailError> {
    record_cleanup_at(Site::CleanupRecord, attempt_dir, status, reason)
}

/// [`record_cleanup`] at a named site (`gc` resuming a cleanup is its own).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_cleanup_at(
    site: Site,
    attempt_dir: &AttemptDir,
    status: StateCleanup,
    reason: Option<&str>,
) -> Result<(), JailError> {
    update_attempt_state(site, attempt_dir, |state| {
        state.state_cleanup = Field::Set(status);
        state.cleanup_reason = Field::or_null(reason.map(str::to_owned));
    })
}

/// What the state modules' tests share.
#[cfg(test)]
pub(crate) mod testing {
    use super::{AttemptDir, AttemptId, SCHEMA_STATE, replace_atomically};

    /// A 0700 temporary directory whatever the umask: a state root under a
    /// group-writable one is refused, rightly.
    pub(crate) fn private_tempdir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("a temporary directory")
    }

    /// Jail state as the JSON on disk.
    pub(crate) fn raw_state(attempt: &AttemptDir) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(attempt.state_path()).unwrap()).unwrap()
    }

    /// A claimed attempt root whose jail state registers nothing.
    pub(crate) fn claimed_attempt() -> (tempfile::TempDir, AttemptDir) {
        let dir = private_tempdir();
        let data = dir.path().canonicalize().unwrap().join("data");
        let attempt = AttemptDir::new(&data, &AttemptId::generate());
        attempt.create(&data).unwrap();
        let state = serde_json::json!({
            "schema": SCHEMA_STATE,
            "vendor_state": null,
            "state_cleanup": "not_needed",
        });
        replace_atomically(&attempt.state_path(), &serde_json::to_vec(&state).unwrap()).unwrap();
        (dir, attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{claimed_attempt, private_tempdir, raw_state};
    use super::*;

    #[test]
    fn only_a_temporary_name_of_a_root_record_is_ours() {
        let id = uuid::Uuid::new_v4().to_string();
        for record in ROOT_RECORDS {
            assert!(
                is_record_temp_name(&format!(".{record}.{id}.tmp")),
                "{record}"
            );
        }
        for other in [
            format!(".trace.ndjson.{id}.tmp"),
            format!(".jail.json.{}.tmp", id.to_uppercase()),
            format!(".jail.json.{}.tmp", id.replace('-', "")),
            format!("jail.json.{id}.tmp"),
            format!(".jail.json.{id}"),
            ".jail.json..tmp".to_owned(),
            ".planted.tmp".to_owned(),
        ] {
            assert!(!is_record_temp_name(&other), "{other}");
        }
    }

    #[test]
    fn world_write_always_counts_and_no_group_write_never_does() {
        assert!(writable_by_others(0o777, 0, 0));
        assert!(writable_by_others(0o702, 1000, 1000));
        assert!(!writable_by_others(0o755, 1000, 1000));
        assert!(!writable_by_others(0o700, 1000, 1000));
    }

    /// The stock Ubuntu home: a state root beneath a directory that is
    /// group-writable by the operator's own private group. Accepted exactly
    /// when the host's account database says the group is private (true for
    /// the reference host's accounts; false for macOS's shared `staff`).
    #[test]
    fn a_group_writable_ancestor_is_refused_unless_its_group_is_private() {
        use std::os::unix::fs::MetadataExt as _;
        let root = tempfile::tempdir().unwrap();
        let shared = root.path().join("dotlocal");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        let state_root = shared.join("state");
        std::fs::create_dir(&state_root).unwrap();
        let metadata = std::fs::metadata(&shared).unwrap();
        let private = accounts::group_is_private_to(metadata.uid(), metadata.gid());
        let checked = check_state_ancestors(&state_root);
        assert_eq!(
            checked.is_ok(),
            private,
            "gid {} private: {private}; check: {checked:?}",
            metadata.gid()
        );
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check_state_ancestors(&state_root).is_err(),
            "world write without the sticky bit is always refused"
        );
    }

    #[test]
    fn group_write_is_private_only_for_the_owners_own_group() {
        use accounts::{Facts, private};
        let name: &[u8] = b"ubuntu";
        let own = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(private(1000, &own), "Ubuntu's user private group");
        let listed_self = Facts {
            members: Some(vec![b"ubuntu".to_vec()]),
            ..own
        };
        assert!(private(1000, &listed_self), "the owner listed as a member");
        let own = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(!private(1001, &own), "not the owner's primary group");
        let shared = Facts {
            owner: Some((name, 1000)),
            members: Some(vec![b"ubuntu".to_vec(), b"someone".to_vec()]),
            another_primary: false,
        };
        assert!(!private(1000, &shared), "another listed member");
        let primary_elsewhere = Facts {
            owner: Some((name, 1000)),
            members: Some(Vec::new()),
            another_primary: true,
        };
        assert!(
            !private(1000, &primary_elsewhere),
            "another account's primary group"
        );
        let unknown_owner = Facts {
            owner: None,
            members: Some(Vec::new()),
            another_primary: false,
        };
        assert!(!private(1000, &unknown_owner));
        let unknown_group = Facts {
            owner: Some((name, 1000)),
            members: None,
            another_primary: false,
        };
        assert!(!private(1000, &unknown_group));
    }

    #[test]
    fn an_uncontained_run_is_live_until_its_guard_settles_both_marker_directories() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = private_tempdir();
        let data = dir.path().join("data");
        let config = dir.path().join("config");
        std::fs::create_dir_all(&data).unwrap();
        let stale = dir.path().join("stale.toml");
        std::fs::write(&stale, b"x").unwrap();
        let dirs = [data.as_path(), config.as_path()];
        assert_eq!(
            uncontained_epoch(&dirs).unwrap(),
            UncontainedEpoch::default()
        );
        // Armed: a live marker in each directory (the missing config
        // directory is created private), and no settled one yet — a
        // concurrent run cannot date anything.
        let guard = UncontainedRun::arm(&dirs, "att_test").unwrap();
        let live = uncontained_epoch(&dirs).unwrap();
        assert_eq!(live.settled, None);
        assert_eq!(
            live.live,
            vec![
                uncontained_live_path(&config, "att_test"),
                uncontained_live_path(&data, "att_test"),
            ]
        );
        assert_eq!(
            config.symlink_metadata().unwrap().mode() & 0o777,
            0o700,
            "a created marker directory is private"
        );
        // Dropped once the tree is gone: settled markers, live ones gone,
        // the operator's file mode, and a ctime every earlier file predates
        // while a later re-save postdates it — the comparison the
        // supervisor's stale-file guard makes.
        drop(guard);
        let settled = uncontained_epoch(&dirs).unwrap();
        assert!(settled.live.is_empty(), "{settled:?}");
        let epoch = settled.settled.expect("settled on drop");
        for dir in dirs {
            let marker = uncontained_settled_path(dir).symlink_metadata().unwrap();
            assert!(marker.is_file());
            assert_eq!(marker.mode() & 0o777, 0o600);
        }
        let ctime = |path: &Path| ctime_of(&path.symlink_metadata().unwrap()).unwrap();
        assert!(ctime(&stale) <= epoch);
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&stale, b"x").unwrap();
        assert!(ctime(&stale) > epoch);
        // No temporary is left behind.
        for dir in dirs {
            let leftovers: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .filter(|name| name.to_string_lossy().ends_with(".tmp"))
                .collect();
            assert!(leftovers.is_empty(), "{leftovers:?}");
        }
    }

    /// Review of audit 6 F1: the child can put a directory where the settled
    /// marker goes, or make the directory unwritable, so the run's own write
    /// fails. The reader refuses a settled marker that is not a file, and the
    /// guard clears both obstacles before it settles.
    #[test]
    fn a_blocked_settled_marker_fails_closed_and_the_guard_clears_the_obstacle() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let guard = UncontainedRun::arm(&dirs, "att_blocked").unwrap();
        // What the uncontained child does while it runs.
        std::fs::create_dir(uncontained_settled_path(&data)).unwrap();
        std::fs::write(uncontained_settled_path(&data).join("inside"), b"x").unwrap();
        let error = uncontained_epoch(&dirs).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeStatePath);
        assert!(error.message.contains("not a regular file"), "{error:?}");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o500)).unwrap();
        drop(guard);
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert!(epoch.settled.is_some(), "{epoch:?}");
        assert!(epoch.live.is_empty(), "{epoch:?}");
        assert!(
            uncontained_settled_path(&data)
                .symlink_metadata()
                .unwrap()
                .is_file()
        );
    }

    /// A settle that cannot be written keeps the live marker, so every later
    /// run still refuses to date trusted files: the failure fails closed.
    #[test]
    fn a_settle_that_cannot_be_written_leaves_the_run_live() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let dirs = [data.as_path()];
        let guard = UncontainedRun::arm(&dirs, "att_unsettled").unwrap();
        // A marker directory replaced by something the guard does not
        // delete: a directory owned by the operator but whose marker path is
        // a non-empty directory it cannot remove because its own child is
        // read-only.
        let blocker = uncontained_settled_path(&data);
        std::fs::create_dir(&blocker).unwrap();
        std::fs::create_dir(blocker.join("locked")).unwrap();
        std::fs::write(blocker.join("locked").join("file"), b"x").unwrap();
        std::fs::set_permissions(
            blocker.join("locked"),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        drop(guard);
        std::fs::set_permissions(
            blocker.join("locked"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let live = uncontained_live_path(&data, "att_unsettled");
        assert!(
            live.exists(),
            "the live marker must stay when settling failed"
        );
    }

    /// A persistence seam that logs the marker steps that order the settle,
    /// and can fail the markers' directory syncs.
    #[derive(Default)]
    struct MarkerIo {
        steps: std::sync::Mutex<Vec<String>>,
        fail_dir_sync: bool,
    }

    impl MarkerIo {
        fn log(&self, step: &str, path: &Path) {
            let name = path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            self.steps.lock().unwrap().push(format!("{step} {name}"));
        }
    }

    impl PersistIo for MarkerIo {
        fn rename(&self, site: Site, from: &Path, to: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("rename", to);
            RealIo.rename(site, from, to)
        }
        fn sync_dir(&self, site: Site, dir: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("sync_dir", dir);
            if self.fail_dir_sync {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            RealIo.sync_dir(site, dir)
        }
        fn remove(&self, site: Site, path: &Path) -> std::io::Result<()> {
            assert_eq!(site, Site::UncontainedMarker);
            self.log("remove", path);
            RealIo.remove(site, path)
        }
    }

    /// The settle is durably ordered: the settled marker is renamed and its
    /// directory synced before the live marker is removed, and the removal
    /// is synced too. A crash can then leave both markers, which later runs
    /// read as "cannot date", but never the live one gone without the
    /// settled one.
    #[test]
    fn the_live_marker_goes_only_after_the_settled_one_is_durable() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let guard = UncontainedRun::arm(&[data.as_path()], "att_ordered").unwrap();
        let io = std::sync::Arc::new(MarkerIo::default());
        let installed = install(io.clone());
        drop(guard);
        drop(installed);
        assert_eq!(
            *io.steps.lock().unwrap(),
            [
                "rename uncontained.epoch",
                "sync_dir data",
                "remove uncontained.att_ordered.live",
                "sync_dir data",
            ]
        );
        assert!(!uncontained_live_path(&data, "att_ordered").exists());
    }

    /// A settled marker whose directory sync fails is not durable, so the
    /// settle fails and the live marker stays: later runs keep refusing to
    /// date trusted files rather than trust a marker a crash could lose.
    #[test]
    fn a_settle_whose_directory_sync_fails_leaves_the_run_live() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let guard = UncontainedRun::arm(&[data.as_path()], "att_unsynced").unwrap();
        let io = std::sync::Arc::new(MarkerIo {
            fail_dir_sync: true,
            ..MarkerIo::default()
        });
        let installed = install(io.clone());
        drop(guard);
        drop(installed);
        assert!(
            uncontained_live_path(&data, "att_unsynced").exists(),
            "{:?}",
            io.steps.lock().unwrap()
        );
        assert!(
            !uncontained_epoch(&[data.as_path()])
                .unwrap()
                .live
                .is_empty()
        );
    }

    #[test]
    fn an_uncontained_run_that_cannot_write_its_live_marker_does_not_arm() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, b"x").unwrap();
        // The second directory lies beneath a regular file.
        let config = blocked.join("config");
        let error = UncontainedRun::arm(&[data.as_path(), config.as_path()], "att_refused")
            .err()
            .expect("an unwritable marker directory refuses");
        assert_eq!(error.code, ErrorCode::StateWriteFailed);
        assert!(
            !uncontained_live_path(&data, "att_refused").exists(),
            "the markers already written are removed"
        );
    }

    /// `expect_err` with a caller-supplied message, so a passing case names the
    /// input that was supposed to refuse.
    trait UnwrapErrOrPanic<E> {
        fn unwrap_err_or_panic(self, message: &str) -> E;
    }

    impl<T: std::fmt::Debug, E> UnwrapErrOrPanic<E> for Result<T, E> {
        fn unwrap_err_or_panic(self, message: &str) -> E {
            match self {
                Ok(value) => panic!("{message}, got {value:?}"),
                Err(error) => error,
            }
        }
    }

    #[test]
    fn an_attempt_root_holding_any_jail_owned_artifact_is_not_fresh() {
        // J3 review H2: §7 refuses every jail-owned artifact, not only
        // `jail-state.json`; `jail.lock` included, since the check runs before
        // this supervisor takes its own lease.
        for name in JAIL_OWNED_NAMES {
            let dir = private_tempdir();
            let data = dir.path().canonicalize().unwrap().join("data");
            let attempt = AttemptDir::new(&data, &AttemptId::generate());
            attempt.create(&data).unwrap();
            assert!(
                check_fresh_attempt(&attempt).is_ok(),
                "{name}: empty is fresh"
            );
            std::fs::write(attempt.root().join("owner-reservation.json"), b"{}").unwrap();
            assert!(
                check_fresh_attempt(&attempt).is_ok(),
                "an owner's own file is fine"
            );
            if name.contains('.') {
                std::fs::write(attempt.root().join(name), b"").unwrap();
            } else {
                std::fs::create_dir(attempt.root().join(name)).unwrap();
            }
            let error = check_fresh_attempt(&attempt).unwrap_err();
            assert_eq!(error.code, ErrorCode::AttemptExists, "{name}");
            assert!(error.message.contains(name), "{name}: {}", error.message);
        }
    }

    #[test]
    fn a_vendor_state_that_already_exists_is_withdrawn_not_registered() {
        let (_dir, attempt) = claimed_attempt();
        std::fs::create_dir(attempt.vendor_state_path()).unwrap();
        std::fs::write(attempt.vendor_state_path().join("precious"), b"keep").unwrap();
        let error = create_vendor_state(&attempt).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsafeStatePath);
        assert_eq!(vendor_registration(&attempt).unwrap(), None);
        let state = raw_state(&attempt);
        assert_eq!(state["state_cleanup"], "not_needed");
        assert!(attempt.vendor_state_path().join("precious").exists());
    }

    #[test]
    fn created_vendor_state_is_registered_with_its_identity() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, attempt) = claimed_attempt();
        let vendor = create_vendor_state(&attempt).unwrap();
        let metadata = std::fs::metadata(attempt.vendor_state_path()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let registration = vendor_registration(&attempt).unwrap().unwrap();
        assert_eq!(
            registration.identity,
            Some((metadata.dev(), metadata.ino()))
        );
        assert_eq!(
            registration.state_cleanup,
            crate::records::StateCleanup::Pending
        );
        assert_eq!(
            vendor.stat().unwrap().identity(),
            (metadata.dev(), metadata.ino())
        );
    }

    #[test]
    fn a_generated_attempt_id_round_trips_through_the_grammar() {
        let id = AttemptId::generate();
        assert!(id.as_str().starts_with("att_"));
        assert_eq!(AttemptId::parse(id.as_str()).expect("valid"), id);
    }

    #[test]
    fn a_malformed_attempt_id_is_a_usage_error() {
        for bad in [
            "att_00000000-0000-0000-8000-000000000001",
            "att_00000000-0000-4000-0000-000000000001",
            "att_00000000000040008000000000000001",
            "att_00000000-0000-4000-8000-00000000000G",
            "00000000-0000-4000-8000-000000000001",
            "att_../../etc",
            "att_00000000-0000-4000-8000-000000000001-extra",
            "ATT_00000000-0000-4000-8000-000000000001",
        ] {
            let error = AttemptId::parse(bad)
                .unwrap_err_or_panic(&format!("`{bad}` must refuse the grammar check"));
            assert_eq!(error.code, ErrorCode::InvalidConfig, "{bad}");
            assert_eq!(error.exit_code(), 2, "{bad}");
        }
        assert!(
            AttemptId::parse("att_00000000-0000-4000-b000-000000000001").is_ok(),
            "variant nibble b is valid"
        );
    }

    /// S1: the epoch takes the *newest* settled marker across the marker
    /// directories, not the last directory's. A `config.toml` written
    /// between a newer data-dir marker and an older config-dir marker must
    /// not be dated after the epoch.
    #[test]
    fn the_epoch_takes_the_newest_settled_marker_across_directories() {
        let dir = private_tempdir();
        let data = dir.path().join("data");
        let config = dir.path().join("config");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let dirs = [data.as_path(), config.as_path()];
        let ctime = |path: &Path| ctime_of(&path.symlink_metadata().unwrap()).unwrap();
        // The config directory settles first; then a trusted file is
        // written; then the data directory settles last.
        std::fs::write(uncontained_settled_path(&config), b"").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let trusted = dir.path().join("config.toml");
        std::fs::write(&trusted, b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(uncontained_settled_path(&data), b"").unwrap();
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert_eq!(
            epoch.settled,
            Some(ctime(&uncontained_settled_path(&data))),
            "the newest marker wins, not the last directory's: a file written \
             between the two markers must not be trusted"
        );
        // The symmetric case: the newest marker is in the config directory.
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(uncontained_settled_path(&config), b"").unwrap();
        let epoch = uncontained_epoch(&dirs).unwrap();
        assert_eq!(
            epoch.settled,
            Some(ctime(&uncontained_settled_path(&config)))
        );
    }

    /// S2: a marker directory that cannot be listed is refused, not skipped:
    /// skipping it would hide the live markers of a run in progress or one
    /// that ended without settling, and every trusted file would be dated.
    #[test]
    fn an_unreadable_marker_directory_is_refused_not_skipped() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = private_tempdir();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o300)).unwrap();
        let error = uncontained_epoch(&[data.as_path()])
            .unwrap_err_or_panic("an unreadable marker directory must refuse");
        assert_eq!(error.code, ErrorCode::UnsafeStatePath, "{error:?}");
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
