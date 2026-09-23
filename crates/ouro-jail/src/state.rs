//! Attempt state: directories, ids, the durable replacement and the lease.
//!
//! Implements jail-v1 §6.2 (state paths and their safety rules) and §7 (attempt
//! id grammar, the attempt directory layout and durable persistence).
//!
//! A successful rename alone is not a durable acknowledgment (§7), so a
//! replacement is: create a new temporary file in the same directory, write,
//! `fsync` the file, rename, then `fsync` the parent directory. The temporary
//! file is only ever renamed by [`TempWrite::commit`], so an abandoned write
//! leaves the previous file untouched.

use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

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
    Ok(home.join(".local").join("share").join("ouro"))
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

    /// The attempt root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `jail.lock`: the exclusive live-supervisor lease.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.root.join("jail.lock")
    }

    /// `jail-state.json`: identity, lifecycle and owned resources.
    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.root.join("jail-state.json")
    }

    /// `policy.json`: the immutable resolved policy envelope.
    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.root.join("policy.json")
    }

    /// `jail.json`: the latest receipt.
    #[must_use]
    pub fn receipt_path(&self) -> PathBuf {
        self.root.join("jail.json")
    }

    /// `trace.ndjson`: the default bounded standalone event sink.
    #[must_use]
    pub fn trace_path(&self) -> PathBuf {
        self.root.join("trace.ndjson")
    }

    /// `vendor-state/`: created only when a launch profile requires it.
    #[must_use]
    pub fn vendor_state_path(&self) -> PathBuf {
        self.root.join("vendor-state")
    }

    /// `scratch/`: the default child-writable scratch directory.
    #[must_use]
    pub fn scratch_path(&self) -> PathBuf {
        self.root.join("scratch")
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
/// or is writable by anyone other than its owner without the sticky bit.
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
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
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

/// The two durability primitives §7 names, as a seam.
///
/// "A successful rename alone is not a durable acknowledgment", so both calls
/// have to happen and a test has to be able to see that they did. A trait is
/// the only way to observe an `fsync` from outside the kernel.
pub trait Durable {
    /// Flushes the file's own data and metadata.
    ///
    /// # Errors
    /// Returns the underlying `fsync` failure.
    fn sync_file(&self, file: &File) -> std::io::Result<()>;

    /// Flushes the directory entry created by the rename.
    ///
    /// # Errors
    /// Returns the underlying open or `fsync` failure.
    fn sync_dir(&self, path: &Path) -> std::io::Result<()>;
}

/// The real durability implementation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fsync;

impl Durable for Fsync {
    fn sync_file(&self, file: &File) -> std::io::Result<()> {
        file.sync_all()
    }

    fn sync_dir(&self, path: &Path) -> std::io::Result<()> {
        File::open(path).and_then(|handle| handle.sync_all())
    }
}

/// A pending durable replacement: written and synced, not yet renamed.
///
/// Dropping it without [`TempWrite::commit`] leaves the target file exactly as
/// it was, which is the "either the old or the new file" property of R02.
pub struct TempWrite<'a> {
    temp: PathBuf,
    target: PathBuf,
    committed: bool,
    durable: &'a dyn Durable,
}

impl std::fmt::Debug for TempWrite<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempWrite")
            .field("temp", &self.temp)
            .field("target", &self.target)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl TempWrite<'static> {
    /// Creates the temporary file beside `target`, writes `bytes` and syncs it.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be created,
    /// written or synced.
    pub fn create(target: &Path, bytes: &[u8]) -> Result<Self, JailError> {
        Self::create_with(target, bytes, &Fsync)
    }
}

impl<'a> TempWrite<'a> {
    /// [`TempWrite::create`] against an explicit durability implementation.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be created,
    /// written or synced.
    pub fn create_with(
        target: &Path,
        bytes: &[u8],
        durable: &'a dyn Durable,
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
        // The id is unique per attempt and per process, so two live supervisors
        // never race on the same temporary name.
        let temp = directory.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temp)
            .map_err(|error| write_failed(&temp, &error))?;
        file.write_all(bytes)
            .map_err(|error| write_failed(&temp, &error))?;
        durable
            .sync_file(&file)
            .map_err(|error| write_failed(&temp, &error))?;
        Ok(TempWrite {
            temp,
            target: target.to_path_buf(),
            committed: false,
            durable,
        })
    }

    /// The temporary file's path, for tests that inspect the failure window.
    #[must_use]
    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    /// Renames the temporary file over the target and syncs the directory.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the rename or the directory
    /// sync fails; a rename that is not followed by a successful directory sync
    /// is reported rather than acknowledged.
    pub fn commit(mut self) -> Result<(), JailError> {
        std::fs::rename(&self.temp, &self.target)
            .map_err(|error| write_failed(&self.target, &error))?;
        self.committed = true;
        let directory = self
            .target
            .parent()
            .expect("create() already established a parent");
        self.durable
            .sync_dir(directory)
            .map_err(|error| write_failed(directory, &error))?;
        Ok(())
    }
}

impl Drop for TempWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            // Best effort: the target is intact either way, and a leftover
            // temporary file is visible state rather than a silent overwrite.
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// Replaces `target` durably (§7).
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically(target: &Path, bytes: &[u8]) -> Result<(), JailError> {
    replace_atomically_with(target, bytes, &Fsync)
}

/// [`replace_atomically`] against an explicit durability implementation.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when any step fails.
pub fn replace_atomically_with(
    target: &Path,
    bytes: &[u8],
    durable: &dyn Durable,
) -> Result<(), JailError> {
    TempWrite::create_with(target, bytes, durable)?.commit()
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
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(FILE_MODE)
            .open(path)
            .map_err(|error| write_failed(path, &error))?;
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

use crate::records::StateCleanup;

/// The vendor-state directory's name inside an attempt directory (§7).
pub const VENDOR_STATE_NAME: &str = "vendor-state";

/// Largest `jail-state.json` this tool reads back. It writes the file itself;
/// the bound is there so a replaced file cannot grow a read without limit.
const STATE_FILE_MAX: u64 = 1024 * 1024;

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
}

fn state_parse_failed(detail: impl std::fmt::Display) -> JailError {
    JailError::new(
        ErrorCode::StateWriteFailed,
        ErrorStage::Preparing,
        Remediation::InspectState,
        format!("the attempt state could not be read back: {detail}"),
    )
}

/// Reads `jail-state.json` back as JSON.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the file is missing,
/// unreadable, oversized, a symlink or not JSON.
pub fn read_attempt_state(attempt_dir: &AttemptDir) -> Result<serde_json::Value, JailError> {
    let path = attempt_dir.state_path();
    let bytes = read_capped(&path, STATE_FILE_MAX)
        .map_err(state_parse_failed)?
        .ok_or_else(|| state_parse_failed("the file is absent"))?;
    serde_json::from_slice(&bytes).map_err(state_parse_failed)
}

/// Read-modify-write of `jail-state.json` through the durable replacement.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be read,
/// parsed or durably replaced.
pub fn update_attempt_state(
    attempt_dir: &AttemptDir,
    change: impl FnOnce(&mut serde_json::Value),
) -> Result<(), JailError> {
    let mut state = read_attempt_state(attempt_dir)?;
    if state.get("schema").and_then(serde_json::Value::as_str) != Some("ouro.jail.state/1") {
        return Err(state_parse_failed("the schema is not ouro.jail.state/1"));
    }
    change(&mut state);
    let bytes = serde_json::to_vec_pretty(&state).map_err(state_parse_failed)?;
    replace_atomically(&attempt_dir.state_path(), &bytes)
}

fn cleanup_word(status: StateCleanup) -> &'static str {
    match status {
        StateCleanup::NotNeeded => "not_needed",
        StateCleanup::Pending => "pending",
        StateCleanup::Complete => "complete",
    }
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
    let Some(vendor) = state.get("vendor_state").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let number = |key: &str| {
        vendor
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
    };
    let identity = number("dev").zip(number("ino"));
    let state_cleanup = match state
        .get("state_cleanup")
        .and_then(serde_json::Value::as_str)
    {
        Some("pending") => StateCleanup::Pending,
        Some("complete") => StateCleanup::Complete,
        // Registered vendor state is never `not_needed`; anything else is a
        // state file this tool did not write.
        other => {
            return Err(state_parse_failed(format!(
                "vendor state is registered with cleanup status {other:?}"
            )));
        }
    };
    let reason = state
        .get("cleanup_reason")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok(Some(VendorRegistration {
        identity,
        state_cleanup,
        reason,
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

/// Registers vendor state in jail state, then creates it (§7, §12).
///
/// "Register vendor state before the first copy, create it mode 0700." The
/// registration is durable before `mkdirat` runs, so a crash between the two
/// leaves a registered, absent directory that cleanup treats as removed, and
/// never an unregistered directory nobody will clean. The directory's identity
/// is recorded once it exists; cleanup refuses to delete anything else.
///
/// # Errors
/// Returns [`ErrorCode::StateWriteFailed`] when either state write or the
/// creation fails, and [`ErrorCode::UnsafeStatePath`] when the attempt
/// directory fails its checks or `vendor-state` already exists.
pub fn create_vendor_state(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    update_attempt_state(attempt_dir, |state| {
        state["vendor_state"] = serde_json::json!({
            "name": VENDOR_STATE_NAME,
            "registered_at": crate::records::rfc3339_utc(std::time::SystemTime::now()),
            "dev": null,
            "ino": null,
            "credentials": [],
        });
        state["state_cleanup"] = serde_json::Value::from(cleanup_word(StateCleanup::Pending));
        state["cleanup_reason"] = serde_json::Value::Null;
    })?;
    let attempt = open_attempt_dir(attempt_dir)?;
    let name = anchored::Name::new(VENDOR_STATE_NAME.as_bytes())
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    let vendor = match attempt.mkdir_at(&name, DIRECTORY_MODE) {
        Ok(vendor) => vendor,
        Err(error) => {
            // Something already there is not this attempt's, and nothing
            // created means nothing to clean: either way the registration is
            // withdrawn, so no later cleanup can remove what this attempt did
            // not make (J3 review H2). If an entry exists that this call may
            // have made (a failure after `mkdirat`), it stays registered with
            // no identity, which cleanup retains rather than deletes.
            let ours_possibly =
                error.kind() != std::io::ErrorKind::AlreadyExists && attempt.stat_at(&name).is_ok();
            if !ours_possibly {
                withdraw_vendor_registration(attempt_dir)?;
            }
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                unsafe_path(
                    &attempt_dir.vendor_state_path(),
                    "already exists in a fresh attempt; it is not this attempt's vendor state",
                )
            } else {
                write_failed(&attempt_dir.vendor_state_path(), &error)
            });
        }
    };
    // The identity is recorded before anything else can fail: cleanup never
    // removes a registered directory whose identity was not recorded.
    let stat = vendor
        .stat()
        .map_err(|error| write_failed(&attempt_dir.vendor_state_path(), &error))?;
    update_attempt_state(attempt_dir, |state| {
        state["vendor_state"]["dev"] = serde_json::Value::from(stat.dev.to_string());
        state["vendor_state"]["ino"] = serde_json::Value::from(stat.ino.to_string());
    })?;
    attempt
        .sync()
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    Ok(vendor)
}

/// Withdraws a vendor-state registration whose directory this attempt did not
/// create: jail state no longer names it, so nothing will ever clean it.
fn withdraw_vendor_registration(attempt_dir: &AttemptDir) -> Result<(), JailError> {
    update_attempt_state(attempt_dir, |state| {
        state["vendor_state"] = serde_json::Value::Null;
        state["vendor_state_withdrawn"] =
            serde_json::Value::from("the directory was not created by this attempt");
        state["state_cleanup"] = serde_json::Value::from(cleanup_word(StateCleanup::NotNeeded));
        state["cleanup_reason"] = serde_json::Value::Null;
    })
}

// J3-agent begin: the proxy directory in jail state (jail-v1 §10)

/// The proxy directory's name inside an attempt directory (§10).
pub const PROXY_DIR_NAME: &str = "proxy";
/// The proxy socket's name inside the proxy directory (§10).
pub const PROXY_SOCKET_NAME: &str = "proxy.sock";

impl AttemptDir {
    /// `proxy/`: created only for a proxy-mode profile.
    #[must_use]
    pub fn proxy_dir_path(&self) -> PathBuf {
        self.root.join(PROXY_DIR_NAME)
    }
}

/// Registers the proxy directory in jail state, then creates it mode 0700
/// (§10: "an operator-owned 0700 directory registered before creation").
///
/// As for vendor state: the registration is durable before `mkdirat`, the
/// directory's identity is recorded once it exists, and an entry that was
/// already there is not this attempt's and withdraws the registration.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when a state write or the creation fails,
/// [`ErrorCode::UnsafeStatePath`] when the attempt directory fails its checks
/// or `proxy` already exists.
pub fn create_proxy_dir(attempt_dir: &AttemptDir) -> Result<anchored::Dir, JailError> {
    create_proxy_dir_observed(attempt_dir, &mut |_| {})
}

/// [`create_proxy_dir`], calling `between` after the registration is durable
/// and before the directory exists: the seam a test uses to observe that
/// order (§10: "registered before creation").
///
/// # Errors
/// As [`create_proxy_dir`].
pub fn create_proxy_dir_observed(
    attempt_dir: &AttemptDir,
    between: &mut dyn FnMut(&AttemptDir),
) -> Result<anchored::Dir, JailError> {
    update_attempt_state(attempt_dir, |state| {
        state["proxy_dir"] = serde_json::json!({
            "name": PROXY_DIR_NAME,
            "registered_at": crate::records::rfc3339_utc(std::time::SystemTime::now()),
            "dev": null,
            "ino": null,
            "removed": false,
        });
    })?;
    between(attempt_dir);
    let attempt = open_attempt_dir(attempt_dir)?;
    let name = anchored::Name::new(PROXY_DIR_NAME.as_bytes())
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    let proxy = match attempt.mkdir_at(&name, DIRECTORY_MODE) {
        Ok(proxy) => proxy,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                update_attempt_state(attempt_dir, |state| {
                    state["proxy_dir"] = serde_json::Value::Null;
                    state["proxy_dir_withdrawn"] =
                        serde_json::Value::from("the directory was not created by this attempt");
                })?;
                return Err(unsafe_path(
                    &attempt_dir.proxy_dir_path(),
                    "already exists in a fresh attempt; it is not this attempt's proxy directory",
                ));
            }
            return Err(write_failed(&attempt_dir.proxy_dir_path(), &error));
        }
    };
    let stat = proxy
        .stat()
        .map_err(|error| write_failed(&attempt_dir.proxy_dir_path(), &error))?;
    update_attempt_state(attempt_dir, |state| {
        state["proxy_dir"]["dev"] = serde_json::Value::from(stat.dev.to_string());
        state["proxy_dir"]["ino"] = serde_json::Value::from(stat.ino.to_string());
    })?;
    attempt
        .sync()
        .map_err(|error| write_failed(attempt_dir.root(), &error))?;
    Ok(proxy)
}

/// The proxy socket node as bound: enough to recognise it after a crash.
/// `(dev, ino)` alone is not an identity across a delete and a recreate
/// (ext4 hands a freed inode straight back), so the node's change time, set
/// when it was created and untouched since, goes with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProxySocketIdentity {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Change time, seconds and nanoseconds.
    pub ctime: (i64, i64),
}

impl ProxySocketIdentity {
    /// The identity a `stat` of the node shows.
    #[must_use]
    pub fn of(stat: &anchored::Stat) -> Self {
        ProxySocketIdentity {
            dev: stat.dev,
            ino: stat.ino,
            ctime: stat.ctime,
        }
    }
}

/// Records the bound proxy socket's identity under the registered proxy
/// directory, so `gc` can remove exactly that node after a crash.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when the state write fails.
pub fn record_proxy_socket(
    attempt_dir: &AttemptDir,
    socket: &ProxySocketIdentity,
) -> Result<(), JailError> {
    update_attempt_state(attempt_dir, |state| {
        state["proxy_dir"]["socket"] = serde_json::json!({
            "dev": socket.dev.to_string(),
            "ino": socket.ino.to_string(),
            "ctime_sec": socket.ctime.0.to_string(),
            "ctime_nsec": socket.ctime.1.to_string(),
        });
    })
}

/// What `gc` did with an attempt's proxy directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProxyDirGc {
    /// None was registered, or it was already removed.
    Nothing,
    /// Removed now, and recorded.
    Removed,
    /// Would be removed (dry run).
    WouldRemove,
    /// Retained because it cannot be proven the attempt's own (§14.2:
    /// "unverifiable identities ... are retained"), with the reason: a skip
    /// reported with its reason, not a failed cleanup.
    Retained(&'static str),
    /// Retained because reading or removing it failed: a failed cleanup
    /// (§6.4, `gc` exits 1).
    Failed(&'static str),
}

impl ProxyDirGc {
    /// The report's spelling, `None` when there was nothing to do.
    #[must_use]
    pub fn describe(&self) -> Option<String> {
        match self {
            ProxyDirGc::Nothing => None,
            ProxyDirGc::Removed => Some("removed".to_owned()),
            ProxyDirGc::WouldRemove => Some("would_remove".to_owned()),
            ProxyDirGc::Retained(reason) => Some(format!("retained: {reason}")),
            ProxyDirGc::Failed(reason) => Some(format!("failed: {reason}")),
        }
    }
}

/// `gc` of the proxy directory of an attempt whose supervisor is gone (the
/// caller holds its lease). Its proxy died with it; the directory holds
/// nothing the child could write. The socket node is unlinked only when its
/// `(dev, ino, ctime)` is the one recorded when it was bound, and the
/// directory only when it is the registered one and then empty; anything
/// else is retained and said so.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when jail state cannot be read or updated.
pub fn gc_proxy_dir(attempt_dir: &AttemptDir, dry_run: bool) -> Result<ProxyDirGc, JailError> {
    let state = read_attempt_state(attempt_dir)?;
    let Some(proxy) = state.get("proxy_dir").filter(|value| !value.is_null()) else {
        return Ok(ProxyDirGc::Nothing);
    };
    if proxy.get("removed").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(ProxyDirGc::Nothing);
    }
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let number = |value: &serde_json::Value, key: &str| text(value, key)?.parse::<u64>().ok();
    let signed = |value: &serde_json::Value, key: &str| text(value, key)?.parse::<i64>().ok();
    let registered = number(proxy, "dev").zip(number(proxy, "ino"));
    let socket = proxy.get("socket").and_then(|socket| {
        Some(ProxySocketIdentity {
            dev: number(socket, "dev")?,
            ino: number(socket, "ino")?,
            ctime: (signed(socket, "ctime_sec")?, signed(socket, "ctime_nsec")?),
        })
    });
    let outcome = gc_removal(attempt_dir, registered, socket, dry_run);
    if !dry_run {
        update_attempt_state(attempt_dir, |state| match &outcome {
            ProxyDirGc::Removed => {
                state["proxy_dir"]["removed"] = serde_json::Value::from(true);
                state["proxy_dir"]["removed_by"] = serde_json::Value::from("gc");
            }
            ProxyDirGc::Retained(reason) | ProxyDirGc::Failed(reason) => {
                state["proxy_dir"]["retained"] = serde_json::Value::from(*reason);
            }
            ProxyDirGc::Nothing | ProxyDirGc::WouldRemove => {}
        })?;
    }
    Ok(outcome)
}

fn gc_removal(
    attempt_dir: &AttemptDir,
    registered: Option<(u64, u64)>,
    socket: Option<ProxySocketIdentity>,
    dry_run: bool,
) -> ProxyDirGc {
    let removed = if dry_run {
        ProxyDirGc::WouldRemove
    } else {
        ProxyDirGc::Removed
    };
    let Ok(attempt) = open_attempt_dir(attempt_dir) else {
        return ProxyDirGc::Failed("attempt_directory_unusable");
    };
    let Ok(name) = anchored::Name::new(PROXY_DIR_NAME.as_bytes()) else {
        return ProxyDirGc::Retained("name_invalid");
    };
    let stat = match attempt.stat_at(&name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return removed,
        Err(_) => return ProxyDirGc::Failed("proxy_directory_unreadable"),
    };
    if registered.is_none() {
        // Created, and the supervisor died before it recorded what it
        // created: nothing proves this directory is the one it made.
        return ProxyDirGc::Retained("proxy_directory_unrecorded");
    }
    if registered != Some(stat.identity()) || stat.kind != anchored::Kind::Directory {
        return ProxyDirGc::Retained("proxy_directory_identity_changed");
    }
    let Ok(proxy) = attempt.open_dir_at(&name, Some(&stat)) else {
        return ProxyDirGc::Failed("proxy_directory_unreadable");
    };
    let Ok(entries) = proxy.names(4) else {
        return ProxyDirGc::Failed("proxy_directory_unreadable");
    };
    let Ok(socket_name) = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()) else {
        return ProxyDirGc::Retained("name_invalid");
    };
    for entry in &entries {
        if entry.as_bytes() != socket_name.as_bytes() {
            return ProxyDirGc::Retained("proxy_directory_holds_a_foreign_object");
        }
        let Ok(node) = proxy.stat_at(entry) else {
            return ProxyDirGc::Failed("proxy_socket_unreadable");
        };
        match socket {
            None => return ProxyDirGc::Retained("proxy_socket_unrecorded"),
            Some(recorded)
                if node.kind == anchored::Kind::Socket
                    && ProxySocketIdentity::of(&node) == recorded => {}
            Some(_) => return ProxyDirGc::Retained("proxy_socket_identity_changed"),
        }
    }
    if dry_run {
        return removed;
    }
    if !entries.is_empty() && proxy.unlink_at(&socket_name).is_err() {
        return ProxyDirGc::Failed("proxy_socket_removal_failed");
    }
    if attempt.rmdir_at(&name).is_err() {
        return ProxyDirGc::Retained("proxy_directory_not_empty");
    }
    if attempt.sync().is_err() {
        return ProxyDirGc::Failed("sync_failed");
    }
    removed
}

/// What became of the proxy directory.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyDirRemoval {
    /// None was registered.
    NotRegistered,
    /// Removed (or already absent), and recorded.
    Removed,
    /// Retained, with a safe reason recorded in jail state.
    Retained(&'static str),
}

/// Removes the registered, empty proxy directory, anchored and never
/// followed, and only when the directory is still the object registered.
/// The platform removes the socket node it bound (by its pinned identity)
/// when it stops the proxy; a directory that still holds anything is
/// retained, never emptied by name. It holds nothing the child could write
/// (it is bound read-only), so removal does not wait for tree death.
///
/// # Errors
/// [`ErrorCode::StateWriteFailed`] when jail state cannot be read or updated.
pub fn remove_proxy_dir(attempt_dir: &AttemptDir) -> Result<ProxyDirRemoval, JailError> {
    let state = read_attempt_state(attempt_dir)?;
    let Some(proxy) = state.get("proxy_dir").filter(|value| !value.is_null()) else {
        return Ok(ProxyDirRemoval::NotRegistered);
    };
    if proxy.get("removed").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(ProxyDirRemoval::Removed);
    }
    let number = |key: &str| {
        proxy
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
    };
    let registered = number("dev").zip(number("ino"));
    let outcome = removal(attempt_dir, registered);
    update_attempt_state(attempt_dir, |state| match outcome {
        ProxyDirRemoval::Removed => {
            state["proxy_dir"]["removed"] = serde_json::Value::from(true);
        }
        ProxyDirRemoval::Retained(reason) => {
            state["proxy_dir"]["retained"] = serde_json::Value::from(reason);
        }
        ProxyDirRemoval::NotRegistered => {}
    })?;
    Ok(outcome)
}

fn removal(attempt_dir: &AttemptDir, registered: Option<(u64, u64)>) -> ProxyDirRemoval {
    let Ok(attempt) = open_attempt_dir(attempt_dir) else {
        return ProxyDirRemoval::Retained("attempt_directory_unusable");
    };
    let Ok(name) = anchored::Name::new(PROXY_DIR_NAME.as_bytes()) else {
        return ProxyDirRemoval::Retained("name_invalid");
    };
    let stat = match attempt.stat_at(&name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProxyDirRemoval::Removed;
        }
        Err(_) => return ProxyDirRemoval::Retained("proxy_directory_unreadable"),
    };
    // No recorded identity means the directory was never proven ours.
    if registered != Some(stat.identity()) || stat.kind != anchored::Kind::Directory {
        return ProxyDirRemoval::Retained("proxy_directory_identity_changed");
    }
    // The platform removed its own socket node when it stopped the proxy;
    // anything still here is not provably the jail's, so it is never
    // deleted: the directory is retained instead.
    if attempt.rmdir_at(&name).is_err() {
        return ProxyDirRemoval::Retained("proxy_directory_not_empty");
    }
    if attempt.sync().is_err() {
        return ProxyDirRemoval::Retained("sync_failed");
    }
    ProxyDirRemoval::Removed
}
// J3-agent end

/// The jail-owned names of an attempt directory (§7), which an existing
/// attempt root must not already hold before this supervisor claims it.
pub const JAIL_OWNED_NAMES: [&str; 9] = [
    "jail.lock",
    "jail-state.json",
    "policy.json",
    "jail.json",
    "trace.ndjson",
    VENDOR_STATE_NAME,
    "scratch",
    "placeholders",
    "proxy",
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
    let rows: Vec<serde_json::Value> = staged
        .iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "mode": row.mode,
                "source_dev": row.source_dev.to_string(),
                "source_ino": row.source_ino.to_string(),
                "source_size": row.source_size.to_string(),
            })
        })
        .collect();
    update_attempt_state(attempt_dir, |state| {
        state["vendor_state"]["credentials"] = serde_json::Value::from(rows);
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
    update_attempt_state(attempt_dir, |state| {
        state["state_cleanup"] = serde_json::Value::from(cleanup_word(status));
        state["cleanup_reason"] = reason.map_or(serde_json::Value::Null, serde_json::Value::from);
    })
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

    fn claimed_attempt() -> (tempfile::TempDir, AttemptDir) {
        let dir = private_tempdir();
        let data = dir.path().canonicalize().unwrap().join("data");
        let attempt = AttemptDir::new(&data, &AttemptId::generate());
        attempt.create(&data).unwrap();
        let state = serde_json::json!({
            "schema": "ouro.jail.state/1",
            "vendor_state": null,
            "state_cleanup": "not_needed",
        });
        replace_atomically(&attempt.state_path(), &serde_json::to_vec(&state).unwrap()).unwrap();
        (dir, attempt)
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
        let state = read_attempt_state(&attempt).unwrap();
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

    // J3-agent begin
    #[test]
    fn the_proxy_directory_is_registered_created_private_and_removed_by_identity() {
        use std::os::unix::fs::MetadataExt as _;
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        let metadata = std::fs::metadata(attempt.proxy_dir_path()).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o700);
        let state = read_attempt_state(&attempt).unwrap();
        assert_eq!(state["proxy_dir"]["dev"], metadata.dev().to_string());
        assert_eq!(state["proxy_dir"]["ino"], metadata.ino().to_string());
        assert_eq!(
            proxy.stat().unwrap().identity(),
            (metadata.dev(), metadata.ino())
        );
        // A leftover socket node is not provably ours: retained, not deleted.
        // Bound through the directory descriptor: macOS's 104-byte
        // `sun_path` cannot hold a temporary attempt path.
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            let _listener = std::os::unix::net::UnixListener::bind(format!(
                "/proc/self/fd/{}/{PROXY_SOCKET_NAME}",
                proxy.as_fd().as_raw_fd()
            ))
            .unwrap();
            assert_eq!(
                remove_proxy_dir(&attempt).unwrap(),
                ProxyDirRemoval::Retained("proxy_directory_not_empty")
            );
            assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
            std::fs::remove_file(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME)).unwrap();
        }
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Removed
        );
        assert!(!attempt.proxy_dir_path().exists());
        assert_eq!(
            read_attempt_state(&attempt).unwrap()["proxy_dir"]["removed"],
            true
        );
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Removed
        );
    }

    #[test]
    fn the_proxy_directory_is_registered_before_it_exists() {
        let (_dir, attempt) = claimed_attempt();
        let mut seen = None;
        let _proxy = create_proxy_dir_observed(&attempt, &mut |attempt| {
            let state = read_attempt_state(attempt).unwrap();
            seen = Some((
                state["proxy_dir"]["name"].clone(),
                state["proxy_dir"]["ino"].clone(),
                attempt.proxy_dir_path().exists(),
            ));
        })
        .unwrap();
        assert_eq!(
            seen,
            Some((serde_json::json!("proxy"), serde_json::Value::Null, false)),
            "registered, identity not yet known, directory not yet there"
        );
    }

    #[test]
    fn gc_retains_a_proxy_directory_whose_identity_was_never_recorded() {
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        update_attempt_state(&attempt, |state| {
            state["proxy_dir"]["dev"] = serde_json::Value::Null;
            state["proxy_dir"]["ino"] = serde_json::Value::Null;
        })
        .unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirGc::Retained("proxy_directory_unrecorded")
        );
        assert!(attempt.proxy_dir_path().exists());
        assert_eq!(
            read_attempt_state(&attempt).unwrap()["proxy_dir"]["retained"],
            "proxy_directory_unrecorded"
        );
        // Registered and never created (the supervisor died in between):
        // nothing to remove, and it is recorded as done.
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::remove_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(gc_proxy_dir(&attempt, false).unwrap(), ProxyDirGc::Removed);
    }

    #[cfg(target_os = "linux")]
    fn bind_in(proxy: &anchored::Dir) -> std::os::unix::net::UnixListener {
        use std::os::fd::AsRawFd as _;
        std::os::unix::net::UnixListener::bind(format!(
            "/proc/self/fd/{}/{PROXY_SOCKET_NAME}",
            proxy.as_fd().as_raw_fd()
        ))
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_removes_the_recorded_socket_node_and_the_directory_and_records_it() {
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        let name = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()).unwrap();
        let node = proxy.stat_at(&name).unwrap();
        record_proxy_socket(&attempt, &ProxySocketIdentity::of(&node)).unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, true).unwrap(),
            ProxyDirGc::WouldRemove
        );
        assert!(
            attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists(),
            "dry run"
        );
        assert_eq!(gc_proxy_dir(&attempt, false).unwrap(), ProxyDirGc::Removed);
        assert!(!attempt.proxy_dir_path().exists());
        let state = read_attempt_state(&attempt).unwrap();
        assert_eq!(state["proxy_dir"]["removed"], true);
        assert_eq!(state["proxy_dir"]["removed_by"], "gc");
        assert_eq!(gc_proxy_dir(&attempt, false).unwrap(), ProxyDirGc::Nothing);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_retains_a_socket_it_cannot_prove_it_bound() {
        // Unrecorded: the supervisor died between bind and record.
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirGc::Retained("proxy_socket_unrecorded")
        );
        assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
        // Replaced after it was recorded, by a node that may even reuse the
        // freed inode number: the change time tells them apart.
        let (_dir, attempt) = claimed_attempt();
        let proxy = create_proxy_dir(&attempt).unwrap();
        drop(bind_in(&proxy));
        let name = anchored::Name::new(PROXY_SOCKET_NAME.as_bytes()).unwrap();
        let node = proxy.stat_at(&name).unwrap();
        record_proxy_socket(&attempt, &ProxySocketIdentity::of(&node)).unwrap();
        proxy.unlink_at(&name).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        drop(bind_in(&proxy));
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirGc::Retained("proxy_socket_identity_changed")
        );
        assert!(attempt.proxy_dir_path().join(PROXY_SOCKET_NAME).exists());
        // Anything else in the directory is not the jail's to delete.
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::write(attempt.proxy_dir_path().join("other"), b"x").unwrap();
        assert_eq!(
            gc_proxy_dir(&attempt, false).unwrap(),
            ProxyDirGc::Retained("proxy_directory_holds_a_foreign_object")
        );
        assert!(attempt.proxy_dir_path().join("other").exists());
    }

    #[test]
    fn a_replaced_or_populated_proxy_directory_is_retained() {
        let (_dir, attempt) = claimed_attempt();
        drop(create_proxy_dir(&attempt).unwrap());
        std::fs::write(attempt.proxy_dir_path().join("keep"), b"not ours").unwrap();
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_not_empty")
        );
        assert!(attempt.proxy_dir_path().join("keep").exists());

        let (_dir, attempt) = claimed_attempt();
        // Held open, so the replacement cannot be handed the same inode
        // number (ext4 reuses a freed one at once).
        let _held = create_proxy_dir(&attempt).unwrap();
        std::fs::remove_dir(attempt.proxy_dir_path()).unwrap();
        std::fs::create_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::Retained("proxy_directory_identity_changed"),
            "a directory that is not the registered one is never removed"
        );
        assert!(attempt.proxy_dir_path().exists());

        let (_dir, attempt) = claimed_attempt();
        std::fs::create_dir(attempt.proxy_dir_path()).unwrap();
        assert_eq!(
            create_proxy_dir(&attempt).unwrap_err().code,
            ErrorCode::UnsafeStatePath
        );
        assert_eq!(
            remove_proxy_dir(&attempt).unwrap(),
            ProxyDirRemoval::NotRegistered
        );
        assert!(attempt.proxy_dir_path().exists(), "not ours, never removed");
    }
    // J3-agent end

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
}
