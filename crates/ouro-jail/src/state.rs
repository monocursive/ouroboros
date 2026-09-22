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

/// Checks that `path` is a private directory this operator owns (§6.2).
///
/// Rejects a symlinked state root, foreign ownership and a mode that lets
/// anyone else read or write it.
///
/// # Errors
/// Returns [`ErrorCode::UnsafeStatePath`] on any of those conditions.
pub fn check_state_dir(path: &Path) -> Result<(), JailError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| unsafe_path(path, format!("cannot be inspected: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_path(path, "a state directory may not be a symlink"));
    }
    if !metadata.is_dir() {
        return Err(unsafe_path(path, "is not a directory"));
    }
    check_owner_and_mode(path, &metadata, DIRECTORY_MODE)
}

fn check_owner_and_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
    expected: u32,
) -> Result<(), JailError> {
    use std::os::unix::fs::MetadataExt as _;
    // SAFETY: `geteuid` reads this process's effective uid. It takes no
    // argument, touches no memory and cannot fail.
    let effective = unsafe { libc::geteuid() };
    if metadata.uid() != effective {
        return Err(unsafe_path(
            path,
            format!(
                "is owned by uid {} rather than this operator ({effective})",
                metadata.uid()
            ),
        ));
    }
    let mode = metadata.mode() & 0o777;
    if mode & !expected != 0 {
        return Err(unsafe_path(
            path,
            format!("has mode {mode:04o}; {expected:04o} or stricter is required"),
        ));
    }
    Ok(())
}

/// A pending durable replacement: written and synced, not yet renamed.
///
/// Dropping it without [`TempWrite::commit`] leaves the target file exactly as
/// it was, which is the "either the old or the new file" property of R02.
#[derive(Debug)]
pub struct TempWrite {
    temp: PathBuf,
    target: PathBuf,
    committed: bool,
}

impl TempWrite {
    /// Creates the temporary file beside `target`, writes `bytes` and syncs it.
    ///
    /// # Errors
    /// Returns [`ErrorCode::StateWriteFailed`] when the file cannot be created,
    /// written or synced.
    pub fn create(target: &Path, bytes: &[u8]) -> Result<Self, JailError> {
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
        file.sync_all()
            .map_err(|error| write_failed(&temp, &error))?;
        Ok(TempWrite {
            temp,
            target: target.to_path_buf(),
            committed: false,
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
        File::open(directory)
            .and_then(|handle| handle.sync_all())
            .map_err(|error| write_failed(directory, &error))?;
        Ok(())
    }
}

impl Drop for TempWrite {
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
    TempWrite::create(target, bytes)?.commit()
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

#[cfg(test)]
mod tests {
    use super::*;

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
