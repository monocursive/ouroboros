//! The attempt lease, `jail.lock` (§7).

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use super::{FILE_MODE, check_state_file, unsafe_path, write_failed};
use crate::records::JailError;

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
