//! Process-scoped locks for an entire deployment and for worker publication.
//! Keep the inode on disk: unlinking an advisory lock lets another caller lock a
//! different inode while the first caller still owns the old one.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

pub struct Lock(File);

impl Lock {
    pub fn acquire(data_dir: &Path, name: &str) -> Result<Self> {
        let path = super::ensure_deploy_dir(data_dir)?.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("opening deployment lock {}", path.display()))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return super::refuse(
                "operation_in_progress",
                "the deployment lock is not a private regular file",
            );
        }
        // SAFETY: the descriptor is owned here for the entire hold.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return super::refuse("operation_in_progress", "another deployment is using this data directory; finish it or resume it before starting another");
        }
        Ok(Self(file))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
