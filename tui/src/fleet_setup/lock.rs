//! Process-scoped locks for an entire deployment and for worker publication.
//! Keep the inode on disk: unlinking an advisory lock lets another caller lock a
//! different inode while the first caller still owns the old one.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Who currently holds `operation.lock`. Written in place after acquire so a waiter
/// can name the holder without racing the inode.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Holder {
    operation: String,
    state: String,
    since: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    machine: Option<String>,
}

pub struct Lock(File);

impl std::fmt::Debug for Lock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Lock")
    }
}

impl Lock {
    pub fn acquire(data_dir: &Path, name: &str) -> Result<Self> {
        Self::lock_file(data_dir, name, None)
    }

    /// The issuer-wide mutation lock. Inspection, host trust, authentication and review
    /// run without it; the engine takes it at the first mutating step.
    pub fn acquire_issuer(
        data_dir: &Path,
        operation: &str,
        state: &str,
        machine: Option<&str>,
    ) -> Result<Self> {
        let holder = Holder {
            operation: operation.to_string(),
            state: state.to_string(),
            since: super::utc_timestamp()?,
            machine: machine
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string),
        };
        Self::lock_file(data_dir, "operation.lock", Some(&holder))
    }

    /// Whether an advisory lock of this name is currently held. Does not create the file.
    pub fn held(data_dir: &Path, name: &str) -> bool {
        let path = super::deploy_dir(data_dir).join(name);
        let Ok(file) = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        else {
            return false;
        };
        // SAFETY: the descriptor is owned here for the duration of the probe.
        let blocked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0;
        if !blocked {
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        blocked
    }

    fn lock_file(data_dir: &Path, name: &str, holder: Option<&Holder>) -> Result<Self> {
        let path = super::ensure_deploy_dir(data_dir)?.join(name);
        let mut file = OpenOptions::new()
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
                "lock_unusable",
                format!(
                    "{} is not a private regular file owned by this account at mode 0600, so it cannot be used as a deployment lock",
                    path.display()
                ),
            );
        }
        // SAFETY: the descriptor is owned here for the entire hold.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == Some(libc::EAGAIN)
                || error.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return refuse_in_progress(&mut file);
            }
            return Err(error).with_context(|| format!("locking {}", path.display()));
        }
        if let Some(holder) = holder {
            write_holder(&mut file, holder)?;
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

fn write_holder(file: &mut File, holder: &Holder) -> Result<()> {
    let bytes = serde_json::to_vec(holder).context("encoding the operation lock holder")?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn refuse_in_progress<T>(file: &mut File) -> Result<T> {
    let detail = match read_holder(file) {
        Some(holder) => match holder.machine {
            Some(machine) if !machine.is_empty() => format!(
                "operation {} ({} for {machine}) holds the issuer; finish, resume or cancel it first",
                holder.operation, holder.state
            ),
            _ => format!(
                "operation {} ({}) holds the issuer; finish, resume or cancel it first",
                holder.operation, holder.state
            ),
        },
        None => {
            "another deployment is using this data directory; finish it or resume it before starting another"
                .to_string()
        }
    };
    super::refuse("operation_in_progress", detail)
}

fn read_holder(file: &mut File) -> Option<Holder> {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_string(&mut text).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    serde_json::from_str(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQUENCE: AtomicU32 = AtomicU32::new(0);

    fn scratch(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ouro-lock-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("a private scratch directory");
        path
    }

    #[test]
    fn a_non_private_lock_file_is_unusable_rather_than_in_progress() {
        let data = scratch("mode");
        super::super::ensure_deploy_dir(&data).expect("a deploy directory");
        let path = super::super::deploy_dir(&data).join("operation.lock");
        std::fs::write(&path, b"{}").expect("a lock file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("a world-readable lock file");
        let error = Lock::acquire(&data, "operation.lock").expect_err("a loose lock");
        assert_eq!(super::super::reason_of(&error), Some("lock_unusable"));
    }

    #[test]
    fn a_waiter_is_told_which_operation_holds_the_issuer() {
        let data = scratch("holder");
        let _held = Lock::acquire_issuer(&data, "op-00000000abcd", "deploying", Some("vps"))
            .expect("the first lock");
        let error = Lock::acquire_issuer(&data, "op-00000000ef01", "inspecting", Some("buildbox"))
            .expect_err("the second lock");
        assert_eq!(
            super::super::reason_of(&error),
            Some("operation_in_progress")
        );
        let detail = format!("{error:#}");
        assert!(
            detail.contains("operation op-00000000abcd (deploying for vps) holds the issuer"),
            "{detail}"
        );
    }
}
