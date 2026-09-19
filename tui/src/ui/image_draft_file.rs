//! Private, atomic draft snapshots. A separate flock keeps simultaneous clients apart.
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
};

const LIMIT: u64 = 8 * 1024 * 1024;
pub struct DraftFile {
    path: PathBuf,
    lock: File,
    previous: Vec<u8>,
}
/// Releases the slot the moment the owner lets go of it.
///
/// A flock belongs to the open file description, and every child this process forks
/// inherits a reference to it until its exec closes the CLOEXEC descriptor. Closing our
/// own descriptor therefore leaves the slot locked for as long as any child is still
/// between fork and exec, and a client reopening in that window would fall through to
/// an empty slot instead of recovering. An explicit unlock releases the description
/// itself, so the drop is what frees the slot rather than the last close.
impl Drop for DraftFile {
    fn drop(&mut self) {
        // SAFETY: flock operates on this live descriptor and holds no Rust references.
        unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN) };
    }
}
impl DraftFile {
    /// Only an authenticated runtime can identify the recovery store. Older runtimes
    /// without a stable namespace use memory-only drafts instead of a token-derived key.
    pub fn namespace(limits: &Value) -> Option<&str> {
        let value = limits["client_recovery_namespace"].as_str()?;
        (limits["client_draft_persistence"] == "private"
            && value.len() == 64
            && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(value)
    }

    pub fn open(directory: &Path, namespace: &str) -> Result<(Self, Option<Value>)> {
        let root = directory.join("image-drafts").join(namespace);
        crate::runtime::ensure_private_data_dir(&root)?;
        let mut names: Vec<PathBuf> = fs::read_dir(&root)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .take(128)
            .collect();
        names.sort_by_key(|path| {
            std::cmp::Reverse(fs::metadata(path).and_then(|m| m.modified()).ok())
        });
        names.push(root.join(format!(
                "{}-{}.json",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos()
            )));
        for path in names {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path.with_extension("lock"))?;
            // SAFETY: flock operates on this live descriptor and holds no Rust references.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                continue;
            }
            let mut bytes = Vec::new();
            if let Ok(file) = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
            {
                anyhow::ensure!(file.metadata()?.is_file(), "Invalid draft file");
                file.take(LIMIT + 1).read_to_end(&mut bytes)?;
            }
            anyhow::ensure!(
                bytes.len() as u64 <= LIMIT,
                "Image draft recovery file is too large"
            );
            let value = if bytes.is_empty() {
                None
            } else {
                Some(serde_json::from_slice(&bytes).context("Invalid image draft recovery file")?)
            };
            return Ok((
                Self {
                    path,
                    lock,
                    previous: bytes,
                },
                value,
            ));
        }
        anyhow::bail!("No private image draft slot is available")
    }
    pub fn save(&mut self, value: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes == self.previous {
            return Ok(());
        }
        anyhow::ensure!(
            bytes.len() as u64 <= LIMIT,
            "Image draft recovery exceeds 8 MiB"
        );
        let temp = self.path.with_extension("pending");
        let _ = fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        self.previous = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn runtime_namespace_recovers_a_snapshot_and_refuses_unscoped_or_ephemeral_limits() {
        let root =
            std::env::temp_dir().join(format!("ouro-drafts-namespace-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let limits = serde_json::json!({"client_draft_persistence":"private", "client_recovery_namespace":"a".repeat(64)});
        let namespace = DraftFile::namespace(&limits).unwrap();
        let (mut before, _) = DraftFile::open(&root, namespace).unwrap();
        let snapshot = serde_json::json!({"pending":[{"turn_id":"original-turn", "input":{"prompt":"preserve me"}}]});
        before.save(&snapshot).unwrap();
        drop(before);
        // The runtime sends the same namespace after token rotation; the credential
        // itself is never an input to the cache path.
        let (after, recovered) =
            DraftFile::open(&root, DraftFile::namespace(&limits).unwrap()).unwrap();
        assert_eq!(recovered, Some(snapshot));
        assert!(
            DraftFile::namespace(&serde_json::json!({"client_draft_persistence":"private"}))
                .is_none()
        );
        assert!(DraftFile::namespace(&serde_json::json!({"client_draft_persistence":"ephemeral", "client_recovery_namespace":"a".repeat(64)})).is_none());
        drop(after);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn recovery_is_private_atomic_and_exclusive_between_live_clients() {
        let root = std::env::temp_dir().join(format!("ouro-drafts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (mut first, value) = DraftFile::open(&root, "identity").unwrap();
        assert!(value.is_none());
        let draft = serde_json::json!({"version":1, "drafts":[{"id":"unsent"}]});
        first.save(&draft).unwrap();
        assert_eq!(
            fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (second, _) = DraftFile::open(&root, "identity").unwrap();
        assert_ne!(first.path, second.path);
        drop(first);
        let (recovered, value) = DraftFile::open(&root, "identity").unwrap();
        assert_eq!(value, Some(draft));
        drop(recovered);
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }
}
