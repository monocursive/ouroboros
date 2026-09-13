//! A sibling staging file and a permanent advisory lock. Rename is the only
//! operation that changes the installed binary; everything before it may fail.
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{bail, Context, Result};
use rand::TryRngCore;
use ring::digest::{Context as Digest, SHA256};

use super::transport::check_cancelled;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn random_suffix() -> Result<String> {
    let mut bytes = [0; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("random staging name: {e}"))?;
    Ok(hex(&bytes))
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
    links: u64,
}
impl From<&Metadata> for Identity {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.len(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
            links: m.nlink(),
        }
    }
}

pub(super) struct Destination {
    pub path: PathBuf,
    identity: Identity,
    digest: Vec<u8>,
    parent: File,
}

impl Destination {
    pub fn inspect(path: &Path, cancelled: &AtomicBool) -> Result<Self> {
        let path = path
            .canonicalize()
            .context("resolving installed executable")?;
        if path.starts_with("/nix/store") || path.components().any(|p| p.as_os_str() == "Cellar") {
            bail!(
                "{} is a package-managed installation; use its package manager",
                path.display()
            );
        }
        let parent_path = path
            .parent()
            .context("executable has no parent directory")?;
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)?;
        validate_parent(&parent.metadata()?)?;
        let mut file = open_existing(&path)?;
        let metadata = file.metadata()?;
        validate_file(&metadata)?;
        if metadata.mode() & 0o111 == 0 {
            bail!("destination is not executable");
        }
        let identity = Identity::from(&metadata);
        let digest = digest_file(&mut file, cancelled)?;
        if identity != Identity::from(&file.metadata()?) {
            bail!("executable changed during inspection; retry");
        }
        let destination = Self {
            path,
            identity,
            digest,
            parent,
        };
        destination.revalidate(cancelled)?;
        Ok(destination)
    }

    pub fn lock(&self) -> Result<File> {
        self.validate_parent()?;
        let key = ring::digest::digest(&SHA256, self.path.file_name().unwrap().as_bytes());
        let path = self
            .path
            .with_file_name(format!(".ouro-update-{}.lock", hex(key.as_ref())));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| {
                format!(
                    "opening update lock beside {}; check directory permissions",
                    self.path.display()
                )
            })?;
        let metadata = lock.metadata()?;
        validate_file(&metadata)?;
        if metadata.mode() & 0o077 != 0 || metadata.len() != 0 {
            bail!(
                "update lock must be an empty private file: {}",
                path.display()
            );
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                bail!(
                    "an update is already in progress for {}; retry when it finishes",
                    self.path.display()
                );
            }
            return Err(error).context("locking update destination");
        }
        if Identity::from(&fs::symlink_metadata(&path)?) != Identity::from(&lock.metadata()?) {
            bail!("update lock changed; refusing replacement");
        }
        Ok(lock)
    }

    fn validate_parent(&self) -> Result<()> {
        let actual = fs::symlink_metadata(self.path.parent().unwrap())?;
        let held = self.parent.metadata()?;
        validate_parent(&actual)?;
        if (actual.dev(), actual.ino()) != (held.dev(), held.ino()) {
            bail!("installation directory changed; retry");
        }
        Ok(())
    }

    pub fn revalidate(&self, cancelled: &AtomicBool) -> Result<()> {
        check_cancelled(cancelled)?;
        self.validate_parent()?;
        let mut file = open_existing(&self.path)?;
        if Identity::from(&file.metadata()?) != self.identity
            || digest_file(&mut file, cancelled)? != self.digest
            || Identity::from(&file.metadata()?) != self.identity
        {
            bail!("installed executable changed during update; rerun the installed command");
        }
        Ok(())
    }

    pub fn stage(&self) -> Result<Stage> {
        self.validate_parent()?;
        let path = self
            .path
            .with_file_name(format!(".ouro-update-{}.tmp", random_suffix()?));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .context("creating update staging file; check free space and directory permissions")?;
        Ok(Stage {
            path,
            file: Some(file),
        })
    }

    pub fn seal(&self, stage: &mut Stage) -> Result<()> {
        let file = stage.file.take().context("staging file already sealed")?;
        file.set_permissions(Permissions::from_mode(self.identity.mode & 0o777))?;
        file.sync_all()
            .context("synchronizing verified executable")?;
        // Close every writable descriptor before executing on Linux (ETXTBSY).
        drop(file);
        Ok(())
    }

    pub fn commit(&self, stage: &Stage, cancelled: &AtomicBool) -> Result<Option<String>> {
        self.commit_with_sync(stage, cancelled, || self.parent.sync_all())
    }

    pub(super) fn commit_with_sync(
        &self,
        stage: &Stage,
        cancelled: &AtomicBool,
        sync: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<Option<String>> {
        self.revalidate(cancelled)?;
        check_cancelled(cancelled)?;
        fs::rename(&stage.path, &self.path)
            .context("replacing executable; existing installation was not changed")?;
        // Commit has happened. Never represent a later failure as an untouched file.
        Ok(sync().err().map(|e| {
            format!("the new executable is installed, but directory synchronization failed: {e}")
        }))
    }
}

fn validate_parent(metadata: &Metadata) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || (metadata.uid() != uid && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
    {
        bail!(
            "installation directory must be owned by you or root and not writable by other users"
        );
    }
    Ok(())
}

fn validate_file(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o6022 != 0
        || metadata.nlink() != 1
    {
        bail!("update requires a regular executable owned by you, without hard links, set-ID bits, or writes by other users");
    }
    Ok(())
}

fn open_existing(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening installed executable {}", path.display()))
}

fn digest_file(file: &mut File, cancelled: &AtomicBool) -> Result<Vec<u8>> {
    let mut digest = Digest::new(&SHA256);
    let mut bytes = [0; 64 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let n = file.read(&mut bytes)?;
        if n == 0 {
            return Ok(digest.finish().as_ref().to_vec());
        }
        digest.update(&bytes[..n]);
    }
}

pub(super) struct Stage {
    pub path: PathBuf,
    pub file: Option<File>,
}
impl Stage {
    pub fn reset(&mut self) -> Result<&mut File> {
        let file = self.file.as_mut().context("staging file is sealed")?;
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(super) struct HashWriter<W> {
    pub writer: W,
    pub digest: Digest,
}
impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self.writer.write(bytes)?;
        self.digest.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
