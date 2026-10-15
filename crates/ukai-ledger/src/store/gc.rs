//! What both GC paths share: an exact inventory of the files a durable
//! anchor authorizes deleting, and the checks that open, hash and publish
//! only private members relative to pinned directories.
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{fd::AsRawFd as _, unix::fs::MetadataExt as _},
    path::Path,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use super::{Store, canonical, digest, stream::Stream};
use crate::{
    faults::{self, Point, Replaced},
    fsx, manifest,
    protocol::{LedgerError, Result},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemovedFile {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) digest: String,
    pub(super) device: u64,
    pub(super) inode: u64,
}

/// GC only ever reads, publishes or unlinks private members.
const UNSAFE_DIRECTORY: &str = "GC requires owned private directories";
const UNSAFE_FILE: &str = "GC refuses unsafe or linked files";

pub(super) fn directory(path: &Path) -> Result<File> {
    fsx::open_dir(path, UNSAFE_DIRECTORY)
}

pub(super) fn safe_file(path: &Path) -> Result<File> {
    fsx::read_file(path, UNSAFE_FILE)
}

pub(super) fn file_hash(file: &mut File, bytes: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut remaining = bytes;
    let mut buffer = [0u8; 65_536];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let n = file.read(&mut buffer[..limit])?;
        if n == 0 {
            return Err(LedgerError::refused(
                "GC file was truncated during verification",
            ));
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(LedgerError::refused("GC file grew during verification"));
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Open relative to a pinned parent, never through a caller-supplied path.
pub(super) fn member(root: &Path, name: &str) -> Result<(File, CString, Option<File>)> {
    let (parent, leaf) = if let Some(leaf) = name.strip_prefix("artifacts/") {
        if !["stdout.bin", "stderr.bin", "argv.bin"].contains(&leaf) {
            return Err(LedgerError::refused("unsafe GC capture path"));
        }
        (root.join("artifacts"), leaf)
    } else {
        let number = name
            .strip_prefix("events-")
            .and_then(|s| s.strip_suffix(".ndjson"))
            .and_then(|s| s.parse::<usize>().ok());
        if !number
            .is_some_and(|i| (1..=manifest::MAX_SEGMENTS).contains(&i) && name == manifest::name(i))
        {
            return Err(LedgerError::refused("unsafe GC segment path"));
        }
        (root.to_owned(), name)
    };
    directory(root)?;
    let parent = directory(&parent)?;
    let leaf = CString::new(leaf).map_err(|_| LedgerError::refused("unsafe GC filename"))?;
    let file = fsx::find_file_at(&parent, &leaf, UNSAFE_FILE)?;
    Ok((parent, leaf, file))
}

pub(super) fn check_member(root: &Path, entry: &RemovedFile) -> Result<(File, CString, bool)> {
    let (parent, leaf, file) = member(root, &entry.path)?;
    let Some(mut file) = file else {
        return Ok((parent, leaf, false));
    };
    let metadata = file.metadata()?;
    if metadata.dev() != entry.device
        || metadata.ino() != entry.inode
        || metadata.len() != entry.bytes
        || file_hash(&mut file, entry.bytes)? != entry.digest
    {
        return Err(LedgerError::refused(
            "GC inventory file identity or content changed; bytes preserved",
        ));
    }
    // Check the namespace again after hashing, before unlinking through the same parent.
    // SAFETY: libc::stat is plain integer fields, for which all-zero is valid.
    let mut current: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: pointers reference a live name and writable stat buffer.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut current,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if i128::from(current.st_dev) != i128::from(metadata.dev())
        || i128::from(current.st_ino) != i128::from(metadata.ino())
    {
        return Err(LedgerError::refused(
            "GC inventory path changed during verification",
        ));
    }
    Ok((parent, leaf, true))
}

pub(super) fn read_json(path: &Path, max: usize) -> Result<Value> {
    const REFUSAL: &str = "oversized or interrupted GC metadata";
    let mut bytes = crate::protocol::read_bounded(safe_file(path)?, max as u64, REFUSAL)?;
    if bytes.pop() != Some(b'\n') {
        return Err(LedgerError::refused(REFUSAL));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if canonical(&value)? != bytes {
        return Err(LedgerError::refused("noncanonical GC metadata"));
    }
    Ok(value)
}

pub(super) fn publish(root: &Path, name: &str, value: &Value, max: usize) -> Result<()> {
    let mut bytes = canonical(value)?;
    if bytes.len() + 1 > max {
        return Err(LedgerError::refused(
            "GC retained metadata exceeds its bounded size; no files removed",
        ));
    }
    // Never replace an existing authority or completion marker.
    if fs::symlink_metadata(root.join(name)).is_ok() {
        if read_json(&root.join(name), max)? != *value {
            return Err(LedgerError::refused("existing GC metadata conflicts"));
        }
        safe_file(&root.join(name))?.sync_all()?;
        directory(root)?.sync_all()?;
        return Ok(());
    }
    // The process-lifetime writer lock serializes publication. A temporary
    // file never becomes authority until its atomic rename is visible.
    bytes.push(b'\n');
    let name = CString::new(name).map_err(|_| LedgerError::refused("unsafe GC filename"))?;
    fsx::replace(
        &directory(root)?,
        &fsx::temporary("gc"),
        &name,
        &bytes,
        Replaced::GcRecord,
    )
}

/// A durable GC authority: an anchor naming the exact files one collection
/// may delete, published before any deletion, and the completion marker
/// published after the last one. Both GC paths delete through [`finish`],
/// so any hardening of the deletion protocol lands once.
pub(super) trait Authority: Serialize + DeserializeOwned {
    /// The anchor's and the completion marker's names in the run directory.
    const ANCHOR: &'static str;
    const DONE: &'static str;
    /// The anchor's size bound.
    const MAX_ANCHOR: usize;
    /// The completion marker's schema.
    const COMPLETE_SCHEMA: &'static str;
    /// Refusals, as each path words them: a completion without its anchor,
    /// an anchor whose checksum or encoding is wrong, an anchor that
    /// vanished or changed while this writer held it, and a completion that
    /// names another anchor.
    const ORPHANED: &'static str;
    const CORRUPT: &'static str;
    const VANISHED: &'static str;
    const CHANGED: &'static str;
    const MISMATCH: &'static str;

    /// The files this authority allows deleting.
    fn files(&self) -> &[RemovedFile];

    /// Refuse an authority that this run could not have produced.
    fn validate(&self, root: &Path, id: &str) -> Result<()>;

    /// Refuse a run directory whose remaining files contradict the
    /// authority; once `complete`, no inventoried file may exist.
    fn check_remaining(&self, root: &Path, complete: bool) -> Result<()>;

    fn digest(&self) -> Result<String> {
        digest(&serde_json::to_value(self)?)
    }

    fn completion(&self) -> Result<Value> {
        Ok(json!({"schema":Self::COMPLETE_SCHEMA,"anchor_digest":self.digest()?}))
    }

    /// Whether this authority's completion marker is published.
    fn complete(&self, root: &Path) -> Result<bool> {
        match fs::symlink_metadata(root.join(Self::DONE)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
            Ok(_) => {
                if read_json(&root.join(Self::DONE), DONE_BYTES)? != self.completion()? {
                    return Err(LedgerError::refused(Self::MISMATCH));
                }
                Ok(true)
            }
        }
    }
}

/// The bound on a completion marker: a schema id and one digest.
const DONE_BYTES: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<A> {
    digest: String,
    retained: A,
}

/// The authority published in `root`, if any, exactly as published and
/// valid for run `id`.
pub(super) fn read<A: Authority>(root: &Path, id: &str) -> Result<Option<A>> {
    directory(root)?;
    match fs::symlink_metadata(root.join(A::ANCHOR)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(root.join(A::DONE)).is_ok() {
                return Err(LedgerError::refused(A::ORPHANED));
            }
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let value = read_json(&root.join(A::ANCHOR), A::MAX_ANCHOR)?;
    let envelope: Envelope<A> = serde_json::from_value(value.clone())?;
    if envelope.digest != envelope.retained.digest()? || serde_json::to_value(&envelope)? != value {
        return Err(LedgerError::refused(A::CORRUPT));
    }
    envelope.retained.validate(root, id)?;
    Ok(Some(envelope.retained))
}

/// Publish `retained` as the run's authority. Until this returns, nothing
/// may be deleted; if it fails, whether the anchor is durable is unknown.
pub(super) fn publish_anchor<A: Authority>(root: &Path, retained: &A) -> Result<()> {
    let value = serde_json::to_value(Envelope {
        digest: retained.digest()?,
        retained,
    })?;
    publish(root, A::ANCHOR, &value, A::MAX_ANCHOR)
}

/// The deletion protocol, resumable from any crash. The published anchor
/// must still be `retained`; each inventoried file is re-identified and
/// re-hashed, then unlinked by name in its pinned parent; the completion
/// marker is published only after every namespace is synchronized.
pub(super) fn finish<A: Authority>(root: &Path, id: &str, retained: &A) -> Result<()> {
    let current = read::<A>(root, id)?.ok_or_else(|| LedgerError::refused(A::VANISHED))?;
    if current.digest()? != retained.digest()? {
        return Err(LedgerError::refused(A::CHANGED));
    }
    let complete = retained.complete(root)?;
    retained.check_remaining(root, complete)?;
    // A visible anchor after an interrupted rename is not a completed durability barrier.
    safe_file(&root.join(A::ANCHOR))?.sync_all()?;
    directory(root)?.sync_all()?;
    if !complete {
        for entry in retained.files() {
            let (parent, name, exists) = check_member(root, entry)?;
            if !exists {
                continue;
            }
            faults::hit(Point::GcBeforeUnlink)?;
            // Only this verified name in its still-pinned parent; a file
            // that vanished since its check is a change, never a success.
            if !fsx::unlink_at(&parent, &name)? {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT).into());
            }
            faults::hit(Point::GcAfterUnlink)?;
            parent.sync_all()?;
            faults::hit(Point::GcDirectorySync)?;
        }
        // Sync both namespaces even if a preceding unlink survived a crash.
        directory(&root.join("artifacts"))?.sync_all()?;
        directory(root)?.sync_all()?;
        faults::hit(Point::GcCompletion)?;
    }
    publish(root, A::DONE, &retained.completion()?, DONE_BYTES)?;
    faults::hit(Point::GcCompletionSync)?;
    Ok(())
}

impl Store {
    /// The run re-read from its canonical bytes, if it is exactly what this
    /// writer accepted, unheld, and last active no later than `cutoff`.
    /// Anything else refuses with `refusal` before any authority exists.
    pub(super) fn verified_for_gc(&self, id: &str, cutoff: &str, refusal: &str) -> Result<Stream> {
        let verified = self.load_stream_with_sync(id, &File::sync_all)?.0;
        let live = self.stream(id)?;
        if verified.is_poisoned()
            || verified.manifest() != live.manifest()
            || serde_json::to_value(verified.run())? != serde_json::to_value(live.run())?
            || verified.replay() != live.replay()
            || !verified.run().holds.is_empty()
            || !verified.retention_time_valid()
            || verified.last_activity_at().is_none_or(|t| t > cutoff)
        {
            return Err(LedgerError::refused(refusal));
        }
        Ok(verified)
    }
}
