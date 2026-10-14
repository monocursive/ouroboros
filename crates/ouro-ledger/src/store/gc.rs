//! What both GC paths share: an exact inventory of the files a durable
//! anchor authorizes deleting, and the checks that open, hash and publish
//! only private members relative to pinned directories.
use std::{ffi::CString, io::Read};

use serde::{Deserialize, Serialize};

use super::*;
use crate::faults::Replaced;
use crate::fsx;

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
            return Err(LedgerError(
                "GC file was truncated during verification".into(),
            ));
        }
        hash.update(&buffer[..n]);
        remaining -= n as u64;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(LedgerError("GC file grew during verification".into()));
    }
    Ok(format!("sha256:{:x}", hash.finalize()))
}

/// Open relative to a pinned parent, never through a caller-supplied path.
pub(super) fn member(root: &Path, name: &str) -> Result<(File, CString, Option<File>)> {
    let (parent, leaf) = if let Some(leaf) = name.strip_prefix("artifacts/") {
        if !["stdout.bin", "stderr.bin", "argv.bin"].contains(&leaf) {
            return Err(LedgerError("unsafe GC capture path".into()));
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
            return Err(LedgerError("unsafe GC segment path".into()));
        }
        (root.to_owned(), name)
    };
    directory(root)?;
    let parent = directory(&parent)?;
    let leaf = CString::new(leaf).map_err(|_| LedgerError("unsafe GC filename".into()))?;
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
        return Err(LedgerError(
            "GC inventory file identity or content changed; bytes preserved".into(),
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
        return Err(LedgerError(
            "GC inventory path changed during verification".into(),
        ));
    }
    Ok((parent, leaf, true))
}

pub(super) fn read_json(path: &Path, max: usize) -> Result<Value> {
    const REFUSAL: &str = "oversized or interrupted GC metadata";
    let mut bytes = crate::protocol::read_bounded(safe_file(path)?, max as u64, REFUSAL)?;
    if bytes.pop() != Some(b'\n') {
        return Err(LedgerError(REFUSAL.into()));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if canonical(&value)? != bytes {
        return Err(LedgerError("noncanonical GC metadata".into()));
    }
    Ok(value)
}

pub(super) fn publish(root: &Path, name: &str, value: &Value, max: usize) -> Result<()> {
    let mut bytes = canonical(value)?;
    if bytes.len() + 1 > max {
        return Err(LedgerError(
            "GC retained metadata exceeds its bounded size; no files removed".into(),
        ));
    }
    // Never replace an existing authority or completion marker.
    if fs::symlink_metadata(root.join(name)).is_ok() {
        if read_json(&root.join(name), max)? != *value {
            return Err(LedgerError("existing GC metadata conflicts".into()));
        }
        safe_file(&root.join(name))?.sync_all()?;
        directory(root)?.sync_all()?;
        return Ok(());
    }
    // The process-lifetime writer lock serializes publication. A temporary
    // file never becomes authority until its atomic rename is visible.
    bytes.push(b'\n');
    let name = CString::new(name).map_err(|_| LedgerError("unsafe GC filename".into()))?;
    fsx::replace(
        &directory(root)?,
        &fsx::temporary("gc"),
        &name,
        &bytes,
        Replaced::GcRecord,
    )
}
