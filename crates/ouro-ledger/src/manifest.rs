//! Durable anchors for the canonical segment and its replay identities.
//! A manifest can lag an unacknowledged append; its committed prefix cannot change.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use ouro_records::canonical::to_jcs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::protocol::{LedgerError, Result};

pub(crate) const NAME: &str = "segments.json";
pub(crate) const STREAM: &str = "events-0001.ndjson";
const MAX_BYTES: u64 = 4096;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub schema: String,
    pub run_id: String,
    pub attempt_id: String,
    pub segment: Segment,
    pub replay_digest: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Segment {
    pub name: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub bytes: u64,
    pub digest: String,
    pub head_digest: String,
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn safe_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(LedgerError("unsafe segment manifest".into()));
    }
    Ok(file)
}

pub(crate) fn read(directory: &Path, run_id: &str) -> Result<Option<Manifest>> {
    let path = directory.join(NAME);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let mut bytes = Vec::new();
    safe_file(&path)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES || bytes.last() != Some(&b'\n') {
        return Err(LedgerError(
            "oversized or interrupted segment manifest".into(),
        ));
    }
    bytes.pop();
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    let value = serde_json::to_value(&manifest)?;
    if to_jcs(&value).map_err(|e| LedgerError(e.to_string()))? != bytes
        || manifest.schema != "ouro.ledger.segments/1"
        || manifest.run_id != run_id
        || manifest.segment.name != STREAM
        || manifest.segment.first_seq != 1
        || manifest.segment.last_seq == 0
        || manifest.segment.bytes == 0
        || !digest(&manifest.segment.digest)
        || !digest(&manifest.segment.head_digest)
        || !digest(&manifest.replay_digest)
    {
        return Err(LedgerError(
            "segment manifest identity or canonical encoding mismatch".into(),
        ));
    }
    Ok(Some(manifest))
}

pub(crate) fn write(directory: &Path, manifest: &Manifest) -> Result<()> {
    let target = directory.join(NAME);
    match fs::symlink_metadata(&target) {
        Ok(_) => {
            safe_file(&target)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let bytes = to_jcs(&serde_json::to_value(manifest)?).map_err(|e| LedgerError(e.to_string()))?;
    if bytes.len() as u64 + 1 > MAX_BYTES {
        return Err(LedgerError("segment manifest exceeds bounded size".into()));
    }
    let temp = directory.join(format!(".segments-{}.tmp", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp, &target)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
