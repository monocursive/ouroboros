//! Durable anchors for ordered canonical segments and their replay identities.
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
pub(crate) const MAX_SEGMENTS: usize = 4096;
const MAX_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) fn name(number: usize) -> String {
    format!("events-{number:04}.ndjson")
}

/// Enumeration never guesses across a gap or silently ignores a segment.
pub(crate) fn names(directory: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name();
        if name.as_encoded_bytes().starts_with(b"events-") {
            names.push(
                name.into_string()
                    .map_err(|_| LedgerError("invalid segment name".into()))?,
            );
            if names.len() > MAX_SEGMENTS {
                return Err(LedgerError("segment count exceeds bounded limit".into()));
            }
        }
    }
    names.sort();
    if names.is_empty() || names.iter().enumerate().any(|(i, n)| *n != name(i + 1)) {
        return Err(LedgerError(
            "missing, reordered or invalid canonical segments".into(),
        ));
    }
    Ok(names)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub schema: String,
    pub run_id: String,
    pub attempt_id: String,
    pub segments: Vec<Segment>,
    pub replay_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Segment {
    pub name: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub bytes: u64,
    pub digest: String,
    pub head_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    schema: String,
    run_id: String,
    attempt_id: String,
    segment: Segment,
    replay_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Wire {
    Current(Manifest),
    Legacy(Legacy),
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
    let wire: Wire = serde_json::from_slice(&bytes)?;
    let value = serde_json::to_value(&wire)?;
    let manifest = match wire {
        Wire::Current(m) if m.schema == "ouro.ledger.segments/2" => m,
        Wire::Legacy(m) if m.schema == "ouro.ledger.segments/1" => Manifest {
            schema: "ouro.ledger.segments/2".into(),
            run_id: m.run_id,
            attempt_id: m.attempt_id,
            segments: vec![m.segment],
            replay_digest: m.replay_digest,
        },
        _ => return Err(LedgerError("unsupported segment manifest version".into())),
    };
    let mut next_seq = Some(1);
    let valid_segments = !manifest.segments.is_empty()
        && manifest.segments.len() <= MAX_SEGMENTS
        && manifest.segments.iter().enumerate().all(|(i, s)| {
            let valid = s.name == name(i + 1)
                && Some(s.first_seq) == next_seq
                && s.last_seq >= s.first_seq
                && s.bytes > 0
                && digest(&s.digest)
                && digest(&s.head_digest);
            next_seq = s.last_seq.checked_add(1);
            valid
        });
    if to_jcs(&value).map_err(|e| LedgerError(e.to_string()))? != bytes
        || manifest.run_id != run_id
        || !valid_segments
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
