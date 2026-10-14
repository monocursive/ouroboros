//! Durable anchors for ordered canonical segments and their replay identities.
//! A manifest can lag an unacknowledged append; its committed prefix cannot change.

use std::{
    ffi::CStr,
    fs::{self, File},
    path::Path,
};

use ouro_records::canonical::to_jcs;
use serde::{Deserialize, Serialize};

use crate::{
    faults::Replaced,
    fsx,
    protocol::{LedgerError, Result, read_bounded, sha256_digest},
    schemas,
};

const MEMBER: &CStr = c"segments.json";
pub(crate) const NAME: &str = fsx::text(MEMBER);
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

/// Refused for any manifest that is not a private file.
const UNSAFE: &str = "unsafe segment manifest";

pub(crate) fn read(directory: &Path, run_id: &str) -> Result<Option<Manifest>> {
    let path = directory.join(NAME);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    const REFUSAL: &str = "oversized or interrupted segment manifest";
    let mut bytes = read_bounded(fsx::read_file(&path, UNSAFE)?, MAX_BYTES, REFUSAL)?;
    if bytes.last() != Some(&b'\n') {
        return Err(LedgerError(
            "oversized or interrupted segment manifest".into(),
        ));
    }
    bytes.pop();
    let wire: Wire = serde_json::from_slice(&bytes)?;
    let value = serde_json::to_value(&wire)?;
    let manifest = match wire {
        Wire::Current(m) if m.schema == schemas::SEGMENTS => m,
        Wire::Legacy(m) if m.schema == schemas::SEGMENTS_V1 => Manifest {
            schema: schemas::SEGMENTS.into(),
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
                && sha256_digest(&s.digest)
                && sha256_digest(&s.head_digest);
            next_seq = s.last_seq.checked_add(1);
            valid
        });
    if to_jcs(&value).map_err(|e| LedgerError(e.to_string()))? != bytes
        || manifest.run_id != run_id
        || !valid_segments
        || !sha256_digest(&manifest.replay_digest)
    {
        return Err(LedgerError(
            "segment manifest identity or canonical encoding mismatch".into(),
        ));
    }
    Ok(Some(manifest))
}

/// The exact published bytes: canonical JSON and one LF, within the bound.
pub(crate) fn encode(manifest: &Manifest) -> Result<Vec<u8>> {
    let mut bytes =
        to_jcs(&serde_json::to_value(manifest)?).map_err(|e| LedgerError(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_BYTES {
        return Err(LedgerError("segment manifest exceeds bounded size".into()));
    }
    Ok(bytes)
}

/// Durably replace the manifest in the pinned run directory `dir`. An
/// existing manifest is an anchor: it is replaced only while it is a private
/// file.
pub(crate) fn write(dir: &File, manifest: &Manifest) -> Result<()> {
    fsx::find_file_at(dir, MEMBER, UNSAFE)?;
    fsx::replace(
        dir,
        &fsx::temporary("segments"),
        MEMBER,
        &encode(manifest)?,
        Replaced::Manifest,
    )
}
