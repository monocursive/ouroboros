//! Rebuilding a stream from its canonical bytes, at startup and for fresh
//! verification.
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader},
    path::Path,
};

use super::{Poison, PoisonKind, Stream};
use crate::{
    manifest,
    protocol::{MAX_FRAME_BYTES, Result},
    store::{capture_pruning, writer::private_file},
};

/// One run's canonical layout as it stood at one moment. A re-read never goes
/// past it, so it is consistent with whatever the writer appends later.
pub(in crate::store) struct Layout {
    pub(in crate::store) manifest: std::result::Result<Option<manifest::Manifest>, String>,
    pub(in crate::store) names: std::result::Result<Vec<String>, String>,
    /// The last segment's length at that moment: appends only ever grow the
    /// last segment, and a rotation seals it at or beyond this length.
    pub(in crate::store) last_bytes: Option<u64>,
    /// Every segment's length at that moment, summed.
    pub(in crate::store) total_bytes: Option<u64>,
}

impl Layout {
    pub(in crate::store) fn read(directory: &Path, run_id: &str) -> Self {
        let manifest = crate::manifest::read(directory, run_id).map_err(|error| error.to_string());
        let names = manifest::names(directory).map_err(|error| error.to_string());
        let length = |name: &String| {
            fs::symlink_metadata(directory.join(name))
                .ok()
                .map(|metadata| metadata.len())
        };
        let names_found = names.as_ref().ok();
        Self {
            last_bytes: names_found.and_then(|names| names.last()).and_then(length),
            total_bytes: names_found
                .and_then(|names| names.iter().map(length).sum::<Option<u64>>()),
            manifest,
            names,
        }
    }
}

pub(in crate::store) struct Loaded {
    pub(in crate::store) stream: Stream,
    pub(in crate::store) events: u64,
    /// The canonical bytes re-read before `proceed` stopped the load, if it did.
    pub(in crate::store) stopped: Option<u64>,
}

/// Re-read and re-validate one run's canonical history within `layout`.
/// `proceed` is asked before every frame; once it answers false the load
/// stops and says how far it got, never what it did not read.
pub(in crate::store) fn load_stream(
    directory: &Path,
    run_id: &str,
    layout: Layout,
    sync: &impl Fn(&File) -> std::io::Result<()>,
    proceed: &mut impl FnMut() -> bool,
) -> Result<Loaded> {
    let mut stream = Stream::empty(run_id);
    let manifest = match layout.manifest {
        Ok(manifest) => manifest,
        Err(error) => {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                format!("invalid segment manifest: {error}"),
            ));
            None
        }
    };
    let names = match layout.names {
        Ok(names) => names,
        Err(error) => {
            stream.poisoned.push(Poison::new(
                PoisonKind::Corrupt,
                format!("invalid segment layout: {error}"),
            ));
            return Ok(Loaded {
                stream,
                events: 0,
                stopped: None,
            });
        }
    };
    let count = names.len();
    if manifest
        .as_ref()
        .is_none_or(|m| count < m.segments.len() || count > m.segments.len() + 1)
        && !(manifest.is_none() && count == 1)
    {
        stream.poisoned.push(Poison::new(
            PoisonKind::Unanchored,
            "segment manifest does not authorize this segment layout",
        ));
    }
    let mut events = 0;
    let mut stopped = None;
    'segments: for (index, name) in names.iter().enumerate() {
        stream.begin_segment(index + 1);
        let anchor = manifest.as_ref().and_then(|m| m.segments.get(index));
        let mut anchored = anchor.is_none();
        let file = match private_file(&directory.join(name), &mut OpenOptions::new()) {
            Ok(file) => file,
            Err(error) => {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Corrupt,
                    format!("missing or unsafe canonical segment: {error}"),
                ));
                break;
            }
        };
        // Once a successor exists, its predecessor is sealed at the
        // durable anchor. A tail there could not come from this writer.
        if index + 1 < count
            && anchor.is_none_or(|a| file.metadata().is_ok_and(|m| m.len() != a.bytes))
        {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                "sealed segment length differs from its manifest anchor",
            ));
            break;
        }
        let limit = match layout.last_bytes {
            Some(bytes) if index + 1 == count => bytes,
            _ => u64::MAX,
        };
        use std::io::Read as _;
        let mut reader = BufReader::new((&file).take(limit));
        loop {
            if !proceed() {
                stopped = Some(stream.accepted_bytes);
                break 'segments;
            }
            let mut bytes = Vec::new();
            // read_until alone is unbounded; the limited reader also catches a missing newline.
            let length = reader
                .by_ref()
                .take((MAX_FRAME_BYTES + 1) as u64)
                .read_until(b'\n', &mut bytes)?;
            if length == 0 {
                break;
            }
            // This writer never emits an oversized frame; only a crash
            // between its write and newline leaves an unterminated tail.
            if length > MAX_FRAME_BYTES {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Corrupt,
                    "oversized canonical frame; bytes retained",
                ));
                break;
            }
            if bytes.last() != Some(&b'\n') {
                stream.poisoned.push(Poison::new(
                    PoisonKind::Incomplete,
                    "interrupted canonical frame; bytes retained",
                ));
                break;
            }
            bytes.pop();
            // Every refusal of a complete frame is an integrity violation:
            // this writer validates the same rules before it appends.
            if let Err(error) = stream.accept_canonical(run_id, &bytes) {
                stream
                    .poisoned
                    .push(Poison::new(PoisonKind::Corrupt, error.to_string()));
                break;
            }
            events += 1;
            if let Some(anchor) = anchor
                && events == anchor.last_seq
            {
                anchored = true;
                let m = manifest.as_ref().expect("anchored manifest");
                if stream.segments.last() != Some(anchor)
                    || stream.run.attempt_id != m.attempt_id
                    || (index + 1 == m.segments.len()
                        && stream.manifest().replay_digest != m.replay_digest)
                {
                    stream.poisoned.push(Poison::new(
                        PoisonKind::Unanchored,
                        "segment manifest committed prefix mismatch",
                    ));
                    break;
                }
            }
        }
        // The manifest is written only after its records are synchronized,
        // so bytes missing below an anchor are lost acknowledged history.
        if !anchored {
            stream.poisoned.push(Poison::new(
                PoisonKind::Unanchored,
                "canonical stream truncated before its segment manifest anchor",
            ));
        }
        // Only one empty unlisted successor of a fully anchored stream can be
        // an interrupted rotation, and only a lone unlisted first segment an
        // interrupted preparation. Never manufacture a missing committed file.
        if stream.segment_bytes == 0 && (index == 0 || anchor.is_some() || index + 1 != count) {
            let kind = if index == 0 && anchor.is_none() && count == 1 {
                PoisonKind::Incomplete
            } else {
                PoisonKind::Corrupt
            };
            stream
                .poisoned
                .push(Poison::new(kind, "empty canonical segment"));
        }
        if !stream.poisoned.is_empty() {
            break;
        }
        // Sync the exact descriptor just verified, not a reopened path. A
        // failure aborts startup before any repaired metadata is published.
        sync(&file)?;
    }
    if stream.poisoned.is_empty() && stopped.is_none() {
        capture_pruning::apply(directory, &mut stream)?;
    }
    Ok(Loaded {
        stream,
        events,
        stopped,
    })
}
