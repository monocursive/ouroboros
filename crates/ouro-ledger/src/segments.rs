//! A bounded, read-only view of an ordered canonical prefix. Logical offsets
//! stay stable when the writer adds a segment. One stream fd is retained between
//! reads; validation and restoration use transient descriptors.
use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::Serialize;

use crate::{
    fsx, manifest,
    protocol::{LedgerError, MAX_FRAME_BYTES, Result},
};

/// What reading the next LF-terminated canonical frame found.
pub(crate) enum Frame {
    /// The input ended on a frame boundary.
    End,
    /// More than `MAX_FRAME_BYTES` with its LF: no frame this writer emits.
    Oversized,
    /// The input ended inside a frame.
    Interrupted,
    /// A frame's bytes, without its LF.
    Complete(Vec<u8>),
}

/// Read the next canonical frame from `reader`, buffering at most one
/// frame's bound: `read_until` alone is unbounded.
pub(crate) fn next_frame(reader: &mut impl BufRead) -> io::Result<Frame> {
    let mut bytes = Vec::new();
    let length = reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    Ok(if length == 0 {
        Frame::End
    } else if length > MAX_FRAME_BYTES {
        Frame::Oversized
    } else if bytes.pop() != Some(b'\n') {
        Frame::Interrupted
    } else {
        Frame::Complete(bytes)
    })
}

#[derive(Clone, Serialize)]
struct Part {
    name: String,
    start: u64,
    bytes: u64,
    device: u64,
    inode: u64,
}

pub(crate) struct Snapshot {
    directory: PathBuf,
    parts: Vec<Part>,
    expected: u64,
    physical_bytes: u64,
    offset: u64,
    current: Option<(usize, File)>,
}

/// A canonical segment, read through its pinned run directory once that
/// directory and the ledger root above it are checked private.
fn open(path: &Path) -> Result<File> {
    const UNSAFE_DIRECTORY: &str = "reader directory is unsafe";
    let run = path
        .parent()
        .ok_or_else(|| LedgerError::refused("missing run directory"))?;
    if let Some(root) = run.parent() {
        fsx::open_dir(root, UNSAFE_DIRECTORY)?;
    }
    let run = fsx::open_dir(run, UNSAFE_DIRECTORY)?;
    let name = path
        .file_name()
        .and_then(|name| CString::new(name.as_encoded_bytes()).ok())
        .ok_or_else(|| LedgerError::refused("reader canonical file is unsafe"))?;
    fsx::open_file_at(
        &run,
        &name,
        libc::O_RDONLY,
        "reader canonical file is unsafe",
    )
}

impl Snapshot {
    pub(crate) fn open(path: &Path, expected: u64) -> Result<Self> {
        let directory = path
            .parent()
            .ok_or_else(|| LedgerError::refused("missing run directory"))?;
        let mut parts = Vec::new();
        let mut physical_bytes = 0u64;
        for name in manifest::names(directory)? {
            let file = open(&directory.join(&name))?;
            let m = file.metadata()?;
            if physical_bytes < expected || parts.is_empty() {
                parts.push(Part {
                    name,
                    start: physical_bytes,
                    bytes: m.len().min(expected.saturating_sub(physical_bytes)),
                    device: m.dev(),
                    inode: m.ino(),
                });
            }
            physical_bytes = physical_bytes
                .checked_add(m.len())
                .ok_or_else(|| LedgerError::refused("canonical byte length overflow"))?;
        }
        Ok(Self {
            directory: directory.into(),
            parts,
            expected,
            physical_bytes,
            offset: 0,
            current: None,
        })
    }

    pub(crate) fn physical_bytes(&self) -> u64 {
        self.physical_bytes
    }

    pub(crate) fn first_identity(&self) -> (u64, u64) {
        (self.parts[0].device, self.parts[0].inode)
    }

    pub(crate) fn identity(&self) -> Result<String> {
        let bytes = to_jcs(&serde_json::to_value(&self.parts)?)
            .map_err(|e| LedgerError::refused(e.to_string()))?;
        Ok(sha256_prefixed(&bytes))
    }

    pub(crate) fn is_single_segment(&self) -> bool {
        self.parts.len() == 1
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.physical_bytes < self.expected {
            return Err(LedgerError::refused("canonical snapshot was truncated"));
        }
        for (i, part) in self.parts.iter().enumerate() {
            let file = open(&self.directory.join(&part.name))?;
            let m = file.metadata()?;
            if m.len() < part.bytes {
                return Err(LedgerError::refused("canonical snapshot was truncated"));
            }
            if m.dev() != part.device
                || m.ino() != part.inode
                || (i + 1 < self.parts.len() && m.len() != part.bytes)
            {
                return Err(LedgerError::refused(
                    "canonical segment identity or length changed",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            directory: self.directory.clone(),
            parts: self.parts.clone(),
            expected: self.expected,
            physical_bytes: self.physical_bytes,
            offset: self.offset,
            current: None,
        })
    }
}

impl Seek for Snapshot {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let offset = match position {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.offset) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.expected) + i128::from(n),
        };
        self.offset =
            u64::try_from(offset).map_err(|_| io::Error::other("invalid canonical offset"))?;
        Ok(self.offset)
    }
}

impl Read for Snapshot {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.expected || buffer.is_empty() {
            return Ok(0);
        }
        let i = self
            .parts
            .partition_point(|part| part.start + part.bytes <= self.offset);
        let part = self
            .parts
            .get(i)
            .ok_or_else(|| io::Error::other("missing canonical segment"))?;
        if self
            .current
            .as_ref()
            .is_none_or(|(current, _)| *current != i)
        {
            let file = open(&self.directory.join(&part.name)).map_err(io::Error::other)?;
            let m = file.metadata()?;
            if m.dev() != part.device || m.ino() != part.inode || m.len() < part.bytes {
                return Err(io::Error::other(
                    "canonical segment identity or length changed",
                ));
            }
            self.current = Some((i, file));
        }
        let file = &mut self.current.as_mut().expect("opened segment").1;
        file.seek(SeekFrom::Start(self.offset - part.start))?;
        let bound = buffer
            .len()
            .min((part.start + part.bytes - self.offset) as usize);
        let n = file.read(&mut buffer[..bound])?;
        self.offset += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(input: &[u8]) -> Vec<Frame> {
        let mut reader = input;
        let mut frames = Vec::new();
        loop {
            match next_frame(&mut reader).unwrap() {
                Frame::End => return frames,
                frame @ (Frame::Oversized | Frame::Interrupted) => {
                    frames.push(frame);
                    return frames;
                }
                frame => frames.push(frame),
            }
        }
    }

    #[test]
    fn a_frame_and_its_lf_fit_the_frame_bound_or_the_frame_is_oversized() {
        let mut largest = vec![b'x'; MAX_FRAME_BYTES - 1];
        largest.push(b'\n');
        largest.extend_from_slice(b"{}\n");
        assert!(matches!(
            frames(&largest).as_slice(),
            [Frame::Complete(first), Frame::Complete(second)]
                if first.len() == MAX_FRAME_BYTES - 1 && second == b"{}"
        ));
        let mut oversized = vec![b'x'; MAX_FRAME_BYTES];
        oversized.push(b'\n');
        assert!(matches!(frames(&oversized).as_slice(), [Frame::Oversized]));
        assert!(matches!(
            frames(b"{}\n{").as_slice(),
            [Frame::Complete(_), Frame::Interrupted]
        ));
        assert!(frames(b"").is_empty());
    }
}
