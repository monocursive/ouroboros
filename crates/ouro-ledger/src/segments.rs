//! A bounded, read-only view of an ordered canonical prefix. Logical offsets
//! stay stable when the writer adds a segment. One stream fd is retained between
//! reads; validation and restoration use transient descriptors.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use ouro_records::canonical::{sha256_prefixed, to_jcs};
use serde::Serialize;

use crate::{
    manifest,
    protocol::{LedgerError, Result},
};

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

fn open(path: &Path) -> Result<File> {
    for directory in path
        .parent()
        .into_iter()
        .chain(path.parent().and_then(Path::parent))
    {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(LedgerError("reader directory is unsafe".into()));
        }
    }
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
        return Err(LedgerError("reader canonical file is unsafe".into()));
    }
    Ok(file)
}

impl Snapshot {
    pub(crate) fn open(path: &Path, expected: u64) -> Result<Self> {
        let directory = path
            .parent()
            .ok_or_else(|| LedgerError("missing run directory".into()))?;
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
                .ok_or_else(|| LedgerError("canonical byte length overflow".into()))?;
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
        let bytes =
            to_jcs(&serde_json::to_value(&self.parts)?).map_err(|e| LedgerError(e.to_string()))?;
        Ok(sha256_prefixed(&bytes))
    }

    pub(crate) fn is_single_segment(&self) -> bool {
        self.parts.len() == 1
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.physical_bytes < self.expected {
            return Err(LedgerError("canonical snapshot was truncated".into()));
        }
        for (i, part) in self.parts.iter().enumerate() {
            let file = open(&self.directory.join(&part.name))?;
            let m = file.metadata()?;
            if m.len() < part.bytes {
                return Err(LedgerError("canonical snapshot was truncated".into()));
            }
            if m.dev() != part.device
                || m.ino() != part.inode
                || (i + 1 < self.parts.len() && m.len() != part.bytes)
            {
                return Err(LedgerError(
                    "canonical segment identity or length changed".into(),
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
