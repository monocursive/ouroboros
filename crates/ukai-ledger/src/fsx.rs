//! Owner-private store members: one rule, checked on open descriptors.
//!
//! Everything the ledger keeps under its data directory is private to the
//! effective uid: owned by it, with no group or other permission bits. A
//! private directory is a directory; a private file is a regular file with
//! exactly one link, so no second name reaches its bytes. Members are opened
//! without following a final symlink and checked on the open descriptor, so
//! what was checked is what gets used.

use std::{
    ffi::{CStr, CString},
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Write as _},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
};

use crate::{
    faults::{self, Point, Replaced, Step},
    protocol::{LedgerError, Result},
};

/// The effective uid every private member, and every peer, must match.
pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments, reads no caller memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// A private file is opened without following a final symlink, closed on
/// exec, and without blocking on a FIFO planted in its place.
const FILE_FLAGS: libc::c_int = libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const DIR_FLAGS: libc::c_int = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// Whether `metadata` is owned by the effective uid with no group or other
/// permission bits, whatever kind of file it describes.
pub(crate) fn owner_only(metadata: &Metadata) -> bool {
    metadata.uid() == euid() && metadata.mode() & 0o077 == 0
}

/// Whether `metadata` is a private directory's.
pub(crate) fn is_private_dir(metadata: &Metadata) -> bool {
    metadata.is_dir() && owner_only(metadata)
}

/// Whether `metadata` is a private file's.
pub(crate) fn is_private_file(metadata: &Metadata) -> bool {
    metadata.is_file() && metadata.nlink() == 1 && owner_only(metadata)
}

/// The open's own error, or `refusal` when the final component is a
/// symlink, or not a directory where one belongs: either way, not a private
/// member.
fn opening(error: io::Error, refusal: &str) -> LedgerError {
    if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
        LedgerError::refused(refusal)
    } else {
        error.into()
    }
}

/// Refuse with `refusal` unless the open `dir` is a private directory.
pub(crate) fn ensure_dir(dir: &File, refusal: &str) -> Result<()> {
    if is_private_dir(&dir.metadata()?) {
        Ok(())
    } else {
        Err(LedgerError::refused(refusal))
    }
}

/// Refuse with `refusal` unless the open `file` is a private file.
pub(crate) fn ensure_file(file: &File, refusal: &str) -> Result<()> {
    if is_private_file(&file.metadata()?) {
        Ok(())
    } else {
        Err(LedgerError::refused(refusal))
    }
}

/// The private directory at `path`.
pub(crate) fn open_dir(path: &Path, refusal: &str) -> Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(path)
        .map_err(|error| opening(error, refusal))?;
    ensure_dir(&dir, refusal)?;
    Ok(dir)
}

/// The private file at `path`, opened as `options` say; a file they create
/// is owner-only.
pub(crate) fn open_file(path: &Path, options: &mut OpenOptions, refusal: &str) -> Result<File> {
    let file = options
        .mode(FILE_MODE)
        .custom_flags(FILE_FLAGS)
        .open(path)
        .map_err(|error| opening(error, refusal))?;
    ensure_file(&file, refusal)?;
    Ok(file)
}

/// The existing private file at `path`, for reading.
pub(crate) fn read_file(path: &Path, refusal: &str) -> Result<File> {
    open_file(path, OpenOptions::new().read(true), refusal)
}

/// Take ownership of the descriptor a successful `openat` returned.
fn opened(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returned a new descriptor owned only here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_file_at_unchecked(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the directory descriptor and the NUL-terminated name stay live
    // through the call; the mode applies only when O_CREAT creates the file.
    opened(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | FILE_FLAGS,
            FILE_MODE as libc::c_uint,
        )
    })
}

/// `name` in the pinned directory `dir`, opened with `flags`, never through
/// a path another process could swap; a file `flags` create is owner-only.
pub(crate) fn open_file_at(
    dir: &File,
    name: &CStr,
    flags: libc::c_int,
    refusal: &str,
) -> Result<File> {
    let file = open_file_at_unchecked(dir, name, flags).map_err(|error| opening(error, refusal))?;
    ensure_file(&file, refusal)?;
    Ok(file)
}

/// The existing private file `name` in `dir` for reading, or `None` when
/// there is no such entry.
pub(crate) fn find_file_at(dir: &File, name: &CStr, refusal: &str) -> Result<Option<File>> {
    let file = match open_file_at_unchecked(dir, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(opening(error, refusal)),
    };
    ensure_file(&file, refusal)?;
    Ok(Some(file))
}

/// The private subdirectory `name` of the pinned directory `dir`.
pub(crate) fn open_dir_at(dir: &File, name: &CStr, refusal: &str) -> Result<File> {
    // SAFETY: the directory descriptor and the NUL-terminated name stay live
    // through the call.
    let child =
        opened(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | DIR_FLAGS) })
            .map_err(|error| opening(error, refusal))?;
    ensure_dir(&child, refusal)?;
    Ok(child)
}

/// The private directory at `path`, created with any missing parent as a
/// private directory; each new entry is synchronized in its parent.
pub(crate) fn create_dir_all(path: &Path) -> Result<File> {
    if fs::symlink_metadata(path).is_err() {
        let parent = path
            .parent()
            .ok_or_else(|| LedgerError::refused("directory has no parent"))?;
        if fs::symlink_metadata(parent).is_err() {
            create_dir_all(parent)?;
        }
        // Created owner-only, so it is never wider than 0700 under any umask;
        // the explicit mode then also corrects a narrower umask.
        fs::DirBuilder::new().mode(DIR_MODE).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(DIR_MODE))?;
        File::open(parent)?.sync_all()?;
    }
    open_dir(
        path,
        &format!(
            "{} must be an owned private directory (0700)",
            path.display()
        ),
    )
}

/// A fresh temporary member name, `.{purpose}-{random}.tmp`.
pub(crate) fn temporary(purpose: &str) -> CString {
    CString::new(format!(".{purpose}-{}.tmp", uuid::Uuid::new_v4().simple()))
        .expect("a purpose and a UUID contain no NUL")
}

/// A member name, as the descriptor-relative calls take it, as text.
pub(crate) const fn text(name: &'static CStr) -> &'static str {
    match name.to_str() {
        Ok(text) => text,
        Err(_) => panic!("member names are ASCII"),
    }
}

/// Remove `name` from the pinned directory `dir`; false when it was absent.
pub(crate) fn unlink_at(dir: &File, name: &CStr) -> Result<bool> {
    // SAFETY: the directory descriptor and the NUL-terminated name stay live
    // through the call.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error.into())
    }
}

/// Durably replace `target` in the pinned private directory `dir` with
/// `bytes`: a fresh `temp` is written, synchronized and renamed over
/// `target`, then `dir` is synchronized.
///
/// A stale `temp` from an interrupted replacement never had authority and is
/// unlinked first. A failure before the rename leaves `target` as it was and
/// removes `temp`; one after it leaves the new bytes visible but perhaps not
/// durable, which the caller must treat as uncertain. Whether an existing
/// `target` may be replaced at all is the caller's decision.
pub(crate) fn replace(
    dir: &File,
    temp: &CStr,
    target: &CStr,
    bytes: &[u8],
    replaced: Replaced,
) -> Result<()> {
    let point = |step| Point::Replace(replaced, step);
    faults::hit(point(Step::BeforeTempUnlink))?;
    unlink_at(dir, temp)?;
    faults::hit(point(Step::BeforeOpen))?;
    let mut file = open_file_at(
        dir,
        temp,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        "a new temporary file is not private",
    )?;
    let renamed = (|| -> Result<()> {
        faults::hit(point(Step::BeforeWrite))?;
        faults::partial_write(point(Step::PartialWrite), &mut file, bytes)?;
        file.write_all(bytes)?;
        faults::hit(point(Step::BeforeSync))?;
        file.sync_all()?;
        faults::hit(point(Step::BeforeRename))?;
        // SAFETY: both names are NUL-terminated members of the one directory
        // descriptor, which stays open through the call.
        if unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    })();
    if renamed.is_err() {
        // An unpublished temporary file has no authority; never leak it.
        let _ = unlink_at(dir, temp);
    }
    renamed?;
    faults::hit(point(Step::BeforeDirectorySync))?;
    dir.sync_all()?;
    faults::hit(point(Step::AfterDirectorySync))?;
    Ok(())
}
