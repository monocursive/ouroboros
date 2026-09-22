//! Filesystem identity: the protected-segment walk, source-path pinning, and
//! the merged-`/usr` runtime roots.
//!
//! jail-v1 §9.1. Two rules shape everything here. A symlink is never
//! followed, because a `.git` symlink must not be able to authorise its
//! target. And a bound that is reached is a refusal, not a shorter answer: a
//! partial walk that reported `existing_and_root` coverage would be a lie the
//! receipt then repeats.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::sys::{PathError, cstring_from_path, empty_stat, errno_name, last_errno};

/// The two path segments the `tool` profile protects (north-star §4.4).
pub const PROTECTED_LITERALS: [&str; 2] = [".git", ".ouroboros"];

/// Bounds on one walk. jail-v1 §9.1 fixes the initial values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanLimits {
    /// Maximum directory entries examined across the whole walk.
    pub max_entries: usize,
    /// Maximum directory depth below the root.
    pub max_depth: usize,
}

impl ScanLimits {
    /// The limits the spec fixes: 100,000 entries and depth 128.
    pub const DEFAULT: Self = Self {
        max_entries: 100_000,
        max_depth: 128,
    };
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a protected segment is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentKind {
    /// An ordinary directory, the usual case.
    Directory,
    /// A file-form `.git`, as a git worktree or submodule leaves behind.
    File,
    /// Something else entirely; still protected, still not descended into.
    Other,
}

/// One protected path segment found beneath a writable root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedSegment {
    /// Absolute path on the host.
    pub path: PathBuf,
    /// What kind of object it is.
    pub kind: SegmentKind,
    /// Device of the object, recorded so the mount can be checked later.
    pub dev: u64,
    /// Inode of the object.
    pub ino: u64,
}

/// State of a root-level protected literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootLiteralState {
    /// Exists as a directory or file; covered by a read-only bind over itself.
    Present(SegmentKind),
    /// Does not exist; jail-v1 §9.1 requires it to be protected anyway, which
    /// is what a placeholder mount is for.
    Absent,
    /// Exists as a symlink. Not followed and not treated as covering its
    /// target (jail-v1 §9.1: "A protected symlink cannot authorize its
    /// target").
    Symlink,
}

/// The result of one complete walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedScan {
    /// The writable root that was walked.
    pub root: PathBuf,
    /// Every protected segment found, in walk order.
    pub segments: Vec<ProtectedSegment>,
    /// Protected names that were symlinks and so were neither followed nor
    /// reported as covering anything.
    pub skipped_symlinks: Vec<PathBuf>,
    /// State of each root-level literal, in the order of [`PROTECTED_LITERALS`].
    pub root_literals: Vec<(&'static str, RootLiteralState)>,
    /// Directory entries examined.
    pub entries_seen: usize,
    /// Greatest depth reached below the root.
    pub max_depth_seen: usize,
}

impl ProtectedScan {
    /// The root-level literals that do not exist and therefore need a
    /// placeholder mount.
    #[must_use]
    pub fn absent_root_literals(&self) -> Vec<&'static str> {
        self.root_literals
            .iter()
            .filter(|(_, state)| *state == RootLiteralState::Absent)
            .map(|(name, _)| *name)
            .collect()
    }
}

/// Why a walk could not produce a complete answer.
#[derive(Debug)]
pub enum ScanError {
    /// The root is not a directory this process can open without following a
    /// symlink.
    BadRoot {
        /// The root that was offered.
        path: PathBuf,
        /// The errno from `open`.
        errno: i32,
    },
    /// A directory beneath the root could not be read, so coverage is unknown.
    Unreadable {
        /// The directory.
        path: PathBuf,
        /// The errno.
        errno: i32,
    },
    /// The entry budget was exhausted.
    EntryLimit {
        /// The limit that was reached.
        limit: usize,
    },
    /// The depth budget was exhausted.
    DepthLimit {
        /// The limit that was reached.
        limit: usize,
        /// Where it happened.
        path: PathBuf,
    },
    /// A path could not be handed to a syscall at all.
    Path(PathError),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRoot { path, errno } => write!(
                f,
                "cannot open writable root {} without following a symlink: {}",
                path.display(),
                errno_name(*errno)
            ),
            Self::Unreadable { path, errno } => write!(
                f,
                "cannot read {}: {}; protected coverage is unknown",
                path.display(),
                errno_name(*errno)
            ),
            Self::EntryLimit { limit } => write!(
                f,
                "protected scan reached its {limit}-entry limit; coverage would be a partial claim"
            ),
            Self::DepthLimit { limit, path } => write!(
                f,
                "protected scan reached depth {limit} at {}; coverage would be a partial claim",
                path.display()
            ),
            Self::Path(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<PathError> for ScanError {
    fn from(value: PathError) -> Self {
        Self::Path(value)
    }
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Enumerate every `.git` and `.ouroboros` segment beneath `root`, with the
/// spec's default limits.
///
/// # Errors
///
/// [`ScanError`] on an unreadable directory or an exhausted bound. The caller
/// must refuse rather than record partial coverage.
pub fn scan_protected(root: &Path) -> Result<ProtectedScan, ScanError> {
    scan_protected_with(root, ScanLimits::DEFAULT)
}

/// Enumerate protected segments with explicit limits.
///
/// # Errors
///
/// As [`scan_protected`].
pub fn scan_protected_with(root: &Path, limits: ScanLimits) -> Result<ProtectedScan, ScanError> {
    let root_c = cstring_from_path(root)?;
    let root_dir = DirHandle::open_root(&root_c).map_err(|errno| ScanError::BadRoot {
        path: root.to_owned(),
        errno,
    })?;

    let mut state = WalkState {
        limits,
        entries_seen: 0,
        max_depth_seen: 0,
        segments: Vec::new(),
        skipped_symlinks: Vec::new(),
        root_found: Vec::new(),
    };
    walk(&root_dir, root, 1, &mut state)?;

    let root_literals = PROTECTED_LITERALS
        .iter()
        .map(|name| {
            let state = state
                .root_found
                .iter()
                .find(|(found, _)| found == name)
                .map_or(RootLiteralState::Absent, |(_, s)| *s);
            (*name, state)
        })
        .collect();

    Ok(ProtectedScan {
        root: root.to_owned(),
        segments: state.segments,
        skipped_symlinks: state.skipped_symlinks,
        root_literals,
        entries_seen: state.entries_seen,
        max_depth_seen: state.max_depth_seen,
    })
}

struct WalkState {
    limits: ScanLimits,
    entries_seen: usize,
    max_depth_seen: usize,
    segments: Vec<ProtectedSegment>,
    skipped_symlinks: Vec<PathBuf>,
    root_found: Vec<(&'static str, RootLiteralState)>,
}

fn walk(
    dir: &DirHandle,
    dir_path: &Path,
    depth: usize,
    state: &mut WalkState,
) -> Result<(), ScanError> {
    state.max_depth_seen = state.max_depth_seen.max(depth);
    let entries = dir.entries().map_err(|errno| ScanError::Unreadable {
        path: dir_path.to_owned(),
        errno,
    })?;

    let mut subdirs: Vec<CString> = Vec::new();
    for name in entries {
        state.entries_seen += 1;
        if state.entries_seen > state.limits.max_entries {
            return Err(ScanError::EntryLimit {
                limit: state.limits.max_entries,
            });
        }
        let name_os = OsStr::from_bytes(name.to_bytes());
        let child_path = dir_path.join(name_os);
        let meta = dir
            .stat_child_nofollow(&name)
            .map_err(|errno| ScanError::Unreadable {
                path: child_path.clone(),
                errno,
            })?;

        let literal = PROTECTED_LITERALS
            .iter()
            .find(|l| name_os == OsStr::new(**l))
            .copied();

        if let Some(literal) = literal {
            if meta.is_symlink {
                state.skipped_symlinks.push(child_path.clone());
                if depth == 1 {
                    state.root_found.push((literal, RootLiteralState::Symlink));
                }
                continue;
            }
            let kind = meta.kind();
            state.segments.push(ProtectedSegment {
                path: child_path,
                kind,
                dev: meta.dev,
                ino: meta.ino,
            });
            if depth == 1 {
                state
                    .root_found
                    .push((literal, RootLiteralState::Present(kind)));
            }
            // Never descend into a protected segment: it is covered whole.
            continue;
        }

        if meta.is_dir && !meta.is_symlink {
            subdirs.push(name);
        }
    }

    for name in subdirs {
        if depth + 1 > state.limits.max_depth {
            let child = dir_path.join(OsStr::from_bytes(name.to_bytes()));
            return Err(ScanError::DepthLimit {
                limit: state.limits.max_depth,
                path: child,
            });
        }
        let child_path = dir_path.join(OsStr::from_bytes(name.to_bytes()));
        let child = dir
            .open_child(&name)
            .map_err(|errno| ScanError::Unreadable {
                path: child_path.clone(),
                errno,
            })?;
        walk(&child, &child_path, depth + 1, state)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory handles: openat / fdopendir, never a path lookup from the root
// ---------------------------------------------------------------------------

struct DirHandle {
    fd: OwnedFd,
}

#[derive(Clone, Copy)]
struct ChildMeta {
    is_dir: bool,
    is_symlink: bool,
    is_file: bool,
    dev: u64,
    ino: u64,
}

impl ChildMeta {
    fn kind(self) -> SegmentKind {
        if self.is_dir {
            SegmentKind::Directory
        } else if self.is_file {
            SegmentKind::File
        } else {
            SegmentKind::Other
        }
    }
}

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

impl DirHandle {
    fn open_root(path: &CStr) -> Result<Self, i32> {
        // SAFETY: `path` is a NUL-terminated C string that outlives the call;
        // O_NOFOLLOW means a symlinked root is refused rather than followed.
        let fd = unsafe { libc::open(path.as_ptr(), DIR_FLAGS) };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: `fd` was just opened and is owned here.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn open_child(&self, name: &CStr) -> Result<Self, i32> {
        // SAFETY: `self.fd` is a live directory fd and `name` is a
        // NUL-terminated string valid for the call. O_NOFOLLOW keeps the walk
        // inside the root even if an entry is replaced by a symlink.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), DIR_FLAGS) };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: `fd` was just opened and is owned here.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn stat_child_nofollow(&self, name: &CStr) -> Result<ChildMeta, i32> {
        let mut st = empty_stat();
        // SAFETY: `st` is a live, writable stat buffer; `name` is
        // NUL-terminated; AT_SYMLINK_NOFOLLOW stats the link itself.
        let rc = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                &raw mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(last_errno());
        }
        let mode = st.st_mode & libc::S_IFMT;
        Ok(ChildMeta {
            is_dir: mode == libc::S_IFDIR,
            is_symlink: mode == libc::S_IFLNK,
            is_file: mode == libc::S_IFREG,
            dev: st.st_dev,
            ino: st.st_ino,
        })
    }

    /// Every entry name in this directory except `.` and `..`.
    fn entries(&self) -> Result<Vec<CString>, i32> {
        // `fdopendir` takes ownership of the fd it is given, so hand it a
        // duplicate and keep ours for `openat`.
        // SAFETY: `self.fd` is a live directory fd; F_DUPFD_CLOEXEC returns a
        // new owned descriptor for the same description.
        let dup = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(last_errno());
        }
        // SAFETY: `dup` is a fresh directory fd; fdopendir consumes it and
        // closedir below releases it exactly once.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let err = last_errno();
            // SAFETY: fdopendir failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(err);
        }
        let mut out = Vec::new();
        let mut result = Ok(());
        loop {
            // SAFETY: readdir is given the DIR* just created; it returns a
            // pointer valid until the next readdir on the same stream.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: as above.
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                let err = last_errno();
                if err != 0 {
                    result = Err(err);
                }
                break;
            }
            // SAFETY: `entry` is non-null and points at a live dirent; d_name
            // is a NUL-terminated array inside it.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            out.push(name.to_owned());
        }
        // SAFETY: `dirp` was created above and is closed exactly once here.
        unsafe { libc::closedir(dirp) };
        result.map(|()| out)
    }
}

// ---------------------------------------------------------------------------
// Source-path pinning
// ---------------------------------------------------------------------------

/// A path whose identity was recorded at policy time, so that a replacement
/// between validation and mount handoff is detected rather than mounted.
#[derive(Debug)]
pub struct PinnedPath {
    fd: OwnedFd,
    path: PathBuf,
    dev: u64,
    ino: u64,
}

/// Why a pinned path is no longer the object that was pinned.
#[derive(Debug)]
pub enum PinError {
    /// The path no longer resolves.
    Missing {
        /// The path.
        path: PathBuf,
        /// The errno from `lstat`.
        errno: i32,
    },
    /// The path resolves to a different object than the one pinned.
    Replaced {
        /// The path.
        path: PathBuf,
        /// Device and inode recorded at pin time.
        expected: (u64, u64),
        /// Device and inode found now.
        found: (u64, u64),
    },
}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { path, errno } => {
                write!(
                    f,
                    "pinned path {} is gone: {}",
                    path.display(),
                    errno_name(*errno)
                )
            }
            Self::Replaced {
                path,
                expected,
                found,
            } => write!(
                f,
                "pinned path {} was replaced: pinned {}:{}, found {}:{}",
                path.display(),
                expected.0,
                expected.1,
                found.0,
                found.1
            ),
        }
    }
}

impl std::error::Error for PinError {}

impl PinnedPath {
    /// Pin `path` by opening an `O_PATH|O_NOFOLLOW` handle and recording the
    /// object's device and inode.
    ///
    /// `O_PATH` opens the object without any read or write authority, which is
    /// all pinning needs.
    ///
    /// # Errors
    ///
    /// The errno from `open` or `fstat`, or [`PathError`] for an unusable path.
    pub fn open(path: &Path) -> Result<Self, io::Error> {
        let c = cstring_from_path(path).map_err(|e| io::Error::other(e.to_string()))?;
        // SAFETY: `c` is NUL-terminated and outlives the call. O_PATH means no
        // I/O authority is acquired; O_NOFOLLOW means a symlink at the final
        // component is pinned as itself rather than followed.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened and is owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut st = empty_stat();
        // SAFETY: `fd` is live and `st` is a writable stat buffer; fstat on an
        // O_PATH descriptor is permitted.
        let rc = unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            path: path.to_owned(),
            dev: st.st_dev,
            ino: st.st_ino,
        })
    }

    /// The path as it was given.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Device and inode recorded at pin time.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// The `O_PATH` handle, for callers that want to hand the kernel the
    /// object rather than the name (`bwrap --ro-bind-fd`).
    #[must_use]
    pub fn borrow_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Check that the name still resolves to the pinned object.
    ///
    /// # Errors
    ///
    /// [`PinError::Missing`] or [`PinError::Replaced`].
    pub fn verify(&self) -> Result<(), PinError> {
        let Ok(c) = cstring_from_path(&self.path) else {
            return Err(PinError::Missing {
                path: self.path.clone(),
                errno: libc::EINVAL,
            });
        };
        let mut st = empty_stat();
        // SAFETY: `c` is NUL-terminated and `st` is writable; lstat does not
        // follow a final symlink, matching how the path was pinned.
        let rc = unsafe { libc::lstat(c.as_ptr(), &raw mut st) };
        if rc != 0 {
            return Err(PinError::Missing {
                path: self.path.clone(),
                errno: last_errno(),
            });
        }
        if (st.st_dev, st.st_ino) != (self.dev, self.ino) {
            return Err(PinError::Replaced {
                path: self.path.clone(),
                expected: (self.dev, self.ino),
                found: (st.st_dev, st.st_ino),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime roots
// ---------------------------------------------------------------------------

/// How one system root must be reproduced inside the jail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootSpec {
    /// A real directory: bind it read-only at the same path.
    RoBind(PathBuf),
    /// A merged-`/usr` compatibility symlink, such as `/bin -> usr/bin`.
    /// Recreate the symlink rather than binding through it, so the jail's view
    /// has the same shape as the host's.
    Symlink {
        /// Where the link lives.
        path: PathBuf,
        /// What it points at, verbatim.
        target: PathBuf,
    },
}

impl RootSpec {
    /// The path inside the jail this spec produces.
    #[must_use]
    pub fn destination(&self) -> &Path {
        match self {
            Self::RoBind(p) | Self::Symlink { path: p, .. } => p,
        }
    }
}

/// Classify a system root on this host. `None` means the path does not exist,
/// which is normal for `/lib32` and `/libx32` on many installs.
#[must_use]
pub fn resolve_runtime_root(path: &Path) -> Option<RootSpec> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        return Some(RootSpec::Symlink {
            path: path.to_owned(),
            target,
        });
    }
    if meta.is_dir() {
        return Some(RootSpec::RoBind(path.to_owned()));
    }
    None
}

/// Whether a path exists, following symlinks. Used for the `/etc` files, which
/// are bound as whatever they resolve to.
#[must_use]
pub fn exists_resolved(path: &Path) -> bool {
    std::fs::metadata(path).is_ok()
}

/// Every path beneath `root`, relative and sorted: a cheap tree listing for
/// tests that must show a directory is unchanged.
///
/// # Errors
///
/// Any failure reading a directory.
pub fn listing(root: &Path) -> io::Result<Vec<OsString>> {
    fn walk(dir: &Path, prefix: &Path, out: &mut Vec<OsString>) -> io::Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let rel = prefix.join(entry.file_name());
            let meta = entry.metadata()?;
            let mut shown = rel.clone().into_os_string();
            if meta.is_dir() {
                shown.push("/");
            }
            out.push(shown);
            if meta.is_dir() && !entry.file_type()?.is_symlink() {
                walk(&entry.path(), &rel, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, Path::new(""), &mut out)?;
    Ok(out)
}
