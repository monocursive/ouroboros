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
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::sys::{PathError, cstring_from_path, empty_stat, errno_name, last_errno};
use crate::state::anchored::{Dir, Kind, Name, Stat, fstat};

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
    /// Identity and timestamps of every directory enumerated.
    pub directories: Vec<DirectoryStamp>,
    /// The writable root that was walked.
    pub root: PathBuf,
    /// Every protected segment found, in walk order.
    pub segments: Vec<ProtectedSegment>,
    /// Protected names that were symlinks and so were neither followed nor
    /// reported as covering anything.
    pub skipped_symlinks: Vec<PathBuf>,
    /// State of each root-level literal, in the order of the requested names.
    pub root_literals: Vec<(String, RootLiteralState)>,
    /// Directory entries examined.
    pub entries_seen: usize,
    /// Greatest depth reached below the root.
    pub max_depth_seen: usize,
}

/// A bounded scan is a snapshot, not an atomic filesystem transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryStamp {
    pub path: PathBuf,
    identity: (u64, u64),
    modified: (i64, i64, i64, i64),
}
impl DirectoryStamp {
    fn read(path: &Path, fd: BorrowedFd<'_>) -> io::Result<Self> {
        let stat = fstat(fd)?;
        Ok(Self {
            path: path.to_owned(),
            identity: stat.identity(),
            modified: (stat.mtime.0, stat.mtime.1, stat.ctime.0, stat.ctime.1),
        })
    }
    /// Whether the directory's pathname, resolved again with every symlink
    /// refused ([`PinnedPath::open`]), still names the scanned directory with
    /// the scanned timestamps.
    ///
    /// # Errors
    ///
    /// The resolution's errno, or a description of the change.
    pub fn verify(&self) -> io::Result<()> {
        let pin = PinnedPath::open(&self.path)?;
        let now = Self::read(&self.path, pin.fd.as_fd())?;
        if now != *self {
            return Err(io::Error::other(format!(
                "scanned directory changed: {}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

impl ProtectedScan {
    /// The root-level literals that do not exist and therefore need a
    /// placeholder mount.
    #[must_use]
    pub fn absent_root_literals(&self) -> Vec<String> {
        self.root_literals
            .iter()
            .filter(|(_, state)| *state == RootLiteralState::Absent)
            .map(|(name, _)| name.clone())
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
    /// A directory the walk enumerated changed before the walk could be
    /// confirmed, on the retry too: coverage would describe a tree that no
    /// longer exists.
    Changed {
        /// The first directory that no longer matched its scan.
        path: PathBuf,
        /// What the confirmation found.
        detail: String,
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
            Self::Changed { path, detail } => write!(
                f,
                "{} changed while the protected scan ran, twice ({detail}); coverage would \
                 describe a tree that no longer exists",
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

/// Enumerate protected segments with the built-in literals.
///
/// # Errors
///
/// [`ScanError`] when the root cannot be walked without following a symlink,
/// a directory cannot be read, or a bound is reached; a partial walk
/// must refuse rather than record partial coverage.
pub fn scan_protected(root: &Path) -> Result<ProtectedScan, ScanError> {
    scan_protected_names(root, &PROTECTED_LITERALS, ScanLimits::DEFAULT)
}

/// Enumerate protected segments with explicit limits and the built-in
/// literals.
///
/// # Errors
///
/// As [`scan_protected`].
pub fn scan_protected_with(root: &Path, limits: ScanLimits) -> Result<ProtectedScan, ScanError> {
    scan_protected_names(root, &PROTECTED_LITERALS, limits)
}

/// Enumerate protected segments by name: the two built-in literals plus any
/// operator-configured `filesystem.protected_segments` (§6.3), with explicit
/// limits.
///
/// # Errors
///
/// As [`scan_protected`].
pub fn scan_protected_names(
    root: &Path,
    names: &[&str],
    limits: ScanLimits,
) -> Result<ProtectedScan, ScanError> {
    cstring_from_path(root)?;
    let root_dir = Dir::open_trusted(root).map_err(|error| ScanError::BadRoot {
        path: root.to_owned(),
        errno: errno_of(&error),
    })?;
    scan_directory(root, &root_dir, names, limits)
}

/// Scan the directory `root` holds, then confirm the scan.
///
/// The walk starts from the pinned handle, so the root is the object that
/// was pinned whatever its pathname names now. The confirmation is by path:
/// every directory the walk enumerated is resolved again
/// ([`DirectoryStamp::verify`]) and must still be the same directory with
/// the same timestamps. A tree that changed during the walk is walked once
/// more; a second change refuses with [`ScanError::Changed`].
///
/// # Errors
///
/// As [`scan_protected`], plus [`ScanError::Changed`].
pub fn scan_pinned(
    root: &PinnedPath,
    names: &[&str],
    limits: ScanLimits,
) -> Result<ProtectedScan, ScanError> {
    let mut retried = false;
    loop {
        let dir = root.open_directory().map_err(|error| ScanError::BadRoot {
            path: root.path.clone(),
            errno: errno_of(&error),
        })?;
        let scan = scan_directory(&root.path, &dir, names, limits)?;
        let changed = scan.directories.iter().find_map(|directory| {
            directory
                .verify()
                .err()
                .map(|error| (directory.path.clone(), error.to_string()))
        });
        match changed {
            None => return Ok(scan),
            Some((path, detail)) if retried => return Err(ScanError::Changed { path, detail }),
            Some(_) => retried = true,
        }
    }
}

fn scan_directory(
    root: &Path,
    root_dir: &Dir,
    names: &[&str],
    limits: ScanLimits,
) -> Result<ProtectedScan, ScanError> {
    let mut state = WalkState {
        directories: Vec::new(),
        limits,
        entries_seen: 0,
        max_depth_seen: 0,
        segments: Vec::new(),
        skipped_symlinks: Vec::new(),
        root_found: Vec::new(),
    };
    walk(root_dir, root, b"", 1, names, &mut state)?;

    // Audit 2026-10-08 M5: only single-component names are root literals —
    // a multi-component name like `.git/hooks` protects what exists and
    // claims nothing for a path that does not (§4.4: a segment created
    // later is outside the claim either way).
    let root_literals = names
        .iter()
        .filter(|name| !name.contains('/'))
        .map(|name| {
            let state = state
                .root_found
                .iter()
                .find(|(found, _)| found == name)
                .map_or(RootLiteralState::Absent, |(_, s)| *s);
            ((*name).to_owned(), state)
        })
        .collect();

    Ok(ProtectedScan {
        directories: state.directories,
        root: root.to_owned(),
        segments: state.segments,
        skipped_symlinks: state.skipped_symlinks,
        root_literals,
        entries_seen: state.entries_seen,
        max_depth_seen: state.max_depth_seen,
    })
}

struct WalkState {
    directories: Vec<DirectoryStamp>,
    limits: ScanLimits,
    entries_seen: usize,
    max_depth_seen: usize,
    segments: Vec<ProtectedSegment>,
    skipped_symlinks: Vec<PathBuf>,
    root_found: Vec<(String, RootLiteralState)>,
}

/// One directory entry, as the walk sees it.
struct Child<'a> {
    /// The entry's name.
    name: &'a CStr,
    /// Its absolute path on the host.
    path: PathBuf,
    /// Its path beneath the writable root, `/`-separated.
    relative: Vec<u8>,
}

/// What the walk does with one entry.
enum EntryAction<'n> {
    /// Nothing beneath it can be protected, and it is not protected itself.
    Skip,
    /// A protected name that is not a symlink: covered whole, never entered.
    Segment {
        literal: &'n str,
        kind: SegmentKind,
        dev: u64,
        ino: u64,
    },
    /// A protected name that is a symlink: neither followed nor reported as
    /// covering anything.
    ProtectedSymlink { literal: &'n str },
    /// A symlink on the way to a deeper protected name, which hides whatever
    /// lives behind it.
    HidingSymlink,
    /// A directory to walk.
    Descend,
}

fn walk(
    dir: &Dir,
    dir_path: &Path,
    relative: &[u8],
    depth: usize,
    names: &[&str],
    state: &mut WalkState,
) -> Result<(), ScanError> {
    let stamp = DirectoryStamp::read(dir_path, dir.as_fd()).map_err(|e| ScanError::Unreadable {
        path: dir_path.to_owned(),
        errno: errno_of(&e),
    })?;
    // A recent directory can change type within one filesystem clock tick
    // without a distinguishable timestamp. Keep the original stat checks in
    // that case and on filesystems whose timestamp clock is not local.
    let ordinary_hint_safe = stable_regular_file_hints(dir, &stamp);
    state.directories.push(stamp);
    state.max_depth_seen = state.max_depth_seen.max(depth);
    let entries = read_entries(
        dir,
        state.limits.max_entries.saturating_sub(state.entries_seen),
    )
    .map_err(|errno| {
        if errno == libc::E2BIG {
            ScanError::EntryLimit {
                limit: state.limits.max_entries,
            }
        } else {
            ScanError::Unreadable {
                path: dir_path.to_owned(),
                errno,
            }
        }
    })?;

    let mut subdirs: Vec<(PathBuf, Name, Vec<u8>)> = Vec::new();
    for entry in &entries {
        state.entries_seen += 1;
        if state.entries_seen > state.limits.max_entries {
            return Err(ScanError::EntryLimit {
                limit: state.limits.max_entries,
            });
        }
        let name = entry.name.as_c_str();
        let mut child_relative = relative.to_vec();
        if !child_relative.is_empty() {
            child_relative.push(b'/');
        }
        child_relative.extend_from_slice(name.to_bytes());
        let child = Child {
            name,
            path: dir_path.join(OsStr::from_bytes(name.to_bytes())),
            relative: child_relative,
        };
        match classify_entry(dir, entry.kind, &child, depth, names, ordinary_hint_safe)? {
            EntryAction::Skip => {}
            EntryAction::Segment {
                literal,
                kind,
                dev,
                ino,
            } => {
                state.segments.push(ProtectedSegment {
                    path: child.path,
                    kind,
                    dev,
                    ino,
                });
                if depth == 1 {
                    state
                        .root_found
                        .push((literal.to_owned(), RootLiteralState::Present(kind)));
                }
            }
            EntryAction::ProtectedSymlink { literal } => {
                state.skipped_symlinks.push(child.path);
                if depth == 1 {
                    state
                        .root_found
                        .push((literal.to_owned(), RootLiteralState::Symlink));
                }
            }
            EntryAction::HidingSymlink => state.skipped_symlinks.push(child.path),
            EntryAction::Descend => {
                let component = Name::new(name.to_bytes()).map_err(|_| ScanError::Unreadable {
                    path: child.path.clone(),
                    errno: libc::EINVAL,
                })?;
                subdirs.push((child.path, component, child.relative));
            }
        }
    }

    for (child_path, name, child_relative) in subdirs {
        if depth + 1 > state.limits.max_depth {
            return Err(ScanError::DepthLimit {
                limit: state.limits.max_depth,
                path: child_path,
            });
        }
        let child = dir
            .open_dir_at(&name, None)
            .map_err(|error| ScanError::Unreadable {
                path: child_path.clone(),
                errno: errno_of(&error),
            })?;
        walk(
            &child,
            &child_path,
            &child_relative,
            depth + 1,
            names,
            state,
        )?;
    }
    Ok(())
}

/// Decides what the walk does with one entry of `dir` whose `readdir` type
/// is `kind`.
fn classify_entry<'n>(
    dir: &Dir,
    kind: u8,
    child: &Child<'_>,
    depth: usize,
    names: &[&'n str],
    ordinary_hint_safe: bool,
) -> Result<EntryAction<'n>, ScanError> {
    // A single-component name matches any directory entry; a
    // multi-component name (audit 2026-10-08 M5) matches the entry's whole
    // path beneath the writable root, so `.git/hooks` protects a nested
    // hooks directory while `.git` itself stays writable. A multi-component
    // name never matches at the root: it is not a root literal and a
    // writable root is never itself protected.
    let entry_name = child.name.to_bytes();
    let literal = names.iter().copied().find(|literal| {
        if literal.contains('/') {
            depth > 1 && literal.as_bytes() == child.relative.as_slice()
        } else {
            entry_name == literal.as_bytes()
        }
    });

    // readdir already identifies ordinary regular files. Their identity is
    // irrelevant unless their name is protected: they cannot contain deeper
    // segments and are never followed. Unknown types, directories, symlinks
    // and every protected name still get the no-follow stat. The directory
    // stamps and mount-handoff verification remain responsible for a
    // rename or type swap after enumeration.
    if ordinary_hint_safe && literal.is_none() && kind == libc::DT_REG {
        return Ok(EntryAction::Skip);
    }
    let meta = stat_entry(dir, child.name).map_err(|errno| ScanError::Unreadable {
        path: child.path.clone(),
        errno,
    })?;

    if let Some(literal) = literal {
        return Ok(if meta.kind == Kind::Symlink {
            EntryAction::ProtectedSymlink { literal }
        } else {
            EntryAction::Segment {
                literal,
                kind: segment_kind(meta.kind),
                dev: meta.dev,
                ino: meta.ino,
            }
        });
    }
    // A symlink on the path *to* a deeper protected name hides whatever
    // lives behind it, so `existing_and_root` cannot claim coverage it could
    // not see (audit 2026-10-08 M5): a `.git` symlink while `.git/hooks` is
    // protected is recorded like a protected symlink.
    if meta.kind == Kind::Symlink
        && names.iter().any(|literal| {
            let literal = literal.as_bytes();
            literal.starts_with(child.relative.as_slice())
                && literal.get(child.relative.len()) == Some(&b'/')
        })
    {
        return Ok(EntryAction::HidingSymlink);
    }
    Ok(if meta.kind == Kind::Directory {
        EntryAction::Descend
    } else {
        EntryAction::Skip
    })
}

fn segment_kind(kind: Kind) -> SegmentKind {
    match kind {
        Kind::Directory => SegmentKind::Directory,
        Kind::Regular => SegmentKind::File,
        _ => SegmentKind::Other,
    }
}

fn errno_of(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(libc::EIO)
}

// ---------------------------------------------------------------------------
// Directory reads: anchored at a descriptor, never a path lookup from the root
// ---------------------------------------------------------------------------

fn stable_hint_clock(fs_type: libc::c_long, changed_second: i64, now_second: Option<i64>) -> bool {
    // The ext family may store only whole-second timestamps. A strictly newer
    // local clock second ensures a subsequent type swap changes the stamp.
    matches!(fs_type, libc::EXT4_SUPER_MAGIC | libc::TMPFS_MAGIC)
        && now_second.is_some_and(|now| now > changed_second)
}

#[cfg(test)]
mod hint_clock_tests {
    use super::stable_hint_clock;

    #[test]
    fn regular_hint_requires_a_known_local_filesystem_and_an_older_change_second() {
        for kind in [libc::EXT4_SUPER_MAGIC, libc::TMPFS_MAGIC] {
            assert!(!stable_hint_clock(kind, 100, None));
            assert!(!stable_hint_clock(kind, 100, Some(99)));
            assert!(!stable_hint_clock(kind, 100, Some(100)));
            assert!(stable_hint_clock(kind, 100, Some(101)));
        }
        assert!(!stable_hint_clock(0, 100, Some(101)));
        assert!(!stable_hint_clock(libc::NFS_SUPER_MAGIC, 100, Some(101)));
    }
}

/// Whether `readdir`'s regular-file type can stand in for a stat in the
/// directory `stamp` describes.
fn stable_regular_file_hints(dir: &Dir, stamp: &DirectoryStamp) -> bool {
    // SAFETY: statfs consists only of C integer fields, for which all-zero
    // is a valid value; the call below overwrites it.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the directory descriptor is live and `filesystem` is writable
    // storage of the type fstatfs fills.
    if unsafe { libc::fstatfs(dir.as_fd().as_raw_fd(), &raw mut filesystem) } != 0 {
        return false;
    }
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: now is live writable storage for this clock result.
    let clock = (unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &raw mut now) } == 0)
        .then_some(now.tv_sec);
    stable_hint_clock(filesystem.f_type, stamp.modified.2, clock)
}

/// One `readdir` entry: its name and the type `readdir` reported for it.
struct DirectoryEntry {
    name: CString,
    kind: u8,
}

/// The kind and identity a no-follow stat of one entry found.
struct EntryMeta {
    kind: Kind,
    dev: u64,
    ino: u64,
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` of one entry of `dir`.
///
/// Deliberately not [`Dir::stat_at`], which adds a `statx` for the mount-root
/// flag to every call: the walk stats up to [`ScanLimits::DEFAULT`] entries
/// and needs only kind and identity.
fn stat_entry(dir: &Dir, name: &CStr) -> Result<EntryMeta, i32> {
    let mut st = empty_stat();
    // SAFETY: the directory descriptor is live, `name` is NUL-terminated and
    // valid for the call, `st` is a writable stat buffer, and
    // AT_SYMLINK_NOFOLLOW stats the entry itself.
    let rc = unsafe {
        libc::fstatat(
            dir.as_fd().as_raw_fd(),
            name.as_ptr(),
            &raw mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(last_errno());
    }
    let mode = st.st_mode & libc::S_IFMT;
    Ok(EntryMeta {
        kind: if mode == libc::S_IFDIR {
            Kind::Directory
        } else if mode == libc::S_IFLNK {
            Kind::Symlink
        } else if mode == libc::S_IFREG {
            Kind::Regular
        } else {
            Kind::Other
        },
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

/// Every entry of `dir` but `.` and `..`, with the type `readdir` reports,
/// read from the start; `E2BIG` once more than `remaining` are found.
///
/// [`Dir::names`] reads names alone; the walk needs the type as well, which
/// is what lets it skip an ordinary file without a stat.
fn read_entries(dir: &Dir, remaining: usize) -> Result<Vec<DirectoryEntry>, i32> {
    // `fdopendir` takes ownership of the descriptor it is given, so it gets a
    // duplicate; a duplicate shares the file offset, so the stream is
    // rewound before reading.
    let duplicate = dir
        .try_clone_fd()
        .map_err(|error| errno_of(&error))?
        .into_raw_fd();
    // SAFETY: `duplicate` is a live directory descriptor owned here; on
    // success the stream owns it and `closedir` below releases it once.
    let dirp = unsafe { libc::fdopendir(duplicate) };
    if dirp.is_null() {
        let errno = last_errno();
        // SAFETY: fdopendir failed, so the descriptor is still ours to close.
        unsafe { libc::close(duplicate) };
        return Err(errno);
    }
    // SAFETY: `dirp` is the live DIR* created above.
    unsafe { libc::rewinddir(dirp) };
    let mut out = Vec::new();
    let mut result = Ok(());
    loop {
        // SAFETY: errno is this thread's own.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `dirp` is live; the entry it returns stays valid until the
        // next call on this stream.
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            let err = last_errno();
            if err != 0 {
                result = Err(err);
            }
            break;
        }
        // SAFETY: `entry` is non-null and points at a live dirent whose
        // `d_name` is a NUL-terminated array inside it.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if out.len() >= remaining {
            result = Err(libc::E2BIG);
            break;
        }
        out.push(DirectoryEntry {
            name: name.to_owned(),
            // SAFETY: the dirent is still live until the next readdir.
            kind: unsafe { (*entry).d_type },
        });
    }
    // SAFETY: `dirp` was created above and is closed exactly once here.
    unsafe { libc::closedir(dirp) };
    result.map(|()| out)
}

/// `openat2(dir, path, flags, how.resolve = resolve)`, relative to `dir` or,
/// with `None`, to the working directory.
///
/// # Errors
///
/// The errno from `openat2` (`ELOOP` for a symlink `RESOLVE_NO_SYMLINKS`
/// refuses), or `InvalidInput` for a path with an interior NUL.
pub(crate) fn openat2(
    dir: Option<BorrowedFd<'_>>,
    path: &Path,
    flags: libc::c_int,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let c = cstring_from_path(path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    // SAFETY: `open_how` is a plain struct of integers (and non-exhaustive,
    // so it is built zeroed); all-zero asks for no flags, mode or resolution.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = u64::try_from(flags)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "negative open flags"))?;
    how.resolve = resolve;
    let base = dir.map_or(libc::AT_FDCWD, |dir| dir.as_raw_fd());
    // SAFETY: `base` is AT_FDCWD or a live descriptor, `c` is a NUL-terminated
    // path and `how` a live `open_how` of the size passed, all valid for the
    // call; openat2 returns a new descriptor or -1.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            base,
            c.as_ptr(),
            &raw const how,
            size_of::<libc::open_how>(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc)
        .map_err(|_| io::Error::other("openat2 returned an out-of-range descriptor"))?;
    // SAFETY: `fd` was just returned by openat2 and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
    /// What `fstat` of the handle found at pin time.
    stat: Stat,
}

/// Why a pinned path is no longer the object that was pinned.
#[derive(Debug)]
pub enum PinError {
    /// The path no longer resolves without a symlink.
    Missing {
        /// The path.
        path: PathBuf,
        /// The errno from resolving it again.
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

/// Opens `path` as an `O_PATH` handle, refusing a symlink at every component
/// (`RESOLVE_NO_SYMLINKS`), so no mutable ancestor can redirect it.
fn open_no_symlinks(path: &Path) -> io::Result<OwnedFd> {
    openat2(
        None,
        path,
        libc::O_PATH | libc::O_CLOEXEC,
        libc::RESOLVE_NO_SYMLINKS,
    )
}

impl PinnedPath {
    /// Pin `path` by opening an `O_PATH` handle with no symlink at any
    /// component and recording the object's identity, owner and mode.
    ///
    /// `O_PATH` opens the object without any read or write authority, which is
    /// all pinning needs.
    ///
    /// # Errors
    ///
    /// The errno from `openat2` (`ELOOP` for a symlink anywhere on the path)
    /// or `fstat`, or `InvalidInput` for an unusable path.
    pub fn open(path: &Path) -> Result<Self, io::Error> {
        let fd = open_no_symlinks(path)?;
        let stat = fstat(fd.as_fd())?;
        Ok(Self {
            fd,
            path: path.to_owned(),
            stat,
        })
    }

    /// Executable owner/mode must stay fixed as well as its pinned identity.
    ///
    /// # Errors
    ///
    /// `PermissionDenied` for an owner or mode that is unsafe or changed, the
    /// errno from `fstat`, or the [`PinError`] of [`PinnedPath::verify`].
    pub fn verify_executable(&self) -> io::Result<()> {
        let now = fstat(self.fd.as_fd())?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if (now.uid != 0 && now.uid != euid)
            || now.uid != self.stat.uid
            || (now.kind, now.mode) != (self.stat.kind, self.stat.mode)
            || now.kind != Kind::Regular
            || now.mode & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "backend executable ownership or mode is unsafe or changed",
            ));
        }
        self.verify().map_err(io::Error::other)
    }

    /// The path as it was given.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Device and inode recorded at pin time.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        self.stat.identity()
    }

    /// Whether the pinned object, rather than its current pathname, is a directory.
    ///
    /// # Errors
    ///
    /// The errno from `fstat`.
    pub fn is_dir(&self) -> io::Result<bool> {
        Ok(fstat(self.fd.as_fd())?.kind == Kind::Directory)
    }

    /// The `O_PATH` handle, for callers that want to hand the kernel the
    /// object rather than the name (`bwrap --ro-bind-fd`).
    #[must_use]
    pub fn borrow_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The pinned directory, opened for reading through the handle rather
    /// than its pathname.
    fn open_directory(&self) -> io::Result<Dir> {
        // SAFETY: the handle is a live `O_PATH` descriptor, which may serve
        // as `openat`'s directory; `"."` is a static NUL-terminated name, and
        // the flags open that same directory for reading, following nothing.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by `openat` and nothing else owns it.
        Ok(Dir::from_owned(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Check that the name, resolved again the way it was pinned (no symlink
    /// at any component), still names the pinned object.
    ///
    /// # Errors
    ///
    /// [`PinError::Missing`] or [`PinError::Replaced`].
    pub fn verify(&self) -> Result<(), PinError> {
        let missing = |error: io::Error| PinError::Missing {
            path: self.path.clone(),
            errno: error.raw_os_error().unwrap_or(libc::EINVAL),
        };
        let now = open_no_symlinks(&self.path)
            .and_then(|fd| fstat(fd.as_fd()))
            .map_err(missing)?;
        if now.identity() != self.stat.identity() {
            return Err(PinError::Replaced {
                path: self.path.clone(),
                expected: self.stat.identity(),
                found: now.identity(),
            });
        }
        Ok(())
    }

    /// Duplicate the `O_PATH` handle (close-on-exec) so a spawn map can
    /// install it at a fixed descriptor number for `bwrap --ro-bind-fd`,
    /// while the pin itself stays here for verification (§9.1).
    ///
    /// # Errors
    ///
    /// The errno from `fcntl(F_DUPFD_CLOEXEC)`.
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_that_changes_on_both_walks_names_the_directory() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("parent");
        let root = parent.join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let pin = PinnedPath::open(&root).unwrap();
        // The held handle still reaches the tree, but its pathname now runs
        // through a symlink, which no confirmation follows: every walk's
        // confirmation fails, and the refusal says where.
        let moved = base.path().join("moved");
        std::fs::rename(&parent, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &parent).unwrap();
        match scan_pinned(&pin, &PROTECTED_LITERALS, ScanLimits::DEFAULT) {
            Err(ScanError::Changed { path, detail }) => {
                assert_eq!(path, root);
                assert!(detail.contains("symbolic links"), "{detail}");
                let message = ScanError::Changed { path, detail }.to_string();
                assert!(message.contains("changed while the protected scan ran"));
                assert!(!message.contains("ESTALE"), "{message}");
            }
            other => panic!("expected a changed-tree refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_pin_is_verified_the_way_it_was_made() {
        let base = tempfile::tempdir().unwrap();
        let parent = base.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("leaf"), b"x").unwrap();
        let pin = PinnedPath::open(&parent.join("leaf")).unwrap();
        pin.verify().expect("unchanged");
        // The same object, now reached through a symlinked ancestor: the pin
        // refused symlinks at every component, so the check does too.
        let moved = base.path().join("moved");
        std::fs::rename(&parent, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &parent).unwrap();
        match pin.verify() {
            Err(PinError::Missing { errno, .. }) => assert_eq!(errno, libc::ELOOP),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(matches!(
            PinnedPath::open(&parent.join("leaf")).map_err(|e| e.raw_os_error()),
            Err(Some(libc::ELOOP))
        ));
    }
}
