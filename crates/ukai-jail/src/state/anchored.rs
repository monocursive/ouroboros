//! Anchored, no-follow filesystem handles (jail-v1 §9.1, §12).
//!
//! Every operation on a credential source, on vendor state and on the launch
//! profile file goes through a directory descriptor and one validated path
//! component at a time: `openat`, `fstatat`, `mkdirat`, `unlinkat` and
//! `renameat` with `O_NOFOLLOW` / `AT_SYMLINK_NOFOLLOW`. A name is never
//! resolved from the filesystem root twice, so a symlink planted between two
//! steps cannot redirect the second one, and identity is compared with `fstat`
//! on the descriptor actually used.
//!
//! This is the one place in the portable crate that calls the POSIX `*at`
//! family directly. It is portable across Linux and macOS because every call
//! here is POSIX; the Linux-only additions (`O_PATH`, `statx` mount roots and
//! the `/proc/self/fd` reopen) are behind `cfg(target_os = "linux")`. Each
//! `unsafe` block states its precondition, and `tests` below try to violate
//! each boundary: a component with a slash, `.`/`..`, an embedded NUL, a
//! symlink at the final component and a directory swapped for a symlink.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// The object kind an `lstat`-style call reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link, never followed.
    Symlink,
    /// A named pipe.
    Fifo,
    /// A Unix-domain socket node.
    Socket,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// Anything else the kernel reports.
    Other,
}

impl Kind {
    fn from_mode(mode: u32) -> Kind {
        let format = mode & wide_mode(libc::S_IFMT);
        if format == wide_mode(libc::S_IFREG) {
            Kind::Regular
        } else if format == wide_mode(libc::S_IFDIR) {
            Kind::Directory
        } else if format == wide_mode(libc::S_IFLNK) {
            Kind::Symlink
        } else if format == wide_mode(libc::S_IFIFO) {
            Kind::Fifo
        } else if format == wide_mode(libc::S_IFSOCK) {
            Kind::Socket
        } else if format == wide_mode(libc::S_IFCHR) {
            Kind::CharDevice
        } else if format == wide_mode(libc::S_IFBLK) {
            Kind::BlockDevice
        } else {
            Kind::Other
        }
    }

    /// A safe phrase for diagnostics: the kind, never a path.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Kind::Regular => "a regular file",
            Kind::Directory => "a directory",
            Kind::Symlink => "a symlink",
            Kind::Fifo => "a FIFO",
            Kind::Socket => "a socket",
            Kind::CharDevice => "a character device",
            Kind::BlockDevice => "a block device",
            Kind::Other => "an unrecognized object",
        }
    }
}

/// The facts one `fstat`/`fstatat` established about an object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stat {
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Object kind.
    pub kind: Kind,
    /// Permission bits, including set-id and sticky (`st_mode & 07777`).
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Owning group.
    pub gid: u32,
    /// Hard-link count.
    pub nlink: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, seconds and nanoseconds.
    pub mtime: (i64, i64),
    /// Status-change time, seconds and nanoseconds.
    pub ctime: (i64, i64),
    /// Whether the object is the root of a mount. Linux reports it through
    /// `statx`; `None` means it could not be established, which callers that
    /// must not cross a mount treat as a refusal, never as "no".
    pub mount_root: Option<bool>,
}

impl Stat {
    /// The `(dev, ino)` pair the kernel uses as the object's identity.
    #[must_use]
    pub const fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }

    /// Whether the content, size and metadata recorded here are the same as
    /// in `other`: same object, same size, same modification and change time.
    #[must_use]
    pub fn unchanged_since(&self, other: &Stat) -> bool {
        self.identity() == other.identity()
            && self.size == other.size
            && self.mtime == other.mtime
            && self.ctime == other.ctime
    }
}

fn wide_mode<T: Into<u32>>(value: T) -> u32 {
    value.into()
}

fn wide_u64<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

fn wide_i64<T: Into<i64>>(value: T) -> i64 {
    value.into()
}

#[cfg(target_os = "macos")]
fn device_of(stat: &libc::stat) -> u64 {
    // `dev_t` is a signed 32-bit value on macOS. The identity only has to be
    // stable and injective, so the bits are reinterpreted, not range-checked.
    u64::from(stat.st_dev.cast_unsigned())
}

#[cfg(not(target_os = "macos"))]
fn device_of(stat: &libc::stat) -> u64 {
    wide_u64(stat.st_dev)
}

fn stat_from(stat: &libc::stat) -> Stat {
    let mode = wide_mode(stat.st_mode);
    Stat {
        dev: device_of(stat),
        ino: wide_u64(stat.st_ino),
        kind: Kind::from_mode(mode),
        mode: mode & 0o7777,
        uid: stat.st_uid,
        gid: stat.st_gid,
        nlink: wide_u64(stat.st_nlink),
        size: u64::try_from(stat.st_size).unwrap_or(0),
        mtime: (wide_i64(stat.st_mtime), wide_i64(stat.st_mtime_nsec)),
        ctime: (wide_i64(stat.st_ctime), wide_i64(stat.st_ctime_nsec)),
        mount_root: None,
    }
}

fn empty_stat() -> libc::stat {
    // SAFETY: `libc::stat` is a plain C struct of integers for which the
    // all-zero pattern is valid; it is only read after a successful call
    // has overwritten it.
    unsafe { std::mem::zeroed() }
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn owned(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by a successful open-like call in this
    // thread and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// One path component: non-empty, no `/`, no NUL, not `.` or `..`.
///
/// Every anchored call takes a `Name`, never a path, so a call can only ever
/// look one level below the directory it is anchored at.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Name(CString);

impl Name {
    /// Validates one component.
    ///
    /// # Errors
    /// `InvalidInput` for an empty component, a slash, a NUL, `.` or `..`.
    pub fn new(bytes: &[u8]) -> io::Result<Name> {
        if bytes.is_empty() || bytes == b"." || bytes == b".." {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a path component may not be empty, `.` or `..`",
            ));
        }
        if bytes.contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a path component may not contain `/`",
            ));
        }
        CString::new(bytes).map(Name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a path component may not contain NUL",
            )
        })
    }

    /// The component's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The component as the C string a system call takes.
    pub(crate) fn as_c(&self) -> &CStr {
        &self.0
    }
}

/// Splits a relative path into validated components.
///
/// `a/b/c` is three components. An empty path, an absolute path, an empty
/// interior component (`a//b`, a trailing `/`) and any `.` or `..` refuse:
/// the caller gets exactly the components that were written, or nothing.
///
/// # Errors
/// `InvalidInput` for any of the refused shapes.
pub fn split_relative(bytes: &[u8]) -> io::Result<Vec<Name>> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a relative path may not be empty",
        ));
    }
    if bytes.starts_with(b"/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a relative path may not be absolute",
        ));
    }
    bytes.split(|byte| *byte == b'/').map(Name::new).collect()
}

/// Splits an absolute path into validated components.
///
/// The path must start with `/`; repeated slashes are tolerated, `.` and `..`
/// refuse (the caller normalizes lexically first, and anything left is not a
/// path this module will walk).
///
/// # Errors
/// `InvalidInput` for a relative path or a refused component.
pub fn split_absolute(bytes: &[u8]) -> io::Result<Vec<Name>> {
    if !bytes.starts_with(b"/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an absolute path is required",
        ));
    }
    bytes
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
        .map(Name::new)
        .collect()
}

// ---------------------------------------------------------------------------
// Directory handles
// ---------------------------------------------------------------------------

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// An open directory: the anchor every other call in this module uses.
#[derive(Debug)]
pub struct Dir {
    fd: OwnedFd,
}

impl Dir {
    /// Opens a trusted operator path as a directory.
    ///
    /// The final component is never followed; ancestors are resolved by the
    /// kernel as usual, which is why only operator-owned locations (the state
    /// root and its attempt directories) come through here. Child-reachable
    /// objects are only ever opened relative to a `Dir`.
    ///
    /// # Errors
    /// The errno from `open`, including `ELOOP`/`ENOTDIR` for a symlink.
    pub fn open_trusted(path: &Path) -> io::Result<Dir> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path contains NUL"))?;
        // SAFETY: `c` is NUL-terminated and outlives the call; the flags open
        // a directory without following a final symlink.
        let fd = unsafe { libc::open(c.as_ptr(), DIR_FLAGS) };
        Ok(Dir { fd: owned(fd)? })
    }

    /// Opens `/` for a no-follow walk. Prefer [`walk`] and [`WalkDir`], which
    /// cannot be mistaken for a readable directory.
    ///
    /// On Linux the handle is `O_PATH`, so a walk needs search permission on
    /// each directory, not read permission, exactly like path resolution.
    ///
    /// # Errors
    /// The errno from `open`.
    pub fn open_root_for_walk() -> io::Result<Dir> {
        // SAFETY: the literal is NUL-terminated and static.
        let fd = unsafe { libc::open(c"/".as_ptr(), walk_flags()) };
        Ok(Dir { fd: owned(fd)? })
    }

    /// Wraps an already-open directory descriptor.
    #[must_use]
    pub fn from_owned(fd: OwnedFd) -> Dir {
        Dir { fd }
    }

    /// The descriptor, borrowed.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// A close-on-exec duplicate of the descriptor.
    ///
    /// # Errors
    /// The errno from `fcntl`.
    pub fn try_clone_fd(&self) -> io::Result<OwnedFd> {
        self.fd.try_clone()
    }

    /// Gives up the handle.
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// `fstat` of the directory itself.
    ///
    /// # Errors
    /// The errno from `fstat`.
    pub fn stat(&self) -> io::Result<Stat> {
        fstat(self.as_fd())
    }

    /// `fstatat(AT_SYMLINK_NOFOLLOW)` of one entry, plus, on Linux, whether it
    /// is a mount root.
    ///
    /// # Errors
    /// The errno from `fstatat`.
    pub fn stat_at(&self, name: &Name) -> io::Result<Stat> {
        stat_at(self.as_fd(), name)
    }

    /// Opens one entry as a directory, never following a symlink, and checks
    /// that the descriptor is the object `expected` described.
    ///
    /// # Errors
    /// The errno from `openat` (`ELOOP`/`ENOTDIR` for a symlink or a
    /// non-directory), or `Other` when the opened object is not `expected`.
    pub fn open_dir_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<Dir> {
        // SAFETY: live descriptor, validated component, flags that refuse a
        // symlink and a non-directory.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_c().as_ptr(), DIR_FLAGS) };
        let dir = Dir { fd: owned(fd)? };
        verify(&dir.stat()?, expected)?;
        Ok(dir)
    }

    /// Opens one entry as a directory for a walk (`O_PATH` on Linux). Prefer
    /// [`WalkDir`], which cannot be mistaken for a readable directory.
    ///
    /// # Errors
    /// As [`Dir::open_dir_at`].
    pub fn open_walk_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<Dir> {
        Ok(Dir {
            fd: open_walk_at(self.as_fd(), name, expected)?,
        })
    }

    /// `mkdirat` of one entry, then `fchmod` to exactly `mode` through a
    /// no-follow handle, so the process umask cannot widen or narrow it.
    ///
    /// # Errors
    /// The errno from `mkdirat` (`EEXIST` when anything is already there,
    /// including a symlink), `openat` or `fchmod`.
    pub fn mkdir_at(&self, name: &Name, mode: u32) -> io::Result<Dir> {
        // SAFETY: live descriptor, validated component; mkdirat never follows
        // a symlink at the final component, it fails with EEXIST.
        check(unsafe { libc::mkdirat(self.fd.as_raw_fd(), name.as_c().as_ptr(), mode_t(0o700)) })?;
        let dir = self.open_dir_at(name, None)?;
        dir.chmod(mode)?;
        Ok(dir)
    }

    /// Creates one new regular file exclusively (`O_CREAT | O_EXCL |
    /// O_NOFOLLOW`) with exactly `mode`.
    ///
    /// # Errors
    /// The errno from `openat` (`EEXIST` for anything already there,
    /// including a dangling symlink) or `fchmod`.
    pub fn create_file_at(&self, name: &Name, mode: u32) -> io::Result<File> {
        // SAFETY: live descriptor, validated component; O_EXCL with O_CREAT
        // refuses every existing entry, a symlink included.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode_arg(0o600),
            )
        };
        let file = File::from(owned(fd)?);
        fchmod(file.as_fd(), mode)?;
        Ok(file)
    }

    /// Opens one entry for reading without following a symlink and without
    /// blocking on a FIFO or acquiring a terminal, then checks it is the
    /// object `expected` described.
    ///
    /// # Errors
    /// The errno from `openat` (`ELOOP` for a symlink), or `Other` when the
    /// opened object is not `expected`.
    pub fn open_read_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<File> {
        open_read_at(self.as_fd(), name, expected)
    }

    /// Opens one entry as an `O_PATH` handle without following it.
    ///
    /// Opening with `O_PATH` performs no open-time side effect on the object:
    /// a FIFO is not waited on and a device driver is never called, so a
    /// special file is refused after `fstat` without ever having been opened
    /// for I/O. A symlink yields a handle to the link itself, which `fstat`
    /// reports as a symlink.
    ///
    /// # Errors
    /// The errno from `openat`.
    #[cfg(target_os = "linux")]
    pub fn open_path_at(&self, name: &Name) -> io::Result<OwnedFd> {
        open_path_at(self.as_fd(), name)
    }

    /// `unlinkat` of a non-directory entry: the entry itself is removed; a
    /// symlink's target and a hard link's other names are never touched.
    ///
    /// # Errors
    /// The errno from `unlinkat`.
    pub fn unlink_at(&self, name: &Name) -> io::Result<()> {
        // SAFETY: live descriptor, validated component; unlinkat removes the
        // directory entry and never resolves a symlink.
        check(unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_c().as_ptr(), 0) })
    }

    /// `unlinkat(AT_REMOVEDIR)` of an empty directory entry.
    ///
    /// # Errors
    /// The errno from `unlinkat` (`ENOTEMPTY`, `EBUSY` for a mount point).
    pub fn rmdir_at(&self, name: &Name) -> io::Result<()> {
        // SAFETY: live descriptor, validated component.
        check(unsafe {
            libc::unlinkat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                libc::AT_REMOVEDIR,
            )
        })
    }

    /// `renameat` of one entry of this directory to one entry of `to`.
    ///
    /// # Errors
    /// The errno from `renameat`.
    pub fn rename_at(&self, name: &Name, to: &Dir, to_name: &Name) -> io::Result<()> {
        // SAFETY: both descriptors are live and both names are validated
        // components; renameat never follows a symlink in either name.
        check(unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                to.fd.as_raw_fd(),
                to_name.as_c().as_ptr(),
            )
        })
    }

    /// `fchmod` of the directory itself.
    ///
    /// # Errors
    /// The errno from `fchmod`.
    pub fn chmod(&self, mode: u32) -> io::Result<()> {
        fchmod(self.as_fd(), mode)
    }

    /// `fchmodat(AT_SYMLINK_NOFOLLOW)` of one entry.
    ///
    /// Used only to regain access to a directory the child made unreadable,
    /// after `stat_at` established that the entry is a directory.
    ///
    /// # Errors
    /// The errno from `fchmodat`; a platform that cannot change a mode
    /// without following reports `EOPNOTSUPP` rather than following.
    pub fn chmod_at(&self, name: &Name, mode: u32) -> io::Result<()> {
        // SAFETY: live descriptor, validated component, AT_SYMLINK_NOFOLLOW
        // asks for the entry itself.
        check(unsafe {
            libc::fchmodat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                mode_t(mode),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }

    /// Up to `max` entry names, `.` and `..` excluded, read from the start,
    /// and whether they are all of them.
    ///
    /// # Errors
    /// As [`Dir::entries`].
    pub fn names(&self, max: usize) -> io::Result<Listing> {
        let entries = self.entries(max)?;
        Ok(Listing {
            names: entries
                .entries
                .into_iter()
                .map(|entry| entry.name)
                .collect(),
            complete: entries.complete,
        })
    }

    /// Up to `max` entries, `.` and `..` excluded, read from the start, each
    /// with the type `readdir` reported, and whether they are all of them.
    /// The type lets a walk skip an ordinary file without a stat.
    ///
    /// # Errors
    /// The errno from `fcntl`, `fdopendir` or `readdir`, or `InvalidData`
    /// for a name the kernel returned that is not a valid component.
    pub fn entries(&self, max: usize) -> io::Result<Entries> {
        // `fdopendir` takes ownership of what it is given, so it gets a
        // duplicate; a duplicate shares the file offset, so the stream is
        // rewound before reading.
        // SAFETY: the descriptor is live; F_DUPFD_CLOEXEC returns a new one.
        let duplicate = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `duplicate` is a fresh directory descriptor owned here; on
        // success the stream owns it and `closedir` releases it once.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so the descriptor is still ours.
            unsafe { libc::close(duplicate) };
            return Err(error);
        }
        // SAFETY: `stream` is the live DIR* created above.
        unsafe { libc::rewinddir(stream) };
        let mut out = Vec::new();
        let mut failure = None;
        let mut complete = false;
        // One entry past `max` is read, and not kept, to tell a directory of
        // exactly `max` entries from a larger one.
        while out.len() <= max {
            clear_errno();
            // SAFETY: `stream` is live; the returned entry stays valid until
            // the next call on this stream.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = io::Error::last_os_error();
                if errno.raw_os_error().unwrap_or(0) != 0 {
                    failure = Some(errno);
                }
                complete = true;
                break;
            }
            // SAFETY: `entry` is non-null and `d_name` is a NUL-terminated
            // array inside it, live until the next call on this stream.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            match Name::new(bytes) {
                Ok(name) => out.push(Entry {
                    name,
                    // SAFETY: as above, the entry is live until the next call.
                    kind: unsafe { (*entry).d_type },
                }),
                Err(_) => {
                    failure = Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the kernel returned an entry name that is not a component",
                    ));
                    break;
                }
            }
        }
        // SAFETY: `stream` was created above and is closed exactly once.
        unsafe { libc::closedir(stream) };
        if let Some(error) = failure {
            return Err(error);
        }
        out.truncate(max);
        Ok(Entries {
            entries: out,
            complete,
        })
    }

    /// `fsync` of the directory, which makes its entries durable.
    ///
    /// # Errors
    /// The errno from `fsync`.
    pub fn sync(&self) -> io::Result<()> {
        // SAFETY: the descriptor is live.
        check(unsafe { libc::fsync(self.fd.as_raw_fd()) })
    }
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` of one entry of `dir`, plus, on Linux,
/// whether it is a mount root.
fn stat_at(dir: BorrowedFd<'_>, name: &Name) -> io::Result<Stat> {
    let mut raw = empty_stat();
    // SAFETY: the descriptor is live, `name` is a validated NUL-terminated
    // component, `raw` is a writable buffer and AT_SYMLINK_NOFOLLOW
    // describes the entry itself.
    check(unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_c().as_ptr(),
            &raw mut raw,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    let mut stat = stat_from(&raw);
    stat.mount_root = mount_root_at(dir, name);
    Ok(stat)
}

/// Opens one entry of `dir` as a walk handle, checked against `expected`.
fn open_walk_at(dir: BorrowedFd<'_>, name: &Name, expected: Option<&Stat>) -> io::Result<OwnedFd> {
    // SAFETY: live descriptor, validated component; the flags refuse a
    // symlink and a non-directory.
    let fd = owned(unsafe { libc::openat(dir.as_raw_fd(), name.as_c().as_ptr(), walk_flags()) })?;
    verify(&fstat(fd.as_fd())?, expected)?;
    Ok(fd)
}

/// Opens one entry of `dir` for reading, checked against `expected`.
fn open_read_at(dir: BorrowedFd<'_>, name: &Name, expected: Option<&Stat>) -> io::Result<File> {
    // SAFETY: live descriptor, validated component; O_NOFOLLOW refuses a
    // final symlink, O_NONBLOCK keeps a FIFO from blocking the open and
    // O_NOCTTY keeps a terminal from becoming controlling.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_c().as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    let file = File::from(owned(fd)?);
    verify(&fstat(file.as_fd())?, expected)?;
    Ok(file)
}

/// Opens one entry of `dir` as an `O_PATH` handle without following it.
#[cfg(target_os = "linux")]
fn open_path_at(dir: BorrowedFd<'_>, name: &Name) -> io::Result<OwnedFd> {
    // SAFETY: live descriptor, validated component; O_PATH|O_NOFOLLOW
    // opens the entry itself with no I/O authority.
    owned(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_c().as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

// ---------------------------------------------------------------------------
// Walk handles and the walk from `/`
// ---------------------------------------------------------------------------

/// A directory opened for a no-follow walk. On Linux it is an `O_PATH`
/// handle: it needs search permission on the directory, not read
/// permission, exactly like path resolution, and it cannot be listed,
/// synced or have its mode changed, so it has no such methods. It anchors
/// the next step of a walk and the opening of what the walk reached;
/// [`Dir`] is the directory that can be read and changed.
#[derive(Debug)]
pub struct WalkDir {
    fd: OwnedFd,
}

impl WalkDir {
    /// Opens `/` for a walk.
    ///
    /// # Errors
    /// The errno from `open`.
    pub fn open_root() -> io::Result<WalkDir> {
        // SAFETY: the literal is NUL-terminated and static.
        let fd = unsafe { libc::open(c"/".as_ptr(), walk_flags()) };
        Ok(WalkDir { fd: owned(fd)? })
    }

    /// The descriptor, borrowed.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// `fstat` of the directory itself.
    ///
    /// # Errors
    /// The errno from `fstat`.
    pub fn stat(&self) -> io::Result<Stat> {
        fstat(self.as_fd())
    }

    /// As [`Dir::stat_at`].
    ///
    /// # Errors
    /// The errno from `fstatat`.
    pub fn stat_at(&self, name: &Name) -> io::Result<Stat> {
        stat_at(self.as_fd(), name)
    }

    /// The next directory of the walk, never followed, checked to be the
    /// object `expected` described.
    ///
    /// # Errors
    /// As [`Dir::open_dir_at`].
    pub fn open_walk_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<WalkDir> {
        Ok(WalkDir {
            fd: open_walk_at(self.as_fd(), name, expected)?,
        })
    }

    /// As [`Dir::open_read_at`].
    ///
    /// # Errors
    /// As [`Dir::open_read_at`].
    pub fn open_read_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<File> {
        open_read_at(self.as_fd(), name, expected)
    }

    /// As [`Dir::open_path_at`].
    ///
    /// # Errors
    /// The errno from `openat`.
    #[cfg(target_os = "linux")]
    pub fn open_path_at(&self, name: &Name) -> io::Result<OwnedFd> {
        open_path_at(self.as_fd(), name)
    }
}

/// What a walk from `/` reached ([`walk`]).
#[derive(Debug)]
pub struct Walked {
    /// The last directory walked (`/` for no components).
    pub dir: WalkDir,
    /// The identities of `/` and of every directory walked, in order.
    pub chain: Vec<(u64, u64)>,
}

/// Why a walk from `/` stopped.
#[derive(Debug)]
pub enum WalkError<E> {
    /// `/` or a component could not be inspected or opened (an open that
    /// reached another object than the one inspected included). `depth` is
    /// the number of components that lead to it: 0 for `/`.
    Io {
        /// Components leading to what failed.
        depth: usize,
        /// The failure.
        error: io::Error,
    },
    /// A component is not a directory, and is never walked through.
    NotDirectory {
        /// Components leading to it, itself included.
        depth: usize,
        /// What it is.
        kind: Kind,
    },
    /// `check` refused `/` or a component.
    Refused(E),
}

/// Walks the directories `components` from `/` without following a link:
/// each is inspected with `fstatat`, must be a directory, is judged by
/// `check` (given the components that lead to it, none for `/`), and is
/// opened as a [`WalkDir`] verified to be the object inspected, so nothing
/// swapped in between the inspection and the open is ever walked through.
///
/// # Errors
/// [`WalkError`]: what stopped the walk, and where.
pub fn walk<E>(
    components: &[Name],
    mut check: impl FnMut(&[Name], &Stat) -> Result<(), E>,
) -> Result<Walked, WalkError<E>> {
    let failed = |depth: usize| move |error| WalkError::Io { depth, error };
    let mut dir = WalkDir::open_root().map_err(failed(0))?;
    let root = dir.stat().map_err(failed(0))?;
    check(&[], &root).map_err(WalkError::Refused)?;
    let mut chain = vec![root.identity()];
    for (index, component) in components.iter().enumerate() {
        let depth = index + 1;
        let stat = dir.stat_at(component).map_err(failed(depth))?;
        if stat.kind != Kind::Directory {
            return Err(WalkError::NotDirectory {
                depth,
                kind: stat.kind,
            });
        }
        check(&components[..depth], &stat).map_err(WalkError::Refused)?;
        dir = dir
            .open_walk_at(component, Some(&stat))
            .map_err(failed(depth))?;
        chain.push(stat.identity());
    }
    Ok(Walked { dir, chain })
}

/// What [`Dir::names`] read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Listing {
    /// The names read, at most the bound asked for.
    pub names: Vec<Name>,
    /// Whether they are every name in the directory; false when it holds
    /// more than the bound.
    pub complete: bool,
}

/// One entry [`Dir::entries`] read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// Its name.
    pub name: Name,
    /// The `d_type` `readdir` reported (`DT_DIR`, `DT_REG`, ...;
    /// `DT_UNKNOWN` where the filesystem does not say).
    pub kind: u8,
}

/// What [`Dir::entries`] read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entries {
    /// The entries read, at most the bound asked for.
    pub entries: Vec<Entry>,
    /// Whether they are every entry in the directory; false when it holds
    /// more than the bound.
    pub complete: bool,
}

fn verify(actual: &Stat, expected: Option<&Stat>) -> io::Result<()> {
    match expected {
        Some(expected) if expected.identity() != actual.identity() => Err(io::Error::other(
            "the object opened is not the object that was inspected",
        )),
        _ => Ok(()),
    }
}

#[cfg(target_os = "linux")]
fn walk_flags() -> libc::c_int {
    libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}

#[cfg(not(target_os = "linux"))]
fn walk_flags() -> libc::c_int {
    DIR_FLAGS
}

#[cfg(target_os = "macos")]
fn mode_t(mode: u32) -> libc::mode_t {
    // `mode_t` is 16 bits on macOS; every mode this module sets is 0o7777 or
    // less, so the truncation can only drop bits that are never set.
    u16::try_from(mode & 0o7777).unwrap_or(0o700)
}

#[cfg(not(target_os = "macos"))]
fn mode_t(mode: u32) -> libc::mode_t {
    mode & 0o7777
}

/// The variadic `mode` argument of `open`/`openat`, which is promoted to
/// `unsigned int` on every supported platform.
fn mode_arg(mode: u32) -> libc::c_uint {
    mode & 0o7777
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: errno is this thread's own.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: errno is this thread's own.
    unsafe { *libc::__error() = 0 };
}

/// Whether one entry is a mount root, where the platform can say.
#[cfg(target_os = "linux")]
fn mount_root_at(dir: BorrowedFd<'_>, name: &Name) -> Option<bool> {
    // SAFETY: an all-zero statx is a valid scratch buffer the kernel fills.
    let mut buffer: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live, `name` is a validated NUL-terminated
    // component, AT_SYMLINK_NOFOLLOW describes the entry itself and `buffer`
    // is a writable statx.
    let rc = unsafe {
        libc::statx(
            dir.as_raw_fd(),
            name.as_c().as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS,
            &raw mut buffer,
        )
    };
    let flag = u64::try_from(libc::STATX_ATTR_MOUNT_ROOT).ok()?;
    if rc != 0 || buffer.stx_attributes_mask & flag == 0 {
        return None;
    }
    Some(buffer.stx_attributes & flag != 0)
}

#[cfg(not(target_os = "linux"))]
fn mount_root_at(_dir: BorrowedFd<'_>, _name: &Name) -> Option<bool> {
    None
}

/// `fstat` of any descriptor.
///
/// # Errors
/// The errno from `fstat`.
pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<Stat> {
    let mut raw = empty_stat();
    // SAFETY: the descriptor is live and `raw` is a writable buffer; fstat is
    // permitted on an O_PATH descriptor.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &raw mut raw) })?;
    Ok(stat_from(&raw))
}

/// `fchmod` of any descriptor to exactly `mode`.
///
/// # Errors
/// The errno from `fchmod`.
pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: the descriptor is live.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode_t(mode)) })
}

/// Filesystem types whose content cannot change while mounted: squashfs,
/// EROFS and ISO 9660 have no write path at all. A read-only *mount* of a
/// writable filesystem is not on this list: the same inode stays writable
/// through any other mount of that filesystem.
#[cfg(target_os = "linux")]
const IMMUTABLE_FILESYSTEMS: [u64; 3] = [
    0x7371_7368, // SQUASHFS_MAGIC
    0xE0F5_E1E2, // EROFS_SUPER_MAGIC_V1
    0x0000_9660, // ISOFS_SUPER_MAGIC
];

/// Whether the object behind `fd` lies on a filesystem that has no write path
/// (squashfs, EROFS, ISO 9660), read with `fstatfs`.
///
/// # Errors
/// The errno from `fstatfs`.
#[cfg(target_os = "linux")]
pub fn immutable_filesystem(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: an all-zero statfs is a valid scratch buffer the kernel fills.
    let mut buffer: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live and `buffer` is a writable statfs;
    // fstatfs is permitted on an O_PATH descriptor.
    check(unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut buffer) })?;
    let magic = buffer.f_type.cast_unsigned() & 0xffff_ffff;
    Ok(IMMUTABLE_FILESYSTEMS.contains(&magic))
}

/// Off Linux no filesystem type is established as immutable, so no `bind_ro`
/// digest is ever recorded.
///
/// # Errors
/// Never.
#[cfg(not(target_os = "linux"))]
pub fn immutable_filesystem(_fd: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(false)
}

/// Reopens an `O_PATH` handle for reading through `/proc/self/fd` and checks
/// that the reopened object is `expected`.
///
/// The magic link resolves to the exact object the handle holds, not to a
/// path, so a rename or a replacement of the original name cannot change what
/// is opened. The identity is still compared with the caller's own record of
/// the object: a reopen that reached anything else (an unexpected `/proc`, a
/// handle that is not the one examined) is refused, never used.
///
/// # Errors
/// The errno from `open`, or `Other` when the identities differ.
#[cfg(target_os = "linux")]
pub fn reopen_checked(fd: BorrowedFd<'_>, expected: &Stat) -> io::Result<File> {
    let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| io::Error::other("descriptor path contains NUL"))?;
    // SAFETY: `path` is NUL-terminated and outlives the call. O_NOFOLLOW is
    // deliberately absent: the final component is the kernel's magic link to
    // the held object, which is exactly what must be followed.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let file = File::from(owned(raw)?);
    verify(&fstat(file.as_fd())?, Some(expected))?;
    Ok(file)
}

/// Reopens the kernel link to a previously checked regular file for refresh.
/// No mutable pathname is opened for I/O.
#[cfg(target_os = "linux")]
pub(crate) fn reopen_write_checked(fd: BorrowedFd<'_>, expected: &Stat) -> io::Result<File> {
    if expected.kind != Kind::Regular {
        return Err(io::Error::other("not regular"));
    }
    let path = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|_| io::Error::other("descriptor"))?;
    // SAFETY: this kernel magic link refers to the held, checked regular inode.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let file = File::from(owned(raw)?);
    verify(&fstat(file.as_fd())?, Some(expected))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    fn temp() -> (tempfile::TempDir, Dir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let handle = Dir::open_trusted(&dir.path().canonicalize().unwrap()).expect("open");
        (dir, handle)
    }

    /// The walk from `/` reaches the directory a path names, records the
    /// identity of every directory on the way, and judges each one.
    #[test]
    fn a_walk_from_the_root_reaches_the_directory_and_records_the_chain() {
        let (root, _) = temp();
        let base = root.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        let target = base.join("a/b");
        let components = split_absolute(target.as_os_str().as_bytes()).unwrap();
        let mut judged = Vec::new();
        let walked = walk(&components, |path, stat| {
            judged.push(path.len());
            assert_eq!(stat.kind, Kind::Directory);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(judged, (0..=components.len()).collect::<Vec<_>>());
        assert_eq!(walked.chain.len(), components.len() + 1);
        let expected = std::fs::metadata(&target).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(
            walked.dir.stat().unwrap().identity(),
            (expected.dev(), expected.ino())
        );
        assert_eq!(
            *walked.chain.last().unwrap(),
            (expected.dev(), expected.ino())
        );
    }

    /// A symlink on the way is never walked through, and a refusal stops
    /// the walk where it was made.
    #[test]
    fn a_walk_never_follows_a_link_and_stops_at_a_refusal() {
        let (root, _) = temp();
        let base = root.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("real/inner")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let through = split_absolute(base.join("link/inner").as_os_str().as_bytes()).unwrap();
        let depth = through.len() - 1;
        match walk(&through, |_, _| Ok::<(), ()>(())) {
            Err(WalkError::NotDirectory { depth: at, kind }) => {
                assert_eq!((at, kind), (depth, Kind::Symlink));
            }
            other => panic!("walked through a link: {other:?}"),
        }
        let real = split_absolute(base.join("real/inner").as_os_str().as_bytes()).unwrap();
        let refused = walk(&real, |path, _| {
            if path.last().is_some_and(|name| name.as_bytes() == b"real") {
                Err("refused")
            } else {
                Ok(())
            }
        });
        assert!(
            matches!(refused, Err(WalkError::Refused("refused"))),
            "{refused:?}"
        );
        let missing = split_absolute(base.join("missing/x").as_os_str().as_bytes()).unwrap();
        match walk(&missing, |_, _| Ok::<(), ()>(())) {
            Err(WalkError::Io { depth: at, error }) => {
                assert_eq!(at, missing.len() - 1);
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_component_with_a_slash_dot_or_nul_never_reaches_a_syscall() {
        for bad in [&b""[..], b".", b"..", b"a/b", b"/", b"a\0b"] {
            assert!(Name::new(bad).is_err(), "{bad:?} must refuse");
        }
        assert!(Name::new(b"ok.name").is_ok());
        for bad in [&b""[..], b"/abs", b"a//b", b"a/", b"a/../b", b"./a", b"a/."] {
            assert!(split_relative(bad).is_err(), "{bad:?} must refuse");
        }
        assert_eq!(split_relative(b"a/b").unwrap().len(), 2);
        assert!(split_absolute(b"relative").is_err());
        assert!(split_absolute(b"/a/../b").is_err());
        assert_eq!(split_absolute(b"//a//b").unwrap().len(), 2);
    }

    #[test]
    fn a_final_symlink_is_never_followed_by_any_open() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("target"), b"secret").unwrap();
        std::fs::create_dir(root.path().join("dir")).unwrap();
        std::os::unix::fs::symlink(root.path().join("target"), root.path().join("link")).unwrap();
        std::os::unix::fs::symlink(root.path().join("dir"), root.path().join("dirlink")).unwrap();
        let link = Name::new(b"link").unwrap();
        let dirlink = Name::new(b"dirlink").unwrap();
        assert_eq!(dir.stat_at(&link).unwrap().kind, Kind::Symlink);
        assert!(dir.open_read_at(&link, None).is_err());
        assert!(dir.open_dir_at(&dirlink, None).is_err());
        assert!(dir.open_walk_at(&dirlink, None).is_err());
        assert!(
            dir.create_file_at(&link, 0o600).is_err(),
            "O_EXCL refuses a link"
        );
        assert!(dir.mkdir_at(&dirlink, 0o700).is_err());
        dir.unlink_at(&link).unwrap();
        assert_eq!(
            std::fs::read(root.path().join("target")).unwrap(),
            b"secret",
            "unlinking a link leaves its target"
        );
        #[cfg(target_os = "linux")]
        {
            let fd = dir.open_path_at(&dirlink).unwrap();
            assert_eq!(fstat(fd.as_fd()).unwrap().kind, Kind::Symlink);
        }
    }

    #[test]
    fn an_open_checks_it_reached_the_object_that_was_inspected() {
        let (root, dir) = temp();
        std::fs::create_dir(root.path().join("a")).unwrap();
        std::fs::create_dir(root.path().join("b")).unwrap();
        let a = Name::new(b"a").unwrap();
        let b = Name::new(b"b").unwrap();
        let stat_b = dir.stat_at(&b).unwrap();
        let error = dir.open_dir_at(&a, Some(&stat_b)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(dir.open_dir_at(&b, Some(&stat_b)).is_ok());
        // The same check on the walk handle: a directory swapped between the
        // inspection and the open is refused, whatever the open flags are.
        let error = dir.open_walk_at(&a, Some(&stat_b)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(dir.open_walk_at(&b, Some(&stat_b)).is_ok());
        // And on a file opened for reading.
        std::fs::write(root.path().join("f"), b"f").unwrap();
        let error = dir
            .open_read_at(&Name::new(b"f").unwrap(), Some(&stat_b))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn an_exclusive_create_refuses_an_existing_regular_file() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("there"), b"operator bytes").unwrap();
        let error = dir
            .create_file_at(&Name::new(b"there").unwrap(), 0o600)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(root.path().join("there")).unwrap(),
            b"operator bytes"
        );
    }

    #[test]
    fn created_objects_have_exactly_the_requested_mode_whatever_the_umask() {
        let (_root, dir) = temp();
        let sub = dir.mkdir_at(&Name::new(b"sub").unwrap(), 0o700).unwrap();
        assert_eq!(sub.stat().unwrap().mode, 0o700);
        let mut file = sub
            .create_file_at(&Name::new(b"f").unwrap(), 0o600)
            .unwrap();
        file.write_all(b"x").unwrap();
        assert_eq!(fstat(file.as_fd()).unwrap().mode, 0o600);
        let mut back = String::new();
        sub.open_read_at(&Name::new(b"f").unwrap(), None)
            .unwrap()
            .read_to_string(&mut back)
            .unwrap();
        assert_eq!(back, "x");
    }

    #[test]
    fn names_rewinds_and_skips_the_dot_entries() {
        let (root, dir) = temp();
        for name in ["one", "two", "three"] {
            std::fs::write(root.path().join(name), b"").unwrap();
        }
        let first = dir.names(usize::MAX - 1).unwrap();
        let second = dir.names(usize::MAX - 1).unwrap();
        assert_eq!(first.names.len(), 3, "{first:?}");
        assert!(first.complete);
        assert_eq!(
            second.names.len(),
            3,
            "a second read starts from the beginning"
        );
        let bounded = dir.names(2).unwrap();
        assert_eq!(bounded.names.len(), 2);
        assert!(
            !bounded.complete,
            "a bound below the count is not all of it"
        );
        let exact = dir.names(3).unwrap();
        assert_eq!(exact.names.len(), 3);
        assert!(exact.complete, "exactly the bound is all of it");
        assert_eq!(
            dir.names(0).unwrap(),
            Listing {
                names: Vec::new(),
                complete: false
            }
        );
    }

    /// Each entry carries the type `readdir` reported, so a walk can tell a
    /// directory from a file without a stat (where the filesystem reports
    /// types at all), and the bound reads as in [`Dir::names`].
    #[test]
    fn entries_carry_the_type_readdir_reported() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("file"), b"").unwrap();
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::os::unix::fs::symlink("file", root.path().join("link")).unwrap();
        let listed = dir.entries(3).unwrap();
        assert!(listed.complete);
        let mut kinds: Vec<(Vec<u8>, u8)> = listed
            .entries
            .iter()
            .map(|entry| (entry.name.as_bytes().to_vec(), entry.kind))
            .collect();
        kinds.sort();
        let expected = [
            (b"file".to_vec(), libc::DT_REG),
            (b"link".to_vec(), libc::DT_LNK),
            (b"sub".to_vec(), libc::DT_DIR),
        ];
        for ((name, kind), (want_name, want_kind)) in kinds.iter().zip(&expected) {
            assert_eq!(name, want_name);
            assert!(
                *kind == *want_kind || *kind == libc::DT_UNKNOWN,
                "{}: d_type {kind}",
                String::from_utf8_lossy(name)
            );
        }
        let bounded = dir.entries(2).unwrap();
        assert_eq!(bounded.entries.len(), 2);
        assert!(!bounded.complete);
        assert_eq!(
            dir.names(3).unwrap().names,
            listed
                .entries
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            "names are the entries' names, in the same order"
        );
    }

    #[test]
    fn a_directory_the_child_made_unreadable_can_be_reopened_after_chmod_at() {
        let (root, dir) = temp();
        let locked = root.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("inside"), b"").unwrap();
        std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let name = Name::new(b"locked").unwrap();
        let stat = dir.stat_at(&name).unwrap();
        if dir.open_dir_at(&name, Some(&stat)).is_err() {
            dir.chmod_at(&name, 0o700).unwrap();
        }
        let opened = dir.open_dir_at(&name, Some(&stat)).unwrap();
        assert_eq!(opened.names(10).unwrap().names.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_o_path_open_of_a_fifo_is_not_a_reader() {
        // A writer blocks in open(2) until a reader opens the FIFO. The
        // O_PATH handle credential staging takes before `fstat` must not be
        // one, so a special file swapped in after the pre-check is still
        // never opened for I/O.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (root, dir) = temp();
        let fifo = root.path().canonicalize().unwrap().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let opened = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&opened);
        let path = fifo.clone();
        let writer = std::thread::spawn(move || {
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            flag.store(true, Ordering::SeqCst);
            drop(file);
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        let handle = dir.open_path_at(&Name::new(b"fifo").unwrap()).unwrap();
        assert_eq!(fstat(handle.as_fd()).unwrap().kind, Kind::Fifo);
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !opened.load(Ordering::SeqCst),
            "the O_PATH open was a reader"
        );
        let reader = std::fs::File::open(&fifo).unwrap();
        writer.join().unwrap();
        drop(reader);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reopened_path_handle_reads_the_held_object_even_after_a_rename() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("held"), b"held-bytes").unwrap();
        let fd = dir.open_path_at(&Name::new(b"held").unwrap()).unwrap();
        std::fs::rename(root.path().join("held"), root.path().join("moved")).unwrap();
        std::fs::write(root.path().join("held"), b"impostor").unwrap();
        let mut back = Vec::new();
        let expected = fstat(fd.as_fd()).unwrap();
        reopen_checked(fd.as_fd(), &expected)
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, b"held-bytes");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reopen_that_reaches_another_object_than_expected_is_refused() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("one"), b"1").unwrap();
        std::fs::write(root.path().join("two"), b"2").unwrap();
        let one = dir.open_path_at(&Name::new(b"one").unwrap()).unwrap();
        let two = dir.stat_at(&Name::new(b"two").unwrap()).unwrap();
        let error = reopen_checked(one.as_fd(), &two).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_ordinary_filesystem_is_not_immutable() {
        let (root, dir) = temp();
        std::fs::write(root.path().join("f"), b"f").unwrap();
        let handle = dir.open_path_at(&Name::new(b"f").unwrap()).unwrap();
        assert!(!immutable_filesystem(handle.as_fd()).unwrap());
        let proc_self = File::open("/proc/self/status").unwrap();
        assert!(!immutable_filesystem(proc_self.as_fd()).unwrap());
    }
}
