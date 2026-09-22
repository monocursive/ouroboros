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

    fn as_c(&self) -> &CStr {
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

    /// Opens `/` for a no-follow walk.
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
        let mut raw = empty_stat();
        // SAFETY: the descriptor is live, `name` is a validated NUL-terminated
        // component, `raw` is a writable buffer and AT_SYMLINK_NOFOLLOW
        // describes the entry itself.
        check(unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                &raw mut raw,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })?;
        let mut stat = stat_from(&raw);
        stat.mount_root = mount_root_at(self.as_fd(), name);
        Ok(stat)
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

    /// Opens one entry as a directory for a walk (`O_PATH` on Linux).
    ///
    /// # Errors
    /// As [`Dir::open_dir_at`].
    pub fn open_walk_at(&self, name: &Name, expected: Option<&Stat>) -> io::Result<Dir> {
        // SAFETY: live descriptor, validated component; the flags refuse a
        // symlink and a non-directory.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_c().as_ptr(), walk_flags()) };
        let dir = Dir { fd: owned(fd)? };
        verify(&dir.stat()?, expected)?;
        Ok(dir)
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
        // SAFETY: live descriptor, validated component; O_NOFOLLOW refuses a
        // final symlink, O_NONBLOCK keeps a FIFO from blocking the open and
        // O_NOCTTY keeps a terminal from becoming controlling.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
            )
        };
        let file = File::from(owned(fd)?);
        verify(&fstat(file.as_fd())?, expected)?;
        Ok(file)
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
        // SAFETY: live descriptor, validated component; O_PATH|O_NOFOLLOW
        // opens the entry itself with no I/O authority.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_c().as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        owned(fd)
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

    /// Up to `max` entry names, `.` and `..` excluded, read from the start.
    ///
    /// # Errors
    /// The errno from `fcntl`, `fdopendir` or `readdir`, or `InvalidData`
    /// for a name the kernel returned that is not a valid component.
    pub fn names(&self, max: usize) -> io::Result<Vec<Name>> {
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
        while out.len() < max {
            clear_errno();
            // SAFETY: `stream` is live; the returned entry stays valid until
            // the next call on this stream.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = io::Error::last_os_error();
                if errno.raw_os_error().unwrap_or(0) != 0 {
                    failure = Some(errno);
                }
                break;
            }
            // SAFETY: `entry` is non-null and `d_name` is a NUL-terminated
            // array inside it.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            match Name::new(bytes) {
                Ok(name) => out.push(name),
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
        match failure {
            Some(error) => Err(error),
            None => Ok(out),
        }
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

/// Whether the filesystem holding `fd` is mounted read-only.
///
/// # Errors
/// The errno from `fstatvfs`.
pub fn readonly_filesystem(fd: BorrowedFd<'_>) -> io::Result<bool> {
    // SAFETY: an all-zero statvfs is a valid scratch buffer.
    let mut buffer: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live and `buffer` is a writable statvfs.
    check(unsafe { libc::fstatvfs(fd.as_raw_fd(), &raw mut buffer) })?;
    Ok(buffer.f_flag & libc::ST_RDONLY != 0)
}

/// Reopens an `O_PATH` handle for reading through `/proc/self/fd`.
///
/// The magic link resolves to the exact object the handle holds, not to a
/// path, so a rename or a replacement of the original name cannot change what
/// is opened. The caller still compares identities: a reopen that reached a
/// different object (an unexpected `/proc`) is refused, never used.
///
/// # Errors
/// The errno from `open`, or `Other` when the identities differ.
#[cfg(target_os = "linux")]
pub fn reopen_for_read(fd: BorrowedFd<'_>) -> io::Result<File> {
    let before = fstat(fd)?;
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
    verify(&fstat(file.as_fd())?, Some(&before))?;
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
        let first = dir.names(usize::MAX).unwrap();
        let second = dir.names(usize::MAX).unwrap();
        assert_eq!(first.len(), 3, "{first:?}");
        assert_eq!(second.len(), 3, "a second read starts from the beginning");
        assert_eq!(dir.names(2).unwrap().len(), 2);
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
        assert_eq!(opened.names(10).unwrap().len(), 1);
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
        reopen_for_read(fd.as_fd())
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, b"held-bytes");
    }
}
